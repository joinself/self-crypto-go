package selfcrypto

/*
#cgo darwin LDFLAGS: -L/usr/local/lib/ -lself_olm
#cgo linux LDFLAGS: -L/usr/lib/libself_olm.so -lself_olm
#include <self_olm/olm.h>
#include <stdlib.h>
*/
import "C"
import (
	"crypto/rand"
)

// Session an olm session
type Session struct {
	recipient string
	ptr       *C.struct_OlmSession
}

func newSession(recipient string) *Session {
	slen := C.olm_session_size()
	buf := C.malloc(slen)

	return &Session{recipient: recipient, ptr: C.olm_session(buf)}
}

// CreateOutboundSession sets up an outbound session for communicating with a third party
func CreateOutboundSession(acc *Account, recipient, identityKey, oneTimeKey string) (*Session, error) {
	sess := newSession(recipient)

	rlen := C.olm_create_outbound_session_random_length(sess.ptr)
	rbuf := make([]byte, rlen)

	_, err := rand.Read(rbuf)
	if err != nil {
		return nil, err
	}

	ikbuf := []byte(identityKey)
	otkbuf := []byte(oneTimeKey)

	cikbuf := C.CBytes(ikbuf)
	cotkbuf := C.CBytes(otkbuf)
	crbuf := C.CBytes(rbuf)

	C.olm_create_outbound_session(
		sess.ptr,
		acc.ptr,
		cikbuf,
		C.size_t(len(ikbuf)),
		cotkbuf,
		C.size_t(len(otkbuf)),
		crbuf,
		rlen,
	)

	C.free(cikbuf)
	C.free(cotkbuf)
	C.free(crbuf)

	return sess, sess.lastError()
}

// CreateInboundSession creates an inbound session for receiving messages from a senders outbound session
func CreateInboundSession(acc *Account, sender string, oneTimeKeyMessage *Message) (*Session, error) {
	sess := newSession(sender)

	mbuf := oneTimeKeyMessage.ciphertext()

	cmbuf := C.CBytes(mbuf)

	C.olm_create_inbound_session(
		sess.ptr,
		acc.ptr,
		cmbuf,
		C.size_t(len(mbuf)),
	)

	C.free(cmbuf)

	return sess, sess.lastError()
}

// SessionFromPickle loads an encoded session from a pickle
func SessionFromPickle(recipient, key, pickle string) (*Session, error) {
	sess := newSession(recipient)

	kbuf := []byte(key)
	pbuf := []byte(pickle)

	ckbuf := C.CBytes(kbuf)
	cpbuf := C.CBytes(pbuf)

	// this returns a result we should probably inspect
	C.olm_unpickle_session(
		sess.ptr,
		ckbuf,
		C.size_t(len(kbuf)),
		cpbuf,
		C.size_t(len(pbuf)),
	)

	C.free(ckbuf)
	C.free(cpbuf)

	return sess, sess.lastError()
}

// Pickle encode the current session
func (s Session) Pickle(key string) (string, error) {
	kbuf := []byte(key)
	plen := C.olm_pickle_session_length(s.ptr)
	pbuf := C.malloc(plen)

	ckbuf := C.CBytes(kbuf)

	// this returns a result we should probably inspect
	C.olm_pickle_session(
		s.ptr,
		ckbuf,
		C.size_t(len(kbuf)),
		pbuf,
		C.size_t(plen),
	)

	data := C.GoBytes(pbuf, C.int(plen))

	C.free(pbuf)
	C.free(ckbuf)

	return string(data), s.lastError()
}

// GetSessionID returns the sessions id
func (s Session) GetSessionID() (string, error) {
	idlen := C.olm_session_id_length(s.ptr)
	idbuf := C.malloc(idlen)

	C.olm_session_id(
		s.ptr,
		idbuf,
		idlen,
	)

	data := C.GoBytes(idbuf, C.int(idlen))

	C.free(idbuf)

	return string(data), s.lastError()
}

// Encrypt encrypts a message using a sessions ratchet
func (s Session) Encrypt(plaintext []byte) (*Message, error) {
	m := Message{
		Type: int(C.olm_encrypt_message_type(s.ptr)),
	}

	rlen := C.olm_encrypt_random_length(s.ptr)
	rbuf := []byte{0}

	if rlen > 0 {
		rbuf = make([]byte, rlen)

		_, err := rand.Read(rbuf)
		if err != nil {
			return nil, err
		}
	}

	mlen := C.olm_encrypt_message_length(
		s.ptr,
		C.size_t(len(plaintext)),
	)

	err := s.lastError()
	if err != nil {
		return nil, err
	}

	mbuf := C.malloc(mlen)

	cptbuf := C.CBytes(plaintext)
	crbuf := C.CBytes(rbuf)

	C.olm_encrypt(
		s.ptr,
		cptbuf,
		C.size_t(len(plaintext)),
		crbuf,
		rlen,
		mbuf,
		mlen,
	)

	data := C.GoBytes(mbuf, C.int(mlen))

	C.free(mbuf)
	C.free(cptbuf)
	C.free(crbuf)

	m.Ciphertext = string(data)

	return &m, s.lastError()
}

// Decrypt decrypts a message using a sessions ratchet
func (s Session) Decrypt(message *Message) ([]byte, error) {
	mbuf := message.ciphertext()

	tcmbuf := C.CBytes(mbuf)
	cmbuf := C.CBytes(mbuf)

	ptlen := C.olm_decrypt_max_plaintext_length(
		s.ptr,
		C.size_t(message.Type),
		tcmbuf,
		C.size_t(len(mbuf)),
	)

	err := s.lastError()
	if err != nil {
		return nil, err
	}

	mbuf = message.ciphertext()

	ptbuf := C.malloc(ptlen)

	ptlen = C.olm_decrypt(
		s.ptr,
		C.size_t(message.Type),
		cmbuf,
		C.size_t(len(mbuf)),
		ptbuf,
		ptlen,
	)

	data := C.GoBytes(ptbuf, C.int(ptlen))

	C.free(ptbuf)
	C.free(cmbuf)
	C.free(tcmbuf)

	err = s.lastError()
	if err != nil {
		return nil, err
	}

	return data[:ptlen], s.lastError()
}

// MatchesInboundSession checks if the PRE_KEY message is for this in-bound session. This can happen
// if multiple messages are sent to this account before this account sends a message in reply.
// returns true if the session matches
func (s Session) MatchesInboundSession(message *Message) (bool, error) {
	mbuf := message.ciphertext()

	cmbuf := C.CBytes(mbuf)

	ret := C.olm_matches_inbound_session(
		s.ptr,
		cmbuf,
		C.size_t(len(mbuf)),
	)

	C.free(cmbuf)

	return ret == 1, s.lastError()
}

func (s Session) lastError() error {
	errStr := C.GoString(C.olm_session_last_error(s.ptr))
	return Error(errStr)
}
