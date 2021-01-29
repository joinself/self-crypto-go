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
	"errors"
	"log"
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

	C.olm_create_outbound_session(
		sess.ptr,
		acc.ptr,
		C.CBytes(ikbuf),
		C.size_t(len(ikbuf)),
		C.CBytes(otkbuf),
		C.size_t(len(otkbuf)),
		C.CBytes(rbuf),
		rlen,
	)

	return sess, sess.lastError()
}

// CreateInboundSession creates an inbound session for receiving messages from a senders outbound session
func CreateInboundSession(acc *Account, sender string, oneTimeKeyMessage *Message) (*Session, error) {
	sess := newSession(sender)

	if oneTimeKeyMessage == nil {
		return nil, errors.New("one time key message is nil")
	}

	mbuf := oneTimeKeyMessage.ciphertext()

	if acc.ptr == nil {
		return nil, errors.New("account pointer is nil")
	}

	if sess == nil {
		return nil, errors.New("session is nil")
	}

	if sess.ptr == nil {
		return nil, errors.New("session pointer is nil")
	}

	if mbuf == nil {
		return nil, errors.New("message is nil")
	}

	if len(mbuf) < 1 {
		log.Println("message:", oneTimeKeyMessage)
		return nil, errors.New("one message is nil")
	}

	C.olm_create_inbound_session(
		sess.ptr,
		acc.ptr,
		C.CBytes(mbuf),
		C.size_t(len(mbuf)),
	)

	return sess, sess.lastError()
}

// SessionFromPickle loads an encoded session from a pickle
func SessionFromPickle(recipient, key, pickle string) (*Session, error) {
	sess := newSession(recipient)

	kbuf := []byte(key)
	pbuf := []byte(pickle)

	// this returns a result we should probably inspect
	C.olm_unpickle_session(
		sess.ptr,
		C.CBytes(kbuf),
		C.size_t(len(kbuf)),
		C.CBytes(pbuf),
		C.size_t(len(pbuf)),
	)

	return sess, sess.lastError()
}

// Pickle encode the current session
func (s Session) Pickle(key string) (string, error) {
	kbuf := []byte(key)
	plen := C.olm_pickle_session_length(s.ptr)
	pbuf := C.malloc(plen)

	// this returns a result we should probably inspect
	C.olm_pickle_session(
		s.ptr,
		C.CBytes(kbuf),
		C.size_t(len(kbuf)),
		pbuf,
		C.size_t(plen),
	)

	data := C.GoBytes(pbuf, C.int(plen))

	C.free(pbuf)

	return string(data), s.lastError()
}

// GetSessionID returns the sessions id
func (s Session) GetSessionID() (string, error) {
	idlen := C.olm_session_id_length(s.ptr)
	idbuf := make([]byte, idlen)

	C.olm_session_id(
		s.ptr,
		C.CBytes(idbuf),
		idlen,
	)

	return string(idbuf), s.lastError()
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

	C.olm_encrypt(
		s.ptr,
		C.CBytes(plaintext),
		C.size_t(len(plaintext)),
		C.CBytes(rbuf),
		rlen,
		mbuf,
		mlen,
	)

	data := C.GoBytes(mbuf, C.int(mlen))

	C.free(mbuf)

	m.Ciphertext = string(data)

	return &m, s.lastError()
}

// Decrypt decrypts a message using a sessions ratchet
func (s Session) Decrypt(message *Message) ([]byte, error) {
	mbuf := message.ciphertext()

	ptlen := C.olm_decrypt_max_plaintext_length(
		s.ptr,
		C.size_t(message.Type),
		C.CBytes(mbuf),
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
		C.CBytes(mbuf),
		C.size_t(len(mbuf)),
		ptbuf,
		ptlen,
	)

	data := C.GoBytes(ptbuf, C.int(ptlen))

	C.free(ptbuf)

	err = s.lastError()
	if err != nil {
		return nil, err
	}

	return data[:ptlen], s.lastError()
}

func (s Session) lastError() error {
	errStr := C.GoString(C.olm_session_last_error(s.ptr))
	return Error(errStr)
}
