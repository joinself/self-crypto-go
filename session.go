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
	"unsafe"
)

// Session an olm session
type Session struct {
	recipient string
	ptr       *C.struct_OlmSession
}

func newSession(recipient string) *Session {
	buf := make([]byte, C.olm_session_size())

	return &Session{recipient: recipient, ptr: C.olm_session(unsafe.Pointer(&buf[0]))}
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
		unsafe.Pointer(&ikbuf[0]),
		C.size_t(len(ikbuf)),
		unsafe.Pointer(&otkbuf[0]),
		C.size_t(len(otkbuf)),
		unsafe.Pointer(&rbuf[0]),
		rlen,
	)

	return sess, sess.lastError()
}

// CreateInboundSession creates an inbound session for receiving messages from a senders outbound session
func CreateInboundSession(acc *Account, sender string, oneTimeKeyMessage *Message) (*Session, error) {
	sess := newSession(sender)

	mbuf := oneTimeKeyMessage.ciphertext()

	C.olm_create_inbound_session(
		sess.ptr,
		acc.ptr,
		unsafe.Pointer(&mbuf[0]),
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
		unsafe.Pointer(&kbuf[0]),
		C.size_t(len(kbuf)),
		unsafe.Pointer(&pbuf[0]),
		C.size_t(len(pbuf)),
	)

	return sess, sess.lastError()
}

// Pickle encode the current session
func (s Session) Pickle(key string) (string, error) {
	kbuf := []byte(key)
	pbuf := make([]byte, C.olm_pickle_session_length(s.ptr))

	// this returns a result we should probably inspect
	C.olm_pickle_session(
		s.ptr,
		unsafe.Pointer(&kbuf[0]),
		C.size_t(len(kbuf)),
		unsafe.Pointer(&pbuf[0]),
		C.size_t(len(pbuf)),
	)

	return string(pbuf), s.lastError()
}

// GetSessionID returns the sessions id
func (s Session) GetSessionID() (string, error) {
	idlen := C.olm_session_id_length(s.ptr)
	idbuf := make([]byte, idlen)

	C.olm_session_id(
		s.ptr,
		unsafe.Pointer(&idbuf[0]),
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

	mbuf := make([]byte, mlen)

	C.olm_encrypt(
		s.ptr,
		unsafe.Pointer(&plaintext[0]),
		C.size_t(len(plaintext)),
		unsafe.Pointer(&rbuf[0]),
		rlen,
		unsafe.Pointer(&mbuf[0]),
		mlen,
	)

	m.Ciphertext = string(mbuf)

	return &m, s.lastError()
}

// Decrypt decrypts a message using a sessions ratchet
func (s Session) Decrypt(message *Message) ([]byte, error) {
	mbuf := message.ciphertext()

	ptlen := C.olm_decrypt_max_plaintext_length(
		s.ptr,
		C.size_t(message.Type),
		unsafe.Pointer(&mbuf[0]),
		C.size_t(len(mbuf)),
	)

	err := s.lastError()
	if err != nil {
		return nil, err
	}

	mbuf = message.ciphertext()

	ptbuf := make([]byte, ptlen)

	ptlen = C.olm_decrypt(
		s.ptr,
		C.size_t(message.Type),
		unsafe.Pointer(&mbuf[0]),
		C.size_t(len(mbuf)),
		unsafe.Pointer(&ptbuf[0]),
		ptlen,
	)

	err = s.lastError()
	if err != nil {
		return nil, err
	}

	return ptbuf[:ptlen], s.lastError()
}

func (s Session) lastError() error {
	errStr := C.GoString(C.olm_session_last_error(s.ptr))
	return Error(errStr)
}
