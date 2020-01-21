package olm

/*
#cgo LDFLAGS: -L/usr/local/lib/libolm.so -lolm
#include <olm/olm.h>
#include <stdlib.h>
*/
import "C"
import (
	"crypto/rand"
	"unsafe"
)

// Session an olm session
type Session struct {
	ptr *C.struct_OlmSession
}

func newSession() *Session {
	buf := make([]byte, C.olm_session_size())

	return &Session{ptr: C.olm_session(unsafe.Pointer(&buf[0]))}
}

// CreateOutboundSession sets up an outbound session for communicating with a third party
func CreateOutboundSession(acc *Account, identityKey, oneTimeKey string) (*Session, error) {
	sess := newSession()

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
func CreateInboundSession(acc *Account, oneTimeKeyMessage string) (*Session, error) {
	sess := newSession()

	otkmbuf := []byte(oneTimeKeyMessage)

	C.olm_create_inbound_session(
		sess.ptr,
		acc.ptr,
		unsafe.Pointer(&otkmbuf[0]),
		C.size_t(len(otkmbuf)),
	)

	return sess, sess.lastError()
}

// SessionFromPickle loads an encoded session from a pickle
func SessionFromPickle(key, pickle string) (*Session, error) {
	sess := newSession()

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
func (s Session) Encrypt(plaintext []byte) (int, []byte, error) {
	rlen := C.olm_encrypt_random_length(s.ptr)
	rbuf := make([]byte, rlen)

	_, err := rand.Read(rbuf)
	if err != nil {
		return 0, nil, err
	}

	mtype := C.olm_encrypt_message_type(s.ptr)
	mlen := C.olm_encrypt_message_length(
		s.ptr,
		C.size_t(len(plaintext)),
	)

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

	return int(mtype), mbuf, s.lastError()
}

// Decrypt decrypts a message using a sessions ratchet
func (s Session) Decrypt(msgType int, message []byte) ([]byte, error) {
	ptlen := C.olm_decrypt_max_plaintext_length(
		s.ptr,
		C.size_t(msgType),
		unsafe.Pointer(&message[0]),
		C.size_t(len(message)),
	)

	ptbuf := make([]byte, ptlen)

	ptlen = C.olm_decrypt(
		s.ptr,
		C.size_t(msgType),
		unsafe.Pointer(&message[0]),
		C.size_t(len(message)),
		unsafe.Pointer(&ptbuf[0]),
		ptlen,
	)

	return ptbuf[:ptlen], s.lastError()
}

func (s Session) lastError() error {
	errStr := C.GoString(C.olm_session_last_error(s.ptr))
	return Error(errStr)
}
