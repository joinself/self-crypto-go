package selfcrypto

/*
#cgo LDFLAGS: -lstdc++
#cgo darwin LDFLAGS: -L/usr/local/lib/ -lself_omemo
#cgo linux LDFLAGS: -L/usr/lib/libself_omemo.a -lself_omemo
#include <self_omemo.h>
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
	slen := C.self_olm_session_size()
	buf := C.malloc(slen)

	return &Session{recipient: recipient, ptr: C.self_olm_session(buf)}
}

// CreateOutboundSession sets up an outbound session for communicating with a third party
func CreateOutboundSession(acc *Account, recipient, identityKey, oneTimeKey string) (*Session, error) {
	sess := newSession(recipient)

	rlen := C.self_olm_create_outbound_session_random_length(sess.ptr)
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

	C.self_olm_create_outbound_session(
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

	return sess, sess.LastError()
}

// CreateInboundSession creates an inbound session for receiving messages from a senders outbound session
func CreateInboundSession(acc *Account, sender string, oneTimeKeyMessage *Message) (*Session, error) {
	sess := newSession(sender)

	mbuf := oneTimeKeyMessage.ciphertext()

	cmbuf := C.CBytes(mbuf)

	C.self_olm_create_inbound_session(
		sess.ptr,
		acc.ptr,
		cmbuf,
		C.size_t(len(mbuf)),
	)

	C.free(cmbuf)

	return sess, sess.LastError()
}

// SessionFromPickle loads an encoded session from a pickle
func SessionFromPickle(recipient, key, pickle string) (*Session, error) {
	sess := newSession(recipient)

	kbuf := []byte(key)
	pbuf := []byte(pickle)

	ckbuf := C.CBytes(kbuf)
	cpbuf := C.CBytes(pbuf)

	// this returns a result we should probably inspect
	C.self_olm_unpickle_session(
		sess.ptr,
		ckbuf,
		C.size_t(len(kbuf)),
		cpbuf,
		C.size_t(len(pbuf)),
	)

	C.free(ckbuf)
	C.free(cpbuf)

	return sess, sess.LastError()
}

// Pickle encode the current session
func (s Session) Pickle(key string) (string, error) {
	kbuf := []byte(key)
	plen := C.self_olm_pickle_session_length(s.ptr)
	pbuf := C.malloc(plen)

	ckbuf := C.CBytes(kbuf)

	// this returns a result we should probably inspect
	C.self_olm_pickle_session(
		s.ptr,
		ckbuf,
		C.size_t(len(kbuf)),
		pbuf,
		C.size_t(plen),
	)

	data := C.GoBytes(pbuf, C.int(plen))

	C.free(pbuf)
	C.free(ckbuf)

	return string(data), s.LastError()
}

// MatchesInboundSession checks if the PRE_KEY message is for this in-bound session. This can happen
// if multiple messages are sent to this account before this account sends a message in reply.
// returns true if the session matches
func (s Session) MatchesInboundSession(message *Message) (bool, error) {
	mbuf := message.ciphertext()

	cmbuf := C.CBytes(mbuf)

	ret := C.self_olm_matches_inbound_session(
		s.ptr,
		cmbuf,
		C.size_t(len(mbuf)),
	)

	C.free(cmbuf)

	return ret == 1, s.LastError()
}

func (s Session) LastError() error {
	errStr := C.GoString(C.self_olm_session_last_error(s.ptr))
	return Error(errStr)
}
