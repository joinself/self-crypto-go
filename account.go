package olm

/*
#cgo LDFLAGS: -L/usr/local/lib/libolm.so -lolm
#include <olm/olm.h>
#include <stdlib.h>
*/
import "C"
import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"unsafe"
)

// Account an olm account that stores the ed25519 and curve25519 secret keys
type Account struct {
	buf []byte
	ptr *C.struct_OlmAccount
}

func newAccount() *Account {
	buf := make([]byte, C.olm_account_size())

	return &Account{
		buf: buf,
		ptr: C.olm_account(unsafe.Pointer(&buf[0])),
	}
}

// NewAccount creates a new account with ed25519 and curve25519 secret keys
func NewAccount() (*Account, error) {
	acc := newAccount()
	rlen := C.olm_create_account_random_length(acc.ptr)
	rbuf := make([]byte, rlen)

	_, err := rand.Read(rbuf)
	if err != nil {
		return nil, err
	}

	C.olm_create_account(
		acc.ptr,
		unsafe.Pointer(&rbuf[0]),
		rlen,
	)

	fmt.Println(acc.buf)

	return acc, nil
}

// AccountFromKey reconstructs an olm account from existing ed25519 secret key
func AccountFromKey(ed25519SK ed25519.PrivateKey) *Account {
	buf := make([]byte, C.olm_account_size())

	ed25519KP := constructKeypair(ed25519SK, ed25519SK.Public().([]byte))

	copy(buf[:len(ed25519KP)], ed25519KP)
	//copy(buf[len(ed25519SK):], curve25519SK)

	acc := C.olm_account(unsafe.Pointer(&buf[0]))

	return &Account{ptr: acc}
}

// AccountFromPickle reconstructs an account from a pickle
func AccountFromPickle(key string, pickle string) *Account {
	acc := newAccount()

	kbuf := []byte(key)
	pbuf := []byte(pickle)

	C.olm_unpickle_account(
		acc.ptr,
		unsafe.Pointer(&kbuf[0]), C.size_t(len(kbuf)),
		unsafe.Pointer(&pbuf[0]), C.size_t(len(pbuf)),
	)

	return acc
}

// Pickle encodes and encrypts an account to a string safe format
func (a Account) Pickle(key string) string {
	kbuf := []byte(key)
	pbuf := make([]byte, C.olm_pickle_account_length(a.ptr))

	// this returns a result we should probably inspect
	C.olm_pickle_account(
		a.ptr,
		unsafe.Pointer(&kbuf[0]), C.size_t(len(kbuf)),
		unsafe.Pointer(&pbuf[0]), C.size_t(len(pbuf)),
	)

	return string(pbuf)
}

// Sign signs a message with the accounts ed25519 secret key
func (a Account) Sign(message []byte) []byte {
	olen := C.olm_account_signature_length(a.ptr)
	obuf := make([]byte, olen)

	C.olm_account_sign(
		a.ptr,
		unsafe.Pointer(&message[0]), C.size_t(len(message)),
		unsafe.Pointer(&obuf[0]), olen,
	)

	return obuf
}

func (a Account) lastError() string {
	return C.GoString(C.olm_account_last_error(a.ptr))
}

func constructKeypair(sk, pk []byte) []byte {
	return append(pk, sk...)
}
