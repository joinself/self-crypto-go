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
	"encoding/json"
)

// Account an olm account that stores the ed25519 and curve25519 secret keys
type Account struct {
	identity string
	ptr      *C.struct_OlmAccount
}

func newAccount(identity string) *Account {
	alen := C.olm_account_size()
	buf := C.malloc(alen)

	return &Account{
		identity: identity,
		ptr:      C.olm_account(buf),
	}
}

// NewAccount creates a new account with ed25519 and curve25519 secret keys
func NewAccount(identity string) (*Account, error) {
	acc := newAccount(identity)

	rlen := C.olm_create_account_random_length(acc.ptr)
	rbuf := make([]byte, rlen)

	_, err := rand.Read(rbuf)
	if err != nil {
		return nil, err
	}

	C.olm_create_account(
		acc.ptr,
		C.CBytes(rbuf),
		rlen,
	)

	return acc, acc.lastError()
}

// AccountFromSeed creates an olm account from existing ed25519 seed, with a derrivitve curve25519 key
func AccountFromSeed(identity string, seed []byte) (*Account, error) {
	acc := newAccount(identity)

	C.olm_create_account_derrived_keys(
		acc.ptr,
		C.CBytes(seed),
		C.size_t(len(seed)),
	)

	return acc, acc.lastError()
}

// AccountFromPickle reconstructs an account from a pickle
func AccountFromPickle(identity, key, pickle string) (*Account, error) {
	acc := newAccount(identity)

	kbuf := []byte(key)
	pbuf := []byte(pickle)

	C.olm_unpickle_account(
		acc.ptr,
		C.CBytes(kbuf),
		C.size_t(len(kbuf)),
		C.CBytes(pbuf),
		C.size_t(len(pbuf)),
	)

	return acc, acc.lastError()
}

// Pickle encodes and encrypts an account to a string safe format
func (a Account) Pickle(key string) (string, error) {
	kbuf := []byte(key)
	plen := C.olm_pickle_account_length(a.ptr)
	pbuf := C.malloc(plen)

	C.olm_pickle_account(
		a.ptr,
		C.CBytes(kbuf),
		C.size_t(len(kbuf)),
		pbuf,
		C.size_t(plen),
	)

	data := C.GoBytes(pbuf, C.int(plen))

	C.free(pbuf)

	return string(data), a.lastError()
}

// Sign signs a message with the accounts ed25519 secret key
func (a Account) Sign(message []byte) ([]byte, error) {
	slen := C.olm_account_signature_length(a.ptr)
	sbuf := C.malloc(slen)

	C.olm_account_sign(
		a.ptr,
		C.CBytes(message),
		C.size_t(len(message)),
		sbuf,
		slen,
	)

	data := C.GoBytes(sbuf, C.int(slen))

	C.free(sbuf)

	return data, a.lastError()
}

// MaxOneTimeKeys returns the maximum amount of keys an account can hold
func (a Account) MaxOneTimeKeys() int {
	return int(C.olm_account_max_number_of_one_time_keys(a.ptr))
}

// MarkKeysAsPublished marks the current set of one time keys as published
func (a Account) MarkKeysAsPublished() {
	C.olm_account_mark_keys_as_published(a.ptr)
}

// GenerateOneTimeKeys Generate a number of new one-time keys.
// If the total number of keys stored by this account exceeds
// max_one_time_keys() then the old keys are discarded
func (a Account) GenerateOneTimeKeys(count int) error {
	rlen := C.olm_account_generate_one_time_keys_random_length(
		a.ptr,
		C.size_t(count),
	)

	rbuf := make([]byte, rlen)

	_, err := rand.Read(rbuf)
	if err != nil {
		return err
	}

	C.olm_account_generate_one_time_keys(
		a.ptr,
		C.size_t(count),
		C.CBytes(rbuf),
		rlen,
	)

	return a.lastError()
}

// OneTimeKeys returns the pulic component of the accounts one time keys
func (a Account) OneTimeKeys() (*OneTimeKeys, error) {
	var otk OneTimeKeys

	olen := C.olm_account_one_time_keys_length(a.ptr)
	obuf := C.malloc(olen)

	C.olm_account_one_time_keys(
		a.ptr,
		obuf,
		olen,
	)

	err := a.lastError()
	if err != nil {
		return nil, err
	}

	data := C.GoBytes(obuf, C.int(olen))

	C.free(obuf)

	return &otk, json.Unmarshal(data, &otk)
}

// RemoveOneTimeKeys removes a sessions one time keys from an account
func (a Account) RemoveOneTimeKeys(s *Session) error {
	C.olm_remove_one_time_keys(a.ptr, s.ptr)

	return a.lastError()
}

// IdentityKeys returns the identity keys associated with the account
func (a Account) IdentityKeys() (*PublicKeys, error) {
	var keys PublicKeys

	olen := C.olm_account_identity_keys_length(a.ptr)
	obuf := C.malloc(olen)

	C.olm_account_identity_keys(
		a.ptr,
		obuf,
		olen,
	)

	err := a.lastError()
	if err != nil {
		return nil, err
	}

	data := C.GoBytes(obuf, C.int(olen))

	C.free(obuf)

	return &keys, json.Unmarshal(data, &keys)
}

func (a Account) lastError() error {
	errStr := C.GoString(C.olm_account_last_error(a.ptr))
	return Error(errStr)
}
