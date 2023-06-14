package selfcrypto

/*
#cgo LDFLAGS: -lstdc++
#cgo darwin LDFLAGS: -L/usr/local/lib/ -lself_omemo2
#cgo linux LDFLAGS: -L/usr/lib/libself_omemo2.a -lself_omemo2
#include <self_omemo2.h>
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
	alen := C.self_olm_account_size()
	buf := C.malloc(alen)

	return &Account{
		identity: identity,
		ptr:      C.self_olm_account(buf),
	}
}

// NewAccount creates a new account with ed25519 and curve25519 secret keys
func NewAccount(identity string) (*Account, error) {
	acc := newAccount(identity)

	rlen := C.self_olm_create_account_random_length(acc.ptr)
	rbuf := make([]byte, rlen)
	crbuf := C.CBytes(rbuf)

	_, err := rand.Read(rbuf)
	if err != nil {
		return nil, err
	}

	C.self_olm_create_account(
		acc.ptr,
		crbuf,
		rlen,
	)

	C.free(crbuf)

	return acc, acc.lastError()
}

// AccountFromSeed creates an olm account from existing ed25519 seed, with a derrivitve curve25519 key
func AccountFromSeed(identity string, seed []byte) (*Account, error) {
	acc := newAccount(identity)

	ed25519PK, ed25519SK, err := Ed25519FromSeed(seed)
	if err != nil {
		return nil, err
	}

	curve25519PK, err := Ed25519PKToCurve25519(ed25519PK)
	if err != nil {
		return nil, err
	}

	curve25519SK, err := Ed25519SKToCurve25519(ed25519PK)
	if err != nil {
		return nil, err
	}

	ed25519PKBuf := C.CBytes(ed25519PK)
	ed25519SKBuf := C.CBytes(ed25519SK)
	curve25519PKBuf := C.CBytes(curve25519PK)
	curve25519SKBuf := C.CBytes(curve25519SK)

	C.self_olm_import_account(
		acc.ptr,
		ed25519SKBuf,
		ed25519PKBuf,
		curve25519SKBuf,
		curve25519PKBuf,
	)

	C.free(ed25519PKBuf)
	C.free(ed25519SKBuf)
	C.free(curve25519PKBuf)
	C.free(curve25519SKBuf)

	return acc, acc.lastError()
}

// AccountFromPickle reconstructs an account from a pickle
func AccountFromPickle(identity, key, pickle string) (*Account, error) {
	acc := newAccount(identity)

	kbuf := []byte(key)
	pbuf := []byte(pickle)
	ckbuf := C.CBytes(kbuf)
	cpbuf := C.CBytes(pbuf)

	C.self_olm_unpickle_account(
		acc.ptr,
		ckbuf,
		C.size_t(len(kbuf)),
		cpbuf,
		C.size_t(len(pbuf)),
	)

	C.free(ckbuf)
	C.free(cpbuf)

	return acc, acc.lastError()
}

// Pickle encodes and encrypts an account to a string safe format
func (a Account) Pickle(key string) (string, error) {
	kbuf := []byte(key)
	plen := C.self_olm_pickle_account_length(a.ptr)
	pbuf := C.malloc(plen)
	ckbuf := C.CBytes(kbuf)

	C.self_olm_pickle_account(
		a.ptr,
		ckbuf,
		C.size_t(len(kbuf)),
		pbuf,
		C.size_t(plen),
	)

	data := C.GoBytes(pbuf, C.int(plen))

	C.free(pbuf)
	C.free(ckbuf)

	return string(data), a.lastError()
}

// Sign signs a message with the accounts ed25519 secret key
func (a Account) Sign(message []byte) ([]byte, error) {
	slen := C.self_olm_account_signature_length(a.ptr)
	sbuf := C.malloc(slen)
	cmbuf := C.CBytes(message)

	C.self_olm_account_sign(
		a.ptr,
		cmbuf,
		C.size_t(len(message)),
		sbuf,
		slen,
	)

	data := C.GoBytes(sbuf, C.int(slen))

	C.free(sbuf)
	// C.free(cmbuf)

	return data, a.lastError()
}

// MaxOneTimeKeys returns the maximum amount of keys an account can hold
func (a Account) MaxOneTimeKeys() int {
	return int(C.self_olm_account_max_number_of_one_time_keys(a.ptr))
}

// MarkKeysAsPublished marks the current set of one time keys as published
func (a Account) MarkKeysAsPublished() {
	C.self_olm_account_mark_keys_as_published(a.ptr)
}

// GenerateOneTimeKeys Generate a number of new one-time keys.
// If the total number of keys stored by this account exceeds
// max_one_time_keys() then the old keys are discarded
func (a Account) GenerateOneTimeKeys(count int) error {
	rlen := C.self_olm_account_generate_one_time_keys_random_length(
		a.ptr,
		C.size_t(count),
	)

	rbuf := make([]byte, rlen)
	crbuf := C.CBytes(rbuf)

	_, err := rand.Read(rbuf)
	if err != nil {
		return err
	}

	C.self_olm_account_generate_one_time_keys(
		a.ptr,
		C.size_t(count),
		crbuf,
		rlen,
	)

	C.free(crbuf)

	return a.lastError()
}

// OneTimeKeys returns the pulic component of the accounts one time keys
func (a Account) OneTimeKeys() (*OneTimeKeys, error) {
	var otk OneTimeKeys

	olen := C.self_olm_account_one_time_keys_length(a.ptr)
	obuf := C.malloc(olen)

	C.self_olm_account_one_time_keys(
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
	C.self_olm_remove_one_time_keys(a.ptr, s.ptr)

	return a.lastError()
}

// IdentityKeys returns the identity keys associated with the account
func (a Account) IdentityKeys() (*PublicKeys, error) {
	var keys PublicKeys

	olen := C.self_olm_account_identity_keys_length(a.ptr)
	obuf := C.malloc(olen)

	C.self_olm_account_identity_keys(
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
	errStr := C.GoString(C.self_olm_account_last_error(a.ptr))
	return Error(errStr)
}
