package selfcrypto

/*
#cgo darwin LDFLAGS: -L/usr/local/lib/ -lself_olm
#cgo linux LDFLAGS: -L/usr/lib/libself_olm.so -lself_olm
#cgo darwin LDFLAGS: -L/usr/local/lib/ -lself_omemo
#cgo linux LDFLAGS: -L/usr/lib/libself_omemo.so -lself_omemo
#include <self_olm/olm.h>
#include <self_omemo.h>
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

// GroupSession stores all recipients of a group message
type GroupSession struct {
	acc        *Account
	recipients []*Session
	ptr    *C.GroupSession
	cstrings   []unsafe.Pointer
}

// GroupMessage group message
type GroupMessage struct {
	Recipients map[string]*Message `json:"recipients"`
	Ciphertext string              `json:"ciphertext"`
}

// CreateGroupSession creates a group session from a number of participants
func CreateGroupSession(account *Account, recipients []*Session) (*GroupSession, error) {
	cstrings := make([]unsafe.Pointer, 0, len(recipients))

	session := C.omemo_create_group_session()

	id := C.CString(account.identity)
	cstrings = append(cstrings, unsafe.Pointer(id))

	C.omemo_set_identity(session, id)

	for _, r := range recipients {
		if r.recipient == "" {
			return nil, errors.New("cannot provide a recipients session with no defined recipient")
		}

		rid := C.CString(r.recipient)

		C.omemo_add_group_participant(session, rid, r.ptr)

		cstrings = append(cstrings, unsafe.Pointer(rid))
	}

	return &GroupSession{
		acc:        account,
		recipients: recipients,
		ptr:        session,
		cstrings:   cstrings,
	}, nil
}


func (gs *GroupSession) Encrypt(message []byte) ([]byte, error){
	sz := C.omemo_encrypted_size(
		gs.ptr,
		C.ulong(len(message)),
	)

	buf := make([]byte, sz)

	sz = C.omemo_encrypt(
		gs.ptr,
		(*C.uchar)(&message[0]),
		C.ulong(len(message)),
		(*C.uchar)(&buf[0]),
		sz,
	)

	if sz == 0 {
		return nil, errors.New("failed to encrypt")
	}

	return buf[:sz], nil
}

func (gs *GroupSession) Decrypt(sender string, message []byte) ([]byte, error) {
	sz := C.omemo_decrypted_size(
		gs.ptr,
		(*C.uchar)(&message[0]),
		C.ulong(len(message)),
	)

	buf := make([]byte, sz)

	sid := C.CString(sender)

	sz = C.omemo_decrypt(
		gs.ptr,
		sid,
		(*C.uchar)(&buf[0]),
		sz,
		(*C.uchar)(&message[0]),
		C.ulong(len(message)),
	)

	C.free(unsafe.Pointer(sid))

	if sz == 0 {
		return nil, errors.New("failed to decrypt")
	}

	return buf[:sz], nil
}

// Close clears up any allocated memory for the group session
func (gs *GroupSession) Close() {
	for i := range gs.cstrings {
		C.free(gs.cstrings[i])
	}

	C.omemo_destroy_group_session(gs.ptr)
}
