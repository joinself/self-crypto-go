// Copyright 2020 Self Group Ltd. All Rights Reserved.

package selfcrypto

import (
	"encoding/base64"
)

var encoder = base64.RawStdEncoding

const (
	// PreKeyMessage is a message used to establish a session
	PreKeyMessage = 0
	// NormalMessage is a normal message
	NormalMessage = 1
)

// Message an encrypted olm message
type Message struct {
	Type       int    `json:"mtype"`
	Ciphertext string `json:"ciphertext"`
}

func (m *Message) encoded() []byte {
	return []byte(encoder.EncodeToString(m.copy()))
}

func (m *Message) copy() []byte {
	cp := make([]byte, len(m.Ciphertext))
	copy(cp, m.Ciphertext)
	return cp
}

func (m *Message) ciphertext() []byte {
	switch m.Type {
	case PreKeyMessage, NormalMessage:
		return m.copy()
	}
	return []byte{}
}
