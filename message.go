package olm

import "encoding/base64"

var encoder = base64.RawStdEncoding

const (
	PreKeyMessage = 0
	NormalMessage = 1
)

// Message an encrypted olm message
type Message struct {
	Type       int    `json:"type"`
	Ciphertext []byte `json:"ciphertext"`
}

func (m *Message) encoded() []byte {
	return []byte(encoder.EncodeToString(m.Ciphertext))
}

func (m *Message) copy() []byte {
	cp := make([]byte, len(m.Ciphertext))
	copy(cp, m.Ciphertext)
	return cp
}

func (m *Message) ciphertext() []byte {
	switch m.Type {
	case PreKeyMessage:
		return m.encoded()
	case NormalMessage:
		return m.copy()
	}
	return []byte{}
}
