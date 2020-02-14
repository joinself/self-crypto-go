package olm

import (
    "golang.org/x/crypto/chacha20poly1305"
    "crypto/rand"
    "encoding/json"
    "errors"
)

// GroupSession stores all recipients of a group message
type GroupSession struct {
	acc        *Account
	recipients []*Session
}

// GroupMessage group message
type GroupMessage struct {
	Recipients map[string]*Message `json:"recipients"`
	Ciphertext []byte              `json:"ciphertext"`
}

// CreateGroupSession creates a group session from a number of participants
func CreateGroupSession(account *Account, recipients []*Session) (*GroupSession, error) {
    for _, r := range recipients {
        if r.recipient == "" {
            return nil, errors.New("cannot provide a recipients session with no defined recipient")
        }
    }

	return &GroupSession{
		acc:    account,
		recipients: recipients,
	}, nil
}

// Encrypt encrypts a message for all recipients
func (gs *GroupSession) Encrypt(message []byte) ([]byte, error) {
    // encrypt the plaintext with a random key and nonce
    key := make([]byte, chacha20poly1305.KeySize)
    nonce := make([]byte, chacha20poly1305.NonceSizeX)

    _, err := rand.Read(key)
    if err != nil {
        return nil, err
    }

    _, err = rand.Read(nonce)
    if err != nil {
        return nil, err
    }

    aead, err := chacha20poly1305.NewX(key)
    if err != nil {
        return nil, err
    }

    gm := GroupMessage{
        Recipients: make(map[string]*Message),
        Ciphertext: aead.Seal(nil, nonce, []byte(message), nil),
    }

    // ecrypt each key with recipients session
    for _, s := range gs.recipients {
        gm.Recipients[s.recipient], err = s.Encrypt(append(key, nonce...))
        if err != nil {
            return nil, err
        }
    }

    return json.Marshal(gm)
}

// Decrypt a message from a recipient
func (gs *GroupSession) Decrypt(sender string, message []byte) ([]byte, error) {
    rs := gs.GetRecipientSession(sender)
    if rs == nil {
        return nil, errors.New("group session does not contain a session for this sender")
    }

    var gm GroupMessage

    err := json.Unmarshal(message, &gm)
    if err != nil {
        return nil, err
    }

    kmsg, ok := gm.Recipients[gs.acc.identity]
    if !ok {
        return nil, errors.New("received message is not intended for this identity")
    }

    keyNonce, err := rs.Decrypt(kmsg)
    if err != nil {
        return nil, err
    }

    if len(keyNonce) != chacha20poly1305.KeySize + chacha20poly1305.NonceSizeX {
        return nil, errors.New("message key and nonce are of an invalid size")
    }

    key := keyNonce[:chacha20poly1305.KeySize]
    nonce := keyNonce[chacha20poly1305.KeySize:]

    aead, err := chacha20poly1305.NewX(key)
    if err != nil {
        return nil, err
    }

    return aead.Open(nil, nonce, gm.Ciphertext, nil)
}

// GetRecipientSession returns the session of an identity if an identity is a recipient in the group session
func (gs *GroupSession) GetRecipientSession(recipient string) *Session {
    for _, r := range gs.recipients {
        if r.recipient == recipient {
            return r
        }
    }

    return nil
}
