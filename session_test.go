// Copyright 2020 Self Group Ltd. All Rights Reserved.

package selfcrypto

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

func TestSessionCreateOutboundSession(t *testing.T) {
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	account, err := NewAccount("alice:1")
	require.Nil(t, err)

	err = account.GenerateOneTimeKeys(1)
	require.Nil(t, err)

	oneTimeKeys, err := account.OneTimeKeys()
	require.Nil(t, err)

	recipient := "john:1"
	recipientsKey := base64.RawStdEncoding.EncodeToString(pk)
	oneTimeKey := oneTimeKeys.Curve25519["AAAAAQ"]

	session, err := CreateOutboundSession(account, recipient, recipientsKey, oneTimeKey)
	require.Nil(t, err)
	require.NotNil(t, session)
}

func TestSessionCreateInboundSession(t *testing.T) {
	alice, err := NewAccount("alice:1")
	require.Nil(t, err)

	bob, err := NewAccount("bob:1")
	require.Nil(t, err)

	err = bob.GenerateOneTimeKeys(1)
	require.Nil(t, err)

	otks, err := bob.OneTimeKeys()
	require.Nil(t, err)

	idks, err := bob.IdentityKeys()
	require.Nil(t, err)

	oneTimeKey := otks.Curve25519["AAAAAQ"]
	recipientsKey := idks.Curve25519

	session, err := CreateOutboundSession(alice, "bob:1", recipientsKey, oneTimeKey)
	require.Nil(t, err)

	msg, err := session.Encrypt([]byte("test message"))
	require.Nil(t, err)
	assert.NotEqual(t, 0, len(msg.Ciphertext))
	assert.NotEqual(t, []byte("test message"), msg.Ciphertext)
	assert.Equal(t, 0, msg.Type)

	_, err = CreateInboundSession(bob, "alice:1", msg)
	require.Nil(t, err)
}

func TestSessionEncryptDecrypt(t *testing.T) {
	alice, err := NewAccount("alice:1")
	require.Nil(t, err)

	bob, err := NewAccount("bob:1")
	require.Nil(t, err)

	err = bob.GenerateOneTimeKeys(1)
	require.Nil(t, err)

	otks, err := bob.OneTimeKeys()
	require.Nil(t, err)

	idks, err := bob.IdentityKeys()
	require.Nil(t, err)

	oneTimeKey := otks.Curve25519["AAAAAQ"]
	recipientsKey := idks.Curve25519

	aliceSession, err := CreateOutboundSession(alice, "bob:1", recipientsKey, oneTimeKey)
	require.Nil(t, err)

	msg, err := aliceSession.Encrypt([]byte("alice init"))
	require.Nil(t, err)

	bobSession, err := CreateInboundSession(bob, "alice:1", msg)
	require.Nil(t, err)

	err = bob.RemoveOneTimeKeys(bobSession)
	require.Nil(t, err)

	pt, err := bobSession.Decrypt(msg)
	require.Nil(t, err)
	assert.Equal(t, []byte("alice init"), pt)

	msg, err = bobSession.Encrypt([]byte("bob init"))
	require.Nil(t, err)

	pt, err = aliceSession.Decrypt(msg)
	require.Nil(t, err)
	assert.Equal(t, []byte("bob init"), pt)

	msg, err = aliceSession.Encrypt([]byte("hello"))
	require.Nil(t, err)

	pt, err = bobSession.Decrypt(msg)
	require.Nil(t, err)
	assert.Equal(t, []byte("hello"), pt)

	msg, err = bobSession.Encrypt([]byte("goodbye"))
	require.Nil(t, err)

	pt, err = aliceSession.Decrypt(msg)
	require.Nil(t, err)
	assert.Equal(t, []byte("goodbye"), pt)
}
