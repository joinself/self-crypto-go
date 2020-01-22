package olm

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

func TestSessionCreateOutboundSession(t *testing.T) {
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	account, err := NewAccount()
	require.Nil(t, err)

	err = account.GenerateOneTimeKeys(1)
	require.Nil(t, err)

	oneTimeKeys, err := account.OneTimeKeys()
	require.Nil(t, err)

	recipientsKey := base64.RawStdEncoding.EncodeToString(pk)
	oneTimeKey := oneTimeKeys.Curve25519["AAAAAQ"]

	session, err := CreateOutboundSession(account, recipientsKey, oneTimeKey)
	require.Nil(t, err)
	require.NotNil(t, session)
}

func TestSessionCreateInboundSession(t *testing.T) {
	alice, err := NewAccount()
	require.Nil(t, err)

	bob, err := NewAccount()
	require.Nil(t, err)

	err = bob.GenerateOneTimeKeys(1)
	require.Nil(t, err)

	otks, err := bob.OneTimeKeys()
	require.Nil(t, err)

	idks, err := bob.IdentityKeys()
	require.Nil(t, err)

	oneTimeKey := otks.Curve25519["AAAAAQ"]
	recipientsKey := idks.Curve25519

	session, err := CreateOutboundSession(alice, recipientsKey, oneTimeKey)
	require.Nil(t, err)

	msgType, msg, err := session.Encrypt([]byte("test message"))
	require.Nil(t, err)
	assert.NotEqual(t, 0, len(msg))
	assert.NotEqual(t, []byte("test message"), msg)
	assert.Equal(t, 0, msgType)

	_, err = CreateInboundSession(bob, msg)
	require.Nil(t, err)
}

func TestSessionEncryptDecrypt(t *testing.T) {
	alice, err := NewAccount()
	require.Nil(t, err)

	bob, err := NewAccount()
	require.Nil(t, err)

	err = bob.GenerateOneTimeKeys(1)
	require.Nil(t, err)

	otks, err := bob.OneTimeKeys()
	require.Nil(t, err)

	idks, err := bob.IdentityKeys()
	require.Nil(t, err)

	oneTimeKey := otks.Curve25519["AAAAAQ"]
	recipientsKey := idks.Curve25519

	aliceSession, err := CreateOutboundSession(alice, recipientsKey, oneTimeKey)
	require.Nil(t, err)

	msgType, msg, err := aliceSession.Encrypt([]byte("init"))
	require.Nil(t, err)

	bobSession, err := CreateInboundSession(bob, msg)
	require.Nil(t, err)

	pt, err := bobSession.Decrypt(msgType, msg)
	require.Nil(t, err)
	fmt.Println(pt)
}
