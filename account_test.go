package olm

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testString = []byte("test-string")

func TestAccountCreateAccount(t *testing.T) {
	account, err := NewAccount("alice:1")
	require.NotNil(t, account)
	require.Nil(t, err)
}

func TestAccountCreateAccountFromSeed(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	account, err := AccountFromSeed("alice:1", sk.Seed())
	require.NotNil(t, account)
	require.Nil(t, err)

	sig, err := account.Sign(testString)
	require.Nil(t, err)

	rawSig, err := base64.RawStdEncoding.DecodeString(string(sig))
	require.Nil(t, err)
	assert.True(t, ed25519.Verify(pk, testString, rawSig))
}

func TestAccountPickle(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	account, err := AccountFromSeed("alice:1", sk.Seed())
	require.NotNil(t, account)
	require.Nil(t, err)

	pickle, err := account.Pickle("test")
	require.Nil(t, err)
	assert.NotEqual(t, 0, len(pickle))

	account, err = AccountFromPickle("alice:1", "test", pickle)
	require.Nil(t, err)
	require.NotNil(t, account)

	sig, err := account.Sign(testString)
	require.Nil(t, err)

	rawSig, err := base64.RawStdEncoding.DecodeString(string(sig))
	require.Nil(t, err)
	assert.True(t, ed25519.Verify(pk, testString, rawSig))
}

func TestAccountOneTimeKeys(t *testing.T) {
	account, err := NewAccount("alice:1")
	require.NotNil(t, account)
	require.Nil(t, err)

	err = account.GenerateOneTimeKeys(5)
	require.Nil(t, err)

	otk, err := account.OneTimeKeys()
	require.Nil(t, err)

	curve25519 := otk.Curve25519
	require.NotNil(t, curve25519)
	assert.Len(t, curve25519, 5)
}

func TestAccountIdentityKeys(t *testing.T) {
	account, err := NewAccount("alice:1")
	require.NotNil(t, account)
	require.Nil(t, err)

	keys, err := account.IdentityKeys()
	require.Nil(t, err)
	require.NotNil(t, keys)
	assert.NotEmpty(t, keys.Curve25519)
	assert.NotEmpty(t, keys.Ed25519)
}
