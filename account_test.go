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
	account, err := NewAccount()
	require.NotNil(t, account)
	require.Nil(t, err)
}

func TestAccountCreateAccountFromKeys(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	account, err := AccountFromKey(sk)
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

	account, err := AccountFromKey(sk)
	require.NotNil(t, account)
	require.Nil(t, err)

	pickle, err := account.Pickle("test")
	require.Nil(t, err)
	assert.NotEqual(t, 0, len(pickle))

	account, err = AccountFromPickle("test", pickle)
	require.Nil(t, err)
	require.NotNil(t, account)

	sig, err := account.Sign(testString)
	require.Nil(t, err)

	rawSig, err := base64.RawStdEncoding.DecodeString(string(sig))
	require.Nil(t, err)
	assert.True(t, ed25519.Verify(pk, testString, rawSig))
}

func TestAccountOneTimeKeys(t *testing.T) {
	account, err := NewAccount()
	require.NotNil(t, account)
	require.Nil(t, err)

	err = account.GenerateOneTimeKeys(5)
	require.Nil(t, err)

	otk, err := account.OneTimeKeys()
	require.Nil(t, err)

	curve25519, ok := otk["curve25519"].(map[string]interface{})
	assert.True(t, ok)
	require.NotNil(t, curve25519)
	assert.Len(t, curve25519, 5)
}
