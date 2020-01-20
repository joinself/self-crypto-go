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

func TestAccountCreateNewAccount(t *testing.T) {
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
