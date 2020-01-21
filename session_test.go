package olm

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

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

	curve25519Keys := oneTimeKeys["curve25519"].(map[string]interface{})

	recipientsKey := base64.RawStdEncoding.EncodeToString(pk)
	oneTimeKey := curve25519Keys["AAAAAQ"].(string)

	session, err := CreateOutboundSession(account, recipientsKey, oneTimeKey)
	require.Nil(t, err)
	require.NotNil(t, session)
}
