// Copyright 2020 Self Group Ltd. All Rights Reserved.

package selfcrypto

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
