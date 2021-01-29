// Copyright 2020 Self Group Ltd. All Rights Reserved.

package selfcrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestSession(t *testing.T, sender *Account, recipient string) (*Account, *Session) {
	bob, err := NewAccount(recipient)
	require.Nil(t, err)

	err = bob.GenerateOneTimeKeys(1)
	require.Nil(t, err)

	otks, err := bob.OneTimeKeys()
	require.Nil(t, err)

	idks, err := bob.IdentityKeys()
	require.Nil(t, err)

	oneTimeKey := otks.Curve25519["AAAAAQ"]
	recipientsKey := idks.Curve25519

	session, err := CreateOutboundSession(sender, recipient, recipientsKey, oneTimeKey)
	require.Nil(t, err)

	return bob, session
}

func TestGroupSessionEncryptDecrypt(t *testing.T) {
	// setup alices group session
	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	alice, err := AccountFromSeed("alice:1", sk.Seed())

	require.Nil(t, err)

	accounts := make(map[string]*Account)
	var recipients []*Session

	for _, r := range []string{"bob:1", "charlie:1"} {
		a, s := createTestSession(t, alice, r)
		recipients = append(recipients, s)
		accounts[r] = a
	}

	gs, err := CreateGroupSession(alice, recipients)
	require.Nil(t, err)

	// encrypt the message
	ct, err := gs.Encrypt([]byte("hello there"))
	require.Nil(t, err)

	// verify the message for bob
	var rgm GroupMessage

	err = json.Unmarshal(ct, &rgm)
	require.Nil(t, err)

	bas, err := CreateInboundSession(accounts["bob:1"], "alice:1", rgm.Recipients["bob:1"])
	require.Nil(t, err)

	bgs, err := CreateGroupSession(accounts["bob:1"], []*Session{bas})
	require.Nil(t, err)

	pt, err := bgs.Decrypt("alice:1", ct)
	require.Nil(t, err)

	assert.Equal(t, []byte("hello there"), pt)

	// verify the message for charlie
	cas, err := CreateInboundSession(accounts["charlie:1"], "alice:1", rgm.Recipients["charlie:1"])
	require.Nil(t, err)

	cgs, err := CreateGroupSession(accounts["charlie:1"], []*Session{cas})
	require.Nil(t, err)

	pt, err = cgs.Decrypt("alice:1", ct)
	require.Nil(t, err)

	assert.Equal(t, []byte("hello there"), pt)

	for i := 0; i < 1000; i++ {
		ct, err := gs.Encrypt([]byte("hello"))
		require.Nil(t, err)

		pt, err := bgs.Decrypt("alice:1", ct)
		require.Nil(t, err)
		assert.Equal(t, "hello", string(pt))
	}
}
