package olm

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

var testString = []byte("test-string")

func TestAccountCreateNewAccount(t *testing.T) {
	account, err := NewAccount()
	require.NotNil(t, account)
	require.Nil(t, err)

	/*
		p := account.Pickle("test")

		rawp, err := base64.RawStdEncoding.DecodeString(p)
		require.Nil(t, err)

		kdfInfo := []byte("Pickle")
		h := hkdf.Expand(sha256.New, []byte("test"), kdfInfo)

		kdfKey := make([]byte, 32)
		_, err = io.ReadAtLeast(h, kdfKey, 32)
		require.Nil(t, err)

		b, err := aes.NewCipher(kdfKey)
		require.Nil(t, err)

		var output []byte
		var pos int

		for pos < len(rawp) {
			buf := make([]byte, b.BlockSize())

			end := pos + b.BlockSize()
			if end > len(rawp) {
				end = len(rawp)
			}

			b.Decrypt(buf, rawp[pos:end])
			output = append(output, buf...)
			pos = pos + b.BlockSize()
		}

		fmt.Println("output:", output)
	*/
}

func TestAccountCreateAccountFromKeys(t *testing.T) {
	pk, ed25519SK, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	account := AccountFromKey(ed25519SK)
	require.NotNil(t, account)

	sig := account.Sign(testString)

	rawSig, err := base64.RawStdEncoding.DecodeString(string(sig))
	require.Nil(t, err)
	require.True(t, ed25519.Verify(pk, testString, rawSig))
}
