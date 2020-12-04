// Copyright 2020 Self Group Ltd. All Rights Reserved.

package selfcrypto

// PublicKeys stores an accounts public keys
type PublicKeys struct {
	Ed25519    string `json:"ed25519"`
	Curve25519 string `json:"curve25519"`
}

// OneTimeKeys stores an accounts one time keys
type OneTimeKeys struct {
	Ed25519    map[string]string `json:"ed25519"`
	Curve25519 map[string]string `json:"curve25519"`
}
