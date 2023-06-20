// Copyright 2020 Self Group Ltd. All Rights Reserved.

package selfcrypto

/*
#cgo LDFLAGS: -lstdc++
#cgo darwin LDFLAGS: -L/usr/local/lib/ -lself_omemo
#cgo linux LDFLAGS: -L/usr/lib/libself_omemo.a -lself_omemo
#include <self_omemo.h>
*/
import "C"
import (
	"errors"
)

type zero struct {
}

func (z zero) Read(b []byte) (int, error) {
	for i := 0; i < len(b); i++ {
		b[i] = byte(0)
	}

	return len(b), nil
}

// Ed25519FromSeed creates an ed25519 secret key from a seed
func Ed25519FromSeed(seed []byte) ([]byte, []byte, error) {
	ed25519SK := make([]byte, int(C.self_crypto_sign_secretkeybytes()))
	ed25519PK := make([]byte, int(C.self_crypto_sign_publickeybytes()))

	success := int(
		C.self_crypto_sign_seed_keypair(
			(*C.uchar)(&ed25519PK[0]),
			(*C.uchar)(&ed25519SK[0]),
			(*C.uchar)(&seed[0]),
		),
	)

	if success != 0 {
		return nil, nil, errors.New("could not convert ed25519 key")
	}

	return ed25519PK, ed25519SK, nil
}

// Ed25519PKToCurve25519 converts an Edwards 25519 public key to a Curve 25519 public key
func Ed25519PKToCurve25519(publicKey []byte) ([]byte, error) {
	if len(publicKey) < int(C.self_crypto_sign_publickeybytes()) {
		return nil, errors.New("provided public key is not the correct size")
	}

	c25519 := make([]byte, int(C.self_crypto_sign_publickeybytes()))

	success := int(
		C.self_crypto_sign_ed25519_pk_to_curve25519(
			(*C.uchar)(&c25519[0]),
			(*C.uchar)(&publicKey[0]),
		),
	)

	if success != 0 {
		return nil, errors.New("could not convert public key")
	}

	return c25519, nil
}

// Ed25519SKToCurve25519 converts an Edwards 25519 private key to a Curve 25519 private key
func Ed25519SKToCurve25519(secretKey []byte) ([]byte, error) {
	if len(secretKey) < int(C.self_crypto_sign_secretkeybytes()) {
		return nil, errors.New("provided private key is not the correct size")
	}

	c25519 := make([]byte, int(C.self_crypto_sign_secretkeybytes()))

	success := int(
		C.self_crypto_sign_ed25519_sk_to_curve25519(
			(*C.uchar)(&c25519[0]),
			(*C.uchar)(&secretKey[0]),
		),
	)

	if success != 0 {
		return nil, errors.New("could not convert private key")
	}

	return c25519, nil
}
