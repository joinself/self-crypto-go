package olm

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import "errors"

// Ed25519PKToCurve25519 converts an Edwards 25519 public key to a Curve 25519 public key
func Ed25519PKToCurve25519(publicKey []byte) ([]byte, error) {
	if len(publicKey) < int(C.crypto_sign_publickeybytes()) {
		return nil, errors.New("provided public key is not the correct size")
	}

	c25519 := make([]byte, int(C.crypto_sign_publickeybytes()))

	success := int(
		C.crypto_sign_ed25519_pk_to_curve25519(
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
	if len(secretKey) < int(C.crypto_sign_publickeybytes()) {
		return nil, errors.New("provided private key is not the correct size")
	}

	c25519 := make([]byte, int(C.crypto_sign_secretkeybytes()))

	success := int(
		C.crypto_sign_ed25519_sk_to_curve25519(
			(*C.uchar)(&c25519[0]),
			(*C.uchar)(&secretKey[0]),
		),
	)

	if success != 0 {
		return nil, errors.New("could not convert private key")
	}

	return c25519, nil
}
