// Package ed25519key validates Ed25519 public keys that act as signing
// trust roots.
package ed25519key

import (
	"bytes"
	"crypto/ed25519"

	"filippo.io/edwards25519"
)

var inverseCofactor = func() edwards25519.Scalar {
	var encoded [32]byte
	encoded[0] = 8
	cofactor, err := edwards25519.NewScalar().SetCanonicalBytes(encoded[:])
	if err != nil {
		panic("ed25519key: invalid internal Ed25519 cofactor")
	}
	return *edwards25519.NewScalar().Invert(cofactor)
}()

// IsCanonicalPrimeOrder reports whether publicKey is the canonical encoding
// of a non-identity point in the prime-order subgroup. crypto/ed25519 accepts
// any 32-byte point encoding: under a small-order key such as the identity a
// fixed signature verifies every message, and non-canonical or mixed-order
// encodings let one authority appear under distinct key material.
func IsCanonicalPrimeOrder(publicKey []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	point, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil || !bytes.Equal(point.Bytes(), publicKey) || point.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}
	projection := new(edwards25519.Point).ScalarMult(&inverseCofactor, new(edwards25519.Point).MultByCofactor(point))
	return projection.Equal(point) == 1
}
