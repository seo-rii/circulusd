package ed25519key

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"filippo.io/edwards25519"
)

func TestIsCanonicalPrimeOrderRejectsSmallOrderMixedOrderAndMalformedKeys(t *testing.T) {
	t.Parallel()

	publicKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if !IsCanonicalPrimeOrder(publicKey) {
		t.Fatal("IsCanonicalPrimeOrder(generated key) = false")
	}

	identity := make([]byte, ed25519.PublicKeySize)
	identity[0] = 1
	nonCanonicalIdentity := append([]byte(nil), identity...)
	nonCanonicalIdentity[31] = 0x80
	orderTwo := bytes.Repeat([]byte{0xff}, ed25519.PublicKeySize)
	orderTwo[0], orderTwo[31] = 0xec, 0x7f
	validPoint, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	torsion, err := new(edwards25519.Point).SetBytes(orderTwo)
	if err != nil {
		t.Fatal(err)
	}
	offCurve := make([]byte, ed25519.PublicKeySize)
	for offCurve[0] = 2; ; offCurve[0]++ {
		if _, err := new(edwards25519.Point).SetBytes(offCurve); err != nil {
			break
		}
	}

	for name, key := range map[string][]byte{
		"empty":                  nil,
		"short":                  publicKey[:ed25519.PublicKeySize-1],
		"long":                   append(append([]byte(nil), publicKey...), 0),
		"off curve":              offCurve,
		"identity":               identity,
		"non-canonical identity": nonCanonicalIdentity,
		"order two":              orderTwo,
		"order four":             make([]byte, ed25519.PublicKeySize),
		"mixed order":            new(edwards25519.Point).Add(validPoint, torsion).Bytes(),
	} {
		if IsCanonicalPrimeOrder(key) {
			t.Errorf("IsCanonicalPrimeOrder(%s) = true", name)
		}
	}
}
