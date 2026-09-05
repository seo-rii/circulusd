package canonical

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

// canonicalFuzzSeeds returns canonical encodings of representative values plus
// adversarial raw byte strings that Decode must reject. Seeds only widen the
// fuzzer's starting coverage; the invariants live in the fuzz body.
func canonicalFuzzSeeds(tb testing.TB) [][]byte {
	tb.Helper()
	options := DefaultOptions()
	values := []Value{
		nil, true, false,
		int64(0), int64(23), int64(24), int64(255), int64(256), int64(65535), int64(65536),
		int64(-1), int64(-24), int64(-256), int64(maxSafeInteger), -int64(maxSafeInteger),
		"", "a", "hello", "café",
		Bytes{}, Bytes{0x00, 0x01, 0x02},
		Array{}, Array{int64(1), "two", Bytes{0x03}},
		Map{}, Map{"a": int64(1), "bb": int64(2), "c": Array{true, nil}},
		Array{Map{"k": "v"}, Array{int64(1), int64(2)}},
	}
	seeds := make([][]byte, 0, len(values)+9)
	for _, value := range values {
		encoded, err := Encode(value, options)
		if err != nil {
			tb.Fatalf("seed Encode(%#v) error = %v", value, err)
		}
		seeds = append(seeds, encoded)
	}
	// Adversarial encodings that Decode MUST reject (non-canonical or unsupported).
	seeds = append(seeds,
		[]byte{0x18, 0x01},       // non-minimal uint (1 in two bytes)
		[]byte{0x19, 0x00, 0x17}, // non-minimal uint (23 in three bytes)
		[]byte{0x1f},             // reserved additional info 31
		[]byte{0x9f, 0xff},       // indefinite-length array
		[]byte{0xc0, 0x00},       // tagged value
		[]byte{0xf9, 0x00, 0x00}, // half-float simple value
		[]byte{0x00, 0x00},       // trailing bytes after a value
		[]byte{0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02}, // map keys "b","a" out of order
		[]byte{0xa1, 0x01, 0x01},                         // map with a non-text key
	)
	return seeds
}

// FuzzDecodeCanonical asserts the two load-bearing properties of the canonical
// codec against arbitrary input:
//
//   - Decode never panics; malformed input yields an error, never a crash.
//   - Canonical CBOR is a bijection, so anything Decode accepts MUST be the
//     unique canonical encoding of its value: re-encoding the decoded value has
//     to reproduce the exact input bytes. A counterexample is a canonical-form
//     malleability bug — two byte strings mapping to one digest — which would
//     let an attacker forge a second pre-image for any StructuredDigest.
func FuzzDecodeCanonical(f *testing.F) {
	options := DefaultOptions()
	for _, seed := range canonicalFuzzSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		value, err := Decode(data, options)
		if err != nil {
			return // rejection is always acceptable; the contract is "never panic".
		}
		reencoded, err := Encode(value, options)
		if err != nil {
			t.Fatalf("decoded value could not be re-encoded: %v\ninput: %x", err, data)
		}
		if !bytes.Equal(reencoded, data) {
			t.Fatalf("Decode accepted a non-canonical encoding:\n input: %x\nreencoded: %x", data, reencoded)
		}
		roundTrip, err := Decode(reencoded, options)
		if err != nil {
			t.Fatalf("re-encoded canonical bytes failed to decode: %v", err)
		}
		reencodedAgain, err := Encode(roundTrip, options)
		if err != nil {
			t.Fatalf("second re-encode failed: %v", err)
		}
		if !bytes.Equal(reencoded, reencodedAgain) {
			t.Fatalf("encode is not deterministic:\n first: %x\nsecond: %x", reencoded, reencodedAgain)
		}
		firstDigest, firstErr := StructuredDigest("circulusd.fuzz", 1, value)
		secondDigest, secondErr := StructuredDigest("circulusd.fuzz", 1, value)
		if (firstErr == nil) != (secondErr == nil) || firstDigest != secondDigest {
			t.Fatalf("StructuredDigest not deterministic: %q/%v vs %q/%v",
				firstDigest, firstErr, secondDigest, secondErr)
		}
	})
}

// TestCanonicalConcurrentUse hammers the stateless codec from many goroutines so
// the race detector proves Encode/Decode/StructuredDigest share no mutable
// state and stay deterministic under contention.
func TestCanonicalConcurrentUse(t *testing.T) {
	t.Parallel()
	options := DefaultOptions()
	value := Array{
		"circulusd", int64(1),
		Map{"a": int64(1), "bb": Array{true, nil, Bytes{0x01, 0x02}}, "ccc": "café"},
	}
	encoded, err := Encode(value, options)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	digest, err := StructuredDigest("circulusd.concurrent", 1, value)
	if err != nil {
		t.Fatalf("StructuredDigest() error = %v", err)
	}

	const workers, iterations = 32, 200
	var waitGroup sync.WaitGroup
	failures := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				gotEncoded, err := Encode(value, options)
				if err != nil {
					failures <- fmt.Errorf("Encode: %w", err)
					return
				}
				if !bytes.Equal(gotEncoded, encoded) {
					failures <- fmt.Errorf("Encode is not deterministic")
					return
				}
				decoded, err := Decode(gotEncoded, options)
				if err != nil {
					failures <- fmt.Errorf("Decode: %w", err)
					return
				}
				reencoded, err := Encode(decoded, options)
				if err != nil {
					failures <- fmt.Errorf("re-Encode: %w", err)
					return
				}
				if !bytes.Equal(reencoded, encoded) {
					failures <- fmt.Errorf("round-trip drift")
					return
				}
				gotDigest, err := StructuredDigest("circulusd.concurrent", 1, value)
				if err != nil {
					failures <- fmt.Errorf("StructuredDigest: %w", err)
					return
				}
				if gotDigest != digest {
					failures <- fmt.Errorf("StructuredDigest is not deterministic")
					return
				}
			}
		}()
	}
	waitGroup.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
}
