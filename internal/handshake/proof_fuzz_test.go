package handshake

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

// FuzzVerifyNonceProof exercises the sandbox handshake proof check at its
// cryptographic boundary. For fuzz-varied request/response shapes it asserts:
//
//   - verification never panics.
//   - the correct HMAC proof is accepted (no false rejects).
//   - any single-bit tampering of the proof, verifying under the wrong nonce,
//     or a truncated proof is rejected (no forgery / no length confusion).
func FuzzVerifyNonceProof(f *testing.F) {
	f.Add([]byte("nonce-seed"), uint8(0), uint64(1), uint8(0))
	f.Add([]byte{}, uint8(3), uint64(0), uint8(31))
	f.Add([]byte("another-seed-value"), uint8(1), uint64(7), uint8(5))

	peers := []Peer{PeerPlatformd, PeerExecutord, PeerSandboxd, PeerPlatformctl}
	f.Fuzz(func(t *testing.T, nonceSeed []byte, peerIndex uint8, major uint64, tamper uint8) {
		nonce := sha256.Sum256(nonceSeed) // exactly NonceSize bytes
		clientPeer := peers[int(peerIndex)%len(peers)]
		serverPeer := peers[(int(peerIndex)+1)%len(peers)]

		request := Request{
			Peer:              clientPeer,
			MinimumVersion:    Version{Major: major % 4},
			MaximumVersion:    Version{Major: major % 4, Minor: 1},
			FeatureBitmap:     FeatureBitmap(major),
			MaximumFrameSize:  1 << 16,
			SandboxGeneration: major,
		}
		response := Response{
			SelectedVersion:  Version{Major: major % 4, Minor: 1},
			FeatureBitmap:    FeatureBitmap(major),
			MaximumFrameSize: 1 << 16,
		}

		transcript, err := handshakeTranscript(request, response, serverPeer)
		if err != nil {
			// Without a transcript there is no valid proof; verification must reject.
			response.NonceProof = make([]byte, sha256.Size)
			if VerifyNonceProof(nonce[:], request, response, serverPeer) {
				t.Fatal("VerifyNonceProof accepted a proof despite a transcript error")
			}
			return
		}

		mac := hmac.New(sha256.New, nonce[:])
		_, _ = mac.Write(transcript)
		correct := mac.Sum(nil)

		response.NonceProof = correct
		if !VerifyNonceProof(nonce[:], request, response, serverPeer) {
			t.Fatal("VerifyNonceProof rejected the correct proof")
		}

		tampered := append([]byte(nil), correct...)
		tampered[int(tamper)%len(tampered)] ^= 0x01
		response.NonceProof = tampered
		if VerifyNonceProof(nonce[:], request, response, serverPeer) {
			t.Fatal("VerifyNonceProof accepted a single-bit-tampered proof")
		}

		response.NonceProof = correct
		wrongNonce := sha256.Sum256(append([]byte{0x00}, nonceSeed...))
		if VerifyNonceProof(wrongNonce[:], request, response, serverPeer) {
			t.Fatal("VerifyNonceProof accepted the correct proof under the wrong nonce")
		}

		response.NonceProof = correct[:sha256.Size-1]
		if VerifyNonceProof(nonce[:], request, response, serverPeer) {
			t.Fatal("VerifyNonceProof accepted a truncated proof")
		}
	})
}
