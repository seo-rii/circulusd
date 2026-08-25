package handshake

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hancomac/circulusd/internal/identity"
)

func TestSandboxNegotiatorBindsAndConsumesOneTimeHandshake(t *testing.T) {
	t.Parallel()

	negotiator, request, nonce := validNegotiator(t)
	response, err := negotiator.Negotiate(request)
	if err != nil {
		t.Fatalf("Negotiate() error = %v", err)
	}
	if response.SelectedVersion != (Version{Major: 1, Minor: 2}) {
		t.Fatalf("selected version = %#v", response.SelectedVersion)
	}
	if response.FeatureBitmap != FeatureProcessStreaming|FeatureReadOnlyWorkspace {
		t.Fatalf("selected features = %#x", response.FeatureBitmap)
	}
	if response.MaximumFrameSize != 32<<10 {
		t.Fatalf("maximum frame size = %d", response.MaximumFrameSize)
	}
	if !VerifyNonceProof(nonce, request, response, PeerSandboxd) {
		t.Fatal("VerifyNonceProof() = false")
	}
	response.MaximumFrameSize++
	if VerifyNonceProof(nonce, request, response, PeerSandboxd) {
		t.Fatal("VerifyNonceProof(tampered response) = true")
	}
	response.MaximumFrameSize--
	request.DescriptorDigest[0] ^= 0xff
	if VerifyNonceProof(nonce, request, response, PeerSandboxd) {
		t.Fatal("VerifyNonceProof(tampered request descriptor) = true")
	}
	if _, err := negotiator.Negotiate(request); !errors.Is(err, ErrHandshakeConsumed) {
		t.Fatalf("second Negotiate() error = %v, want ErrHandshakeConsumed", err)
	}
}

func TestSandboxNegotiatorRejectsUnencodableFeatureBitmaps(t *testing.T) {
	t.Parallel()

	negotiator, request, _ := validNegotiator(t)
	request.FeatureBitmap |= FeatureBitmap(1) << 63
	if _, err := negotiator.Negotiate(request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Negotiate(high feature bit) error = %v, want ErrInvalidRequest", err)
	}
	request.FeatureBitmap &^= FeatureBitmap(1) << 63
	if _, err := negotiator.Negotiate(request); err != nil {
		t.Fatalf("Negotiate(valid after high feature bit) error = %v", err)
	}

	nonce := bytes.Repeat([]byte{1}, NonceSize)
	sandboxID := fixedSandboxID(t, 3)
	_, err := NewSandboxNegotiator(Config{
		ServerPeer:        PeerSandboxd,
		AllowedClientPeer: PeerExecutord,
		MinimumVersion:    Version{Major: 1},
		MaximumVersion:    Version{Major: 1},
		SupportedFeatures: FeatureBitmap(1) << 63,
		MinimumFrameSize:  1,
		MaximumFrameSize:  1,
		DescriptorDigest:  [DigestSize]byte{1},
		SandboxID:         sandboxID,
		SandboxGeneration: 1,
		OneTimeNonce:      nonce,
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewSandboxNegotiator(high feature bit) error = %v, want ErrInvalidConfig", err)
	}
}

func TestSandboxNegotiatorRejectsInvalidBindingsWithoutConsumingNonce(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Request)
		want   error
	}{
		{name: "peer", mutate: func(request *Request) { request.Peer = PeerPlatformd }, want: ErrPeerRejected},
		{name: "version", mutate: func(request *Request) {
			request.MinimumVersion = Version{Major: 2}
			request.MaximumVersion = Version{Major: 2, Minor: 1}
		}, want: ErrUnsupportedProtocol},
		{name: "feature", mutate: func(request *Request) {
			request.FeatureBitmap &^= FeatureProcessStreaming
		}, want: ErrMissingFeature},
		{name: "frame", mutate: func(request *Request) {
			request.MaximumFrameSize = 512
		}, want: ErrFrameSize},
		{name: "descriptor", mutate: func(request *Request) {
			request.DescriptorDigest[0] ^= 0xff
		}, want: ErrDescriptorMismatch},
		{name: "nonce", mutate: func(request *Request) {
			request.OneTimeNonce[0] ^= 0xff
		}, want: ErrNonceMismatch},
		{name: "sandbox", mutate: func(request *Request) {
			request.SandboxID = fixedSandboxID(t, 2)
		}, want: ErrSandboxBinding},
		{name: "generation", mutate: func(request *Request) {
			request.SandboxGeneration++
		}, want: ErrSandboxBinding},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			negotiator, valid, _ := validNegotiator(t)
			invalid := valid
			invalid.OneTimeNonce = append([]byte(nil), valid.OneTimeNonce...)
			test.mutate(&invalid)
			if _, err := negotiator.Negotiate(invalid); !errors.Is(err, test.want) {
				t.Fatalf("Negotiate(invalid) error = %v, want %v", err, test.want)
			}
			if _, err := negotiator.Negotiate(valid); err != nil {
				t.Fatalf("Negotiate(valid after rejection) error = %v", err)
			}
		})
	}
}

func TestSandboxNegotiatorAllowsExactlyOneConcurrentSuccess(t *testing.T) {
	t.Parallel()

	negotiator, request, _ := validNegotiator(t)
	const callers = 64
	start := make(chan struct{})
	var successes atomic.Int64
	var consumed atomic.Int64
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := negotiator.Negotiate(request)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrHandshakeConsumed):
				consumed.Add(1)
			default:
				t.Errorf("Negotiate() error = %v", err)
			}
		}()
	}
	close(start)
	wait.Wait()
	if successes.Load() != 1 || consumed.Load() != callers-1 {
		t.Fatalf("successes = %d, consumed = %d", successes.Load(), consumed.Load())
	}
}

func TestSandboxNegotiatorSnapshotsNonceAndRedactsRequests(t *testing.T) {
	t.Parallel()

	negotiator, request, nonce := validNegotiator(t)
	originalNonce := append([]byte(nil), nonce...)
	for index := range nonce {
		nonce[index] ^= 0xff
	}
	if _, err := negotiator.Negotiate(request); err != nil {
		t.Fatalf("Negotiate() after caller nonce mutation error = %v", err)
	}

	rendered := fmt.Sprintf("%v %#v", request, request)
	if strings.Contains(rendered, fmt.Sprintf("%x", originalNonce)) ||
		strings.Contains(rendered, string(originalNonce)) {
		t.Fatalf("request formatting exposed nonce: %s", rendered)
	}
}

func validNegotiator(t *testing.T) (*Negotiator, Request, []byte) {
	t.Helper()

	nonce := bytes.Repeat([]byte{0x5a}, NonceSize)
	descriptor := [DigestSize]byte{1, 2, 3}
	sandboxID := fixedSandboxID(t, 1)
	negotiator, err := NewSandboxNegotiator(Config{
		ServerPeer:        PeerSandboxd,
		AllowedClientPeer: PeerExecutord,
		MinimumVersion:    Version{Major: 1, Minor: 1},
		MaximumVersion:    Version{Major: 1, Minor: 3},
		SupportedFeatures: FeatureProcessStreaming | FeatureReadOnlyWorkspace | FeatureWorkspaceProtection,
		RequiredFeatures:  FeatureProcessStreaming,
		MinimumFrameSize:  4 << 10,
		MaximumFrameSize:  64 << 10,
		DescriptorDigest:  descriptor,
		SandboxID:         sandboxID,
		SandboxGeneration: 7,
		OneTimeNonce:      nonce,
	})
	if err != nil {
		t.Fatalf("NewSandboxNegotiator() error = %v", err)
	}
	return negotiator, Request{
		Peer:              PeerExecutord,
		MinimumVersion:    Version{Major: 1},
		MaximumVersion:    Version{Major: 1, Minor: 2},
		FeatureBitmap:     FeatureProcessStreaming | FeatureReadOnlyWorkspace,
		MaximumFrameSize:  32 << 10,
		DescriptorDigest:  descriptor,
		OneTimeNonce:      append([]byte(nil), nonce...),
		SandboxID:         sandboxID,
		SandboxGeneration: 7,
	}, nonce
}

func fixedSandboxID(t *testing.T, fill byte) identity.ID {
	t.Helper()

	id, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte{fill}, 16))}).New(identity.Sandbox)
	if err != nil {
		t.Fatalf("generate sandbox ID: %v", err)
	}
	return id
}
