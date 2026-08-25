package handshake

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"sync"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

const maxProtocolInteger = uint64(9_007_199_254_740_991)

type Negotiator struct {
	mu sync.Mutex

	config   Config
	nonce    []byte
	consumed bool
}

func NewSandboxNegotiator(config Config) (*Negotiator, error) {
	if config.ServerPeer != PeerSandboxd || config.AllowedClientPeer != PeerExecutord {
		return nil, fmt.Errorf("%w: sandboxd accepts only executord", ErrInvalidConfig)
	}
	if config.MinimumVersion.Major == 0 ||
		config.MinimumVersion.Major != config.MaximumVersion.Major ||
		config.MinimumVersion.Minor > config.MaximumVersion.Minor ||
		config.MaximumVersion.Major > maxProtocolInteger ||
		config.MaximumVersion.Minor > maxProtocolInteger {
		return nil, fmt.Errorf("%w: supported version range is invalid", ErrInvalidConfig)
	}
	if config.RequiredFeatures&config.SupportedFeatures != config.RequiredFeatures {
		return nil, fmt.Errorf("%w: required features are not supported", ErrInvalidConfig)
	}
	if uint64(config.SupportedFeatures) > maxProtocolInteger ||
		uint64(config.RequiredFeatures) > maxProtocolInteger {
		return nil, fmt.Errorf("%w: feature bitmap exceeds the shared integer range", ErrInvalidConfig)
	}
	if config.MinimumFrameSize == 0 ||
		config.MinimumFrameSize > config.MaximumFrameSize ||
		config.MaximumFrameSize > maxProtocolInteger {
		return nil, fmt.Errorf("%w: frame size bounds are invalid", ErrInvalidConfig)
	}
	if config.DescriptorDigest == ([DigestSize]byte{}) {
		return nil, fmt.Errorf("%w: descriptor digest is empty", ErrInvalidConfig)
	}
	if config.SandboxID.Kind() != identity.Sandbox || config.SandboxID.String() == "" {
		return nil, fmt.Errorf("%w: sandbox identity is invalid", ErrInvalidConfig)
	}
	if config.SandboxGeneration == 0 || config.SandboxGeneration > maxProtocolInteger {
		return nil, fmt.Errorf("%w: sandbox generation is invalid", ErrInvalidConfig)
	}
	if len(config.OneTimeNonce) != NonceSize {
		return nil, fmt.Errorf("%w: one-time nonce must be %d bytes", ErrInvalidConfig, NonceSize)
	}

	nonce := append([]byte(nil), config.OneTimeNonce...)
	config.OneTimeNonce = nil
	return &Negotiator{config: config, nonce: nonce}, nil
}

func (negotiator *Negotiator) Negotiate(request Request) (Response, error) {
	if negotiator == nil {
		return Response{}, fmt.Errorf("%w: negotiator is nil", ErrInvalidConfig)
	}

	negotiator.mu.Lock()
	defer negotiator.mu.Unlock()

	if negotiator.consumed {
		return Response{}, ErrHandshakeConsumed
	}
	if request.Peer != negotiator.config.AllowedClientPeer {
		return Response{}, ErrPeerRejected
	}
	if len(request.OneTimeNonce) != NonceSize ||
		subtle.ConstantTimeCompare(request.OneTimeNonce, negotiator.nonce) != 1 {
		return Response{}, ErrNonceMismatch
	}
	if request.SandboxID != negotiator.config.SandboxID ||
		request.SandboxGeneration != negotiator.config.SandboxGeneration {
		return Response{}, ErrSandboxBinding
	}
	if request.MinimumVersion.Major == 0 ||
		request.MinimumVersion.Major != request.MaximumVersion.Major ||
		request.MinimumVersion.Minor > request.MaximumVersion.Minor ||
		request.MaximumVersion.Major > maxProtocolInteger ||
		request.MaximumVersion.Minor > maxProtocolInteger {
		return Response{}, fmt.Errorf("%w: requested version range is invalid", ErrInvalidRequest)
	}
	if request.MinimumVersion.Major != negotiator.config.MinimumVersion.Major {
		return Response{}, ErrUnsupportedProtocol
	}
	minimumMinor := request.MinimumVersion.Minor
	if negotiator.config.MinimumVersion.Minor > minimumMinor {
		minimumMinor = negotiator.config.MinimumVersion.Minor
	}
	maximumMinor := request.MaximumVersion.Minor
	if negotiator.config.MaximumVersion.Minor < maximumMinor {
		maximumMinor = negotiator.config.MaximumVersion.Minor
	}
	if minimumMinor > maximumMinor {
		return Response{}, ErrUnsupportedProtocol
	}
	if request.FeatureBitmap&negotiator.config.RequiredFeatures != negotiator.config.RequiredFeatures {
		return Response{}, ErrMissingFeature
	}
	if uint64(request.FeatureBitmap) > maxProtocolInteger {
		return Response{}, fmt.Errorf("%w: feature bitmap exceeds the shared integer range", ErrInvalidRequest)
	}
	maximumFrameSize := request.MaximumFrameSize
	if negotiator.config.MaximumFrameSize < maximumFrameSize {
		maximumFrameSize = negotiator.config.MaximumFrameSize
	}
	if maximumFrameSize < negotiator.config.MinimumFrameSize ||
		request.MaximumFrameSize > maxProtocolInteger {
		return Response{}, ErrFrameSize
	}
	if subtle.ConstantTimeCompare(
		request.DescriptorDigest[:],
		negotiator.config.DescriptorDigest[:],
	) != 1 {
		return Response{}, ErrDescriptorMismatch
	}

	response := Response{
		SelectedVersion: Version{
			Major: negotiator.config.MaximumVersion.Major,
			Minor: maximumMinor,
		},
		FeatureBitmap:    request.FeatureBitmap & negotiator.config.SupportedFeatures,
		MaximumFrameSize: maximumFrameSize,
		DescriptorDigest: negotiator.config.DescriptorDigest,
	}
	transcript, err := handshakeTranscript(request, response, negotiator.config.ServerPeer)
	if err != nil {
		return Response{}, fmt.Errorf("encode handshake transcript: %w", err)
	}
	proof := hmac.New(sha256.New, negotiator.nonce)
	_, _ = proof.Write(transcript)
	response.NonceProof = proof.Sum(nil)

	for index := range negotiator.nonce {
		negotiator.nonce[index] = 0
	}
	negotiator.nonce = nil
	negotiator.consumed = true
	return response, nil
}

func VerifyNonceProof(
	nonce []byte,
	request Request,
	response Response,
	serverPeer Peer,
) bool {
	if len(nonce) != NonceSize || len(response.NonceProof) != sha256.Size {
		return false
	}
	transcript, err := handshakeTranscript(request, response, serverPeer)
	if err != nil {
		return false
	}
	proof := hmac.New(sha256.New, nonce)
	_, _ = proof.Write(transcript)
	return hmac.Equal(response.NonceProof, proof.Sum(nil))
}

func handshakeTranscript(request Request, response Response, serverPeer Peer) ([]byte, error) {
	return canonical.Encode(
		canonical.Array{
			"circulusd.sandbox-handshake-proof",
			uint64(1),
			canonical.Map{
				"clientPeer": string(request.Peer),
				"serverPeer": string(serverPeer),
				"minimumVersion": canonical.Array{
					request.MinimumVersion.Major,
					request.MinimumVersion.Minor,
				},
				"maximumVersion": canonical.Array{
					request.MaximumVersion.Major,
					request.MaximumVersion.Minor,
				},
				"requestedFeatures":  uint64(request.FeatureBitmap),
				"requestedFrameSize": request.MaximumFrameSize,
				"requestedDescriptorDigest": canonical.Bytes(
					request.DescriptorDigest[:],
				),
				"selectedVersion": canonical.Array{
					response.SelectedVersion.Major,
					response.SelectedVersion.Minor,
				},
				"selectedFeatures":  uint64(response.FeatureBitmap),
				"selectedFrameSize": response.MaximumFrameSize,
				"descriptorDigest":  canonical.Bytes(response.DescriptorDigest[:]),
				"sandboxId":         request.SandboxID.String(),
				"sandboxGeneration": request.SandboxGeneration,
			},
		},
		canonical.Options{},
	)
}
