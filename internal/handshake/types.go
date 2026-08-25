package handshake

import (
	"errors"
	"fmt"

	"github.com/hancomac/circulusd/internal/identity"
)

const (
	NonceSize  = 32
	DigestSize = 32
)

var (
	ErrInvalidConfig       = errors.New("invalid handshake configuration")
	ErrInvalidRequest      = errors.New("invalid handshake request")
	ErrHandshakeConsumed   = errors.New("one-time handshake was already consumed")
	ErrPeerRejected        = errors.New("protocol peer is not allowed")
	ErrUnsupportedProtocol = errors.New("protocol version is unsupported")
	ErrMissingFeature      = errors.New("required protocol feature is missing")
	ErrFrameSize           = errors.New("protocol frame size is incompatible")
	ErrDescriptorMismatch  = errors.New("protocol descriptor digest mismatch")
	ErrNonceMismatch       = errors.New("one-time handshake nonce mismatch")
	ErrSandboxBinding      = errors.New("sandbox identity or generation mismatch")
)

type Peer string

const (
	PeerPlatformd   Peer = "platformd"
	PeerExecutord   Peer = "executord"
	PeerSandboxd    Peer = "sandboxd"
	PeerPlatformctl Peer = "platformctl"
)

type FeatureBitmap uint64

const (
	FeatureProcessStreaming    FeatureBitmap = 1 << 1
	FeatureWorkspaceProtection FeatureBitmap = 1 << 2
	FeatureInvocationLedger    FeatureBitmap = 1 << 3
	FeatureAuthorityRenewal    FeatureBitmap = 1 << 4
	FeatureOverlayFSDiff       FeatureBitmap = 1 << 5
	FeatureReadOnlyWorkspace   FeatureBitmap = 1 << 6
)

type Version struct {
	Major uint64
	Minor uint64
}

type Request struct {
	Peer              Peer
	MinimumVersion    Version
	MaximumVersion    Version
	FeatureBitmap     FeatureBitmap
	MaximumFrameSize  uint64
	DescriptorDigest  [DigestSize]byte
	OneTimeNonce      []byte
	SandboxID         identity.ID
	SandboxGeneration uint64
}

func (request Request) String() string {
	return fmt.Sprintf(
		"handshake-request<peer=%s version=%d.%d-%d.%d sandbox-generation=%d nonce=<redacted>>",
		request.Peer,
		request.MinimumVersion.Major,
		request.MinimumVersion.Minor,
		request.MaximumVersion.Major,
		request.MaximumVersion.Minor,
		request.SandboxGeneration,
	)
}

func (request Request) GoString() string {
	return request.String()
}

type Response struct {
	SelectedVersion  Version
	FeatureBitmap    FeatureBitmap
	MaximumFrameSize uint64
	DescriptorDigest [DigestSize]byte
	NonceProof       []byte
}

type Config struct {
	ServerPeer        Peer
	AllowedClientPeer Peer
	MinimumVersion    Version
	MaximumVersion    Version
	SupportedFeatures FeatureBitmap
	RequiredFeatures  FeatureBitmap
	MinimumFrameSize  uint64
	MaximumFrameSize  uint64
	DescriptorDigest  [DigestSize]byte
	SandboxID         identity.ID
	SandboxGeneration uint64
	OneTimeNonce      []byte
}
