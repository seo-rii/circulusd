package executor

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

const cacheKeyDomain = "circulusd.executor.sandbox-cache-key.v1\x00"

// SandboxSpec contains every effective isolation input that may affect safe
// sandbox reuse. Logical names are not accepted in place of immutable digests.
type SandboxSpec struct {
	LaunchAuthority        LaunchAuthority
	Backend                Backend
	EnvironmentDigest      string
	ResourceDigest         string
	NetworkDigest          string
	EffectivePolicyDigest  string
	SecretExposure         SecretExposureClass
	SandboxProtocolVersion uint32
	IdleTimeoutSeconds     uint32
	MaximumLifetimeSeconds uint32
	WorkspaceAccess        WorkspaceAccess
	Projection             WorkspaceProjection
	Scope                  SandboxScope
}

// CanonicalCacheKey validates the spec and returns a domain-separated SHA-256
// key over a length-delimited canonical field sequence. Length delimiters make
// the encoding unambiguous even when opaque scope identities contain ordinary
// punctuation.
func (spec SandboxSpec) CanonicalCacheKey() (CacheKey, error) {
	if spec.LaunchAuthority.IsZero() {
		return CacheKey{}, fmt.Errorf("%w: missing launch authority", ErrInvalidSpec)
	}
	switch spec.Backend {
	case BackendNsJail, BackendDocker, BackendFirecracker, BackendMock:
	default:
		return CacheKey{}, fmt.Errorf("%w: unsupported backend %q", ErrInvalidSpec, spec.Backend)
	}
	switch spec.SecretExposure {
	case SecretProxyOnly,
		SecretGatewayHeader,
		SecretSandboxEnv,
		SecretSandboxFile,
		SecretShortLivedToken:
	default:
		return CacheKey{}, fmt.Errorf(
			"%w: unsupported secret exposure class %q",
			ErrInvalidSpec,
			spec.SecretExposure,
		)
	}
	if spec.SandboxProtocolVersion == 0 {
		return CacheKey{}, fmt.Errorf("%w: sandbox protocol version must be positive", ErrInvalidSpec)
	}
	if spec.IdleTimeoutSeconds == 0 || spec.MaximumLifetimeSeconds == 0 {
		return CacheKey{}, fmt.Errorf("%w: sandbox lifetimes must be positive", ErrInvalidSpec)
	}
	if spec.IdleTimeoutSeconds > spec.MaximumLifetimeSeconds {
		return CacheKey{}, fmt.Errorf("%w: idle timeout exceeds maximum lifetime", ErrInvalidSpec)
	}

	digests := []struct {
		name  string
		value string
	}{
		{name: "environment", value: spec.EnvironmentDigest},
		{name: "resource", value: spec.ResourceDigest},
		{name: "network", value: spec.NetworkDigest},
		{name: "effective policy", value: spec.EffectivePolicyDigest},
	}
	for _, digest := range digests {
		if len(digest.value) != len("sha256:")+sha256.Size*2 ||
			!strings.HasPrefix(digest.value, "sha256:") ||
			digest.value != strings.ToLower(digest.value) {
			return CacheKey{}, fmt.Errorf(
				"%w: %s digest is not canonical SHA-256",
				ErrInvalidSpec,
				digest.name,
			)
		}
		decoded, err := hex.DecodeString(strings.TrimPrefix(digest.value, "sha256:"))
		if err != nil || len(decoded) != sha256.Size {
			return CacheKey{}, fmt.Errorf(
				"%w: %s digest is malformed",
				ErrInvalidSpec,
				digest.name,
			)
		}
	}

	switch spec.WorkspaceAccess {
	case WorkspaceReadOnly, WorkspaceReadWrite:
	default:
		return CacheKey{}, fmt.Errorf(
			"%w: unsupported workspace access %q",
			ErrInvalidSpec,
			spec.WorkspaceAccess,
		)
	}
	switch spec.Projection {
	case ProjectionMaterializedManifest, ProjectionFUSEExperimental:
	default:
		return CacheKey{}, fmt.Errorf(
			"%w: unsupported workspace projection %q",
			ErrInvalidSpec,
			spec.Projection,
		)
	}
	switch spec.Scope.Kind {
	case ScopeWorkspace, ScopeSession, ScopeInvocation:
	default:
		return CacheKey{}, fmt.Errorf(
			"%w: unsupported sandbox scope %q",
			ErrInvalidSpec,
			spec.Scope.Kind,
		)
	}
	if spec.Scope.Identity == "" ||
		!utf8.ValidString(spec.Scope.Identity) ||
		strings.IndexByte(spec.Scope.Identity, 0) >= 0 {
		return CacheKey{}, fmt.Errorf("%w: invalid scope identity", ErrInvalidSpec)
	}

	fields := []string{
		spec.LaunchAuthority.tenant.String(),
		string(spec.Backend),
		spec.EnvironmentDigest,
		spec.ResourceDigest,
		spec.NetworkDigest,
		spec.EffectivePolicyDigest,
		string(spec.SecretExposure),
		fmt.Sprintf("%d", spec.SandboxProtocolVersion),
		fmt.Sprintf("%d", spec.IdleTimeoutSeconds),
		fmt.Sprintf("%d", spec.MaximumLifetimeSeconds),
		string(spec.WorkspaceAccess),
		string(spec.Projection),
		string(spec.Scope.Kind),
		spec.Scope.Identity,
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(cacheKeyDomain))
	var length [4]byte
	for _, field := range fields {
		if uint64(len(field)) > uint64(^uint32(0)) {
			return CacheKey{}, fmt.Errorf("%w: canonical field is too large", ErrInvalidSpec)
		}
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(field))
	}

	var key CacheKey
	copy(key.digest[:], hash.Sum(nil))
	return key, nil
}
