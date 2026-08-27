package executor

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/hancomac/circulusd/internal/identity"
)

var (
	ErrStaleAuthority = errors.New("stale sandbox launch authority")
	handleIssuerID    atomic.Uint64
)

// HandleIssuer is the minimum opaque authority needed by an out-of-package
// execution provider to issue and resolve its own SandboxHandles. It never
// reveals or accepts a provider identifier, so handles cannot be forged by
// copying provider-local slot and generation numbers.
type HandleIssuer struct {
	providerID uint64
}

// NewHandleIssuer creates one process-local handle authority. Issuers must be
// retained for the complete lifetime of their provider.
func NewHandleIssuer() *HandleIssuer {
	identifier := handleIssuerID.Add(1)
	if identifier == 0 {
		// A zero provider ID is permanently invalid. Reaching this branch would
		// require issuing 2^64 authorities in one process lifetime.
		identifier = handleIssuerID.Add(1)
	}
	return &HandleIssuer{providerID: identifier}
}

func (issuer *HandleIssuer) String() string {
	if issuer == nil || issuer.providerID == 0 {
		return "sandbox-handle-issuer<zero>"
	}
	return "sandbox-handle-issuer<opaque>"
}

func (issuer *HandleIssuer) GoString() string {
	return issuer.String()
}

// GoString keeps provider-local slot and issuer identifiers out of diagnostic
// formatting while retaining the public generation already exposed by String.
func (handle SandboxHandle) GoString() string {
	return handle.String()
}

// Issue creates a handle scoped to this issuer.
func (issuer *HandleIssuer) Issue(slotID, generation uint64) (SandboxHandle, error) {
	if issuer == nil || issuer.providerID == 0 || slotID == 0 || generation == 0 {
		return SandboxHandle{}, fmt.Errorf("%w: invalid handle authority, slot, or generation", ErrInvalidSpec)
	}
	return SandboxHandle{
		providerID: issuer.providerID,
		slotID:     slotID,
		generation: generation,
	}, nil
}

// Resolve returns provider-local fields only for a handle issued by this
// exact authority.
func (issuer *HandleIssuer) Resolve(handle SandboxHandle) (uint64, uint64, error) {
	if issuer == nil || issuer.providerID == 0 || handle.IsZero() || handle.providerID != issuer.providerID {
		return 0, 0, ErrUnknownHandle
	}
	if handle.slotID == 0 || handle.generation == 0 {
		return 0, 0, ErrUnknownHandle
	}
	return handle.slotID, handle.generation, nil
}

// LaunchFence retains tenant equality without exposing the tenant identifier
// to an execution backend. Only the exact admitted generation authorizes new
// control operations.
type LaunchFence struct {
	tenant     identity.ID
	generation uint64
}

func NewLaunchFence(authority LaunchAuthority) (LaunchFence, error) {
	if authority.IsZero() || authority.tenant.Kind() != identity.Tenant || authority.generation == 0 {
		return LaunchFence{}, fmt.Errorf("%w: invalid launch authority", ErrInvalidSpec)
	}
	return LaunchFence{tenant: authority.tenant, generation: authority.generation}, nil
}

// Admit returns a monotonically advanced fence. Replaying an older generation
// or crossing a tenant boundary fails closed.
func (fence LaunchFence) Admit(authority LaunchAuthority) (LaunchFence, error) {
	if fence.tenant.Kind() != identity.Tenant || fence.generation == 0 || authority.IsZero() {
		return LaunchFence{}, fmt.Errorf("%w: invalid launch fence", ErrInvalidSpec)
	}
	if authority.tenant != fence.tenant {
		return LaunchFence{}, fmt.Errorf("%w: launch authority tenant mismatch", ErrInvalidSpec)
	}
	if authority.generation < fence.generation {
		return LaunchFence{}, ErrStaleAuthority
	}
	return LaunchFence{tenant: fence.tenant, generation: authority.generation}, nil
}

// Authorizes reports whether authority is the exact current tenant generation.
func (fence LaunchFence) Authorizes(authority LaunchAuthority) bool {
	return fence.tenant.Kind() == identity.Tenant && fence.generation != 0 &&
		!authority.IsZero() && authority.tenant == fence.tenant && authority.generation == fence.generation
}

func (fence LaunchFence) Generation() uint64 {
	return fence.generation
}

func (fence LaunchFence) String() string {
	if fence.tenant.Kind() != identity.Tenant || fence.generation == 0 {
		return "sandbox-launch-fence<zero>"
	}
	return fmt.Sprintf("sandbox-launch-fence<generation=%d>", fence.generation)
}

func (fence LaunchFence) GoString() string {
	return fence.String()
}
