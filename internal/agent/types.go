// Package agent implements agentd's process-shard admission boundary. It does
// not call workerd's Worker Loader API; the returned placement is consumed by
// the trusted SessionHost running inside workerd.
package agent

import (
	"context"
	"errors"
	"time"

	"github.com/hancomac/circulusd/internal/identity"
)

var (
	ErrInvalidConfig            = errors.New("agent: invalid manager configuration")
	ErrInvalidRequest           = errors.New("agent: invalid placement request")
	ErrIsolationDowngrade       = errors.New("agent: placement weakens trust-class isolation")
	ErrCapacity                 = errors.New("agent: shard admission capacity unavailable")
	ErrStalePlacement           = errors.New("agent: stale placement generation")
	ErrPlacementConflict        = errors.New("agent: placement generation reused with different inputs")
	ErrPlacementNotFound        = errors.New("agent: placement not found")
	ErrShardNotFound            = errors.New("agent: shard not found")
	ErrStaleObservation         = errors.New("agent: stale shard observation identity")
	ErrStaleObservationSequence = errors.New("agent: stale shard observation sequence")
	ErrManagerClosed            = errors.New("agent: manager is shut down")
)

// ErrTerminalShardCleanup marks a cleanup result whose process ownership has
// been released or quarantined, making another Stop unsafe or meaningless. The
// same marked error must be replayed without side effects.
var ErrTerminalShardCleanup = errors.New("agent: terminal shard cleanup failure")

type ProcessScope string

const (
	ScopeShared  ProcessScope = "shared"
	ScopeTenant  ProcessScope = "tenant"
	ScopeSession ProcessScope = "session"
)

type OuterIsolation string

const (
	IsolationNone        OuterIsolation = "none"
	IsolationNSJail      OuterIsolation = "nsjail"
	IsolationDocker      OuterIsolation = "docker"
	IsolationFirecracker OuterIsolation = "firecracker"
)

type TrustClass string

const (
	TrustPlatformReviewed TrustClass = "platform-reviewed"
	TrustTenantReviewed   TrustClass = "tenant-reviewed"
	TrustSignedThirdParty TrustClass = "signed-third-party"
	TrustUnreviewed       TrustClass = "unreviewed"
)

type PlacementProfile struct {
	ProcessScope   ProcessScope
	OuterIsolation OuterIsolation
}

type RuntimeIdentity struct {
	RuntimeRevisionDigest string
	PiAdapterABI          uint64
	CompatibilityDate     string
	CompatibilityFlags    []string
}

type Limits struct {
	MaximumSessions               int
	MemoryLimitBytes              uint64
	AdmissionMemoryWatermarkBytes uint64
	MaximumLifetime               time.Duration
}

type PlacementRequest struct {
	TenantID             identity.ID
	SessionID            identity.ID
	PlacementGeneration  uint64
	TrustClass           TrustClass
	Profile              PlacementProfile
	Runtime              RuntimeIdentity
	EstimatedMemoryBytes uint64
	Now                  time.Time
}

type Placement struct {
	TenantID            identity.ID
	SessionID           identity.ID
	PlacementGeneration uint64
	ShardID             string
	WorkerID            string
	Profile             PlacementProfile
	AdmittedAt          time.Time
	Replayed            bool
}

type ReleaseRequest struct {
	SessionID           identity.ID
	PlacementGeneration uint64
}

// ShardGeneration identifies one concrete OS process start attempt. It is
// manager-owned and is independent from a session's PlacementGeneration.
type ShardGeneration uint64

type ShardSpec struct {
	AgentInstanceID identity.ID
	ShardID         string
	ShardGeneration ShardGeneration
	ScopeKey        string
	Profile         PlacementProfile
	Limits          Limits
	CreatedAt       time.Time
}

type ShardProcess interface {
	ID() string
	AgentInstanceID() identity.ID
	ShardGeneration() ShardGeneration
	// Stop returns nil only after the shard can no longer execute requests.
	// A nil result is idempotent, while unknown non-nil errors are retryable.
	// ErrTerminalShardCleanup marks an error for released or quarantined
	// ownership that must be replayed without another cleanup side effect.
	Stop(context.Context) error
}

type Launcher interface {
	Start(context.Context, ShardSpec) (ShardProcess, error)
}

// ShardObservation is one immutable, generation-bound resource sample.
// ObservationSequence must increase within that generation. ObservedAt is
// required diagnostic metadata and is never an ordering or lifetime authority.
type ShardObservation struct {
	AgentInstanceID     identity.ID
	ShardID             string
	ShardGeneration     ShardGeneration
	ObservationSequence uint64
	RSSBytes            uint64
	OOMObserved         bool
	HeapPressure        bool
	ObservedAt          time.Time
}

type ManagerSnapshot struct {
	Shards                         int
	DrainingShards                 int
	ResidentSessions               int
	ResidentMemoryReservationBytes uint64
}
