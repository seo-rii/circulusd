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
	ErrInvalidConfig      = errors.New("agent: invalid manager configuration")
	ErrInvalidRequest     = errors.New("agent: invalid placement request")
	ErrIsolationDowngrade = errors.New("agent: placement weakens trust-class isolation")
	ErrCapacity           = errors.New("agent: shard admission capacity unavailable")
	ErrStalePlacement     = errors.New("agent: stale placement generation")
	ErrPlacementConflict  = errors.New("agent: placement generation reused with different inputs")
	ErrPlacementNotFound  = errors.New("agent: placement not found")
	ErrShardNotFound      = errors.New("agent: shard not found")
	ErrManagerClosed      = errors.New("agent: manager is shut down")
)

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

type ShardSpec struct {
	ShardID   string
	ScopeKey  string
	Profile   PlacementProfile
	Limits    Limits
	CreatedAt time.Time
}

type ShardProcess interface {
	ID() string
	// Stop is idempotent and returns nil only after the shard can no longer
	// execute requests. A daemon shutdown retries uncertain failures.
	Stop(context.Context) error
}

type Launcher interface {
	Start(context.Context, ShardSpec) (ShardProcess, error)
}

type ShardObservation struct {
	ShardID      string
	RSSBytes     uint64
	OOMObserved  bool
	HeapPressure bool
	ObservedAt   time.Time
}

type ManagerSnapshot struct {
	Shards                         int
	DrainingShards                 int
	ResidentSessions               int
	ResidentMemoryReservationBytes uint64
}
