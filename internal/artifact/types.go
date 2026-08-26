// Package artifact implements the provider-neutral Artifact Service core.
// Workspace files are copied from an exact immutable revision into a
// tenant-scoped content-addressed namespace. Durable providers implement the
// Repository transaction boundary; BlobStore contains only immutable bytes.
package artifact

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidConfig          = errors.New("artifact: invalid service configuration")
	ErrInvalidRequest         = errors.New("artifact: invalid request")
	ErrInvalidWorkspaceSource = errors.New("artifact: invalid workspace snapshot source")
	ErrAccessDenied           = errors.New("artifact: access denied")
	ErrInvocationConflict     = errors.New("artifact: invocation ID reused with another request")
	ErrInvocationAbandoned    = errors.New("artifact: invocation was abandoned")
	ErrQuotaExceeded          = errors.New("artifact: tenant artifact quota exceeded")
	ErrArtifactNotFound       = errors.New("artifact: artifact not found")
	ErrArtifactUnavailable    = errors.New("artifact: artifact is deleted or expired")
	ErrStorageCorruption      = errors.New("artifact: content-addressed storage corruption")
	ErrBlobNotFound           = errors.New("artifact: blob not found")
	ErrBlobVersionConflict    = errors.New("artifact: blob incarnation changed")
	ErrGCInProgress           = errors.New("artifact: object is being garbage-collected")
	ErrRepositoryConflict     = errors.New("artifact: repository transition conflict")
)

type Operation string

const (
	OperationCreate Operation = "artifact.create"
	OperationOpen   Operation = "artifact.open"
	OperationDelete Operation = "artifact.delete"
)

// AccessContext names the authenticated scope presented to the ACL service.
// Its fields are comparison inputs, not self-authenticating capabilities.
type AccessContext struct {
	TenantID    string
	SubjectID   string
	SessionID   string
	WorkspaceID string
}

type AuthorizationRequest struct {
	Operation Operation

	TenantID    string
	SubjectID   string
	SessionID   string
	WorkspaceID string

	ResourceSessionID   string
	ResourceWorkspaceID string
	ArtifactID          string
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) error
}

type AuthorizerFunc func(context.Context, AuthorizationRequest) error

func (function AuthorizerFunc) Authorize(ctx context.Context, request AuthorizationRequest) error {
	return function(ctx, request)
}

type WorkspaceSource struct {
	RevisionID string
	Path       string
}

type WorkspaceReadRequest struct {
	TenantID     string
	WorkspaceID  string
	RevisionID   string
	Path         string
	MaximumBytes int64
}

type WorkspaceFileKind string

const (
	WorkspaceRegularFile WorkspaceFileKind = "file"
	WorkspaceDirectory   WorkspaceFileKind = "directory"
	WorkspaceSymlink     WorkspaceFileKind = "symlink"
)

// WorkspaceFile repeats the source identity so the service can detect a
// confused or stale snapshot provider. ReadFile must honor MaximumBytes, and
// the service independently rejects an oversized response.
type WorkspaceFile struct {
	TenantID      string
	WorkspaceID   string
	RevisionID    string
	Path          string
	Kind          WorkspaceFileKind
	Size          int64
	ContentDigest string
	Data          []byte
}

type WorkspaceSnapshotReader interface {
	ReadFile(context.Context, WorkspaceReadRequest) (WorkspaceFile, error)
}

type Metadata struct {
	Name       string
	MediaType  string
	RetainFor  time.Duration
	Attributes map[string]string
}

type CreateRequest struct {
	Access       AccessContext
	InvocationID string
	Source       WorkspaceSource
	Metadata     Metadata
}

type ArtifactRef struct {
	ArtifactID     string
	ContentDigest  string
	MetadataDigest string
	ObjectKey      string
	Size           int64
	CreatedAt      time.Time
	RetainUntil    time.Time
}

type OpenRequest struct {
	Access     AccessContext
	ArtifactID string
}

type OpenedArtifact struct {
	Ref      ArtifactRef
	Metadata Metadata
	Data     []byte
}

type DeleteRequest struct {
	Access     AccessContext
	ArtifactID string
}

type ArtifactState string

const (
	ArtifactActive     ArtifactState = "active"
	ArtifactTombstoned ArtifactState = "tombstoned"
	ArtifactPurged     ArtifactState = "purged"
)

type ArtifactRecord struct {
	ArtifactID    string
	TenantID      string
	SessionID     string
	WorkspaceID   string
	InvocationID  string
	RequestDigest string

	SourceRevisionID string
	SourcePath       string
	ContentDigest    string
	MetadataDigest   string
	ObjectKey        string
	Size             int64
	Metadata         Metadata

	CreatedAt    time.Time
	RetainUntil  time.Time
	State        ArtifactState
	TombstonedAt *time.Time
	PurgedAt     *time.Time
}

type InvocationState string

const (
	InvocationInflight  InvocationState = "inflight"
	InvocationCommitted InvocationState = "committed"
	InvocationAbandoned InvocationState = "abandoned"
)

type CreateReservation struct {
	TenantID      string
	SessionID     string
	WorkspaceID   string
	InvocationID  string
	RequestDigest string
	ArtifactID    string
	ObjectKey     string
	Size          int64
	StartedAt     time.Time

	SourceRevisionID string
	SourcePath       string
	ContentDigest    string
	MetadataDigest   string
	Metadata         Metadata
}

type InvocationRecord struct {
	TenantID      string
	SessionID     string
	WorkspaceID   string
	InvocationID  string
	RequestDigest string
	ArtifactID    string
	ObjectKey     string
	Size          int64
	StartedAt     time.Time
	HeartbeatAt   time.Time
	Generation    uint64
	State         InvocationState

	SourceRevisionID string
	SourcePath       string
	ContentDigest    string
	MetadataDigest   string
	Metadata         Metadata
}

type CommitCreateRequest struct {
	InvocationID  string
	RequestDigest string
	Generation    uint64
	Artifact      ArtifactRecord
}

type SweepClaim struct {
	ObjectKey     string
	ObjectVersion string
	Token         uint64
	LeaseToken    uint64
}

// GCCheckpoint is the durable progress of the bounded scans that make up one
// artifact GC cycle. BlobEpoch is an opaque, snapshot-consistent object-store
// enumeration token; cursors are opaque to the service and only interpreted by
// their owning provider.
type GCCheckpoint struct {
	ExpiredCursor  string
	InflightCursor string
	SweepCursor    string
	BlobEpoch      string
	BlobCursor     string
}

// GCLease is a fencing token for one collector. A production repository must
// persist both the current token and checkpoint atomically. An expired worker
// may continue an external request, but must not be able to finalize metadata
// after a newer token is issued.
type GCLease struct {
	Token      uint64
	ExpiresAt  time.Time
	Checkpoint GCCheckpoint
}

// Repository methods that reserve, commit, tombstone, and claim sweep work
// must each be one durable transaction in a production provider. A sweep claim
// must prevent a concurrent BeginCreate for the same object until FinishSweep,
// and PendingSweeps must survive process restart so deletion can be finalized.
type Repository interface {
	LookupInvocation(context.Context, string) (InvocationRecord, bool, error)
	BeginCreate(context.Context, CreateReservation) (InvocationRecord, bool, error)
	HeartbeatCreate(context.Context, string, string, uint64, time.Time) (InvocationRecord, error)
	CommitCreate(context.Context, CommitCreateRequest) (ArtifactRecord, bool, error)
	GetArtifact(context.Context, string) (ArtifactRecord, error)
	TombstoneArtifact(context.Context, string, string, time.Time) (ArtifactRecord, bool, error)
	TombstoneExpiredPage(context.Context, GCLease, time.Time, string, int) (int, string, bool, error)
	AbandonInflightPage(context.Context, GCLease, time.Time, string, int) (int, string, bool, error)
	AcquireGC(context.Context, time.Time, time.Duration) (GCLease, bool, error)
	RenewGC(context.Context, GCLease, time.Time, time.Duration) (GCLease, error)
	ReleaseGC(context.Context, GCLease, GCCheckpoint) error
	PendingSweepsPage(context.Context, GCLease, string, int) ([]SweepClaim, string, bool, error)
	ClaimSweepLeased(context.Context, GCLease, string, string, time.Time) (SweepClaim, bool, error)
	RetireSweepLeased(context.Context, GCLease, SweepClaim) error
	FinishSweepLeased(context.Context, GCLease, SweepClaim, bool, time.Time) (int, error)
}

type BlobPut struct {
	Key       string
	Digest    string
	Data      []byte
	CreatedAt time.Time
}

type BlobObject struct {
	Key       string
	Version   string
	Digest    string
	Data      []byte
	CreatedAt time.Time
}

type BlobInfo struct {
	Key       string
	Version   string
	Digest    string
	Size      int64
	CreatedAt time.Time
}

type BlobListRequest struct {
	Epoch  string
	Cursor string
	Limit  int
}

type BlobListPage struct {
	Epoch      string
	NextCursor string
	Objects    []BlobInfo
	Done       bool
}

// BlobStore is a namespace dedicated to artifacts. Implementations must make
// PutIfAbsent immutable and idempotent for identical bytes. Every recreation of
// a deleted key must receive a new opaque Version, and DeleteIfVersion must
// never delete a different version. ListPage must keep an epoch stable across
// restart until its cursor reaches Done. Head must be linearizable with
// PutIfAbsent and DeleteIfVersion: ErrBlobNotFound proves that no version exists
// at the read's linearization point. Head is the reconciliation read for an
// uncertain delete; linearizability plus version fencing makes it safe to clear
// a sweep claim even if an older conditional delete completes after a new
// object is created.
type BlobStore interface {
	PutIfAbsent(context.Context, BlobPut) error
	Get(context.Context, string) (BlobObject, error)
	Head(context.Context, string) (BlobInfo, error)
	ListPage(context.Context, BlobListRequest) (BlobListPage, error)
	DeleteIfVersion(context.Context, string, string) error
}

type Config struct {
	Workspace  WorkspaceSnapshotReader
	Authorizer Authorizer
	Repository Repository
	Blobs      BlobStore

	Now           func() time.Time
	NewArtifactID func() (string, error)

	MaximumArtifactBytes      int64
	DefaultRetention          time.Duration
	MaximumRetention          time.Duration
	GCGrace                   time.Duration
	InflightTimeout           time.Duration
	InflightHeartbeatInterval time.Duration
	GCBatchSize               int
	GCLeaseDuration           time.Duration
}

type GCResult struct {
	ExpiredArtifacts     int
	AbandonedInvocations int
	DeletedObjects       int
	PurgedArtifacts      int
}

type RepositoryStats struct {
	Artifacts     int
	Invocations   int
	UsedBytes     int64
	ReservedBytes int64
}
