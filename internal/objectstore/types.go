// Package objectstore defines the conditional-write contract required by the
// state plane and a durable local filesystem implementation for the reference
// single-node profile. External S3-compatible providers must pass the same
// behavioral conformance contract before celld starts.
package objectstore

import (
	"context"
	"errors"
)

var (
	ErrInvalidBucket      = errors.New("objectstore: invalid bucket")
	ErrInvalidKey         = errors.New("objectstore: invalid object key")
	ErrInvalidETag        = errors.New("objectstore: invalid ETag")
	ErrNotFound           = errors.New("objectstore: object not found")
	ErrPreconditionFailed = errors.New("objectstore: conditional write precondition failed")
	ErrObjectTooLarge     = errors.New("objectstore: object exceeds configured size limit")
	ErrUnsafePath         = errors.New("objectstore: unsafe filesystem path")
)

type Bucket string

const (
	BucketCelldState            Bucket = "pi-celld-state"
	BucketWorkspaceBlobs        Bucket = "pi-workspace-blobs"
	BucketArtifacts             Bucket = "pi-artifacts"
	BucketExtensionBundles      Bucket = "pi-extension-bundles"
	BucketRuntimeBundles        Bucket = "pi-runtime-bundles"
	BucketExecutionEnvironments Bucket = "pi-execution-environments"
	BucketBackups               Bucket = "pi-backups"
)

type ETag string

type Object struct {
	Data []byte
	ETag ETag
}

type Store interface {
	Get(context.Context, Bucket, string) (Object, error)
	PutIfAbsent(context.Context, Bucket, string, []byte) (ETag, error)
	CompareAndSwap(context.Context, Bucket, string, ETag, []byte) (ETag, error)
	DeleteIfMatch(context.Context, Bucket, string, ETag) error
}

type FileStoreOptions struct {
	MaximumObjectBytes int64
}
