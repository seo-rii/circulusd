package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/objectstore"
)

var (
	ErrInvalidContentStore = errors.New("blob: invalid content store")
	ErrInvalidReference    = errors.New("blob: invalid content reference")
	ErrTenantMismatch      = errors.New("blob: tenant scope mismatch")
	ErrCorruptObject       = errors.New("blob: content-addressed object is corrupt")
)

type Reference struct {
	TenantID identity.ID
	Digest   string
	Size     uint64
}

func ReferenceFor(tenant identity.ID, data []byte) Reference {
	digest := sha256.Sum256(data)
	return Reference{
		TenantID: tenant,
		Digest:   "sha256:" + hex.EncodeToString(digest[:]),
		Size:     uint64(len(data)),
	}
}

func (reference Reference) ObjectKey() string {
	if reference.TenantID.Kind() != identity.Tenant || !digestPattern.MatchString(reference.Digest) {
		return ""
	}
	hexDigest := reference.Digest[len("sha256:"):]
	return reference.TenantID.String() + "/sha256/" + hexDigest[:2] + "/" + hexDigest[2:4] + "/" + hexDigest
}

type ContentStore struct {
	objects objectstore.Store
	guards  *GuardTable
}

// NewContentStore binds physical blob operations to a process-local guard
// authority. Stores sharing an object namespace must share the same GuardTable.
// Direct writes/deletes through objects bypass its incarnation fence.
func NewContentStore(objects objectstore.Store, guards *GuardTable) (*ContentStore, error) {
	if objects == nil || guards == nil {
		return nil, ErrInvalidContentStore
	}
	return &ContentStore{objects: objects, guards: guards}, nil
}

func (store *ContentStore) Upload(ctx context.Context, tenant identity.ID, data []byte, createdAt time.Time) (Reference, error) {
	if tenant.Kind() != identity.Tenant || createdAt.IsZero() {
		return Reference{}, ErrInvalidReference
	}
	reference := ReferenceFor(tenant, data)
	guardKey := Key{TenantID: tenant.String(), Digest: reference.Digest}
	release, err := store.guards.acquireStorage(ctx, guardKey)
	if err != nil {
		return Reference{}, err
	}
	defer release()
	key := reference.ObjectKey()
	_, err = store.objects.PutIfAbsent(ctx, objectstore.BucketWorkspaceBlobs, key, data)
	if errors.Is(err, objectstore.ErrPreconditionFailed) {
		existing, readErr := store.objects.Get(ctx, objectstore.BucketWorkspaceBlobs, key)
		if readErr != nil {
			return Reference{}, fmt.Errorf("read deduplicated workspace blob: %w", readErr)
		}
		if string(existing.ETag) != reference.Digest || !bytes.Equal(existing.Data, data) {
			return Reference{}, ErrCorruptObject
		}
	} else if err != nil {
		return Reference{}, fmt.Errorf("create workspace blob: %w", err)
	}
	if err := store.guards.register(guardKey, createdAt); err != nil {
		return Reference{}, fmt.Errorf("register workspace blob guard: %w", err)
	}
	return reference, nil
}

func (store *ContentStore) Read(ctx context.Context, tenant identity.ID, reference Reference) ([]byte, error) {
	if err := validateReference(tenant, reference); err != nil {
		return nil, err
	}
	object, err := store.objects.Get(ctx, objectstore.BucketWorkspaceBlobs, reference.ObjectKey())
	if err != nil {
		return nil, fmt.Errorf("read workspace blob: %w", err)
	}
	digest := sha256.Sum256(object.Data)
	actual := "sha256:" + hex.EncodeToString(digest[:])
	if actual != reference.Digest || string(object.ETag) != reference.Digest || uint64(len(object.Data)) != reference.Size {
		return nil, ErrCorruptObject
	}
	return append([]byte(nil), object.Data...), nil
}

func (store *ContentStore) Protect(ctx context.Context, tenant identity.ID, reference Reference, permitID string) (Permit, error) {
	if err := validateReference(tenant, reference); err != nil {
		return Permit{}, err
	}
	release, err := store.guards.acquireStorage(ctx, Key{TenantID: tenant.String(), Digest: reference.Digest})
	if err != nil {
		return Permit{}, err
	}
	defer release()
	if _, err := store.Read(ctx, tenant, reference); err != nil {
		return Permit{}, err
	}
	permit, err := store.guards.Protect(Key{TenantID: tenant.String(), Digest: reference.Digest}, permitID)
	if err != nil {
		return Permit{}, err
	}
	return permit, nil
}

func (store *ContentStore) Delete(ctx context.Context, deletion Deletion) error {
	release, err := store.guards.acquireStorage(ctx, deletion.Key)
	if err != nil {
		return err
	}
	defer release()
	if err := store.guards.ValidateDeletion(deletion); err != nil {
		return err
	}
	tenant, err := identity.Parse(identity.Tenant, deletion.Key.TenantID)
	if err != nil || !digestPattern.MatchString(deletion.Key.Digest) {
		return ErrInvalidReference
	}
	reference := Reference{TenantID: tenant, Digest: deletion.Key.Digest}
	err = store.objects.DeleteIfMatch(
		ctx,
		objectstore.BucketWorkspaceBlobs,
		reference.ObjectKey(),
		objectstore.ETag(deletion.Key.Digest),
	)
	if err != nil && !errors.Is(err, objectstore.ErrNotFound) {
		return fmt.Errorf("delete workspace blob: %w", err)
	}
	if err := store.guards.completeDeletion(deletion); err != nil {
		return err
	}
	return nil
}

func validateReference(tenant identity.ID, reference Reference) error {
	if tenant.Kind() != identity.Tenant || reference.TenantID.Kind() != identity.Tenant || !digestPattern.MatchString(reference.Digest) || reference.ObjectKey() == "" {
		return ErrInvalidReference
	}
	if tenant != reference.TenantID {
		return ErrTenantMismatch
	}
	return nil
}
