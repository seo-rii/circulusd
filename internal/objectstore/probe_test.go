package objectstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/conformance"
)

func TestCASProbeNeverDeletesAnExistingObjectAfterNonceCollision(t *testing.T) {
	root := t.TempDir()
	store, err := NewFileStore(root, FileStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key := ".doctor/cas-45454545454545454545454545454545"
	data := []byte("unrelated existing object")
	if _, err := store.PutIfAbsent(context.Background(), BucketCelldState, key, data); err != nil {
		t.Fatal(err)
	}
	result := ProbeCAS(context.Background(), ProbeConfig{Component: "object-store/collision", Random: bytes.NewReader(bytes.Repeat([]byte{0x45}, 16)), Open: func(context.Context) (Store, error) { return NewFileStore(root, FileStoreOptions{}) }})
	if result.Status != conformance.Fail {
		t.Fatalf("collision result=%#v", result)
	}
	object, err := store.Get(context.Background(), BucketCelldState, key)
	if err != nil || !bytes.Equal(object.Data, data) {
		t.Fatalf("collision deleted existing object: %#v %v", object, err)
	}
}

func TestCASProbeBoundsCleanupAndClosesClientAfterUncertainResponse(t *testing.T) {
	closed := false
	store := &blockedCleanupStore{closed: &closed}
	started := time.Now()
	result := ProbeCAS(context.Background(), ProbeConfig{Component: "object-store/cleanup-timeout", CleanupTimeout: 15 * time.Millisecond, Open: func(context.Context) (Store, error) { return store, nil }})
	if result.Status != conformance.Unavailable || !closed || time.Since(started) > time.Second {
		t.Fatalf("cleanup result=%#v closed=%v", result, closed)
	}
}

type blockedCleanupStore struct {
	Store
	closed *bool
}

func TestCASProbeRequiresConditionalCleanupToActuallyRemoveTheObject(t *testing.T) {
	root := t.TempDir()
	result := ProbeCAS(context.Background(), ProbeConfig{Component: "object-store/noop-delete", Open: func(context.Context) (Store, error) {
		store, err := NewFileStore(root, FileStoreOptions{})
		if err != nil {
			return nil, err
		}
		return &noopDeleteStore{Store: store}, nil
	}})
	if result.Status != conformance.Fail {
		t.Fatalf("noop conditional delete admitted: %#v", result)
	}
}

type noopDeleteStore struct{ Store }

func (s *noopDeleteStore) DeleteIfMatch(ctx context.Context, b Bucket, k string, etag ETag) error {
	object, err := s.Store.Get(ctx, b, k)
	if err != nil {
		return err
	}
	if object.ETag != etag {
		return ErrPreconditionFailed
	}
	return nil
}

func (*blockedCleanupStore) PutIfAbsent(context.Context, Bucket, string, []byte) (ETag, error) {
	return "", ErrUnavailable
}
func (*blockedCleanupStore) Get(ctx context.Context, _ Bucket, _ string) (Object, error) {
	<-ctx.Done()
	return Object{}, ctx.Err()
}
func (s *blockedCleanupStore) Close() error { *s.closed = true; return nil }

func TestCASProbeAcceptsOpaqueProviderETagsAndClosesBothClients(t *testing.T) {
	root := t.TempDir()
	var lock sync.Mutex
	closed := 0
	result := ProbeCAS(context.Background(), ProbeConfig{Component: "object-store/opaque", Open: func(context.Context) (Store, error) {
		store, err := NewFileStore(root, FileStoreOptions{})
		if err != nil {
			return nil, err
		}
		return &opaqueETagStore{Store: store, close: func() error { lock.Lock(); closed++; lock.Unlock(); return store.Close() }}, nil
	}})
	if result.Status != conformance.Pass {
		t.Fatalf("opaque provider CAS = %#v", result)
	}
	if closed != 2 {
		t.Fatalf("closed %d clients, want 2", closed)
	}
}

type opaqueETagStore struct {
	Store
	close func() error
}

func opaqueETag(etag ETag) ETag { return ETag(fmt.Sprintf("\"native-%s\"", etag)) }
func (s *opaqueETagStore) Get(ctx context.Context, b Bucket, k string) (Object, error) {
	o, e := s.Store.Get(ctx, b, k)
	o.ETag = opaqueETag(o.ETag)
	return o, e
}
func (s *opaqueETagStore) PutIfAbsent(ctx context.Context, b Bucket, k string, d []byte) (ETag, error) {
	e, r := s.Store.PutIfAbsent(ctx, b, k, d)
	return opaqueETag(e), r
}
func (s *opaqueETagStore) CompareAndSwap(ctx context.Context, b Bucket, k string, e ETag, d []byte) (ETag, error) {
	o, r := s.Store.Get(ctx, b, k)
	if r != nil {
		return "", r
	}
	if opaqueETag(o.ETag) != e {
		return "", ErrPreconditionFailed
	}
	next, r := s.Store.CompareAndSwap(ctx, b, k, o.ETag, d)
	return opaqueETag(next), r
}
func (s *opaqueETagStore) DeleteIfMatch(ctx context.Context, b Bucket, k string, e ETag) error {
	o, r := s.Store.Get(ctx, b, k)
	if r != nil {
		return r
	}
	if opaqueETag(o.ETag) != e {
		return ErrPreconditionFailed
	}
	return s.Store.DeleteIfMatch(ctx, b, k, o.ETag)
}
func (s *opaqueETagStore) Close() error { return s.close() }

func TestCASProbePassesAllRequiredChecksAndCleansUp(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	result := ProbeCAS(context.Background(), ProbeConfig{
		Component: "object-store/local-cas",
		Mock:      true,
		Random:    bytes.NewReader(bytes.Repeat([]byte{0x42}, 16)),
		Open: func(context.Context) (Store, error) {
			return NewFileStore(root, FileStoreOptions{MaximumObjectBytes: 1 << 20})
		},
	})
	if result.Status != conformance.Pass || result.Component != "object-store/local-cas" || !result.Evidence.Mock {
		t.Fatalf("ProbeCAS() = %#v, want mock PASS", result)
	}

	if objects := objectCount(t, root); objects != 0 {
		t.Fatalf("probe left %d test objects behind", objects)
	}
}

func TestCASProbeFailsClosedWhenConditionalWriteIsBroken(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	result := ProbeCAS(context.Background(), ProbeConfig{
		Component: "object-store/broken",
		Random:    bytes.NewReader(bytes.Repeat([]byte{0x43}, 16)),
		Open: func(context.Context) (Store, error) {
			store, err := NewFileStore(root, FileStoreOptions{MaximumObjectBytes: 1 << 20})
			if err != nil {
				return nil, err
			}
			return &brokenConditionalStore{Store: store}, nil
		},
	})
	if result.Status != conformance.Fail || result.Reason == "" {
		t.Fatalf("ProbeCAS() = %#v, want explained FAIL", result)
	}
	collector := conformance.NewCollector()
	if err := collector.Add(result); err != nil {
		t.Fatalf("Add(result) error = %v", err)
	}
	if err := collector.Evaluate(conformance.Profile{Name: "production", Production: true, Required: []string{"object-store/broken"}}); err == nil {
		t.Fatal("production profile accepted broken conditional store")
	}
}

func TestCASProbeRequiresRestartAndValidConfiguration(t *testing.T) {
	t.Parallel()
	for _, config := range []ProbeConfig{
		{},
		{Component: "object-store/no-open"},
		{Component: "Bad Component", Open: func(context.Context) (Store, error) { return nil, errors.New("unused") }},
	} {
		result := ProbeCAS(context.Background(), config)
		if result.Status != conformance.Fail || result.Reason == "" {
			t.Fatalf("ProbeCAS(%#v) = %#v, want explained FAIL", config, result)
		}
	}
}

func TestCASProbeCleansUpAnUncertainCreateResponse(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	result := ProbeCAS(context.Background(), ProbeConfig{
		Component: "object-store/lost-create-response",
		Random:    bytes.NewReader(bytes.Repeat([]byte{0x44}, 16)),
		Open: func(context.Context) (Store, error) {
			store, err := NewFileStore(root, FileStoreOptions{MaximumObjectBytes: 1 << 20})
			if err != nil {
				return nil, err
			}
			return &lostCreateResponseStore{Store: store}, nil
		},
	})
	if result.Status != conformance.Fail {
		t.Fatalf("ProbeCAS() = %#v, want FAIL", result)
	}
	if objects := objectCount(t, root); objects != 0 {
		t.Fatalf("failed probe left %d uncertain objects behind", objects)
	}
}

type brokenConditionalStore struct {
	Store
}

type lostCreateResponseStore struct {
	Store
}

func (store *lostCreateResponseStore) PutIfAbsent(ctx context.Context, bucket Bucket, key string, data []byte) (ETag, error) {
	if _, err := store.Store.PutIfAbsent(ctx, bucket, key, data); err != nil {
		return "", err
	}
	return "", errors.New("injected response loss")
}

func (store *brokenConditionalStore) CompareAndSwap(ctx context.Context, bucket Bucket, key string, _ ETag, data []byte) (ETag, error) {
	object, err := store.Store.Get(ctx, bucket, key)
	if err != nil {
		return "", err
	}
	return store.Store.CompareAndSwap(ctx, bucket, key, object.ETag, data)
}

func objectCount(t *testing.T, root string) int {
	t.Helper()
	objects := 0
	bucketRoot := filepath.Join(root, string(BucketCelldState))
	err := filepath.WalkDir(bucketRoot, func(_ string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type().IsRegular() {
			objects++
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("WalkDir(probe bucket) error = %v", err)
	}
	return objects
}
