package objectstore

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/hancomac/circulusd/internal/conformance"
)

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
