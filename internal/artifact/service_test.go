package artifact

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	tenantA        = "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	tenantB        = "tenant_EEEEEEEEEEEEEEEEEEEEEEEEEE"
	subjectA       = "subject_IIIIIIIIIIIIIIIIIIIIIIIIII"
	sessionA       = "sess_MMMMMMMMMMMMMMMMMMMMMMMMMM"
	workspaceA     = "ws_QQQQQQQQQQQQQQQQQQQQQQQQQQ"
	invocationA    = "inv_UUUUUUUUUUUUUUUUUUUUUUUUUU"
	revisionA      = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testIDAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

var baseTime = time.Date(2026, 8, 26, 3, 0, 0, 0, time.UTC)

func TestCreateFromWorkspacePinsAndValidatesSnapshotThenOpensArtifact(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("final report"), 1<<20)
	request := harness.createRequest(invocationA)
	request.Metadata = Metadata{
		Name:       "report.pdf",
		MediaType:  "application/pdf",
		RetainFor:  48 * time.Hour,
		Attributes: map[string]string{"classification": "internal"},
	}

	ref, err := harness.service.CreateFromWorkspace(context.Background(), request)
	if err != nil {
		t.Fatalf("CreateFromWorkspace() error = %v", err)
	}
	if ref.ArtifactID == "" || !strings.HasPrefix(ref.ContentDigest, "sha256:") || ref.Size != 12 {
		t.Fatalf("CreateFromWorkspace() = %#v", ref)
	}
	if ref.MetadataDigest == "" || ref.ObjectKey == "" || strings.Contains(ref.ObjectKey, workspaceA) {
		t.Fatalf("content-addressed metadata/object key = %#v", ref)
	}
	read := harness.source.lastRequest()
	if read.TenantID != tenantA || read.WorkspaceID != workspaceA || read.RevisionID != revisionA || read.Path != "out/report.pdf" {
		t.Fatalf("workspace read request = %#v", read)
	}
	if read.MaximumBytes != 1<<20 {
		t.Fatalf("workspace read maximum = %d, want %d", read.MaximumBytes, 1<<20)
	}

	opened, err := harness.service.Open(context.Background(), OpenRequest{Access: request.Access, ArtifactID: ref.ArtifactID})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if got := string(opened.Data); got != "final report" {
		t.Fatalf("Open().Data = %q", got)
	}
	opened.Data[0] = 'X'
	reopened, err := harness.service.Open(context.Background(), OpenRequest{Access: request.Access, ArtifactID: ref.ArtifactID})
	if err != nil || string(reopened.Data) != "final report" {
		t.Fatalf("Open() aliases store data: %q, %v", reopened.Data, err)
	}
}

func TestCreateRejectsConfusedDeputyWorkspaceResponses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*WorkspaceFile)
	}{
		{name: "tenant", mutate: func(file *WorkspaceFile) { file.TenantID = tenantB }},
		{name: "workspace", mutate: func(file *WorkspaceFile) { file.WorkspaceID = "ws_YYYYYYYYYYYYYYYYYYYYYYYYYY" }},
		{name: "revision", mutate: func(file *WorkspaceFile) { file.RevisionID = "sha256:" + strings.Repeat("b", 64) }},
		{name: "path", mutate: func(file *WorkspaceFile) { file.Path = "out/other.pdf" }},
		{name: "kind", mutate: func(file *WorkspaceFile) { file.Kind = WorkspaceDirectory }},
		{name: "declared size", mutate: func(file *WorkspaceFile) { file.Size++ }},
		{name: "declared digest", mutate: func(file *WorkspaceFile) { file.ContentDigest = "sha256:" + strings.Repeat("c", 64) }},
		{name: "oversized body", mutate: func(file *WorkspaceFile) {
			file.Data = make([]byte, (1<<20)+1)
			file.Size = int64(len(file.Data))
			file.ContentDigest = digestBytes(file.Data)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newHarness(t, []byte("final report"), 1<<20)
			harness.source.mutate = test.mutate
			_, err := harness.service.CreateFromWorkspace(context.Background(), harness.createRequest(invocationA))
			if !errors.Is(err, ErrInvalidWorkspaceSource) {
				t.Fatalf("CreateFromWorkspace() error = %v, want ErrInvalidWorkspaceSource", err)
			}
			if got := harness.blobs.ObjectCount(); got != 0 {
				t.Fatalf("invalid source wrote %d objects", got)
			}
		})
	}
}

func TestArtifactACLAndTenantIsolationApplyToEveryOperation(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("private"), 1<<20)
	created, err := harness.service.CreateFromWorkspace(context.Background(), harness.createRequest(invocationA))
	if err != nil {
		t.Fatalf("CreateFromWorkspace() error = %v", err)
	}

	crossTenant := harness.access
	crossTenant.TenantID = tenantB
	if _, err := harness.service.Open(context.Background(), OpenRequest{Access: crossTenant, ArtifactID: created.ArtifactID}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("Open(cross tenant) error = %v, want ErrAccessDenied", err)
	}
	if err := harness.service.Delete(context.Background(), DeleteRequest{Access: crossTenant, ArtifactID: created.ArtifactID}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("Delete(cross tenant) error = %v, want ErrAccessDenied", err)
	}

	harness.authorizer.deny(OperationOpen)
	if _, err := harness.service.Open(context.Background(), OpenRequest{Access: harness.access, ArtifactID: created.ArtifactID}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("Open(ACL deny) error = %v, want ErrAccessDenied", err)
	}
	harness.authorizer.allow(OperationOpen)
	harness.authorizer.deny(OperationDelete)
	if err := harness.service.Delete(context.Background(), DeleteRequest{Access: harness.access, ArtifactID: created.ArtifactID}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("Delete(ACL deny) error = %v, want ErrAccessDenied", err)
	}

	requests := harness.authorizer.requestsSnapshot()
	for _, operation := range []Operation{OperationCreate, OperationOpen, OperationDelete} {
		found := false
		for _, request := range requests {
			if request.Operation == operation && request.TenantID == tenantA && request.SessionID == sessionA && request.WorkspaceID == workspaceA {
				found = true
			}
		}
		if !found {
			t.Fatalf("ACL did not receive complete %q scope: %#v", operation, requests)
		}
	}
}

func TestConcurrentInvocationReplayCreatesExactlyOneArtifact(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("one object"), 1<<20)
	request := harness.createRequest(invocationA)
	const workers = 96
	results := make(chan ArtifactRef, workers)
	errorsSeen := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			ref, err := harness.service.CreateFromWorkspace(context.Background(), request)
			results <- ref
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent CreateFromWorkspace() error = %v", err)
		}
	}
	ids := map[string]struct{}{}
	for result := range results {
		ids[result.ArtifactID] = struct{}{}
	}
	if len(ids) != 1 {
		t.Fatalf("artifact IDs = %v, want exactly one", ids)
	}
	stats := harness.repository.Stats(tenantA)
	if stats.Artifacts != 1 || stats.Invocations != 1 || stats.ReservedBytes != 0 || stats.UsedBytes != int64(len("one object")) {
		t.Fatalf("repository stats = %#v", stats)
	}
	if harness.blobs.ObjectCount() != 1 {
		t.Fatalf("blob objects = %d, want 1", harness.blobs.ObjectCount())
	}

	conflict := request
	conflict.Metadata.Name = "changed.pdf"
	if _, err := harness.service.CreateFromWorkspace(context.Background(), conflict); !errors.Is(err, ErrInvocationConflict) {
		t.Fatalf("conflicting replay error = %v, want ErrInvocationConflict", err)
	}
}

func TestCommittedInvocationReplayDoesNotDependOnWorkspaceSnapshotAvailability(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("durable result"), 1<<20)
	request := harness.createRequest(invocationA)
	first, err := harness.service.CreateFromWorkspace(context.Background(), request)
	if err != nil {
		t.Fatalf("CreateFromWorkspace(first) error = %v", err)
	}
	harness.source.setError(errors.New("snapshot retention elapsed"))
	replayed, err := harness.service.CreateFromWorkspace(context.Background(), request)
	if err != nil {
		t.Fatalf("CreateFromWorkspace(replay) error = %v", err)
	}
	if replayed != first {
		t.Fatalf("replayed ref = %#v, want %#v", replayed, first)
	}
}

func TestInvocationDigestDoesNotTruncateSubMillisecondRetention(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("precise retention"), 1<<20)
	request := harness.createRequest(invocationA)
	request.Metadata.RetainFor = time.Nanosecond
	if _, err := harness.service.CreateFromWorkspace(context.Background(), request); err != nil {
		t.Fatalf("CreateFromWorkspace(first) error = %v", err)
	}
	request.Metadata.RetainFor = 2 * time.Nanosecond
	if _, err := harness.service.CreateFromWorkspace(context.Background(), request); !errors.Is(err, ErrInvocationConflict) {
		t.Fatalf("CreateFromWorkspace(conflicting retention) error = %v, want ErrInvocationConflict", err)
	}
}

func TestMetadataDigestBindsTheArtifactContent(t *testing.T) {
	t.Parallel()
	firstHarness := newHarness(t, []byte("content one"), 1<<20)
	first, err := firstHarness.service.CreateFromWorkspace(context.Background(), firstHarness.createRequest(invocationA))
	if err != nil {
		t.Fatalf("CreateFromWorkspace(first) error = %v", err)
	}
	secondHarness := newHarness(t, []byte("content two"), 1<<20)
	second, err := secondHarness.service.CreateFromWorkspace(context.Background(), secondHarness.createRequest(invocationA))
	if err != nil {
		t.Fatalf("CreateFromWorkspace(second) error = %v", err)
	}
	if first.MetadataDigest == second.MetadataDigest {
		t.Fatalf("metadata digest %q did not bind content", first.MetadataDigest)
	}
}

func TestQuotaReservationIsAtomicAndLeavesNoPartialMutation(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("0123456789"), 9)
	_, err := harness.service.CreateFromWorkspace(context.Background(), harness.createRequest(invocationA))
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("CreateFromWorkspace() error = %v, want ErrQuotaExceeded", err)
	}
	if stats := harness.repository.Stats(tenantA); stats != (RepositoryStats{}) {
		t.Fatalf("quota rejection left durable state: %#v", stats)
	}
	if harness.blobs.ObjectCount() != 0 {
		t.Fatalf("quota rejection wrote %d blobs", harness.blobs.ObjectCount())
	}
}

func TestConcurrentDistinctInvocationsCannotOverbookTenantQuota(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("123456"), 6)
	const workers = 32
	errorsSeen := make(chan error, workers)
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			request := harness.createRequest("inv_" + string(testIDAlphabet[index]) + strings.Repeat("A", 25))
			_, err := harness.service.CreateFromWorkspace(context.Background(), request)
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	succeeded, quotaDenied := 0, 0
	for err := range errorsSeen {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrQuotaExceeded):
			quotaDenied++
		default:
			t.Fatalf("CreateFromWorkspace() unexpected error = %v", err)
		}
	}
	if succeeded != 1 || quotaDenied != workers-1 {
		t.Fatalf("success=%d quota-denied=%d, want 1/%d", succeeded, quotaDenied, workers-1)
	}
	if stats := harness.repository.Stats(tenantA); stats.Artifacts != 1 || stats.Invocations != 1 || stats.UsedBytes != 6 || stats.ReservedBytes != 0 {
		t.Fatalf("concurrent quota stats = %#v", stats)
	}
	if harness.blobs.ObjectCount() != 1 {
		t.Fatalf("concurrent quota wrote %d objects", harness.blobs.ObjectCount())
	}
}

func TestDeleteRetentionAndGCUseTombstonesAndProtectSharedContent(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("shared"), 1<<20)
	first, err := harness.service.CreateFromWorkspace(context.Background(), harness.createRequest(invocationA))
	if err != nil {
		t.Fatalf("CreateFromWorkspace(first) error = %v", err)
	}
	secondRequest := harness.createRequest("inv_YYYYYYYYYYYYYYYYYYYYYYYYYY")
	second, err := harness.service.CreateFromWorkspace(context.Background(), secondRequest)
	if err != nil {
		t.Fatalf("CreateFromWorkspace(second) error = %v", err)
	}
	if first.ObjectKey != second.ObjectKey || harness.blobs.ObjectCount() != 1 {
		t.Fatalf("shared content was not tenant-scoped deduplicated: %#v %#v", first, second)
	}

	if err := harness.service.Delete(context.Background(), DeleteRequest{Access: harness.access, ArtifactID: first.ArtifactID}); err != nil {
		t.Fatalf("Delete(first) error = %v", err)
	}
	if _, err := harness.service.Open(context.Background(), OpenRequest{Access: harness.access, ArtifactID: first.ArtifactID}); !errors.Is(err, ErrArtifactUnavailable) {
		t.Fatalf("Open(tombstoned) error = %v, want ErrArtifactUnavailable", err)
	}
	if stats := harness.repository.Stats(tenantA); stats.UsedBytes != int64(len("shared")) {
		t.Fatalf("delete did not release logical quota once: %#v", stats)
	}

	harness.advance(2 * time.Hour)
	result, err := harness.service.CollectGarbage(context.Background())
	if err != nil || result.DeletedObjects != 0 || harness.blobs.ObjectCount() != 1 {
		t.Fatalf("GC deleted content with a live reference: %#v, %v", result, err)
	}
	if err := harness.service.Delete(context.Background(), DeleteRequest{Access: harness.access, ArtifactID: second.ArtifactID}); err != nil {
		t.Fatalf("Delete(second) error = %v", err)
	}
	result, err = harness.service.CollectGarbage(context.Background())
	if err != nil || result.DeletedObjects != 0 {
		t.Fatalf("GC ignored grace = %#v, %v", result, err)
	}
	harness.advance(61 * time.Minute)
	result, err = harness.service.CollectGarbage(context.Background())
	if err != nil || result.DeletedObjects != 1 || result.PurgedArtifacts != 2 || harness.blobs.ObjectCount() != 0 {
		t.Fatalf("GC result = %#v, %v, objects=%d", result, err, harness.blobs.ObjectCount())
	}
}

func TestRetentionExpiryRevokesOpenBeforePhysicalGC(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("expiring"), 1<<20)
	request := harness.createRequest(invocationA)
	request.Metadata.RetainFor = time.Hour
	ref, err := harness.service.CreateFromWorkspace(context.Background(), request)
	if err != nil {
		t.Fatalf("CreateFromWorkspace() error = %v", err)
	}
	harness.advance(time.Hour)
	harness.authorizer.deny(OperationOpen)
	if _, err := harness.service.Open(context.Background(), OpenRequest{Access: harness.access, ArtifactID: ref.ArtifactID}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("Open(expired, ACL deny) error = %v, want ErrAccessDenied", err)
	}
	harness.authorizer.allow(OperationOpen)
	if _, err := harness.service.Open(context.Background(), OpenRequest{Access: harness.access, ArtifactID: ref.ArtifactID}); !errors.Is(err, ErrArtifactUnavailable) {
		t.Fatalf("Open(expired) error = %v, want ErrArtifactUnavailable", err)
	}
	result, err := harness.service.CollectGarbage(context.Background())
	if err != nil || result.ExpiredArtifacts != 1 || result.DeletedObjects != 0 {
		t.Fatalf("first expiry GC = %#v, %v", result, err)
	}
	if stats := harness.repository.Stats(tenantA); stats.UsedBytes != 0 {
		t.Fatalf("expiry did not release quota: %#v", stats)
	}
	harness.advance(61 * time.Minute)
	result, err = harness.service.CollectGarbage(context.Background())
	if err != nil || result.DeletedObjects != 1 {
		t.Fatalf("post-grace GC = %#v, %v", result, err)
	}
}

func TestGCRestartsAClaimAfterBlobDeletionResponseIsLost(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("recover sweep"), 1<<20)
	ref, err := harness.service.CreateFromWorkspace(context.Background(), harness.createRequest(invocationA))
	if err != nil {
		t.Fatalf("CreateFromWorkspace() error = %v", err)
	}
	if err := harness.service.Delete(context.Background(), DeleteRequest{Access: harness.access, ArtifactID: ref.ArtifactID}); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	harness.advance(61 * time.Minute)
	claim, claimed, err := harness.repository.ClaimSweep(context.Background(), ref.ObjectKey, harness.currentTime().Add(-time.Hour))
	if err != nil || !claimed {
		t.Fatalf("ClaimSweep() = %#v, %t, %v", claim, claimed, err)
	}
	if err := harness.blobs.Delete(context.Background(), ref.ObjectKey); err != nil {
		t.Fatalf("Delete(blob) error = %v", err)
	}

	result, err := harness.service.CollectGarbage(context.Background())
	if err != nil || result.DeletedObjects != 1 || result.PurgedArtifacts != 1 {
		t.Fatalf("recovery GC = %#v, %v", result, err)
	}
}

func TestGCUncertainDeleteKeepsFenceUntilHeadReconciliation(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("uncertain delete"), 1<<20)
	ref, err := harness.service.CreateFromWorkspace(context.Background(), harness.createRequest(invocationA))
	if err != nil {
		t.Fatalf("CreateFromWorkspace() error = %v", err)
	}
	if err := harness.service.Delete(context.Background(), DeleteRequest{Access: harness.access, ArtifactID: ref.ArtifactID}); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	harness.advance(61 * time.Minute)
	harness.blobs.FailAfterDelete(errors.New("delete response lost"))
	if _, err := harness.service.CollectGarbage(context.Background()); err == nil {
		t.Fatal("CollectGarbage() error = nil after uncertain delete")
	}
	claims, err := harness.repository.PendingSweeps(context.Background())
	if err != nil || len(claims) != 1 || claims[0].ObjectKey != ref.ObjectKey {
		t.Fatalf("pending claims = %#v, %v; want retained delete fence", claims, err)
	}

	retry := harness.createRequest("inv_YYYYYYYYYYYYYYYYYYYYYYYYYY")
	if _, err := harness.service.CreateFromWorkspace(context.Background(), retry); !errors.Is(err, ErrGCInProgress) {
		t.Fatalf("CreateFromWorkspace(while delete uncertain) error = %v, want ErrGCInProgress", err)
	}

	harness.blobs.FailAfterDelete(nil)
	result, err := harness.service.CollectGarbage(context.Background())
	if err != nil || result.DeletedObjects != 1 || result.PurgedArtifacts != 1 {
		t.Fatalf("reconciled GC = %#v, %v", result, err)
	}
	if _, err := harness.service.CreateFromWorkspace(context.Background(), retry); err != nil {
		t.Fatalf("CreateFromWorkspace(after reconciliation) error = %v", err)
	}
}

func TestGCUsesBoundedDurableSnapshotCursor(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("unused"), 1<<20)
	harness.service.gcBatchSize = 2
	for index := range 5 {
		data := []byte(fmt.Sprintf("orphan-%d", index))
		if err := harness.blobs.PutIfAbsent(context.Background(), BlobPut{
			Key: fmt.Sprintf("%s/orphan/%d", tenantA, index), Digest: digestBytes(data),
			Data: data, CreatedAt: harness.currentTime().Add(-2 * time.Hour),
		}); err != nil {
			t.Fatalf("PutIfAbsent(orphan %d) error = %v", index, err)
		}
	}

	first, err := harness.service.CollectGarbage(context.Background())
	if err != nil || first.DeletedObjects != 2 {
		t.Fatalf("first bounded GC = %#v, %v; want exactly two objects", first, err)
	}
	lease, acquired, err := harness.repository.AcquireGC(context.Background(), harness.currentTime(), time.Minute)
	if err != nil || !acquired {
		t.Fatalf("AcquireGC() = %#v, %t, %v", lease, acquired, err)
	}
	if lease.Checkpoint.BlobEpoch == "" || lease.Checkpoint.BlobCursor == "" {
		t.Fatalf("durable blob checkpoint = %#v", lease.Checkpoint)
	}
	if err := harness.repository.ReleaseGC(context.Background(), lease, lease.Checkpoint); err != nil {
		t.Fatalf("ReleaseGC() error = %v", err)
	}

	deleted := first.DeletedObjects
	for attempts := 0; attempts < 4 && harness.blobs.ObjectCount() != 0; attempts++ {
		result, collectErr := harness.service.CollectGarbage(context.Background())
		if collectErr != nil {
			t.Fatalf("CollectGarbage(page %d) error = %v", attempts+2, collectErr)
		}
		if result.DeletedObjects > 2 {
			t.Fatalf("GC page deleted %d objects, batch size 2", result.DeletedObjects)
		}
		deleted += result.DeletedObjects
	}
	if deleted != 5 || harness.blobs.ObjectCount() != 0 {
		t.Fatalf("paged GC deleted %d objects, remaining=%d", deleted, harness.blobs.ObjectCount())
	}
}

func TestBlobEnumerationEpochIsSnapshotConsistent(t *testing.T) {
	t.Parallel()
	store := NewMemoryBlobStore()
	for _, value := range []string{"a", "c"} {
		data := []byte(value)
		if err := store.PutIfAbsent(context.Background(), BlobPut{Key: value, Digest: digestBytes(data), Data: data, CreatedAt: baseTime}); err != nil {
			t.Fatalf("PutIfAbsent(%q) error = %v", value, err)
		}
	}
	first, err := store.ListPage(context.Background(), BlobListRequest{Limit: 1})
	if err != nil || len(first.Objects) != 1 || first.Epoch == "" || first.Done {
		t.Fatalf("first ListPage() = %#v, %v", first, err)
	}
	data := []byte("b")
	if err := store.PutIfAbsent(context.Background(), BlobPut{Key: "b", Digest: digestBytes(data), Data: data, CreatedAt: baseTime}); err != nil {
		t.Fatalf("PutIfAbsent(new object) error = %v", err)
	}
	second, err := store.ListPage(context.Background(), BlobListRequest{
		Epoch: first.Epoch, Cursor: first.NextCursor, Limit: 2,
	})
	if err != nil || len(second.Objects) != 1 || second.Objects[0].Key != "c" || !second.Done {
		t.Fatalf("second ListPage() = %#v, %v; new object leaked into snapshot", second, err)
	}
}

func TestConcurrentGCIsLeaseFenced(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("lease fenced"), 1<<20)
	ref, err := harness.service.CreateFromWorkspace(context.Background(), harness.createRequest(invocationA))
	if err != nil {
		t.Fatalf("CreateFromWorkspace() error = %v", err)
	}
	if err := harness.service.Delete(context.Background(), DeleteRequest{Access: harness.access, ArtifactID: ref.ArtifactID}); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	harness.advance(61 * time.Minute)
	blocking := &blockingDeleteBlobStore{
		MemoryBlobStore: harness.blobs, started: make(chan struct{}), release: make(chan struct{}),
	}
	harness.service.blobs = blocking
	firstDone := make(chan error, 1)
	go func() {
		_, collectErr := harness.service.CollectGarbage(context.Background())
		firstDone <- collectErr
	}()
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("first GC did not reach blob delete")
	}
	if _, err := harness.service.CollectGarbage(context.Background()); !errors.Is(err, ErrGCInProgress) {
		t.Fatalf("concurrent CollectGarbage() error = %v, want ErrGCInProgress", err)
	}
	close(blocking.release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first CollectGarbage() error = %v", err)
	}
}

func TestExpiredGCLeaseFencesThePreviousCollector(t *testing.T) {
	t.Parallel()
	repository := NewMemoryRepository(map[string]int64{tenantA: 1 << 20})
	first, acquired, err := repository.AcquireGC(context.Background(), baseTime, time.Minute)
	if err != nil || !acquired {
		t.Fatalf("AcquireGC(first) = %#v, %t, %v", first, acquired, err)
	}
	claim, claimed, err := repository.ClaimSweepLeased(
		context.Background(), first, tenantA+"/orphan", "version-1", baseTime,
	)
	if err != nil || !claimed {
		t.Fatalf("ClaimSweepLeased(first) = %#v, %t, %v", claim, claimed, err)
	}
	second, acquired, err := repository.AcquireGC(context.Background(), baseTime.Add(2*time.Minute), time.Minute)
	if err != nil || !acquired || second.Token == first.Token {
		t.Fatalf("AcquireGC(takeover) = %#v, %t, %v", second, acquired, err)
	}
	if err := repository.ReleaseGC(context.Background(), first, first.Checkpoint); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("ReleaseGC(stale lease) error = %v, want ErrRepositoryConflict", err)
	}
	if _, err := repository.FinishSweepLeased(context.Background(), first, claim, true, baseTime); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("FinishSweepLeased(stale lease) error = %v, want ErrRepositoryConflict", err)
	}
	if err := repository.ReleaseGC(context.Background(), second, second.Checkpoint); err != nil {
		t.Fatalf("ReleaseGC(current lease) error = %v", err)
	}
}

func TestStaleConditionalDeleteCannotRemoveRecreatedBlobAfterLeaseTakeover(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("recreated immutable blob"), 1<<20)
	firstRef, err := harness.service.CreateFromWorkspace(context.Background(), harness.createRequest(invocationA))
	if err != nil {
		t.Fatalf("CreateFromWorkspace(first) error = %v", err)
	}
	if err := harness.service.Delete(context.Background(), DeleteRequest{Access: harness.access, ArtifactID: firstRef.ArtifactID}); err != nil {
		t.Fatalf("Delete(first artifact) error = %v", err)
	}
	harness.advance(61 * time.Minute)
	harness.service.gcLeaseDuration = time.Hour
	delayed := &delayedFirstDeleteBlobStore{
		MemoryBlobStore: harness.blobs, firstStarted: make(chan struct{}), releaseFirst: make(chan struct{}),
	}
	harness.service.blobs = delayed
	firstGCDone := make(chan error, 1)
	go func() {
		_, collectErr := harness.service.CollectGarbage(context.Background())
		firstGCDone <- collectErr
	}()
	select {
	case <-delayed.firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first collector did not dispatch delete")
	}

	harness.advance(2 * time.Hour)
	result, err := harness.service.CollectGarbage(context.Background())
	if err != nil || result.DeletedObjects != 1 || result.PurgedArtifacts != 1 {
		t.Fatalf("takeover GC = %#v, %v", result, err)
	}
	secondRequest := harness.createRequest("inv_YYYYYYYYYYYYYYYYYYYYYYYYYY")
	secondRef, err := harness.service.CreateFromWorkspace(context.Background(), secondRequest)
	if err != nil {
		t.Fatalf("CreateFromWorkspace(recreated) error = %v", err)
	}
	close(delayed.releaseFirst)
	if err := <-firstGCDone; err == nil {
		t.Fatal("stale collector unexpectedly finalized successfully")
	}
	opened, err := harness.service.Open(context.Background(), OpenRequest{Access: harness.access, ArtifactID: secondRef.ArtifactID})
	if err != nil || string(opened.Data) != "recreated immutable blob" {
		t.Fatalf("Open(recreated) = %q, %v; stale delete removed new incarnation", opened.Data, err)
	}
}

func TestGCDiscardsStaleVersionClaimWithoutPurgingCurrentIncarnation(t *testing.T) {
	t.Parallel()
	data := []byte("stale sweep incarnation")
	harness := newHarness(t, data, 1<<20)
	digest := digestBytes(data)
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	key := tenantA + "/sha256/" + hexDigest[:2] + "/" + hexDigest[2:4] + "/" + hexDigest
	if err := harness.blobs.PutIfAbsent(context.Background(), BlobPut{
		Key: key, Digest: digest, Data: data, CreatedAt: harness.currentTime().Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("PutIfAbsent(v1) error = %v", err)
	}
	v1, err := harness.blobs.Head(context.Background(), key)
	if err != nil {
		t.Fatalf("Head(v1) error = %v", err)
	}
	if err := harness.blobs.DeleteIfVersion(context.Background(), key, v1.Version); err != nil {
		t.Fatalf("DeleteIfVersion(v1) error = %v", err)
	}
	if err := harness.blobs.PutIfAbsent(context.Background(), BlobPut{
		Key: key, Digest: digest, Data: data, CreatedAt: harness.currentTime().Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("PutIfAbsent(v2) error = %v", err)
	}
	v2, err := harness.blobs.Head(context.Background(), key)
	if err != nil || v2.Version == v1.Version {
		t.Fatalf("Head(v2) = %#v, %v", v2, err)
	}

	lease, acquired, err := harness.repository.AcquireGC(context.Background(), harness.currentTime(), time.Minute)
	if err != nil || !acquired {
		t.Fatalf("AcquireGC() = %#v, %t, %v", lease, acquired, err)
	}
	if _, claimed, claimErr := harness.repository.ClaimSweepLeased(
		context.Background(), lease, key, v1.Version, harness.currentTime().Add(-time.Hour),
	); claimErr != nil || !claimed {
		t.Fatalf("ClaimSweepLeased(v1) claimed=%t error=%v", claimed, claimErr)
	}
	if err := harness.repository.ReleaseGC(context.Background(), lease, lease.Checkpoint); err != nil {
		t.Fatalf("ReleaseGC() error = %v", err)
	}

	result, err := harness.service.CollectGarbage(context.Background())
	if err != nil || result.DeletedObjects != 0 || harness.blobs.ObjectCount() != 1 {
		t.Fatalf("CollectGarbage(stale claim) = %#v, %v, objects=%d", result, err, harness.blobs.ObjectCount())
	}
	claims, err := harness.repository.PendingSweeps(context.Background())
	if err != nil || len(claims) != 0 {
		t.Fatalf("stale pending claims = %#v, %v", claims, err)
	}
	if _, err := harness.service.CreateFromWorkspace(context.Background(), harness.createRequest(invocationA)); err != nil {
		t.Fatalf("CreateFromWorkspace(after stale claim) error = %v", err)
	}
	current, err := harness.blobs.Head(context.Background(), key)
	if err != nil || current.Version != v2.Version {
		t.Fatalf("current blob = %#v, %v; stale retirement replaced v2", current, err)
	}
}

func TestUncertainBlobWriteRemainsInflightUntilAbandonedThenSwept(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("uncertain"), 1<<20)
	harness.blobs.FailAfterPut(errors.New("lost response"))
	_, err := harness.service.CreateFromWorkspace(context.Background(), harness.createRequest(invocationA))
	if err == nil {
		t.Fatal("CreateFromWorkspace() error = nil")
	}
	if stats := harness.repository.Stats(tenantA); stats.ReservedBytes != int64(len("uncertain")) || stats.Invocations != 1 {
		t.Fatalf("uncertain write lost ledger protection: %#v", stats)
	}
	if harness.blobs.ObjectCount() != 1 {
		t.Fatalf("uncertain write object count = %d, want 1", harness.blobs.ObjectCount())
	}
	harness.blobs.FailAfterPut(nil)
	harness.advance(30 * time.Minute)
	result, err := harness.service.CollectGarbage(context.Background())
	if err != nil || result.DeletedObjects != 0 || result.AbandonedInvocations != 0 {
		t.Fatalf("young inflight GC = %#v, %v", result, err)
	}
	harness.advance(2 * time.Hour)
	result, err = harness.service.CollectGarbage(context.Background())
	if err != nil || result.AbandonedInvocations != 1 || result.DeletedObjects != 1 {
		t.Fatalf("abandoned invocation GC = %#v, %v", result, err)
	}
	if stats := harness.repository.Stats(tenantA); stats.ReservedBytes != 0 || stats.UsedBytes != 0 {
		t.Fatalf("abandoned reservation remained: %#v", stats)
	}
	if _, err := harness.service.CreateFromWorkspace(context.Background(), harness.createRequest(invocationA)); !errors.Is(err, ErrInvocationAbandoned) {
		t.Fatalf("replay of abandoned invocation error = %v, want ErrInvocationAbandoned", err)
	}
}

func TestUncertainBlobWriteReplayRecoversWithoutWorkspaceSnapshot(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("recover without workspace"), 1<<20)
	request := harness.createRequest(invocationA)
	harness.blobs.FailAfterPut(errors.New("write response lost"))
	if _, err := harness.service.CreateFromWorkspace(context.Background(), request); err == nil {
		t.Fatal("CreateFromWorkspace(first) error = nil")
	}
	harness.blobs.FailAfterPut(nil)
	harness.source.setError(errors.New("snapshot retention elapsed"))
	ref, err := harness.service.CreateFromWorkspace(context.Background(), request)
	if err != nil {
		t.Fatalf("CreateFromWorkspace(replay) error = %v", err)
	}
	opened, err := harness.service.Open(context.Background(), OpenRequest{Access: harness.access, ArtifactID: ref.ArtifactID})
	if err != nil || string(opened.Data) != "recover without workspace" {
		t.Fatalf("Open(recovered) = %q, %v", opened.Data, err)
	}
}

func TestUncertainBlobReplayHeartbeatsDuringSlowReconciliation(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("slow reconciliation"), 1<<20)
	request := harness.createRequest(invocationA)
	harness.blobs.FailAfterPut(errors.New("write response lost"))
	if _, err := harness.service.CreateFromWorkspace(context.Background(), request); err == nil {
		t.Fatal("CreateFromWorkspace(first) error = nil")
	}
	harness.blobs.FailAfterPut(nil)
	harness.source.setError(errors.New("snapshot retention elapsed"))
	harness.service.inflightTimeout = 50 * time.Millisecond
	harness.service.inflightHeartbeatInterval = 5 * time.Millisecond
	blocking := &blockingGetBlobStore{
		MemoryBlobStore: harness.blobs, started: make(chan struct{}), release: make(chan struct{}),
	}
	harness.service.blobs = blocking
	replayDone := make(chan error, 1)
	go func() {
		_, replayErr := harness.service.CreateFromWorkspace(context.Background(), request)
		replayDone <- replayErr
	}()
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("replay did not reach blob reconciliation")
	}
	recordBefore, found, err := harness.repository.LookupInvocation(context.Background(), invocationA)
	if err != nil || !found {
		t.Fatalf("LookupInvocation(before) = %#v, %t, %v", recordBefore, found, err)
	}
	harness.advance(time.Hour)
	deadline := time.Now().Add(time.Second)
	for {
		record, _, lookupErr := harness.repository.LookupInvocation(context.Background(), invocationA)
		if lookupErr != nil {
			t.Fatalf("LookupInvocation() error = %v", lookupErr)
		}
		if record.HeartbeatAt.After(recordBefore.HeartbeatAt) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("reconciliation heartbeat did not advance: before=%s after=%s", recordBefore.HeartbeatAt, record.HeartbeatAt)
		}
		time.Sleep(time.Millisecond)
	}
	result, err := harness.service.CollectGarbage(context.Background())
	if err != nil || result.AbandonedInvocations != 0 {
		t.Fatalf("GC abandoned active reconciliation: %#v, %v", result, err)
	}
	close(blocking.release)
	if err := <-replayDone; err != nil {
		t.Fatalf("CreateFromWorkspace(replay) error = %v", err)
	}
}

func TestPendingSweepQueueCannotStarveAnUnresolvedClaim(t *testing.T) {
	t.Parallel()
	repository := NewMemoryRepository(map[string]int64{tenantA: 1 << 20})
	lease, acquired, err := repository.AcquireGC(context.Background(), baseTime, time.Hour)
	if err != nil || !acquired {
		t.Fatalf("AcquireGC() = %#v, %t, %v", lease, acquired, err)
	}
	for _, key := range []string{"a", "b"} {
		if _, claimed, claimErr := repository.ClaimSweepLeased(context.Background(), lease, key, "v-"+key, baseTime); claimErr != nil || !claimed {
			t.Fatalf("ClaimSweepLeased(%q) claimed=%t error=%v", key, claimed, claimErr)
		}
	}
	claims, cursor, _, err := repository.PendingSweepsPage(context.Background(), lease, "", 1)
	if err != nil || len(claims) != 1 || claims[0].ObjectKey != "a" {
		t.Fatalf("first PendingSweepsPage() = %#v, %q, %v", claims, cursor, err)
	}
	if _, err := repository.FinishSweepLeased(context.Background(), lease, claims[0], false, baseTime); err != nil {
		t.Fatalf("FinishSweepLeased(unresolved) error = %v", err)
	}
	seenAgain := false
	for index, key := range []string{"c", "d", "e"} {
		if _, claimed, claimErr := repository.ClaimSweepLeased(context.Background(), lease, key, "v-"+key, baseTime); claimErr != nil || !claimed {
			t.Fatalf("ClaimSweepLeased(%q) claimed=%t error=%v", key, claimed, claimErr)
		}
		claims, next, _, pageErr := repository.PendingSweepsPage(context.Background(), lease, cursor, 1)
		if pageErr != nil || len(claims) != 1 {
			t.Fatalf("PendingSweepsPage(%d) = %#v, %q, %v", index, claims, next, pageErr)
		}
		cursor = next
		if claims[0].ObjectKey == "a" {
			seenAgain = true
			break
		}
	}
	if !seenAgain {
		t.Fatal("unresolved claim was starved by continuously arriving later claims")
	}
}

func TestMemoryPagesBoundPerCallWorkAndDoNotAccumulateSnapshots(t *testing.T) {
	t.Parallel()
	store := NewMemoryBlobStore()
	for index := range 64 {
		data := []byte(fmt.Sprintf("object-%d", index))
		if err := store.PutIfAbsent(context.Background(), BlobPut{
			Key: fmt.Sprintf("key-%03d", index), Digest: digestBytes(data), Data: data, CreatedAt: baseTime,
		}); err != nil {
			t.Fatalf("PutIfAbsent(%d) error = %v", index, err)
		}
	}
	baseline := store.EnumerationStateSize()
	for cycle := range 10 {
		request := BlobListRequest{Limit: 3}
		for {
			page, err := store.ListPage(context.Background(), request)
			if err != nil {
				t.Fatalf("ListPage(cycle %d) error = %v", cycle, err)
			}
			if scanned := store.LastListScanCount(); scanned > request.Limit {
				t.Fatalf("ListPage scanned %d records with limit %d", scanned, request.Limit)
			}
			if page.Done {
				break
			}
			request.Epoch, request.Cursor = page.Epoch, page.NextCursor
		}
	}
	if stateSize := store.EnumerationStateSize(); stateSize != baseline {
		t.Fatalf("completed enumerations grew state from %d to %d", baseline, stateSize)
	}

	repository := NewMemoryRepository(map[string]int64{tenantA: 1 << 20})
	for index := range 64 {
		invocationID := "inv_" + string(testIDAlphabet[index%len(testIDAlphabet)]) + fmt.Sprintf("%025d", index)
		_, _, err := repository.BeginCreate(context.Background(), CreateReservation{
			TenantID: tenantA, InvocationID: invocationID, RequestDigest: digestBytes([]byte(invocationID)),
			ArtifactID: "artifact_" + string(testIDAlphabet[index%len(testIDAlphabet)]) + fmt.Sprintf("%025d", index),
			ObjectKey:  fmt.Sprintf("key-%03d", index), Size: 1, StartedAt: baseTime,
		})
		if err != nil {
			t.Fatalf("BeginCreate(%d) error = %v", index, err)
		}
	}
	lease, acquired, err := repository.AcquireGC(context.Background(), baseTime.Add(time.Hour), time.Minute)
	if err != nil || !acquired {
		t.Fatalf("AcquireGC() = %#v, %t, %v", lease, acquired, err)
	}
	if _, _, _, err := repository.AbandonInflightPage(context.Background(), lease, baseTime.Add(time.Hour), "", 3); err != nil {
		t.Fatalf("AbandonInflightPage() error = %v", err)
	}
	if scanned := repository.LastInvocationScanCount(); scanned > 3 {
		t.Fatalf("AbandonInflightPage scanned %d records with limit 3", scanned)
	}
}

func TestActiveSlowBlobWriteIsProtectedByInvocationHeartbeat(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("slow durable write"), 1<<20)
	harness.service.inflightTimeout = 50 * time.Millisecond
	harness.service.inflightHeartbeatInterval = 5 * time.Millisecond
	blocking := &blockingPutBlobStore{
		MemoryBlobStore: harness.blobs, started: make(chan struct{}), release: make(chan struct{}),
	}
	harness.service.blobs = blocking
	createDone := make(chan error, 1)
	go func() {
		_, createErr := harness.service.CreateFromWorkspace(context.Background(), harness.createRequest(invocationA))
		createDone <- createErr
	}()
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("create did not reach blob write")
	}
	recordBefore, found, err := harness.repository.LookupInvocation(context.Background(), invocationA)
	if err != nil || !found || recordBefore.Generation == 0 {
		t.Fatalf("initial invocation = %#v, %t, %v", recordBefore, found, err)
	}
	harness.advance(time.Hour)
	deadline := time.Now().Add(time.Second)
	for {
		record, _, lookupErr := harness.repository.LookupInvocation(context.Background(), invocationA)
		if lookupErr != nil {
			t.Fatalf("LookupInvocation() error = %v", lookupErr)
		}
		if record.HeartbeatAt.After(recordBefore.HeartbeatAt) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("invocation heartbeat did not advance: before=%s after=%s", recordBefore.HeartbeatAt, record.HeartbeatAt)
		}
		time.Sleep(time.Millisecond)
	}
	result, err := harness.service.CollectGarbage(context.Background())
	if err != nil || result.AbandonedInvocations != 0 {
		t.Fatalf("GC abandoned active write: %#v, %v", result, err)
	}
	close(blocking.release)
	if err := <-createDone; err != nil {
		t.Fatalf("CreateFromWorkspace() error = %v", err)
	}
}

func TestCreateBoundsAllCallerControlledInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*CreateRequest)
	}{
		{name: "empty invocation", mutate: func(request *CreateRequest) { request.InvocationID = "" }},
		{name: "untyped tenant", mutate: func(request *CreateRequest) { request.Access.TenantID = "tenant-a" }},
		{name: "path traversal", mutate: func(request *CreateRequest) { request.Source.Path = "out/../secret" }},
		{name: "long name", mutate: func(request *CreateRequest) { request.Metadata.Name = strings.Repeat("x", 256) }},
		{name: "long media type", mutate: func(request *CreateRequest) { request.Metadata.MediaType = strings.Repeat("x", 256) }},
		{name: "too many attributes", mutate: func(request *CreateRequest) {
			request.Metadata.Attributes = map[string]string{}
			for index := range 65 {
				request.Metadata.Attributes[fmt.Sprintf("k%d", index)] = "v"
			}
		}},
		{name: "too much retention", mutate: func(request *CreateRequest) { request.Metadata.RetainFor = 31 * 24 * time.Hour }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newHarness(t, []byte("bounded"), 1<<20)
			request := harness.createRequest(invocationA)
			test.mutate(&request)
			if _, err := harness.service.CreateFromWorkspace(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("CreateFromWorkspace() error = %v, want ErrInvalidRequest", err)
			}
			if harness.blobs.ObjectCount() != 0 {
				t.Fatal("invalid request reached blob store")
			}
		})
	}
}

func TestOpenDetectsContentAddressedStorageCorruption(t *testing.T) {
	t.Parallel()
	harness := newHarness(t, []byte("trusted"), 1<<20)
	ref, err := harness.service.CreateFromWorkspace(context.Background(), harness.createRequest(invocationA))
	if err != nil {
		t.Fatalf("CreateFromWorkspace() error = %v", err)
	}
	harness.blobs.Corrupt(ref.ObjectKey, []byte("tampered"))
	if _, err := harness.service.Open(context.Background(), OpenRequest{Access: harness.access, ArtifactID: ref.ArtifactID}); !errors.Is(err, ErrStorageCorruption) {
		t.Fatalf("Open(corrupt) error = %v, want ErrStorageCorruption", err)
	}
}

type testHarness struct {
	service    *Service
	source     *fakeWorkspaceReader
	authorizer *fakeAuthorizer
	repository *MemoryRepository
	blobs      *MemoryBlobStore
	access     AccessContext
	mu         sync.Mutex
	now        time.Time
}

func newHarness(t *testing.T, data []byte, quota int64) *testHarness {
	t.Helper()
	harness := &testHarness{
		source:     &fakeWorkspaceReader{data: append([]byte(nil), data...)},
		authorizer: newFakeAuthorizer(),
		repository: NewMemoryRepository(map[string]int64{tenantA: quota, tenantB: quota}),
		blobs:      NewMemoryBlobStore(),
		access: AccessContext{
			TenantID: tenantA, SubjectID: subjectA, SessionID: sessionA, WorkspaceID: workspaceA,
		},
		now: baseTime,
	}
	var sequence atomic.Uint32
	service, err := NewService(Config{
		Workspace:  harness.source,
		Authorizer: harness.authorizer,
		Repository: harness.repository,
		Blobs:      harness.blobs,
		Now:        harness.currentTime,
		NewArtifactID: func() (string, error) {
			value := sequence.Add(1)
			character := testIDAlphabet[(value-1)%uint32(len(testIDAlphabet))]
			return "artifact_" + string(character) + strings.Repeat("A", 25), nil
		},
		MaximumArtifactBytes: 1 << 20,
		DefaultRetention:     24 * time.Hour,
		MaximumRetention:     30 * 24 * time.Hour,
		GCGrace:              time.Hour,
		InflightTimeout:      2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	harness.service = service
	return harness
}

func (harness *testHarness) createRequest(invocationID string) CreateRequest {
	return CreateRequest{
		Access:       harness.access,
		InvocationID: invocationID,
		Source: WorkspaceSource{
			RevisionID: revisionA,
			Path:       "out/report.pdf",
		},
		Metadata: Metadata{Name: "report.pdf", MediaType: "application/pdf"},
	}
}

func (harness *testHarness) currentTime() time.Time {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	return harness.now
}

func (harness *testHarness) advance(duration time.Duration) {
	harness.mu.Lock()
	harness.now = harness.now.Add(duration)
	harness.mu.Unlock()
}

type fakeWorkspaceReader struct {
	mu      sync.Mutex
	data    []byte
	request WorkspaceReadRequest
	mutate  func(*WorkspaceFile)
	err     error
}

func (reader *fakeWorkspaceReader) ReadFile(_ context.Context, request WorkspaceReadRequest) (WorkspaceFile, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.request = request
	if reader.err != nil {
		return WorkspaceFile{}, reader.err
	}
	data := append([]byte(nil), reader.data...)
	file := WorkspaceFile{
		TenantID: request.TenantID, WorkspaceID: request.WorkspaceID,
		RevisionID: request.RevisionID, Path: request.Path, Kind: WorkspaceRegularFile,
		Size: int64(len(data)), ContentDigest: digestBytes(data), Data: data,
	}
	if reader.mutate != nil {
		reader.mutate(&file)
	}
	return file, nil
}

func (reader *fakeWorkspaceReader) setError(err error) {
	reader.mu.Lock()
	reader.err = err
	reader.mu.Unlock()
}

func (reader *fakeWorkspaceReader) lastRequest() WorkspaceReadRequest {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.request
}

type fakeAuthorizer struct {
	mu       sync.Mutex
	denied   map[Operation]bool
	requests []AuthorizationRequest
}

func newFakeAuthorizer() *fakeAuthorizer {
	return &fakeAuthorizer{denied: map[Operation]bool{}}
}

func (authorizer *fakeAuthorizer) Authorize(_ context.Context, request AuthorizationRequest) error {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	authorizer.requests = append(authorizer.requests, request)
	if authorizer.denied[request.Operation] {
		return ErrAccessDenied
	}
	return nil
}

func (authorizer *fakeAuthorizer) deny(operation Operation) {
	authorizer.mu.Lock()
	authorizer.denied[operation] = true
	authorizer.mu.Unlock()
}

func (authorizer *fakeAuthorizer) allow(operation Operation) {
	authorizer.mu.Lock()
	delete(authorizer.denied, operation)
	authorizer.mu.Unlock()
}

func (authorizer *fakeAuthorizer) requestsSnapshot() []AuthorizationRequest {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	return append([]AuthorizationRequest(nil), authorizer.requests...)
}

type blockingPutBlobStore struct {
	*MemoryBlobStore
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type blockingGetBlobStore struct {
	*MemoryBlobStore
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (store *blockingGetBlobStore) Get(ctx context.Context, key string) (BlobObject, error) {
	store.once.Do(func() { close(store.started) })
	select {
	case <-store.release:
		return store.MemoryBlobStore.Get(ctx, key)
	case <-ctx.Done():
		return BlobObject{}, ctx.Err()
	}
}

func (store *blockingPutBlobStore) PutIfAbsent(ctx context.Context, request BlobPut) error {
	store.once.Do(func() { close(store.started) })
	select {
	case <-store.release:
		return store.MemoryBlobStore.PutIfAbsent(ctx, request)
	case <-ctx.Done():
		return ctx.Err()
	}
}

type blockingDeleteBlobStore struct {
	*MemoryBlobStore
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (store *blockingDeleteBlobStore) DeleteIfVersion(ctx context.Context, key string, version string) error {
	store.once.Do(func() { close(store.started) })
	select {
	case <-store.release:
		return store.MemoryBlobStore.DeleteIfVersion(ctx, key, version)
	case <-ctx.Done():
		return ctx.Err()
	}
}

type delayedFirstDeleteBlobStore struct {
	*MemoryBlobStore
	firstStarted chan struct{}
	releaseFirst chan struct{}
	calls        atomic.Uint32
}

func (store *delayedFirstDeleteBlobStore) DeleteIfVersion(ctx context.Context, key string, version string) error {
	if store.calls.Add(1) == 1 {
		close(store.firstStarted)
		select {
		case <-store.releaseFirst:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return store.MemoryBlobStore.DeleteIfVersion(ctx, key, version)
}
