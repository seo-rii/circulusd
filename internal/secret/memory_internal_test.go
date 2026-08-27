package secret

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

type cancelAfterInitialCheckContext struct {
	context.Context
	checks atomic.Int32
}

func (ctx *cancelAfterInitialCheckContext) Err() error {
	if ctx.checks.Add(1) > 1 {
		return context.Canceled
	}
	return nil
}

func testUseAdmission(record Record, recovery UseRecoveryBinding) UseAdmissionPermit {
	now := time.Now().Round(0).UTC()
	operation := OperationSandboxUse
	if record.Exposure != ExposureSandboxEnv && record.Exposure != ExposureSandboxFile {
		operation = OperationGatewayUse
	}
	return UseAdmissionPermit{
		Authorization: AuthorizationRequest{
			Operation: operation,
			Access: AccessContext{
				TenantID: recovery.TenantID, SubjectID: recovery.SubjectID,
				SessionID: recovery.SessionID, WorkspaceID: recovery.WorkspaceID,
				TurnID: recovery.TurnID, RuntimeRevision: recovery.RuntimeRevision,
				TurnLeaseGeneration:     recovery.TurnLeaseGeneration,
				PlacementGeneration:     recovery.PlacementGeneration,
				SandboxGeneration:       recovery.SandboxGeneration,
				AuthorizationGeneration: recovery.AuthorizationGeneration,
				Permission:              recovery.Permission, ServiceBinding: recovery.ServiceBinding,
				AuthorityExpiresAt: recovery.AuthorityExpiresAt,
			},
			SecretID: record.SecretID, Exposure: record.Exposure,
			Endpoint: recovery.Endpoint, Audience: recovery.Audience,
			InvocationID: recovery.InvocationID,
		},
		HandleExpiresAt: now.Add(time.Minute), IssuedAt: now,
		ExpiresAt: now.Add(time.Minute), Proof: "test-admission-proof",
	}
}

func withTestAuthority(recovery UseRecoveryBinding) UseRecoveryBinding {
	recovery.TurnID = "turn_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	recovery.RuntimeRevision = "runtime_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	recovery.TurnLeaseGeneration = 5
	recovery.PlacementGeneration = 7
	recovery.SandboxGeneration = 11
	recovery.AuthorizationGeneration = 3
	recovery.Permission = "secret.use"
	recovery.ServiceBinding = "secret"
	recovery.AuthorityExpiresAt = time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)
	return recovery
}

func TestMemoryStoreClearsReplacedCredentialAndAllowsEmptyRevocation(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	initial := Record{
		SecretID: "secret_rotation", TenantID: "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA", Version: 1,
		Exposure: ExposureProxyOnly, Value: []byte("old-secret-buffer"),
		InjectionName: "Authorization", Endpoint: "https://proxy.internal",
		Audience: "proxy.internal", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, initial); err != nil {
		t.Fatalf("CompareAndSwap(create) error = %v", err)
	}
	store.mu.RLock()
	oldBacking := store.records[initial.TenantID+"\x00"+initial.SecretID].Value
	store.mu.RUnlock()
	revoked := initial
	revoked.Version = 2
	revoked.Value = nil
	revoked.Active = false
	if err := store.CompareAndSwap(ctx, 1, revoked); err != nil {
		t.Fatalf("CompareAndSwap(revoke) error = %v", err)
	}
	for _, value := range oldBacking {
		if value != 0 {
			t.Fatalf("replaced credential buffer was not cleared: %v", oldBacking)
		}
	}
	stored, err := store.Get(ctx, initial.TenantID, initial.SecretID)
	if err != nil || stored.Active || len(stored.Value) != 0 {
		t.Fatalf("Get(revoked) = %#v, %v", stored, err)
	}
}

func TestMemoryStoreGetAndRotationNeverRaceOrReturnPartiallyClearedValue(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	const size = maximumDefaultSecretBytes
	record := Record{
		SecretID: "secret_get_rotate", TenantID: "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA", Version: 1,
		Exposure: ExposureProxyOnly, Value: []byte(strings.Repeat("a", size)),
		InjectionName: "Authorization", Endpoint: "https://proxy.internal",
		Audience: "proxy.internal", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap(create) error = %v", err)
	}

	var wait sync.WaitGroup
	start := make(chan struct{})
	readErrors := make(chan error, 64)
	for range 64 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			got, err := store.Get(ctx, record.TenantID, record.SecretID)
			if err != nil {
				readErrors <- err
				return
			}
			if len(got.Value) != size {
				readErrors <- errors.New("unexpected credential length")
				return
			}
			for _, value := range got.Value {
				if value != 'a' && value != 'b' {
					readErrors <- errors.New("partially cleared credential read")
					return
				}
			}
		}()
	}
	close(start)
	next := record
	next.Version = 2
	next.Value = []byte(strings.Repeat("b", size))
	if err := store.CompareAndSwap(ctx, 1, next); err != nil {
		t.Fatalf("CompareAndSwap(rotate) error = %v", err)
	}
	wait.Wait()
	close(readErrors)
	for err := range readErrors {
		t.Fatal(err)
	}
}

func TestMemoryStoreNeverRebindsCompletedRecoveryID(t *testing.T) {
	ctx := context.Background()
	record := Record{
		SecretID: "secret_completed_recovery", TenantID: "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA", Version: 1,
		Exposure: ExposureSandboxEnv, Value: []byte("sandbox-value"),
		InjectionName: "SERVICE_TOKEN", Active: true,
	}
	recovery := withTestAuthority(UseRecoveryBinding{
		TenantID: record.TenantID, SubjectID: "subject_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		SessionID: "sess_AAAAAAAAAAAAAAAAAAAAAAAAAA", WorkspaceID: "ws_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		SecretID: record.SecretID, SecretVersion: record.Version,
		Exposure: record.Exposure, InvocationID: "inv_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		RecoveryID:       "op_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		ResolvedCacheKey: "sha256:" + strings.Repeat("a", 64),
	})

	for name, nextRecovery := range map[string]UseRecoveryBinding{
		"exact": recovery,
		"same ID with altered binding": func() UseRecoveryBinding {
			altered := recovery
			altered.ResolvedCacheKey = "sha256:" + strings.Repeat("b", 64)
			return altered
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			store := NewMemoryStore()
			if err := store.CompareAndSwap(ctx, 0, record); err != nil {
				t.Fatalf("CompareAndSwap() error = %v", err)
			}
			_, _, err := store.BeginUse(ctx, BeginUseRequest{
				TenantID: record.TenantID, SecretID: record.SecretID,
				ExpectedVersion: record.Version, Recovery: recovery,
				Admission: testUseAdmission(record, recovery),
			})
			if err != nil {
				t.Fatalf("BeginUse(first) error = %v", err)
			}
			if err := store.CompleteUseRecovery(ctx, recovery); err != nil {
				t.Fatalf("CompleteUseRecovery() error = %v", err)
			}
			if _, _, err := store.BeginUse(ctx, BeginUseRequest{
				TenantID: record.TenantID, SecretID: record.SecretID,
				ExpectedVersion: record.Version, Recovery: nextRecovery,
				Admission: testUseAdmission(record, nextRecovery),
			}); !errors.Is(err, ErrUseLeaseInvalid) {
				t.Fatalf("BeginUse(completed recovery ID) error = %v, want ErrUseLeaseInvalid", err)
			}
		})
	}
}

func TestMemoryStoreListsPendingRecoveriesInBoundedStablePages(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	for index, suffix := range []string{"I", "A", "E"} {
		record := Record{
			SecretID: "secret_pending_" + strings.ToLower(suffix),
			TenantID: "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA", Version: 1,
			Exposure: ExposureSandboxEnv, Value: []byte("raw-must-not-be-enumerated"),
			InjectionName: "SERVICE_TOKEN", Active: true,
		}
		if err := store.CompareAndSwap(ctx, 0, record); err != nil {
			t.Fatalf("CompareAndSwap(%d) error = %v", index, err)
		}
		recovery := withTestAuthority(UseRecoveryBinding{
			TenantID: record.TenantID, SubjectID: "subject_AAAAAAAAAAAAAAAAAAAAAAAAAA",
			SessionID: "sess_AAAAAAAAAAAAAAAAAAAAAAAAAA", WorkspaceID: "ws_AAAAAAAAAAAAAAAAAAAAAAAAAA",
			SecretID: record.SecretID, SecretVersion: 1,
			Exposure: record.Exposure, InvocationID: "inv_AAAAAAAAAAAAAAAAAAAAAAAAAA",
			RecoveryID:       "op_AAAAAAAAAAAAAAAAAAAAAAAAA" + suffix,
			ResolvedCacheKey: "sha256:" + strings.Repeat(fmt.Sprintf("%x", index+1), 64),
		})
		if _, _, err := store.BeginUse(ctx, BeginUseRequest{
			TenantID: record.TenantID, SecretID: record.SecretID, ExpectedVersion: 1, Recovery: recovery,
			Admission: testUseAdmission(record, recovery),
		}); err != nil {
			t.Fatalf("BeginUse(%d) error = %v", index, err)
		}
	}

	first, err := store.ListPendingUseRecoveries(ctx, PendingUseRecoveryQuery{
		TenantID: "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA", Limit: 2,
	})
	if err != nil {
		t.Fatalf("ListPendingUseRecoveries(first) error = %v", err)
	}
	if len(first.Recoveries) != 2 || first.Recoveries[0].RecoveryID != "op_AAAAAAAAAAAAAAAAAAAAAAAAAA" ||
		first.Recoveries[1].RecoveryID != "op_AAAAAAAAAAAAAAAAAAAAAAAAAE" ||
		first.NextAfterRecoveryID != first.Recoveries[1].RecoveryID {
		t.Fatalf("first recovery page = %#v", first)
	}
	if strings.Contains(fmt.Sprintf("%#v", first), "raw-must-not-be-enumerated") {
		t.Fatal("pending recovery enumeration exposed credential material")
	}
	second, err := store.ListPendingUseRecoveries(ctx, PendingUseRecoveryQuery{
		TenantID:        "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		AfterRecoveryID: first.NextAfterRecoveryID, Limit: 2,
	})
	if err != nil || len(second.Recoveries) != 1 ||
		second.Recoveries[0].RecoveryID != "op_AAAAAAAAAAAAAAAAAAAAAAAAAI" || second.NextAfterRecoveryID != "" {
		t.Fatalf("second recovery page = %#v, %v", second, err)
	}
}

func TestMemoryStoreClearsRejectedCompareAndSwapCopy(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	initial := Record{
		SecretID: "secret_rejected_copy", TenantID: "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA", Version: 1,
		Exposure: ExposureProxyOnly, Value: []byte("active-value"),
		InjectionName: "Authorization", Endpoint: "https://proxy.internal",
		Audience: "proxy.internal", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, initial); err != nil {
		t.Fatalf("CompareAndSwap(create) error = %v", err)
	}
	var rejectedCopy []byte
	store.cloneRecordForWrite = func(record Record) Record {
		copy := cloneRecord(record)
		rejectedCopy = copy.Value
		return copy
	}
	conflicting := initial
	conflicting.Version = 2
	conflicting.Value = []byte("rejected-sensitive-copy")
	if err := store.CompareAndSwap(ctx, 0, conflicting); !errors.Is(err, ErrStoreConflict) {
		t.Fatalf("CompareAndSwap(conflict) error = %v, want ErrStoreConflict", err)
	}
	if len(rejectedCopy) == 0 {
		t.Fatal("test did not observe the rejected store-owned copy")
	}
	for _, value := range rejectedCopy {
		if value != 0 {
			t.Fatalf("rejected store-owned copy was not cleared: %v", rejectedCopy)
		}
	}
}

func TestMemoryStoreValidatesAdmissionExpiryAndGenerationInsideUseTransaction(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 27, 18, 0, 0, 0, time.UTC)
	record := Record{
		SecretID: "secret_atomic_admission", TenantID: "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA", Version: 1,
		Exposure: ExposureSandboxEnv, Value: []byte("must-not-return"),
		InjectionName: "SERVICE_TOKEN", Active: true,
	}
	recovery := withTestAuthority(UseRecoveryBinding{
		TenantID: record.TenantID, SubjectID: "subject_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		SessionID: "sess_AAAAAAAAAAAAAAAAAAAAAAAAAA", WorkspaceID: "ws_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		SecretID: record.SecretID, SecretVersion: 1,
		Exposure: record.Exposure, InvocationID: "inv_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		RecoveryID:       "op_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		ResolvedCacheKey: "sha256:" + strings.Repeat("a", 64),
	})

	for name, mutate := range map[string]func(*UseAdmissionPermit){
		"expired": func(permit *UseAdmissionPermit) {
			permit.HandleExpiresAt = now
			permit.ExpiresAt = now
		},
		"generation mismatch": func(permit *UseAdmissionPermit) {
			permit.Authorization.Access.AuthorizationGeneration++
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := NewMemoryStoreWithClock(func() time.Time { return now })
			if err := store.CompareAndSwap(ctx, 0, record); err != nil {
				t.Fatalf("CompareAndSwap() error = %v", err)
			}
			admission := testUseAdmission(record, recovery)
			admission.IssuedAt = now.Add(-time.Second)
			admission.ExpiresAt = now.Add(time.Minute)
			admission.HandleExpiresAt = now.Add(time.Minute)
			mutate(&admission)
			got, _, err := store.BeginUse(ctx, BeginUseRequest{
				TenantID: record.TenantID, SecretID: record.SecretID,
				ExpectedVersion: 1, Recovery: recovery, Admission: admission,
			})
			if !errors.Is(err, ErrAccessDenied) || len(got.Value) != 0 {
				t.Fatalf("BeginUse(%s) = %#v, %v, want no raw material and ErrAccessDenied", name, got, err)
			}
			if store.activeByKey[record.TenantID+"\x00"+record.SecretID] != 0 {
				t.Fatal("rejected admission installed a use lease")
			}
		})
	}
}

func TestMemoryStoreNeverReturnsRawMaterialWithoutRecoveryBinding(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	record := Record{
		SecretID: "secret_missing_recovery", TenantID: "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA", Version: 1,
		Exposure: ExposureProxyOnly, Value: []byte("must-not-return"),
		InjectionName: "Authorization", Endpoint: "https://proxy.internal",
		Audience: "proxy.internal", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	recovery := withTestAuthority(UseRecoveryBinding{
		TenantID: record.TenantID, SubjectID: "subject_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		SessionID: "sess_AAAAAAAAAAAAAAAAAAAAAAAAAA", WorkspaceID: "ws_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		SecretID: record.SecretID, SecretVersion: 1,
		Exposure: record.Exposure, RecoveryID: "op_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		Endpoint: record.Endpoint, Audience: record.Audience,
	})
	got, _, err := store.BeginUse(ctx, BeginUseRequest{
		TenantID: record.TenantID, SecretID: record.SecretID, ExpectedVersion: 1,
		Admission: testUseAdmission(record, recovery),
	})
	if !errors.Is(err, ErrUseLeaseInvalid) || len(got.Value) != 0 {
		t.Fatalf("BeginUse(without recovery) = %#v, %v, want no raw material and ErrUseLeaseInvalid", got, err)
	}
}

func TestMemoryStoreRejectsUnsafeSandboxFilePaths(t *testing.T) {
	for name, injectionName := range map[string]string{
		"nul":       "/run/credentials/token\x00ignored",
		"newline":   "/run/credentials/token\nignored",
		"oversized": "/run/credentials/" + strings.Repeat("a", maximumTextBytes),
	} {
		t.Run(name, func(t *testing.T) {
			store := NewMemoryStore()
			err := store.CompareAndSwap(context.Background(), 0, Record{
				SecretID: "secret_unsafe_path", TenantID: "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA",
				Version: 1, Exposure: ExposureSandboxFile, Value: []byte("raw"),
				InjectionName: injectionName, Active: true,
			})
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("CompareAndSwap(%q) error = %v, want ErrInvalidRequest", injectionName, err)
			}
		})
	}
}

func TestMemoryStoreRechecksCancellationAtUseLinearizationBoundary(t *testing.T) {
	store := NewMemoryStore()
	record := Record{
		SecretID: "secret_cancel_linearize", TenantID: "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		Version: 1, Exposure: ExposureProxyOnly, Value: []byte("must-not-return"),
		InjectionName: "Authorization", Endpoint: "https://proxy.internal",
		Audience: "proxy.internal", Active: true,
	}
	if err := store.CompareAndSwap(context.Background(), 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	recovery := withTestAuthority(UseRecoveryBinding{
		TenantID: record.TenantID, SubjectID: "subject_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		SessionID: "sess_AAAAAAAAAAAAAAAAAAAAAAAAAA", WorkspaceID: "ws_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		SecretID: record.SecretID, SecretVersion: 1, Exposure: record.Exposure,
		RecoveryID: "op_AAAAAAAAAAAAAAAAAAAAAAAAAA", Endpoint: record.Endpoint, Audience: record.Audience,
	})
	ctx := &cancelAfterInitialCheckContext{Context: context.Background()}
	got, _, err := store.BeginUse(ctx, BeginUseRequest{
		TenantID: record.TenantID, SecretID: record.SecretID, ExpectedVersion: 1,
		Recovery: recovery, Admission: testUseAdmission(record, recovery),
	})
	if !errors.Is(err, context.Canceled) || len(got.Value) != 0 {
		t.Fatalf("BeginUse(cancelled at linearization) = %#v, %v, want no raw material/context.Canceled", got, err)
	}
	if store.activeByKey[record.TenantID+"\x00"+record.SecretID] != 0 {
		t.Fatal("cancelled BeginUse installed a durable recovery lease")
	}
}
