package tenant_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/tenant"
)

type fixture struct {
	repository *tenant.MemoryRepository

	tenantA    identity.ID
	tenantB    identity.ID
	workspaceA identity.ID
	workspaceB identity.ID
	platform   identity.ID
	adminA     identity.ID
	ownerA     identity.ID
	memberA    identity.ID
	userA      identity.ID
	memberB    identity.ID
}

type recordingLifecycleVerifier struct {
	mu       sync.Mutex
	receipt  tenant.TeardownReceipt
	err      error
	requests []tenant.TeardownVerificationRequest
}

func (verifier *recordingLifecycleVerifier) VerifyTeardown(
	_ context.Context,
	request tenant.TeardownVerificationRequest,
) (tenant.TeardownReceipt, error) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.requests = append(verifier.requests, request)
	return verifier.receipt, verifier.err
}

type claimedDurableRepository struct {
	tenant.Repository
}

func (claimedDurableRepository) Durability() tenant.RepositoryDurability {
	return tenant.RepositoryDurability{
		CrashDurable:             true,
		AtomicExpectedVersionCAS: true,
		AtomicMutationReceipt:    true,
	}
}

func (repository claimedDurableRepository) Release(
	ctx context.Context,
	request tenant.TransitionRequest,
) (tenant.Receipt, error) {
	receipt, err := repository.Repository.Release(ctx, request)
	receipt.Durable = err == nil
	return receipt, err
}

func (repository claimedDurableRepository) Recover(
	ctx context.Context,
	request tenant.RecoveryRequest,
) (tenant.Recovery, error) {
	recovery, err := repository.Repository.Recover(ctx, request)
	recovery.Receipt.Durable = err == nil
	return recovery, err
}

func TestACLRequiresTenantMembershipAndWorkspaceGrant(t *testing.T) {
	t.Parallel()
	f := newFixture(t, testLimits())
	ctx := context.Background()

	tests := []struct {
		name      string
		principal identity.ID
		resource  tenant.Resource
		action    tenant.Action
		wantRole  tenant.Role
		wantErr   error
	}{
		{
			name:      "platform administrator may explicitly target another tenant",
			principal: f.platform,
			resource:  tenant.Resource{TenantID: f.tenantB, WorkspaceID: f.workspaceB},
			action:    tenant.ActionWorkspaceManage,
			wantRole:  tenant.RolePlatformAdmin,
		},
		{
			name:      "tenant administrator controls a workspace in its tenant",
			principal: f.adminA,
			resource:  tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA},
			action:    tenant.ActionWorkspaceManage,
			wantRole:  tenant.RoleTenantAdmin,
		},
		{
			name:      "workspace owner manages its workspace",
			principal: f.ownerA,
			resource:  tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA},
			action:    tenant.ActionWorkspaceManage,
			wantRole:  tenant.RoleWorkspaceOwner,
		},
		{
			name:      "workspace member uses its workspace",
			principal: f.memberA,
			resource:  tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA},
			action:    tenant.ActionSessionCreate,
			wantRole:  tenant.RoleWorkspaceMember,
		},
		{
			name:      "workspace member cannot manage ACL",
			principal: f.memberA,
			resource:  tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA},
			action:    tenant.ActionWorkspaceManage,
			wantErr:   tenant.ErrAccessDenied,
		},
		{
			name:      "tenant user without workspace grant is denied",
			principal: f.userA,
			resource:  tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA},
			action:    tenant.ActionWorkspaceRead,
			wantErr:   tenant.ErrAccessDenied,
		},
		{
			name:      "resource ID in another tenant grants nothing",
			principal: f.memberA,
			resource:  tenant.Resource{TenantID: f.tenantB, WorkspaceID: f.workspaceB},
			action:    tenant.ActionWorkspaceRead,
			wantErr:   tenant.ErrAccessDenied,
		},
		{
			name:      "workspace and tenant scope cannot be spliced",
			principal: f.adminA,
			resource:  tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceB},
			action:    tenant.ActionWorkspaceRead,
			wantErr:   tenant.ErrAccessDenied,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := f.repository.Authorize(ctx, tenant.AuthorizationRequest{
				Principal: tenant.Principal{SubjectID: test.principal},
				Resource:  test.resource,
				Action:    test.action,
			})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Authorize() error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil && (decision.Role != test.wantRole || decision.Version != 1) {
				t.Fatalf("Authorize() = %#v, want role %q at version 1", decision, test.wantRole)
			}
		})
	}
}

func TestAuthorizeAndReserveCASAndReceiptReplayAreAtomic(t *testing.T) {
	t.Parallel()
	f := newFixture(t, testLimits())
	ctx := context.Background()
	request := tenant.ReserveRequest{
		OperationID:     testID(t, identity.Operation),
		ExpectedVersion: 1,
		Principal:       tenant.Principal{SubjectID: f.ownerA},
		Resource:        tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA},
		Action:          tenant.ActionSessionCreate,
		Amount:          tenant.Quota{Sessions: 1},
		Instance:        resourceInstance(t, tenant.ActionSessionCreate),
	}

	receipt, err := f.repository.AuthorizeAndReserve(ctx, request)
	if err != nil {
		t.Fatalf("AuthorizeAndReserve() error = %v", err)
	}
	if receipt.Kind != tenant.OperationReserve || receipt.Version != 2 ||
		receipt.ReservationID != request.OperationID || receipt.State != tenant.ReservationReserved ||
		receipt.Durable || receipt.Fingerprint == "" {
		t.Fatalf("AuthorizeAndReserve() receipt = %#v", receipt)
	}

	replayed, err := f.repository.AuthorizeAndReserve(ctx, request)
	if err != nil || replayed != receipt {
		t.Fatalf("stale expected-version replay = %#v, %v; want %#v", replayed, err, receipt)
	}

	changed := request
	changed.Amount = tenant.Quota{Sessions: 2}
	if _, err := f.repository.AuthorizeAndReserve(ctx, changed); !errors.Is(err, tenant.ErrOperationConflict) {
		t.Fatalf("changed operation replay error = %v, want ErrOperationConflict", err)
	}

	stale := request
	stale.OperationID = testID(t, identity.Operation)
	if _, err := f.repository.AuthorizeAndReserve(ctx, stale); !errors.Is(err, tenant.ErrVersionConflict) {
		t.Fatalf("new stale operation error = %v, want ErrVersionConflict", err)
	}

	snapshot := adminSnapshot(t, f, f.tenantA)
	if snapshot.Version != 2 || snapshot.Reserved != (tenant.Quota{Sessions: 1}) || snapshot.Used != (tenant.Quota{}) {
		t.Fatalf("snapshot after replay/conflicts = %#v", snapshot)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	request.OperationID = testID(t, identity.Operation)
	request.ExpectedVersion = snapshot.Version
	if _, err := f.repository.AuthorizeAndReserve(cancelled, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled reserve error = %v, want context.Canceled", err)
	}
	if got := adminSnapshot(t, f, f.tenantA); got != snapshot {
		t.Fatalf("cancelled reserve mutated snapshot: got %#v, want %#v", got, snapshot)
	}
}

func TestEveryQuotaDimensionRejectsWithoutPartialMutation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		action  tenant.Action
		limit   tenant.Quota
		amount  tenant.Quota
		profile tenant.ResourceProfile
	}{
		{name: "sessions", action: tenant.ActionSessionCreate, limit: tenant.Quota{Sessions: 1}, amount: tenant.Quota{Sessions: 1}},
		{name: "workspace bytes", action: tenant.ActionWorkspaceWrite, limit: tenant.Quota{WorkspaceBytes: 8}, amount: tenant.Quota{WorkspaceBytes: 8}},
		{name: "blob bytes", action: tenant.ActionBlobStore, limit: tenant.Quota{WorkspaceBytes: 8, BlobBytes: 8}, amount: tenant.Quota{WorkspaceBytes: 8, BlobBytes: 8}},
		{name: "artifact bytes", action: tenant.ActionArtifactCreate, limit: tenant.Quota{ArtifactBytes: 8}, amount: tenant.Quota{ArtifactBytes: 8}},
		{name: "active sandboxes", action: tenant.ActionSandboxStart, limit: tenant.Quota{ActiveSandboxes: 1}, amount: tenant.Quota{ActiveSandboxes: 1}, profile: tenant.ResourceProfile{CPUUnits: 2, MemoryBytes: 2048}},
		{name: "model tokens and cost", action: tenant.ActionModelUse, limit: tenant.Quota{ModelTokens: 10, ModelCostMicros: 20}, amount: tenant.Quota{ModelTokens: 10, ModelCostMicros: 20}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t, test.limit)
			ctx := context.Background()
			first := tenant.ReserveRequest{
				OperationID: testID(t, identity.Operation), ExpectedVersion: 1,
				Principal: tenant.Principal{SubjectID: f.memberA},
				Resource:  tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA},
				Action:    test.action, Amount: test.amount, RequestedProfile: test.profile,
				Instance: resourceInstance(t, test.action),
			}
			receipt, err := f.repository.AuthorizeAndReserve(ctx, first)
			if err != nil {
				t.Fatalf("first reserve error = %v", err)
			}
			before := adminSnapshot(t, f, f.tenantA)
			second := first
			second.OperationID = testID(t, identity.Operation)
			second.ExpectedVersion = receipt.Version
			if _, err := f.repository.AuthorizeAndReserve(ctx, second); !errors.Is(err, tenant.ErrQuotaExceeded) {
				t.Fatalf("over-limit reserve error = %v, want ErrQuotaExceeded", err)
			}
			if after := adminSnapshot(t, f, f.tenantA); after != before {
				t.Fatalf("quota rejection left partial mutation: before %#v, after %#v", before, after)
			}
			if _, err := f.repository.Recover(ctx, tenant.RecoveryRequest{
				OperationID: second.OperationID,
				Principal:   second.Principal,
				Resource:    second.Resource,
				Action:      second.Action,
			}); !errors.Is(err, tenant.ErrReceiptNotFound) {
				t.Fatalf("recovery after rejected reserve error = %v, want ErrReceiptNotFound", err)
			}
		})
	}
}

func TestConcurrentReservationsCannotOverbook(t *testing.T) {
	t.Parallel()
	const limit = 8
	f := newFixture(t, tenant.Quota{Sessions: limit})
	ctx := context.Background()

	var successes atomic.Int64
	var quotaFailures atomic.Int64
	var wait sync.WaitGroup
	for range 64 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			operationID := testID(t, identity.Operation)
			instance := resourceInstance(t, tenant.ActionSessionCreate)
			for {
				snapshot, err := f.repository.Snapshot(ctx, tenant.SnapshotRequest{
					Principal: tenant.Principal{SubjectID: f.adminA},
					TenantID:  f.tenantA,
				})
				if err != nil {
					t.Errorf("Snapshot() error = %v", err)
					return
				}
				_, err = f.repository.AuthorizeAndReserve(ctx, tenant.ReserveRequest{
					OperationID: operationID, ExpectedVersion: snapshot.Version,
					Principal: tenant.Principal{SubjectID: f.memberA},
					Resource:  tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA},
					Action:    tenant.ActionSessionCreate, Amount: tenant.Quota{Sessions: 1},
					Instance: instance,
				})
				switch {
				case err == nil:
					successes.Add(1)
					return
				case errors.Is(err, tenant.ErrVersionConflict):
					continue
				case errors.Is(err, tenant.ErrQuotaExceeded):
					quotaFailures.Add(1)
					return
				default:
					t.Errorf("AuthorizeAndReserve() error = %v", err)
					return
				}
			}
		}()
	}
	wait.Wait()

	if successes.Load() != limit || quotaFailures.Load() != 64-limit {
		t.Fatalf("successes = %d, quota failures = %d", successes.Load(), quotaFailures.Load())
	}
	snapshot := adminSnapshot(t, f, f.tenantA)
	if snapshot.Reserved.Sessions != limit || snapshot.Used.Sessions != 0 {
		t.Fatalf("concurrent snapshot = %#v", snapshot)
	}
}

func TestConsumeReleaseAndRecoveryAreCASIdempotent(t *testing.T) {
	t.Parallel()
	f := newFixture(t, testLimits())
	ctx := context.Background()
	resource := tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA}
	principal := tenant.Principal{SubjectID: f.ownerA}
	reserveRequest := tenant.ReserveRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: 1,
		Principal: principal, Resource: resource, Action: tenant.ActionSessionCreate,
		Amount:   tenant.Quota{Sessions: 1},
		Instance: resourceInstance(t, tenant.ActionSessionCreate),
	}
	reserved, err := f.repository.AuthorizeAndReserve(ctx, reserveRequest)
	if err != nil {
		t.Fatalf("reserve error = %v", err)
	}

	consumeRequest := tenant.TransitionRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: reserved.Version,
		ReservationID: reserved.ReservationID, Principal: principal, Resource: resource,
		Action: tenant.ActionSessionCreate,
	}
	consumed, err := f.repository.Consume(ctx, consumeRequest)
	if err != nil {
		t.Fatalf("Consume() error = %v", err)
	}
	if consumed.Kind != tenant.OperationConsume || consumed.State != tenant.ReservationConsumed || consumed.Version != 3 || consumed.Durable {
		t.Fatalf("Consume() = %#v", consumed)
	}
	if replay, err := f.repository.Consume(ctx, consumeRequest); err != nil || replay != consumed {
		t.Fatalf("Consume() replay = %#v, %v; want %#v", replay, err, consumed)
	}

	recovery, err := f.repository.Recover(ctx, tenant.RecoveryRequest{
		OperationID: reserveRequest.OperationID, Principal: principal, Resource: resource,
		Action: tenant.ActionSessionCreate,
	})
	if err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if recovery.Receipt != reserved || recovery.CurrentState != tenant.ReservationConsumed {
		t.Fatalf("Recover() = %#v", recovery)
	}

	cancelReservation, err := f.repository.AuthorizeAndReserve(ctx, tenant.ReserveRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: consumed.Version,
		Principal: principal, Resource: resource, Action: tenant.ActionSessionCreate,
		Amount: tenant.Quota{Sessions: 1}, Instance: resourceInstance(t, tenant.ActionSessionCreate),
	})
	if err != nil {
		t.Fatalf("second reserve error = %v", err)
	}
	releaseRequest := tenant.TransitionRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: cancelReservation.Version,
		ReservationID: cancelReservation.ReservationID, Principal: principal, Resource: resource,
		Action: tenant.ActionSessionCreate,
	}
	released, err := f.repository.Release(ctx, releaseRequest)
	if err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if released.Kind != tenant.OperationRelease || released.State != tenant.ReservationReleased || released.Version != 5 {
		t.Fatalf("Release() = %#v", released)
	}
	if replay, err := f.repository.Release(ctx, releaseRequest); err != nil || replay != released {
		t.Fatalf("Release() replay = %#v, %v; want %#v", replay, err, released)
	}

	before := adminSnapshot(t, f, f.tenantA)
	consumeAfterRelease := releaseRequest
	consumeAfterRelease.OperationID = testID(t, identity.Operation)
	consumeAfterRelease.ExpectedVersion = before.Version
	if _, err := f.repository.Consume(ctx, consumeAfterRelease); !errors.Is(err, tenant.ErrReservationState) {
		t.Fatalf("consume after release error = %v, want ErrReservationState", err)
	}
	if after := adminSnapshot(t, f, f.tenantA); after != before || after.Reserved != (tenant.Quota{}) || after.Used != (tenant.Quota{Sessions: 1}) {
		t.Fatalf("failed transition mutated usage: before %#v, after %#v", before, after)
	}
}

func TestConsumedModelBudgetCannotBeRefunded(t *testing.T) {
	t.Parallel()
	f := newFixture(t, tenant.Quota{ModelTokens: 100, ModelCostMicros: 200})
	ctx := context.Background()
	principal := tenant.Principal{SubjectID: f.memberA}
	resource := tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA}
	reserved, err := f.repository.AuthorizeAndReserve(ctx, tenant.ReserveRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: 1,
		Principal: principal, Resource: resource, Action: tenant.ActionModelUse,
		Amount: tenant.Quota{ModelTokens: 100, ModelCostMicros: 200},
	})
	if err != nil {
		t.Fatalf("reserve model budget error = %v", err)
	}
	consumed, err := f.repository.Consume(ctx, tenant.TransitionRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: reserved.Version,
		ReservationID: reserved.ReservationID, Principal: principal, Resource: resource,
		Action: tenant.ActionModelUse,
	})
	if err != nil {
		t.Fatalf("consume model budget error = %v", err)
	}
	before := adminSnapshot(t, f, f.tenantA)
	_, err = f.repository.Release(ctx, tenant.TransitionRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: consumed.Version,
		ReservationID: reserved.ReservationID, Principal: principal, Resource: resource,
		Action: tenant.ActionModelUse,
	})
	if !errors.Is(err, tenant.ErrReservationState) {
		t.Fatalf("release consumed model budget error = %v, want ErrReservationState", err)
	}
	if after := adminSnapshot(t, f, f.tenantA); after != before ||
		after.Used != (tenant.Quota{ModelTokens: 100, ModelCostMicros: 200}) {
		t.Fatalf("model budget was refunded: before %#v, after %#v", before, after)
	}
}

func TestConcurrentConsumeAndReleaseHaveOneCASWinner(t *testing.T) {
	t.Parallel()
	for iteration := range 50 {
		f := newFixture(t, tenant.Quota{Sessions: 1})
		ctx := context.Background()
		principal := tenant.Principal{SubjectID: f.memberA}
		resource := tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA}
		reserved, err := f.repository.AuthorizeAndReserve(ctx, tenant.ReserveRequest{
			OperationID: testID(t, identity.Operation), ExpectedVersion: 1,
			Principal: principal, Resource: resource, Action: tenant.ActionSessionCreate,
			Amount:   tenant.Quota{Sessions: 1},
			Instance: resourceInstance(t, tenant.ActionSessionCreate),
		})
		if err != nil {
			t.Fatalf("iteration %d reserve error = %v", iteration, err)
		}

		requests := []struct {
			kind string
			call func(context.Context, tenant.TransitionRequest) (tenant.Receipt, error)
		}{
			{kind: "consume", call: f.repository.Consume},
			{kind: "release", call: f.repository.Release},
		}
		results := make(chan error, len(requests))
		var wait sync.WaitGroup
		for _, candidate := range requests {
			candidate := candidate
			wait.Add(1)
			go func() {
				defer wait.Done()
				_, err := candidate.call(ctx, tenant.TransitionRequest{
					OperationID: testID(t, identity.Operation), ExpectedVersion: reserved.Version,
					ReservationID: reserved.ReservationID, Principal: principal, Resource: resource,
					Action: tenant.ActionSessionCreate,
				})
				if err != nil {
					err = errors.Join(errors.New(candidate.kind), err)
				}
				results <- err
			}()
		}
		wait.Wait()
		close(results)
		successes := 0
		conflicts := 0
		for err := range results {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, tenant.ErrVersionConflict):
				conflicts++
			default:
				t.Fatalf("iteration %d transition error = %v", iteration, err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("iteration %d successes = %d, conflicts = %d", iteration, successes, conflicts)
		}
		snapshot := adminSnapshot(t, f, f.tenantA)
		if snapshot.Version != reserved.Version+1 || snapshot.Reserved != (tenant.Quota{}) ||
			(snapshot.Used != (tenant.Quota{}) && snapshot.Used != (tenant.Quota{Sessions: 1})) {
			t.Fatalf("iteration %d final snapshot = %#v", iteration, snapshot)
		}
	}
}

func TestActionAmountAndResourceProfileValidationFailClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t, testLimits())
	ctx := context.Background()
	base := tenant.ReserveRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: 1,
		Principal: tenant.Principal{SubjectID: f.memberA},
		Resource:  tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA},
	}

	tests := []struct {
		name    string
		action  tenant.Action
		amount  tenant.Quota
		profile tenant.ResourceProfile
		wantErr error
	}{
		{name: "unknown action", action: tenant.Action("future.action"), amount: tenant.Quota{Sessions: 1}, wantErr: tenant.ErrInvalidRequest},
		{name: "read cannot reserve", action: tenant.ActionWorkspaceRead, amount: tenant.Quota{Sessions: 1}, wantErr: tenant.ErrInvalidRequest},
		{name: "session cannot reserve artifacts", action: tenant.ActionSessionCreate, amount: tenant.Quota{ArtifactBytes: 1}, wantErr: tenant.ErrInvalidRequest},
		{name: "discrete session amount must be one", action: tenant.ActionSessionCreate, amount: tenant.Quota{Sessions: 2}, wantErr: tenant.ErrInvalidRequest},
		{name: "sandbox requires profile", action: tenant.ActionSandboxStart, amount: tenant.Quota{ActiveSandboxes: 1}, wantErr: tenant.ErrPolicyViolation},
		{name: "sandbox below policy minimum", action: tenant.ActionSandboxStart, amount: tenant.Quota{ActiveSandboxes: 1}, profile: tenant.ResourceProfile{CPUUnits: 1, MemoryBytes: 2048}, wantErr: tenant.ErrPolicyViolation},
		{name: "sandbox above policy maximum", action: tenant.ActionSandboxStart, amount: tenant.Quota{ActiveSandboxes: 1}, profile: tenant.ResourceProfile{CPUUnits: 9, MemoryBytes: 2048}, wantErr: tenant.ErrPolicyViolation},
		{name: "non-sandbox cannot smuggle profile", action: tenant.ActionSessionCreate, amount: tenant.Quota{Sessions: 1}, profile: tenant.ResourceProfile{CPUUnits: 2, MemoryBytes: 2048}, wantErr: tenant.ErrInvalidRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base
			request.OperationID = testID(t, identity.Operation)
			request.Action, request.Amount, request.RequestedProfile = test.action, test.amount, test.profile
			request.Instance = resourceInstance(t, test.action)
			if _, err := f.repository.AuthorizeAndReserve(ctx, request); !errors.Is(err, test.wantErr) {
				t.Fatalf("AuthorizeAndReserve() error = %v, want %v", err, test.wantErr)
			}
		})
	}
	if snapshot := adminSnapshot(t, f, f.tenantA); snapshot.Version != 1 || snapshot.Reserved != (tenant.Quota{}) || snapshot.Used != (tenant.Quota{}) {
		t.Fatalf("invalid requests mutated state: %#v", snapshot)
	}
}

func TestPolicyIntersectionAndTighteningCannotRelaxLimits(t *testing.T) {
	t.Parallel()
	base := tenant.Policy{
		Limits:         tenant.Quota{Sessions: 10, WorkspaceBytes: 100, BlobBytes: 100, ArtifactBytes: 100, ActiveSandboxes: 5, ModelTokens: 1000, ModelCostMicros: 2000},
		MinimumProfile: tenant.ResourceProfile{CPUUnits: 1, MemoryBytes: 1024},
		MaximumProfile: tenant.ResourceProfile{CPUUnits: 16, MemoryBytes: 16384},
	}
	restriction := tenant.Policy{
		Limits:         tenant.Quota{Sessions: 5, WorkspaceBytes: 90, BlobBytes: 80, ArtifactBytes: 70, ActiveSandboxes: 4, ModelTokens: 900, ModelCostMicros: 1900},
		MinimumProfile: tenant.ResourceProfile{CPUUnits: 2, MemoryBytes: 2048},
		MaximumProfile: tenant.ResourceProfile{CPUUnits: 8, MemoryBytes: 8192},
	}
	resolved, err := tenant.IntersectPolicies(base, restriction)
	if err != nil {
		t.Fatalf("IntersectPolicies() error = %v", err)
	}
	if resolved != restriction {
		t.Fatalf("IntersectPolicies() = %#v, want strongest %#v", resolved, restriction)
	}
	conflict := restriction
	conflict.MinimumProfile.CPUUnits = 9
	conflict.MaximumProfile.CPUUnits = 16
	if _, err := tenant.IntersectPolicies(base, restriction, conflict); !errors.Is(err, tenant.ErrPolicyConflict) {
		t.Fatalf("conflicting intersection error = %v, want ErrPolicyConflict", err)
	}

	f := newFixture(t, base.Limits)
	ctx := context.Background()
	request := tenant.TightenPolicyRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: 1,
		Principal: tenant.Principal{SubjectID: f.adminA}, TenantID: f.tenantA,
		Policy: restriction,
	}
	receipt, err := f.repository.TightenPolicy(ctx, request)
	if err != nil {
		t.Fatalf("TightenPolicy() error = %v", err)
	}
	if receipt.Kind != tenant.OperationPolicyTighten || receipt.Version != 2 || receipt.Durable {
		t.Fatalf("TightenPolicy() = %#v", receipt)
	}
	if replay, err := f.repository.TightenPolicy(ctx, request); err != nil || replay != receipt {
		t.Fatalf("TightenPolicy() replay = %#v, %v; want %#v", replay, err, receipt)
	}

	for name, relaxed := range map[string]tenant.Policy{
		"quota":           func() tenant.Policy { value := restriction; value.Limits.Sessions++; return value }(),
		"minimum profile": func() tenant.Policy { value := restriction; value.MinimumProfile.CPUUnits--; return value }(),
		"maximum profile": func() tenant.Policy { value := restriction; value.MaximumProfile.CPUUnits++; return value }(),
	} {
		t.Run(name+" relaxation", func(t *testing.T) {
			bad := request
			bad.OperationID = testID(t, identity.Operation)
			bad.ExpectedVersion = receipt.Version
			bad.Policy = relaxed
			if _, err := f.repository.TightenPolicy(ctx, bad); !errors.Is(err, tenant.ErrPolicyRelaxation) {
				t.Fatalf("TightenPolicy() relaxation error = %v, want ErrPolicyRelaxation", err)
			}
		})
	}
	if snapshot := adminSnapshot(t, f, f.tenantA); snapshot.Version != receipt.Version || snapshot.Policy != restriction {
		t.Fatalf("relaxation attempts mutated policy: %#v", snapshot)
	}
}

func TestConfigurationValidationRejectsUnknownOrEscalatingACL(t *testing.T) {
	t.Parallel()
	tenantID := testID(t, identity.Tenant)
	workspaceID := testID(t, identity.Workspace)
	subjectID := testID(t, identity.Subject)
	base := tenant.Configuration{Tenants: []tenant.TenantConfiguration{{
		TenantID:   tenantID,
		Members:    []tenant.Membership{{SubjectID: subjectID, Role: tenant.RoleUser}},
		Workspaces: []tenant.WorkspaceACL{{WorkspaceID: workspaceID, Grants: []tenant.WorkspaceGrant{{SubjectID: subjectID, Role: tenant.RoleWorkspaceMember}}}},
		Policy:     testPolicy(testLimits()),
	}}}

	tests := []struct {
		name   string
		mutate func(*tenant.Configuration)
	}{
		{name: "unknown tenant role", mutate: func(config *tenant.Configuration) { config.Tenants[0].Members[0].Role = tenant.Role("superuser") }},
		{name: "workspace role in tenant membership", mutate: func(config *tenant.Configuration) { config.Tenants[0].Members[0].Role = tenant.RoleWorkspaceOwner }},
		{name: "tenant role in workspace ACL", mutate: func(config *tenant.Configuration) {
			config.Tenants[0].Workspaces[0].Grants[0].Role = tenant.RoleTenantAdmin
		}},
		{name: "ACL subject without tenant membership", mutate: func(config *tenant.Configuration) {
			config.Tenants[0].Workspaces[0].Grants[0].SubjectID = testID(t, identity.Subject)
		}},
		{name: "duplicate tenant membership", mutate: func(config *tenant.Configuration) {
			config.Tenants[0].Members = append(config.Tenants[0].Members, config.Tenants[0].Members[0])
		}},
		{name: "invalid profile range", mutate: func(config *tenant.Configuration) {
			config.Tenants[0].Policy.MinimumProfile.CPUUnits = config.Tenants[0].Policy.MaximumProfile.CPUUnits + 1
		}},
		{name: "overflow-prone quota", mutate: func(config *tenant.Configuration) { config.Tenants[0].Policy.Limits.ModelTokens = ^uint64(0) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := cloneConfiguration(base)
			test.mutate(&config)
			if _, err := tenant.NewMemoryRepository(config); !errors.Is(err, tenant.ErrInvalidConfiguration) {
				t.Fatalf("NewMemoryRepository() error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}
}

func TestConsumedLiveQuotaCannotReleaseWithoutTeardownProof(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		action  tenant.Action
		amount  tenant.Quota
		profile tenant.ResourceProfile
	}{
		{name: "session", action: tenant.ActionSessionCreate, amount: tenant.Quota{Sessions: 1}},
		{name: "workspace", action: tenant.ActionWorkspaceWrite, amount: tenant.Quota{WorkspaceBytes: 8}},
		{name: "blob", action: tenant.ActionBlobStore, amount: tenant.Quota{WorkspaceBytes: 8, BlobBytes: 8}},
		{name: "artifact", action: tenant.ActionArtifactCreate, amount: tenant.Quota{ArtifactBytes: 8}},
		{name: "sandbox", action: tenant.ActionSandboxStart, amount: tenant.Quota{ActiveSandboxes: 1}, profile: tenant.ResourceProfile{CPUUnits: 2, MemoryBytes: 2048}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t, test.amount)
			ctx := context.Background()
			principal := tenant.Principal{SubjectID: f.memberA}
			resource := tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA}
			reserved, err := f.repository.AuthorizeAndReserve(ctx, tenant.ReserveRequest{
				OperationID: testID(t, identity.Operation), ExpectedVersion: 1,
				Principal: principal, Resource: resource, Action: test.action,
				Amount: test.amount, RequestedProfile: test.profile,
				Instance: resourceInstance(t, test.action),
			})
			if err != nil {
				t.Fatalf("reserve error = %v", err)
			}
			consumed, err := f.repository.Consume(ctx, tenant.TransitionRequest{
				OperationID: testID(t, identity.Operation), ExpectedVersion: reserved.Version,
				ReservationID: reserved.ReservationID, Principal: principal, Resource: resource,
				Action: test.action,
			})
			if err != nil {
				t.Fatalf("consume error = %v", err)
			}
			_, err = f.repository.Release(ctx, tenant.TransitionRequest{
				OperationID: testID(t, identity.Operation), ExpectedVersion: consumed.Version,
				ReservationID: reserved.ReservationID, Principal: principal, Resource: resource,
				Action: test.action,
			})
			if !errors.Is(err, tenant.ErrTeardownUnproven) {
				t.Fatalf("Release() error = %v, want ErrTeardownUnproven", err)
			}
			snapshot := adminSnapshot(t, f, f.tenantA)
			if snapshot.Version != consumed.Version || snapshot.Used != test.amount || snapshot.Reserved != (tenant.Quota{}) {
				t.Fatalf("unproven release mutated state: %#v", snapshot)
			}
		})
	}
}

func TestConsumeRejectsReservationAfterQuotaTightening(t *testing.T) {
	t.Parallel()
	f := newFixture(t, tenant.Quota{Sessions: 1})
	ctx := context.Background()
	principal := tenant.Principal{SubjectID: f.memberA}
	resource := tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA}
	reserved, err := f.repository.AuthorizeAndReserve(ctx, tenant.ReserveRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: 1,
		Principal: principal, Resource: resource, Action: tenant.ActionSessionCreate,
		Amount: tenant.Quota{Sessions: 1}, Instance: resourceInstance(t, tenant.ActionSessionCreate),
	})
	if err != nil {
		t.Fatalf("reserve error = %v", err)
	}
	tightened, err := f.repository.TightenPolicy(ctx, tenant.TightenPolicyRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: reserved.Version,
		Principal: tenant.Principal{SubjectID: f.adminA}, TenantID: f.tenantA,
		Policy: testPolicy(tenant.Quota{}),
	})
	if err != nil {
		t.Fatalf("tighten error = %v", err)
	}
	_, err = f.repository.Consume(ctx, tenant.TransitionRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: tightened.Version,
		ReservationID: reserved.ReservationID, Principal: principal, Resource: resource,
		Action: tenant.ActionSessionCreate,
	})
	if err == nil {
		t.Fatal("Consume() accepted a reservation disallowed by current quota policy")
	}
	snapshot := adminSnapshot(t, f, f.tenantA)
	if snapshot.Version != tightened.Version || snapshot.Used != (tenant.Quota{}) || snapshot.Reserved != (tenant.Quota{Sessions: 1}) {
		t.Fatalf("rejected consume mutated reservation: %#v", snapshot)
	}
}

func TestBlobReservationRequiresEqualWorkspaceAndBlobBytes(t *testing.T) {
	t.Parallel()
	f := newFixture(t, tenant.Quota{WorkspaceBytes: 8, BlobBytes: 8})
	_, err := f.repository.AuthorizeAndReserve(context.Background(), tenant.ReserveRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: 1,
		Principal: tenant.Principal{SubjectID: f.memberA},
		Resource:  tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA},
		Action:    tenant.ActionBlobStore, Amount: tenant.Quota{BlobBytes: 8},
		Instance: resourceInstance(t, tenant.ActionBlobStore),
	})
	if err == nil {
		t.Fatal("AuthorizeAndReserve() accepted blob bytes without equal workspace bytes")
	}
	if snapshot := adminSnapshot(t, f, f.tenantA); snapshot.Version != 1 || snapshot.Reserved != (tenant.Quota{}) {
		t.Fatalf("rejected blob reservation mutated state: %#v", snapshot)
	}
}

func TestMemoryRepositoryDoesNotClaimCrashDurability(t *testing.T) {
	t.Parallel()
	f := newFixture(t, tenant.Quota{Sessions: 1})
	receipt, err := f.repository.AuthorizeAndReserve(context.Background(), tenant.ReserveRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: 1,
		Principal: tenant.Principal{SubjectID: f.memberA},
		Resource:  tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA},
		Action:    tenant.ActionSessionCreate, Amount: tenant.Quota{Sessions: 1},
		Instance: resourceInstance(t, tenant.ActionSessionCreate),
	})
	if err != nil {
		t.Fatalf("AuthorizeAndReserve() error = %v", err)
	}
	if receipt.Durable {
		t.Fatal("MemoryRepository receipt incorrectly claims crash durability")
	}
}

func TestProductionServiceRejectsNonDurableRepository(t *testing.T) {
	t.Parallel()
	f := newFixture(t, tenant.Quota{Sessions: 1})
	capability := f.repository.Durability()
	if capability.CrashDurable || !capability.AtomicExpectedVersionCAS || !capability.AtomicMutationReceipt {
		t.Fatalf("MemoryRepository durability = %#v", capability)
	}
	_, err := tenant.NewService(tenant.ServiceConfig{
		Repository: f.repository,
		Lifecycle:  &recordingLifecycleVerifier{},
	})
	if !errors.Is(err, tenant.ErrRepositoryNotDurable) {
		t.Fatalf("NewService(MemoryRepository) error = %v, want ErrRepositoryNotDurable", err)
	}
	if _, err := tenant.NewService(tenant.ServiceConfig{
		Repository:           f.repository,
		Lifecycle:            &recordingLifecycleVerifier{},
		AllowReferenceMemory: true,
	}); err != nil {
		t.Fatalf("NewService(explicit reference memory) error = %v", err)
	}
}

func TestLiveQuotaReleaseRequiresExactDurableLifecycleReceipt(t *testing.T) {
	t.Parallel()
	f := newFixture(t, tenant.Quota{Sessions: 1})
	ctx := context.Background()
	principal := tenant.Principal{SubjectID: f.memberA}
	resource := tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA}
	instance := resourceInstance(t, tenant.ActionSessionCreate)
	reserved, err := f.repository.AuthorizeAndReserve(ctx, tenant.ReserveRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: 1,
		Principal: principal, Resource: resource, Action: tenant.ActionSessionCreate,
		Amount: tenant.Quota{Sessions: 1}, Instance: instance,
	})
	if err != nil {
		t.Fatalf("reserve error = %v", err)
	}
	consumed, err := f.repository.Consume(ctx, tenant.TransitionRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: reserved.Version,
		ReservationID: reserved.ReservationID, Principal: principal, Resource: resource,
		Action: tenant.ActionSessionCreate,
	})
	if err != nil {
		t.Fatalf("consume error = %v", err)
	}
	releaseOperationID := testID(t, identity.Operation)
	verifier := &recordingLifecycleVerifier{receipt: tenant.TeardownReceipt{
		ReleaseOperationID:  releaseOperationID,
		ReservationID:       reserved.ReservationID,
		ReservationVersion:  reserved.Version,
		TenantID:            resource.TenantID,
		WorkspaceID:         resource.WorkspaceID,
		Action:              tenant.ActionSessionCreate,
		Instance:            instance,
		State:               tenant.LifecycleDestroyed,
		LifecycleGeneration: instance.Generation,
		Durable:             false,
		Sequence:            1,
		ProofDigest:         "sha256:" + strings.Repeat("a", 64),
	}}
	service, err := tenant.NewService(tenant.ServiceConfig{
		Repository: claimedDurableRepository{Repository: f.repository},
		Lifecycle:  verifier,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	releaseRequest := tenant.ReleaseRequest{
		OperationID: releaseOperationID, ExpectedVersion: consumed.Version,
		ReservationID: reserved.ReservationID, ReservationVersion: reserved.Version,
		Principal: principal, Resource: resource, Action: tenant.ActionSessionCreate,
		Instance: instance,
	}
	unauthorized := releaseRequest
	unauthorized.OperationID = testID(t, identity.Operation)
	unauthorized.Principal = tenant.Principal{SubjectID: f.userA}
	if _, err := service.Release(ctx, unauthorized); !errors.Is(err, tenant.ErrAccessDenied) {
		t.Fatalf("Release(unauthorized) error = %v, want ErrAccessDenied", err)
	}
	verifier.mu.Lock()
	unauthorizedVerifications := len(verifier.requests)
	verifier.mu.Unlock()
	if unauthorizedVerifications != 0 {
		t.Fatalf("unauthorized release reached lifecycle verifier %d times", unauthorizedVerifications)
	}
	if _, err := service.Release(ctx, releaseRequest); !errors.Is(err, tenant.ErrTeardownUnproven) {
		t.Fatalf("Release(nondurable proof) error = %v, want ErrTeardownUnproven", err)
	}
	if snapshot := adminSnapshot(t, f, f.tenantA); snapshot.Version != consumed.Version || snapshot.Used != (tenant.Quota{Sessions: 1}) {
		t.Fatalf("nondurable proof mutated usage: %#v", snapshot)
	}

	verifier.mu.Lock()
	verifier.receipt.Durable = true
	verifier.receipt.Instance.ID += "-other"
	verifier.mu.Unlock()
	if _, err := service.Release(ctx, releaseRequest); !errors.Is(err, tenant.ErrTeardownUnproven) {
		t.Fatalf("Release(wrong instance proof) error = %v, want ErrTeardownUnproven", err)
	}
	if snapshot := adminSnapshot(t, f, f.tenantA); snapshot.Version != consumed.Version || snapshot.Used != (tenant.Quota{Sessions: 1}) {
		t.Fatalf("wrong proof mutated usage: %#v", snapshot)
	}
	verifier.mu.Lock()
	verifier.receipt.Instance = instance
	verifier.mu.Unlock()
	released, err := service.Release(ctx, releaseRequest)
	if err != nil {
		t.Fatalf("Release(durable proof) error = %v", err)
	}
	if !released.Durable || released.State != tenant.ReservationReleased || released.Instance != instance ||
		released.TeardownProofDigest != verifier.receipt.ProofDigest {
		t.Fatalf("Release(durable proof) = %#v", released)
	}
	if snapshot := adminSnapshot(t, f, f.tenantA); snapshot.Version != released.Version || snapshot.Used != (tenant.Quota{}) {
		t.Fatalf("durable teardown did not release usage: %#v", snapshot)
	}
	verifier.mu.Lock()
	verificationCount := len(verifier.requests)
	verifier.err = errors.New("lifecycle owner unavailable")
	verifier.mu.Unlock()
	replayed, err := service.Release(ctx, releaseRequest)
	if err != nil || replayed != released {
		t.Fatalf("Release(committed replay) = %#v, %v; want %#v", replayed, err, released)
	}
	verifier.mu.Lock()
	replayedVerificationCount := len(verifier.requests)
	verifier.mu.Unlock()
	if replayedVerificationCount != verificationCount {
		t.Fatalf("committed replay consulted lifecycle verifier: before %d, after %d", verificationCount, replayedVerificationCount)
	}
}

func TestConsumeRejectsSandboxProfileAfterPolicyTightening(t *testing.T) {
	t.Parallel()
	f := newFixture(t, tenant.Quota{ActiveSandboxes: 1})
	ctx := context.Background()
	principal := tenant.Principal{SubjectID: f.memberA}
	resource := tenant.Resource{TenantID: f.tenantA, WorkspaceID: f.workspaceA}
	reserved, err := f.repository.AuthorizeAndReserve(ctx, tenant.ReserveRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: 1,
		Principal: principal, Resource: resource, Action: tenant.ActionSandboxStart,
		Amount:           tenant.Quota{ActiveSandboxes: 1},
		RequestedProfile: tenant.ResourceProfile{CPUUnits: 2, MemoryBytes: 2048},
		Instance:         resourceInstance(t, tenant.ActionSandboxStart),
	})
	if err != nil {
		t.Fatalf("reserve error = %v", err)
	}
	tightenedPolicy := testPolicy(tenant.Quota{ActiveSandboxes: 1})
	tightenedPolicy.MinimumProfile.CPUUnits = 4
	tightened, err := f.repository.TightenPolicy(ctx, tenant.TightenPolicyRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: reserved.Version,
		Principal: tenant.Principal{SubjectID: f.adminA}, TenantID: f.tenantA,
		Policy: tightenedPolicy,
	})
	if err != nil {
		t.Fatalf("tighten error = %v", err)
	}
	_, err = f.repository.Consume(ctx, tenant.TransitionRequest{
		OperationID: testID(t, identity.Operation), ExpectedVersion: tightened.Version,
		ReservationID: reserved.ReservationID, Principal: principal, Resource: resource,
		Action: tenant.ActionSandboxStart,
	})
	if !errors.Is(err, tenant.ErrPolicyViolation) {
		t.Fatalf("Consume(stale profile) error = %v, want ErrPolicyViolation", err)
	}
	if snapshot := adminSnapshot(t, f, f.tenantA); snapshot.Version != tightened.Version ||
		snapshot.Reserved != (tenant.Quota{ActiveSandboxes: 1}) || snapshot.Used != (tenant.Quota{}) {
		t.Fatalf("rejected sandbox consume mutated usage: %#v", snapshot)
	}
}

func newFixture(t *testing.T, limits tenant.Quota) fixture {
	t.Helper()
	f := fixture{
		tenantA: testID(t, identity.Tenant), tenantB: testID(t, identity.Tenant),
		workspaceA: testID(t, identity.Workspace), workspaceB: testID(t, identity.Workspace),
		platform: testID(t, identity.Subject), adminA: testID(t, identity.Subject),
		ownerA: testID(t, identity.Subject), memberA: testID(t, identity.Subject),
		userA: testID(t, identity.Subject), memberB: testID(t, identity.Subject),
	}
	configuration := tenant.Configuration{
		PlatformAdmins: []identity.ID{f.platform},
		Tenants: []tenant.TenantConfiguration{
			{
				TenantID: f.tenantA,
				Members: []tenant.Membership{
					{SubjectID: f.adminA, Role: tenant.RoleTenantAdmin},
					{SubjectID: f.ownerA, Role: tenant.RoleUser},
					{SubjectID: f.memberA, Role: tenant.RoleUser},
					{SubjectID: f.userA, Role: tenant.RoleUser},
				},
				Workspaces: []tenant.WorkspaceACL{{
					WorkspaceID: f.workspaceA,
					Grants: []tenant.WorkspaceGrant{
						{SubjectID: f.ownerA, Role: tenant.RoleWorkspaceOwner},
						{SubjectID: f.memberA, Role: tenant.RoleWorkspaceMember},
					},
				}},
				Policy: testPolicy(limits),
			},
			{
				TenantID: f.tenantB,
				Members:  []tenant.Membership{{SubjectID: f.memberB, Role: tenant.RoleUser}},
				Workspaces: []tenant.WorkspaceACL{{
					WorkspaceID: f.workspaceB,
					Grants:      []tenant.WorkspaceGrant{{SubjectID: f.memberB, Role: tenant.RoleWorkspaceMember}},
				}},
				Policy: testPolicy(testLimits()),
			},
		},
	}
	repository, err := tenant.NewMemoryRepository(configuration)
	if err != nil {
		t.Fatalf("NewMemoryRepository() error = %v", err)
	}
	f.repository = repository
	return f
}

func testLimits() tenant.Quota {
	return tenant.Quota{
		Sessions: 10, WorkspaceBytes: 100, BlobBytes: 100, ArtifactBytes: 100,
		ActiveSandboxes: 5, ModelTokens: 1000, ModelCostMicros: 2000,
	}
}

func testPolicy(limits tenant.Quota) tenant.Policy {
	return tenant.Policy{
		Limits:         limits,
		MinimumProfile: tenant.ResourceProfile{CPUUnits: 2, MemoryBytes: 1024},
		MaximumProfile: tenant.ResourceProfile{CPUUnits: 8, MemoryBytes: 8192},
	}
}

func adminSnapshot(t *testing.T, f fixture, tenantID identity.ID) tenant.Snapshot {
	t.Helper()
	snapshot, err := f.repository.Snapshot(context.Background(), tenant.SnapshotRequest{
		Principal: tenant.Principal{SubjectID: f.adminA},
		TenantID:  tenantID,
	})
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	return snapshot
}

func testID(t *testing.T, kind identity.Kind) identity.ID {
	t.Helper()
	id, err := identity.New(kind)
	if err != nil {
		t.Fatalf("identity.New(%q) error = %v", kind, err)
	}
	return id
}

func resourceInstance(t *testing.T, action tenant.Action) tenant.ResourceInstance {
	t.Helper()
	var kind identity.Kind
	switch action {
	case tenant.ActionSessionCreate:
		kind = identity.Session
	case tenant.ActionSandboxStart:
		kind = identity.Sandbox
	case tenant.ActionArtifactCreate:
		kind = identity.Artifact
	case tenant.ActionWorkspaceWrite, tenant.ActionBlobStore:
		kind = identity.Commit
	default:
		return tenant.ResourceInstance{}
	}
	return tenant.ResourceInstance{ID: testID(t, kind).String(), Generation: 1}
}

func cloneConfiguration(configuration tenant.Configuration) tenant.Configuration {
	cloned := configuration
	cloned.PlatformAdmins = append([]identity.ID(nil), configuration.PlatformAdmins...)
	cloned.Tenants = append([]tenant.TenantConfiguration(nil), configuration.Tenants...)
	for index := range cloned.Tenants {
		cloned.Tenants[index].Members = append([]tenant.Membership(nil), configuration.Tenants[index].Members...)
		cloned.Tenants[index].Workspaces = append([]tenant.WorkspaceACL(nil), configuration.Tenants[index].Workspaces...)
		for workspaceIndex := range cloned.Tenants[index].Workspaces {
			cloned.Tenants[index].Workspaces[workspaceIndex].Grants = append(
				[]tenant.WorkspaceGrant(nil),
				configuration.Tenants[index].Workspaces[workspaceIndex].Grants...,
			)
		}
	}
	return cloned
}
