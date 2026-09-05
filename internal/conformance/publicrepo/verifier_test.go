package publicrepo_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/conformance"
	"github.com/hancomac/circulusd/internal/conformance/publicrepo"
	"github.com/hancomac/circulusd/internal/platformapi"
)

const (
	repoTenantID         = "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	repoSubjectID        = "subject_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	repoSessionID        = "sess_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	repoWorkspaceID      = "ws_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	repoRuntimeRevision  = "runtime_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	repoPlacementGen     = uint64(4)
	repoAuthorizationGen = uint64(7)
)

// durableMemoryStore wraps the non-durable MemoryStore reference and overrides
// only its self-reported durability, letting a test drive the PASS path (all
// atomic behavioral checks hold) while the harness provenance controls whether
// the evidence is promotable.
type durableMemoryStore struct {
	*platformapi.MemoryStore
}

func (durableMemoryStore) Durability() platformapi.RepositoryDurability {
	return platformapi.RepositoryDurability{
		CrashDurable: true, AtomicIdempotency: true, AtomicEventSequence: true,
		AtomicReplaySubscribe: true, AtomicAuthorizationFence: true,
	}
}

type memoryHarness struct {
	reference bool
	durable   bool
}

func (harness memoryHarness) NewSubject(ctx context.Context) (*publicrepo.Subject, error) {
	store := platformapi.NewMemoryStore()
	if err := store.RegisterSession(ctx, platformapi.SessionRegistration{
		TenantID: repoTenantID, SubjectID: repoSubjectID, SessionID: repoSessionID,
		RuntimeRevision: repoRuntimeRevision, WorkspaceID: repoWorkspaceID,
		PlacementGeneration: repoPlacementGen, AuthorizationGeneration: repoAuthorizationGen,
	}); err != nil {
		return nil, err
	}
	var repository platformapi.Repository = store
	if harness.durable {
		repository = durableMemoryStore{MemoryStore: store}
	}
	return &publicrepo.Subject{
		Repository: repository,
		TenantID:   repoTenantID, SubjectID: repoSubjectID, SessionID: repoSessionID,
		WorkspaceID: repoWorkspaceID, RuntimeRevision: repoRuntimeRevision,
		PlacementGeneration: repoPlacementGen, AuthorizationGeneration: repoAuthorizationGen,
		Permit: func(op platformapi.Operation) platformapi.AuthorizationPermit {
			return platformapi.AuthorizationPermit{
				Operation: op,
				Principal: platformapi.Principal{TenantID: repoTenantID, SubjectID: repoSubjectID},
				SessionID: repoSessionID, AuthorizationGeneration: repoAuthorizationGen,
				Proof: platformapi.OpaqueAuthorizationProof{1},
			}
		},
	}, nil
}

func (harness memoryHarness) Provenance() publicrepo.Provenance {
	return publicrepo.Provenance{Version: "0.1.0", Reference: harness.reference}
}

func mustCollect(t *testing.T, result conformance.Result) {
	t.Helper()
	collector := conformance.NewCollector()
	if err := collector.Add(result); err != nil {
		t.Fatalf("result failed conformance validation: %v", err)
	}
}

func TestQualifyWithoutHarnessIsUnavailable(t *testing.T) {
	t.Parallel()
	result := publicrepo.Qualify(context.Background(), nil)
	if result.Component != publicrepo.Component || result.Status != conformance.Unavailable {
		t.Fatalf("result = %+v, want %s UNAVAILABLE", result, publicrepo.Component)
	}
	if strings.TrimSpace(result.Reason) == "" {
		t.Fatal("UNAVAILABLE result must carry a reason")
	}
	mustCollect(t, result)
}

func TestQualifyMemoryReferenceFailsCrashDurable(t *testing.T) {
	t.Parallel()
	// The plain MemoryStore satisfies every atomic behavioral check but is not
	// crash durable, so the gate must FAIL it — the honest reference outcome.
	result := publicrepo.Qualify(context.Background(), memoryHarness{reference: true, durable: false})
	if result.Status != conformance.Fail {
		t.Fatalf("result = %+v, want FAIL", result)
	}
	if !strings.Contains(result.Reason, "crash-durable") {
		t.Fatalf("reason %q should name the crash-durable check", result.Reason)
	}
	mustCollect(t, result)
}

func TestQualifyDurableReferencePassesButIsNotPromotable(t *testing.T) {
	t.Parallel()
	result := publicrepo.Qualify(context.Background(), memoryHarness{reference: true, durable: true})
	if result.Status != conformance.Pass {
		t.Fatalf("durable reference result = %+v, want PASS", result)
	}
	if !result.Evidence.Mock || result.Evidence.Class != conformance.EvidenceClassReferenceOnly {
		t.Fatalf("reference PASS evidence = %+v, want mock reference-only", result.Evidence)
	}
	mustCollect(t, result)

	collector := conformance.NewCollector()
	if err := collector.Add(result); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	profile := conformance.Profile{Name: "production", Production: true, Required: []string{publicrepo.Component}}
	if err := collector.Evaluate(profile); err == nil {
		t.Fatal("production profile accepted a reference/mock repository PASS")
	}
}

func TestQualifyDurableExternalCarriesExternalEvidence(t *testing.T) {
	t.Parallel()
	result := publicrepo.Qualify(context.Background(), memoryHarness{reference: false, durable: true})
	if result.Status != conformance.Pass {
		t.Fatalf("result = %+v, want PASS", result)
	}
	if result.Evidence.Mock || result.Evidence.Class != conformance.EvidenceClassExternal {
		t.Fatalf("evidence = %+v, want external non-mock", result.Evidence)
	}
	mustCollect(t, result)
}

func TestRequiredChecksCoverDurableContract(t *testing.T) {
	t.Parallel()
	want := map[string]bool{
		"atomic-idempotency":         false,
		"atomic-event-sequence":      false,
		"atomic-replay-subscribe":    false,
		"atomic-authorization-fence": false,
		"crash-durable":              false,
	}
	seen := make(map[string]struct{})
	for _, check := range publicrepo.RequiredChecks() {
		if _, duplicate := seen[check.ID]; duplicate {
			t.Fatalf("duplicate check id %q", check.ID)
		}
		seen[check.ID] = struct{}{}
		if check.Reference == "" || check.Description == "" {
			t.Fatalf("check %q is missing its SPEC reference or description", check.ID)
		}
		if _, expected := want[check.ID]; expected {
			want[check.ID] = true
		}
	}
	for id, covered := range want {
		if !covered {
			t.Fatalf("required durable contract check %q is missing", id)
		}
	}
}

type unfencedRepository struct {
	platformapi.Repository
	subject *publicrepo.Subject
	permit  bool
}

func (repo unfencedRepository) CreateTurn(ctx context.Context, command platformapi.CreateTurnCommand) (platformapi.Turn, bool, error) {
	if repo.permit {
		command.Authorization = repo.subject.Permit(platformapi.OperationCreateTurn)
	}
	return repo.Repository.CreateTurn(ctx, command)
}

func (repo unfencedRepository) AppendDurableEvent(ctx context.Context, command platformapi.AppendEventCommand) (platformapi.Event, bool, error) {
	if !repo.permit {
		command.Authority.Scope.TenantID = repo.subject.TenantID
		command.Authority.Scope.UserID = repo.subject.SubjectID
		command.Authority.Scope.RuntimeRevision = repo.subject.RuntimeRevision
		command.Authority.Scope.WorkspaceID = repo.subject.WorkspaceID
	}
	return repo.Repository.AppendDurableEvent(ctx, command)
}

type unfencedHarness struct{ permit bool }

func (harness unfencedHarness) NewSubject(ctx context.Context) (*publicrepo.Subject, error) {
	subject, err := (memoryHarness{reference: true, durable: true}).NewSubject(ctx)
	if err != nil {
		return nil, err
	}
	subject.Repository = unfencedRepository{Repository: subject.Repository, subject: subject, permit: harness.permit}
	return subject, nil
}

func (unfencedHarness) Provenance() publicrepo.Provenance {
	return (memoryHarness{reference: true, durable: true}).Provenance()
}

func TestQualifyRejectsRepositoriesThatDropAuthorizationScope(t *testing.T) {
	for _, permit := range []bool{false, true} {
		name := "event-scope"
		if permit {
			name = "creation-permit"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := publicrepo.Qualify(context.Background(), unfencedHarness{permit: permit})
			if result.Status != conformance.Fail || !strings.Contains(result.Reason, "atomic-authorization-fence") {
				t.Fatalf("unfenced repository qualification = %+v", result)
			}
		})
	}
}
