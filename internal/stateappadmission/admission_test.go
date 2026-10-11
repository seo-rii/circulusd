package stateappadmission

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	dependencycontract "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/platformapi"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

type admissionTestClient struct {
	*dependencycontract.ProductionProofs
	calls   int
	request stateappclient.AdmitSessionTurnRequest
	err     error
}

func (client *admissionTestClient) AdmitSessionTurn(_ context.Context, request stateappclient.AdmitSessionTurnRequest) (stateappclient.AdmitSessionTurnResult, error) {
	client.calls++
	client.request = request
	return stateappclient.AdmitSessionTurnResult{TurnID: request.TurnID, TurnSequence: 0, Version: 1, Activated: true}, client.err
}

type admissionTestPlanner struct {
	*dependencycontract.ProductionProofs
	calls int
	plan  AdmissionPlan
}

func (planner *admissionTestPlanner) PlanAdmission(_ context.Context, request platformapi.SessionTurnAdmission) (AdmissionPlan, error) {
	planner.calls++
	request.Input.(canonical.Map)["messages"].(canonical.Array)[0].(canonical.Map)["content"] = "planner changed copy"
	return planner.plan, nil
}
func TestTurnAdmitterRequiresIndependentPlannerProofAndSameDomain(t *testing.T) {
	groups := []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent}
	proofs := dependencycontract.NewProductionProofs(t, groups)
	client := &admissionTestClient{ProductionProofs: proofs}
	verifiedClient := dependencycontract.Verify[AdmissionClient](t, proofs, client, groups)
	if _, err := NewTurnAdmitter(verifiedClient, dependency.Verified[AdmissionPlanner]{}); !errors.Is(err, platformapi.ErrRepositoryNotDurable) {
		t.Fatalf("raw planner accepted: %v", err)
	}
	restricted := dependencycontract.NewProductionProofs(t, groups[:2])
	planner := &admissionTestPlanner{ProductionProofs: restricted}
	verifiedPlanner := dependencycontract.Verify[AdmissionPlanner](t, restricted, planner, groups[:2])
	if _, err := NewTurnAdmitter(verifiedClient, verifiedPlanner); !errors.Is(err, platformapi.ErrRepositoryNotDurable) {
		t.Fatalf("mismatched planner domain accepted: %v", err)
	}
	if client.calls != 0 || planner.calls != 0 {
		t.Fatal("unverified composition performed an operation")
	}
}
func TestTurnAdmitterPreservesFullInputAndUsesQualifiedPlan(t *testing.T) {
	groups := []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent}
	proofs := dependencycontract.NewProductionProofs(t, groups)
	client := &admissionTestClient{ProductionProofs: proofs}
	planner := &admissionTestPlanner{ProductionProofs: proofs, plan: AdmissionPlan{CommandID: "trusted-command", ExpectedEventSequence: 9, GenesisCheckpoint: canonical.Map{"kind": "genesis"}, TurnLeaseGeneration: 4, LeaseExpiresAt: 1900000000000}}
	store, err := NewTurnAdmitter(dependencycontract.Verify[AdmissionClient](t, proofs, client, groups), dependencycontract.Verify[AdmissionPlanner](t, proofs, planner, groups))
	if err != nil {
		t.Fatal(err)
	}
	input := canonical.Map{"messages": canonical.Array{canonical.Map{"role": "user", "content": "original input"}}}
	permit := validTestPermit(validTestID("tenant", 1), validTestID("subject", 1), validTestID("sess", 1), 7)
	permit.Operation = platformapi.OperationCreateTurn
	request := platformapi.SessionTurnAdmission{Authorization: permit, ProposedTurnID: validTestID("turn", 1), Input: input, InputDigest: "input-digest", RequestDigest: "request-digest", KeyDigest: "key-digest"}
	result, err := store.AdmitTurn(context.Background(), request)
	if err != nil || result.TurnID != request.ProposedTurnID || !result.Activated {
		t.Fatalf("admission result=%+v err=%v", result, err)
	}
	if planner.calls != 1 || client.calls != 1 || !reflect.DeepEqual(client.request.Input, input) || input["messages"].(canonical.Array)[0].(canonical.Map)["content"] != "original input" {
		t.Fatal("planner mutation changed signed input")
	}
	if client.request.CommandID != planner.plan.CommandID || client.request.TurnLeaseGeneration != 4 || client.request.ExpectedEventSequence != 9 || client.request.ExpectedAuthorizationGeneration != 7 || client.request.ActorSubjectID != permit.Principal.SubjectID {
		t.Fatal("trusted plan or actor scope dropped")
	}
	for code, want := range map[string]error{"PERMISSION_DENIED": platformapi.ErrAccessDenied, "STALE_GENERATION": platformapi.ErrStaleAuthority, "IDEMPOTENCY_CONFLICT": platformapi.ErrIdempotencyConflict, "CONFLICT": platformapi.ErrSequenceConflict, "NOT_INITIALIZED": platformapi.ErrSessionNotFound, "INTERNAL_ERROR": platformapi.ErrRepositoryFailure} {
		client.err = &stateappclient.RemoteError{Code: code}
		if _, err := store.AdmitTurn(context.Background(), request); !errors.Is(err, want) {
			t.Fatalf("%s error=%v", code, err)
		}
	}
	calls := planner.calls
	request.Authorization.Proof = platformapi.OpaqueAuthorizationProof{}
	if _, err := store.AdmitTurn(context.Background(), request); !errors.Is(err, platformapi.ErrAccessDenied) {
		t.Fatalf("zero authority err=%v", err)
	}
	if planner.calls != calls {
		t.Fatal("invalid authority reached planner")
	}
}

func validTestID(prefix string, index uint64) string {
	var entropy [16]byte
	binary.BigEndian.PutUint64(entropy[8:], index)
	return prefix + "_" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(entropy[:])
}
func validTestPermit(tenant, subject, session string, generation uint64) platformapi.AuthorizationPermit {
	return platformapi.AuthorizationPermit{Operation: platformapi.OperationCreateTurn, Principal: platformapi.Principal{TenantID: tenant, SubjectID: subject}, SessionID: session, AuthorizationGeneration: generation, Proof: platformapi.OpaqueAuthorizationProof{1}}
}
