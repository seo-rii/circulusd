package stateappadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	dependencycontract "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/platformapi"
	"github.com/hancomac/circulusd/internal/stateappclient"
	"github.com/hancomac/circulusd/internal/stateappcodec"
	"google.golang.org/protobuf/proto"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type plannerTestAuthority struct {
	*dependencycontract.ProductionProofs
	result stateappclient.PlanSessionTurnAdmissionResult
	calls  int
	err    error
}

func (authority *plannerTestAuthority) PlanSessionTurnAdmission(_ context.Context, request stateappclient.PlanSessionTurnAdmissionRequest) (stateappclient.PlanSessionTurnAdmissionResult, error) {
	authority.calls++
	request.Input.(canonical.Map)["messages"].(canonical.Array)[0].(canonical.Map)["content"] = "authority mutated its copy"
	return authority.result, authority.err
}

type plannerTestGenesis struct {
	*dependencycontract.ProductionProofs
	checkpoint *v1.AgentCheckpoint
	request    GenesisRequest
	calls      int
	err        error
}

func (provider *plannerTestGenesis) CreateGenesis(_ context.Context, request GenesisRequest) (*v1.AgentCheckpoint, error) {
	provider.calls++
	provider.request = request
	request.Input.(canonical.Map)["messages"].(canonical.Array)[0].(canonical.Map)["content"] = "provider mutated its copy"
	return provider.checkpoint, provider.err
}

func actualAdmissionFixture(t *testing.T) (platformapi.SessionTurnAdmission, stateappclient.PlanSessionTurnAdmissionResult, *v1.AgentCheckpoint) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "packages", "protocol-types", "fixtures", "state-app-admission-plan-v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		RequestCBORHex  string `json:"requestCborHex"`
		ResponseCBORHex string `json:"responseCborHex"`
		GenesisCBORHex  string `json:"genesisCborHex"`
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	decode := func(text string) canonical.Value {
		t.Helper()
		data, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		value, err := canonical.Decode(data, canonical.Options{MaxBytes: 8 << 20, MaxDepth: 72, MaxItems: 100_000})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	m := decode(fixture.RequestCBORHex).(canonical.Map)
	request := platformapi.SessionTurnAdmission{Authorization: validTestPermit(m["tenantId"].(string), m["actorSubjectId"].(string), m["sessionId"].(string), uint64(m["expectedAuthorizationGeneration"].(int64))), ProposedTurnID: m["proposedTurnId"].(string), KeyDigest: m["idempotencyKeyDigest"].(string), RequestDigest: m["requestDigest"].(string), Input: m["input"], InputDigest: m["inputDigest"].(string)}
	request.Authorization.Operation = platformapi.OperationCreateTurn
	plan, err := stateappclient.DecodeAdmissionPlanningResult(decode(fixture.ResponseCBORHex).(canonical.Map)["payload"].(canonical.Map)["result"], stateappclient.PlanSessionTurnAdmissionRequest{TenantID: m["tenantId"].(string), ActorSubjectID: m["actorSubjectId"].(string), SessionID: m["sessionId"].(string), ExpectedAuthorizationGeneration: uint64(m["expectedAuthorizationGeneration"].(int64)), ProposedTurnID: request.ProposedTurnID, Input: request.Input, InputDigest: request.InputDigest, IdempotencyKeyDigest: request.KeyDigest, RequestDigest: request.RequestDigest})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := stateappcodec.CheckpointFromValue(decode(fixture.GenesisCBORHex))
	if err != nil {
		t.Fatal(err)
	}
	return request, plan, checkpoint
}

func qualifiedPlannerFixture(t *testing.T) (*Planner, *plannerTestAuthority, *plannerTestGenesis, platformapi.SessionTurnAdmission) {
	t.Helper()
	request, result, checkpoint := actualAdmissionFixture(t)
	groups := []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent}
	authorityProofs := dependencycontract.NewProductionProofs(t, groups)
	authority := &plannerTestAuthority{ProductionProofs: authorityProofs, result: result}
	genesisProofs := dependencycontract.NewProductionProofs(t, []dependency.AtomicGroup{dependency.AtomicEngineGenesis})
	genesis := &plannerTestGenesis{ProductionProofs: genesisProofs, checkpoint: checkpoint}
	planner, err := NewPlanner(dependencycontract.Verify[PlanningClient](t, authorityProofs, authority, groups), PlannerConfig{Genesis: dependencycontract.Verify[GenesisProvider](t, genesisProofs, genesis, []dependency.AtomicGroup{dependency.AtomicEngineGenesis})})
	if err != nil {
		t.Fatal(err)
	}
	return planner, authority, genesis, request
}

func TestPlannerRequiresIndependentExecutableGenesisCapability(t *testing.T) {
	planner, _, _, _ := qualifiedPlannerFixture(t)
	if _, err := NewPlanner(planner.clientBinding, PlannerConfig{}); !errors.Is(err, platformapi.ErrRepositoryNotDurable) {
		t.Fatalf("unqualified genesis accepted %v", err)
	}
	unrelated := dependencycontract.NewProductionProofs(t, []dependency.AtomicGroup{dependency.AtomicEffectLifecycle})
	provider := &plannerTestGenesis{ProductionProofs: unrelated}
	if _, err := NewPlanner(planner.clientBinding, PlannerConfig{Genesis: dependencycontract.Verify[GenesisProvider](t, unrelated, provider, []dependency.AtomicGroup{dependency.AtomicEffectLifecycle})}); !errors.Is(err, platformapi.ErrRepositoryNotDurable) {
		t.Fatalf("unrelated capability accepted %v", err)
	}
	if _, err := NewPlanner(dependency.Verified[PlanningClient]{}, PlannerConfig{Genesis: planner.genesisBinding}); !errors.Is(err, platformapi.ErrRepositoryNotDurable) {
		t.Fatalf("unqualified plan accepted %v", err)
	}
}

func TestPlannerPreservesActualPiGenesisFullInputRuntimeAndAuthoritativeLease(t *testing.T) {
	planner, authority, genesis, request := qualifiedPlannerFixture(t)
	plan, err := planner.PlanAdmission(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.CommandID != authority.result.CommandID || plan.ExpectedEventSequence != 0 || plan.TurnLeaseGeneration != 1 || plan.LeaseExpiresAt != 1_700_000_120_000 || plan.ReplayedAdmission != nil {
		t.Fatalf("plan=%+v", plan)
	}
	if genesis.calls != 1 || genesis.request.Runtime != authority.result.Runtime || genesis.request.WorkspaceID != authority.result.WorkspaceID || genesis.request.TurnID != request.ProposedTurnID || genesis.request.InputDigest != request.InputDigest {
		t.Fatal("genesis scope or runtime dropped")
	}
	if request.Input.(canonical.Map)["messages"].(canonical.Array)[0].(canonical.Map)["content"] != "First public message." {
		t.Fatal("trusted dependencies mutated original input")
	}
	checkpoint, err := stateappcodec.CheckpointFromValue(plan.GenesisCheckpoint)
	if err != nil || !proto.Equal(checkpoint, genesis.checkpoint) {
		t.Fatalf("actual executable genesis changed %v", err)
	}
}

func TestPlannerRejectsMalformedAuthorityBeforeGenesis(t *testing.T) {
	for _, mode := range []string{"workspace", "command", "CAS", "lease", "runtime", "runtime digest", "unsupported Pi ABI", "replay turn", "input digest"} {
		t.Run(mode, func(t *testing.T) {
			planner, authority, genesis, request := qualifiedPlannerFixture(t)
			switch mode {
			case "workspace":
				authority.result.WorkspaceID = request.ProposedTurnID
			case "command":
				authority.result.CommandID = "admission:forged"
			case "CAS":
				authority.result.ExpectedEventSequence = maximumSharedInteger
			case "lease":
				authority.result.LeaseExpiresAt = authority.result.PlannedAt
			case "runtime":
				authority.result.Runtime.AdapterABIVersion = 0
			case "runtime digest":
				authority.result.Runtime.RuntimeRevisionDigest = "sha256:not-a-digest"
			case "unsupported Pi ABI":
				authority.result.Runtime.AdapterABIVersion = 1
			case "replay turn":
				authority.result.ReplayedAdmission = &stateappclient.AdmitSessionTurnResult{TurnID: request.Authorization.SessionID, TurnSequence: 0, Version: 1, Replayed: true}
			case "input digest":
				request.InputDigest = "sha256:" + strings.Repeat("f", 64)
			}
			if _, err := planner.PlanAdmission(context.Background(), request); err == nil {
				t.Fatal("malformed authority accepted")
			}
			if genesis.calls != 0 {
				t.Fatal("invalid request reached genesis provider")
			}
		})
	}
}

func TestPlannerRejectsWrongOrEmptyGenesisAndSanitizesDependencyFailures(t *testing.T) {
	for _, mode := range []string{"nil", "empty", "oversized", "scope", "runtime", "input", "state version", "malformed core", "secret error"} {
		t.Run(mode, func(t *testing.T) {
			planner, _, genesis, request := qualifiedPlannerFixture(t)
			switch mode {
			case "nil":
				genesis.checkpoint = nil
			case "empty":
				genesis.checkpoint.PayloadBytes = nil
			case "oversized":
				genesis.checkpoint.PayloadBytes = make([]byte, (4<<20)+1)
			case "scope":
				genesis.checkpoint.TurnId = genesis.checkpoint.SessionId
			case "runtime":
				genesis.checkpoint.RuntimeRevisionDigest.Value = bytes.Repeat([]byte{0xff}, 32)
			case "secret error":
				genesis.err = errors.New("credential-secret-must-not-leak")
			case "input", "state version", "malformed core":
				payload, err := canonical.Decode(genesis.checkpoint.PayloadBytes, canonical.Options{MaxBytes: 4 << 20, MaxDepth: 64, MaxItems: 100_000})
				if err != nil {
					t.Fatal(err)
				}
				state := payload.(canonical.Map)
				if mode == "input" {
					state["turnInput"] = canonical.Map{"messages": canonical.Array{canonical.Map{"role": "user", "content": "different"}}}
				} else if mode == "malformed core" {
					state["coreState"] = nil
				} else {
					state["version"] = int64(2)
				}
				bytes, err := canonical.Encode(state, canonical.Options{MaxBytes: 4 << 20, MaxDepth: 64, MaxItems: 100_000})
				if err != nil {
					t.Fatal(err)
				}
				genesis.checkpoint.PayloadBytes = bytes
				sum := sha256.Sum256(bytes)
				genesis.checkpoint.PayloadDigest.Value = sum[:]
			}
			if _, err := planner.PlanAdmission(context.Background(), request); !errors.Is(err, platformapi.ErrRepositoryFailure) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("invalid genesis err=%v", err)
			}
		})
	}
}

func TestPlannerReplaySkipsGenesisAndTurnAdmitterReturnsOriginalReceipt(t *testing.T) {
	planner, authority, genesis, request := qualifiedPlannerFixture(t)
	authority.result.ReplayedAdmission = &stateappclient.AdmitSessionTurnResult{TurnID: validTestID("turn", 2), TurnSequence: 0, Version: 1, Replayed: true, Activated: true}
	plan, err := planner.PlanAdmission(context.Background(), request)
	if err != nil || plan.ReplayedAdmission == nil || genesis.calls != 0 {
		t.Fatalf("replay plan=%+v err=%v", plan, err)
	}
	// This adapter's planner is independently sealed to the same native domain as
	// its operational planning authority, rather than using genesis's identity.
	groups := []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent}
	client := &admissionTestClient{ProductionProofs: authority.ProductionProofs}
	store, err := NewTurnAdmitter(dependencycontract.Verify[AdmissionClient](t, authority.ProductionProofs, client, groups), dependencycontract.Verify[AdmissionPlanner](t, authority.ProductionProofs, planner, groups))
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.AdmitTurn(context.Background(), request)
	if err != nil || !result.Deduplicated || result.TurnID != validTestID("turn", 2) || client.calls != 0 || genesis.calls != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := authority.calls
	if _, err := planner.PlanAdmission(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if authority.calls != calls {
		t.Fatal("cancelled request reached authority")
	}
}
