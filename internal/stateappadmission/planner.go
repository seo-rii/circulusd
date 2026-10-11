package stateappadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/sessionadmission"
	"github.com/hancomac/circulusd/internal/stateappclient"
	"github.com/hancomac/circulusd/internal/stateappcodec"
	"strings"
)

// PlanningClient challenges and queries the same native Session authority.
type PlanningClient interface {
	dependency.ProductionProbe
	PlanSessionTurnAdmission(context.Context, stateappclient.PlanSessionTurnAdmissionRequest) (stateappclient.PlanSessionTurnAdmissionResult, error)
}

// GenesisProvider must create the actual executable engine state, including its
// runtime-owned initial core state. A local constructor or empty protocol-level
// genesis cannot borrow the Session transport's production qualification.
type GenesisProvider interface {
	dependency.ProductionProbe
	CreateGenesis(context.Context, GenesisRequest) (*v1.AgentCheckpoint, error)
}

type GenesisRequest struct {
	TenantID       string
	WorkspaceID    string
	ActorSubjectID string
	SessionID      string
	TurnID         string
	Runtime        stateappclient.AdmissionRuntime
	Input          canonical.Value
	InputDigest    string
}

type PlannerConfig struct {
	Genesis dependency.Verified[GenesisProvider]
}

type Planner struct {
	client         PlanningClient
	genesis        GenesisProvider
	clientBinding  dependency.Verified[PlanningClient]
	genesisBinding dependency.Verified[GenesisProvider]
}

var _ AdmissionPlanner = (*Planner)(nil)

func NewPlanner(client dependency.Verified[PlanningClient], config PlannerConfig) (*Planner, error) {
	operational, _, err := client.Open()
	if err != nil || adapterClientIsNil(operational) {
		return nil, sessionadmission.ErrRepositoryNotDurable
	}
	genesis, _, err := config.Genesis.Open()
	if err != nil || adapterClientIsNil(genesis) {
		return nil, sessionadmission.ErrRepositoryNotDurable
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{dependency.AtomicEngineGenesis}, config.Genesis); err != nil {
		return nil, sessionadmission.ErrRepositoryNotDurable
	}
	// The planner remains a Session authority. Its independent executable-engine
	// binding need not own the Session's durable transaction domain.
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent}, client); err != nil {
		return nil, sessionadmission.ErrRepositoryNotDurable
	}
	return &Planner{client: operational, genesis: genesis, clientBinding: client, genesisBinding: config.Genesis}, nil
}

func (planner *Planner) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	if planner == nil || adapterClientIsNil(planner.client) || adapterClientIsNil(planner.genesis) {
		return dependency.ProbeResponse{}, dependency.ErrUnverifiedDependency
	}
	if _, _, err := planner.clientBinding.Open(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	if _, _, err := planner.genesisBinding.Open(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	return planner.client.ProbeProduction(ctx, challenge)
}

func (planner *Planner) PlanAdmission(ctx context.Context, request sessionadmission.SessionTurnAdmission) (AdmissionPlan, error) {
	var fail AdmissionPlan
	if ctx == nil {
		return fail, sessionadmission.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return fail, err
	}
	if planner == nil || adapterClientIsNil(planner.client) || adapterClientIsNil(planner.genesis) {
		return fail, sessionadmission.ErrRepositoryNotDurable
	}
	if _, _, err := planner.clientBinding.Open(); err != nil {
		return fail, sessionadmission.ErrRepositoryNotDurable
	}
	if _, _, err := planner.genesisBinding.Open(); err != nil {
		return fail, sessionadmission.ErrRepositoryNotDurable
	}
	permit := request.Authorization
	if permit.Operation != sessionadmission.OperationCreateTurn || permit.Proof == (sessionadmission.OpaqueAuthorizationProof{}) {
		return fail, sessionadmission.ErrAccessDenied
	}
	planned, err := stateappclient.SnapshotAdmissionPlanningRequest(stateappclient.PlanSessionTurnAdmissionRequest{
		TenantID: permit.Principal.TenantID, ActorSubjectID: permit.Principal.SubjectID, SessionID: permit.SessionID,
		ExpectedAuthorizationGeneration: permit.AuthorizationGeneration, ProposedTurnID: request.ProposedTurnID,
		Input: request.Input, InputDigest: request.InputDigest, IdempotencyKeyDigest: request.KeyDigest, RequestDigest: request.RequestDigest,
	})
	if err != nil {
		return fail, sessionadmission.ErrInvalidRequest
	}
	// Retain a second independent copy for validating provider output; neither
	// trusted dependency may mutate the full input signed by the other boundary.
	original, err := stateappclient.SnapshotAdmissionPlanningRequest(planned)
	if err != nil {
		return fail, sessionadmission.ErrInvalidRequest
	}
	result, err := planner.client.PlanSessionTurnAdmission(ctx, planned)
	if contextErr := ctx.Err(); contextErr != nil {
		return fail, contextErr
	}
	if err != nil {
		return fail, admissionError(err)
	}
	if result.ReplayedAdmission != nil {
		receipt := *result.ReplayedAdmission
		if !receipt.Replayed || receipt.TurnSequence > maximumSharedInteger || receipt.Version <= receipt.TurnSequence || receipt.Version > maximumSharedInteger {
			return fail, sessionadmission.ErrRepositoryFailure
		}
		if _, err := identity.Parse(identity.Turn, receipt.TurnID); err != nil {
			return fail, sessionadmission.ErrRepositoryFailure
		}
		return AdmissionPlan{ReplayedAdmission: &receipt}, nil
	}
	expectedCommand, err := stateappclient.AdmissionPlanningCommandID(original)
	if err != nil || result.CommandID != expectedCommand || result.ExpectedEventSequence >= maximumSharedInteger ||
		result.TurnLeaseGeneration < 1 || result.TurnLeaseGeneration > maximumSharedInteger || result.LeaseExpiresAt > maximumSharedInteger ||
		result.PlannedAt > maximumSharedInteger || result.LeaseExpiresAt <= result.PlannedAt || result.LeaseExpiresAt-result.PlannedAt > 300_000 {
		return fail, sessionadmission.ErrRepositoryFailure
	}
	if result.Runtime.EngineKind == "low-level" && (result.Runtime.AdapterABIVersion != 2 || result.Runtime.CheckpointSchemaVersion != 2) {
		return fail, sessionadmission.ErrRepositoryFailure
	}
	if _, err := identity.Parse(identity.Workspace, result.WorkspaceID); err != nil {
		return fail, sessionadmission.ErrRepositoryFailure
	}
	if result.Runtime.AdapterABIVersion < 1 || result.Runtime.AdapterABIVersion > maximumSharedInteger ||
		result.Runtime.CheckpointSchemaVersion < 1 || result.Runtime.CheckpointSchemaVersion > maximumSharedInteger ||
		(result.Runtime.EngineKind != "low-level" && result.Runtime.EngineKind != "agent-harness") {
		return fail, sessionadmission.ErrRepositoryFailure
	}
	if len(result.Runtime.RuntimeRevisionDigest) != 71 || !strings.HasPrefix(result.Runtime.RuntimeRevisionDigest, "sha256:") ||
		strings.ToLower(result.Runtime.RuntimeRevisionDigest) != result.Runtime.RuntimeRevisionDigest {
		return fail, sessionadmission.ErrRepositoryFailure
	}
	if _, err := hex.DecodeString(result.Runtime.RuntimeRevisionDigest[7:]); err != nil {
		return fail, sessionadmission.ErrRepositoryFailure
	}
	providerInput, err := stateappclient.SnapshotAdmissionPlanningRequest(original)
	if err != nil {
		return fail, sessionadmission.ErrInvalidRequest
	}
	checkpoint, err := planner.genesis.CreateGenesis(ctx, GenesisRequest{TenantID: original.TenantID, WorkspaceID: result.WorkspaceID,
		ActorSubjectID: original.ActorSubjectID, SessionID: original.SessionID, TurnID: original.ProposedTurnID,
		Runtime: result.Runtime, Input: providerInput.Input, InputDigest: original.InputDigest,
	})
	if contextErr := ctx.Err(); contextErr != nil {
		return fail, contextErr
	}
	if err != nil {
		return fail, admissionError(err)
	}
	if checkpoint == nil || len(checkpoint.PayloadBytes) < 1 || len(checkpoint.PayloadBytes) > 4<<20 {
		return fail, sessionadmission.ErrRepositoryFailure
	}
	value, err := stateappcodec.CheckpointToValue(checkpoint)
	if err != nil ||
		value["kind"] != "genesis" || value["sessionId"] != original.SessionID || value["turnId"] != original.ProposedTurnID ||
		value["runtimeRevisionDigest"] != result.Runtime.RuntimeRevisionDigest || value["engineKind"] != result.Runtime.EngineKind ||
		checkpoint.AdapterAbiVersion != result.Runtime.AdapterABIVersion || checkpoint.CheckpointSchemaVersion != result.Runtime.CheckpointSchemaVersion {
		return fail, sessionadmission.ErrRepositoryFailure
	}
	// Actual Pi genesis uses the canonical adapter state. Validate the embedded
	// input, so a provider cannot supply a valid checkpoint for another prompt.
	if result.Runtime.EngineKind == "low-level" {
		if err := validatePiGenesis(checkpoint, original.Input); err != nil {
			return fail, sessionadmission.ErrRepositoryFailure
		}
	}
	return AdmissionPlan{CommandID: result.CommandID, ExpectedEventSequence: result.ExpectedEventSequence, GenesisCheckpoint: value,
		TurnLeaseGeneration: result.TurnLeaseGeneration, LeaseExpiresAt: result.LeaseExpiresAt}, nil
}

func validatePiGenesis(checkpoint *v1.AgentCheckpoint, input canonical.Value) error {
	if checkpoint.PayloadEncoding != v1.CheckpointPayloadEncoding_CHECKPOINT_PAYLOAD_ENCODING_CANONICAL_CBOR {
		return errors.New("unsupported Pi genesis encoding")
	}
	value, err := canonical.Decode(checkpoint.PayloadBytes, canonical.Options{MaxBytes: 4 << 20, MaxDepth: 64, MaxItems: 100_000})
	if err != nil {
		return err
	}
	state, ok := value.(canonical.Map)
	if !ok || len(state) != 9 || state["version"] != int64(1) || state["status"] != "ready" || state["beforeTurnCompleted"] != false || state["awaiting"] != nil || state["terminalCode"] != nil {
		return errors.New("invalid Pi genesis state")
	}
	for _, field := range []string{"pendingTools", "completedTools"} {
		array, ok := state[field].(canonical.Array)
		if !ok || len(array) != 0 {
			return errors.New("noninitial Pi genesis state")
		}
	}
	core, ok := state["coreState"].(canonical.Map)
	if !ok || len(core) != 4 || core["version"] != int64(2) || core["phase"] != "ready" {
		return errors.New("invalid runtime-owned Pi core state")
	}
	for _, field := range []string{"messages", "pendingToolCalls"} {
		array, ok := core[field].(canonical.Array)
		if !ok || len(array) != 0 {
			return errors.New("noninitial Pi core state")
		}
	}
	expected, err := canonical.Encode(input, canonical.Options{MaxBytes: 1 << 20, MaxDepth: 64, MaxItems: 100_000})
	if err != nil {
		return err
	}
	actual, err := canonical.Encode(state["turnInput"], canonical.Options{MaxBytes: 1 << 20, MaxDepth: 64, MaxItems: 100_000})
	if err != nil || !bytes.Equal(expected, actual) {
		return errors.New("Pi genesis input mismatch")
	}
	return nil
}
