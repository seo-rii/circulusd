// Package stateappadmission admits public Session turns through the
// state-app. A Planner asks the native Session authority for an admission
// plan (command ID, expected event sequence and turn lease) and has a
// GenesisProvider create the genesis checkpoint. A TurnAdmitter then submits
// the turn with that plan through the state-app ingress client. Both require
// verified production dependencies (package dependency), and a replayed
// admission is returned as deduplicated.
package stateappadmission

import (
	"context"
	"errors"
	"reflect"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/sessionadmission"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

// AdmissionPlanner is an independently qualified authority over the same
// Session transaction domain. A local callback or caller-supplied checkpoint
// cannot acquire production authority by borrowing the transport's probe.
type AdmissionPlanner interface {
	dependency.ProductionProbe
	PlanAdmission(context.Context, sessionadmission.SessionTurnAdmission) (AdmissionPlan, error)
}

type AdmissionPlan struct {
	CommandID             string
	ExpectedEventSequence uint64
	GenesisCheckpoint     canonical.Value
	TurnLeaseGeneration   uint64
	LeaseExpiresAt        uint64
	ReplayedAdmission     *stateappclient.AdmitSessionTurnResult
}

type AdmissionClient interface {
	dependency.ProductionProbe
	AdmitSessionTurn(context.Context, stateappclient.AdmitSessionTurnRequest) (stateappclient.AdmitSessionTurnResult, error)
}

type TurnAdmitter struct {
	client         AdmissionClient
	planner        AdmissionPlanner
	clientBinding  dependency.Verified[AdmissionClient]
	plannerBinding dependency.Verified[AdmissionPlanner]
}

var _ sessionadmission.SessionTurnStore = (*TurnAdmitter)(nil)

func NewTurnAdmitter(client dependency.Verified[AdmissionClient], planner dependency.Verified[AdmissionPlanner]) (*TurnAdmitter, error) {
	operationalClient, _, err := client.Open()
	if err != nil {
		return nil, sessionadmission.ErrRepositoryNotDurable
	}
	operationalPlanner, _, err := planner.Open()
	if err != nil {
		return nil, sessionadmission.ErrRepositoryNotDurable
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{
		dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent,
	}, client, planner); err != nil {
		return nil, sessionadmission.ErrRepositoryNotDurable
	}
	return &TurnAdmitter{client: operationalClient, planner: operationalPlanner, clientBinding: client, plannerBinding: planner}, nil
}

func (store *TurnAdmitter) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	if store == nil || adapterClientIsNil(store.client) || adapterClientIsNil(store.planner) {
		return dependency.ProbeResponse{}, dependency.ErrUnverifiedDependency
	}
	if _, _, err := store.clientBinding.Open(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	if _, _, err := store.plannerBinding.Open(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	return store.client.ProbeProduction(ctx, challenge)
}

func (store *TurnAdmitter) AdmitTurn(ctx context.Context, request sessionadmission.SessionTurnAdmission) (sessionadmission.SessionTurnAdmissionResult, error) {
	fail := sessionadmission.SessionTurnAdmissionResult{}
	if ctx == nil {
		return fail, sessionadmission.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return fail, err
	}
	if store == nil || adapterClientIsNil(store.client) || adapterClientIsNil(store.planner) {
		return fail, sessionadmission.ErrRepositoryNotDurable
	}
	permit := request.Authorization
	if permit.Operation != sessionadmission.OperationCreateTurn || permit.AuthorizationGeneration < 1 || permit.AuthorizationGeneration > maximumSharedInteger ||
		permit.Proof == (sessionadmission.OpaqueAuthorizationProof{}) {
		return fail, sessionadmission.ErrAccessDenied
	}
	for kind, value := range map[identity.Kind]string{identity.Tenant: permit.Principal.TenantID, identity.Subject: permit.Principal.SubjectID, identity.Session: permit.SessionID, identity.Turn: request.ProposedTurnID} {
		if _, err := identity.Parse(kind, value); err != nil {
			return fail, sessionadmission.ErrInvalidRequest
		}
	}
	// Own the full input before trusted preparation and give the planner a
	// separate copy, so it cannot mutate the semantic request that is signed.
	options := canonical.Options{MaxBytes: 1 << 20, MaxDepth: 64, MaxItems: 100_000}
	bytes, err := canonical.Encode(request.Input, options)
	if err != nil {
		return fail, sessionadmission.ErrInvalidRequest
	}
	input, err := canonical.Decode(bytes, options)
	if err != nil {
		return fail, sessionadmission.ErrInvalidRequest
	}
	plannerInput, err := canonical.Decode(bytes, options)
	if err != nil {
		return fail, sessionadmission.ErrInvalidRequest
	}
	plannedRequest := request
	plannedRequest.Input = plannerInput
	plan, err := store.planner.PlanAdmission(ctx, plannedRequest)
	if contextErr := ctx.Err(); contextErr != nil {
		return fail, contextErr
	}
	if err != nil {
		return fail, admissionError(err)
	}
	if plan.ReplayedAdmission != nil {
		result := *plan.ReplayedAdmission
		if !result.Replayed || result.TurnSequence > maximumSharedInteger || result.Version <= result.TurnSequence || result.Version > maximumSharedInteger {
			return fail, sessionadmission.ErrRepositoryFailure
		}
		if _, err := identity.Parse(identity.Turn, result.TurnID); err != nil {
			return fail, sessionadmission.ErrRepositoryFailure
		}
		return sessionadmission.SessionTurnAdmissionResult{TurnID: result.TurnID, TurnSequence: result.TurnSequence,
			Activated: result.Activated, Deduplicated: true}, nil
	}
	result, err := store.client.AdmitSessionTurn(ctx, stateappclient.AdmitSessionTurnRequest{
		TenantID: permit.Principal.TenantID, ActorSubjectID: permit.Principal.SubjectID, SessionID: permit.SessionID,
		ExpectedAuthorizationGeneration: permit.AuthorizationGeneration, CommandID: plan.CommandID, ExpectedEventSequence: plan.ExpectedEventSequence,
		TurnID: request.ProposedTurnID, Input: input, InputDigest: request.InputDigest, GenesisCheckpoint: plan.GenesisCheckpoint,
		TurnLeaseGeneration: plan.TurnLeaseGeneration, LeaseExpiresAt: plan.LeaseExpiresAt, IdempotencyKeyDigest: request.KeyDigest, RequestDigest: request.RequestDigest,
	})
	if contextErr := ctx.Err(); contextErr != nil {
		return fail, contextErr
	}
	if err != nil {
		return fail, admissionError(err)
	}
	if result.TurnSequence > maximumSharedInteger || result.Version <= result.TurnSequence ||
		(!result.Replayed && result.TurnID != request.ProposedTurnID) {
		return fail, sessionadmission.ErrRepositoryFailure
	}
	if _, err := identity.Parse(identity.Turn, result.TurnID); err != nil {
		return fail, sessionadmission.ErrRepositoryFailure
	}
	return sessionadmission.SessionTurnAdmissionResult{TurnID: result.TurnID, TurnSequence: result.TurnSequence, Activated: result.Activated, Deduplicated: result.Replayed}, nil
}

func admissionError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var remote *stateappclient.RemoteError
	if errors.As(err, &remote) {
		switch remote.Code {
		case "PERMISSION_DENIED":
			return sessionadmission.ErrAccessDenied
		case "STALE_GENERATION":
			return sessionadmission.ErrStaleAuthority
		case "NOT_FOUND", "NOT_INITIALIZED":
			return sessionadmission.ErrSessionNotFound
		case "IDEMPOTENCY_CONFLICT":
			return sessionadmission.ErrIdempotencyConflict
		case "CONFLICT":
			return sessionadmission.ErrSequenceConflict
		}
	}
	return sessionadmission.ErrRepositoryFailure
}

const maximumSharedInteger = uint64(9_007_199_254_740_991)

func adapterClientIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	}
	return false
}
