package modelgateway

import (
	"bytes"
	"context"
	"io"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"github.com/hancomac/circulusd/internal/identity"
)

type fixture struct {
	scope         ValidatedAuthority
	request       ModelRequest
	requestDigest Digest
	bounds        Bounds
	grant         ModelGrant
	authority     *fakeAuthority
	counter       *fakeTokenCounter
	quota         *fakeQuota
	dispatches    *fakeDispatchCoordinator
	provider      *fakeProvider
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	scope := ValidatedAuthority{
		TenantID:        mustID(t, identity.Tenant, 'a'),
		UserID:          mustID(t, identity.Subject, 'b'),
		SessionID:       mustID(t, identity.Session, 'c'),
		TurnID:          mustID(t, identity.Turn, 'd'),
		EffectID:        mustID(t, identity.Effect, 'e'),
		InvocationID:    mustID(t, identity.Invocation, 'f'),
		RuntimeRevision: mustID(t, identity.RuntimeRevision, 'g'),
		Generations:     Generations{TurnLease: 1, Placement: 2, Policy: 3},
	}
	request := ModelRequest{
		Model: "model-a",
		Messages: []Message{
			{Role: RoleSystem, Content: "be concise"},
			{Role: RoleUser, Content: "hello"},
		},
		MaxOutputTokens: 17,
	}
	requestDigest, err := ModelRequestDigest(request)
	if err != nil {
		t.Fatalf("ModelRequestDigest() error = %v", err)
	}
	dispatches := &fakeDispatchCoordinator{scope: scope, claimed: make(map[string]struct{})}
	provider := &fakeProvider{
		availability: ProviderAvailability{Available: true}, providerRequestID: "provider-request-1",
		stream: emptyProviderStream{}, dispatches: dispatches,
	}
	return &fixture{
		scope:         scope,
		request:       request,
		requestDigest: requestDigest,
		bounds: Bounds{
			MaxAuthorityBytes:         64,
			MaxMessages:               4,
			MaxMessageBytes:           64,
			MaxInputBytes:             128,
			MaxModelBytes:             32,
			MaxProviderIDBytes:        16,
			MaxProviderRequestIDBytes: 24,
			MaxEventBytes:             32,
			MaxEvents:                 16,
			MaxStreamBytes:            128,
			MaxResponseBytes:          128,
			MaxReasonBytes:            32,
		},
		grant: ModelGrant{
			TenantID:              scope.TenantID,
			UserID:                scope.UserID,
			Model:                 "model-a",
			ProviderID:            "provider-a",
			MaxContextTokens:      40,
			MaxOutputTokens:       30,
			MaxTotalTokens:        50,
			MaxPreDispatchRetries: 1,
		},
		authority:  &fakeAuthority{scope: scope},
		counter:    &fakeTokenCounter{tokens: 11},
		quota:      &fakeQuota{},
		dispatches: dispatches,
		provider:   provider,
	}
}

func (fixture *fixture) configuration() Configuration {
	return Configuration{Bounds: fixture.bounds, Grants: []ModelGrant{fixture.grant}, AllowReferenceMemory: true}
}

func (fixture *fixture) dependencies() Dependencies {
	return Dependencies{
		Authority:    fixture.authority,
		TokenCounter: fixture.counter,
		Quota:        fixture.quota,
		Dispatches:   fixture.dispatches,
		Providers:    map[string]Provider{"provider-a": fixture.provider},
	}
}

func (fixture *fixture) gateway(t *testing.T) *Gateway {
	t.Helper()
	gateway, err := NewGateway(fixture.configuration(), fixture.dependencies())
	if err != nil {
		t.Fatalf("NewGateway() error = %v", err)
	}
	return gateway
}

func (fixture *fixture) admissionRequest() AdmissionRequest {
	return AdmissionRequest{
		Authority:     OpaqueAuthority("opaque-authority"),
		EffectID:      fixture.scope.EffectID,
		InvocationID:  fixture.scope.InvocationID,
		RequestDigest: fixture.requestDigest,
		Request:       cloneModelRequest(fixture.request),
	}
}

func (fixture *fixture) admit(t *testing.T, gateway *Gateway) Effect {
	t.Helper()
	effect, err := gateway.Admit(context.Background(), fixture.admissionRequest())
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	return effect
}

type fakeAuthority struct {
	mu             sync.Mutex
	scope          ValidatedAuthority
	admissionErr   error
	settlementErr  error
	admissions     int
	settlements    int
	lastAdmission  AdmissionAuthorityRequest
	lastSettlement SettlementAuthorityRequest
	concurrent     bool
}

func (*fakeAuthority) Durability() AuthorityDurability {
	return AuthorityDurability{CurrentGenerationFencing: true, ReferenceMemory: true}
}

func (authority *fakeAuthority) ValidateAdmission(_ context.Context, _ OpaqueAuthority, request AdmissionAuthorityRequest) (ValidatedAuthority, error) {
	if authority.concurrent {
		authority.mu.Lock()
		defer authority.mu.Unlock()
	}
	authority.admissions++
	authority.lastAdmission = request
	return authority.scope, authority.admissionErr
}

func (authority *fakeAuthority) ValidateSettlement(_ context.Context, _ OpaqueAuthority, request SettlementAuthorityRequest) (ValidatedAuthority, error) {
	if authority.concurrent {
		authority.mu.Lock()
		defer authority.mu.Unlock()
	}
	authority.settlements++
	authority.lastSettlement = request
	return authority.scope, authority.settlementErr
}

type fakeTokenCounter struct {
	mu         sync.Mutex
	tokens     uint64
	err        error
	calls      int
	concurrent bool
}

func (counter *fakeTokenCounter) Count(_ context.Context, _ TokenCountRequest) (uint64, error) {
	if counter.concurrent {
		counter.mu.Lock()
		defer counter.mu.Unlock()
	}
	counter.calls++
	return counter.tokens, counter.err
}

type fakeQuota struct {
	mu           sync.Mutex
	err          error
	settleErr    error
	calls        int
	last         QuotaRequest
	mutate       func(*QuotaPermit)
	concurrent   bool
	reservations int
	settlements  int
	permits      map[identity.ID]struct {
		request QuotaRequest
		permit  QuotaPermit
	}
	receipts map[string]struct {
		request QuotaSettlementRequest
		receipt QuotaSettlementReceipt
	}
}

func (*fakeQuota) Durability() QuotaDurability {
	return QuotaDurability{AtomicReservationSettlement: true, ReferenceMemory: true}
}

func (quota *fakeQuota) Admit(_ context.Context, request QuotaRequest) (QuotaPermit, error) {
	if quota.concurrent {
		quota.mu.Lock()
		defer quota.mu.Unlock()
	}
	quota.calls++
	quota.last = request
	if quota.err != nil {
		return QuotaPermit{}, quota.err
	}
	if quota.permits == nil {
		quota.permits = make(map[identity.ID]struct {
			request QuotaRequest
			permit  QuotaPermit
		})
	}
	if existing, found := quota.permits[request.InvocationID]; found {
		if existing.request != request {
			return QuotaPermit{}, ErrQuotaConflict
		}
		return existing.permit, nil
	}
	permit := QuotaPermit{
		ReservationID:   "reservation-1",
		Durable:         true,
		TenantID:        request.TenantID,
		UserID:          request.UserID,
		EffectID:        request.EffectID,
		InvocationID:    request.InvocationID,
		SessionID:       request.SessionID,
		TurnID:          request.TurnID,
		RuntimeRevision: request.RuntimeRevision,
		Generations:     request.Generations,
		RequestDigest:   request.RequestDigest,
		ContextTokens:   request.ContextTokens,
		OutputTokens:    request.OutputTokens,
	}
	if quota.mutate != nil {
		quota.mutate(&permit)
	}
	quota.permits[request.InvocationID] = struct {
		request QuotaRequest
		permit  QuotaPermit
	}{request: request, permit: permit}
	quota.reservations++
	return permit, nil
}

func (quota *fakeQuota) Settle(_ context.Context, request QuotaSettlementRequest) (QuotaSettlementReceipt, error) {
	quota.mu.Lock()
	defer quota.mu.Unlock()
	if quota.settleErr != nil {
		return QuotaSettlementReceipt{}, quota.settleErr
	}
	if quota.receipts == nil {
		quota.receipts = make(map[string]struct {
			request QuotaSettlementRequest
			receipt QuotaSettlementReceipt
		})
	}
	if existing, found := quota.receipts[request.Permit.ReservationID]; found {
		if existing.request != request {
			validRecovery := request.Recovery.Durable && request.Recovery.Proof != (OpaqueResumePermit{}) &&
				request.Recovery.EffectID == request.Permit.EffectID && request.Recovery.InvocationID == request.Permit.InvocationID &&
				request.Recovery.RequestDigest == request.Permit.RequestDigest
			validResolution := request.Resolution.Durable && request.Resolution.Proof != (OpaqueUncertainResolutionPermit{}) &&
				request.Resolution.EffectID == request.Permit.EffectID && request.Resolution.InvocationID == request.Permit.InvocationID &&
				request.Resolution.RequestDigest == request.Permit.RequestDigest && request.Resolution.TerminalDigest == request.Authorization.TerminalDigest &&
				((request.Resolution.Decision == UncertainResolutionConsume && request.Disposition == QuotaDispositionConsume) ||
					(request.Resolution.Decision == UncertainResolutionRelease && request.Disposition == QuotaDispositionRelease))
			canReconcileHold := existing.request.Disposition == QuotaDispositionHold &&
				(request.Disposition == QuotaDispositionHold || request.Disposition == QuotaDispositionConsume || request.Disposition == QuotaDispositionRelease) &&
				request.Authorization.Durable && request.Authorization.Proof != (OpaqueSettlementPermit{}) &&
				(validRecovery || validResolution)
			if !canReconcileHold {
				return QuotaSettlementReceipt{}, ErrQuotaConflict
			}
		} else {
			return existing.receipt, nil
		}
	}
	receipt := QuotaSettlementReceipt{
		ReservationID: request.Permit.ReservationID,
		EffectID:      request.Permit.EffectID, InvocationID: request.Permit.InvocationID,
		RequestDigest: request.Permit.RequestDigest, Outcome: request.Outcome,
		Disposition: request.Disposition, Usage: request.Usage,
		ProviderRequestID: request.ProviderRequestID, Attempt: request.Attempt, Durable: true,
		Authorization: request.Authorization, Recovery: request.Recovery, Resolution: request.Resolution,
	}
	quota.receipts[request.Permit.ReservationID] = struct {
		request QuotaSettlementRequest
		receipt QuotaSettlementReceipt
	}{request: request, receipt: receipt}
	quota.settlements++
	return receipt, nil
}

type fakeProvider struct {
	mu                     sync.Mutex
	availability           ProviderAvailability
	availabilityErr        error
	availabilityCalls      int
	dispatchCalls          int
	dispatchErr            error
	stream                 ProviderStream
	dispatches             *fakeDispatchCoordinator
	dispatchedWithoutClaim bool
	providerRequestID      string
	returnRequestIDOnError bool
	resumeCalls            int
	lastResume             ProviderResumeCommand
	resumeErr              error
	cancelCalls            int
	lastCancel             CancelCommand
	cancelResult           ProviderCancellation
	cancelErr              error
	onDispatch             func()
	concurrent             bool
}

func (provider *fakeProvider) Availability(context.Context) (ProviderAvailability, error) {
	if provider.concurrent {
		provider.mu.Lock()
		defer provider.mu.Unlock()
	}
	provider.availabilityCalls++
	return provider.availability, provider.availabilityErr
}

func (provider *fakeProvider) Dispatch(_ context.Context, command DispatchCommand) (ProviderDispatchResult, error) {
	if provider.concurrent {
		provider.mu.Lock()
		defer provider.mu.Unlock()
	}
	provider.dispatchCalls++
	if provider.onDispatch != nil {
		provider.onDispatch()
	}
	if provider.dispatches == nil || provider.dispatches.claimCount(command) != 1 || !command.Permit.Durable {
		provider.dispatchedWithoutClaim = true
	}
	result := ProviderDispatchResult{ProviderRequestID: provider.providerRequestID, Stream: provider.stream}
	if provider.dispatchErr != nil && !provider.returnRequestIDOnError {
		result = ProviderDispatchResult{}
	}
	return result, provider.dispatchErr
}

func (provider *fakeProvider) Cancel(_ context.Context, command CancelCommand) (ProviderCancellation, error) {
	if provider.concurrent {
		provider.mu.Lock()
		defer provider.mu.Unlock()
	}
	provider.cancelCalls++
	provider.lastCancel = command
	return provider.cancelResult, provider.cancelErr
}

func (provider *fakeProvider) Resume(_ context.Context, command ProviderResumeCommand) (ProviderStream, error) {
	if provider.concurrent {
		provider.mu.Lock()
		defer provider.mu.Unlock()
	}
	provider.resumeCalls++
	provider.lastResume = command
	return provider.stream, provider.resumeErr
}

type fakeDispatchCoordinator struct {
	mu                 sync.Mutex
	scope              ValidatedAuthority
	claimed            map[string]struct{}
	claims             int
	acceptances        int
	mutate             func(*DispatchCommitRequest)
	acceptedContextErr error
	concurrent         bool
	durable            *Effect
	dispatchStage      map[string]string
	settlementPermits  map[Digest]SettlementPermit
	resolutionPermits  map[identity.ID]UncertainResolutionPermit
}

func (*fakeDispatchCoordinator) Durability() DispatchDurability {
	return DispatchDurability{AtomicEffectTransitions: true, ExclusiveDispatchClaim: true, ReferenceMemory: true}
}

func (coordinator *fakeDispatchCoordinator) CommitAndClaimDispatch(_ context.Context, request DispatchCommitRequest) (DispatchPermit, error) {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if request.CurrentScope != coordinator.scope || request.Effect.Scope != coordinator.scope || request.ExpectedRevision+1 != request.Effect.Revision || request.Command.Attempt != request.Effect.Attempt {
		return DispatchPermit{}, ErrAuthorityMismatch
	}
	if coordinator.mutate != nil {
		coordinator.mutate(&request)
	}
	key := request.Effect.Scope.EffectID.String() + ":" + request.Effect.ProviderID + ":" + strconv.FormatUint(uint64(request.Effect.Attempt), 10)
	if coordinator.durable != nil && coordinator.durable.Revision != request.ExpectedRevision {
		return DispatchPermit{}, ErrConcurrentTransition
	}
	if _, found := coordinator.claimed[key]; found {
		return DispatchPermit{}, ErrConcurrentTransition
	}
	coordinator.claimed[key] = struct{}{}
	if coordinator.dispatchStage == nil {
		coordinator.dispatchStage = make(map[string]string)
	}
	coordinator.dispatchStage[key] = "claimed"
	stored := request.Effect
	stored.Request = cloneModelRequest(request.Effect.Request)
	stored.Response = cloneResponse(request.Effect.Response)
	coordinator.durable = &stored
	coordinator.claims++
	var proof OpaqueDispatchPermit
	proof[0] = byte(request.Effect.Attempt)
	proof[1] = 1
	return DispatchPermit{
		Proof: proof, Durable: true, Scope: request.Effect.Scope, EffectID: request.Effect.Scope.EffectID,
		InvocationID: request.Effect.Scope.InvocationID, RequestDigest: request.Effect.RequestDigest,
		ProviderID: request.Effect.ProviderID, Attempt: request.Effect.Attempt, EffectRevision: request.Effect.Revision,
	}, nil
}

func (coordinator *fakeDispatchCoordinator) BeginProviderDispatch(_ context.Context, permit DispatchPermit) error {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	key := permit.EffectID.String() + ":" + permit.ProviderID + ":" + strconv.FormatUint(uint64(permit.Attempt), 10)
	if !permit.Durable || permit.Proof == (OpaqueDispatchPermit{}) || coordinator.dispatchStage[key] != "claimed" {
		return ErrConcurrentTransition
	}
	coordinator.dispatchStage[key] = "started"
	return nil
}

func (coordinator *fakeDispatchCoordinator) CommitProviderAccepted(ctx context.Context, request ProviderAcceptedCommitRequest) error {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	coordinator.acceptedContextErr = ctx.Err()
	if coordinator.acceptedContextErr != nil {
		return coordinator.acceptedContextErr
	}
	if request.Permit.Scope != coordinator.scope || !request.Permit.Durable || request.ExpectedRevision+1 != request.Effect.Revision ||
		request.Effect.State != StateDispatched || request.Effect.ProviderRequestID == "" || request.Permit.EffectID != request.Effect.Scope.EffectID ||
		request.Permit.Attempt != request.Effect.Attempt {
		return ErrAuthorityMismatch
	}
	if coordinator.durable == nil || coordinator.durable.Revision != request.ExpectedRevision {
		return ErrConcurrentTransition
	}
	stored := request.Effect
	stored.Request = cloneModelRequest(request.Effect.Request)
	stored.Response = cloneResponse(request.Effect.Response)
	coordinator.durable = &stored
	coordinator.acceptances++
	return nil
}

func (coordinator *fakeDispatchCoordinator) CommitAndClaimCancellation(_ context.Context, request CancellationCommitRequest) (CancellationPermit, error) {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if !sameAuthorityIdentity(request.CurrentScope, request.Effect.Scope) || request.ExpectedRevision+1 != request.Effect.Revision ||
		request.Effect.State != StateCancellationPending || request.Command.Attempt != request.Effect.Attempt {
		return CancellationPermit{}, ErrAuthorityMismatch
	}
	if coordinator.durable != nil && coordinator.durable.Revision != request.ExpectedRevision {
		return CancellationPermit{}, ErrConcurrentTransition
	}
	key := request.Effect.Scope.EffectID.String() + ":" + request.Effect.ProviderID + ":" + strconv.FormatUint(uint64(request.Effect.Attempt), 10)
	prevented := coordinator.dispatchStage[key] == "claimed"
	if prevented {
		coordinator.dispatchStage[key] = "cancelled"
	}
	stored := request.Effect
	stored.Request = cloneModelRequest(request.Effect.Request)
	stored.Response = cloneResponse(request.Effect.Response)
	coordinator.durable = &stored
	var proof OpaqueCancellationPermit
	proof[0], proof[1] = byte(request.Effect.Attempt), 1
	return CancellationPermit{
		Proof: proof, Durable: true, CurrentScope: request.CurrentScope,
		EffectID: request.Effect.Scope.EffectID, InvocationID: request.Effect.Scope.InvocationID,
		RequestDigest: request.Effect.RequestDigest, ProviderID: request.Effect.ProviderID,
		ProviderRequestID: request.Effect.ProviderRequestID, Attempt: request.Effect.Attempt,
		EffectRevision: request.Effect.Revision, DispatchPrevented: prevented,
	}, nil
}

func (coordinator *fakeDispatchCoordinator) CommitAndClaimResume(_ context.Context, request ResumeCommitRequest) (ResumePermit, error) {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if !sameAuthorityIdentity(request.CurrentScope, request.Effect.Scope) || request.Effect.ProviderRequestID == "" {
		return ResumePermit{}, ErrAuthorityMismatch
	}
	if coordinator.durable != nil && !reflect.DeepEqual(*coordinator.durable, request.Effect) {
		return ResumePermit{}, ErrConcurrentTransition
	}
	var proof OpaqueResumePermit
	proof[0], proof[1] = byte(request.Effect.Attempt), byte(request.CurrentScope.Generations.Placement)
	return ResumePermit{
		Proof: proof, Durable: true, OriginScope: request.Effect.Scope, CurrentScope: request.CurrentScope,
		EffectID: request.Effect.Scope.EffectID, InvocationID: request.Effect.Scope.InvocationID,
		RequestDigest: request.Effect.RequestDigest, ProviderID: request.Effect.ProviderID,
		ProviderRequestID: request.Effect.ProviderRequestID, Attempt: request.Effect.Attempt,
		EffectRevision: request.Effect.Revision,
	}, nil
}

func (coordinator *fakeDispatchCoordinator) CommitAndClaimSettlement(_ context.Context, request SettlementCommitRequest) (SettlementPermit, error) {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if !sameAuthorityIdentity(request.CurrentScope, request.Effect.Scope) || request.TerminalDigest == (Digest{}) ||
		request.Effect.Outcome == "" || request.ExpectedRevision+1 != request.Effect.Revision {
		return SettlementPermit{}, ErrAuthorityMismatch
	}
	if coordinator.durable != nil {
		sameTerminal := reflect.DeepEqual(*coordinator.durable, request.Effect)
		if !sameTerminal && coordinator.durable.Revision != request.ExpectedRevision {
			return SettlementPermit{}, ErrConcurrentTransition
		}
	}
	stored := request.Effect
	stored.Request = cloneModelRequest(request.Effect.Request)
	stored.Response = cloneResponse(request.Effect.Response)
	coordinator.durable = &stored
	if coordinator.settlementPermits == nil {
		coordinator.settlementPermits = make(map[Digest]SettlementPermit)
	}
	if existing, found := coordinator.settlementPermits[request.TerminalDigest]; found {
		return existing, nil
	}
	var proof OpaqueSettlementPermit
	proof[0], proof[1] = byte(request.Effect.Revision), 1
	permit := SettlementPermit{
		Proof: proof, Durable: true, CurrentScope: request.CurrentScope,
		EffectID: request.Effect.Scope.EffectID, InvocationID: request.Effect.Scope.InvocationID,
		RequestDigest: request.Effect.RequestDigest, EffectRevision: request.Effect.Revision,
		TerminalDigest: request.TerminalDigest, ReservationID: request.Effect.QuotaPermit.ReservationID,
	}
	coordinator.settlementPermits[request.TerminalDigest] = permit
	return permit, nil
}

func (coordinator *fakeDispatchCoordinator) CommitAndClaimUncertainResolution(_ context.Context, request UncertainResolutionCommitRequest) (UncertainResolutionPermit, error) {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if !sameAuthorityIdentity(request.CurrentScope, request.Effect.Scope) || request.Effect.State != StateUncertain ||
		request.Effect.Outcome != OutcomeUncertain || request.TerminalDigest == (Digest{}) {
		return UncertainResolutionPermit{}, ErrAuthorityMismatch
	}
	if coordinator.durable == nil || !reflect.DeepEqual(*coordinator.durable, request.Effect) {
		return UncertainResolutionPermit{}, ErrConcurrentTransition
	}
	if coordinator.resolutionPermits == nil {
		coordinator.resolutionPermits = make(map[identity.ID]UncertainResolutionPermit)
	}
	if existing, found := coordinator.resolutionPermits[request.Effect.Scope.EffectID]; found {
		if existing.TerminalDigest != request.TerminalDigest || existing.Decision != request.Decision {
			return UncertainResolutionPermit{}, ErrQuotaConflict
		}
		return existing, nil
	}
	var proof OpaqueUncertainResolutionPermit
	proof[0], proof[1] = byte(request.Effect.Revision), 1
	permit := UncertainResolutionPermit{
		Proof: proof, Durable: true, CurrentScope: request.CurrentScope,
		EffectID: request.Effect.Scope.EffectID, InvocationID: request.Effect.Scope.InvocationID,
		RequestDigest: request.Effect.RequestDigest, TerminalDigest: request.TerminalDigest,
		ReservationID: request.Effect.QuotaPermit.ReservationID, Decision: request.Decision,
	}
	coordinator.resolutionPermits[request.Effect.Scope.EffectID] = permit
	return permit, nil
}

func (coordinator *fakeDispatchCoordinator) claimCount(command DispatchCommand) int {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	key := command.EffectID.String() + ":" + command.ProviderID + ":" + strconv.FormatUint(uint64(command.Attempt), 10)
	if _, found := coordinator.claimed[key]; found {
		return 1
	}
	return 0
}

type emptyProviderStream struct{}

func (emptyProviderStream) Next(context.Context) (ProviderEvent, error) {
	return ProviderEvent{}, io.EOF
}
func (emptyProviderStream) Close() error { return nil }

func mustID(t *testing.T, kind identity.Kind, fill byte) identity.ID {
	t.Helper()
	id, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte{fill}, 16))}).New(kind)
	if err != nil {
		t.Fatalf("identity.New(%s) error = %v", kind, err)
	}
	return id
}

func testDigest(fill byte) Digest {
	var digest Digest
	copy(digest[:], bytes.Repeat([]byte{fill}, len(digest)))
	return digest
}
