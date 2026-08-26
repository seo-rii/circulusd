package platformapi_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/hancomac/circulusd/internal/authority"
	"github.com/hancomac/circulusd/internal/platformapi"
)

const (
	apiTenantID    = "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	apiSubjectID   = "subject_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	otherSubjectID = "subject_AAAAAAAAAAAAAAAAAAAAAAAAAE"
	apiSessionID   = "sess_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	apiTurnID      = "turn_AAAAAAAAAAAAAAAAAAAAAAAAAA"
)

type scopedAuthorizer struct {
	mu         sync.Mutex
	requests   []platformapi.AuthorizationRequest
	err        error
	after      func(platformapi.AuthorizationRequest)
	generation uint64
}

type scopedEventAuthorizer struct {
	mu       sync.Mutex
	requests []platformapi.EventAuthority
	err      error
}

type recordingTurnValidator struct {
	mu      sync.Mutex
	binding authority.ServiceBinding
	request authority.AdmissionRequest
	err     error
}

type incompleteStreamRepository struct {
	*platformapi.MemoryStore
}

func (*incompleteStreamRepository) Durability() platformapi.RepositoryDurability {
	return platformapi.RepositoryDurability{
		CrashDurable: true, AtomicIdempotency: true, AtomicEventSequence: true,
		AtomicAuthorizationFence: true,
	}
}

func (validator *recordingTurnValidator) ValidateAdmission(
	_ context.Context,
	_ authority.TurnAuthority,
	binding authority.ServiceBinding,
	request authority.AdmissionRequest,
) error {
	validator.mu.Lock()
	defer validator.mu.Unlock()
	validator.binding = binding
	validator.request = request
	return validator.err
}

func (authorizer *scopedEventAuthorizer) AuthorizeEvent(
	_ context.Context,
	request platformapi.EventAuthority,
) error {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	authorizer.requests = append(authorizer.requests, request)
	return authorizer.err
}

func (authorizer *scopedAuthorizer) Authorize(
	_ context.Context,
	request platformapi.AuthorizationRequest,
) (platformapi.AuthorizationPermit, error) {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	authorizer.requests = append(authorizer.requests, request)
	generation := authorizer.generation
	if generation == 0 {
		generation = 7
	}
	permit := platformapi.AuthorizationPermit{
		Operation: request.Operation, Principal: request.Principal, SessionID: request.SessionID,
		AuthorizationGeneration: generation, Proof: platformapi.OpaqueAuthorizationProof{1},
	}
	if authorizer.after != nil {
		authorizer.after(request)
	}
	return permit, authorizer.err
}

func newAPIService(t *testing.T, store *platformapi.MemoryStore, authorizer platformapi.Authorizer) *platformapi.Service {
	t.Helper()
	service, err := platformapi.NewService(platformapi.Config{
		Store: store, Authorizer: authorizer, EventAuthorizer: &scopedEventAuthorizer{},
		IdempotencySecret:   []byte(strings.Repeat("i", 32)),
		MaximumMessageBytes: 1024, MaximumEventBytes: 1024, MaximumReplayEvents: 256,
		AllowReferenceMemory: true,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func TestProductionServiceRejectsReferenceMemoryRepository(t *testing.T) {
	_, err := platformapi.NewService(platformapi.Config{
		Store: platformapi.NewMemoryStore(), Authorizer: &scopedAuthorizer{},
		EventAuthorizer:     &scopedEventAuthorizer{},
		IdempotencySecret:   []byte(strings.Repeat("i", 32)),
		MaximumMessageBytes: 1024, MaximumEventBytes: 1024, MaximumReplayEvents: 256,
	})
	if !errors.Is(err, platformapi.ErrRepositoryNotDurable) {
		t.Fatalf("NewService(MemoryStore) error = %v, want ErrRepositoryNotDurable", err)
	}
	capability := platformapi.NewMemoryStore().Durability()
	if capability.CrashDurable || !capability.AtomicIdempotency || !capability.AtomicEventSequence ||
		!capability.AtomicReplaySubscribe || !capability.AtomicAuthorizationFence {
		t.Fatalf("MemoryStore durability = %#v", capability)
	}

	var nilStore *platformapi.MemoryStore
	_, err = platformapi.NewService(platformapi.Config{
		Store: nilStore, Authorizer: &scopedAuthorizer{}, EventAuthorizer: &scopedEventAuthorizer{},
		IdempotencySecret: []byte(strings.Repeat("i", 32)), MaximumMessageBytes: 1024,
		MaximumEventBytes: 1024, MaximumReplayEvents: 256, AllowReferenceMemory: true,
	})
	if !errors.Is(err, platformapi.ErrInvalidConfig) {
		t.Fatalf("NewService(typed nil store) error = %v, want ErrInvalidConfig", err)
	}

	var nilAuthorizer *scopedAuthorizer
	_, err = platformapi.NewService(platformapi.Config{
		Store: platformapi.NewMemoryStore(), Authorizer: nilAuthorizer,
		EventAuthorizer: &scopedEventAuthorizer{}, IdempotencySecret: []byte(strings.Repeat("i", 32)),
		MaximumMessageBytes: 1024, MaximumEventBytes: 1024, MaximumReplayEvents: 256,
		AllowReferenceMemory: true,
	})
	if !errors.Is(err, platformapi.ErrInvalidConfig) {
		t.Fatalf("NewService(typed nil authorizer) error = %v, want ErrInvalidConfig", err)
	}
}

func TestProductionServiceRequiresAtomicReplaySubscription(t *testing.T) {
	_, err := platformapi.NewService(platformapi.Config{
		Store:      &incompleteStreamRepository{MemoryStore: platformapi.NewMemoryStore()},
		Authorizer: &scopedAuthorizer{}, EventAuthorizer: &scopedEventAuthorizer{},
		IdempotencySecret: []byte(strings.Repeat("i", 32)), MaximumMessageBytes: 1024,
		MaximumEventBytes: 1024, MaximumReplayEvents: 256,
	})
	if !errors.Is(err, platformapi.ErrRepositoryNotDurable) {
		t.Fatalf("NewService(non-atomic replay subscription) error = %v, want ErrRepositoryNotDurable", err)
	}
}

func eventAuthority(turnID string) platformapi.EventAuthority {
	return platformapi.EventAuthority{
		Scope: authority.Scope{
			TenantID: apiTenantID, UserID: apiSubjectID, SessionID: apiSessionID,
			TurnID: turnID, RuntimeRevision: "runtime_AAAAAAAAAAAAAAAAAAAAAAAAAA",
			WorkspaceID: "ws_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		PlacementGeneration: 4, AuthorizationGeneration: 7,
	}
}

func registerAPISession(t *testing.T, store *platformapi.MemoryStore) {
	t.Helper()
	if err := store.RegisterSession(context.Background(), platformapi.SessionRegistration{
		TenantID: apiTenantID, SubjectID: apiSubjectID, SessionID: apiSessionID,
		RuntimeRevision:     "runtime_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		WorkspaceID:         "ws_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		PlacementGeneration: 4, AuthorizationGeneration: 7,
	}); err != nil {
		t.Fatalf("RegisterSession() error = %v", err)
	}
}

func TestConcurrentCreateTurnConvergesAndConflictingBodyIsRejected(t *testing.T) {
	ctx := context.Background()
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	service := newAPIService(t, store, &scopedAuthorizer{})
	request := platformapi.CreateTurnRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, IdempotencyKey: "client-key",
		Messages: []platformapi.Message{{Role: "user", Content: "explain the invariant"}},
	}

	const workers = 64
	type result struct {
		value platformapi.CreateTurnResult
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, workers)
	for range workers {
		go func() {
			<-start
			value, err := service.CreateTurn(ctx, request)
			results <- result{value: value, err: err}
		}()
	}
	close(start)
	turnIDs := make(map[string]struct{})
	created := 0
	for range workers {
		result := <-results
		if result.err != nil {
			t.Fatalf("CreateTurn() error = %v", result.err)
		}
		turnIDs[result.value.Turn.ID] = struct{}{}
		if !result.value.Deduplicated {
			created++
		}
	}
	if len(turnIDs) != 1 || created != 1 {
		t.Fatalf("turn IDs/created = %v/%d, want one durable turn and one creator", turnIDs, created)
	}

	conflicting := request
	conflicting.Messages = []platformapi.Message{{Role: "user", Content: "different body"}}
	if _, err := service.CreateTurn(ctx, conflicting); !errors.Is(err, platformapi.ErrIdempotencyConflict) {
		t.Fatalf("CreateTurn(conflicting body) error = %v, want ErrIdempotencyConflict", err)
	}
	if count := store.TurnCount(apiTenantID, apiSessionID); count != 1 {
		t.Fatalf("TurnCount() = %d after conflict, want 1", count)
	}
}

func TestAuthorizationRunsBeforeMissingSessionLookup(t *testing.T) {
	authorizer := &scopedAuthorizer{err: errors.New("denied")}
	service := newAPIService(t, platformapi.NewMemoryStore(), authorizer)
	_, err := service.CreateTurn(context.Background(), platformapi.CreateTurnRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, IdempotencyKey: "denied-key",
		Messages: []platformapi.Message{{Role: "user", Content: "private"}},
	})
	if !errors.Is(err, platformapi.ErrAccessDenied) {
		t.Fatalf("CreateTurn(denied missing session) error = %v, want ErrAccessDenied", err)
	}
	if len(authorizer.requests) != 1 || authorizer.requests[0].Operation != platformapi.OperationCreateTurn {
		t.Fatalf("authorization requests = %#v", authorizer.requests)
	}
}

func TestRepositoryRejectsCrossSubjectTurnInjection(t *testing.T) {
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	service := newAPIService(t, store, &scopedAuthorizer{})
	_, err := service.CreateTurn(context.Background(), platformapi.CreateTurnRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: otherSubjectID},
		SessionID: apiSessionID, IdempotencyKey: "cross-subject",
		Messages: []platformapi.Message{{Role: "user", Content: "inject"}},
	})
	if !errors.Is(err, platformapi.ErrAccessDenied) {
		t.Fatalf("CreateTurn(cross subject) error = %v, want ErrAccessDenied", err)
	}
	if count := store.TurnCount(apiTenantID, apiSessionID); count != 0 {
		t.Fatalf("TurnCount() = %d after rejected cross-subject request, want 0", count)
	}
	_, err = service.ReplayEvents(context.Background(), platformapi.ReplayEventsRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: otherSubjectID},
		SessionID: apiSessionID,
	})
	if !errors.Is(err, platformapi.ErrAccessDenied) {
		t.Fatalf("ReplayEvents(cross subject) error = %v, want ErrAccessDenied", err)
	}
}

func TestCreateTurnRejectsAuthorizationRevokedBetweenCheckAndCommit(t *testing.T) {
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	authorizer := &scopedAuthorizer{after: func(platformapi.AuthorizationRequest) {
		if err := store.RotateAuthorizationGeneration(
			context.Background(), apiTenantID, apiSubjectID, apiSessionID, 7, 8,
		); err != nil {
			t.Errorf("RotateAuthorizationGeneration() error = %v", err)
		}
	}}
	service := newAPIService(t, store, authorizer)
	_, err := service.CreateTurn(context.Background(), platformapi.CreateTurnRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, IdempotencyKey: "revoked-during-admission",
		Messages: []platformapi.Message{{Role: "user", Content: "must not commit"}},
	})
	if !errors.Is(err, platformapi.ErrAccessDenied) {
		t.Fatalf("CreateTurn(revoked admission) error = %v, want ErrAccessDenied", err)
	}
	if count := store.TurnCount(apiTenantID, apiSessionID); count != 0 {
		t.Fatalf("TurnCount() = %d after revoked admission, want 0", count)
	}
}

func TestAuthorityEventAuthorizerUsesExactEventBindingAndScope(t *testing.T) {
	validator := &recordingTurnValidator{}
	authorizer, err := platformapi.NewAuthorityEventAuthorizer(validator)
	if err != nil {
		t.Fatalf("NewAuthorityEventAuthorizer() error = %v", err)
	}
	request := eventAuthority(apiTurnID)
	if err := authorizer.AuthorizeEvent(context.Background(), request); err != nil {
		t.Fatalf("AuthorizeEvent() error = %v", err)
	}
	if validator.binding != authority.BindingEvents || validator.request.Scope != request.Scope ||
		validator.request.Permission != authority.Permission("events.append") {
		t.Fatalf("validator binding/request = %q/%#v", validator.binding, validator.request)
	}
	validator.err = errors.New("forged credential details")
	if err := authorizer.AuthorizeEvent(context.Background(), request); err == nil ||
		strings.Contains(err.Error(), "forged credential details") {
		t.Fatalf("AuthorizeEvent(dependency error) = %v, want redacted denial", err)
	}
	if _, err := platformapi.NewAuthorityEventAuthorizer(nil); !errors.Is(err, platformapi.ErrInvalidConfig) {
		t.Fatalf("NewAuthorityEventAuthorizer(nil) error = %v, want ErrInvalidConfig", err)
	}
	var typedNilValidator *recordingTurnValidator
	if _, err := platformapi.NewAuthorityEventAuthorizer(typedNilValidator); !errors.Is(err, platformapi.ErrInvalidConfig) {
		t.Fatalf("NewAuthorityEventAuthorizer(typed nil) error = %v, want ErrInvalidConfig", err)
	}
}

func TestDurableEventAppendIsFencedIdempotentAndReplayable(t *testing.T) {
	ctx := context.Background()
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	service := newAPIService(t, store, &scopedAuthorizer{})
	created, err := service.CreateTurn(ctx, platformapi.CreateTurnRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, IdempotencyKey: "event-turn",
		Messages: []platformapi.Message{{Role: "user", Content: "run"}},
	})
	if err != nil {
		t.Fatalf("CreateTurn() error = %v", err)
	}
	authority := eventAuthority(created.Turn.ID)
	acceptedRequest := platformapi.AppendDurableEventRequest{
		Authority: authority, CommandID: "op_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		ExpectedSequence: 0, Type: platformapi.EventTurnAccepted,
		Payload: []byte(`{"state":"accepted"}`), TurnStatus: platformapi.TurnActive,
	}
	accepted, replayed, err := service.AppendDurableEvent(ctx, acceptedRequest)
	if err != nil || replayed || accepted.Sequence != 1 {
		t.Fatalf("AppendDurableEvent() = %#v, %t, %v", accepted, replayed, err)
	}
	replayedAccepted, replayed, err := service.AppendDurableEvent(ctx, acceptedRequest)
	if err != nil || !replayed || replayedAccepted != accepted {
		t.Fatalf("AppendDurableEvent(replay) = %#v, %t, %v", replayedAccepted, replayed, err)
	}
	conflict := acceptedRequest
	conflict.Payload = []byte(`{"state":"different"}`)
	if _, _, err := service.AppendDurableEvent(ctx, conflict); !errors.Is(err, platformapi.ErrIdempotencyConflict) {
		t.Fatalf("AppendDurableEvent(command conflict) error = %v", err)
	}
	stale := acceptedRequest
	stale.CommandID = "op_AAAAAAAAAAAAAAAAAAAAAAAAAE"
	stale.ExpectedSequence = 1
	stale.Authority.PlacementGeneration--
	if _, _, err := service.AppendDurableEvent(ctx, stale); !errors.Is(err, platformapi.ErrStaleAuthority) {
		t.Fatalf("AppendDurableEvent(stale placement) error = %v", err)
	}

	delta, err := service.PublishEphemeralEvent(ctx, platformapi.EphemeralEventRequest{
		Authority: authority, Type: platformapi.EventModelDelta, Payload: []byte("partial"),
	})
	if err != nil || delta.Sequence != 0 || delta.Durable {
		t.Fatalf("PublishEphemeralEvent() = %#v, %v", delta, err)
	}
	completed, replayed, err := service.AppendDurableEvent(ctx, platformapi.AppendDurableEventRequest{
		Authority: authority, CommandID: "op_AAAAAAAAAAAAAAAAAAAAAAAAAI",
		ExpectedSequence: 1, Type: platformapi.EventTurnCompleted,
		Payload: []byte(`{"state":"completed"}`), TurnStatus: platformapi.TurnCompleted,
	})
	if err != nil || replayed || completed.Sequence != 2 {
		t.Fatalf("AppendDurableEvent(completed) = %#v, %t, %v", completed, replayed, err)
	}

	replay, err := service.ReplayEvents(ctx, platformapi.ReplayEventsRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, AfterSequence: 0, Limit: 10,
	})
	if err != nil {
		t.Fatalf("ReplayEvents() error = %v", err)
	}
	if replay.Snapshot.LastDurableSequence != 2 || replay.Snapshot.ActiveTurnID != created.Turn.ID ||
		replay.Snapshot.TurnStatus != platformapi.TurnCompleted || len(replay.Events) != 2 ||
		replay.Events[0].Sequence != 1 || replay.Events[1].Sequence != 2 {
		t.Fatalf("ReplayEvents() = %#v", replay)
	}
	afterFirst, err := service.ReplayEvents(ctx, platformapi.ReplayEventsRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, AfterSequence: 1, Limit: 10,
	})
	if err != nil || len(afterFirst.Events) != 1 || afterFirst.Events[0].Sequence != 2 {
		t.Fatalf("ReplayEvents(after 1) = %#v, %v", afterFirst, err)
	}
	if _, err := service.ReplayEvents(ctx, platformapi.ReplayEventsRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, AfterSequence: 3, Limit: 10,
	}); !errors.Is(err, platformapi.ErrInvalidCursor) {
		t.Fatalf("ReplayEvents(future cursor) error = %v, want ErrInvalidCursor", err)
	}
}

func TestEventAuthorizationPrecedesRepositoryLookup(t *testing.T) {
	eventAuthorizer := &scopedEventAuthorizer{err: errors.New("stale signed authority")}
	service, err := platformapi.NewService(platformapi.Config{
		Store: platformapi.NewMemoryStore(), Authorizer: &scopedAuthorizer{},
		EventAuthorizer:     eventAuthorizer,
		IdempotencySecret:   []byte(strings.Repeat("i", 32)),
		MaximumMessageBytes: 1024, MaximumEventBytes: 1024, MaximumReplayEvents: 256,
		AllowReferenceMemory: true,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	_, _, err = service.AppendDurableEvent(context.Background(), platformapi.AppendDurableEventRequest{
		Authority: eventAuthority(apiTurnID), CommandID: "op_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		Type: platformapi.EventTurnAccepted, Payload: []byte(`{"state":"accepted"}`),
		TurnStatus: platformapi.TurnActive,
	})
	if !errors.Is(err, platformapi.ErrStaleAuthority) {
		t.Fatalf("AppendDurableEvent(denied missing session) error = %v, want ErrStaleAuthority", err)
	}
	if len(eventAuthorizer.requests) != 1 {
		t.Fatalf("event authorization requests = %d, want 1", len(eventAuthorizer.requests))
	}
}

func TestConcurrentDurableAppendHasOneSequenceWinner(t *testing.T) {
	ctx := context.Background()
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	service := newAPIService(t, store, &scopedAuthorizer{})
	created, err := service.CreateTurn(ctx, platformapi.CreateTurnRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, IdempotencyKey: "race-turn",
		Messages: []platformapi.Message{{Role: "user", Content: "race"}},
	})
	if err != nil {
		t.Fatalf("CreateTurn() error = %v", err)
	}
	authority := eventAuthority(created.Turn.ID)

	const workers = 64
	start := make(chan struct{})
	errorsByWriter := make(chan error, workers)
	for index := range workers {
		go func() {
			<-start
			alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
			commandID := "op_" + strings.Repeat("A", 23) +
				string([]byte{alphabet[index/32], alphabet[index%32]}) + "A"
			_, _, err := service.AppendDurableEvent(ctx, platformapi.AppendDurableEventRequest{
				Authority:        authority,
				CommandID:        commandID,
				ExpectedSequence: 0, Type: platformapi.EventTurnAccepted,
				Payload: []byte(fmt.Sprintf(`{"writer":%d}`, index)), TurnStatus: platformapi.TurnActive,
			})
			errorsByWriter <- err
		}()
	}
	close(start)
	succeeded := 0
	conflicted := 0
	for range workers {
		switch err := <-errorsByWriter; {
		case err == nil:
			succeeded++
		case errors.Is(err, platformapi.ErrSequenceConflict):
			conflicted++
		default:
			t.Fatalf("AppendDurableEvent(concurrent) error = %v", err)
		}
	}
	if succeeded != 1 || conflicted != workers-1 {
		t.Fatalf("append success/conflict = %d/%d, want 1/%d", succeeded, conflicted, workers-1)
	}
}
