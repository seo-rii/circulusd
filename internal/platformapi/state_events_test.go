package platformapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/hancomac/circulusd/internal/dependency"
	dependencycontract "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/platformapi"
)

const (
	stateEventTenantID  = "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	stateEventSubjectID = "subject_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	stateEventSessionID = "sess_AAAAAAAAAAAAAAAAAAAAAAAAAA"
)

var stateEventPrincipal = platformapi.Principal{
	TenantID:  stateEventTenantID,
	SubjectID: stateEventSubjectID,
}

type stateEventAuthorizer struct {
	mu      sync.Mutex
	permit  platformapi.AuthorizationPermit
	err     error
	request platformapi.AuthorizationRequest
	calls   int
}

func (authorizer *stateEventAuthorizer) Authorize(
	_ context.Context,
	request platformapi.AuthorizationRequest,
) (platformapi.AuthorizationPermit, error) {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	authorizer.request = request
	authorizer.calls++
	if authorizer.permit == (platformapi.AuthorizationPermit{}) {
		return stateEventPermit(7), authorizer.err
	}
	return authorizer.permit, authorizer.err
}

type stateEventReader struct {
	mu      sync.Mutex
	page    platformapi.SessionPublicEventPage
	err     error
	request platformapi.AuthorizedSessionEventPageRequest
	calls   int
}

type stateEventPageReader interface {
	ReadSessionEventPage(
		context.Context,
		platformapi.AuthorizedSessionEventPageRequest,
	) (platformapi.SessionPublicEventPage, error)
}

type productionStateEventPageReader struct {
	*dependencycontract.ProductionProofs
	reader stateEventPageReader
}

func (reader *productionStateEventPageReader) ReadSessionEventPage(
	ctx context.Context,
	request platformapi.AuthorizedSessionEventPageRequest,
) (platformapi.SessionPublicEventPage, error) {
	return reader.reader.ReadSessionEventPage(ctx, request)
}

func (reader *stateEventReader) ReadSessionEventPage(
	_ context.Context,
	request platformapi.AuthorizedSessionEventPageRequest,
) (platformapi.SessionPublicEventPage, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.request = request
	reader.calls++
	return reader.page, reader.err
}

func stateEventPermit(generation uint64) platformapi.AuthorizationPermit {
	return platformapi.AuthorizationPermit{
		Operation:               platformapi.OperationReadEvents,
		Principal:               stateEventPrincipal,
		SessionID:               stateEventSessionID,
		AuthorizationGeneration: generation,
		Proof:                   platformapi.OpaqueAuthorizationProof{1, 2, 3},
	}
}

func emptyStateEventPage() platformapi.SessionPublicEventPage {
	return platformapi.SessionPublicEventPage{
		Snapshot: platformapi.SessionPublicEventSnapshot{
			SessionID: stateEventSessionID,
		},
	}
}

func stateEventRequest(after uint64, limit int) platformapi.ReadSessionEventPageRequest {
	return platformapi.ReadSessionEventPageRequest{
		Principal:     stateEventPrincipal,
		SessionID:     stateEventSessionID,
		AfterSequence: after,
		Limit:         limit,
	}
}

func newStateEventService(
	t *testing.T,
	reader stateEventPageReader,
	authorizer platformapi.Authorizer,
) *platformapi.SessionEventService {
	t.Helper()
	groups := []dependency.AtomicGroup{
		dependency.AtomicCommandReceipt,
		dependency.AtomicEffectLifecycle,
	}
	proofs := dependencycontract.NewProductionProofs(t, groups)
	verified := dependencycontract.Verify[platformapi.SessionEventPageReader](
		t,
		proofs,
		&productionStateEventPageReader{ProductionProofs: proofs, reader: reader},
		groups,
	)
	service, err := platformapi.NewSessionEventService(platformapi.SessionEventServiceConfig{
		Reader: verified, Authorizer: authorizer, MaximumPageEvents: 16,
	})
	if err != nil {
		t.Fatalf("NewSessionEventService() error = %v", err)
	}
	return service
}

func TestSessionEventServiceConfigRequiresVerifiedProductionReader(t *testing.T) {
	t.Parallel()

	field, ok := reflect.TypeOf(platformapi.SessionEventServiceConfig{}).FieldByName("Reader")
	want := reflect.TypeOf(dependency.Verified[platformapi.SessionEventPageReader]{})
	if !ok || field.Type != want {
		t.Fatalf("SessionEventServiceConfig.Reader = %v, want %v", field.Type, want)
	}
}

func TestSessionEventServiceRejectsUnverifiedOrInsufficientAtomicDomainBeforeCalls(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		verified func(*testing.T, stateEventPageReader) dependency.Verified[platformapi.SessionEventPageReader]
	}{
		{
			name: "zero seal",
			verified: func(*testing.T, stateEventPageReader) dependency.Verified[platformapi.SessionEventPageReader] {
				return dependency.Verified[platformapi.SessionEventPageReader]{}
			},
		},
		{
			name: "command receipt without effect lifecycle",
			verified: func(t *testing.T, reader stateEventPageReader) dependency.Verified[platformapi.SessionEventPageReader] {
				groups := []dependency.AtomicGroup{dependency.AtomicCommandReceipt}
				proofs := dependencycontract.NewProductionProofs(t, groups)
				return dependencycontract.Verify[platformapi.SessionEventPageReader](
					t,
					proofs,
					&productionStateEventPageReader{ProductionProofs: proofs, reader: reader},
					groups,
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			reader := &stateEventReader{}
			authorizer := &stateEventAuthorizer{}
			service, err := platformapi.NewSessionEventService(platformapi.SessionEventServiceConfig{
				Reader: test.verified(t, reader), Authorizer: authorizer, MaximumPageEvents: 16,
			})
			if service != nil || !errors.Is(err, platformapi.ErrRepositoryNotDurable) {
				t.Fatalf("NewSessionEventService() = (%#v, %v), want nil/ErrRepositoryNotDurable", service, err)
			}
			if authorizer.calls != 0 || reader.calls != 0 {
				t.Fatalf("constructor dependency calls = authorize:%d read:%d, want zero", authorizer.calls, reader.calls)
			}
		})
	}
}

func TestSessionEventServiceRejectsInvalidConfigBeforeOpeningReader(t *testing.T) {
	t.Parallel()

	var zero dependency.Verified[platformapi.SessionEventPageReader]

	var nilAuthorizer *stateEventAuthorizer
	_, err := platformapi.NewSessionEventService(platformapi.SessionEventServiceConfig{
		Reader:     zero,
		Authorizer: nilAuthorizer, MaximumPageEvents: 16,
	})
	if !errors.Is(err, platformapi.ErrInvalidConfig) {
		t.Fatalf("NewSessionEventService(typed nil authorizer) error = %v, want ErrInvalidConfig", err)
	}
	for _, maximum := range []int{0, 257} {
		_, err = platformapi.NewSessionEventService(platformapi.SessionEventServiceConfig{
			Reader: zero, Authorizer: &stateEventAuthorizer{}, MaximumPageEvents: maximum,
		})
		if !errors.Is(err, platformapi.ErrInvalidConfig) {
			t.Fatalf("NewSessionEventService(maximum %d) error = %v, want ErrInvalidConfig", maximum, err)
		}
	}
}

func TestSessionEventPageAuthorizationIsExactAndRefencedAgainByReader(t *testing.T) {
	t.Parallel()
	permit := stateEventPermit(41)
	authorizer := &stateEventAuthorizer{permit: permit}
	reader := &stateEventReader{
		page: emptyStateEventPage(),
	}
	service := newStateEventService(t, reader, authorizer)

	page, err := service.ReadSessionEventPage(context.Background(), stateEventRequest(0, 0))
	if err != nil {
		t.Fatalf("ReadSessionEventPage() error = %v", err)
	}
	if page.Snapshot.SessionID != stateEventSessionID || len(page.Events) != 0 {
		t.Fatalf("ReadSessionEventPage() = %#v", page)
	}
	wantAuthorizationRequest := platformapi.AuthorizationRequest{
		Operation: platformapi.OperationReadEvents,
		Principal: stateEventPrincipal,
		SessionID: stateEventSessionID,
	}
	if authorizer.request != wantAuthorizationRequest || authorizer.calls != 1 {
		t.Fatalf("authorizer request/calls = %#v/%d", authorizer.request, authorizer.calls)
	}
	if reader.request.Authorization != permit ||
		reader.request.SessionID != stateEventSessionID ||
		reader.request.AfterSequence != 0 || reader.request.Limit != 16 || reader.calls != 1 {
		t.Fatalf("reader request/calls = %#v/%d", reader.request, reader.calls)
	}
}

func TestSessionPublicEventPageJSONShapeMatchesStateApp(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		page    platformapi.SessionPublicEventPage
		request platformapi.ReadSessionEventPageRequest
		want    string
	}{
		"null snapshot and empty page": {
			page: emptyStateEventPage(), request: stateEventRequest(0, 1),
			want: `{"snapshot":{"sessionId":"sess_AAAAAAAAAAAAAAAAAAAAAAAAAA","activeTurnId":null,"turnStatus":null,"lastEventSequence":0},"events":[]}`,
		},
		"event discriminant omits other family metadata": {
			page: platformapi.SessionPublicEventPage{
				Snapshot: platformapi.SessionPublicEventSnapshot{
					SessionID: stateEventSessionID, LastEventSequence: 1,
				},
				Events: []platformapi.SessionPublicEvent{acceptedStateEvent(1, "turn-one", 0)},
			},
			request: stateEventRequest(0, 1),
			want:    `{"snapshot":{"sessionId":"sess_AAAAAAAAAAAAAAAAAAAAAAAAAA","activeTurnId":null,"turnStatus":null,"lastEventSequence":1},"events":[{"sequence":1,"type":"turn.accepted","turnId":"turn-one","turnSequence":0,"status":"active"}]}`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			reader := &stateEventReader{page: test.page}
			service := newStateEventService(t, reader, &stateEventAuthorizer{})
			result, err := service.ReadSessionEventPage(context.Background(), test.request)
			if err != nil {
				t.Fatalf("ReadSessionEventPage() error = %v", err)
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			if string(encoded) != test.want {
				t.Fatalf("json.Marshal() = %s, want %s", encoded, test.want)
			}
		})
	}
}

func TestSessionEventPageRejectsForgedAuthorizationBeforeReader(t *testing.T) {
	t.Parallel()
	valid := stateEventPermit(7)
	for name, mutate := range map[string]func(*platformapi.AuthorizationPermit){
		"operation": func(permit *platformapi.AuthorizationPermit) {
			permit.Operation = platformapi.OperationCreateTurn
		},
		"principal": func(permit *platformapi.AuthorizationPermit) {
			permit.Principal.SubjectID = "subject_AAAAAAAAAAAAAAAAAAAAAAAAAE"
		},
		"session": func(permit *platformapi.AuthorizationPermit) {
			permit.SessionID = "sess_AAAAAAAAAAAAAAAAAAAAAAAAAE"
		},
		"zero generation": func(permit *platformapi.AuthorizationPermit) {
			permit.AuthorizationGeneration = 0
		},
		"unsafe generation": func(permit *platformapi.AuthorizationPermit) {
			permit.AuthorizationGeneration = 9_007_199_254_740_992
		},
		"empty proof": func(permit *platformapi.AuthorizationPermit) {
			permit.Proof = platformapi.OpaqueAuthorizationProof{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			forged := valid
			mutate(&forged)
			reader := &stateEventReader{page: emptyStateEventPage()}
			service := newStateEventService(t, reader, &stateEventAuthorizer{permit: forged})
			_, err := service.ReadSessionEventPage(context.Background(), stateEventRequest(0, 1))
			if !errors.Is(err, platformapi.ErrAccessDenied) {
				t.Fatalf("ReadSessionEventPage() error = %v, want ErrAccessDenied", err)
			}
			if reader.calls != 0 {
				t.Fatalf("reader calls = %d after forged permit, want 0", reader.calls)
			}
		})
	}
}

func TestSessionEventPageMapsReaderErrorsWithoutLeakingInternals(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		readerError error
		want        error
	}{
		"stale generation": {readerError: platformapi.ErrStaleAuthority, want: platformapi.ErrStaleAuthority},
		"access revoked":   {readerError: platformapi.ErrAccessDenied, want: platformapi.ErrAccessDenied},
		"missing session":  {readerError: platformapi.ErrSessionNotFound, want: platformapi.ErrSessionNotFound},
		"invalid cursor":   {readerError: platformapi.ErrInvalidCursor, want: platformapi.ErrInvalidCursor},
		"internal":         {readerError: errors.New("sqlite page 71 contains private state"), want: platformapi.ErrRepositoryFailure},
		"unrelated typed error": {
			readerError: platformapi.ErrIdempotencyConflict, want: platformapi.ErrRepositoryFailure,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			reader := &stateEventReader{err: test.readerError}
			service := newStateEventService(t, reader, &stateEventAuthorizer{})
			_, err := service.ReadSessionEventPage(context.Background(), stateEventRequest(0, 1))
			if !errors.Is(err, test.want) {
				t.Fatalf("ReadSessionEventPage() error = %v, want %v", err, test.want)
			}
			if test.want == platformapi.ErrRepositoryFailure && strings.Contains(err.Error(), "sqlite") {
				t.Fatalf("ReadSessionEventPage() leaked reader detail: %v", err)
			}
		})
	}
}

func TestSessionEventPageValidatesInputAndResponseBounds(t *testing.T) {
	t.Parallel()
	validReader := func() *stateEventReader {
		return &stateEventReader{page: emptyStateEventPage()}
	}
	for name, request := range map[string]platformapi.ReadSessionEventPageRequest{
		"invalid principal": {
			Principal: platformapi.Principal{}, SessionID: stateEventSessionID, Limit: 1,
		},
		"invalid session": {
			Principal: stateEventPrincipal, SessionID: "not-a-session", Limit: 1,
		},
		"unsafe cursor":   stateEventRequest(9_007_199_254_740_992, 1),
		"negative limit":  stateEventRequest(0, -1),
		"excessive limit": stateEventRequest(0, 17),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			reader := validReader()
			service := newStateEventService(t, reader, &stateEventAuthorizer{})
			_, err := service.ReadSessionEventPage(context.Background(), request)
			if !errors.Is(err, platformapi.ErrInvalidRequest) {
				t.Fatalf("ReadSessionEventPage() error = %v, want ErrInvalidRequest", err)
			}
			if reader.calls != 0 {
				t.Fatalf("reader calls = %d after invalid input, want 0", reader.calls)
			}
		})
	}

	validAccepted := acceptedStateEvent(1, "turn-one", 0)
	for name, page := range map[string]platformapi.SessionPublicEventPage{
		"cross session": {
			Snapshot: platformapi.SessionPublicEventSnapshot{SessionID: "sess_AAAAAAAAAAAAAAAAAAAAAAAAAE"},
		},
		"cursor ahead of snapshot": {
			Snapshot: platformapi.SessionPublicEventSnapshot{SessionID: stateEventSessionID, LastEventSequence: 0},
		},
		"underfilled page": {
			Snapshot: platformapi.SessionPublicEventSnapshot{SessionID: stateEventSessionID, LastEventSequence: 2},
			Events:   []platformapi.SessionPublicEvent{validAccepted},
		},
		"too many events": {
			Snapshot: platformapi.SessionPublicEventSnapshot{SessionID: stateEventSessionID, LastEventSequence: 2},
			Events:   []platformapi.SessionPublicEvent{validAccepted, acceptedStateEvent(2, "turn-two", 1)},
		},
		"sequence overlap": {
			Snapshot: platformapi.SessionPublicEventSnapshot{SessionID: stateEventSessionID, LastEventSequence: 2},
			Events:   []platformapi.SessionPublicEvent{validAccepted},
		},
		"sequence gap": {
			Snapshot: platformapi.SessionPublicEventSnapshot{SessionID: stateEventSessionID, LastEventSequence: 2},
			Events:   []platformapi.SessionPublicEvent{acceptedStateEvent(2, "turn-two", 1)},
		},
		"event ahead of snapshot": {
			Snapshot: platformapi.SessionPublicEventSnapshot{SessionID: stateEventSessionID, LastEventSequence: 1},
			Events:   []platformapi.SessionPublicEvent{acceptedStateEvent(2, "turn-two", 1)},
		},
		"active snapshot names terminal turn": {
			Snapshot: platformapi.SessionPublicEventSnapshot{
				SessionID: stateEventSessionID, ActiveTurnID: stateEventString("turn-one"),
				TurnStatus: stateEventTurnStatus(platformapi.TurnActive), LastEventSequence: 2,
			},
			Events: []platformapi.SessionPublicEvent{
				validAccepted,
				{Sequence: 2, Type: platformapi.EventTurnCompleted, TurnID: "turn-one"},
			},
		},
		"caught-up active snapshot lacks admission": {
			Snapshot: platformapi.SessionPublicEventSnapshot{
				SessionID: stateEventSessionID, ActiveTurnID: stateEventString("turn-two"),
				TurnStatus: stateEventTurnStatus(platformapi.TurnActive), LastEventSequence: 1,
			},
			Events: []platformapi.SessionPublicEvent{validAccepted},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := stateEventRequest(0, 1)
			switch name {
			case "cursor ahead of snapshot":
				request.AfterSequence = 1
			case "underfilled page", "active snapshot names terminal turn":
				request.Limit = 2
			case "too many events":
				request.Limit = 1
			case "sequence overlap":
				request.AfterSequence = 1
			}
			reader := &stateEventReader{page: page}
			service := newStateEventService(t, reader, &stateEventAuthorizer{})
			_, err := service.ReadSessionEventPage(context.Background(), request)
			if !errors.Is(err, platformapi.ErrRepositoryFailure) {
				t.Fatalf("ReadSessionEventPage() error = %v, want ErrRepositoryFailure", err)
			}
		})
	}
}

func TestSessionEventPageValidatesSnapshotAndEveryEventFamily(t *testing.T) {
	t.Parallel()
	page := platformapi.SessionPublicEventPage{
		Snapshot: platformapi.SessionPublicEventSnapshot{
			SessionID: stateEventSessionID, LastEventSequence: 7,
		},
		Events: []platformapi.SessionPublicEvent{
			acceptedStateEvent(1, "turn-one", 0),
			effectStateEvent(2, platformapi.EventModelEffectPrepared, "turn-one", 0, "effect-model", "inv-model", platformapi.SessionEffectModel),
			settledStateEvent(3, platformapi.EventModelSettled, "turn-one", 0, "effect-model", "inv-model", platformapi.SessionEffectModel),
			effectStateEvent(4, platformapi.EventToolEffectPrepared, "turn-one", 0, "effect-tool", "inv-tool", platformapi.SessionEffectExecutor),
			{
				Sequence: 5, Type: platformapi.EventToolExternallyCommit,
				TurnID: "turn-one", TurnSequence: 0, EffectID: "effect-tool",
				InvocationID: "inv-tool", Service: platformapi.SessionEffectExecutor,
				Operation: "execute", ExternalCommitID: "commit-tool", ResultRef: "result-tool",
			},
			settledStateEvent(6, platformapi.EventToolSettled, "turn-one", 0, "effect-tool", "inv-tool", platformapi.SessionEffectExecutor),
			{Sequence: 7, Type: platformapi.EventTurnCompleted, TurnID: "turn-one", TurnSequence: 0},
		},
	}
	reader := &stateEventReader{page: page}
	service := newStateEventService(t, reader, &stateEventAuthorizer{})
	got, err := service.ReadSessionEventPage(context.Background(), stateEventRequest(0, 16))
	if err != nil {
		t.Fatalf("ReadSessionEventPage() error = %v", err)
	}
	if len(got.Events) != 7 || got.Events[4].ExternalCommitID != "commit-tool" {
		t.Fatalf("ReadSessionEventPage() = %#v", got)
	}

	active := emptyStateEventPage()
	active.Snapshot.ActiveTurnID = stateEventString("turn-active")
	active.Snapshot.TurnStatus = stateEventTurnStatus(platformapi.TurnActive)
	reader.page = active
	if _, err := service.ReadSessionEventPage(context.Background(), stateEventRequest(0, 1)); !errors.Is(err, platformapi.ErrRepositoryFailure) {
		t.Fatalf("ReadSessionEventPage(active snapshot without journal) error = %v, want ErrRepositoryFailure", err)
	}
}

func TestSessionEventPageRejectsMalformedFamilyMetadataAndCausality(t *testing.T) {
	t.Parallel()
	accepted := acceptedStateEvent(1, "turn-one", 0)
	prepared := effectStateEvent(2, platformapi.EventToolEffectPrepared, "turn-one", 0, "effect-one", "inv-one", platformapi.SessionEffectExecutor)
	terminal := platformapi.SessionPublicEvent{
		Sequence: 2, Type: platformapi.EventTurnCompleted, TurnID: "turn-one", TurnSequence: 0,
	}
	for name, events := range map[string][]platformapi.SessionPublicEvent{
		"accepted missing status": {
			{Sequence: 1, Type: platformapi.EventTurnAccepted, TurnID: "turn-one"},
		},
		"accepted has effect metadata": {
			func() platformapi.SessionPublicEvent { event := accepted; event.EffectID = "effect-one"; return event }(),
		},
		"effect missing metadata": {
			accepted, {Sequence: 2, Type: platformapi.EventToolEffectPrepared, TurnID: "turn-one"},
		},
		"model family with tool service": {
			accepted, effectStateEvent(2, platformapi.EventModelEffectPrepared, "turn-one", 0, "effect-one", "inv-one", platformapi.SessionEffectExecutor),
		},
		"tool family with model service": {
			accepted, effectStateEvent(2, platformapi.EventToolEffectPrepared, "turn-one", 0, "effect-one", "inv-one", platformapi.SessionEffectModel),
		},
		"external commit missing refs": {
			accepted, prepared, {
				Sequence: 3, Type: platformapi.EventToolExternallyCommit, TurnID: "turn-one",
				EffectID: "effect-one", InvocationID: "inv-one",
				Service: platformapi.SessionEffectExecutor, Operation: "execute",
			},
		},
		"settled missing kind": {
			accepted, prepared, func() platformapi.SessionPublicEvent {
				event := settledStateEvent(3, platformapi.EventToolSettled, "turn-one", 0, "effect-one", "inv-one", platformapi.SessionEffectExecutor)
				event.SettlementKind = ""
				return event
			}(),
		},
		"later event before accepted": {
			effectStateEvent(1, platformapi.EventToolEffectPrepared, "turn-one", 0, "effect-one", "inv-one", platformapi.SessionEffectExecutor),
			func() platformapi.SessionPublicEvent { event := accepted; event.Sequence = 2; return event }(),
		},
		"terminal before later event": {
			accepted, terminal, func() platformapi.SessionPublicEvent { event := prepared; event.Sequence = 3; return event }(),
		},
		"terminal with unsettled effect": {
			accepted, prepared,
			{Sequence: 3, Type: platformapi.EventTurnFailed, TurnID: "turn-one"},
		},
		"multiple in-flight effects": {
			accepted, prepared,
			effectStateEvent(3, platformapi.EventModelEffectPrepared, "turn-one", 0, "effect-two", "inv-two", platformapi.SessionEffectModel),
		},
		"turn sequence changes": {
			accepted, func() platformapi.SessionPublicEvent { event := prepared; event.TurnSequence = 1; return event }(),
		},
		"turn sequence reused": {
			accepted, acceptedStateEvent(2, "turn-two", 0),
		},
		"accepted turn sequence moves backward": {
			acceptedStateEvent(1, "turn-one", 10),
			func() platformapi.SessionPublicEvent {
				event := acceptedStateEvent(2, "turn-two", 5)
				event.Status = platformapi.TurnQueued
				return event
			}(),
		},
		"invocation reused by another effect": {
			accepted,
			effectStateEvent(2, platformapi.EventToolEffectPrepared, "turn-one", 0, "effect-one", "inv-shared", platformapi.SessionEffectExecutor),
			settledStateEvent(3, platformapi.EventToolSettled, "turn-one", 0, "effect-one", "inv-shared", platformapi.SessionEffectExecutor),
			effectStateEvent(4, platformapi.EventToolEffectPrepared, "turn-one", 0, "effect-two", "inv-shared", platformapi.SessionEffectExecutor),
		},
		"control identifier": {
			accepted, effectStateEvent(2, platformapi.EventToolEffectPrepared, "turn-one", 0, "effect\none", "inv-one", platformapi.SessionEffectExecutor),
		},
		"oversize identifier": {
			accepted, effectStateEvent(2, platformapi.EventToolEffectPrepared, "turn-one", 0, strings.Repeat("x", 257), "inv-one", platformapi.SessionEffectExecutor),
		},
		"non normalized identifier": {
			accepted, effectStateEvent(2, platformapi.EventToolEffectPrepared, "turn-one", 0, "e\u0301", "inv-one", platformapi.SessionEffectExecutor),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			reader := &stateEventReader{
				page: platformapi.SessionPublicEventPage{
					Snapshot: platformapi.SessionPublicEventSnapshot{
						SessionID: stateEventSessionID, LastEventSequence: uint64(len(events)),
					},
					Events: events,
				},
			}
			service := newStateEventService(t, reader, &stateEventAuthorizer{})
			_, err := service.ReadSessionEventPage(context.Background(), stateEventRequest(0, 16))
			if !errors.Is(err, platformapi.ErrRepositoryFailure) {
				t.Fatalf("ReadSessionEventPage() error = %v, want ErrRepositoryFailure", err)
			}
		})
	}

	for name, snapshot := range map[string]platformapi.SessionPublicEventSnapshot{
		"active id without status": {SessionID: stateEventSessionID, ActiveTurnID: stateEventString("turn-active")},
		"status without active id": {SessionID: stateEventSessionID, TurnStatus: stateEventTurnStatus(platformapi.TurnActive)},
		"terminal active status": {
			SessionID: stateEventSessionID, ActiveTurnID: stateEventString("turn-active"), TurnStatus: stateEventTurnStatus(platformapi.TurnCompleted),
		},
		"oversize active id": {
			SessionID: stateEventSessionID, ActiveTurnID: stateEventString(strings.Repeat("x", 257)), TurnStatus: stateEventTurnStatus(platformapi.TurnActive),
		},
	} {
		t.Run("snapshot "+name, func(t *testing.T) {
			t.Parallel()
			reader := &stateEventReader{
				page: platformapi.SessionPublicEventPage{Snapshot: snapshot},
			}
			service := newStateEventService(t, reader, &stateEventAuthorizer{})
			_, err := service.ReadSessionEventPage(context.Background(), stateEventRequest(0, 1))
			if !errors.Is(err, platformapi.ErrRepositoryFailure) {
				t.Fatalf("ReadSessionEventPage() error = %v, want ErrRepositoryFailure", err)
			}
		})
	}
}

func TestSessionEventPageAllowsPartialPageWhoseAcceptancePrecedesCursor(t *testing.T) {
	t.Parallel()
	reader := &stateEventReader{
		page: platformapi.SessionPublicEventPage{
			Snapshot: platformapi.SessionPublicEventSnapshot{
				SessionID: stateEventSessionID, LastEventSequence: 3,
			},
			Events: []platformapi.SessionPublicEvent{
				effectStateEvent(2, platformapi.EventToolEffectPrepared, "turn-one", 0, "effect-one", "inv-one", platformapi.SessionEffectExecutor),
				settledStateEvent(3, platformapi.EventToolSettled, "turn-one", 0, "effect-one", "inv-one", platformapi.SessionEffectExecutor),
			},
		},
	}
	service := newStateEventService(t, reader, &stateEventAuthorizer{})
	page, err := service.ReadSessionEventPage(context.Background(), stateEventRequest(1, 16))
	if err != nil || len(page.Events) != 2 {
		t.Fatalf("ReadSessionEventPage(partial) = %#v, %v", page, err)
	}
}

func TestSessionEventPagePreservesSchemaV2EffectTransitionMigration(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		events       []platformapi.SessionPublicEvent
		activeTurnID string
	}{
		"terminal history omitted between active admissions": {
			events: []platformapi.SessionPublicEvent{
				acceptedStateEvent(1, "turn-one", 0),
				acceptedStateEvent(2, "turn-two", 1),
			},
		},
		"model settled without backfilled preparation": {
			events: []platformapi.SessionPublicEvent{
				acceptedStateEvent(1, "turn-one", 0),
				settledStateEvent(2, platformapi.EventModelSettled, "turn-one", 0, "effect-model", "inv-model", platformapi.SessionEffectModel),
			},
			activeTurnID: "turn-one",
		},
		"tool external commit without backfilled preparation": {
			events: []platformapi.SessionPublicEvent{
				acceptedStateEvent(1, "turn-one", 0),
				{
					Sequence: 2, Type: platformapi.EventToolExternallyCommit,
					TurnID: "turn-one", EffectID: "effect-tool", InvocationID: "inv-tool",
					Service: platformapi.SessionEffectExecutor, Operation: "execute",
					ExternalCommitID: "commit-tool", ResultRef: "result-tool",
				},
				settledStateEvent(3, platformapi.EventToolSettled, "turn-one", 0, "effect-tool", "inv-tool", platformapi.SessionEffectExecutor),
			},
			activeTurnID: "turn-one",
		},
		"queued admission advances after omitted legacy terminal": {
			events: []platformapi.SessionPublicEvent{
				acceptedStateEvent(1, "turn-one", 0),
				func() platformapi.SessionPublicEvent {
					event := acceptedStateEvent(2, "turn-two", 1)
					event.Status = platformapi.TurnQueued
					return event
				}(),
				effectStateEvent(3, platformapi.EventToolEffectPrepared, "turn-two", 1, "effect-two", "inv-two", platformapi.SessionEffectExecutor),
			},
			activeTurnID: "turn-two",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			snapshot := platformapi.SessionPublicEventSnapshot{
				SessionID: stateEventSessionID, LastEventSequence: uint64(len(test.events)),
			}
			if test.activeTurnID != "" {
				snapshot.ActiveTurnID = stateEventString(test.activeTurnID)
				snapshot.TurnStatus = stateEventTurnStatus(platformapi.TurnActive)
			}
			reader := &stateEventReader{
				page: platformapi.SessionPublicEventPage{
					Snapshot: snapshot,
					Events:   test.events,
				},
			}
			service := newStateEventService(t, reader, &stateEventAuthorizer{})
			page, err := service.ReadSessionEventPage(context.Background(), stateEventRequest(0, 16))
			if err != nil || len(page.Events) != len(test.events) {
				t.Fatalf("ReadSessionEventPage(migrated) = %#v, %v", page, err)
			}
		})
	}
}

func TestSessionEventPageRejectsImpossiblePartialPrefixCausality(t *testing.T) {
	t.Parallel()
	for name, events := range map[string][]platformapi.SessionPublicEvent{
		"two unseen effects consume one prefix": {
			settledStateEvent(2, platformapi.EventToolSettled, "turn-one", 0, "effect-one", "inv-one", platformapi.SessionEffectExecutor),
			settledStateEvent(3, platformapi.EventModelSettled, "turn-one", 0, "effect-two", "inv-two", platformapi.SessionEffectModel),
		},
		"active admission while prefix turn remains live": {
			effectStateEvent(2, platformapi.EventToolEffectPrepared, "turn-one", 0, "effect-one", "inv-one", platformapi.SessionEffectExecutor),
			acceptedStateEvent(3, "turn-two", 1),
		},
		"accepted turn predates observed prefix turn": {
			settledStateEvent(2, platformapi.EventToolSettled, "turn-later", 10, "effect-later", "inv-later", platformapi.SessionEffectExecutor),
			func() platformapi.SessionPublicEvent {
				event := acceptedStateEvent(3, "turn-earlier", 5)
				event.Status = platformapi.TurnQueued
				return event
			}(),
		},
		"lifecycle turn sequence moves backward": {
			settledStateEvent(2, platformapi.EventToolSettled, "turn-later", 10, "effect-later", "inv-later", platformapi.SessionEffectExecutor),
			{Sequence: 3, Type: platformapi.EventTurnAborted, TurnID: "turn-earlier", TurnSequence: 5},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			reader := &stateEventReader{
				page: platformapi.SessionPublicEventPage{
					Snapshot: platformapi.SessionPublicEventSnapshot{
						SessionID: stateEventSessionID, LastEventSequence: 3,
					},
					Events: events,
				},
			}
			service := newStateEventService(t, reader, &stateEventAuthorizer{})
			_, err := service.ReadSessionEventPage(context.Background(), stateEventRequest(1, 16))
			if !errors.Is(err, platformapi.ErrRepositoryFailure) {
				t.Fatalf("ReadSessionEventPage() error = %v, want ErrRepositoryFailure", err)
			}
		})
	}
}

func TestSessionEventPageReturnDoesNotAliasReaderMemory(t *testing.T) {
	t.Parallel()
	reader := &stateEventReader{
		page: platformapi.SessionPublicEventPage{
			Snapshot: platformapi.SessionPublicEventSnapshot{
				SessionID: stateEventSessionID, ActiveTurnID: stateEventString("turn-one"),
				TurnStatus: stateEventTurnStatus(platformapi.TurnActive), LastEventSequence: 1,
			},
			Events: []platformapi.SessionPublicEvent{acceptedStateEvent(1, "turn-one", 0)},
		},
	}
	service := newStateEventService(t, reader, &stateEventAuthorizer{})
	page, err := service.ReadSessionEventPage(context.Background(), stateEventRequest(0, 1))
	if err != nil {
		t.Fatalf("ReadSessionEventPage() error = %v", err)
	}
	page.Events[0].TurnID = "attacker-mutated"
	page.Events = append(page.Events, acceptedStateEvent(2, "attacker-added", 1))
	*page.Snapshot.ActiveTurnID = "attacker-mutated"
	*page.Snapshot.TurnStatus = platformapi.TurnNeedsConfirmation

	reader.mu.Lock()
	defer reader.mu.Unlock()
	if len(reader.page.Events) != 1 || reader.page.Events[0].TurnID != "turn-one" ||
		*reader.page.Snapshot.ActiveTurnID != "turn-one" ||
		*reader.page.Snapshot.TurnStatus != platformapi.TurnActive {
		t.Fatalf("reader-owned page was mutated through result: %#v", reader.page)
	}
}

type rotatingStateEventBoundary struct {
	mu                   sync.Mutex
	generation           uint64
	staleReads           int
	goodReads            int
	authorizationReached chan<- struct{}
	releaseAuthorization <-chan struct{}
}

func (boundary *rotatingStateEventBoundary) Authorize(
	_ context.Context,
	request platformapi.AuthorizationRequest,
) (platformapi.AuthorizationPermit, error) {
	boundary.mu.Lock()
	permit := stateEventPermit(boundary.generation)
	permit.Operation = request.Operation
	permit.Principal = request.Principal
	permit.SessionID = request.SessionID
	boundary.mu.Unlock()
	if boundary.authorizationReached != nil {
		boundary.authorizationReached <- struct{}{}
	}
	if boundary.releaseAuthorization != nil {
		<-boundary.releaseAuthorization
	}
	return permit, nil
}

func (boundary *rotatingStateEventBoundary) ReadSessionEventPage(
	_ context.Context,
	request platformapi.AuthorizedSessionEventPageRequest,
) (platformapi.SessionPublicEventPage, error) {
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	if request.Authorization.AuthorizationGeneration != boundary.generation {
		boundary.staleReads++
		return platformapi.SessionPublicEventPage{}, platformapi.ErrStaleAuthority
	}
	boundary.goodReads++
	return emptyStateEventPage(), nil
}

func (boundary *rotatingStateEventBoundary) rotate() {
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	boundary.generation++
}

func TestSessionEventPageConcurrentReadsRemainGenerationFencedDuringRotation(t *testing.T) {
	const readers = 64
	authorizationReached := make(chan struct{}, readers)
	releaseAuthorization := make(chan struct{})
	boundary := &rotatingStateEventBoundary{
		generation: 1, authorizationReached: authorizationReached,
		releaseAuthorization: releaseAuthorization,
	}
	service := newStateEventService(t, boundary, boundary)
	start := make(chan struct{})
	errorsChannel := make(chan error, readers)
	for range readers {
		go func() {
			<-start
			_, err := service.ReadSessionEventPage(context.Background(), stateEventRequest(0, 1))
			errorsChannel <- err
		}()
	}
	close(start)
	for range readers {
		<-authorizationReached
	}
	boundary.rotate()
	close(releaseAuthorization)
	for range readers {
		err := <-errorsChannel
		if !errors.Is(err, platformapi.ErrStaleAuthority) {
			t.Fatalf("ReadSessionEventPage() error = %v, want ErrStaleAuthority", err)
		}
	}
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	if boundary.goodReads != 0 || boundary.staleReads != readers {
		t.Fatalf("good/stale reads = %d/%d, want 0/%d", boundary.goodReads, boundary.staleReads, readers)
	}
}

func acceptedStateEvent(sequence uint64, turnID string, turnSequence uint64) platformapi.SessionPublicEvent {
	return platformapi.SessionPublicEvent{
		Sequence: sequence, Type: platformapi.EventTurnAccepted,
		TurnID: turnID, TurnSequence: turnSequence, Status: platformapi.TurnActive,
	}
}

func effectStateEvent(
	sequence uint64,
	eventType platformapi.EventType,
	turnID string,
	turnSequence uint64,
	effectID string,
	invocationID string,
	service platformapi.SessionEffectService,
) platformapi.SessionPublicEvent {
	return platformapi.SessionPublicEvent{
		Sequence: sequence, Type: eventType, TurnID: turnID, TurnSequence: turnSequence,
		EffectID: effectID, InvocationID: invocationID, Service: service, Operation: "execute",
	}
}

func settledStateEvent(
	sequence uint64,
	eventType platformapi.EventType,
	turnID string,
	turnSequence uint64,
	effectID string,
	invocationID string,
	service platformapi.SessionEffectService,
) platformapi.SessionPublicEvent {
	event := effectStateEvent(
		sequence, eventType, turnID, turnSequence, effectID, invocationID, service,
	)
	event.SettlementKind = platformapi.SessionSettlementSuccess
	return event
}

func stateEventString(value string) *string {
	return &value
}

func stateEventTurnStatus(value platformapi.TurnStatus) *platformapi.TurnStatus {
	return &value
}
