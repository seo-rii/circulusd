package platformapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/idempotency"
	"github.com/hancomac/circulusd/internal/identity"
	"golang.org/x/text/unicode/norm"
)

const (
	maximumConfiguredBytes = 64 << 20
	maximumMessages        = 256
	maximumReplayLimit     = 4096
	maximumSharedInteger   = uint64(9_007_199_254_740_991)
)

type Service struct {
	store               Repository
	authorizer          Authorizer
	eventAuthorizer     EventAuthorizer
	idempotencySecret   []byte
	maximumMessageBytes int
	maximumEventBytes   int
	maximumReplayEvents int
	newTurnID           func() (string, error)
}

func NewService(config Config) (*Service, error) {
	if config.Store == nil || config.Authorizer == nil || config.EventAuthorizer == nil ||
		len(config.IdempotencySecret) < 32 ||
		config.MaximumMessageBytes <= 0 || config.MaximumMessageBytes > maximumConfiguredBytes ||
		config.MaximumEventBytes <= 0 || config.MaximumEventBytes > maximumConfiguredBytes ||
		config.MaximumReplayEvents <= 0 || config.MaximumReplayEvents > maximumReplayLimit {
		return nil, ErrInvalidConfig
	}
	for _, dependency := range []any{config.Store, config.Authorizer, config.EventAuthorizer} {
		value := reflect.ValueOf(dependency)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			if value.IsNil() {
				return nil, ErrInvalidConfig
			}
		}
	}
	durability := config.Store.Durability()
	if !durability.CrashDurable || !durability.AtomicIdempotency || !durability.AtomicEventSequence ||
		!durability.AtomicReplaySubscribe || !durability.AtomicAuthorizationFence {
		_, referenceMemory := config.Store.(*MemoryStore)
		if !config.AllowReferenceMemory || !referenceMemory {
			return nil, ErrRepositoryNotDurable
		}
	}
	newTurnID := config.NewTurnID
	if newTurnID == nil {
		newTurnID = func() (string, error) {
			value, err := identity.New(identity.Turn)
			return value.String(), err
		}
	}
	return &Service{
		store: config.Store, authorizer: config.Authorizer, eventAuthorizer: config.EventAuthorizer,
		idempotencySecret:   append([]byte(nil), config.IdempotencySecret...),
		maximumMessageBytes: config.MaximumMessageBytes,
		maximumEventBytes:   config.MaximumEventBytes,
		maximumReplayEvents: config.MaximumReplayEvents,
		newTurnID:           newTurnID,
	}, nil
}

func (service *Service) CreateTurn(ctx context.Context, request CreateTurnRequest) (CreateTurnResult, error) {
	if err := ctx.Err(); err != nil {
		return CreateTurnResult{}, err
	}
	if validatePrincipal(request.Principal) != nil {
		return CreateTurnResult{}, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Session, request.SessionID); err != nil ||
		len(request.Messages) == 0 || len(request.Messages) > maximumMessages {
		return CreateTurnResult{}, ErrInvalidRequest
	}
	messages := make(canonical.Array, 0, len(request.Messages))
	totalBytes := 0
	for _, message := range request.Messages {
		if message.Role != "user" || message.Content == "" || !utf8.ValidString(message.Content) ||
			!norm.NFC.IsNormalString(message.Content) {
			return CreateTurnResult{}, ErrInvalidRequest
		}
		totalBytes += len(message.Content)
		if totalBytes > service.maximumMessageBytes {
			return CreateTurnResult{}, ErrInvalidRequest
		}
		messages = append(messages, canonical.Array{message.Role, message.Content})
	}
	keyDigest, err := idempotency.DigestKey(service.idempotencySecret, request.IdempotencyKey)
	if err != nil {
		return CreateTurnResult{}, ErrInvalidRequest
	}
	requestDigest, err := canonical.StructuredDigest("circulusd.public.turn.create", 1, canonical.Map{
		"sessionId": request.SessionID,
		"messages":  messages,
	})
	if err != nil {
		return CreateTurnResult{}, ErrInvalidRequest
	}
	authorizationRequest := AuthorizationRequest{
		Operation: OperationCreateTurn, Principal: request.Principal, SessionID: request.SessionID,
	}
	authorization, err := service.authorizer.Authorize(ctx, authorizationRequest)
	if err != nil || validateAuthorizationPermit(authorization, authorizationRequest) != nil {
		return CreateTurnResult{}, ErrAccessDenied
	}
	turnID, err := service.newTurnID()
	if err != nil {
		return CreateTurnResult{}, fmt.Errorf("%w: identity generation failed", ErrRepositoryFailure)
	}
	if _, err := identity.Parse(identity.Turn, turnID); err != nil {
		return CreateTurnResult{}, ErrRepositoryFailure
	}
	proposed := Turn{
		ID: turnID, TenantID: request.Principal.TenantID, SubjectID: request.Principal.SubjectID,
		SessionID: request.SessionID, RequestDigest: requestDigest, Status: TurnQueued,
	}
	turn, deduplicated, err := service.store.CreateTurn(ctx, CreateTurnCommand{
		TenantID: request.Principal.TenantID, SubjectID: request.Principal.SubjectID,
		SessionID: request.SessionID, KeyDigest: keyDigest, RequestDigest: requestDigest,
		ProposedTurn: proposed, Authorization: authorization,
	})
	if err != nil {
		return CreateTurnResult{}, repositoryError(ctx, err)
	}
	if validateStoredTurn(turn, request.Principal, request.SessionID, requestDigest) != nil {
		return CreateTurnResult{}, ErrRepositoryFailure
	}
	return CreateTurnResult{Turn: turn, Deduplicated: deduplicated}, nil
}

func (service *Service) AppendDurableEvent(
	ctx context.Context,
	request AppendDurableEventRequest,
) (Event, bool, error) {
	if err := ctx.Err(); err != nil {
		return Event{}, false, err
	}
	if validateEventAuthority(request.Authority) != nil ||
		request.ExpectedSequence > maximumSharedInteger || !validDurableEvent(request.Type) ||
		validateEventPayload(request.Payload, service.maximumEventBytes) != nil ||
		validateStatusForEvent(request.Type, request.TurnStatus) != nil {
		return Event{}, false, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Operation, request.CommandID); err != nil {
		return Event{}, false, ErrInvalidRequest
	}
	if err := service.eventAuthorizer.AuthorizeEvent(ctx, request.Authority); err != nil {
		return Event{}, false, ErrStaleAuthority
	}
	commandDigest, err := canonical.StructuredDigest("circulusd.public.durable-event.append", 1, canonical.Map{
		"tenantId":                request.Authority.Scope.TenantID,
		"userId":                  request.Authority.Scope.UserID,
		"sessionId":               request.Authority.Scope.SessionID,
		"turnId":                  request.Authority.Scope.TurnID,
		"runtimeRevision":         request.Authority.Scope.RuntimeRevision,
		"workspaceId":             request.Authority.Scope.WorkspaceID,
		"placementGeneration":     request.Authority.PlacementGeneration,
		"authorizationGeneration": request.Authority.AuthorizationGeneration,
		"expectedSequence":        request.ExpectedSequence,
		"type":                    string(request.Type),
		"payload":                 string(request.Payload),
		"turnStatus":              string(request.TurnStatus),
	})
	if err != nil {
		return Event{}, false, ErrInvalidRequest
	}
	event, replayed, err := service.store.AppendDurableEvent(ctx, AppendEventCommand{
		Authority: request.Authority, CommandID: request.CommandID, CommandDigest: commandDigest,
		ExpectedSequence: request.ExpectedSequence, Type: request.Type,
		Payload: string(request.Payload), TurnStatus: request.TurnStatus,
	})
	if err != nil {
		return Event{}, false, repositoryError(ctx, err)
	}
	if !event.Durable || event.Sequence == 0 || event.TurnID != request.Authority.Scope.TurnID ||
		event.Type != request.Type || event.Payload != string(request.Payload) {
		return Event{}, false, ErrRepositoryFailure
	}
	return event, replayed, nil
}

func (service *Service) PublishEphemeralEvent(
	ctx context.Context,
	request EphemeralEventRequest,
) (Event, error) {
	if err := ctx.Err(); err != nil {
		return Event{}, err
	}
	if validateEventAuthority(request.Authority) != nil || !validEphemeralEvent(request.Type) ||
		validateEventPayload(request.Payload, service.maximumEventBytes) != nil {
		return Event{}, ErrInvalidRequest
	}
	if err := service.eventAuthorizer.AuthorizeEvent(ctx, request.Authority); err != nil {
		return Event{}, ErrStaleAuthority
	}
	event := Event{
		TurnID: request.Authority.Scope.TurnID, Type: request.Type,
		Payload: string(request.Payload), Durable: false,
	}
	if err := service.store.PublishEphemeralEvent(ctx, request.Authority, event); err != nil {
		return Event{}, repositoryError(ctx, err)
	}
	return event, nil
}

func (service *Service) ReplayEvents(ctx context.Context, request ReplayEventsRequest) (EventReplay, error) {
	query, err := service.authorizeReplay(ctx, request)
	if err != nil {
		return EventReplay{}, err
	}
	replay, err := service.store.ReplayEvents(ctx, query)
	if err != nil {
		return EventReplay{}, repositoryError(ctx, err)
	}
	if service.validateReplay(replay, request, query.Limit) != nil {
		return EventReplay{}, ErrRepositoryFailure
	}
	return replay, nil
}

func (service *Service) OpenEventStream(ctx context.Context, request ReplayEventsRequest) (EventStream, error) {
	query, err := service.authorizeReplay(ctx, request)
	if err != nil {
		return EventStream{}, err
	}
	stream, err := service.store.OpenEventStream(ctx, query)
	if err != nil {
		return EventStream{}, repositoryError(ctx, err)
	}
	valid := service.validateReplay(stream.Replay, request, query.Limit) == nil
	lastReplayed := request.AfterSequence
	if len(stream.Replay.Events) != 0 {
		lastReplayed = stream.Replay.Events[len(stream.Replay.Events)-1].Sequence
	}
	hasSubscription := stream.Subscription != nil
	closableSubscription := hasSubscription
	if hasSubscription {
		value := reflect.ValueOf(stream.Subscription)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			closableSubscription = !value.IsNil()
		}
	}
	usableSubscription := closableSubscription
	var subscriptionEvents <-chan Event
	if closableSubscription {
		subscriptionEvents = stream.Subscription.Events()
		usableSubscription = subscriptionEvents != nil
	}
	if stream.CaughtUp {
		valid = valid && usableSubscription && lastReplayed == stream.Replay.Snapshot.LastDurableSequence
	} else {
		valid = valid && !hasSubscription && lastReplayed < stream.Replay.Snapshot.LastDurableSequence
	}
	if !valid {
		if closableSubscription {
			stream.Subscription.Close()
		}
		return EventStream{}, ErrRepositoryFailure
	}
	if stream.CaughtUp {
		stream.Subscription = &validatedEventSubscription{
			source: stream.Subscription, events: subscriptionEvents,
		}
	}
	return stream, nil
}

type validatedEventSubscription struct {
	source EventSubscription
	events <-chan Event
}

func (subscription *validatedEventSubscription) Events() <-chan Event {
	return subscription.events
}

func (subscription *validatedEventSubscription) Close() {
	subscription.source.Close()
}

func (service *Service) authorizeReplay(ctx context.Context, request ReplayEventsRequest) (ReplayQuery, error) {
	if err := ctx.Err(); err != nil {
		return ReplayQuery{}, err
	}
	if validatePrincipal(request.Principal) != nil || request.AfterSequence > maximumSharedInteger {
		return ReplayQuery{}, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Session, request.SessionID); err != nil {
		return ReplayQuery{}, ErrInvalidRequest
	}
	limit := request.Limit
	if limit == 0 {
		limit = service.maximumReplayEvents
	}
	if limit < 1 || limit > service.maximumReplayEvents {
		return ReplayQuery{}, ErrInvalidRequest
	}
	authorizationRequest := AuthorizationRequest{
		Operation: OperationReadEvents, Principal: request.Principal, SessionID: request.SessionID,
	}
	authorization, err := service.authorizer.Authorize(ctx, authorizationRequest)
	if err != nil || validateAuthorizationPermit(authorization, authorizationRequest) != nil {
		return ReplayQuery{}, ErrAccessDenied
	}
	return ReplayQuery{
		TenantID: request.Principal.TenantID, SubjectID: request.Principal.SubjectID,
		SessionID:     request.SessionID,
		AfterSequence: request.AfterSequence, Limit: limit, Authorization: authorization,
	}, nil
}

func validateAuthorizationPermit(permit AuthorizationPermit, request AuthorizationRequest) error {
	if permit.Operation != request.Operation || permit.Principal != request.Principal ||
		permit.SessionID != request.SessionID || permit.AuthorizationGeneration == 0 ||
		permit.AuthorizationGeneration > maximumSharedInteger || permit.Proof == (OpaqueAuthorizationProof{}) {
		return ErrAccessDenied
	}
	return nil
}

func (service *Service) validateReplay(replay EventReplay, request ReplayEventsRequest, limit int) error {
	if replay.Snapshot.SessionID != request.SessionID ||
		replay.Snapshot.LastDurableSequence < request.AfterSequence || len(replay.Events) > limit {
		return ErrRepositoryFailure
	}
	previous := request.AfterSequence
	for _, event := range replay.Events {
		if !event.Durable || event.Sequence != previous+1 || event.Sequence > replay.Snapshot.LastDurableSequence {
			return ErrRepositoryFailure
		}
		previous = event.Sequence
	}
	return nil
}

func repositoryError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	for _, known := range []error{
		ErrAccessDenied, ErrSessionNotFound, ErrTurnNotFound, ErrIdempotencyConflict,
		ErrSequenceConflict, ErrInvalidCursor, ErrStaleAuthority, ErrInvalidTransition,
	} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrRepositoryFailure
}

func validatePrincipal(principal Principal) error {
	if _, err := identity.Parse(identity.Tenant, principal.TenantID); err != nil {
		return ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Subject, principal.SubjectID); err != nil {
		return ErrInvalidRequest
	}
	return nil
}

func validateEventAuthority(authority EventAuthority) error {
	if _, err := identity.Parse(identity.Tenant, authority.Scope.TenantID); err != nil {
		return ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Subject, authority.Scope.UserID); err != nil {
		return ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Session, authority.Scope.SessionID); err != nil {
		return ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Turn, authority.Scope.TurnID); err != nil {
		return ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.RuntimeRevision, authority.Scope.RuntimeRevision); err != nil {
		return ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Workspace, authority.Scope.WorkspaceID); err != nil ||
		authority.PlacementGeneration == 0 || authority.PlacementGeneration > maximumSharedInteger ||
		authority.AuthorizationGeneration == 0 || authority.AuthorizationGeneration > maximumSharedInteger {
		return ErrInvalidRequest
	}
	return nil
}

func validateStoredTurn(turn Turn, principal Principal, sessionID string, requestDigest string) error {
	if _, err := identity.Parse(identity.Turn, turn.ID); err != nil ||
		turn.TenantID != principal.TenantID || turn.SubjectID != principal.SubjectID ||
		turn.SessionID != sessionID || turn.RequestDigest != requestDigest || turn.Status != TurnQueued {
		return ErrRepositoryFailure
	}
	return nil
}

func validateEventPayload(payload []byte, maximumBytes int) error {
	if len(payload) == 0 || len(payload) > maximumBytes || !utf8.Valid(payload) ||
		!norm.NFC.IsNormal(payload) {
		return ErrInvalidRequest
	}
	return nil
}

func validDurableEvent(value EventType) bool {
	switch value {
	case EventTurnAccepted, EventModelEffectPrepared, EventModelSettled,
		EventToolEffectPrepared, EventToolExternallyCommit, EventToolSettled,
		EventTurnNeedsConfirmation, EventTurnCompleted, EventTurnFailed, EventTurnAborted:
		return true
	default:
		return false
	}
}

func validEphemeralEvent(value EventType) bool {
	switch value {
	case EventModelDelta, EventToolStdout, EventToolStderr, EventToolLeaseWaiting:
		return true
	default:
		return false
	}
}

func validateStatusForEvent(event EventType, status TurnStatus) error {
	wanted := TurnActive
	switch event {
	case EventTurnNeedsConfirmation:
		wanted = TurnNeedsConfirmation
	case EventTurnCompleted:
		wanted = TurnCompleted
	case EventTurnFailed:
		wanted = TurnFailed
	case EventTurnAborted:
		wanted = TurnAborted
	}
	if status != wanted {
		return ErrInvalidTransition
	}
	return nil
}

func validateTurnTransition(current TurnStatus, next TurnStatus, event EventType) error {
	if validateStatusForEvent(event, next) != nil {
		return ErrInvalidTransition
	}
	switch current {
	case TurnQueued:
		if event == EventTurnAccepted && next == TurnActive {
			return nil
		}
	case TurnActive:
		if next == TurnActive || next == TurnNeedsConfirmation || next == TurnCompleted ||
			next == TurnFailed || next == TurnAborted {
			return nil
		}
	case TurnNeedsConfirmation:
		if next == TurnActive || next == TurnCompleted || next == TurnFailed || next == TurnAborted {
			return nil
		}
	}
	return ErrInvalidTransition
}
