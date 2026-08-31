package platformapi

import (
	"context"
	"errors"
	"reflect"
	"unicode"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/sessionevent"
	"golang.org/x/text/unicode/norm"
)

const (
	maximumSessionEventPageEvents = 256
	maximumSessionIdentifierBytes = 256
)

// SessionEventPageReader is deliberately read-only. Implementations must not
// expose an append or mutation operation through this authority boundary. The
// live probe must be served by the same concrete reader that handles requests.
type SessionEventPageReader = sessionevent.SessionEventPageReader

// AuthorizedSessionEventPageRequest carries the exact permit returned by the
// public Authorizer. Readers re-fence its authorization generation while
// reading the authoritative Session snapshot and journal page atomically.
type AuthorizedSessionEventPageRequest = sessionevent.AuthorizedSessionEventPageRequest

type ReadSessionEventPageRequest struct {
	Principal     Principal
	SessionID     string
	AfterSequence uint64
	Limit         int
}

type SessionEffectService = sessionevent.SessionEffectService

const (
	SessionEffectModel        = sessionevent.SessionEffectModel
	SessionEffectWorkspace    = sessionevent.SessionEffectWorkspace
	SessionEffectExecutor     = sessionevent.SessionEffectExecutor
	SessionEffectMCP          = sessionevent.SessionEffectMCP
	SessionEffectArtifact     = sessionevent.SessionEffectArtifact
	SessionEffectExternalTool = sessionevent.SessionEffectExternalTool
)

type SessionSettlementKind = sessionevent.SessionSettlementKind

const (
	SessionSettlementSuccess            = sessionevent.SessionSettlementSuccess
	SessionSettlementError              = sessionevent.SessionSettlementError
	SessionSettlementInterruptedUnknown = sessionevent.SessionSettlementInterruptedUnknown
	SessionSettlementAbandoned          = sessionevent.SessionSettlementAbandoned
)

// SessionPublicEvent mirrors the state-app SessionPublicEvent discriminated
// union. Fields not belonging to an event's Type must retain their zero value;
// the service validates this exact family shape before returning a page.
type SessionPublicEvent = sessionevent.SessionPublicEvent

// SessionPublicEventSnapshot mirrors state-app's page-time Session snapshot.
// Nil ActiveTurnID and TurnStatus represent its null active-turn fields.
type SessionPublicEventSnapshot = sessionevent.SessionPublicEventSnapshot
type SessionPublicEventPage = sessionevent.SessionPublicEventPage

type SessionEventServiceConfig struct {
	Reader            dependency.Verified[SessionEventPageReader]
	Authorizer        Authorizer
	MaximumPageEvents int
}

type SessionEventService struct {
	reader            SessionEventPageReader
	authorizer        Authorizer
	maximumPageEvents int
}

func NewSessionEventService(config SessionEventServiceConfig) (*SessionEventService, error) {
	if config.Authorizer == nil || config.MaximumPageEvents < 1 ||
		config.MaximumPageEvents > maximumSessionEventPageEvents {
		return nil, ErrInvalidConfig
	}
	value := reflect.ValueOf(config.Authorizer)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, ErrInvalidConfig
		}
	}
	reader, _, err := config.Reader.Open()
	if err != nil {
		return nil, ErrRepositoryNotDurable
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{
		dependency.AtomicCommandReceipt,
		dependency.AtomicEffectLifecycle,
	}, config.Reader); err != nil {
		return nil, ErrRepositoryNotDurable
	}
	return &SessionEventService{
		reader: reader, authorizer: config.Authorizer,
		maximumPageEvents: config.MaximumPageEvents,
	}, nil
}

func (service *SessionEventService) ReadSessionEventPage(
	ctx context.Context,
	request ReadSessionEventPageRequest,
) (SessionPublicEventPage, error) {
	if err := ctx.Err(); err != nil {
		return SessionPublicEventPage{}, err
	}
	if service == nil || service.reader == nil || service.authorizer == nil {
		return SessionPublicEventPage{}, ErrInvalidConfig
	}
	if validatePrincipal(request.Principal) != nil || request.AfterSequence > maximumSharedInteger {
		return SessionPublicEventPage{}, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Session, request.SessionID); err != nil {
		return SessionPublicEventPage{}, ErrInvalidRequest
	}
	limit := request.Limit
	if limit == 0 {
		limit = service.maximumPageEvents
	}
	if limit < 1 || limit > service.maximumPageEvents {
		return SessionPublicEventPage{}, ErrInvalidRequest
	}
	authorizationRequest := AuthorizationRequest{
		Operation: OperationReadEvents, Principal: request.Principal, SessionID: request.SessionID,
	}
	permit, err := service.authorizer.Authorize(ctx, authorizationRequest)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return SessionPublicEventPage{}, ctxErr
	}
	if err != nil || validateAuthorizationPermit(permit, authorizationRequest) != nil {
		return SessionPublicEventPage{}, ErrAccessDenied
	}
	page, err := service.reader.ReadSessionEventPage(ctx, AuthorizedSessionEventPageRequest{
		Authorization: permit, SessionID: request.SessionID,
		AfterSequence: request.AfterSequence, Limit: limit,
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return SessionPublicEventPage{}, ctxErr
		}
		for _, known := range []error{
			ErrAccessDenied, ErrSessionNotFound, ErrInvalidCursor, ErrStaleAuthority,
		} {
			if errors.Is(err, known) {
				return SessionPublicEventPage{}, known
			}
		}
		return SessionPublicEventPage{}, ErrRepositoryFailure
	}
	if len(page.Events) > limit {
		return SessionPublicEventPage{}, ErrRepositoryFailure
	}
	events := make([]SessionPublicEvent, len(page.Events))
	copy(events, page.Events)
	page.Events = events
	if page.Snapshot.ActiveTurnID != nil {
		activeTurnID := *page.Snapshot.ActiveTurnID
		page.Snapshot.ActiveTurnID = &activeTurnID
	}
	if page.Snapshot.TurnStatus != nil {
		turnStatus := *page.Snapshot.TurnStatus
		page.Snapshot.TurnStatus = &turnStatus
	}
	if validateSessionPublicEventPage(page, request.SessionID, request.AfterSequence, limit) != nil {
		return SessionPublicEventPage{}, ErrRepositoryFailure
	}
	return page, nil
}

func validateSessionPublicEventPage(
	page SessionPublicEventPage,
	sessionID string,
	afterSequence uint64,
	limit int,
) error {
	snapshot := page.Snapshot
	if snapshot.SessionID != sessionID || snapshot.LastEventSequence > maximumSharedInteger ||
		snapshot.LastEventSequence < afterSequence || len(page.Events) > limit {
		return ErrRepositoryFailure
	}
	if (snapshot.ActiveTurnID == nil) != (snapshot.TurnStatus == nil) {
		return ErrRepositoryFailure
	}
	if snapshot.LastEventSequence == 0 && snapshot.ActiveTurnID != nil {
		return ErrRepositoryFailure
	}
	snapshotActiveTurnID := ""
	if snapshot.ActiveTurnID != nil {
		snapshotActiveTurnID = *snapshot.ActiveTurnID
		if !validSessionProtocolIdentifier(snapshotActiveTurnID) ||
			(*snapshot.TurnStatus != TurnActive && *snapshot.TurnStatus != TurnNeedsConfirmation) {
			return ErrRepositoryFailure
		}
	}
	remaining := snapshot.LastEventSequence - afterSequence
	expectedEvents := limit
	if remaining < uint64(limit) {
		expectedEvents = int(remaining)
	}
	if len(page.Events) != expectedEvents {
		return ErrRepositoryFailure
	}

	type turnPageState struct {
		turnSequence uint64
		accepted     bool
		terminal     bool
	}
	type effectPageState struct {
		turnID       string
		invocationID string
		service      SessionEffectService
		operation    string
		prepared     bool
		external     bool
		settled      bool
	}
	turns := make(map[string]turnPageState)
	turnIDsBySequence := make(map[uint64]string)
	liveLifecycleTurns := make(map[string]uint64)
	effects := make(map[string]effectPageState)
	effectIDsByInvocation := make(map[string]string)
	activeEffectID := ""
	// A page can inherit one in-flight effect either from its cursor prefix or
	// from a schema-v2 journal, which preserved admission events but did not
	// backfill an already prepared effect during the schema-v3 migration.
	canConsumeUnseenEffect := true
	maxSeenTurnSequence := uint64(0)
	hasSeenTurnSequence := false
	lastLifecycleTurnSequence := uint64(0)
	hasLifecycleTurnSequence := false
	previousSequence := afterSequence
	for _, event := range page.Events {
		if event.Sequence != previousSequence+1 || event.Sequence > snapshot.LastEventSequence ||
			event.TurnSequence > maximumSharedInteger || !validSessionProtocolIdentifier(event.TurnID) {
			return ErrRepositoryFailure
		}
		previousSequence = event.Sequence
		turn, turnSeen := turns[event.TurnID]
		if turnSeen && turn.turnSequence != event.TurnSequence {
			return ErrRepositoryFailure
		}
		if otherTurnID, sequenceSeen := turnIDsBySequence[event.TurnSequence]; sequenceSeen && otherTurnID != event.TurnID {
			return ErrRepositoryFailure
		}
		turnIDsBySequence[event.TurnSequence] = event.TurnID

		if event.Type == EventTurnAccepted {
			if turnSeen || hasSeenTurnSequence && event.TurnSequence <= maxSeenTurnSequence ||
				event.Status == TurnActive && len(liveLifecycleTurns) != 0 ||
				event.Status != TurnActive && event.Status != TurnQueued ||
				event.EffectID != "" || event.InvocationID != "" || event.Service != "" ||
				event.Operation != "" || event.ExternalCommitID != "" || event.ResultRef != "" ||
				event.SettlementKind != "" {
				return ErrRepositoryFailure
			}
			turns[event.TurnID] = turnPageState{turnSequence: event.TurnSequence, accepted: true}
			maxSeenTurnSequence = event.TurnSequence
			hasSeenTurnSequence = true
			continue
		}
		if hasLifecycleTurnSequence && event.TurnSequence < lastLifecycleTurnSequence {
			return ErrRepositoryFailure
		}
		lastLifecycleTurnSequence = event.TurnSequence
		hasLifecycleTurnSequence = true
		if !hasSeenTurnSequence || event.TurnSequence > maxSeenTurnSequence {
			maxSeenTurnSequence = event.TurnSequence
			hasSeenTurnSequence = true
		}
		if !turnSeen {
			if afterSequence == 0 {
				return ErrRepositoryFailure
			}
			turn = turnPageState{turnSequence: event.TurnSequence, accepted: true}
		}
		if !turn.accepted || turn.terminal || event.Status != "" {
			return ErrRepositoryFailure
		}
		for otherTurnID, otherTurnSequence := range liveLifecycleTurns {
			if otherTurnID != event.TurnID && otherTurnSequence < event.TurnSequence {
				return ErrRepositoryFailure
			}
		}

		switch event.Type {
		case EventTurnCompleted, EventTurnFailed, EventTurnAborted:
			if activeEffectID != "" || event.TurnID == snapshotActiveTurnID || event.EffectID != "" ||
				event.InvocationID != "" || event.Service != "" ||
				event.Operation != "" || event.ExternalCommitID != "" || event.ResultRef != "" ||
				event.SettlementKind != "" {
				return ErrRepositoryFailure
			}
			turn.terminal = true
			canConsumeUnseenEffect = false
			delete(liveLifecycleTurns, event.TurnID)
		case EventModelEffectPrepared, EventToolEffectPrepared, EventToolExternallyCommit,
			EventModelSettled, EventToolSettled, EventTurnNeedsConfirmation:
			if !validSessionProtocolIdentifier(event.EffectID) ||
				!validSessionProtocolIdentifier(event.InvocationID) ||
				!validSessionProtocolIdentifier(event.Operation) || !validSessionEffectService(event.Service) {
				return ErrRepositoryFailure
			}
			modelFamily := event.Type == EventModelEffectPrepared || event.Type == EventModelSettled
			toolFamily := event.Type == EventToolEffectPrepared || event.Type == EventToolExternallyCommit ||
				event.Type == EventToolSettled
			if modelFamily != (event.Service == SessionEffectModel) && event.Type != EventTurnNeedsConfirmation ||
				toolFamily && event.Service == SessionEffectModel {
				return ErrRepositoryFailure
			}
			liveLifecycleTurns[event.TurnID] = event.TurnSequence
			effect, effectSeen := effects[event.EffectID]
			if otherEffectID, invocationSeen := effectIDsByInvocation[event.InvocationID]; invocationSeen && otherEffectID != event.EffectID {
				return ErrRepositoryFailure
			}
			effectIDsByInvocation[event.InvocationID] = event.EffectID
			if effectSeen && (effect.turnID != event.TurnID || effect.invocationID != event.InvocationID ||
				effect.service != event.Service || effect.operation != event.Operation) {
				return ErrRepositoryFailure
			}
			if !effectSeen {
				effect = effectPageState{
					turnID: event.TurnID, invocationID: event.InvocationID,
					service: event.Service, operation: event.Operation,
				}
			}
			preparation := event.Type == EventModelEffectPrepared || event.Type == EventToolEffectPrepared
			if !preparation && !effectSeen && activeEffectID == "" {
				if !canConsumeUnseenEffect {
					return ErrRepositoryFailure
				}
				canConsumeUnseenEffect = false
				activeEffectID = event.EffectID
			}
			switch event.Type {
			case EventModelEffectPrepared, EventToolEffectPrepared:
				if activeEffectID != "" || effectSeen || event.ExternalCommitID != "" || event.ResultRef != "" ||
					event.SettlementKind != "" {
					return ErrRepositoryFailure
				}
				effect.prepared = true
				activeEffectID = event.EffectID
				canConsumeUnseenEffect = false
			case EventToolExternallyCommit:
				if activeEffectID != "" && activeEffectID != event.EffectID ||
					effect.external || effect.settled || !validSessionProtocolIdentifier(event.ExternalCommitID) ||
					!validSessionProtocolIdentifier(event.ResultRef) || event.SettlementKind != "" {
					return ErrRepositoryFailure
				}
				effect.external = true
				activeEffectID = event.EffectID
			case EventModelSettled, EventToolSettled:
				if activeEffectID != "" && activeEffectID != event.EffectID ||
					effect.settled || event.ExternalCommitID != "" || event.ResultRef != "" ||
					!validSessionSettlementKind(event.SettlementKind) {
					return ErrRepositoryFailure
				}
				effect.settled = true
				activeEffectID = ""
			case EventTurnNeedsConfirmation:
				if activeEffectID != "" && activeEffectID != event.EffectID ||
					effect.external || effect.settled || event.ExternalCommitID != "" ||
					event.ResultRef != "" || event.SettlementKind != "" {
					return ErrRepositoryFailure
				}
				activeEffectID = event.EffectID
			}
			effects[event.EffectID] = effect
		default:
			return ErrRepositoryFailure
		}
		turns[event.TurnID] = turn
	}
	if afterSequence == 0 && previousSequence == snapshot.LastEventSequence &&
		snapshotActiveTurnID != "" {
		activeTurn, found := turns[snapshotActiveTurnID]
		if !found || !activeTurn.accepted || activeTurn.terminal {
			return ErrRepositoryFailure
		}
	}
	return nil
}

func validSessionProtocolIdentifier(value string) bool {
	if value == "" || len(value) > maximumSessionIdentifierBytes || !utf8.ValidString(value) ||
		!norm.NFC.IsNormalString(value) {
		return false
	}
	for _, character := range value {
		if unicode.Is(unicode.Cc, character) {
			return false
		}
	}
	return true
}

func validSessionEffectService(value SessionEffectService) bool {
	switch value {
	case SessionEffectModel, SessionEffectWorkspace, SessionEffectExecutor,
		SessionEffectMCP, SessionEffectArtifact, SessionEffectExternalTool:
		return true
	default:
		return false
	}
}

func validSessionSettlementKind(value SessionSettlementKind) bool {
	switch value {
	case SessionSettlementSuccess, SessionSettlementError,
		SessionSettlementInterruptedUnknown, SessionSettlementAbandoned:
		return true
	default:
		return false
	}
}
