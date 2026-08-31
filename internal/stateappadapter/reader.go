// Package stateappadapter maps the authenticated state-app ingress onto the
// public API's read-only Session event shape while capability evidence remains
// fail-closed until the external durable boundary is verified.
package stateappadapter

import (
	"context"
	"errors"
	"net/http"
	"reflect"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/platformapi"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

const (
	maximumEventPageEvents = 256
	maximumSharedInteger   = uint64(9_007_199_254_740_991)
)

type sessionEventClient interface {
	ReadSessionEvents(context.Context, stateappclient.Request) (canonical.Value, error)
	dependency.ProductionProbe
}

// Reader is a state-app-backed Session event reader and production-probe
// candidate. Production consumers must accept it only through a
// dependency.Verified wrapper.
type Reader struct {
	client sessionEventClient
}

// New builds a candidate around the exact concrete client that serves both
// operational reads and the production challenge.
func New(client *stateappclient.Client) (*Reader, error) {
	if adapterClientIsNil(client) {
		return nil, platformapi.ErrInvalidConfig
	}
	return &Reader{client: client}, nil
}

// newCandidateReaderForTest preserves the same single-client invariant while
// allowing deterministic contract tests without a network listener.
func newCandidateReaderForTest(client sessionEventClient) (*Reader, error) {
	if adapterClientIsNil(client) {
		return nil, platformapi.ErrInvalidConfig
	}
	return &Reader{client: client}, nil
}

func (reader *Reader) ProbeProduction(
	ctx context.Context,
	challenge dependency.ProbeChallenge,
) (dependency.ProbeResponse, error) {
	if reader == nil || adapterClientIsNil(reader.client) {
		return dependency.ProbeResponse{}, dependency.ErrInvalidConfiguration
	}
	return reader.client.ProbeProduction(ctx, challenge)
}

func (reader *Reader) ReadSessionEventPage(
	ctx context.Context,
	request platformapi.AuthorizedSessionEventPageRequest,
) (platformapi.SessionPublicEventPage, error) {
	if ctx == nil {
		return platformapi.SessionPublicEventPage{}, platformapi.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return platformapi.SessionPublicEventPage{}, err
	}
	if reader == nil || adapterClientIsNil(reader.client) {
		return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
	}
	permit := request.Authorization
	if permit.Operation != platformapi.OperationReadEvents ||
		permit.Principal.TenantID == "" || permit.Principal.SubjectID == "" ||
		permit.SessionID != request.SessionID || permit.AuthorizationGeneration < 1 ||
		permit.AuthorizationGeneration > maximumSharedInteger ||
		permit.Proof == (platformapi.OpaqueAuthorizationProof{}) {
		return platformapi.SessionPublicEventPage{}, platformapi.ErrAccessDenied
	}
	if _, err := identity.Parse(identity.Tenant, permit.Principal.TenantID); err != nil {
		return platformapi.SessionPublicEventPage{}, platformapi.ErrAccessDenied
	}
	if _, err := identity.Parse(identity.Subject, permit.Principal.SubjectID); err != nil {
		return platformapi.SessionPublicEventPage{}, platformapi.ErrAccessDenied
	}
	if _, err := identity.Parse(identity.Session, request.SessionID); err != nil {
		return platformapi.SessionPublicEventPage{}, platformapi.ErrAccessDenied
	}
	if request.AfterSequence > maximumSharedInteger || request.Limit < 1 || request.Limit > maximumEventPageEvents {
		return platformapi.SessionPublicEventPage{}, platformapi.ErrInvalidCursor
	}

	result, err := reader.client.ReadSessionEvents(ctx, stateappclient.Request{
		TenantID: permit.Principal.TenantID, ActorSubjectID: permit.Principal.SubjectID,
		SessionID:                       request.SessionID,
		ExpectedAuthorizationGeneration: permit.AuthorizationGeneration,
		AfterSequence:                   request.AfterSequence, Limit: request.Limit,
	})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return platformapi.SessionPublicEventPage{}, ctxErr
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return platformapi.SessionPublicEventPage{}, err
		}
		var remote *stateappclient.RemoteError
		if errors.As(err, &remote) {
			switch remote.Code {
			case "NOT_FOUND", "NOT_INITIALIZED":
				return platformapi.SessionPublicEventPage{}, platformapi.ErrSessionNotFound
			case "PERMISSION_DENIED":
				return platformapi.SessionPublicEventPage{}, platformapi.ErrAccessDenied
			case "STALE_GENERATION":
				return platformapi.SessionPublicEventPage{}, platformapi.ErrStaleAuthority
			case "INVALID_ARGUMENT":
				if remote.Status == http.StatusOK {
					return platformapi.SessionPublicEventPage{}, platformapi.ErrInvalidCursor
				}
			}
		}
		return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
	}

	record, ok := result.(canonical.Map)
	if !ok || len(record) != 2 {
		return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
	}
	snapshotValue, hasSnapshot := record["snapshot"]
	eventsValue, hasEvents := record["events"]
	if !hasSnapshot || !hasEvents {
		return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
	}
	snapshot, ok := snapshotValue.(canonical.Map)
	if !ok || len(snapshot) != 4 {
		return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
	}
	sessionID, sessionIDOK := snapshot["sessionId"].(string)
	activeTurnValue, hasActiveTurn := snapshot["activeTurnId"]
	turnStatusValue, hasTurnStatus := snapshot["turnStatus"]
	lastSequenceValue, hasLastSequence := snapshot["lastEventSequence"]
	lastSequence, lastSequenceOK := lastSequenceValue.(int64)
	if !sessionIDOK || sessionID != request.SessionID ||
		!hasActiveTurn || !hasTurnStatus || !hasLastSequence || !lastSequenceOK ||
		lastSequence < 0 || uint64(lastSequence) > maximumSharedInteger {
		return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
	}
	var activeTurnID *string
	if activeTurnValue != nil {
		value, valueOK := activeTurnValue.(string)
		if !valueOK {
			return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
		}
		activeTurnID = &value
	}
	var turnStatus *platformapi.TurnStatus
	if turnStatusValue != nil {
		value, valueOK := turnStatusValue.(string)
		status := platformapi.TurnStatus(value)
		if !valueOK || status != platformapi.TurnActive && status != platformapi.TurnNeedsConfirmation {
			return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
		}
		turnStatus = &status
	}
	eventValues, ok := eventsValue.(canonical.Array)
	if !ok || len(eventValues) > request.Limit || len(eventValues) > maximumEventPageEvents {
		return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
	}
	events := make([]platformapi.SessionPublicEvent, 0, len(eventValues))
	for _, eventValue := range eventValues {
		eventRecord, eventOK := eventValue.(canonical.Map)
		if !eventOK {
			return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
		}
		typeValue, hasType := eventRecord["type"]
		eventTypeText, typeOK := typeValue.(string)
		sequenceValue, hasSequence := eventRecord["sequence"]
		sequence, sequenceOK := sequenceValue.(int64)
		turnIDValue, hasTurnID := eventRecord["turnId"]
		turnID, turnIDOK := turnIDValue.(string)
		turnSequenceValue, hasTurnSequence := eventRecord["turnSequence"]
		turnSequence, turnSequenceOK := turnSequenceValue.(int64)
		if !hasType || !typeOK || !hasSequence || !sequenceOK || sequence < 0 ||
			uint64(sequence) > maximumSharedInteger || !hasTurnID || !turnIDOK ||
			!hasTurnSequence || !turnSequenceOK || turnSequence < 0 ||
			uint64(turnSequence) > maximumSharedInteger {
			return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
		}
		event := platformapi.SessionPublicEvent{
			Sequence: uint64(sequence), Type: platformapi.EventType(eventTypeText),
			TurnID: turnID, TurnSequence: uint64(turnSequence),
		}
		switch event.Type {
		case platformapi.EventTurnAccepted:
			statusValue, hasStatus := eventRecord["status"]
			statusText, statusOK := statusValue.(string)
			status := platformapi.TurnStatus(statusText)
			if len(eventRecord) != 5 || !hasStatus || !statusOK ||
				status != platformapi.TurnActive && status != platformapi.TurnQueued {
				return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
			}
			event.Status = status
		case platformapi.EventModelEffectPrepared, platformapi.EventToolEffectPrepared,
			platformapi.EventToolExternallyCommit, platformapi.EventModelSettled,
			platformapi.EventToolSettled, platformapi.EventTurnNeedsConfirmation:
			effectIDValue, hasEffectID := eventRecord["effectId"]
			effectID, effectIDOK := effectIDValue.(string)
			invocationIDValue, hasInvocationID := eventRecord["invocationId"]
			invocationID, invocationIDOK := invocationIDValue.(string)
			serviceValue, hasService := eventRecord["service"]
			serviceText, serviceOK := serviceValue.(string)
			operationValue, hasOperation := eventRecord["operation"]
			operation, operationOK := operationValue.(string)
			service := platformapi.SessionEffectService(serviceText)
			validService := service == platformapi.SessionEffectModel ||
				service == platformapi.SessionEffectWorkspace ||
				service == platformapi.SessionEffectExecutor ||
				service == platformapi.SessionEffectMCP ||
				service == platformapi.SessionEffectArtifact ||
				service == platformapi.SessionEffectExternalTool
			if !hasEffectID || !effectIDOK || !hasInvocationID || !invocationIDOK ||
				!hasService || !serviceOK || !validService || !hasOperation || !operationOK {
				return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
			}
			event.EffectID = effectID
			event.InvocationID = invocationID
			event.Service = service
			event.Operation = operation
			switch event.Type {
			case platformapi.EventToolExternallyCommit:
				externalCommitValue, hasExternalCommit := eventRecord["externalCommitId"]
				externalCommitID, externalCommitOK := externalCommitValue.(string)
				resultRefValue, hasResultRef := eventRecord["resultRef"]
				resultRef, resultRefOK := resultRefValue.(string)
				if len(eventRecord) != 10 || !hasExternalCommit || !externalCommitOK ||
					!hasResultRef || !resultRefOK {
					return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
				}
				event.ExternalCommitID = externalCommitID
				event.ResultRef = resultRef
			case platformapi.EventModelSettled, platformapi.EventToolSettled:
				settlementValue, hasSettlement := eventRecord["settlementKind"]
				settlementText, settlementOK := settlementValue.(string)
				settlement := platformapi.SessionSettlementKind(settlementText)
				validSettlement := settlement == platformapi.SessionSettlementSuccess ||
					settlement == platformapi.SessionSettlementError ||
					settlement == platformapi.SessionSettlementInterruptedUnknown ||
					settlement == platformapi.SessionSettlementAbandoned
				if len(eventRecord) != 9 || !hasSettlement || !settlementOK || !validSettlement {
					return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
				}
				event.SettlementKind = settlement
			default:
				if len(eventRecord) != 8 {
					return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
				}
			}
		case platformapi.EventTurnCompleted, platformapi.EventTurnFailed, platformapi.EventTurnAborted:
			if len(eventRecord) != 4 {
				return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
			}
		default:
			return platformapi.SessionPublicEventPage{}, platformapi.ErrRepositoryFailure
		}
		events = append(events, event)
	}

	return platformapi.SessionPublicEventPage{
		Snapshot: platformapi.SessionPublicEventSnapshot{
			SessionID: sessionID, ActiveTurnID: activeTurnID, TurnStatus: turnStatus,
			LastEventSequence: uint64(lastSequence),
		},
		Events: events,
	}, nil
}

func adapterClientIsNil(client any) bool {
	if client == nil {
		return true
	}
	value := reflect.ValueOf(client)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

var _ platformapi.SessionEventPageReader = (*Reader)(nil)
