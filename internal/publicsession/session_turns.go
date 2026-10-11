package publicsession

import (
	"context"
	"reflect"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/idempotency"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/sessionadmission"
	"golang.org/x/text/unicode/norm"
)

const maximumSessionTurnInputBytes = 1 << 20

type SessionTurnAdmission = sessionadmission.SessionTurnAdmission
type SessionTurnAdmissionResult = sessionadmission.SessionTurnAdmissionResult
type SessionTurnStore = sessionadmission.SessionTurnStore

type SessionTurnServiceConfig struct {
	Store               dependency.Verified[SessionTurnStore]
	SessionEvents       dependency.Verified[SessionEventPageReader]
	Authorizer          Authorizer
	IdempotencySecret   []byte
	MaximumMessageBytes int
	NewTurnID           func() (string, error)
}

// SessionTurnService admits turns through verified state adapters. It has no
// reference-memory override and never appends a second public event journal.
type SessionTurnService struct {
	store               SessionTurnStore
	storeBinding        dependency.Verified[SessionTurnStore]
	authorizer          Authorizer
	idempotencySecret   []byte
	maximumMessageBytes int
	newTurnID           func() (string, error)
}

var _ TurnAdmitter = (*SessionTurnService)(nil)

func NewSessionTurnService(config SessionTurnServiceConfig) (*SessionTurnService, error) {
	if config.Authorizer == nil || len(config.IdempotencySecret) < 32 ||
		config.MaximumMessageBytes < 1 || config.MaximumMessageBytes > maximumSessionTurnInputBytes {
		return nil, ErrInvalidConfig
	}
	authorizerValue := reflect.ValueOf(config.Authorizer)
	switch authorizerValue.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if authorizerValue.IsNil() {
			return nil, ErrInvalidConfig
		}
	}
	store, _, err := config.Store.Open()
	if err != nil {
		return nil, ErrRepositoryNotDurable
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{
		dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent,
	}, config.Store, config.SessionEvents); err != nil {
		return nil, ErrRepositoryNotDurable
	}
	newTurnID := config.NewTurnID
	if newTurnID == nil {
		newTurnID = func() (string, error) {
			id, err := identity.New(identity.Turn)
			return id.String(), err
		}
	}
	return &SessionTurnService{
		store: store, storeBinding: config.Store, authorizer: config.Authorizer,
		idempotencySecret:   append([]byte(nil), config.IdempotencySecret...),
		maximumMessageBytes: config.MaximumMessageBytes, newTurnID: newTurnID,
	}, nil
}

func (service *SessionTurnService) validateEventService(events *SessionEventService) error {
	if service == nil || events == nil {
		return ErrRepositoryNotDurable
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{
		dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent,
	}, service.storeBinding, events.readerBinding); err != nil {
		return ErrRepositoryNotDurable
	}
	return nil
}

func (service *SessionTurnService) CreateTurn(ctx context.Context, request CreateTurnRequest) (CreateTurnResult, error) {
	if ctx == nil {
		return CreateTurnResult{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return CreateTurnResult{}, err
	}
	if service == nil || service.store == nil || service.authorizer == nil {
		return CreateTurnResult{}, ErrInvalidConfig
	}
	if ValidatePrincipal(request.Principal) != nil || len(request.Messages) < 1 || len(request.Messages) > maximumMessages {
		return CreateTurnResult{}, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Session, request.SessionID); err != nil {
		return CreateTurnResult{}, ErrInvalidRequest
	}
	// Snapshot before calling the authorizer so an asynchronous dependency cannot
	// race caller mutation of the message slice or alter its digest binding.
	messages := append([]Message(nil), request.Messages...)
	requestMessages := make(canonical.Array, 0, len(messages))
	inputMessages := make(canonical.Array, 0, len(messages))
	totalBytes := 0
	for _, message := range messages {
		if message.Role != "user" || message.Content == "" || !utf8.ValidString(message.Content) || !norm.NFC.IsNormalString(message.Content) {
			return CreateTurnResult{}, ErrInvalidRequest
		}
		totalBytes += len(message.Content)
		if totalBytes > service.maximumMessageBytes {
			return CreateTurnResult{}, ErrInvalidRequest
		}
		requestMessages = append(requestMessages, canonical.Array{message.Role, message.Content})
		inputMessages = append(inputMessages, canonical.Map{"role": message.Role, "content": message.Content})
	}
	keyDigest, err := idempotency.DigestKey(service.idempotencySecret, request.IdempotencyKey)
	if err != nil {
		return CreateTurnResult{}, ErrInvalidRequest
	}
	requestDigest, err := canonical.StructuredDigest("circulusd.public.turn.create", 1, canonical.Map{
		"sessionId": request.SessionID, "messages": requestMessages,
	})
	if err != nil {
		return CreateTurnResult{}, ErrInvalidRequest
	}
	input := canonical.Map{"messages": inputMessages}
	if _, err := canonical.Encode(input, canonical.Options{
		MaxDepth: 64, MaxBytes: maximumSessionTurnInputBytes, MaxItems: 100_000,
	}); err != nil {
		return CreateTurnResult{}, ErrInvalidRequest
	}
	inputDigest, err := canonical.StructuredDigest("circulusd.session.turn-input", 1, input)
	if err != nil {
		return CreateTurnResult{}, ErrInvalidRequest
	}
	authorizationRequest := AuthorizationRequest{
		Operation: OperationCreateTurn, Principal: request.Principal, SessionID: request.SessionID,
	}
	permit, err := service.authorizer.Authorize(ctx, authorizationRequest)
	if contextErr := ctx.Err(); contextErr != nil {
		return CreateTurnResult{}, contextErr
	}
	if err != nil || ValidateAuthorizationPermit(permit, authorizationRequest) != nil {
		return CreateTurnResult{}, ErrAccessDenied
	}
	turnID, err := service.newTurnID()
	if err != nil {
		return CreateTurnResult{}, ErrRepositoryFailure
	}
	if _, err := identity.Parse(identity.Turn, turnID); err != nil {
		return CreateTurnResult{}, ErrRepositoryFailure
	}
	result, err := service.store.AdmitTurn(ctx, SessionTurnAdmission{
		Authorization: permit, ProposedTurnID: turnID, KeyDigest: keyDigest, RequestDigest: requestDigest,
		Input: input, InputDigest: inputDigest,
	})
	if contextErr := ctx.Err(); contextErr != nil {
		return CreateTurnResult{}, contextErr
	}
	if err != nil {
		return CreateTurnResult{}, RepositoryError(ctx, err)
	}
	if _, err := identity.Parse(identity.Turn, result.TurnID); err != nil ||
		result.TurnSequence > maximumSharedInteger || (!result.Deduplicated && result.TurnID != turnID) {
		return CreateTurnResult{}, ErrRepositoryFailure
	}
	status := TurnQueued
	if result.Activated {
		status = TurnActive
	}
	return CreateTurnResult{
		Turn: Turn{
			ID: result.TurnID, TenantID: request.Principal.TenantID, SubjectID: request.Principal.SubjectID,
			SessionID: request.SessionID, RequestDigest: requestDigest, Status: status,
		}, Deduplicated: result.Deduplicated,
	}, nil
}
