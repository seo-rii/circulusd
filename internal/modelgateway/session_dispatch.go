package modelgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/effectledger"
	"github.com/hancomac/circulusd/internal/identity"
)

const (
	sessionDispatchCommandVersion = 1
	sessionDispatchResultVersion  = 1
	sessionDispatchOperation      = "model.generate"
	sessionDispatchFactTimeout    = 5 * time.Second

	// These budgets cover JSON member names, punctuation, maximum-width numbers,
	// fixed enum values, typed identities and digest arrays. Variable strings and
	// repeated message/tool envelopes are accounted for separately below.
	sessionDispatchPayloadEnvelopeBytes = 4096
	sessionDispatchResultEnvelopeBytes  = 1024
	sessionDispatchMessageEnvelopeBytes = 64
	sessionDispatchToolEnvelopeBytes    = 96
)

var sessionDispatchCommandDomain = []byte("circulusd.modelgateway.session-dispatch.v1\x00")

// SessionDispatchStarter is a reference-only adapter from the Session-owned
// single-start claim to one model provider invocation. It records immutable
// provider facts in a subordinate effect ledger, never another effect phase or
// retry authority. Production composition must replace the reference ledger
// with a separately qualified durable implementation.
type SessionDispatchStarter struct {
	gateway *Gateway
	ledger  effectledger.Ledger
	route   broker.Digest
}

// NewReferenceSessionDispatchStarter deliberately names the reference-only
// deployment status of the currently available effectledger implementation.
func NewReferenceSessionDispatchStarter(
	gateway *Gateway,
	ledger effectledger.Ledger,
	route broker.Digest,
) (*SessionDispatchStarter, error) {
	ledgerIsNil := ledger == nil
	if !ledgerIsNil {
		value := reflect.ValueOf(ledger)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			ledgerIsNil = value.IsNil()
		}
	}
	if gateway == nil || ledgerIsNil || route == (broker.Digest{}) {
		return nil, ErrInvalidConfiguration
	}
	required := requiredSessionDispatchLedgerLimits(gateway.bounds)
	limits := ledger.Limits()
	if limits.MaximumPayloadBytes < required.MaximumPayloadBytes || limits.MaximumResultBytes < required.MaximumResultBytes {
		return nil, fmt.Errorf("%w: subordinate ledger limits cannot retain the configured model JSON envelopes", ErrInvalidConfiguration)
	}
	return &SessionDispatchStarter{gateway: gateway, ledger: ledger, route: route}, nil
}

func requiredSessionDispatchLedgerLimits(bounds Bounds) effectledger.ReferenceLimits {
	// encoding/json can expand one string byte to six bytes (for example '<'
	// becomes '\u003c'). The same multiplier also covers base64 tool arguments:
	// 4*ceil(n/3) <= 6*n for every nonempty canonical argument.
	const jsonExpansion = 6
	const maximumQuotaReservationBytes = 256
	inputBytes := min(bounds.MaxInputBytes, uint64(bounds.MaxMessages)*bounds.MaxMessageBytes)
	messageCount := min(uint64(bounds.MaxMessages), inputBytes)
	payloadBytes := sessionDispatchPayloadEnvelopeBytes +
		jsonExpansion*(inputBytes+bounds.MaxModelBytes+bounds.MaxProviderIDBytes+maximumQuotaReservationBytes) +
		messageCount*sessionDispatchMessageEnvelopeBytes

	// Completion is constrained by both the response and single-event budgets.
	// normalizeToolCalls charges at least one byte each for ID, name and CBOR,
	// plus nine order bytes, which bounds the number of JSON tool envelopes.
	responseBytes := min(bounds.MaxResponseBytes, bounds.MaxEventBytes)
	toolCount := min(uint64(hardMaxEvents), responseBytes/12)
	resultBytes := sessionDispatchResultEnvelopeBytes +
		jsonExpansion*(responseBytes+bounds.MaxProviderRequestIDBytes+bounds.MaxReasonBytes) +
		toolCount*sessionDispatchToolEnvelopeBytes
	// Gateway construction caps every operand, keeping both totals within int
	// even on 32-bit targets. Incompatible reference-ledger caps fail above.
	return effectledger.ReferenceLimits{MaximumPayloadBytes: int(payloadBytes), MaximumResultBytes: int(resultBytes)}
}

func (starter *SessionDispatchStarter) RouteDigest() broker.Digest {
	if starter == nil {
		return broker.Digest{}
	}
	return starter.route
}

// Prepare stores only an already-admitted EventBeginDispatch transition. In
// particular, the caller's OpaqueAuthority and the later claimed-start bearer
// are absent from the service payload.
func (starter *SessionDispatchStarter) Prepare(
	ctx context.Context,
	dispatch broker.DispatchPermit,
	transition Transition,
) (broker.Digest, error) {
	if starter == nil || starter.gateway == nil || starter.ledger == nil || ctx == nil {
		return broker.Digest{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return broker.Digest{}, err
	}
	if dispatch.Opaque == "" {
		return broker.Digest{}, ErrAuthorityMismatch
	}
	effect, _, err := starter.gateway.validateDispatchTransition(transition)
	if err != nil {
		return broker.Digest{}, err
	}
	if err := starter.validateSessionBinding(dispatch, effect); err != nil {
		return broker.Digest{}, err
	}
	payload := sessionDispatchPayload{
		Version:                 sessionDispatchCommandVersion,
		Scope:                   effect.Scope,
		RequestDigest:           effect.RequestDigest,
		Request:                 cloneModelRequest(effect.Request),
		ProviderID:              effect.ProviderID,
		QuotaPermit:             effect.QuotaPermit,
		ContextTokens:           effect.ContextTokens,
		RequestedOutputTokens:   effect.RequestedOutputTokens,
		MaxContextTokens:        effect.MaxContextTokens,
		MaxTotalTokens:          effect.MaxTotalTokens,
		MaxPreDispatchRetries:   effect.MaxPreDispatchRetries,
		DurableRequestRetrieval: effect.DurableRequestRetrieval,
		State:                   effect.State,
		Revision:                effect.Revision,
		Attempt:                 effect.Attempt,
		EventCount:              effect.EventCount,
		EventBytes:              effect.EventBytes,
		StreamBytes:             effect.StreamBytes,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return broker.Digest{}, fmt.Errorf("%w: encode Session model command", ErrInvalidRequest)
	}
	digest := sessionDispatchCommandDigest(encoded)
	if err := starter.ledger.Prepare(ctx, effectledger.Command{
		Dispatch: dispatch, CommandDigest: digest, Payload: encoded,
	}); err != nil {
		return broker.Digest{}, fmt.Errorf("prepare Session model command: %w", err)
	}
	return digest, nil
}

// Start consumes exactly one broker-minted claimed start. It performs no
// provider retry and never calls the model gateway's independent dispatch
// claim methods. The stream is drained here so no accepted response is left
// attached to a returned-and-forgotten ProviderStream.
func (starter *SessionDispatchStarter) Start(ctx context.Context, claim broker.ClaimedDispatchStart) (startErr error) {
	if starter == nil || starter.gateway == nil || starter.ledger == nil || ctx == nil {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	start, opened := claim.Open()
	if !opened || start.Opaque == "" || start.Dispatch.Opaque == "" || !start.Durable || start.EventSequence == 0 ||
		start.CommandDigest == (broker.Digest{}) || start.Dispatch.ProviderRouteDigest != starter.route {
		return ErrDispatchNotDurable
	}
	claimed, err := starter.ledger.ClaimStart(ctx, claim)
	if err != nil {
		return fmt.Errorf("claim subordinate Session model command: %w", err)
	}
	command, commandOpened := claimed.Open()
	observation, observationOpened := claimed.Observation()
	startBinding := start.Dispatch
	startBinding.Opaque = ""
	if !commandOpened || !observationOpened || command.Dispatch != startBinding ||
		command.CommandDigest != start.CommandDigest || len(command.Payload) == 0 ||
		sessionDispatchCommandDigest(command.Payload) != start.CommandDigest {
		return ErrDispatchNotDurable
	}

	var payload sessionDispatchPayload
	if err := decodeCanonicalJSON(command.Payload, &payload); err != nil || payload.Version != sessionDispatchCommandVersion {
		return fmt.Errorf("%w: decode Session model command", ErrInvalidRequest)
	}
	effect := Effect{
		Scope: payload.Scope, RequestDigest: payload.RequestDigest,
		Request: cloneModelRequest(payload.Request), ProviderID: payload.ProviderID,
		QuotaPermit: payload.QuotaPermit, ContextTokens: payload.ContextTokens,
		RequestedOutputTokens: payload.RequestedOutputTokens, MaxContextTokens: payload.MaxContextTokens,
		MaxTotalTokens: payload.MaxTotalTokens, MaxPreDispatchRetries: payload.MaxPreDispatchRetries,
		DurableRequestRetrieval: payload.DurableRequestRetrieval, State: payload.State,
		Revision: payload.Revision, Attempt: payload.Attempt, EventCount: payload.EventCount,
		EventBytes: payload.EventBytes, StreamBytes: payload.StreamBytes,
	}
	transition := Transition{
		Effect: effect,
		Dispatch: &DispatchCommand{
			ProviderID: effect.ProviderID, Scope: effect.Scope, EffectID: effect.Scope.EffectID,
			InvocationID: effect.Scope.InvocationID, RequestDigest: effect.RequestDigest,
			QuotaPermit: effect.QuotaPermit, Request: cloneModelRequest(effect.Request), Attempt: effect.Attempt,
		},
	}
	effect, providerCommand, err := starter.gateway.validateDispatchTransition(transition)
	if err != nil {
		return err
	}
	if err := starter.validateSessionBinding(command.Dispatch, effect); err != nil {
		return err
	}

	proofHash := sha256.New()
	_, _ = proofHash.Write([]byte("circulusd.modelgateway.session-start-proof.v1\x00"))
	_, _ = proofHash.Write([]byte(start.Opaque))
	_, _ = proofHash.Write(start.CommandDigest[:])
	_, _ = proofHash.Write(starter.route[:])
	var proof OpaqueDispatchPermit
	copy(proof[:], proofHash.Sum(nil))
	if proof == (OpaqueDispatchPermit{}) {
		return ErrDispatchNotDurable
	}
	permit := DispatchPermit{
		Proof: proof, Durable: true, Scope: effect.Scope, EffectID: effect.Scope.EffectID,
		InvocationID: effect.Scope.InvocationID, RequestDigest: effect.RequestDigest,
		ProviderID: effect.ProviderID, Attempt: effect.Attempt, EffectRevision: effect.Revision,
	}
	execution, executionErr := starter.gateway.executeProviderDispatch(
		ctx, effect, providerCommand, permit,
		func(recordContext context.Context, request ProviderAcceptedCommitRequest) error {
			factContext, cancelFacts := context.WithTimeout(recordContext, sessionDispatchFactTimeout)
			defer cancelFacts()
			return starter.ledger.RecordAccepted(factContext, observation, request.Effect.ProviderRequestID)
		},
	)
	if execution.Stream != nil {
		// Retain the observed terminal result before cleanup can wait or fail.
		// Close owns a fresh finite lifetime, even when stream consumption used
		// up the dispatch context, and runs synchronously until it has finished.
		defer func() {
			startErr = errors.Join(startErr, execution.Stream.Close(context.WithoutCancel(ctx)))
		}()
	}
	current := execution.Effect
	if current.Scope == (ValidatedAuthority{}) {
		current = effect
	}
	accepted := current.ProviderRequestID != ""
	terminalStatus := effectledger.TerminalUnknown
	returnUnknown := executionErr != nil

	if execution.Failure != nil {
		failure := *execution.Failure
		failure.ExpectedRevision = current.Revision
		applied, applyErr := starter.gateway.Apply(current, failure)
		if applyErr != nil {
			returnUnknown = true
		} else {
			current = applied.Effect
			switch failure.Failure {
			case FailurePreDispatch, FailureProviderRejected:
				terminalStatus = effectledger.TerminalFailed
			default:
				terminalStatus = effectledger.TerminalUnknown
			}
		}
		if !accepted {
			returnUnknown = true
		}
	} else if executionErr == nil && execution.Stream != nil {
		for {
			event, nextErr := execution.Stream.Next(ctx)
			if nextErr != nil {
				terminalStatus = effectledger.TerminalUnknown
				if !errors.Is(nextErr, io.EOF) {
					returnUnknown = false
				}
				break
			}
			event.ExpectedRevision = current.Revision
			applied, applyErr := starter.gateway.Apply(current, event)
			if applyErr != nil {
				terminalStatus = effectledger.TerminalUnknown
				break
			}
			current = applied.Effect
			switch event.Kind {
			case EventResponseCompleted:
				terminalStatus = effectledger.TerminalCommitted
			case EventDispatchFailed:
				switch event.Failure {
				case FailurePreDispatch, FailureProviderRejected:
					terminalStatus = effectledger.TerminalFailed
				default:
					terminalStatus = effectledger.TerminalUnknown
				}
			}
			if event.Kind == EventResponseCompleted || event.Kind == EventDispatchFailed {
				break
			}
		}
	} else {
		returnUnknown = true
	}

	wire := sessionDispatchResultWire{
		Version: sessionDispatchResultVersion, State: current.State, Outcome: current.Outcome,
		Revision: current.Revision, Attempt: current.Attempt, EventCount: current.EventCount,
		EventBytes: current.EventBytes, StreamBytes: current.StreamBytes,
		ProviderRequestID: current.ProviderRequestID, PartialOutput: current.PartialOutput,
		FailureReason: current.FailureReason,
	}
	if current.Response != nil {
		wire.Response = &sessionModelResponseWire{
			Text: current.Response.Text, FinishReason: current.Response.FinishReason,
			Usage: current.Response.Usage, ToolCalls: make([]sessionToolCallWire, len(current.Response.ToolCalls)),
		}
		for index, call := range current.Response.ToolCalls {
			wire.Response.ToolCalls[index] = sessionToolCallWire{
				ID: call.ID, Name: call.Name, Arguments: call.Arguments.Bytes(), Order: call.Order,
			}
		}
	}
	result, err := json.Marshal(wire)
	if err != nil {
		return fmt.Errorf("%w: encode Session model result", ErrInvalidRequest)
	}
	factContext, cancelFacts := context.WithTimeout(context.WithoutCancel(ctx), sessionDispatchFactTimeout)
	defer cancelFacts()
	if _, err := starter.ledger.RecordTerminal(factContext, observation, effectledger.Terminal{
		Status: terminalStatus, Result: result,
	}); err != nil {
		return fmt.Errorf("record Session model terminal fact: %w", err)
	}
	if returnUnknown || !accepted {
		return errors.Join(fmt.Errorf("%w: provider start has no durable acceptance", ErrProviderUnavailable), executionErr)
	}
	return nil
}

// SessionDispatchResult is the bounded provider observation retained by the
// subordinate ledger. It is data for a fresh Session recovery actor, not
// authority to settle or restart the effect.
type SessionDispatchResult struct {
	State             State
	Outcome           Outcome
	Revision          uint64
	Attempt           uint32
	EventCount        uint32
	EventBytes        uint64
	StreamBytes       uint64
	ProviderRequestID string
	PartialOutput     bool
	FailureReason     string
	Response          *ModelResponse
}

func DecodeSessionDispatchResult(encoded []byte) (SessionDispatchResult, error) {
	if len(encoded) == 0 || uint64(len(encoded)) > hardMaxResponseBytes+hardMaxInputBytes+hardMaxEventBytes {
		return SessionDispatchResult{}, ErrInvalidRequest
	}
	var wire sessionDispatchResultWire
	if err := decodeCanonicalJSON(encoded, &wire); err != nil || wire.Version != sessionDispatchResultVersion ||
		wire.Attempt == 0 || wire.Revision == 0 {
		return SessionDispatchResult{}, ErrInvalidRequest
	}
	result := SessionDispatchResult{
		State: wire.State, Outcome: wire.Outcome, Revision: wire.Revision, Attempt: wire.Attempt,
		EventCount: wire.EventCount, EventBytes: wire.EventBytes, StreamBytes: wire.StreamBytes,
		ProviderRequestID: wire.ProviderRequestID, PartialOutput: wire.PartialOutput,
		FailureReason: wire.FailureReason,
	}
	if wire.Response != nil {
		result.Response = &ModelResponse{
			Text: wire.Response.Text, FinishReason: wire.Response.FinishReason,
			Usage: wire.Response.Usage, ToolCalls: make([]ToolCall, len(wire.Response.ToolCalls)),
		}
		for index, call := range wire.Response.ToolCalls {
			arguments, err := ParseCanonicalToolArguments(call.Arguments)
			if err != nil {
				return SessionDispatchResult{}, ErrInvalidRequest
			}
			result.Response.ToolCalls[index] = ToolCall{
				ID: call.ID, Name: call.Name, Arguments: arguments, Order: call.Order,
			}
		}
	}
	return result, nil
}

func (starter *SessionDispatchStarter) validateSessionBinding(dispatch broker.DispatchPermit, effect Effect) error {
	if starter == nil || !dispatch.Durable || dispatch.EventSequence == 0 ||
		dispatch.Service != broker.ServiceModel || dispatch.ProviderRouteDigest != starter.route ||
		dispatch.TenantID != effect.Scope.TenantID || dispatch.UserID != effect.Scope.UserID ||
		dispatch.SessionID != effect.Scope.SessionID || dispatch.TurnID != effect.Scope.TurnID ||
		dispatch.EffectID != effect.Scope.EffectID || dispatch.InvocationID != effect.Scope.InvocationID ||
		dispatch.RequestDigest != broker.Digest(effect.RequestDigest) ||
		dispatch.Generations.TurnLease != effect.Scope.Generations.TurnLease ||
		dispatch.Generations.Placement != effect.Scope.Generations.Placement ||
		dispatch.Generations.Authorization != effect.Scope.Generations.Policy ||
		dispatch.Generations.Sandbox == 0 || dispatch.DispatchAttempt == 0 ||
		dispatch.DispatchAttempt > math.MaxUint32 || uint32(dispatch.DispatchAttempt) != effect.Attempt ||
		dispatch.WorkspaceID.Kind() != identity.Workspace || dispatch.Operation != sessionDispatchOperation ||
		dispatch.Ordinal == 0 || dispatch.Deadline.IsZero() ||
		(dispatch.ProviderRequestID != (identity.ID{}) && dispatch.ProviderRequestID.Kind() != identity.Request) {
		return ErrAuthorityMismatch
	}
	return nil
}

func sessionDispatchCommandDigest(payload []byte) broker.Digest {
	digest := sha256.New()
	_, _ = digest.Write(sessionDispatchCommandDomain)
	_, _ = digest.Write(payload)
	var result broker.Digest
	copy(result[:], digest.Sum(nil))
	return result
}

func decodeCanonicalJSON[T any](encoded []byte, target *T) error {
	if len(encoded) == 0 || target == nil {
		return ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrInvalidRequest
	}
	return nil
}

type sessionDispatchPayload struct {
	Version                 uint64
	Scope                   ValidatedAuthority
	RequestDigest           Digest
	Request                 ModelRequest
	ProviderID              string
	QuotaPermit             QuotaPermit
	ContextTokens           uint64
	RequestedOutputTokens   uint64
	MaxContextTokens        uint64
	MaxTotalTokens          uint64
	MaxPreDispatchRetries   uint32
	DurableRequestRetrieval bool
	State                   State
	Revision                uint64
	Attempt                 uint32
	EventCount              uint32
	EventBytes              uint64
	StreamBytes             uint64
}

type sessionDispatchResultWire struct {
	Version           uint64
	State             State
	Outcome           Outcome
	Revision          uint64
	Attempt           uint32
	EventCount        uint32
	EventBytes        uint64
	StreamBytes       uint64
	ProviderRequestID string
	PartialOutput     bool
	FailureReason     string
	Response          *sessionModelResponseWire
}

type sessionModelResponseWire struct {
	Text         string
	FinishReason FinishReason
	Usage        Usage
	ToolCalls    []sessionToolCallWire
}

type sessionToolCallWire struct {
	ID        string
	Name      string
	Arguments []byte
	Order     ToolCallOrder
}
