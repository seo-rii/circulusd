package modelgateway

import (
	"context"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/identity"
)

// ProviderAvailability is evaluated before quota admission. Durable request
// retrieval permits an explicit recovery adapter; it never enables automatic
// replay of a partially streamed request.
type ProviderAvailability struct {
	Available               bool
	Reason                  string
	DurableRequestRetrieval bool
}

type ProviderEventKind string

const (
	ProviderEventDelta             ProviderEventKind = "delta"
	ProviderEventResponseCompleted ProviderEventKind = "response_completed"
	ProviderEventFailed            ProviderEventKind = "failed"
)

// ProviderResponse is the narrow, untrusted success payload accepted from a
// provider adapter. The gateway converts it to a normalized ModelResponse.
type ProviderResponse struct {
	Text         string
	FinishReason string
	Usage        Usage
	ToolCalls    []ToolCall
}

// ProviderEvent intentionally cannot express gateway control-plane events,
// revisions, cancellation proofs, or recovery proofs. Diagnostic is never
// propagated across the provider credential boundary.
type ProviderEvent struct {
	Kind       ProviderEventKind
	Delta      string
	Response   *ProviderResponse
	Failure    FailureClass
	Diagnostic string
}

// ProviderStream leaves network framing in a provider adapter while exposing
// only the narrow provider-neutral data plane above. Close must release its
// owned resources and return by the supplied context's cancellation/deadline;
// it must not leave an unobserved background cleanup task behind. The gateway
// always supplies a finite cleanup context.
type ProviderStream interface {
	Next(context.Context) (ProviderEvent, error)
	Close(context.Context) error
}

// EventStream contains gateway-normalized events safe to apply to an Effect.
// Close honors the caller's context and the configured stream cleanup bound.
type EventStream interface {
	Next(context.Context) (Event, error)
	Close(context.Context) error
}

// ProviderDispatchResult carries the stable request identity. A successful or
// possibly accepted Dispatch returns this ID immediately, including alongside
// an error. The returned stream starts after request acceptance and must not
// repeat EventProviderAccepted. This lets the gateway durably store the ID
// before exposing any response bytes.
type ProviderDispatchResult struct {
	ProviderRequestID string
	Stream            ProviderStream
}

// ProviderResumeCommand identifies an already-created provider request. A
// retriever must fetch/resume only this request and MUST NOT initiate a new
// model inference when the request is absent or indeterminate.
type ProviderResumeCommand struct {
	ProviderID        string
	Scope             ValidatedAuthority
	OriginScope       ValidatedAuthority
	EffectID          identity.ID
	InvocationID      identity.ID
	RequestDigest     Digest
	ProviderRequestID string
	Attempt           uint32
	Permit            ResumePermit
}

// ProviderRequestRetriever is an optional, provider-verified durable
// request/result retrieval contract. Resume MUST be idempotent and must not
// turn absence into a new inference. Advertising DurableRequestRetrieval
// without implementing this interface fails closed during admission.
type ProviderRequestRetriever interface {
	Resume(context.Context, ProviderResumeCommand) (ProviderStream, error)
}

type ProviderCancellation struct {
	// DispatchPrevented is advisory only. The gateway classifies a request as
	// definitely not sent solely from a durable CancellationPermit issued before
	// BeginProviderDispatch wins; provider error/result strings are not proofs.
	DispatchPrevented bool
}

// ProviderDispatchFailureClass distinguishes cryptographic/transport proof
// that no provider request was sent from the conservative unknown case.
type ProviderDispatchFailureClass string

const (
	DispatchFailureDefinitelyNotSent ProviderDispatchFailureClass = "definitely_not_sent"
	DispatchFailureUnknown           ProviderDispatchFailureClass = "unknown"
)

type ProviderDispatchError struct {
	class  ProviderDispatchFailureClass
	reason string
	cause  error
}

func NewProviderDispatchError(class ProviderDispatchFailureClass, reason string, cause error) (*ProviderDispatchError, error) {
	switch class {
	case DispatchFailureDefinitelyNotSent, DispatchFailureUnknown:
	default:
		return nil, fmt.Errorf("%w: invalid provider dispatch failure class", ErrInvalidRequest)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || !utf8.ValidString(reason) || strings.IndexFunc(reason, unicode.IsControl) >= 0 || len(reason) > hardMaxReasonBytes {
		return nil, fmt.Errorf("%w: provider dispatch failure reason is required and bounded", ErrInvalidRequest)
	}
	return &ProviderDispatchError{class: class, reason: reason, cause: cause}, nil
}

func (failure *ProviderDispatchError) Error() string {
	if failure == nil {
		return "model provider dispatch failure"
	}
	return failure.reason
}

func (failure *ProviderDispatchError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

func (failure *ProviderDispatchError) Classification() ProviderDispatchFailureClass {
	if failure == nil {
		return DispatchFailureUnknown
	}
	return failure.class
}

// Provider is the only interface through which endpoint credentials and
// provider-specific transport should be used. This package intentionally ships
// no network-capable provider.
type Provider interface {
	Availability(context.Context) (ProviderAvailability, error)
	Dispatch(context.Context, DispatchCommand) (ProviderDispatchResult, error)
	Cancel(context.Context, CancelCommand) (ProviderCancellation, error)
}

type unavailableProvider struct {
	reason string
}

func NewUnavailableProvider(reason string) (Provider, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || !utf8.ValidString(reason) || strings.IndexFunc(reason, unicode.IsControl) >= 0 || len(reason) > 512 {
		return nil, fmt.Errorf("%w: unavailable provider reason is required and bounded", ErrInvalidConfiguration)
	}
	return unavailableProvider{reason: reason}, nil
}

func (provider unavailableProvider) Availability(context.Context) (ProviderAvailability, error) {
	return ProviderAvailability{Available: false, Reason: provider.reason}, nil
}

func (provider unavailableProvider) Dispatch(context.Context, DispatchCommand) (ProviderDispatchResult, error) {
	return ProviderDispatchResult{}, fmt.Errorf("%w: %s", ErrProviderUnavailable, provider.reason)
}

func (provider unavailableProvider) Cancel(context.Context, CancelCommand) (ProviderCancellation, error) {
	return ProviderCancellation{}, fmt.Errorf("%w: %s", ErrProviderUnavailable, provider.reason)
}
