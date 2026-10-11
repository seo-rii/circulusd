//go:build linux

// Package referenceworkload implements reference-only broker dispatch handoff.
// Its bounded guards are process-local and never prove restart durability.
package referenceworkload

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/controlrpc"
	"github.com/hancomac/circulusd/internal/identity"
)

const maximumReferenceClaims = 4096

// ReferenceWorkloadResult is an observed executor result, not a durable receipt.
// The platform-side return sink must confirm and settle it through its authority.
type ReferenceWorkloadResult struct {
	ExternalCommitID identity.ID
	ResultRef        identity.ID
	Result           []byte
}

func (ReferenceWorkloadResult) String() string   { return "reference-workload-result<redacted>" }
func (ReferenceWorkloadResult) GoString() string { return "reference-workload-result<redacted>" }

var receivedDispatchSeal = new(struct{})

// ReceivedDispatchStart proves only authentication by this private RPC handler.
// It cannot be converted into broker.ClaimedDispatchStart and is not proof of
// durable single-start ownership. The caller-side Session claim remains owner.
type ReceivedDispatchStart struct {
	permit  broker.DispatchStartPermit
	command []byte
	seal    *struct{}
}

// Open returns authenticated transport metadata and a command snapshot. The
// permit fields, including Durable, report the sender claim; this is not a fresh
// state proof and never carries the private broker start seal.
func (start ReceivedDispatchStart) Open() (broker.DispatchStartPermit, []byte, bool) {
	if start.seal != receivedDispatchSeal {
		return broker.DispatchStartPermit{}, nil, false
	}
	return start.permit, bytes.Clone(start.command), true
}
func (ReceivedDispatchStart) String() string   { return "received-reference-dispatch<redacted>" }
func (ReceivedDispatchStart) GoString() string { return "received-reference-dispatch<redacted>" }

type ReferenceWorkloadReturnSink interface {
	ConfirmExternalCommit(context.Context, broker.ClaimedDispatchStart, ReferenceWorkloadResult) error
	SettleEffect(context.Context, broker.ClaimedDispatchStart, ReferenceWorkloadResult) error
}

// These guards are bounded, process-local reference evidence only. Entries are
// never evicted: exhaustion rejects new work instead of permitting old replay.
// Reconstructing a guard is not a durable restart protocol.
type referenceAttemptKey struct {
	effect, invocation identity.ID
	attempt            uint64
}
type referenceClaimGuard struct {
	mu      sync.Mutex
	maximum int
	claims  map[referenceAttemptKey]broker.Digest
}

func newReferenceClaimGuard(maximum int) (*referenceClaimGuard, error) {
	if maximum < 1 || maximum > maximumReferenceClaims {
		return nil, broker.ErrInvalidRequest
	}
	return &referenceClaimGuard{maximum: maximum, claims: make(map[referenceAttemptKey]broker.Digest)}, nil
}
func (guard *referenceClaimGuard) consume(permit broker.DispatchStartPermit, body broker.Digest) error {
	key := referenceAttemptKey{permit.Dispatch.EffectID, permit.Dispatch.InvocationID, permit.Dispatch.DispatchAttempt}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if previous, exists := guard.claims[key]; exists {
		if previous != body {
			return connect.NewError(connect.CodeAlreadyExists, errors.New("claimed attempt identity conflicts"))
		}
		return connect.NewError(connect.CodeAlreadyExists, broker.ErrDispatchAlreadyStarted)
	}
	if len(guard.claims) >= guard.maximum {
		return connect.NewError(connect.CodeResourceExhausted, errors.New("reference claim capacity exhausted"))
	}
	guard.claims[key] = body
	return nil
}

type ReferenceWorkloadHandlerConfig struct {
	Service       broker.EffectService
	RouteDigest   broker.Digest
	MaximumClaims int
	Execute       func(context.Context, ReceivedDispatchStart) (ReferenceWorkloadResult, error)
}
type ReferenceWorkloadHandler struct {
	transport *controlrpc.ReferenceWorkloadService
	service   broker.EffectService
	route     broker.Digest
	guard     *referenceClaimGuard
	execute   func(context.Context, ReceivedDispatchStart) (ReferenceWorkloadResult, error)
}

// NewReferenceWorkloadHandler constructs a reference executor boundary. Its
// process-local duplicate guard does not establish restart durability or validate
// a fresh Session proof; production handoff requires an authoritative protocol.
func NewReferenceWorkloadHandler(config ReferenceWorkloadHandlerConfig) (*ReferenceWorkloadHandler, error) {
	guard, err := newReferenceClaimGuard(config.MaximumClaims)
	if err != nil || config.Execute == nil || workloadService(config.Service) == 0 || config.RouteDigest == (broker.Digest{}) {
		return nil, broker.ErrInvalidRequest
	}
	handler := &ReferenceWorkloadHandler{service: config.Service, route: config.RouteDigest, guard: guard, execute: config.Execute}
	handler.transport, err = controlrpc.NewReferenceWorkloadService(handler.receive)
	if err != nil {
		return nil, err
	}
	return handler, nil
}

type ReferenceDispatchStarterConfig struct {
	Client        *controlrpc.Client
	Service       broker.EffectService
	RouteDigest   broker.Digest
	MaximumClaims int
	// Command is a read-only loader, never provider I/O. Its returned bytes are
	// cloned before validation or transport; the loader may run on a replay.
	Command    func(context.Context, broker.DispatchStartPermit) ([]byte, error)
	ReturnSink ReferenceWorkloadReturnSink
}
type ReferenceDispatchStarter struct {
	client  *controlrpc.ReferenceWorkloadClient
	service broker.EffectService
	route   broker.Digest
	guard   *referenceClaimGuard
	command func(context.Context, broker.DispatchStartPermit) ([]byte, error)
	sink    ReferenceWorkloadReturnSink
}

func NewReferenceDispatchStarter(config ReferenceDispatchStarterConfig) (*ReferenceDispatchStarter, error) {
	guard, err := newReferenceClaimGuard(config.MaximumClaims)
	if err != nil || config.Client == nil ||
		workloadService(config.Service) == 0 || config.RouteDigest == (broker.Digest{}) || config.Command == nil || config.ReturnSink == nil {
		return nil, broker.ErrInvalidRequest
	}
	value := reflect.ValueOf(config.ReturnSink)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, broker.ErrInvalidRequest
		}
	}
	client, err := controlrpc.NewReferenceWorkloadClient(config.Client)
	if err != nil {
		return nil, broker.ErrInvalidRequest
	}
	return &ReferenceDispatchStarter{client: client, service: config.Service, route: config.RouteDigest, guard: guard, command: config.Command, sink: config.ReturnSink}, nil
}
func (starter *ReferenceDispatchStarter) RouteDigest() broker.Digest {
	if starter == nil {
		return broker.Digest{}
	}
	return starter.route
}
func cloneReferenceWorkloadResult(result ReferenceWorkloadResult) ReferenceWorkloadResult {
	result.Result = bytes.Clone(result.Result)
	return result
}

func (starter *ReferenceDispatchStarter) Start(ctx context.Context, claim broker.ClaimedDispatchStart) error {
	if starter == nil || starter.client == nil || starter.guard == nil || starter.command == nil || starter.sink == nil || ctx == nil {
		return broker.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	permit, ok := claim.Open()
	if !ok || permit.Dispatch.Service != starter.service || permit.Dispatch.ProviderRouteDigest != starter.route {
		return broker.ErrFenceMismatch
	}
	wireClaim, err := encodeWorkloadClaim(permit)
	if err != nil {
		return err
	}
	command, err := starter.command(ctx, permit)
	if err != nil {
		return err
	}
	command = bytes.Clone(command)
	digest, err := ReferenceWorkloadCommandDigest(command)
	if err != nil || digest != permit.CommandDigest {
		return broker.ErrFenceMismatch
	}
	body, err := workloadBodyDigest(wireClaim, command)
	if err != nil {
		return err
	}
	if err := starter.guard.consume(permit, body); err != nil {
		return err
	}
	wireResult, err := starter.client.Start(ctx, wireClaim, command)
	if err != nil {
		return err
	}
	result, err := decodeWorkloadResult(wireResult)
	if err != nil {
		return connect.NewError(connect.CodeDataLoss, errors.New("invalid workload result"))
	}
	if err := starter.sink.ConfirmExternalCommit(ctx, claim, cloneReferenceWorkloadResult(result)); err != nil {
		return err
	}
	return starter.sink.SettleEffect(ctx, claim, cloneReferenceWorkloadResult(result))
}

// Transport exposes only the explicit reference wire service. It conveys no
// durable authority and can be installed only on eligible control RPC roles.
func (handler *ReferenceWorkloadHandler) Transport() *controlrpc.ReferenceWorkloadService {
	if handler == nil {
		return nil
	}
	return handler.transport
}

func (handler *ReferenceWorkloadHandler) receive(ctx context.Context, claim *v1.ReferenceWorkloadClaim, command []byte) (*v1.ReferenceWorkloadResult, error) {
	permit, err := decodeWorkloadClaim(claim)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid workload claim"))
	}
	digest, err := ReferenceWorkloadCommandDigest(command)
	if err != nil || digest != permit.CommandDigest || permit.Dispatch.Service != handler.service || permit.Dispatch.ProviderRouteDigest != handler.route {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("workload command or route mismatch"))
	}
	body, err := workloadBodyDigest(claim, command)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid workload body"))
	}
	if err := handler.guard.consume(permit, body); err != nil {
		return nil, err
	}
	result, err := handler.execute(ctx, ReceivedDispatchStart{permit: permit, command: bytes.Clone(command), seal: receivedDispatchSeal})
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("reference executor outcome is unproven"))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	wireResult, err := encodeWorkloadResult(result)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("reference executor returned invalid result"))
	}
	return wireResult, nil
}

var _ broker.DispatchStarter = (*ReferenceDispatchStarter)(nil)
