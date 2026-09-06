package broker

import (
	"context"
	"reflect"
	"time"
)

// DispatchAdmitter admits an effect dispatch through the durable state plane.
// *Coordinator satisfies it via AdmitDispatch. It is the platformd-owned durable
// admission half of the workload composition.
type DispatchAdmitter interface {
	AdmitDispatch(context.Context, DispatchRequest) (DispatchPermit, error)
}

// WorkloadDispatcher is the private platformd workload entry point (Unit 14). It
// composes the two durable steps of one out-of-process effect: it admits the
// dispatch through the durable store (DispatchAdmitter) and then hands the
// resulting durable permit to the DispatchConsumer, which claims the single
// start and runs the agentd/executord provider. It performs no retry of its own:
// AdmitDispatch is durable and operation-keyed and StartExactAttempt is
// exactly-once, so a replayed Dispatch never starts the provider twice. It is
// the seam cmd/platformd backs with a celld-backed DurableStore and a
// controlrpc-transported DispatchStarter; the reference tests wire it over the
// in-process reference store and a reference starter and promote nothing.
type WorkloadDispatcher struct {
	admitter DispatchAdmitter
	consumer *DispatchConsumer
}

// WorkloadDispatch is one immutable workload dispatch request: the durable
// admission inputs plus the start-authority fence, transaction time, and command
// digest the consumer binds to the returned permit.
type WorkloadDispatch struct {
	Dispatch      DispatchRequest
	Authority     ValidatedTurnFence
	Now           time.Time
	CommandDigest Digest
}

// NewWorkloadDispatcher validates that both halves of the composition are
// present. A nil admitter (including a typed-nil interface value) or a nil
// consumer is rejected before any dispatch can run.
func NewWorkloadDispatcher(admitter DispatchAdmitter, consumer *DispatchConsumer) (*WorkloadDispatcher, error) {
	if consumer == nil || isNilAdmitter(admitter) {
		return nil, ErrInvalidRequest
	}
	return &WorkloadDispatcher{admitter: admitter, consumer: consumer}, nil
}

// Dispatch admits the effect and then claims and starts the single provider
// attempt. Any admission error is returned before the consumer is reached; once
// the durable permit exists, exactly-once and replay semantics are the
// DispatchConsumer's. Dispatch never retries.
func (dispatcher *WorkloadDispatcher) Dispatch(
	ctx context.Context,
	request WorkloadDispatch,
) (DispatchStartExecution, error) {
	if dispatcher == nil || ctx == nil {
		return DispatchStartExecution{}, ErrInvalidRequest
	}
	permit, err := dispatcher.admitter.AdmitDispatch(ctx, request.Dispatch)
	if err != nil {
		return DispatchStartExecution{}, err
	}
	return dispatcher.consumer.StartExactAttempt(ctx, DispatchStartRequest{
		Authority:     request.Authority,
		Now:           request.Now,
		Dispatch:      permit,
		CommandDigest: request.CommandDigest,
	})
}

func isNilAdmitter(admitter DispatchAdmitter) bool {
	if admitter == nil {
		return true
	}
	value := reflect.ValueOf(admitter)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
