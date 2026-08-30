package broker

import (
	"context"
	"fmt"
	"reflect"
	"time"
)

const maximumDispatchStartTimeout = 5 * time.Minute

// DispatchConsumer owns the complete durable-claim-to-provider-start boundary.
// Its registry is immutable after construction and every starter must honor
// the finite context supplied to Start.
type DispatchConsumer struct {
	claimer  DispatchStartClaimer
	starters map[EffectService]dispatchStarterBinding
	timeout  time.Duration
}

// DispatchStartClaimer is the narrow durability boundary required before any
// provider start. Coordinator and external authoritative adapters both satisfy
// it without granting the consumer access to unrelated state mutations.
type DispatchStartClaimer interface {
	ClaimDispatchStart(context.Context, DispatchStartRequest) (DispatchStartClaim, error)
}

type dispatchStarterBinding struct {
	starter     DispatchStarter
	routeDigest Digest
}

func NewDispatchConsumer(
	claimer DispatchStartClaimer,
	starters map[EffectService]DispatchStarter,
	timeout time.Duration,
) (*DispatchConsumer, error) {
	claimerIsNil := claimer == nil
	if !claimerIsNil {
		value := reflect.ValueOf(claimer)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			claimerIsNil = value.IsNil()
		}
	}
	if claimerIsNil || timeout <= 0 || timeout > maximumDispatchStartTimeout || len(starters) == 0 {
		return nil, ErrDispatchStarterUnavailable
	}
	registry := make(map[EffectService]dispatchStarterBinding, len(starters))
	for service, starter := range starters {
		starterIsNil := starter == nil
		if !starterIsNil {
			value := reflect.ValueOf(starter)
			switch value.Kind() {
			case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
				starterIsNil = value.IsNil()
			}
		}
		if !validService(service) || starterIsNil {
			return nil, ErrDispatchStarterUnavailable
		}
		routeDigest := starter.RouteDigest()
		if routeDigest == (Digest{}) {
			return nil, ErrDispatchStarterUnavailable
		}
		registry[service] = dispatchStarterBinding{starter: starter, routeDigest: routeDigest}
	}
	return &DispatchConsumer{claimer: claimer, starters: registry, timeout: timeout}, nil
}

// StartExactAttempt makes no provider retry. Once the durable store returns a
// fresh claim, caller cancellation is detached and replaced with the finite
// consumer timeout so authority expiry cannot interrupt already-admitted
// external progress. Any starter error leaves the exact attempt unknown.
func (consumer *DispatchConsumer) StartExactAttempt(
	ctx context.Context,
	request DispatchStartRequest,
) (DispatchStartExecution, error) {
	if consumer == nil || ctx == nil {
		return DispatchStartExecution{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return DispatchStartExecution{}, err
	}
	binding, found := consumer.starters[request.Dispatch.Service]
	if !found {
		return DispatchStartExecution{}, ErrDispatchStarterUnavailable
	}
	if request.Dispatch.ProviderRouteDigest != binding.routeDigest {
		return DispatchStartExecution{}, ErrFenceMismatch
	}
	claim, err := consumer.claimer.ClaimDispatchStart(ctx, request)
	if err != nil {
		return DispatchStartExecution{}, err
	}
	if claim.Permit.Opaque == "" || !claim.Permit.Durable || claim.Permit.EventSequence == 0 ||
		claim.Permit.CommandDigest != request.CommandDigest ||
		!sameDispatchPermit(claim.Permit.Dispatch, request.Dispatch) {
		return DispatchStartExecution{}, fmt.Errorf("%w: consumer received a mismatched dispatch start claim", ErrFenceMismatch)
	}
	execution := DispatchStartExecution{Claim: claim, Outcome: DispatchStartOutcomeUnknown}
	if !claim.Fresh {
		return execution, ErrDispatchAlreadyStarted
	}
	startContext, cancelStart := context.WithTimeout(context.WithoutCancel(ctx), consumer.timeout)
	defer cancelStart()
	if err := binding.starter.Start(startContext, claim.Permit); err != nil {
		return execution, fmt.Errorf("%w: starter returned without a proven outcome", ErrDispatchStartUnknown)
	}
	execution.Outcome = DispatchStartOutcomeStarted
	return execution, nil
}
