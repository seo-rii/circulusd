// Package fakeeffect provides a deterministic reference effect adapter for
// tests and development. It must never be treated as a production provider or
// an availability dependency.
package fakeeffect

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/effectledger"
)

const MaximumPayloadBytes = 1 << 20

const maximumFactWriteDuration = 5 * time.Second

var (
	ErrInvalidConfiguration    = errors.New("fake effect: invalid reference configuration")
	ErrInvalidCommand          = errors.New("fake effect: invalid command")
	ErrPayloadTooLarge         = errors.New("fake effect: payload exceeds reference limit")
	ErrProviderOutcomeUnknown  = errors.New("fake effect: provider outcome unknown")
	ErrCanonicalCommandFailure = errors.New("fake effect: canonical command failure")
)

const commandDigestDomain = "circulusd.fake-effect.command"

// NewCommand copies a bounded payload and binds it to the adapter domain,
// schema, service, operation, and route with canonical bytes.
func NewCommand(dispatch broker.DispatchPermit, payload []byte) (effectledger.Command, error) {
	if len(payload) > MaximumPayloadBytes {
		return effectledger.Command{}, ErrPayloadTooLarge
	}
	validService := false
	switch dispatch.Service {
	case broker.ServiceModel, broker.ServiceWorkspace, broker.ServiceExecutor, broker.ServiceMCP,
		broker.ServiceArtifact, broker.ServiceExternalTool:
		validService = true
	}
	if !validService || dispatch.Operation == "" || dispatch.ProviderRouteDigest == (broker.Digest{}) {
		return effectledger.Command{}, ErrInvalidCommand
	}
	encoded, err := canonical.Encode(canonical.Array{
		commandDigestDomain,
		int64(1),
		string(dispatch.Service),
		dispatch.Operation,
		canonical.Bytes(dispatch.ProviderRouteDigest[:]),
		canonical.Bytes(payload),
	}, canonical.DefaultOptions())
	if err != nil {
		return effectledger.Command{}, ErrCanonicalCommandFailure
	}
	digest := sha256.Sum256(encoded)
	return effectledger.Command{
		Dispatch: dispatch, CommandDigest: broker.Digest(digest), Payload: append([]byte(nil), payload...),
	}, nil
}

type Request struct {
	Dispatch broker.DispatchPermit
	Payload  []byte
}

func (Request) String() string   { return "fake-effect-request<redacted>" }
func (Request) GoString() string { return "fake-effect-request<redacted>" }

type Response struct {
	ExternalProviderRequestID string
	Terminal                  effectledger.Terminal
}

func (Response) String() string   { return "fake-effect-response<redacted>" }
func (Response) GoString() string { return "fake-effect-response<redacted>" }

type Provider interface {
	Start(context.Context, Request) (Response, error)
}

type ProviderFunc func(context.Context, Request) (Response, error)

func (provider ProviderFunc) Start(ctx context.Context, request Request) (Response, error) {
	return provider(ctx, request)
}

// BoundLedger exposes immutable construction-time routing in addition to the
// generic subordinate-ledger contract.
type BoundLedger interface {
	effectledger.Ledger
	Service() broker.EffectService
	RouteDigest() broker.Digest
}

// Starter performs one provider call after the sealed Session claim has been
// consumed by its subordinate ledger. It has no retry loop.
type Starter struct {
	ledger   BoundLedger
	provider Provider
}

func NewStarter(ledger BoundLedger, provider Provider) (*Starter, error) {
	for _, candidate := range []any{ledger, provider} {
		if candidate == nil {
			return nil, ErrInvalidConfiguration
		}
		value := reflect.ValueOf(candidate)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			if value.IsNil() {
				return nil, ErrInvalidConfiguration
			}
		}
	}
	if ledger.Service() == "" || ledger.RouteDigest() == (broker.Digest{}) {
		return nil, ErrInvalidConfiguration
	}
	return &Starter{ledger: ledger, provider: provider}, nil
}

func (starter *Starter) RouteDigest() broker.Digest {
	if starter == nil || starter.ledger == nil {
		return broker.Digest{}
	}
	return starter.ledger.RouteDigest()
}

func (starter *Starter) Start(ctx context.Context, claim broker.ClaimedDispatchStart) error {
	if starter == nil || starter.ledger == nil || starter.provider == nil || ctx == nil {
		return ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	claimed, err := starter.ledger.ClaimStart(ctx, claim)
	if err != nil {
		return err
	}
	command, opened := claimed.Open()
	observation, observed := claimed.Observation()
	if !opened || !observed || command.Dispatch.Service != starter.ledger.Service() ||
		command.Dispatch.ProviderRouteDigest != starter.ledger.RouteDigest() {
		return effectledger.ErrBindingMismatch
	}
	canonicalCommand, err := NewCommand(command.Dispatch, command.Payload)
	if err != nil || canonicalCommand.CommandDigest != command.CommandDigest {
		return effectledger.ErrBindingMismatch
	}

	response, providerErr := starter.provider.Start(ctx, Request{
		Dispatch: command.Dispatch,
		Payload:  append([]byte(nil), command.Payload...),
	})
	factContext, cancelFacts := context.WithTimeout(context.WithoutCancel(ctx), maximumFactWriteDuration)
	defer cancelFacts()
	var outcomeErr error
	if response.ExternalProviderRequestID != "" {
		outcomeErr = starter.ledger.RecordAccepted(
			factContext, observation, response.ExternalProviderRequestID,
		)
	}
	if providerErr == nil && outcomeErr == nil {
		if response.ExternalProviderRequestID == "" {
			switch response.Terminal.Status {
			case effectledger.TerminalFailed, effectledger.TerminalUnknown:
				_, outcomeErr = starter.ledger.RecordTerminal(factContext, observation, response.Terminal)
			default:
				outcomeErr = effectledger.ErrInvalidCommand
			}
		} else {
			_, outcomeErr = starter.ledger.RecordTerminal(factContext, observation, response.Terminal)
		}
		if outcomeErr == nil {
			return nil
		}
	}
	_, unknownErr := starter.ledger.RecordTerminal(
		factContext, observation, effectledger.Terminal{Status: effectledger.TerminalUnknown},
	)
	if unknownErr != nil {
		return errors.Join(ErrProviderOutcomeUnknown, outcomeErr, unknownErr)
	}
	return ErrProviderOutcomeUnknown
}

func (Starter) String() string   { return "fake-effect-starter<redacted>" }
func (Starter) GoString() string { return "fake-effect-starter<redacted>" }

var _ broker.DispatchStarter = (*Starter)(nil)
