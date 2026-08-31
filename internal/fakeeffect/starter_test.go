package fakeeffect_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/dependency"
	dependencycontract "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/effectledger"
	"github.com/hancomac/circulusd/internal/fakeeffect"
	"github.com/hancomac/circulusd/internal/identity"
)

func TestNewCommandUsesBoundedDomainSeparatedCanonicalDigest(t *testing.T) {
	dispatch := fakeDispatch(t, 1)
	payload := []byte("super-secret")
	command, err := fakeeffect.NewCommand(dispatch, payload)
	if err != nil {
		t.Fatalf("NewCommand() error = %v", err)
	}
	if command.CommandDigest == (broker.Digest{}) || !bytes.Equal(command.Payload, payload) {
		t.Fatalf("NewCommand() = %#v", command)
	}
	payload[0] = 'X'
	if bytes.Equal(command.Payload, payload) {
		t.Fatal("NewCommand() retained caller payload")
	}

	same, err := fakeeffect.NewCommand(dispatch, []byte("super-secret"))
	if err != nil || same.CommandDigest != command.CommandDigest {
		t.Fatalf("NewCommand(exact) digest = %x, %v", same.CommandDigest, err)
	}
	differentPayload, err := fakeeffect.NewCommand(dispatch, []byte("different"))
	if err != nil || differentPayload.CommandDigest == command.CommandDigest {
		t.Fatalf("NewCommand(different payload) digest = %x, %v", differentPayload.CommandDigest, err)
	}
	differentService := dispatch
	differentService.Service = broker.ServiceMCP
	serviceCommand, err := fakeeffect.NewCommand(differentService, []byte("super-secret"))
	if err != nil || serviceCommand.CommandDigest == command.CommandDigest {
		t.Fatalf("NewCommand(different service) digest = %x, %v", serviceCommand.CommandDigest, err)
	}
	differentRoute := dispatch
	differentRoute.ProviderRouteDigest = fakeDigest(90)
	routeCommand, err := fakeeffect.NewCommand(differentRoute, []byte("super-secret"))
	if err != nil || routeCommand.CommandDigest == command.CommandDigest {
		t.Fatalf("NewCommand(different route) digest = %x, %v", routeCommand.CommandDigest, err)
	}

	oversized := bytes.Repeat([]byte{'p'}, fakeeffect.MaximumPayloadBytes+1)
	if command, err := fakeeffect.NewCommand(dispatch, oversized); len(command.Payload) != 0 || !errors.Is(err, fakeeffect.ErrPayloadTooLarge) {
		t.Fatalf("NewCommand(oversized) = %#v, %v", command, err)
	}
}

func TestStarterRejectsInvalidConfigurationAndZeroClaimBeforeProvider(t *testing.T) {
	dispatch := fakeDispatch(t, 2)
	command := mustFakeCommand(t, dispatch, []byte("payload"))
	store := effectledger.NewReferenceStore()
	ledger := fakeLedger(t, store, dispatch)
	provider := &recordingProvider{}

	var nilLedger *effectledger.ReferenceLedger
	if starter, err := fakeeffect.NewStarter(nilLedger, provider); starter != nil || !errors.Is(err, fakeeffect.ErrInvalidConfiguration) {
		t.Fatalf("NewStarter(typed nil ledger) = %#v, %v", starter, err)
	}
	var nilProvider *recordingProvider
	if starter, err := fakeeffect.NewStarter(ledger, nilProvider); starter != nil || !errors.Is(err, fakeeffect.ErrInvalidConfiguration) {
		t.Fatalf("NewStarter(typed nil provider) = %#v, %v", starter, err)
	}
	starter, err := fakeeffect.NewStarter(ledger, provider)
	if err != nil {
		t.Fatalf("NewStarter() error = %v", err)
	}
	if err := ledger.Prepare(context.Background(), command); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if err := starter.Start(context.Background(), broker.ClaimedDispatchStart{}); !errors.Is(err, effectledger.ErrInvalidClaim) {
		t.Fatalf("Start(zero claim) error = %v", err)
	}
	if provider.calls.Load() != 0 {
		t.Fatalf("provider calls = %d, want zero", provider.calls.Load())
	}
}

func TestStarterCallsProviderOnceWithoutHoldingLedgerLockAndRecordsAcceptanceThenTerminal(t *testing.T) {
	dispatch := fakeDispatch(t, 3)
	command := mustFakeCommand(t, dispatch, []byte("super-secret"))
	store := effectledger.NewReferenceStore()
	ledger := fakeLedger(t, store, dispatch)
	if err := ledger.Prepare(context.Background(), command); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	provider := &recordingProvider{}
	provider.start = func(ctx context.Context, request fakeeffect.Request) (fakeeffect.Response, error) {
		expectedDispatch := command.Dispatch
		expectedDispatch.Opaque = ""
		if !bytes.Equal(request.Payload, command.Payload) || request.Dispatch != expectedDispatch {
			t.Fatalf("provider request = %#v", request)
		}
		request.Payload[0] = 'X'
		record, err := ledger.Lookup(ctx, fakeLookup(dispatch))
		if err != nil || record.Status != broker.LedgerInflight {
			t.Fatalf("provider-time Lookup() = %#v, %v", record, err)
		}
		facts, err := ledger.Inspect(ctx, fakeLookup(dispatch))
		if err != nil || facts.State != effectledger.StateClaimed || !bytes.Equal(facts.Command.Payload, command.Payload) {
			t.Fatalf("provider-time Inspect() = %#v, %v", facts, err)
		}
		return fakeeffect.Response{
			ExternalProviderRequestID: "provider-secret",
			Terminal: effectledger.Terminal{
				Status: effectledger.TerminalCommitted, Result: []byte("secret-result"),
			},
		}, nil
	}
	starter, err := fakeeffect.NewStarter(ledger, provider)
	if err != nil {
		t.Fatalf("NewStarter() error = %v", err)
	}
	if starter.RouteDigest() != dispatch.ProviderRouteDigest {
		t.Fatalf("RouteDigest() = %x", starter.RouteDigest())
	}
	if err := starter.Start(context.Background(), mintFakeClaim(t, command)); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if provider.calls.Load() != 1 {
		t.Fatalf("provider calls = %d, want 1", provider.calls.Load())
	}
	facts, err := ledger.Inspect(context.Background(), fakeLookup(dispatch))
	if err != nil || facts.State != effectledger.StateTerminal ||
		facts.ExternalProviderRequestID != "provider-secret" ||
		facts.Terminal.Status != effectledger.TerminalCommitted ||
		facts.Terminal.ExternalCommitID.Kind() != identity.Commit ||
		facts.Terminal.ResultRef.Kind() != identity.Artifact ||
		!bytes.Equal(facts.Terminal.Result, []byte("secret-result")) {
		t.Fatalf("terminal facts = %#v, %v", facts, err)
	}
	if !bytes.Equal(facts.Command.Payload, command.Payload) {
		t.Fatal("provider request mutation changed stored command")
	}
	record, err := ledger.Lookup(context.Background(), fakeLookup(dispatch))
	if err != nil || record.Status != broker.LedgerCommitted || record.ExternalCommitID != facts.Terminal.ExternalCommitID || record.ResultRef != facts.Terminal.ResultRef {
		t.Fatalf("Lookup() = %#v, %v", record, err)
	}
	if strings.Contains(fmt.Sprintf("%#v", fakeeffect.Request{Payload: []byte("super-secret")}), "super-secret") ||
		strings.Contains(fmt.Sprintf("%#v", fakeeffect.Response{ExternalProviderRequestID: "provider-secret"}), "provider-secret") ||
		strings.Contains(fmt.Sprintf("%#v", starter), "provider-secret") {
		t.Fatal("fake effect String/GoString leaked sensitive content")
	}
}

func TestStarterProviderErrorRecordsUnknownAndNeverRetriesAfterReconstruction(t *testing.T) {
	dispatch := fakeDispatch(t, 4)
	command := mustFakeCommand(t, dispatch, []byte("payload"))
	store := effectledger.NewReferenceStore()
	firstLedger := fakeLedger(t, store, dispatch)
	if err := firstLedger.Prepare(context.Background(), command); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	provider := &recordingProvider{err: errors.New("provider secret failure")}
	firstStarter, err := fakeeffect.NewStarter(firstLedger, provider)
	if err != nil {
		t.Fatalf("NewStarter() error = %v", err)
	}
	claim := mintFakeClaim(t, command)
	if err := firstStarter.Start(context.Background(), claim); !errors.Is(err, fakeeffect.ErrProviderOutcomeUnknown) || strings.Contains(err.Error(), "provider secret failure") {
		t.Fatalf("Start(provider error) error = %v", err)
	}
	if provider.calls.Load() != 1 {
		t.Fatalf("provider calls = %d, want 1", provider.calls.Load())
	}
	record, err := firstLedger.Lookup(context.Background(), fakeLookup(dispatch))
	if err != nil || record.Status != broker.LedgerUnknown {
		t.Fatalf("Lookup() = %#v, %v; want unknown", record, err)
	}

	secondLedger := fakeLedger(t, store, dispatch)
	secondProvider := &recordingProvider{}
	secondStarter, err := fakeeffect.NewStarter(secondLedger, secondProvider)
	if err != nil {
		t.Fatalf("NewStarter(reconstructed) error = %v", err)
	}
	if err := secondStarter.Start(context.Background(), claim); !errors.Is(err, effectledger.ErrStartAlreadyClaimed) {
		t.Fatalf("reconstructed Start() error = %v", err)
	}
	if secondProvider.calls.Load() != 0 {
		t.Fatalf("reconstructed provider calls = %d, want zero", secondProvider.calls.Load())
	}
}

func TestStarterPreservesAcceptanceReturnedWithProviderError(t *testing.T) {
	dispatch := fakeDispatch(t, 5)
	command := mustFakeCommand(t, dispatch, []byte("payload"))
	store := effectledger.NewReferenceStore()
	ledger := fakeLedger(t, store, dispatch)
	if err := ledger.Prepare(context.Background(), command); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	provider := &recordingProvider{
		response: fakeeffect.Response{ExternalProviderRequestID: "provider-accepted"},
		err:      errors.New("stream setup outcome unknown"),
	}
	starter, err := fakeeffect.NewStarter(ledger, provider)
	if err != nil {
		t.Fatalf("NewStarter() error = %v", err)
	}
	if err := starter.Start(context.Background(), mintFakeClaim(t, command)); !errors.Is(err, fakeeffect.ErrProviderOutcomeUnknown) {
		t.Fatalf("Start() error = %v, want ErrProviderOutcomeUnknown", err)
	}
	facts, err := ledger.Inspect(context.Background(), fakeLookup(dispatch))
	if err != nil || facts.ExternalProviderRequestID != "provider-accepted" ||
		facts.Terminal.Status != effectledger.TerminalUnknown {
		t.Fatalf("Inspect() = %#v, %v", facts, err)
	}
}

func TestConcurrentStarterCallsInvokeProviderOnce(t *testing.T) {
	const callers = 64
	dispatch := fakeDispatch(t, 8)
	command := mustFakeCommand(t, dispatch, []byte("payload"))
	store := effectledger.NewReferenceStore()
	ledger := fakeLedger(t, store, dispatch)
	if err := ledger.Prepare(context.Background(), command); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	provider := &recordingProvider{response: fakeeffect.Response{
		ExternalProviderRequestID: "provider",
		Terminal: effectledger.Terminal{
			Status: effectledger.TerminalFailed, Result: []byte("deterministic failure"),
		},
	}}
	starter, err := fakeeffect.NewStarter(ledger, provider)
	if err != nil {
		t.Fatalf("NewStarter() error = %v", err)
	}
	claim := mintFakeClaim(t, command)
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsSeen <- starter.Start(context.Background(), claim)
		}()
	}
	wait.Wait()
	close(errorsSeen)

	started, alreadyStarted := 0, 0
	for startErr := range errorsSeen {
		switch {
		case startErr == nil:
			started++
		case errors.Is(startErr, effectledger.ErrStartAlreadyClaimed):
			alreadyStarted++
		default:
			t.Fatalf("Start() error = %v", startErr)
		}
	}
	if started != 1 || alreadyStarted != callers-1 || provider.calls.Load() != 1 {
		t.Fatalf("started/already/provider = %d/%d/%d", started, alreadyStarted, provider.calls.Load())
	}
}

func TestStarterInvalidProviderResponseFallsBackToUnknown(t *testing.T) {
	tests := []struct {
		name     string
		response fakeeffect.Response
	}{
		{
			name: "missing acceptance",
			response: fakeeffect.Response{
				Terminal: effectledger.Terminal{Status: effectledger.TerminalCommitted, Result: []byte("result")},
			},
		},
		{
			name: "invalid terminal after acceptance",
			response: fakeeffect.Response{
				ExternalProviderRequestID: "provider",
				Terminal:                  effectledger.Terminal{Status: effectledger.TerminalCommitted},
			},
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dispatch := fakeDispatch(t, byte(10+index))
			command := mustFakeCommand(t, dispatch, []byte("payload"))
			store := effectledger.NewReferenceStore()
			ledger := fakeLedger(t, store, dispatch)
			if err := ledger.Prepare(context.Background(), command); err != nil {
				t.Fatalf("Prepare() error = %v", err)
			}
			provider := &recordingProvider{response: test.response}
			starter, err := fakeeffect.NewStarter(ledger, provider)
			if err != nil {
				t.Fatalf("NewStarter() error = %v", err)
			}
			if err := starter.Start(context.Background(), mintFakeClaim(t, command)); !errors.Is(err, fakeeffect.ErrProviderOutcomeUnknown) {
				t.Fatalf("Start() error = %v", err)
			}
			if provider.calls.Load() != 1 {
				t.Fatalf("provider calls = %d, want 1", provider.calls.Load())
			}
			record, err := ledger.Lookup(context.Background(), fakeLookup(dispatch))
			if err != nil || record.Status != broker.LedgerUnknown {
				t.Fatalf("Lookup() = %#v, %v; want unknown", record, err)
			}
		})
	}
}

func TestStarterAcceptsAuthoritativeTerminalBeforeProviderAcceptance(t *testing.T) {
	tests := []struct {
		name       string
		terminal   effectledger.Terminal
		wantStatus broker.LedgerStatus
	}{
		{
			name: "definitely not sent",
			terminal: effectledger.Terminal{
				Status: effectledger.TerminalFailed, Result: []byte("not sent"),
			},
			wantStatus: broker.LedgerFailed,
		},
		{
			name: "provider outcome unknown",
			terminal: effectledger.Terminal{
				Status: effectledger.TerminalUnknown, Result: []byte("unknown"),
			},
			wantStatus: broker.LedgerUnknown,
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dispatch := fakeDispatch(t, byte(20+index))
			command := mustFakeCommand(t, dispatch, []byte("payload"))
			store := effectledger.NewReferenceStore()
			ledger := fakeLedger(t, store, dispatch)
			if err := ledger.Prepare(context.Background(), command); err != nil {
				t.Fatalf("Prepare() error = %v", err)
			}
			provider := &recordingProvider{response: fakeeffect.Response{Terminal: test.terminal}}
			starter, err := fakeeffect.NewStarter(ledger, provider)
			if err != nil {
				t.Fatalf("NewStarter() error = %v", err)
			}
			if err := starter.Start(context.Background(), mintFakeClaim(t, command)); err != nil {
				t.Fatalf("Start() error = %v", err)
			}
			record, err := ledger.Lookup(context.Background(), fakeLookup(dispatch))
			if err != nil || record.Status != test.wantStatus {
				t.Fatalf("Lookup() = %#v, %v", record, err)
			}
			facts, err := ledger.Inspect(context.Background(), fakeLookup(dispatch))
			if err != nil || facts.ExternalProviderRequestID != "" || facts.Terminal.Status != test.terminal.Status {
				t.Fatalf("Inspect() = %#v, %v", facts, err)
			}
		})
	}
}

type recordingProvider struct {
	calls    atomic.Int64
	start    func(context.Context, fakeeffect.Request) (fakeeffect.Response, error)
	response fakeeffect.Response
	err      error
}

func (provider *recordingProvider) Start(ctx context.Context, request fakeeffect.Request) (fakeeffect.Response, error) {
	provider.calls.Add(1)
	if provider.start != nil {
		return provider.start(ctx, request)
	}
	return provider.response, provider.err
}

type fakeClaimer struct {
	*dependencycontract.ProductionProofs
	claim broker.DispatchStartClaim
}

func (claimer *fakeClaimer) ClaimDispatchStart(context.Context, broker.DispatchStartRequest) (broker.DispatchStartClaim, error) {
	return claimer.claim, nil
}

type fakeClaimCapture struct {
	route broker.Digest
	claim broker.ClaimedDispatchStart
}

func (capture *fakeClaimCapture) RouteDigest() broker.Digest { return capture.route }

func (capture *fakeClaimCapture) Start(_ context.Context, claim broker.ClaimedDispatchStart) error {
	capture.claim = claim
	return nil
}

func mintFakeClaim(t *testing.T, command effectledger.Command) broker.ClaimedDispatchStart {
	t.Helper()
	permit := broker.DispatchStartPermit{
		Dispatch: command.Dispatch, Opaque: broker.OpaquePermit("start-secret"),
		CommandDigest: command.CommandDigest, EventSequence: 2, Durable: true,
	}
	proofs := dependencycontract.NewProductionProofs(t, []dependency.AtomicGroup{
		dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle,
	})
	claimer := &fakeClaimer{ProductionProofs: proofs, claim: broker.DispatchStartClaim{Permit: permit, Fresh: true}}
	capture := &fakeClaimCapture{route: command.Dispatch.ProviderRouteDigest}
	consumer, err := broker.NewDispatchConsumer(
		dependencycontract.Verify(t, proofs, broker.DispatchStartClaimer(claimer), []dependency.AtomicGroup{
			dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle,
		}),
		map[broker.EffectService]broker.DispatchStarter{command.Dispatch.Service: capture},
		time.Second,
	)
	if err != nil {
		t.Fatalf("NewDispatchConsumer() error = %v", err)
	}
	if _, err := consumer.StartExactAttempt(context.Background(), broker.DispatchStartRequest{
		Dispatch: command.Dispatch, CommandDigest: command.CommandDigest,
	}); err != nil {
		t.Fatalf("StartExactAttempt() error = %v", err)
	}
	return capture.claim
}

func fakeLedger(t *testing.T, store *effectledger.ReferenceStore, dispatch broker.DispatchPermit) *effectledger.ReferenceLedger {
	t.Helper()
	ledger, err := effectledger.NewReferenceLedger(
		store, dispatch.Service, dispatch.ProviderRouteDigest,
		effectledger.ReferenceLimits{MaximumPayloadBytes: fakeeffect.MaximumPayloadBytes, MaximumResultBytes: 1 << 20},
	)
	if err != nil {
		t.Fatalf("NewReferenceLedger() error = %v", err)
	}
	return ledger
}

func mustFakeCommand(t *testing.T, dispatch broker.DispatchPermit, payload []byte) effectledger.Command {
	t.Helper()
	command, err := fakeeffect.NewCommand(dispatch, payload)
	if err != nil {
		t.Fatalf("NewCommand() error = %v", err)
	}
	return command
}

func fakeDispatch(t *testing.T, seed byte) broker.DispatchPermit {
	t.Helper()
	return broker.DispatchPermit{
		EffectKey: broker.EffectKey{
			SessionID: fakeID(t, identity.Session, seed), TurnID: fakeID(t, identity.Turn, seed+1),
			EffectID: fakeID(t, identity.Effect, seed+2), InvocationID: fakeID(t, identity.Invocation, seed+3),
			RequestDigest: fakeDigest(seed + 4),
		},
		Opaque:   broker.OpaquePermit("dispatch-secret"),
		TenantID: fakeID(t, identity.Tenant, seed+5), WorkspaceID: fakeID(t, identity.Workspace, seed+6),
		UserID: fakeID(t, identity.Subject, seed+7), Service: broker.ServiceExternalTool, Operation: "fake.call",
		ParentOperationID: fakeID(t, identity.Operation, seed+8), Ordinal: 1,
		ReplayPolicy: broker.ReplayNever, Generations: broker.Generations{TurnLease: 1, Placement: 2, Sandbox: 3, Authorization: 4},
		DispatchAttempt: 1, ProviderRequestID: fakeID(t, identity.Request, seed+9),
		ProviderRouteDigest: fakeDigest(seed + 10), Deadline: time.Unix(1_900_200_000, 0).UTC(),
		EventSequence: 1, Durable: true,
	}
}

func fakeLookup(dispatch broker.DispatchPermit) broker.LedgerLookup {
	return broker.LedgerLookup{
		EffectKey: dispatch.EffectKey, TenantID: dispatch.TenantID, WorkspaceID: dispatch.WorkspaceID,
		Service: dispatch.Service, Operation: dispatch.Operation, DispatchAttempt: dispatch.DispatchAttempt,
		ProviderRequestID: dispatch.ProviderRequestID, ProviderRouteDigest: dispatch.ProviderRouteDigest,
	}
}

func fakeID(t *testing.T, kind identity.Kind, seed byte) identity.ID {
	t.Helper()
	id, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte{seed}, 16))}).New(kind)
	if err != nil {
		t.Fatalf("identity.New(%s) error = %v", kind, err)
	}
	return id
}

func fakeDigest(seed byte) broker.Digest {
	var digest broker.Digest
	for index := range digest {
		digest[index] = seed + byte(index)
	}
	return digest
}
