package effectledger_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/dependency"
	dependencycontract "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/effectledger"
	"github.com/hancomac/circulusd/internal/identity"
)

func TestReferenceLedgerPrepareCopiesBoundsAndConflicts(t *testing.T) {
	store := effectledger.NewReferenceStore()
	command := referenceCommand(t, 1)
	ledger := referenceLedger(t, store, command.Dispatch.Service, command.Dispatch.ProviderRouteDigest)
	exact := cloneCommand(command)

	if err := ledger.Prepare(context.Background(), command); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	command.Payload[0] = 'X'
	if err := ledger.Prepare(context.Background(), exact); err != nil {
		t.Fatalf("Prepare(exact replay) error = %v", err)
	}

	facts, err := ledger.Inspect(context.Background(), lookupFor(exact.Dispatch))
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if facts.State != effectledger.StatePrepared || !bytes.Equal(facts.Command.Payload, exact.Payload) {
		t.Fatalf("Inspect() = %#v, want immutable prepared command", facts)
	}
	facts.Command.Payload[0] = 'Y'
	factsAgain, err := ledger.Inspect(context.Background(), lookupFor(exact.Dispatch))
	if err != nil || !bytes.Equal(factsAgain.Command.Payload, exact.Payload) {
		t.Fatalf("Inspect(after result mutation) = %#v, %v", factsAgain, err)
	}

	conflictingPayload := cloneCommand(exact)
	conflictingPayload.Payload = []byte("different")
	if err := ledger.Prepare(context.Background(), conflictingPayload); !errors.Is(err, effectledger.ErrPrepareConflict) {
		t.Fatalf("Prepare(conflicting payload) error = %v, want ErrPrepareConflict", err)
	}
	conflictingOperation := cloneCommand(exact)
	conflictingOperation.Dispatch.Operation = "different"
	if err := ledger.Prepare(context.Background(), conflictingOperation); !errors.Is(err, effectledger.ErrPrepareConflict) {
		t.Fatalf("Prepare(conflicting permit) error = %v, want ErrPrepareConflict", err)
	}

	wrongRoute := cloneCommand(exact)
	wrongRoute.Dispatch.ProviderRouteDigest = testDigest(90)
	if err := ledger.Prepare(context.Background(), wrongRoute); !errors.Is(err, effectledger.ErrBindingMismatch) {
		t.Fatalf("Prepare(wrong route) error = %v, want ErrBindingMismatch", err)
	}
	wrongService := cloneCommand(exact)
	wrongService.Dispatch.Service = broker.ServiceMCP
	if err := ledger.Prepare(context.Background(), wrongService); !errors.Is(err, effectledger.ErrBindingMismatch) {
		t.Fatalf("Prepare(wrong service) error = %v, want ErrBindingMismatch", err)
	}
	oversized := cloneCommand(exact)
	oversized.Dispatch.DispatchAttempt++
	oversized.Payload = bytes.Repeat([]byte{'p'}, 65)
	if err := ledger.Prepare(context.Background(), oversized); !errors.Is(err, effectledger.ErrLimitExceeded) {
		t.Fatalf("Prepare(oversized) error = %v, want ErrLimitExceeded", err)
	}
}

func TestReferenceLedgerNeverRetainsDispatchOpaque(t *testing.T) {
	store := effectledger.NewReferenceStore()
	command := referenceCommand(t, 70)
	ledger := referenceLedger(t, store, command.Dispatch.Service, command.Dispatch.ProviderRouteDigest)
	if command.Dispatch.Opaque == "" {
		t.Fatal("test command is missing its input dispatch proof")
	}
	if err := ledger.Prepare(context.Background(), command); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	prepared, err := ledger.Inspect(context.Background(), lookupFor(command.Dispatch))
	if err != nil {
		t.Fatalf("Inspect(prepared) error = %v", err)
	}
	if prepared.Command.Dispatch.Opaque != "" {
		t.Fatalf("Inspect(prepared) retained Dispatch.Opaque = %v", prepared.Command.Dispatch.Opaque)
	}

	claimed, err := ledger.ClaimStart(context.Background(), mintClaim(t, command))
	if err != nil {
		t.Fatalf("ClaimStart() error = %v", err)
	}
	opened, ok := claimed.Open()
	if !ok {
		t.Fatal("ClaimedCommand.Open() rejected a broker-minted claim")
	}
	if opened.Dispatch.Opaque != "" {
		t.Fatalf("ClaimedCommand.Open() retained Dispatch.Opaque = %v", opened.Dispatch.Opaque)
	}
	claimedFacts, err := ledger.Inspect(context.Background(), lookupFor(command.Dispatch))
	if err != nil {
		t.Fatalf("Inspect(claimed) error = %v", err)
	}
	if claimedFacts.Command.Dispatch.Opaque != "" {
		t.Fatalf("Inspect(claimed) retained Dispatch.Opaque = %v", claimedFacts.Command.Dispatch.Opaque)
	}
}

func TestReferenceStoreRejectsTypedNilGenerator(t *testing.T) {
	var generator *nilIdentityGenerator
	if store, err := effectledger.NewReferenceStoreWithGenerator(generator); store != nil || !errors.Is(err, effectledger.ErrInvalidConfiguration) {
		t.Fatalf("NewReferenceStoreWithGenerator(typed nil) = %#v, %v", store, err)
	}
}

func TestReferenceLedgerClaimStartIsSealedExactAndAtomic(t *testing.T) {
	const callers = 64
	store := effectledger.NewReferenceStore()
	command := referenceCommand(t, 2)
	ledger := referenceLedger(t, store, command.Dispatch.Service, command.Dispatch.ProviderRouteDigest)
	if err := ledger.Prepare(context.Background(), command); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	claim := mintClaim(t, command)

	results := make(chan claimResult, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			claimed, err := ledger.ClaimStart(context.Background(), claim)
			results <- claimResult{claimed: claimed, err: err}
		}()
	}
	wait.Wait()
	close(results)

	winners := 0
	alreadyClaimed := 0
	var winner effectledger.ClaimedCommand
	for result := range results {
		switch {
		case result.err == nil:
			winners++
			winner = result.claimed
		case errors.Is(result.err, effectledger.ErrStartAlreadyClaimed):
			alreadyClaimed++
		default:
			t.Fatalf("ClaimStart() error = %v", result.err)
		}
	}
	if winners != 1 || alreadyClaimed != callers-1 {
		t.Fatalf("claim results winners/already = %d/%d", winners, alreadyClaimed)
	}
	opened, ok := winner.Open()
	wantOpened := cloneCommand(command)
	wantOpened.Dispatch.Opaque = ""
	if !ok || !sameCommand(opened, wantOpened) {
		t.Fatalf("ClaimedCommand.Open() = %#v, %t", opened, ok)
	}
	opened.Payload[0] = 'Z'
	openedAgain, ok := winner.Open()
	if !ok || !bytes.Equal(openedAgain.Payload, command.Payload) {
		t.Fatalf("ClaimedCommand.Open(after mutation) = %#v, %t", openedAgain, ok)
	}
	if observation, ok := winner.Observation(); !ok || observation == (effectledger.Observation{}) {
		t.Fatalf("ClaimedCommand.Observation() = %#v, %t", observation, ok)
	}

	if claimed, err := ledger.ClaimStart(context.Background(), broker.ClaimedDispatchStart{}); !errors.Is(err, effectledger.ErrInvalidClaim) {
		t.Fatalf("ClaimStart(zero) = %#v, %v", claimed, err)
	}
	if _, ok := (effectledger.ClaimedCommand{}).Open(); ok {
		t.Fatal("zero ClaimedCommand opened")
	}
	if _, ok := (effectledger.ClaimedCommand{}).Observation(); ok {
		t.Fatal("zero ClaimedCommand produced an observation")
	}
	if err := ledger.RecordAccepted(context.Background(), effectledger.Observation{}, "provider-secret"); !errors.Is(err, effectledger.ErrInvalidObservation) {
		t.Fatalf("RecordAccepted(zero observation) error = %v", err)
	}
	if _, err := ledger.RecordTerminal(context.Background(), effectledger.Observation{}, effectledger.Terminal{Status: effectledger.TerminalUnknown}); !errors.Is(err, effectledger.ErrInvalidObservation) {
		t.Fatalf("RecordTerminal(zero observation) error = %v", err)
	}

	otherStore := effectledger.NewReferenceStore()
	otherLedger := referenceLedger(t, otherStore, command.Dispatch.Service, command.Dispatch.ProviderRouteDigest)
	if err := otherLedger.Prepare(context.Background(), command); err != nil {
		t.Fatalf("other Prepare() error = %v", err)
	}
	wrongDigest := cloneCommand(command)
	wrongDigest.CommandDigest = testDigest(91)
	if _, err := otherLedger.ClaimStart(context.Background(), mintClaim(t, wrongDigest)); !errors.Is(err, effectledger.ErrBindingMismatch) {
		t.Fatalf("ClaimStart(wrong digest) error = %v, want ErrBindingMismatch", err)
	}
}

func TestReferenceLedgerRestartPreservesFactsAndOnlyResumesObservation(t *testing.T) {
	store := effectledger.NewReferenceStore()
	command := referenceCommand(t, 3)
	first := referenceLedger(t, store, command.Dispatch.Service, command.Dispatch.ProviderRouteDigest)
	if err := first.Prepare(context.Background(), command); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	claimed, err := first.ClaimStart(context.Background(), mintClaim(t, command))
	if err != nil {
		t.Fatalf("ClaimStart() error = %v", err)
	}
	observation, ok := claimed.Observation()
	if !ok {
		t.Fatal("ClaimedCommand.Observation() was not valid")
	}

	second := referenceLedger(t, store, command.Dispatch.Service, command.Dispatch.ProviderRouteDigest)
	record, err := second.Lookup(context.Background(), lookupFor(command.Dispatch))
	if err != nil || record.Status != broker.LedgerInflight {
		t.Fatalf("restarted Lookup() = %#v, %v; want inflight", record, err)
	}
	if _, err := second.ClaimStart(context.Background(), mintClaim(t, command)); !errors.Is(err, effectledger.ErrStartAlreadyClaimed) {
		t.Fatalf("restarted ClaimStart() error = %v, want ErrStartAlreadyClaimed", err)
	}

	resumed, err := second.ResumeObservation(context.Background(), lookupFor(command.Dispatch), command.CommandDigest)
	if err != nil {
		t.Fatalf("ResumeObservation() error = %v", err)
	}
	if resumed == (effectledger.Observation{}) {
		t.Fatal("ResumeObservation() returned zero handle")
	}
	if _, err := second.ResumeObservation(context.Background(), lookupFor(command.Dispatch), testDigest(92)); !errors.Is(err, effectledger.ErrBindingMismatch) {
		t.Fatalf("ResumeObservation(wrong digest) error = %v", err)
	}
	if err := second.RecordAccepted(context.Background(), resumed, "provider-secret"); err != nil {
		t.Fatalf("RecordAccepted(resumed) error = %v", err)
	}
	if err := second.RecordAccepted(context.Background(), observation, "provider-secret"); err != nil {
		t.Fatalf("RecordAccepted(original idempotent) error = %v", err)
	}
	if err := second.RecordAccepted(context.Background(), resumed, "other-provider"); !errors.Is(err, effectledger.ErrAcceptanceConflict) {
		t.Fatalf("RecordAccepted(conflict) error = %v", err)
	}

	third := referenceLedger(t, store, command.Dispatch.Service, command.Dispatch.ProviderRouteDigest)
	facts, err := third.Inspect(context.Background(), lookupFor(command.Dispatch))
	if err != nil || facts.State != effectledger.StateAccepted || facts.ExternalProviderRequestID != "provider-secret" {
		t.Fatalf("restarted Inspect() = %#v, %v", facts, err)
	}
	if strings.Contains(fmt.Sprintf("%#v", resumed), "provider-secret") || strings.Contains(fmt.Sprint(facts), "provider-secret") {
		t.Fatal("observation or facts String leaked provider identifier")
	}
	for name, value := range map[string]any{"store": store, "ledger": third} {
		formatted := fmt.Sprintf("%#v", value)
		if strings.Contains(formatted, "provider-secret") || !strings.Contains(formatted, "redacted") {
			t.Fatalf("%s GoString() = %q", name, formatted)
		}
	}
}

func TestReferenceLedgerTerminalFactsAreImmutableAndProjected(t *testing.T) {
	tests := []struct {
		name       string
		status     effectledger.TerminalStatus
		wantStatus broker.LedgerStatus
	}{
		{name: "committed", status: effectledger.TerminalCommitted, wantStatus: broker.LedgerCommitted},
		{name: "failed", status: effectledger.TerminalFailed, wantStatus: broker.LedgerFailed},
		{name: "unknown", status: effectledger.TerminalUnknown, wantStatus: broker.LedgerUnknown},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := effectledger.NewReferenceStore()
			command := referenceCommand(t, byte(10+index))
			ledger := referenceLedger(t, store, command.Dispatch.Service, command.Dispatch.ProviderRouteDigest)
			if err := ledger.Prepare(context.Background(), command); err != nil {
				t.Fatalf("Prepare() error = %v", err)
			}
			claimed, err := ledger.ClaimStart(context.Background(), mintClaim(t, command))
			if err != nil {
				t.Fatalf("ClaimStart() error = %v", err)
			}
			observation, ok := claimed.Observation()
			if !ok {
				t.Fatal("Observation() invalid")
			}
			if err := ledger.RecordAccepted(context.Background(), observation, "provider-secret"); err != nil {
				t.Fatalf("RecordAccepted() error = %v", err)
			}

			terminal := effectledger.Terminal{Status: test.status, Result: []byte("secret-result")}
			if test.status == effectledger.TerminalCommitted {
				terminal.ExternalCommitID = testID(t, identity.Commit, byte(60+index))
				terminal.ResultRef = testID(t, identity.Artifact, byte(70+index))
			}
			if _, err := ledger.RecordTerminal(context.Background(), observation, terminal); err != nil {
				t.Fatalf("RecordTerminal() error = %v", err)
			}
			if replay, err := ledger.RecordTerminal(context.Background(), observation, terminal); err != nil || !sameTerminal(replay, terminal) {
				t.Fatalf("RecordTerminal(exact replay) = %#v, %v", replay, err)
			}
			conflict := terminal
			conflict.Result = []byte("different")
			if _, err := ledger.RecordTerminal(context.Background(), observation, conflict); !errors.Is(err, effectledger.ErrTerminalConflict) {
				t.Fatalf("RecordTerminal(conflict) error = %v", err)
			}

			facts, err := ledger.Inspect(context.Background(), lookupFor(command.Dispatch))
			if err != nil || facts.State != effectledger.StateTerminal || facts.ExternalProviderRequestID != "provider-secret" || !sameTerminal(facts.Terminal, terminal) {
				t.Fatalf("Inspect() = %#v, %v", facts, err)
			}
			facts.Terminal.Result[0] = 'X'
			factsAgain, err := ledger.Inspect(context.Background(), lookupFor(command.Dispatch))
			if err != nil || !bytes.Equal(factsAgain.Terminal.Result, terminal.Result) {
				t.Fatalf("Inspect(after result mutation) = %#v, %v", factsAgain, err)
			}

			record, err := ledger.Lookup(context.Background(), lookupFor(command.Dispatch))
			if err != nil || record.Status != test.wantStatus || record.ExternalCommitID != terminal.ExternalCommitID || record.ResultRef != terminal.ResultRef {
				t.Fatalf("Lookup() = %#v, %v", record, err)
			}
			if !strings.Contains(fmt.Sprint(terminal), "redacted") || strings.Contains(fmt.Sprintf("%#v", facts), "secret-result") {
				t.Fatal("terminal facts String/GoString did not redact content")
			}
		})
	}
}

func TestReferenceLedgerAllocatesStableCommittedIdentities(t *testing.T) {
	store := effectledger.NewReferenceStore()
	command := referenceCommand(t, 18)
	ledger := referenceLedger(t, store, command.Dispatch.Service, command.Dispatch.ProviderRouteDigest)
	var contract effectledger.Ledger = ledger
	if contract == nil {
		t.Fatal("ReferenceLedger does not implement Ledger")
	}
	if err := ledger.Prepare(context.Background(), command); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	claimed, err := ledger.ClaimStart(context.Background(), mintClaim(t, command))
	if err != nil {
		t.Fatalf("ClaimStart() error = %v", err)
	}
	observation, _ := claimed.Observation()
	if err := ledger.RecordAccepted(context.Background(), observation, "provider"); err != nil {
		t.Fatalf("RecordAccepted() error = %v", err)
	}
	input := effectledger.Terminal{Status: effectledger.TerminalCommitted, Result: []byte("result")}
	first, err := ledger.RecordTerminal(context.Background(), observation, input)
	if err != nil {
		t.Fatalf("RecordTerminal() error = %v", err)
	}
	if first.ExternalCommitID.Kind() != identity.Commit || first.ResultRef.Kind() != identity.Artifact {
		t.Fatalf("RecordTerminal() identities = %v/%v", first.ExternalCommitID.Kind(), first.ResultRef.Kind())
	}
	second, err := ledger.RecordTerminal(context.Background(), observation, input)
	if err != nil || !sameTerminal(second, first) {
		t.Fatalf("RecordTerminal(write-response-loss replay) = %#v, %v; want %#v", second, err, first)
	}
}

func TestReferenceLedgerAllowsClaimedFailureOrUnknownButRequiresAcceptanceForCommit(t *testing.T) {
	for index, status := range []effectledger.TerminalStatus{effectledger.TerminalFailed, effectledger.TerminalUnknown} {
		store := effectledger.NewReferenceStore()
		command := referenceCommand(t, byte(40+index))
		ledger := referenceLedger(t, store, command.Dispatch.Service, command.Dispatch.ProviderRouteDigest)
		if err := ledger.Prepare(context.Background(), command); err != nil {
			t.Fatalf("Prepare() error = %v", err)
		}
		claimed, err := ledger.ClaimStart(context.Background(), mintClaim(t, command))
		if err != nil {
			t.Fatalf("ClaimStart() error = %v", err)
		}
		observation, _ := claimed.Observation()
		terminal := effectledger.Terminal{Status: status, Result: []byte("provider outcome")}
		if _, err := ledger.RecordTerminal(context.Background(), observation, terminal); err != nil {
			t.Fatalf("RecordTerminal(%s from claimed) error = %v", status, err)
		}
	}

	store := effectledger.NewReferenceStore()
	command := referenceCommand(t, 50)
	ledger := referenceLedger(t, store, command.Dispatch.Service, command.Dispatch.ProviderRouteDigest)
	if err := ledger.Prepare(context.Background(), command); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	claimed, err := ledger.ClaimStart(context.Background(), mintClaim(t, command))
	if err != nil {
		t.Fatalf("ClaimStart() error = %v", err)
	}
	observation, _ := claimed.Observation()
	if _, err := ledger.RecordTerminal(context.Background(), observation, effectledger.Terminal{Status: effectledger.TerminalCommitted, Result: []byte("result")}); !errors.Is(err, effectledger.ErrInvalidTransition) {
		t.Fatalf("RecordTerminal(committed before accepted) error = %v", err)
	}
}

func TestReferenceLedgerRejectsUnsafeProviderIDAndEmptyCommit(t *testing.T) {
	store := effectledger.NewReferenceStore()
	command := referenceCommand(t, 55)
	ledger := referenceLedger(t, store, command.Dispatch.Service, command.Dispatch.ProviderRouteDigest)
	if err := ledger.Prepare(context.Background(), command); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	claimed, err := ledger.ClaimStart(context.Background(), mintClaim(t, command))
	if err != nil {
		t.Fatalf("ClaimStart() error = %v", err)
	}
	observation, _ := claimed.Observation()
	for _, providerID := range []string{" provider", "provider ", "provider\nrequest", "provider\u200e"} {
		if err := ledger.RecordAccepted(context.Background(), observation, providerID); !errors.Is(err, effectledger.ErrInvalidCommand) {
			t.Fatalf("RecordAccepted(%q) error = %v", providerID, err)
		}
	}
	if err := ledger.RecordAccepted(context.Background(), observation, "provider"); err != nil {
		t.Fatalf("RecordAccepted(valid) error = %v", err)
	}
	if _, err := ledger.RecordTerminal(context.Background(), observation, effectledger.Terminal{Status: effectledger.TerminalCommitted}); !errors.Is(err, effectledger.ErrInvalidCommand) {
		t.Fatalf("RecordTerminal(empty committed) error = %v", err)
	}
	terminal := effectledger.Terminal{
		Status: effectledger.TerminalCommitted, ResultRef: testID(t, identity.Artifact, 56),
	}
	if _, err := ledger.RecordTerminal(context.Background(), observation, terminal); err != nil {
		t.Fatalf("RecordTerminal(result ref only) error = %v", err)
	}
}

func TestReferenceLedgerRejectsOversizedTerminalAndForeignObservation(t *testing.T) {
	store := effectledger.NewReferenceStore()
	command := referenceCommand(t, 20)
	ledger := referenceLedger(t, store, command.Dispatch.Service, command.Dispatch.ProviderRouteDigest)
	if err := ledger.Prepare(context.Background(), command); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	claimed, err := ledger.ClaimStart(context.Background(), mintClaim(t, command))
	if err != nil {
		t.Fatalf("ClaimStart() error = %v", err)
	}
	observation, _ := claimed.Observation()
	if err := ledger.RecordAccepted(context.Background(), observation, "provider"); err != nil {
		t.Fatalf("RecordAccepted() error = %v", err)
	}
	oversized := effectledger.Terminal{Status: effectledger.TerminalFailed, Result: bytes.Repeat([]byte{'r'}, 65)}
	if _, err := ledger.RecordTerminal(context.Background(), observation, oversized); !errors.Is(err, effectledger.ErrLimitExceeded) {
		t.Fatalf("RecordTerminal(oversized) error = %v", err)
	}

	foreignStore := effectledger.NewReferenceStore()
	foreign := referenceLedger(t, foreignStore, command.Dispatch.Service, command.Dispatch.ProviderRouteDigest)
	if err := foreign.RecordAccepted(context.Background(), observation, "provider"); !errors.Is(err, effectledger.ErrInvalidObservation) {
		t.Fatalf("foreign RecordAccepted() error = %v", err)
	}
}

func TestReferenceLedgerLookupReturnsExactAbsentIdentity(t *testing.T) {
	store := effectledger.NewReferenceStore()
	command := referenceCommand(t, 30)
	ledger := referenceLedger(t, store, command.Dispatch.Service, command.Dispatch.ProviderRouteDigest)
	lookup := lookupFor(command.Dispatch)

	record, err := ledger.Lookup(context.Background(), lookup)
	if err != nil {
		t.Fatalf("Lookup(absent) error = %v", err)
	}
	want := broker.LedgerRecord{
		Status: broker.LedgerAbsent, TenantID: lookup.TenantID, WorkspaceID: lookup.WorkspaceID,
		EffectID: lookup.EffectID, InvocationID: lookup.InvocationID, RequestDigest: lookup.RequestDigest,
		Service: lookup.Service, Operation: lookup.Operation, DispatchAttempt: lookup.DispatchAttempt,
		ProviderRequestID: lookup.ProviderRequestID, ProviderRouteDigest: lookup.ProviderRouteDigest,
	}
	if record != want {
		t.Fatalf("Lookup(absent) = %#v, want %#v", record, want)
	}
	if _, err := ledger.ResumeObservation(context.Background(), lookup, command.CommandDigest); !errors.Is(err, effectledger.ErrObservationUnavailable) {
		t.Fatalf("ResumeObservation(absent) error = %v", err)
	}

	wrongRoute := lookup
	wrongRoute.ProviderRouteDigest = testDigest(99)
	if _, err := ledger.Lookup(context.Background(), wrongRoute); !errors.Is(err, effectledger.ErrBindingMismatch) {
		t.Fatalf("Lookup(wrong route) error = %v", err)
	}
	wrongService := lookup
	wrongService.Service = broker.ServiceMCP
	if _, err := ledger.Lookup(context.Background(), wrongService); !errors.Is(err, effectledger.ErrBindingMismatch) {
		t.Fatalf("Lookup(wrong service) error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ledger.Lookup(canceled, lookup); !errors.Is(err, context.Canceled) {
		t.Fatalf("Lookup(canceled) error = %v", err)
	}
}

type claimResult struct {
	claimed effectledger.ClaimedCommand
	err     error
}

type nilIdentityGenerator struct{}

func (*nilIdentityGenerator) New(identity.Kind) (identity.ID, error) {
	return identity.ID{}, nil
}

type testClaimer struct {
	*dependencycontract.ProductionProofs
	claim broker.DispatchStartClaim
}

func (claimer *testClaimer) ClaimDispatchStart(context.Context, broker.DispatchStartRequest) (broker.DispatchStartClaim, error) {
	return claimer.claim, nil
}

type claimCapture struct {
	route broker.Digest
	claim broker.ClaimedDispatchStart
}

func (capture *claimCapture) RouteDigest() broker.Digest { return capture.route }

func (capture *claimCapture) Start(_ context.Context, claim broker.ClaimedDispatchStart) error {
	capture.claim = claim
	return nil
}

func mintClaim(t *testing.T, command effectledger.Command) broker.ClaimedDispatchStart {
	t.Helper()
	permit := broker.DispatchStartPermit{
		Dispatch: command.Dispatch, Opaque: broker.OpaquePermit("start-secret"),
		CommandDigest: command.CommandDigest, EventSequence: 2, Durable: true,
	}
	proofs := dependencycontract.NewProductionProofs(t, []dependency.AtomicGroup{
		dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle,
	})
	claimer := &testClaimer{ProductionProofs: proofs, claim: broker.DispatchStartClaim{Permit: permit, Fresh: true}}
	capture := &claimCapture{route: command.Dispatch.ProviderRouteDigest}
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
	request := broker.DispatchStartRequest{Dispatch: command.Dispatch, CommandDigest: command.CommandDigest}
	if _, err := consumer.StartExactAttempt(context.Background(), request); err != nil {
		t.Fatalf("StartExactAttempt() error = %v", err)
	}
	return capture.claim
}

func referenceLedger(t *testing.T, store *effectledger.ReferenceStore, service broker.EffectService, route broker.Digest) *effectledger.ReferenceLedger {
	t.Helper()
	ledger, err := effectledger.NewReferenceLedger(store, service, route, effectledger.ReferenceLimits{
		MaximumPayloadBytes: 64,
		MaximumResultBytes:  64,
	})
	if err != nil {
		t.Fatalf("NewReferenceLedger() error = %v", err)
	}
	return ledger
}

func referenceCommand(t *testing.T, seed byte) effectledger.Command {
	t.Helper()
	dispatch := broker.DispatchPermit{
		EffectKey: broker.EffectKey{
			SessionID: testID(t, identity.Session, seed), TurnID: testID(t, identity.Turn, seed+1),
			EffectID: testID(t, identity.Effect, seed+2), InvocationID: testID(t, identity.Invocation, seed+3),
			RequestDigest: testDigest(seed + 4),
		},
		Opaque:   broker.OpaquePermit("dispatch-secret"),
		TenantID: testID(t, identity.Tenant, seed+5), WorkspaceID: testID(t, identity.Workspace, seed+6),
		UserID: testID(t, identity.Subject, seed+7), Service: broker.ServiceExternalTool, Operation: "fake.call",
		ParentOperationID: testID(t, identity.Operation, seed+8), Ordinal: 1,
		ReplayPolicy: broker.ReplayNever, Generations: broker.Generations{TurnLease: 1, Placement: 2, Sandbox: 3, Authorization: 4},
		DispatchAttempt: 1, ProviderRequestID: testID(t, identity.Request, seed+9),
		ProviderRouteDigest: testDigest(seed + 10), Deadline: time.Unix(1_900_100_000, 0).UTC(),
		EventSequence: 1, Durable: true,
	}
	return effectledger.Command{Dispatch: dispatch, CommandDigest: testDigest(seed + 11), Payload: []byte("super-secret")}
}

func lookupFor(dispatch broker.DispatchPermit) broker.LedgerLookup {
	return broker.LedgerLookup{
		EffectKey: dispatch.EffectKey, TenantID: dispatch.TenantID, WorkspaceID: dispatch.WorkspaceID,
		Service: dispatch.Service, Operation: dispatch.Operation, DispatchAttempt: dispatch.DispatchAttempt,
		ProviderRequestID: dispatch.ProviderRequestID, ProviderRouteDigest: dispatch.ProviderRouteDigest,
	}
}

func cloneCommand(command effectledger.Command) effectledger.Command {
	command.Payload = append([]byte(nil), command.Payload...)
	return command
}

func sameCommand(left, right effectledger.Command) bool {
	return left.Dispatch == right.Dispatch && left.CommandDigest == right.CommandDigest && bytes.Equal(left.Payload, right.Payload)
}

func sameTerminal(left, right effectledger.Terminal) bool {
	return left.Status == right.Status && left.ExternalCommitID == right.ExternalCommitID &&
		left.ResultRef == right.ResultRef && bytes.Equal(left.Result, right.Result)
}

func testID(t *testing.T, kind identity.Kind, seed byte) identity.ID {
	t.Helper()
	id, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte{seed}, 16))}).New(kind)
	if err != nil {
		t.Fatalf("identity.New(%s) error = %v", kind, err)
	}
	return id
}

func testDigest(seed byte) broker.Digest {
	var digest broker.Digest
	for index := range digest {
		digest[index] = seed + byte(index)
	}
	return digest
}
