package effectledger_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/celldbridge"
	"github.com/hancomac/circulusd/internal/dependency"
	dependencycontract "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/effectledger"
	"github.com/hancomac/circulusd/internal/identity"
)

// This fault-injecting source is explicitly an unqualified in-process fixture.
// contracttest signatures exercise constructors; they are never live evidence.
type nativeLedgerFixture struct {
	*dependencycontract.ProductionProofs
	mu          sync.Mutex
	objects     map[string]celldbridge.Snapshot
	reads       int
	commits     int
	barriers    uint64
	conflicts   int
	commitLoss  bool
	barrierLoss bool
	lastObject  string
}

func (fixture *nativeLedgerFixture) ReadSnapshot(ctx context.Context, request celldbridge.SnapshotRequest) (celldbridge.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return celldbridge.Snapshot{}, err
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.reads++
	fixture.lastObject = request.ObjectID
	snapshot, found := fixture.objects[request.ObjectID]
	if !found {
		snapshot = celldbridge.Snapshot{SnapshotRef: celldbridge.SnapshotRef{ObjectID: request.ObjectID, StateDigest: celld.Digest(sha256.Sum256(nil))}}
	}
	snapshot.State = bytes.Clone(snapshot.State)
	return snapshot, nil
}

func (fixture *nativeLedgerFixture) ReadReceipt(_ context.Context, request celldbridge.ReceiptRequest) (celldbridge.ReceiptResult, error) {
	return celldbridge.ReceiptResult{Snapshot: request.Snapshot, CommandID: request.CommandID}, nil
}

func (fixture *nativeLedgerFixture) CompareAndCommit(ctx context.Context, request celldbridge.CommitRequest) (celldbridge.CommitResult, error) {
	if err := ctx.Err(); err != nil {
		return celldbridge.CommitResult{}, err
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.commits++
	if fixture.conflicts != 0 {
		fixture.conflicts--
		return celldbridge.CommitResult{}, celldbridge.ErrSnapshotConflict
	}
	current, found := fixture.objects[request.Snapshot.ObjectID]
	if !found {
		current = celldbridge.Snapshot{SnapshotRef: celldbridge.SnapshotRef{ObjectID: request.Snapshot.ObjectID, StateDigest: celld.Digest(sha256.Sum256(nil))}}
	}
	if current.SnapshotRef != request.Snapshot {
		return celldbridge.CommitResult{}, celldbridge.ErrSnapshotConflict
	}
	if len(request.Receipts) != 0 {
		return celldbridge.CommitResult{}, errors.New("fixture does not implement receipts")
	}
	if request.StateWritten {
		current.State = bytes.Clone(request.State)
		current.StateDigest = celld.Digest(sha256.Sum256(current.State))
	}
	current.Exists = true
	current.Revision++
	fixture.objects[current.ObjectID] = current
	if fixture.commitLoss {
		fixture.commitLoss = false
		return celldbridge.CommitResult{}, errors.New("persisted native commit response lost")
	}
	return celldbridge.CommitResult{Snapshot: current.SnapshotRef, RequestDigest: request.RequestDigest,
		Token: celld.CommitToken{ObjectID: current.ObjectID, Revision: current.Revision}}, nil
}

func (fixture *nativeLedgerFixture) ConfirmBarrier(ctx context.Context, request celldbridge.BarrierRequest) (celldbridge.BarrierResult, error) {
	if err := ctx.Err(); err != nil {
		return celldbridge.BarrierResult{}, err
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	current, found := fixture.objects[request.Token.ObjectID]
	if !found || current.Revision < request.Token.Revision {
		return celldbridge.BarrierResult{}, errors.New("missing committed revision")
	}
	fixture.barriers++
	if fixture.barrierLoss {
		fixture.barrierLoss = false
		return celldbridge.BarrierResult{}, errors.New("barrier response lost")
	}
	return celldbridge.BarrierResult{Token: request.Token, Marker: request.Marker, ObservedRevision: current.Revision, BarrierSerial: fixture.barriers}, nil
}

func nativeLedgerStorage(t *testing.T, missing dependency.AtomicGroup) (*nativeLedgerFixture, dependency.Verified[*celldbridge.Storage]) {
	t.Helper()
	groups := []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle,
		celldbridge.AtomicNativeStorage, effectledger.AtomicProviderObservationLedger}
	groups = slices.DeleteFunc(groups, func(group dependency.AtomicGroup) bool { return group == missing })
	slices.Sort(groups)
	proofs := dependencycontract.NewProductionProofs(t, groups)
	fixture := &nativeLedgerFixture{ProductionProofs: proofs, objects: make(map[string]celldbridge.Snapshot)}
	transport := dependencycontract.Verify[celldbridge.NativeTransport](t, proofs, fixture, groups)
	storage, err := celldbridge.New(celldbridge.Config{Transport: transport, MaximumAttempts: 8,
		Bounds: celldbridge.Bounds{MaxStateBytes: 32768, MaxReceiptResponseBytes: 1024, MaxCapabilityClaims: 1,
			MaxCapabilityClaimBytes: 1024, MaxReceiptLookups: 1, MaxReceiptWrites: 1, MaxTransactionBytes: 65536}})
	if err != nil {
		t.Fatalf("native Storage fixture: %v", err)
	}
	return fixture, dependencycontract.Verify(t, proofs, storage, groups)
}

func nativeLedgerConfig(storage dependency.Verified[*celldbridge.Storage], command effectledger.Command) effectledger.NativeConfig {
	return effectledger.NativeConfig{Storage: storage, Service: command.Dispatch.Service, RouteDigest: command.Dispatch.ProviderRouteDigest,
		Limits: effectledger.ReferenceLimits{MaximumPayloadBytes: 64, MaximumResultBytes: 64}, MaximumStateBytes: 32768}
}

func nativeLedger(t *testing.T, config effectledger.NativeConfig) *effectledger.NativeLedger {
	t.Helper()
	ledger, err := effectledger.NewNativeLedger(config)
	if err != nil {
		t.Fatalf("NewNativeLedger: %v", err)
	}
	return ledger
}

func nativeClaim(t *testing.T, ledger *effectledger.NativeLedger, command effectledger.Command) effectledger.Observation {
	t.Helper()
	if err := ledger.Prepare(context.Background(), command); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	claimed, err := ledger.ClaimStart(context.Background(), mintClaim(t, command))
	if err != nil {
		t.Fatalf("ClaimStart: %v", err)
	}
	observation, ok := claimed.Observation()
	if !ok {
		t.Fatal("claimed observation did not open")
	}
	return observation
}

func TestNativeLedgerRequiresExactAtomicQualificationAndBoundedPolicy(t *testing.T) {
	command := referenceCommand(t, 1)
	for _, missing := range []dependency.AtomicGroup{dependency.AtomicEffectLifecycle, effectledger.AtomicProviderObservationLedger} {
		t.Run(string(missing), func(t *testing.T) {
			fixture, storage := nativeLedgerStorage(t, missing)
			if ledger, err := effectledger.NewNativeLedger(nativeLedgerConfig(storage, command)); ledger != nil || !errors.Is(err, dependency.ErrRequirementMismatch) {
				t.Fatalf("missing qualification: ledger=%v err=%v", ledger, err)
			}
			if fixture.reads != 0 {
				t.Fatal("unqualified constructor reached operational source")
			}
		})
	}
	_, storage := nativeLedgerStorage(t, "")
	config := nativeLedgerConfig(storage, command)
	if ledger, err := effectledger.NewNativeLedger(effectledger.NativeConfig{}); ledger != nil || !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatalf("unsealed source: %v, %v", ledger, err)
	}
	for _, mutate := range []func(*effectledger.NativeConfig){
		func(c *effectledger.NativeConfig) { c.Service = "invalid" },
		func(c *effectledger.NativeConfig) { c.RouteDigest = broker.Digest{} },
		func(c *effectledger.NativeConfig) { c.Limits.MaximumPayloadBytes = 0 },
		func(c *effectledger.NativeConfig) { c.Limits.MaximumResultBytes = -1 },
		func(c *effectledger.NativeConfig) { c.MaximumStateBytes = 1024 },
		func(c *effectledger.NativeConfig) { c.MaximumStateBytes = celldbridge.MaximumStateBytes + 1 },
	} {
		invalid := config
		mutate(&invalid)
		if ledger, err := effectledger.NewNativeLedger(invalid); ledger != nil || !errors.Is(err, effectledger.ErrInvalidConfiguration) {
			t.Fatalf("invalid immutable policy: %v, %v", ledger, err)
		}
	}
	ledger := nativeLedger(t, config)
	config.Limits.MaximumPayloadBytes = 1
	if ledger.Limits().MaximumPayloadBytes != 64 {
		t.Fatal("constructor retained mutable policy")
	}
}

func TestNativeLedgerPreparePersistsCompleteBindingWithoutBearers(t *testing.T) {
	fixture, storage := nativeLedgerStorage(t, "")
	command := referenceCommand(t, 20)
	command.Dispatch.ParentOperationID, command.Dispatch.ProviderRequestID = identity.ID{}, identity.ID{}
	command.Dispatch.ParentOperation, command.Dispatch.Ordinal = "pi-parent", 0
	config := nativeLedgerConfig(storage, command)
	ledger := nativeLedger(t, config)
	exact := cloneCommand(command)
	if err := ledger.Prepare(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	command.Payload[0] ^= 1
	if err := ledger.Prepare(context.Background(), exact); err != nil {
		t.Fatal(err)
	}
	reopened := nativeLedger(t, config)
	facts, err := reopened.Inspect(context.Background(), lookupFor(exact.Dispatch))
	want := cloneCommand(exact)
	want.Dispatch.Opaque = ""
	if err != nil || !sameCommand(facts.Command, want) || facts.State != effectledger.StatePrepared {
		t.Fatalf("cold exact binding: %v, %v", facts, err)
	}
	fixture.mu.Lock()
	encoded := bytes.Clone(fixture.objects[fixture.lastObject].State)
	fixture.mu.Unlock()
	if bytes.Contains(encoded, []byte("dispatch-secret")) || bytes.Contains(encoded, []byte("start-secret")) {
		t.Fatal("opaque authority reached persistent state")
	}
	for _, mutate := range []func(*effectledger.Command){
		func(c *effectledger.Command) { c.Payload = []byte("changed") },
		func(c *effectledger.Command) { c.Dispatch.TenantID = testID(t, identity.Tenant, 100) },
		func(c *effectledger.Command) { c.Dispatch.WorkspaceID = testID(t, identity.Workspace, 101) },
		func(c *effectledger.Command) { c.Dispatch.ParentOperation = "different-parent" },
		func(c *effectledger.Command) { c.Dispatch.Ordinal++ },
		func(c *effectledger.Command) { c.Dispatch.ProviderRequestID = testID(t, identity.Request, 102) },
		func(c *effectledger.Command) { c.Dispatch.Operation = "different.call" },
		func(c *effectledger.Command) { c.Dispatch.RequestDigest = testDigest(103) },
		func(c *effectledger.Command) { c.CommandDigest = testDigest(104) },
	} {
		changed := cloneCommand(exact)
		mutate(&changed)
		if err := reopened.Prepare(context.Background(), changed); !errors.Is(err, effectledger.ErrPrepareConflict) {
			t.Fatalf("relabeled exact attempt accepted: %v", err)
		}
	}
	if _, err := reopened.ResumeObservation(context.Background(), lookupFor(exact.Dispatch), exact.CommandDigest); !errors.Is(err, effectledger.ErrObservationUnavailable) {
		t.Fatalf("prepared command gained observation authority: %v", err)
	}
}

func TestNativeLedgerConcurrentClaimHasOneDurableWinner(t *testing.T) {
	_, storage := nativeLedgerStorage(t, "")
	command := referenceCommand(t, 40)
	ledger := nativeLedger(t, nativeLedgerConfig(storage, command))
	if err := ledger.Prepare(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	claim := mintClaim(t, command)
	results := make(chan claimResult, 32)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			claimed, err := ledger.ClaimStart(context.Background(), claim)
			results <- claimResult{claimed: claimed, err: err}
		})
	}
	wg.Wait()
	close(results)
	winners := 0
	for result := range results {
		if result.err == nil {
			winners++
			if _, ok := result.claimed.Open(); !ok {
				t.Fatal("successful durable winner did not open")
			}
		} else if !errors.Is(result.err, effectledger.ErrStartAlreadyClaimed) {
			t.Fatalf("claim loser: %v", result.err)
		} else if _, ok := result.claimed.Open(); ok {
			t.Fatal("loser retained provider-start handle")
		}
	}
	if winners != 1 {
		t.Fatalf("provider-start winners=%d", winners)
	}
}

func TestNativeLedgerReopenObservationCannotRestartAndBindsExactOwner(t *testing.T) {
	_, storage := nativeLedgerStorage(t, "")
	command := referenceCommand(t, 60)
	config := nativeLedgerConfig(storage, command)
	ledger := nativeLedger(t, config)
	observation := nativeClaim(t, ledger, command)
	reopened := nativeLedger(t, config)
	if err := reopened.RecordAccepted(context.Background(), observation, "provider-1"); !errors.Is(err, effectledger.ErrInvalidObservation) {
		t.Fatalf("moved old native handle: %v", err)
	}
	if _, err := reopened.ClaimStart(context.Background(), mintClaim(t, command)); !errors.Is(err, effectledger.ErrStartAlreadyClaimed) {
		t.Fatalf("reopen restarted provider: %v", err)
	}
	resumed, err := reopened.ResumeObservation(context.Background(), lookupFor(command.Dispatch), command.CommandDigest)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.RecordAccepted(context.Background(), resumed, "provider-1"); err != nil {
		t.Fatal(err)
	}
	if err := reopened.RecordAccepted(context.Background(), resumed, "provider-1"); err != nil {
		t.Fatal(err)
	}
	if err := reopened.RecordAccepted(context.Background(), resumed, "provider-2"); !errors.Is(err, effectledger.ErrAcceptanceConflict) {
		t.Fatalf("changed acceptance: %v", err)
	}
	reference := referenceLedger(t, effectledger.NewReferenceStore(), command.Dispatch.Service, command.Dispatch.ProviderRouteDigest)
	if err := reference.Prepare(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	refClaimed, err := reference.ClaimStart(context.Background(), mintClaim(t, command))
	if err != nil {
		t.Fatal(err)
	}
	refObservation, _ := refClaimed.Observation()
	if err := reopened.RecordAccepted(context.Background(), refObservation, "provider-1"); !errors.Is(err, effectledger.ErrInvalidObservation) {
		t.Fatalf("reference observation crossed native owner: %v", err)
	}
	if err := reference.RecordAccepted(context.Background(), resumed, "provider-1"); !errors.Is(err, effectledger.ErrInvalidObservation) {
		t.Fatalf("native observation crossed reference store: %v", err)
	}
}

func TestNativeLedgerLostClaimResponseNeverRestartsProvider(t *testing.T) {
	for _, fault := range []string{"commit", "barrier"} {
		t.Run(fault, func(t *testing.T) {
			fixture, storage := nativeLedgerStorage(t, "")
			command := referenceCommand(t, 80)
			config := nativeLedgerConfig(storage, command)
			ledger := nativeLedger(t, config)
			if err := ledger.Prepare(context.Background(), command); err != nil {
				t.Fatal(err)
			}
			fixture.commitLoss, fixture.barrierLoss = fault == "commit", fault == "barrier"
			claimed, err := ledger.ClaimStart(context.Background(), mintClaim(t, command))
			if err == nil {
				t.Fatal("ambiguous claim returned success")
			}
			if _, ok := claimed.Open(); ok {
				t.Fatal("ambiguous claim exposed provider-start authority")
			}
			if _, ok := claimed.Observation(); ok {
				t.Fatal("ambiguous claim exposed observation")
			}
			reopened := nativeLedger(t, config)
			if _, err := reopened.ClaimStart(context.Background(), mintClaim(t, command)); !errors.Is(err, effectledger.ErrStartAlreadyClaimed) {
				t.Fatalf("lost response restarted provider: %v", err)
			}
			if _, err := reopened.ResumeObservation(context.Background(), lookupFor(command.Dispatch), command.CommandDigest); err != nil {
				t.Fatalf("facts-only recovery: %v", err)
			}
			record, err := reopened.Lookup(context.Background(), lookupFor(command.Dispatch))
			if err != nil || record.Status != broker.LedgerInflight {
				t.Fatalf("uncertain start facts: %v, %v", record, err)
			}
		})
	}
}

func TestNativeLedgerLostTerminalReplyReplaysExactPersistedIDsAndBytes(t *testing.T) {
	for _, fault := range []string{"commit", "barrier"} {
		t.Run(fault, func(t *testing.T) {
			fixture, storage := nativeLedgerStorage(t, "")
			command := referenceCommand(t, 100)
			config := nativeLedgerConfig(storage, command)
			ledger := nativeLedger(t, config)
			observation := nativeClaim(t, ledger, command)
			if err := ledger.RecordAccepted(context.Background(), observation, "provider-result-1"); err != nil {
				t.Fatal(err)
			}
			requested := effectledger.Terminal{Status: effectledger.TerminalCommitted, Result: []byte("canonical-result")}
			fixture.commitLoss, fixture.barrierLoss = fault == "commit", fault == "barrier"
			terminal, err := ledger.RecordTerminal(context.Background(), observation, requested)
			if err == nil || terminal.Status != "" || len(terminal.Result) != 0 || terminal.ExternalCommitID != (identity.ID{}) {
				t.Fatalf("ambiguous terminal exposed success: %v, %v", terminal, err)
			}
			reopened := nativeLedger(t, config)
			resumed, err := reopened.ResumeObservation(context.Background(), lookupFor(command.Dispatch), command.CommandDigest)
			if err != nil {
				t.Fatal(err)
			}
			facts, err := reopened.Inspect(context.Background(), lookupFor(command.Dispatch))
			if err != nil || facts.Terminal.ExternalCommitID.Kind() != identity.Commit || facts.Terminal.ResultRef.Kind() != identity.Artifact {
				t.Fatalf("persisted generated identities: %v, %v", facts, err)
			}
			for range 3 {
				replayed, err := reopened.RecordTerminal(context.Background(), resumed, requested)
				if err != nil || !sameTerminal(replayed, facts.Terminal) {
					t.Fatalf("exact terminal replay: %v, %v", replayed, err)
				}
			}
			changed := facts.Terminal
			changed.ExternalCommitID = testID(t, identity.Commit, 140)
			if _, err := reopened.RecordTerminal(context.Background(), resumed, changed); !errors.Is(err, effectledger.ErrTerminalConflict) {
				t.Fatalf("terminal identity changed: %v", err)
			}
			requested.Result[0] ^= 1
			if _, err := reopened.RecordTerminal(context.Background(), resumed, requested); !errors.Is(err, effectledger.ErrTerminalConflict) {
				t.Fatalf("terminal bytes changed: %v", err)
			}
		})
	}
}

func TestNativeLedgerRetriesCallbacksAndRequiresFreshReadBarrier(t *testing.T) {
	fixture, storage := nativeLedgerStorage(t, "")
	command := referenceCommand(t, 120)
	ledger := nativeLedger(t, nativeLedgerConfig(storage, command))
	fixture.conflicts = 2
	if err := ledger.Prepare(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	if fixture.reads != 3 {
		t.Fatalf("definite conflict callbacks=%d", fixture.reads)
	}
	observation := nativeClaim(t, ledger, command)
	fixture.barrierLoss = true
	if facts, err := ledger.Inspect(context.Background(), lookupFor(command.Dispatch)); err == nil || facts.State != "" {
		t.Fatalf("failed read barrier exposed facts: %v, %v", facts, err)
	}
	fixture.barrierLoss = true
	if resumed, err := ledger.ResumeObservation(context.Background(), lookupFor(command.Dispatch), command.CommandDigest); err == nil || resumed != (effectledger.Observation{}) {
		t.Fatalf("failed barrier minted observation: %v, %v", resumed, err)
	}
	fixture.barrierLoss = true
	if record, err := ledger.Lookup(context.Background(), lookupFor(command.Dispatch)); err == nil || record.Status != "" {
		t.Fatalf("failed lookup barrier exposed facts: %v, %v", record, err)
	}
	if _, err := ledger.RecordTerminal(context.Background(), observation, effectledger.Terminal{Status: effectledger.TerminalCommitted, Result: []byte("result")}); !errors.Is(err, effectledger.ErrInvalidTransition) {
		t.Fatalf("unaccepted commit: %v", err)
	}
	terminal, err := ledger.RecordTerminal(context.Background(), observation, effectledger.Terminal{Status: effectledger.TerminalUnknown, Result: []byte("uncertain")})
	if err != nil || terminal.ExternalCommitID != (identity.ID{}) || terminal.ResultRef != (identity.ID{}) {
		t.Fatalf("explicit zero terminal IDs: %v, %v", terminal, err)
	}
	record, err := ledger.Lookup(context.Background(), lookupFor(command.Dispatch))
	if err != nil || record.Status != broker.LedgerUnknown {
		t.Fatalf("unknown durable result: %v, %v", record, err)
	}
}

func TestNativeLedgerRejectsCorruptCanonicalStateAndAliases(t *testing.T) {
	for _, name := range []string{"json", "duplicate", "unknown", "alias", "missing-optional", "payload-corruption", "accepted-without-id", "wrong-object"} {
		t.Run(name, func(t *testing.T) {
			fixture, storage := nativeLedgerStorage(t, "")
			command := referenceCommand(t, 150)
			ledger := nativeLedger(t, nativeLedgerConfig(storage, command))
			if err := ledger.Prepare(context.Background(), command); err != nil {
				t.Fatal(err)
			}
			fixture.mu.Lock()
			object := fixture.objects[fixture.lastObject]
			value, err := canonical.Decode(object.State, canonical.DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			m := value.(canonical.Map)
			d := m["command"].(canonical.Map)["dispatch"].(canonical.Map)
			switch name {
			case "json":
				object.State = []byte(`{"state":"prepared","state":"claimed"}`)
			case "duplicate":
				object.State = []byte{0xa2, 0x61, 'a', 1, 0x61, 'a', 2}
			case "unknown":
				m["opaque"] = "must-not-enter"
			case "alias":
				m["Protocol"] = m["protocol"]
				delete(m, "protocol")
			case "missing-optional":
				delete(d, "parentOperationId")
			case "payload-corruption":
				m["command"].(canonical.Map)["payload"] = canonical.Bytes("corrupted")
			case "accepted-without-id":
				m["state"] = "accepted"
			case "wrong-object":
				d["invocationId"] = testID(t, identity.Invocation, 200).String()
			}
			if name != "json" && name != "duplicate" {
				object.State, err = canonical.Encode(m, canonical.DefaultOptions())
				if err != nil {
					t.Fatal(err)
				}
			}
			object.StateDigest = celld.Digest(sha256.Sum256(object.State))
			fixture.objects[object.ObjectID] = object
			fixture.mu.Unlock()
			if facts, err := ledger.Inspect(context.Background(), lookupFor(command.Dispatch)); !errors.Is(err, celld.ErrStorageContract) || facts.State != "" {
				t.Fatalf("corrupt record exposed: %v, %v", facts, err)
			}
		})
	}
}

func TestNativeLedgerLookupRequiresCompleteIdentityAndOwnedLimits(t *testing.T) {
	fixture, storage := nativeLedgerStorage(t, "")
	command := referenceCommand(t, 170)
	ledger := nativeLedger(t, nativeLedgerConfig(storage, command))
	lookup := lookupFor(command.Dispatch)
	absent, err := ledger.Lookup(context.Background(), lookup)
	if err != nil || absent.Status != broker.LedgerAbsent || absent.TenantID != lookup.TenantID || absent.RequestDigest != lookup.RequestDigest {
		t.Fatalf("exact absent identity: %v, %v", absent, err)
	}
	if err := ledger.Prepare(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*broker.LedgerLookup){
		func(q *broker.LedgerLookup) { q.TenantID = testID(t, identity.Tenant, 220) },
		func(q *broker.LedgerLookup) { q.WorkspaceID = testID(t, identity.Workspace, 221) },
		func(q *broker.LedgerLookup) { q.Operation = "changed.call" },
		func(q *broker.LedgerLookup) { q.RequestDigest = testDigest(222) },
		func(q *broker.LedgerLookup) { q.ProviderRequestID = testID(t, identity.Request, 223) },
		func(q *broker.LedgerLookup) { q.ProviderRouteDigest = testDigest(224) },
	} {
		changed := lookup
		mutate(&changed)
		if record, err := ledger.Lookup(context.Background(), changed); !errors.Is(err, effectledger.ErrBindingMismatch) || record.Status != "" {
			t.Fatalf("relabeled lookup: %v, %v", record, err)
		}
	}
	command.Dispatch.DispatchAttempt++
	command.Payload = bytes.Repeat([]byte{'x'}, 65)
	reads := fixture.reads
	if err := ledger.Prepare(context.Background(), command); !errors.Is(err, effectledger.ErrLimitExceeded) || fixture.reads != reads {
		t.Fatalf("oversized command reached native I/O: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ledger.Lookup(canceled, lookup); !errors.Is(err, context.Canceled) || fixture.reads != reads {
		t.Fatalf("canceled lookup reached native I/O: %v", err)
	}
	if got := fmt.Sprintf("%v %#v", ledger, nativeLedgerConfig(storage, command)); bytes.Contains([]byte(got), command.Payload) {
		t.Fatal("configuration formatting exposed bytes")
	}
}
