package mcpgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/effectledger"
	"github.com/hancomac/circulusd/internal/identity"
)

// These are protocol/source fixtures, never signed runtime qualification.
func nativeHTTPTestServer(t *testing.T, call http.HandlerFunc, observers ...func()) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			if r.Header.Get("MCP-Session-Id") != "private-native-fixture-session" || r.Header.Get("MCP-Protocol-Version") != streamableHTTPProtocol {
				t.Error("fixture session termination mismatch")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		for _, observe := range observers {
			observe()
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error("fixture request body read failed")
			return
		}
		message, err := decodeMCPMessage(body)
		if err != nil {
			t.Error("fixture request envelope invalid")
			return
		}
		if message.Method == "initialize" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("MCP-Session-Id", "private-native-fixture-session")
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}`, message.ID)
			return
		}
		if r.Header.Get("MCP-Session-Id") != "private-native-fixture-session" || r.Header.Get("MCP-Protocol-Version") != streamableHTTPProtocol {
			t.Error("fixture session/protocol mismatch")
		}
		if message.Method == "notifications/initialized" {
			w.WriteHeader(202)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		call(w, r)
	}))
	t.Cleanup(server.Close)
	return server
}

func newNativeHTTPFixture(t *testing.T, url string) nativeFactoryFixture {
	t.Helper()
	fixture := newNativeFactoryFixture(t)
	fixture.effect.Scope.WorkspaceID = mustID(t, identity.Workspace)
	fixture.effect.Scope.Generations.Sandbox = 11
	fixture.grant.Scope = fixture.effect.Scope
	fixture.reference.scope = fixture.effect.Scope
	config := cloneNativeConfiguration(fixture.configuration)
	// Native transactions/barriers perform substantially more work than the
	// reference fixture's 100 ms cancellation window, especially under race.
	config.Bounds.CancelTimeout = 2 * time.Second
	config.Servers[0].Transport = TransportStreamableHTTP
	config.Servers[0].Affinity = BackendAffinity{}
	config.Servers[0].TargetRef = "registry/test"
	fixture.effect.Transport = TransportStreamableHTTP
	fixture.effect.Affinity = BackendAffinity{}
	fixture.effect.TargetRef = "registry/test"
	fixture.effect.SupportsInvocationLedger = true
	fixture.effect.SupportsIdempotencyKey = false
	repository, err := newNativeRepository(fixture.source, fixture.factory.repository.binding, fixture.factory.repository.check, "native-http-fixture", 128, 1<<20, fixture.factory.repository.now)
	if err != nil {
		t.Fatal(err)
	}
	transport := testMCPHTTPConfig(url)
	factory, err := newNativeFactory(repository, config, map[string]NativeProviderConfig{fixture.effect.ProviderID: {StreamableHTTP: &transport}})
	if err != nil {
		t.Fatal(err)
	}
	fixture.factory = factory
	fixture.configuration = config
	return fixture
}

func prepareNativeHTTPCommand(t *testing.T, fixture nativeFactoryFixture) (*Gateway, ProviderCommand, Effect) {
	t.Helper()
	ctx := context.Background()
	authorization := provisionNativeFixture(t, fixture)
	gateway, err := NewProductionGateway(fixture.configuration, qualifyNativeFactory(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := fixture.factory.repository.Admit(ctx, fixture.effect)
	if err != nil {
		t.Fatal(err)
	}
	begin, err := gateway.Apply(stored.Effect, Event{ExpectedRevision: stored.Effect.Revision, Kind: EventBeginDispatch})
	if err != nil {
		t.Fatal(err)
	}
	dispatch, err := fixture.factory.repository.CommitAndClaimDispatch(ctx, DispatchClaimRequest{ExpectedRevision: stored.Effect.Revision, CurrentScope: fixture.effect.Scope, Previous: stored.Effect, Next: begin.Effect, Authorization: authorization})
	if err != nil {
		t.Fatal(err)
	}
	command := *begin.Dispatch
	command.Authorization = authorization
	command.Dispatch = dispatch
	provider := fixture.factory.providers[fixture.effect.ProviderID]
	receipt, err := provider.Negotiate(ctx, nativeNegotiation(command))
	if err != nil {
		t.Fatal(err)
	}
	next, err := gateway.Apply(begin.Effect, Event{ExpectedRevision: begin.Effect.Revision, Kind: EventNegotiationRecorded, Negotiation: receipt})
	if err != nil {
		t.Fatal(err)
	}
	current, err := gateway.persistAfterExternal(ctx, fixture.effect.Scope, begin.Effect, next.Effect)
	if err != nil {
		t.Fatal(err)
	}
	start, err := fixture.factory.repository.ClaimProviderStart(ctx, ProviderStartClaimRequest{CurrentScope: fixture.effect.Scope, Effect: current, Dispatch: dispatch, Lease: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	command.Negotiation = receipt
	command.Start = start
	return gateway, command, current
}

func nativeHTTPResult(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	message, _ := decodeMCPMessage(body)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"actual fixture result"}],"isError":false}}`, message.ID)
}

func TestNativeHTTPProviderOneWinnerAndDurableImmutableTerminalAfterReconstruction(t *testing.T) {
	var calls atomic.Int32
	server := nativeHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); nativeHTTPResult(w, r) })
	fixture := newNativeHTTPFixture(t, server.URL)
	_, command, _ := prepareNativeHTTPCommand(t, fixture)
	provider := fixture.factory.providers[fixture.effect.ProviderID]
	var wait sync.WaitGroup
	results := make(chan ProviderStartResult, 32)
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := provider.Start(context.Background(), command)
			if err == nil {
				results <- result
			}
		}()
	}
	wait.Wait()
	close(results)
	if calls.Load() != 1 {
		t.Fatalf("actual HTTP tools/call count=%d", calls.Load())
	}
	var accepted string
	for result := range results {
		if accepted == "" {
			accepted = result.ProviderRequestID
		}
		if result.ProviderRequestID != accepted || result.Call == nil {
			t.Fatal("immutable acceptance mismatch")
		}
		event, err := result.Call.Next(context.Background())
		if err != nil || event.Kind != ProviderCompleted || !json.Valid(event.Output) || event.ExternalCommitID != "" {
			t.Fatal("invented or invalid terminal receipt")
		}
	}
	if accepted == "" {
		t.Fatal("no winning completed receipt")
	}
	repository, err := newNativeRepository(fixture.source, fixture.factory.repository.binding, fixture.factory.repository.check, "native-http-fixture", 128, 1<<20, fixture.factory.repository.now)
	if err != nil {
		t.Fatal(err)
	}
	config := testMCPHTTPConfig(server.URL)
	reopened, err := newNativeFactory(repository, fixture.configuration, map[string]NativeProviderConfig{fixture.effect.ProviderID: {StreamableHTTP: &config}})
	if err != nil {
		t.Fatal(err)
	}
	query := LedgerQuery{Scope: command.Scope, Server: command.Server, ToolName: command.ToolName, InvocationID: command.InvocationID, RequestDigest: command.RequestDigest, Negotiation: command.Negotiation, Start: command.Start}
	record, err := reopened.providers[fixture.effect.ProviderID].Lookup(context.Background(), query)
	if err != nil || record.Status != LedgerCommitted || record.ProviderRequestID != accepted || !json.Valid(record.Output) || calls.Load() != 1 {
		t.Fatalf("reopened retained fact: %v/%s/%d", err, record.Status, calls.Load())
	}
	fixture.source.mu.Lock()
	barriers := len(fixture.source.barriers)
	fixture.source.mu.Unlock()
	if barriers < 32 {
		t.Fatal("provider reads/claims returned without exact barriers")
	}
}

func TestNativeHTTPProviderLostResponseNeverRestartsClaimedInvocation(t *testing.T) {
	var calls atomic.Int32
	server := nativeHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	})
	fixture := newNativeHTTPFixture(t, server.URL)
	_, command, _ := prepareNativeHTTPCommand(t, fixture)
	provider := fixture.factory.providers[fixture.effect.ProviderID]
	for range 3 {
		result, err := provider.Start(context.Background(), command)
		if err == nil || result.ProviderRequestID != "" {
			t.Fatal("lost response manufactured acceptance")
		}
	}
	record, err := provider.Lookup(context.Background(), LedgerQuery{Scope: command.Scope, Server: command.Server, ToolName: command.ToolName, InvocationID: command.InvocationID, RequestDigest: command.RequestDigest, Negotiation: command.Negotiation, Start: command.Start})
	if err != nil || record.Status != LedgerUnknown || calls.Load() != 1 {
		t.Fatalf("ambiguous start replayed or promoted: %v/%s/%d", err, record.Status, calls.Load())
	}
}

func TestNativeHTTPProviderRPCErrorDoesNotProveExternalRollback(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(fmt.Sprint(valid), func(t *testing.T) {
			var calls atomic.Int32
			server := nativeHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, _ := io.ReadAll(r.Body)
				message, _ := decodeMCPMessage(body)
				w.Header().Set("Content-Type", "application/json")
				failure := `{"code":-32603,"message":"internal failure"}`
				if !valid {
					failure = `null`
				}
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":%s}`, message.ID, failure)
			})
			fixture := newNativeHTTPFixture(t, server.URL)
			_, command, _ := prepareNativeHTTPCommand(t, fixture)
			provider := fixture.factory.providers[fixture.effect.ProviderID]
			for range 2 {
				if _, err := provider.Start(context.Background(), command); err == nil {
					t.Fatal("RPC error was promoted to a completed tool result")
				}
			}
			record, err := provider.Lookup(context.Background(), LedgerQuery{Scope: command.Scope, Server: command.Server, ToolName: command.ToolName, InvocationID: command.InvocationID, RequestDigest: command.RequestDigest, Negotiation: command.Negotiation, Start: command.Start})
			if err != nil || record.Status != LedgerUnknown || calls.Load() != 1 {
				t.Fatal("RPC error manufactured rollback or replay authority")
			}
			if valid != (record.ProviderRequestID != "") {
				t.Fatal("malformed error supplied acceptance authority")
			}
		})
	}
}

func TestNativeHTTPProviderCancellationNotificationCannotProvePrevention(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls, cancels atomic.Int32
	server := nativeHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		message, _ := decodeMCPMessage(body)
		if message.Method == "notifications/cancelled" {
			cancels.Add(1)
			w.WriteHeader(202)
			return
		}
		calls.Add(1)
		close(started)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		nativeHTTPResult(w, r)
	})
	fixture := newNativeHTTPFixture(t, server.URL)
	gateway, command, current := prepareNativeHTTPCommand(t, fixture)
	provider := fixture.factory.providers[fixture.effect.ProviderID]
	done := make(chan error, 1)
	go func() { _, err := provider.Start(context.Background(), command); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("actual call did not start")
	}
	cancelled, err := gateway.Cancel(context.Background(), fixture.bearer, current)
	if err != nil || cancelled.State == StateCancelled || cancels.Load() != 1 {
		close(release)
		t.Fatalf("notification fabricated prevention: %v/%s/%d", err, cancelled.State, cancels.Load())
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("late cancelled response was promoted")
	}
	record, err := provider.Lookup(context.Background(), LedgerQuery{Scope: command.Scope, Server: command.Server, ToolName: command.ToolName, InvocationID: command.InvocationID, RequestDigest: command.RequestDigest, Negotiation: command.Negotiation, Start: command.Start})
	if err != nil || record.Status != LedgerUnknown || calls.Load() != 1 {
		t.Fatal("cancellation lost conservative unknown fact")
	}
	repository, err := newNativeRepository(fixture.source, fixture.factory.repository.binding, fixture.factory.repository.check, "native-http-fixture", 128, 1<<20, fixture.factory.repository.now)
	if err != nil {
		t.Fatal(err)
	}
	config := testMCPHTTPConfig(server.URL)
	reopened, err := newNativeFactory(repository, fixture.configuration, map[string]NativeProviderConfig{fixture.effect.ProviderID: {StreamableHTTP: &config}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.providers[fixture.effect.ProviderID].Start(context.Background(), command); err == nil {
		t.Fatal("cold cancellation replay restarted an uncertain invocation")
	}
	cold, err := reopened.repository.Load(context.Background(), command.InvocationID)
	if err != nil || cold.Effect.State != StateUncertain || calls.Load() != 1 {
		t.Fatalf("cold owner/state did not survive: %v/%s", err, cold.Effect.State)
	}
	fixture.source.mu.Lock()
	encoded := bytes.Clone(fixture.source.state)
	fixture.source.mu.Unlock()
	state, err := decodeNativeState(encoded, "native-http-fixture", 128, 1<<20)
	if err != nil || state.Repository.active[keyForScope(command.Scope)] != command.InvocationID.String() || !state.WireInvocations[nativeWireKey(fixture.effect.ProviderID, command.InvocationID, command.Attempt)].CancellationClaimed {
		t.Fatal("cold reconstruction cleared cancellation tombstone or uncertain owner")
	}
}

func TestNativeHTTPProviderRejectsLostBarrierStaleAuthorityAndForgedStart(t *testing.T) {
	var calls atomic.Int32
	server := nativeHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); nativeHTTPResult(w, r) })
	fixture := newNativeHTTPFixture(t, server.URL)
	_, command, _ := prepareNativeHTTPCommand(t, fixture)
	provider := fixture.factory.providers[fixture.effect.ProviderID]
	for _, mutate := range []func(*ProviderCommand){func(c *ProviderCommand) { c.Start.Proof[0] ^= 1 }, func(c *ProviderCommand) { c.Scope.Generations.Policy++ }, func(c *ProviderCommand) { c.InputCanonical = []byte{0xa0} }} {
		invalid := command
		mutate(&invalid)
		if _, err := provider.Start(context.Background(), invalid); err == nil {
			t.Fatal("invalid authority/start/input entered HTTP")
		}
	}
	fixture.source.mu.Lock()
	fixture.source.barrierError = errors.New("fixture barrier unavailable")
	fixture.source.mu.Unlock()
	if _, err := provider.Start(context.Background(), command); err == nil {
		t.Fatal("lost claim barrier enabled I/O")
	}
	fixture.source.mu.Lock()
	fixture.source.barrierError = nil
	fixture.source.mu.Unlock()
	if _, err := provider.Start(context.Background(), command); err == nil {
		t.Fatal("a possibly persisted claim was restarted after barrier loss")
	}
	if calls.Load() != 0 {
		t.Fatal("unauthorized or non-durable start reached actual HTTP")
	}
}

func TestNativeHTTPFactoryPolicyBindsTargetsAndUnavailableMode(t *testing.T) {
	server := nativeHTTPTestServer(t, nativeHTTPResult)
	fixture := newNativeHTTPFixture(t, server.URL)
	provisionNativeFixture(t, fixture)
	repository, err := newNativeRepository(fixture.source, fixture.factory.repository.binding, fixture.factory.repository.check, "native-http-fixture", 128, 1<<20, fixture.factory.repository.now)
	if err != nil {
		t.Fatal(err)
	}
	changed := testMCPHTTPConfig(server.URL + "/changed")
	other, err := newNativeFactory(repository, fixture.configuration, map[string]NativeProviderConfig{fixture.effect.ProviderID: {StreamableHTTP: &changed}})
	if err != nil {
		t.Fatal(err)
	}
	if other.policyDigest == fixture.factory.policyDigest {
		t.Fatal("target mutation retained policy identity")
	}
	if err := other.ProvisionGrant(context.Background(), fixture.grant); !errors.Is(err, ErrStaleAuthority) {
		t.Fatal("changed target reused existing native policy state")
	}
	if _, err := NewProductionGateway(fixture.configuration, qualifyNativeFactory(t, fixture)); err != nil {
		t.Fatal(err)
	}
	if _, err := newNativeFactory(nil, fixture.configuration, nil); err == nil {
		t.Fatal("missing native source accepted")
	}
}

func TestNativeHTTPProductionSessionConstructorRequiresExactFactoryOwnedTransport(t *testing.T) {
	server := nativeHTTPTestServer(t, nativeHTTPResult)
	fixture := newNativeHTTPFixture(t, server.URL)
	gateway, err := NewProductionGateway(fixture.configuration, qualifyNativeFactory(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	route := broker.Digest(digestWithByte(99))
	ledger := nativeStarterFixtureLedger(t, fixture.proofs, broker.ServiceMCP, route, effectledger.ReferenceLimits{MaximumPayloadBytes: 1 << 16, MaximumResultBytes: 1 << 16})
	starter, err := NewProductionSessionDispatchStarter(gateway, ledger, route)
	if err != nil || starter.nativeSource == nil || starter.nativeSource.factory != fixture.factory {
		t.Fatalf("concrete native production starter: %v", err)
	}
	if !reflect.DeepEqual(starter.nativeSource.routeDigest, route) {
		t.Fatal("Session route provenance lost")
	}
}

func TestNativeHTTPProviderRejectsGenuineReferenceSessionPermitBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	server := nativeHTTPTestServer(t, nativeHTTPResult, func() { calls.Add(1) })
	fixture := newNativeHTTPFixture(t, server.URL)
	provisionNativeFixture(t, fixture)
	// The ordinary prepared native command supplies real persisted dispatch and
	// authorization, while the Session seal is a genuine reference broker claim.
	_, command, _ := prepareNativeHTTPCommand(t, fixture)
	route := broker.Digest(digestWithByte(98))
	call := sessionCall(fixture.reference)
	dispatch := sessionDispatch(t, fixture.reference, call, route)
	dispatch.EffectID = command.Scope.EffectID
	dispatch.InvocationID = command.Scope.InvocationID
	dispatch.WorkspaceID = command.Scope.WorkspaceID
	dispatch.Generations.Sandbox = command.Scope.Generations.Sandbox
	store := effectledger.NewReferenceStore()
	sessionLedger := newSessionLedger(t, store, route)
	reference, err := NewReferenceSessionDispatchStarter(fixture.reference.gateway, sessionLedger, route)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := reference.Prepare(context.Background(), dispatch, fixture.effect.Scope.RuntimeRevision, call)
	if err != nil {
		t.Fatal(err)
	}
	var permit SessionProviderPermit
	fixture.reference.provider.negotiate = func(ctx context.Context, cmd NegotiationCommand) (StartNegotiationReceipt, error) {
		permit = cmd.Session
		return StartNegotiationReceipt{}, ErrProviderUnavailable
	}
	consumer := mustSessionConsumer(t, newSessionClaimer(t, dispatch, prepared), reference)
	if _, err := consumer.StartExactAttempt(context.Background(), broker.DispatchStartRequest{Dispatch: dispatch, CommandDigest: prepared}); err != nil {
		t.Fatal(err)
	}
	opened, ok := permit.Open()
	if !ok {
		t.Fatal("genuine reference Session permit did not open")
	}
	command.Dispatch.Proof = OpaqueDispatchPermit(permit.Proof)
	command.Dispatch.EffectRevision = opened.EventSequence
	command.Session = permit
	before := calls.Load()
	if _, err := fixture.factory.providers[fixture.effect.ProviderID].Negotiate(context.Background(), nativeNegotiation(command)); err == nil {
		t.Fatal("reference Session permit obtained native provider authority")
	}
	if calls.Load() != before {
		t.Fatal("reference Session claim reached provider network I/O")
	}
}
