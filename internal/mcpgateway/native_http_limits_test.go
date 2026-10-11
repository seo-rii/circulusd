package mcpgateway

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
)

func nativeHTTPWireLimitInput(t *testing.T, fixture *nativeFactoryFixture) canonical.Map {
	t.Helper()
	// HTML escaping grows an ordinary legal CBOR string beyond the 4 KiB
	// HTTP limit. No unsupported value or oversized canonical input is needed.
	input := canonical.Map{"text": strings.Repeat("<", 750)}
	encoded, digest, err := canonicalizeCall(CallRequest{ServerID: fixture.effect.ServerID, ToolName: fixture.effect.ToolName, Input: input}, fixture.configuration.Bounds)
	if err != nil || len(encoded) != 759 || len(encoded) >= int(fixture.configuration.Bounds.MaxInputBytes) {
		t.Fatalf("ordinary bounded canonical input: bytes=%d, error=%v", len(encoded), err)
	}
	fixture.effect.InputCanonical = encoded
	fixture.effect.RequestDigest = digest
	fixture.grant.RequestDigest = digest
	return input
}

func TestNativeHTTPProviderWireLimitPreservesAbsenceAfterReplayAndReconstruction(t *testing.T) {
	var calls atomic.Int32
	server := nativeHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		nativeHTTPResult(w, r)
	})
	fixture := newNativeHTTPFixture(t, server.URL)
	nativeHTTPWireLimitInput(t, &fixture)
	_, command, _ := prepareNativeHTTPCommand(t, fixture)
	query := LedgerQuery{Scope: command.Scope, Server: command.Server, ToolName: command.ToolName, InvocationID: command.InvocationID, RequestDigest: command.RequestDigest, Negotiation: command.Negotiation, Start: command.Start}
	provider := fixture.factory.providers[fixture.effect.ProviderID]
	for reconstruction := 0; reconstruction < 2; reconstruction++ {
		if reconstruction != 0 {
			repository, err := newNativeRepository(fixture.source, fixture.factory.repository.binding, fixture.factory.repository.check, "native-http-fixture", 128, 1<<20, fixture.factory.repository.now)
			if err != nil {
				t.Fatal(err)
			}
			config := testMCPHTTPConfig(server.URL)
			reopened, err := newNativeFactory(repository, fixture.configuration, map[string]NativeProviderConfig{fixture.effect.ProviderID: {StreamableHTTP: &config}})
			if err != nil {
				t.Fatal(err)
			}
			provider = reopened.providers[fixture.effect.ProviderID]
		}
		for range 2 {
			result, err := provider.Start(context.Background(), command)
			var failure *ProviderDispatchError
			if !errors.As(err, &failure) || failure.Classification() != DispatchDefinitelyNotSent || !errors.Is(err, ErrInvalidRequest) || result.ProviderRequestID != "" || result.Call != nil {
				t.Fatalf("pre-I/O size rejection did not prove absence: result=%#v, error=%v", result, err)
			}
			record, err := provider.Lookup(context.Background(), query)
			if err != nil || record.Status != LedgerAbsent || record.ProviderRequestID != "" || calls.Load() != 0 {
				t.Fatalf("unsent invocation lost absence: status=%s, error=%v, calls=%d", record.Status, err, calls.Load())
			}
		}
	}
}

func TestNativeHTTPProviderWireLimitStillRequiresAuthorityAndReadBarrier(t *testing.T) {
	var calls atomic.Int32
	server := nativeHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		nativeHTTPResult(w, r)
	})
	fixture := newNativeHTTPFixture(t, server.URL)
	nativeHTTPWireLimitInput(t, &fixture)
	_, command, _ := prepareNativeHTTPCommand(t, fixture)
	provider := fixture.factory.providers[fixture.effect.ProviderID]
	forged := command
	forged.Start.Proof = OpaqueProviderStartPermit{}
	_, err := provider.Start(context.Background(), forged)
	var failure *ProviderDispatchError
	if errors.As(err, &failure) || !errors.Is(err, ErrDispatchNotDurable) {
		t.Fatalf("size rejection bypassed the durable start permit: %v", err)
	}
	fixture.source.mu.Lock()
	barriers := len(fixture.source.barriers)
	fixture.source.mu.Unlock()
	_, err = provider.Start(context.Background(), command)
	if !errors.As(err, &failure) || failure.Classification() != DispatchDefinitelyNotSent {
		t.Fatalf("ordinary pre-I/O rejection: %v", err)
	}
	fixture.source.mu.Lock()
	observed := len(fixture.source.barriers)
	fixture.source.barrierError = errors.New("fixture barrier unavailable")
	fixture.source.mu.Unlock()
	if observed <= barriers {
		t.Fatal("size rejection bypassed the native read barrier")
	}
	_, err = provider.Start(context.Background(), command)
	if errors.As(err, &failure) || !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("lost barrier incorrectly proved absence: %v", err)
	}
	fixture.source.mu.Lock()
	fixture.source.barrierError = nil
	fixture.source.mu.Unlock()
	current := command.Scope
	current.Generations.Policy++
	if err := fixture.factory.repository.SetCurrentAuthority(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	_, err = provider.Start(context.Background(), command)
	if errors.As(err, &failure) || !errors.Is(err, ErrStaleAuthority) || calls.Load() != 0 {
		t.Fatalf("size rejection bypassed current authority: error=%v, calls=%d", err, calls.Load())
	}
}

func TestNativeHTTPProviderClaimedAttemptCannotBecomeDefinitelyNotSent(t *testing.T) {
	var calls atomic.Int32
	server := nativeHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		connection, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			connection.Close()
		}
	})
	fixture := newNativeHTTPFixture(t, server.URL)
	_, command, _ := prepareNativeHTTPCommand(t, fixture)
	provider := fixture.factory.providers[fixture.effect.ProviderID].(*nativeHTTPProvider)
	if _, err := provider.Start(context.Background(), command); err == nil {
		t.Fatal("lost response invented a completed call")
	}
	// Even a newly restrictive local bound cannot erase an existing durable
	// start claim: the previous request might already have external effects.
	provider.transport.config.MaximumRequestBytes = 128
	result, err := provider.Start(context.Background(), command)
	var failure *ProviderDispatchError
	if err == nil || errors.As(err, &failure) || result.ProviderRequestID != "" {
		t.Fatalf("claimed invocation was reclassified as absent: result=%#v, error=%v", result, err)
	}
	record, err := provider.Lookup(context.Background(), LedgerQuery{Scope: command.Scope, Server: command.Server, ToolName: command.ToolName, InvocationID: command.InvocationID, RequestDigest: command.RequestDigest, Negotiation: command.Negotiation, Start: command.Start})
	if err != nil || record.Status != LedgerUnknown || calls.Load() != 1 {
		t.Fatalf("claimed wire attempt changed: status=%s, error=%v, calls=%d", record.Status, err, calls.Load())
	}
}

func TestNativeHTTPGatewayWireLimitTerminatesAfterAllowedRetries(t *testing.T) {
	var calls atomic.Int32
	server := nativeHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		nativeHTTPResult(w, r)
	})
	fixture := newNativeHTTPFixture(t, server.URL)
	input := nativeHTTPWireLimitInput(t, &fixture)
	provisionNativeFixture(t, fixture)
	gateway, err := NewProductionGateway(fixture.configuration, qualifyNativeFactory(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	current, err := gateway.Admit(context.Background(), AdmissionRequest{Authority: fixture.bearer, EffectID: fixture.effect.Scope.EffectID, InvocationID: fixture.effect.Scope.InvocationID, RequestDigest: fixture.effect.RequestDigest, Call: CallRequest{ServerID: fixture.effect.ServerID, ToolName: fixture.effect.ToolName, Input: input}})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := uint32(0); attempt <= current.MaxAutomaticRetries; attempt++ {
		current, err = gateway.Execute(context.Background(), fixture.bearer, current, discardSink())
		if err != nil {
			t.Fatal(err)
		}
		want := StateRetryPending
		if attempt == current.MaxAutomaticRetries {
			want = StateFailed
		}
		last, ok := current.CurrentAttempt()
		if !ok || current.State != want || last.Failure != FailureDefinitelyNotSent || last.ProviderRequestID != "" || calls.Load() != 0 {
			t.Fatalf("pre-I/O attempt %d: state=%s, failure=%s, provider=%q, calls=%d", attempt, current.State, last.Failure, last.ProviderRequestID, calls.Load())
		}
	}
}
