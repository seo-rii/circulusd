package mcpgateway

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/identity"
)

// TestEffectCrashRestartMatrix exercises a fresh Gateway instance against the
// same repository port at every durable boundary. MemoryRepository is only the
// reference transaction model; constructing a new Gateway ensures recovery is
// driven by committed state rather than executor-local memory.
func TestEffectCrashRestartMatrix(t *testing.T) {
	restart := func(
		t *testing.T,
		fixture gatewayFixture,
		server ServerRegistration,
		sampling SamplingBroker,
	) *Gateway {
		t.Helper()
		gateway, err := NewGateway(Configuration{
			Bounds: testBounds(), Servers: []ServerRegistration{server}, Tools: []ToolRegistration{fixture.tool},
			AllowReferenceMemory: true,
		}, Dependencies{
			Authority: fixture.authority, Authorizer: fixture.authorizer, Credentials: fixture.credentials,
			Repository: fixture.repository, Audit: fixture.gateway.audit,
			Providers: map[string]Provider{"stdio": fixture.provider}, Sampling: sampling,
		})
		if err != nil {
			t.Fatalf("restart gateway: %v", err)
		}
		return gateway
	}

	scenarios := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "prepared_safe_dispatches_once_after_restart",
			run: func(t *testing.T) {
				fixture := newGatewayFixture(t, ReplaySafe)
				prepared := admitFixtureEffect(t, fixture)
				fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
					return ProviderStartResult{
						ProviderRequestID: "rpc-restart-prepared", Call: completedCall(`{"prepared":true}`),
					}, nil
				}
				gateway := restart(t, fixture, fixture.server, nil)
				completed, err := gateway.Execute(context.Background(), OpaqueAuthority("renewed"), prepared, discardSink())
				if err != nil || completed.State != StateCompleted || fixture.provider.startCount() != 1 {
					t.Fatalf("prepared restart=%+v starts=%d err=%v", completed, fixture.provider.startCount(), err)
				}
			},
		},
		{
			name: "dispatch_claim_before_negotiation_recovers_without_phantom_start",
			run: func(t *testing.T) {
				fixture := newGatewayFixture(t, ReplaySafe)
				prepared := admitFixtureEffect(t, fixture)
				dispatching := applyFixtureEvent(t, fixture.gateway, prepared, Event{Kind: EventBeginDispatch})
				permit, err := fixture.repository.CommitAndClaimDispatch(context.Background(), DispatchClaimRequest{
					ExpectedRevision: prepared.Revision, CurrentScope: prepared.Scope,
					Previous: prepared, Next: dispatching, Authorization: permitForEffect(dispatching),
				})
				if err != nil || !permit.Durable {
					t.Fatalf("dispatch claim=%+v err=%v", permit, err)
				}
				gateway := restart(t, fixture, fixture.server, nil)
				recovered, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), dispatching)
				if err != nil || recovered.Action != RecoveryRetry || recovered.Effect.State != StateRetryPending ||
					fixture.provider.startCount() != 0 {
					t.Fatalf("pre-negotiation recovery=%+v starts=%d err=%v", recovered, fixture.provider.startCount(), err)
				}
				fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
					return ProviderStartResult{
						ProviderRequestID: "rpc-restart-dispatch-2", Call: completedCall(`{"retried":true}`),
					}, nil
				}
				completed, err := gateway.Execute(
					context.Background(), OpaqueAuthority("renewed"), recovered.Effect, discardSink(),
				)
				if err != nil || completed.State != StateCompleted || fixture.provider.startCount() != 1 {
					t.Fatalf("safe retry=%+v starts=%d err=%v", completed, fixture.provider.startCount(), err)
				}
			},
		},
		{
			name: "provider_accept_absent_safe_replays_but_confirm_unknown_does_not",
			run: func(t *testing.T) {
				t.Run("safe_absent", func(t *testing.T) {
					fixture := newGatewayFixture(t, ReplaySafe)
					dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-restart-safe-accepted")
					fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
						return LedgerRecord{
							InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerAbsent,
						}, nil
					}
					gateway := restart(t, fixture, fixture.server, nil)
					recovered, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), dispatched)
					if err != nil || recovered.Action != RecoveryRetry || recovered.Effect.State != StateRetryPending {
						t.Fatalf("safe absent recovery=%+v err=%v", recovered, err)
					}
					fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
						return ProviderStartResult{
							ProviderRequestID: "rpc-restart-safe-replay", Call: completedCall(`{"safe":true}`),
						}, nil
					}
					completed, err := gateway.Execute(
						context.Background(), OpaqueAuthority("renewed"), recovered.Effect, discardSink(),
					)
					if err != nil || completed.State != StateCompleted || fixture.provider.startCount() != 1 {
						t.Fatalf("safe replay=%+v starts=%d err=%v", completed, fixture.provider.startCount(), err)
					}
				})

				t.Run("confirm_unknown", func(t *testing.T) {
					fixture := newGatewayFixture(t, ReplayConfirm)
					dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-restart-confirm-accepted")
					fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
						return LedgerRecord{
							InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerUnknown,
						}, nil
					}
					gateway := restart(t, fixture, fixture.server, nil)
					recovered, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), dispatched)
					if err != nil || recovered.Action != RecoveryConfirmation ||
						recovered.Effect.State != StateNeedsConfirmation || fixture.provider.startCount() != 0 {
						t.Fatalf("confirm unknown recovery=%+v starts=%d err=%v",
							recovered, fixture.provider.startCount(), err)
					}
				})
			},
		},
		{
			name: "partial_chunk_without_retrieval_never_replays_after_restart",
			run: func(t *testing.T) {
				fixture := newGatewayFixture(t, ReplaySafe)
				fixture.provider.availability.SupportsInvocationLedger = false
				prepared := admitFixtureEffect(t, fixture)
				step := 0
				fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
					return ProviderStartResult{
						ProviderRequestID: "rpc-restart-partial",
						Call: &functionCall{next: func(context.Context) (ProviderEvent, error) {
							if step == 0 {
								step++
								return ProviderEvent{Kind: ProviderOutputChunk, Chunk: []byte("delivered")}, nil
							}
							return ProviderEvent{}, errors.New("transport lost after chunk")
						}},
					}, nil
				}
				uncertain, err := fixture.gateway.Execute(
					context.Background(), OpaqueAuthority("renewed"), prepared, discardSink(),
				)
				if err != nil || uncertain.State != StateUncertain || uncertain.ChunkCount != 1 {
					t.Fatalf("partial execution=%+v err=%v", uncertain, err)
				}
				starts := fixture.provider.startCount()
				gateway := restart(t, fixture, fixture.server, nil)
				recovered, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), uncertain)
				if err != nil || recovered.Action != RecoveryInterrupted || !sameEffect(recovered.Effect, uncertain) ||
					fixture.provider.startCount() != starts {
					t.Fatalf("partial restart=%+v starts=%d->%d err=%v",
						recovered, starts, fixture.provider.startCount(), err)
				}
				_, executeErr := gateway.Execute(
					context.Background(), OpaqueAuthority("renewed"), recovered.Effect, discardSink(),
				)
				if !errors.Is(executeErr, ErrInvalidTransition) || fixture.provider.startCount() != starts {
					t.Fatalf("partial restart replayed: starts=%d->%d err=%v",
						starts, fixture.provider.startCount(), executeErr)
				}
			},
		},
		{
			name: "final_commit_restarts_settlement_only",
			run: func(t *testing.T) {
				fixture := newGatewayFixture(t, ReplayNever)
				dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-restart-final")
				external := applyFixtureEvent(t, fixture.gateway, dispatched, Event{
					Kind: EventCallCommitted, Output: []byte(`{"committed":true}`), ExternalCommitID: "commit-restart-final",
				})
				persistFixtureEffect(t, fixture.repository, dispatched, external)
				lookups := 0
				fixture.provider.lookup = func(context.Context, LedgerQuery) (LedgerRecord, error) {
					lookups++
					return LedgerRecord{}, errors.New("settlement-only recovery must not query")
				}
				gateway := restart(t, fixture, fixture.server, nil)
				recovered, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), external)
				if err != nil || recovered.Action != RecoverySettled || recovered.Effect.State != StateCompleted ||
					lookups != 0 || fixture.provider.startCount() != 0 {
					t.Fatalf("final restart=%+v lookups=%d starts=%d err=%v",
						recovered, lookups, fixture.provider.startCount(), err)
				}
			},
		},
		{
			name: "settled_state_and_stale_snapshot_are_terminal_after_restart",
			run: func(t *testing.T) {
				fixture := newGatewayFixture(t, ReplayNever)
				dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-restart-settled")
				external := applyFixtureEvent(t, fixture.gateway, dispatched, Event{
					Kind: EventCallCommitted, Output: []byte(`{"settled":true}`), ExternalCommitID: "commit-restart-settled",
				})
				persistFixtureEffect(t, fixture.repository, dispatched, external)
				completed := applyFixtureEvent(t, fixture.gateway, external, Event{Kind: EventSettlementCompleted})
				persistFixtureEffect(t, fixture.repository, external, completed)
				lookups := 0
				fixture.provider.lookup = func(context.Context, LedgerQuery) (LedgerRecord, error) {
					lookups++
					return LedgerRecord{}, errors.New("terminal recovery must not query")
				}
				gateway := restart(t, fixture, fixture.server, nil)
				recovered, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), dispatched)
				if err != nil || recovered.Action != RecoverySettled || !sameEffect(recovered.Effect, completed) ||
					lookups != 0 || fixture.provider.startCount() != 0 {
					t.Fatalf("stale settled restart=%+v lookups=%d starts=%d err=%v",
						recovered, lookups, fixture.provider.startCount(), err)
				}
			},
		},
		{
			name: "durable_cancel_intent_is_reissued_after_restart",
			run: func(t *testing.T) {
				fixture := newGatewayFixture(t, ReplayNever)
				dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-restart-cancel")
				pending := applyFixtureEvent(t, fixture.gateway, dispatched, Event{Kind: EventCancelRequested})
				persistFixtureEffect(t, fixture.repository, dispatched, pending)
				cancels := 0
				fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
					cancels++
					return CancellationResult{Status: CancellationAbsent}, nil
				}
				gateway := restart(t, fixture, fixture.server, nil)
				recovered, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), pending)
				if err != nil || recovered.Effect.State != StateCancelled || cancels != 1 {
					t.Fatalf("cancel restart=%+v cancels=%d err=%v", recovered, cancels, err)
				}
				again := restart(t, fixture, fixture.server, nil)
				replayed, err := again.Recover(context.Background(), OpaqueAuthority("renewed"), pending)
				if err != nil || replayed.Effect.State != StateCancelled || cancels != 1 {
					t.Fatalf("cancel replay=%+v cancels=%d err=%v", replayed, cancels, err)
				}
			},
		},
		{
			name: "expired_server_child_claim_is_cancelled_before_parent_after_restart",
			run: func(t *testing.T) {
				fixture, _, sampling := newSamplingGatewayFixture(t)
				server := fixture.server
				server.AllowedServerRequests = []ServerRequestMethod{ServerRequestSampling}
				dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-restart-child")
				now := time.Unix(1_800_000_000, 0)
				fixture.repository.now = func() time.Time { return now }
				claimed, err := fixture.repository.ClaimServerRequest(context.Background(), ServerRequestClaimRequest{
					CurrentScope: dispatched.Scope, Parent: dispatched, ProviderRequestID: "rpc-restart-child",
					ConnectionGeneration: connectionGenerationForEffect(dispatched), RequestID: "sampling-restart-child",
					Method: string(ServerRequestSampling), RequestDigest: sha256.Sum256([]byte("sampling-restart-child")),
					ChildEffectID: mustID(t, identity.Effect), ChildInvocationID: mustID(t, identity.Invocation),
					BrokerCancellationRequired: true,
					MaxRequests:                testBounds().MaxEvents, Lease: testBounds().CancelTimeout,
				})
				if err != nil || !claimed.Fresh {
					t.Fatalf("child claim=%+v err=%v", claimed, err)
				}
				now = now.Add(testBounds().CancelTimeout + time.Nanosecond)
				fixture.provider.cancel = func(context.Context, CancelCommand) (CancellationResult, error) {
					return CancellationResult{Status: CancellationAbsent}, nil
				}
				gateway := restart(t, fixture, server, sampling)
				recovered, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), dispatched)
				if err != nil || recovered.Effect.State != StateCancelled || sampling.cancelCalls != 1 {
					t.Fatalf("child restart=%+v child-cancels=%d err=%v", recovered, sampling.cancelCalls, err)
				}
				fixture.repository.mu.RLock()
				record := fixture.repository.serverRequests[serverRequestKey{
					invocation: dispatched.Scope.InvocationID, providerRequestID: "rpc-restart-child",
					connectionGeneration: connectionGenerationForEffect(dispatched), requestID: "sampling-restart-child",
				}]
				fixture.repository.mu.RUnlock()
				if record.State != ServerRequestAbandoned || record.ChildCancellation == (SamplingCancellationReceipt{}) {
					t.Fatalf("child reconciliation was not durable: %+v", record)
				}
			},
		},
		{
			name: "active_provider_start_claim_waits_then_lease_expiry_uses_ledger",
			run: func(t *testing.T) {
				fixture := newGatewayFixture(t, ReplaySafe)
				now := time.Unix(1_800_000_000, 0)
				fixture.repository.now = func() time.Time { return now }
				prepared := admitFixtureEffect(t, fixture)
				dispatching := applyFixtureEvent(t, fixture.gateway, prepared, Event{Kind: EventBeginDispatch})
				dispatchPermit, err := fixture.repository.CommitAndClaimDispatch(context.Background(), DispatchClaimRequest{
					ExpectedRevision: prepared.Revision, CurrentScope: prepared.Scope,
					Previous: prepared, Next: dispatching, Authorization: permitForEffect(dispatching),
				})
				if err != nil {
					t.Fatal(err)
				}
				negotiated := negotiateFixtureEffect(t, fixture.gateway, dispatching)
				persistFixtureEffect(t, fixture.repository, dispatching, negotiated)
				startPermit, err := fixture.repository.ClaimProviderStart(context.Background(), ProviderStartClaimRequest{
					CurrentScope: negotiated.Scope, Effect: negotiated, Dispatch: dispatchPermit, Lease: testBounds().CancelTimeout,
				})
				if err != nil || !startPermit.Durable {
					t.Fatalf("provider start claim=%+v err=%v", startPermit, err)
				}
				lookups := 0
				fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
					lookups++
					return LedgerRecord{
						InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerAbsent,
					}, nil
				}
				gateway := restart(t, fixture, fixture.server, nil)
				waiting, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), negotiated)
				if err != nil || waiting.Action != RecoveryWait || !sameEffect(waiting.Effect, negotiated) || lookups != 0 {
					t.Fatalf("live lease recovery=%+v lookups=%d err=%v", waiting, lookups, err)
				}
				now = now.Add(testBounds().CancelTimeout + time.Nanosecond)
				recovered, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), negotiated)
				if err != nil || recovered.Action != RecoveryRetry || recovered.Effect.State != StateRetryPending || lookups != 1 ||
					fixture.provider.startCount() != 0 {
					t.Fatalf("expired lease recovery=%+v lookups=%d starts=%d err=%v",
						recovered, lookups, fixture.provider.startCount(), err)
				}
			},
		},
		{
			name: "stale_generation_fails_before_provider_after_restart",
			run: func(t *testing.T) {
				fixture := newGatewayFixture(t, ReplaySafe)
				prepared := admitFixtureEffect(t, fixture)
				rotated := prepared.Scope
				rotated.Generations.Placement++
				if err := fixture.repository.SetCurrentAuthority(rotated); err != nil {
					t.Fatal(err)
				}
				fixture.provider.start = func(context.Context, ProviderCommand) (ProviderStartResult, error) {
					return ProviderStartResult{
						ProviderRequestID: "must-not-run", Call: completedCall(`{"unsafe":true}`),
					}, nil
				}
				gateway := restart(t, fixture, fixture.server, nil)
				_, err := gateway.Execute(context.Background(), OpaqueAuthority("stale"), prepared, discardSink())
				if !errors.Is(err, ErrStaleAuthority) || fixture.provider.startCount() != 0 {
					t.Fatalf("stale restart starts=%d err=%v", fixture.provider.startCount(), err)
				}
			},
		},
		{
			name: "concurrent_restarted_recovery_converges_after_cas_loss",
			run: func(t *testing.T) {
				fixture := newGatewayFixture(t, ReplayNever)
				dispatched := durablyDispatchedFixtureEffect(t, fixture, "rpc-restart-cas")
				arrived := make(chan struct{}, 2)
				release := make(chan struct{})
				fixture.provider.lookup = func(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
					arrived <- struct{}{}
					<-release
					return LedgerRecord{
						InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerCommitted,
						ProviderRequestID: "rpc-restart-cas", ExternalCommitID: "commit-restart-cas",
						Output: []byte(`{"cas":true}`),
					}, nil
				}
				gateways := []*Gateway{
					restart(t, fixture, fixture.server, nil), restart(t, fixture, fixture.server, nil),
				}
				type result struct {
					recovery RecoveryResult
					err      error
				}
				results := make(chan result, 2)
				for _, gateway := range gateways {
					gateway := gateway
					go func() {
						recovery, err := gateway.Recover(context.Background(), OpaqueAuthority("renewed"), dispatched)
						results <- result{recovery: recovery, err: err}
					}()
				}
				<-arrived
				<-arrived
				close(release)
				for range 2 {
					result := <-results
					if result.err != nil || result.recovery.Action != RecoverySettled ||
						result.recovery.Effect.State != StateCompleted {
						t.Fatalf("CAS recovery=%+v err=%v", result.recovery, result.err)
					}
				}
				if fixture.provider.startCount() != 0 {
					t.Fatalf("CAS convergence redispatched provider %d times", fixture.provider.startCount())
				}
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, scenario.run)
	}
}
