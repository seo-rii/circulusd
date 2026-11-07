package modelgateway

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/celldbridge"
	"github.com/hancomac/circulusd/internal/dependency"
	contract "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/effectledger"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/stateappbroker"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

// Every transport and signature below is an explicitly unqualified fixture.
// The real concrete Store decodes authenticated HTTP bytes; its runtime proof
// is still only contracttest evidence, never a served-path qualification.
type sessionQuotaHost struct {
	*contract.ProductionProofs
	mu     sync.Mutex
	result canonical.Map
	tamper bool
}

func (host *sessionQuotaHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "fixture read failed", 400)
		return
	}
	value, err := canonical.Decode(body, canonical.DefaultOptions())
	if err != nil {
		http.Error(w, "fixture decode failed", 400)
		return
	}
	request := value.(canonical.Map)
	if r.URL.Path == "/circulusd/state/v1/production:probe" {
		response, err := host.ProbeProduction(r.Context(), dependency.ProbeChallenge{Nonce: request["nonce"].(canonical.Bytes)})
		if err != nil {
			http.Error(w, "fixture probe failed", 400)
			return
		}
		d := response.Descriptor
		groups := canonical.Array{}
		for _, group := range d.AtomicGroups {
			groups = append(groups, string(group))
		}
		wire := canonical.Map{"protocol": "circulus.state-production-probe.v1alpha1", "major": int64(1), "minor": int64(0), "schemaDigest": "sha256:33c8297cba9d6460e219e31e8c080927ed6275407c6eb159ea1f4d06fc87910f", "algorithm": "ed25519", "keyId": response.KeyID, "signature": canonical.Bytes(response.Signature), "descriptor": canonical.Map{"schemaVersion": uint64(d.SchemaVersion), "backendKind": d.BackendKind, "buildDigest": d.BuildDigest, "applicationDigest": d.ApplicationDigest, "instanceId": d.InstanceID, "transactionDomainId": d.TransactionDomainID, "durabilityClass": d.DurabilityClass, "conformanceRunId": d.ConformanceRunID, "conformanceDigest": d.ConformanceDigest, "runtimeKeyId": d.RuntimeKeyID, "probeEpoch": d.ProbeEpoch, "productionEligible": d.ProductionEligible, "atomicGroups": groups}}
		encoded, _ := canonical.Encode(wire, canonical.DefaultOptions())
		w.Header().Set("Content-Type", "application/vnd.circulusd.state-production-probe+cbor")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(encoded)
		return
	}
	if r.URL.Path != "/circulusd/state/v1/session-broker:execute" || request["operation"] != "lookup-operation" {
		http.Error(w, "unexpected fixture operation", 400)
		return
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	id := request["requestId"].(string)
	response, _ := canonical.Encode(canonical.Map{"protocol": "circulus.v1alpha1", "major": int64(1), "minor": int64(0), "schemaDigest": "sha256:5f9c46ee54e71d97d57295235810a70d70b1579fdcb077ede948c3e680405845", "requestId": id, "payload": canonical.Map{"ok": true, "result": host.result}}, canonical.DefaultOptions())
	const contentType = "application/vnd.circulusd.state-broker-ingress+cbor"
	requestDigest, bodyDigest := sha256.Sum256(body), sha256.Sum256(response)
	keyMAC := hmac.New(sha256.New, bytes.Repeat([]byte{4}, 32))
	_, _ = keyMAC.Write([]byte("circulusd.state-ingress.key.response.v1\x00"))
	mac := hmac.New(sha256.New, keyMAC.Sum(nil))
	for _, part := range [][]byte{[]byte("circulusd.state-broker-ingress.response.v1"), []byte("broker"), []byte(id), requestDigest[:], []byte("200"), []byte(contentType), bodyDigest[:]} {
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], uint32(len(part)))
		_, _ = mac.Write(prefix[:])
		_, _ = mac.Write(part)
	}
	signature := hex.EncodeToString(mac.Sum(nil))
	if host.tamper {
		signature = hex.EncodeToString(make([]byte, 32))
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Circulus-State-Key-Id", "broker")
	w.Header().Set("X-Circulus-State-Signature", signature)
	_, _ = w.Write(response)
}

type sessionQuotaResults struct{ *contract.ProductionProofs }

func (*sessionQuotaResults) ResolveResult(context.Context, stateappbroker.ResultRequest) (stateappbroker.Result, error) {
	return stateappbroker.Result{}, errors.New("lookup fixture never resolves results")
}

type sessionQuotaSource struct {
	*nativeModelFixture
	fault          string
	failedRevision uint64
}

func (source *sessionQuotaSource) CompareAndCommit(ctx context.Context, request celldbridge.CommitRequest) (celldbridge.CommitResult, error) {
	result, err := source.nativeModelFixture.CompareAndCommit(ctx, request)
	if err != nil || !request.StateWritten {
		return result, err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	switch source.fault {
	case "commit-reply":
		source.fault = ""
		return celldbridge.CommitResult{}, errors.New("test accounting commit reply lost")
	case "projection-barrier":
		source.failedRevision = result.Token.Revision
	}
	return result, nil
}

func (source *sessionQuotaSource) ConfirmBarrier(ctx context.Context, request celldbridge.BarrierRequest) (celldbridge.BarrierResult, error) {
	result, err := source.nativeModelFixture.ConfirmBarrier(ctx, request)
	if err != nil {
		return result, err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if (source.fault == "projection-barrier" && source.failedRevision == request.Token.Revision) || (source.fault == "ledger-barrier" && request.Token.ObjectID != "native-model-test") {
		source.fault = ""
		return celldbridge.BarrierResult{}, errors.New("test exact accounting barrier reply lost")
	}
	return result, nil
}

type sessionQuotaFixture struct {
	factory       *NativeFactory
	source        *nativeModelFixture
	faultSource   *sessionQuotaSource
	factoryConfig NativeFactoryConfig
	reference     *fixture
	ledger        *effectledger.NativeLedger
	bridge        *NativeSessionQuotaBridge
	config        NativeSessionQuotaConfig
	host          *sessionQuotaHost
	client        *stateappclient.Client
	request       QuotaRequest
	permit        QuotaPermit
	operation     NativeSessionOperation
}

func newSessionQuotaFixture(t *testing.T) *sessionQuotaFixture {
	t.Helper()
	reference := newFixture(t)
	// Stored provider commands contain the normalized request emitted by
	// admission, rather than the caller's optional/default spelling.
	reference.request.Reasoning.Effort = ReasoningEffortDefault
	groups := append(nativeModelGroups(), celldbridge.AtomicNativeStorage, dependency.AtomicEffectLifecycle, effectledger.AtomicProviderObservationLedger)
	slices.Sort(groups)
	proofs := contract.NewProductionProofs(t, groups)
	source := &nativeModelFixture{ProductionProofs: proofs, objects: make(map[string]celldbridge.Snapshot)}
	faultSource := &sessionQuotaSource{nativeModelFixture: source}
	transport := contract.Verify[celldbridge.NativeTransport](t, proofs, faultSource, groups)
	storage, err := celldbridge.New(celldbridge.Config{Transport: transport, MaximumAttempts: 8, Bounds: celldbridge.Bounds{MaxStateBytes: 131072, MaxReceiptResponseBytes: 1024, MaxCapabilityClaims: 1, MaxCapabilityClaimBytes: 1024, MaxReceiptLookups: 1, MaxReceiptWrites: 1, MaxTransactionBytes: 262144}})
	if err != nil {
		t.Fatal(err)
	}
	verifiedStorage := contract.Verify(t, proofs, storage, groups)
	factoryConfig := nativeModelConfig(verifiedStorage, reference)
	factory, err := NewNativeFactory(factoryConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := factory.ProvisionGrant(context.Background(), nativeModelGrant(t, reference, reference.scope, "fixture-authority")); err != nil {
		t.Fatal(err)
	}
	request := nativeModelQuotaRequest(reference, reference.scope)
	request.ContextTokens = 11
	request.OutputTokens = 17
	permit, err := factory.Candidates().Quota.Admit(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	route := sessionBrokerDigest(71)
	ledger, err := effectledger.NewNativeLedger(effectledger.NativeConfig{Storage: verifiedStorage, Service: broker.ServiceModel, RouteDigest: route, Limits: requiredSessionDispatchLedgerLimits(factory.configuration.Bounds), MaximumStateBytes: 131072})
	if err != nil {
		t.Fatal(err)
	}
	verifiedLedger := contract.Verify(t, proofs, ledger, groups)
	host := &sessionQuotaHost{ProductionProofs: proofs}
	server := httptest.NewServer(host)
	t.Cleanup(server.Close)
	client, err := stateappclient.New(stateappclient.Config{Endpoint: server.URL, KeyID: "read", RootKey: bytes.Repeat([]byte{1}, 32), BrokerKeyID: "broker", BrokerRootKey: bytes.Repeat([]byte{4}, 32), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	scope := NativeSessionQuotaScope{reference.scope.TenantID, reference.scope.UserID, mustID(t, identity.Workspace, 'w'), reference.scope.SessionID}
	results := &sessionQuotaResults{proofs}
	store, err := stateappbroker.New(client, stateappbroker.Config{Scope: stateappclient.BrokerScope{TenantID: scope.TenantID.String(), WorkspaceID: scope.WorkspaceID.String(), SessionID: scope.SessionID.String(), ActorSubjectID: scope.UserID.String(), ExpectedAuthorizationGeneration: reference.scope.Generations.Policy}, UserID: scope.UserID, EngineStepLimits: broker.EngineStepBudget{MaximumEvents: 1, MaximumEphemeralBytes: 65536, MaximumWallClock: time.Second}, Results: contract.Verify[stateappbroker.ResultResolver](t, proofs, results, groups)})
	if err != nil {
		t.Fatal(err)
	}
	config := NativeSessionQuotaConfig{Factory: factory, Session: contract.Verify(t, proofs, store, groups), Ledger: verifiedLedger, Scope: scope, RouteDigest: route}
	bridge, err := NewNativeSessionQuotaBridge(config)
	if err != nil {
		t.Fatal(err)
	}
	operation := NativeSessionOperation{Kind: broker.OperationRecoverySettlement, Key: "fixture-recovery", Digest: sessionBrokerDigest(81)}
	f := &sessionQuotaFixture{factory: factory, source: source, faultSource: faultSource, factoryConfig: factoryConfig, reference: reference, ledger: ledger, bridge: bridge, config: config, host: host, client: client, request: request, permit: permit, operation: operation}
	f.setReceipt(nil)
	return f
}

func (f *sessionQuotaFixture) setReceipt(receipt canonical.Value) {
	f.host.mu.Lock()
	defer f.host.mu.Unlock()
	f.host.result = canonical.Map{"found": receipt != nil, "kind": string(f.operation.Kind), "operationDigest": quotaWireDigest(f.operation.Digest), "receipt": receipt}
}

func quotaWireDigest(digest broker.Digest) string { return "sha256:" + hex.EncodeToString(digest[:]) }

func (f *sessionQuotaFixture) settlement(attempt uint64, recovery broker.RecoverySettlementKind, terminal effectledger.Terminal) canonical.Map {
	s := f.reference.scope
	var commit, result canonical.Value
	if terminal.ExternalCommitID != (identity.ID{}) {
		commit = terminal.ExternalCommitID.String()
	}
	if terminal.ResultRef != (identity.ID{}) {
		result = terminal.ResultRef.String()
	}
	var last canonical.Value
	if attempt != 0 {
		last = canonical.Map{"turnLeaseGeneration": s.Generations.TurnLease, "placementGeneration": s.Generations.Placement, "sandboxGeneration": uint64(4), "authorizationGeneration": s.Generations.Policy, "dispatchAttempt": attempt, "deadline": uint64(1800000060000), "providerRequestId": mustFixtureID(identity.Request, 'r').String(), "providerRouteDigest": quotaWireDigest(f.config.RouteDigest), "start": nil}
	}
	var recoveryValue canonical.Value
	var publicError canonical.Value
	if recovery != "" {
		recoveryValue = string(recovery)
		publicError = canonical.Map{"code": uint64(v1.ErrorCode_ERROR_CODE_UNAVAILABLE), "reason": "provider.failed", "message": "failed", "retryable": false, "retryAfterMs": uint64(0), "metadata": canonical.Map{}, "requestId": nil}
	}
	effect := canonical.Map{"tenantId": s.TenantID.String(), "userId": s.UserID.String(), "sessionId": s.SessionID.String(), "turnId": s.TurnID.String(), "effectId": s.EffectID.String(), "invocationId": s.InvocationID.String(), "requestDigest": quotaWireDigest(broker.Digest(f.request.RequestDigest)), "service": "model", "operation": sessionDispatchOperation, "replayPolicy": "never", "phase": "settled", "dispatchAttempt": attempt, "lastDispatch": last, "externalCommitId": commit, "resultRef": result, "settlement": nil, "consumedAtCheckpointSequence": nil, "consumedByAbort": false, "requestPayload": canonical.Map{}, "parentOperationId": "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{9}, 32)), "ordinal": uint64(0)}
	return canonical.Map{"tenantId": s.TenantID.String(), "workspaceId": f.config.Scope.WorkspaceID.String(), "userId": s.UserID.String(), "sessionId": s.SessionID.String(), "turnId": s.TurnID.String(), "effectId": s.EffectID.String(), "invocationId": s.InvocationID.String(), "requestDigest": quotaWireDigest(broker.Digest(f.request.RequestDigest)), "state": "settled", "dispatchAttempt": attempt, "externalCommitId": commit, "resultRef": result, "error": publicError, "operationDigest": quotaWireDigest(f.operation.Digest), "recoveryKind": recoveryValue, "effect": effect, "eventSequence": uint64(11), "durable": true}
}

func mustFixtureID(kind identity.Kind, seed byte) identity.ID {
	id, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte{seed}, 16))}).New(kind)
	if err != nil {
		panic(err)
	}
	return id
}

type sessionQuotaClaimer struct {
	*contract.ProductionProofs
	permit broker.DispatchStartPermit
}

func (claimer *sessionQuotaClaimer) ClaimDispatchStart(context.Context, broker.DispatchStartRequest) (broker.DispatchStartClaim, error) {
	return broker.DispatchStartClaim{Permit: claimer.permit, Fresh: true}, nil
}

type sessionQuotaCapture struct {
	route broker.Digest
	claim broker.ClaimedDispatchStart
}

func (capture *sessionQuotaCapture) RouteDigest() broker.Digest { return capture.route }
func (capture *sessionQuotaCapture) Start(_ context.Context, claim broker.ClaimedDispatchStart) error {
	capture.claim = claim
	return nil
}

func (f *sessionQuotaFixture) commitResult(t *testing.T, usage Usage) effectledger.Terminal {
	t.Helper()
	scope := f.reference.scope
	payload := sessionDispatchPayload{Version: sessionDispatchCommandVersion, Scope: scope, RequestDigest: f.request.RequestDigest, Request: f.reference.request, ProviderID: "provider-a", QuotaPermit: f.permit, ContextTokens: f.request.ContextTokens, RequestedOutputTokens: f.request.OutputTokens, MaxContextTokens: f.reference.grant.MaxContextTokens, MaxTotalTokens: f.reference.grant.MaxTotalTokens, MaxPreDispatchRetries: f.reference.grant.MaxPreDispatchRetries, State: StateDispatching, Revision: 2, Attempt: 1, EventCount: 1}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	dispatch := broker.DispatchPermit{EffectKey: broker.EffectKey{SessionID: scope.SessionID, TurnID: scope.TurnID, EffectID: scope.EffectID, InvocationID: scope.InvocationID, RequestDigest: broker.Digest(f.request.RequestDigest)}, Opaque: "fixture-bearer", TenantID: scope.TenantID, WorkspaceID: f.config.Scope.WorkspaceID, UserID: scope.UserID, Service: broker.ServiceModel, Operation: sessionDispatchOperation, ParentOperation: "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{9}, 32)), ReplayPolicy: broker.ReplayNever, Generations: broker.Generations{TurnLease: scope.Generations.TurnLease, Placement: scope.Generations.Placement, Sandbox: 4, Authorization: scope.Generations.Policy}, DispatchAttempt: 1, ProviderRequestID: mustID(t, identity.Request, 'r'), ProviderRouteDigest: f.config.RouteDigest, Deadline: time.UnixMilli(1800000060000), EventSequence: 7, Durable: true}
	command := effectledger.Command{Dispatch: dispatch, CommandDigest: sessionDispatchCommandDigest(encoded), Payload: encoded}
	if err := f.ledger.Prepare(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	groups := []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle}
	p := contract.NewProductionProofs(t, groups)
	claimer := &sessionQuotaClaimer{p, broker.DispatchStartPermit{Dispatch: dispatch, Opaque: "fixture-start", CommandDigest: command.CommandDigest, EventSequence: 8, Durable: true}}
	capture := &sessionQuotaCapture{route: f.config.RouteDigest}
	consumer, err := broker.NewDispatchConsumer(contract.Verify[broker.DispatchStartClaimer](t, p, claimer, groups), map[broker.EffectService]broker.DispatchStarter{broker.ServiceModel: capture}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.StartExactAttempt(context.Background(), broker.DispatchStartRequest{Dispatch: dispatch, CommandDigest: command.CommandDigest}); err != nil {
		t.Fatal(err)
	}
	claimed, err := f.ledger.ClaimStart(context.Background(), capture.claim)
	if err != nil {
		t.Fatal(err)
	}
	observation, ok := claimed.Observation()
	if !ok {
		t.Fatal("no sealed native observation")
	}
	if err := f.ledger.RecordAccepted(context.Background(), observation, "provider-request-1"); err != nil {
		t.Fatal(err)
	}
	result := sessionDispatchResultWire{Version: sessionDispatchResultVersion, State: StateCompleted, Outcome: OutcomeCompleted, Revision: 4, Attempt: 1, EventCount: 3, EventBytes: 26, ProviderRequestID: "provider-request-1", Response: &sessionModelResponseWire{Text: "done", FinishReason: FinishReasonStop, Usage: usage}}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := f.ledger.RecordTerminal(context.Background(), observation, effectledger.Terminal{Status: effectledger.TerminalCommitted, Result: resultBytes})
	if err != nil {
		t.Fatal(err)
	}
	f.operation.Kind = broker.OperationSettlement
	f.operation.Key = "fixture-settlement"
	f.setReceipt(f.settlement(1, "", terminal))
	return terminal
}

func TestNativeSessionQuotaReleaseRequiresAuthenticatedPreDispatchReceiptAndReplaysAfterTakeover(t *testing.T) {
	f := newSessionQuotaFixture(t)
	f.setReceipt(f.settlement(0, broker.RecoverySettlementFailed, effectledger.Terminal{}))
	var receipts [6]NativeSessionQuotaReceipt
	var errs [6]error
	var wg sync.WaitGroup
	for index := range receipts {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			receipts[i], errs[i] = f.bridge.Reconcile(context.Background(), f.request, f.operation)
		}(index)
	}
	wg.Wait()
	for index := range receipts {
		// A bounded CAS retry may conservatively fail under six simultaneous
		// readers/writers. Such a failure must expose no receipt; only an exact
		// subsequent authenticated replay may acknowledge the one decision.
		if errors.Is(errs[index], ErrStateDependenciesNotDurable) {
			if receipts[index] != (NativeSessionQuotaReceipt{}) {
				t.Fatal("bounded CAS failure exposed stale success")
			}
			receipts[index], errs[index] = f.bridge.Reconcile(context.Background(), f.request, f.operation)
		}
	}
	for index := range receipts {
		if errs[index] != nil || receipts[index] != receipts[0] || receipts[index].Disposition != QuotaDispositionRelease {
			t.Fatalf("release/replay %d: %v", index, errs[index])
		}
	}
	if receipts[0].DispatchAttempt != 0 || receipts[0].Usage != (Usage{}) || receipts[0].WitnessDigest == (Digest{}) {
		t.Fatal("invalid release witness")
	}
	if err := f.factory.SetCurrentAuthority(context.Background(), func() ValidatedAuthority { scope := f.reference.scope; scope.Generations.TurnLease++; return scope }()); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewNativeFactory(f.factoryConfig)
	if err != nil {
		t.Fatal(err)
	}
	config := f.config
	config.Factory = reopened
	bridge, err := NewNativeSessionQuotaBridge(config)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := bridge.Reconcile(context.Background(), f.request, f.operation)
	if err != nil || replay != receipts[0] {
		t.Fatalf("takeover changed original settlement: %v", err)
	}
	_, err = nativeModelOperation(context.Background(), reopened, func(state *nativeModelState) (bool, error) {
		if charge := nativeReservationCharge(state, state.Reservations[f.request.InvocationID.String()]); charge != 0 {
			t.Fatalf("released reservation charges %d", charge)
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Candidates().Quota.Durability().AtomicReservationSettlement {
		t.Fatal("cross-object accounting advertised atomic")
	}
}

func TestNativeSessionQuotaHoldsMissingInterruptedAndDispatchedFailedFacts(t *testing.T) {
	for _, mode := range []string{"missing", "interrupted", "failed-after-start", "normal-failure"} {
		t.Run(mode, func(t *testing.T) {
			f := newSessionQuotaFixture(t)
			switch mode {
			case "interrupted":
				f.setReceipt(f.settlement(1, broker.RecoverySettlementInterrupted, effectledger.Terminal{}))
			case "failed-after-start":
				f.setReceipt(f.settlement(1, broker.RecoverySettlementFailed, effectledger.Terminal{}))
			case "normal-failure":
				f.operation.Kind = broker.OperationSettlement
				r := f.settlement(1, "", effectledger.Terminal{})
				r["error"] = canonical.Map{"code": uint64(v1.ErrorCode_ERROR_CODE_UNAVAILABLE), "reason": "provider.failed", "message": "failed", "retryable": false, "retryAfterMs": uint64(0), "metadata": canonical.Map{}, "requestId": nil}
				f.setReceipt(r)
			}
			receipt, err := f.bridge.Reconcile(context.Background(), f.request, f.operation)
			if err != nil || receipt.Disposition != QuotaDispositionHold {
				t.Fatalf("unknown start was released: %v", err)
			}
			_, err = nativeModelOperation(context.Background(), f.factory, func(state *nativeModelState) (bool, error) {
				if nativeReservationCharge(state, state.Reservations[f.request.InvocationID.String()]) != 28 {
					t.Fatal("held reservation undercharged")
				}
				return true, nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeSessionQuotaConsumesOnlyExactCommittedNormalizedModelResult(t *testing.T) {
	for _, mode := range []string{"exact", "raw-provider-usage", "wrong-parent", "wrong-commit", "wrong-invocation", "wrong-generation", "wrong-request", "tampered-mac"} {
		t.Run(mode, func(t *testing.T) {
			f := newSessionQuotaFixture(t)
			usage := Usage{11, 17}
			if mode == "raw-provider-usage" {
				usage = Usage{2, 3}
			}
			terminal := f.commitResult(t, usage)
			r := f.settlement(1, "", terminal)
			switch mode {
			case "wrong-parent":
				r["effect"].(canonical.Map)["parentOperationId"] = mustID(t, identity.Operation, 'o').String()
			case "wrong-commit":
				r["externalCommitId"] = mustID(t, identity.Commit, 'x').String()
				r["effect"].(canonical.Map)["externalCommitId"] = r["externalCommitId"]
			case "wrong-invocation":
				r["effect"].(canonical.Map)["invocationId"] = mustID(t, identity.Invocation, 'x').String()
			case "wrong-generation":
				r["effect"].(canonical.Map)["lastDispatch"].(canonical.Map)["placementGeneration"] = uint64(91)
			case "wrong-request":
				r["effect"].(canonical.Map)["lastDispatch"].(canonical.Map)["providerRequestId"] = mustID(t, identity.Request, 'x').String()
			case "tampered-mac":
				f.host.tamper = true
			}
			f.setReceipt(r)
			receipt, err := f.bridge.Reconcile(context.Background(), f.request, f.operation)
			if mode != "exact" {
				if err == nil || receipt != (NativeSessionQuotaReceipt{}) {
					t.Fatal("mismatched authenticated facts published consumption")
				}
				return
			}
			if err != nil || receipt.Disposition != QuotaDispositionConsume || receipt.Usage != usage || receipt.ExternalCommitID != terminal.ExternalCommitID || receipt.ResultRef != terminal.ResultRef {
				t.Fatalf("exact committed consumption: %v", err)
			}
			replay, err := f.bridge.Reconcile(context.Background(), f.request, f.operation)
			if err != nil || replay != receipt {
				t.Fatalf("consume replay changed: %v", err)
			}
		})
	}
}

func TestNativeSessionQuotaLostBarrierAndPersistedReplyNeverPublishSuccess(t *testing.T) {
	for _, mode := range []string{"read-barrier", "projection-barrier", "commit-reply"} {
		t.Run(mode, func(t *testing.T) {
			f := newSessionQuotaFixture(t)
			f.setReceipt(f.settlement(0, broker.RecoverySettlementFailed, effectledger.Terminal{}))
			if mode == "read-barrier" {
				f.source.barrierLoss = true
			} else {
				f.faultSource.fault = mode
			}
			// The targeted fault applies only to the projection's state write;
			// initial reservation reads also perform real CAS/barrier operations.
			receipt, err := f.bridge.Reconcile(context.Background(), f.request, f.operation)
			if !errors.Is(err, ErrStateDependenciesNotDurable) || receipt != (NativeSessionQuotaReceipt{}) {
				t.Fatalf("lost durability exposed receipt: %v", err)
			}
			replay, err := f.bridge.Reconcile(context.Background(), f.request, f.operation)
			if err != nil || replay.Disposition != QuotaDispositionRelease {
				t.Fatalf("exact recovery from persisted ambiguity failed: %v", err)
			}
		})
	}
}

func TestNativeSessionQuotaRejectsUnverifiedScopeRouteAndChangedReservation(t *testing.T) {
	f := newSessionQuotaFixture(t)
	for _, mutate := range []func(*NativeSessionQuotaConfig){func(c *NativeSessionQuotaConfig) { c.Session = dependency.Verified[*stateappbroker.Store]{} }, func(c *NativeSessionQuotaConfig) { c.Ledger = dependency.Verified[*effectledger.NativeLedger]{} }, func(c *NativeSessionQuotaConfig) { c.RouteDigest[0]++ }, func(c *NativeSessionQuotaConfig) { c.Scope.WorkspaceID = identity.ID{} }} {
		candidate := f.config
		mutate(&candidate)
		if bridge, err := NewNativeSessionQuotaBridge(candidate); err == nil || bridge != nil {
			t.Fatal("invalid concrete binding accepted")
		}
	}
	request := f.request
	request.OutputTokens++
	if receipt, err := f.bridge.Reconcile(context.Background(), request, f.operation); !errors.Is(err, ErrQuotaConflict) || receipt != (NativeSessionQuotaReceipt{}) {
		t.Fatalf("changed original reservation accepted: %v", err)
	}
	config := f.config
	config.Scope.WorkspaceID = mustID(t, identity.Workspace, 'x')
	bridge, err := NewNativeSessionQuotaBridge(config)
	if err != nil {
		t.Fatal(err)
	}
	if receipt, err := bridge.Reconcile(context.Background(), f.request, f.operation); err == nil || receipt != (NativeSessionQuotaReceipt{}) {
		t.Fatal("scope did not bind actual concrete Store")
	}
	if _, err := f.factory.Candidates().Quota.Settle(context.Background(), QuotaSettlementRequest{}); !errors.Is(err, ErrSettlementNotReady) {
		t.Fatal("caller data became settlement authority")
	}
}

func TestNativeSessionQuotaCanonicalMigrationAndCorruptProjectionRejection(t *testing.T) {
	f := newSessionQuotaFixture(t)
	f.source.mu.Lock()
	snapshot := f.source.objects[f.factory.objectID]
	f.source.mu.Unlock()
	state, err := f.factory.decodeState(snapshot.State)
	if err != nil {
		t.Fatal(err)
	}
	legacy := nativeModelStateV1{"circulus.native-model-admission.v1", state.ObjectID, state.PolicyDigest, state.Fences, state.Grants, state.Reservations}
	value, err := nativeEncodeValue(reflect.ValueOf(legacy))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := canonical.Encode(value, f.factory.stateOptions())
	if err != nil {
		t.Fatal(err)
	}
	converted, err := f.factory.decodeState(encoded)
	if err != nil || converted.Protocol != nativeModelProtocol || len(converted.Projections) != 0 || !reflect.DeepEqual(converted.Reservations, state.Reservations) {
		t.Fatal("exact v1 state could not reopen")
	}
	legacyMembers := value.(canonical.Map)
	legacyMembers["Projections"] = canonical.Array{}
	aliased, _ := canonical.Encode(legacyMembers, f.factory.stateOptions())
	if _, err := f.factory.decodeState(aliased); err == nil {
		t.Fatal("v1 silently accepted v2 accounting fields")
	}
	delete(legacyMembers, "Projections")
	f.source.mu.Lock()
	snapshot.State = encoded
	snapshot.StateDigest = celld.Digest(sha256.Sum256(encoded))
	f.source.objects[f.factory.objectID] = snapshot
	f.source.mu.Unlock()
	f.setReceipt(f.settlement(0, broker.RecoverySettlementFailed, effectledger.Terminal{}))
	if _, err := f.bridge.Reconcile(context.Background(), f.request, f.operation); err != nil {
		t.Fatal(err)
	}
	f.source.mu.Lock()
	snapshot = f.source.objects[f.factory.objectID]
	f.source.mu.Unlock()
	state, err = f.factory.decodeState(snapshot.State)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*nativeSessionQuotaRecord){func(r *nativeSessionQuotaRecord) { r.Receipt.DispatchAttempt = 1 }, func(r *nativeSessionQuotaRecord) { r.Scope.SessionID = mustID(t, identity.Session, 'x') }, func(r *nativeSessionQuotaRecord) { r.Receipt.WitnessDigest[0]++ }} {
		candidate := *state
		candidate.Projections = make(map[string]nativeSessionQuotaRecord)
		for k, r := range state.Projections {
			mutate(&r)
			candidate.Projections[k] = r
		}
		v, err := nativeEncodeValue(reflect.ValueOf(candidate))
		if err != nil {
			t.Fatal(err)
		}
		body, err := canonical.Encode(v, f.factory.stateOptions())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.factory.decodeState(body); err == nil {
			t.Fatal("corrupt accounting projection reopened")
		}
	}
}

func TestNativeSessionQuotaPendingFactsCanPromoteOnlyToAuthenticatedFinalDecision(t *testing.T) {
	f := newSessionQuotaFixture(t)
	held, err := f.bridge.Reconcile(context.Background(), f.request, f.operation)
	if err != nil || held.Disposition != QuotaDispositionHold {
		t.Fatal("missing operation did not retain quota")
	}
	terminal := f.commitResult(t, Usage{11, 17})
	f.faultSource.fault = "ledger-barrier"
	if receipt, err := f.bridge.Reconcile(context.Background(), f.request, f.operation); !errors.Is(err, ErrStateDependenciesNotDurable) || receipt != (NativeSessionQuotaReceipt{}) {
		t.Fatalf("lost ledger barrier published consumption: %v", err)
	}
	consumed, err := f.bridge.Reconcile(context.Background(), f.request, f.operation)
	if err != nil || consumed.Disposition != QuotaDispositionConsume || consumed.WitnessDigest == held.WitnessDigest {
		t.Fatalf("pending exact result did not consume: %v", err)
	}
	changed := f.operation
	changed.Key = "different-operation"
	changed.Digest[0]++
	f.operation = changed
	f.setReceipt(f.settlement(1, "", terminal))
	if receipt, err := f.bridge.Reconcile(context.Background(), f.request, changed); !errors.Is(err, ErrQuotaConflict) || receipt != (NativeSessionQuotaReceipt{}) {
		t.Fatalf("final consumption overwritten by another operation: %v", err)
	}
}

func TestNativeSessionQuotaReleasedReservationRestoresCapacityWithoutChangingItsIdentity(t *testing.T) {
	f := newSessionQuotaFixture(t)
	f.setReceipt(f.settlement(0, broker.RecoverySettlementFailed, effectledger.Terminal{}))
	if _, err := f.bridge.Reconcile(context.Background(), f.request, f.operation); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 4; index++ {
		scope := f.reference.scope
		scope.EffectID = mustID(t, identity.Effect, byte(40+index))
		scope.InvocationID = mustID(t, identity.Invocation, byte(50+index))
		if err := f.factory.ProvisionGrant(context.Background(), nativeModelGrant(t, f.reference, scope, "fixture-extra-"+scope.InvocationID.String())); err != nil {
			t.Fatal(err)
		}
		request := f.request
		request.EffectID, request.InvocationID = scope.EffectID, scope.InvocationID
		permit, err := f.factory.Candidates().Quota.Admit(context.Background(), request)
		if index < 3 {
			if err != nil || permit.ReservationID != request.InvocationID.String() {
				t.Fatalf("released capacity was not restored: %v", err)
			}
		} else if !errors.Is(err, ErrQuotaExceeded) || permit != (QuotaPermit{}) {
			t.Fatal("released capacity permitted overspend")
		}
	}
	permit, found, err := f.factory.InspectReservation(context.Background(), f.request)
	if err != nil || !found || permit != f.permit {
		t.Fatal("release removed immutable reservation identity")
	}
}
