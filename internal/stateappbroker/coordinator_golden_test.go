package stateappbroker

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	proof "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/stateappclient"
	"github.com/hancomac/circulusd/internal/stateappcodec"
	"google.golang.org/protobuf/proto"
)

// This transport replays bytes recorded by actual SessionCell transactions. It
// checks every outgoing mutation against that same fixture, rather than creating
// Go-shaped receipts that could conceal a projection mismatch.
type coordinatorGoldenClient struct {
	*proof.ProductionProofs
	t        *testing.T
	scope    stateappclient.BrokerScope
	rows     map[string]struct{ RequestCborHex, ResponseCborHex string }
	blobs    map[string][]byte
	current  string
	claims   int
	receipts map[string]canonical.Value
}

func (c *coordinatorGoldenClient) request(name string) canonical.Map {
	return decodeHex(c.t, c.rows[name].RequestCborHex).(canonical.Map)["body"].(canonical.Map)
}

func (c *coordinatorGoldenClient) response(name string) canonical.Map {
	return decodeHex(c.t, c.rows[name].ResponseCborHex).(canonical.Map)
}

func coordinatorGoldenBytes(t *testing.T, value canonical.Value) []byte {
	t.Helper()
	b, err := canonical.Encode(value, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (c *coordinatorGoldenClient) ExecuteSessionBroker(ctx context.Context, request stateappclient.BrokerRequest) (canonical.Value, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if request.Scope != c.scope {
		c.t.Fatal("broker request escaped immutable fixture scope")
	}
	if request.Operation == "read-turn" {
		return c.response(c.current), nil
	}
	if request.Operation == "lookup-operation" {
		key := request.Body["operationKey"].(string)
		receipt, found := c.receipts[key]
		return canonical.Map{"found": found, "kind": request.Body["kind"], "operationDigest": request.Body["operationDigest"], "receipt": receipt}, nil
	}
	var name, next string
	scenario := strings.Split(c.current, ".")[0]
	switch request.Operation {
	case "acquire-step":
		name = scenario + ".acquire"
		if c.current == scenario+".settled" {
			name = scenario + ".resume-grant"
		}
	case "commit-step":
		name, next = scenario+".commit", scenario+".prepared"
	case "dispatch":
		name, next = scenario+".dispatch", scenario+".dispatched"
	case "claim-start":
		name, next = scenario+".start", scenario+".started"
		if c.claims != 0 {
			name = scenario + ".start-replay"
		}
		c.claims++
	case "confirm":
		name, next = scenario+".confirmation", scenario+".confirmed"
	case "settle":
		name, next = scenario+".settlement", scenario+".settled"
	default:
		c.t.Fatalf("unexpected operation %q", request.Operation)
	}
	want := c.request(name)
	if name == scenario+".start-replay" {
		// The Coordinator re-reads after the first claim. The recorded replay
		// uses the original snapshot; Session excludes this CAS snapshot from
		// receipt identity and returns the original proof in either case.
		current := c.response(c.current)
		effect := current["activeEffect"].(canonical.Map)
		want["snapshot"] = canonical.Map{"turnId": current["turnId"], "eventSequence": current["eventSequence"], "checkpointDigest": current["checkpointDigest"], "fence": current["fence"], "activeEffect": canonical.Map{"effectId": effect["effectId"], "invocationId": effect["invocationId"], "requestDigest": effect["requestDigest"], "phase": effect["phase"], "dispatchAttempt": effect["dispatchAttempt"]}}
	}
	if !bytes.Equal(coordinatorGoldenBytes(c.t, request.Body), coordinatorGoldenBytes(c.t, want)) {
		c.t.Fatalf("%s request differs from actual SessionCell fixture", name)
	}
	response := c.response(name)
	if next != "" {
		c.current = next
	}
	if key, ok := request.Body["operationKey"].(string); ok {
		c.receipts[key] = response
	}
	return response, nil
}

func (c *coordinatorGoldenClient) ReadSessionBlob(ctx context.Context, request stateappclient.ReadSessionBlobRequest) (*stateappclient.SessionBlob, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if request.TenantID != c.scope.TenantID || request.ActorSubjectID != c.scope.ActorSubjectID || request.SessionID != c.scope.SessionID || request.ExpectedAuthorizationGeneration != c.scope.ExpectedAuthorizationGeneration {
		c.t.Fatal("blob read escaped immutable fixture scope")
	}
	body, ok := c.blobs[request.Digest]
	if !ok {
		c.t.Fatal("requested blob absent from actual SessionCell fixture")
	}
	return &stateappclient.SessionBlob{Digest: request.Digest, EncodedBytes: len(body), Bytes: bytes.Clone(body)}, nil
}

type coordinatorGoldenLedger struct {
	t      *testing.T
	record broker.LedgerRecord
	calls  int
}

func (l *coordinatorGoldenLedger) Lookup(_ context.Context, lookup broker.LedgerLookup) (broker.LedgerRecord, error) {
	l.calls++
	r := l.record
	if lookup.TenantID != r.TenantID || lookup.WorkspaceID != r.WorkspaceID || lookup.EffectID != r.EffectID || lookup.InvocationID != r.InvocationID || lookup.RequestDigest != r.RequestDigest || lookup.Service != r.Service || lookup.Operation != r.Operation || lookup.DispatchAttempt != r.DispatchAttempt || lookup.ProviderRequestID != r.ProviderRequestID || lookup.ProviderRouteDigest != r.ProviderRouteDigest {
		l.t.Fatal("confirmation queried a different invocation")
	}
	return r, nil
}

type coordinatorGoldenFixture struct {
	Authority stateappclient.BrokerScope
	Responses []struct{ Name, RequestCborHex, ResponseCborHex string }
	Blobs     []struct {
		Digest       string
		EncodedBytes int
		Bytes        struct{ Hex string }
	}
}

func loadCoordinatorGolden(t *testing.T) coordinatorGoldenFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "packages", "protocol-types", "fixtures", "state-app-broker-lifecycle-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture coordinatorGoldenFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestCoordinatorActualSessionLifecycle(t *testing.T) {
	for _, scenario := range []string{"success", "error"} {
		t.Run(scenario, func(t *testing.T) { testCoordinatorActualSessionLifecycle(t, scenario) })
	}
}

func testCoordinatorActualSessionLifecycle(t *testing.T, scenario string) {
	fixture := loadCoordinatorGolden(t)
	groups := []dependency.AtomicGroup{dependency.AtomicEffectLifecycle}
	qualified := proof.NewProductionProofs(t, groups)
	client := &coordinatorGoldenClient{ProductionProofs: qualified, t: t, scope: fixture.Authority, rows: map[string]struct{ RequestCborHex, ResponseCborHex string }{}, blobs: map[string][]byte{}, current: scenario + ".active", receipts: map[string]canonical.Value{}}
	for _, row := range fixture.Responses {
		client.rows[row.Name] = struct{ RequestCborHex, ResponseCborHex string }{row.RequestCborHex, row.ResponseCborHex}
	}
	for _, blob := range fixture.Blobs {
		body, err := hex.DecodeString(blob.Bytes.Hex)
		if err != nil || len(body) != blob.EncodedBytes {
			t.Fatal("invalid fixture blob")
		}
		client.blobs[blob.Digest] = body
	}
	d := decoder{}
	active := client.response(scenario + ".active")
	limits := d.budget(active["engineStepLimits"])
	settlementBody := client.request(scenario + ".settlement")
	outcome := settlementBody["settlement"].(canonical.Map)
	results := &testResults{ProductionProofs: qualified, body: coordinatorGoldenBytes(t, outcome["result"])}
	store, err := newStore(client, Config{Scope: fixture.Authority, UserID: d.id(identity.Subject, active["userId"], false), EngineStepLimits: limits, Results: proof.Verify[ResultResolver](t, qualified, results, groups)})
	if err != nil {
		t.Fatal(err)
	}
	authority := broker.ValidatedTurnFence{TenantID: d.id(identity.Tenant, active["tenantId"], false), WorkspaceID: d.id(identity.Workspace, active["workspaceId"], false), SessionID: d.id(identity.Session, active["sessionId"], false), TurnID: d.id(identity.Turn, active["turnId"], false), Generations: d.fence(active["fence"]), ExpiresAt: d.time(active["leaseExpiresAt"])}
	if d.err != nil {
		t.Fatal(d.err)
	}
	ledger := &coordinatorGoldenLedger{t: t}
	coordinator, err := broker.NewCoordinator(store, ledger)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	acquire := client.request(scenario + ".acquire")
	now := d.time(acquire["nowUnixMs"])
	permit, err := coordinator.AcquireEngineStep(ctx, broker.EngineStepRequest{Authority: authority, Now: now, Budget: limits, OperationKey: acquire["operationKey"].(string)})
	if err != nil {
		t.Fatalf("acquire actual genesis: %v", err)
	}
	commit := client.request(scenario + ".commit")
	step := commit["step"].(canonical.Map)
	checkpoint, err := stateappcodec.CheckpointFromValue(step["checkpoint"])
	if err != nil {
		t.Fatal(err)
	}
	checkpointDigest, err := stateappcodec.CheckpointDigest(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	intent := step["request"].(canonical.Map)
	if intent["service"] != "model" {
		t.Fatal("unexpected golden model intent")
	}
	requestDigest := d.digest(intent["requestDigest"])
	pbIntent := &v1.EffectIntent{Service: v1.EffectService_EFFECT_SERVICE_MODEL, Operation: intent["operation"].(string), ReplayPolicy: map[string]v1.ReplayPolicy{"safe": v1.ReplayPolicy_REPLAY_POLICY_SAFE, "idempotency-key": v1.ReplayPolicy_REPLAY_POLICY_IDEMPOTENCY_KEY, "never": v1.ReplayPolicy_REPLAY_POLICY_NEVER, "confirm": v1.ReplayPolicy_REPLAY_POLICY_CONFIRM}[intent["replayPolicy"].(string)], RequestDigest: &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: bytes.Clone(requestDigest[:])}, Payload: coordinatorGoldenBytes(t, intent["payload"])}
	if parent, ok := intent["parentOperationId"].(string); ok {
		pbIntent.ParentOperationId = &v1.OpaqueId{Value: []byte(parent)}
		pbIntent.Ordinal = d.uint(intent["ordinal"])
	}
	boundary := &v1.EngineStepBoundary{Checkpoint: checkpoint, Boundary: &v1.EngineStepBoundary_EffectRequest{EffectRequest: pbIntent}}
	encodedBoundary, err := stateappcodec.BoundaryToValue(boundary)
	if err != nil || !bytes.Equal(coordinatorGoldenBytes(t, encodedBoundary), coordinatorGoldenBytes(t, step)) {
		t.Fatalf("fixture protobuf boundary changed the Pi checkpoint or request: %v", err)
	}

	committed, err := coordinator.CommitEngineStep(ctx, broker.EngineStepCommit{Permit: permit, Now: now, OperationKey: commit["operationKey"].(string), RequestDigest: d.digest(commit["requestDigest"]), Boundary: broker.EngineBoundary{CheckpointDigest: checkpointDigest, Message: boundary}})
	if err != nil {
		t.Fatalf("commit actual Pi boundary: %v", err)
	}
	preparation := *committed.PreparationPermit
	dispatchBody := client.request(scenario + ".dispatch")
	dispatch, err := coordinator.AdmitDispatch(ctx, broker.DispatchRequest{Authority: authority, Now: now, EffectID: preparation.EffectID, InvocationID: preparation.InvocationID, RequestDigest: preparation.RequestDigest, Service: preparation.Service, Operation: preparation.Operation, OperationKey: dispatchBody["operationKey"].(string), OperationDigest: d.digest(dispatchBody["operationDigest"]), PreparationPermit: preparation, ProviderRequestID: d.id(identity.Request, dispatchBody["providerRequestId"], false), ProviderRouteDigest: d.digest(dispatchBody["providerRouteDigest"]), Deadline: preparation.Deadline})
	if err != nil {
		t.Fatalf("dispatch actual prepared effect: %v", err)
	}
	claimRequest := broker.DispatchStartRequest{Authority: authority, Now: now, Dispatch: dispatch, CommandDigest: d.digest(client.request(scenario + ".start")["commandDigest"])}
	claim, err := coordinator.ClaimDispatchStart(ctx, claimRequest)
	if err != nil || !claim.Fresh {
		t.Fatalf("claim actual dispatch start: %v", err)
	}
	replayedClaim, err := coordinator.ClaimDispatchStart(ctx, claimRequest)
	if err != nil || replayedClaim.Fresh || replayedClaim.Permit.Opaque != claim.Permit.Opaque {
		t.Fatalf("replay actual dispatch start: %v", err)
	}
	confirmationBody := client.request(scenario + ".confirmation")
	ledger.record = broker.LedgerRecord{Status: broker.LedgerCommitted, TenantID: authority.TenantID, WorkspaceID: authority.WorkspaceID, EffectID: dispatch.EffectID, InvocationID: dispatch.InvocationID, RequestDigest: dispatch.RequestDigest, Service: dispatch.Service, Operation: dispatch.Operation, DispatchAttempt: dispatch.DispatchAttempt, ProviderRequestID: dispatch.ProviderRequestID, ProviderRouteDigest: dispatch.ProviderRouteDigest, ExternalCommitID: d.id(identity.Commit, confirmationBody["externalCommitId"], false), ResultRef: d.id(identity.Artifact, confirmationBody["resultRef"], true)}
	confirmed, err := coordinator.ConfirmExternalCommit(ctx, broker.ConfirmationRequest{Authority: authority, Now: now, EffectID: dispatch.EffectID, InvocationID: dispatch.InvocationID, RequestDigest: dispatch.RequestDigest, Service: dispatch.Service, Operation: dispatch.Operation, DispatchAttempt: dispatch.DispatchAttempt, ProviderRequestID: dispatch.ProviderRequestID, OperationKey: confirmationBody["operationKey"].(string), OperationDigest: d.digest(confirmationBody["operationDigest"])})
	if err != nil || ledger.calls != 1 {
		t.Fatalf("confirm actual invocation: %v", err)
	}
	settleRequest := broker.SettlementRequest{Authority: authority, Now: now, EffectID: dispatch.EffectID, InvocationID: dispatch.InvocationID, RequestDigest: dispatch.RequestDigest, DispatchAttempt: dispatch.DispatchAttempt, ExternalCommitID: confirmed.ExternalCommitID, ResultRef: confirmed.ResultRef, Error: d.publicError(settlementBody["error"]), OperationKey: settlementBody["operationKey"].(string), SettlementDigest: d.digest(settlementBody["operationDigest"])}
	settled, err := coordinator.SettleEffect(ctx, settleRequest)
	if err != nil {
		t.Fatalf("settle actual model result: %v", err)
	}
	replayedSettlement, err := coordinator.SettleEffect(ctx, settleRequest)
	if err != nil || !proto.Equal(replayedSettlement.Effect, settled.Effect) || replayedSettlement.EventSequence != settled.EventSequence || results.calls != map[string]int{"success": 1, "error": 0}[scenario] || !proto.Equal(settled.Error, settleRequest.Error) {
		t.Fatalf("settlement replay lost original receipt or resolved result again: %v", err)
	}
	resumeBody := client.request(scenario + ".resume-grant")
	resume, err := coordinator.AcquireEngineStep(ctx, broker.EngineStepRequest{Authority: authority, Now: now, Budget: limits, OperationKey: resumeBody["operationKey"].(string)})
	if err != nil {
		t.Fatalf("resume actual settled turn: %v", err)
	}
	expectedSettlement := canonical.Map{"requestDigest": digestValue(dispatch.RequestDigest), "outcome": outcome}
	if !bytes.Equal(resume.ResumeSettlement, coordinatorGoldenBytes(t, expectedSettlement)) || !proto.Equal(resume.UnconsumedSettlement, settled.Effect) || !proto.Equal(resume.Checkpoint, checkpoint) {
		t.Fatal("resume lost the canonical Pi result or checkpoint")
	}
	if d.err != nil {
		t.Fatal(d.err)
	}
}

// Canonical maps and arrays can arrive inside malformed but signed responses.
// Comparing their interface values directly must never panic the broker process.
func TestNestedDispatchStartRouteTypesFailWithoutPanic(t *testing.T) {
	fixture := loadCoordinatorGolden(t)
	var encoded string
	for _, row := range fixture.Responses {
		if row.Name == "success.started" {
			encoded = row.ResponseCborHex
		}
	}
	if encoded == "" {
		t.Fatal("missing started-state fixture")
	}
	for _, invalid := range []struct {
		name  string
		value canonical.Value
	}{
		{"map", canonical.Map{"bad": true}}, {"array", canonical.Array{"bad"}},
		{"bytes", canonical.Bytes{1, 2}},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			response := decodeHex(t, encoded).(canonical.Map)
			effect := response["activeEffect"].(canonical.Map)
			last := effect["lastDispatch"].(canonical.Map)
			start := last["start"].(canonical.Map)
			last["providerRouteDigest"], start["providerRouteDigest"] = invalid.value, invalid.value
			d := decoder{}
			d.effect(effect, broker.Generations{})
			if d.err == nil {
				t.Fatal("malformed nested route accepted")
			}
		})
	}
}
