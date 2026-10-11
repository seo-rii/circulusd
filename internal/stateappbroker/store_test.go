package stateappbroker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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

type testState struct {
	*proof.ProductionProofs
	response      canonical.Value
	request       stateappclient.BrokerRequest
	calls, reads  int
	blobs         map[string][]byte
	tamper        bool
	expectedScope *stateappclient.BrokerScope
}

func (s *testState) ExecuteSessionBroker(_ context.Context, r stateappclient.BrokerRequest) (canonical.Value, error) {
	s.calls++
	s.request = r
	return s.response, nil
}
func (s *testState) ReadSessionBlob(_ context.Context, r stateappclient.ReadSessionBlobRequest) (*stateappclient.SessionBlob, error) {
	s.reads++
	expected := stateappclient.BrokerScope{TenantID: sid(identity.Tenant).String(), ActorSubjectID: sid(identity.Subject).String(), SessionID: sid(identity.Session).String(), ExpectedAuthorizationGeneration: 7}
	if s.expectedScope != nil {
		expected = *s.expectedScope
	}
	if r.TenantID != expected.TenantID || r.ActorSubjectID != expected.ActorSubjectID || r.SessionID != expected.SessionID || r.ExpectedAuthorizationGeneration != expected.ExpectedAuthorizationGeneration {
		return nil, broker.ErrFenceMismatch
	}
	body := bytes.Clone(s.blobs[r.Digest])
	if s.tamper {
		body = append(body, 0)
	}
	return &stateappclient.SessionBlob{Digest: r.Digest, EncodedBytes: len(body), Bytes: body}, nil
}

type testResults struct {
	*proof.ProductionProofs
	tamper  bool
	calls   int
	request ResultRequest
	body    []byte
}

func (r *testResults) ResolveResult(_ context.Context, request ResultRequest) (Result, error) {
	r.calls++
	r.request = request
	result := Result{Request: request, PayloadDigest: broker.Digest(sha256.Sum256(r.body)), CanonicalCBOR: bytes.Clone(r.body)}
	if r.tamper {
		result.Request.InvocationID = sid(identity.Invocation)
	}
	return result, nil
}
func sid(kind identity.Kind) identity.ID {
	id, err := identity.Parse(kind, string(kind)+"_"+strings.Repeat("A", 26))
	if err != nil {
		panic(err)
	}
	return id
}
func makeStore(t *testing.T) (*Store, *testState, *testResults) {
	t.Helper()
	groups := []dependency.AtomicGroup{dependency.AtomicEffectLifecycle}
	p := proof.NewProductionProofs(t, groups)
	s := &testState{ProductionProofs: p, blobs: map[string][]byte{}}
	results := &testResults{ProductionProofs: p, body: []byte{0xa1, 0x61, 'x', 0x01}}
	store, err := newStore(s, Config{Scope: stateappclient.BrokerScope{TenantID: sid(identity.Tenant).String(), WorkspaceID: sid(identity.Workspace).String(), SessionID: sid(identity.Session).String(), ActorSubjectID: sid(identity.Subject).String(), ExpectedAuthorizationGeneration: 7}, UserID: sid(identity.Subject), EngineStepLimits: broker.EngineStepBudget{MaximumEvents: 1, MaximumEphemeralBytes: 65536, MaximumWallClock: time.Second}, Results: proof.Verify[ResultResolver](t, p, results, groups)})
	if err != nil {
		t.Fatal(err)
	}
	return store, s, results
}

type codecFixture struct {
	Checkpoints []struct{ Name, WireHex, ExternalHex, PayloadHex, ChainDigest string }
	Settlements []struct{ Name, WireHex, StoredHex, PayloadHex, Digest string }
}

func loadCodec(t *testing.T) codecFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "packages", "protocol-types", "fixtures", "stateapp-pi-codec-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture codecFixture
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}
func decodeHex(t *testing.T, s string) canonical.Value {
	t.Helper()
	data, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	value, err := canonical.Decode(data, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func inactive(store *Store) canonical.Map {
	return canonical.Map{"tenantId": store.scope.TenantID, "workspaceId": store.scope.WorkspaceID, "userId": store.user.String(), "sessionId": store.scope.SessionID, "turnId": nil, "active": false, "abortRequested": false, "leaseExpiresAt": nil, "fence": fenceValue(broker.Generations{Authorization: 7}), "eventSequence": uint64(0), "engineStepLimits": canonical.Map{"maximumEvents": uint64(1), "maximumEphemeralBytes": uint64(65536), "maximumWallClockMs": uint64(1000)}, "checkpointDigest": nil, "checkpoint": nil, "activeEffect": nil, "preparation": nil, "dispatch": nil, "start": nil, "unconsumedSettlement": nil}
}

func TestReadTurnHydratesActualPiCheckpointAndRejectsScopeBeforeBlobIO(t *testing.T) {
	for _, mode := range []string{"valid", "wrong tenant", "wrong actor", "wrong generation", "malformed effect", "tampered blob", "unknown field"} {
		t.Run(mode, func(t *testing.T) {
			store, client, _ := makeStore(t)
			fixture := loadCodec(t).Checkpoints[1]
			view := inactive(store)
			view["turnId"], view["active"], view["leaseExpiresAt"] = sid(identity.Turn).String(), true, int64(1900000001000)
			view["fence"] = fenceValue(broker.Generations{TurnLease: 3, Authorization: 7})
			view["checkpoint"], view["checkpointDigest"] = decodeHex(t, fixture.ExternalHex), fixture.ChainDigest
			body, _ := hex.DecodeString(fixture.PayloadHex)
			blobDigest := digestValue(broker.Digest(sha256.Sum256(body)))
			client.blobs[blobDigest] = body
			switch mode {
			case "wrong tenant":
				view["tenantId"] = sid(identity.Subject).String()
			case "wrong actor":
				view["userId"] = sid(identity.Tenant).String()
			case "wrong generation":
				view["fence"].(canonical.Map)["authorizationGeneration"] = uint64(8)
			case "malformed effect":
				view["activeEffect"] = canonical.Array{}
			case "tampered blob":
				client.tamper = true
			case "unknown field":
				view["extra"] = true
			}
			client.response = view
			snapshot, err := store.ReadTurn(context.Background(), sid(identity.Session))
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				want, err := stateappcodec.CheckpointFromValue(decodeHex(t, fixture.WireHex))
				if err != nil || !proto.Equal(snapshot.Checkpoint, want) || client.reads != 1 {
					t.Fatal("cold Pi checkpoint was not reconstructed exactly")
				}
			} else {
				if err == nil {
					t.Fatal("invalid state accepted")
				}
				if mode != "tampered blob" && client.reads != 0 {
					t.Fatal("invalid scoped state reached blob reader")
				}
			}
		})
	}
}

func TestStoreConstructorRequiresQualifiedResultReader(t *testing.T) {
	store, client, _ := makeStore(t)
	_, err := newStore(client, Config{Scope: store.scope, UserID: store.user, EngineStepLimits: store.limits})
	if !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatalf("unqualified resolver accepted: %v", err)
	}
	if client.calls != 0 || client.reads != 0 {
		t.Fatal("constructor performed operations")
	}
}

func TestPublicErrorRetainsFullOriginalAndRejectsUnknownProtoFields(t *testing.T) {
	error := &v1.PublicError{Code: v1.ErrorCode_ERROR_CODE_UNAVAILABLE, Reason: "provider.failed", Message: strings.Repeat("x", 4096), Retryable: true, RetryAfterMs: 53, Metadata: map[string]string{"provider": "qualified-provider"}, RequestId: &v1.OpaqueId{Value: []byte(sid(identity.Request).String())}}
	value, err := errorValue(error)
	if err != nil {
		t.Fatal(err)
	}
	d := decoder{}
	got := d.publicError(value)
	if d.err != nil || !proto.Equal(got, error) {
		t.Fatal("public error lost original fields")
	}
	error.Metadata["provider"] = "mutated"
	if got.Metadata["provider"] != "qualified-provider" {
		t.Fatal("receipt aliases caller metadata")
	}
	for _, field := range []string{"message", "reason", "metadata-key", "metadata-value"} {
		invalid := proto.Clone(error).(*v1.PublicError)
		switch field {
		case "message":
			invalid.Message = "e\u0301"
		case "reason":
			invalid.Reason = "e\u0301"
		case "metadata-key":
			invalid.Metadata["e\u0301"] = "x"
		case "metadata-value":
			invalid.Metadata["provider"] = "e\u0301"
		}
		if _, err := errorValue(invalid); err == nil {
			t.Fatalf("non-NFC %s silently changed original PublicError", field)
		}
	}
	error.ProtoReflect().SetUnknown([]byte{0x40, 0x01})
	if _, err = errorValue(error); err == nil {
		t.Fatal("unknown protobuf field silently dropped")
	}
}

func TestSettlementUsesActualBoundResultAndRejectsRelabelledInvocation(t *testing.T) {
	for _, tamper := range []bool{false, true} {
		t.Run(map[bool]string{false: "body", true: "wrong invocation"}[tamper], func(t *testing.T) {
			store, client, results := makeStore(t)
			results.tamper = tamper
			inv, _ := identity.New(identity.Invocation)
			snapshot := broker.TurnSnapshot{TenantID: sid(identity.Tenant), WorkspaceID: sid(identity.Workspace), UserID: sid(identity.Subject), SessionID: sid(identity.Session), TurnID: sid(identity.Turn), Generations: broker.Generations{TurnLease: 3, Authorization: 7}, CheckpointDigest: broker.Digest{1}}
			command := broker.SettleCommand{Snapshot: snapshot, Key: broker.EffectKey{SessionID: snapshot.SessionID, TurnID: snapshot.TurnID, EffectID: sid(identity.Effect), InvocationID: inv, RequestDigest: broker.Digest{2}}, ExternalCommitID: sid(identity.Commit), ResultRef: sid(identity.Artifact), DispatchAttempt: 1, OperationKey: "settle", SettlementDigest: broker.Digest{3}}
			// This transport response is intentionally invalid: after checking outbound
			// body semantics the Store must still fail closed on a missing typed receipt.
			client.response = canonical.Map{}
			_, err := store.SettleEffect(context.Background(), command)
			if err == nil {
				t.Fatal("missing receipt accepted")
			}
			if tamper {
				if !errors.Is(err, broker.ErrLedgerMismatch) || client.calls != 0 {
					t.Fatal("relabelled result reached Session mutation")
				}
			} else {
				if client.calls != 1 || !reflect.DeepEqual(client.request.Body["settlement"], canonical.Map{"kind": "success", "result": canonical.Map{"x": int64(1)}}) {
					t.Fatal("artifact ID replaced actual canonical result")
				}
			}
		})
	}
}

func TestMillisecondContractDoesNotSilentlyTruncateTime(t *testing.T) {
	for _, invalid := range []time.Time{time.Time{}, time.Unix(0, 0), time.Unix(1900000000, 1)} {
		if _, err := millis(invalid); err == nil {
			t.Fatal("invalid time silently truncated")
		}
	}
	if got, err := millis(time.UnixMilli(1900000000123)); err != nil || got != 1900000000123 {
		t.Fatal("valid millisecond time rejected")
	}
}

func TestMalformedBrokerResponsesNeverPanic(t *testing.T) {
	store, client, _ := makeStore(t)
	for _, value := range []canonical.Value{nil, true, "text", canonical.Array{}, canonical.Map{}, inactive(store)} {
		client.response = value
		_, _ = store.ReadTurn(context.Background(), sid(identity.Session))
		_, _ = store.decodeStep(value)
		_, _ = store.decodeGrant(context.Background(), value)
		d := decoder{store: store}
		d.dispatch(value)
		d.claim(value)
		d.confirmation(value)
		d.settlement(value)
		d.block(value)
	}
}
