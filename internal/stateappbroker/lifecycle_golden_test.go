package stateappbroker

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	proof "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/stateappclient"
	"github.com/hancomac/circulusd/internal/stateappcodec"
)

type lifecycleFixture struct {
	Version   int
	Authority stateappclient.BrokerScope
	Policy    struct {
		EngineStepLimits struct{ MaximumEvents, MaximumEphemeralBytes, MaximumWallClockMs uint64 }
	}
	Responses []struct{ Name, Operation, RequestCborHex, ResponseCborHex string }
	Blobs     []struct {
		Digest       string
		EncodedBytes int
		Bytes        struct{ Hex string }
	}
}

func loadLifecycle(t *testing.T) lifecycleFixture {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "packages", "protocol-types", "fixtures", "state-app-broker-lifecycle-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture lifecycleFixture
	if err = json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 {
		t.Fatal("unsupported fixture")
	}
	return fixture
}
func lifecycleStore(t *testing.T, fixture lifecycleFixture) (*Store, *testState, *testResults) {
	t.Helper()
	groups := []dependency.AtomicGroup{dependency.AtomicEffectLifecycle}
	p := proof.NewProductionProofs(t, groups)
	client := &testState{ProductionProofs: p, blobs: map[string][]byte{}, expectedScope: &fixture.Authority}
	results := &testResults{ProductionProofs: p}
	for _, blob := range fixture.Blobs {
		body, err := hex.DecodeString(blob.Bytes.Hex)
		if err != nil || len(body) != blob.EncodedBytes {
			t.Fatal("invalid fixture blob")
		}
		client.blobs[blob.Digest] = body
	}
	limits := fixture.Policy.EngineStepLimits
	user, err := identity.Parse(identity.Subject, fixture.Authority.ActorSubjectID)
	if err != nil {
		t.Fatal(err)
	}
	store, err := newStore(client, Config{Scope: fixture.Authority, UserID: user, EngineStepLimits: broker.EngineStepBudget{MaximumEvents: limits.MaximumEvents, MaximumEphemeralBytes: limits.MaximumEphemeralBytes, MaximumWallClock: time.Duration(limits.MaximumWallClockMs) * time.Millisecond}, Results: proof.Verify[ResultResolver](t, p, results, groups)})
	if err != nil {
		t.Fatal(err)
	}
	return store, client, results
}

func TestAllActualSessionCellBrokerLifecycleReceipts(t *testing.T) {
	fixture := loadLifecycle(t)
	store, client, _ := lifecycleStore(t, fixture)
	for _, vector := range fixture.Responses {
		t.Run(vector.Name, func(t *testing.T) {
			value := decodeHex(t, vector.ResponseCborHex)
			client.response = value
			d := decoder{store: store}
			var err error
			switch vector.Operation {
			case "read-turn":
				var turn broker.TurnSnapshot
				turn, err = store.ReadTurn(context.Background(), sid(identity.Session))
				if vector.Name == "success.settled" {
					if turn.UnconsumedSettlement == nil || len(turn.ResumeSettlement) == 0 {
						t.Fatal("missing actual engine settlement")
					}
					want := decodeHex(t, loadCodec(t).Settlements[0].WireHex)
					got, e := canonical.Decode(turn.ResumeSettlement, canonical.DefaultOptions())
					if e != nil || !sameValue(got, want) {
						t.Fatal("fractional Pi settlement changed during cold hydration")
					}
				}
			case "acquire-step":
				_, err = store.decodeGrant(context.Background(), value)
			case "commit-step":
				_, err = store.decodeStep(value)
			case "dispatch":
				d.dispatch(value)
			case "claim-start":
				d.claim(value)
			case "confirm":
				d.confirmation(value)
			case "settle", "settle-recovery":
				d.settlement(value)
			case "block":
				d.block(value)
			case "prepare-retry":
				d.preparation(value)
			case "lookup-operation":
				request := decodeHex(t, vector.RequestCborHex).(canonical.Map)["body"].(canonical.Map)
				_, err = store.LookupOperation(context.Background(), broker.OperationLookup{Kind: broker.OperationKind(request["kind"].(string)), OperationKey: request["operationKey"].(string), OperationDigest: d.digest(request["operationDigest"]), TenantID: sid(identity.Tenant), WorkspaceID: sid(identity.Workspace), SessionID: sid(identity.Session)})
			default:
				t.Fatalf("missing operation decoder: %s", vector.Operation)
			}
			if err != nil || d.err != nil {
				t.Fatalf("actual Session receipt rejected: %v / %v", err, d.err)
			}
		})
	}
}

func TestNestedResumeIdentityAndConsumptionRejectedBeforeAnyBlobRead(t *testing.T) {
	fixture := loadLifecycle(t)
	var wire string
	for _, v := range fixture.Responses {
		if v.Name == "success.settled" {
			wire = v.ResponseCborHex
		}
	}
	for _, mode := range []string{"checkpoint turn", "settlement turn", "settlement tenant", "consumed", "different outcome", "malformed sidecar", "missing sidecar"} {
		t.Run(mode, func(t *testing.T) {
			store, client, _ := lifecycleStore(t, fixture)
			m := decodeHex(t, wire).(canonical.Map)
			sidecar := m["unconsumedSettlement"].(canonical.Map)
			effect := sidecar["effect"].(canonical.Map)
			switch mode {
			case "checkpoint turn":
				other, _ := identity.New(identity.Turn)
				m["checkpoint"].(canonical.Map)["turnId"] = other.String()
			case "settlement turn":
				other, _ := identity.New(identity.Turn)
				effect["turnId"] = other.String()
				m["activeEffect"].(canonical.Map)["turnId"] = other.String()
			case "settlement tenant":
				other, _ := identity.New(identity.Tenant)
				effect["tenantId"] = other.String()
				m["activeEffect"].(canonical.Map)["tenantId"] = other.String()
			case "consumed":
				effect["consumedAtCheckpointSequence"] = int64(3)
				m["activeEffect"].(canonical.Map)["consumedAtCheckpointSequence"] = int64(3)
			case "different outcome":
				sidecar["settlement"] = canonical.Map{"kind": "success", "result": false}
			case "malformed sidecar":
				m["unconsumedSettlement"] = canonical.Array{}
			case "missing sidecar":
				m["unconsumedSettlement"] = nil
			}
			client.response = m
			if _, err := store.ReadTurn(context.Background(), sid(identity.Session)); err == nil {
				t.Fatal("invalid resume accepted")
			}
			if client.reads != 0 {
				t.Fatal("invalid nested identity reached blob I/O")
			}
		})
	}
}

func TestActualResumeGrantCarriesOwnedCanonicalResultBytes(t *testing.T) {
	fixture := loadLifecycle(t)
	store, _, _ := lifecycleStore(t, fixture)
	for _, vector := range fixture.Responses {
		if vector.Name != "success.resume-grant" {
			continue
		}
		value := decodeHex(t, vector.ResponseCborHex)
		permit, err := store.decodeGrant(context.Background(), value)
		if err != nil {
			t.Fatal(err)
		}
		original := bytes.Clone(permit.ResumeSettlement)
		value.(canonical.Map)["opaque"].(canonical.Bytes)[0] ^= 1
		if !bytes.Equal(permit.ResumeSettlement, original) || permit.UnconsumedSettlement == nil {
			t.Fatal("grant aliases response or omits actual settlement")
		}
		digest, err := stateappcodec.CheckpointDigest(permit.Checkpoint)
		if err != nil || digest != permit.CheckpointDigest {
			t.Fatal("hydrated grant checkpoint digest changed")
		}
		return
	}
	t.Fatal("resume grant missing")
}
