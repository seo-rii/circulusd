package stateappclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/hancomac/circulusd/internal/canonical"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func admissionPlanFixture(t *testing.T) (goldenFixture, PlanSessionTurnAdmissionRequest, canonical.Map) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "packages", "protocol-types", "fixtures", "state-app-admission-plan-v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture goldenFixture
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	encoded, err := hex.DecodeString(fixture.RequestCBORHex)
	if err != nil {
		t.Fatal(err)
	}
	value, err := canonical.Decode(encoded, canonical.Options{MaxBytes: 2 << 20, MaxDepth: 72, MaxItems: 100_000})
	if err != nil {
		t.Fatal(err)
	}
	m := value.(canonical.Map)
	request := PlanSessionTurnAdmissionRequest{TenantID: m["tenantId"].(string), ActorSubjectID: m["actorSubjectId"].(string), SessionID: m["sessionId"].(string),
		ExpectedAuthorizationGeneration: uint64(m["expectedAuthorizationGeneration"].(int64)), ProposedTurnID: m["proposedTurnId"].(string), Input: m["input"], InputDigest: m["inputDigest"].(string), IdempotencyKeyDigest: m["idempotencyKeyDigest"].(string), RequestDigest: m["requestDigest"].(string)}
	encoded, err = hex.DecodeString(fixture.ResponseCBORHex)
	if err != nil {
		t.Fatal(err)
	}
	value, err = canonical.Decode(encoded, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	return fixture, request, value.(canonical.Map)
}

func TestAdmissionPlanGoldenOwnsFullInputAndUsesSeparateMACDomains(t *testing.T) {
	for _, mode := range []string{"golden", "changed request MAC domain", "wrong scope", "wrong command", "expired interval", "bad runtime", "tampered response", "replay"} {
		t.Run(mode, func(t *testing.T) {
			fixture, input, response := admissionPlanFixture(t)
			root, _ := hex.DecodeString(fixture.RootKeyHex)
			endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				body := mustReadRequest(t, request)
				if request.URL.Path != fixture.Path || request.Header.Get("Content-Type") != fixture.ContentType || request.Header.Get(signatureHeader) != fixture.RequestMACHex || hex.EncodeToString(body) != fixture.RequestCBORHex {
					t.Error("signed plan differs from actual TS Cell golden")
				}
				result := response["payload"].(canonical.Map)["result"].(canonical.Map)
				switch mode {
				case "wrong scope":
					result["actorSubjectId"] = validID("subject", 2)
				case "wrong command":
					result["commandId"] = "admission:arbitrary"
				case "expired interval":
					result["leaseExpiresAt"] = result["plannedAt"]
				case "bad runtime":
					result["runtime"].(canonical.Map)["adapterAbiVersion"] = int64(0)
				case "replay":
					for _, field := range []string{"commandId", "expectedEventSequence", "turnLeaseGeneration", "leaseExpiresAt", "plannedAt", "runtime"} {
						delete(result, field)
					}
					result["kind"] = "replay"
					result["admission"] = canonical.Map{"turnId": validID("turn", 2), "turnSequence": int64(0), "activated": true, "version": int64(1)}
				}
				encoded, err := canonical.Encode(response, canonical.DefaultOptions())
				if err != nil {
					t.Fatal(err)
				}
				domain := "circulusd.state-turn-plan-ingress.response.v1"
				if mode == "changed request MAC domain" {
					domain = "circulusd.state-turn-ingress.response.v1"
				}
				signature := responseMACFor(root, fixture.KeyID, fixture.Request.RequestID, body, 200, fixture.ContentType, domain, encoded)
				if mode == "golden" && signature != fixture.ResponseMACHex {
					t.Error("response MAC differs from TS golden")
				}
				if mode == "tampered response" {
					signature = strings.Repeat("0", 64)
				}
				writeWireResponse(writer, wireResponse{status: 200, contentType: fixture.ContentType, keyID: fixture.KeyID, signature: signature, body: encoded})
			}))
			client, err := newWithSources(Config{Endpoint: endpoint, KeyID: "read-plan-1", RootKey: bytes.Repeat([]byte{0x31}, 32), AdmissionKeyID: fixture.KeyID, AdmissionRootKey: root, Timeout: time.Second}, clientSources{clock: func() time.Time { return time.UnixMilli(fixture.Request.SentAtUnixMS) }, newRequestID: func() (string, error) { return fixture.Request.RequestID, nil }})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			result, err := client.PlanSessionTurnAdmission(context.Background(), input)
			if mode == "golden" {
				if err != nil || result.WorkspaceID != validID("ws", 0) || result.Runtime.EngineKind != "low-level" || result.LeaseExpiresAt != uint64(fixture.Request.SentAtUnixMS+120_000) {
					t.Fatalf("result=%+v err=%v", result, err)
				}
			} else if mode == "replay" {
				if err != nil || result.ReplayedAdmission == nil || result.ReplayedAdmission.TurnID != validID("turn", 2) {
					t.Fatalf("replay=%+v err=%v", result, err)
				}
			} else if mode == "changed request MAC domain" || mode == "tampered response" {
				if !errors.Is(err, ErrUnauthenticatedResponse) {
					t.Fatalf("bad authentication accepted: %v", err)
				}
			} else if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("malformed plan accepted=%+v err=%v", result, err)
			}
		})
	}
}

func TestAdmissionPlanRejectsMalformedInputBeforeTransportAndOwnsCopy(t *testing.T) {
	_, request, _ := admissionPlanFixture(t)
	snapshot, err := SnapshotAdmissionPlanningRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Input.(canonical.Map)["messages"].(canonical.Array)[0].(canonical.Map)["content"] = "mutation"
	if request.Input.(canonical.Map)["messages"].(canonical.Array)[0].(canonical.Map)["content"] == "mutation" {
		t.Fatal("snapshot aliases input")
	}
	for _, field := range []string{"input", "input digest", "request digest", "generation", "key"} {
		t.Run(field, func(t *testing.T) {
			_, candidate, _ := admissionPlanFixture(t)
			switch field {
			case "input":
				candidate.Input = canonical.Map{"messages": canonical.Array{canonical.Map{"role": "assistant", "content": "wrong role"}}}
			case "input digest":
				candidate.InputDigest = "sha256:" + strings.Repeat("f", 64)
			case "request digest":
				candidate.RequestDigest = "sha256:" + strings.Repeat("f", 64)
			case "generation":
				candidate.ExpectedAuthorizationGeneration = ^uint64(0)
			case "key":
				candidate.IdempotencyKeyDigest = "raw-key"
			}
			if _, err := SnapshotAdmissionPlanningRequest(candidate); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("invalid request accepted %v", err)
			}
		})
	}
}
