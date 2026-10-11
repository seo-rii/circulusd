package stateappclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
)

func admissionFixture(t *testing.T) (goldenFixture, AdmitSessionTurnRequest) {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "..", "packages", "protocol-types", "fixtures", "state-app-admission-v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture goldenFixture
	if err = json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	bytes, err := hex.DecodeString(fixture.RequestCBORHex)
	if err != nil {
		t.Fatal(err)
	}
	value, err := canonical.Decode(bytes, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	v := value.(canonical.Map)
	return fixture, AdmitSessionTurnRequest{TenantID: v["tenantId"].(string), ActorSubjectID: v["actorSubjectId"].(string), SessionID: v["sessionId"].(string),
		ExpectedAuthorizationGeneration: uint64(v["expectedAuthorizationGeneration"].(int64)), CommandID: v["commandId"].(string), ExpectedEventSequence: uint64(v["expectedEventSequence"].(int64)),
		TurnID: v["turnId"].(string), Input: v["input"], InputDigest: v["inputDigest"].(string), GenesisCheckpoint: v["genesisCheckpoint"],
		TurnLeaseGeneration: uint64(v["turnLeaseGeneration"].(int64)), LeaseExpiresAt: uint64(v["leaseExpiresAt"].(int64)), IdempotencyKeyDigest: v["idempotencyKeyDigest"].(string), RequestDigest: v["requestDigest"].(string)}
}

func TestAdmitSessionTurnGoldenAndAuthenticatedResponseValidation(t *testing.T) {
	for _, mode := range []string{"golden", "replay", "wrong fresh turn", "invalid outcome", "tampered MAC"} {
		t.Run(mode, func(t *testing.T) {
			fixture, input := admissionFixture(t)
			root, _ := hex.DecodeString(fixture.RootKeyHex)
			endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				body := mustReadRequest(t, request)
				if request.URL.Path != fixture.Path || request.Header.Get("Content-Type") != fixture.ContentType || request.Header.Get(keyIDHeader) != fixture.KeyID ||
					request.Header.Get(signatureHeader) != fixture.RequestMACHex || hex.EncodeToString(body) != fixture.RequestCBORHex {
					t.Error("signed admission differs from TS golden")
				}
				responseBody, _ := hex.DecodeString(fixture.ResponseCBORHex)
				value, err := canonical.Decode(responseBody, canonical.DefaultOptions())
				if err != nil {
					t.Fatal(err)
				}
				result := value.(canonical.Map)["payload"].(canonical.Map)["result"].(canonical.Map)
				switch mode {
				case "replay":
					result["replayed"] = true
					result["outcome"].(canonical.Map)["turnId"] = validID("turn", 2)
				case "wrong fresh turn":
					result["outcome"].(canonical.Map)["turnId"] = validID("turn", 2)
				case "invalid outcome":
					result["outcome"].(canonical.Map)["turnSequence"] = int64(-1)
				}
				responseBody, err = canonical.Encode(value, canonical.DefaultOptions())
				if err != nil {
					t.Fatal(err)
				}
				signature := responseMACFor(root, fixture.KeyID, fixture.Request.RequestID, body, 200, fixture.ContentType, admissionResponseMACDomain, responseBody)
				if mode == "golden" && signature != fixture.ResponseMACHex {
					t.Error("response MAC differs from TS golden")
				}
				if mode == "tampered MAC" {
					signature = strings.Repeat("0", 64)
				}
				writeWireResponse(writer, wireResponse{status: 200, contentType: fixture.ContentType, keyID: fixture.KeyID, signature: signature, body: responseBody})
			}))
			client, err := newWithSources(Config{Endpoint: endpoint, KeyID: "read-1", RootKey: bytes.Repeat([]byte{0x31}, 32), AdmissionKeyID: fixture.KeyID, AdmissionRootKey: root, Timeout: time.Second}, clientSources{
				clock: func() time.Time { return time.UnixMilli(fixture.Request.SentAtUnixMS) }, newRequestID: func() (string, error) { return fixture.Request.RequestID, nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			result, err := client.AdmitSessionTurn(context.Background(), input)
			switch mode {
			case "golden":
				if err != nil || result.TurnID != input.TurnID || result.Replayed || !result.Activated {
					t.Fatalf("result=%+v err=%v", result, err)
				}
			case "replay":
				if err != nil || !result.Replayed || result.TurnID != validID("turn", 2) {
					t.Fatalf("replay result=%+v err=%v", result, err)
				}
			case "tampered MAC":
				if !errors.Is(err, ErrUnauthenticatedResponse) {
					t.Fatalf("err=%v", err)
				}
			default:
				if !errors.Is(err, ErrInvalidResponse) {
					t.Fatalf("err=%v", err)
				}
			}
		})
	}
}

func TestAdmissionCredentialsAndInputFailBeforeTransport(t *testing.T) {
	_, input := admissionFixture(t)
	base := Config{Endpoint: "http://127.0.0.1:1", KeyID: "reader", RootKey: bytes.Repeat([]byte{0x31}, 32), DispatchStartKeyID: "dispatch", DispatchStartRootKey: bytes.Repeat([]byte{0x91}, 32), Timeout: time.Second}
	for _, edit := range []func(*Config){
		func(c *Config) { c.AdmissionKeyID = "reader"; c.AdmissionRootKey = bytes.Repeat([]byte{0x72}, 32) },
		func(c *Config) { c.AdmissionKeyID = "dispatch"; c.AdmissionRootKey = bytes.Repeat([]byte{0x72}, 32) },
		func(c *Config) { c.AdmissionKeyID = "admit"; c.AdmissionRootKey = c.RootKey },
		func(c *Config) { c.AdmissionKeyID = "admit"; c.AdmissionRootKey = c.DispatchStartRootKey },
		func(c *Config) { c.AdmissionKeyID = "admit" },
	} {
		config := base
		edit(&config)
		if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("credential alias err=%v", err)
		}
	}
	client, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.AdmitSessionTurn(context.Background(), input); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing role err=%v", err)
	}
	for _, edit := range []func(*AdmitSessionTurnRequest){
		func(r *AdmitSessionTurnRequest) {
			r.Input = canonical.Map{"messages": canonical.Array{canonical.Map{"role": "user", "content": "changed"}}}
		},
		func(r *AdmitSessionTurnRequest) { r.CommandID = strings.Repeat("x", 257) },
		func(r *AdmitSessionTurnRequest) { r.ExpectedAuthorizationGeneration = 0 },
		func(r *AdmitSessionTurnRequest) {
			r.GenesisCheckpoint = canonical.Map{"sessionId": r.SessionID, "turnId": validID("turn", 9)}
		},
	} {
		r := input
		edit(&r)
		if _, err := client.AdmitSessionTurn(context.Background(), r); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid input err=%v", err)
		}
	}
}
