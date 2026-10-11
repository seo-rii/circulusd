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
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
)

func TestSessionBrokerMatchesTypeScriptGolden(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "packages", "protocol-types", "fixtures", "state-app-broker-ingress-v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		goldenFixture
		Request struct {
			BrokerScope
			Operation    string `json:"operation"`
			RequestID    string `json:"requestId"`
			SentAtUnixMS int64  `json:"sentAtUnixMs"`
		} `json:"request"`
	}
	if err = json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(fixture.RootKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	response, err := hex.DecodeString(fixture.ResponseCBORHex)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := mustReadRequest(t, r)
		if r.Method != fixture.Method || r.URL.RequestURI() != fixture.Path || r.Header.Get("Content-Type") != fixture.ContentType || r.Header.Get(testKeyHeader) != fixture.KeyID || r.Header.Get(testSignatureHeader) != fixture.RequestMACHex || hex.EncodeToString(body) != fixture.RequestCBORHex {
			t.Error("broker request differs from independent TypeScript golden")
		}
		writeWireResponse(w, wireResponse{status: fixture.ResponseStatus, contentType: fixture.ContentType, keyID: fixture.KeyID, signature: fixture.ResponseMACHex, body: response})
	}))
	client, err := newWithSources(Config{Endpoint: endpoint, KeyID: "read-independent", RootKey: bytes.Repeat([]byte{0x27}, 32), BrokerKeyID: fixture.KeyID, BrokerRootKey: key, Timeout: time.Second}, clientSources{clock: func() time.Time { return time.UnixMilli(fixture.Request.SentAtUnixMS) }, newRequestID: func() (string, error) { return fixture.Request.RequestID, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	clear(key)
	result, err := client.ExecuteSessionBroker(context.Background(), BrokerRequest{Scope: fixture.Request.BrokerScope, Operation: fixture.Request.Operation, Body: canonical.Map{}})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := result.(canonical.Map)
	if !ok || m["active"] != false || m["sessionId"] != fixture.Request.SessionID {
		t.Fatal("invalid inactive Session view")
	}
}

func TestSessionBrokerSignedTransportAndInvalidUnion(t *testing.T) {
	for _, tamper := range []bool{false, true} {
		t.Run(map[bool]string{false: "authenticated", true: "tampered"}[tamper], func(t *testing.T) {
			root := bytes.Repeat([]byte{4}, 32)
			var calls atomic.Int32
			endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body := mustReadRequest(t, r)
				if r.URL.Path != brokerIngressPath || r.Header.Get(keyIDHeader) != "broker" || r.Header.Get("Content-Type") != brokerIngressContentType {
					t.Error("wrong operation role/path")
				}
				value, err := canonical.Decode(body, canonical.DefaultOptions())
				if err != nil {
					t.Fatal(err)
				}
				request := value.(canonical.Map)
				id := request["requestId"].(string)
				if request["operation"] != "read-turn" || request["schemaDigest"] != brokerIngressSchemaDigest {
					t.Error("wrong typed operation")
				}
				response, err := canonical.Encode(canonical.Map{"protocol": hostProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": dispatchStartHostSchemaDigest, "requestId": id,
					"payload": canonical.Map{"ok": true, "result": canonical.Map{"marker": "read"}}}, canonical.DefaultOptions())
				if err != nil {
					t.Fatal(err)
				}
				signature := responseMACFor(root, "broker", id, body, 200, brokerIngressContentType, brokerResponseMACDomain, response)
				if tamper {
					signature = strings.Repeat("0", 64)
				}
				writeWireResponse(w, wireResponse{status: 200, contentType: brokerIngressContentType, keyID: "broker", signature: signature, body: response})
			}))
			client, err := New(Config{Endpoint: endpoint, KeyID: "read", RootKey: bytes.Repeat([]byte{1}, 32), BrokerKeyID: "broker", BrokerRootKey: root, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			scope := BrokerScope{TenantID: validID("tenant", 1), WorkspaceID: validID("ws", 1), SessionID: validID("sess", 1), ActorSubjectID: validID("subject", 1), ExpectedAuthorizationGeneration: 1}
			value, err := client.ExecuteSessionBroker(context.Background(), BrokerRequest{Scope: scope, Operation: "read-turn", Body: canonical.Map{}})
			if tamper {
				if !errors.Is(err, ErrUnauthenticatedResponse) {
					t.Fatalf("got %v", err)
				}
			} else if err != nil || value.(canonical.Map)["marker"] != "read" {
				t.Fatalf("result=%v err=%v", value, err)
			}
			for _, request := range []BrokerRequest{{Scope: scope, Operation: "session.execute", Body: canonical.Map{}}, {Scope: scope, Operation: "read-turn", Body: canonical.Map{"command": true}}, {Scope: scope, Operation: "lookup-operation", Body: canonical.Map{"kind": "dispatch", "operationKey": "x", "operationDigest": int64(1 << 54)}}} {
				if _, err := client.ExecuteSessionBroker(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
					t.Fatalf("invalid input got %v", err)
				}
			}
			if calls.Load() != 1 {
				t.Fatal("invalid input reached transport")
			}
		})
	}
}
