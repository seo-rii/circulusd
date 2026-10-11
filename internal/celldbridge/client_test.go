package celldbridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celld"
)

type wireVector struct {
	Name        string `json:"name"`
	Operation   string `json:"operation"`
	Status      int    `json:"status"`
	RequestHex  string `json:"requestHex"`
	ResponseHex string `json:"responseHex"`
	RequestMAC  string `json:"requestMac"`
	ResponseMAC string `json:"responseMac"`
}
type wireFixture struct {
	Protocol          string       `json:"protocol"`
	SchemaDigest      string       `json:"schemaDigest"`
	ProbeProtocol     string       `json:"probeProtocol"`
	ProbeSchemaDigest string       `json:"probeSchemaDigest"`
	KeyID             string       `json:"keyId"`
	RootKeyHex        string       `json:"rootKeyHex"`
	RequestKeyHex     string       `json:"requestKeyHex"`
	ResponseKeyHex    string       `json:"responseKeyHex"`
	Cases             []wireVector `json:"cases"`
}

func clientFixtureKey() []byte {
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index)
	}
	return key
}
func clientFixtureID() string     { return "req_" + strings.Repeat("A", 26) }
func clientFixtureObject() string { return "auth:tenant_" + strings.Repeat("A", 26) }
func clientFixtureCommit(t *testing.T) CommitRequest {
	t.Helper()
	request := CommitRequest{Snapshot: SnapshotRef{ObjectID: clientFixtureObject(), StateDigest: celld.Digest(sha256.Sum256(nil))},
		StateWritten: true, State: []byte{0, 1, 2}, Receipts: []ReceiptWrite{{CommandID: "publish:1", Receipt: celld.StoredReceipt{
			CommandDigest: celld.Digest(sha256.Sum256([]byte("original-command"))), Response: []byte{120, 121},
			CapabilityClaims: []celld.RawCapabilityClaims{{Kind: "provider-result", Payload: []byte{10, 11}}}}}}}
	var err error
	request.RequestDigest, err = CommitDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	return request
}
func clientFixtureMarker() [32]byte {
	var value [32]byte
	for index := range value {
		value[index] = byte(index + 1)
	}
	return value
}

func generatedWireFixture(t *testing.T) wireFixture {
	t.Helper()
	key := clientFixtureKey()
	requestKey := directionalKey(key, "request")
	responseKey := directionalKey(key, "response")
	fixture := wireFixture{Protocol: storageProtocol, SchemaDigest: storageSchema, ProbeProtocol: probeProtocol, ProbeSchemaDigest: probeSchema,
		KeyID: "fixture-storage", RootKeyHex: hex.EncodeToString(key), RequestKeyHex: hex.EncodeToString(requestKey[:]), ResponseKeyHex: hex.EncodeToString(responseKey[:])}
	commit := clientFixtureCommit(t)
	absent, _ := refValue(commit.Snapshot)
	current := commit.Snapshot
	current.Exists = true
	current.Revision = 1
	current.StateDigest = celld.Digest(sha256.Sum256(commit.State))
	currentValue, _ := refValue(current)
	token, _ := tokenValue(celld.CommitToken{ObjectID: current.ObjectID, Revision: 1})
	receipt, _ := receiptValue(commit.Receipts[0].Receipt)
	commitBody, _ := commitValue(commit, true)
	marker := clientFixtureMarker()
	readonly := CommitRequest{Snapshot: current}
	readonly.RequestDigest, _ = CommitDigest(readonly)
	readonlyBody, _ := commitValue(readonly, true)
	later := current
	later.Revision = 2
	laterValue, _ := refValue(later)
	laterToken, _ := tokenValue(celld.CommitToken{ObjectID: current.ObjectID, Revision: 2})
	add := func(name, operation string, body, result canonical.Map, status int, errorCode string) {
		envelope := canonical.Map{"protocol": storageProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": storageSchema,
			"requestId": clientFixtureID(), "sentAtUnixMs": int64(1_700_000_000_000), "operation": operation, "body": body}
		request, err := canonical.Encode(envelope, wireOptions(MaximumTransactionBytes))
		if err != nil {
			t.Fatal(err)
		}
		digest, err := storageDigest("circulusd.native.storage.request", envelope)
		if err != nil {
			t.Fatal(err)
		}
		payload := canonical.Map{"ok": true, "result": result}
		if errorCode != "" {
			payload = canonical.Map{"ok": false, "error": errorCode, "notCommitted": true}
		}
		response, err := canonical.Encode(canonical.Map{"protocol": storageProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": storageSchema,
			"requestId": clientFixtureID(), "requestDigest": digest, "payload": payload}, wireOptions(MaximumTransactionBytes))
		if err != nil {
			t.Fatal(err)
		}
		fixture.Cases = append(fixture.Cases, wireVector{Name: name, Operation: operation, Status: status, RequestHex: hex.EncodeToString(request), ResponseHex: hex.EncodeToString(response),
			RequestMAC: requestMAC(requestKey, fixture.KeyID, request), ResponseMAC: responseMAC(responseKey, fixture.KeyID, clientFixtureID(), request, status, response)})
	}
	add("absent-snapshot", "snapshot", canonical.Map{"objectId": current.ObjectID}, canonical.Map{"snapshot": absent, "state": canonical.Bytes{}}, 200, "")
	add("initial-state-and-receipt", "commit", commitBody, canonical.Map{"snapshot": currentValue, "token": token, "requestDigest": digestText(commit.RequestDigest)}, 200, "")
	add("immutable-receipt", "receipt", canonical.Map{"snapshot": currentValue, "commandId": "publish:1"}, canonical.Map{"snapshot": currentValue, "commandId": "publish:1", "found": true, "receipt": receipt}, 200, "")
	add("native-marker-barrier", "barrier", canonical.Map{"token": token, "marker": canonical.Bytes(marker[:])}, canonical.Map{"token": token, "marker": canonical.Bytes(marker[:]), "observedRevision": int64(1), "barrierSerial": int64(1)}, 200, "")
	add("stored-snapshot", "snapshot", canonical.Map{"objectId": current.ObjectID}, canonical.Map{"snapshot": currentValue, "state": canonical.Bytes(commit.State)}, 200, "")
	add("missing-receipt", "receipt", canonical.Map{"snapshot": currentValue, "commandId": "missing"}, canonical.Map{"snapshot": currentValue, "commandId": "missing", "found": false, "receipt": nil}, 200, "")
	add("readonly-commit-advances-revision", "commit", readonlyBody, canonical.Map{"snapshot": laterValue, "token": laterToken, "requestDigest": digestText(readonly.RequestDigest)}, 200, "")
	add("historical-revision-barrier", "barrier", canonical.Map{"token": token, "marker": canonical.Bytes(marker[:])}, canonical.Map{"token": token, "marker": canonical.Bytes(marker[:]), "observedRevision": int64(2), "barrierSerial": int64(2)}, 200, "")
	add("definite-stale-cas-conflict", "commit", readonlyBody, nil, 409, "SNAPSHOT_CONFLICT")
	return fixture
}

func TestNativeStorageGoldenWire(t *testing.T) {
	expected := generatedWireFixture(t)
	path := "../../packages/protocol-types/fixtures/native-storage-v1alpha1.json"
	encoded, err := json.MarshalIndent(expected, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if os.Getenv("CIRCULUSD_UPDATE_NATIVE_STORAGE_FIXTURE") == "1" {
		if err := os.WriteFile(path, encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, encoded) {
		t.Fatal("native Go/TypeScript wire fixture drift")
	}
}

func TestClientNativeOperationGoldenReplies(t *testing.T) {
	fixture := generatedWireFixture(t)
	for _, vector := range fixture.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			var called atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				called.Add(1)
				body, _ := io.ReadAll(request.Body)
				if hex.EncodeToString(body) != vector.RequestHex || request.URL.Path != transactionPath || request.Method != "POST" || request.Header.Get(keyHeader) != fixture.KeyID || request.Header.Get(signatureHeader) != vector.RequestMAC {
					t.Error("client changed pinned request/MAC")
				}
				encoded, _ := hex.DecodeString(vector.ResponseHex)
				response.Header().Set("Content-Type", transactionType)
				response.Header().Set("Cache-Control", "no-store")
				response.Header().Set(keyHeader, fixture.KeyID)
				response.Header().Set(signatureHeader, vector.ResponseMAC)
				response.WriteHeader(vector.Status)
				_, _ = response.Write(encoded)
			}))
			defer server.Close()
			client, err := newClient(ClientConfig{Endpoint: server.URL, KeyID: fixture.KeyID, RootKey: clientFixtureKey(), Timeout: time.Second},
				func() time.Time { return time.UnixMilli(1_700_000_000_000) }, func() (string, error) { return clientFixtureID(), nil })
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			requestBytes, _ := hex.DecodeString(vector.RequestHex)
			requestValue, _ := canonical.Decode(requestBytes, wireOptions(MaximumTransactionBytes))
			body := requestValue.(canonical.Map)["body"].(canonical.Map)
			_, err = client.call(context.Background(), vector.Operation, body)
			if vector.Status == 409 {
				if !errors.Is(err, ErrSnapshotConflict) {
					t.Fatalf("conflict=%v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if called.Load() != 1 {
				t.Fatal("operation unexpectedly replayed")
			}
		})
	}
}

func TestClientValidatesOperationPayloads(t *testing.T) {
	fixture := generatedWireFixture(t)
	for _, name := range []string{"absent-snapshot", "initial-state-and-receipt", "immutable-receipt", "missing-receipt", "native-marker-barrier"} {
		t.Run(name, func(t *testing.T) {
			var vector wireVector
			for _, candidate := range fixture.Cases {
				if candidate.Name == name {
					vector = candidate
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				body, _ := io.ReadAll(request.Body)
				value, _ := canonical.Decode(body, wireOptions(MaximumTransactionBytes))
				envelope := value.(canonical.Map)
				golden, _ := hex.DecodeString(vector.ResponseHex)
				parsed, _ := canonical.Decode(golden, wireOptions(MaximumTransactionBytes))
				reply := parsed.(canonical.Map)
				reply["requestId"] = envelope["requestId"]
				reply["requestDigest"], _ = storageDigest("circulusd.native.storage.request", envelope)
				encoded, _ := canonical.Encode(reply, wireOptions(MaximumTransactionBytes))
				id := envelope["requestId"].(string)
				response.Header().Set("Content-Type", transactionType)
				response.Header().Set("Cache-Control", "no-store")
				response.Header().Set(keyHeader, fixture.KeyID)
				response.Header().Set(signatureHeader, responseMAC(directionalKey(clientFixtureKey(), "response"), fixture.KeyID, id, body, 200, encoded))
				_, _ = response.Write(encoded)
			}))
			defer server.Close()
			client, err := NewClient(ClientConfig{Endpoint: server.URL, KeyID: fixture.KeyID, RootKey: clientFixtureKey(), Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			commit := clientFixtureCommit(t)
			current := commit.Snapshot
			current.Exists = true
			current.Revision = 1
			current.StateDigest = celld.Digest(sha256.Sum256(commit.State))
			switch name {
			case "absent-snapshot":
				result, err := client.ReadSnapshot(context.Background(), SnapshotRequest{ObjectID: current.ObjectID})
				if err != nil || result.Exists || result.Revision != 0 {
					t.Fatalf("snapshot=%+v err=%v", result, err)
				}
			case "initial-state-and-receipt":
				result, err := client.CompareAndCommit(context.Background(), commit)
				if err != nil || result.Token.Revision != 1 || result.Snapshot != current {
					t.Fatalf("commit=%+v err=%v", result, err)
				}
			case "immutable-receipt", "missing-receipt":
				command := "publish:1"
				if name == "missing-receipt" {
					command = "missing"
				}
				result, err := client.ReadReceipt(context.Background(), ReceiptRequest{Snapshot: current, CommandID: command})
				if err != nil || result.Found != (name == "immutable-receipt") {
					t.Fatalf("receipt=%+v err=%v", result, err)
				}
			case "native-marker-barrier":
				result, err := client.ConfirmBarrier(context.Background(), BarrierRequest{Token: celld.CommitToken{ObjectID: current.ObjectID, Revision: 1}, Marker: clientFixtureMarker()})
				if err != nil || result.BarrierSerial != 1 {
					t.Fatalf("barrier=%+v err=%v", result, err)
				}
			}
		})
	}
}

func TestClientNeverPromotesForgedOrAmbiguousConflict(t *testing.T) {
	for _, mode := range []string{"bad-mac", "false-not-committed", "wrong-status", "unknown-code", "extra-field", "wrong-request-digest", "wrong-request-id", "noncanonical", "wrong-content-type", "compressed", "ambiguous-close"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				body, _ := io.ReadAll(request.Body)
				if mode == "ambiguous-close" {
					connection, _, _ := response.(http.Hijacker).Hijack()
					_ = connection.Close()
					return
				}
				value, _ := canonical.Decode(body, wireOptions(MaximumTransactionBytes))
				envelope := value.(canonical.Map)
				id := envelope["requestId"].(string)
				digest, _ := storageDigest("circulusd.native.storage.request", envelope)
				payload := canonical.Map{"ok": false, "error": "SNAPSHOT_CONFLICT", "notCommitted": true}
				status := 409
				if mode == "false-not-committed" {
					payload["notCommitted"] = false
				}
				if mode == "wrong-status" {
					status = 503
				}
				if mode == "unknown-code" {
					payload["error"] = "RETRY_ME"
				}
				if mode == "extra-field" {
					payload["retry"] = true
				}
				reply := canonical.Map{"protocol": storageProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": storageSchema, "requestId": id, "requestDigest": digest, "payload": payload}
				if mode == "wrong-request-digest" {
					reply["requestDigest"] = digestText(celld.Digest{})
				}
				if mode == "wrong-request-id" {
					reply["requestId"] = "req_" + strings.Repeat("B", 25) + "A"
				}
				encoded, _ := canonical.Encode(reply, wireOptions(MaximumTransactionBytes))
				if mode == "noncanonical" {
					encoded = append(encoded, 0)
				}
				response.Header().Set("Content-Type", transactionType)
				response.Header().Set("Cache-Control", "no-store")
				response.Header().Set(keyHeader, "fixture-storage")
				signature := responseMAC(directionalKey(clientFixtureKey(), "response"), "fixture-storage", id, body, status, encoded)
				if mode == "bad-mac" {
					signature = strings.Repeat("0", 64)
				}
				response.Header().Set(signatureHeader, signature)
				if mode == "wrong-content-type" {
					response.Header().Set("Content-Type", "application/json")
				}
				if mode == "compressed" {
					response.Header().Set("Content-Encoding", "gzip")
				}
				response.WriteHeader(status)
				_, _ = response.Write(encoded)
			}))
			defer server.Close()
			client, err := NewClient(ClientConfig{Endpoint: server.URL, KeyID: "fixture-storage", RootKey: clientFixtureKey(), Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_, err = client.CompareAndCommit(context.Background(), clientFixtureCommit(t))
			if err == nil || errors.Is(err, ErrSnapshotConflict) || strings.Contains(err.Error(), server.URL) {
				t.Fatalf("untrusted retry/error exposed: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatal("ambiguous request replayed")
			}
		})
	}
}

func TestClientPinsOriginAndBoundsWholeRequestLifetime(t *testing.T) {
	base := ClientConfig{Endpoint: "http://127.0.0.1:1234", KeyID: "fixture-storage", RootKey: clientFixtureKey(), Timeout: time.Second}
	for _, endpoint := range []string{"http://localhost:1234", "https://127.0.0.1:1234", "http://127.0.0.1:0", "http://127.0.0.1:01234", "http://127.0.0.1:1234/", "http://127.0.0.1:1234?x=1", "http://user@127.0.0.1:1234", "http://192.0.2.1:1234"} {
		config := base
		config.Endpoint = endpoint
		if _, err := NewClient(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("accepted endpoint %s", endpoint)
		}
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", base, base), hex.EncodeToString(base.RootKey)) {
		t.Fatal("configuration reveals credentials")
	}
	for _, size := range []int{31, 33, 64, 256} {
		config := base
		config.RootKey = make([]byte, size)
		if _, err := NewClient(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("accepted native credential length %d", size)
		}
	}
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		close(started)
		<-request.Context().Done()
	}))
	defer server.Close()
	client, err := NewClient(ClientConfig{Endpoint: server.URL, KeyID: base.KeyID, RootKey: base.RootKey, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := client.ReadSnapshot(context.Background(), SnapshotRequest{ObjectID: clientFixtureObject()})
		done <- err
	}()
	<-started
	client.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed source returned successful result")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel owned request")
	}
	_, err = client.ReadSnapshot(context.Background(), SnapshotRequest{ObjectID: clientFixtureObject()})
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("closed request=%v", err)
	}
}

func TestLargeCommitDigestUsesDeclaredWireBound(t *testing.T) {
	request := clientFixtureCommit(t)
	request.State = make([]byte, MaximumStateBytes)
	digest, err := CommitDigest(request)
	if err != nil || digest == (celld.Digest{}) {
		t.Fatalf("maximum state digest=%v err=%v", digest, err)
	}
	request.State = append(request.State, 0)
	if _, err := CommitDigest(request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("oversized state accepted")
	}
}
