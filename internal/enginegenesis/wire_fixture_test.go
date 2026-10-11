package enginegenesis

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/stateappcodec"
	"google.golang.org/protobuf/proto"
)

type genesisWireCase struct {
	Name            string `json:"name"`
	Status          int    `json:"status"`
	ResponseCBORHex string `json:"responseCBORHex"`
	ResponseMAC     string `json:"responseMAC"`
	Error           string `json:"error,omitempty"`
}

type genesisWireFixture struct {
	TestOnly    bool   `json:"testOnly"`
	Description string `json:"description"`
	Protocol    string `json:"protocol"`
	Major       int    `json:"major"`
	Minor       int    `json:"minor"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	ContentType string `json:"contentType"`
	HeaderNames struct {
		KeyID     string `json:"keyId"`
		Signature string `json:"signature"`
	} `json:"headerNames"`
	SchemaDigests struct {
		Genesis string `json:"genesis"`
		Probe   string `json:"probe"`
	} `json:"schemaDigests"`
	RequestDomain     string            `json:"requestDomain"`
	ResponseDomain    string            `json:"responseDomain"`
	KeyID             string            `json:"keyId"`
	RootKey           string            `json:"rootKey"`
	RequestKey        string            `json:"requestKey"`
	ResponseKey       string            `json:"responseKey"`
	RequestID         string            `json:"requestId"`
	SentAtUnixMs      int64             `json:"sentAtUnixMs"`
	RequestCBORHex    string            `json:"requestCBORHex"`
	RequestMAC        string            `json:"requestMAC"`
	RequestDigest     string            `json:"requestDigest"`
	CheckpointCBORHex string            `json:"checkpointCBORHex"`
	Cases             []genesisWireCase `json:"cases"`
}

func genesisWireFixturePath() string {
	return filepath.Join("..", "..", "packages", "protocol-types", "fixtures", "engine-genesis-v1alpha1.json")
}

func genesisFixtureEncode(t *testing.T, value canonical.Value, limit int) []byte {
	t.Helper()
	encoded, err := canonical.Encode(value, wireOptions(limit))
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func genesisFixtureUnhex(t *testing.T, value string) []byte {
	t.Helper()
	encoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// These public keys authenticate deterministic protocol examples only. The
// fixture contains no native probe signature, evidence or deployment secrets.
func expectedGenesisWireFixture(t *testing.T) genesisWireFixture {
	t.Helper()
	request, checkpoint := actualPiFixture(t)
	_, body, err := snapshotRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	inline, err := stateappcodec.CheckpointToValue(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	root := make([]byte, 32)
	for i := range root {
		root[i] = byte(i)
	}
	requestKey, responseKey := directionalKey(root, "request"), directionalKey(root, "response")
	fixture := genesisWireFixture{
		TestOnly: true, Description: "Public deterministic HMAC test material and actual Pi checkpoint; not deployment credentials or native qualification evidence.",
		Protocol: genesisProtocol, Major: 1, Minor: 0, Method: http.MethodPost, Path: genesisPath, ContentType: genesisType,
		RequestDomain: requestDomain, ResponseDomain: responseDomain,
		KeyID: "engine-genesis-fixture-1", RootKey: hex.EncodeToString(root),
		RequestKey: hex.EncodeToString(requestKey[:]), ResponseKey: hex.EncodeToString(responseKey[:]),
		RequestID: "req_AAAAAAAAAAAAAAAAAAAAAAAAAA", SentAtUnixMs: 1_700_000_000_000,
		CheckpointCBORHex: hex.EncodeToString(genesisFixtureEncode(t, inline, maximumResponseBytes)),
	}
	fixture.HeaderNames.KeyID, fixture.HeaderNames.Signature = keyHeader, signatureHeader
	fixture.SchemaDigests.Genesis, fixture.SchemaDigests.Probe = genesisSchema, probeSchema
	encoded := genesisFixtureEncode(t, canonical.Map{
		"protocol": genesisProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": genesisSchema,
		"requestId": fixture.RequestID, "sentAtUnixMs": fixture.SentAtUnixMs, "body": body,
	}, maximumRequestBytes)
	fixture.RequestCBORHex = hex.EncodeToString(encoded)
	fixture.RequestMAC = requestMAC(requestKey, fixture.KeyID, encoded)
	fixture.RequestDigest, err = canonical.StructuredDigest("circulusd.engine.genesis-request", 1, body)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []genesisWireCase{
		{Name: "success", Status: http.StatusOK},
		{Name: "unavailable", Status: http.StatusServiceUnavailable, Error: "UNAVAILABLE"},
		{Name: "bad-source", Status: http.StatusServiceUnavailable, Error: "BAD_SOURCE"},
	} {
		payload := canonical.Map{"ok": false, "error": test.Error}
		if test.Status == http.StatusOK {
			payload = canonical.Map{"ok": true, "identity": requestIdentity(request), "checkpoint": inline}
		}
		response := genesisFixtureEncode(t, canonical.Map{
			"protocol": genesisProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": genesisSchema,
			"requestId": fixture.RequestID, "requestDigest": fixture.RequestDigest, "payload": payload,
		}, maximumResponseBytes)
		test.ResponseCBORHex = hex.EncodeToString(response)
		test.ResponseMAC = responseMAC(responseKey, fixture.KeyID, fixture.RequestID, encoded, test.Status, response)
		fixture.Cases = append(fixture.Cases, test)
	}
	return fixture
}

func readGenesisWireFixture(t *testing.T) genesisWireFixture {
	t.Helper()
	encoded, err := os.ReadFile(genesisWireFixturePath())
	if err != nil {
		t.Fatal(err)
	}
	var fixture genesisWireFixture
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestEngineGenesisWireFixtureMatchesOperationalServer(t *testing.T) {
	fixture := expectedGenesisWireFixture(t)
	expected, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	expected = append(expected, '\n')
	if os.Getenv("CIRCULUSD_UPDATE_ENGINE_GENESIS_FIXTURE") == "1" {
		if err := os.WriteFile(genesisWireFixturePath(), expected, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := os.ReadFile(genesisWireFixturePath())
	if err != nil {
		t.Fatalf("read fixture (explicit update: CIRCULUSD_UPDATE_ENGINE_GENESIS_FIXTURE=1): %v", err)
	}
	if !bytes.Equal(stored, expected) {
		t.Fatal("engine genesis wire fixture differs from regenerated canonical bytes; explicit update requires CIRCULUSD_UPDATE_ENGINE_GENESIS_FIXTURE=1")
	}
	for _, test := range fixture.Cases {
		t.Run(test.Name, func(t *testing.T) {
			source, sealed := qualifiedSource(t)
			switch test.Error {
			case "UNAVAILABLE":
				source.err = errors.New("source-secret-must-not-escape")
			case "BAD_SOURCE":
				source.checkpoint = nil
			}
			handler, err := newServer(ServerConfig{KeyID: fixture.KeyID, RootKey: genesisFixtureUnhex(t, fixture.RootKey), Source: sealed}, func() time.Time {
				return time.UnixMilli(fixture.SentAtUnixMs)
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(fixture.Method, fixture.Path, bytes.NewReader(genesisFixtureUnhex(t, fixture.RequestCBORHex)))
			request.Header.Set("Content-Type", fixture.ContentType)
			request.Header.Set(fixture.HeaderNames.KeyID, fixture.KeyID)
			request.Header.Set(fixture.HeaderNames.Signature, fixture.RequestMAC)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.Status || response.Header().Get("Content-Type") != fixture.ContentType || response.Header().Get("Cache-Control") != "no-store" ||
				response.Header().Get(fixture.HeaderNames.KeyID) != fixture.KeyID || response.Header().Get(fixture.HeaderNames.Signature) != test.ResponseMAC ||
				!bytes.Equal(response.Body.Bytes(), genesisFixtureUnhex(t, test.ResponseCBORHex)) || source.calls.Load() != 1 {
				t.Fatal("operational server changed fixture status, authenticated envelope or exact original checkpoint")
			}
		})
	}
}

func TestEngineGenesisClientConsumesSharedWireFixture(t *testing.T) {
	fixture := readGenesisWireFixture(t)
	request, checkpoint := actualPiFixture(t)
	inline, err := stateappcodec.CheckpointToValue(checkpoint)
	if err != nil || !bytes.Equal(genesisFixtureEncode(t, inline, maximumResponseBytes), genesisFixtureUnhex(t, fixture.CheckpointCBORHex)) {
		t.Fatal("shared fixture checkpoint differs from actual Pi genesis", err)
	}
	requestBytes := genesisFixtureUnhex(t, fixture.RequestCBORHex)
	for _, test := range fixture.Cases {
		t.Run(test.Name, func(t *testing.T) {
			responseBytes := genesisFixtureUnhex(t, test.ResponseCBORHex)
			received := make(chan error, 1)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				body, err := io.ReadAll(io.LimitReader(request.Body, maximumRequestBytes+1))
				if err != nil || request.Method != fixture.Method || request.URL.RequestURI() != fixture.Path ||
					request.Header.Get("Content-Type") != fixture.ContentType || request.Header.Get("Accept") != fixture.ContentType ||
					request.Header.Get("Cache-Control") != "no-store" || request.Header.Get(fixture.HeaderNames.KeyID) != fixture.KeyID ||
					request.Header.Get(fixture.HeaderNames.Signature) != fixture.RequestMAC || !bytes.Equal(body, requestBytes) {
					received <- fmt.Errorf("actual client request differs from fixture: %v", err)
					writer.WriteHeader(http.StatusBadRequest)
					return
				}
				received <- nil
				writer.Header().Set("Content-Type", fixture.ContentType)
				writer.Header().Set("Cache-Control", "no-store")
				writer.Header().Set(fixture.HeaderNames.KeyID, fixture.KeyID)
				writer.Header().Set(fixture.HeaderNames.Signature, test.ResponseMAC)
				writer.WriteHeader(test.Status)
				_, _ = writer.Write(responseBytes)
			}))
			t.Cleanup(server.Close)
			client, err := newClient(ClientConfig{Endpoint: server.URL, KeyID: fixture.KeyID, RootKey: genesisFixtureUnhex(t, fixture.RootKey), Timeout: time.Second}, func() time.Time {
				return time.UnixMilli(fixture.SentAtUnixMs)
			}, func() (string, error) { return fixture.RequestID, nil })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.Close)
			actual, err := client.RequestGenesis(context.Background(), request)
			select {
			case requestErr := <-received:
				if requestErr != nil {
					t.Fatal(requestErr)
				}
			default:
				t.Fatal("actual client did not send fixture request", err)
			}
			if test.Status == http.StatusOK {
				if err != nil || !proto.Equal(actual, checkpoint) {
					t.Fatal("actual client did not retain exact original executable Pi checkpoint", err)
				}
			} else if !errors.Is(err, ErrUnavailable) || actual != nil {
				t.Fatal("authenticated error exposed a genesis result", err)
			}
		})
	}
}
