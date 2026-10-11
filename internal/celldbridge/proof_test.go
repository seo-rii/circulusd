package celldbridge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/dependency/contracttest"
)

func TestClientNativeProofIsIndependentOfTransportMAC(t *testing.T) {
	groups := []dependency.AtomicGroup{dependency.AtomicCommandReceipt, AtomicNativeStorage}
	proofs := contracttest.NewProductionProofs(t, groups)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.URL.Path != probePath || request.Header.Get("Content-Type") != probeType || request.Header.Get(keyHeader) != "" || request.Header.Get(signatureHeader) != "" {
			t.Error("probe borrowed operational transport authority")
		}
		body, _ := io.ReadAll(request.Body)
		value, err := canonical.Decode(body, wireOptions(256))
		if err != nil {
			t.Error(err)
			response.WriteHeader(400)
			return
		}
		m := value.(canonical.Map)
		nonce := m["nonce"].(canonical.Bytes)
		if len(m) != 5 || m["protocol"] != probeProtocol || m["schemaDigest"] != probeSchema {
			t.Error("probe request drift")
		}
		proof, err := proofs.ProbeProduction(request.Context(), dependency.ProbeChallenge{Nonce: nonce})
		if err != nil {
			t.Error(err)
			return
		}
		payload, err := proofValue(proof, nonce)
		if err != nil {
			t.Error(err)
			return
		}
		encoded, _ := canonical.Encode(payload, wireOptions(maximumProbeBytes))
		response.Header().Set("Content-Type", probeType)
		response.Header().Set("Cache-Control", "no-store")
		_, _ = response.Write(encoded)
	}))
	defer server.Close()
	client, err := NewClient(ClientConfig{Endpoint: server.URL, KeyID: "fixture-storage", RootKey: clientFixtureKey(), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	nonce := bytes.Repeat([]byte{1}, dependency.ChallengeBytes)
	proof, err := client.ProbeProduction(context.Background(), dependency.ProbeChallenge{Nonce: nonce})
	if err != nil || !reflect.DeepEqual(proof.Descriptor, proofs.Descriptor()) {
		t.Fatalf("native proof=%+v err=%v", proof, err)
	}
	// Both seals invoke the exact client's original native signature. Neither
	// constructor may replace it with the operational HMAC or create a key.
	verified := contracttest.Verify[NativeTransport](t, proofs, client, groups)
	storage, err := New(Config{Transport: verified, Bounds: Bounds{MaxStateBytes: 1024, MaxReceiptResponseBytes: 1024, MaxCapabilityClaims: 4, MaxCapabilityClaimBytes: 1024, MaxReceiptLookups: 4, MaxReceiptWrites: 4, MaxTransactionBytes: 8192}, MaximumAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	_ = contracttest.Verify(t, proofs, storage, groups)
	if calls.Load() != 3 {
		t.Fatalf("independent challenges=%d", calls.Load())
	}
}

func TestClientRejectsMalformedNativeProofAndCanceledProbe(t *testing.T) {
	proofs := contracttest.NewProductionProofs(t, []dependency.AtomicGroup{dependency.AtomicCommandReceipt, AtomicNativeStorage})
	for _, mode := range []string{"wrong-nonce", "storage-mac", "extra-field", "missing-native-group", "bad-signature-shape", "wrong-key-id", "wrong-schema", "duplicate-header"} {
		t.Run(mode, func(t *testing.T) {
			var called atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				called.Add(1)
				body, _ := io.ReadAll(request.Body)
				value, _ := canonical.Decode(body, wireOptions(256))
				nonce := value.(canonical.Map)["nonce"].(canonical.Bytes)
				proof, _ := proofs.ProbeProduction(request.Context(), dependency.ProbeChallenge{Nonce: nonce})
				payload, _ := proofValue(proof, nonce)
				switch mode {
				case "wrong-nonce":
					payload["nonce"] = canonical.Bytes(bytes.Repeat([]byte{9}, 32))
				case "storage-mac":
					response.Header().Set(keyHeader, "fixture-storage")
					response.Header().Set(signatureHeader, strings.Repeat("a", 64))
				case "extra-field":
					payload["qualified"] = true
				case "missing-native-group":
					payload["descriptor"].(canonical.Map)["atomicGroups"] = canonical.Array{"command-receipt"}
				case "bad-signature-shape":
					payload["signature"] = canonical.Bytes{1, 2}
				case "wrong-key-id":
					payload["keyId"] = "unrelated-native-key"
				case "wrong-schema":
					payload["schemaDigest"] = storageSchema
				}
				encoded, _ := canonical.Encode(payload, wireOptions(maximumProbeBytes))
				response.Header().Set("Content-Type", probeType)
				response.Header().Set("Cache-Control", "no-store")
				if mode == "duplicate-header" {
					response.Header().Add("Content-Type", probeType)
				}
				_, _ = response.Write(encoded)
			}))
			defer server.Close()
			client, err := NewClient(ClientConfig{Endpoint: server.URL, KeyID: "fixture-storage", RootKey: clientFixtureKey(), Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_, err = client.ProbeProduction(context.Background(), dependency.ProbeChallenge{Nonce: bytes.Repeat([]byte{1}, 32)})
			if err == nil {
				t.Fatalf("accepted %s", mode)
			}
			before := called.Load()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err = client.ProbeProduction(ctx, dependency.ProbeChallenge{Nonce: bytes.Repeat([]byte{1}, 32)})
			if !errors.Is(err, context.Canceled) || called.Load() != before {
				t.Fatal("canceled probe reached native source")
			}
		})
	}
}
