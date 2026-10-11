package stateappclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
)

func providerRequest() ProviderResultRequest {
	return ProviderResultRequest{TenantID: validID("tenant", 1), WorkspaceID: validID("ws", 1), SessionID: validID("sess", 1),
		EffectID: validID("effect", 1), InvocationID: validID("inv", 1), RequestDigest: "sha256:" + strings.Repeat("1", 64),
		ExternalCommitID: validID("commit", 1), ResultRef: validID("artifact", 1)}
}

func TestProviderResultBindsEveryReferenceAndImmutableBytes(t *testing.T) {
	for _, mode := range []string{"valid", "tenantId", "workspaceId", "sessionId", "effectId", "invocationId", "requestDigest", "externalCommitId", "resultRef", "extra-request-field", "digest", "noncanonical", "wrong-domain", "request-replay", "missing-body", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			root := bytes.Repeat([]byte{7}, 32)
			serverRoot := bytes.Clone(root)
			request := providerRequest()
			payload, err := canonical.Encode(canonical.Map{"text": "result", "cost": canonical.Map{"decimal": "0.00000125"}}, canonical.DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := mustReadRequest(t, r)
				if r.URL.RequestURI() != ProviderResultPath || r.Header.Get("Content-Type") != ProviderResultContentType {
					t.Error("wrong contract")
				}
				decoded, err := canonical.Decode(body, canonical.DefaultOptions())
				if err != nil {
					t.Fatal(err)
				}
				wire := decoded.(canonical.Map)
				if wire["schemaDigest"] != ProviderResultSchemaDigest() || wire["protocol"] != ProviderResultProtocol {
					t.Error("wrong schema")
				}
				requestID := wire["requestId"].(string)
				if r.Header.Get(signatureHeader) != requestMACFor(serverRoot, "provider", ProviderResultRequestMACDomain, ProviderResultPath, body) {
					t.Error("wrong request MAC domain")
				}
				echo := providerResultRequestValue(request)
				for field := range echo {
					if mode == field {
						echo[field] = "changed"
					}
				}
				if mode == "extra-request-field" {
					echo["extra"] = true
				}
				bodyPayload := bytes.Clone(payload)
				if mode == "noncanonical" {
					bodyPayload = []byte{0x18, 0}
				}
				if mode == "oversized" {
					bodyPayload = make([]byte, MaximumProviderResultBytes+1)
				}
				digest := fmt.Sprintf("sha256:%x", sha256.Sum256(bodyPayload))
				if mode == "digest" {
					digest = "sha256:" + strings.Repeat("0", 64)
				}
				result := canonical.Map{"request": echo, "payloadDigest": digest, "canonicalCbor": canonical.Bytes(bodyPayload)}
				if mode == "missing-body" {
					delete(result, "canonicalCbor")
				}
				response, err := canonical.Encode(canonical.Map{"protocol": hostProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": ProviderResultSchemaDigest(), "requestId": requestID, "payload": canonical.Map{"ok": true, "result": result}}, canonical.DefaultOptions())
				if err != nil {
					t.Fatal(err)
				}
				domain := ProviderResultResponseMACDomain
				if mode == "wrong-domain" {
					domain = responseMACDomain
				}
				requestBody := body
				if mode == "request-replay" {
					requestBody = []byte("prior request")
				}
				signature := responseMACFor(serverRoot, "provider", requestID, requestBody, 200, ProviderResultContentType, domain, response)
				writeWireResponse(w, wireResponse{status: 200, contentType: ProviderResultContentType, keyID: "provider", signature: signature, body: response})
			}))
			client, err := New(Config{Endpoint: endpoint, KeyID: "provider", RootKey: root, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			clear(root)
			result, err := client.ReadProviderResult(context.Background(), request)
			if mode == "valid" {
				if err != nil || result.Request != request || !bytes.Equal(result.CanonicalCBOR, payload) {
					t.Fatalf("roundtrip: %v", err)
				}
				return
			}
			want := ErrInvalidResponse
			if mode == "wrong-domain" || mode == "request-replay" {
				want = ErrUnauthenticatedResponse
			}
			if !errors.Is(err, want) || result.CanonicalCBOR != nil {
				t.Fatalf("got %v, want %v and no body", err, want)
			}
		})
	}
}

func TestProviderResultRejectsInvalidInputBeforeIOAndClosedClient(t *testing.T) {
	var calls atomic.Int32
	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	client, err := New(Config{Endpoint: endpoint, KeyID: "provider", RootKey: bytes.Repeat([]byte{7}, 32), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"tenant", "workspace", "session", "effect", "invocation", "commit", "artifact", "digest"} {
		request := providerRequest()
		switch field {
		case "tenant":
			request.TenantID = "wrong"
		case "workspace":
			request.WorkspaceID = "wrong"
		case "session":
			request.SessionID = "wrong"
		case "effect":
			request.EffectID = "wrong"
		case "invocation":
			request.InvocationID = "wrong"
		case "commit":
			request.ExternalCommitID = "wrong"
		case "artifact":
			request.ResultRef = "wrong"
		case "digest":
			request.RequestDigest = "sha256:" + strings.Repeat("0", 64)
		}
		if _, err := client.ReadProviderResult(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
			t.Fatal(err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid reference reached provider")
	}
	client.Close()
	if _, err := client.ReadProviderResult(context.Background(), providerRequest()); !errors.Is(err, ErrClientClosed) {
		t.Fatal(err)
	}
}
