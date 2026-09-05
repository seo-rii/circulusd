package stateappclient

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
)

const (
	testIngressPath        = "/circulusd/state/v1/session-events:read"
	testIngressContentType = "application/vnd.circulusd.state-ingress+cbor"
	testDispatchStartPath  = "/circulusd/state/v1/session-dispatch-start:claim"
	testDispatchStartType  = "application/vnd.circulusd.state-dispatch-start-ingress+cbor"
	testDispatchStartKeyID = "state-dispatch-current-1"
	testKeyHeader          = "X-Circulus-State-Key-Id"
	testSignatureHeader    = "X-Circulus-State-Signature"
)

func TestClaimDispatchStartUsesExactAuthenticatedWireAndParsesFreshResultAfterJournalAdvance(t *testing.T) {
	readRootKey := bytes.Repeat([]byte{0x31}, 32)
	dispatchStartRootKey := bytes.Repeat([]byte{0x91}, 32)
	serverDispatchStartRootKey := append([]byte(nil), dispatchStartRootKey...)
	requestValue := validClaimDispatchStartRequest()
	requestID := validID("req", 90)
	sentAt := time.UnixMilli(1_900_000_000_000)
	wantClaims := claimDispatchPermitClaimsMap(requestValue.DispatchPermitClaims)

	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body := mustReadRequest(t, request)
		if request.Method != http.MethodPost || request.URL.Path != testDispatchStartPath || request.URL.RawQuery != "" {
			t.Errorf("request target = %s %s, want POST %s", request.Method, request.URL.RequestURI(), testDispatchStartPath)
		}
		if values := request.Header.Values("Content-Type"); len(values) != 1 || values[0] != testDispatchStartType {
			t.Errorf("Content-Type = %q, want exact claim media type", values)
		}
		if request.Header.Get("Content-Encoding") != "" {
			t.Errorf("unexpected Content-Encoding = %q", request.Header.Get("Content-Encoding"))
		}
		wantSignature := requestMACFor(
			serverDispatchStartRootKey,
			testDispatchStartKeyID,
			"circulusd.state-dispatch-start-ingress.request.v1",
			testDispatchStartPath,
			body,
		)
		if values := request.Header.Values(testKeyHeader); len(values) != 1 || values[0] != testDispatchStartKeyID {
			t.Errorf("claim key header = %q, want operation-scoped key ID", values)
		}
		if values := request.Header.Values(testSignatureHeader); len(values) != 1 || values[0] != wantSignature {
			t.Errorf("request signature = %q, want %q", values, wantSignature)
		}

		decoded, err := canonical.Decode(body, canonical.Options{
			MaxBytes: maximumDispatchStartRequestBytes,
			MaxDepth: maximumDispatchStartRequestDepth,
			MaxItems: maximumDispatchStartRequestItems,
		})
		if err != nil {
			t.Fatalf("decode claim request: %v", err)
		}
		wantRequest := canonical.Map{
			"protocol": "circulus.state-dispatch-start-ingress.v1alpha1", "major": int64(1), "minor": int64(0),
			"schemaDigest": "sha256:a86295cc9ad723e50c8729318e4ec4994faa7b4c64c30a718696de8fa6edc724",
			"requestId":    requestID, "sentAtUnixMs": sentAt.UnixMilli(),
			"tenantId": requestValue.TenantID, "workspaceId": requestValue.WorkspaceID,
			"sessionId": requestValue.SessionID,
			"commandId": requestValue.CommandID, "expectedEventSequence": int64(requestValue.ExpectedEventSequence),
			"turnId": requestValue.TurnID, "effectId": requestValue.EffectID,
			"invocationId": requestValue.InvocationID, "requestDigest": requestValue.RequestDigest,
			"fence": canonical.Map{
				"turnLeaseGeneration":     int64(requestValue.Fence.TurnLeaseGeneration),
				"placementGeneration":     int64(requestValue.Fence.PlacementGeneration),
				"sandboxGeneration":       int64(requestValue.Fence.SandboxGeneration),
				"authorizationGeneration": int64(requestValue.Fence.AuthorizationGeneration),
			},
			"dispatchAttempt":      int64(requestValue.DispatchAttempt),
			"providerRequestId":    requestValue.ProviderRequestID,
			"providerRouteDigest":  requestValue.ProviderRouteDigest,
			"dispatchPermitClaims": wantClaims,
			"commandDigest":        requestValue.CommandDigest,
		}
		if !reflect.DeepEqual(decoded, wantRequest) {
			t.Errorf("claim request = %#v\nwant          = %#v", decoded, wantRequest)
		}

		result := canonical.Map{
			"outcome": canonical.Map{
				"kind": "dispatch_start_claimed", "effectId": requestValue.EffectID, "fresh": true,
				"startPermit": canonical.Map{
					"dispatchPermitClaims": wantClaims,
					"providerRequestId":    requestValue.ProviderRequestID,
					"commandDigest":        requestValue.CommandDigest,
					"claimedEventSequence": uint64(14),
				},
			},
			"version": uint64(14), "replayed": false,
		}
		responseBody := mustEncode(t, claimSuccessEnvelope(requestID, result))
		writeWireResponse(writer, wireResponse{
			status: http.StatusOK, contentType: testDispatchStartType, keyID: testDispatchStartKeyID,
			signature: responseMACFor(
				serverDispatchStartRootKey,
				testDispatchStartKeyID,
				requestID,
				body,
				http.StatusOK,
				testDispatchStartType,
				"circulusd.state-dispatch-start-ingress.response.v1",
				responseBody,
			),
			body: responseBody,
		})
	}))

	client, err := newWithSources(Config{
		Endpoint: endpoint, KeyID: testKeyID, RootKey: readRootKey,
		DispatchStartKeyID: testDispatchStartKeyID, DispatchStartRootKey: dispatchStartRootKey,
		Timeout: time.Second,
	}, clientSources{
		clock:        func() time.Time { return sentAt },
		newRequestID: func() (string, error) { return requestID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	clear(readRootKey)
	clear(dispatchStartRootKey)

	result, err := client.ClaimDispatchStart(context.Background(), requestValue)
	if err != nil {
		t.Fatalf("ClaimDispatchStart() error = %v", err)
	}
	wantResult := ClaimDispatchStartResult{
		OutcomeFresh: true, HostReplayed: false, Version: 14, EffectID: requestValue.EffectID,
		Permit: DispatchStartPermit{
			DispatchPermitClaims: requestValue.DispatchPermitClaims,
			ProviderRequestID:    requestValue.ProviderRequestID,
			CommandDigest:        requestValue.CommandDigest,
			ClaimedEventSequence: 14,
		},
	}
	if !reflect.DeepEqual(result, wantResult) {
		t.Fatalf("ClaimDispatchStart() = %#v, want %#v", result, wantResult)
	}
}

func TestClaimDispatchStartRequiresOperationScopedCredentialsBeforeSourcesOrDial(t *testing.T) {
	var generated atomic.Int64
	client, err := newWithSources(Config{
		Endpoint: "http://127.0.0.1:1", KeyID: testKeyID,
		RootKey: bytes.Repeat([]byte{0x36}, 32), Timeout: time.Second,
	}, clientSources{
		clock: time.Now,
		newRequestID: func() (string, error) {
			generated.Add(1)
			return validID("req", 1), nil
		},
	})
	if err != nil {
		t.Fatalf("New(read-only client) error = %v", err)
	}
	t.Cleanup(client.Close)
	if _, err := client.ClaimDispatchStart(context.Background(), validClaimDispatchStartRequest()); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("read-only ClaimDispatchStart() error = %v, want ErrInvalidConfig", err)
	}
	if generated.Load() != 0 {
		t.Fatalf("read-only claim generated %d request IDs", generated.Load())
	}
}

func TestClaimDispatchStartEncodesCompositeClaimsAndNullableProviderRequest(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x32}, 32)
	requestValue := validClaimDispatchStartRequest()
	requestValue.ProviderRequestID = ""
	requestValue.DispatchPermitClaims.ParentOperationID = validID("op", 1)
	requestValue.DispatchPermitClaims.Ordinal = 0
	requestID := validID("req", 91)

	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body := mustReadRequest(t, request)
		decoded, err := canonical.Decode(body, canonical.Options{
			MaxBytes: maximumDispatchStartRequestBytes,
			MaxDepth: maximumDispatchStartRequestDepth,
			MaxItems: maximumDispatchStartRequestItems,
		})
		if err != nil {
			t.Fatal(err)
		}
		record := decoded.(canonical.Map)
		if record["providerRequestId"] != nil {
			t.Errorf("providerRequestId = %#v, want null", record["providerRequestId"])
		}
		claims := record["dispatchPermitClaims"].(canonical.Map)
		if claims["parentOperationId"] != requestValue.DispatchPermitClaims.ParentOperationID || claims["ordinal"] != int64(0) {
			t.Errorf("composite claims = %#v", claims)
		}
		responseResult := claimResultMap(requestValue, false, true, 14, 13)
		responseBody := mustEncode(t, claimSuccessEnvelope(requestID, responseResult))
		writeWireResponse(writer, wireResponse{
			status: 200, contentType: testDispatchStartType, keyID: testDispatchStartKeyID,
			signature: responseMACFor(rootKey, testDispatchStartKeyID, requestID, body, 200, testDispatchStartType, "circulusd.state-dispatch-start-ingress.response.v1", responseBody),
			body:      responseBody,
		})
	}))
	client := newClaimTestClient(t, endpoint, rootKey, func() (string, error) { return requestID, nil }, time.Second)
	result, err := client.ClaimDispatchStart(context.Background(), requestValue)
	if err != nil {
		t.Fatalf("ClaimDispatchStart() error = %v", err)
	}
	if result.OutcomeFresh || !result.HostReplayed || result.Version != 14 || result.Permit.ProviderRequestID != "" {
		t.Fatalf("replayed result = %#v", result)
	}
}

func TestClaimDispatchStartRejectsInvalidRequestBeforeDial(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x33}, 32)
	var generated atomic.Int64
	client, err := newWithSources(Config{
		Endpoint: "http://127.0.0.1:1", KeyID: testKeyID,
		RootKey:            bytes.Repeat([]byte{0x13}, 32),
		DispatchStartKeyID: testDispatchStartKeyID, DispatchStartRootKey: rootKey,
		Timeout: time.Second,
	}, clientSources{
		clock:        time.Now,
		newRequestID: func() (string, error) { generated.Add(1); return validID("req", 1), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	base := validClaimDispatchStartRequest()
	tests := []struct {
		name string
		edit func(*ClaimDispatchStartRequest)
	}{
		{name: "tenant kind", edit: func(value *ClaimDispatchStartRequest) { value.TenantID = validID("subject", 1) }},
		{name: "empty workspace", edit: func(value *ClaimDispatchStartRequest) { value.WorkspaceID = "" }},
		{name: "workspace kind", edit: func(value *ClaimDispatchStartRequest) { value.WorkspaceID = validID("sess", 1) }},
		{name: "session kind", edit: func(value *ClaimDispatchStartRequest) { value.SessionID = validID("turn", 1) }},
		{name: "empty command ID", edit: func(value *ClaimDispatchStartRequest) { value.CommandID = "" }},
		{name: "event sequence cannot increment", edit: func(value *ClaimDispatchStartRequest) { value.ExpectedEventSequence = maximumSharedInteger }},
		{name: "unsafe expected sequence", edit: func(value *ClaimDispatchStartRequest) { value.ExpectedEventSequence = maximumSharedInteger + 1 }},
		{name: "turn kind", edit: func(value *ClaimDispatchStartRequest) { value.TurnID = validID("sess", 1) }},
		{name: "effect kind", edit: func(value *ClaimDispatchStartRequest) { value.EffectID = validID("inv", 1) }},
		{name: "invocation kind", edit: func(value *ClaimDispatchStartRequest) { value.InvocationID = validID("effect", 1) }},
		{name: "request digest", edit: func(value *ClaimDispatchStartRequest) { value.RequestDigest = "sha256:ABC" }},
		{name: "zero request digest", edit: func(value *ClaimDispatchStartRequest) {
			value.RequestDigest = "sha256:" + strings.Repeat("0", 64)
			value.DispatchPermitClaims.RequestDigest = value.RequestDigest
		}},
		{name: "unsafe fence", edit: func(value *ClaimDispatchStartRequest) { value.Fence.AuthorizationGeneration = maximumSharedInteger + 1 }},
		{name: "zero dispatch attempt", edit: func(value *ClaimDispatchStartRequest) { value.DispatchAttempt = 0 }},
		{name: "provider request kind", edit: func(value *ClaimDispatchStartRequest) { value.ProviderRequestID = validID("effect", 1) }},
		{name: "zero provider route digest", edit: func(value *ClaimDispatchStartRequest) {
			value.ProviderRouteDigest = "sha256:" + strings.Repeat("0", 64)
		}},
		{name: "claims tenant mismatch", edit: func(value *ClaimDispatchStartRequest) { value.DispatchPermitClaims.TenantID = validID("tenant", 2) }},
		{name: "claims service", edit: func(value *ClaimDispatchStartRequest) { value.DispatchPermitClaims.Service = "database" }},
		{name: "claims operation", edit: func(value *ClaimDispatchStartRequest) { value.DispatchPermitClaims.Operation = "bad\noperation" }},
		{name: "claims replay policy", edit: func(value *ClaimDispatchStartRequest) { value.DispatchPermitClaims.ReplayPolicy = "sometimes" }},
		{name: "orphan ordinal", edit: func(value *ClaimDispatchStartRequest) { value.DispatchPermitClaims.Ordinal = 1 }},
		{name: "claims unsafe generation", edit: func(value *ClaimDispatchStartRequest) {
			value.DispatchPermitClaims.SandboxGeneration = maximumSharedInteger + 1
		}},
		{name: "zero deadline", edit: func(value *ClaimDispatchStartRequest) { value.DispatchPermitClaims.DeadlineUnixMS = 0 }},
		{name: "unsafe deadline", edit: func(value *ClaimDispatchStartRequest) {
			value.DispatchPermitClaims.DeadlineUnixMS = maximumSharedInteger + 1
		}},
		{name: "zero command digest", edit: func(value *ClaimDispatchStartRequest) { value.CommandDigest = "sha256:" + strings.Repeat("0", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base
			test.edit(&request)
			if _, claimErr := client.ClaimDispatchStart(context.Background(), request); !errors.Is(claimErr, ErrInvalidRequest) {
				t.Fatalf("ClaimDispatchStart() error = %v, want ErrInvalidRequest", claimErr)
			}
		})
	}
	if generated.Load() != 0 {
		t.Fatalf("invalid requests generated %d request IDs", generated.Load())
	}
}

func TestClaimDispatchStartRejectsUnauthenticatedMalformedOrRelabelledResponses(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x34}, 32)
	readRootKey := bytes.Repeat([]byte{0x10}, 32)
	requestValue := validClaimDispatchStartRequest()
	tests := []struct {
		name string
		edit func(canonical.Map, *wireResponse)
		want error
	}{
		{
			name: "unsigned",
			edit: func(_ canonical.Map, response *wireResponse) {
				response.keyID = ""
				response.signature = ""
			},
			want: ErrUnauthenticatedResponse,
		},
		{
			name: "read ingress MAC domain",
			edit: func(_ canonical.Map, response *wireResponse) {
				response.signature = "read-domain"
			},
			want: ErrUnauthenticatedResponse,
		},
		{
			name: "read credential with claim MAC domain",
			edit: func(_ canonical.Map, response *wireResponse) {
				response.keyID = testKeyID
				response.signature = "read-credential"
			},
			want: ErrUnauthenticatedResponse,
		},
		{
			name: "tampered body",
			edit: func(_ canonical.Map, response *wireResponse) {
				response.body[len(response.body)-1] ^= 1
			},
			want: ErrUnauthenticatedResponse,
		},
		{
			name: "wrong content type",
			edit: func(_ canonical.Map, response *wireResponse) {
				response.contentType = testIngressContentType
			},
			want: ErrUnauthenticatedResponse,
		},
		{
			name: "content encoding",
			edit: func(_ canonical.Map, response *wireResponse) {
				response.contentEncoding = "identity"
			},
			want: ErrUnauthenticatedResponse,
		},
		{
			name: "oversized signed body",
			edit: func(_ canonical.Map, response *wireResponse) {
				response.body = bytes.Repeat([]byte{0xf6}, maximumResponseBytes+1)
				response.resign = true
			},
			want: ErrInvalidResponse,
		},
		{
			name: "read host schema relabel",
			edit: func(envelope canonical.Map, response *wireResponse) {
				envelope["schemaDigest"] = hostSchemaDigest
				response.reencode = true
			},
			want: ErrInvalidResponse,
		},
		{
			name: "request ID relabel",
			edit: func(envelope canonical.Map, response *wireResponse) {
				envelope["requestId"] = validID("req", 99)
				response.reencode = true
			},
			want: ErrInvalidResponse,
		},
		{
			name: "outcome kind relabel",
			edit: func(envelope canonical.Map, response *wireResponse) {
				claimOutcomeFromEnvelope(envelope)["kind"] = "effect_dispatched"
				response.reencode = true
			},
			want: ErrInvalidResponse,
		},
		{
			name: "effect ID relabel",
			edit: func(envelope canonical.Map, response *wireResponse) {
				claimOutcomeFromEnvelope(envelope)["effectId"] = validID("effect", 99)
				response.reencode = true
			},
			want: ErrInvalidResponse,
		},
		{
			name: "fresh and replayed",
			edit: func(envelope canonical.Map, response *wireResponse) {
				claimResultFromEnvelope(envelope)["replayed"] = true
				response.reencode = true
			},
			want: ErrInvalidResponse,
		},
		{
			name: "nonfresh and nonreplayed",
			edit: func(envelope canonical.Map, response *wireResponse) {
				claimOutcomeFromEnvelope(envelope)["fresh"] = false
				response.reencode = true
			},
			want: ErrInvalidResponse,
		},
		{
			name: "extra result field",
			edit: func(envelope canonical.Map, response *wireResponse) {
				claimResultFromEnvelope(envelope)["unknown"] = true
				response.reencode = true
			},
			want: ErrInvalidResponse,
		},
		{
			name: "permit claims relabel",
			edit: func(envelope canonical.Map, response *wireResponse) {
				permit := claimPermitFromEnvelope(envelope)
				claims := permit["dispatchPermitClaims"].(canonical.Map)
				claims["deadline"] = uint64(1_900_000_060_001)
				response.reencode = true
			},
			want: ErrInvalidResponse,
		},
		{
			name: "provider request relabel",
			edit: func(envelope canonical.Map, response *wireResponse) {
				claimPermitFromEnvelope(envelope)["providerRequestId"] = nil
				response.reencode = true
			},
			want: ErrInvalidResponse,
		},
		{
			name: "command digest relabel",
			edit: func(envelope canonical.Map, response *wireResponse) {
				claimPermitFromEnvelope(envelope)["commandDigest"] = "sha256:" + strings.Repeat("9", 64)
				response.reencode = true
			},
			want: ErrInvalidResponse,
		},
		{
			name: "zero claimed event sequence",
			edit: func(envelope canonical.Map, response *wireResponse) {
				claimPermitFromEnvelope(envelope)["claimedEventSequence"] = int64(0)
				response.reencode = true
			},
			want: ErrInvalidResponse,
		},
		{
			name: "claimed sequence does not follow dispatch receipt",
			edit: func(envelope canonical.Map, response *wireResponse) {
				claimPermitFromEnvelope(envelope)["claimedEventSequence"] = int64(requestValue.ExpectedEventSequence)
				claimResultFromEnvelope(envelope)["version"] = int64(requestValue.ExpectedEventSequence)
				response.reencode = true
			},
			want: ErrInvalidResponse,
		},
		{
			name: "fresh version differs from claim",
			edit: func(envelope canonical.Map, response *wireResponse) {
				claimResultFromEnvelope(envelope)["version"] = uint64(14)
				response.reencode = true
			},
			want: ErrInvalidResponse,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requestID := validID("req", 1)
			endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requestBody := mustReadRequest(t, request)
				wantRequestSignature := requestMACFor(
					rootKey,
					testDispatchStartKeyID,
					"circulusd.state-dispatch-start-ingress.request.v1",
					testDispatchStartPath,
					requestBody,
				)
				if request.Header.Get(testSignatureHeader) != wantRequestSignature {
					t.Errorf("claim request signature = %q, want %q", request.Header.Get(testSignatureHeader), wantRequestSignature)
				}
				envelope := claimSuccessEnvelope(requestID, claimResultMap(requestValue, true, false, 13, 13))
				response := wireResponse{
					status: http.StatusOK, contentType: testDispatchStartType,
					keyID: testDispatchStartKeyID, envelope: envelope,
				}
				response.body = mustEncode(t, envelope)
				response.signature = responseMACFor(rootKey, testDispatchStartKeyID, requestID, requestBody, response.status, response.contentType, "circulusd.state-dispatch-start-ingress.response.v1", response.body)
				test.edit(envelope, &response)
				if response.signature == "read-domain" {
					response.signature = responseMAC(rootKey, testDispatchStartKeyID, requestID, requestBody, response.status, response.contentType, response.body)
				}
				if response.signature == "read-credential" {
					response.signature = responseMACFor(readRootKey, testKeyID, requestID, requestBody, response.status, response.contentType, "circulusd.state-dispatch-start-ingress.response.v1", response.body)
				}
				if response.reencode {
					response.body = mustEncode(t, response.envelope)
					response.resign = true
				}
				if response.resign {
					response.signature = responseMACFor(rootKey, response.keyID, requestID, requestBody, response.status, response.contentType, "circulusd.state-dispatch-start-ingress.response.v1", response.body)
				}
				writeWireResponse(writer, response)
			}))
			client := newClaimTestClient(t, endpoint, rootKey, func() (string, error) { return requestID, nil }, time.Second)
			_, err := client.ClaimDispatchStart(context.Background(), requestValue)
			if !errors.Is(err, test.want) {
				t.Fatalf("ClaimDispatchStart() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestClaimDispatchStartDisablesRedirects(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x35}, 32)
	var redirected atomic.Int64
	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/escaped" {
			redirected.Add(1)
			writer.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(writer, request, "/escaped", http.StatusTemporaryRedirect)
	}))
	client := newClaimTestClient(t, endpoint, rootKey, func() (string, error) { return validID("req", 1), nil }, time.Second)
	_, err := client.ClaimDispatchStart(context.Background(), validClaimDispatchStartRequest())
	if !errors.Is(err, ErrTransport) || redirected.Load() != 0 {
		t.Fatalf("ClaimDispatchStart() error = %v, redirected requests = %d", err, redirected.Load())
	}
}

type goldenFixture struct {
	Protocol        string `json:"protocol"`
	Major           int64  `json:"major"`
	Minor           int64  `json:"minor"`
	SchemaDigest    string `json:"schemaDigest"`
	Method          string `json:"method"`
	Path            string `json:"path"`
	ContentType     string `json:"contentType"`
	KeyID           string `json:"keyId"`
	RootKeyHex      string `json:"rootKeyHex"`
	RequestCBORHex  string `json:"requestCborHex"`
	RequestMACHex   string `json:"requestMacHex"`
	ResponseStatus  int    `json:"responseStatus"`
	ResponseCBORHex string `json:"responseCborHex"`
	ResponseMACHex  string `json:"responseMacHex"`
	Request         struct {
		RequestID                       string `json:"requestId"`
		SentAtUnixMS                    int64  `json:"sentAtUnixMs"`
		TenantID                        string `json:"tenantId"`
		ActorSubjectID                  string `json:"actorSubjectId"`
		SessionID                       string `json:"sessionId"`
		ExpectedAuthorizationGeneration int64  `json:"expectedAuthorizationGeneration"`
		AfterSequence                   int64  `json:"afterSequence"`
		Limit                           int64  `json:"limit"`
	} `json:"request"`
}

func TestConfigExportsOnlyBoundedProductionInputs(t *testing.T) {
	typeOfConfig := reflect.TypeOf(Config{})
	want := []string{"Endpoint", "KeyID", "RootKey", "DispatchStartKeyID", "DispatchStartRootKey", "Timeout"}
	if typeOfConfig.NumField() != len(want) {
		t.Fatalf("Config fields = %d, want %d (%v)", typeOfConfig.NumField(), len(want), want)
	}
	for index, name := range want {
		field := typeOfConfig.Field(index)
		if field.Name != name || field.PkgPath != "" {
			t.Errorf("Config field %d = %s (PkgPath %q), want exported %s", index, field.Name, field.PkgPath, name)
		}
	}
}

func TestNewAcceptsPinnedCelldLoopbackTCPEndpoint(t *testing.T) {
	for _, endpoint := range []string{"http://127.0.0.1:8080", "http://[::1]:8080"} {
		t.Run(endpoint, func(t *testing.T) {
			rootKey := bytes.Repeat([]byte{0x11}, 32)
			client, err := New(Config{
				Endpoint: endpoint,
				KeyID:    testKeyID,
				RootKey:  rootKey,
				Timeout:  time.Second,
			})
			if err != nil {
				t.Fatalf("New(celld TCP endpoint) error = %v", err)
			}
			client.Close()
		})
	}
}

func TestReadSessionEventsUsesIPv6LoopbackWhenAvailable(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	rootKey := bytes.Repeat([]byte{0x12}, 32)
	endpoint := startHTTPServer(t, listener, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		host, _, splitErr := net.SplitHostPort(request.RemoteAddr)
		remoteIP := net.ParseIP(host)
		if splitErr != nil || remoteIP == nil || !remoteIP.IsLoopback() || remoteIP.To4() != nil {
			t.Errorf("remote address = %q, want IPv6 loopback", request.RemoteAddr)
		}
		requestBody := mustReadRequest(t, request)
		requestID := requestIDFromBody(t, requestBody)
		body := mustEncode(t, successEnvelope(requestID, canonical.Map{"transport": "tcp6"}))
		writeWireResponse(writer, wireResponse{
			status: http.StatusOK, contentType: testIngressContentType, keyID: testKeyID,
			signature: responseMAC(rootKey, testKeyID, requestID, requestBody, http.StatusOK, testIngressContentType, body),
			body:      body,
		})
	}))
	client := newTestClient(t, endpoint, rootKey, func() (string, error) { return validID("req", 2), nil }, time.Second)
	result, err := client.ReadSessionEvents(context.Background(), validRequest(2))
	if err != nil {
		t.Fatalf("ReadSessionEvents() error = %v", err)
	}
	resultMap, ok := result.(canonical.Map)
	if !ok || resultMap["transport"] != "tcp6" {
		t.Fatalf("result = %#v, want authenticated tcp6 response", result)
	}
}

func TestReadSessionEventsMatchesCrossLanguageGoldenAndSnapshotsKey(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "packages", "protocol-types", "fixtures", "state-app-ingress-v1alpha1.json")
	contents, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}
	var fixture goldenFixture
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatalf("decode golden fixture: %v", err)
	}
	rootKey, err := hex.DecodeString(fixture.RootKeyHex)
	if err != nil {
		t.Fatalf("decode root key: %v", err)
	}
	wantRequestBody, err := hex.DecodeString(fixture.RequestCBORHex)
	if err != nil {
		t.Fatalf("decode request CBOR: %v", err)
	}
	wantResponseBody, err := hex.DecodeString(fixture.ResponseCBORHex)
	if err != nil {
		t.Fatalf("decode response CBOR: %v", err)
	}

	var endpoint string
	endpoint = startLoopbackHTTPServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		if request.Method != fixture.Method || request.URL.Path != fixture.Path || request.URL.RawQuery != "" {
			t.Errorf("request target = %s %s, want %s %s", request.Method, request.URL.RequestURI(), fixture.Method, fixture.Path)
		}
		if request.Host != strings.TrimPrefix(endpoint, "http://") {
			t.Errorf("request Host = %q, want pinned endpoint authority", request.Host)
		}
		if got := request.Header.Values("Content-Type"); len(got) != 1 || got[0] != fixture.ContentType {
			t.Errorf("Content-Type = %q", got)
		}
		if got := request.Header.Values(testKeyHeader); len(got) != 1 || got[0] != fixture.KeyID {
			t.Errorf("key header = %q", got)
		}
		if got := request.Header.Values(testSignatureHeader); len(got) != 1 || got[0] != fixture.RequestMACHex {
			t.Errorf("signature header = %q", got)
		}
		if request.Header.Get("Content-Encoding") != "" {
			t.Errorf("unexpected Content-Encoding = %q", request.Header.Get("Content-Encoding"))
		}
		if request.ContentLength != int64(len(wantRequestBody)) {
			t.Errorf("Content-Length = %d, want %d", request.ContentLength, len(wantRequestBody))
		}
		if !bytes.Equal(body, wantRequestBody) {
			t.Errorf("request CBOR = %x\nwant         = %x", body, wantRequestBody)
		}
		response.Header().Set("Content-Type", fixture.ContentType)
		response.Header().Set(testKeyHeader, fixture.KeyID)
		response.Header().Set(testSignatureHeader, fixture.ResponseMACHex)
		response.WriteHeader(fixture.ResponseStatus)
		_, _ = response.Write(wantResponseBody)
	}))

	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	client, err := newWithSources(Config{
		Endpoint: endpoint,
		KeyID:    fixture.KeyID,
		RootKey:  rootKey,
		Timeout:  time.Second,
	}, clientSources{
		clock: func() time.Time {
			return time.UnixMilli(fixture.Request.SentAtUnixMS)
		},
		newRequestID: func() (string, error) { return fixture.Request.RequestID, nil },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(client.Close)
	clear(rootKey)

	result, err := client.ReadSessionEvents(context.Background(), Request{
		TenantID:                        fixture.Request.TenantID,
		ActorSubjectID:                  fixture.Request.ActorSubjectID,
		SessionID:                       fixture.Request.SessionID,
		ExpectedAuthorizationGeneration: uint64(fixture.Request.ExpectedAuthorizationGeneration),
		AfterSequence:                   uint64(fixture.Request.AfterSequence),
		Limit:                           int(fixture.Request.Limit),
	})
	if err != nil {
		t.Fatalf("ReadSessionEvents() error = %v", err)
	}
	resultMap, ok := result.(canonical.Map)
	if !ok {
		t.Fatalf("result type = %T, want canonical.Map", result)
	}
	snapshot, ok := resultMap["snapshot"].(canonical.Map)
	if !ok || snapshot["sessionId"] != fixture.Request.SessionID || snapshot["lastEventSequence"] != int64(0) {
		t.Fatalf("snapshot = %#v", resultMap["snapshot"])
	}
	if events, ok := resultMap["events"].(canonical.Array); !ok || len(events) != 0 {
		t.Fatalf("events = %#v", resultMap["events"])
	}
	if resultMap["injected"] != nil {
		t.Fatal("unexpected result field")
	}
}

func TestReadSessionEventsRejectsUnauthenticatedOrMalformedResponses(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x31}, 32)
	tests := []struct {
		name string
		edit func(*wireResponse)
		want error
	}{
		{
			name: "unsigned",
			edit: func(response *wireResponse) {
				response.status = http.StatusUnauthorized
				response.keyID = ""
				response.signature = ""
				response.body = nil
			},
			want: ErrUnauthenticatedResponse,
		},
		{
			name: "tampered body",
			edit: func(response *wireResponse) {
				response.body[len(response.body)-1] ^= 1
			},
			want: ErrUnauthenticatedResponse,
		},
		{
			name: "tampered status",
			edit: func(response *wireResponse) { response.status = http.StatusBadGateway },
			want: ErrUnauthenticatedResponse,
		},
		{
			name: "tampered content type",
			edit: func(response *wireResponse) { response.contentType = "application/cbor" },
			want: ErrUnauthenticatedResponse,
		},
		{
			name: "response bound to another request digest",
			edit: func(response *wireResponse) { response.wrongRequestBinding = true },
			want: ErrUnauthenticatedResponse,
		},
		{
			name: "wrong key id",
			edit: func(response *wireResponse) { response.keyID = "state-other-1" },
			want: ErrUnauthenticatedResponse,
		},
		{
			name: "invalid signature hex",
			edit: func(response *wireResponse) { response.signature = strings.Repeat("G", 64) },
			want: ErrUnauthenticatedResponse,
		},
		{
			name: "duplicate content type",
			edit: func(response *wireResponse) { response.duplicateHeader = "Content-Type" },
			want: ErrUnauthenticatedResponse,
		},
		{
			name: "duplicate key id",
			edit: func(response *wireResponse) { response.duplicateHeader = testKeyHeader },
			want: ErrUnauthenticatedResponse,
		},
		{
			name: "duplicate signature",
			edit: func(response *wireResponse) { response.duplicateHeader = testSignatureHeader },
			want: ErrUnauthenticatedResponse,
		},
		{
			name: "content encoding",
			edit: func(response *wireResponse) { response.contentEncoding = "gzip" },
			want: ErrUnauthenticatedResponse,
		},
		{
			name: "signed noncanonical CBOR",
			edit: func(response *wireResponse) {
				response.body = append(response.body, 0xf6)
				response.resign = true
			},
			want: ErrInvalidResponse,
		},
		{
			name: "signed unknown envelope field",
			edit: func(response *wireResponse) {
				response.envelope["unknown"] = int64(1)
				response.reencode = true
			},
			want: ErrInvalidResponse,
		},
		{
			name: "signed mismatched request id",
			edit: func(response *wireResponse) {
				response.envelope["requestId"] = validID("req", 999)
				response.reencode = true
			},
			want: ErrInvalidResponse,
		},
		{
			name: "oversized signed body",
			edit: func(response *wireResponse) {
				response.body = bytes.Repeat([]byte{0xf6}, maximumResponseBytes+1)
				response.resign = true
			},
			want: ErrInvalidResponse,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requestBody := mustReadRequest(t, request)
				requestID := requestIDFromBody(t, requestBody)
				envelope := successEnvelope(requestID, canonical.Map{"token": requestID})
				response := wireResponse{
					status: http.StatusOK, contentType: testIngressContentType,
					keyID: testKeyID, envelope: envelope,
				}
				response.body = mustEncode(t, envelope)
				response.signature = responseMAC(rootKey, testKeyID, requestID, requestBody, response.status, response.contentType, response.body)
				test.edit(&response)
				if response.reencode {
					response.body = mustEncode(t, response.envelope)
					response.resign = true
				}
				if response.resign {
					response.signature = responseMAC(rootKey, response.keyID, requestID, requestBody, response.status, response.contentType, response.body)
				}
				if response.wrongRequestBinding {
					otherRequestBody := append(append([]byte(nil), requestBody...), 0)
					response.signature = responseMAC(rootKey, response.keyID, requestID, otherRequestBody, response.status, response.contentType, response.body)
				}
				writeWireResponse(writer, response)
			}))
			client := newTestClient(t, endpoint, rootKey, func() (string, error) { return validID("req", 1), nil }, time.Second)
			_, err := client.ReadSessionEvents(context.Background(), validRequest(1))
			if !errors.Is(err, test.want) {
				t.Fatalf("ReadSessionEvents() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestReadSessionEventsValidatesSignedErrorEnvelopeAndStatus(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x44}, 32)
	tests := []struct {
		name           string
		status         int
		payload        canonical.Map
		wantRemoteCode string
	}{
		{
			name:   "known safe host error",
			status: http.StatusOK,
			payload: canonical.Map{"ok": false, "error": canonical.Map{
				"code": "STALE_GENERATION", "message": "The supplied generation is stale.",
			}},
			wantRemoteCode: "STALE_GENERATION",
		},
		{
			name:   "authenticated invalid argument",
			status: http.StatusBadRequest,
			payload: canonical.Map{"ok": false, "error": canonical.Map{
				"code": "INVALID_ARGUMENT", "message": "The RPC request is invalid.",
			}},
			wantRemoteCode: "INVALID_ARGUMENT",
		},
		{
			name:   "authenticated internal failure",
			status: http.StatusInternalServerError,
			payload: canonical.Map{"ok": false, "error": canonical.Map{
				"code": "INTERNAL_ERROR", "message": "The operation could not be completed.",
			}},
			wantRemoteCode: "INTERNAL_ERROR",
		},
		{
			name:   "authenticated upstream exhaustion",
			status: http.StatusBadGateway,
			payload: canonical.Map{"ok": false, "error": canonical.Map{
				"code": "RESOURCE_EXHAUSTED", "message": "The RPC response exceeds its operation limit.",
			}},
			wantRemoteCode: "RESOURCE_EXHAUSTED",
		},
		{
			name:   "unknown code",
			status: http.StatusOK,
			payload: canonical.Map{"ok": false, "error": canonical.Map{
				"code": "SECRET_BACKEND_DETAIL", "message": "secret",
			}},
		},
		{
			name:   "wrong safe message",
			status: http.StatusOK,
			payload: canonical.Map{"ok": false, "error": canonical.Map{
				"code": "STALE_GENERATION", "message": "database address leaked",
			}},
		},
		{
			name:   "invalid failure status mapping",
			status: http.StatusBadRequest,
			payload: canonical.Map{"ok": false, "error": canonical.Map{
				"code": "INTERNAL_ERROR", "message": "The operation could not be completed.",
			}},
		},
		{
			name:    "success with failure status",
			status:  http.StatusBadGateway,
			payload: canonical.Map{"ok": true, "result": canonical.Map{}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requestBody := mustReadRequest(t, request)
				requestID := requestIDFromBody(t, requestBody)
				envelope := baseEnvelope(requestID, test.payload)
				body := mustEncode(t, envelope)
				writeWireResponse(writer, wireResponse{
					status: test.status, contentType: testIngressContentType, keyID: testKeyID,
					signature: responseMAC(rootKey, testKeyID, requestID, requestBody, test.status, testIngressContentType, body),
					body:      body,
				})
			}))
			client := newTestClient(t, endpoint, rootKey, func() (string, error) { return validID("req", 1), nil }, time.Second)
			_, err := client.ReadSessionEvents(context.Background(), validRequest(1))
			if test.wantRemoteCode != "" {
				var remote *RemoteError
				if !errors.As(err, &remote) || remote.Code != test.wantRemoteCode || remote.Status != test.status ||
					!errors.Is(err, ErrRemote) {
					t.Fatalf("ReadSessionEvents() error = %#v, want safe RemoteError", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("ReadSessionEvents() error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestReadSessionEventsBoundsTransportAndDisablesRedirects(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x55}, 32)
	t.Run("truncated body", func(t *testing.T) {
		endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			requestBody := mustReadRequest(t, request)
			requestID := requestIDFromBody(t, requestBody)
			body := mustEncode(t, successEnvelope(requestID, canonical.Map{}))
			writer.Header().Set("Content-Type", testIngressContentType)
			writer.Header().Set(testKeyHeader, testKeyID)
			writer.Header().Set(testSignatureHeader, responseMAC(rootKey, testKeyID, requestID, requestBody, 200, testIngressContentType, body))
			writer.Header().Set("Content-Length", strconv.Itoa(len(body)+7))
			_, _ = writer.Write(body)
		}))
		client := newTestClient(t, endpoint, rootKey, func() (string, error) { return validID("req", 2), nil }, time.Second)
		_, err := client.ReadSessionEvents(context.Background(), validRequest(1))
		if !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("ReadSessionEvents() error = %v, want ErrInvalidResponse", err)
		}
	})

	t.Run("response headers bounded", func(t *testing.T) {
		endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("X-Fill", strings.Repeat("x", maximumResponseHeaderBytes+1))
			writer.WriteHeader(http.StatusOK)
		}))
		client := newTestClient(t, endpoint, rootKey, func() (string, error) { return validID("req", 3), nil }, time.Second)
		_, err := client.ReadSessionEvents(context.Background(), validRequest(1))
		if !errors.Is(err, ErrTransport) {
			t.Fatalf("ReadSessionEvents() error = %v, want ErrTransport", err)
		}
	})

	t.Run("redirect disabled", func(t *testing.T) {
		var redirected atomic.Int64
		endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/escaped" {
				redirected.Add(1)
				writer.WriteHeader(http.StatusOK)
				return
			}
			http.Redirect(writer, request, "/escaped", http.StatusTemporaryRedirect)
		}))
		client := newTestClient(t, endpoint, rootKey, func() (string, error) { return validID("req", 4), nil }, time.Second)
		_, err := client.ReadSessionEvents(context.Background(), validRequest(1))
		if !errors.Is(err, ErrTransport) || redirected.Load() != 0 {
			t.Fatalf("ReadSessionEvents() error = %v, redirected requests = %d", err, redirected.Load())
		}
	})
}

func TestReadSessionEventsHonorsCancellationAndConfiguredDeadline(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x66}, 32)
	var calls atomic.Int64
	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		<-request.Context().Done()
		writer.WriteHeader(http.StatusGatewayTimeout)
	}))

	client := newTestClient(t, endpoint, rootKey, func() (string, error) { return validID("req", 5), nil }, 40*time.Millisecond)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.ReadSessionEvents(canceled, validRequest(1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ReadSessionEvents() error = %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("pre-canceled request reached server %d times", got)
	}

	started := time.Now()
	_, err := client.ReadSessionEvents(context.Background(), validRequest(1))
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrTransport) {
		t.Fatalf("timed ReadSessionEvents() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("configured timeout took %s", elapsed)
	}
}

func TestQueuedSourceWaiterExpiresWithoutInvokingSource(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x68}, 32)
	var calls atomic.Uint64
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	client, err := newWithSources(Config{
		Endpoint: "http://127.0.0.1:1", KeyID: testKeyID,
		RootKey: rootKey, Timeout: time.Second,
	}, clientSources{
		clock: func() time.Time { return time.UnixMilli(1_700_000_000_000) },
		newRequestID: func() (string, error) {
			call := calls.Add(1)
			if call == 1 {
				close(firstEntered)
				<-releaseFirst
			}
			return validID("req", call), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	firstDone := make(chan error, 1)
	go func() {
		_, readErr := client.ReadSessionEvents(context.Background(), validRequest(1))
		firstDone <- readErr
	}()
	<-firstEntered

	secondContext, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	secondDone := make(chan error, 1)
	go func() {
		_, readErr := client.ReadSessionEvents(secondContext, validRequest(2))
		secondDone <- readErr
	}()
	select {
	case readErr := <-secondDone:
		if !errors.Is(readErr, context.DeadlineExceeded) {
			t.Errorf("queued read error = %v, want context deadline", readErr)
		}
	case <-time.After(200 * time.Millisecond):
		close(releaseFirst)
		<-firstDone
		t.Fatal("queued read did not honor its deadline while source gate was held")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("source calls = %d, want 1", got)
	}
	close(releaseFirst)
	if readErr := <-firstDone; !errors.Is(readErr, ErrTransport) {
		t.Fatalf("first read error = %v, want transport failure", readErr)
	}
}

func TestCloseLinearizesBeforePausedReadCanDial(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x69}, 32)
	var serverCalls atomic.Int64
	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		serverCalls.Add(1)
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	sourceEntered := make(chan struct{})
	releaseSource := make(chan struct{})
	client, err := newWithSources(Config{
		Endpoint: endpoint, KeyID: testKeyID, RootKey: rootKey, Timeout: time.Second,
	}, clientSources{
		clock: func() time.Time { return time.UnixMilli(1_700_000_000_000) },
		newRequestID: func() (string, error) {
			close(sourceEntered)
			<-releaseSource
			return validID("req", 1), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, readErr := client.ReadSessionEvents(context.Background(), validRequest(1))
		readDone <- readErr
	}()
	<-sourceEntered
	closeDone := make(chan struct{})
	go func() {
		client.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
		close(releaseSource)
		t.Fatal("Close returned before the registered paused read exited")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseSource)
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close did not join the paused read")
	}
	if readErr := <-readDone; !errors.Is(readErr, ErrClientClosed) {
		t.Fatalf("paused read error = %v, want ErrClientClosed", readErr)
	}
	if got := serverCalls.Load(); got != 0 {
		t.Fatalf("server calls after Close linearized = %d, want 0", got)
	}
}

func TestCloseCancelsAndJoinsActiveHTTPRead(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x6a}, 32)
	handlerEntered := make(chan struct{})
	handlerCanceled := make(chan struct{})
	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestBody := mustReadRequest(t, request)
		requestID := requestIDFromBody(t, requestBody)
		body := mustEncode(t, successEnvelope(requestID, canonical.Map{}))
		writer.Header().Set("Content-Type", testIngressContentType)
		writer.Header().Set(testKeyHeader, testKeyID)
		writer.Header().Set(testSignatureHeader, responseMAC(rootKey, testKeyID, requestID, requestBody, 200, testIngressContentType, body))
		writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		close(handlerEntered)
		<-request.Context().Done()
		close(handlerCanceled)
	}))
	client := newTestClient(t, endpoint, rootKey, func() (string, error) { return validID("req", 1), nil }, time.Second)
	readDone := make(chan error, 1)
	go func() {
		_, readErr := client.ReadSessionEvents(context.Background(), validRequest(1))
		readDone <- readErr
	}()
	<-handlerEntered
	client.Close()
	select {
	case <-handlerCanceled:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the active HTTP request")
	}
	select {
	case readErr := <-readDone:
		if !errors.Is(readErr, ErrClientClosed) {
			t.Fatalf("active read error = %v, want ErrClientClosed", readErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Close returned without joining the active read")
	}
	if _, err := client.ReadSessionEvents(context.Background(), validRequest(1)); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("read after Close error = %v, want ErrClientClosed", err)
	}
}

func TestCloseZeroizesSnapshottedIngressKeys(t *testing.T) {
	readRootKey := bytes.Repeat([]byte{0x6c}, 32)
	dispatchStartRootKey := bytes.Repeat([]byte{0x7c}, 32)
	client, err := New(Config{
		Endpoint: "http://127.0.0.1:1", KeyID: testKeyID, RootKey: readRootKey,
		DispatchStartKeyID: testDispatchStartKeyID, DispatchStartRootKey: dispatchStartRootKey,
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	readRequestKey := client.requestKey
	readResponseKey := client.responseKey
	dispatchRequestKey := client.dispatchStartRequestKey
	dispatchResponseKey := client.dispatchStartResponseKey
	clear(readRootKey)
	clear(dispatchStartRootKey)
	if client.requestKey != readRequestKey || client.responseKey != readResponseKey ||
		client.dispatchStartRequestKey != dispatchRequestKey ||
		client.dispatchStartResponseKey != dispatchResponseKey {
		t.Fatal("client keys changed when caller-owned root-key buffers were cleared")
	}

	client.Close()
	zero := [sha256.Size]byte{}
	if client.requestKey != zero || client.responseKey != zero ||
		client.dispatchStartRequestKey != zero || client.dispatchStartResponseKey != zero {
		t.Fatal("Close did not zeroize all derived ingress keys")
	}
}

func TestCloseJoinsActiveClaimBeforeZeroizingKeys(t *testing.T) {
	readRootKey := bytes.Repeat([]byte{0x6d}, 32)
	dispatchStartRootKey := bytes.Repeat([]byte{0x7d}, 32)
	sourceEntered := make(chan struct{})
	releaseSource := make(chan struct{})
	client, err := newWithSources(Config{
		Endpoint: "http://127.0.0.1:1", KeyID: testKeyID, RootKey: readRootKey,
		DispatchStartKeyID: testDispatchStartKeyID, DispatchStartRootKey: dispatchStartRootKey,
		Timeout: time.Second,
	}, clientSources{
		clock: func() time.Time { return time.UnixMilli(1_700_000_000_000) },
		newRequestID: func() (string, error) {
			close(sourceEntered)
			<-releaseSource
			return validID("req", 1), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	claimDone := make(chan error, 1)
	go func() {
		_, claimErr := client.ClaimDispatchStart(
			context.Background(),
			validClaimDispatchStartRequest(),
		)
		claimDone <- claimErr
	}()
	<-sourceEntered
	closeDone := make(chan struct{})
	go func() {
		client.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
		close(releaseSource)
		t.Fatal("Close returned before the registered claim exited")
	case <-time.After(20 * time.Millisecond):
	}
	zero := [sha256.Size]byte{}
	if client.dispatchStartRequestKey == zero {
		close(releaseSource)
		t.Fatal("Close zeroized a claim key while an active claim still held it")
	}
	close(releaseSource)
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close did not join the active claim")
	}
	if claimErr := <-claimDone; !errors.Is(claimErr, ErrClientClosed) {
		t.Fatalf("active claim error = %v, want ErrClientClosed", claimErr)
	}
	if client.requestKey != zero || client.responseKey != zero ||
		client.dispatchStartRequestKey != zero || client.dispatchStartResponseKey != zero {
		t.Fatal("Close did not zeroize keys after joining the active claim")
	}
}

func TestConcurrentCloseIsIdempotentAndRejectsRacingReads(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x6b}, 32)
	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	client := newTestClient(t, endpoint, rootKey, func() (string, error) { return validID("req", 1), nil }, time.Second)
	const readers = 32
	const closers = 16
	results := make(chan error, readers)
	var group sync.WaitGroup
	for index := 0; index < readers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, readErr := client.ReadSessionEvents(context.Background(), validRequest(1))
			results <- readErr
		}()
	}
	for index := 0; index < closers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			client.Close()
		}()
	}
	group.Wait()
	close(results)
	for readErr := range results {
		if !errors.Is(readErr, ErrClientClosed) {
			t.Errorf("racing read error = %v, want ErrClientClosed", readErr)
		}
	}
	client.Close()
}

func TestZeroValueClientCloseDoesNotPanic(t *testing.T) {
	(&Client{}).Close()
}

func TestReadSessionEventsKeepsSixtyFourConcurrentRequestsIsolated(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x77}, 32)
	serverRootKey := append([]byte(nil), rootKey...)
	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestBody := mustReadRequest(t, request)
		requestID := requestIDFromBody(t, requestBody)
		if requestID[len(requestID)-1]%2 == 0 {
			time.Sleep(time.Millisecond)
		}
		body := mustEncode(t, successEnvelope(requestID, canonical.Map{"token": requestID}))
		writeWireResponse(writer, wireResponse{
			status: 200, contentType: testIngressContentType, keyID: testKeyID,
			signature: responseMAC(serverRootKey, testKeyID, requestID, requestBody, 200, testIngressContentType, body),
			body:      body,
		})
	}))
	var next atomic.Uint64
	var activeSourceCalls atomic.Int64
	var overlappingSourceCalls atomic.Bool
	useSource := func() {
		if activeSourceCalls.Add(1) != 1 {
			overlappingSourceCalls.Store(true)
		}
		time.Sleep(100 * time.Microsecond)
		activeSourceCalls.Add(-1)
	}
	client, err := newWithSources(Config{
		Endpoint: endpoint, KeyID: testKeyID, RootKey: rootKey, Timeout: 3 * time.Second,
	}, clientSources{
		clock: func() time.Time {
			useSource()
			return time.UnixMilli(1_700_000_000_000)
		},
		newRequestID: func() (string, error) {
			useSource()
			return validID("req", next.Add(1)), nil
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(client.Close)
	clear(rootKey)

	const count = 64
	results := make(chan error, count)
	var group sync.WaitGroup
	for index := 0; index < count; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := client.ReadSessionEvents(context.Background(), validRequest(1))
			if err != nil {
				results <- err
				return
			}
			resultMap, ok := result.(canonical.Map)
			token, tokenOK := resultMap["token"].(string)
			if !ok || !tokenOK || !strings.HasPrefix(token, "req_") {
				results <- fmt.Errorf("unexpected result %#v", result)
				return
			}
			results <- nil
		}()
	}
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Error(err)
		}
	}
	if got := next.Load(); got != count {
		t.Fatalf("request ID calls = %d, want %d", got, count)
	}
	if overlappingSourceCalls.Load() {
		t.Fatal("configured Clock or NewRequestID was called concurrently")
	}
}

func TestReadSessionEventsRejectsInvalidRequestBeforeDial(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x22}, 32)
	var generated atomic.Int64
	client, err := newWithSources(Config{
		Endpoint: "http://127.0.0.1:1", KeyID: testKeyID,
		RootKey: rootKey, Timeout: time.Second,
	}, clientSources{
		clock: time.Now,
		newRequestID: func() (string, error) {
			generated.Add(1)
			return validID("req", 1), nil
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(client.Close)
	if _, err := client.ReadSessionEvents(nil, validRequest(1)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil-context ReadSessionEvents() error = %v, want ErrInvalidRequest", err)
	}

	tests := []Request{
		{},
		func() Request { value := validRequest(1); value.TenantID = validID("subject", 1); return value }(),
		func() Request { value := validRequest(1); value.ActorSubjectID = validID("tenant", 1); return value }(),
		func() Request { value := validRequest(1); value.SessionID = "sess_not-base32"; return value }(),
		func() Request { value := validRequest(1); value.ExpectedAuthorizationGeneration = 0; return value }(),
		func() Request { value := validRequest(1); value.AfterSequence = 9_007_199_254_740_992; return value }(),
		func() Request { value := validRequest(1); value.Limit = 0; return value }(),
		func() Request { value := validRequest(1); value.Limit = 257; return value }(),
	}
	for index, request := range tests {
		if _, err := client.ReadSessionEvents(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("case %d error = %v, want ErrInvalidRequest", index, err)
		}
	}
	if generated.Load() != 0 {
		t.Fatalf("invalid requests generated %d request IDs", generated.Load())
	}

	badIDClient, err := newWithSources(Config{
		Endpoint: "http://127.0.0.1:1", KeyID: testKeyID,
		RootKey: rootKey, Timeout: time.Second,
	}, clientSources{
		clock: time.Now, newRequestID: func() (string, error) { return "req_invalid", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(badIDClient.Close)
	if _, err := badIDClient.ReadSessionEvents(context.Background(), validRequest(1)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid generated request ID error = %v", err)
	}

	generationError := errors.New("entropy unavailable")
	failedIDClient, err := newWithSources(Config{
		Endpoint: "http://127.0.0.1:1", KeyID: testKeyID,
		RootKey: rootKey, Timeout: time.Second,
	}, clientSources{
		clock: time.Now, newRequestID: func() (string, error) { return "", generationError },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(failedIDClient.Close)
	if _, err := failedIDClient.ReadSessionEvents(context.Background(), validRequest(1)); !errors.Is(err, generationError) || !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("request ID generation error = %v", err)
	}

	for _, clock := range []func() time.Time{
		func() time.Time { return time.UnixMilli(-1) },
		func() time.Time { return time.UnixMilli(int64(maximumSharedInteger) + 1) },
	} {
		clockClient, clockErr := newWithSources(Config{
			Endpoint: "http://127.0.0.1:1", KeyID: testKeyID,
			RootKey: rootKey, Timeout: time.Second,
		}, clientSources{
			clock: clock, newRequestID: func() (string, error) { return validID("req", 1), nil },
		})
		if clockErr != nil {
			t.Fatal(clockErr)
		}
		if _, readErr := clockClient.ReadSessionEvents(context.Background(), validRequest(1)); !errors.Is(readErr, ErrInvalidRequest) {
			t.Errorf("out-of-range clock error = %v, want ErrInvalidRequest", readErr)
		}
		clockClient.Close()
	}
}

func TestNewRejectsEndpointsOutsidePinnedCelldSurfaceAndInvalidSecrets(t *testing.T) {
	valid := Config{
		Endpoint: "http://127.0.0.1:8080", KeyID: testKeyID,
		RootKey: bytes.Repeat([]byte{0x11}, 32), Timeout: time.Second,
	}
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{name: "empty endpoint", edit: func(config *Config) { config.Endpoint = "" }},
		{name: "Unix endpoint", edit: func(config *Config) { config.Endpoint = "unix:///run/circulusd/state.sock" }},
		{name: "TLS endpoint", edit: func(config *Config) { config.Endpoint = "https://127.0.0.1:8080" }},
		{name: "hostname endpoint", edit: func(config *Config) { config.Endpoint = "http://localhost:8080" }},
		{name: "non-loopback endpoint", edit: func(config *Config) { config.Endpoint = "http://192.0.2.1:8080" }},
		{name: "mapped IPv6 loopback", edit: func(config *Config) { config.Endpoint = "http://[::ffff:127.0.0.1]:8080" }},
		{name: "missing port", edit: func(config *Config) { config.Endpoint = "http://127.0.0.1" }},
		{name: "zero port", edit: func(config *Config) { config.Endpoint = "http://127.0.0.1:0" }},
		{name: "noncanonical port", edit: func(config *Config) { config.Endpoint = "http://127.0.0.1:08080" }},
		{name: "root path", edit: func(config *Config) { config.Endpoint = "http://127.0.0.1:8080/" }},
		{name: "path", edit: func(config *Config) { config.Endpoint = "http://127.0.0.1:8080/base" }},
		{name: "encoded path", edit: func(config *Config) { config.Endpoint = "http://127.0.0.1:8080/%2e" }},
		{name: "userinfo", edit: func(config *Config) { config.Endpoint = "http://user@127.0.0.1:8080" }},
		{name: "query", edit: func(config *Config) { config.Endpoint += "?target=other" }},
		{name: "fragment", edit: func(config *Config) { config.Endpoint += "#other" }},
		{name: "empty fragment", edit: func(config *Config) { config.Endpoint += "#" }},
		{name: "NUL", edit: func(config *Config) { config.Endpoint = "http://127.0.0.1:8080/%00" }},
		{name: "control", edit: func(config *Config) { config.Endpoint += "\n" }},
		{name: "empty key id", edit: func(config *Config) { config.KeyID = "" }},
		{name: "invalid key id", edit: func(config *Config) { config.KeyID = "State Key" }},
		{name: "short root key", edit: func(config *Config) { config.RootKey = make([]byte, 31) }},
		{name: "long root key", edit: func(config *Config) { config.RootKey = make([]byte, 257) }},
		{name: "dispatch key without root", edit: func(config *Config) { config.DispatchStartKeyID = testDispatchStartKeyID }},
		{name: "dispatch root without key", edit: func(config *Config) { config.DispatchStartRootKey = bytes.Repeat([]byte{0x22}, 32) }},
		{name: "same dispatch key id", edit: func(config *Config) {
			config.DispatchStartKeyID = config.KeyID
			config.DispatchStartRootKey = bytes.Repeat([]byte{0x22}, 32)
		}},
		{name: "same dispatch root", edit: func(config *Config) {
			config.DispatchStartKeyID = testDispatchStartKeyID
			config.DispatchStartRootKey = append([]byte(nil), config.RootKey...)
		}},
		{name: "invalid dispatch key id", edit: func(config *Config) {
			config.DispatchStartKeyID = "State Dispatch"
			config.DispatchStartRootKey = bytes.Repeat([]byte{0x22}, 32)
		}},
		{name: "short dispatch root", edit: func(config *Config) {
			config.DispatchStartKeyID = testDispatchStartKeyID
			config.DispatchStartRootKey = make([]byte, 31)
		}},
		{name: "long dispatch root", edit: func(config *Config) {
			config.DispatchStartKeyID = testDispatchStartKeyID
			config.DispatchStartRootKey = make([]byte, 257)
		}},
		{name: "zero timeout", edit: func(config *Config) { config.Timeout = 0 }},
		{name: "negative timeout", edit: func(config *Config) { config.Timeout = -time.Second }},
		{name: "excessive timeout", edit: func(config *Config) { config.Timeout = 30*time.Second + time.Nanosecond }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			config.RootKey = append([]byte(nil), valid.RootKey...)
			test.edit(&config)
			client, err := New(config)
			if client != nil || !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New() = (%v, %v), want nil ErrInvalidConfig", client, err)
			}
		})
	}
}

type wireResponse struct {
	status              int
	contentType         string
	contentEncoding     string
	keyID               string
	signature           string
	body                []byte
	envelope            canonical.Map
	duplicateHeader     string
	reencode            bool
	resign              bool
	wrongRequestBinding bool
}

const testKeyID = "state-current-1"

func startLoopbackHTTPServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback TCP: %v", err)
	}
	return startHTTPServer(t, listener, handler)
}

func startHTTPServer(t *testing.T, listener net.Listener, handler http.Handler) string {
	t.Helper()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("serve loopback HTTP: %v", serveErr)
		}
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})
	return "http://" + listener.Addr().String()
}

func newTestClient(t *testing.T, endpoint string, rootKey []byte, newRequestID func() (string, error), timeout time.Duration) *Client {
	t.Helper()
	client, err := newWithSources(Config{
		Endpoint: endpoint, KeyID: testKeyID, RootKey: rootKey,
		Timeout: timeout,
	}, clientSources{
		clock: time.Now, newRequestID: newRequestID,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(client.Close)
	return client
}

func newClaimTestClient(
	t *testing.T,
	endpoint string,
	dispatchStartRootKey []byte,
	newRequestID func() (string, error),
	timeout time.Duration,
) *Client {
	t.Helper()
	client, err := newWithSources(Config{
		Endpoint: endpoint, KeyID: testKeyID,
		RootKey:            bytes.Repeat([]byte{0x10}, 32),
		DispatchStartKeyID: testDispatchStartKeyID, DispatchStartRootKey: dispatchStartRootKey,
		Timeout: timeout,
	}, clientSources{
		clock: time.Now, newRequestID: newRequestID,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(client.Close)
	return client
}

func validRequest(index uint64) Request {
	return Request{
		TenantID: validID("tenant", index), ActorSubjectID: validID("subject", index),
		SessionID: validID("sess", index), ExpectedAuthorizationGeneration: 1,
		AfterSequence: 0, Limit: 16,
	}
}

func validClaimDispatchStartRequest() ClaimDispatchStartRequest {
	requestDigest := "sha256:" + strings.Repeat("6", 64)
	providerRouteDigest := "sha256:" + strings.Repeat("7", 64)
	return ClaimDispatchStartRequest{
		TenantID: validID("tenant", 1), WorkspaceID: validID("ws", 1),
		SessionID: validID("sess", 1),
		CommandID: "claim-dispatch-start-1", ExpectedEventSequence: 12,
		TurnID: validID("turn", 1), EffectID: validID("effect", 1),
		InvocationID: validID("inv", 1), RequestDigest: requestDigest,
		Fence: DispatchStartFence{
			TurnLeaseGeneration: 4, PlacementGeneration: 5,
			SandboxGeneration: 6, AuthorizationGeneration: 7,
		},
		DispatchAttempt: 3, ProviderRequestID: validID("req", 70),
		ProviderRouteDigest: providerRouteDigest,
		DispatchPermitClaims: DispatchPermitClaims{
			TenantID: validID("tenant", 1), UserID: validID("subject", 1),
			SessionID: validID("sess", 1), TurnID: validID("turn", 1),
			EffectID: validID("effect", 1), InvocationID: validID("inv", 1),
			RequestDigest: requestDigest, Service: "executor", Operation: "process.spawn",
			ReplayPolicy: "idempotency-key", DispatchAttempt: 3,
			TurnLeaseGeneration: 4, PlacementGeneration: 5,
			SandboxGeneration: 6, AuthorizationGeneration: 7,
			ProviderRouteDigest: providerRouteDigest, DeadlineUnixMS: 1_900_000_060_000,
		},
		CommandDigest: "sha256:" + strings.Repeat("8", 64),
	}
}

func claimDispatchPermitClaimsMap(claims DispatchPermitClaims) canonical.Map {
	result := canonical.Map{
		"tenantId": claims.TenantID, "userId": claims.UserID,
		"sessionId": claims.SessionID, "turnId": claims.TurnID,
		"effectId": claims.EffectID, "invocationId": claims.InvocationID,
		"requestDigest": claims.RequestDigest, "service": claims.Service,
		"operation": claims.Operation, "replayPolicy": claims.ReplayPolicy,
		"dispatchAttempt":         int64(claims.DispatchAttempt),
		"turnLeaseGeneration":     int64(claims.TurnLeaseGeneration),
		"placementGeneration":     int64(claims.PlacementGeneration),
		"sandboxGeneration":       int64(claims.SandboxGeneration),
		"authorizationGeneration": int64(claims.AuthorizationGeneration),
		"providerRouteDigest":     claims.ProviderRouteDigest,
		"deadline":                int64(claims.DeadlineUnixMS),
	}
	if claims.ParentOperationID != "" {
		result["parentOperationId"] = claims.ParentOperationID
		result["ordinal"] = int64(claims.Ordinal)
	}
	return result
}

func claimResultMap(
	request ClaimDispatchStartRequest,
	fresh bool,
	replayed bool,
	version uint64,
	claimedEventSequence uint64,
) canonical.Map {
	var providerRequestID canonical.Value
	if request.ProviderRequestID != "" {
		providerRequestID = request.ProviderRequestID
	}
	return canonical.Map{
		"outcome": canonical.Map{
			"kind": "dispatch_start_claimed", "effectId": request.EffectID, "fresh": fresh,
			"startPermit": canonical.Map{
				"dispatchPermitClaims": claimDispatchPermitClaimsMap(request.DispatchPermitClaims),
				"providerRequestId":    providerRequestID,
				"commandDigest":        request.CommandDigest,
				"claimedEventSequence": claimedEventSequence,
			},
		},
		"version": version, "replayed": replayed,
	}
}

func claimSuccessEnvelope(requestID string, result canonical.Value) canonical.Map {
	return canonical.Map{
		"protocol": "circulus.v1alpha1", "major": int64(1), "minor": int64(0),
		"schemaDigest": "sha256:2b94724f102698a958e5d03593a9f49e1b50665045b22b831d3c0f3538558144",
		"requestId":    requestID,
		"payload":      canonical.Map{"ok": true, "result": result},
	}
}

func claimResultFromEnvelope(envelope canonical.Map) canonical.Map {
	payload := envelope["payload"].(canonical.Map)
	return payload["result"].(canonical.Map)
}

func claimOutcomeFromEnvelope(envelope canonical.Map) canonical.Map {
	return claimResultFromEnvelope(envelope)["outcome"].(canonical.Map)
}

func claimPermitFromEnvelope(envelope canonical.Map) canonical.Map {
	return claimOutcomeFromEnvelope(envelope)["startPermit"].(canonical.Map)
}

func validID(prefix string, index uint64) string {
	var entropy [16]byte
	binary.BigEndian.PutUint64(entropy[8:], index)
	return prefix + "_" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(entropy[:])
}

func mustReadRequest(t *testing.T, request *http.Request) []byte {
	t.Helper()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Errorf("read request: %v", err)
		return nil
	}
	return body
}

func requestIDFromBody(t *testing.T, body []byte) string {
	t.Helper()
	value, err := canonical.Decode(body, canonical.Options{MaxBytes: 4_096, MaxDepth: 2, MaxItems: 32})
	if err != nil {
		t.Errorf("decode request: %v", err)
		return "invalid-request"
	}
	record, ok := value.(canonical.Map)
	requestID, idOK := record["requestId"].(string)
	if !ok || !idOK {
		t.Errorf("request is not an envelope: %#v", value)
		return "invalid-request"
	}
	return requestID
}

func baseEnvelope(requestID string, payload canonical.Map) canonical.Map {
	return canonical.Map{
		"protocol": "circulus.v1alpha1", "major": int64(1), "minor": int64(0),
		"schemaDigest": "sha256:6d9260ac502780b0480ed359ac7a5c368ddb7baa0a2c5772f6a5bc89d5647fba",
		"requestId":    requestID, "payload": payload,
	}
}

func successEnvelope(requestID string, result canonical.Value) canonical.Map {
	return baseEnvelope(requestID, canonical.Map{"ok": true, "result": result})
}

func mustEncode(t *testing.T, value canonical.Value) []byte {
	t.Helper()
	encoded, err := canonical.Encode(value, canonical.Options{
		MaxBytes: maximumResponseBytes, MaxDepth: maximumResponseDepth, MaxItems: maximumResponseItems,
	})
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	return encoded
}

func writeWireResponse(writer http.ResponseWriter, response wireResponse) {
	if response.contentType != "" {
		writer.Header()["Content-Type"] = []string{response.contentType}
	}
	if response.keyID != "" {
		writer.Header()[testKeyHeader] = []string{response.keyID}
	}
	if response.signature != "" {
		writer.Header()[testSignatureHeader] = []string{response.signature}
	}
	if response.contentEncoding != "" {
		writer.Header().Set("Content-Encoding", response.contentEncoding)
	}
	if response.duplicateHeader != "" {
		writer.Header()[response.duplicateHeader] = append(writer.Header()[response.duplicateHeader], writer.Header().Get(response.duplicateHeader))
	}
	writer.WriteHeader(response.status)
	_, _ = writer.Write(response.body)
}

func responseMAC(rootKey []byte, keyID, requestID string, requestBody []byte, status int, contentType string, body []byte) string {
	return responseMACFor(rootKey, keyID, requestID, requestBody, status, contentType, "circulusd.state-ingress.response.v1", body)
}

func requestMACFor(rootKey []byte, keyID, domain, path string, body []byte) string {
	bodyDigest := sha256.Sum256(body)
	keyMAC := hmac.New(sha256.New, rootKey)
	_, _ = keyMAC.Write([]byte("circulusd.state-ingress.key.request.v1\x00"))
	requestKey := keyMAC.Sum(nil)
	parts := [][]byte{
		[]byte(domain), []byte(keyID), []byte(http.MethodPost), []byte(path), bodyDigest[:],
	}
	length := 0
	for _, part := range parts {
		length += 4 + len(part)
	}
	framed := make([]byte, 0, length)
	var prefix [4]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(prefix[:], uint32(len(part)))
		framed = append(framed, prefix[:]...)
		framed = append(framed, part...)
	}
	mac := hmac.New(sha256.New, requestKey)
	_, _ = mac.Write(framed)
	return hex.EncodeToString(mac.Sum(nil))
}

func responseMACFor(
	rootKey []byte,
	keyID string,
	requestID string,
	requestBody []byte,
	status int,
	contentType string,
	domain string,
	body []byte,
) string {
	requestDigest := sha256.Sum256(requestBody)
	bodyDigest := sha256.Sum256(body)
	keyMAC := hmac.New(sha256.New, rootKey)
	_, _ = keyMAC.Write([]byte("circulusd.state-ingress.key.response.v1\x00"))
	responseKey := keyMAC.Sum(nil)
	parts := [][]byte{
		[]byte(domain), []byte(keyID), []byte(requestID), requestDigest[:],
		[]byte(strconv.Itoa(status)), []byte(contentType), bodyDigest[:],
	}
	length := 0
	for _, part := range parts {
		length += 4 + len(part)
	}
	framed := make([]byte, 0, length)
	var prefix [4]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(prefix[:], uint32(len(part)))
		framed = append(framed, prefix[:]...)
		framed = append(framed, part...)
	}
	mac := hmac.New(sha256.New, responseKey)
	_, _ = mac.Write(framed)
	return hex.EncodeToString(mac.Sum(nil))
}
