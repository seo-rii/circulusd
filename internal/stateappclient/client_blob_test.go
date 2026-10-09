package stateappclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
)

type blobGoldenFixture struct {
	Protocol        string `json:"protocol"`
	SchemaDigest    string `json:"schemaDigest"`
	Method          string `json:"method"`
	Path            string `json:"path"`
	ContentType     string `json:"contentType"`
	KeyID           string `json:"keyId"`
	RootKeyHex      string `json:"rootKeyHex"`
	RequestCBORHex  string `json:"requestCborHex"`
	RequestMACHex   string `json:"requestMacHex"`
	ResponseStatus  int    `json:"responseStatus"`
	BlobHex         string `json:"blobHex"`
	ResponseCBORHex string `json:"responseCborHex"`
	ResponseMACHex  string `json:"responseMacHex"`
	Request         struct {
		RequestID                       string `json:"requestId"`
		SentAtUnixMS                    int64  `json:"sentAtUnixMs"`
		TenantID                        string `json:"tenantId"`
		ActorSubjectID                  string `json:"actorSubjectId"`
		SessionID                       string `json:"sessionId"`
		ExpectedAuthorizationGeneration int64  `json:"expectedAuthorizationGeneration"`
		Digest                          string `json:"digest"`
	} `json:"request"`
}

func TestReadSessionBlobMatchesCrossLanguageGolden(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "packages", "protocol-types", "fixtures", "state-app-blob-ingress-v1alpha1.json")
	contents, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}
	var fixture blobGoldenFixture
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatalf("decode golden fixture: %v", err)
	}
	if fixture.Protocol != blobIngressProtocol || fixture.SchemaDigest != blobIngressSchemaDigest ||
		fixture.Path != blobIngressPath || fixture.ContentType != blobIngressContentType {
		t.Fatalf("fixture wire identity = %+v, want the compiled blob ingress constants", fixture)
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
	wantBlob, err := hex.DecodeString(fixture.BlobHex)
	if err != nil {
		t.Fatalf("decode blob: %v", err)
	}
	blobDigest := sha256.Sum256(wantBlob)
	if "sha256:"+hex.EncodeToString(blobDigest[:]) != fixture.Request.Digest {
		t.Fatalf("fixture blob does not hash to %s", fixture.Request.Digest)
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
		if want := requestMACFor(rootKey, fixture.KeyID, blobRequestMACDomain, blobIngressPath, body); want != fixture.RequestMACHex {
			t.Errorf("fixture request MAC is not the blob-domain MAC of its own bytes")
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

	blob, err := client.ReadSessionBlob(context.Background(), BlobRequest{
		TenantID:                        fixture.Request.TenantID,
		ActorSubjectID:                  fixture.Request.ActorSubjectID,
		SessionID:                       fixture.Request.SessionID,
		ExpectedAuthorizationGeneration: uint64(fixture.Request.ExpectedAuthorizationGeneration),
		Digest:                          fixture.Request.Digest,
	})
	if err != nil {
		t.Fatalf("ReadSessionBlob() error = %v", err)
	}
	if blob.Digest != fixture.Request.Digest || !bytes.Equal(blob.Bytes, wantBlob) {
		t.Fatalf("ReadSessionBlob() = %+v, want digest %s and %d fixture bytes", blob, fixture.Request.Digest, len(wantBlob))
	}
}

func TestReadSessionBlobRejectsInvalidRequestBeforeDial(t *testing.T) {
	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("an invalid blob request must not be dialed")
	}))
	client := newTestClient(t, endpoint, bytes.Repeat([]byte{0x31}, 32), func() (string, error) { return validID("req", 1), nil }, time.Second)
	valid := validBlobRequest(1)
	tests := []struct {
		name string
		edit func(*BlobRequest)
	}{
		{name: "tenant", edit: func(request *BlobRequest) { request.TenantID = "tenant_invalid" }},
		{name: "actor", edit: func(request *BlobRequest) { request.ActorSubjectID = validID("tenant", 1) }},
		{name: "session", edit: func(request *BlobRequest) { request.SessionID = "" }},
		{name: "zero generation", edit: func(request *BlobRequest) { request.ExpectedAuthorizationGeneration = 0 }},
		{name: "generation beyond shared range", edit: func(request *BlobRequest) { request.ExpectedAuthorizationGeneration = maximumSharedInteger + 1 }},
		{name: "empty digest", edit: func(request *BlobRequest) { request.Digest = "" }},
		{name: "short digest", edit: func(request *BlobRequest) { request.Digest = "sha256:abc" }},
		{name: "uppercase digest", edit: func(request *BlobRequest) { request.Digest = "sha256:" + strings.Repeat("A", 64) }},
		{name: "zero digest", edit: func(request *BlobRequest) { request.Digest = "sha256:" + strings.Repeat("0", 64) }},
		{name: "unprefixed digest", edit: func(request *BlobRequest) { request.Digest = strings.Repeat("a", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.edit(&request)
			if _, err := client.ReadSessionBlob(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("ReadSessionBlob() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
	//nolint:staticcheck // the nil context is the condition under test.
	if _, err := client.ReadSessionBlob(nil, valid); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("ReadSessionBlob(nil ctx) error = %v, want ErrInvalidRequest", err)
	}
	var nilClient *Client
	if _, err := nilClient.ReadSessionBlob(context.Background(), valid); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil client ReadSessionBlob() error = %v, want ErrInvalidConfig", err)
	}
}

func TestReadSessionBlobValidatesHydratedResultAndNull(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x33}, 32)
	payload := []byte("hydrated checkpoint payload bytes")
	payloadDigest := sha256.Sum256(payload)
	digest := "sha256:" + hex.EncodeToString(payloadDigest[:])
	maximumPayload := bytes.Repeat([]byte{0x5a}, maximumBlobBytes)
	maximumDigestSum := sha256.Sum256(maximumPayload)
	maximumDigest := "sha256:" + hex.EncodeToString(maximumDigestSum[:])
	hydrated := func(bytesValue []byte, digestValue string) canonical.Map {
		return canonical.Map{
			"digest": digestValue, "encodedBytes": int64(len(bytesValue)), "bytes": canonical.Bytes(bytesValue),
		}
	}

	tests := []struct {
		name          string
		requestDigest string
		result        canonical.Value
		oversizedBody bool
		wantBytes     []byte
		want          error
	}{
		{name: "hydrated", requestDigest: digest, result: hydrated(payload, digest), wantBytes: payload},
		{name: "maximum blob", requestDigest: maximumDigest, result: hydrated(maximumPayload, maximumDigest), wantBytes: maximumPayload},
		{name: "null when unreferenced", requestDigest: digest, result: nil, want: ErrBlobNotReferenced},
		{
			name: "echoes another digest", requestDigest: digest,
			result: hydrated(payload, "sha256:"+strings.Repeat("1", 64)), want: ErrInvalidResponse,
		},
		{
			name: "misdeclares its length", requestDigest: digest,
			result: canonical.Map{"digest": digest, "encodedBytes": int64(len(payload) + 1), "bytes": canonical.Bytes(payload)},
			want:   ErrInvalidResponse,
		},
		{
			name: "bytes do not hash to the digest", requestDigest: digest,
			result: hydrated(bytes.Repeat([]byte{0}, len(payload)), digest), want: ErrInvalidResponse,
		},
		{
			name: "extra field", requestDigest: digest,
			result: canonical.Map{"digest": digest, "encodedBytes": int64(len(payload)), "bytes": canonical.Bytes(payload), "encoding": "cbor"},
			want:   ErrInvalidResponse,
		},
		{
			name: "missing field", requestDigest: digest,
			result: canonical.Map{"digest": digest, "bytes": canonical.Bytes(payload)}, want: ErrInvalidResponse,
		},
		{
			name: "bytes as text", requestDigest: digest,
			result: canonical.Map{"digest": digest, "encodedBytes": int64(len(payload)), "bytes": string(payload)},
			want:   ErrInvalidResponse,
		},
		{
			name: "empty bytes", requestDigest: digest,
			result: canonical.Map{"digest": digest, "encodedBytes": int64(0), "bytes": canonical.Bytes{}},
			want:   ErrInvalidResponse,
		},
		{
			name: "length as text", requestDigest: digest,
			result: canonical.Map{"digest": digest, "encodedBytes": "33", "bytes": canonical.Bytes(payload)},
			want:   ErrInvalidResponse,
		},
		{name: "non-object result", requestDigest: digest, result: int64(7), want: ErrInvalidResponse},
		{
			name: "exceeds the blob bound", requestDigest: digest,
			result: hydrated(bytes.Repeat([]byte{0x5a}, maximumBlobBytes+1), digest), want: ErrInvalidResponse,
		},
		{
			name: "exceeds the response bound", requestDigest: digest,
			result: hydrated(payload, digest), oversizedBody: true, want: ErrInvalidResponse,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requestBody := mustReadRequest(t, request)
				requestID := requestIDFromBody(t, requestBody)
				if request.URL.Path != blobIngressPath || request.Header.Get("Content-Type") != blobIngressContentType {
					t.Errorf("request target = %s %s", request.URL.Path, request.Header.Get("Content-Type"))
				}
				if want := requestMACFor(rootKey, testKeyID, blobRequestMACDomain, blobIngressPath, requestBody); request.Header.Get(testSignatureHeader) != want {
					t.Errorf("request signature is not the blob-domain MAC")
				}
				envelope := canonical.Map{
					"protocol": "circulus.v1alpha1", "major": int64(1), "minor": int64(0),
					"schemaDigest": blobHostSchemaDigest, "requestId": requestID,
					"payload": canonical.Map{"ok": true, "result": test.result},
				}
				body, err := canonical.Encode(envelope, canonical.Options{
					MaxBytes: maximumBlobResponseBytes * 2, MaxDepth: maximumResponseDepth, MaxItems: maximumResponseItems,
				})
				if err != nil {
					t.Errorf("encode response: %v", err)
					return
				}
				if test.oversizedBody {
					body = bytes.Repeat([]byte{0xf6}, maximumBlobResponseBytes+1)
				}
				writeWireResponse(writer, wireResponse{
					status: http.StatusOK, contentType: blobIngressContentType, keyID: testKeyID,
					signature: responseMACFor(rootKey, testKeyID, requestID, requestBody, http.StatusOK, blobIngressContentType, blobResponseMACDomain, body),
					body:      body,
				})
			}))
			client := newTestClient(t, endpoint, rootKey, func() (string, error) { return validID("req", 2), nil }, 5*time.Second)
			request := validBlobRequest(2)
			request.Digest = test.requestDigest
			blob, err := client.ReadSessionBlob(context.Background(), request)
			if test.want != nil {
				if !errors.Is(err, test.want) {
					t.Fatalf("ReadSessionBlob() error = %v, want %v", err, test.want)
				}
				if blob.Bytes != nil || blob.Digest != "" {
					t.Fatalf("ReadSessionBlob() returned %+v alongside an error", blob)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadSessionBlob() error = %v", err)
			}
			if blob.Digest != test.requestDigest || !bytes.Equal(blob.Bytes, test.wantBytes) {
				t.Fatalf("ReadSessionBlob() digest = %s, %d bytes; want %s, %d bytes", blob.Digest, len(blob.Bytes), test.requestDigest, len(test.wantBytes))
			}
		})
	}
}

func TestReadSessionBlobRejectsReadEventsDomainSignatureAndSchema(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x35}, 32)
	payload := []byte("hydrated checkpoint payload bytes")
	payloadDigest := sha256.Sum256(payload)
	digest := "sha256:" + hex.EncodeToString(payloadDigest[:])
	tests := []struct {
		name         string
		domain       string
		schemaDigest string
		want         error
	}{
		{name: "read-events response domain", domain: responseMACDomain, schemaDigest: blobHostSchemaDigest, want: ErrUnauthenticatedResponse},
		{name: "read-events host schema", domain: blobResponseMACDomain, schemaDigest: hostSchemaDigest, want: ErrInvalidResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requestBody := mustReadRequest(t, request)
				requestID := requestIDFromBody(t, requestBody)
				envelope := canonical.Map{
					"protocol": "circulus.v1alpha1", "major": int64(1), "minor": int64(0),
					"schemaDigest": test.schemaDigest, "requestId": requestID,
					"payload": canonical.Map{"ok": true, "result": canonical.Map{
						"digest": digest, "encodedBytes": int64(len(payload)), "bytes": canonical.Bytes(payload),
					}},
				}
				body := mustEncode(t, envelope)
				writeWireResponse(writer, wireResponse{
					status: http.StatusOK, contentType: blobIngressContentType, keyID: testKeyID,
					signature: responseMACFor(rootKey, testKeyID, requestID, requestBody, http.StatusOK, blobIngressContentType, test.domain, body),
					body:      body,
				})
			}))
			client := newTestClient(t, endpoint, rootKey, func() (string, error) { return validID("req", 3), nil }, time.Second)
			request := validBlobRequest(3)
			request.Digest = digest
			if _, err := client.ReadSessionBlob(context.Background(), request); !errors.Is(err, test.want) {
				t.Fatalf("ReadSessionBlob() error = %v, want %v", err, test.want)
			}
		})
	}
}

func validBlobRequest(index uint64) BlobRequest {
	return BlobRequest{
		TenantID: validID("tenant", index), ActorSubjectID: validID("subject", index),
		SessionID: validID("sess", index), ExpectedAuthorizationGeneration: 1,
		Digest: "sha256:" + strings.Repeat("a", 64),
	}
}
