package stateappclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
)

func TestReadSessionBlobMatchesCrossLanguageGolden(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "packages", "protocol-types", "fixtures", "state-app-blob-ingress-v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		goldenFixture
		Request struct {
			ReadSessionBlobRequest
			RequestID    string `json:"requestId"`
			SentAtUnixMS int64  `json:"sentAtUnixMs"`
		} `json:"request"`
		Response struct {
			Payload struct {
				Result struct {
					Digest       string `json:"digest"`
					EncodedBytes int    `json:"encodedBytes"`
					Bytes        struct {
						Hex string `json:"hex"`
					} `json:"bytes"`
				} `json:"result"`
			} `json:"payload"`
		} `json:"response"`
	}
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	rootKey, err := hex.DecodeString(fixture.RootKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := hex.DecodeString(fixture.ResponseCBORHex)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body := mustReadRequest(t, request)
		if request.Method != fixture.Method || request.URL.RequestURI() != fixture.Path ||
			request.Header.Get("Content-Type") != fixture.ContentType ||
			request.Header.Get(testKeyHeader) != fixture.KeyID ||
			request.Header.Get(testSignatureHeader) != fixture.RequestMACHex ||
			hex.EncodeToString(body) != fixture.RequestCBORHex {
			t.Error("blob request differs from the cross-language golden")
		}
		writeWireResponse(writer, wireResponse{
			status: fixture.ResponseStatus, contentType: fixture.ContentType, keyID: fixture.KeyID,
			signature: fixture.ResponseMACHex, body: responseBody,
		})
	}))
	client, err := newWithSources(Config{
		Endpoint: endpoint, KeyID: fixture.KeyID, RootKey: rootKey, Timeout: time.Second,
	}, clientSources{
		clock:        func() time.Time { return time.UnixMilli(fixture.Request.SentAtUnixMS) },
		newRequestID: func() (string, error) { return fixture.Request.RequestID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	clear(rootKey)
	result, err := client.ReadSessionBlob(context.Background(), fixture.Request.ReadSessionBlobRequest)
	if err != nil {
		t.Fatal(err)
	}
	want := fixture.Response.Payload.Result
	if result == nil || result.Digest != want.Digest || result.EncodedBytes != want.EncodedBytes ||
		hex.EncodeToString(result.Bytes) != want.Bytes.Hex {
		t.Fatalf("blob result = %#v, want golden blob", result)
	}
}

func TestReadSessionBlobAcceptsLargePayloadsThroughFourMiB(t *testing.T) {
	for _, size := range []int{(1 << 20) + 1, 4 << 20} {
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			blob := encodeBlobResponse(t, strings.Repeat("x", size-5))
			requestValue := validBlobRequest(blob)
			rootKey := bytes.Repeat([]byte{0x31}, 32)
			endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requestBody := mustReadRequest(t, request)
				requestID := requestIDFromBody(t, requestBody)
				if got := request.Header.Get(testSignatureHeader); got != requestMACFor(rootKey, testKeyID,
					"circulusd.state-blob-ingress.request.v1", "/circulusd/state/v1/session-blob:read", requestBody) {
					t.Error("blob request did not use read credentials with its operation MAC domain")
				}
				writeWireResponse(writer, signedBlobResponse(t, rootKey, requestID, requestBody, canonical.Map{
					"ok": true, "result": canonical.Map{
						"digest": requestValue.Digest, "encodedBytes": len(blob), "bytes": canonical.Bytes(blob),
					},
				}))
			}))
			client := newTestClient(t, endpoint, rootKey, func() (string, error) { return validID("req", 1), nil }, 3*time.Second)
			result, err := client.ReadSessionBlob(context.Background(), requestValue)
			if err != nil || result == nil || result.EncodedBytes != size || !bytes.Equal(result.Bytes, blob) {
				t.Fatalf("ReadSessionBlob() size = %d, error = %v", size, err)
			}
		})
	}
}

func TestReadSessionBlobRejectsTamperingAndInvalidAuthenticatedResults(t *testing.T) {
	blob := encodeBlobResponse(t, canonical.Map{"message": "hydrated"})
	requestValue := validBlobRequest(blob)
	for _, test := range []struct {
		name    string
		edit    func(canonical.Map)
		tamper  bool
		wantErr error
	}{
		{name: "unsigned body change", tamper: true, wantErr: ErrUnauthenticatedResponse},
		{name: "digest differs from requested", edit: func(result canonical.Map) {
			result["digest"] = "sha256:" + strings.Repeat("0", 64)
		}},
		{name: "bytes differ from signed digest", edit: func(result canonical.Map) {
			changed := append(canonical.Bytes(nil), blob...)
			changed[len(changed)-1] ^= 1
			result["bytes"] = changed
		}},
		{name: "wrong encoded byte count", edit: func(result canonical.Map) { result["encodedBytes"] = len(blob) + 1 }},
		{name: "negative encoded byte count", edit: func(result canonical.Map) { result["encodedBytes"] = -1 }},
		{name: "empty blob", edit: func(result canonical.Map) {
			result["bytes"], result["encodedBytes"] = canonical.Bytes{}, 0
		}},
		{name: "blob above four MiB", edit: func(result canonical.Map) {
			result["bytes"], result["encodedBytes"] = canonical.Bytes(make([]byte, (4<<20)+1)), (4<<20)+1
		}},
		{name: "text instead of byte string", edit: func(result canonical.Map) { result["bytes"] = "not bytes" }},
		{name: "unknown field", edit: func(result canonical.Map) { result["untrusted"] = true }},
		{name: "missing field", edit: func(result canonical.Map) { delete(result, "digest") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			rootKey := bytes.Repeat([]byte{0x31}, 32)
			endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requestBody := mustReadRequest(t, request)
				result := canonical.Map{"digest": requestValue.Digest, "encodedBytes": len(blob), "bytes": canonical.Bytes(blob)}
				if test.edit != nil {
					test.edit(result)
				}
				response := signedBlobResponse(t, rootKey, requestIDFromBody(t, requestBody), requestBody,
					canonical.Map{"ok": true, "result": result})
				if test.tamper {
					response.body[len(response.body)-1] ^= 1
				}
				writeWireResponse(writer, response)
			}))
			client := newTestClient(t, endpoint, rootKey, func() (string, error) { return validID("req", 1), nil }, 3*time.Second)
			result, err := client.ReadSessionBlob(context.Background(), requestValue)
			wantErr := test.wantErr
			if wantErr == nil {
				wantErr = ErrInvalidResponse
			}
			if result != nil || !errors.Is(err, wantErr) {
				t.Fatalf("ReadSessionBlob() = (%v, %v), want nil %v", result, err, wantErr)
			}
		})
	}
}

func TestReadSessionBlobValidatesMissingAndStaleAuthorizationResults(t *testing.T) {
	requestValue := validBlobRequest([]byte("content"))
	for _, stale := range []bool{false, true} {
		t.Run(fmt.Sprintf("stale=%t", stale), func(t *testing.T) {
			rootKey := bytes.Repeat([]byte{0x31}, 32)
			endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requestBody := mustReadRequest(t, request)
				payload := canonical.Map{"ok": true, "result": nil}
				if stale {
					payload = canonical.Map{"ok": false, "error": canonical.Map{
						"code": "STALE_GENERATION", "message": "The supplied generation is stale.",
					}}
				}
				writeWireResponse(writer, signedBlobResponse(t, rootKey, requestIDFromBody(t, requestBody), requestBody, payload))
			}))
			client := newTestClient(t, endpoint, rootKey, func() (string, error) { return validID("req", 1), nil }, time.Second)
			result, err := client.ReadSessionBlob(context.Background(), requestValue)
			var remote *RemoteError
			if result != nil || !stale && err != nil || stale && (!errors.As(err, &remote) || remote.Code != "STALE_GENERATION") {
				t.Fatalf("ReadSessionBlob() = (%v, %v)", result, err)
			}
		})
	}
}

func TestReadSessionBlobBoundsAdvertisedAndStreamingResponses(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprintf("streaming=%t", streaming), func(t *testing.T) {
			endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				_ = mustReadRequest(t, request)
				writer.Header().Set("Content-Type", blobIngressContentType)
				writer.Header().Set(testKeyHeader, testKeyID)
				writer.Header().Set(testSignatureHeader, strings.Repeat("0", 64))
				if streaming {
					writer.(http.Flusher).Flush()
				} else {
					writer.Header().Set("Content-Length", fmt.Sprint(maximumBlobResponseBytes+1))
				}
				_, _ = writer.Write(make([]byte, maximumBlobResponseBytes+1))
			}))
			client := newTestClient(t, endpoint, bytes.Repeat([]byte{0x31}, 32),
				func() (string, error) { return validID("req", 1), nil }, 3*time.Second)
			if _, err := client.ReadSessionBlob(context.Background(), validBlobRequest([]byte("content"))); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("oversize blob envelope error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestReadSessionBlobPreservesCancellationAndCloseLifecycle(t *testing.T) {
	for _, closeClient := range []bool{false, true} {
		t.Run(fmt.Sprintf("close=%t", closeClient), func(t *testing.T) {
			started := make(chan struct{})
			endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
				_ = mustReadRequest(t, request)
				close(started)
				<-request.Context().Done()
			}))
			client := newTestClient(t, endpoint, bytes.Repeat([]byte{0x31}, 32),
				func() (string, error) { return validID("req", 1), nil }, 3*time.Second)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			requestValue := validBlobRequest([]byte("content"))
			done := make(chan error, 1)
			go func() {
				_, err := client.ReadSessionBlob(ctx, requestValue)
				done <- err
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("blob request did not reach server")
			}
			wantErr := context.Canceled
			if closeClient {
				client.Close()
				wantErr = ErrClientClosed
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, wantErr) {
					t.Fatalf("ReadSessionBlob() error = %v, want %v", err, wantErr)
				}
			case <-time.After(time.Second):
				t.Fatal("blob request did not stop")
			}
			client.Close()
			if _, err := client.ReadSessionBlob(context.Background(), requestValue); !errors.Is(err, ErrClientClosed) {
				t.Fatalf("read after Close() error = %v", err)
			}
		})
	}
}

func TestReadSessionBlobRejectsInvalidRequestsBeforeSources(t *testing.T) {
	var generated atomic.Int64
	client := newTestClient(t, "http://127.0.0.1:1", bytes.Repeat([]byte{0x31}, 32), func() (string, error) {
		generated.Add(1)
		return validID("req", 1), nil
	}, time.Second)
	for _, edit := range []func(*ReadSessionBlobRequest){
		func(request *ReadSessionBlobRequest) { request.TenantID = "tenant_invalid" },
		func(request *ReadSessionBlobRequest) { request.ActorSubjectID = "subject_invalid" },
		func(request *ReadSessionBlobRequest) { request.SessionID = "sess_invalid" },
		func(request *ReadSessionBlobRequest) { request.ExpectedAuthorizationGeneration = 0 },
		func(request *ReadSessionBlobRequest) {
			request.ExpectedAuthorizationGeneration = maximumSharedInteger + 1
		},
		func(request *ReadSessionBlobRequest) { request.Digest = "sha256:bad" },
	} {
		request := validBlobRequest([]byte("content"))
		edit(&request)
		if _, err := client.ReadSessionBlob(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid request error = %v", err)
		}
	}
	if generated.Load() != 0 {
		t.Fatalf("invalid requests invoked sources %d times", generated.Load())
	}
}

func validBlobRequest(blob []byte) ReadSessionBlobRequest {
	sum := sha256.Sum256(blob)
	return ReadSessionBlobRequest{
		TenantID: validID("tenant", 1), ActorSubjectID: validID("subject", 1), SessionID: validID("sess", 1),
		ExpectedAuthorizationGeneration: 7, Digest: "sha256:" + hex.EncodeToString(sum[:]),
	}
}

func encodeBlobResponse(t *testing.T, value canonical.Value) []byte {
	t.Helper()
	body, err := canonical.Encode(value, canonical.Options{
		MaxBytes: maximumBlobResponseBytes, MaxDepth: maximumResponseDepth, MaxItems: maximumResponseItems,
	})
	if err != nil {
		t.Fatalf("encode blob response: %v", err)
	}
	return body
}

func signedBlobResponse(t *testing.T, rootKey []byte, requestID string, requestBody []byte, payload canonical.Map) wireResponse {
	t.Helper()
	body := encodeBlobResponse(t, canonical.Map{
		"protocol": "circulus.v1alpha1", "major": int64(1), "minor": int64(0),
		"schemaDigest": blobHostSchemaDigest, "requestId": requestID, "payload": payload,
	})
	return wireResponse{
		status: http.StatusOK, contentType: blobIngressContentType, keyID: testKeyID, body: body,
		signature: responseMACFor(rootKey, testKeyID, requestID, requestBody, http.StatusOK,
			blobIngressContentType, "circulusd.state-blob-ingress.response.v1", body),
	}
}
