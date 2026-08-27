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
	testKeyHeader          = "X-Circulus-State-Key-Id"
	testSignatureHeader    = "X-Circulus-State-Signature"
)

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
	want := []string{"Endpoint", "KeyID", "RootKey", "Timeout"}
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

	endpoint := startUnixHTTPServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		if request.Method != fixture.Method || request.URL.Path != fixture.Path || request.URL.RawQuery != "" {
			t.Errorf("request target = %s %s, want %s %s", request.Method, request.URL.RequestURI(), fixture.Method, fixture.Path)
		}
		if request.Host != "state.invalid" {
			t.Errorf("request Host = %q, want state.invalid", request.Host)
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
			endpoint := startUnixHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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
			endpoint := startUnixHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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
		endpoint := startUnixHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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
		endpoint := startUnixHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
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
		endpoint := startUnixHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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
	endpoint := startUnixHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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
		Endpoint: "unix:///definitely/not/present/state.sock", KeyID: testKeyID,
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
	endpoint := startUnixHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
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
	endpoint := startUnixHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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

func TestConcurrentCloseIsIdempotentAndRejectsRacingReads(t *testing.T) {
	rootKey := bytes.Repeat([]byte{0x6b}, 32)
	endpoint := startUnixHTTPServer(t, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
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
	endpoint := startUnixHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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
		Endpoint: "unix:///definitely/not/present/state.sock", KeyID: testKeyID,
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
		Endpoint: "unix:///definitely/not/present/state.sock", KeyID: testKeyID,
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
		Endpoint: "unix:///definitely/not/present/state.sock", KeyID: testKeyID,
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
			Endpoint: "unix:///definitely/not/present/state.sock", KeyID: testKeyID,
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

func TestNewRejectsNonUnixOrNoncanonicalEndpointAndInvalidSecrets(t *testing.T) {
	valid := Config{
		Endpoint: "unix:///run/circulusd/state.sock", KeyID: testKeyID,
		RootKey: bytes.Repeat([]byte{0x11}, 32), Timeout: time.Second,
	}
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{name: "empty endpoint", edit: func(config *Config) { config.Endpoint = "" }},
		{name: "network endpoint", edit: func(config *Config) { config.Endpoint = "http://127.0.0.1/state" }},
		{name: "relative Unix path", edit: func(config *Config) { config.Endpoint = "unix:state.sock" }},
		{name: "Unix host", edit: func(config *Config) { config.Endpoint = "unix://host/run/state.sock" }},
		{name: "root path", edit: func(config *Config) { config.Endpoint = "unix:///" }},
		{name: "noncanonical path", edit: func(config *Config) { config.Endpoint = "unix:///run/../state.sock" }},
		{name: "encoded path", edit: func(config *Config) { config.Endpoint = "unix:///run/state%2Esock" }},
		{name: "query", edit: func(config *Config) { config.Endpoint += "?target=other" }},
		{name: "fragment", edit: func(config *Config) { config.Endpoint += "#other" }},
		{name: "NUL", edit: func(config *Config) { config.Endpoint = "unix:///run/state%00.sock" }},
		{name: "socket path too long", edit: func(config *Config) { config.Endpoint = "unix:///" + strings.Repeat("x", 108) }},
		{name: "empty key id", edit: func(config *Config) { config.KeyID = "" }},
		{name: "invalid key id", edit: func(config *Config) { config.KeyID = "State Key" }},
		{name: "short root key", edit: func(config *Config) { config.RootKey = make([]byte, 31) }},
		{name: "long root key", edit: func(config *Config) { config.RootKey = make([]byte, 257) }},
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

func startUnixHTTPServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	directory, err := os.MkdirTemp(os.TempDir(), "sac-")
	if err != nil {
		t.Fatalf("create short Unix socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socketPath := filepath.Join(directory, "state.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen Unix socket: %v", err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("serve Unix HTTP: %v", serveErr)
		}
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})
	return "unix://" + socketPath
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

func validRequest(index uint64) Request {
	return Request{
		TenantID: validID("tenant", index), ActorSubjectID: validID("subject", index),
		SessionID: validID("sess", index), ExpectedAuthorizationGeneration: 1,
		AfterSequence: 0, Limit: 16,
	}
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
		"schemaDigest": "sha256:58371a0cde5b6e833a492ee580e02d9ae80a9b311ec2cda116475b51417ba164",
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
	requestDigest := sha256.Sum256(requestBody)
	bodyDigest := sha256.Sum256(body)
	keyMAC := hmac.New(sha256.New, rootKey)
	_, _ = keyMAC.Write([]byte("circulusd.state-ingress.key.response.v1\x00"))
	responseKey := keyMAC.Sum(nil)
	parts := [][]byte{
		[]byte("circulusd.state-ingress.response.v1"), []byte(keyID), []byte(requestID), requestDigest[:],
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
