package platformapi_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hancomac/circulusd/internal/platformapi"
)

var publicRequestIDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{0,127}$`)

type nonFlushingRecorder struct {
	recorder *httptest.ResponseRecorder
}

func (recorder *nonFlushingRecorder) Header() http.Header {
	return recorder.recorder.Header()
}

func (recorder *nonFlushingRecorder) Write(payload []byte) (int, error) {
	return recorder.recorder.Write(payload)
}

func (recorder *nonFlushingRecorder) WriteHeader(status int) {
	recorder.recorder.WriteHeader(status)
}

func TestHTTPPreStreamErrorsUsePublicErrorContract(t *testing.T) {
	validAuthenticator := func() platformapi.RequestAuthenticator {
		return &requestAuthenticator{principal: platformapi.Principal{
			TenantID: apiTenantID, SubjectID: apiSubjectID,
		}}
	}
	service := newAPIService(t, platformapi.NewMemoryStore(), &scopedAuthorizer{})
	tests := []struct {
		name          string
		handler       func() http.Handler
		method        string
		target        string
		body          string
		headers       map[string]string
		status        int
		code          string
		reason        string
		allow         string
		forbiddenText string
	}{
		{
			name: "authentication failure", handler: func() http.Handler {
				return newHTTPHandler(t, service, &requestAuthenticator{
					err: errors.New("secret PAT database row 42"),
				})
			}, method: http.MethodPost, target: "/v1/sessions/" + apiSessionID + "/turns",
			body: `{"messages":[{"role":"user","content":"hello"}]}`,
			headers: map[string]string{
				"Content-Type": "application/json", "Idempotency-Key": "auth-error",
			},
			status: http.StatusUnauthorized, code: "unauthenticated", reason: "AUTHENTICATION_REQUIRED",
			forbiddenText: "database row 42",
		},
		{
			name: "malformed request", handler: func() http.Handler {
				return newHTTPHandler(t, service, validAuthenticator())
			}, method: http.MethodPost, target: "/v1/sessions/" + apiSessionID + "/turns",
			body: `{"messages":`, headers: map[string]string{
				"Content-Type": "application/json", "Idempotency-Key": "malformed-error",
			},
			status: http.StatusBadRequest, code: "invalid_argument", reason: "INVALID_REQUEST",
		},
		{
			name: "unknown route", handler: func() http.Handler {
				return newHTTPHandler(t, service, validAuthenticator())
			}, method: http.MethodGet, target: "/v1/unknown", status: http.StatusNotFound,
			code: "not_found", reason: "ROUTE_NOT_FOUND",
		},
		{
			name: "unclean route", handler: func() http.Handler {
				return newHTTPHandler(t, service, validAuthenticator())
			}, method: http.MethodGet, target: "/v1//unknown", status: http.StatusNotFound,
			code: "not_found", reason: "ROUTE_NOT_FOUND",
		},
		{
			name: "asterisk form", handler: func() http.Handler {
				return newHTTPHandler(t, service, validAuthenticator())
			}, method: http.MethodOptions, target: "*", status: http.StatusNotFound,
			code: "not_found", reason: "ROUTE_NOT_FOUND",
		},
		{
			name: "wrong method", handler: func() http.Handler {
				return newHTTPHandler(t, service, validAuthenticator())
			}, method: http.MethodPut, target: "/v1/sessions/" + apiSessionID + "/turns",
			status: http.StatusMethodNotAllowed, code: "invalid_argument", reason: "METHOD_NOT_ALLOWED",
			allow: http.MethodPost,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
			for name, value := range test.headers {
				request.Header.Set(name, value)
			}
			response := httptest.NewRecorder()
			test.handler().ServeHTTP(response, request)

			if response.Code != test.status {
				t.Fatalf("status/body = %d/%s, want %d", response.Code, response.Body.String(), test.status)
			}
			if got := response.Header().Get("Allow"); got != test.allow {
				t.Fatalf("Allow = %q, want %q", got, test.allow)
			}
			assertPublicHTTPError(t, response, test.code, test.reason, test.forbiddenText)
		})
	}
}

func TestHTTPServiceIdempotencyConflictUsesDedicatedPublicCode(t *testing.T) {
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	service := newAPIService(t, store, &scopedAuthorizer{})
	handler := newHTTPHandler(t, service, &requestAuthenticator{principal: platformapi.Principal{
		TenantID: apiTenantID, SubjectID: apiSubjectID,
	}})

	for index, content := range []string{"first", "conflicting"} {
		request := httptest.NewRequest(
			http.MethodPost,
			"/v1/sessions/"+apiSessionID+"/turns",
			strings.NewReader(`{"messages":[{"role":"user","content":"`+content+`"}]}`),
		)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "same-key")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if index == 0 {
			if response.Code != http.StatusAccepted {
				t.Fatalf("initial status/body = %d/%s, want 202", response.Code, response.Body.String())
			}
			continue
		}
		if response.Code != http.StatusConflict {
			t.Fatalf("conflict status/body = %d/%s, want 409", response.Code, response.Body.String())
		}
		assertPublicHTTPError(t, response, "idempotency_conflict", "IDEMPOTENCY_CONFLICT", "")
	}
}

func TestHTTPStreamingCapabilityErrorUsesPublicErrorContract(t *testing.T) {
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	service := newAPIService(t, store, &scopedAuthorizer{})
	handler := newHTTPHandler(t, service, &requestAuthenticator{principal: platformapi.Principal{
		TenantID: apiTenantID, SubjectID: apiSubjectID,
	}})
	request := httptest.NewRequest(http.MethodGet, "/v1/sessions/"+apiSessionID+"/events", nil)
	underlying := httptest.NewRecorder()
	response := &nonFlushingRecorder{recorder: underlying}
	handler.ServeHTTP(response, request)

	if underlying.Code != http.StatusServiceUnavailable {
		t.Fatalf("status/body = %d/%s, want 503", underlying.Code, underlying.Body.String())
	}
	assertPublicHTTPError(t, underlying, "unavailable", "STREAMING_UNAVAILABLE", "")
}

func TestHTTPConfigInjectsOneStableRequestIDPerRequest(t *testing.T) {
	service := newAPIService(t, platformapi.NewMemoryStore(), &scopedAuthorizer{})
	var calls atomic.Int64
	handler, err := platformapi.NewHTTPHandler(platformapi.HTTPConfig{
		Service: service,
		Authenticator: &requestAuthenticator{principal: platformapi.Principal{
			TenantID: apiTenantID, SubjectID: apiSubjectID,
		}},
		MaximumBodyBytes: 4 << 10,
		NewRequestID: func() (string, error) {
			calls.Add(1)
			return "req_DETERMINISTIC.1", nil
		},
	})
	if err != nil {
		t.Fatalf("NewHTTPHandler() error = %v", err)
	}
	request := httptest.NewRequest(
		http.MethodPost, "/v1/sessions/"+apiSessionID+"/turns", strings.NewReader(`{"messages":`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "deterministic-id")
	request.Header.Set("X-Request-ID", "req_CALLER_CONTROLLED")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if calls.Load() != 1 {
		t.Fatalf("NewRequestID() calls = %d, want 1", calls.Load())
	}
	if got := response.Header().Get("X-Request-ID"); got != "req_DETERMINISTIC.1" {
		t.Fatalf("X-Request-ID = %q", got)
	}
	assertPublicHTTPError(t, response, "invalid_argument", "INVALID_REQUEST", "")
}

func TestHTTPRequestIDGeneratorFailureFailsClosedWithSchemaValidFallback(t *testing.T) {
	service := newAPIService(t, platformapi.NewMemoryStore(), &scopedAuthorizer{})
	tests := []struct {
		name string
		id   string
		err  error
	}{
		{name: "generator error", err: errors.New("entropy source details")},
		{name: "empty identifier"},
		{name: "invalid identifier", id: "1-invalid"},
		{name: "oversized identifier", id: "req_" + strings.Repeat("x", 125)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authenticator := &requestAuthenticator{principal: platformapi.Principal{
				TenantID: apiTenantID, SubjectID: apiSubjectID,
			}}
			handler, err := platformapi.NewHTTPHandler(platformapi.HTTPConfig{
				Service: service, Authenticator: authenticator, MaximumBodyBytes: 4 << 10,
				NewRequestID: func() (string, error) { return test.id, test.err },
			})
			if err != nil {
				t.Fatalf("NewHTTPHandler() error = %v", err)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/unknown", nil))
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status/body = %d/%s, want 500", response.Code, response.Body.String())
			}
			if authenticator.calls != 0 {
				t.Fatalf("Authenticate() calls = %d, want 0", authenticator.calls)
			}
			if strings.Contains(response.Body.String(), "entropy source details") {
				t.Fatalf("generator error leaked: %q", response.Body.String())
			}
			assertPublicHTTPError(t, response, "internal", "REQUEST_ID_GENERATION_FAILED", test.id)
		})
	}
}

func TestDefaultHTTPRequestIDsAreUniqueUnderConcurrency(t *testing.T) {
	service := newAPIService(t, platformapi.NewMemoryStore(), &scopedAuthorizer{})
	handler := newHTTPHandler(t, service, &requestAuthenticator{principal: platformapi.Principal{
		TenantID: apiTenantID, SubjectID: apiSubjectID,
	}})

	const count = 128
	start := make(chan struct{})
	ids := make(chan string, count)
	var wait sync.WaitGroup
	for range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/unknown", nil))
			if response.Code != http.StatusNotFound {
				ids <- "bad-status"
				return
			}
			ids <- response.Header().Get("X-Request-ID")
		}()
	}
	close(start)
	wait.Wait()
	close(ids)

	seen := make(map[string]struct{}, count)
	for id := range ids {
		if !publicRequestIDPattern.MatchString(id) {
			t.Fatalf("request ID = %q, want valid", id)
		}
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("duplicate request ID %q", id)
		}
		seen[id] = struct{}{}
	}
}

func assertPublicHTTPError(
	t *testing.T,
	response *httptest.ResponseRecorder,
	wantCode string,
	wantReason string,
	forbiddenText string,
) {
	t.Helper()
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	requestID := response.Header().Get("X-Request-ID")
	if !publicRequestIDPattern.MatchString(requestID) {
		t.Fatalf("X-Request-ID = %q, want schema-valid opaque ID", requestID)
	}
	if forbiddenText != "" && strings.Contains(response.Body.String(), forbiddenText) {
		t.Fatalf("sensitive error text leaked in body: %q", response.Body.String())
	}

	var document map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode public error: %v", err)
	}
	wantKeys := map[string]bool{
		"apiVersion": true, "code": true, "reason": true,
		"message": true, "retryable": true, "requestId": true,
	}
	if len(document) != len(wantKeys) {
		t.Fatalf("public error keys = %#v, want exactly %#v", document, wantKeys)
	}
	for key := range document {
		if !wantKeys[key] {
			t.Fatalf("public error contains unexpected field %q: %#v", key, document)
		}
	}
	if document["apiVersion"] != "v1alpha" || document["code"] != wantCode ||
		document["reason"] != wantReason || document["requestId"] != requestID {
		t.Fatalf("public error identity = %#v", document)
	}
	message, messageOK := document["message"].(string)
	retryable, retryableOK := document["retryable"].(bool)
	if !messageOK || message == "" || len(message) > 4096 || !retryableOK {
		t.Fatalf("public error message/retryable = %#v/%#v", message, retryable)
	}
}
