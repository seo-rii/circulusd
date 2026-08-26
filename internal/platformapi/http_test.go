package platformapi_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/platformapi"
)

type requestAuthenticator struct {
	mu        sync.Mutex
	principal platformapi.Principal
	err       error
	calls     int
}

type cancelingRecorder struct {
	*httptest.ResponseRecorder
	cancel context.CancelFunc
	marker string
}

func (recorder *cancelingRecorder) Write(payload []byte) (int, error) {
	written, err := recorder.ResponseRecorder.Write(payload)
	if strings.Contains(recorder.Body.String(), recorder.marker) {
		recorder.cancel()
	}
	return written, err
}

func (authenticator *requestAuthenticator) Authenticate(
	_ context.Context,
	_ *http.Request,
) (platformapi.Principal, error) {
	authenticator.mu.Lock()
	defer authenticator.mu.Unlock()
	authenticator.calls++
	return authenticator.principal, authenticator.err
}

func newHTTPHandler(
	t *testing.T,
	service *platformapi.Service,
	authenticator platformapi.RequestAuthenticator,
) http.Handler {
	t.Helper()
	handler, err := platformapi.NewHTTPHandler(platformapi.HTTPConfig{
		Service: service, Authenticator: authenticator, MaximumBodyBytes: 4 << 10,
	})
	if err != nil {
		t.Fatalf("NewHTTPHandler() error = %v", err)
	}
	return handler
}

func TestHTTPHandlerRejectsTypedNilAuthenticator(t *testing.T) {
	service := newAPIService(t, platformapi.NewMemoryStore(), &scopedAuthorizer{})
	var authenticator *requestAuthenticator
	_, err := platformapi.NewHTTPHandler(platformapi.HTTPConfig{
		Service: service, Authenticator: authenticator, MaximumBodyBytes: 4096,
	})
	if !errors.Is(err, platformapi.ErrInvalidConfig) {
		t.Fatalf("NewHTTPHandler(typed nil authenticator) error = %v, want ErrInvalidConfig", err)
	}
}

func TestHTTPCreateTurnIsAuthenticatedStrictAndIdempotent(t *testing.T) {
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	service := newAPIService(t, store, &scopedAuthorizer{})
	authenticator := &requestAuthenticator{principal: platformapi.Principal{
		TenantID: apiTenantID, SubjectID: apiSubjectID,
	}}
	handler := newHTTPHandler(t, service, authenticator)

	requestBody := `{"messages":[{"role":"user","content":"hello"}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/sessions/"+apiSessionID+"/turns", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "http-key")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("POST turn status/body = %d/%s, want 202", response.Code, response.Body.String())
	}
	var created struct {
		TurnID       string                 `json:"turnId"`
		Status       platformapi.TurnStatus `json:"status"`
		Deduplicated bool                   `json:"deduplicated"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.TurnID == "" || created.Status != platformapi.TurnQueued || created.Deduplicated {
		t.Fatalf("create response = %#v", created)
	}

	retry := httptest.NewRequest(http.MethodPost, "/v1/sessions/"+apiSessionID+"/turns", strings.NewReader(requestBody))
	retry.Header.Set("Content-Type", "application/json")
	retry.Header.Set("Idempotency-Key", "http-key")
	retryResponse := httptest.NewRecorder()
	handler.ServeHTTP(retryResponse, retry)
	if retryResponse.Code != http.StatusOK {
		t.Fatalf("POST duplicate status/body = %d/%s, want 200", retryResponse.Code, retryResponse.Body.String())
	}
	var deduplicated struct {
		TurnID       string `json:"turnId"`
		Deduplicated bool   `json:"deduplicated"`
	}
	if err := json.Unmarshal(retryResponse.Body.Bytes(), &deduplicated); err != nil {
		t.Fatalf("decode duplicate response: %v", err)
	}
	if deduplicated.TurnID != created.TurnID || !deduplicated.Deduplicated {
		t.Fatalf("duplicate response = %#v, created = %#v", deduplicated, created)
	}

	unknownField := httptest.NewRequest(http.MethodPost, "/v1/sessions/"+apiSessionID+"/turns", strings.NewReader(
		`{"messages":[{"role":"user","content":"hello"}],"tenantId":"forged"}`,
	))
	unknownField.Header.Set("Content-Type", "application/json")
	unknownField.Header.Set("Idempotency-Key", "strict-key")
	unknownResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownResponse, unknownField)
	if unknownResponse.Code != http.StatusBadRequest {
		t.Fatalf("POST unknown field status = %d, want 400", unknownResponse.Code)
	}

	duplicateJSON := httptest.NewRequest(http.MethodPost, "/v1/sessions/"+apiSessionID+"/turns", strings.NewReader(
		`{"messages":[{"role":"user","content":"first","content":"second"}]}`,
	))
	duplicateJSON.Header.Set("Content-Type", "application/json")
	duplicateJSON.Header.Set("Idempotency-Key", "duplicate-json-key")
	duplicateJSONResponse := httptest.NewRecorder()
	handler.ServeHTTP(duplicateJSONResponse, duplicateJSON)
	if duplicateJSONResponse.Code != http.StatusBadRequest {
		t.Fatalf("POST duplicate JSON key status = %d, want 400", duplicateJSONResponse.Code)
	}

	for name, rawBody := range map[string][]byte{
		"invalid UTF-8":  []byte("{\"messages\":[{\"role\":\"user\",\"content\":\"\xff\"}]}"),
		"lone surrogate": []byte(`{"messages":[{"role":"user","content":"\ud800"}]}`),
	} {
		t.Run(name, func(t *testing.T) {
			invalidText := httptest.NewRequest(http.MethodPost, "/v1/sessions/"+apiSessionID+"/turns", strings.NewReader(string(rawBody)))
			invalidText.Header.Set("Content-Type", "application/json")
			invalidText.Header.Set("Idempotency-Key", "invalid-text-"+name)
			invalidTextResponse := httptest.NewRecorder()
			handler.ServeHTTP(invalidTextResponse, invalidText)
			if invalidTextResponse.Code != http.StatusBadRequest {
				t.Fatalf("POST %s status = %d, want 400", name, invalidTextResponse.Code)
			}
		})
	}

	duplicateHeader := httptest.NewRequest(http.MethodPost, "/v1/sessions/"+apiSessionID+"/turns", strings.NewReader(requestBody))
	duplicateHeader.Header.Set("Content-Type", "application/json")
	duplicateHeader.Header.Add("Idempotency-Key", "first-key")
	duplicateHeader.Header.Add("Idempotency-Key", "second-key")
	duplicateHeaderResponse := httptest.NewRecorder()
	handler.ServeHTTP(duplicateHeaderResponse, duplicateHeader)
	if duplicateHeaderResponse.Code != http.StatusBadRequest {
		t.Fatalf("POST duplicate idempotency header status = %d, want 400", duplicateHeaderResponse.Code)
	}
}

func TestHTTPAuthenticationPrecedesBodyParsingAndErrorsAreRedacted(t *testing.T) {
	store := platformapi.NewMemoryStore()
	service := newAPIService(t, store, &scopedAuthorizer{})
	authenticator := &requestAuthenticator{err: errors.New("PAT record 42 leaked details")}
	handler := newHTTPHandler(t, service, authenticator)

	request := httptest.NewRequest(http.MethodPost, "/v1/sessions/"+apiSessionID+"/turns", strings.NewReader("not-json"))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "denied-key")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("POST unauthenticated status = %d, want 401", response.Code)
	}
	if strings.Contains(response.Body.String(), "record 42") {
		t.Fatalf("authentication details leaked in body: %q", response.Body.String())
	}
	if authenticator.calls != 1 {
		t.Fatalf("Authenticate() calls = %d, want 1", authenticator.calls)
	}
}

func TestHTTPSSEReplaysOnlyEventsAfterLastEventIDWithSnapshot(t *testing.T) {
	ctx := context.Background()
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	service := newAPIService(t, store, &scopedAuthorizer{})
	created, err := service.CreateTurn(ctx, platformapi.CreateTurnRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, IdempotencyKey: "sse-turn",
		Messages: []platformapi.Message{{Role: "user", Content: "stream"}},
	})
	if err != nil {
		t.Fatalf("CreateTurn() error = %v", err)
	}
	eventAuth := eventAuthority(created.Turn.ID)
	for index, event := range []struct {
		command string
		type_   platformapi.EventType
		status  platformapi.TurnStatus
	}{
		{command: "op_AAAAAAAAAAAAAAAAAAAAAAAAAA", type_: platformapi.EventTurnAccepted, status: platformapi.TurnActive},
		{command: "op_AAAAAAAAAAAAAAAAAAAAAAAAAE", type_: platformapi.EventTurnCompleted, status: platformapi.TurnCompleted},
	} {
		if _, _, err := service.AppendDurableEvent(ctx, platformapi.AppendDurableEventRequest{
			Authority: eventAuth, CommandID: event.command, ExpectedSequence: uint64(index),
			Type: event.type_, Payload: []byte(`{"index":` + string(rune('1'+index)) + `}`), TurnStatus: event.status,
		}); err != nil {
			t.Fatalf("AppendDurableEvent(%d) error = %v", index, err)
		}
	}

	handler := newHTTPHandler(t, service, &requestAuthenticator{principal: platformapi.Principal{
		TenantID: apiTenantID, SubjectID: apiSubjectID,
	}})
	streamContext, cancelStream := context.WithCancel(context.Background())
	defer cancelStream()
	request := httptest.NewRequest(http.MethodGet, "/v1/sessions/"+apiSessionID+"/events", nil).
		WithContext(streamContext)
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Last-Event-ID", "1")
	response := &cancelingRecorder{
		ResponseRecorder: httptest.NewRecorder(), cancel: cancelStream, marker: "event: turn.completed\n",
	}
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET events status/body = %d/%s", response.Code, response.Body.String())
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", contentType)
	}
	body, err := io.ReadAll(response.Result().Body)
	if err != nil {
		t.Fatalf("read SSE body: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "event: session.snapshot\n") || !strings.Contains(text, "\"lastDurableSequence\":2") ||
		!strings.Contains(text, "id: 2\n") || !strings.Contains(text, "event: turn.completed\n") {
		t.Fatalf("SSE body missing snapshot or event 2:\n%s", text)
	}
	if strings.Contains(text, "id: 1\n") || strings.Contains(text, "event: turn.accepted\n") {
		t.Fatalf("SSE body replayed event at cursor:\n%s", text)
	}

	invalid := httptest.NewRequest(http.MethodGet, "/v1/sessions/"+apiSessionID+"/events", nil)
	invalid.Header.Set("Accept", "text/event-stream")
	invalid.Header.Set("Last-Event-ID", "-1")
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusBadRequest {
		t.Fatalf("GET events invalid cursor status = %d, want 400", invalidResponse.Code)
	}

	duplicateCursor := httptest.NewRequest(http.MethodGet, "/v1/sessions/"+apiSessionID+"/events", nil)
	duplicateCursor.Header.Set("Accept", "text/event-stream")
	duplicateCursor.Header.Add("Last-Event-ID", "1")
	duplicateCursor.Header.Add("Last-Event-ID", "2")
	duplicateCursorResponse := httptest.NewRecorder()
	handler.ServeHTTP(duplicateCursorResponse, duplicateCursor)
	if duplicateCursorResponse.Code != http.StatusBadRequest {
		t.Fatalf("GET events duplicate cursor status = %d, want 400", duplicateCursorResponse.Code)
	}
}

func TestHTTPSSEContinuesWithLiveEphemeralEvents(t *testing.T) {
	ctx := context.Background()
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	service := newAPIService(t, store, &scopedAuthorizer{})
	created, err := service.CreateTurn(ctx, platformapi.CreateTurnRequest{
		Principal: platformapi.Principal{TenantID: apiTenantID, SubjectID: apiSubjectID},
		SessionID: apiSessionID, IdempotencyKey: "sse-live-turn",
		Messages: []platformapi.Message{{Role: "user", Content: "stream live"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	eventAuth := eventAuthority(created.Turn.ID)
	if _, _, err := service.AppendDurableEvent(ctx, platformapi.AppendDurableEventRequest{
		Authority: eventAuth, CommandID: "op_AAAAAAAAAAAAAAAAAAAAAAAAAA", ExpectedSequence: 0,
		Type: platformapi.EventTurnAccepted, Payload: []byte(`{"state":"accepted"}`), TurnStatus: platformapi.TurnActive,
	}); err != nil {
		t.Fatal(err)
	}
	handler := newHTTPHandler(t, service, &requestAuthenticator{principal: platformapi.Principal{
		TenantID: apiTenantID, SubjectID: apiSubjectID,
	}})
	server := httptest.NewServer(handler)
	defer server.Close()
	requestContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext, http.MethodGet, server.URL+"/v1/sessions/"+apiSessionID+"/events", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Last-Event-ID", "1")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read initial SSE snapshot: %v", err)
		}
		if line == "\n" {
			break
		}
	}
	if _, err := service.PublishEphemeralEvent(ctx, platformapi.EphemeralEventRequest{
		Authority: eventAuth, Type: platformapi.EventModelDelta, Payload: []byte("partial"),
	}); err != nil {
		t.Fatal(err)
	}
	var live strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read live SSE event: %v", err)
		}
		live.WriteString(line)
		if line == "\n" {
			break
		}
	}
	if text := live.String(); !strings.Contains(text, "event: model.delta\n") ||
		!strings.Contains(text, `"payload":"partial"`) || strings.Contains(text, "id:") {
		t.Fatalf("live ephemeral SSE event = %q", text)
	}
}
