package platformapi_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/platformapi"
)

type authoritativeHTTPReader struct {
	mu       sync.Mutex
	page     platformapi.SessionPublicEventPage
	err      error
	requests []platformapi.AuthorizedSessionEventPageRequest
}

func (*authoritativeHTTPReader) SessionEventReaderEvidence() platformapi.SessionEventReaderEvidence {
	return platformapi.SessionEventReaderEvidence{
		CrashDurable: true, AuthoritativeSessionJournal: true,
		AtomicAuthorizationGenerationFence: true,
	}
}

func (reader *authoritativeHTTPReader) ReadSessionEventPage(
	_ context.Context,
	request platformapi.AuthorizedSessionEventPageRequest,
) (platformapi.SessionPublicEventPage, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.requests = append(reader.requests, request)
	return reader.page, reader.err
}

type countingFlushRecorder struct {
	*httptest.ResponseRecorder
	writes  int
	flushes int
}

func (recorder *countingFlushRecorder) Write(payload []byte) (int, error) {
	recorder.writes++
	return recorder.ResponseRecorder.Write(payload)
}

func (recorder *countingFlushRecorder) Flush() {
	recorder.flushes++
	recorder.ResponseRecorder.Flush()
}

type nonFlushingHTTPWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (writer *nonFlushingHTTPWriter) Header() http.Header {
	return writer.header
}

func (writer *nonFlushingHTTPWriter) WriteHeader(status int) {
	if writer.status == 0 {
		writer.status = status
	}
}

func (writer *nonFlushingHTTPWriter) Write(payload []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	return writer.body.Write(payload)
}

type observedLegacyRecorder struct {
	*httptest.ResponseRecorder
	flushed          chan struct{}
	ephemeralWritten chan struct{}
}

func (recorder *observedLegacyRecorder) Write(payload []byte) (int, error) {
	if bytes.Contains(payload, []byte("event: model.delta\n")) {
		select {
		case recorder.ephemeralWritten <- struct{}{}:
		default:
		}
	}
	return recorder.ResponseRecorder.Write(payload)
}

func (recorder *observedLegacyRecorder) Flush() {
	recorder.ResponseRecorder.Flush()
	select {
	case recorder.flushed <- struct{}{}:
	default:
	}
}

func newAuthoritativeHTTPHandler(
	t *testing.T,
	legacy *platformapi.Service,
	events *platformapi.SessionEventService,
	authenticator platformapi.RequestAuthenticator,
) http.Handler {
	t.Helper()
	handler, err := platformapi.NewHTTPHandler(platformapi.HTTPConfig{
		Service: legacy, SessionEvents: events, Authenticator: authenticator,
		MaximumBodyBytes: 4 << 10,
	})
	if err != nil {
		t.Fatalf("NewHTTPHandler() error = %v", err)
	}
	return handler
}

func newAuthoritativeHTTPEventService(
	t *testing.T,
	reader platformapi.SessionEventPageReader,
) *platformapi.SessionEventService {
	t.Helper()
	service, err := platformapi.NewSessionEventService(platformapi.SessionEventServiceConfig{
		Reader: reader, Authorizer: &stateEventAuthorizer{}, MaximumPageEvents: 16,
	})
	if err != nil {
		t.Fatalf("NewSessionEventService() error = %v", err)
	}
	return service
}

func legacyHTTPService(t *testing.T) *platformapi.Service {
	t.Helper()
	return newAPIService(t, platformapi.NewMemoryStore(), &scopedAuthorizer{})
}

func TestHTTPSSEFailsClosedWithoutAuthoritativeSessionReader(t *testing.T) {
	legacy := newAPIService(t, platformapi.NewMemoryStore(), &scopedAuthorizer{})
	authenticator := &requestAuthenticator{principal: stateEventPrincipal}
	handler := newHTTPHandler(t, legacy, authenticator)
	request := httptest.NewRequest(
		http.MethodGet, "/v1/sessions/"+stateEventSessionID+"/events", nil,
	)
	request.Header.Set("Accept", "text/event-stream")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET events status/body = %d/%s, want 503", response.Code, response.Body.String())
	}
	if authenticator.calls != 1 {
		t.Fatalf("Authenticate() calls = %d, want 1", authenticator.calls)
	}
}

func TestAuthoritativeHTTPSSEFramesOneBoundedPageAndCloses(t *testing.T) {
	reader := &authoritativeHTTPReader{page: platformapi.SessionPublicEventPage{
		Snapshot: platformapi.SessionPublicEventSnapshot{
			SessionID: stateEventSessionID, LastEventSequence: 2,
		},
		Events: []platformapi.SessionPublicEvent{{
			Sequence: 2, Type: platformapi.EventTurnCompleted,
			TurnID: "turn-one", TurnSequence: 0,
		}},
	}}
	events := newAuthoritativeHTTPEventService(t, reader)
	handler := newAuthoritativeHTTPHandler(
		t, legacyHTTPService(t), events,
		&requestAuthenticator{principal: stateEventPrincipal},
	)
	request := httptest.NewRequest(
		http.MethodGet, "/v1/sessions/"+stateEventSessionID+"/events", nil,
	)
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Last-Event-ID", "1")
	response := &countingFlushRecorder{ResponseRecorder: httptest.NewRecorder()}

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("GET events status/body = %d/%s, want 200", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "text/event-stream" ||
		response.Header().Get("Cache-Control") != "no-cache, no-store" ||
		response.Header().Get("X-Accel-Buffering") != "no" {
		t.Fatalf("SSE headers = %#v", response.Header())
	}
	const wantBody = "retry: 1000\n\n" +
		"event: session.snapshot\n" +
		"data: {\"sessionId\":\"sess_AAAAAAAAAAAAAAAAAAAAAAAAAA\",\"activeTurnId\":null,\"turnStatus\":null,\"lastEventSequence\":2}\n\n" +
		"id: 2\n" +
		"event: turn.completed\n" +
		"data: {\"sequence\":2,\"type\":\"turn.completed\",\"turnId\":\"turn-one\",\"turnSequence\":0}\n\n"
	if response.Body.String() != wantBody {
		t.Fatalf("SSE body = %q, want %q", response.Body.String(), wantBody)
	}
	if response.writes != 1 || response.flushes != 1 {
		t.Fatalf("SSE writes/flushes = %d/%d, want 1/1", response.writes, response.flushes)
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if len(reader.requests) != 1 || reader.requests[0].AfterSequence != 1 ||
		reader.requests[0].Limit != 16 || reader.requests[0].SessionID != stateEventSessionID ||
		reader.requests[0].Authorization != stateEventPermit(7) {
		t.Fatalf("authoritative reader requests = %#v", reader.requests)
	}
}

func TestAuthoritativeHTTPSSERequiresExactAcceptAndCanonicalCursor(t *testing.T) {
	for name, test := range map[string]struct {
		accepts []string
		cursors []string
		status  int
	}{
		"missing accept":       {status: http.StatusNotAcceptable},
		"wrong accept":         {accepts: []string{"application/json"}, status: http.StatusNotAcceptable},
		"parameterized accept": {accepts: []string{"text/event-stream; charset=utf-8"}, status: http.StatusNotAcceptable},
		"comma accept":         {accepts: []string{"text/event-stream, text/plain"}, status: http.StatusNotAcceptable},
		"duplicate accept":     {accepts: []string{"text/event-stream", "text/event-stream"}, status: http.StatusNotAcceptable},
		"empty cursor":         {accepts: []string{"text/event-stream"}, cursors: []string{""}, status: http.StatusBadRequest},
		"plus cursor":          {accepts: []string{"text/event-stream"}, cursors: []string{"+1"}, status: http.StatusBadRequest},
		"leading zero cursor":  {accepts: []string{"text/event-stream"}, cursors: []string{"01"}, status: http.StatusBadRequest},
		"space cursor":         {accepts: []string{"text/event-stream"}, cursors: []string{" 1"}, status: http.StatusBadRequest},
		"comma cursor":         {accepts: []string{"text/event-stream"}, cursors: []string{"1,2"}, status: http.StatusBadRequest},
		"negative cursor":      {accepts: []string{"text/event-stream"}, cursors: []string{"-1"}, status: http.StatusBadRequest},
		"unsafe cursor":        {accepts: []string{"text/event-stream"}, cursors: []string{"9007199254740992"}, status: http.StatusBadRequest},
		"overflow cursor":      {accepts: []string{"text/event-stream"}, cursors: []string{"18446744073709551616"}, status: http.StatusBadRequest},
		"duplicate cursor":     {accepts: []string{"text/event-stream"}, cursors: []string{"1", "2"}, status: http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			reader := &authoritativeHTTPReader{page: emptyStateEventPage()}
			events := newAuthoritativeHTTPEventService(t, reader)
			authenticator := &requestAuthenticator{principal: stateEventPrincipal}
			handler := newAuthoritativeHTTPHandler(t, legacyHTTPService(t), events, authenticator)
			request := httptest.NewRequest(
				http.MethodGet, "/v1/sessions/"+stateEventSessionID+"/events", nil,
			)
			for _, value := range test.accepts {
				request.Header.Add("Accept", value)
			}
			for _, value := range test.cursors {
				request.Header.Add("Last-Event-ID", value)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.status {
				t.Fatalf("GET events status/body = %d/%s, want %d", response.Code, response.Body.String(), test.status)
			}
			if authenticator.calls != 1 {
				t.Fatalf("Authenticate() calls = %d, want 1", authenticator.calls)
			}
			reader.mu.Lock()
			defer reader.mu.Unlock()
			if len(reader.requests) != 0 {
				t.Fatalf("authoritative reader requests = %#v, want none", reader.requests)
			}
		})
	}
}

func TestAuthoritativeHTTPSSEAcceptsCanonicalZeroCursor(t *testing.T) {
	reader := &authoritativeHTTPReader{page: emptyStateEventPage()}
	events := newAuthoritativeHTTPEventService(t, reader)
	handler := newAuthoritativeHTTPHandler(
		t, legacyHTTPService(t), events,
		&requestAuthenticator{principal: stateEventPrincipal},
	)
	request := httptest.NewRequest(
		http.MethodGet, "/v1/sessions/"+stateEventSessionID+"/events", nil,
	)
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Last-Event-ID", "0")
	response := &countingFlushRecorder{ResponseRecorder: httptest.NewRecorder()}

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.flushes != 1 {
		t.Fatalf("GET events status/body/flushes = %d/%q/%d", response.Code, response.Body.String(), response.flushes)
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if len(reader.requests) != 1 || reader.requests[0].AfterSequence != 0 {
		t.Fatalf("authoritative reader requests = %#v", reader.requests)
	}
}

func TestAuthoritativeHTTPSSEChecksFlusherBeforeReading(t *testing.T) {
	reader := &authoritativeHTTPReader{page: emptyStateEventPage()}
	events := newAuthoritativeHTTPEventService(t, reader)
	handler := newAuthoritativeHTTPHandler(
		t, legacyHTTPService(t), events,
		&requestAuthenticator{principal: stateEventPrincipal},
	)
	request := httptest.NewRequest(
		http.MethodGet, "/v1/sessions/"+stateEventSessionID+"/events", nil,
	)
	request.Header.Set("Accept", "text/event-stream")
	response := &nonFlushingHTTPWriter{header: make(http.Header)}

	handler.ServeHTTP(response, request)

	if response.status != http.StatusServiceUnavailable ||
		!strings.Contains(response.body.String(), `"reason":"STREAMING_UNAVAILABLE"`) {
		t.Fatalf("GET events status/body = %d/%s, want structured 503", response.status, response.body.String())
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if len(reader.requests) != 0 {
		t.Fatalf("authoritative reader requests = %#v, want none", reader.requests)
	}
}

func TestAuthoritativeHTTPSSERejectsMalformedPageBeforeStreaming(t *testing.T) {
	reader := &authoritativeHTTPReader{page: platformapi.SessionPublicEventPage{
		Snapshot: platformapi.SessionPublicEventSnapshot{
			SessionID: "sess_AAAAAAAAAAAAAAAAAAAAAAAAAE",
		},
	}}
	events := newAuthoritativeHTTPEventService(t, reader)
	handler := newAuthoritativeHTTPHandler(
		t, legacyHTTPService(t), events,
		&requestAuthenticator{principal: stateEventPrincipal},
	)
	request := httptest.NewRequest(
		http.MethodGet, "/v1/sessions/"+stateEventSessionID+"/events", nil,
	)
	request.Header.Set("Accept", "text/event-stream")
	response := &countingFlushRecorder{ResponseRecorder: httptest.NewRecorder()}

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError || response.flushes != 0 ||
		response.Header().Get("Content-Type") != "application/json" ||
		strings.Contains(response.Body.String(), "session.snapshot") {
		t.Fatalf("GET malformed events status/headers/body/flushes = %d/%#v/%s/%d",
			response.Code, response.Header(), response.Body.String(), response.flushes)
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if len(reader.requests) != 1 {
		t.Fatalf("authoritative reader requests = %#v, want one", reader.requests)
	}
}

type appendAfterReadHTTPJournal struct {
	mu       sync.Mutex
	events   []platformapi.SessionPublicEvent
	appended bool
	requests []platformapi.AuthorizedSessionEventPageRequest
}

func (*appendAfterReadHTTPJournal) SessionEventReaderEvidence() platformapi.SessionEventReaderEvidence {
	return platformapi.SessionEventReaderEvidence{
		CrashDurable: true, AuthoritativeSessionJournal: true,
		AtomicAuthorizationGenerationFence: true,
	}
}

func (journal *appendAfterReadHTTPJournal) ReadSessionEventPage(
	_ context.Context,
	request platformapi.AuthorizedSessionEventPageRequest,
) (platformapi.SessionPublicEventPage, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	journal.requests = append(journal.requests, request)
	if request.Authorization != stateEventPermit(7) || request.AfterSequence > uint64(len(journal.events)) {
		return platformapi.SessionPublicEventPage{}, platformapi.ErrStaleAuthority
	}
	head := uint64(len(journal.events))
	end := request.AfterSequence + uint64(request.Limit)
	if end > head {
		end = head
	}
	pageEvents := append(
		[]platformapi.SessionPublicEvent(nil),
		journal.events[int(request.AfterSequence):int(end)]...,
	)
	snapshot := platformapi.SessionPublicEventSnapshot{
		SessionID: stateEventSessionID, LastEventSequence: head,
	}
	if head != 0 && journal.events[head-1].Type != platformapi.EventTurnCompleted {
		snapshot.ActiveTurnID = stateEventString("turn-one")
		snapshot.TurnStatus = stateEventTurnStatus(platformapi.TurnActive)
	}
	page := platformapi.SessionPublicEventPage{Snapshot: snapshot, Events: pageEvents}
	if !journal.appended {
		journal.events = append(journal.events, platformapi.SessionPublicEvent{
			Sequence: 2, Type: platformapi.EventTurnCompleted,
			TurnID: "turn-one", TurnSequence: 0,
		})
		journal.appended = true
	}
	return page, nil
}

func TestAuthoritativeHTTPSSEReconnectRecoversAppendAfterReadWithoutCursorDuplicate(t *testing.T) {
	journal := &appendAfterReadHTTPJournal{events: []platformapi.SessionPublicEvent{
		acceptedStateEvent(1, "turn-one", 0),
	}}
	events := newAuthoritativeHTTPEventService(t, journal)
	handler := newAuthoritativeHTTPHandler(
		t, legacyHTTPService(t), events,
		&requestAuthenticator{principal: stateEventPrincipal},
	)
	firstRequest := httptest.NewRequest(
		http.MethodGet, "/v1/sessions/"+stateEventSessionID+"/events", nil,
	)
	firstRequest.Header.Set("Accept", "text/event-stream")
	firstResponse := &countingFlushRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(firstResponse, firstRequest)
	if firstResponse.Code != http.StatusOK || !strings.Contains(firstResponse.Body.String(), "id: 1\n") ||
		strings.Contains(firstResponse.Body.String(), "id: 2\n") {
		t.Fatalf("first SSE status/body = %d/%q", firstResponse.Code, firstResponse.Body.String())
	}

	secondRequest := httptest.NewRequest(
		http.MethodGet, "/v1/sessions/"+stateEventSessionID+"/events", nil,
	)
	secondRequest.Header.Set("Accept", "text/event-stream")
	secondRequest.Header.Set("Last-Event-ID", "1")
	secondResponse := &countingFlushRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(secondResponse, secondRequest)
	if secondResponse.Code != http.StatusOK || !strings.Contains(secondResponse.Body.String(), "id: 2\n") ||
		strings.Contains(secondResponse.Body.String(), "id: 1\n") {
		t.Fatalf("second SSE status/body = %d/%q", secondResponse.Code, secondResponse.Body.String())
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if len(journal.requests) != 2 || journal.requests[0].AfterSequence != 0 ||
		journal.requests[1].AfterSequence != 1 {
		t.Fatalf("journal requests = %#v", journal.requests)
	}
}

func TestAuthoritativeHTTPSSEDoesNotExposeLegacyEphemeralSource(t *testing.T) {
	ctx := context.Background()
	store := platformapi.NewMemoryStore()
	registerAPISession(t, store)
	legacy := newAPIService(t, store, &scopedAuthorizer{})
	created, err := legacy.CreateTurn(ctx, platformapi.CreateTurnRequest{
		Principal: stateEventPrincipal, SessionID: stateEventSessionID,
		IdempotencyKey: "legacy-ephemeral-source",
		Messages:       []platformapi.Message{{Role: "user", Content: "must stay private"}},
	})
	if err != nil {
		t.Fatalf("CreateTurn() error = %v", err)
	}
	legacyAuthority := eventAuthority(created.Turn.ID)
	if _, _, err := legacy.AppendDurableEvent(ctx, platformapi.AppendDurableEventRequest{
		Authority: legacyAuthority, CommandID: "op_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		ExpectedSequence: 0, Type: platformapi.EventTurnAccepted,
		Payload: []byte(`{"legacy":true}`), TurnStatus: platformapi.TurnActive,
	}); err != nil {
		t.Fatalf("AppendDurableEvent() error = %v", err)
	}
	reader := &authoritativeHTTPReader{page: platformapi.SessionPublicEventPage{
		Snapshot: platformapi.SessionPublicEventSnapshot{
			SessionID: stateEventSessionID, LastEventSequence: 1,
		},
	}}
	events := newAuthoritativeHTTPEventService(t, reader)
	handler := newAuthoritativeHTTPHandler(
		t, legacy, events, &requestAuthenticator{principal: stateEventPrincipal},
	)
	requestContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest(
		http.MethodGet, "/v1/sessions/"+stateEventSessionID+"/events", nil,
	).WithContext(requestContext)
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Last-Event-ID", "1")
	response := &observedLegacyRecorder{
		ResponseRecorder: httptest.NewRecorder(), flushed: make(chan struct{}, 1),
		ephemeralWritten: make(chan struct{}, 1),
	}
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, request)
		close(done)
	}()
	select {
	case <-response.flushed:
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("GET events did not flush its bounded response")
	}
	if _, err := legacy.PublishEphemeralEvent(ctx, platformapi.EphemeralEventRequest{
		Authority: legacyAuthority, Type: platformapi.EventModelDelta, Payload: []byte("legacy-partial"),
	}); err != nil {
		cancel()
		<-done
		t.Fatalf("PublishEphemeralEvent() error = %v", err)
	}
	select {
	case <-done:
	case <-response.ephemeralWritten:
		cancel()
		<-done
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("GET events retained a live subscription")
	}
	if strings.Contains(response.Body.String(), "model.delta") ||
		strings.Contains(response.Body.String(), "legacy-partial") {
		t.Fatalf("authoritative SSE exposed legacy ephemeral event: %q", response.Body.String())
	}
}

func TestAuthoritativeHTTPSSEMapsReaderFailureBeforeWritingHeaders(t *testing.T) {
	reader := &authoritativeHTTPReader{err: errors.New("private celld shard path")}
	events := newAuthoritativeHTTPEventService(t, reader)
	handler := newAuthoritativeHTTPHandler(
		t, legacyHTTPService(t), events,
		&requestAuthenticator{principal: stateEventPrincipal},
	)
	request := httptest.NewRequest(
		http.MethodGet, "/v1/sessions/"+stateEventSessionID+"/events", nil,
	)
	request.Header.Set("Accept", "text/event-stream")
	response := &countingFlushRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || response.flushes != 0 ||
		strings.Contains(response.Body.String(), "celld") {
		t.Fatalf("GET events status/body/flushes = %d/%q/%d", response.Code, response.Body.String(), response.flushes)
	}
}
