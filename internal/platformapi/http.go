package platformapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strconv"
	"time"
	"unicode/utf8"
)

type RequestAuthenticator interface {
	Authenticate(context.Context, *http.Request) (Principal, error)
}

type HTTPConfig struct {
	Service          *Service
	Authenticator    RequestAuthenticator
	MaximumBodyBytes int64
}

type HTTPHandler struct {
	service          *Service
	authenticator    RequestAuthenticator
	maximumBodyBytes int64
	mux              *http.ServeMux
}

func NewHTTPHandler(config HTTPConfig) (*HTTPHandler, error) {
	if config.Service == nil || config.Authenticator == nil || config.MaximumBodyBytes <= 0 ||
		config.MaximumBodyBytes > maximumConfiguredBytes {
		return nil, ErrInvalidConfig
	}
	authenticator := reflect.ValueOf(config.Authenticator)
	switch authenticator.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if authenticator.IsNil() {
			return nil, ErrInvalidConfig
		}
	}
	handler := &HTTPHandler{
		service: config.Service, authenticator: config.Authenticator,
		maximumBodyBytes: config.MaximumBodyBytes, mux: http.NewServeMux(),
	}
	handler.mux.HandleFunc("POST /v1/sessions/{sessionId}/turns", handler.createTurn)
	handler.mux.HandleFunc("GET /v1/sessions/{sessionId}/events", handler.replayEvents)
	return handler, nil
}

func (handler *HTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("X-Content-Type-Options", "nosniff")
	handler.mux.ServeHTTP(response, request)
}

func (handler *HTTPHandler) createTurn(response http.ResponseWriter, request *http.Request) {
	principal, err := handler.authenticate(request)
	if err != nil {
		writeHTTPError(response, http.StatusUnauthorized, "unauthenticated")
		return
	}
	contentTypes := request.Header.Values("Content-Type")
	idempotencyKeys := request.Header.Values("Idempotency-Key")
	if len(contentTypes) != 1 {
		writeHTTPError(response, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	if len(idempotencyKeys) != 1 {
		writeHTTPError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		writeHTTPError(response, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, handler.maximumBodyBytes)
	document, err := io.ReadAll(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeHTTPError(response, http.StatusRequestEntityTooLarge, "request_too_large")
			return
		}
		writeHTTPError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if !utf8.Valid(document) {
		writeHTTPError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	inString := false
	validStrings := true
	for index := 0; index < len(document) && validStrings; index++ {
		switch document[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(document) {
				continue
			}
			if document[index+1] != 'u' {
				index++
				continue
			}
			if index+5 >= len(document) {
				validStrings = false
				continue
			}
			unit := uint16(0)
			for offset := 2; offset <= 5; offset++ {
				character := document[index+offset]
				unit <<= 4
				switch {
				case character >= '0' && character <= '9':
					unit |= uint16(character - '0')
				case character >= 'a' && character <= 'f':
					unit |= uint16(character-'a') + 10
				case character >= 'A' && character <= 'F':
					unit |= uint16(character-'A') + 10
				default:
					validStrings = false
				}
			}
			if !validStrings {
				continue
			}
			switch {
			case unit >= 0xd800 && unit <= 0xdbff:
				if index+11 >= len(document) || document[index+6] != '\\' || document[index+7] != 'u' {
					validStrings = false
					continue
				}
				low := uint16(0)
				for offset := 8; offset <= 11; offset++ {
					character := document[index+offset]
					low <<= 4
					switch {
					case character >= '0' && character <= '9':
						low |= uint16(character - '0')
					case character >= 'a' && character <= 'f':
						low |= uint16(character-'a') + 10
					case character >= 'A' && character <= 'F':
						low |= uint16(character-'A') + 10
					default:
						validStrings = false
					}
				}
				if low < 0xdc00 || low > 0xdfff {
					validStrings = false
					continue
				}
				index += 11
			case unit >= 0xdc00 && unit <= 0xdfff:
				validStrings = false
			default:
				index += 5
			}
		}
	}
	if !validStrings {
		writeHTTPError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	scanner := json.NewDecoder(bytes.NewReader(document))
	scanner.UseNumber()
	var scanValue func(int) error
	scanValue = func(depth int) error {
		if depth > 64 {
			return ErrInvalidRequest
		}
		token, err := scanner.Token()
		if err != nil {
			return err
		}
		delimiter, structured := token.(json.Delim)
		if !structured {
			return nil
		}
		switch delimiter {
		case '{':
			keys := make(map[string]struct{})
			for scanner.More() {
				keyToken, err := scanner.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrInvalidRequest
				}
				if _, duplicate := keys[key]; duplicate {
					return ErrInvalidRequest
				}
				keys[key] = struct{}{}
				if err := scanValue(depth + 1); err != nil {
					return err
				}
			}
			closing, err := scanner.Token()
			if err != nil || closing != json.Delim('}') {
				return ErrInvalidRequest
			}
		case '[':
			for scanner.More() {
				if err := scanValue(depth + 1); err != nil {
					return err
				}
			}
			closing, err := scanner.Token()
			if err != nil || closing != json.Delim(']') {
				return ErrInvalidRequest
			}
		default:
			return ErrInvalidRequest
		}
		return nil
	}
	if err := scanValue(0); err != nil {
		writeHTTPError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if _, err := scanner.Token(); err != io.EOF {
		writeHTTPError(response, http.StatusBadRequest, "invalid_request")
		return
	}

	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var body struct {
		Messages []Message `json:"messages"`
	}
	if err := decoder.Decode(&body); err != nil {
		writeHTTPError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeHTTPError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	result, err := handler.service.CreateTurn(request.Context(), CreateTurnRequest{
		Principal: principal, SessionID: request.PathValue("sessionId"),
		IdempotencyKey: idempotencyKeys[0], Messages: body.Messages,
	})
	if err != nil {
		writeServiceError(response, err)
		return
	}
	status := http.StatusAccepted
	if result.Deduplicated {
		status = http.StatusOK
	}
	writeJSON(response, status, struct {
		TurnID       string     `json:"turnId"`
		Status       TurnStatus `json:"status"`
		Deduplicated bool       `json:"deduplicated"`
	}{
		TurnID: result.Turn.ID, Status: result.Turn.Status, Deduplicated: result.Deduplicated,
	})
}

func (handler *HTTPHandler) replayEvents(response http.ResponseWriter, request *http.Request) {
	principal, err := handler.authenticate(request)
	if err != nil {
		writeHTTPError(response, http.StatusUnauthorized, "unauthenticated")
		return
	}
	afterSequence := uint64(0)
	cursors := request.Header.Values("Last-Event-ID")
	if len(cursors) > 1 {
		writeHTTPError(response, http.StatusBadRequest, "invalid_cursor")
		return
	}
	if len(cursors) == 1 && cursors[0] != "" {
		cursor := cursors[0]
		afterSequence, err = strconv.ParseUint(cursor, 10, 64)
		if err != nil {
			writeHTTPError(response, http.StatusBadRequest, "invalid_cursor")
			return
		}
	}
	stream, err := handler.service.OpenEventStream(request.Context(), ReplayEventsRequest{
		Principal: principal, SessionID: request.PathValue("sessionId"), AfterSequence: afterSequence,
	})
	if err != nil {
		writeServiceError(response, err)
		return
	}
	if stream.Subscription != nil {
		defer stream.Subscription.Close()
	}
	flusher, canFlush := response.(http.Flusher)
	if !canFlush {
		writeHTTPError(response, http.StatusInternalServerError, "streaming_unsupported")
		return
	}
	replay := stream.Replay
	response.Header().Set("Content-Type", "text/event-stream")
	response.Header().Set("Cache-Control", "no-cache, no-store")
	response.Header().Set("X-Accel-Buffering", "no")
	response.WriteHeader(http.StatusOK)
	snapshotPayload, err := json.Marshal(struct {
		SessionID           string     `json:"sessionId"`
		ActiveTurnID        string     `json:"activeTurnId,omitempty"`
		TurnStatus          TurnStatus `json:"turnStatus,omitempty"`
		LastDurableSequence uint64     `json:"lastDurableSequence"`
	}{
		SessionID: replay.Snapshot.SessionID, ActiveTurnID: replay.Snapshot.ActiveTurnID,
		TurnStatus:          replay.Snapshot.TurnStatus,
		LastDurableSequence: replay.Snapshot.LastDurableSequence,
	})
	if err != nil {
		return
	}
	if _, err := fmt.Fprintf(response, "event: session.snapshot\ndata: %s\n\n", snapshotPayload); err != nil {
		return
	}
	flusher.Flush()
	for _, event := range replay.Events {
		payload, err := json.Marshal(struct {
			TurnID  string `json:"turnId"`
			Payload string `json:"payload"`
		}{TurnID: event.TurnID, Payload: event.Payload})
		if err != nil {
			return
		}
		if _, err := fmt.Fprintf(response, "id: %d\nevent: %s\ndata: %s\n\n", event.Sequence, event.Type, payload); err != nil {
			return
		}
		flusher.Flush()
	}
	if !stream.CaughtUp {
		return
	}
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-request.Context().Done():
			return
		case event, open := <-stream.Subscription.Events():
			if !open {
				return
			}
			payload, err := json.Marshal(struct {
				TurnID  string `json:"turnId"`
				Payload string `json:"payload"`
			}{TurnID: event.TurnID, Payload: event.Payload})
			if err != nil {
				return
			}
			if event.Durable {
				if _, err := fmt.Fprintf(
					response, "id: %d\nevent: %s\ndata: %s\n\n", event.Sequence, event.Type, payload,
				); err != nil {
					return
				}
			} else if _, err := fmt.Fprintf(response, "event: %s\ndata: %s\n\n", event.Type, payload); err != nil {
				return
			}
			flusher.Flush()
		case <-keepalive.C:
			if _, err := io.WriteString(response, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (handler *HTTPHandler) authenticate(request *http.Request) (Principal, error) {
	principal, err := handler.authenticator.Authenticate(request.Context(), request)
	if err != nil || validatePrincipal(principal) != nil {
		return Principal{}, ErrAccessDenied
	}
	return principal, nil
}

func writeServiceError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		writeHTTPError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, ErrAccessDenied):
		writeHTTPError(response, http.StatusForbidden, "access_denied")
	case errors.Is(err, ErrSessionNotFound), errors.Is(err, ErrTurnNotFound):
		writeHTTPError(response, http.StatusNotFound, "not_found")
	case errors.Is(err, ErrIdempotencyConflict), errors.Is(err, ErrSequenceConflict),
		errors.Is(err, ErrInvalidCursor), errors.Is(err, ErrStaleAuthority),
		errors.Is(err, ErrInvalidTransition):
		writeHTTPError(response, http.StatusConflict, "conflict")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeHTTPError(response, http.StatusRequestTimeout, "request_cancelled")
	default:
		writeHTTPError(response, http.StatusInternalServerError, "internal_error")
	}
}

func writeHTTPError(response http.ResponseWriter, status int, code string) {
	writeJSON(response, status, struct {
		Error string `json:"error"`
	}{Error: code})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
