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
	"path"
	"reflect"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/identity"
)

type RequestAuthenticator interface {
	Authenticate(context.Context, *http.Request) (Principal, error)
}

type HTTPConfig struct {
	Service          *Service
	Authenticator    RequestAuthenticator
	MaximumBodyBytes int64
	NewRequestID     func() (string, error)
}

type HTTPHandler struct {
	service          *Service
	authenticator    RequestAuthenticator
	maximumBodyBytes int64
	newRequestID     func() (string, error)
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
	newRequestID := config.NewRequestID
	if newRequestID == nil {
		newRequestID = newSecureRequestID
	}
	handler := &HTTPHandler{
		service: config.Service, authenticator: config.Authenticator,
		maximumBodyBytes: config.MaximumBodyBytes, newRequestID: newRequestID,
		mux: http.NewServeMux(),
	}
	handler.mux.HandleFunc("/v1/sessions/{sessionId}/turns", handler.routeCreateTurn)
	handler.mux.HandleFunc("/v1/sessions/{sessionId}/events", handler.routeReplayEvents)
	handler.mux.HandleFunc("/", handler.routeNotFound)
	return handler, nil
}

func (handler *HTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("X-Content-Type-Options", "nosniff")
	requestID, err := handler.newRequestID()
	if err != nil || !validPublicRequestID(requestID) {
		requestID, err = newSecureRequestID()
		if err != nil || !validPublicRequestID(requestID) {
			requestID = "req_FALLBACK"
		}
		response.Header().Set("X-Request-ID", requestID)
		writeHTTPError(
			response, http.StatusInternalServerError, "internal", "REQUEST_ID_GENERATION_FAILED",
			"the request could not be initialized", true,
		)
		return
	}
	response.Header().Set("X-Request-ID", requestID)
	if request.RequestURI == "*" ||
		(request.URL.Path != "/" && path.Clean(request.URL.Path) != request.URL.Path) {
		handler.routeNotFound(response, request)
		return
	}
	handler.mux.ServeHTTP(response, request)
}

func (handler *HTTPHandler) routeCreateTurn(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		writeHTTPError(
			response, http.StatusMethodNotAllowed, "invalid_argument", "METHOD_NOT_ALLOWED",
			"the request method is not allowed for this route", false,
		)
		return
	}
	handler.createTurn(response, request)
}

func (handler *HTTPHandler) routeReplayEvents(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		writeHTTPError(
			response, http.StatusMethodNotAllowed, "invalid_argument", "METHOD_NOT_ALLOWED",
			"the request method is not allowed for this route", false,
		)
		return
	}
	handler.replayEvents(response, request)
}

func (*HTTPHandler) routeNotFound(response http.ResponseWriter, _ *http.Request) {
	writeHTTPError(
		response, http.StatusNotFound, "not_found", "ROUTE_NOT_FOUND",
		"the requested route was not found", false,
	)
}

func (handler *HTTPHandler) createTurn(response http.ResponseWriter, request *http.Request) {
	principal, err := handler.authenticate(request)
	if err != nil {
		writeHTTPError(
			response, http.StatusUnauthorized, "unauthenticated", "AUTHENTICATION_REQUIRED",
			"authentication is required", false,
		)
		return
	}
	contentTypes := request.Header.Values("Content-Type")
	idempotencyKeys := request.Header.Values("Idempotency-Key")
	if len(contentTypes) != 1 {
		writeHTTPError(
			response, http.StatusUnsupportedMediaType, "invalid_argument", "UNSUPPORTED_MEDIA_TYPE",
			"the request Content-Type must be application/json", false,
		)
		return
	}
	if len(idempotencyKeys) != 1 {
		writeHTTPError(
			response, http.StatusBadRequest, "invalid_argument", "INVALID_IDEMPOTENCY_KEY",
			"exactly one idempotency key is required", false,
		)
		return
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		writeHTTPError(
			response, http.StatusUnsupportedMediaType, "invalid_argument", "UNSUPPORTED_MEDIA_TYPE",
			"the request Content-Type must be application/json", false,
		)
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, handler.maximumBodyBytes)
	document, err := io.ReadAll(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeHTTPError(
				response, http.StatusRequestEntityTooLarge, "resource_exhausted", "REQUEST_BODY_TOO_LARGE",
				"the request body is too large", false,
			)
			return
		}
		writeHTTPError(
			response, http.StatusBadRequest, "invalid_argument", "INVALID_REQUEST",
			"the request is invalid", false,
		)
		return
	}
	if !utf8.Valid(document) {
		writeHTTPError(
			response, http.StatusBadRequest, "invalid_argument", "INVALID_REQUEST",
			"the request is invalid", false,
		)
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
		writeHTTPError(
			response, http.StatusBadRequest, "invalid_argument", "INVALID_REQUEST",
			"the request is invalid", false,
		)
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
		writeHTTPError(
			response, http.StatusBadRequest, "invalid_argument", "INVALID_REQUEST",
			"the request is invalid", false,
		)
		return
	}
	if _, err := scanner.Token(); err != io.EOF {
		writeHTTPError(
			response, http.StatusBadRequest, "invalid_argument", "INVALID_REQUEST",
			"the request is invalid", false,
		)
		return
	}

	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var body struct {
		Messages []Message `json:"messages"`
	}
	if err := decoder.Decode(&body); err != nil {
		writeHTTPError(
			response, http.StatusBadRequest, "invalid_argument", "INVALID_REQUEST",
			"the request is invalid", false,
		)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeHTTPError(
			response, http.StatusBadRequest, "invalid_argument", "INVALID_REQUEST",
			"the request is invalid", false,
		)
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
		writeHTTPError(
			response, http.StatusUnauthorized, "unauthenticated", "AUTHENTICATION_REQUIRED",
			"authentication is required", false,
		)
		return
	}
	afterSequence := uint64(0)
	cursors := request.Header.Values("Last-Event-ID")
	if len(cursors) > 1 {
		writeHTTPError(
			response, http.StatusBadRequest, "invalid_argument", "INVALID_CURSOR",
			"the event cursor is invalid", false,
		)
		return
	}
	if len(cursors) == 1 && cursors[0] != "" {
		cursor := cursors[0]
		afterSequence, err = strconv.ParseUint(cursor, 10, 64)
		if err != nil {
			writeHTTPError(
				response, http.StatusBadRequest, "invalid_argument", "INVALID_CURSOR",
				"the event cursor is invalid", false,
			)
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
		writeHTTPError(
			response, http.StatusServiceUnavailable, "unavailable", "STREAMING_UNAVAILABLE",
			"event streaming is unavailable", true,
		)
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
		writeHTTPError(
			response, http.StatusBadRequest, "invalid_argument", "INVALID_REQUEST",
			"the request is invalid", false,
		)
	case errors.Is(err, ErrAccessDenied):
		writeHTTPError(
			response, http.StatusForbidden, "permission_denied", "ACCESS_DENIED",
			"permission was denied", false,
		)
	case errors.Is(err, ErrSessionNotFound), errors.Is(err, ErrTurnNotFound):
		writeHTTPError(
			response, http.StatusNotFound, "not_found", "RESOURCE_NOT_FOUND",
			"the requested resource was not found", false,
		)
	case errors.Is(err, ErrIdempotencyConflict):
		writeHTTPError(
			response, http.StatusConflict, "idempotency_conflict", "IDEMPOTENCY_CONFLICT",
			"the idempotency key was already used for a different request", false,
		)
	case errors.Is(err, ErrSequenceConflict):
		writeHTTPError(
			response, http.StatusConflict, "conflict", "DURABLE_SEQUENCE_CONFLICT",
			"the durable event sequence conflicts with current state", false,
		)
	case errors.Is(err, ErrInvalidCursor):
		writeHTTPError(
			response, http.StatusBadRequest, "invalid_argument", "INVALID_CURSOR",
			"the event cursor is invalid", false,
		)
	case errors.Is(err, ErrStaleAuthority):
		writeHTTPError(
			response, http.StatusConflict, "stale_generation", "STALE_AUTHORIZATION_GENERATION",
			"the caller authorization generation is stale", false,
		)
	case errors.Is(err, ErrInvalidTransition):
		writeHTTPError(
			response, http.StatusPreconditionFailed, "failed_precondition", "INVALID_TURN_TRANSITION",
			"the requested turn transition is not allowed", false,
		)
	case errors.Is(err, context.Canceled):
		writeHTTPError(
			response, http.StatusRequestTimeout, "aborted", "REQUEST_CANCELED",
			"the request was canceled", false,
		)
	case errors.Is(err, context.DeadlineExceeded):
		writeHTTPError(
			response, http.StatusGatewayTimeout, "deadline_exceeded", "REQUEST_DEADLINE_EXCEEDED",
			"the request deadline was exceeded", true,
		)
	default:
		writeHTTPError(
			response, http.StatusInternalServerError, "internal", "INTERNAL_ERROR",
			"an internal error occurred", false,
		)
	}
}

func writeHTTPError(
	response http.ResponseWriter,
	status int,
	code string,
	reason string,
	message string,
	retryable bool,
) {
	requestID := response.Header().Get("X-Request-ID")
	if !validPublicRequestID(requestID) {
		generated, err := newSecureRequestID()
		if err == nil && validPublicRequestID(generated) {
			requestID = generated
		} else {
			requestID = "req_FALLBACK"
		}
		response.Header().Set("X-Request-ID", requestID)
	}
	writeJSON(response, status, struct {
		APIVersion string `json:"apiVersion"`
		Code       string `json:"code"`
		Reason     string `json:"reason"`
		Message    string `json:"message"`
		Retryable  bool   `json:"retryable"`
		RequestID  string `json:"requestId"`
	}{
		APIVersion: "v1alpha", Code: code, Reason: reason, Message: message,
		Retryable: retryable, RequestID: requestID,
	})
}

func newSecureRequestID() (string, error) {
	value, err := identity.New(identity.Request)
	if err != nil {
		return "", err
	}
	return value.String(), nil
}

func validPublicRequestID(value string) bool {
	if len(value) == 0 || len(value) > 128 ||
		!((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z')) &&
			(character < '0' || character > '9') &&
			character != '_' && character != '.' && character != ':' && character != '-' {
			return false
		}
	}
	return true
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
