package platformapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteServiceErrorMapsStablePublicCodesWithoutLeaks(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		status    int
		code      string
		reason    string
		retryable bool
	}{
		{name: "invalid request", err: ErrInvalidRequest, status: http.StatusBadRequest, code: "invalid_argument", reason: "INVALID_REQUEST"},
		{name: "access denied", err: ErrAccessDenied, status: http.StatusForbidden, code: "permission_denied", reason: "ACCESS_DENIED"},
		{name: "session not found", err: ErrSessionNotFound, status: http.StatusNotFound, code: "not_found", reason: "RESOURCE_NOT_FOUND"},
		{name: "turn not found", err: ErrTurnNotFound, status: http.StatusNotFound, code: "not_found", reason: "RESOURCE_NOT_FOUND"},
		{name: "idempotency conflict", err: ErrIdempotencyConflict, status: http.StatusConflict, code: "idempotency_conflict", reason: "IDEMPOTENCY_CONFLICT"},
		{name: "sequence conflict", err: ErrSequenceConflict, status: http.StatusConflict, code: "conflict", reason: "DURABLE_SEQUENCE_CONFLICT"},
		{name: "invalid cursor", err: ErrInvalidCursor, status: http.StatusBadRequest, code: "invalid_argument", reason: "INVALID_CURSOR"},
		{name: "stale authority", err: ErrStaleAuthority, status: http.StatusConflict, code: "stale_generation", reason: "STALE_AUTHORIZATION_GENERATION"},
		{name: "invalid transition", err: ErrInvalidTransition, status: http.StatusPreconditionFailed, code: "failed_precondition", reason: "INVALID_TURN_TRANSITION"},
		{name: "canceled", err: context.Canceled, status: http.StatusRequestTimeout, code: "aborted", reason: "REQUEST_CANCELED"},
		{name: "deadline", err: context.DeadlineExceeded, status: http.StatusGatewayTimeout, code: "deadline_exceeded", reason: "REQUEST_DEADLINE_EXCEEDED", retryable: true},
		{name: "internal", err: errors.New("database password hunter2"), status: http.StatusInternalServerError, code: "internal", reason: "INTERNAL_ERROR"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			response.Header().Set("X-Request-ID", "req_AAAAAAAAAAAAAAAAAAAAAAAAAA")
			writeServiceError(response, fmt.Errorf("sensitive dependency location: %w", test.err))
			if response.Code != test.status {
				t.Fatalf("status/body = %d/%s, want %d", response.Code, response.Body.String(), test.status)
			}
			if strings.Contains(response.Body.String(), "hunter2") ||
				strings.Contains(response.Body.String(), "sensitive dependency location") {
				t.Fatalf("internal error leaked: %q", response.Body.String())
			}
			var document map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if len(document) != 6 || document["apiVersion"] != "v1alpha" ||
				document["code"] != test.code || document["reason"] != test.reason ||
				document["requestId"] != "req_AAAAAAAAAAAAAAAAAAAAAAAAAA" ||
				document["retryable"] != test.retryable {
				t.Fatalf("public error = %#v", document)
			}
		})
	}
}
