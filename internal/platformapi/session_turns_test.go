package platformapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	dependencycontract "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/idempotency"
	"github.com/hancomac/circulusd/internal/platformapi"
)

type admissionAuthorizerFunc func(context.Context, platformapi.AuthorizationRequest) (platformapi.AuthorizationPermit, error)

func (authorize admissionAuthorizerFunc) Authorize(ctx context.Context, request platformapi.AuthorizationRequest) (platformapi.AuthorizationPermit, error) {
	return authorize(ctx, request)
}

func admissionPermit(request platformapi.AuthorizationRequest) platformapi.AuthorizationPermit {
	return platformapi.AuthorizationPermit{
		Operation: request.Operation, Principal: request.Principal, SessionID: request.SessionID,
		AuthorizationGeneration: 7, Proof: platformapi.OpaqueAuthorizationProof{1, 2, 3},
	}
}

// Test-only signed proofs qualify constructor composition, not a deployment.
// Both operational interfaces use the same exact candidate and proof identity.
type admissionCandidate struct {
	*dependencycontract.ProductionProofs
	admissions []platformapi.SessionTurnAdmission
	reads      []platformapi.AuthorizedSessionEventPageRequest
	result     platformapi.SessionTurnAdmissionResult
	err        error
}

func (candidate *admissionCandidate) AdmitTurn(_ context.Context, request platformapi.SessionTurnAdmission) (platformapi.SessionTurnAdmissionResult, error) {
	candidate.admissions = append(candidate.admissions, request)
	return candidate.result, candidate.err
}

func (candidate *admissionCandidate) ReadSessionEventPage(_ context.Context, request platformapi.AuthorizedSessionEventPageRequest) (platformapi.SessionPublicEventPage, error) {
	candidate.reads = append(candidate.reads, request)
	id, status := apiTurnID, platformapi.TurnActive
	return platformapi.SessionPublicEventPage{
		Snapshot: platformapi.SessionPublicEventSnapshot{
			SessionID: apiSessionID, ActiveTurnID: &id, TurnStatus: &status, LastEventSequence: 1,
		},
		Events: []platformapi.SessionPublicEvent{{
			Sequence: 1, Type: platformapi.EventTurnAccepted, TurnID: id, TurnSequence: 0, Status: status,
		}},
	}, nil
}

func admissionFixture(t *testing.T, authorize admissionAuthorizerFunc) (
	*platformapi.SessionTurnService, *platformapi.SessionEventService, *admissionCandidate, platformapi.SessionTurnServiceConfig,
) {
	t.Helper()
	groups := []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent}
	proofs := dependencycontract.NewProductionProofs(t, groups)
	candidate := &admissionCandidate{
		ProductionProofs: proofs,
		result:           platformapi.SessionTurnAdmissionResult{TurnID: apiTurnID, Activated: true},
	}
	store := dependencycontract.Verify[platformapi.SessionTurnStore](t, proofs, candidate, groups)
	reader := dependencycontract.Verify[platformapi.SessionEventPageReader](t, proofs, candidate, groups)
	if authorize == nil {
		authorize = func(_ context.Context, request platformapi.AuthorizationRequest) (platformapi.AuthorizationPermit, error) {
			return admissionPermit(request), nil
		}
	}
	config := platformapi.SessionTurnServiceConfig{
		Store: store, SessionEvents: reader, Authorizer: authorize,
		IdempotencySecret: []byte(strings.Repeat("s", 32)), MaximumMessageBytes: 4096,
		NewTurnID: func() (string, error) { return apiTurnID, nil },
	}
	service, err := platformapi.NewSessionTurnService(config)
	if err != nil {
		t.Fatal(err)
	}
	events, err := platformapi.NewSessionEventService(platformapi.SessionEventServiceConfig{
		Reader: reader, Authorizer: authorize, MaximumPageEvents: 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, events, candidate, config
}

func admissionHTTP(t *testing.T, service *platformapi.SessionTurnService, events *platformapi.SessionEventService, authenticator platformapi.RequestAuthenticator) http.Handler {
	t.Helper()
	handler, err := platformapi.NewHTTPHandler(platformapi.HTTPConfig{
		TurnAdmitter: service, SessionEvents: events, Authenticator: authenticator, MaximumBodyBytes: 8192,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func postAdmission(handler http.Handler, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/v1/sessions/"+apiSessionID+"/turns", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "complete-input-key")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestAuthoritativeTurnHTTPPreservesFullInputAndSameSessionEventReader(t *testing.T) {
	service, events, candidate, _ := admissionFixture(t, nil)
	handler := admissionHTTP(t, service, events, &requestAuthenticator{principal: stateEventPrincipal})
	body := `{"messages":[{"role":"user","content":"첫 줄\nsecond line"},{"role":"user","content":"keep order: 1.25"}]}`
	response := postAdmission(handler, body)
	if response.Code != http.StatusAccepted || len(candidate.admissions) != 1 {
		t.Fatalf("POST = %d/%s, admissions %d", response.Code, response.Body, len(candidate.admissions))
	}
	input := canonical.Map{"messages": canonical.Array{
		canonical.Map{"role": "user", "content": "첫 줄\nsecond line"},
		canonical.Map{"role": "user", "content": "keep order: 1.25"},
	}}
	admitted := candidate.admissions[0]
	if !reflect.DeepEqual(admitted.Input, input) || admitted.ProposedTurnID != apiTurnID {
		t.Fatalf("admitted input/turn differs: %#v", admitted.Input)
	}
	inputDigest, _ := canonical.StructuredDigest("circulusd.session.turn-input", 1, input)
	requestDigest, _ := canonical.StructuredDigest("circulusd.public.turn.create", 1, canonical.Map{
		"sessionId": apiSessionID, "messages": canonical.Array{
			canonical.Array{"user", "첫 줄\nsecond line"}, canonical.Array{"user", "keep order: 1.25"},
		},
	})
	keyDigest, _ := idempotency.DigestKey([]byte(strings.Repeat("s", 32)), "complete-input-key")
	if admitted.InputDigest != inputDigest || admitted.RequestDigest != requestDigest || admitted.KeyDigest != keyDigest {
		t.Fatal("canonical input, semantic request, or idempotency binding differs")
	}
	if admitted.Authorization != admissionPermit(platformapi.AuthorizationRequest{
		Operation: platformapi.OperationCreateTurn, Principal: stateEventPrincipal, SessionID: apiSessionID,
	}) {
		t.Fatal("admission lost its exact authorization permit")
	}
	var created struct {
		TurnID string                 `json:"turnId"`
		Status platformapi.TurnStatus `json:"status"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || created.TurnID != apiTurnID || created.Status != platformapi.TurnActive {
		t.Fatalf("created response = %#v/%v", created, err)
	}
	candidate.result.Deduplicated = true
	if duplicate := postAdmission(handler, body); duplicate.Code != http.StatusOK {
		t.Fatalf("duplicate POST = %d/%s", duplicate.Code, duplicate.Body)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/sessions/"+apiSessionID+"/events", nil)
	request.Header.Set("Accept", "text/event-stream")
	replayed := httptest.NewRecorder()
	handler.ServeHTTP(replayed, request)
	if replayed.Code != http.StatusOK || len(candidate.reads) != 1 ||
		!strings.Contains(replayed.Body.String(), "id: 1\nevent: turn.accepted\n") {
		t.Fatalf("authoritative SSE = %d/%s, reads %d", replayed.Code, replayed.Body, len(candidate.reads))
	}
	if candidate.reads[0].Authorization.Operation != platformapi.OperationReadEvents || len(candidate.admissions) != 2 {
		t.Fatal("SSE did not retain its separate authorized read boundary")
	}
}

func TestAuthoritativeTurnAuthenticationAndAuthorizationPrecedeStoreIO(t *testing.T) {
	for _, unauthenticated := range []bool{true, false} {
		t.Run(map[bool]string{true: "authentication", false: "authorization"}[unauthenticated], func(t *testing.T) {
			authorizations := 0
			service, events, candidate, _ := admissionFixture(t, func(_ context.Context, _ platformapi.AuthorizationRequest) (platformapi.AuthorizationPermit, error) {
				authorizations++
				return platformapi.AuthorizationPermit{}, errors.New("private authorization detail")
			})
			authenticator := &requestAuthenticator{principal: stateEventPrincipal}
			if unauthenticated {
				authenticator.err = errors.New("private bearer detail")
			}
			handler := admissionHTTP(t, service, events, authenticator)
			response := postAdmission(handler, `{"messages":[{"role":"user","content":"hello"}]}`)
			wanted := http.StatusForbidden
			if unauthenticated {
				wanted = http.StatusUnauthorized
			}
			if response.Code != wanted || len(candidate.admissions) != 0 || len(candidate.reads) != 0 || strings.Contains(response.Body.String(), "private") {
				t.Fatalf("denied POST = %d/%s, I/O %d/%d", response.Code, response.Body, len(candidate.admissions), len(candidate.reads))
			}
			if unauthenticated && authorizations != 0 {
				t.Fatal("unauthenticated request reached authorization")
			}
		})
	}
}

func TestAuthoritativeTurnServiceRejectsUnverifiedOrDifferentDomainEvents(t *testing.T) {
	service, events, _, config := admissionFixture(t, nil)
	for _, mutate := range []func(*platformapi.SessionTurnServiceConfig){
		func(config *platformapi.SessionTurnServiceConfig) {
			config.Store = dependency.Verified[platformapi.SessionTurnStore]{}
		},
		func(config *platformapi.SessionTurnServiceConfig) {
			config.SessionEvents = dependency.Verified[platformapi.SessionEventPageReader]{}
		},
	} {
		invalid := config
		mutate(&invalid)
		if _, err := platformapi.NewSessionTurnService(invalid); !errors.Is(err, platformapi.ErrRepositoryNotDurable) {
			t.Fatalf("unverified constructor = %v", err)
		}
	}
	// A valid read-only proof without the writer's atomic public-admission group
	// cannot be substituted after constructing the turn service.
	otherEvents := newAuthoritativeHTTPEventService(t, &authoritativeHTTPReader{})
	authenticator := &requestAuthenticator{principal: stateEventPrincipal}
	for _, config := range []platformapi.HTTPConfig{
		{TurnAdmitter: service, Authenticator: authenticator, MaximumBodyBytes: 4096},
		{TurnAdmitter: service, SessionEvents: otherEvents, Authenticator: authenticator, MaximumBodyBytes: 4096},
	} {
		if _, err := platformapi.NewHTTPHandler(config); !errors.Is(err, platformapi.ErrRepositoryNotDurable) {
			t.Fatalf("unbound events HTTP constructor = %v", err)
		}
	}
	var nilService *platformapi.SessionTurnService
	for _, admitter := range []platformapi.TurnAdmitter{nil, nilService} {
		if _, err := platformapi.NewHTTPHandler(platformapi.HTTPConfig{
			TurnAdmitter: admitter, SessionEvents: events, Authenticator: authenticator, MaximumBodyBytes: 4096,
		}); !errors.Is(err, platformapi.ErrInvalidConfig) {
			t.Fatalf("nil admission HTTP constructor = %v", err)
		}
	}
	if _, err := platformapi.NewHTTPHandler(platformapi.HTTPConfig{
		Service: legacyHTTPService(t), TurnAdmitter: service, SessionEvents: events,
		Authenticator: authenticator, MaximumBodyBytes: 4096,
	}); !errors.Is(err, platformapi.ErrInvalidConfig) {
		t.Fatalf("ambiguous legacy/authoritative constructor = %v", err)
	}
}

func TestAuthoritativeTurnSnapshotsMessagesBeforeAuthorizationAndHonorsCancellation(t *testing.T) {
	messages := []platformapi.Message{{Role: "user", Content: "original"}}
	service, _, candidate, _ := admissionFixture(t, func(_ context.Context, request platformapi.AuthorizationRequest) (platformapi.AuthorizationPermit, error) {
		messages[0].Content = "mutated by caller while authorizing"
		return admissionPermit(request), nil
	})
	request := platformapi.CreateTurnRequest{Principal: stateEventPrincipal, SessionID: apiSessionID, IdempotencyKey: "snapshot-key", Messages: messages}
	if _, err := service.CreateTurn(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	want := canonical.Map{"messages": canonical.Array{canonical.Map{"role": "user", "content": "original"}}}
	if !reflect.DeepEqual(candidate.admissions[0].Input, want) {
		t.Fatal("caller mutation altered authorized input")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancelled, _, cancelledCandidate, _ := admissionFixture(t, func(_ context.Context, request platformapi.AuthorizationRequest) (platformapi.AuthorizationPermit, error) {
		cancel()
		return admissionPermit(request), nil
	})
	if _, err := cancelled.CreateTurn(ctx, request); !errors.Is(err, context.Canceled) || len(cancelledCandidate.admissions) != 0 {
		t.Fatalf("cancelled admission = %v, writes %d", err, len(cancelledCandidate.admissions))
	}
}

func TestAuthoritativeTurnRejectsInvalidInputAndRedactsStoreFailures(t *testing.T) {
	service, events, candidate, config := admissionFixture(t, nil)
	handler := admissionHTTP(t, service, events, &requestAuthenticator{principal: stateEventPrincipal})
	for _, body := range []string{
		`{"messages":[]}`, `{"messages":[{"role":"assistant","content":"no"}]}`,
		`{"messages":[{"role":"user","content":"e\u0301"}]}`,
		`{"messages":[{"role":"user","content":"` + strings.Repeat("x", 4097) + `"}]}`,
	} {
		if response := postAdmission(handler, body); response.Code != http.StatusBadRequest || len(candidate.admissions) != 0 {
			t.Fatalf("invalid POST = %d/%s, writes %d", response.Code, response.Body, len(candidate.admissions))
		}
	}
	config.MaximumMessageBytes = 1 << 20
	large, err := platformapi.NewSessionTurnService(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := large.CreateTurn(context.Background(), platformapi.CreateTurnRequest{
		Principal: stateEventPrincipal, SessionID: apiSessionID, IdempotencyKey: "oversize-encoding",
		Messages: []platformapi.Message{{Role: "user", Content: strings.Repeat("x", 1<<20)}},
	}); !errors.Is(err, platformapi.ErrInvalidRequest) || len(candidate.admissions) != 0 {
		t.Fatalf("encoded input limit = %v, writes %d", err, len(candidate.admissions))
	}
	candidate.err = errors.New("private upstream credentials")
	response := postAdmission(handler, `{"messages":[{"role":"user","content":"valid"}]}`)
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "private") {
		t.Fatalf("store failure response = %d/%s", response.Code, response.Body)
	}
}

func TestAuthoritativeTurnRejectsMalformedCommittedAdmission(t *testing.T) {
	for _, result := range []platformapi.SessionTurnAdmissionResult{
		{TurnID: "invalid"},
		{TurnID: apiTurnID, TurnSequence: 9_007_199_254_740_992},
		{TurnID: "turn_BBBBBBBBBBBBBBBBBBBBBBBBBB"},
	} {
		service, _, candidate, _ := admissionFixture(t, nil)
		candidate.result = result
		_, err := service.CreateTurn(context.Background(), platformapi.CreateTurnRequest{
			Principal: stateEventPrincipal, SessionID: apiSessionID, IdempotencyKey: "malformed-response",
			Messages: []platformapi.Message{{Role: "user", Content: "hello"}},
		})
		if !errors.Is(err, platformapi.ErrRepositoryFailure) {
			t.Fatalf("malformed admission response = %#v/%v", result, err)
		}
	}
}
