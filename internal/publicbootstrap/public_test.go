package publicbootstrap_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/auth"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	contract "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/publicbootstrap"
	"github.com/hancomac/circulusd/internal/sessionadmission"
	"github.com/hancomac/circulusd/internal/sessionevent"
	"github.com/hancomac/circulusd/internal/stateappadmission"
)

// Only test sources mint these proofs. These constructor and HTTP tests do not
// attest any real native credential store, ACL registry or engine.
type credentials struct {
	*contract.ProductionProofs
	mu      sync.Mutex
	records map[string]auth.PATRecord
	audits  []auth.PATAuditEvent
	err     error
}

func (store *credentials) CreatePAT(_ context.Context, record auth.PATRecord, event auth.PATAuditEvent) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.err != nil {
		return store.err
	}
	if _, ok := store.records[record.ID]; ok {
		return auth.ErrPATConflict
	}
	store.records[record.ID] = record
	store.audits = append(store.audits, event)
	return nil
}
func (store *credentials) LoadPATByID(_ context.Context, id string) (auth.PATRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.err != nil {
		return auth.PATRecord{}, store.err
	}
	record, ok := store.records[id]
	if !ok {
		return auth.PATRecord{}, auth.ErrPATNotFound
	}
	return record, nil
}
func (store *credentials) LoadPATByDigest(_ context.Context, digest string) (auth.PATRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.err != nil {
		return auth.PATRecord{}, store.err
	}
	for _, record := range store.records {
		if record.Digest == digest {
			return record, nil
		}
	}
	return auth.PATRecord{}, auth.ErrPATNotFound
}
func (store *credentials) CommitPAT(_ context.Context, id string, version uint64, next auth.PATRecord, event auth.PATAuditEvent) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.err != nil {
		return store.err
	}
	if store.records[id].Version != version {
		return auth.ErrPATVersionConflict
	}
	store.records[id] = next
	store.audits = append(store.audits, event)
	return nil
}

type state struct {
	*contract.ProductionProofs
	principal      sessionevent.Principal
	sessionID      string
	admission      dependency.Verified[sessionadmission.SessionTurnStore]
	reader         dependency.Verified[sessionevent.SessionEventPageReader]
	factories      int
	admissions     []sessionadmission.SessionTurnAdmission
	authorizations []sessionevent.AuthorizationRequest
	reads          []sessionevent.AuthorizedSessionEventPageRequest
	wait           chan struct{}
}

func (source *state) SessionEventReader() dependency.Verified[sessionevent.SessionEventPageReader] {
	return source.reader
}
func (source *state) SessionAdmission(ctx context.Context, _ stateappadmission.PlannerConfig) (dependency.Verified[sessionadmission.SessionTurnStore], error) {
	source.factories++
	return source.admission, ctx.Err()
}
func (source *state) Authorize(ctx context.Context, request sessionevent.AuthorizationRequest) (sessionevent.AuthorizationPermit, error) {
	source.authorizations = append(source.authorizations, request)
	if source.wait != nil {
		close(source.wait)
		<-ctx.Done()
		return sessionevent.AuthorizationPermit{}, ctx.Err()
	}
	if request.Principal != source.principal || request.SessionID != source.sessionID {
		return sessionevent.AuthorizationPermit{}, errors.New("private current ACL diagnostic")
	}
	return sessionevent.AuthorizationPermit{Operation: request.Operation, Principal: request.Principal, SessionID: request.SessionID, AuthorizationGeneration: 7, Proof: sessionevent.OpaqueAuthorizationProof{9}}, nil
}
func (source *state) AdmitTurn(_ context.Context, request sessionadmission.SessionTurnAdmission) (sessionadmission.SessionTurnAdmissionResult, error) {
	source.admissions = append(source.admissions, request)
	return sessionadmission.SessionTurnAdmissionResult{TurnID: source.admissions[0].ProposedTurnID, Activated: true, Deduplicated: len(source.admissions) > 1}, nil
}
func (source *state) ReadSessionEventPage(_ context.Context, request sessionevent.AuthorizedSessionEventPageRequest) (sessionevent.SessionPublicEventPage, error) {
	source.reads = append(source.reads, request)
	id, status := source.admissions[0].ProposedTurnID, sessionevent.TurnActive
	return sessionevent.SessionPublicEventPage{Snapshot: sessionevent.SessionPublicEventSnapshot{SessionID: source.sessionID, ActiveTurnID: &id, TurnStatus: &status, LastEventSequence: 1}, Events: []sessionevent.SessionPublicEvent{{Sequence: 1, Type: sessionevent.EventTurnAccepted, TurnID: id, Status: status}}}, nil
}

type genesis struct{ *contract.ProductionProofs }

func (*genesis) CreateGenesis(context.Context, stateappadmission.GenesisRequest) (*v1.AgentCheckpoint, error) {
	return nil, errors.New("test graph never invokes genesis directly")
}

type fixture struct {
	config publicbootstrap.Config
	state  *state
	store  *credentials
	pat    *auth.PATService
	token  string
	record auth.PATRecord
}

func identifier(t *testing.T, kind identity.Kind) string {
	t.Helper()
	id, err := identity.New(kind)
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}
func newFixture(t *testing.T) fixture {
	t.Helper()
	groups := []dependency.AtomicGroup{publicbootstrap.AtomicACLAuthorization, dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent}
	s := &state{ProductionProofs: contract.NewProductionProofs(t, groups), principal: sessionevent.Principal{TenantID: identifier(t, identity.Tenant), SubjectID: identifier(t, identity.Subject)}, sessionID: identifier(t, identity.Session)}
	s.admission = contract.Verify[sessionadmission.SessionTurnStore](t, s.ProductionProofs, s, groups)
	s.reader = contract.Verify[sessionevent.SessionEventPageReader](t, s.ProductionProofs, s, groups)
	credentialGroups := []dependency.AtomicGroup{publicbootstrap.AtomicCredentialAudit}
	c := &credentials{ProductionProofs: contract.NewProductionProofs(t, credentialGroups), records: make(map[string]auth.PATRecord)}
	now := func() time.Time { return time.Unix(1_900_000_000, 0).UTC() }
	pat, err := auth.NewPATService(auth.PATServiceConfig{Store: c, Now: now, MaximumCASRetries: 4})
	if err != nil {
		t.Fatal(err)
	}
	token, record, err := pat.Issue(context.Background(), s.principal.TenantID, s.principal.SubjectID, []string{"turns:create", "events:read"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	g := &genesis{contract.NewProductionProofs(t, []dependency.AtomicGroup{dependency.AtomicEngineGenesis})}
	config := publicbootstrap.Config{State: s, Genesis: contract.Verify[stateappadmission.GenesisProvider](t, g.ProductionProofs, g, []dependency.AtomicGroup{dependency.AtomicEngineGenesis}), Credentials: contract.Verify[publicbootstrap.CredentialStore](t, c.ProductionProofs, c, credentialGroups), Authorizer: contract.Verify[publicbootstrap.SessionAuthorizer](t, s.ProductionProofs, s, groups), Now: now, IdempotencySecret: []byte(strings.Repeat("s", 32)), CreateTurnScope: "turns:create", ReadEventsScope: "events:read", MaximumCASRetries: 4, MaximumMessageBytes: 4096, MaximumBodyBytes: 8192, MaximumPageEvents: 16, RequestTimeout: time.Second}
	return fixture{config, s, c, pat, token, record}
}
func post(handler http.Handler, sessionID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions/"+sessionID+"/turns", strings.NewReader(`{"messages":[{"role":"user","content":"첫 번째"},{"role":"user","content":"second"}]}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "ordered-input")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func TestQualifiedPublicGraphConnectsPATAdmissionReplayAndSSE(t *testing.T) {
	f := newFixture(t)
	graph, err := publicbootstrap.New(context.Background(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	defer graph.Close()
	clear(f.config.IdempotencySecret)
	for _, want := range []int{http.StatusAccepted, http.StatusOK} {
		response := post(graph, f.state.sessionID, f.token)
		if response.Code != want {
			t.Fatalf("POST=%d/%s", response.Code, response.Body)
		}
	}
	expected := canonical.Map{"messages": canonical.Array{canonical.Map{"role": "user", "content": "첫 번째"}, canonical.Map{"role": "user", "content": "second"}}}
	if !reflect.DeepEqual(f.state.admissions[0].Input, expected) || f.state.admissions[0].KeyDigest != f.state.admissions[1].KeyDigest {
		t.Fatal("public input/idempotency snapshot lost")
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/sessions/"+f.state.sessionID+"/events", nil)
	request.Header.Set("Authorization", "Bearer "+f.token)
	request.Header.Set("Accept", "text/event-stream")
	response := httptest.NewRecorder()
	graph.ServeHTTP(response, request)
	if response.Code != 200 || !strings.Contains(response.Body.String(), "id: 1\nevent: turn.accepted\n") || len(f.state.reads) != 1 {
		t.Fatalf("SSE=%d/%s", response.Code, response.Body)
	}
	if f.state.factories != 1 || len(f.store.audits) != 4 || f.store.audits[3].Scope != "events:read" || f.state.reads[0].Authorization.Operation != sessionevent.OperationReadEvents {
		t.Fatal("actual credential/audit/ACL paths not used")
	}
}

func TestInvalidQualificationFailsBeforeAdmissionFactory(t *testing.T) {
	for _, mutate := range []func(*publicbootstrap.Config){
		func(c *publicbootstrap.Config) {
			c.Credentials = dependency.Verified[publicbootstrap.CredentialStore]{}
		},
		func(c *publicbootstrap.Config) {
			c.Authorizer = dependency.Verified[publicbootstrap.SessionAuthorizer]{}
		},
		func(c *publicbootstrap.Config) { c.Genesis = dependency.Verified[stateappadmission.GenesisProvider]{} },
		func(c *publicbootstrap.Config) { c.CreateTurnScope = c.ReadEventsScope },
		func(c *publicbootstrap.Config) { c.IdempotencySecret = nil },
		func(c *publicbootstrap.Config) { c.RequestTimeout = 0 },
	} {
		f := newFixture(t)
		mutate(&f.config)
		if graph, err := publicbootstrap.New(context.Background(), f.config); err == nil || graph != nil || f.state.factories != 0 {
			t.Fatalf("invalid construction=%v, admission factory calls=%d", err, f.state.factories)
		}
	}
}

func TestAuthenticationAndCurrentACLFailuresPreventSessionIO(t *testing.T) {
	for _, scenario := range []string{"invalid-token", "wrong-scope", "other-principal", "audit-failure", "revoked"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			graph, err := publicbootstrap.New(context.Background(), f.config)
			if err != nil {
				t.Fatal(err)
			}
			defer graph.Close()
			token := f.token
			want := http.StatusUnauthorized
			switch scenario {
			case "invalid-token":
				token = "invalid"
			case "wrong-scope":
				token, _, err = f.pat.Issue(context.Background(), f.state.principal.TenantID, f.state.principal.SubjectID, []string{"events:read"}, time.Hour)
			case "other-principal":
				token, _, err = f.pat.Issue(context.Background(), f.state.principal.TenantID, identifier(t, identity.Subject), []string{"turns:create"}, time.Hour)
				want = http.StatusForbidden
			case "audit-failure":
				f.store.err = errors.New("private audit storage diagnostic")
			case "revoked":
				_, err = f.pat.Revoke(context.Background(), f.record.ID, f.record.Version)
			}
			if err != nil {
				t.Fatal(err)
			}
			response := post(graph, f.state.sessionID, token)
			if response.Code != want || len(f.state.admissions) != 0 || len(f.state.reads) != 0 || strings.Contains(response.Body.String(), "private") {
				t.Fatalf("denial=%d/%s, admissions=%d", response.Code, response.Body, len(f.state.admissions))
			}
			if want == http.StatusUnauthorized && len(f.state.authorizations) != 0 {
				t.Fatal("authentication denial reached ACL")
			}
		})
	}
}

func TestCloseCancelsActiveAuthorizationAndRejectsLaterHTTP(t *testing.T) {
	f := newFixture(t)
	f.state.wait = make(chan struct{})
	graph, err := publicbootstrap.New(context.Background(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); post(graph, f.state.sessionID, f.token) }()
	select {
	case <-f.state.wait:
	case <-time.After(time.Second):
		t.Fatal("authorization did not start")
	}
	graph.Close()
	graph.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close did not cancel active request")
	}
	if response := post(graph, f.state.sessionID, f.token); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed=%d", response.Code)
	}
	if len(f.state.admissions) != 0 {
		t.Fatal("canceled authorization admitted turn")
	}
}

type stalledBody struct {
	closed chan struct{}
	once   sync.Once
}

func (body *stalledBody) Read([]byte) (int, error) { <-body.closed; return 0, context.DeadlineExceeded }
func (body *stalledBody) Close() error             { body.once.Do(func() { close(body.closed) }); return nil }

func TestRequestTimeoutClosesStalledBodyBeforeSessionIO(t *testing.T) {
	f := newFixture(t)
	f.config.RequestTimeout = 25 * time.Millisecond
	graph, err := publicbootstrap.New(context.Background(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	defer graph.Close()
	body := &stalledBody{closed: make(chan struct{})}
	request := httptest.NewRequest(http.MethodPost, "/v1/sessions/"+f.state.sessionID+"/turns", body)
	request.Header.Set("Authorization", "Bearer "+f.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "stalled-input")
	done := make(chan struct{})
	go func() { defer close(done); graph.ServeHTTP(httptest.NewRecorder(), request) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		body.Close()
		t.Fatal("request timeout did not interrupt body read")
	}
	if len(f.state.admissions) != 0 || len(f.state.authorizations) != 0 {
		t.Fatal("timed-out body reached Session authority")
	}
}

func TestMissingAtomicCapabilitiesAndUnqualifiedFactoryOutputFailClosed(t *testing.T) {
	t.Run("credential-audit", func(t *testing.T) {
		f := newFixture(t)
		groups := []dependency.AtomicGroup{dependency.AtomicCommandReceipt}
		c := &credentials{ProductionProofs: contract.NewProductionProofs(t, groups), records: map[string]auth.PATRecord{}}
		f.config.Credentials = contract.Verify[publicbootstrap.CredentialStore](t, c.ProductionProofs, c, groups)
		if graph, err := publicbootstrap.New(context.Background(), f.config); err == nil || graph != nil || f.state.factories != 0 {
			t.Fatal("credential proof without atomic audit accepted")
		}
	})
	t.Run("current-acl", func(t *testing.T) {
		f := newFixture(t)
		groups := []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent}
		s := &state{ProductionProofs: contract.NewProductionProofs(t, groups)}
		f.config.Authorizer = contract.Verify[publicbootstrap.SessionAuthorizer](t, s.ProductionProofs, s, groups)
		if graph, err := publicbootstrap.New(context.Background(), f.config); err == nil || graph != nil || f.state.factories != 0 {
			t.Fatal("authorizer proof without current ACL accepted")
		}
	})
	t.Run("reader", func(t *testing.T) {
		f := newFixture(t)
		f.state.reader = dependency.Verified[sessionevent.SessionEventPageReader]{}
		if graph, err := publicbootstrap.New(context.Background(), f.config); err == nil || graph != nil || f.state.factories != 0 {
			t.Fatal("unqualified event reader accepted")
		}
	})
	t.Run("admission-output", func(t *testing.T) {
		f := newFixture(t)
		f.state.admission = dependency.Verified[sessionadmission.SessionTurnStore]{}
		if graph, err := publicbootstrap.New(context.Background(), f.config); err == nil || graph != nil || f.state.factories != 1 {
			t.Fatal("unqualified admission factory output accepted")
		}
	})
	t.Run("canceled", func(t *testing.T) {
		f := newFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if graph, err := publicbootstrap.New(ctx, f.config); !errors.Is(err, context.Canceled) || graph != nil || f.state.factories != 0 {
			t.Fatal("canceled bootstrap reached admission factory")
		}
	})
}
