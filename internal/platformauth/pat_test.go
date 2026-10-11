package platformauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/auth"
	"github.com/hancomac/circulusd/internal/identity"
)

type recordingPAT struct {
	principal    auth.PATPrincipal
	err          error
	calls        int
	token, scope string
}

func (p *recordingPAT) Authenticate(_ context.Context, token, scope string) (auth.PATPrincipal, error) {
	p.calls++
	p.token, p.scope = token, scope
	return p.principal, p.err
}

func fixture(t *testing.T) (*Authenticator, *recordingPAT, string) {
	t.Helper()
	tenant, err := identity.New(identity.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := identity.New(identity.Subject)
	if err != nil {
		t.Fatal(err)
	}
	session, err := identity.New(identity.Session)
	if err != nil {
		t.Fatal(err)
	}
	service := &recordingPAT{principal: auth.PATPrincipal{TenantID: tenant.String(), UserID: subject.String(), PATID: "patid_test"}}
	authenticator, err := New(Config{PAT: service, CreateTurnScope: "session:write", ReadEventsScope: "session:read"})
	if err != nil {
		t.Fatal(err)
	}
	return authenticator, service, "/v1/sessions/" + session.String()
}

func TestPATScopesAreBoundToThePublicOperation(t *testing.T) {
	for _, tc := range []struct{ method, suffix, scope string }{
		{http.MethodPost, "/turns", "session:write"},
		{http.MethodGet, "/events", "session:read"},
	} {
		t.Run(tc.scope, func(t *testing.T) {
			a, p, base := fixture(t)
			r := httptest.NewRequest(tc.method, base+tc.suffix, nil)
			r.Header.Set("Authorization", "bEaReR pat_"+strings.Repeat("A", 43))
			principal, err := a.Authenticate(r.Context(), r)
			if err != nil || principal.TenantID != p.principal.TenantID || principal.SubjectID != p.principal.UserID || p.calls != 1 || p.scope != tc.scope || p.token != "pat_"+strings.Repeat("A", 43) {
				t.Fatalf("authentication = %v; calls/scope = %d/%s", err, p.calls, p.scope)
			}
		})
	}
}

func TestMalformedCredentialsAndRoutesNeverReachPATStore(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"missing", func(r *http.Request) { r.Header.Del("Authorization") }},
		{"duplicate", func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) }},
		{"case duplicate", func(r *http.Request) { r.Header["authorization"] = []string{r.Header.Get("Authorization")} }},
		{"basic", func(r *http.Request) { r.Header.Set("Authorization", "Basic password") }},
		{"comma", func(r *http.Request) { r.Header.Add("Authorization", ",Bearer second") }},
		{"tab", func(r *http.Request) { r.Header.Set("Authorization", "Bearer\tpat_"+strings.Repeat("A", 43)) }},
		{"space", func(r *http.Request) { r.Header.Set("Authorization", "Bearer  pat_"+strings.Repeat("A", 43)) }},
		{"oversized", func(r *http.Request) { r.Header.Set("Authorization", "Bearer pat_"+strings.Repeat("A", 10000)) }},
		{"wrong method", func(r *http.Request) { r.Method = http.MethodGet }},
		{"unknown route", func(r *http.Request) { r.URL.Path += "/unknown" }},
		{"invalid session", func(r *http.Request) { r.URL.Path = "/v1/sessions/invalid/turns" }},
		{"escaped route", func(r *http.Request) { r.URL.RawPath = strings.Replace(r.URL.Path, "sessions", "%73essions", 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, p, base := fixture(t)
			r := httptest.NewRequest(http.MethodPost, base+"/turns", nil)
			r.Header.Set("Authorization", "Bearer pat_"+strings.Repeat("A", 43))
			tc.mutate(r)
			if _, err := a.Authenticate(r.Context(), r); !errors.Is(err, auth.ErrInvalidCredential) || p.calls != 0 {
				t.Fatalf("error/calls = %v/%d", err, p.calls)
			}
		})
	}
}

func TestPATFailureAndInvalidPrincipalAreRedacted(t *testing.T) {
	for _, kind := range []string{"store", "tenant", "subject", "pat"} {
		t.Run(kind, func(t *testing.T) {
			a, p, base := fixture(t)
			switch kind {
			case "store":
				p.err = errors.New("secret credential details")
			case "tenant":
				p.principal.TenantID = "invalid"
			case "subject":
				p.principal.UserID = p.principal.TenantID
			case "pat":
				p.principal.PATID = ""
			}
			r := httptest.NewRequest(http.MethodPost, base+"/turns", nil)
			r.Header.Set("Authorization", "Bearer pat_"+strings.Repeat("A", 43))
			principal, err := a.Authenticate(r.Context(), r)
			if err != auth.ErrInvalidCredential || principal.TenantID != "" || principal.SubjectID != "" {
				t.Fatalf("unsafe error/principal: %v", err)
			}
		})
	}
}

func TestPATConfigurationAndCanceledRequestFailClosed(t *testing.T) {
	var typedNil *recordingPAT
	for _, cfg := range []Config{
		{}, {PAT: typedNil, CreateTurnScope: "write", ReadEventsScope: "read"},
		{PAT: &recordingPAT{}, CreateTurnScope: "same", ReadEventsScope: "same"},
		{PAT: &recordingPAT{}, CreateTurnScope: "write\n", ReadEventsScope: "read"},
	} {
		if _, err := New(cfg); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	a, p, base := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodPost, base+"/turns", nil)
	r.Header.Set("Authorization", "Bearer pat_"+strings.Repeat("A", 43))
	if _, err := a.Authenticate(ctx, r); !errors.Is(err, context.Canceled) || p.calls != 0 {
		t.Fatalf("error/calls = %v/%d", err, p.calls)
	}
	if _, err := a.Authenticate(nil, r); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := a.Authenticate(context.Background(), nil); err == nil {
		t.Fatal("nil request accepted")
	}
}
