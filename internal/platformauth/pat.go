// Package platformauth connects public HTTP authentication to the PAT service.
// It does not provide credential storage or attest that an injected store is
// durable; the production composition must verify that dependency separately.
package platformauth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/auth"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/publicsession"
)

// PATAuthenticator is implemented by auth.PATService. Authentication includes
// its atomic credential-version check and audit-outbox commit before returning.
type PATAuthenticator interface {
	Authenticate(context.Context, string, string) (auth.PATPrincipal, error)
}

type Config struct {
	PAT             PATAuthenticator
	CreateTurnScope string
	ReadEventsScope string
}

type Authenticator struct {
	pat             PATAuthenticator
	createTurnScope string
	readEventsScope string
}

var _ publicsession.RequestAuthenticator = (*Authenticator)(nil)
var _ PATAuthenticator = (*auth.PATService)(nil)

func New(config Config) (*Authenticator, error) {
	if config.PAT == nil || !validScope(config.CreateTurnScope) || !validScope(config.ReadEventsScope) || config.CreateTurnScope == config.ReadEventsScope {
		return nil, errors.New("public PAT authentication: invalid configuration")
	}
	value := reflect.ValueOf(config.PAT)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, errors.New("public PAT authentication: invalid configuration")
		}
	}
	return &Authenticator{pat: config.PAT, createTurnScope: config.CreateTurnScope, readEventsScope: config.ReadEventsScope}, nil
}

func (a *Authenticator) Authenticate(ctx context.Context, request *http.Request) (publicsession.Principal, error) {
	if ctx == nil || a == nil || a.pat == nil || request == nil || request.URL == nil {
		return publicsession.Principal{}, auth.ErrInvalidCredential
	}
	if err := ctx.Err(); err != nil {
		return publicsession.Principal{}, err
	}
	parts := strings.Split(request.URL.Path, "/")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "v1" || parts[2] != "sessions" || request.URL.EscapedPath() != request.URL.Path {
		return publicsession.Principal{}, auth.ErrInvalidCredential
	}
	if _, err := identity.Parse(identity.Session, parts[3]); err != nil {
		return publicsession.Principal{}, auth.ErrInvalidCredential
	}
	var scope string
	switch {
	case request.Method == http.MethodPost && parts[4] == "turns":
		scope = a.createTurnScope
	case request.Method == http.MethodGet && parts[4] == "events":
		scope = a.readEventsScope
	default:
		return publicsession.Principal{}, auth.ErrInvalidCredential
	}
	var headers []string
	for name, values := range request.Header {
		if strings.EqualFold(name, "Authorization") {
			headers = append(headers, values...)
		}
	}
	if len(headers) != 1 {
		return publicsession.Principal{}, auth.ErrInvalidCredential
	}
	// The only accepted transport is one Authorization header with one PAT.
	// Cookies, query parameters, proxy identity headers and Basic auth cannot
	// create a principal through this API adapter.
	scheme, token, ok := strings.Cut(headers[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || len(token) != 47 || !strings.HasPrefix(token, "pat_") {
		return publicsession.Principal{}, auth.ErrInvalidCredential
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token[4:])
	if err != nil || len(raw) != auth.TokenEntropyBytes || base64.RawURLEncoding.EncodeToString(raw) != token[4:] {
		clear(raw)
		return publicsession.Principal{}, auth.ErrInvalidCredential
	}
	clear(raw)
	principal, err := a.pat.Authenticate(ctx, token, scope)
	if err != nil {
		return publicsession.Principal{}, auth.ErrInvalidCredential
	}
	if _, err := identity.Parse(identity.Tenant, principal.TenantID); err != nil {
		return publicsession.Principal{}, auth.ErrInvalidCredential
	}
	if _, err := identity.Parse(identity.Subject, principal.UserID); err != nil {
		return publicsession.Principal{}, auth.ErrInvalidCredential
	}
	if principal.PATID == "" {
		return publicsession.Principal{}, auth.ErrInvalidCredential
	}
	return publicsession.Principal{TenantID: principal.TenantID, SubjectID: principal.UserID}, nil
}

func validScope(scope string) bool {
	if scope == "" || len(scope) > 256 || !utf8.ValidString(scope) {
		return false
	}
	for _, char := range scope {
		if unicode.IsSpace(char) || unicode.IsControl(char) {
			return false
		}
	}
	return true
}
