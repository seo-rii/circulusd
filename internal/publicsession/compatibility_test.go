package publicsession_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/hancomac/circulusd/internal/platformapi"
	"github.com/hancomac/circulusd/internal/publicsession"
	"github.com/hancomac/circulusd/internal/sessionadmission"
	"github.com/hancomac/circulusd/internal/sessionevent"
)

// Assignment in both directions requires aliases, rather than merely equal
// struct layouts; callers retain the same request/result and service identity.
var (
	_ publicsession.CreateTurnRequest    = platformapi.CreateTurnRequest{}
	_ platformapi.CreateTurnRequest      = publicsession.CreateTurnRequest{}
	_ sessionadmission.CreateTurnResult  = platformapi.CreateTurnResult{}
	_ platformapi.CreateTurnResult       = sessionadmission.CreateTurnResult{}
	_ publicsession.Message              = platformapi.Message{}
	_ platformapi.Message                = publicsession.Message{}
	_ publicsession.Turn                 = platformapi.Turn{}
	_ platformapi.Turn                   = publicsession.Turn{}
	_ *publicsession.SessionTurnService  = (*platformapi.SessionTurnService)(nil)
	_ *platformapi.SessionTurnService    = (*publicsession.SessionTurnService)(nil)
	_ *publicsession.SessionEventService = (*platformapi.SessionEventService)(nil)
	_ *platformapi.SessionEventService   = (*publicsession.SessionEventService)(nil)
	_ *publicsession.HTTPHandler         = (*platformapi.HTTPHandler)(nil)
	_ *platformapi.HTTPHandler           = (*publicsession.HTTPHandler)(nil)
	_ publicsession.RequestAuthenticator = legacyAuthenticator{}
)

type legacyAdmitter struct{}

func (*legacyAdmitter) CreateTurn(context.Context, platformapi.CreateTurnRequest) (platformapi.CreateTurnResult, error) {
	return platformapi.CreateTurnResult{}, platformapi.ErrAccessDenied
}

type legacyAuthenticator struct{}

func (legacyAuthenticator) Authenticate(context.Context, *http.Request) (platformapi.Principal, error) {
	return platformapi.Principal{}, platformapi.ErrAccessDenied
}

func TestLegacyNilServiceDoesNotSupplyAnInterface(t *testing.T) {
	var service *platformapi.Service
	config := platformapi.HTTPConfig{
		Service: service, TurnAdmitter: &legacyAdmitter{},
		Authenticator: legacyAuthenticator{}, MaximumBodyBytes: 1024,
	}
	if handler, err := platformapi.NewHTTPHandler(config); err != nil || handler == nil {
		t.Fatalf("legacy nil concrete service with admitter: handler=%v err=%v", handler, err)
	}
	config.TurnAdmitter = (*legacyAdmitter)(nil)
	if _, err := platformapi.NewHTTPHandler(config); err != platformapi.ErrInvalidConfig {
		t.Fatalf("typed nil admitter: %v", err)
	}
	config.Service = &platformapi.Service{}
	config.TurnAdmitter = &legacyAdmitter{}
	if _, err := platformapi.NewHTTPHandler(config); err != platformapi.ErrInvalidConfig {
		t.Fatalf("both admission options: %v", err)
	}
}

func TestPublicErrorSentinelsRetainIdentity(t *testing.T) {
	pairs := [][2]error{
		{platformapi.ErrInvalidConfig, publicsession.ErrInvalidConfig},
		{platformapi.ErrInvalidRequest, publicsession.ErrInvalidRequest},
		{platformapi.ErrAccessDenied, publicsession.ErrAccessDenied},
		{platformapi.ErrSessionNotFound, publicsession.ErrSessionNotFound},
		{platformapi.ErrTurnNotFound, sessionadmission.ErrTurnNotFound},
		{platformapi.ErrIdempotencyConflict, publicsession.ErrIdempotencyConflict},
		{platformapi.ErrSequenceConflict, publicsession.ErrSequenceConflict},
		{platformapi.ErrInvalidCursor, sessionevent.ErrInvalidCursor},
		{platformapi.ErrStaleAuthority, publicsession.ErrStaleAuthority},
		{platformapi.ErrInvalidTransition, sessionadmission.ErrInvalidTransition},
		{platformapi.ErrRepositoryFailure, publicsession.ErrRepositoryFailure},
		{platformapi.ErrRepositoryNotDurable, publicsession.ErrRepositoryNotDurable},
	}
	for _, pair := range pairs {
		if pair[0] != pair[1] {
			t.Fatalf("public errors have different identities: %v / %v", pair[0], pair[1])
		}
	}
}
