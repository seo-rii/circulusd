package platformapi

import (
	"net/http"

	"github.com/hancomac/circulusd/internal/publicsession"
)

type RequestAuthenticator = publicsession.RequestAuthenticator
type TurnAdmitter = publicsession.TurnAdmitter
type HTTPHandler = publicsession.HTTPHandler

// HTTPConfig preserves the legacy concrete Service option. The implementation
// is shared with the production HTTP handler in publicsession.
type HTTPConfig struct {
	Service          *Service
	TurnAdmitter     TurnAdmitter
	SessionEvents    *SessionEventService
	Authenticator    RequestAuthenticator
	MaximumBodyBytes int64
	NewRequestID     func() (string, error)
}

var _ TurnAdmitter = (*Service)(nil)

func NewHTTPHandler(config HTTPConfig) (*HTTPHandler, error) {
	pure := publicsession.HTTPConfig{
		TurnAdmitter: config.TurnAdmitter, SessionEvents: config.SessionEvents,
		Authenticator: config.Authenticator, MaximumBodyBytes: config.MaximumBodyBytes,
		NewRequestID: config.NewRequestID,
	}
	if config.Service != nil {
		pure.Service = config.Service
	}
	return publicsession.NewHTTPHandler(pure)
}

func writeServiceError(response http.ResponseWriter, err error) {
	publicsession.WriteServiceError(response, err)
}
