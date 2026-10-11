package platformapi

import "github.com/hancomac/circulusd/internal/publicsession"

type SessionTurnAdmission = publicsession.SessionTurnAdmission
type SessionTurnAdmissionResult = publicsession.SessionTurnAdmissionResult
type SessionTurnStore = publicsession.SessionTurnStore
type SessionTurnServiceConfig = publicsession.SessionTurnServiceConfig
type SessionTurnService = publicsession.SessionTurnService

func NewSessionTurnService(config SessionTurnServiceConfig) (*SessionTurnService, error) {
	return publicsession.NewSessionTurnService(config)
}
