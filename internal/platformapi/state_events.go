package platformapi

import "github.com/hancomac/circulusd/internal/publicsession"

type SessionEventPageReader = publicsession.SessionEventPageReader
type AuthorizedSessionEventPageRequest = publicsession.AuthorizedSessionEventPageRequest
type ReadSessionEventPageRequest = publicsession.ReadSessionEventPageRequest
type SessionEffectService = publicsession.SessionEffectService

const (
	SessionEffectModel        = publicsession.SessionEffectModel
	SessionEffectWorkspace    = publicsession.SessionEffectWorkspace
	SessionEffectExecutor     = publicsession.SessionEffectExecutor
	SessionEffectMCP          = publicsession.SessionEffectMCP
	SessionEffectArtifact     = publicsession.SessionEffectArtifact
	SessionEffectExternalTool = publicsession.SessionEffectExternalTool
)

type SessionSettlementKind = publicsession.SessionSettlementKind

const (
	SessionSettlementSuccess            = publicsession.SessionSettlementSuccess
	SessionSettlementError              = publicsession.SessionSettlementError
	SessionSettlementInterruptedUnknown = publicsession.SessionSettlementInterruptedUnknown
	SessionSettlementAbandoned          = publicsession.SessionSettlementAbandoned
)

type SessionPublicEvent = publicsession.SessionPublicEvent
type SessionPublicEventSnapshot = publicsession.SessionPublicEventSnapshot
type SessionPublicEventPage = publicsession.SessionPublicEventPage
type SessionEventServiceConfig = publicsession.SessionEventServiceConfig
type SessionEventService = publicsession.SessionEventService

func NewSessionEventService(config SessionEventServiceConfig) (*SessionEventService, error) {
	return publicsession.NewSessionEventService(config)
}
