package stateappclient

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

const (
	brokerIngressPath        = "/circulusd/state/v1/session-broker:execute"
	brokerIngressContentType = "application/vnd.circulusd.state-broker-ingress+cbor"
	brokerIngressProtocol    = "circulus.state-broker-ingress.v1alpha1"
	brokerIngressDescriptor  = "circulus.state-broker-ingress.v1alpha1|major=1|minor=0|typed-session-broker|operations=read-turn,lookup-operation,acquire-step,commit-step,dispatch,claim-start,confirm,settle,block,prepare-retry,settle-recovery|fields=protocol,major,minor,schemaDigest,requestId,sentAtUnixMs,tenantId,workspaceId,sessionId,actorSubjectId,expectedAuthorizationGeneration,operation,body|maxBytes=9437184|maxDepth=72|maxItems=100000"
	brokerRequestMACDomain   = "circulusd.state-broker-ingress.request.v1"
	brokerResponseMACDomain  = "circulusd.state-broker-ingress.response.v1"
)

var brokerIngressSchemaDigest = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(brokerIngressDescriptor)))

// SessionBrokerConfigured reports only local transport configuration. It is
// never production evidence or a durability/readiness grant.
func (client *Client) SessionBrokerConfigured() bool {
	if client == nil {
		return false
	}
	client.lifecycleMu.Lock()
	defer client.lifecycleMu.Unlock()
	return !client.closed && client.brokerKeyID != "" && len(client.brokerRequestKey) == 32 && len(client.brokerResponseKey) == 32
}

// BrokerScope binds every read, archived receipt lookup and mutation to one
// immutable Session scope. The state owner compares it before archive I/O.
type BrokerScope struct {
	TenantID                        string
	WorkspaceID                     string
	SessionID                       string
	ActorSubjectID                  string
	ExpectedAuthorizationGeneration uint64
}

type BrokerRequest struct {
	Scope     BrokerScope
	Operation string
	Body      canonical.Map
}

var brokerBodyFields = map[string][]string{
	"read-turn":        {},
	"lookup-operation": {"kind", "operationKey", "operationDigest"},
	"acquire-step":     {"snapshot", "operationKey", "nowUnixMs", "budget"},
	"commit-step":      {"snapshot", "operationKey", "requestDigest", "permitOpaque", "nowUnixMs", "step"},
	"dispatch":         {"snapshot", "key", "operationKey", "operationDigest", "preparationOpaque", "providerRequestId", "providerRouteDigest", "nowUnixMs", "deadlineUnixMs"},
	"claim-start":      {"snapshot", "key", "dispatchOpaque", "commandDigest", "nowUnixMs"},
	"confirm":          {"snapshot", "key", "operationKey", "operationDigest", "dispatchAttempt", "providerRequestId", "providerRouteDigest", "externalCommitId", "resultRef"},
	"settle":           {"snapshot", "key", "operationKey", "operationDigest", "dispatchAttempt", "externalCommitId", "resultRef", "error", "settlement"},
	"block":            {"snapshot", "key", "operationKey", "operationDigest", "reason"},
	"prepare-retry":    {"snapshot", "key", "operationKey", "operationDigest", "nowUnixMs", "deadlineUnixMs", "userConfirmed"},
	"settle-recovery":  {"snapshot", "key", "operationKey", "operationDigest", "kind", "error"},
}

// ExecuteSessionBroker accepts only the fixed broker operation union. It never
// exposes arbitrary Session commands, initialization, or capability issuance.
// Transport success is not durability qualification; the adapter still requires
// independent production verification of this same client and transaction domain.
func (client *Client) ExecuteSessionBroker(ctx context.Context, request BrokerRequest) (canonical.Value, error) {
	if ctx == nil {
		return nil, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if client == nil || client.httpClient == nil || client.brokerKeyID == "" {
		return nil, ErrInvalidConfig
	}
	for kind, value := range map[identity.Kind]string{identity.Tenant: request.Scope.TenantID, identity.Workspace: request.Scope.WorkspaceID, identity.Session: request.Scope.SessionID, identity.Subject: request.Scope.ActorSubjectID} {
		if _, err := identity.Parse(kind, value); err != nil {
			return nil, ErrInvalidRequest
		}
	}
	if request.Scope.ExpectedAuthorizationGeneration < 1 || request.Scope.ExpectedAuthorizationGeneration > maximumSharedInteger {
		return nil, ErrInvalidRequest
	}
	fields, ok := brokerBodyFields[request.Operation]
	if !ok || request.Body == nil || len(request.Body) != len(fields) {
		return nil, ErrInvalidRequest
	}
	for _, field := range fields {
		if _, ok := request.Body[field]; !ok {
			return nil, ErrInvalidRequest
		}
	}
	options := canonical.Options{MaxBytes: 9 << 20, MaxDepth: 72, MaxItems: 100_000}
	encoded, err := canonical.Encode(request.Body, options)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	owned, err := canonical.Decode(encoded, options)
	if err != nil || !brokerSharedIntegers(owned) {
		return nil, ErrInvalidRequest
	}
	body := owned.(canonical.Map)
	return client.invokeAuthenticatedIngress(ctx, authenticatedIngressContract{
		path: brokerIngressPath, contentType: brokerIngressContentType,
		requestMACDomain: brokerRequestMACDomain, responseMACDomain: brokerResponseMACDomain,
		hostSchemaDigest: dispatchStartHostSchemaDigest, requestOptions: options,
		maximumResponseBytes: (9 << 20) + 65_536, brokerCredentials: true,
	}, func(requestID string, sentAt int64) canonical.Map {
		return canonical.Map{"protocol": brokerIngressProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": brokerIngressSchemaDigest,
			"requestId": requestID, "sentAtUnixMs": sentAt, "tenantId": request.Scope.TenantID, "workspaceId": request.Scope.WorkspaceID,
			"sessionId": request.Scope.SessionID, "actorSubjectId": request.Scope.ActorSubjectID,
			"expectedAuthorizationGeneration": request.Scope.ExpectedAuthorizationGeneration, "operation": request.Operation, "body": body}
	})
}

func brokerSharedIntegers(value canonical.Value) bool {
	switch v := value.(type) {
	case int64:
		return v >= -int64(maximumSharedInteger) && v <= int64(maximumSharedInteger)
	case uint64:
		return v <= maximumSharedInteger
	case canonical.Array:
		for _, child := range v {
			if !brokerSharedIntegers(child) {
				return false
			}
		}
	case canonical.Map:
		for _, child := range v {
			if !brokerSharedIntegers(child) {
				return false
			}
		}
	}
	return true
}
