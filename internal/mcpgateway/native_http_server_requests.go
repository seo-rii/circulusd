package mcpgateway

import (
	"context"
	"encoding/json"
	"reflect"
)

// Every denial, including those received before initialize completes, is bound
// to the exact persisted invocation and audited before its error is sent.
func (provider *nativeHTTPProvider) serverResponse(ctx context.Context, expected nativeWireInvocation, request mcpRPCMessage) ([]byte, error) {
	response := mcpRPCMessage{JSONRPC: "2.0", ID: request.ID}
	paramsValid := len(request.Params) == 0
	if !paramsValid {
		var params map[string]json.RawMessage
		paramsValid = json.Unmarshal(request.Params, &params) == nil && params != nil && len(params) == 0
	}
	if request.Method == "ping" && paramsValid {
		response.Result = json.RawMessage(`{}`)
		return json.Marshal(response)
	}
	envelope, err := nativeStateOperation(ctx, provider.factory.repository, func(state *nativeRepositoryState) (AuditEnvelope, error) {
		row, found := state.WireInvocations[nativeWireKey(provider.id, expected.Scope.InvocationID, expected.Attempt)]
		if !found || !reflect.DeepEqual(row, expected) || row.CancellationClaimed || !provider.factory.currentGrant(state, row.Scope, row.RequestDigest, "mcp.tools.call", false) {
			return AuditEnvelope{}, ErrStaleAuthority
		}
		return state.Repository.AppendAudit(ctx, AuditEvent{TenantID: row.Scope.TenantID, UserID: row.Scope.UserID, SessionID: row.Scope.SessionID, TurnID: row.Scope.TurnID, InvocationID: row.Scope.InvocationID, ServerID: row.Server.ServerID,
			Method: normalizedServerRequestAuditMethod(request.Method), Decision: "denied", Reason: "server-initiated method is not allowed"})
	})
	if err != nil {
		return nil, err
	}
	if err := provider.factory.validator.deliverAuditEnvelope(ctx, envelope); err != nil {
		return nil, err
	}
	code, message := jsonRPCMethodNotFound, "Method not found"
	if request.Method == "ping" {
		code, message = jsonRPCInvalidParams, "Invalid params"
	}
	response.Error, _ = json.Marshal(map[string]any{"code": code, "message": message})
	return json.Marshal(response)
}
