package mcpgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sync"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
)

// Wire state is authoritative only inside the exact native transaction. A
// claim survives process loss; a missing response never authorizes resending.
type nativeWireInvocation struct {
	ProviderID           string
	Scope                ValidatedAuthority
	Server               ServerDescriptor
	ToolName             string
	RequestDigest        Digest
	Attempt              uint32
	Dispatch             DispatchPermit
	Session              nativeWireSession
	ConnectionGeneration uint64
	ConnectionRef        string
	Receipt              StartNegotiationReceipt
	Start                ProviderStartPermit
	StartClaimed         bool
	CancellationClaimed  bool
	ProviderRequestID    string
	TerminalStatus       LedgerStatus
	TerminalJSON         []byte
}

// This complete broker binding contains no bearer or private Go seal. The
// provider verifies Session.Open before constructing it and persists every
// immutable dispatch fact, including parent/ordinal, deadline and start event.
type nativeWireSession struct {
	Proof                 Digest
	CommandDigest         Digest
	RouteDigest           Digest
	DispatchAttempt       uint64
	StartEventSequence    uint64
	DispatchEventSequence uint64
	PlatformRequestID     identity.ID
	Operation             string
	ParentOperationID     identity.ID
	ParentOperation       string
	Ordinal               uint64
	ReplayPolicy          broker.ReplayPolicy
	DeadlineUnixNano      int64
}

func nativeWireKey(provider string, invocation identity.ID, attempt uint32) string {
	return fmt.Sprintf("%s\x00%s\x00%d", provider, invocation.String(), attempt)
}
func nativeWireRequestID(kind string, digest Digest, key string) string {
	return fmt.Sprintf("%x", sha256.Sum256(append(append([]byte(kind+"\x00"), digest[:]...), []byte(key)...)))
}

func validNativeWireInvocation(row nativeWireInvocation) bool {
	if row.ProviderID == "" || !validScope(row.Scope) || row.RequestDigest == (Digest{}) || row.Attempt == 0 || row.ToolName == "" || row.ConnectionGeneration == 0 ||
		!validMCPSessionID(row.ConnectionRef) || !row.Dispatch.Durable || row.Dispatch.Scope != row.Scope || row.Dispatch.RequestDigest != row.RequestDigest || row.Dispatch.InvocationID != row.Scope.InvocationID || row.Dispatch.ProviderID != row.ProviderID || row.Dispatch.Attempt != row.Attempt {
		return false
	}
	if row.StartClaimed && row.Start.Proof == (OpaqueProviderStartPermit{}) {
		return false
	}
	if row.Receipt != (StartNegotiationReceipt{}) && (row.Receipt.Scope != row.Scope || row.Receipt.Server != row.Server || row.Receipt.RequestDigest != row.RequestDigest || row.Receipt.Attempt != row.Attempt || row.Receipt.ConnectionGeneration != row.ConnectionGeneration) {
		return false
	}
	if row.TerminalStatus != "" {
		if !row.StartClaimed || row.ProviderRequestID == "" || (row.TerminalStatus != LedgerCommitted && row.TerminalStatus != LedgerUnknown) || validMCPResponse(row.TerminalJSON, row.ProviderRequestID) != nil {
			return false
		}
		rpc, _ := decodeMCPMessage(row.TerminalJSON)
		if (row.TerminalStatus == LedgerCommitted && len(rpc.Error) != 0) || (row.TerminalStatus == LedgerUnknown && !validMCPError(rpc.Error)) {
			return false
		}
	} else if len(row.TerminalJSON) != 0 {
		return false
	}
	return true
}

type nativeHTTPProvider struct {
	factory   *NativeFactory
	id        string
	transport *StreamableHTTPTransport
}

func (*nativeHTTPProvider) String() string   { return "native-mcp-http-provider<redacted>" }
func (*nativeHTTPProvider) GoString() string { return "native-mcp-http-provider<redacted>" }
func (provider *nativeHTTPProvider) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return provider.factory.repository.ProbeProduction(ctx, challenge)
}
func (provider *nativeHTTPProvider) registered(server ServerRegistration) bool {
	_, found := provider.transport.targets[server.TargetRef]
	return found && server.Transport == TransportStreamableHTTP && server.ProtocolVersion == streamableHTTPProtocol && server.Affinity == (BackendAffinity{}) && server.Credential == (CredentialBinding{})
}
func (provider *nativeHTTPProvider) server(scope ValidatedAuthority, descriptor ServerDescriptor, tool string) bool {
	registration, found := provider.factory.validator.servers[serverKey{tenant: scope.TenantID, user: scope.UserID, server: descriptor.ServerID}]
	if !found || registration.ProviderID != provider.id || !provider.registered(registration) || descriptorFor(registration) != descriptor {
		return false
	}
	_, found = provider.factory.validator.tools[toolKey{serverKey: serverKey{tenant: scope.TenantID, user: scope.UserID, server: descriptor.ServerID}, tool: tool}]
	return found
}
func (provider *nativeHTTPProvider) Availability(ctx context.Context, descriptor ServerDescriptor) (ServerAvailability, error) {
	if err := provider.factory.repository.ready(ctx); err != nil {
		return ServerAvailability{}, err
	}
	found := false
	for _, server := range provider.factory.configuration.Servers {
		if server.ProviderID == provider.id && provider.registered(server) && descriptorFor(server) == descriptor {
			found = true
		}
	}
	if !found {
		return ServerAvailability{}, ErrServerNotAllowed
	}
	return ServerAvailability{Available: true, DurableNegotiation: true, NegotiatedProtocolVersion: streamableHTTPProtocol, SupportsInvocationLedger: true}, nil
}

func nativeSessionBinding(permit SessionProviderPermit, scope ValidatedAuthority, serverID, tool string, digest Digest, attempt uint32) (nativeWireSession, error) {
	if permit == (SessionProviderPermit{}) {
		return nativeWireSession{}, nil
	}
	start, opened := permit.Open()
	if !opened {
		return nativeWireSession{}, ErrDispatchNotDurable
	}
	d := start.Dispatch
	if d.Service != broker.ServiceMCP || d.Operation != tool || d.TenantID != scope.TenantID || d.UserID != scope.UserID || d.WorkspaceID != scope.WorkspaceID || d.SessionID != scope.SessionID || d.TurnID != scope.TurnID || d.EffectID != scope.EffectID || d.InvocationID != scope.InvocationID || d.RequestDigest != broker.Digest(digest) || d.DispatchAttempt != uint64(attempt) || d.Generations.TurnLease != scope.Generations.TurnLease || d.Generations.Placement != scope.Generations.Placement || d.Generations.Sandbox != scope.Generations.Sandbox || d.Generations.Authorization != scope.Generations.Policy || d.ProviderRequestID.Kind() != identity.Request || !d.Durable {
		return nativeWireSession{}, ErrAuthorityMismatch
	}
	return nativeWireSession{Proof: permit.Proof, CommandDigest: permit.CommandDigest, RouteDigest: permit.RouteDigest, DispatchAttempt: permit.DispatchAttempt, StartEventSequence: start.EventSequence,
		DispatchEventSequence: d.EventSequence, PlatformRequestID: d.ProviderRequestID, Operation: d.Operation, ParentOperationID: d.ParentOperationID, ParentOperation: d.ParentOperation, Ordinal: d.Ordinal, ReplayPolicy: d.ReplayPolicy, DeadlineUnixNano: d.Deadline.UnixNano()}, nil
}

func (provider *nativeHTTPProvider) authorize(state *nativeRepositoryState, command NegotiationCommand) (nativeWireSession, error) {
	if !provider.server(command.Scope, command.Server, command.ToolName) || command.InvocationID != command.Scope.InvocationID || command.Attempt == 0 || !validScope(command.Scope) || command.Credential != (CredentialPermit{}) {
		return nativeWireSession{}, ErrInvalidRequest
	}
	if !provider.factory.currentGrant(state, command.Scope, command.RequestDigest, "mcp.tools.call", true) {
		return nativeWireSession{}, ErrStaleAuthority
	}
	if permit, found := state.ToolPermits[permitKey(command.Authorization.Proof)]; !found || permit != command.Authorization || !validAuthorizationPermit(permit, command.Scope, command.Server.ServerID, command.ToolName, command.RequestDigest) {
		return nativeWireSession{}, ErrAuthorizationMismatch
	}
	d := command.Dispatch
	if !d.Durable || d.Proof == (OpaqueDispatchPermit{}) || d.Scope != command.Scope || d.InvocationID != command.InvocationID || d.RequestDigest != command.RequestDigest || d.ProviderID != provider.id || d.Attempt != command.Attempt || d.Authorization != command.Authorization {
		return nativeWireSession{}, ErrDispatchNotDurable
	}
	session, err := nativeSessionBinding(command.Session, command.Scope, command.Server.ServerID, command.ToolName, command.RequestDigest, command.Attempt)
	if err != nil {
		return nativeWireSession{}, err
	}
	if session != (nativeWireSession{}) {
		source := command.Session.source
		if source == nil || source.factory != provider.factory || source.routeDigest != broker.Digest(session.RouteDigest) {
			return nativeWireSession{}, ErrDispatchNotDurable
		}
		ledger, descriptor, err := source.verified.Open()
		if err != nil || ledger != source.ledger || !reflect.DeepEqual(descriptor, provider.factory.repository.descriptor) {
			return nativeWireSession{}, ErrDispatchNotDurable
		}
	}
	if session == (nativeWireSession{}) {
		if state.Repository.claims[dispatchClaimKey(command.InvocationID.String(), command.Attempt)] != d {
			return nativeWireSession{}, ErrDispatchNotDurable
		}
		effect, found := state.Repository.effects[command.InvocationID.String()]
		if !found || effect.CancellationRequested || effect.State != StateDispatching || effect.Scope != command.Scope || effect.RequestDigest != command.RequestDigest || effect.ServerID != command.Server.ServerID || effect.ToolName != command.ToolName {
			return nativeWireSession{}, ErrDispatchNotDurable
		}
	} else if d.Proof != OpaqueDispatchPermit(command.Session.Proof) || d.EffectRevision != session.StartEventSequence {
		return nativeWireSession{}, ErrDispatchNotDurable
	}
	return session, nil
}

func (provider *nativeHTTPProvider) Negotiate(ctx context.Context, command NegotiationCommand) (StartNegotiationReceipt, error) {
	key := nativeWireKey(provider.id, command.InvocationID, command.Attempt)
	type claim struct {
		Row   nativeWireInvocation
		Fresh bool
	}
	claimed, err := nativeStateOperation(ctx, provider.factory.repository, func(state *nativeRepositoryState) (claim, error) {
		session, err := provider.authorize(state, command)
		if err != nil {
			return claim{}, err
		}
		if old, found := state.WireInvocations[key]; found {
			if old.Scope != command.Scope || old.Server != command.Server || old.ToolName != command.ToolName || old.RequestDigest != command.RequestDigest || old.Dispatch != command.Dispatch || old.Session != session {
				return claim{}, ErrInvocationConflict
			}
			if old.CancellationClaimed || old.Receipt == (StartNegotiationReceipt{}) {
				return claim{}, ErrProviderUnavailable
			}
			return claim{Row: old}, nil
		}
		state.Repository.nonce++
		row := nativeWireInvocation{ProviderID: provider.id, Scope: command.Scope, Server: command.Server, ToolName: command.ToolName, RequestDigest: command.RequestDigest, Attempt: command.Attempt, Dispatch: command.Dispatch, Session: session, ConnectionGeneration: state.Repository.nonce}
		state.WireInvocations[key] = row
		return claim{row, true}, nil
	})
	if err != nil {
		return StartNegotiationReceipt{}, err
	}
	if !claimed.Fresh {
		return claimed.Row.Receipt, nil
	}
	id := nativeWireRequestID("initialize", provider.factory.policyDigest, key)
	message, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "initialize", "params": map[string]any{"protocolVersion": streamableHTTPProtocol, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "circulusd", "version": "1"}}})
	response, err := provider.transport.Exchange(ctx, MCPWireRequest{TargetRef: command.Server.TargetRef, MessageJSON: message})
	if err != nil {
		return StartNegotiationReceipt{}, err
	}
	rpc, err := decodeMCPMessage(response.MessageJSON)
	if err != nil || len(rpc.Error) != 0 {
		return StartNegotiationReceipt{}, ErrProtocolMismatch
	}
	var initialized struct {
		ProtocolVersion string                     `json:"protocolVersion"`
		Capabilities    map[string]json.RawMessage `json:"capabilities"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if json.Unmarshal(rpc.Result, &initialized) != nil || initialized.ProtocolVersion != streamableHTTPProtocol || initialized.ServerInfo.Name == "" || initialized.ServerInfo.Version == "" || initialized.Capabilities["tools"] == nil {
		return StartNegotiationReceipt{}, ErrProtocolMismatch
	}
	_, err = provider.transport.Exchange(ctx, MCPWireRequest{TargetRef: command.Server.TargetRef, ConnectionRef: response.ConnectionRef, MessageJSON: []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)})
	if err != nil {
		return StartNegotiationReceipt{}, err
	}
	return nativeStateOperation(ctx, provider.factory.repository, func(state *nativeRepositoryState) (StartNegotiationReceipt, error) {
		if _, err := provider.authorize(state, command); err != nil {
			return StartNegotiationReceipt{}, err
		}
		row, found := state.WireInvocations[key]
		if !found || !reflect.DeepEqual(row, claimed.Row) || row.CancellationClaimed {
			return StartNegotiationReceipt{}, ErrConcurrentTransition
		}
		row.ConnectionRef = response.ConnectionRef
		row.Receipt = StartNegotiationReceipt{Durable: true, Scope: command.Scope, Server: command.Server, InvocationID: command.InvocationID, RequestDigest: command.RequestDigest, Attempt: command.Attempt, NegotiatedProtocolVersion: streamableHTTPProtocol, SupportsInvocationLedger: true, ConnectionGeneration: row.ConnectionGeneration}
		state.WireInvocations[key] = row
		return row.Receipt, nil
	})
}

func nativeNegotiation(command ProviderCommand) NegotiationCommand {
	return NegotiationCommand{Scope: command.Scope, Server: command.Server, ToolName: command.ToolName, InvocationID: command.InvocationID, RequestDigest: command.RequestDigest, Attempt: command.Attempt, Authorization: command.Authorization, Credential: command.Credential, Dispatch: command.Dispatch, Session: command.Session}
}

func (provider *nativeHTTPProvider) Start(ctx context.Context, command ProviderCommand) (ProviderStartResult, error) {
	input, err := canonical.Decode(command.InputCanonical, canonical.DefaultOptions())
	if err != nil {
		return ProviderStartResult{}, ErrInvalidRequest
	}
	if _, ok := input.(canonical.Map); !ok {
		return ProviderStartResult{}, ErrInvalidRequest
	}
	if !nativeJSONValue(input) {
		return ProviderStartResult{}, ErrInvalidRequest
	}
	digest, err := digestCanonicalCall(command.Server.ServerID, command.ToolName, command.InputCanonical)
	if err != nil || digest != command.RequestDigest || command.IdempotencyKey != "" || command.ReplayPolicy == ReplayIdempotencyKey {
		return ProviderStartResult{}, ErrInvalidRequest
	}
	if command.Session != (SessionProviderPermit{}) {
		_, commandDigest, err := encodeSessionDispatchPayload(command.Scope.RuntimeRevision, command.Server.ServerID, command.ToolName, command.InputCanonical, provider.factory.validator.bounds)
		if err != nil || Digest(commandDigest) != command.Session.CommandDigest {
			return ProviderStartResult{}, ErrAuthorityMismatch
		}
	}
	key := nativeWireKey(provider.id, command.InvocationID, command.Attempt)
	type claim struct {
		Row   nativeWireInvocation
		Fresh bool
	}
	claimed, err := nativeStateOperation(ctx, provider.factory.repository, func(state *nativeRepositoryState) (claim, error) {
		session, err := provider.authorize(state, nativeNegotiation(command))
		if err != nil {
			return claim{}, err
		}
		row, found := state.WireInvocations[key]
		if !found || row.Receipt == (StartNegotiationReceipt{}) || row.Receipt != command.Negotiation || row.Scope != command.Scope || row.Server != command.Server || row.ToolName != command.ToolName || row.RequestDigest != command.RequestDigest || row.Dispatch != command.Dispatch || row.Session != session {
			return claim{}, ErrDispatchNotDurable
		}
		start := command.Start
		if row.CancellationClaimed {
			return claim{}, ErrConcurrentTransition
		}
		if row.StartClaimed {
			if row.Start != start {
				return claim{}, ErrDispatchNotDurable
			}
			return claim{Row: row}, nil
		}
		if !start.Durable || start.Proof == (OpaqueProviderStartPermit{}) || start.Scope != command.Scope || start.InvocationID != command.InvocationID || start.RequestDigest != command.RequestDigest || start.ProviderID != provider.id || start.Attempt != command.Attempt || start.ClaimGeneration == 0 || start.EffectRevision == 0 || start.Dispatch != command.Dispatch || start.Negotiation != command.Negotiation || provider.factory.repository.now().UnixNano() >= start.LeaseExpiresAtUnixNano {
			return claim{}, ErrDispatchNotDurable
		}
		if session == (nativeWireSession{}) {
			native, found := state.Repository.providerStarts[dispatchClaimKey(command.InvocationID.String(), command.Attempt)]
			if !found || native.Status != providerStartActive || native.Permit != start {
				return claim{}, ErrDispatchNotDurable
			}
		} else if start.Proof != OpaqueProviderStartPermit(command.Session.Proof) || start.EffectRevision != session.StartEventSequence || start.ClaimGeneration != 1 || session.ReplayPolicy != broker.ReplayPolicy(command.ReplayPolicy) || provider.factory.repository.now().UnixNano() >= session.DeadlineUnixNano {
			return claim{}, ErrDispatchNotDurable
		}
		row.Start = start
		row.StartClaimed = true
		state.WireInvocations[key] = row
		return claim{row, true}, nil
	})
	if err != nil {
		return ProviderStartResult{}, err
	}
	if !claimed.Fresh {
		return nativeRetainedCall(claimed.Row)
	}
	if provider.factory.repository.now().UnixNano() >= claimed.Row.Start.LeaseExpiresAtUnixNano {
		return ProviderStartResult{}, ErrDispatchNotDurable
	}
	id := nativeWireRequestID("tools/call", provider.factory.policyDigest, key)
	message, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": command.ToolName, "arguments": input}})
	if err != nil {
		return ProviderStartResult{}, ErrInvalidRequest
	}
	response, err := provider.transport.Exchange(ctx, MCPWireRequest{TargetRef: command.Server.TargetRef, ConnectionRef: claimed.Row.ConnectionRef, MessageJSON: message})
	if err != nil {
		return ProviderStartResult{}, ErrProviderUnavailable
	}
	rpc, err := decodeMCPMessage(response.MessageJSON)
	if err != nil {
		return ProviderStartResult{}, ErrProtocolMismatch
	}
	if len(rpc.Error) == 0 {
		var result map[string]json.RawMessage
		var content []json.RawMessage
		if json.Unmarshal(rpc.Result, &result) != nil || result == nil || json.Unmarshal(result["content"], &content) != nil || content == nil || len(rpc.Result) > int(provider.factory.validator.bounds.MaxOutputBytes) {
			return ProviderStartResult{}, ErrProtocolMismatch
		}
		if raw, found := result["isError"]; found {
			var toolError bool
			if json.Unmarshal(raw, &toolError) != nil {
				return ProviderStartResult{}, ErrProtocolMismatch
			}
		}
	} else if !validMCPError(rpc.Error) {
		return ProviderStartResult{}, ErrProtocolMismatch
	}
	row, err := nativeStateOperation(ctx, provider.factory.repository, func(state *nativeRepositoryState) (nativeWireInvocation, error) {
		row, found := state.WireInvocations[key]
		if !found || row.Start != command.Start || !row.StartClaimed || row.TerminalStatus != "" {
			return nativeWireInvocation{}, ErrConcurrentTransition
		}
		row.ProviderRequestID = id
		// A cancellation already linearized: retain observed acceptance, but
		// ignore its late response rather than claiming cancellation prevented it.
		if !row.CancellationClaimed {
			row.TerminalJSON = bytes.Clone(response.MessageJSON)
			row.TerminalStatus = LedgerCommitted
			if len(rpc.Error) != 0 {
				// A correlated RPC error does not prove rollback of external
				// work. Retain its immutable response privately as unknown.
				row.TerminalStatus = LedgerUnknown
			}
		}
		state.WireInvocations[key] = row
		return row, nil
	})
	if err != nil {
		return ProviderStartResult{ProviderRequestID: id}, err
	}
	return nativeRetainedCall(row)
}

func nativeJSONValue(value canonical.Value) bool {
	switch value := value.(type) {
	case nil, bool, string, int64, uint64:
		return true
	case canonical.Array:
		for _, child := range value {
			if !nativeJSONValue(child) {
				return false
			}
		}
		return true
	case canonical.Map:
		for _, child := range value {
			if !nativeJSONValue(child) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func nativeRetainedCall(row nativeWireInvocation) (ProviderStartResult, error) {
	result := ProviderStartResult{ProviderRequestID: row.ProviderRequestID}
	if row.TerminalStatus != LedgerCommitted {
		return result, ErrProviderUnavailable
	}
	rpc, err := decodeMCPMessage(row.TerminalJSON)
	if err != nil {
		return result, ErrProtocolMismatch
	}
	result.Call = &nativeHTTPCall{output: bytes.Clone(rpc.Result)}
	return result, nil
}

type nativeHTTPCall struct {
	mu     sync.Mutex
	output []byte
	closed bool
}

func (*nativeHTTPCall) String() string   { return "native-mcp-http-call<redacted>" }
func (*nativeHTTPCall) GoString() string { return "native-mcp-http-call<redacted>" }

func (call *nativeHTTPCall) Next(ctx context.Context) (ProviderEvent, error) {
	if err := ctx.Err(); err != nil {
		return ProviderEvent{}, err
	}
	call.mu.Lock()
	defer call.mu.Unlock()
	if call.closed || len(call.output) == 0 {
		return ProviderEvent{}, io.EOF
	}
	output := call.output
	call.output = nil
	return ProviderEvent{Kind: ProviderCompleted, Output: output}, nil
}
func (call *nativeHTTPCall) Close(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	call.mu.Lock()
	defer call.mu.Unlock()
	call.closed = true
	call.output = nil
	return nil
}

func nativeWireLedger(row nativeWireInvocation, scope ValidatedAuthority, digest Digest) LedgerRecord {
	record := LedgerRecord{InvocationID: scope.InvocationID, RequestDigest: digest, ProviderRequestID: row.ProviderRequestID, Status: LedgerUnknown}
	if row.TerminalStatus == LedgerCommitted {
		rpc, _ := decodeMCPMessage(row.TerminalJSON)
		record.Status = LedgerCommitted
		record.Output = bytes.Clone(rpc.Result)
	}
	if !row.StartClaimed {
		record.Status = LedgerAbsent
	}
	return record
}

func (provider *nativeHTTPProvider) Lookup(ctx context.Context, query LedgerQuery) (LedgerRecord, error) {
	return nativeStateOperation(ctx, provider.factory.repository, func(state *nativeRepositoryState) (LedgerRecord, error) {
		if !provider.server(query.Scope, query.Server, query.ToolName) || query.Scope.InvocationID != query.InvocationID || query.Credential != (CredentialPermit{}) || !provider.factory.currentGrant(state, query.Scope, query.RequestDigest, "mcp.recover", false) {
			return LedgerRecord{}, ErrStaleAuthority
		}
		// Absence of a claimed start proves only local non-dispatch. The HTTP
		// protocol has no provider-side invocation lookup/idempotency extension.
		row, found := state.WireInvocations[nativeWireKey(provider.id, query.InvocationID, query.Negotiation.Attempt)]
		if !found {
			return LedgerRecord{InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerUnknown}, nil
		}
		if !sameOperationScope(row.Scope, query.Scope) || row.Server != query.Server || row.ToolName != query.ToolName || row.RequestDigest != query.RequestDigest || row.Receipt != query.Negotiation || (row.StartClaimed && row.Start.Proof != query.Start.Proof) {
			return LedgerRecord{}, ErrLedgerMismatch
		}
		return nativeWireLedger(row, query.Scope, query.RequestDigest), nil
	})
}

func (provider *nativeHTTPProvider) Cancel(ctx context.Context, command CancelCommand) (CancellationResult, error) {
	key := nativeWireKey(provider.id, command.InvocationID, command.Attempt)
	type claim struct {
		Row    nativeWireInvocation
		Send   bool
		Result CancellationResult
	}
	claimed, err := nativeStateOperation(ctx, provider.factory.repository, func(state *nativeRepositoryState) (claim, error) {
		permit := command.Cancellation
		if !provider.server(command.Scope, command.Server, command.ToolName) || command.Scope.InvocationID != command.InvocationID || command.Credential != (CredentialPermit{}) || !provider.factory.currentGrant(state, command.Scope, command.RequestDigest, "mcp.cancel", false) {
			return claim{}, ErrStaleAuthority
		}
		if !permit.Durable || permit.Proof == (OpaqueCancellationPermit{}) || permit.Scope != command.Scope || permit.InvocationID != command.InvocationID || permit.RequestDigest != command.RequestDigest || permit.ProviderID != provider.id || permit.Attempt != command.Attempt || permit.ProviderRequestID != command.ProviderRequestID || permit.Start != command.Start || provider.factory.repository.now().UnixNano() >= permit.LeaseExpiresAtUnixNano || state.Repository.cancellationClaims[dispatchClaimKey(command.InvocationID.String(), command.Attempt)] != permit {
			return claim{}, ErrDispatchNotDurable
		}
		if permit.ServerRequestMethod != "" {
			return claim{}, ErrServerRequestDenied
		}
		row, found := state.WireInvocations[key]
		if !found {
			// An exact native cancellation must block a negotiation that has not
			// yet persisted a row. The repository's cancellation intent already
			// prevents ordinary dispatch claims from passing authorize.
			return claim{Result: CancellationResult{Status: CancellationPrevented}}, nil
		}
		if !sameOperationScope(row.Scope, command.Scope) || row.Server != command.Server || row.ToolName != command.ToolName || row.RequestDigest != command.RequestDigest || row.Receipt != command.Negotiation || (row.StartClaimed && row.Start.Proof != command.Start.Proof) {
			return claim{}, ErrLedgerMismatch
		}
		if row.TerminalStatus == LedgerCommitted {
			record := nativeWireLedger(row, command.Scope, command.RequestDigest)
			return claim{Result: CancellationResult{Status: CancellationCommitted, Record: record}}, nil
		}
		if row.TerminalStatus == LedgerUnknown {
			row.CancellationClaimed = true
			state.WireInvocations[key] = row
			return claim{Result: CancellationResult{Status: CancellationUnknown}}, nil
		}
		fresh := !row.CancellationClaimed
		row.CancellationClaimed = true
		state.WireInvocations[key] = row
		status := CancellationUnknown
		if !row.StartClaimed {
			status = CancellationPrevented
		}
		return claim{Row: row, Send: fresh && row.StartClaimed, Result: CancellationResult{Status: status}}, nil
	})
	if err != nil {
		return CancellationResult{Status: CancellationUnknown}, err
	}
	if !claimed.Send {
		return claimed.Result, nil
	}
	id := nativeWireRequestID("tools/call", provider.factory.policyDigest, key)
	message, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": id, "reason": "Cancellation requested"}})
	_, err = provider.transport.Exchange(ctx, MCPWireRequest{TargetRef: command.Server.TargetRef, ConnectionRef: claimed.Row.ConnectionRef, MessageJSON: message})
	// HTTP 202 is notification receipt, never proof of stopping side effects.
	return CancellationResult{Status: CancellationUnknown}, err
}

func validMCPError(raw json.RawMessage) bool {
	var rpcError struct {
		Code    *int64  `json:"code"`
		Message *string `json:"message"`
	}
	return json.Unmarshal(raw, &rpcError) == nil && rpcError.Code != nil && rpcError.Message != nil
}

var _ ProductionProvider = (*nativeHTTPProvider)(nil)
