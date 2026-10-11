package effectledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/identity"
	"golang.org/x/text/unicode/norm"
)

const nativeLedgerProtocol = "circulusd.provider-observation-ledger.v1"

func nativeCommandSnapshot(command Command) Command {
	command = cloneCommand(command)
	command.Dispatch = dispatchWithoutOpaque(command.Dispatch)
	command.Dispatch.Deadline = command.Dispatch.Deadline.UTC().Round(0)
	return command
}

func nativeObjectID(key attemptKey) (string, error) {
	if key.sessionID.Kind() != identity.Session || key.turnID.Kind() != identity.Turn ||
		key.effectID.Kind() != identity.Effect || key.invocationID.Kind() != identity.Invocation ||
		key.dispatchAttempt == 0 || key.dispatchAttempt > maximumOccurrenceOrdinal {
		return "", ErrInvalidCommand
	}
	// Relabeling a tenant, operation, route or request digest cannot create a
	// second object beside this exact Session occurrence and dispatch attempt.
	encoded, err := canonical.Encode(canonical.Array{nativeLedgerProtocol, key.sessionID.String(), key.turnID.String(),
		key.effectID.String(), key.invocationID.String(), key.dispatchAttempt}, canonical.Options{MaxBytes: 1024, MaxDepth: 2, MaxItems: 16})
	if err != nil {
		return "", ErrInvalidCommand
	}
	digest := sha256.Sum256(encoded)
	return "provider-observation.v1/" + hex.EncodeToString(digest[:]), nil
}

func (ledger *NativeLedger) codecOptions() canonical.Options {
	return canonical.Options{MaxBytes: ledger.maximumStateBytes, MaxDepth: 4, MaxItems: 128}
}

func (ledger *NativeLedger) validateEntry(record *entry) error {
	if record == nil || record.command.Dispatch.Opaque != "" || record.command.CommandDigest == (broker.Digest{}) ||
		validateDispatchCore(record.command.Dispatch, false) != nil ||
		len(record.command.Payload) > ledger.limits.MaximumPayloadBytes ||
		!nativeText(record.command.Dispatch.Operation, 256, false) ||
		!nativeText(record.command.Dispatch.ParentOperation, 256, true) {
		return celld.ErrStorageContract
	}
	dispatch := record.command.Dispatch
	for _, value := range []uint64{dispatch.DispatchAttempt, dispatch.Ordinal, dispatch.EventSequence,
		dispatch.Generations.TurnLease, dispatch.Generations.Placement, dispatch.Generations.Sandbox, dispatch.Generations.Authorization} {
		if value > maximumOccurrenceOrdinal {
			return celld.ErrStorageContract
		}
	}
	deadline, err := time.Parse(time.RFC3339Nano, dispatch.Deadline.Format(time.RFC3339Nano))
	if err != nil || !deadline.Equal(dispatch.Deadline) || dispatch.Deadline.Location() != time.UTC {
		return celld.ErrStorageContract
	}
	if record.externalProviderRequestID != "" && (validateProviderRequestID(record.externalProviderRequestID) != nil ||
		!nativeText(record.externalProviderRequestID, maximumProviderRequestBytes, false)) {
		return celld.ErrStorageContract
	}
	switch record.state {
	case StatePrepared, StateClaimed:
		if record.externalProviderRequestID != "" || record.terminal != nil {
			return celld.ErrStorageContract
		}
	case StateAccepted:
		if record.externalProviderRequestID == "" || record.terminal != nil {
			return celld.ErrStorageContract
		}
	case StateTerminal:
		if record.terminal == nil || validateTerminal(*record.terminal) != nil || len(record.terminal.Result) > ledger.limits.MaximumResultBytes {
			return celld.ErrStorageContract
		}
		if record.terminal.Status == TerminalCommitted && (record.externalProviderRequestID == "" ||
			record.terminal.ExternalCommitID.Kind() != identity.Commit ||
			len(record.terminal.Result) != 0 && record.terminal.ResultRef.Kind() != identity.Artifact) {
			return celld.ErrStorageContract
		}
	default:
		return celld.ErrStorageContract
	}
	return nil
}

func nativeText(value string, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	return len(value) <= maximum && utf8.ValidString(value) && norm.NFC.IsNormalString(value) && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) || unicode.In(r, unicode.Cf) }) < 0
}

func (ledger *NativeLedger) encodeEntry(record *entry) ([]byte, error) {
	if err := ledger.validateEntry(record); err != nil {
		return nil, err
	}
	command := record.command
	d := command.Dispatch
	payloadDigest := sha256.Sum256(command.Payload)
	dispatch := canonical.Map{
		"tenantId": d.TenantID.String(), "workspaceId": d.WorkspaceID.String(), "userId": d.UserID.String(),
		"sessionId": d.SessionID.String(), "turnId": d.TurnID.String(), "effectId": d.EffectID.String(), "invocationId": d.InvocationID.String(),
		"requestDigest": canonical.Bytes(d.RequestDigest[:]), "service": string(d.Service), "operation": d.Operation,
		// Explicit empty strings avoid identity.ID.MarshalText rejecting optional
		// zero identities and prevent absent/default aliases in persistent data.
		"parentOperationId": d.ParentOperationID.String(), "parentOperation": d.ParentOperation, "ordinal": d.Ordinal,
		"replayPolicy": string(d.ReplayPolicy), "turnLeaseGeneration": d.Generations.TurnLease,
		"placementGeneration": d.Generations.Placement, "sandboxGeneration": d.Generations.Sandbox, "authorizationGeneration": d.Generations.Authorization,
		"dispatchAttempt": d.DispatchAttempt, "providerRequestId": d.ProviderRequestID.String(),
		"providerRouteDigest": canonical.Bytes(d.ProviderRouteDigest[:]), "deadline": d.Deadline.Format(time.RFC3339Nano),
		"eventSequence": d.EventSequence, "durable": d.Durable,
	}
	var terminal canonical.Value
	if record.terminal != nil {
		t := record.terminal
		digest := sha256.Sum256(t.Result)
		terminal = canonical.Map{"status": string(t.Status), "externalCommitId": t.ExternalCommitID.String(), "resultRef": t.ResultRef.String(),
			"result": canonical.Bytes(t.Result), "resultDigest": canonical.Bytes(digest[:])}
	}
	encoded, err := canonical.Encode(canonical.Map{"protocol": nativeLedgerProtocol, "version": int64(1), "state": string(record.state),
		"command": canonical.Map{"dispatch": dispatch, "digest": canonical.Bytes(command.CommandDigest[:]),
			"payload": canonical.Bytes(command.Payload), "payloadDigest": canonical.Bytes(payloadDigest[:])},
		"externalProviderRequestId": record.externalProviderRequestID, "terminal": terminal}, ledger.codecOptions())
	if err != nil {
		return nil, ErrLimitExceeded
	}
	return encoded, nil
}

func (ledger *NativeLedger) decodeEntry(state []byte) (*entry, error) {
	value, err := canonical.Decode(state, ledger.codecOptions())
	if err != nil {
		return nil, celld.ErrStorageContract
	}
	m, ok := value.(canonical.Map)
	if !ok || len(m) != 6 || m["protocol"] != nativeLedgerProtocol || m["version"] != int64(1) {
		return nil, celld.ErrStorageContract
	}
	stateText, stateOK := m["state"].(string)
	providerID, providerOK := m["externalProviderRequestId"].(string)
	command, commandOK := m["command"].(canonical.Map)
	if !stateOK || !providerOK || !commandOK || len(command) != 4 {
		return nil, celld.ErrStorageContract
	}
	d, err := nativeDispatch(command["dispatch"])
	if err != nil {
		return nil, err
	}
	digest, digestOK := nativeDigest(command["digest"])
	payload, payloadOK := command["payload"].(canonical.Bytes)
	payloadDigest, payloadDigestOK := nativeDigest(command["payloadDigest"])
	if !digestOK || !payloadOK || !payloadDigestOK || broker.Digest(sha256.Sum256(payload)) != payloadDigest {
		return nil, celld.ErrStorageContract
	}
	record := &entry{state: State(stateText), command: Command{Dispatch: d, CommandDigest: digest, Payload: bytes.Clone(payload)}, externalProviderRequestID: providerID}
	terminalValue, found := m["terminal"]
	if !found {
		return nil, celld.ErrStorageContract
	}
	if terminalValue != nil {
		terminal, err := nativeTerminal(terminalValue)
		if err != nil {
			return nil, err
		}
		record.terminal = &terminal
	}
	if err := ledger.validateEntry(record); err != nil {
		return nil, err
	}
	encoded, err := ledger.encodeEntry(record)
	if err != nil || !bytes.Equal(encoded, state) {
		return nil, celld.ErrStorageContract
	}
	return record, nil
}

func nativeDispatch(value canonical.Value) (broker.DispatchPermit, error) {
	m, ok := value.(canonical.Map)
	if !ok || len(m) != 24 {
		return broker.DispatchPermit{}, celld.ErrStorageContract
	}
	var d broker.DispatchPermit
	for _, field := range []struct {
		name     string
		kind     identity.Kind
		output   *identity.ID
		optional bool
	}{
		{"tenantId", identity.Tenant, &d.TenantID, false}, {"workspaceId", identity.Workspace, &d.WorkspaceID, false},
		{"userId", identity.Subject, &d.UserID, false}, {"sessionId", identity.Session, &d.SessionID, false},
		{"turnId", identity.Turn, &d.TurnID, false}, {"effectId", identity.Effect, &d.EffectID, false},
		{"invocationId", identity.Invocation, &d.InvocationID, false}, {"parentOperationId", identity.Operation, &d.ParentOperationID, true},
		{"providerRequestId", identity.Request, &d.ProviderRequestID, true},
	} {
		parsed, err := nativeID(m[field.name], field.kind, field.optional)
		if err != nil {
			return broker.DispatchPermit{}, err
		}
		*field.output = parsed
	}
	for _, field := range []struct {
		name   string
		output *uint64
	}{
		{"ordinal", &d.Ordinal}, {"turnLeaseGeneration", &d.Generations.TurnLease}, {"placementGeneration", &d.Generations.Placement},
		{"sandboxGeneration", &d.Generations.Sandbox}, {"authorizationGeneration", &d.Generations.Authorization},
		{"dispatchAttempt", &d.DispatchAttempt}, {"eventSequence", &d.EventSequence},
	} {
		value, ok := m[field.name].(int64)
		if !ok || value < 0 {
			return broker.DispatchPermit{}, celld.ErrStorageContract
		}
		*field.output = uint64(value)
	}
	var digestOK bool
	d.RequestDigest, digestOK = nativeDigest(m["requestDigest"])
	if !digestOK {
		return broker.DispatchPermit{}, celld.ErrStorageContract
	}
	d.ProviderRouteDigest, digestOK = nativeDigest(m["providerRouteDigest"])
	if !digestOK {
		return broker.DispatchPermit{}, celld.ErrStorageContract
	}
	service, serviceOK := m["service"].(string)
	operation, operationOK := m["operation"].(string)
	parent, parentOK := m["parentOperation"].(string)
	replay, replayOK := m["replayPolicy"].(string)
	deadline, deadlineOK := m["deadline"].(string)
	durable, durableOK := m["durable"].(bool)
	if !serviceOK || !operationOK || !parentOK || !replayOK || !deadlineOK || !durableOK {
		return broker.DispatchPermit{}, celld.ErrStorageContract
	}
	d.Service, d.Operation, d.ParentOperation, d.ReplayPolicy, d.Durable = broker.EffectService(service), operation, parent, broker.ReplayPolicy(replay), durable
	var err error
	d.Deadline, err = time.Parse(time.RFC3339Nano, deadline)
	if err != nil || d.Deadline.Location() != time.UTC || d.Deadline.Format(time.RFC3339Nano) != deadline {
		return broker.DispatchPermit{}, celld.ErrStorageContract
	}
	return d, nil
}

func nativeTerminal(value canonical.Value) (Terminal, error) {
	m, ok := value.(canonical.Map)
	if !ok || len(m) != 5 {
		return Terminal{}, celld.ErrStorageContract
	}
	status, statusOK := m["status"].(string)
	result, resultOK := m["result"].(canonical.Bytes)
	digest, digestOK := nativeDigest(m["resultDigest"])
	externalCommitID, commitErr := nativeID(m["externalCommitId"], identity.Commit, true)
	resultRef, refErr := nativeID(m["resultRef"], identity.Artifact, true)
	if !statusOK || !resultOK || !digestOK || commitErr != nil || refErr != nil || broker.Digest(sha256.Sum256(result)) != digest {
		return Terminal{}, celld.ErrStorageContract
	}
	return Terminal{Status: TerminalStatus(status), ExternalCommitID: externalCommitID, ResultRef: resultRef, Result: bytes.Clone(result)}, nil
}

func nativeID(value canonical.Value, kind identity.Kind, optional bool) (identity.ID, error) {
	text, ok := value.(string)
	if !ok {
		return identity.ID{}, celld.ErrStorageContract
	}
	if text == "" && optional {
		return identity.ID{}, nil
	}
	id, err := identity.Parse(kind, text)
	if err != nil {
		return identity.ID{}, celld.ErrStorageContract
	}
	return id, nil
}

func nativeDigest(value canonical.Value) (broker.Digest, bool) {
	encoded, ok := value.(canonical.Bytes)
	if !ok || len(encoded) != 32 {
		return broker.Digest{}, false
	}
	var digest broker.Digest
	copy(digest[:], encoded)
	return digest, true
}
