package celldrepo

import (
	"fmt"

	"github.com/hancomac/circulusd/internal/canonical"
)

// sessionRecord is the durable public-session state. The zero value decoded from
// an empty object is an unregistered session.
type sessionRecord struct {
	schemaVersion           int64
	tenantID                string
	subjectID               string
	sessionID               string
	runtimeRevision         string
	workspaceID             string
	placementGeneration     int64
	authorizationGeneration int64
	lastDurableSequence     int64
	activeTurnID            string
	turnStatus              string
	turns                   map[string]turnRecord
	creationReceipts        map[string]creationRecord
	events                  []eventRecord
}

type turnRecord struct {
	requestDigest string
	status        string
}

type creationRecord struct {
	requestDigest string
	turnID        string
}

type eventRecord struct {
	sequence  int64
	turnID    string
	eventType string
	payload   string
}

func (record sessionRecord) registered() bool { return record.sessionID != "" }

func (record sessionRecord) clone() sessionRecord {
	next := record
	next.turns = make(map[string]turnRecord, len(record.turns))
	for id, turn := range record.turns {
		next.turns[id] = turn
	}
	next.creationReceipts = make(map[string]creationRecord, len(record.creationReceipts))
	for key, receipt := range record.creationReceipts {
		next.creationReceipts[key] = receipt
	}
	next.events = append([]eventRecord(nil), record.events...)
	return next
}

// Snapshot is a read-only projection of the durable record used by the
// Repository adapter to build replay pages.
type Snapshot struct {
	SessionID           string
	ActiveTurnID        string
	TurnStatus          string
	LastDurableSequence uint64
}

// DurableEvent is one durable journal entry projected for replay.
type DurableEvent struct {
	Sequence uint64
	TurnID   string
	Type     string
	Payload  string
}

// ProjectState decodes committed state bytes into a replay snapshot and its
// durable events after afterSequence, bounded to limit entries. It is the
// read path a Repository read uses over a committed object.
func ProjectState(encoded []byte, afterSequence uint64, limit int) (Snapshot, []DurableEvent, error) {
	record, err := decodeState(encoded)
	if err != nil {
		return Snapshot{}, nil, err
	}
	return project(record, afterSequence, limit)
}

// project builds a replay snapshot and bounded event page from an already
// decoded record. A cursor past the durable head is ErrSequenceConflict.
func project(record sessionRecord, afterSequence uint64, limit int) (Snapshot, []DurableEvent, error) {
	if limit < 1 {
		return Snapshot{}, nil, fmt.Errorf("%w: limit must be positive", ErrInvalidState)
	}
	snapshot := Snapshot{
		SessionID:           record.sessionID,
		ActiveTurnID:        record.activeTurnID,
		TurnStatus:          record.turnStatus,
		LastDurableSequence: uint64(record.lastDurableSequence),
	}
	if afterSequence > uint64(len(record.events)) {
		return Snapshot{}, nil, fmt.Errorf("%w: cursor past head", ErrSequenceConflict)
	}
	events := make([]DurableEvent, 0, limit)
	for _, event := range record.events[afterSequence:] {
		if len(events) == limit {
			break
		}
		events = append(events, DurableEvent{
			Sequence: uint64(event.sequence), TurnID: event.turnID,
			Type: event.eventType, Payload: event.payload,
		})
	}
	return snapshot, events, nil
}

func encodeState(record sessionRecord) ([]byte, error) {
	turns := make(canonical.Map, len(record.turns))
	for id, turn := range record.turns {
		turns[id] = canonical.Map{"requestDigest": turn.requestDigest, "status": turn.status}
	}
	receipts := make(canonical.Map, len(record.creationReceipts))
	for key, receipt := range record.creationReceipts {
		receipts[key] = canonical.Map{"requestDigest": receipt.requestDigest, "turnId": receipt.turnID}
	}
	events := make(canonical.Array, len(record.events))
	for index, event := range record.events {
		events[index] = canonical.Map{
			"sequence": event.sequence, "turnId": event.turnID,
			"type": event.eventType, "payload": event.payload,
		}
	}
	return canonical.Encode(canonical.Map{
		"schemaVersion":           record.schemaVersion,
		"tenantId":                record.tenantID,
		"subjectId":               record.subjectID,
		"sessionId":               record.sessionID,
		"runtimeRevision":         record.runtimeRevision,
		"workspaceId":             record.workspaceID,
		"placementGeneration":     record.placementGeneration,
		"authorizationGeneration": record.authorizationGeneration,
		"lastDurableSequence":     record.lastDurableSequence,
		"activeTurnId":            record.activeTurnID,
		"turnStatus":              record.turnStatus,
		"turns":                   turns,
		"creationReceipts":        receipts,
		"events":                  events,
	}, canonical.DefaultOptions())
}

func decodeState(encoded []byte) (sessionRecord, error) {
	if len(encoded) == 0 {
		return sessionRecord{
			schemaVersion:    stateSchemaVersion,
			turns:            map[string]turnRecord{},
			creationReceipts: map[string]creationRecord{},
		}, nil
	}
	value, err := canonical.Decode(encoded, canonical.DefaultOptions())
	if err != nil {
		return sessionRecord{}, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	fields, ok := value.(canonical.Map)
	if !ok {
		return sessionRecord{}, fmt.Errorf("%w: state is not a map", ErrInvalidState)
	}
	record := sessionRecord{turns: map[string]turnRecord{}, creationReceipts: map[string]creationRecord{}}
	ints := []struct {
		key   string
		field *int64
	}{
		{"schemaVersion", &record.schemaVersion},
		{"placementGeneration", &record.placementGeneration},
		{"authorizationGeneration", &record.authorizationGeneration},
		{"lastDurableSequence", &record.lastDurableSequence},
	}
	for _, entry := range ints {
		if *entry.field, err = stateInt(fields, entry.key); err != nil {
			return sessionRecord{}, err
		}
	}
	strs := []struct {
		key   string
		field *string
	}{
		{"tenantId", &record.tenantID},
		{"subjectId", &record.subjectID},
		{"sessionId", &record.sessionID},
		{"runtimeRevision", &record.runtimeRevision},
		{"workspaceId", &record.workspaceID},
		{"activeTurnId", &record.activeTurnID},
		{"turnStatus", &record.turnStatus},
	}
	for _, entry := range strs {
		if *entry.field, err = stateString(fields, entry.key); err != nil {
			return sessionRecord{}, err
		}
	}
	if record.schemaVersion != stateSchemaVersion {
		return sessionRecord{}, fmt.Errorf("%w: schema version %d", ErrInvalidState, record.schemaVersion)
	}
	if record.placementGeneration < 0 || record.authorizationGeneration < 0 || record.lastDurableSequence < 0 {
		return sessionRecord{}, fmt.Errorf("%w: negative counter", ErrInvalidState)
	}
	if record.turns, err = decodeTurns(fields); err != nil {
		return sessionRecord{}, err
	}
	if record.creationReceipts, err = decodeReceipts(fields); err != nil {
		return sessionRecord{}, err
	}
	if record.events, err = decodeEvents(fields); err != nil {
		return sessionRecord{}, err
	}
	if int64(len(record.events)) != record.lastDurableSequence {
		return sessionRecord{}, fmt.Errorf("%w: event count %d != lastDurableSequence %d",
			ErrInvalidState, len(record.events), record.lastDurableSequence)
	}
	return record, nil
}

func decodeTurns(fields canonical.Map) (map[string]turnRecord, error) {
	raw, ok := fields["turns"].(canonical.Map)
	if !ok {
		return nil, fmt.Errorf("%w: turns is not a map", ErrInvalidState)
	}
	turns := make(map[string]turnRecord, len(raw))
	for id, value := range raw {
		entry, ok := value.(canonical.Map)
		if !ok {
			return nil, fmt.Errorf("%w: turn %q is not a map", ErrInvalidState, id)
		}
		digest, err := stateString(entry, "requestDigest")
		if err != nil {
			return nil, err
		}
		status, err := stateString(entry, "status")
		if err != nil {
			return nil, err
		}
		turns[id] = turnRecord{requestDigest: digest, status: status}
	}
	return turns, nil
}

func decodeReceipts(fields canonical.Map) (map[string]creationRecord, error) {
	raw, ok := fields["creationReceipts"].(canonical.Map)
	if !ok {
		return nil, fmt.Errorf("%w: creationReceipts is not a map", ErrInvalidState)
	}
	receipts := make(map[string]creationRecord, len(raw))
	for key, value := range raw {
		entry, ok := value.(canonical.Map)
		if !ok {
			return nil, fmt.Errorf("%w: creation receipt %q is not a map", ErrInvalidState, key)
		}
		digest, err := stateString(entry, "requestDigest")
		if err != nil {
			return nil, err
		}
		turnID, err := stateString(entry, "turnId")
		if err != nil {
			return nil, err
		}
		receipts[key] = creationRecord{requestDigest: digest, turnID: turnID}
	}
	return receipts, nil
}

func decodeEvents(fields canonical.Map) ([]eventRecord, error) {
	raw, ok := fields["events"].(canonical.Array)
	if !ok {
		return nil, fmt.Errorf("%w: events is not an array", ErrInvalidState)
	}
	events := make([]eventRecord, 0, len(raw))
	for index, value := range raw {
		entry, ok := value.(canonical.Map)
		if !ok {
			return nil, fmt.Errorf("%w: event %d is not a map", ErrInvalidState, index)
		}
		sequence, err := stateInt(entry, "sequence")
		if err != nil {
			return nil, err
		}
		if sequence != int64(index)+1 {
			return nil, fmt.Errorf("%w: event %d has non-contiguous sequence %d", ErrInvalidState, index, sequence)
		}
		turnID, err := stateString(entry, "turnId")
		if err != nil {
			return nil, err
		}
		eventType, err := stateString(entry, "type")
		if err != nil {
			return nil, err
		}
		payload, err := stateString(entry, "payload")
		if err != nil {
			return nil, err
		}
		events = append(events, eventRecord{
			sequence: sequence, turnID: turnID, eventType: eventType, payload: payload,
		})
	}
	return events, nil
}

// command is one decoded aggregate command.
type command struct {
	kind                    string
	tenantID                string
	subjectID               string
	sessionID               string
	runtimeRevision         string
	workspaceID             string
	placementGeneration     int64
	authorizationGeneration int64
	keyDigest               string
	requestDigest           string
	proposedTurnID          string
	turnID                  string
	expectedSequence        int64
	eventType               string
	payload                 string
	turnStatus              string
}

// RegisterCommand is the input to EncodeRegister.
type RegisterCommand struct {
	TenantID                string
	SubjectID               string
	SessionID               string
	RuntimeRevision         string
	WorkspaceID             string
	PlacementGeneration     int64
	AuthorizationGeneration int64
}

// CreateTurnCommand is the input to EncodeCreateTurn.
type CreateTurnCommand struct {
	TenantID                string
	SubjectID               string
	SessionID               string
	KeyDigest               string
	RequestDigest           string
	ProposedTurnID          string
	AuthorizationGeneration int64
}

// AppendEventCommand is the input to EncodeAppendEvent.
type AppendEventCommand struct {
	TenantID                string
	SubjectID               string
	SessionID               string
	RuntimeRevision         string
	WorkspaceID             string
	TurnID                  string
	ExpectedSequence        int64
	Type                    string
	Payload                 string
	TurnStatus              string
	PlacementGeneration     int64
	AuthorizationGeneration int64
}

// EncodeRegister encodes a session registration command.
func EncodeRegister(input RegisterCommand) ([]byte, error) {
	return encodeCommand(command{
		kind: commandRegister, tenantID: input.TenantID, subjectID: input.SubjectID,
		sessionID: input.SessionID, runtimeRevision: input.RuntimeRevision, workspaceID: input.WorkspaceID,
		placementGeneration: input.PlacementGeneration, authorizationGeneration: input.AuthorizationGeneration,
	})
}

// EncodeCreateTurn encodes a create-turn command.
func EncodeCreateTurn(input CreateTurnCommand) ([]byte, error) {
	return encodeCommand(command{
		kind: commandCreateTurn, tenantID: input.TenantID, subjectID: input.SubjectID,
		sessionID: input.SessionID, keyDigest: input.KeyDigest,
		requestDigest: input.RequestDigest, proposedTurnID: input.ProposedTurnID,
		authorizationGeneration: input.AuthorizationGeneration,
	})
}

// EncodeAppendEvent encodes a durable append-event command.
func EncodeAppendEvent(input AppendEventCommand) ([]byte, error) {
	return encodeCommand(command{
		kind: commandAppendEvent, tenantID: input.TenantID, subjectID: input.SubjectID,
		sessionID: input.SessionID, runtimeRevision: input.RuntimeRevision, workspaceID: input.WorkspaceID,
		turnID: input.TurnID, expectedSequence: input.ExpectedSequence,
		eventType: input.Type, payload: input.Payload, turnStatus: input.TurnStatus,
		placementGeneration: input.PlacementGeneration, authorizationGeneration: input.AuthorizationGeneration,
	})
}

func encodeCommand(cmd command) ([]byte, error) {
	if err := validateCommandShape(cmd); err != nil {
		return nil, err
	}
	fields := canonical.Map{"kind": cmd.kind}
	switch cmd.kind {
	case commandRegister:
		fields["tenantId"] = cmd.tenantID
		fields["subjectId"] = cmd.subjectID
		fields["sessionId"] = cmd.sessionID
		fields["runtimeRevision"] = cmd.runtimeRevision
		fields["workspaceId"] = cmd.workspaceID
		fields["placementGeneration"] = cmd.placementGeneration
		fields["authorizationGeneration"] = cmd.authorizationGeneration
	case commandCreateTurn:
		fields["tenantId"] = cmd.tenantID
		fields["subjectId"] = cmd.subjectID
		fields["sessionId"] = cmd.sessionID
		fields["keyDigest"] = cmd.keyDigest
		fields["requestDigest"] = cmd.requestDigest
		fields["proposedTurnId"] = cmd.proposedTurnID
		fields["authorizationGeneration"] = cmd.authorizationGeneration
	case commandAppendEvent:
		fields["tenantId"] = cmd.tenantID
		fields["subjectId"] = cmd.subjectID
		fields["sessionId"] = cmd.sessionID
		fields["runtimeRevision"] = cmd.runtimeRevision
		fields["workspaceId"] = cmd.workspaceID
		fields["turnId"] = cmd.turnID
		fields["expectedSequence"] = cmd.expectedSequence
		fields["type"] = cmd.eventType
		fields["payload"] = cmd.payload
		fields["turnStatus"] = cmd.turnStatus
		fields["placementGeneration"] = cmd.placementGeneration
		fields["authorizationGeneration"] = cmd.authorizationGeneration
	}
	return canonical.Encode(fields, canonical.DefaultOptions())
}

func decodeCommand(encoded []byte) (command, error) {
	value, err := canonical.Decode(encoded, canonical.DefaultOptions())
	if err != nil {
		return command{}, fmt.Errorf("%w: %v", ErrInvalidCommand, err)
	}
	fields, ok := value.(canonical.Map)
	if !ok {
		return command{}, fmt.Errorf("%w: command is not a map", ErrInvalidCommand)
	}
	kind, ok := fields["kind"].(string)
	if !ok {
		return command{}, fmt.Errorf("%w: missing kind", ErrInvalidCommand)
	}
	cmd := command{
		kind:                    kind,
		tenantID:                commandString(fields, "tenantId"),
		subjectID:               commandString(fields, "subjectId"),
		sessionID:               commandString(fields, "sessionId"),
		runtimeRevision:         commandString(fields, "runtimeRevision"),
		workspaceID:             commandString(fields, "workspaceId"),
		placementGeneration:     commandInt(fields, "placementGeneration"),
		authorizationGeneration: commandInt(fields, "authorizationGeneration"),
		keyDigest:               commandString(fields, "keyDigest"),
		requestDigest:           commandString(fields, "requestDigest"),
		proposedTurnID:          commandString(fields, "proposedTurnId"),
		turnID:                  commandString(fields, "turnId"),
		expectedSequence:        commandInt(fields, "expectedSequence"),
		eventType:               commandString(fields, "type"),
		payload:                 commandString(fields, "payload"),
		turnStatus:              commandString(fields, "turnStatus"),
	}
	if err := validateCommandShape(cmd); err != nil {
		return command{}, err
	}
	return cmd, nil
}

func validateCommandShape(cmd command) error {
	switch cmd.kind {
	case commandRegister:
		for _, id := range []string{cmd.tenantID, cmd.subjectID, cmd.sessionID, cmd.runtimeRevision, cmd.workspaceID} {
			if !nonControlUTF8(id) {
				return fmt.Errorf("%w: register requires non-empty identity fields", ErrInvalidCommand)
			}
		}
		if cmd.placementGeneration <= 0 || cmd.authorizationGeneration <= 0 {
			return fmt.Errorf("%w: register requires positive generations", ErrInvalidCommand)
		}
	case commandCreateTurn:
		if !nonControlUTF8(cmd.tenantID) || !nonControlUTF8(cmd.sessionID) ||
			!nonControlUTF8(cmd.subjectID) || !nonControlUTF8(cmd.keyDigest) ||
			!nonControlUTF8(cmd.requestDigest) || !nonControlUTF8(cmd.proposedTurnID) {
			return fmt.Errorf("%w: create requires tenant, subject, session, key, digest, and proposed turn", ErrInvalidCommand)
		}
		if cmd.authorizationGeneration <= 0 {
			return fmt.Errorf("%w: create requires a positive authorization generation", ErrInvalidCommand)
		}
	case commandAppendEvent:
		for _, id := range []string{cmd.tenantID, cmd.subjectID, cmd.sessionID, cmd.runtimeRevision, cmd.workspaceID} {
			if !nonControlUTF8(id) {
				return fmt.Errorf("%w: append requires complete authority scope", ErrInvalidCommand)
			}
		}
		if !nonControlUTF8(cmd.turnID) || !nonControlUTF8(cmd.payload) {
			return fmt.Errorf("%w: append requires a turn id and payload", ErrInvalidCommand)
		}
		if !validDurableEventType(cmd.eventType) {
			return fmt.Errorf("%w: append requires a durable event type", ErrInvalidCommand)
		}
		if !validTurnStatus(cmd.turnStatus) {
			return fmt.Errorf("%w: append requires a valid turn status", ErrInvalidCommand)
		}
		if cmd.expectedSequence < 0 {
			return fmt.Errorf("%w: append expected sequence must be non-negative", ErrInvalidCommand)
		}
		if cmd.placementGeneration <= 0 || cmd.authorizationGeneration <= 0 {
			return fmt.Errorf("%w: append requires positive generations", ErrInvalidCommand)
		}
	default:
		return fmt.Errorf("%w: %q", ErrUnknownCommand, cmd.kind)
	}
	return nil
}

// DecodeState decodes committed aggregate state; an empty slice is an
// unregistered session. Exposed for the Repository adapter and tests.
func DecodeState(encoded []byte) (sessionRecordView, error) {
	record, err := decodeState(encoded)
	if err != nil {
		return sessionRecordView{}, err
	}
	return sessionRecordView{record: record}, nil
}

// sessionRecordView is a read-only accessor over a decoded record for tests.
type sessionRecordView struct {
	record sessionRecord
}

func (view sessionRecordView) Registered() bool           { return view.record.registered() }
func (view sessionRecordView) LastDurableSequence() int64 { return view.record.lastDurableSequence }
func (view sessionRecordView) ActiveTurnID() string       { return view.record.activeTurnID }
func (view sessionRecordView) TurnStatus() string         { return view.record.turnStatus }
func (view sessionRecordView) EventCount() int            { return len(view.record.events) }

// DecodeCreateResponse decodes the response of a create-turn command.
func DecodeCreateResponse(encoded []byte) (turnID string, deduplicated bool, status string, err error) {
	fields, err := decodeResponse(encoded)
	if err != nil {
		return "", false, "", err
	}
	turnID, _ = fields["turnId"].(string)
	status, _ = fields["status"].(string)
	flag, _ := fields["deduplicated"].(int64)
	return turnID, flag == 1, status, nil
}

// DecodeAppendResponse decodes the response of an append-event command.
func DecodeAppendResponse(encoded []byte) (sequence uint64, turnID, eventType, payload string, err error) {
	fields, err := decodeResponse(encoded)
	if err != nil {
		return 0, "", "", "", err
	}
	seq, _ := fields["sequence"].(int64)
	if seq < 0 {
		return 0, "", "", "", fmt.Errorf("%w: negative response sequence", ErrInvalidState)
	}
	turnID, _ = fields["turnId"].(string)
	eventType, _ = fields["type"].(string)
	payload, _ = fields["payload"].(string)
	return uint64(seq), turnID, eventType, payload, nil
}

func decodeResponse(encoded []byte) (canonical.Map, error) {
	value, err := canonical.Decode(encoded, canonical.DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	fields, ok := value.(canonical.Map)
	if !ok {
		return nil, fmt.Errorf("%w: response is not a map", ErrInvalidState)
	}
	return fields, nil
}

func stateInt(fields canonical.Map, key string) (int64, error) {
	raw, ok := fields[key]
	if !ok {
		return 0, fmt.Errorf("%w: missing %q", ErrInvalidState, key)
	}
	value, ok := raw.(int64)
	if !ok {
		return 0, fmt.Errorf("%w: %q is not an integer", ErrInvalidState, key)
	}
	return value, nil
}

func stateString(fields canonical.Map, key string) (string, error) {
	raw, ok := fields[key]
	if !ok {
		return "", fmt.Errorf("%w: missing %q", ErrInvalidState, key)
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%w: %q is not a string", ErrInvalidState, key)
	}
	return value, nil
}

func commandString(fields canonical.Map, key string) string {
	if raw, ok := fields[key].(string); ok {
		return raw
	}
	return ""
}

func commandInt(fields canonical.Map, key string) int64 {
	if raw, ok := fields[key].(int64); ok {
		return raw
	}
	return 0
}
