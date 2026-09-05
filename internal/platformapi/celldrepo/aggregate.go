// Package celldrepo composes the public turn/event Repository contract over the
// celld host boundary (Unit 12.4, reference-first). The Aggregate is a pure,
// deterministic celld.Aggregate holding the public session's durable record —
// registration, per-key creation receipts, turns, the durable event journal,
// and the replay snapshot — in canonical CBOR. Idempotency, single-writer
// serialization, and the crash barrier come from the celld.Host it runs under.
//
// This is host-independent reference work: run over a non-durable reference
// celld.Storage it proves the composition and recovery LOGIC only. It promotes
// no §53 status. A real crash-durable celld substrate is qualified separately
// (Unit 11.6) and is what a served, promotable Repository requires.
package celldrepo

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/sessionevent"
)

const stateSchemaVersion = int64(1)

const (
	commandRegister    = "register"
	commandCreateTurn  = "create_turn"
	commandAppendEvent = "append_event"
)

var (
	// ErrInvalidCommand is returned for a malformed command.
	ErrInvalidCommand = errors.New("celldrepo: invalid command")
	// ErrUnknownCommand is returned for an unrecognized command kind.
	ErrUnknownCommand = errors.New("celldrepo: unknown command kind")
	// ErrInvalidState is returned for malformed or unsupported aggregate state.
	ErrInvalidState = errors.New("celldrepo: invalid session state")
	// ErrNotRegistered is returned when a command targets an unregistered session.
	ErrNotRegistered = errors.New("celldrepo: session is not registered")
	// ErrRegistrationConflict is returned when re-registering a session with
	// different registration fields.
	ErrRegistrationConflict = errors.New("celldrepo: session already registered with different fields")
	// ErrAccessDenied is returned when a command's subject does not match the
	// registered session subject.
	ErrAccessDenied = errors.New("celldrepo: access denied")
	// ErrIdempotencyConflict is returned when an idempotency key is reused with a
	// different request digest, or a proposed turn id collides.
	ErrIdempotencyConflict = errors.New("celldrepo: idempotency conflict")
	// ErrSequenceConflict is returned when a durable append does not match the
	// current expected sequence.
	ErrSequenceConflict = errors.New("celldrepo: durable event sequence conflict")
	// ErrTurnNotFound is returned when a durable append targets an unknown turn.
	ErrTurnNotFound = errors.New("celldrepo: turn not found")
	// ErrInvalidTransition is returned when a durable event is not valid from the
	// current turn status.
	ErrInvalidTransition = errors.New("celldrepo: invalid turn transition")
	// ErrStaleAuthority is returned when a command carries a placement or
	// authorization generation that does not match the registered session.
	ErrStaleAuthority = errors.New("celldrepo: stale authority generation")
)

// Aggregate is the public-session durable record state machine. It holds no
// fields: all state crosses the boundary as canonical-CBOR bytes.
type Aggregate struct{}

// ValidateCommand rejects malformed or unknown commands before any state read.
func (Aggregate) ValidateCommand(_ context.Context, encoded []byte) error {
	_, err := decodeCommand(encoded)
	return err
}

// ValidateState rejects malformed or unsupported stored state.
func (Aggregate) ValidateState(_ context.Context, encoded []byte) error {
	_, err := decodeState(encoded)
	return err
}

// Authorize decodes both sides so a malformed pair is rejected before the
// idempotency lookup. The durable authority and generation fences live in Apply,
// which runs against the committed record.
func (Aggregate) Authorize(_ context.Context, stateBytes, commandBytes []byte) error {
	if _, err := decodeState(stateBytes); err != nil {
		return err
	}
	if _, err := decodeCommand(commandBytes); err != nil {
		return err
	}
	return nil
}

// Apply performs one deterministic durable transition and returns the next state
// and a response.
func (Aggregate) Apply(_ context.Context, stateBytes, commandBytes []byte) (celld.ApplyResult, error) {
	state, err := decodeState(stateBytes)
	if err != nil {
		return celld.ApplyResult{}, err
	}
	cmd, err := decodeCommand(commandBytes)
	if err != nil {
		return celld.ApplyResult{}, err
	}
	switch cmd.kind {
	case commandRegister:
		return applyRegister(state, cmd)
	case commandCreateTurn:
		return applyCreateTurn(state, cmd)
	case commandAppendEvent:
		return applyAppendEvent(state, cmd)
	default:
		return celld.ApplyResult{}, fmt.Errorf("%w: %q", ErrUnknownCommand, cmd.kind)
	}
}

func applyRegister(state sessionRecord, cmd command) (celld.ApplyResult, error) {
	incoming := sessionRecord{
		schemaVersion: stateSchemaVersion,
		tenantID:      cmd.tenantID, subjectID: cmd.subjectID, sessionID: cmd.sessionID,
		runtimeRevision: cmd.runtimeRevision, workspaceID: cmd.workspaceID,
		placementGeneration: cmd.placementGeneration, authorizationGeneration: cmd.authorizationGeneration,
	}
	if state.registered() {
		if state.tenantID != incoming.tenantID || state.subjectID != incoming.subjectID ||
			state.sessionID != incoming.sessionID || state.runtimeRevision != incoming.runtimeRevision ||
			state.workspaceID != incoming.workspaceID ||
			state.placementGeneration != incoming.placementGeneration ||
			state.authorizationGeneration != incoming.authorizationGeneration {
			return celld.ApplyResult{}, ErrRegistrationConflict
		}
		return finish(state, canonical.Map{"kind": "registered", "sessionId": state.sessionID})
	}
	incoming.turns = state.turns
	incoming.creationReceipts = state.creationReceipts
	incoming.events = state.events
	return finish(incoming, canonical.Map{"kind": "registered", "sessionId": incoming.sessionID})
}

func applyCreateTurn(state sessionRecord, cmd command) (celld.ApplyResult, error) {
	if !state.registered() {
		return celld.ApplyResult{}, ErrNotRegistered
	}
	if cmd.subjectID != state.subjectID {
		return celld.ApplyResult{}, ErrAccessDenied
	}
	if cmd.authorizationGeneration != state.authorizationGeneration {
		return celld.ApplyResult{}, ErrStaleAuthority
	}
	if receipt, found := state.creationReceipts[cmd.keyDigest]; found {
		if receipt.requestDigest != cmd.requestDigest {
			return celld.ApplyResult{}, ErrIdempotencyConflict
		}
		turn := state.turns[receipt.turnID]
		return finish(state, createResponse(receipt.turnID, true, turn.status))
	}
	if _, collision := state.turns[cmd.proposedTurnID]; collision {
		return celld.ApplyResult{}, ErrIdempotencyConflict
	}
	next := state.clone()
	next.turns[cmd.proposedTurnID] = turnRecord{requestDigest: cmd.requestDigest, status: string(sessionevent.TurnQueued)}
	next.creationReceipts[cmd.keyDigest] = creationRecord{requestDigest: cmd.requestDigest, turnID: cmd.proposedTurnID}
	if next.activeTurnID == "" {
		next.activeTurnID = cmd.proposedTurnID
		next.turnStatus = string(sessionevent.TurnQueued)
	}
	return finish(next, createResponse(cmd.proposedTurnID, false, string(sessionevent.TurnQueued)))
}

func applyAppendEvent(state sessionRecord, cmd command) (celld.ApplyResult, error) {
	if !state.registered() {
		return celld.ApplyResult{}, ErrNotRegistered
	}
	if cmd.placementGeneration != state.placementGeneration ||
		cmd.authorizationGeneration != state.authorizationGeneration {
		return celld.ApplyResult{}, ErrStaleAuthority
	}
	if cmd.expectedSequence != int64(len(state.events)) {
		return celld.ApplyResult{}, ErrSequenceConflict
	}
	turn, found := state.turns[cmd.turnID]
	if !found {
		return celld.ApplyResult{}, ErrTurnNotFound
	}
	if err := validateTurnTransition(turn.status, cmd.turnStatus, cmd.eventType); err != nil {
		return celld.ApplyResult{}, err
	}
	next := state.clone()
	sequence := int64(len(next.events)) + 1
	next.events = append(next.events, eventRecord{
		sequence: sequence, turnID: cmd.turnID, eventType: cmd.eventType, payload: cmd.payload,
	})
	turn.status = cmd.turnStatus
	next.turns[cmd.turnID] = turn
	next.activeTurnID = cmd.turnID
	next.turnStatus = cmd.turnStatus
	next.lastDurableSequence = sequence
	return finish(next, canonical.Map{
		"sequence": sequence, "turnId": cmd.turnID,
		"type": cmd.eventType, "payload": cmd.payload,
	})
}

func createResponse(turnID string, deduplicated bool, status string) canonical.Map {
	flag := int64(0)
	if deduplicated {
		flag = 1
	}
	return canonical.Map{"turnId": turnID, "deduplicated": flag, "status": status}
}

func finish(state sessionRecord, response canonical.Map) (celld.ApplyResult, error) {
	nextBytes, err := encodeState(state)
	if err != nil {
		return celld.ApplyResult{}, err
	}
	responseBytes, err := canonical.Encode(response, canonical.DefaultOptions())
	if err != nil {
		return celld.ApplyResult{}, err
	}
	return celld.ApplyResult{NextState: nextBytes, Response: responseBytes}, nil
}

// validateStatusForEvent mirrors the platformapi status/event pairing: a durable
// event may only accompany the exact turn status it represents.
func validateStatusForEvent(eventType, status string) error {
	wanted := string(sessionevent.TurnActive)
	switch eventType {
	case string(sessionevent.EventTurnNeedsConfirmation):
		wanted = string(sessionevent.TurnNeedsConfirmation)
	case string(sessionevent.EventTurnCompleted):
		wanted = string(sessionevent.TurnCompleted)
	case string(sessionevent.EventTurnFailed):
		wanted = string(sessionevent.TurnFailed)
	case string(sessionevent.EventTurnAborted):
		wanted = string(sessionevent.TurnAborted)
	}
	if status != wanted {
		return ErrInvalidTransition
	}
	return nil
}

// validateTurnTransition mirrors platformapi.validateTurnTransition, enforcing
// the durable turn status ladder for an appended event.
func validateTurnTransition(current, next, eventType string) error {
	if !validDurableEventType(eventType) {
		return ErrInvalidTransition
	}
	if err := validateStatusForEvent(eventType, next); err != nil {
		return err
	}
	switch current {
	case string(sessionevent.TurnQueued):
		if eventType == string(sessionevent.EventTurnAccepted) && next == string(sessionevent.TurnActive) {
			return nil
		}
	case string(sessionevent.TurnActive):
		switch next {
		case string(sessionevent.TurnActive), string(sessionevent.TurnNeedsConfirmation),
			string(sessionevent.TurnCompleted), string(sessionevent.TurnFailed), string(sessionevent.TurnAborted):
			return nil
		}
	case string(sessionevent.TurnNeedsConfirmation):
		switch next {
		case string(sessionevent.TurnActive), string(sessionevent.TurnCompleted),
			string(sessionevent.TurnFailed), string(sessionevent.TurnAborted):
			return nil
		}
	}
	return ErrInvalidTransition
}

func validDurableEventType(value string) bool {
	switch sessionevent.EventType(value) {
	case sessionevent.EventTurnAccepted, sessionevent.EventModelEffectPrepared, sessionevent.EventModelSettled,
		sessionevent.EventToolEffectPrepared, sessionevent.EventToolExternallyCommit, sessionevent.EventToolSettled,
		sessionevent.EventTurnNeedsConfirmation, sessionevent.EventTurnCompleted,
		sessionevent.EventTurnFailed, sessionevent.EventTurnAborted:
		return true
	default:
		return false
	}
}

func validTurnStatus(value string) bool {
	switch sessionevent.TurnStatus(value) {
	case sessionevent.TurnQueued, sessionevent.TurnActive, sessionevent.TurnNeedsConfirmation,
		sessionevent.TurnCompleted, sessionevent.TurnFailed, sessionevent.TurnAborted:
		return true
	default:
		return false
	}
}

// nonControlUTF8 reports whether value is a non-empty UTF-8 string free of C0/C1
// control characters — the shape required of a protocol identifier.
func nonControlUTF8(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return false
		}
	}
	return true
}
