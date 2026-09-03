// Package sessionstate implements the durable Session-DO turn state machine as a
// celld.Aggregate (SPEC.md §15.2–15.3, Phase 0B / Unit 11). This first increment
// covers sequential turn admission with a monotone event sequence, at most one
// active turn, and turn-lease generation fencing. The aggregate is pure and
// deterministic; durability, idempotency, and the crash barrier come from the
// celld.Host it runs under. It is host-independent reference work and does not
// promote any §53 status.
package sessionstate

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celld"
)

const stateSchemaVersion = int64(1)

const (
	commandOpenTurn     = "open_turn"
	commandCompleteTurn = "complete_turn"

	turnStatusIdle      = "idle"
	turnStatusAccepted  = "accepted"
	turnStatusCompleted = "completed"
)

var (
	// ErrUnknownCommand is returned for a command whose kind is not recognized.
	ErrUnknownCommand = errors.New("sessionstate: unknown command kind")
	// ErrInvalidCommand is returned for a malformed command.
	ErrInvalidCommand = errors.New("sessionstate: invalid command")
	// ErrInvalidState is returned for malformed or unsupported aggregate state.
	ErrInvalidState = errors.New("sessionstate: invalid session state")
	// ErrTurnActive is returned when a turn is opened while one is already active.
	ErrTurnActive = errors.New("sessionstate: a turn is already active")
	// ErrNoActiveTurn is returned when completing a turn that is not the active one.
	ErrNoActiveTurn = errors.New("sessionstate: no such active turn")
	// ErrStaleGeneration is returned when a command carries a turn-lease
	// generation older than the state's fenced generation.
	ErrStaleGeneration = errors.New("sessionstate: stale turn-lease generation")
)

// SessionState is the durable Session-DO turn state. The zero value (an empty
// stored object) is the initial idle session.
type SessionState struct {
	SchemaVersion       int64
	EventSequence       int64
	TurnLeaseGeneration int64
	ActiveTurnID        string
	TurnStatus          string
}

type command struct {
	Kind                string
	TurnID              string
	TurnLeaseGeneration int64
}

// Aggregate is the Session-DO turn state machine. It holds no fields: all state
// crosses the boundary as canonical-CBOR bytes.
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

// Authorize fences on the turn-lease generation before the idempotency lookup,
// so a command minted under a rotated-out generation is rejected even on replay.
func (Aggregate) Authorize(_ context.Context, stateBytes, commandBytes []byte) error {
	state, err := decodeState(stateBytes)
	if err != nil {
		return err
	}
	cmd, err := decodeCommand(commandBytes)
	if err != nil {
		return err
	}
	if cmd.TurnLeaseGeneration < state.TurnLeaseGeneration {
		return fmt.Errorf("%w: command %d < state %d", ErrStaleGeneration, cmd.TurnLeaseGeneration, state.TurnLeaseGeneration)
	}
	return nil
}

// Apply performs one deterministic turn transition and returns the next state
// and a response. It never produces capability claims in this increment.
func (Aggregate) Apply(_ context.Context, stateBytes, commandBytes []byte) (celld.ApplyResult, error) {
	state, err := decodeState(stateBytes)
	if err != nil {
		return celld.ApplyResult{}, err
	}
	cmd, err := decodeCommand(commandBytes)
	if err != nil {
		return celld.ApplyResult{}, err
	}
	switch cmd.Kind {
	case commandOpenTurn:
		if state.ActiveTurnID != "" {
			return celld.ApplyResult{}, fmt.Errorf("%w: %q is active", ErrTurnActive, state.ActiveTurnID)
		}
		state.ActiveTurnID = cmd.TurnID
		state.TurnStatus = turnStatusAccepted
	case commandCompleteTurn:
		if state.ActiveTurnID != cmd.TurnID {
			return celld.ApplyResult{}, fmt.Errorf("%w: active %q, requested %q", ErrNoActiveTurn, state.ActiveTurnID, cmd.TurnID)
		}
		state.ActiveTurnID = ""
		state.TurnStatus = turnStatusCompleted
	default:
		return celld.ApplyResult{}, fmt.Errorf("%w: %q", ErrUnknownCommand, cmd.Kind)
	}
	state.EventSequence++
	state.TurnLeaseGeneration = cmd.TurnLeaseGeneration

	nextState, err := encodeState(state)
	if err != nil {
		return celld.ApplyResult{}, err
	}
	response, err := canonical.Encode(canonical.Map{
		"admittedTurnId": cmd.TurnID,
		"turnStatus":     state.TurnStatus,
		"eventSequence":  state.EventSequence,
	}, canonical.DefaultOptions())
	if err != nil {
		return celld.ApplyResult{}, err
	}
	return celld.ApplyResult{NextState: nextState, Response: response}, nil
}

// EncodeOpenTurn / EncodeCompleteTurn build canonical command bytes.
func EncodeOpenTurn(turnID string, turnLeaseGeneration int64) ([]byte, error) {
	return encodeCommand(command{Kind: commandOpenTurn, TurnID: turnID, TurnLeaseGeneration: turnLeaseGeneration})
}

func EncodeCompleteTurn(turnID string, turnLeaseGeneration int64) ([]byte, error) {
	return encodeCommand(command{Kind: commandCompleteTurn, TurnID: turnID, TurnLeaseGeneration: turnLeaseGeneration})
}

// DecodeState decodes stored aggregate state (an empty slice is the initial
// idle session). Exposed so tests and future readers can inspect a session.
func DecodeState(encoded []byte) (SessionState, error) {
	return decodeState(encoded)
}

func encodeState(state SessionState) ([]byte, error) {
	return canonical.Encode(canonical.Map{
		"schemaVersion":       state.SchemaVersion,
		"eventSequence":       state.EventSequence,
		"turnLeaseGeneration": state.TurnLeaseGeneration,
		"activeTurnId":        state.ActiveTurnID,
		"turnStatus":          state.TurnStatus,
	}, canonical.DefaultOptions())
}

func decodeState(encoded []byte) (SessionState, error) {
	if len(encoded) == 0 {
		return SessionState{SchemaVersion: stateSchemaVersion, TurnStatus: turnStatusIdle}, nil
	}
	value, err := canonical.Decode(encoded, canonical.DefaultOptions())
	if err != nil {
		return SessionState{}, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	fields, ok := value.(canonical.Map)
	if !ok {
		return SessionState{}, fmt.Errorf("%w: state is not a map", ErrInvalidState)
	}
	state := SessionState{}
	if state.SchemaVersion, err = mapInt(fields, "schemaVersion"); err != nil {
		return SessionState{}, err
	}
	if state.SchemaVersion != stateSchemaVersion {
		return SessionState{}, fmt.Errorf("%w: schema version %d", ErrInvalidState, state.SchemaVersion)
	}
	if state.EventSequence, err = mapInt(fields, "eventSequence"); err != nil {
		return SessionState{}, err
	}
	if state.TurnLeaseGeneration, err = mapInt(fields, "turnLeaseGeneration"); err != nil {
		return SessionState{}, err
	}
	if state.ActiveTurnID, err = mapString(fields, "activeTurnId"); err != nil {
		return SessionState{}, err
	}
	if state.TurnStatus, err = mapString(fields, "turnStatus"); err != nil {
		return SessionState{}, err
	}
	if state.EventSequence < 0 || state.TurnLeaseGeneration < 0 {
		return SessionState{}, fmt.Errorf("%w: negative counter", ErrInvalidState)
	}
	return state, nil
}

func encodeCommand(cmd command) ([]byte, error) {
	return canonical.Encode(canonical.Map{
		"kind":                cmd.Kind,
		"turnId":              cmd.TurnID,
		"turnLeaseGeneration": cmd.TurnLeaseGeneration,
	}, canonical.DefaultOptions())
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
	cmd := command{}
	if cmd.Kind, err = mapString(fields, "kind"); err != nil {
		return command{}, err
	}
	if cmd.Kind != commandOpenTurn && cmd.Kind != commandCompleteTurn {
		return command{}, fmt.Errorf("%w: %q", ErrUnknownCommand, cmd.Kind)
	}
	if cmd.TurnID, err = mapString(fields, "turnId"); err != nil {
		return command{}, err
	}
	if cmd.TurnID == "" || !utf8.ValidString(cmd.TurnID) {
		return command{}, fmt.Errorf("%w: empty or non-UTF-8 turn id", ErrInvalidCommand)
	}
	if cmd.TurnLeaseGeneration, err = mapInt(fields, "turnLeaseGeneration"); err != nil {
		return command{}, err
	}
	if cmd.TurnLeaseGeneration <= 0 {
		return command{}, fmt.Errorf("%w: turn-lease generation must be positive", ErrInvalidCommand)
	}
	return cmd, nil
}

func mapInt(fields canonical.Map, key string) (int64, error) {
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

func mapString(fields canonical.Map, key string) (string, error) {
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
