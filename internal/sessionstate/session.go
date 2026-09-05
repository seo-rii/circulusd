// Package sessionstate implements the durable Session-DO turn/effect state
// machine as a celld.Aggregate (SPEC.md §15.2-15.4, Phase 0B / Unit 11). The
// aggregate is pure and deterministic; durability, idempotency, and the crash
// barrier come from the celld.Host it runs under. It is host-independent
// reference work and does not promote any §53 status.
//
// The turn ladder is
//
//	idle → accepted → model_prepared → model_dispatched → model_settled →
//	       tool_prepared → tool_dispatched → tool_external_commit → tool_settled → (idle)
//
// with the §15.3 serial-effect invariant: at most one effect is active (between
// prepared and settled) at any time.
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

// Turn ladder phases.
const (
	phaseIdle               = "idle"
	phaseAccepted           = "accepted"
	phaseModelPrepared      = "model_prepared"
	phaseModelDispatched    = "model_dispatched"
	phaseModelSettled       = "model_settled"
	phaseToolPrepared       = "tool_prepared"
	phaseToolDispatched     = "tool_dispatched"
	phaseToolExternalCommit = "tool_external_commit"
	phaseToolSettled        = "tool_settled"
)

// Effect kinds and effect phases.
const (
	effectKindModel = "model"
	effectKindTool  = "tool"

	effectPhasePrepared   = "prepared"
	effectPhaseDispatched = "dispatched"
	effectPhaseCommitted  = "committed"
)

// Command kinds.
const (
	commandOpenTurn      = "open_turn"
	commandCompleteTurn  = "complete_turn"
	commandPrepareModel  = "prepare_model_effect"
	commandDispatchModel = "dispatch_model_effect"
	commandSettleModel   = "settle_model_effect"
	commandPrepareTool   = "prepare_tool_effect"
	commandDispatchTool  = "dispatch_tool_effect"
	commandCommitTool    = "commit_tool_effect"
	commandSettleTool    = "settle_tool_effect"

	commandRotatePlacement = "rotate_placement_generation"
	commandRotatePolicy    = "rotate_policy_generation"
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
	// ErrNoActiveTurn is returned when acting on a turn that is not the active one.
	ErrNoActiveTurn = errors.New("sessionstate: no such active turn")
	// ErrInvalidTransition is returned when a command is not valid from the
	// current turn phase (an out-of-order ladder step).
	ErrInvalidTransition = errors.New("sessionstate: invalid turn transition")
	// ErrEffectActive is returned when a new effect is prepared while one is
	// already active, violating the §15.3 serial-effect invariant.
	ErrEffectActive = errors.New("sessionstate: an effect is already active")
	// ErrEffectMismatch is returned when a command targets an effect id, kind, or
	// phase that does not match the active effect.
	ErrEffectMismatch = errors.New("sessionstate: effect identity or phase mismatch")
	// ErrStaleGeneration is returned when a command carries a turn-lease
	// generation older than the state's fenced generation.
	ErrStaleGeneration = errors.New("sessionstate: stale turn-lease generation")
	// ErrStalePlacementGeneration is returned when a dispatch carries a placement
	// generation older than the session's rotated placement generation (§53.4).
	ErrStalePlacementGeneration = errors.New("sessionstate: stale placement generation")
	// ErrStalePolicyGeneration is returned when a prepare carries a policy
	// generation older than the session's rotated policy generation (§53.4).
	ErrStalePolicyGeneration = errors.New("sessionstate: stale policy generation")
	// ErrInvalidRotation is returned when a generation rotation does not strictly
	// advance the current generation.
	ErrInvalidRotation = errors.New("sessionstate: generation rotation must advance")
)

// SessionState is the durable Session-DO turn/effect state. The zero value (an
// empty stored object) is the initial idle session.
type SessionState struct {
	SchemaVersion       int64
	EventSequence       int64
	TurnLeaseGeneration int64
	PlacementGeneration int64
	PolicyGeneration    int64
	ActiveTurnID        string
	TurnPhase           string

	// At most one effect is active (§15.3 serial-effect invariant). Empty
	// EffectID means no active effect.
	EffectID         string
	EffectKind       string
	EffectPhase      string
	EffectRequestID  string
	EffectProviderID string
	EffectExternalID string
}

type command struct {
	Kind                string
	TurnID              string
	EffectID            string
	RequestDigest       string
	ProviderRequestID   string
	ExternalCommitID    string
	TurnLeaseGeneration int64
	PlacementGeneration int64
	PolicyGeneration    int64
}

// Aggregate is the Session-DO turn/effect state machine. It holds no fields: all
// state crosses the boundary as canonical-CBOR bytes.
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

// Apply performs one deterministic turn/effect transition and returns the next
// state and a response.
func (Aggregate) Apply(_ context.Context, stateBytes, commandBytes []byte) (celld.ApplyResult, error) {
	state, err := decodeState(stateBytes)
	if err != nil {
		return celld.ApplyResult{}, err
	}
	cmd, err := decodeCommand(commandBytes)
	if err != nil {
		return celld.ApplyResult{}, err
	}
	next, err := transition(state, cmd)
	if err != nil {
		return celld.ApplyResult{}, err
	}
	next.EventSequence = state.EventSequence + 1
	next.TurnLeaseGeneration = cmd.TurnLeaseGeneration

	nextBytes, err := encodeState(next)
	if err != nil {
		return celld.ApplyResult{}, err
	}
	response, err := canonical.Encode(canonical.Map{
		"turnId":        cmd.TurnID,
		"turnPhase":     next.TurnPhase,
		"eventSequence": next.EventSequence,
	}, canonical.DefaultOptions())
	if err != nil {
		return celld.ApplyResult{}, err
	}
	return celld.ApplyResult{NextState: nextBytes, Response: response}, nil
}

// transition returns the next state for one command, enforcing the ladder order
// and the serial-effect invariant. It does not touch EventSequence or the
// turn-lease generation floor; Apply advances those.
func transition(state SessionState, cmd command) (SessionState, error) {
	switch cmd.Kind {
	case commandOpenTurn:
		if state.ActiveTurnID != "" {
			return SessionState{}, fmt.Errorf("%w: %q is active", ErrTurnActive, state.ActiveTurnID)
		}
		state.ActiveTurnID = cmd.TurnID
		state.TurnPhase = phaseAccepted
		return state, nil

	case commandCompleteTurn:
		if err := requireActiveTurn(state, cmd.TurnID); err != nil {
			return SessionState{}, err
		}
		if state.EffectID != "" {
			return SessionState{}, fmt.Errorf("%w: cannot complete with active effect %q", ErrEffectActive, state.EffectID)
		}
		switch state.TurnPhase {
		case phaseAccepted, phaseModelSettled, phaseToolSettled:
		default:
			return SessionState{}, fmt.Errorf("%w: cannot complete from %q", ErrInvalidTransition, state.TurnPhase)
		}
		state.ActiveTurnID = ""
		state.TurnPhase = phaseIdle
		return state, nil

	case commandPrepareModel:
		return prepareEffect(state, cmd, effectKindModel, phaseAccepted, phaseModelPrepared)

	case commandDispatchModel:
		return dispatchEffect(state, cmd, effectKindModel, phaseModelPrepared, phaseModelDispatched)

	case commandSettleModel:
		if err := requireActiveEffect(state, cmd, effectKindModel, effectPhaseDispatched, phaseModelDispatched); err != nil {
			return SessionState{}, err
		}
		clearEffect(&state)
		state.TurnPhase = phaseModelSettled
		return state, nil

	case commandPrepareTool:
		return prepareEffect(state, cmd, effectKindTool, phaseModelSettled, phaseToolPrepared)

	case commandDispatchTool:
		return dispatchEffect(state, cmd, effectKindTool, phaseToolPrepared, phaseToolDispatched)

	case commandCommitTool:
		// The external commit is recorded before settlement (commit-before-settle
		// ordering): a tool effect cannot settle until its external side effect is
		// durably acknowledged.
		if err := requireActiveEffect(state, cmd, effectKindTool, effectPhaseDispatched, phaseToolDispatched); err != nil {
			return SessionState{}, err
		}
		state.TurnPhase = phaseToolExternalCommit
		state.EffectPhase = effectPhaseCommitted
		state.EffectExternalID = cmd.ExternalCommitID
		return state, nil

	case commandSettleTool:
		if err := requireActiveEffect(state, cmd, effectKindTool, effectPhaseCommitted, phaseToolExternalCommit); err != nil {
			return SessionState{}, err
		}
		clearEffect(&state)
		state.TurnPhase = phaseToolSettled
		return state, nil

	case commandRotatePlacement:
		if cmd.PlacementGeneration <= state.PlacementGeneration {
			return SessionState{}, fmt.Errorf("%w: placement %d <= %d", ErrInvalidRotation, cmd.PlacementGeneration, state.PlacementGeneration)
		}
		state.PlacementGeneration = cmd.PlacementGeneration
		return state, nil

	case commandRotatePolicy:
		if cmd.PolicyGeneration <= state.PolicyGeneration {
			return SessionState{}, fmt.Errorf("%w: policy %d <= %d", ErrInvalidRotation, cmd.PolicyGeneration, state.PolicyGeneration)
		}
		state.PolicyGeneration = cmd.PolicyGeneration
		return state, nil

	default:
		return SessionState{}, fmt.Errorf("%w: %q", ErrUnknownCommand, cmd.Kind)
	}
}

func prepareEffect(state SessionState, cmd command, kind, fromPhase, toPhase string) (SessionState, error) {
	if err := requireActiveTurn(state, cmd.TurnID); err != nil {
		return SessionState{}, err
	}
	// The serial-effect invariant is checked first: no new effect may begin
	// while one is still active (§15.3).
	if state.EffectID != "" {
		return SessionState{}, fmt.Errorf("%w: %q still active", ErrEffectActive, state.EffectID)
	}
	if state.TurnPhase != fromPhase {
		return SessionState{}, fmt.Errorf("%w: prepare %s from %q", ErrInvalidTransition, kind, state.TurnPhase)
	}
	// A prepare minted under a policy generation the session has since rotated
	// past is fenced out (§53.4).
	if cmd.PolicyGeneration < state.PolicyGeneration {
		return SessionState{}, fmt.Errorf("%w: %d < %d", ErrStalePolicyGeneration, cmd.PolicyGeneration, state.PolicyGeneration)
	}
	state.TurnPhase = toPhase
	state.EffectID = cmd.EffectID
	state.EffectKind = kind
	state.EffectPhase = effectPhasePrepared
	state.EffectRequestID = cmd.RequestDigest
	return state, nil
}

func dispatchEffect(state SessionState, cmd command, kind, fromPhase, toPhase string) (SessionState, error) {
	if err := requireActiveEffect(state, cmd, kind, effectPhasePrepared, fromPhase); err != nil {
		return SessionState{}, err
	}
	// A dispatch minted under a placement generation the session has since
	// rotated past is fenced out (§53.4).
	if cmd.PlacementGeneration < state.PlacementGeneration {
		return SessionState{}, fmt.Errorf("%w: %d < %d", ErrStalePlacementGeneration, cmd.PlacementGeneration, state.PlacementGeneration)
	}
	state.TurnPhase = toPhase
	state.EffectPhase = effectPhaseDispatched
	state.EffectProviderID = cmd.ProviderRequestID
	return state, nil
}

func requireActiveTurn(state SessionState, turnID string) error {
	if state.ActiveTurnID == "" || state.ActiveTurnID != turnID {
		return fmt.Errorf("%w: active %q, requested %q", ErrNoActiveTurn, state.ActiveTurnID, turnID)
	}
	return nil
}

func requireActiveEffect(state SessionState, cmd command, kind, effectPhase, turnPhase string) error {
	if err := requireActiveTurn(state, cmd.TurnID); err != nil {
		return err
	}
	if state.TurnPhase != turnPhase {
		return fmt.Errorf("%w: expected %q, in %q", ErrInvalidTransition, turnPhase, state.TurnPhase)
	}
	if state.EffectID != cmd.EffectID || state.EffectKind != kind || state.EffectPhase != effectPhase {
		return fmt.Errorf("%w: active %s/%s/%s, requested %s", ErrEffectMismatch,
			state.EffectID, state.EffectKind, state.EffectPhase, cmd.EffectID)
	}
	return nil
}

func clearEffect(state *SessionState) {
	state.EffectID = ""
	state.EffectKind = ""
	state.EffectPhase = ""
	state.EffectRequestID = ""
	state.EffectProviderID = ""
	state.EffectExternalID = ""
}

// Command encoders. Each builds a canonical-CBOR command body.

func EncodeOpenTurn(turnID string, turnLeaseGeneration int64) ([]byte, error) {
	return encodeCommand(command{Kind: commandOpenTurn, TurnID: turnID, TurnLeaseGeneration: turnLeaseGeneration})
}

func EncodeCompleteTurn(turnID string, turnLeaseGeneration int64) ([]byte, error) {
	return encodeCommand(command{Kind: commandCompleteTurn, TurnID: turnID, TurnLeaseGeneration: turnLeaseGeneration})
}

func EncodePrepareModelEffect(turnID, effectID, requestDigest string, turnLeaseGeneration int64) ([]byte, error) {
	return encodeCommand(command{
		Kind: commandPrepareModel, TurnID: turnID, EffectID: effectID,
		RequestDigest: requestDigest, TurnLeaseGeneration: turnLeaseGeneration,
	})
}

func EncodeDispatchModelEffect(turnID, effectID, providerRequestID string, turnLeaseGeneration int64) ([]byte, error) {
	return encodeCommand(command{
		Kind: commandDispatchModel, TurnID: turnID, EffectID: effectID,
		ProviderRequestID: providerRequestID, TurnLeaseGeneration: turnLeaseGeneration,
	})
}

func EncodeSettleModelEffect(turnID, effectID, externalCommitID string, turnLeaseGeneration int64) ([]byte, error) {
	return encodeCommand(command{
		Kind: commandSettleModel, TurnID: turnID, EffectID: effectID,
		ExternalCommitID: externalCommitID, TurnLeaseGeneration: turnLeaseGeneration,
	})
}

func EncodePrepareToolEffect(turnID, effectID, requestDigest string, turnLeaseGeneration int64) ([]byte, error) {
	return encodeCommand(command{
		Kind: commandPrepareTool, TurnID: turnID, EffectID: effectID,
		RequestDigest: requestDigest, TurnLeaseGeneration: turnLeaseGeneration,
	})
}

func EncodeDispatchToolEffect(turnID, effectID, providerRequestID string, turnLeaseGeneration int64) ([]byte, error) {
	return encodeCommand(command{
		Kind: commandDispatchTool, TurnID: turnID, EffectID: effectID,
		ProviderRequestID: providerRequestID, TurnLeaseGeneration: turnLeaseGeneration,
	})
}

func EncodeCommitToolEffect(turnID, effectID, externalCommitID string, turnLeaseGeneration int64) ([]byte, error) {
	return encodeCommand(command{
		Kind: commandCommitTool, TurnID: turnID, EffectID: effectID,
		ExternalCommitID: externalCommitID, TurnLeaseGeneration: turnLeaseGeneration,
	})
}

func EncodeSettleToolEffect(turnID, effectID string, turnLeaseGeneration int64) ([]byte, error) {
	return encodeCommand(command{
		Kind: commandSettleTool, TurnID: turnID, EffectID: effectID,
		TurnLeaseGeneration: turnLeaseGeneration,
	})
}

// EncodeDispatchModelEffectAt is EncodeDispatchModelEffect bound to a placement
// generation, so a dispatch minted under a rotated-out placement is fenced.
func EncodeDispatchModelEffectAt(turnID, effectID, providerRequestID string, placementGeneration, turnLeaseGeneration int64) ([]byte, error) {
	return encodeCommand(command{
		Kind: commandDispatchModel, TurnID: turnID, EffectID: effectID,
		ProviderRequestID: providerRequestID, PlacementGeneration: placementGeneration,
		TurnLeaseGeneration: turnLeaseGeneration,
	})
}

// EncodePrepareModelEffectAt is EncodePrepareModelEffect bound to a policy
// generation, so a prepare minted under a rotated-out policy is fenced.
func EncodePrepareModelEffectAt(turnID, effectID, requestDigest string, policyGeneration, turnLeaseGeneration int64) ([]byte, error) {
	return encodeCommand(command{
		Kind: commandPrepareModel, TurnID: turnID, EffectID: effectID,
		RequestDigest: requestDigest, PolicyGeneration: policyGeneration,
		TurnLeaseGeneration: turnLeaseGeneration,
	})
}

func EncodeRotatePlacement(turnID string, placementGeneration, turnLeaseGeneration int64) ([]byte, error) {
	return encodeCommand(command{
		Kind: commandRotatePlacement, TurnID: turnID,
		PlacementGeneration: placementGeneration, TurnLeaseGeneration: turnLeaseGeneration,
	})
}

func EncodeRotatePolicy(turnID string, policyGeneration, turnLeaseGeneration int64) ([]byte, error) {
	return encodeCommand(command{
		Kind: commandRotatePolicy, TurnID: turnID,
		PolicyGeneration: policyGeneration, TurnLeaseGeneration: turnLeaseGeneration,
	})
}

// DecodeState decodes stored aggregate state (an empty slice is the initial idle
// session). Exposed so tests and future readers can inspect a session.
func DecodeState(encoded []byte) (SessionState, error) {
	return decodeState(encoded)
}

func encodeState(state SessionState) ([]byte, error) {
	return canonical.Encode(canonical.Map{
		"schemaVersion":       state.SchemaVersion,
		"eventSequence":       state.EventSequence,
		"turnLeaseGeneration": state.TurnLeaseGeneration,
		"placementGeneration": state.PlacementGeneration,
		"policyGeneration":    state.PolicyGeneration,
		"activeTurnId":        state.ActiveTurnID,
		"turnPhase":           state.TurnPhase,
		"effectId":            state.EffectID,
		"effectKind":          state.EffectKind,
		"effectPhase":         state.EffectPhase,
		"effectRequestId":     state.EffectRequestID,
		"effectProviderId":    state.EffectProviderID,
		"effectExternalId":    state.EffectExternalID,
	}, canonical.DefaultOptions())
}

func decodeState(encoded []byte) (SessionState, error) {
	if len(encoded) == 0 {
		return SessionState{SchemaVersion: stateSchemaVersion, TurnPhase: phaseIdle}, nil
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
	ints := []struct {
		key   string
		field *int64
	}{
		{"schemaVersion", &state.SchemaVersion},
		{"eventSequence", &state.EventSequence},
		{"turnLeaseGeneration", &state.TurnLeaseGeneration},
		{"placementGeneration", &state.PlacementGeneration},
		{"policyGeneration", &state.PolicyGeneration},
	}
	for _, entry := range ints {
		if *entry.field, err = reqInt(fields, entry.key); err != nil {
			return SessionState{}, err
		}
	}
	strs := []struct {
		key   string
		field *string
	}{
		{"activeTurnId", &state.ActiveTurnID},
		{"turnPhase", &state.TurnPhase},
		{"effectId", &state.EffectID},
		{"effectKind", &state.EffectKind},
		{"effectPhase", &state.EffectPhase},
		{"effectRequestId", &state.EffectRequestID},
		{"effectProviderId", &state.EffectProviderID},
		{"effectExternalId", &state.EffectExternalID},
	}
	for _, entry := range strs {
		if *entry.field, err = reqString(fields, entry.key); err != nil {
			return SessionState{}, err
		}
	}
	if state.SchemaVersion != stateSchemaVersion {
		return SessionState{}, fmt.Errorf("%w: schema version %d", ErrInvalidState, state.SchemaVersion)
	}
	if state.EventSequence < 0 || state.TurnLeaseGeneration < 0 || state.PlacementGeneration < 0 || state.PolicyGeneration < 0 {
		return SessionState{}, fmt.Errorf("%w: negative counter", ErrInvalidState)
	}
	return state, nil
}

func encodeCommand(cmd command) ([]byte, error) {
	fields := canonical.Map{
		"kind":                cmd.Kind,
		"turnId":              cmd.TurnID,
		"turnLeaseGeneration": cmd.TurnLeaseGeneration,
	}
	if cmd.EffectID != "" {
		fields["effectId"] = cmd.EffectID
	}
	if cmd.RequestDigest != "" {
		fields["requestDigest"] = cmd.RequestDigest
	}
	if cmd.ProviderRequestID != "" {
		fields["providerRequestId"] = cmd.ProviderRequestID
	}
	if cmd.ExternalCommitID != "" {
		fields["externalCommitId"] = cmd.ExternalCommitID
	}
	if cmd.PlacementGeneration != 0 {
		fields["placementGeneration"] = cmd.PlacementGeneration
	}
	if cmd.PolicyGeneration != 0 {
		fields["policyGeneration"] = cmd.PolicyGeneration
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
	cmd := command{}
	if cmd.Kind, err = reqString(fields, "kind"); err != nil {
		return command{}, err
	}
	if cmd.TurnID, err = reqString(fields, "turnId"); err != nil {
		return command{}, err
	}
	if cmd.TurnLeaseGeneration, err = reqInt(fields, "turnLeaseGeneration"); err != nil {
		return command{}, err
	}
	cmd.EffectID = optString(fields, "effectId")
	cmd.RequestDigest = optString(fields, "requestDigest")
	cmd.ProviderRequestID = optString(fields, "providerRequestId")
	cmd.ExternalCommitID = optString(fields, "externalCommitId")
	cmd.PlacementGeneration = optInt(fields, "placementGeneration")
	cmd.PolicyGeneration = optInt(fields, "policyGeneration")

	if err := validateCommandShape(cmd); err != nil {
		return command{}, err
	}
	return cmd, nil
}

func validateCommandShape(cmd command) error {
	if cmd.TurnID == "" || !utf8.ValidString(cmd.TurnID) {
		return fmt.Errorf("%w: empty or non-UTF-8 turn id", ErrInvalidCommand)
	}
	if cmd.TurnLeaseGeneration <= 0 {
		return fmt.Errorf("%w: turn-lease generation must be positive", ErrInvalidCommand)
	}
	switch cmd.Kind {
	case commandOpenTurn, commandCompleteTurn:
	case commandPrepareModel:
		if cmd.EffectID == "" || cmd.RequestDigest == "" {
			return fmt.Errorf("%w: prepare requires effect id and request digest", ErrInvalidCommand)
		}
	case commandDispatchModel:
		if cmd.EffectID == "" || cmd.ProviderRequestID == "" {
			return fmt.Errorf("%w: dispatch requires effect id and provider request id", ErrInvalidCommand)
		}
	case commandSettleModel:
		if cmd.EffectID == "" || cmd.ExternalCommitID == "" {
			return fmt.Errorf("%w: settle requires effect id and external commit id", ErrInvalidCommand)
		}
	case commandPrepareTool:
		if cmd.EffectID == "" || cmd.RequestDigest == "" {
			return fmt.Errorf("%w: prepare requires effect id and request digest", ErrInvalidCommand)
		}
	case commandDispatchTool:
		if cmd.EffectID == "" || cmd.ProviderRequestID == "" {
			return fmt.Errorf("%w: dispatch requires effect id and provider request id", ErrInvalidCommand)
		}
	case commandCommitTool:
		if cmd.EffectID == "" || cmd.ExternalCommitID == "" {
			return fmt.Errorf("%w: commit requires effect id and external commit id", ErrInvalidCommand)
		}
	case commandSettleTool:
		if cmd.EffectID == "" {
			return fmt.Errorf("%w: settle requires effect id", ErrInvalidCommand)
		}
	case commandRotatePlacement:
		if cmd.PlacementGeneration <= 0 {
			return fmt.Errorf("%w: rotate placement requires a positive generation", ErrInvalidCommand)
		}
	case commandRotatePolicy:
		if cmd.PolicyGeneration <= 0 {
			return fmt.Errorf("%w: rotate policy requires a positive generation", ErrInvalidCommand)
		}
	default:
		return fmt.Errorf("%w: %q", ErrUnknownCommand, cmd.Kind)
	}
	return nil
}

func reqInt(fields canonical.Map, key string) (int64, error) {
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

func reqString(fields canonical.Map, key string) (string, error) {
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

func optString(fields canonical.Map, key string) string {
	if raw, ok := fields[key].(string); ok {
		return raw
	}
	return ""
}

func optInt(fields canonical.Map, key string) int64 {
	if raw, ok := fields[key].(int64); ok {
		return raw
	}
	return 0
}
