package stateappbroker

import (
	"bytes"
	"context"
	"encoding/hex"
	"math"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/stateappcodec"
	"golang.org/x/text/unicode/norm"
)

func isNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}
func hasGroup(descriptor dependency.Descriptor, group dependency.AtomicGroup) bool {
	for _, candidate := range descriptor.AtomicGroups {
		if candidate == group {
			return true
		}
	}
	return false
}
func millis(value time.Time) (int64, error) {
	ms := value.UnixMilli()
	if value.IsZero() || value.Nanosecond()%int(time.Millisecond) != 0 || ms < 1 || uint64(ms) > stateappcodec.MaximumSafeInteger {
		return 0, broker.ErrInvalidRequest
	}
	return ms, nil
}
func budgetValue(value broker.EngineStepBudget) (canonical.Map, error) {
	if value.MaximumEvents != 1 || value.MaximumEphemeralBytes < 1 || value.MaximumEphemeralBytes > stateappcodec.MaximumSafeInteger || value.MaximumWallClock <= 0 || value.MaximumWallClock%time.Millisecond != 0 {
		return nil, broker.ErrInvalidRequest
	}
	return canonical.Map{"maximumEvents": value.MaximumEvents, "maximumEphemeralBytes": value.MaximumEphemeralBytes, "maximumWallClockMs": int64(value.MaximumWallClock / time.Millisecond)}, nil
}
func digestValue(value broker.Digest) string { return "sha256:" + hex.EncodeToString(value[:]) }
func optionalID(value identity.ID) canonical.Value {
	if value == (identity.ID{}) {
		return nil
	}
	return value.String()
}
func keyValue(value broker.EffectKey) canonical.Map {
	return canonical.Map{"turnId": value.TurnID.String(), "effectId": value.EffectID.String(), "invocationId": value.InvocationID.String(), "requestDigest": digestValue(value.RequestDigest)}
}
func fenceValue(value broker.Generations) canonical.Map {
	return canonical.Map{"turnLeaseGeneration": value.TurnLease, "placementGeneration": value.Placement, "sandboxGeneration": value.Sandbox, "authorizationGeneration": value.Authorization}
}
func errorValue(value *v1.PublicError) (canonical.Value, error) {
	if value == nil {
		return nil, nil
	}
	if len(value.ProtoReflect().GetUnknown()) != 0 {
		return nil, broker.ErrInvalidRequest
	}
	if _, ok := v1.ErrorCode_name[int32(value.Code)]; !ok || value.RetryAfterMs > stateappcodec.MaximumSafeInteger {
		return nil, broker.ErrInvalidRequest
	}
	metadata := canonical.Map{}
	if !utf8.ValidString(value.Reason) || !norm.NFC.IsNormalString(value.Reason) || !utf8.ValidString(value.Message) || !norm.NFC.IsNormalString(value.Message) {
		return nil, broker.ErrInvalidRequest
	}
	for key, item := range value.Metadata {
		if !utf8.ValidString(key) || !norm.NFC.IsNormalString(key) || !utf8.ValidString(item) || !norm.NFC.IsNormalString(item) {
			return nil, broker.ErrInvalidRequest
		}
		metadata[key] = item
	}
	var request canonical.Value
	if value.RequestId != nil {
		if len(value.RequestId.ProtoReflect().GetUnknown()) != 0 {
			return nil, broker.ErrInvalidRequest
		}
		id, err := identity.Parse(identity.Request, string(value.RequestId.Value))
		if err != nil {
			return nil, broker.ErrInvalidRequest
		}
		request = id.String()
	}
	m := canonical.Map{"code": int64(value.Code), "reason": value.Reason, "message": value.Message, "retryable": value.Retryable, "retryAfterMs": value.RetryAfterMs, "metadata": metadata, "requestId": request}
	if _, err := canonical.Encode(m, canonical.Options{MaxBytes: 1 << 20, MaxDepth: 64, MaxItems: 100_000}); err != nil {
		return nil, broker.ErrInvalidRequest
	}
	return m, nil
}

// A signed transport authenticates bytes; this decoder also validates their
// typed identity and original-receipt structure before exposing broker facts.
type decoder struct {
	store *Store
	err   error
}

func (d *decoder) fail() {
	if d.err == nil {
		d.err = broker.ErrFenceMismatch
	}
}
func (d *decoder) record(value canonical.Value, fields ...string) canonical.Map {
	m, ok := value.(canonical.Map)
	if !ok || len(m) != len(fields) {
		d.fail()
		return canonical.Map{}
	}
	for _, field := range fields {
		if _, ok := m[field]; !ok {
			d.fail()
		}
	}
	return m
}
func (d *decoder) text(value canonical.Value) string {
	s, ok := value.(string)
	if !ok || !utf8.ValidString(s) || !norm.NFC.IsNormalString(s) {
		d.fail()
	}
	return s
}
func (d *decoder) identifier(value canonical.Value) string {
	s := d.text(value)
	if len(s) < 1 || len(s) > 256 || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		d.fail()
	}
	return s
}
func (d *decoder) boolean(value canonical.Value) bool {
	b, ok := value.(bool)
	if !ok {
		d.fail()
	}
	return b
}
func (d *decoder) durable(value canonical.Value) bool {
	b := d.boolean(value)
	if !b {
		d.err = broker.ErrDurabilityBarrier
	}
	return b
}
func (d *decoder) uint(value canonical.Value) uint64 {
	var n uint64
	switch v := value.(type) {
	case uint64:
		n = v
	case int64:
		if v < 0 {
			d.fail()
			return 0
		}
		n = uint64(v)
	default:
		d.fail()
	}
	if n > stateappcodec.MaximumSafeInteger {
		d.fail()
	}
	return n
}
func (d *decoder) time(value canonical.Value) time.Time {
	n := d.uint(value)
	if n == 0 {
		d.fail()
	}
	return time.UnixMilli(int64(n))
}
func (d *decoder) id(kind identity.Kind, value canonical.Value, nullable bool) identity.ID {
	if nullable && value == nil {
		return identity.ID{}
	}
	id, err := identity.Parse(kind, d.text(value))
	if err != nil {
		d.fail()
	}
	return id
}
func (d *decoder) digest(value canonical.Value) broker.Digest {
	s := d.text(value)
	var result broker.Digest
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		d.fail()
		return result
	}
	decoded, err := hex.DecodeString(s[7:])
	if err != nil || hex.EncodeToString(decoded) != s[7:] {
		d.fail()
		return result
	}
	copy(result[:], decoded)
	return result
}
func (d *decoder) opaque(value canonical.Value) broker.OpaquePermit {
	b, ok := value.(canonical.Bytes)
	if !ok || len(b) != 32 {
		d.fail()
	}
	return broker.OpaquePermit(bytes.Clone(b))
}
func (d *decoder) fence(value canonical.Value) broker.Generations {
	m := d.record(value, "turnLeaseGeneration", "placementGeneration", "sandboxGeneration", "authorizationGeneration")
	return broker.Generations{TurnLease: d.uint(m["turnLeaseGeneration"]), Placement: d.uint(m["placementGeneration"]), Sandbox: d.uint(m["sandboxGeneration"]), Authorization: d.uint(m["authorizationGeneration"])}
}
func (d *decoder) budget(value canonical.Value) broker.EngineStepBudget {
	m := d.record(value, "maximumEvents", "maximumEphemeralBytes", "maximumWallClockMs")
	ms := d.uint(m["maximumWallClockMs"])
	result := broker.EngineStepBudget{MaximumEvents: d.uint(m["maximumEvents"]), MaximumEphemeralBytes: d.uint(m["maximumEphemeralBytes"])}
	if result.MaximumEvents != 1 || result.MaximumEphemeralBytes == 0 || ms == 0 || ms > math.MaxInt64/uint64(time.Millisecond) {
		d.fail()
		return result
	}
	result.MaximumWallClock = time.Duration(ms) * time.Millisecond
	return result
}
func (d *decoder) publicError(value canonical.Value) *v1.PublicError {
	if value == nil {
		return nil
	}
	m := d.record(value, "code", "reason", "message", "retryable", "retryAfterMs", "metadata", "requestId")
	code := d.uint(m["code"])
	if code > math.MaxInt32 {
		d.fail()
	}
	if _, ok := v1.ErrorCode_name[int32(code)]; !ok {
		d.fail()
	}
	result := &v1.PublicError{Code: v1.ErrorCode(code), Reason: d.text(m["reason"]), Message: d.text(m["message"]), Retryable: d.boolean(m["retryable"]), RetryAfterMs: d.uint(m["retryAfterMs"]), Metadata: map[string]string{}}
	metadata, ok := m["metadata"].(canonical.Map)
	if !ok {
		d.fail()
	}
	for key, value := range metadata {
		result.Metadata[key] = d.text(value)
	}
	if m["requestId"] != nil {
		result.RequestId = &v1.OpaqueId{Value: []byte(d.id(identity.Request, m["requestId"], false).String())}
	}
	if _, err := errorValue(result); err != nil {
		d.fail()
	}
	return result
}
func (d *decoder) scope(m canonical.Map) (tenant, workspace, user, session, turn identity.ID) {
	tenant = d.id(identity.Tenant, m["tenantId"], false)
	workspace = d.id(identity.Workspace, m["workspaceId"], false)
	user = d.id(identity.Subject, m["userId"], false)
	session = d.id(identity.Session, m["sessionId"], false)
	turn = d.id(identity.Turn, m["turnId"], false)
	if d.store != nil && !d.store.matchesPermit(tenant, workspace, user, session) {
		d.fail()
	}
	return
}
func (d *decoder) effectKey(m canonical.Map) broker.EffectKey {
	return broker.EffectKey{SessionID: d.id(identity.Session, m["sessionId"], false), TurnID: d.id(identity.Turn, m["turnId"], false), EffectID: d.id(identity.Effect, m["effectId"], false), InvocationID: d.id(identity.Invocation, m["invocationId"], false), RequestDigest: d.digest(m["requestDigest"])}
}
func (d *decoder) service(value canonical.Value) broker.EffectService {
	v := broker.EffectService(d.text(value))
	switch v {
	case broker.ServiceModel, broker.ServiceWorkspace, broker.ServiceExecutor, broker.ServiceMCP, broker.ServiceArtifact, broker.ServiceExternalTool:
	default:
		d.fail()
	}
	return v
}
func (d *decoder) policy(value canonical.Value) broker.ReplayPolicy {
	v := broker.ReplayPolicy(d.text(value))
	switch v {
	case broker.ReplaySafe, broker.ReplayIdempotencyKey, broker.ReplayNever, broker.ReplayConfirm:
	default:
		d.fail()
	}
	return v
}
func (d *decoder) parent(value canonical.Value) (identity.ID, string) {
	if value == nil {
		return identity.ID{}, ""
	}
	text := d.identifier(value)
	if id, err := identity.Parse(identity.Operation, text); err == nil {
		return id, ""
	}
	return identity.ID{}, text
}

var preparationFields = []string{"tenantId", "workspaceId", "userId", "sessionId", "turnId", "effectId", "invocationId", "requestDigest", "opaque", "service", "operation", "parentOperationId", "ordinal", "replayPolicy", "fence", "dispatchAttempt", "deadline", "eventSequence", "durable"}

func (d *decoder) preparation(value canonical.Value) broker.EffectPreparationPermit {
	m := d.record(value, preparationFields...)
	tenant, workspace, user, _, _ := d.scope(m)
	parent, raw := d.parent(m["parentOperationId"])
	r := broker.EffectPreparationPermit{EffectKey: d.effectKey(m), Opaque: d.opaque(m["opaque"]), TenantID: tenant, WorkspaceID: workspace, UserID: user, Service: d.service(m["service"]), Operation: d.identifier(m["operation"]), ParentOperationID: parent, ParentOperation: raw, Ordinal: d.uint(m["ordinal"]), ReplayPolicy: d.policy(m["replayPolicy"]), Generations: d.fence(m["fence"]), DispatchAttempt: d.uint(m["dispatchAttempt"]), Deadline: d.time(m["deadline"]), EventSequence: d.uint(m["eventSequence"]), Durable: d.durable(m["durable"])}
	if r.DispatchAttempt == 0 || r.EventSequence == 0 || (parent == (identity.ID{}) && raw == "" && r.Ordinal != 0) {
		d.fail()
	}
	return r
}
func (d *decoder) dispatch(value canonical.Value) broker.DispatchPermit {
	fields := append(append([]string{}, preparationFields...), "providerRequestId", "providerRouteDigest")
	m := d.record(value, fields...)
	base := canonical.Map{}
	for _, key := range preparationFields {
		base[key] = m[key]
	}
	p := d.preparation(base)
	return broker.DispatchPermit{EffectKey: p.EffectKey, Opaque: p.Opaque, TenantID: p.TenantID, WorkspaceID: p.WorkspaceID, UserID: p.UserID, Service: p.Service, Operation: p.Operation, ParentOperationID: p.ParentOperationID, ParentOperation: p.ParentOperation, Ordinal: p.Ordinal, ReplayPolicy: p.ReplayPolicy, Generations: p.Generations, DispatchAttempt: p.DispatchAttempt, Deadline: p.Deadline, EventSequence: p.EventSequence, Durable: p.Durable, ProviderRequestID: d.id(identity.Request, m["providerRequestId"], true), ProviderRouteDigest: d.digest(m["providerRouteDigest"])}
}
func (d *decoder) start(value canonical.Value) broker.DispatchStartPermit {
	m := d.record(value, "dispatch", "opaque", "commandDigest", "eventSequence", "durable")
	r := broker.DispatchStartPermit{Dispatch: d.dispatch(m["dispatch"]), Opaque: d.opaque(m["opaque"]), CommandDigest: d.digest(m["commandDigest"]), EventSequence: d.uint(m["eventSequence"]), Durable: d.durable(m["durable"])}
	if r.EventSequence == 0 {
		d.fail()
	}
	return r
}
func (d *decoder) claim(value canonical.Value) broker.DispatchStartClaim {
	m := d.record(value, "fresh", "permit")
	return broker.DispatchStartClaim{Fresh: d.boolean(m["fresh"]), Permit: d.start(m["permit"])}
}
func (d *decoder) confirmation(value canonical.Value) broker.ConfirmationReceipt {
	m := d.record(value, "tenantId", "workspaceId", "userId", "sessionId", "turnId", "effectId", "invocationId", "requestDigest", "service", "operation", "dispatchAttempt", "providerRequestId", "externalCommitId", "resultRef", "operationDigest", "eventSequence", "durable")
	tenant, workspace, _, _, _ := d.scope(m)
	r := broker.ConfirmationReceipt{EffectKey: d.effectKey(m), TenantID: tenant, WorkspaceID: workspace, Service: d.service(m["service"]), Operation: d.identifier(m["operation"]), DispatchAttempt: d.uint(m["dispatchAttempt"]), ProviderRequestID: d.id(identity.Request, m["providerRequestId"], true), ExternalCommitID: d.id(identity.Commit, m["externalCommitId"], false), ResultRef: d.id(identity.Artifact, m["resultRef"], true), OperationDigest: d.digest(m["operationDigest"]), EventSequence: d.uint(m["eventSequence"]), Durable: d.durable(m["durable"])}
	if r.DispatchAttempt == 0 || r.EventSequence == 0 {
		d.fail()
	}
	return r
}
func (d *decoder) settlement(value canonical.Value) broker.SettlementReceipt {
	m := d.record(value, "tenantId", "workspaceId", "userId", "sessionId", "turnId", "effectId", "invocationId", "requestDigest", "state", "dispatchAttempt", "externalCommitId", "resultRef", "error", "operationDigest", "recoveryKind", "effect", "eventSequence", "durable")
	tenant, workspace, _, _, _ := d.scope(m)
	_, effect := d.effect(m["effect"], broker.Generations{})
	r := broker.SettlementReceipt{EffectKey: d.effectKey(m), TenantID: tenant, WorkspaceID: workspace, State: broker.EffectState(d.text(m["state"])), DispatchAttempt: d.uint(m["dispatchAttempt"]), ExternalCommitID: d.id(identity.Commit, m["externalCommitId"], true), ResultRef: d.id(identity.Artifact, m["resultRef"], true), Error: d.publicError(m["error"]), OperationDigest: d.digest(m["operationDigest"]), Effect: effect, EventSequence: d.uint(m["eventSequence"]), Durable: d.durable(m["durable"])}
	if m["recoveryKind"] != nil {
		r.RecoveryKind = broker.RecoverySettlementKind(d.text(m["recoveryKind"]))
		if r.RecoveryKind != broker.RecoverySettlementFailed && r.RecoveryKind != broker.RecoverySettlementInterrupted {
			d.fail()
		}
	}
	if r.State != broker.EffectSettled || r.EventSequence == 0 || effect == nil || string(effect.EffectId.GetValue()) != r.EffectID.String() || string(effect.InvocationId.GetValue()) != r.InvocationID.String() || effect.DispatchAttempt != r.DispatchAttempt || effect.State != v1.EffectState_EFFECT_STATE_SETTLED {
		d.fail()
	}
	return r
}
func (d *decoder) block(value canonical.Value) broker.BlockReceipt {
	m := d.record(value, "tenantId", "workspaceId", "userId", "sessionId", "turnId", "effectId", "invocationId", "requestDigest", "state", "replayPolicy", "dispatchAttempt", "operationDigest", "reason", "eventSequence", "durable")
	tenant, workspace, _, _, _ := d.scope(m)
	r := broker.BlockReceipt{EffectKey: d.effectKey(m), TenantID: tenant, WorkspaceID: workspace, State: broker.EffectState(d.text(m["state"])), ReplayPolicy: d.policy(m["replayPolicy"]), DispatchAttempt: d.uint(m["dispatchAttempt"]), OperationDigest: d.digest(m["operationDigest"]), Reason: d.publicError(m["reason"]), EventSequence: d.uint(m["eventSequence"]), Durable: d.durable(m["durable"])}
	if r.State != broker.EffectBlocked || r.EventSequence == 0 || r.Reason == nil {
		d.fail()
	}
	return r
}

func (d *decoder) effect(value canonical.Value, fence broker.Generations) (*broker.EffectSnapshot, *v1.EffectRecord) {
	m, ok := value.(canonical.Map)
	if !ok {
		d.fail()
		return nil, nil
	}
	fields := []string{"tenantId", "userId", "sessionId", "turnId", "effectId", "invocationId", "requestDigest", "service", "operation", "replayPolicy", "phase", "dispatchAttempt", "lastDispatch", "externalCommitId", "resultRef", "settlement", "consumedAtCheckpointSequence", "consumedByAbort"}
	_, inline := m["requestPayload"]
	_, external := m["requestPayloadRef"]
	if inline == external {
		d.fail()
	}
	if inline {
		fields = append(fields, "requestPayload")
	} else {
		fields = append(fields, "requestPayloadRef")
	}
	if _, ok := m["parentOperationId"]; ok {
		fields = append(fields, "parentOperationId", "ordinal")
	}
	d.record(value, fields...)
	record, err := stateappcodec.EffectRecordFromValue(value, fence)
	if err != nil {
		d.fail()
		return nil, nil
	}
	tenant := d.id(identity.Tenant, m["tenantId"], false)
	user := d.id(identity.Subject, m["userId"], false)
	session := d.id(identity.Session, m["sessionId"], false)
	d.id(identity.Turn, m["turnId"], false)
	if d.store != nil && (tenant.String() != d.store.scope.TenantID || user != d.store.user || session.String() != d.store.scope.SessionID) {
		d.fail()
	}
	parent, raw := d.parent(m["parentOperationId"])
	ordinal := uint64(0)
	if m["parentOperationId"] != nil {
		ordinal = d.uint(m["ordinal"])
	}
	r := &broker.EffectSnapshot{EffectID: d.id(identity.Effect, m["effectId"], false), InvocationID: d.id(identity.Invocation, m["invocationId"], false), RequestDigest: d.digest(m["requestDigest"]), Service: d.service(m["service"]), Operation: d.identifier(m["operation"]), ParentOperationID: parent, ParentOperation: raw, Ordinal: ordinal, ReplayPolicy: d.policy(m["replayPolicy"]), State: broker.EffectState(d.text(m["phase"])), DispatchAttempt: record.DispatchAttempt, Generations: broker.Generations{TurnLease: record.TurnLeaseGeneration, Placement: record.PlacementGeneration, Sandbox: record.SandboxGeneration, Authorization: record.AuthorizationGeneration}, ExternalCommitID: d.id(identity.Commit, m["externalCommitId"], true), ResultRef: d.id(identity.Artifact, m["resultRef"], true)}
	if m["lastDispatch"] != nil {
		last := d.record(m["lastDispatch"], "turnLeaseGeneration", "placementGeneration", "sandboxGeneration", "authorizationGeneration", "dispatchAttempt", "deadline", "providerRequestId", "providerRouteDigest", "start")
		r.LastDispatch = &broker.DispatchMetadata{DispatchAttempt: d.uint(last["dispatchAttempt"]), Generations: r.Generations, ProviderRequestID: d.id(identity.Request, last["providerRequestId"], true), ProviderRouteDigest: d.digest(last["providerRouteDigest"]), Deadline: d.time(last["deadline"])}
		if last["start"] != nil {
			start := d.record(last["start"], "turnLeaseGeneration", "placementGeneration", "sandboxGeneration", "authorizationGeneration", "dispatchAttempt", "deadline", "providerRequestId", "providerRouteDigest", "commandDigest", "claimedEventSequence")
			for _, field := range []string{"turnLeaseGeneration", "placementGeneration", "sandboxGeneration", "authorizationGeneration", "dispatchAttempt", "deadline", "providerRequestId", "providerRouteDigest"} {
				if !sameValue(start[field], last[field]) {
					d.fail()
				}
			}
			d.digest(start["commandDigest"])
			if d.uint(start["claimedEventSequence"]) == 0 {
				d.fail()
			}
		}
	}
	d.boolean(m["consumedByAbort"])
	if m["consumedAtCheckpointSequence"] != nil {
		d.uint(m["consumedAtCheckpointSequence"])
	}
	if r.State == broker.EffectSettled {
		r.Settlement = record
	}
	return r, record
}

func (store *Store) hydrate(ctx context.Context, d *decoder, turn identity.ID, fence broker.Generations, checkpoint canonical.Value, digest broker.Digest, settlement canonical.Value) (*v1.AgentCheckpoint, *v1.EffectRecord, []byte, error) {
	if d.err != nil {
		return nil, nil, nil, d.err
	}
	metadata, ok := checkpoint.(canonical.Map)
	if !ok || metadata["turnId"] != turn.String() || metadata["sessionId"] != store.scope.SessionID {
		d.fail()
	}
	var effect *v1.EffectRecord
	var m canonical.Map
	if settlement != nil {
		m = d.record(settlement, "effect", "settlement")
		_, effect = d.effect(m["effect"], fence)
		e, ok := m["effect"].(canonical.Map)
		if !ok || e["turnId"] != turn.String() || e["phase"] != "settled" || e["consumedAtCheckpointSequence"] != nil || e["consumedByAbort"] != false || !sameValue(e["settlement"], m["settlement"]) {
			d.fail()
		}
	}
	if d.err != nil {
		return nil, nil, nil, d.err
	}
	cp, err := store.codec.HydrateCheckpoint(ctx, checkpoint, digestValue(digest))
	if err != nil {
		return nil, nil, nil, err
	}
	if settlement == nil {
		return cp, nil, nil, nil
	}
	normalized, err := store.codec.HydrateSettlement(ctx, digestValue(d.digest(m["effect"].(canonical.Map)["requestDigest"])), m["settlement"])
	if err != nil {
		return nil, nil, nil, err
	}
	body, err := canonical.Encode(normalized, canonical.Options{MaxBytes: 4 << 20, MaxDepth: 64, MaxItems: 100_000})
	if err != nil {
		return nil, nil, nil, err
	}
	return cp, effect, body, nil
}

func sameValue(a, b canonical.Value) bool {
	options := canonical.Options{MaxBytes: 9 << 20, MaxDepth: 72, MaxItems: 100_000}
	left, err := canonical.Encode(a, options)
	if err != nil {
		return false
	}
	right, err := canonical.Encode(b, options)
	return err == nil && bytes.Equal(left, right)
}

func permitMatchesEffect(permit canonical.Value, effect canonical.Value) bool {
	p, ok := permit.(canonical.Map)
	if !ok {
		return false
	}
	e, ok := effect.(canonical.Map)
	if !ok {
		return false
	}
	for _, field := range []string{"tenantId", "userId", "sessionId", "turnId", "effectId", "invocationId", "requestDigest", "service", "operation", "replayPolicy", "parentOperationId"} {
		if !sameValue(p[field], e[field]) {
			return false
		}
	}
	ordinal := e["ordinal"]
	if ordinal == nil {
		ordinal = int64(0)
	}
	return sameValue(p["ordinal"], ordinal)
}

func (store *Store) decodeTurn(ctx context.Context, value canonical.Value) (broker.TurnSnapshot, error) {
	d := decoder{store: store}
	m := d.record(value, "tenantId", "workspaceId", "userId", "sessionId", "turnId", "active", "abortRequested", "leaseExpiresAt", "fence", "eventSequence", "engineStepLimits", "checkpointDigest", "checkpoint", "activeEffect", "preparation", "dispatch", "start", "unconsumedSettlement")
	r := broker.TurnSnapshot{TenantID: d.id(identity.Tenant, m["tenantId"], false), WorkspaceID: d.id(identity.Workspace, m["workspaceId"], false), UserID: d.id(identity.Subject, m["userId"], false), SessionID: d.id(identity.Session, m["sessionId"], false), TurnID: d.id(identity.Turn, m["turnId"], true), Active: d.boolean(m["active"]), AbortRequested: d.boolean(m["abortRequested"]), Generations: d.fence(m["fence"]), EventSequence: d.uint(m["eventSequence"]), EngineStepLimits: d.budget(m["engineStepLimits"])}
	if !store.matchesPermit(r.TenantID, r.WorkspaceID, r.UserID, r.SessionID) || r.Generations.Authorization != store.scope.ExpectedAuthorizationGeneration || r.EngineStepLimits != store.limits {
		d.fail()
	}
	if m["leaseExpiresAt"] != nil {
		r.LeaseExpiresAt = d.time(m["leaseExpiresAt"])
	}
	if r.TurnID == (identity.ID{}) {
		if r.Active || m["checkpoint"] != nil || m["checkpointDigest"] != nil || m["activeEffect"] != nil || m["preparation"] != nil || m["dispatch"] != nil || m["start"] != nil || m["unconsumedSettlement"] != nil || m["leaseExpiresAt"] != nil {
			d.fail()
		}
		return r, d.err
	}
	r.CheckpointDigest = d.digest(m["checkpointDigest"])
	if m["activeEffect"] != nil {
		r.ActiveEffect, _ = d.effect(m["activeEffect"], r.Generations)
		effectMap, ok := m["activeEffect"].(canonical.Map)
		if !ok || effectMap["turnId"] != r.TurnID.String() {
			d.fail()
		}
	}
	if m["preparation"] != nil {
		p := d.preparation(m["preparation"])
		if r.ActiveEffect == nil || !permitMatchesEffect(m["preparation"], m["activeEffect"]) || p.TurnID != r.TurnID || p.Generations != r.Generations || p.DispatchAttempt != r.ActiveEffect.DispatchAttempt+1 || p.EventSequence > r.EventSequence || p.Deadline.After(r.LeaseExpiresAt) {
			d.fail()
		} else {
			r.ActiveEffect.PreparationPermit = &p
		}
	}
	if m["dispatch"] != nil {
		p := d.dispatch(m["dispatch"])
		if r.ActiveEffect == nil || r.ActiveEffect.LastDispatch == nil || !permitMatchesEffect(m["dispatch"], m["activeEffect"]) || p.EventSequence > r.EventSequence || p.TurnID != r.TurnID || p.DispatchAttempt != r.ActiveEffect.LastDispatch.DispatchAttempt || p.Generations != r.ActiveEffect.LastDispatch.Generations || p.ProviderRequestID != r.ActiveEffect.LastDispatch.ProviderRequestID || p.ProviderRouteDigest != r.ActiveEffect.LastDispatch.ProviderRouteDigest || !p.Deadline.Equal(r.ActiveEffect.LastDispatch.Deadline) {
			d.fail()
		}
	}
	if m["start"] != nil {
		p := d.start(m["start"])
		startMap := d.record(m["start"], "dispatch", "opaque", "commandDigest", "eventSequence", "durable")
		effectMap, ok := m["activeEffect"].(canonical.Map)
		var original canonical.Map
		if ok {
			if last, ok := effectMap["lastDispatch"].(canonical.Map); ok {
				original, _ = last["start"].(canonical.Map)
			}
		}
		if r.ActiveEffect == nil || r.ActiveEffect.LastDispatch == nil || original == nil || !sameValue(startMap["dispatch"], m["dispatch"]) || !sameValue(startMap["commandDigest"], original["commandDigest"]) || !sameValue(startMap["eventSequence"], original["claimedEventSequence"]) || p.EventSequence > r.EventSequence {
			d.fail()
		} else {
			r.ActiveEffect.LastDispatch.Start = &p
		}
	} else if effectMap, ok := m["activeEffect"].(canonical.Map); ok && (effectMap["phase"] == "dispatched" || effectMap["phase"] == "externally_committed") {
		if last, ok := effectMap["lastDispatch"].(canonical.Map); ok && last["start"] != nil {
			d.fail()
		}
	}
	if r.Active && (r.Generations.TurnLease == 0 || r.LeaseExpiresAt.IsZero()) {
		d.fail()
	}
	var err error
	if (r.ActiveEffect != nil && r.ActiveEffect.State == broker.EffectSettled) != (m["unconsumedSettlement"] != nil) {
		d.fail()
	}
	if m["unconsumedSettlement"] != nil {
		settlement := d.record(m["unconsumedSettlement"], "effect", "settlement")
		if !sameValue(m["activeEffect"], settlement["effect"]) {
			d.fail()
		}
	}
	r.Checkpoint, r.UnconsumedSettlement, r.ResumeSettlement, err = store.hydrate(ctx, &d, r.TurnID, r.Generations, m["checkpoint"], r.CheckpointDigest, m["unconsumedSettlement"])
	if err != nil {
		return broker.TurnSnapshot{}, err
	}
	if string(r.Checkpoint.TurnId.GetValue()) != r.TurnID.String() {
		d.fail()
	}
	return r, d.err
}

func (store *Store) decodeGrant(ctx context.Context, value canonical.Value) (broker.EngineStepPermit, error) {
	d := decoder{store: store}
	m := d.record(value, "tenantId", "workspaceId", "userId", "sessionId", "turnId", "opaque", "operationKey", "fence", "expectedEventSequence", "checkpointDigest", "budget", "deadline", "checkpoint", "unconsumedSettlement", "durable")
	tenant, workspace, user, session, turn := d.scope(m)
	r := broker.EngineStepPermit{Opaque: d.opaque(m["opaque"]), TenantID: tenant, WorkspaceID: workspace, UserID: user, SessionID: session, TurnID: turn, OperationKey: d.identifier(m["operationKey"]), Generations: d.fence(m["fence"]), ExpectedEventSequence: d.uint(m["expectedEventSequence"]), CheckpointDigest: d.digest(m["checkpointDigest"]), Budget: d.budget(m["budget"]), Deadline: d.time(m["deadline"]), Durable: d.durable(m["durable"])}
	if r.Generations.Authorization != store.scope.ExpectedAuthorizationGeneration || r.Generations.TurnLease == 0 || r.Budget.MaximumEphemeralBytes > store.limits.MaximumEphemeralBytes || r.Budget.MaximumWallClock > store.limits.MaximumWallClock {
		d.fail()
	}
	var err error
	r.Checkpoint, r.UnconsumedSettlement, r.ResumeSettlement, err = store.hydrate(ctx, &d, r.TurnID, r.Generations, m["checkpoint"], r.CheckpointDigest, m["unconsumedSettlement"])
	if err != nil {
		return broker.EngineStepPermit{}, err
	}
	if string(r.Checkpoint.TurnId.GetValue()) != r.TurnID.String() {
		d.fail()
	}
	return r, d.err
}
func (store *Store) decodeStep(value canonical.Value) (broker.EngineStepReceipt, error) {
	d := decoder{store: store}
	m := d.record(value, "operationKey", "eventSequence", "durable", "preparedEffect", "preparation")
	r := broker.EngineStepReceipt{OperationKey: d.identifier(m["operationKey"]), EventSequence: d.uint(m["eventSequence"]), Durable: d.durable(m["durable"])}
	if r.EventSequence == 0 {
		d.fail()
	}
	if (m["preparation"] == nil) != (m["preparedEffect"] == nil) {
		d.fail()
	}
	if m["preparation"] != nil {
		p := d.preparation(m["preparation"])
		r.PreparationPermit = &p
		_, r.PreparedEffect = d.effect(m["preparedEffect"], p.Generations)
		if r.PreparedEffect == nil || r.PreparedEffect.State != v1.EffectState_EFFECT_STATE_PREPARED || p.EventSequence != r.EventSequence || !permitMatchesEffect(m["preparation"], m["preparedEffect"]) {
			d.fail()
		}
		if r.PreparedEffect != nil {
			// Session stores the reservation deadline in the original preparation
			// permit. Project that authenticated fact into the broker protobuf view.
			r.PreparedEffect.DeadlineUnixMs = uint64(p.Deadline.UnixMilli())
		}
	}
	return r, d.err
}
