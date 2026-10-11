package mcpgateway

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"sort"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

const nativeRepositoryProtocol = "circulus.mcp-repository.v2"

var errNativeState = errors.New("mcp gateway: invalid native repository state")

type nativeScopeKey struct{ Tenant, Session, Turn identity.ID }
type nativeRequestKey struct {
	Invocation           identity.ID
	ProviderRequestID    string
	ConnectionGeneration uint64
	RequestID            string
}

// All fields in this versioned snapshot are exact. Map keys are encoded as
// sorted key/value pairs, including the binary dispatch-claim suffix; integers
// use eight bytes so native nanosecond leases never lose precision through the
// shared CBOR safe-integer limit. Identity and credential wrappers are explicit.
type nativeRepositoryWire struct {
	Protocol                         string
	ObjectID                         string
	Effects                          map[string]Effect
	Scopes                           map[nativeScopeKey]ValidatedAuthority
	Active                           map[nativeScopeKey]string
	Claims                           map[string]DispatchPermit
	ProviderStarts                   map[string]providerStartRecord
	CancellationClaims               map[string]CancellationPermit
	ServerRequests                   map[nativeRequestKey]ServerRequestRecord
	ServerRequestCounts              map[string]uint32
	ServerRequestLimits              map[string]uint32
	ActiveServerRequests             map[string]nativeRequestKey
	ServerRequestReconciliations     map[string]nativeRequestKey
	ServerRequestCancellationPermits map[nativeRequestKey]ServerRequestPermit
	ParentCancellationRequired       map[string]nativeRequestKey
	PendingAudits                    map[uint64]AuditEnvelope
	AuditSequence                    uint64
	Nonce                            uint64
	PolicyDigest                     Digest
	AuthorityGrants                  map[string]NativeAuthorityGrant
	ToolPermits                      map[string]ToolAuthorizationPermit
	DeliveredAudits                  map[uint64]AuditEvent
	WireInvocations                  map[string]nativeWireInvocation
}

type nativeRepositoryState struct {
	Repository      *MemoryRepository
	PolicyDigest    Digest
	AuthorityGrants map[string]NativeAuthorityGrant
	ToolPermits     map[string]ToolAuthorizationPermit
	DeliveredAudits map[uint64]AuditEvent
	WireInvocations map[string]nativeWireInvocation
}

func newNativeState(repository *MemoryRepository) *nativeRepositoryState {
	return &nativeRepositoryState{Repository: repository, AuthorityGrants: make(map[string]NativeAuthorityGrant),
		ToolPermits: make(map[string]ToolAuthorizationPermit), DeliveredAudits: make(map[uint64]AuditEvent), WireInvocations: make(map[string]nativeWireInvocation)}
}

func nativeScope(key scopeKey) nativeScopeKey {
	return nativeScopeKey{key.tenant, key.session, key.turn}
}
func localScope(key nativeScopeKey) scopeKey { return scopeKey{key.Tenant, key.Session, key.Turn} }
func nativeRequest(key serverRequestKey) nativeRequestKey {
	return nativeRequestKey{key.invocation, key.providerRequestID, key.connectionGeneration, key.requestID}
}
func localRequest(key nativeRequestKey) serverRequestKey {
	return serverRequestKey{key.Invocation, key.ProviderRequestID, key.ConnectionGeneration, key.RequestID}
}

func nativeWire(repository *MemoryRepository, objectID string) nativeRepositoryWire {
	w := nativeRepositoryWire{Protocol: nativeRepositoryProtocol, ObjectID: objectID,
		Effects: repository.effects, Claims: repository.claims, ProviderStarts: repository.providerStarts,
		CancellationClaims: repository.cancellationClaims, ServerRequestCounts: repository.serverRequestCounts,
		ServerRequestLimits: repository.serverRequestLimits, PendingAudits: repository.pendingAudits,
		AuditSequence: repository.auditSequence, Nonce: repository.nonce,
		Scopes: make(map[nativeScopeKey]ValidatedAuthority), Active: make(map[nativeScopeKey]string),
		ServerRequests: make(map[nativeRequestKey]ServerRequestRecord), ActiveServerRequests: make(map[string]nativeRequestKey),
		ServerRequestReconciliations: make(map[string]nativeRequestKey), ServerRequestCancellationPermits: make(map[nativeRequestKey]ServerRequestPermit),
		ParentCancellationRequired: make(map[string]nativeRequestKey)}
	for k, v := range repository.scopes {
		w.Scopes[nativeScope(k)] = v
	}
	for k, v := range repository.active {
		w.Active[nativeScope(k)] = v
	}
	for k, v := range repository.serverRequests {
		w.ServerRequests[nativeRequest(k)] = v
	}
	for k, v := range repository.activeServerRequests {
		w.ActiveServerRequests[k] = nativeRequest(v)
	}
	for k, v := range repository.serverRequestReconciliations {
		w.ServerRequestReconciliations[k] = nativeRequest(v)
	}
	for k, v := range repository.serverRequestCancellationPermits {
		w.ServerRequestCancellationPermits[nativeRequest(k)] = v
	}
	for k, v := range repository.parentCancellationRequired {
		w.ParentCancellationRequired[k] = nativeRequest(v)
	}
	return w
}

func localRepository(w nativeRepositoryWire) *MemoryRepository {
	r := NewMemoryRepository()
	r.effects, r.claims, r.providerStarts = w.Effects, w.Claims, w.ProviderStarts
	r.cancellationClaims, r.serverRequestCounts, r.serverRequestLimits = w.CancellationClaims, w.ServerRequestCounts, w.ServerRequestLimits
	r.pendingAudits, r.auditSequence, r.nonce = w.PendingAudits, w.AuditSequence, w.Nonce
	for k, v := range w.Scopes {
		r.scopes[localScope(k)] = v
	}
	for k, v := range w.Active {
		r.active[localScope(k)] = v
	}
	for k, v := range w.ServerRequests {
		r.serverRequests[localRequest(k)] = v
	}
	for k, v := range w.ActiveServerRequests {
		r.activeServerRequests[k] = localRequest(v)
	}
	for k, v := range w.ServerRequestReconciliations {
		r.serverRequestReconciliations[k] = localRequest(v)
	}
	for k, v := range w.ServerRequestCancellationPermits {
		r.serverRequestCancellationPermits[localRequest(k)] = v
	}
	for k, v := range w.ParentCancellationRequired {
		r.parentCancellationRequired[k] = localRequest(v)
	}
	return r
}

func nativeStateOptions(maximumBytes int) canonical.Options {
	return canonical.Options{MaxBytes: maximumBytes, MaxDepth: 64, MaxItems: 1_000_000}
}

func validateNativeWire(w nativeRepositoryWire, objectID string, maximumRecords int) error {
	if w.Protocol != nativeRepositoryProtocol || w.ObjectID != objectID || w.Nonce == ^uint64(0) {
		return errNativeState
	}
	v := reflect.ValueOf(w)
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if field.Kind() == reflect.Map && (field.IsNil() || field.Len() > maximumRecords) {
			return errNativeState
		}
	}
	for key, scope := range w.Scopes {
		if !validScope(scope) || nativeScope(keyForScope(scope)) != key {
			return errNativeState
		}
	}
	for key, effect := range w.Effects {
		if key != effect.Scope.InvocationID.String() || !validScope(effect.Scope) || effect.RequestDigest == (Digest{}) ||
			effect.Revision == 0 || effect.Revision != uint64(effect.EventCount)+1 || len(effect.InputCanonical) == 0 {
			return errNativeState
		}
		digest, err := digestCanonicalCall(effect.ServerID, effect.ToolName, effect.InputCanonical)
		if err != nil || digest != effect.RequestDigest {
			return errNativeState
		}
		if _, found := w.Scopes[nativeScope(keyForScope(effect.Scope))]; !found {
			return errNativeState
		}
	}
	for key, invocation := range w.Active {
		effect, found := w.Effects[invocation]
		if !found || nativeScope(keyForScope(effect.Scope)) != key || (effect.Terminal() && !retainsLateProviderOwner(effect)) {
			return errNativeState
		}
	}
	for sequence, envelope := range w.PendingAudits {
		if sequence == 0 || sequence > w.AuditSequence || envelope.Sequence != sequence || envelope.Event.OutboxSequence != sequence {
			return errNativeState
		}
	}
	for key, record := range w.ServerRequests {
		if key.Invocation != record.ParentInvocationID || key.ProviderRequestID != record.ProviderRequestID ||
			key.ConnectionGeneration != record.ConnectionGeneration || key.RequestID != record.RequestID {
			return errNativeState
		}
		if _, found := w.Effects[key.Invocation.String()]; !found {
			return errNativeState
		}
	}
	if (len(w.AuthorityGrants) > 0 || len(w.ToolPermits) > 0 || len(w.DeliveredAudits) > 0) && w.PolicyDigest == (Digest{}) {
		return errNativeState
	}
	for key, grant := range w.AuthorityGrants {
		if !validNativeGrant(grant) || key != nativeGrantKey(grant.BearerDigest) {
			return errNativeState
		}
	}
	for key, permit := range w.ToolPermits {
		if key != permitKey(permit.Proof) || !validAuthorizationPermit(permit, permit.Scope, permit.ServerID, permit.ToolName, permit.RequestDigest) ||
			!validScope(permit.Scope) || permit.RequestDigest == (Digest{}) {
			return errNativeState
		}
	}
	for sequence, event := range w.DeliveredAudits {
		if sequence == 0 || event.OutboxSequence != sequence || sequence > w.AuditSequence {
			return errNativeState
		}
	}
	for key, invocation := range w.WireInvocations {
		if key != nativeWireKey(invocation.ProviderID, invocation.Scope.InvocationID, invocation.Attempt) || !validNativeWireInvocation(invocation) || w.PolicyDigest == (Digest{}) {
			return errNativeState
		}
	}
	return nil
}

func encodeNativeRepository(repository *MemoryRepository, objectID string, maximumRecords, maximumBytes int) ([]byte, error) {
	return encodeNativeState(newNativeState(repository), objectID, maximumRecords, maximumBytes)
}

func encodeNativeState(state *nativeRepositoryState, objectID string, maximumRecords, maximumBytes int) ([]byte, error) {
	w := nativeWire(state.Repository, objectID)
	w.PolicyDigest, w.AuthorityGrants, w.ToolPermits, w.DeliveredAudits = state.PolicyDigest, state.AuthorityGrants, state.ToolPermits, state.DeliveredAudits
	w.WireInvocations = state.WireInvocations
	if err := validateNativeWire(w, objectID, maximumRecords); err != nil {
		return nil, err
	}
	value, err := nativeEncodeValue(reflect.ValueOf(w))
	if err != nil {
		return nil, err
	}
	return canonical.Encode(value, nativeStateOptions(maximumBytes))
}

func decodeNativeRepository(encoded []byte, objectID string, maximumRecords, maximumBytes int) (*MemoryRepository, error) {
	state, err := decodeNativeState(encoded, objectID, maximumRecords, maximumBytes)
	if err != nil {
		return nil, err
	}
	return state.Repository, nil
}

func decodeNativeState(encoded []byte, objectID string, maximumRecords, maximumBytes int) (*nativeRepositoryState, error) {
	if len(encoded) == 0 {
		return newNativeState(NewMemoryRepository()), nil
	}
	value, err := canonical.Decode(encoded, nativeStateOptions(maximumBytes))
	if err != nil {
		return nil, errNativeState
	}
	var w nativeRepositoryWire
	if nativeDecodeValue(value, reflect.ValueOf(&w).Elem()) != nil || validateNativeWire(w, objectID, maximumRecords) != nil {
		return nil, errNativeState
	}
	state := &nativeRepositoryState{Repository: localRepository(w), PolicyDigest: w.PolicyDigest, AuthorityGrants: w.AuthorityGrants, ToolPermits: w.ToolPermits, DeliveredAudits: w.DeliveredAudits, WireInvocations: w.WireInvocations}
	canonicalBytes, err := encodeNativeState(state, objectID, maximumRecords, maximumBytes)
	if err != nil || !bytes.Equal(encoded, canonicalBytes) {
		return nil, errNativeState
	}
	return state, nil
}

var nativeIdentityType = reflect.TypeOf(identity.ID{})
var nativeCredentialType = reflect.TypeOf(CredentialHandle{})

func nativeEncodeValue(value reflect.Value) (canonical.Value, error) {
	if value.Type() == nativeIdentityType {
		return value.Interface().(identity.ID).String(), nil
	}
	if value.Type() == nativeCredentialType {
		return canonical.Bytes(value.Interface().(CredentialHandle).value), nil
	}
	switch value.Kind() {
	case reflect.Bool:
		return value.Bool(), nil
	case reflect.String:
		return canonical.Bytes(value.String()), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(value.Int()))
		return canonical.Bytes(b[:]), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], value.Uint())
		return canonical.Bytes(b[:]), nil
	case reflect.Pointer:
		if value.IsNil() {
			return nil, nil
		}
		return nativeEncodeValue(value.Elem())
	case reflect.Struct:
		m := canonical.Map{}
		for i := 0; i < value.NumField(); i++ {
			field := value.Type().Field(i)
			if !field.IsExported() {
				return nil, errNativeState
			}
			child, err := nativeEncodeValue(value.Field(i))
			if err != nil {
				return nil, err
			}
			m[field.Name] = child
		}
		return m, nil
	case reflect.Slice, reflect.Array:
		if value.Kind() == reflect.Slice && value.IsNil() {
			return nil, nil
		}
		if value.Type().Elem().Kind() == reflect.Uint8 {
			b := make([]byte, value.Len())
			reflect.Copy(reflect.ValueOf(b), value)
			return canonical.Bytes(b), nil
		}
		a := make(canonical.Array, value.Len())
		for i := range a {
			child, err := nativeEncodeValue(value.Index(i))
			if err != nil {
				return nil, err
			}
			a[i] = child
		}
		return a, nil
	case reflect.Map:
		if value.IsNil() {
			return nil, nil
		}
		type pair struct {
			key   []byte
			value canonical.Array
		}
		pairs := make([]pair, 0, value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			key, err := nativeEncodeValue(iterator.Key())
			if err != nil {
				return nil, err
			}
			encoded, err := canonical.Encode(key, canonical.DefaultOptions())
			if err != nil {
				return nil, err
			}
			child, err := nativeEncodeValue(iterator.Value())
			if err != nil {
				return nil, err
			}
			pairs = append(pairs, pair{encoded, canonical.Array{key, child}})
		}
		sort.Slice(pairs, func(i, j int) bool { return bytes.Compare(pairs[i].key, pairs[j].key) < 0 })
		a := make(canonical.Array, len(pairs))
		for i, pair := range pairs {
			a[i] = pair.value
		}
		return a, nil
	}
	return nil, errNativeState
}

func nativeDecodeValue(value canonical.Value, target reflect.Value) error {
	if target.Type() == nativeIdentityType {
		text, ok := value.(string)
		if !ok {
			return errNativeState
		}
		if text == "" {
			target.Set(reflect.ValueOf(identity.ID{}))
			return nil
		}
		var id identity.ID
		if id.UnmarshalText([]byte(text)) != nil {
			return errNativeState
		}
		target.Set(reflect.ValueOf(id))
		return nil
	}
	if target.Type() == nativeCredentialType {
		b, ok := value.(canonical.Bytes)
		if !ok {
			return errNativeState
		}
		handle := CredentialHandle{}
		if len(b) > 0 {
			var err error
			handle, err = NewCredentialHandle(string(b))
			if err != nil {
				return errNativeState
			}
		}
		target.Set(reflect.ValueOf(handle))
		return nil
	}
	if value == nil {
		switch target.Kind() {
		case reflect.Slice, reflect.Map, reflect.Pointer:
			target.SetZero()
			return nil
		}
		return errNativeState
	}
	switch target.Kind() {
	case reflect.Bool:
		v, ok := value.(bool)
		if !ok {
			return errNativeState
		}
		target.SetBool(v)
	case reflect.String:
		v, ok := value.(canonical.Bytes)
		if !ok {
			return errNativeState
		}
		target.SetString(string(v))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v, ok := value.(canonical.Bytes)
		if !ok || len(v) != 8 {
			return errNativeState
		}
		number := int64(binary.BigEndian.Uint64(v))
		if target.OverflowInt(number) {
			return errNativeState
		}
		target.SetInt(number)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v, ok := value.(canonical.Bytes)
		if !ok || len(v) != 8 {
			return errNativeState
		}
		number := binary.BigEndian.Uint64(v)
		if target.OverflowUint(number) {
			return errNativeState
		}
		target.SetUint(number)
	case reflect.Pointer:
		target.Set(reflect.New(target.Type().Elem()))
		return nativeDecodeValue(value, target.Elem())
	case reflect.Struct:
		m, ok := value.(canonical.Map)
		if !ok || len(m) != target.NumField() {
			return errNativeState
		}
		for i := 0; i < target.NumField(); i++ {
			field := target.Type().Field(i)
			if !field.IsExported() {
				return errNativeState
			}
			child, found := m[field.Name]
			if !found || nativeDecodeValue(child, target.Field(i)) != nil {
				return errNativeState
			}
		}
	case reflect.Slice, reflect.Array:
		if target.Type().Elem().Kind() == reflect.Uint8 {
			v, ok := value.(canonical.Bytes)
			if !ok || (target.Kind() == reflect.Array && len(v) != target.Len()) {
				return errNativeState
			}
			if target.Kind() == reflect.Slice {
				target.Set(reflect.MakeSlice(target.Type(), len(v), len(v)))
			}
			reflect.Copy(target, reflect.ValueOf(v))
			return nil
		}
		a, ok := value.(canonical.Array)
		if !ok || (target.Kind() == reflect.Array && len(a) != target.Len()) {
			return errNativeState
		}
		if target.Kind() == reflect.Slice {
			target.Set(reflect.MakeSlice(target.Type(), len(a), len(a)))
		}
		for i, child := range a {
			if nativeDecodeValue(child, target.Index(i)) != nil {
				return errNativeState
			}
		}
	case reflect.Map:
		a, ok := value.(canonical.Array)
		if !ok {
			return errNativeState
		}
		target.Set(reflect.MakeMapWithSize(target.Type(), len(a)))
		var previous []byte
		for _, child := range a {
			pair, ok := child.(canonical.Array)
			if !ok || len(pair) != 2 {
				return errNativeState
			}
			keyBytes, err := canonical.Encode(pair[0], canonical.DefaultOptions())
			if err != nil || (previous != nil && bytes.Compare(previous, keyBytes) >= 0) {
				return errNativeState
			}
			previous = keyBytes
			key, item := reflect.New(target.Type().Key()).Elem(), reflect.New(target.Type().Elem()).Elem()
			if nativeDecodeValue(pair[0], key) != nil || nativeDecodeValue(pair[1], item) != nil || target.MapIndex(key).IsValid() {
				return errNativeState
			}
			target.SetMapIndex(key, item)
		}
	default:
		return errNativeState
	}
	return nil
}
