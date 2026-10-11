package modelgateway

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"slices"
	"sort"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

const nativeModelProtocol = "circulus.native-model-admission.v2"

// Exact v1 input remains readable. Its original field set is deliberately
// separate so missing v2 fields cannot alias an empty projection map.
type nativeModelStateV1 struct {
	Protocol     string
	ObjectID     string
	PolicyDigest Digest
	Fences       map[string]ValidatedAuthority
	Grants       map[string]NativeAuthorityGrant
	Reservations map[string]nativeQuotaReservation
}

var errNativeState = errors.New("model gateway: corrupt native admission state")
var nativeIdentityType = reflect.TypeOf(identity.ID{})

func (factory *NativeFactory) stateOptions() canonical.Options {
	return canonical.Options{MaxBytes: factory.maximumBytes, MaxDepth: 24, MaxItems: min(1_000_000, factory.maximumRecords*256+1024)}
}

func (factory *NativeFactory) newState() *nativeModelState {
	return &nativeModelState{Protocol: nativeModelProtocol, ObjectID: factory.objectID, PolicyDigest: factory.policyDigest,
		Fences: make(map[string]ValidatedAuthority), Grants: make(map[string]NativeAuthorityGrant), Reservations: make(map[string]nativeQuotaReservation), Projections: make(map[string]nativeSessionQuotaRecord)}
}

func (factory *NativeFactory) validateState(state *nativeModelState) error {
	if state == nil || state.Protocol != nativeModelProtocol || state.ObjectID != factory.objectID || state.PolicyDigest != factory.policyDigest ||
		state.Fences == nil || state.Grants == nil || state.Reservations == nil || state.Projections == nil {
		return errNativeState
	}
	if len(state.Fences)+len(state.Grants)+len(state.Reservations)+len(state.Projections) > factory.maximumRecords {
		return ErrInputLimit
	}
	for key, fence := range state.Fences {
		if !validNativeScope(fence) || key != nativeFenceKey(fence) {
			return errNativeState
		}
	}
	for key, grant := range state.Grants {
		if !validNativeGrant(grant) || key != nativeDigestKey(grant.BearerDigest) {
			return errNativeState
		}
		if _, ok := state.Fences[nativeFenceKey(grant.Scope)]; !ok {
			return errNativeState
		}
	}
	reserved := make(map[string]uint64)
	for key, projection := range state.Projections {
		reservation, found := state.Reservations[key]
		if !found || factory.validateProjection(projection, reservation) != nil {
			return errNativeState
		}
	}
	for key, reservation := range state.Reservations {
		request := reservation.Request
		if !validNativeQuotaRequest(request) || key != request.InvocationID.String() || reservation.Permit != nativeQuotaPermit(request) {
			return errNativeState
		}
		bound := false
		for _, grant := range state.Grants {
			if grant.Scope == quotaRequestScope(request) && grant.RequestDigest == request.RequestDigest && slices.Contains(grant.Permissions, "model.dispatch") {
				bound = true
				break
			}
		}
		if !bound {
			return errNativeState
		}
		budgetKey := nativeQuotaKey(request.TenantID, request.UserID)
		limit := factory.quotaLimit(request.TenantID, request.UserID)
		amount := nativeReservationCharge(state, reservation)
		if amount > limit || reserved[budgetKey] > limit-amount {
			return errNativeState
		}
		reserved[budgetKey] += amount
	}
	return nil
}

func (factory *NativeFactory) encodeState(state *nativeModelState) ([]byte, error) {
	if err := factory.validateState(state); err != nil {
		return nil, err
	}
	value, err := nativeEncodeValue(reflect.ValueOf(*state))
	if err != nil {
		return nil, err
	}
	return canonical.Encode(value, factory.stateOptions())
}

func (factory *NativeFactory) decodeState(encoded []byte) (*nativeModelState, error) {
	if len(encoded) == 0 {
		return factory.newState(), nil
	}
	value, err := canonical.Decode(encoded, factory.stateOptions())
	if err != nil {
		return nil, errNativeState
	}
	var state nativeModelState
	members, _ := value.(canonical.Map)
	protocol, _ := members["Protocol"].(canonical.Bytes)
	if bytes.Equal(protocol, []byte("circulus.native-model-admission.v1")) {
		var legacy nativeModelStateV1
		if nativeDecodeValue(value, reflect.ValueOf(&legacy).Elem()) != nil {
			return nil, errNativeState
		}
		rebuiltValue, err := nativeEncodeValue(reflect.ValueOf(legacy))
		if err != nil {
			return nil, errNativeState
		}
		rebuilt, err := canonical.Encode(rebuiltValue, factory.stateOptions())
		if err != nil || !bytes.Equal(encoded, rebuilt) {
			return nil, errNativeState
		}
		state = nativeModelState{Protocol: nativeModelProtocol, ObjectID: legacy.ObjectID, PolicyDigest: legacy.PolicyDigest,
			Fences: legacy.Fences, Grants: legacy.Grants, Reservations: legacy.Reservations, Projections: make(map[string]nativeSessionQuotaRecord)}
		if factory.validateState(&state) != nil {
			return nil, errNativeState
		}
		return &state, nil
	}
	if nativeDecodeValue(value, reflect.ValueOf(&state).Elem()) != nil || factory.validateState(&state) != nil {
		return nil, errNativeState
	}
	rebuilt, err := factory.encodeState(&state)
	if err != nil || !bytes.Equal(encoded, rebuilt) {
		return nil, errNativeState
	}
	return &state, nil
}

// Versioned state uses exact struct field sets and sorted map entries. Explicit
// identity strings also encode optional zero IDs without invoking MarshalText.
// Full-width integers use eight bytes, preserving nanosecond deadlines exactly.
// Re-encoding rejects aliases, unknown members and alternate representations.
func nativeEncodeValue(value reflect.Value) (canonical.Value, error) {
	if value.Type() == nativeIdentityType {
		return value.Interface().(identity.ID).String(), nil
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
