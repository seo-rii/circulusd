package platformapi

import (
	"context"
	"reflect"

	"github.com/hancomac/circulusd/internal/authority"
)

const eventAppendPermission = authority.Permission("events.append")

// AuthorityEventAuthorizer adapts the snapshot-backed authority validator to
// the event API. Dependency errors are deliberately collapsed so signed
// claims and authoritative snapshot details never cross the public boundary.
type AuthorityEventAuthorizer struct {
	validator TurnAdmissionValidator
}

func NewAuthorityEventAuthorizer(validator TurnAdmissionValidator) (*AuthorityEventAuthorizer, error) {
	if validator == nil {
		return nil, ErrInvalidConfig
	}
	value := reflect.ValueOf(validator)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, ErrInvalidConfig
		}
	}
	return &AuthorityEventAuthorizer{validator: validator}, nil
}

func (authorizer *AuthorityEventAuthorizer) AuthorizeEvent(
	ctx context.Context,
	request EventAuthority,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if authorizer == nil || authorizer.validator == nil || validateEventAuthority(request) != nil {
		return ErrStaleAuthority
	}
	if err := authorizer.validator.ValidateAdmission(
		ctx,
		request.Credential,
		authority.BindingEvents,
		authority.AdmissionRequest{Scope: request.Scope, Permission: eventAppendPermission},
	); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrStaleAuthority
	}
	return nil
}
