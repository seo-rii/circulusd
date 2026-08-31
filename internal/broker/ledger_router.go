package broker

import (
	"context"
	"fmt"
	"reflect"
)

// InvocationLedgerRouter selects one immutable subordinate provider ledger by
// the Session-bound service. A result is accepted only when it repeats the
// complete lookup identity, including absent and unknown observations.
type InvocationLedgerRouter struct {
	ledgers map[EffectService]InvocationLedger
}

func NewInvocationLedgerRouter(ledgers map[EffectService]InvocationLedger) (*InvocationLedgerRouter, error) {
	if len(ledgers) == 0 {
		return nil, ErrLedgerUnavailable
	}
	registry := make(map[EffectService]InvocationLedger, len(ledgers))
	for service, ledger := range ledgers {
		ledgerIsNil := ledger == nil
		if !ledgerIsNil {
			value := reflect.ValueOf(ledger)
			switch value.Kind() {
			case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
				ledgerIsNil = value.IsNil()
			}
		}
		if !validService(service) || ledgerIsNil {
			return nil, ErrLedgerUnavailable
		}
		registry[service] = ledger
	}
	return &InvocationLedgerRouter{ledgers: registry}, nil
}

func (router *InvocationLedgerRouter) Lookup(ctx context.Context, lookup LedgerLookup) (LedgerRecord, error) {
	if router == nil || ctx == nil {
		return LedgerRecord{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return LedgerRecord{}, err
	}
	ledger, found := router.ledgers[lookup.Service]
	if !found {
		return LedgerRecord{}, ErrLedgerUnavailable
	}
	record, err := ledger.Lookup(ctx, lookup)
	if err != nil {
		return LedgerRecord{}, fmt.Errorf("lookup %s invocation ledger: %w", lookup.Service, err)
	}
	if err := validateLedgerRoute(record, lookup); err != nil {
		return LedgerRecord{}, err
	}
	return record, nil
}
