package broker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/hancomac/circulusd/internal/identity"
)

func TestInvocationLedgerRouterRoutesExactServiceAndCopiesRegistry(t *testing.T) {
	t.Parallel()

	lookup := baseLedgerLookup()
	selected := &routingLedger{record: exactLedgerRecord(lookup, LedgerInflight)}
	replacement := &routingLedger{record: exactLedgerRecord(lookup, LedgerFailed)}
	registry := map[EffectService]InvocationLedger{ServiceExecutor: selected}
	router, err := NewInvocationLedgerRouter(registry)
	if err != nil {
		t.Fatalf("NewInvocationLedgerRouter() error = %v", err)
	}
	registry[ServiceExecutor] = replacement

	record, err := router.Lookup(context.Background(), lookup)
	if err != nil || record.Status != LedgerInflight {
		t.Fatalf("Lookup() = %#v, %v; want selected inflight ledger", record, err)
	}
	if selected.lookups.Load() != 1 || replacement.lookups.Load() != 0 {
		t.Fatalf("lookup calls selected/replacement = %d/%d", selected.lookups.Load(), replacement.lookups.Load())
	}
}

func TestInvocationLedgerRouterRejectsMissingTypedNilAndRelabeledLedgers(t *testing.T) {
	t.Parallel()

	var typedNil *routingLedger
	for name, registry := range map[string]map[EffectService]InvocationLedger{
		"empty":     {},
		"typed nil": {ServiceExecutor: typedNil},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if router, err := NewInvocationLedgerRouter(registry); router != nil || !errors.Is(err, ErrLedgerUnavailable) {
				t.Fatalf("NewInvocationLedgerRouter() = %#v, %v; want nil/ErrLedgerUnavailable", router, err)
			}
		})
	}

	lookup := baseLedgerLookup()
	wrong := exactLedgerRecord(lookup, LedgerUnknown)
	wrong.Service = ServiceWorkspace
	router, err := NewInvocationLedgerRouter(map[EffectService]InvocationLedger{
		ServiceExecutor: &routingLedger{record: wrong},
	})
	if err != nil {
		t.Fatalf("NewInvocationLedgerRouter() error = %v", err)
	}
	if record, lookupErr := router.Lookup(context.Background(), lookup); record != (LedgerRecord{}) || !errors.Is(lookupErr, ErrLedgerMismatch) {
		t.Fatalf("Lookup(relabeled) = %#v, %v; want zero/ErrLedgerMismatch", record, lookupErr)
	}
	lookup.Service = ServiceMCP
	if record, lookupErr := router.Lookup(context.Background(), lookup); record != (LedgerRecord{}) || !errors.Is(lookupErr, ErrLedgerUnavailable) {
		t.Fatalf("Lookup(missing) = %#v, %v; want zero/ErrLedgerUnavailable", record, lookupErr)
	}
}

type routingLedger struct {
	record  LedgerRecord
	lookups atomic.Int64
}

func (ledger *routingLedger) Lookup(context.Context, LedgerLookup) (LedgerRecord, error) {
	ledger.lookups.Add(1)
	return ledger.record, nil
}

func baseLedgerLookup() LedgerLookup {
	return LedgerLookup{
		EffectKey: EffectKey{
			SessionID: sessionID, TurnID: turnID, EffectID: effectID,
			InvocationID: invocationID, RequestDigest: digest(2),
		},
		TenantID: tenantID, WorkspaceID: workspaceID, Service: ServiceExecutor,
		Operation: "run", DispatchAttempt: 1,
		ProviderRequestID: mustID(identity.Request, "R"), ProviderRouteDigest: digest(152),
	}
}

func exactLedgerRecord(lookup LedgerLookup, status LedgerStatus) LedgerRecord {
	return LedgerRecord{
		Status: status, TenantID: lookup.TenantID, WorkspaceID: lookup.WorkspaceID,
		EffectID: lookup.EffectID, InvocationID: lookup.InvocationID, RequestDigest: lookup.RequestDigest,
		Service: lookup.Service, Operation: lookup.Operation, DispatchAttempt: lookup.DispatchAttempt,
		ProviderRequestID: lookup.ProviderRequestID, ProviderRouteDigest: lookup.ProviderRouteDigest,
	}
}
