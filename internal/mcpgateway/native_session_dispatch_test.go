package mcpgateway

import (
	"context"
	"errors"
	"testing"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/celldbridge"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/effectledger"
)

// These constructor-only fixtures never perform storage or provider I/O. Their
// test authorities prove that the actual candidate instances are challenged;
// they are not conformance evidence for a running native application.
type nativeStarterFixtureTransport struct{ mcpRuntimeProof }

func (transport *nativeStarterFixtureTransport) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return transport.respond(ctx, challenge)
}
func (*nativeStarterFixtureTransport) ReadSnapshot(context.Context, celldbridge.SnapshotRequest) (celldbridge.Snapshot, error) {
	return celldbridge.Snapshot{}, celldbridge.ErrUnavailable
}
func (*nativeStarterFixtureTransport) ReadReceipt(context.Context, celldbridge.ReceiptRequest) (celldbridge.ReceiptResult, error) {
	return celldbridge.ReceiptResult{}, celldbridge.ErrUnavailable
}
func (*nativeStarterFixtureTransport) CompareAndCommit(context.Context, celldbridge.CommitRequest) (celldbridge.CommitResult, error) {
	return celldbridge.CommitResult{}, celldbridge.ErrUnavailable
}
func (*nativeStarterFixtureTransport) ConfirmBarrier(context.Context, celldbridge.BarrierRequest) (celldbridge.BarrierResult, error) {
	return celldbridge.BarrierResult{}, celldbridge.ErrUnavailable
}

func nativeStarterFixtureLedger(t *testing.T, proofs mcpProductionProofs, service broker.EffectService, route broker.Digest, limits effectledger.ReferenceLimits) dependency.Verified[*effectledger.NativeLedger] {
	t.Helper()
	transport := &nativeStarterFixtureTransport{proofs.runtimeProof}
	verified := verifyMCPProduction(t, proofs, celldbridge.NativeTransport(transport))
	storage, err := celldbridge.New(celldbridge.Config{Transport: verified, Bounds: celldbridge.Bounds{MaxStateBytes: 1 << 20, MaxReceiptResponseBytes: 4096,
		MaxCapabilityClaims: 8, MaxCapabilityClaimBytes: 1024, MaxReceiptLookups: 4, MaxReceiptWrites: 4, MaxTransactionBytes: 2 << 20}, MaximumAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	qualifiedStorage := verifyMCPProduction(t, proofs, storage)
	ledger, err := effectledger.NewNativeLedger(effectledger.NativeConfig{Storage: qualifiedStorage, Service: service, RouteDigest: route, Limits: limits, MaximumStateBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return verifyMCPProduction(t, proofs, ledger)
}

func TestNativeSessionStarterRejectsReferenceWrongRouteBoundsAndUnavailableProvider(t *testing.T) {
	fixture := newNativeFactoryFixture(t)
	gateway, err := NewProductionGateway(fixture.configuration, qualifyNativeFactory(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	route := broker.Digest(digestWithByte(71))
	limits := effectledger.ReferenceLimits{MaximumPayloadBytes: 1 << 16, MaximumResultBytes: 1 << 16}
	ledger := nativeStarterFixtureLedger(t, fixture.proofs, broker.ServiceMCP, route, limits)
	if _, err := NewProductionSessionDispatchStarter(fixture.reference.gateway, ledger, route); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatal("reference gateway entered a production Session starter")
	}
	if _, err := NewProductionSessionDispatchStarter(gateway, dependency.Verified[*effectledger.NativeLedger]{}, route); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatal("unqualified concrete ledger entered production")
	}
	if _, err := NewProductionSessionDispatchStarter(gateway, ledger, broker.Digest(digestWithByte(72))); !errors.Is(err, ErrAuthorityMismatch) {
		t.Fatal("different native ledger route accepted")
	}
	modelLedger := nativeStarterFixtureLedger(t, fixture.proofs, broker.ServiceModel, route, limits)
	if _, err := NewProductionSessionDispatchStarter(gateway, modelLedger, route); !errors.Is(err, ErrAuthorityMismatch) {
		t.Fatal("non-MCP native ledger accepted")
	}
	small := nativeStarterFixtureLedger(t, fixture.proofs, broker.ServiceMCP, route, effectledger.ReferenceLimits{MaximumPayloadBytes: 256, MaximumResultBytes: 256})
	if _, err := NewProductionSessionDispatchStarter(gateway, small, route); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("ledger cannot retain actual configured MCP envelopes")
	}
	if _, err := NewProductionSessionDispatchStarter(gateway, ledger, route); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatal("unavailable-only candidate enabled actual Session admission")
	}
}

func TestNativeSessionStarterRejectsDifferentQualifiedNativeSource(t *testing.T) {
	fixture := newNativeFactoryFixture(t)
	gateway, err := NewProductionGateway(fixture.configuration, qualifyNativeFactory(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	other := newMCPProductionProofs(t, "different-native-domain", fixture.proofs.descriptor.AtomicGroups)
	route := broker.Digest(digestWithByte(73))
	ledger := nativeStarterFixtureLedger(t, other, broker.ServiceMCP, route, effectledger.ReferenceLimits{MaximumPayloadBytes: 1 << 16, MaximumResultBytes: 1 << 16})
	if _, err := NewProductionSessionDispatchStarter(gateway, ledger, route); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatal("a different actual native source supplied the observation ledger")
	}
}
