package modelgateway

import (
	"context"

	"github.com/hancomac/circulusd/internal/dependency"
)

// The served Session path consumes broker.ClaimedDispatchStart through its
// subordinate NativeLedger. This candidate intentionally cannot create a
// second effect owner, retry authority or provider-start permit.
type nativeDispatchUnavailable struct{ factory *NativeFactory }

func (coordinator *nativeDispatchUnavailable) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	return coordinator.factory.probe(ctx, challenge)
}
func (*nativeDispatchUnavailable) Durability() DispatchDurability { return DispatchDurability{} }
func (*nativeDispatchUnavailable) CommitAndClaimDispatch(context.Context, DispatchCommitRequest) (DispatchPermit, error) {
	return DispatchPermit{}, ErrDispatchNotDurable
}
func (*nativeDispatchUnavailable) BeginProviderDispatch(context.Context, DispatchPermit) error {
	return ErrDispatchNotDurable
}
func (*nativeDispatchUnavailable) CommitProviderAccepted(context.Context, ProviderAcceptedCommitRequest) error {
	return ErrDispatchNotDurable
}
func (*nativeDispatchUnavailable) CommitAndClaimCancellation(context.Context, CancellationCommitRequest) (CancellationPermit, error) {
	return CancellationPermit{}, ErrDispatchNotDurable
}
func (*nativeDispatchUnavailable) CommitAndClaimResume(context.Context, ResumeCommitRequest) (ResumePermit, error) {
	return ResumePermit{}, ErrDispatchNotDurable
}
func (*nativeDispatchUnavailable) CommitAndClaimSettlement(context.Context, SettlementCommitRequest) (SettlementPermit, error) {
	return SettlementPermit{}, ErrSettlementNotReady
}
func (*nativeDispatchUnavailable) CommitAndClaimUncertainResolution(context.Context, UncertainResolutionCommitRequest) (UncertainResolutionPermit, error) {
	return UncertainResolutionPermit{}, ErrSettlementNotReady
}
