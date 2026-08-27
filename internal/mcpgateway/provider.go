package mcpgateway

import (
	"context"
	"fmt"
	"strings"
)

func NewProviderDispatchError(classification DispatchFailureClassification, reason string, cause error) (*ProviderDispatchError, error) {
	switch classification {
	case DispatchDefinitelyNotSent, DispatchUnknown:
	default:
		return nil, fmt.Errorf("%w: invalid provider failure classification", ErrInvalidRequest)
	}
	reason = strings.TrimSpace(reason)
	if !validBoundedText(reason, hardMaxFailureBytes) {
		return nil, fmt.Errorf("%w: provider failure reason is required and bounded", ErrInvalidRequest)
	}
	return &ProviderDispatchError{classification: classification, reason: reason, cause: cause}, nil
}

func (failure *ProviderDispatchError) Error() string {
	if failure == nil {
		return "MCP provider dispatch failed"
	}
	return failure.reason
}

func (failure *ProviderDispatchError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

func (failure *ProviderDispatchError) Classification() DispatchFailureClassification {
	if failure == nil {
		return DispatchUnknown
	}
	return failure.classification
}

type unavailableProvider struct{ reason string }

func NewUnavailableProvider(reason string) (Provider, error) {
	reason = strings.TrimSpace(reason)
	if !validBoundedText(reason, 512) {
		return nil, fmt.Errorf("%w: unavailable provider reason is required and bounded", ErrInvalidConfiguration)
	}
	return unavailableProvider{reason: reason}, nil
}

func (provider unavailableProvider) Availability(context.Context, ServerDescriptor) (ServerAvailability, error) {
	return ServerAvailability{Available: false, Reason: provider.reason}, nil
}

func (provider unavailableProvider) Negotiate(context.Context, NegotiationCommand) (StartNegotiationReceipt, error) {
	return StartNegotiationReceipt{}, fmt.Errorf("%w: %s", ErrProviderUnavailable, provider.reason)
}

func (provider unavailableProvider) Start(context.Context, ProviderCommand) (ProviderStartResult, error) {
	return ProviderStartResult{}, fmt.Errorf("%w: %s", ErrProviderUnavailable, provider.reason)
}

func (provider unavailableProvider) Cancel(context.Context, CancelCommand) (CancellationResult, error) {
	return CancellationResult{Status: CancellationUnknown}, fmt.Errorf("%w: %s", ErrProviderUnavailable, provider.reason)
}

func (provider unavailableProvider) Lookup(_ context.Context, query LedgerQuery) (LedgerRecord, error) {
	return LedgerRecord{InvocationID: query.InvocationID, RequestDigest: query.RequestDigest, Status: LedgerUnknown},
		fmt.Errorf("%w: %s", ErrProviderUnavailable, provider.reason)
}
