package providerresult

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/effectledger"
	"github.com/hancomac/circulusd/internal/mcpgateway"
	"github.com/hancomac/circulusd/internal/modelgateway"
	"github.com/hancomac/circulusd/internal/stateappbroker"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

const MaximumCommittedLedgerResultBytes = 16 << 20

var ErrUnsupportedService = errors.New("provider result: unsupported effect service")

// CommittedRecord retains the provider's immutable terminal observation and
// its independently captured normalized Pi body under one complete identity.
// A reader must qualify the atomic binding between those records, the committed
// status and the reference IDs. A bare canonical body or subordinate reference
// ledger does not establish this durable relationship.
type CommittedRecord struct {
	Request       stateappbroker.ResultRequest
	Service       broker.EffectService
	Status        effectledger.TerminalStatus
	LedgerResult  []byte
	PayloadDigest broker.Digest
	CanonicalCBOR []byte
}

func (CommittedRecord) String() string   { return "committed-provider-record<redacted>" }
func (CommittedRecord) GoString() string { return "committed-provider-record<redacted>" }

// Records reads the same immutable record domain attested by its native probe.
// It cannot invoke a provider, retry an effect or mint settlement authority.
type Records interface {
	ReadCommittedResult(context.Context, stateappbroker.ResultRequest) (CommittedRecord, error)
	dependency.ProductionProbe
}

// RecordResolverConfig chooses an immutable normalization policy. Nil MCPBounds
// permits model results only. Non-nil bounds enable MCP results after the full
// gateway bound validation; the constructor retains a value copy.
type RecordResolverConfig struct {
	MCPBounds *mcpgateway.Bounds
}

type RecordResolver struct {
	records    Records
	binding    dependency.Verified[Records]
	mcpBounds  mcpgateway.Bounds
	mcpEnabled bool
}

// NewRecordResolver retains an independently qualified operational record
// reader and checks its terminal facts before exposing Pi result bytes. The
// resulting resolver needs its own fresh qualification before NewServer or
// stateappbroker.Store can accept it. Its probe delegates only to this same
// reader; no Session-state probe or reference implementation is substituted.
func NewRecordResolver(binding dependency.Verified[Records], config RecordResolverConfig) (*RecordResolver, error) {
	records, descriptor, err := binding.Open()
	if err != nil || nilInterface(records) || !slices.Contains(descriptor.AtomicGroups, dependency.AtomicEffectLifecycle) {
		return nil, dependency.ErrUnverifiedDependency
	}
	resolver := &RecordResolver{records: records, binding: binding}
	if config.MCPBounds != nil {
		bounds := *config.MCPBounds
		if err := mcpgateway.ValidateSessionPiResultBounds(bounds); err != nil {
			return nil, dependency.ErrInvalidConfiguration
		}
		resolver.mcpBounds, resolver.mcpEnabled = bounds, true
	}
	return resolver, nil
}

func (resolver *RecordResolver) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	if ctx == nil {
		return dependency.ProbeResponse{}, broker.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	if resolver == nil || nilInterface(resolver.records) {
		return dependency.ProbeResponse{}, dependency.ErrUnverifiedDependency
	}
	if _, _, err := resolver.binding.Open(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	response, err := resolver.records.ProbeProduction(ctx, challenge)
	if err != nil {
		return dependency.ProbeResponse{}, recordError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	return response, nil
}

func (resolver *RecordResolver) ResolveResult(ctx context.Context, request stateappbroker.ResultRequest) (stateappbroker.Result, error) {
	if ctx == nil {
		return stateappbroker.Result{}, broker.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return stateappbroker.Result{}, err
	}
	if resolver == nil || nilInterface(resolver.records) {
		return stateappbroker.Result{}, dependency.ErrUnverifiedDependency
	}
	if _, _, err := resolver.binding.Open(); err != nil {
		return stateappbroker.Result{}, err
	}
	if err := stateappclient.ValidateProviderResultRequest(requestWire(request)); err != nil {
		return stateappbroker.Result{}, broker.ErrInvalidRequest
	}
	record, err := resolver.records.ReadCommittedResult(ctx, request)
	if err != nil {
		// Keep the fixed record classes (absent, conflicting, fenced) so the
		// caller and the read route can tell them apart from transport loss.
		return stateappbroker.Result{}, persistenceError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return stateappbroker.Result{}, err
	}
	if record.Request != request {
		return stateappbroker.Result{}, broker.ErrFenceMismatch
	}
	if record.Status != effectledger.TerminalCommitted {
		return stateappbroker.Result{}, broker.ErrInvalidEffectState
	}
	if record.Service != broker.ServiceModel && (record.Service != broker.ServiceMCP || !resolver.mcpEnabled) {
		return stateappbroker.Result{}, ErrUnsupportedService
	}
	if len(record.LedgerResult) < 1 || len(record.LedgerResult) > MaximumCommittedLedgerResultBytes ||
		len(record.CanonicalCBOR) < 1 || len(record.CanonicalCBOR) > stateappclient.MaximumProviderResultBytes {
		return stateappbroker.Result{}, stateappclient.ErrInvalidResponse
	}
	// Check both limits before copying. The record's complete request identity
	// and committed status were compared before inspecting either result body.
	ledger, body := bytes.Clone(record.LedgerResult), bytes.Clone(record.CanonicalCBOR)
	digest := broker.Digest(sha256.Sum256(body))
	if digest != record.PayloadDigest || !validBody(body) {
		return stateappbroker.Result{}, stateappclient.ErrInvalidResponse
	}
	switch record.Service {
	case broker.ServiceModel:
		body, err = modelgateway.ValidateSessionPiResult(ledger, body)
	case broker.ServiceMCP:
		body, err = mcpgateway.ValidateSessionPiResult(ledger, body, resolver.mcpBounds)
	default:
		return stateappbroker.Result{}, ErrUnsupportedService
	}
	if err != nil {
		return stateappbroker.Result{}, stateappclient.ErrInvalidResponse
	}
	if err := ctx.Err(); err != nil {
		return stateappbroker.Result{}, err
	}
	return stateappbroker.Result{Request: request, PayloadDigest: digest, CanonicalCBOR: body}, nil
}

func recordError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	for _, safe := range []error{context.Canceled, context.DeadlineExceeded,
		stateappclient.ErrClientClosed, stateappclient.ErrInvalidConfig, stateappclient.ErrInvalidRequest,
		stateappclient.ErrUnauthenticatedResponse, stateappclient.ErrInvalidResponse, stateappclient.ErrRemote,
		dependency.ErrUnverifiedDependency} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return stateappclient.ErrTransport
}

var _ stateappbroker.ResultResolver = (*RecordResolver)(nil)
