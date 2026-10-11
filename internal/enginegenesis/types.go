// Package enginegenesis connects independently qualified executable engine
// genesis sources across a bounded authenticated native transport. It does not
// construct engine core state or mint runtime production proofs.
package enginegenesis

import (
	"context"
	"errors"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/stateappadmission"
)

var (
	ErrInvalidConfig           = errors.New("engine genesis: invalid configuration")
	ErrInvalidRequest          = errors.New("engine genesis: invalid request")
	ErrInvalidResponse         = errors.New("engine genesis: invalid response")
	ErrUnauthenticatedResponse = errors.New("engine genesis: unauthenticated response")
	ErrUnavailable             = errors.New("engine genesis: qualified source unavailable")
	ErrClosed                  = errors.New("engine genesis: transport closed")
)

// Transport owns operational genesis and its native runtime challenge on the
// same origin. Its raw network client does not acquire provider authority until
// NewProvider receives a verifier-sealed binding with engine-genesis capability.
type Transport interface {
	dependency.ProductionProbe
	RequestGenesis(context.Context, stateappadmission.GenesisRequest) (*v1.AgentCheckpoint, error)
}

type Provider struct {
	transport Transport
	binding   dependency.Verified[Transport]
}

var _ stateappadmission.GenesisProvider = (*Provider)(nil)

func (*Provider) String() string   { return "qualified-engine-genesis-provider<redacted>" }
func (*Provider) GoString() string { return "qualified-engine-genesis-provider<redacted>" }

func NewProvider(binding dependency.Verified[Transport]) (*Provider, error) {
	transport, _, err := binding.Open()
	if err != nil || transport == nil {
		return nil, dependency.ErrUnverifiedDependency
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{dependency.AtomicEngineGenesis}, binding); err != nil {
		return nil, err
	}
	return &Provider{transport: transport, binding: binding}, nil
}

func (provider *Provider) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	if provider == nil {
		return dependency.ProbeResponse{}, dependency.ErrUnverifiedDependency
	}
	if _, _, err := provider.binding.Open(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	return provider.transport.ProbeProduction(ctx, challenge)
}

func (provider *Provider) CreateGenesis(ctx context.Context, request stateappadmission.GenesisRequest) (*v1.AgentCheckpoint, error) {
	if ctx == nil {
		return nil, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if provider == nil {
		return nil, dependency.ErrUnverifiedDependency
	}
	if _, _, err := provider.binding.Open(); err != nil {
		return nil, dependency.ErrUnverifiedDependency
	}
	owned, _, err := snapshotRequest(request)
	if err != nil {
		return nil, err
	}
	retained, _, err := snapshotRequest(owned)
	if err != nil {
		return nil, err
	}
	checkpoint, err := provider.transport.RequestGenesis(ctx, owned)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	return snapshotCheckpoint(checkpoint, retained)
}
