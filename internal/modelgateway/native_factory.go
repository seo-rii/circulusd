package modelgateway

import (
	"context"
	"crypto/sha256"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celldbridge"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
)

// NativeQuotaLimit caps the sum of outstanding reservations for one exact
// tenant/user. No inferred default budget or unbounded quota is permitted.
type NativeQuotaLimit struct {
	TenantID      identity.ID
	UserID        identity.ID
	MaximumTokens uint64
}

// Ports remain provider-neutral data interfaces. This primitive factory
// rejects configured ports until concrete adapters are qualified separately.
type NativeProviderConfig struct {
	Port              Provider
	UnavailableReason string
}

type NativeFactoryConfig struct {
	Storage           dependency.Verified[*celldbridge.Storage]
	ObjectID          string
	MaximumRecords    int
	MaximumStateBytes int
	Configuration     Configuration
	QuotaLimits       []NativeQuotaLimit
	TokenCounter      TokenCounter
	Providers         map[string]NativeProviderConfig
}

func (NativeFactoryConfig) String() string   { return "native-model-factory-config<redacted>" }
func (NativeFactoryConfig) GoString() string { return "native-model-factory-config<redacted>" }

// NativeCandidates are operational instances awaiting independent native
// evidence, not proof of readiness. In particular, settlement and the legacy
// effect coordinator are deliberately unavailable in this primitive unit.
type NativeCandidates struct {
	Authority    ProductionAuthorityValidator
	Quota        ProductionQuotaAdmitter
	Dispatches   ProductionDispatchCoordinator
	TokenCounter TokenCounter
	Providers    map[string]Provider
}

type NativeFactory struct {
	source         nativeModelSource
	binding        dependency.Binding
	descriptor     dependency.Descriptor
	check          func() error
	objectID       string
	maximumRecords int
	maximumBytes   int
	configuration  Configuration
	quotaLimits    []NativeQuotaLimit
	policyDigest   Digest
	now            func() time.Time
	authority      *nativeAuthority
	quota          *nativeQuota
	dispatches     *nativeDispatchUnavailable
	counter        *nativeCounterUnavailable
	providers      map[string]*nativeModelUnavailableProvider
}

func (*NativeFactory) String() string   { return "native-model-factory<redacted>" }
func (*NativeFactory) GoString() string { return "native-model-factory<redacted>" }

func NewNativeFactory(config NativeFactoryConfig) (*NativeFactory, error) {
	source, _, err := config.Storage.Open()
	if err != nil || source == nil {
		return nil, dependency.ErrUnverifiedDependency
	}
	if config.Configuration.AllowReferenceMemory || config.ObjectID == "" || len(config.ObjectID) > 256 ||
		!identifierPattern.MatchString(config.ObjectID) || config.MaximumRecords < 1 || config.MaximumRecords > 16_384 ||
		config.MaximumStateBytes < 1024 || config.MaximumStateBytes > celldbridge.MaximumStateBytes ||
		len(config.Providers) == 0 || len(config.Providers) > config.MaximumRecords || len(config.Configuration.Grants) > config.MaximumRecords ||
		len(config.QuotaLimits) == 0 || len(config.QuotaLimits) > config.MaximumRecords {
		return nil, ErrInvalidConfiguration
	}
	if !nativeNil(config.TokenCounter) {
		return nil, ErrProviderUnavailable
	}
	descriptor, err := dependency.RequireAtomicDomain(nativeModelGroups(), config.Storage)
	if err != nil {
		return nil, err
	}
	configuration := config.Configuration
	configuration.Grants = slices.Clone(configuration.Grants)
	limits := slices.Clone(config.QuotaLimits)
	slices.SortFunc(limits, func(a, b NativeQuotaLimit) int {
		return strings.Compare(nativeQuotaKey(a.TenantID, a.UserID), nativeQuotaKey(b.TenantID, b.UserID))
	})
	for i, limit := range limits {
		if limit.TenantID.Kind() != identity.Tenant || limit.UserID.Kind() != identity.Subject || limit.MaximumTokens == 0 ||
			(i > 0 && nativeQuotaKey(limits[i-1].TenantID, limits[i-1].UserID) == nativeQuotaKey(limit.TenantID, limit.UserID)) {
			return nil, ErrInvalidConfiguration
		}
	}
	factory := &NativeFactory{source: source, binding: config.Storage, descriptor: descriptor, check: func() error {
		_, _, err := config.Storage.Open()
		return err
	}, objectID: config.ObjectID, maximumRecords: config.MaximumRecords, maximumBytes: config.MaximumStateBytes,
		configuration: configuration, quotaLimits: limits, now: time.Now, providers: make(map[string]*nativeModelUnavailableProvider)}
	factory.authority, factory.quota = &nativeAuthority{factory}, &nativeQuota{factory}
	factory.dispatches, factory.counter = &nativeDispatchUnavailable{factory}, &nativeCounterUnavailable{factory}
	providers := make(map[string]Provider, len(config.Providers))
	reasons := make(map[string]string, len(config.Providers))
	for id, config := range config.Providers {
		if !nativeNil(config.Port) {
			return nil, ErrProviderUnavailable
		}
		provider, err := NewUnavailableProvider(config.UnavailableReason)
		if err != nil {
			return nil, err
		}
		wrapped := &nativeModelUnavailableProvider{factory: factory, provider: provider}
		providers[id], factory.providers[id], reasons[id] = wrapped, wrapped, provider.(unavailableProvider).reason
	}
	if _, err := newGatewayConfiguration(configuration, providers); err != nil {
		return nil, err
	}
	for _, grant := range configuration.Grants {
		if factory.quotaLimit(grant.TenantID, grant.UserID) == 0 {
			return nil, ErrInvalidConfiguration
		}
	}
	policy := struct {
		Version       string
		ObjectID      string
		Records       int
		Bytes         int
		Configuration Configuration
		QuotaLimits   []NativeQuotaLimit
		Providers     map[string]string
	}{"circulus.native-model-policy.v1", factory.objectID, factory.maximumRecords, factory.maximumBytes, configuration, limits, reasons}
	value, err := nativeEncodeValue(reflect.ValueOf(policy))
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	encoded, err := canonical.Encode(value, factory.stateOptions())
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	factory.policyDigest = sha256.Sum256(encoded)
	return factory, nil
}

func nativeNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func (factory *NativeFactory) Candidates() NativeCandidates {
	if factory == nil {
		return NativeCandidates{}
	}
	providers := make(map[string]Provider, len(factory.providers))
	for id, provider := range factory.providers {
		providers[id] = provider
	}
	return NativeCandidates{factory.authority, factory.quota, factory.dispatches, factory.counter, providers}
}

// SealDependencies binds independently verified candidates to their exact
// concrete storage and immutable policy. A seal alone cannot enable Gateway:
// the missing Session settlement bridge keeps its durability gate closed.
func (factory *NativeFactory) SealDependencies(dependencies ProductionDependencies) (ProductionDependencies, error) {
	if err := factory.validateDependencies(dependencies); err != nil {
		return ProductionDependencies{}, err
	}
	dependencies.factory = factory
	providers := make(map[string]Provider, len(dependencies.Providers))
	for id, provider := range dependencies.Providers {
		providers[id] = provider
	}
	dependencies.Providers = providers
	return dependencies, nil
}

func (factory *NativeFactory) validateDependencies(dependencies ProductionDependencies) error {
	if factory == nil || factory.check == nil || factory.check() != nil {
		return ErrStateDependenciesNotDurable
	}
	authority, descriptor, err := dependencies.Authority.Open()
	if err != nil || authority != factory.authority || !reflect.DeepEqual(descriptor, factory.descriptor) {
		return ErrStateDependenciesNotDurable
	}
	quota, descriptor, err := dependencies.Quota.Open()
	if err != nil || quota != factory.quota || !reflect.DeepEqual(descriptor, factory.descriptor) {
		return ErrStateDependenciesNotDurable
	}
	dispatches, descriptor, err := dependencies.Dispatches.Open()
	if err != nil || dispatches != factory.dispatches || !reflect.DeepEqual(descriptor, factory.descriptor) || dependencies.TokenCounter != factory.counter || len(dependencies.Providers) != len(factory.providers) {
		return ErrStateDependenciesNotDurable
	}
	for id, provider := range factory.providers {
		if dependencies.Providers[id] != provider {
			return ErrStateDependenciesNotDurable
		}
	}
	if _, err := dependency.RequireAtomicDomain(nativeModelGroups(), factory.binding, dependencies.Authority, dependencies.Quota, dependencies.Dispatches); err != nil {
		return ErrStateDependenciesNotDurable
	}
	return nil
}

type nativeCounterUnavailable struct{ factory *NativeFactory }

func (*nativeCounterUnavailable) Count(context.Context, TokenCountRequest) (uint64, error) {
	return 0, ErrProviderUnavailable
}

type nativeModelUnavailableProvider struct {
	factory  *NativeFactory
	provider Provider
}

func (provider *nativeModelUnavailableProvider) Availability(ctx context.Context) (ProviderAvailability, error) {
	return provider.provider.Availability(ctx)
}
func (*nativeModelUnavailableProvider) Dispatch(context.Context, DispatchCommand) (ProviderDispatchResult, error) {
	return ProviderDispatchResult{}, ErrProviderUnavailable
}
func (*nativeModelUnavailableProvider) Cancel(context.Context, CancelCommand) (ProviderCancellation, error) {
	return ProviderCancellation{}, ErrProviderUnavailable
}
