package modelgateway

import (
	"context"
	"errors"
	"testing"
)

func TestUnavailableProviderFailsClosed(t *testing.T) {
	t.Parallel()
	provider, err := NewUnavailableProvider("provider binary is absent")
	if err != nil {
		t.Fatalf("NewUnavailableProvider() error = %v", err)
	}
	availability, err := provider.Availability(context.Background())
	if err != nil {
		t.Fatalf("Availability() error = %v", err)
	}
	if availability.Available || availability.Reason != "provider binary is absent" {
		t.Fatalf("Availability() = %#v", availability)
	}
	if _, err := provider.Dispatch(context.Background(), DispatchCommand{}); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("Dispatch() error = %v, want ErrProviderUnavailable", err)
	}
	if _, err := provider.Cancel(context.Background(), CancelCommand{}); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("Cancel() error = %v, want ErrProviderUnavailable", err)
	}
}

func TestUnavailableProviderRejectsAnUnsafeReason(t *testing.T) {
	t.Parallel()
	if _, err := NewUnavailableProvider("offline\nAuthorization: secret"); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("NewUnavailableProvider(control reason) error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestGatewayRequiresEveryTrustedDependency(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	configuration := fixture.configuration()
	dependencies := fixture.dependencies()

	tests := []struct {
		name   string
		mutate func(*Dependencies)
	}{
		{name: "authority", mutate: func(d *Dependencies) { d.Authority = nil }},
		{name: "token counter", mutate: func(d *Dependencies) { d.TokenCounter = nil }},
		{name: "quota", mutate: func(d *Dependencies) { d.Quota = nil }},
		{name: "dispatch coordinator", mutate: func(d *Dependencies) { d.Dispatches = nil }},
		{name: "provider", mutate: func(d *Dependencies) { d.Providers = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copy := dependencies
			test.mutate(&copy)
			if _, err := NewGateway(configuration, copy); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("NewGateway() error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}
}

func TestGatewayRejectsATypedNilProvider(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	dependencies := fixture.dependencies()
	var provider *fakeProvider
	dependencies.Providers = map[string]Provider{"provider-a": provider}

	if _, err := NewGateway(fixture.configuration(), dependencies); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("NewGateway(typed nil provider) error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestGatewayRejectsTypedNilTrustedDependencies(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	tests := []struct {
		name   string
		mutate func(*Dependencies)
	}{
		{name: "authority", mutate: func(dependencies *Dependencies) {
			var dependency *fakeAuthority
			dependencies.Authority = dependency
		}},
		{name: "token counter", mutate: func(dependencies *Dependencies) {
			var dependency *fakeTokenCounter
			dependencies.TokenCounter = dependency
		}},
		{name: "quota", mutate: func(dependencies *Dependencies) {
			var dependency *fakeQuota
			dependencies.Quota = dependency
		}},
		{name: "dispatch coordinator", mutate: func(dependencies *Dependencies) {
			var dependency *fakeDispatchCoordinator
			dependencies.Dispatches = dependency
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := fixture.dependencies()
			test.mutate(&dependencies)
			if _, err := NewGateway(fixture.configuration(), dependencies); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("NewGateway(typed nil %s) error = %v, want ErrInvalidConfiguration", test.name, err)
			}
		})
	}
}

func TestGatewayRejectsReferenceMemoryStateDependenciesWithoutAnExplicitGate(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	configuration := fixture.configuration()
	configuration.AllowReferenceMemory = false

	_, err := NewGateway(configuration, fixture.dependencies())
	if !errors.Is(err, ErrStateDependenciesNotDurable) {
		t.Fatalf("NewGateway(reference memory) error = %v, want ErrStateDependenciesNotDurable", err)
	}

	configuration.AllowReferenceMemory = true
	if _, err := NewGateway(configuration, fixture.dependencies()); err != nil {
		t.Fatalf("NewGateway(explicit reference memory) error = %v", err)
	}
}

func TestGatewayAcceptsCrashDurableAtomicStateDependenciesInProduction(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	configuration := fixture.configuration()
	configuration.AllowReferenceMemory = false
	dependencies := fixture.dependencies()
	dependencies.Authority = crashDurableAuthority{AuthorityValidator: dependencies.Authority}
	dependencies.Quota = crashDurableQuota{QuotaAdmitter: dependencies.Quota}
	dependencies.Dispatches = crashDurableDispatchCoordinator{DispatchCoordinator: dependencies.Dispatches}

	if _, err := NewGateway(configuration, dependencies); err != nil {
		t.Fatalf("NewGateway(crash durable dependencies) error = %v", err)
	}
}

func TestGatewayRejectsAnIncompleteDurabilityCapabilityEvenInReferenceMode(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	dependencies := fixture.dependencies()
	dependencies.Quota = incompleteReferenceQuota{QuotaAdmitter: dependencies.Quota}

	_, err := NewGateway(fixture.configuration(), dependencies)
	if !errors.Is(err, ErrStateDependenciesNotDurable) {
		t.Fatalf("NewGateway(incomplete reference capability) error = %v, want ErrStateDependenciesNotDurable", err)
	}
}

func TestGatewayRejectsAReferenceAuthorityInProduction(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	configuration := fixture.configuration()
	configuration.AllowReferenceMemory = false
	dependencies := fixture.dependencies()
	dependencies.Quota = crashDurableQuota{QuotaAdmitter: dependencies.Quota}
	dependencies.Dispatches = crashDurableDispatchCoordinator{DispatchCoordinator: dependencies.Dispatches}
	dependencies.Authority = referenceDurabilityAuthority{AuthorityValidator: dependencies.Authority}

	if _, err := NewGateway(configuration, dependencies); !errors.Is(err, ErrStateDependenciesNotDurable) {
		t.Fatalf("NewGateway(reference authority in production) error = %v, want ErrStateDependenciesNotDurable", err)
	}

	dependencies.Authority = crashDurableAuthority{AuthorityValidator: dependencies.Authority}
	if _, err := NewGateway(configuration, dependencies); err != nil {
		t.Fatalf("NewGateway(crash-durable authority) error = %v", err)
	}
}

type crashDurableQuota struct{ QuotaAdmitter }

type referenceDurabilityAuthority struct{ AuthorityValidator }

func (referenceDurabilityAuthority) Durability() AuthorityDurability {
	return AuthorityDurability{CurrentGenerationFencing: true, ReferenceMemory: true}
}

type crashDurableAuthority struct{ AuthorityValidator }

func (crashDurableAuthority) Durability() AuthorityDurability {
	return AuthorityDurability{CrashDurable: true, CurrentGenerationFencing: true}
}

func (crashDurableQuota) Durability() QuotaDurability {
	return QuotaDurability{CrashDurable: true, AtomicReservationSettlement: true}
}

type crashDurableDispatchCoordinator struct{ DispatchCoordinator }

func (crashDurableDispatchCoordinator) Durability() DispatchDurability {
	return DispatchDurability{CrashDurable: true, AtomicEffectTransitions: true, ExclusiveDispatchClaim: true}
}

type incompleteReferenceQuota struct{ QuotaAdmitter }

func (incompleteReferenceQuota) Durability() QuotaDurability {
	return QuotaDurability{ReferenceMemory: true}
}

func TestProviderDispatchErrorDoesNotFormatItsUnderlyingTransportDetails(t *testing.T) {
	t.Parallel()
	cause := errors.New("Authorization: secret-provider-key")
	failure, err := NewProviderDispatchError(DispatchFailureUnknown, "provider acknowledgement missing", cause)
	if err != nil {
		t.Fatalf("NewProviderDispatchError() error = %v", err)
	}
	if got := failure.Error(); got != "provider acknowledgement missing" {
		t.Fatalf("ProviderDispatchError.Error() = %q", got)
	}
	if !errors.Is(failure, cause) {
		t.Fatal("ProviderDispatchError did not preserve its cause for programmatic inspection")
	}
}
