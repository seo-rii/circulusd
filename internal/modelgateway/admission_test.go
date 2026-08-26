package modelgateway

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/hancomac/circulusd/internal/identity"
)

func TestAdmitChecksAuthorityAllowlistTokensQuotaAndAvailability(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)

	request := fixture.admissionRequest()
	effect, err := gateway.Admit(context.Background(), request)
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	if effect.State != StateAdmitted || effect.Revision != 1 || effect.Attempt != 0 {
		t.Fatalf("Admit() state = %#v", effect)
	}
	if effect.ContextTokens != 11 || effect.RequestedOutputTokens != 17 {
		t.Fatalf("Admit() token accounting = %d/%d", effect.ContextTokens, effect.RequestedOutputTokens)
	}
	if effect.Scope != fixture.scope || effect.ProviderID != "provider-a" {
		t.Fatalf("Admit() scope/provider = %#v/%q", effect.Scope, effect.ProviderID)
	}
	if fixture.authority.admissions != 1 || fixture.quota.calls != 1 || fixture.counter.calls != 1 || fixture.provider.availabilityCalls != 1 {
		t.Fatalf("hook calls authority/quota/counter/provider = %d/%d/%d/%d", fixture.authority.admissions, fixture.quota.calls, fixture.counter.calls, fixture.provider.availabilityCalls)
	}
	if fixture.quota.last.ContextTokens != 11 || fixture.quota.last.OutputTokens != 17 || fixture.quota.last.RequestDigest != request.RequestDigest {
		t.Fatalf("quota request = %#v", fixture.quota.last)
	}

	request.Request.Messages[0].Content = "mutated"
	if effect.Request.Messages[0].Content == "mutated" {
		t.Fatal("Admit() retained caller-owned message storage")
	}
}

func TestAdmitRejectsARequestBodyThatDoesNotMatchItsPreparedDigest(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	request := fixture.admissionRequest()
	request.Request.Messages[1].Content = "a different body under the same effect digest"

	if _, err := gateway.Admit(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Admit(mismatched digest) error = %v, want ErrInvalidRequest", err)
	}
	if fixture.authority.admissions != 0 || fixture.quota.calls != 0 {
		t.Fatalf("mismatched digest reached trusted hooks: authority=%d quota=%d", fixture.authority.admissions, fixture.quota.calls)
	}
}

func TestModelRequestDigestEnforcesHardInputCeilings(t *testing.T) {
	t.Parallel()
	request := ModelRequest{
		Model:           strings.Repeat("m", hardMaxIdentifierBytes+1),
		Messages:        []Message{{Role: RoleUser, Content: "bounded"}},
		MaxOutputTokens: 1,
	}
	if _, err := ModelRequestDigest(request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("ModelRequestDigest(oversized model) error = %v, want ErrInvalidRequest", err)
	}
}

func TestModelRequestDigestNormalizesProviderNeutralReasoningOptions(t *testing.T) {
	t.Parallel()
	request := ModelRequest{
		Model:           "model-a",
		Messages:        []Message{{Role: RoleUser, Content: "reason carefully"}},
		MaxOutputTokens: 16,
	}
	implicit, err := ModelRequestDigest(request)
	if err != nil {
		t.Fatalf("ModelRequestDigest(implicit) error = %v", err)
	}
	request.Reasoning = ReasoningOptions{Effort: ReasoningEffortDefault}
	explicit, err := ModelRequestDigest(request)
	if err != nil {
		t.Fatalf("ModelRequestDigest(explicit default) error = %v", err)
	}
	if implicit != explicit {
		t.Fatalf("implicit and explicit default reasoning digests differ: %x != %x", implicit, explicit)
	}

	request.Reasoning.Effort = ReasoningEffortHigh
	high, err := ModelRequestDigest(request)
	if err != nil {
		t.Fatalf("ModelRequestDigest(high) error = %v", err)
	}
	if high == explicit {
		t.Fatal("reasoning effort was omitted from the canonical request digest")
	}

	request.Reasoning.Effort = ReasoningEffort("HIGH")
	if _, err := ModelRequestDigest(request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("ModelRequestDigest(non-canonical reasoning) error = %v, want ErrInvalidRequest", err)
	}
}

func TestAdmitStoresAndDispatchesNormalizedReasoningOptions(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	if effect.Request.Reasoning.Effort != ReasoningEffortDefault {
		t.Fatalf("Admit() reasoning = %#v, want normalized default", effect.Request.Reasoning)
	}
	transition := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	if transition.Dispatch == nil || transition.Dispatch.Request.Reasoning != effect.Request.Reasoning {
		t.Fatalf("dispatch reasoning = %#v, admitted = %#v", transition.Dispatch, effect.Request.Reasoning)
	}
}

func TestRestoredEffectRejectsAReasoningAliasInsteadOfCanonicalizingDurableState(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect.Request.Reasoning = ReasoningOptions{}

	_, err := gateway.Apply(effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Apply(non-normalized restored reasoning) error = %v, want ErrInvalidRequest", err)
	}
}

func TestAdmitRejectsWrongTenantUserOrModel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*fixture)
	}{
		{name: "tenant", mutate: func(f *fixture) { f.authority.scope.TenantID = mustID(t, identity.Tenant, 'x') }},
		{name: "user", mutate: func(f *fixture) { f.authority.scope.UserID = mustID(t, identity.Subject, 'x') }},
		{name: "model", mutate: func(f *fixture) { f.request.Model = "not-allowed" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newFixture(t)
			test.mutate(fixture)
			if digest, digestErr := ModelRequestDigest(fixture.request); digestErr == nil {
				fixture.requestDigest = digest
			}
			gateway := fixture.gateway(t)
			_, err := gateway.Admit(context.Background(), fixture.admissionRequest())
			if !errors.Is(err, ErrModelNotAllowed) {
				t.Fatalf("Admit() error = %v, want ErrModelNotAllowed", err)
			}
			if fixture.quota.calls != 0 {
				t.Fatalf("quota calls = %d, want 0", fixture.quota.calls)
			}
		})
	}
}

func TestAdmitRejectsContextAndOutputLimitsBeforeQuota(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*fixture, *AdmissionRequest)
	}{
		{name: "context", mutate: func(f *fixture, _ *AdmissionRequest) { f.counter.tokens = 41 }},
		{name: "output", mutate: func(_ *fixture, r *AdmissionRequest) { r.Request.MaxOutputTokens = 31 }},
		{name: "total", mutate: func(f *fixture, r *AdmissionRequest) { f.counter.tokens = 35; r.Request.MaxOutputTokens = 16 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newFixture(t)
			gateway := fixture.gateway(t)
			request := fixture.admissionRequest()
			test.mutate(fixture, &request)
			if digest, digestErr := ModelRequestDigest(request.Request); digestErr == nil {
				request.RequestDigest = digest
			}
			_, err := gateway.Admit(context.Background(), request)
			if !errors.Is(err, ErrTokenLimit) {
				t.Fatalf("Admit() error = %v, want ErrTokenLimit", err)
			}
			if fixture.quota.calls != 0 {
				t.Fatalf("quota calls = %d, want 0", fixture.quota.calls)
			}
		})
	}
}

func TestAdmitFailsClosedBeforeQuotaWhenProviderUnavailable(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.provider.availability = ProviderAvailability{Available: false, Reason: "offline endpoint not installed"}
	gateway := fixture.gateway(t)

	_, err := gateway.Admit(context.Background(), fixture.admissionRequest())
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("Admit() error = %v, want ErrProviderUnavailable", err)
	}
	if fixture.quota.calls != 0 {
		t.Fatalf("quota calls = %d, want 0", fixture.quota.calls)
	}
}

func TestAdmitNeverReflectsProviderAvailabilityDetails(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	const providerSecret = "tenant-specific-endpoint-secret"
	fixture.provider.availability = ProviderAvailability{Available: false, Reason: providerSecret}
	gateway := fixture.gateway(t)

	_, err := gateway.Admit(context.Background(), fixture.admissionRequest())
	if !errors.Is(err, ErrProviderUnavailable) || err.Error() != ErrProviderUnavailable.Error() {
		t.Fatalf("Admit() error = %q, want fixed ErrProviderUnavailable", err)
	}
	if strings.Contains(err.Error(), providerSecret) {
		t.Fatalf("Admit() reflected provider availability details: %v", err)
	}
}

func TestAdmitDoesNotReflectAnUnboundedProviderAvailabilityReason(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	untrustedReason := strings.Repeat("x", int(fixture.bounds.MaxReasonBytes+1))
	fixture.provider.availability = ProviderAvailability{Available: false, Reason: untrustedReason}
	gateway := fixture.gateway(t)

	_, err := gateway.Admit(context.Background(), fixture.admissionRequest())
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("Admit() error = %v, want ErrProviderUnavailable", err)
	}
	if strings.Contains(err.Error(), untrustedReason) {
		t.Fatalf("Admit() reflected an unbounded provider reason: %v", err)
	}
}

func TestAdmitRejectsAnAdvertisedDurableRetrievalCapabilityWithoutItsInterface(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.provider.availability.DurableRequestRetrieval = true
	dependencies := fixture.dependencies()
	dependencies.Providers = map[string]Provider{"provider-a": providerWithoutRetrieval{Provider: fixture.provider}}
	gateway, err := NewGateway(fixture.configuration(), dependencies)
	if err != nil {
		t.Fatalf("NewGateway() error = %v", err)
	}

	if _, err := gateway.Admit(context.Background(), fixture.admissionRequest()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("Admit(unimplemented durable retrieval) error = %v, want ErrProviderUnavailable", err)
	}
	if fixture.quota.calls != 0 {
		t.Fatalf("quota calls = %d, want 0", fixture.quota.calls)
	}
}

type providerWithoutRetrieval struct{ Provider }

func TestAdmitFailsClosedOnAuthorityOrQuotaMismatch(t *testing.T) {
	t.Parallel()
	t.Run("authority rejection", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.authority.admissionErr = ErrStaleAuthority
		gateway := fixture.gateway(t)
		_, err := gateway.Admit(context.Background(), fixture.admissionRequest())
		if !errors.Is(err, ErrStaleAuthority) || fixture.counter.calls != 0 || fixture.quota.calls != 0 {
			t.Fatalf("Admit() error/hooks = %v/%d/%d", err, fixture.counter.calls, fixture.quota.calls)
		}
	})
	t.Run("authority proof mismatch", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.authority.scope.EffectID = mustID(t, identity.Effect, 'z')
		gateway := fixture.gateway(t)
		_, err := gateway.Admit(context.Background(), fixture.admissionRequest())
		if !errors.Is(err, ErrAuthorityMismatch) {
			t.Fatalf("Admit() error = %v, want ErrAuthorityMismatch", err)
		}
	})
	t.Run("quota rejection", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.quota.err = ErrQuotaExceeded
		gateway := fixture.gateway(t)
		_, err := gateway.Admit(context.Background(), fixture.admissionRequest())
		if !errors.Is(err, ErrQuotaExceeded) {
			t.Fatalf("Admit() error = %v, want ErrQuotaExceeded", err)
		}
	})
	t.Run("quota permit mismatch", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.quota.mutate = func(permit *QuotaPermit) { permit.OutputTokens++ }
		gateway := fixture.gateway(t)
		_, err := gateway.Admit(context.Background(), fixture.admissionRequest())
		if !errors.Is(err, ErrQuotaMismatch) {
			t.Fatalf("Admit() error = %v, want ErrQuotaMismatch", err)
		}
	})
	t.Run("invalid quota reservation identifier", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.quota.mutate = func(permit *QuotaPermit) { permit.ReservationID = "reservation\nid" }
		gateway := fixture.gateway(t)
		_, err := gateway.Admit(context.Background(), fixture.admissionRequest())
		if !errors.Is(err, ErrQuotaMismatch) {
			t.Fatalf("Admit() error = %v, want ErrQuotaMismatch", err)
		}
	})
	t.Run("non-durable quota reservation", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.quota.mutate = func(permit *QuotaPermit) { permit.Durable = false }
		gateway := fixture.gateway(t)
		_, err := gateway.Admit(context.Background(), fixture.admissionRequest())
		if !errors.Is(err, ErrQuotaMismatch) {
			t.Fatalf("Admit() error = %v, want ErrQuotaMismatch", err)
		}
	})
}

func TestAdmitBoundsInputBeforeCallingTrustedHooks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*AdmissionRequest)
	}{
		{name: "empty authority", mutate: func(r *AdmissionRequest) { r.Authority = nil }},
		{name: "zero digest", mutate: func(r *AdmissionRequest) { r.RequestDigest = Digest{} }},
		{name: "too many messages", mutate: func(r *AdmissionRequest) {
			r.Request.Messages = append(r.Request.Messages, r.Request.Messages...)
			r.Request.Messages = append(r.Request.Messages, Message{Role: RoleUser, Content: "overflow"})
		}},
		{name: "oversized message", mutate: func(r *AdmissionRequest) { r.Request.Messages[0].Content = string(bytes.Repeat([]byte("x"), 65)) }},
		{name: "invalid utf8", mutate: func(r *AdmissionRequest) { r.Request.Messages[0].Content = string([]byte{0xff}) }},
		{name: "invalid role", mutate: func(r *AdmissionRequest) { r.Request.Messages[0].Role = Role("operator") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newFixture(t)
			gateway := fixture.gateway(t)
			request := fixture.admissionRequest()
			test.mutate(&request)
			_, err := gateway.Admit(context.Background(), request)
			if !errors.Is(err, ErrInvalidRequest) && !errors.Is(err, ErrInputLimit) {
				t.Fatalf("Admit() error = %v, want bounded input rejection", err)
			}
			if fixture.authority.admissions != 0 || fixture.counter.calls != 0 || fixture.quota.calls != 0 {
				t.Fatalf("trusted hooks called for invalid input: %d/%d/%d", fixture.authority.admissions, fixture.counter.calls, fixture.quota.calls)
			}
		})
	}
}

func TestGatewayIsImmutableAndSafeForConcurrentAdmission(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.authority.concurrent = true
	fixture.counter.concurrent = true
	fixture.quota.concurrent = true
	fixture.provider.concurrent = true
	gateway := fixture.gateway(t)

	const workers = 64
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := gateway.Admit(context.Background(), fixture.admissionRequest())
			errorsChannel <- err
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("Admit() error = %v", err)
		}
	}
	if fixture.quota.reservations != 1 {
		t.Fatalf("durable quota reservations = %d, want 1", fixture.quota.reservations)
	}
}
