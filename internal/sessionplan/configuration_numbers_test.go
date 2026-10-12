package sessionplan_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/environment"
	"github.com/hancomac/circulusd/internal/extensionregistry"
	"github.com/hancomac/circulusd/internal/sessionplan"
)

func numberConfigurationFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	schema := []byte(`{"type":"object","properties":{"scale":{"type":"number","minimum":0,"maximum":2},"nested":{"type":"object","properties":{"values":{"type":"array","items":{"type":"number"}}},"required":["values"],"additionalProperties":false}},"required":["scale"],"additionalProperties":false}`)
	f.records[0].Revision.ConfigurationSchema = schema
	f.records[0].Revision.ConfigurationSchemaDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(schema))
	f.sign(t, 0)
	return f
}

func compileConfiguration(t *testing.T, registry *extensionregistry.Registry, f *fixture) extensionregistry.RuntimeRevision {
	t.Helper()
	runtime, err := registry.CompileRuntime(extensionregistry.CompileRequest{
		Selections: f.request.Selections, Configuration: f.request.Configuration,
		Workerd: f.policy.Workerd, Pi: f.policy.Pi, Architecture: f.policy.Architecture,
		Backend: environment.BackendNsJail, PolicyGeneration: f.policy.PolicyGeneration,
		PolicyMinimumIsolation: f.policy.MinimumIsolation,
	})
	if err != nil {
		t.Fatalf("signed registry configuration: %v", err)
	}
	return runtime
}

func TestPlanPreservesSignedNumericConfiguration(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
	}{
		{"fraction", float64(0.5)},
		{"JSON integer", float64(1)},
		{"canonical integer", int64(1)},
		{"JSON number", json.Number("0.5")},
		{"float32", float32(0.5)},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := numberConfigurationFixture(t)
			f.request.Configuration["official/python"] = canonical.Map{"scale": test.value}
			registry := f.registry(t)
			want := compileConfiguration(t, registry, f)
			planner, err := sessionplan.New(registry, f.policy)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := planner.Plan(context.Background(), f.request)
			if err != nil {
				t.Fatalf("plan supported number %v (%T): %v", test.value, test.value, err)
			}
			if plan.Validate() != nil || plan.RuntimeRevision().Digest != want.Digest ||
				plan.RuntimeRevision().ConfigurationDigest != want.ConfigurationDigest {
				t.Fatal("plan changed the signed compiler's numeric configuration binding")
			}
			if test.value == float64(1) || test.value == int64(1) {
				legacy, err := canonical.StructuredDigest("circulusd.runtime.extension-configuration", 1, canonical.Map{
					"official/python": canonical.Map{"scale": int64(1)}, "official/report": canonical.Map{},
				})
				if err != nil || plan.RuntimeRevision().ConfigurationDigest != legacy {
					t.Fatalf("safe-integer v1 configuration digest changed: %v", err)
				}
			}
		})
	}
}

func TestPlanOwnsNumericConfigurationBeforeResolver(t *testing.T) {
	f := numberConfigurationFixture(t)
	values := []any{float64(0.25), float64(1)}
	nested := map[string]any{"values": values}
	f.request.Configuration["official/python"] = canonical.Map{"scale": float64(0.5), "nested": nested}
	want := compileConfiguration(t, f.registry(t), f)
	resolver, err := environment.NewResolver([]environment.Revision{f.environment})
	if err != nil {
		t.Fatal(err)
	}
	f.resolver = resolverFunc(func(request environment.Request) (environment.Revision, error) {
		values[0] = math.NaN()
		nested["values"] = []any{float64(9)}
		f.request.Configuration["official/python"] = canonical.Map{"scale": float64(99)}
		f.request.Selections[0].ID = "caller/mutated"
		return resolver.Resolve(request)
	})
	planner, err := sessionplan.New(f.registry(t), f.policy)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.Plan(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.RuntimeRevision().Digest != want.Digest || plan.RuntimeRevision().ConfigurationDigest != want.ConfigurationDigest {
		t.Fatal("resolver callback changed the normalized configuration snapshot")
	}
	f.request.Configuration["official/python"] = canonical.Map{"scale": float64(100)}
	if plan.Validate() != nil || plan.RuntimeRevision().ConfigurationDigest != want.ConfigurationDigest {
		t.Fatal("caller mutation changed the returned plan")
	}
}

func TestPlanRejectsInvalidNumericConfigurationBeforeResolver(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
	}{
		{"NaN", math.NaN()},
		{"infinity", math.Inf(1)},
		{"negative infinity", math.Inf(-1)},
		{"number overflow", json.Number("1e309")},
		{"unsafe integer", int64(9_007_199_254_740_992)},
		{"below schema minimum", float64(-0.5)},
		{"above schema maximum", float64(3)},
		{"wrong schema type", "0.5"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := numberConfigurationFixture(t)
			f.request.Configuration["official/python"] = canonical.Map{"scale": test.value}
			calls := 0
			f.resolver = resolverFunc(func(environment.Request) (environment.Revision, error) {
				calls++
				return f.environment, nil
			})
			planner, err := sessionplan.New(f.registry(t), f.policy)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := planner.Plan(context.Background(), f.request)
			if !errors.Is(err, extensionregistry.ErrInvalidRequest) || calls != 0 || plan.Validate() == nil {
				t.Fatalf("invalid config must fail before resolution: err=%v, calls=%d", err, calls)
			}
		})
	}
}
