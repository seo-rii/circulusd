package sessionplan_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hancomac/circulusd/internal/environment"
	"github.com/hancomac/circulusd/internal/sessionplan"
)

func TestSignedWildcardRequirementsCannotSelectSaturatedVersions(t *testing.T) {
	for _, test := range []struct {
		name       string
		version    string
		constraint string
		invalid    bool
	}{
		{"major overflow", "18446744073709551615.1.0", "18446744073709551616.x", true},
		{"major overflow with minor", "18446744073709551615.1.0", "18446744073709551616.1.x", true},
		{"minor overflow", "1.18446744073709551615.0", "1.18446744073709551616.x", true},
		{"maximum major", "18446744073709551615.1.0", "18446744073709551615.x", false},
		{"maximum minor", "1.18446744073709551615.0", "1.18446744073709551615.x", false},
		{"ordinary", "3.13.2", "3.13.x", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			f.environment.Packages[0].Version = test.version
			f.redigest(t)
			f.records[0].Revision.NativeRequirements = []environment.Requirement{{PackageID: "python", Constraint: test.constraint}}
			f.sign(t, 0)
			planner, err := sessionplan.New(f.registry(t), f.policy)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := planner.Plan(context.Background(), f.request)
			if test.invalid {
				if !errors.Is(err, environment.ErrInvalidRequest) || plan.Validate() == nil {
					t.Fatalf("signed out-of-range requirement %q produced a usable plan: err=%v", test.constraint, err)
				}
				if _, err := plan.EnsureRequest(); !errors.Is(err, sessionplan.ErrInvalidPlan) {
					t.Fatalf("invalid plan produced an executor request: %v", err)
				}
			} else {
				if err != nil || plan.Validate() != nil || plan.Environment().Digest != f.environment.Digest ||
					plan.Environment().ID != f.environment.ID {
					t.Fatalf("supported signed requirement %q lost its curated environment: %v", test.constraint, err)
				}
				version := ""
				for _, item := range plan.Environment().Packages {
					if item.ID == "python" {
						version = item.Version
					}
				}
				if version != test.version {
					t.Fatalf("selected python version %q, want %q", version, test.version)
				}
			}
		})
	}
}
