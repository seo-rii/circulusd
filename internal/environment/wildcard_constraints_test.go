package environment

import (
	"errors"
	"testing"
)

func TestResolverWildcardNumericBounds(t *testing.T) {
	for _, test := range []struct {
		name       string
		version    string
		constraint string
		invalid    bool
	}{
		{"major overflow", "18446744073709551615.1.0", "18446744073709551616.x", true},
		{"major overflow with minor", "18446744073709551615.1.0", "18446744073709551616.1.x", true},
		{"minor overflow", "1.18446744073709551615.0", "1.18446744073709551616.x", true},
		{"exact overflow", "18446744073709551615.1.0", "18446744073709551616.1.0", true},
		{"comparison overflow", "18446744073709551615.1.0", ">=18446744073709551616.0.0", true},
		{"maximum major", "18446744073709551615.1.0", "18446744073709551615.x", false},
		{"maximum minor", "1.18446744073709551615.0", "1.18446744073709551615.x", false},
		{"maximum major and minor", "18446744073709551615.18446744073709551615.0", "18446744073709551615.18446744073709551615.x", false},
		{"zero major", "0.0.1", "0.x", false},
		{"zero minor", "0.0.1", "0.0.x", false},
		{"ordinary major", "3.13.2", "3.x", false},
		{"ordinary minor", "3.13.2", "3.13.x", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			revision := validRevision(t, "Z", []Package{{ID: "python", Version: test.version, Digest: testDigest('1')}}, BackendArtifacts{
				NsJail: &NsJailArtifact{RootfsDigest: testDigest('2')},
			})
			resolver, err := NewResolver([]Revision{revision})
			if err != nil {
				t.Fatal(err)
			}
			result, err := resolver.Resolve(Request{
				Architecture: ArchitectureX8664, RequiredBackends: []Backend{BackendNsJail},
				Requirements: []Requirement{{PackageID: "python", Constraint: test.constraint}},
			})
			if test.invalid {
				if !errors.Is(err, ErrInvalidRequest) || result.ID.String() != "" {
					t.Fatalf("out-of-range constraint %q selected package version %q: result=%s err=%v", test.constraint, test.version, result.ID, err)
				}
			} else if err != nil || result.ID != revision.ID || result.Digest != revision.Digest {
				t.Fatalf("supported constraint %q did not select package version %q: result=%s err=%v", test.constraint, test.version, result.ID, err)
			}
		})
	}
}
