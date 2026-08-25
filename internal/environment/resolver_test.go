package environment

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/hancomac/circulusd/internal/identity"
)

func TestResolverCombinesRequirementsIntoOneImmutableRevision(t *testing.T) {
	t.Parallel()
	minimal := validRevision(t, "A", []Package{{ID: "shell", Version: "1.0.0", Digest: testDigest('1')}}, BackendArtifacts{
		NsJail: &NsJailArtifact{RootfsDigest: testDigest('2')},
	})
	standard := validRevision(t, "B", []Package{
		{ID: "document-tools", Version: "3.4.1", Digest: testDigest('3')},
		{ID: "python-runtime", Version: "3.13.2", Digest: testDigest('4')},
		{ID: "shell", Version: "1.0.0", Digest: testDigest('1')},
	}, BackendArtifacts{
		NsJail: &NsJailArtifact{RootfsDigest: testDigest('5')},
		Docker: &DockerArtifact{ImageDigest: testDigest('6')},
	})
	resolver, err := NewResolver([]Revision{minimal, standard})
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}

	resolved, err := resolver.Resolve(Request{
		Architecture:     ArchitectureX8664,
		RequiredBackends: []Backend{BackendDocker, BackendNsJail},
		Requirements: []Requirement{
			{PackageID: "python-runtime", Constraint: ">=3.13.0 <4.0.0"},
			{PackageID: "document-tools", Constraint: "3.x"},
		},
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if resolved.ID != standard.ID || resolved.Digest != standard.Digest {
		t.Fatalf("Resolve() = %s/%s, want %s/%s", resolved.ID, resolved.Digest, standard.ID, standard.Digest)
	}

	// A caller cannot mutate the resolver's immutable registry through a result.
	resolved.Packages[0].Version = "99.0.0"
	resolved.Artifacts.Docker.ImageDigest = testDigest('f')
	again, err := resolver.Resolve(Request{
		Architecture:     ArchitectureX8664,
		RequiredBackends: []Backend{BackendDocker},
		Requirements:     []Requirement{{PackageID: "python-runtime", Constraint: "3.13.x"}},
	})
	if err != nil {
		t.Fatalf("Resolve(second) error = %v", err)
	}
	if again.Packages[1].Version != "3.13.2" || again.Artifacts.Docker.ImageDigest != testDigest('6') {
		t.Fatalf("resolver registry was mutated through returned revision: %#v", again)
	}
}

func TestResolverNeverFallsBackToAnotherBackendOrArchitecture(t *testing.T) {
	t.Parallel()
	revision := validRevision(t, "C", []Package{{ID: "python-runtime", Version: "3.13.2", Digest: testDigest('1')}}, BackendArtifacts{
		NsJail: &NsJailArtifact{RootfsDigest: testDigest('2')},
	})
	resolver, err := NewResolver([]Revision{revision})
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}

	for _, request := range []Request{
		{Architecture: ArchitectureX8664, RequiredBackends: []Backend{BackendDocker}, Requirements: []Requirement{{PackageID: "python-runtime", Constraint: ">=3.0.0"}}},
		{Architecture: ArchitectureAArch64, RequiredBackends: []Backend{BackendNsJail}, Requirements: []Requirement{{PackageID: "python-runtime", Constraint: ">=3.0.0"}}},
	} {
		if _, err := resolver.Resolve(request); !errors.Is(err, ErrNoEnvironment) {
			t.Fatalf("Resolve(%#v) error = %v, want ErrNoEnvironment", request, err)
		}
	}
}

func TestResolverRejectsConflictsAndInvalidConstraints(t *testing.T) {
	t.Parallel()
	revision := validRevision(t, "D", []Package{{ID: "python-runtime", Version: "3.13.2", Digest: testDigest('1')}}, BackendArtifacts{
		NsJail: &NsJailArtifact{RootfsDigest: testDigest('2')},
	})
	resolver, err := NewResolver([]Revision{revision})
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}

	_, err = resolver.Resolve(Request{
		Architecture:     ArchitectureX8664,
		RequiredBackends: []Backend{BackendNsJail},
		Requirements: []Requirement{
			{PackageID: "python-runtime", Constraint: ">=3.13.0"},
			{PackageID: "python-runtime", Constraint: "<3.0.0"},
		},
	})
	if !errors.Is(err, ErrNoEnvironment) {
		t.Fatalf("Resolve(conflict) error = %v, want ErrNoEnvironment", err)
	}

	for _, constraint := range []string{"", "latest", ">=3", "3.*", ">=3.0.0 || <2.0.0"} {
		_, err := resolver.Resolve(Request{
			Architecture:     ArchitectureX8664,
			RequiredBackends: []Backend{BackendNsJail},
			Requirements:     []Requirement{{PackageID: "python-runtime", Constraint: constraint}},
		})
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("Resolve(constraint %q) error = %v, want ErrInvalidRequest", constraint, err)
		}
	}
}

func TestResolverSelectionIsDeterministicAndUsesSmallestSuperset(t *testing.T) {
	t.Parallel()
	small := validRevision(t, "E", []Package{{ID: "python-runtime", Version: "3.13.2", Digest: testDigest('1')}}, BackendArtifacts{
		NsJail: &NsJailArtifact{RootfsDigest: testDigest('2')},
	})
	large := validRevision(t, "F", []Package{
		{ID: "browser", Version: "1.0.0", Digest: testDigest('3')},
		{ID: "python-runtime", Version: "3.13.2", Digest: testDigest('1')},
	}, BackendArtifacts{NsJail: &NsJailArtifact{RootfsDigest: testDigest('4')}})
	request := Request{
		Architecture:     ArchitectureX8664,
		RequiredBackends: []Backend{BackendNsJail, BackendNsJail},
		Requirements:     []Requirement{{PackageID: "python-runtime", Constraint: ">=3.13.0 <4.0.0"}},
	}

	for _, revisions := range [][]Revision{{large, small}, {small, large}} {
		resolver, err := NewResolver(revisions)
		if err != nil {
			t.Fatalf("NewResolver() error = %v", err)
		}
		resolved, err := resolver.Resolve(request)
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
		if resolved.ID != small.ID {
			t.Fatalf("Resolve() ID = %s, want smallest superset %s", resolved.ID, small.ID)
		}
	}
}

func TestResolverIsSafeForConcurrentResolution(t *testing.T) {
	t.Parallel()
	revision := validRevision(t, "I", []Package{{ID: "shell", Version: "1.0.0", Digest: testDigest('1')}}, BackendArtifacts{
		NsJail: &NsJailArtifact{RootfsDigest: testDigest('2')},
	})
	resolver, err := NewResolver([]Revision{revision})
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	request := Request{
		Architecture:     ArchitectureX8664,
		RequiredBackends: []Backend{BackendNsJail},
		Requirements:     []Requirement{{PackageID: "shell", Constraint: "1.x"}},
	}

	const workers = 64
	results := make(chan Revision, workers)
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			resolved, err := resolver.Resolve(request)
			results <- resolved
			errorsChannel <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
	}
	for result := range results {
		if result.ID != revision.ID || result.Digest != revision.Digest {
			t.Fatalf("concurrent Resolve() = %s/%s, want %s/%s", result.ID, result.Digest, revision.ID, revision.Digest)
		}
	}
}

func TestRegistryRejectsNonCanonicalOrDigestMismatchedRevisions(t *testing.T) {
	t.Parallel()
	valid := validRevision(t, "G", []Package{{ID: "shell", Version: "1.0.0", Digest: testDigest('1')}}, BackendArtifacts{
		NsJail: &NsJailArtifact{RootfsDigest: testDigest('2')},
	})

	tests := []struct {
		name   string
		mutate func(*Revision)
	}{
		{name: "digest mismatch", mutate: func(revision *Revision) { revision.Digest = testDigest('f') }},
		{name: "duplicate package", mutate: func(revision *Revision) { revision.Packages = append(revision.Packages, revision.Packages[0]) }},
		{name: "raw path artifact", mutate: func(revision *Revision) { revision.Artifacts.NsJail.RootfsDigest = "/srv/rootfs" }},
		{name: "wrong ID kind", mutate: func(revision *Revision) { revision.ID = mustEnvironmentID(t, identity.RuntimeRevision, "H") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			revision := cloneRevision(valid)
			test.mutate(&revision)
			if _, err := NewResolver([]Revision{revision}); !errors.Is(err, ErrInvalidRevision) {
				t.Fatalf("NewResolver() error = %v, want ErrInvalidRevision", err)
			}
		})
	}
}

func validRevision(t *testing.T, fill string, packages []Package, artifacts BackendArtifacts) Revision {
	t.Helper()
	revision := Revision{
		ID:                     mustEnvironmentID(t, identity.EnvironmentRevision, fill),
		Architecture:           ArchitectureX8664,
		Packages:               packages,
		SandboxdDigest:         testDigest('a'),
		SeccompProfileDigest:   testDigest('b'),
		FilesystemPolicyDigest: testDigest('c'),
		Artifacts:              artifacts,
	}
	digest, err := DigestRevision(revision)
	if err != nil {
		t.Fatalf("DigestRevision() error = %v", err)
	}
	revision.Digest = digest
	return revision
}

func mustEnvironmentID(t *testing.T, kind identity.Kind, fill string) identity.ID {
	t.Helper()
	id, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte(fill), 16))}).New(kind)
	if err != nil {
		t.Fatalf("New(environment ID) error = %v", err)
	}
	return id
}

func testDigest(fill byte) string {
	return "sha256:" + string(bytes.Repeat([]byte{fill}, 64))
}
