package extensionregistry

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/environment"
	"github.com/hancomac/circulusd/internal/identity"
)

func TestRegistryVerifiesSignedRecordsAndCompilesDeterministicRuntime(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registry := fixture.registry(t, []SignedRevision{fixture.python, fixture.pdf})

	first, err := registry.CompileRuntime(CompileRequest{
		Selections: []Selection{{ID: "official/pdf", Version: "1.4.2"}, {ID: "official/python", Version: "2.0.0"}},
		Configuration: canonical.Map{
			"official/python": canonical.Map{"interpreter": "python3"},
			"official/pdf":    canonical.Map{"outputFormat": "pdf"},
		},
		Workerd: WorkerdRevision{
			BinaryDigest:      testDigest('1'),
			CompatibilityDate: "2026-08-01",
			CompatibilityFlags: []string{
				"nodejs_compat",
			},
			LoaderABIVersion: 1,
		},
		Pi:               PiRevision{PackageDigest: testDigest('2'), AdapterABIVersion: 1, AgentEngine: "low-level"},
		Architecture:     environment.ArchitectureX8664,
		Backend:          environment.BackendNsJail,
		PolicyGeneration: 17,
		PolicyMinimumIsolation: Isolation{
			ProcessScope:   ProcessScopeShared,
			OuterIsolation: OuterIsolationNone,
		},
	})
	if err != nil {
		t.Fatalf("CompileRuntime() error = %v", err)
	}
	second, err := registry.CompileRuntime(CompileRequest{
		Selections: []Selection{{ID: "official/python", Version: "2.0.0"}, {ID: "official/pdf", Version: "1.4.2"}},
		Configuration: canonical.Map{
			"official/pdf":    canonical.Map{"outputFormat": "pdf"},
			"official/python": canonical.Map{"interpreter": "python3"},
		},
		Workerd: WorkerdRevision{
			BinaryDigest:       testDigest('1'),
			CompatibilityDate:  "2026-08-01",
			CompatibilityFlags: []string{"nodejs_compat"},
			LoaderABIVersion:   1,
		},
		Pi:               PiRevision{PackageDigest: testDigest('2'), AdapterABIVersion: 1, AgentEngine: "low-level"},
		Architecture:     environment.ArchitectureX8664,
		Backend:          environment.BackendNsJail,
		PolicyGeneration: 17,
		PolicyMinimumIsolation: Isolation{
			ProcessScope:   ProcessScopeShared,
			OuterIsolation: OuterIsolationNone,
		},
	})
	if err != nil {
		t.Fatalf("CompileRuntime(shuffled) error = %v", err)
	}

	if first.Digest != second.Digest || first.AgentBundleDigest != second.AgentBundleDigest || first.ConfigurationDigest != second.ConfigurationDigest {
		t.Fatalf("runtime compilation is order-dependent:\nfirst  = %#v\nsecond = %#v", first, second)
	}
	if len(first.Extensions) != 2 || first.Extensions[0].ID != "official/pdf" || first.Extensions[1].ID != "official/python" {
		t.Fatalf("Extensions = %#v, want canonical ID order", first.Extensions)
	}
	if len(first.HookOrder) != 2 || first.HookOrder[0] != "official/python" || first.HookOrder[1] != "official/pdf" {
		t.Fatalf("HookOrder = %#v, want priority then ID order", first.HookOrder)
	}
	if first.Environment.Digest != fixture.environment.Digest {
		t.Fatalf("Environment.Digest = %q, want %q", first.Environment.Digest, fixture.environment.Digest)
	}
	if first.MinimumIsolation != (Isolation{ProcessScope: ProcessScopeTenant, OuterIsolation: OuterIsolationNsJail}) {
		t.Fatalf("MinimumIsolation = %#v, want strongest signed/manifest requirement", first.MinimumIsolation)
	}
	if first.Digest == "" || first.AgentBundleDigest == "" || first.ConfigurationDigest == "" || first.EnvironmentRequirementDigest == "" {
		t.Fatalf("compiled runtime has an empty digest: %#v", first)
	}

	// Returned values are detached snapshots and cannot mutate registry authority.
	first.Extensions[0].Version = "99.0.0"
	first.HookOrder[0] = "forged/extension"
	first.Environment.Packages[0].Version = "99.0.0"
	again, err := registry.CompileRuntime(CompileRequest{
		Selections: []Selection{{ID: "official/pdf", Version: "1.4.2"}, {ID: "official/python", Version: "2.0.0"}},
		Configuration: canonical.Map{
			"official/pdf":    canonical.Map{"outputFormat": "pdf"},
			"official/python": canonical.Map{"interpreter": "python3"},
		},
		Workerd:          WorkerdRevision{BinaryDigest: testDigest('1'), CompatibilityDate: "2026-08-01", CompatibilityFlags: []string{"nodejs_compat"}, LoaderABIVersion: 1},
		Pi:               PiRevision{PackageDigest: testDigest('2'), AdapterABIVersion: 1, AgentEngine: "low-level"},
		Architecture:     environment.ArchitectureX8664,
		Backend:          environment.BackendNsJail,
		PolicyGeneration: 17,
		PolicyMinimumIsolation: Isolation{
			ProcessScope: ProcessScopeShared, OuterIsolation: OuterIsolationNone,
		},
	})
	if err != nil {
		t.Fatalf("CompileRuntime(after mutation) error = %v", err)
	}
	if again.Digest != second.Digest || again.Extensions[0].Version != "1.4.2" || again.HookOrder[0] != "official/python" {
		t.Fatalf("caller mutation escaped into registry: %#v", again)
	}
}

func TestRegistryRejectsInvalidSignaturesAndImmutableCoordinateConflicts(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)

	tests := []struct {
		name   string
		mutate func(*SignedRevision)
		want   error
	}{
		{name: "tampered revision", mutate: func(record *SignedRevision) { record.Revision.Priority++ }, want: ErrUntrusted},
		{name: "tampered bundle signature", mutate: func(record *SignedRevision) { record.BundleSignature.Value[0] ^= 0xff }, want: ErrUntrusted},
		{name: "unknown publisher key", mutate: func(record *SignedRevision) { record.BundleSignature.KeyID = "publisher-missing" }, want: ErrUntrusted},
		{name: "publisher signer identity substitution", mutate: func(record *SignedRevision) { record.BundleSignature.KeyID = "publisher-platform-alias" }, want: ErrUntrusted},
		{name: "assessment targets another digest", mutate: func(record *SignedRevision) { record.Assessment.ExtensionDigest = testDigest('f') }, want: ErrInvalidRecord},
		{name: "tampered assessment", mutate: func(record *SignedRevision) { record.Assessment.TrustClass = TrustClassUnreviewed }, want: ErrUntrusted},
		{name: "unknown assessor key", mutate: func(record *SignedRevision) { record.Assessment.Signature.KeyID = "assessor-missing" }, want: ErrUntrusted},
		{name: "assessor identity substitution", mutate: func(record *SignedRevision) { record.Assessment.Signature.KeyID = "platform-security-alias" }, want: ErrUntrusted},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := cloneSignedRevision(fixture.pdf)
			test.mutate(&record)
			_, err := New(fixture.roots, []SignedRevision{record}, fixture.resolver)
			if !errors.Is(err, test.want) {
				t.Fatalf("New() error = %v, want %v", err, test.want)
			}
		})
	}

	conflict := cloneSignedRevision(fixture.pdf)
	conflict.Revision.RevisionDigest = testDigest('e')
	conflict = fixture.signRecord(t, conflict.Revision, conflict.Assessment)
	if _, err := New(fixture.roots, []SignedRevision{fixture.pdf, conflict}, fixture.resolver); !errors.Is(err, ErrConflict) {
		t.Fatalf("New(coordinate conflict) error = %v, want ErrConflict", err)
	}
	if _, err := New(fixture.roots, []SignedRevision{fixture.pdf, cloneSignedRevision(fixture.pdf)}, fixture.resolver); !errors.Is(err, ErrConflict) {
		t.Fatalf("New(duplicate record) error = %v, want ErrConflict", err)
	}
}

func TestSignedThirdPartyAssessmentAcceptsEitherSharedKernelBoundaryButNeverNone(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	docker := cloneSignedRevision(fixture.pdf)
	docker.Assessment.TrustClass = TrustClassSignedThirdParty
	docker.Assessment.MinimumIsolation = Isolation{ProcessScope: ProcessScopeTenant, OuterIsolation: OuterIsolationDocker}
	docker.Assessment.AllowedExecutionBackends = []environment.Backend{environment.BackendDocker}
	docker = fixture.signRecord(t, docker.Revision, docker.Assessment)
	if _, err := New(fixture.roots, []SignedRevision{docker}, fixture.resolver); err != nil {
		t.Fatalf("New(signed third party with Docker boundary) error = %v", err)
	}

	weak := cloneSignedRevision(docker)
	weak.Assessment.MinimumIsolation.OuterIsolation = OuterIsolationNone
	weak = fixture.signRecord(t, weak.Revision, weak.Assessment)
	if _, err := New(fixture.roots, []SignedRevision{weak}, fixture.resolver); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("New(signed third party without outer boundary) error = %v, want ErrInvalidRecord", err)
	}
}

func TestRegistryRejectsSignedRecordsWithoutAUsableAssessedBackend(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	tests := []struct {
		name   string
		mutate func(*SignedRevision)
	}{
		{
			name: "manifest and assessment backend sets are disjoint",
			mutate: func(record *SignedRevision) {
				record.Revision.SupportedBackends = []environment.Backend{environment.BackendDocker}
				record.Assessment.AllowedExecutionBackends = []environment.Backend{environment.BackendNsJail}
			},
		},
		{
			name: "common backend is weaker than final minimum isolation",
			mutate: func(record *SignedRevision) {
				record.Revision.RequestedMinimumIsolation = Isolation{
					ProcessScope: ProcessScopeSession, OuterIsolation: OuterIsolationFirecracker,
				}
				record.Revision.SupportedBackends = []environment.Backend{environment.BackendNsJail}
				record.Assessment.AllowedExecutionBackends = []environment.Backend{environment.BackendNsJail}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := cloneSignedRevision(fixture.pdf)
			test.mutate(&record)
			record = fixture.signRecord(t, record.Revision, record.Assessment)
			if _, err := New(fixture.roots, []SignedRevision{record}, fixture.resolver); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("New(unusable backend) error = %v, want ErrInvalidRecord", err)
			}
		})
	}
}

func TestRegistryRejectsTypedNilEnvironmentResolver(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	var resolver *staticResolver
	if _, err := New(fixture.roots, []SignedRevision{fixture.pdf}, resolver); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("New(typed nil resolver) error = %v, want ErrInvalidRecord", err)
	}
}

func TestRegistryRejectsAnOversizedBundleBeforeSigning(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	record := cloneSignedRevision(fixture.pdf)
	record.Revision.BundleSize = 8<<20 + 1
	if _, err := BundleSignatureDigest(record.Revision, "publisher-platform-1"); err == nil {
		t.Fatal("BundleSignatureDigest(oversized bundle) error = nil")
	}
}

func TestRuntimeCompilerNormalizesStableManifestRangesForTheCuratedResolver(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	for _, constraint := range []string{"^3.13.0", "~3.13.0"} {
		t.Run(constraint, func(t *testing.T) {
			record := cloneSignedRevision(fixture.python)
			record.Revision.NativeRequirements[0].Constraint = constraint
			record.Revision.RevisionDigest = testDigest('f')
			record = fixture.signRecord(t, record.Revision, record.Assessment)
			registry := fixture.registry(t, []SignedRevision{record})
			request := fixture.compileRequest()
			request.Selections = []Selection{{ID: "official/python", Version: "2.0.0"}}
			request.Configuration = canonical.Map{"official/python": canonical.Map{}}
			if _, err := registry.CompileRuntime(request); err != nil {
				t.Fatalf("CompileRuntime(%q) error = %v", constraint, err)
			}
		})
	}
}

func TestRuntimeCompilerRevalidatesTheEnvironmentResolverOutput(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	forged := fixture.environment
	forged.Digest = testDigest('f')
	registry, err := New(fixture.roots, []SignedRevision{fixture.pdf, fixture.python}, staticResolver{revision: forged})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := registry.CompileRuntime(fixture.compileRequest()); !errors.Is(err, environment.ErrInvalidRevision) {
		t.Fatalf("CompileRuntime(forged environment) error = %v, want environment.ErrInvalidRevision", err)
	}
}

func TestRuntimeCompilationRejectsSelectionToolEnvironmentAndIsolationConflicts(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)

	colliding := cloneSignedRevision(fixture.python)
	colliding.Revision.ID = "official/colliding"
	colliding.Revision.Version = "1.0.0"
	colliding.Revision.Tools = []string{"pdf.render"}
	colliding.Revision.RevisionDigest = testDigest('9')
	colliding.Assessment.ExtensionDigest = colliding.Revision.ContentDigest
	colliding = fixture.signRecord(t, colliding.Revision, colliding.Assessment)
	registry := fixture.registry(t, []SignedRevision{fixture.pdf, fixture.python, colliding})

	base := fixture.compileRequest()
	tests := []struct {
		name   string
		mutate func(*CompileRequest)
		want   error
	}{
		{name: "missing selection", mutate: func(request *CompileRequest) { request.Selections[0].Version = "9.9.9" }, want: ErrNotFound},
		{name: "duplicate selection", mutate: func(request *CompileRequest) { request.Selections = append(request.Selections, request.Selections[0]) }, want: ErrInvalidRequest},
		{name: "missing configuration snapshot", mutate: func(request *CompileRequest) { delete(request.Configuration, "official/pdf") }, want: ErrInvalidRequest},
		{name: "unknown configuration", mutate: func(request *CompileRequest) { request.Configuration["evil/unknown"] = canonical.Map{} }, want: ErrInvalidRequest},
		{name: "backend denied by assessment", mutate: func(request *CompileRequest) { request.Backend = environment.BackendDocker }, want: ErrNoCompatibleBackend},
		{name: "backend weaker than policy", mutate: func(request *CompileRequest) {
			request.PolicyMinimumIsolation.OuterIsolation = OuterIsolationFirecracker
		}, want: ErrNoCompatibleBackend},
		{name: "environment package conflict", mutate: func(request *CompileRequest) {
			request.Selections = []Selection{{ID: "official/pdf", Version: "1.4.2"}}
			request.Configuration = canonical.Map{"official/pdf": canonical.Map{}}
			request.Architecture = environment.ArchitectureAArch64
		}, want: environment.ErrNoEnvironment},
		{name: "tool collision", mutate: func(request *CompileRequest) {
			request.Selections = []Selection{{ID: "official/pdf", Version: "1.4.2"}, {ID: "official/colliding", Version: "1.0.0"}}
			request.Configuration = canonical.Map{"official/pdf": canonical.Map{}, "official/colliding": canonical.Map{}}
		}, want: ErrConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := cloneCompileRequest(base)
			test.mutate(&request)
			if _, err := registry.CompileRuntime(request); !errors.Is(err, test.want) {
				t.Fatalf("CompileRuntime() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRegistryIsSafeForConcurrentRuntimeCompilation(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registry := fixture.registry(t, []SignedRevision{fixture.pdf, fixture.python})
	request := fixture.compileRequest()
	want, err := registry.CompileRuntime(request)
	if err != nil {
		t.Fatalf("CompileRuntime() error = %v", err)
	}

	const workers = 64
	results := make(chan RuntimeRevision, workers)
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, compileErr := registry.CompileRuntime(request)
			results <- result
			errorsChannel <- compileErr
		}()
	}
	wait.Wait()
	close(results)
	close(errorsChannel)
	for compileErr := range errorsChannel {
		if compileErr != nil {
			t.Fatalf("concurrent CompileRuntime() error = %v", compileErr)
		}
	}
	for result := range results {
		if result.Digest != want.Digest || result.Environment.Digest != want.Environment.Digest {
			t.Fatalf("concurrent result = %q/%q, want %q/%q", result.Digest, result.Environment.Digest, want.Digest, want.Environment.Digest)
		}
	}
}

type testFixture struct {
	bundlePublic      ed25519.PublicKey
	bundlePrivate     ed25519.PrivateKey
	assessmentPublic  ed25519.PublicKey
	assessmentPrivate ed25519.PrivateKey
	roots             TrustRoots
	resolver          *environment.Resolver
	environment       environment.Revision
	pdf               SignedRevision
	python            SignedRevision
}

type staticResolver struct {
	revision environment.Revision
}

func (resolver staticResolver) Resolve(environment.Request) (environment.Revision, error) {
	return resolver.revision, nil
}

func newFixture(t *testing.T) testFixture {
	t.Helper()
	bundlePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	assessmentPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	fixture := testFixture{
		bundlePublic:      bundlePrivate.Public().(ed25519.PublicKey),
		bundlePrivate:     bundlePrivate,
		assessmentPublic:  assessmentPrivate.Public().(ed25519.PublicKey),
		assessmentPrivate: assessmentPrivate,
	}
	fixture.roots = TrustRoots{
		Bundle: map[string]ed25519.PublicKey{
			"publisher-platform-1":     fixture.bundlePublic,
			"publisher-platform-alias": fixture.bundlePublic,
		},
		Assessment: map[string]ed25519.PublicKey{
			"platform-security-1":     fixture.assessmentPublic,
			"platform-security-alias": fixture.assessmentPublic,
		},
	}
	fixture.environment = validEnvironment(t)
	resolver, err := environment.NewResolver([]environment.Revision{fixture.environment})
	if err != nil {
		t.Fatalf("environment.NewResolver() error = %v", err)
	}
	fixture.resolver = resolver

	pdf := CompiledRevision{
		ID: "official/pdf", Version: "1.4.2", Publisher: "platform",
		ContentDigest: testDigest('a'), RevisionDigest: testDigest('b'), BundleDigest: testDigest('c'), BundleSize: 4096,
		SBOMDigest: testDigest('d'), ConfigurationSchemaDigest: testDigest('e'), Priority: 100,
		Tools:                     []string{"pdf.render"},
		NativeRequirements:        []environment.Requirement{{PackageID: "document-tools", Constraint: ">=3.2.0 <4.0.0"}},
		SupportedBackends:         []environment.Backend{environment.BackendDocker, environment.BackendNsJail},
		RequestedMinimumIsolation: Isolation{ProcessScope: ProcessScopeShared, OuterIsolation: OuterIsolationNone},
		StateSchemaVersion:        3,
	}
	pdfAssessment := SecurityAssessment{
		ExtensionDigest: pdf.ContentDigest, TrustClass: TrustClassPlatformReviewed,
		AssessedAt: "2026-08-22T00:00:00Z", MinimumIsolation: Isolation{ProcessScope: ProcessScopeShared, OuterIsolation: OuterIsolationNone},
		AllowedExecutionBackends: []environment.Backend{environment.BackendNsJail},
	}
	fixture.pdf = fixture.signRecord(t, pdf, pdfAssessment)

	python := CompiledRevision{
		ID: "official/python", Version: "2.0.0", Publisher: "platform",
		ContentDigest: testDigest('3'), RevisionDigest: testDigest('4'), BundleDigest: testDigest('5'), BundleSize: 2048,
		SBOMDigest: testDigest('6'), ConfigurationSchemaDigest: testDigest('7'), Priority: 50,
		Tools:                     []string{"python.run"},
		NativeRequirements:        []environment.Requirement{{PackageID: "python-runtime", Constraint: "3.13.x"}},
		SupportedBackends:         []environment.Backend{environment.BackendNsJail, environment.BackendDocker},
		RequestedMinimumIsolation: Isolation{ProcessScope: ProcessScopeShared, OuterIsolation: OuterIsolationNone},
		StateSchemaVersion:        1,
	}
	pythonAssessment := SecurityAssessment{
		ExtensionDigest: python.ContentDigest, TrustClass: TrustClassSignedThirdParty,
		AssessedAt: "2026-08-22T00:00:00Z", MinimumIsolation: Isolation{ProcessScope: ProcessScopeTenant, OuterIsolation: OuterIsolationNsJail},
		AllowedExecutionBackends: []environment.Backend{environment.BackendNsJail, environment.BackendDocker},
	}
	fixture.python = fixture.signRecord(t, python, pythonAssessment)
	return fixture
}

func (fixture testFixture) signRecord(t *testing.T, revision CompiledRevision, assessment SecurityAssessment) SignedRevision {
	t.Helper()
	bundleDigest, err := BundleSignatureDigest(revision, "publisher-platform-1")
	if err != nil {
		t.Fatalf("BundleSignatureDigest() error = %v", err)
	}
	assessment.Signature = Signature{KeyID: "platform-security-1"}
	assessmentDigest, err := AssessmentSignatureDigest(assessment)
	if err != nil {
		t.Fatalf("AssessmentSignatureDigest() error = %v", err)
	}
	return SignedRevision{
		Revision:        revision,
		BundleSignature: Signature{KeyID: "publisher-platform-1", Value: ed25519.Sign(fixture.bundlePrivate, []byte(bundleDigest))},
		Assessment: func() SecurityAssessment {
			assessment.Signature = Signature{KeyID: "platform-security-1", Value: ed25519.Sign(fixture.assessmentPrivate, []byte(assessmentDigest))}
			return assessment
		}(),
	}
}

func (fixture testFixture) registry(t *testing.T, records []SignedRevision) *Registry {
	t.Helper()
	registry, err := New(fixture.roots, records, fixture.resolver)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return registry
}

func (fixture testFixture) compileRequest() CompileRequest {
	return CompileRequest{
		Selections:    []Selection{{ID: "official/pdf", Version: "1.4.2"}, {ID: "official/python", Version: "2.0.0"}},
		Configuration: canonical.Map{"official/pdf": canonical.Map{}, "official/python": canonical.Map{}},
		Workerd:       WorkerdRevision{BinaryDigest: testDigest('1'), CompatibilityDate: "2026-08-01", CompatibilityFlags: []string{"nodejs_compat"}, LoaderABIVersion: 1},
		Pi:            PiRevision{PackageDigest: testDigest('2'), AdapterABIVersion: 1, AgentEngine: "low-level"},
		Architecture:  environment.ArchitectureX8664, Backend: environment.BackendNsJail, PolicyGeneration: 17,
		PolicyMinimumIsolation: Isolation{ProcessScope: ProcessScopeShared, OuterIsolation: OuterIsolationNone},
	}
}

func validEnvironment(t *testing.T) environment.Revision {
	t.Helper()
	id, err := identity.Parse(identity.EnvironmentRevision, "env_AAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatalf("identity.Parse() error = %v", err)
	}
	revision := environment.Revision{
		ID: id, Architecture: environment.ArchitectureX8664,
		Packages: []environment.Package{
			{ID: "document-tools", Version: "3.4.1", Digest: testDigest('8')},
			{ID: "python-runtime", Version: "3.13.2", Digest: testDigest('9')},
		},
		SandboxdDigest: testDigest('a'), SeccompProfileDigest: testDigest('b'), FilesystemPolicyDigest: testDigest('c'),
		Artifacts: environment.BackendArtifacts{NsJail: &environment.NsJailArtifact{RootfsDigest: testDigest('d')}},
	}
	revision.Digest, err = environment.DigestRevision(revision)
	if err != nil {
		t.Fatalf("environment.DigestRevision() error = %v", err)
	}
	return revision
}

func cloneSignedRevision(record SignedRevision) SignedRevision {
	record.Revision.Tools = append([]string(nil), record.Revision.Tools...)
	record.Revision.NativeRequirements = append([]environment.Requirement(nil), record.Revision.NativeRequirements...)
	record.Revision.SupportedBackends = append([]environment.Backend(nil), record.Revision.SupportedBackends...)
	record.BundleSignature.Value = append([]byte(nil), record.BundleSignature.Value...)
	record.Assessment.AllowedExecutionBackends = append([]environment.Backend(nil), record.Assessment.AllowedExecutionBackends...)
	record.Assessment.Signature.Value = append([]byte(nil), record.Assessment.Signature.Value...)
	return record
}

func cloneCompileRequest(request CompileRequest) CompileRequest {
	request.Selections = append([]Selection(nil), request.Selections...)
	request.Workerd.CompatibilityFlags = append([]string(nil), request.Workerd.CompatibilityFlags...)
	configuration := make(canonical.Map, len(request.Configuration))
	for key, value := range request.Configuration {
		configuration[key] = value
	}
	request.Configuration = configuration
	return request
}

func testDigest(fill byte) string {
	return "sha256:" + string(bytes.Repeat([]byte{fill}, 64))
}
