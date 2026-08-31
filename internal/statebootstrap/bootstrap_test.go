package statebootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/platformapi"
	"github.com/hancomac/circulusd/internal/release"
	releasecontract "github.com/hancomac/circulusd/internal/release/contracttest"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

var requiredStateGroups = []dependency.AtomicGroup{
	dependency.AtomicCommandReceipt,
	dependency.AtomicEffectLifecycle,
}

type signedProbe struct {
	mu         sync.Mutex
	descriptor dependency.Descriptor
	privateKey ed25519.PrivateKey
	nonces     [][]byte
	roles      []string
}

func (probe *signedProbe) response(
	ctx context.Context,
	role string,
	challenge dependency.ProbeChallenge,
) (dependency.ProbeResponse, error) {
	if err := ctx.Err(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	probe.mu.Lock()
	probe.nonces = append(probe.nonces, append([]byte(nil), challenge.Nonce...))
	probe.roles = append(probe.roles, role)
	probe.mu.Unlock()
	descriptor := probe.descriptor
	descriptor.AtomicGroups = append([]dependency.AtomicGroup(nil), descriptor.AtomicGroups...)
	digest, err := dependency.ProbeSigningDigest(descriptor, challenge.Nonce)
	if err != nil {
		return dependency.ProbeResponse{}, err
	}
	return dependency.ProbeResponse{
		Descriptor: descriptor,
		KeyID:      descriptor.RuntimeKeyID,
		Signature:  ed25519.Sign(probe.privateKey, []byte(digest)),
	}, nil
}

func (probe *signedProbe) snapshot() ([][]byte, []string) {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	nonces := make([][]byte, len(probe.nonces))
	for index := range probe.nonces {
		nonces[index] = append([]byte(nil), probe.nonces[index]...)
	}
	return nonces, append([]string(nil), probe.roles...)
}

type testReader struct{ probe *signedProbe }

func (reader *testReader) ProbeProduction(
	ctx context.Context,
	challenge dependency.ProbeChallenge,
) (dependency.ProbeResponse, error) {
	return reader.probe.response(ctx, "reader", challenge)
}

func (*testReader) ReadSessionEventPage(
	context.Context,
	platformapi.AuthorizedSessionEventPageRequest,
) (platformapi.SessionPublicEventPage, error) {
	return platformapi.SessionPublicEventPage{}, nil
}

type testClaimer struct{ probe *signedProbe }

func (claimer *testClaimer) ProbeProduction(
	ctx context.Context,
	challenge dependency.ProbeChallenge,
) (dependency.ProbeResponse, error) {
	return claimer.probe.response(ctx, "claimer", challenge)
}

func (*testClaimer) ClaimDispatchStart(
	context.Context,
	broker.DispatchStartRequest,
) (broker.DispatchStartClaim, error) {
	return broker.DispatchStartClaim{}, nil
}

type bootstrapFixture struct {
	state      stateConfiguration
	manifest   release.Manifest
	trustStore *release.TrustStore
	artifacts  release.AuthenticatedStateArtifactDigests
	verifier   *dependency.Verifier
	evidence   dependency.Evidence
	descriptor dependency.Descriptor
	client     *stateappclient.Client
	probe      *signedProbe
}

func newBootstrapFixture(t *testing.T) *bootstrapFixture {
	t.Helper()
	now := time.Unix(1_900_000_000, 0).UTC()
	conformancePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	runtimePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	descriptor := dependency.Descriptor{
		SchemaVersion:       1,
		BackendKind:         dependency.BackendCelld,
		BuildDigest:         "sha256:" + strings.Repeat("1", 64),
		ApplicationDigest:   "sha256:" + strings.Repeat("2", 64),
		InstanceID:          "state-node-bootstrap-test",
		TransactionDomainID: "state-domain-bootstrap-test",
		DurabilityClass:     dependency.DurabilityCrashRPOZero,
		ConformanceRunID:    "state-conformance-bootstrap-test",
		ConformanceDigest:   "sha256:" + strings.Repeat("3", 64),
		RuntimeKeyID:        "state-runtime-bootstrap-test",
		ProbeEpoch:          9,
		ProductionEligible:  true,
		AtomicGroups:        append([]dependency.AtomicGroup(nil), requiredStateGroups...),
	}
	evidence := dependency.Evidence{
		Descriptor:   descriptor,
		IssuedAtUnix: now.Add(-time.Minute).Unix(), ExpiresAtUnix: now.Add(time.Hour).Unix(),
		KeyID: "state-conformance-bootstrap-test",
	}
	digest, err := dependency.EvidenceSigningDigest(evidence)
	if err != nil {
		t.Fatalf("EvidenceSigningDigest() error = %v", err)
	}
	evidence.Signature = ed25519.Sign(conformancePrivate, []byte(digest))
	verifier, err := dependency.NewVerifier(dependency.VerifierConfig{
		ConformanceRoots: map[string]ed25519.PublicKey{
			evidence.KeyID: conformancePrivate.Public().(ed25519.PublicKey),
		},
		RuntimeRoots: map[string]ed25519.PublicKey{
			descriptor.RuntimeKeyID: runtimePrivate.Public().(ed25519.PublicKey),
		},
		Clock: func() time.Time { return now },
		Entropy: bytes.NewReader(append(
			bytes.Repeat([]byte{0x41}, dependency.ChallengeBytes),
			bytes.Repeat([]byte{0x42}, dependency.ChallengeBytes)...,
		)),
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	releasePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
	trustStore, err := release.NewTrustStore(map[string]ed25519.PublicKey{
		"release-root-bootstrap-test": releasePrivate.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatalf("NewTrustStore() error = %v", err)
	}
	client, err := stateappclient.New(stateappclient.Config{
		Endpoint: "http://127.0.0.1:9", KeyID: "state-read-bootstrap-test",
		RootKey:              bytes.Repeat([]byte{0x51}, 32),
		DispatchStartKeyID:   "state-dispatch-bootstrap-test",
		DispatchStartRootKey: bytes.Repeat([]byte{0x52}, 32), Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("stateappclient.New() error = %v", err)
	}
	t.Cleanup(client.Close)
	return &bootstrapFixture{
		state: stateConfiguration{
			endpoint: "http://127.0.0.1:9", readKeyID: "state-read-bootstrap-test",
			readRootKeyFile:          "/run/credentials/state-read.key",
			dispatchStartKeyID:       "state-dispatch-bootstrap-test",
			dispatchStartRootKeyFile: "/run/credentials/state-dispatch.key",
			httpTimeout:              time.Second, dispatchStartTimeout: 30 * time.Second,
			instanceID: descriptor.InstanceID, transactionDomainID: descriptor.TransactionDomainID,
			minimumProbeEpoch: descriptor.ProbeEpoch, maximumEvidenceAge: time.Hour,
			productionEvidenceFile: "/etc/pi-platform/state/evidence.json",
			conformanceRootsFile:   "/etc/pi-platform/state/conformance.json",
			runtimeRootsFile:       "/etc/pi-platform/state/runtime.json",
		},
		trustStore: trustStore,
		artifacts: releasecontract.StateArtifactDigests(
			t, descriptor.BuildDigest, descriptor.ApplicationDigest,
		),
		verifier: verifier, evidence: evidence, descriptor: descriptor, client: client,
		probe: &signedProbe{descriptor: descriptor, privateKey: runtimePrivate},
	}
}

type sourceObservation struct {
	mu            sync.Mutex
	events        []string
	readerClient  *stateappclient.Client
	claimerClient *stateappclient.Client
	reader        platformapi.SessionEventPageReader
	claimer       broker.DispatchStartClaimer
	closes        atomic.Int32
}

func (observation *sourceObservation) add(event string) {
	observation.mu.Lock()
	observation.events = append(observation.events, event)
	observation.mu.Unlock()
}

func (observation *sourceObservation) snapshot() []string {
	observation.mu.Lock()
	defer observation.mu.Unlock()
	return append([]string(nil), observation.events...)
}

func newTestSources(
	t *testing.T,
	fixture *bootstrapFixture,
	observation *sourceObservation,
) bootstrapSources {
	t.Helper()
	return bootstrapSources{
		clock:   func() time.Time { return time.Unix(1_900_000_000, 0).UTC() },
		entropy: bytes.NewReader(bytes.Repeat([]byte{0x77}, 2*dependency.ChallengeBytes)),
		loadConfiguration: func(path string) (stateConfiguration, error) {
			observation.add("config")
			if path != "/etc/pi-platform/config.yaml" {
				t.Errorf("configuration path = %q", path)
			}
			return fixture.state, nil
		},
		loadManifest: func(path string) (release.Manifest, error) {
			observation.add("manifest")
			if path != "/usr/lib/pi-platform/release.json" {
				t.Errorf("manifest path = %q", path)
			}
			return fixture.manifest, nil
		},
		loadTrustStore: func(path string) (*release.TrustStore, error) {
			observation.add("trust")
			if path != "/etc/pi-platform/release-roots.json" {
				t.Errorf("trust roots path = %q", path)
			}
			return fixture.trustStore, nil
		},
		architecture: func() (string, error) {
			observation.add("architecture")
			return "x86_64", nil
		},
		deriveArtifacts: func(
			store *release.TrustStore,
			manifest release.Manifest,
			architecture string,
		) (release.AuthenticatedStateArtifactDigests, error) {
			observation.add("artifacts")
			if store != fixture.trustStore || architecture != "x86_64" {
				t.Errorf("derive inputs = %p/%q", store, architecture)
			}
			return fixture.artifacts, nil
		},
		loadProofs: func(config dependency.ProductionProofFileConfig) (*dependency.Verifier, dependency.Evidence, error) {
			observation.add("proofs")
			if config.EvidenceFile != fixture.state.productionEvidenceFile ||
				config.ConformanceRootsFile != fixture.state.conformanceRootsFile ||
				config.RuntimeRootsFile != fixture.state.runtimeRootsFile ||
				config.Clock == nil || config.Entropy == nil {
				t.Errorf("proof file config = %#v", config)
			}
			return fixture.verifier, fixture.evidence, nil
		},
		newRequirements: func(
			artifacts release.AuthenticatedStateArtifactDigests,
			config dependency.ProductionRequirementsConfig,
		) (dependency.Requirements, error) {
			observation.add("requirements")
			if artifacts.CelldBuildDigest() != fixture.descriptor.BuildDigest ||
				artifacts.StateAppApplicationDigest() != fixture.descriptor.ApplicationDigest ||
				config.InstanceID != fixture.descriptor.InstanceID ||
				config.TransactionDomainID != fixture.descriptor.TransactionDomainID ||
				config.MinimumProbeEpoch != fixture.descriptor.ProbeEpoch ||
				config.MaximumEvidenceAge != time.Hour ||
				!reflect.DeepEqual(config.RequiredAtomicGroups, requiredStateGroups) {
				t.Errorf("production requirements config = %#v", config)
			}
			return dependency.NewProductionRequirements(artifacts, config)
		},
		newClient: func(config stateappclient.CredentialFileConfig) (*stateappclient.Client, error) {
			observation.add("client")
			if config.Endpoint != fixture.state.endpoint || config.KeyID != fixture.state.readKeyID ||
				config.RootKeyFile != fixture.state.readRootKeyFile ||
				config.DispatchStartKeyID != fixture.state.dispatchStartKeyID ||
				config.DispatchStartRootKeyFile != fixture.state.dispatchStartRootKeyFile ||
				config.Timeout != fixture.state.httpTimeout {
				t.Errorf("credential client config = %#v", config)
			}
			return fixture.client, nil
		},
		newReader: func(client *stateappclient.Client) (platformapi.SessionEventPageReader, error) {
			observation.add("reader")
			observation.readerClient = client
			observation.reader = &testReader{probe: fixture.probe}
			return observation.reader, nil
		},
		newClaimer: func(client *stateappclient.Client) (broker.DispatchStartClaimer, error) {
			observation.add("claimer")
			observation.claimerClient = client
			observation.claimer = &testClaimer{probe: fixture.probe}
			return observation.claimer, nil
		},
		verifyReader: func(
			ctx context.Context,
			verifier *dependency.Verifier,
			reader platformapi.SessionEventPageReader,
			evidence dependency.Evidence,
			requirements dependency.Requirements,
		) (dependency.Verified[platformapi.SessionEventPageReader], error) {
			observation.add("reader.seal")
			verified, err := dependency.VerifyDependency(ctx, verifier, reader, evidence, requirements)
			if len(evidence.Descriptor.AtomicGroups) != 0 {
				evidence.Descriptor.AtomicGroups[0] = dependency.AtomicQuotaSettlement
			}
			if len(evidence.Signature) != 0 {
				evidence.Signature[0] ^= 0xff
			}
			if len(requirements.RequiredAtomicGroups) != 0 {
				requirements.RequiredAtomicGroups[0] = dependency.AtomicQuotaSettlement
			}
			return verified, err
		},
		verifyClaimer: func(
			ctx context.Context,
			verifier *dependency.Verifier,
			claimer broker.DispatchStartClaimer,
			evidence dependency.Evidence,
			requirements dependency.Requirements,
		) (dependency.Verified[broker.DispatchStartClaimer], error) {
			observation.add("claimer.seal")
			return dependency.VerifyDependency(ctx, verifier, claimer, evidence, requirements)
		},
		requireDomain: func(
			required []dependency.AtomicGroup,
			bindings ...dependency.Binding,
		) (dependency.Descriptor, error) {
			observation.add("domain")
			if !reflect.DeepEqual(required, requiredStateGroups) || len(bindings) != 2 {
				t.Errorf("domain requirement = %v across %d bindings", required, len(bindings))
			}
			return dependency.RequireAtomicDomain(required, bindings...)
		},
		closeClient: func(client *stateappclient.Client) {
			observation.add("close")
			observation.closes.Add(1)
			client.Close()
		},
	}
}

func testFiles() Files {
	return Files{
		Configuration:     "/etc/pi-platform/config.yaml",
		ReleaseManifest:   "/usr/lib/pi-platform/release.json",
		ReleaseTrustRoots: "/etc/pi-platform/release-roots.json",
	}
}

func TestLoadBuildsOneJointlyVerifiedImmutableStateGraph(t *testing.T) {
	fixture := newBootstrapFixture(t)
	observation := &sourceObservation{}
	graph, err := loadWithSources(context.Background(), testFiles(), newTestSources(t, fixture, observation))
	if err != nil {
		t.Fatalf("loadWithSources() error = %v", err)
	}
	wantEvents := []string{
		"config", "manifest", "trust", "architecture", "artifacts", "requirements",
		"proofs", "client", "reader", "claimer", "reader.seal", "claimer.seal", "domain",
	}
	if got := observation.snapshot(); !reflect.DeepEqual(got, wantEvents) {
		t.Fatalf("bootstrap events = %v, want %v", got, wantEvents)
	}
	if observation.readerClient != fixture.client || observation.claimerClient != fixture.client {
		t.Fatalf("adapter clients = %p/%p, want exact %p", observation.readerClient, observation.claimerClient, fixture.client)
	}
	reader, readerDescriptor, err := graph.SessionEventReader().Open()
	if err != nil || reader != observation.reader {
		t.Fatalf("SessionEventReader().Open() = %T/%v, want %T", reader, err, observation.reader)
	}
	claimer, claimerDescriptor, err := graph.DispatchStartClaimer().Open()
	if err != nil || claimer != observation.claimer {
		t.Fatalf("DispatchStartClaimer().Open() = %T/%v, want %T", claimer, err, observation.claimer)
	}
	if !reflect.DeepEqual(readerDescriptor, fixture.descriptor) ||
		!reflect.DeepEqual(claimerDescriptor, fixture.descriptor) ||
		!reflect.DeepEqual(graph.Descriptor(), fixture.descriptor) ||
		graph.DispatchStartTimeout() != fixture.state.dispatchStartTimeout {
		t.Fatalf("graph metadata = %#v/%v", graph.Descriptor(), graph.DispatchStartTimeout())
	}
	nonces, roles := fixture.probe.snapshot()
	if len(nonces) != 2 || bytes.Equal(nonces[0], nonces[1]) || !reflect.DeepEqual(roles, []string{"reader", "claimer"}) {
		t.Fatalf("production probes = nonces %x roles %v", nonces, roles)
	}
	mutated := graph.Descriptor()
	mutated.AtomicGroups[0] = dependency.AtomicQuotaSettlement
	readerDescriptor.AtomicGroups[0] = dependency.AtomicQuotaSettlement
	if !reflect.DeepEqual(graph.Descriptor(), fixture.descriptor) {
		t.Fatalf("descriptor aliases caller mutation: %#v", graph.Descriptor())
	}

	var wait sync.WaitGroup
	for range 64 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			graph.Close()
		}()
	}
	wait.Wait()
	if observation.closes.Load() != 1 {
		t.Fatalf("client closes = %d, want 1", observation.closes.Load())
	}
}

func TestGraphFormattingRedactsThePrivateStateClient(t *testing.T) {
	fixture := newBootstrapFixture(t)
	graph := &graph{client: fixture.client}
	want := "production-state-graph<redacted>"
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(format, graph); got != want {
			t.Fatalf("Sprintf(%q, graph) = %q, want %q", format, got, want)
		}
	}
}

func TestLoadFailsBeforeCredentialsWhenPublicStateInputsAreInvalid(t *testing.T) {
	boom := errors.New("public bootstrap input failed")
	tests := []struct {
		name       string
		wantEvents []string
	}{
		{name: "configuration", wantEvents: []string{"config"}},
		{name: "manifest", wantEvents: []string{"config", "manifest"}},
		{name: "trust roots", wantEvents: []string{"config", "manifest", "trust"}},
		{name: "architecture", wantEvents: []string{"config", "manifest", "trust", "architecture"}},
		{name: "authenticated artifacts", wantEvents: []string{"config", "manifest", "trust", "architecture", "artifacts"}},
		{name: "requirements", wantEvents: []string{"config", "manifest", "trust", "architecture", "artifacts", "requirements"}},
		{
			name: "proof bundle",
			wantEvents: []string{
				"config", "manifest", "trust", "architecture", "artifacts", "requirements", "proofs",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBootstrapFixture(t)
			observation := &sourceObservation{}
			sources := newTestSources(t, fixture, observation)
			switch test.name {
			case "configuration":
				sources.loadConfiguration = func(string) (stateConfiguration, error) {
					observation.add("config")
					return stateConfiguration{}, boom
				}
			case "manifest":
				sources.loadManifest = func(string) (release.Manifest, error) {
					observation.add("manifest")
					return release.Manifest{}, boom
				}
			case "trust roots":
				sources.loadTrustStore = func(path string) (*release.TrustStore, error) {
					observation.add("trust")
					return nil, boom
				}
			case "architecture":
				sources.architecture = func() (string, error) {
					observation.add("architecture")
					return "", boom
				}
			case "authenticated artifacts":
				sources.deriveArtifacts = func(
					*release.TrustStore,
					release.Manifest,
					string,
				) (release.AuthenticatedStateArtifactDigests, error) {
					observation.add("artifacts")
					return release.AuthenticatedStateArtifactDigests{}, boom
				}
			case "requirements":
				sources.newRequirements = func(
					release.AuthenticatedStateArtifactDigests,
					dependency.ProductionRequirementsConfig,
				) (dependency.Requirements, error) {
					observation.add("requirements")
					return dependency.Requirements{}, boom
				}
			case "proof bundle":
				sources.loadProofs = func(
					dependency.ProductionProofFileConfig,
				) (*dependency.Verifier, dependency.Evidence, error) {
					observation.add("proofs")
					return nil, dependency.Evidence{}, boom
				}
			}
			graph, err := loadWithSources(context.Background(), testFiles(), sources)
			if graph != nil || !errors.Is(err, boom) {
				t.Fatalf("loadWithSources() = %v/%v, want nil/%v", graph, err, boom)
			}
			if got := observation.snapshot(); !reflect.DeepEqual(got, test.wantEvents) {
				t.Fatalf("events = %v, want %v", got, test.wantEvents)
			}
			if observation.closes.Load() != 0 {
				t.Fatalf("client closes = %d, want zero before credentials", observation.closes.Load())
			}
		})
	}
}

func TestLoadClosesTheClientAfterEveryPostConstructionFailure(t *testing.T) {
	boom := errors.New("bootstrap stage failed")
	tests := []struct {
		name   string
		mutate func(*bootstrapSources)
	}{
		{
			name: "credential client",
			mutate: func(sources *bootstrapSources) {
				constructor := sources.newClient
				sources.newClient = func(config stateappclient.CredentialFileConfig) (*stateappclient.Client, error) {
					client, err := constructor(config)
					if err != nil {
						return client, err
					}
					return client, boom
				}
			},
		},
		{
			name: "reader",
			mutate: func(sources *bootstrapSources) {
				sources.newReader = func(*stateappclient.Client) (platformapi.SessionEventPageReader, error) {
					return nil, boom
				}
			},
		},
		{
			name: "claimer",
			mutate: func(sources *bootstrapSources) {
				sources.newClaimer = func(*stateappclient.Client) (broker.DispatchStartClaimer, error) {
					return nil, boom
				}
			},
		},
		{
			name: "reader seal",
			mutate: func(sources *bootstrapSources) {
				sources.verifyReader = func(
					context.Context,
					*dependency.Verifier,
					platformapi.SessionEventPageReader,
					dependency.Evidence,
					dependency.Requirements,
				) (dependency.Verified[platformapi.SessionEventPageReader], error) {
					return dependency.Verified[platformapi.SessionEventPageReader]{}, boom
				}
			},
		},
		{
			name: "claimer seal",
			mutate: func(sources *bootstrapSources) {
				sources.verifyClaimer = func(
					context.Context,
					*dependency.Verifier,
					broker.DispatchStartClaimer,
					dependency.Evidence,
					dependency.Requirements,
				) (dependency.Verified[broker.DispatchStartClaimer], error) {
					return dependency.Verified[broker.DispatchStartClaimer]{}, boom
				}
			},
		},
		{
			name: "joint domain",
			mutate: func(sources *bootstrapSources) {
				sources.requireDomain = func([]dependency.AtomicGroup, ...dependency.Binding) (dependency.Descriptor, error) {
					return dependency.Descriptor{}, boom
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBootstrapFixture(t)
			observation := &sourceObservation{}
			sources := newTestSources(t, fixture, observation)
			test.mutate(&sources)
			graph, err := loadWithSources(context.Background(), testFiles(), sources)
			if graph != nil || !errors.Is(err, boom) {
				t.Fatalf("loadWithSources() = %v/%v, want nil/%v", graph, err, boom)
			}
			if observation.closes.Load() != 1 {
				t.Fatalf("client closes = %d, want 1", observation.closes.Load())
			}
		})
	}
}

func TestLoadStopsBeforeTheSecondSealWhenCanceledAndClosesTheClient(t *testing.T) {
	fixture := newBootstrapFixture(t)
	observation := &sourceObservation{}
	ctx, cancel := context.WithCancel(context.Background())
	sources := newTestSources(t, fixture, observation)
	verifyReader := sources.verifyReader
	sources.verifyReader = func(
		ctx context.Context,
		verifier *dependency.Verifier,
		reader platformapi.SessionEventPageReader,
		evidence dependency.Evidence,
		requirements dependency.Requirements,
	) (dependency.Verified[platformapi.SessionEventPageReader], error) {
		verified, err := verifyReader(ctx, verifier, reader, evidence, requirements)
		cancel()
		return verified, err
	}
	graph, err := loadWithSources(ctx, testFiles(), sources)
	if graph != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("loadWithSources(canceled) = %v/%v, want nil/context.Canceled", graph, err)
	}
	_, roles := fixture.probe.snapshot()
	if !reflect.DeepEqual(roles, []string{"reader"}) {
		t.Fatalf("probe roles = %v, want reader only", roles)
	}
	if observation.closes.Load() != 1 {
		t.Fatalf("client closes = %d, want 1", observation.closes.Load())
	}
}

func TestLoadRejectsInvalidInputsBeforeUsingSources(t *testing.T) {
	valid := testFiles()
	tests := []struct {
		name  string
		ctx   context.Context
		files Files
	}{
		{name: "nil context", files: valid},
		{name: "empty", ctx: context.Background()},
		{name: "relative", ctx: context.Background(), files: Files{Configuration: "config.yaml", ReleaseManifest: valid.ReleaseManifest, ReleaseTrustRoots: valid.ReleaseTrustRoots}},
		{name: "root", ctx: context.Background(), files: Files{Configuration: "/", ReleaseManifest: valid.ReleaseManifest, ReleaseTrustRoots: valid.ReleaseTrustRoots}},
		{name: "unclean", ctx: context.Background(), files: Files{Configuration: "/etc/../etc/config.yaml", ReleaseManifest: valid.ReleaseManifest, ReleaseTrustRoots: valid.ReleaseTrustRoots}},
		{name: "duplicate", ctx: context.Background(), files: Files{Configuration: valid.Configuration, ReleaseManifest: valid.Configuration, ReleaseTrustRoots: valid.ReleaseTrustRoots}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if graph, err := loadWithSources(test.ctx, test.files, bootstrapSources{}); graph != nil || !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("loadWithSources() = %v/%v, want nil/ErrInvalidConfiguration", graph, err)
			}
		})
	}
}
