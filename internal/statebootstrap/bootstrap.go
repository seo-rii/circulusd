// Package statebootstrap constructs the production state boundary from
// startup configuration, release, proof, and credential inputs. It owns the
// shared state-app client until the complete verified graph is closed.
package statebootstrap

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/config"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/platformapi"
	"github.com/hancomac/circulusd/internal/release"
	"github.com/hancomac/circulusd/internal/stateappadapter"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

var ErrInvalidConfiguration = errors.New("state bootstrap: invalid configuration")

// Files identifies the three service-owned input paths read once at startup.
// The individual reads do not claim a globally atomic filesystem rollout.
type Files struct {
	Configuration     string
	ReleaseManifest   string
	ReleaseTrustRoots string
}

// Graph is the opaque production state dependency boundary. Its concrete
// representation is private so callers cannot copy or format the credential-
// bearing client; verified adapters and metadata remain immutable.
type Graph interface {
	SessionEventReader() dependency.Verified[platformapi.SessionEventPageReader]
	DispatchStartClaimer() dependency.Verified[broker.DispatchStartClaimer]
	Descriptor() dependency.Descriptor
	DispatchStartTimeout() time.Duration
	Close()
}

type graph struct {
	sessionEventReader   dependency.Verified[platformapi.SessionEventPageReader]
	dispatchStartClaimer dependency.Verified[broker.DispatchStartClaimer]
	descriptor           dependency.Descriptor
	dispatchStartTimeout time.Duration
	client               *stateappclient.Client
	closeClient          func(*stateappclient.Client)
	closeOnce            sync.Once
}

func (*graph) String() string   { return "production-state-graph<redacted>" }
func (*graph) GoString() string { return "production-state-graph<redacted>" }

func (graph *graph) SessionEventReader() dependency.Verified[platformapi.SessionEventPageReader] {
	if graph == nil {
		return dependency.Verified[platformapi.SessionEventPageReader]{}
	}
	return graph.sessionEventReader
}

func (graph *graph) DispatchStartClaimer() dependency.Verified[broker.DispatchStartClaimer] {
	if graph == nil {
		return dependency.Verified[broker.DispatchStartClaimer]{}
	}
	return graph.dispatchStartClaimer
}

func (graph *graph) Descriptor() dependency.Descriptor {
	if graph == nil {
		return dependency.Descriptor{}
	}
	descriptor := graph.descriptor
	descriptor.AtomicGroups = append([]dependency.AtomicGroup(nil), graph.descriptor.AtomicGroups...)
	return descriptor
}

func (graph *graph) DispatchStartTimeout() time.Duration {
	if graph == nil {
		return 0
	}
	return graph.dispatchStartTimeout
}

func (graph *graph) Close() {
	if graph == nil {
		return
	}
	graph.closeOnce.Do(func() {
		if graph.closeClient != nil && graph.client != nil {
			graph.closeClient(graph.client)
		}
	})
}

type stateConfiguration struct {
	endpoint                 string
	readKeyID                string
	readRootKeyFile          string
	dispatchStartKeyID       string
	dispatchStartRootKeyFile string
	httpTimeout              time.Duration
	dispatchStartTimeout     time.Duration
	instanceID               string
	transactionDomainID      string
	minimumProbeEpoch        uint64
	maximumEvidenceAge       time.Duration
	productionEvidenceFile   string
	conformanceRootsFile     string
	runtimeRootsFile         string
}

type bootstrapSources struct {
	clock             func() time.Time
	entropy           io.Reader
	loadConfiguration func(string) (stateConfiguration, error)
	loadManifest      func(string) (release.Manifest, error)
	loadTrustStore    func(string) (*release.TrustStore, error)
	architecture      func() (string, error)
	deriveArtifacts   func(
		*release.TrustStore,
		release.Manifest,
		string,
	) (release.AuthenticatedStateArtifactDigests, error)
	loadProofs      func(dependency.ProductionProofFileConfig) (*dependency.Verifier, dependency.Evidence, error)
	newRequirements func(
		release.AuthenticatedStateArtifactDigests,
		dependency.ProductionRequirementsConfig,
	) (dependency.Requirements, error)
	newClient    func(stateappclient.CredentialFileConfig) (*stateappclient.Client, error)
	newReader    func(*stateappclient.Client) (platformapi.SessionEventPageReader, error)
	newClaimer   func(*stateappclient.Client) (broker.DispatchStartClaimer, error)
	verifyReader func(
		context.Context,
		*dependency.Verifier,
		platformapi.SessionEventPageReader,
		dependency.Evidence,
		dependency.Requirements,
	) (dependency.Verified[platformapi.SessionEventPageReader], error)
	verifyClaimer func(
		context.Context,
		*dependency.Verifier,
		broker.DispatchStartClaimer,
		dependency.Evidence,
		dependency.Requirements,
	) (dependency.Verified[broker.DispatchStartClaimer], error)
	requireDomain func([]dependency.AtomicGroup, ...dependency.Binding) (dependency.Descriptor, error)
	closeClient   func(*stateappclient.Client)
}

// Load snapshots and verifies every production state input before returning a
// graph. Any failure after client construction closes that client before the
// error is returned.
func Load(ctx context.Context, files Files) (Graph, error) {
	sources := bootstrapSources{
		clock:   time.Now,
		entropy: rand.Reader,
		loadConfiguration: func(path string) (stateConfiguration, error) {
			file, err := os.Open(path)
			if err != nil {
				return stateConfiguration{}, fmt.Errorf("open platform configuration: %w", err)
			}
			defer file.Close()
			configuration, err := config.Parse(file)
			if err != nil {
				return stateConfiguration{}, err
			}
			state := configuration.State
			return stateConfiguration{
				endpoint:                 state.Endpoint.String(),
				readKeyID:                state.ReadKeyID,
				readRootKeyFile:          state.ReadRootKeyFile,
				dispatchStartKeyID:       state.DispatchStartKeyID,
				dispatchStartRootKeyFile: state.DispatchStartRootKeyFile,
				httpTimeout:              state.HTTPTimeout.Duration(),
				dispatchStartTimeout:     state.DispatchStartTimeout.Duration(),
				instanceID:               state.InstanceID,
				transactionDomainID:      state.TransactionDomainID,
				minimumProbeEpoch:        state.MinimumProbeEpoch,
				maximumEvidenceAge:       state.MaximumEvidenceAge.Duration(),
				productionEvidenceFile:   state.ProductionEvidenceFile,
				conformanceRootsFile:     state.ConformanceRootsFile,
				runtimeRootsFile:         state.RuntimeRootsFile,
			}, nil
		},
		loadManifest:   release.Load,
		loadTrustStore: release.LoadTrustStore,
		architecture: func() (string, error) {
			switch runtime.GOARCH {
			case "amd64":
				return "x86_64", nil
			case "arm64":
				return "aarch64", nil
			default:
				return "", fmt.Errorf("%w: runtime architecture %q is unsupported", ErrInvalidConfiguration, runtime.GOARCH)
			}
		},
		deriveArtifacts: func(
			store *release.TrustStore,
			manifest release.Manifest,
			architecture string,
		) (release.AuthenticatedStateArtifactDigests, error) {
			if store == nil {
				return release.AuthenticatedStateArtifactDigests{}, ErrInvalidConfiguration
			}
			return store.DeriveProductionStateArtifactDigests(manifest, architecture)
		},
		loadProofs:      dependency.NewVerifierFromFiles,
		newRequirements: dependency.NewProductionRequirements,
		newClient:       stateappclient.NewFromCredentialFiles,
		newReader: func(client *stateappclient.Client) (platformapi.SessionEventPageReader, error) {
			return stateappadapter.New(client)
		},
		newClaimer: func(client *stateappclient.Client) (broker.DispatchStartClaimer, error) {
			return stateappadapter.NewDispatchStartClaimer(client)
		},
		verifyReader: func(
			ctx context.Context,
			verifier *dependency.Verifier,
			reader platformapi.SessionEventPageReader,
			evidence dependency.Evidence,
			requirements dependency.Requirements,
		) (dependency.Verified[platformapi.SessionEventPageReader], error) {
			return dependency.VerifyDependency(ctx, verifier, reader, evidence, requirements)
		},
		verifyClaimer: func(
			ctx context.Context,
			verifier *dependency.Verifier,
			claimer broker.DispatchStartClaimer,
			evidence dependency.Evidence,
			requirements dependency.Requirements,
		) (dependency.Verified[broker.DispatchStartClaimer], error) {
			return dependency.VerifyDependency(ctx, verifier, claimer, evidence, requirements)
		},
		requireDomain: dependency.RequireAtomicDomain,
		closeClient:   (*stateappclient.Client).Close,
	}
	return loadWithSources(ctx, files, sources)
}

func loadWithSources(ctx context.Context, files Files, sources bootstrapSources) (Graph, error) {
	if ctx == nil {
		return nil, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	paths := []string{files.Configuration, files.ReleaseManifest, files.ReleaseTrustRoots}
	for _, path := range paths {
		valid := path != "" && utf8.ValidString(path) && filepath.IsAbs(path) &&
			filepath.Clean(path) == path && path != string(filepath.Separator)
		for _, character := range path {
			if unicode.IsControl(character) {
				valid = false
			}
		}
		if !valid {
			return nil, ErrInvalidConfiguration
		}
	}
	if files.Configuration == files.ReleaseManifest ||
		files.Configuration == files.ReleaseTrustRoots ||
		files.ReleaseManifest == files.ReleaseTrustRoots {
		return nil, ErrInvalidConfiguration
	}
	entropyIsNil := sources.entropy == nil
	if !entropyIsNil {
		value := reflect.ValueOf(sources.entropy)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			entropyIsNil = value.IsNil()
		}
	}
	if sources.clock == nil || entropyIsNil || sources.loadConfiguration == nil ||
		sources.loadManifest == nil || sources.loadTrustStore == nil || sources.architecture == nil ||
		sources.deriveArtifacts == nil || sources.loadProofs == nil || sources.newRequirements == nil ||
		sources.newClient == nil || sources.newReader == nil || sources.newClaimer == nil ||
		sources.verifyReader == nil || sources.verifyClaimer == nil || sources.requireDomain == nil ||
		sources.closeClient == nil {
		return nil, ErrInvalidConfiguration
	}

	state, err := sources.loadConfiguration(files.Configuration)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, fmt.Errorf("load platform configuration: %w", err)
	}
	manifest, err := sources.loadManifest(files.ReleaseManifest)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, fmt.Errorf("load release manifest: %w", err)
	}
	trustStore, err := sources.loadTrustStore(files.ReleaseTrustRoots)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, fmt.Errorf("load release trust roots: %w", err)
	}
	if trustStore == nil {
		return nil, ErrInvalidConfiguration
	}
	architecture, err := sources.architecture()
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, fmt.Errorf("select release architecture: %w", err)
	}
	artifacts, err := sources.deriveArtifacts(trustStore, manifest, architecture)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, fmt.Errorf("authenticate production state artifacts: %w", err)
	}
	requirements, err := sources.newRequirements(
		artifacts,
		dependency.ProductionRequirementsConfig{
			InstanceID: state.instanceID, TransactionDomainID: state.transactionDomainID,
			RequiredAtomicGroups: []dependency.AtomicGroup{
				dependency.AtomicCommandReceipt,
				dependency.AtomicEffectLifecycle,
			},
			MinimumProbeEpoch: state.minimumProbeEpoch, MaximumEvidenceAge: state.maximumEvidenceAge,
		},
	)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, fmt.Errorf("seal production state requirements: %w", err)
	}
	verifier, evidence, err := sources.loadProofs(dependency.ProductionProofFileConfig{
		EvidenceFile: state.productionEvidenceFile, ConformanceRootsFile: state.conformanceRootsFile,
		RuntimeRootsFile: state.runtimeRootsFile, Clock: sources.clock, Entropy: sources.entropy,
	})
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, fmt.Errorf("load production state proof: %w", err)
	}
	if verifier == nil {
		return nil, ErrInvalidConfiguration
	}

	client, clientErr := sources.newClient(stateappclient.CredentialFileConfig{
		Endpoint: state.endpoint, KeyID: state.readKeyID, RootKeyFile: state.readRootKeyFile,
		DispatchStartKeyID:       state.dispatchStartKeyID,
		DispatchStartRootKeyFile: state.dispatchStartRootKeyFile,
		Timeout:                  state.httpTimeout,
	})
	clientOwned := client != nil
	defer func() {
		if clientOwned {
			sources.closeClient(client)
		}
	}()
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if clientErr != nil {
		return nil, fmt.Errorf("construct state-app client: %w", clientErr)
	}
	if client == nil {
		return nil, ErrInvalidConfiguration
	}
	reader, err := sources.newReader(client)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, fmt.Errorf("construct session event reader: %w", err)
	}
	claimer, err := sources.newClaimer(client)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, fmt.Errorf("construct dispatch-start claimer: %w", err)
	}

	readerEvidence := evidence
	readerEvidence.Descriptor.AtomicGroups = append(
		[]dependency.AtomicGroup(nil), evidence.Descriptor.AtomicGroups...,
	)
	readerEvidence.Signature = append([]byte(nil), evidence.Signature...)
	claimerEvidence := evidence
	claimerEvidence.Descriptor.AtomicGroups = append(
		[]dependency.AtomicGroup(nil), evidence.Descriptor.AtomicGroups...,
	)
	claimerEvidence.Signature = append([]byte(nil), evidence.Signature...)
	readerRequirements := requirements
	readerRequirements.RequiredAtomicGroups = append(
		[]dependency.AtomicGroup(nil), requirements.RequiredAtomicGroups...,
	)
	claimerRequirements := requirements
	claimerRequirements.RequiredAtomicGroups = append(
		[]dependency.AtomicGroup(nil), requirements.RequiredAtomicGroups...,
	)
	verifiedReader, err := sources.verifyReader(
		ctx, verifier, reader, readerEvidence, readerRequirements,
	)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, fmt.Errorf("verify session event reader: %w", err)
	}
	verifiedClaimer, err := sources.verifyClaimer(
		ctx, verifier, claimer, claimerEvidence, claimerRequirements,
	)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, fmt.Errorf("verify dispatch-start claimer: %w", err)
	}
	descriptor, err := sources.requireDomain(
		[]dependency.AtomicGroup{
			dependency.AtomicCommandReceipt,
			dependency.AtomicEffectLifecycle,
		},
		verifiedReader,
		verifiedClaimer,
	)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, fmt.Errorf("verify joint state transaction domain: %w", err)
	}
	descriptor.AtomicGroups = append([]dependency.AtomicGroup(nil), descriptor.AtomicGroups...)
	result := &graph{
		sessionEventReader: verifiedReader, dispatchStartClaimer: verifiedClaimer,
		descriptor: descriptor, dispatchStartTimeout: state.dispatchStartTimeout,
		client: client, closeClient: sources.closeClient,
	}
	clientOwned = false
	return result, nil
}
