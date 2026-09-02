package workerd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hancomac/circulusd/internal/agent"
	"github.com/hancomac/circulusd/internal/conformance"
)

// resourceRunnerMaximumShards bounds the delegated cgroup subtree the runner
// asks the preflight to validate. The qualification composition creates only a
// few generation-derived leaves; this is not a product capacity.
const resourceRunnerMaximumShards = 4

var (
	// errResourceProbesNotImplemented is the sentinel a probe runner returns
	// when the live resource probes are not wired in this build. The runner
	// maps it to NOT_RUN (never PASS and never a silent skip-as-pass), matching
	// the status table's "runner is not implemented" row.
	errResourceProbesNotImplemented = errors.New("workerd resource qualification: live resource probes are not implemented in this runner build")
	errResourceRunnerInvalid        = errors.New("workerd resource qualification: runner precondition failed")
)

// resourceRunnerHostIdentity is the live host/boot identity bound into one run.
// Kernel is the running kernel release, HostBootID the current boot's 128-bit
// identity, and RunID a fresh 128-bit value per run.
type resourceRunnerHostIdentity struct {
	Kernel     string
	HostBootID string // 32 lowercase hex
	RunID      string // 32 lowercase hex
}

// resolvedResourceRelease is a resolved sealed release the probe runner drives.
// openExecutable duplicates the sealed snapshot for one launcher handoff; close
// releases the resolver-owned snapshot.
type resolvedResourceRelease struct {
	identity       resourceQualificationReleaseIdentity
	openExecutable func() (*os.File, error)
	close          func() error
}

// resourceProbeRunInput is everything a probe runner needs to drive the live
// qualification composition for one run.
type resourceProbeRunInput struct {
	config         resourceQualificationConfig
	release        resourceQualificationReleaseIdentity
	openExecutable func() (*os.File, error)
	fixture        resourceFixtureRendering
	provisioning   agent.WorkerdCgroupProvisioning
	host           resourceRunnerHostIdentity
}

// resourceProbeRunResult is what a probe runner reports after driving the
// composition. It records only observations and the run-scoped agent identity
// the live subsystems established; the orchestrator binds evidence and evaluates.
type resourceProbeRunResult struct {
	agentInstanceID string // 32 hex from the live Manager boot
	probes          []resourceProbeObservation
	cleanupComplete bool
}

// resourceProbeRunner drives the four required probes plus the recorded
// residual-gap probe against the live release, fixture, and cgroup boundary.
type resourceProbeRunner interface {
	Run(context.Context, resourceProbeRunInput) (resourceProbeRunResult, error)
}

// resourceRunnerBinding carries the runner's self-describing digests bound into
// every run's evidence.
type resourceRunnerBinding struct {
	runnerBinaryDigest   string
	sourceDigest         string
	probeInventoryDigest string
}

// resourceRunnerDeps injects the host- and release-dependent seams so the
// orchestration is host-independently testable. Production wiring is
// liveResourceRunnerDeps; tests substitute fakes.
type resourceRunnerDeps struct {
	now             func() time.Time
	hostIdentity    func() (resourceRunnerHostIdentity, error)
	resolveRelease  func(resourceQualificationConfig) (*resolvedResourceRelease, error)
	provisionCgroup func(agent.WorkerdCgroupConfig) agent.WorkerdCgroupProvisioning
	makeFixtureDir  func() (string, func(), error)
	probeRunner     resourceProbeRunner
	binding         resourceRunnerBinding
}

// runResourceQualification orchestrates one external resource qualification run:
// parse config, resolve the sealed release, preflight the delegated cgroup,
// materialize the private fixture, drive the probes, then bind, retain, and
// evaluate the evidence. Every failure maps to the fixed status table; a
// structural framing error (a runner bug) collapses to a uniform FAIL.
func runResourceQualification(ctx context.Context, deps resourceRunnerDeps, configPath string) conformance.Report {
	if configPath == "" || !filepath.IsAbs(configPath) ||
		filepath.Clean(configPath) != configPath || strings.ContainsRune(configPath, 0) {
		return uniformResourceReport(conformance.Fail, "qualification config path is not canonical and absolute")
	}
	rawConfig, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return uniformResourceReport(conformance.Unavailable, "qualification config is absent")
		}
		return uniformResourceReport(conformance.Fail, fmt.Sprintf("read qualification config: %v", err))
	}
	config, err := parseResourceQualificationConfig(bytes.NewReader(rawConfig))
	if err != nil {
		return uniformResourceReport(conformance.Fail, err.Error())
	}
	configDigest := "sha256:" + hexSHA256(rawConfig)

	release, err := deps.resolveRelease(config)
	if err != nil {
		if errors.Is(err, errResourceQualificationReleaseUnavailable) {
			return uniformResourceReport(conformance.Unavailable, err.Error())
		}
		return uniformResourceReport(conformance.Fail, err.Error())
	}
	defer func() { _ = release.close() }()

	provisioning := deps.provisionCgroup(resourceCgroupConfig(config))
	if !provisioning.Satisfied {
		if provisioning.HostUnavailable {
			return uniformResourceReport(conformance.Unavailable, provisioning.Reason)
		}
		return uniformResourceReport(conformance.Fail, provisioning.Reason)
	}

	fixtureDir, cleanupFixture, err := deps.makeFixtureDir()
	if err != nil {
		return uniformResourceReport(conformance.Fail, fmt.Sprintf("create fixture directory: %v", err))
	}
	defer cleanupFixture()
	fixture, err := materializeResourceQualificationFixture(fixtureDir, release.identity.workerdVersion)
	if err != nil {
		return uniformResourceReport(conformance.Fail, err.Error())
	}

	host, err := deps.hostIdentity()
	if err != nil {
		return uniformResourceReport(conformance.Fail, fmt.Sprintf("capture host identity: %v", err))
	}

	startedAt := deps.now().UTC()
	outcome, err := deps.probeRunner.Run(ctx, resourceProbeRunInput{
		config:         config,
		release:        release.identity,
		openExecutable: release.openExecutable,
		fixture:        fixture,
		provisioning:   provisioning,
		host:           host,
	})
	finishedAt := deps.now().UTC()
	if err != nil {
		switch {
		case errors.Is(err, errResourceProbesNotImplemented):
			return uniformResourceReport(conformance.NotRun, err.Error())
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return uniformResourceReport(conformance.NotRun, "qualification canceled before completion")
		default:
			return uniformResourceReport(conformance.Fail, err.Error())
		}
	}

	if err := validateResourceProbeSet(outcome.probes); err != nil {
		return uniformResourceReport(conformance.Fail, err.Error())
	}
	agentInstanceID, ok := normalizeResourceHexIdentity(outcome.agentInstanceID)
	if !ok {
		return uniformResourceReport(conformance.Fail, "probe runner returned an invalid agent instance identity")
	}

	binaryDigest, okBinary := normalizeSha256Digest(release.identity.extractedExecutableSHA256)
	archiveDigest, okArchive := normalizeSha256Digest(release.identity.archiveSHA256)
	manifestDigest, okManifest := normalizeSha256Digest(release.identity.manifestSigningDigest)
	runnerBinary, okRunner := normalizeSha256Digest(deps.binding.runnerBinaryDigest)
	sourceDigest, okSource := normalizeSha256Digest(deps.binding.sourceDigest)
	probeInventory, okInventory := normalizeSha256Digest(deps.binding.probeInventoryDigest)
	if !okBinary || !okArchive || !okManifest || !okRunner || !okSource || !okInventory {
		return uniformResourceReport(conformance.Fail, "release or runner identity carries a non-canonical digest")
	}
	environmentDigest := resourceEnvironmentDigest(fixture, probeInventory)

	envelope := resourceEvidenceEnvelope{
		RunID:              host.RunID,
		StartedAt:          startedAt,
		FinishedAt:         finishedAt,
		RunnerBinary:       runnerBinary,
		SourceDigest:       sourceDigest,
		FixtureDigest:      resourceFixtureDigest(fixture),
		ProbeInventory:     probeInventory,
		ReleaseManifest:    manifestDigest,
		ReleaseStatus:      release.identity.releaseStatus,
		Architecture:       config.Architecture,
		ArchiveDigest:      archiveDigest,
		ExtractionRecipe:   release.identity.extractionRecipe,
		ExecutableDigest:   binaryDigest,
		WorkerdVersion:     release.identity.workerdVersion,
		ConfigDigest:       configDigest,
		EnvironmentDigest:  environmentDigest,
		Kernel:             host.Kernel,
		HostBootID:         host.HostBootID,
		AgentInstanceID:    agentInstanceID,
		CgroupRootDevice:   provisioning.RootDevice,
		CgroupRootInode:    provisioning.RootInode,
		EnabledControllers: provisioning.EnabledControllers,
		Limits:             config.Limits,
		ColdStartSamples:   config.ColdStartSamples,
		Probes:             outcome.probes,
		CleanupComplete:    outcome.cleanupComplete,
	}
	encoded, observationDigest, err := encodeResourceEvidenceEnvelope(envelope)
	if err != nil {
		return uniformResourceReport(conformance.Fail, err.Error())
	}
	if _, err := retainResourceEvidence(config.EvidenceOutputDirectory, resourceObservationArtifactName, encoded); err != nil {
		return uniformResourceReport(conformance.Fail, err.Error())
	}

	results := bindResourceResults(outcome.probes, binaryDigest, environmentDigest, observationDigest, host.Kernel, config.Architecture)
	if _, framingErr := evaluateResourceQualificationRun(results); framingErr != nil {
		return uniformResourceReport(conformance.Fail, framingErr.Error())
	}
	return conformance.Report{SchemaVersion: 1, Results: results}
}

// uniformResourceReport reports the same terminal status and reason for every
// named component. It is the honest shape of a run that could not even begin
// its probes (config, release, cgroup, or host preflight failure).
func uniformResourceReport(status conformance.Status, reason string) conformance.Report {
	results := make([]conformance.Result, 0, len(resourceQualificationComponents))
	for _, component := range resourceQualificationComponents {
		results = append(results, conformance.Result{Component: component, Status: status, Reason: reason})
	}
	sort.Slice(results, func(left, right int) bool { return results[left].Component < results[right].Component })
	return conformance.Report{SchemaVersion: 1, Results: results}
}

// bindResourceResults binds each probe observation to the run evidence
// envelope. Every result carries external non-mock evidence with the run's
// binary, environment, and observation-artifact digests; the evaluator enforces
// the PASS-specific predicate on the required components and the honest-FAIL
// predicate on the recorded ones.
func bindResourceResults(probes []resourceProbeObservation, binaryDigest, environmentDigest, observationDigest, kernel, architecture string) []conformance.Result {
	byComponent := make(map[string]resourceProbeObservation, len(probes))
	for _, probe := range probes {
		byComponent[probe.Component] = probe
	}
	results := make([]conformance.Result, 0, len(resourceQualificationComponents))
	for _, component := range resourceQualificationComponents {
		probe := byComponent[component]
		results = append(results, conformance.Result{
			Component: component,
			Status:    probe.Status,
			Reason:    probe.Reason,
			Evidence: conformance.Evidence{
				Class:             conformance.EvidenceClassExternal,
				BinaryDigest:      binaryDigest,
				EnvironmentDigest: environmentDigest,
				Kernel:            kernel,
				Architecture:      architecture,
				ArtifactReferences: []conformance.ArtifactReference{
					{Name: resourceObservationArtifactName, Digest: observationDigest},
				},
			},
		})
	}
	sort.Slice(results, func(left, right int) bool { return results[left].Component < results[right].Component })
	return results
}

// validateResourceProbeSet requires the probe runner to have reported exactly
// the full component set once each. The evidence validator separately bounds
// each observation's timestamps and status.
func validateResourceProbeSet(probes []resourceProbeObservation) error {
	seen := make(map[string]struct{}, len(probes))
	for _, probe := range probes {
		if !isResourceQualificationComponent(probe.Component) {
			return fmt.Errorf("%w: probe runner reported unknown component %q", errResourceRunnerInvalid, probe.Component)
		}
		if _, duplicate := seen[probe.Component]; duplicate {
			return fmt.Errorf("%w: probe runner reported duplicate component %q", errResourceRunnerInvalid, probe.Component)
		}
		seen[probe.Component] = struct{}{}
	}
	for _, component := range resourceQualificationComponents {
		if _, found := seen[component]; !found {
			return fmt.Errorf("%w: probe runner did not report component %q", errResourceRunnerInvalid, component)
		}
	}
	return nil
}

func resourceCgroupConfig(config resourceQualificationConfig) agent.WorkerdCgroupConfig {
	return agent.WorkerdCgroupConfig{
		RootPath:       config.CgroupRootPath,
		MaximumShards:  resourceRunnerMaximumShards,
		DrainTimeout:   config.Timeouts.Drain,
		MemoryMaxBytes: config.Limits.MemoryMaxBytes,
		SwapMaxBytes:   config.Limits.MemorySwapMaxBytes,
		CPUMax: agent.CPUMax{
			QuotaMicros:  config.Limits.CPUMaxQuotaMicros,
			PeriodMicros: config.Limits.CPUMaxPeriodMicros,
		},
		PIDsMax: config.Limits.PIDsMax,
	}
}

func normalizeSha256Digest(value string) (string, bool) {
	trimmed := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "sha256:")
	if !sha256HexPattern.MatchString(trimmed) {
		return "", false
	}
	return "sha256:" + trimmed, true
}

func normalizeResourceHexIdentity(value string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(value))
	if !resourceEvidenceHexIdentity.MatchString(lower) {
		return "", false
	}
	return lower, true
}

func resourceEnvironmentDigest(fixture resourceFixtureRendering, probeInventoryDigest string) string {
	hash := sha256.New()
	for _, value := range []string{
		"workerd-resource-environment-v1",
		resourceQualificationCompatibilityDate,
		fixture.ArtifactDigest,
		fixture.ConfigDigest,
		fixture.EntryDigest,
		fixture.WorkerDigest,
		probeInventoryDigest,
	} {
		_, _ = hash.Write([]byte(fmt.Sprintf("%d:", len(value))))
		_, _ = hash.Write([]byte(value))
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func resourceFixtureDigest(fixture resourceFixtureRendering) string {
	hash := sha256.New()
	for _, value := range []string{
		fixture.ArtifactDigest,
		fixture.ConfigDigest,
		fixture.EntryDigest,
		fixture.WorkerDigest,
	} {
		_, _ = hash.Write([]byte(fmt.Sprintf("%d:", len(value))))
		_, _ = hash.Write([]byte(value))
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func resourceProbeInventoryDigest() string {
	hash := sha256.New()
	for _, component := range resourceQualificationComponents {
		role := "required"
		if isRecordedResourceQualificationComponent(component) {
			role = "recorded"
		}
		for _, value := range []string{"component", component, role} {
			_, _ = hash.Write([]byte(fmt.Sprintf("%d:", len(value))))
			_, _ = hash.Write([]byte(value))
		}
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func resourceSourceDigest() string {
	hash := sha256.New()
	for _, name := range []string{
		"fixture/phase0-resource.capnp.tmpl",
		"fixture/session-host-resource.mjs",
		"fixture/phase0-resource-entry.mjs",
	} {
		data, err := resourceFixtureFiles.ReadFile(name)
		if err != nil {
			data = []byte(name)
		}
		_, _ = hash.Write([]byte(fmt.Sprintf("%d:", len(data))))
		_, _ = hash.Write(data)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func resourceRunnerBinaryDigest() string {
	path, err := os.Executable()
	if err != nil {
		return resourceSourceDigest()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return resourceSourceDigest()
	}
	return "sha256:" + hexSHA256(data)
}

func defaultResourceRunnerBinding() resourceRunnerBinding {
	return resourceRunnerBinding{
		runnerBinaryDigest:   resourceRunnerBinaryDigest(),
		sourceDigest:         resourceSourceDigest(),
		probeInventoryDigest: resourceProbeInventoryDigest(),
	}
}

// liveResourceRunnerHostIdentity captures the running kernel, this boot's
// identity, and a fresh run identity from the live host.
func liveResourceRunnerHostIdentity() (resourceRunnerHostIdentity, error) {
	kernelRaw, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return resourceRunnerHostIdentity{}, fmt.Errorf("read kernel release: %w", err)
	}
	kernel := strings.TrimSpace(string(kernelRaw))
	if kernel == "" {
		return resourceRunnerHostIdentity{}, errors.New("kernel release is empty")
	}
	bootRaw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return resourceRunnerHostIdentity{}, fmt.Errorf("read boot id: %w", err)
	}
	boot := strings.ReplaceAll(strings.TrimSpace(string(bootRaw)), "-", "")
	if !resourceEvidenceHexIdentity.MatchString(boot) {
		return resourceRunnerHostIdentity{}, errors.New("boot id is not a 128-bit hex value")
	}
	var runBytes [16]byte
	if _, err := rand.Read(runBytes[:]); err != nil {
		return resourceRunnerHostIdentity{}, fmt.Errorf("generate run id: %w", err)
	}
	return resourceRunnerHostIdentity{
		Kernel:     kernel,
		HostBootID: boot,
		RunID:      hex.EncodeToString(runBytes[:]),
	}, nil
}

func makePrivateResourceFixtureDir() (string, func(), error) {
	dir, err := os.MkdirTemp("", "cq")
	if err != nil {
		return "", nil, err
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

// notImplementedResourceProbeRunner is the honest placeholder until the live
// probes land: it never fabricates a PASS, so the gate reports NOT_RUN.
type notImplementedResourceProbeRunner struct{}

func (notImplementedResourceProbeRunner) Run(context.Context, resourceProbeRunInput) (resourceProbeRunResult, error) {
	return resourceProbeRunResult{}, errResourceProbesNotImplemented
}

// liveResourceRunnerDeps wires the production host, release, cgroup, fixture,
// and probe seams. The probe runner is the honest not-implemented placeholder
// until the live probes are wired in a later slice.
func liveResourceRunnerDeps() resourceRunnerDeps {
	return resourceRunnerDeps{
		now:          time.Now,
		hostIdentity: liveResourceRunnerHostIdentity,
		resolveRelease: func(config resourceQualificationConfig) (*resolvedResourceRelease, error) {
			resolved, err := resolveResourceQualificationRelease(config)
			if err != nil {
				return nil, err
			}
			return &resolvedResourceRelease{
				identity:       resolved.identitySnapshot(),
				openExecutable: resolved.openExecutableSnapshot,
				close:          resolved.close,
			}, nil
		},
		provisionCgroup: agent.ProbeWorkerdCgroupProvisioning,
		makeFixtureDir:  makePrivateResourceFixtureDir,
		probeRunner:     liveResourceProbeRunner{},
		binding:         defaultResourceRunnerBinding(),
	}
}
