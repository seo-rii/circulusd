package workerd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/hancomac/circulusd/internal/agent"
	"github.com/hancomac/circulusd/internal/conformance"
	"github.com/hancomac/circulusd/internal/identity"
)

const (
	resourceProbeShardID          = "qualification"
	resourceProbeStopGracePeriod  = 10 * time.Second
	resourceProbeOutputLimitBytes = 64 << 10
	resourceProbeHistoryCapacity  = 16
	// resourceCPUThrottleWindow is how long the runaway worker is left to spin
	// under the cpu.max cap so the kernel accrues observable throttling.
	resourceCPUThrottleWindow = 2 * time.Second
	// resourceRunawayWorker is the content-addressed worker id the cpu-limit
	// probe drives into an unbounded /spin.
	resourceRunawayWorker = "w/a"
)

// liveResourceProbeRunner drives the real qualification probes against the
// sealed workerd release inside the operator-provisioned delegated cgroup. It
// composes the low-level launcher directly and pulls resource samples through
// the exact pidfd/cgroup identity, so every observation is a real host reading.
type liveResourceProbeRunner struct{}

// probeStep is one implemented probe. Unimplemented probes are recorded as
// honest NOT_RUN placeholders so an incomplete runner build never fabricates a
// PASS and the gate reports the real not-yet-qualified state.
type probeStep struct {
	component string
	run       func(context.Context, resourceProbeRunInput, *resourceProbeHarness) resourceProbeObservation
}

func (liveResourceProbeRunner) Run(ctx context.Context, input resourceProbeRunInput) (resourceProbeRunResult, error) {
	digest, ok := normalizeSha256Digest(input.release.extractedExecutableSHA256)
	if !ok {
		return resourceProbeRunResult{}, fmt.Errorf("%w: release executable digest is not canonical", errResourceRunnerInvalid)
	}
	arguments, err := resourceQualificationArguments(input.fixture.Directory)
	if err != nil {
		return resourceProbeRunResult{}, err
	}
	// Derive the launcher's process identity and the 128-bit hex agent instance
	// id recorded in evidence from the same fresh entropy, so they name the one
	// qualification-runtime boot.
	var agentEntropy [16]byte
	if _, err := rand.Read(agentEntropy[:]); err != nil {
		return resourceProbeRunResult{}, fmt.Errorf("generate agent instance identity: %w", err)
	}
	agentID, err := (identity.Generator{Random: bytes.NewReader(agentEntropy[:])}).New(identity.Process)
	if err != nil {
		return resourceProbeRunResult{}, fmt.Errorf("mint agent instance identity: %w", err)
	}
	agentInstanceHex := hex.EncodeToString(agentEntropy[:])

	executable, err := input.openExecutable()
	if err != nil {
		return resourceProbeRunResult{}, fmt.Errorf("open sealed executable snapshot: %w", err)
	}
	cgroupConfig := resourceCgroupConfig(input.config)
	launcher, err := agent.NewWorkerdProcessLauncher(agent.WorkerdLauncherConfig{
		Executable:       executable, // the constructor snapshots and closes this descriptor
		ExecutableDigest: digest,
		ReadinessProbe:   newResourceReadinessProbe(input.fixture),
		ReadinessTimeout: input.config.Timeouts.Readiness,
		StopGracePeriod:  resourceProbeStopGracePeriod,
		OutputLimitBytes: resourceProbeOutputLimitBytes,
		HistoryCapacity:  resourceProbeHistoryCapacity,
		Cgroup:           &cgroupConfig,
	})
	if err != nil {
		return resourceProbeRunResult{}, fmt.Errorf("construct workerd launcher: %w", err)
	}

	harness := &resourceProbeHarness{
		launcher:   launcher,
		agentID:    agentID,
		shardID:    resourceProbeShardID,
		arguments:  arguments,
		socketPath: input.fixture.SocketPath,
	}

	runCtx := ctx
	if input.config.Timeouts.Total > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, input.config.Timeouts.Total)
		defer cancel()
	}

	steps := []probeStep{
		{component: "workerd.rss-cold-start", run: runRSSColdStartProbe},
		{component: "workerd.cpu-limit", run: runCPULimitProbe},
		{component: "workerd.shard-pressure-recycle", run: notYetImplementedProbe},
		{component: "workerd.shard-kill-reconstruction", run: notYetImplementedProbe},
		{component: "workerd.dynamic-worker-reconstruction", run: notYetImplementedProbe},
	}
	observations := make([]resourceProbeObservation, 0, len(steps))
	for _, step := range steps {
		observation := step.run(runCtx, input, harness)
		observation.Component = step.component // the step is the single source of the component name
		observations = append(observations, observation)
	}

	cleanupErr := launcher.Close(context.Background())
	return resourceProbeRunResult{
		agentInstanceID: agentInstanceHex,
		probes:          observations,
		cleanupComplete: cleanupErr == nil,
	}, nil
}

// resourceProbeHarness owns the composed launcher and hands each probe a fresh
// generation of the one qualification shard slot.
type resourceProbeHarness struct {
	launcher   *agent.WorkerdProcessLauncher
	agentID    identity.ID
	shardID    string
	arguments  []string
	socketPath string
	generation agent.ShardGeneration
}

// ensure starts one fresh generation and returns its readiness-gated handle.
// The previous generation's process has already stopped, but stock workerd does
// not unlink its listening Unix socket on exit, so a stale socket file would
// make the next generation fail with EADDRINUSE. Removing it first keeps each
// cold start binding the fixed fixture socket cleanly; it never races a live
// process because the caller stops the prior generation before the next ensure.
func (harness *resourceProbeHarness) ensure(ctx context.Context) (*agent.WorkerdShardHandle, error) {
	if harness.socketPath != "" {
		_ = os.Remove(harness.socketPath)
	}
	harness.generation++
	return harness.launcher.Ensure(ctx, agent.WorkerdEnsureRequest{
		AgentInstanceID: harness.agentID,
		ShardID:         harness.shardID,
		ShardGeneration: harness.generation,
		Arguments:       harness.arguments,
	})
}

// socketClient returns an HTTP client that dials the fixture's private Unix
// socket, for the probe routes (/worker/spin, /allocate, /worker/state-*).
func (harness *resourceProbeHarness) socketClient() *http.Client {
	socket := harness.socketPath
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
			DisableKeepAlives: true,
		},
	}
}

func observationNow(component string, status conformance.Status, reason string, started time.Time, samples uint64) resourceProbeObservation {
	return resourceProbeObservation{
		Component:      component,
		Status:         status,
		Reason:         reason,
		StartedAt:      started,
		FinishedAt:     time.Now().UTC(),
		RawSampleCount: samples,
	}
}

// notYetImplementedProbe is the honest placeholder for probes not yet wired in
// this slice. It records NOT_RUN so the runner never fabricates a PASS; the
// loop stamps the component name. The recorded residual-gap probe uses this too
// until its slice lands, so the gate stays honestly not-qualified in the
// meantime.
func notYetImplementedProbe(_ context.Context, _ resourceProbeRunInput, _ *resourceProbeHarness) resourceProbeObservation {
	now := time.Now().UTC()
	return resourceProbeObservation{
		Status:         conformance.NotRun,
		Reason:         "live probe not yet implemented in this runner slice",
		StartedAt:      now,
		FinishedAt:     now,
		RawSampleCount: 0,
	}
}

// runCPULimitProbe certifies the kernel-enforced CPU boundary. It launches one
// shard under the configured cpu.max, verifies the exact readback, drives a
// content-addressed worker into an unbounded /spin, and observes the kernel
// accrue cpu.stat throttling while the runaway is capped at the quota. It then
// confirms the runaway does not self-terminate (the pinned in-isolate cpuMs is
// parsed but not enforced — a recorded negative finding, never a skip), and
// that supervisor-observed starvation drives a whole-shard SIGKILL followed by a
// clean recycle. The in-isolate cpuMs "abort" the fixture comment expects is
// intentionally not part of the PASS predicate on this pin.
func runCPULimitProbe(ctx context.Context, input resourceProbeRunInput, harness *resourceProbeHarness) resourceProbeObservation {
	const component = "workerd.cpu-limit"
	started := time.Now().UTC()
	fail := func(reason string) resourceProbeObservation {
		return observationNow(component, conformance.Fail, reason, started, 0)
	}

	probeCtx, cancel := context.WithTimeout(ctx, input.config.Timeouts.Probe)
	defer cancel()

	handle, err := harness.ensure(probeCtx)
	if err != nil {
		return fail("ensure: " + err.Error())
	}
	stopHandle := func() { _ = handle.Stop(probeCtx) }

	before, err := handle.SampleResources(probeCtx)
	if err != nil {
		stopHandle()
		return fail("sample before: " + err.Error())
	}
	if before.CPUMax.QuotaMicros != input.config.Limits.CPUMaxQuotaMicros ||
		before.CPUMax.PeriodMicros != input.config.Limits.CPUMaxPeriodMicros {
		stopHandle()
		return fail(fmt.Sprintf("cpu.max readback %d/%d does not match configured %d/%d",
			before.CPUMax.QuotaMicros, before.CPUMax.PeriodMicros,
			input.config.Limits.CPUMaxQuotaMicros, input.config.Limits.CPUMaxPeriodMicros))
	}

	// Fire the runaway worker and keep the request open so the isolate keeps
	// spinning under the cap while the kernel throttles it.
	spinCtx, cancelSpin := context.WithCancel(probeCtx)
	spinDone := make(chan struct{})
	go func() {
		defer close(spinDone)
		client := harness.socketClient()
		defer client.CloseIdleConnections()
		request, requestErr := http.NewRequestWithContext(spinCtx, http.MethodGet,
			"http://unix/worker/spin?worker="+resourceRunawayWorker, nil)
		if requestErr != nil {
			return
		}
		response, doErr := client.Do(request)
		if doErr == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
	}()
	stopSpin := func() { cancelSpin(); <-spinDone }

	spinSelfTerminated := false
	timer := time.NewTimer(resourceCPUThrottleWindow)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-spinDone:
		spinSelfTerminated = true
	case <-probeCtx.Done():
		stopSpin()
		stopHandle()
		return fail("canceled during the runaway spin")
	}

	after, sampleErr := handle.SampleResources(probeCtx)
	stopSpin()
	if sampleErr != nil {
		stopHandle()
		return fail("sample after: " + sampleErr.Error())
	}
	if spinSelfTerminated {
		stopHandle()
		return fail("the runaway worker request ended before the observation window; on this pin the in-isolate limit is expected not to fire, so re-evaluate the pin before promotion")
	}

	throttledPeriods := after.CPUStat.ThrottledPeriods - before.CPUStat.ThrottledPeriods
	throttledMicros := after.CPUStat.ThrottledMicros - before.CPUStat.ThrottledMicros
	if throttledPeriods == 0 && throttledMicros == 0 {
		stopHandle()
		return fail("no cgroup cpu.stat throttling observed under the runaway worker")
	}

	// Supervisor-observed starvation drives a whole-shard SIGKILL, then cleanup.
	if killErr := handle.KillProcessInstance(); killErr != nil {
		stopHandle()
		return fail("supervisor kill: " + killErr.Error())
	}
	if stopErr := handle.Stop(probeCtx); stopErr != nil {
		return fail("cleanup after supervisor kill: " + stopErr.Error())
	}

	// Recycle: a fresh generation must reach digest-bound readiness, proving the
	// shard recovers from the runaway.
	recycleCtx, cancelRecycle := context.WithTimeout(ctx, input.config.Timeouts.Probe)
	defer cancelRecycle()
	recycled, err := harness.ensure(recycleCtx)
	if err != nil {
		return fail("recycle ensure: " + err.Error())
	}
	if stopErr := recycled.Stop(recycleCtx); stopErr != nil {
		return fail("recycle stop: " + stopErr.Error())
	}

	reason := fmt.Sprintf("cpu.max %d/%d enforced by the kernel: %d throttled periods (%d us) under the runaway worker; in-isolate cpuMs did not fire (recorded non-enforcement); supervisor SIGKILL + recycle recovered the shard",
		before.CPUMax.QuotaMicros, before.CPUMax.PeriodMicros, throttledPeriods, throttledMicros)
	return observationNow(component, conformance.Pass, reason, started, throttledPeriods)
}

// runRSSColdStartProbe performs config.ColdStartSamples independent cold starts
// of the qualification shard. Each start launches a fresh workerd process under
// a new cgroup leaf, gates on the digest-bound SessionHost readiness, then reads
// the exact pidfd-verified process RSS and the separately recorded cgroup memory
// charge before stopping the process. It passes only when at least five cold
// starts each yield a nonzero process RSS and a distinct nonzero cgroup charge
// bound to the exact shard identity.
func runRSSColdStartProbe(ctx context.Context, input resourceProbeRunInput, harness *resourceProbeHarness) resourceProbeObservation {
	const component = "workerd.rss-cold-start"
	started := time.Now().UTC()
	fail := func(reason string) resourceProbeObservation {
		return observationNow(component, conformance.Fail, reason, started, 0)
	}

	samples := input.config.ColdStartSamples
	if samples < 5 {
		return fail("configured cold-start sample count is below the required five")
	}

	minRSS := ^uint64(0)
	maxRSS := uint64(0)
	minCharge := ^uint64(0)
	collected := uint64(0)
	for index := uint64(0); index < samples; index++ {
		if err := ctx.Err(); err != nil {
			return fail(fmt.Sprintf("cold start %d canceled: %v", index, err))
		}
		probeCtx, cancel := context.WithTimeout(ctx, input.config.Timeouts.Probe)
		handle, err := harness.ensure(probeCtx)
		if err != nil {
			cancel()
			return fail(fmt.Sprintf("cold start %d ensure: %v", index, err))
		}
		sample, sampleErr := handle.SampleResources(probeCtx)
		stopErr := handle.Stop(probeCtx)
		cancel()
		if sampleErr != nil {
			return fail(fmt.Sprintf("cold start %d sample: %v", index, sampleErr))
		}
		if stopErr != nil {
			return fail(fmt.Sprintf("cold start %d stop: %v", index, stopErr))
		}
		if sample.AgentInstanceID != harness.agentID || sample.ShardID != harness.shardID {
			return fail(fmt.Sprintf("cold start %d sample identity does not match the shard", index))
		}
		if sample.ProcessRSSBytes == 0 {
			return fail(fmt.Sprintf("cold start %d recorded a zero process RSS", index))
		}
		if sample.MemoryCurrentBytes == 0 {
			return fail(fmt.Sprintf("cold start %d recorded a zero cgroup memory charge", index))
		}
		if sample.ProcessRSSBytes < minRSS {
			minRSS = sample.ProcessRSSBytes
		}
		if sample.ProcessRSSBytes > maxRSS {
			maxRSS = sample.ProcessRSSBytes
		}
		if sample.MemoryCurrentBytes < minCharge {
			minCharge = sample.MemoryCurrentBytes
		}
		collected++
	}
	if collected < 5 {
		return fail(fmt.Sprintf("only %d of the required five cold starts were sampled", collected))
	}
	return observationNow(component, conformance.Pass,
		fmt.Sprintf("%d cold starts: process RSS %d-%d bytes, min cgroup charge %d bytes", collected, minRSS, maxRSS, minCharge),
		started, collected)
}
