package workerd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	// resourceInIsolateFaultWindow bounds how long the recorded-gap probe waits
	// for the pinned in-isolate cpuMs limit to abort a runaway isolate. On this
	// pin it never does, which is the recorded FAIL.
	resourceInIsolateFaultWindow = 4 * time.Second
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
		{component: "workerd.shard-pressure-recycle", run: runShardPressureRecycleProbe},
		{component: "workerd.shard-kill-reconstruction", run: runShardKillReconstructionProbe},
		{component: "workerd.dynamic-worker-reconstruction", run: runDynamicWorkerReconstructionProbe},
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

// workerStateResponse is the bounded JSON the fixture's Dynamic Worker routes
// return. Only the fields the reconstruction probes read are decoded.
type workerStateResponse struct {
	InitializationInstance string `json:"initializationInstance"`
	CheckpointBase64       string `json:"checkpointBase64"`
	RestoredValue          string `json:"restoredValue"`
}

// readInitInstance returns the worker's current module-local initialization
// instance, lazily initializing the isolate on first call.
func (harness *resourceProbeHarness) readInitInstance(ctx context.Context, worker string) (string, error) {
	data, status, err := harness.call(ctx, http.MethodGet, "/worker/initialization-instance?worker="+worker, nil)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("status %d", status)
	}
	var response workerStateResponse
	if jsonErr := json.Unmarshal(data, &response); jsonErr != nil {
		return "", jsonErr
	}
	if response.InitializationInstance == "" {
		return "", fmt.Errorf("empty initialization instance")
	}
	return response.InitializationInstance, nil
}

const maximumResourceProbeBodyBytes = 1 << 20

// call performs one bounded request to a fixture probe route and returns the
// body and status. It is used for the state, initialization-instance, and
// allocate routes; the long-lived /spin request is driven separately.
func (harness *resourceProbeHarness) call(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	client := harness.socketClient()
	defer client.CloseIdleConnections()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, reader)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		request.Header.Set("content-type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maximumResourceProbeBodyBytes+1))
	if err != nil {
		return nil, response.StatusCode, err
	}
	if len(data) > maximumResourceProbeBodyBytes {
		return nil, response.StatusCode, fmt.Errorf("worker response exceeds %d bytes", maximumResourceProbeBodyBytes)
	}
	return data, response.StatusCode, nil
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

// runReconstructionProbe is the shared destructive-fault reconstruction proof
// for the shard-level probes. It commits the worker's retained state to the
// external acknowledged checkpoint store, gates the fault on acknowledgement,
// injects the caller's destructive fault, drains the faulted shard, then brings
// up a fresh generation and requires (a) a genuinely new initialization instance
// — a new isolate, which only whole-shard destruction produces on this pin —
// and (b) that the acknowledged checkpoint replays the exact committed state.
func runReconstructionProbe(
	ctx context.Context,
	input resourceProbeRunInput,
	harness *resourceProbeHarness,
	component, worker, faultLabel string,
	injectFault func(context.Context, *agent.WorkerdShardHandle) (string, error),
) resourceProbeObservation {
	started := time.Now().UTC()
	fail := func(reason string) resourceProbeObservation {
		return observationNow(component, conformance.Fail, reason, started, 0)
	}
	store := newWorkerdCheckpointStore()

	probeCtx, cancel := context.WithTimeout(ctx, input.config.Timeouts.Probe)
	defer cancel()

	handle, err := harness.ensure(probeCtx)
	if err != nil {
		return fail("ensure: " + err.Error())
	}

	initData, status, err := harness.call(probeCtx, http.MethodPost, "/worker/state-init?worker="+worker, nil)
	if err != nil || status != http.StatusOK {
		_ = handle.Stop(probeCtx)
		return fail(fmt.Sprintf("state-init (status %d): %v", status, err))
	}
	var initResp workerStateResponse
	if jsonErr := json.Unmarshal(initData, &initResp); jsonErr != nil ||
		initResp.InitializationInstance == "" || initResp.CheckpointBase64 == "" {
		_ = handle.Stop(probeCtx)
		return fail("state-init response is malformed")
	}
	firstInstance := initResp.InitializationInstance
	expectedValue := "state-" + firstInstance

	ack, err := store.commit(worker, []byte(initResp.CheckpointBase64))
	if err != nil {
		_ = handle.Stop(probeCtx)
		return fail("commit checkpoint: " + err.Error())
	}
	if ackErr := store.requireAcknowledged(worker, ack.Digest); ackErr != nil {
		_ = handle.Stop(probeCtx)
		return fail("checkpoint not acknowledged before fault: " + ackErr.Error())
	}

	faultDetail, faultErr := injectFault(probeCtx, handle)
	if faultErr != nil {
		_ = handle.Stop(probeCtx)
		return fail(faultLabel + ": " + faultErr.Error())
	}
	if stopErr := handle.Stop(probeCtx); stopErr != nil {
		return fail("drain after " + faultLabel + ": " + stopErr.Error())
	}

	reconCtx, cancelRecon := context.WithTimeout(ctx, input.config.Timeouts.Probe)
	defer cancelRecon()
	recon, err := harness.ensure(reconCtx)
	if err != nil {
		return fail("reconstruct ensure: " + err.Error())
	}
	stopRecon := func() { _ = recon.Stop(reconCtx) }

	instData, status, err := harness.call(reconCtx, http.MethodGet, "/worker/initialization-instance?worker="+worker, nil)
	if err != nil || status != http.StatusOK {
		stopRecon()
		return fail(fmt.Sprintf("read reconstructed initialization instance (status %d): %v", status, err))
	}
	var instResp workerStateResponse
	if jsonErr := json.Unmarshal(instData, &instResp); jsonErr != nil || instResp.InitializationInstance == "" {
		stopRecon()
		return fail("reconstructed initialization instance response is malformed")
	}
	if instResp.InitializationInstance == firstInstance {
		stopRecon()
		return fail(fmt.Sprintf("initialization instance %s unchanged after %s; no reconstruction", firstInstance, faultLabel))
	}

	acknowledged, err := store.acknowledged(worker)
	if err != nil {
		stopRecon()
		return fail("reload acknowledged checkpoint: " + err.Error())
	}
	loadBody, _ := json.Marshal(map[string]string{"checkpointBase64": string(acknowledged.Payload)})
	loadData, status, err := harness.call(reconCtx, http.MethodPost, "/worker/state-load?worker="+worker, loadBody)
	if err != nil || status != http.StatusOK {
		stopRecon()
		return fail(fmt.Sprintf("state-load (status %d): %v", status, err))
	}
	var loadResp workerStateResponse
	if jsonErr := json.Unmarshal(loadData, &loadResp); jsonErr != nil {
		stopRecon()
		return fail("state-load response is malformed")
	}
	if loadResp.RestoredValue != expectedValue {
		stopRecon()
		return fail(fmt.Sprintf("restored value %q does not match the committed state %q", loadResp.RestoredValue, expectedValue))
	}
	stopRecon()

	detailSuffix := ""
	if faultDetail != "" {
		detailSuffix = " [" + faultDetail + "]"
	}
	return observationNow(component, conformance.Pass,
		fmt.Sprintf("%s%s forced a new isolate (init %s->%s); acknowledged checkpoint seq %d replayed value %q",
			faultLabel, detailSuffix, firstInstance, instResp.InitializationInstance, acknowledged.Sequence, loadResp.RestoredValue),
		started, 1)
}

// runShardKillReconstructionProbe injects an explicit whole-shard SIGKILL as the
// destructive fault, then reconstructs from the acknowledged checkpoint.
func runShardKillReconstructionProbe(ctx context.Context, input resourceProbeRunInput, harness *resourceProbeHarness) resourceProbeObservation {
	return runReconstructionProbe(ctx, input, harness,
		"workerd.shard-kill-reconstruction", "w/kill", "whole-shard SIGKILL",
		func(_ context.Context, handle *agent.WorkerdShardHandle) (string, error) {
			return "", handle.KillProcessInstance()
		})
}

// runShardPressureRecycleProbe drives real cgroup memory pressure into an OOM by
// growing SessionHost memory through /allocate until the kernel reclaims at
// memory.max and OOM-kills the shard, then reconstructs from the acknowledged
// checkpoint. Allocation proceeds in bounded increments with a sample after
// each, so the climb toward memory.max and the terminal OOM are observed on the
// live process before its death is inferred from the failed request/sample.
func runShardPressureRecycleProbe(ctx context.Context, input resourceProbeRunInput, harness *resourceProbeHarness) resourceProbeObservation {
	const (
		worker         = "w/pressure"
		allocationStep = 16 // MiB per /allocate call
		maxAllocations = 512
	)
	return runReconstructionProbe(ctx, input, harness,
		"workerd.shard-pressure-recycle", worker, "cgroup OOM",
		func(faultCtx context.Context, handle *agent.WorkerdShardHandle) (string, error) {
			baseline, err := handle.SampleResources(faultCtx)
			if err != nil {
				return "", fmt.Errorf("baseline sample: %w", err)
			}
			memoryMax := input.config.Limits.MemoryMaxBytes
			peakCurrent := baseline.MemoryCurrentBytes
			maxPressureDelta := uint64(0)
			oomObserved := false
			body, _ := json.Marshal(map[string]int{"mebibytes": allocationStep})
			for allocation := 0; allocation < maxAllocations; allocation++ {
				if faultCtx.Err() != nil {
					return "", faultCtx.Err()
				}
				_, status, callErr := harness.call(faultCtx, http.MethodPost, "/allocate", body)
				if callErr != nil {
					oomObserved = true // the request died mid-allocation: OOM-killed
					break
				}
				if status != http.StatusOK {
					return "", fmt.Errorf("allocate rejected: status %d", status)
				}
				sample, sampleErr := handle.SampleResources(faultCtx)
				if sampleErr != nil {
					oomObserved = true // the process is gone: OOM-killed
					break
				}
				if sample.MemoryCurrentBytes > peakCurrent {
					peakCurrent = sample.MemoryCurrentBytes
				}
				if delta := sample.MemoryEvents.Max - baseline.MemoryEvents.Max; delta > maxPressureDelta {
					maxPressureDelta = delta
				}
				if sample.MemoryEvents.OOMKill > baseline.MemoryEvents.OOMKill ||
					sample.MemoryEvents.OOM > baseline.MemoryEvents.OOM {
					oomObserved = true
					break
				}
			}
			// Require genuine pressure: either counted reclaim events at the
			// limit, or an OOM corroborated by memory.current having climbed to
			// at least three quarters of the cap (so a transient early failure
			// is never mislabeled as OOM).
			climbedNearMax := peakCurrent >= memoryMax/4*3
			if maxPressureDelta == 0 && !(oomObserved && climbedNearMax) {
				return "", fmt.Errorf("insufficient cgroup memory pressure: peak memory.current %d of max %d, events.max +%d, oom=%v",
					peakCurrent, memoryMax, maxPressureDelta, oomObserved)
			}
			// The faulted process may already be dead (OOM) or still alive after
			// reclaim pressure; force the whole-shard kill so the drain+recycle
			// deterministically yields a fresh isolate either way.
			_ = handle.KillProcessInstance()
			return fmt.Sprintf("peak memory.current %d of max %d bytes, memory.events.max +%d, oom-killed=%v",
				peakCurrent, memoryMax, maxPressureDelta, oomObserved), nil
		})
}

// runDynamicWorkerReconstructionProbe records the documented residual gap: stock
// workerd does not reconstruct a Worker Loader isolate after an in-isolate
// fault. It initializes one worker, captures its initialization instance, then
// drives the designated in-isolate destructive fault — the cpuMs runaway that a
// compliant runtime would abort and reconstruct. On this pin the runaway is
// never aborted within its window (cpuMs is parsed but not enforced) and no
// reconstruction occurs, so the probe records FAIL. It returns FAIL for every
// non-reconstruction outcome and only ever returns PASS if the isolate is
// genuinely reconstructed with a new instance — which cannot happen on this pin
// and deliberately triggers the run-level evaluator's framing error so a human
// re-scopes or re-pins rather than silently promoting.
func runDynamicWorkerReconstructionProbe(ctx context.Context, input resourceProbeRunInput, harness *resourceProbeHarness) resourceProbeObservation {
	const component = "workerd.dynamic-worker-reconstruction"
	const worker = "w/dwr"
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
	defer func() {
		stopCtx, cancelStop := context.WithTimeout(context.Background(), resourceProbeStopGracePeriod+2*time.Second)
		_ = handle.Stop(stopCtx)
		cancelStop()
	}()

	firstInstance, err := harness.readInitInstance(probeCtx, worker)
	if err != nil {
		return fail("read initialization instance: " + err.Error())
	}

	// Attempt the designated in-isolate destructive fault: the cpuMs runaway.
	faultCtx, cancelFault := context.WithTimeout(probeCtx, resourceInIsolateFaultWindow)
	_, status, spinErr := harness.call(faultCtx, http.MethodGet, "/worker/spin?worker="+worker, nil)
	faultTimedOut := faultCtx.Err() != nil
	cancelFault()

	if spinErr != nil {
		if faultTimedOut {
			return fail(fmt.Sprintf("stock workerd did not enforce the in-isolate cpuMs limit: the runaway worker %q was not aborted within %s, so the isolate is never destroyed or reconstructed (pre-fault initialization instance %s)",
				worker, resourceInIsolateFaultWindow, firstInstance))
		}
		return fail("in-isolate fault request failed: " + spinErr.Error())
	}

	// The runaway returned — unexpected on this pin. Check for reconstruction.
	secondInstance, err := harness.readInitInstance(probeCtx, worker)
	if err != nil {
		return fail(fmt.Sprintf("runaway returned (status %d) but reading the post-fault initialization instance failed: %v", status, err))
	}
	if secondInstance != firstInstance {
		// A genuine per-isolate reconstruction, impossible on this pin. Report
		// PASS so evaluateResourceQualificationRun raises its framing error.
		return observationNow(component, conformance.Pass,
			fmt.Sprintf("UNEXPECTED on this pin: the in-isolate fault reconstructed the isolate for worker %q (initialization instance %s->%s); Unit 10 must be re-scoped or re-pinned",
				worker, firstInstance, secondInstance),
			started, 1)
	}
	return fail(fmt.Sprintf("the in-isolate fault returned (status %d) but the isolate survived with an identical initialization instance %s; stock workerd does not reconstruct a faulted isolate",
		status, firstInstance))
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
