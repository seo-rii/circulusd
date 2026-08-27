package workerd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/conformance"
)

func TestRunReportsEveryRequiredProbeUnavailableWhenWorkerdIsMissing(t *testing.T) {
	t.Parallel()

	harness, err := New(testConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	harness.lookPath = func(string) (string, error) { return "", fs.ErrNotExist }
	var commands atomic.Int32
	harness.runCommand = func(context.Context, string, []string, string) commandOutput {
		commands.Add(1)
		return commandOutput{}
	}

	first := harness.Run(t.Context())
	second := harness.Run(t.Context())
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Run() is nondeterministic:\nfirst:  %+v\nsecond: %+v", first, second)
	}
	if commands.Load() != 0 {
		t.Fatalf("commands = %d, want 0", commands.Load())
	}
	assertUniformResults(t, first, conformance.Unavailable, "workerd executable is unavailable")
}

func TestRunRejectsAnUnpinnedBinaryWithoutExecutingIt(t *testing.T) {
	t.Parallel()

	binary := writeExecutable(t, []byte("not the pinned workerd"))
	config := testConfig()
	config.BinaryPath = binary
	harness, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	var commands atomic.Int32
	harness.runCommand = func(context.Context, string, []string, string) commandOutput {
		commands.Add(1)
		return commandOutput{}
	}

	report := harness.Run(t.Context())
	if commands.Load() != 0 {
		t.Fatalf("commands = %d, want 0", commands.Load())
	}
	assertUniformResults(t, report, conformance.Fail, "workerd binary digest does not match the release pin")
	actual := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("not the pinned workerd")))
	for _, result := range report.Results {
		if result.Evidence.BinaryDigest != actual || result.Evidence.Mock {
			t.Fatalf("result evidence = %+v, want actual non-mock digest %q", result.Evidence, actual)
		}
	}
}

func TestRunRequiresThePinnedVersionBeforeExecutingProbes(t *testing.T) {
	t.Parallel()

	contents := []byte("fake workerd")
	binary := writeExecutable(t, contents)
	config := testConfig()
	config.BinaryPath = binary
	config.ExpectedBinaryDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(contents))
	harness, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	var commands atomic.Int32
	harness.runCommand = func(_ context.Context, _ string, arguments []string, _ string) commandOutput {
		commands.Add(1)
		if !reflect.DeepEqual(arguments, []string{"--version"}) {
			t.Fatalf("arguments = %q, want version probe", arguments)
		}
		return commandOutput{stdout: []byte("workerd 1900-01-01\n")}
	}

	report := harness.Run(t.Context())
	if commands.Load() != 1 {
		t.Fatalf("commands = %d, want 1", commands.Load())
	}
	assertUniformResults(t, report, conformance.Fail, "workerd version does not match the release pin")
}

func TestRunAcceptsThePinnedWorkerdVerifiedFDVersionDiagnostic(t *testing.T) {
	t.Parallel()

	contents := []byte("fake pinned workerd")
	binary := writeExecutable(t, contents)
	config := testConfig()
	config.BinaryPath = binary
	config.ExpectedBinaryDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(contents))
	harness, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	harness.runCommand = func(_ context.Context, _ string, arguments []string, _ string) commandOutput {
		if reflect.DeepEqual(arguments, []string{"--version"}) {
			return commandOutput{
				stdout: []byte(config.ExpectedVersion + "\n"),
				stderr: []byte("Unable to find and open the program executable, so unable to determine if there is a compiled-in config file. Proceeding on the assumption that there is not.\n"),
			}
		}
		return commandOutput{}
	}

	report := harness.Run(t.Context())
	for _, result := range report.Results {
		if result.Status == conformance.Fail {
			t.Fatalf("result = %+v, want verified-fd diagnostic accepted", result)
		}
		if result.Evidence.Version != config.ExpectedVersion {
			t.Fatalf("result version = %q, want %q", result.Evidence.Version, config.ExpectedVersion)
		}
	}
}

func TestRunExecutesPinnedStockWorkerdProbesAndPreservesIndependentFailures(t *testing.T) {
	t.Parallel()

	contents := []byte("fake pinned workerd")
	binary := writeExecutable(t, contents)
	config := testConfig()
	config.BinaryPath = binary
	config.ExpectedBinaryDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(contents))
	harness, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	var mutex sync.Mutex
	seen := make(map[string]int)
	harness.runCommand = func(_ context.Context, command string, arguments []string, directory string) commandOutput {
		executed, readErr := os.ReadFile(command)
		if readErr != nil {
			t.Fatalf("ReadFile(%q) error = %v", command, readErr)
		}
		if !bytes.Equal(executed, contents) {
			t.Fatalf("executed bytes = %q, want pinned bytes %q", executed, contents)
		}
		if len(arguments) == 1 && arguments[0] == "--version" {
			return commandOutput{stdout: []byte(config.ExpectedVersion + "\n")}
		}
		if len(arguments) != 7 || arguments[0] != "test" ||
			arguments[1] != "--experimental" || arguments[2] != "--predictable" ||
			arguments[3] != "--no-verbose" || arguments[4] != "-I"+directory ||
			arguments[5] != filepath.Join(directory, "phase0.capnp") {
			t.Fatalf("probe arguments = %q", arguments)
		}
		broker, readBrokerErr := os.ReadFile(filepath.Join(directory, "fake-broker.mjs"))
		if readBrokerErr != nil {
			t.Fatalf("ReadFile(materialized fake broker) error = %v", readBrokerErr)
		}
		if !bytes.Contains(broker, []byte("export const model")) ||
			!bytes.Contains(broker, []byte("export const mcp")) {
			t.Fatal("materialized fake broker does not expose stable model and MCP services")
		}
		entrypoint := strings.TrimPrefix(arguments[6], "phase0:")
		mutex.Lock()
		seen[entrypoint]++
		mutex.Unlock()
		if entrypoint == "outboundDenial" {
			return commandOutput{err: errors.New("exit status 1")}
		}
		return commandOutput{stderr: []byte("stock workerd test diagnostics\n")}
	}

	report := harness.Run(t.Context())
	runnableProbes := 0
	for _, probe := range requiredProbes {
		if probe.entrypoint != "" {
			runnableProbes++
		}
	}
	if len(seen) != runnableProbes {
		t.Fatalf("executed probes = %v, want %d distinct probes", seen, runnableProbes)
	}
	for _, probe := range requiredProbes {
		if probe.entrypoint == "" {
			continue
		}
		if seen[probe.entrypoint] != 1 {
			t.Fatalf("probe %q calls = %d, want 1", probe.entrypoint, seen[probe.entrypoint])
		}
	}
	resourceResults := make(map[string]conformance.Result)
	for _, result := range report.Results {
		wantStatus := conformance.Pass
		wantReason := ""
		wantMock := false
		switch result.Component {
		case "workerd.cpu-limit":
			resourceResults[result.Component] = result
			wantStatus = conformance.NotRun
			wantReason = "agentd-managed cgroup CPU enforcement and Worker process-failure observation are not configured"
		case "workerd.outbound-denial":
			wantStatus = conformance.Fail
			wantReason = "stock workerd probe returned a non-zero exit status"
		case "workerd.rss-cold-start":
			resourceResults[result.Component] = result
			wantStatus = conformance.NotRun
			wantReason = "agentd-managed cgroup RSS attribution and cold-start process measurement are not configured"
		case "workerd.shard-recycle":
			wantStatus = conformance.NotRun
			wantReason = "agentd-managed cgroup pressure and same-identity Worker reconstruction probe is not configured"
		case "workerd.stable-broker-binding":
			wantMock = true
		}
		if result.Status != wantStatus || result.Reason != wantReason {
			t.Fatalf("result %q = %+v, want status=%s reason=%q", result.Component, result, wantStatus, wantReason)
		}
		if result.Evidence.BinaryDigest != config.ExpectedBinaryDigest ||
			result.Evidence.Version != config.ExpectedVersion ||
			result.Evidence.EnvironmentDigest == "" || result.Evidence.Mock != wantMock {
			t.Fatalf("result %q evidence = %+v", result.Component, result.Evidence)
		}
	}
	for component, reason := range map[string]string{
		"workerd.cpu-limit":      "agentd-managed cgroup CPU enforcement and Worker process-failure observation are not configured",
		"workerd.rss-cold-start": "agentd-managed cgroup RSS attribution and cold-start process measurement are not configured",
	} {
		result, found := resourceResults[component]
		if !found || result.Status != conformance.NotRun || result.Reason != reason {
			t.Fatalf("resource result %q = %+v, found=%t", component, result, found)
		}
	}
}

func TestProbeInventoryDoesNotOverstateTheEmbeddedFixture(t *testing.T) {
	t.Parallel()

	componentsByEntrypoint := make(map[string]string)
	notRunReasons := make(map[string]string)
	for _, candidate := range requiredProbes {
		if candidate.entrypoint == "" {
			notRunReasons[candidate.component] = candidate.notRunReason
			continue
		}
		componentsByEntrypoint[candidate.entrypoint] = candidate.component
	}

	if got := componentsByEntrypoint["agentEngine"]; got != "workerd.agent-engine" {
		t.Fatalf("agentEngine component = %q, want real Pi engine", got)
	}
	if _, found := notRunReasons["workerd.agent-engine"]; found {
		t.Fatal("real Pi engine is still marked NOT_RUN")
	}
	if got := componentsByEntrypoint["shardRecycle"]; got != "" {
		t.Fatalf("shardRecycle component = %q, want no runnable substitute for the agentd cgroup gate", got)
	}
	if got := componentsByEntrypoint["stableBrokerBinding"]; got != "workerd.stable-broker-binding" {
		t.Fatalf("stableBrokerBinding component = %q, want real workerd binding probe", got)
	}
	wantNotRun := map[string]string{
		"workerd.cpu-limit":      "agentd-managed cgroup CPU enforcement and Worker process-failure observation are not configured",
		"workerd.rss-cold-start": "agentd-managed cgroup RSS attribution and cold-start process measurement are not configured",
		"workerd.shard-recycle":  "agentd-managed cgroup pressure and same-identity Worker reconstruction probe is not configured",
	}
	if !reflect.DeepEqual(notRunReasons, wantNotRun) {
		t.Fatalf("NOT_RUN checks = %#v, want %#v", notRunReasons, wantNotRun)
	}
}

func TestStableBrokerFixtureUsesRealBindingsAndConcurrentIdentities(t *testing.T) {
	t.Parallel()

	broker, err := fixtureFiles.ReadFile("fixture/fake-broker.mjs")
	if err != nil {
		t.Errorf("ReadFile(fake broker) error = %v", err)
	}
	for _, required := range [][]byte{
		[]byte("export const model"),
		[]byte("export const mcp"),
		[]byte("requestDigest"),
		[]byte("initialModelIdentities"),
		[]byte("rendezvous-pending"),
	} {
		if !bytes.Contains(broker, required) {
			t.Errorf("fake broker does not contain %q", required)
		}
	}

	configuration, err := fixtureFiles.ReadFile("fixture/phase0.capnp.tmpl")
	if err != nil {
		t.Fatalf("ReadFile(configuration) error = %v", err)
	}
	for _, required := range [][]byte{
		[]byte(`(name = "fake-broker.mjs", esModule = embed "fake-broker.mjs")`),
		[]byte(`(name = "MODEL", service = (name = "fake-broker", entrypoint = "model"))`),
		[]byte(`(name = "MCP", service = (name = "fake-broker", entrypoint = "mcp"))`),
	} {
		if !bytes.Contains(configuration, required) {
			t.Errorf("workerd configuration does not contain %q", required)
		}
	}

	host, err := fixtureFiles.ReadFile("fixture/session-host.mjs")
	if err != nil {
		t.Fatalf("ReadFile(session host) error = %v", err)
	}
	worker, err := fixtureFiles.ReadFile("fixture/pi-worker.mjs")
	if err != nil {
		t.Fatalf("ReadFile(worker bundle) error = %v", err)
	}
	workerDigest := fmt.Sprintf("stable-broker/sha256-%x/", sha256.Sum256(worker))
	for _, required := range [][]byte{
		[]byte("MODEL: env.MODEL"),
		[]byte("MCP: env.MCP"),
		[]byte(workerDigest + "identity-a"),
		[]byte(workerDigest + "identity-b"),
		[]byte("Promise.all(["),
		[]byte("missing-model"),
		[]byte("missing-mcp"),
		[]byte("Math.max(leftResult.initialModelAttempts, rightResult.initialModelAttempts) >= 2"),
		[]byte(`"model", "external-tool", "model", "turn_complete"`),
	} {
		if !bytes.Contains(host, required) {
			t.Errorf("session host does not contain stable broker contract %q", required)
		}
	}

	entry, err := os.ReadFile("fixture/pi-worker.entry.ts")
	if err != nil {
		t.Fatalf("ReadFile(worker entry) error = %v", err)
	}
	for _, required := range [][]byte{
		[]byte(`path === "/stable-broker-turn"`),
		[]byte("env.MODEL.fetch"),
		[]byte("env.MCP.fetch"),
		[]byte("requestDigest"),
		[]byte("initialModelAttempts"),
	} {
		if !bytes.Contains(entry, required) {
			t.Errorf("Pi worker does not contain stable broker dispatch %q", required)
		}
	}
}

func TestEnvironmentDigestBindsTheFakeBrokerFixture(t *testing.T) {
	t.Parallel()

	config := testConfig()
	harness, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	hash := sha256.New()
	for _, value := range []string{
		config.CompatibilityDate,
		strings.Join(config.CompatibilityFlags, "\x00"),
		"fixture/phase0.capnp.tmpl",
		"fixture/session-host.mjs",
		"fixture/pi-worker.mjs",
		"fixture/fake-broker.mjs",
	} {
		_, _ = hash.Write([]byte(fmt.Sprintf("%d:", len(value))))
		_, _ = hash.Write([]byte(value))
	}
	for _, candidate := range requiredProbes {
		for _, value := range []string{
			"probe",
			candidate.component,
			candidate.entrypoint,
			candidate.notRunReason,
			fmt.Sprintf("%t", candidate.mock),
		} {
			_, _ = hash.Write([]byte(fmt.Sprintf("%d:", len(value))))
			_, _ = hash.Write([]byte(value))
		}
	}
	for _, path := range []string{
		"fixture/phase0.capnp.tmpl",
		"fixture/session-host.mjs",
		"fixture/pi-worker.mjs",
		"fixture/fake-broker.mjs",
	} {
		contents, readErr := fixtureFiles.ReadFile(path)
		if readErr != nil {
			t.Fatalf("ReadFile(%q) error = %v", path, readErr)
		}
		_, _ = hash.Write([]byte(fmt.Sprintf("%d:", len(contents))))
		_, _ = hash.Write(contents)
	}
	want := fmt.Sprintf("sha256:%x", hash.Sum(nil))
	if harness.environmentDigest != want {
		t.Fatalf("environment digest = %q, want fake-broker-bound %q", harness.environmentDigest, want)
	}
}

func TestEnvironmentDigestBindsProbeInventory(t *testing.T) {
	original := append([]probe(nil), requiredProbes...)
	defer func() { requiredProbes = original }()

	first, err := New(testConfig())
	if err != nil {
		t.Fatalf("New(first) error = %v", err)
	}
	requiredProbes = append([]probe(nil), requiredProbes...)
	requiredProbes[0].component = "workerd.changed-probe-contract"
	second, err := New(testConfig())
	if err != nil {
		t.Fatalf("New(second) error = %v", err)
	}
	if first.environmentDigest == second.environmentDigest {
		t.Fatalf("environment digest did not bind probe inventory: %q", first.environmentDigest)
	}
	first.lookPath = func(string) (string, error) { return "", fs.ErrNotExist }
	firstReport := first.Run(t.Context())
	for _, result := range firstReport.Results {
		if result.Component == "workerd.changed-probe-contract" {
			t.Fatal("constructed harness did not retain its digested probe inventory")
		}
	}
}

func TestRunExecutesTheVerifiedOpenBinaryAfterPathReplacement(t *testing.T) {
	t.Parallel()

	original := []byte("verified workerd inode")
	replacement := []byte("different executable at the configured path")
	binary := writeExecutable(t, original)
	config := testConfig()
	config.BinaryPath = binary
	config.ExpectedBinaryDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(original))
	harness, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	var replaceOnce sync.Once
	var observed [][]byte
	var mutex sync.Mutex
	harness.runCommand = func(_ context.Context, command string, arguments []string, _ string) commandOutput {
		replaceOnce.Do(func() {
			replacementPath := binary + ".replacement"
			if writeErr := os.WriteFile(replacementPath, replacement, 0o700); writeErr != nil {
				t.Errorf("WriteFile(replacement) error = %v", writeErr)
				return
			}
			if renameErr := os.Rename(replacementPath, binary); renameErr != nil {
				t.Errorf("Rename(replacement) error = %v", renameErr)
			}
		})
		contents, readErr := os.ReadFile(command)
		if readErr != nil {
			t.Errorf("ReadFile(executed binary) error = %v", readErr)
		}
		mutex.Lock()
		observed = append(observed, contents)
		mutex.Unlock()
		if len(arguments) == 1 && arguments[0] == "--version" {
			return commandOutput{stdout: []byte(config.ExpectedVersion + "\n")}
		}
		return commandOutput{}
	}

	report := harness.Run(t.Context())
	if len(observed) == 0 {
		t.Fatal("Run() did not execute the verified binary")
	}
	for index, contents := range observed {
		if !bytes.Equal(contents, original) {
			t.Fatalf("executed binary[%d] = %q, want verified bytes %q", index, contents, original)
		}
	}
	for _, result := range report.Results {
		if result.Status == conformance.Fail {
			t.Fatalf("result = %+v, want no execution failure", result)
		}
	}
}

func TestRunIsConcurrentAndCanceledRunsNeverStartWorkerd(t *testing.T) {
	t.Parallel()

	harness, err := New(testConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	var lookups atomic.Int32
	harness.lookPath = func(string) (string, error) {
		lookups.Add(1)
		return "", fs.ErrNotExist
	}

	const runs = 32
	reports := make(chan conformance.Report, runs)
	var wait sync.WaitGroup
	for range runs {
		wait.Add(1)
		go func() {
			defer wait.Done()
			reports <- harness.Run(context.Background())
		}()
	}
	wait.Wait()
	close(reports)
	var first *conformance.Report
	for report := range reports {
		if first == nil {
			copy := report
			first = &copy
			continue
		}
		if !reflect.DeepEqual(*first, report) {
			t.Fatalf("concurrent reports differ: %+v != %+v", *first, report)
		}
	}
	if lookups.Load() != runs {
		t.Fatalf("lookups = %d, want %d", lookups.Load(), runs)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	before := lookups.Load()
	report := harness.Run(canceled)
	if lookups.Load() != before {
		t.Fatal("canceled Run() looked up workerd")
	}
	assertUniformResults(t, report, conformance.NotRun, "conformance run was canceled")
}

func TestNewRejectsAmbiguousOrUnboundedConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "relative binary", mutate: func(config *Config) { config.BinaryPath = "workerd" }},
		{name: "digest", mutate: func(config *Config) { config.ExpectedBinaryDigest = "sha256:ABC" }},
		{name: "version", mutate: func(config *Config) { config.ExpectedVersion = "workerd\nforged" }},
		{name: "date", mutate: func(config *Config) { config.CompatibilityDate = "latest" }},
		{name: "impossible date", mutate: func(config *Config) { config.CompatibilityDate = "2026-02-30" }},
		{name: "flag", mutate: func(config *Config) { config.CompatibilityFlags = []string{"nodejs-compat"} }},
		{name: "duplicate flag", mutate: func(config *Config) { config.CompatibilityFlags = []string{"a", "a"} }},
		{name: "unsorted flag", mutate: func(config *Config) { config.CompatibilityFlags = []string{"z", "a"} }},
		{name: "timeout", mutate: func(config *Config) { config.ProbeTimeout = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := testConfig()
			test.mutate(&config)
			if _, err := New(config); err == nil {
				t.Fatal("New() error = nil")
			}
		})
	}
}

func TestWorkerFixtureContainsThePinnedPiAgentCoreAdapter(t *testing.T) {
	t.Parallel()

	entry, err := os.ReadFile("fixture/pi-worker.entry.ts")
	if err != nil {
		t.Fatalf("ReadFile(entry) error = %v", err)
	}
	worker, err := fixtureFiles.ReadFile("fixture/pi-worker.mjs")
	if err != nil {
		t.Fatalf("ReadFile(bundle) error = %v", err)
	}
	for _, required := range [][]byte{
		[]byte("createPiAgentCoreFactory"),
		[]byte("createPiAgentCoreInitialState"),
		[]byte("adapterAbiVersion: 2"),
		[]byte("checkpointSchemaVersion: 2"),
	} {
		if !bytes.Contains(entry, required) {
			t.Fatalf("worker entry does not contain %q from the pinned Pi adapter", required)
		}
	}
	for _, required := range [][]byte{
		[]byte("var PI_AGENT_CORE_PACKAGE_VERSION = \"0.84.3\""),
		[]byte("var PI_AGENT_CORE_ADAPTER_ABI_VERSION = 2"),
		[]byte("var PI_AGENT_CORE_STATE_VERSION = 2"),
		[]byte("Pi tool continuation did not produce one configured model request"),
	} {
		if !bytes.Contains(worker, required) {
			t.Fatalf("worker bundle does not contain %q from the pinned Pi adapter", required)
		}
	}
	for _, forbidden := range [][]byte{
		[]byte("type AgentCoreFactory"),
		[]byte("adapterAbiVersion: 1"),
		[]byte("checkpointSchemaVersion: 1"),
		[]byte(`from "@earendil-works/`),
		[]byte(`from "node:`),
		[]byte(`import("node:`),
		[]byte("nodejs_compat"),
	} {
		if bytes.Contains(entry, forbidden) || bytes.Contains(worker, forbidden) {
			t.Fatalf("worker fixture contains forbidden synthetic or unresolved dependency %q", forbidden)
		}
	}
	if bytes.Count(worker, []byte("import(")) != 1 ||
		!bytes.Contains(worker, []byte(`import("cloudflare:sockets")`)) ||
		bytes.Contains(worker, []byte("\nimport ")) {
		t.Fatal("worker bundle contains an unresolved import outside cloudflare:sockets")
	}
}

func TestSessionHostRequiresTheCompletePinnedPiBoundaryTrace(t *testing.T) {
	t.Parallel()

	host, err := fixtureFiles.ReadFile("fixture/session-host.mjs")
	if err != nil {
		t.Fatalf("ReadFile(session host) error = %v", err)
	}
	for _, required := range [][]byte{
		[]byte("result.modelBoundaries === 2"),
		[]byte("result.toolRequests === 1"),
		[]byte(`"model", "external-tool", "model", "turn_complete"`),
	} {
		if !bytes.Contains(host, required) {
			t.Fatalf("session host does not require actual Pi boundary evidence %q", required)
		}
	}
	if bytes.Contains(host, []byte("result.modelRequests")) {
		t.Fatal("session host still accepts the synthetic unique-model-service counter")
	}
}

func TestColdPiReconstructionExposesEveryExtensionLifecycle(t *testing.T) {
	t.Parallel()

	entry, err := os.ReadFile("fixture/pi-worker.entry.ts")
	if err != nil {
		t.Fatalf("ReadFile(entry) error = %v", err)
	}
	for _, forbidden := range [][]byte{[]byte("seenHooks"), []byte("recordHook")} {
		if bytes.Contains(entry, forbidden) {
			t.Fatalf("worker entry hides repeated cold-engine lifecycle events with %q", forbidden)
		}
	}
	host, err := fixtureFiles.ReadFile("fixture/session-host.mjs")
	if err != nil {
		t.Fatalf("ReadFile(session host) error = %v", err)
	}
	for hook, want := range map[string]int{
		`"a:initialize"`:         4,
		`"a:beforeAgentStart"`:   4,
		`"a:beforeTurn"`:         1,
		`"a:beforeModelRequest"`: 2,
		`"a:afterModelResponse"`: 2,
		`"a:beforeToolCall"`:     1,
		`"a:afterToolCall"`:      1,
		`"a:afterTurn"`:          1,
	} {
		if got := bytes.Count(host, []byte(hook)); got != want {
			t.Fatalf("session host occurrences of %s = %d, want %d", hook, got, want)
		}
	}
}

func TestEmbeddedFixtureDoesNotCarryAnUnboundedShardRecycleSubstitute(t *testing.T) {
	t.Parallel()

	host, err := fixtureFiles.ReadFile("fixture/session-host.mjs")
	if err != nil {
		t.Fatalf("ReadFile(session host) error = %v", err)
	}
	worker, err := fixtureFiles.ReadFile("fixture/pi-worker.mjs")
	if err != nil {
		t.Fatalf("ReadFile(worker) error = %v", err)
	}
	for name, candidate := range map[string][]byte{
		"host shard entrypoint": bytes.TrimSpace([]byte("export const shardRecycle")),
		"worker spin route":     bytes.TrimSpace([]byte(`path === "/spin"`)),
	} {
		if bytes.Contains(host, candidate) || bytes.Contains(worker, candidate) {
			t.Fatalf("embedded fixture contains %s %q", name, candidate)
		}
	}
}

func TestStockWorkerdFixture(t *testing.T) {
	binary := os.Getenv("CIRCULUSD_WORKERD_PATH")
	digest := os.Getenv("CIRCULUSD_WORKERD_SHA256")
	version := os.Getenv("CIRCULUSD_WORKERD_VERSION")
	if binary == "" || digest == "" || version == "" {
		t.Skip("set CIRCULUSD_WORKERD_PATH, CIRCULUSD_WORKERD_SHA256, and CIRCULUSD_WORKERD_VERSION")
	}
	config := testConfig()
	config.BinaryPath = binary
	config.ExpectedBinaryDigest = digest
	config.ExpectedVersion = version
	config.CompatibilityFlags = nil
	config.ProbeTimeout = 15 * time.Second
	harness, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	runCommand := harness.runCommand
	harness.runCommand = func(ctx context.Context, command string, arguments []string, directory string) commandOutput {
		output := runCommand(ctx, command, arguments, directory)
		if output.err != nil || reflect.DeepEqual(arguments, []string{"--version"}) {
			t.Logf("command %q failed: %v\nstdout:\n%s\nstderr:\n%s", arguments, output.err, output.stdout, output.stderr)
		}
		return output
	}
	report := harness.Run(t.Context())
	for _, result := range report.Results {
		switch result.Component {
		case "workerd.cpu-limit", "workerd.rss-cold-start", "workerd.shard-recycle":
			if result.Status != conformance.NotRun {
				t.Fatalf("external-boundary result = %+v, want NOT_RUN", result)
			}
		default:
			if result.Status != conformance.Pass {
				t.Fatalf("stock workerd result = %+v", result)
			}
		}
		wantMock := result.Component == "workerd.stable-broker-binding"
		if result.Evidence.Mock != wantMock {
			t.Fatalf("stock workerd result %q mock evidence = %t, want %t", result.Component, result.Evidence.Mock, wantMock)
		}
	}
}

func testConfig() Config {
	return Config{
		ExpectedBinaryDigest: "sha256:" + strings.Repeat("a", 64),
		ExpectedVersion:      "workerd 2026-08-25",
		CompatibilityDate:    "2026-08-26",
		CompatibilityFlags:   []string{"nodejs_compat", "streams_enable_constructors"},
		ProbeTimeout:         time.Second,
	}
}

func writeExecutable(t *testing.T, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "workerd")
	if err := os.WriteFile(path, contents, 0o700); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func assertUniformResults(t *testing.T, report conformance.Report, status conformance.Status, reason string) {
	t.Helper()
	if len(report.Results) != len(requiredProbes) {
		t.Fatalf("len(results) = %d, want %d", len(report.Results), len(requiredProbes))
	}
	components := make([]string, 0, len(requiredProbes))
	for _, probe := range requiredProbes {
		components = append(components, probe.component)
	}
	sort.Strings(components)
	for index, result := range report.Results {
		if result.Component != components[index] || result.Status != status || result.Reason != reason {
			t.Fatalf("result[%d] = %+v, want component=%q status=%s reason=%q", index, result, components[index], status, reason)
		}
	}
}
