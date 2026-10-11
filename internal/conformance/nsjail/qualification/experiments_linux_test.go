//go:build linux

package qualification

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/conformance"
	"github.com/hancomac/circulusd/internal/conformance/nsjail/fixture"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/sandboxd"
	"github.com/hancomac/circulusd/internal/sandboxrpc"
	"golang.org/x/sys/unix"
)

func testExperiments(run string) []experimentObservation {
	var result []experimentObservation
	for i, kind := range []string{"seccomp", "cpu", "memory", "pids"} {
		id, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte{byte(i + 1)}, 16))}).New(identity.Sandbox)
		if err != nil {
			panic(err)
		}
		snapshot := func() cgroupObservation {
			return cgroupObservation{Device: 1, Inode: uint64(i + 1), Files: map[string]string{"memory.max": "536870912", "memory.swap.max": "0", "pids.max": "64", "cpu.max": "500000 1000000", "cgroup.procs": "111", "cpu.stat": "usage_usec 100\nnr_throttled 0\nthrottled_usec 0", "memory.events": "oom 0\noom_kill 0", "pids.events": "max 0", "memory.current": "1000000", "pids.current": "12"}}
		}
		done := fixture.ExperimentRecord{SchemaVersion: 1, RunID: run, Kind: kind, Phase: "done"}
		o := experimentObservation{Kind: kind, SandboxID: id.String(), Ready: fixture.ExperimentRecord{SchemaVersion: 1, RunID: run, Kind: kind, Phase: "ready"}, Done: &done, Before: snapshot(), After: snapshot(), Exit: &v1.ProcessResult{ExitCode: 0, FinishedAtUnixMs: 1}, CleanupComplete: true}
		switch kind {
		case "seccomp":
			o.HostSyscallResult = 123
			done.Attempts = 1
			done.SyscallResult = -1
			done.Errno = int(unix.EPERM)
		case "cpu":
			done.WorkUnits = 900
			done.ElapsedMillis = 3000
			o.After.Files["cpu.stat"] = "usage_usec 1500100\nnr_throttled 3\nthrottled_usec 1500000"
		case "memory":
			o.Done = nil
			o.Exit = &v1.ProcessResult{ExitCode: -1, TerminatingSignal: v1.ProcessSignal_PROCESS_SIGNAL_KILL, FinishedAtUnixMs: 1}
			o.After.Files["memory.events"] = "oom 1\noom_kill 1"
		case "pids":
			done.Attempts = 40
			done.WorkUnits = 39
			done.Errno = int(unix.EAGAIN)
			o.After.Files["pids.events"] = "max 1"
		}
		result = append(result, o)
	}
	return result
}

func TestEnforcementNeedsPressureNotJustAppliedLimits(t *testing.T) {
	run := testHost().RunID
	tests := []struct {
		name   string
		mutate func([]experimentObservation)
	}{
		{"no syscall denial", func(o []experimentObservation) { o[0].Done.Errno = 0 }},
		{"host also denies syscall", func(o []experimentObservation) { o[0].HostSyscallErrno = int(unix.EPERM) }},
		{"no CPU pressure", func(o []experimentObservation) { o[1].After = o[1].Before }},
		{"CPU counter reset", func(o []experimentObservation) {
			o[1].After.Files["cpu.stat"] = "usage_usec 0\nnr_throttled 3\nthrottled_usec 3"
		}},
		{"CPU helper did no work", func(o []experimentObservation) { o[1].Done.WorkUnits = 0 }},
		{"CPU experiment too short", func(o []experimentObservation) { o[1].Done.ElapsedMillis = 2999 }},
		{"memory allocated without OOM", func(o []experimentObservation) { o[2].After = o[2].Before }},
		{"memory OOM without kill", func(o []experimentObservation) { o[2].After.Files["memory.events"] = "oom 1\noom_kill 0" }},
		{"memory helper failed", func(o []experimentObservation) {
			o[2].Exit.TerminatingSignal = v1.ProcessSignal_PROCESS_SIGNAL_UNSPECIFIED
			o[2].Exit.ExitCode = 1
		}},
		{"memory clean stream without terminal", func(o []experimentObservation) { o[2].Exit = nil }},
		{"memory canceled", func(o []experimentObservation) { o[2].Exit.Cancelled = true }},
		{"PIDs no pressure", func(o []experimentObservation) { o[3].After = o[3].Before }},
		{"PIDs unbounded attempts", func(o []experimentObservation) { o[3].Done.Attempts = 129 }},
		{"counter missing", func(o []experimentObservation) { delete(o[3].After.Files, "pids.events") }},
		{"counter duplicate", func(o []experimentObservation) { o[3].After.Files["pids.events"] = "max 1\nmax 1" }},
		{"counter noncanonical", func(o []experimentObservation) { o[3].After.Files["pids.events"] = "max 01" }},
		{"replaced cgroup", func(o []experimentObservation) { o[2].After.Inode++ }},
		{"limits raised", func(o []experimentObservation) { o[2].After.Files["memory.max"] = "max" }},
		{"not fresh", func(o []experimentObservation) { o[2].Before.Files["memory.events"] = "oom 1\noom_kill 1" }},
		{"reused session", func(o []experimentObservation) { o[2].SandboxID = o[1].SandboxID }},
		{"wrong run", func(o []experimentObservation) { o[0].Ready.RunID = strings.Repeat("c", 32) }},
		{"cleanup failure", func(o []experimentObservation) { o[2].CleanupComplete = false }},
	}
	seccomp, cgroups := evaluateEnforcementExperiments(run, testExperiments(run))
	if !seccomp || !cgroups {
		t.Fatal("valid raw experiment fixture failed")
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := testExperiments(run)
			tc.mutate(o)
			s, c := evaluateEnforcementExperiments(run, o)
			if s && c {
				t.Fatal("missing/inconsistent raw evidence passed")
			}
		})
	}
	o := testExperiments(run)
	o[2].Exit = nil
	o[2].TransportEnded = true
	if s, c := evaluateEnforcementExperiments(run, o); !s || !c {
		t.Fatal("fresh raw OOM counters lost with sandboxd EOF")
	}
}

func TestExperimentRawRecordRejectsMissingNullOrPrematureFields(t *testing.T) {
	run := testHost().RunID
	raw, _ := json.Marshal(testExperiments(run)[0].Ready)
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"errno":0`), []byte(`"errno":null`), 1), bytes.Replace(raw, []byte(`,"errno":0`), nil, 1), bytes.Replace(raw, []byte(`"attempts":0`), []byte(`"attempts":1`), 1), bytes.Replace(raw, []byte(`"runId":"`+run+`"`), []byte(`"runId":"other"`), 1), append(raw, raw...)} {
		var o fixture.ExperimentRecord
		if err := decodeExperimentRecord(bad, run, "seccomp", "ready", &o); err == nil {
			t.Fatalf("accepted ambiguous raw observation %s", bad)
		}
	}
}

type fakeExperimentCgroup struct {
	before, after     cgroupObservation
	snapshots, closed int
	snapshot          func(int) error
	closeErr          error
}

func (c *fakeExperimentCgroup) Snapshot() (cgroupObservation, error) {
	c.snapshots++
	if c.snapshot != nil {
		if err := c.snapshot(c.snapshots); err != nil {
			return cgroupObservation{}, err
		}
	}
	if c.snapshots == 1 {
		return c.before, nil
	}
	return c.after, nil
}
func (c *fakeExperimentCgroup) Close() error { c.closed++; return c.closeErr }

// The real UDS, launch binding, authentication, process protocol and stdin flow
// are exercised. A FakeRunner never starts the helper or any OS subprocess.
func experimentRPCFixture(t *testing.T) (*liveQualificationSession, *sandboxd.FakeRunner, context.Context) {
	t.Helper()
	dir, err := os.MkdirTemp("", "nqe-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	workspace := filepath.Join(dir, "workspace")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	id, err := identity.New(identity.Sandbox)
	if err != nil {
		t.Fatal(err)
	}
	runner := sandboxd.NewFakeRunner()
	supervisor, err := sandboxd.NewSupervisor(sandboxd.Config{Authority: sandboxd.LaunchAuthority{SandboxID: id.String(), Generation: 1}, WorkspaceRoot: workspace, Commands: map[string]string{helperCommand: "/bin/qualification-helper"}, Runner: runner, ReplayLimitBytes: 1 << 20, ReplayLimitEvents: 128, SubscriberBuffer: 16, ReadChunkBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	env := digestBytes([]byte("fixture"))
	rawEnv, _ := hex.DecodeString(env[7:])
	nonce := bytes.Repeat([]byte{9}, 32)
	socket := filepath.Join(dir, "rpc.sock")
	server, err := sandboxrpc.ListenServer(sandboxrpc.ServerConfig{SocketPath: socket, AllowedClientUIDs: []uint32{uint32(os.Geteuid())}, SandboxID: []byte(id.String()), SandboxGeneration: 1, Backend: v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL, ExecutionEnvironmentDigest: rawEnv, OneTimeNonce: nonce, Supervisor: supervisor})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(context.Background()) }()
	t.Cleanup(func() {
		_ = server.Close()
		if err := <-served; err != nil {
			t.Error(err)
		}
	})
	client, err := sandboxrpc.NewClient(sandboxrpc.ClientConfig{SocketPath: socket, ServerUID: uint32(os.Geteuid()), SandboxID: []byte(id.String()), SandboxGeneration: 1, OneTimeNonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	if err := client.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	return &liveQualificationSession{client: client, sandboxID: id, release: qualificationRelease{config: validTestConfig(), environmentDigest: env}}, runner, ctx
}
func awaitExperimentTrigger(t *testing.T, ctx context.Context, p *sandboxd.FakeProcess) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if string(p.StdinBytes()) == "GO" {
			_, err := p.Stdin().WriteContext(ctx, nil)
			if errors.Is(err, io.ErrClosedPipe) {
				return
			}
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("bounded GO trigger was not completed")
			return
		}
	}
}

func TestEnforcementRPCRequiresReadyThenPinnedLimitsBeforeGO(t *testing.T) {
	for _, kind := range []string{"seccomp", "cpu", "memory", "pids"} {
		t.Run(kind, func(t *testing.T) {
			s, runner, ctx := experimentRPCFixture(t)
			run := testHost().RunID
			var raw experimentObservation
			for _, o := range testExperiments(run) {
				if o.Kind == kind {
					raw = o
				}
			}
			capture := &fakeExperimentCgroup{before: raw.Before, after: raw.After}
			processReady := make(chan *sandboxd.FakeProcess, 1)
			capture.snapshot = func(n int) error {
				if n == 1 {
					p := <-processReady
					if len(p.StdinBytes()) != 0 {
						return errors.New("pressure preceded limits snapshot")
					}
				}
				return nil
			}
			type result struct {
				o   experimentObservation
				err error
			}
			done := make(chan result, 1)
			go func() {
				o, err := s.runExperiment(ctx, run, kind, experimentDependencies{openCgroup: func() (experimentCgroup, error) { return capture, nil }, hostGetppid: func() (int64, int) { return 123, 0 }})
				done <- result{o, err}
			}()
			p := awaitQualificationProcess(t, ctx, runner)
			defer p.Complete(sandboxd.RunResult{ExitCode: 1})
			processReady <- p
			ready, _ := json.Marshal(raw.Ready)
			if err := p.EmitStdout(append(ready, '\n')); err != nil {
				t.Fatal(err)
			}
			awaitExperimentTrigger(t, ctx, p)
			if raw.Done != nil {
				encoded, _ := json.Marshal(raw.Done)
				if err := p.EmitStdout(encoded); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "memory" {
				p.Complete(sandboxd.RunResult{ExitCode: -1, Signal: sandboxd.SignalKill})
			} else {
				p.Complete(sandboxd.RunResult{ExitCode: 0})
			}
			resultValue := <-done
			if resultValue.err != nil {
				t.Fatal(resultValue.err)
			}
			if capture.snapshots != 2 || capture.closed != 1 || resultValue.o.SandboxID != s.sandboxID.String() || runner.StartCount() != 1 {
				t.Fatal("snapshot/cleanup/binding or no-retry contract violated")
			}
			resultValue.o.CleanupComplete = true
			all := testExperiments(run)
			for i := range all {
				if all[i].Kind == kind {
					all[i] = resultValue.o
				}
			}
			if a, b := evaluateEnforcementExperiments(run, all); !a || !b {
				t.Fatal("authenticated raw observations failed evaluation")
			}
		})
	}
}

func TestEnforcementRPCRejectsPrematureOrUnsafePressureAndClosesCapture(t *testing.T) {
	for _, name := range []string{"bad ready", "premature done", "raised limit", "startup pressure", "snapshot error", "canceled", "capture close error"} {
		t.Run(name, func(t *testing.T) {
			s, runner, ctx := experimentRPCFixture(t)
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			run := testHost().RunID
			raw := testExperiments(run)[1]
			capture := &fakeExperimentCgroup{before: raw.Before, after: raw.After}
			opened := 0
			if name == "raised limit" {
				capture.before.Files["pids.max"] = "max"
			}
			if name == "startup pressure" {
				capture.before.Files["pids.events"] = "max 1"
			}
			if name == "snapshot error" {
				capture.snapshot = func(int) error { return errors.New("read failed") }
			}
			if name == "capture close error" {
				capture.closeErr = errors.New("close failed")
			}
			done := make(chan error, 1)
			go func() {
				_, err := s.runExperiment(ctx, run, "cpu", experimentDependencies{openCgroup: func() (experimentCgroup, error) { opened++; return capture, nil }})
				done <- err
			}()
			p := awaitQualificationProcess(t, ctx, runner)
			defer p.Complete(sandboxd.RunResult{ExitCode: 1})
			ready, _ := json.Marshal(raw.Ready)
			if name == "bad ready" {
				ready = []byte(`{"passed":true}`)
			}
			ready = append(ready, '\n')
			if name == "premature done" {
				ready = append(ready, []byte(`{"phase":"done"}`)...)
			}
			if err := p.EmitStdout(ready); err != nil {
				t.Fatal(err)
			}
			if name == "canceled" || name == "capture close error" {
				awaitExperimentTrigger(t, ctx, p)
				if name == "canceled" {
					cancel()
				} else {
					b, _ := json.Marshal(raw.Done)
					if err := p.EmitStdout(b); err != nil {
						t.Fatal(err)
					}
					p.Complete(sandboxd.RunResult{ExitCode: 0})
				}
			}
			if err := <-done; err == nil {
				t.Fatal("unsafe pressure passed")
			}
			if opened != capture.closed {
				t.Fatal("capture not closed exactly once")
			}
			if name != "canceled" && name != "capture close error" && len(p.StdinBytes()) != 0 {
				t.Fatal("GO sent before safe snapshot")
			}
		})
	}
}

func TestFreshExperimentFailureStillDestroysEveryOwnedInstance(t *testing.T) {
	for _, name := range []string{"partial start", "experiment error", "cleanup error", "canceled"} {
		t.Run(name, func(t *testing.T) {
			path, deps, _, _ := referenceFixture(t)
			var sessions []*fakeQualificationSession
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			deps.start = func(context.Context, qualificationRelease) (qualificationSession, error) {
				s := &fakeQualificationSession{o: testObservations(validTestConfig())}
				sessions = append(sessions, s)
				if len(sessions) == 3 {
					switch name {
					case "partial start":
						return s, errors.New("partial launch")
					case "experiment error":
						s.experimentErr = errors.New("experiment failed")
					case "cleanup error":
						s.destroyErr = errors.New("owned cgroup remains")
					case "canceled":
						s.experimentCancel = cancel
						s.experimentErr = context.Canceled
					}
				}
				return s, nil
			}
			deps.retain = func(string, string, []byte) error { return nil }
			report := runReferenceQualification(ctx, path, deps)
			if len(sessions) != 3 {
				t.Fatalf("retried failed experiment: %d", len(sessions))
			}
			for _, s := range sessions {
				if s.destroyed != 1 || !s.cleanupLive {
					t.Fatal("owned instance not cleaned exactly once with live cleanup context")
				}
			}
			for _, r := range report.Results {
				if r.Status != conformance.Fail || r.Evidence.Class != conformance.EvidenceClassReferenceOnly {
					t.Fatal("failed experiment promoted")
				}
			}
		})
	}
}
