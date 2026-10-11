//go:build linux

package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"connectrpc.com/connect"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/conformance/nsjail/fixture"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/sandboxrpc"
	"golang.org/x/sys/unix"
)

type experimentObservation struct {
	Kind              string                    `json:"kind"`
	SandboxID         string                    `json:"sandboxId"`
	Ready             fixture.ExperimentRecord  `json:"ready"`
	Done              *fixture.ExperimentRecord `json:"done,omitempty"`
	HostSyscallResult int64                     `json:"hostSyscallResult"`
	HostSyscallErrno  int                       `json:"hostSyscallErrno"`
	Before            cgroupObservation         `json:"before"`
	After             cgroupObservation         `json:"after"`
	Exit              *v1.ProcessResult         `json:"exit,omitempty"`
	TransportEnded    bool                      `json:"transportEnded"`
	CleanupComplete   bool                      `json:"cleanupComplete"`
}
type experimentDependencies struct {
	openCgroup  func() (experimentCgroup, error)
	hostGetppid func() (int64, int)
}

func (s *liveQualificationSession) Experiment(ctx context.Context, run, kind string) (experimentObservation, error) {
	return s.runExperiment(ctx, run, kind, experimentDependencies{openCgroup: s.openExperimentCgroup, hostGetppid: func() (int64, int) {
		value, _, errno := unix.RawSyscall(unix.SYS_GETPPID, 0, 0, 0)
		return int64(value), int(errno)
	}})
}
func (s *liveQualificationSession) runExperiment(ctx context.Context, run, kind string, deps experimentDependencies) (out experimentObservation, returnErr error) {
	out.Kind = kind
	out.SandboxID = s.sandboxID.String()
	if kind != "seccomp" && kind != "cpu" && kind != "memory" && kind != "pids" {
		return out, errors.New("unsupported enforcement experiment")
	}
	if kind == "seccomp" {
		out.HostSyscallResult, out.HostSyscallErrno = deps.hostGetppid()
		if out.HostSyscallResult < 1 || out.HostSyscallErrno != 0 {
			return out, errors.New("host control syscall is unavailable")
		}
	}
	handle, err := s.spawn(ctx, kind, run)
	if err != nil {
		return out, err
	}
	stream, err := s.client.Attach(ctx, &v1.AttachProcessRequest{Meta: s.operationMeta("experiment", handle), Process: handle})
	if err != nil {
		return out, err
	}
	defer stream.Close()
	ready, err := readExperimentReady(stream)
	if err != nil {
		return out, err
	}
	if err := decodeExperimentRecord(ready, run, kind, "ready", &out.Ready); err != nil {
		return out, err
	}
	capture, err := deps.openCgroup()
	if err != nil {
		return out, err
	}
	defer func() { returnErr = errors.Join(returnErr, capture.Close()) }()
	out.Before, err = capture.Snapshot()
	if err != nil || !fixedExperimentLimits(out.Before) || out.Before.Files["cgroup.procs"] == "" {
		return out, errors.New("experiment hard limits are not applied")
	}
	// Refuse contaminated startup before admitting pressure. Kernel counters are
	// sampled after the helper's ready marker, before any allocation/fork loop.
	for _, check := range []struct{ file, key string }{{"memory.events", "oom"}, {"memory.events", "oom_kill"}, {"pids.events", "max"}} {
		counters, err := parseKernelCounters(out.Before.Files[check.file])
		value, ok := counters[check.key]
		if err != nil || !ok || value != 0 {
			return out, errors.New("fresh experiment cgroup already recorded pressure")
		}
	}
	if _, err := s.client.WriteStdin(ctx, &v1.WriteStdinRequest{Meta: s.operationMeta("experiment-go", handle), Process: handle, ChunkSequence: 1, Data: []byte("GO")}); err != nil {
		return out, err
	}
	if _, err := s.client.CloseStdin(ctx, &v1.CloseStdinRequest{Meta: s.operationMeta("experiment-close", handle), Process: handle}); err != nil {
		return out, err
	}
	var done []byte
	for stream.Receive() {
		event := stream.Msg()
		switch e := event.GetEvent().(type) {
		case *v1.ProcessEvent_Stdout:
			if e.Stdout.GetTruncated() || len(done)+len(e.Stdout.GetData()) > 4096 {
				return out, errors.New("experiment output exceeds bound")
			}
			done = append(done, e.Stdout.GetData()...)
		case *v1.ProcessEvent_Stderr:
			if len(e.Stderr.GetData()) > 0 && kind != "memory" {
				return out, errors.New("enforcement helper failed")
			}
		case *v1.ProcessEvent_Exit:
			out.Exit = e.Exit
		case *v1.ProcessEvent_Error:
			return out, errors.New("enforcement experiment reported a process error")
		}
	}
	if err := stream.Err(); err != nil {
		// Only a lost transport can accompany a kernel-proven OOM. Wire
		// corruption, authorization errors and deadline failures never qualify.
		if kind != "memory" || connect.CodeOf(err) != connect.CodeUnavailable && connect.CodeOf(err) != connect.CodeUnknown {
			return out, err
		}
		out.TransportEnded = true
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	out.After, err = capture.Snapshot()
	if err != nil {
		return out, err
	}
	if len(bytes.TrimSpace(done)) > 0 {
		var record fixture.ExperimentRecord
		if err := decodeExperimentRecord(done, run, kind, "done", &record); err != nil {
			return out, err
		}
		out.Done = &record
	}
	return out, nil
}
func readExperimentReady(stream *sandboxrpc.ProcessEventStream) ([]byte, error) {
	var raw []byte
	for stream.Receive() {
		switch e := stream.Msg().GetEvent().(type) {
		case *v1.ProcessEvent_Stdout:
			if e.Stdout.GetTruncated() || len(raw)+len(e.Stdout.GetData()) > 4096 {
				return nil, errors.New("experiment ready output exceeds bound")
			}
			raw = append(raw, e.Stdout.GetData()...)
			if index := bytes.IndexByte(raw, '\n'); index >= 0 {
				if len(bytes.TrimSpace(raw[index+1:])) != 0 {
					return nil, errors.New("experiment ran before GO")
				}
				return raw[:index], nil
			}
		case *v1.ProcessEvent_Stderr, *v1.ProcessEvent_Exit, *v1.ProcessEvent_Error:
			return nil, errors.New("experiment exited before readiness")
		}
	}
	return nil, errors.New("experiment stream ended before readiness")
}
func decodeExperimentRecord(raw []byte, run, kind, phase string, target *fixture.ExperimentRecord) error {
	if err := strictQualificationJSON(raw, target); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for _, key := range []string{"schemaVersion", "runId", "kind", "phase", "attempts", "workUnits", "elapsedMillis", "bytesTouched", "syscallResult", "errno"} {
		value, ok := fields[key]
		if !ok || string(value) == "null" {
			return errors.New("missing raw experiment field")
		}
	}
	if target.SchemaVersion != 1 || target.RunID != run || target.Kind != kind || target.Phase != phase || !validRunIdentity(run) || target.Errno < 0 || target.Errno > 4095 {
		return errors.New("experiment observation identity mismatch")
	}
	if phase == "done" && !validExperimentDone(target) {
		return errors.New("raw experiment exceeds its signed bounds")
	}
	if phase == "ready" && *target != (fixture.ExperimentRecord{SchemaVersion: 1, RunID: run, Kind: kind, Phase: phase}) {
		return errors.New("pressure occurred before readiness")
	}
	return nil
}

func validExperimentDone(record *fixture.ExperimentRecord) bool {
	if record == nil || record.Phase != "done" || record.ElapsedMillis > 600000 || record.Errno < 0 || record.Errno > 4095 {
		return false
	}
	d := fixture.RequiredExperiments()
	switch record.Kind {
	case "seccomp":
		return record.Attempts == 1 && record.WorkUnits == 0 && record.BytesTouched == 0
	case "cpu":
		return record.Attempts == 0 && record.BytesTouched == 0 && record.SyscallResult == 0 && record.Errno == 0
	case "memory":
		return record.Attempts <= d.MemoryBytes/(4<<20) && record.WorkUnits == 0 && record.BytesTouched <= d.MemoryBytes && record.BytesTouched%(4<<20) == 0 && record.SyscallResult == 0 && (record.Errno == 0 || record.Errno == int(unix.ENOMEM))
	case "pids":
		return record.Attempts > 0 && record.Attempts <= d.PIDsAttempts && record.WorkUnits <= record.Attempts && record.BytesTouched == 0 && record.SyscallResult == 0 && (record.Errno == 0 || record.Errno == int(unix.EAGAIN))
	default:
		return false
	}
}

func evaluateEnforcementExperiments(run string, experiments []experimentObservation) (seccomp, cgroups bool) {
	if !validRunIdentity(run) || len(experiments) != 4 {
		return false, false
	}
	seen := map[string]bool{}
	sandboxIDs := map[string]bool{}
	seccomp = false
	cgroups = true
	for _, o := range experiments {
		parsed, err := identity.Parse(identity.Sandbox, o.SandboxID)
		if err != nil || parsed.String() != o.SandboxID || sandboxIDs[o.SandboxID] || seen[o.Kind] || !o.CleanupComplete || !fixedExperimentLimits(o.Before) || !fixedExperimentLimits(o.After) || o.Before.Device != o.After.Device || o.Before.Inode != o.After.Inode {
			return false, false
		}
		for _, check := range []struct{ file, key string }{{"memory.events", "oom"}, {"memory.events", "oom_kill"}, {"pids.events", "max"}} {
			counters, err := parseKernelCounters(o.Before.Files[check.file])
			value, ok := counters[check.key]
			if err != nil || !ok || value != 0 {
				return false, false
			}
		}
		sandboxIDs[o.SandboxID] = true
		seen[o.Kind] = true
		if o.Ready != (fixture.ExperimentRecord{SchemaVersion: 1, RunID: run, Kind: o.Kind, Phase: "ready"}) {
			return false, false
		}
		successful := validExperimentDone(o.Done) && o.Done.SchemaVersion == 1 && o.Done.RunID == run && o.Done.Kind == o.Kind && o.Done.Phase == "done" && o.Exit != nil && o.Exit.GetExitCode() == 0 && !o.Exit.GetCancelled() && !o.Exit.GetTimedOut() && !o.Exit.GetOutputTruncated() && o.Exit.GetTerminatingSignal() == v1.ProcessSignal_PROCESS_SIGNAL_UNSPECIFIED && !o.TransportEnded
		switch o.Kind {
		case "seccomp":
			seccomp = successful && o.HostSyscallResult > 0 && o.HostSyscallErrno == 0 && o.Done.Attempts == 1 && o.Done.SyscallResult == -1 && o.Done.Errno == int(unix.EPERM)
		case "cpu":
			periods, pok := counterDelta(o.Before, o.After, "cpu.stat", "nr_throttled")
			throttle, tok := counterDelta(o.Before, o.After, "cpu.stat", "throttled_usec")
			usage, uok := counterDelta(o.Before, o.After, "cpu.stat", "usage_usec")
			cgroups = cgroups && successful && o.Done.Errno == 0 && o.Done.WorkUnits > 0 && o.Done.ElapsedMillis >= fixture.RequiredExperiments().CPUMillis && pok && tok && uok && periods > 0 && throttle > 0 && usage > 0
		case "memory":
			kills, kok := counterDelta(o.Before, o.After, "memory.events", "oom_kill")
			ooms, ook := counterDelta(o.Before, o.After, "memory.events", "oom")
			// A normal helper completion must include its bounded raw record.
			// The exceptional OOM path is exactly SIGKILL or a lost transport;
			// a helper error, cancellation or clean truncated stream cannot pass.
			completed := successful || o.Exit == nil && o.TransportEnded || o.Exit != nil && o.Exit.GetTerminatingSignal() == v1.ProcessSignal_PROCESS_SIGNAL_KILL
			cgroups = cgroups && kok && ook && kills > 0 && ooms > 0 && completed && (o.Exit == nil || !o.Exit.GetCancelled() && !o.Exit.GetTimedOut() && !o.Exit.GetOutputTruncated())
		case "pids":
			limit, lok := counterDelta(o.Before, o.After, "pids.events", "max")
			cgroups = cgroups && successful && o.Done.Attempts > 0 && o.Done.Attempts <= fixture.RequiredExperiments().PIDsAttempts && lok && limit > 0
		default:
			return false, false
		}
	}
	return seccomp, cgroups && seen["cpu"] && seen["memory"] && seen["pids"]
}
