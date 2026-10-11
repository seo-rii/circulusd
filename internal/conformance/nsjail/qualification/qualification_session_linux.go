//go:build linux

package qualification

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/conformance/nsjail/fixture"
	"github.com/hancomac/circulusd/internal/executor"
	executorns "github.com/hancomac/circulusd/internal/executor/nsjail"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/sandboxrpc"
)

// This path is a qualification fixture controller, not the production effect
// dispatcher: fixture permits never leave the fresh private sandboxd session.
// It cannot create a broker.ClaimedDispatchStart or production dispatch proof.
type liveQualificationSession struct {
	instance                   *executorns.Instance
	client                     *sandboxrpc.Client
	sandboxID                  identity.ID
	release                    qualificationRelease
	generationPath, cgroupPath string
}

func startQualificationSession(ctx context.Context, r qualificationRelease) (qualificationSession, error) {
	planner, err := qualificationPlanner(r)
	if err != nil {
		return nil, err
	}
	sandboxID, err := identity.New(identity.Sandbox)
	if err != nil {
		return nil, err
	}
	request := executorns.Request{SandboxID: sandboxID, Generation: 1, EnvironmentDigest: r.environmentDigest, RootfsDigest: r.environmentDigest, SeccompProfileDigest: r.inventory.SeccompDigest, SandboxdDigest: r.inventory.SandboxdDigest, HostUID: r.config.HostUID, HostGID: r.config.HostGID, WorkspaceAccess: executor.WorkspaceReadWrite, Network: executorns.NetworkNone, Resources: executorns.ResourceLimits{MemoryBytes: 512 << 20, MaximumProcesses: 64, AddressSpaceBytes: r.inventory.Experiments.AddressSpaceBytes, MaximumUserProcesses: r.inventory.Experiments.MaximumUserProcesses, CPUMillisPerSecond: 500, ScratchBytes: 16 << 20, TemporaryBytes: 16 << 20, RunBytes: 16 << 20, MaximumOpenFiles: 256, MaximumFileBytes: 16 << 20, MaximumLifetimeSeconds: uint32(r.config.TotalMillis/1000 + 1)}}
	plan, err := planner.Build(request)
	if err != nil {
		return nil, err
	}
	broker := executorns.NewHandshakeBroker()
	instance, err := executorns.NewLauncher(broker).Start(ctx, plan)
	if err != nil {
		return nil, err
	}
	session := &liveQualificationSession{instance: instance, sandboxID: sandboxID, release: r, generationPath: filepath.Dir(plan.ConfigPath()), cgroupPath: filepath.Join(r.config.CgroupRoot, sandboxID.String(), "generation-0000000000000001")}
	readyCtx, cancel := context.WithTimeout(ctx, time.Duration(r.config.StepMillis)*time.Millisecond)
	defer cancel()
	control, err := broker.AwaitReady(readyCtx, sandboxID, 1)
	if err != nil {
		return session, err
	}
	client, ok := control.(*sandboxrpc.Client)
	if !ok || client == nil {
		return session, errors.New("launcher broker returned a non-production sandbox client")
	}
	session.client = client
	return session, nil
}

func (s *liveQualificationSession) Observe(ctx context.Context, run string) ([]byte, error) {
	handle, err := s.spawn(ctx, "observe", run)
	if err != nil {
		return nil, err
	}
	return s.collect(ctx, handle, false)
}
func (s *liveQualificationSession) ReadWorkspace(run string) (string, error) {
	if !validRunIdentity(run) {
		return "", errors.New("invalid run identity")
	}
	path := filepath.Join(s.generationPath, "workspace", "qualification-"+run)
	// The workspace is owned by the allocated sandbox UID, not the controller.
	// Pin it without following symlinks and bound the returned marker bytes.
	raw, err := readQualificationWorkspace(path, s.release.config.HostUID)
	return string(raw), err
}
func (s *liveQualificationSession) ReadCgroups() (map[string]string, error) {
	observations := map[string]string{}
	count := 0
	err := walkQualificationDirectory(s.cgroupPath, 1024, 3, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(s.cgroupPath, path)
		if err != nil {
			return err
		}
		if strings.Count(relative, string(filepath.Separator)) > 2 {
			return errors.New("qualification cgroup nesting exceeds bound")
		}
		count++
		if count > 1024 {
			return errors.New("qualification cgroup entry bound exceeded")
		}
		if !d.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
		if err != nil {
			return err
		}
		pids := strings.Fields(string(raw))
		if len(pids) == 0 {
			return nil
		}
		if len(pids) > 64 || len(observations) != 0 {
			return errors.New("unexpected cgroup process placement")
		}
		for _, pid := range pids {
			if n, e := strconv.ParseUint(pid, 10, 32); e != nil || n == 0 {
				return errors.New("invalid cgroup membership")
			}
		}
		observations["cgroup.procs"] = strings.Join(pids, " ")
		for _, name := range []string{"memory.max", "memory.swap.max", "pids.max", "cpu.max"} {
			raw, err := os.ReadFile(filepath.Join(path, name))
			if err != nil {
				return err
			}
			if len(raw) > 128 {
				return errors.New("cgroup observation exceeds bound")
			}
			observations[name] = strings.Join(strings.Fields(string(raw)), " ")
		}
		return nil
	})
	return observations, err
}
func (s *liveQualificationSession) CancelProbe(ctx context.Context, run string) (fixture.ChildObservation, bool, bool, error) {
	var child fixture.ChildObservation
	handle, err := s.spawn(ctx, "hold", run)
	if err != nil {
		return child, false, false, err
	}
	raw, err := s.collect(ctx, handle, true)
	if err != nil {
		return child, false, false, err
	}
	if err := strictQualificationJSON(raw, &child); err != nil || child.SchemaVersion != 1 || child.RunID != run || child.PID < 2 {
		return child, false, false, errors.New("invalid cancellation child observation")
	}
	canceled, err := s.client.Cancel(ctx, &v1.CancelProcessRequest{Meta: s.operationMeta("cancel", handle), Process: handle, Reason: "qualification process-tree cancellation"})
	if err != nil {
		return child, false, false, err
	}
	if !canceled.GetProcessGroupTerminationStarted() {
		return child, false, false, errors.New("process group cancellation was not admitted")
	}
	waited, err := s.client.Wait(ctx, &v1.WaitProcessRequest{Meta: s.operationMeta("wait", handle), Process: handle})
	if err != nil {
		return child, false, false, err
	}
	if waited.GetResult() == nil || !waited.GetResult().GetCancelled() {
		return child, false, false, errors.New("canceled fixture did not report cancellation")
	}
	handle, err = s.spawn(ctx, "inspect", run, strconv.Itoa(child.PID), child.StartTime)
	if err != nil {
		return child, true, false, err
	}
	raw, err = s.collect(ctx, handle, false)
	if err != nil {
		return child, true, false, err
	}
	var inspected fixture.ChildObservation
	if err := strictQualificationJSON(raw, &inspected); err != nil || inspected != child {
		return child, true, false, errors.New("child reaping observation does not bind to the original child")
	}
	return child, true, true, nil
}
func (s *liveQualificationSession) Destroy(ctx context.Context) error {
	err := s.instance.Destroy(ctx)
	if err != nil {
		return err
	}
	for _, path := range []string{s.generationPath, s.cgroupPath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("owned generation remains after destroy")
		}
	}
	return nil
}

func (s *liveQualificationSession) collect(ctx context.Context, handle *v1.ProcessHandle, oneLine bool) ([]byte, error) {
	stream, err := s.client.Attach(ctx, &v1.AttachProcessRequest{Meta: s.operationMeta("attach", handle), Process: handle})
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	out := []byte{}
	for stream.Receive() {
		event := stream.Msg()
		switch e := event.GetEvent().(type) {
		case *v1.ProcessEvent_Stdout:
			if e.Stdout.GetTruncated() || len(out)+len(e.Stdout.GetData()) > 64<<10 {
				return nil, errors.New("qualification output exceeded bound")
			}
			out = append(out, e.Stdout.GetData()...)
			if oneLine && bytes.Contains(out, []byte{'\n'}) {
				if bytes.Count(out, []byte{'\n'}) != 1 {
					return nil, errors.New("multiple qualification observations")
				}
				return out, nil
			}
		case *v1.ProcessEvent_Stderr:
			if len(e.Stderr.GetData()) > 0 {
				return nil, errors.New("qualification helper emitted an error")
			}
		case *v1.ProcessEvent_Exit:
			if e.Exit.GetExitCode() != 0 || e.Exit.GetCancelled() || e.Exit.GetTimedOut() || e.Exit.GetOutputTruncated() || e.Exit.GetTerminatingSignal() != v1.ProcessSignal_PROCESS_SIGNAL_UNSPECIFIED {
				return nil, errors.New("qualification helper did not exit successfully")
			}
			return out, nil
		case *v1.ProcessEvent_Error:
			return nil, errors.New("qualification process stream failed")
		}
	}
	if err := stream.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("qualification stream ended before a terminal observation")
}

func (s *liveQualificationSession) spawn(ctx context.Context, args ...string) (*v1.ProcessHandle, error) {
	if s.client == nil {
		return nil, errors.New("sandbox session is not authenticated")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	invocation := "qualification-" + hex.EncodeToString(nonce[:16])
	id := func(v string) *v1.OpaqueId { return &v1.OpaqueId{Value: []byte(v)} }
	hash := digestBytes([]byte(strings.Join(args, "\x00")))
	rawDigest, _ := hex.DecodeString(hash[7:])
	requestDigest := &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: rawDigest}
	envBytes, _ := hex.DecodeString(s.release.environmentDigest[7:])
	backend := v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL
	deadline := time.Now().Add(time.Duration(s.release.config.StepMillis) * time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if !deadline.After(time.Now()) {
		return nil, context.DeadlineExceeded
	}
	expires := uint64(deadline.UnixMilli())
	permit := &v1.DispatchPermit{Value: append([]byte(nil), nonce[:]...), TenantId: id("qualification-tenant"), UserId: id("qualification-subject"), SessionId: id("qualification-session"), TurnId: id("qualification-turn"), EffectId: id(invocation), InvocationId: id(invocation), RequestDigest: requestDigest, Service: v1.EffectService_EFFECT_SERVICE_EXECUTOR, Operation: "executor.run", ReplayPolicy: v1.ReplayPolicy_REPLAY_POLICY_NEVER, DispatchAttempt: 1, TurnLeaseGeneration: 1, PlacementGeneration: 1, SandboxGeneration: 1, AuthorizationGeneration: 1, DeadlineUnixMs: expires}
	workspace := &v1.WorkspaceProtectionPermit{Value: append([]byte(nil), nonce[:]...), TenantId: permit.TenantId, UserId: permit.UserId, WorkspaceId: id("qualification-workspace"), LeaseId: id("qualification-lease"), InvocationId: id(invocation), RequestDigest: requestDigest, EffectId: permit.EffectId, SessionId: permit.SessionId, SandboxId: id(s.sandboxID.String()), Backend: backend, AccessMode: v1.WorkspaceAccessMode_WORKSPACE_ACCESS_MODE_READ_WRITE, LeaseGeneration: 1, DispatchAttempt: 1, TurnLeaseGeneration: 1, PlacementGeneration: 1, SandboxGeneration: 1, ProjectionGeneration: 1, AuthorizationGeneration: 1, IssuedAtUnixMs: uint64(time.Now().Add(-time.Second).UnixMilli()), ExpiresAtUnixMs: expires, MaximumHoldDeadlineUnixMs: expires, EnqueueSequence: 1}
	stdinMode := v1.StdinMode_STDIN_MODE_CLOSED
	if len(args) > 0 {
		switch args[0] {
		case "seccomp", "cpu", "memory", "pids":
			stdinMode = v1.StdinMode_STDIN_MODE_STREAM
		}
	}
	response, err := s.client.Spawn(ctx, &v1.SpawnProcessRequest{Meta: &v1.RpcRequestMeta{IdempotencyKey: append([]byte(nil), nonce[:]...)}, DispatchPermit: permit, Sandbox: &v1.SandboxHandle{SandboxId: id(s.sandboxID.String()), Generation: 1, Backend: backend, ExecutionEnvironmentDigest: &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: envBytes}}, WorkspaceProtection: workspace, InvocationId: id(invocation), RequestDigest: requestDigest, Executable: helperCommand, Arguments: args, TimeoutMs: s.release.config.StepMillis, OutputLimitBytes: 64 << 10, StdinMode: stdinMode})
	if err != nil {
		return nil, fmt.Errorf("qualification spawn failed: %w", err)
	}
	return response.GetProcess(), nil
}

func (s *liveQualificationSession) operationMeta(operation string, process *v1.ProcessHandle) *v1.RpcRequestMeta {
	key := sha256.Sum256(append([]byte("circulusd.nsjail-qualification.rpc.v1\x00"+s.sandboxID.String()+"\x00"+operation+"\x00"), process.GetProcessId().GetValue()...))
	return &v1.RpcRequestMeta{IdempotencyKey: append([]byte(nil), key[:]...)}
}
