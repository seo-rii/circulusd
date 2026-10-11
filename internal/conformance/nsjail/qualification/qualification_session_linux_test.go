//go:build linux

package qualification

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/sandboxd"
	"github.com/hancomac/circulusd/internal/sandboxrpc"
)

// The real private UDS and production protocol validation run here. Only the
// OS process starter is fake; no helper executable or jail is launched.
func TestQualificationCommandsUseAuthenticatedSandboxRPCAndCancelTree(t *testing.T) {
	dir, err := os.MkdirTemp("", "nq-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	workspace := filepath.Join(dir, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
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
	environment := digestBytes([]byte("fixture"))
	rawEnv, _ := hex.DecodeString(environment[7:])
	nonce := bytes.Repeat([]byte{9}, 32)
	socket := filepath.Join(dir, "rpc.sock")
	server, err := sandboxrpc.ListenServer(sandboxrpc.ServerConfig{SocketPath: socket, AllowedClientUIDs: []uint32{uint32(os.Geteuid())}, SandboxID: []byte(id.String()), SandboxGeneration: 1, Backend: v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL, ExecutionEnvironmentDigest: rawEnv, OneTimeNonce: nonce, Supervisor: supervisor})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(context.Background()) }()
	defer func() {
		_ = server.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	client, err := sandboxrpc.NewClient(sandboxrpc.ClientConfig{SocketPath: socket, ServerUID: uint32(os.Geteuid()), SandboxID: []byte(id.String()), SandboxGeneration: 1, OneTimeNonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	c := validTestConfig()
	c.StepMillis = 5000
	s := &liveQualificationSession{client: client, sandboxID: id, release: qualificationRelease{config: c, environmentDigest: environment}}
	observations := testObservations(c)
	output, _ := json.Marshal(observations.Jail)
	observed := make(chan error, 1)
	go func() {
		raw, err := s.Observe(ctx, testHost().RunID)
		if err == nil && !bytes.Equal(raw, output) {
			err = bytes.ErrTooLarge
		}
		observed <- err
	}()
	process := awaitQualificationProcess(t, ctx, runner)
	if spec := process.Spec(); spec.ExecutablePath != "/bin/qualification-helper" || len(spec.Arguments) != 2 || spec.Arguments[0] != "observe" || spec.Arguments[1] != testHost().RunID {
		t.Fatalf("unfixed fixture command: %#v", spec)
	}
	if err := process.EmitStdout(output); err != nil {
		t.Fatal(err)
	}
	process.Complete(sandboxd.RunResult{ExitCode: 0})
	if err := <-observed; err != nil {
		t.Fatal(err)
	}
	go func() {
		child, canceled, reaped, err := s.CancelProbe(ctx, testHost().RunID)
		if err == nil && (child != observations.Child || !canceled || !reaped) {
			err = bytes.ErrTooLarge
		}
		observed <- err
	}()
	hold := awaitQualificationProcess(t, ctx, runner)
	if hold.Spec().Arguments[0] != "hold" {
		t.Fatal("missing hold command")
	}
	childRaw, _ := json.Marshal(observations.Child)
	if err := hold.EmitStdout(append(childRaw, '\n')); err != nil {
		t.Fatal(err)
	}
	inspect := awaitQualificationProcess(t, ctx, runner)
	if inspect.Spec().Arguments[0] != "inspect" || len(hold.Signals()) != 1 || hold.Signals()[0] != sandboxd.SignalCancel {
		t.Fatalf("cancel did not reach mock process group: %v", hold.Signals())
	}
	if err := inspect.EmitStdout(childRaw); err != nil {
		t.Fatal(err)
	}
	inspect.Complete(sandboxd.RunResult{ExitCode: 0})
	if err := <-observed; err != nil {
		t.Fatal(err)
	}
	if runner.StartCount() != 3 {
		t.Fatalf("unexpected subprocess retries: %d", runner.StartCount())
	}
}
func awaitQualificationProcess(t *testing.T, ctx context.Context, r *sandboxd.FakeRunner) *sandboxd.FakeProcess {
	t.Helper()
	select {
	case p := <-r.Started():
		return p
	case <-ctx.Done():
		t.Fatal("qualification process did not start")
		return nil
	}
}
