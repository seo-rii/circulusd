//go:build linux

package nsjail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/executor"
)

func TestLauncherMaterializesPrivatePlanAndStartsWithoutAmbientEnvironment(t *testing.T) {
	t.Parallel()
	fixture := newLauncherFixture(t)
	process := newFakeLaunchedProcess()
	starter := &recordingProcessStarter{process: process}
	registry := &recordingHandshakeNonceRegistry{}
	launcher := newLauncherWithNonceRegistry(starter, registry)

	instance, err := launcher.Start(context.Background(), fixture.plan)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	commands := starter.snapshot()
	if len(commands) != 1 {
		t.Fatalf("starter calls = %d, want 1", len(commands))
	}
	command := commands[0]
	if command.Executable != fixture.plan.Executable() || len(command.Arguments) != 2 ||
		command.Arguments[0] != "--config" || command.Arguments[1] != fixture.plan.ConfigPath() {
		t.Fatalf("launch command = %#v", command)
	}
	if len(command.Environment) != 0 {
		t.Fatalf("launch environment = %#v, want empty", command.Environment)
	}
	if len(command.ExtraFiles) != 1 {
		t.Fatalf("launch extra files = %d, want nonce on fd 3 only", len(command.ExtraFiles))
	}
	nonces := starter.nonceSnapshot()
	if len(nonces) != 1 || len(nonces[0]) != handshakeNonceBytes {
		t.Fatalf("handshake nonces = %#v, want one %d-byte nonce", nonces, handshakeNonceBytes)
	}
	configuration, err := os.ReadFile(fixture.plan.ConfigPath())
	if err != nil {
		t.Fatalf("ReadFile(config) error = %v", err)
	}
	if string(configuration) != string(fixture.plan.Configuration()) {
		t.Fatal("materialized config differs from sealed plan")
	}
	if bytes.Contains(configuration, nonces[0]) || strings.Contains(strings.Join(command.Arguments, "\x00"), hex.EncodeToString(nonces[0])) ||
		strings.Contains(strings.Join(command.Environment, "\x00"), hex.EncodeToString(nonces[0])) {
		t.Fatal("one-time handshake nonce escaped its anonymous pipe")
	}
	if !instance.ConsumeHandshakeNonce(nonces[0]) {
		t.Fatal("ConsumeHandshakeNonce(first) = false, want true")
	}
	if instance.ConsumeHandshakeNonce(nonces[0]) {
		t.Fatal("ConsumeHandshakeNonce(second) = true, nonce was replayable")
	}
	assertPathModeAndOwner(t, fixture.sandboxPath, os.ModeDir|0o700, os.Geteuid(), os.Getegid())
	assertPathModeAndOwner(t, filepath.Join(fixture.sandboxPath, "workspace"), os.ModeDir|0o700, fixture.hostUID, fixture.hostGID)
	assertPathModeAndOwner(t, filepath.Join(fixture.sandboxPath, "control"), os.ModeDir|0o700, fixture.hostUID, fixture.hostGID)
	assertPathModeAndOwner(t, fixture.plan.ConfigPath(), 0o600, os.Geteuid(), os.Getegid())

	waitContext, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if waitErr := instance.Wait(waitContext); !errors.Is(waitErr, context.DeadlineExceeded) {
		t.Fatalf("Wait(running) error = %v, want deadline", waitErr)
	}
	process.finish(nil)
	if waitErr := instance.Wait(context.Background()); waitErr != nil {
		t.Fatalf("Wait(exited) error = %v", waitErr)
	}
	if err := instance.Destroy(context.Background()); err != nil {
		t.Fatalf("Destroy() error = %v", err)
	}
	registrations := registry.snapshot()
	if len(registrations) != 1 || registrations[0].revocations != 1 || !bytes.Equal(registrations[0].nonce, make([]byte, handshakeNonceBytes)) {
		t.Fatalf("destroyed registration = %#v, want one revoked and forgotten nonce", registrations)
	}
}

func TestLauncherRejectsTamperingAndUnsafeArtifactsBeforeProcessStart(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*launcherFixture)
		wantErr error
	}{
		{name: "configuration mutation", mutate: func(fixture *launcherFixture) {
			fixture.plan.configuration[0] ^= 0xff
		}, wantErr: ErrPlanTampered},
		{name: "argument mutation", mutate: func(fixture *launcherFixture) {
			fixture.plan.arguments = []string{"--version"}
		}, wantErr: ErrPlanTampered},
		{name: "group writable NsJail binary", mutate: func(fixture *launcherFixture) {
			if err := os.Chmod(fixture.plan.Executable(), 0o775); err != nil {
				fixture.t.Fatal(err)
			}
		}, wantErr: ErrUnsafeArtifact},
		{name: "setuid NsJail binary", mutate: func(fixture *launcherFixture) {
			if err := os.Chmod(fixture.plan.Executable(), os.ModeSetuid|0o500); err != nil {
				fixture.t.Fatal(err)
			}
		}, wantErr: ErrUnsafeArtifact},
		{name: "symlinked sandboxd", mutate: func(fixture *launcherFixture) {
			if err := os.Remove(fixture.sandboxdHostPath); err != nil {
				fixture.t.Fatal(err)
			}
			if err := os.Symlink("/bin/true", fixture.sandboxdHostPath); err != nil {
				fixture.t.Fatal(err)
			}
		}, wantErr: ErrUnsafeArtifact},
		{name: "sandboxd digest mismatch", mutate: func(fixture *launcherFixture) {
			if err := os.Chmod(fixture.sandboxdHostPath, 0o700); err != nil {
				fixture.t.Fatal(err)
			}
			if err := os.WriteFile(fixture.sandboxdHostPath, []byte("substituted sandboxd"), 0o500); err != nil {
				fixture.t.Fatal(err)
			}
		}, wantErr: ErrArtifactDigestMismatch},
		{name: "seccomp digest mismatch", mutate: func(fixture *launcherFixture) {
			if err := os.Chmod(fixture.seccompPath, 0o600); err != nil {
				fixture.t.Fatal(err)
			}
			if err := os.WriteFile(fixture.seccompPath, []byte("ALLOW ALL"), 0o400); err != nil {
				fixture.t.Fatal(err)
			}
		}, wantErr: ErrArtifactDigestMismatch},
		{name: "writable rootfs ancestor", mutate: func(fixture *launcherFixture) {
			if err := os.Chmod(filepath.Dir(fixture.rootfsPath), 0o777); err != nil {
				fixture.t.Fatal(err)
			}
		}, wantErr: ErrUnsafeArtifact},
		{name: "symlinked rootfs mount target", mutate: func(fixture *launcherFixture) {
			workspace := filepath.Join(fixture.rootfsPath, "workspace")
			if err := os.Remove(workspace); err != nil {
				fixture.t.Fatal(err)
			}
			if err := os.Symlink("/tmp", workspace); err != nil {
				fixture.t.Fatal(err)
			}
		}, wantErr: ErrUnsafeArtifact},
		{name: "writable sandbox root", mutate: func(fixture *launcherFixture) {
			if err := os.Chmod(fixture.sandboxRoot, 0o777); err != nil {
				fixture.t.Fatal(err)
			}
		}, wantErr: ErrUnsafeArtifact},
		{name: "existing sandbox directory", mutate: func(fixture *launcherFixture) {
			if err := os.MkdirAll(fixture.sandboxPath, 0o700); err != nil {
				fixture.t.Fatal(err)
			}
		}, wantErr: ErrSandboxExists},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLauncherFixture(t)
			test.mutate(&fixture)
			starter := &recordingProcessStarter{process: newFakeLaunchedProcess()}
			_, err := newLauncher(starter).Start(context.Background(), fixture.plan)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Start() error = %v, want %v", err, test.wantErr)
			}
			if calls := starter.snapshot(); len(calls) != 0 {
				t.Fatalf("unsafe plan started %d process(es)", len(calls))
			}
		})
	}
}

func TestLauncherConcurrentStartAdmitsOneProcess(t *testing.T) {
	t.Parallel()
	fixture := newLauncherFixture(t)
	process := newFakeLaunchedProcess()
	starter := &recordingProcessStarter{process: process}

	const workers = 32
	type result struct {
		instance *Instance
		err      error
	}
	results := make(chan result, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			instance, err := newLauncher(starter).Start(context.Background(), fixture.plan)
			results <- result{instance: instance, err: err}
		}()
	}
	wait.Wait()
	close(results)
	winners := 0
	var instance *Instance
	for result := range results {
		if result.err == nil {
			winners++
			instance = result.instance
			continue
		}
		if !errors.Is(result.err, ErrSandboxExists) {
			t.Fatalf("concurrent Start() error = %v", result.err)
		}
	}
	if winners != 1 || len(starter.snapshot()) != 1 {
		t.Fatalf("winners = %d, starts = %d, want 1/1", winners, len(starter.snapshot()))
	}
	process.finish(nil)
	if err := instance.Destroy(context.Background()); err != nil {
		t.Fatalf("Destroy() error = %v", err)
	}
}

func TestLauncherRollsBackFailedStartAndPermitsRetry(t *testing.T) {
	t.Parallel()
	fixture := newLauncherFixture(t)
	startFailure := errors.New("injected process start failure")
	starter := &recordingProcessStarter{startErr: startFailure}
	launcher := newLauncher(starter)
	if _, err := launcher.Start(context.Background(), fixture.plan); !errors.Is(err, startFailure) || !errors.Is(err, ErrLaunchFailed) {
		t.Fatalf("Start(failing) error = %v", err)
	}
	if _, err := os.Lstat(fixture.sandboxPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed start left sandbox path: %v", err)
	}

	process := newFakeLaunchedProcess()
	starter.setResult(process, nil)
	instance, err := launcher.Start(context.Background(), fixture.plan)
	if err != nil {
		t.Fatalf("Start(retry) error = %v", err)
	}
	nonces := starter.nonceSnapshot()
	if len(nonces) != 2 || bytes.Equal(nonces[0], nonces[1]) {
		t.Fatalf("retry reused one-time nonce: %#v", nonces)
	}
	process.finish(nil)
	if err := instance.Destroy(context.Background()); err != nil {
		t.Fatalf("Destroy() error = %v", err)
	}
}

func TestInstanceKillAndDestroyAreConcurrentIdempotent(t *testing.T) {
	t.Parallel()
	fixture := newLauncherFixture(t)
	process := newFakeLaunchedProcess()
	instance, err := newLauncher(&recordingProcessStarter{process: process}).Start(context.Background(), fixture.plan)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixture.sandboxPath, "workspace", "ephemeral"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(fixture.sandboxRoot, "unrelated")
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	const workers = 32
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsChannel <- instance.Kill(context.Background())
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for killErr := range errorsChannel {
		if killErr != nil {
			t.Fatalf("Kill() error = %v", killErr)
		}
	}
	if signals := process.signalSnapshot(); len(signals) != 1 || signals[0] != syscall.SIGKILL {
		t.Fatalf("signals = %#v, want one SIGKILL", signals)
	}

	errorsChannel = make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsChannel <- instance.Destroy(context.Background())
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for destroyErr := range errorsChannel {
		if destroyErr != nil {
			t.Fatalf("Destroy() error = %v", destroyErr)
		}
	}
	if _, err := os.Lstat(fixture.sandboxPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sandbox path after Destroy = %v", err)
	}
	if content, err := os.ReadFile(unrelated); err != nil || string(content) != "keep" {
		t.Fatalf("unrelated sibling = %q, %v", content, err)
	}
}

func TestInstanceDestroyRemovesEmptySandboxAndCgroupIdentityDirectories(t *testing.T) {
	t.Parallel()
	fixture := newLauncherFixture(t)
	process := newFakeLaunchedProcess()
	instance, err := newLauncher(&recordingProcessStarter{process: process}).Start(
		context.Background(),
		fixture.plan,
	)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	process.finish(nil)
	if err := instance.Destroy(context.Background()); err != nil {
		t.Fatalf("Destroy() error = %v", err)
	}

	identityPaths := []string{
		filepath.Join(fixture.sandboxRoot, fixture.plan.sandboxID.String()),
		filepath.Dir(fixture.plan.cgroupPath),
	}
	for _, identityPath := range identityPaths {
		if _, err := os.Lstat(identityPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("empty identity directory %s remains: %v", identityPath, err)
		}
	}
}

func TestProductionScopedKillUsesCgroupAndProcessHandle(t *testing.T) {
	t.Parallel()
	fixture := newLauncherFixture(t)
	process := &fakeCgroupLaunchedProcess{fakeLaunchedProcess: newFakeLaunchedProcess()}
	instance, err := newLauncher(&recordingProcessStarter{process: process}).Start(context.Background(), fixture.plan)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	cgroupKill := filepath.Join(fixture.plan.cgroupPath, "cgroup.kill")
	if err := os.WriteFile(cgroupKill, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := instance.Kill(context.Background()); err != nil {
		t.Fatalf("Kill() error = %v", err)
	}
	if content, err := os.ReadFile(cgroupKill); err != nil || string(content) != "1" {
		t.Fatalf("cgroup.kill = %q, %v", content, err)
	}
	if signals := process.signalSnapshot(); len(signals) != 1 || signals[0] != syscall.SIGKILL {
		t.Fatalf("leader signals = %#v, want one SIGKILL", signals)
	}
	if err := os.Remove(cgroupKill); err != nil {
		t.Fatal(err)
	}
	instance.invalidateHandshakeNonce()
	revokeContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := instance.nonceRegistration.Revoke(revokeContext); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	instance.directories.close()
}

func TestProductionScopedKillRetriesAfterCgroupControlFailure(t *testing.T) {
	t.Parallel()
	fixture := newLauncherFixture(t)
	process := &fakeCgroupLaunchedProcess{fakeLaunchedProcess: newFakeLaunchedProcess()}
	instance, err := newLauncher(&recordingProcessStarter{process: process}).Start(context.Background(), fixture.plan)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := instance.Kill(context.Background()); err == nil {
		t.Fatal("Kill(without cgroup.kill) error = nil")
	}
	if err := instance.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	cgroupKill := filepath.Join(fixture.plan.cgroupPath, "cgroup.kill")
	if err := os.WriteFile(cgroupKill, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := instance.Kill(context.Background()); err != nil {
		t.Fatalf("Kill(retry) error = %v", err)
	}
	if content, err := os.ReadFile(cgroupKill); err != nil || string(content) != "1" {
		t.Fatalf("cgroup.kill after retry = %q, %v", content, err)
	}
	if signals := process.signalSnapshot(); len(signals) != 1 {
		t.Fatalf("leader signals after retry = %#v, want exactly one", signals)
	}
	if err := os.Remove(cgroupKill); err != nil {
		t.Fatal(err)
	}
	instance.invalidateHandshakeNonce()
	revokeContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := instance.nonceRegistration.Revoke(revokeContext); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	instance.directories.close()
}

func TestInstanceDestroyUsesSealedDirectoryHandlesAfterPathReplacement(t *testing.T) {
	t.Parallel()
	fixture := newLauncherFixture(t)
	process := newFakeLaunchedProcess()
	instance, err := newLauncher(&recordingProcessStarter{process: process}).Start(context.Background(), fixture.plan)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	sealedSandboxRoot := fixture.sandboxRoot + "-sealed"
	if err := os.Rename(fixture.sandboxRoot, sealedSandboxRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(fixture.sandboxRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	replacementSandbox := fixture.sandboxPath
	if err := os.MkdirAll(replacementSandbox, 0o700); err != nil {
		t.Fatal(err)
	}
	sandboxVictim := filepath.Join(replacementSandbox, "unrelated")
	if err := os.WriteFile(sandboxVictim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	cgroupRoot := filepath.Dir(filepath.Dir(fixture.plan.cgroupPath))
	sealedCgroupRoot := cgroupRoot + "-sealed"
	if err := os.Rename(cgroupRoot, sealedCgroupRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cgroupRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fixture.plan.cgroupPath, 0o700); err != nil {
		t.Fatal(err)
	}
	cgroupVictim := filepath.Join(fixture.plan.cgroupPath, "unrelated")
	if err := os.WriteFile(cgroupVictim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	process.finish(nil)
	if err := instance.Destroy(context.Background()); err != nil {
		t.Fatalf("Destroy() error = %v", err)
	}
	for _, victim := range []string{sandboxVictim, cgroupVictim} {
		if content, err := os.ReadFile(victim); err != nil || string(content) != "keep" {
			t.Fatalf("replacement victim %s = %q, %v", victim, content, err)
		}
	}
	sealedSandboxGeneration := filepath.Join(sealedSandboxRoot, fixture.plan.sandboxID.String(), filepath.Base(fixture.plan.cgroupPath))
	sealedCgroupGeneration := filepath.Join(sealedCgroupRoot, fixture.plan.sandboxID.String(), filepath.Base(fixture.plan.cgroupPath))
	for _, removed := range []string{sealedSandboxGeneration, sealedCgroupGeneration} {
		if _, err := os.Lstat(removed); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("sealed generation %s remains: %v", removed, err)
		}
	}
}

func TestLauncherHonorsCanceledContextBeforeFilesystemMutation(t *testing.T) {
	t.Parallel()
	fixture := newLauncherFixture(t)
	starter := &recordingProcessStarter{process: newFakeLaunchedProcess()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newLauncher(starter).Start(ctx, fixture.plan); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start(canceled) error = %v", err)
	}
	if _, err := os.Lstat(fixture.sandboxPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled start created sandbox path: %v", err)
	}
	if len(starter.snapshot()) != 0 {
		t.Fatal("canceled start invoked process starter")
	}
}

func TestLauncherRegistersNonceBeforeStartAndRevokesFailedLaunch(t *testing.T) {
	t.Parallel()
	fixture := newLauncherFixture(t)
	registry := &recordingHandshakeNonceRegistry{}
	startFailure := errors.New("injected registered launch failure")
	starter := &recordingProcessStarter{startErr: startFailure}
	starter.onStart = func() error {
		if registry.activeCount() != 1 {
			return errors.New("nonce was not registered before process start")
		}
		return nil
	}
	_, err := newLauncherWithNonceRegistry(starter, registry).Start(context.Background(), fixture.plan)
	if !errors.Is(err, ErrLaunchFailed) || !errors.Is(err, startFailure) {
		t.Fatalf("Start() error = %v", err)
	}
	registrations := registry.snapshot()
	if len(registrations) != 1 || len(registrations[0].nonce) != handshakeNonceBytes || registrations[0].revocations != 1 {
		t.Fatalf("registrations = %#v, want one revoked %d-byte nonce", registrations, handshakeNonceBytes)
	}
	if registrations[0].sandboxID != fixture.plan.sandboxID.String() || registrations[0].generation != fixture.plan.generation {
		t.Fatalf("registered scope = %s/%d", registrations[0].sandboxID, registrations[0].generation)
	}
	if _, statErr := os.Lstat(fixture.sandboxPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed registered launch left sandbox path: %v", statErr)
	}
}

func TestLauncherRegistrationFailureRollsBackWithoutStarting(t *testing.T) {
	t.Parallel()
	fixture := newLauncherFixture(t)
	registrationFailure := errors.New("injected nonce registration failure")
	registry := &recordingHandshakeNonceRegistry{registerErr: registrationFailure}
	starter := &recordingProcessStarter{process: newFakeLaunchedProcess()}
	_, err := newLauncherWithNonceRegistry(starter, registry).Start(context.Background(), fixture.plan)
	if !errors.Is(err, registrationFailure) {
		t.Fatalf("Start() error = %v", err)
	}
	if len(starter.snapshot()) != 0 {
		t.Fatal("registration failure invoked process starter")
	}
	if _, statErr := os.Lstat(fixture.sandboxPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("registration failure left sandbox path: %v", statErr)
	}
}

func TestLauncherConcurrentRegistrationsUseUniqueNonces(t *testing.T) {
	t.Parallel()
	const workers = 16
	fixtures := make([]launcherFixture, workers)
	processes := make([]*fakeLaunchedProcess, workers)
	for index := range workers {
		fixtures[index] = newLauncherFixture(t)
		processes[index] = newFakeLaunchedProcess()
	}
	registry := &recordingHandshakeNonceRegistry{}
	type result struct {
		index    int
		instance *Instance
		err      error
	}
	results := make(chan result, workers)
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			starter := &recordingProcessStarter{process: processes[index]}
			instance, err := newLauncherWithNonceRegistry(starter, registry).Start(context.Background(), fixtures[index].plan)
			results <- result{index: index, instance: instance, err: err}
		}()
	}
	wait.Wait()
	close(results)
	instances := make([]*Instance, workers)
	for result := range results {
		if result.err != nil {
			t.Fatalf("Start(%d) error = %v", result.index, result.err)
		}
		instances[result.index] = result.instance
	}
	registrations := registry.snapshot()
	if len(registrations) != workers {
		t.Fatalf("registrations = %d, want %d", len(registrations), workers)
	}
	seen := make(map[string]struct{}, workers)
	for _, registration := range registrations {
		encoded := hex.EncodeToString(registration.nonce)
		if len(registration.nonce) != handshakeNonceBytes {
			t.Fatalf("nonce length = %d", len(registration.nonce))
		}
		if _, duplicate := seen[encoded]; duplicate {
			t.Fatalf("duplicate concurrent nonce %s", encoded)
		}
		seen[encoded] = struct{}{}
	}
	for index, instance := range instances {
		processes[index].finish(nil)
		if err := instance.Destroy(context.Background()); err != nil {
			t.Fatalf("Destroy(%d) error = %v", index, err)
		}
	}
}

func TestDestroyRetriesFailedNonceRevocationWithoutReleasingAdmission(t *testing.T) {
	t.Parallel()
	fixture := newLauncherFixture(t)
	process := newFakeLaunchedProcess()
	revokeFailure := errors.New("injected revoke failure")
	registry := &recordingHandshakeNonceRegistry{revokeFailures: 1, revokeErr: revokeFailure}
	instance, err := newLauncherWithNonceRegistry(&recordingProcessStarter{process: process}, registry).Start(context.Background(), fixture.plan)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	process.finish(nil)
	if err := instance.Destroy(context.Background()); !errors.Is(err, revokeFailure) {
		t.Fatalf("Destroy(first) error = %v", err)
	}
	if _, err := os.Lstat(fixture.sandboxPath); err != nil {
		t.Fatalf("failed Destroy released admission: %v", err)
	}
	if err := instance.Destroy(context.Background()); err != nil {
		t.Fatalf("Destroy(retry) error = %v", err)
	}
	if _, err := os.Lstat(fixture.sandboxPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful retry left sandbox path: %v", err)
	}
	registrations := registry.snapshot()
	if len(registrations) != 1 || registrations[0].revocations != 2 || !bytes.Equal(registrations[0].nonce, make([]byte, handshakeNonceBytes)) {
		t.Fatalf("retry registration = %#v", registrations)
	}
}

func TestDestroyStillKillsRunningSandboxWhenNonceRevocationFails(t *testing.T) {
	t.Parallel()
	fixture := newLauncherFixture(t)
	process := newFakeLaunchedProcess()
	revokeFailure := errors.New("injected revoke failure")
	registry := &recordingHandshakeNonceRegistry{revokeFailures: 1, revokeErr: revokeFailure}
	instance, err := newLauncherWithNonceRegistry(
		&recordingProcessStarter{process: process},
		registry,
	).Start(context.Background(), fixture.plan)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if err := instance.Destroy(context.Background()); !errors.Is(err, revokeFailure) {
		t.Fatalf("Destroy(first) error = %v", err)
	}
	if signals := process.signalSnapshot(); len(signals) != 1 || signals[0] != syscall.SIGKILL {
		t.Fatalf("signals after failed revoke = %#v, want one SIGKILL", signals)
	}
	if err := instance.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() after failed revoke = %v", err)
	}
	if _, err := os.Lstat(fixture.sandboxPath); err != nil {
		t.Fatalf("failed Destroy released admission: %v", err)
	}
	if err := instance.Destroy(context.Background()); err != nil {
		t.Fatalf("Destroy(retry) error = %v", err)
	}
}

func TestHandshakeNonceConsumptionIsConcurrentAndFailClosed(t *testing.T) {
	t.Parallel()
	nonce := bytes.Repeat([]byte{0x5a}, handshakeNonceBytes)
	instance := &Instance{handshakeCommitment: sha256.Sum256(nonce)}
	const workers = 32
	winners := make(chan bool, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			winners <- instance.ConsumeHandshakeNonce(nonce)
		}()
	}
	wait.Wait()
	close(winners)
	successes := 0
	for success := range winners {
		if success {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent consumes = %d, want 1", successes)
	}

	wrongFirst := &Instance{handshakeCommitment: sha256.Sum256(nonce)}
	if wrongFirst.ConsumeHandshakeNonce(bytes.Repeat([]byte{0x01}, handshakeNonceBytes)) {
		t.Fatal("wrong nonce was accepted")
	}
	if wrongFirst.ConsumeHandshakeNonce(nonce) {
		t.Fatal("nonce remained usable after a failed attempt")
	}
}

func TestCleanupRetainsAdmissionUntilCgroupGenerationIsGone(t *testing.T) {
	t.Parallel()
	fixture := newLauncherFixture(t)
	if err := os.MkdirAll(fixture.sandboxPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fixture.plan.cgroupPath, 0o700); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(fixture.plan.cgroupPath, "still-attached")
	if err := os.WriteFile(blocker, []byte("busy"), 0o600); err != nil {
		t.Fatal(err)
	}

	cgroupRoot := filepath.Dir(filepath.Dir(fixture.plan.cgroupPath))
	err := cleanupGeneration(
		fixture.plan.sandboxRoot,
		cgroupRoot,
		fixture.plan.sandboxID.String(),
		filepath.Base(fixture.plan.cgroupPath),
	)
	if err == nil {
		t.Fatal("cleanupGeneration() error = nil, want busy cgroup failure")
	}
	if _, statErr := os.Lstat(fixture.sandboxPath); statErr != nil {
		t.Fatalf("admission directory was released before cgroup cleanup: %v", statErr)
	}
}

func TestWaitForEmptyCgroupObservesPopulatedTransition(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	eventsPath := filepath.Join(directory, "cgroup.events")
	if err := os.WriteFile(eventsPath, []byte("populated 1\nfrozen 0\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer directoryFile.Close()
	updated := make(chan struct{})
	go func() {
		defer close(updated)
		time.Sleep(20 * time.Millisecond)
		if err := os.Chmod(eventsPath, 0o600); err != nil {
			return
		}
		_ = os.WriteFile(eventsPath, []byte("populated 0\nfrozen 0\n"), 0o400)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitForEmptyCgroup(ctx, int(directoryFile.Fd())); err != nil {
		t.Fatalf("waitForEmptyCgroup() error = %v", err)
	}
	<-updated
}

type launcherFixture struct {
	t                *testing.T
	plan             LaunchPlan
	sandboxRoot      string
	sandboxPath      string
	rootfsPath       string
	seccompPath      string
	sandboxdHostPath string
	hostUID          int
	hostGID          int
}

func newLauncherFixture(t *testing.T) launcherFixture {
	t.Helper()
	base := t.TempDir()
	environmentRoot := filepath.Join(base, "environments")
	sandboxRoot := filepath.Join(base, "sandboxes")
	cgroupRoot := filepath.Join(base, "cgroup")
	binaryPath := filepath.Join(base, "nsjail")
	for _, directory := range []string{environmentRoot, sandboxRoot, cgroupRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(binaryPath, []byte("pinned nsjail"), 0o500); err != nil {
		t.Fatal(err)
	}

	rootfsDigest := "sha256:" + strings.Repeat("b", 64)
	rootfsPath := filepath.Join(environmentRoot, rootfsDigest, "nsjail", "rootfs")
	sandboxdHostPath := filepath.Join(rootfsPath, "usr", "lib", "circulusd", "sandboxd")
	if err := os.MkdirAll(filepath.Dir(sandboxdHostPath), 0o700); err != nil {
		t.Fatal(err)
	}
	sandboxdContent := []byte("pinned sandboxd")
	if err := os.WriteFile(sandboxdHostPath, sandboxdContent, 0o500); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"workspace", "scratch", "tmp", "run", "run/circulusd/control", "proc", "dev",
	} {
		if err := os.MkdirAll(filepath.Join(rootfsPath, filepath.FromSlash(target)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []string{"dev/null", "dev/zero", "dev/urandom"} {
		if err := os.WriteFile(filepath.Join(rootfsPath, filepath.FromSlash(target)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sandboxdSum := sha256.Sum256(sandboxdContent)

	seccompContent := []byte("POLICY circulusd { ALLOW { read, write, exit_group } DEFAULT KILL }")
	seccompSum := sha256.Sum256(seccompContent)
	seccompDigest := "sha256:" + hex.EncodeToString(seccompSum[:])
	seccompPath := filepath.Join(environmentRoot, rootfsDigest, "nsjail", "seccomp", seccompDigest+".policy")
	if err := os.MkdirAll(filepath.Dir(seccompPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seccompPath, seccompContent, 0o400); err != nil {
		t.Fatal(err)
	}

	hostUID := os.Geteuid()
	hostGID := os.Getegid()
	if hostUID == 0 {
		hostUID = 65534
	}
	if hostGID == 0 {
		hostGID = 65534
	}
	planner, err := NewPlanner(Config{
		BinaryPath: binaryPath, EnvironmentRoot: environmentRoot, SandboxRoot: sandboxRoot,
		CgroupRoot: cgroupRoot, SandboxdPath: "/usr/lib/circulusd/sandboxd", ProtocolVersion: 1,
		SandboxdClientUID: 65534,
	})
	if err != nil {
		t.Fatalf("NewPlanner() error = %v", err)
	}
	request := validRequest(t)
	request.RootfsDigest = rootfsDigest
	request.SeccompProfileDigest = seccompDigest
	request.SandboxdDigest = "sha256:" + hex.EncodeToString(sandboxdSum[:])
	request.HostUID = uint32(hostUID)
	request.HostGID = uint32(hostGID)
	request.WorkspaceAccess = executor.WorkspaceReadOnly
	plan, err := planner.Build(request)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	return launcherFixture{
		t: t, plan: plan, sandboxRoot: sandboxRoot,
		sandboxPath: filepath.Dir(plan.ConfigPath()), rootfsPath: rootfsPath,
		seccompPath: seccompPath, sandboxdHostPath: sandboxdHostPath, hostUID: hostUID, hostGID: hostGID,
	}
}

func assertPathModeAndOwner(t *testing.T, path string, wantMode os.FileMode, wantUID, wantGID int) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%s) error = %v", path, err)
	}
	if info.Mode() != wantMode {
		t.Fatalf("mode(%s) = %v, want %v", path, info.Mode(), wantMode)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != wantUID || int(stat.Gid) != wantGID {
		t.Fatalf("owner(%s) = %#v, want %d:%d", path, info.Sys(), wantUID, wantGID)
	}
}

type recordingProcessStarter struct {
	mu       sync.Mutex
	commands []launchCommand
	nonces   [][]byte
	process  launchedProcess
	startErr error
	onStart  func() error
}

func (starter *recordingProcessStarter) Start(command launchCommand) (launchedProcess, error) {
	var nonces [][]byte
	for _, file := range command.ExtraFiles {
		nonce, err := io.ReadAll(file)
		if err != nil {
			return nil, err
		}
		nonces = append(nonces, nonce)
	}
	if starter.onStart != nil {
		if err := starter.onStart(); err != nil {
			return nil, err
		}
	}
	starter.mu.Lock()
	copy := command
	copy.Arguments = append([]string(nil), command.Arguments...)
	copy.Environment = append([]string(nil), command.Environment...)
	copy.ExtraFiles = append([]*os.File(nil), command.ExtraFiles...)
	starter.commands = append(starter.commands, copy)
	starter.nonces = append(starter.nonces, nonces...)
	process, err := starter.process, starter.startErr
	starter.mu.Unlock()
	return process, err
}

type recordedHandshakeNonceRegistration struct {
	registry    *recordingHandshakeNonceRegistry
	sandboxID   string
	generation  uint64
	nonce       []byte
	revocations int
}

type recordingHandshakeNonceRegistry struct {
	mu             sync.Mutex
	registrations  []*recordedHandshakeNonceRegistration
	registerErr    error
	revokeFailures int
	revokeErr      error
}

func newLauncher(starter processStarter) *Launcher {
	return newLauncherWithNonceRegistry(starter, &recordingHandshakeNonceRegistry{})
}

func (registry *recordingHandshakeNonceRegistry) RegisterHandshakeNonce(
	_ context.Context,
	sandboxID string,
	generation uint64,
	nonce []byte,
) (HandshakeNonceRegistration, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.registerErr != nil {
		return nil, registry.registerErr
	}
	registration := &recordedHandshakeNonceRegistration{
		registry: registry, sandboxID: sandboxID, generation: generation, nonce: append([]byte(nil), nonce...),
	}
	registry.registrations = append(registry.registrations, registration)
	return registration, nil
}

func (registration *recordedHandshakeNonceRegistration) Revoke(context.Context) error {
	registration.registry.mu.Lock()
	registration.revocations++
	if registration.registry.revokeFailures > 0 {
		registration.registry.revokeFailures--
		err := registration.registry.revokeErr
		registration.registry.mu.Unlock()
		return err
	}
	zeroBytes(registration.nonce)
	registration.registry.mu.Unlock()
	return nil
}

func (registry *recordingHandshakeNonceRegistry) activeCount() int {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	active := 0
	for _, registration := range registry.registrations {
		if registration.revocations == 0 {
			active++
		}
	}
	return active
}

func (registry *recordingHandshakeNonceRegistry) snapshot() []recordedHandshakeNonceRegistration {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	result := make([]recordedHandshakeNonceRegistration, len(registry.registrations))
	for index, registration := range registry.registrations {
		result[index] = *registration
		result[index].registry = nil
		result[index].nonce = append([]byte(nil), registration.nonce...)
	}
	return result
}

func (starter *recordingProcessStarter) nonceSnapshot() [][]byte {
	starter.mu.Lock()
	defer starter.mu.Unlock()
	result := make([][]byte, len(starter.nonces))
	for index := range starter.nonces {
		result[index] = append([]byte(nil), starter.nonces[index]...)
	}
	return result
}

func (starter *recordingProcessStarter) snapshot() []launchCommand {
	starter.mu.Lock()
	defer starter.mu.Unlock()
	result := append([]launchCommand(nil), starter.commands...)
	return result
}

func (starter *recordingProcessStarter) setResult(process launchedProcess, err error) {
	starter.mu.Lock()
	starter.process = process
	starter.startErr = err
	starter.mu.Unlock()
}

type fakeLaunchedProcess struct {
	mu      sync.Mutex
	done    chan struct{}
	once    sync.Once
	waitErr error
	signals []syscall.Signal
}

type fakeCgroupLaunchedProcess struct {
	*fakeLaunchedProcess
}

func (*fakeCgroupLaunchedProcess) requiresCgroupKill() {}

func newFakeLaunchedProcess() *fakeLaunchedProcess {
	return &fakeLaunchedProcess{done: make(chan struct{})}
}

func (process *fakeLaunchedProcess) Wait() error {
	<-process.done
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.waitErr
}

func (process *fakeLaunchedProcess) SignalGroup(signal syscall.Signal) error {
	process.mu.Lock()
	process.signals = append(process.signals, signal)
	process.mu.Unlock()
	if signal == syscall.SIGKILL {
		process.finish(nil)
	}
	return nil
}

func (process *fakeLaunchedProcess) finish(err error) {
	process.once.Do(func() {
		process.mu.Lock()
		process.waitErr = err
		process.mu.Unlock()
		close(process.done)
	})
}

func (process *fakeLaunchedProcess) signalSnapshot() []syscall.Signal {
	process.mu.Lock()
	defer process.mu.Unlock()
	return append([]syscall.Signal(nil), process.signals...)
}
