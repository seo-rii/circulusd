package nsjail

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/hancomac/circulusd/internal/executor"
	"github.com/hancomac/circulusd/internal/identity"
)

func TestPlannerBuildsExplicitFailClosedProductionPlan(t *testing.T) {
	t.Parallel()
	planner, err := NewPlanner(validConfig())
	if err != nil {
		t.Fatalf("NewPlanner() error = %v", err)
	}

	request := validRequest(t)
	plan, err := planner.Build(request)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if plan.Executable() != "/usr/lib/circulusd/nsjail" {
		t.Fatalf("Executable = %q", plan.Executable())
	}
	generationPath := request.SandboxID.String() + "/generation-0000000000000007"
	wantArguments := []string{
		"--config",
		"/run/circulusd/sandboxes/" + generationPath + "/nsjail.pbtxt",
	}
	if !reflect.DeepEqual(plan.Arguments(), wantArguments) {
		t.Fatalf("Arguments = %#v, want %#v", plan.Arguments(), wantArguments)
	}
	if plan.ConfigPath() != wantArguments[1] {
		t.Fatalf("ConfigPath = %q, want %q", plan.ConfigPath(), wantArguments[1])
	}
	if !strings.HasPrefix(plan.Digest(), "sha256:") || len(plan.Digest()) != 71 {
		t.Fatalf("Digest = %q, want canonical SHA-256", plan.Digest())
	}

	configuration := string(plan.Configuration())
	required := []string{
		"mode: ONCE",
		"keep_env: false",
		"keep_caps: false",
		"disable_no_new_privs: false",
		"clone_newnet: true",
		"clone_newuser: true",
		"clone_newns: true",
		"clone_newpid: true",
		"clone_newipc: true",
		"clone_newuts: true",
		"clone_newcgroup: true",
		"use_cgroupv2: true",
		"detect_cgroupv2: false",
		"cgroupv2_mount: \"/sys/fs/cgroup/circulusd/" + generationPath + "\"",
		"cgroup_mem_max: 268435456",
		"cgroup_mem_swap_max: 0",
		"cgroup_pids_max: 64",
		"cgroup_cpu_ms_per_sec: 500",
		"rlimit_nofile: 256",
		"rlimit_fsize: 64",
		"seccomp_policy_file: \"/var/lib/circulusd/environments/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/nsjail/seccomp/sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.policy\"",
		"src: \"/var/lib/circulusd/environments/sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/nsjail/rootfs\"\n  dst: \"/\"\n  is_bind: true\n  rw: false\n  mandatory: true\n  nosuid: true\n  nodev: true",
		"src: \"/run/circulusd/sandboxes/" + generationPath + "/workspace\"\n  dst: \"/workspace\"\n  is_bind: true\n  rw: false",
		"src: \"/run/circulusd/sandboxes/" + generationPath + "/control\"\n  dst: \"/run/circulusd/control\"\n  is_bind: true\n  rw: true",
		"dst: \"/scratch\"\n  fstype: \"tmpfs\"\n  options: \"size=67108864,mode=0700,nosuid,nodev\"",
		"dst: \"/tmp\"\n  fstype: \"tmpfs\"\n  options: \"size=16777216,mode=1777,nosuid,nodev,noexec\"",
		"mount_proc: true",
		"pass_fd: 3",
		"envar: \"PATH=/usr/local/bin:/usr/bin:/bin\"",
		"path: \"/usr/lib/circulusd/sandboxd\"",
		"arg: \"--control-socket\"",
		"arg: \"/run/circulusd/control/control.sock\"",
		"arg: \"--sandbox-id\"",
		"arg: \"" + request.SandboxID.String() + "\"",
		"arg: \"--generation\"",
		"arg: \"7\"",
		"arg: \"--protocol-version\"",
		"arg: \"1\"",
		"arg: \"--allow-client-uid\"",
		"arg: \"65534\"",
	}
	for _, fragment := range required {
		if !strings.Contains(configuration, fragment) {
			t.Errorf("configuration missing %q:\n%s", fragment, configuration)
		}
	}
	for _, forbidden := range []string{
		"disable_clone_",
		"keep_caps: true",
		"disable_no_new_privs: true",
		"user_net",
		"iface_own",
		"cgroup_mem_memsw_max",
		"nonce",
		"docker.sock",
		"/dev/kvm",
		"src: \"/home\"",
		"src: \"/root\"",
	} {
		if strings.Contains(configuration, forbidden) {
			t.Errorf("configuration contains forbidden fragment %q:\n%s", forbidden, configuration)
		}
	}
	for _, device := range []string{"/dev/null", "/dev/zero", "/dev/urandom"} {
		if !strings.Contains(configuration, "src: \""+device+"\"\n  dst: \""+device+"\"") {
			t.Errorf("configuration does not explicitly mount %s", device)
		}
	}
}

func TestPlannerSeparatesReadOnlyAndWritableWorkspacePlans(t *testing.T) {
	t.Parallel()
	planner, err := NewPlanner(validConfig())
	if err != nil {
		t.Fatalf("NewPlanner() error = %v", err)
	}
	request := validRequest(t)
	readOnly, err := planner.Build(request)
	if err != nil {
		t.Fatalf("Build(read-only) error = %v", err)
	}
	writableRequest := request
	writableRequest.WorkspaceAccess = executor.WorkspaceReadWrite
	writable, err := planner.Build(writableRequest)
	if err != nil {
		t.Fatalf("Build(read-write) error = %v", err)
	}
	if bytes.Equal(readOnly.Configuration(), writable.Configuration()) || readOnly.Digest() == writable.Digest() {
		t.Fatal("read-only and read-write plans must have different content identities")
	}
	workspacePrefix := "src: \"/run/circulusd/sandboxes/" + request.SandboxID.String() + "/generation-0000000000000007/workspace\"\n  dst: \"/workspace\"\n  is_bind: true\n  rw: "
	if !strings.Contains(string(readOnly.Configuration()), workspacePrefix+"false") {
		t.Fatal("read-only plan does not mount /workspace read-only")
	}
	if !strings.Contains(string(writable.Configuration()), workspacePrefix+"true") {
		t.Fatal("read-write plan does not mount /workspace read-write")
	}

	arguments := readOnly.Arguments()
	configuration := readOnly.Configuration()
	arguments[0] = "mutated"
	configuration[0] = 'X'
	if readOnly.Arguments()[0] != "--config" || readOnly.Configuration()[0] == 'X' {
		t.Fatal("getter mutation changed sealed plan state")
	}
	if err := readOnly.Validate(); err != nil {
		t.Fatalf("Validate(after getter mutation) error = %v", err)
	}

	tamperedArguments := readOnly
	tamperedArguments.arguments = append(tamperedArguments.arguments, "--disable_clone_newnet")
	if err := tamperedArguments.Validate(); !errors.Is(err, ErrPlanTampered) {
		t.Fatalf("Validate(tampered arguments) error = %v, want ErrPlanTampered", err)
	}
	tamperedConfiguration := readOnly
	tamperedConfiguration.configuration = append([]byte(nil), tamperedConfiguration.configuration...)
	tamperedConfiguration.configuration[0] ^= 0xff
	if err := tamperedConfiguration.Validate(); !errors.Is(err, ErrPlanTampered) {
		t.Fatalf("Validate(tampered configuration) error = %v, want ErrPlanTampered", err)
	}
}

func TestPlannerPartitionsEveryGenerationAuthorityPath(t *testing.T) {
	t.Parallel()
	planner, err := NewPlanner(validConfig())
	if err != nil {
		t.Fatalf("NewPlanner() error = %v", err)
	}
	firstRequest := validRequest(t)
	secondRequest := firstRequest
	secondRequest.Generation++
	first, err := planner.Build(firstRequest)
	if err != nil {
		t.Fatalf("Build(first) error = %v", err)
	}
	second, err := planner.Build(secondRequest)
	if err != nil {
		t.Fatalf("Build(second) error = %v", err)
	}
	if first.ConfigPath() == second.ConfigPath() || first.Digest() == second.Digest() {
		t.Fatal("two generations share a config authority path or digest")
	}
	firstConfig := string(first.Configuration())
	secondConfig := string(second.Configuration())
	for _, suffix := range []string{"/workspace", "/control", "\"\nuse_cgroupv2"} {
		if !strings.Contains(firstConfig, "generation-0000000000000007"+suffix) ||
			!strings.Contains(secondConfig, "generation-0000000000000008"+suffix) {
			t.Fatalf("generation-scoped path %q missing", suffix)
		}
	}
}

func TestPlannerRejectsUntrustedPathsDowngradesAndUnboundedResources(t *testing.T) {
	t.Parallel()
	configTests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "relative binary", mutate: func(config *Config) { config.BinaryPath = "nsjail" }},
		{name: "binary below mutable sandbox root", mutate: func(config *Config) { config.BinaryPath = "/run/circulusd/sandboxes/nsjail" }},
		{name: "unclean environment root", mutate: func(config *Config) { config.EnvironmentRoot = "/var/lib/../tmp" }},
		{name: "sandbox root delimiter", mutate: func(config *Config) { config.SandboxRoot = "/run/circulusd:other" }},
		{name: "overlapping trusted roots", mutate: func(config *Config) { config.SandboxRoot = "/var/lib/circulusd/environments/sandboxes" }},
		{name: "host sandboxd path", mutate: func(config *Config) { config.SandboxdPath = "../../bin/sh" }},
		{name: "mutable sandboxd path", mutate: func(config *Config) { config.SandboxdPath = "/workspace/sandboxd" }},
		{name: "zero protocol", mutate: func(config *Config) { config.ProtocolVersion = 0 }},
		{name: "zero sandboxd client uid", mutate: func(config *Config) { config.SandboxdClientUID = 0 }},
		{name: "sandboxd client uid sentinel", mutate: func(config *Config) { config.SandboxdClientUID = math.MaxUint32 }},
	}
	for _, test := range configTests {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig()
			test.mutate(&config)
			if _, err := NewPlanner(config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("NewPlanner() error = %v, want ErrInvalidConfig", err)
			}
		})
	}

	planner, err := NewPlanner(validConfig())
	if err != nil {
		t.Fatalf("NewPlanner() error = %v", err)
	}
	wrongKindID, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte{'x'}, 16))}).New(identity.Session)
	if err != nil {
		t.Fatal(err)
	}
	requestTests := []struct {
		name   string
		mutate func(*Request)
	}{
		{name: "zero sandbox ID", mutate: func(request *Request) { request.SandboxID = identity.ID{} }},
		{name: "wrong kind sandbox ID", mutate: func(request *Request) { request.SandboxID = wrongKindID }},
		{name: "zero generation", mutate: func(request *Request) { request.Generation = 0 }},
		{name: "unsafe shared generation", mutate: func(request *Request) { request.Generation = 9_007_199_254_740_992 }},
		{name: "bad rootfs digest", mutate: func(request *Request) { request.RootfsDigest = "/srv/rootfs" }},
		{name: "bad seccomp digest", mutate: func(request *Request) { request.SeccompProfileDigest = "sha256:ABC" }},
		{name: "bad sandboxd digest", mutate: func(request *Request) { request.SandboxdDigest = "latest" }},
		{name: "host root uid", mutate: func(request *Request) { request.HostUID = 0 }},
		{name: "host root gid", mutate: func(request *Request) { request.HostGID = 0 }},
		{name: "uid sentinel", mutate: func(request *Request) { request.HostUID = math.MaxUint32 }},
		{name: "gid sentinel", mutate: func(request *Request) { request.HostGID = math.MaxUint32 }},
		{name: "unsupported network", mutate: func(request *Request) { request.Network = NetworkAllowlisted }},
		{name: "invalid workspace access", mutate: func(request *Request) { request.WorkspaceAccess = "raw-host-path" }},
		{name: "zero memory", mutate: func(request *Request) { request.Resources.MemoryBytes = 0 }},
		{name: "zero cpu", mutate: func(request *Request) { request.Resources.CPUMillisPerSecond = 0 }},
		{name: "zero pids", mutate: func(request *Request) { request.Resources.MaximumProcesses = 0 }},
		{name: "zero lifetime", mutate: func(request *Request) { request.Resources.MaximumLifetimeSeconds = 0 }},
		{name: "sub-mebibyte file limit", mutate: func(request *Request) { request.Resources.MaximumFileBytes = (1 << 20) - 1 }},
	}
	for _, test := range requestTests {
		t.Run(test.name, func(t *testing.T) {
			request := validRequest(t)
			test.mutate(&request)
			if _, err := planner.Build(request); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Build() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestPlannerBuildIsDeterministicAndConcurrentSafe(t *testing.T) {
	t.Parallel()
	planner, err := NewPlanner(validConfig())
	if err != nil {
		t.Fatalf("NewPlanner() error = %v", err)
	}
	request := validRequest(t)
	want, err := planner.Build(request)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	const workers = 64
	results := make(chan LaunchPlan, workers)
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			plan, buildErr := planner.Build(request)
			results <- plan
			errorsChannel <- buildErr
		}()
	}
	wait.Wait()
	close(results)
	close(errorsChannel)
	for buildErr := range errorsChannel {
		if buildErr != nil {
			t.Fatalf("Build() error = %v", buildErr)
		}
	}
	for result := range results {
		if !reflect.DeepEqual(result, want) {
			t.Fatalf("concurrent Build() = %#v, want %#v", result, want)
		}
	}
}

func validConfig() Config {
	return Config{
		BinaryPath:        "/usr/lib/circulusd/nsjail",
		EnvironmentRoot:   "/var/lib/circulusd/environments",
		SandboxRoot:       "/run/circulusd/sandboxes",
		CgroupRoot:        "/sys/fs/cgroup/circulusd",
		SandboxdPath:      "/usr/lib/circulusd/sandboxd",
		ProtocolVersion:   1,
		SandboxdClientUID: 65534,
	}
}

func validRequest(t *testing.T) Request {
	t.Helper()
	sandboxID, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte{'s'}, 16))}).New(identity.Sandbox)
	if err != nil {
		t.Fatalf("New(sandbox ID) error = %v", err)
	}
	return Request{
		SandboxID:            sandboxID,
		Generation:           7,
		RootfsDigest:         "sha256:" + strings.Repeat("b", 64),
		SeccompProfileDigest: "sha256:" + strings.Repeat("c", 64),
		SandboxdDigest:       "sha256:" + strings.Repeat("d", 64),
		HostUID:              65536,
		HostGID:              65537,
		WorkspaceAccess:      executor.WorkspaceReadOnly,
		Network:              NetworkNone,
		Resources: ResourceLimits{
			MemoryBytes:            256 << 20,
			MaximumProcesses:       64,
			CPUMillisPerSecond:     500,
			ScratchBytes:           64 << 20,
			TemporaryBytes:         16 << 20,
			RunBytes:               8 << 20,
			MaximumOpenFiles:       256,
			MaximumFileBytes:       64 << 20,
			MaximumLifetimeSeconds: 600,
		},
	}
}
