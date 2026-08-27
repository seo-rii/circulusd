// Package nsjail compiles trusted sandbox metadata into immutable NsJail
// launch plans. It does not accept raw mount, executable, cgroup, or network
// configuration from an extension or user request.
package nsjail

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/executor"
)

const (
	planDigestDomain = "circulusd.executor.nsjail-launch-plan.v1\x00"
	mebibyte         = uint64(1 << 20)
)

var (
	ErrInvalidConfig  = errors.New("invalid NsJail planner config")
	ErrInvalidRequest = errors.New("invalid NsJail launch request")

	sandboxIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$`)
)

// Config fixes every host and in-jail path at trusted executord bootstrap.
// These values must never be populated from an extension manifest or tool
// request.
type Config struct {
	BinaryPath      string
	EnvironmentRoot string
	SandboxRoot     string
	CgroupRoot      string
	SandboxdPath    string
	ProtocolVersion uint32
}

// NetworkMode is deliberately narrow for the first production slice. A
// caller cannot silently turn default-deny networking into a weaker mode.
type NetworkMode string

const (
	NetworkNone        NetworkMode = "none"
	NetworkAllowlisted NetworkMode = "allowlisted"
)

// ResourceLimits contains effective, administrator-resolved hard limits.
// NsJail's cgroup v2 controls are authoritative for memory, process count,
// and CPU; rlimits and bounded tmpfs mounts are additional defenses.
type ResourceLimits struct {
	MemoryBytes            uint64
	MaximumProcesses       uint64
	CPUMillisPerSecond     uint32
	ScratchBytes           uint64
	TemporaryBytes         uint64
	RunBytes               uint64
	MaximumOpenFiles       uint64
	MaximumFileBytes       uint64
	MaximumLifetimeSeconds uint32
}

// Request contains only opaque identities, immutable artifact digests,
// allocated host credentials, and effective policy. Host paths are derived by
// Planner from Config and cannot be supplied here.
type Request struct {
	SandboxID            string
	Generation           uint64
	RootfsDigest         string
	SeccompProfileDigest string
	HostUID              uint32
	HostGID              uint32
	WorkspaceAccess      executor.WorkspaceAccess
	Network              NetworkMode
	Resources            ResourceLimits
}

// LaunchPlan is a deterministic snapshot ready for a privileged launcher to
// materialize with exclusive creation and then exec. Configuration is a
// protobuf-text NsJail config, and Digest binds the binary, config path, and
// exact bytes for audit.
type LaunchPlan struct {
	Executable    string
	Arguments     []string
	ConfigPath    string
	Configuration []byte
	Digest        string
}

// Planner is immutable and safe for concurrent Build calls.
type Planner struct {
	config Config
}

// NewPlanner validates and snapshots trusted bootstrap configuration.
func NewPlanner(config Config) (*Planner, error) {
	hostPaths := []struct {
		name  string
		value string
	}{
		{name: "NsJail binary", value: config.BinaryPath},
		{name: "environment root", value: config.EnvironmentRoot},
		{name: "sandbox root", value: config.SandboxRoot},
		{name: "cgroup root", value: config.CgroupRoot},
	}
	for _, candidate := range hostPaths {
		if candidate.value == "" || len(candidate.value) > 4096 ||
			!utf8.ValidString(candidate.value) || strings.IndexByte(candidate.value, 0) >= 0 ||
			strings.ContainsAny(candidate.value, "\r\n") || !filepath.IsAbs(candidate.value) ||
			filepath.Clean(candidate.value) != candidate.value || candidate.value == string(filepath.Separator) ||
			strings.Contains(candidate.value, ":") {
			return nil, fmt.Errorf("%w: %s must be a canonical absolute path", ErrInvalidConfig, candidate.name)
		}
	}
	if config.SandboxdPath == "" || len(config.SandboxdPath) > 4096 ||
		!utf8.ValidString(config.SandboxdPath) || strings.IndexByte(config.SandboxdPath, 0) >= 0 ||
		strings.ContainsAny(config.SandboxdPath, "\r\n") || !path.IsAbs(config.SandboxdPath) ||
		path.Clean(config.SandboxdPath) != config.SandboxdPath || config.SandboxdPath == "/" {
		return nil, fmt.Errorf("%w: sandboxd path must be canonical and absolute inside the jail", ErrInvalidConfig)
	}
	for _, mutableRoot := range []string{"/workspace", "/scratch", "/tmp", "/run", "/proc", "/dev", "/sys"} {
		if config.SandboxdPath == mutableRoot || strings.HasPrefix(config.SandboxdPath, mutableRoot+"/") {
			return nil, fmt.Errorf("%w: sandboxd cannot be loaded from a mutable or virtual mount", ErrInvalidConfig)
		}
	}
	if config.ProtocolVersion == 0 {
		return nil, fmt.Errorf("%w: sandbox protocol version must be positive", ErrInvalidConfig)
	}
	roots := []string{config.EnvironmentRoot, config.SandboxRoot, config.CgroupRoot}
	for left := range roots {
		for right := left + 1; right < len(roots); right++ {
			leftToRight, leftErr := filepath.Rel(roots[left], roots[right])
			rightToLeft, rightErr := filepath.Rel(roots[right], roots[left])
			if leftErr != nil || rightErr != nil ||
				leftToRight == "." || (leftToRight != ".." && !strings.HasPrefix(leftToRight, ".."+string(filepath.Separator))) ||
				(rightToLeft != ".." && !strings.HasPrefix(rightToLeft, ".."+string(filepath.Separator))) {
				return nil, fmt.Errorf("%w: trusted roots must not overlap", ErrInvalidConfig)
			}
		}
	}
	binaryFromSandbox, err := filepath.Rel(config.SandboxRoot, config.BinaryPath)
	if err != nil || binaryFromSandbox == "." ||
		(binaryFromSandbox != ".." && !strings.HasPrefix(binaryFromSandbox, ".."+string(filepath.Separator))) {
		return nil, fmt.Errorf("%w: NsJail binary cannot be loaded from the mutable sandbox root", ErrInvalidConfig)
	}

	return &Planner{config: config}, nil
}

// Build compiles an explicit production policy. The pinned NsJail schema uses
// true for all required namespaces, false for keep_caps/keep_env and false for
// disable_no_new_privs; the generated config spells these values out so an
// upgrade cannot inherit a weaker default silently.
func (planner *Planner) Build(request Request) (LaunchPlan, error) {
	if planner == nil {
		return LaunchPlan{}, fmt.Errorf("%w: nil planner", ErrInvalidRequest)
	}
	if !sandboxIDPattern.MatchString(request.SandboxID) || request.Generation == 0 {
		return LaunchPlan{}, fmt.Errorf("%w: invalid sandbox identity or generation", ErrInvalidRequest)
	}
	digests := []struct {
		name  string
		value string
	}{
		{name: "rootfs", value: request.RootfsDigest},
		{name: "seccomp profile", value: request.SeccompProfileDigest},
	}
	for _, digest := range digests {
		if len(digest.value) != len("sha256:")+sha256.Size*2 ||
			!strings.HasPrefix(digest.value, "sha256:") || digest.value != strings.ToLower(digest.value) {
			return LaunchPlan{}, fmt.Errorf("%w: %s digest is not canonical SHA-256", ErrInvalidRequest, digest.name)
		}
		decoded, err := hex.DecodeString(strings.TrimPrefix(digest.value, "sha256:"))
		if err != nil || len(decoded) != sha256.Size {
			return LaunchPlan{}, fmt.Errorf("%w: malformed %s digest", ErrInvalidRequest, digest.name)
		}
	}
	if request.HostUID == 0 || request.HostGID == 0 {
		return LaunchPlan{}, fmt.Errorf("%w: sandbox host UID and GID must be unprivileged", ErrInvalidRequest)
	}
	if request.WorkspaceAccess != executor.WorkspaceReadOnly && request.WorkspaceAccess != executor.WorkspaceReadWrite {
		return LaunchPlan{}, fmt.Errorf("%w: unsupported workspace access %q", ErrInvalidRequest, request.WorkspaceAccess)
	}
	if request.Network != NetworkNone {
		return LaunchPlan{}, fmt.Errorf("%w: only isolated network mode is implemented", ErrInvalidRequest)
	}
	limits := request.Resources
	if limits.MemoryBytes == 0 || limits.MemoryBytes > 1<<50 ||
		limits.MaximumProcesses == 0 || limits.MaximumProcesses > 1<<20 ||
		limits.CPUMillisPerSecond == 0 || limits.CPUMillisPerSecond > 1_000_000 ||
		limits.ScratchBytes == 0 || limits.ScratchBytes > 1<<50 ||
		limits.TemporaryBytes == 0 || limits.TemporaryBytes > 1<<40 ||
		limits.RunBytes == 0 || limits.RunBytes > 1<<40 ||
		limits.MaximumOpenFiles == 0 || limits.MaximumOpenFiles > 1<<20 ||
		limits.MaximumFileBytes < mebibyte || limits.MaximumFileBytes > 1<<50 ||
		limits.MaximumFileBytes%mebibyte != 0 || limits.MaximumLifetimeSeconds == 0 {
		return LaunchPlan{}, fmt.Errorf("%w: resource limits are zero, unrepresentable, or exceed platform bounds", ErrInvalidRequest)
	}

	rootfsPath := filepath.Join(planner.config.EnvironmentRoot, request.RootfsDigest, "nsjail", "rootfs")
	seccompPath := filepath.Join(
		planner.config.EnvironmentRoot,
		request.RootfsDigest,
		"nsjail",
		"seccomp",
		request.SeccompProfileDigest+".policy",
	)
	sandboxPath := filepath.Join(planner.config.SandboxRoot, request.SandboxID)
	workspacePath := filepath.Join(sandboxPath, "workspace")
	controlPath := filepath.Join(sandboxPath, "control")
	configPath := filepath.Join(sandboxPath, "nsjail.pbtxt")
	for _, generated := range []string{rootfsPath, seccompPath, sandboxPath, workspacePath, controlPath, configPath} {
		if len(generated) > 4096 || !filepath.IsAbs(generated) || filepath.Clean(generated) != generated {
			return LaunchPlan{}, fmt.Errorf("%w: derived host path exceeds platform bounds", ErrInvalidRequest)
		}
	}

	var configuration strings.Builder
	_, _ = fmt.Fprintf(&configuration, "name: %s\n", strconv.Quote("circulusd-"+request.SandboxID))
	_, _ = configuration.WriteString("mode: ONCE\n")
	_, _ = fmt.Fprintf(&configuration, "hostname: %s\n", strconv.Quote("circulusd-"+request.SandboxID))
	_, _ = configuration.WriteString("cwd: \"/\"\n")
	_, _ = fmt.Fprintf(&configuration, "time_limit: %d\n", limits.MaximumLifetimeSeconds)
	_, _ = configuration.WriteString("daemon: false\nkeep_env: false\nkeep_caps: false\ndisable_no_new_privs: false\n")
	_, _ = configuration.WriteString("skip_setsid: false\nforward_signals: false\n")
	_, _ = fmt.Fprintf(&configuration, "rlimit_as: %d\nrlimit_as_type: VALUE\n", (limits.MemoryBytes+mebibyte-1)/mebibyte)
	_, _ = configuration.WriteString("rlimit_core: 0\nrlimit_core_type: VALUE\n")
	_, _ = fmt.Fprintf(&configuration, "rlimit_cpu: %d\nrlimit_cpu_type: VALUE\n", limits.MaximumLifetimeSeconds)
	_, _ = fmt.Fprintf(&configuration, "rlimit_fsize: %d\nrlimit_fsize_type: VALUE\n", limits.MaximumFileBytes/mebibyte)
	_, _ = fmt.Fprintf(&configuration, "rlimit_nofile: %d\nrlimit_nofile_type: VALUE\n", limits.MaximumOpenFiles)
	_, _ = fmt.Fprintf(&configuration, "rlimit_nproc: %d\nrlimit_nproc_type: VALUE\n", limits.MaximumProcesses)
	_, _ = configuration.WriteString("clone_newnet: true\nclone_newuser: true\nclone_newns: true\n")
	_, _ = configuration.WriteString("clone_newpid: true\nclone_newipc: true\nclone_newuts: true\nclone_newcgroup: true\n")
	_, _ = fmt.Fprintf(&configuration, "uidmap {\n  inside_id: \"0\"\n  outside_id: %s\n  count: 1\n  use_newidmap: false\n}\n", strconv.Quote(strconv.FormatUint(uint64(request.HostUID), 10)))
	_, _ = fmt.Fprintf(&configuration, "gidmap {\n  inside_id: \"0\"\n  outside_id: %s\n  count: 1\n  use_newidmap: false\n}\n", strconv.Quote(strconv.FormatUint(uint64(request.HostGID), 10)))
	_, _ = configuration.WriteString("mount_proc: true\n")
	_, _ = fmt.Fprintf(&configuration, "seccomp_policy_file: %s\n", strconv.Quote(seccompPath))
	_, _ = configuration.WriteString("seccomp_log: true\n")
	_, _ = fmt.Fprintf(&configuration, "cgroup_mem_max: %d\ncgroup_mem_memsw_max: %d\ncgroup_mem_swap_max: 0\n", limits.MemoryBytes, limits.MemoryBytes)
	_, _ = fmt.Fprintf(&configuration, "cgroup_pids_max: %d\ncgroup_cpu_ms_per_sec: %d\n", limits.MaximumProcesses, limits.CPUMillisPerSecond)
	_, _ = fmt.Fprintf(&configuration, "cgroupv2_mount: %s\nuse_cgroupv2: true\ndetect_cgroupv2: false\n", strconv.Quote(planner.config.CgroupRoot))
	_, _ = configuration.WriteString("iface_no_lo: false\n")
	_, _ = fmt.Fprintf(&configuration, "mount {\n  src: %s\n  dst: \"/\"\n  is_bind: true\n  rw: false\n  mandatory: true\n  nosuid: true\n  nodev: true\n}\n", strconv.Quote(rootfsPath))
	_, _ = fmt.Fprintf(&configuration, "mount {\n  src: %s\n  dst: \"/workspace\"\n  is_bind: true\n  rw: %t\n  mandatory: true\n  nosuid: true\n  nodev: true\n}\n", strconv.Quote(workspacePath), request.WorkspaceAccess == executor.WorkspaceReadWrite)
	_, _ = fmt.Fprintf(&configuration, "mount {\n  dst: \"/scratch\"\n  fstype: \"tmpfs\"\n  options: %s\n  rw: true\n  mandatory: true\n  nosuid: true\n  nodev: true\n}\n", strconv.Quote(fmt.Sprintf("size=%d,mode=0700,nosuid,nodev", limits.ScratchBytes)))
	_, _ = fmt.Fprintf(&configuration, "mount {\n  dst: \"/tmp\"\n  fstype: \"tmpfs\"\n  options: %s\n  rw: true\n  mandatory: true\n  nosuid: true\n  nodev: true\n  noexec: true\n}\n", strconv.Quote(fmt.Sprintf("size=%d,mode=1777,nosuid,nodev,noexec", limits.TemporaryBytes)))
	_, _ = fmt.Fprintf(&configuration, "mount {\n  dst: \"/run\"\n  fstype: \"tmpfs\"\n  options: %s\n  rw: true\n  mandatory: true\n  nosuid: true\n  nodev: true\n  noexec: true\n}\n", strconv.Quote(fmt.Sprintf("size=%d,mode=0755,nosuid,nodev,noexec", limits.RunBytes)))
	_, _ = fmt.Fprintf(&configuration, "mount {\n  src: %s\n  dst: \"/run/circulusd/control\"\n  is_bind: true\n  rw: true\n  mandatory: true\n  nosuid: true\n  nodev: true\n  noexec: true\n}\n", strconv.Quote(controlPath))
	for _, device := range []string{"/dev/null", "/dev/zero", "/dev/urandom"} {
		_, _ = fmt.Fprintf(&configuration, "mount {\n  src: %s\n  dst: %s\n  is_bind: true\n  rw: true\n  mandatory: true\n  nosuid: true\n}\n", strconv.Quote(device), strconv.Quote(device))
	}
	_, _ = configuration.WriteString("envar: \"PATH=/usr/local/bin:/usr/bin:/bin\"\n")
	_, _ = configuration.WriteString("envar: \"HOME=/scratch\"\nenvar: \"TMPDIR=/tmp\"\n")
	_, _ = fmt.Fprintf(&configuration, "exec_bin {\n  path: %s\n", strconv.Quote(planner.config.SandboxdPath))
	_, _ = configuration.WriteString("  arg: \"--control-socket\"\n  arg: \"/run/circulusd/control/control.sock\"\n")
	_, _ = fmt.Fprintf(&configuration, "  arg: \"--sandbox-id\"\n  arg: %s\n", strconv.Quote(request.SandboxID))
	_, _ = fmt.Fprintf(&configuration, "  arg: \"--generation\"\n  arg: %s\n", strconv.Quote(strconv.FormatUint(request.Generation, 10)))
	_, _ = fmt.Fprintf(&configuration, "  arg: \"--protocol-version\"\n  arg: %s\n}\n", strconv.Quote(strconv.FormatUint(uint64(planner.config.ProtocolVersion), 10)))

	configurationBytes := []byte(configuration.String())
	arguments := []string{"--config", configPath}
	hash := sha256.New()
	_, _ = hash.Write([]byte(planDigestDomain))
	fields := [][]byte{
		[]byte(planner.config.BinaryPath),
		[]byte(configPath),
		configurationBytes,
	}
	var length [8]byte
	for _, field := range fields {
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(field)
	}

	return LaunchPlan{
		Executable:    planner.config.BinaryPath,
		Arguments:     arguments,
		ConfigPath:    configPath,
		Configuration: configurationBytes,
		Digest:        "sha256:" + hex.EncodeToString(hash.Sum(nil)),
	}, nil
}
