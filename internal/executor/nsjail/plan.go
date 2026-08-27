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
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/executor"
	"github.com/hancomac/circulusd/internal/identity"
)

const (
	planDigestDomain        = "circulusd.executor.nsjail-launch-plan.v1\x00"
	mebibyte                = uint64(1 << 20)
	maximumSharedGeneration = uint64(9_007_199_254_740_991)
	handshakeNonceFD        = 3
)

var (
	ErrInvalidConfig  = errors.New("invalid NsJail planner config")
	ErrInvalidRequest = errors.New("invalid NsJail launch request")
	ErrPlanTampered   = errors.New("NsJail launch plan integrity check failed")
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
	// SandboxdClientUID is the trusted executord peer UID as observed from
	// sandboxd's user namespace (normally the host kernel overflow UID).
	SandboxdClientUID uint32
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
	SandboxID            identity.ID
	Generation           uint64
	RootfsDigest         string
	SeccompProfileDigest string
	SandboxdDigest       string
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
	executable    string
	arguments     []string
	configPath    string
	configuration []byte
	digest        string

	sandboxID            identity.ID
	generation           uint64
	environmentRoot      string
	sandboxRoot          string
	cgroupPath           string
	rootfsPath           string
	seccompPath          string
	sandboxdHostPath     string
	rootfsDigest         string
	seccompProfileDigest string
	sandboxdDigest       string
	hostUID              uint32
	hostGID              uint32
}

// Executable returns the trusted NsJail binary path.
func (plan LaunchPlan) Executable() string {
	return plan.executable
}

// Arguments returns a defensive copy of the only permitted launcher argv.
func (plan LaunchPlan) Arguments() []string {
	return append([]string(nil), plan.arguments...)
}

// ConfigPath returns the generation-scoped config destination.
func (plan LaunchPlan) ConfigPath() string {
	return plan.configPath
}

// Configuration returns a defensive copy of the sealed protobuf-text bytes.
func (plan LaunchPlan) Configuration() []byte {
	return append([]byte(nil), plan.configuration...)
}

// Digest returns the content identity of the complete launch command and its
// trusted launch metadata. The one-time handshake nonce is deliberately not a
// serializable plan field.
func (plan LaunchPlan) Digest() string {
	return plan.digest
}

// Validate rechecks plan integrity immediately before filesystem mutation or
// exec. LaunchPlan has no exported mutable storage, but this also detects
// accidental corruption inside the trusted process.
func (plan LaunchPlan) Validate() error {
	if plan.sandboxID.Kind() != identity.Sandbox || plan.sandboxID.String() == "" ||
		plan.generation == 0 || plan.generation > maximumSharedGeneration ||
		plan.executable == "" || plan.configPath == "" || len(plan.configuration) == 0 ||
		len(plan.arguments) != 2 || plan.arguments[0] != "--config" || plan.arguments[1] != plan.configPath ||
		plan.digest == "" || plan.digest != digestLaunchPlan(plan) {
		return ErrPlanTampered
	}
	return nil
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
	if config.SandboxdClientUID == 0 || config.SandboxdClientUID == ^uint32(0) {
		return nil, fmt.Errorf("%w: sandboxd client UID must be an explicit unprivileged UID", ErrInvalidConfig)
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
	if request.SandboxID.Kind() != identity.Sandbox || request.SandboxID.String() == "" ||
		request.Generation == 0 || request.Generation > maximumSharedGeneration {
		return LaunchPlan{}, fmt.Errorf("%w: invalid sandbox identity or generation", ErrInvalidRequest)
	}
	digests := []struct {
		name  string
		value string
	}{
		{name: "rootfs", value: request.RootfsDigest},
		{name: "seccomp profile", value: request.SeccompProfileDigest},
		{name: "sandboxd", value: request.SandboxdDigest},
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
	if request.HostUID == 0 || request.HostGID == 0 ||
		request.HostUID == ^uint32(0) || request.HostGID == ^uint32(0) {
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
	generationPath := fmt.Sprintf("generation-%016x", request.Generation)
	sandboxPath := filepath.Join(planner.config.SandboxRoot, request.SandboxID.String(), generationPath)
	workspacePath := filepath.Join(sandboxPath, "workspace")
	controlPath := filepath.Join(sandboxPath, "control")
	configPath := filepath.Join(sandboxPath, "nsjail.pbtxt")
	cgroupPath := filepath.Join(planner.config.CgroupRoot, request.SandboxID.String(), generationPath)
	sandboxdHostPath := filepath.Join(rootfsPath, filepath.FromSlash(strings.TrimPrefix(planner.config.SandboxdPath, "/")))
	for _, generated := range []string{
		rootfsPath,
		seccompPath,
		sandboxPath,
		workspacePath,
		controlPath,
		configPath,
		cgroupPath,
		sandboxdHostPath,
	} {
		if len(generated) > 4096 || !filepath.IsAbs(generated) || filepath.Clean(generated) != generated {
			return LaunchPlan{}, fmt.Errorf("%w: derived host path exceeds platform bounds", ErrInvalidRequest)
		}
	}

	var configuration strings.Builder
	_, _ = fmt.Fprintf(&configuration, "name: %s\n", strconv.Quote("circulusd-"+request.SandboxID.String()+"-"+generationPath))
	_, _ = configuration.WriteString("mode: ONCE\n")
	_, _ = fmt.Fprintf(&configuration, "hostname: %s\n", strconv.Quote(fmt.Sprintf("circulusd-%x", request.Generation)))
	_, _ = configuration.WriteString("cwd: \"/\"\n")
	_, _ = fmt.Fprintf(&configuration, "time_limit: %d\n", limits.MaximumLifetimeSeconds)
	_, _ = configuration.WriteString("daemon: false\nkeep_env: false\nkeep_caps: false\ndisable_no_new_privs: false\n")
	_, _ = configuration.WriteString("skip_setsid: false\nforward_signals: false\n")
	_, _ = fmt.Fprintf(&configuration, "pass_fd: %d\n", handshakeNonceFD)
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
	_, _ = fmt.Fprintf(&configuration, "cgroup_mem_max: %d\ncgroup_mem_swap_max: 0\n", limits.MemoryBytes)
	_, _ = fmt.Fprintf(&configuration, "cgroup_pids_max: %d\ncgroup_cpu_ms_per_sec: %d\n", limits.MaximumProcesses, limits.CPUMillisPerSecond)
	_, _ = fmt.Fprintf(&configuration, "cgroupv2_mount: %s\nuse_cgroupv2: true\ndetect_cgroupv2: false\n", strconv.Quote(cgroupPath))
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
	_, _ = fmt.Fprintf(&configuration, "  arg: \"--sandbox-id\"\n  arg: %s\n", strconv.Quote(request.SandboxID.String()))
	_, _ = fmt.Fprintf(&configuration, "  arg: \"--generation\"\n  arg: %s\n", strconv.Quote(strconv.FormatUint(request.Generation, 10)))
	_, _ = fmt.Fprintf(&configuration, "  arg: \"--protocol-version\"\n  arg: %s\n", strconv.Quote(strconv.FormatUint(uint64(planner.config.ProtocolVersion), 10)))
	_, _ = fmt.Fprintf(&configuration, "  arg: \"--allow-client-uid\"\n  arg: %s\n}\n", strconv.Quote(strconv.FormatUint(uint64(planner.config.SandboxdClientUID), 10)))

	plan := LaunchPlan{
		executable:           planner.config.BinaryPath,
		arguments:            []string{"--config", configPath},
		configPath:           configPath,
		configuration:        []byte(configuration.String()),
		sandboxID:            request.SandboxID,
		generation:           request.Generation,
		environmentRoot:      planner.config.EnvironmentRoot,
		sandboxRoot:          planner.config.SandboxRoot,
		cgroupPath:           cgroupPath,
		rootfsPath:           rootfsPath,
		seccompPath:          seccompPath,
		sandboxdHostPath:     sandboxdHostPath,
		rootfsDigest:         request.RootfsDigest,
		seccompProfileDigest: request.SeccompProfileDigest,
		sandboxdDigest:       request.SandboxdDigest,
		hostUID:              request.HostUID,
		hostGID:              request.HostGID,
	}
	plan.digest = digestLaunchPlan(plan)
	return plan, nil
}

func digestLaunchPlan(plan LaunchPlan) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(planDigestDomain))
	fields := [][]byte{
		[]byte(plan.executable),
		[]byte(strconv.Itoa(len(plan.arguments))),
	}
	for _, argument := range plan.arguments {
		fields = append(fields, []byte(argument))
	}
	fields = append(fields,
		[]byte(plan.configPath),
		plan.configuration,
		[]byte(plan.sandboxID.String()),
		[]byte(strconv.FormatUint(plan.generation, 10)),
		[]byte(plan.environmentRoot),
		[]byte(plan.sandboxRoot),
		[]byte(plan.cgroupPath),
		[]byte(plan.rootfsPath),
		[]byte(plan.seccompPath),
		[]byte(plan.sandboxdHostPath),
		[]byte(plan.rootfsDigest),
		[]byte(plan.seccompProfileDigest),
		[]byte(plan.sandboxdDigest),
		[]byte(strconv.FormatUint(uint64(plan.hostUID), 10)),
		[]byte(strconv.FormatUint(uint64(plan.hostGID), 10)),
	)
	var length [8]byte
	for _, field := range fields {
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(field)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}
