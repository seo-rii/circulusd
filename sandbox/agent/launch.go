//go:build linux

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	controlSocketInside  = "/run/circulusd/control/control.sock"
	manifestInside       = "/etc/circulusd/commands.json"
	sandboxdInside       = "/sandbox/sandboxd"
	pythonWrapperInside  = "/sandbox/python3"
	dockerDefaultImage   = "python:3.14-slim"
	dockerPythonPath     = "/usr/local/bin/python3"
	sharedStateDir       = "/mnt/wsl/circulusd-test"
	setprivPath          = "/usr/bin/setpriv"
	unprivilegedUID      = 1000
	launchNonceFD        = 3
	readyTimeout         = 20 * time.Second
	readyTimeoutDocker   = 80 * time.Second
	socketPollInterval   = 50 * time.Millisecond
	defaultWorkspaceSize = "256m"
)

var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type launchOptions struct {
	sandboxd      string
	stateDir      string
	launcher      string
	backend       string
	python        string
	image         string
	workspaceSize string
	bindHost      string
	maxSessions   int
	sessionIdle   time.Duration
	ledgerBudget  int
}

type pythonInfo struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Command string `json:"command"`
}

// launcherPlan is everything decided once at startup: which launcher, the
// sandboxd digest and copy, the interpreter, the command manifest, and the
// execution-environment digest. launch() stamps out one sandboxd instance per
// session from it, so every session gets its own jail (mount/pid/net
// namespaces or container), its own tmpfs /workspace, and its own sandboxd
// idempotency ledger.
type launcherPlan struct {
	Launcher          string
	Backend           string
	SandboxdDigest    string
	EnvironmentDigest string
	Python            pythonInfo
	StateDir          string
	Extra             map[string]any

	options      launchOptions
	self         string
	manifest     []byte
	sandboxdCopy string // shared, digest-named copy under StateDir (bind-mounted read-only into every jail)
	wrapper      string
	uid, gid     uint32
	subUID       uint32
	subGID       uint32
	image        string
}

// instance is one running sandboxd generation for one session.
type instance struct {
	ID         string
	Generation uint64
	Launcher   string
	Nonce      []byte
	// ServerUID is sandboxd's uid as seen from this process (SO_PEERCRED).
	ServerUID uint32
	// ClientUID is this process's uid as sandboxd sees it (the --allow-client-uid value).
	ClientUID     uint32
	SocketPath    string
	InstanceDir   string
	containerName string

	cmd     *exec.Cmd
	watched bool // the Wait goroutine owns cmd.Wait and closes done
	done    chan struct{}
	err     error
}

func newIdentity(kind string) string {
	entropy := make([]byte, 16)
	if _, err := rand.Read(entropy); err != nil {
		panic(err)
	}
	return kind + "_" + idEncoding.EncodeToString(entropy)
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func environmentDigestOf(environment map[string]any) string {
	encoded, err := json.Marshal(environment)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func subordinateRange(path, name string) (uint32, bool) {
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(content), "\n") {
		parts := strings.Split(strings.TrimSpace(line), ":")
		if len(parts) == 3 && parts[0] == name {
			start, err := strconv.ParseUint(parts[1], 10, 32)
			if err == nil {
				return uint32(start), true
			}
		}
	}
	return 0, false
}

func kernelRelease() string {
	content, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return runtime.GOOS
	}
	return strings.TrimSpace(string(content))
}

func distroName() string {
	if name := os.Getenv("WSL_DISTRO_NAME"); name != "" {
		return name
	}
	host, err := os.Hostname()
	if err != nil {
		return "linux"
	}
	return host
}

// pythonWrapperScript is the manifest command sandboxd runs as inner root; it
// drops to the unprivileged inner uid before starting the interpreter.
func pythonWrapperScript(python string) string {
	return fmt.Sprintf("#!/bin/sh\nexec %s --reuid=%d --regid=%d --clear-groups --inh-caps=-all --no-new-privs %s \"$@\"\n",
		setprivPath, unprivilegedUID, unprivilegedUID, python)
}

func sandboxdArguments(id string, generation uint64, backend, environmentDigest string, allowClientUID uint32) []string {
	return []string{
		sandboxdInside,
		"--control-socket", controlSocketInside,
		"--command-manifest", manifestInside,
		"--command-manifest-owner-uid", strconv.Itoa(unprivilegedUID),
		"--sandbox-id", id,
		"--generation", strconv.FormatUint(generation, 10),
		"--backend", backend,
		"--execution-environment-digest", environmentDigest,
		"--protocol-version", "1",
		"--allow-client-uid", strconv.FormatUint(uint64(allowClientUID), 10),
	}
}

// ------------------------------------------------------------ launcher choice

// chooseLauncher: an explicit launcher must be usable; auto takes the first
// usable one of nsjail, docker, unshare and says why the others were skipped.
func chooseLauncher(requested string) (string, string, error) {
	if requested != "auto" {
		if problem := launcherProblem(requested); problem != "" {
			return "", "", fmt.Errorf("launcher %s is unavailable: %s", requested, problem)
		}
		return requested, "", nil
	}
	var skipped []string
	for _, candidate := range []string{"nsjail", "docker", "unshare"} {
		problem := launcherProblem(candidate)
		if problem == "" {
			why := "auto: using " + candidate
			if len(skipped) > 0 {
				why += " (" + strings.Join(skipped, "; ") + ")"
			}
			return candidate, why, nil
		}
		skipped = append(skipped, candidate+": "+problem)
	}
	return "", "", errors.New("no sandbox launcher is usable: " + strings.Join(skipped, "; "))
}

func launcherProblem(launcher string) string {
	switch launcher {
	case "docker":
		_, problem := dockerStatus()
		return problem
	case "nsjail", "unshare":
		return namespacesProblem(launcher)
	default:
		return "unknown launcher"
	}
}

func namespacesProblem(launcher string) string {
	current, err := user.Current()
	if err != nil {
		return err.Error()
	}
	if _, ok := subordinateRange("/etc/subuid", current.Username); !ok {
		return fmt.Sprintf("no subordinate uid range for %s in /etc/subuid (add '%s:100000:65536'; needs root)", current.Username, current.Username)
	}
	if _, ok := subordinateRange("/etc/subgid", current.Username); !ok {
		return fmt.Sprintf("no subordinate gid range for %s in /etc/subgid (add '%s:100000:65536'; needs root)", current.Username, current.Username)
	}
	required := []string{"unshare", "newuidmap", "newgidmap"}
	if launcher == "nsjail" {
		required = append(required, "nsjail")
	}
	for _, tool := range required {
		if _, err := exec.LookPath(tool); err != nil {
			return tool + " is not on PATH"
		}
	}
	// The python wrapper inside the jail calls setpriv by this exact path.
	if _, err := os.Stat(setprivPath); err != nil {
		return setprivPath + " is missing (install util-linux)"
	}
	return ""
}

var dockerStatusOnce struct {
	sync.Once
	version string
	problem string
}

// dockerStatus asks the daemon once per process.
func dockerStatus() (string, string) {
	dockerStatusOnce.Do(func() {
		if _, err := exec.LookPath("docker"); err != nil {
			dockerStatusOnce.problem = "docker CLI is not on PATH in this environment"
			return
		}
		output, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}} {{.OSType}}/{{.Architecture}}").Output()
		if err != nil {
			detail := err.Error()
			var exitError *exec.ExitError
			if errors.As(err, &exitError) && len(exitError.Stderr) > 0 {
				lines := strings.Split(strings.TrimSpace(string(exitError.Stderr)), "\n")
				detail = lines[len(lines)-1]
			}
			dockerStatusOnce.problem = "docker daemon unreachable: " + detail
			return
		}
		dockerStatusOnce.version = strings.TrimSpace(string(output))
	})
	return dockerStatusOnce.version, dockerStatusOnce.problem
}

// ---------------------------------------------------------------------- plan

func preparePlan(options launchOptions) (*launcherPlan, error) {
	if os.Getuid() == 0 {
		return nil, errors.New("refusing to launch as root; run as an unprivileged user")
	}
	if _, err := os.Stat(options.sandboxd); err != nil {
		return nil, fmt.Errorf("sandboxd binary not found at %s; build it with `pnpm sandbox:build`", options.sandboxd)
	}
	digest, err := sha256File(options.sandboxd)
	if err != nil {
		return nil, err
	}
	launcher, why, err := chooseLauncher(options.launcher)
	if err != nil {
		return nil, err
	}
	if why != "" {
		logf("%s", why)
	}
	backend := options.backend
	if backend == "" {
		if launcher == "docker" {
			backend = "docker"
		} else {
			backend = "nsjail"
		}
	}
	if (launcher == "docker") != (backend == "docker") {
		return nil, errors.New("--backend docker goes with the docker launcher only")
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	plan := &launcherPlan{
		Launcher:       launcher,
		Backend:        backend,
		SandboxdDigest: digest,
		Extra:          map[string]any{},
		options:        options,
		self:           self,
	}
	if launcher == "docker" {
		err = plan.prepareDocker()
	} else {
		err = plan.prepareNamespaces()
	}
	if err != nil {
		return nil, err
	}
	plan.sweepStaleInstances()
	return plan, nil
}

// staleInstanceAge is how old an instance directory must be before a sweep
// may treat a silent control socket as abandoned rather than still starting.
const staleInstanceAge = 2 * time.Minute

// sweepStaleInstances removes instance directories (and, for docker, their
// containers) left behind by an agent that did not shut down cleanly. A
// directory is stale when it is old enough and nothing answers on its control
// socket; live instances of another agent sharing the state directory stay.
func (plan *launcherPlan) sweepStaleInstances() {
	entries, err := os.ReadDir(plan.StateDir)
	if err != nil {
		return
	}
	removed := 0
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || !strings.HasPrefix(name, "sandbox_") || !strings.Contains(name, "-g") {
			continue
		}
		info, err := entry.Info()
		if err != nil || time.Since(info.ModTime()) < staleInstanceAge {
			continue
		}
		directory := filepath.Join(plan.StateDir, name)
		if connection, err := net.DialTimeout("unix", filepath.Join(directory, "control", "control.sock"), time.Second); err == nil {
			_ = connection.Close()
			continue // a live sandboxd still serves it
		}
		if plan.Launcher == "docker" {
			_ = exec.Command("docker", "rm", "-f", "circulusd-"+name).Run()
		}
		if err := os.RemoveAll(directory); err == nil {
			removed++
		}
	}
	if removed > 0 {
		logf("removed %d stale sandbox instance directories from %s", removed, plan.StateDir)
	}
}

func (plan *launcherPlan) prepareNamespaces() error {
	options := plan.options
	current, err := user.Current()
	if err != nil {
		return err
	}
	plan.subUID, _ = subordinateRange("/etc/subuid", current.Username)
	plan.subGID, _ = subordinateRange("/etc/subgid", current.Username)
	plan.uid, plan.gid = uint32(os.Getuid()), uint32(os.Getgid())
	pythonVersion, err := probePython([]string{options.python})
	if err != nil {
		return err
	}
	if err := ensurePrivateDirectory(options.stateDir); err != nil {
		return err
	}
	plan.StateDir = options.stateDir
	plan.sandboxdCopy = filepath.Join(options.stateDir, "sandboxd-"+plan.SandboxdDigest[:16])
	if _, err := os.Stat(plan.sandboxdCopy); err != nil {
		if err := copyFile(options.sandboxd, plan.sandboxdCopy, 0o755); err != nil {
			return err
		}
	}
	manifest := map[string]any{"schemaVersion": 1, "commands": []map[string]string{{"name": "python3", "path": pythonWrapperInside}}}
	plan.manifest, _ = json.Marshal(manifest)
	plan.wrapper = pythonWrapperScript(options.python)
	plan.EnvironmentDigest = environmentDigestOf(map[string]any{
		"harness":       "circulusd-test",
		"launcher":      plan.Launcher,
		"sandboxd":      plan.SandboxdDigest,
		"python":        options.python,
		"pythonVersion": pythonVersion,
		"manifest":      manifest,
		"kernel":        kernelRelease(),
		"workspaceSize": options.workspaceSize,
	})
	plan.Python = pythonInfo{Path: options.python, Version: pythonVersion, Command: "python3"}
	return nil
}

func (plan *launcherPlan) prepareDocker() error {
	options := plan.options
	version, problem := dockerStatus()
	if problem != "" {
		return errors.New("docker launcher unavailable: " + problem)
	}
	image := options.image
	if image == "" {
		image = dockerDefaultImage
	}
	imageID, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", image).Output()
	if err != nil {
		logf("pulling %s", image)
		pull := exec.Command("docker", "pull", "--quiet", image)
		pull.Stdout, pull.Stderr = os.Stderr, os.Stderr
		if err := pull.Run(); err != nil {
			return fmt.Errorf("docker pull %s: %w", image, err)
		}
		if imageID, err = exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", image).Output(); err != nil {
			return err
		}
	}
	uid := strconv.Itoa(os.Getuid())
	pythonVersion, err := probePython([]string{"docker", "run", "--rm", "--network", "none", "--user", uid + ":" + uid, "--entrypoint", dockerPythonPath, image})
	if err != nil {
		return err
	}
	// The control socket must be reachable by the daemon; /mnt/wsl is shared
	// across WSL distributions, so it is preferred when it is writable.
	stateDir := options.stateDir
	if info, err := os.Stat(filepath.Dir(sharedStateDir)); err == nil && info.IsDir() {
		if probe, err := os.CreateTemp(filepath.Dir(sharedStateDir), ".circulusd-probe-"); err == nil {
			_ = probe.Close()
			_ = os.Remove(probe.Name())
			stateDir = sharedStateDir
		}
	}
	if err := ensurePrivateDirectory(stateDir); err != nil {
		return err
	}
	plan.StateDir = stateDir
	plan.image = image
	// One shared, digest-named copy for every container (the state directory
	// is usually a tmpfs, so a copy per session would cost RAM per session).
	plan.sandboxdCopy = filepath.Join(stateDir, "sandboxd-"+plan.SandboxdDigest[:16])
	if _, err := os.Stat(plan.sandboxdCopy); err != nil {
		if err := copyFile(options.sandboxd, plan.sandboxdCopy, 0o755); err != nil {
			return err
		}
	}
	trimmedID := strings.TrimSpace(string(imageID))
	manifest := map[string]any{"schemaVersion": 1, "commands": []map[string]string{{"name": "python3", "path": dockerPythonPath}}}
	plan.manifest, _ = json.Marshal(manifest)
	plan.EnvironmentDigest = environmentDigestOf(map[string]any{
		"harness":       "circulusd-test",
		"launcher":      "docker",
		"sandboxd":      plan.SandboxdDigest,
		"image":         image,
		"imageId":       trimmedID,
		"python":        dockerPythonPath,
		"pythonVersion": pythonVersion,
		"manifest":      manifest,
		"docker":        version,
		"workspaceSize": options.workspaceSize,
	})
	plan.Python = pythonInfo{Path: dockerPythonPath, Version: pythonVersion, Command: "python3"}
	plan.Extra["image"] = image
	plan.Extra["imageId"] = trimmedID
	plan.Extra["docker"] = version
	return nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

func probePython(command []string) (string, error) {
	output, err := exec.Command(command[0], append(command[1:], "-I", "-c", "import sys; print(sys.version.split()[0])")...).Output()
	if err != nil {
		return "", fmt.Errorf("python probe failed: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

// ------------------------------------------------------------------ instances

// launch starts sandboxd generation `generation` of sandbox `id` in a fresh
// jail and returns once its control socket exists. On any failure nothing is
// left behind (process, container, state directory).
func (plan *launcherPlan) launch(id string, generation uint64) (*instance, error) {
	inst := &instance{
		ID:         id,
		Generation: generation,
		Launcher:   plan.Launcher,
		Nonce:      make([]byte, handshakeNonceBytes),
		ServerUID:  uint32(os.Getuid()),
		done:       make(chan struct{}),
	}
	if _, err := rand.Read(inst.Nonce); err != nil {
		return nil, err
	}
	instanceDir := filepath.Join(plan.StateDir, fmt.Sprintf("%s-g%d", id, generation))
	controlDir := filepath.Join(instanceDir, "control")
	if err := ensurePrivateDirectory(controlDir); err != nil {
		return nil, err
	}
	inst.InstanceDir = instanceDir
	inst.SocketPath = filepath.Join(controlDir, "control.sock")

	var err error
	if plan.Launcher == "docker" {
		err = plan.launchDocker(inst, instanceDir, controlDir)
	} else {
		err = plan.launchNamespaces(inst, instanceDir, controlDir)
	}
	if err != nil {
		inst.stop()
		return nil, err
	}
	inst.watched = true
	go func() {
		inst.err = inst.cmd.Wait()
		close(inst.done)
	}()
	timeout := readyTimeout
	if plan.Launcher == "docker" {
		timeout = readyTimeoutDocker
	}
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(inst.SocketPath); err == nil {
			return inst, nil
		}
		if isClosed(inst.done) {
			inst.cleanup()
			return nil, fmt.Errorf("sandboxd exited (%v) before opening its control socket", inst.err)
		}
		if time.Now().After(deadline) {
			inst.stop()
			return nil, errors.New("sandboxd did not open its control socket in time")
		}
		time.Sleep(socketPollInterval)
	}
}

// exited reports whether the sandboxd process is gone.
func (inst *instance) exited() bool {
	return isClosed(inst.done)
}

// stop ends the sandboxd process (SIGINT, then SIGKILL) and removes its state.
func (inst *instance) stop() {
	if inst.cmd != nil && inst.cmd.Process != nil {
		switch {
		case !inst.watched:
			// launch failed before the Wait watcher was armed.
			_ = inst.cmd.Process.Kill()
			_ = inst.cmd.Wait()
		case !isClosed(inst.done):
			_ = inst.cmd.Process.Signal(os.Interrupt)
			select {
			case <-inst.done:
			case <-time.After(5 * time.Second):
				_ = inst.cmd.Process.Kill()
				<-inst.done
			}
		}
	}
	inst.cleanup()
}

func isClosed(done chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func (inst *instance) cleanup() {
	if inst.containerName != "" {
		_ = exec.Command("docker", "rm", "-f", inst.containerName).Run()
	}
	if inst.InstanceDir != "" {
		_ = os.RemoveAll(inst.InstanceDir)
	}
}

// ------------------------------------------------------- namespace launchers

func (plan *launcherPlan) launchNamespaces(inst *instance, instanceDir, controlDir string) error {
	options := plan.options
	// This process connects as the outside uid, which maps to inner root.
	inst.ClientUID = 0
	command := sandboxdArguments(inst.ID, inst.Generation, plan.Backend, plan.EnvironmentDigest, 0)

	var full []string
	if plan.Launcher == "nsjail" {
		files := map[string]string{
			"passwd":   filepath.Join(instanceDir, "passwd"),
			"group":    filepath.Join(instanceDir, "group"),
			"manifest": filepath.Join(instanceDir, "commands.json"),
			"wrapper":  filepath.Join(instanceDir, "python3"),
		}
		if err := os.WriteFile(files["passwd"], []byte(fmt.Sprintf("root:x:0:0::/:/usr/bin/false\nsandbox:x:%d:%d::/workspace:/usr/bin/false\n", unprivilegedUID, unprivilegedUID)), 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(files["group"], []byte(fmt.Sprintf("root:x:0:\nsandbox:x:%d:\n", unprivilegedUID)), 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(files["wrapper"], []byte(plan.wrapper), 0o755); err != nil {
			return err
		}
		// sandboxd rejects a root-owned manifest: create it as the inner
		// unprivileged uid through a throwaway user namespace with the same map.
		helper := exec.Command("unshare", "--user",
			fmt.Sprintf("--map-users=%d,0,1", plan.uid), fmt.Sprintf("--map-users=%d,%d,1", plan.subUID, unprivilegedUID),
			fmt.Sprintf("--map-groups=%d,0,1", plan.gid), fmt.Sprintf("--map-groups=%d,%d,1", plan.subGID, unprivilegedUID),
			plan.self, "write-manifest", files["manifest"], string(plan.manifest))
		helper.Stderr = os.Stderr
		if err := helper.Run(); err != nil {
			return fmt.Errorf("write manifest as inner uid: %w", err)
		}
		full = nsjailCommand(plan.uid, plan.gid, plan.subUID, plan.subGID, files, controlDir, plan.sandboxdCopy, options.workspaceSize, command)
	} else {
		jail := append([]string{
			plan.self, "jail-init",
			"--root", filepath.Join(instanceDir, "root"),
			"--control", controlDir,
			"--sandboxd", plan.sandboxdCopy,
			"--python", options.python,
			"--manifest", string(plan.manifest),
			"--workspace-size", options.workspaceSize,
			"--",
		}, command...)
		full = append([]string{
			"unshare", "--user",
			fmt.Sprintf("--map-users=%d,0,1", plan.uid), fmt.Sprintf("--map-users=%d,%d,1", plan.subUID, unprivilegedUID),
			fmt.Sprintf("--map-groups=%d,0,1", plan.gid), fmt.Sprintf("--map-groups=%d,%d,1", plan.subGID, unprivilegedUID),
			"--mount", "--pid", "--fork", "--kill-child", "--net", "--ipc", "--uts",
		}, jail...)
	}

	nonceRead, nonceWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	if _, err := nonceWrite.Write(inst.Nonce); err != nil {
		_ = nonceRead.Close()
		_ = nonceWrite.Close()
		return err
	}
	_ = nonceWrite.Close()
	cmd := exec.Command(full[0], full[1:]...)
	cmd.Stdin = nil
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{nonceRead} // becomes fd 3 in the child
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C.UTF-8"}
	// If this agent dies without cleaning up, the jail supervisor is killed
	// too; nsjail and `unshare --kill-child` then take sandboxd down with them.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	err = cmd.Start()
	_ = nonceRead.Close()
	if err != nil {
		return fmt.Errorf("start %s: %w", plan.Launcher, err)
	}
	inst.cmd = cmd
	return nil
}

func nsjailCommand(uid, gid, subUID, subGID uint32, files map[string]string, controlDir, sandboxdCopy, workspaceSize string, command []string) []string {
	args := []string{
		"nsjail",
		"--mode", "o",
		"--quiet",
		"--hostname", "sandbox",
		"--cwd", "/",
		"--time_limit", "0",
		// Both mappings go through newuidmap/newgidmap: nsjail cannot mix a
		// self-written map with an external one.
		"--uid_mapping", fmt.Sprintf("0:%d:1", uid),
		"--uid_mapping", fmt.Sprintf("%d:%d:1", unprivilegedUID, subUID),
		"--gid_mapping", fmt.Sprintf("0:%d:1", gid),
		"--gid_mapping", fmt.Sprintf("%d:%d:1", unprivilegedUID, subGID),
		// sandboxd runs as inner root with only what setpriv needs to drop the
		// python processes to the unprivileged uid, plus CAP_KILL so it can
		// enforce deadlines on those uid-1000 process groups.
		"--cap", "CAP_SETUID",
		"--cap", "CAP_SETGID",
		"--cap", "CAP_KILL",
		"--rlimit_as", "2048",
		"--rlimit_fsize", "512",
		"--rlimit_nofile", "512",
		"--rlimit_nproc", "256",
		"--rlimit_core", "0",
		"--bindmount_ro", "/usr",
	}
	for _, link := range []string{"bin", "lib", "lib64", "lib32", "sbin"} {
		if info, err := os.Stat("/usr/" + link); err == nil && info.IsDir() {
			args = append(args, "--symlink", "/usr/"+link+":/"+link)
		}
	}
	for _, node := range []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"} {
		args = append(args, "--bindmount_ro", node)
	}
	if _, err := os.Stat("/etc/ld.so.cache"); err == nil {
		args = append(args, "--bindmount_ro", "/etc/ld.so.cache")
	}
	args = append(args,
		"--bindmount_ro", files["passwd"]+":/etc/passwd",
		"--bindmount_ro", files["group"]+":/etc/group",
		"--bindmount_ro", files["manifest"]+":"+manifestInside,
		"--bindmount_ro", files["wrapper"]+":"+pythonWrapperInside,
		"--bindmount_ro", sandboxdCopy+":"+sandboxdInside,
		"--tmpfsmount", "/tmp",
		"--mount", fmt.Sprintf("none:/workspace:tmpfs:mode=0755,size=%s,uid=%d,gid=%d", workspaceSize, unprivilegedUID, unprivilegedUID),
		"--bindmount", controlDir+":/run/circulusd/control",
		"--pass_fd", strconv.Itoa(launchNonceFD),
		"--",
	)
	return append(args, command...)
}

// ------------------------------------------------------------ docker launcher

func (plan *launcherPlan) launchDocker(inst *instance, instanceDir, controlDir string) error {
	options := plan.options
	uid := strconv.Itoa(os.Getuid())
	manifestPath := filepath.Join(instanceDir, "commands.json")
	if err := os.WriteFile(manifestPath, append(append([]byte(nil), plan.manifest...), '\n'), 0o644); err != nil {
		return err
	}
	inst.ClientUID = uint32(os.Getuid())
	inst.containerName = fmt.Sprintf("circulusd-%s-g%d", inst.ID, inst.Generation)
	command := sandboxdArguments(inst.ID, inst.Generation, plan.Backend, plan.EnvironmentDigest, uint32(os.Getuid()))
	// sandboxd and the model's python share this uid inside the container (a
	// non-root --user has no capability to setuid). The container is per
	// session, so the only sandboxd python can reach is its own.
	args := []string{
		"run", "--rm", "-i",
		"--name", inst.containerName,
		"--hostname", "sandbox",
		"--network", "none",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true",
		"--pids-limit", "256",
		"--memory", "512m",
		"--user", uid + ":" + uid,
		"--tmpfs", fmt.Sprintf("/workspace:rw,nosuid,nodev,size=%s,uid=%s,gid=%s,mode=0755", options.workspaceSize, uid, uid),
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
		"-v", controlDir + ":/run/circulusd/control",
		"-v", plan.sandboxdCopy + ":" + sandboxdInside + ":ro",
		"-v", manifestPath + ":" + manifestInside + ":ro",
		"--entrypoint", "/bin/sh",
		plan.image,
		// The launch nonce arrives on stdin; sandboxd requires it on fd 3 as a pipe.
		"-c", `exec 3<&0 0</dev/null; exec "$@"`, "sh",
	}
	args = append(args, command...)
	cmd := exec.Command("docker", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("docker run: %w", err)
	}
	inst.cmd = cmd
	if _, err := stdin.Write(inst.Nonce); err != nil {
		return fmt.Errorf("write launch nonce: %w", err)
	}
	_ = stdin.Close() // EOF: sandboxd reads exactly 32 bytes
	return nil
}

// copyFile writes through a unique temporary file so concurrent agents
// sharing a state directory never see (or rename) each other's partial copy.
func copyFile(source, destination string, mode os.FileMode) error {
	content, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), "."+filepath.Base(destination)+".*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		_ = os.Remove(name)
		return err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, destination); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}
