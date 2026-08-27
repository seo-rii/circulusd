//go:build linux

package nsjail

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	handshakeNonceBytes  = 32
	privateDirectoryMode = uint32(0o700)
	privateFileMode      = uint32(0o600)
	secureResolveFlags   = uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS)
	cgroupDrainTimeout   = 30 * time.Second
	nonceRevokeTimeout   = 5 * time.Second
)

var (
	ErrUnsafeArtifact         = errors.New("unsafe NsJail artifact")
	ErrArtifactDigestMismatch = errors.New("NsJail artifact digest mismatch")
	ErrSandboxExists          = errors.New("NsJail sandbox generation already exists")
	ErrLaunchFailed           = errors.New("NsJail process launch failed")
)

// launchCommand is the complete exec boundary. Environment is always a
// non-nil empty slice, and ExtraFiles contains only the anonymous nonce read
// end, which becomes descriptor 3 in the child.
type launchCommand struct {
	Executable  string
	Arguments   []string
	Environment []string
	ExtraFiles  []*os.File
}

type processStarter interface {
	Start(launchCommand) (launchedProcess, error)
}

type launchedProcess interface {
	Wait() error
	SignalGroup(syscall.Signal) error
}

// cgroupScopedProcess marks the production process implementation. Its leader
// signal is pidfd-bound, while Instance first uses cgroup.kill as the authority
// for every descendant in the sandbox generation.
type cgroupScopedProcess interface {
	launchedProcess
	requiresCgroupKill()
}

// HandshakeNonceRegistration is a one-time broker registration. Revoke must
// be idempotent and must forget the raw nonce before returning success.
type HandshakeNonceRegistration interface {
	Revoke(context.Context) error
}

// HandshakeNonceRegistrationRequest is launch-time authority captured only
// after Launcher has securely materialized the exact control directory. Its
// formatting deliberately redacts the one-time nonce.
type HandshakeNonceRegistrationRequest struct {
	SandboxID    string
	Generation   uint64
	SocketPath   string
	ServerUID    uint32
	OneTimeNonce []byte
}

func (request HandshakeNonceRegistrationRequest) String() string {
	return formatRedactedHandshakeRegistration(request, "")
}

func (request HandshakeNonceRegistrationRequest) GoString() string {
	return formatRedactedHandshakeRegistration(request, "nsjail.HandshakeNonceRegistrationRequest")
}

func formatRedactedHandshakeRegistration(request HandshakeNonceRegistrationRequest, prefix string) string {
	return fmt.Sprintf("%s{SandboxID:%q Generation:%d SocketPath:%q ServerUID:%d OneTimeNonce:<redacted>}",
		prefix, request.SandboxID, request.Generation, request.SocketPath, request.ServerUID)
}

// HandshakeNonceRegistry synchronously snapshots a raw nonce, the exact sealed
// host socket path, and its expected server UID before NsJail is started. The
// broker can later consume that launch authority while authenticating sandboxd.
type HandshakeNonceRegistry interface {
	RegisterHandshakeNonce(
		context.Context,
		HandshakeNonceRegistrationRequest,
	) (HandshakeNonceRegistration, error)
}

// Launcher validates and atomically materializes sealed plans before invoking
// NsJail. Its cross-process admission authority is the exclusive generation
// directory, not in-memory state.
type Launcher struct {
	starter       processStarter
	nonceRegistry HandshakeNonceRegistry
}

// NewLauncher returns the production Linux process launcher.
func NewLauncher(nonceRegistry HandshakeNonceRegistry) *Launcher {
	return newLauncherWithNonceRegistry(osProcessStarter{}, nonceRegistry)
}

func newLauncherWithNonceRegistry(starter processStarter, nonceRegistry HandshakeNonceRegistry) *Launcher {
	return &Launcher{starter: starter, nonceRegistry: nonceRegistry}
}

// Start validates all sealed metadata before mutation, admits exactly one
// generation, supplies a fresh nonce on fd 3, and starts NsJail with no
// ambient environment.
func (launcher *Launcher) Start(ctx context.Context, plan LaunchPlan) (*Instance, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrLaunchFailed)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if launcher == nil || launcher.starter == nil || launcher.nonceRegistry == nil {
		return nil, fmt.Errorf("%w: launcher has no process starter or handshake nonce registry", ErrLaunchFailed)
	}

	generationName := fmt.Sprintf("generation-%016x", plan.generation)
	sandboxPath := filepath.Join(plan.sandboxRoot, plan.sandboxID.String(), generationName)
	expectedRootfsPath := filepath.Join(plan.environmentRoot, plan.rootfsDigest, "nsjail", "rootfs")
	expectedSeccompPath := filepath.Join(plan.environmentRoot, plan.rootfsDigest, "nsjail", "seccomp", plan.seccompProfileDigest+".policy")
	cgroupIdentityPath := filepath.Dir(plan.cgroupPath)
	cgroupRoot := filepath.Dir(cgroupIdentityPath)
	if filepath.Dir(plan.configPath) != sandboxPath || filepath.Base(plan.configPath) != "nsjail.pbtxt" ||
		plan.rootfsPath != expectedRootfsPath || plan.seccompPath != expectedSeccompPath ||
		filepath.Base(plan.cgroupPath) != generationName ||
		filepath.Base(cgroupIdentityPath) != plan.sandboxID.String() ||
		filepath.Join(cgroupRoot, plan.sandboxID.String(), generationName) != plan.cgroupPath {
		return nil, ErrPlanTampered
	}

	// Keep every trusted artifact open while it is checked. openat2 rejects
	// symlinks and magic links in every component; directory policy rejects
	// mutable replacement points.
	binaryFD, err := openTrustedAbsolute(plan.executable, uint64(unix.O_RDONLY|unix.O_CLOEXEC))
	if err != nil {
		return nil, fmt.Errorf("%w: NsJail binary: %w", ErrUnsafeArtifact, err)
	}
	defer unix.Close(binaryFD)
	if err := verifyTrustedRegular(binaryFD, true); err != nil {
		return nil, fmt.Errorf("%w: NsJail binary: %w", ErrUnsafeArtifact, err)
	}

	environmentFD, err := openTrustedAbsolute(plan.environmentRoot, uint64(unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC))
	if err != nil {
		return nil, fmt.Errorf("%w: environment root: %w", ErrUnsafeArtifact, err)
	}
	defer unix.Close(environmentFD)
	if err := verifyTrustedDirectory(environmentFD, false); err != nil {
		return nil, fmt.Errorf("%w: environment root: %w", ErrUnsafeArtifact, err)
	}

	rootfsRelative, err := relativeBeneath(plan.environmentRoot, plan.rootfsPath)
	if err != nil {
		return nil, ErrPlanTampered
	}
	rootfsFD, err := openTrustedRelative(environmentFD, rootfsRelative, uint64(unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC), false)
	if err != nil {
		return nil, fmt.Errorf("%w: rootfs chain: %w", ErrUnsafeArtifact, err)
	}
	defer unix.Close(rootfsFD)
	if err := verifyTrustedDirectory(rootfsFD, false); err != nil {
		return nil, fmt.Errorf("%w: rootfs: %w", ErrUnsafeArtifact, err)
	}

	for _, target := range []struct {
		path      string
		directory bool
	}{
		{path: "workspace", directory: true},
		{path: "scratch", directory: true},
		{path: "tmp", directory: true},
		{path: "run", directory: true},
		{path: "run/circulusd/control", directory: true},
		{path: "proc", directory: true},
		{path: "dev/null"},
		{path: "dev/zero"},
		{path: "dev/urandom"},
	} {
		flags := uint64(unix.O_PATH | unix.O_CLOEXEC)
		if target.directory {
			flags |= unix.O_DIRECTORY
		}
		fd, openErr := openTrustedRelative(rootfsFD, target.path, flags, true)
		if openErr != nil {
			return nil, fmt.Errorf("%w: rootfs mount target %s: %w", ErrUnsafeArtifact, target.path, openErr)
		}
		if target.directory {
			openErr = verifyTrustedDirectory(fd, false)
		} else {
			openErr = verifyTrustedRegular(fd, false)
		}
		_ = unix.Close(fd)
		if openErr != nil {
			return nil, fmt.Errorf("%w: rootfs mount target %s: %w", ErrUnsafeArtifact, target.path, openErr)
		}
	}

	sandboxdRelative, err := relativeBeneath(plan.rootfsPath, plan.sandboxdHostPath)
	if err != nil {
		return nil, ErrPlanTampered
	}
	sandboxdFD, err := openTrustedRelative(rootfsFD, sandboxdRelative, uint64(unix.O_RDONLY|unix.O_CLOEXEC), true)
	if err != nil {
		return nil, fmt.Errorf("%w: sandboxd: %w", ErrUnsafeArtifact, err)
	}
	defer unix.Close(sandboxdFD)
	if err := verifyTrustedRegular(sandboxdFD, true); err != nil {
		return nil, fmt.Errorf("%w: sandboxd: %w", ErrUnsafeArtifact, err)
	}
	if err := verifyFileDigest(sandboxdFD, plan.sandboxdDigest); err != nil {
		return nil, fmt.Errorf("%w: sandboxd: %w", ErrArtifactDigestMismatch, err)
	}

	seccompRelative, err := relativeBeneath(plan.environmentRoot, plan.seccompPath)
	if err != nil {
		return nil, ErrPlanTampered
	}
	seccompFD, err := openTrustedRelative(environmentFD, seccompRelative, uint64(unix.O_RDONLY|unix.O_CLOEXEC), false)
	if err != nil {
		return nil, fmt.Errorf("%w: seccomp profile: %w", ErrUnsafeArtifact, err)
	}
	defer unix.Close(seccompFD)
	if err := verifyTrustedRegular(seccompFD, false); err != nil {
		return nil, fmt.Errorf("%w: seccomp profile: %w", ErrUnsafeArtifact, err)
	}
	if err := verifyFileDigest(seccompFD, plan.seccompProfileDigest); err != nil {
		return nil, fmt.Errorf("%w: seccomp profile: %w", ErrArtifactDigestMismatch, err)
	}

	sandboxRootFD, err := openTrustedAbsolute(plan.sandboxRoot, uint64(unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC))
	if err != nil {
		return nil, fmt.Errorf("%w: sandbox root: %w", ErrUnsafeArtifact, err)
	}
	defer unix.Close(sandboxRootFD)
	if err := verifyTrustedDirectory(sandboxRootFD, true); err != nil {
		return nil, fmt.Errorf("%w: sandbox root: %w", ErrUnsafeArtifact, err)
	}
	cgroupRootFD, err := openTrustedAbsolute(cgroupRoot, uint64(unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC))
	if err != nil {
		return nil, fmt.Errorf("%w: cgroup root: %w", ErrUnsafeArtifact, err)
	}
	defer unix.Close(cgroupRootFD)
	if err := verifyTrustedDirectory(cgroupRootFD, true); err != nil {
		return nil, fmt.Errorf("%w: cgroup root: %w", ErrUnsafeArtifact, err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sandboxIDFD, _, err := ensurePrivateDirectory(sandboxRootFD, plan.sandboxID.String(), uint32(os.Geteuid()), uint32(os.Getegid()))
	if err != nil {
		return nil, fmt.Errorf("%w: sandbox identity directory: %w", ErrUnsafeArtifact, err)
	}
	defer unix.Close(sandboxIDFD)
	sandboxGenerationFD, err := createPrivateDirectoryExclusive(sandboxIDFD, generationName, uint32(os.Geteuid()), uint32(os.Getegid()))
	if errors.Is(err, unix.EEXIST) {
		return nil, ErrSandboxExists
	}
	if err != nil {
		return nil, fmt.Errorf("materialize sandbox generation: %w", err)
	}
	defer unix.Close(sandboxGenerationFD)
	materialized := true
	cleanupOnFailure := func(cause error) error {
		if !materialized {
			return cause
		}
		cleanupErr := cleanupGeneration(plan.sandboxRoot, cgroupRoot, plan.sandboxID.String(), generationName)
		return errors.Join(cause, cleanupErr)
	}

	for _, directory := range []string{"workspace", "control"} {
		fd, createErr := createPrivateDirectoryExclusive(sandboxGenerationFD, directory, plan.hostUID, plan.hostGID)
		if createErr != nil {
			return nil, cleanupOnFailure(fmt.Errorf("materialize %s: %w", directory, createErr))
		}
		_ = unix.Close(fd)
	}

	configFD, err := unix.Openat(sandboxGenerationFD, "nsjail.pbtxt", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, privateFileMode)
	if err != nil {
		return nil, cleanupOnFailure(fmt.Errorf("materialize NsJail config: %w", err))
	}
	if err := unix.Fchmod(configFD, privateFileMode); err == nil {
		err = unix.Fchown(configFD, os.Geteuid(), os.Getegid())
	}
	if err == nil {
		remaining := plan.configuration
		for len(remaining) > 0 {
			var count int
			count, err = unix.Write(configFD, remaining)
			if err != nil {
				break
			}
			if count == 0 {
				err = io.ErrShortWrite
				break
			}
			remaining = remaining[count:]
		}
	}
	if err == nil {
		err = unix.Fsync(configFD)
	}
	closeErr := unix.Close(configFD)
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, cleanupOnFailure(fmt.Errorf("write NsJail config: %w", err))
	}

	cgroupIDFD, _, err := ensurePrivateDirectory(cgroupRootFD, plan.sandboxID.String(), uint32(os.Geteuid()), uint32(os.Getegid()))
	if err != nil {
		return nil, cleanupOnFailure(fmt.Errorf("materialize cgroup identity directory: %w", err))
	}
	defer unix.Close(cgroupIDFD)
	cgroupGenerationFD, err := createPrivateDirectoryExclusive(cgroupIDFD, generationName, uint32(os.Geteuid()), uint32(os.Getegid()))
	if errors.Is(err, unix.EEXIST) {
		return nil, cleanupOnFailure(ErrSandboxExists)
	}
	if err != nil {
		return nil, cleanupOnFailure(fmt.Errorf("materialize cgroup generation: %w", err))
	}
	defer unix.Close(cgroupGenerationFD)

	heldDirectories := generationHandles{
		sandboxRootFD:       -1,
		sandboxIdentityFD:   -1,
		sandboxGenerationFD: -1,
		cgroupRootFD:        -1,
		cgroupIdentityFD:    -1,
		cgroupGenerationFD:  -1,
	}
	for destination, source := range map[*int]int{
		&heldDirectories.sandboxRootFD:       sandboxRootFD,
		&heldDirectories.sandboxIdentityFD:   sandboxIDFD,
		&heldDirectories.sandboxGenerationFD: sandboxGenerationFD,
		&heldDirectories.cgroupRootFD:        cgroupRootFD,
		&heldDirectories.cgroupIdentityFD:    cgroupIDFD,
		&heldDirectories.cgroupGenerationFD:  cgroupGenerationFD,
	} {
		*destination, err = duplicateCloseOnExec(source)
		if err != nil {
			heldDirectories.close()
			return nil, cleanupOnFailure(fmt.Errorf("seal generation directory handles: %w", err))
		}
	}
	heldDirectoriesTransferred := false
	defer func() {
		if !heldDirectoriesTransferred {
			heldDirectories.close()
		}
	}()

	if err := ctx.Err(); err != nil {
		return nil, cleanupOnFailure(err)
	}
	if err := plan.Validate(); err != nil {
		return nil, cleanupOnFailure(err)
	}
	materializedConfigFD, err := openTrustedRelative(sandboxGenerationFD, "nsjail.pbtxt", uint64(unix.O_RDONLY|unix.O_CLOEXEC), false)
	if err != nil {
		return nil, cleanupOnFailure(fmt.Errorf("verify materialized config: %w", err))
	}
	materializedConfig := os.NewFile(uintptr(materializedConfigFD), "nsjail.pbtxt")
	if materializedConfig == nil {
		_ = unix.Close(materializedConfigFD)
		return nil, cleanupOnFailure(errors.New("verify materialized config: invalid descriptor"))
	}
	if err := verifyExactPrivateRegular(materializedConfigFD, uint32(os.Geteuid()), uint32(os.Getegid())); err != nil {
		_ = materializedConfig.Close()
		return nil, cleanupOnFailure(fmt.Errorf("verify materialized config: %w", err))
	}
	materializedConfiguration, err := io.ReadAll(materializedConfig)
	closeErr = materializedConfig.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil || !equalBytes(materializedConfiguration, plan.configuration) {
		if err == nil {
			err = ErrPlanTampered
		}
		return nil, cleanupOnFailure(fmt.Errorf("verify materialized config: %w", err))
	}

	nonce := make([]byte, handshakeNonceBytes)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		zeroBytes(nonce)
		return nil, cleanupOnFailure(fmt.Errorf("%w: generate handshake nonce: %w", ErrLaunchFailed, err))
	}
	nonceCommitment := sha256.Sum256(nonce)
	registryNonce := append([]byte(nil), nonce...)
	nonceRegistration, registrationErr := launcher.nonceRegistry.RegisterHandshakeNonce(
		ctx,
		HandshakeNonceRegistrationRequest{
			SandboxID:    plan.sandboxID.String(),
			Generation:   plan.generation,
			SocketPath:   filepath.Join(sandboxPath, "control", sandboxControlSocketName),
			ServerUID:    plan.hostUID,
			OneTimeNonce: registryNonce,
		},
	)
	zeroBytes(registryNonce)
	if registrationErr != nil || nonceRegistration == nil {
		zeroBytes(nonce)
		if nonceRegistration != nil {
			revokeContext, cancel := context.WithTimeout(context.Background(), nonceRevokeTimeout)
			revokeErr := nonceRegistration.Revoke(revokeContext)
			cancel()
			registrationErr = errors.Join(registrationErr, revokeErr)
		}
		if registrationErr == nil {
			registrationErr = errors.New("handshake nonce registry returned a nil registration")
		}
		return nil, cleanupOnFailure(fmt.Errorf("%w: register handshake nonce: %w", ErrLaunchFailed, registrationErr))
	}
	revokeRegisteredNonce := func(cause error) error {
		revokeContext, cancel := context.WithTimeout(context.Background(), nonceRevokeTimeout)
		revokeErr := nonceRegistration.Revoke(revokeContext)
		cancel()
		return cleanupOnFailure(errors.Join(cause, revokeErr))
	}
	if err := ctx.Err(); err != nil {
		zeroBytes(nonce)
		return nil, revokeRegisteredNonce(err)
	}
	nonceReader, nonceWriter, err := os.Pipe()
	if err != nil {
		zeroBytes(nonce)
		return nil, revokeRegisteredNonce(fmt.Errorf("%w: create handshake pipe: %w", ErrLaunchFailed, err))
	}
	written := 0
	for written < len(nonce) {
		count, writeErr := nonceWriter.Write(nonce[written:])
		if writeErr != nil {
			err = writeErr
			break
		}
		if count == 0 {
			err = io.ErrShortWrite
			break
		}
		written += count
	}
	zeroBytes(nonce)
	writerCloseErr := nonceWriter.Close()
	if err == nil {
		err = writerCloseErr
	}
	if err != nil {
		_ = nonceReader.Close()
		return nil, revokeRegisteredNonce(fmt.Errorf("%w: populate handshake pipe: %w", ErrLaunchFailed, err))
	}

	arguments := plan.Arguments()
	command := launchCommand{
		Executable:  plan.Executable(),
		Arguments:   arguments,
		Environment: make([]string, 0),
		ExtraFiles:  []*os.File{nonceReader},
	}
	process, startErr := launcher.starter.Start(command)
	_ = nonceReader.Close()
	if startErr != nil || process == nil {
		if process != nil {
			_ = process.SignalGroup(syscall.SIGKILL)
			_ = process.Wait()
		}
		if startErr == nil {
			startErr = errors.New("process starter returned nil process")
		}
		return nil, revokeRegisteredNonce(fmt.Errorf("%w: %w", ErrLaunchFailed, startErr))
	}
	materialized = false
	heldDirectoriesTransferred = true

	instance := &Instance{
		process:             process,
		directories:         heldDirectories,
		sandboxID:           plan.sandboxID.String(),
		generationName:      generationName,
		handshakeCommitment: nonceCommitment,
		nonceRegistration:   nonceRegistration,
		waitDone:            make(chan struct{}),
	}
	go func() {
		instance.waitErr = process.Wait()
		close(instance.waitDone)
	}()
	return instance, nil
}

// Instance owns a running NsJail process group and its exact generation
// directories. Lifecycle methods are safe for concurrent callers.
type Instance struct {
	process        launchedProcess
	directories    generationHandles
	sandboxID      string
	generationName string

	waitDone chan struct{}
	waitErr  error

	killMu       sync.Mutex
	killComplete bool
	killAttempt  chan struct{}
	killErr      error

	destroyMu       sync.Mutex
	destroyComplete bool
	destroyAttempt  chan struct{}
	destroyErr      error

	handshakeMu         sync.Mutex
	handshakeCommitment [sha256.Size]byte
	handshakeConsumed   bool
	nonceRegistration   HandshakeNonceRegistration
}

type generationHandles struct {
	sandboxRootFD       int
	sandboxIdentityFD   int
	sandboxGenerationFD int
	cgroupRootFD        int
	cgroupIdentityFD    int
	cgroupGenerationFD  int
	cgroupRemoved       bool
}

func (handles *generationHandles) close() {
	for _, descriptor := range []*int{
		&handles.sandboxRootFD,
		&handles.sandboxIdentityFD,
		&handles.sandboxGenerationFD,
		&handles.cgroupRootFD,
		&handles.cgroupIdentityFD,
		&handles.cgroupGenerationFD,
	} {
		if *descriptor >= 0 {
			_ = unix.Close(*descriptor)
			*descriptor = -1
		}
	}
}

func (handles *generationHandles) cleanup(sandboxID, generationName string) error {
	// cgroup cleanup precedes release of the sandbox admission directory.
	// Every unlink is authorized by an FD captured before exec and an inode
	// comparison, so a path replacement cannot redirect cleanup.
	for _, check := range []struct {
		fd      int
		private bool
	}{
		{fd: handles.cgroupRootFD},
		{fd: handles.sandboxRootFD},
		{fd: handles.cgroupIdentityFD, private: true},
		{fd: handles.cgroupGenerationFD, private: true},
		{fd: handles.sandboxIdentityFD, private: true},
		{fd: handles.sandboxGenerationFD, private: true},
	} {
		var err error
		if check.private {
			err = verifyExactPrivateDirectory(check.fd, uint32(os.Geteuid()), uint32(os.Getegid()))
		} else {
			err = verifyTrustedDirectory(check.fd, true)
		}
		if err != nil {
			return fmt.Errorf("verify sealed cleanup directory: %w", err)
		}
	}
	if !handles.cgroupRemoved {
		if err := verifyDirectoryEntry(handles.cgroupIdentityFD, generationName, handles.cgroupGenerationFD); err != nil {
			return fmt.Errorf("verify cgroup generation entry: %w", err)
		}
		if err := unix.Unlinkat(handles.cgroupIdentityFD, generationName, unix.AT_REMOVEDIR); err != nil {
			return fmt.Errorf("remove cgroup generation: %w", err)
		}
		handles.cgroupRemoved = true
	}
	if err := verifyDirectoryEntry(handles.cgroupRootFD, sandboxID, handles.cgroupIdentityFD); err != nil {
		if !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("verify cgroup identity entry: %w", err)
		}
	} else if err := unix.Unlinkat(handles.cgroupRootFD, sandboxID, unix.AT_REMOVEDIR); err != nil &&
		!errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTEMPTY) && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("remove empty cgroup identity: %w", err)
	}

	if err := removeDirectoryContents(handles.sandboxGenerationFD); err != nil {
		return fmt.Errorf("empty sandbox generation: %w", err)
	}
	if err := verifyDirectoryEntry(handles.sandboxIdentityFD, generationName, handles.sandboxGenerationFD); err != nil {
		return fmt.Errorf("verify sandbox generation entry: %w", err)
	}
	if err := unix.Unlinkat(handles.sandboxIdentityFD, generationName, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("remove sandbox generation: %w", err)
	}
	if err := verifyDirectoryEntry(handles.sandboxRootFD, sandboxID, handles.sandboxIdentityFD); err != nil {
		if !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("verify sandbox identity entry: %w", err)
		}
	} else if err := unix.Unlinkat(handles.sandboxRootFD, sandboxID, unix.AT_REMOVEDIR); err != nil &&
		!errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTEMPTY) && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("remove empty sandbox identity: %w", err)
	}
	return nil
}

// ConsumeHandshakeNonce validates and consumes the sandbox's raw fd-3 nonce.
// A failed attempt also consumes the commitment, preventing guessing and
// replay. The private UDS verifier must call this exactly once per Instance.
func (instance *Instance) ConsumeHandshakeNonce(candidate []byte) bool {
	if instance == nil {
		return false
	}
	instance.handshakeMu.Lock()
	defer instance.handshakeMu.Unlock()
	if instance.handshakeConsumed {
		return false
	}
	instance.handshakeConsumed = true
	candidateCommitment := sha256.Sum256(candidate)
	valid := len(candidate) == handshakeNonceBytes && subtle.ConstantTimeCompare(
		candidateCommitment[:],
		instance.handshakeCommitment[:],
	) == 1
	zeroBytes(instance.handshakeCommitment[:])
	return valid
}

func (instance *Instance) invalidateHandshakeNonce() {
	instance.handshakeMu.Lock()
	instance.handshakeConsumed = true
	zeroBytes(instance.handshakeCommitment[:])
	instance.handshakeMu.Unlock()
}

// Wait returns the process result or the caller's context error.
func (instance *Instance) Wait(ctx context.Context) error {
	if instance == nil || ctx == nil {
		return fmt.Errorf("%w: invalid instance or context", ErrLaunchFailed)
	}
	select {
	case <-instance.waitDone:
		return instance.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Kill sends SIGKILL once successfully to the complete NsJail cgroup and its
// pidfd-bound leader. A failed attempt can be retried by a later caller.
func (instance *Instance) Kill(ctx context.Context) error {
	if instance == nil || ctx == nil {
		return fmt.Errorf("%w: invalid instance or context", ErrLaunchFailed)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	instance.killMu.Lock()
	if instance.killComplete {
		instance.killMu.Unlock()
		return nil
	}
	if instance.killAttempt != nil {
		attempt := instance.killAttempt
		instance.killMu.Unlock()
		select {
		case <-attempt:
			instance.killMu.Lock()
			err := instance.killErr
			instance.killMu.Unlock()
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	attempt := make(chan struct{})
	instance.killAttempt = attempt
	instance.killMu.Unlock()

	var killErr error
	if _, required := instance.process.(cgroupScopedProcess); required {
		killFD, err := unix.Openat2(instance.directories.cgroupGenerationFD, "cgroup.kill", &unix.OpenHow{
			Flags:   uint64(unix.O_WRONLY | unix.O_CLOEXEC),
			Resolve: secureResolveFlags,
		})
		if err == nil {
			var count int
			count, err = unix.Write(killFD, []byte("1"))
			if err == nil && count != 1 {
				err = io.ErrShortWrite
			}
			closeErr := unix.Close(killFD)
			if err == nil {
				err = closeErr
			}
		}
		if err != nil {
			killErr = fmt.Errorf("kill sandbox cgroup: %w", err)
		}
	}
	select {
	case <-instance.waitDone:
	default:
		signalErr := instance.process.SignalGroup(syscall.SIGKILL)
		if !errors.Is(signalErr, syscall.ESRCH) {
			killErr = errors.Join(killErr, signalErr)
		}
	}
	instance.killMu.Lock()
	instance.killErr = killErr
	instance.killComplete = killErr == nil
	instance.killAttempt = nil
	close(attempt)
	instance.killMu.Unlock()
	return killErr
}

// Destroy stops the process group, waits for it to exit, and removes only the
// owned generation. Cleanup continues independently once admitted so caller
// cancellation cannot leave a half-destroyed sandbox.
func (instance *Instance) Destroy(ctx context.Context) error {
	if instance == nil || ctx == nil {
		return fmt.Errorf("%w: invalid instance or context", ErrLaunchFailed)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	instance.destroyMu.Lock()
	if instance.destroyComplete {
		instance.destroyMu.Unlock()
		return nil
	}
	if instance.destroyAttempt == nil {
		attempt := make(chan struct{})
		instance.destroyAttempt = attempt
		go func() {
			instance.invalidateHandshakeNonce()
			revokeContext, cancel := context.WithTimeout(context.Background(), nonceRevokeTimeout)
			revokeErr := instance.nonceRegistration.Revoke(revokeContext)
			cancel()
			killErr := instance.Kill(context.Background())
			var drainErr error
			if killErr == nil {
				<-instance.waitDone
				if _, required := instance.process.(cgroupScopedProcess); required && !instance.directories.cgroupRemoved {
					drainContext, cancel := context.WithTimeout(context.Background(), cgroupDrainTimeout)
					drainErr = waitForEmptyCgroup(drainContext, instance.directories.cgroupGenerationFD)
					cancel()
				}
			}
			destroyErr := errors.Join(revokeErr, killErr, drainErr)
			if destroyErr == nil {
				destroyErr = instance.directories.cleanup(instance.sandboxID, instance.generationName)
			}
			instance.destroyMu.Lock()
			instance.destroyErr = destroyErr
			instance.destroyComplete = destroyErr == nil
			instance.destroyAttempt = nil
			if destroyErr == nil {
				instance.directories.close()
			}
			close(attempt)
			instance.destroyMu.Unlock()
		}()
	}
	attempt := instance.destroyAttempt
	instance.destroyMu.Unlock()
	select {
	case <-attempt:
		instance.destroyMu.Lock()
		err := instance.destroyErr
		instance.destroyMu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

type osProcessStarter struct{}

func (osProcessStarter) Start(command launchCommand) (launchedProcess, error) {
	process := exec.Command(command.Executable, command.Arguments...)
	process.Env = command.Environment
	process.ExtraFiles = command.ExtraFiles
	process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := process.Start(); err != nil {
		return nil, err
	}
	pidFD, err := unix.PidfdOpen(process.Process.Pid, 0)
	if err != nil {
		// Wait has not run, so the leader PID cannot yet be recycled. This is
		// the only safe point at which a raw group signal is used.
		_ = syscall.Kill(-process.Process.Pid, syscall.SIGKILL)
		_ = process.Wait()
		return nil, fmt.Errorf("open NsJail pidfd: %w", err)
	}
	return &osLaunchedProcess{process: process, pidFD: pidFD}, nil
}

type osLaunchedProcess struct {
	process *exec.Cmd
	mu      sync.Mutex
	pidFD   int
}

func (process *osLaunchedProcess) Wait() error {
	err := process.process.Wait()
	process.mu.Lock()
	if process.pidFD >= 0 {
		_ = unix.Close(process.pidFD)
		process.pidFD = -1
	}
	process.mu.Unlock()
	return err
}

func (process *osLaunchedProcess) SignalGroup(signal syscall.Signal) error {
	if process == nil || process.process == nil || process.process.Process == nil {
		return syscall.ESRCH
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.pidFD < 0 {
		return syscall.ESRCH
	}
	return unix.PidfdSendSignal(process.pidFD, unix.Signal(signal), nil, 0)
}

func (*osLaunchedProcess) requiresCgroupKill() {}

func openTrustedAbsolute(path string, finalFlags uint64) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return -1, errors.New("path is not canonical and absolute")
	}
	currentFD, err := unix.Open(string(filepath.Separator), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for index, component := range components {
		flags := uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC)
		if index == len(components)-1 {
			flags = finalFlags
		}
		nextFD, openErr := unix.Openat2(currentFD, component, &unix.OpenHow{Flags: flags, Resolve: secureResolveFlags})
		_ = unix.Close(currentFD)
		if openErr != nil {
			return -1, openErr
		}
		if index != len(components)-1 {
			if verifyErr := verifyTrustedDirectory(nextFD, false); verifyErr != nil {
				_ = unix.Close(nextFD)
				return -1, verifyErr
			}
		}
		currentFD = nextFD
	}
	return currentFD, nil
}

func openTrustedRelative(parentFD int, relative string, finalFlags uint64, noCrossDevice bool) (int, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative ||
		relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return -1, errors.New("path is not canonical and relative")
	}
	currentFD, err := duplicateCloseOnExec(parentFD)
	if err != nil {
		return -1, err
	}
	components := strings.Split(relative, string(filepath.Separator))
	for index, component := range components {
		flags := uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC)
		if index == len(components)-1 {
			flags = finalFlags
		}
		resolve := secureResolveFlags
		if noCrossDevice {
			resolve |= unix.RESOLVE_NO_XDEV
		}
		nextFD, openErr := unix.Openat2(currentFD, component, &unix.OpenHow{Flags: flags, Resolve: resolve})
		_ = unix.Close(currentFD)
		if openErr != nil {
			return -1, openErr
		}
		if index != len(components)-1 {
			if verifyErr := verifyTrustedDirectory(nextFD, false); verifyErr != nil {
				_ = unix.Close(nextFD)
				return -1, verifyErr
			}
		}
		currentFD = nextFD
	}
	return currentFD, nil
}

func verifyTrustedDirectory(fd int, exactPrivate bool) error {
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil {
		return err
	}
	if status.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("not a directory")
	}
	if !trustedOwner(status.Uid, status.Gid) {
		return fmt.Errorf("untrusted owner %d:%d", status.Uid, status.Gid)
	}
	permissions := status.Mode & 0o7777
	if exactPrivate {
		if permissions != privateDirectoryMode {
			return fmt.Errorf("directory mode %#o is not private", permissions)
		}
		return nil
	}
	if permissions&0o022 != 0 && !(status.Uid == 0 && permissions&uint32(unix.S_ISVTX) != 0) {
		return fmt.Errorf("directory mode %#o permits replacement", permissions)
	}
	return nil
}

func verifyTrustedRegular(fd int, executable bool) error {
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil {
		return err
	}
	if status.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("not a regular file")
	}
	if !trustedOwner(status.Uid, status.Gid) {
		return fmt.Errorf("untrusted owner %d:%d", status.Uid, status.Gid)
	}
	permissions := status.Mode & 0o7777
	if permissions&0o7022 != 0 {
		return fmt.Errorf("file mode %#o permits modification", permissions)
	}
	if executable && permissions&0o100 == 0 {
		return fmt.Errorf("file mode %#o is not owner-executable", permissions)
	}
	return nil
}

func trustedOwner(uid, gid uint32) bool {
	effectiveUID, effectiveGID := uint32(os.Geteuid()), uint32(os.Getegid())
	return uid == 0 || (uid == effectiveUID && (gid == 0 || gid == effectiveGID))
}

func verifyFileDigest(fd int, expected string) error {
	readFD, err := duplicateCloseOnExec(fd)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(readFD), "verified-artifact")
	if file == nil {
		_ = unix.Close(readFD)
		return errors.New("invalid artifact descriptor")
	}
	defer file.Close()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	actual := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if actual != expected {
		return fmt.Errorf("got %s, want %s", actual, expected)
	}
	return nil
}

func relativeBeneath(base, target string) (string, error) {
	relative, err := filepath.Rel(base, target)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) ||
		filepath.IsAbs(relative) || filepath.Clean(relative) != relative {
		return "", errors.New("target escapes trusted root")
	}
	return relative, nil
}

func ensurePrivateDirectory(parentFD int, name string, uid, gid uint32) (int, bool, error) {
	created := false
	if err := unix.Mkdirat(parentFD, name, privateDirectoryMode); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return -1, false, err
		}
	} else {
		created = true
	}
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: secureResolveFlags,
	})
	if err != nil {
		if created {
			_ = unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
		}
		return -1, created, err
	}
	if created {
		if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
			return -1, true, err
		}
		if err := unix.Fchmod(fd, privateDirectoryMode); err != nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
			return -1, true, err
		}
	}
	if err := verifyExactPrivateDirectory(fd, uid, gid); err != nil {
		_ = unix.Close(fd)
		if created {
			_ = unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
		}
		return -1, created, err
	}
	return fd, created, nil
}

func createPrivateDirectoryExclusive(parentFD int, name string, uid, gid uint32) (int, error) {
	if err := unix.Mkdirat(parentFD, name, privateDirectoryMode); err != nil {
		return -1, err
	}
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: secureResolveFlags,
	})
	if err != nil {
		_ = unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
		return -1, err
	}
	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
		return -1, err
	}
	if err := unix.Fchmod(fd, privateDirectoryMode); err != nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
		return -1, err
	}
	if err := verifyExactPrivateDirectory(fd, uid, gid); err != nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
		return -1, err
	}
	return fd, nil
}

func verifyExactPrivateDirectory(fd int, uid, gid uint32) error {
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil {
		return err
	}
	if status.Mode&unix.S_IFMT != unix.S_IFDIR || status.Mode&0o7777 != privateDirectoryMode || status.Uid != uid || status.Gid != gid {
		return fmt.Errorf("directory is not sealed as %#o %d:%d", privateDirectoryMode, uid, gid)
	}
	return nil
}

func verifyExactPrivateRegular(fd int, uid, gid uint32) error {
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil {
		return err
	}
	if status.Mode&unix.S_IFMT != unix.S_IFREG || status.Mode&0o7777 != privateFileMode || status.Uid != uid || status.Gid != gid {
		return fmt.Errorf("file is not sealed as %#o %d:%d", privateFileMode, uid, gid)
	}
	return nil
}

func verifyDirectoryEntry(parentFD int, name string, heldFD int) error {
	var heldStatus unix.Stat_t
	if err := unix.Fstat(heldFD, &heldStatus); err != nil {
		return err
	}
	var namedStatus unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &namedStatus, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if heldStatus.Mode&unix.S_IFMT != unix.S_IFDIR || namedStatus.Mode&unix.S_IFMT != unix.S_IFDIR ||
		heldStatus.Dev != namedStatus.Dev || heldStatus.Ino != namedStatus.Ino {
		return errors.New("directory entry no longer names the sealed inode")
	}
	return nil
}

func waitForEmptyCgroup(ctx context.Context, generationFD int) error {
	if ctx == nil {
		return errors.New("nil cgroup wait context")
	}
	eventsFD, err := unix.Openat2(generationFD, "cgroup.events", &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC),
		Resolve: secureResolveFlags,
	})
	if err != nil {
		return fmt.Errorf("open cgroup.events: %w", err)
	}
	defer unix.Close(eventsFD)
	buffer := make([]byte, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		count, readErr := unix.Pread(eventsFD, buffer, 0)
		if readErr != nil {
			if errors.Is(readErr, unix.EINTR) {
				continue
			}
			return fmt.Errorf("read cgroup.events: %w", readErr)
		}
		if count == 0 || count == len(buffer) {
			return errors.New("cgroup.events is empty or exceeds the parser bound")
		}
		populatedSeen := false
		populated := true
		for _, line := range strings.Split(string(buffer[:count]), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if len(fields) != 2 {
				return fmt.Errorf("malformed cgroup.events line %q", line)
			}
			if fields[0] == "populated" {
				if populatedSeen || (fields[1] != "0" && fields[1] != "1") {
					return errors.New("invalid cgroup.events populated field")
				}
				populatedSeen = true
				populated = fields[1] == "1"
			}
		}
		if !populatedSeen {
			return errors.New("cgroup.events omits populated field")
		}
		if !populated {
			return nil
		}

		pollMilliseconds := 50
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return ctx.Err()
			}
			if remaining < 50*time.Millisecond {
				pollMilliseconds = int((remaining + time.Millisecond - 1) / time.Millisecond)
			}
		}
		_, pollErr := unix.Poll([]unix.PollFd{{Fd: int32(eventsFD), Events: unix.POLLPRI | unix.POLLERR}}, pollMilliseconds)
		if pollErr != nil && !errors.Is(pollErr, unix.EINTR) {
			return fmt.Errorf("poll cgroup.events: %w", pollErr)
		}
	}
}

func cleanupGeneration(sandboxRoot, cgroupRoot, sandboxID, generationName string) error {
	// The sandbox generation is the admission authority. Keep it present until
	// the cgroup is gone so a retry cannot be admitted while this cleanup can
	// still address the same generation name (an ABA race).
	cgroupRootFD, err := openTrustedAbsolute(cgroupRoot, uint64(unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC))
	if err != nil {
		return fmt.Errorf("open cgroup root for cleanup: %w", err)
	}
	if err := verifyTrustedDirectory(cgroupRootFD, true); err != nil {
		_ = unix.Close(cgroupRootFD)
		return fmt.Errorf("verify cgroup root for cleanup: %w", err)
	}
	identityFD, openErr := unix.Openat2(cgroupRootFD, sandboxID, &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: secureResolveFlags,
	})
	if openErr == nil {
		if verifyErr := verifyExactPrivateDirectory(identityFD, uint32(os.Geteuid()), uint32(os.Getegid())); verifyErr != nil {
			_ = unix.Close(identityFD)
			_ = unix.Close(cgroupRootFD)
			return fmt.Errorf("verify cgroup identity directory: %w", verifyErr)
		}
		if removeErr := unix.Unlinkat(identityFD, generationName, unix.AT_REMOVEDIR); removeErr != nil && !errors.Is(removeErr, unix.ENOENT) {
			_ = unix.Close(identityFD)
			_ = unix.Close(cgroupRootFD)
			return fmt.Errorf("remove cgroup generation: %w", removeErr)
		}
		_ = unix.Close(identityFD)
		if removeErr := unix.Unlinkat(cgroupRootFD, sandboxID, unix.AT_REMOVEDIR); removeErr != nil &&
			!errors.Is(removeErr, unix.ENOENT) && !errors.Is(removeErr, unix.ENOTEMPTY) && !errors.Is(removeErr, unix.EEXIST) {
			_ = unix.Close(cgroupRootFD)
			return fmt.Errorf("remove cgroup identity directory: %w", removeErr)
		}
	} else if !errors.Is(openErr, unix.ENOENT) {
		_ = unix.Close(cgroupRootFD)
		return fmt.Errorf("open cgroup identity directory: %w", openErr)
	}
	_ = unix.Close(cgroupRootFD)

	sandboxRootFD, err := openTrustedAbsolute(sandboxRoot, uint64(unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC))
	if err != nil {
		return fmt.Errorf("open sandbox root for cleanup: %w", err)
	}
	defer unix.Close(sandboxRootFD)
	if err := verifyTrustedDirectory(sandboxRootFD, true); err != nil {
		return fmt.Errorf("verify sandbox root for cleanup: %w", err)
	}
	if err := removeTreeBeneath(sandboxRootFD, sandboxID, generationName); err != nil {
		return fmt.Errorf("remove sandbox generation: %w", err)
	}
	return nil
}

func removeTreeBeneath(rootFD int, identityName, generationName string) error {
	identityFD, err := unix.Openat2(rootFD, identityName, &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: secureResolveFlags,
	})
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	generationFD, err := unix.Openat2(identityFD, generationName, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: secureResolveFlags | unix.RESOLVE_NO_XDEV,
	})
	if errors.Is(err, unix.ENOENT) {
		_ = unix.Close(identityFD)
		return nil
	}
	if err != nil {
		_ = unix.Close(identityFD)
		return err
	}
	if err := removeDirectoryContents(generationFD); err != nil {
		_ = unix.Close(generationFD)
		_ = unix.Close(identityFD)
		return err
	}
	_ = unix.Close(generationFD)
	if err := unix.Unlinkat(identityFD, generationName, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		_ = unix.Close(identityFD)
		return err
	}
	_ = unix.Close(identityFD)
	if err := unix.Unlinkat(rootFD, identityName, unix.AT_REMOVEDIR); err != nil &&
		!errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTEMPTY) && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

func removeDirectoryContents(directoryFD int) error {
	duplicateFD, err := duplicateCloseOnExec(directoryFD)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(duplicateFD), "sandbox-generation")
	if directory == nil {
		_ = unix.Close(duplicateFD)
		return errors.New("invalid generation descriptor")
	}
	entries, err := directory.ReadDir(-1)
	_ = directory.Close()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		var status unix.Stat_t
		if err := unix.Fstatat(directoryFD, name, &status, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return err
		}
		if status.Mode&unix.S_IFMT == unix.S_IFDIR {
			childFD, openErr := unix.Openat2(directoryFD, name, &unix.OpenHow{
				Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
				Resolve: secureResolveFlags | unix.RESOLVE_NO_XDEV,
			})
			if openErr != nil {
				return openErr
			}
			if removeErr := removeDirectoryContents(childFD); removeErr != nil {
				_ = unix.Close(childFD)
				return removeErr
			}
			_ = unix.Close(childFD)
			if err := unix.Unlinkat(directoryFD, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
				return err
			}
			continue
		}
		if err := unix.Unlinkat(directoryFD, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	return nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func duplicateCloseOnExec(fd int) (int, error) {
	return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
}
