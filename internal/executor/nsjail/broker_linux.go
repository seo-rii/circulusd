//go:build linux

package nsjail

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/sandboxrpc"
	"golang.org/x/sys/unix"
)

const defaultHandshakeSocketPollInterval = 5 * time.Millisecond

var (
	ErrInvalidHandshakeRegistration   = errors.New("invalid sandbox handshake registration")
	ErrDuplicateHandshakeRegistration = errors.New("duplicate sandbox handshake registration")
	ErrActiveHandshakeRegistration    = errors.New("another sandbox handshake generation is active")
	ErrStaleHandshakeGeneration       = errors.New("stale sandbox handshake generation")
	ErrHandshakeRegistrationNotFound  = errors.New("sandbox handshake registration not found")
	ErrHandshakeRegistrationRevoked   = errors.New("sandbox handshake registration revoked")
	ErrHandshakeSocketIdentity        = errors.New("sandbox handshake socket identity changed")
	ErrSandboxHandshakeFailed         = errors.New("sandboxd handshake failed")
)

type handshakeControlClient interface {
	ControlSession
	Ready(context.Context) error
}

type handshakeBrokerDependencies struct {
	newClient     func(sandboxrpc.ClientConfig, int) (handshakeControlClient, error)
	retryInterval time.Duration
}

// SandboxdHandshakeBroker binds a launcher's one-time nonce to one exact
// sandbox generation and control socket. One readiness attempt is shared by
// all callers; only Revoke cancels that lifecycle-owned attempt.
type SandboxdHandshakeBroker struct {
	mu sync.Mutex

	dependencies handshakeBrokerDependencies
	active       map[string]*sandboxHandshakeRegistration
	latest       map[string]uint64
}

type sandboxHandshakeRegistration struct {
	broker *SandboxdHandshakeBroker

	sandboxID         string
	generation        uint64
	socketPath        string
	serverUID         uint32
	directoryFD       int
	directoryIdentity handshakeDirectoryIdentity
	socketFD          int
	nonce             [handshakeNonceBytes]byte

	attemptStarted bool
	attemptDone    chan struct{}
	attemptCancel  context.CancelFunc
	attemptErr     error
	client         handshakeControlClient

	revoked       bool
	revokeStarted bool
	revokeDone    chan struct{}
	revokeErr     error
}

type handshakeDirectoryIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
	gid    uint32
	mode   uint32
}

type handshakeDirectoryOpenDependencies struct {
	beforeOpen func() error
}

// NewHandshakeBroker constructs the production broker backed by
// sandboxrpc.Client.
func NewHandshakeBroker() *SandboxdHandshakeBroker {
	return newHandshakeBrokerWithDependencies(handshakeBrokerDependencies{})
}

func newHandshakeBrokerWithDependencies(dependencies handshakeBrokerDependencies) *SandboxdHandshakeBroker {
	if dependencies.newClient == nil {
		dependencies.newClient = func(config sandboxrpc.ClientConfig, pinnedSocketFD int) (handshakeControlClient, error) {
			return sandboxrpc.NewClientFromPinnedSocketFD(config, pinnedSocketFD)
		}
	}
	if dependencies.retryInterval <= 0 {
		dependencies.retryInterval = defaultHandshakeSocketPollInterval
	}
	return &SandboxdHandshakeBroker{
		dependencies: dependencies,
		active:       make(map[string]*sandboxHandshakeRegistration),
		latest:       make(map[string]uint64),
	}
}

func (broker *SandboxdHandshakeBroker) RegisterHandshakeNonce(
	ctx context.Context,
	request HandshakeNonceRegistrationRequest,
) (HandshakeNonceRegistration, error) {
	if broker == nil || ctx == nil {
		return nil, fmt.Errorf("%w: nil broker or context", ErrInvalidHandshakeRegistration)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parsedSandboxID, err := identity.Parse(identity.Sandbox, request.SandboxID)
	if err != nil || parsedSandboxID.String() != request.SandboxID || request.Generation == 0 ||
		request.Generation > maximumSharedGeneration || len(request.OneTimeNonce) != handshakeNonceBytes ||
		request.SocketPath == "" || strings.IndexByte(request.SocketPath, 0) >= 0 ||
		!filepath.IsAbs(request.SocketPath) || filepath.Clean(request.SocketPath) != request.SocketPath ||
		len(request.SocketPath) > maximumUnixSocketPathBytes || filepath.Base(request.SocketPath) != sandboxControlSocketName {
		return nil, ErrInvalidHandshakeRegistration
	}

	broker.mu.Lock()
	if current := broker.active[request.SandboxID]; current != nil {
		switch {
		case current.generation == request.Generation:
			broker.mu.Unlock()
			return nil, ErrDuplicateHandshakeRegistration
		case request.Generation < current.generation:
			broker.mu.Unlock()
			return nil, ErrStaleHandshakeGeneration
		default:
			broker.mu.Unlock()
			return nil, ErrActiveHandshakeRegistration
		}
	}
	if latest, found := broker.latest[request.SandboxID]; found && request.Generation <= latest {
		broker.mu.Unlock()
		return nil, ErrStaleHandshakeGeneration
	}
	directoryFD, directoryIdentity, err := openHandshakeDirectory(filepath.Dir(request.SocketPath), request.ServerUID)
	if err != nil {
		broker.mu.Unlock()
		return nil, fmt.Errorf("%w: control directory: %v", ErrInvalidHandshakeRegistration, err)
	}
	var socketStatus unix.Stat_t
	err = unix.Fstatat(directoryFD, sandboxControlSocketName, &socketStatus, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		_ = unix.Close(directoryFD)
		broker.mu.Unlock()
		return nil, fmt.Errorf("%w: control socket already exists", ErrInvalidHandshakeRegistration)
	}
	if !errors.Is(err, unix.ENOENT) {
		_ = unix.Close(directoryFD)
		broker.mu.Unlock()
		return nil, fmt.Errorf("%w: inspect control socket: %v", ErrInvalidHandshakeRegistration, err)
	}
	if err := ctx.Err(); err != nil {
		_ = unix.Close(directoryFD)
		broker.mu.Unlock()
		return nil, err
	}

	registration := &sandboxHandshakeRegistration{
		broker:            broker,
		sandboxID:         request.SandboxID,
		generation:        request.Generation,
		socketPath:        request.SocketPath,
		serverUID:         request.ServerUID,
		directoryFD:       directoryFD,
		directoryIdentity: directoryIdentity,
		socketFD:          -1,
		revokeDone:        make(chan struct{}),
	}
	copy(registration.nonce[:], request.OneTimeNonce)
	broker.active[request.SandboxID] = registration
	broker.latest[request.SandboxID] = request.Generation
	broker.mu.Unlock()
	return registration, nil
}

func (broker *SandboxdHandshakeBroker) AwaitReady(
	ctx context.Context,
	sandboxID identity.ID,
	generation uint64,
) (ControlSession, error) {
	if broker == nil || ctx == nil || sandboxID.Kind() != identity.Sandbox || sandboxID.String() == "" ||
		generation == 0 || generation > maximumSharedGeneration {
		return nil, ErrInvalidHandshakeRegistration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	broker.mu.Lock()
	registration := broker.active[sandboxID.String()]
	if registration == nil || registration.generation != generation {
		latest, found := broker.latest[sandboxID.String()]
		broker.mu.Unlock()
		if found && generation <= latest {
			return nil, ErrStaleHandshakeGeneration
		}
		return nil, ErrHandshakeRegistrationNotFound
	}
	if registration.revoked {
		broker.mu.Unlock()
		return nil, ErrHandshakeRegistrationRevoked
	}
	if !registration.attemptStarted {
		attemptContext, cancelAttempt := context.WithCancel(context.Background())
		registration.attemptStarted = true
		registration.attemptDone = make(chan struct{})
		registration.attemptCancel = cancelAttempt
		go broker.runHandshake(attemptContext, registration)
	}
	attemptDone := registration.attemptDone
	broker.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-attemptDone:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		broker.mu.Lock()
		defer broker.mu.Unlock()
		if registration.revoked {
			return nil, ErrHandshakeRegistrationRevoked
		}
		if registration.attemptErr != nil {
			return nil, registration.attemptErr
		}
		if isNilInterface(registration.client) {
			return nil, ErrSandboxHandshakeFailed
		}
		return registration.client, nil
	}
}

func (registration *sandboxHandshakeRegistration) Revoke(ctx context.Context) error {
	if registration == nil || registration.broker == nil {
		return ErrInvalidHandshakeRegistration
	}
	done := registration.broker.beginRevoke(registration)
	if ctx == nil {
		return fmt.Errorf("%w: nil revoke context", ErrInvalidHandshakeRegistration)
	}
	select {
	case <-done:
		registration.broker.mu.Lock()
		err := registration.revokeErr
		registration.broker.mu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (broker *SandboxdHandshakeBroker) beginRevoke(registration *sandboxHandshakeRegistration) <-chan struct{} {
	broker.mu.Lock()
	if !registration.revokeStarted {
		registration.revokeStarted = true
		registration.revoked = true
		clear(registration.nonce[:])
		if broker.active[registration.sandboxID] == registration {
			delete(broker.active, registration.sandboxID)
		}
		if registration.attemptCancel != nil {
			registration.attemptCancel()
		}
		attemptDone := registration.attemptDone
		go broker.finishRevoke(registration, attemptDone)
	}
	done := registration.revokeDone
	broker.mu.Unlock()
	return done
}

func (broker *SandboxdHandshakeBroker) finishRevoke(
	registration *sandboxHandshakeRegistration,
	attemptDone <-chan struct{},
) {
	if attemptDone != nil {
		<-attemptDone
	}
	broker.mu.Lock()
	client := registration.client
	registration.client = nil
	directoryFD := registration.directoryFD
	registration.directoryFD = -1
	socketFD := registration.socketFD
	registration.socketFD = -1
	broker.mu.Unlock()

	var revokeErr error
	if !isNilInterface(client) {
		revokeErr = client.Close()
	}
	if directoryFD >= 0 {
		revokeErr = errors.Join(revokeErr, unix.Close(directoryFD))
	}
	if socketFD >= 0 {
		revokeErr = errors.Join(revokeErr, unix.Close(socketFD))
	}
	broker.mu.Lock()
	registration.revokeErr = revokeErr
	close(registration.revokeDone)
	broker.mu.Unlock()
}

func (broker *SandboxdHandshakeBroker) runHandshake(
	ctx context.Context,
	registration *sandboxHandshakeRegistration,
) {
	client, err := broker.connectRegisteredSandbox(ctx, registration)
	broker.mu.Lock()
	if registration.revoked || err != nil {
		broker.mu.Unlock()
		if !isNilInterface(client) {
			err = errors.Join(err, client.Close())
		}
		broker.mu.Lock()
		if registration.revoked {
			err = errors.Join(ErrHandshakeRegistrationRevoked, err)
		}
		registration.attemptErr = err
		close(registration.attemptDone)
		broker.mu.Unlock()
		return
	}
	registration.client = client
	registration.attemptErr = nil
	close(registration.attemptDone)
	broker.mu.Unlock()
}

func (broker *SandboxdHandshakeBroker) connectRegisteredSandbox(
	ctx context.Context,
	registration *sandboxHandshakeRegistration,
) (handshakeControlClient, error) {
	socketFD := -1
	var socketIdentity handshakeDirectoryIdentity
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		currentFD, currentIdentity, err := openHandshakeDirectory(filepath.Dir(registration.socketPath), registration.serverUID)
		if err != nil || currentIdentity != registration.directoryIdentity {
			if currentFD >= 0 {
				_ = unix.Close(currentFD)
			}
			return nil, fmt.Errorf("%w: control directory no longer matches registration", ErrHandshakeSocketIdentity)
		}

		candidateFD, statErr := unix.Openat(
			currentFD,
			sandboxControlSocketName,
			unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		closeDirectoryErr := unix.Close(currentFD)
		if closeDirectoryErr != nil {
			if candidateFD >= 0 {
				_ = unix.Close(candidateFD)
			}
			return nil, fmt.Errorf("%w: release inspected control directory: %v", ErrHandshakeSocketIdentity, closeDirectoryErr)
		}
		switch {
		case statErr == nil:
			var status unix.Stat_t
			if statErr = unix.Fstat(candidateFD, &status); statErr != nil {
				_ = unix.Close(candidateFD)
				return nil, fmt.Errorf("%w: inspect control endpoint: %v", ErrHandshakeSocketIdentity, statErr)
			}
			if status.Mode&unix.S_IFMT != unix.S_IFSOCK || status.Uid != registration.serverUID {
				_ = unix.Close(candidateFD)
				return nil, fmt.Errorf("%w: control endpoint is not the registered server socket", ErrHandshakeSocketIdentity)
			}
			if status.Mode&0o7777 == privateFileMode {
				socketFD = candidateFD
				socketIdentity = handshakeDirectoryIdentity{
					device: uint64(status.Dev),
					inode:  status.Ino,
					uid:    status.Uid,
					gid:    status.Gid,
					mode:   status.Mode,
				}
			} else {
				_ = unix.Close(candidateFD)
			}
		case errors.Is(statErr, unix.ENOENT):
		default:
			return nil, fmt.Errorf("%w: inspect control endpoint: %v", ErrHandshakeSocketIdentity, statErr)
		}
		if socketFD >= 0 {
			break
		}
		timer := time.NewTimer(broker.dependencies.retryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}

	broker.mu.Lock()
	if registration.revoked {
		broker.mu.Unlock()
		_ = unix.Close(socketFD)
		return nil, ErrHandshakeRegistrationRevoked
	}
	registration.socketFD = socketFD
	nonce := append([]byte(nil), registration.nonce[:]...)
	clear(registration.nonce[:])
	broker.mu.Unlock()
	client, err := broker.dependencies.newClient(sandboxrpc.ClientConfig{
		SocketPath:        registration.socketPath,
		ServerUID:         registration.serverUID,
		SandboxID:         []byte(registration.sandboxID),
		SandboxGeneration: registration.generation,
		OneTimeNonce:      nonce,
	}, socketFD)
	clear(nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize authenticated client: %v", ErrSandboxHandshakeFailed, err)
	}
	if isNilInterface(client) {
		return nil, fmt.Errorf("%w: client factory returned nil", ErrSandboxHandshakeFailed)
	}
	currentDirectoryFD, currentDirectoryIdentity, directoryErr := openHandshakeDirectory(
		filepath.Dir(registration.socketPath),
		registration.serverUID,
	)
	currentSocketFD := -1
	var socketErr error
	if directoryErr == nil && currentDirectoryIdentity == registration.directoryIdentity {
		currentSocketFD, socketErr = unix.Openat(
			currentDirectoryFD,
			sandboxControlSocketName,
			unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
	}
	if currentDirectoryFD >= 0 {
		directoryErr = errors.Join(directoryErr, unix.Close(currentDirectoryFD))
	}
	var currentSocketIdentity handshakeDirectoryIdentity
	if socketErr == nil {
		var status unix.Stat_t
		socketErr = unix.Fstat(currentSocketFD, &status)
		currentSocketIdentity = handshakeDirectoryIdentity{
			device: uint64(status.Dev),
			inode:  status.Ino,
			uid:    status.Uid,
			gid:    status.Gid,
			mode:   status.Mode,
		}
		socketErr = errors.Join(socketErr, unix.Close(currentSocketFD))
	}
	if directoryErr != nil || currentDirectoryIdentity != registration.directoryIdentity ||
		socketErr != nil || currentSocketIdentity != socketIdentity {
		return client, errors.Join(
			ErrSandboxHandshakeFailed,
			fmt.Errorf("%w: endpoint changed while constructing the client", ErrHandshakeSocketIdentity),
		)
	}
	if err := client.Ready(ctx); err != nil {
		return client, fmt.Errorf("%w: readiness: %v", ErrSandboxHandshakeFailed, err)
	}
	return client, nil
}

func openHandshakeDirectory(path string, expectedUID uint32) (int, handshakeDirectoryIdentity, error) {
	return openHandshakeDirectoryWithDependencies(path, expectedUID, handshakeDirectoryOpenDependencies{})
}

func openHandshakeDirectoryWithDependencies(
	path string,
	expectedUID uint32,
	dependencies handshakeDirectoryOpenDependencies,
) (int, handshakeDirectoryIdentity, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, handshakeDirectoryIdentity{}, errors.New("control directory path is not canonical and absolute")
	}
	if dependencies.beforeOpen != nil {
		if err := dependencies.beforeOpen(); err != nil {
			return -1, handshakeDirectoryIdentity{}, err
		}
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags: uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: uint64(
			unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
		),
	})
	if err != nil {
		return -1, handshakeDirectoryIdentity{}, err
	}
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil {
		_ = unix.Close(fd)
		return -1, handshakeDirectoryIdentity{}, err
	}
	if status.Mode&unix.S_IFMT != unix.S_IFDIR || status.Mode&0o7777 != privateDirectoryMode || status.Uid != expectedUID {
		_ = unix.Close(fd)
		return -1, handshakeDirectoryIdentity{}, errors.New("control directory mode or owner does not match launch authority")
	}
	return fd, handshakeDirectoryIdentity{
		device: uint64(status.Dev),
		inode:  status.Ino,
		uid:    status.Uid,
		gid:    status.Gid,
		mode:   status.Mode,
	}, nil
}

var _ HandshakeBroker = (*SandboxdHandshakeBroker)(nil)
var _ HandshakeNonceRegistration = (*sandboxHandshakeRegistration)(nil)
