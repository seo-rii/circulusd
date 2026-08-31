//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/sandboxd"
	"github.com/hancomac/circulusd/internal/sandboxrpc"
)

const (
	defaultControlSocketPath = "/run/circulusd/control/control.sock"
	defaultCommandManifest   = "/etc/circulusd/commands.json"
	workspaceRoot            = "/workspace"
	launchNonceFD            = 3
	launchNonceBytes         = 32
	maximumAllowedClientUIDs = 64
	maximumSharedGeneration  = uint64(9_007_199_254_740_991)
	defaultReplayLimitBytes  = 1 << 20
	defaultReplayLimitEvents = 4096
	defaultSubscriberBuffer  = 64
	defaultProcessReadBytes  = 32 << 10
	supportedProtocolVersion = "1"
)

type daemonServer interface {
	Serve(context.Context) error
	Close() error
}

type daemonDependencies struct {
	stderr        io.Writer
	readNonce     func() ([]byte, error)
	loadCommands  func(string, uint32) (map[string]string, error)
	newSupervisor func(sandboxd.Config) (*sandboxd.Supervisor, error)
	listen        func(sandboxrpc.ServerConfig) (daemonServer, error)
	runner        sandboxd.Runner
}

type singleStringValue struct {
	name  string
	value string
	set   bool
}

func (value *singleStringValue) String() string {
	if value == nil {
		return ""
	}
	return value.value
}

func (value *singleStringValue) Set(raw string) error {
	if value.set {
		return fmt.Errorf("%s may only be supplied once", value.name)
	}
	value.value = raw
	value.set = true
	return nil
}

type uidValues struct {
	values []uint32
}

func (values *uidValues) String() string {
	if values == nil || len(values.values) == 0 {
		return ""
	}
	encoded := make([]string, len(values.values))
	for index, value := range values.values {
		encoded[index] = strconv.FormatUint(uint64(value), 10)
	}
	return strings.Join(encoded, ",")
}

func (values *uidValues) Set(raw string) error {
	parsed, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || strconv.FormatUint(parsed, 10) != raw {
		return fmt.Errorf("UID must be a canonical unsigned 32-bit integer")
	}
	if len(values.values) >= maximumAllowedClientUIDs {
		return fmt.Errorf("at most %d client UIDs may be allowed", maximumAllowedClientUIDs)
	}
	uid := uint32(parsed)
	for _, existing := range values.values {
		if existing == uid {
			return fmt.Errorf("client UID %d is repeated", uid)
		}
	}
	values.values = append(values.values, uid)
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(execute(ctx, os.Args[1:], defaultDependencies()))
}

func execute(ctx context.Context, arguments []string, dependencies daemonDependencies) int {
	flags := flag.NewFlagSet("sandboxd", flag.ContinueOnError)
	flagOutput := dependencies.stderr
	if flagOutput == nil {
		flagOutput = io.Discard
	}
	flags.SetOutput(flagOutput)
	socketPath := singleStringValue{name: "control socket", value: defaultControlSocketPath}
	manifestPath := singleStringValue{name: "command manifest", value: defaultCommandManifest}
	manifestOwnerUID := singleStringValue{name: "command manifest owner UID"}
	sandboxID := singleStringValue{name: "sandbox ID"}
	generationValue := singleStringValue{name: "generation"}
	backendValue := singleStringValue{name: "backend"}
	executionEnvironmentDigestValue := singleStringValue{name: "execution environment digest"}
	protocolVersion := singleStringValue{name: "protocol version"}
	var allowedClientUIDs uidValues
	flags.Var(&socketPath, "control-socket", "canonical absolute private control socket path")
	flags.Var(&manifestPath, "command-manifest", "canonical absolute sealed command manifest path")
	flags.Var(&manifestOwnerUID, "command-manifest-owner-uid", "expected owner UID of the sealed command manifest")
	flags.Var(&sandboxID, "sandbox-id", "launch-time sandbox identity")
	flags.Var(&generationValue, "generation", "positive launch-time sandbox generation")
	flags.Var(&backendValue, "backend", "launch-time execution backend: nsjail, docker, or firecracker")
	flags.Var(&executionEnvironmentDigestValue, "execution-environment-digest", "canonical launch-time SHA-256 environment digest")
	flags.Var(&protocolVersion, "protocol-version", "sandbox protocol major version")
	flags.Var(&allowedClientUIDs, "allow-client-uid", "peer UID allowed to use the private socket; may be repeated")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}
	parsedSandboxID, sandboxIDError := identity.Parse(identity.Sandbox, sandboxID.value)
	generation, generationError := strconv.ParseUint(generationValue.value, 10, 64)
	parsedManifestOwnerUID, manifestOwnerError := strconv.ParseUint(manifestOwnerUID.value, 10, 32)
	backend := v1.ExecutionBackend_EXECUTION_BACKEND_UNSPECIFIED
	switch backendValue.value {
	case "nsjail":
		backend = v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL
	case "docker":
		backend = v1.ExecutionBackend_EXECUTION_BACKEND_DOCKER
	case "firecracker":
		backend = v1.ExecutionBackend_EXECUTION_BACKEND_FIRECRACKER
	}
	executionEnvironmentDigest, executionEnvironmentDigestError := hex.DecodeString(
		strings.TrimPrefix(executionEnvironmentDigestValue.value, "sha256:"),
	)
	validExecutionEnvironmentDigest := executionEnvironmentDigestValue.set &&
		len(executionEnvironmentDigestValue.value) == len("sha256:")+sha256.Size*2 &&
		strings.HasPrefix(executionEnvironmentDigestValue.value, "sha256:") &&
		executionEnvironmentDigestValue.value == strings.ToLower(executionEnvironmentDigestValue.value) &&
		executionEnvironmentDigestError == nil && len(executionEnvironmentDigest) == sha256.Size
	if sandboxIDError != nil || generationError != nil || generation == 0 ||
		generation > maximumSharedGeneration || strconv.FormatUint(generation, 10) != generationValue.value ||
		backend == v1.ExecutionBackend_EXECUTION_BACKEND_UNSPECIFIED || !backendValue.set ||
		!validExecutionEnvironmentDigest ||
		manifestOwnerError != nil || parsedManifestOwnerUID == 0 || parsedManifestOwnerUID == uint64(^uint32(0)) ||
		strconv.FormatUint(parsedManifestOwnerUID, 10) != manifestOwnerUID.value || !manifestOwnerUID.set ||
		protocolVersion.value != supportedProtocolVersion || !protocolVersion.set ||
		len(allowedClientUIDs.values) == 0 || socketPath.value == "" || len(socketPath.value) > 107 ||
		!filepath.IsAbs(socketPath.value) || filepath.Clean(socketPath.value) != socketPath.value ||
		socketPath.value == string(filepath.Separator) || manifestPath.value == "" ||
		!filepath.IsAbs(manifestPath.value) || filepath.Clean(manifestPath.value) != manifestPath.value ||
		manifestPath.value == string(filepath.Separator) {
		if dependencies.stderr != nil {
			fmt.Fprintln(dependencies.stderr, "sandboxd: invalid launch authority or path")
		}
		return 2
	}
	if ctx == nil || dependencies.stderr == nil || dependencies.readNonce == nil ||
		dependencies.loadCommands == nil || dependencies.newSupervisor == nil ||
		dependencies.listen == nil || dependencies.runner == nil {
		return 1
	}
	if err := ctx.Err(); err != nil {
		fmt.Fprintln(dependencies.stderr, "sandboxd: launch context is unavailable")
		return 1
	}

	commands, err := dependencies.loadCommands(manifestPath.value, uint32(parsedManifestOwnerUID))
	if err != nil {
		fmt.Fprintf(dependencies.stderr, "sandboxd: load command manifest: %v\n", err)
		return 1
	}
	nonce, err := dependencies.readNonce()
	if err != nil || len(nonce) != launchNonceBytes {
		clearBytes(nonce)
		fmt.Fprintln(dependencies.stderr, "sandboxd: read launch capability")
		return 1
	}

	supervisor, err := dependencies.newSupervisor(sandboxd.Config{
		Authority: sandboxd.LaunchAuthority{
			SandboxID:  parsedSandboxID.String(),
			Generation: generation,
		},
		WorkspaceRoot:     workspaceRoot,
		Commands:          commands,
		Runner:            dependencies.runner,
		ReplayLimitBytes:  defaultReplayLimitBytes,
		ReplayLimitEvents: defaultReplayLimitEvents,
		SubscriberBuffer:  defaultSubscriberBuffer,
		ReadChunkBytes:    defaultProcessReadBytes,
	})
	if err != nil || supervisor == nil {
		clearBytes(nonce)
		fmt.Fprintln(dependencies.stderr, "sandboxd: initialize supervisor")
		return 1
	}
	defer supervisor.Fence(generation + 1) // generation is bounded below uint64 overflow.

	server, err := dependencies.listen(sandboxrpc.ServerConfig{
		SocketPath:                 socketPath.value,
		AllowedClientUIDs:          append([]uint32(nil), allowedClientUIDs.values...),
		SandboxID:                  []byte(parsedSandboxID.String()),
		SandboxGeneration:          generation,
		Backend:                    backend,
		ExecutionEnvironmentDigest: append([]byte(nil), executionEnvironmentDigest...),
		OneTimeNonce:               nonce,
		Supervisor:                 supervisor,
	})
	clearBytes(nonce)
	if err != nil || server == nil {
		fmt.Fprintf(dependencies.stderr, "sandboxd: listen on control socket: %v\n", err)
		return 1
	}
	serveError := server.Serve(ctx)
	closeError := server.Close()
	if serveError != nil {
		fmt.Fprintf(dependencies.stderr, "sandboxd: serve control socket: %v\n", serveError)
		return 1
	}
	if closeError != nil {
		fmt.Fprintln(dependencies.stderr, "sandboxd: close control socket")
		return 1
	}
	return 0
}

func defaultDependencies() daemonDependencies {
	return daemonDependencies{
		stderr: os.Stderr,
		readNonce: func() ([]byte, error) {
			return readLaunchNonceFD(launchNonceFD)
		},
		loadCommands:  sandboxd.LoadCommandManifest,
		newSupervisor: sandboxd.NewSupervisor,
		listen: func(config sandboxrpc.ServerConfig) (daemonServer, error) {
			return sandboxrpc.ListenServer(config)
		},
		runner: sandboxd.NewDevelopmentExecRunner(),
	}
}

func readLaunchNonceFD(fileDescriptor int) ([]byte, error) {
	if fileDescriptor < 0 {
		return nil, errors.New("sandboxd: invalid launch capability descriptor")
	}
	file := os.NewFile(uintptr(fileDescriptor), "sandboxd-launch-capability")
	if file == nil {
		return nil, errors.New("sandboxd: launch capability descriptor is unavailable")
	}
	defer file.Close()
	information, err := file.Stat()
	if err != nil || information.Mode().Type() != os.ModeNamedPipe {
		return nil, errors.New("sandboxd: launch capability must be supplied through a pipe")
	}
	nonce, err := io.ReadAll(io.LimitReader(file, launchNonceBytes+1))
	if err != nil || len(nonce) != launchNonceBytes {
		clearBytes(nonce)
		return nil, errors.New("sandboxd: launch capability has an invalid length")
	}
	return nonce, nil
}

func clearBytes(value []byte) {
	clear(value)
}
