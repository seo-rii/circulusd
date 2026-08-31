package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/controlrpc"
	"github.com/hancomac/circulusd/internal/statebootstrap"
)

const (
	defaultControlSocketPath     = "/run/pi-platform/platformd.sock"
	defaultConfigurationPath     = "/etc/pi-platform/config.yaml"
	defaultReleaseManifestPath   = "/usr/lib/pi-platform/release-manifest.json"
	defaultReleaseTrustRootsPath = "/etc/pi-platform/release-trust-roots.json"
	maximumAllowedUIDs           = 64
)

type stateRuntime interface {
	Close()
}

type controlServer interface {
	Serve(context.Context) error
	Close() error
}

type daemonDependencies struct {
	stderr             io.Writer
	effectiveUID       func() int
	capabilityProvider controlrpc.CapabilityProvider
	bootstrap          func(context.Context, statebootstrap.Files) (stateRuntime, error)
	listen             func(controlrpc.ServerConfig) (controlServer, error)
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
	if len(values.values) >= maximumAllowedUIDs {
		return fmt.Errorf("at most %d UIDs may be allowed", maximumAllowedUIDs)
	}
	uid := uint32(parsed)
	for _, existing := range values.values {
		if existing == uid {
			return fmt.Errorf("UID %d is repeated", uid)
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
	flags := flag.NewFlagSet("platformd", flag.ContinueOnError)
	flags.SetOutput(dependencies.stderr)
	socketPath := flags.String("socket", defaultControlSocketPath, "canonical absolute control socket path")
	configurationPath := flags.String("config", defaultConfigurationPath, "canonical absolute platform configuration path")
	releaseManifestPath := flags.String("release-manifest", defaultReleaseManifestPath, "canonical absolute release manifest path")
	releaseTrustRootsPath := flags.String("release-trust-roots", defaultReleaseTrustRootsPath, "canonical absolute release trust-roots path")
	var allowedUIDs uidValues
	flags.Var(&allowedUIDs, "allow-uid", "peer UID allowed to use the control socket; may be repeated")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}
	paths := []string{*socketPath, *configurationPath, *releaseManifestPath, *releaseTrustRootsPath}
	pathsValid := true
	for _, path := range paths {
		if !utf8.ValidString(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
			path == string(filepath.Separator) {
			pathsValid = false
		}
		for _, character := range path {
			if unicode.IsControl(character) {
				pathsValid = false
			}
		}
	}
	if !pathsValid {
		if dependencies.stderr != nil {
			fmt.Fprintln(dependencies.stderr, "platformd: paths must be canonical absolute files")
		}
		return 2
	}
	if ctx == nil || dependencies.stderr == nil || dependencies.effectiveUID == nil ||
		dependencies.capabilityProvider == nil || dependencies.bootstrap == nil || dependencies.listen == nil {
		return 1
	}
	if ctx.Err() != nil {
		return 0
	}
	if len(allowedUIDs.values) == 0 {
		effectiveUID := dependencies.effectiveUID()
		if effectiveUID < 0 || uint64(effectiveUID) > uint64(^uint32(0)) {
			fmt.Fprintln(dependencies.stderr, "platformd: effective UID is invalid")
			return 1
		}
		allowedUIDs.values = append(allowedUIDs.values, uint32(effectiveUID))
	}

	runtime, err := dependencies.bootstrap(ctx, statebootstrap.Files{
		Configuration:     *configurationPath,
		ReleaseManifest:   *releaseManifestPath,
		ReleaseTrustRoots: *releaseTrustRootsPath,
	})
	runtimeIsNil := runtime == nil
	if !runtimeIsNil {
		value := reflect.ValueOf(runtime)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			runtimeIsNil = value.IsNil()
		}
	}
	runtimeReady := err == nil && !runtimeIsNil
	if !runtimeReady {
		if !runtimeIsNil {
			runtime.Close()
		}
		if ctx.Err() != nil {
			return 0
		}
		fmt.Fprintln(dependencies.stderr, "platformd: production state is unavailable")
	} else {
		defer runtime.Close()
	}
	if ctx.Err() != nil {
		return 0
	}

	server, err := dependencies.listen(controlrpc.ServerConfig{
		SocketPath:         *socketPath,
		AllowedUIDs:        append([]uint32(nil), allowedUIDs.values...),
		AllowedPeers:       []v1.ProtocolPeer{v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL},
		CapabilityProvider: dependencies.capabilityProvider,
	})
	serverIsNil := server == nil
	if !serverIsNil {
		value := reflect.ValueOf(server)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			serverIsNil = value.IsNil()
		}
	}
	if err != nil || serverIsNil {
		if !serverIsNil {
			_ = server.Close()
		}
		if err != nil {
			fmt.Fprintf(dependencies.stderr, "platformd: listen on control socket: %v\n", err)
		} else {
			fmt.Fprintln(dependencies.stderr, "platformd: listen returned no control server")
		}
		return 1
	}
	defer server.Close()
	if err := server.Serve(ctx); err != nil {
		if ctx.Err() != nil {
			return 0
		}
		fmt.Fprintf(dependencies.stderr, "platformd: serve control socket: %v\n", err)
		return 1
	}
	return 0
}

func defaultDependencies() daemonDependencies {
	return daemonDependencies{
		stderr:       os.Stderr,
		effectiveUID: os.Geteuid,
		bootstrap: func(ctx context.Context, files statebootstrap.Files) (stateRuntime, error) {
			return statebootstrap.Load(ctx, files)
		},
		listen: func(config controlrpc.ServerConfig) (controlServer, error) {
			return controlrpc.ListenServer(config)
		},
		capabilityProvider: func(ctx context.Context) ([]*v1.CapabilityStatus, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			names := []string{
				"agent.isolation",
				"api.public",
				"control.protocol",
				"execution.docker",
				"execution.environments",
				"execution.firecracker",
				"execution.nsjail",
				"extension.registry",
				"mcp.gateway",
				"model.gateway",
				"resource.profiles",
				"state.celld",
			}
			capabilities := make([]*v1.CapabilityStatus, 0, len(names))
			for _, name := range names {
				message := name + " has no production adapter"
				if name == "state.celld" {
					message = "state.celld native signer and restart conformance are not qualified"
				}
				capability := &v1.CapabilityStatus{
					Name:         name,
					Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_UNAVAILABLE,
					UnavailableReason: &v1.PublicError{
						Code:    v1.ErrorCode_ERROR_CODE_UNAVAILABLE,
						Reason:  "NOT_WIRED",
						Message: message,
					},
				}
				if name == "control.protocol" {
					capability.Availability = v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE
					capability.UnavailableReason = nil
				}
				capabilities = append(capabilities, capability)
			}
			return capabilities, nil
		},
	}
}
