package main

import (
	"context"
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
	"github.com/hancomac/circulusd/internal/controlrpc"
)

const (
	defaultControlSocketPath = "/run/pi-platform/platformd.sock"
	maximumAllowedUIDs       = 64
)

type daemonDependencies struct {
	stderr             io.Writer
	effectiveUID       func() int
	capabilityProvider controlrpc.CapabilityProvider
	listen             func(controlrpc.ServerConfig) (*controlrpc.Server, error)
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
	var allowedUIDs uidValues
	flags.Var(&allowedUIDs, "allow-uid", "peer UID allowed to use the control socket; may be repeated")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}
	if !filepath.IsAbs(*socketPath) || filepath.Clean(*socketPath) != *socketPath || *socketPath == string(filepath.Separator) {
		if dependencies.stderr != nil {
			fmt.Fprintln(dependencies.stderr, "platformd: socket path must be a canonical absolute file")
		}
		return 2
	}
	if ctx == nil || dependencies.stderr == nil || dependencies.effectiveUID == nil ||
		dependencies.capabilityProvider == nil || dependencies.listen == nil {
		return 1
	}
	if len(allowedUIDs.values) == 0 {
		effectiveUID := dependencies.effectiveUID()
		if effectiveUID < 0 || uint64(effectiveUID) > uint64(^uint32(0)) {
			fmt.Fprintln(dependencies.stderr, "platformd: effective UID is invalid")
			return 1
		}
		allowedUIDs.values = append(allowedUIDs.values, uint32(effectiveUID))
	}

	server, err := dependencies.listen(controlrpc.ServerConfig{
		SocketPath:         *socketPath,
		AllowedUIDs:        append([]uint32(nil), allowedUIDs.values...),
		AllowedPeers:       []v1.ProtocolPeer{v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL},
		CapabilityProvider: dependencies.capabilityProvider,
	})
	if err != nil {
		fmt.Fprintf(dependencies.stderr, "platformd: listen on control socket: %v\n", err)
		return 1
	}
	defer server.Close()
	if err := server.Serve(ctx); err != nil {
		fmt.Fprintf(dependencies.stderr, "platformd: serve control socket: %v\n", err)
		return 1
	}
	return 0
}

func defaultDependencies() daemonDependencies {
	return daemonDependencies{
		stderr:       os.Stderr,
		effectiveUID: os.Geteuid,
		listen:       controlrpc.ListenServer,
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
				capability := &v1.CapabilityStatus{
					Name:         name,
					Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_UNAVAILABLE,
					UnavailableReason: &v1.PublicError{
						Code:    v1.ErrorCode_ERROR_CODE_UNAVAILABLE,
						Reason:  "NOT_WIRED",
						Message: name + " has no production adapter",
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
