// Package daemonshell runs diagnostic-only host daemon control sockets.
// It deliberately has no application listener, workerd launcher, or execution
// provider dependency, so these shells cannot accidentally admit workload.
package daemonshell

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/controlrpc"
	"github.com/hancomac/circulusd/internal/platformdaemon"
)

const (
	maximumAllowedUIDsPerRole  = 64
	maximumUnixSocketPathBytes = 107
)

// Server is the complete network surface owned by a diagnostic shell.
type Server interface {
	Serve(context.Context) error
	Close() error
}

type closeTrackingServer struct {
	Server
	mutex    sync.Mutex
	serveErr error
	closeErr error
}

func (server *closeTrackingServer) Serve(ctx context.Context) error {
	err := server.Server.Serve(ctx)
	server.mutex.Lock()
	server.serveErr = err
	server.mutex.Unlock()
	return err
}

func (server *closeTrackingServer) Close() error {
	err := server.Server.Close()
	server.mutex.Lock()
	server.closeErr = err
	server.mutex.Unlock()
	return err
}

func (server *closeTrackingServer) CloseError() error {
	server.mutex.Lock()
	defer server.mutex.Unlock()
	return server.closeErr
}

func (server *closeTrackingServer) ServeError() error {
	server.mutex.Lock()
	defer server.mutex.Unlock()
	return server.serveErr
}

// ListenerConfig keeps the shell listener boundary explicit: it contains only
// the shared control protocol and no workload-serving handler.
type ListenerConfig struct {
	Control controlrpc.ServerConfig
}

// Dependencies are the process-owned effects needed after CLI validation.
type Dependencies struct {
	Stderr io.Writer
	Listen func(context.Context, ListenerConfig) (Server, error)
}

// Profile is an immutable daemon identity and its honest diagnostic surface.
type Profile struct {
	name                    string
	serverPeer              v1.ProtocolPeer
	defaultSocketPath       string
	unavailableCapabilities []string
}

// AgentdProfile returns a control-only agentd profile. No workerd manager is
// constructed by this profile.
func AgentdProfile() Profile {
	return Profile{
		name:              "agentd",
		serverPeer:        v1.ProtocolPeer_PROTOCOL_PEER_AGENTD,
		defaultSocketPath: "/run/pi-platform/agentd.sock",
		unavailableCapabilities: []string{
			"agent.isolation",
			"agent.workerd",
		},
	}
}

// ExecutordProfile returns a control-only executord profile. No privileged
// provider, sandbox launcher, Docker socket, or KVM handle is constructed.
func ExecutordProfile() Profile {
	return Profile{
		name:              "executord",
		serverPeer:        v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD,
		defaultSocketPath: "/run/pi-platform/executord.sock",
		unavailableCapabilities: []string{
			"execution.docker",
			"execution.environments",
			"execution.firecracker",
			"execution.nsjail",
		},
	}
}

// ServerPeer is the role authenticated by the control handshake.
func (profile Profile) ServerPeer() v1.ProtocolPeer {
	return profile.serverPeer
}

// DefaultSocketPath is the profile's private control UDS path.
func (profile Profile) DefaultSocketPath() string {
	return profile.defaultSocketPath
}

// CapabilityProvider returns a fresh snapshot on every call.
func (profile Profile) CapabilityProvider() controlrpc.CapabilityProvider {
	snapshot := profile
	snapshot.unavailableCapabilities = append([]string(nil), profile.unavailableCapabilities...)
	return func(ctx context.Context) ([]*v1.CapabilityStatus, error) {
		if ctx == nil {
			return nil, errors.New("daemon shell: capability context is required")
		}
		if !validProfile(snapshot) {
			return nil, errors.New("daemon shell: capability profile is invalid")
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attributes := map[string]string{
			"admissionEnabled":   "false",
			"daemonRole":         snapshot.name,
			"productionEligible": "false",
			"runtimeProfile":     "diagnostic-only",
		}
		capabilities := []*v1.CapabilityStatus{
			{
				Name:         "control.protocol",
				Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
				Attributes:   maps.Clone(attributes),
			},
			{
				Name:         "daemon." + snapshot.name,
				Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
				Attributes:   maps.Clone(attributes),
			},
		}
		for _, name := range snapshot.unavailableCapabilities {
			capabilities = append(capabilities, &v1.CapabilityStatus{
				Name:         name,
				Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_UNAVAILABLE,
				UnavailableReason: &v1.PublicError{
					Code:    v1.ErrorCode_ERROR_CODE_UNAVAILABLE,
					Reason:  "NOT_WIRED",
					Message: name + " is not composed in the " + snapshot.name + " diagnostic shell",
				},
				Attributes: maps.Clone(attributes),
			})
		}
		return capabilities, nil
	}
}

// DefaultDependencies binds the shell to the hardened credentialed UDS
// transport. ServerPeer and the UID/peer pairs are populated by Execute.
func DefaultDependencies(stderr io.Writer) Dependencies {
	return Dependencies{
		Stderr: stderr,
		Listen: func(ctx context.Context, config ListenerConfig) (Server, error) {
			if ctx == nil {
				return nil, errors.New("daemon shell: listener context is required")
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return controlrpc.ListenServer(config.Control)
		},
	}
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
	if len(values.values) >= maximumAllowedUIDsPerRole {
		return fmt.Errorf("at most %d UIDs may be allowed per role", maximumAllowedUIDsPerRole)
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

// Execute validates the complete shell command before binding its sole UDS.
// Cancellation is graceful and always closes the listener before returning.
func Execute(ctx context.Context, arguments []string, profile Profile, dependencies Dependencies) int {
	stderrNil := dependencies.Stderr == nil
	if !stderrNil {
		reflected := reflect.ValueOf(dependencies.Stderr)
		switch reflected.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			stderrNil = reflected.IsNil()
		}
	}
	if ctx == nil || stderrNil || dependencies.Listen == nil || !validProfile(profile) {
		return 1
	}
	flags := flag.NewFlagSet(profile.name, flag.ContinueOnError)
	flags.SetOutput(dependencies.Stderr)
	socketPath := singleStringValue{name: "control socket", value: profile.defaultSocketPath}
	var platformdUIDs uidValues
	var platformctlUIDs uidValues
	flags.Var(&socketPath, "socket", "canonical absolute diagnostic control socket path")
	flags.Var(&platformdUIDs, "allow-platformd-uid", "peer UID allowed to authenticate as platformd; may be repeated")
	flags.Var(&platformctlUIDs, "allow-platformctl-uid", "peer UID allowed to authenticate as platformctl; may be repeated")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}
	if !validSocketPath(socketPath.value) {
		fmt.Fprintf(dependencies.Stderr, "%s: socket must be a canonical absolute path\n", profile.name)
		return 2
	}
	if len(platformdUIDs.values) == 0 && len(platformctlUIDs.values) == 0 {
		fmt.Fprintf(dependencies.Stderr, "%s: at least one peer UID authority is required\n", profile.name)
		return 2
	}
	if ctx.Err() != nil {
		return 0
	}

	authorities := make([]controlrpc.PeerUIDAuthority, 0, len(platformdUIDs.values)+len(platformctlUIDs.values))
	for _, uid := range platformdUIDs.values {
		authorities = append(authorities, controlrpc.PeerUIDAuthority{
			UID:  uid,
			Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD,
		})
	}
	for _, uid := range platformctlUIDs.values {
		authorities = append(authorities, controlrpc.PeerUIDAuthority{
			UID:  uid,
			Peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL,
		})
	}
	server, listenErr := dependencies.Listen(ctx, ListenerConfig{Control: controlrpc.ServerConfig{
		SocketPath:         socketPath.value,
		PeerUIDAuthorities: authorities,
		ServerPeer:         profile.serverPeer,
		CapabilityProvider: profile.CapabilityProvider(),
	}})
	serverNil := server == nil
	if !serverNil {
		reflected := reflect.ValueOf(server)
		switch reflected.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			serverNil = reflected.IsNil()
		}
	}
	if listenErr != nil || serverNil {
		var closeErr error
		if !serverNil {
			closeErr = server.Close()
		}
		if closeErr != nil {
			fmt.Fprintf(dependencies.Stderr, "%s: diagnostic control socket cleanup failed\n", profile.name)
			return 1
		}
		if ctx.Err() != nil {
			return 0
		}
		fmt.Fprintf(dependencies.Stderr, "%s: diagnostic control socket is unavailable\n", profile.name)
		return 1
	}
	if ctx.Err() != nil {
		if err := server.Close(); err != nil {
			fmt.Fprintf(dependencies.Stderr, "%s: diagnostic control socket cleanup failed\n", profile.name)
			return 1
		}
		return 0
	}
	trackedServer := &closeTrackingServer{Server: server}
	if err := platformdaemon.Serve(ctx, trackedServer, nil, nil); err != nil {
		if ctx.Err() != nil && trackedServer.ServeError() == nil && trackedServer.CloseError() == nil {
			return 0
		}
		fmt.Fprintf(dependencies.Stderr, "%s: diagnostic control service failed\n", profile.name)
		return 1
	}
	return 0
}

func validProfile(profile Profile) bool {
	validIdentity := profile.name == "agentd" && profile.serverPeer == v1.ProtocolPeer_PROTOCOL_PEER_AGENTD ||
		profile.name == "executord" && profile.serverPeer == v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD
	if !validIdentity || !validSocketPath(profile.defaultSocketPath) || len(profile.unavailableCapabilities) == 0 {
		return false
	}
	seen := map[string]struct{}{
		"control.protocol":       {},
		"daemon." + profile.name: {},
	}
	for _, name := range profile.unavailableCapabilities {
		if name == "" {
			return false
		}
		if _, duplicate := seen[name]; duplicate {
			return false
		}
		seen[name] = struct{}{}
	}
	return true
}

func validSocketPath(path string) bool {
	if !utf8.ValidString(path) || len(path) > maximumUnixSocketPathBytes || !filepath.IsAbs(path) ||
		filepath.Clean(path) != path || path == string(filepath.Separator) {
		return false
	}
	for _, character := range path {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
