package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/controlrpc"
	"github.com/hancomac/circulusd/internal/platformdaemon"
)

var errInvalidDevelopmentListenAddress = errors.New("platformd-dev: listen address must be a canonical literal loopback address with a nonzero port")

const (
	developmentStatusJSON           = `{"apiVersion":"v1alpha","profile":"development-reference","mode":"diagnostic-only","productionEligible":false,"admissionEnabled":false,"state":{"availability":"unavailable","reason":"NOT_WIRED","implementation":"none","durability":"none"},"execution":{"availability":"unavailable","reason":"NOT_WIRED","provider":"none","isolationConformance":"NOT_RUN"}}`
	defaultDevelopmentControlSocket = "/run/pi-platform/platformd-dev.sock"
	defaultDevelopmentHTTPAddress   = "127.0.0.1:8081"
	maximumDevelopmentAllowedUIDs   = 64
	developmentHTTPIOTimeout        = 5 * time.Second
)

type developmentListenAddress struct {
	network string
	address netip.AddrPort
}

type tcpListenerFactory func(context.Context, string, string) (net.Listener, error)

type onceListener struct {
	net.Listener
	closeOnce sync.Once
	closeErr  error
}

func (listener *onceListener) Close() error {
	listener.closeOnce.Do(func() {
		listener.closeErr = listener.Listener.Close()
	})
	return listener.closeErr
}

type developmentHTTPServer struct {
	listener   *onceListener
	httpServer *http.Server
	serveMu    sync.Mutex
	served     bool
	closed     atomic.Bool
}

type developmentDependencies struct {
	stderr             io.Writer
	effectiveUID       func() int
	capabilityProvider controlrpc.CapabilityProvider
	bootstrap          func(context.Context) (platformdaemon.Runtime, error)
	listenApplication  func(context.Context, developmentListenAddress) (platformdaemon.Server, error)
	listenControl      func(controlrpc.ServerConfig) (platformdaemon.Server, error)
}

type developmentUIDValues struct {
	values []uint32
}

func (values *developmentUIDValues) String() string {
	if values == nil || len(values.values) == 0 {
		return ""
	}
	encoded := make([]string, len(values.values))
	for index, value := range values.values {
		encoded[index] = strconv.FormatUint(uint64(value), 10)
	}
	return strings.Join(encoded, ",")
}

func (values *developmentUIDValues) Set(raw string) error {
	parsed, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || strconv.FormatUint(parsed, 10) != raw {
		return fmt.Errorf("UID must be a canonical unsigned 32-bit integer")
	}
	if len(values.values) >= maximumDevelopmentAllowedUIDs {
		return fmt.Errorf("at most %d UIDs may be allowed", maximumDevelopmentAllowedUIDs)
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

type developmentRuntime struct{}

func (*developmentRuntime) Close() {}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(executeDevelopment(ctx, os.Args[1:], defaultDevelopmentDependencies()))
}

func parseDevelopmentListenAddress(raw string) (developmentListenAddress, error) {
	if !utf8.ValidString(raw) {
		return developmentListenAddress{}, errInvalidDevelopmentListenAddress
	}
	for _, character := range raw {
		if unicode.IsControl(character) {
			return developmentListenAddress{}, errInvalidDevelopmentListenAddress
		}
	}
	address, err := netip.ParseAddrPort(raw)
	if err != nil || address.String() != raw || address.Port() == 0 ||
		!address.Addr().IsLoopback() || address.Addr().Is4In6() || address.Addr().Zone() != "" {
		return developmentListenAddress{}, errInvalidDevelopmentListenAddress
	}
	network := "tcp6"
	if address.Addr().Is4() {
		network = "tcp4"
	}
	return developmentListenAddress{network: network, address: address}, nil
}

func executeDevelopment(ctx context.Context, arguments []string, dependencies developmentDependencies) int {
	if ctx == nil || dependencies.stderr == nil || dependencies.effectiveUID == nil ||
		dependencies.capabilityProvider == nil || dependencies.bootstrap == nil ||
		dependencies.listenApplication == nil || dependencies.listenControl == nil {
		return 1
	}
	flags := flag.NewFlagSet("platformd-dev", flag.ContinueOnError)
	flags.SetOutput(dependencies.stderr)
	listenAddress := flags.String("listen", defaultDevelopmentHTTPAddress, "canonical literal loopback HTTP listen address")
	socketPath := flags.String("socket", defaultDevelopmentControlSocket, "canonical absolute diagnostic control socket path")
	var allowedUIDs developmentUIDValues
	flags.Var(&allowedUIDs, "allow-uid", "peer UID allowed to use the diagnostic control socket; may be repeated")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}
	parsedAddress, err := parseDevelopmentListenAddress(*listenAddress)
	if err != nil {
		fmt.Fprintln(dependencies.stderr, errInvalidDevelopmentListenAddress)
		return 2
	}
	validSocketPath := utf8.ValidString(*socketPath) && filepath.IsAbs(*socketPath) &&
		filepath.Clean(*socketPath) == *socketPath && *socketPath != string(filepath.Separator)
	for _, character := range *socketPath {
		if unicode.IsControl(character) {
			validSocketPath = false
		}
	}
	if !validSocketPath {
		fmt.Fprintln(dependencies.stderr, "platformd-dev: socket must be a canonical absolute path")
		return 2
	}
	if err := ctx.Err(); err != nil {
		return 0
	}
	if len(allowedUIDs.values) == 0 {
		effectiveUID := dependencies.effectiveUID()
		if effectiveUID < 0 || uint64(effectiveUID) > uint64(^uint32(0)) {
			fmt.Fprintln(dependencies.stderr, "platformd-dev: effective UID is invalid")
			return 1
		}
		allowedUIDs.values = append(allowedUIDs.values, uint32(effectiveUID))
	}

	runtime, err := dependencies.bootstrap(ctx)
	runtimeNil := interfaceIsNil(runtime)
	if err != nil || runtimeNil {
		if !runtimeNil {
			runtime.Close()
		}
		if ctx.Err() != nil {
			return 0
		}
		fmt.Fprintln(dependencies.stderr, "platformd-dev: development diagnostic graph is unavailable")
		return 1
	}
	if ctx.Err() != nil {
		runtime.Close()
		return 0
	}

	application, err := dependencies.listenApplication(ctx, parsedAddress)
	applicationNil := interfaceIsNil(application)
	if err != nil || applicationNil {
		if !applicationNil {
			_ = application.Close()
		}
		runtime.Close()
		if ctx.Err() != nil {
			return 0
		}
		fmt.Fprintln(dependencies.stderr, "platformd-dev: loopback diagnostic HTTP is unavailable")
		return 1
	}
	if ctx.Err() != nil {
		_ = application.Close()
		runtime.Close()
		return 0
	}

	control, err := dependencies.listenControl(controlrpc.ServerConfig{
		SocketPath:         *socketPath,
		AllowedUIDs:        append([]uint32(nil), allowedUIDs.values...),
		AllowedPeers:       []v1.ProtocolPeer{v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL},
		CapabilityProvider: dependencies.capabilityProvider,
	})
	controlNil := interfaceIsNil(control)
	if err != nil || controlNil {
		if !controlNil {
			_ = control.Close()
		}
		_ = application.Close()
		runtime.Close()
		if ctx.Err() != nil {
			return 0
		}
		fmt.Fprintln(dependencies.stderr, "platformd-dev: diagnostic control socket is unavailable")
		return 1
	}
	if err := platformdaemon.Serve(ctx, control, application, runtime); err != nil {
		if ctx.Err() != nil {
			return 0
		}
		fmt.Fprintf(dependencies.stderr, "platformd-dev: serve diagnostic listeners: %v\n", err)
		return 1
	}
	return 0
}

func developmentStatusHandler() http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL == nil || request.URL.EscapedPath() != "/v1/status" {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		if request.Method != http.MethodGet {
			response.Header().Set("Allow", http.MethodGet)
			response.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		response.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(response, developmentStatusJSON)
	})
}

func listenDevelopmentHTTP(
	ctx context.Context,
	requested developmentListenAddress,
	listen tcpListenerFactory,
) (*developmentHTTPServer, error) {
	if ctx == nil || listen == nil {
		return nil, fmt.Errorf("platformd-dev: invalid HTTP listener dependencies")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	validated, err := parseDevelopmentListenAddress(requested.address.String())
	if err != nil || validated != requested {
		return nil, errInvalidDevelopmentListenAddress
	}
	listener, err := listen(ctx, requested.network, requested.address.String())
	listenerNil := interfaceIsNil(listener)
	if err != nil || listenerNil {
		if !listenerNil {
			_ = listener.Close()
		}
		if err != nil {
			return nil, fmt.Errorf("platformd-dev: bind diagnostic HTTP listener: %w", err)
		}
		return nil, fmt.Errorf("platformd-dev: bind diagnostic HTTP listener: no listener")
	}
	if err := ctx.Err(); err != nil {
		_ = listener.Close()
		return nil, err
	}
	boundAddress := listener.Addr()
	if interfaceIsNil(boundAddress) {
		_ = listener.Close()
		return nil, fmt.Errorf("platformd-dev: bound listener has no address")
	}
	actual, actualError := parseDevelopmentListenAddress(boundAddress.String())
	if actualError != nil || actual != requested {
		_ = listener.Close()
		return nil, fmt.Errorf("platformd-dev: bound listener does not match requested loopback address")
	}
	once := &onceListener{Listener: listener}
	return &developmentHTTPServer{
		listener: once,
		httpServer: &http.Server{
			Handler:           developmentStatusHandler(),
			ReadTimeout:       developmentHTTPIOTimeout,
			ReadHeaderTimeout: developmentHTTPIOTimeout,
			WriteTimeout:      developmentHTTPIOTimeout,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    16 << 10,
		},
	}, nil
}

func interfaceIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func defaultDevelopmentDependencies() developmentDependencies {
	return developmentDependencies{
		stderr:       os.Stderr,
		effectiveUID: os.Geteuid,
		bootstrap: func(ctx context.Context) (platformdaemon.Runtime, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return &developmentRuntime{}, nil
		},
		listenApplication: func(ctx context.Context, address developmentListenAddress) (platformdaemon.Server, error) {
			var listenerConfig net.ListenConfig
			return listenDevelopmentHTTP(ctx, address, listenerConfig.Listen)
		},
		listenControl: func(config controlrpc.ServerConfig) (platformdaemon.Server, error) {
			return controlrpc.ListenServer(config)
		},
		capabilityProvider: developmentCapabilityProvider,
	}
}

func developmentCapabilityProvider(ctx context.Context) ([]*v1.CapabilityStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	names := []string{
		"agent.isolation",
		"api.development-status",
		"api.public",
		"control.protocol",
		"execution.environments",
		"mcp.gateway",
		"model.gateway",
		"state.celld",
	}
	capabilities := make([]*v1.CapabilityStatus, 0, len(names))
	for _, name := range names {
		attributes := map[string]string{
			"admissionEnabled":   "false",
			"productionEligible": "false",
			"runtimeProfile":     "development-reference",
		}
		capability := &v1.CapabilityStatus{
			Name:         name,
			Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_UNAVAILABLE,
			UnavailableReason: &v1.PublicError{
				Code:    v1.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Reason:  "NOT_WIRED",
				Message: name + " is not composed in the development diagnostic profile",
			},
			Attributes: attributes,
		}
		if name == "control.protocol" || name == "api.development-status" {
			capability.Availability = v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE
			capability.UnavailableReason = nil
		}
		if name == "state.celld" {
			attributes["durability"] = "none"
			attributes["implementation"] = "none"
		}
		if name == "execution.environments" || name == "agent.isolation" {
			attributes["isolationConformance"] = "NOT_RUN"
			attributes["provider"] = "none"
		}
		capabilities = append(capabilities, capability)
	}
	return capabilities, nil
}

func (server *developmentHTTPServer) Serve(ctx context.Context) error {
	if server == nil || ctx == nil {
		return fmt.Errorf("platformd-dev: invalid HTTP server")
	}
	server.serveMu.Lock()
	if server.served {
		server.serveMu.Unlock()
		return fmt.Errorf("platformd-dev: HTTP server can only be served once")
	}
	server.served = true
	server.serveMu.Unlock()
	if server.closed.Load() {
		return nil
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-stop:
		}
	}()
	err := server.httpServer.Serve(server.listener)
	close(stop)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (server *developmentHTTPServer) Close() error {
	if server == nil {
		return nil
	}
	server.closed.Store(true)
	httpError := server.httpServer.Close()
	listenerError := server.listener.Close()
	if errors.Is(httpError, net.ErrClosed) {
		httpError = nil
	}
	if errors.Is(listenerError, net.ErrClosed) {
		listenerError = nil
	}
	return errors.Join(httpError, listenerError)
}
