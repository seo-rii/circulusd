package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/controlrpc"
	"github.com/hancomac/circulusd/internal/platformdaemon"
)

type recordingListener struct {
	mu      sync.Mutex
	address net.Addr
	closes  int
}

func (listener *recordingListener) Accept() (net.Conn, error) {
	return nil, net.ErrClosed
}

func (listener *recordingListener) Close() error {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	listener.closes++
	return nil
}

func (listener *recordingListener) Addr() net.Addr {
	return listener.address
}

func (listener *recordingListener) closeCount() int {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	return listener.closes
}

type staticAddress string

func (address staticAddress) Network() string { return "tcp" }
func (address staticAddress) String() string  { return string(address) }

type pointerAddress string

func (*pointerAddress) Network() string        { return "tcp" }
func (address *pointerAddress) String() string { return string(*address) }

type recordingRuntime struct {
	mu     *sync.Mutex
	events *[]string
	closes int
}

func (runtime *recordingRuntime) Close() {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.closes++
	*runtime.events = append(*runtime.events, "runtime.close")
}

type recordingServer struct {
	name      string
	mu        *sync.Mutex
	events    *[]string
	waitFor   <-chan struct{}
	started   chan struct{}
	closed    chan struct{}
	block     bool
	closeOnce sync.Once
	closes    int
}

func (server *recordingServer) Serve(context.Context) error {
	if server.waitFor != nil {
		<-server.waitFor
	}
	server.mu.Lock()
	*server.events = append(*server.events, server.name+".serve")
	server.mu.Unlock()
	close(server.started)
	if server.block {
		<-server.closed
	}
	return nil
}

func (server *recordingServer) Close() error {
	server.closeOnce.Do(func() {
		server.mu.Lock()
		server.closes++
		*server.events = append(*server.events, server.name+".close")
		server.mu.Unlock()
		close(server.closed)
	})
	return nil
}

func TestPlatformdDevDependencyGraphStaysDiagnosticOnly(t *testing.T) {
	command := exec.Command("go", "list", "-deps", ".")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, output)
	}
	allowedInternal := map[string]struct{}{
		"github.com/hancomac/circulusd/internal/controlrpc":     {},
		"github.com/hancomac/circulusd/internal/platformdaemon": {},
	}
	for _, dependency := range strings.Fields(string(output)) {
		if !strings.HasPrefix(dependency, "github.com/hancomac/circulusd/internal/") {
			continue
		}
		if _, allowed := allowedInternal[dependency]; !allowed {
			t.Fatalf("development diagnostic dependency graph contains %q", dependency)
		}
	}
}

func TestParseDevelopmentListenAddressAcceptsOnlyCanonicalLiteralLoopback(t *testing.T) {
	accepted := []struct {
		input       string
		wantNetwork string
	}{
		{input: "127.0.0.1:8081", wantNetwork: "tcp4"},
		{input: "127.0.0.2:8081", wantNetwork: "tcp4"},
		{input: "[::1]:8081", wantNetwork: "tcp6"},
	}
	for _, test := range accepted {
		t.Run("accept_"+test.input, func(t *testing.T) {
			got, err := parseDevelopmentListenAddress(test.input)
			if err != nil {
				t.Fatalf("parseDevelopmentListenAddress(%q) error = %v", test.input, err)
			}
			if got.network != test.wantNetwork || got.address.String() != test.input {
				t.Fatalf("address = %#v, want network %q address %q", got, test.wantNetwork, test.input)
			}
		})
	}

	rejected := []string{
		"localhost:8081",
		"0.0.0.0:8081",
		"[::]:8081",
		"192.0.2.1:8081",
		"[fe80::1]:8081",
		"[::ffff:127.0.0.1]:8081",
		"[::1%lo]:8081",
		"127.0.0.1",
		":8081",
		"127.0.0.1:0",
		"127.0.0.1:65536",
		"127.0.0.1:08081",
		"0:0:0:0:0:0:0:1:8081",
		"[0:0:0:0:0:0:0:1]:8081",
		"http://127.0.0.1:8081",
		"127.0.0.1:8081/path",
		" 127.0.0.1:8081",
		"127.0.0.1:8081 ",
		"127.0.0.1:8081\n",
		"127.0.0.1:\xff",
	}
	for _, input := range rejected {
		t.Run("reject_"+input, func(t *testing.T) {
			if _, err := parseDevelopmentListenAddress(input); err == nil {
				t.Fatalf("parseDevelopmentListenAddress(%q) succeeded", input)
			}
		})
	}
}

func TestDevelopmentStatusHandlerIsExplicitlyDiagnosticOnly(t *testing.T) {
	handler := developmentStatusHandler()
	wantBody := `{"apiVersion":"v1alpha","profile":"development-reference","mode":"diagnostic-only","productionEligible":false,"admissionEnabled":false,"state":{"availability":"unavailable","reason":"NOT_WIRED","implementation":"none","durability":"none"},"execution":{"availability":"unavailable","reason":"NOT_WIRED","provider":"none","isolationConformance":"NOT_RUN"}}`

	plainRequest := httptest.NewRequest(http.MethodGet, "http://localhost/v1/status", nil)
	plainResponse := httptest.NewRecorder()
	handler.ServeHTTP(plainResponse, plainRequest)
	if plainResponse.Code != http.StatusOK || plainResponse.Body.String() != wantBody {
		t.Fatalf("GET /v1/status = %d %q", plainResponse.Code, plainResponse.Body.String())
	}
	if got := plainResponse.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := plainResponse.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := plainResponse.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
	if got := plainResponse.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want absent", got)
	}
	for _, misleading := range []string{"reference-memory", `"fake"`, `"mock"`, "crashDurable"} {
		if strings.Contains(plainResponse.Body.String(), misleading) {
			t.Fatalf("status body contains unsupported claim %q", misleading)
		}
	}

	forwardedRequest := httptest.NewRequest(http.MethodGet, "http://example.invalid/v1/status", nil)
	forwardedRequest.Header.Set("Forwarded", "for=203.0.113.9;host=public.example")
	forwardedRequest.Header.Set("X-Forwarded-For", "203.0.113.9")
	forwardedRequest.Header.Set("X-Forwarded-Host", "public.example")
	forwardedRequest.Header.Set("X-Forwarded-Proto", "https")
	forwardedResponse := httptest.NewRecorder()
	handler.ServeHTTP(forwardedResponse, forwardedRequest)
	if forwardedResponse.Code != plainResponse.Code || forwardedResponse.Body.String() != plainResponse.Body.String() {
		t.Fatalf("forwarded headers changed response to %d %q", forwardedResponse.Code, forwardedResponse.Body.String())
	}

	postRequest := httptest.NewRequest(http.MethodPost, "http://localhost/v1/status", nil)
	postResponse := httptest.NewRecorder()
	handler.ServeHTTP(postResponse, postRequest)
	if postResponse.Code != http.StatusMethodNotAllowed || postResponse.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST /v1/status = %d Allow %q", postResponse.Code, postResponse.Header().Get("Allow"))
	}

	for _, path := range []string{
		"/readyz", "/v1/sessions", "/v1/turns", "/v1/effects", "/v1/%73tatus",
	} {
		request := httptest.NewRequest(http.MethodGet, "http://localhost"+path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404", path, response.Code)
		}
	}
}

func TestListenDevelopmentHTTPRechecksTheBoundLoopbackAddress(t *testing.T) {
	requested, err := parseDevelopmentListenAddress("127.0.0.1:8081")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name            string
		actual          string
		nilAddress      bool
		typedNilAddress bool
		listenError     error
		wantError       bool
	}{
		{name: "exact", actual: "127.0.0.1:8081"},
		{name: "wildcard", actual: "0.0.0.0:8081", wantError: true},
		{name: "different loopback", actual: "127.0.0.2:8081", wantError: true},
		{name: "different port", actual: "127.0.0.1:8082", wantError: true},
		{name: "malformed", actual: "not-an-address", wantError: true},
		{name: "nil address", nilAddress: true, wantError: true},
		{name: "typed nil address", typedNilAddress: true, wantError: true},
		{name: "partial listener error", actual: "127.0.0.1:8081", listenError: errors.New("bind failed"), wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var actual net.Addr = staticAddress(test.actual)
			if test.nilAddress {
				actual = nil
			}
			if test.typedNilAddress {
				var typedNil *pointerAddress
				actual = typedNil
			}
			listener := &recordingListener{address: actual}
			calls := 0
			server, err := listenDevelopmentHTTP(
				context.Background(),
				requested,
				func(_ context.Context, network string, address string) (net.Listener, error) {
					calls++
					if network != "tcp4" || address != "127.0.0.1:8081" {
						t.Fatalf("listen arguments = %q %q", network, address)
					}
					return listener, test.listenError
				},
			)
			if calls != 1 {
				t.Fatalf("listen calls = %d, want 1", calls)
			}
			if test.wantError {
				if err == nil || server != nil || listener.closeCount() != 1 {
					t.Fatalf("server/error/closes = %v/%v/%d", server, err, listener.closeCount())
				}
				return
			}
			if err != nil || server == nil {
				t.Fatalf("listenDevelopmentHTTP() = %v, %v", server, err)
			}
			if closeErr := server.Close(); closeErr != nil {
				t.Fatalf("Close() error = %v", closeErr)
			}
			if listener.closeCount() != 1 {
				t.Fatalf("listener closes = %d, want 1", listener.closeCount())
			}
		})
	}
}

func TestDevelopmentHTTPServerCloseIsConcurrentAndIdempotentBeforeServe(t *testing.T) {
	requested, err := parseDevelopmentListenAddress("127.0.0.1:8081")
	if err != nil {
		t.Fatal(err)
	}
	listener := &recordingListener{address: staticAddress("127.0.0.1:8081")}
	server, err := listenDevelopmentHTTP(
		context.Background(),
		requested,
		func(context.Context, string, string) (net.Listener, error) {
			return listener, nil
		},
	)
	if err != nil {
		t.Fatalf("listenDevelopmentHTTP() error = %v", err)
	}

	const closerCount = 128
	var closers sync.WaitGroup
	closeErrors := make(chan error, closerCount)
	for range closerCount {
		closers.Add(1)
		go func() {
			defer closers.Done()
			closeErrors <- server.Close()
		}()
	}
	closers.Wait()
	close(closeErrors)
	for closeError := range closeErrors {
		if closeError != nil {
			t.Errorf("Close() error = %v", closeError)
		}
	}
	if listener.closeCount() != 1 {
		t.Fatalf("listener closes = %d, want 1", listener.closeCount())
	}
	if err := server.Serve(context.Background()); err != nil {
		t.Fatalf("Serve() after Close error = %v", err)
	}
}

func TestDevelopmentHTTPServerBoundsWholeRequestAndResponseIO(t *testing.T) {
	requested, err := parseDevelopmentListenAddress("127.0.0.1:8081")
	if err != nil {
		t.Fatal(err)
	}
	listener := &recordingListener{address: staticAddress("127.0.0.1:8081")}
	server, err := listenDevelopmentHTTP(
		context.Background(),
		requested,
		func(context.Context, string, string) (net.Listener, error) {
			return listener, nil
		},
	)
	if err != nil {
		t.Fatalf("listenDevelopmentHTTP() error = %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	if server.httpServer.ReadTimeout != 5*time.Second {
		t.Fatalf("ReadTimeout = %s, want 5s", server.httpServer.ReadTimeout)
	}
	if server.httpServer.WriteTimeout != 5*time.Second {
		t.Fatalf("WriteTimeout = %s, want 5s", server.httpServer.WriteTimeout)
	}
	if !server.httpServer.DisableGeneralOptionsHandler {
		t.Fatal("general OPTIONS handler is enabled outside the diagnostic route")
	}
}

func TestPlatformdDevRejectsProductionInputsBeforeBootstrapOrListen(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
	}{
		{name: "production config", arguments: []string{"--config", "/etc/pi-platform/config.yaml"}},
		{name: "release manifest", arguments: []string{"--release-manifest", "/tmp/release.json"}},
		{name: "release trust roots", arguments: []string{"--release-trust-roots", "/tmp/roots.json"}},
		{name: "wildcard IPv4", arguments: []string{"--listen", "0.0.0.0:8081"}},
		{name: "wildcard IPv6", arguments: []string{"--listen", "[::]:8081"}},
		{name: "hostname", arguments: []string{"--listen", "localhost:8081"}},
		{name: "relative socket", arguments: []string{"--socket", "platformd-dev.sock"}},
		{name: "root socket", arguments: []string{"--socket", "/"}},
		{name: "invalid UID", arguments: []string{"--allow-uid", "01"}},
		{name: "positional argument", arguments: []string{"unexpected"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bootstrapCalls := 0
			applicationListenCalls := 0
			controlListenCalls := 0
			dependencies := defaultDevelopmentDependencies()
			dependencies.stderr = io.Discard
			dependencies.bootstrap = func(context.Context) (platformdaemon.Runtime, error) {
				bootstrapCalls++
				return nil, nil
			}
			dependencies.listenApplication = func(context.Context, developmentListenAddress) (platformdaemon.Server, error) {
				applicationListenCalls++
				return nil, nil
			}
			dependencies.listenControl = func(controlrpc.ServerConfig) (platformdaemon.Server, error) {
				controlListenCalls++
				return nil, nil
			}

			if exitCode := executeDevelopment(context.Background(), test.arguments, dependencies); exitCode != 2 {
				t.Fatalf("executeDevelopment() = %d, want 2", exitCode)
			}
			if bootstrapCalls != 0 || applicationListenCalls != 0 || controlListenCalls != 0 {
				t.Fatalf(
					"calls = bootstrap %d application %d control %d, want zero",
					bootstrapCalls, applicationListenCalls, controlListenCalls,
				)
			}
		})
	}
}

func TestPlatformdDevRejectsNilDependenciesBeforeBootstrap(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*developmentDependencies)
	}{
		{name: "stderr", mutate: func(dependencies *developmentDependencies) { dependencies.stderr = nil }},
		{name: "effective UID", mutate: func(dependencies *developmentDependencies) { dependencies.effectiveUID = nil }},
		{name: "capability provider", mutate: func(dependencies *developmentDependencies) { dependencies.capabilityProvider = nil }},
		{name: "bootstrap", mutate: func(dependencies *developmentDependencies) { dependencies.bootstrap = nil }},
		{name: "application listener", mutate: func(dependencies *developmentDependencies) { dependencies.listenApplication = nil }},
		{name: "control listener", mutate: func(dependencies *developmentDependencies) { dependencies.listenControl = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bootstrapCalls := 0
			dependencies := defaultDevelopmentDependencies()
			dependencies.stderr = io.Discard
			dependencies.bootstrap = func(context.Context) (platformdaemon.Runtime, error) {
				bootstrapCalls++
				return nil, nil
			}
			test.mutate(&dependencies)

			if exitCode := executeDevelopment(context.Background(), nil, dependencies); exitCode != 1 {
				t.Fatalf("executeDevelopment() = %d, want 1", exitCode)
			}
			if bootstrapCalls != 0 {
				t.Fatalf("bootstrap calls = %d, want zero", bootstrapCalls)
			}
		})
	}
}

func TestPlatformdDevFailureMatrixOwnsEveryConstructedResource(t *testing.T) {
	tests := []struct {
		name                  string
		bootstrapResult       string
		applicationResult     string
		controlResult         string
		cancelAfter           string
		wantExit              int
		wantEvents            string
		wantRuntimeCloses     int
		wantApplicationCloses int
		wantControlCloses     int
	}{
		{
			name: "partial bootstrap error", bootstrapResult: "partial-error", wantExit: 1,
			wantEvents: "bootstrap,runtime.close", wantRuntimeCloses: 1,
		},
		{
			name: "typed nil bootstrap", bootstrapResult: "typed-nil", wantExit: 1,
			wantEvents: "bootstrap",
		},
		{
			name: "canceled after bootstrap", cancelAfter: "bootstrap", wantExit: 0,
			wantEvents: "bootstrap,runtime.close", wantRuntimeCloses: 1,
		},
		{
			name: "partial application error", applicationResult: "partial-error", wantExit: 1,
			wantEvents:        "bootstrap,application.listen,application.close,runtime.close",
			wantRuntimeCloses: 1, wantApplicationCloses: 1,
		},
		{
			name: "typed nil application", applicationResult: "typed-nil", wantExit: 1,
			wantEvents: "bootstrap,application.listen,runtime.close", wantRuntimeCloses: 1,
		},
		{
			name: "canceled after application", cancelAfter: "application", wantExit: 0,
			wantEvents:        "bootstrap,application.listen,application.close,runtime.close",
			wantRuntimeCloses: 1, wantApplicationCloses: 1,
		},
		{
			name: "partial control error", controlResult: "partial-error", wantExit: 1,
			wantEvents:        "bootstrap,application.listen,control.listen,control.close,application.close,runtime.close",
			wantRuntimeCloses: 1, wantApplicationCloses: 1, wantControlCloses: 1,
		},
		{
			name: "typed nil control", controlResult: "typed-nil", wantExit: 1,
			wantEvents:        "bootstrap,application.listen,control.listen,application.close,runtime.close",
			wantRuntimeCloses: 1, wantApplicationCloses: 1,
		},
		{
			name: "canceled after control", cancelAfter: "control", wantExit: 0,
			wantEvents:        "bootstrap,application.listen,control.listen,application.close,control.close,runtime.close",
			wantRuntimeCloses: 1, wantApplicationCloses: 1, wantControlCloses: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			var mu sync.Mutex
			var events []string
			runtime := &recordingRuntime{mu: &mu, events: &events}
			application := &recordingServer{
				name: "application", mu: &mu, events: &events,
				started: make(chan struct{}), closed: make(chan struct{}), block: true,
			}
			control := &recordingServer{
				name: "control", mu: &mu, events: &events,
				started: make(chan struct{}), closed: make(chan struct{}), block: true,
			}
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			dependencies := defaultDevelopmentDependencies()
			dependencies.stderr = &stderr
			dependencies.bootstrap = func(context.Context) (platformdaemon.Runtime, error) {
				mu.Lock()
				events = append(events, "bootstrap")
				mu.Unlock()
				if test.cancelAfter == "bootstrap" {
					cancel()
				}
				switch test.bootstrapResult {
				case "partial-error":
					return runtime, errors.New("private bootstrap detail")
				case "typed-nil":
					var typedNil *recordingRuntime
					return typedNil, nil
				default:
					return runtime, nil
				}
			}
			dependencies.listenApplication = func(context.Context, developmentListenAddress) (platformdaemon.Server, error) {
				mu.Lock()
				events = append(events, "application.listen")
				mu.Unlock()
				if test.cancelAfter == "application" {
					cancel()
				}
				switch test.applicationResult {
				case "partial-error":
					return application, errors.New("private application detail")
				case "typed-nil":
					var typedNil *recordingServer
					return typedNil, nil
				default:
					return application, nil
				}
			}
			dependencies.listenControl = func(controlrpc.ServerConfig) (platformdaemon.Server, error) {
				mu.Lock()
				events = append(events, "control.listen")
				mu.Unlock()
				if test.cancelAfter == "control" {
					cancel()
				}
				switch test.controlResult {
				case "partial-error":
					return control, errors.New("private control detail")
				case "typed-nil":
					var typedNil *recordingServer
					return typedNil, nil
				default:
					return control, nil
				}
			}

			exitCode := executeDevelopment(ctx, []string{
				"--listen", "127.0.0.1:8081", "--socket", "/tmp/platformd-dev-fault.sock",
			}, dependencies)
			if exitCode != test.wantExit {
				t.Fatalf("executeDevelopment() = %d, want %d; stderr=%q", exitCode, test.wantExit, stderr.String())
			}
			if strings.Contains(stderr.String(), "private") {
				t.Fatalf("stderr exposed constructor detail: %q", stderr.String())
			}
			mu.Lock()
			gotEvents := strings.Join(events, ",")
			gotRuntimeCloses := runtime.closes
			gotApplicationCloses := application.closes
			gotControlCloses := control.closes
			mu.Unlock()
			if gotEvents != test.wantEvents {
				t.Fatalf("events = %q, want %q", gotEvents, test.wantEvents)
			}
			if gotRuntimeCloses != test.wantRuntimeCloses ||
				gotApplicationCloses != test.wantApplicationCloses ||
				gotControlCloses != test.wantControlCloses {
				t.Fatalf(
					"close counts = runtime %d application %d control %d, want %d/%d/%d",
					gotRuntimeCloses, gotApplicationCloses, gotControlCloses,
					test.wantRuntimeCloses, test.wantApplicationCloses, test.wantControlCloses,
				)
			}
		})
	}
}

func TestPlatformdDevComposesAndClosesItsSeparateGraphInOrder(t *testing.T) {
	var stderr bytes.Buffer
	var mu sync.Mutex
	var events []string
	applicationStarted := make(chan struct{})
	runtime := &recordingRuntime{mu: &mu, events: &events}
	application := &recordingServer{
		name: "application", mu: &mu, events: &events,
		started: applicationStarted, closed: make(chan struct{}), block: true,
	}
	control := &recordingServer{
		name: "control", mu: &mu, events: &events, waitFor: applicationStarted,
		started: make(chan struct{}), closed: make(chan struct{}),
	}
	dependencies := defaultDevelopmentDependencies()
	dependencies.stderr = &stderr
	dependencies.bootstrap = func(context.Context) (platformdaemon.Runtime, error) {
		mu.Lock()
		events = append(events, "bootstrap")
		mu.Unlock()
		return runtime, nil
	}
	dependencies.listenApplication = func(_ context.Context, address developmentListenAddress) (platformdaemon.Server, error) {
		if address.address.String() != "127.0.0.1:8081" {
			t.Fatalf("application address = %q", address.address.String())
		}
		mu.Lock()
		events = append(events, "application.listen")
		mu.Unlock()
		return application, nil
	}
	dependencies.listenControl = func(config controlrpc.ServerConfig) (platformdaemon.Server, error) {
		if config.SocketPath != "/tmp/platformd-dev-test.sock" || len(config.AllowedUIDs) != 1 || config.AllowedUIDs[0] != 1000 {
			t.Fatalf("control config = %#v", config)
		}
		mu.Lock()
		events = append(events, "control.listen")
		mu.Unlock()
		return control, nil
	}

	exitCode := executeDevelopment(context.Background(), []string{
		"--socket", "/tmp/platformd-dev-test.sock",
		"--listen", "127.0.0.1:8081",
		"--allow-uid", "1000",
	}, dependencies)
	if exitCode != 0 {
		t.Fatalf("executeDevelopment() = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	mu.Lock()
	gotEvents := strings.Join(events, ",")
	applicationCloses := application.closes
	controlCloses := control.closes
	runtimeCloses := runtime.closes
	mu.Unlock()
	wantEvents := "bootstrap,application.listen,control.listen,application.serve,control.serve,application.close,control.close,runtime.close"
	if gotEvents != wantEvents {
		t.Fatalf("events = %q, want %q", gotEvents, wantEvents)
	}
	if applicationCloses != 1 || controlCloses != 1 || runtimeCloses != 1 {
		t.Fatalf("close counts = application %d control %d runtime %d", applicationCloses, controlCloses, runtimeCloses)
	}
}

func TestPlatformdDevServesLoopbackStatusAndDevelopmentCapabilities(t *testing.T) {
	prebound, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind loopback listener: %v", err)
	}
	t.Cleanup(func() {
		if closeError := prebound.Close(); closeError != nil && !errors.Is(closeError, net.ErrClosed) {
			t.Errorf("close prebound listener: %v", closeError)
		}
	})
	listenAddress := prebound.Addr().String()
	socketDirectory, err := os.MkdirTemp("/tmp", "circulusd-pddev-")
	if err != nil {
		t.Fatalf("create short socket directory: %v", err)
	}
	t.Cleanup(func() {
		if removeError := os.RemoveAll(socketDirectory); removeError != nil {
			t.Errorf("remove socket directory: %v", removeError)
		}
	})
	socketPath := filepath.Join(socketDirectory, "control.sock")
	var stderr bytes.Buffer
	dependencies := defaultDevelopmentDependencies()
	dependencies.stderr = &stderr
	dependencies.listenApplication = func(
		ctx context.Context,
		address developmentListenAddress,
	) (platformdaemon.Server, error) {
		return listenDevelopmentHTTP(
			ctx,
			address,
			func(_ context.Context, network string, requestedAddress string) (net.Listener, error) {
				if network != "tcp4" || requestedAddress != listenAddress {
					return nil, fmt.Errorf(
						"listen arguments = %q %q, want tcp4 %q",
						network,
						requestedAddress,
						listenAddress,
					)
				}
				return prebound, nil
			},
		)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- executeDevelopment(ctx, []string{
			"--listen", listenAddress,
			"--socket", socketPath,
		}, dependencies)
	}()
	t.Cleanup(cancel)

	client := &http.Client{
		Transport: &http.Transport{Proxy: nil},
		Timeout:   time.Second,
	}
	t.Cleanup(client.CloseIdleConnections)
	deadline := time.Now().Add(3 * time.Second)
	var responseBody string
	for time.Now().Before(deadline) {
		response, requestError := client.Get("http://" + listenAddress + "/v1/status")
		if requestError == nil {
			body, readError := io.ReadAll(response.Body)
			closeError := response.Body.Close()
			if readError == nil && closeError == nil && response.StatusCode == http.StatusOK {
				responseBody = string(body)
				break
			}
		}
		select {
		case exitCode := <-done:
			t.Fatalf("platformd-dev exited early with %d; stderr=%q", exitCode, stderr.String())
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if responseBody != developmentStatusJSON {
		cancel()
		t.Fatalf("status body = %q", responseBody)
	}
	optionsConnection, err := net.DialTimeout("tcp4", listenAddress, time.Second)
	if err != nil {
		cancel()
		t.Fatalf("dial OPTIONS probe: %v", err)
	}
	if err := optionsConnection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		_ = optionsConnection.Close()
		cancel()
		t.Fatalf("set OPTIONS deadline: %v", err)
	}
	if _, err := io.WriteString(
		optionsConnection,
		"OPTIONS * HTTP/1.1\r\nHost: platformd-dev.invalid\r\nConnection: close\r\n\r\n",
	); err != nil {
		_ = optionsConnection.Close()
		cancel()
		t.Fatalf("write OPTIONS probe: %v", err)
	}
	optionsResponse, err := http.ReadResponse(
		bufio.NewReader(optionsConnection),
		&http.Request{Method: http.MethodOptions},
	)
	if err != nil {
		_ = optionsConnection.Close()
		cancel()
		t.Fatalf("read OPTIONS response: %v", err)
	}
	if closeError := optionsResponse.Body.Close(); closeError != nil {
		t.Errorf("close OPTIONS response: %v", closeError)
	}
	if closeError := optionsConnection.Close(); closeError != nil {
		t.Errorf("close OPTIONS connection: %v", closeError)
	}
	if optionsResponse.StatusCode != http.StatusNotFound {
		cancel()
		t.Fatalf("OPTIONS * status = %d, want 404", optionsResponse.StatusCode)
	}

	for time.Now().Before(deadline) {
		if _, statError := os.Lstat(socketPath); statError == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	controlClient, err := controlrpc.NewClient(controlrpc.ClientConfig{
		SocketPath: socketPath,
		Peer:       v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL,
	})
	if err != nil {
		cancel()
		t.Fatalf("NewClient() error = %v; stderr=%q", err, stderr.String())
	}
	requestContext, requestCancel := context.WithTimeout(context.Background(), time.Second)
	capabilities, err := controlClient.GetCapabilities(requestContext)
	requestCancel()
	if closeError := controlClient.Close(); closeError != nil {
		t.Errorf("control client close: %v", closeError)
	}
	if err != nil {
		cancel()
		t.Fatalf("GetCapabilities() error = %v", err)
	}
	wantCapabilityNames := []string{
		"agent.isolation",
		"api.development-status",
		"api.public",
		"control.protocol",
		"execution.environments",
		"mcp.gateway",
		"model.gateway",
		"state.celld",
	}
	if len(capabilities.GetCapabilities()) != len(wantCapabilityNames) {
		cancel()
		t.Fatalf("capability count = %d, want %d", len(capabilities.GetCapabilities()), len(wantCapabilityNames))
	}
	for index, capability := range capabilities.GetCapabilities() {
		if capability.GetName() != wantCapabilityNames[index] {
			cancel()
			t.Fatalf("capability[%d] = %q, want %q", index, capability.GetName(), wantCapabilityNames[index])
		}
		attributes := capability.GetAttributes()
		if attributes["runtimeProfile"] != "development-reference" ||
			attributes["productionEligible"] != "false" || attributes["admissionEnabled"] != "false" {
			cancel()
			t.Fatalf("capability %q attributes = %#v", capability.GetName(), attributes)
		}
		available := capability.GetName() == "control.protocol" || capability.GetName() == "api.development-status"
		if available {
			if capability.GetAvailability() != v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE ||
				capability.GetUnavailableReason() != nil {
				cancel()
				t.Fatalf("available capability = %v", capability)
			}
			continue
		}
		if capability.GetAvailability() != v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_UNAVAILABLE ||
			capability.GetUnavailableReason().GetReason() != "NOT_WIRED" {
			cancel()
			t.Fatalf("unwired capability = %v", capability)
		}
	}

	var concurrent sync.WaitGroup
	concurrentErrors := make(chan error, 64)
	for range 64 {
		concurrent.Add(1)
		go func() {
			defer concurrent.Done()
			response, requestError := client.Get("http://" + listenAddress + "/v1/status")
			if requestError != nil {
				concurrentErrors <- requestError
				return
			}
			body, readError := io.ReadAll(response.Body)
			closeError := response.Body.Close()
			if readError != nil || closeError != nil || response.StatusCode != http.StatusOK || string(body) != developmentStatusJSON {
				concurrentErrors <- fmt.Errorf("status response = %d %q, read=%v close=%v", response.StatusCode, body, readError, closeError)
			}
		}()
	}
	concurrent.Wait()
	close(concurrentErrors)
	for requestError := range concurrentErrors {
		cancel()
		t.Errorf("concurrent status request: %v", requestError)
	}

	cancel()
	select {
	case exitCode := <-done:
		if exitCode != 0 {
			t.Fatalf("executeDevelopment() = %d, want 0; stderr=%q", exitCode, stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("platformd-dev did not stop after cancellation")
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("control socket remains after shutdown: %v", err)
	}
}
