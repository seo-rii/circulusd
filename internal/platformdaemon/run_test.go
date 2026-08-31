package platformdaemon

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type testRuntime struct {
	mu     *sync.Mutex
	events *[]string
}

func (runtime *testRuntime) Close() {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	*runtime.events = append(*runtime.events, "runtime.close")
}

type testServer struct {
	name                       string
	mu                         *sync.Mutex
	events                     *[]string
	waitFor                    <-chan struct{}
	started                    chan struct{}
	closed                     chan struct{}
	serveError                 error
	serveContext               context.Context
	contextCanceledBeforeClose bool
	closeOnce                  sync.Once
}

func (server *testServer) Serve(ctx context.Context) error {
	server.mu.Lock()
	server.serveContext = ctx
	server.mu.Unlock()
	close(server.started)
	if server.waitFor != nil {
		<-server.waitFor
	}
	if server.serveError != nil {
		return server.serveError
	}
	<-server.closed
	return nil
}

func (server *testServer) Close() error {
	server.closeOnce.Do(func() {
		server.mu.Lock()
		server.contextCanceledBeforeClose = server.serveContext != nil && server.serveContext.Err() != nil
		*server.events = append(*server.events, server.name+".close")
		server.mu.Unlock()
		close(server.closed)
	})
	return nil
}

func (server *testServer) sawCanceledContextBeforeClose() bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.contextCanceledBeforeClose
}

func (server *testServer) serveContextCanceled() bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.serveContext != nil && server.serveContext.Err() != nil
}

func TestServeClosesApplicationControlAndRuntimeInOrder(t *testing.T) {
	var mu sync.Mutex
	var events []string
	controlStarted := make(chan struct{})
	control := &testServer{
		name: "control", mu: &mu, events: &events,
		started: controlStarted, closed: make(chan struct{}),
	}
	serveFailure := errors.New("application serve failed")
	application := &testServer{
		name: "application", mu: &mu, events: &events,
		waitFor: controlStarted, started: make(chan struct{}), closed: make(chan struct{}),
		serveError: serveFailure,
	}
	runtime := &testRuntime{mu: &mu, events: &events}

	err := Serve(context.Background(), control, application, runtime)
	if !errors.Is(err, serveFailure) {
		t.Fatalf("Serve() error = %v, want application failure", err)
	}
	mu.Lock()
	got := strings.Join(events, ",")
	mu.Unlock()
	if got != "application.close,control.close,runtime.close" {
		t.Fatalf("close events = %q", got)
	}
	if application.sawCanceledContextBeforeClose() || control.sawCanceledContextBeforeClose() {
		t.Fatal("listener context was canceled before ordered Close calls completed")
	}
	if !application.serveContextCanceled() || !control.serveContextCanceled() {
		t.Fatal("listener contexts remained active after Serve returned")
	}
}

func TestServeCancellationClosesBlockedApplicationControlAndRuntime(t *testing.T) {
	var mu sync.Mutex
	var events []string
	control := &testServer{
		name: "control", mu: &mu, events: &events,
		started: make(chan struct{}), closed: make(chan struct{}),
	}
	application := &testServer{
		name: "application", mu: &mu, events: &events,
		started: make(chan struct{}), closed: make(chan struct{}),
	}
	runtime := &testRuntime{mu: &mu, events: &events}
	t.Cleanup(func() {
		_ = application.Close()
		_ = control.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, control, application, runtime)
	}()
	waitForTestServer(t, control.started)
	waitForTestServer(t, application.started)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not close blocked listeners after cancellation")
	}
	mu.Lock()
	got := strings.Join(events, ",")
	mu.Unlock()
	if got != "application.close,control.close,runtime.close" {
		t.Fatalf("close events = %q", got)
	}
	if application.sawCanceledContextBeforeClose() || control.sawCanceledContextBeforeClose() {
		t.Fatal("listener context was canceled before ordered Close calls completed")
	}
	if !application.serveContextCanceled() || !control.serveContextCanceled() {
		t.Fatal("listener contexts remained active after Serve returned")
	}
}

func TestServeCancellationClosesBlockedDiagnosticControlAndRuntime(t *testing.T) {
	var mu sync.Mutex
	var events []string
	control := &testServer{
		name: "control", mu: &mu, events: &events,
		started: make(chan struct{}), closed: make(chan struct{}),
	}
	runtime := &testRuntime{mu: &mu, events: &events}
	t.Cleanup(func() { _ = control.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, control, nil, runtime)
	}()
	waitForTestServer(t, control.started)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not close blocked control listener after cancellation")
	}
	mu.Lock()
	got := strings.Join(events, ",")
	mu.Unlock()
	if got != "control.close,runtime.close" {
		t.Fatalf("close events = %q", got)
	}
	if control.sawCanceledContextBeforeClose() {
		t.Fatal("diagnostic listener context was canceled before its Close call completed")
	}
	if !control.serveContextCanceled() {
		t.Fatal("diagnostic listener context remained active after Serve returned")
	}
}

func waitForTestServer(t *testing.T, started <-chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("server did not enter Serve")
	}
}
