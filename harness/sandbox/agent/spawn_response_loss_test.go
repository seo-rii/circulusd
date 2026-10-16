//go:build linux

package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/hancomac/circulusd/internal/sandboxd"
)

func TestLostSpawnResponseSuppressesNeverReplay(t *testing.T) {
	fixture := newHarnessTransport(t)
	root, err := os.MkdirTemp("", "spawn-loss-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	listener, err := net.Listen("unix", filepath.Join(root, "proxy.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(listener.Addr().String(), 0o600); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", fixture.inst.SocketPath)
	}}
	defer transport.CloseIdleConnections()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded := r.Clone(r.Context())
		forwarded.URL.Scheme = "http"
		forwarded.URL.Host = "sandbox.invalid"
		forwarded.RequestURI = ""
		response, err := transport.RoundTrip(forwarded)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		if strings.HasSuffix(r.URL.Path, "/Spawn") {
			// The real RPC server has accepted the request and started its runner.
			// Lose only the reply, leaving the caller unable to know that it ran.
			if response.StatusCode != http.StatusOK {
				t.Errorf("upstream Spawn status = %d", response.StatusCode)
			}
			if _, err := io.Copy(io.Discard, response.Body); err != nil {
				t.Errorf("reading Spawn response: %v", err)
			}
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("dropping Spawn response: %v", err)
				return
			}
			connection.Close()
			return
		}
		for key, values := range response.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		io.Copy(w, response.Body)
	})}
	defer server.Close()
	go server.Serve(listener)
	client, err := newSandboxClient(listener.Addr().String(), fixture.inst.ServerUID, fixture.inst.ID, fixture.inst.Generation, fixture.nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.handshake(ctx); err != nil {
		t.Fatal(err)
	}
	executor := newExecutor(client, fixture.inst, "nsjail", fixture.environment)
	_, err = executor.run(ctx, runRequest{
		SessionID: "session-loss", TurnID: "turn-loss", ToolCallID: "tool-loss",
		Code: "print('ran')", ReplayPolicy: "never", TimeoutMs: 1000,
	})
	select {
	case process := <-fixture.runner.Started():
		process.Complete(sandboxd.RunResult{})
	case <-ctx.Done():
		t.Fatal("Spawn did not reach the runner")
	}
	if fixture.runner.StartCount() != 1 {
		t.Fatalf("runner starts = %d, want 1", fixture.runner.StartCount())
	}
	if connect.CodeOf(err) != connect.CodeUnavailable || !shouldRelaunch(err) {
		t.Fatalf("expected a lost response requiring sandbox recovery: %v", err)
	}
	if !wasSpawned(err) {
		t.Fatalf("pool would replay a never-policy script after a lost Spawn response: %v", err)
	}
}
