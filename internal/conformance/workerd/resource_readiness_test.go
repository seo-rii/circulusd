package workerd

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/agent"
)

func readinessProbeFixture(socketPath string) resourceFixtureRendering {
	return resourceFixtureRendering{
		SocketPath:     socketPath,
		ArtifactDigest: "sha256:" + strings.Repeat("a", 64),
		ConfigDigest:   "sha256:" + strings.Repeat("b", 64),
		WorkerdRelease: "1.20260825.1",
	}
}

// readinessHandler serves /ready like the fixture. mutate lets a test corrupt
// the response before it is written.
func readinessHandler(fixture resourceFixtureRendering, mutate func(*resourceReadinessResponse)) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", func(writer http.ResponseWriter, request *http.Request) {
		nonce := request.URL.Query().Get("nonce")
		payload := resourceReadinessResponse{
			SchemaVersion:  1,
			Nonce:          nonce,
			HostInstance:   strings.Repeat("c", 32),
			ArtifactDigest: fixture.ArtifactDigest,
			ConfigDigest:   fixture.ConfigDigest,
			WorkerdRelease: fixture.WorkerdRelease,
			LoaderABI:      1,
		}
		if mutate != nil {
			mutate(&payload)
		}
		writer.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(writer).Encode(payload)
	})
	return mux
}

func serveReadiness(t *testing.T, socketPath string, handler http.Handler) {
	t.Helper()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
}

func readinessSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rp")
	if err != nil {
		t.Fatalf("mkdir socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func TestResourceReadinessProbeAcceptsADigestBoundReadyResponse(t *testing.T) {
	socket := readinessSocketPath(t)
	fixture := readinessProbeFixture(socket)
	serveReadiness(t, socket, readinessHandler(fixture, nil))

	probe := newResourceReadinessProbe(fixture)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := probe.WaitReady(ctx, agent.WorkerdProcessInfo{}); err != nil {
		t.Fatalf("WaitReady() error = %v, want nil", err)
	}
}

func TestResourceReadinessProbeRejectsAServedButInvalidResponse(t *testing.T) {
	for name, mutate := range map[string]func(*resourceReadinessResponse){
		"wrong nonce":       func(r *resourceReadinessResponse) { r.Nonce = strings.Repeat("f", 32) },
		"wrong artifact":    func(r *resourceReadinessResponse) { r.ArtifactDigest = "sha256:" + strings.Repeat("9", 64) },
		"wrong config":      func(r *resourceReadinessResponse) { r.ConfigDigest = "sha256:" + strings.Repeat("9", 64) },
		"wrong release":     func(r *resourceReadinessResponse) { r.WorkerdRelease = "9.9.9" },
		"wrong schema":      func(r *resourceReadinessResponse) { r.SchemaVersion = 2 },
		"wrong abi":         func(r *resourceReadinessResponse) { r.LoaderABI = 2 },
		"bad host instance": func(r *resourceReadinessResponse) { r.HostInstance = "not-hex" },
	} {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			socket := readinessSocketPath(t)
			fixture := readinessProbeFixture(socket)
			serveReadiness(t, socket, readinessHandler(fixture, mutate))

			probe := newResourceReadinessProbe(fixture)
			// A served-but-invalid response is terminal: the probe must fail fast
			// rather than burn its whole deadline retrying.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			start := time.Now()
			if err := probe.WaitReady(ctx, agent.WorkerdProcessInfo{}); err == nil {
				t.Fatal("WaitReady() = nil, want rejection")
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("WaitReady retried a terminal failure for %v", elapsed)
			}
		})
	}
}

func TestResourceReadinessProbeRetriesTransientDialFailuresThenSucceeds(t *testing.T) {
	socket := readinessSocketPath(t)
	fixture := readinessProbeFixture(socket)

	var once sync.Once
	go func() {
		time.Sleep(80 * time.Millisecond)
		once.Do(func() { serveReadiness(t, socket, readinessHandler(fixture, nil)) })
	}()

	probe := newResourceReadinessProbe(fixture)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := probe.WaitReady(ctx, agent.WorkerdProcessInfo{}); err != nil {
		t.Fatalf("WaitReady() error = %v, want nil after transient dial failures", err)
	}
}

func TestResourceReadinessProbeTimesOutWhenNothingServes(t *testing.T) {
	socket := readinessSocketPath(t)
	fixture := readinessProbeFixture(socket)

	probe := newResourceReadinessProbe(fixture)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := probe.WaitReady(ctx, agent.WorkerdProcessInfo{}); err == nil {
		t.Fatal("WaitReady() = nil, want a deadline error")
	}
}
