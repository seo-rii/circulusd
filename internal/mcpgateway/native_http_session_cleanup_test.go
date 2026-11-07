package mcpgateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeHTTPProviderCompletedCallsTerminateSessions(t *testing.T) {
	var created, deleted, calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			if r.Header.Get("MCP-Session-Id") == "" || r.Header.Get("MCP-Protocol-Version") != streamableHTTPProtocol {
				t.Error("termination omitted session/protocol")
			}
			deleted.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		body, _ := io.ReadAll(r.Body)
		rpc, err := decodeMCPMessage(body)
		if err != nil {
			t.Error(err)
			return
		}
		switch rpc.Method {
		case "initialize":
			n := created.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("MCP-Session-Id", fmt.Sprintf("session-%d", n))
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}`, rpc.ID)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/call":
			calls.Add(1)
			r.Body = io.NopCloser(bytes.NewReader(body))
			nativeHTTPResult(w, r)
		default:
			t.Errorf("unexpected method %s", rpc.Method)
		}
	}))
	defer server.Close()
	for range 3 {
		fixture := newNativeHTTPFixture(t, server.URL)
		_, command, _ := prepareNativeHTTPCommand(t, fixture)
		started, err := fixture.factory.providers[fixture.effect.ProviderID].Start(context.Background(), command)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := started.Call.Next(context.Background()); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := started.Call.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if calls.Load() != 3 || created.Load() != 3 || deleted.Load() != 3 {
		t.Fatalf("calls=%d sessions=%d deletions=%d", calls.Load(), created.Load(), deleted.Load())
	}
}

func TestNativeHTTPCallRetriesFailedSessionCleanupWithoutReplayingOutput(t *testing.T) {
	var deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.Header.Get("MCP-Session-Id") != "session-1" {
			t.Error("unexpected cleanup request")
		}
		if deletes.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	transport, err := NewStreamableHTTPTransport(testMCPHTTPConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	call := &nativeHTTPCall{output: []byte(`{"content":[]}`), closeSession: func(ctx context.Context) error {
		return transport.terminateSession(ctx, "registry/test", "session-1")
	}}
	if err := call.Close(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("first close: %v", err)
	}
	if _, err := call.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("closed output was replayable: %v", err)
	}
	if err := call.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := call.Close(context.Background()); err != nil || deletes.Load() != 2 {
		t.Fatalf("idempotent close: %v, deletes=%d", err, deletes.Load())
	}
}

func TestStreamableHTTPAllowsUnsupportedOrAlreadyDeletedSessions(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
			defer server.Close()
			transport, err := NewStreamableHTTPTransport(testMCPHTTPConfig(server.URL))
			if err != nil {
				t.Fatal(err)
			}
			if err := transport.terminateSession(context.Background(), "registry/test", "session-1"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStreamableHTTPBoundsSessionCleanupWaitingForCapacity(t *testing.T) {
	config := testMCPHTTPConfig("http://127.0.0.1:1")
	config.MaximumConcurrentRequests = 1
	config.RequestTimeout = 20 * time.Millisecond
	transport, err := NewStreamableHTTPTransport(config)
	if err != nil {
		t.Fatal(err)
	}
	transport.slots <- struct{}{}
	defer func() { <-transport.slots }()
	if err := transport.terminateSession(context.Background(), "registry/test", "session-1"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cleanup capacity wait: %v", err)
	}
}
