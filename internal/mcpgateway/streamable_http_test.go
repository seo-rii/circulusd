package mcpgateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testMCPHTTPConfig(target string) StreamableHTTPConfig {
	return StreamableHTTPConfig{Targets: map[string]string{"registry/test": target}, ProtocolVersion: streamableHTTPProtocol,
		MaximumRequestBytes: 4096, MaximumResponseBytes: 8192, MaximumEvents: 8, MaximumConcurrentRequests: 2, RequestTimeout: time.Second}
}

func TestStreamableHTTPActualJSONAndSSESessionLifecycle(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.Header.Get("Accept") != "application/json, text/event-stream" || r.Header.Get("Authorization") != "" {
			t.Error("unexpected HTTP request boundary")
		}
		body, _ := io.ReadAll(r.Body)
		message, err := decodeMCPMessage(body)
		if err != nil {
			t.Error(err)
			return
		}
		if message.Method == "initialize" {
			if r.Header.Get("MCP-Session-Id") != "" {
				t.Error("initialization inherited a session")
			}
			w.Header().Set("MCP-Session-Id", "private-fixture-session")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":"init","result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}`)
			return
		}
		if r.Header.Get("MCP-Session-Id") != "private-fixture-session" || r.Header.Get("MCP-Protocol-Version") != streamableHTTPProtocol {
			t.Error("session/protocol were not retained")
		}
		if message.Method == "notifications/initialized" {
			w.WriteHeader(202)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, ": keepalive\n\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"call\",\"result\":{\"content\":[]}}\n\n")
	}))
	defer server.Close()
	config := testMCPHTTPConfig(server.URL)
	transport, err := NewStreamableHTTPTransport(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Targets["registry/test"] = "http://127.0.0.1:1/mutated"
	init, err := transport.Exchange(context.Background(), MCPWireRequest{TargetRef: "registry/test", MessageJSON: []byte(`{"jsonrpc":"2.0","id":"init","method":"initialize","params":{}}`)})
	if err != nil || init.ConnectionRef != "private-fixture-session" {
		t.Fatalf("initialization failed: %v", err)
	}
	_, err = transport.Exchange(context.Background(), MCPWireRequest{TargetRef: "registry/test", ConnectionRef: init.ConnectionRef, MessageJSON: []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)})
	if err != nil {
		t.Fatal(err)
	}
	result, err := transport.Exchange(context.Background(), MCPWireRequest{TargetRef: "registry/test", ConnectionRef: init.ConnectionRef, MessageJSON: []byte(`{"jsonrpc":"2.0","id":"call","method":"tools/call","params":{}}`)})
	if err != nil || !json.Valid(result.MessageJSON) || calls.Load() != 3 {
		t.Fatalf("SSE result/call count: %v %d", err, calls.Load())
	}
}

func TestStreamableHTTPRejectsRedirectProxyUnknownTargetAndDuplicateJSON(t *testing.T) {
	var leaked atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1); w.WriteHeader(200) }))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 307) }))
	defer origin.Close()
	t.Setenv("HTTP_PROXY", destination.URL)
	t.Setenv("HTTPS_PROXY", destination.URL)
	t.Setenv("NO_PROXY", "")
	transport, _ := NewStreamableHTTPTransport(testMCPHTTPConfig(origin.URL))
	request := MCPWireRequest{TargetRef: "registry/test", MessageJSON: []byte(`{"jsonrpc":"2.0","id":"one","method":"tools/call"}`)}
	if _, err := transport.Exchange(context.Background(), request); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("redirect: %v", err)
	}
	request.TargetRef = "caller/supplied"
	if _, err := transport.Exchange(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unknown target: %v", err)
	}
	request.TargetRef = "registry/test"
	request.MessageJSON = []byte(`{"jsonrpc":"2.0","id":"one","method":"tools/call","params":{"name":"a","name":"b"}}`)
	if _, err := transport.Exchange(context.Background(), request); !errors.Is(err, ErrProtocolMismatch) {
		t.Fatal("duplicate keys accepted")
	}
	if leaked.Load() != 0 {
		t.Fatal("redirect or ambient proxy received an MCP request")
	}
}

func TestStreamableHTTPRejectsUnboundedInvalidAndServerInitiatedMessages(t *testing.T) {
	for _, test := range []struct{ name, contentType, body string }{
		{"wrong-id", "application/json", `{"jsonrpc":"2.0","id":"wrong","result":{}}`},
		{"duplicate-response", "application/json", `{"jsonrpc":"2.0","id":"one","result":{"x":1,"x":2}}`},
		{"server-request", "text/event-stream", "data: {\"jsonrpc\":\"2.0\",\"id\":\"sampling\",\"method\":\"sampling/createMessage\"}\n\n"},
		{"oversized", "application/json", strings.Repeat(" ", 8193)},
		{"too-many-events", "text/event-stream", strings.Repeat("data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n", 9)},
		{"lost-response", "text/event-stream", "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			transport, _ := NewStreamableHTTPTransport(testMCPHTTPConfig(server.URL))
			_, err := transport.Exchange(context.Background(), MCPWireRequest{TargetRef: "registry/test", MessageJSON: []byte(`{"jsonrpc":"2.0","id":"one","method":"tools/call"}`)})
			if !errors.Is(err, ErrProtocolMismatch) {
				t.Fatalf("invalid response accepted: %v", err)
			}
		})
	}
}

func TestStreamableHTTPConnectionLossIsOnePOSTAndCancellationClosesStream(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	defer server.Close()
	transport, _ := NewStreamableHTTPTransport(testMCPHTTPConfig(server.URL))
	request := MCPWireRequest{TargetRef: "registry/test", MessageJSON: []byte(`{"jsonrpc":"2.0","id":"one","method":"tools/call"}`)}
	if _, err := transport.Exchange(context.Background(), request); err == nil || posts.Load() != 1 {
		t.Fatalf("lost response replayed or accepted: %v/%d", err, posts.Load())
	}
	closed := make(chan struct{})
	stream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
			t.Error("server did not observe connection close")
		}
		close(closed)
	}))
	defer stream.Close()
	transport, _ = NewStreamableHTTPTransport(testMCPHTTPConfig(stream.URL))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := transport.Exchange(ctx, request); err == nil {
		t.Fatal("unbounded stream accepted")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("cancelled stream leaked HTTP connection")
	}
}

func TestStreamableHTTPRejectsCredentialsInsecureDNSAndUnpinnedProtocol(t *testing.T) {
	for _, target := range []string{"http://localhost/mcp", "http://192.0.2.1/mcp", "https://user:secret@example.com/mcp", "https://example.com/mcp?token=secret", "https://example.com/mcp#fragment"} {
		if _, err := NewStreamableHTTPTransport(testMCPHTTPConfig(target)); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatal("invalid registry target accepted")
		}
	}
	config := testMCPHTTPConfig("http://127.0.0.1/mcp")
	config.ProtocolVersion = "2026-07-28"
	if _, err := NewStreamableHTTPTransport(config); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("unimplemented protocol was accepted")
	}
}
