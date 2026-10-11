package mcpgateway

import (
	"context"
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

// Separate HTTP chunks exercise delimiters and the UTF-8 BOM split over reads.
func writeSSEFormatFixture(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/event-stream")
	for i := 0; i < len(body); i++ {
		fmt.Fprint(w, body[i:i+1])
		w.(http.Flusher).Flush()
	}
}

func TestStreamableHTTPStandardSSEFormats(t *testing.T) {
	for _, test := range []struct{ name, prefix, separator string }{
		{"lf", "", "\n"},
		{"crlf", "", "\r\n"},
		{"cr-only", "", "\r"},
		{"leading-bom", "\xef\xbb\xbf", "\n"},
		{"leading-bom-crlf", "\xef\xbb\xbf", "\r\n"},
		{"leading-bom-cr", "\xef\xbb\xbf", "\r"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeSSEFormatFixture(w, fmt.Sprintf("%sdata: {\"jsonrpc\":\"2.0\",\"id\":\"one\",\"result\":{\"content\":[]}}%s%s", test.prefix, test.separator, test.separator))
			}))
			defer server.Close()
			transport, err := NewStreamableHTTPTransport(testMCPHTTPConfig(server.URL))
			if err != nil {
				t.Fatal(err)
			}
			_, err = transport.Exchange(context.Background(), MCPWireRequest{TargetRef: "registry/test", MessageJSON: []byte(`{"jsonrpc":"2.0","id":"one","method":"tools/call"}`)})
			if err != nil {
				t.Fatalf("legal SSE format %s rejected: %v", test.name, err)
			}
		})
	}
}

func TestStreamableHTTPStandardSSEFormatsRetainNativeTerminal(t *testing.T) {
	for _, test := range []struct{ name, prefix, separator string }{
		{"lf", "", "\n"},
		{"crlf", "", "\r\n"},
		{"cr-only", "", "\r"},
		{"leading-bom", "\xef\xbb\xbf", "\n"},
		{"leading-bom-crlf", "\xef\xbb\xbf", "\r\n"},
		{"leading-bom-cr", "\xef\xbb\xbf", "\r"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := nativeHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, _ := io.ReadAll(r.Body)
				message, err := decodeMCPMessage(body)
				if err != nil {
					t.Error(err)
					return
				}
				writeSSEFormatFixture(w, fmt.Sprintf("%sdata: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"committed result\"}]}}%s%s", test.prefix, message.ID, test.separator, test.separator))
			})
			fixture := newNativeHTTPFixture(t, server.URL)
			_, command, _ := prepareNativeHTTPCommand(t, fixture)
			provider := fixture.factory.providers[fixture.effect.ProviderID]
			result, startErr := provider.Start(context.Background(), command)
			record, lookupErr := provider.Lookup(context.Background(), LedgerQuery{Scope: command.Scope, Server: command.Server, ToolName: command.ToolName, InvocationID: command.InvocationID, RequestDigest: command.RequestDigest, Negotiation: command.Negotiation, Start: command.Start})
			if startErr != nil || lookupErr != nil || result.Call == nil || record.Status != LedgerCommitted || calls.Load() != 1 {
				t.Fatalf("valid terminal was lost: format=%s startErr=%v lookupErr=%v ledger=%s externalCalls=%d", test.name, startErr, lookupErr, record.Status, calls.Load())
			}
		})
	}
}

func TestStreamableHTTPCRResponseDoesNotWaitForEOF(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		writeSSEFormatFixture(w, "data: {\"jsonrpc\":\"2.0\",\"id\":\"one\",\"result\":{\"content\":[]}}\r\r")
		// A terminal response must be delivered even if the peer keeps the stream
		// open. Waiting for EOF or an optional LF would time out this request.
		<-r.Context().Done()
	}))
	defer server.Close()
	transport, err := NewStreamableHTTPTransport(testMCPHTTPConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = transport.Exchange(ctx, MCPWireRequest{TargetRef: "registry/test", MessageJSON: []byte(`{"jsonrpc":"2.0","id":"one","method":"tools/call"}`)})
	if err != nil {
		t.Fatalf("complete CR event waited for another byte or EOF: %v", err)
	}
}

func TestStreamableHTTPStandardSSEFormatsPreserveBounds(t *testing.T) {
	for _, separator := range []string{"\n", "\r\n", "\r"} {
		for _, prefix := range []string{"", "\xef\xbb\xbf"} {
			for _, test := range []struct{ name, body string }{
				{"unterminated-event", "data: {\"jsonrpc\":\"2.0\",\"id\":\"one\",\"result\":{}}" + separator},
				{"oversized", "data: " + strings.Repeat("x", 8193) + separator + separator},
				{"too-many-events", strings.Repeat("data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}"+separator+separator, 9)},
			} {
				t.Run(fmt.Sprintf("%q/%q/%s", separator, prefix, test.name), func(t *testing.T) {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "text/event-stream")
						fmt.Fprint(w, prefix+test.body)
					}))
					defer server.Close()
					transport, err := NewStreamableHTTPTransport(testMCPHTTPConfig(server.URL))
					if err != nil {
						t.Fatal(err)
					}
					_, err = transport.Exchange(context.Background(), MCPWireRequest{TargetRef: "registry/test", MessageJSON: []byte(`{"jsonrpc":"2.0","id":"one","method":"tools/call"}`)})
					if !errors.Is(err, ErrProtocolMismatch) {
						t.Fatalf("invalid or unbounded SSE accepted: %v", err)
					}
				})
			}
		}
	}
}
