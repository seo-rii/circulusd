package mcpgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestNativeHTTPProviderAuditsDeniedServerRequestsBeforeReply(t *testing.T) {
	for _, phase := range []string{"initialize", "tools/call"} {
		t.Run(phase, func(t *testing.T) {
			var replies atomic.Int32
			var inspectAudit func()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				rpc, err := decodeMCPMessage(body)
				if err != nil {
					t.Error(err)
					return
				}
				if rpc.Method == "" {
					var denial struct {
						Code int `json:"code"`
					}
					if string(rpc.ID) != "44" || json.Unmarshal(rpc.Error, &denial) != nil || denial.Code != jsonRPCMethodNotFound {
						t.Errorf("invalid denial response: %s", body)
					}
					if r.Header.Get("MCP-Session-Id") != "audit-session" {
						t.Error("denial lost the initializing session")
					}
					inspectAudit()
					replies.Add(1)
					w.WriteHeader(http.StatusAccepted)
					return
				}
				if rpc.Method == "notifications/initialized" {
					w.WriteHeader(http.StatusAccepted)
					return
				}
				result := `{"content":[]}`
				if rpc.Method == "initialize" {
					w.Header().Set("MCP-Session-Id", "audit-session")
					result = `{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}`
				}
				if rpc.Method == phase {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":44,\"method\":\"sampling/createMessage\",\"params\":{\"private\":\"do not audit params\"}}\n\n")
					fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%s}\n\n", rpc.ID, result)
				} else {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, rpc.ID, result)
				}
			}))
			defer server.Close()
			fixture := newNativeHTTPFixture(t, server.URL)
			provider := fixture.factory.providers[fixture.effect.ProviderID].(*nativeHTTPProvider)
			provider.transport.slots = make(chan struct{}, 1)
			inspectAudit = func() {
				fixture.source.mu.Lock()
				encoded := bytes.Clone(fixture.source.state)
				fixture.source.mu.Unlock()
				state, err := decodeNativeState(encoded, fixture.factory.repository.objectID, 128, 1<<20)
				if err != nil {
					t.Error(err)
					return
				}
				if len(state.DeliveredAudits) != 1 || len(state.Repository.pendingAudits) != 0 {
					t.Errorf("reply preceded durable audit: delivered=%d pending=%d", len(state.DeliveredAudits), len(state.Repository.pendingAudits))
				}
				for _, event := range state.DeliveredAudits {
					if event.TenantID != fixture.effect.Scope.TenantID || event.InvocationID != fixture.effect.Scope.InvocationID || event.Method != "sampling/createMessage" || event.Decision != "denied" {
						t.Error("audit lost its invocation or denial binding")
					}
				}
			}
			_, command, _ := prepareNativeHTTPCommand(t, fixture)
			started, err := provider.Start(context.Background(), command)
			if err != nil || started.Call == nil {
				t.Fatalf("start after denial: %v", err)
			}
			defer started.Call.Close(context.Background())
			if replies.Load() != 1 {
				t.Fatalf("denial responses = %d, want 1", replies.Load())
			}
		})
	}
}

func TestNativeHTTPProviderDoesNotReplyWhenDenialAuditCannotCommit(t *testing.T) {
	var fixture nativeFactoryFixture
	var replies atomic.Int32
	server := nativeHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rpc, err := decodeMCPMessage(body)
		if err != nil {
			t.Error(err)
			return
		}
		if rpc.Method == "" {
			replies.Add(1)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		fixture.source.mu.Lock()
		fixture.source.failCommit = true
		fixture.source.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":\"denied\",\"method\":\"roots/list\",\"params\":{}}\n\n")
		fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[]}}\n\n", rpc.ID)
	})
	fixture = newNativeHTTPFixture(t, server.URL)
	_, command, _ := prepareNativeHTTPCommand(t, fixture)
	_, err := fixture.factory.providers[fixture.effect.ProviderID].Start(context.Background(), command)
	if !errors.Is(err, ErrProviderUnavailable) || replies.Load() != 0 {
		t.Fatalf("failed audit: start error=%v, replies=%d", err, replies.Load())
	}
	fixture.source.mu.Lock()
	fixture.source.failCommit = false
	fixture.source.mu.Unlock()
	counts, err := nativeStateOperation(context.Background(), fixture.factory.repository, func(state *nativeRepositoryState) ([2]int, error) {
		return [2]int{len(state.Repository.pendingAudits), len(state.DeliveredAudits)}, nil
	})
	if err != nil || counts != [2]int{} {
		t.Fatalf("failed audit was retained: %v %v", counts, err)
	}
}
