//go:build linux

package controlrpc

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
)

// TestControlRPCConcurrentClientsShareServerUnderLoad drives many independent
// real clients — each performing its own credentialed handshake over the shared
// Unix socket — against one server at once. It is an end-to-end integration and
// concurrency test: it exercises the real accept loop, per-connection session
// issuance, the capability provider, and the handler's atomic request sequence
// under contention. The load-bearing invariant is that the server assigns a
// distinct, non-zero request sequence to every one of the concurrent calls, so
// no two responses can be confused for one another.
func TestControlRPCConcurrentClientsShareServerUnderLoad(t *testing.T) {
	var providerCalls atomic.Int64
	server := startTestServer(t, ServerConfig{
		SocketPath:   testSocketPath(t),
		AllowedUIDs:  []uint32{uint32(os.Getuid())},
		AllowedPeers: []v1.ProtocolPeer{v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL},
		CapabilityProvider: func(ctx context.Context) ([]*v1.CapabilityStatus, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			providerCalls.Add(1)
			return []*v1.CapabilityStatus{{
				Name:         "control.protocol",
				Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
			}}, nil
		},
	})

	const clients, callsPerClient = 16, 12
	total := clients * callsPerClient

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var (
		waitGroup sync.WaitGroup
		mu        sync.Mutex
		sequences = make(map[uint64]int, total)
		firstErr  error
	)
	recordError := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}

	for clientIndex := 0; clientIndex < clients; clientIndex++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			client, err := NewClient(ClientConfig{
				SocketPath: server.SocketPath(),
				Peer:       v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL,
			})
			if err != nil {
				recordError(fmt.Errorf("NewClient: %w", err))
				return
			}
			defer func() { _ = client.Close() }()
			for call := 0; call < callsPerClient; call++ {
				response, err := client.GetCapabilities(ctx)
				if err != nil {
					recordError(fmt.Errorf("GetCapabilities: %w", err))
					return
				}
				capabilities := response.GetCapabilities()
				if len(capabilities) != 1 || capabilities[0].GetName() != "control.protocol" {
					recordError(fmt.Errorf("unexpected capabilities: %v", capabilities))
					return
				}
				sequence := response.GetMeta().GetServerSequence()
				mu.Lock()
				sequences[sequence]++
				mu.Unlock()
			}
		}()
	}
	waitGroup.Wait()

	if firstErr != nil {
		t.Fatalf("concurrent client error: %v", firstErr)
	}
	if len(sequences) != total {
		t.Fatalf("server issued %d distinct request sequences across %d concurrent calls; duplicates or losses occurred", len(sequences), total)
	}
	for sequence, count := range sequences {
		if sequence == 0 {
			t.Fatal("server issued request sequence 0")
		}
		if count != 1 {
			t.Fatalf("server sequence %d observed %d times, want exactly once", sequence, count)
		}
	}
	if got := providerCalls.Load(); got < int64(total) {
		t.Fatalf("capability provider invoked %d times, want at least %d", got, total)
	}
}
