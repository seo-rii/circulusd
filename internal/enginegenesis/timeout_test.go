package enginegenesis

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type stalledRequestBody struct {
	closed chan struct{}
	once   sync.Once
	reads  int
}

func (body *stalledRequestBody) Read([]byte) (int, error) {
	body.reads++
	<-body.closed
	return 0, context.DeadlineExceeded
}
func (body *stalledRequestBody) Close() error {
	body.once.Do(func() { close(body.closed) })
	return nil
}

func TestServerTimeoutBoundsStalledBodiesForBothNativeRoutes(t *testing.T) {
	for _, route := range []string{genesisPath, probePath} {
		t.Run(route, func(t *testing.T) {
			source, sealed := qualifiedSource(t)
			server, err := NewServer(ServerConfig{KeyID: "engine-genesis-1", RootKey: bytes.Repeat([]byte{7}, 32), Source: sealed, Timeout: 25 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			body := &stalledRequestBody{closed: make(chan struct{})}
			request := httptest.NewRequest(http.MethodPost, route, body)
			if route == genesisPath {
				request.Header.Set("Content-Type", genesisType)
				request.Header.Set(keyHeader, server.keyID)
				request.Header.Set(signatureHeader, strings.Repeat("0", 64))
			} else {
				request.Header.Set("Content-Type", probeType)
			}
			response := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { defer close(done); server.ServeHTTP(response, request) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				body.Close()
				t.Fatal("stalled body survived whole-request timeout")
			}
			if response.Code != 400 || source.calls.Load() != 0 {
				t.Fatalf("stalled request=%d, source calls=%d", response.Code, source.calls.Load())
			}
		})
	}
}

func TestMalformedAuthenticationRejectsBeforeReadingBody(t *testing.T) {
	_, sealed := qualifiedSource(t)
	server, err := NewServer(ServerConfig{KeyID: "engine-genesis-1", RootKey: bytes.Repeat([]byte{7}, 32), Source: sealed, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	body := &stalledRequestBody{closed: make(chan struct{})}
	request := httptest.NewRequest(http.MethodPost, genesisPath, body)
	request.Header.Set("Content-Type", genesisType)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != 401 || body.reads != 0 {
		t.Fatal("invalid authentication entered body read")
	}
}

func TestServerTimeoutCancelsActualGenesisSource(t *testing.T) {
	source, sealed := qualifiedSource(t)
	source.block = make(chan struct{})
	key := bytes.Repeat([]byte{9}, 32)
	handler, err := NewServer(ServerConfig{KeyID: "engine-genesis-1", RootKey: key, Source: sealed, Timeout: 25 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client, err := NewClient(ClientConfig{Endpoint: server.URL, KeyID: "engine-genesis-1", RootKey: key, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request, _ := actualPiFixture(t)
	started := time.Now()
	if checkpoint, err := client.RequestGenesis(context.Background(), request); err == nil || checkpoint != nil {
		t.Fatal("stalled native source returned checkpoint")
	}
	if time.Since(started) > 500*time.Millisecond || source.calls.Load() != 1 {
		t.Fatal("source call exceeded server-owned timeout")
	}
}

func TestServerRejectsUnboundedTimeout(t *testing.T) {
	_, sealed := qualifiedSource(t)
	for _, timeout := range []time.Duration{-time.Second, 31 * time.Second} {
		if _, err := NewServer(ServerConfig{KeyID: "engine-genesis-1", RootKey: bytes.Repeat([]byte{9}, 32), Source: sealed, Timeout: timeout}); err != ErrInvalidConfig {
			t.Fatalf("invalid timeout=%v", err)
		}
	}
}
