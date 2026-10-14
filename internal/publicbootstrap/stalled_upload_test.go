package publicbootstrap

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A stalled HTTP/1.1 upload must not hold the handler after Close. The body's
// Close waits for the in-progress Read, so Close also has to expire the read
// deadline instead of waiting for the request timeout.
func TestCloseReleasesHandlerBlockedOnStalledUpload(t *testing.T) {
	t.Parallel()
	reading := make(chan struct{})
	handled := make(chan error, 1)
	graphCtx, cancel := context.WithCancel(context.Background())
	graph := &Graph{
		handler: http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
			if _, err := io.ReadFull(request.Body, make([]byte, 1)); err != nil {
				handled <- err
				return
			}
			close(reading)
			_, err := io.ReadAll(request.Body)
			handled <- err
		}),
		ctx: graphCtx, cancel: cancel, requestTimeout: time.Minute,
	}
	server := httptest.NewServer(graph)
	defer server.Close()
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// Closing the client first releases the handler if the test fails.
	defer conn.Close()
	if _, err := fmt.Fprint(conn, "POST /v1/sessions/stalled/turns HTTP/1.1\r\nHost: test\r\n"+
		"Content-Type: application/json\r\nContent-Length: 1024\r\n\r\n{"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reading:
	case err := <-handled:
		t.Fatalf("first body byte: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not start reading the body")
	}

	graph.Close()
	select {
	case err := <-handled:
		if err == nil {
			t.Fatal("stalled body read succeeded after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler still blocked on the stalled upload after Close")
	}
	// The server then answers and drops the connection instead of reading the
	// rest of the stalled body.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("connection after Close: %v", err)
	}
}
