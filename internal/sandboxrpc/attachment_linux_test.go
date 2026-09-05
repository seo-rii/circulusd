//go:build linux

package sandboxrpc

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	v1connect "github.com/hancomac/circulusd/api/generated/circulus/v1alpha/circulusv1alphaconnect"
	"github.com/hancomac/circulusd/internal/sandboxd"
)

func TestSandboxWireAttachmentReportsBackpressureAndReplays(t *testing.T) {
	t.Parallel()
	writeEntered := make(chan struct{})
	releaseWrite := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseWrite) }) }
	defer release()
	var gateOnce sync.Once
	runner := sandboxd.NewFakeRunner()
	server, client := startTestTransportWithRunner(t, runner, func(server *Server) {
		handler := server.httpServer.Handler
		server.httpServer.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == v1connect.SandboxProcessServiceAttachProcedure {
				writer = &pausedAttachmentWriter{
					ResponseWriter: writer, ctx: request.Context(),
					once: &gateOnce, entered: writeEntered, release: releaseWrite,
				}
			}
			handler.ServeHTTP(writer, request)
		})
	})
	defer server.Close()
	defer client.Close()
	spawned, err := client.Spawn(context.Background(), validSpawnRequest("backpressure-spawn", "backpressure-invocation"))
	if err != nil {
		t.Fatal(err)
	}
	process := nextFakeProcess(t, runner)
	defer process.Complete(sandboxd.RunResult{ExitCode: 0})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type attachResult struct {
		stream *ProcessEventStream
		err    error
	}
	attached := make(chan attachResult, 1)
	go func() {
		stream, err := client.Attach(ctx, &v1.AttachProcessRequest{
			Meta: idempotentMeta("backpressure-attach"), Process: spawned.GetProcess(),
		})
		attached <- attachResult{stream: stream, err: err}
	}()
	select {
	case <-writeEntered:
	case <-ctx.Done():
		t.Fatal("attachment did not reach the paused response writer")
	}
	// The server has consumed the started event and cannot drain any more
	// events until released. Thirty-two separate writes exceed its seventeen
	// buffered slots, deterministically producing supervisor backpressure.
	for range 32 {
		if err := process.EmitStdout([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	process.Complete(sandboxd.RunResult{ExitCode: 0})
	if _, err := client.Wait(ctx, &v1.WaitProcessRequest{
		Meta: idempotentMeta("backpressure-wait"), Process: spawned.GetProcess(),
	}); err != nil {
		t.Fatal(err)
	}
	release()
	var stream *ProcessEventStream
	select {
	case result := <-attached:
		if result.err != nil {
			t.Fatal(result.err)
		}
		stream = result.stream
	case <-ctx.Done():
		t.Fatal("attachment did not return after releasing its response writer")
	}
	defer stream.Close()
	var lastSequence uint64
	outputBytes := 0
	for stream.Receive() {
		event := stream.Msg()
		lastSequence = event.GetSequence()
		outputBytes += len(event.GetStdout().GetData())
		if event.GetExit() != nil {
			t.Fatal("backpressured attachment unexpectedly delivered the later exit")
		}
	}
	if err := stream.Err(); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("backpressured stream error = %v, want resource exhausted", err)
	}
	if lastSequence == 0 {
		t.Fatal("backpressured stream omitted its accepted events")
	}
	replayed, err := client.Attach(ctx, &v1.AttachProcessRequest{
		Meta: idempotentMeta("backpressure-replay"), Process: spawned.GetProcess(),
		AfterSequence: lastSequence,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer replayed.Close()
	exited := false
	for replayed.Receive() {
		event := replayed.Msg()
		outputBytes += len(event.GetStdout().GetData())
		exited = exited || event.GetExit() != nil
	}
	if err := replayed.Err(); err != nil || !exited || outputBytes != 32 {
		t.Fatalf("replay = (error %v, exited %t, output bytes %d), want successful complete output", err, exited, outputBytes)
	}
}

type pausedAttachmentWriter struct {
	http.ResponseWriter
	ctx     context.Context
	once    *sync.Once
	entered chan struct{}
	release <-chan struct{}
}

func (writer *pausedAttachmentWriter) Write(data []byte) (int, error) {
	writer.once.Do(func() {
		close(writer.entered)
		select {
		case <-writer.release:
		case <-writer.ctx.Done():
		}
	})
	return writer.ResponseWriter.Write(data)
}

func (writer *pausedAttachmentWriter) Flush() {
	_ = http.NewResponseController(writer.ResponseWriter).Flush()
}

func (writer *pausedAttachmentWriter) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}
