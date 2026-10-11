//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/sandboxrpc"
	"google.golang.org/protobuf/proto"
)

const (
	unaryRPCTimeout           = 35 * time.Second
	maximumAttachmentDuration = 5 * time.Minute
)

// sandboxClient supplies the harness's operation keys and caller deadlines.
// The shared client owns the pinned socket, peer credentials, launch nonce,
// protocol metadata, and validation of every response and process event.
type sandboxClient struct{ rpc *sandboxrpc.Client }

func newSandboxClient(socketPath string, serverUID uint32, sandboxID string, generation uint64, nonce []byte) (*sandboxClient, error) {
	client, err := sandboxrpc.NewClient(sandboxrpc.ClientConfig{SocketPath: socketPath, ServerUID: serverUID, SandboxID: []byte(sandboxID), SandboxGeneration: generation, OneTimeNonce: nonce})
	if err != nil {
		return nil, err
	}
	return &sandboxClient{rpc: client}, nil
}

func (client *sandboxClient) handshake(ctx context.Context) error { return client.rpc.Ready(ctx) }
func (client *sandboxClient) close() error {
	if client == nil {
		return nil
	}
	return client.rpc.Close()
}

// The library stamps bounded wire deadlines. The harness also bounds its own
// wait when the caller has no deadline, including a peer that stops responding.
func boundedRPC(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		return nil, func() {}
	}
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, unaryRPCTimeout)
}

func operationMeta() *v1.RpcRequestMeta {
	key := make([]byte, 24)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return &v1.RpcRequestMeta{IdempotencyKey: key}
}

func (client *sandboxClient) spawn(ctx context.Context, message *v1.SpawnProcessRequest) (*v1.ProcessHandle, error) {
	if message == nil {
		return nil, errors.New("spawn request is missing")
	}
	request := proto.Clone(message).(*v1.SpawnProcessRequest)
	request.Meta = operationMeta()
	ctx, cancel := boundedRPC(ctx)
	defer cancel()
	response, err := client.rpc.Spawn(ctx, request)
	if err != nil {
		return nil, err
	}
	return response.Process, nil
}

func (client *sandboxClient) writeStdin(ctx context.Context, handle *v1.ProcessHandle, sequence uint64, data []byte) error {
	ctx, cancel := boundedRPC(ctx)
	defer cancel()
	_, err := client.rpc.WriteStdin(ctx, &v1.WriteStdinRequest{Meta: operationMeta(), Process: handle, ChunkSequence: sequence, Data: data})
	return err
}

func (client *sandboxClient) closeStdin(ctx context.Context, handle *v1.ProcessHandle) error {
	ctx, cancel := boundedRPC(ctx)
	defer cancel()
	_, err := client.rpc.CloseStdin(ctx, &v1.CloseStdinRequest{Meta: operationMeta(), Process: handle})
	return err
}

func (client *sandboxClient) cancel(ctx context.Context, handle *v1.ProcessHandle, reason string) error {
	ctx, cancel := boundedRPC(ctx)
	defer cancel()
	_, err := client.rpc.Cancel(ctx, &v1.CancelProcessRequest{Meta: operationMeta(), Process: handle, Reason: reason})
	return err
}

// The shared stream checks the process identity, generation, ordering, unknown
// fields, and payload shape before the harness consumes an event.
func (client *sandboxClient) attach(ctx context.Context, handle *v1.ProcessHandle, after uint64) (*sandboxrpc.ProcessEventStream, error) {
	return client.rpc.Attach(ctx, &v1.AttachProcessRequest{Meta: operationMeta(), Process: handle, AfterSequence: after})
}

// attachDeadline bounds one attachment; the harness resumes a long run after
// the last validated sequence using another bounded attachment.
func attachDeadline(remaining time.Duration) time.Duration {
	deadline := remaining + 10*time.Second
	if deadline < time.Second {
		deadline = time.Second
	}
	if deadline > maximumAttachmentDuration {
		deadline = maximumAttachmentDuration
	}
	return deadline
}
