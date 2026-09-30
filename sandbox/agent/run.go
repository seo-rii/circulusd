//go:build linux

package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"google.golang.org/protobuf/proto"
)

const (
	tenantID              = "tenant_circulusd-test"
	userID                = "subject_local"
	pythonCommand         = "python3"
	outputLimitBytes      = 1 << 20 // what sandboxd may buffer per process
	capturedStreamLimit   = 256 << 10
	maximumCodeBytes      = 100 << 10
	maximumStdinBytes     = 1 << 20
	maximumProcessTimeout = 24 * time.Hour
	reattachPause         = 100 * time.Millisecond
)

// runRequest is what the Node backend posts to /v1/run.
type runRequest struct {
	SessionID     string `json:"sessionId"`
	TurnID        string `json:"turnId"`
	ToolCallID    string `json:"toolCallId"`
	RequestDigest string `json:"requestDigest"` // the engine's effect request digest, sha256:<hex>
	ReplayPolicy  string `json:"replayPolicy"`
	Code          string `json:"code"`
	Stdin         string `json:"stdin"`
	TimeoutMs     uint64 `json:"timeoutMs"`
}

type runResult struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdoutTruncated"`
	StderrTruncated bool   `json:"stderrTruncated"`
	ExitCode        int32  `json:"exitCode"`
	TimedOut        bool   `json:"timedOut"`
	Cancelled       bool   `json:"cancelled"`
	OutputTruncated bool   `json:"outputTruncated"`
	Signal          string `json:"signal"`
	SandboxID       string `json:"sandboxId"`
	Generation      uint64 `json:"generation"`
	// Note is set when the session's sandbox was (re)launched for this run.
	Note string `json:"note,omitempty"`
}

// executor drives one sandboxd generation of one session. Runs on a session
// are serialised by the pool, so it needs no locking of its own.
type executor struct {
	client    *sandboxClient
	inst      *instance
	backend   string
	envDigest string
	permitKey []byte
	// keyed counts the idempotency-keyed RPCs sent to this generation.
	// sandboxd's ledger never forgets a key, so the pool relaunches the
	// generation before the ledger fills up.
	keyed int
}

func newExecutor(client *sandboxClient, inst *instance, backend, environmentDigest string) *executor {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return &executor{client: client, inst: inst, backend: backend, envDigest: environmentDigest, permitKey: key}
}

var replayPolicies = map[string]v1.ReplayPolicy{
	"safe":            v1.ReplayPolicy_REPLAY_POLICY_SAFE,
	"idempotency-key": v1.ReplayPolicy_REPLAY_POLICY_IDEMPOTENCY_KEY,
	"never":           v1.ReplayPolicy_REPLAY_POLICY_NEVER,
	"confirm":         v1.ReplayPolicy_REPLAY_POLICY_CONFIRM,
}

var backends = map[string]v1.ExecutionBackend{
	"nsjail":      v1.ExecutionBackend_EXECUTION_BACKEND_NSJAIL,
	"docker":      v1.ExecutionBackend_EXECUTION_BACKEND_DOCKER,
	"firecracker": v1.ExecutionBackend_EXECUTION_BACKEND_FIRECRACKER,
}

type spawnPlan struct {
	executable    string
	arguments     []string
	stdin         string
	timeout       time.Duration
	sessionID     string
	turnID        string
	effectID      string
	requestDigest []byte
	replayPolicy  v1.ReplayPolicy
}

// safeDirectory reduces a session id to a file-system and log friendly key.
func safeDirectory(sessionID string) string {
	var builder strings.Builder
	for _, r := range sessionID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			builder.WriteRune(r)
		} else {
			builder.WriteByte('_')
		}
		if builder.Len() >= 96 {
			break
		}
	}
	if builder.Len() == 0 {
		return "session"
	}
	return builder.String()
}

func digestBytes(digest string, fallback []byte) []byte {
	if strings.HasPrefix(digest, "sha256:") {
		if value, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:")); err == nil && len(value) == sha256.Size {
			return value
		}
	}
	sum := sha256.Sum256(fallback)
	return sum[:]
}

// shouldRelaunch reports errors that a fresh sandboxd generation cures: a full
// idempotency ledger, or a sandboxd that no longer answers (gone or wedged).
// Anything else (a permit rejected, a protocol violation) would recur.
func shouldRelaunch(err error) bool {
	if err == nil {
		return false
	}
	switch connect.CodeOf(err) {
	case connect.CodeResourceExhausted, connect.CodeUnavailable, connect.CodeDeadlineExceeded:
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// errInvalidRequest marks caller mistakes (reported as 400, not 500).
var errInvalidRequest = errors.New("invalid run request")

// validateRunRequest rejects requests no sandbox should be launched for.
func validateRunRequest(request runRequest) error {
	if strings.TrimSpace(request.Code) == "" {
		return fmt.Errorf("%w: code must not be empty", errInvalidRequest)
	}
	if strings.IndexByte(request.Code, 0) >= 0 {
		return fmt.Errorf("%w: code must not contain NUL bytes", errInvalidRequest)
	}
	if request.SessionID == "" {
		return fmt.Errorf("%w: sessionId is required", errInvalidRequest)
	}
	// The code travels as one argv entry: Linux caps a single argument at
	// 128 KiB (MAX_ARG_STRLEN), and the spawn request must fit one message.
	if len(request.Code) > maximumCodeBytes {
		return fmt.Errorf("%w: code exceeds %d bytes", errInvalidRequest, maximumCodeBytes)
	}
	if len(request.Stdin) > maximumStdinBytes {
		return fmt.Errorf("%w: stdin exceeds %d bytes", errInvalidRequest, maximumStdinBytes)
	}
	return nil
}

func (e *executor) run(ctx context.Context, request runRequest) (*runResult, error) {
	if err := validateRunRequest(request); err != nil {
		return nil, err
	}
	replayPolicy, ok := replayPolicies[request.ReplayPolicy]
	if !ok {
		replayPolicy = v1.ReplayPolicy_REPLAY_POLICY_NEVER
	}
	timeout := time.Duration(request.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if timeout > maximumProcessTimeout {
		timeout = maximumProcessTimeout
	}
	effectSum := sha256.Sum256([]byte("effect|" + request.SessionID + "|" + request.TurnID + "|" + request.ToolCallID))
	plan := spawnPlan{
		sessionID:     request.SessionID,
		turnID:        request.TurnID,
		effectID:      "effect_" + idEncoding.EncodeToString(effectSum[:16]),
		requestDigest: digestBytes(request.RequestDigest, []byte(request.Code)),
		replayPolicy:  replayPolicy,
		executable:    pythonCommand,
		// The sandbox is private to the session, so /workspace itself is the cwd.
		arguments: []string{"-I", "-B", "-X", "utf8", "-c", request.Code},
		stdin:     request.Stdin,
		timeout:   timeout,
	}
	return e.execute(ctx, plan)
}

func (e *executor) sign(domain string, message proto.Message) []byte {
	wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		panic(err)
	}
	mac := hmac.New(sha256.New, e.permitKey)
	mac.Write([]byte(domain))
	mac.Write([]byte{0})
	mac.Write(wire)
	return mac.Sum(nil)
}

func (e *executor) execute(ctx context.Context, plan spawnPlan) (*runResult, error) {
	inst := e.inst
	invocationID := newIdentity("inv")
	now := time.Now()
	permitDeadline := uint64(now.Add(plan.timeout + time.Minute).UnixMilli())
	opaque := func(text string) *v1.OpaqueId { return &v1.OpaqueId{Value: []byte(text)} }
	digest := &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: plan.requestDigest}
	sandbox := &v1.SandboxHandle{
		SandboxId:                  opaque(inst.ID),
		Generation:                 inst.Generation,
		Backend:                    backends[e.backend],
		ExecutionEnvironmentDigest: &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: digestBytes(e.envDigest, nil)},
	}
	// Harness-issued permits: sandboxd fail-closes on their explicit field
	// bindings (see sandboxrpc/server_linux.go Spawn); in circulusd proper the
	// state layer issues and executord verifies them before this point.
	dispatch := &v1.DispatchPermit{
		TenantId:                opaque(tenantID),
		UserId:                  opaque(userID),
		SessionId:               opaque(plan.sessionID),
		TurnId:                  opaque(plan.turnID),
		EffectId:                opaque(plan.effectID),
		InvocationId:            opaque(invocationID),
		RequestDigest:           digest,
		Service:                 v1.EffectService_EFFECT_SERVICE_EXECUTOR,
		Operation:               "executor.run",
		ReplayPolicy:            plan.replayPolicy,
		DispatchAttempt:         1,
		TurnLeaseGeneration:     1,
		PlacementGeneration:     1,
		SandboxGeneration:       inst.Generation,
		AuthorizationGeneration: 1,
		DeadlineUnixMs:          permitDeadline,
	}
	dispatch.Value = e.sign("dispatch", dispatch)
	workspace := &v1.WorkspaceProtectionPermit{
		TenantId:                  opaque(tenantID),
		UserId:                    opaque(userID),
		WorkspaceId:               opaque("ws_" + plan.sessionID),
		LeaseId:                   opaque("lease_" + plan.sessionID),
		InvocationId:              opaque(invocationID),
		RequestDigest:             digest,
		EffectId:                  opaque(plan.effectID),
		SessionId:                 opaque(plan.sessionID),
		SandboxId:                 opaque(inst.ID),
		Backend:                   backends[e.backend],
		AccessMode:                v1.WorkspaceAccessMode_WORKSPACE_ACCESS_MODE_READ_WRITE,
		LeaseGeneration:           1,
		DispatchAttempt:           1,
		TurnLeaseGeneration:       1,
		PlacementGeneration:       1,
		SandboxGeneration:         inst.Generation,
		ProjectionGeneration:      1,
		AuthorizationGeneration:   1,
		IssuedAtUnixMs:            uint64(now.Add(-time.Second).UnixMilli()),
		ExpiresAtUnixMs:           permitDeadline,
		MaximumHoldDeadlineUnixMs: permitDeadline,
		EnqueueSequence:           1,
	}
	workspace.Value = e.sign("workspace", workspace)
	stdinMode := v1.StdinMode_STDIN_MODE_CLOSED
	if plan.stdin != "" {
		stdinMode = v1.StdinMode_STDIN_MODE_STREAM
	}
	spawnRequest := &v1.SpawnProcessRequest{
		Meta:                &v1.RpcRequestMeta{},
		DispatchPermit:      dispatch,
		Sandbox:             sandbox,
		WorkspaceProtection: workspace,
		InvocationId:        opaque(invocationID),
		RequestDigest:       digest,
		Executable:          plan.executable,
		Arguments:           plan.arguments,
		WorkingDirectory:    "",
		TimeoutMs:           uint64(plan.timeout / time.Millisecond),
		OutputLimitBytes:    outputLimitBytes,
		StdinMode:           stdinMode,
	}
	e.keyed++
	handle, err := e.client.spawn(ctx, spawnRequest)
	if err != nil {
		return nil, err
	}
	if plan.stdin != "" {
		// A script that exits without draining stdin makes a later write fail
		// (EPIPE, or "process exited"); that is the script's business, not an
		// error of the run, so the result is still collected. sandboxd closes
		// its end of the pipe on a failed write.
		if err := e.feedStdin(ctx, handle, []byte(plan.stdin)); err != nil {
			if ctx.Err() != nil {
				e.cancel(handle, "client gone")
				return nil, ctx.Err()
			}
			logf("stdin for %s not fully delivered: %v", handle.GetProcessId().GetValue(), err)
		}
	}
	return e.collect(ctx, handle, plan.timeout)
}

// feedStdin streams the data in protocol-sized chunks and closes stdin.
func (e *executor) feedStdin(ctx context.Context, handle *v1.ProcessHandle, data []byte) error {
	var sequence uint64
	for offset := 0; offset < len(data); offset += maximumStdinChunkBytes {
		sequence++
		end := min(offset+maximumStdinChunkBytes, len(data))
		e.keyed++
		if err := e.client.writeStdin(ctx, handle, sequence, data[offset:end]); err != nil {
			return err
		}
	}
	e.keyed++
	return e.client.closeStdin(ctx, handle)
}

func (e *executor) cancel(handle *v1.ProcessHandle, reason string) {
	e.keyed++
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = e.client.cancel(ctx, handle, reason)
}

type capture struct {
	data      []byte
	truncated bool
}

func (c *capture) push(chunk []byte) {
	if c.truncated {
		return
	}
	c.data = append(c.data, chunk...)
	if len(c.data) > capturedStreamLimit {
		// Do not leave a torn multi-byte character at the cut.
		c.data = trimIncompleteRune(c.data[:capturedStreamLimit])
		c.truncated = true
	}
}

// collect follows the process event stream until the exit event. One Attach
// RPC is bounded by the protocol's maximum deadline, so a long run re-attaches
// after the last seen sequence; any other stream failure is fatal.
func (e *executor) collect(ctx context.Context, handle *v1.ProcessHandle, timeout time.Duration) (*runResult, error) {
	var stdout, stderr capture
	started := time.Now()
	var after uint64
	for {
		remaining := timeout - time.Since(started)
		attachCtx, cancel := context.WithTimeout(ctx, attachDeadline(remaining))
		stream, err := e.client.attach(attachCtx, handle, after)
		if err != nil {
			cancel()
			if ctx.Err() == nil {
				e.cancel(handle, "attach failed")
			}
			return nil, err
		}
		var exit *v1.ProcessResult
		for stream.Receive() {
			event := stream.Msg()
			if event == nil || hasUnknownFields(event) || !proto.Equal(event.GetProcess(), handle) || event.GetSequence() != after+1 {
				_ = stream.Close()
				cancel()
				e.cancel(handle, "protocol violation")
				return nil, errors.New("process event failed protocol validation")
			}
			after = event.GetSequence()
			switch payload := event.GetEvent().(type) {
			case *v1.ProcessEvent_Stdout:
				stdout.push(payload.Stdout.GetData())
			case *v1.ProcessEvent_Stderr:
				stderr.push(payload.Stderr.GetData())
			case *v1.ProcessEvent_Exit:
				exit = payload.Exit
			case *v1.ProcessEvent_Error:
				_ = stream.Close()
				cancel()
				return nil, fmt.Errorf("sandbox process stream failed: %s", payload.Error.GetMessage())
			}
			if exit != nil {
				break
			}
		}
		streamErr := stream.Err()
		attachExpired := attachCtx.Err() != nil && ctx.Err() == nil
		_ = stream.Close()
		cancel()
		if exit != nil {
			signal := ""
			switch exit.GetTerminatingSignal() {
			case v1.ProcessSignal_PROCESS_SIGNAL_INTERRUPT:
				signal = "SIGINT"
			case v1.ProcessSignal_PROCESS_SIGNAL_TERMINATE:
				signal = "SIGTERM"
			case v1.ProcessSignal_PROCESS_SIGNAL_KILL:
				signal = "SIGKILL"
			case v1.ProcessSignal_PROCESS_SIGNAL_HANGUP:
				signal = "SIGHUP"
			}
			return &runResult{
				Stdout:          string(stdout.data),
				Stderr:          string(stderr.data),
				StdoutTruncated: stdout.truncated,
				StderrTruncated: stderr.truncated,
				ExitCode:        exit.GetExitCode(),
				TimedOut:        exit.GetTimedOut(),
				Cancelled:       exit.GetCancelled(),
				OutputTruncated: exit.GetOutputTruncated(),
				Signal:          signal,
			}, nil
		}
		if ctx.Err() != nil {
			e.cancel(handle, "client gone")
			return nil, ctx.Err()
		}
		if time.Since(started) > timeout+maximumRPCDeadline {
			e.cancel(handle, "no exit within deadline")
			return nil, fmt.Errorf("sandbox process did not report an exit within its deadline (%v)", streamErr)
		}
		if streamErr != nil && !attachExpired {
			e.cancel(handle, "attach stream failed")
			return nil, fmt.Errorf("sandbox process stream failed: %w", streamErr)
		}
		if !attachExpired {
			// sandboxd ended the stream without an exit; give it a moment before re-attaching.
			time.Sleep(reattachPause)
		}
	}
}
