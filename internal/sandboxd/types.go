// Package sandboxd implements the backend-neutral long-lived process
// supervisor core used inside native sandboxes.
package sandboxd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalidConfig      = errors.New("invalid sandbox supervisor config")
	ErrInvalidRequest     = errors.New("invalid process request")
	ErrIDConflict         = errors.New("request or process ID conflict")
	ErrCommandNotAllowed  = errors.New("command is not allowlisted")
	ErrUnknownProcess     = errors.New("unknown process handle")
	ErrStaleGeneration    = errors.New("stale sandbox generation")
	ErrSandboxFenced      = errors.New("sandbox supervisor is fenced")
	ErrStdinClosed        = errors.New("process stdin is closed")
	ErrProcessExited      = errors.New("process has exited")
	ErrReplayUnavailable  = errors.New("requested process event replay is unavailable")
	ErrInvalidCursor      = errors.New("invalid process event cursor")
	ErrOutputBackpressure = errors.New("process event subscriber exceeded its buffer")
	ErrInvalidSignal      = errors.New("invalid process signal")
	ErrInvalidGeneration  = errors.New("generation must increase monotonically")
)

// CommandName is a logical environment allowlist key, never a host path.
type CommandName struct {
	value string
}

// ParseCommandName validates a logical command name. Path separators are
// forbidden so user input cannot turn this value into an executable path.
func ParseCommandName(value string) (CommandName, error) {
	if value == "" || value == "." || value == ".." ||
		len(value) > 128 || !utf8.ValidString(value) ||
		strings.ContainsAny(value, "/\\\x00") {
		return CommandName{}, fmt.Errorf("%w: invalid logical command name", ErrInvalidRequest)
	}
	return CommandName{value: value}, nil
}

func (name CommandName) String() string {
	return name.value
}

// WorkspacePath is a canonical slash-separated path relative to the fixed
// launch-time workspace root. The zero value is invalid.
type WorkspacePath struct {
	value string
}

// ParseWorkspacePath validates a workspace-relative working directory. Empty
// input denotes the workspace root and canonicalizes to '.'.
func ParseWorkspacePath(value string) (WorkspacePath, error) {
	if value == "" {
		return WorkspacePath{value: "."}, nil
	}
	if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 ||
		path.IsAbs(value) || len(value) > 4096 || path.Clean(value) != value {
		return WorkspacePath{}, fmt.Errorf("%w: invalid workspace-relative path", ErrInvalidRequest)
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." || len(component) > 255 {
			return WorkspacePath{}, fmt.Errorf("%w: invalid workspace path component", ErrInvalidRequest)
		}
	}
	return WorkspacePath{value: value}, nil
}

func (workspacePath WorkspacePath) String() string {
	return workspacePath.value
}

// StdinMode determines whether stdin accepts streamed writes.
type StdinMode string

const (
	StdinClosed StdinMode = "closed"
	StdinStream StdinMode = "stream"
)

// SpawnRequest contains no sandbox, tenant, workspace identity, raw host path,
// mount, device, or environment authority. Those values are fixed by trusted
// launch-time Config.
type SpawnRequest struct {
	RequestID    string
	ProcessID    string
	InvocationID string

	Command          CommandName
	Arguments        []string
	WorkingDirectory WorkspacePath

	StdinMode        StdinMode
	OutputLimitBytes int64
	Deadline         time.Time
}

// LaunchAuthority fixes sandbox identity and generation before command traffic
// is accepted. It is trusted executord/bootstrap input, not a SpawnRequest.
type LaunchAuthority struct {
	SandboxID  string
	Generation uint64
}

// Config contains trusted launch-time paths and bounded stream settings.
type Config struct {
	Authority LaunchAuthority

	WorkspaceRoot string
	Commands      map[string]string
	Runner        Runner

	ReplayLimitBytes  int
	ReplayLimitEvents int
	SubscriberBuffer  int
	ReadChunkBytes    int
}

// ProcessSignal always targets the runner's process group abstraction.
type ProcessSignal string

const (
	SignalInterrupt ProcessSignal = "interrupt"
	SignalTerminate ProcessSignal = "terminate"
	SignalKill      ProcessSignal = "kill"
	SignalCancel    ProcessSignal = "cancel"
)

// ExitReason classifies a terminal process result independently of an OS PID.
type ExitReason string

const (
	ExitReasonExited      ExitReason = "exited"
	ExitReasonFailed      ExitReason = "failed"
	ExitReasonSignaled    ExitReason = "signaled"
	ExitReasonCanceled    ExitReason = "canceled"
	ExitReasonDeadline    ExitReason = "deadline"
	ExitReasonOutputLimit ExitReason = "output-limit"
	ExitReasonFenced      ExitReason = "fenced"
)

// RunResult is the trusted runner's raw terminal result.
type RunResult struct {
	ExitCode int
	Signal   ProcessSignal
	Error    string
}

// ProcessResult is the stable supervisor terminal result.
type ProcessResult struct {
	Reason     ExitReason
	ExitCode   int
	Signal     ProcessSignal
	Error      string
	FinishedAt time.Time
}

// EventType identifies one ordered process stream event.
type EventType string

const (
	EventStarted EventType = "started"
	EventStdout  EventType = "stdout"
	EventStderr  EventType = "stderr"
	EventError   EventType = "error"
	EventExit    EventType = "exit"
)

// ProcessEvent has a process-global, strictly increasing sequence number.
type ProcessEvent struct {
	Sequence   uint64
	Type       EventType
	Data       []byte
	Error      string
	Result     ProcessResult
	OccurredAt time.Time
}

// ProcessHandle is opaque and bound to one supervisor instance and launch
// generation. OS PIDs are never exposed as authority.
type ProcessHandle struct {
	supervisorID uint64
	recordID     uint64
	generation   uint64
}

func (handle ProcessHandle) Generation() uint64 {
	return handle.generation
}

func (handle ProcessHandle) IsZero() bool {
	return handle == ProcessHandle{}
}

func (handle ProcessHandle) String() string {
	if handle.IsZero() {
		return "process-handle<zero>"
	}
	return fmt.Sprintf("process-handle<generation=%d>", handle.generation)
}

// SpawnResult reports whether an idempotent request reused an existing
// process identity.
type SpawnResult struct {
	Handle ProcessHandle
	Reused bool
}

// Attachment is a bounded event stream. A slow client is disconnected with
// ErrOutputBackpressure on Done and can reconnect using its last sequence.
type Attachment struct {
	Events <-chan ProcessEvent
	Done   <-chan error

	closeOnce sync.Once
	close     func()
}

func (attachment *Attachment) Close() {
	if attachment == nil {
		return
	}
	attachment.closeOnce.Do(attachment.close)
}

// RunSpec is trusted input produced only after Supervisor resolves logical
// request fields against launch-time roots and allowlists.
type RunSpec struct {
	ExecutablePath   string
	Arguments        []string
	WorkingDirectory string
	StdinMode        StdinMode
}

// ProcessStdin is the runner-owned input pipe. WriteContext must return promptly
// when its context is canceled. Close must also interrupt an ongoing write
// without waiting for that write to release a lock.
type ProcessStdin interface {
	WriteContext(context.Context, []byte) (int, error)
	Close() error
}

// RunningProcess is the minimum process-group abstraction shared by the
// deterministic fake and development os/exec runner.
type RunningProcess interface {
	Stdin() ProcessStdin
	Stdout() io.ReadCloser
	Stderr() io.ReadCloser
	SignalGroup(ProcessSignal) error
	Wait() RunResult
}

// Runner starts a process from a trusted, fully resolved RunSpec.
type Runner interface {
	Start(context.Context, RunSpec) (RunningProcess, error)
}
