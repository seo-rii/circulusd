package sandboxd

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const spawnDigestDomain = "circulusd.sandboxd.spawn-request.v1\x00"

var supervisorSequence atomic.Uint64

// Supervisor owns all process identity and event state for one launch-time
// sandbox authority.
type Supervisor struct {
	mu sync.Mutex

	supervisorID uint64
	sandboxID    string
	generation   uint64
	fenced       bool

	workspaceRoot string
	commands      map[string]string
	runner        Runner

	replayLimitBytes  int
	replayLimitEvents int
	subscriberBuffer  int
	readChunkBytes    int

	nextRecordID uint64
	processes    map[uint64]*processRecord
	requests     map[string]spawnIdentity
	processIDs   map[string]spawnIdentity
	inflightReq  map[string]*spawnCall
	inflightProc map[string]*spawnCall
}

type spawnIdentity struct {
	digest [sha256.Size]byte
	handle ProcessHandle
}

type spawnCall struct {
	digest    [sha256.Size]byte
	requestID string
	processID string
	done      chan struct{}
	result    SpawnResult
	err       error
}

type processRecord struct {
	mu        sync.Mutex
	stdinMu   sync.Mutex
	controlMu sync.Mutex

	handle  ProcessHandle
	running RunningProcess
	stdin   io.WriteCloser

	stdinMode   StdinMode
	stdinClosed bool

	nextSequence uint64
	replay       []ProcessEvent
	replayBytes  int

	nextSubscriberID uint64
	subscribers      map[uint64]*eventSubscriber

	outputBytes int64
	outputLimit int64

	terminationReason ExitReason
	terminationSignal ProcessSignal
	terminal          bool
	result            ProcessResult
	done              chan struct{}
}

type eventSubscriber struct {
	id       uint64
	events   chan ProcessEvent
	done     chan error
	finished bool
}

// NewSupervisor validates and snapshots trusted launch configuration.
func NewSupervisor(config Config) (*Supervisor, error) {
	if config.Authority.SandboxID == "" ||
		!utf8.ValidString(config.Authority.SandboxID) ||
		strings.IndexByte(config.Authority.SandboxID, 0) >= 0 {
		return nil, fmt.Errorf("%w: invalid sandbox identity", ErrInvalidConfig)
	}
	if config.Authority.Generation == 0 {
		return nil, fmt.Errorf("%w: generation must be positive", ErrInvalidConfig)
	}
	if config.Runner == nil {
		return nil, fmt.Errorf("%w: runner is required", ErrInvalidConfig)
	}
	if config.WorkspaceRoot == "" || !filepath.IsAbs(config.WorkspaceRoot) ||
		filepath.Clean(config.WorkspaceRoot) != config.WorkspaceRoot ||
		strings.IndexByte(config.WorkspaceRoot, 0) >= 0 {
		return nil, fmt.Errorf("%w: workspace root must be a canonical absolute path", ErrInvalidConfig)
	}
	if config.ReplayLimitBytes <= 0 || config.ReplayLimitEvents <= 0 ||
		config.SubscriberBuffer <= 0 || config.ReadChunkBytes <= 0 {
		return nil, fmt.Errorf("%w: stream limits must be positive", ErrInvalidConfig)
	}

	commands := make(map[string]string, len(config.Commands))
	for name, executablePath := range config.Commands {
		parsed, err := ParseCommandName(name)
		if err != nil || parsed.String() != name {
			return nil, fmt.Errorf("%w: invalid command allowlist key %q", ErrInvalidConfig, name)
		}
		if executablePath == "" || !filepath.IsAbs(executablePath) ||
			filepath.Clean(executablePath) != executablePath ||
			strings.IndexByte(executablePath, 0) >= 0 {
			return nil, fmt.Errorf("%w: command %q has an invalid executable path", ErrInvalidConfig, name)
		}
		commands[name] = executablePath
	}

	return &Supervisor{
		supervisorID:      supervisorSequence.Add(1),
		sandboxID:         config.Authority.SandboxID,
		generation:        config.Authority.Generation,
		workspaceRoot:     config.WorkspaceRoot,
		commands:          commands,
		runner:            config.Runner,
		replayLimitBytes:  config.ReplayLimitBytes,
		replayLimitEvents: config.ReplayLimitEvents,
		subscriberBuffer:  config.SubscriberBuffer,
		readChunkBytes:    config.ReadChunkBytes,
		processes:         make(map[uint64]*processRecord),
		requests:          make(map[string]spawnIdentity),
		processIDs:        make(map[string]spawnIdentity),
		inflightReq:       make(map[string]*spawnCall),
		inflightProc:      make(map[string]*spawnCall),
	}, nil
}

// Spawn starts or idempotently returns a process for the request/process ID
// pair. Concurrent duplicates share one runner start.
func (supervisor *Supervisor) Spawn(
	ctx context.Context,
	request SpawnRequest,
) (SpawnResult, error) {
	if err := ctx.Err(); err != nil {
		return SpawnResult{}, err
	}

	identifiers := []struct {
		name  string
		value string
	}{
		{name: "request", value: request.RequestID},
		{name: "process", value: request.ProcessID},
		{name: "invocation", value: request.InvocationID},
	}
	for _, identifier := range identifiers {
		if identifier.value == "" || len(identifier.value) > 256 ||
			!utf8.ValidString(identifier.value) || strings.IndexByte(identifier.value, 0) >= 0 {
			return SpawnResult{}, fmt.Errorf("%w: invalid %s ID", ErrInvalidRequest, identifier.name)
		}
	}
	if request.Command.value == "" || request.WorkingDirectory.value == "" {
		return SpawnResult{}, fmt.Errorf("%w: command and working directory must be parsed", ErrInvalidRequest)
	}
	if request.StdinMode != StdinClosed && request.StdinMode != StdinStream {
		return SpawnResult{}, fmt.Errorf("%w: unsupported stdin mode %q", ErrInvalidRequest, request.StdinMode)
	}
	if request.OutputLimitBytes <= 0 {
		return SpawnResult{}, fmt.Errorf("%w: output limit must be positive", ErrInvalidRequest)
	}
	if len(request.Arguments) > 4096 {
		return SpawnResult{}, fmt.Errorf("%w: too many command arguments", ErrInvalidRequest)
	}
	argumentBytes := 0
	for _, argument := range request.Arguments {
		if !utf8.ValidString(argument) || strings.IndexByte(argument, 0) >= 0 {
			return SpawnResult{}, fmt.Errorf("%w: argument is not a valid process string", ErrInvalidRequest)
		}
		argumentBytes += len(argument)
		if argumentBytes > 1<<20 {
			return SpawnResult{}, fmt.Errorf("%w: command arguments exceed one MiB", ErrInvalidRequest)
		}
	}

	requestHash := sha256.New()
	_, _ = requestHash.Write([]byte(spawnDigestDomain))
	writeString := func(value string) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = requestHash.Write(length[:])
		_, _ = requestHash.Write([]byte(value))
	}
	writeString(request.RequestID)
	writeString(request.ProcessID)
	writeString(request.InvocationID)
	writeString(request.Command.value)
	writeString(request.WorkingDirectory.value)
	writeString(string(request.StdinMode))
	var fixed [8]byte
	binary.BigEndian.PutUint64(fixed[:], uint64(request.OutputLimitBytes))
	_, _ = requestHash.Write(fixed[:])
	binary.BigEndian.PutUint64(fixed[:], uint64(request.Deadline.UnixNano()))
	_, _ = requestHash.Write(fixed[:])
	var argumentCount [4]byte
	binary.BigEndian.PutUint32(argumentCount[:], uint32(len(request.Arguments)))
	_, _ = requestHash.Write(argumentCount[:])
	for _, argument := range request.Arguments {
		writeString(argument)
	}
	var requestDigest [sha256.Size]byte
	copy(requestDigest[:], requestHash.Sum(nil))

	supervisor.mu.Lock()
	if supervisor.fenced {
		supervisor.mu.Unlock()
		return SpawnResult{}, ErrSandboxFenced
	}
	if identity, exists := supervisor.requests[request.RequestID]; exists {
		if identity.digest != requestDigest {
			supervisor.mu.Unlock()
			return SpawnResult{}, fmt.Errorf("%w: request ID %q", ErrIDConflict, request.RequestID)
		}
		supervisor.mu.Unlock()
		return SpawnResult{Handle: identity.handle, Reused: true}, nil
	}
	if identity, exists := supervisor.processIDs[request.ProcessID]; exists {
		if identity.digest != requestDigest {
			supervisor.mu.Unlock()
			return SpawnResult{}, fmt.Errorf("%w: process ID %q", ErrIDConflict, request.ProcessID)
		}
		supervisor.mu.Unlock()
		return SpawnResult{Handle: identity.handle, Reused: true}, nil
	}
	if call := supervisor.inflightReq[request.RequestID]; call != nil {
		if call.digest != requestDigest {
			supervisor.mu.Unlock()
			return SpawnResult{}, fmt.Errorf("%w: in-flight request ID %q", ErrIDConflict, request.RequestID)
		}
		supervisor.mu.Unlock()
		select {
		case <-call.done:
			if call.err != nil {
				return SpawnResult{}, call.err
			}
			result := call.result
			result.Reused = true
			return result, nil
		case <-ctx.Done():
			return SpawnResult{}, ctx.Err()
		}
	}
	if call := supervisor.inflightProc[request.ProcessID]; call != nil {
		if call.digest != requestDigest {
			supervisor.mu.Unlock()
			return SpawnResult{}, fmt.Errorf("%w: in-flight process ID %q", ErrIDConflict, request.ProcessID)
		}
		supervisor.mu.Unlock()
		select {
		case <-call.done:
			if call.err != nil {
				return SpawnResult{}, call.err
			}
			result := call.result
			result.Reused = true
			return result, nil
		case <-ctx.Done():
			return SpawnResult{}, ctx.Err()
		}
	}

	executablePath, allowed := supervisor.commands[request.Command.value]
	if !allowed {
		supervisor.mu.Unlock()
		return SpawnResult{}, fmt.Errorf("%w: %q", ErrCommandNotAllowed, request.Command.value)
	}
	call := &spawnCall{
		digest:    requestDigest,
		requestID: request.RequestID,
		processID: request.ProcessID,
		done:      make(chan struct{}),
	}
	supervisor.inflightReq[request.RequestID] = call
	supervisor.inflightProc[request.ProcessID] = call
	workspaceRoot := supervisor.workspaceRoot
	runner := supervisor.runner
	supervisor.mu.Unlock()

	arguments := append([]string(nil), request.Arguments...)
	workingDirectory := workspaceRoot
	if request.WorkingDirectory.value != "." {
		workingDirectory = filepath.Join(workspaceRoot, filepath.FromSlash(request.WorkingDirectory.value))
	}
	running, startErr := runner.Start(ctx, RunSpec{
		ExecutablePath:   executablePath,
		Arguments:        arguments,
		WorkingDirectory: workingDirectory,
		StdinMode:        request.StdinMode,
	})
	if startErr != nil {
		supervisor.mu.Lock()
		call.err = startErr
		delete(supervisor.inflightReq, request.RequestID)
		delete(supervisor.inflightProc, request.ProcessID)
		close(call.done)
		supervisor.mu.Unlock()
		return SpawnResult{}, startErr
	}

	supervisor.mu.Lock()
	if supervisor.fenced {
		call.err = ErrSandboxFenced
		delete(supervisor.inflightReq, request.RequestID)
		delete(supervisor.inflightProc, request.ProcessID)
		close(call.done)
		supervisor.mu.Unlock()
		_ = running.SignalGroup(SignalKill)
		go running.Wait()
		return SpawnResult{}, ErrSandboxFenced
	}
	supervisor.nextRecordID++
	handle := ProcessHandle{
		supervisorID: supervisor.supervisorID,
		recordID:     supervisor.nextRecordID,
		generation:   supervisor.generation,
	}
	record := &processRecord{
		handle:      handle,
		running:     running,
		stdin:       running.Stdin(),
		stdinMode:   request.StdinMode,
		outputLimit: request.OutputLimitBytes,
		subscribers: make(map[uint64]*eventSubscriber),
		done:        make(chan struct{}),
	}
	if request.StdinMode == StdinClosed {
		record.stdinClosed = true
		_ = record.stdin.Close()
	}
	supervisor.processes[handle.recordID] = record
	supervisor.mu.Unlock()

	supervisor.publish(record, ProcessEvent{Type: EventStarted})
	var streams sync.WaitGroup
	streams.Add(2)
	go func() {
		defer streams.Done()
		supervisor.consumeStream(record, running.Stdout(), EventStdout)
	}()
	go func() {
		defer streams.Done()
		supervisor.consumeStream(record, running.Stderr(), EventStderr)
	}()
	streamsDone := make(chan struct{})
	go func() {
		streams.Wait()
		close(streamsDone)
	}()
	go func() {
		<-streamsDone
		runResult := running.Wait()

		record.stdinMu.Lock()
		if !record.stdinClosed {
			record.stdinClosed = true
			_ = record.stdin.Close()
		}
		record.stdinMu.Unlock()

		record.mu.Lock()
		reason := record.terminationReason
		signal := record.terminationSignal
		if reason == "" {
			switch {
			case runResult.Signal != "":
				reason = ExitReasonSignaled
				signal = runResult.Signal
			case runResult.Error != "":
				reason = ExitReasonFailed
			default:
				reason = ExitReasonExited
			}
		}
		record.result = ProcessResult{
			Reason:   reason,
			ExitCode: runResult.ExitCode,
			Signal:   signal,
			Error:    runResult.Error,
		}
		record.terminal = true
		result := record.result
		supervisor.publishLocked(record, ProcessEvent{Type: EventExit, Result: result})
		record.mu.Unlock()
		close(record.done)
	}()
	if !request.Deadline.IsZero() {
		go func() {
			delay := time.Until(request.Deadline)
			if delay < 0 {
				delay = 0
			}
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
				_ = supervisor.terminate(record, ExitReasonDeadline, SignalKill)
			case <-record.done:
			}
		}()
	}

	supervisor.mu.Lock()
	identity := spawnIdentity{digest: requestDigest, handle: handle}
	supervisor.requests[request.RequestID] = identity
	supervisor.processIDs[request.ProcessID] = identity
	call.result = SpawnResult{Handle: handle}
	delete(supervisor.inflightReq, request.RequestID)
	delete(supervisor.inflightProc, request.ProcessID)
	close(call.done)
	result := call.result
	supervisor.mu.Unlock()
	return result, nil
}

// Attach returns retained events after the caller's last observed sequence and
// registers for live events when the process is still running.
func (supervisor *Supervisor) Attach(
	ctx context.Context,
	handle ProcessHandle,
	afterSequence uint64,
) (*Attachment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	record, err := supervisor.processForHandle(handle)
	if err != nil {
		return nil, err
	}

	record.mu.Lock()
	if afterSequence > record.nextSequence {
		record.mu.Unlock()
		return nil, ErrInvalidCursor
	}
	if len(record.replay) > 0 {
		oldest := record.replay[0].Sequence
		if afterSequence < oldest-1 {
			record.mu.Unlock()
			return nil, ErrReplayUnavailable
		}
	} else if afterSequence < record.nextSequence {
		record.mu.Unlock()
		return nil, ErrReplayUnavailable
	}
	replay := make([]ProcessEvent, 0, len(record.replay))
	for _, event := range record.replay {
		if event.Sequence > afterSequence {
			replay = append(replay, cloneProcessEvent(event))
		}
	}
	record.nextSubscriberID++
	subscriber := &eventSubscriber{
		id:     record.nextSubscriberID,
		events: make(chan ProcessEvent, len(replay)+supervisor.subscriberBuffer),
		done:   make(chan error, 1),
	}
	for _, event := range replay {
		subscriber.events <- event
	}
	if record.terminal {
		supervisor.finishSubscriber(record, subscriber, nil)
	} else {
		record.subscribers[subscriber.id] = subscriber
	}
	record.mu.Unlock()

	attachment := &Attachment{
		Events: subscriber.events,
		Done:   subscriber.done,
		close: func() {
			record.mu.Lock()
			supervisor.finishSubscriber(record, subscriber, nil)
			record.mu.Unlock()
		},
	}
	if ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				record.mu.Lock()
				supervisor.finishSubscriber(record, subscriber, ctx.Err())
				record.mu.Unlock()
			case <-subscriber.done:
			}
		}()
	}
	return attachment, nil
}

// WriteStdin serializes writes so each call remains contiguous.
func (supervisor *Supervisor) WriteStdin(
	ctx context.Context,
	handle ProcessHandle,
	data []byte,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	record, err := supervisor.processForHandle(handle)
	if err != nil {
		return err
	}
	record.stdinMu.Lock()
	defer record.stdinMu.Unlock()
	if record.stdinMode != StdinStream || record.stdinClosed {
		return ErrStdinClosed
	}
	record.mu.Lock()
	terminal := record.terminal
	record.mu.Unlock()
	if terminal {
		return ErrProcessExited
	}
	written, err := record.stdin.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

// CloseStdin is idempotent and serialized with concurrent writes.
func (supervisor *Supervisor) CloseStdin(ctx context.Context, handle ProcessHandle) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	record, err := supervisor.processForHandle(handle)
	if err != nil {
		return err
	}
	record.stdinMu.Lock()
	defer record.stdinMu.Unlock()
	if record.stdinClosed {
		return nil
	}
	record.stdinClosed = true
	return record.stdin.Close()
}

// Signal targets the process group abstraction. Cancel and kill remain
// idempotent after process exit.
func (supervisor *Supervisor) Signal(
	ctx context.Context,
	handle ProcessHandle,
	signal ProcessSignal,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if signal != SignalInterrupt && signal != SignalTerminate &&
		signal != SignalKill && signal != SignalCancel {
		return ErrInvalidSignal
	}
	record, err := supervisor.processForHandle(handle)
	if err != nil {
		return err
	}
	reason := ExitReason("")
	if signal == SignalCancel {
		reason = ExitReasonCanceled
	}
	err = supervisor.terminate(record, reason, signal)
	if errors.Is(err, ErrProcessExited) && (signal == SignalCancel || signal == SignalKill) {
		return nil
	}
	return err
}

// Wait supports any number of concurrent callers and never consumes the
// terminal result.
func (supervisor *Supervisor) Wait(
	ctx context.Context,
	handle ProcessHandle,
) (ProcessResult, error) {
	if err := ctx.Err(); err != nil {
		return ProcessResult{}, err
	}
	record, err := supervisor.processForHandle(handle)
	if err != nil {
		return ProcessResult{}, err
	}
	select {
	case <-record.done:
		record.mu.Lock()
		result := record.result
		record.mu.Unlock()
		return result, nil
	case <-ctx.Done():
		return ProcessResult{}, ctx.Err()
	}
}

// Fence monotonically invalidates every issued handle, kills active process
// groups, and permanently denies new admission to this sandbox instance.
func (supervisor *Supervisor) Fence(generation uint64) error {
	supervisor.mu.Lock()
	if generation <= supervisor.generation {
		supervisor.mu.Unlock()
		return ErrInvalidGeneration
	}
	supervisor.generation = generation
	supervisor.fenced = true
	records := make([]*processRecord, 0, len(supervisor.processes))
	for _, record := range supervisor.processes {
		records = append(records, record)
	}
	supervisor.mu.Unlock()

	for _, record := range records {
		_ = supervisor.terminate(record, ExitReasonFenced, SignalKill)
	}
	return nil
}

func (supervisor *Supervisor) processForHandle(handle ProcessHandle) (*processRecord, error) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if handle.IsZero() || handle.supervisorID != supervisor.supervisorID {
		return nil, ErrUnknownProcess
	}
	if handle.generation != supervisor.generation {
		return nil, ErrStaleGeneration
	}
	record := supervisor.processes[handle.recordID]
	if record == nil || record.handle != handle {
		return nil, ErrUnknownProcess
	}
	return record, nil
}

func (supervisor *Supervisor) consumeStream(
	record *processRecord,
	stream io.ReadCloser,
	eventType EventType,
) {
	defer stream.Close()
	buffer := make([]byte, supervisor.readChunkBytes)
	for {
		count, err := stream.Read(buffer)
		if count > 0 {
			record.mu.Lock()
			remaining := record.outputLimit - record.outputBytes
			accepted := int64(count)
			if accepted > remaining {
				accepted = remaining
			}
			if accepted < 0 {
				accepted = 0
			}
			record.outputBytes += accepted
			record.mu.Unlock()
			if accepted > 0 {
				data := append([]byte(nil), buffer[:accepted]...)
				supervisor.publish(record, ProcessEvent{Type: eventType, Data: data})
			}
			if accepted < int64(count) {
				_ = supervisor.terminate(record, ExitReasonOutputLimit, SignalKill)
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				supervisor.publish(record, ProcessEvent{Type: EventError, Error: err.Error()})
			}
			return
		}
	}
}

func (supervisor *Supervisor) terminate(
	record *processRecord,
	reason ExitReason,
	signal ProcessSignal,
) error {
	record.controlMu.Lock()
	defer record.controlMu.Unlock()

	record.mu.Lock()
	if record.terminal {
		record.mu.Unlock()
		return ErrProcessExited
	}
	previousReason := record.terminationReason
	previousSignal := record.terminationSignal
	if reason != "" {
		priority := func(value ExitReason) int {
			switch value {
			case ExitReasonFenced:
				return 5
			case ExitReasonOutputLimit:
				return 4
			case ExitReasonDeadline:
				return 3
			case ExitReasonCanceled:
				return 2
			default:
				return 0
			}
		}
		if priority(reason) >= priority(previousReason) {
			record.terminationReason = reason
			record.terminationSignal = signal
		}
	}
	record.mu.Unlock()

	if err := record.running.SignalGroup(signal); err != nil {
		record.mu.Lock()
		if !record.terminal {
			record.terminationReason = previousReason
			record.terminationSignal = previousSignal
		}
		record.mu.Unlock()
		return err
	}
	return nil
}

func (supervisor *Supervisor) publish(record *processRecord, event ProcessEvent) {
	record.mu.Lock()
	supervisor.publishLocked(record, event)
	record.mu.Unlock()
}

func (supervisor *Supervisor) publishLocked(record *processRecord, event ProcessEvent) {
	record.nextSequence++
	event.Sequence = record.nextSequence
	event = cloneProcessEvent(event)
	record.replay = append(record.replay, event)
	record.replayBytes += len(event.Data)
	for len(record.replay) > supervisor.replayLimitEvents ||
		record.replayBytes > supervisor.replayLimitBytes {
		record.replayBytes -= len(record.replay[0].Data)
		record.replay = record.replay[1:]
	}
	for _, subscriber := range record.subscribers {
		select {
		case subscriber.events <- cloneProcessEvent(event):
		default:
			supervisor.finishSubscriber(record, subscriber, ErrOutputBackpressure)
		}
	}
	if event.Type == EventExit {
		for _, subscriber := range record.subscribers {
			supervisor.finishSubscriber(record, subscriber, nil)
		}
	}
}

func cloneProcessEvent(event ProcessEvent) ProcessEvent {
	event.Data = append([]byte(nil), event.Data...)
	return event
}

func (supervisor *Supervisor) finishSubscriber(
	record *processRecord,
	subscriber *eventSubscriber,
	err error,
) {
	if subscriber.finished {
		return
	}
	subscriber.finished = true
	delete(record.subscribers, subscriber.id)
	close(subscriber.events)
	if err != nil {
		subscriber.done <- err
	}
	close(subscriber.done)
}
