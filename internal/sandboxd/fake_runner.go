package sandboxd

import (
	"bytes"
	"context"
	"io"
	"sync"
	"sync/atomic"
)

// FakeRunner is a deterministic, process-free Runner for contract and race
// tests. Tests explicitly emit output and complete each started process.
type FakeRunner struct {
	starts  atomic.Int64
	started chan *FakeProcess
}

func NewFakeRunner() *FakeRunner {
	return &FakeRunner{started: make(chan *FakeProcess, 256)}
}

func (runner *FakeRunner) Start(ctx context.Context, spec RunSpec) (RunningProcess, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	runner.starts.Add(1)
	stdoutReader, stdoutWriter := io.Pipe()
	stderrReader, stderrWriter := io.Pipe()
	stdin := &fakeStdin{}
	process := &FakeProcess{
		spec:         spec,
		stdin:        stdin,
		stdoutReader: stdoutReader,
		stdoutWriter: stdoutWriter,
		stderrReader: stderrReader,
		stderrWriter: stderrWriter,
		result:       make(chan RunResult, 1),
	}
	select {
	case runner.started <- process:
		return process, nil
	case <-ctx.Done():
		process.Complete(RunResult{ExitCode: -1, Error: ctx.Err().Error()})
		return nil, ctx.Err()
	}
}

func (runner *FakeRunner) Started() <-chan *FakeProcess {
	return runner.started
}

func (runner *FakeRunner) StartCount() int64 {
	return runner.starts.Load()
}

// FakeProcess exposes deterministic test controls while implementing
// RunningProcess.
type FakeProcess struct {
	spec RunSpec

	stdin        *fakeStdin
	stdoutReader *io.PipeReader
	stdoutWriter *io.PipeWriter
	stderrReader *io.PipeReader
	stderrWriter *io.PipeWriter

	signalsMu sync.Mutex
	signals   []ProcessSignal

	completeOnce sync.Once
	result       chan RunResult
}

func (process *FakeProcess) Stdin() io.WriteCloser {
	return process.stdin
}

func (process *FakeProcess) Stdout() io.ReadCloser {
	return process.stdoutReader
}

func (process *FakeProcess) Stderr() io.ReadCloser {
	return process.stderrReader
}

func (process *FakeProcess) SignalGroup(signal ProcessSignal) error {
	process.signalsMu.Lock()
	process.signals = append(process.signals, signal)
	process.signalsMu.Unlock()
	if signal == SignalKill || signal == SignalCancel {
		process.Complete(RunResult{ExitCode: -1, Signal: signal})
	}
	return nil
}

func (process *FakeProcess) Wait() RunResult {
	return <-process.result
}

func (process *FakeProcess) EmitStdout(data []byte) error {
	_, err := process.stdoutWriter.Write(append([]byte(nil), data...))
	return err
}

func (process *FakeProcess) EmitStderr(data []byte) error {
	_, err := process.stderrWriter.Write(append([]byte(nil), data...))
	return err
}

func (process *FakeProcess) Complete(result RunResult) {
	process.completeOnce.Do(func() {
		_ = process.stdoutWriter.Close()
		_ = process.stderrWriter.Close()
		_ = process.stdin.Close()
		process.result <- result
		close(process.result)
	})
}

func (process *FakeProcess) StdinBytes() []byte {
	return process.stdin.Bytes()
}

func (process *FakeProcess) Signals() []ProcessSignal {
	process.signalsMu.Lock()
	defer process.signalsMu.Unlock()
	return append([]ProcessSignal(nil), process.signals...)
}

// Spec returns a defensive copy of the trusted resolved start spec.
func (process *FakeProcess) Spec() RunSpec {
	spec := process.spec
	spec.Arguments = append([]string(nil), spec.Arguments...)
	return spec
}

type fakeStdin struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	closed bool
}

func (stdin *fakeStdin) Write(data []byte) (int, error) {
	stdin.mu.Lock()
	defer stdin.mu.Unlock()
	if stdin.closed {
		return 0, io.ErrClosedPipe
	}
	return stdin.buffer.Write(data)
}

func (stdin *fakeStdin) Close() error {
	stdin.mu.Lock()
	stdin.closed = true
	stdin.mu.Unlock()
	return nil
}

func (stdin *fakeStdin) Bytes() []byte {
	stdin.mu.Lock()
	defer stdin.mu.Unlock()
	return append([]byte(nil), stdin.buffer.Bytes()...)
}

var _ Runner = (*FakeRunner)(nil)
var _ RunningProcess = (*FakeProcess)(nil)
