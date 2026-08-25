package sandboxd

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"syscall"
)

// NewDevelopmentExecRunner returns the local os/exec implementation. It is a
// development adapter, not a replacement for NsJail, Docker, or Firecracker.
func NewDevelopmentExecRunner() Runner {
	return developmentExecRunner{}
}

type developmentExecRunner struct{}

func (developmentExecRunner) Start(ctx context.Context, spec RunSpec) (RunningProcess, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	command := exec.Command(spec.ExecutablePath, spec.Arguments...)
	command.Dir = spec.WorkingDirectory
	command.Env = []string{}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, err
	}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, err
	}
	return &developmentExecProcess{
		command: command,
		stdin:   stdin,
		stdout:  stdout,
		stderr:  stderr,
	}, nil
}

type developmentExecProcess struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	stderr  io.ReadCloser
}

func (process *developmentExecProcess) Stdin() io.WriteCloser {
	return process.stdin
}

func (process *developmentExecProcess) Stdout() io.ReadCloser {
	return process.stdout
}

func (process *developmentExecProcess) Stderr() io.ReadCloser {
	return process.stderr
}

func (process *developmentExecProcess) SignalGroup(signal ProcessSignal) error {
	var osSignal syscall.Signal
	switch signal {
	case SignalInterrupt:
		osSignal = syscall.SIGINT
	case SignalTerminate:
		osSignal = syscall.SIGTERM
	case SignalKill, SignalCancel:
		osSignal = syscall.SIGKILL
	default:
		return ErrInvalidSignal
	}
	err := syscall.Kill(-process.command.Process.Pid, osSignal)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func (process *developmentExecProcess) Wait() RunResult {
	err := process.command.Wait()
	result := RunResult{ExitCode: process.command.ProcessState.ExitCode()}
	if err == nil {
		return result
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		result.Error = err.Error()
		return result
	}
	status, ok := exitError.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() {
		return result
	}
	switch status.Signal() {
	case syscall.SIGINT:
		result.Signal = SignalInterrupt
	case syscall.SIGTERM:
		result.Signal = SignalTerminate
	default:
		result.Signal = SignalKill
	}
	return result
}

var _ Runner = developmentExecRunner{}
var _ RunningProcess = (*developmentExecProcess)(nil)
