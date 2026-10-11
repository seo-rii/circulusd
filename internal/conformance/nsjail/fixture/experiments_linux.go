//go:build linux

package fixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// ExperimentDescriptor is signed as part of the dedicated environment
// inventory. Only this exact bounded experiment suite is implemented. These
// values are not general workload policy knobs.
type ExperimentDescriptor struct {
	Version              uint32 `json:"version"`
	SeccompSyscall       string `json:"seccompSyscall"`
	SeccompErrno         int    `json:"seccompErrno"`
	CPUMillis            uint64 `json:"cpuMillis"`
	MemoryBytes          uint64 `json:"memoryBytes"`
	PIDsAttempts         uint64 `json:"pidsAttempts"`
	AddressSpaceBytes    uint64 `json:"addressSpaceBytes"`
	MaximumUserProcesses uint64 `json:"maximumUserProcesses"`
}

func RequiredExperiments() ExperimentDescriptor {
	return ExperimentDescriptor{Version: 1, SeccompSyscall: "getppid", SeccompErrno: int(unix.EPERM), CPUMillis: 3000, MemoryBytes: 768 << 20, PIDsAttempts: 128, AddressSpaceBytes: 4 << 30, MaximumUserProcesses: 512}
}

type ExperimentRecord struct {
	SchemaVersion int    `json:"schemaVersion"`
	RunID         string `json:"runId"`
	Kind          string `json:"kind"`
	Phase         string `json:"phase"`
	Attempts      uint64 `json:"attempts"`
	WorkUnits     uint64 `json:"workUnits"`
	ElapsedMillis uint64 `json:"elapsedMillis"`
	BytesTouched  uint64 `json:"bytesTouched"`
	SyscallResult int64  `json:"syscallResult"`
	Errno         int    `json:"errno"`
}

// experiment runs only after a ready/GO exchange on sandboxd's authenticated
// process stream. The host snapshots the owned cgroup and verifies its hard
// limits before sending GO. Merely invoking the helper cannot start pressure.
func experiment(kind, run string, in io.Reader, out io.Writer) (returnErr error) {
	if !validRunID(run) {
		return errors.New("invalid experiment identity")
	}
	switch kind {
	case "seccomp", "cpu", "memory", "pids":
	default:
		return errors.New("unknown experiment")
	}
	if err := requireExperimentJail(); err != nil {
		return err
	}
	record := ExperimentRecord{SchemaVersion: 1, RunID: run, Kind: kind, Phase: "ready"}
	if err := json.NewEncoder(out).Encode(record); err != nil {
		return err
	}
	trigger, err := io.ReadAll(io.LimitReader(in, 3))
	if err != nil || !bytes.Equal(trigger, []byte("GO")) {
		return errors.New("experiment requires the exact bounded host trigger")
	}
	descriptor := RequiredExperiments()
	started := time.Now()
	record.Phase = "done"
	switch kind {
	case "seccomp":
		value, _, errno := unix.RawSyscall(unix.SYS_GETPPID, 0, 0, 0)
		record.Attempts = 1
		record.SyscallResult = int64(value)
		record.Errno = int(errno)
	case "cpu":
		deadline := started.Add(time.Duration(descriptor.CPUMillis) * time.Millisecond)
		var block [1024]byte
		var result [32]byte
		for time.Now().Before(deadline) {
			block[0]++
			result = sha256.Sum256(block[:])
			record.WorkUnits++
		}
		runtime.KeepAlive(result)
	case "memory":
		mappings := [][]byte{}
		defer func() {
			for _, memory := range mappings {
				returnErr = errors.Join(returnErr, unix.Munmap(memory))
			}
		}()
		const chunk = 4 << 20
		for record.BytesTouched < descriptor.MemoryBytes {
			record.Attempts++
			memory, err := unix.Mmap(-1, 0, chunk, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
			if err != nil {
				record.Errno = errorNumber(err)
				break
			}
			mappings = append(mappings, memory)
			for i := 0; i < len(memory); i += 4096 {
				memory[i] = 1
			}
			record.BytesTouched += chunk
		}
		runtime.KeepAlive(mappings)
	case "pids":
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		children := []*exec.Cmd{}
		defer func() {
			for _, child := range children {
				if err := child.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
					returnErr = errors.Join(returnErr, err)
				}
			}
			for _, child := range children {
				if err := child.Wait(); err != nil {
					var exited *exec.ExitError
					if !errors.As(err, &exited) {
						returnErr = errors.Join(returnErr, err)
					}
				}
			}
		}()
		for record.Attempts < descriptor.PIDsAttempts {
			record.Attempts++
			child := exec.Command(executable, "leaf", run)
			child.Env = []string{}
			if err := child.Start(); err != nil {
				record.Errno = errorNumber(err)
				break
			}
			children = append(children, child)
			record.WorkUnits++
		}
	}
	record.ElapsedMillis = uint64(time.Since(started) / time.Millisecond)
	return json.NewEncoder(out).Encode(record)
}

// A malformed launch must fail before pressure, even if an operator invokes a
// fixture command incorrectly. This is additional defense, not qualification
// evidence: the host independently checks namespace and cgroup observations.
func requireExperimentJail() error {
	mapping, err := limitedRead("/proc/self/uid_map")
	if err != nil {
		return err
	}
	fields := strings.Fields(mapping)
	if len(fields) != 3 || fields[0] != "0" || fields[2] != "1" || os.Geteuid() != 0 {
		return errors.New("pressure helper requires a mapped jail UID")
	}
	outside, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil || outside == 0 {
		return errors.New("pressure helper requires an unprivileged host UID")
	}
	status, err := limitedRead("/proc/self/status")
	if err != nil {
		return err
	}
	noNewPrivs := false
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "NoNewPrivs:" && fields[1] == "1" {
			noNewPrivs = true
		}
	}
	var root unix.Statfs_t
	if err := unix.Statfs("/", &root); err != nil || root.Flags&unix.ST_RDONLY == 0 || !noNewPrivs {
		return errors.New("pressure helper requires a read-only jail and no_new_privs")
	}
	return nil
}
