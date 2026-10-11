//go:build linux

// Package fixture contains the fixed, side-effect-bounded in-jail qualification
// command. It emits raw observations, never a PASS or production claim.
package fixture

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var NamespaceNames = []string{"user", "mnt", "pid", "ipc", "uts", "net"}
var HiddenPaths = []string{"/home", "/root", "/var/lib/pi-platform", "/var/run/docker.sock", "/dev/kvm"}

type Observation struct {
	SchemaVersion    int               `json:"schemaVersion"`
	RunID            string            `json:"runId"`
	Namespaces       map[string]string `json:"namespaces"`
	UIDMap           string            `json:"uidMap"`
	GIDMap           string            `json:"gidMap"`
	Status           map[string]string `json:"status"`
	RootMountFlags   uint64            `json:"rootMountFlags"`
	WriteErrnos      map[string]int    `json:"writeErrnos"`
	HiddenPathErrnos map[string]int    `json:"hiddenPathErrnos"`
	Interfaces       []string          `json:"interfaces"`
	NetworkErrno     int               `json:"networkErrno"`
	ControlErrno     int               `json:"controlErrno"`
}
type ChildObservation struct {
	SchemaVersion int    `json:"schemaVersion"`
	RunID         string `json:"runId"`
	PID           int    `json:"pid"`
	StartTime     string `json:"startTime"`
}

func validRunID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 16 && s == hex.EncodeToString(b)
}
func errorNumber(err error) int {
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return int(errno)
	}
	return -1
}
func limitedRead(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil || len(b) > 16384 {
		return "", errors.New("observation exceeds bound")
	}
	return string(b), nil
}
func processStartTime(pid int) (string, error) {
	s, e := limitedRead(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return "", e
	}
	i := strings.LastIndex(s, ") ")
	if i < 0 {
		return "", errors.New("invalid process stat")
	}
	fields := strings.Fields(s[i+2:])
	if len(fields) < 20 {
		return "", errors.New("short process stat")
	}
	return fields[19], nil
}

// Observe is called only in the provisioned jail. Unit tests do not call it on
// the host: its fixed writes and network socket observation belong to that jail.
func Observe(runID string) (Observation, error) {
	o := Observation{SchemaVersion: 1, RunID: runID, Namespaces: map[string]string{}, Status: map[string]string{}, WriteErrnos: map[string]int{}, HiddenPathErrnos: map[string]int{}, Interfaces: []string{}}
	if !validRunID(runID) {
		return o, errors.New("invalid run identity")
	}
	for _, name := range NamespaceNames {
		value, e := os.Readlink("/proc/self/ns/" + name)
		if e != nil {
			return o, e
		}
		o.Namespaces[name] = value
	}
	var err error
	if o.UIDMap, err = limitedRead("/proc/self/uid_map"); err != nil {
		return o, err
	}
	if o.GIDMap, err = limitedRead("/proc/self/gid_map"); err != nil {
		return o, err
	}
	status, err := limitedRead("/proc/self/status")
	if err != nil {
		return o, err
	}
	scanner := bufio.NewScanner(strings.NewReader(status))
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 2)
		if len(parts) == 2 {
			switch parts[0] {
			case "NoNewPrivs", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "Seccomp":
				o.Status[parts[0]] = strings.TrimSpace(parts[1])
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return o, err
	}
	var fs unix.Statfs_t
	if err := unix.Statfs("/", &fs); err != nil {
		return o, err
	}
	o.RootMountFlags = uint64(fs.Flags)
	for _, directory := range []string{"/", "/workspace", "/scratch", "/tmp"} {
		path := filepath.Join(directory, "qualification-"+runID)
		err := os.WriteFile(path, []byte(runID), 0o600)
		o.WriteErrnos[directory] = errorNumber(err)
		if err == nil && directory != "/workspace" {
			if err := os.Remove(path); err != nil {
				return o, err
			}
		}
	}
	for _, path := range HiddenPaths {
		_, err := os.Lstat(path)
		o.HiddenPathErrnos[path] = errorNumber(err)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return o, err
	}
	for _, iface := range interfaces {
		o.Interfaces = append(o.Interfaces, iface.Name)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return o, err
	}
	// UDP connect selects a route without transmitting a packet.
	err = unix.Connect(fd, &unix.SockaddrInet4{Port: 9, Addr: [4]byte{192, 0, 2, 1}})
	o.NetworkErrno = errorNumber(err)
	_ = unix.Close(fd)
	conn, err := net.DialTimeout("unix", "/run/circulusd/control/rpc.sock", time.Second)
	o.ControlErrno = errorNumber(err)
	if conn != nil {
		_ = conn.Close()
	}
	return o, nil
}

// Main recognizes a closed command set. hold/leaf exercise cancellation of a
// real child process; inspect binds PID reuse to the originally observed tick.
func Main(args []string, out io.Writer) error {
	if len(args) < 2 || !validRunID(args[1]) {
		return errors.New("usage: observe|hold|leaf|inspect RUN_ID [PID START_TIME]")
	}
	switch args[0] {
	case "seccomp", "cpu", "memory", "pids":
		if len(args) != 2 {
			return errors.New("unexpected experiment arguments")
		}
		return experiment(args[0], args[1], os.Stdin, out)
	case "observe":
		if len(args) != 2 {
			return errors.New("unexpected arguments")
		}
		o, e := Observe(args[1])
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(o)
	case "leaf":
		if len(args) != 2 {
			return errors.New("unexpected arguments")
		}
		for {
			time.Sleep(time.Hour)
		}
	case "hold":
		if len(args) != 2 {
			return errors.New("unexpected arguments")
		}
		executable, e := os.Executable()
		if e != nil {
			return e
		}
		child := exec.Command(executable, "leaf", args[1])
		child.Env = []string{}
		if e := child.Start(); e != nil {
			return e
		}
		defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
		start, e := processStartTime(child.Process.Pid)
		if e != nil {
			return e
		}
		if e := json.NewEncoder(out).Encode(ChildObservation{1, args[1], child.Process.Pid, start}); e != nil {
			return e
		}
		return child.Wait()
	case "inspect":
		if len(args) != 4 {
			return errors.New("inspect requires PID and start time")
		}
		pid, e := strconv.Atoi(args[2])
		if e != nil || pid < 2 {
			return errors.New("invalid child PID")
		}
		original, e := strconv.ParseUint(args[3], 10, 64)
		if e != nil || original == 0 {
			return errors.New("invalid child identity")
		}
		current, e := processStartTime(pid)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if e == nil && current == args[3] {
			return errors.New("original child remains after cancellation")
		}
		return json.NewEncoder(out).Encode(ChildObservation{1, args[1], pid, args[3]})
	default:
		return errors.New("unknown qualification command")
	}
}
