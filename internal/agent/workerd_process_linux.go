//go:build linux

package agent

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maximumWorkerdProcStatBytes       = 4096
	maximumWorkerdProcStatmBytes      = 256
	maximumWorkerdProcessPageSize     = uint64(1 << 30)
	workerdProcStatNumericFieldCount  = 49
	workerdProcStatStartTicksField    = 18
	workerdProcStatmResidentPageField = 1
)

var (
	errWorkerdProcessContract       = errors.New("workerd process contract violation")
	errInvalidWorkerdProcessRequest = errors.New("invalid workerd process request")
	errStaleWorkerdProcessIdentity  = errors.New("stale workerd process identity")
)

type workerdProcessToken struct {
	PID        int
	StartTicks uint64
}

type workerdProcessSample struct {
	PID        int
	StartTicks uint64
	RSSBytes   uint64
}

type workerdProcessRawSnapshot struct {
	StatBefore string
	Statm      string
	StatAfter  string
}

type workerdProcessReader interface {
	readStat(pid int, maximumBytes int) (string, error)
	readSnapshot(pid int, statMaximumBytes int, statmMaximumBytes int) (workerdProcessRawSnapshot, error)
}

type linuxWorkerdProcessReader struct{}

func parseWorkerdProcStat(value string, expectedPID int) (workerdProcessToken, error) {
	if expectedPID <= 0 {
		return workerdProcessToken{}, fmt.Errorf("%w: PID must be positive", errInvalidWorkerdProcessRequest)
	}
	payload, err := canonicalWorkerdProcPayload(value, maximumWorkerdProcStatBytes)
	if err != nil {
		return workerdProcessToken{}, err
	}
	prefix := strconv.Itoa(expectedPID) + " ("
	if !strings.HasPrefix(payload, prefix) {
		return workerdProcessToken{}, fmt.Errorf("%w: unexpected stat PID", errWorkerdProcessContract)
	}
	closing := strings.LastIndex(payload, ") ")
	if closing < len(prefix) {
		return workerdProcessToken{}, fmt.Errorf("%w: malformed stat comm", errWorkerdProcessContract)
	}
	remainder := payload[closing+2:]
	if len(remainder) < 3 || remainder[1] != ' ' || !strings.ContainsRune("RSDZTtXxKWPI", rune(remainder[0])) {
		return workerdProcessToken{}, fmt.Errorf("%w: malformed stat state", errWorkerdProcessContract)
	}
	fields := strings.Split(remainder[2:], " ")
	if len(fields) != workerdProcStatNumericFieldCount {
		return workerdProcessToken{}, fmt.Errorf("%w: unexpected stat field count", errWorkerdProcessContract)
	}
	for index, field := range fields {
		signed := false
		switch index {
		case 0, 1, 2, 3, 4, 12, 13, 14, 15, 16, 17, 20, 34, 35, 40, 48:
			signed = true
		}
		if signed {
			if field == "" || field[0] == '+' || (len(field) > 1 && field[0] == '0') || field == "-0" {
				return workerdProcessToken{}, fmt.Errorf("%w: malformed stat field %d", errWorkerdProcessContract, index+4)
			}
			if field[0] == '-' {
				if len(field) == 1 || (len(field) > 2 && field[1] == '0') {
					return workerdProcessToken{}, fmt.Errorf("%w: malformed stat field %d", errWorkerdProcessContract, index+4)
				}
				for digitIndex := 1; digitIndex < len(field); digitIndex++ {
					if field[digitIndex] < '0' || field[digitIndex] > '9' {
						return workerdProcessToken{}, fmt.Errorf("%w: malformed stat field %d", errWorkerdProcessContract, index+4)
					}
				}
			} else {
				for digitIndex := range len(field) {
					if field[digitIndex] < '0' || field[digitIndex] > '9' {
						return workerdProcessToken{}, fmt.Errorf("%w: malformed stat field %d", errWorkerdProcessContract, index+4)
					}
				}
			}
			parsed, parseErr := strconv.ParseInt(field, 10, 64)
			if parseErr != nil || strconv.FormatInt(parsed, 10) != field {
				return workerdProcessToken{}, fmt.Errorf("%w: malformed stat field %d", errWorkerdProcessContract, index+4)
			}
			continue
		}
		if _, parseErr := parseCanonicalWorkerdUnsigned(field); parseErr != nil {
			return workerdProcessToken{}, fmt.Errorf("%w: malformed stat field %d", errWorkerdProcessContract, index+4)
		}
	}
	startTicks, err := parseCanonicalWorkerdUnsigned(fields[workerdProcStatStartTicksField])
	if err != nil || startTicks == 0 {
		return workerdProcessToken{}, fmt.Errorf("%w: invalid stat starttime", errWorkerdProcessContract)
	}
	return workerdProcessToken{PID: expectedPID, StartTicks: startTicks}, nil
}

func parseWorkerdProcStatm(value string, pageSize uint64) (uint64, error) {
	if pageSize == 0 || pageSize > maximumWorkerdProcessPageSize || pageSize&(pageSize-1) != 0 {
		return 0, fmt.Errorf("%w: invalid page size", errWorkerdProcessContract)
	}
	payload, err := canonicalWorkerdProcPayload(value, maximumWorkerdProcStatmBytes)
	if err != nil {
		return 0, err
	}
	fields := strings.Split(payload, " ")
	if len(fields) != 7 {
		return 0, fmt.Errorf("%w: unexpected statm field count", errWorkerdProcessContract)
	}
	var residentPages uint64
	for index, field := range fields {
		parsed, parseErr := parseCanonicalWorkerdUnsigned(field)
		if parseErr != nil {
			return 0, fmt.Errorf("%w: malformed statm field %d", errWorkerdProcessContract, index+1)
		}
		if index == workerdProcStatmResidentPageField {
			residentPages = parsed
		}
	}
	if residentPages > math.MaxUint64/pageSize {
		return 0, fmt.Errorf("%w: statm RSS overflow", errWorkerdProcessContract)
	}
	return residentPages * pageSize, nil
}

func captureWorkerdProcessToken(reader workerdProcessReader, pid int) (workerdProcessToken, error) {
	if reader == nil || pid <= 0 {
		return workerdProcessToken{}, fmt.Errorf("%w: reader and positive PID are required", errInvalidWorkerdProcessRequest)
	}
	stat, err := reader.readStat(pid, maximumWorkerdProcStatBytes)
	if err != nil {
		return workerdProcessToken{}, fmt.Errorf("read workerd process identity: %w", err)
	}
	return parseWorkerdProcStat(stat, pid)
}

func sampleWorkerdProcess(reader workerdProcessReader, token workerdProcessToken, pageSize uint64) (workerdProcessSample, error) {
	if reader == nil || token.PID <= 0 || token.StartTicks == 0 {
		return workerdProcessSample{}, fmt.Errorf("%w: reader and process token are required", errInvalidWorkerdProcessRequest)
	}
	if pageSize == 0 || pageSize > maximumWorkerdProcessPageSize || pageSize&(pageSize-1) != 0 {
		return workerdProcessSample{}, fmt.Errorf("%w: invalid page size", errInvalidWorkerdProcessRequest)
	}
	snapshot, err := reader.readSnapshot(token.PID, maximumWorkerdProcStatBytes, maximumWorkerdProcStatmBytes)
	if err != nil {
		return workerdProcessSample{}, fmt.Errorf("read workerd process snapshot: %w", err)
	}
	before, err := parseWorkerdProcStat(snapshot.StatBefore, token.PID)
	if err != nil {
		return workerdProcessSample{}, err
	}
	if before.StartTicks != token.StartTicks {
		return workerdProcessSample{}, fmt.Errorf("%w: expected starttime %d, observed %d before RSS read", errStaleWorkerdProcessIdentity, token.StartTicks, before.StartTicks)
	}
	rssBytes, err := parseWorkerdProcStatm(snapshot.Statm, pageSize)
	if err != nil {
		return workerdProcessSample{}, err
	}
	after, err := parseWorkerdProcStat(snapshot.StatAfter, token.PID)
	if err != nil {
		return workerdProcessSample{}, err
	}
	if after.StartTicks != token.StartTicks {
		return workerdProcessSample{}, fmt.Errorf("%w: expected starttime %d, observed %d after RSS read", errStaleWorkerdProcessIdentity, token.StartTicks, after.StartTicks)
	}
	return workerdProcessSample{PID: token.PID, StartTicks: token.StartTicks, RSSBytes: rssBytes}, nil
}

func (linuxWorkerdProcessReader) readStat(pid int, maximumBytes int) (string, error) {
	processFD, err := openWorkerdProcessDirectory(pid)
	if err != nil {
		return "", err
	}
	value, readErr := readBoundedWorkerdProcFileAt(processFD, "stat", maximumBytes)
	closeErr := unix.Close(processFD)
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return value, nil
}

func (linuxWorkerdProcessReader) readSnapshot(pid int, statMaximumBytes int, statmMaximumBytes int) (workerdProcessRawSnapshot, error) {
	processFD, err := openWorkerdProcessDirectory(pid)
	if err != nil {
		return workerdProcessRawSnapshot{}, err
	}
	statBefore, readErr := readBoundedWorkerdProcFileAt(processFD, "stat", statMaximumBytes)
	if readErr == nil {
		var statm string
		statm, readErr = readBoundedWorkerdProcFileAt(processFD, "statm", statmMaximumBytes)
		if readErr == nil {
			var statAfter string
			statAfter, readErr = readBoundedWorkerdProcFileAt(processFD, "stat", statMaximumBytes)
			if readErr == nil {
				closeErr := unix.Close(processFD)
				if closeErr != nil {
					return workerdProcessRawSnapshot{}, closeErr
				}
				return workerdProcessRawSnapshot{StatBefore: statBefore, Statm: statm, StatAfter: statAfter}, nil
			}
		}
	}
	closeErr := unix.Close(processFD)
	if readErr != nil {
		return workerdProcessRawSnapshot{}, readErr
	}
	return workerdProcessRawSnapshot{}, closeErr
}

func canonicalWorkerdProcPayload(value string, maximumBytes int) (string, error) {
	if maximumBytes < 1 || len(value) == 0 || len(value) > maximumBytes {
		return "", fmt.Errorf("%w: empty or oversized proc value", errWorkerdProcessContract)
	}
	if value[len(value)-1] != '\n' {
		return "", fmt.Errorf("%w: missing proc line terminator", errWorkerdProcessContract)
	}
	payload := value[:len(value)-1]
	if payload == "" || strings.ContainsAny(payload, "\x00\r\n") {
		return "", fmt.Errorf("%w: malformed proc line", errWorkerdProcessContract)
	}
	return payload, nil
}

func parseCanonicalWorkerdUnsigned(value string) (uint64, error) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, errWorkerdProcessContract
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return 0, errWorkerdProcessContract
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, errWorkerdProcessContract
	}
	return parsed, nil
}

func openWorkerdProcessDirectory(pid int) (int, error) {
	if pid <= 0 {
		return -1, fmt.Errorf("%w: PID must be positive", errInvalidWorkerdProcessRequest)
	}
	procFD, err := unix.Open("/proc", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(procFD, &filesystem); err != nil {
		_ = unix.Close(procFD)
		return -1, err
	}
	if filesystem.Type != unix.PROC_SUPER_MAGIC {
		_ = unix.Close(procFD)
		return -1, fmt.Errorf("%w: /proc filesystem identity", errWorkerdProcessContract)
	}
	processFD, openErr := unix.Openat2(procFD, strconv.Itoa(pid), &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS),
	})
	closeErr := unix.Close(procFD)
	if openErr != nil {
		return -1, openErr
	}
	if closeErr != nil {
		_ = unix.Close(processFD)
		return -1, closeErr
	}
	var stat unix.Stat_t
	if err := unix.Fstat(processFD, &stat); err != nil {
		_ = unix.Close(processFD)
		return -1, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = unix.Close(processFD)
		return -1, fmt.Errorf("%w: process directory type", errWorkerdProcessContract)
	}
	if err := unix.Fstatfs(processFD, &filesystem); err != nil {
		_ = unix.Close(processFD)
		return -1, err
	}
	if filesystem.Type != unix.PROC_SUPER_MAGIC {
		_ = unix.Close(processFD)
		return -1, fmt.Errorf("%w: process directory filesystem identity", errWorkerdProcessContract)
	}
	return processFD, nil
}

func readBoundedWorkerdProcFileAt(processFD int, name string, maximumBytes int) (string, error) {
	if processFD < 0 || maximumBytes < 1 || maximumBytes > maximumWorkerdProcStatBytes || (name != "stat" && name != "statm") {
		return "", fmt.Errorf("%w: invalid bounded proc read", errInvalidWorkerdProcessRequest)
	}
	fd, err := unix.Openat2(processFD, name, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC),
		Resolve: uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS),
	})
	if err != nil {
		return "", err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return "", err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return "", fmt.Errorf("%w: proc entry type", errWorkerdProcessContract)
	}
	buffer := make([]byte, maximumBytes+1)
	offset := 0
	var readErr error
	for offset < len(buffer) {
		read, currentErr := unix.Read(fd, buffer[offset:])
		if currentErr != nil {
			if errors.Is(currentErr, unix.EINTR) {
				continue
			}
			readErr = currentErr
			break
		}
		if read == 0 {
			break
		}
		offset += read
	}
	closeErr := unix.Close(fd)
	if readErr != nil {
		return "", readErr
	}
	if offset > maximumBytes {
		return "", fmt.Errorf("%w: oversized proc value", errWorkerdProcessContract)
	}
	if closeErr != nil {
		return "", closeErr
	}
	return string(buffer[:offset]), nil
}
