//go:build linux

package agent

import (
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCaptureWorkerdProcessIdentityOwnsPIDFDAndImmutableToken(t *testing.T) {
	reader := &fakeWorkerdProcessReader{stat: validWorkerdProcStat(77, "owned", 1234)}
	backend := &fakeWorkerdPIDFDBackend{openFD: 91}
	processIdentity, err := captureWorkerdProcessIdentity(reader, backend, 77)
	if err != nil {
		t.Fatalf("captureWorkerdProcessIdentity() error = %v", err)
	}
	if processIdentity == nil || processIdentity.token != (workerdProcessToken{PID: 77, StartTicks: 1234}) || processIdentity.pidfd != 91 {
		t.Fatalf("process identity = %#v", processIdentity)
	}
	reader.mu.Lock()
	reader.stat = validWorkerdProcStat(77, "mutated", 9999)
	reader.mu.Unlock()
	if processIdentity.token != (workerdProcessToken{PID: 77, StartTicks: 1234}) {
		t.Fatalf("owned token changed after reader mutation: %+v", processIdentity.token)
	}
	openPIDs, closeFDs := backend.calls()
	if len(openPIDs) != 1 || openPIDs[0] != 77 || len(closeFDs) != 0 {
		t.Fatalf("pidfd calls after capture = open %#v, close %#v", openPIDs, closeFDs)
	}
	if err := processIdentity.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
	if err := processIdentity.close(); err != nil {
		t.Fatalf("close(replay) error = %v", err)
	}
	_, closeFDs = backend.calls()
	if len(closeFDs) != 1 || closeFDs[0] != 91 {
		t.Fatalf("pidfd close calls = %#v, want [91]", closeFDs)
	}
}

func TestCaptureWorkerdProcessIdentityClassifiesOnlyPureENOSYSAsUnsupported(t *testing.T) {
	tests := map[string]struct {
		openErr         error
		wantUnsupported bool
	}{
		"enosys":                   {openErr: unix.ENOSYS, wantUnsupported: true},
		"wrapped enosys":           {openErr: fmt.Errorf("wrapped: %w", unix.ENOSYS), wantUnsupported: true},
		"joined enosys":            {openErr: errors.Join(unix.ENOSYS, unix.ENOSYS), wantUnsupported: true},
		"permission":               {openErr: unix.EPERM},
		"access":                   {openErr: unix.EACCES},
		"invalid":                  {openErr: unix.EINVAL},
		"stale":                    {openErr: unix.ESRCH},
		"mixed unsupported access": {openErr: errors.Join(unix.ENOSYS, unix.EACCES)},
		"mixed unsupported stale":  {openErr: errors.Join(unix.ENOSYS, unix.ESRCH)},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			reader := &fakeWorkerdProcessReader{stat: validWorkerdProcStat(77, "must-not-read", 1234)}
			backend := &fakeWorkerdPIDFDBackend{openErr: test.openErr}
			processIdentity, err := captureWorkerdProcessIdentity(reader, backend, 77)
			if processIdentity != nil || err == nil {
				t.Fatalf("captureWorkerdProcessIdentity() = %#v, %v, want nil error", processIdentity, err)
			}
			if errors.Is(err, errWorkerdPIDFDUnsupported) != test.wantUnsupported {
				t.Fatalf("unsupported classification for %v = %v, want %v", test.openErr, errors.Is(err, errWorkerdPIDFDUnsupported), test.wantUnsupported)
			}
			statCalls, _ := reader.calls()
			_, closeFDs := backend.calls()
			if len(statCalls) != 0 || len(closeFDs) != 0 {
				t.Fatalf("calls after pidfd open failure = stat %#v, close %#v", statCalls, closeFDs)
			}
		})
	}
}

func TestCaptureWorkerdProcessIdentityClosesPIDFDOnTokenFailureAndJoinsCloseError(t *testing.T) {
	readErr := errors.New("test: proc stat denied")
	closeErr := errors.New("test: pidfd close failed")
	reader := &fakeWorkerdProcessReader{err: readErr}
	backend := &fakeWorkerdPIDFDBackend{openFD: 92, closeErr: closeErr}
	processIdentity, err := captureWorkerdProcessIdentity(reader, backend, 77)
	if processIdentity != nil || !errors.Is(err, readErr) || !errors.Is(err, closeErr) {
		t.Fatalf("captureWorkerdProcessIdentity() = %#v, %v, want joined read/close failure", processIdentity, err)
	}
	openPIDs, closeFDs := backend.calls()
	if len(openPIDs) != 1 || len(closeFDs) != 1 || closeFDs[0] != 92 {
		t.Fatalf("pidfd calls = open %#v, close %#v", openPIDs, closeFDs)
	}
}

func TestWorkerdProcessIdentityCloseWaitsForSampleBorrowWithoutHoldingMutex(t *testing.T) {
	captureReader := &fakeWorkerdProcessReader{stat: validWorkerdProcStat(77, "borrowed", 1234)}
	backend := &fakeWorkerdPIDFDBackend{openFD: 93, closeEntered: make(chan struct{}, 1)}
	processIdentity, err := captureWorkerdProcessIdentity(captureReader, backend, 77)
	if err != nil {
		t.Fatalf("captureWorkerdProcessIdentity() error = %v", err)
	}
	sampleEntered := make(chan struct{}, 1)
	sampleGate := make(chan struct{})
	sampleReader := &fakeWorkerdProcessReader{
		snapshot: workerdProcessRawSnapshot{
			StatBefore: validWorkerdProcStat(77, "before", 1234),
			Statm:      "100 25 10 5 0 2 0\n",
			StatAfter:  validWorkerdProcStat(77, "after", 1234),
		},
		snapshotEntered: sampleEntered,
		snapshotGate:    sampleGate,
	}
	sampleResult := make(chan error, 1)
	go func() {
		_, sampleErr := processIdentity.sample(sampleReader, 4096)
		sampleResult <- sampleErr
	}()
	<-sampleEntered
	closeResult := make(chan error, 1)
	go func() { closeResult <- processIdentity.close() }()
	deadline := time.Now().Add(time.Second)
	for {
		processIdentity.mu.Lock()
		closing := processIdentity.closing
		processIdentity.mu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("close did not enter closing state")
		}
		runtime.Gosched()
	}
	if !processIdentity.mu.TryLock() {
		t.Fatal("process identity mutex held while close waited for a borrow")
	}
	processIdentity.mu.Unlock()
	if sample, sampleErr := processIdentity.sample(sampleReader, 4096); sample != (workerdProcessSample{}) || !errors.Is(sampleErr, errWorkerdProcessIdentityUnavailable) {
		t.Fatalf("sample(after closing) = %+v, %v, want unavailable", sample, sampleErr)
	}
	select {
	case <-backend.closeEntered:
		t.Fatal("pidfd close started before the sample borrow returned")
	default:
	}
	close(sampleGate)
	if sampleErr := <-sampleResult; sampleErr != nil {
		t.Fatalf("borrowed sample error = %v", sampleErr)
	}
	select {
	case <-backend.closeEntered:
	case <-time.After(time.Second):
		t.Fatal("pidfd close did not start after the final borrow returned")
	}
	if closeErr := <-closeResult; closeErr != nil {
		t.Fatalf("close() error = %v", closeErr)
	}
}

func TestWorkerdProcessIdentitySampleStillRejectsStartTicksChangeAroundRSS(t *testing.T) {
	for name, snapshot := range map[string]workerdProcessRawSnapshot{
		"before": {
			StatBefore: validWorkerdProcStat(77, "reused", 1235),
			Statm:      "100 25 10 5 0 2 0\n",
			StatAfter:  validWorkerdProcStat(77, "reused", 1235),
		},
		"after": {
			StatBefore: validWorkerdProcStat(77, "original", 1234),
			Statm:      "100 25 10 5 0 2 0\n",
			StatAfter:  validWorkerdProcStat(77, "reused", 1235),
		},
	} {
		t.Run(name, func(t *testing.T) {
			backend := &fakeWorkerdPIDFDBackend{openFD: 95}
			processIdentity, err := captureWorkerdProcessIdentity(&fakeWorkerdProcessReader{stat: validWorkerdProcStat(77, "captured", 1234)}, backend, 77)
			if err != nil {
				t.Fatalf("captureWorkerdProcessIdentity() error = %v", err)
			}
			sample, sampleErr := processIdentity.sample(&fakeWorkerdProcessReader{snapshot: snapshot}, 4096)
			if sample != (workerdProcessSample{}) || !errors.Is(sampleErr, errStaleWorkerdProcessIdentity) {
				t.Fatalf("sample(%s startTicks change) = %+v, %v, want stale identity", name, sample, sampleErr)
			}
			if closeErr := processIdentity.close(); closeErr != nil {
				t.Fatalf("close() error = %v", closeErr)
			}
		})
	}
}

func TestWorkerdProcessIdentityConcurrentCloseCachesTerminalErrorAndClosesOnce(t *testing.T) {
	closeErr := errors.New("test: terminal pidfd close failure")
	closeGate := make(chan struct{})
	backend := &fakeWorkerdPIDFDBackend{
		openFD: 94, closeErr: closeErr, closeEntered: make(chan struct{}, 1), closeGate: closeGate,
	}
	processIdentity, err := captureWorkerdProcessIdentity(&fakeWorkerdProcessReader{stat: validWorkerdProcStat(77, "closing", 1234)}, backend, 77)
	if err != nil {
		t.Fatalf("captureWorkerdProcessIdentity() error = %v", err)
	}
	lockObserved := make(chan bool, 1)
	backend.mu.Lock()
	backend.closeHook = func() {
		identityLockHeld := !processIdentity.mu.TryLock()
		if !identityLockHeld {
			processIdentity.mu.Unlock()
		}
		lockObserved <- identityLockHeld
	}
	backend.mu.Unlock()
	const callers = 32
	results := make(chan error, callers)
	go func() { results <- processIdentity.close() }()
	<-backend.closeEntered
	if <-lockObserved {
		t.Fatal("process identity mutex held across pidfd close syscall")
	}
	for caller := 1; caller < callers; caller++ {
		go func() { results <- processIdentity.close() }()
	}
	close(closeGate)
	var cachedErr error
	for range callers {
		currentErr := <-results
		if !errors.Is(currentErr, closeErr) || !errors.Is(currentErr, ErrTerminalShardCleanup) {
			t.Fatalf("close() error = %v, want marked terminal close failure", currentErr)
		}
		if cachedErr == nil {
			cachedErr = currentErr
		} else if currentErr != cachedErr {
			t.Fatalf("close() result = %p, want cached %p", currentErr, cachedErr)
		}
	}
	if replayErr := processIdentity.close(); replayErr != cachedErr {
		t.Fatalf("close(replay) error = %p, want cached %p", replayErr, cachedErr)
	}
	_, closeFDs := backend.calls()
	if len(closeFDs) != 1 || closeFDs[0] != 94 {
		t.Fatalf("pidfd close calls = %#v, want one close", closeFDs)
	}
}

func TestParseWorkerdProcStatHandlesSpacesAndParentheses(t *testing.T) {
	value := validWorkerdProcStat(42, "workerd pool ) (nested)", 987_654)
	token, err := parseWorkerdProcStat(value, 42)
	if err != nil {
		t.Fatalf("parseWorkerdProcStat() error = %v", err)
	}
	if token != (workerdProcessToken{PID: 42, StartTicks: 987_654}) {
		t.Fatalf("process token = %+v", token)
	}
}

func TestParseWorkerdProcStatRejectsMalformedOrOversizedInput(t *testing.T) {
	valid := validWorkerdProcStat(42, "workerd", 987_654)
	startToken := "987654"
	tests := map[string]string{
		"empty":               "",
		"zero pid":            strings.Replace(valid, "42 (", "0 (", 1),
		"wrong pid":           strings.Replace(valid, "42 (", "43 (", 1),
		"missing open":        strings.Replace(valid, "42 (", "42 ", 1),
		"missing close":       strings.Replace(valid, ") S ", " S ", 1),
		"missing fields":      "42 (workerd) S 1 2 3\n",
		"zero start":          strings.Replace(valid, startToken, "0", 1),
		"negative start":      strings.Replace(valid, startToken, "-1", 1),
		"plus start":          strings.Replace(valid, startToken, "+987654", 1),
		"leading-zero start":  strings.Replace(valid, startToken, "0987654", 1),
		"overflow start":      strings.Replace(valid, startToken, "18446744073709551616", 1),
		"double spacing":      strings.Replace(valid, ") S ", ") S  ", 1),
		"trailing whitespace": strings.TrimSuffix(valid, "\n") + " \n",
		"trailing field":      strings.TrimSuffix(valid, "\n") + " 1\n",
		"trailing newline":    valid + "\n",
		"trailing text":       strings.TrimSuffix(valid, "\n") + " text\n",
		"oversized":           strings.Repeat("1", maximumWorkerdProcStatBytes+1),
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if token, err := parseWorkerdProcStat(value, 42); token != (workerdProcessToken{}) || !errors.Is(err, errWorkerdProcessContract) {
				t.Fatalf("parseWorkerdProcStat(%q) = %+v, %v, want zero, contract error", value, token, err)
			}
		})
	}
	if token, err := parseWorkerdProcStat(valid, 0); token != (workerdProcessToken{}) || !errors.Is(err, errInvalidWorkerdProcessRequest) {
		t.Fatalf("parseWorkerdProcStat(zero expected PID) = %+v, %v, want invalid request", token, err)
	}
}

func TestParseWorkerdProcStatmRejectsInvalidRSSAndPageSize(t *testing.T) {
	rss, err := parseWorkerdProcStatm("100 25 10 5 0 2 0\n", 4096)
	if err != nil || rss != 102_400 {
		t.Fatalf("parseWorkerdProcStatm(valid) = %d, %v, want 102400", rss, err)
	}
	for name, test := range map[string]struct {
		value    string
		pageSize uint64
	}{
		"empty":               {value: "", pageSize: 4096},
		"negative rss":        {value: "100 -1 10 5 0 2 0\n", pageSize: 4096},
		"plus rss":            {value: "100 +1 10 5 0 2 0\n", pageSize: 4096},
		"leading-zero rss":    {value: "100 01 10 5 0 2 0\n", pageSize: 4096},
		"missing field":       {value: "100 25 10 5 0 2\n", pageSize: 4096},
		"extra field":         {value: "100 25 10 5 0 2 0 1\n", pageSize: 4096},
		"trailing whitespace": {value: "100 25 10 5 0 2 0 \n", pageSize: 4096},
		"trailing newline":    {value: "100 25 10 5 0 2 0\n\n", pageSize: 4096},
		"overflow rss":        {value: "100 18446744073709551616 10 5 0 2 0\n", pageSize: 4096},
		"multiply overflow":   {value: fmt.Sprintf("100 %d 10 5 0 2 0\n", uint64(math.MaxUint64/4096)+1), pageSize: 4096},
		"zero page size":      {value: "100 25 10 5 0 2 0\n", pageSize: 0},
		"non-power page size": {value: "100 25 10 5 0 2 0\n", pageSize: 4095},
		"excessive page size": {value: "100 25 10 5 0 2 0\n", pageSize: maximumWorkerdProcessPageSize * 2},
		"oversized":           {value: strings.Repeat("1", maximumWorkerdProcStatmBytes+1), pageSize: 4096},
	} {
		t.Run(name, func(t *testing.T) {
			if got, parseErr := parseWorkerdProcStatm(test.value, test.pageSize); got != 0 || !errors.Is(parseErr, errWorkerdProcessContract) {
				t.Fatalf("parseWorkerdProcStatm(%q, %d) = %d, %v, want zero, contract error", test.value, test.pageSize, got, parseErr)
			}
		})
	}
}

func TestCaptureAndSampleWorkerdProcessUseBoundedReaderAndImmutableIdentity(t *testing.T) {
	reader := &fakeWorkerdProcessReader{
		stat: validWorkerdProcStat(77, "capture", 1234),
		snapshot: workerdProcessRawSnapshot{
			StatBefore: validWorkerdProcStat(77, "sample before", 1234),
			Statm:      "100 25 10 5 0 2 0\n",
			StatAfter:  validWorkerdProcStat(77, "sample after", 1234),
		},
	}
	token, err := captureWorkerdProcessToken(reader, 77)
	if err != nil {
		t.Fatalf("captureWorkerdProcessToken() error = %v", err)
	}
	if token != (workerdProcessToken{PID: 77, StartTicks: 1234}) {
		t.Fatalf("captured token = %+v", token)
	}
	sample, err := sampleWorkerdProcess(reader, token, 4096)
	if err != nil {
		t.Fatalf("sampleWorkerdProcess() error = %v", err)
	}
	want := workerdProcessSample{PID: 77, StartTicks: 1234, RSSBytes: 102_400}
	if sample != want {
		t.Fatalf("process sample = %+v, want %+v", sample, want)
	}
	statLimits, snapshots := reader.calls()
	if len(statLimits) != 1 || statLimits[0] != maximumWorkerdProcStatBytes {
		t.Fatalf("stat read limits = %#v", statLimits)
	}
	if len(snapshots) != 1 || snapshots[0] != (fakeWorkerdSnapshotCall{StatLimit: maximumWorkerdProcStatBytes, StatmLimit: maximumWorkerdProcStatmBytes}) {
		t.Fatalf("snapshot calls = %#v", snapshots)
	}
	reader.mu.Lock()
	reader.snapshot.Statm = "100 1 10 5 0 2 0\n"
	reader.mu.Unlock()
	if sample != want {
		t.Fatalf("returned sample changed after reader mutation: %+v", sample)
	}
}

func TestSampleWorkerdProcessDistinguishesStaleStartIdentity(t *testing.T) {
	for name, snapshot := range map[string]workerdProcessRawSnapshot{
		"before": {
			StatBefore: validWorkerdProcStat(77, "reused", 1235),
			Statm:      "100 25 10 5 0 2 0\n",
			StatAfter:  validWorkerdProcStat(77, "reused", 1235),
		},
		"after": {
			StatBefore: validWorkerdProcStat(77, "original", 1234),
			Statm:      "100 25 10 5 0 2 0\n",
			StatAfter:  validWorkerdProcStat(77, "reused", 1235),
		},
	} {
		t.Run(name, func(t *testing.T) {
			reader := &fakeWorkerdProcessReader{snapshot: snapshot}
			sample, err := sampleWorkerdProcess(reader, workerdProcessToken{PID: 77, StartTicks: 1234}, 4096)
			if sample != (workerdProcessSample{}) || !errors.Is(err, errStaleWorkerdProcessIdentity) || errors.Is(err, errWorkerdProcessContract) {
				t.Fatalf("sampleWorkerdProcess(stale %s) = %+v, %v, want zero, stale-only error", name, sample, err)
			}
		})
	}
}

func TestSampleWorkerdProcessRejectsInvalidTokenBeforeReader(t *testing.T) {
	reader := &fakeWorkerdProcessReader{}
	for name, token := range map[string]workerdProcessToken{
		"zero pid":   {StartTicks: 1},
		"zero start": {PID: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if sample, err := sampleWorkerdProcess(reader, token, 4096); sample != (workerdProcessSample{}) || !errors.Is(err, errInvalidWorkerdProcessRequest) {
				t.Fatalf("sampleWorkerdProcess(%+v) = %+v, %v, want invalid request", token, sample, err)
			}
		})
	}
	if statCalls, snapshotCalls := reader.calls(); len(statCalls) != 0 || len(snapshotCalls) != 0 {
		t.Fatalf("reader calls for invalid token = %#v/%#v", statCalls, snapshotCalls)
	}
}

func TestSampleWorkerdProcessDoesNotSerializeReaderIO(t *testing.T) {
	entered := make(chan struct{}, 2)
	gate := make(chan struct{})
	reader := &fakeWorkerdProcessReader{
		snapshot: workerdProcessRawSnapshot{
			StatBefore: validWorkerdProcStat(77, "parallel", 1234),
			Statm:      "100 25 10 5 0 2 0\n",
			StatAfter:  validWorkerdProcStat(77, "parallel", 1234),
		},
		snapshotEntered: entered,
		snapshotGate:    gate,
	}
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := sampleWorkerdProcess(reader, workerdProcessToken{PID: 77, StartTicks: 1234}, 4096)
			results <- err
		}()
	}
	for index := 0; index < 2; index++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("reader I/O was serialized or blocked before entry")
		}
	}
	close(gate)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("sampleWorkerdProcess() error = %v", err)
		}
	}
}

func TestLinuxWorkerdProcessReaderSamplesCurrentProcess(t *testing.T) {
	reader := linuxWorkerdProcessReader{}
	pid := os.Getpid()
	token, err := captureWorkerdProcessToken(reader, pid)
	if err != nil {
		t.Fatalf("capture current process token: %v", err)
	}
	sample, err := sampleWorkerdProcess(reader, token, uint64(os.Getpagesize()))
	if err != nil {
		t.Fatalf("sample current process: %v", err)
	}
	if sample.PID != pid || sample.StartTicks != token.StartTicks {
		t.Fatalf("current process sample = %+v, token = %+v", sample, token)
	}
}

func validWorkerdProcStat(pid int, comm string, startTicks uint64) string {
	fields := make([]string, 49)
	for index := range fields {
		fields[index] = "0"
	}
	fields[0] = "1"
	fields[18] = strconv.FormatUint(startTicks, 10)
	return fmt.Sprintf("%d (%s) S %s\n", pid, comm, strings.Join(fields, " "))
}

type fakeWorkerdSnapshotCall struct {
	StatLimit  int
	StatmLimit int
}

type fakeWorkerdProcessReader struct {
	mu sync.Mutex

	stat            string
	snapshot        workerdProcessRawSnapshot
	err             error
	statLimits      []int
	snapshotCalls   []fakeWorkerdSnapshotCall
	snapshotEntered chan<- struct{}
	snapshotGate    <-chan struct{}
}

type fakeWorkerdPIDFDBackend struct {
	mu sync.Mutex

	openFD       int
	openErr      error
	closeErr     error
	closeHook    func()
	openPIDs     []int
	closeFDs     []int
	closeEntered chan struct{}
	closeGate    <-chan struct{}
}

func (backend *fakeWorkerdPIDFDBackend) openPIDFD(pid int) (int, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.openPIDs = append(backend.openPIDs, pid)
	return backend.openFD, backend.openErr
}

func (backend *fakeWorkerdPIDFDBackend) closeFD(fd int) error {
	backend.mu.Lock()
	backend.closeFDs = append(backend.closeFDs, fd)
	closeErr := backend.closeErr
	closeHook := backend.closeHook
	entered := backend.closeEntered
	gate := backend.closeGate
	backend.mu.Unlock()
	if closeHook != nil {
		closeHook()
	}
	if entered != nil {
		entered <- struct{}{}
	}
	if gate != nil {
		<-gate
	}
	return closeErr
}

func (backend *fakeWorkerdPIDFDBackend) calls() ([]int, []int) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return append([]int(nil), backend.openPIDs...), append([]int(nil), backend.closeFDs...)
}

func (reader *fakeWorkerdProcessReader) readStat(_ int, maximumBytes int) (string, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.statLimits = append(reader.statLimits, maximumBytes)
	return reader.stat, reader.err
}

func (reader *fakeWorkerdProcessReader) readSnapshot(_ int, statMaximumBytes int, statmMaximumBytes int) (workerdProcessRawSnapshot, error) {
	reader.mu.Lock()
	reader.snapshotCalls = append(reader.snapshotCalls, fakeWorkerdSnapshotCall{StatLimit: statMaximumBytes, StatmLimit: statmMaximumBytes})
	snapshot := reader.snapshot
	err := reader.err
	entered := reader.snapshotEntered
	gate := reader.snapshotGate
	reader.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
	}
	if gate != nil {
		<-gate
	}
	return snapshot, err
}

func (reader *fakeWorkerdProcessReader) calls() ([]int, []fakeWorkerdSnapshotCall) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return append([]int(nil), reader.statLimits...), append([]fakeWorkerdSnapshotCall(nil), reader.snapshotCalls...)
}
