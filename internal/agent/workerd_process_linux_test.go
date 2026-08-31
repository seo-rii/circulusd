//go:build linux

package agent

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

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
