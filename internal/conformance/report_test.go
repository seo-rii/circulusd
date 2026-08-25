package conformance

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestRequiredProfileAcceptsOnlyPass(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status Status
		reason string
		ok     bool
	}{
		{name: "pass", status: Pass, ok: true},
		{name: "fail", status: Fail},
		{name: "unavailable", status: Unavailable, reason: "binary missing"},
		{name: "not run", status: NotRun},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			collector := NewCollector()
			result := Result{Component: "nsjail", Status: test.status, Reason: test.reason}
			if err := collector.Add(result); err != nil {
				t.Fatalf("Add() error = %v", err)
			}
			err := collector.Evaluate(Profile{Name: "lightweight", Required: []string{"nsjail"}})
			if test.ok && err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if !test.ok && err == nil {
				t.Fatal("Evaluate() error = nil, want fail-closed error")
			}
		})
	}
}

func TestUnavailableRequiresReason(t *testing.T) {
	t.Parallel()

	collector := NewCollector()
	if err := collector.Add(Result{Component: "firecracker", Status: Unavailable}); err == nil {
		t.Fatal("Add() error = nil, want missing reason error")
	}
}

func TestProductionProfileRejectsMock(t *testing.T) {
	t.Parallel()

	collector := NewCollector()
	if err := collector.Add(Result{Component: "mock", Status: Pass}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if err := collector.Evaluate(Profile{Name: "production", Production: true, Required: []string{"mock"}}); err == nil {
		t.Fatal("Evaluate() error = nil, want mock rejection")
	}
}

func TestCollectorRejectsConflictingDuplicateEvidence(t *testing.T) {
	t.Parallel()

	collector := NewCollector()
	first := Result{Component: "celld", Status: Pass, Evidence: Evidence{BinaryDigest: validDigest("1")}}
	if err := collector.Add(first); err != nil {
		t.Fatalf("Add(first) error = %v", err)
	}
	if err := collector.Add(first); err != nil {
		t.Fatalf("Add(idempotent duplicate) error = %v", err)
	}
	second := first
	second.Evidence.BinaryDigest = validDigest("2")
	if err := collector.Add(second); err == nil {
		t.Fatal("Add(conflicting duplicate) error = nil")
	}
}

func TestCollectorIsConcurrentAndReportJSONIsDeterministic(t *testing.T) {
	t.Parallel()

	collector := NewCollector()
	var wait sync.WaitGroup
	for index := range 100 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			component := fmt.Sprintf("component-%03d", index)
			result := Result{Component: component, Status: Pass, Evidence: Evidence{BinaryDigest: validDigest(fmt.Sprintf("%x", index%16))}}
			if err := collector.Add(result); err != nil {
				t.Errorf("Add(%q) error = %v", component, err)
			}
		}()
	}
	wait.Wait()

	first, err := json.Marshal(collector.Report())
	if err != nil {
		t.Fatalf("Marshal(first) error = %v", err)
	}
	second, err := json.Marshal(collector.Report())
	if err != nil {
		t.Fatalf("Marshal(second) error = %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("report JSON is not deterministic:\nfirst:  %s\nsecond: %s", first, second)
	}

	report := collector.Report()
	if len(report.Results) != 100 {
		t.Fatalf("len(Report.Results) = %d, want 100", len(report.Results))
	}
	for index := 1; index < len(report.Results); index++ {
		if report.Results[index-1].Component >= report.Results[index].Component {
			t.Fatalf("results not sorted at %d: %q >= %q", index, report.Results[index-1].Component, report.Results[index].Component)
		}
	}
}

func TestMergeDoesNotOverwriteConflictingResult(t *testing.T) {
	t.Parallel()

	collector := NewCollector()
	if err := collector.Merge(Report{SchemaVersion: 1, Results: []Result{{Component: "workerd", Status: Pass}}}); err != nil {
		t.Fatalf("Merge(first) error = %v", err)
	}
	if err := collector.Merge(Report{SchemaVersion: 1, Results: []Result{{Component: "workerd", Status: Fail, Reason: "outbound allowed"}}}); err == nil {
		t.Fatal("Merge(conflict) error = nil")
	}
	if got := collector.Report().Results[0].Status; got != Pass {
		t.Fatalf("stored status = %q, want %q", got, Pass)
	}
}

func validDigest(nibble string) string {
	return "sha256:" + strings.Repeat(nibble, 64)
}
