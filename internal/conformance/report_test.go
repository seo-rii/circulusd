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

func TestProductionProfileRejectsExplicitReferenceEvidenceClasses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		component string
		evidence  Evidence
		wantError bool
	}{
		{
			name:      "external conformance",
			component: "state.kill-durability",
			evidence:  Evidence{Class: EvidenceClassExternal},
		},
		{
			name:      "host observation for host gate",
			component: "host.kernel",
			evidence:  Evidence{Class: EvidenceClassHostObservation},
		},
		{
			name:      "legacy unclassified evidence remains compatible",
			component: "state.kill-durability",
		},
		{
			name:      "reference only",
			component: "state.kill-durability",
			evidence:  Evidence{Class: EvidenceClassReferenceOnly},
			wantError: true,
		},
		{
			name:      "legacy mock",
			component: "state.kill-durability",
			evidence:  Evidence{Mock: true},
			wantError: true,
		},
		{
			name:      "host observation cannot qualify a service gate",
			component: "state.kill-durability",
			evidence:  Evidence{Class: EvidenceClassHostObservation},
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			collector := NewCollector()
			if err := collector.Add(Result{
				Component: test.component,
				Status:    Pass,
				Evidence:  test.evidence,
			}); err != nil {
				t.Fatalf("Add() error = %v", err)
			}
			err := collector.Evaluate(Profile{
				Name:       "production",
				Production: true,
				Required:   []string{test.component},
			})
			if test.wantError && err == nil {
				t.Fatal("Evaluate() error = nil, want fail-closed evidence rejection")
			}
			if !test.wantError && err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
		})
	}
}

func TestCollectorValidatesEvidenceClassAndArtifactReferences(t *testing.T) {
	t.Parallel()

	valid := Result{
		Component: "workerd.dynamic-worker",
		Status:    Pass,
		Evidence: Evidence{
			Class: EvidenceClassExternal,
			ArtifactReferences: []ArtifactReference{{
				Name:   "workerd-linux-x86_64.gz",
				Digest: validDigest("a"),
			}},
		},
	}
	if err := NewCollector().Add(valid); err != nil {
		t.Fatalf("Add(valid) error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Result)
	}{
		{name: "unknown class", mutate: func(result *Result) { result.Evidence.Class = EvidenceClass("guessed") }},
		{name: "invalid artifact name", mutate: func(result *Result) { result.Evidence.ArtifactReferences[0].Name = "../workerd" }},
		{name: "invalid artifact digest", mutate: func(result *Result) { result.Evidence.ArtifactReferences[0].Digest = "sha256:no" }},
		{name: "duplicate artifact", mutate: func(result *Result) {
			result.Evidence.ArtifactReferences = append(result.Evidence.ArtifactReferences, result.Evidence.ArtifactReferences[0])
		}},
		{name: "duplicate artifact name with another digest", mutate: func(result *Result) {
			result.Evidence.ArtifactReferences = append(result.Evidence.ArtifactReferences, ArtifactReference{
				Name:   result.Evidence.ArtifactReferences[0].Name,
				Digest: validDigest("b"),
			})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.Evidence.ArtifactReferences = append([]ArtifactReference(nil), valid.Evidence.ArtifactReferences...)
			test.mutate(&candidate)
			if err := NewCollector().Add(candidate); err == nil {
				t.Fatal("Add() error = nil, want invalid evidence rejection")
			}
		})
	}
}

func TestCollectorOwnsArtifactReferenceSlices(t *testing.T) {
	t.Parallel()

	digest := validDigest("a")
	result := Result{
		Component: "workerd.dynamic-worker",
		Status:    Pass,
		Evidence: Evidence{
			Class: EvidenceClassExternal,
			ArtifactReferences: []ArtifactReference{{
				Name:   "worker.mjs",
				Digest: digest,
			}},
		},
	}
	collector := NewCollector()
	if err := collector.Add(result); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	result.Evidence.ArtifactReferences[0].Digest = validDigest("b")
	first := collector.Report()
	if got := first.Results[0].Evidence.ArtifactReferences[0].Digest; got != digest {
		t.Fatalf("Report() digest after Add input mutation = %q, want %q", got, digest)
	}
	first.Results[0].Evidence.ArtifactReferences[0].Digest = validDigest("c")
	if got := collector.Report().Results[0].Evidence.ArtifactReferences[0].Digest; got != digest {
		t.Fatalf("Report() digest after output mutation = %q, want %q", got, digest)
	}

	mergedResult := result
	mergedResult.Evidence.ArtifactReferences = []ArtifactReference{{
		Name:   "worker.mjs",
		Digest: digest,
	}}
	merged := NewCollector()
	input := Report{SchemaVersion: 1, Results: []Result{mergedResult}}
	if err := merged.Merge(input); err != nil {
		t.Fatalf("Merge() error = %v", err)
	}
	input.Results[0].Evidence.ArtifactReferences[0].Digest = validDigest("d")
	if got := merged.Report().Results[0].Evidence.ArtifactReferences[0].Digest; got != digest {
		t.Fatalf("Report() digest after Merge input mutation = %q, want %q", got, digest)
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
