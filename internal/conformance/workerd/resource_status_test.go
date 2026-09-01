package workerd

import (
	"errors"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/conformance"
)

func TestResourceDispositionMapsTheFixedStatusTable(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		disposition resourceDisposition
		want        conformance.Status
	}{
		{resourceDispositionNotRun, conformance.NotRun},
		{resourceDispositionUnavailable, conformance.Unavailable},
		{resourceDispositionFail, conformance.Fail},
		{resourceDispositionPass, conformance.Pass},
	} {
		if got := test.disposition.status(); got != test.want {
			t.Errorf("disposition %d status = %s, want %s", test.disposition, got, test.want)
		}
	}
}

func TestResourceDispositionJoinLetsFailDominateUnavailable(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		left  resourceDisposition
		right resourceDisposition
		want  resourceDisposition
	}{
		{resourceDispositionUnavailable, resourceDispositionFail, resourceDispositionFail},
		{resourceDispositionFail, resourceDispositionUnavailable, resourceDispositionFail},
		{resourceDispositionNotRun, resourceDispositionUnavailable, resourceDispositionUnavailable},
		{resourceDispositionPass, resourceDispositionNotRun, resourceDispositionNotRun},
		{resourceDispositionPass, resourceDispositionPass, resourceDispositionPass},
	} {
		if got := joinResourceDisposition(test.left, test.right); got != test.want {
			t.Errorf("join(%d, %d) = %d, want %d", test.left, test.right, got, test.want)
		}
	}
}

func passingResourceResult(component, observationDigest, binaryDigest, environmentDigest string) conformance.Result {
	return conformance.Result{
		Component: component,
		Status:    conformance.Pass,
		Evidence: conformance.Evidence{
			Class:             conformance.EvidenceClassExternal,
			BinaryDigest:      binaryDigest,
			EnvironmentDigest: environmentDigest,
			ArtifactReferences: []conformance.ArtifactReference{
				{Name: resourceObservationArtifactName, Digest: observationDigest},
			},
		},
	}
}

func TestResourceComponentPassPredicateRequiresExternalEnvelopeBinding(t *testing.T) {
	t.Parallel()
	observation := "sha256:" + strings.Repeat("a", 64)
	binary := "sha256:" + strings.Repeat("b", 64)
	environment := "sha256:" + strings.Repeat("c", 64)
	good := passingResourceResult("workerd.rss-cold-start", observation, binary, environment)
	if err := resourceComponentPassError(good, observation, binary, environment); err != nil {
		t.Fatalf("resourceComponentPassError(valid) = %v, want nil", err)
	}
	for name, mutate := range map[string]func(*conformance.Result){
		"not pass": func(r *conformance.Result) { r.Status = conformance.NotRun },
		"mock evidence": func(r *conformance.Result) {
			r.Evidence.Mock = true
			r.Evidence.Class = conformance.EvidenceClassReferenceOnly
		},
		"reference only":      func(r *conformance.Result) { r.Evidence.Class = conformance.EvidenceClassReferenceOnly },
		"host observation":    func(r *conformance.Result) { r.Evidence.Class = conformance.EvidenceClassHostObservation },
		"empty class":         func(r *conformance.Result) { r.Evidence.Class = "" },
		"missing binary":      func(r *conformance.Result) { r.Evidence.BinaryDigest = "" },
		"missing environment": func(r *conformance.Result) { r.Evidence.EnvironmentDigest = "" },
		"no observation ref":  func(r *conformance.Result) { r.Evidence.ArtifactReferences = nil },
		"wrong observation": func(r *conformance.Result) {
			r.Evidence.ArtifactReferences = []conformance.ArtifactReference{{Name: "other.cbor", Digest: observation}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			result := passingResourceResult("workerd.rss-cold-start", observation, binary, environment)
			mutate(&result)
			if err := resourceComponentPassError(result, observation, binary, environment); err == nil {
				t.Fatalf("resourceComponentPassError(%s) = nil, want rejection", name)
			}
		})
	}
	t.Run("observation digest disagreement", func(t *testing.T) {
		other := "sha256:" + strings.Repeat("d", 64)
		if err := resourceComponentPassError(good, other, binary, environment); err == nil {
			t.Fatal("resourceComponentPassError(mismatched envelope digest) = nil, want rejection")
		}
	})
}

// recordedFailResourceResult builds the honest FAIL that a recorded
// residual-gap component (dynamic-worker-reconstruction) must carry: a real
// external finding that the pinned workerd never reconstructs a per-isolate
// fault, never a skip and never a PASS.
func recordedFailResourceResult(component string) conformance.Result {
	return conformance.Result{
		Component: component,
		Status:    conformance.Fail,
		Reason:    "stock workerd does not reconstruct a per-isolate fault on this pin",
		Evidence: conformance.Evidence{
			Class: conformance.EvidenceClassExternal,
			Mock:  false,
		},
	}
}

func TestEvaluateResourceQualificationRunRequiresFourPassPlusRecordedFail(t *testing.T) {
	t.Parallel()
	observation := "sha256:" + strings.Repeat("a", 64)
	binary := "sha256:" + strings.Repeat("b", 64)
	environment := "sha256:" + strings.Repeat("c", 64)

	// Sanity: the partition is exactly the union of required and recorded, and
	// dynamic-worker-reconstruction is the demoted recorded gap.
	if len(requiredResourceQualificationComponents)+len(recordedResourceQualificationComponents) != len(resourceQualificationComponents) {
		t.Fatalf("component partition is not a clean split of the full set")
	}
	if !isRecordedResourceQualificationComponent("workerd.dynamic-worker-reconstruction") {
		t.Fatalf("dynamic-worker-reconstruction must be a recorded residual-gap component")
	}
	for _, required := range requiredResourceQualificationComponents {
		if isRecordedResourceQualificationComponent(required) {
			t.Fatalf("required component %q must not also be recorded", required)
		}
	}

	qualified := func() []conformance.Result {
		results := make([]conformance.Result, 0, len(resourceQualificationComponents))
		for _, component := range requiredResourceQualificationComponents {
			results = append(results, passingResourceResult(component, observation, binary, environment))
		}
		for _, component := range recordedResourceQualificationComponents {
			results = append(results, recordedFailResourceResult(component))
		}
		return results
	}
	if qualifiedRun, err := evaluateResourceQualificationRun(qualified()); !qualifiedRun || err != nil {
		t.Fatalf("evaluateResourceQualificationRun(4 pass + recorded fail) = %v, %v, want qualified", qualifiedRun, err)
	}

	// A recorded residual-gap component reported as PASS is a framing error:
	// the pinned workerd cannot legitimately produce it.
	recordedClaimsPass := qualified()
	for i := range recordedClaimsPass {
		if isRecordedResourceQualificationComponent(recordedClaimsPass[i].Component) {
			recordedClaimsPass[i] = passingResourceResult(recordedClaimsPass[i].Component, observation, binary, environment)
		}
	}
	if qualifiedRun, err := evaluateResourceQualificationRun(recordedClaimsPass); qualifiedRun || err == nil {
		t.Fatalf("evaluateResourceQualificationRun(recorded PASS) = %v, %v, want framing error", qualifiedRun, err)
	}

	// A recorded component left NOT_RUN (never executed) is incomplete, not a
	// framing error, and never qualified.
	recordedNotRun := qualified()
	for i := range recordedNotRun {
		if isRecordedResourceQualificationComponent(recordedNotRun[i].Component) {
			recordedNotRun[i].Status = conformance.NotRun
		}
	}
	if qualifiedRun, err := evaluateResourceQualificationRun(recordedNotRun); qualifiedRun || err != nil {
		t.Fatalf("evaluateResourceQualificationRun(recorded NOT_RUN) = %v, %v, want incomplete without a framing error", qualifiedRun, err)
	}

	missing := qualified()[:len(resourceQualificationComponents)-1]
	if qualifiedRun, err := evaluateResourceQualificationRun(missing); qualifiedRun || err == nil {
		t.Fatalf("evaluateResourceQualificationRun(missing component) = %v, %v, want failure", qualifiedRun, err)
	}

	oneRequiredFailed := qualified()
	oneRequiredFailed[0].Status = conformance.Fail
	oneRequiredFailed[0].Reason = "cgroup cpu.max readback mismatch"
	if qualifiedRun, err := evaluateResourceQualificationRun(oneRequiredFailed); qualifiedRun || err != nil {
		t.Fatalf("evaluateResourceQualificationRun(one required FAIL) = %v, %v, want not-qualified without a framing error", qualifiedRun, err)
	}

	splitEnvelope := qualified()
	splitEnvelope[1].Evidence.ArtifactReferences = []conformance.ArtifactReference{
		{Name: resourceObservationArtifactName, Digest: "sha256:" + strings.Repeat("e", 64)},
	}
	if qualifiedRun, err := evaluateResourceQualificationRun(splitEnvelope); qualifiedRun || err == nil {
		t.Fatalf("evaluateResourceQualificationRun(split envelope) = %v, %v, want cross-run rejection", qualifiedRun, err)
	}

	duplicate := qualified()
	duplicate[1].Component = duplicate[0].Component
	if qualifiedRun, err := evaluateResourceQualificationRun(duplicate); qualifiedRun || err == nil {
		t.Fatalf("evaluateResourceQualificationRun(duplicate component) = %v, %v, want rejection", qualifiedRun, err)
	}

	unknown := qualified()
	unknown[0].Component = "workerd.unknown-result"
	if qualifiedRun, err := evaluateResourceQualificationRun(unknown); qualifiedRun || err == nil {
		t.Fatalf("evaluateResourceQualificationRun(unknown component) = %v, %v, want rejection", qualifiedRun, err)
	}
}

func TestEvaluateResourceQualificationRunRejectsInvalidResults(t *testing.T) {
	t.Parallel()
	if _, err := evaluateResourceQualificationRun(nil); err == nil {
		t.Fatal("evaluateResourceQualificationRun(nil) = nil error, want rejection")
	}
	if _, err := evaluateResourceQualificationRun([]conformance.Result{}); err == nil {
		t.Fatal("evaluateResourceQualificationRun(empty) = nil error, want rejection")
	}
	var mapErr *resourceQualificationComponentError
	err := describeResourceComponentError("workerd.cpu-limit")
	if !errors.As(err, &mapErr) || mapErr.Component != "workerd.cpu-limit" {
		t.Fatalf("describeResourceComponentError() = %v, want typed component error", err)
	}
}
