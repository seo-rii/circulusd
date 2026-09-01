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

func TestEvaluateResourceQualificationRunRequiresAllFiveFromOneEnvelope(t *testing.T) {
	t.Parallel()
	observation := "sha256:" + strings.Repeat("a", 64)
	binary := "sha256:" + strings.Repeat("b", 64)
	environment := "sha256:" + strings.Repeat("c", 64)
	full := func() []conformance.Result {
		results := make([]conformance.Result, 0, len(resourceQualificationComponents))
		for _, component := range resourceQualificationComponents {
			results = append(results, passingResourceResult(component, observation, binary, environment))
		}
		return results
	}
	if allPass, err := evaluateResourceQualificationRun(full()); !allPass || err != nil {
		t.Fatalf("evaluateResourceQualificationRun(complete) = %v, %v, want all pass", allPass, err)
	}

	missing := full()[:len(resourceQualificationComponents)-1]
	if allPass, err := evaluateResourceQualificationRun(missing); allPass || err == nil {
		t.Fatalf("evaluateResourceQualificationRun(missing component) = %v, %v, want failure", allPass, err)
	}

	oneFailed := full()
	oneFailed[0].Status = conformance.Fail
	oneFailed[0].Reason = "workerd does not enforce cpuMs"
	if allPass, err := evaluateResourceQualificationRun(oneFailed); allPass || err != nil {
		t.Fatalf("evaluateResourceQualificationRun(one FAIL) = %v, %v, want not-all-pass without a framing error", allPass, err)
	}

	splitEnvelope := full()
	splitEnvelope[1].Evidence.ArtifactReferences = []conformance.ArtifactReference{
		{Name: resourceObservationArtifactName, Digest: "sha256:" + strings.Repeat("e", 64)},
	}
	if allPass, err := evaluateResourceQualificationRun(splitEnvelope); allPass || err == nil {
		t.Fatalf("evaluateResourceQualificationRun(split envelope) = %v, %v, want cross-run rejection", allPass, err)
	}

	duplicate := full()
	duplicate[1].Component = duplicate[0].Component
	if allPass, err := evaluateResourceQualificationRun(duplicate); allPass || err == nil {
		t.Fatalf("evaluateResourceQualificationRun(duplicate component) = %v, %v, want rejection", allPass, err)
	}

	unknown := full()
	unknown[0].Component = "workerd.unknown-result"
	if allPass, err := evaluateResourceQualificationRun(unknown); allPass || err == nil {
		t.Fatalf("evaluateResourceQualificationRun(unknown component) = %v, %v, want rejection", allPass, err)
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
