package workerd

import (
	"fmt"
	"sort"

	"github.com/hancomac/circulusd/internal/conformance"
)

// resourceObservationArtifactName is the canonical evidence artifact every
// Unit 10 resource PASS result must reference. A shared digest for this name
// across all five results is what binds them to one qualification run.
const resourceObservationArtifactName = "workerd-resource-observation-v1.cbor"

// resourceQualificationComponents are the exact five external results the
// Unit 10 resource gate produces. The old ambiguous workerd.shard-recycle
// result is intentionally absent.
var resourceQualificationComponents = []string{
	"workerd.cpu-limit",
	"workerd.dynamic-worker-reconstruction",
	"workerd.rss-cold-start",
	"workerd.shard-kill-reconstruction",
	"workerd.shard-pressure-recycle",
}

// resourceDisposition is the internal severity of one classification input.
// It maps to a conformance.Status and joins by taking the more severe value,
// so a genuine failure dominates a joined host-unavailable error.
type resourceDisposition int

const (
	resourceDispositionPass resourceDisposition = iota
	resourceDispositionNotRun
	resourceDispositionUnavailable
	resourceDispositionFail
)

func (disposition resourceDisposition) status() conformance.Status {
	switch disposition {
	case resourceDispositionPass:
		return conformance.Pass
	case resourceDispositionNotRun:
		return conformance.NotRun
	case resourceDispositionUnavailable:
		return conformance.Unavailable
	default:
		return conformance.Fail
	}
}

// joinResourceDisposition returns the more severe of two dispositions. The
// severity order is Pass < NotRun < Unavailable < Fail, so a FAIL dominates a
// joined UNAVAILABLE and any non-pass dominates a pass.
func joinResourceDisposition(left resourceDisposition, right resourceDisposition) resourceDisposition {
	if left >= right {
		return left
	}
	return right
}

// resourceQualificationComponentError is a typed per-component classification
// failure so callers can attribute a rejection to one named result.
type resourceQualificationComponentError struct {
	Component string
	Reason    string
}

func (err *resourceQualificationComponentError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return fmt.Sprintf("workerd resource qualification: component %q: %s", err.Component, err.Reason)
}

func describeResourceComponentError(component string) error {
	return &resourceQualificationComponentError{Component: component, Reason: "classification"}
}

func isResourceQualificationComponent(component string) bool {
	for _, candidate := range resourceQualificationComponents {
		if candidate == component {
			return true
		}
	}
	return false
}

// resourceComponentPassError verifies one result satisfies every predicate
// the plan requires of a Unit 10 resource PASS: external, non-mock evidence
// carrying the canonical binary and environment digests plus an observation
// artifact reference whose digest matches the run envelope. A non-PASS status,
// or any missing or disagreeing binding, is a rejection.
func resourceComponentPassError(result conformance.Result, observationDigest string, binaryDigest string, environmentDigest string) error {
	reject := func(reason string) error {
		return &resourceQualificationComponentError{Component: result.Component, Reason: reason}
	}
	if result.Status != conformance.Pass {
		return reject(fmt.Sprintf("status is %s, want PASS", result.Status))
	}
	if result.Evidence.Class != conformance.EvidenceClassExternal {
		return reject(fmt.Sprintf("evidence class %q is not external", result.Evidence.Class))
	}
	if result.Evidence.Mock {
		return reject("evidence is mock")
	}
	if result.Evidence.BinaryDigest == "" || result.Evidence.BinaryDigest != binaryDigest {
		return reject("binary digest does not match the run envelope")
	}
	if result.Evidence.EnvironmentDigest == "" || result.Evidence.EnvironmentDigest != environmentDigest {
		return reject("environment digest does not match the run envelope")
	}
	observationReferences := 0
	for _, artifact := range result.Evidence.ArtifactReferences {
		if artifact.Name != resourceObservationArtifactName {
			continue
		}
		observationReferences++
		if artifact.Digest == "" || artifact.Digest != observationDigest {
			return reject("observation artifact digest does not match the run envelope")
		}
	}
	if observationReferences != 1 {
		return reject("result must reference the observation artifact exactly once")
	}
	return nil
}

// evaluateResourceQualificationRun reports whether every one of the five
// required components passes its predicate against one shared envelope. It
// returns a framing error only when the result set is structurally invalid
// (missing, duplicate, unknown, or empty); a well-formed run in which some
// component did not PASS returns (false, nil) so the caller can still emit an
// honest report.
func evaluateResourceQualificationRun(results []conformance.Result) (bool, error) {
	if len(results) == 0 {
		return false, fmt.Errorf("workerd resource qualification: no results to evaluate")
	}
	byComponent := make(map[string]conformance.Result, len(results))
	for _, result := range results {
		if !isResourceQualificationComponent(result.Component) {
			return false, fmt.Errorf("workerd resource qualification: unexpected component %q", result.Component)
		}
		if _, duplicate := byComponent[result.Component]; duplicate {
			return false, fmt.Errorf("workerd resource qualification: duplicate component %q", result.Component)
		}
		byComponent[result.Component] = result
	}
	ordered := append([]string(nil), resourceQualificationComponents...)
	sort.Strings(ordered)
	for _, component := range ordered {
		if _, found := byComponent[component]; !found {
			return false, fmt.Errorf("workerd resource qualification: missing component %q", component)
		}
	}

	// Every PASS-status result must belong to one shared envelope. A
	// disagreement among PASS results is a structural integrity violation the
	// runner must never emit, so it is a framing error rather than a quiet
	// not-all-pass.
	type envelope struct {
		binary      string
		environment string
		observation string
	}
	var reference *envelope
	for _, component := range ordered {
		result := byComponent[component]
		if result.Status != conformance.Pass {
			continue
		}
		observation := ""
		observationCount := 0
		for _, artifact := range result.Evidence.ArtifactReferences {
			if artifact.Name == resourceObservationArtifactName {
				observation = artifact.Digest
				observationCount++
			}
		}
		current := envelope{
			binary:      result.Evidence.BinaryDigest,
			environment: result.Evidence.EnvironmentDigest,
			observation: observation,
		}
		if observationCount != 1 || current.binary == "" || current.environment == "" || current.observation == "" {
			return false, fmt.Errorf("workerd resource qualification: PASS component %q has an incomplete evidence envelope", component)
		}
		if reference == nil {
			envelopeValue := current
			reference = &envelopeValue
			continue
		}
		if current != *reference {
			return false, fmt.Errorf("workerd resource qualification: PASS component %q does not share the run evidence envelope", component)
		}
	}

	if reference == nil {
		return false, nil
	}
	allPass := true
	for _, component := range ordered {
		if err := resourceComponentPassError(byComponent[component], reference.observation, reference.binary, reference.environment); err != nil {
			allPass = false
		}
	}
	return allPass, nil
}
