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

// requiredResourceQualificationComponents must each reach a run-bound external
// PASS for the achievable Unit 10 resource bar. workerd.cpu-limit is certified
// at the kernel boundary — exact cgroup cpu.max readback plus an observed
// cpu.stat throttling increase under a runaway Worker, escalated by
// supervisor-observed starvation to a deterministic whole-shard kill/recycle —
// not by workerd's in-isolate cpuMs, which the pinned build parses but does not
// enforce. That kernel boundary is the certified safety boundary; it holds
// against a fully uncooperative isolate, which an in-isolate soft limit does
// not.
var requiredResourceQualificationComponents = []string{
	"workerd.cpu-limit",
	"workerd.rss-cold-start",
	"workerd.shard-kill-reconstruction",
	"workerd.shard-pressure-recycle",
}

// recordedResourceQualificationComponents cannot reach PASS on the pinned
// workerd and are demoted from the required set to a recorded honest FAIL.
// Stock workerd 1.20260825.1 never reconstructs a Worker Loader isolate after
// any reachable in-isolate fault: the module-local initialization-instance ID
// is preserved across an uncaught throw, an async rejection, an oversized-array
// and a stack RangeError, and even a 4 GB allocation. Each recorded component
// is required to be present and to carry an honest FAIL — never a PASS and
// never a skip — so the residual gap stays visible. Unit 10 keeps
// AdmissionReady=false while any recorded gap stands; the safety-relevant
// recovery of a wedged worker is delivered at the shard level by the
// kill/pressure reconstruction results, not per isolate.
var recordedResourceQualificationComponents = []string{
	"workerd.dynamic-worker-reconstruction",
}

// resourceQualificationComponents is the full set of external results the
// Unit 10 resource gate emits — the required components plus the recorded
// residual-gap components — in canonical-name order. The old ambiguous
// workerd.shard-recycle result is intentionally absent.
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

func isRecordedResourceQualificationComponent(component string) bool {
	for _, candidate := range recordedResourceQualificationComponents {
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

// evaluateResourceQualificationRun reports whether the run meets the achievable
// Unit 10 resource bar: every required component passes its predicate against
// one shared envelope, and every recorded residual-gap component carries an
// honest FAIL. It returns a framing error when the result set is structurally
// invalid (missing, duplicate, unknown, or empty), when PASS-status required
// results disagree on the run envelope, or when a recorded residual-gap
// component reports PASS (which the pinned workerd cannot legitimately produce,
// so it signals a fabrication or an unreviewed behavior change). A well-formed
// run that merely did not reach the bar — a required component that did not
// PASS, or a recorded component left NOT_RUN/UNAVAILABLE rather than FAIL —
// returns (false, nil) so the caller can still emit an honest report.
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
	for _, component := range resourceQualificationComponents {
		if _, found := byComponent[component]; !found {
			return false, fmt.Errorf("workerd resource qualification: missing component %q", component)
		}
	}

	// A recorded residual-gap component can never legitimately PASS on the
	// pinned workerd. A reported PASS is a fabrication or an unreviewed
	// behavior change, so it is a framing error rather than a quiet success.
	// The achievable bar requires each recorded component to carry an honest
	// FAIL; any other non-PASS status leaves the run merely incomplete.
	recordedAllFail := true
	for _, component := range recordedResourceQualificationComponents {
		switch byComponent[component].Status {
		case conformance.Pass:
			return false, fmt.Errorf("workerd resource qualification: recorded residual-gap component %q reported PASS; the pinned workerd cannot enforce it, so this run must be re-scoped or re-pinned before promotion", component)
		case conformance.Fail:
		default:
			recordedAllFail = false
		}
	}

	// Every PASS-status required result must belong to one shared envelope. A
	// disagreement among required PASS results is a structural integrity
	// violation the runner must never emit, so it is a framing error rather
	// than a quiet not-all-pass.
	ordered := append([]string(nil), requiredResourceQualificationComponents...)
	sort.Strings(ordered)
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
	allRequiredPass := true
	for _, component := range ordered {
		if err := resourceComponentPassError(byComponent[component], reference.observation, reference.binary, reference.environment); err != nil {
			allRequiredPass = false
		}
	}
	return allRequiredPass && recordedAllFail, nil
}
