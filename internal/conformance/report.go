package conformance

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const reportSchemaVersion = 1

var (
	componentPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)
	sha256Pattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	artifactPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`)
)

type Status string

const (
	Pass        Status = "PASS"
	Fail        Status = "FAIL"
	Unavailable Status = "UNAVAILABLE"
	NotRun      Status = "NOT_RUN"
)

type EvidenceClass string

const (
	EvidenceClassExternal        EvidenceClass = "external"
	EvidenceClassHostObservation EvidenceClass = "host-observation"
	EvidenceClassReferenceOnly   EvidenceClass = "reference-only"
)

type ArtifactReference struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

type Evidence struct {
	Class              EvidenceClass       `json:"evidenceClass,omitempty"`
	BinaryDigest       string              `json:"binaryDigest,omitempty"`
	Version            string              `json:"version,omitempty"`
	EnvironmentDigest  string              `json:"environmentDigest,omitempty"`
	Kernel             string              `json:"kernel,omitempty"`
	Architecture       string              `json:"architecture,omitempty"`
	ArtifactReferences []ArtifactReference `json:"artifactReferences"`
	Mock               bool                `json:"mock,omitempty"`
}

type Result struct {
	Component string   `json:"component"`
	Status    Status   `json:"status"`
	Reason    string   `json:"reason,omitempty"`
	Evidence  Evidence `json:"evidence,omitempty"`
}

type Report struct {
	SchemaVersion int      `json:"schemaVersion"`
	Results       []Result `json:"results"`
}

type Profile struct {
	Name       string
	Production bool
	Required   []string
}

type Collector struct {
	mu      sync.RWMutex
	results map[string]Result
}

func NewCollector() *Collector {
	return &Collector{results: make(map[string]Result)}
}

func (collector *Collector) Add(result Result) error {
	if err := validateResult(result); err != nil {
		return err
	}
	result = cloneResult(result)

	collector.mu.Lock()
	defer collector.mu.Unlock()

	if existing, found := collector.results[result.Component]; found {
		if reflect.DeepEqual(existing, result) {
			return nil
		}
		return fmt.Errorf("component %q has conflicting conformance results", result.Component)
	}
	collector.results[result.Component] = result
	return nil
}

func (collector *Collector) Merge(report Report) error {
	if report.SchemaVersion != reportSchemaVersion {
		return fmt.Errorf("conformance report schemaVersion %d is unsupported", report.SchemaVersion)
	}
	for _, result := range report.Results {
		if err := validateResult(result); err != nil {
			return err
		}
	}

	collector.mu.Lock()
	defer collector.mu.Unlock()

	merged := make(map[string]Result, len(collector.results)+len(report.Results))
	for component, result := range collector.results {
		merged[component] = result
	}
	for _, result := range report.Results {
		if existing, found := merged[result.Component]; found && !reflect.DeepEqual(existing, result) {
			return fmt.Errorf("component %q has conflicting conformance results", result.Component)
		}
		merged[result.Component] = cloneResult(result)
	}
	collector.results = merged
	return nil
}

func (collector *Collector) Report() Report {
	collector.mu.RLock()
	results := make([]Result, 0, len(collector.results))
	for _, result := range collector.results {
		results = append(results, cloneResult(result))
	}
	collector.mu.RUnlock()

	sort.Slice(results, func(left, right int) bool {
		return results[left].Component < results[right].Component
	})
	return Report{SchemaVersion: reportSchemaVersion, Results: results}
}

func cloneResult(result Result) Result {
	if result.Evidence.ArtifactReferences == nil {
		return result
	}
	result.Evidence.ArtifactReferences = append(
		make([]ArtifactReference, 0, len(result.Evidence.ArtifactReferences)),
		result.Evidence.ArtifactReferences...,
	)
	return result
}

func (collector *Collector) Evaluate(profile Profile) error {
	if strings.TrimSpace(profile.Name) == "" {
		return fmt.Errorf("conformance profile name is required")
	}

	collector.mu.RLock()
	defer collector.mu.RUnlock()

	seen := make(map[string]struct{}, len(profile.Required))
	for _, component := range profile.Required {
		if _, duplicate := seen[component]; duplicate {
			return fmt.Errorf("profile %q repeats required component %q", profile.Name, component)
		}
		seen[component] = struct{}{}

		result, found := collector.results[component]
		if !found {
			return fmt.Errorf("profile %q requires missing component %q", profile.Name, component)
		}
		if profile.Production && result.Status == Pass {
			if result.Evidence.Mock || component == "mock" || strings.HasPrefix(component, "mock-") || strings.HasPrefix(component, "fake-") {
				return fmt.Errorf("production profile %q rejects synthetic component %q", profile.Name, component)
			}
			switch result.Evidence.Class {
			case "", EvidenceClassExternal:
			case EvidenceClassHostObservation:
				if !strings.HasPrefix(component, "host.") {
					return fmt.Errorf("production profile %q rejects host-only evidence for %q", profile.Name, component)
				}
			default:
				return fmt.Errorf("production profile %q requires explicit external evidence for %q", profile.Name, component)
			}
		}
		if result.Status != Pass {
			return fmt.Errorf("profile %q requires %q to PASS, got %s", profile.Name, component, result.Status)
		}
	}
	return nil
}

func validateResult(result Result) error {
	if !componentPattern.MatchString(result.Component) {
		return fmt.Errorf("component %q is invalid", result.Component)
	}
	switch result.Status {
	case Pass, Fail, Unavailable, NotRun:
	default:
		return fmt.Errorf("component %q has unknown status %q", result.Component, result.Status)
	}
	if result.Status == Unavailable && strings.TrimSpace(result.Reason) == "" {
		return fmt.Errorf("component %q is UNAVAILABLE without a reason", result.Component)
	}
	switch result.Evidence.Class {
	case "", EvidenceClassExternal, EvidenceClassHostObservation, EvidenceClassReferenceOnly:
	default:
		return fmt.Errorf("component %q has unknown evidenceClass %q", result.Component, result.Evidence.Class)
	}
	if result.Evidence.Mock && result.Evidence.Class != "" && result.Evidence.Class != EvidenceClassReferenceOnly {
		return fmt.Errorf("component %q labels mock evidence as %q", result.Component, result.Evidence.Class)
	}
	for field, digest := range map[string]string{
		"binaryDigest":      result.Evidence.BinaryDigest,
		"environmentDigest": result.Evidence.EnvironmentDigest,
	} {
		if digest != "" && !sha256Pattern.MatchString(digest) {
			return fmt.Errorf("component %q evidence %s is not a canonical SHA-256 digest", result.Component, field)
		}
	}
	seenArtifacts := make(map[string]struct{}, len(result.Evidence.ArtifactReferences))
	for index, artifact := range result.Evidence.ArtifactReferences {
		if !artifactPattern.MatchString(artifact.Name) || !sha256Pattern.MatchString(artifact.Digest) {
			return fmt.Errorf("component %q evidence artifact %d is invalid", result.Component, index)
		}
		if _, duplicate := seenArtifacts[artifact.Name]; duplicate {
			return fmt.Errorf("component %q repeats evidence artifact %q", result.Component, artifact.Name)
		}
		seenArtifacts[artifact.Name] = struct{}{}
	}
	return nil
}
