package conformance

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const reportSchemaVersion = 1

var (
	componentPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)
	sha256Pattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Status string

const (
	Pass        Status = "PASS"
	Fail        Status = "FAIL"
	Unavailable Status = "UNAVAILABLE"
	NotRun      Status = "NOT_RUN"
)

type Evidence struct {
	BinaryDigest      string `json:"binaryDigest,omitempty"`
	Version           string `json:"version,omitempty"`
	EnvironmentDigest string `json:"environmentDigest,omitempty"`
	Kernel            string `json:"kernel,omitempty"`
	Architecture      string `json:"architecture,omitempty"`
	Mock              bool   `json:"mock,omitempty"`
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

	collector.mu.Lock()
	defer collector.mu.Unlock()

	if existing, found := collector.results[result.Component]; found {
		if existing == result {
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
		if existing, found := merged[result.Component]; found && existing != result {
			return fmt.Errorf("component %q has conflicting conformance results", result.Component)
		}
		merged[result.Component] = result
	}
	collector.results = merged
	return nil
}

func (collector *Collector) Report() Report {
	collector.mu.RLock()
	results := make([]Result, 0, len(collector.results))
	for _, result := range collector.results {
		results = append(results, result)
	}
	collector.mu.RUnlock()

	sort.Slice(results, func(left, right int) bool {
		return results[left].Component < results[right].Component
	})
	return Report{SchemaVersion: reportSchemaVersion, Results: results}
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
		if profile.Production && (result.Evidence.Mock || component == "mock" || strings.HasPrefix(component, "mock-") || strings.HasPrefix(component, "fake-")) {
			return fmt.Errorf("production profile %q rejects synthetic component %q", profile.Name, component)
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
	for field, digest := range map[string]string{
		"binaryDigest":      result.Evidence.BinaryDigest,
		"environmentDigest": result.Evidence.EnvironmentDigest,
	} {
		if digest != "" && !sha256Pattern.MatchString(digest) {
			return fmt.Errorf("component %q evidence %s is not a canonical SHA-256 digest", result.Component, field)
		}
	}
	return nil
}
