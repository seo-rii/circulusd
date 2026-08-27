// Package doctor runs identity-bound conformance probes without treating
// synthetic or missing evidence as production qualification.
package doctor

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hancomac/circulusd/internal/conformance"
)

const reportSchemaVersion = 1

var (
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
)

type Probe struct {
	Component string
	Run       func(context.Context) conformance.Result
}

type Plan struct {
	RunID         string
	Profile       conformance.Profile
	ConfigDigest  string
	ReleaseDigest string
	HostID        string
	Clock         func() time.Time
	Probes        []Probe
}

type Report struct {
	SchemaVersion      int                  `json:"schemaVersion"`
	RunID              string               `json:"runId"`
	Profile            string               `json:"profile"`
	ConfigDigest       string               `json:"configDigest"`
	ReleaseDigest      string               `json:"releaseDigest"`
	HostID             string               `json:"hostId"`
	StartedAt          time.Time            `json:"startedAt"`
	FinishedAt         time.Time            `json:"finishedAt"`
	ProfileQualified   bool                 `json:"profileQualified"`
	ProductionEligible bool                 `json:"productionEligible"`
	FailureReason      string               `json:"failureReason,omitempty"`
	Results            []conformance.Result `json:"results"`
}

func Run(ctx context.Context, plan Plan) (Report, error) {
	if ctx == nil || ctx.Err() != nil {
		if ctx == nil {
			return Report{}, fmt.Errorf("doctor: context is required")
		}
		return Report{}, ctx.Err()
	}
	if !identifierPattern.MatchString(plan.RunID) ||
		!identifierPattern.MatchString(plan.HostID) ||
		!digestPattern.MatchString(plan.ConfigDigest) ||
		!digestPattern.MatchString(plan.ReleaseDigest) ||
		plan.Clock == nil || len(plan.Profile.Required) == 0 {
		return Report{}, fmt.Errorf("doctor: plan identity is invalid")
	}

	validationCollector := conformance.NewCollector()
	for _, component := range plan.Profile.Required {
		if err := validationCollector.Add(conformance.Result{
			Component: component,
			Status:    conformance.Pass,
		}); err != nil {
			return Report{}, fmt.Errorf("doctor: required component: %w", err)
		}
	}
	if err := validationCollector.Evaluate(plan.Profile); err != nil {
		return Report{}, fmt.Errorf("doctor: profile: %w", err)
	}

	configured := make(map[string]struct{}, len(plan.Probes))
	for _, probe := range plan.Probes {
		if probe.Run == nil {
			return Report{}, fmt.Errorf("doctor: probe %q has no runner", probe.Component)
		}
		probeValidation := conformance.NewCollector()
		if err := probeValidation.Add(conformance.Result{
			Component: probe.Component,
			Status:    conformance.NotRun,
		}); err != nil {
			return Report{}, fmt.Errorf("doctor: probe component: %w", err)
		}
		if _, duplicate := configured[probe.Component]; duplicate {
			return Report{}, fmt.Errorf("doctor: probe %q is duplicated", probe.Component)
		}
		configured[probe.Component] = struct{}{}
	}

	startedAt := plan.Clock().UTC()
	if startedAt.IsZero() {
		return Report{}, fmt.Errorf("doctor: clock returned zero time")
	}
	collector := conformance.NewCollector()
	for _, probe := range plan.Probes {
		result := func() (result conformance.Result) {
			defer func() {
				if recover() != nil {
					result = conformance.Result{
						Component: probe.Component,
						Status:    conformance.Fail,
						Reason:    "probe panicked",
					}
				}
			}()
			if err := ctx.Err(); err != nil {
				return conformance.Result{
					Component: probe.Component,
					Status:    conformance.Fail,
					Reason:    "probe canceled",
				}
			}
			candidate := probe.Run(ctx)
			if candidate.Component != probe.Component {
				return conformance.Result{
					Component: probe.Component,
					Status:    conformance.Fail,
					Reason:    "probe returned evidence for a different component",
				}
			}
			candidateCollector := conformance.NewCollector()
			if err := candidateCollector.Add(candidate); err != nil {
				return conformance.Result{
					Component: probe.Component,
					Status:    conformance.Fail,
					Reason:    "probe returned invalid evidence",
				}
			}
			return candidate
		}()
		if err := collector.Add(result); err != nil {
			return Report{}, fmt.Errorf("doctor: collect probe %q: %w", probe.Component, err)
		}
	}
	for _, component := range plan.Profile.Required {
		if _, found := configured[component]; found {
			continue
		}
		if err := collector.Add(conformance.Result{
			Component: component,
			Status:    conformance.NotRun,
			Reason:    "required probe is not configured",
		}); err != nil {
			return Report{}, fmt.Errorf("doctor: collect missing probe %q: %w", component, err)
		}
	}

	finishedAt := plan.Clock().UTC()
	if finishedAt.IsZero() || finishedAt.Before(startedAt) {
		return Report{}, fmt.Errorf("doctor: clock moved backwards")
	}
	evaluationError := collector.Evaluate(plan.Profile)
	report := Report{
		SchemaVersion:      reportSchemaVersion,
		RunID:              plan.RunID,
		Profile:            plan.Profile.Name,
		ConfigDigest:       plan.ConfigDigest,
		ReleaseDigest:      plan.ReleaseDigest,
		HostID:             plan.HostID,
		StartedAt:          startedAt,
		FinishedAt:         finishedAt,
		ProfileQualified:   evaluationError == nil,
		ProductionEligible: plan.Profile.Production && evaluationError == nil,
		Results:            collector.Report().Results,
	}
	if evaluationError != nil {
		report.FailureReason = strings.TrimSpace(evaluationError.Error())
	}
	return report, nil
}
