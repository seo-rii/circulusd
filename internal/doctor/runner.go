// Package doctor runs identity-bound conformance probes without treating
// synthetic or missing evidence as production qualification.
package doctor

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/hancomac/circulusd/internal/conformance"
)

const (
	reportAPIVersion       = "v1alpha"
	reportSchemaVersion    = 1
	maximumDoctorReportAge = 24 * time.Hour
	maximumReportItems     = 256
	maximumArtifactItems   = 64
	maximumReasonLength    = 1024
	maximumVersionLength   = 128
	maximumKernelLength    = 256
)

var (
	digestPattern       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	identifierPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
	architecturePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

type Probe struct {
	Component string
	Run       func(context.Context) conformance.Result
}

type Plan struct {
	RunID              string
	Profile            conformance.Profile
	ConfigDigest       string
	ReleaseDigest      string
	HostID             string
	RunnerBinaryDigest string
	TargetInstanceID   string
	Clock              func() time.Time
	Probes             []Probe
}

type Report struct {
	SchemaVersion      int                  `json:"schemaVersion"`
	APIVersion         string               `json:"apiVersion"`
	RunID              string               `json:"probeRunId"`
	Profile            string               `json:"profile"`
	ConfigDigest       string               `json:"configDigest"`
	ReleaseDigest      string               `json:"releaseDigest"`
	HostID             string               `json:"hostId"`
	RunnerBinaryDigest string               `json:"runnerBinaryDigest"`
	TargetInstanceID   string               `json:"targetInstanceId"`
	ProductionProfile  bool                 `json:"productionProfile"`
	RequiredComponents []string             `json:"requiredComponents"`
	StartedAt          time.Time            `json:"startedAt"`
	FinishedAt         time.Time            `json:"finishedAt"`
	ObservedAt         time.Time            `json:"observedAt"`
	ProfileQualified   bool                 `json:"profileQualified"`
	ProductionEligible bool                 `json:"productionEligible"`
	FailureReason      string               `json:"failureReason,omitempty"`
	Results            []conformance.Result `json:"results"`
}

type CurrentIdentity struct {
	Profile            string
	ConfigDigest       string
	ReleaseDigest      string
	HostID             string
	RunnerBinaryDigest string
	TargetInstanceID   string
	ProductionProfile  bool
	RequiredComponents []string
	Now                time.Time
	MaximumAge         time.Duration
}

func Run(ctx context.Context, plan Plan) (Report, error) {
	if ctx == nil || ctx.Err() != nil {
		if ctx == nil {
			return Report{}, fmt.Errorf("doctor: context is required")
		}
		return Report{}, ctx.Err()
	}
	probes := append([]Probe(nil), plan.Probes...)
	if !identifierPattern.MatchString(plan.RunID) ||
		!identifierPattern.MatchString(plan.Profile.Name) ||
		!identifierPattern.MatchString(plan.HostID) ||
		!identifierPattern.MatchString(plan.TargetInstanceID) ||
		!digestPattern.MatchString(plan.ConfigDigest) ||
		!digestPattern.MatchString(plan.ReleaseDigest) ||
		!digestPattern.MatchString(plan.RunnerBinaryDigest) ||
		plan.Clock == nil || len(plan.Profile.Required) == 0 ||
		len(plan.Profile.Required) > maximumReportItems || len(probes) > maximumReportItems {
		return Report{}, fmt.Errorf("doctor: plan identity is invalid")
	}

	requiredComponents := append([]string(nil), plan.Profile.Required...)
	sort.Strings(requiredComponents)
	reportProfile := plan.Profile
	reportProfile.Required = requiredComponents
	validationCollector := conformance.NewCollector()
	for _, component := range reportProfile.Required {
		if err := validationCollector.Add(conformance.Result{
			Component: component,
			Status:    conformance.Pass,
			Evidence: conformance.Evidence{
				Class: conformance.EvidenceClassExternal,
			},
		}); err != nil {
			return Report{}, fmt.Errorf("doctor: required component: %w", err)
		}
	}
	if err := validationCollector.Evaluate(reportProfile); err != nil {
		return Report{}, fmt.Errorf("doctor: profile: %w", err)
	}

	configured := make(map[string]struct{}, len(probes))
	for _, probe := range probes {
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
	reportItemCount := len(configured)
	for _, component := range reportProfile.Required {
		if _, found := configured[component]; !found {
			reportItemCount++
		}
	}
	if reportItemCount > maximumReportItems {
		return Report{}, fmt.Errorf("doctor: plan produces too many results")
	}

	startedAt := plan.Clock().UTC()
	if startedAt.IsZero() {
		return Report{}, fmt.Errorf("doctor: clock returned zero time")
	}
	collector := conformance.NewCollector()
	for _, probe := range probes {
		result := func() (result conformance.Result) {
			defer func() {
				if recover() != nil {
					result = conformance.Result{
						Component: probe.Component,
						Status:    conformance.Fail,
						Reason:    "probe panicked",
						Evidence:  reportEvidence(conformance.EvidenceClassExternal, nil),
					}
				}
			}()
			if err := ctx.Err(); err != nil {
				return conformance.Result{
					Component: probe.Component,
					Status:    conformance.NotRun,
					Reason:    "probe canceled",
					Evidence:  reportEvidence(conformance.EvidenceClassExternal, nil),
				}
			}
			candidate := probe.Run(ctx)
			candidate.Evidence.ArtifactReferences = append(
				[]conformance.ArtifactReference(nil),
				candidate.Evidence.ArtifactReferences...,
			)
			if candidate.Evidence.ArtifactReferences == nil {
				candidate.Evidence.ArtifactReferences = make([]conformance.ArtifactReference, 0)
			}
			sort.Slice(candidate.Evidence.ArtifactReferences, func(left, right int) bool {
				return candidate.Evidence.ArtifactReferences[left].Name < candidate.Evidence.ArtifactReferences[right].Name
			})
			if candidate.Evidence.Class == "" {
				switch {
				case candidate.Evidence.Mock:
					candidate.Evidence.Class = conformance.EvidenceClassReferenceOnly
				case strings.HasPrefix(probe.Component, "host."):
					candidate.Evidence.Class = conformance.EvidenceClassHostObservation
				case candidate.Status == conformance.Pass && reportProfile.Production:
					return conformance.Result{
						Component: probe.Component,
						Status:    conformance.Fail,
						Reason:    "production probe PASS omitted evidenceClass",
						Evidence:  reportEvidence(conformance.EvidenceClassExternal, nil),
					}
				case candidate.Status == conformance.Pass:
					candidate.Evidence.Class = conformance.EvidenceClassReferenceOnly
				default:
					candidate.Evidence.Class = conformance.EvidenceClassExternal
				}
			}
			if err := ctx.Err(); err != nil {
				return conformance.Result{
					Component: probe.Component,
					Status:    conformance.NotRun,
					Reason:    "probe canceled",
					Evidence:  reportEvidence(candidate.Evidence.Class, candidate.Evidence.ArtifactReferences),
				}
			}
			if candidate.Component != probe.Component {
				return conformance.Result{
					Component: probe.Component,
					Status:    conformance.Fail,
					Reason:    "probe returned evidence for a different component",
					Evidence:  reportEvidence(conformance.EvidenceClassExternal, nil),
				}
			}
			if !validReportEvidence(candidate) {
				return conformance.Result{
					Component: probe.Component,
					Status:    conformance.Fail,
					Reason:    "probe returned invalid evidence",
					Evidence:  reportEvidence(conformance.EvidenceClassExternal, nil),
				}
			}
			candidateCollector := conformance.NewCollector()
			if err := candidateCollector.Add(candidate); err != nil {
				return conformance.Result{
					Component: probe.Component,
					Status:    conformance.Fail,
					Reason:    "probe returned invalid evidence",
					Evidence:  reportEvidence(conformance.EvidenceClassExternal, nil),
				}
			}
			return candidate
		}()
		if err := collector.Add(result); err != nil {
			return Report{}, fmt.Errorf("doctor: collect probe %q: %w", probe.Component, err)
		}
	}
	for _, component := range reportProfile.Required {
		if _, found := configured[component]; found {
			continue
		}
		if err := collector.Add(conformance.Result{
			Component: component,
			Status:    conformance.NotRun,
			Reason:    "required probe is not configured",
			Evidence:  reportEvidence(conformance.EvidenceClassExternal, nil),
		}); err != nil {
			return Report{}, fmt.Errorf("doctor: collect missing probe %q: %w", component, err)
		}
	}

	finishedAt := plan.Clock().UTC()
	if finishedAt.IsZero() || finishedAt.Before(startedAt) {
		return Report{}, fmt.Errorf("doctor: clock moved backwards")
	}
	evaluationError := collector.Evaluate(reportProfile)
	report := Report{
		SchemaVersion:      reportSchemaVersion,
		APIVersion:         reportAPIVersion,
		RunID:              plan.RunID,
		Profile:            plan.Profile.Name,
		ConfigDigest:       plan.ConfigDigest,
		ReleaseDigest:      plan.ReleaseDigest,
		HostID:             plan.HostID,
		RunnerBinaryDigest: plan.RunnerBinaryDigest,
		TargetInstanceID:   plan.TargetInstanceID,
		ProductionProfile:  reportProfile.Production,
		RequiredComponents: append([]string(nil), reportProfile.Required...),
		StartedAt:          startedAt,
		FinishedAt:         finishedAt,
		ObservedAt:         finishedAt,
		ProfileQualified:   evaluationError == nil,
		ProductionEligible: reportProfile.Production && evaluationError == nil,
		Results:            collector.Report().Results,
	}
	if evaluationError != nil {
		report.FailureReason = strings.TrimSpace(evaluationError.Error())
	}
	if err := validateReport(report); err != nil {
		return Report{}, fmt.Errorf("doctor: generated report: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	return report, nil
}

func ValidateCurrent(report Report, current CurrentIdentity) error {
	if err := validateReport(report); err != nil {
		return err
	}
	if !identifierPattern.MatchString(current.Profile) ||
		!identifierPattern.MatchString(current.HostID) ||
		!identifierPattern.MatchString(current.TargetInstanceID) ||
		!digestPattern.MatchString(current.ConfigDigest) ||
		!digestPattern.MatchString(current.ReleaseDigest) ||
		!digestPattern.MatchString(current.RunnerBinaryDigest) ||
		!validRequiredComponents(current.RequiredComponents) ||
		current.Now.IsZero() || current.MaximumAge <= 0 ||
		current.MaximumAge > maximumDoctorReportAge {
		return fmt.Errorf("doctor: current identity is invalid")
	}
	if report.Profile != current.Profile ||
		report.ConfigDigest != current.ConfigDigest ||
		report.ReleaseDigest != current.ReleaseDigest ||
		report.HostID != current.HostID ||
		report.RunnerBinaryDigest != current.RunnerBinaryDigest ||
		report.TargetInstanceID != current.TargetInstanceID ||
		report.ProductionProfile != current.ProductionProfile ||
		!slices.Equal(report.RequiredComponents, current.RequiredComponents) {
		return fmt.Errorf("doctor: report identity does not match the current target")
	}
	now := current.Now.UTC()
	if report.ObservedAt.After(now) || report.FinishedAt.After(now) {
		return fmt.Errorf("doctor: report evidence window is in the future")
	}
	if now.Sub(report.StartedAt) > current.MaximumAge {
		return fmt.Errorf("doctor: report evidence is stale")
	}
	return nil
}

func validateReport(report Report) error {
	if report.SchemaVersion != reportSchemaVersion || report.APIVersion != reportAPIVersion ||
		!identifierPattern.MatchString(report.RunID) ||
		!identifierPattern.MatchString(report.Profile) ||
		!identifierPattern.MatchString(report.HostID) ||
		!identifierPattern.MatchString(report.TargetInstanceID) ||
		!digestPattern.MatchString(report.ConfigDigest) ||
		!digestPattern.MatchString(report.ReleaseDigest) ||
		!digestPattern.MatchString(report.RunnerBinaryDigest) ||
		report.StartedAt.IsZero() || report.FinishedAt.IsZero() || report.ObservedAt.IsZero() ||
		report.FinishedAt.Before(report.StartedAt) ||
		report.FinishedAt.Sub(report.StartedAt) > maximumDoctorReportAge ||
		report.ObservedAt.Before(report.StartedAt) || report.ObservedAt.After(report.FinishedAt) ||
		!validRequiredComponents(report.RequiredComponents) || len(report.Results) == 0 ||
		len(report.Results) > maximumReportItems ||
		len(report.FailureReason) > maximumReasonLength {
		return fmt.Errorf("doctor: report structure is invalid")
	}
	collector := conformance.NewCollector()
	previous := ""
	for _, result := range report.Results {
		if !validReportEvidence(result) ||
			previous != "" && previous >= result.Component {
			return fmt.Errorf("doctor: report evidence is invalid")
		}
		if err := collector.Add(result); err != nil {
			return fmt.Errorf("doctor: report evidence is invalid: %w", err)
		}
		previous = result.Component
	}
	evaluationError := collector.Evaluate(conformance.Profile{
		Name:       report.Profile,
		Production: report.ProductionProfile,
		Required:   report.RequiredComponents,
	})
	qualified := evaluationError == nil
	eligible := report.ProductionProfile && qualified
	if eligible {
		for _, result := range report.Results {
			if result.Status == conformance.Pass &&
				result.Evidence.Class != conformance.EvidenceClassExternal &&
				result.Evidence.Class != conformance.EvidenceClassHostObservation {
				return fmt.Errorf("doctor: production report contains non-production PASS evidence")
			}
		}
	}
	failureReason := ""
	if evaluationError != nil {
		failureReason = strings.TrimSpace(evaluationError.Error())
	}
	if report.ProfileQualified != qualified || report.ProductionEligible != eligible ||
		report.FailureReason != failureReason {
		return fmt.Errorf("doctor: report qualification summary is invalid")
	}
	return nil
}

func validRequiredComponents(components []string) bool {
	if len(components) == 0 || len(components) > maximumReportItems {
		return false
	}
	validator := conformance.NewCollector()
	previous := ""
	for _, component := range components {
		if previous != "" && previous >= component {
			return false
		}
		if err := validator.Add(conformance.Result{
			Component: component,
			Status:    conformance.NotRun,
		}); err != nil {
			return false
		}
		previous = component
	}
	return true
}

func validResultReason(result conformance.Result) bool {
	reasonLength := len(result.Reason)
	if result.Status == conformance.Pass {
		return reasonLength == 0
	}
	return strings.TrimSpace(result.Reason) != "" && reasonLength <= maximumReasonLength
}

func validReportEvidence(result conformance.Result) bool {
	if result.Evidence.Class == "" || result.Evidence.ArtifactReferences == nil ||
		len(result.Evidence.ArtifactReferences) > maximumArtifactItems ||
		len(result.Evidence.Version) > maximumVersionLength ||
		len(result.Evidence.Kernel) > maximumKernelLength ||
		result.Evidence.Architecture != "" && !architecturePattern.MatchString(result.Evidence.Architecture) ||
		result.Evidence.Class == conformance.EvidenceClassHostObservation &&
			!strings.HasPrefix(result.Component, "host.") {
		return false
	}
	previousArtifact := ""
	for _, artifact := range result.Evidence.ArtifactReferences {
		if previousArtifact != "" && previousArtifact >= artifact.Name {
			return false
		}
		previousArtifact = artifact.Name
	}
	return validResultReason(result)
}

func reportEvidence(
	class conformance.EvidenceClass,
	artifacts []conformance.ArtifactReference,
) conformance.Evidence {
	cloned := make([]conformance.ArtifactReference, len(artifacts))
	copy(cloned, artifacts)
	return conformance.Evidence{
		Class:              class,
		ArtifactReferences: cloned,
	}
}
