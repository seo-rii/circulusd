package extensionregistry

import (
	"fmt"
	"sort"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/environment"
)

func (registry *Registry) CompileRuntime(request CompileRequest) (RuntimeRevision, error) {
	if registry == nil || registry.resolver == nil || len(request.Selections) == 0 || len(request.Selections) > 256 {
		return RuntimeRevision{}, ErrInvalidRequest
	}
	if !digestPattern.MatchString(request.Workerd.BinaryDigest) || !digestPattern.MatchString(request.Pi.PackageDigest) || request.Workerd.LoaderABIVersion == 0 || request.Workerd.LoaderABIVersion > maxSafeInteger || request.Pi.AdapterABIVersion == 0 || request.Pi.AdapterABIVersion > maxSafeInteger || request.PolicyGeneration == 0 || request.PolicyGeneration > maxSafeInteger || request.Pi.AgentEngine != "low-level" {
		return RuntimeRevision{}, fmt.Errorf("%w: invalid runtime binary or ABI pin", ErrInvalidRequest)
	}
	compatibilityDate, err := time.Parse("2006-01-02", request.Workerd.CompatibilityDate)
	if err != nil || compatibilityDate.Format("2006-01-02") != request.Workerd.CompatibilityDate {
		return RuntimeRevision{}, fmt.Errorf("%w: workerd compatibility date is not canonical", ErrInvalidRequest)
	}
	flags, err := canonical.NormalizeStringSet(request.Workerd.CompatibilityFlags)
	if err != nil || len(flags) > 256 {
		return RuntimeRevision{}, fmt.Errorf("%w: compatibility flags are invalid", ErrInvalidRequest)
	}
	for _, flag := range flags {
		if !identifierPattern.MatchString(flag) {
			return RuntimeRevision{}, fmt.Errorf("%w: compatibility flag %q is invalid", ErrInvalidRequest, flag)
		}
	}
	if err := validateIsolation(request.PolicyMinimumIsolation); err != nil {
		return RuntimeRevision{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	switch request.Architecture {
	case environment.ArchitectureX8664, environment.ArchitectureAArch64:
	default:
		return RuntimeRevision{}, fmt.Errorf("%w: unsupported architecture %q", ErrInvalidRequest, request.Architecture)
	}
	switch request.Backend {
	case environment.BackendNsJail, environment.BackendDocker, environment.BackendFirecracker:
	default:
		return RuntimeRevision{}, fmt.Errorf("%w: unsupported backend %q", ErrInvalidRequest, request.Backend)
	}

	selections := append([]Selection(nil), request.Selections...)
	sort.Slice(selections, func(left, right int) bool {
		if selections[left].ID != selections[right].ID {
			return selections[left].ID < selections[right].ID
		}
		return selections[left].Version < selections[right].Version
	})
	selected := make([]installedRevision, 0, len(selections))
	seenSelections := make(map[string]struct{}, len(selections))
	for _, selection := range selections {
		if !extensionIDPattern.MatchString(selection.ID) || !semverPattern.MatchString(selection.Version) {
			return RuntimeRevision{}, fmt.Errorf("%w: selected coordinate is not canonical", ErrInvalidRequest)
		}
		if _, duplicate := seenSelections[selection.ID]; duplicate {
			return RuntimeRevision{}, fmt.Errorf("%w: extension %q was selected more than once", ErrInvalidRequest, selection.ID)
		}
		seenSelections[selection.ID] = struct{}{}
		installed, found := registry.revisions[selection.ID+"\x00"+selection.Version]
		if !found {
			return RuntimeRevision{}, fmt.Errorf("%w: %s@%s", ErrNotFound, selection.ID, selection.Version)
		}
		selected = append(selected, installed)
	}
	if len(request.Configuration) != len(selected) {
		return RuntimeRevision{}, fmt.Errorf("%w: configuration must be an exact selected-extension snapshot", ErrInvalidRequest)
	}
	for extensionID := range request.Configuration {
		if _, found := seenSelections[extensionID]; !found {
			return RuntimeRevision{}, fmt.Errorf("%w: configuration for unselected extension %q", ErrInvalidRequest, extensionID)
		}
	}
	for extensionID := range seenSelections {
		if _, found := request.Configuration[extensionID]; !found {
			return RuntimeRevision{}, fmt.Errorf("%w: configuration for selected extension %q is missing", ErrInvalidRequest, extensionID)
		}
	}
	configurationDigest, err := canonical.StructuredDigest("circulusd.runtime.extension-configuration", 1, request.Configuration)
	if err != nil {
		return RuntimeRevision{}, fmt.Errorf("%w: configuration is not canonical: %v", ErrInvalidRequest, err)
	}

	minimumIsolation := request.PolicyMinimumIsolation
	tools := make(map[string]string)
	requirements := make([]sourcedRequirement, 0)
	extensions := make([]ResolvedExtension, len(selected))
	for index, installed := range selected {
		revisionBackends := make(map[environment.Backend]struct{}, len(installed.revision.SupportedBackends))
		for _, backend := range installed.revision.SupportedBackends {
			revisionBackends[backend] = struct{}{}
		}
		assessmentBackends := make(map[environment.Backend]struct{}, len(installed.assessment.AllowedExecutionBackends))
		for _, backend := range installed.assessment.AllowedExecutionBackends {
			assessmentBackends[backend] = struct{}{}
		}
		_, revisionSupportsBackend := revisionBackends[request.Backend]
		_, assessmentAllowsBackend := assessmentBackends[request.Backend]
		if !revisionSupportsBackend || !assessmentAllowsBackend {
			return RuntimeRevision{}, fmt.Errorf("%w: backend %q is not allowed for %s", ErrNoCompatibleBackend, request.Backend, installed.revision.ID)
		}
		minimumIsolation = joinIsolation(minimumIsolation, installed.revision.RequestedMinimumIsolation)
		minimumIsolation = joinIsolation(minimumIsolation, installed.assessment.MinimumIsolation)
		for _, tool := range installed.revision.Tools {
			if owner, collision := tools[tool]; collision {
				return RuntimeRevision{}, fmt.Errorf("%w: tool %q is declared by %s and %s", ErrConflict, tool, owner, installed.revision.ID)
			}
			tools[tool] = installed.revision.ID
		}
		for _, requirement := range installed.revision.NativeRequirements {
			requirements = append(requirements, sourcedRequirement{extensionID: installed.revision.ID, requirement: requirement})
		}
		extensions[index] = ResolvedExtension{
			ID: installed.revision.ID, Version: installed.revision.Version,
			ContentDigest: installed.revision.ContentDigest, RevisionDigest: installed.revision.RevisionDigest,
		}
	}
	if !backendSatisfies(request.Backend, minimumIsolation.OuterIsolation) {
		return RuntimeRevision{}, fmt.Errorf("%w: backend %q is weaker than minimum outer isolation %q", ErrNoCompatibleBackend, request.Backend, minimumIsolation.OuterIsolation)
	}

	sort.Slice(requirements, func(left, right int) bool {
		if requirements[left].requirement.PackageID != requirements[right].requirement.PackageID {
			return requirements[left].requirement.PackageID < requirements[right].requirement.PackageID
		}
		if requirements[left].requirement.Constraint != requirements[right].requirement.Constraint {
			return requirements[left].requirement.Constraint < requirements[right].requirement.Constraint
		}
		return requirements[left].extensionID < requirements[right].extensionID
	})
	requirementValues := make(canonical.Array, len(requirements))
	environmentRequirements := make([]environment.Requirement, len(requirements))
	for index, requirement := range requirements {
		requirementValues[index] = canonical.Map{
			"extensionId": requirement.extensionID,
			"packageId":   requirement.requirement.PackageID,
			"constraint":  requirement.requirement.Constraint,
		}
		normalizedConstraint, normalizeErr := normalizeConstraint(requirement.requirement.Constraint)
		if normalizeErr != nil {
			return RuntimeRevision{}, fmt.Errorf("%w: normalize native requirement: %v", ErrInvalidRequest, normalizeErr)
		}
		environmentRequirements[index] = environment.Requirement{PackageID: requirement.requirement.PackageID, Constraint: normalizedConstraint}
	}
	environmentRequirementDigest, err := canonical.StructuredDigest("circulusd.runtime.execution-environment-requirements", 1, requirementValues)
	if err != nil {
		return RuntimeRevision{}, fmt.Errorf("%w: digest environment requirements: %v", ErrInvalidRequest, err)
	}
	environmentRequest := environment.Request{
		Architecture: request.Architecture, RequiredBackends: []environment.Backend{request.Backend}, Requirements: environmentRequirements,
	}
	resolvedEnvironment, err := registry.resolver.Resolve(environmentRequest)
	if err != nil {
		return RuntimeRevision{}, err
	}
	verifyingResolver, err := environment.NewResolver([]environment.Revision{resolvedEnvironment})
	if err != nil {
		return RuntimeRevision{}, err
	}
	verifiedEnvironment, err := verifyingResolver.Resolve(environmentRequest)
	if err != nil || verifiedEnvironment.Digest != resolvedEnvironment.Digest || verifiedEnvironment.ID != resolvedEnvironment.ID {
		return RuntimeRevision{}, fmt.Errorf("%w: resolver returned a revision that does not satisfy the request", environment.ErrInvalidRevision)
	}

	extensionValues := make(canonical.Array, len(extensions))
	for index, extension := range extensions {
		extensionValues[index] = canonical.Map{
			"id": extension.ID, "version": extension.Version,
			"contentDigest": extension.ContentDigest, "revisionDigest": extension.RevisionDigest,
		}
	}
	agentBundleDigest, err := canonical.StructuredDigest("circulusd.agent-bundle", 1, canonical.Map{
		"piPackageDigest": request.Pi.PackageDigest,
		"extensions":      extensionValues,
	})
	if err != nil {
		return RuntimeRevision{}, fmt.Errorf("%w: digest agent bundle: %v", ErrInvalidRequest, err)
	}
	hookOrder := append([]installedRevision(nil), selected...)
	sort.Slice(hookOrder, func(left, right int) bool {
		if hookOrder[left].revision.Priority != hookOrder[right].revision.Priority {
			return hookOrder[left].revision.Priority < hookOrder[right].revision.Priority
		}
		return hookOrder[left].revision.ID < hookOrder[right].revision.ID
	})
	hookIDs := make([]string, len(hookOrder))
	for index, installed := range hookOrder {
		hookIDs[index] = installed.revision.ID
	}
	flagValues := make(canonical.Array, len(flags))
	for index, flag := range flags {
		flagValues[index] = flag
	}
	runtimeDigest, err := canonical.StructuredDigest("circulusd.runtime-revision", 1, canonical.Map{
		"workerd": canonical.Map{
			"binaryDigest": request.Workerd.BinaryDigest, "compatibilityDate": request.Workerd.CompatibilityDate,
			"compatibilityFlags": flagValues, "loaderAbiVersion": request.Workerd.LoaderABIVersion,
		},
		"pi": canonical.Map{
			"packageDigest": request.Pi.PackageDigest, "adapterAbiVersion": request.Pi.AdapterABIVersion, "agentEngine": request.Pi.AgentEngine,
		},
		"agentBundleDigest":                     agentBundleDigest,
		"extensions":                            extensionValues,
		"configurationDigest":                   configurationDigest,
		"executionEnvironmentRequirementDigest": environmentRequirementDigest,
		"executionEnvironmentDigest":            resolvedEnvironment.Digest,
		"backend":                               string(request.Backend),
		"minimumIsolation":                      isolationValue(minimumIsolation),
		"policyGeneration":                      request.PolicyGeneration,
	})
	if err != nil {
		return RuntimeRevision{}, fmt.Errorf("%w: digest runtime revision: %v", ErrInvalidRequest, err)
	}
	resolvedEnvironment.Packages = append([]environment.Package(nil), resolvedEnvironment.Packages...)
	if resolvedEnvironment.Artifacts.NsJail != nil {
		artifact := *resolvedEnvironment.Artifacts.NsJail
		resolvedEnvironment.Artifacts.NsJail = &artifact
	}
	if resolvedEnvironment.Artifacts.Docker != nil {
		artifact := *resolvedEnvironment.Artifacts.Docker
		resolvedEnvironment.Artifacts.Docker = &artifact
	}
	if resolvedEnvironment.Artifacts.Firecracker != nil {
		artifact := *resolvedEnvironment.Artifacts.Firecracker
		resolvedEnvironment.Artifacts.Firecracker = &artifact
	}
	return RuntimeRevision{
		Digest: runtimeDigest,
		Workerd: WorkerdRevision{
			BinaryDigest: request.Workerd.BinaryDigest, CompatibilityDate: request.Workerd.CompatibilityDate,
			CompatibilityFlags: append([]string(nil), flags...), LoaderABIVersion: request.Workerd.LoaderABIVersion,
		},
		Pi:                PiRevision{PackageDigest: request.Pi.PackageDigest, AdapterABIVersion: request.Pi.AdapterABIVersion, AgentEngine: request.Pi.AgentEngine},
		AgentBundleDigest: agentBundleDigest, Extensions: append([]ResolvedExtension(nil), extensions...), HookOrder: hookIDs,
		ConfigurationDigest: configurationDigest, EnvironmentRequirementDigest: environmentRequirementDigest,
		Environment: resolvedEnvironment, Backend: request.Backend, MinimumIsolation: minimumIsolation,
		PolicyGeneration: request.PolicyGeneration,
	}, nil
}

type sourcedRequirement struct {
	extensionID string
	requirement environment.Requirement
}

func joinIsolation(left, right Isolation) Isolation {
	result := left
	processRanks := map[ProcessScope]int{ProcessScopeShared: 0, ProcessScopeTenant: 1, ProcessScopeSession: 2}
	if processRanks[right.ProcessScope] > processRanks[result.ProcessScope] {
		result.ProcessScope = right.ProcessScope
	}
	outerRanks := map[OuterIsolation]int{OuterIsolationNone: 0, OuterIsolationNsJail: 1, OuterIsolationDocker: 1, OuterIsolationFirecracker: 2}
	if outerRanks[right.OuterIsolation] > outerRanks[result.OuterIsolation] {
		result.OuterIsolation = right.OuterIsolation
	} else if outerRanks[right.OuterIsolation] == outerRanks[result.OuterIsolation] && right.OuterIsolation != result.OuterIsolation {
		result.OuterIsolation = OuterIsolationFirecracker
	}
	return result
}

func backendSatisfies(backend environment.Backend, minimum OuterIsolation) bool {
	if minimum == OuterIsolationNone {
		return true
	}
	if backend == environment.BackendFirecracker {
		return true
	}
	return (backend == environment.BackendNsJail && minimum == OuterIsolationNsJail) ||
		(backend == environment.BackendDocker && minimum == OuterIsolationDocker)
}
