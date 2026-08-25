package executor

import "fmt"

// ResolveBackend selects one exact backend without silent fallback. The
// result is a pure value: no returned slice aliases caller-controlled memory.
func ResolveBackend(selection BackendSelection) (BackendSelectionResult, error) {
	if selection.Mode != DeploymentDevelopment && selection.Mode != DeploymentProduction {
		return BackendSelectionResult{}, fmt.Errorf(
			"%w: unsupported deployment mode %q",
			ErrInvalidSpec,
			selection.Mode,
		)
	}
	if selection.MinimumIsolation != IsolationSharedKernel && selection.MinimumIsolation != IsolationMicroVM {
		return BackendSelectionResult{}, fmt.Errorf(
			"%w: unsupported minimum isolation %q",
			ErrInvalidSpec,
			selection.MinimumIsolation,
		)
	}

	preferences := []struct {
		name    string
		backend Backend
	}{
		{name: "tool/session", backend: selection.ToolOrSession},
		{name: "workspace", backend: selection.WorkspaceDefault},
		{name: "user", backend: selection.UserDefault},
		{name: "server", backend: selection.ServerDefault},
	}
	requested := Backend("")
	for _, preference := range preferences {
		if preference.backend == "" {
			continue
		}
		switch preference.backend {
		case BackendNsJail, BackendDocker, BackendFirecracker, BackendMock:
		default:
			return BackendSelectionResult{}, fmt.Errorf(
				"%w: %s preference names unsupported backend %q",
				ErrInvalidSpec,
				preference.name,
				preference.backend,
			)
		}
		if requested == "" {
			requested = preference.backend
		}
	}
	if requested == "" {
		return BackendSelectionResult{}, fmt.Errorf("%w: no backend preference is configured", ErrInvalidSpec)
	}

	constraintInputs := []struct {
		name     string
		backends []Backend
	}{
		{name: "server allowed", backends: selection.ServerAllowed},
		{name: "registry allowed", backends: selection.RegistryAllowed},
		{name: "extension supported", backends: selection.ExtensionSupported},
		{name: "environment artifacts", backends: selection.EnvironmentArtifacts},
	}
	constraintSets := make([]map[Backend]struct{}, 0, len(constraintInputs))
	for _, input := range constraintInputs {
		if len(input.backends) == 0 {
			return BackendSelectionResult{}, fmt.Errorf("%w: %s set is empty", ErrInvalidSpec, input.name)
		}
		set := make(map[Backend]struct{}, len(input.backends))
		for _, backend := range input.backends {
			switch backend {
			case BackendNsJail, BackendDocker, BackendFirecracker, BackendMock:
			default:
				return BackendSelectionResult{}, fmt.Errorf(
					"%w: %s set names unsupported backend %q",
					ErrInvalidSpec,
					input.name,
					backend,
				)
			}
			if _, duplicate := set[backend]; duplicate {
				return BackendSelectionResult{}, fmt.Errorf(
					"%w: %s set repeats backend %q",
					ErrInvalidSpec,
					input.name,
					backend,
				)
			}
			set[backend] = struct{}{}
		}
		constraintSets = append(constraintSets, set)
	}

	if len(selection.HostCapabilities) == 0 {
		return BackendSelectionResult{}, fmt.Errorf("%w: host capability set is empty", ErrInvalidSpec)
	}
	hostCapabilities := make(map[Backend]Capability, len(selection.HostCapabilities))
	for _, capability := range selection.HostCapabilities {
		switch capability.Backend {
		case BackendNsJail, BackendDocker, BackendFirecracker, BackendMock:
		default:
			return BackendSelectionResult{}, fmt.Errorf(
				"%w: host capability names unsupported backend %q",
				ErrInvalidSpec,
				capability.Backend,
			)
		}
		if _, duplicate := hostCapabilities[capability.Backend]; duplicate {
			return BackendSelectionResult{}, fmt.Errorf(
				"%w: host capability repeats backend %q",
				ErrInvalidSpec,
				capability.Backend,
			)
		}
		if capability.Available == (capability.UnavailableReason != "") {
			return BackendSelectionResult{}, fmt.Errorf(
				"%w: capability availability and reason disagree for %q",
				ErrInvalidSpec,
				capability.Backend,
			)
		}
		if capability.Backend == BackendMock && !capability.DevelopmentOnly {
			return BackendSelectionResult{}, fmt.Errorf(
				"%w: mock host capability must be marked development-only",
				ErrInvalidSpec,
			)
		}
		hostCapabilities[capability.Backend] = capability
	}

	switch selection.Fallback.Mode {
	case FallbackDisabled:
		if len(selection.Fallback.Order) != 0 || selection.Fallback.AllowSecurityDowngrade {
			return BackendSelectionResult{}, fmt.Errorf(
				"%w: disabled fallback cannot carry order or downgrade permission",
				ErrInvalidSpec,
			)
		}
	case FallbackExplicit:
		if len(selection.Fallback.Order) == 0 {
			return BackendSelectionResult{}, fmt.Errorf("%w: explicit fallback order is empty", ErrInvalidSpec)
		}
		seenFallbacks := make(map[Backend]struct{}, len(selection.Fallback.Order))
		for _, backend := range selection.Fallback.Order {
			switch backend {
			case BackendNsJail, BackendDocker, BackendFirecracker, BackendMock:
			default:
				return BackendSelectionResult{}, fmt.Errorf(
					"%w: fallback order names unsupported backend %q",
					ErrInvalidSpec,
					backend,
				)
			}
			if _, duplicate := seenFallbacks[backend]; duplicate {
				return BackendSelectionResult{}, fmt.Errorf(
					"%w: fallback order repeats backend %q",
					ErrInvalidSpec,
					backend,
				)
			}
			seenFallbacks[backend] = struct{}{}
		}
	default:
		return BackendSelectionResult{}, fmt.Errorf(
			"%w: unsupported fallback mode %q",
			ErrInvalidSpec,
			selection.Fallback.Mode,
		)
	}

	canonicalOrder := [...]Backend{BackendNsJail, BackendDocker, BackendFirecracker, BackendMock}
	eligible := make([]Backend, 0, len(canonicalOrder))
	for _, backend := range canonicalOrder {
		allowed := true
		for _, set := range constraintSets {
			if _, exists := set[backend]; !exists {
				allowed = false
				break
			}
		}
		capability, hasCapability := hostCapabilities[backend]
		if !hasCapability || !capability.Available {
			allowed = false
		}
		if backend == BackendMock || capability.DevelopmentOnly {
			if selection.Mode != DeploymentDevelopment {
				allowed = false
			}
		}
		if selection.MinimumIsolation == IsolationMicroVM && backend != BackendFirecracker {
			allowed = false
		}
		if allowed {
			eligible = append(eligible, backend)
		}
	}

	result := BackendSelectionResult{
		Requested: requested,
		Eligible:  append([]Backend(nil), eligible...),
	}
	requestedEligible := false
	for _, backend := range eligible {
		if backend == requested {
			requestedEligible = true
			break
		}
	}
	if requested == BackendMock && selection.Mode != DeploymentDevelopment {
		return BackendSelectionResult{}, fmt.Errorf("%w: mock backend requires development mode", ErrDevelopmentOnly)
	}
	requestedBelowMinimum := selection.MinimumIsolation == IsolationMicroVM && requested != BackendFirecracker
	if requestedBelowMinimum && selection.Fallback.Mode == FallbackDisabled {
		return BackendSelectionResult{}, fmt.Errorf(
			"%w: requested backend %q does not satisfy %q",
			ErrSecurityDowngrade,
			requested,
			selection.MinimumIsolation,
		)
	}
	if requestedEligible {
		result.Resolved = requested
		return result, nil
	}

	if selection.Fallback.Mode == FallbackDisabled {
		return BackendSelectionResult{}, fmt.Errorf(
			"%w: exact backend %q failed one or more availability constraints",
			ErrBackendUnavailable,
			requested,
		)
	}

	downgradeBlocked := false
	for _, fallback := range selection.Fallback.Order {
		fallbackEligible := false
		for _, backend := range eligible {
			if backend == fallback {
				fallbackEligible = true
				break
			}
		}
		if !fallbackEligible {
			continue
		}
		if fallback == BackendMock && requested != BackendMock {
			return BackendSelectionResult{}, fmt.Errorf(
				"%w: mock cannot satisfy a native backend request",
				ErrDevelopmentOnly,
			)
		}
		securityDowngrade := requested == BackendFirecracker && fallback != BackendFirecracker
		if securityDowngrade && !selection.Fallback.AllowSecurityDowngrade {
			downgradeBlocked = true
			continue
		}
		result.Resolved = fallback
		result.FallbackUsed = true
		result.SecurityDowngrade = securityDowngrade
		return result, nil
	}
	if downgradeBlocked {
		return BackendSelectionResult{}, fmt.Errorf(
			"%w: fallback from %q requires explicit downgrade permission",
			ErrSecurityDowngrade,
			requested,
		)
	}
	if requestedBelowMinimum {
		return BackendSelectionResult{}, fmt.Errorf(
			"%w: no fallback for %q satisfies minimum isolation %q",
			ErrSecurityDowngrade,
			requested,
			selection.MinimumIsolation,
		)
	}
	return BackendSelectionResult{}, fmt.Errorf(
		"%w: no configured fallback satisfies every constraint",
		ErrBackendUnavailable,
	)
}
