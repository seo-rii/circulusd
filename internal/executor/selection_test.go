package executor_test

import (
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/hancomac/circulusd/internal/executor"
)

func TestResolveBackendUsesDeclaredPreferencePrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		selection executor.BackendSelection
		want      executor.Backend
	}{
		{
			name: "tool or session overrides every default",
			selection: backendSelection(func(selection *executor.BackendSelection) {
				selection.ToolOrSession = executor.BackendFirecracker
				selection.WorkspaceDefault = executor.BackendDocker
				selection.UserDefault = executor.BackendNsJail
			}),
			want: executor.BackendFirecracker,
		},
		{
			name: "workspace overrides user and server",
			selection: backendSelection(func(selection *executor.BackendSelection) {
				selection.WorkspaceDefault = executor.BackendDocker
				selection.UserDefault = executor.BackendNsJail
				selection.ServerDefault = executor.BackendFirecracker
			}),
			want: executor.BackendDocker,
		},
		{
			name: "user overrides server",
			selection: backendSelection(func(selection *executor.BackendSelection) {
				selection.UserDefault = executor.BackendNsJail
				selection.ServerDefault = executor.BackendDocker
			}),
			want: executor.BackendNsJail,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := executor.ResolveBackend(test.selection)
			if err != nil {
				t.Fatalf("ResolveBackend() error = %v", err)
			}
			if result.Requested != test.want || result.Resolved != test.want || result.FallbackUsed {
				t.Fatalf("ResolveBackend() = %#v, want exact %q", result, test.want)
			}
		})
	}
}

func TestResolveBackendRequiresEveryAvailabilityConstraint(t *testing.T) {
	t.Parallel()

	constraints := []struct {
		name   string
		mutate func(*executor.BackendSelection)
	}{
		{name: "server", mutate: func(selection *executor.BackendSelection) {
			selection.ServerAllowed = []executor.Backend{executor.BackendNsJail}
		}},
		{name: "registry", mutate: func(selection *executor.BackendSelection) {
			selection.RegistryAllowed = []executor.Backend{executor.BackendNsJail}
		}},
		{name: "extension", mutate: func(selection *executor.BackendSelection) {
			selection.ExtensionSupported = []executor.Backend{executor.BackendNsJail}
		}},
		{name: "environment artifact", mutate: func(selection *executor.BackendSelection) {
			selection.EnvironmentArtifacts = []executor.Backend{executor.BackendNsJail}
		}},
		{name: "host", mutate: func(selection *executor.BackendSelection) {
			selection.HostCapabilities = []executor.Capability{
				{Backend: executor.BackendDocker, Available: false, UnavailableReason: "daemon unavailable"},
				{Backend: executor.BackendNsJail, Available: true},
				{Backend: executor.BackendFirecracker, Available: true},
			}
		}},
	}

	for _, constraint := range constraints {
		t.Run(constraint.name, func(t *testing.T) {
			t.Parallel()
			selection := backendSelection(func(selection *executor.BackendSelection) {
				selection.ToolOrSession = executor.BackendDocker
			})
			constraint.mutate(&selection)
			_, err := executor.ResolveBackend(selection)
			if !errors.Is(err, executor.ErrBackendUnavailable) {
				t.Fatalf("ResolveBackend() error = %v, want ErrBackendUnavailable", err)
			}
		})
	}
}

func TestResolveBackendNeverSilentlyFallsBack(t *testing.T) {
	t.Parallel()

	selection := backendSelection(func(selection *executor.BackendSelection) {
		selection.ToolOrSession = executor.BackendDocker
		selection.HostCapabilities = []executor.Capability{
			{Backend: executor.BackendDocker, Available: false, UnavailableReason: "daemon unavailable"},
			{Backend: executor.BackendNsJail, Available: true},
			{Backend: executor.BackendFirecracker, Available: true},
		}
	})
	_, err := executor.ResolveBackend(selection)
	if !errors.Is(err, executor.ErrBackendUnavailable) {
		t.Fatalf("ResolveBackend() error = %v, want fail-closed unavailability", err)
	}
}

func TestResolveBackendUsesOnlyExplicitOrderedFallback(t *testing.T) {
	t.Parallel()

	selection := backendSelection(func(selection *executor.BackendSelection) {
		selection.ToolOrSession = executor.BackendDocker
		selection.HostCapabilities = []executor.Capability{
			{Backend: executor.BackendDocker, Available: false, UnavailableReason: "daemon unavailable"},
			{Backend: executor.BackendNsJail, Available: true},
			{Backend: executor.BackendFirecracker, Available: true},
		}
		selection.Fallback = executor.BackendFallbackPolicy{
			Mode:  executor.FallbackExplicit,
			Order: []executor.Backend{executor.BackendFirecracker, executor.BackendNsJail},
		}
	})
	result, err := executor.ResolveBackend(selection)
	if err != nil {
		t.Fatalf("ResolveBackend() error = %v", err)
	}
	if result.Requested != executor.BackendDocker || result.Resolved != executor.BackendFirecracker || !result.FallbackUsed {
		t.Fatalf("ResolveBackend() = %#v", result)
	}
	if !reflect.DeepEqual(result.Eligible, []executor.Backend{executor.BackendNsJail, executor.BackendFirecracker}) {
		t.Fatalf("eligible = %#v", result.Eligible)
	}
}

func TestResolveBackendRejectsSecurityDowngradeWithoutOptIn(t *testing.T) {
	t.Parallel()

	selection := backendSelection(func(selection *executor.BackendSelection) {
		selection.ToolOrSession = executor.BackendFirecracker
		selection.HostCapabilities = []executor.Capability{
			{Backend: executor.BackendNsJail, Available: true},
			{Backend: executor.BackendDocker, Available: true},
			{Backend: executor.BackendFirecracker, Available: false, UnavailableReason: "KVM unavailable"},
		}
		selection.Fallback = executor.BackendFallbackPolicy{
			Mode:  executor.FallbackExplicit,
			Order: []executor.Backend{executor.BackendDocker},
		}
	})
	_, err := executor.ResolveBackend(selection)
	if !errors.Is(err, executor.ErrSecurityDowngrade) {
		t.Fatalf("ResolveBackend() error = %v, want ErrSecurityDowngrade", err)
	}

	selection.Fallback.AllowSecurityDowngrade = true
	result, err := executor.ResolveBackend(selection)
	if err != nil {
		t.Fatalf("ResolveBackend(opted in) error = %v", err)
	}
	if result.Resolved != executor.BackendDocker || !result.SecurityDowngrade {
		t.Fatalf("ResolveBackend(opted in) = %#v", result)
	}
}

func TestResolveBackendEnforcesToolIsolationMinimum(t *testing.T) {
	t.Parallel()

	selection := backendSelection(func(selection *executor.BackendSelection) {
		selection.ToolOrSession = executor.BackendDocker
		selection.MinimumIsolation = executor.IsolationMicroVM
	})
	_, err := executor.ResolveBackend(selection)
	if !errors.Is(err, executor.ErrSecurityDowngrade) {
		t.Fatalf("ResolveBackend() error = %v, want ErrSecurityDowngrade", err)
	}
}

func TestResolveBackendMayExplicitlyUpgradeToMeetToolIsolationMinimum(t *testing.T) {
	t.Parallel()

	selection := backendSelection(func(selection *executor.BackendSelection) {
		selection.ToolOrSession = executor.BackendDocker
		selection.MinimumIsolation = executor.IsolationMicroVM
		selection.Fallback = executor.BackendFallbackPolicy{
			Mode:  executor.FallbackExplicit,
			Order: []executor.Backend{executor.BackendFirecracker},
		}
	})
	result, err := executor.ResolveBackend(selection)
	if err != nil {
		t.Fatalf("ResolveBackend() error = %v", err)
	}
	if result.Resolved != executor.BackendFirecracker || !result.FallbackUsed || result.SecurityDowngrade {
		t.Fatalf("ResolveBackend() = %#v", result)
	}
}

func TestResolveBackendRejectsMockOutsideExplicitDevelopmentSelection(t *testing.T) {
	t.Parallel()

	selection := backendSelection(func(selection *executor.BackendSelection) {
		selection.ToolOrSession = executor.BackendMock
		selection.ServerAllowed = append(selection.ServerAllowed, executor.BackendMock)
		selection.RegistryAllowed = append(selection.RegistryAllowed, executor.BackendMock)
		selection.ExtensionSupported = append(selection.ExtensionSupported, executor.BackendMock)
		selection.EnvironmentArtifacts = append(selection.EnvironmentArtifacts, executor.BackendMock)
		selection.HostCapabilities = append(selection.HostCapabilities, executor.Capability{
			Backend: executor.BackendMock, Available: true, DevelopmentOnly: true,
		})
	})
	_, err := executor.ResolveBackend(selection)
	if !errors.Is(err, executor.ErrDevelopmentOnly) {
		t.Fatalf("ResolveBackend(production mock) error = %v, want ErrDevelopmentOnly", err)
	}

	selection.Mode = executor.DeploymentDevelopment
	result, err := executor.ResolveBackend(selection)
	if err != nil {
		t.Fatalf("ResolveBackend(development mock) error = %v", err)
	}
	if result.Resolved != executor.BackendMock {
		t.Fatalf("ResolveBackend(development mock) = %#v", result)
	}

	selection.ToolOrSession = executor.BackendDocker
	selection.HostCapabilities = []executor.Capability{
		{Backend: executor.BackendDocker, Available: false, UnavailableReason: "daemon unavailable"},
		{Backend: executor.BackendMock, Available: true, DevelopmentOnly: true},
	}
	selection.Fallback = executor.BackendFallbackPolicy{
		Mode:  executor.FallbackExplicit,
		Order: []executor.Backend{executor.BackendMock},
	}
	_, err = executor.ResolveBackend(selection)
	if !errors.Is(err, executor.ErrDevelopmentOnly) {
		t.Fatalf("ResolveBackend(mock fallback) error = %v, want ErrDevelopmentOnly", err)
	}
}

func TestResolveBackendRejectsMalformedAndDuplicateInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*executor.BackendSelection)
	}{
		{name: "missing preference", mutate: func(selection *executor.BackendSelection) {
			selection.ServerDefault = ""
		}},
		{name: "unknown backend", mutate: func(selection *executor.BackendSelection) {
			selection.ToolOrSession = executor.Backend("podman")
		}},
		{name: "duplicate server backend", mutate: func(selection *executor.BackendSelection) {
			selection.ServerAllowed = []executor.Backend{executor.BackendNsJail, executor.BackendNsJail}
		}},
		{name: "duplicate capability", mutate: func(selection *executor.BackendSelection) {
			selection.HostCapabilities = append(selection.HostCapabilities, executor.Capability{Backend: executor.BackendDocker, Available: true})
		}},
		{name: "unavailable capability without reason", mutate: func(selection *executor.BackendSelection) {
			selection.HostCapabilities[0].Available = false
			selection.HostCapabilities[0].UnavailableReason = ""
		}},
		{name: "available capability with reason", mutate: func(selection *executor.BackendSelection) {
			selection.HostCapabilities[0].UnavailableReason = "unexpected"
		}},
		{name: "mock capability not development marked", mutate: func(selection *executor.BackendSelection) {
			selection.HostCapabilities = append(selection.HostCapabilities, executor.Capability{Backend: executor.BackendMock, Available: true})
		}},
		{name: "duplicate fallback", mutate: func(selection *executor.BackendSelection) {
			selection.Fallback = executor.BackendFallbackPolicy{Mode: executor.FallbackExplicit, Order: []executor.Backend{executor.BackendNsJail, executor.BackendNsJail}}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			selection := backendSelection(test.mutate)
			_, err := executor.ResolveBackend(selection)
			if !errors.Is(err, executor.ErrInvalidSpec) {
				t.Fatalf("ResolveBackend() error = %v, want ErrInvalidSpec", err)
			}
		})
	}
}

func TestResolveBackendIsConcurrentAndDoesNotAliasCallerSlices(t *testing.T) {
	t.Parallel()

	selection := backendSelection(func(selection *executor.BackendSelection) {
		selection.ToolOrSession = executor.BackendDocker
	})
	const callers = 64
	results := make(chan executor.BackendSelectionResult, callers)
	errs := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := executor.ResolveBackend(selection)
			if err != nil {
				errs <- err
				return
			}
			results <- result
		}()
	}
	wait.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatalf("ResolveBackend() error = %v", err)
	}
	for result := range results {
		result.Eligible[0] = executor.Backend("corrupted")
	}
	result, err := executor.ResolveBackend(selection)
	if err != nil {
		t.Fatalf("ResolveBackend() after mutation error = %v", err)
	}
	if result.Eligible[0] != executor.BackendNsJail {
		t.Fatalf("eligible aliased caller/result memory: %#v", result.Eligible)
	}
}

func backendSelection(mutate func(*executor.BackendSelection)) executor.BackendSelection {
	selection := executor.BackendSelection{
		Mode:                 executor.DeploymentProduction,
		ServerDefault:        executor.BackendDocker,
		ServerAllowed:        []executor.Backend{executor.BackendNsJail, executor.BackendDocker, executor.BackendFirecracker},
		RegistryAllowed:      []executor.Backend{executor.BackendNsJail, executor.BackendDocker, executor.BackendFirecracker},
		ExtensionSupported:   []executor.Backend{executor.BackendNsJail, executor.BackendDocker, executor.BackendFirecracker},
		EnvironmentArtifacts: []executor.Backend{executor.BackendNsJail, executor.BackendDocker, executor.BackendFirecracker},
		HostCapabilities:     []executor.Capability{{Backend: executor.BackendNsJail, Available: true}, {Backend: executor.BackendDocker, Available: true}, {Backend: executor.BackendFirecracker, Available: true}},
		MinimumIsolation:     executor.IsolationSharedKernel,
		Fallback:             executor.BackendFallbackPolicy{Mode: executor.FallbackDisabled},
	}
	mutate(&selection)
	return selection
}
