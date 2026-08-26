package config_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/config"
)

const validConfiguration = `
server:
  publicAddress: 127.0.0.1:8443
  dataDirectory: /var/lib/pi-platform
deployment:
  mode: single-node
strictInstall: true
state:
  provider: celld
  endpoint: unix:///run/pi-platform/celld.sock
objectStore:
  endpoint: http://127.0.0.1:8333
  stateBucket: pi-celld-state
  workspaceBlobBucket: pi-workspace-blobs
  artifactBucket: pi-artifacts
agent:
  runtime: workerd
  perSessionIsolate: true
  defaultIsolation:
    processScope: shared
    outerIsolation: none
  shard:
    cpu: 4
    maxResidentSessions: 200
    maximumLifetime: 6h
    memoryLimit: 4GiB
    memoryAdmissionHighWatermark: 80%
    recycleOnOom: true
    recycleOnHeapPressure: true
execution:
  allowUserSelection: true
  allowedBackends: [nsjail, docker, firecracker]
  defaultBackend: docker
  sandboxScope: auto
  workspaceProjection: materialized-manifest
  fallback:
    mode: disabled
executors:
  nsjail:
    enabled: true
    binary: /usr/lib/pi-platform/nsjail
    environmentRoot: /var/lib/pi-platform/environments
    cgroupRoot: /sys/fs/cgroup/pi-platform
    uniqueUidPerSandbox: true
    allowPasta: false
  docker:
    enabled: true
    mode: system
    socket: unix:///var/run/docker.sock
  firecracker:
    enabled: true
    firecrackerBinary: /usr/lib/pi-platform/firecracker
    jailerBinary: /usr/lib/pi-platform/jailer
    kernelDirectory: /var/lib/pi-platform/firecracker/kernels
    rootfsDirectory: /var/lib/pi-platform/firecracker/rootfs
workspace:
  projectionMode: materialized-manifest
  manifestVerification: full-scan
  diffStrategy: auto
  treeManifestThreshold: 50000
  leaseWaitPolicy: queue
  leaseAcquireTimeout: 120s
  blobHash: sha256
network:
  defaultMode: none
  productionPolicyAuthority: host
models:
  default: local/primary
  endpoints:
    local/primary:
      protocol: openai-compatible
      endpoint: http://127.0.0.1:8000/v1
security:
  turnAuthorityTtl: 15m
  turnAuthorityRenewal: lease-bound
  maxTurnWallClock: 2h
  rotatePlacementGenerationOnShardFailure: true
  exposeRawSecretsToExtensions: false
  unreviewedExtensionMinimumOuterIsolation: firecracker
api:
  requireIdempotencyKeyForMutations: true
  durableEventRetention: 7d
retention:
  workspaceBlobGcGrace: 24h
  artifactDefault: 30d
  runtimeRollbackWindow: 24h
resourceProfiles:
  light:
    cpu: 1
    memory: 1GiB
    swap: 0
    pids: 128
    scratchDisk: 2GiB
    commandTimeout: 60s
    openFiles: 256
  standard:
    cpu: 2
    memory: 2GiB
    swap: 0
    pids: 256
    scratchDisk: 8GiB
    commandTimeout: 300s
    openFiles: 1024
  heavy:
    cpu: 4
    memory: 8GiB
    swap: 0
    pids: 512
    scratchDisk: 32GiB
    commandTimeout: 1800s
    openFiles: 4096
agentShardProfiles:
  standard:
    cpu: 4
    memory: 4GiB
    maxResidentSessions: 200
    maxLifetime: 6h
policy:
  users:
    defaultMaximumResourceProfile: standard
  extensions:
    official/libreoffice:
      minimumResourceProfile: standard
`

func TestParseAcceptsReferenceConfiguration(t *testing.T) {
	configuration, err := config.Parse(strings.NewReader(validConfiguration))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if configuration.Deployment.Mode != config.DeploymentSingleNode ||
		configuration.Execution.DefaultBackend != config.BackendDocker ||
		configuration.Agent.Shard.CPU != 4 ||
		configuration.Agent.Shard.MaximumLifetime.Duration() != 6*time.Hour ||
		configuration.Agent.Shard.MemoryLimit.Bytes() != 4<<30 ||
		configuration.Agent.Shard.MemoryAdmissionHighWatermark != 80 {
		t.Fatalf("Parse() = %#v", configuration)
	}
	if configuration.Models.Endpoints["local/primary"].Endpoint.String() != "http://127.0.0.1:8000/v1" {
		t.Fatalf("model endpoint = %q", configuration.Models.Endpoints["local/primary"].Endpoint.String())
	}
	if configuration.API.DurableEventRetention.Duration() != 7*24*time.Hour ||
		configuration.Retention.ArtifactDefault.Duration() != 30*24*time.Hour ||
		configuration.Network.DefaultMode != "none" ||
		configuration.Network.ProductionPolicyAuthority != "host" {
		t.Fatalf("reference policy = %#v", configuration)
	}
	light := configuration.ResourceProfiles["light"]
	if light.CPU != 1 || light.Memory.Bytes() != 1<<30 || light.Swap.Bytes() != 0 ||
		light.PIDs != 128 || light.ScratchDisk.Bytes() != 2<<30 ||
		light.CommandTimeout.Duration() != time.Minute || light.OpenFiles != 256 {
		t.Fatalf("light resource profile = %#v", light)
	}
	if configuration.AgentShardProfiles["standard"].CPU != 4 ||
		configuration.Policy.Users.DefaultMaximumResourceProfile != "standard" ||
		configuration.Policy.Extensions["official/libreoffice"].MinimumResourceProfile != "standard" {
		t.Fatalf("profile policy = %#v", configuration.Policy)
	}
	if !configuration.StrictInstall {
		t.Fatal("strictInstall = false, want true")
	}
	if err := configuration.ValidateForProfile(config.InstallProfileFull); err != nil {
		t.Fatalf("ValidateForProfile(full) error = %v", err)
	}
}

func TestParseRequiresSharedAndTenantShardCPUAndPressureRecycle(t *testing.T) {
	tests := []struct {
		name    string
		replace func(string) string
	}{
		{name: "shared without CPU quota", replace: func(value string) string {
			return strings.Replace(value, "cpu: 4\n    maxResidentSessions", "cpu: 0\n    maxResidentSessions", 1)
		}},
		{name: "tenant without heap pressure recycle", replace: func(value string) string {
			value = strings.Replace(value, "processScope: shared", "processScope: tenant", 1)
			return strings.Replace(value, "recycleOnHeapPressure: true", "recycleOnHeapPressure: false", 1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := config.Parse(strings.NewReader(test.replace(validConfiguration)))
			if !errors.Is(err, config.ErrInvalidConfiguration) {
				t.Fatalf("Parse() error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}
}

func TestValidateForProfileEnforcesInstallMatrix(t *testing.T) {
	tests := []struct {
		name      string
		profile   config.InstallProfile
		configure func(string) string
		wantErr   error
	}{
		{name: "lightweight", profile: config.InstallProfileLightweight, configure: func(value string) string {
			value = strings.Replace(value, "allowedBackends: [nsjail, docker, firecracker]", "allowedBackends: [nsjail]", 1)
			value = strings.Replace(value, "defaultBackend: docker", "defaultBackend: nsjail", 1)
			value = strings.Replace(value, "docker:\n    enabled: true", "docker:\n    enabled: false", 1)
			return strings.Replace(value, "firecracker:\n    enabled: true", "firecracker:\n    enabled: false", 1)
		}},
		{name: "docker", profile: config.InstallProfileDocker, configure: func(value string) string {
			value = strings.Replace(value, "allowedBackends: [nsjail, docker, firecracker]", "allowedBackends: [docker]", 1)
			value = strings.Replace(value, "nsjail:\n    enabled: true", "nsjail:\n    enabled: false", 1)
			return strings.Replace(value, "firecracker:\n    enabled: true", "firecracker:\n    enabled: false", 1)
		}},
		{name: "firecracker", profile: config.InstallProfileFirecracker, configure: func(value string) string {
			value = strings.Replace(value, "allowedBackends: [nsjail, docker, firecracker]", "allowedBackends: [firecracker]", 1)
			value = strings.Replace(value, "defaultBackend: docker", "defaultBackend: firecracker", 1)
			value = strings.Replace(value, "nsjail:\n    enabled: true", "nsjail:\n    enabled: false", 1)
			return strings.Replace(value, "docker:\n    enabled: true", "docker:\n    enabled: false", 1)
		}},
		{name: "full", profile: config.InstallProfileFull, configure: func(value string) string { return value }},
		{name: "development nsjail and docker", profile: config.InstallProfileDevelopment, configure: func(value string) string {
			value = strings.Replace(value, "allowedBackends: [nsjail, docker, firecracker]", "allowedBackends: [nsjail, docker]", 1)
			return strings.Replace(value, "firecracker:\n    enabled: true", "firecracker:\n    enabled: false", 1)
		}},
		{name: "strict full requires every backend", profile: config.InstallProfileFull, configure: func(value string) string {
			value = strings.Replace(value, "allowedBackends: [nsjail, docker, firecracker]", "allowedBackends: [nsjail, docker]", 1)
			return strings.Replace(value, "firecracker:\n    enabled: true", "firecracker:\n    enabled: false", 1)
		}, wantErr: config.ErrInstallProfileMismatch},
		{name: "non-strict full permits unavailable optional backend", profile: config.InstallProfileFull, configure: func(value string) string {
			value = strings.Replace(value, "strictInstall: true", "strictInstall: false", 1)
			value = strings.Replace(value, "allowedBackends: [nsjail, docker, firecracker]", "allowedBackends: [nsjail, docker]", 1)
			return strings.Replace(value, "firecracker:\n    enabled: true", "firecracker:\n    enabled: false", 1)
		}},
		{name: "full cannot default to firecracker", profile: config.InstallProfileFull, configure: func(value string) string {
			return strings.Replace(value, "defaultBackend: docker", "defaultBackend: firecracker", 1)
		}, wantErr: config.ErrInstallProfileMismatch},
		{name: "development excludes firecracker", profile: config.InstallProfileDevelopment, configure: func(value string) string {
			return value
		}, wantErr: config.ErrInstallProfileMismatch},
		{name: "unknown profile", profile: config.InstallProfile("future"), configure: func(value string) string {
			return value
		}, wantErr: config.ErrInstallProfileMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration, err := config.Parse(strings.NewReader(test.configure(validConfiguration)))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			err = configuration.ValidateForProfile(test.profile)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("ValidateForProfile(%q) error = %v, want %v", test.profile, err, test.wantErr)
			}
		})
	}
}

func TestParseRejectsEnabledButDisallowedBackend(t *testing.T) {
	misconfigured := strings.Replace(validConfiguration,
		"allowedBackends: [nsjail, docker, firecracker]", "allowedBackends: [nsjail, docker]", 1)
	_, err := config.Parse(strings.NewReader(misconfigured))
	if !errors.Is(err, config.ErrInvalidConfiguration) {
		t.Fatalf("Parse() error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestParseRejectsInvalidResourceProfilesAndPolicyClamps(t *testing.T) {
	tests := []struct {
		name    string
		replace func(string) string
	}{
		{name: "zero CPU", replace: func(value string) string {
			return strings.Replace(value, "cpu: 1\n    memory: 1GiB", "cpu: 0\n    memory: 1GiB", 1)
		}},
		{name: "zero memory", replace: func(value string) string {
			return strings.Replace(value, "memory: 1GiB", "memory: 0", 1)
		}},
		{name: "zero pids", replace: func(value string) string {
			return strings.Replace(value, "pids: 128", "pids: 0", 1)
		}},
		{name: "zero scratch", replace: func(value string) string {
			return strings.Replace(value, "scratchDisk: 2GiB", "scratchDisk: 0", 1)
		}},
		{name: "zero command timeout", replace: func(value string) string {
			return strings.Replace(value, "commandTimeout: 60s", "commandTimeout: 0s", 1)
		}},
		{name: "zero open files", replace: func(value string) string {
			return strings.Replace(value, "openFiles: 256", "openFiles: 0", 1)
		}},
		{name: "missing maximum profile", replace: func(value string) string {
			return strings.Replace(value, "defaultMaximumResourceProfile: standard", "defaultMaximumResourceProfile: absent", 1)
		}},
		{name: "missing minimum profile", replace: func(value string) string {
			return strings.Replace(value, "minimumResourceProfile: standard", "minimumResourceProfile: absent", 1)
		}},
		{name: "empty extension identifier", replace: func(value string) string {
			return strings.Replace(value, "official/libreoffice:\n      minimumResourceProfile", "\"\":\n      minimumResourceProfile", 1)
		}},
		{name: "empty extension publisher", replace: func(value string) string {
			return strings.Replace(value, "official/libreoffice:\n      minimumResourceProfile", "/libreoffice:\n      minimumResourceProfile", 1)
		}},
		{name: "minimum exceeds default maximum", replace: func(value string) string {
			return strings.Replace(value, "minimumResourceProfile: standard", "minimumResourceProfile: heavy", 1)
		}},
		{name: "invalid network default", replace: func(value string) string {
			return strings.Replace(value, "defaultMode: none", "defaultMode: proxy", 1)
		}},
		{name: "non-host production authority", replace: func(value string) string {
			return strings.Replace(value, "productionPolicyAuthority: host", "productionPolicyAuthority: sandbox", 1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := config.Parse(strings.NewReader(test.replace(validConfiguration)))
			if !errors.Is(err, config.ErrInvalidConfiguration) {
				t.Fatalf("Parse() error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}
}

func TestParseAcceptsSandboxedWorkerdPlacementProfile(t *testing.T) {
	sandboxed := strings.Replace(validConfiguration,
		"processScope: shared\n    outerIsolation: none",
		"processScope: session\n    outerIsolation: firecracker", 1)
	configuration, err := config.Parse(strings.NewReader(sandboxed))
	if err != nil {
		t.Fatalf("Parse(sandboxed-workerd) error = %v", err)
	}
	if configuration.Agent.DefaultIsolation.ProcessScope != "session" ||
		configuration.Agent.DefaultIsolation.OuterIsolation != "firecracker" {
		t.Fatalf("sandboxed isolation = %#v", configuration.Agent.DefaultIsolation)
	}
}

func TestParseRejectsMultiNodeUntilAuthenticatedTransportIsConfigured(t *testing.T) {
	multiNode := strings.Replace(validConfiguration, "mode: single-node", "mode: multi-node", 1)
	_, err := config.Parse(strings.NewReader(multiNode))
	if !errors.Is(err, config.ErrUnsupportedDeployment) {
		t.Fatalf("Parse(multi-node) error = %v, want ErrUnsupportedDeployment", err)
	}
}

func TestParseRejectsAmbiguousOrExpandableYAML(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		marker error
	}{
		{name: "unknown field", input: validConfiguration + "futureOption: true\n", marker: config.ErrInvalidSyntax},
		{name: "second document", input: validConfiguration + "---\n{}\n", marker: config.ErrInvalidSyntax},
		{name: "alias", input: strings.Replace(validConfiguration,
			"allowedBackends: [nsjail, docker, firecracker]",
			"allowedBackends: &backends [nsjail, docker, firecracker]\n  mirroredBackends: *backends", 1), marker: config.ErrInvalidSyntax},
		{name: "explicit tag", input: strings.Replace(validConfiguration,
			"mode: single-node", "mode: !deployment single-node", 1), marker: config.ErrInvalidSyntax},
		{name: "oversized", input: strings.Repeat("#", config.MaximumDocumentBytes+1), marker: config.ErrDocumentTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := config.Parse(strings.NewReader(test.input))
			if !errors.Is(err, test.marker) {
				t.Fatalf("Parse() error = %v, want %v", err, test.marker)
			}
		})
	}
}

func TestParseRejectsUnsafePathsAndEndpointForms(t *testing.T) {
	tests := []struct {
		name    string
		replace func(string) string
		marker  error
	}{
		{name: "NUL in data directory", replace: func(value string) string {
			return strings.Replace(value, "dataDirectory: /var/lib/pi-platform", "dataDirectory: \"/var/lib/pi-platform\\0data\"", 1)
		}, marker: config.ErrInvalidConfiguration},
		{name: "control character in binary path", replace: func(value string) string {
			return strings.Replace(value, "binary: /usr/lib/pi-platform/nsjail", "binary: \"/usr/lib/pi-platform/\\tnsjail\"", 1)
		}, marker: config.ErrInvalidConfiguration},
		{name: "encoded NUL in Unix endpoint", replace: func(value string) string {
			return strings.Replace(value, "unix:///run/pi-platform/celld.sock", "unix:///run/pi-platform/%00celld.sock", 1)
		}, marker: config.ErrInvalidSyntax},
		{name: "noncanonical Unix endpoint", replace: func(value string) string {
			return strings.Replace(value, "unix:///run/pi-platform/celld.sock", "unix:/run/pi-platform/celld.sock", 1)
		}, marker: config.ErrInvalidSyntax},
		{name: "object store endpoint query", replace: func(value string) string {
			return strings.Replace(value, "http://127.0.0.1:8333", "http://127.0.0.1:8333?credential=raw", 1)
		}, marker: config.ErrInvalidSyntax},
		{name: "model endpoint query", replace: func(value string) string {
			return strings.Replace(value, "http://127.0.0.1:8000/v1", "http://127.0.0.1:8000/v1?token=raw", 1)
		}, marker: config.ErrInvalidSyntax},
		{name: "network endpoint zero port", replace: func(value string) string {
			return strings.Replace(value, "http://127.0.0.1:8333", "http://127.0.0.1:0", 1)
		}, marker: config.ErrInvalidSyntax},
		{name: "single-node object store is not loopback", replace: func(value string) string {
			return strings.Replace(value, "http://127.0.0.1:8333", "https://object-store.internal:8333", 1)
		}, marker: config.ErrInvalidConfiguration},
		{name: "public address whitespace host", replace: func(value string) string {
			return strings.Replace(value, "127.0.0.1:8443", "bad host:8443", 1)
		}, marker: config.ErrInvalidConfiguration},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := config.Parse(strings.NewReader(test.replace(validConfiguration)))
			if !errors.Is(err, test.marker) {
				t.Fatalf("Parse() error = %v, want %v", err, test.marker)
			}
		})
	}
}

func TestValidateFailsClosedOnBackendAndSecurityMisconfiguration(t *testing.T) {
	tests := []struct {
		name    string
		replace func(string) string
	}{
		{name: "fallback enabled", replace: func(value string) string {
			return strings.Replace(value, "mode: disabled", "mode: automatic", 1)
		}},
		{name: "default not allowed", replace: func(value string) string {
			return strings.Replace(value, "defaultBackend: docker", "defaultBackend: future", 1)
		}},
		{name: "allowed provider disabled", replace: func(value string) string {
			return strings.Replace(value, "docker:\n    enabled: true", "docker:\n    enabled: false", 1)
		}},
		{name: "relative privileged binary", replace: func(value string) string {
			return strings.Replace(value, "/usr/lib/pi-platform/nsjail", "bin/nsjail", 1)
		}},
		{name: "shared object buckets", replace: func(value string) string {
			return strings.Replace(value, "artifactBucket: pi-artifacts", "artifactBucket: pi-workspace-blobs", 1)
		}},
		{name: "raw extension secrets", replace: func(value string) string {
			return strings.Replace(value, "exposeRawSecretsToExtensions: false", "exposeRawSecretsToExtensions: true", 1)
		}},
		{name: "non-isolated sessions", replace: func(value string) string {
			return strings.Replace(value, "perSessionIsolate: true", "perSessionIsolate: false", 1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := config.Parse(strings.NewReader(test.replace(validConfiguration)))
			if !errors.Is(err, config.ErrInvalidConfiguration) {
				t.Fatalf("Parse() error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}
}
