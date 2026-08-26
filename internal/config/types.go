// Package config loads and validates the fail-closed platform configuration.
package config

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const MaximumDocumentBytes = 1 << 20

var (
	ErrInvalidSyntax          = errors.New("config: invalid YAML syntax")
	ErrDocumentTooLarge       = errors.New("config: document is too large")
	ErrInvalidConfiguration   = errors.New("config: invalid configuration")
	ErrUnsupportedDeployment  = errors.New("config: deployment mode is not yet supported")
	ErrInstallProfileMismatch = errors.New("config: install profile does not match enabled backends")
)

type DeploymentMode string

const (
	DeploymentSingleNode DeploymentMode = "single-node"
	DeploymentMultiNode  DeploymentMode = "multi-node"
)

type Backend string

const (
	BackendNsJail      Backend = "nsjail"
	BackendDocker      Backend = "docker"
	BackendFirecracker Backend = "firecracker"
)

type InstallProfile string

const (
	InstallProfileLightweight InstallProfile = "lightweight"
	InstallProfileDocker      InstallProfile = "docker"
	InstallProfileFull        InstallProfile = "full"
	InstallProfileFirecracker InstallProfile = "firecracker"
	InstallProfileDevelopment InstallProfile = "development"
)

type Duration time.Duration

func (duration *Duration) UnmarshalText(value []byte) error {
	raw := string(value)
	var parsed time.Duration
	if strings.HasSuffix(raw, "d") && strings.Count(raw, "d") == 1 {
		days, err := strconv.ParseInt(strings.TrimSuffix(raw, "d"), 10, 64)
		if err != nil || days > math.MaxInt64/int64(24*time.Hour) || days < math.MinInt64/int64(24*time.Hour) {
			return fmt.Errorf("duration is invalid")
		}
		parsed = time.Duration(days) * 24 * time.Hour
	} else {
		var err error
		parsed, err = time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("duration is invalid")
		}
	}
	*duration = Duration(parsed)
	return nil
}

func (duration Duration) Duration() time.Duration {
	return time.Duration(duration)
}

type ByteSize uint64

func (size *ByteSize) UnmarshalText(value []byte) error {
	raw := string(value)
	if raw == "0" {
		*size = 0
		return nil
	}
	units := []struct {
		suffix     string
		multiplier uint64
	}{
		{suffix: "TiB", multiplier: 1 << 40},
		{suffix: "GiB", multiplier: 1 << 30},
		{suffix: "MiB", multiplier: 1 << 20},
		{suffix: "KiB", multiplier: 1 << 10},
		{suffix: "B", multiplier: 1},
	}
	for _, unit := range units {
		if !strings.HasSuffix(raw, unit.suffix) {
			continue
		}
		amount, err := strconv.ParseUint(strings.TrimSuffix(raw, unit.suffix), 10, 63)
		if err != nil || amount == 0 || amount > math.MaxInt64/unit.multiplier {
			return fmt.Errorf("byte size is invalid")
		}
		*size = ByteSize(amount * unit.multiplier)
		return nil
	}
	return fmt.Errorf("byte size requires a binary unit")
}

func (size ByteSize) Bytes() uint64 {
	return uint64(size)
}

type Percentage uint8

func (percentage *Percentage) UnmarshalText(value []byte) error {
	raw := string(value)
	if !strings.HasSuffix(raw, "%") {
		return fmt.Errorf("percentage requires %% suffix")
	}
	parsed, err := strconv.ParseUint(strings.TrimSuffix(raw, "%"), 10, 8)
	if err != nil || parsed == 0 || parsed > 100 {
		return fmt.Errorf("percentage is outside 1..100")
	}
	*percentage = Percentage(parsed)
	return nil
}

type Endpoint struct {
	raw    string
	scheme string
	host   string
}

func (endpoint *Endpoint) UnmarshalText(value []byte) error {
	raw := string(value)
	if raw != strings.TrimSpace(raw) || containsControl(raw) {
		return fmt.Errorf("endpoint is invalid")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || containsControl(parsed.Path) {
		return fmt.Errorf("endpoint is invalid")
	}
	if parsed.Scheme == "unix" {
		if !strings.HasPrefix(raw, "unix:///") || parsed.Host != "" || !validAbsolutePath(parsed.Path) || parsed.Path == "/" {
			return fmt.Errorf("Unix endpoint is invalid")
		}
	} else {
		if (parsed.Scheme != "http" && parsed.Scheme != "https") ||
			!strings.HasPrefix(raw, parsed.Scheme+"://") || !validNetworkHost(parsed.Hostname()) {
			return fmt.Errorf("network endpoint is invalid")
		}
		if port := parsed.Port(); port != "" {
			parsedPort, portErr := strconv.ParseUint(port, 10, 16)
			if portErr != nil || parsedPort == 0 {
				return fmt.Errorf("network endpoint port is invalid")
			}
		} else if strings.HasSuffix(parsed.Host, ":") {
			return fmt.Errorf("network endpoint port is invalid")
		}
	}
	endpoint.raw = raw
	endpoint.scheme = parsed.Scheme
	endpoint.host = parsed.Hostname()
	return nil
}

func (endpoint Endpoint) String() string {
	return endpoint.raw
}

type Configuration struct {
	Server             ServerConfiguration          `yaml:"server"`
	Deployment         DeploymentConfiguration      `yaml:"deployment"`
	StrictInstall      bool                         `yaml:"strictInstall"`
	State              StateConfiguration           `yaml:"state"`
	ObjectStore        ObjectStoreConfiguration     `yaml:"objectStore"`
	Agent              AgentConfiguration           `yaml:"agent"`
	Execution          ExecutionConfiguration       `yaml:"execution"`
	Executors          ExecutorsConfiguration       `yaml:"executors"`
	Workspace          WorkspaceConfiguration       `yaml:"workspace"`
	Network            NetworkConfiguration         `yaml:"network"`
	Models             ModelsConfiguration          `yaml:"models"`
	Security           SecurityConfiguration        `yaml:"security"`
	API                APIConfiguration             `yaml:"api"`
	Retention          RetentionConfiguration       `yaml:"retention"`
	ResourceProfiles   map[string]ResourceProfile   `yaml:"resourceProfiles"`
	AgentShardProfiles map[string]AgentShardProfile `yaml:"agentShardProfiles"`
	Policy             ResourcePolicyConfiguration  `yaml:"policy"`
}

type ServerConfiguration struct {
	PublicAddress string `yaml:"publicAddress"`
	DataDirectory string `yaml:"dataDirectory"`
}

type DeploymentConfiguration struct {
	Mode DeploymentMode `yaml:"mode"`
}

type StateConfiguration struct {
	Provider string   `yaml:"provider"`
	Endpoint Endpoint `yaml:"endpoint"`
}

type ObjectStoreConfiguration struct {
	Endpoint            Endpoint `yaml:"endpoint"`
	StateBucket         string   `yaml:"stateBucket"`
	WorkspaceBlobBucket string   `yaml:"workspaceBlobBucket"`
	ArtifactBucket      string   `yaml:"artifactBucket"`
}

type AgentIsolation struct {
	ProcessScope   string `yaml:"processScope"`
	OuterIsolation string `yaml:"outerIsolation"`
}

type AgentShardConfiguration struct {
	CPU                          uint64     `yaml:"cpu"`
	MaxResidentSessions          uint64     `yaml:"maxResidentSessions"`
	MaximumLifetime              Duration   `yaml:"maximumLifetime"`
	MemoryLimit                  ByteSize   `yaml:"memoryLimit"`
	MemoryAdmissionHighWatermark Percentage `yaml:"memoryAdmissionHighWatermark"`
	RecycleOnOOM                 bool       `yaml:"recycleOnOom"`
	RecycleOnHeapPressure        bool       `yaml:"recycleOnHeapPressure"`
}

type AgentConfiguration struct {
	Runtime           string                  `yaml:"runtime"`
	PerSessionIsolate bool                    `yaml:"perSessionIsolate"`
	DefaultIsolation  AgentIsolation          `yaml:"defaultIsolation"`
	Shard             AgentShardConfiguration `yaml:"shard"`
}

type FallbackConfiguration struct {
	Mode string `yaml:"mode"`
}

type ExecutionConfiguration struct {
	AllowUserSelection  bool                  `yaml:"allowUserSelection"`
	AllowedBackends     []Backend             `yaml:"allowedBackends"`
	DefaultBackend      Backend               `yaml:"defaultBackend"`
	SandboxScope        string                `yaml:"sandboxScope"`
	WorkspaceProjection string                `yaml:"workspaceProjection"`
	Fallback            FallbackConfiguration `yaml:"fallback"`
}

type NsJailConfiguration struct {
	Enabled             bool   `yaml:"enabled"`
	Binary              string `yaml:"binary"`
	EnvironmentRoot     string `yaml:"environmentRoot"`
	CgroupRoot          string `yaml:"cgroupRoot"`
	UniqueUIDPerSandbox bool   `yaml:"uniqueUidPerSandbox"`
	AllowPasta          bool   `yaml:"allowPasta"`
}

type DockerConfiguration struct {
	Enabled bool     `yaml:"enabled"`
	Mode    string   `yaml:"mode"`
	Socket  Endpoint `yaml:"socket"`
}

type FirecrackerConfiguration struct {
	Enabled           bool   `yaml:"enabled"`
	FirecrackerBinary string `yaml:"firecrackerBinary"`
	JailerBinary      string `yaml:"jailerBinary"`
	KernelDirectory   string `yaml:"kernelDirectory"`
	RootfsDirectory   string `yaml:"rootfsDirectory"`
}

type ExecutorsConfiguration struct {
	NsJail      NsJailConfiguration      `yaml:"nsjail"`
	Docker      DockerConfiguration      `yaml:"docker"`
	Firecracker FirecrackerConfiguration `yaml:"firecracker"`
}

type WorkspaceConfiguration struct {
	ProjectionMode        string   `yaml:"projectionMode"`
	ManifestVerification  string   `yaml:"manifestVerification"`
	DiffStrategy          string   `yaml:"diffStrategy"`
	TreeManifestThreshold uint64   `yaml:"treeManifestThreshold"`
	LeaseWaitPolicy       string   `yaml:"leaseWaitPolicy"`
	LeaseAcquireTimeout   Duration `yaml:"leaseAcquireTimeout"`
	BlobHash              string   `yaml:"blobHash"`
}

type NetworkConfiguration struct {
	DefaultMode               string `yaml:"defaultMode"`
	ProductionPolicyAuthority string `yaml:"productionPolicyAuthority"`
}

type ModelEndpoint struct {
	Protocol string   `yaml:"protocol"`
	Endpoint Endpoint `yaml:"endpoint"`
}

type ModelsConfiguration struct {
	Default   string                   `yaml:"default"`
	Endpoints map[string]ModelEndpoint `yaml:"endpoints"`
}

type SecurityConfiguration struct {
	TurnAuthorityTTL                         Duration `yaml:"turnAuthorityTtl"`
	TurnAuthorityRenewal                     string   `yaml:"turnAuthorityRenewal"`
	MaxTurnWallClock                         Duration `yaml:"maxTurnWallClock"`
	RotatePlacementGenerationOnShardFailure  bool     `yaml:"rotatePlacementGenerationOnShardFailure"`
	ExposeRawSecretsToExtensions             bool     `yaml:"exposeRawSecretsToExtensions"`
	UnreviewedExtensionMinimumOuterIsolation string   `yaml:"unreviewedExtensionMinimumOuterIsolation"`
}

type APIConfiguration struct {
	RequireIdempotencyKeyForMutations bool     `yaml:"requireIdempotencyKeyForMutations"`
	DurableEventRetention             Duration `yaml:"durableEventRetention"`
}

type RetentionConfiguration struct {
	WorkspaceBlobGCGrace  Duration `yaml:"workspaceBlobGcGrace"`
	ArtifactDefault       Duration `yaml:"artifactDefault"`
	RuntimeRollbackWindow Duration `yaml:"runtimeRollbackWindow"`
}

type ResourceProfile struct {
	CPU            uint64   `yaml:"cpu"`
	Memory         ByteSize `yaml:"memory"`
	Swap           ByteSize `yaml:"swap"`
	PIDs           uint64   `yaml:"pids"`
	ScratchDisk    ByteSize `yaml:"scratchDisk"`
	CommandTimeout Duration `yaml:"commandTimeout"`
	OpenFiles      uint64   `yaml:"openFiles"`
}

type AgentShardProfile struct {
	CPU                 uint64   `yaml:"cpu"`
	Memory              ByteSize `yaml:"memory"`
	MaxResidentSessions uint64   `yaml:"maxResidentSessions"`
	MaxLifetime         Duration `yaml:"maxLifetime"`
}

type UserResourcePolicy struct {
	DefaultMaximumResourceProfile string `yaml:"defaultMaximumResourceProfile"`
}

type ExtensionResourcePolicy struct {
	MinimumResourceProfile string `yaml:"minimumResourceProfile"`
}

type ResourcePolicyConfiguration struct {
	Users      UserResourcePolicy                 `yaml:"users"`
	Extensions map[string]ExtensionResourcePolicy `yaml:"extensions"`
}
