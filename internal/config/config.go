package config

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

const (
	maximumStateHTTPTimeout          = 30 * time.Second
	maximumStateDispatchStartTimeout = 5 * time.Minute
	maximumStateEvidenceAge          = 24 * time.Hour
)

var (
	stateKeyIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	stateIdentityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
)

func Parse(reader io.Reader) (Configuration, error) {
	if reader == nil {
		return Configuration{}, ErrInvalidSyntax
	}
	document, err := io.ReadAll(io.LimitReader(reader, MaximumDocumentBytes+1))
	if err != nil {
		return Configuration{}, fmt.Errorf("%w: read failed", ErrInvalidSyntax)
	}
	if len(document) > MaximumDocumentBytes {
		return Configuration{}, ErrDocumentTooLarge
	}
	var syntax yaml.Node
	if err := yaml.Unmarshal(document, &syntax); err != nil {
		return Configuration{}, fmt.Errorf("%w: %v", ErrInvalidSyntax, err)
	}
	var inspect func(*yaml.Node) error
	inspect = func(node *yaml.Node) error {
		if node.Kind == yaml.AliasNode || node.Anchor != "" || node.Style&yaml.TaggedStyle != 0 {
			return ErrInvalidSyntax
		}
		for _, child := range node.Content {
			if err := inspect(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := inspect(&syntax); err != nil {
		return Configuration{}, err
	}

	decoder := yaml.NewDecoder(bytes.NewReader(document))
	decoder.KnownFields(true)
	var configuration Configuration
	if err := decoder.Decode(&configuration); err != nil {
		return Configuration{}, fmt.Errorf("%w: %v", ErrInvalidSyntax, err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Configuration{}, ErrInvalidSyntax
	}
	if err := configuration.Validate(); err != nil {
		return Configuration{}, err
	}
	return configuration, nil
}

func (configuration Configuration) Validate() error {
	if configuration.Deployment.Mode == DeploymentMultiNode {
		return ErrUnsupportedDeployment
	}
	if configuration.Deployment.Mode != DeploymentSingleNode {
		return fmt.Errorf("%w: deployment mode", ErrInvalidConfiguration)
	}
	host, port, err := net.SplitHostPort(configuration.Server.PublicAddress)
	parsedPort, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || !validNetworkHost(host) || portErr != nil || parsedPort == 0 ||
		!validAbsolutePath(configuration.Server.DataDirectory) || configuration.Server.DataDirectory == "/" {
		return fmt.Errorf("%w: server", ErrInvalidConfiguration)
	}
	stateEndpoint := configuration.State.Endpoint
	stateIP := net.ParseIP(stateEndpoint.host)
	statePort, statePortErr := strconv.ParseUint(stateEndpoint.port, 10, 16)
	if configuration.State.Provider != "celld" || stateEndpoint.scheme != "http" ||
		stateIP == nil || !stateIP.IsLoopback() || statePortErr != nil || statePort == 0 ||
		strconv.FormatUint(statePort, 10) != stateEndpoint.port || stateEndpoint.path != "" ||
		stateEndpoint.authority != net.JoinHostPort(stateIP.String(), stateEndpoint.port) {
		return fmt.Errorf("%w: state provider", ErrInvalidConfiguration)
	}
	state := configuration.State
	if !stateKeyIDPattern.MatchString(state.ReadKeyID) ||
		!stateKeyIDPattern.MatchString(state.DispatchStartKeyID) ||
		state.ReadKeyID == state.DispatchStartKeyID ||
		state.HTTPTimeout.Duration() <= 0 ||
		state.HTTPTimeout.Duration() > maximumStateHTTPTimeout ||
		state.DispatchStartTimeout.Duration() <= 0 ||
		state.DispatchStartTimeout.Duration() > maximumStateDispatchStartTimeout ||
		!stateIdentityPattern.MatchString(state.InstanceID) ||
		!stateIdentityPattern.MatchString(state.TransactionDomainID) ||
		state.MinimumProbeEpoch == 0 ||
		state.MaximumEvidenceAge.Duration() <= 0 ||
		state.MaximumEvidenceAge.Duration() > maximumStateEvidenceAge {
		return fmt.Errorf("%w: state production boundary", ErrInvalidConfiguration)
	}
	stateFiles := []string{
		state.ReadRootKeyFile,
		state.DispatchStartRootKeyFile,
		state.ProductionEvidenceFile,
		state.ConformanceRootsFile,
		state.RuntimeRootsFile,
	}
	seenStateFiles := make(map[string]struct{}, len(stateFiles))
	for _, path := range stateFiles {
		if !validAbsolutePath(path) || path == "/" {
			return fmt.Errorf("%w: state production file", ErrInvalidConfiguration)
		}
		if _, duplicate := seenStateFiles[path]; duplicate {
			return fmt.Errorf("%w: state production files must be distinct", ErrInvalidConfiguration)
		}
		seenStateFiles[path] = struct{}{}
	}
	objectStoreIP := net.ParseIP(configuration.ObjectStore.Endpoint.host)
	if (configuration.ObjectStore.Endpoint.scheme != "http" && configuration.ObjectStore.Endpoint.scheme != "https") ||
		objectStoreIP == nil || !objectStoreIP.IsLoopback() {
		return fmt.Errorf("%w: object store endpoint", ErrInvalidConfiguration)
	}
	buckets := []string{
		configuration.ObjectStore.StateBucket,
		configuration.ObjectStore.WorkspaceBlobBucket,
		configuration.ObjectStore.ArtifactBucket,
	}
	seenBuckets := make(map[string]struct{}, len(buckets))
	for _, bucket := range buckets {
		validBucket := len(bucket) >= 3 && len(bucket) <= 63 &&
			!strings.HasPrefix(bucket, "-") && !strings.HasSuffix(bucket, "-")
		for _, character := range bucket {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				validBucket = false
			}
		}
		if !validBucket {
			return fmt.Errorf("%w: object store bucket", ErrInvalidConfiguration)
		}
		if _, duplicate := seenBuckets[bucket]; duplicate {
			return fmt.Errorf("%w: object store buckets must be distinct", ErrInvalidConfiguration)
		}
		seenBuckets[bucket] = struct{}{}
	}
	isolation := configuration.Agent.DefaultIsolation
	validIsolation := (isolation.ProcessScope == "shared" || isolation.ProcessScope == "tenant" ||
		isolation.ProcessScope == "session") &&
		(isolation.OuterIsolation == "none" || isolation.OuterIsolation == "nsjail" ||
			isolation.OuterIsolation == "docker" || isolation.OuterIsolation == "firecracker")
	sharedShard := isolation.ProcessScope == "shared" || isolation.ProcessScope == "tenant"
	if configuration.Agent.Runtime != "workerd" || !configuration.Agent.PerSessionIsolate || !validIsolation ||
		configuration.Agent.Shard.MaxResidentSessions == 0 ||
		configuration.Agent.Shard.MaximumLifetime.Duration() <= 0 ||
		configuration.Agent.Shard.MemoryLimit.Bytes() == 0 ||
		configuration.Agent.Shard.MemoryAdmissionHighWatermark == 0 ||
		!configuration.Agent.Shard.RecycleOnOOM ||
		(sharedShard && (configuration.Agent.Shard.CPU == 0 || !configuration.Agent.Shard.RecycleOnHeapPressure)) {
		return fmt.Errorf("%w: agent", ErrInvalidConfiguration)
	}
	if len(configuration.Execution.AllowedBackends) == 0 || configuration.Execution.Fallback.Mode != "disabled" ||
		(configuration.Execution.SandboxScope != "auto" && configuration.Execution.SandboxScope != "session" &&
			configuration.Execution.SandboxScope != "invocation") ||
		configuration.Execution.WorkspaceProjection != "materialized-manifest" {
		return fmt.Errorf("%w: execution policy", ErrInvalidConfiguration)
	}
	seenBackends := make(map[Backend]struct{}, len(configuration.Execution.AllowedBackends))
	for _, backend := range configuration.Execution.AllowedBackends {
		if backend != BackendNsJail && backend != BackendDocker && backend != BackendFirecracker {
			return fmt.Errorf("%w: unknown execution backend", ErrInvalidConfiguration)
		}
		if _, duplicate := seenBackends[backend]; duplicate {
			return fmt.Errorf("%w: duplicate execution backend", ErrInvalidConfiguration)
		}
		seenBackends[backend] = struct{}{}
		enabled := false
		switch backend {
		case BackendNsJail:
			enabled = configuration.Executors.NsJail.Enabled
		case BackendDocker:
			enabled = configuration.Executors.Docker.Enabled
		case BackendFirecracker:
			enabled = configuration.Executors.Firecracker.Enabled
		}
		if !enabled {
			return fmt.Errorf("%w: allowed execution backend is disabled", ErrInvalidConfiguration)
		}
	}
	_, nsJailAllowed := seenBackends[BackendNsJail]
	_, dockerAllowed := seenBackends[BackendDocker]
	_, firecrackerAllowed := seenBackends[BackendFirecracker]
	if configuration.Executors.NsJail.Enabled != nsJailAllowed ||
		configuration.Executors.Docker.Enabled != dockerAllowed ||
		configuration.Executors.Firecracker.Enabled != firecrackerAllowed {
		return fmt.Errorf("%w: execution backend enablement", ErrInvalidConfiguration)
	}
	if _, allowed := seenBackends[configuration.Execution.DefaultBackend]; !allowed {
		return fmt.Errorf("%w: default execution backend", ErrInvalidConfiguration)
	}
	if configuration.Executors.NsJail.Enabled &&
		(!validAbsolutePath(configuration.Executors.NsJail.Binary) ||
			!validAbsolutePath(configuration.Executors.NsJail.EnvironmentRoot) ||
			!validAbsolutePath(configuration.Executors.NsJail.CgroupRoot) ||
			!configuration.Executors.NsJail.UniqueUIDPerSandbox) {
		return fmt.Errorf("%w: nsjail executor", ErrInvalidConfiguration)
	}
	if configuration.Executors.Docker.Enabled &&
		((configuration.Executors.Docker.Mode != "system" && configuration.Executors.Docker.Mode != "rootless") ||
			configuration.Executors.Docker.Socket.scheme != "unix") {
		return fmt.Errorf("%w: docker executor", ErrInvalidConfiguration)
	}
	if configuration.Executors.Firecracker.Enabled &&
		(!validAbsolutePath(configuration.Executors.Firecracker.FirecrackerBinary) ||
			!validAbsolutePath(configuration.Executors.Firecracker.JailerBinary) ||
			!validAbsolutePath(configuration.Executors.Firecracker.KernelDirectory) ||
			!validAbsolutePath(configuration.Executors.Firecracker.RootfsDirectory)) {
		return fmt.Errorf("%w: firecracker executor", ErrInvalidConfiguration)
	}
	workspace := configuration.Workspace
	if workspace.ProjectionMode != "materialized-manifest" ||
		workspace.ProjectionMode != configuration.Execution.WorkspaceProjection ||
		(workspace.ManifestVerification != "full-scan" && workspace.ManifestVerification != "incremental") ||
		(workspace.DiffStrategy != "auto" && workspace.DiffStrategy != "full-scan" && workspace.DiffStrategy != "overlayfs") ||
		workspace.TreeManifestThreshold == 0 ||
		(workspace.LeaseWaitPolicy != "queue" && workspace.LeaseWaitPolicy != "fail") ||
		workspace.LeaseAcquireTimeout.Duration() <= 0 || workspace.BlobHash != "sha256" {
		return fmt.Errorf("%w: workspace", ErrInvalidConfiguration)
	}
	if configuration.Network.DefaultMode != "none" || configuration.Network.ProductionPolicyAuthority != "host" {
		return fmt.Errorf("%w: network", ErrInvalidConfiguration)
	}
	if len(configuration.ResourceProfiles) == 0 {
		return fmt.Errorf("%w: resource profiles", ErrInvalidConfiguration)
	}
	for name, profile := range configuration.ResourceProfiles {
		validName := name != "" && strings.TrimSpace(name) == name && len(name) <= 128
		for _, character := range name {
			if character < 0x20 || character == 0x7f {
				validName = false
			}
		}
		if !validName || profile.CPU == 0 || profile.Memory.Bytes() == 0 || profile.PIDs == 0 ||
			profile.ScratchDisk.Bytes() == 0 || profile.CommandTimeout.Duration() <= 0 || profile.OpenFiles == 0 {
			return fmt.Errorf("%w: resource profile", ErrInvalidConfiguration)
		}
	}
	if len(configuration.AgentShardProfiles) == 0 {
		return fmt.Errorf("%w: agent shard profiles", ErrInvalidConfiguration)
	}
	for name, profile := range configuration.AgentShardProfiles {
		validName := name != "" && strings.TrimSpace(name) == name && len(name) <= 128
		for _, character := range name {
			if character < 0x20 || character == 0x7f {
				validName = false
			}
		}
		if !validName || profile.CPU == 0 || profile.Memory.Bytes() == 0 ||
			profile.MaxResidentSessions == 0 || profile.MaxLifetime.Duration() <= 0 {
			return fmt.Errorf("%w: agent shard profile", ErrInvalidConfiguration)
		}
	}
	maximumProfile, found := configuration.ResourceProfiles[configuration.Policy.Users.DefaultMaximumResourceProfile]
	if !found || configuration.Policy.Users.DefaultMaximumResourceProfile == "" {
		return fmt.Errorf("%w: default maximum resource profile", ErrInvalidConfiguration)
	}
	for extensionID, extensionPolicy := range configuration.Policy.Extensions {
		validExtensionID := extensionID != "" && strings.TrimSpace(extensionID) == extensionID &&
			len(extensionID) <= 256 && strings.Count(extensionID, "/") == 1 &&
			!strings.HasPrefix(extensionID, "/") && !strings.HasSuffix(extensionID, "/")
		for _, character := range extensionID {
			if character < 0x20 || character == 0x7f {
				validExtensionID = false
			}
		}
		minimumProfile, minimumFound := configuration.ResourceProfiles[extensionPolicy.MinimumResourceProfile]
		if !validExtensionID || !minimumFound || extensionPolicy.MinimumResourceProfile == "" ||
			minimumProfile.CPU > maximumProfile.CPU || minimumProfile.Memory.Bytes() > maximumProfile.Memory.Bytes() ||
			minimumProfile.Swap.Bytes() > maximumProfile.Swap.Bytes() || minimumProfile.PIDs > maximumProfile.PIDs ||
			minimumProfile.ScratchDisk.Bytes() > maximumProfile.ScratchDisk.Bytes() ||
			minimumProfile.CommandTimeout.Duration() > maximumProfile.CommandTimeout.Duration() ||
			minimumProfile.OpenFiles > maximumProfile.OpenFiles {
			return fmt.Errorf("%w: extension resource policy", ErrInvalidConfiguration)
		}
	}
	if configuration.Models.Default == "" || len(configuration.Models.Endpoints) == 0 {
		return fmt.Errorf("%w: models", ErrInvalidConfiguration)
	}
	for name, model := range configuration.Models.Endpoints {
		if name == "" || (model.Protocol != "openai-compatible" && model.Protocol != "anthropic-compatible") ||
			(model.Endpoint.scheme != "http" && model.Endpoint.scheme != "https") {
			return fmt.Errorf("%w: model endpoint", ErrInvalidConfiguration)
		}
	}
	if _, found := configuration.Models.Endpoints[configuration.Models.Default]; !found {
		return fmt.Errorf("%w: default model", ErrInvalidConfiguration)
	}
	security := configuration.Security
	if security.TurnAuthorityTTL.Duration() <= 0 || security.MaxTurnWallClock.Duration() <= 0 ||
		security.TurnAuthorityTTL.Duration() >= security.MaxTurnWallClock.Duration() ||
		security.TurnAuthorityRenewal != "lease-bound" || !security.RotatePlacementGenerationOnShardFailure ||
		security.ExposeRawSecretsToExtensions || security.UnreviewedExtensionMinimumOuterIsolation != "firecracker" {
		return fmt.Errorf("%w: security", ErrInvalidConfiguration)
	}
	if !configuration.API.RequireIdempotencyKeyForMutations ||
		configuration.API.DurableEventRetention.Duration() <= 0 ||
		configuration.Retention.WorkspaceBlobGCGrace.Duration() <= 0 ||
		configuration.Retention.ArtifactDefault.Duration() <= 0 ||
		configuration.Retention.RuntimeRollbackWindow.Duration() <= 0 {
		return fmt.Errorf("%w: retention or API", ErrInvalidConfiguration)
	}
	return nil
}

// ValidateForProfile verifies the exact backend matrix installed by the
// external air-gap installer. Full installations may operate with a subset of
// healthy backends only when strictInstall is disabled; an unavailable backend
// must already be disabled and removed from allowedBackends.
func (configuration Configuration) ValidateForProfile(profile InstallProfile) error {
	if err := configuration.Validate(); err != nil {
		return err
	}
	nsJailEnabled := configuration.Executors.NsJail.Enabled
	dockerEnabled := configuration.Executors.Docker.Enabled
	firecrackerEnabled := configuration.Executors.Firecracker.Enabled
	defaultBackend := configuration.Execution.DefaultBackend
	valid := false
	switch profile {
	case InstallProfileLightweight:
		valid = nsJailEnabled && !dockerEnabled && !firecrackerEnabled && defaultBackend == BackendNsJail
	case InstallProfileDocker:
		valid = !nsJailEnabled && dockerEnabled && !firecrackerEnabled && defaultBackend == BackendDocker
	case InstallProfileFirecracker:
		valid = !nsJailEnabled && !dockerEnabled && firecrackerEnabled && defaultBackend == BackendFirecracker
	case InstallProfileFull:
		validDefault := defaultBackend == BackendDocker || defaultBackend == BackendNsJail
		valid = validDefault && (!configuration.StrictInstall ||
			(nsJailEnabled && dockerEnabled && firecrackerEnabled))
	case InstallProfileDevelopment:
		valid = (nsJailEnabled || dockerEnabled) && !firecrackerEnabled
	}
	if !valid {
		return fmt.Errorf("%w: %s", ErrInstallProfileMismatch, profile)
	}
	return nil
}

func validAbsolutePath(value string) bool {
	return value != "" && !containsControl(value) && filepath.IsAbs(value) && filepath.Clean(value) == value
}

func validNetworkHost(host string) bool {
	if host == "" || len(host) > 253 || containsControl(host) || strings.TrimSpace(host) != host {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	trimmed := strings.TrimSuffix(host, ".")
	if trimmed == "" {
		return false
	}
	for _, label := range strings.Split(trimmed, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func containsControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}
