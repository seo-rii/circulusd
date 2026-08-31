package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
)

const (
	maxManifestBytes = 4 << 20
	maxJSONInteger   = uint64(9_007_199_254_740_991)

	// ExtractionRecipeGzipSingleFileV1 identifies byte-for-byte decompression
	// of one complete gzip stream into one executable, without member selection
	// or content transformation.
	ExtractionRecipeGzipSingleFileV1 = "gzip-single-file-v1"
)

var (
	commitPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	namePattern       = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	semverPattern     = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$`)
	signingKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

	requiredProductionComponents = []string{
		"platformd",
		"agentd",
		"executord",
		"sandboxd",
		"workerd",
		"celld",
		"session-host",
		"pi-runtime",
		"state-app",
	}
	requiredProtocolPairs = []string{
		"platformd-agentd",
		"platformd-executord",
		"session-host-dynamic-worker",
		"executord-sandboxd",
		"state-app-schema",
	}
)

type Manifest struct {
	SchemaVersion         int                     `json:"schemaVersion"`
	Release               Release                 `json:"release"`
	Toolchains            map[string]string       `json:"toolchains"`
	Components            []Component             `json:"components"`
	ProtocolCompatibility []ProtocolCompatibility `json:"protocolCompatibility"`
	Signatures            []Signature             `json:"signatures"`
	UnresolvedArtifacts   []string                `json:"unresolvedArtifacts"`
}

type Release struct {
	Version       string   `json:"version"`
	Status        string   `json:"status"`
	Architectures []string `json:"architectures"`
}

type Component struct {
	Name          string     `json:"name"`
	Version       string     `json:"version"`
	Commit        string     `json:"commit"`
	License       string     `json:"license"`
	Source        string     `json:"source"`
	Qualification string     `json:"qualification"`
	Artifacts     []Artifact `json:"artifacts"`
}

type Artifact struct {
	Architecture string `json:"architecture"`
	Name         string `json:"name"`
	// SHA256 covers the exact archive bytes before extraction.
	SHA256                    string     `json:"sha256"`
	ExtractionRecipe          string     `json:"extractionRecipe,omitempty"`
	ExtractedExecutableSHA256 string     `json:"extractedExecutableSha256,omitempty"`
	SizeBytes                 *uint64    `json:"sizeBytes,omitempty"`
	Signature                 *Signature `json:"signature,omitempty"`
}

type ProtocolVersion struct {
	Major uint64 `json:"major"`
	Minor uint64 `json:"minor"`
}

type ProtocolCompatibility struct {
	Pair             string          `json:"pair"`
	Minimum          ProtocolVersion `json:"minimum"`
	Maximum          ProtocolVersion `json:"maximum"`
	DescriptorSHA256 string          `json:"descriptorSha256"`
	FeatureBitmap    uint64          `json:"featureBitmap,omitempty"`
}

type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyId"`
	Value     string `json:"value"`
}

func Load(path string) (Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("open release manifest: %w", err)
	}
	defer file.Close()

	encoded, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("read release manifest: %w", err)
	}
	if len(encoded) > maxManifestBytes {
		return Manifest{}, fmt.Errorf("release manifest exceeds %d bytes", maxManifestBytes)
	}

	var manifest Manifest
	if err := decodeStrictJSON(encoded, "release manifest", &manifest); err != nil {
		return Manifest{}, err
	}

	return manifest, nil
}

// Validate checks the manifest shape and promotion completeness. It validates
// signature encodings but does not establish trust or verify signature bytes;
// installers must additionally verify them against configured offline roots.
func (manifest Manifest) Validate() error {
	if manifest.SchemaVersion != 1 {
		return fmt.Errorf("schemaVersion %d is unsupported", manifest.SchemaVersion)
	}
	if !semverPattern.MatchString(manifest.Release.Version) {
		return fmt.Errorf("release.version %q is not canonical semver", manifest.Release.Version)
	}
	if manifest.Release.Status != "development" && manifest.Release.Status != "candidate" && manifest.Release.Status != "production" {
		return fmt.Errorf("release.status %q is invalid", manifest.Release.Status)
	}
	if len(manifest.Release.Architectures) == 0 {
		return fmt.Errorf("release.architectures must not be empty")
	}

	architectures := make(map[string]struct{}, len(manifest.Release.Architectures))
	for _, architecture := range manifest.Release.Architectures {
		if architecture != "x86_64" && architecture != "aarch64" {
			return fmt.Errorf("release architecture %q is unsupported", architecture)
		}
		if _, exists := architectures[architecture]; exists {
			return fmt.Errorf("release architecture %q is duplicated", architecture)
		}
		architectures[architecture] = struct{}{}
	}

	requiredToolchains := map[string]struct{}{
		"go":     {},
		"node":   {},
		"pnpm":   {},
		"protoc": {},
	}
	if manifest.Release.Status != "development" {
		requiredToolchains["protocGenGo"] = struct{}{}
		requiredToolchains["protocGenConnectGo"] = struct{}{}
	}
	allowedToolchains := map[string]struct{}{
		"go":                 {},
		"node":               {},
		"pnpm":               {},
		"protoc":             {},
		"protocGenGo":        {},
		"protocGenConnectGo": {},
	}
	for name, version := range manifest.Toolchains {
		if _, allowed := allowedToolchains[name]; !allowed {
			return fmt.Errorf("toolchain %q is unsupported", name)
		}
		if version == "" || len(version) > 128 {
			return fmt.Errorf("toolchain %q has an invalid version", name)
		}
	}
	for name := range requiredToolchains {
		if manifest.Toolchains[name] == "" {
			return fmt.Errorf("toolchain %q is required", name)
		}
	}

	if len(manifest.Components) == 0 {
		return fmt.Errorf("components must not be empty")
	}
	components := make(map[string]struct{}, len(manifest.Components))
	for componentIndex, component := range manifest.Components {
		if !namePattern.MatchString(component.Name) ||
			component.Version == "" || len(component.Version) > 128 ||
			component.License == "" || len(component.License) > 128 ||
			component.Source == "" ||
			component.Qualification == "" || len(component.Qualification) > 128 {
			return fmt.Errorf("component[%d] has an empty required field", componentIndex)
		}
		if _, exists := components[component.Name]; exists {
			return fmt.Errorf("component %q is duplicated", component.Name)
		}
		components[component.Name] = struct{}{}
		if !commitPattern.MatchString(component.Commit) {
			return fmt.Errorf("component %q commit must be a lowercase 40-character git digest", component.Name)
		}
		sourceURL, err := url.Parse(component.Source)
		if err != nil || sourceURL.Scheme != "https" || sourceURL.Host == "" {
			return fmt.Errorf("component %q source must be an absolute HTTPS URL", component.Name)
		}

		artifacts := make(map[string]struct{}, len(component.Artifacts))
		coveredArchitectures := make(map[string]struct{}, len(component.Artifacts))
		for artifactIndex, artifact := range component.Artifacts {
			if artifact.Architecture == "" || artifact.Name == "" ||
				len(artifact.Name) > 255 || strings.ContainsAny(artifact.Name, `/\\`) {
				return fmt.Errorf("component %q artifact[%d] has an empty required field", component.Name, artifactIndex)
			}
			if artifact.Architecture != "any" {
				if _, exists := architectures[artifact.Architecture]; !exists {
					return fmt.Errorf("component %q artifact architecture %q is not released", component.Name, artifact.Architecture)
				}
			}
			coveredArchitectures[artifact.Architecture] = struct{}{}
			if !digestPattern.MatchString(artifact.SHA256) {
				return fmt.Errorf("component %q artifact %q has an invalid archive SHA-256 digest", component.Name, artifact.Name)
			}
			hasExtractionProvenance := artifact.ExtractionRecipe != "" || artifact.ExtractedExecutableSHA256 != ""
			if component.Name == "workerd" || hasExtractionProvenance {
				if artifact.ExtractionRecipe != ExtractionRecipeGzipSingleFileV1 {
					return fmt.Errorf("component %q artifact %q has an invalid extraction recipe", component.Name, artifact.Name)
				}
				if !digestPattern.MatchString(artifact.ExtractedExecutableSHA256) {
					return fmt.Errorf("component %q artifact %q has an invalid extracted executable SHA-256 digest", component.Name, artifact.Name)
				}
			}
			if artifact.SizeBytes != nil && *artifact.SizeBytes > maxJSONInteger {
				return fmt.Errorf("component %q artifact %q size exceeds the JSON safe-integer range", component.Name, artifact.Name)
			}
			if manifest.Release.Status != "development" &&
				(artifact.SizeBytes == nil || *artifact.SizeBytes == 0) {
				return fmt.Errorf("component %q artifact %q requires a positive signed size", component.Name, artifact.Name)
			}
			artifactKey := artifact.Architecture + "\x00" + artifact.Name
			if _, exists := artifacts[artifactKey]; exists {
				return fmt.Errorf("component %q artifact %q for %q is duplicated", component.Name, artifact.Name, artifact.Architecture)
			}
			artifacts[artifactKey] = struct{}{}

			if artifact.Signature != nil {
				if artifact.Signature.Algorithm != "ed25519" ||
					!signingKeyPattern.MatchString(artifact.Signature.KeyID) {
					return fmt.Errorf("component %q artifact %q has invalid signature metadata", component.Name, artifact.Name)
				}
				decoded, err := base64.StdEncoding.Strict().DecodeString(artifact.Signature.Value)
				if err != nil || len(decoded) != ed25519.SignatureSize {
					return fmt.Errorf("component %q artifact %q has an invalid Ed25519 signature", component.Name, artifact.Name)
				}
			}
			if manifest.Release.Status != "development" && artifact.Signature == nil {
				return fmt.Errorf("component %q artifact %q is unsigned", component.Name, artifact.Name)
			}
		}
		if manifest.Release.Status != "development" {
			if len(component.Artifacts) == 0 {
				return fmt.Errorf("component %q has no release artifact", component.Name)
			}
			if _, coversAll := coveredArchitectures["any"]; !coversAll {
				for architecture := range architectures {
					if _, covered := coveredArchitectures[architecture]; !covered {
						return fmt.Errorf("component %q has no artifact for %q", component.Name, architecture)
					}
				}
			}
		}
	}

	unresolved := make(map[string]struct{}, len(manifest.UnresolvedArtifacts))
	for index, item := range manifest.UnresolvedArtifacts {
		if item == "" || len(item) > 1024 {
			return fmt.Errorf("unresolvedArtifacts[%d] is invalid", index)
		}
		if _, duplicate := unresolved[item]; duplicate {
			return fmt.Errorf("unresolved artifact %q is duplicated", item)
		}
		unresolved[item] = struct{}{}
	}

	pairs := make(map[string]struct{}, len(manifest.ProtocolCompatibility))
	for index, compatibility := range manifest.ProtocolCompatibility {
		knownPair := false
		for _, required := range requiredProtocolPairs {
			if compatibility.Pair == required {
				knownPair = true
				break
			}
		}
		if !knownPair {
			return fmt.Errorf("protocolCompatibility[%d] pair %q is unsupported", index, compatibility.Pair)
		}
		if _, duplicate := pairs[compatibility.Pair]; duplicate {
			return fmt.Errorf("protocol pair %q is duplicated", compatibility.Pair)
		}
		pairs[compatibility.Pair] = struct{}{}
		if compatibility.Minimum.Major > compatibility.Maximum.Major ||
			(compatibility.Minimum.Major == compatibility.Maximum.Major &&
				compatibility.Minimum.Minor > compatibility.Maximum.Minor) {
			return fmt.Errorf("protocol pair %q has a reversed version range", compatibility.Pair)
		}
		if compatibility.Minimum.Major > maxJSONInteger ||
			compatibility.Minimum.Minor > maxJSONInteger ||
			compatibility.Maximum.Major > maxJSONInteger ||
			compatibility.Maximum.Minor > maxJSONInteger ||
			compatibility.FeatureBitmap > maxJSONInteger {
			return fmt.Errorf("protocol pair %q exceeds the JSON safe-integer range", compatibility.Pair)
		}
		if !digestPattern.MatchString(compatibility.DescriptorSHA256) {
			return fmt.Errorf("protocol pair %q has an invalid descriptor digest", compatibility.Pair)
		}
	}

	for index, signature := range manifest.Signatures {
		if signature.Algorithm != "ed25519" || !signingKeyPattern.MatchString(signature.KeyID) {
			return fmt.Errorf("signature[%d] has invalid metadata", index)
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(signature.Value)
		if err != nil || len(decoded) != ed25519.SignatureSize {
			return fmt.Errorf("signature[%d] is not a valid Ed25519 signature", index)
		}
	}

	if manifest.Release.Status != "development" {
		if len(manifest.UnresolvedArtifacts) != 0 {
			return fmt.Errorf("%s release has unresolved artifacts", manifest.Release.Status)
		}
		if len(manifest.Signatures) == 0 {
			return fmt.Errorf("%s release is unsigned", manifest.Release.Status)
		}
		for _, name := range requiredProductionComponents {
			if _, present := components[name]; !present {
				return fmt.Errorf("%s release is missing component %q", manifest.Release.Status, name)
			}
		}
		if len(pairs) != len(requiredProtocolPairs) {
			return fmt.Errorf("%s release has an incomplete protocol compatibility matrix", manifest.Release.Status)
		}
	}

	return nil
}
