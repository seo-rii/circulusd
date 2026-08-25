package release

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
)

const maxManifestBytes = 4 << 20

var (
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Manifest struct {
	SchemaVersion       int               `json:"schemaVersion"`
	Release             Release           `json:"release"`
	Toolchains          map[string]string `json:"toolchains"`
	Components          []Component       `json:"components"`
	UnresolvedArtifacts []string          `json:"unresolvedArtifacts"`
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
	SHA256       string `json:"sha256"`
}

func Load(path string) (Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("open release manifest: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(io.LimitReader(file, maxManifestBytes+1))
	decoder.DisallowUnknownFields()

	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode release manifest: %w", err)
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Manifest{}, fmt.Errorf("decode release manifest: trailing JSON value")
		}
		return Manifest{}, fmt.Errorf("decode release manifest trailer: %w", err)
	}

	return manifest, nil
}

func (manifest Manifest) Validate() error {
	if manifest.SchemaVersion != 1 {
		return fmt.Errorf("schemaVersion %d is unsupported", manifest.SchemaVersion)
	}
	if manifest.Release.Version == "" {
		return fmt.Errorf("release.version is required")
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

	if len(manifest.Components) == 0 {
		return fmt.Errorf("components must not be empty")
	}
	components := make(map[string]struct{}, len(manifest.Components))
	for componentIndex, component := range manifest.Components {
		if component.Name == "" || component.Version == "" || component.License == "" || component.Source == "" || component.Qualification == "" {
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
		for artifactIndex, artifact := range component.Artifacts {
			if artifact.Architecture == "" || artifact.Name == "" {
				return fmt.Errorf("component %q artifact[%d] has an empty required field", component.Name, artifactIndex)
			}
			if artifact.Architecture != "any" {
				if _, exists := architectures[artifact.Architecture]; !exists {
					return fmt.Errorf("component %q artifact architecture %q is not released", component.Name, artifact.Architecture)
				}
			}
			if !digestPattern.MatchString(artifact.SHA256) {
				return fmt.Errorf("component %q artifact %q has an invalid SHA-256 digest", component.Name, artifact.Name)
			}
			artifactKey := artifact.Architecture + "\x00" + artifact.Name
			if _, exists := artifacts[artifactKey]; exists {
				return fmt.Errorf("component %q artifact %q for %q is duplicated", component.Name, artifact.Name, artifact.Architecture)
			}
			artifacts[artifactKey] = struct{}{}
		}
	}

	return nil
}
