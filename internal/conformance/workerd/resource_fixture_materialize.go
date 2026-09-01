package workerd

import (
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resourceQualificationCompatibilityDate is a compiled probe-inventory input.
// The qualification document supplies only operator and host inputs, never
// compatibility metadata.
const resourceQualificationCompatibilityDate = "2026-08-26"

const resourceQualificationSocketName = "qualification.sock"

var (
	//go:embed fixture/phase0-resource.capnp.tmpl fixture/session-host-resource.mjs fixture/phase0-resource-entry.mjs
	resourceFixtureFiles embed.FS

	errResourceFixtureMaterialization = errors.New("workerd resource qualification: fixture materialization failed")
)

// resourceFixtureRendering records exactly what was materialized so evidence
// can bind the artifact, configuration, and module digests of one run.
type resourceFixtureRendering struct {
	Directory      string
	SocketPath     string
	ConfigPath     string
	ArtifactDigest string
	ConfigDigest   string
	EntryDigest    string
	WorkerDigest   string
	WorkerdRelease string
}

// materializeResourceQualificationFixture renders the persistent private
// serve fixture into an existing private directory. The artifact digest binds
// the unrendered SessionHost source, the configuration digest binds the fully
// rendered workerd configuration, and the socket path is derived from the
// directory so the fixed argument vector stays the only launch input.
func materializeResourceQualificationFixture(directory string, workerdRelease string) (resourceFixtureRendering, error) {
	if _, err := resourceQualificationArguments(directory); err != nil {
		return resourceFixtureRendering{}, err
	}
	if workerdRelease == "" || len(workerdRelease) > 128 ||
		strings.TrimSpace(workerdRelease) != workerdRelease ||
		strings.ContainsAny(workerdRelease, "\r\n\x00@\"") {
		return resourceFixtureRendering{}, fmt.Errorf("%w: workerd release identity is not canonical", errResourceFixtureMaterialization)
	}
	hostTemplate, err := resourceFixtureFiles.ReadFile("fixture/session-host-resource.mjs")
	if err != nil {
		return resourceFixtureRendering{}, fmt.Errorf("%w: read session host template: %v", errResourceFixtureMaterialization, err)
	}
	configTemplate, err := resourceFixtureFiles.ReadFile("fixture/phase0-resource.capnp.tmpl")
	if err != nil {
		return resourceFixtureRendering{}, fmt.Errorf("%w: read configuration template: %v", errResourceFixtureMaterialization, err)
	}
	entry, err := resourceFixtureFiles.ReadFile("fixture/phase0-resource-entry.mjs")
	if err != nil {
		return resourceFixtureRendering{}, fmt.Errorf("%w: read worker entry module: %v", errResourceFixtureMaterialization, err)
	}
	worker, err := fixtureFiles.ReadFile("fixture/pi-worker.mjs")
	if err != nil {
		return resourceFixtureRendering{}, fmt.Errorf("%w: read pinned worker bundle: %v", errResourceFixtureMaterialization, err)
	}

	socketPath := filepath.Join(directory, resourceQualificationSocketName)
	replaceCommon := func(value string) string {
		value = strings.ReplaceAll(value, "@COMPATIBILITY_DATE@", resourceQualificationCompatibilityDate)
		return strings.ReplaceAll(value, "@COMPATIBILITY_FLAGS@", "")
	}
	renderedConfig := replaceCommon(string(configTemplate))
	renderedConfig = strings.ReplaceAll(renderedConfig, "@SOCKET_PATH@", socketPath)

	artifactDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(hostTemplate))
	configDigest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(renderedConfig)))
	renderedHost := replaceCommon(string(hostTemplate))
	renderedHost = strings.ReplaceAll(renderedHost, "@ARTIFACT_DIGEST@", artifactDigest)
	renderedHost = strings.ReplaceAll(renderedHost, "@CONFIG_DIGEST@", configDigest)
	renderedHost = strings.ReplaceAll(renderedHost, "@WORKERD_RELEASE@", workerdRelease)

	for _, rendered := range []string{renderedConfig, renderedHost} {
		if strings.Contains(rendered, "@COMPATIBILITY_") || strings.Contains(rendered, "@SOCKET_PATH@") ||
			strings.Contains(rendered, "@ARTIFACT_DIGEST@") || strings.Contains(rendered, "@CONFIG_DIGEST@") ||
			strings.Contains(rendered, "@WORKERD_RELEASE@") {
			return resourceFixtureRendering{}, fmt.Errorf("%w: unrendered placeholder remains", errResourceFixtureMaterialization)
		}
	}

	configPath := filepath.Join(directory, "phase0-resource.capnp")
	for name, contents := range map[string][]byte{
		"phase0-resource.capnp":      []byte(renderedConfig),
		"session-host-resource.mjs":  []byte(renderedHost),
		"phase0-resource-entry.mjs":  entry,
		"pi-worker.mjs":              worker,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), contents, 0o600); err != nil {
			return resourceFixtureRendering{}, fmt.Errorf("%w: write %s: %v", errResourceFixtureMaterialization, name, err)
		}
	}
	return resourceFixtureRendering{
		Directory:      directory,
		SocketPath:     socketPath,
		ConfigPath:     configPath,
		ArtifactDigest: artifactDigest,
		ConfigDigest:   configDigest,
		EntryDigest:    fmt.Sprintf("sha256:%x", sha256.Sum256(entry)),
		WorkerDigest:   fmt.Sprintf("sha256:%x", sha256.Sum256(worker)),
		WorkerdRelease: workerdRelease,
	}, nil
}
