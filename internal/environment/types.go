// Package environment resolves extension native-package requirements to one
// immutable, curated Execution Environment Revision. It never composes images
// online and never substitutes a backend or architecture requested by policy.
package environment

import (
	"errors"

	"github.com/hancomac/circulusd/internal/identity"
)

var (
	ErrInvalidRequest  = errors.New("environment: invalid resolution request")
	ErrInvalidRevision = errors.New("environment: invalid revision")
	ErrNoEnvironment   = errors.New("environment: no curated revision satisfies the request")
)

type Architecture string

const (
	ArchitectureX8664   Architecture = "x86_64"
	ArchitectureAArch64 Architecture = "aarch64"
)

type Backend string

const (
	BackendNsJail      Backend = "nsjail"
	BackendDocker      Backend = "docker"
	BackendFirecracker Backend = "firecracker"
)

type Package struct {
	ID      string
	Version string
	Digest  string
}

type NsJailArtifact struct {
	RootfsDigest string
}

type DockerArtifact struct {
	ImageDigest string
}

type FirecrackerArtifact struct {
	KernelDigest string
	RootfsDigest string
}

type BackendArtifacts struct {
	NsJail      *NsJailArtifact
	Docker      *DockerArtifact
	Firecracker *FirecrackerArtifact
}

type Revision struct {
	ID                     identity.ID
	Digest                 string
	Architecture           Architecture
	Packages               []Package
	SandboxdDigest         string
	SeccompProfileDigest   string
	FilesystemPolicyDigest string
	Artifacts              BackendArtifacts
}

type Requirement struct {
	PackageID  string
	Constraint string
}

type Request struct {
	Architecture     Architecture
	RequiredBackends []Backend
	Requirements     []Requirement
}

type Resolver struct {
	revisions []Revision
}
