// Package extensionregistry verifies offline extension and security-assessment
// signatures, stores immutable installed revisions, and compiles a selected set
// into one content-addressed runtime revision.
package extensionregistry

import (
	"crypto/ed25519"
	"errors"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/environment"
)

var (
	ErrInvalidRecord       = errors.New("extension registry: invalid signed record")
	ErrUntrusted           = errors.New("extension registry: signature is not trusted")
	ErrConflict            = errors.New("extension registry: immutable revision conflict")
	ErrNotFound            = errors.New("extension registry: selected revision was not found")
	ErrInvalidRequest      = errors.New("extension registry: invalid runtime compile request")
	ErrNoCompatibleBackend = errors.New("extension registry: selected backend does not satisfy extension policy")
)

type ProcessScope string

const (
	ProcessScopeShared  ProcessScope = "shared"
	ProcessScopeTenant  ProcessScope = "tenant"
	ProcessScopeSession ProcessScope = "session"
)

type OuterIsolation string

const (
	OuterIsolationNone        OuterIsolation = "none"
	OuterIsolationNsJail      OuterIsolation = "nsjail"
	OuterIsolationDocker      OuterIsolation = "docker"
	OuterIsolationFirecracker OuterIsolation = "firecracker"
)

type TrustClass string

const (
	TrustClassPlatformReviewed TrustClass = "platform-reviewed"
	TrustClassTenantReviewed   TrustClass = "tenant-reviewed"
	TrustClassSignedThirdParty TrustClass = "signed-third-party"
	TrustClassUnreviewed       TrustClass = "unreviewed"
)

type Isolation struct {
	ProcessScope   ProcessScope
	OuterIsolation OuterIsolation
}

// CompiledRevision is the security-relevant output of the hermetic extension
// manifest/compiler pipeline. Raw paths and backend-specific artifacts are
// deliberately absent.
type CompiledRevision struct {
	ID                        string
	Version                   string
	Publisher                 string
	ContentDigest             string
	RevisionDigest            string
	BundleDigest              string
	BundleSize                uint64
	SBOMDigest                string
	ConfigurationSchemaDigest string
	Priority                  int
	Tools                     []string
	NativeRequirements        []environment.Requirement
	SupportedBackends         []environment.Backend
	RequestedMinimumIsolation Isolation
	StateSchemaVersion        uint64
}

type Signature struct {
	KeyID string
	Value []byte
}

type SecurityAssessment struct {
	ExtensionDigest          string
	TrustClass               TrustClass
	AssessedAt               string
	MinimumIsolation         Isolation
	AllowedExecutionBackends []environment.Backend
	Signature                Signature
}

type SignedRevision struct {
	Revision        CompiledRevision
	BundleSignature Signature
	Assessment      SecurityAssessment
}

// TrustRoots contains separate offline trust domains for publisher bundles and
// security assessments. New snapshots every key so caller mutation cannot
// change verification authority after construction.
type TrustRoots struct {
	Bundle     map[string]ed25519.PublicKey
	Assessment map[string]ed25519.PublicKey
}

type EnvironmentResolver interface {
	Resolve(environment.Request) (environment.Revision, error)
}

type Selection struct {
	ID      string
	Version string
}

type WorkerdRevision struct {
	BinaryDigest       string
	CompatibilityDate  string
	CompatibilityFlags []string
	LoaderABIVersion   uint64
}

type PiRevision struct {
	PackageDigest     string
	AdapterABIVersion uint64
	AgentEngine       string
}

type CompileRequest struct {
	Selections             []Selection
	Configuration          canonical.Map
	Workerd                WorkerdRevision
	Pi                     PiRevision
	Architecture           environment.Architecture
	Backend                environment.Backend
	PolicyGeneration       uint64
	PolicyMinimumIsolation Isolation
}

type ResolvedExtension struct {
	ID             string
	Version        string
	ContentDigest  string
	RevisionDigest string
}

type RuntimeRevision struct {
	Digest                       string
	Workerd                      WorkerdRevision
	Pi                           PiRevision
	AgentBundleDigest            string
	Extensions                   []ResolvedExtension
	HookOrder                    []string
	ConfigurationDigest          string
	EnvironmentRequirementDigest string
	Environment                  environment.Revision
	Backend                      environment.Backend
	MinimumIsolation             Isolation
	PolicyGeneration             uint64
}

type installedRevision struct {
	revision   CompiledRevision
	assessment SecurityAssessment
}

type Registry struct {
	revisions map[string]installedRevision
	resolver  EnvironmentResolver
}
