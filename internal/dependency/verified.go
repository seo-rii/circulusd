// Package dependency verifies production state dependencies before they enter
// a service graph. Boolean capability claims are deliberately insufficient:
// verification binds signed conformance evidence, a live runtime challenge,
// the exact adapter instance, and an immutable transaction-domain descriptor.
package dependency

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"slices"
	"sync"
	"time"

	"filippo.io/edwards25519"
	"github.com/hancomac/circulusd/internal/canonical"
)

const (
	ChallengeBytes = 32

	BackendCelld           = "celld"
	BackendReferenceMemory = "reference-memory"

	DurabilityCrashRPOZero = "crash-durable-rpo0"
	DurabilityProcessLocal = "process-local"

	verificationSchemaVersion = 1
	maximumIdentifierBytes    = 256
	evidenceSignatureDomain   = "circulusd.production-dependency-evidence"
	probeSignatureDomain      = "circulusd.production-dependency-probe"
)

var (
	ErrInvalidConfiguration      = errors.New("dependency: invalid verifier configuration")
	ErrInvalidDescriptor         = errors.New("dependency: invalid descriptor")
	ErrUnverifiedDependency      = errors.New("dependency: unverified production dependency")
	ErrEvidenceExpired           = errors.New("dependency: conformance evidence is stale or expired")
	ErrRequirementMismatch       = errors.New("dependency: production requirement mismatch")
	ErrTransactionDomainMismatch = errors.New("dependency: transaction domain mismatch")

	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

	inverseEd25519Cofactor = func() edwards25519.Scalar {
		var encoded [32]byte
		encoded[0] = 8
		cofactor, err := edwards25519.NewScalar().SetCanonicalBytes(encoded[:])
		if err != nil {
			panic("dependency: invalid internal Ed25519 cofactor")
		}
		return *edwards25519.NewScalar().Invert(cofactor)
	}()
)

type AtomicGroup string

const (
	AtomicCommandReceipt  AtomicGroup = "command-receipt"
	AtomicEffectLifecycle AtomicGroup = "effect-lifecycle"
	AtomicQuotaSettlement AtomicGroup = "quota-settlement"
	AtomicPublicEvent     AtomicGroup = "public-idempotency-event"
)

// Descriptor is the immutable identity measured by both an offline
// conformance run and a live dependency probe. AtomicGroups name transaction
// groups, not independent feature booleans.
type Descriptor struct {
	SchemaVersion       uint32
	BackendKind         string
	BuildDigest         string
	ApplicationDigest   string
	InstanceID          string
	TransactionDomainID string
	DurabilityClass     string
	ConformanceRunID    string
	ConformanceDigest   string
	RuntimeKeyID        string
	ProbeEpoch          uint64
	ProductionEligible  bool
	AtomicGroups        []AtomicGroup
}

type Evidence struct {
	Descriptor    Descriptor
	IssuedAtUnix  int64
	ExpiresAtUnix int64
	KeyID         string
	Signature     []byte
}

func (Evidence) String() string   { return "production-dependency-evidence<redacted>" }
func (Evidence) GoString() string { return "production-dependency-evidence<redacted>" }

type ProbeChallenge struct {
	Nonce []byte
}

func (ProbeChallenge) String() string   { return "production-probe-challenge<redacted>" }
func (ProbeChallenge) GoString() string { return "production-probe-challenge<redacted>" }

type ProbeResponse struct {
	Descriptor Descriptor
	KeyID      string
	Signature  []byte
}

func (ProbeResponse) String() string   { return "production-probe-response<redacted>" }
func (ProbeResponse) GoString() string { return "production-probe-response<redacted>" }

// ProductionProbe must challenge the same concrete dependency that is wrapped
// by VerifyDependency. The signed response proves liveness of the configured
// runtime identity; it is not a caller-supplied durability declaration.
type ProductionProbe interface {
	ProbeProduction(context.Context, ProbeChallenge) (ProbeResponse, error)
}

type Requirements struct {
	BackendKind          string
	BuildDigest          string
	ApplicationDigest    string
	InstanceID           string
	TransactionDomainID  string
	RequiredAtomicGroups []AtomicGroup
	MinimumProbeEpoch    uint64
	MaximumEvidenceAge   time.Duration
	seal                 *productionRequirementsSeal
}

type VerifierConfig struct {
	ConformanceRoots map[string]ed25519.PublicKey
	RuntimeRoots     map[string]ed25519.PublicKey
	Clock            func() time.Time
	Entropy          io.Reader
}

// Verifier owns defensive copies of all roots. Production bootstrap is
// responsible for loading these roots from its pinned trust configuration.
type Verifier struct {
	conformanceRoots map[string]ed25519.PublicKey
	runtimeRoots     map[string]ed25519.PublicKey
	clock            func() time.Time
	entropy          io.Reader
	challengeMu      sync.Mutex
	issuedChallenges map[[ChallengeBytes]byte]struct{}
}

func NewVerifier(config VerifierConfig) (*Verifier, error) {
	if len(config.ConformanceRoots) == 0 || len(config.RuntimeRoots) == 0 || config.Clock == nil || interfaceNil(config.Entropy) {
		return nil, ErrInvalidConfiguration
	}
	conformanceRoots, err := copyRoots(config.ConformanceRoots)
	if err != nil {
		return nil, err
	}
	runtimeRoots, err := copyRoots(config.RuntimeRoots)
	if err != nil {
		return nil, err
	}
	for conformanceKeyID, conformanceRoot := range conformanceRoots {
		for runtimeKeyID, runtimeRoot := range runtimeRoots {
			if conformanceKeyID == runtimeKeyID || bytes.Equal(conformanceRoot, runtimeRoot) {
				return nil, ErrInvalidConfiguration
			}
		}
	}
	return &Verifier{
		conformanceRoots: conformanceRoots,
		runtimeRoots:     runtimeRoots,
		clock:            config.Clock,
		entropy:          config.Entropy,
		issuedChallenges: make(map[[ChallengeBytes]byte]struct{}),
	}, nil
}

type verificationSeal struct {
	descriptorDigest string
	evidenceDigest   string
	probeDigest      string
}

// Verified can only contain a non-nil seal after VerifyDependency succeeds.
// The dependency itself is kept private so production constructors can accept
// this wrapper instead of a raw, self-asserting interface.
type Verified[T ProductionProbe] struct {
	dependency T
	descriptor Descriptor
	seal       *verificationSeal
}

func (Verified[T]) String() string   { return "verified-production-dependency<redacted>" }
func (Verified[T]) GoString() string { return "verified-production-dependency<redacted>" }

func (verified Verified[T]) Open() (T, Descriptor, error) {
	var zero T
	if verified.seal == nil || interfaceNil(verified.dependency) {
		return zero, Descriptor{}, ErrUnverifiedDependency
	}
	digest, err := descriptorDigest(verified.descriptor)
	if err != nil || digest != verified.seal.descriptorDigest {
		return zero, Descriptor{}, ErrUnverifiedDependency
	}
	return verified.dependency, cloneDescriptor(verified.descriptor), nil
}

// Binding has an unexported method, so arbitrary external types cannot pose as
// verified dependencies in an atomic-domain check.
type Binding interface {
	verifiedBinding() bindingMetadata
}

type bindingMetadata struct {
	descriptor Descriptor
	seal       *verificationSeal
}

func (verified Verified[T]) verifiedBinding() bindingMetadata {
	return bindingMetadata{descriptor: cloneDescriptor(verified.descriptor), seal: verified.seal}
}

func VerifyDependency[T ProductionProbe](
	ctx context.Context,
	verifier *Verifier,
	productionDependency T,
	evidence Evidence,
	requirements Requirements,
) (Verified[T], error) {
	if err := ctx.Err(); err != nil {
		return Verified[T]{}, err
	}
	if verifier == nil || len(verifier.conformanceRoots) == 0 || len(verifier.runtimeRoots) == 0 || verifier.clock == nil || interfaceNil(verifier.entropy) || interfaceNil(productionDependency) {
		return Verified[T]{}, ErrInvalidConfiguration
	}
	requirements.RequiredAtomicGroups = append([]AtomicGroup(nil), requirements.RequiredAtomicGroups...)
	if err := validateRequirements(requirements); err != nil {
		return Verified[T]{}, err
	}

	evidenceDigest, err := verifier.verifyEvidence(evidence, requirements)
	if err != nil {
		return Verified[T]{}, err
	}
	nonce := make([]byte, ChallengeBytes)
	verifier.challengeMu.Lock()
	_, challengeErr := io.ReadFull(verifier.entropy, nonce)
	var challengeKey [ChallengeBytes]byte
	copy(challengeKey[:], nonce)
	_, repeatedChallenge := verifier.issuedChallenges[challengeKey]
	if challengeErr == nil && !repeatedChallenge {
		verifier.issuedChallenges[challengeKey] = struct{}{}
	}
	verifier.challengeMu.Unlock()
	if challengeErr != nil || repeatedChallenge {
		return Verified[T]{}, fmt.Errorf("%w: generate live probe challenge", ErrUnverifiedDependency)
	}
	response, err := productionDependency.ProbeProduction(ctx, ProbeChallenge{Nonce: append([]byte(nil), nonce...)})
	if err != nil {
		return Verified[T]{}, fmt.Errorf("%w: runtime probe failed", ErrUnverifiedDependency)
	}
	if !equalDescriptor(response.Descriptor, evidence.Descriptor) || response.KeyID != evidence.Descriptor.RuntimeKeyID || len(response.Signature) != ed25519.SignatureSize {
		return Verified[T]{}, ErrUnverifiedDependency
	}
	runtimeRoot, trusted := verifier.runtimeRoots[response.KeyID]
	if !trusted {
		return Verified[T]{}, ErrUnverifiedDependency
	}
	probeDigest, err := ProbeSigningDigest(response.Descriptor, nonce)
	if err != nil || !ed25519.Verify(runtimeRoot, []byte(probeDigest), response.Signature) {
		return Verified[T]{}, ErrUnverifiedDependency
	}
	descriptor := cloneDescriptor(evidence.Descriptor)
	descriptorDigest, err := descriptorDigest(descriptor)
	if err != nil {
		return Verified[T]{}, ErrUnverifiedDependency
	}
	return Verified[T]{
		dependency: productionDependency,
		descriptor: descriptor,
		seal: &verificationSeal{
			descriptorDigest: descriptorDigest,
			evidenceDigest:   evidenceDigest,
			probeDigest:      probeDigest,
		},
	}, nil
}

// RequireAtomicDomain verifies that every binding was sealed, names the same
// transaction/conformance identity, and individually advertises every required
// atomic group. Atomicity therefore cannot be assembled from unrelated stores.
func RequireAtomicDomain(required []AtomicGroup, bindings ...Binding) (Descriptor, error) {
	if len(required) == 0 || len(bindings) == 0 {
		return Descriptor{}, ErrInvalidConfiguration
	}
	if err := validateAtomicGroups(required, false); err != nil {
		return Descriptor{}, ErrInvalidConfiguration
	}
	var domain Descriptor
	for index, binding := range bindings {
		if binding == nil {
			return Descriptor{}, ErrUnverifiedDependency
		}
		metadata := binding.verifiedBinding()
		if metadata.seal == nil {
			return Descriptor{}, ErrUnverifiedDependency
		}
		digest, err := descriptorDigest(metadata.descriptor)
		if err != nil || digest != metadata.seal.descriptorDigest {
			return Descriptor{}, ErrUnverifiedDependency
		}
		if !containsAtomicGroups(metadata.descriptor.AtomicGroups, required) {
			return Descriptor{}, ErrRequirementMismatch
		}
		if index == 0 {
			domain = cloneDescriptor(metadata.descriptor)
			continue
		}
		if !sameAtomicDomain(domain, metadata.descriptor) {
			return Descriptor{}, ErrTransactionDomainMismatch
		}
	}
	return cloneDescriptor(domain), nil
}

func (verifier *Verifier) verifyEvidence(evidence Evidence, requirements Requirements) (string, error) {
	if err := validateDescriptor(evidence.Descriptor); err != nil || !identifierPattern.MatchString(evidence.KeyID) || evidence.IssuedAtUnix <= 0 || evidence.ExpiresAtUnix <= evidence.IssuedAtUnix || len(evidence.Signature) != ed25519.SignatureSize {
		return "", ErrUnverifiedDependency
	}
	digest, err := EvidenceSigningDigest(evidence)
	if err != nil {
		return "", ErrUnverifiedDependency
	}
	root, trusted := verifier.conformanceRoots[evidence.KeyID]
	if !trusted || !ed25519.Verify(root, []byte(digest), evidence.Signature) {
		return "", ErrUnverifiedDependency
	}
	now := verifier.clock().Unix()
	if now < evidence.IssuedAtUnix || now >= evidence.ExpiresAtUnix || time.Duration(now-evidence.IssuedAtUnix)*time.Second > requirements.MaximumEvidenceAge {
		return "", ErrEvidenceExpired
	}
	descriptor := evidence.Descriptor
	if descriptor.BackendKind != BackendCelld || descriptor.DurabilityClass != DurabilityCrashRPOZero || !descriptor.ProductionEligible ||
		descriptor.BackendKind != requirements.BackendKind || descriptor.BuildDigest != requirements.BuildDigest ||
		descriptor.ApplicationDigest != requirements.ApplicationDigest || descriptor.InstanceID != requirements.InstanceID ||
		descriptor.TransactionDomainID != requirements.TransactionDomainID || descriptor.ProbeEpoch < requirements.MinimumProbeEpoch ||
		!containsAtomicGroups(descriptor.AtomicGroups, requirements.RequiredAtomicGroups) {
		return "", ErrRequirementMismatch
	}
	return digest, nil
}

func EvidenceSigningDigest(evidence Evidence) (string, error) {
	if err := validateDescriptor(evidence.Descriptor); err != nil || !identifierPattern.MatchString(evidence.KeyID) || evidence.IssuedAtUnix <= 0 || evidence.ExpiresAtUnix <= evidence.IssuedAtUnix {
		return "", ErrInvalidDescriptor
	}
	descriptor, err := descriptorCanonicalValue(evidence.Descriptor)
	if err != nil {
		return "", err
	}
	return canonical.StructuredDigest(evidenceSignatureDomain, verificationSchemaVersion, canonical.Map{
		"descriptor":    descriptor,
		"issuedAtUnix":  evidence.IssuedAtUnix,
		"expiresAtUnix": evidence.ExpiresAtUnix,
		"keyId":         evidence.KeyID,
	})
}

func ProbeSigningDigest(descriptor Descriptor, nonce []byte) (string, error) {
	if err := validateDescriptor(descriptor); err != nil || len(nonce) != ChallengeBytes {
		return "", ErrInvalidDescriptor
	}
	value, err := descriptorCanonicalValue(descriptor)
	if err != nil {
		return "", err
	}
	return canonical.StructuredDigest(probeSignatureDomain, verificationSchemaVersion, canonical.Map{
		"descriptor": value,
		"nonce":      canonical.Bytes(append([]byte(nil), nonce...)),
	})
}

func descriptorDigest(descriptor Descriptor) (string, error) {
	value, err := descriptorCanonicalValue(descriptor)
	if err != nil {
		return "", err
	}
	return canonical.StructuredDigest("circulusd.production-dependency-descriptor", verificationSchemaVersion, value)
}

func descriptorCanonicalValue(descriptor Descriptor) (canonical.Value, error) {
	if err := validateDescriptor(descriptor); err != nil {
		return nil, err
	}
	groups := make(canonical.Array, len(descriptor.AtomicGroups))
	for index, group := range descriptor.AtomicGroups {
		groups[index] = string(group)
	}
	return canonical.Map{
		"schemaVersion":       uint64(descriptor.SchemaVersion),
		"backendKind":         descriptor.BackendKind,
		"buildDigest":         descriptor.BuildDigest,
		"applicationDigest":   descriptor.ApplicationDigest,
		"instanceId":          descriptor.InstanceID,
		"transactionDomainId": descriptor.TransactionDomainID,
		"durabilityClass":     descriptor.DurabilityClass,
		"conformanceRunId":    descriptor.ConformanceRunID,
		"conformanceDigest":   descriptor.ConformanceDigest,
		"runtimeKeyId":        descriptor.RuntimeKeyID,
		"probeEpoch":          descriptor.ProbeEpoch,
		"productionEligible":  descriptor.ProductionEligible,
		"atomicGroups":        groups,
	}, nil
}

func validateDescriptor(descriptor Descriptor) error {
	if descriptor.SchemaVersion != verificationSchemaVersion ||
		(descriptor.BackendKind != BackendCelld && descriptor.BackendKind != BackendReferenceMemory) ||
		!digestPattern.MatchString(descriptor.BuildDigest) || !digestPattern.MatchString(descriptor.ApplicationDigest) ||
		!identifierPattern.MatchString(descriptor.InstanceID) || !identifierPattern.MatchString(descriptor.TransactionDomainID) ||
		!identifierPattern.MatchString(descriptor.ConformanceRunID) || !digestPattern.MatchString(descriptor.ConformanceDigest) ||
		!identifierPattern.MatchString(descriptor.RuntimeKeyID) || descriptor.ProbeEpoch == 0 ||
		len(descriptor.InstanceID) > maximumIdentifierBytes || len(descriptor.TransactionDomainID) > maximumIdentifierBytes ||
		len(descriptor.AtomicGroups) == 0 {
		return ErrInvalidDescriptor
	}
	if descriptor.BackendKind == BackendCelld {
		if descriptor.DurabilityClass != DurabilityCrashRPOZero || !descriptor.ProductionEligible {
			return ErrInvalidDescriptor
		}
	} else if descriptor.DurabilityClass != DurabilityProcessLocal || descriptor.ProductionEligible {
		return ErrInvalidDescriptor
	}
	if err := validateAtomicGroups(descriptor.AtomicGroups, true); err != nil {
		return ErrInvalidDescriptor
	}
	return nil
}

func validateRequirements(requirements Requirements) error {
	if err := validateRequirementsShape(requirements); err != nil || requirements.seal == nil {
		return ErrInvalidConfiguration
	}
	digest, err := productionRequirementsDigest(requirements)
	if err != nil || digest != requirements.seal.digest {
		return ErrInvalidConfiguration
	}
	return nil
}

func validateRequirementsShape(requirements Requirements) error {
	if requirements.BackendKind != BackendCelld || !digestPattern.MatchString(requirements.BuildDigest) ||
		!digestPattern.MatchString(requirements.ApplicationDigest) || !identifierPattern.MatchString(requirements.InstanceID) ||
		!identifierPattern.MatchString(requirements.TransactionDomainID) || len(requirements.RequiredAtomicGroups) == 0 ||
		len(requirements.RequiredAtomicGroups) > maximumProductionAtomicGroups || requirements.MinimumProbeEpoch == 0 ||
		requirements.MaximumEvidenceAge <= 0 || requirements.MaximumEvidenceAge > maximumProductionEvidenceAge {
		return ErrInvalidConfiguration
	}
	if err := validateAtomicGroups(requirements.RequiredAtomicGroups, false); err != nil {
		return ErrInvalidConfiguration
	}
	return nil
}

func validateAtomicGroups(groups []AtomicGroup, requireSorted bool) error {
	seen := make(map[AtomicGroup]struct{}, len(groups))
	for index, group := range groups {
		if !identifierPattern.MatchString(string(group)) {
			return ErrInvalidDescriptor
		}
		if _, duplicate := seen[group]; duplicate {
			return ErrInvalidDescriptor
		}
		seen[group] = struct{}{}
		if requireSorted && index > 0 && groups[index-1] >= group {
			return ErrInvalidDescriptor
		}
	}
	return nil
}

func containsAtomicGroups(available []AtomicGroup, required []AtomicGroup) bool {
	set := make(map[AtomicGroup]struct{}, len(available))
	for _, group := range available {
		set[group] = struct{}{}
	}
	for _, group := range required {
		if _, found := set[group]; !found {
			return false
		}
	}
	return true
}

func sameAtomicDomain(left Descriptor, right Descriptor) bool {
	return left.BackendKind == right.BackendKind && left.BuildDigest == right.BuildDigest &&
		left.ApplicationDigest == right.ApplicationDigest && left.TransactionDomainID == right.TransactionDomainID &&
		left.DurabilityClass == right.DurabilityClass && left.ConformanceRunID == right.ConformanceRunID &&
		left.ConformanceDigest == right.ConformanceDigest
}

func equalDescriptor(left Descriptor, right Descriptor) bool {
	return left.SchemaVersion == right.SchemaVersion && left.BackendKind == right.BackendKind &&
		left.BuildDigest == right.BuildDigest && left.ApplicationDigest == right.ApplicationDigest &&
		left.InstanceID == right.InstanceID && left.TransactionDomainID == right.TransactionDomainID &&
		left.DurabilityClass == right.DurabilityClass && left.ConformanceRunID == right.ConformanceRunID &&
		left.ConformanceDigest == right.ConformanceDigest && left.RuntimeKeyID == right.RuntimeKeyID &&
		left.ProbeEpoch == right.ProbeEpoch && left.ProductionEligible == right.ProductionEligible &&
		slices.Equal(left.AtomicGroups, right.AtomicGroups)
}

func cloneDescriptor(descriptor Descriptor) Descriptor {
	descriptor.AtomicGroups = append([]AtomicGroup(nil), descriptor.AtomicGroups...)
	return descriptor
}

func copyRoots(roots map[string]ed25519.PublicKey) (map[string]ed25519.PublicKey, error) {
	copied := make(map[string]ed25519.PublicKey, len(roots))
	materials := make(map[[ed25519.PublicKeySize]byte]struct{}, len(roots))
	for keyID, publicKey := range roots {
		material, valid := canonicalPrimeOrderEd25519Key(publicKey)
		if !identifierPattern.MatchString(keyID) || !valid {
			return nil, ErrInvalidConfiguration
		}
		if _, duplicate := materials[material]; duplicate {
			return nil, ErrInvalidConfiguration
		}
		materials[material] = struct{}{}
		copied[keyID] = append(ed25519.PublicKey(nil), material[:]...)
	}
	return copied, nil
}

func canonicalPrimeOrderEd25519Key(publicKey []byte) ([ed25519.PublicKeySize]byte, bool) {
	var canonical [ed25519.PublicKeySize]byte
	if len(publicKey) != ed25519.PublicKeySize {
		return canonical, false
	}
	point, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return canonical, false
	}
	encoded := point.Bytes()
	if !bytes.Equal(encoded, publicKey) || point.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return canonical, false
	}
	primeOrderProjection := new(edwards25519.Point).ScalarMult(
		&inverseEd25519Cofactor,
		new(edwards25519.Point).MultByCofactor(point),
	)
	if point.Equal(primeOrderProjection) != 1 {
		return canonical, false
	}
	copy(canonical[:], encoded)
	return canonical, true
}

func interfaceNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
