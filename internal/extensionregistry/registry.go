package extensionregistry

import (
	"crypto/ed25519"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/environment"
)

const (
	maxSafeInteger = uint64(9_007_199_254_740_991)
	maxBundleBytes = uint64(8 << 20)
)

var (
	digestPattern             = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	extensionIDPattern        = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?/[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$`)
	identifierPattern         = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$`)
	semverPattern             = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	toolPattern               = regexp.MustCompile(`^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+$`)
	constraintPattern         = regexp.MustCompile(`^(?:(?:<=|>=|<|>|=|~|\^)?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?|(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?\.x)(?: +(?:(?:<=|>=|<|>|=|~|\^)?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?))*$`)
	stableVersionPattern      = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	wildcardConstraintPattern = regexp.MustCompile(`^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?\.x$`)
)

func New(roots TrustRoots, records []SignedRevision, resolver EnvironmentResolver) (*Registry, error) {
	if resolver == nil {
		return nil, fmt.Errorf("%w: environment resolver is required", ErrInvalidRecord)
	}
	resolverValue := reflect.ValueOf(resolver)
	switch resolverValue.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if resolverValue.IsNil() {
			return nil, fmt.Errorf("%w: environment resolver is required", ErrInvalidRecord)
		}
	}
	bundleRoots := make(map[string]ed25519.PublicKey, len(roots.Bundle))
	for keyID, publicKey := range roots.Bundle {
		if !identifierPattern.MatchString(keyID) || len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: bundle trust root %q is invalid", ErrInvalidRecord, keyID)
		}
		bundleRoots[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	assessmentRoots := make(map[string]ed25519.PublicKey, len(roots.Assessment))
	for keyID, publicKey := range roots.Assessment {
		if !identifierPattern.MatchString(keyID) || len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: assessment trust root %q is invalid", ErrInvalidRecord, keyID)
		}
		assessmentRoots[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	if len(bundleRoots) == 0 || len(assessmentRoots) == 0 {
		return nil, fmt.Errorf("%w: both trust domains require at least one root", ErrInvalidRecord)
	}

	installed := make(map[string]installedRevision, len(records))
	seenRevisionDigests := make(map[string]struct{}, len(records))
	for index, record := range records {
		if err := validateCompiledRevision(record.Revision); err != nil {
			return nil, fmt.Errorf("%w at index %d: %v", ErrInvalidRecord, index, err)
		}
		if err := validateAssessmentShape(record.Assessment); err != nil {
			return nil, fmt.Errorf("%w at index %d: %v", ErrInvalidRecord, index, err)
		}
		if record.Assessment.ExtensionDigest != record.Revision.ContentDigest {
			return nil, fmt.Errorf("%w at index %d: assessment targets another extension digest", ErrInvalidRecord, index)
		}
		bundleDigest, err := BundleSignatureDigest(record.Revision, record.BundleSignature.KeyID)
		if err != nil {
			return nil, fmt.Errorf("%w at index %d: %v", ErrInvalidRecord, index, err)
		}
		bundlePublicKey, bundleTrusted := bundleRoots[record.BundleSignature.KeyID]
		if !bundleTrusted || len(record.BundleSignature.Value) != ed25519.SignatureSize || !ed25519.Verify(bundlePublicKey, []byte(bundleDigest), record.BundleSignature.Value) {
			return nil, fmt.Errorf("%w at index %d: bundle signature", ErrUntrusted, index)
		}
		assessmentDigest, err := AssessmentSignatureDigest(record.Assessment)
		if err != nil {
			return nil, fmt.Errorf("%w at index %d: %v", ErrInvalidRecord, index, err)
		}
		assessmentPublicKey, assessmentTrusted := assessmentRoots[record.Assessment.Signature.KeyID]
		if !assessmentTrusted || len(record.Assessment.Signature.Value) != ed25519.SignatureSize || !ed25519.Verify(assessmentPublicKey, []byte(assessmentDigest), record.Assessment.Signature.Value) {
			return nil, fmt.Errorf("%w at index %d: assessment signature", ErrUntrusted, index)
		}
		baseline := Isolation{ProcessScope: ProcessScopeShared, OuterIsolation: OuterIsolationNone}
		switch record.Assessment.TrustClass {
		case TrustClassTenantReviewed:
			baseline.ProcessScope = ProcessScopeTenant
		case TrustClassSignedThirdParty:
			baseline.ProcessScope = ProcessScopeTenant
			if record.Assessment.MinimumIsolation.OuterIsolation == OuterIsolationNone {
				return nil, fmt.Errorf("%w at index %d: trust class %q requires nsjail, docker, or firecracker outer isolation", ErrInvalidRecord, index, record.Assessment.TrustClass)
			}
		case TrustClassUnreviewed:
			baseline = Isolation{ProcessScope: ProcessScopeSession, OuterIsolation: OuterIsolationFirecracker}
		}
		minimum := joinIsolation(baseline, record.Assessment.MinimumIsolation)
		if minimum != record.Assessment.MinimumIsolation {
			return nil, fmt.Errorf("%w at index %d: trust class %q requires at least %#v", ErrInvalidRecord, index, record.Assessment.TrustClass, baseline)
		}
		finalMinimum := joinIsolation(record.Revision.RequestedMinimumIsolation, record.Assessment.MinimumIsolation)
		hasUsableBackend := false
		for _, supported := range record.Revision.SupportedBackends {
			for _, allowed := range record.Assessment.AllowedExecutionBackends {
				if supported == allowed && backendSatisfies(supported, finalMinimum.OuterIsolation) {
					hasUsableBackend = true
					break
				}
			}
			if hasUsableBackend {
				break
			}
		}
		if !hasUsableBackend {
			return nil, fmt.Errorf("%w at index %d: no mutually permitted backend satisfies the final minimum isolation", ErrInvalidRecord, index)
		}

		coordinate := record.Revision.ID + "\x00" + record.Revision.Version
		if _, duplicate := installed[coordinate]; duplicate {
			return nil, fmt.Errorf("%w: duplicate extension coordinate %s@%s", ErrConflict, record.Revision.ID, record.Revision.Version)
		}
		if _, duplicate := seenRevisionDigests[record.Revision.RevisionDigest]; duplicate {
			return nil, fmt.Errorf("%w: duplicate extension revision digest %s", ErrConflict, record.Revision.RevisionDigest)
		}
		seenRevisionDigests[record.Revision.RevisionDigest] = struct{}{}
		revision := record.Revision
		revision.Tools = append([]string(nil), revision.Tools...)
		revision.NativeRequirements = append([]environment.Requirement(nil), revision.NativeRequirements...)
		revision.SupportedBackends = append([]environment.Backend(nil), revision.SupportedBackends...)
		sort.Strings(revision.Tools)
		sort.Slice(revision.NativeRequirements, func(left, right int) bool {
			return revision.NativeRequirements[left].PackageID < revision.NativeRequirements[right].PackageID
		})
		sort.Slice(revision.SupportedBackends, func(left, right int) bool {
			return revision.SupportedBackends[left] < revision.SupportedBackends[right]
		})
		assessment := record.Assessment
		assessment.AllowedExecutionBackends, _ = normalizedBackends(assessment.AllowedExecutionBackends)
		assessment.Signature.Value = append([]byte(nil), assessment.Signature.Value...)
		installed[coordinate] = installedRevision{revision: revision, assessment: assessment}
	}
	return &Registry{revisions: installed, resolver: resolver}, nil
}

func BundleSignatureDigest(revision CompiledRevision, signingKeyID string) (string, error) {
	if err := validateCompiledRevision(revision); err != nil {
		return "", err
	}
	if !identifierPattern.MatchString(signingKeyID) {
		return "", fmt.Errorf("bundle signing key ID is not canonical")
	}
	tools := append([]string(nil), revision.Tools...)
	sort.Strings(tools)
	toolValues := make(canonical.Array, len(tools))
	for index, tool := range tools {
		toolValues[index] = tool
	}
	requirements := append([]environment.Requirement(nil), revision.NativeRequirements...)
	sort.Slice(requirements, func(left, right int) bool {
		if requirements[left].PackageID != requirements[right].PackageID {
			return requirements[left].PackageID < requirements[right].PackageID
		}
		return requirements[left].Constraint < requirements[right].Constraint
	})
	requirementValues := make(canonical.Array, len(requirements))
	for index, requirement := range requirements {
		requirementValues[index] = canonical.Map{"id": requirement.PackageID, "version": requirement.Constraint}
	}
	backends := append([]environment.Backend(nil), revision.SupportedBackends...)
	sort.Slice(backends, func(left, right int) bool { return backends[left] < backends[right] })
	backendValues := make(canonical.Array, len(backends))
	for index, backend := range backends {
		backendValues[index] = string(backend)
	}
	return canonical.StructuredDigest("circulusd.extension.bundle-signature", 1, canonical.Map{
		"signingKeyId":              signingKeyID,
		"id":                        revision.ID,
		"version":                   revision.Version,
		"publisher":                 revision.Publisher,
		"contentDigest":             revision.ContentDigest,
		"revisionDigest":            revision.RevisionDigest,
		"bundleDigest":              revision.BundleDigest,
		"bundleSize":                revision.BundleSize,
		"sbomDigest":                revision.SBOMDigest,
		"configurationSchemaDigest": revision.ConfigurationSchemaDigest,
		"priority":                  int64(revision.Priority),
		"tools":                     toolValues,
		"nativeRequirements":        requirementValues,
		"supportedBackends":         backendValues,
		"requestedMinimumIsolation": isolationValue(revision.RequestedMinimumIsolation),
		"stateSchemaVersion":        revision.StateSchemaVersion,
	})
}

func AssessmentSignatureDigest(assessment SecurityAssessment) (string, error) {
	if err := validateAssessmentShape(assessment); err != nil {
		return "", err
	}
	if !identifierPattern.MatchString(assessment.Signature.KeyID) {
		return "", fmt.Errorf("assessment signing key ID is not canonical")
	}
	backends := append([]environment.Backend(nil), assessment.AllowedExecutionBackends...)
	sort.Slice(backends, func(left, right int) bool { return backends[left] < backends[right] })
	backendValues := make(canonical.Array, len(backends))
	for index, backend := range backends {
		backendValues[index] = string(backend)
	}
	return canonical.StructuredDigest("circulusd.extension.security-assessment-signature", 1, canonical.Map{
		"assessorKeyId":            assessment.Signature.KeyID,
		"extensionDigest":          assessment.ExtensionDigest,
		"trustClass":               string(assessment.TrustClass),
		"assessedAt":               assessment.AssessedAt,
		"minimumIsolation":         isolationValue(assessment.MinimumIsolation),
		"allowedExecutionBackends": backendValues,
	})
}

func validateCompiledRevision(revision CompiledRevision) error {
	if !extensionIDPattern.MatchString(revision.ID) || !semverPattern.MatchString(revision.Version) || !identifierPattern.MatchString(revision.Publisher) {
		return fmt.Errorf("extension identity metadata is not canonical")
	}
	for name, digest := range map[string]string{
		"content": revision.ContentDigest, "revision": revision.RevisionDigest, "bundle": revision.BundleDigest,
		"SBOM": revision.SBOMDigest, "configuration schema": revision.ConfigurationSchemaDigest,
	} {
		if !digestPattern.MatchString(digest) {
			return fmt.Errorf("%s digest is not canonical SHA-256", name)
		}
	}
	if revision.BundleSize == 0 || revision.BundleSize > maxBundleBytes || revision.Priority < -1_000_000 || revision.Priority > 1_000_000 || revision.StateSchemaVersion == 0 || revision.StateSchemaVersion > maxSafeInteger {
		return fmt.Errorf("extension numeric metadata is outside supported bounds")
	}
	if err := validateIsolation(revision.RequestedMinimumIsolation); err != nil {
		return fmt.Errorf("requested isolation: %w", err)
	}
	if len(revision.Tools) > 4096 || len(revision.NativeRequirements) > 4096 || len(revision.SupportedBackends) == 0 || len(revision.SupportedBackends) > 3 {
		return fmt.Errorf("extension collection size is outside supported bounds")
	}
	seenTools := make(map[string]struct{}, len(revision.Tools))
	for _, tool := range revision.Tools {
		if !toolPattern.MatchString(tool) {
			return fmt.Errorf("tool %q is not canonical", tool)
		}
		if _, duplicate := seenTools[tool]; duplicate {
			return fmt.Errorf("duplicate tool %q", tool)
		}
		seenTools[tool] = struct{}{}
	}
	seenPackages := make(map[string]struct{}, len(revision.NativeRequirements))
	for _, requirement := range revision.NativeRequirements {
		if !identifierPattern.MatchString(requirement.PackageID) || len(requirement.Constraint) > 256 || !constraintPattern.MatchString(requirement.Constraint) {
			return fmt.Errorf("native package requirement %q is not canonical", requirement.PackageID)
		}
		if _, err := normalizeConstraint(requirement.Constraint); err != nil {
			return fmt.Errorf("native package requirement %q: %w", requirement.PackageID, err)
		}
		if _, duplicate := seenPackages[requirement.PackageID]; duplicate {
			return fmt.Errorf("duplicate native package requirement %q", requirement.PackageID)
		}
		seenPackages[requirement.PackageID] = struct{}{}
	}
	if _, err := normalizedBackends(revision.SupportedBackends); err != nil {
		return err
	}
	return nil
}

func validateAssessmentShape(assessment SecurityAssessment) error {
	if !digestPattern.MatchString(assessment.ExtensionDigest) {
		return fmt.Errorf("assessment extension digest is not canonical SHA-256")
	}
	switch assessment.TrustClass {
	case TrustClassPlatformReviewed, TrustClassTenantReviewed, TrustClassSignedThirdParty, TrustClassUnreviewed:
	default:
		return fmt.Errorf("unsupported trust class %q", assessment.TrustClass)
	}
	parsed, err := time.Parse(time.RFC3339, assessment.AssessedAt)
	if err != nil || parsed.UTC().Format(time.RFC3339) != assessment.AssessedAt {
		return fmt.Errorf("assessedAt must be a canonical UTC RFC3339 timestamp")
	}
	if err := validateIsolation(assessment.MinimumIsolation); err != nil {
		return fmt.Errorf("assessment isolation: %w", err)
	}
	if len(assessment.AllowedExecutionBackends) == 0 || len(assessment.AllowedExecutionBackends) > 3 {
		return fmt.Errorf("assessment must allow one through three execution backends")
	}
	if _, err := normalizedBackends(assessment.AllowedExecutionBackends); err != nil {
		return err
	}
	return nil
}

func validateIsolation(isolation Isolation) error {
	switch isolation.ProcessScope {
	case ProcessScopeShared, ProcessScopeTenant, ProcessScopeSession:
	default:
		return fmt.Errorf("unsupported process scope %q", isolation.ProcessScope)
	}
	switch isolation.OuterIsolation {
	case OuterIsolationNone, OuterIsolationNsJail, OuterIsolationDocker, OuterIsolationFirecracker:
	default:
		return fmt.Errorf("unsupported outer isolation %q", isolation.OuterIsolation)
	}
	return nil
}

func normalizedBackends(backends []environment.Backend) ([]environment.Backend, error) {
	normalized := append([]environment.Backend(nil), backends...)
	sort.Slice(normalized, func(left, right int) bool { return normalized[left] < normalized[right] })
	for index, backend := range normalized {
		switch backend {
		case environment.BackendNsJail, environment.BackendDocker, environment.BackendFirecracker:
		default:
			return nil, fmt.Errorf("unsupported execution backend %q", backend)
		}
		if index > 0 && normalized[index-1] == backend {
			return nil, fmt.Errorf("duplicate execution backend %q", backend)
		}
	}
	return normalized, nil
}

func normalizeConstraint(constraint string) (string, error) {
	if wildcardConstraintPattern.MatchString(constraint) {
		return constraint, nil
	}
	tokens := strings.Fields(constraint)
	if len(tokens) == 0 {
		return "", fmt.Errorf("version constraint is empty")
	}
	normalized := make([]string, 0, len(tokens)+1)
	for _, token := range tokens {
		operator := ""
		for _, candidate := range []string{">=", "<=", ">", "<", "=", "^", "~"} {
			if strings.HasPrefix(token, candidate) {
				operator = candidate
				break
			}
		}
		version := strings.TrimPrefix(token, operator)
		match := stableVersionPattern.FindStringSubmatch(version)
		if match == nil {
			return "", fmt.Errorf("version constraint %q is not supported by curated environments", constraint)
		}
		if operator != "^" && operator != "~" {
			if operator == "" && len(tokens) > 1 {
				operator = "="
			}
			normalized = append(normalized, operator+version)
			continue
		}
		major, majorErr := strconv.ParseUint(match[1], 10, 64)
		minor, minorErr := strconv.ParseUint(match[2], 10, 64)
		patch, patchErr := strconv.ParseUint(match[3], 10, 64)
		if majorErr != nil || minorErr != nil || patchErr != nil {
			return "", fmt.Errorf("version constraint %q exceeds numeric bounds", constraint)
		}
		normalized = append(normalized, ">="+version)
		switch {
		case operator == "~":
			if minor == ^uint64(0) {
				return "", fmt.Errorf("version constraint %q exceeds numeric bounds", constraint)
			}
			normalized = append(normalized, fmt.Sprintf("<%d.%d.0", major, minor+1))
		case major > 0:
			if major == ^uint64(0) {
				return "", fmt.Errorf("version constraint %q exceeds numeric bounds", constraint)
			}
			normalized = append(normalized, fmt.Sprintf("<%d.0.0", major+1))
		case minor > 0:
			if minor == ^uint64(0) {
				return "", fmt.Errorf("version constraint %q exceeds numeric bounds", constraint)
			}
			normalized = append(normalized, fmt.Sprintf("<0.%d.0", minor+1))
		default:
			if patch == ^uint64(0) {
				return "", fmt.Errorf("version constraint %q exceeds numeric bounds", constraint)
			}
			normalized = append(normalized, fmt.Sprintf("<0.0.%d", patch+1))
		}
	}
	return strings.Join(normalized, " "), nil
}

func isolationValue(isolation Isolation) canonical.Map {
	return canonical.Map{"processScope": string(isolation.ProcessScope), "outerIsolation": string(isolation.OuterIsolation)}
}
