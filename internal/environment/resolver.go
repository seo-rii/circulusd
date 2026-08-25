package environment

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

var (
	packageIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	versionPattern   = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	wildcardPattern  = regexp.MustCompile(`^(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?\.x$`)
)

type semanticVersion struct {
	major uint64
	minor uint64
	patch uint64
}

func NewResolver(revisions []Revision) (*Resolver, error) {
	registry := make([]Revision, len(revisions))
	seenIDs := make(map[identity.ID]struct{}, len(revisions))
	seenDigests := make(map[string]struct{}, len(revisions))
	for index, revision := range revisions {
		if err := validateRevisionContent(revision); err != nil {
			return nil, fmt.Errorf("%w at index %d: %v", ErrInvalidRevision, index, err)
		}
		digest, err := DigestRevision(revision)
		if err != nil {
			return nil, fmt.Errorf("%w at index %d: %v", ErrInvalidRevision, index, err)
		}
		if revision.Digest != digest {
			return nil, fmt.Errorf("%w at index %d: content digest mismatch", ErrInvalidRevision, index)
		}
		if _, duplicate := seenIDs[revision.ID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate revision ID %s", ErrInvalidRevision, revision.ID)
		}
		if _, duplicate := seenDigests[revision.Digest]; duplicate {
			return nil, fmt.Errorf("%w: duplicate revision digest %s", ErrInvalidRevision, revision.Digest)
		}
		seenIDs[revision.ID] = struct{}{}
		seenDigests[revision.Digest] = struct{}{}
		registry[index] = cloneRevision(revision)
		sort.Slice(registry[index].Packages, func(left, right int) bool {
			return registry[index].Packages[left].ID < registry[index].Packages[right].ID
		})
	}
	return &Resolver{revisions: registry}, nil
}

func (resolver *Resolver) Resolve(request Request) (Revision, error) {
	if resolver == nil || (request.Architecture != ArchitectureX8664 && request.Architecture != ArchitectureAArch64) || len(request.RequiredBackends) == 0 {
		return Revision{}, ErrInvalidRequest
	}
	requiredBackends := make(map[Backend]struct{}, len(request.RequiredBackends))
	for _, backend := range request.RequiredBackends {
		switch backend {
		case BackendNsJail, BackendDocker, BackendFirecracker:
			requiredBackends[backend] = struct{}{}
		default:
			return Revision{}, fmt.Errorf("%w: unsupported backend %q", ErrInvalidRequest, backend)
		}
	}

	type parsedRequirement struct {
		packageID string
		matches   func(semanticVersion) bool
	}
	parsed := make([]parsedRequirement, 0, len(request.Requirements))
	for _, requirement := range request.Requirements {
		if !packageIDPattern.MatchString(requirement.PackageID) || len(requirement.Constraint) > 256 {
			return Revision{}, fmt.Errorf("%w: invalid package requirement", ErrInvalidRequest)
		}
		constraint := requirement.Constraint
		if wildcard := wildcardPattern.FindStringSubmatch(constraint); wildcard != nil {
			major, _ := strconv.ParseUint(wildcard[1], 10, 64)
			if wildcard[2] == "" {
				parsed = append(parsed, parsedRequirement{packageID: requirement.PackageID, matches: func(candidate semanticVersion) bool {
					return candidate.major == major
				}})
			} else {
				minor, _ := strconv.ParseUint(wildcard[2], 10, 64)
				parsed = append(parsed, parsedRequirement{packageID: requirement.PackageID, matches: func(candidate semanticVersion) bool {
					return candidate.major == major && candidate.minor == minor
				}})
			}
			continue
		}
		if exact, err := parseVersion(constraint); err == nil {
			parsed = append(parsed, parsedRequirement{packageID: requirement.PackageID, matches: func(candidate semanticVersion) bool {
				return candidate == exact
			}})
			continue
		}
		tokens := strings.Fields(constraint)
		if len(tokens) == 0 {
			return Revision{}, fmt.Errorf("%w: empty version constraint", ErrInvalidRequest)
		}
		comparisons := make([]func(semanticVersion) bool, 0, len(tokens))
		for _, token := range tokens {
			operator := ""
			for _, candidate := range []string{">=", "<=", ">", "<", "="} {
				if strings.HasPrefix(token, candidate) {
					operator = candidate
					break
				}
			}
			if operator == "" {
				return Revision{}, fmt.Errorf("%w: invalid version constraint %q", ErrInvalidRequest, constraint)
			}
			threshold, err := parseVersion(strings.TrimPrefix(token, operator))
			if err != nil {
				return Revision{}, fmt.Errorf("%w: invalid version constraint %q", ErrInvalidRequest, constraint)
			}
			switch operator {
			case ">=":
				comparisons = append(comparisons, func(candidate semanticVersion) bool { return candidate.compare(threshold) >= 0 })
			case "<=":
				comparisons = append(comparisons, func(candidate semanticVersion) bool { return candidate.compare(threshold) <= 0 })
			case ">":
				comparisons = append(comparisons, func(candidate semanticVersion) bool { return candidate.compare(threshold) > 0 })
			case "<":
				comparisons = append(comparisons, func(candidate semanticVersion) bool { return candidate.compare(threshold) < 0 })
			case "=":
				comparisons = append(comparisons, func(candidate semanticVersion) bool { return candidate == threshold })
			}
		}
		parsed = append(parsed, parsedRequirement{packageID: requirement.PackageID, matches: func(candidate semanticVersion) bool {
			for _, comparison := range comparisons {
				if !comparison(candidate) {
					return false
				}
			}
			return true
		}})
	}

	candidates := make([]Revision, 0, len(resolver.revisions))
	for _, revision := range resolver.revisions {
		if revision.Architecture != request.Architecture {
			continue
		}
		artifactsAvailable := true
		for backend := range requiredBackends {
			switch backend {
			case BackendNsJail:
				artifactsAvailable = artifactsAvailable && revision.Artifacts.NsJail != nil
			case BackendDocker:
				artifactsAvailable = artifactsAvailable && revision.Artifacts.Docker != nil
			case BackendFirecracker:
				artifactsAvailable = artifactsAvailable && revision.Artifacts.Firecracker != nil
			}
		}
		if !artifactsAvailable {
			continue
		}
		packages := make(map[string]semanticVersion, len(revision.Packages))
		for _, item := range revision.Packages {
			version, _ := parseVersion(item.Version)
			packages[item.ID] = version
		}
		matches := true
		for _, requirement := range parsed {
			version, found := packages[requirement.packageID]
			if !found || !requirement.matches(version) {
				matches = false
				break
			}
		}
		if matches {
			candidates = append(candidates, revision)
		}
	}
	if len(candidates) == 0 {
		return Revision{}, ErrNoEnvironment
	}
	sort.Slice(candidates, func(left, right int) bool {
		if len(candidates[left].Packages) != len(candidates[right].Packages) {
			return len(candidates[left].Packages) < len(candidates[right].Packages)
		}
		return candidates[left].Digest < candidates[right].Digest
	})
	return cloneRevision(candidates[0]), nil
}

func DigestRevision(revision Revision) (string, error) {
	if err := validateRevisionContent(revision); err != nil {
		return "", err
	}
	packages := append([]Package(nil), revision.Packages...)
	sort.Slice(packages, func(left, right int) bool { return packages[left].ID < packages[right].ID })
	packageValues := make(canonical.Array, len(packages))
	for index, item := range packages {
		packageValues[index] = canonical.Map{"digest": item.Digest, "id": item.ID, "version": item.Version}
	}
	artifacts := canonical.Map{}
	if revision.Artifacts.NsJail != nil {
		artifacts[string(BackendNsJail)] = canonical.Map{"rootfsDigest": revision.Artifacts.NsJail.RootfsDigest}
	}
	if revision.Artifacts.Docker != nil {
		artifacts[string(BackendDocker)] = canonical.Map{"imageDigest": revision.Artifacts.Docker.ImageDigest}
	}
	if revision.Artifacts.Firecracker != nil {
		artifacts[string(BackendFirecracker)] = canonical.Map{
			"kernelDigest": revision.Artifacts.Firecracker.KernelDigest,
			"rootfsDigest": revision.Artifacts.Firecracker.RootfsDigest,
		}
	}
	return canonical.StructuredDigest("circulusd.execution-environment-revision", 1, canonical.Map{
		"architecture":           string(revision.Architecture),
		"artifacts":              artifacts,
		"filesystemPolicyDigest": revision.FilesystemPolicyDigest,
		"packages":               packageValues,
		"sandboxdDigest":         revision.SandboxdDigest,
		"seccompProfileDigest":   revision.SeccompProfileDigest,
	})
}

func validateRevisionContent(revision Revision) error {
	if revision.ID.Kind() != identity.EnvironmentRevision {
		return fmt.Errorf("revision ID has kind %q", revision.ID.Kind())
	}
	if revision.Architecture != ArchitectureX8664 && revision.Architecture != ArchitectureAArch64 {
		return fmt.Errorf("unsupported architecture %q", revision.Architecture)
	}
	if !digestPattern.MatchString(revision.SandboxdDigest) || !digestPattern.MatchString(revision.SeccompProfileDigest) || !digestPattern.MatchString(revision.FilesystemPolicyDigest) {
		return fmt.Errorf("environment policy digest is not canonical SHA-256")
	}
	seenPackages := make(map[string]struct{}, len(revision.Packages))
	for _, item := range revision.Packages {
		if !packageIDPattern.MatchString(item.ID) || !digestPattern.MatchString(item.Digest) {
			return fmt.Errorf("package %q is not canonical", item.ID)
		}
		if _, err := parseVersion(item.Version); err != nil {
			return fmt.Errorf("package %q version: %w", item.ID, err)
		}
		if _, duplicate := seenPackages[item.ID]; duplicate {
			return fmt.Errorf("duplicate package %q", item.ID)
		}
		seenPackages[item.ID] = struct{}{}
	}
	artifactCount := 0
	if revision.Artifacts.NsJail != nil {
		artifactCount++
		if !digestPattern.MatchString(revision.Artifacts.NsJail.RootfsDigest) {
			return fmt.Errorf("NsJail rootfs digest is not canonical SHA-256")
		}
	}
	if revision.Artifacts.Docker != nil {
		artifactCount++
		if !digestPattern.MatchString(revision.Artifacts.Docker.ImageDigest) {
			return fmt.Errorf("Docker image digest is not canonical SHA-256")
		}
	}
	if revision.Artifacts.Firecracker != nil {
		artifactCount++
		if !digestPattern.MatchString(revision.Artifacts.Firecracker.KernelDigest) || !digestPattern.MatchString(revision.Artifacts.Firecracker.RootfsDigest) {
			return fmt.Errorf("Firecracker artifact digest is not canonical SHA-256")
		}
	}
	if artifactCount == 0 {
		return fmt.Errorf("at least one backend artifact is required")
	}
	return nil
}

func parseVersion(value string) (semanticVersion, error) {
	match := versionPattern.FindStringSubmatch(value)
	if match == nil {
		return semanticVersion{}, fmt.Errorf("version %q is not canonical major.minor.patch", value)
	}
	major, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil {
		return semanticVersion{}, err
	}
	minor, err := strconv.ParseUint(match[2], 10, 64)
	if err != nil {
		return semanticVersion{}, err
	}
	patch, err := strconv.ParseUint(match[3], 10, 64)
	if err != nil {
		return semanticVersion{}, err
	}
	return semanticVersion{major: major, minor: minor, patch: patch}, nil
}

func (version semanticVersion) compare(other semanticVersion) int {
	if version.major != other.major {
		if version.major < other.major {
			return -1
		}
		return 1
	}
	if version.minor != other.minor {
		if version.minor < other.minor {
			return -1
		}
		return 1
	}
	if version.patch < other.patch {
		return -1
	}
	if version.patch > other.patch {
		return 1
	}
	return 0
}

func cloneRevision(revision Revision) Revision {
	copy := revision
	copy.Packages = append([]Package(nil), revision.Packages...)
	if revision.Artifacts.NsJail != nil {
		artifact := *revision.Artifacts.NsJail
		copy.Artifacts.NsJail = &artifact
	}
	if revision.Artifacts.Docker != nil {
		artifact := *revision.Artifacts.Docker
		copy.Artifacts.Docker = &artifact
	}
	if revision.Artifacts.Firecracker != nil {
		artifact := *revision.Artifacts.Firecracker
		copy.Artifacts.Firecracker = &artifact
	}
	return copy
}
