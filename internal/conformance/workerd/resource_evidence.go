package workerd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/conformance"
	"golang.org/x/sys/unix"
)

func hexSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

const (
	resourceEvidenceSchemaVersion = uint64(1)
	maximumResourceEvidenceBytes  = 1 << 20
)

var (
	errResourceEvidenceInvalid = errors.New("workerd resource qualification: invalid evidence envelope")
	errResourceEvidenceExists  = errors.New("workerd resource qualification: evidence artifact already exists")
	errResourceEvidenceRetain  = errors.New("workerd resource qualification: evidence retention failed")

	resourceEvidenceHexIdentity = regexp.MustCompile(`^[0-9a-f]{32}$`)
	resourceEvidenceController  = regexp.MustCompile(`^[a-z]{1,32}$`)
)

// resourceProbeObservation is one probe's bounded record inside the envelope.
type resourceProbeObservation struct {
	Component      string
	Status         conformance.Status
	Reason         string
	StartedAt      time.Time
	FinishedAt     time.Time
	RawSampleCount uint64
}

// resourceEvidenceEnvelope is the versioned qualification evidence document.
// It is historical evidence of one run, never startup authority; a later
// consumer must independently reauthenticate host, boot, release, and target.
type resourceEvidenceEnvelope struct {
	RunID              string
	StartedAt          time.Time
	FinishedAt         time.Time
	RunnerBinary       string
	SourceDigest       string
	FixtureDigest      string
	ProbeInventory     string
	ReleaseManifest    string
	ReleaseStatus      string
	Architecture       string
	ArchiveDigest      string
	ExtractionRecipe   string
	ExecutableDigest   string
	WorkerdVersion     string
	ConfigDigest       string
	EnvironmentDigest  string
	Kernel             string
	HostBootID         string
	AgentInstanceID    string
	CgroupRootDevice   uint64
	CgroupRootInode    uint64
	EnabledControllers []string
	Limits             resourceQualificationLimits
	ColdStartSamples   uint64
	Probes             []resourceProbeObservation
	CleanupComplete    bool
}

func validResourceEvidenceDigest(value string) bool {
	return len(value) == 71 && strings.HasPrefix(value, "sha256:") &&
		strings.ToLower(value) == value && sha256HexPattern.MatchString(value[7:])
}

var sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validateResourceEvidenceEnvelope(envelope resourceEvidenceEnvelope) error {
	if !resourceEvidenceHexIdentity.MatchString(envelope.RunID) ||
		!resourceEvidenceHexIdentity.MatchString(envelope.HostBootID) ||
		!resourceEvidenceHexIdentity.MatchString(envelope.AgentInstanceID) {
		return fmt.Errorf("%w: run, boot, or agent identity is not a 128-bit hex value", errResourceEvidenceInvalid)
	}
	if envelope.StartedAt.IsZero() || envelope.FinishedAt.IsZero() || envelope.FinishedAt.Before(envelope.StartedAt) {
		return fmt.Errorf("%w: run timestamps are missing or non-monotonic", errResourceEvidenceInvalid)
	}
	for _, digest := range []string{
		envelope.RunnerBinary, envelope.SourceDigest, envelope.FixtureDigest, envelope.ProbeInventory,
		envelope.ReleaseManifest, envelope.ArchiveDigest, envelope.ExecutableDigest,
		envelope.ConfigDigest, envelope.EnvironmentDigest,
	} {
		if !validResourceEvidenceDigest(digest) {
			return fmt.Errorf("%w: evidence digest %q is not canonical", errResourceEvidenceInvalid, digest)
		}
	}
	if envelope.Architecture != "x86_64" && envelope.Architecture != "aarch64" {
		return fmt.Errorf("%w: architecture %q is not supported", errResourceEvidenceInvalid, envelope.Architecture)
	}
	switch envelope.ReleaseStatus {
	case "development", "candidate", "production":
	default:
		return fmt.Errorf("%w: release status %q is not supported", errResourceEvidenceInvalid, envelope.ReleaseStatus)
	}
	if envelope.ExtractionRecipe == "" || envelope.WorkerdVersion == "" || envelope.Kernel == "" {
		return fmt.Errorf("%w: release provenance metadata is incomplete", errResourceEvidenceInvalid)
	}
	if len(envelope.EnabledControllers) == 0 {
		return fmt.Errorf("%w: no enabled controllers recorded", errResourceEvidenceInvalid)
	}
	seenControllers := make(map[string]struct{}, len(envelope.EnabledControllers))
	for _, controller := range envelope.EnabledControllers {
		if !resourceEvidenceController.MatchString(controller) {
			return fmt.Errorf("%w: controller %q is malformed", errResourceEvidenceInvalid, controller)
		}
		if _, duplicate := seenControllers[controller]; duplicate {
			return fmt.Errorf("%w: controller %q is duplicated", errResourceEvidenceInvalid, controller)
		}
		seenControllers[controller] = struct{}{}
	}
	if envelope.ColdStartSamples < 5 || envelope.ColdStartSamples > maximumResourceQualificationSamples {
		return fmt.Errorf("%w: cold-start sample count is outside its bound", errResourceEvidenceInvalid)
	}
	if len(envelope.Probes) == 0 {
		return fmt.Errorf("%w: no probe observations recorded", errResourceEvidenceInvalid)
	}
	seenComponents := make(map[string]struct{}, len(envelope.Probes))
	for _, probe := range envelope.Probes {
		if !componentPatternMatches(probe.Component) {
			return fmt.Errorf("%w: probe component %q is malformed", errResourceEvidenceInvalid, probe.Component)
		}
		if _, duplicate := seenComponents[probe.Component]; duplicate {
			return fmt.Errorf("%w: probe component %q is duplicated", errResourceEvidenceInvalid, probe.Component)
		}
		seenComponents[probe.Component] = struct{}{}
		switch probe.Status {
		case conformance.Pass, conformance.Fail, conformance.Unavailable, conformance.NotRun:
		default:
			return fmt.Errorf("%w: probe %q has an unknown status", errResourceEvidenceInvalid, probe.Component)
		}
		if probe.StartedAt.IsZero() || probe.FinishedAt.IsZero() || probe.FinishedAt.Before(probe.StartedAt) {
			return fmt.Errorf("%w: probe %q timestamps are missing or non-monotonic", errResourceEvidenceInvalid, probe.Component)
		}
	}
	return nil
}

var componentPatternRegexp = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)

func componentPatternMatches(component string) bool {
	return componentPatternRegexp.MatchString(component)
}

// encodeResourceEvidenceEnvelope validates the envelope, encodes it as
// deterministic canonical CBOR, and returns the bytes and their content
// digest. The same envelope always encodes to the same bytes and digest.
func encodeResourceEvidenceEnvelope(envelope resourceEvidenceEnvelope) ([]byte, string, error) {
	if err := validateResourceEvidenceEnvelope(envelope); err != nil {
		return nil, "", err
	}
	controllers := append([]string(nil), envelope.EnabledControllers...)
	sort.Strings(controllers)
	controllerValues := make(canonical.Array, len(controllers))
	for index, controller := range controllers {
		controllerValues[index] = controller
	}

	probes := append([]resourceProbeObservation(nil), envelope.Probes...)
	sort.Slice(probes, func(left, right int) bool { return probes[left].Component < probes[right].Component })
	probeValues := make(canonical.Array, len(probes))
	for index, probe := range probes {
		probeValues[index] = canonical.Map{
			"component":      probe.Component,
			"status":         string(probe.Status),
			"reason":         probe.Reason,
			"startedAtUnix":  int64(probe.StartedAt.UTC().Unix()),
			"finishedAtUnix": int64(probe.FinishedAt.UTC().Unix()),
			"rawSampleCount": int64(probe.RawSampleCount),
		}
	}

	payload := canonical.Map{
		"runId":              envelope.RunID,
		"startedAtUnix":      int64(envelope.StartedAt.UTC().Unix()),
		"finishedAtUnix":     int64(envelope.FinishedAt.UTC().Unix()),
		"runnerBinary":       envelope.RunnerBinary,
		"sourceDigest":       envelope.SourceDigest,
		"fixtureDigest":      envelope.FixtureDigest,
		"probeInventory":     envelope.ProbeInventory,
		"releaseManifest":    envelope.ReleaseManifest,
		"releaseStatus":      envelope.ReleaseStatus,
		"architecture":       envelope.Architecture,
		"archiveDigest":      envelope.ArchiveDigest,
		"extractionRecipe":   envelope.ExtractionRecipe,
		"executableDigest":   envelope.ExecutableDigest,
		"workerdVersion":     envelope.WorkerdVersion,
		"configDigest":       envelope.ConfigDigest,
		"environmentDigest":  envelope.EnvironmentDigest,
		"kernel":             envelope.Kernel,
		"hostBootId":         envelope.HostBootID,
		"agentInstanceId":    envelope.AgentInstanceID,
		"cgroupRootDevice":   int64(envelope.CgroupRootDevice),
		"cgroupRootInode":    int64(envelope.CgroupRootInode),
		"enabledControllers": controllerValues,
		"limits": canonical.Map{
			"cpuMaxQuotaMicros":  int64(envelope.Limits.CPUMaxQuotaMicros),
			"cpuMaxPeriodMicros": int64(envelope.Limits.CPUMaxPeriodMicros),
			"memoryMaxBytes":     int64(envelope.Limits.MemoryMaxBytes),
			"memorySwapMaxBytes": int64(envelope.Limits.MemorySwapMaxBytes),
			"pidsMax":            int64(envelope.Limits.PIDsMax),
		},
		"coldStartSamples": int64(envelope.ColdStartSamples),
		"probes":           probeValues,
		"cleanupComplete":  envelope.CleanupComplete,
	}
	document := canonical.Map{"schemaVersion": int64(resourceEvidenceSchemaVersion)}
	for key, value := range payload {
		document[key] = value
	}
	encoded, err := canonical.Encode(document, canonical.DefaultOptions())
	if err != nil {
		return nil, "", fmt.Errorf("%w: canonical encode: %v", errResourceEvidenceInvalid, err)
	}
	if len(encoded) > maximumResourceEvidenceBytes {
		return nil, "", fmt.Errorf("%w: encoded envelope exceeds %d bytes", errResourceEvidenceInvalid, maximumResourceEvidenceBytes)
	}
	// The returned digest is the artifact content digest: exactly what a
	// verifier recomputes over the retained file and what a component PASS
	// result references. Deterministic canonical encoding makes it stable.
	return encoded, "sha256:" + hexSHA256(encoded), nil
}

// retainResourceEvidence atomically publishes one evidence artifact into a
// private output directory: a same-directory exclusive 0600 temporary file,
// fsync, no-clobber renameat2, directory fsync, and read-back digest
// verification. It never replaces, relabels, or appends to an existing
// artifact and leaves no staging file on failure.
func retainResourceEvidence(directory string, name string, encoded []byte) (returnDigest string, returnErr error) {
	if directory == string(filepath.Separator) || !filepath.IsAbs(directory) ||
		filepath.Clean(directory) != directory || strings.ContainsRune(directory, 0) {
		return "", fmt.Errorf("%w: output directory is not canonical and absolute", errResourceEvidenceInvalid)
	}
	if name == "" || strings.ContainsAny(name, "/\x00") || len(encoded) == 0 || len(encoded) > maximumResourceEvidenceBytes {
		return "", fmt.Errorf("%w: evidence artifact name or payload is invalid", errResourceEvidenceInvalid)
	}
	expectedDigest := "sha256:" + hexSHA256(encoded)

	directoryFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", fmt.Errorf("%w: open output directory: %v", errResourceEvidenceRetain, err)
	}
	defer unix.Close(directoryFD)
	var directoryStat unix.Stat_t
	if err := unix.Fstat(directoryFD, &directoryStat); err != nil {
		return "", fmt.Errorf("%w: stat output directory: %v", errResourceEvidenceRetain, err)
	}
	if directoryStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return "", fmt.Errorf("%w: output path is not a directory", errResourceEvidenceInvalid)
	}
	if directoryStat.Uid != uint32(os.Getuid()) || directoryStat.Mode&0o077 != 0 {
		return "", fmt.Errorf("%w: output directory is not caller-owned and private", errResourceEvidenceInvalid)
	}

	writeFD, err := unix.Openat(directoryFD, ".", unix.O_WRONLY|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600)
	tmpfile := writeFD >= 0 && err == nil
	var stageName string
	if !tmpfile {
		stageName = "." + name + ".staging"
		writeFD, err = unix.Openat(directoryFD, stageName,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err != nil {
			return "", fmt.Errorf("%w: create staging file: %v", errResourceEvidenceRetain, err)
		}
	}
	cleanupStage := func() {
		if stageName != "" {
			_ = unix.Unlinkat(directoryFD, stageName, 0)
		}
	}
	published := false
	defer func() {
		if !published {
			cleanupStage()
		}
	}()

	if _, err := writeAllAt(writeFD, encoded); err != nil {
		_ = unix.Close(writeFD)
		return "", fmt.Errorf("%w: write evidence bytes: %v", errResourceEvidenceRetain, err)
	}
	if err := unix.Fsync(writeFD); err != nil {
		_ = unix.Close(writeFD)
		return "", fmt.Errorf("%w: fsync evidence bytes: %v", errResourceEvidenceRetain, err)
	}

	if tmpfile {
		procPath := fmt.Sprintf("/proc/self/fd/%d", writeFD)
		if err := unix.Linkat(unix.AT_FDCWD, procPath, directoryFD, name, unix.AT_SYMLINK_FOLLOW); err != nil {
			_ = unix.Close(writeFD)
			if errors.Is(err, unix.EEXIST) {
				return "", fmt.Errorf("%w", errResourceEvidenceExists)
			}
			return "", fmt.Errorf("%w: link evidence into place: %v", errResourceEvidenceRetain, err)
		}
		_ = unix.Close(writeFD)
	} else {
		_ = unix.Close(writeFD)
		if err := unix.Renameat2(directoryFD, stageName, directoryFD, name, unix.RENAME_NOREPLACE); err != nil {
			if errors.Is(err, unix.EEXIST) || errors.Is(err, unix.ENOTEMPTY) {
				return "", fmt.Errorf("%w", errResourceEvidenceExists)
			}
			return "", fmt.Errorf("%w: publish evidence: %v", errResourceEvidenceRetain, err)
		}
		stageName = ""
	}
	published = true
	if err := unix.Fsync(directoryFD); err != nil {
		return "", fmt.Errorf("%w: fsync output directory: %v", errResourceEvidenceRetain, err)
	}

	readBack, err := readBoundedFileAt(directoryFD, name, maximumResourceEvidenceBytes)
	if err != nil {
		return "", fmt.Errorf("%w: read back evidence: %v", errResourceEvidenceRetain, err)
	}
	if "sha256:"+hexSHA256(readBack) != expectedDigest {
		return "", fmt.Errorf("%w: read-back digest does not match written evidence", errResourceEvidenceRetain)
	}
	return expectedDigest, nil
}

func writeAllAt(fd int, data []byte) (int, error) {
	written := 0
	for written < len(data) {
		count, err := unix.Write(fd, data[written:])
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return written, err
		}
		if count <= 0 {
			return written, fmt.Errorf("short write")
		}
		written += count
	}
	return written, nil
}

func readBoundedFileAt(directoryFD int, name string, maximumBytes int) ([]byte, error) {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	buffer := make([]byte, maximumBytes+1)
	offset := 0
	for offset < len(buffer) {
		count, readErr := unix.Read(fd, buffer[offset:])
		if readErr != nil {
			if errors.Is(readErr, unix.EINTR) {
				continue
			}
			return nil, readErr
		}
		if count == 0 {
			break
		}
		offset += count
	}
	if offset > maximumBytes {
		return nil, fmt.Errorf("evidence artifact exceeds %d bytes", maximumBytes)
	}
	return buffer[:offset], nil
}
