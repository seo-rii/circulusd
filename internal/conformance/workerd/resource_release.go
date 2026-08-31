package workerd

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hancomac/circulusd/internal/release"
	"golang.org/x/sys/unix"
)

const maximumResourceQualificationExecutableBytes = 256 << 20

var (
	errResourceQualificationReleaseUnavailable = errors.New("workerd resource qualification: release input unavailable")
	errResourceQualificationReleaseInvalid     = errors.New("workerd resource qualification: invalid release identity")
	errResourceQualificationReleaseClosed      = errors.New("workerd resource qualification: release snapshot closed")
)

// resourceQualificationReleaseIdentity is a value snapshot derived only from
// a validated release manifest and the opened installed executable. All fields
// are private so callers can consume an identity copy but cannot rewrite the
// resolver-owned identity in place.
type resourceQualificationReleaseIdentity struct {
	releaseVersion               string
	releaseStatus                string
	manifestSigningDigest        string
	architecture                 string
	workerdVersion               string
	workerdCommit                string
	artifactName                 string
	archiveSHA256                string
	extractionRecipe             string
	extractedExecutableSHA256    string
	archiveSizeBytes             uint64
	archiveSizeKnown             bool
	installedExecutableSizeBytes uint64
	promotionVerified            bool
	productionQualified          bool
}

// resourceQualificationRelease owns a sealed executable snapshot. The source
// pathname is deliberately not retained as execution authority: replacing it
// after resolution cannot change the bytes represented by this object.
type resourceQualificationRelease struct {
	identity resourceQualificationReleaseIdentity

	mu         sync.Mutex
	executable *os.File
}

func resolveResourceQualificationRelease(config resourceQualificationConfig) (*resourceQualificationRelease, error) {
	return resolveResourceQualificationReleaseWithOpenat2(config, unix.Openat2)
}

func resolveResourceQualificationReleaseWithOpenat2(
	config resourceQualificationConfig,
	openat2 func(int, string, *unix.OpenHow) (int, error),
) (*resourceQualificationRelease, error) {
	if openat2 == nil {
		return nil, fmt.Errorf("%w: openat2 implementation is nil", errResourceQualificationReleaseInvalid)
	}
	for _, input := range []struct {
		name string
		path string
	}{
		{name: "release manifest", path: config.ReleaseManifestPath},
		{name: "release trust roots", path: config.ReleaseTrustRootsPath},
		{name: "installed workerd", path: config.InstalledWorkerdPath},
	} {
		if input.path == string(filepath.Separator) || !filepath.IsAbs(input.path) ||
			filepath.Clean(input.path) != input.path || strings.ContainsRune(input.path, 0) {
			return nil, fmt.Errorf(
				"%w: %s path is not canonical and absolute",
				errResourceQualificationReleaseInvalid,
				input.name,
			)
		}
	}
	if config.Architecture != "x86_64" && config.Architecture != "aarch64" {
		return nil, fmt.Errorf(
			"%w: unsupported architecture %q",
			errResourceQualificationReleaseInvalid,
			config.Architecture,
		)
	}

	manifest, err := release.Load(config.ReleaseManifestPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOTDIR) {
			return nil, fmt.Errorf(
				"%w: load release manifest: %v",
				errResourceQualificationReleaseUnavailable,
				err,
			)
		}
		return nil, fmt.Errorf(
			"%w: load release manifest: %v",
			errResourceQualificationReleaseInvalid,
			err,
		)
	}
	if err := manifest.Validate(); err != nil {
		return nil, fmt.Errorf("%w: validate release manifest: %v", errResourceQualificationReleaseInvalid, err)
	}
	trustStore, err := release.LoadTrustStore(config.ReleaseTrustRootsPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOTDIR) {
			return nil, fmt.Errorf(
				"%w: load release trust roots: %v",
				errResourceQualificationReleaseUnavailable,
				err,
			)
		}
		return nil, fmt.Errorf(
			"%w: load release trust roots: %v",
			errResourceQualificationReleaseInvalid,
			err,
		)
	}

	promotionVerified := false
	switch manifest.Release.Status {
	case "development":
		// Development manifests can bind Phase 0 metadata, but they are not
		// promotable and must never inherit production qualification. The
		// configured offline roots were still parsed and policy-validated.
	case "candidate", "production":
		if verifyErr := trustStore.VerifyPromotion(manifest); verifyErr != nil {
			return nil, fmt.Errorf("%w: verify release promotion: %v", errResourceQualificationReleaseInvalid, verifyErr)
		}
		promotionVerified = true
	default:
		return nil, fmt.Errorf("%w: unsupported release status %q", errResourceQualificationReleaseInvalid, manifest.Release.Status)
	}

	releasedArchitecture := false
	for _, candidate := range manifest.Release.Architectures {
		if candidate == config.Architecture {
			releasedArchitecture = true
			break
		}
	}
	if !releasedArchitecture {
		return nil, fmt.Errorf(
			"%w: release has no %q architecture",
			errResourceQualificationReleaseUnavailable,
			config.Architecture,
		)
	}

	var component *release.Component
	for index := range manifest.Components {
		if manifest.Components[index].Name == "workerd" {
			componentCopy := manifest.Components[index]
			component = &componentCopy
			break
		}
	}
	if component == nil {
		return nil, fmt.Errorf(
			"%w: release has no workerd component",
			errResourceQualificationReleaseUnavailable,
		)
	}
	var artifact *release.Artifact
	for index := range component.Artifacts {
		candidate := component.Artifacts[index]
		if candidate.Architecture != config.Architecture {
			continue
		}
		if artifact != nil {
			return nil, fmt.Errorf(
				"%w: release has multiple workerd artifacts for %q",
				errResourceQualificationReleaseInvalid,
				config.Architecture,
			)
		}
		artifact = &candidate
	}
	if artifact == nil {
		return nil, fmt.Errorf(
			"%w: release has no exact workerd artifact for %q",
			errResourceQualificationReleaseUnavailable,
			config.Architecture,
		)
	}
	manifestDigest, err := release.ManifestSigningDigest(manifest)
	if err != nil {
		return nil, fmt.Errorf("%w: derive release manifest identity: %v", errResourceQualificationReleaseInvalid, err)
	}
	expectedExecutableDigest, err := hex.DecodeString(artifact.ExtractedExecutableSHA256)
	if err != nil || len(expectedExecutableDigest) != sha256.Size {
		return nil, fmt.Errorf("%w: decode extracted executable digest", errResourceQualificationReleaseInvalid)
	}

	rootFD, err := unix.Open(
		string(filepath.Separator),
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: open filesystem root: %v", errResourceQualificationReleaseInvalid, err)
	}
	currentFD := rootFD
	components := strings.Split(
		strings.TrimPrefix(config.InstalledWorkerdPath, string(filepath.Separator)),
		string(filepath.Separator),
	)
	for index, pathComponent := range components {
		flags := uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW)
		if index == len(components)-1 {
			flags = uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK)
		}
		nextFD, openErr := openat2(currentFD, pathComponent, &unix.OpenHow{
			Flags:   flags,
			Resolve: uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS),
		})
		symlinkComponent := false
		if errors.Is(openErr, unix.ENOTDIR) {
			var pathStat unix.Stat_t
			if statErr := unix.Fstatat(currentFD, pathComponent, &pathStat, unix.AT_SYMLINK_NOFOLLOW); statErr == nil {
				symlinkComponent = pathStat.Mode&unix.S_IFMT == unix.S_IFLNK
			}
		}
		_ = unix.Close(currentFD)
		if openErr != nil {
			if !symlinkComponent && (errors.Is(openErr, fs.ErrNotExist) || errors.Is(openErr, unix.ENOTDIR) ||
				errors.Is(openErr, unix.ENOSYS) || errors.Is(openErr, unix.EOPNOTSUPP)) {
				return nil, fmt.Errorf(
					"%w: open installed workerd path: %v",
					errResourceQualificationReleaseUnavailable,
					openErr,
				)
			}
			return nil, fmt.Errorf(
				"%w: safely open installed workerd path: %v",
				errResourceQualificationReleaseInvalid,
				openErr,
			)
		}
		currentFD = nextFD
	}
	sourceExecutable := os.NewFile(uintptr(currentFD), config.InstalledWorkerdPath)
	if sourceExecutable == nil {
		_ = unix.Close(currentFD)
		return nil, fmt.Errorf("%w: wrap opened workerd executable", errResourceQualificationReleaseInvalid)
	}
	defer sourceExecutable.Close()

	var stat unix.Stat_t
	if err := unix.Fstat(int(sourceExecutable.Fd()), &stat); err != nil {
		return nil, fmt.Errorf("%w: stat opened workerd executable: %v", errResourceQualificationReleaseInvalid, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o111 == 0 || stat.Mode&0o022 != 0 ||
		stat.Mode&(unix.S_ISUID|unix.S_ISGID) != 0 {
		return nil, fmt.Errorf("%w: unsafe workerd executable mode %#o", errResourceQualificationReleaseInvalid, stat.Mode)
	}
	if stat.Size <= 0 || stat.Size > maximumResourceQualificationExecutableBytes {
		return nil, fmt.Errorf(
			"%w: workerd executable size %d exceeds 1..%d bytes",
			errResourceQualificationReleaseInvalid,
			stat.Size,
			maximumResourceQualificationExecutableBytes,
		)
	}

	sealedFD, err := unix.MemfdCreate(
		"circulusd-qualified-workerd",
		unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC,
	)
	if errors.Is(err, unix.EINVAL) {
		sealedFD, err = unix.MemfdCreate(
			"circulusd-qualified-workerd",
			unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: create executable snapshot: %v", errResourceQualificationReleaseUnavailable, err)
	}
	sealedExecutable := os.NewFile(uintptr(sealedFD), "qualified-workerd")
	if sealedExecutable == nil {
		_ = unix.Close(sealedFD)
		return nil, fmt.Errorf("%w: wrap executable snapshot", errResourceQualificationReleaseInvalid)
	}
	keepSealedExecutable := false
	defer func() {
		if !keepSealedExecutable {
			_ = sealedExecutable.Close()
		}
	}()

	hash := sha256.New()
	written, copyErr := io.CopyN(io.MultiWriter(sealedExecutable, hash), sourceExecutable, stat.Size)
	if copyErr != nil || written != stat.Size {
		return nil, fmt.Errorf(
			"%w: copy executable snapshot: copied %d of %d bytes: %v",
			errResourceQualificationReleaseInvalid,
			written,
			stat.Size,
			copyErr,
		)
	}
	var trailing [1]byte
	if count, readErr := sourceExecutable.Read(trailing[:]); count != 0 || !errors.Is(readErr, io.EOF) {
		return nil, fmt.Errorf("%w: executable size changed while snapshotting", errResourceQualificationReleaseInvalid)
	}
	if subtle.ConstantTimeCompare(hash.Sum(nil), expectedExecutableDigest) != 1 {
		return nil, fmt.Errorf("%w: installed workerd digest does not match release provenance", errResourceQualificationReleaseInvalid)
	}
	if err := unix.Fchmod(sealedFD, 0o500); err != nil {
		return nil, fmt.Errorf("%w: set executable snapshot mode: %v", errResourceQualificationReleaseInvalid, err)
	}
	wantedSeals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(sealedExecutable.Fd(), unix.F_ADD_SEALS, wantedSeals); err != nil {
		return nil, fmt.Errorf("%w: seal executable snapshot: %v", errResourceQualificationReleaseInvalid, err)
	}
	seals, err := unix.FcntlInt(sealedExecutable.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&wantedSeals != wantedSeals {
		return nil, fmt.Errorf("%w: verify executable snapshot seals %#x: %v", errResourceQualificationReleaseInvalid, seals, err)
	}
	if _, err := sealedExecutable.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("%w: rewind executable snapshot: %v", errResourceQualificationReleaseInvalid, err)
	}
	keepSealedExecutable = true

	identity := resourceQualificationReleaseIdentity{
		releaseVersion:               manifest.Release.Version,
		releaseStatus:                manifest.Release.Status,
		manifestSigningDigest:        manifestDigest,
		architecture:                 artifact.Architecture,
		workerdVersion:               component.Version,
		workerdCommit:                component.Commit,
		artifactName:                 artifact.Name,
		archiveSHA256:                artifact.SHA256,
		extractionRecipe:             artifact.ExtractionRecipe,
		extractedExecutableSHA256:    artifact.ExtractedExecutableSHA256,
		installedExecutableSizeBytes: uint64(stat.Size),
		promotionVerified:            promotionVerified,
		productionQualified:          promotionVerified && manifest.Release.Status == "production",
	}
	if artifact.SizeBytes != nil {
		identity.archiveSizeBytes = *artifact.SizeBytes
		identity.archiveSizeKnown = true
	}

	return &resourceQualificationRelease{
		identity:   identity,
		executable: sealedExecutable,
	}, nil
}

func (resolved *resourceQualificationRelease) identitySnapshot() resourceQualificationReleaseIdentity {
	if resolved == nil {
		return resourceQualificationReleaseIdentity{}
	}
	return resolved.identity
}

func (resolved *resourceQualificationRelease) openExecutableSnapshot() (*os.File, error) {
	return resolved.openExecutableSnapshotWithOpen(unix.Open)
}

func (resolved *resourceQualificationRelease) openExecutableSnapshotWithOpen(
	open func(string, int, uint32) (int, error),
) (*os.File, error) {
	if resolved == nil {
		return nil, errResourceQualificationReleaseClosed
	}
	if open == nil {
		return nil, fmt.Errorf("%w: snapshot opener is nil", errResourceQualificationReleaseInvalid)
	}
	resolved.mu.Lock()
	defer resolved.mu.Unlock()
	if resolved.executable == nil {
		return nil, errResourceQualificationReleaseClosed
	}
	ownerFD := resolved.executable.Fd()
	if ownerFD == ^uintptr(0) {
		return nil, errResourceQualificationReleaseClosed
	}
	path := fmt.Sprintf("/proc/self/fd/%d", ownerFD)
	fd, err := open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) ||
			errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
			return nil, fmt.Errorf("%w: duplicate executable snapshot: %v", errResourceQualificationReleaseUnavailable, err)
		}
		return nil, fmt.Errorf("%w: duplicate executable snapshot: %v", errResourceQualificationReleaseInvalid, err)
	}
	duplicate := os.NewFile(uintptr(fd), "qualified-workerd-snapshot")
	if duplicate == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: wrap duplicated executable snapshot", errResourceQualificationReleaseInvalid)
	}
	return duplicate, nil
}

func (resolved *resourceQualificationRelease) close() error {
	if resolved == nil {
		return nil
	}
	resolved.mu.Lock()
	executable := resolved.executable
	resolved.executable = nil
	resolved.mu.Unlock()
	if executable == nil {
		return nil
	}
	return executable.Close()
}
