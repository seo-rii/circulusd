//go:build linux

package dependency

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const maximumProductionProofPathBytes = 4096

type productionProofFilePolicy struct {
	label           string
	maximumBytes    int64
	invalidFile     error
	invalidDocument error
	tooLarge        error
}

type productionProofFileCandidate struct {
	path   string
	policy productionProofFilePolicy
}

var (
	productionEvidenceFilePolicy = productionProofFilePolicy{
		label:           "evidence",
		maximumBytes:    maximumEvidenceDocumentBytes,
		invalidFile:     ErrInvalidEvidenceFile,
		invalidDocument: ErrInvalidEvidenceDocument,
		tooLarge:        ErrEvidenceDocumentTooLarge,
	}
	productionTrustRootsFilePolicy = productionProofFilePolicy{
		label:           "trust roots",
		maximumBytes:    maximumTrustRootsDocumentBytes,
		invalidFile:     ErrInvalidTrustRootsFile,
		invalidDocument: ErrInvalidTrustRootsDocument,
		tooLarge:        ErrTrustRootsDocumentTooLarge,
	}
)

type pinnedProductionProofFile struct {
	file   *os.File
	status unix.Stat_t
	policy productionProofFilePolicy
}

func newVerifierFromFiles(config ProductionProofFileConfig) (*Verifier, Evidence, error) {
	return newVerifierFromFilesForOwner(config, productionProofOwnerUID())
}

func productionProofOwnerUID() uint32 {
	return 0
}

func newVerifierFromFilesForOwner(
	config ProductionProofFileConfig,
	expectedOwnerUID uint32,
) (verifier *Verifier, evidence Evidence, err error) {
	if err := validateProductionProofFileConfig(config); err != nil {
		return nil, Evidence{}, err
	}
	candidates := []productionProofFileCandidate{
		{path: config.EvidenceFile, policy: productionEvidenceFilePolicy},
		{path: config.ConformanceRootsFile, policy: productionTrustRootsFilePolicy},
		{path: config.RuntimeRootsFile, policy: productionTrustRootsFilePolicy},
	}
	files, err := openPinnedProductionProofFiles(candidates, expectedOwnerUID)
	if err != nil {
		return nil, Evidence{}, err
	}
	defer func() {
		if closeErr := closePinnedProductionProofFiles(files); closeErr != nil {
			if err == nil {
				verifier = nil
				evidence = Evidence{}
				err = closeErr
			} else {
				err = errors.Join(err, closeErr)
			}
		}
	}()
	documents := make([][]byte, len(files))
	for index, pinned := range files {
		documents[index], err = readPinnedProductionProofFile(pinned)
		if err != nil {
			return nil, Evidence{}, err
		}
	}
	if err := validatePinnedProductionProofFiles(files); err != nil {
		return nil, Evidence{}, err
	}

	loadedEvidence, decodeErr := DecodeEvidence(bytes.NewReader(documents[0]))
	if decodeErr != nil {
		return nil, Evidence{}, errors.Join(ErrInvalidEvidenceFile, decodeErr)
	}
	conformanceRoots, decodeErr := DecodeTrustRoots(
		bytes.NewReader(documents[1]),
		TrustDomainConformanceEvidence,
	)
	if decodeErr != nil {
		return nil, Evidence{}, errors.Join(ErrInvalidTrustRootsFile, decodeErr)
	}
	runtimeRoots, decodeErr := DecodeTrustRoots(
		bytes.NewReader(documents[2]),
		TrustDomainRuntimeProbe,
	)
	if decodeErr != nil {
		return nil, Evidence{}, errors.Join(ErrInvalidTrustRootsFile, decodeErr)
	}
	loadedVerifier, verifierErr := NewVerifier(VerifierConfig{
		ConformanceRoots: conformanceRoots,
		RuntimeRoots:     runtimeRoots,
		Clock:            config.Clock,
		Entropy:          config.Entropy,
	})
	if verifierErr != nil {
		return nil, Evidence{}, errors.Join(ErrInvalidTrustRootsFile, verifierErr)
	}
	return loadedVerifier, loadedEvidence, nil
}

func openPinnedProductionProofFiles(
	candidates []productionProofFileCandidate,
	expectedOwnerUID uint32,
) ([]*pinnedProductionProofFile, error) {
	if len(candidates) != 3 {
		return nil, ErrInvalidConfiguration
	}
	files := make([]*pinnedProductionProofFile, 0, len(candidates))
	for _, candidate := range candidates {
		pinned, err := openProductionProofFile(candidate.path, expectedOwnerUID, candidate.policy)
		if err != nil {
			return nil, errors.Join(err, closePinnedProductionProofFiles(files))
		}
		files = append(files, pinned)
	}
	if err := validateDistinctProductionProofFiles(files); err != nil {
		return nil, errors.Join(err, closePinnedProductionProofFiles(files))
	}
	return files, nil
}

func openProductionProofFile(
	path string,
	expectedOwnerUID uint32,
	policy productionProofFilePolicy,
) (*pinnedProductionProofFile, error) {
	if !validProductionProofPath(path) {
		return nil, fmt.Errorf("%w: %s path must be canonical and absolute", policy.invalidFile, policy.label)
	}
	rootDescriptor, err := unix.Open(
		string(filepath.Separator),
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: open filesystem root: %w", policy.invalidFile, err)
	}
	currentDescriptor := rootDescriptor
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for index, component := range components {
		final := index == len(components)-1
		flags := uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW)
		if final {
			flags = uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK)
		}
		nextDescriptor, openErr := unix.Openat2(currentDescriptor, component, &unix.OpenHow{
			Flags: flags,
			Resolve: uint64(
				unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
			),
		})
		_ = unix.Close(currentDescriptor)
		if openErr != nil {
			return nil, fmt.Errorf("%w: open %s path: %w", policy.invalidFile, policy.label, openErr)
		}
		currentDescriptor = nextDescriptor

		var status unix.Stat_t
		if statErr := unix.Fstat(currentDescriptor, &status); statErr != nil {
			_ = unix.Close(currentDescriptor)
			return nil, fmt.Errorf("%w: inspect %s path: %w", policy.invalidFile, policy.label, statErr)
		}
		if !final {
			if !trustedProductionProofDirectory(status, expectedOwnerUID) {
				_ = unix.Close(currentDescriptor)
				return nil, fmt.Errorf("%w: %s parent owner or mode is unsafe", policy.invalidFile, policy.label)
			}
			continue
		}
		if !trustedProductionProofFile(status, expectedOwnerUID, policy.maximumBytes) {
			_ = unix.Close(currentDescriptor)
			if status.Size > policy.maximumBytes {
				return nil, errors.Join(policy.invalidFile, policy.invalidDocument, policy.tooLarge)
			}
			if status.Size <= 0 {
				return nil, errors.Join(policy.invalidFile, policy.invalidDocument)
			}
			return nil, fmt.Errorf("%w: %s file type, owner, mode, link count, or size is unsafe", policy.invalidFile, policy.label)
		}
		file := os.NewFile(uintptr(currentDescriptor), "production-"+policy.label)
		if file == nil {
			_ = unix.Close(currentDescriptor)
			return nil, fmt.Errorf("%w: %s file descriptor is unavailable", policy.invalidFile, policy.label)
		}
		return &pinnedProductionProofFile{file: file, status: status, policy: policy}, nil
	}
	_ = unix.Close(currentDescriptor)
	return nil, fmt.Errorf("%w: %s path has no file component", policy.invalidFile, policy.label)
}

func readPinnedProductionProofFile(pinned *pinnedProductionProofFile) ([]byte, error) {
	if pinned == nil || pinned.file == nil {
		return nil, ErrInvalidConfiguration
	}
	encoded := make([]byte, int(pinned.status.Size))
	if _, err := io.ReadFull(pinned.file, encoded); err != nil {
		return nil, fmt.Errorf("%w: read %s file: %w", pinned.policy.invalidFile, pinned.policy.label, err)
	}
	var trailing [1]byte
	if count, err := pinned.file.Read(trailing[:]); count != 0 || err != io.EOF {
		return nil, fmt.Errorf("%w: %s file changed while it was read", pinned.policy.invalidFile, pinned.policy.label)
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(pinned.file.Fd()), &after); err != nil || !sameProductionProofFileStatus(pinned.status, after) {
		return nil, fmt.Errorf("%w: %s file changed while it was read", pinned.policy.invalidFile, pinned.policy.label)
	}
	return encoded, nil
}

func validatePinnedProductionProofFiles(files []*pinnedProductionProofFile) error {
	for _, pinned := range files {
		if pinned == nil || pinned.file == nil {
			return ErrInvalidConfiguration
		}
		var after unix.Stat_t
		if err := unix.Fstat(int(pinned.file.Fd()), &after); err != nil || !sameProductionProofFileStatus(pinned.status, after) {
			return fmt.Errorf("%w: %s file changed while the bundle was read", pinned.policy.invalidFile, pinned.policy.label)
		}
	}
	return nil
}

func validateDistinctProductionProofFiles(files []*pinnedProductionProofFile) error {
	for left := range files {
		for right := left + 1; right < len(files); right++ {
			if files[left].status.Dev == files[right].status.Dev && files[left].status.Ino == files[right].status.Ino {
				return errors.Join(
					ErrInvalidConfiguration,
					files[left].policy.invalidFile,
					files[right].policy.invalidFile,
				)
			}
		}
	}
	return nil
}

func closePinnedProductionProofFiles(files []*pinnedProductionProofFile) error {
	var closeErr error
	for index := len(files) - 1; index >= 0; index-- {
		pinned := files[index]
		if pinned == nil || pinned.file == nil {
			continue
		}
		if err := pinned.file.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("%w: close %s file: %w", pinned.policy.invalidFile, pinned.policy.label, err))
		}
		pinned.file = nil
	}
	return closeErr
}

func validProductionProofPath(path string) bool {
	if path == "" || len(path) > maximumProductionProofPathBytes || !utf8.ValidString(path) ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return false
	}
	for _, character := range path {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func trustedProductionProofDirectory(status unix.Stat_t, expectedOwnerUID uint32) bool {
	return status.Mode&unix.S_IFMT == unix.S_IFDIR &&
		(status.Uid == 0 || status.Uid == expectedOwnerUID) && status.Mode&0o022 == 0
}

func trustedProductionProofFile(status unix.Stat_t, expectedOwnerUID uint32, maximumBytes int64) bool {
	permissions := status.Mode & 0o7777
	return status.Mode&unix.S_IFMT == unix.S_IFREG && status.Nlink == 1 &&
		status.Uid == expectedOwnerUID && (permissions == 0o444 || permissions == 0o644) &&
		status.Size > 0 && status.Size <= maximumBytes
}

func sameProductionProofFileStatus(before, after unix.Stat_t) bool {
	return before.Dev == after.Dev && before.Ino == after.Ino && before.Mode == after.Mode &&
		before.Nlink == after.Nlink && before.Uid == after.Uid && before.Gid == after.Gid &&
		before.Size == after.Size && before.Mtim == after.Mtim && before.Ctim == after.Ctim
}
