//go:build linux

package dependency

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNewVerifierFromFilesLoadsPinnedProductionProofBundle(t *testing.T) {
	t.Parallel()

	bundle := writeProductionProofTestBundle(t, 0o644)
	verifier, evidence, err := newVerifierFromFilesForOwner(bundle.config, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("newVerifierFromFilesForOwner() error = %v", err)
	}
	if !sameProductionEvidence(evidence, bundle.fixture.evidence) {
		t.Fatalf("newVerifierFromFilesForOwner() evidence = %#v, want signed fixture", evidence)
	}
	for _, path := range []string{bundle.evidencePath, bundle.conformanceRootsPath, bundle.runtimeRootsPath} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	probe := &signedProbe{descriptor: bundle.fixture.descriptor, privateKey: bundle.fixture.runtimePrivateKey}
	verified, err := VerifyDependency(context.Background(), verifier, probe, evidence, bundle.fixture.requirements())
	if err != nil {
		t.Fatalf("VerifyDependency(after proof removal) error = %v", err)
	}
	if _, _, err := verified.Open(); err != nil {
		t.Fatalf("Open(after proof removal) error = %v", err)
	}
}

func TestNewVerifierFromFilesUsesRootOwnershipPolicy(t *testing.T) {
	t.Parallel()

	bundle := writeProductionProofTestBundle(t, 0o644)
	verifier, evidence, err := NewVerifierFromFiles(bundle.config)
	if os.Geteuid() == 0 {
		if err != nil || verifier == nil || !sameProductionEvidence(evidence, bundle.fixture.evidence) {
			t.Fatalf("NewVerifierFromFiles(root) verifier/evidence/error = %v/%#v/%v", verifier, evidence, err)
		}
		return
	}
	if verifier != nil || !sameProductionEvidence(evidence, Evidence{}) || !errors.Is(err, ErrInvalidEvidenceFile) {
		t.Fatalf("NewVerifierFromFiles(non-root-owned files) verifier/evidence/error = %v/%#v/%v", verifier, evidence, err)
	}
}

func TestProductionProofPublicOwnerPolicyIsRoot(t *testing.T) {
	t.Parallel()

	if owner := productionProofOwnerUID(); owner != 0 {
		t.Fatalf("productionProofOwnerUID() = %d, want 0", owner)
	}
	fileStatus := unix.Stat_t{Mode: unix.S_IFREG | 0o644, Nlink: 1, Uid: 0, Size: 1}
	if !trustedProductionProofFile(fileStatus, productionProofOwnerUID(), maximumEvidenceDocumentBytes) {
		t.Fatal("root-owned proof file was rejected by production policy")
	}
	directoryStatus := unix.Stat_t{Mode: unix.S_IFDIR | 0o755, Uid: 0}
	if !trustedProductionProofDirectory(directoryStatus, productionProofOwnerUID()) {
		t.Fatal("root-owned proof directory was rejected by production policy")
	}
	if os.Geteuid() != 0 {
		fileStatus.Uid = uint32(os.Geteuid())
		directoryStatus.Uid = uint32(os.Geteuid())
		if trustedProductionProofFile(fileStatus, productionProofOwnerUID(), maximumEvidenceDocumentBytes) ||
			trustedProductionProofDirectory(directoryStatus, productionProofOwnerUID()) {
			t.Fatal("service-owned proof path was accepted by production root policy")
		}
	}
}

func TestNewVerifierFromFilesValidatesSourcesAndDistinctPathsBeforeOpening(t *testing.T) {
	t.Parallel()

	config := ProductionProofFileConfig{
		EvidenceFile:         "/does/not/exist/evidence.json",
		ConformanceRootsFile: "/does/not/exist/conformance.json",
		RuntimeRootsFile:     "/does/not/exist/runtime.json",
		Clock:                time.Now,
		Entropy:              strings.NewReader(strings.Repeat("n", ChallengeBytes)),
	}
	tests := []struct {
		name string
		edit func(*ProductionProofFileConfig)
	}{
		{name: "missing evidence path", edit: func(candidate *ProductionProofFileConfig) { candidate.EvidenceFile = "" }},
		{name: "missing conformance path", edit: func(candidate *ProductionProofFileConfig) { candidate.ConformanceRootsFile = "" }},
		{name: "missing runtime path", edit: func(candidate *ProductionProofFileConfig) { candidate.RuntimeRootsFile = "" }},
		{name: "evidence and conformance path alias", edit: func(candidate *ProductionProofFileConfig) { candidate.ConformanceRootsFile = candidate.EvidenceFile }},
		{name: "evidence and runtime path alias", edit: func(candidate *ProductionProofFileConfig) { candidate.RuntimeRootsFile = candidate.EvidenceFile }},
		{name: "root path alias", edit: func(candidate *ProductionProofFileConfig) {
			candidate.RuntimeRootsFile = candidate.ConformanceRootsFile
		}},
		{name: "nil clock", edit: func(candidate *ProductionProofFileConfig) { candidate.Clock = nil }},
		{name: "nil entropy", edit: func(candidate *ProductionProofFileConfig) { candidate.Entropy = nil }},
		{name: "typed nil entropy", edit: func(candidate *ProductionProofFileConfig) {
			var reader *bytes.Reader
			candidate.Entropy = reader
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			candidate := config
			test.edit(&candidate)
			verifier, evidence, err := newVerifierFromFilesForOwner(candidate, uint32(os.Geteuid()))
			if verifier != nil || !sameProductionEvidence(evidence, Evidence{}) || !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("newVerifierFromFilesForOwner() verifier/evidence/error = %v/%#v/%v", verifier, evidence, err)
			}
		})
	}
}

func TestProductionProofFilesAcceptExactModeBoundaries(t *testing.T) {
	t.Parallel()

	for _, mode := range []os.FileMode{0o444, 0o644} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()

			bundle := writeProductionProofTestBundle(t, mode)
			verifier, evidence, err := newVerifierFromFilesForOwner(bundle.config, uint32(os.Geteuid()))
			if err != nil || verifier == nil || !sameProductionEvidence(evidence, bundle.fixture.evidence) {
				t.Fatalf("newVerifierFromFilesForOwner(mode %04o) verifier/evidence/error = %v/%#v/%v", mode, verifier, evidence, err)
			}
		})
	}
}

func TestProductionProofFilesRejectUnsafeFinalModes(t *testing.T) {
	t.Parallel()

	roles := []struct {
		name      string
		path      func(productionProofTestBundle) string
		wantError error
	}{
		{name: "evidence", path: func(bundle productionProofTestBundle) string { return bundle.evidencePath }, wantError: ErrInvalidEvidenceFile},
		{name: "conformance roots", path: func(bundle productionProofTestBundle) string { return bundle.conformanceRootsPath }, wantError: ErrInvalidTrustRootsFile},
		{name: "runtime roots", path: func(bundle productionProofTestBundle) string { return bundle.runtimeRootsPath }, wantError: ErrInvalidTrustRootsFile},
	}
	for _, role := range roles {
		for _, mode := range []os.FileMode{0, 0o400, 0o440, 0o600, 0o640, 0o664, 0o755, os.ModeSetuid | 0o644} {
			role, mode := role, mode
			t.Run(role.name+" "+mode.String(), func(t *testing.T) {
				t.Parallel()

				bundle := writeProductionProofTestBundle(t, 0o644)
				if err := os.Chmod(role.path(bundle), mode); err != nil {
					t.Fatal(err)
				}
				verifier, evidence, err := newVerifierFromFilesForOwner(bundle.config, uint32(os.Geteuid()))
				if verifier != nil || !sameProductionEvidence(evidence, Evidence{}) || !errors.Is(err, role.wantError) {
					t.Fatalf("newVerifierFromFilesForOwner(%s mode %04o) error = %v", role.name, mode, err)
				}
			})
		}
	}
}

func TestProductionProofFilesRejectUnsafeObjectsAndParents(t *testing.T) {
	t.Parallel()

	t.Run("final symbolic link", func(t *testing.T) {
		t.Parallel()

		bundle := writeProductionProofTestBundle(t, 0o644)
		link := filepath.Join(bundle.directory, "evidence-link.json")
		if err := os.Symlink(bundle.evidencePath, link); err != nil {
			t.Fatal(err)
		}
		bundle.config.EvidenceFile = link
		if _, _, err := newVerifierFromFilesForOwner(bundle.config, uint32(os.Geteuid())); !errors.Is(err, ErrInvalidEvidenceFile) {
			t.Fatalf("newVerifierFromFilesForOwner(final symlink) error = %v", err)
		}
	})
	t.Run("parent symbolic link", func(t *testing.T) {
		t.Parallel()

		bundle := writeProductionProofTestBundle(t, 0o644)
		target := filepath.Join(bundle.directory, "target")
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatal(err)
		}
		moved := filepath.Join(target, "evidence.json")
		if err := os.Rename(bundle.evidencePath, moved); err != nil {
			t.Fatal(err)
		}
		linked := filepath.Join(bundle.directory, "linked")
		if err := os.Symlink(target, linked); err != nil {
			t.Fatal(err)
		}
		bundle.config.EvidenceFile = filepath.Join(linked, "evidence.json")
		if _, _, err := newVerifierFromFilesForOwner(bundle.config, uint32(os.Geteuid())); !errors.Is(err, ErrInvalidEvidenceFile) {
			t.Fatalf("newVerifierFromFilesForOwner(parent symlink) error = %v", err)
		}
	})
	t.Run("proc magic link", func(t *testing.T) {
		t.Parallel()

		bundle := writeProductionProofTestBundle(t, 0o644)
		file, err := os.Open(bundle.evidencePath)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		bundle.config.EvidenceFile = filepath.Join("/proc/self/fd", strconv.Itoa(int(file.Fd())))
		if _, _, err := newVerifierFromFilesForOwner(bundle.config, uint32(os.Geteuid())); !errors.Is(err, ErrInvalidEvidenceFile) {
			t.Fatalf("newVerifierFromFilesForOwner(proc magic link) error = %v", err)
		}
	})
	t.Run("hard link", func(t *testing.T) {
		t.Parallel()

		bundle := writeProductionProofTestBundle(t, 0o644)
		if err := os.Link(bundle.evidencePath, filepath.Join(bundle.directory, "evidence-alias.json")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := newVerifierFromFilesForOwner(bundle.config, uint32(os.Geteuid())); !errors.Is(err, ErrInvalidEvidenceFile) {
			t.Fatalf("newVerifierFromFilesForOwner(hard link) error = %v", err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		t.Parallel()

		bundle := writeProductionProofTestBundle(t, 0o644)
		bundle.config.EvidenceFile = bundle.directory
		if _, _, err := newVerifierFromFilesForOwner(bundle.config, uint32(os.Geteuid())); !errors.Is(err, ErrInvalidEvidenceFile) {
			t.Fatalf("newVerifierFromFilesForOwner(directory) error = %v", err)
		}
	})
	t.Run("named pipe", func(t *testing.T) {
		t.Parallel()

		bundle := writeProductionProofTestBundle(t, 0o644)
		pipe := filepath.Join(bundle.directory, "evidence.fifo")
		if err := unix.Mkfifo(pipe, 0o644); err != nil {
			t.Fatal(err)
		}
		bundle.config.EvidenceFile = pipe
		if _, _, err := newVerifierFromFilesForOwner(bundle.config, uint32(os.Geteuid())); !errors.Is(err, ErrInvalidEvidenceFile) {
			t.Fatalf("newVerifierFromFilesForOwner(named pipe) error = %v", err)
		}
	})
	t.Run("unsafe parent mode", func(t *testing.T) {
		t.Parallel()

		bundle := writeProductionProofTestBundle(t, 0o644)
		parent := filepath.Join(bundle.directory, "writable")
		if err := os.Mkdir(parent, 0o755); err != nil {
			t.Fatal(err)
		}
		moved := filepath.Join(parent, "evidence.json")
		if err := os.Rename(bundle.evidencePath, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		bundle.config.EvidenceFile = moved
		if _, _, err := newVerifierFromFilesForOwner(bundle.config, uint32(os.Geteuid())); !errors.Is(err, ErrInvalidEvidenceFile) {
			t.Fatalf("newVerifierFromFilesForOwner(unsafe parent) error = %v", err)
		}
	})
	t.Run("unexpected owner", func(t *testing.T) {
		t.Parallel()

		bundle := writeProductionProofTestBundle(t, 0o644)
		if _, _, err := newVerifierFromFilesForOwner(bundle.config, uint32(os.Geteuid())^1); !errors.Is(err, ErrInvalidEvidenceFile) {
			t.Fatalf("newVerifierFromFilesForOwner(unexpected owner) error = %v", err)
		}
	})
}

func TestProductionProofFilesRejectInvalidPaths(t *testing.T) {
	t.Parallel()

	bundle := writeProductionProofTestBundle(t, 0o644)
	tests := []struct {
		name string
		path string
		want error
	}{
		{name: "empty", path: "", want: ErrInvalidConfiguration},
		{name: "relative", path: "evidence.json", want: ErrInvalidEvidenceFile},
		{name: "root", path: string(filepath.Separator), want: ErrInvalidEvidenceFile},
		{name: "noncanonical", path: bundle.directory + "/sub/../evidence.json", want: ErrInvalidEvidenceFile},
		{name: "nul", path: filepath.Join(bundle.directory, "evidence\x00.json"), want: ErrInvalidEvidenceFile},
		{name: "newline", path: filepath.Join(bundle.directory, "evidence\n.json"), want: ErrInvalidEvidenceFile},
		{name: "invalid UTF-8", path: bundle.directory + "/" + string([]byte{0xff}), want: ErrInvalidEvidenceFile},
		{name: "oversized", path: string(filepath.Separator) + strings.Repeat("a", 4096), want: ErrInvalidEvidenceFile},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			config := bundle.config
			config.EvidenceFile = test.path
			if _, _, err := newVerifierFromFilesForOwner(config, uint32(os.Geteuid())); !errors.Is(err, test.want) {
				t.Fatalf("newVerifierFromFilesForOwner(%q) error = %v, want %v", test.path, err, test.want)
			}
		})
	}
}

func TestProductionProofFilesPreserveRoleSpecificDocumentErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		edit       func(*testing.T, productionProofTestBundle)
		wantFile   error
		wantFormat error
	}{
		{name: "malformed evidence", edit: func(t *testing.T, bundle productionProofTestBundle) {
			writeProductionProofTestFile(t, bundle.evidencePath, []byte(`{}`), 0o644)
		}, wantFile: ErrInvalidEvidenceFile, wantFormat: ErrInvalidEvidenceDocument},
		{name: "oversized evidence", edit: func(t *testing.T, bundle productionProofTestBundle) {
			writeProductionProofTestFile(t, bundle.evidencePath, bytes.Repeat([]byte{' '}, maximumEvidenceDocumentBytes+1), 0o644)
		}, wantFile: ErrInvalidEvidenceFile, wantFormat: ErrEvidenceDocumentTooLarge},
		{name: "malformed conformance roots", edit: func(t *testing.T, bundle productionProofTestBundle) {
			writeProductionProofTestFile(t, bundle.conformanceRootsPath, []byte(`{}`), 0o644)
		}, wantFile: ErrInvalidTrustRootsFile, wantFormat: ErrInvalidTrustRootsDocument},
		{name: "oversized runtime roots", edit: func(t *testing.T, bundle productionProofTestBundle) {
			writeProductionProofTestFile(t, bundle.runtimeRootsPath, bytes.Repeat([]byte{' '}, maximumTrustRootsDocumentBytes+1), 0o644)
		}, wantFile: ErrInvalidTrustRootsFile, wantFormat: ErrTrustRootsDocumentTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			bundle := writeProductionProofTestBundle(t, 0o644)
			test.edit(t, bundle)
			verifier, evidence, err := newVerifierFromFilesForOwner(bundle.config, uint32(os.Geteuid()))
			if verifier != nil || !sameProductionEvidence(evidence, Evidence{}) ||
				!errors.Is(err, test.wantFile) || !errors.Is(err, test.wantFormat) {
				t.Fatalf("newVerifierFromFilesForOwner() verifier/evidence/error = %v/%#v/%v, want %v and %v", verifier, evidence, err, test.wantFile, test.wantFormat)
			}
		})
	}
}

func TestNewVerifierFromFilesBindsEachTrustRootRole(t *testing.T) {
	t.Parallel()

	bundle := writeProductionProofTestBundle(t, 0o644)
	bundle.config.ConformanceRootsFile, bundle.config.RuntimeRootsFile =
		bundle.config.RuntimeRootsFile, bundle.config.ConformanceRootsFile
	verifier, evidence, err := newVerifierFromFilesForOwner(bundle.config, uint32(os.Geteuid()))
	if verifier != nil || !sameProductionEvidence(evidence, Evidence{}) ||
		!errors.Is(err, ErrInvalidTrustRootsFile) || !errors.Is(err, ErrInvalidTrustRootsDocument) {
		t.Fatalf("newVerifierFromFilesForOwner(swapped roles) verifier/evidence/error = %v/%#v/%v", verifier, evidence, err)
	}
}

func TestOpenPinnedProductionProofFilesPinsEveryFileBeforeReading(t *testing.T) {
	t.Parallel()

	bundle := writeProductionProofTestBundle(t, 0o644)
	files, err := openPinnedProductionProofFiles([]productionProofFileCandidate{
		{path: bundle.evidencePath, policy: productionEvidenceFilePolicy},
		{path: bundle.conformanceRootsPath, policy: productionTrustRootsFilePolicy},
		{path: bundle.runtimeRootsPath, policy: productionTrustRootsFilePolicy},
	}, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("openPinnedProductionProofFiles() error = %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("openPinnedProductionProofFiles() count = %d, want 3", len(files))
	}
	for index, pinned := range files {
		if pinned == nil || pinned.file == nil {
			t.Fatalf("openPinnedProductionProofFiles()[%d] is unavailable", index)
		}
		offset, err := pinned.file.Seek(0, io.SeekCurrent)
		if err != nil {
			t.Fatalf("Seek(current %d) error = %v", index, err)
		}
		if offset != 0 {
			t.Fatalf("pinned file %d offset = %d before bundle read, want 0", index, offset)
		}
	}
	for index, pinned := range files {
		if _, err := readPinnedProductionProofFile(pinned); err != nil {
			t.Fatalf("readPinnedProductionProofFile(%d) error = %v", index, err)
		}
	}
	if err := closePinnedProductionProofFiles(files); err != nil {
		t.Fatalf("closePinnedProductionProofFiles() error = %v", err)
	}
}

func TestPinnedProductionProofFileNeverFollowsPathReplacementAndRejectsMutation(t *testing.T) {
	t.Parallel()

	bundle := writeProductionProofTestBundle(t, 0o644)
	original, err := os.ReadFile(bundle.evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := openProductionProofFile(bundle.evidencePath, uint32(os.Geteuid()), productionEvidenceFilePolicy)
	if err != nil {
		t.Fatalf("openProductionProofFile() error = %v", err)
	}
	defer pinned.file.Close()
	if err := os.Rename(bundle.evidencePath, filepath.Join(bundle.directory, "original-evidence.json")); err != nil {
		t.Fatal(err)
	}
	writeProductionProofTestFile(t, bundle.evidencePath, bytes.Repeat([]byte{'x'}, len(original)), 0o644)
	got, err := readPinnedProductionProofFile(pinned)
	if err != nil && !errors.Is(err, ErrInvalidEvidenceFile) {
		t.Fatalf("readPinnedProductionProofFile(path replacement) error = %v", err)
	}
	if err == nil && !bytes.Equal(got, original) {
		t.Fatal("readPinnedProductionProofFile() followed the replacement path")
	}

	mutablePath := filepath.Join(bundle.directory, "mutable-evidence.json")
	writeProductionProofTestFile(t, mutablePath, original, 0o644)
	mutable, err := openProductionProofFile(mutablePath, uint32(os.Geteuid()), productionEvidenceFilePolicy)
	if err != nil {
		t.Fatalf("openProductionProofFile(mutable) error = %v", err)
	}
	defer mutable.file.Close()
	changed := append([]byte(nil), original...)
	changed[len(changed)/2] ^= 1
	writeProductionProofTestFile(t, mutablePath, changed, 0o644)
	changedAt := time.Now().Add(time.Hour)
	if err := os.Chtimes(mutablePath, changedAt, changedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := readPinnedProductionProofFile(mutable); !errors.Is(err, ErrInvalidEvidenceFile) {
		t.Fatalf("readPinnedProductionProofFile(mutated inode) error = %v", err)
	}
}

func TestProductionProofBundleRejectsPairwiseInodeAliases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		files []*pinnedProductionProofFile
		want  []error
	}{
		{
			name: "evidence and conformance",
			files: []*pinnedProductionProofFile{
				{status: unix.Stat_t{Dev: 1, Ino: 1, Nlink: 1}, policy: productionEvidenceFilePolicy},
				{status: unix.Stat_t{Dev: 1, Ino: 1, Nlink: 1}, policy: productionTrustRootsFilePolicy},
				{status: unix.Stat_t{Dev: 1, Ino: 3, Nlink: 1}, policy: productionTrustRootsFilePolicy},
			},
			want: []error{ErrInvalidConfiguration, ErrInvalidEvidenceFile, ErrInvalidTrustRootsFile},
		},
		{
			name: "evidence and runtime",
			files: []*pinnedProductionProofFile{
				{status: unix.Stat_t{Dev: 2, Ino: 1, Nlink: 1}, policy: productionEvidenceFilePolicy},
				{status: unix.Stat_t{Dev: 2, Ino: 2, Nlink: 1}, policy: productionTrustRootsFilePolicy},
				{status: unix.Stat_t{Dev: 2, Ino: 1, Nlink: 1}, policy: productionTrustRootsFilePolicy},
			},
			want: []error{ErrInvalidConfiguration, ErrInvalidEvidenceFile, ErrInvalidTrustRootsFile},
		},
		{
			name: "conformance and runtime",
			files: []*pinnedProductionProofFile{
				{status: unix.Stat_t{Dev: 3, Ino: 1, Nlink: 1}, policy: productionEvidenceFilePolicy},
				{status: unix.Stat_t{Dev: 3, Ino: 2, Nlink: 1}, policy: productionTrustRootsFilePolicy},
				{status: unix.Stat_t{Dev: 3, Ino: 2, Nlink: 1}, policy: productionTrustRootsFilePolicy},
			},
			want: []error{ErrInvalidConfiguration, ErrInvalidTrustRootsFile},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := validateDistinctProductionProofFiles(test.files)
			for _, want := range test.want {
				if !errors.Is(err, want) {
					t.Fatalf("validateDistinctProductionProofFiles() error = %v, want %v", err, want)
				}
			}
		})
	}
}

func TestProductionProofBundleFinalStatRejectsEarlierFileMutation(t *testing.T) {
	t.Parallel()

	bundle := writeProductionProofTestBundle(t, 0o644)
	files := make([]*pinnedProductionProofFile, 0, 3)
	for _, candidate := range []struct {
		path   string
		policy productionProofFilePolicy
	}{
		{path: bundle.evidencePath, policy: productionEvidenceFilePolicy},
		{path: bundle.conformanceRootsPath, policy: productionTrustRootsFilePolicy},
		{path: bundle.runtimeRootsPath, policy: productionTrustRootsFilePolicy},
	} {
		pinned, err := openProductionProofFile(candidate.path, uint32(os.Geteuid()), candidate.policy)
		if err != nil {
			t.Fatalf("openProductionProofFile() error = %v", err)
		}
		files = append(files, pinned)
		defer pinned.file.Close()
	}
	if _, err := readPinnedProductionProofFile(files[0]); err != nil {
		t.Fatalf("readPinnedProductionProofFile(evidence) error = %v", err)
	}
	evidence, err := os.ReadFile(bundle.evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	evidence[len(evidence)/2] ^= 1
	writeProductionProofTestFile(t, bundle.evidencePath, evidence, 0o644)
	changedAt := time.Now().Add(time.Hour)
	if err := os.Chtimes(bundle.evidencePath, changedAt, changedAt); err != nil {
		t.Fatal(err)
	}
	for _, pinned := range files[1:] {
		if _, err := readPinnedProductionProofFile(pinned); err != nil {
			t.Fatalf("readPinnedProductionProofFile(root) error = %v", err)
		}
	}
	if err := validatePinnedProductionProofFiles(files); !errors.Is(err, ErrInvalidEvidenceFile) {
		t.Fatalf("validatePinnedProductionProofFiles() error = %v", err)
	}
}

func TestNewVerifierFromFilesIsSafeForConcurrentConstruction(t *testing.T) {
	t.Parallel()

	bundle := writeProductionProofTestBundle(t, 0o444)
	const constructors = 64
	type constructorResult struct {
		verifier *Verifier
		evidence Evidence
		err      error
	}
	start := make(chan struct{})
	resultsSeen := make(chan constructorResult, constructors)
	var ready sync.WaitGroup
	ready.Add(constructors)
	for range constructors {
		go func() {
			ready.Done()
			<-start
			config := bundle.config
			config.Entropy = strings.NewReader(strings.Repeat("n", ChallengeBytes*4))
			verifier, evidence, err := newVerifierFromFilesForOwner(config, uint32(os.Geteuid()))
			resultsSeen <- constructorResult{verifier: verifier, evidence: evidence, err: err}
		}()
	}
	ready.Wait()
	close(start)
	results := make([]constructorResult, 0, constructors)
	for range constructors {
		result := <-resultsSeen
		if result.err != nil || result.verifier == nil || !sameProductionEvidence(result.evidence, bundle.fixture.evidence) {
			t.Fatalf("concurrent newVerifierFromFilesForOwner() verifier/evidence/error = %v/%#v/%v", result.verifier, result.evidence, result.err)
		}
		probe := &signedProbe{descriptor: bundle.fixture.descriptor, privateKey: bundle.fixture.runtimePrivateKey}
		if _, err := VerifyDependency(context.Background(), result.verifier, probe, result.evidence, bundle.fixture.requirements()); err != nil {
			t.Fatalf("concurrent result VerifyDependency() error = %v", err)
		}
		results = append(results, result)
	}
	results[0].evidence.Signature[0] ^= 0xff
	results[0].evidence.Descriptor.AtomicGroups[0] = "mutated"
	results[0].verifier.conformanceRoots[bundle.fixture.evidence.KeyID][0] ^= 0xff
	results[0].verifier.runtimeRoots[bundle.fixture.descriptor.RuntimeKeyID][0] ^= 0xff
	for index, result := range results[1:] {
		if !sameProductionEvidence(result.evidence, bundle.fixture.evidence) ||
			!bytes.Equal(result.verifier.conformanceRoots[bundle.fixture.evidence.KeyID], bundle.fixture.conformancePublicKey) ||
			!bytes.Equal(result.verifier.runtimeRoots[bundle.fixture.descriptor.RuntimeKeyID], bundle.fixture.runtimePublicKey) {
			t.Fatalf("concurrent result %d shared mutable proof state", index+1)
		}
	}
}

func TestNewVerifierFromFilesDoesNotLeakDescriptors(t *testing.T) {
	success := writeProductionProofTestBundle(t, 0o644)
	firstOpenFailure := writeProductionProofTestBundle(t, 0o644)
	if err := os.Chmod(firstOpenFailure.evidencePath, 0); err != nil {
		t.Fatal(err)
	}
	secondOpenFailure := writeProductionProofTestBundle(t, 0o644)
	if err := os.Chmod(secondOpenFailure.conformanceRootsPath, 0); err != nil {
		t.Fatal(err)
	}
	thirdOpenFailure := writeProductionProofTestBundle(t, 0o644)
	if err := os.Chmod(thirdOpenFailure.runtimeRootsPath, 0); err != nil {
		t.Fatal(err)
	}
	evidenceDecodeFailure := writeProductionProofTestBundle(t, 0o644)
	writeProductionProofTestFile(t, evidenceDecodeFailure.evidencePath, []byte(`{}`), 0o644)
	conformanceDecodeFailure := writeProductionProofTestBundle(t, 0o644)
	writeProductionProofTestFile(t, conformanceDecodeFailure.conformanceRootsPath, []byte(`{}`), 0o644)
	runtimeDecodeFailure := writeProductionProofTestBundle(t, 0o644)
	writeProductionProofTestFile(t, runtimeDecodeFailure.runtimeRootsPath, []byte(`{}`), 0o644)
	verifierFailure := writeProductionProofTestBundle(t, 0o644)
	writeProductionProofTestFile(t, verifierFailure.runtimeRootsPath, encodeTrustRootsDocument(
		t,
		TrustDomainRuntimeProbe,
		[]trustRootDocumentFixture{{
			KeyID: verifierFailure.fixture.evidence.KeyID, Algorithm: "ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(verifierFailure.fixture.conformancePublicKey),
		}},
		nil,
	), 0o644)
	cases := []struct {
		name    string
		config  ProductionProofFileConfig
		wantErr bool
	}{
		{name: "success", config: success.config},
		{name: "first open failure", config: firstOpenFailure.config, wantErr: true},
		{name: "second open failure", config: secondOpenFailure.config, wantErr: true},
		{name: "third open failure", config: thirdOpenFailure.config, wantErr: true},
		{name: "evidence decode failure", config: evidenceDecodeFailure.config, wantErr: true},
		{name: "conformance decode failure", config: conformanceDecodeFailure.config, wantErr: true},
		{name: "runtime decode failure", config: runtimeDecodeFailure.config, wantErr: true},
		{name: "verifier failure", config: verifierFailure.config, wantErr: true},
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 16 {
		for _, test := range cases {
			verifier, evidence, err := newVerifierFromFilesForOwner(test.config, uint32(os.Geteuid()))
			if (err != nil) != test.wantErr || test.wantErr && (verifier != nil || !sameProductionEvidence(evidence, Evidence{})) {
				t.Fatalf("newVerifierFromFilesForOwner(%s) verifier/evidence/error = %v/%#v/%v", test.name, verifier, evidence, err)
			}
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("open descriptor count changed from %d to %d", len(before), len(after))
	}
}

func TestClosePinnedProductionProofFilesAttemptsEveryClose(t *testing.T) {
	t.Parallel()

	bundle := writeProductionProofTestBundle(t, 0o644)
	evidenceFile, err := os.Open(bundle.evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	rootFile, err := os.Open(bundle.conformanceRootsPath)
	if err != nil {
		evidenceFile.Close()
		t.Fatal(err)
	}
	files := []*pinnedProductionProofFile{
		{file: evidenceFile, policy: productionEvidenceFilePolicy},
		{file: rootFile, policy: productionTrustRootsFilePolicy},
	}
	if err := evidenceFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := rootFile.Close(); err != nil {
		t.Fatal(err)
	}
	err = closePinnedProductionProofFiles(files)
	if !errors.Is(err, ErrInvalidEvidenceFile) || !errors.Is(err, ErrInvalidTrustRootsFile) {
		t.Fatalf("closePinnedProductionProofFiles() error = %v", err)
	}
	if files[0].file != nil || files[1].file != nil {
		t.Fatal("closePinnedProductionProofFiles() retained a closed descriptor")
	}
}

type productionProofTestBundle struct {
	directory            string
	evidencePath         string
	conformanceRootsPath string
	runtimeRootsPath     string
	config               ProductionProofFileConfig
	fixture              verificationFixture
}

func writeProductionProofTestBundle(t *testing.T, mode os.FileMode) productionProofTestBundle {
	t.Helper()

	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(workingDirectory, ".production-proof-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("RemoveAll(%q) error = %v", directory, err)
		}
	})
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newVerificationFixture(t, "state-domain-a")
	evidencePath := filepath.Join(directory, "evidence.json")
	conformanceRootsPath := filepath.Join(directory, "conformance-roots.json")
	runtimeRootsPath := filepath.Join(directory, "runtime-roots.json")
	writeProductionProofTestFile(t, evidencePath, encodeEvidenceDocument(t, fixture.evidence, nil), mode)
	writeProductionProofTestFile(t, conformanceRootsPath, encodeTrustRootsDocument(t, TrustDomainConformanceEvidence, []trustRootDocumentFixture{{
		KeyID: fixture.evidence.KeyID, Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(fixture.conformancePublicKey),
	}}, nil), mode)
	writeProductionProofTestFile(t, runtimeRootsPath, encodeTrustRootsDocument(t, TrustDomainRuntimeProbe, []trustRootDocumentFixture{{
		KeyID: fixture.descriptor.RuntimeKeyID, Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(fixture.runtimePublicKey),
	}}, nil), mode)
	return productionProofTestBundle{
		directory: directory, evidencePath: evidencePath,
		conformanceRootsPath: conformanceRootsPath, runtimeRootsPath: runtimeRootsPath,
		config: ProductionProofFileConfig{
			EvidenceFile: evidencePath, ConformanceRootsFile: conformanceRootsPath, RuntimeRootsFile: runtimeRootsPath,
			Clock: func() time.Time { return fixture.now }, Entropy: strings.NewReader(strings.Repeat("n", ChallengeBytes*4)),
		},
		fixture: fixture,
	}
}

func writeProductionProofTestFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func sameProductionEvidence(left, right Evidence) bool {
	return equalDescriptor(left.Descriptor, right.Descriptor) && left.IssuedAtUnix == right.IssuedAtUnix &&
		left.ExpiresAtUnix == right.ExpiresAtUnix && left.KeyID == right.KeyID && bytes.Equal(left.Signature, right.Signature)
}
