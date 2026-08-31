package workerd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/hancomac/circulusd/internal/release"
	"golang.org/x/sys/unix"
)

func TestResolveResourceQualificationReleaseValidDevelopmentSnapshot(t *testing.T) {
	t.Parallel()

	executable := []byte("#!/bin/sh\nprintf pinned-workerd\n")
	fixture := newResourceReleaseTestFixture(t, "development", executable)

	resolved, err := resolveResourceQualificationRelease(fixture.config)
	if err != nil {
		t.Fatalf("resolveResourceQualificationRelease() error = %v", err)
	}
	t.Cleanup(func() {
		if err := resolved.close(); err != nil {
			t.Errorf("close resolved release: %v", err)
		}
	})

	identity := resolved.identitySnapshot()
	if identity.releaseVersion != fixture.manifest.Release.Version ||
		identity.releaseStatus != "development" ||
		identity.architecture != fixture.config.Architecture ||
		identity.workerdVersion != fixture.manifest.Components[0].Version ||
		identity.artifactName != fixture.manifest.Components[0].Artifacts[0].Name ||
		identity.archiveSHA256 != fixture.manifest.Components[0].Artifacts[0].SHA256 ||
		identity.extractionRecipe != release.ExtractionRecipeGzipSingleFileV1 ||
		identity.extractedExecutableSHA256 != sha256Hex(executable) ||
		identity.installedExecutableSizeBytes != uint64(len(executable)) {
		t.Fatalf("identitySnapshot() = %#v", identity)
	}
	if identity.promotionVerified {
		t.Fatal("development identity promotionVerified = true")
	}
	if identity.productionQualified {
		t.Fatal("development identity productionQualified = true")
	}
	if identity.manifestSigningDigest == "" {
		t.Fatal("development identity manifestSigningDigest is empty")
	}

	replacement := []byte("#!/bin/sh\nprintf replacement\n")
	if err := os.Remove(fixture.config.InstalledWorkerdPath); err != nil {
		t.Fatalf("remove installed executable: %v", err)
	}
	writeResourceReleaseExecutable(t, fixture.config.InstalledWorkerdPath, replacement)

	snapshot, err := resolved.openExecutableSnapshot()
	if err != nil {
		t.Fatalf("openExecutableSnapshot() error = %v", err)
	}
	defer snapshot.Close()
	got, err := io.ReadAll(snapshot)
	if err != nil {
		t.Fatalf("read executable snapshot: %v", err)
	}
	if string(got) != string(executable) {
		t.Fatalf("snapshot bytes = %q, want %q", got, executable)
	}
	wantedSeals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	seals, err := unix.FcntlInt(snapshot.Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		t.Fatalf("F_GET_SEALS: %v", err)
	}
	if seals&wantedSeals != wantedSeals {
		t.Fatalf("snapshot seals = %#x, want at least %#x", seals, wantedSeals)
	}
}

func TestResolveResourceQualificationReleaseValidatesDevelopmentTrustRoots(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
		want   error
	}{
		{
			name: "missing",
			mutate: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatalf("remove development trust roots: %v", err)
				}
			},
			want: errResourceQualificationReleaseUnavailable,
		},
		{
			name: "malformed",
			mutate: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
					t.Fatalf("write malformed development trust roots: %v", err)
				}
			},
			want: errResourceQualificationReleaseInvalid,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newResourceReleaseTestFixture(t, "development", []byte("workerd"))
			test.mutate(t, fixture.config.ReleaseTrustRootsPath)

			_, err := resolveResourceQualificationRelease(fixture.config)
			assertResourceReleaseError(t, err, test.want)
		})
	}
}

func TestResolveResourceQualificationReleaseRejectsMissingArchitectureArtifact(t *testing.T) {
	t.Parallel()

	fixture := newResourceReleaseTestFixture(t, "development", []byte("workerd"))
	fixture.config.Architecture = "aarch64"

	_, err := resolveResourceQualificationRelease(fixture.config)
	assertResourceReleaseError(t, err, errResourceQualificationReleaseUnavailable)
}

func TestResolveResourceQualificationReleaseRejectsMissingWorkerdArtifact(t *testing.T) {
	t.Parallel()

	fixture := newResourceReleaseTestFixture(t, "development", []byte("workerd"))
	fixture.manifest.Components[0].Name = "platformd"
	fixture.manifest.Components[0].Artifacts[0].ExtractionRecipe = ""
	fixture.manifest.Components[0].Artifacts[0].ExtractedExecutableSHA256 = ""
	writeReleaseManifest(t, fixture.config.ReleaseManifestPath, fixture.manifest)

	_, err := resolveResourceQualificationRelease(fixture.config)
	assertResourceReleaseError(t, err, errResourceQualificationReleaseUnavailable)
}

func TestResolveResourceQualificationReleaseRejectsMissingProvenance(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*release.Artifact)
	}{
		{
			name: "extraction recipe",
			mutate: func(artifact *release.Artifact) {
				artifact.ExtractionRecipe = ""
			},
		},
		{
			name: "extracted executable digest",
			mutate: func(artifact *release.Artifact) {
				artifact.ExtractedExecutableSHA256 = ""
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newResourceReleaseTestFixture(t, "development", []byte("workerd"))
			test.mutate(&fixture.manifest.Components[0].Artifacts[0])
			writeReleaseManifest(t, fixture.config.ReleaseManifestPath, fixture.manifest)

			_, err := resolveResourceQualificationRelease(fixture.config)
			assertResourceReleaseError(t, err, errResourceQualificationReleaseInvalid)
		})
	}
}

func TestResolveResourceQualificationReleaseHasNoCallerIdentityOverride(t *testing.T) {
	t.Parallel()

	resolver := reflect.TypeOf(resolveResourceQualificationRelease)
	configType := reflect.TypeOf(resourceQualificationConfig{})
	if resolver.NumIn() != 1 || resolver.In(0) != configType {
		t.Fatalf("resolver inputs = %v, want exactly resourceQualificationConfig", resolver)
	}
	for _, forbidden := range []string{
		"ExpectedDigest",
		"ExpectedVersion",
		"ExpectedWorkerdDigest",
		"ExpectedWorkerdVersion",
		"WorkerdArguments",
		"ChildEnvironment",
	} {
		if _, found := configType.FieldByName(forbidden); found {
			t.Fatalf("resourceQualificationConfig contains caller identity override %q", forbidden)
		}
	}

	executable := []byte("release-owned-workerd")
	fixture := newResourceReleaseTestFixture(t, "development", executable)
	fixture.config.CgroupRootPath = "/caller/controlled/expected/digest/ignored"
	fixture.config.EvidenceOutputDirectory = "/caller/controlled/version/ignored"
	fixture.config.Limits = resourceQualificationLimits{}
	fixture.config.Timeouts = resourceQualificationTimeouts{}
	fixture.config.ColdStartSamples = 0

	resolved, err := resolveResourceQualificationRelease(fixture.config)
	if err != nil {
		t.Fatalf("resolveResourceQualificationRelease() error = %v", err)
	}
	defer resolved.close()
	if got := resolved.identitySnapshot().extractedExecutableSHA256; got != sha256Hex(executable) {
		t.Fatalf("extracted executable digest = %q, want release-owned digest", got)
	}
}

func TestResolveResourceQualificationReleaseRejectsSymlinks(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*testing.T, resourceReleaseTestFixture) string
	}{
		{
			name: "final component",
			mutate: func(t *testing.T, fixture resourceReleaseTestFixture) string {
				link := filepath.Join(t.TempDir(), "workerd-link")
				if err := os.Symlink(fixture.config.InstalledWorkerdPath, link); err != nil {
					t.Fatalf("symlink executable: %v", err)
				}
				return link
			},
		},
		{
			name: "ancestor component",
			mutate: func(t *testing.T, fixture resourceReleaseTestFixture) string {
				realDirectory := filepath.Dir(fixture.config.InstalledWorkerdPath)
				link := filepath.Join(t.TempDir(), "installed-link")
				if err := os.Symlink(realDirectory, link); err != nil {
					t.Fatalf("symlink executable ancestor: %v", err)
				}
				return filepath.Join(link, filepath.Base(fixture.config.InstalledWorkerdPath))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newResourceReleaseTestFixture(t, "development", []byte("workerd"))
			fixture.config.InstalledWorkerdPath = test.mutate(t, fixture)

			_, err := resolveResourceQualificationRelease(fixture.config)
			assertResourceReleaseError(t, err, errResourceQualificationReleaseInvalid)
		})
	}
}

func TestResolveResourceQualificationReleaseRejectsNonRegularExecutable(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		make func(*testing.T, string)
	}{
		{
			name: "directory",
			make: func(t *testing.T, path string) {
				if err := os.Mkdir(path, 0o500); err != nil {
					t.Fatalf("mkdir nonregular executable: %v", err)
				}
			},
		},
		{
			name: "fifo",
			make: func(t *testing.T, path string) {
				if err := unix.Mkfifo(path, 0o500); err != nil {
					t.Fatalf("mkfifo nonregular executable: %v", err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newResourceReleaseTestFixture(t, "development", []byte("workerd"))
			nonregular := filepath.Join(t.TempDir(), "nonregular")
			test.make(t, nonregular)
			fixture.config.InstalledWorkerdPath = nonregular

			_, err := resolveResourceQualificationRelease(fixture.config)
			assertResourceReleaseError(t, err, errResourceQualificationReleaseInvalid)
		})
	}
}

func TestResolveResourceQualificationReleaseRejectsOversizeExecutable(t *testing.T) {
	t.Parallel()

	fixture := newResourceReleaseTestFixture(t, "development", []byte("workerd"))
	oversize := filepath.Join(t.TempDir(), "oversize-workerd")
	file, err := os.OpenFile(oversize, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o500)
	if err != nil {
		t.Fatalf("create oversize executable: %v", err)
	}
	if err := file.Truncate(maximumResourceQualificationExecutableBytes + 1); err != nil {
		file.Close()
		t.Fatalf("truncate oversize executable: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close oversize executable: %v", err)
	}
	fixture.config.InstalledWorkerdPath = oversize

	_, err = resolveResourceQualificationRelease(fixture.config)
	assertResourceReleaseError(t, err, errResourceQualificationReleaseInvalid)
}

func TestResolveResourceQualificationReleaseRejectsExecutableDigestMismatch(t *testing.T) {
	t.Parallel()

	fixture := newResourceReleaseTestFixture(t, "development", []byte("expected-workerd"))
	if err := os.Remove(fixture.config.InstalledWorkerdPath); err != nil {
		t.Fatalf("remove expected executable: %v", err)
	}
	writeResourceReleaseExecutable(t, fixture.config.InstalledWorkerdPath, []byte("different-workerd"))

	_, err := resolveResourceQualificationRelease(fixture.config)
	assertResourceReleaseError(t, err, errResourceQualificationReleaseInvalid)
}

func TestResolveResourceQualificationReleaseClassifiesMissingHostPaths(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*resourceQualificationConfig)
	}{
		{
			name: "manifest",
			mutate: func(config *resourceQualificationConfig) {
				config.ReleaseManifestPath = filepath.Join(filepath.Dir(config.ReleaseManifestPath), "missing-manifest.json")
			},
		},
		{
			name: "installed executable",
			mutate: func(config *resourceQualificationConfig) {
				config.InstalledWorkerdPath = filepath.Join(filepath.Dir(config.InstalledWorkerdPath), "missing-workerd")
			},
		},
		{
			name: "installed executable ancestor is not a directory",
			mutate: func(config *resourceQualificationConfig) {
				config.InstalledWorkerdPath += "/child"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newResourceReleaseTestFixture(t, "development", []byte("workerd"))
			test.mutate(&fixture.config)

			_, err := resolveResourceQualificationRelease(fixture.config)
			assertResourceReleaseError(t, err, errResourceQualificationReleaseUnavailable)
		})
	}
}

func TestResolveResourceQualificationReleaseClassifiesOpenat2Errnos(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		errno error
		want  error
	}{
		{name: "permission denied", errno: unix.EACCES, want: errResourceQualificationReleaseInvalid},
		{name: "operation not permitted", errno: unix.EPERM, want: errResourceQualificationReleaseInvalid},
		{name: "openat2 unavailable", errno: unix.ENOSYS, want: errResourceQualificationReleaseUnavailable},
		{name: "openat2 unsupported", errno: unix.EOPNOTSUPP, want: errResourceQualificationReleaseUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newResourceReleaseTestFixture(t, "development", []byte("workerd"))
			_, err := resolveResourceQualificationReleaseWithOpenat2(
				fixture.config,
				func(int, string, *unix.OpenHow) (int, error) {
					return -1, test.errno
				},
			)
			assertResourceReleaseError(t, err, test.want)
		})
	}
}

func TestResolveResourceQualificationReleaseClassifiesMalformedManifest(t *testing.T) {
	t.Parallel()

	fixture := newResourceReleaseTestFixture(t, "development", []byte("workerd"))
	if err := os.WriteFile(fixture.config.ReleaseManifestPath, []byte("{"), 0o600); err != nil {
		t.Fatalf("write malformed manifest: %v", err)
	}

	_, err := resolveResourceQualificationRelease(fixture.config)
	assertResourceReleaseError(t, err, errResourceQualificationReleaseInvalid)
}

func TestResolveResourceQualificationReleaseEnforcesPromotionTrust(t *testing.T) {
	t.Parallel()

	for _, status := range []string{"candidate", "production"} {
		t.Run(status, func(t *testing.T) {
			t.Parallel()
			executable := []byte("trusted-" + status + "-workerd")
			fixture := newResourceReleaseTestFixture(t, status, executable)

			resolved, err := resolveResourceQualificationRelease(fixture.config)
			if err != nil {
				t.Fatalf("resolveResourceQualificationRelease() error = %v", err)
			}
			defer resolved.close()
			identity := resolved.identitySnapshot()
			if !identity.promotionVerified {
				t.Fatal("promotionVerified = false")
			}
			if got, want := identity.productionQualified, status == "production"; got != want {
				t.Fatalf("productionQualified = %t, want %t", got, want)
			}
		})
	}
}

func TestResolveResourceQualificationReleaseRejectsPromotionTrustBypass(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *resourceReleaseTestFixture)
		want   error
	}{
		{
			name: "missing trust roots",
			mutate: func(t *testing.T, fixture *resourceReleaseTestFixture) {
				if err := os.Remove(fixture.config.ReleaseTrustRootsPath); err != nil {
					t.Fatalf("remove trust roots: %v", err)
				}
			},
			want: errResourceQualificationReleaseUnavailable,
		},
		{
			name: "untrusted root",
			mutate: func(t *testing.T, fixture *resourceReleaseTestFixture) {
				_, unrelatedPrivate, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("generate unrelated root: %v", err)
				}
				writeTrustRoots(t, fixture.config.ReleaseTrustRootsPath, unrelatedPrivate.Public().(ed25519.PublicKey))
			},
			want: errResourceQualificationReleaseInvalid,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newResourceReleaseTestFixture(t, "candidate", []byte("candidate-workerd"))
			test.mutate(t, &fixture)

			_, err := resolveResourceQualificationRelease(fixture.config)
			assertResourceReleaseError(t, err, test.want)
		})
	}
}

func TestResourceQualificationReleaseSupportsConcurrentSnapshotReaders(t *testing.T) {
	t.Parallel()

	executable := []byte("concurrently-readable-workerd")
	fixture := newResourceReleaseTestFixture(t, "development", executable)
	resolved, err := resolveResourceQualificationRelease(fixture.config)
	if err != nil {
		t.Fatalf("resolveResourceQualificationRelease() error = %v", err)
	}
	defer resolved.close()

	const readers = 32
	var wait sync.WaitGroup
	errorsFound := make(chan error, readers)
	for range readers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if identity := resolved.identitySnapshot(); identity.extractedExecutableSHA256 != sha256Hex(executable) {
				errorsFound <- fmt.Errorf("identity digest = %q", identity.extractedExecutableSHA256)
				return
			}
			snapshot, openErr := resolved.openExecutableSnapshot()
			if openErr != nil {
				errorsFound <- openErr
				return
			}
			defer snapshot.Close()
			got, readErr := io.ReadAll(snapshot)
			if readErr != nil {
				errorsFound <- readErr
				return
			}
			if string(got) != string(executable) {
				errorsFound <- fmt.Errorf("snapshot = %q", got)
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Errorf("concurrent snapshot reader: %v", err)
	}
}

func TestResourceQualificationReleaseSnapshotCloneErrorClassification(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		errno error
		want  error
	}{
		{name: "proc fd missing", errno: unix.ENOENT, want: errResourceQualificationReleaseUnavailable},
		{name: "proc fd parent missing", errno: unix.ENOTDIR, want: errResourceQualificationReleaseUnavailable},
		{name: "syscall unavailable", errno: unix.ENOSYS, want: errResourceQualificationReleaseUnavailable},
		{name: "operation unsupported", errno: unix.EOPNOTSUPP, want: errResourceQualificationReleaseUnavailable},
		{name: "permission denied", errno: unix.EACCES, want: errResourceQualificationReleaseInvalid},
		{name: "operation not permitted", errno: unix.EPERM, want: errResourceQualificationReleaseInvalid},
		{name: "unexpected io failure", errno: unix.EIO, want: errResourceQualificationReleaseInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newResourceReleaseTestFixture(t, "development", []byte("clone-error-workerd"))
			resolved, err := resolveResourceQualificationRelease(fixture.config)
			if err != nil {
				t.Fatalf("resolveResourceQualificationRelease() error = %v", err)
			}
			defer resolved.close()

			_, err = resolved.openExecutableSnapshotWithOpen(func(string, int, uint32) (int, error) {
				return -1, test.errno
			})
			assertResourceReleaseError(t, err, test.want)
			if errors.Is(err, errResourceQualificationReleaseClosed) {
				t.Fatalf("clone error = %v also matches closed snapshot", err)
			}
		})
	}
}

func TestResourceQualificationReleaseSnapshotCloneOwnsIndependentDescriptor(t *testing.T) {
	t.Parallel()

	executable := []byte("independent-snapshot-workerd")
	fixture := newResourceReleaseTestFixture(t, "development", executable)
	resolved, err := resolveResourceQualificationRelease(fixture.config)
	if err != nil {
		t.Fatalf("resolveResourceQualificationRelease() error = %v", err)
	}

	if _, err := resolved.executable.Seek(7, io.SeekStart); err != nil {
		t.Fatalf("seek owner snapshot: %v", err)
	}
	discardedClone, err := resolved.openExecutableSnapshot()
	if err != nil {
		t.Fatalf("open disposable executable snapshot: %v", err)
	}
	if err := discardedClone.Close(); err != nil {
		t.Fatalf("close disposable executable snapshot: %v", err)
	}
	clone, err := resolved.openExecutableSnapshot()
	if err != nil {
		t.Fatalf("openExecutableSnapshot() error = %v", err)
	}
	defer clone.Close()

	cloneOffset, err := clone.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatalf("inspect clone offset: %v", err)
	}
	if cloneOffset != 0 {
		t.Fatalf("clone offset = %d, want independent offset 0", cloneOffset)
	}
	if _, err := clone.Seek(5, io.SeekStart); err != nil {
		t.Fatalf("seek clone snapshot: %v", err)
	}
	ownerOffset, err := resolved.executable.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatalf("inspect owner offset: %v", err)
	}
	if ownerOffset != 7 {
		t.Fatalf("owner offset after clone seek = %d, want 7", ownerOffset)
	}

	fdFlags, err := unix.FcntlInt(clone.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("F_GETFD clone: %v", err)
	}
	if fdFlags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("clone descriptor flags = %#x, want FD_CLOEXEC", fdFlags)
	}
	statusFlags, err := unix.FcntlInt(clone.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatalf("F_GETFL clone: %v", err)
	}
	if statusFlags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatalf("clone status flags = %#x, want read-only", statusFlags)
	}
	wantedSeals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	seals, err := unix.FcntlInt(clone.Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		t.Fatalf("F_GET_SEALS clone: %v", err)
	}
	if seals&wantedSeals != wantedSeals {
		t.Fatalf("clone seals = %#x, want at least %#x", seals, wantedSeals)
	}

	if err := resolved.close(); err != nil {
		t.Fatalf("close owner snapshot: %v", err)
	}
	if _, err := clone.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("rewind clone after owner close: %v", err)
	}
	got, err := io.ReadAll(clone)
	if err != nil {
		t.Fatalf("read clone after owner close: %v", err)
	}
	if string(got) != string(executable) {
		t.Fatalf("clone after owner close = %q, want %q", got, executable)
	}
	if _, err := resolved.openExecutableSnapshot(); !errors.Is(err, errResourceQualificationReleaseClosed) {
		t.Fatalf("open after owner close error = %v, want closed snapshot", err)
	}
}

type resourceReleaseTestFixture struct {
	config   resourceQualificationConfig
	manifest release.Manifest
}

func newResourceReleaseTestFixture(t *testing.T, status string, executable []byte) resourceReleaseTestFixture {
	t.Helper()

	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "release-manifest.json")
	trustRootsPath := filepath.Join(directory, "release-trust-roots.json")
	executablePath := filepath.Join(directory, "workerd")
	writeResourceReleaseExecutable(t, executablePath, executable)

	manifest := developmentResourceReleaseManifest(executable)
	manifest.Release.Status = status
	if status == "candidate" || status == "production" {
		var publicKey ed25519.PublicKey
		manifest, publicKey = signedResourceReleaseManifest(t, status, executable)
		writeTrustRoots(t, trustRootsPath, publicKey)
	} else {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate development trust root: %v", err)
		}
		writeTrustRoots(t, trustRootsPath, publicKey)
	}
	writeReleaseManifest(t, manifestPath, manifest)

	return resourceReleaseTestFixture{
		config: resourceQualificationConfig{
			SchemaVersion:         1,
			ReleaseManifestPath:   manifestPath,
			ReleaseTrustRootsPath: trustRootsPath,
			InstalledWorkerdPath:  executablePath,
			Architecture:          "x86_64",
		},
		manifest: manifest,
	}
}

func developmentResourceReleaseManifest(executable []byte) release.Manifest {
	archiveDigest := sha256.Sum256([]byte("workerd-archive"))
	return release.Manifest{
		SchemaVersion: 1,
		Release: release.Release{
			Version:       "1.2.3",
			Status:        "development",
			Architectures: []string{"x86_64"},
		},
		Toolchains: map[string]string{
			"go":     "go1.25.0",
			"node":   "24.1.0",
			"pnpm":   "10.0.0",
			"protoc": "31.0",
		},
		Components: []release.Component{
			{
				Name:          "workerd",
				Version:       "1.20250823.0",
				Commit:        strings.Repeat("1", 40),
				License:       "Apache-2.0",
				Source:        "https://example.invalid/workerd",
				Qualification: "phase0-resource",
				Artifacts: []release.Artifact{
					{
						Architecture:              "x86_64",
						Name:                      "workerd-x86_64.gz",
						SHA256:                    hex.EncodeToString(archiveDigest[:]),
						ExtractionRecipe:          release.ExtractionRecipeGzipSingleFileV1,
						ExtractedExecutableSHA256: sha256Hex(executable),
					},
				},
			},
		},
	}
}

func signedResourceReleaseManifest(t *testing.T, status string, executable []byte) (release.Manifest, ed25519.PublicKey) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate release signing key: %v", err)
	}
	manifest := release.Manifest{
		SchemaVersion: 1,
		Release: release.Release{
			Version:       "1.2.3",
			Status:        status,
			Architectures: []string{"x86_64"},
		},
		Toolchains: map[string]string{
			"go":                 "go1.25.0",
			"node":               "24.1.0",
			"pnpm":               "10.0.0",
			"protoc":             "31.0",
			"protocGenGo":        "1.36.0",
			"protocGenConnectGo": "1.18.0",
		},
	}
	for _, name := range []string{
		"platformd",
		"agentd",
		"executord",
		"sandboxd",
		"workerd",
		"celld",
		"session-host",
		"pi-runtime",
		"state-app",
	} {
		archiveDigest := sha256.Sum256([]byte(name + "-archive"))
		size := uint64(len(name) + 1)
		artifact := release.Artifact{
			Architecture: "x86_64",
			Name:         name + "-x86_64.bin",
			SHA256:       hex.EncodeToString(archiveDigest[:]),
			SizeBytes:    &size,
		}
		if name == "workerd" {
			artifact.ExtractionRecipe = release.ExtractionRecipeGzipSingleFileV1
			artifact.ExtractedExecutableSHA256 = sha256Hex(executable)
		}
		component := release.Component{
			Name:          name,
			Version:       "1.0.0",
			Commit:        strings.Repeat("2", 40),
			License:       "Apache-2.0",
			Source:        "https://example.invalid/" + name,
			Qualification: "release",
			Artifacts:     []release.Artifact{artifact},
		}
		digest, err := release.ArtifactSigningDigest(manifest.Release, component, artifact)
		if err != nil {
			t.Fatalf("ArtifactSigningDigest(%q): %v", name, err)
		}
		component.Artifacts[0].Signature = &release.Signature{
			Algorithm: "ed25519",
			KeyID:     "qualification-test-root",
			Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(digest))),
		}
		manifest.Components = append(manifest.Components, component)
	}
	for _, pair := range []string{
		"platformd-agentd",
		"platformd-executord",
		"session-host-dynamic-worker",
		"executord-sandboxd",
		"state-app-schema",
	} {
		manifest.ProtocolCompatibility = append(manifest.ProtocolCompatibility, release.ProtocolCompatibility{
			Pair:             pair,
			Minimum:          release.ProtocolVersion{Major: 1},
			Maximum:          release.ProtocolVersion{Major: 1},
			DescriptorSHA256: strings.Repeat("3", 64),
		})
	}
	manifestDigest, err := release.ManifestSigningDigest(manifest)
	if err != nil {
		t.Fatalf("ManifestSigningDigest(): %v", err)
	}
	manifest.Signatures = []release.Signature{
		{
			Algorithm: "ed25519",
			KeyID:     "qualification-test-root",
			Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(manifestDigest))),
		},
	}
	if err := manifest.Validate(); err != nil {
		t.Fatalf("signed manifest Validate(): %v", err)
	}
	return manifest, publicKey
}

func writeReleaseManifest(t *testing.T, path string, manifest release.Manifest) {
	t.Helper()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal release manifest: %v", err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write release manifest: %v", err)
	}
}

func writeTrustRoots(t *testing.T, path string, publicKey ed25519.PublicKey) {
	t.Helper()
	document := struct {
		SchemaVersion int `json:"schemaVersion"`
		Roots         []struct {
			KeyID     string `json:"keyId"`
			Algorithm string `json:"algorithm"`
			PublicKey string `json:"publicKey"`
		} `json:"roots"`
	}{SchemaVersion: 1}
	document.Roots = append(document.Roots, struct {
		KeyID     string `json:"keyId"`
		Algorithm string `json:"algorithm"`
		PublicKey string `json:"publicKey"`
	}{
		KeyID:     "qualification-test-root",
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
	})
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal trust roots: %v", err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write trust roots: %v", err)
	}
}

func writeResourceReleaseExecutable(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o500); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	if err := os.Chmod(path, 0o500); err != nil {
		t.Fatalf("chmod executable: %v", err)
	}
}

func sha256Hex(contents []byte) string {
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

func assertResourceReleaseError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want errors.Is(_, %v)", err, want)
	}
	other := errResourceQualificationReleaseInvalid
	if errors.Is(want, other) {
		other = errResourceQualificationReleaseUnavailable
	}
	if errors.Is(err, other) {
		t.Fatalf("error = %v matches both release error classes", err)
	}
}
