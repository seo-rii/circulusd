//go:build linux

package qualification

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hancomac/circulusd/internal/conformance/nsjail/fixture"
	executorns "github.com/hancomac/circulusd/internal/executor/nsjail"
	"github.com/hancomac/circulusd/internal/release"
	"github.com/hancomac/circulusd/internal/strictjson"
	"golang.org/x/sys/unix"
)

const maximumQualificationDocument = 4 << 20
const helperCommand = "circulusd-nsjail-qualification"

// Paths select preprovisioned dedicated resources; no install or delegation is
// performed. Artifact identities are resolved from the signed release, never
// accepted as a caller assertion in this document.
type qualificationConfig struct {
	SchemaVersion            int    `json:"schemaVersion"`
	ReleaseManifestPath      string `json:"releaseManifestPath"`
	TrustRootsPath           string `json:"trustRootsPath"`
	InstalledNsJailPath      string `json:"installedNsJailPath"`
	EnvironmentInventoryPath string `json:"environmentInventoryPath"`
	EnvironmentRoot          string `json:"environmentRoot"`
	SandboxRoot              string `json:"sandboxRoot"`
	CgroupRoot               string `json:"cgroupRoot"`
	EvidenceOutputDirectory  string `json:"evidenceOutputDirectory"`
	HostUID                  uint32 `json:"hostUid"`
	HostGID                  uint32 `json:"hostGid"`
	SandboxdClientUID        uint32 `json:"sandboxdClientUid"`
	CommandManifestOwnerUID  uint32 `json:"commandManifestOwnerUid"`
	TotalMillis              uint64 `json:"totalMillis"`
	StepMillis               uint64 `json:"stepMillis"`
	CleanupMillis            uint64 `json:"cleanupMillis"`
}

// The SHA-256 of this exact signed inventory is both the rootfs directory name
// and the qualification environment identity. Every rootfs entry is listed;
// regular files are hashed and no unlisted entry is accepted.
type environmentInventory struct {
	SchemaVersion  int                          `json:"schemaVersion"`
	Architecture   string                       `json:"architecture"`
	SandboxdPath   string                       `json:"sandboxdPath"`
	SandboxdDigest string                       `json:"sandboxdDigest"`
	HelperPath     string                       `json:"helperPath"`
	HelperDigest   string                       `json:"helperDigest"`
	SeccompDigest  string                       `json:"seccompDigest"`
	Entries        []inventoryEntry             `json:"entries"`
	Experiments    fixture.ExperimentDescriptor `json:"experiments"`
}
type inventoryEntry struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Mode   uint32 `json:"mode"`
	Digest string `json:"digest,omitempty"`
	Target string `json:"target,omitempty"`
}
type qualificationRelease struct {
	config                                                           qualificationConfig
	inventory                                                        environmentInventory
	binaryDigest, environmentDigest, manifestDigest, version, rootfs string
}

func digestBytes(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func canonicalDigest(s string) bool {
	b, e := hex.DecodeString(strings.TrimPrefix(s, "sha256:"))
	return e == nil && len(b) == 32 && s == "sha256:"+hex.EncodeToString(b)
}
func canonicalPath(s string) bool {
	return s != "" && s != "/" && len(s) <= 4096 && !strings.ContainsAny(s, "\x00\r\n") && filepath.IsAbs(s) && filepath.Clean(s) == s
}

// Reject duplicate, unknown and case-folded members at all depths, and
// trailing JSON. encoding/json alone would match keys case-insensitively.
func strictQualificationJSON(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > maximumQualificationDocument {
		return errors.New("qualification document exceeds bounds")
	}
	return strictjson.Decode(raw, target)
}

func readQualificationFile(path string, max int64, executable bool) ([]byte, error) {
	if !canonicalPath(path) {
		return nil, errors.New("path must be canonical and absolute")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "qualification-input")
	defer f.Close()
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Mode&0o022 != 0 || before.Mode&0o6000 != 0 || (before.Uid != 0 && before.Uid != uint32(os.Geteuid())) || before.Size < 0 || before.Size > max || (executable && before.Mode&0o111 == 0) {
		return nil, errors.New("unsafe qualification file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(raw)) > max {
		return nil, errors.New("qualification read failed or exceeded bounds")
	}
	if err := unix.Fstat(fd, &after); err != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, errors.New("qualification input changed while reading")
	}
	return raw, nil
}

func parseQualificationConfig(raw []byte) (qualificationConfig, error) {
	var c qualificationConfig
	if err := strictQualificationJSON(raw, &c); err != nil {
		return c, err
	}
	if c.SchemaVersion != 1 || c.HostUID == 0 || c.HostUID == ^uint32(0) || c.HostGID == 0 || c.HostGID == ^uint32(0) || c.HostUID == uint32(os.Geteuid()) || c.HostGID == uint32(os.Getegid()) || c.TotalMillis < 1000 || c.TotalMillis > 600000 || c.StepMillis < 10000 || c.StepMillis >= c.TotalMillis || c.CleanupMillis < 100 || c.CleanupMillis > 60000 {
		return c, errors.New("invalid identity or timeout bounds")
	}
	paths := []string{c.ReleaseManifestPath, c.TrustRootsPath, c.InstalledNsJailPath, c.EnvironmentInventoryPath, c.EnvironmentRoot, c.SandboxRoot, c.CgroupRoot, c.EvidenceOutputDirectory}
	for i, p := range paths {
		if !canonicalPath(p) {
			return c, errors.New("invalid qualification input path")
		}
		for _, q := range paths[:i] {
			if p == q {
				return c, errors.New("qualification paths must be distinct")
			}
		}
	}
	for _, p := range []string{c.SandboxRoot, c.CgroupRoot, c.EvidenceOutputDirectory} {
		for _, q := range paths {
			if p != q && (strings.HasPrefix(q, p+"/") || strings.HasPrefix(p, q+"/")) {
				return c, errors.New("mutable qualification roots must not overlap inputs")
			}
		}
	}
	return c, nil
}

func resolveQualificationRelease(c qualificationConfig) (qualificationRelease, error) {
	r := qualificationRelease{config: c}
	// Existing strict release loader and offline signature verifier own release
	// policy. A development manifest can never authorize this external driver.
	manifestFile, err := snapshotQualificationDocument(c.ReleaseManifestPath)
	if err != nil {
		return r, err
	}
	defer manifestFile.Close()
	manifest, err := release.Load(fmt.Sprintf("/proc/self/fd/%d", manifestFile.Fd()))
	if err != nil {
		return r, err
	}
	if err = manifest.Validate(); err != nil {
		return r, err
	}
	rootsFile, err := snapshotQualificationDocument(c.TrustRootsPath)
	if err != nil {
		return r, err
	}
	defer rootsFile.Close()
	roots, err := release.LoadTrustStore(fmt.Sprintf("/proc/self/fd/%d", rootsFile.Fd()))
	if err != nil {
		return r, err
	}
	if manifest.Release.Status != "candidate" && manifest.Release.Status != "production" {
		return r, errors.New("qualification requires a signed candidate or production release")
	}
	if err = roots.VerifyPromotion(manifest); err != nil {
		return r, err
	}
	arch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	if arch == "" {
		return r, errors.New("unsupported qualification architecture")
	}
	artifactIdentity := func(name string) (string, uint64, error) {
		found := ""
		var size uint64
		for _, component := range manifest.Components {
			if component.Name != name {
				continue
			}
			for _, artifact := range component.Artifacts {
				if artifact.Architecture != arch {
					continue
				}
				if found != "" {
					return "", 0, errors.New("ambiguous qualification artifact")
				}
				if artifact.ExtractionRecipe != "" || artifact.SizeBytes == nil || *artifact.SizeBytes == 0 {
					return "", 0, errors.New("qualification artifacts require direct-file bytes and a signed size")
				}
				found = "sha256:" + artifact.SHA256
				size = *artifact.SizeBytes
			}
		}
		if !canonicalDigest(found) {
			return "", 0, fmt.Errorf("missing signed %s artifact", name)
		}
		return found, size, nil
	}
	var binarySize, inventorySize uint64
	if r.binaryDigest, binarySize, err = artifactIdentity("nsjail"); err != nil {
		return r, err
	}
	if r.environmentDigest, inventorySize, err = artifactIdentity("nsjail-qualification-environment"); err != nil {
		return r, err
	}
	raw, err := readQualificationFile(c.EnvironmentInventoryPath, maximumQualificationDocument, false)
	if err != nil {
		return r, err
	}
	if digestBytes(raw) != r.environmentDigest || uint64(len(raw)) != inventorySize {
		return r, errors.New("environment inventory digest or signed size mismatch")
	}
	if err = strictQualificationJSON(raw, &r.inventory); err != nil {
		return r, err
	}
	inv := r.inventory
	if inv.Experiments != fixture.RequiredExperiments() || inv.SchemaVersion != 1 || inv.Architecture != arch || !canonicalPath(inv.SandboxdPath) || !canonicalPath(inv.HelperPath) || inv.HelperPath == inv.SandboxdPath || !canonicalDigest(inv.SandboxdDigest) || !canonicalDigest(inv.HelperDigest) || !canonicalDigest(inv.SeccompDigest) || len(inv.Entries) == 0 || len(inv.Entries) > 10000 {
		return r, errors.New("invalid qualification environment inventory")
	}
	binary, err := readQualificationFile(c.InstalledNsJailPath, 256<<20, true)
	if err != nil {
		return r, err
	}
	if digestBytes(binary) != r.binaryDigest || uint64(len(binary)) != binarySize {
		return r, errors.New("NsJail executable digest or signed size mismatch")
	}
	r.rootfs = filepath.Join(c.EnvironmentRoot, r.environmentDigest, "nsjail", "rootfs")
	if err = verifyQualificationRootfs(r); err != nil {
		return r, err
	}
	seccomp := filepath.Join(c.EnvironmentRoot, r.environmentDigest, "nsjail", "seccomp", inv.SeccompDigest+".policy")
	raw, err = readQualificationFile(seccomp, maximumQualificationDocument, false)
	if err != nil || digestBytes(raw) != inv.SeccompDigest {
		return r, errors.New("seccomp artifact unavailable or mismatched")
	}
	r.version = manifest.Release.Version
	r.manifestDigest, err = release.ManifestSigningDigest(manifest)
	return r, err
}

func qualificationPlanner(r qualificationRelease) (*executorns.Planner, error) {
	c := r.config
	return executorns.NewPlanner(executorns.Config{BinaryPath: c.InstalledNsJailPath, BinaryDigest: r.binaryDigest, EnvironmentRoot: c.EnvironmentRoot, SandboxRoot: c.SandboxRoot, CgroupRoot: c.CgroupRoot, SandboxdPath: r.inventory.SandboxdPath, ProtocolVersion: 1, SandboxdClientUID: c.SandboxdClientUID, CommandManifestOwnerUID: c.CommandManifestOwnerUID})
}

func verifyQualificationRootfs(r qualificationRelease) error {
	entries := map[string]inventoryEntry{}
	var total int64
	for _, entry := range r.inventory.Entries {
		if entry.Path == "" || filepath.IsAbs(entry.Path) || filepath.Clean(entry.Path) != entry.Path || entry.Path == "." || entry.Path == ".." || strings.HasPrefix(entry.Path, "../") || strings.ContainsAny(entry.Path, "\x00\r\n") || entry.Mode > 0o777 || entry.Mode&0o022 != 0 {
			return errors.New("unsafe rootfs inventory entry")
		}
		if _, ok := entries[entry.Path]; ok {
			return errors.New("duplicate rootfs inventory entry")
		}
		entries[entry.Path] = entry
	}
	seen := 0
	err := walkQualificationDirectory(r.rootfs, 10001, 32, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		var status unix.Stat_t
		if err := unix.Lstat(path, &status); err != nil {
			return err
		}
		if (status.Uid != 0 && status.Uid != uint32(os.Geteuid())) || status.Mode&0o6022 != 0 {
			return errors.New("unsafe rootfs owner or mode")
		}
		if path == r.rootfs {
			if !d.IsDir() {
				return errors.New("rootfs is not a directory")
			}
			return nil
		}
		relative, err := filepath.Rel(r.rootfs, path)
		if err != nil {
			return err
		}
		entry, ok := entries[relative]
		if !ok {
			return errors.New("unlisted rootfs entry")
		}
		seen++
		info, err := d.Info()
		if err != nil {
			return err
		}
		if uint32(info.Mode().Perm()) != entry.Mode {
			return errors.New("rootfs entry mode mismatch")
		}
		switch entry.Kind {
		case "directory":
			if !d.IsDir() || entry.Digest != "" || entry.Target != "" {
				return errors.New("invalid inventory directory")
			}
		case "file":
			if !info.Mode().IsRegular() || !canonicalDigest(entry.Digest) || entry.Target != "" {
				return errors.New("invalid inventory file")
			}
			raw, err := readQualificationFile(path, 256<<20, false)
			if err != nil {
				return err
			}
			total += int64(len(raw))
			if total > 1<<30 || digestBytes(raw) != entry.Digest {
				return errors.New("rootfs byte bound or digest mismatch")
			}
		default:
			return errors.New("qualification rootfs accepts only regular files and directories")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if seen != len(entries) {
		return errors.New("rootfs inventory entry absent")
	}
	for path, digest := range map[string]string{r.inventory.SandboxdPath: r.inventory.SandboxdDigest, r.inventory.HelperPath: r.inventory.HelperDigest} {
		entry, ok := entries[strings.TrimPrefix(path, "/")]
		if !ok || entry.Kind != "file" || entry.Digest != digest || entry.Mode&0o111 == 0 {
			return errors.New("sandboxd or helper identity absent from rootfs inventory")
		}
	}
	raw, err := readQualificationFile(filepath.Join(r.rootfs, "etc/circulusd/commands.json"), 1<<20, false)
	if err != nil {
		return err
	}
	var commands struct {
		SchemaVersion int `json:"schemaVersion"`
		Commands      []struct {
			Name string `json:"name"`
			Path string `json:"path"`
		} `json:"commands"`
	}
	if err := strictQualificationJSON(raw, &commands); err != nil || commands.SchemaVersion != 1 || len(commands.Commands) != 1 || commands.Commands[0].Name != helperCommand || commands.Commands[0].Path != r.inventory.HelperPath {
		return errors.New("qualification rootfs must allow only the pinned helper command")
	}
	return nil
}

// Both signed metadata and offline trust roots are parsed from the same bytes
// whose file ownership, permissions, size and read stability were checked.
func snapshotQualificationDocument(path string) (*os.File, error) {
	raw, err := readQualificationFile(path, maximumQualificationDocument, false)
	if err != nil {
		return nil, err
	}
	fd, err := unix.MemfdCreate("nsjail-qualification-metadata", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "qualification-metadata")
	if _, err = file.Write(raw); err == nil {
		_, err = unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL)
	}
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

// Directory contents are read in chunks, so a malformed or unexpectedly large
// dedicated tree cannot allocate an unbounded listing before it is rejected.
func readQualificationDirectory(path string, maximum int) ([]os.DirEntry, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "qualification-directory")
	defer file.Close()
	entries := []os.DirEntry{}
	for {
		chunk, err := file.ReadDir(128)
		if len(entries)+len(chunk) > maximum {
			return nil, errors.New("qualification directory entry bound exceeded")
		}
		entries = append(entries, chunk...)
		if errors.Is(err, io.EOF) {
			return entries, nil
		}
		if err != nil {
			return nil, err
		}
	}
}
func walkQualificationDirectory(root string, maximum, depthLimit int, visit func(string, os.DirEntry, error) error) error {
	count := 0
	var walk func(string, int) error
	walk = func(path string, depth int) error {
		count++
		if count > maximum || depth > depthLimit {
			return errors.New("qualification directory traversal bound exceeded")
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		entry := fs.FileInfoToDirEntry(info)
		if err := visit(path, entry, nil); err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		entries, err := readQualificationDirectory(path, maximum-count)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := walk(filepath.Join(path, entry.Name()), depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root, 0)
}
