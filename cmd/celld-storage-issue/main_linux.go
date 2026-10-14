//go:build linux

// celld-storage-issue consumes independently signed raw observations. It does
// not run a service, generate a key, write a bucket or promote a platform release.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hancomac/circulusd/internal/conformance/celld/issuance"
	"github.com/hancomac/circulusd/internal/dependency"
	"golang.org/x/sys/unix"
)

type issuerConfig struct {
	SchemaVersion        uint32 `json:"schemaVersion"`
	SelectionFile        string `json:"selectionFile"`
	ReleaseRootsFile     string `json:"releaseRootsFile"`
	ObserverRootsFile    string `json:"observerRootsFile"`
	ConformanceSeedFile  string `json:"conformanceSeedFile"`
	ConformanceKeyID     string `json:"conformanceKeyId"`
	RuntimeRootsFile     string `json:"runtimeRootsFile"`
	RuntimeKeyID         string `json:"runtimeKeyId"`
	MeasurementFile      string `json:"measurementFile"`
	RawReportFile        string `json:"rawReportFile"`
	OwnerObservationFile string `json:"ownerObservationFile"`
	ExecutableFile       string `json:"executableFile"`
	ApplicationFile      string `json:"applicationFile"`
	HostBootIDFile       string `json:"hostBootIdFile"`
	DriverFile           string `json:"driverFile"`
	LifetimeSeconds      uint32 `json:"lifetimeSeconds"`
}

type roleRoots struct {
	SchemaVersion uint32 `json:"schemaVersion"`
	TrustDomain   string `json:"trustDomain"`
	Roots         []struct {
		KeyID     string `json:"keyId"`
		Algorithm string `json:"algorithm"`
		PublicKey string `json:"publicKey"`
	} `json:"roots"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now)) }

func run(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	flags := flag.NewFlagSet("celld-storage-issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "owned private issuer config")
	output := flags.String("output", "", "new evidence file in an owned private directory")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *configPath == "" || *output == "" {
		fmt.Fprintln(stderr, "usage: celld-storage-issue --config /absolute/private.json --output /absolute/private/evidence.json")
		return 2
	}
	encoded, err := readPrivate(*configPath, issuance.MaximumReportBytes)
	var config issuerConfig
	if err != nil || issuance.DecodeStrict(encoded, &config) != nil || config.SchemaVersion != 1 || config.LifetimeSeconds == 0 || config.LifetimeSeconds > 86400 {
		fmt.Fprintln(stderr, "UNAVAILABLE: invalid private issuer configuration")
		return 2
	}
	public, err := issueFiles(config, now())
	if err != nil {
		if errors.Is(err, issuance.ErrUnqualified) {
			fmt.Fprintln(stderr, "UNAVAILABLE: required independent native fault observations are incomplete")
			return 2
		}
		fmt.Fprintln(stderr, "FAIL: independent measurement or authority verification failed")
		return 1
	}
	if err := retain(*output, public); err != nil {
		fmt.Fprintln(stderr, "FAIL: evidence output could not be retained exclusively")
		return 1
	}
	encodedDigest := sha256.Sum256(public)
	_ = json.NewEncoder(stdout).Encode(struct {
		SchemaVersion          uint32 `json:"schemaVersion"`
		Kind                   string `json:"kind"`
		EvidenceDigest         string `json:"evidenceDigest"`
		PlatformAdmissionReady bool   `json:"platformAdmissionReady"`
	}{1, "circulusd.native-storage-issued/v1", fmt.Sprintf("sha256:%x", encodedDigest), false})
	return 0
}

func issueFiles(c issuerConfig, now time.Time) ([]byte, error) {
	selectionBytes, err := readPrivate(c.SelectionFile, issuance.MaximumReportBytes)
	if err != nil {
		return nil, err
	}
	var selected issuance.StorageSelection
	if err := issuance.DecodeStrict(selectionBytes, &selected); err != nil {
		return nil, err
	}
	releaseRoots, err := readRoots(c.ReleaseRootsFile, "native-storage-release-selection")
	if err != nil {
		return nil, err
	}
	observerRoots, err := readRoots(c.ObserverRootsFile, "native-storage-observation")
	if err != nil {
		return nil, err
	}
	runtimeBytes, err := readPrivate(c.RuntimeRootsFile, issuance.MaximumReportBytes)
	if err != nil {
		return nil, err
	}
	runtimeRoots, err := dependency.DecodeTrustRoots(bytes.NewReader(runtimeBytes), dependency.TrustDomainRuntimeProbe)
	if err != nil {
		return nil, err
	}
	runtimeKey, ok := runtimeRoots[c.RuntimeKeyID]
	if !ok {
		return nil, issuance.ErrInvalidConfiguration
	}
	measurementBytes, err := readPrivate(c.MeasurementFile, issuance.MaximumReportBytes)
	if err != nil {
		return nil, err
	}
	var measured issuance.Measurement
	if err := issuance.DecodeStrict(measurementBytes, &measured); err != nil {
		return nil, err
	}
	if measured.CelldCommit != selected.CelldCommit {
		return nil, issuance.ErrInvalidConfiguration
	}
	executableDigest, executableSize, err := hashPrivate(c.ExecutableFile, 1<<30)
	if err != nil {
		return nil, err
	}
	applicationDigest, applicationSize, err := hashPrivate(c.ApplicationFile, 32<<20)
	if err != nil {
		return nil, err
	}
	if executableDigest != selected.BuildDigest || executableDigest != measured.BuildDigest || executableSize != selected.ArtifactSizeBytes ||
		applicationDigest != selected.ApplicationDigest || applicationDigest != measured.ApplicationDigest || applicationSize != selected.ApplicationSizeBytes {
		return nil, issuance.ErrInvalidConfiguration
	}
	if err := verifyRunningProcess(measured, selected.ArtifactSizeBytes); err != nil {
		return nil, err
	}
	driverDigest, _, err := hashPrivate(c.DriverFile, 1<<30)
	if err != nil {
		return nil, err
	}
	bootBytes, err := readPrivate(c.HostBootIDFile, 64)
	if err != nil {
		return nil, err
	}
	actualBoot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.ReplaceAll(strings.TrimSpace(string(actualBoot)), "-", "") != strings.TrimSpace(string(bootBytes)) {
		return nil, issuance.ErrInvalidConfiguration
	}
	seedHex, err := readPrivate(c.ConformanceSeedFile, 64)
	if err != nil {
		return nil, err
	}
	defer clear(seedHex)
	seed, err := hex.DecodeString(string(seedHex))
	if err != nil || len(seed) != ed25519.SeedSize || hex.EncodeToString(seed) != string(seedHex) {
		clear(seed)
		return nil, issuance.ErrInvalidConfiguration
	}
	defer clear(seed)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	reportBytes, err := readPrivate(c.RawReportFile, issuance.MaximumReportBytes)
	if err != nil {
		return nil, err
	}
	ownerBytes, err := readPrivate(c.OwnerObservationFile, 32<<10)
	if err != nil {
		return nil, err
	}
	var owner issuance.OwnerObservation
	if issuance.DecodeStrict(ownerBytes, &owner) != nil {
		return nil, issuance.ErrInvalidReport
	}
	report, _, err := issuance.DecodeReport(bytes.NewReader(reportBytes))
	if err != nil || report.OwnerObservation != owner {
		return nil, issuance.ErrInvalidReport
	}
	_, public, err := issuance.Issue(reportBytes, issuance.Config{
		Selection: selected, ReleaseRoots: releaseRoots, ObserverRoots: observerRoots, ConformanceKeyID: c.ConformanceKeyID, ConformancePrivateKey: private,
		RuntimeKeyID: c.RuntimeKeyID, RuntimePublicKey: runtimeKey, ExpectedMeasurement: measured,
		HostBootID: strings.TrimSpace(string(bootBytes)), DriverDigest: driverDigest, Now: now, Lifetime: time.Duration(c.LifetimeSeconds) * time.Second,
	})
	return public, err
}

func processStart(pid uint32) (uint64, error) {
	if pid == 0 {
		return 0, issuance.ErrInvalidConfiguration
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, issuance.ErrInvalidConfiguration
	}
	defer f.Close()
	encoded, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(encoded) > 4096 {
		return 0, issuance.ErrInvalidConfiguration
	}
	end := bytes.LastIndexByte(encoded, ')')
	if end < 0 {
		return 0, issuance.ErrInvalidConfiguration
	}
	fields := strings.Fields(string(encoded[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return 0, issuance.ErrInvalidConfiguration
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return 0, issuance.ErrInvalidConfiguration
	}
	return start, nil
}

func verifyRunningProcess(m issuance.Measurement, size uint64) error {
	start, err := processStart(m.ProcessID)
	if err != nil || start != m.ProcessStartTimeTicks {
		return issuance.ErrInvalidConfiguration
	}
	// /proc/PID/exe is the one intentional symlink: the kernel owns its target.
	// Operator-controlled paths still go through privateOpen with O_NOFOLLOW.
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", m.ProcessID))
	if err != nil {
		return issuance.ErrInvalidConfiguration
	}
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(int(f.Fd()), &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Geteuid()) || before.Mode&0077 != 0 || before.Nlink != 1 || before.Size < 1 || uint64(before.Size) != size || size > 1<<30 {
		return issuance.ErrInvalidConfiguration
	}
	h := sha256.New()
	read, err := io.Copy(h, io.LimitReader(f, int64(size)+1))
	if err != nil || uint64(read) != size || unix.Fstat(int(f.Fd()), &after) != nil || !sameInput(before, after) || fmt.Sprintf("sha256:%x", h.Sum(nil)) != m.BuildDigest {
		return issuance.ErrInvalidConfiguration
	}
	current, err := processStart(m.ProcessID)
	if err != nil || current != start {
		return issuance.ErrInvalidConfiguration
	}
	return nil
}

func readRoots(path, role string) (map[string]ed25519.PublicKey, error) {
	encoded, err := readPrivate(path, issuance.MaximumReportBytes)
	if err != nil {
		return nil, err
	}
	var document roleRoots
	if issuance.DecodeStrict(encoded, &document) != nil || document.SchemaVersion != 1 || document.TrustDomain != role || len(document.Roots) == 0 || len(document.Roots) > 64 {
		return nil, issuance.ErrInvalidConfiguration
	}
	roots := make(map[string]ed25519.PublicKey, len(document.Roots))
	for _, root := range document.Roots {
		key, err := base64.StdEncoding.Strict().DecodeString(root.PublicKey)
		if err != nil || root.Algorithm != "ed25519" || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != root.PublicKey {
			return nil, issuance.ErrInvalidConfiguration
		}
		if _, found := roots[root.KeyID]; found {
			return nil, issuance.ErrInvalidConfiguration
		}
		for _, existing := range roots {
			if bytes.Equal(existing, key) {
				return nil, issuance.ErrInvalidConfiguration
			}
		}
		roots[root.KeyID] = key
	}
	return roots, nil
}

func privateOpen(path string) (*os.File, unix.Stat_t, error) {
	var stat unix.Stat_t
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return nil, stat, issuance.ErrInvalidConfiguration
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, stat, issuance.ErrInvalidConfiguration
	}
	file := os.NewFile(uintptr(fd), "private-input")
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 || stat.Nlink != 1 {
		_ = file.Close()
		return nil, stat, issuance.ErrInvalidConfiguration
	}
	return file, stat, nil
}

func readPrivate(path string, maximum int64) ([]byte, error) {
	f, before, err := privateOpen(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if before.Size < 1 || before.Size > maximum {
		return nil, issuance.ErrInvalidConfiguration
	}
	encoded, err := io.ReadAll(io.LimitReader(f, maximum+1))
	var after unix.Stat_t
	if err != nil || int64(len(encoded)) != before.Size || unix.Fstat(int(f.Fd()), &after) != nil || !sameInput(before, after) {
		clear(encoded)
		return nil, issuance.ErrInvalidConfiguration
	}
	return encoded, nil
}

func hashPrivate(path string, maximum int64) (string, uint64, error) {
	f, before, err := privateOpen(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	if before.Size < 1 || before.Size > maximum {
		return "", 0, issuance.ErrInvalidConfiguration
	}
	h := sha256.New()
	size, err := io.Copy(h, io.LimitReader(f, maximum+1))
	var after unix.Stat_t
	if err != nil || size != before.Size || unix.Fstat(int(f.Fd()), &after) != nil || !sameInput(before, after) {
		return "", 0, issuance.ErrInvalidConfiguration
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil)), uint64(size), nil
}

func sameInput(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Uid == b.Uid && a.Gid == b.Gid &&
		a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func retain(path string, payload []byte) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) || len(payload) == 0 || len(payload) > issuance.MaximumReportBytes {
		return issuance.ErrInvalidConfiguration
	}
	parent, name := filepath.Dir(path), filepath.Base(path)
	dir, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	var st unix.Stat_t
	if unix.Fstat(dir, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		return issuance.ErrInvalidConfiguration
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	stage := ".native-evidence-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(dir, stage, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "issued-evidence")
	defer func() { _ = f.Close(); _ = unix.Unlinkat(dir, stage, 0) }()
	if _, err := f.Write(payload); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := unix.Renameat2(dir, stage, dir, name, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return unix.Fsync(dir)
}
