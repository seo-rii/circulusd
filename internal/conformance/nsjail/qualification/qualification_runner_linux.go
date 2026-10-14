//go:build linux

// Package qualification runs the live NsJail isolation qualification on a
// provisioned dedicated host. RunQualification launches a preprovisioned,
// signed fixture described by a qualification config file and returns a
// conformance report. It installs nothing, and its result is historical
// evidence, not a startup grant.
//
// The only caller is TestProvisionedNsJailQualification. It runs when
// CIRCULUSD_NSJAIL_QUALIFICATION_CONFIG names the config file and is skipped
// otherwise.
package qualification

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hancomac/circulusd/internal/conformance"
	gate "github.com/hancomac/circulusd/internal/conformance/nsjail"
	"github.com/hancomac/circulusd/internal/conformance/nsjail/fixture"
	"golang.org/x/sys/unix"
)

type qualificationHost struct {
	RunID        string            `json:"runId"`
	BootID       string            `json:"bootId"`
	Kernel       string            `json:"kernel"`
	RunnerDigest string            `json:"runnerDigest"`
	Namespaces   map[string]string `json:"namespaces"`
}
type qualificationObservations struct {
	Jail              fixture.Observation      `json:"jail"`
	WorkspaceReadback string                   `json:"workspaceReadback"`
	Child             fixture.ChildObservation `json:"child"`
	CancelResult      bool                     `json:"cancelResult"`
	ChildReaped       bool                     `json:"childReaped"`
	Cgroups           map[string]string        `json:"cgroups"`
	CleanupComplete   bool                     `json:"cleanupComplete"`
	Experiments       []experimentObservation  `json:"experiments"`
}
type qualificationEvidence struct {
	SchemaVersion     int                       `json:"schemaVersion"`
	Host              qualificationHost         `json:"host"`
	StartedAt         time.Time                 `json:"startedAt"`
	FinishedAt        time.Time                 `json:"finishedAt"`
	ConfigDigest      string                    `json:"configDigest"`
	ReleaseDigest     string                    `json:"releaseDigest"`
	BinaryDigest      string                    `json:"binaryDigest"`
	EnvironmentDigest string                    `json:"environmentDigest"`
	ReferenceOnly     bool                      `json:"referenceOnly"`
	Observations      qualificationObservations `json:"observations"`
	Results           []conformance.Result      `json:"results"`
}
type qualificationSession interface {
	Observe(context.Context, string) ([]byte, error)
	ReadWorkspace(string) (string, error)
	ReadCgroups() (map[string]string, error)
	CancelProbe(context.Context, string) (fixture.ChildObservation, bool, bool, error)
	Experiment(context.Context, string, string) (experimentObservation, error)
	Destroy(context.Context) error
}
type qualificationDependencies struct {
	resolve   func(qualificationConfig) (qualificationRelease, error)
	host      func() (qualificationHost, error)
	preflight func(qualificationConfig) (func() error, error)
	start     func(context.Context, qualificationRelease) (qualificationSession, error)
	retain    func(string, string, []byte) error
}

// RunQualification launches only a preprovisioned, signed dedicated fixture.
// It does not install anything, provision cgroups, or qualify an offline install
// or a durable application turn. The result is historical evidence, never a
// startup grant. Every enforcement experiment requires fresh kernel observations.
func RunQualification(ctx context.Context, configPath string) conformance.Report {
	return runQualification(ctx, configPath, qualificationDependencies{resolve: resolveQualificationRelease, host: captureQualificationHost, preflight: preflightQualificationRoots, start: startQualificationSession, retain: retainQualificationEvidence}, false)
}

// Every dependency-injected run is structurally reference-only. Tests cannot
// accidentally promote a fake subprocess into external evidence through this
// entry point.
func runReferenceQualification(ctx context.Context, path string, deps qualificationDependencies) conformance.Report {
	return runQualification(ctx, path, deps, true)
}

func uniformQualificationReport(status conformance.Status, reason string, reference bool) conformance.Report {
	out := conformance.Report{SchemaVersion: 1, Results: []conformance.Result{}}
	for _, check := range gate.RequiredChecks() {
		e := conformance.Evidence{Class: conformance.EvidenceClassExternal, ArtifactReferences: []conformance.ArtifactReference{}}
		if reference {
			e.Class = conformance.EvidenceClassReferenceOnly
			e.Mock = true
		}
		out.Results = append(out.Results, conformance.Result{Component: check.Component, Status: status, Reason: reason, Evidence: e})
	}
	return out
}

func runQualification(ctx context.Context, path string, deps qualificationDependencies, reference bool) conformance.Report {
	fail := func(reason string) conformance.Report {
		return uniformQualificationReport(conformance.Fail, reason, reference)
	}
	if ctx == nil {
		return fail("qualification context is required")
	}
	if err := ctx.Err(); err != nil {
		return uniformQualificationReport(conformance.NotRun, "qualification canceled before preflight", reference)
	}
	raw, err := readQualificationFile(path, maximumQualificationDocument, false)
	if err != nil {
		status := conformance.Fail
		if errors.Is(err, os.ErrNotExist) {
			status = conformance.Unavailable
		}
		return uniformQualificationReport(status, "qualification config unavailable or unsafe", reference)
	}
	c, err := parseQualificationConfig(raw)
	if err != nil {
		return fail("invalid qualification config: " + err.Error())
	}
	release, err := deps.resolve(c)
	if err != nil {
		status := conformance.Fail
		if errors.Is(err, os.ErrNotExist) {
			status = conformance.Unavailable
		}
		return uniformQualificationReport(status, "signed qualification artifacts unavailable or invalid: "+err.Error(), reference)
	}
	if !canonicalDigest(release.binaryDigest) || !canonicalDigest(release.environmentDigest) || !canonicalDigest(release.manifestDigest) {
		return fail("release identity is incomplete")
	}
	unlock, err := deps.preflight(c)
	if err != nil {
		return uniformQualificationReport(conformance.Unavailable, "dedicated root preflight failed: "+err.Error(), reference)
	}
	defer unlock()
	host, err := deps.host()
	if err != nil {
		return fail("cannot capture qualification host identity")
	}
	if !validRunIdentity(host.RunID) || host.BootID == "" || host.Kernel == "" || !canonicalDigest(host.RunnerDigest) || len(host.Namespaces) != len(fixture.NamespaceNames) {
		return fail("qualification host identity is incomplete")
	}
	for _, n := range fixture.NamespaceNames {
		if !validNamespace(host.Namespaces[n], n) {
			return fail("qualification host namespace is invalid")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.TotalMillis)*time.Millisecond)
	defer cancel()
	started := time.Now().UTC()
	observations := qualificationObservations{Cgroups: map[string]string{}}
	session, runErr := deps.start(ctx, release)
	if session != nil {
		if runErr == nil {
			stepCtx, cancel := context.WithTimeout(ctx, time.Duration(c.StepMillis)*time.Millisecond)
			observationRaw, e := session.Observe(stepCtx, host.RunID)
			cancel()
			runErr = e
			if runErr == nil {
				runErr = decodeQualificationObservation(observationRaw, &observations.Jail)
			}
			if runErr == nil {
				observations.WorkspaceReadback, runErr = session.ReadWorkspace(host.RunID)
			}
			if runErr == nil {
				observations.Cgroups, runErr = session.ReadCgroups()
			}
			if runErr == nil {
				stepCtx, cancel := context.WithTimeout(ctx, time.Duration(c.StepMillis)*time.Millisecond)
				observations.Child, observations.CancelResult, observations.ChildReaped, runErr = session.CancelProbe(stepCtx, host.RunID)
				cancel()
			}
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Duration(c.CleanupMillis)*time.Millisecond)
		cleanupErr := session.Destroy(cleanupCtx)
		cancel()
		observations.CleanupComplete = cleanupErr == nil
		if cleanupErr != nil {
			runErr = errors.Join(runErr, fmt.Errorf("qualification cleanup failed: %w", cleanupErr))
		}
	} else if runErr == nil {
		runErr = errors.New("launcher returned no owned session")
	}
	if runErr == nil {
		for _, kind := range []string{"seccomp", "cpu", "memory", "pids"} {
			fresh, startErr := deps.start(ctx, release)
			var experiment experimentObservation
			if fresh != nil {
				if startErr == nil {
					stepCtx, stop := context.WithTimeout(ctx, time.Duration(c.StepMillis)*time.Millisecond)
					experiment, startErr = fresh.Experiment(stepCtx, host.RunID, kind)
					stop()
				}
				cleanupCtx, stop := context.WithTimeout(context.Background(), time.Duration(c.CleanupMillis)*time.Millisecond)
				cleanupErr := fresh.Destroy(cleanupCtx)
				stop()
				experiment.CleanupComplete = cleanupErr == nil
				if cleanupErr != nil {
					observations.CleanupComplete = false
					startErr = errors.Join(startErr, fmt.Errorf("experiment cleanup failed: %w", cleanupErr))
				}
			} else if startErr == nil {
				startErr = errors.New("experiment launcher returned no owned session")
			}
			observations.Experiments = append(observations.Experiments, experiment)
			if startErr != nil {
				runErr = fmt.Errorf("%s enforcement experiment: %w", kind, startErr)
				break
			}
		}
	}
	results := evaluateQualificationObservations(host, c, observations)
	if runErr != nil {
		results = uniformQualificationReport(conformance.Fail, "qualification did not complete: "+runErr.Error(), reference).Results
	}
	envelope := qualificationEvidence{SchemaVersion: 1, Host: host, StartedAt: started, FinishedAt: time.Now().UTC(), ConfigDigest: digestBytes(raw), ReleaseDigest: release.manifestDigest, BinaryDigest: release.binaryDigest, EnvironmentDigest: release.environmentDigest, ReferenceOnly: reference, Observations: observations, Results: results}
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) > maximumQualificationDocument {
		return fail("qualification evidence exceeds bounds")
	}
	name := "nsjail-" + host.RunID + ".json"
	if err := deps.retain(c.EvidenceOutputDirectory, name, encoded); err != nil {
		return fail("qualification evidence retention failed")
	}
	artifact := conformance.ArtifactReference{Name: name, Digest: digestBytes(encoded)}
	for i := range results {
		results[i].Evidence = conformance.Evidence{Class: conformance.EvidenceClassExternal, Version: release.version, BinaryDigest: release.binaryDigest, EnvironmentDigest: release.environmentDigest, Kernel: host.Kernel, Architecture: map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH], ArtifactReferences: []conformance.ArtifactReference{artifact}}
		if reference {
			results[i].Evidence.Class = conformance.EvidenceClassReferenceOnly
			results[i].Evidence.Mock = true
			results[i].Evidence.BinaryDigest = ""
			results[i].Evidence.EnvironmentDigest = ""
		}
	}
	return conformance.Report{SchemaVersion: 1, Results: results}
}

func validRunIdentity(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 16 && s == hex.EncodeToString(b)
}
func validNamespace(s, name string) bool {
	prefix := name + ":["
	if !strings.HasPrefix(s, prefix) || !strings.HasSuffix(s, "]") {
		return false
	}
	n, e := strconv.ParseUint(s[len(prefix):len(s)-1], 10, 64)
	return e == nil && n > 0
}
func evaluateQualificationObservations(host qualificationHost, c qualificationConfig, o qualificationObservations) []conformance.Result {
	results := uniformQualificationReport(conformance.Fail, "missing or inconsistent raw observation", false).Results
	passed := func(component string, ok bool) {
		for i := range results {
			if results[i].Component == component && ok {
				results[i].Status = conformance.Pass
				results[i].Reason = ""
			}
		}
	}
	if o.Jail.SchemaVersion != 1 || o.Jail.RunID != host.RunID || len(o.Jail.Namespaces) != 6 || len(o.Jail.Status) != 7 || len(o.Jail.WriteErrnos) != 4 || len(o.Jail.HiddenPathErrnos) != 5 {
		return results
	}
	different := true
	for _, name := range fixture.NamespaceNames {
		different = different && validNamespace(o.Jail.Namespaces[name], name) && o.Jail.Namespaces[name] != host.Namespaces[name]
	}
	passed("nsjail.namespace", different)
	mapping := func(s string, id uint32) bool {
		return strings.Join(strings.Fields(s), " ") == fmt.Sprintf("0 %d 1", id)
	}
	passed("nsjail.unique-uid", mapping(o.Jail.UIDMap, c.HostUID) && mapping(o.Jail.GIDMap, c.HostGID))
	rootDenied, hasRoot := o.Jail.WriteErrnos["/"]
	workspace, hasWorkspace := o.Jail.WriteErrnos["/workspace"]
	scratch, hasScratch := o.Jail.WriteErrnos["/scratch"]
	tmp, hasTmp := o.Jail.WriteErrnos["/tmp"]
	passed("nsjail.read-only-rootfs", hasRoot && rootDenied == int(unix.EROFS) && o.Jail.RootMountFlags&unix.ST_RDONLY != 0)
	passed("nsjail.workspace-roundtrip", hasRoot && hasWorkspace && hasScratch && hasTmp && rootDenied == int(unix.EROFS) && workspace == 0 && scratch == 0 && tmp == 0 && o.WorkspaceReadback == host.RunID)
	hidden := true
	for _, path := range fixture.HiddenPaths {
		errno, ok := o.Jail.HiddenPathErrnos[path]
		hidden = hidden && ok && errno == int(unix.ENOENT)
	}
	passed("nsjail.host-path-invisibility", hidden)
	passed("nsjail.no-new-privileges", o.Jail.Status["NoNewPrivs"] == "1")
	caps := true
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		s, ok := o.Jail.Status[key]
		n, e := strconv.ParseUint(s, 16, 64)
		caps = caps && ok && e == nil && n == 0
	}
	passed("nsjail.capability-drop", caps)
	passed("nsjail.network-deny", len(o.Jail.Interfaces) == 1 && o.Jail.Interfaces[0] == "lo" && o.Jail.NetworkErrno == int(unix.ENETUNREACH) && o.Jail.Namespaces["net"] != host.Namespaces["net"])
	passed("nsjail.sandboxd-uds", o.Jail.ControlErrno == 0 && hidden)
	passed("nsjail.process-cancel", o.Child.SchemaVersion == 1 && o.Child.RunID == host.RunID && o.Child.PID > 1 && o.Child.StartTime != "" && o.CancelResult && o.ChildReaped)
	passed("nsjail.destroy-cleanup", o.CleanupComplete)
	seccomp, cgroupPressure := evaluateEnforcementExperiments(host.RunID, o.Experiments)
	passed("nsjail.seccomp", o.Jail.Status["Seccomp"] == "2" && seccomp)
	applied := o.Cgroups["memory.max"] == "536870912" && o.Cgroups["memory.swap.max"] == "0" && o.Cgroups["pids.max"] == "64" && validCPUQuota(o.Cgroups["cpu.max"]) && o.Cgroups["cgroup.procs"] != ""
	passed("nsjail.cgroup-limits", applied && cgroupPressure)
	return results
}

func captureQualificationHost() (qualificationHost, error) {
	h := qualificationHost{Namespaces: map[string]string{}}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return h, err
	}
	h.RunID = hex.EncodeToString(id[:])
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return h, err
	}
	h.BootID = strings.TrimSpace(string(boot))
	var name unix.Utsname
	if err := unix.Uname(&name); err != nil {
		return h, err
	}
	h.Kernel = unix.ByteSliceToString(name.Release[:])
	binary, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return h, err
	}
	h.RunnerDigest = digestBytes(binary)
	for _, name := range fixture.NamespaceNames {
		value, err := os.Readlink("/proc/self/ns/" + name)
		if err != nil {
			return h, err
		}
		h.Namespaces[name] = value
	}
	return h, nil
}

func preflightQualificationRoots(c qualificationConfig) (func() error, error) {
	opened := []int{}
	closeAll := func() error {
		var err error
		for _, fd := range opened {
			err = errors.Join(err, unix.Close(fd))
		}
		return err
	}
	failed := true
	defer func() {
		if failed {
			_ = closeAll()
		}
	}()
	for _, path := range []string{c.SandboxRoot, c.CgroupRoot, c.EvidenceOutputDirectory} {
		fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			return nil, err
		}
		opened = append(opened, fd)
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return nil, err
		}
		if st.Uid != uint32(os.Geteuid()) || st.Mode&0o777 != 0o700 {
			return nil, errors.New("dedicated roots must be current-owner mode 0700")
		}
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return nil, errors.New("dedicated root already in use")
		}
		var entries []os.DirEntry
		if path != c.EvidenceOutputDirectory {
			entries, err = readQualificationDirectory(path, 128)
			if err != nil {
				return nil, err
			}
		}
		if path == c.SandboxRoot && len(entries) != 0 {
			return nil, errors.New("sandbox root is not empty")
		}
		if path == c.CgroupRoot {
			var fs unix.Statfs_t
			if err := unix.Fstatfs(fd, &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
				return nil, errors.New("delegated root is not cgroup v2")
			}
			for _, entry := range entries {
				if entry.IsDir() {
					return nil, errors.New("delegated cgroup has existing children")
				}
			}
			for _, name := range []string{"cgroup.procs", "cgroup.subtree_control", "cgroup.controllers"} {
				raw, err := os.ReadFile(filepath.Join(path, name))
				if err != nil {
					return nil, err
				}
				if name == "cgroup.procs" && strings.TrimSpace(string(raw)) != "" {
					return nil, errors.New("delegated cgroup contains processes")
				}
				if name != "cgroup.procs" {
					fields := strings.Fields(string(raw))
					sort.Strings(fields)
					for _, required := range []string{"cpu", "memory", "pids"} {
						found := false
						for _, f := range fields {
							found = found || f == required
						}
						if !found {
							return nil, errors.New("delegated cgroup lacks enabled cpu/memory/pids controllers")
						}
					}
				}
			}
		}
	}
	failed = false
	return closeAll, nil
}

func retainQualificationEvidence(directory, name string, raw []byte) error {
	if len(raw) > maximumQualificationDocument || !strings.HasPrefix(name, "nsjail-") || filepath.Base(name) != name {
		return errors.New("invalid evidence artifact")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, directory, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil || status.Uid != uint32(os.Geteuid()) || status.Mode&0o777 != 0o700 {
		return errors.New("unsafe evidence directory")
	}
	stage := "." + name + ".staging"
	fileFD, err := unix.Openat(fd, stage, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(fd, stage, 0)
	file := os.NewFile(uintptr(fileFD), "nsjail-evidence")
	count, writeErr := file.Write(raw)
	if writeErr == nil && count != len(raw) {
		writeErr = errors.New("short evidence write")
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := unix.Renameat2(fd, stage, fd, name, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		return err
	}
	readFD, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	readFile := os.NewFile(uintptr(readFD), "nsjail-evidence-readback")
	defer readFile.Close()
	retained, err := io.ReadAll(io.LimitReader(readFile, maximumQualificationDocument+1))
	if err != nil || digestBytes(retained) != digestBytes(raw) {
		return errors.New("evidence readback mismatch")
	}
	return nil
}

func decodeQualificationObservation(raw []byte, target *fixture.Observation) error {
	if err := strictQualificationJSON(raw, target); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for _, name := range []string{"schemaVersion", "runId", "namespaces", "uidMap", "gidMap", "status", "rootMountFlags", "writeErrnos", "hiddenPathErrnos", "interfaces", "networkErrno", "controlErrno"} {
		if value, ok := fields[name]; !ok || string(value) == "null" {
			return errors.New("required observation field missing")
		}
	}
	// JSON null is accepted by encoding/json for an int map value and becomes
	// zero. Zero means a successful syscall here, so require actual integer
	// tokens for every nested errno instead of trusting that coercion.
	for field, required := range map[string][]string{"writeErrnos": {"/", "/workspace", "/scratch", "/tmp"}, "hiddenPathErrnos": fixture.HiddenPaths} {
		var values map[string]json.RawMessage
		if err := json.Unmarshal(fields[field], &values); err != nil || len(values) != len(required) {
			return errors.New("invalid errno observation map")
		}
		for _, key := range required {
			value, ok := values[key]
			if !ok || string(value) == "null" {
				return errors.New("missing errno observation")
			}
			var errno int
			if err := json.Unmarshal(value, &errno); err != nil || errno < 0 || errno > 4095 {
				return errors.New("invalid errno observation")
			}
		}
	}
	return nil
}
func validCPUQuota(s string) bool {
	parts := strings.Fields(s)
	if len(parts) != 2 {
		return false
	}
	quota, e1 := strconv.ParseUint(parts[0], 10, 32)
	period, e2 := strconv.ParseUint(parts[1], 10, 32)
	return e1 == nil && e2 == nil && period > 0 && quota*2 == period
}
