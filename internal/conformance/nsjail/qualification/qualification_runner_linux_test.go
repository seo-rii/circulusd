//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/conformance"
	"github.com/hancomac/circulusd/internal/conformance/nsjail/fixture"
	"golang.org/x/sys/unix"
)

// This is the only live gate. Absence is a skip, never external PASS. The
// signed experiment profile and raw kernel observations must qualify all checks.
func TestProvisionedNsJailQualification(t *testing.T) {
	path := os.Getenv("CIRCULUSD_NSJAIL_QUALIFICATION_CONFIG")
	if path == "" {
		t.Skip("set CIRCULUSD_NSJAIL_QUALIFICATION_CONFIG only on a provisioned dedicated host")
	}
	report := RunQualification(t.Context(), path)
	complete := true
	for _, result := range report.Results {
		t.Logf("%s = %s (%s)", result.Component, result.Status, result.Reason)
		complete = complete && result.Status == conformance.Pass && result.Evidence.Class == conformance.EvidenceClassExternal && !result.Evidence.Mock
	}
	if !complete {
		t.Fatal("NsJail isolation remains unqualified; retained observations do not qualify offline install or durable application recovery")
	}
}

func validTestConfig() qualificationConfig {
	return qualificationConfig{SchemaVersion: 1, ReleaseManifestPath: "/q/release.json", TrustRootsPath: "/q/roots.json", InstalledNsJailPath: "/q/nsjail", EnvironmentInventoryPath: "/q/inventory.json", EnvironmentRoot: "/q/env", SandboxRoot: "/q/s", CgroupRoot: "/q/c", EvidenceOutputDirectory: "/q/e", HostUID: 400001, HostGID: 400001, SandboxdClientUID: 65534, CommandManifestOwnerUID: 65534, TotalMillis: 120000, StepMillis: 10000, CleanupMillis: 1000}
}
func testHost() qualificationHost {
	host := qualificationHost{RunID: strings.Repeat("a", 32), BootID: strings.Repeat("b", 32), Kernel: "qualification-test-kernel", RunnerDigest: digestBytes([]byte("runner")), Namespaces: map[string]string{}}
	for _, name := range fixture.NamespaceNames {
		host.Namespaces[name] = name + ":[1]"
	}
	return host
}
func testObservations(c qualificationConfig) qualificationObservations {
	host := testHost()
	o := qualificationObservations{Jail: fixture.Observation{SchemaVersion: 1, RunID: host.RunID, Namespaces: map[string]string{}, UIDMap: "0 400001 1\n", GIDMap: "0 400001 1\n", Status: map[string]string{"NoNewPrivs": "1", "CapInh": "0000000000000000", "CapPrm": "0", "CapEff": "0", "CapBnd": "0", "CapAmb": "0", "Seccomp": "2"}, RootMountFlags: unix.ST_RDONLY, WriteErrnos: map[string]int{"/": int(unix.EROFS), "/workspace": 0, "/scratch": 0, "/tmp": 0}, HiddenPathErrnos: map[string]int{}, Interfaces: []string{"lo"}, NetworkErrno: int(unix.ENETUNREACH), ControlErrno: 0}, WorkspaceReadback: host.RunID, Child: fixture.ChildObservation{SchemaVersion: 1, RunID: host.RunID, PID: 10, StartTime: "1234"}, CancelResult: true, ChildReaped: true, Cgroups: map[string]string{"memory.max": "536870912", "memory.swap.max": "0", "pids.max": "64", "cpu.max": "500000 1000000", "cgroup.procs": "111"}, CleanupComplete: true, Experiments: testExperiments(host.RunID)}
	for _, name := range fixture.NamespaceNames {
		o.Jail.Namespaces[name] = name + ":[2]"
	}
	for _, path := range fixture.HiddenPaths {
		o.Jail.HiddenPathErrnos[path] = int(unix.ENOENT)
	}
	return o
}

type fakeQualificationSession struct {
	o                      qualificationObservations
	observeErr, destroyErr error
	destroyed              int
	cleanupLive            bool
	cancel                 context.CancelFunc
	raw                    []byte
	experimentErr          error
	experimentCancel       context.CancelFunc
}

func (s *fakeQualificationSession) Observe(context.Context, string) ([]byte, error) {
	if s.cancel != nil {
		s.cancel()
	}
	if s.raw != nil {
		return s.raw, s.observeErr
	}
	b, _ := json.Marshal(s.o.Jail)
	return b, s.observeErr
}
func (s *fakeQualificationSession) ReadWorkspace(string) (string, error) {
	return s.o.WorkspaceReadback, nil
}
func (s *fakeQualificationSession) ReadCgroups() (map[string]string, error) { return s.o.Cgroups, nil }
func (s *fakeQualificationSession) CancelProbe(context.Context, string) (fixture.ChildObservation, bool, bool, error) {
	return s.o.Child, s.o.CancelResult, s.o.ChildReaped, nil
}
func (s *fakeQualificationSession) Destroy(ctx context.Context) error {
	s.destroyed++
	s.cleanupLive = ctx.Err() == nil
	return s.destroyErr
}

func referenceFixture(t *testing.T) (string, qualificationDependencies, *fakeQualificationSession, *[]byte) {
	t.Helper()
	c := validTestConfig()
	encoded, _ := json.Marshal(c)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	session := &fakeQualificationSession{o: testObservations(c)}
	var retained []byte
	deps := qualificationDependencies{resolve: func(c qualificationConfig) (qualificationRelease, error) {
		return qualificationRelease{config: c, binaryDigest: digestBytes([]byte("binary")), environmentDigest: digestBytes([]byte("environment")), manifestDigest: digestBytes([]byte("manifest")), version: "1.0.0", inventory: environmentInventory{Experiments: fixture.RequiredExperiments()}}, nil
	}, host: func() (qualificationHost, error) { return testHost(), nil }, preflight: func(qualificationConfig) (func() error, error) { return func() error { return nil }, nil }, start: func(context.Context, qualificationRelease) (qualificationSession, error) { return session, nil }, retain: func(_, _ string, b []byte) error {
		if session.destroyed != 5 && session.destroyed != 1 {
			return errors.New("evidence precedes cleanup")
		}
		retained = append([]byte(nil), b...)
		return nil
	}}
	return path, deps, session, &retained
}

func TestReferenceRunnerExercisesLifecycleWithoutExternalPromotion(t *testing.T) {
	path, deps, session, retained := referenceFixture(t)
	report := runReferenceQualification(context.Background(), path, deps)
	if len(report.Results) != 13 || session.destroyed != 5 || !session.cleanupLive || len(*retained) == 0 {
		t.Fatalf("incomplete lifecycle: %#v", report)
	}
	counts := map[conformance.Status]int{}
	for _, result := range report.Results {
		counts[result.Status]++
		if result.Evidence.Class != conformance.EvidenceClassReferenceOnly || !result.Evidence.Mock || result.Evidence.BinaryDigest != "" || result.Evidence.EnvironmentDigest != "" || len(result.Evidence.ArtifactReferences) != 1 || result.Evidence.ArtifactReferences[0].Digest != digestBytes(*retained) {
			t.Fatalf("mock promoted or unbound evidence: %#v", result)
		}
	}
	if counts[conformance.Pass] != 13 || counts[conformance.Unavailable] != 0 {
		t.Fatalf("statuses=%v", counts)
	}
	var evidence qualificationEvidence
	if err := strictQualificationJSON(*retained, &evidence); err != nil {
		t.Fatal(err)
	}
	if !evidence.ReferenceOnly || !evidence.Observations.CleanupComplete || evidence.Host.RunID != testHost().RunID {
		t.Fatal("evidence lost identity or reference scope")
	}
}

func TestRunnerFailClosedBeforeLaunchAndOnObservationOrCleanupFailure(t *testing.T) {
	for _, name := range []string{"release mismatch", "root unavailable", "host mismatch", "observe error", "malformed", "missing scalar", "null errno", "cleanup failure", "retention failure", "partial start"} {
		t.Run(name, func(t *testing.T) {
			path, deps, session, _ := referenceFixture(t)
			expected := conformance.Fail
			starts := 0
			start := deps.start
			deps.start = func(c context.Context, r qualificationRelease) (qualificationSession, error) {
				starts++
				return start(c, r)
			}
			switch name {
			case "release mismatch":
				deps.resolve = func(qualificationConfig) (qualificationRelease, error) {
					return qualificationRelease{}, errors.New("digest mismatch")
				}
			case "root unavailable":
				deps.preflight = func(qualificationConfig) (func() error, error) { return nil, errors.New("not delegated") }
				expected = conformance.Unavailable
			case "host mismatch":
				deps.host = func() (qualificationHost, error) { h := testHost(); h.Namespaces["pid"] = ""; return h, nil }
			case "observe error":
				session.observeErr = errors.New("subprocess failed")
			case "malformed":
				session.raw = []byte(`{"passed":true}`)
			case "missing scalar":
				b, _ := json.Marshal(session.o.Jail)
				var fields map[string]json.RawMessage
				_ = json.Unmarshal(b, &fields)
				delete(fields, "controlErrno")
				session.raw, _ = json.Marshal(fields)
			case "null errno":
				b, _ := json.Marshal(session.o.Jail)
				session.raw = bytesReplace(b, `"/scratch":0`, `"/scratch":null`)
			case "cleanup failure":
				session.destroyErr = errors.New("cgroup remains")
			case "retention failure":
				deps.retain = func(string, string, []byte) error { return errors.New("disk full") }
			case "partial start":
				deps.start = func(context.Context, qualificationRelease) (qualificationSession, error) {
					starts++
					return session, errors.New("handshake failed")
				}
			}
			report := runReferenceQualification(context.Background(), path, deps)
			for _, result := range report.Results {
				if result.Status != expected {
					t.Fatalf("%s=%s", result.Component, result.Status)
				}
			}
			if name == "release mismatch" || name == "root unavailable" || name == "host mismatch" {
				if starts != 0 || session.destroyed != 0 {
					t.Fatal("preflight failure launched a process")
				}
			} else if session.destroyed != 5 && session.destroyed != 1 {
				t.Fatal("owned process was not cleaned exactly once")
			}
		})
	}
}

func TestRunnerCleanupOutlivesCanceledRequest(t *testing.T) {
	path, deps, session, _ := referenceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	session.cancel = cancel
	session.observeErr = context.Canceled
	report := runReferenceQualification(ctx, path, deps)
	if session.destroyed != 1 || !session.cleanupLive {
		t.Fatal("cleanup inherited cancellation")
	}
	for _, r := range report.Results {
		if r.Status == conformance.Pass {
			t.Fatal("canceled run passed")
		}
	}
}

func TestObservationsRejectActualIsolationRegressions(t *testing.T) {
	for _, tc := range []struct {
		name, component string
		mutate          func(*qualificationObservations)
	}{
		{"same namespace", "nsjail.namespace", func(o *qualificationObservations) { o.Jail.Namespaces["mnt"] = testHost().Namespaces["mnt"] }},
		{"wrong UID", "nsjail.unique-uid", func(o *qualificationObservations) { o.Jail.UIDMap = "0 0 1" }},
		{"writable root", "nsjail.read-only-rootfs", func(o *qualificationObservations) { o.Jail.WriteErrnos["/"] = 0 }},
		{"workspace not host backed", "nsjail.workspace-roundtrip", func(o *qualificationObservations) { o.WorkspaceReadback = "other" }},
		{"host exposed", "nsjail.host-path-invisibility", func(o *qualificationObservations) { o.Jail.HiddenPathErrnos["/root"] = 0 }},
		{"privileges", "nsjail.no-new-privileges", func(o *qualificationObservations) { o.Jail.Status["NoNewPrivs"] = "0" }},
		{"capability retained", "nsjail.capability-drop", func(o *qualificationObservations) { o.Jail.Status["CapAmb"] = "1" }},
		{"seccomp disabled", "nsjail.seccomp", func(o *qualificationObservations) { o.Jail.Status["Seccomp"] = "0" }},
		{"external route", "nsjail.network-deny", func(o *qualificationObservations) { o.Jail.NetworkErrno = 0 }},
		{"uncanceled child", "nsjail.process-cancel", func(o *qualificationObservations) { o.ChildReaped = false }},
		{"socket unreachable", "nsjail.sandboxd-uds", func(o *qualificationObservations) { o.Jail.ControlErrno = int(unix.ENOENT) }},
		{"cleanup incomplete", "nsjail.destroy-cleanup", func(o *qualificationObservations) { o.CleanupComplete = false }},
		{"limits missing", "nsjail.cgroup-limits", func(o *qualificationObservations) { delete(o.Cgroups, "pids.max") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validTestConfig()
			o := testObservations(c)
			tc.mutate(&o)
			for _, result := range evaluateQualificationObservations(testHost(), c, o) {
				if result.Component == tc.component && result.Status != conformance.Fail {
					t.Fatalf("regressed isolation passed: %#v", result)
				}
			}
		})
	}
}

func TestConfigAndEvidenceRejectAmbiguitySymlinksAndClobber(t *testing.T) {
	encoded, _ := json.Marshal(validTestConfig())
	for _, raw := range [][]byte{append([]byte(`{"schemaVersion":1,`), encoded[1:]...), append(encoded, []byte(` {}`)...), bytesReplace(encoded, `"schemaVersion":1`, `"schemaVersion":1,"passed":true`), bytesReplace(encoded, `"hostUid":400001`, `"hostUid":0`), bytesReplace(encoded, `"stepMillis":10000`, `"stepMillis":9999`), bytesReplace(encoded, `"sandboxRoot":"/q/s"`, `"sandboxRoot":"/q"`)} {
		if _, err := parseQualificationConfig(raw); err == nil {
			t.Fatalf("accepted invalid config: %s", raw)
		}
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "nsjail-" + strings.Repeat("a", 32) + ".json"
	first := []byte(`{"observation":1}`)
	if err := retainQualificationEvidence(dir, name, first); err != nil {
		t.Fatal(err)
	}
	if err := retainQualificationEvidence(dir, name, []byte("replace")); err == nil {
		t.Fatal("retained evidence overwritten")
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil || string(data) != string(first) {
		t.Fatal("evidence identity changed")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("staging evidence leaked")
	}
	if err := os.Symlink(dir, filepath.Join(t.TempDir(), "link")); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(input, encoded, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(input, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := readQualificationFile(input, maximumQualificationDocument, false); err == nil {
		t.Fatal("writable configuration trusted")
	}
}
func bytesReplace(b []byte, old, new string) []byte {
	return []byte(strings.Replace(string(b), old, new, 1))
}

func TestQualificationDirectoryTraversalBoundsEntriesDepthAndSymlinks(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := readQualificationDirectory(root, 2); err == nil {
		t.Fatal("directory entry limit ignored")
	}
	calls := 0
	if err := walkQualificationDirectory(root, 3, 2, func(string, os.DirEntry, error) error { calls++; return nil }); err == nil || calls > 3 {
		t.Fatalf("tree bound ignored: visits=%d error=%v", calls, err)
	}
	deep := filepath.Join(t.TempDir(), "a", "b", "c")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := walkQualificationDirectory(filepath.Dir(filepath.Dir(filepath.Dir(deep))), 10, 1, func(string, os.DirEntry, error) error { return nil }); err == nil {
		t.Fatal("directory depth limit ignored")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readQualificationDirectory(link, 10); err == nil {
		t.Fatal("directory symlink followed")
	}
}

func (s *fakeQualificationSession) Experiment(_ context.Context, run, kind string) (experimentObservation, error) {
	if s.experimentCancel != nil {
		s.experimentCancel()
	}
	if s.experimentErr != nil {
		return experimentObservation{}, s.experimentErr
	}
	for _, e := range s.o.Experiments {
		if e.Kind == kind {
			return e, nil
		}
	}
	return experimentObservation{}, errors.New("missing test experiment")
}
