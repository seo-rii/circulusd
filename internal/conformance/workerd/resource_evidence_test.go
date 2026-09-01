package workerd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/conformance"
)

func sampleResourceEvidenceEnvelope() resourceEvidenceEnvelope {
	digest := func(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
	return resourceEvidenceEnvelope{
		RunID:              strings.Repeat("7", 32),
		StartedAt:          time.Unix(1_700_000_000, 0).UTC(),
		FinishedAt:         time.Unix(1_700_000_030, 0).UTC(),
		RunnerBinary:       digest("1"),
		SourceDigest:       digest("2"),
		FixtureDigest:      digest("3"),
		ProbeInventory:     digest("4"),
		ReleaseManifest:    digest("5"),
		ReleaseStatus:      "development",
		Architecture:       "x86_64",
		ArchiveDigest:      digest("6"),
		ExtractionRecipe:   "gzip-single-file-v1",
		ExecutableDigest:   digest("7"),
		WorkerdVersion:     "workerd 2026-08-25",
		ConfigDigest:       digest("8"),
		EnvironmentDigest:  digest("9"),
		Kernel:             "6.18.0-microsoft-standard-WSL2",
		HostBootID:         strings.Repeat("a", 32),
		AgentInstanceID:    strings.Repeat("b", 32),
		CgroupRootDevice:   64,
		CgroupRootInode:    4096,
		EnabledControllers: []string{"cpu", "memory", "pids"},
		Limits: resourceQualificationLimits{
			CPUMaxQuotaMicros: 50000, CPUMaxPeriodMicros: 100000,
			MemoryMaxBytes: 1073741824, MemorySwapMaxBytes: 0, PIDsMax: 128,
		},
		ColdStartSamples: 5,
		Probes: []resourceProbeObservation{
			{Component: "workerd.rss-cold-start", Status: conformance.Pass, StartedAt: time.Unix(1_700_000_001, 0).UTC(), FinishedAt: time.Unix(1_700_000_006, 0).UTC(), RawSampleCount: 5},
			{Component: "workerd.cpu-limit", Status: conformance.Fail, Reason: "workerd does not enforce cpuMs", StartedAt: time.Unix(1_700_000_007, 0).UTC(), FinishedAt: time.Unix(1_700_000_012, 0).UTC()},
		},
		CleanupComplete: true,
	}
}

func TestResourceEvidenceEnvelopeEncodesCanonicalCBORWithStableDigest(t *testing.T) {
	t.Parallel()
	envelope := sampleResourceEvidenceEnvelope()
	encoded, digest, err := encodeResourceEvidenceEnvelope(envelope)
	if err != nil {
		t.Fatalf("encodeResourceEvidenceEnvelope() error = %v", err)
	}
	if !strings.HasPrefix(digest, "sha256:") || len(encoded) == 0 {
		t.Fatalf("encode = %d bytes, digest %q", len(encoded), digest)
	}
	secondEncoded, secondDigest, err := encodeResourceEvidenceEnvelope(envelope)
	if err != nil {
		t.Fatalf("re-encode error = %v", err)
	}
	if digest != secondDigest || string(encoded) != string(secondEncoded) {
		t.Fatal("envelope encoding is not deterministic")
	}
	decoded, err := canonical.Decode(encoded, canonical.DefaultOptions())
	if err != nil {
		t.Fatalf("decode canonical envelope error = %v", err)
	}
	envelopeMap, ok := decoded.(canonical.Map)
	if !ok {
		t.Fatalf("decoded envelope is %T, want canonical.Map", decoded)
	}
	if envelopeMap["runId"] != envelope.RunID {
		t.Fatalf("decoded runId = %v, want %q", envelopeMap["runId"], envelope.RunID)
	}
	probes, ok := envelopeMap["probes"].(canonical.Array)
	if !ok || len(probes) != 2 {
		t.Fatalf("decoded probes = %#v, want two ordered probe records", envelopeMap["probes"])
	}
	first, _ := probes[0].(canonical.Map)
	if first["component"] != "workerd.cpu-limit" {
		t.Fatalf("probes are not canonical-name sorted: first = %v", first["component"])
	}
}

func TestResourceEvidenceEnvelopeRejectsMalformedFields(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*resourceEvidenceEnvelope){
		"empty run id":      func(e *resourceEvidenceEnvelope) { e.RunID = "" },
		"bad runner digest": func(e *resourceEvidenceEnvelope) { e.RunnerBinary = "deadbeef" },
		"finish before start": func(e *resourceEvidenceEnvelope) {
			e.FinishedAt = e.StartedAt.Add(-time.Second)
		},
		"no probes":            func(e *resourceEvidenceEnvelope) { e.Probes = nil },
		"bad architecture":     func(e *resourceEvidenceEnvelope) { e.Architecture = "MIPS" },
		"duplicate controller": func(e *resourceEvidenceEnvelope) { e.EnabledControllers = []string{"cpu", "cpu"} },
	} {
		t.Run(name, func(t *testing.T) {
			envelope := sampleResourceEvidenceEnvelope()
			mutate(&envelope)
			if _, _, err := encodeResourceEvidenceEnvelope(envelope); !errors.Is(err, errResourceEvidenceInvalid) {
				t.Fatalf("encodeResourceEvidenceEnvelope(%s) error = %v, want invalid evidence", name, err)
			}
		})
	}
}

func newPrivateEvidenceDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "evidence-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestRetainResourceEvidenceWritesAtomicallyAndRevalidates(t *testing.T) {
	t.Parallel()
	directory := newPrivateEvidenceDirectory(t)
	envelope := sampleResourceEvidenceEnvelope()
	encoded, digest, err := encodeResourceEvidenceEnvelope(envelope)
	if err != nil {
		t.Fatalf("encode error = %v", err)
	}
	path := filepath.Join(directory, resourceObservationArtifactName)
	retainedDigest, err := retainResourceEvidence(directory, resourceObservationArtifactName, encoded)
	if err != nil {
		t.Fatalf("retainResourceEvidence() error = %v", err)
	}
	if retainedDigest != digest {
		t.Fatalf("retained digest = %q, want %q", retainedDigest, digest)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat retained evidence error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("retained evidence mode = %v, want 0600", info.Mode().Perm())
	}
	stored, err := os.ReadFile(path)
	if err != nil || string(stored) != string(encoded) {
		t.Fatalf("retained bytes differ from the encoded envelope: %v", err)
	}
}

func TestRetainResourceEvidenceNeverClobbersExistingArtifact(t *testing.T) {
	t.Parallel()
	directory := newPrivateEvidenceDirectory(t)
	_, _, _ = encodeResourceEvidenceEnvelope(sampleResourceEvidenceEnvelope())
	first := []byte("first-evidence-payload")
	if _, err := retainResourceEvidence(directory, resourceObservationArtifactName, first); err != nil {
		t.Fatalf("first retention error = %v", err)
	}
	second := []byte("second-evidence-payload")
	if _, err := retainResourceEvidence(directory, resourceObservationArtifactName, second); !errors.Is(err, errResourceEvidenceExists) {
		t.Fatalf("second retention error = %v, want no-clobber refusal", err)
	}
	stored, err := os.ReadFile(filepath.Join(directory, resourceObservationArtifactName))
	if err != nil || string(stored) != string(first) {
		t.Fatalf("existing artifact was mutated: %q, %v", stored, err)
	}
	staging, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(staging) != 1 {
		t.Fatalf("directory holds %d entries, want only the retained artifact (no staging leak)", len(staging))
	}
}

func TestRetainResourceEvidenceRejectsUnsafeDirectory(t *testing.T) {
	t.Parallel()
	if _, err := retainResourceEvidence("relative", resourceObservationArtifactName, []byte("x")); err == nil {
		t.Fatal("retainResourceEvidence(relative dir) = nil, want rejection")
	}
	directory := newPrivateEvidenceDirectory(t)
	if err := os.Chmod(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := retainResourceEvidence(directory, resourceObservationArtifactName, []byte("x")); !errors.Is(err, errResourceEvidenceInvalid) {
		t.Fatalf("retainResourceEvidence(group-writable dir) error = %v, want invalid evidence directory", err)
	}
}
