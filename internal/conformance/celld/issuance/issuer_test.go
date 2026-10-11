package issuance

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/conformance/celld"
	"github.com/hancomac/circulusd/internal/dependency"
)

func authority(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
}
func d(value byte) string { return "sha256:" + strings.Repeat(string(value), 64) }

func qualifiedFixture(t *testing.T) (RawReport, Config, ed25519.PrivateKey) {
	t.Helper()
	releaseKey, observerKey, conformanceKey, runtimeKey := authority(1), authority(2), authority(3), authority(4)
	s := StorageSelection{SchemaVersion: 1, ReleaseVersion: "0.3.0-native", Architecture: "x86_64", CelldCommit: strings.Repeat("1", 40), ArtifactName: "celld-native", ArtifactSizeBytes: 1, ExtractionRecipe: "raw-executable-v1", BuildDigest: d('a'), ApplicationSizeBytes: 1, ApplicationDigest: d('b'), KeyID: "release-1", Algorithm: "ed25519"}
	selectionDigest, err := SelectionSigningDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	s.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(releaseKey, []byte(selectionDigest)))
	m := Measurement{SchemaVersion: 1, CelldCommit: s.CelldCommit, BuildDigest: s.BuildDigest, ApplicationDigest: s.ApplicationDigest, EffectiveConfigurationDigest: d('c'), InstanceID: "instance-1", TransactionDomainID: "domain-1", RuntimeKeyID: "runtime-1", RuntimePublicKey: base64.StdEncoding.EncodeToString(runtimeKey.Public().(ed25519.PublicKey)), ProbeEpoch: 3, ProcessID: 103, ProcessStartTimeTicks: 98765}
	c := Config{Selection: s, ReleaseRoots: map[string]ed25519.PublicKey{"release-1": releaseKey.Public().(ed25519.PublicKey)}, ObserverRoots: map[string]ed25519.PublicKey{"observer-1": observerKey.Public().(ed25519.PublicKey)}, ConformanceKeyID: "conformance-1", ConformancePrivateKey: conformanceKey, RuntimeKeyID: m.RuntimeKeyID, RuntimePublicKey: runtimeKey.Public().(ed25519.PublicKey), ExpectedMeasurement: m, HostBootID: strings.Repeat("2", 32), DriverDigest: d('d'), Now: time.Unix(1700000010, 0), Lifetime: time.Hour}
	r := RawReport{SchemaVersion: 1, Kind: "circulusd.native-storage-raw-report/v1", RunID: "run-1", StartedAtUnix: 1700000000, FinishedAtUnix: 1700000005, HostBootID: c.HostBootID, DriverDigest: c.DriverDigest, Measurement: m, ObserverKeyID: "observer-1", Algorithm: "ed25519"}
	r.CAS = CASFacts{Contenders: 32, Winners: 1, PreconditionFailures: 31, InitialETag: `"original-native-etag"`, CurrentETag: `"opaque-current-native-etag"`, StaleUpdateStatus: 412, DuplicateCreateStatus: 412, StaleDeleteStatus: 412, ExpectedDataDigest: d('e'), ObservedDataDigest: d('e'), FreshClientDataDigest: d('e')}
	r.Transaction = TransactionFacts{ObjectID: "qualification-1", CommandID: "command-1", BeforeRevision: 0, AcknowledgedRevision: 1, TokenRevision: 1, RequestDigest: d('1'), CommandDigest: d('2'), ResponseDigest: d('3'), CapabilityClaimsDigest: d('4'), ExpectedStateDigest: d('5'), ObservedStateDigest: d('5'), ReceiptRevision: 1, ReceiptCommandDigest: d('2'), ReceiptResponseDigest: d('3'), ReceiptCapabilityClaimsDigest: d('4'), BarrierRevision: 1, BarrierSerial: 1}
	r.ProcessFaults = []ProcessFault{
		{Kind: "sigkill-local-restart", BeforePID: 101, AfterPID: 102, Signal: 9, ExitSignal: 9, BeforeRootDigest: d('6'), AfterRootDigest: d('6'), BeforeEpoch: 1, AfterEpoch: 2, ObservedRevision: 1, ObservedStateDigest: d('5'), ReceiptCommandDigest: d('2'), ReceiptResponseDigest: d('3'), ReceiptCapabilityClaimsDigest: d('4')},
		{Kind: "sigkill-fresh-directory-recovery", BeforePID: 102, AfterPID: 103, Signal: 9, ExitSignal: 9, BeforeRootDigest: d('6'), AfterRootDigest: d('7'), BeforeEpoch: 2, AfterEpoch: 3, ObservedRevision: 1, ObservedStateDigest: d('5'), ReceiptCommandDigest: d('2'), ReceiptResponseDigest: d('3'), ReceiptCapabilityClaimsDigest: d('4')},
	}
	r.NativeOwnerFence = NativeOwnerFence{PriorEpoch: 2, CurrentEpoch: 3, PriorPID: 104, CurrentPID: 103, PriorProcessState: "running", LateWriteErrorCode: "stale-owner", Requests: 1, AcceptedLateWrites: 0, BeforeRevision: 1, AfterRevision: 1, ObservationDigest: d('8')}
	r.ResponseLoss = ResponseLossFacts{BackendStatus: 200, BackendRequests: 1, ReceivedBytes: 0, ClientErrorCode: "UNAVAILABLE", BarrierErrorCode: "NONE", EffectDispatchCount: 0}
	priorMeasurement := m
	priorMeasurement.ProcessID = 104
	priorMeasurement.ProcessStartTimeTicks = 43210
	priorMeasurement.ProbeEpoch = 2
	priorMeasurement.InstanceID = "prior-instance"
	priorRecord := OwnershipRecord{Body: base64.StdEncoding.EncodeToString([]byte(`{"node":"native-owner-A","epoch":91}`)), ETag: `"owner-A-etag"`}
	currentRecord := OwnershipRecord{Body: base64.StdEncoding.EncodeToString([]byte(`{"node":"native-owner-B","epoch":92}`)), ETag: `"owner-B-etag"`}
	r.OwnerObservation = OwnerObservation{SchemaVersion: 1, Kind: "circulusd.native-owner-observation/v1", ObjectID: "qualification-1", CellID: "native-cell-1", OwnershipKeyDigest: d('c'), LTXKeyDigest: d('c'), LTXBodyDigest: d('d'), LTXPutStatus: 200, LTXPutCompletedSequence: 2, OwnershipGetStartedSequence: 3, OwnershipGetReleasedSequence: 5, OwnershipGetCompletedSequence: 6, OwnershipGetStatus: 200, HeldRequests: 1, ClientRequestCount: 1, PriorMeasurement: priorMeasurement, CurrentMeasurement: m, PriorRecord: priorRecord, CurrentRecord: currentRecord, ProofOwnershipRead: currentRecord, PriorProcessStateBeforeRelease: "running", PausedRequestDigest: d('f'), PriorWriteStartedSequence: 1, CurrentOwnerObservedSequence: 4, PriorWriteReleasedSequence: 5, PriorResponseObservedSequence: 7, OldResponseStatus: 500, OldResponseBody: base64.StdEncoding.EncodeToString([]byte("durability unproven: DurabilityUnproven")), ClientErrorCode: "HTTP_FAILURE", BeforeRevision: 1, AfterRevision: 1, BeforeStateDigest: d('5'), AfterStateDigest: d('5')}
	r.NativeOwnerFence.ObservationDigest, _ = OwnerObservationDigest(r.OwnerObservation)

	receipt := celld.ReceiptFact{CommandID: "command-1", Found: true, CommandDigest: d('2'), ResponseDigest: d('3'), CapabilityClaimsDigest: d('4')}
	for i, kind := range []string{"seed", "verify", "verify", "stale-cas", "response-loss"} {
		epoch := uint64(3)
		if i < 2 {
			epoch = uint64(i + 1)
		}
		p := celld.ObservationReport{SchemaVersion: 1, Kind: "circulusd.celld.raw-observation/v1", Phase: kind, RunID: r.RunID, EndpointDigest: d('9'), ClaimedBinding: celld.ObservationBinding{ReleaseDigest: m.BuildDigest, ExecutableDigest: m.BuildDigest, ApplicationDigest: m.ApplicationDigest, EffectiveConfigDigest: m.EffectiveConfigurationDigest, DurabilityDomain: m.TransactionDomainID, DurabilityEpoch: epoch}, Expected: celld.ObservationExpected{Token: celld.TokenFact{ObjectID: "qualification-1", Revision: 1}, RequestDigest: d('1'), StateDigest: d('5'), Receipt: receipt}, Errors: []string{}}
		p.Facts = celld.ObservationFacts{After: &celld.SnapshotFact{ObjectID: "qualification-1", Exists: true, Revision: 1, StateDigest: d('5')}, Commit: &celld.CommitFact{RequestDigest: d('1'), Token: celld.TokenFact{ObjectID: "qualification-1", Revision: 1}, Attempts: 1}, Receipt: &celld.ReceiptFact{CommandID: receipt.CommandID, Found: receipt.Found, CommandDigest: receipt.CommandDigest, ResponseDigest: receipt.ResponseDigest, CapabilityClaimsDigest: receipt.CapabilityClaimsDigest}, Barrier: &celld.BarrierFact{Token: celld.TokenFact{ObjectID: "qualification-1", Revision: 1}, MarkerDigest: d('a'), ObservedRevision: 1, BarrierSerial: uint64(i + 1)}}
		if i == 0 {
			p.Facts.Before = &celld.SnapshotFact{ObjectID: "qualification-1", StateDigest: d('0')}
		}
		if i == 1 || i == 2 {
			p.Facts.Commit = nil
		}
		if i == 3 {
			p.Facts.Before = &celld.SnapshotFact{ObjectID: "qualification-1", Exists: true, Revision: 1, StateDigest: d('5')}
			p.Facts.Commit.Token = celld.TokenFact{}
			p.Facts.Commit.RequestDigest = d('f')
			p.Facts.StaleCAS = &celld.StaleCASFact{ErrorCode: "SNAPSHOT_CONFLICT", RequestCount: 1, Snapshot: celld.SnapshotFact{ObjectID: "qualification-1", Revision: 0, StateDigest: d('0')}}
		}
		if i == 4 {
			p.Expected.Token.Revision = 2
			p.Expected.RequestDigest = d('a')
			p.Facts.Commit.RequestDigest = d('a')
			p.Expected.Receipt.CommandDigest = d('b')
			p.Expected.Receipt.ResponseDigest = d('c')
			p.Expected.Receipt.CapabilityClaimsDigest = d('d')
			p.Facts.Receipt.CommandDigest = d('b')
			p.Facts.Receipt.ResponseDigest = d('c')
			p.Facts.Receipt.CapabilityClaimsDigest = d('d')
			p.Expected.StateDigest = d('6')
			p.Expected.Receipt.CommandID = "command-loss"
			p.Facts.Before = &celld.SnapshotFact{ObjectID: "qualification-1", Exists: true, Revision: 1, StateDigest: d('5')}
			p.Facts.After.Revision = 2
			p.Facts.After.StateDigest = d('6')
			p.Facts.Commit.Token.Revision = 2
			p.Facts.Receipt.CommandID = "command-loss"
			p.Facts.Barrier.Token.Revision = 2
			p.Facts.Barrier.ObservedRevision = 2
			received := uint64(0)
			p.Facts.ResponseLoss = &celld.ResponseLossFact{BackendStatus: 200, RequestCount: 1, ClientError: "UNAVAILABLE", ReceivedBytes: &received}
		}
		r.PhaseReports = append(r.PhaseReports, p)
	}
	for i := range r.ProcessFaults {
		r.ProcessFaults[i].SeedObservationDigest, _ = PhaseDigest(r.PhaseReports[i])
		r.ProcessFaults[i].RecoveryObservationDigest, _ = PhaseDigest(r.PhaseReports[i+1])
	}
	r.ResponseLoss.ObservationDigest, _ = PhaseDigest(r.PhaseReports[4])
	return r, c, observerKey
}

func signReport(t *testing.T, r RawReport, key ed25519.PrivateKey) []byte {
	t.Helper()
	digest, err := ReportSigningDigest(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(digest)))
	encoded, err := EncodeReport(r)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestIssueExactDependencyEnvelopeFromDisjointAuthorities(t *testing.T) {
	r, c, key := qualifiedFixture(t)
	evidence, document, err := Issue(signReport(t, r, key), c)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := dependency.DecodeEvidence(bytes.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	d, err := dependency.EvidenceSigningDigest(decoded)
	if err != nil || !ed25519.Verify(c.ConformancePrivateKey.Public().(ed25519.PublicKey), []byte(d), decoded.Signature) {
		t.Fatal("conformance signature did not verify")
	}
	if evidence.Descriptor.ConformanceDigest == r.Measurement.BuildDigest || len(evidence.Descriptor.AtomicGroups) != 2 || evidence.Descriptor.AtomicGroups[0] != dependency.AtomicCommandReceipt || evidence.Descriptor.AtomicGroups[1] != "native-storage" {
		t.Fatal("issuer amplified qualification authority")
	}
}

func TestIssueRejectsSignedIncompleteNativeFacts(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*RawReport)
	}{
		{"application-CAS-is-not-native-owner", func(r *RawReport) { r.NativeOwnerFence.LateWriteErrorCode = "SNAPSHOT_CONFLICT" }},
		{"missing-owner-experiment", func(r *RawReport) { r.NativeOwnerFence = NativeOwnerFence{} }},
		{"old-owner-not-live", func(r *RawReport) { r.NativeOwnerFence.PriorProcessState = "exited" }},
		{"late-owner-write-accepted", func(r *RawReport) { r.NativeOwnerFence.AcceptedLateWrites = 1 }},
		{"restart-without-sigkill", func(r *RawReport) { r.ProcessFaults[0].Signal = 15 }},
		{"fresh-recovery-reused-local-root", func(r *RawReport) { r.ProcessFaults[1].AfterRootDigest = r.ProcessFaults[1].BeforeRootDigest }},
		{"revision-without-receipt", func(r *RawReport) { r.ProcessFaults[1].ReceiptResponseDigest = d('0') }},
		{"CAS-two-winners", func(r *RawReport) { r.CAS.Winners = 2 }},
		{"ETag-synthesized", func(r *RawReport) { r.CAS.CurrentETag = d('f') }},
		{"effect-dispatched-on-loss", func(r *RawReport) { r.ResponseLoss.EffectDispatchCount = 1 }},
		{"lost-commit-retried", func(r *RawReport) { r.ResponseLoss.BackendRequests = 2 }},
		{"missing-response-byte-observation", func(r *RawReport) { r.PhaseReports[4].Facts.ResponseLoss.ReceivedBytes = nil }},
		{"response-delivered-before-drop", func(r *RawReport) {
			received := uint64(1)
			r.PhaseReports[4].Facts.ResponseLoss.ReceivedBytes = &received
		}},
		{"phase-error-hidden-by-root", func(r *RawReport) { r.PhaseReports[1].Errors = []string{"receipt:ERROR"} }},
		{"phase-rebound-to-other-domain", func(r *RawReport) { r.PhaseReports[2].ClaimedBinding.DurabilityDomain = "other" }},
		{"process-fault-phase-digest-unbound", func(r *RawReport) { r.ProcessFaults[1].RecoveryObservationDigest = d('a') }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, c, key := qualifiedFixture(t)
			test.alter(&r)
			if _, _, err := Issue(signReport(t, r, key), c); !errors.Is(err, ErrUnqualified) {
				t.Fatalf("error=%v want ErrUnqualified", err)
			}
		})
	}
}

func TestIssueRejectsUntrustedOrChangedIdentity(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*RawReport, *Config)
	}{
		{"different-executable", func(r *RawReport, c *Config) { r.Measurement.BuildDigest = d('f') }},
		{"different-main-app", func(r *RawReport, c *Config) { r.Measurement.ApplicationDigest = d('f') }},
		{"restarted-process", func(r *RawReport, c *Config) { r.Measurement.ProcessStartTimeTicks++ }},
		{"different-effective-graph", func(r *RawReport, c *Config) { r.Measurement.EffectiveConfigurationDigest = d('f') }},
		{"different-host-boot", func(r *RawReport, c *Config) { r.HostBootID = strings.Repeat("3", 32) }},
		{"report-after-now", func(r *RawReport, c *Config) { r.FinishedAtUnix = c.Now.Unix() + 1 }},
		{"stale-run", func(r *RawReport, c *Config) { r.StartedAtUnix = c.Now.Unix() - 86401 }},
		{"report-runtime-key-not-pinned", func(r *RawReport, c *Config) { r.Measurement.RuntimeKeyID = "runtime-2" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, c, key := qualifiedFixture(t)
			test.alter(&r, &c)
			if _, _, err := Issue(signReport(t, r, key), c); !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	r, c, key := qualifiedFixture(t)
	encoded := signReport(t, r, key)
	encoded = bytes.Replace(encoded, []byte(`"run-1"`), []byte(`"run-2"`), 1)
	if _, _, err := Issue(encoded, c); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("unsigned report mutation error=%v", err)
	}
}

func TestIssuerDoesNotAcceptSelfIssuedOrSharedAuthority(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*Config)
	}{
		{"observer-runtime-key", func(c *Config) { c.ObserverRoots = map[string]ed25519.PublicKey{"observer-1": c.RuntimePublicKey} }},
		{"observer-conformance-key", func(c *Config) {
			c.ObserverRoots = map[string]ed25519.PublicKey{"observer-1": c.ConformancePrivateKey.Public().(ed25519.PublicKey)}
		}},
		{"release-observer-key", func(c *Config) {
			c.ReleaseRoots = map[string]ed25519.PublicKey{"release-1": c.ObserverRoots["observer-1"]}
		}},
		{"empty-release-selection", func(c *Config) { c.Selection = StorageSelection{} }},
		{"stock-archive-relabelled-as-executable", func(c *Config) { c.Selection.ExtractionRecipe = "gzip-single-file-v1" }},
		{"modified-selected-app", func(c *Config) { c.Selection.ApplicationDigest = d('f') }},
		{"unbounded-validity", func(c *Config) { c.Lifetime = 25 * time.Hour }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, c, key := qualifiedFixture(t)
			test.alter(&c)
			if _, _, err := Issue(signReport(t, r, key), c); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestReportRejectsPASSDuplicateAndAliasInputs(t *testing.T) {
	r, _, key := qualifiedFixture(t)
	valid := signReport(t, r, key)
	tests := [][]byte{
		bytes.Replace(valid, []byte(`"kind":`), []byte(`"status":"PASS","kind":`), 1),
		bytes.Replace(valid, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":0,"schemaVersion":1`), 1),
		bytes.Replace(valid, []byte(`"schemaVersion":1`), []byte(`"SchemaVersion":1`), 1),
		append(valid, []byte("{}")...), bytes.Repeat([]byte("x"), MaximumReportBytes+1),
	}
	for i, input := range tests {
		if _, _, err := DecodeReport(bytes.NewReader(input)); !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("case%d error=%v", i, err)
		}
	}
}

func TestStrictJSONRejectsAliasesDuplicatesNullAndMissingFields(t *testing.T) {
	for _, input := range []string{`{"value":1,"value":2}`, `{"Value":1}`, `{"value":null}`, `{}`, `{"value":1,"pass":true}`} {
		var target struct {
			Value uint32 `json:"value"`
		}
		if DecodeStrict([]byte(input), &target) == nil {
			t.Fatalf("accepted%s", input)
		}
	}
	var target struct {
		Value uint32 `json:"value"`
	}
	if DecodeStrict([]byte(" {\n\"value\" : 1 } "), &target) != nil || target.Value != 1 {
		t.Fatal("rejected formatted exact typed input")
	}
}

func TestIssuerValidatesEmbeddedActualOwnershipTranscript(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*RawReport)
	}{
		{"missing-transcript", func(r *RawReport) { r.OwnerObservation = OwnerObservation{} }},
		{"ownership-did-not-transfer", func(r *RawReport) {
			r.OwnerObservation.CurrentRecord = r.OwnerObservation.PriorRecord
			r.OwnerObservation.ProofOwnershipRead = r.OwnerObservation.PriorRecord
		}},
		{"no-fresh-proof-ownership-read", func(r *RawReport) { r.OwnerObservation.ProofOwnershipRead = r.OwnerObservation.PriorRecord }},
		{"accepted-old-response", func(r *RawReport) { r.OwnerObservation.OldResponseStatus = 200 }},
		{"old-request-released-before-takeover", func(r *RawReport) { r.OwnerObservation.PriorWriteReleasedSequence = 1 }},
		{"unrelated-old-process", func(r *RawReport) { r.OwnerObservation.PriorMeasurement.ProcessID = 999 }},
		{"new-owner-state-corrupted", func(r *RawReport) { r.OwnerObservation.AfterStateDigest = d('f') }},
		{"arbitrary-exit-without-self-fence", func(r *RawReport) {
			r.OwnerObservation.OldResponseStatus = 0
			r.OwnerObservation.OldResponseBody = ""
			r.OwnerObservation.ClientErrorCode = "UNAVAILABLE"
			r.OwnerObservation.PriorExitCode = 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, c, key := qualifiedFixture(t)
			test.alter(&r)
			r.NativeOwnerFence.ObservationDigest, _ = OwnerObservationDigest(r.OwnerObservation)
			if _, _, err := Issue(signReport(t, r, key), c); !errors.Is(err, ErrUnqualified) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestIssuerAcceptsObservedTerminalNativeSelfFenceWithoutInventingHTTPStatus(t *testing.T) {
	r, c, key := qualifiedFixture(t)
	r.OwnerObservation.OldResponseStatus = 0
	r.OwnerObservation.OldResponseBody = ""
	r.OwnerObservation.ClientErrorCode = "UNAVAILABLE"
	r.OwnerObservation.PriorExitCode = 3
	r.OwnerObservation.PriorTerminationLogBody = base64.StdEncoding.EncodeToString([]byte("SELF-FENCE: node lease expired\n"))
	r.NativeOwnerFence.LateWriteErrorCode = "self-fenced"
	r.NativeOwnerFence.ObservationDigest, _ = OwnerObservationDigest(r.OwnerObservation)
	if _, _, err := Issue(signReport(t, r, key), c); err != nil {
		t.Fatal(err)
	}
	r.OwnerObservation.PriorTerminationLogBody = base64.StdEncoding.EncodeToString([]byte("ordinary failure"))
	r.NativeOwnerFence.ObservationDigest, _ = OwnerObservationDigest(r.OwnerObservation)
	if _, _, err := Issue(signReport(t, r, key), c); !errors.Is(err, ErrUnqualified) {
		t.Fatalf("error=%v", err)
	}
}

func TestIssuerRejectsLossPhaseReusingSeedCommandAndStaleSnapshotSubstitution(t *testing.T) {
	for _, alter := range []func(*RawReport){
		func(r *RawReport) {
			p := &r.PhaseReports[4]
			p.Expected.Receipt = r.PhaseReports[0].Expected.Receipt
			*p.Facts.Receipt = p.Expected.Receipt
		},
		func(r *RawReport) { r.PhaseReports[4].Facts.Before.Exists = false },
		func(r *RawReport) { r.PhaseReports[4].Facts.Before.StateDigest = d('f') },
		func(r *RawReport) { r.PhaseReports[3].Facts.StaleCAS.Snapshot.StateDigest = d('f') },
	} {
		r, c, key := qualifiedFixture(t)
		alter(&r)
		r.ResponseLoss.ObservationDigest, _ = PhaseDigest(r.PhaseReports[4])
		if _, _, err := Issue(signReport(t, r, key), c); !errors.Is(err, ErrUnqualified) {
			t.Fatalf("error=%v", err)
		}
	}
}

func TestReissuanceCannotRefreshAnOldObservationRun(t *testing.T) {
	r, c, key := qualifiedFixture(t)
	r.StartedAtUnix = c.Now.Unix() - 23*3600
	c.Lifetime = 24 * time.Hour
	evidence, _, err := Issue(signReport(t, r, key), c)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.ExpiresAtUnix != r.StartedAtUnix+24*3600 {
		t.Fatal("issuer refreshed the report's observed age")
	}
	r.StartedAtUnix = c.Now.Unix() - 24*3600
	if _, _, err := Issue(signReport(t, r, key), c); !errors.Is(err, ErrUnqualified) {
		t.Fatalf("error=%v", err)
	}
}
