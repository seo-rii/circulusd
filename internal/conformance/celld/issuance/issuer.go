// Package issuance separates observed native Storage faults from the later
// conformance authority. A report signed by an independently configured
// observer is necessary; caller PASS flags and a live probe are not inputs.
package issuance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celldbridge"
	"github.com/hancomac/circulusd/internal/conformance/celld"
	"github.com/hancomac/circulusd/internal/dependency"
)

const MaximumReportBytes = 128 << 10

var (
	ErrInvalidReport        = errors.New("native storage issuance: invalid raw report")
	ErrUnqualified          = errors.New("native storage issuance: required native fault evidence is unavailable")
	ErrInvalidConfiguration = errors.New("native storage issuance: invalid independent authority configuration")
	identifier              = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
	digest                  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	commit                  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	bootID                  = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Measurement is an actual native boot snapshot, never a Worker variable.
// BuildDigest identifies the selected raw executable artifact. That recipe
// means the artifact and /proc/self/exe hashes must be equal.
type Measurement struct {
	SchemaVersion                uint32 `json:"schemaVersion"`
	CelldCommit                  string `json:"celldCommit"`
	BuildDigest                  string `json:"buildDigest"`
	ApplicationDigest            string `json:"applicationDigest"`
	EffectiveConfigurationDigest string `json:"effectiveConfigurationDigest"`
	InstanceID                   string `json:"instanceId"`
	TransactionDomainID          string `json:"transactionDomainId"`
	RuntimeKeyID                 string `json:"runtimeKeyId"`
	RuntimePublicKey             string `json:"runtimePublicKey"`
	ProbeEpoch                   uint64 `json:"probeEpoch"`
	ProcessID                    uint32 `json:"processId"`
	ProcessStartTimeTicks        uint64 `json:"processStartTimeTicks"`
}

type CASFacts struct {
	Contenders            uint32 `json:"contenders"`
	Winners               uint32 `json:"winners"`
	PreconditionFailures  uint32 `json:"preconditionFailures"`
	InitialETag           string `json:"initialETag"`
	CurrentETag           string `json:"currentETag"`
	StaleUpdateStatus     uint32 `json:"staleUpdateStatus"`
	DuplicateCreateStatus uint32 `json:"duplicateCreateStatus"`
	StaleDeleteStatus     uint32 `json:"staleDeleteStatus"`
	ExpectedDataDigest    string `json:"expectedDataDigest"`
	ObservedDataDigest    string `json:"observedDataDigest"`
	FreshClientDataDigest string `json:"freshClientDataDigest"`
}

type TransactionFacts struct {
	ObjectID                      string `json:"objectId"`
	CommandID                     string `json:"commandId"`
	BeforeRevision                uint64 `json:"beforeRevision"`
	AcknowledgedRevision          uint64 `json:"acknowledgedRevision"`
	TokenRevision                 uint64 `json:"tokenRevision"`
	RequestDigest                 string `json:"requestDigest"`
	CommandDigest                 string `json:"commandDigest"`
	ResponseDigest                string `json:"responseDigest"`
	CapabilityClaimsDigest        string `json:"capabilityClaimsDigest"`
	ExpectedStateDigest           string `json:"expectedStateDigest"`
	ObservedStateDigest           string `json:"observedStateDigest"`
	ReceiptRevision               uint64 `json:"receiptRevision"`
	ReceiptCommandDigest          string `json:"receiptCommandDigest"`
	ReceiptResponseDigest         string `json:"receiptResponseDigest"`
	ReceiptCapabilityClaimsDigest string `json:"receiptCapabilityClaimsDigest"`
	BarrierRevision               uint64 `json:"barrierRevision"`
	BarrierSerial                 uint64 `json:"barrierSerial"`
}

type ProcessFault struct {
	Kind                          string `json:"kind"`
	BeforePID                     uint32 `json:"beforePid"`
	AfterPID                      uint32 `json:"afterPid"`
	Signal                        uint32 `json:"signal"`
	ExitSignal                    uint32 `json:"exitSignal"`
	BeforeRootDigest              string `json:"beforeRootDigest"`
	AfterRootDigest               string `json:"afterRootDigest"`
	BeforeEpoch                   uint64 `json:"beforeEpoch"`
	AfterEpoch                    uint64 `json:"afterEpoch"`
	ObservedRevision              uint64 `json:"observedRevision"`
	ObservedStateDigest           string `json:"observedStateDigest"`
	ReceiptCommandDigest          string `json:"receiptCommandDigest"`
	ReceiptResponseDigest         string `json:"receiptResponseDigest"`
	ReceiptCapabilityClaimsDigest string `json:"receiptCapabilityClaimsDigest"`
	SeedObservationDigest         string `json:"seedObservationDigest"`
	RecoveryObservationDigest     string `json:"recoveryObservationDigest"`
}

// NativeOwnerFence requires an actual late write from a still-running prior
// native owner. A stale application revision or stale object-store ETag is
// deliberately not accepted as this experiment.
type NativeOwnerFence struct {
	PriorEpoch         uint64 `json:"priorEpoch"`
	CurrentEpoch       uint64 `json:"currentEpoch"`
	PriorPID           uint32 `json:"priorPid"`
	CurrentPID         uint32 `json:"currentPid"`
	PriorProcessState  string `json:"priorProcessState"`
	LateWriteErrorCode string `json:"lateWriteErrorCode"`
	Requests           uint32 `json:"requests"`
	AcceptedLateWrites uint32 `json:"acceptedLateWrites"`
	BeforeRevision     uint64 `json:"beforeRevision"`
	AfterRevision      uint64 `json:"afterRevision"`
	ObservationDigest  string `json:"observationDigest"`
}

type ResponseLossFacts struct {
	BackendStatus       uint32 `json:"backendStatus"`
	BackendRequests     uint32 `json:"backendRequests"`
	ReceivedBytes       uint64 `json:"receivedBytes"`
	ClientErrorCode     string `json:"clientErrorCode"`
	BarrierErrorCode    string `json:"barrierErrorCode"`
	EffectDispatchCount uint32 `json:"effectDispatchCount"`
	ObservationDigest   string `json:"observationDigest"`
}

// RawReport contains observations only. Its content digest, including the
// independent observer signature, is the subsequent conformanceDigest. No
// field can contain a later Evidence, descriptor, probe or signer response.
type RawReport struct {
	SchemaVersion    uint32                    `json:"schemaVersion"`
	Kind             string                    `json:"kind"`
	RunID            string                    `json:"runId"`
	StartedAtUnix    int64                     `json:"startedAtUnix"`
	FinishedAtUnix   int64                     `json:"finishedAtUnix"`
	HostBootID       string                    `json:"hostBootId"`
	DriverDigest     string                    `json:"driverDigest"`
	Measurement      Measurement               `json:"measurement"`
	CAS              CASFacts                  `json:"cas"`
	Transaction      TransactionFacts          `json:"transaction"`
	ProcessFaults    []ProcessFault            `json:"processFaults"`
	NativeOwnerFence NativeOwnerFence          `json:"nativeOwnerFence"`
	OwnerObservation OwnerObservation          `json:"ownerObservation"`
	ResponseLoss     ResponseLossFacts         `json:"responseLoss"`
	PhaseReports     []celld.ObservationReport `json:"phaseReports"`
	ObserverKeyID    string                    `json:"observerKeyId"`
	Algorithm        string                    `json:"algorithm"`
	Signature        string                    `json:"signature"`
}

// Config pins four disjoint authorities and an authenticated storage-only
// release selection. RuntimePublicKey must match the actual boot snapshot.
// The issuer never generates trust roots, keys or a replacement release.
type Config struct {
	Selection             StorageSelection
	ReleaseRoots          map[string]ed25519.PublicKey
	ObserverRoots         map[string]ed25519.PublicKey
	ConformanceKeyID      string
	ConformancePrivateKey ed25519.PrivateKey
	RuntimeKeyID          string
	RuntimePublicKey      ed25519.PublicKey
	ExpectedMeasurement   Measurement
	HostBootID            string
	DriverDigest          string
	Now                   time.Time
	Lifetime              time.Duration
}

func DecodeReport(reader io.Reader) (RawReport, []byte, error) {
	if reader == nil {
		return RawReport{}, nil, ErrInvalidReport
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, MaximumReportBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > MaximumReportBytes {
		return RawReport{}, nil, ErrInvalidReport
	}
	var report RawReport
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return RawReport{}, nil, ErrInvalidReport
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return RawReport{}, nil, ErrInvalidReport
	}
	// Requiring the exact canonical JSON emitted by EncodeReport closes both
	// duplicate-key and case-folded Go JSON aliases without a second parser.
	canonicalJSON, err := EncodeReport(report)
	if err != nil || !bytes.Equal(encoded, canonicalJSON) {
		return RawReport{}, nil, ErrInvalidReport
	}
	return report, append([]byte(nil), encoded...), nil
}

func EncodeReport(report RawReport) ([]byte, error) {
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) > MaximumReportBytes {
		return nil, ErrInvalidReport
	}
	return append(encoded, '\n'), nil
}

// ReportSigningDigest uses a separate domain from conformance/runtime
// signatures. Clearing Signature leaves the observer identity in the signed
// payload; issuance verifies against independently pinned observer roots.
func ReportSigningDigest(report RawReport) (string, error) {
	report.Signature = ""
	encoded, err := EncodeReport(report)
	if err != nil {
		return "", err
	}
	return canonical.StructuredDigest("circulusd.native-storage-raw-observation", 1, canonical.Bytes(encoded))
}

// Issue reauthenticates selected artifacts and measured identity, validates
// raw fault facts, and only then signs the exact existing dependency envelope.
// A missing native ownership experiment remains ErrUnqualified even if every
// application CAS and restart check succeeded.
func Issue(encoded []byte, config Config) (dependency.Evidence, []byte, error) {
	report, exact, err := DecodeReport(bytes.NewReader(encoded))
	if err != nil {
		return dependency.Evidence{}, nil, err
	}
	if err := validateConfig(config); err != nil {
		return dependency.Evidence{}, nil, err
	}
	root, trusted := config.ObserverRoots[report.ObserverKeyID]
	signature, err := base64.StdEncoding.Strict().DecodeString(report.Signature)
	signingDigest, digestErr := ReportSigningDigest(report)
	if !trusted || err != nil || digestErr != nil || len(signature) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(signature) != report.Signature || report.Algorithm != "ed25519" ||
		!ed25519.Verify(root, []byte(signingDigest), signature) {
		return dependency.Evidence{}, nil, ErrInvalidReport
	}
	if err := validateFacts(report, config); err != nil {
		return dependency.Evidence{}, nil, err
	}
	reportHash := sha256.Sum256(exact)
	expires := config.Now.Add(config.Lifetime).Unix()
	// Re-signing an older fault report cannot reset its observation age. The
	// retained run's earliest observation supplies the outer freshness bound.
	observationExpiry := report.StartedAtUnix + 24*60*60
	if expires > observationExpiry {
		expires = observationExpiry
	}
	if expires <= config.Now.Unix() {
		return dependency.Evidence{}, nil, ErrUnqualified
	}
	evidence := dependency.Evidence{
		Descriptor: dependency.Descriptor{
			SchemaVersion: 1, BackendKind: dependency.BackendCelld,
			BuildDigest: report.Measurement.BuildDigest, ApplicationDigest: report.Measurement.ApplicationDigest,
			InstanceID: report.Measurement.InstanceID, TransactionDomainID: report.Measurement.TransactionDomainID,
			DurabilityClass: dependency.DurabilityCrashRPOZero, ConformanceRunID: report.RunID,
			ConformanceDigest: "sha256:" + hex.EncodeToString(reportHash[:]), RuntimeKeyID: report.Measurement.RuntimeKeyID,
			ProbeEpoch: report.Measurement.ProbeEpoch, ProductionEligible: true,
			AtomicGroups: []dependency.AtomicGroup{dependency.AtomicCommandReceipt, celldbridge.AtomicNativeStorage},
		},
		IssuedAtUnix: config.Now.Unix(), ExpiresAtUnix: expires,
		KeyID: config.ConformanceKeyID,
	}
	d, err := dependency.EvidenceSigningDigest(evidence)
	if err != nil {
		return dependency.Evidence{}, nil, ErrInvalidReport
	}
	evidence.Signature = ed25519.Sign(config.ConformancePrivateKey, []byte(d))
	publicDocument, err := json.Marshal(evidenceDocument(evidence))
	if err != nil {
		return dependency.Evidence{}, nil, ErrInvalidReport
	}
	publicDocument = append(publicDocument, '\n')
	if _, err := dependency.DecodeEvidence(bytes.NewReader(publicDocument)); err != nil {
		return dependency.Evidence{}, nil, ErrInvalidReport
	}
	return evidence, publicDocument, nil
}

func validateConfig(config Config) error {
	if VerifySelection(config.Selection, config.ReleaseRoots) != nil || !digest.MatchString(config.Selection.BuildDigest) || !digest.MatchString(config.Selection.ApplicationDigest) ||
		!validMeasurement(config.ExpectedMeasurement) || !bootID.MatchString(config.HostBootID) || !digest.MatchString(config.DriverDigest) ||
		!identifier.MatchString(config.ConformanceKeyID) || !identifier.MatchString(config.RuntimeKeyID) ||
		len(config.ConformancePrivateKey) != ed25519.PrivateKeySize || len(config.RuntimePublicKey) != ed25519.PublicKeySize ||
		len(config.ObserverRoots) == 0 || len(config.ObserverRoots) > 64 || config.Now.Unix() <= 0 ||
		config.Lifetime < time.Second || config.Lifetime > 24*time.Hour {
		return ErrInvalidConfiguration
	}
	if config.Selection.CelldCommit != config.ExpectedMeasurement.CelldCommit {
		return ErrInvalidConfiguration
	}
	derived := ed25519.NewKeyFromSeed(config.ConformancePrivateKey[:ed25519.SeedSize])
	if !bytes.Equal(derived, config.ConformancePrivateKey) {
		clear(derived)
		return ErrInvalidConfiguration
	}
	clear(derived)
	conformancePublic := config.ConformancePrivateKey.Public().(ed25519.PublicKey)
	if _, err := dependency.NewVerifier(dependency.VerifierConfig{
		ConformanceRoots: map[string]ed25519.PublicKey{config.ConformanceKeyID: conformancePublic},
		RuntimeRoots:     map[string]ed25519.PublicKey{config.RuntimeKeyID: config.RuntimePublicKey},
		Clock:            func() time.Time { return config.Now }, Entropy: bytes.NewReader(make([]byte, 32)),
	}); err != nil {
		return ErrInvalidConfiguration
	}
	for id, root := range config.ObserverRoots {
		if id == config.ConformanceKeyID || id == config.RuntimeKeyID || bytes.Equal(root, conformancePublic) || bytes.Equal(root, config.RuntimePublicKey) {
			return ErrInvalidConfiguration
		}
		if _, err := dependency.NewVerifier(dependency.VerifierConfig{
			ConformanceRoots: map[string]ed25519.PublicKey{id: root},
			RuntimeRoots:     map[string]ed25519.PublicKey{config.RuntimeKeyID: config.RuntimePublicKey},
			Clock:            func() time.Time { return config.Now }, Entropy: bytes.NewReader(make([]byte, 32)),
		}); err != nil {
			return ErrInvalidConfiguration
		}
	}
	return separateReleaseRoots(config)
}

func validMeasurement(m Measurement) bool {
	key, err := base64.StdEncoding.Strict().DecodeString(m.RuntimePublicKey)
	return m.SchemaVersion == 1 && commit.MatchString(m.CelldCommit) && digest.MatchString(m.BuildDigest) &&
		digest.MatchString(m.ApplicationDigest) && digest.MatchString(m.EffectiveConfigurationDigest) &&
		identifier.MatchString(m.InstanceID) && identifier.MatchString(m.TransactionDomainID) &&
		identifier.MatchString(m.RuntimeKeyID) && m.ProbeEpoch > 0 && m.ProcessID > 0 && m.ProcessStartTimeTicks > 0 && err == nil && len(key) == ed25519.PublicKeySize &&
		base64.StdEncoding.EncodeToString(key) == m.RuntimePublicKey
}

func validateFacts(r RawReport, c Config) error {
	if r.SchemaVersion != 1 || r.Kind != "circulusd.native-storage-raw-report/v1" || !identifier.MatchString(r.RunID) ||
		r.StartedAtUnix <= 0 || r.FinishedAtUnix < r.StartedAtUnix || r.FinishedAtUnix > c.Now.Unix() ||
		c.Now.Unix()-r.StartedAtUnix > 24*60*60 || r.HostBootID != c.HostBootID || r.DriverDigest != c.DriverDigest ||
		r.Measurement != c.ExpectedMeasurement || r.Measurement.BuildDigest != c.Selection.BuildDigest ||
		r.Measurement.ApplicationDigest != c.Selection.ApplicationDigest || r.Measurement.RuntimeKeyID != c.RuntimeKeyID ||
		r.Measurement.RuntimePublicKey != base64.StdEncoding.EncodeToString(c.RuntimePublicKey) {
		return ErrInvalidReport
	}
	cas := r.CAS
	if cas.Contenders != 32 || cas.Winners != 1 || cas.PreconditionFailures != 31 || !validETag(cas.InitialETag) ||
		!validETag(cas.CurrentETag) || cas.InitialETag == cas.CurrentETag || cas.StaleUpdateStatus != 412 ||
		cas.DuplicateCreateStatus != 412 || cas.StaleDeleteStatus != 412 || !digest.MatchString(cas.ExpectedDataDigest) ||
		cas.ExpectedDataDigest != cas.ObservedDataDigest || cas.ExpectedDataDigest != cas.FreshClientDataDigest {
		return ErrUnqualified
	}
	t := r.Transaction
	if !identifier.MatchString(t.ObjectID) || !identifier.MatchString(t.CommandID) || t.BeforeRevision == ^uint64(0) ||
		t.AcknowledgedRevision != t.BeforeRevision+1 || t.TokenRevision != t.AcknowledgedRevision || t.ReceiptRevision != t.AcknowledgedRevision ||
		t.BarrierRevision < t.AcknowledgedRevision || t.BarrierSerial == 0 || !digest.MatchString(t.RequestDigest) ||
		!digest.MatchString(t.CommandDigest) || !digest.MatchString(t.ResponseDigest) || !digest.MatchString(t.CapabilityClaimsDigest) ||
		!digest.MatchString(t.ExpectedStateDigest) || t.ObservedStateDigest != t.ExpectedStateDigest || t.ReceiptCommandDigest != t.CommandDigest ||
		t.ReceiptResponseDigest != t.ResponseDigest || t.ReceiptCapabilityClaimsDigest != t.CapabilityClaimsDigest {
		return ErrUnqualified
	}
	if len(r.ProcessFaults) != 2 {
		return ErrUnqualified
	}
	previousPID := uint32(0)
	previousEpoch := uint64(0)
	for i, f := range r.ProcessFaults {
		kind := "sigkill-local-restart"
		if i == 1 {
			kind = "sigkill-fresh-directory-recovery"
		}
		if f.Kind != kind || f.BeforePID == 0 || f.AfterPID == 0 || f.BeforePID == f.AfterPID || f.Signal != 9 || f.ExitSignal != 9 ||
			!digest.MatchString(f.BeforeRootDigest) || !digest.MatchString(f.AfterRootDigest) ||
			(f.BeforeRootDigest != f.AfterRootDigest) != (i == 1) || f.BeforeEpoch == 0 || f.AfterEpoch <= f.BeforeEpoch ||
			(i > 0 && (f.BeforePID != previousPID || f.BeforeEpoch != previousEpoch)) ||
			f.ObservedRevision != t.AcknowledgedRevision || f.ObservedStateDigest != t.ExpectedStateDigest ||
			f.ReceiptCommandDigest != t.CommandDigest || f.ReceiptResponseDigest != t.ResponseDigest ||
			f.ReceiptCapabilityClaimsDigest != t.CapabilityClaimsDigest || !digest.MatchString(f.SeedObservationDigest) ||
			!digest.MatchString(f.RecoveryObservationDigest) || f.SeedObservationDigest == f.RecoveryObservationDigest {
			return ErrUnqualified
		}
		previousPID, previousEpoch = f.AfterPID, f.AfterEpoch
	}
	if previousPID != r.Measurement.ProcessID || previousEpoch != r.Measurement.ProbeEpoch {
		return ErrUnqualified
	}
	f := r.NativeOwnerFence
	if f.PriorEpoch == 0 || f.CurrentEpoch <= f.PriorEpoch || f.CurrentEpoch != r.Measurement.ProbeEpoch ||
		f.PriorPID == 0 || f.CurrentPID != previousPID || f.PriorPID == f.CurrentPID || (f.PriorProcessState != "running" && f.PriorProcessState != "stopped") ||
		(f.LateWriteErrorCode != "stale-owner" && f.LateWriteErrorCode != "output-gate-rejected" && f.LateWriteErrorCode != "self-fenced") || f.Requests != 1 || f.AcceptedLateWrites != 0 ||
		f.BeforeRevision != f.AfterRevision || f.AfterRevision < t.AcknowledgedRevision || !digest.MatchString(f.ObservationDigest) {
		return ErrUnqualified
	}
	l := r.ResponseLoss
	if l.BackendStatus != 200 || l.BackendRequests != 1 || l.ReceivedBytes != 0 || (l.ClientErrorCode != "UNAVAILABLE" && l.ClientErrorCode != "INVALID_RESPONSE") ||
		l.BarrierErrorCode != "NONE" || l.EffectDispatchCount != 0 || !digest.MatchString(l.ObservationDigest) {
		return ErrUnqualified
	}
	if err := validatePhases(r); err != nil {
		return err
	}
	return validateOwnerObservation(r)
}

func validETag(etag string) bool {
	if len(etag) < 3 || len(etag) > 1024 || etag[0] != '"' || etag[len(etag)-1] != '"' {
		return false
	}
	for _, c := range etag[1 : len(etag)-1] {
		if c < 0x21 || c > 0x7e || c == '"' {
			return false
		}
	}
	return true
}

func evidenceDocument(e dependency.Evidence) any {
	d := e.Descriptor
	return struct {
		SchemaVersion uint32 `json:"schemaVersion"`
		Descriptor    any    `json:"descriptor"`
		IssuedAtUnix  int64  `json:"issuedAtUnix"`
		ExpiresAtUnix int64  `json:"expiresAtUnix"`
		KeyID         string `json:"keyId"`
		Algorithm     string `json:"algorithm"`
		Signature     string `json:"signature"`
	}{1, struct {
		SchemaVersion       uint32                   `json:"schemaVersion"`
		BackendKind         string                   `json:"backendKind"`
		BuildDigest         string                   `json:"buildDigest"`
		ApplicationDigest   string                   `json:"applicationDigest"`
		InstanceID          string                   `json:"instanceId"`
		TransactionDomainID string                   `json:"transactionDomainId"`
		DurabilityClass     string                   `json:"durabilityClass"`
		ConformanceRunID    string                   `json:"conformanceRunId"`
		ConformanceDigest   string                   `json:"conformanceDigest"`
		RuntimeKeyID        string                   `json:"runtimeKeyId"`
		ProbeEpoch          uint64                   `json:"probeEpoch"`
		ProductionEligible  bool                     `json:"productionEligible"`
		AtomicGroups        []dependency.AtomicGroup `json:"atomicGroups"`
	}{d.SchemaVersion, d.BackendKind, d.BuildDigest, d.ApplicationDigest, d.InstanceID, d.TransactionDomainID, d.DurabilityClass, d.ConformanceRunID, d.ConformanceDigest, d.RuntimeKeyID, d.ProbeEpoch, d.ProductionEligible, d.AtomicGroups}, e.IssuedAtUnix, e.ExpiresAtUnix, e.KeyID, "ed25519", base64.StdEncoding.EncodeToString(e.Signature)}
}
