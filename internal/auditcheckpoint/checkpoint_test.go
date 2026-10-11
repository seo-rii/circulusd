package auditcheckpoint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/auth"
	"github.com/hancomac/circulusd/internal/authstate"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/dependency"
	proof "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/identity"
)

// These fsync-backed transactions and signed descriptors are only contract-test
// fixtures. They do not qualify a local file driver or signing key for runtime.
type testFrame struct {
	State    []byte
	Receipts map[string]celld.StoredReceipt
	Revision uint64
}

type testSource struct {
	*proof.ProductionProofs
	mu                                                         sync.Mutex
	directory                                                  string
	fault                                                      celld.FaultPoint
	faultReceiptsOnly                                          bool
	transactionError, barrierError                             error
	cancelCommit, cancelBarrier                                context.CancelFunc
	tokenMode                                                  string
	callbackRetries                                            int
	stateWrites, receiptWrites, barriers, transactions, probes atomic.Int32
}

var testDiagnostic = errors.New("test: diagnostic contains private source material")

func (s *testSource) path(object string) string {
	digest := sha256.Sum256([]byte(object))
	return filepath.Join(s.directory, hex.EncodeToString(digest[:])+".json")
}
func (s *testSource) read(object string) (testFrame, error) {
	encoded, err := os.ReadFile(s.path(object))
	if errors.Is(err, os.ErrNotExist) {
		return testFrame{Receipts: map[string]celld.StoredReceipt{}}, nil
	}
	if err != nil {
		return testFrame{}, err
	}
	var frame testFrame
	err = json.Unmarshal(encoded, &frame)
	return frame, err
}
func (s *testSource) persist(object string, frame testFrame) error {
	encoded, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.directory, "checkpoint-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(encoded); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, s.path(object)); err != nil {
		return err
	}
	dir, err := os.Open(s.directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (s *testSource) ProbeProduction(ctx context.Context, c dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	s.probes.Add(1)
	return s.ProductionProofs.ProbeProduction(ctx, c)
}
func (s *testSource) Transaction(ctx context.Context, object string, callback func(celld.Transaction) error) (celld.CommitToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transactions.Add(1)
	if err := ctx.Err(); err != nil {
		return celld.CommitToken{}, err
	}
	if s.transactionError != nil {
		return celld.CommitToken{}, s.transactionError
	}
	if s.tokenMode == "skip" {
		return celld.CommitToken{ObjectID: object, Revision: 1}, nil
	}
	if s.tokenMode == "nil" {
		return celld.CommitToken{}, callback(nil)
	}
	frame, err := s.read(object)
	if err != nil {
		return celld.CommitToken{}, err
	}
	var tx *testTransaction
	for attempt := 0; attempt <= s.callbackRetries; attempt++ {
		tx = &testTransaction{frame: cloneFrame(frame)}
		if err = callback(tx); err != nil {
			return celld.CommitToken{}, err
		}
	}
	fault := s.fault
	if s.faultReceiptsOnly && !tx.receiptChanged {
		fault = ""
	}
	if fault == celld.FaultBeforeCommit {
		return celld.CommitToken{}, testDiagnostic
	}
	if tx.changed || frame.Revision == 0 {
		tx.frame.Revision++
		if err = s.persist(object, tx.frame); err != nil {
			return celld.CommitToken{}, err
		}
		if tx.stateChanged {
			s.stateWrites.Add(1)
		}
		if tx.receiptChanged {
			s.receiptWrites.Add(1)
		}
	}
	if s.cancelCommit != nil {
		s.cancelCommit()
	}
	if fault == celld.FaultAfterCommit {
		return celld.CommitToken{}, testDiagnostic
	}
	token := celld.CommitToken{ObjectID: object, Revision: tx.frame.Revision}
	if s.tokenMode == "object" {
		token.ObjectID += "-other"
	}
	if s.tokenMode == "revision" {
		token.Revision = 0
	}
	return token, nil
}
func (s *testSource) DurabilityBarrier(ctx context.Context, token celld.CommitToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.barriers.Add(1)
	if err := ctx.Err(); err != nil {
		return err
	}
	frame, err := s.read(token.ObjectID)
	if err != nil {
		return err
	}
	if token.Revision == 0 || frame.Revision < token.Revision {
		return testDiagnostic
	}
	if s.barrierError != nil {
		return s.barrierError
	}
	fault := s.fault
	if s.faultReceiptsOnly && s.receiptWrites.Load() == 0 {
		fault = ""
	}
	if fault == celld.FaultBeforeBarrier {
		return testDiagnostic
	}
	if s.cancelBarrier != nil {
		s.cancelBarrier()
	}
	if fault == celld.FaultAfterBarrier || fault == celld.FaultBeforeResponse {
		return testDiagnostic
	}
	return nil
}

type testTransaction struct {
	frame                                 testFrame
	changed, stateChanged, receiptChanged bool
}

func (tx *testTransaction) ReadState() ([]byte, error) { return bytes.Clone(tx.frame.State), nil }
func (tx *testTransaction) LookupReceipt(id string) (celld.StoredReceipt, bool, error) {
	r, ok := tx.frame.Receipts[id]
	r.Response = bytes.Clone(r.Response)
	return r, ok, nil
}
func (tx *testTransaction) WriteState(state []byte) error {
	tx.frame.State = bytes.Clone(state)
	tx.changed = true
	tx.stateChanged = true
	return nil
}
func (tx *testTransaction) WriteReceipt(id string, r celld.StoredReceipt) error {
	r.Response = bytes.Clone(r.Response)
	tx.frame.Receipts[id] = r
	tx.changed = true
	tx.receiptChanged = true
	return nil
}
func cloneFrame(frame testFrame) testFrame {
	frame.State = bytes.Clone(frame.State)
	receipts := make(map[string]celld.StoredReceipt, len(frame.Receipts))
	for id, r := range frame.Receipts {
		r.Response = bytes.Clone(r.Response)
		r.CapabilityClaims = append([]celld.RawCapabilityClaims(nil), r.CapabilityClaims...)
		receipts[id] = r
	}
	frame.Receipts = receipts
	return frame
}

type testSigner struct {
	*proof.ProductionProofs
	private       ed25519.PrivateKey
	calls, probes atomic.Int32
	before        func(context.Context)
	mutate        func(*SigningResponse)
	err           error
}

func (s *testSigner) ProbeProduction(ctx context.Context, c dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	s.probes.Add(1)
	return s.ProductionProofs.ProbeProduction(ctx, c)
}
func (s *testSigner) SignCheckpoint(ctx context.Context, r SigningRequest) (SigningResponse, error) {
	s.calls.Add(1)
	if s.before != nil {
		s.before(ctx)
	}
	if s.err != nil {
		return SigningResponse{}, s.err
	}
	digest, err := SigningDigest(r.CanonicalClaims)
	if err != nil || digest != r.SigningDigest || r.KeyID != "audit-key-v1" {
		return SigningResponse{}, testDiagnostic
	}
	response := SigningResponse{KeyID: r.KeyID, SigningDigest: digest, Signature: ed25519.Sign(s.private, digest[:])}
	if s.mutate != nil {
		s.mutate(&response)
	}
	return response, nil
}

type testReader struct {
	AuditReader
	mutate func(*authstate.AuditSnapshot)
	after  context.CancelFunc
	err    error
}

func (r *testReader) ReadAuditSnapshot(ctx context.Context) (authstate.AuditSnapshot, error) {
	if r.err != nil {
		return authstate.AuditSnapshot{}, r.err
	}
	snapshot, err := r.AuditReader.ReadAuditSnapshot(ctx)
	if r.mutate != nil {
		r.mutate(&snapshot)
	}
	if r.after != nil {
		r.after()
	}
	return snapshot, err
}

type fixture struct {
	source       *testSource
	signer       *testSigner
	reader       AuditReader
	config       Config
	publisher    *Publisher
	pat          *auth.PATService
	account      *authstate.AccountStore
	tenant, user string
}

func testID(t *testing.T, kind identity.Kind) string {
	t.Helper()
	id, err := identity.New(kind)
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}
func newFixture(t *testing.T, group dependency.AtomicGroup, issued bool) *fixture {
	t.Helper()
	groups := []dependency.AtomicGroup{group, dependency.AtomicCommandReceipt}
	slices.Sort(groups)
	p := proof.NewProductionProofs(t, groups)
	source := &testSource{ProductionProofs: p, directory: t.TempDir()}
	sourceBinding := proof.Verify[authstate.Source](t, p, source, groups)
	f := &fixture{source: source, tenant: testID(t, identity.Tenant), user: testID(t, identity.Subject)}
	clock := func() time.Time { return time.Unix(2_000_000_000, 0).UTC() }
	if group == authstate.AtomicCredentialAudit {
		store, err := authstate.New(authstate.Config{Source: sourceBinding, TenantID: f.tenant, Now: clock})
		if err != nil {
			t.Fatal(err)
		}
		f.reader = store
		f.pat, err = auth.NewPATService(auth.PATServiceConfig{Store: store, Now: clock, MaximumCASRetries: 128})
		if err != nil {
			t.Fatal(err)
		}
		if issued {
			f.issue(t)
		}
	} else {
		parameters := auth.Argon2idParams{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}
		store, err := authstate.NewAccountStore(authstate.AccountConfig{Config: authstate.Config{Source: sourceBinding, TenantID: f.tenant, Now: clock}, LoginPolicy: auth.LoginPolicy{MaximumFailures: 2, LockoutDuration: time.Minute}, PasswordParameters: parameters})
		if err != nil {
			t.Fatal(err)
		}
		f.reader, f.account = store, store
		if issued {
			hash, err := auth.HashPassword("bounded-test-password", parameters, bytes.NewReader(bytes.Repeat([]byte{7}, 16)))
			if err != nil {
				t.Fatal(err)
			}
			if err = store.CreateAccount(context.Background(), auth.Account{TenantID: f.tenant, UserID: f.user, Username: "alice", PasswordHash: hash, Version: 1}); err != nil {
				t.Fatal(err)
			}
		}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signerProof := proof.NewProductionProofs(t, []dependency.AtomicGroup{AtomicCheckpointSigning})
	f.signer = &testSigner{ProductionProofs: signerProof, private: private}
	f.config = Config{TenantID: f.tenant, AuditGroup: group, Reader: proof.Verify[AuditReader](t, p, f.reader, []dependency.AtomicGroup{group}), Storage: sourceBinding, Signer: proof.Verify[Signer](t, signerProof, f.signer, []dependency.AtomicGroup{AtomicCheckpointSigning}), KeyID: "audit-key-v1", PublicKey: public}
	f.publisher, err = New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *fixture) issue(t *testing.T) {
	t.Helper()
	if _, _, err := f.pat.Issue(context.Background(), f.tenant, f.user, []string{"events:read"}, time.Hour); err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) frame(t *testing.T) testFrame {
	t.Helper()
	f.source.mu.Lock()
	defer f.source.mu.Unlock()
	frame, err := f.source.read(f.publisher.template.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}
func (f *fixture) rewrite(t *testing.T, mutate func(*testFrame)) {
	t.Helper()
	f.source.mu.Lock()
	defer f.source.mu.Unlock()
	frame, err := f.source.read(f.publisher.template.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&frame)
	if err = f.source.persist(f.publisher.template.ObjectID, frame); err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) setReader(t *testing.T, reader AuditReader) {
	t.Helper()
	f.config.Reader = proof.Verify[AuditReader](t, f.source.ProductionProofs, reader, []dependency.AtomicGroup{dependency.AtomicGroup(f.publisher.template.AuditGroup)})
	p, err := New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.publisher = p
}

func TestActualAuditSnapshotsPublishImmutableSignedCheckpoints(t *testing.T) {
	for _, group := range []dependency.AtomicGroup{authstate.AtomicCredentialAudit, authstate.AtomicAccountAudit} {
		for _, issued := range []bool{false, true} {
			t.Run(string(group)+map[bool]string{false: "/empty", true: "/retained"}[issued], func(t *testing.T) {
				f := newFixture(t, group, issued)
				page, err := f.reader.ReadAuditSnapshot(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				before := f.frame(t)
				writes := f.source.stateWrites.Load()
				signerProbes := f.signer.probes.Load()
				first, err := f.publisher.Publish(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if err = Verify(first, f.config.PublicKey); err != nil || first.Claims.TenantID != page.TenantID || first.Claims.ObjectID != page.ObjectID || first.Claims.HeadSequence != page.HeadSequence || first.Claims.HeadDigest != page.HeadDigest || first.Claims.StateDigest != page.StateDigest || first.Claims.AuditGroup != string(group) {
					t.Fatal("checkpoint lost exact audited snapshot", err)
				}
				after := f.frame(t)
				if !bytes.Equal(before.State, after.State) || f.source.stateWrites.Load() != writes || f.source.receiptWrites.Load() != 1 || f.signer.calls.Load() != 1 || f.signer.probes.Load() != signerProbes {
					t.Fatal("checkpoint modified credential state or requalified signer")
				}
				encoded, err := Encode(first)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := Decode(encoded, f.config.PublicKey)
				if err != nil || decoded.Claims != first.Claims || !bytes.Equal(decoded.Signature, first.Signature) {
					t.Fatal("wire checkpoint changed", err)
				}
				decoded.Signature[0] ^= 1
				if bytes.Equal(decoded.Signature, first.Signature) {
					t.Fatal("decoded signature aliases input")
				}
				key := bytes.Clone(f.config.PublicKey)
				f.config.PublicKey[0] ^= 1
				cold, err := New(Config{TenantID: f.config.TenantID, AuditGroup: group, Reader: f.config.Reader, Storage: f.config.Storage, Signer: f.config.Signer, KeyID: f.config.KeyID, PublicKey: key})
				if err != nil {
					t.Fatal(err)
				}
				replayed, err := cold.Publish(context.Background())
				if err != nil || replayed.Claims != first.Claims || !bytes.Equal(replayed.Signature, first.Signature) || f.signer.calls.Load() != 1 || f.source.receiptWrites.Load() != 1 {
					t.Fatal("cold replay changed immutable original", err)
				}
				if err = Verify(replayed, key); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestConcurrentAuditMutationCannotRelabelSignedHead(t *testing.T) {
	for _, mode := range []string{"actual audit mutation", "raw state only"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, authstate.AtomicCredentialAudit, true)
			f.signer.before = func(context.Context) {
				if mode == "actual audit mutation" {
					f.issue(t)
				} else {
					f.rewrite(t, func(frame *testFrame) { frame.State = append(frame.State, 0) })
				}
			}
			result, err := f.publisher.Publish(context.Background())
			if !errors.Is(err, ErrStaleSnapshot) || len(result.Signature) != 0 || len(f.frame(t).Receipts) != 0 {
				t.Fatal("concurrent change published stale authority", err)
			}
		})
	}
}

func TestConcurrentPublishersReturnOneOriginalCheckpoint(t *testing.T) {
	f := newFixture(t, authstate.AtomicCredentialAudit, true)
	var wg sync.WaitGroup
	results := make(chan Checkpoint, 12)
	errs := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			checkpoint, err := f.publisher.Publish(context.Background())
			results <- checkpoint
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first []byte
	for checkpoint := range results {
		if err := Verify(checkpoint, f.config.PublicKey); err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = checkpoint.Signature
		}
		if !bytes.Equal(first, checkpoint.Signature) {
			t.Fatal("concurrent publishers changed original signature")
		}
	}
	if f.source.receiptWrites.Load() != 1 {
		t.Fatal("more than one immutable receipt")
	}
}

func TestSnapshotsFailClosedBeforeNativeSigning(t *testing.T) {
	for _, mode := range []string{"tenant", "object", "state", "sequence", "head", "zero-head", "uppercase"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, authstate.AtomicCredentialAudit, true)
			reader := &testReader{AuditReader: f.reader, mutate: func(s *authstate.AuditSnapshot) {
				switch mode {
				case "tenant":
					s.TenantID = testID(t, identity.Tenant)
				case "object":
					s.ObjectID += "-other"
				case "state":
					s.StateDigest[0] ^= 1
				case "sequence":
					s.HeadSequence = maximumAuditSequence + 1
				case "head":
					s.HeadDigest = "sha256:" + strings.Repeat("4", 64)
				case "zero-head":
					s.HeadDigest = zeroHeadDigest
				case "uppercase":
					s.HeadDigest = "sha256:" + strings.Repeat("A", 64)
				}
			}}
			f.setReader(t, reader)
			result, err := f.publisher.Publish(context.Background())
			if err == nil || len(result.Signature) != 0 || f.signer.calls.Load() != 0 || f.source.receiptWrites.Load() != 0 {
				t.Fatal("invalid audit snapshot reached signer")
			}
		})
	}
}

func TestNativeSigningResponseRequiresExactPinnedProof(t *testing.T) {
	for _, mode := range []string{"key", "digest", "signature", "length", "other-key", "error"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, authstate.AtomicCredentialAudit, true)
			f.signer.mutate = func(r *SigningResponse) {
				switch mode {
				case "key":
					r.KeyID += "-other"
				case "digest":
					r.SigningDigest[0] ^= 1
				case "signature":
					r.Signature[0] ^= 1
				case "length":
					r.Signature = r.Signature[:63]
				case "other-key":
					_, key, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						t.Fatal(err)
					}
					r.Signature = ed25519.Sign(key, r.SigningDigest[:])
				}
			}
			want := ErrInvalidCheckpoint
			if mode == "error" {
				f.signer.err = testDiagnostic
				want = ErrUnavailable
			}
			result, err := f.publisher.Publish(context.Background())
			if err != want || len(result.Signature) != 0 || f.source.receiptWrites.Load() != 0 {
				t.Fatal("unverified signer result published", err)
			}
		})
	}
}

func TestCheckpointVerificationBindsEveryIdentityAndStateField(t *testing.T) {
	f := newFixture(t, authstate.AtomicCredentialAudit, true)
	checkpoint, err := f.publisher.Publish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*Claims){"tenant": func(c *Claims) { c.TenantID = testID(t, identity.Tenant) }, "object": func(c *Claims) { c.ObjectID += "-other" }, "group": func(c *Claims) { c.AuditGroup = string(authstate.AtomicAccountAudit) }, "sequence": func(c *Claims) { c.HeadSequence++ }, "head": func(c *Claims) { c.HeadDigest = "sha256:" + strings.Repeat("5", 64) }, "state": func(c *Claims) { c.StateDigest[0] ^= 1 }, "source": func(c *Claims) { c.SourceInstanceID += "-other" }, "domain": func(c *Claims) { c.TransactionDomainID += "-other" }, "source-build": func(c *Claims) { c.SourceBuildDigest = "sha256:" + strings.Repeat("4", 64) }, "source-app": func(c *Claims) { c.SourceApplicationDigest = "sha256:" + strings.Repeat("4", 64) }, "signer": func(c *Claims) { c.SignerInstanceID += "-other" }, "key": func(c *Claims) { c.SignerKeyID += "-other" }, "signer-domain": func(c *Claims) { c.SignerTransactionDomainID += "-other" }, "signer-build": func(c *Claims) { c.SignerBuildDigest = "sha256:" + strings.Repeat("4", 64) }, "signer-app": func(c *Claims) { c.SignerApplicationDigest = "sha256:" + strings.Repeat("4", 64) }}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			mutated := checkpoint
			change(&mutated.Claims)
			if Verify(mutated, f.config.PublicKey) != ErrInvalidCheckpoint {
				t.Fatal("signed claim relabel accepted")
			}
		})
	}
	for _, key := range []ed25519.PublicKey{make([]byte, 32), append([]byte{1}, make([]byte, 31)...), bytes.Repeat([]byte{255}, 32), f.config.PublicKey[:31]} {
		if Verify(checkpoint, key) != ErrInvalidCheckpoint {
			t.Fatal("invalid trust root accepted")
		}
	}
}

func TestImmutableReceiptCorruptionCannotBeReplaced(t *testing.T) {
	for _, mode := range []string{"digest", "signature", "claims", "oversize", "capabilities", "unknown-field"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, authstate.AtomicCredentialAudit, true)
			first, err := f.publisher.Publish(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			f.rewrite(t, func(frame *testFrame) {
				id := "audit-checkpoint.v1/1"
				r := frame.Receipts[id]
				switch mode {
				case "digest":
					r.CommandDigest[0] ^= 1
				case "signature":
					r.Response[len(r.Response)-1] ^= 1
				case "claims":
					c := first
					c.Claims.StateDigest[0] ^= 1
					_, c.SigningDigest, _ = signingPayload(c.Claims)
					c.Signature = ed25519.Sign(f.signer.private, c.SigningDigest[:])
					r.Response, _ = Encode(c)
					r.CommandDigest = celld.Digest(c.SigningDigest)
				case "oversize":
					r.Response = make([]byte, MaximumCheckpointBytes+1)
				case "capabilities":
					r.CapabilityClaims = []celld.RawCapabilityClaims{{}}
				case "unknown-field":
					v, _ := canonical.Decode(r.Response, checkpointOptions())
					m := v.(canonical.Map)
					m["unknown"] = true
					r.Response, _ = canonical.Encode(m, checkpointOptions())
				}
				frame.Receipts[id] = r
			})
			result, err := f.publisher.Publish(context.Background())
			if err == nil || len(result.Signature) != 0 || f.signer.calls.Load() != 1 || f.source.receiptWrites.Load() != 1 {
				t.Fatal("corrupt immutable receipt replaced", err)
			}
		})
	}
}

func TestPublicationFaultsAndColdReopenPreserveOriginalFacts(t *testing.T) {
	for _, point := range []celld.FaultPoint{celld.FaultBeforeCommit, celld.FaultAfterCommit, celld.FaultBeforeBarrier, celld.FaultAfterBarrier, celld.FaultBeforeResponse} {
		t.Run(string(point), func(t *testing.T) {
			f := newFixture(t, authstate.AtomicCredentialAudit, true)
			f.source.fault = point
			f.source.faultReceiptsOnly = true
			result, err := f.publisher.Publish(context.Background())
			if err == nil || len(result.Signature) != 0 {
				t.Fatal("unconfirmed publication escaped")
			}
			before := f.frame(t)
			expectedWrites := int32(1)
			if point == celld.FaultBeforeCommit {
				expectedWrites = 0
			}
			if f.source.receiptWrites.Load() != expectedWrites {
				t.Fatal("fault persistence differs")
			}
			coldSource := &testSource{ProductionProofs: f.source.ProductionProofs, directory: f.source.directory}
			f.config.Storage = proof.Verify[authstate.Source](t, coldSource.ProductionProofs, coldSource, coldSource.Descriptor().AtomicGroups)
			store, err := authstate.New(authstate.Config{Source: f.config.Storage, TenantID: f.tenant, Now: func() time.Time { return time.Unix(2_000_000_000, 0).UTC() }})
			if err != nil {
				t.Fatal(err)
			}
			f.config.Reader = proof.Verify[AuditReader](t, coldSource.ProductionProofs, store, []dependency.AtomicGroup{authstate.AtomicCredentialAudit})
			cold, err := New(f.config)
			if err != nil {
				t.Fatal(err)
			}
			replayed, err := cold.Publish(context.Background())
			if err != nil || Verify(replayed, f.config.PublicKey) != nil {
				t.Fatal("cold reopen did not recover", err)
			}
			if expectedWrites == 1 {
				original, err := Decode(before.Receipts["audit-checkpoint.v1/1"].Response, f.config.PublicKey)
				if err != nil || !bytes.Equal(original.Signature, replayed.Signature) || f.signer.calls.Load() != 1 {
					t.Fatal("cold replay changed original", err)
				}
			}
		})
	}
}

func TestOperationalErrorsAndCancellationNeverExposePartialCheckpoint(t *testing.T) {
	for _, mode := range []string{"reader-error", "transaction-error", "barrier-error", "reader-cancel", "signer-cancel", "commit-cancel", "barrier-cancel", "pre-cancel", "nil-context"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, authstate.AtomicCredentialAudit, true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := error(context.Canceled)
			switch mode {
			case "reader-error":
				f.setReader(t, &testReader{AuditReader: f.reader, err: testDiagnostic})
				want = ErrUnavailable
			case "transaction-error":
				f.source.transactionError = testDiagnostic
				want = authstate.ErrUnavailable
			case "barrier-error":
				f.signer.before = func(context.Context) { f.source.barrierError = testDiagnostic }
				want = celld.ErrDurabilityBarrier
			case "reader-cancel":
				f.setReader(t, &testReader{AuditReader: f.reader, after: cancel})
			case "signer-cancel":
				f.signer.before = func(context.Context) { cancel() }
			case "commit-cancel":
				f.signer.before = func(context.Context) { f.source.cancelCommit = cancel }
			case "barrier-cancel":
				f.signer.before = func(context.Context) { f.source.cancelBarrier = cancel }
			case "pre-cancel":
				cancel()
			case "nil-context":
				ctx = nil
				want = ErrInvalidRequest
			}
			result, err := f.publisher.Publish(ctx)
			if err != want || len(result.Signature) != 0 || strings.Contains(err.Error(), "private source") {
				t.Fatal("partial or diagnostic escaped", err)
			}
		})
	}
}

func TestStrictBoundsCanonicalEncodingAndTransactionContract(t *testing.T) {
	for _, mode := range []string{"skip", "nil", "object", "revision"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, authstate.AtomicCredentialAudit, true)
			f.signer.before = func(context.Context) { f.source.tokenMode = mode }
			if _, err := f.publisher.Publish(context.Background()); err != celld.ErrStorageContract {
				t.Fatal(err)
			}
		})
	}
	f := newFixture(t, authstate.AtomicCredentialAudit, true)
	f.source.callbackRetries = 2
	if _, err := f.publisher.Publish(context.Background()); err != nil || f.source.receiptWrites.Load() != 1 {
		t.Fatal("valid callback retry failed", err)
	}
	f = newFixture(t, authstate.AtomicCredentialAudit, true)
	f.setReader(t, &testReader{AuditReader: f.reader, mutate: func(*authstate.AuditSnapshot) {
		f.rewrite(t, func(frame *testFrame) { frame.State = make([]byte, maximumAuditStateBytes+1) })
	}})
	if _, err := f.publisher.Publish(context.Background()); err != ErrInvalidCheckpoint || f.signer.calls.Load() != 0 {
		t.Fatal("oversize raw state accepted", err)
	}
	if _, err := Decode(make([]byte, MaximumCheckpointBytes+1), f.config.PublicKey); err != ErrInvalidCheckpoint {
		t.Fatal("oversize checkpoint accepted")
	}
	if _, err := SigningDigest([]byte{0xa0}); err != ErrInvalidCheckpoint {
		t.Fatal("empty claim frame accepted")
	}
}

func TestIndependentQualificationAndPinnedConfiguration(t *testing.T) {
	f := newFixture(t, authstate.AtomicCredentialAudit, true)
	for _, mode := range []string{"reader", "storage", "signer", "key", "public-key", "tenant", "group", "receipt-group", "signer-group", "audit-group"} {
		t.Run(mode, func(t *testing.T) {
			config := f.config
			switch mode {
			case "reader":
				config.Reader = dependency.Verified[AuditReader]{}
			case "storage":
				config.Storage = dependency.Verified[authstate.Source]{}
			case "signer":
				config.Signer = dependency.Verified[Signer]{}
			case "key":
				config.KeyID = "\n"
			case "public-key":
				config.PublicKey = append([]byte{1}, make([]byte, 31)...)
			case "tenant":
				config.TenantID = f.user
			case "group":
				config.AuditGroup = "other"
			case "receipt-group":
				p := proof.NewProductionProofs(t, []dependency.AtomicGroup{authstate.AtomicCredentialAudit})
				source := &testSource{ProductionProofs: p, directory: t.TempDir()}
				config.Storage = proof.Verify[authstate.Source](t, p, source, p.Descriptor().AtomicGroups)
			case "signer-group":
				p := proof.NewProductionProofs(t, []dependency.AtomicGroup{authstate.AtomicCredentialAudit})
				s := &testSigner{ProductionProofs: p, private: f.signer.private}
				config.Signer = proof.Verify[Signer](t, p, s, p.Descriptor().AtomicGroups)
			case "audit-group":
				config.AuditGroup = authstate.AtomicAccountAudit
			}
			if _, err := New(config); err == nil {
				t.Fatal("unqualified or mutable wiring accepted")
			}
		})
	}
	if _, err := (*Publisher)(nil).Publish(context.Background()); err != dependency.ErrUnverifiedDependency {
		t.Fatal(err)
	}
}
