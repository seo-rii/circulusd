package authstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/auth"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/dependency"
	proof "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/identity"
)

// This fsync-backed fixture exercises transaction rollback and reopen behavior.
// Its signatures are contract-test fixtures, not native production qualification.
type fileSource struct {
	*proof.ProductionProofs
	directory                                        string
	mu                                               sync.Mutex
	failWrite, failBarrier, skipCallback, wrongToken bool
	transactions                                     atomic.Int32
}

type diskFrame struct {
	Revision uint64
	State    []byte
}

func (source *fileSource) path(object string) string {
	return filepath.Join(source.directory, fmt.Sprintf("%x.json", sha256.Sum256([]byte(object))))
}

func (source *fileSource) read(object string) (diskFrame, error) {
	bytes, err := os.ReadFile(source.path(object))
	if errors.Is(err, os.ErrNotExist) {
		return diskFrame{}, nil
	}
	if err != nil {
		return diskFrame{}, err
	}
	var frame diskFrame
	if err := json.Unmarshal(bytes, &frame); err != nil {
		return diskFrame{}, err
	}
	return frame, nil
}

func (source *fileSource) Transaction(ctx context.Context, object string, callback func(celld.Transaction) error) (celld.CommitToken, error) {
	source.transactions.Add(1)
	source.mu.Lock()
	defer source.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return celld.CommitToken{}, err
	}
	frame, err := source.read(object)
	if err != nil {
		return celld.CommitToken{}, err
	}
	if source.skipCallback {
		return celld.CommitToken{ObjectID: object, Revision: 1}, nil
	}
	tx := &fileTransaction{state: bytes.Clone(frame.State), failWrite: source.failWrite}
	if err := callback(tx); err != nil {
		return celld.CommitToken{}, err
	}
	if err := ctx.Err(); err != nil {
		return celld.CommitToken{}, err
	}
	if tx.changed || frame.Revision == 0 {
		frame.Revision++
		frame.State = tx.state
		if err := source.persist(object, frame); err != nil {
			return celld.CommitToken{}, err
		}
	}
	token := celld.CommitToken{ObjectID: object, Revision: frame.Revision}
	if source.wrongToken && tx.changed {
		token.ObjectID = "wrong-object"
	}
	return token, nil
}

func (source *fileSource) persist(object string, frame diskFrame) error {
	data, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(source.directory, "auth-transaction-*")
	if err != nil {
		return err
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(path, source.path(object)); err != nil {
		return err
	}
	directory, err := os.Open(source.directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (source *fileSource) DurabilityBarrier(ctx context.Context, token celld.CommitToken) error {
	source.mu.Lock()
	defer source.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if source.failBarrier && token.Revision > 1 {
		return errors.New("private-native-credential-diagnostic")
	}
	frame, err := source.read(token.ObjectID)
	if err != nil || frame.Revision < token.Revision || token.Revision == 0 {
		return errors.New("invalid barrier")
	}
	return nil
}

type fileTransaction struct {
	state              []byte
	changed, failWrite bool
}

func (tx *fileTransaction) ReadState() ([]byte, error) { return bytes.Clone(tx.state), nil }
func (*fileTransaction) LookupReceipt(string) (celld.StoredReceipt, bool, error) {
	return celld.StoredReceipt{}, false, nil
}
func (tx *fileTransaction) WriteState(state []byte) error {
	if tx.failWrite {
		return errors.New("private-native-credential-diagnostic")
	}
	tx.state = bytes.Clone(state)
	tx.changed = true
	return nil
}
func (*fileTransaction) WriteReceipt(string, celld.StoredReceipt) error {
	return errors.New("unexpected receipt")
}

type fixture struct {
	store        *PATStore
	source       *fileSource
	service      *auth.PATService
	now          atomic.Int64
	tenant, user string
}

func typedID(t *testing.T, kind identity.Kind) string {
	t.Helper()
	id, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte{3}, 16))}).New(kind)
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}
func newFixture(t *testing.T, bound int) *fixture {
	t.Helper()
	p := proof.NewProductionProofs(t, []dependency.AtomicGroup{AtomicCredentialAudit})
	source := &fileSource{ProductionProofs: p, directory: t.TempDir()}
	f := &fixture{source: source, tenant: typedID(t, identity.Tenant), user: typedID(t, identity.Subject)}
	f.now.Store(time.Unix(2_000_000_000, 123).UnixNano())
	store, err := New(Config{Source: proof.Verify[Source](t, p, source, []dependency.AtomicGroup{AtomicCredentialAudit}), TenantID: f.tenant, Now: f.clock, MaximumAuditEntries: bound})
	if err != nil {
		t.Fatal(err)
	}
	f.store = store
	f.service = newService(t, store, f.clock)
	return f
}
func (f *fixture) clock() time.Time { return time.Unix(0, f.now.Load()).UTC() }
func newService(t *testing.T, store auth.PATStore, clock func() time.Time) *auth.PATService {
	t.Helper()
	service, err := auth.NewPATService(auth.PATServiceConfig{Store: store, Now: clock, MaximumCASRetries: 128})
	if err != nil {
		t.Fatal(err)
	}
	return service
}
func issue(t *testing.T, f *fixture) (string, auth.PATRecord) {
	t.Helper()
	token, record, err := f.service.Issue(context.Background(), f.tenant, f.user, []string{"events:read", "turns:create"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return token, record
}

func TestNativeCredentialQualificationIsIndependentAndRequired(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatal(err)
	}
	p := proof.NewProductionProofs(t, []dependency.AtomicGroup{dependency.AtomicCommandReceipt})
	source := &fileSource{ProductionProofs: p, directory: t.TempDir()}
	if _, err := New(Config{Source: proof.Verify[Source](t, p, source, p.Descriptor().AtomicGroups), TenantID: typedID(t, identity.Tenant), Now: time.Now}); !errors.Is(err, dependency.ErrRequirementMismatch) {
		t.Fatal(err)
	}
	f := newFixture(t, 0)
	response, err := f.store.ProbeProduction(context.Background(), dependency.ProbeChallenge{Nonce: bytes.Repeat([]byte{4}, 32)})
	if err != nil || response.Descriptor.TransactionDomainID != f.source.Descriptor().TransactionDomainID || len(response.Signature) != 64 {
		t.Fatal("adapter fabricated source qualification", err)
	}
	for _, mode := range []string{"tenant", "clock", "records", "audit", "bytes"} {
		config := Config{Source: f.store.binding, TenantID: f.tenant, Now: f.clock}
		switch mode {
		case "tenant":
			config.TenantID = f.user
		case "clock":
			config.Now = nil
		case "records":
			config.MaximumRecords = -1
		case "audit":
			config.MaximumAuditEntries = maximumAuditEntries + 1
		case "bytes":
			config.MaximumStateBytes = maximumStateBytes + 1
		}
		if _, err := New(config); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("%s %v", mode, err)
		}
	}
}

func TestPATServiceDurableCurrentRecordAtomicAuditAndReopen(t *testing.T) {
	f := newFixture(t, 0)
	token, record := issue(t, f)
	f.now.Add(int64(time.Second))
	principal, err := f.service.Authenticate(context.Background(), token, "turns:create")
	if err != nil || principal.TenantID != f.tenant || principal.UserID != f.user || principal.PATID != record.ID {
		t.Fatal(principal, err)
	}
	// Reopen both the file-backed source and the adapter, retaining only the
	// original qualification fixture identity, not any credential/audit cache.
	source := &fileSource{ProductionProofs: f.source.ProductionProofs, directory: f.source.directory}
	reopened, err := New(Config{Source: proof.Verify[Source](t, source.ProductionProofs, source, []dependency.AtomicGroup{AtomicCredentialAudit}), TenantID: f.tenant, Now: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	current, err := reopened.LoadPATByDigest(context.Background(), record.Digest)
	if err != nil || current.Version != 2 || current.UseCount != 1 || !current.LastUsedAt.Equal(f.clock()) {
		t.Fatal(current.Version, err)
	}
	current.Scopes[0] = "mutated"
	current, err = reopened.LoadPATByID(context.Background(), record.ID)
	if err != nil || current.Scopes[0] != "events:read" {
		t.Fatal("returned scopes alias durable bytes", err)
	}
	f.now.Add(int64(time.Second))
	service := newService(t, reopened, f.clock)
	if _, err := service.Revoke(context.Background(), record.ID, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(context.Background(), token, "turns:create"); !errors.Is(err, auth.ErrCredentialRevoked) {
		t.Fatal(err)
	}
	page, err := reopened.ReadAudit(context.Background(), 0, 2)
	frame, snapshotErr := source.read(reopened.objectID)
	if snapshotErr != nil || page.TenantID != f.tenant || page.ObjectID != reopened.objectID || page.StateDigest != sha256.Sum256(frame.State) {
		t.Fatal("audit snapshot was relabeled or does not bind the exact source bytes", snapshotErr)
	}
	if err != nil || len(page.Entries) != 2 || page.HeadSequence != 3 || page.Entries[0].PreviousDigest != zeroDigest ||
		page.Entries[1].PreviousDigest != page.Entries[0].Digest || page.Entries[1].Event.Scope != "turns:create" {
		t.Fatal("audit chain changed", err)
	}
	last, err := reopened.ReadAudit(context.Background(), 2, 1024)
	if err != nil || len(last.Entries) != 1 || last.Entries[0].Event.Kind != auth.PATAuditRevoked || last.HeadDigest != last.Entries[0].Digest {
		t.Fatal("revocation audit missing", err)
	}
	data, err := os.ReadFile(source.path(reopened.objectID))
	if err != nil || bytes.Contains(data, []byte(token)) {
		t.Fatal("plaintext credential stored", err)
	}
}

func TestPATAuthenticationCannotOutrunRevocationOrExpiry(t *testing.T) {
	for _, mode := range []string{"expiry", "revoked", "stale-version", "scope", "future-time", "tenant", "identity", "scopes", "expiry-change"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, 0)
			_, record := issue(t, f)
			next := cloneRecord(record)
			next.Version++
			next.UseCount++
			next.LastUsedAt = f.clock().Add(time.Second)
			event := auth.PATAuditEvent{At: next.LastUsedAt, Kind: auth.PATAuditUsed, PATID: record.ID, TenantID: f.tenant, UserID: f.user, Scope: "turns:create"}
			f.now.Add(int64(2 * time.Second))
			expected := record.Version
			want := auth.ErrInvalidCredential
			switch mode {
			case "expiry":
				f.now.Add(int64(time.Hour))
			case "revoked":
				if _, err := f.service.Revoke(context.Background(), record.ID, record.Version); err != nil {
					t.Fatal(err)
				}
				want = auth.ErrPATVersionConflict
			case "stale-version":
				expected++
				want = auth.ErrPATVersionConflict
			case "scope":
				event.Scope = "administrator:all"
			case "future-time":
				event.At = f.clock().Add(time.Second)
				next.LastUsedAt = event.At
			case "tenant":
				next.TenantID = typedID(t, identity.Subject)
			case "identity":
				next.UserID = typedID(t, identity.Tenant)
			case "scopes":
				next.Scopes = []string{"administrator:all"}
			case "expiry-change":
				next.ExpiresAt = record.ExpiresAt.Add(time.Hour)
			}
			if err := f.store.CommitPAT(context.Background(), record.ID, expected, next, event); !errors.Is(err, want) {
				t.Fatalf("got %v want %v", err, want)
			}
			current, err := f.store.LoadPATByID(context.Background(), record.ID)
			if err != nil || current.UseCount != 0 {
				t.Fatal("failed authentication changed credential", err)
			}
			page, err := f.store.ReadAudit(context.Background(), 0, 1024)
			wantEvents := 1
			if mode == "revoked" {
				wantEvents++
			}
			if err != nil || len(page.Entries) != wantEvents {
				t.Fatal("failed authentication appended audit", err)
			}
		})
	}
}

func TestAtomicOutboxFailureAndUnconfirmedDurabilityReturnNoPrincipal(t *testing.T) {
	for _, mode := range []string{"write", "capacity", "barrier", "no-callback", "wrong-token"} {
		t.Run(mode, func(t *testing.T) {
			bound := 0
			if mode == "capacity" {
				bound = 1
			}
			f := newFixture(t, bound)
			token, record := issue(t, f)
			switch mode {
			case "write":
				f.source.failWrite = true
			case "barrier":
				f.source.failBarrier = true
			case "no-callback":
				f.source.skipCallback = true
			case "wrong-token":
				f.source.wrongToken = true
			}
			principal, err := f.service.Authenticate(context.Background(), token, "turns:create")
			if err == nil || principal != (auth.PATPrincipal{}) || strings.Contains(err.Error(), "private-native") {
				t.Fatal("unsafe failed authentication", err)
			}
			f.source.failWrite, f.source.failBarrier, f.source.skipCallback, f.source.wrongToken = false, false, false, false
			current, err := f.store.LoadPATByID(context.Background(), record.ID)
			if err != nil {
				t.Fatal(err)
			}
			page, err := f.store.ReadAudit(context.Background(), 0, 1024)
			if err != nil {
				t.Fatal(err)
			}
			committed := mode == "barrier" || mode == "wrong-token"
			if committed {
				if current.UseCount != 1 || len(page.Entries) != 2 {
					t.Fatal("lost committed atomic outbox")
				}
			} else if current.UseCount != 0 || len(page.Entries) != 1 {
				t.Fatal("failed write did not roll back atomically")
			}
		})
	}
}

func TestConcurrentAuthenticationHasContiguousVersionedAudit(t *testing.T) {
	f := newFixture(t, 0)
	token, record := issue(t, f)
	var wg sync.WaitGroup
	errorsCh := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.service.Authenticate(context.Background(), token, "turns:create")
			errorsCh <- err
		}()
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	current, err := f.store.LoadPATByID(context.Background(), record.ID)
	if err != nil || current.UseCount != 12 || current.Version != 13 {
		t.Fatal("CAS authentication lost writes", err)
	}
	page, err := f.store.ReadAudit(context.Background(), 0, 1024)
	if err != nil || len(page.Entries) != 13 {
		t.Fatal(err)
	}
	for i, entry := range page.Entries {
		if entry.Sequence != uint64(i+1) || entry.CredentialVersion != uint64(i+1) {
			t.Fatal("audit sequence has a gap")
		}
	}
}

func TestTamperedDurableCredentialsAndAuditFailClosedWithoutDiagnostics(t *testing.T) {
	for _, mode := range []string{"chain", "event", "head", "scope", "duplicate", "schema", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, 0)
			_, record := issue(t, f)
			frame, err := f.source.read(f.store.objectID)
			if err != nil {
				t.Fatal(err)
			}
			value, err := canonical.Decode(frame.State, canonical.DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			state := value.(canonical.Map)
			switch mode {
			case "chain":
				state["audit"].(canonical.Array)[0].(canonical.Map)["previousDigest"] = record.Digest
			case "event":
				state["audit"].(canonical.Array)[0].(canonical.Map)["event"].(canonical.Map)["userId"] = "different"
			case "head":
				state["headDigest"] = record.Digest
			case "scope":
				state["records"].(canonical.Array)[0].(canonical.Map)["tenantId"] = "different"
			case "duplicate":
				state["records"] = append(state["records"].(canonical.Array), state["records"].(canonical.Array)[0])
			case "schema":
				state["version"] = int64(2)
			case "malformed":
				state["headDigest"] = canonical.Map{"bad": canonical.Array{true}}
			}
			frame.State, err = canonical.Encode(state, canonical.DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			if err := f.source.persist(f.store.objectID, frame); err != nil {
				t.Fatal(err)
			}
			if result, err := f.store.LoadPATByID(context.Background(), record.ID); !errors.Is(err, ErrCorruptState) || result.ID != "" {
				t.Fatal("corruption accepted", err)
			}
		})
	}
}

func TestCredentialSnapshotBoundsRejectBeforeNativeIO(t *testing.T) {
	f := newFixture(t, 0)
	_, record := issue(t, f)
	before := f.source.transactions.Load()
	oversized := record
	oversized.Scopes = make([]string, 129)
	event := auth.PATAuditEvent{At: record.IssuedAt, Kind: auth.PATAuditIssued, PATID: record.ID, TenantID: record.TenantID, UserID: record.UserID}
	if err := f.store.CreatePAT(context.Background(), oversized, event); !errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatal(err)
	}
	if err := f.store.CommitPAT(context.Background(), record.ID, record.Version, oversized, event); !errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatal(err)
	}
	if f.source.transactions.Load() != before {
		t.Fatal("unbounded caller snapshot reached native storage")
	}
	snapshot, err := f.store.ReadAuditSnapshot(context.Background())
	frame, frameErr := f.source.read(f.store.objectID)
	if err != nil || frameErr != nil || snapshot.TenantID != f.tenant || snapshot.ObjectID != f.store.objectID || snapshot.StateDigest != sha256.Sum256(frame.State) || snapshot.HeadSequence != 1 {
		t.Fatal("checkpoint snapshot lost original identity or state bytes", err, frameErr)
	}
}
