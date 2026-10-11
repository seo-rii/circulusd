package publicbootstrap_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/auth"
	"github.com/hancomac/circulusd/internal/authstate"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/dependency"
	contract "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/publicbootstrap"
)

// The storage/proofs here are explicit test fixtures. The test exercises the
// concrete authstate codecs, transitions, CAS, audit chain and barriers through
// the real public handler, without claiming an external durability run.
type authTransactionSource struct {
	*contract.ProductionProofs
	mu           sync.Mutex
	objects      map[string]authObject
	barrierError error
}
type authObject struct {
	data     []byte
	revision uint64
}
type authTransaction struct {
	data  []byte
	dirty bool
}

func (tx *authTransaction) ReadState() ([]byte, error) { return bytes.Clone(tx.data), nil }
func (tx *authTransaction) WriteState(data []byte) error {
	tx.data, tx.dirty = bytes.Clone(data), true
	return nil
}
func (*authTransaction) LookupReceipt(string) (celld.StoredReceipt, bool, error) {
	return celld.StoredReceipt{}, false, errors.New("test: no receipt access expected")
}
func (*authTransaction) WriteReceipt(string, celld.StoredReceipt) error {
	return errors.New("test: no receipt write expected")
}
func (source *authTransactionSource) Transaction(ctx context.Context, id string, callback func(celld.Transaction) error) (celld.CommitToken, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return celld.CommitToken{}, err
	}
	object := source.objects[id]
	tx := &authTransaction{data: bytes.Clone(object.data)}
	if err := callback(tx); err != nil {
		return celld.CommitToken{}, err
	}
	if tx.dirty {
		object = authObject{data: bytes.Clone(tx.data), revision: object.revision + 1}
		source.objects[id] = object
	}
	return celld.CommitToken{ObjectID: id, Revision: object.revision}, nil
}
func (source *authTransactionSource) DurabilityBarrier(ctx context.Context, token celld.CommitToken) error {
	source.mu.Lock()
	defer source.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if source.barrierError != nil {
		return source.barrierError
	}
	if object, ok := source.objects[token.ObjectID]; !ok || token.Revision == 0 || token.Revision > object.revision {
		return errors.New("test: invalid token")
	}
	return nil
}

func TestConcreteCredentialAuditAndACLAdaptersComposeWithPublicHTTP(t *testing.T) {
	f := newFixture(t)
	groups := []dependency.AtomicGroup{authstate.AtomicCredentialAudit}
	source := &authTransactionSource{ProductionProofs: contract.NewProductionProofs(t, groups), objects: map[string]authObject{}}
	storeConfig := authstate.Config{Source: contract.Verify[authstate.Source](t, source.ProductionProofs, source, groups), TenantID: f.state.principal.TenantID, Now: f.config.Now}
	store, err := authstate.New(storeConfig)
	if err != nil {
		t.Fatal(err)
	}
	pat, err := auth.NewPATService(auth.PATServiceConfig{Store: store, Now: f.config.Now, MaximumCASRetries: 4})
	if err != nil {
		t.Fatal(err)
	}
	token, record, err := pat.Issue(context.Background(), f.state.principal.TenantID, f.state.principal.SubjectID, []string{f.config.CreateTurnScope, f.config.ReadEventsScope}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	stateGroups := []dependency.AtomicGroup{authstate.AtomicACLAuthorization, dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent}
	authorizer, err := authstate.NewAuthorizer(contract.Verify[authstate.AuthorizationSource](t, f.state.ProductionProofs, f.state, stateGroups))
	if err != nil {
		t.Fatal(err)
	}
	f.config.Authorizer = contract.Verify[publicbootstrap.SessionAuthorizer](t, f.state.ProductionProofs, authorizer, stateGroups)
	f.config.Credentials = contract.Verify[publicbootstrap.CredentialStore](t, source.ProductionProofs, store, groups)
	graph, err := publicbootstrap.New(context.Background(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	// A failed durable-read barrier cannot expose a PAT principal or reach ACL.
	source.barrierError = errors.New("private credential barrier details")
	if response := post(graph, f.state.sessionID, token); response.Code != http.StatusUnauthorized || len(f.state.authorizations) != 0 || len(f.state.admissions) != 0 {
		t.Fatal("failed credential barrier reached Session authority")
	}
	source.barrierError = nil
	if response := post(graph, f.state.sessionID, token); response.Code != http.StatusAccepted {
		t.Fatalf("POST=%d/%s", response.Code, response.Body)
	}
	graph.Close()
	// Reconstruct both store and public graph from the same committed bytes.
	reopened, err := authstate.New(storeConfig)
	if err != nil {
		t.Fatal(err)
	}
	f.config.Credentials = contract.Verify[publicbootstrap.CredentialStore](t, source.ProductionProofs, reopened, groups)
	graph, err = publicbootstrap.New(context.Background(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	defer graph.Close()
	if response := post(graph, f.state.sessionID, token); response.Code != http.StatusOK {
		t.Fatalf("replay=%d/%s", response.Code, response.Body)
	}
	page, err := reopened.ReadAudit(context.Background(), 0, 32)
	if err != nil {
		t.Fatal(err)
	}
	if page.HeadSequence != 3 || len(page.Entries) != 3 || page.HeadDigest != page.Entries[2].Digest || page.Entries[2].PreviousDigest != page.Entries[1].Digest {
		t.Fatal("credential audit did not survive reconstruction")
	}
	loaded, err := reopened.LoadPATByID(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.UseCount != 2 || loaded.Version != 3 {
		t.Fatal("public requests bypassed concrete credential CAS")
	}
	pat, err = auth.NewPATService(auth.PATServiceConfig{Store: reopened, Now: f.config.Now, MaximumCASRetries: 4})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pat.Revoke(context.Background(), loaded.ID, loaded.Version); err != nil {
		t.Fatal(err)
	}
	if response := post(graph, f.state.sessionID, token); response.Code != http.StatusUnauthorized || len(f.state.admissions) != 2 {
		t.Fatal("revoked credential reached admission")
	}
}
