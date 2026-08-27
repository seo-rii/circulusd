package secret_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/secret"
)

const (
	tenantID     = "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	subjectID    = "subject_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	sessionID    = "sess_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	workspaceID  = "ws_AAAAAAAAAAAAAAAAAAAAAAAAAA"
	invocationID = "inv_AAAAAAAAAAAAAAAAAAAAAAAAAA"
)

type allowingAuthorizer struct {
	mu       sync.Mutex
	requests []secret.AuthorizationRequest
	err      error
	order    *[]string
}

func (authorizer *allowingAuthorizer) Authorize(_ context.Context, request secret.AuthorizationRequest) error {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	if authorizer.order != nil {
		*authorizer.order = append(*authorizer.order, "authorize")
	}
	authorizer.requests = append(authorizer.requests, request)
	return authorizer.err
}

func (authorizer *allowingAuthorizer) Admit(
	_ context.Context,
	request secret.UseAdmissionRequest,
) (secret.UseAdmissionPermit, error) {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	if authorizer.order != nil {
		*authorizer.order = append(*authorizer.order, "admit")
	}
	if authorizer.err != nil {
		return secret.UseAdmissionPermit{}, authorizer.err
	}
	return secret.UseAdmissionPermit{
		Authorization: request.Authorization, HandleExpiresAt: request.HandleExpiresAt,
		IssuedAt: request.RequestedAt, ExpiresAt: request.HandleExpiresAt,
		Proof: "test-admission-proof",
	}, nil
}

type recordingAudit struct {
	mu      sync.Mutex
	events  []secret.AuditEvent
	durable bool
	err     error
	order   *[]string
}

type allowingRecoveryAuthorizer struct {
	mu       sync.Mutex
	requests []secret.RecoveryAuthorizationRequest
	err      error
}

func (authorizer *allowingRecoveryAuthorizer) AuthorizeRecovery(
	_ context.Context,
	request secret.RecoveryAuthorizationRequest,
) error {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	authorizer.requests = append(authorizer.requests, request)
	return authorizer.err
}

type recordingRecoveryAudit struct {
	mu      sync.Mutex
	events  []secret.RecoveryAuditEvent
	durable bool
	err     error
}

func (audit *recordingRecoveryAudit) AppendRecovery(
	_ context.Context,
	event secret.RecoveryAuditEvent,
) (secret.AuditReceipt, error) {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	audit.events = append(audit.events, event)
	return secret.AuditReceipt{Durable: audit.durable, Sequence: uint64(len(audit.events))}, audit.err
}

func (audit *recordingAudit) Append(_ context.Context, event secret.AuditEvent) (secret.AuditReceipt, error) {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if audit.order != nil {
		*audit.order = append(*audit.order, "audit")
	}
	audit.events = append(audit.events, event)
	return secret.AuditReceipt{Durable: audit.durable, Sequence: uint64(len(audit.events))}, audit.err
}

type recordingGateway struct {
	mu                  sync.Mutex
	calls               int
	recoveryCalls       int
	credential          []byte
	response            []byte
	err                 error
	panicOnDispatch     bool
	recoveryErr         error
	recoveryUnsafe      bool
	recoveryReceipt     secret.GatewayRecoveryReference
	recoveryHadDeadline bool
}

type incompleteRecoveryGateway struct {
	*recordingGateway
}

func (*incompleteRecoveryGateway) Capabilities() secret.GatewayCapabilities {
	return secret.GatewayCapabilities{}
}

func (*recordingGateway) Capabilities() secret.GatewayCapabilities {
	return secret.GatewayCapabilities{DurableRecovery: true, IdempotentRecovery: true}
}

func (gateway *recordingGateway) Dispatch(
	_ context.Context,
	dispatch secret.GatewayDispatch,
	credential secret.CredentialMaterial,
) (secret.GatewayResponse, error) {
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	if gateway.panicOnDispatch {
		panic("gateway panic after receiving credential")
	}
	gateway.calls++
	gateway.credential = append([]byte(nil), credential.Value...)
	for index := range credential.Value {
		credential.Value[index] = 0
	}
	return secret.GatewayResponse{
		Payload: append([]byte(nil), gateway.response...), Recovery: dispatch.Recovery,
		RecoveryDurable: true,
	}, gateway.err
}

func (gateway *recordingGateway) Recover(
	ctx context.Context,
	dispatch secret.GatewayRecoveryDispatch,
) (secret.GatewayRecoveryReceipt, error) {
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	gateway.recoveryCalls++
	_, gateway.recoveryHadDeadline = ctx.Deadline()
	recovery := gateway.recoveryReceipt
	if recovery == (secret.GatewayRecoveryReference{}) {
		recovery = dispatch.Recovery
	}
	return secret.GatewayRecoveryReceipt{
		Recovery: recovery, Durable: !gateway.recoveryUnsafe,
		SafeToRelease: !gateway.recoveryUnsafe,
	}, gateway.recoveryErr
}

type recordingSandbox struct {
	mu                    sync.Mutex
	calls                 int
	credential            []byte
	dispatches            []secret.SandboxDispatch
	receipt               secret.SandboxCleanupReceipt
	err                   error
	order                 *[]string
	prepareCalls          int
	cleanupCalls          int
	quarantineCalls       int
	cleanupConfirmed      bool
	quarantineDurable     bool
	quarantineCacheKey    string
	panicOnUse            bool
	panicOnPrepare        bool
	cleanupHadDeadline    bool
	quarantineHadDeadline bool
}

type advancingPrepareSandbox struct {
	*recordingSandbox
	advance func()
}

func (sandbox *advancingPrepareSandbox) Prepare(
	ctx context.Context,
	dispatch secret.SandboxDispatch,
	recovery secret.SandboxRecoveryReference,
) (secret.SandboxExposurePermit, error) {
	permit, err := sandbox.recordingSandbox.Prepare(ctx, dispatch, recovery)
	sandbox.advance()
	return permit, err
}

func (sandbox *recordingSandbox) Use(
	_ context.Context,
	dispatch secret.SandboxDispatch,
	permit secret.SandboxExposurePermit,
	credential secret.CredentialMaterial,
) (secret.SandboxCleanupReceipt, error) {
	sandbox.mu.Lock()
	defer sandbox.mu.Unlock()
	if sandbox.panicOnUse {
		panic("sandbox panic after receiving credential")
	}
	if sandbox.order != nil {
		*sandbox.order = append(*sandbox.order, "inject")
	}
	sandbox.calls++
	sandbox.dispatches = append(sandbox.dispatches, dispatch)
	sandbox.credential = append([]byte(nil), credential.Value...)
	receipt := sandbox.receipt
	if receipt.Recovery == (secret.SandboxRecoveryReference{}) {
		receipt.Recovery = permit.Recovery
	}
	return receipt, sandbox.err
}

func (sandbox *recordingSandbox) Prepare(
	_ context.Context,
	dispatch secret.SandboxDispatch,
	recovery secret.SandboxRecoveryReference,
) (secret.SandboxExposurePermit, error) {
	sandbox.mu.Lock()
	defer sandbox.mu.Unlock()
	sandbox.prepareCalls++
	if sandbox.panicOnPrepare {
		panic("sandbox panic after durable preparation")
	}
	if sandbox.order != nil {
		*sandbox.order = append(*sandbox.order, "prepare")
	}
	return secret.SandboxExposurePermit{
		InvocationID: dispatch.InvocationID, RecoveryID: recovery.RecoveryID,
		ResolvedCacheKey: dispatch.ResolvedCacheKey, Recovery: recovery, Durable: true,
	}, nil
}

func (sandbox *recordingSandbox) Cleanup(
	ctx context.Context,
	dispatch secret.SandboxDispatch,
	permit secret.SandboxExposurePermit,
) (secret.SandboxCleanupReceipt, error) {
	sandbox.mu.Lock()
	defer sandbox.mu.Unlock()
	sandbox.cleanupCalls++
	_, sandbox.cleanupHadDeadline = ctx.Deadline()
	if sandbox.order != nil {
		*sandbox.order = append(*sandbox.order, "cleanup")
	}
	if !sandbox.cleanupConfirmed {
		return secret.SandboxCleanupReceipt{InvocationID: dispatch.InvocationID}, nil
	}
	return secret.SandboxCleanupReceipt{
		InvocationID: dispatch.InvocationID, FileRemoved: true,
		EnvironmentCleared: true, SandboxDestroyed: true, Recovery: permit.Recovery,
	}, nil
}

func (sandbox *recordingSandbox) Quarantine(
	ctx context.Context,
	dispatch secret.SandboxDispatch,
	permit secret.SandboxExposurePermit,
) (secret.SandboxQuarantineReceipt, error) {
	sandbox.mu.Lock()
	defer sandbox.mu.Unlock()
	sandbox.quarantineCalls++
	_, sandbox.quarantineHadDeadline = ctx.Deadline()
	if sandbox.order != nil {
		*sandbox.order = append(*sandbox.order, "quarantine")
	}
	resolvedCacheKey := sandbox.quarantineCacheKey
	if resolvedCacheKey == "" {
		resolvedCacheKey = dispatch.ResolvedCacheKey
	}
	return secret.SandboxQuarantineReceipt{
		InvocationID: dispatch.InvocationID, RecoveryID: permit.RecoveryID,
		ResolvedCacheKey: resolvedCacheKey, Durable: sandbox.quarantineDurable,
	}, nil
}

type recordingTokenMinter struct {
	mu          sync.Mutex
	request     secret.TokenMintRequest
	value       []byte
	expires     time.Time
	err         error
	returnSeed  bool
	panicOnMint bool
}

func (minter *recordingTokenMinter) Mint(
	_ context.Context,
	request secret.TokenMintRequest,
) (secret.MintedToken, error) {
	minter.mu.Lock()
	defer minter.mu.Unlock()
	minter.request = request
	if minter.panicOnMint {
		panic("token minter panic after receiving seed")
	}
	if minter.returnSeed {
		return secret.MintedToken{Value: request.Seed, ExpiresAt: minter.expires}, minter.err
	}
	return secret.MintedToken{Value: minter.value, ExpiresAt: minter.expires}, minter.err
}

type observingStore struct {
	mu         sync.Mutex
	record     secret.Record
	lastRead   []byte
	order      *[]string
	getErr     error
	beginErr   error
	acquireErr error
}

func (store *observingStore) Get(
	_ context.Context,
	tenant string,
	secretID string,
) (secret.Record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.order != nil {
		*store.order = append(*store.order, "get")
	}
	if tenant != store.record.TenantID || secretID != store.record.SecretID {
		return secret.Record{}, secret.ErrSecretNotFound
	}
	copy := store.record
	copy.Value = append([]byte(nil), store.record.Value...)
	store.lastRead = copy.Value
	return copy, store.getErr
}

func (store *observingStore) BeginUse(
	ctx context.Context,
	request secret.BeginUseRequest,
) (secret.Record, secret.UseLease, error) {
	record, err := store.Get(ctx, request.TenantID, request.SecretID)
	if err != nil {
		return secret.Record{}, secret.UseLease{}, err
	}
	if !record.Active || record.Version != request.ExpectedVersion {
		return secret.Record{}, secret.UseLease{}, secret.ErrSecretNotFound
	}
	return record, secret.UseLease{
		LeaseID: "lease_AAAAAAAAAAAAAAAAAAAAAAAAAA", TenantID: request.TenantID,
		SecretID: request.SecretID, Version: request.ExpectedVersion,
	}, store.beginErr
}

func (*observingStore) EndUse(context.Context, secret.UseLease) error { return nil }

func (store *observingStore) ReserveUse(
	ctx context.Context,
	request secret.ReserveUseRequest,
) (secret.UseLease, error) {
	record, lease, err := store.BeginUse(ctx, request)
	clear(record.Value)
	return lease, err
}

func (store *observingStore) AcquireReservedUse(
	ctx context.Context,
	request secret.AcquireReservedUseRequest,
) (secret.Record, error) {
	record, err := store.Get(ctx, request.TenantID, request.SecretID)
	if err != nil {
		return record, err
	}
	return record, store.acquireErr
}

func (*observingStore) ValidateUseRecovery(context.Context, secret.UseRecoveryBinding) error {
	return secret.ErrUseLeaseInvalid
}

func (*observingStore) CompleteUseRecovery(context.Context, secret.UseRecoveryBinding) error {
	return secret.ErrUseLeaseInvalid
}

func (*observingStore) Capabilities() secret.StoreCapabilities {
	return secret.StoreCapabilities{
		Durable: true, AtomicUseRecovery: true, AtomicAdmissionValidation: true,
		AtomicPreparedUse: true, BoundedRecoveryEnumeration: true,
	}
}

func (*observingStore) ListPendingUseRecoveries(
	context.Context,
	secret.PendingUseRecoveryQuery,
) (secret.PendingUseRecoveryPage, error) {
	return secret.PendingUseRecoveryPage{}, nil
}

type blockingAudit struct {
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

type failingEndUseStore struct {
	*secret.MemoryStore
	fail                bool
	commitBeforeFailure bool
}

func (store *failingEndUseStore) Capabilities() secret.StoreCapabilities {
	return secret.StoreCapabilities{
		Durable: true, AtomicUseRecovery: true, AtomicAdmissionValidation: true,
		AtomicPreparedUse: true, BoundedRecoveryEnumeration: true,
	}
}

func (store *failingEndUseStore) EndUse(ctx context.Context, lease secret.UseLease) error {
	if store.fail {
		if store.commitBeforeFailure {
			if err := store.MemoryStore.EndUse(ctx, lease); err != nil {
				return err
			}
		}
		return errors.New("durability acknowledgement lost")
	}
	return store.MemoryStore.EndUse(ctx, lease)
}

type durableMemoryStore struct {
	*secret.MemoryStore
}

func newDurableMemoryStore() *durableMemoryStore {
	return &durableMemoryStore{MemoryStore: secret.NewMemoryStore()}
}

func newDurableMemoryStoreWithClock(now func() time.Time) *durableMemoryStore {
	return &durableMemoryStore{MemoryStore: secret.NewMemoryStoreWithClock(now)}
}

func (*durableMemoryStore) Capabilities() secret.StoreCapabilities {
	return secret.StoreCapabilities{
		Durable: true, AtomicUseRecovery: true, AtomicAdmissionValidation: true,
		AtomicPreparedUse: true, BoundedRecoveryEnumeration: true,
	}
}

func (audit *blockingAudit) Append(_ context.Context, _ secret.AuditEvent) (secret.AuditReceipt, error) {
	audit.once.Do(func() { close(audit.entered) })
	<-audit.resume
	return secret.AuditReceipt{Durable: true, Sequence: 1}, nil
}

func (store *observingStore) readWasCleared() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, value := range store.lastRead {
		if value != 0 {
			return false
		}
	}
	return len(store.lastRead) > 0
}

func access() secret.AccessContext {
	return secret.AccessContext{
		TenantID: tenantID, SubjectID: subjectID, SessionID: sessionID, WorkspaceID: workspaceID,
		TurnID: "turn_AAAAAAAAAAAAAAAAAAAAAAAAAA", RuntimeRevision: "runtime_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		TurnLeaseGeneration: 5, PlacementGeneration: 7, SandboxGeneration: 11,
		AuthorizationGeneration: 3, Permission: "secret.use", ServiceBinding: "secret",
		AuthorityExpiresAt: time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC),
	}
}

func newTestService(config secret.Config) (*secret.Service, error) {
	if config.ServiceBinding == "" {
		config.ServiceBinding = "secret"
	}
	if config.RecoveryAuthorizer == nil {
		config.RecoveryAuthorizer = &allowingRecoveryAuthorizer{}
	}
	if config.RecoveryAudit == nil {
		config.RecoveryAudit = &recordingRecoveryAudit{durable: true}
	}
	return secret.NewService(config)
}

func TestServiceRejectsVolatileOrIncompleteSecretStore(t *testing.T) {
	for name, capabilities := range map[string]secret.StoreCapabilities{
		"volatile": {
			AtomicUseRecovery: true, AtomicAdmissionValidation: true, AtomicPreparedUse: true,
			BoundedRecoveryEnumeration: true,
		},
		"non-atomic recovery": {
			Durable: true, AtomicAdmissionValidation: true, AtomicPreparedUse: true,
			BoundedRecoveryEnumeration: true,
		},
		"non-atomic admission": {
			Durable: true, AtomicUseRecovery: true, AtomicPreparedUse: true,
			BoundedRecoveryEnumeration: true,
		},
		"non-atomic prepared use": {
			Durable: true, AtomicUseRecovery: true, AtomicAdmissionValidation: true,
			BoundedRecoveryEnumeration: true,
		},
		"unbounded recovery scan": {
			Durable: true, AtomicUseRecovery: true, AtomicAdmissionValidation: true,
			AtomicPreparedUse: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := &capabilityStore{MemoryStore: secret.NewMemoryStore(), capabilities: capabilities}
			_, err := newTestService(secret.Config{
				Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
				MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
			})
			if !errors.Is(err, secret.ErrStoreNotDurable) {
				t.Fatalf("NewService() error = %v, want ErrStoreNotDurable", err)
			}
		})
	}
}

func TestServiceRequiresDedicatedRecoveryAuthorityAndAudit(t *testing.T) {
	base := secret.Config{
		Store: newDurableMemoryStore(), Authorizer: &allowingAuthorizer{},
		Audit: &recordingAudit{durable: true}, MaximumRequestBytes: 1024,
		MaximumResponseBytes: 1024, ServiceBinding: "secret",
	}
	for name, configure := range map[string]func(*secret.Config){
		"missing authority": func(config *secret.Config) {
			config.RecoveryAudit = &recordingRecoveryAudit{durable: true}
		},
		"missing audit": func(config *secret.Config) {
			config.RecoveryAuthorizer = &allowingRecoveryAuthorizer{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			configure(&config)
			if _, err := secret.NewService(config); !errors.Is(err, secret.ErrInvalidConfig) {
				t.Fatalf("NewService() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestServiceRejectsTypedNilDependencies(t *testing.T) {
	base := secret.Config{
		Store: newDurableMemoryStore(), Authorizer: &allowingAuthorizer{},
		Audit: &recordingAudit{durable: true}, RecoveryAuthorizer: &allowingRecoveryAuthorizer{},
		RecoveryAudit:       &recordingRecoveryAudit{durable: true},
		MaximumRequestBytes: 1024, MaximumResponseBytes: 1024, ServiceBinding: "secret",
	}
	for name, configure := range map[string]func(*secret.Config){
		"store":      func(config *secret.Config) { config.Store = (*durableMemoryStore)(nil) },
		"authorizer": func(config *secret.Config) { config.Authorizer = (*allowingAuthorizer)(nil) },
		"admitter":   func(config *secret.Config) { config.Admitter = (*allowingAuthorizer)(nil) },
		"audit":      func(config *secret.Config) { config.Audit = (*recordingAudit)(nil) },
		"recovery authorizer": func(config *secret.Config) {
			config.RecoveryAuthorizer = (*allowingRecoveryAuthorizer)(nil)
		},
		"recovery audit": func(config *secret.Config) {
			config.RecoveryAudit = (*recordingRecoveryAudit)(nil)
		},
		"gateway":      func(config *secret.Config) { config.Gateway = (*recordingGateway)(nil) },
		"sandbox":      func(config *secret.Config) { config.Sandbox = (*recordingSandbox)(nil) },
		"token minter": func(config *secret.Config) { config.TokenMinter = (*recordingTokenMinter)(nil) },
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			configure(&config)
			var err error
			func() {
				defer func() {
					if panicValue := recover(); panicValue != nil {
						t.Fatalf("NewService() panicked for typed nil %s: %v", name, panicValue)
					}
				}()
				_, err = secret.NewService(config)
			}()
			if !errors.Is(err, secret.ErrInvalidConfig) {
				t.Fatalf("NewService(typed nil %s) error = %v, want ErrInvalidConfig", name, err)
			}
		})
	}
}

func TestServiceRejectsGatewayWithoutDurableIdempotentRecovery(t *testing.T) {
	_, err := newTestService(secret.Config{
		Store: newDurableMemoryStore(), Authorizer: &allowingAuthorizer{},
		Audit:               &recordingAudit{durable: true},
		Gateway:             &incompleteRecoveryGateway{recordingGateway: &recordingGateway{}},
		MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if !errors.Is(err, secret.ErrInvalidConfig) {
		t.Fatalf("NewService(incomplete gateway) error = %v, want ErrInvalidConfig", err)
	}
}

type capabilityStore struct {
	*secret.MemoryStore
	capabilities secret.StoreCapabilities
}

func (store *capabilityStore) Capabilities() secret.StoreCapabilities {
	return store.capabilities
}

func TestGatewayUseIsOpaqueTenantEndpointAudienceAndVersionBound(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	raw := []byte("top-secret-bearer")
	record := secret.Record{
		SecretID: "secret_primary", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureGatewayHeader, Value: raw,
		InjectionName: "Authorization", Endpoint: "https://model.internal/v1",
		Audience: "model.internal", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap(create) error = %v", err)
	}
	authorizer := &allowingAuthorizer{}
	audit := &recordingAudit{durable: true}
	gateway := &recordingGateway{response: []byte("ok")}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: authorizer, Audit: audit, Gateway: gateway,
		MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		Endpoint: record.Endpoint, Audience: record.Audience,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	for _, rendered := range []string{fmt.Sprint(handle), fmt.Sprintf("%#v", handle)} {
		if strings.Contains(rendered, string(raw)) || strings.Contains(rendered, record.SecretID) {
			t.Fatalf("opaque handle rendered sensitive data: %q", rendered)
		}
	}

	response, err := service.UseGateway(ctx, secret.GatewayUseRequest{
		Access: access(), Handle: handle, Endpoint: record.Endpoint, Audience: record.Audience,
		Payload: []byte("request"),
	})
	if err != nil || string(response.Payload) != "ok" {
		t.Fatalf("UseGateway() = %q, %v", response.Payload, err)
	}
	if string(gateway.credential) != string(raw) || gateway.calls != 1 {
		t.Fatalf("gateway credential/calls = %q/%d", gateway.credential, gateway.calls)
	}
	if string(raw) != "top-secret-bearer" {
		t.Fatal("dispatcher mutation escaped into caller-owned or stored secret bytes")
	}

	for name, mutate := range map[string]func(*secret.GatewayUseRequest){
		"tenant": func(request *secret.GatewayUseRequest) {
			request.Access.TenantID = "tenant_AAAAAAAAAAAAAAAAAAAAAAAAAB"
		},
		"endpoint": func(request *secret.GatewayUseRequest) { request.Endpoint += "/other" },
		"audience": func(request *secret.GatewayUseRequest) { request.Audience = "other.internal" },
	} {
		t.Run(name, func(t *testing.T) {
			request := secret.GatewayUseRequest{
				Access: access(), Handle: handle, Endpoint: record.Endpoint,
				Audience: record.Audience, Payload: []byte("request"),
			}
			mutate(&request)
			if _, err := service.UseGateway(ctx, request); err == nil {
				t.Fatal("UseGateway() accepted a handle outside its bound scope")
			}
		})
	}
	if gateway.calls != 1 {
		t.Fatalf("rejected requests reached gateway: calls = %d", gateway.calls)
	}

	rotated := record
	rotated.Version = 2
	rotated.Value = []byte("rotated-secret")
	if err := store.CompareAndSwap(ctx, 1, rotated); err != nil {
		t.Fatalf("CompareAndSwap(rotate) error = %v", err)
	}
	if _, err := service.UseGateway(ctx, secret.GatewayUseRequest{
		Access: access(), Handle: handle, Endpoint: record.Endpoint,
		Audience: record.Audience, Payload: []byte("request"),
	}); !errors.Is(err, secret.ErrStaleHandle) {
		t.Fatalf("UseGateway(old handle) error = %v, want ErrStaleHandle", err)
	}
}

func TestSandboxExposureRequiresDurableAuditAndConfirmedCleanup(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_sandbox", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureSandboxFile, Value: []byte("sandbox-secret"),
		InjectionName: "/run/credentials/service-token", Active: true,
		DestroySandboxAfterUse: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	order := []string{}
	audit := &recordingAudit{durable: true, order: &order}
	sandbox := &recordingSandbox{
		order:             &order,
		quarantineDurable: true,
		receipt: secret.SandboxCleanupReceipt{
			InvocationID: invocationID, FileRemoved: true, EnvironmentCleared: true,
			SandboxDestroyed: true,
		},
	}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: audit,
		Sandbox: sandbox, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		InvocationID: invocationID,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	receipt, err := service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: access(), Handle: handle, InvocationID: invocationID,
		BaseCacheKey: "sha256:" + strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatalf("UseSandbox() error = %v", err)
	}
	if !receipt.FileRemoved || !receipt.EnvironmentCleared || !receipt.SandboxDestroyed {
		t.Fatalf("cleanup receipt = %#v", receipt)
	}
	if fmt.Sprint(order) != "[audit prepare inject]" {
		t.Fatalf("raw exposure order = %v, want durable audit before injection", order)
	}
	if string(sandbox.credential) != "sandbox-secret" {
		t.Fatalf("sandbox credential = %q", sandbox.credential)
	}
	if len(sandbox.dispatches) != 1 || !sandbox.dispatches[0].DestroySandboxAfterUse {
		t.Fatalf("sandbox destroy policy was not dispatched: %#v", sandbox.dispatches)
	}

	audit.durable = false
	if _, err := service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: access(), Handle: handle, InvocationID: invocationID,
		BaseCacheKey: "sha256:" + strings.Repeat("a", 64),
	}); !errors.Is(err, secret.ErrAuditNotDurable) {
		t.Fatalf("UseSandbox(nondurable audit) error = %v, want ErrAuditNotDurable", err)
	}
	if sandbox.calls != 1 {
		t.Fatalf("nondurable audit reached injector: calls = %d", sandbox.calls)
	}

	audit.durable = true
	sandbox.receipt.SandboxDestroyed = false
	if _, err := service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: access(), Handle: handle, InvocationID: invocationID,
		BaseCacheKey: "sha256:" + strings.Repeat("a", 64),
	}); !errors.Is(err, secret.ErrCleanupUnconfirmed) {
		t.Fatalf("UseSandbox(incomplete cleanup) error = %v, want ErrCleanupUnconfirmed", err)
	}
}

func TestSecretBearingDependencyErrorsAreRedacted(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	raw := "credential-must-not-escape"
	record := secret.Record{
		SecretID: "secret_redaction", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureProxyOnly, Value: []byte(raw), InjectionName: "Authorization",
		Endpoint: "https://proxy.internal", Audience: "proxy.internal", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	gateway := &recordingGateway{err: fmt.Errorf("transport Authorization: Bearer %s", raw)}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Gateway: gateway, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		Endpoint: record.Endpoint, Audience: record.Audience,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	_, err = service.UseGateway(ctx, secret.GatewayUseRequest{
		Access: access(), Handle: handle, Endpoint: record.Endpoint,
		Audience: record.Audience, Payload: []byte("request"),
	})
	if !errors.Is(err, secret.ErrGatewayFailed) || strings.Contains(fmt.Sprint(err), raw) {
		t.Fatalf("UseGateway() leaked dependency error: %v", err)
	}
}

func TestSecretBearingTypesRejectGenericJSONSerialization(t *testing.T) {
	raw := []byte("credential-must-never-be-json")
	values := map[string]any{
		"record":              secret.Record{Value: append([]byte(nil), raw...)},
		"credential material": secret.CredentialMaterial{Value: append([]byte(nil), raw...)},
		"token mint request":  secret.TokenMintRequest{Seed: append([]byte(nil), raw...)},
		"minted token":        secret.MintedToken{Value: append([]byte(nil), raw...)},
		"admission permit":    secret.UseAdmissionPermit{Proof: string(raw)},
	}
	for name, value := range values {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(value)
			if !errors.Is(err, secret.ErrSensitiveSerialization) {
				t.Fatalf("json.Marshal() = %q, %v, want ErrSensitiveSerialization", encoded, err)
			}
			if strings.Contains(string(encoded), string(raw)) ||
				strings.Contains(string(encoded), base64.StdEncoding.EncodeToString(raw)) {
				t.Fatalf("json.Marshal() exposed raw material: %q", encoded)
			}
		})
	}
}

func TestIssueAuthorizationPrecedesSecretLookup(t *testing.T) {
	authorizer := &allowingAuthorizer{err: errors.New("denied")}
	service, err := newTestService(secret.Config{
		Store: newDurableMemoryStore(), Authorizer: authorizer,
		Audit: &recordingAudit{durable: true}, MaximumRequestBytes: 1024,
		MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	_, err = service.IssueHandle(context.Background(), secret.IssueRequest{
		Access: access(), SecretID: "secret_not_present", Exposure: secret.ExposureProxyOnly,
		Endpoint: "https://proxy.internal", Audience: "proxy.internal",
	})
	if !errors.Is(err, secret.ErrAccessDenied) {
		t.Fatalf("IssueHandle(denied missing secret) error = %v, want ErrAccessDenied", err)
	}
	if len(authorizer.requests) != 1 {
		t.Fatalf("authorization calls = %d, want 1 before lookup", len(authorizer.requests))
	}
}

func TestShortLivedTokenIsBoundExpiringAndZeroized(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 26, 12, 0, 0, 0, time.UTC)
	store := newDurableMemoryStoreWithClock(func() time.Time { return now })
	raw := []byte("long-lived-seed")
	record := secret.Record{
		SecretID: "secret_token", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureShortLivedToken, Value: raw,
		InjectionName: "Authorization", Endpoint: "https://model.internal/v1",
		Audience: "model.internal", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	issued := []byte("ephemeral-token")
	minter := &recordingTokenMinter{value: issued, expires: now.Add(2 * time.Minute)}
	gateway := &recordingGateway{response: []byte("ok")}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Gateway: gateway, TokenMinter: minter, Now: func() time.Time { return now },
		MaximumRequestBytes: 1024, MaximumResponseBytes: 1024, MaximumTokenTTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		Endpoint: record.Endpoint, Audience: record.Audience,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	if _, err := service.UseGateway(ctx, secret.GatewayUseRequest{
		Access: access(), Handle: handle, Endpoint: record.Endpoint,
		Audience: record.Audience, Payload: []byte("request"),
	}); err != nil {
		t.Fatalf("UseGateway() error = %v", err)
	}
	if string(gateway.credential) != "ephemeral-token" {
		t.Fatalf("gateway credential = %q", gateway.credential)
	}
	if minter.request.TenantID != tenantID || minter.request.SecretID != record.SecretID ||
		minter.request.Version != record.Version || minter.request.Endpoint != record.Endpoint ||
		minter.request.Audience != record.Audience || !minter.request.ExpiresBy.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("mint request is not fully bound: %#v", minter.request)
	}
	for _, value := range minter.request.Seed {
		if value != 0 {
			t.Fatalf("mint seed was retained after use: %v", minter.request.Seed)
		}
	}
	for _, value := range issued {
		if value != 0 {
			t.Fatalf("minted token was retained after copying: %v", issued)
		}
	}
	for name, value := range map[string]any{
		"record":       record,
		"mint request": minter.request,
		"minted token": secret.MintedToken{Value: []byte("token"), ExpiresAt: now},
	} {
		for _, rendered := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value)} {
			if !strings.Contains(rendered, "<redacted>") || strings.Contains(rendered, "long-lived-seed") {
				t.Fatalf("%s rendered secret-bearing fields: %q", name, rendered)
			}
		}
	}
}

func TestShortLivedTokenMinterMayReturnItsSeedBuffer(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_token_alias", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureShortLivedToken, Value: []byte("aliased-token-value"),
		InjectionName: "Authorization", Endpoint: "https://model.internal/v1",
		Audience: "model.internal", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	minter := &recordingTokenMinter{returnSeed: true, expires: time.Now().Add(time.Minute)}
	gateway := &recordingGateway{response: []byte("ok")}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Gateway: gateway, TokenMinter: minter,
		MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		Endpoint: record.Endpoint, Audience: record.Audience,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	if _, err := service.UseGateway(ctx, secret.GatewayUseRequest{
		Access: access(), Handle: handle, Endpoint: record.Endpoint,
		Audience: record.Audience, Payload: []byte("request"),
	}); err != nil {
		t.Fatalf("UseGateway() error = %v", err)
	}
	if string(gateway.credential) != "aliased-token-value" {
		t.Fatalf("gateway credential = %q, want aliased token snapshot", gateway.credential)
	}
}

func TestSandboxFailureReportsUnconfirmedCleanupAndIsolatesCache(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_cache", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureSandboxEnv, Value: []byte("sandbox-value"),
		InjectionName: "SERVICE_TOKEN", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	sandbox := &recordingSandbox{
		receipt: secret.SandboxCleanupReceipt{InvocationID: invocationID},
		err:     errors.New("spawn failed after injection"), quarantineDurable: true,
	}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Sandbox: sandbox, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		InvocationID: invocationID,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	base := "sha256:" + strings.Repeat("b", 64)
	_, err = service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: access(), Handle: handle, InvocationID: invocationID, BaseCacheKey: base,
	})
	if !errors.Is(err, secret.ErrCleanupUnconfirmed) {
		t.Fatalf("UseSandbox(failed, uncleared) error = %v, want ErrCleanupUnconfirmed", err)
	}
	if len(sandbox.dispatches) != 1 || sandbox.dispatches[0].ResolvedCacheKey == base ||
		!strings.HasPrefix(sandbox.dispatches[0].ResolvedCacheKey, "sha256:") ||
		strings.Contains(sandbox.dispatches[0].ResolvedCacheKey, record.SecretID) {
		t.Fatalf("resolved cache isolation key = %#v", sandbox.dispatches)
	}
}

func TestSandboxUseErrorAlwaysRunsBoundCleanup(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_error_cleanup", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureSandboxEnv, Value: []byte("sandbox-value"),
		InjectionName: "SERVICE_TOKEN", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	sandbox := &recordingSandbox{
		receipt: secret.SandboxCleanupReceipt{
			InvocationID: invocationID, EnvironmentCleared: true,
		},
		err: errors.New("injector failed after reporting cleanup"), cleanupConfirmed: true,
		quarantineDurable: true,
	}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Sandbox: sandbox, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		InvocationID: invocationID,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	_, err = service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: access(), Handle: handle, InvocationID: invocationID,
		BaseCacheKey: "sha256:" + strings.Repeat("1", 64),
	})
	if !errors.Is(err, secret.ErrSandboxFailed) {
		t.Fatalf("UseSandbox(use error) error = %v, want ErrSandboxFailed", err)
	}
	if sandbox.cleanupCalls != 1 {
		t.Fatalf("UseSandbox(use error) cleanup calls = %d, want 1", sandbox.cleanupCalls)
	}
	if !sandbox.cleanupHadDeadline {
		t.Fatal("UseSandbox(use error) cleanup context had no bounded deadline")
	}
}

func TestSandboxUseReceiptMustMatchPreparedRecoveryAndCache(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_receipt_binding", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureSandboxEnv, Value: []byte("sandbox-value"),
		InjectionName: "SERVICE_TOKEN", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	sandbox := &recordingSandbox{
		receipt: secret.SandboxCleanupReceipt{
			InvocationID: invocationID, EnvironmentCleared: true,
			Recovery: secret.SandboxRecoveryReference{
				RecoveryID:       "op_AAAAAAAAAAAAAAAAAAAAAAAAAB",
				ResolvedCacheKey: "sha256:" + strings.Repeat("2", 64),
			},
		},
		quarantineDurable: true,
	}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Sandbox: sandbox, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		InvocationID: invocationID,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	_, err = service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: access(), Handle: handle, InvocationID: invocationID,
		BaseCacheKey: "sha256:" + strings.Repeat("3", 64),
	})
	if !errors.Is(err, secret.ErrCleanupUnconfirmed) {
		t.Fatalf("UseSandbox(mismatched receipt) error = %v, want ErrCleanupUnconfirmed", err)
	}
	if sandbox.cleanupCalls != 1 || sandbox.quarantineCalls != 1 {
		t.Fatalf("mismatched receipt cleanup/quarantine calls = %d/%d, want 1/1",
			sandbox.cleanupCalls, sandbox.quarantineCalls)
	}
}

func TestSandboxQuarantineReceiptMustMatchPreparedCache(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_quarantine_binding", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureSandboxEnv, Value: []byte("sandbox-value"),
		InjectionName: "SERVICE_TOKEN", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	sandbox := &recordingSandbox{
		receipt:            secret.SandboxCleanupReceipt{InvocationID: invocationID},
		quarantineDurable:  true,
		quarantineCacheKey: "sha256:" + strings.Repeat("6", 64),
	}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Sandbox: sandbox, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		InvocationID: invocationID,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	receipt, err := service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: access(), Handle: handle, InvocationID: invocationID,
		BaseCacheKey: "sha256:" + strings.Repeat("7", 64),
	})
	if !errors.Is(err, secret.ErrContainmentUnconfirmed) || receipt.Recovery.RecoveryID == "" {
		t.Fatalf("UseSandbox(mismatched quarantine cache) = %#v, %v", receipt, err)
	}
}

func TestMemoryStoreCompareAndSwapIsAtomicAndClonesRecords(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_concurrent", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureProxyOnly, Value: []byte("initial"),
		InjectionName: "Authorization", Endpoint: "https://proxy.internal",
		Audience: "proxy.internal", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap(create) error = %v", err)
	}
	record.Value[0] = 'X'
	got, err := store.Get(ctx, tenantID, record.SecretID)
	if err != nil || string(got.Value) != "initial" {
		t.Fatalf("Get(after caller mutation) = %q, %v", got.Value, err)
	}
	got.Value[0] = 'Y'
	again, err := store.Get(ctx, tenantID, record.SecretID)
	if err != nil || string(again.Value) != "initial" {
		t.Fatalf("Get(after result mutation) = %q, %v", again.Value, err)
	}

	start := make(chan struct{})
	errorsByWriter := make(chan error, 2)
	for suffix := byte('a'); suffix <= 'b'; suffix++ {
		next := again
		next.Version = 2
		next.Value = []byte{suffix}
		go func() {
			<-start
			errorsByWriter <- store.CompareAndSwap(ctx, 1, next)
		}()
	}
	close(start)
	succeeded := 0
	conflicted := 0
	for range 2 {
		err := <-errorsByWriter
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, secret.ErrStoreConflict):
			conflicted++
		default:
			t.Fatalf("CompareAndSwap(concurrent) error = %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent CAS success/conflict = %d/%d, want 1/1", succeeded, conflicted)
	}
}

func TestServiceClearsEachStoreReadAfterUse(t *testing.T) {
	ctx := context.Background()
	store := &observingStore{record: secret.Record{
		SecretID: "secret_transient", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureProxyOnly, Value: []byte("transient-store-copy"),
		InjectionName: "Authorization", Endpoint: "https://proxy.internal",
		Audience: "proxy.internal", Active: true,
	}}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Gateway:             &recordingGateway{response: []byte("ok")},
		MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: store.record.SecretID, Exposure: store.record.Exposure,
		Endpoint: store.record.Endpoint, Audience: store.record.Audience,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	if !store.readWasCleared() {
		t.Fatal("IssueHandle() retained the store-owned read copy")
	}
	if _, err := service.UseGateway(ctx, secret.GatewayUseRequest{
		Access: access(), Handle: handle, Endpoint: store.record.Endpoint,
		Audience: store.record.Audience, Payload: []byte("request"),
	}); err != nil {
		t.Fatalf("UseGateway() error = %v", err)
	}
	if !store.readWasCleared() {
		t.Fatal("UseGateway() retained the store-owned read copy")
	}
}

func TestServiceClearsPartialStoreReadsReturnedWithErrors(t *testing.T) {
	t.Run("handle lookup", func(t *testing.T) {
		store := &observingStore{record: secret.Record{
			SecretID: "secret_partial_get", TenantID: tenantID, Version: 1,
			Exposure: secret.ExposureProxyOnly, Value: []byte("partial-get-value"),
			InjectionName: "Authorization", Endpoint: "https://proxy.internal",
			Audience: "proxy.internal", Active: true,
		}, getErr: errors.New("read acknowledgement lost")}
		service, err := newTestService(secret.Config{
			Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
			MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
		})
		if err != nil {
			t.Fatalf("NewService() error = %v", err)
		}
		_, _ = service.IssueHandle(context.Background(), secret.IssueRequest{
			Access: access(), SecretID: store.record.SecretID, Exposure: store.record.Exposure,
			Endpoint: store.record.Endpoint, Audience: store.record.Audience,
		})
		if !store.readWasCleared() {
			t.Fatal("IssueHandle() retained a partial error read")
		}
	})

	t.Run("gateway begin use", func(t *testing.T) {
		store := &observingStore{record: secret.Record{
			SecretID: "secret_partial_begin", TenantID: tenantID, Version: 1,
			Exposure: secret.ExposureProxyOnly, Value: []byte("partial-begin-value"),
			InjectionName: "Authorization", Endpoint: "https://proxy.internal",
			Audience: "proxy.internal", Active: true,
		}}
		service, err := newTestService(secret.Config{
			Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
			Gateway: &recordingGateway{}, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
		})
		if err != nil {
			t.Fatalf("NewService() error = %v", err)
		}
		handle, err := service.IssueHandle(context.Background(), secret.IssueRequest{
			Access: access(), SecretID: store.record.SecretID, Exposure: store.record.Exposure,
			Endpoint: store.record.Endpoint, Audience: store.record.Audience,
		})
		if err != nil {
			t.Fatalf("IssueHandle() error = %v", err)
		}
		store.beginErr = errors.New("begin acknowledgement lost")
		_, _ = service.UseGateway(context.Background(), secret.GatewayUseRequest{
			Access: access(), Handle: handle, Endpoint: store.record.Endpoint,
			Audience: store.record.Audience,
		})
		if !store.readWasCleared() {
			t.Fatal("UseGateway() retained a partial BeginUse read")
		}
	})

	t.Run("sandbox acquire", func(t *testing.T) {
		store := &observingStore{record: secret.Record{
			SecretID: "secret_partial_acquire", TenantID: tenantID, Version: 1,
			Exposure: secret.ExposureSandboxEnv, Value: []byte("partial-acquire-value"),
			InjectionName: "SERVICE_TOKEN", Active: true,
		}}
		sandbox := &recordingSandbox{cleanupConfirmed: true}
		service, err := newTestService(secret.Config{
			Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
			Sandbox: sandbox, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
		})
		if err != nil {
			t.Fatalf("NewService() error = %v", err)
		}
		handle, err := service.IssueHandle(context.Background(), secret.IssueRequest{
			Access: access(), SecretID: store.record.SecretID, Exposure: store.record.Exposure,
			InvocationID: invocationID,
		})
		if err != nil {
			t.Fatalf("IssueHandle() error = %v", err)
		}
		store.acquireErr = errors.New("acquire acknowledgement lost")
		_, _ = service.UseSandbox(context.Background(), secret.SandboxUseRequest{
			Access: access(), Handle: handle, InvocationID: invocationID,
			BaseCacheKey: "sha256:" + strings.Repeat("a", 64),
		})
		if !store.readWasCleared() {
			t.Fatal("UseSandbox() retained a partial AcquireReservedUse read")
		}
	})
}

func TestEveryUseAuthorizesBeforeReadingSecretMaterial(t *testing.T) {
	ctx := context.Background()
	order := []string{}
	store := &observingStore{order: &order, record: secret.Record{
		SecretID: "secret_recheck", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureProxyOnly, Value: []byte("must-not-be-read-after-revoke"),
		InjectionName: "Authorization", Endpoint: "https://proxy.internal",
		Audience: "proxy.internal", Active: true,
	}}
	authorizer := &allowingAuthorizer{order: &order}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: authorizer, Audit: &recordingAudit{durable: true},
		Gateway: &recordingGateway{}, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: store.record.SecretID, Exposure: store.record.Exposure,
		Endpoint: store.record.Endpoint, Audience: store.record.Audience,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	order = order[:0]
	authorizer.err = errors.New("revoked")
	_, err = service.UseGateway(ctx, secret.GatewayUseRequest{
		Access: access(), Handle: handle, Endpoint: store.record.Endpoint,
		Audience: store.record.Audience, Payload: []byte("request"),
	})
	if !errors.Is(err, secret.ErrAccessDenied) {
		t.Fatalf("UseGateway(revoked) error = %v, want ErrAccessDenied", err)
	}
	if fmt.Sprint(order) != "[authorize]" {
		t.Fatalf("revoked use order = %v, want authorization without secret read", order)
	}
}

func TestRotationCannotCompleteAcrossAnInFlightUse(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_fenced", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureProxyOnly, Value: []byte("old-value"),
		InjectionName: "Authorization", Endpoint: "https://proxy.internal",
		Audience: "proxy.internal", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap(create) error = %v", err)
	}
	audit := &blockingAudit{entered: make(chan struct{}), resume: make(chan struct{})}
	gateway := &recordingGateway{}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: audit, Gateway: gateway,
		MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		Endpoint: record.Endpoint, Audience: record.Audience,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	useResult := make(chan error, 1)
	go func() {
		_, err := service.UseGateway(ctx, secret.GatewayUseRequest{
			Access: access(), Handle: handle, Endpoint: record.Endpoint,
			Audience: record.Audience, Payload: []byte("request"),
		})
		useResult <- err
	}()
	<-audit.entered
	revoked := record
	revoked.Version = 2
	revoked.Active = false
	revoked.Value = []byte("value-that-must-never-dispatch")
	rotationErr := store.CompareAndSwap(ctx, 1, revoked)
	close(audit.resume)
	if err := <-useResult; err != nil {
		t.Fatalf("already-admitted UseGateway() error = %v", err)
	}
	if rotationErr == nil {
		t.Fatal("CompareAndSwap(revoke) completed while an older use could still dispatch")
	}
	if gateway.calls != 1 || string(gateway.credential) != "old-value" {
		t.Fatalf("admitted gateway call = %d/%q", gateway.calls, gateway.credential)
	}
	if err := store.CompareAndSwap(ctx, 1, revoked); err != nil {
		t.Fatalf("CompareAndSwap(revoke after use) error = %v", err)
	}
}

func TestDependencyPanicKeepsRecoveryFence(t *testing.T) {
	for name, exposure := range map[string]secret.ExposureClass{
		"gateway":      secret.ExposureGatewayHeader,
		"sandbox":      secret.ExposureSandboxEnv,
		"token-minter": secret.ExposureShortLivedToken,
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store := newDurableMemoryStore()
			record := secret.Record{
				SecretID: "secret_panic_" + name, TenantID: tenantID, Version: 1,
				Exposure: exposure, Value: []byte("panic-value"), Active: true,
			}
			if exposure == secret.ExposureGatewayHeader || exposure == secret.ExposureShortLivedToken {
				record.InjectionName = "Authorization"
				record.Endpoint = "https://gateway.internal"
				record.Audience = "gateway.internal"
			} else {
				record.InjectionName = "SERVICE_TOKEN"
			}
			if err := store.CompareAndSwap(ctx, 0, record); err != nil {
				t.Fatalf("CompareAndSwap() error = %v", err)
			}
			config := secret.Config{
				Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
				MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
			}
			var sandbox *recordingSandbox
			if exposure == secret.ExposureGatewayHeader {
				config.Gateway = &recordingGateway{panicOnDispatch: true}
			} else if exposure == secret.ExposureShortLivedToken {
				config.Gateway = &recordingGateway{}
				config.TokenMinter = &recordingTokenMinter{panicOnMint: true}
			} else {
				sandbox = &recordingSandbox{panicOnUse: true}
				config.Sandbox = sandbox
			}
			service, err := newTestService(config)
			if err != nil {
				t.Fatalf("NewService() error = %v", err)
			}
			issue := secret.IssueRequest{
				Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
				Endpoint: record.Endpoint, Audience: record.Audience,
			}
			if exposure == secret.ExposureSandboxEnv {
				issue.InvocationID = invocationID
			}
			handle, err := service.IssueHandle(ctx, issue)
			if err != nil {
				t.Fatalf("IssueHandle() error = %v", err)
			}
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				if exposure != secret.ExposureSandboxEnv {
					_, _ = service.UseGateway(ctx, secret.GatewayUseRequest{
						Access: access(), Handle: handle, Endpoint: record.Endpoint,
						Audience: record.Audience, Payload: []byte("request"),
					})
					return
				}
				_, _ = service.UseSandbox(ctx, secret.SandboxUseRequest{
					Access: access(), Handle: handle, InvocationID: invocationID,
					BaseCacheKey: "sha256:" + strings.Repeat("a", 64),
				})
			}()
			if recovered == nil {
				t.Fatal("dependency did not panic")
			}
			if sandbox != nil && (sandbox.cleanupCalls != 1 || sandbox.quarantineCalls != 1) {
				t.Fatalf("sandbox panic containment calls = cleanup %d/quarantine %d, want 1/1",
					sandbox.cleanupCalls, sandbox.quarantineCalls)
			}
			revoked := record
			revoked.Version = 2
			revoked.Active = false
			revoked.Value = nil
			if err := store.CompareAndSwap(ctx, 1, revoked); !errors.Is(err, secret.ErrStoreInUse) {
				t.Fatalf("CompareAndSwap(after dependency panic) error = %v, want ErrStoreInUse", err)
			}
		})
	}
}

func TestSandboxPreparePanicAttemptsStableContainment(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_prepare_panic", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureSandboxEnv, Value: []byte("sandbox-value"),
		InjectionName: "SERVICE_TOKEN", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	sandbox := &recordingSandbox{panicOnPrepare: true}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Sandbox: sandbox, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		InvocationID: invocationID,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	var panicValue any
	func() {
		defer func() { panicValue = recover() }()
		_, _ = service.UseSandbox(ctx, secret.SandboxUseRequest{
			Access: access(), Handle: handle, InvocationID: invocationID,
			BaseCacheKey: "sha256:" + strings.Repeat("b", 64),
		})
	}()
	if panicValue == nil {
		t.Fatal("Prepare() did not panic")
	}
	if sandbox.cleanupCalls != 1 || sandbox.quarantineCalls != 1 {
		t.Fatalf("Prepare panic containment calls = cleanup %d/quarantine %d, want 1/1",
			sandbox.cleanupCalls, sandbox.quarantineCalls)
	}
	revoked := record
	revoked.Version = 2
	revoked.Active = false
	revoked.Value = nil
	if err := store.CompareAndSwap(ctx, 1, revoked); !errors.Is(err, secret.ErrStoreInUse) {
		t.Fatalf("CompareAndSwap(after uncontained Prepare panic) error = %v, want ErrStoreInUse", err)
	}
}

func TestGatewayEndUseFailureReturnsRecoverableFence(t *testing.T) {
	ctx := context.Background()
	store := &failingEndUseStore{MemoryStore: secret.NewMemoryStore(), fail: true}
	record := secret.Record{
		SecretID: "secret_gateway_release", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureGatewayHeader, Value: []byte("gateway-value"),
		InjectionName: "Authorization", Endpoint: "https://gateway.internal",
		Audience: "gateway.internal", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Gateway:             &recordingGateway{response: []byte("committed")},
		MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		Endpoint: record.Endpoint, Audience: record.Audience,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	response, err := service.UseGateway(ctx, secret.GatewayUseRequest{
		Access: access(), Handle: handle, Endpoint: record.Endpoint,
		Audience: record.Audience, Payload: []byte("request"),
	})
	if !errors.Is(err, secret.ErrUseReleaseUnconfirmed) {
		t.Fatalf("UseGateway(EndUse failure) error = %v, want ErrUseReleaseUnconfirmed", err)
	}
	if response.Recovery.RecoveryID == "" || response.Recovery.SecretID != record.SecretID {
		t.Fatalf("UseGateway(EndUse failure) recovery = %#v", response.Recovery)
	}

	revoked := record
	revoked.Version = 2
	revoked.Active = false
	revoked.Value = nil
	if err := store.CompareAndSwap(ctx, 1, revoked); !errors.Is(err, secret.ErrStoreInUse) {
		t.Fatalf("CompareAndSwap(orphaned gateway lease) error = %v, want ErrStoreInUse", err)
	}
	if _, err := service.RecoverGateway(ctx, secret.GatewayRecoveryRequest{
		Authority: secret.RecoveryAuthority{TenantID: tenantID, SubjectID: subjectID},
		Recovery:  response.Recovery,
	}); err != nil {
		t.Fatalf("RecoverGateway() error = %v", err)
	}
	if err := store.CompareAndSwap(ctx, 1, revoked); err != nil {
		t.Fatalf("CompareAndSwap(after gateway recovery) error = %v", err)
	}
}

func TestGatewayRecoveryIsIdempotentAfterReleaseAcknowledgementLoss(t *testing.T) {
	ctx := context.Background()
	store := &failingEndUseStore{
		MemoryStore: secret.NewMemoryStore(), fail: true, commitBeforeFailure: true,
	}
	record := secret.Record{
		SecretID: "secret_gateway_ack_loss", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureGatewayHeader, Value: []byte("gateway-value"),
		InjectionName: "Authorization", Endpoint: "https://gateway.internal",
		Audience: "gateway.internal", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Gateway:             &recordingGateway{response: []byte("committed")},
		MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		Endpoint: record.Endpoint, Audience: record.Audience,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	response, err := service.UseGateway(ctx, secret.GatewayUseRequest{
		Access: access(), Handle: handle, Endpoint: record.Endpoint,
		Audience: record.Audience, Payload: []byte("request"),
	})
	if !errors.Is(err, secret.ErrUseReleaseUnconfirmed) {
		t.Fatalf("UseGateway(ack loss) error = %v, want ErrUseReleaseUnconfirmed", err)
	}
	if _, err := service.RecoverGateway(ctx, secret.GatewayRecoveryRequest{
		Authority: secret.RecoveryAuthority{TenantID: tenantID, SubjectID: subjectID},
		Recovery:  response.Recovery,
	}); err != nil {
		t.Fatalf("RecoverGateway(after committed release) error = %v", err)
	}
}

func TestGatewayDispatchAcknowledgementLossKeepsRecoveryFence(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_gateway_dispatch_ack", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureGatewayHeader, Value: []byte("gateway-value"),
		InjectionName: "Authorization", Endpoint: "https://gateway.internal",
		Audience: "gateway.internal", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	gateway := &recordingGateway{err: errors.New("response acknowledgement lost")}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Gateway: gateway, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		Endpoint: record.Endpoint, Audience: record.Audience,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	response, err := service.UseGateway(ctx, secret.GatewayUseRequest{
		Access: access(), Handle: handle, Endpoint: record.Endpoint,
		Audience: record.Audience, Payload: []byte("request"),
	})
	if !errors.Is(err, secret.ErrGatewayFailed) || response.Recovery.RecoveryID == "" {
		t.Fatalf("UseGateway(dispatch ack loss) = %#v, %v, want recoverable ErrGatewayFailed", response, err)
	}
	revoked := record
	revoked.Version = 2
	revoked.Active = false
	revoked.Value = nil
	if err := store.CompareAndSwap(ctx, 1, revoked); !errors.Is(err, secret.ErrStoreInUse) {
		t.Fatalf("CompareAndSwap(uncertain dispatch) error = %v, want ErrStoreInUse", err)
	}
}

func TestGatewayRecoveryConsultsExternalLedgerBeforeReleasingFence(t *testing.T) {
	ctx := context.Background()
	store := &failingEndUseStore{MemoryStore: secret.NewMemoryStore(), fail: true}
	record := secret.Record{
		SecretID: "secret_gateway_external_recovery", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureGatewayHeader, Value: []byte("gateway-value"),
		InjectionName: "Authorization", Endpoint: "https://gateway.internal",
		Audience: "gateway.internal", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	gateway := &recordingGateway{response: []byte("ok")}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Gateway: gateway, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		Endpoint: record.Endpoint, Audience: record.Audience,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	response, err := service.UseGateway(ctx, secret.GatewayUseRequest{
		Access: access(), Handle: handle, Endpoint: record.Endpoint,
		Audience: record.Audience, Payload: []byte("request"),
	})
	if !errors.Is(err, secret.ErrUseReleaseUnconfirmed) {
		t.Fatalf("UseGateway(release failure) error = %v", err)
	}
	store.fail = false
	if _, err := service.RecoverGateway(ctx, secret.GatewayRecoveryRequest{
		Authority: secret.RecoveryAuthority{TenantID: tenantID, SubjectID: subjectID},
		Recovery:  response.Recovery,
	}); err != nil {
		t.Fatalf("RecoverGateway() error = %v", err)
	}
	if gateway.recoveryCalls != 1 {
		t.Fatalf("gateway external recovery calls = %d, want 1", gateway.recoveryCalls)
	}
	if !gateway.recoveryHadDeadline {
		t.Fatal("gateway external recovery context had no bounded deadline")
	}
}

func TestSandboxEndUseFailureReturnsContainmentRecovery(t *testing.T) {
	ctx := context.Background()
	store := &failingEndUseStore{MemoryStore: secret.NewMemoryStore(), fail: true}
	record := secret.Record{
		SecretID: "secret_sandbox_release", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureSandboxEnv, Value: []byte("sandbox-value"),
		InjectionName: "SERVICE_TOKEN", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	sandbox := &recordingSandbox{
		receipt: secret.SandboxCleanupReceipt{
			InvocationID: invocationID, EnvironmentCleared: true,
		},
		quarantineDurable: true,
	}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Sandbox: sandbox, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		InvocationID: invocationID,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	receipt, err := service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: access(), Handle: handle, InvocationID: invocationID,
		BaseCacheKey: "sha256:" + strings.Repeat("9", 64),
	})
	if !errors.Is(err, secret.ErrUseReleaseUnconfirmed) || receipt.Recovery.RecoveryID == "" {
		t.Fatalf("UseSandbox(EndUse failure) = %#v, %v", receipt, err)
	}
	if _, err := service.RecoverSandbox(ctx, secret.SandboxRecoveryRequest{
		Authority: secret.RecoveryAuthority{TenantID: tenantID, SubjectID: subjectID},
		Recovery:  receipt.Recovery,
	}); err != nil {
		t.Fatalf("RecoverSandbox(after EndUse failure) error = %v", err)
	}
}

func TestUnconfirmedSandboxCleanupTriggersRecoveryAndQuarantine(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_containment", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureSandboxFile, Value: []byte("sandbox-value"),
		InjectionName: "/run/credentials/token", Active: true, DestroySandboxAfterUse: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	sandbox := &recordingSandbox{
		receipt:          secret.SandboxCleanupReceipt{InvocationID: invocationID},
		cleanupConfirmed: false, quarantineDurable: true,
	}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Sandbox: sandbox, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		InvocationID: invocationID,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	_, err = service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: access(), Handle: handle, InvocationID: invocationID,
		BaseCacheKey: "sha256:" + strings.Repeat("c", 64),
	})
	if !errors.Is(err, secret.ErrCleanupUnconfirmed) {
		t.Fatalf("UseSandbox(unconfirmed cleanup) error = %v, want ErrCleanupUnconfirmed", err)
	}
	if sandbox.prepareCalls != 1 || sandbox.cleanupCalls != 1 || sandbox.quarantineCalls != 1 {
		t.Fatalf("prepare/cleanup/quarantine calls = %d/%d/%d, want 1/1/1",
			sandbox.prepareCalls, sandbox.cleanupCalls, sandbox.quarantineCalls)
	}
}

func TestSandboxHandleIsInvocationGenerationAndExpiryBound(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_scoped_sandbox", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureSandboxEnv, Value: []byte("sandbox-value"),
		InjectionName: "SERVICE_TOKEN", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	now := time.Date(2026, time.August, 26, 14, 0, 0, 0, time.UTC)
	authorizer := &allowingAuthorizer{}
	sandbox := &recordingSandbox{
		receipt: secret.SandboxCleanupReceipt{
			InvocationID: invocationID, EnvironmentCleared: true,
		},
	}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: authorizer, Audit: &recordingAudit{durable: true},
		Sandbox: sandbox, Now: func() time.Time { return now }, HandleTTL: time.Minute,
		MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		InvocationID: invocationID,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	if len(authorizer.requests) != 1 || authorizer.requests[0].InvocationID != invocationID ||
		authorizer.requests[0].Access.AuthorizationGeneration != 3 {
		t.Fatalf("issue authorization binding = %#v", authorizer.requests)
	}
	otherInvocation := "inv_AAAAAAAAAAAAAAAAAAAAAAAAAE"
	if _, err := service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: access(), Handle: handle, InvocationID: otherInvocation,
		BaseCacheKey: "sha256:" + strings.Repeat("d", 64),
	}); !errors.Is(err, secret.ErrStaleHandle) {
		t.Fatalf("UseSandbox(other invocation) error = %v, want ErrStaleHandle", err)
	}
	newGeneration := access()
	newGeneration.AuthorizationGeneration++
	if _, err := service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: newGeneration, Handle: handle, InvocationID: invocationID,
		BaseCacheKey: "sha256:" + strings.Repeat("d", 64),
	}); !errors.Is(err, secret.ErrStaleHandle) {
		t.Fatalf("UseSandbox(other generation) error = %v, want ErrStaleHandle", err)
	}
	now = now.Add(time.Minute)
	if _, err := service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: access(), Handle: handle, InvocationID: invocationID,
		BaseCacheKey: "sha256:" + strings.Repeat("d", 64),
	}); !errors.Is(err, secret.ErrStaleHandle) {
		t.Fatalf("UseSandbox(expired handle) error = %v, want ErrStaleHandle", err)
	}
	if sandbox.calls != 0 || sandbox.prepareCalls != 0 {
		t.Fatalf("out-of-scope handles reached sandbox: use/prepare = %d/%d", sandbox.calls, sandbox.prepareCalls)
	}
}

func TestSandboxPrepareCannotOutliveHandleAdmission(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.August, 27, 12, 0, 0, 0, time.UTC)
	store := newDurableMemoryStoreWithClock(func() time.Time { return now })
	record := secret.Record{
		SecretID: "secret_prepare_expiry", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureSandboxEnv, Value: []byte("must-not-be-read"),
		InjectionName: "SERVICE_TOKEN", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	recorder := &recordingSandbox{receipt: secret.SandboxCleanupReceipt{
		InvocationID: invocationID, EnvironmentCleared: true,
	}, cleanupConfirmed: true}
	sandbox := &advancingPrepareSandbox{
		recordingSandbox: recorder,
		advance:          func() { now = now.Add(time.Minute) },
	}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Sandbox: sandbox, Now: func() time.Time { return now }, HandleTTL: time.Minute,
		MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		InvocationID: invocationID,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	_, err = service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: access(), Handle: handle, InvocationID: invocationID,
		BaseCacheKey: "sha256:" + strings.Repeat("4", 64),
	})
	if !errors.Is(err, secret.ErrStaleHandle) {
		t.Fatalf("UseSandbox(handle expired during Prepare) error = %v, want ErrStaleHandle", err)
	}
	if recorder.calls != 0 || len(recorder.credential) != 0 {
		t.Fatalf("expired admission exposed raw material: calls/credential = %d/%q",
			recorder.calls, recorder.credential)
	}
}

func TestSandboxPrepareCannotOutliveAuthorizationGeneration(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_prepare_revoke", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureSandboxEnv, Value: []byte("must-not-be-read"),
		InjectionName: "SERVICE_TOKEN", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	authorizer := &allowingAuthorizer{}
	recorder := &recordingSandbox{receipt: secret.SandboxCleanupReceipt{
		InvocationID: invocationID, EnvironmentCleared: true,
	}, cleanupConfirmed: true}
	sandbox := &advancingPrepareSandbox{
		recordingSandbox: recorder,
		advance:          func() { authorizer.err = errors.New("generation revoked") },
	}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: authorizer, Audit: &recordingAudit{durable: true},
		Sandbox: sandbox, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		InvocationID: invocationID,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	_, err = service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: access(), Handle: handle, InvocationID: invocationID,
		BaseCacheKey: "sha256:" + strings.Repeat("8", 64),
	})
	if !errors.Is(err, secret.ErrAccessDenied) {
		t.Fatalf("UseSandbox(revoked during Prepare) error = %v, want ErrAccessDenied", err)
	}
	if recorder.calls != 0 || len(recorder.credential) != 0 {
		t.Fatalf("revoked admission exposed raw material: calls/credential = %d/%q",
			recorder.calls, recorder.credential)
	}
	if recorder.cleanupCalls != 1 {
		t.Fatalf("revoked admission orphaned prepared sandbox: cleanup calls = %d, want 1",
			recorder.cleanupCalls)
	}
}

func TestSandboxCancellationAfterPrepareCleansStableReservation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_prepare_cancel", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureSandboxEnv, Value: []byte("must-not-be-read"),
		InjectionName: "SERVICE_TOKEN", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	recorder := &recordingSandbox{receipt: secret.SandboxCleanupReceipt{
		InvocationID: invocationID, EnvironmentCleared: true,
	}, cleanupConfirmed: true}
	sandbox := &advancingPrepareSandbox{recordingSandbox: recorder, advance: cancel}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Sandbox: sandbox, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		InvocationID: invocationID,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	_, err = service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: access(), Handle: handle, InvocationID: invocationID,
		BaseCacheKey: "sha256:" + strings.Repeat("0", 64),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("UseSandbox(cancelled after Prepare) error = %v, want context.Canceled", err)
	}
	if recorder.cleanupCalls != 1 || recorder.calls != 0 {
		t.Fatalf("cancelled prepared sandbox use/cleanup calls = %d/%d, want 0/1",
			recorder.calls, recorder.cleanupCalls)
	}
}

func TestUncontainedSandboxExposureKeepsRotationFence(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_uncontained", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureSandboxEnv, Value: []byte("sandbox-value"),
		InjectionName: "SERVICE_TOKEN", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	sandbox := &recordingSandbox{
		receipt:           secret.SandboxCleanupReceipt{InvocationID: invocationID},
		quarantineDurable: false,
	}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Sandbox: sandbox, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		InvocationID: invocationID,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	recovery, err := service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: access(), Handle: handle, InvocationID: invocationID,
		BaseCacheKey: "sha256:" + strings.Repeat("e", 64),
	})
	if !errors.Is(err, secret.ErrContainmentUnconfirmed) {
		t.Fatalf("UseSandbox(uncontained) error = %v, want ErrContainmentUnconfirmed", err)
	}
	if recovery.InvocationID != invocationID || recovery.Recovery.RecoveryID == "" {
		t.Fatalf("UseSandbox(uncontained) recovery receipt = %#v", recovery)
	}
	revoked := record
	revoked.Version = 2
	revoked.Active = false
	revoked.Value = nil
	if err := store.CompareAndSwap(ctx, 1, revoked); !errors.Is(err, secret.ErrStoreInUse) {
		t.Fatalf("CompareAndSwap(after uncontained exposure) error = %v, want ErrStoreInUse", err)
	}
	_, err = service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: access(), Handle: handle, InvocationID: invocationID,
		BaseCacheKey: "sha256:" + strings.Repeat("e", 64),
	})
	if !errors.Is(err, secret.ErrStoreInUse) {
		t.Fatalf("UseSandbox(after uncontained exposure) error = %v, want ErrStoreInUse", err)
	}
	if sandbox.calls != 1 || sandbox.prepareCalls != 1 {
		t.Fatalf("active recovery was prepared or reused again: use/prepare = %d/%d, want 1/1",
			sandbox.calls, sandbox.prepareCalls)
	}
	sandbox.quarantineDurable = true
	contained, err := service.RecoverSandbox(ctx, secret.SandboxRecoveryRequest{
		Authority: secret.RecoveryAuthority{TenantID: tenantID, SubjectID: subjectID},
		Recovery:  recovery.Recovery,
	})
	if err != nil || !contained.Durable || contained.RecoveryID != recovery.Recovery.RecoveryID {
		t.Fatalf("RecoverSandbox() = %#v, %v", contained, err)
	}
	if err := store.CompareAndSwap(ctx, 1, revoked); err != nil {
		t.Fatalf("CompareAndSwap(after durable recovery) error = %v", err)
	}
}

func TestPrivilegedSandboxRecoveryIgnoresRevokedActorAndOrdinaryAuditOutage(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_privileged_recovery", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureSandboxEnv, Value: []byte("sandbox-value"),
		InjectionName: "SERVICE_TOKEN", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	actorAuthorizer := &allowingAuthorizer{}
	ordinaryAudit := &recordingAudit{durable: true}
	recoveryAuthorizer := &allowingRecoveryAuthorizer{}
	recoveryAudit := &recordingRecoveryAudit{durable: true}
	sandbox := &recordingSandbox{
		receipt:           secret.SandboxCleanupReceipt{InvocationID: invocationID},
		quarantineDurable: false,
	}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: actorAuthorizer, Audit: ordinaryAudit,
		RecoveryAuthorizer: recoveryAuthorizer, RecoveryAudit: recoveryAudit,
		Sandbox: sandbox, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: access(), SecretID: record.SecretID, Exposure: record.Exposure,
		InvocationID: invocationID,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	receipt, err := service.UseSandbox(ctx, secret.SandboxUseRequest{
		Access: access(), Handle: handle, InvocationID: invocationID,
		BaseCacheKey: "sha256:" + strings.Repeat("5", 64),
	})
	if !errors.Is(err, secret.ErrContainmentUnconfirmed) {
		t.Fatalf("UseSandbox(uncontained) error = %v, want ErrContainmentUnconfirmed", err)
	}
	actorCalls := len(actorAuthorizer.requests)
	actorAuthorizer.err = errors.New("actor revoked")
	ordinaryAudit.err = errors.New("ordinary audit unavailable")
	ordinaryAudit.durable = false
	sandbox.quarantineDurable = true
	page, err := service.ListPendingRecoveries(ctx, secret.PendingRecoveryRequest{
		Authority: secret.RecoveryAuthority{TenantID: tenantID, SubjectID: subjectID}, Limit: 1,
	})
	if err != nil || len(page.Recoveries) != 1 || page.Recoveries[0] != receipt.Recovery {
		t.Fatalf("ListPendingRecoveries() = %#v, %v", page, err)
	}

	contained, err := service.RecoverSandbox(ctx, secret.SandboxRecoveryRequest{
		Authority: secret.RecoveryAuthority{TenantID: tenantID, SubjectID: subjectID},
		Recovery:  receipt.Recovery,
	})
	if err != nil || !contained.Durable {
		t.Fatalf("RecoverSandbox(privileged) = %#v, %v", contained, err)
	}
	if !sandbox.quarantineHadDeadline {
		t.Fatal("sandbox recovery quarantine context had no bounded deadline")
	}
	if len(actorAuthorizer.requests) != actorCalls {
		t.Fatalf("recovery consulted revoked actor authority: calls = %d, want %d",
			len(actorAuthorizer.requests), actorCalls)
	}
	if len(recoveryAuthorizer.requests) != 2 ||
		recoveryAuthorizer.requests[0].Operation != secret.RecoveryListPending ||
		recoveryAuthorizer.requests[1].Operation != secret.RecoveryContainSandbox ||
		recoveryAuthorizer.requests[1].RecoveryID != receipt.Recovery.RecoveryID {
		t.Fatalf("recovery authorization = %#v", recoveryAuthorizer.requests)
	}
	if len(recoveryAudit.events) != 2 || recoveryAudit.events[0].Operation != secret.RecoveryListPending ||
		recoveryAudit.events[1].RecoveryID != receipt.Recovery.RecoveryID {
		t.Fatalf("recovery audit = %#v", recoveryAudit.events)
	}
}

func TestSandboxCacheIsolatedAcrossAuthorizationGenerations(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_policy_cache", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureSandboxEnv, Value: []byte("sandbox-value"),
		InjectionName: "SERVICE_TOKEN", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	sandbox := &recordingSandbox{receipt: secret.SandboxCleanupReceipt{
		InvocationID: invocationID, EnvironmentCleared: true,
	}}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Sandbox: sandbox, MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	base := "sha256:" + strings.Repeat("f", 64)
	for generation := uint64(3); generation <= 4; generation++ {
		requestAccess := access()
		requestAccess.AuthorizationGeneration = generation
		handle, err := service.IssueHandle(ctx, secret.IssueRequest{
			Access: requestAccess, SecretID: record.SecretID, Exposure: record.Exposure,
			InvocationID: invocationID,
		})
		if err != nil {
			t.Fatalf("IssueHandle(generation %d) error = %v", generation, err)
		}
		if _, err := service.UseSandbox(ctx, secret.SandboxUseRequest{
			Access: requestAccess, Handle: handle, InvocationID: invocationID, BaseCacheKey: base,
		}); err != nil {
			t.Fatalf("UseSandbox(generation %d) error = %v", generation, err)
		}
	}
	if len(sandbox.dispatches) != 2 ||
		sandbox.dispatches[0].ResolvedCacheKey == sandbox.dispatches[1].ResolvedCacheKey {
		t.Fatalf("authorization generations reused cache key: %#v", sandbox.dispatches)
	}
}

func TestGatewayHandleRejectsEveryChangedTurnAuthorityDimension(t *testing.T) {
	ctx := context.Background()
	store := newDurableMemoryStore()
	record := secret.Record{
		SecretID: "secret_turn_authority", TenantID: tenantID, Version: 1,
		Exposure: secret.ExposureGatewayHeader, Value: []byte("gateway-value"),
		InjectionName: "Authorization", Endpoint: "https://gateway.internal",
		Audience: "gateway.internal", Active: true,
	}
	if err := store.CompareAndSwap(ctx, 0, record); err != nil {
		t.Fatalf("CompareAndSwap() error = %v", err)
	}
	service, err := newTestService(secret.Config{
		Store: store, Authorizer: &allowingAuthorizer{}, Audit: &recordingAudit{durable: true},
		Gateway:             &recordingGateway{response: []byte("ok")},
		MaximumRequestBytes: 1024, MaximumResponseBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	original := access()
	handle, err := service.IssueHandle(ctx, secret.IssueRequest{
		Access: original, SecretID: record.SecretID, Exposure: record.Exposure,
		Endpoint: record.Endpoint, Audience: record.Audience,
	})
	if err != nil {
		t.Fatalf("IssueHandle() error = %v", err)
	}
	mutations := map[string]func(*secret.AccessContext){
		"turn": func(access *secret.AccessContext) {
			access.TurnID = "turn_AAAAAAAAAAAAAAAAAAAAAAAAAB"
		},
		"runtime revision": func(access *secret.AccessContext) {
			access.RuntimeRevision = "runtime_AAAAAAAAAAAAAAAAAAAAAAAAAB"
		},
		"turn lease generation": func(access *secret.AccessContext) { access.TurnLeaseGeneration++ },
		"placement generation":  func(access *secret.AccessContext) { access.PlacementGeneration++ },
		"sandbox generation":    func(access *secret.AccessContext) { access.SandboxGeneration++ },
		"policy generation":     func(access *secret.AccessContext) { access.AuthorizationGeneration++ },
		"permission":            func(access *secret.AccessContext) { access.Permission = "secret.admin" },
		"service binding":       func(access *secret.AccessContext) { access.ServiceBinding = "mcp" },
		"authority deadline": func(access *secret.AccessContext) {
			access.AuthorityExpiresAt = access.AuthorityExpiresAt.Add(-time.Second)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := original
			mutate(&changed)
			_, err := service.UseGateway(ctx, secret.GatewayUseRequest{
				Access: changed, Handle: handle, Endpoint: record.Endpoint,
				Audience: record.Audience, Payload: []byte("request"),
			})
			if !errors.Is(err, secret.ErrStaleHandle) {
				t.Fatalf("UseGateway(changed authority) error = %v, want ErrStaleHandle", err)
			}
		})
	}
}
