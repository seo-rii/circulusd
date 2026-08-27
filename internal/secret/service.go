package secret

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/identity"
	"golang.org/x/text/unicode/norm"
)

const (
	maximumDefaultSecretBytes  = 1 << 20
	maximumTextBytes           = 256
	maximumEndpointBytes       = 2048
	maximumConfiguredBytes     = 64 << 20
	defaultMaximumTokenTTL     = 15 * time.Minute
	defaultHandleTTL           = 5 * time.Minute
	maximumHandleTTL           = time.Hour
	defaultRecoveryTimeout     = 30 * time.Second
	maximumRecoveryTimeout     = 5 * time.Minute
	maximumSharedGeneration    = uint64(9_007_199_254_740_991)
	maximumAdmissionProofBytes = 4096
)

var (
	secretIDPattern        = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,255}$`)
	environmentNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,255}$`)
	digestPattern          = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Service struct {
	store                Store
	authorizer           Authorizer
	admitter             UseAdmitter
	audit                AuditSink
	recoveryAuthorizer   RecoveryAuthorizer
	recoveryAudit        RecoveryAuditSink
	gateway              GatewayDispatcher
	sandbox              SandboxInjector
	tokenMinter          TokenMinter
	now                  func() time.Time
	maximumRequestBytes  int
	maximumResponseBytes int
	maximumSecretBytes   int
	maximumTokenTTL      time.Duration
	handleTTL            time.Duration
	serviceBinding       string
	recoveryTimeout      time.Duration
}

func NewService(config Config) (*Service, error) {
	if isNilDependency(config.Store) || isNilDependency(config.Authorizer) || isNilDependency(config.Audit) ||
		isNilDependency(config.RecoveryAuthorizer) || isNilDependency(config.RecoveryAudit) ||
		(config.Admitter != nil && isNilDependency(config.Admitter)) ||
		(config.Gateway != nil && isNilDependency(config.Gateway)) ||
		(config.Sandbox != nil && isNilDependency(config.Sandbox)) ||
		(config.TokenMinter != nil && isNilDependency(config.TokenMinter)) ||
		config.MaximumRequestBytes <= 0 || config.MaximumRequestBytes > maximumConfiguredBytes ||
		config.MaximumResponseBytes <= 0 || config.MaximumResponseBytes > maximumConfiguredBytes ||
		validateBoundedText(config.ServiceBinding, false) != nil {
		return nil, ErrInvalidConfig
	}
	admitter := config.Admitter
	if admitter == nil {
		var supported bool
		admitter, supported = config.Authorizer.(UseAdmitter)
		if !supported {
			return nil, ErrInvalidConfig
		}
	}
	capabilities := config.Store.Capabilities()
	if !capabilities.Durable || !capabilities.AtomicUseRecovery ||
		!capabilities.AtomicAdmissionValidation || !capabilities.AtomicPreparedUse ||
		!capabilities.BoundedRecoveryEnumeration {
		return nil, ErrStoreNotDurable
	}
	if config.Gateway != nil {
		gatewayCapabilities := config.Gateway.Capabilities()
		if !gatewayCapabilities.DurableRecovery || !gatewayCapabilities.IdempotentRecovery {
			return nil, ErrInvalidConfig
		}
	}
	maximumSecretBytes := config.MaximumSecretBytes
	if maximumSecretBytes == 0 {
		maximumSecretBytes = maximumDefaultSecretBytes
	}
	if maximumSecretBytes < 1 || maximumSecretBytes > maximumConfiguredBytes {
		return nil, ErrInvalidConfig
	}
	maximumTokenTTL := config.MaximumTokenTTL
	if maximumTokenTTL == 0 {
		maximumTokenTTL = defaultMaximumTokenTTL
	}
	if maximumTokenTTL <= 0 || maximumTokenTTL > 24*time.Hour {
		return nil, ErrInvalidConfig
	}
	handleTTL := config.HandleTTL
	if handleTTL == 0 {
		handleTTL = defaultHandleTTL
	}
	if handleTTL <= 0 || handleTTL > maximumHandleTTL {
		return nil, ErrInvalidConfig
	}
	recoveryTimeout := config.RecoveryTimeout
	if recoveryTimeout == 0 {
		recoveryTimeout = defaultRecoveryTimeout
	}
	if recoveryTimeout <= 0 || recoveryTimeout > maximumRecoveryTimeout {
		return nil, ErrInvalidConfig
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Service{
		store: config.Store, authorizer: config.Authorizer, admitter: admitter, audit: config.Audit,
		recoveryAuthorizer: config.RecoveryAuthorizer, recoveryAudit: config.RecoveryAudit,
		gateway: config.Gateway, sandbox: config.Sandbox, tokenMinter: config.TokenMinter,
		now: now, maximumRequestBytes: config.MaximumRequestBytes,
		maximumResponseBytes: config.MaximumResponseBytes,
		maximumSecretBytes:   maximumSecretBytes, maximumTokenTTL: maximumTokenTTL,
		handleTTL: handleTTL, serviceBinding: config.ServiceBinding,
		recoveryTimeout: recoveryTimeout,
	}, nil
}

func (service *Service) IssueHandle(ctx context.Context, request IssueRequest) (Handle, error) {
	if err := ctx.Err(); err != nil {
		return Handle{}, err
	}
	bindingValid := false
	switch request.Exposure {
	case ExposureProxyOnly, ExposureGatewayHeader, ExposureShortLivedToken:
		bindingValid = validateEndpoint(request.Endpoint) == nil &&
			validateBoundedText(request.Audience, false) == nil && request.InvocationID == ""
	case ExposureSandboxEnv, ExposureSandboxFile:
		_, invocationErr := identity.Parse(identity.Invocation, request.InvocationID)
		bindingValid = request.Endpoint == "" && request.Audience == "" && invocationErr == nil
	}
	now := service.now().Round(0).UTC()
	if validateAccess(request.Access) != nil || request.Access.ServiceBinding != service.serviceBinding ||
		!now.Before(request.Access.AuthorityExpiresAt) || validateSecretID(request.SecretID) != nil ||
		!validExposure(request.Exposure) || !bindingValid {
		return Handle{}, ErrInvalidRequest
	}
	if err := service.authorizer.Authorize(ctx, AuthorizationRequest{
		Operation: OperationIssue, Access: request.Access, SecretID: request.SecretID,
		Exposure: request.Exposure, Endpoint: request.Endpoint, Audience: request.Audience,
		InvocationID: request.InvocationID,
	}); err != nil {
		return Handle{}, ErrAccessDenied
	}
	record, err := service.store.Get(ctx, request.Access.TenantID, request.SecretID)
	defer clear(record.Value)
	if err != nil {
		if err == ErrSecretNotFound {
			return Handle{}, err
		}
		return Handle{}, fmt.Errorf("%w: read failed", ErrSecretNotFound)
	}
	if validateRecord(record, service.maximumSecretBytes) != nil {
		return Handle{}, ErrInvalidRequest
	}
	if !record.Active || record.TenantID != request.Access.TenantID || record.SecretID != request.SecretID ||
		record.Exposure != request.Exposure || record.Endpoint != request.Endpoint || record.Audience != request.Audience {
		return Handle{}, ErrExposureDenied
	}
	expiresAt := now.Add(service.handleTTL)
	if request.Access.AuthorityExpiresAt.Before(expiresAt) {
		expiresAt = request.Access.AuthorityExpiresAt
	}
	return Handle{
		access: request.Access, secretID: record.SecretID, version: record.Version,
		exposure: record.Exposure, endpoint: record.Endpoint, audience: record.Audience,
		destroySandboxAfterUse: record.DestroySandboxAfterUse,
		invocationID:           request.InvocationID, expiresAt: expiresAt,
	}, nil
}

func (service *Service) UseGateway(
	ctx context.Context,
	request GatewayUseRequest,
) (result GatewayResponse, resultErr error) {
	if err := ctx.Err(); err != nil {
		return GatewayResponse{}, err
	}
	if isNilDependency(service.gateway) {
		return GatewayResponse{}, ErrGatewayUnavailable
	}
	if len(request.Payload) > service.maximumRequestBytes || validateEndpoint(request.Endpoint) != nil ||
		validateBoundedText(request.Audience, false) != nil {
		return GatewayResponse{}, ErrInvalidRequest
	}
	if err := service.authorizeHandle(
		ctx, request.Access, request.Handle, OperationGatewayUse, request.Endpoint, request.Audience, "",
	); err != nil {
		return GatewayResponse{}, err
	}
	recoveryID, err := identity.New(identity.Operation)
	if err != nil {
		return GatewayResponse{}, ErrGatewayFailed
	}
	recovery := UseRecoveryBinding{
		TenantID: request.Access.TenantID, SubjectID: request.Access.SubjectID,
		SessionID: request.Access.SessionID, WorkspaceID: request.Access.WorkspaceID,
		TurnID: request.Access.TurnID, RuntimeRevision: request.Access.RuntimeRevision,
		TurnLeaseGeneration:     request.Access.TurnLeaseGeneration,
		PlacementGeneration:     request.Access.PlacementGeneration,
		SandboxGeneration:       request.Access.SandboxGeneration,
		AuthorizationGeneration: request.Access.AuthorizationGeneration,
		Permission:              request.Access.Permission, ServiceBinding: request.Access.ServiceBinding,
		AuthorityExpiresAt:     request.Access.AuthorityExpiresAt,
		DestroySandboxAfterUse: request.Handle.destroySandboxAfterUse,
		SecretID:               request.Handle.secretID, SecretVersion: request.Handle.version,
		Exposure: request.Handle.exposure, RecoveryID: recoveryID.String(),
		Endpoint: request.Endpoint, Audience: request.Audience,
	}
	admission, err := service.admitHandleUse(
		ctx, request.Access, request.Handle, OperationGatewayUse,
		request.Endpoint, request.Audience, "",
	)
	if err != nil {
		return GatewayResponse{}, err
	}
	record, lease, err := service.beginHandleUse(ctx, request.Access, request.Handle, recovery, admission)
	if err != nil {
		if errors.Is(err, ErrUseReleaseUnconfirmed) {
			return GatewayResponse{Recovery: recovery}, err
		}
		return GatewayResponse{}, err
	}
	releaseLease := true
	defer func() {
		if releaseLease {
			if err := service.releaseUse(ctx, lease); err != nil {
				result.Recovery = recovery
				resultErr = errors.Join(resultErr, err)
			}
		}
	}()
	defer clear(record.Value)
	switch record.Exposure {
	case ExposureProxyOnly, ExposureGatewayHeader, ExposureShortLivedToken:
	default:
		return GatewayResponse{}, ErrExposureDenied
	}
	if err := service.appendAudit(ctx, record, request.Access, OperationGatewayUse, ""); err != nil {
		return GatewayResponse{}, err
	}
	material := CredentialMaterial{
		Exposure: record.Exposure, InjectionName: record.InjectionName,
	}
	if record.Exposure == ExposureShortLivedToken {
		if isNilDependency(service.tokenMinter) {
			return GatewayResponse{}, ErrTokenUnavailable
		}
		now := service.now().UTC()
		seed := append([]byte(nil), record.Value...)
		defer clear(seed)
		releaseLease = false
		token, mintErr := service.tokenMinter.Mint(ctx, TokenMintRequest{
			TenantID: record.TenantID, SecretID: record.SecretID, Version: record.Version,
			Endpoint: record.Endpoint, Audience: record.Audience, Seed: seed,
			ExpiresBy: now.Add(service.maximumTokenTTL),
		})
		releaseLease = true
		tokenValue := append([]byte(nil), token.Value...)
		tokenExpiresAt := token.ExpiresAt
		clear(token.Value)
		clear(seed)
		if mintErr != nil {
			clear(tokenValue)
			return GatewayResponse{}, ErrTokenFailed
		}
		if len(tokenValue) == 0 || len(tokenValue) > service.maximumSecretBytes ||
			!tokenExpiresAt.After(now) || tokenExpiresAt.After(now.Add(service.maximumTokenTTL)) {
			clear(tokenValue)
			return GatewayResponse{}, ErrTokenFailed
		}
		material.Value = tokenValue
		material.ExpiresAt = tokenExpiresAt.UTC()
	} else {
		material.Value = append([]byte(nil), record.Value...)
	}
	defer clear(material.Value)
	releaseLease = false
	response, dispatchErr := service.gateway.Dispatch(ctx, GatewayDispatch{
		Authority: request.Access, Endpoint: request.Endpoint, Audience: request.Audience,
		Payload: append([]byte(nil), request.Payload...), Recovery: recovery,
	}, material)
	if dispatchErr != nil || !response.RecoveryDurable || response.Recovery != recovery {
		return GatewayResponse{Recovery: recovery}, ErrGatewayFailed
	}
	releaseLease = true
	if len(response.Payload) > service.maximumResponseBytes {
		return GatewayResponse{}, ErrResponseTooLarge
	}
	return GatewayResponse{Payload: append([]byte(nil), response.Payload...)}, nil
}

func (service *Service) UseSandbox(
	ctx context.Context,
	request SandboxUseRequest,
) (result SandboxCleanupReceipt, resultErr error) {
	if err := ctx.Err(); err != nil {
		return SandboxCleanupReceipt{}, err
	}
	if isNilDependency(service.sandbox) {
		return SandboxCleanupReceipt{}, ErrSandboxUnavailable
	}
	if _, err := identity.Parse(identity.Invocation, request.InvocationID); err != nil ||
		!digestPattern.MatchString(request.BaseCacheKey) {
		return SandboxCleanupReceipt{}, ErrInvalidRequest
	}
	if err := service.authorizeHandle(
		ctx, request.Access, request.Handle, OperationSandboxUse, "", "", request.InvocationID,
	); err != nil {
		return SandboxCleanupReceipt{}, err
	}
	if request.Handle.exposure != ExposureSandboxEnv && request.Handle.exposure != ExposureSandboxFile {
		return SandboxCleanupReceipt{}, ErrExposureDenied
	}
	recordIdentity := Record{
		TenantID: request.Access.TenantID, SecretID: request.Handle.secretID,
		Version: request.Handle.version, Exposure: request.Handle.exposure,
		DestroySandboxAfterUse: request.Handle.destroySandboxAfterUse,
	}
	if err := service.appendAudit(
		ctx, recordIdentity, request.Access, OperationSandboxUse, request.InvocationID,
	); err != nil {
		return SandboxCleanupReceipt{}, err
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf(
		"circulusd.sandbox-secret-cache.v3\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%d\x00%d\x00%s\x00%s\x00%s\x00%s\x00%d\x00%s\x00%t",
		request.BaseCacheKey, request.Access.TenantID, request.Access.SubjectID,
		request.Access.SessionID, request.Access.WorkspaceID, request.Access.TurnID,
		request.Access.RuntimeRevision, request.Access.TurnLeaseGeneration,
		request.Access.PlacementGeneration, request.Access.SandboxGeneration,
		request.Access.AuthorizationGeneration, request.Access.Permission,
		request.Access.ServiceBinding, request.Access.AuthorityExpiresAt.Format(time.RFC3339Nano),
		request.Handle.secretID, request.Handle.version, request.Handle.exposure,
		request.Handle.destroySandboxAfterUse,
	)))
	resolvedCacheKey := "sha256:" + hex.EncodeToString(digest[:])
	dispatch := SandboxDispatch{
		TenantID: request.Access.TenantID, SubjectID: request.Access.SubjectID,
		SessionID: request.Access.SessionID, WorkspaceID: request.Access.WorkspaceID,
		InvocationID: request.InvocationID, ResolvedCacheKey: resolvedCacheKey,
		DestroySandboxAfterUse: request.Handle.destroySandboxAfterUse,
	}
	recoveryID, err := identity.New(identity.Operation)
	if err != nil {
		return SandboxCleanupReceipt{}, ErrSandboxFailed
	}
	recovery := UseRecoveryBinding{
		TenantID: request.Access.TenantID, SubjectID: request.Access.SubjectID,
		SessionID: request.Access.SessionID, WorkspaceID: request.Access.WorkspaceID,
		TurnID: request.Access.TurnID, RuntimeRevision: request.Access.RuntimeRevision,
		TurnLeaseGeneration:     request.Access.TurnLeaseGeneration,
		PlacementGeneration:     request.Access.PlacementGeneration,
		SandboxGeneration:       request.Access.SandboxGeneration,
		AuthorizationGeneration: request.Access.AuthorizationGeneration,
		Permission:              request.Access.Permission, ServiceBinding: request.Access.ServiceBinding,
		AuthorityExpiresAt:     request.Access.AuthorityExpiresAt,
		DestroySandboxAfterUse: request.Handle.destroySandboxAfterUse,
		SecretID:               request.Handle.secretID, SecretVersion: request.Handle.version,
		Exposure: request.Handle.exposure, InvocationID: request.InvocationID,
		RecoveryID: recoveryID.String(), ResolvedCacheKey: resolvedCacheKey,
	}
	permit := SandboxExposurePermit{
		InvocationID: request.InvocationID, RecoveryID: recovery.RecoveryID,
		ResolvedCacheKey: resolvedCacheKey, Recovery: recovery, Durable: true,
	}
	admission, err := service.admitHandleUse(
		ctx, request.Access, request.Handle, OperationSandboxUse,
		"", "", request.InvocationID,
	)
	if err != nil {
		return SandboxCleanupReceipt{}, err
	}
	lease, err := service.store.ReserveUse(ctx, ReserveUseRequest{
		TenantID: request.Access.TenantID, SecretID: request.Handle.secretID,
		ExpectedVersion: request.Handle.version, Recovery: recovery, Admission: admission,
	})
	if err != nil {
		if err == ErrStoreInUse {
			return SandboxCleanupReceipt{}, ErrStoreInUse
		}
		if err == ErrSecretNotFound {
			return SandboxCleanupReceipt{}, ErrStaleHandle
		}
		return SandboxCleanupReceipt{}, fmt.Errorf("%w: reservation failed", ErrStaleHandle)
	}
	releaseLease := false
	defer func() {
		if releaseLease {
			if err := service.releaseUse(ctx, lease); err != nil {
				result.InvocationID = request.InvocationID
				result.Recovery = recovery
				resultErr = errors.Join(resultErr, err)
			}
		}
	}()
	var record Record
	var material CredentialMaterial
	defer func() {
		panicValue := recover()
		if panicValue == nil {
			return
		}
		clear(material.Value)
		clear(record.Value)
		_, containErr := service.containSandboxUse(
			ctx, dispatch, permit, request.Handle.exposure, request.Handle.destroySandboxAfterUse,
		)
		if !errors.Is(containErr, ErrContainmentUnconfirmed) {
			releaseLease = true
		}
		panic(panicValue)
	}()
	prepared, prepareErr := service.sandbox.Prepare(ctx, dispatch, recovery)
	if prepareErr != nil || prepared != permit {
		contained, containErr := service.containSandboxUse(
			ctx, dispatch, permit, request.Handle.exposure, request.Handle.destroySandboxAfterUse,
		)
		if errors.Is(containErr, ErrContainmentUnconfirmed) {
			return contained, containErr
		}
		releaseLease = true
		if containErr != nil {
			return contained, containErr
		}
		return SandboxCleanupReceipt{}, ErrSandboxFailed
	}
	admission, err = service.admitHandleUse(
		ctx, request.Access, request.Handle, OperationSandboxUse,
		"", "", request.InvocationID,
	)
	if err != nil {
		contained, containErr := service.containSandboxUse(
			ctx, dispatch, permit, request.Handle.exposure, request.Handle.destroySandboxAfterUse,
		)
		if errors.Is(containErr, ErrContainmentUnconfirmed) {
			return contained, containErr
		}
		releaseLease = true
		if containErr != nil {
			return contained, containErr
		}
		return SandboxCleanupReceipt{}, err
	}
	record, err = service.store.AcquireReservedUse(ctx, AcquireReservedUseRequest{
		TenantID: request.Access.TenantID, SecretID: request.Handle.secretID,
		ExpectedVersion: request.Handle.version, Recovery: recovery, Lease: lease, Admission: admission,
	})
	if err != nil {
		clear(record.Value)
		contained, containErr := service.containSandboxUse(
			ctx, dispatch, permit, request.Handle.exposure, request.Handle.destroySandboxAfterUse,
		)
		if errors.Is(containErr, ErrContainmentUnconfirmed) {
			return contained, containErr
		}
		releaseLease = true
		if containErr != nil {
			return contained, containErr
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return SandboxCleanupReceipt{}, contextErr
		}
		if err == ErrSecretNotFound || err == ErrUseLeaseInvalid {
			return SandboxCleanupReceipt{}, ErrStaleHandle
		}
		if err == ErrStoreInUse {
			return SandboxCleanupReceipt{}, ErrStoreInUse
		}
		return SandboxCleanupReceipt{}, ErrAccessDenied
	}
	defer clear(record.Value)
	if validateRecord(record, service.maximumSecretBytes) != nil || !record.Active ||
		record.TenantID != request.Access.TenantID || record.SecretID != request.Handle.secretID ||
		record.Version != request.Handle.version || record.Exposure != request.Handle.exposure ||
		record.Endpoint != request.Handle.endpoint || record.Audience != request.Handle.audience ||
		record.DestroySandboxAfterUse != request.Handle.destroySandboxAfterUse {
		contained, containErr := service.containSandboxUse(
			ctx, dispatch, permit, request.Handle.exposure, request.Handle.destroySandboxAfterUse,
		)
		if errors.Is(containErr, ErrContainmentUnconfirmed) {
			return contained, containErr
		}
		releaseLease = true
		if containErr != nil {
			return contained, containErr
		}
		return SandboxCleanupReceipt{}, ErrStaleHandle
	}
	material = CredentialMaterial{
		Exposure: record.Exposure, InjectionName: record.InjectionName,
		Value: append([]byte(nil), record.Value...),
	}
	defer clear(material.Value)
	releaseLease = false
	receipt, useErr := service.sandbox.Use(ctx, dispatch, permit, material)
	if useErr != nil || receipt.InvocationID != request.InvocationID || receipt.Recovery != recovery ||
		!receipt.EnvironmentCleared ||
		(record.Exposure == ExposureSandboxFile && !receipt.FileRemoved) ||
		(record.DestroySandboxAfterUse && !receipt.SandboxDestroyed) {
		recovered, containErr := service.containSandboxUse(
			ctx, dispatch, permit, record.Exposure, record.DestroySandboxAfterUse,
		)
		if errors.Is(containErr, ErrContainmentUnconfirmed) {
			return recovered, containErr
		}
		releaseLease = true
		if containErr != nil {
			return recovered, containErr
		}
		if useErr != nil {
			return SandboxCleanupReceipt{}, ErrSandboxFailed
		}
		return recovered, nil
	}
	releaseLease = true
	return receipt, nil
}

func (service *Service) containSandboxUse(
	ctx context.Context,
	dispatch SandboxDispatch,
	permit SandboxExposurePermit,
	exposure ExposureClass,
	destroySandboxAfterUse bool,
) (SandboxCleanupReceipt, error) {
	cleanupContext, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), service.recoveryTimeout)
	defer cancelCleanup()
	recovered, cleanupErr := service.sandbox.Cleanup(cleanupContext, dispatch, permit)
	if cleanupErr == nil && recovered.InvocationID == permit.InvocationID && recovered.Recovery == permit.Recovery &&
		recovered.EnvironmentCleared && (exposure != ExposureSandboxFile || recovered.FileRemoved) &&
		(!destroySandboxAfterUse || recovered.SandboxDestroyed) {
		return recovered, nil
	}
	quarantineContext, cancelQuarantine := context.WithTimeout(context.WithoutCancel(ctx), service.recoveryTimeout)
	defer cancelQuarantine()
	quarantine, quarantineErr := service.sandbox.Quarantine(quarantineContext, dispatch, permit)
	if quarantineErr != nil || !quarantine.Durable || quarantine.InvocationID != permit.InvocationID ||
		quarantine.RecoveryID != permit.RecoveryID || quarantine.ResolvedCacheKey != permit.ResolvedCacheKey {
		return SandboxCleanupReceipt{
			InvocationID: permit.InvocationID, Recovery: permit.Recovery,
		}, ErrContainmentUnconfirmed
	}
	return SandboxCleanupReceipt{}, ErrCleanupUnconfirmed
}

func (service *Service) RecoverSandbox(
	ctx context.Context,
	request SandboxRecoveryRequest,
) (SandboxQuarantineReceipt, error) {
	if err := ctx.Err(); err != nil {
		return SandboxQuarantineReceipt{}, err
	}
	recovery := request.Recovery
	if isNilDependency(service.sandbox) || validateRecoveryAuthority(request.Authority) != nil ||
		validateRecoveryBinding(recovery) != nil || request.Authority.TenantID != recovery.TenantID ||
		(recovery.Exposure != ExposureSandboxEnv && recovery.Exposure != ExposureSandboxFile) {
		return SandboxQuarantineReceipt{}, ErrInvalidRequest
	}
	if err := service.authorizeRecovery(ctx, RecoveryContainSandbox, request.Authority, recovery); err != nil {
		return SandboxQuarantineReceipt{}, err
	}
	if err := service.store.ValidateUseRecovery(ctx, recovery); err != nil {
		return SandboxQuarantineReceipt{}, ErrUseLeaseInvalid
	}
	if err := service.appendRecoveryAudit(ctx, RecoveryContainSandbox, request.Authority, recovery); err != nil {
		return SandboxQuarantineReceipt{}, err
	}
	dispatch := SandboxDispatch{
		TenantID: recovery.TenantID, SubjectID: recovery.SubjectID,
		SessionID: recovery.SessionID, WorkspaceID: recovery.WorkspaceID,
		InvocationID: recovery.InvocationID, ResolvedCacheKey: recovery.ResolvedCacheKey,
		DestroySandboxAfterUse: recovery.DestroySandboxAfterUse,
	}
	permit := SandboxExposurePermit{
		InvocationID: recovery.InvocationID, RecoveryID: recovery.RecoveryID,
		ResolvedCacheKey: recovery.ResolvedCacheKey, Recovery: recovery, Durable: true,
	}
	recoveryContext, cancelRecovery := context.WithTimeout(ctx, service.recoveryTimeout)
	defer cancelRecovery()
	receipt, err := service.sandbox.Quarantine(recoveryContext, dispatch, permit)
	if err != nil || !receipt.Durable || receipt.InvocationID != recovery.InvocationID ||
		receipt.RecoveryID != recovery.RecoveryID || receipt.ResolvedCacheKey != recovery.ResolvedCacheKey {
		return SandboxQuarantineReceipt{}, ErrContainmentUnconfirmed
	}
	if err := service.completeUseRecovery(ctx, recovery); err != nil {
		return receipt, ErrUseReleaseUnconfirmed
	}
	return receipt, nil
}

func (service *Service) RecoverGateway(
	ctx context.Context,
	request GatewayRecoveryRequest,
) (GatewayRecoveryReference, error) {
	if err := ctx.Err(); err != nil {
		return GatewayRecoveryReference{}, err
	}
	recovery := request.Recovery
	if isNilDependency(service.gateway) || validateRecoveryAuthority(request.Authority) != nil ||
		validateRecoveryBinding(recovery) != nil ||
		request.Authority.TenantID != recovery.TenantID ||
		(recovery.Exposure != ExposureProxyOnly && recovery.Exposure != ExposureGatewayHeader &&
			recovery.Exposure != ExposureShortLivedToken) {
		return GatewayRecoveryReference{}, ErrInvalidRequest
	}
	if err := service.authorizeRecovery(ctx, RecoveryReleaseGateway, request.Authority, recovery); err != nil {
		return GatewayRecoveryReference{}, err
	}
	if err := service.store.ValidateUseRecovery(ctx, recovery); err != nil {
		return GatewayRecoveryReference{}, ErrUseLeaseInvalid
	}
	if err := service.appendRecoveryAudit(ctx, RecoveryReleaseGateway, request.Authority, recovery); err != nil {
		return recovery, err
	}
	recoveryContext, cancelRecovery := context.WithTimeout(ctx, service.recoveryTimeout)
	defer cancelRecovery()
	receipt, err := service.gateway.Recover(recoveryContext, GatewayRecoveryDispatch{Recovery: recovery})
	if err != nil || !receipt.Durable || !receipt.SafeToRelease || receipt.Recovery != recovery {
		return recovery, ErrGatewayRecoveryUnconfirmed
	}
	if err := service.completeUseRecovery(ctx, recovery); err != nil {
		return recovery, ErrUseReleaseUnconfirmed
	}
	return recovery, nil
}

func (service *Service) ListPendingRecoveries(
	ctx context.Context,
	request PendingRecoveryRequest,
) (PendingUseRecoveryPage, error) {
	if err := ctx.Err(); err != nil {
		return PendingUseRecoveryPage{}, err
	}
	if validateRecoveryAuthority(request.Authority) != nil {
		return PendingUseRecoveryPage{}, ErrInvalidRequest
	}
	if err := service.authorizeRecovery(
		ctx, RecoveryListPending, request.Authority, UseRecoveryBinding{},
	); err != nil {
		return PendingUseRecoveryPage{}, err
	}
	if err := service.appendRecoveryAudit(
		ctx, RecoveryListPending, request.Authority, UseRecoveryBinding{TenantID: request.Authority.TenantID},
	); err != nil {
		return PendingUseRecoveryPage{}, err
	}
	return service.store.ListPendingUseRecoveries(ctx, PendingUseRecoveryQuery{
		TenantID: request.Authority.TenantID, AfterRecoveryID: request.AfterRecoveryID,
		Limit: request.Limit,
	})
}

func (service *Service) authorizeHandle(
	ctx context.Context,
	access AccessContext,
	handle Handle,
	operation Operation,
	endpoint string,
	audience string,
	invocationID string,
) error {
	now := service.now().Round(0).UTC()
	if validateAccess(access) != nil || access.ServiceBinding != service.serviceBinding ||
		handle.version == 0 || validateSecretID(handle.secretID) != nil ||
		!validExposure(handle.exposure) || handle.access != access || handle.endpoint != endpoint ||
		handle.audience != audience || handle.invocationID != invocationID || handle.expiresAt.IsZero() ||
		!now.Before(handle.expiresAt) || !now.Before(access.AuthorityExpiresAt) {
		return ErrStaleHandle
	}
	if err := service.authorizer.Authorize(ctx, AuthorizationRequest{
		Operation: operation, Access: access, SecretID: handle.secretID,
		Exposure: handle.exposure, Endpoint: handle.endpoint, Audience: handle.audience,
		InvocationID: invocationID,
	}); err != nil {
		return ErrAccessDenied
	}
	return nil
}

func (service *Service) beginHandleUse(
	ctx context.Context,
	access AccessContext,
	handle Handle,
	recovery UseRecoveryBinding,
	admission UseAdmissionPermit,
) (Record, UseLease, error) {
	record, lease, err := service.store.BeginUse(ctx, BeginUseRequest{
		TenantID: access.TenantID, SecretID: handle.secretID,
		ExpectedVersion: handle.version, Recovery: recovery, Admission: admission,
	})
	if err != nil {
		clear(record.Value)
		if err == ErrSecretNotFound {
			return Record{}, UseLease{}, ErrStaleHandle
		}
		if err == ErrStoreInUse {
			return Record{}, UseLease{}, ErrStoreInUse
		}
		return Record{}, UseLease{}, fmt.Errorf("%w: read failed", ErrStaleHandle)
	}
	if validateRecord(record, service.maximumSecretBytes) != nil || !record.Active ||
		record.TenantID != access.TenantID || record.SecretID != handle.secretID ||
		record.Version != handle.version || record.Exposure != handle.exposure ||
		record.Endpoint != handle.endpoint || record.Audience != handle.audience ||
		record.DestroySandboxAfterUse != handle.destroySandboxAfterUse {
		clear(record.Value)
		if err := service.releaseUse(ctx, lease); err != nil {
			return Record{}, UseLease{}, errors.Join(ErrStaleHandle, err)
		}
		return Record{}, UseLease{}, ErrStaleHandle
	}
	return record, lease, nil
}

func (service *Service) admitHandleUse(
	ctx context.Context,
	access AccessContext,
	handle Handle,
	operation Operation,
	endpoint string,
	audience string,
	invocationID string,
) (UseAdmissionPermit, error) {
	now := service.now().Round(0).UTC()
	if !now.Before(handle.expiresAt) {
		return UseAdmissionPermit{}, ErrStaleHandle
	}
	authorization := AuthorizationRequest{
		Operation: operation, Access: access, SecretID: handle.secretID,
		Exposure: handle.exposure, Endpoint: endpoint, Audience: audience,
		InvocationID: invocationID,
	}
	request := UseAdmissionRequest{
		Authorization: authorization, HandleExpiresAt: handle.expiresAt, RequestedAt: now,
	}
	permit, err := service.admitter.Admit(ctx, request)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return UseAdmissionPermit{}, contextErr
		}
		return UseAdmissionPermit{}, ErrAccessDenied
	}
	now = service.now().Round(0).UTC()
	if permit.Authorization != authorization || !permit.HandleExpiresAt.Equal(handle.expiresAt) ||
		!permit.IssuedAt.Equal(request.RequestedAt) || validateUseAdmission(permit, now) != nil {
		if !now.Before(handle.expiresAt) {
			return UseAdmissionPermit{}, ErrStaleHandle
		}
		return UseAdmissionPermit{}, ErrAccessDenied
	}
	return permit, nil
}

func (service *Service) releaseUse(ctx context.Context, lease UseLease) error {
	releaseContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), service.recoveryTimeout)
	defer cancel()
	if err := service.store.EndUse(releaseContext, lease); err != nil {
		return ErrUseReleaseUnconfirmed
	}
	return nil
}

func (service *Service) completeUseRecovery(ctx context.Context, recovery UseRecoveryBinding) error {
	completionContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), service.recoveryTimeout)
	defer cancel()
	return service.store.CompleteUseRecovery(completionContext, recovery)
}

func (service *Service) appendAudit(
	ctx context.Context,
	record Record,
	access AccessContext,
	operation Operation,
	invocationID string,
) error {
	receipt, err := service.audit.Append(ctx, AuditEvent{
		Operation: operation, TenantID: access.TenantID, SubjectID: access.SubjectID,
		SessionID: access.SessionID, WorkspaceID: access.WorkspaceID,
		InvocationID: invocationID, SecretID: record.SecretID, Version: record.Version,
		Exposure: record.Exposure, Endpoint: record.Endpoint, Audience: record.Audience,
		TurnID: access.TurnID, RuntimeRevision: access.RuntimeRevision,
		TurnLeaseGeneration:     access.TurnLeaseGeneration,
		PlacementGeneration:     access.PlacementGeneration,
		SandboxGeneration:       access.SandboxGeneration,
		AuthorizationGeneration: access.AuthorizationGeneration,
		Permission:              access.Permission, ServiceBinding: access.ServiceBinding,
		AuthorityExpiresAt: access.AuthorityExpiresAt,
	})
	if err != nil || !receipt.Durable || receipt.Sequence == 0 {
		return ErrAuditNotDurable
	}
	return nil
}

func (service *Service) authorizeRecovery(
	ctx context.Context,
	operation RecoveryOperation,
	authority RecoveryAuthority,
	recovery UseRecoveryBinding,
) error {
	if err := service.recoveryAuthorizer.AuthorizeRecovery(ctx, RecoveryAuthorizationRequest{
		Operation: operation, Authority: authority, RecoveryID: recovery.RecoveryID,
		OriginalSubjectID: recovery.SubjectID, SessionID: recovery.SessionID,
		WorkspaceID: recovery.WorkspaceID, AuthorizationGeneration: recovery.AuthorizationGeneration,
		TurnID: recovery.TurnID, RuntimeRevision: recovery.RuntimeRevision,
		TurnLeaseGeneration: recovery.TurnLeaseGeneration,
		PlacementGeneration: recovery.PlacementGeneration,
		SandboxGeneration:   recovery.SandboxGeneration,
		Permission:          recovery.Permission, ServiceBinding: recovery.ServiceBinding,
		AuthorityExpiresAt:     recovery.AuthorityExpiresAt,
		DestroySandboxAfterUse: recovery.DestroySandboxAfterUse,
		SecretID:               recovery.SecretID, SecretVersion: recovery.SecretVersion,
		Exposure: recovery.Exposure, InvocationID: recovery.InvocationID,
		ResolvedCacheKey: recovery.ResolvedCacheKey, Endpoint: recovery.Endpoint, Audience: recovery.Audience,
	}); err != nil {
		return ErrRecoveryDenied
	}
	return nil
}

func (service *Service) appendRecoveryAudit(
	ctx context.Context,
	operation RecoveryOperation,
	authority RecoveryAuthority,
	recovery UseRecoveryBinding,
) error {
	receipt, err := service.recoveryAudit.AppendRecovery(ctx, RecoveryAuditEvent{
		Operation: operation, Authority: authority, RecoveryID: recovery.RecoveryID,
		TenantID: recovery.TenantID, OriginalSubjectID: recovery.SubjectID,
		SessionID: recovery.SessionID, WorkspaceID: recovery.WorkspaceID,
		TurnID: recovery.TurnID, RuntimeRevision: recovery.RuntimeRevision,
		TurnLeaseGeneration:     recovery.TurnLeaseGeneration,
		PlacementGeneration:     recovery.PlacementGeneration,
		SandboxGeneration:       recovery.SandboxGeneration,
		AuthorizationGeneration: recovery.AuthorizationGeneration,
		Permission:              recovery.Permission, ServiceBinding: recovery.ServiceBinding,
		AuthorityExpiresAt:     recovery.AuthorityExpiresAt,
		DestroySandboxAfterUse: recovery.DestroySandboxAfterUse,
		SecretID:               recovery.SecretID, SecretVersion: recovery.SecretVersion,
		Exposure: recovery.Exposure, InvocationID: recovery.InvocationID,
		ResolvedCacheKey: recovery.ResolvedCacheKey, Endpoint: recovery.Endpoint, Audience: recovery.Audience,
	})
	if err != nil || !receipt.Durable || receipt.Sequence == 0 {
		return ErrRecoveryAuditNotDurable
	}
	return nil
}

func validateRecord(record Record, maximumSecretBytes int) error {
	if _, err := identity.Parse(identity.Tenant, record.TenantID); err != nil ||
		validateSecretID(record.SecretID) != nil || record.Version == 0 || !validExposure(record.Exposure) ||
		(record.Active && len(record.Value) == 0) || len(record.Value) > maximumSecretBytes ||
		validateBinding(record.Exposure, record.InjectionName, record.Endpoint, record.Audience) != nil {
		return ErrInvalidRequest
	}
	if record.DestroySandboxAfterUse && record.Exposure != ExposureSandboxEnv && record.Exposure != ExposureSandboxFile {
		return ErrInvalidRequest
	}
	return nil
}

func validateUseAdmission(permit UseAdmissionPermit, now time.Time) error {
	if validateAccess(permit.Authorization.Access) != nil ||
		validateSecretID(permit.Authorization.SecretID) != nil ||
		!validExposure(permit.Authorization.Exposure) || permit.HandleExpiresAt.IsZero() ||
		permit.IssuedAt.IsZero() || permit.ExpiresAt.IsZero() || len(permit.Proof) == 0 ||
		len(permit.Proof) > maximumAdmissionProofBytes || !utf8.ValidString(permit.Proof) ||
		!permit.IssuedAt.Equal(permit.IssuedAt.Round(0).UTC()) ||
		!permit.ExpiresAt.Equal(permit.ExpiresAt.Round(0).UTC()) ||
		!permit.HandleExpiresAt.Equal(permit.HandleExpiresAt.Round(0).UTC()) ||
		now.Before(permit.IssuedAt) || !now.Before(permit.ExpiresAt) ||
		!now.Before(permit.HandleExpiresAt) || !now.Before(permit.Authorization.Access.AuthorityExpiresAt) ||
		permit.ExpiresAt.After(permit.HandleExpiresAt) ||
		permit.HandleExpiresAt.After(permit.Authorization.Access.AuthorityExpiresAt) {
		return ErrAccessDenied
	}
	switch permit.Authorization.Operation {
	case OperationGatewayUse:
		if permit.Authorization.InvocationID != "" || validateEndpoint(permit.Authorization.Endpoint) != nil ||
			validateBoundedText(permit.Authorization.Audience, false) != nil ||
			(permit.Authorization.Exposure != ExposureProxyOnly &&
				permit.Authorization.Exposure != ExposureGatewayHeader &&
				permit.Authorization.Exposure != ExposureShortLivedToken) {
			return ErrAccessDenied
		}
	case OperationSandboxUse:
		if permit.Authorization.Endpoint != "" || permit.Authorization.Audience != "" ||
			(permit.Authorization.Exposure != ExposureSandboxEnv &&
				permit.Authorization.Exposure != ExposureSandboxFile) {
			return ErrAccessDenied
		}
		if _, err := identity.Parse(identity.Invocation, permit.Authorization.InvocationID); err != nil {
			return ErrAccessDenied
		}
	default:
		return ErrAccessDenied
	}
	return nil
}

func validateAccess(access AccessContext) error {
	for kind, value := range map[identity.Kind]string{
		identity.Tenant: access.TenantID, identity.Subject: access.SubjectID,
		identity.Session: access.SessionID, identity.Workspace: access.WorkspaceID,
		identity.Turn: access.TurnID, identity.RuntimeRevision: access.RuntimeRevision,
	} {
		if _, err := identity.Parse(kind, value); err != nil {
			return ErrInvalidRequest
		}
	}
	for _, generation := range []uint64{
		access.TurnLeaseGeneration, access.PlacementGeneration, access.SandboxGeneration,
		access.AuthorizationGeneration,
	} {
		if generation == 0 || generation > maximumSharedGeneration {
			return ErrInvalidRequest
		}
	}
	if validateBoundedText(access.Permission, false) != nil ||
		validateBoundedText(access.ServiceBinding, false) != nil || access.AuthorityExpiresAt.IsZero() ||
		!access.AuthorityExpiresAt.Equal(access.AuthorityExpiresAt.Round(0).UTC()) {
		return ErrInvalidRequest
	}
	return nil
}

func validateRecoveryAuthority(authority RecoveryAuthority) error {
	if _, err := identity.Parse(identity.Tenant, authority.TenantID); err != nil {
		return ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Subject, authority.SubjectID); err != nil {
		return ErrInvalidRequest
	}
	return nil
}

func validateSecretID(value string) error {
	if !secretIDPattern.MatchString(value) || !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) {
		return ErrInvalidRequest
	}
	return nil
}

func validExposure(value ExposureClass) bool {
	switch value {
	case ExposureProxyOnly, ExposureGatewayHeader, ExposureSandboxEnv, ExposureSandboxFile, ExposureShortLivedToken:
		return true
	default:
		return false
	}
}

func validateBinding(exposure ExposureClass, injectionName string, endpoint string, audience string) error {
	switch exposure {
	case ExposureProxyOnly, ExposureGatewayHeader, ExposureShortLivedToken:
		if !validHeaderName(injectionName) || validateEndpoint(endpoint) != nil ||
			validateBoundedText(audience, false) != nil {
			return ErrInvalidRequest
		}
	case ExposureSandboxEnv:
		if !environmentNamePattern.MatchString(injectionName) || endpoint != "" || audience != "" {
			return ErrInvalidRequest
		}
	case ExposureSandboxFile:
		if validateBoundedText(injectionName, false) != nil ||
			!strings.HasPrefix(injectionName, "/run/credentials/") || path.Clean(injectionName) != injectionName ||
			strings.Contains(injectionName, "..") || endpoint != "" || audience != "" {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

func validateEndpoint(value string) error {
	if validateBoundedText(value, false) != nil || len(value) > maximumEndpointBytes {
		return ErrInvalidRequest
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.String() != value {
		return ErrInvalidRequest
	}
	return nil
}

func validateBoundedText(value string, allowEmpty bool) error {
	if (!allowEmpty && value == "") || len(value) > maximumTextBytes || !utf8.ValidString(value) ||
		!norm.NFC.IsNormalString(value) {
		return ErrInvalidRequest
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return ErrInvalidRequest
		}
	}
	return nil
}

func validHeaderName(value string) bool {
	if value == "" || len(value) > maximumTextBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character)) {
			return false
		}
	}
	return true
}

func isNilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
