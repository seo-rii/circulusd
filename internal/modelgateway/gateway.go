package modelgateway

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
	"golang.org/x/text/unicode/norm"
)

const (
	hardMaxAuthorityBytes         = 64 << 10
	hardMaxMessages               = 4096
	hardMaxMessageBytes           = 1 << 20
	hardMaxInputBytes             = 8 << 20
	hardMaxIdentifierBytes        = 256
	hardMaxProviderRequestIDBytes = 1024
	hardMaxEventBytes             = 1 << 20
	hardMaxEvents                 = 1 << 20
	hardMaxStreamBytes            = 64 << 20
	hardMaxResponseBytes          = 64 << 20
	hardMaxReasonBytes            = 4096
	hardMaxPreDispatchRetries     = 16
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

type grantKey struct {
	tenant identity.ID
	user   identity.ID
	model  string
}

// Gateway is immutable after construction. Its collaborators must be safe for
// concurrent use. Apply itself is pure; durable writers must CAS Effect.Revision.
type Gateway struct {
	bounds       Bounds
	grants       map[grantKey]ModelGrant
	authority    AuthorityValidator
	tokenCounter TokenCounter
	quota        QuotaAdmitter
	dispatches   DispatchCoordinator
	providers    map[string]Provider
}

func NewGateway(configuration Configuration, dependencies Dependencies) (*Gateway, error) {
	bounds := configuration.Bounds
	if bounds.MaxAuthorityBytes == 0 || bounds.MaxAuthorityBytes > hardMaxAuthorityBytes ||
		bounds.MaxMessages == 0 || bounds.MaxMessages > hardMaxMessages ||
		bounds.MaxMessageBytes == 0 || bounds.MaxMessageBytes > hardMaxMessageBytes ||
		bounds.MaxInputBytes == 0 || bounds.MaxInputBytes > hardMaxInputBytes ||
		bounds.MaxModelBytes == 0 || bounds.MaxModelBytes > hardMaxIdentifierBytes ||
		bounds.MaxProviderIDBytes == 0 || bounds.MaxProviderIDBytes > hardMaxIdentifierBytes ||
		bounds.MaxProviderRequestIDBytes == 0 || bounds.MaxProviderRequestIDBytes > hardMaxProviderRequestIDBytes ||
		bounds.MaxEventBytes == 0 || bounds.MaxEventBytes > hardMaxEventBytes ||
		bounds.MaxEvents == 0 || bounds.MaxEvents > hardMaxEvents ||
		bounds.MaxStreamBytes == 0 || bounds.MaxStreamBytes > hardMaxStreamBytes ||
		bounds.MaxResponseBytes == 0 || bounds.MaxResponseBytes > hardMaxResponseBytes ||
		bounds.MaxReasonBytes == 0 || bounds.MaxReasonBytes > hardMaxReasonBytes ||
		bounds.MaxMessageBytes > bounds.MaxInputBytes || bounds.MaxEvents < 4 {
		return nil, fmt.Errorf("%w: every input and event bound must be positive, internally consistent, and below its hard ceiling", ErrInvalidConfiguration)
	}
	missingTrustedDependency := false
	for _, dependency := range []any{dependencies.Authority, dependencies.TokenCounter, dependencies.Quota, dependencies.Dispatches} {
		if dependency == nil {
			missingTrustedDependency = true
			break
		}
		dependencyValue := reflect.ValueOf(dependency)
		switch dependencyValue.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			if dependencyValue.IsNil() {
				missingTrustedDependency = true
			}
		}
		if missingTrustedDependency {
			break
		}
	}
	if missingTrustedDependency || len(dependencies.Providers) == 0 {
		return nil, fmt.Errorf("%w: authority, token counter, quota admitter, dispatch coordinator, and provider registry are required", ErrInvalidConfiguration)
	}
	authorityDurability := dependencies.Authority.Durability()
	authorityIsDurable := authorityDurability.CrashDurable && authorityDurability.CurrentGenerationFencing && !authorityDurability.ReferenceMemory
	authorityIsAllowedReference := configuration.AllowReferenceMemory && !authorityDurability.CrashDurable &&
		authorityDurability.CurrentGenerationFencing && authorityDurability.ReferenceMemory
	quotaDurability := dependencies.Quota.Durability()
	quotaIsDurable := quotaDurability.CrashDurable && quotaDurability.AtomicReservationSettlement && !quotaDurability.ReferenceMemory
	quotaIsAllowedReference := configuration.AllowReferenceMemory && !quotaDurability.CrashDurable &&
		quotaDurability.AtomicReservationSettlement && quotaDurability.ReferenceMemory
	dispatchDurability := dependencies.Dispatches.Durability()
	dispatchIsDurable := dispatchDurability.CrashDurable && dispatchDurability.AtomicEffectTransitions &&
		dispatchDurability.ExclusiveDispatchClaim && !dispatchDurability.ReferenceMemory
	dispatchIsAllowedReference := configuration.AllowReferenceMemory && !dispatchDurability.CrashDurable &&
		dispatchDurability.AtomicEffectTransitions && dispatchDurability.ExclusiveDispatchClaim && dispatchDurability.ReferenceMemory
	if (!authorityIsDurable && !authorityIsAllowedReference) || (!quotaIsDurable && !quotaIsAllowedReference) ||
		(!dispatchIsDurable && !dispatchIsAllowedReference) {
		return nil, ErrStateDependenciesNotDurable
	}
	providers := make(map[string]Provider, len(dependencies.Providers))
	for providerID, provider := range dependencies.Providers {
		providerIsNil := provider == nil
		if !providerIsNil {
			providerValue := reflect.ValueOf(provider)
			switch providerValue.Kind() {
			case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
				providerIsNil = providerValue.IsNil()
			}
		}
		if !identifierPattern.MatchString(providerID) || uint64(len(providerID)) > bounds.MaxProviderIDBytes || providerIsNil {
			return nil, fmt.Errorf("%w: invalid provider registration %q", ErrInvalidConfiguration, providerID)
		}
		providers[providerID] = provider
	}
	if len(configuration.Grants) == 0 {
		return nil, fmt.Errorf("%w: at least one exact tenant/user/model grant is required", ErrInvalidConfiguration)
	}
	grants := make(map[grantKey]ModelGrant, len(configuration.Grants))
	for _, grant := range configuration.Grants {
		if grant.TenantID.Kind() != identity.Tenant || grant.UserID.Kind() != identity.Subject ||
			!identifierPattern.MatchString(grant.Model) || uint64(len(grant.Model)) > bounds.MaxModelBytes ||
			!identifierPattern.MatchString(grant.ProviderID) || uint64(len(grant.ProviderID)) > bounds.MaxProviderIDBytes ||
			grant.MaxContextTokens == 0 || grant.MaxOutputTokens == 0 || grant.MaxTotalTokens == 0 ||
			grant.MaxContextTokens > grant.MaxTotalTokens || grant.MaxOutputTokens > grant.MaxTotalTokens ||
			grant.MaxPreDispatchRetries > hardMaxPreDispatchRetries ||
			uint64(bounds.MaxEvents) < uint64(grant.MaxPreDispatchRetries)*2+4 {
			return nil, fmt.Errorf("%w: invalid model grant", ErrInvalidConfiguration)
		}
		if _, found := providers[grant.ProviderID]; !found {
			return nil, fmt.Errorf("%w: model grant references unregistered provider %q", ErrInvalidConfiguration, grant.ProviderID)
		}
		key := grantKey{tenant: grant.TenantID, user: grant.UserID, model: grant.Model}
		if _, duplicate := grants[key]; duplicate {
			return nil, fmt.Errorf("%w: duplicate tenant/user/model grant", ErrInvalidConfiguration)
		}
		grants[key] = grant
	}
	return &Gateway{
		bounds:       bounds,
		grants:       grants,
		authority:    dependencies.Authority,
		tokenCounter: dependencies.TokenCounter,
		quota:        dependencies.Quota,
		dispatches:   dependencies.Dispatches,
		providers:    providers,
	}, nil
}

func (gateway *Gateway) Admit(ctx context.Context, request AdmissionRequest) (Effect, error) {
	if err := ctx.Err(); err != nil {
		return Effect{}, err
	}
	if request.EffectID.Kind() != identity.Effect || request.InvocationID.Kind() != identity.Invocation || request.RequestDigest == (Digest{}) ||
		len(request.Authority) == 0 || uint64(len(request.Authority)) > gateway.bounds.MaxAuthorityBytes {
		return Effect{}, ErrInvalidRequest
	}
	if err := gateway.validateModelRequest(request.Request); err != nil {
		return Effect{}, err
	}
	normalizedReasoning, err := normalizeReasoningOptions(request.Request.Reasoning)
	if err != nil {
		return Effect{}, err
	}
	request.Request.Reasoning = normalizedReasoning
	requestDigest, err := ModelRequestDigest(request.Request)
	if err != nil || requestDigest != request.RequestDigest {
		return Effect{}, fmt.Errorf("%w: model request digest does not match the prepared effect", ErrInvalidRequest)
	}

	credential := append(OpaqueAuthority(nil), request.Authority...)
	scope, err := gateway.authority.ValidateAdmission(ctx, credential, AdmissionAuthorityRequest{
		EffectID: request.EffectID, InvocationID: request.InvocationID, RequestDigest: request.RequestDigest, Permission: "model.dispatch",
	})
	if err != nil {
		return Effect{}, err
	}
	if scope.TenantID.Kind() != identity.Tenant || scope.UserID.Kind() != identity.Subject || scope.SessionID.Kind() != identity.Session ||
		scope.TurnID.Kind() != identity.Turn || scope.EffectID != request.EffectID || scope.InvocationID != request.InvocationID ||
		scope.RuntimeRevision.Kind() != identity.RuntimeRevision || scope.Generations.TurnLease == 0 || scope.Generations.Placement == 0 || scope.Generations.Policy == 0 {
		return Effect{}, ErrAuthorityMismatch
	}
	grant, allowed := gateway.grants[grantKey{tenant: scope.TenantID, user: scope.UserID, model: request.Request.Model}]
	if !allowed {
		return Effect{}, ErrModelNotAllowed
	}

	countRequest := TokenCountRequest{Model: request.Request.Model, Messages: append([]Message(nil), request.Request.Messages...)}
	contextTokens, err := gateway.tokenCounter.Count(ctx, countRequest)
	if err != nil {
		return Effect{}, fmt.Errorf("count model context: %w", err)
	}
	if contextTokens > grant.MaxContextTokens || request.Request.MaxOutputTokens > grant.MaxOutputTokens ||
		contextTokens > grant.MaxTotalTokens || request.Request.MaxOutputTokens > grant.MaxTotalTokens-contextTokens {
		return Effect{}, ErrTokenLimit
	}
	provider := gateway.providers[grant.ProviderID]
	availability, err := provider.Availability(ctx)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return Effect{}, contextErr
		}
		return Effect{}, fmt.Errorf("%w: availability probe failed", ErrProviderUnavailable)
	}
	if !availability.Available {
		return Effect{}, ErrProviderUnavailable
	}
	if availability.DurableRequestRetrieval {
		if _, supported := provider.(ProviderRequestRetriever); !supported {
			return Effect{}, fmt.Errorf("%w: provider advertised durable retrieval without implementing its contract", ErrProviderUnavailable)
		}
	}

	quotaRequest := QuotaRequest{
		TenantID: scope.TenantID, UserID: scope.UserID, SessionID: scope.SessionID, TurnID: scope.TurnID,
		EffectID: scope.EffectID, InvocationID: scope.InvocationID, RequestDigest: request.RequestDigest,
		RuntimeRevision: scope.RuntimeRevision, Generations: scope.Generations,
		ContextTokens: contextTokens, OutputTokens: request.Request.MaxOutputTokens,
	}
	permit, err := gateway.quota.Admit(ctx, quotaRequest)
	if err != nil {
		return Effect{}, err
	}
	if !permit.Durable || permit.ReservationID == "" || len(permit.ReservationID) > 256 || !utf8.ValidString(permit.ReservationID) || strings.IndexFunc(permit.ReservationID, unicode.IsControl) >= 0 ||
		permit.TenantID != quotaRequest.TenantID || permit.UserID != quotaRequest.UserID || permit.EffectID != quotaRequest.EffectID ||
		permit.InvocationID != quotaRequest.InvocationID || permit.SessionID != quotaRequest.SessionID || permit.TurnID != quotaRequest.TurnID ||
		permit.RuntimeRevision != quotaRequest.RuntimeRevision || permit.Generations != quotaRequest.Generations || permit.RequestDigest != quotaRequest.RequestDigest ||
		permit.ContextTokens != quotaRequest.ContextTokens || permit.OutputTokens != quotaRequest.OutputTokens {
		return Effect{}, ErrQuotaMismatch
	}

	return Effect{
		Scope: scope, RequestDigest: request.RequestDigest, Request: cloneModelRequest(request.Request), ProviderID: grant.ProviderID,
		QuotaPermit: permit, ContextTokens: contextTokens, RequestedOutputTokens: request.Request.MaxOutputTokens,
		MaxContextTokens: grant.MaxContextTokens, MaxTotalTokens: grant.MaxTotalTokens,
		MaxPreDispatchRetries: grant.MaxPreDispatchRetries, DurableRequestRetrieval: availability.DurableRequestRetrieval,
		State: StateAdmitted, Revision: 1,
	}, nil
}

func (gateway *Gateway) AuthorizeSettlement(ctx context.Context, effect Effect, authority OpaqueAuthority) (Settlement, error) {
	authorized, err := gateway.authorizeTerminal(ctx, effect, authority)
	if err != nil {
		return Settlement{}, err
	}
	quotaRequest := QuotaSettlementRequest{
		Permit: effect.QuotaPermit, Authorization: authorized.permit, Recovery: effect.RecoveryPermit, Outcome: effect.Outcome,
		ProviderRequestID: effect.ProviderRequestID, Attempt: effect.Attempt,
	}
	switch effect.Outcome {
	case OutcomeCompleted:
		quotaRequest.Disposition = QuotaDispositionConsume
		quotaRequest.Usage = effect.Response.Usage
	case OutcomeFailed, OutcomeCancelled:
		quotaRequest.Disposition = QuotaDispositionRelease
	case OutcomeUncertain:
		quotaRequest.Disposition = QuotaDispositionHold
	default:
		return Settlement{}, ErrSettlementNotReady
	}
	quotaReceipt, err := gateway.quota.Settle(ctx, quotaRequest)
	if err != nil {
		return Settlement{}, err
	}
	if !gateway.validQuotaSettlementReceipt(effect, quotaRequest, quotaReceipt) {
		return Settlement{}, ErrQuotaMismatch
	}
	return gateway.settlementResult(effect, authorized.currentScope, quotaReceipt, effect.Outcome == OutcomeUncertain), nil
}

// ResolveUncertain applies an explicit, durable user/operator accounting
// decision to an uncertain provider request. It never re-dispatches inference.
func (gateway *Gateway) ResolveUncertain(ctx context.Context, effect Effect, authority OpaqueAuthority, resolution UncertainResolution) (Settlement, error) {
	var disposition QuotaDisposition
	var permission string
	switch resolution {
	case UncertainResolutionConsume:
		disposition = QuotaDispositionConsume
		permission = "model.resolve-uncertain.consume"
	case UncertainResolutionRelease:
		disposition = QuotaDispositionRelease
		permission = "model.resolve-uncertain.release"
	default:
		return Settlement{}, ErrInvalidRequest
	}
	if effect.State != StateUncertain || effect.Outcome != OutcomeUncertain {
		return Settlement{}, ErrInvalidTransition
	}
	authorized, err := gateway.authorizeTerminal(ctx, effect, authority)
	if err != nil {
		return Settlement{}, err
	}
	resolutionScope, err := gateway.authority.ValidateAdmission(ctx, append(OpaqueAuthority(nil), authority...), AdmissionAuthorityRequest{
		EffectID: effect.Scope.EffectID, InvocationID: effect.Scope.InvocationID,
		RequestDigest: effect.RequestDigest, Permission: permission,
	})
	if err != nil {
		return Settlement{}, err
	}
	if !sameAuthorityIdentity(resolutionScope, effect.Scope) || resolutionScope.Generations.TurnLease == 0 ||
		resolutionScope.Generations.Placement == 0 || resolutionScope.Generations.Policy == 0 {
		return Settlement{}, ErrAuthorityMismatch
	}
	commitEffect := effect
	commitEffect.Request = cloneModelRequest(effect.Request)
	commitEffect.Response = cloneResponse(effect.Response)
	resolutionPermit, err := gateway.dispatches.CommitAndClaimUncertainResolution(ctx, UncertainResolutionCommitRequest{
		CurrentScope: resolutionScope, Effect: commitEffect, TerminalDigest: authorized.terminalDigest, Decision: resolution,
	})
	if err != nil {
		return Settlement{}, err
	}
	if !resolutionPermit.Durable || resolutionPermit.Proof == (OpaqueUncertainResolutionPermit{}) ||
		!sameAuthorityIdentity(resolutionPermit.CurrentScope, resolutionScope) || resolutionPermit.CurrentScope.Generations.TurnLease == 0 ||
		resolutionPermit.CurrentScope.Generations.Placement == 0 || resolutionPermit.CurrentScope.Generations.Policy == 0 ||
		resolutionPermit.EffectID != effect.Scope.EffectID || resolutionPermit.InvocationID != effect.Scope.InvocationID ||
		resolutionPermit.RequestDigest != effect.RequestDigest || resolutionPermit.TerminalDigest != authorized.terminalDigest ||
		resolutionPermit.ReservationID != effect.QuotaPermit.ReservationID || resolutionPermit.Decision != resolution {
		return Settlement{}, ErrDispatchNotDurable
	}
	quotaRequest := QuotaSettlementRequest{
		Permit: effect.QuotaPermit, Authorization: authorized.permit, Recovery: effect.RecoveryPermit, Resolution: resolutionPermit,
		Outcome: effect.Outcome, Disposition: disposition, ProviderRequestID: effect.ProviderRequestID, Attempt: effect.Attempt,
	}
	if disposition == QuotaDispositionConsume {
		quotaRequest.Usage = Usage{InputTokens: effect.ContextTokens, OutputTokens: effect.RequestedOutputTokens}
	}
	quotaReceipt, err := gateway.quota.Settle(ctx, quotaRequest)
	if err != nil {
		return Settlement{}, err
	}
	if !gateway.validQuotaSettlementReceipt(effect, quotaRequest, quotaReceipt) {
		return Settlement{}, ErrQuotaMismatch
	}
	return gateway.settlementResult(effect, resolutionScope, quotaReceipt, false), nil
}

type terminalAuthorization struct {
	currentScope   ValidatedAuthority
	terminalDigest Digest
	permit         SettlementPermit
}

func (gateway *Gateway) authorizeTerminal(ctx context.Context, effect Effect, authority OpaqueAuthority) (terminalAuthorization, error) {
	if err := ctx.Err(); err != nil {
		return terminalAuthorization{}, err
	}
	if len(authority) == 0 || uint64(len(authority)) > gateway.bounds.MaxAuthorityBytes {
		return terminalAuthorization{}, ErrInvalidRequest
	}
	if err := gateway.validateEffect(effect); err != nil {
		return terminalAuthorization{}, err
	}
	switch effect.State {
	case StateCompleted, StateFailed, StateCancelled, StateUncertain:
	default:
		return terminalAuthorization{}, ErrSettlementNotReady
	}
	terminalHasher := sha256.New()
	writeTerminalBytes := func(value []byte) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = terminalHasher.Write(size[:])
		_, _ = terminalHasher.Write(value)
	}
	writeTerminalString := func(value string) { writeTerminalBytes([]byte(value)) }
	writeTerminalUint := func(value uint64) {
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], value)
		writeTerminalBytes(encoded[:])
	}
	writeTerminalString("circulusd.model-settlement.v2")
	for _, value := range []string{
		effect.Scope.TenantID.String(), effect.Scope.UserID.String(), effect.Scope.SessionID.String(), effect.Scope.TurnID.String(),
		effect.Scope.EffectID.String(), effect.Scope.InvocationID.String(), effect.Scope.RuntimeRevision.String(),
		effect.ProviderID, effect.ProviderRequestID, effect.QuotaPermit.ReservationID,
		string(effect.State), string(effect.Outcome), effect.FailureReason,
	} {
		writeTerminalString(value)
	}
	writeTerminalBytes(effect.RequestDigest[:])
	for _, value := range []uint64{
		effect.Scope.Generations.TurnLease, effect.Scope.Generations.Placement, effect.Scope.Generations.Policy,
		effect.Revision, uint64(effect.Attempt), uint64(effect.EventCount), effect.EventBytes, effect.StreamBytes,
	} {
		writeTerminalUint(value)
	}
	if effect.PartialOutput {
		writeTerminalUint(1)
	} else {
		writeTerminalUint(0)
	}
	if effect.Response == nil {
		writeTerminalUint(0)
	} else {
		writeTerminalUint(1)
		writeTerminalString(effect.Response.Text)
		writeTerminalString(string(effect.Response.FinishReason))
		writeTerminalUint(effect.Response.Usage.InputTokens)
		writeTerminalUint(effect.Response.Usage.OutputTokens)
		writeTerminalUint(uint64(len(effect.Response.ToolCalls)))
		for _, call := range effect.Response.ToolCalls {
			writeTerminalString(call.ID)
			writeTerminalString(call.Name)
			writeTerminalBytes(call.Arguments.encoded)
			if call.Order.Declared {
				writeTerminalUint(1)
			} else {
				writeTerminalUint(0)
			}
			writeTerminalUint(uint64(call.Order.Index))
		}
	}
	writeTerminalBytes(effect.CancellationPermit.Proof[:])
	writeTerminalBytes(effect.RecoveryPermit.Proof[:])
	writeTerminalUint(effect.CancellationPermit.EffectRevision)
	writeTerminalUint(effect.RecoveryPermit.EffectRevision)
	var terminalDigest Digest
	copy(terminalDigest[:], terminalHasher.Sum(nil))
	usage := Usage{}
	if effect.Response != nil {
		usage = effect.Response.Usage
	}
	request := SettlementAuthorityRequest{
		TenantID: effect.Scope.TenantID, UserID: effect.Scope.UserID, SessionID: effect.Scope.SessionID, TurnID: effect.Scope.TurnID,
		EffectID: effect.Scope.EffectID, InvocationID: effect.Scope.InvocationID, RuntimeRevision: effect.Scope.RuntimeRevision,
		Generations: effect.Scope.Generations, RequestDigest: effect.RequestDigest, ProviderRequestID: effect.ProviderRequestID, Attempt: effect.Attempt,
		EffectRevision: effect.Revision, State: effect.State, Outcome: effect.Outcome, Usage: usage, TerminalDigest: terminalDigest,
	}
	currentScope, err := gateway.authority.ValidateSettlement(ctx, append(OpaqueAuthority(nil), authority...), request)
	if err != nil {
		return terminalAuthorization{}, err
	}
	if !sameAuthorityIdentity(currentScope, effect.Scope) || currentScope.Generations.TurnLease == 0 ||
		currentScope.Generations.Placement == 0 || currentScope.Generations.Policy == 0 {
		return terminalAuthorization{}, ErrAuthorityMismatch
	}
	commitEffect := effect
	commitEffect.Request = cloneModelRequest(effect.Request)
	commitEffect.Response = cloneResponse(effect.Response)
	settlementPermit, err := gateway.dispatches.CommitAndClaimSettlement(ctx, SettlementCommitRequest{
		ExpectedRevision: effect.Revision - 1, CurrentScope: currentScope,
		Effect: commitEffect, TerminalDigest: terminalDigest,
	})
	if err != nil {
		return terminalAuthorization{}, err
	}
	if !settlementPermit.Durable || settlementPermit.Proof == (OpaqueSettlementPermit{}) ||
		!sameAuthorityIdentity(settlementPermit.CurrentScope, currentScope) || settlementPermit.CurrentScope.Generations.TurnLease == 0 ||
		settlementPermit.CurrentScope.Generations.Placement == 0 || settlementPermit.CurrentScope.Generations.Policy == 0 ||
		settlementPermit.EffectID != effect.Scope.EffectID || settlementPermit.InvocationID != effect.Scope.InvocationID ||
		settlementPermit.RequestDigest != effect.RequestDigest || settlementPermit.EffectRevision != effect.Revision ||
		settlementPermit.TerminalDigest != terminalDigest || settlementPermit.ReservationID != effect.QuotaPermit.ReservationID {
		return terminalAuthorization{}, ErrDispatchNotDurable
	}
	return terminalAuthorization{currentScope: currentScope, terminalDigest: terminalDigest, permit: settlementPermit}, nil
}

func (gateway *Gateway) validQuotaSettlementReceipt(effect Effect, request QuotaSettlementRequest, receipt QuotaSettlementReceipt) bool {
	return receipt.Durable && receipt.ReservationID == effect.QuotaPermit.ReservationID &&
		receipt.EffectID == effect.Scope.EffectID && receipt.InvocationID == effect.Scope.InvocationID &&
		receipt.RequestDigest == effect.RequestDigest && receipt.Outcome == request.Outcome &&
		receipt.Disposition == request.Disposition && receipt.Usage == request.Usage &&
		receipt.ProviderRequestID == request.ProviderRequestID && receipt.Attempt == request.Attempt &&
		receipt.Authorization == request.Authorization && receipt.Recovery == request.Recovery && receipt.Resolution == request.Resolution
}

func (gateway *Gateway) settlementResult(effect Effect, currentScope ValidatedAuthority, quotaReceipt QuotaSettlementReceipt, needsConfirmation bool) Settlement {
	return Settlement{
		Scope: currentScope, RequestDigest: effect.RequestDigest, Outcome: effect.Outcome,
		ProviderRequestID: effect.ProviderRequestID, Attempt: effect.Attempt,
		PartialOutput:     effect.PartialOutput && effect.Outcome != OutcomeCompleted,
		NeedsConfirmation: needsConfirmation,
		FailureReason:     effect.FailureReason, Response: cloneResponse(effect.Response), QuotaReceipt: quotaReceipt,
	}
}

func sameAuthorityIdentity(left ValidatedAuthority, right ValidatedAuthority) bool {
	return left.TenantID == right.TenantID && left.UserID == right.UserID && left.SessionID == right.SessionID &&
		left.TurnID == right.TurnID && left.EffectID == right.EffectID && left.InvocationID == right.InvocationID &&
		left.RuntimeRevision == right.RuntimeRevision
}

func (gateway *Gateway) validateEffect(effect Effect) error {
	if effect.Scope.TenantID.Kind() != identity.Tenant || effect.Scope.UserID.Kind() != identity.Subject ||
		effect.Scope.SessionID.Kind() != identity.Session || effect.Scope.TurnID.Kind() != identity.Turn ||
		effect.Scope.EffectID.Kind() != identity.Effect || effect.Scope.InvocationID.Kind() != identity.Invocation ||
		effect.Scope.RuntimeRevision.Kind() != identity.RuntimeRevision || effect.Scope.Generations.TurnLease == 0 ||
		effect.Scope.Generations.Placement == 0 || effect.Scope.Generations.Policy == 0 || effect.RequestDigest == (Digest{}) ||
		effect.Revision == 0 || effect.Revision != uint64(effect.EventCount)+1 || effect.EventCount > gateway.bounds.MaxEvents || effect.EventBytes > uint64(effect.EventCount)*gateway.bounds.MaxEventBytes ||
		effect.StreamBytes > gateway.bounds.MaxStreamBytes || effect.Attempt > effect.MaxPreDispatchRetries+1 {
		return ErrInvalidRequest
	}
	if err := gateway.validateModelRequest(effect.Request); err != nil {
		return fmt.Errorf("%w: invalid restored model request: %v", ErrInvalidRequest, err)
	}
	normalizedReasoning, err := normalizeReasoningOptions(effect.Request.Reasoning)
	if err != nil || normalizedReasoning != effect.Request.Reasoning {
		return fmt.Errorf("%w: restored reasoning options are not normalized", ErrInvalidRequest)
	}
	restoredDigest, err := ModelRequestDigest(effect.Request)
	if err != nil || restoredDigest != effect.RequestDigest {
		return fmt.Errorf("%w: restored model request digest mismatch", ErrInvalidRequest)
	}
	grant, found := gateway.grants[grantKey{tenant: effect.Scope.TenantID, user: effect.Scope.UserID, model: effect.Request.Model}]
	if !found || grant.ProviderID != effect.ProviderID || grant.MaxContextTokens != effect.MaxContextTokens ||
		grant.MaxTotalTokens != effect.MaxTotalTokens || grant.MaxPreDispatchRetries != effect.MaxPreDispatchRetries ||
		effect.ContextTokens > grant.MaxContextTokens || effect.RequestedOutputTokens == 0 ||
		effect.RequestedOutputTokens > grant.MaxOutputTokens || effect.ContextTokens > grant.MaxTotalTokens ||
		effect.RequestedOutputTokens > grant.MaxTotalTokens-effect.ContextTokens || effect.Request.MaxOutputTokens != effect.RequestedOutputTokens {
		return ErrInvalidRequest
	}
	if !identifierPattern.MatchString(effect.ProviderID) || uint64(len(effect.ProviderID)) > gateway.bounds.MaxProviderIDBytes ||
		!effect.QuotaPermit.Durable || effect.QuotaPermit.ReservationID == "" || len(effect.QuotaPermit.ReservationID) > 256 || !utf8.ValidString(effect.QuotaPermit.ReservationID) || strings.IndexFunc(effect.QuotaPermit.ReservationID, unicode.IsControl) >= 0 ||
		effect.QuotaPermit.TenantID != effect.Scope.TenantID ||
		effect.QuotaPermit.UserID != effect.Scope.UserID || effect.QuotaPermit.EffectID != effect.Scope.EffectID ||
		effect.QuotaPermit.InvocationID != effect.Scope.InvocationID || effect.QuotaPermit.SessionID != effect.Scope.SessionID ||
		effect.QuotaPermit.TurnID != effect.Scope.TurnID || effect.QuotaPermit.RuntimeRevision != effect.Scope.RuntimeRevision ||
		effect.QuotaPermit.Generations != effect.Scope.Generations || effect.QuotaPermit.RequestDigest != effect.RequestDigest ||
		effect.QuotaPermit.ContextTokens != effect.ContextTokens || effect.QuotaPermit.OutputTokens != effect.RequestedOutputTokens {
		return ErrQuotaMismatch
	}
	if effect.ProviderRequestID != "" && (!utf8.ValidString(effect.ProviderRequestID) || strings.IndexFunc(effect.ProviderRequestID, unicode.IsControl) >= 0 ||
		uint64(len(effect.ProviderRequestID)) > gateway.bounds.MaxProviderRequestIDBytes || uint64(len(effect.ProviderRequestID)) > gateway.bounds.MaxEventBytes) {
		return ErrInvalidRequest
	}
	if effect.FailureReason != "" && (!utf8.ValidString(effect.FailureReason) || strings.IndexFunc(effect.FailureReason, unicode.IsControl) >= 0 || uint64(len(effect.FailureReason)) > gateway.bounds.MaxReasonBytes) {
		return ErrInvalidRequest
	}
	if effect.FailureReason != "" {
		normalized := false
		for _, class := range []FailureClass{FailurePreDispatch, FailureProviderRejected, FailureTransportUnknown, FailureAfterPartial} {
			if effect.FailureReason == gateway.normalizedFailureReason(class) {
				normalized = true
				break
			}
		}
		if !normalized {
			return ErrInvalidRequest
		}
	}
	if effect.CancellationPermit != (CancellationPermit{}) && !validCancellationPermit(effect, effect.CancellationPermit) {
		return ErrInvalidRequest
	}
	if effect.RecoveryPermit != (ResumePermit{}) && !validResumePermit(effect, effect.RecoveryPermit) {
		return ErrInvalidRequest
	}
	if (effect.PartialOutput && effect.StreamBytes == 0) || (!effect.PartialOutput && effect.StreamBytes != 0) {
		return ErrInvalidRequest
	}
	accountedEventBytes := effect.StreamBytes + uint64(len(effect.ProviderRequestID)) + uint64(len(effect.FailureReason))
	if effect.Response != nil {
		if effect.Response.Usage.InputTokens > effect.ContextTokens {
			return ErrQuotaMismatch
		}
		normalizedCalls, toolCallBytes, err := normalizeToolCalls(effect.Response.ToolCalls)
		if err != nil || !equalToolCalls(normalizedCalls, effect.Response.ToolCalls) {
			return ErrInvalidRequest
		}
		if !utf8.ValidString(effect.Response.Text) || uint64(len(effect.Response.Text)) > gateway.bounds.MaxResponseBytes ||
			!validFinishReason(effect.Response.FinishReason) || uint64(len(effect.Response.FinishReason)) > gateway.bounds.MaxReasonBytes ||
			effect.Response.Usage != (Usage{InputTokens: effect.ContextTokens, OutputTokens: effect.RequestedOutputTokens}) ||
			effect.Response.Usage.InputTokens > effect.MaxContextTokens || effect.Response.Usage.OutputTokens > effect.RequestedOutputTokens ||
			effect.Response.Usage.InputTokens > effect.MaxTotalTokens || effect.Response.Usage.OutputTokens > effect.MaxTotalTokens-effect.Response.Usage.InputTokens {
			return ErrInvalidRequest
		}
		responseBytes := uint64(len(effect.Response.Text)) + uint64(len(effect.Response.FinishReason))
		if toolCallBytes > math.MaxUint64-responseBytes || responseBytes+toolCallBytes > gateway.bounds.MaxResponseBytes ||
			responseBytes+toolCallBytes > math.MaxUint64-accountedEventBytes {
			return ErrInvalidRequest
		}
		accountedEventBytes += responseBytes + toolCallBytes
	}
	if accountedEventBytes > effect.EventBytes {
		return ErrInvalidRequest
	}
	if effect.EventBytes > math.MaxUint64-gateway.bounds.MaxEventBytes {
		return ErrInvalidRequest
	}
	switch effect.State {
	case StateAdmitted:
		if effect.Outcome != "" || effect.Attempt != 0 || effect.EventCount != 0 || effect.ProviderRequestID != "" || effect.PartialOutput || effect.FailureReason != "" || effect.Response != nil ||
			effect.CancellationPermit != (CancellationPermit{}) || effect.RecoveryPermit != (ResumePermit{}) {
			return ErrInvalidRequest
		}
	case StateDispatching:
		if effect.Outcome != "" || effect.Attempt == 0 || effect.ProviderRequestID != "" || effect.PartialOutput || effect.FailureReason != "" || effect.Response != nil ||
			effect.CancellationPermit != (CancellationPermit{}) || effect.RecoveryPermit != (ResumePermit{}) {
			return ErrInvalidRequest
		}
	case StateRetryPending:
		if effect.Outcome != "" || effect.Attempt == 0 || effect.ProviderRequestID != "" || effect.PartialOutput || effect.FailureReason == "" || effect.Response != nil ||
			effect.CancellationPermit != (CancellationPermit{}) || effect.RecoveryPermit != (ResumePermit{}) {
			return ErrInvalidRequest
		}
	case StateDispatched:
		if effect.Outcome != "" || effect.Attempt == 0 || effect.ProviderRequestID == "" || effect.PartialOutput || effect.FailureReason != "" || effect.Response != nil ||
			effect.CancellationPermit != (CancellationPermit{}) || effect.RecoveryPermit != (ResumePermit{}) {
			return ErrInvalidRequest
		}
	case StateStreaming:
		if effect.Outcome != "" || effect.Attempt == 0 || effect.ProviderRequestID == "" || !effect.PartialOutput || effect.FailureReason != "" || effect.Response != nil ||
			effect.CancellationPermit != (CancellationPermit{}) {
			return ErrInvalidRequest
		}
	case StateCancellationPending:
		if effect.Outcome != "" || effect.Attempt == 0 || effect.Response != nil || (effect.PartialOutput && effect.ProviderRequestID == "") ||
			effect.CancellationPermit != (CancellationPermit{}) || effect.RecoveryPermit != (ResumePermit{}) {
			return ErrInvalidRequest
		}
	case StateCompleted:
		if effect.Outcome != OutcomeCompleted || effect.Attempt == 0 || effect.ProviderRequestID == "" || effect.FailureReason != "" || effect.Response == nil ||
			effect.CancellationPermit != (CancellationPermit{}) {
			return ErrInvalidRequest
		}
	case StateFailed:
		if effect.Outcome != OutcomeFailed || effect.Attempt == 0 || effect.PartialOutput || effect.FailureReason == "" || effect.Response != nil ||
			effect.CancellationPermit != (CancellationPermit{}) {
			return ErrInvalidRequest
		}
	case StateCancelled:
		if effect.Outcome != OutcomeCancelled || effect.ProviderRequestID != "" || effect.PartialOutput || effect.FailureReason != "" || effect.Response != nil ||
			effect.RecoveryPermit != (ResumePermit{}) ||
			(effect.CancellationPermit != (CancellationPermit{}) && !effect.CancellationPermit.DispatchPrevented) {
			return ErrInvalidRequest
		}
	case StateUncertain:
		if effect.Outcome != OutcomeUncertain || effect.Attempt == 0 || effect.Response != nil || (effect.PartialOutput && effect.ProviderRequestID == "") ||
			(effect.CancellationPermit != (CancellationPermit{}) && effect.CancellationPermit.DispatchPrevented) ||
			(effect.CancellationPermit != (CancellationPermit{}) && effect.RecoveryPermit != (ResumePermit{})) {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	if effect.Outcome == "" && uint64(effect.EventCount)+uint64(minimumTerminalEvents(effect)) > uint64(gateway.bounds.MaxEvents) {
		return ErrInvalidRequest
	}
	return nil
}

func (gateway *Gateway) validateModelRequest(request ModelRequest) error {
	if !identifierPattern.MatchString(request.Model) || uint64(len(request.Model)) > gateway.bounds.MaxModelBytes ||
		request.MaxOutputTokens == 0 || len(request.Messages) == 0 || uint64(len(request.Messages)) > uint64(gateway.bounds.MaxMessages) {
		return ErrInvalidRequest
	}
	if _, err := normalizeReasoningOptions(request.Reasoning); err != nil {
		return err
	}
	var inputBytes uint64
	for _, message := range request.Messages {
		switch message.Role {
		case RoleSystem, RoleUser, RoleAssistant, RoleTool:
		default:
			return ErrInvalidRequest
		}
		if message.Content == "" || !utf8.ValidString(message.Content) || norm.NFC.String(message.Content) != message.Content || uint64(len(message.Content)) > gateway.bounds.MaxMessageBytes {
			return ErrInputLimit
		}
		messageBytes := uint64(len(message.Content))
		if messageBytes > gateway.bounds.MaxInputBytes-inputBytes {
			return ErrInputLimit
		}
		inputBytes += messageBytes
	}
	return nil
}

// ModelRequestDigest is the canonical digest that the Session effect must
// prepare before calling Admit. Recomputing it at the gateway prevents a
// caller from changing provider-visible request bytes under a durable digest.
func ModelRequestDigest(request ModelRequest) (Digest, error) {
	if !identifierPattern.MatchString(request.Model) || len(request.Model) > hardMaxIdentifierBytes || request.MaxOutputTokens == 0 ||
		len(request.Messages) == 0 || len(request.Messages) > hardMaxMessages {
		return Digest{}, ErrInvalidRequest
	}
	reasoning, err := normalizeReasoningOptions(request.Reasoning)
	if err != nil {
		return Digest{}, err
	}
	messages := make(canonical.Array, len(request.Messages))
	var inputBytes uint64
	for index, message := range request.Messages {
		switch message.Role {
		case RoleSystem, RoleUser, RoleAssistant, RoleTool:
		default:
			return Digest{}, ErrInvalidRequest
		}
		if message.Content == "" || !utf8.ValidString(message.Content) || norm.NFC.String(message.Content) != message.Content || len(message.Content) > hardMaxMessageBytes {
			return Digest{}, ErrInvalidRequest
		}
		messageBytes := uint64(len(message.Content))
		if messageBytes > hardMaxInputBytes-inputBytes {
			return Digest{}, ErrInputLimit
		}
		inputBytes += messageBytes
		messages[index] = canonical.Array{string(message.Role), message.Content}
	}
	value, err := canonical.StructuredDigest("model.request", 2, canonical.Map{
		"model": request.Model, "messages": messages, "maxOutputTokens": request.MaxOutputTokens,
		"reasoning": canonical.Map{"effort": string(reasoning.Effort)},
	})
	if err != nil {
		return Digest{}, fmt.Errorf("%w: canonical model request: %v", ErrInvalidRequest, err)
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	if err != nil || len(decoded) != len(Digest{}) {
		return Digest{}, fmt.Errorf("%w: canonical model request digest", ErrInvalidRequest)
	}
	var digest Digest
	copy(digest[:], decoded)
	return digest, nil
}

func normalizeReasoningOptions(options ReasoningOptions) (ReasoningOptions, error) {
	if options.Effort == "" {
		options.Effort = ReasoningEffortDefault
	}
	switch options.Effort {
	case ReasoningEffortDefault, ReasoningEffortDisabled, ReasoningEffortLow, ReasoningEffortMedium, ReasoningEffortHigh:
		return options, nil
	default:
		return ReasoningOptions{}, ErrInvalidRequest
	}
}

func validFinishReason(reason FinishReason) bool {
	switch reason {
	case FinishReasonStop, FinishReasonLength, FinishReasonToolCalls, FinishReasonContentFilter, FinishReasonCancelled, FinishReasonOther:
		return true
	default:
		return false
	}
}

func (gateway *Gateway) normalizedFailureReason(class FailureClass) string {
	reason := "provider request failed"
	switch class {
	case FailurePreDispatch:
		reason = "provider dispatch definitely not sent"
	case FailureProviderRejected:
		reason = "provider request rejected"
	case FailureTransportUnknown:
		reason = "provider dispatch outcome unknown"
	case FailureAfterPartial:
		reason = "provider stream interrupted after partial output"
	}
	limit := min(gateway.bounds.MaxReasonBytes, gateway.bounds.MaxEventBytes)
	if uint64(len(reason)) > limit {
		return strings.Repeat("?", int(limit))
	}
	return reason
}

func minimumTerminalEvents(effect Effect) uint32 {
	if effect.DurableRequestRetrieval {
		switch effect.State {
		case StateDispatching:
			// Provider acceptance may still have to be persisted before a
			// cancellation can be classified and an uncertain request recovered.
			return 4
		case StateDispatched, StateStreaming:
			return 3
		case StateCancellationPending:
			return 2
		}
	}
	switch effect.State {
	case StateDispatching:
		return 3
	case StateDispatched, StateStreaming:
		return 2
	case StateAdmitted, StateRetryPending, StateCancellationPending:
		return 1
	default:
		return 0
	}
}

func cloneModelRequest(request ModelRequest) ModelRequest {
	request.Messages = append([]Message(nil), request.Messages...)
	return request
}

func cloneResponse(response *ModelResponse) *ModelResponse {
	if response == nil {
		return nil
	}
	copy := *response
	if response.ToolCalls != nil {
		copy.ToolCalls = make([]ToolCall, len(response.ToolCalls))
		for index, call := range response.ToolCalls {
			copy.ToolCalls[index] = call
			copy.ToolCalls[index].Arguments.encoded = append([]byte(nil), call.Arguments.encoded...)
		}
	}
	return &copy
}
