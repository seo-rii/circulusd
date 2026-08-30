package authority

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const authorityMACDomain = "circulusd.turn-authority.v2\x00"

type Validator struct {
	reader SnapshotReader
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

// NewValidator creates a stateless verifier. It retains no session, turn, or
// effect state; SnapshotReader remains the sole authority for those values.
func NewValidator(config Config) (*Validator, error) {
	if config.SnapshotReader == nil {
		return nil, fmt.Errorf("%w: snapshot reader is required", ErrInvalidConfig)
	}
	if len(config.HMACSecret) < 32 {
		return nil, fmt.Errorf("%w: HMAC secret must contain at least 32 bytes", ErrInvalidConfig)
	}
	if config.AuthorityTTL <= 0 {
		return nil, fmt.Errorf("%w: authority TTL must be positive", ErrInvalidConfig)
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Validator{
		reader: config.SnapshotReader,
		secret: append([]byte(nil), config.HMACSecret...),
		ttl:    config.AuthorityTTL,
		now:    now,
	}, nil
}

// Issue snapshots current Session DO authority into an opaque, service-bound
// handle. Requested scope and permissions are comparison targets only.
func (validator *Validator) Issue(
	ctx context.Context,
	binding ServiceBinding,
	request IssueRequest,
) (TurnAuthority, error) {
	if err := ctx.Err(); err != nil {
		return TurnAuthority{}, err
	}
	if !isServiceBinding(binding) || validateScope(request.Scope) != nil || len(request.Permissions) == 0 {
		return TurnAuthority{}, ErrInvalidRequest
	}
	permissions := append([]Permission(nil), request.Permissions...)
	seen := make(map[Permission]struct{}, len(permissions))
	for _, permission := range permissions {
		if !validPermission(permission) {
			return TurnAuthority{}, fmt.Errorf("%w: invalid permission", ErrInvalidRequest)
		}
		if _, duplicate := seen[permission]; duplicate {
			return TurnAuthority{}, fmt.Errorf("%w: duplicate permission", ErrInvalidRequest)
		}
		seen[permission] = struct{}{}
	}
	sort.Slice(permissions, func(left, right int) bool { return permissions[left] < permissions[right] })

	snapshot, err := validator.readSnapshot(ctx, request.Scope.SessionID)
	if err != nil {
		return TurnAuthority{}, err
	}
	now := validator.currentTime()
	if err := validateSnapshot(snapshot, now, true); err != nil {
		return TurnAuthority{}, err
	}
	if snapshot.Scope != request.Scope {
		return TurnAuthority{}, ErrScopeMismatch
	}
	for _, permission := range permissions {
		if !hasPermission(snapshot.EffectivePermissions, permission) {
			return TurnAuthority{}, ErrPermissionDenied
		}
	}

	expiresAt := now.Add(validator.ttl)
	if snapshot.LeaseExpiresAt.Before(expiresAt) {
		expiresAt = snapshot.LeaseExpiresAt
	}
	claims := authorityClaims{
		purpose:                 purposeAdmission,
		binding:                 binding,
		scope:                   snapshot.Scope,
		permissions:             permissions,
		turnLeaseGeneration:     snapshot.TurnLeaseGeneration,
		placementGeneration:     snapshot.PlacementGeneration,
		authorizationGeneration: snapshot.AuthorizationGeneration,
		policySnapshotDigest:    snapshot.PolicySnapshotDigest,
		emergencyOverlayDigest:  snapshot.EmergencyOverlayDigest,
		issuedAtUnixNano:        now.UnixNano(),
		expiresAtUnixNano:       expiresAt.UnixNano(),
	}
	return TurnAuthority{signed: validator.signClaims(claims)}, nil
}

// ValidateAdmission authorizes one new broker call against a fresh snapshot.
func (validator *Validator) ValidateAdmission(
	ctx context.Context,
	authority TurnAuthority,
	binding ServiceBinding,
	request AdmissionRequest,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !isServiceBinding(binding) || validateScope(request.Scope) != nil || !validPermission(request.Permission) {
		return ErrInvalidRequest
	}
	claims, err := validator.verifyClaims(authority.signed)
	if err != nil || claims.purpose != purposeAdmission {
		return ErrInvalidAuthority
	}
	if claims.binding != binding {
		return ErrServiceBindingMismatch
	}
	snapshot, err := validator.readSnapshot(ctx, claims.scope.SessionID)
	if err != nil {
		return err
	}
	now := validator.currentTime()
	if now.UnixNano() < claims.issuedAtUnixNano {
		return ErrInvalidAuthority
	}
	if err := validateSnapshot(snapshot, now, true); err != nil {
		return err
	}
	if err := validateCurrent(claims, snapshot); err != nil {
		return err
	}
	if now.UnixNano() >= claims.expiresAtUnixNano {
		return ErrAuthorityExpired
	}
	if claims.scope != request.Scope {
		return ErrScopeMismatch
	}
	if !hasPermission(claims.permissions, request.Permission) {
		return ErrPermissionDenied
	}
	if !hasPermission(snapshot.EffectivePermissions, request.Permission) {
		return ErrPermissionDenied
	}
	return nil
}

// Renew issues a new TTL for exactly the same active turn, generations,
// policies, service binding, scope, and permission set.
func (validator *Validator) Renew(
	ctx context.Context,
	authority TurnAuthority,
	binding ServiceBinding,
) (TurnAuthority, error) {
	if err := ctx.Err(); err != nil {
		return TurnAuthority{}, err
	}
	if !isServiceBinding(binding) {
		return TurnAuthority{}, ErrInvalidRequest
	}
	claims, err := validator.verifyClaims(authority.signed)
	if err != nil || claims.purpose != purposeAdmission {
		return TurnAuthority{}, ErrInvalidAuthority
	}
	if claims.binding != binding {
		return TurnAuthority{}, ErrServiceBindingMismatch
	}
	snapshot, err := validator.readSnapshot(ctx, claims.scope.SessionID)
	if err != nil {
		return TurnAuthority{}, err
	}
	now := validator.currentTime()
	if now.UnixNano() < claims.issuedAtUnixNano {
		return TurnAuthority{}, ErrInvalidAuthority
	}
	if err := validateSnapshot(snapshot, now, true); err != nil {
		return TurnAuthority{}, err
	}
	if err := validateCurrent(claims, snapshot); err != nil {
		return TurnAuthority{}, err
	}
	if now.UnixNano() >= claims.expiresAtUnixNano {
		return TurnAuthority{}, ErrAuthorityExpired
	}
	for _, permission := range claims.permissions {
		if !hasPermission(snapshot.EffectivePermissions, permission) {
			return TurnAuthority{}, ErrPermissionDenied
		}
	}

	claims.issuedAtUnixNano = now.UnixNano()
	expiresAt := now.Add(validator.ttl)
	if snapshot.LeaseExpiresAt.Before(expiresAt) {
		expiresAt = snapshot.LeaseExpiresAt
	}
	claims.expiresAtUnixNano = expiresAt.UnixNano()
	return TurnAuthority{signed: validator.signClaims(claims)}, nil
}

// IssueSettlementAuthority is for trusted ADR-008 reconciliation wiring. It
// returns a distinct capability that can settle one current effect and cannot
// be passed to admission or renewal APIs.
func (validator *Validator) IssueSettlementAuthority(
	ctx context.Context,
	binding ServiceBinding,
	request SettlementRequest,
) (SettlementAuthority, error) {
	if err := ctx.Err(); err != nil {
		return SettlementAuthority{}, err
	}
	if !isServiceBinding(binding) || validateSettlementRequest(request) != nil {
		return SettlementAuthority{}, ErrInvalidRequest
	}
	snapshot, err := validator.readSnapshot(ctx, request.Scope.SessionID)
	if err != nil {
		return SettlementAuthority{}, err
	}
	now := validator.currentTime()
	if err := validateSnapshot(snapshot, now, false); err != nil {
		return SettlementAuthority{}, err
	}
	if snapshot.Scope != request.Scope {
		return SettlementAuthority{}, ErrScopeMismatch
	}
	if !hasPermission(snapshot.EffectivePermissions, request.Permission) {
		return SettlementAuthority{}, ErrPermissionDenied
	}
	if err := validateEffect(snapshot, binding, request); err != nil {
		return SettlementAuthority{}, err
	}
	claims := authorityClaims{
		purpose:                 purposeSettlement,
		binding:                 binding,
		scope:                   snapshot.Scope,
		permissions:             []Permission{request.Permission},
		turnLeaseGeneration:     snapshot.TurnLeaseGeneration,
		placementGeneration:     snapshot.PlacementGeneration,
		authorizationGeneration: snapshot.AuthorizationGeneration,
		policySnapshotDigest:    snapshot.PolicySnapshotDigest,
		emergencyOverlayDigest:  snapshot.EmergencyOverlayDigest,
		issuedAtUnixNano:        now.UnixNano(),
		effectID:                snapshot.ActiveEffect.EffectID,
		invocationID:            snapshot.ActiveEffect.InvocationID,
		requestDigest:           snapshot.ActiveEffect.RequestDigest,
		effectService:           snapshot.ActiveEffect.Service,
		effectOperation:         snapshot.ActiveEffect.Operation,
		dispatchAttempt:         snapshot.ActiveEffect.DispatchAttempt,
	}
	return SettlementAuthority{signed: validator.signClaims(claims)}, nil
}

// ValidateSettlement ignores admission TTL and lease wall-clock expiry because
// the effect is already dispatched. Current generations, policies, scope, and
// exact durable effect/invocation identity remain mandatory.
func (validator *Validator) ValidateSettlement(
	ctx context.Context,
	credential SettlementCredential,
	binding ServiceBinding,
	request SettlementRequest,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !isServiceBinding(binding) || validateSettlementRequest(request) != nil {
		return ErrInvalidRequest
	}
	var signed signedAuthority
	switch credential := credential.(type) {
	case SettlementAuthority:
		signed = credential.signed
	default:
		return ErrInvalidAuthority
	}
	claims, err := validator.verifyClaims(signed)
	if err != nil || claims.purpose != purposeSettlement {
		return ErrInvalidAuthority
	}
	if claims.binding != binding {
		return ErrServiceBindingMismatch
	}
	if claims.scope != request.Scope {
		return ErrScopeMismatch
	}
	if !hasPermission(claims.permissions, request.Permission) {
		return ErrPermissionDenied
	}
	if err := validateEffectBinding(binding, claims.effectService); err != nil {
		return err
	}
	if claims.effectID != request.EffectID ||
		claims.invocationID != request.InvocationID ||
		claims.requestDigest != request.RequestDigest ||
		claims.effectService != request.Service ||
		claims.effectOperation != request.Operation ||
		claims.dispatchAttempt != request.DispatchAttempt {
		return ErrEffectMismatch
	}

	snapshot, err := validator.readSnapshot(ctx, claims.scope.SessionID)
	if err != nil {
		return err
	}
	now := validator.currentTime()
	if now.UnixNano() < claims.issuedAtUnixNano {
		return ErrInvalidAuthority
	}
	if err := validateSnapshot(snapshot, now, false); err != nil {
		return err
	}
	if err := validateCurrent(claims, snapshot); err != nil {
		return err
	}
	if !hasPermission(snapshot.EffectivePermissions, request.Permission) {
		return ErrPermissionDenied
	}
	return validateEffect(snapshot, binding, request)
}

func (validator *Validator) currentTime() time.Time {
	return validator.now().Round(0).UTC()
}

func (validator *Validator) readSnapshot(ctx context.Context, sessionID string) (Snapshot, error) {
	snapshot, err := validator.reader.ReadSnapshot(ctx, sessionID)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Snapshot{}, ctxErr
		}
		return Snapshot{}, fmt.Errorf("%w: %v", ErrSnapshotUnavailable, err)
	}
	return snapshot, nil
}

func (validator *Validator) signClaims(claims authorityClaims) signedAuthority {
	return signedAuthority{claims: claims, mac: validator.calculateMAC(claims)}
}

func (validator *Validator) verifyClaims(signed signedAuthority) (authorityClaims, error) {
	want := validator.calculateMAC(signed.claims)
	if !hmac.Equal(signed.mac[:], want[:]) {
		return authorityClaims{}, ErrInvalidAuthority
	}
	return signed.claims, nil
}

func (validator *Validator) calculateMAC(claims authorityClaims) [sha256.Size]byte {
	mac := hmac.New(sha256.New, validator.secret)
	_, _ = mac.Write([]byte(authorityMACDomain))
	writeString := func(value string) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = mac.Write(length[:])
		_, _ = mac.Write([]byte(value))
	}
	_, _ = mac.Write([]byte{byte(claims.purpose)})
	writeString(string(claims.binding))
	writeString(claims.scope.TenantID)
	writeString(claims.scope.UserID)
	writeString(claims.scope.SessionID)
	writeString(claims.scope.TurnID)
	writeString(claims.scope.RuntimeRevision)
	writeString(claims.scope.WorkspaceID)
	var integer [8]byte
	for _, value := range []uint64{
		claims.turnLeaseGeneration,
		claims.placementGeneration,
		claims.authorizationGeneration,
	} {
		binary.BigEndian.PutUint64(integer[:], value)
		_, _ = mac.Write(integer[:])
	}
	writeString(claims.policySnapshotDigest)
	writeString(claims.emergencyOverlayDigest)
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(claims.permissions)))
	_, _ = mac.Write(count[:])
	for _, permission := range claims.permissions {
		writeString(string(permission))
	}
	binary.BigEndian.PutUint64(integer[:], uint64(claims.issuedAtUnixNano))
	_, _ = mac.Write(integer[:])
	binary.BigEndian.PutUint64(integer[:], uint64(claims.expiresAtUnixNano))
	_, _ = mac.Write(integer[:])
	writeString(claims.effectID)
	writeString(claims.invocationID)
	writeString(claims.requestDigest)
	writeString(string(claims.effectService))
	writeString(claims.effectOperation)
	binary.BigEndian.PutUint64(integer[:], claims.dispatchAttempt)
	_, _ = mac.Write(integer[:])
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func validateSnapshot(snapshot Snapshot, now time.Time, admission bool) error {
	if validateScope(snapshot.Scope) != nil ||
		snapshot.TurnLeaseGeneration == 0 ||
		snapshot.PlacementGeneration == 0 ||
		snapshot.AuthorizationGeneration == 0 {
		return ErrInvalidSnapshot
	}
	if !validDigest(snapshot.PolicySnapshotDigest) || !validDigest(snapshot.EmergencyOverlayDigest) {
		return ErrInvalidSnapshot
	}
	seen := make(map[Permission]struct{}, len(snapshot.EffectivePermissions))
	for _, permission := range snapshot.EffectivePermissions {
		if !validPermission(permission) {
			return ErrInvalidSnapshot
		}
		if _, duplicate := seen[permission]; duplicate {
			return ErrInvalidSnapshot
		}
		seen[permission] = struct{}{}
	}
	if snapshot.SessionStatus != SessionActive {
		return ErrInactiveSession
	}
	if admission {
		if snapshot.TurnStatus != TurnActive {
			return ErrInactiveTurn
		}
		if !snapshot.LeaseActive || snapshot.LeaseExpiresAt.IsZero() || !now.Before(snapshot.LeaseExpiresAt) {
			return ErrLeaseInvalid
		}
		return nil
	}
	if snapshot.TurnStatus != TurnActive && snapshot.TurnStatus != TurnSettling && snapshot.TurnStatus != TurnAborting {
		return ErrInactiveTurn
	}
	return nil
}

func validateCurrent(claims authorityClaims, snapshot Snapshot) error {
	if claims.scope.TenantID != snapshot.Scope.TenantID ||
		claims.scope.UserID != snapshot.Scope.UserID ||
		claims.scope.SessionID != snapshot.Scope.SessionID ||
		claims.scope.TurnID != snapshot.Scope.TurnID ||
		claims.scope.WorkspaceID != snapshot.Scope.WorkspaceID {
		return ErrScopeMismatch
	}
	if claims.scope.RuntimeRevision != snapshot.Scope.RuntimeRevision {
		return ErrRuntimeChanged
	}
	if claims.turnLeaseGeneration != snapshot.TurnLeaseGeneration {
		return ErrStaleTurnLease
	}
	if claims.placementGeneration != snapshot.PlacementGeneration {
		return ErrStalePlacement
	}
	if claims.authorizationGeneration != snapshot.AuthorizationGeneration {
		return ErrStaleAuthorization
	}
	if claims.policySnapshotDigest != snapshot.PolicySnapshotDigest {
		return ErrPolicySnapshotChanged
	}
	if claims.emergencyOverlayDigest != snapshot.EmergencyOverlayDigest {
		return ErrEmergencyOverlayChanged
	}
	return nil
}

func validateScope(scope Scope) error {
	for _, value := range []string{
		scope.TenantID,
		scope.UserID,
		scope.SessionID,
		scope.TurnID,
		scope.RuntimeRevision,
	} {
		if !validIdentifier(value, false) {
			return ErrInvalidRequest
		}
	}
	if !validIdentifier(scope.WorkspaceID, true) {
		return ErrInvalidRequest
	}
	return nil
}

func validateSettlementRequest(request SettlementRequest) error {
	if validateScope(request.Scope) != nil ||
		!validPermission(request.Permission) ||
		!validIdentifier(request.EffectID, false) ||
		!validIdentifier(request.InvocationID, false) ||
		!validDigest(request.RequestDigest) ||
		!validEffectService(request.Service) ||
		!validProtocolText(request.Operation, false) ||
		request.DispatchAttempt == 0 {
		return ErrInvalidRequest
	}
	return nil
}

func validateEffect(
	snapshot Snapshot,
	binding ServiceBinding,
	request SettlementRequest,
) error {
	if snapshot.ActiveEffect == nil {
		return ErrEffectMismatch
	}
	effect := snapshot.ActiveEffect
	if !validIdentifier(effect.EffectID, false) ||
		!validIdentifier(effect.InvocationID, false) ||
		!validDigest(effect.RequestDigest) ||
		!validEffectService(effect.Service) ||
		!validProtocolText(effect.Operation, false) ||
		effect.DispatchAttempt == 0 {
		return ErrInvalidSnapshot
	}
	if err := validateEffectBinding(binding, effect.Service); err != nil {
		return err
	}
	if effect.EffectID != request.EffectID ||
		effect.InvocationID != request.InvocationID ||
		effect.RequestDigest != request.RequestDigest ||
		effect.Service != request.Service ||
		effect.Operation != request.Operation ||
		effect.DispatchAttempt != request.DispatchAttempt {
		return ErrEffectMismatch
	}
	if effect.Status != EffectDispatched && effect.Status != EffectExternallyCommitted {
		return ErrEffectNotDispatched
	}
	return nil
}

func validateEffectBinding(binding ServiceBinding, service EffectService) error {
	if binding == BindingWorkspace && service != EffectServiceWorkspace {
		return ErrServiceBindingMismatch
	}
	return nil
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func validEffectService(service EffectService) bool {
	switch service {
	case EffectServiceModel, EffectServiceWorkspace, EffectServiceExecutor,
		EffectServiceMCP, EffectServiceArtifact, EffectServiceExternalTool:
		return true
	default:
		return false
	}
}

func validIdentifier(value string, optional bool) bool {
	return validProtocolText(value, optional)
}

func validProtocolText(value string, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > 256 || !utf8.ValidString(value) ||
		!norm.NFC.IsNormalString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validPermission(permission Permission) bool {
	return validProtocolText(string(permission), false)
}

func isServiceBinding(binding ServiceBinding) bool {
	switch binding {
	case BindingState, BindingWorkspace, BindingModel, BindingMCP,
		BindingExecutor, BindingArtifacts, BindingEvents:
		return true
	default:
		return false
	}
}

func hasPermission(permissions []Permission, requested Permission) bool {
	for _, permission := range permissions {
		if permission == requested {
			return true
		}
	}
	return false
}
