package idempotency

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

var (
	ErrKeyReused        = errors.New("idempotency key was reused with another request")
	ErrRecordNotFound   = errors.New("idempotency record was not found")
	ErrSagaConflict     = errors.New("creation saga identity or result conflicts")
	ErrInvalidSagaPhase = errors.New("creation saga is in an invalid phase")
)

var (
	methodPattern    = regexp.MustCompile(`^[A-Z]+$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	keyDigestPattern = regexp.MustCompile(`^hmac-sha256:[0-9a-f]{64}$`)
)

type Scope struct {
	TenantID      string
	SubjectID     string
	Method        string
	RouteTemplate string
	TargetID      string
}

type CreationPhase string

const (
	Reserved          CreationPhase = "reserved"
	TargetInitialized CreationPhase = "target_initialized"
	Finalized         CreationPhase = "finalized"
)

type CreationRecord struct {
	Scope         Scope
	KeyDigest     string
	RequestDigest string
	ResourceID    string
	Phase         CreationPhase
	ResultRef     string
}

type CreationRegistry struct {
	mu      sync.RWMutex
	records map[recordKey]CreationRecord
}

type recordKey struct {
	Scope     Scope
	KeyDigest string
}

func DigestKey(secret []byte, rawKey string) (string, error) {
	if len(secret) < 32 {
		return "", fmt.Errorf("idempotency HMAC secret must be at least 32 bytes")
	}
	if len(rawKey) == 0 || len(rawKey) > 256 {
		return "", fmt.Errorf("idempotency key must contain 1 to 256 bytes")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(rawKey))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), nil
}

func NewCreationRegistry() *CreationRegistry {
	return &CreationRegistry{records: make(map[recordKey]CreationRecord)}
}

func (registry *CreationRegistry) Reserve(
	scope Scope,
	keyDigest string,
	requestDigest string,
	proposedResourceID string,
) (CreationRecord, bool, error) {
	if err := validateScopeAndKey(scope, keyDigest); err != nil {
		return CreationRecord{}, false, err
	}
	if err := validateRequestDigest(requestDigest); err != nil {
		return CreationRecord{}, false, err
	}
	if strings.TrimSpace(proposedResourceID) == "" || len(proposedResourceID) > 256 {
		return CreationRecord{}, false, fmt.Errorf("proposed resource ID is invalid")
	}

	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.records == nil {
		registry.records = make(map[recordKey]CreationRecord)
	}

	key := recordKey{Scope: scope, KeyDigest: keyDigest}
	if existing, found := registry.records[key]; found {
		if existing.RequestDigest != requestDigest {
			return CreationRecord{}, false, ErrKeyReused
		}
		return existing, true, nil
	}
	record := CreationRecord{
		Scope:         scope,
		KeyDigest:     keyDigest,
		RequestDigest: requestDigest,
		ResourceID:    proposedResourceID,
		Phase:         Reserved,
	}
	registry.records[key] = record
	return record, false, nil
}

func (registry *CreationRegistry) Lookup(
	scope Scope,
	keyDigest string,
) (CreationRecord, bool, error) {
	if err := validateScopeAndKey(scope, keyDigest); err != nil {
		return CreationRecord{}, false, err
	}

	registry.mu.RLock()
	record, found := registry.records[recordKey{Scope: scope, KeyDigest: keyDigest}]
	registry.mu.RUnlock()
	return record, found, nil
}

func (registry *CreationRegistry) MarkTargetInitialized(
	scope Scope,
	keyDigest string,
	requestDigest string,
	resourceID string,
	resultRef string,
) (CreationRecord, error) {
	if strings.TrimSpace(resultRef) == "" || len(resultRef) > 256 {
		return CreationRecord{}, fmt.Errorf("target result reference is invalid")
	}

	registry.mu.Lock()
	defer registry.mu.Unlock()
	record, key, err := registry.recordForTransition(scope, keyDigest, requestDigest, resourceID)
	if err != nil {
		return CreationRecord{}, err
	}
	switch record.Phase {
	case Reserved:
		record.Phase = TargetInitialized
		record.ResultRef = resultRef
		registry.records[key] = record
		return record, nil
	case TargetInitialized, Finalized:
		if record.ResultRef != resultRef {
			return CreationRecord{}, ErrSagaConflict
		}
		return record, nil
	default:
		return CreationRecord{}, ErrInvalidSagaPhase
	}
}

func (registry *CreationRegistry) Finalize(
	scope Scope,
	keyDigest string,
	requestDigest string,
	resourceID string,
) (CreationRecord, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	record, key, err := registry.recordForTransition(scope, keyDigest, requestDigest, resourceID)
	if err != nil {
		return CreationRecord{}, err
	}
	switch record.Phase {
	case Reserved:
		return CreationRecord{}, ErrInvalidSagaPhase
	case TargetInitialized:
		record.Phase = Finalized
		registry.records[key] = record
		return record, nil
	case Finalized:
		return record, nil
	default:
		return CreationRecord{}, ErrInvalidSagaPhase
	}
}

func (registry *CreationRegistry) recordForTransition(
	scope Scope,
	keyDigest string,
	requestDigest string,
	resourceID string,
) (CreationRecord, recordKey, error) {
	if err := validateScopeAndKey(scope, keyDigest); err != nil {
		return CreationRecord{}, recordKey{}, err
	}
	if err := validateRequestDigest(requestDigest); err != nil {
		return CreationRecord{}, recordKey{}, err
	}
	key := recordKey{Scope: scope, KeyDigest: keyDigest}
	record, found := registry.records[key]
	if !found {
		return CreationRecord{}, recordKey{}, ErrRecordNotFound
	}
	if record.RequestDigest != requestDigest {
		return CreationRecord{}, recordKey{}, ErrKeyReused
	}
	if record.ResourceID != resourceID {
		return CreationRecord{}, recordKey{}, ErrSagaConflict
	}
	return record, key, nil
}

func validateScopeAndKey(scope Scope, keyDigest string) error {
	for field, value := range map[string]string{
		"tenant ID":  scope.TenantID,
		"subject ID": scope.SubjectID,
	} {
		if strings.TrimSpace(value) == "" || len(value) > 256 {
			return fmt.Errorf("idempotency scope %s is invalid", field)
		}
	}
	if !methodPattern.MatchString(scope.Method) {
		return fmt.Errorf("idempotency scope method %q is not canonical", scope.Method)
	}
	if !strings.HasPrefix(scope.RouteTemplate, "/") ||
		strings.ContainsAny(scope.RouteTemplate, "?#") ||
		len(scope.RouteTemplate) > 512 {
		return fmt.Errorf("idempotency route template %q is not canonical", scope.RouteTemplate)
	}
	if len(scope.TargetID) > 256 {
		return fmt.Errorf("idempotency target ID is too long")
	}
	if !keyDigestPattern.MatchString(keyDigest) {
		return fmt.Errorf("idempotency key digest is not canonical HMAC-SHA-256")
	}
	return nil
}

func validateRequestDigest(value string) error {
	if !digestPattern.MatchString(value) {
		return fmt.Errorf("idempotency request digest is not canonical SHA-256")
	}
	return nil
}
