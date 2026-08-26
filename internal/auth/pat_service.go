package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"
)

var (
	ErrPATNotFound        = errors.New("PAT not found")
	ErrPATConflict        = errors.New("PAT already exists")
	ErrPATVersionConflict = errors.New("PAT version conflict")
	ErrPATStoreContended  = errors.New("PAT store remained contended")
)

type PATAuditKind string

const (
	PATAuditIssued  PATAuditKind = "issued"
	PATAuditUsed    PATAuditKind = "used"
	PATAuditRevoked PATAuditKind = "revoked"
)

type PATAuditEvent struct {
	At       time.Time
	Kind     PATAuditKind
	PATID    string
	TenantID string
	UserID   string
	Scope    string
}

type PATStore interface {
	// CreatePAT atomically creates record and appends event to a durable audit
	// outbox. It must leave neither mutation behind when either write fails.
	CreatePAT(context.Context, PATRecord, PATAuditEvent) error
	LoadPATByDigest(context.Context, string) (PATRecord, error)
	LoadPATByID(context.Context, string) (PATRecord, error)
	// CommitPAT atomically compares the current version, writes next, and
	// appends event to a durable audit outbox.
	CommitPAT(context.Context, string, uint64, PATRecord, PATAuditEvent) error
}

type PATServiceConfig struct {
	Store             PATStore
	Entropy           io.Reader
	Now               func() time.Time
	MaximumCASRetries uint32
}

type PATService struct {
	store             PATStore
	entropy           io.Reader
	now               func() time.Time
	maximumCASRetries uint32
	entropyMu         sync.Mutex
}

type PATPrincipal struct {
	TenantID string
	UserID   string
	PATID    string
}

func NewPATService(config PATServiceConfig) (*PATService, error) {
	if config.Store == nil || config.Now == nil {
		return nil, errors.New("PAT store and clock are required")
	}
	if config.MaximumCASRetries == 0 || config.MaximumCASRetries > 256 {
		return nil, errors.New("maximum PAT CAS retries must be between 1 and 256")
	}
	entropy := config.Entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	return &PATService{
		store:             config.Store,
		entropy:           entropy,
		now:               config.Now,
		maximumCASRetries: config.MaximumCASRetries,
	}, nil
}

func (service *PATService) Issue(
	ctx context.Context,
	tenantID string,
	userID string,
	scopes []string,
	lifetime time.Duration,
) (string, PATRecord, error) {
	if ctx == nil {
		return "", PATRecord{}, errors.New("PAT context is required")
	}
	if lifetime <= 0 || lifetime > maximumPATLifetime {
		return "", PATRecord{}, errors.New("PAT lifetime is outside the supported range")
	}
	issuedAt := service.now().UTC()
	for range service.maximumCASRetries {
		service.entropyMu.Lock()
		plaintext, record, err := issuePAT(
			service.entropy,
			tenantID,
			userID,
			scopes,
			issuedAt,
			issuedAt.Add(lifetime),
		)
		service.entropyMu.Unlock()
		if err != nil {
			return "", PATRecord{}, err
		}
		event := PATAuditEvent{
			At:       issuedAt,
			Kind:     PATAuditIssued,
			PATID:    record.ID,
			TenantID: record.TenantID,
			UserID:   record.UserID,
		}
		if err := service.store.CreatePAT(ctx, record, event); err != nil {
			if errors.Is(err, ErrPATConflict) {
				continue
			}
			return "", PATRecord{}, fmt.Errorf("store issued PAT: %w", err)
		}
		return plaintext, clonePATRecord(record), nil
	}
	return "", PATRecord{}, ErrPATStoreContended
}

func (service *PATService) Authenticate(
	ctx context.Context,
	plaintext string,
	requiredScope string,
) (PATPrincipal, error) {
	if ctx == nil {
		return PATPrincipal{}, errors.New("PAT context is required")
	}
	digest, err := parsePATPlaintext(plaintext)
	if err != nil {
		return PATPrincipal{}, ErrInvalidCredential
	}
	digestText := "sha256:" + hex.EncodeToString(digest[:])
	for range service.maximumCASRetries {
		record, err := service.store.LoadPATByDigest(ctx, digestText)
		if err != nil {
			if errors.Is(err, ErrPATNotFound) {
				return PATPrincipal{}, ErrInvalidCredential
			}
			return PATPrincipal{}, fmt.Errorf("load PAT: %w", err)
		}
		now := service.now().UTC()
		if err := verifyPATSnapshot(plaintext, record, requiredScope, now); err != nil {
			return PATPrincipal{}, err
		}
		if record.Version == math.MaxUint64 || record.UseCount == math.MaxUint64 {
			return PATPrincipal{}, ErrInvalidCredential
		}
		next := clonePATRecord(record)
		next.LastUsedAt = now
		next.UseCount++
		next.Version++
		event := PATAuditEvent{
			At:       now,
			Kind:     PATAuditUsed,
			PATID:    record.ID,
			TenantID: record.TenantID,
			UserID:   record.UserID,
			Scope:    requiredScope,
		}
		if err := service.store.CommitPAT(ctx, record.ID, record.Version, next, event); err != nil {
			if errors.Is(err, ErrPATVersionConflict) {
				continue
			}
			return PATPrincipal{}, fmt.Errorf("commit PAT use: %w", err)
		}
		return PATPrincipal{
			TenantID: record.TenantID,
			UserID:   record.UserID,
			PATID:    record.ID,
		}, nil
	}
	return PATPrincipal{}, ErrPATStoreContended
}

func (service *PATService) Revoke(
	ctx context.Context,
	patID string,
	expectedVersion uint64,
) (PATRecord, error) {
	if ctx == nil {
		return PATRecord{}, errors.New("PAT context is required")
	}
	if err := validateBoundedText(patID); err != nil || expectedVersion == 0 {
		return PATRecord{}, ErrInvalidCredential
	}
	record, err := service.store.LoadPATByID(ctx, patID)
	if err != nil {
		return PATRecord{}, err
	}
	if err := validatePATRecord(record); err != nil || record.ID != patID {
		return PATRecord{}, ErrInvalidCredential
	}
	if record.RevokedAt != nil {
		return clonePATRecord(record), nil
	}
	if record.Version != expectedVersion {
		return PATRecord{}, ErrPATVersionConflict
	}
	now := service.now().UTC()
	next, err := applyPATRevocation(record, now)
	if err != nil {
		return PATRecord{}, err
	}
	event := PATAuditEvent{
		At:       *next.RevokedAt,
		Kind:     PATAuditRevoked,
		PATID:    record.ID,
		TenantID: record.TenantID,
		UserID:   record.UserID,
	}
	if err := service.store.CommitPAT(ctx, record.ID, record.Version, next, event); err != nil {
		return PATRecord{}, err
	}
	return clonePATRecord(next), nil
}
