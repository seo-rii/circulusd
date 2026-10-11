// Package authstate binds authentication persistence to one independently
// qualified native transaction source. It owns no process-local durable state.
package authstate

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/hancomac/circulusd/internal/auth"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
)

const AtomicCredentialAudit dependency.AtomicGroup = "credential-audit"

var (
	ErrInvalidConfiguration = errors.New("authstate: invalid configuration")
	ErrInvalidRequest       = errors.New("authstate: invalid request")
	ErrUnavailable          = errors.New("authstate: durable authentication unavailable")
	ErrCorruptState         = errors.New("authstate: corrupt durable authentication state")
	ErrCapacity             = errors.New("authstate: durable authentication capacity exhausted")
)

// Source must serialize one object's read/write set, roll back every callback
// error, and confirm the exact commit token's durability. Its native probe must
// attest the operational implementation, including credential/audit atomicity.
// Wrapping a file fixture or memory store cannot create that qualification.
type Source interface {
	celld.Storage
	dependency.ProductionProbe
}

type Config struct {
	Source              dependency.Verified[Source]
	TenantID            string
	Now                 func() time.Time
	MaximumRecords      int
	MaximumAuditEntries int
	MaximumStateBytes   int
}

func (Config) String() string   { return "authstate-config<redacted>" }
func (Config) GoString() string { return "authstate-config<redacted>" }

type PATStore struct {
	source   Source
	binding  dependency.Verified[Source]
	tenantID string
	objectID string
	now      func() time.Time
	limits   limits
}

func (*PATStore) String() string   { return "authstate-pat-store<redacted>" }
func (*PATStore) GoString() string { return "authstate-pat-store<redacted>" }

func New(config Config) (*PATStore, error) {
	source, _, err := config.Source.Open()
	if err != nil || nilInterface(source) {
		return nil, dependency.ErrUnverifiedDependency
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{AtomicCredentialAudit}, config.Source); err != nil {
		return nil, err
	}
	if _, err := identity.Parse(identity.Tenant, config.TenantID); err != nil || config.Now == nil {
		return nil, ErrInvalidConfiguration
	}
	bound, err := configuredLimits(config)
	if err != nil {
		return nil, err
	}
	return &PATStore{source: source, binding: config.Source, tenantID: config.TenantID,
		objectID: "auth:" + config.TenantID, now: config.Now, limits: bound}, nil
}

func (store *PATStore) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	if store == nil || nilInterface(store.source) {
		return dependency.ProbeResponse{}, dependency.ErrUnverifiedDependency
	}
	if _, _, err := store.binding.Open(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	return store.source.ProbeProduction(ctx, challenge)
}

func (store *PATStore) CreatePAT(ctx context.Context, record auth.PATRecord, event auth.PATAuditEvent) error {
	if err := store.ready(ctx); err != nil {
		return err
	}
	if len(record.Scopes) < 1 || len(record.Scopes) > 128 {
		return auth.ErrInvalidCredential
	}
	record = cloneRecord(record)
	if !validRecord(record, store.tenantID) || record.Version != 1 || record.UseCount != 0 ||
		record.RevokedAt != nil || !record.LastUsedAt.IsZero() || !matchesEvent(record, event) ||
		event.Kind != auth.PATAuditIssued || event.Scope != "" || !event.At.Equal(record.IssuedAt) {
		return auth.ErrInvalidCredential
	}
	return store.transact(ctx, func(state *durableState, now time.Time) (bool, error) {
		if !validNow(now) || now.Before(event.At) || !now.Before(record.ExpiresAt) {
			return false, auth.ErrInvalidCredential
		}
		for _, current := range state.records {
			if current.ID == record.ID || current.Digest == record.Digest {
				return false, auth.ErrPATConflict
			}
		}
		if len(state.records) >= store.limits.records {
			return false, ErrCapacity
		}
		state.records = append(state.records, record)
		if err := state.appendAudit(event, record.Version, now, store.limits); err != nil {
			return false, err
		}
		return true, nil
	})
}

func (store *PATStore) LoadPATByDigest(ctx context.Context, digest string) (auth.PATRecord, error) {
	if !validDigest(digest) {
		return auth.PATRecord{}, auth.ErrInvalidCredential
	}
	return store.load(ctx, func(record auth.PATRecord) bool { return record.Digest == digest })
}

func (store *PATStore) LoadPATByID(ctx context.Context, id string) (auth.PATRecord, error) {
	if !validPATID(id) {
		return auth.PATRecord{}, auth.ErrInvalidCredential
	}
	return store.load(ctx, func(record auth.PATRecord) bool { return record.ID == id })
}

func (store *PATStore) load(ctx context.Context, match func(auth.PATRecord) bool) (auth.PATRecord, error) {
	if err := store.ready(ctx); err != nil {
		return auth.PATRecord{}, err
	}
	var result auth.PATRecord
	err := store.transact(ctx, func(state *durableState, _ time.Time) (bool, error) {
		result = auth.PATRecord{}
		for _, record := range state.records {
			if match(record) {
				result = cloneRecord(record)
				return false, nil
			}
		}
		return false, auth.ErrPATNotFound
	})
	if err != nil {
		return auth.PATRecord{}, err
	}
	return result, nil
}

func (store *PATStore) CommitPAT(ctx context.Context, id string, expectedVersion uint64, next auth.PATRecord, event auth.PATAuditEvent) error {
	if err := store.ready(ctx); err != nil {
		return err
	}
	if len(next.Scopes) < 1 || len(next.Scopes) > 128 {
		return auth.ErrInvalidCredential
	}
	next = cloneRecord(next)
	if !validPATID(id) || expectedVersion == 0 || expectedVersion >= maximumInteger ||
		!validRecord(next, store.tenantID) || next.ID != id || !matchesEvent(next, event) {
		return auth.ErrInvalidCredential
	}
	return store.transact(ctx, func(state *durableState, now time.Time) (bool, error) {
		for index, current := range state.records {
			if current.ID != id {
				continue
			}
			if current.Version != expectedVersion {
				return false, auth.ErrPATVersionConflict
			}
			if !validTransition(current, next, event, now) {
				return false, auth.ErrInvalidCredential
			}
			state.records[index] = next
			if err := state.appendAudit(event, next.Version, now, store.limits); err != nil {
				return false, err
			}
			return true, nil
		}
		return false, auth.ErrPATNotFound
	})
}

// AuditEntry is both the immutable hash-chain row and the durable outbox row.
// Only a separately qualified delivery/checkpoint service can acknowledge or
// export it. Reading this outbox never removes it or advances credential state.
type AuditEntry struct {
	Sequence          uint64
	PreviousDigest    string
	Digest            string
	CredentialVersion uint64
	CommittedAt       time.Time
	Event             auth.PATAuditEvent
}

func (AuditEntry) String() string   { return "authstate-audit-entry<redacted>" }
func (AuditEntry) GoString() string { return "authstate-audit-entry<redacted>" }

type AuditPage struct {
	TenantID     string
	ObjectID     string
	StateDigest  [32]byte
	Entries      []AuditEntry
	HeadSequence uint64
	HeadDigest   string
}

func (store *PATStore) ReadAudit(ctx context.Context, afterSequence uint64, limit uint32) (AuditPage, error) {
	if err := store.ready(ctx); err != nil {
		return AuditPage{}, err
	}
	if afterSequence > maximumInteger || limit < 1 || limit > 1024 {
		return AuditPage{}, ErrInvalidRequest
	}
	var result AuditPage
	err := store.transact(ctx, func(state *durableState, _ time.Time) (bool, error) {
		if afterSequence > uint64(len(state.audit)) {
			return false, ErrInvalidRequest
		}
		end := min(uint64(len(state.audit)), afterSequence+uint64(limit))
		result = AuditPage{TenantID: store.tenantID, ObjectID: store.objectID, StateDigest: state.rawDigest,
			Entries:      append([]AuditEntry(nil), state.audit[afterSequence:end]...),
			HeadSequence: uint64(len(state.audit)), HeadDigest: state.headDigest()}
		return false, nil
	})
	if err != nil {
		return AuditPage{}, err
	}
	return result, nil
}

func (store *PATStore) ready(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil || nilInterface(store.source) {
		return dependency.ErrUnverifiedDependency
	}
	if _, _, err := store.binding.Open(); err != nil {
		return dependency.ErrUnverifiedDependency
	}
	return nil
}

func (store *PATStore) transact(ctx context.Context, apply func(*durableState, time.Time) (bool, error)) error {
	started, completed := 0, 0
	token, err := store.source.Transaction(ctx, store.objectID, func(transaction celld.Transaction) error {
		started++
		if nilInterface(transaction) {
			return ErrUnavailable
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		bytes, err := transaction.ReadState()
		if err != nil {
			return safeError(ctx, err)
		}
		state, err := decodeState(bytes, store.tenantID, store.limits)
		if err != nil {
			return err
		}
		changed, err := apply(state, store.now().UTC())
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if changed {
			bytes, err := encodeState(state, store.limits)
			if err != nil {
				return err
			}
			if err := transaction.WriteState(bytes); err != nil {
				return safeError(ctx, err)
			}
		}
		completed++
		return nil
	})
	if err != nil {
		return safeError(ctx, err)
	}
	if started == 0 || completed != started || token.ObjectID != store.objectID || token.Revision == 0 {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := store.source.DurabilityBarrier(ctx, token); err != nil {
		return safeError(ctx, err)
	}
	return ctx.Err()
}

func safeError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	// Return the sentinel, never an arbitrary backend error wrapping that
	// sentinel with native diagnostics, bearer material or credential digests.
	for _, safe := range []error{auth.ErrInvalidCredential, auth.ErrPATConflict, auth.ErrPATNotFound,
		auth.ErrPATVersionConflict, ErrCorruptState, ErrCapacity, ErrInvalidRequest} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return ErrUnavailable
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

var _ auth.PATStore = (*PATStore)(nil)
var _ dependency.ProductionProbe = (*PATStore)(nil)
