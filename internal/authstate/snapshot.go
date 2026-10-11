package authstate

import "context"

// AuditSnapshot binds a checkpoint to one exact native transaction's original
// state bytes and audit head. It contains no credential record or event body.
type AuditSnapshot struct {
	TenantID, ObjectID string
	StateDigest        [32]byte
	HeadSequence       uint64
	HeadDigest         string
}

func (store *PATStore) ReadAuditSnapshot(ctx context.Context) (AuditSnapshot, error) {
	page, err := store.ReadAudit(ctx, 0, 1)
	if err != nil {
		return AuditSnapshot{}, err
	}
	return AuditSnapshot{TenantID: page.TenantID, ObjectID: page.ObjectID, StateDigest: page.StateDigest,
		HeadSequence: page.HeadSequence, HeadDigest: page.HeadDigest}, nil
}

func (store *AccountStore) ReadAuditSnapshot(ctx context.Context) (AuditSnapshot, error) {
	page, err := store.ReadAudit(ctx, 0, 1)
	if err != nil {
		return AuditSnapshot{}, err
	}
	return AuditSnapshot{TenantID: page.TenantID, ObjectID: page.ObjectID, StateDigest: page.StateDigest,
		HeadSequence: page.HeadSequence, HeadDigest: page.HeadDigest}, nil
}
