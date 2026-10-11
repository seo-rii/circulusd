// Package auditcheckpoint publishes historical integrity checkpoints for the
// qualified credential-audit stream. Checkpoints do not authorize credential
// use or certify that their head remains current after publication.
package auditcheckpoint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/hancomac/circulusd/internal/authstate"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
)

const AtomicCheckpointSigning dependency.AtomicGroup = "audit-checkpoint-signing"

var (
	ErrInvalidConfiguration = errors.New("audit checkpoint: invalid configuration")
	ErrInvalidRequest       = errors.New("audit checkpoint: invalid request")
	ErrInvalidCheckpoint    = errors.New("audit checkpoint: invalid checkpoint")
	ErrStaleSnapshot        = errors.New("audit checkpoint: source snapshot changed")
	ErrCheckpointConflict   = errors.New("audit checkpoint: immutable checkpoint conflict")
	ErrUnavailable          = errors.New("audit checkpoint: qualified source unavailable")
)

type AuditReader interface {
	ReadAuditSnapshot(context.Context) (authstate.AuditSnapshot, error)
	dependency.ProductionProbe
}

// Signer is a native operational signing service supplied by trusted wiring.
// Its independent qualification must attest this bounded checkpoint-signing
// role, not borrow the audit-storage probe. No runtime private key is created,
// retained, or recovered by this package.
type Signer interface {
	SignCheckpoint(context.Context, SigningRequest) (SigningResponse, error)
	dependency.ProductionProbe
}

type SigningRequest struct {
	KeyID           string
	CanonicalClaims []byte
	SigningDigest   [32]byte
}

type SigningResponse struct {
	KeyID         string
	SigningDigest [32]byte
	Signature     []byte
}

func (SigningRequest) String() string    { return "audit-checkpoint-signing-request<redacted>" }
func (SigningRequest) GoString() string  { return "audit-checkpoint-signing-request<redacted>" }
func (SigningResponse) String() string   { return "audit-checkpoint-signing-response<redacted>" }
func (SigningResponse) GoString() string { return "audit-checkpoint-signing-response<redacted>" }

type Claims struct {
	AuditGroup                                               string
	TenantID, ObjectID                                       string
	SourceInstanceID, TransactionDomainID                    string
	SourceBuildDigest, SourceApplicationDigest               string
	HeadSequence                                             uint64
	HeadDigest                                               string
	StateDigest                                              [32]byte
	SignerKeyID, SignerInstanceID, SignerTransactionDomainID string
	SignerBuildDigest, SignerApplicationDigest               string
}

type Checkpoint struct {
	Claims        Claims
	SigningDigest [32]byte
	Signature     []byte
}

func (Checkpoint) String() string   { return "signed-audit-checkpoint<redacted>" }
func (Checkpoint) GoString() string { return "signed-audit-checkpoint<redacted>" }

type Config struct {
	TenantID   string
	AuditGroup dependency.AtomicGroup
	Reader     dependency.Verified[AuditReader]
	Storage    dependency.Verified[authstate.Source]
	Signer     dependency.Verified[Signer]
	KeyID      string
	PublicKey  ed25519.PublicKey
}

type Publisher struct {
	reader         AuditReader
	storage        authstate.Source
	signer         Signer
	readerBinding  dependency.Verified[AuditReader]
	storageBinding dependency.Verified[authstate.Source]
	signerBinding  dependency.Verified[Signer]
	template       Claims
	publicKey      ed25519.PublicKey
}

func New(config Config) (*Publisher, error) {
	reader, readerDescriptor, readerErr := config.Reader.Open()
	storage, storageDescriptor, storageErr := config.Storage.Open()
	signer, signerDescriptor, signerErr := config.Signer.Open()
	if readerErr != nil || storageErr != nil || signerErr != nil || isNil(reader) || isNil(storage) || isNil(signer) ||
		!slices.Contains(storageDescriptor.AtomicGroups, dependency.AtomicCommandReceipt) ||
		!slices.Contains(signerDescriptor.AtomicGroups, AtomicCheckpointSigning) {
		return nil, dependency.ErrUnverifiedDependency
	}
	group := config.AuditGroup
	if group == "" {
		group = authstate.AtomicCredentialAudit
	}
	if group != authstate.AtomicCredentialAudit && group != authstate.AtomicAccountAudit {
		return nil, ErrInvalidConfiguration
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{group}, config.Reader, config.Storage); err != nil {
		return nil, err
	}
	if _, err := identity.Parse(identity.Tenant, config.TenantID); err != nil || !validIdentifier(config.KeyID) || !validPublicKey(config.PublicKey) {
		return nil, ErrInvalidConfiguration
	}
	// The storage descriptor supplies the transaction identity. Require the
	// same concrete runtime identity as the retained audited reader as well.
	if readerDescriptor.InstanceID != storageDescriptor.InstanceID || readerDescriptor.BuildDigest != storageDescriptor.BuildDigest ||
		readerDescriptor.ApplicationDigest != storageDescriptor.ApplicationDigest {
		return nil, dependency.ErrTransactionDomainMismatch
	}
	return &Publisher{reader: reader, storage: storage, signer: signer,
		readerBinding: config.Reader, storageBinding: config.Storage, signerBinding: config.Signer,
		publicKey: bytes.Clone(config.PublicKey), template: Claims{AuditGroup: string(group), TenantID: config.TenantID, ObjectID: auditObjectID(group, config.TenantID),
			SourceInstanceID: storageDescriptor.InstanceID, TransactionDomainID: storageDescriptor.TransactionDomainID,
			SourceBuildDigest: storageDescriptor.BuildDigest, SourceApplicationDigest: storageDescriptor.ApplicationDigest,
			SignerKeyID: config.KeyID, SignerInstanceID: signerDescriptor.InstanceID,
			SignerTransactionDomainID: signerDescriptor.TransactionDomainID,
			SignerBuildDigest:         signerDescriptor.BuildDigest, SignerApplicationDigest: signerDescriptor.ApplicationDigest}}, nil
}

// Publish signs the actual retained audit snapshot, compares its full raw state
// SHA and head again inside the same audit object's transaction, then publishes
// an immutable receipt. Any concurrent state change fails with ErrStaleSnapshot;
// signing is outside the transaction and performs no credential state mutation.
// Existing checkpoint replay returns its exact original signature without a
// new signing call. The receipt's exact durability barrier must confirm before
// a checkpoint is exposed. Scheduling and external audit conformance remain
// the operator's responsibility.
func (publisher *Publisher) Publish(ctx context.Context) (Checkpoint, error) {
	if err := publisher.ready(ctx); err != nil {
		return Checkpoint{}, err
	}
	page, err := publisher.reader.ReadAuditSnapshot(ctx)
	if err != nil {
		return Checkpoint{}, safeError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return Checkpoint{}, err
	}
	claims, err := publisher.claims(page)
	if err != nil {
		return Checkpoint{}, err
	}
	existing, found, err := publisher.transact(ctx, claims, nil)
	if err != nil || found {
		return existing, err
	}
	canonicalClaims, digest, err := signingPayload(claims)
	if err != nil {
		return Checkpoint{}, ErrInvalidCheckpoint
	}
	response, err := publisher.signer.SignCheckpoint(ctx, SigningRequest{KeyID: claims.SignerKeyID,
		CanonicalClaims: bytes.Clone(canonicalClaims), SigningDigest: digest})
	if err != nil {
		return Checkpoint{}, safeError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return Checkpoint{}, err
	}
	if response.KeyID != claims.SignerKeyID || response.SigningDigest != digest || len(response.Signature) != ed25519.SignatureSize {
		return Checkpoint{}, ErrInvalidCheckpoint
	}
	checkpoint := Checkpoint{Claims: claims, SigningDigest: digest, Signature: bytes.Clone(response.Signature)}
	if err := Verify(checkpoint, publisher.publicKey); err != nil {
		return Checkpoint{}, err
	}
	result, _, err := publisher.transact(ctx, claims, &checkpoint)
	return result, err
}

func (publisher *Publisher) ready(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if publisher == nil || isNil(publisher.reader) || isNil(publisher.storage) || isNil(publisher.signer) {
		return dependency.ErrUnverifiedDependency
	}
	if _, _, err := publisher.readerBinding.Open(); err != nil {
		return err
	}
	if _, _, err := publisher.storageBinding.Open(); err != nil {
		return err
	}
	_, _, err := publisher.signerBinding.Open()
	return err
}

func (publisher *Publisher) claims(page authstate.AuditSnapshot) (Claims, error) {
	if page.TenantID != publisher.template.TenantID || page.ObjectID != publisher.template.ObjectID ||
		page.StateDigest == ([32]byte{}) || page.HeadSequence > maximumAuditSequence || !validDigest(page.HeadDigest) ||
		(page.HeadSequence == 0) != (page.HeadDigest == zeroHeadDigest) {
		return Claims{}, ErrInvalidCheckpoint
	}
	claims := publisher.template
	claims.HeadSequence, claims.HeadDigest, claims.StateDigest = page.HeadSequence, page.HeadDigest, page.StateDigest
	return claims, nil
}

func (publisher *Publisher) transact(ctx context.Context, claims Claims, publish *Checkpoint) (Checkpoint, bool, error) {
	var result Checkpoint
	var found bool
	started := 0
	var complete bool
	id := fmt.Sprintf("audit-checkpoint.v1/%d", claims.HeadSequence)
	token, err := publisher.storage.Transaction(ctx, claims.ObjectID, func(tx celld.Transaction) error {
		started++
		result, found, complete = Checkpoint{}, false, false
		if isNil(tx) {
			return celld.ErrStorageContract
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		state, err := tx.ReadState()
		if err != nil {
			return err
		}
		if len(state) > maximumAuditStateBytes {
			return ErrInvalidCheckpoint
		}
		if sha256.Sum256(state) != claims.StateDigest || !matchesHead(state, claims) {
			return ErrStaleSnapshot
		}
		receipt, exists, err := tx.LookupReceipt(id)
		if err != nil {
			return err
		}
		if exists {
			if len(receipt.Response) > MaximumCheckpointBytes || len(receipt.CapabilityClaims) != 0 {
				return ErrInvalidCheckpoint
			}
			result, err = Decode(receipt.Response, publisher.publicKey)
			if err != nil {
				return err
			}
			if result.Claims != claims || receipt.CommandDigest != celld.Digest(result.SigningDigest) {
				return ErrCheckpointConflict
			}
			found = true
		} else if publish != nil {
			response, err := Encode(*publish)
			if err != nil {
				return err
			}
			if err := tx.WriteReceipt(id, celld.StoredReceipt{CommandDigest: celld.Digest(publish.SigningDigest), Response: response}); err != nil {
				return err
			}
			result = *publish
			result.Signature = bytes.Clone(publish.Signature)
			found = true
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		complete = true
		return nil
	})
	if err != nil {
		return Checkpoint{}, false, safeError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return Checkpoint{}, false, err
	}
	if started == 0 || !complete || token.ObjectID != claims.ObjectID || token.Revision == 0 {
		return Checkpoint{}, false, celld.ErrStorageContract
	}
	if err := publisher.storage.DurabilityBarrier(ctx, token); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return Checkpoint{}, false, contextErr
		}
		return Checkpoint{}, false, celld.ErrDurabilityBarrier
	}
	if err := ctx.Err(); err != nil {
		return Checkpoint{}, false, err
	}
	return result, found, nil
}

func safeError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	for _, safe := range []error{context.Canceled, context.DeadlineExceeded, ErrInvalidCheckpoint, ErrStaleSnapshot,
		ErrCheckpointConflict, celld.ErrStorageContract, celld.ErrDurabilityBarrier, dependency.ErrUnverifiedDependency,
		authstate.ErrCorruptState, authstate.ErrInvalidRequest, authstate.ErrUnavailable} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return ErrUnavailable
}

func isNil(value any) bool {
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

func auditObjectID(group dependency.AtomicGroup, tenant string) string {
	if group == authstate.AtomicAccountAudit {
		return "auth-accounts:" + tenant
	}
	return "auth:" + tenant
}
