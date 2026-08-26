package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
	"golang.org/x/text/unicode/norm"
)

const (
	maximumArtifactNameBytes       = 255
	maximumMediaTypeBytes          = 255
	maximumAttributeCount          = 64
	maximumAttributeKeyBytes       = 128
	maximumAttributeValueBytes     = 1024
	maximumAttributeMetadataBytes  = 16 << 10
	maximumWorkspacePathBytes      = 4096
	maximumWorkspaceComponentBytes = 255
	maximumCanonicalInteger        = int64(9_007_199_254_740_991)
	defaultGCBatchSize             = 256
	maximumGCBatchSize             = 4096
	defaultGCLeaseDuration         = time.Minute
)

type Service struct {
	workspace                 WorkspaceSnapshotReader
	authorizer                Authorizer
	repository                Repository
	blobs                     BlobStore
	now                       func() time.Time
	newArtifactID             func() (string, error)
	maximumArtifactBytes      int64
	defaultRetention          time.Duration
	maximumRetention          time.Duration
	gcGrace                   time.Duration
	inflightTimeout           time.Duration
	inflightHeartbeatInterval time.Duration
	gcBatchSize               int
	gcLeaseDuration           time.Duration
}

func NewService(config Config) (*Service, error) {
	if config.Workspace == nil || config.Authorizer == nil || config.Repository == nil || config.Blobs == nil ||
		config.MaximumArtifactBytes <= 0 || config.DefaultRetention <= 0 || config.MaximumRetention <= 0 ||
		config.DefaultRetention > config.MaximumRetention || config.GCGrace <= 0 || config.InflightTimeout <= 0 {
		return nil, ErrInvalidConfig
	}
	if config.MaximumArtifactBytes > maximumCanonicalInteger || config.MaximumRetention.Nanoseconds() > maximumCanonicalInteger {
		return nil, ErrInvalidConfig
	}
	if config.InflightHeartbeatInterval < 0 || config.InflightHeartbeatInterval >= config.InflightTimeout ||
		config.GCBatchSize < 0 || config.GCBatchSize > maximumGCBatchSize || config.GCLeaseDuration < 0 {
		return nil, ErrInvalidConfig
	}
	inflightHeartbeatInterval := config.InflightHeartbeatInterval
	if inflightHeartbeatInterval == 0 {
		inflightHeartbeatInterval = config.InflightTimeout / 3
	}
	if inflightHeartbeatInterval <= 0 {
		return nil, ErrInvalidConfig
	}
	gcBatchSize := config.GCBatchSize
	if gcBatchSize == 0 {
		gcBatchSize = defaultGCBatchSize
	}
	gcLeaseDuration := config.GCLeaseDuration
	if gcLeaseDuration == 0 {
		gcLeaseDuration = defaultGCLeaseDuration
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	newArtifactID := config.NewArtifactID
	if newArtifactID == nil {
		newArtifactID = func() (string, error) {
			value, err := identity.New(identity.Artifact)
			if err != nil {
				return "", err
			}
			return value.String(), nil
		}
	}
	return &Service{
		workspace: config.Workspace, authorizer: config.Authorizer,
		repository: config.Repository, blobs: config.Blobs,
		now: now, newArtifactID: newArtifactID,
		maximumArtifactBytes: config.MaximumArtifactBytes,
		defaultRetention:     config.DefaultRetention, maximumRetention: config.MaximumRetention,
		gcGrace: config.GCGrace, inflightTimeout: config.InflightTimeout,
		inflightHeartbeatInterval: inflightHeartbeatInterval,
		gcBatchSize:               gcBatchSize, gcLeaseDuration: gcLeaseDuration,
	}, nil
}

func (service *Service) CreateFromWorkspace(ctx context.Context, request CreateRequest) (ArtifactRef, error) {
	if err := validateAccess(request.Access); err != nil {
		return ArtifactRef{}, err
	}
	if _, err := identity.Parse(identity.Invocation, request.InvocationID); err != nil {
		return ArtifactRef{}, fmt.Errorf("%w: invocation ID: %v", ErrInvalidRequest, err)
	}
	if !validDigest(request.Source.RevisionID) {
		return ArtifactRef{}, fmt.Errorf("%w: source revision is not a canonical digest", ErrInvalidRequest)
	}
	if err := validateWorkspacePath(request.Source.Path); err != nil {
		return ArtifactRef{}, err
	}

	metadata := Metadata{
		Name: norm.NFC.String(request.Metadata.Name), MediaType: norm.NFC.String(request.Metadata.MediaType),
		RetainFor: request.Metadata.RetainFor,
	}
	if metadata.RetainFor == 0 {
		metadata.RetainFor = service.defaultRetention
	}
	if metadata.RetainFor < 0 || metadata.RetainFor > service.maximumRetention ||
		!utf8.ValidString(request.Metadata.Name) || norm.NFC.String(request.Metadata.Name) != request.Metadata.Name ||
		metadata.Name == "" || len(metadata.Name) > maximumArtifactNameBytes || metadata.Name == "." || metadata.Name == ".." ||
		strings.ContainsAny(metadata.Name, `/\`) ||
		!utf8.ValidString(request.Metadata.MediaType) || norm.NFC.String(request.Metadata.MediaType) != request.Metadata.MediaType ||
		metadata.MediaType == "" || len(metadata.MediaType) > maximumMediaTypeBytes || strings.Count(metadata.MediaType, "/") != 1 {
		return ArtifactRef{}, fmt.Errorf("%w: artifact metadata is invalid", ErrInvalidRequest)
	}
	for _, value := range []string{metadata.Name, metadata.MediaType} {
		for _, character := range value {
			if unicode.IsControl(character) {
				return ArtifactRef{}, fmt.Errorf("%w: artifact metadata contains control characters", ErrInvalidRequest)
			}
		}
	}
	if len(request.Metadata.Attributes) > maximumAttributeCount {
		return ArtifactRef{}, fmt.Errorf("%w: too many metadata attributes", ErrInvalidRequest)
	}
	metadata.Attributes = make(map[string]string, len(request.Metadata.Attributes))
	attributeBytes := 0
	for rawKey, rawValue := range request.Metadata.Attributes {
		if !utf8.ValidString(rawKey) || !utf8.ValidString(rawValue) {
			return ArtifactRef{}, fmt.Errorf("%w: metadata attribute is not UTF-8", ErrInvalidRequest)
		}
		key, value := norm.NFC.String(rawKey), norm.NFC.String(rawValue)
		if key == "" || len(key) > maximumAttributeKeyBytes || len(value) > maximumAttributeValueBytes {
			return ArtifactRef{}, fmt.Errorf("%w: metadata attribute exceeds a bound", ErrInvalidRequest)
		}
		if _, duplicate := metadata.Attributes[key]; duplicate {
			return ArtifactRef{}, fmt.Errorf("%w: normalized metadata attribute collision", ErrInvalidRequest)
		}
		for _, text := range []string{key, value} {
			for _, character := range text {
				if unicode.IsControl(character) {
					return ArtifactRef{}, fmt.Errorf("%w: metadata attribute contains control characters", ErrInvalidRequest)
				}
			}
		}
		attributeBytes += len(key) + len(value)
		if attributeBytes > maximumAttributeMetadataBytes {
			return ArtifactRef{}, fmt.Errorf("%w: metadata attributes exceed the aggregate bound", ErrInvalidRequest)
		}
		metadata.Attributes[key] = value
	}
	requestAttributes := canonical.Map{}
	for key, value := range metadata.Attributes {
		requestAttributes[key] = value
	}
	requestDigest, err := canonical.StructuredDigest("artifact.create-from-workspace", 1, canonical.Map{
		"tenantId": request.Access.TenantID, "sessionId": request.Access.SessionID,
		"workspaceId": request.Access.WorkspaceID, "revisionId": request.Source.RevisionID,
		"path": request.Source.Path,
		"metadata": canonical.Map{
			"name": metadata.Name, "mediaType": metadata.MediaType,
			"retainForNanoseconds": metadata.RetainFor.Nanoseconds(), "attributes": requestAttributes,
		},
	})
	if err != nil {
		return ArtifactRef{}, fmt.Errorf("%w: digest create request: %v", ErrInvalidRequest, err)
	}

	if err := service.authorizer.Authorize(ctx, AuthorizationRequest{
		Operation: OperationCreate, TenantID: request.Access.TenantID, SubjectID: request.Access.SubjectID,
		SessionID: request.Access.SessionID, WorkspaceID: request.Access.WorkspaceID,
		ResourceSessionID: request.Access.SessionID, ResourceWorkspaceID: request.Access.WorkspaceID,
	}); err != nil {
		return ArtifactRef{}, fmt.Errorf("%w: create authorization failed", ErrAccessDenied)
	}
	existingInvocation, found, err := service.repository.LookupInvocation(ctx, request.InvocationID)
	if err != nil {
		return ArtifactRef{}, err
	}
	var reservation InvocationRecord
	blobReady := false
	workCtx := ctx
	var cancelRecovery context.CancelFunc
	var recoveryHeartbeatDone chan error
	defer func() {
		if cancelRecovery != nil {
			cancelRecovery()
			<-recoveryHeartbeatDone
		}
	}()
	if found {
		if existingInvocation.TenantID != request.Access.TenantID || existingInvocation.RequestDigest != requestDigest {
			return ArtifactRef{}, ErrInvocationConflict
		}
		switch existingInvocation.State {
		case InvocationCommitted:
			record, getErr := service.repository.GetArtifact(ctx, existingInvocation.ArtifactID)
			if getErr != nil || !validArtifactRecord(record, service.maximumArtifactBytes) ||
				record.TenantID != request.Access.TenantID || record.InvocationID != request.InvocationID ||
				record.RequestDigest != requestDigest || record.ArtifactID != existingInvocation.ArtifactID {
				return ArtifactRef{}, fmt.Errorf("%w: committed invocation has no artifact", ErrStorageCorruption)
			}
			return artifactRefFromRecord(record), nil
		case InvocationAbandoned:
			return ArtifactRef{}, ErrInvocationAbandoned
		case InvocationInflight:
			reservation = existingInvocation
		default:
			return ArtifactRef{}, ErrStorageCorruption
		}
		if reservation.SessionID != request.Access.SessionID || reservation.WorkspaceID != request.Access.WorkspaceID ||
			reservation.SourceRevisionID != request.Source.RevisionID || reservation.SourcePath != request.Source.Path ||
			reservation.InvocationID != request.InvocationID || reservation.Generation == 0 ||
			reservation.StartedAt.IsZero() || reservation.HeartbeatAt.IsZero() || reservation.Size < 0 ||
			reservation.Size > service.maximumArtifactBytes || !validDigest(reservation.ContentDigest) ||
			!validDigest(reservation.MetadataDigest) {
			return ArtifactRef{}, ErrStorageCorruption
		}
		if _, parseErr := identity.Parse(identity.Artifact, reservation.ArtifactID); parseErr != nil {
			return ArtifactRef{}, ErrStorageCorruption
		}
		hexDigest := strings.TrimPrefix(reservation.ContentDigest, "sha256:")
		expectedObjectKey := request.Access.TenantID + "/sha256/" + hexDigest[:2] + "/" + hexDigest[2:4] + "/" + hexDigest
		expectedMetadataDigest, digestErr := digestMetadata(metadata, reservation.ContentDigest, reservation.Size)
		storedMetadataDigest, storedDigestErr := digestMetadata(reservation.Metadata, reservation.ContentDigest, reservation.Size)
		if digestErr != nil || storedDigestErr != nil || reservation.ObjectKey != expectedObjectKey ||
			reservation.MetadataDigest != expectedMetadataDigest || reservation.MetadataDigest != storedMetadataDigest {
			return ArtifactRef{}, ErrStorageCorruption
		}
		reservation, err = service.repository.HeartbeatCreate(
			ctx, request.InvocationID, requestDigest, reservation.Generation, service.now().UTC(),
		)
		if err != nil {
			return ArtifactRef{}, err
		}
		recoveryGeneration := reservation.Generation
		workCtx, cancelRecovery = context.WithCancel(ctx)
		recoveryHeartbeatDone = make(chan error, 1)
		go func() {
			ticker := time.NewTicker(service.inflightHeartbeatInterval)
			defer ticker.Stop()
			for {
				select {
				case <-workCtx.Done():
					recoveryHeartbeatDone <- nil
					return
				case <-ticker.C:
					if _, heartbeatErr := service.repository.HeartbeatCreate(
						workCtx, request.InvocationID, requestDigest, recoveryGeneration, service.now().UTC(),
					); heartbeatErr != nil {
						if workCtx.Err() != nil {
							recoveryHeartbeatDone <- nil
							return
						}
						cancelRecovery()
						recoveryHeartbeatDone <- heartbeatErr
						return
					}
				}
			}
		}()
		object, getErr := service.blobs.Get(workCtx, reservation.ObjectKey)
		switch {
		case getErr == nil:
			if object.Key != reservation.ObjectKey || object.Version == "" || object.Digest != reservation.ContentDigest ||
				int64(len(object.Data)) != reservation.Size || digestBytes(object.Data) != reservation.ContentDigest {
				return ArtifactRef{}, ErrStorageCorruption
			}
			blobReady = true
		case errors.Is(getErr, ErrBlobNotFound):
		default:
			return ArtifactRef{}, fmt.Errorf("reconcile inflight artifact bytes: %w", getErr)
		}
	}

	var file WorkspaceFile
	if !blobReady {
		readRequest := WorkspaceReadRequest{
			TenantID: request.Access.TenantID, WorkspaceID: request.Access.WorkspaceID,
			RevisionID: request.Source.RevisionID, Path: request.Source.Path,
			MaximumBytes: service.maximumArtifactBytes,
		}
		file, err = service.workspace.ReadFile(workCtx, readRequest)
		if err != nil {
			return ArtifactRef{}, fmt.Errorf("%w: read exact workspace snapshot: %v", ErrInvalidWorkspaceSource, err)
		}
		if file.TenantID != readRequest.TenantID || file.WorkspaceID != readRequest.WorkspaceID ||
			file.RevisionID != readRequest.RevisionID || file.Path != readRequest.Path || file.Kind != WorkspaceRegularFile ||
			file.Size < 0 || file.Size != int64(len(file.Data)) || file.Size > service.maximumArtifactBytes ||
			!validDigest(file.ContentDigest) || file.ContentDigest != digestBytes(file.Data) {
			return ArtifactRef{}, ErrInvalidWorkspaceSource
		}
		if err := validateWorkspacePath(file.Path); err != nil {
			return ArtifactRef{}, ErrInvalidWorkspaceSource
		}

		metadataDigest, digestErr := digestMetadata(metadata, file.ContentDigest, file.Size)
		if digestErr != nil {
			return ArtifactRef{}, fmt.Errorf("%w: encode artifact metadata: %v", ErrInvalidRequest, digestErr)
		}
		hexDigest := strings.TrimPrefix(file.ContentDigest, "sha256:")
		objectKey := request.Access.TenantID + "/sha256/" + hexDigest[:2] + "/" + hexDigest[2:4] + "/" + hexDigest
		if !found {
			artifactID, idErr := service.newArtifactID()
			if idErr != nil {
				return ArtifactRef{}, fmt.Errorf("generate artifact ID: %w", idErr)
			}
			if _, parseErr := identity.Parse(identity.Artifact, artifactID); parseErr != nil {
				return ArtifactRef{}, fmt.Errorf("%w: generated artifact ID: %v", ErrInvalidConfig, parseErr)
			}
			now := service.now().UTC()
			reservation, _, err = service.repository.BeginCreate(workCtx, CreateReservation{
				TenantID: request.Access.TenantID, SessionID: request.Access.SessionID,
				WorkspaceID: request.Access.WorkspaceID, InvocationID: request.InvocationID,
				RequestDigest: requestDigest, ArtifactID: artifactID, ObjectKey: objectKey,
				Size: file.Size, StartedAt: now, SourceRevisionID: request.Source.RevisionID,
				SourcePath: request.Source.Path, ContentDigest: file.ContentDigest,
				MetadataDigest: metadataDigest, Metadata: cloneMetadata(metadata),
			})
			if err != nil {
				return ArtifactRef{}, err
			}
			switch reservation.State {
			case InvocationAbandoned:
				return ArtifactRef{}, ErrInvocationAbandoned
			case InvocationCommitted:
				record, getErr := service.repository.GetArtifact(ctx, reservation.ArtifactID)
				if getErr != nil || !validArtifactRecord(record, service.maximumArtifactBytes) ||
					record.TenantID != request.Access.TenantID || record.InvocationID != request.InvocationID ||
					record.RequestDigest != requestDigest || record.ArtifactID != reservation.ArtifactID {
					return ArtifactRef{}, fmt.Errorf("%w: committed invocation has no artifact", ErrStorageCorruption)
				}
				return artifactRefFromRecord(record), nil
			case InvocationInflight:
			default:
				return ArtifactRef{}, ErrStorageCorruption
			}
		}
		if reservation.TenantID != request.Access.TenantID || reservation.SessionID != request.Access.SessionID ||
			reservation.WorkspaceID != request.Access.WorkspaceID || reservation.InvocationID != request.InvocationID ||
			reservation.RequestDigest != requestDigest || reservation.SourceRevisionID != request.Source.RevisionID ||
			reservation.SourcePath != request.Source.Path || reservation.ObjectKey != objectKey ||
			reservation.Size != file.Size || reservation.ContentDigest != file.ContentDigest ||
			reservation.MetadataDigest != metadataDigest || reservation.Generation == 0 {
			return ArtifactRef{}, fmt.Errorf("%w: immutable workspace revision changed during invocation replay", ErrInvalidWorkspaceSource)
		}
		reservation, err = service.repository.HeartbeatCreate(
			workCtx, request.InvocationID, requestDigest, reservation.Generation, service.now().UTC(),
		)
		if err != nil {
			return ArtifactRef{}, err
		}

		operationCtx, cancelOperation := context.WithCancel(workCtx)
		heartbeatDone := make(chan error, 1)
		go func() {
			ticker := time.NewTicker(service.inflightHeartbeatInterval)
			defer ticker.Stop()
			for {
				select {
				case <-operationCtx.Done():
					heartbeatDone <- nil
					return
				case <-ticker.C:
					if _, heartbeatErr := service.repository.HeartbeatCreate(
						operationCtx, request.InvocationID, requestDigest, reservation.Generation, service.now().UTC(),
					); heartbeatErr != nil {
						if operationCtx.Err() != nil {
							heartbeatDone <- nil
							return
						}
						cancelOperation()
						heartbeatDone <- heartbeatErr
						return
					}
				}
			}
		}()
		putErr := service.blobs.PutIfAbsent(operationCtx, BlobPut{
			Key: reservation.ObjectKey, Digest: reservation.ContentDigest,
			Data: append([]byte(nil), file.Data...), CreatedAt: reservation.StartedAt,
		})
		cancelOperation()
		heartbeatErr := <-heartbeatDone
		if heartbeatErr != nil {
			return ArtifactRef{}, fmt.Errorf("heartbeat artifact invocation: %w", heartbeatErr)
		}
		if putErr != nil {
			// The response can be uncertain after the object became durable. Keep the
			// invocation and quota reservation inflight so replay or GC can recover it.
			return ArtifactRef{}, fmt.Errorf("store artifact bytes: %w", putErr)
		}
		reservation, err = service.repository.HeartbeatCreate(
			workCtx, request.InvocationID, requestDigest, reservation.Generation, service.now().UTC(),
		)
		if err != nil {
			return ArtifactRef{}, err
		}
	}

	record, _, err := service.repository.CommitCreate(workCtx, CommitCreateRequest{
		InvocationID: request.InvocationID, RequestDigest: requestDigest, Generation: reservation.Generation,
		Artifact: ArtifactRecord{
			ArtifactID: reservation.ArtifactID, TenantID: reservation.TenantID,
			SessionID: reservation.SessionID, WorkspaceID: reservation.WorkspaceID,
			InvocationID: request.InvocationID, RequestDigest: requestDigest,
			SourceRevisionID: reservation.SourceRevisionID, SourcePath: reservation.SourcePath,
			ContentDigest: reservation.ContentDigest, MetadataDigest: reservation.MetadataDigest,
			ObjectKey: reservation.ObjectKey, Size: reservation.Size, Metadata: cloneMetadata(reservation.Metadata),
			CreatedAt: reservation.StartedAt, RetainUntil: reservation.StartedAt.Add(reservation.Metadata.RetainFor),
			State: ArtifactActive,
		},
	})
	if err != nil {
		return ArtifactRef{}, err
	}
	if !validArtifactRecord(record, service.maximumArtifactBytes) {
		return ArtifactRef{}, ErrStorageCorruption
	}
	return artifactRefFromRecord(record), nil
}

func (service *Service) Open(ctx context.Context, request OpenRequest) (OpenedArtifact, error) {
	if err := validateAccess(request.Access); err != nil {
		return OpenedArtifact{}, err
	}
	if _, err := identity.Parse(identity.Artifact, request.ArtifactID); err != nil {
		return OpenedArtifact{}, fmt.Errorf("%w: artifact ID: %v", ErrInvalidRequest, err)
	}
	record, err := service.repository.GetArtifact(ctx, request.ArtifactID)
	if err != nil {
		return OpenedArtifact{}, err
	}
	if record.TenantID != request.Access.TenantID {
		return OpenedArtifact{}, ErrAccessDenied
	}
	if !validArtifactRecord(record, service.maximumArtifactBytes) {
		return OpenedArtifact{}, ErrStorageCorruption
	}
	if err := service.authorizer.Authorize(ctx, AuthorizationRequest{
		Operation: OperationOpen, TenantID: request.Access.TenantID, SubjectID: request.Access.SubjectID,
		SessionID: request.Access.SessionID, WorkspaceID: request.Access.WorkspaceID,
		ResourceSessionID: record.SessionID, ResourceWorkspaceID: record.WorkspaceID, ArtifactID: record.ArtifactID,
	}); err != nil {
		return OpenedArtifact{}, fmt.Errorf("%w: open authorization failed", ErrAccessDenied)
	}
	if record.State != ArtifactActive || !service.now().UTC().Before(record.RetainUntil) {
		return OpenedArtifact{}, ErrArtifactUnavailable
	}
	if metadataDigest, digestErr := digestMetadata(record.Metadata, record.ContentDigest, record.Size); digestErr != nil || metadataDigest != record.MetadataDigest {
		return OpenedArtifact{}, ErrStorageCorruption
	}
	object, err := service.blobs.Get(ctx, record.ObjectKey)
	if err != nil {
		return OpenedArtifact{}, fmt.Errorf("%w: load artifact object", ErrStorageCorruption)
	}
	if object.Key != record.ObjectKey || object.Version == "" || object.Digest != record.ContentDigest || int64(len(object.Data)) != record.Size ||
		!validDigest(object.Digest) || digestBytes(object.Data) != object.Digest {
		return OpenedArtifact{}, ErrStorageCorruption
	}
	return OpenedArtifact{
		Ref: artifactRefFromRecord(record), Metadata: cloneMetadata(record.Metadata),
		Data: append([]byte(nil), object.Data...),
	}, nil
}

func (service *Service) Delete(ctx context.Context, request DeleteRequest) error {
	if err := validateAccess(request.Access); err != nil {
		return err
	}
	if _, err := identity.Parse(identity.Artifact, request.ArtifactID); err != nil {
		return fmt.Errorf("%w: artifact ID: %v", ErrInvalidRequest, err)
	}
	record, err := service.repository.GetArtifact(ctx, request.ArtifactID)
	if err != nil {
		return err
	}
	if record.TenantID != request.Access.TenantID {
		return ErrAccessDenied
	}
	if !validArtifactRecord(record, service.maximumArtifactBytes) {
		return ErrStorageCorruption
	}
	if err := service.authorizer.Authorize(ctx, AuthorizationRequest{
		Operation: OperationDelete, TenantID: request.Access.TenantID, SubjectID: request.Access.SubjectID,
		SessionID: request.Access.SessionID, WorkspaceID: request.Access.WorkspaceID,
		ResourceSessionID: record.SessionID, ResourceWorkspaceID: record.WorkspaceID, ArtifactID: record.ArtifactID,
	}); err != nil {
		return fmt.Errorf("%w: delete authorization failed", ErrAccessDenied)
	}
	_, _, err = service.repository.TombstoneArtifact(ctx, request.ArtifactID, request.Access.TenantID, service.now().UTC())
	return err
}

func (service *Service) CollectGarbage(ctx context.Context) (GCResult, error) {
	now := service.now().UTC()
	result := GCResult{}
	lease, acquired, err := service.repository.AcquireGC(ctx, now, service.gcLeaseDuration)
	if err != nil {
		return result, err
	}
	if !acquired {
		return result, ErrGCInProgress
	}
	checkpoint := lease.Checkpoint
	operationCtx, cancelOperation := context.WithCancel(ctx)
	heartbeatDone := make(chan error, 1)
	go func() {
		interval := service.gcLeaseDuration / 3
		if interval <= 0 {
			interval = time.Nanosecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-operationCtx.Done():
				heartbeatDone <- nil
				return
			case <-ticker.C:
				if _, renewErr := service.repository.RenewGC(
					operationCtx, lease, service.now().UTC(), service.gcLeaseDuration,
				); renewErr != nil {
					if operationCtx.Err() != nil {
						heartbeatDone <- nil
						return
					}
					cancelOperation()
					heartbeatDone <- renewErr
					return
				}
			}
		}
	}()

	var workErrors []error
	count, next, done, scanErr := service.repository.TombstoneExpiredPage(
		operationCtx, lease, now, checkpoint.ExpiredCursor, service.gcBatchSize,
	)
	if scanErr != nil {
		workErrors = append(workErrors, scanErr)
	} else {
		result.ExpiredArtifacts = count
		if done {
			checkpoint.ExpiredCursor = ""
		} else {
			checkpoint.ExpiredCursor = next
		}
	}
	if len(workErrors) == 0 {
		count, next, done, scanErr = service.repository.AbandonInflightPage(
			operationCtx, lease, now.Add(-service.inflightTimeout), checkpoint.InflightCursor, service.gcBatchSize,
		)
		if scanErr != nil {
			workErrors = append(workErrors, scanErr)
		} else {
			result.AbandonedInvocations = count
			if done {
				checkpoint.InflightCursor = ""
			} else {
				checkpoint.InflightCursor = next
			}
		}
	}

	claims := []SweepClaim{}
	unresolvedSweep := false
	if len(workErrors) == 0 {
		pending, sweepNext, sweepDone, pendingErr := service.repository.PendingSweepsPage(
			operationCtx, lease, checkpoint.SweepCursor, service.gcBatchSize,
		)
		if pendingErr != nil {
			workErrors = append(workErrors, pendingErr)
		} else {
			claims = append(claims, pending...)
			if sweepDone {
				checkpoint.SweepCursor = ""
			} else {
				checkpoint.SweepCursor = sweepNext
			}
		}
	}

	remaining := service.gcBatchSize - len(claims)
	if len(workErrors) == 0 && remaining > 0 {
		page, listErr := service.blobs.ListPage(operationCtx, BlobListRequest{
			Epoch: checkpoint.BlobEpoch, Cursor: checkpoint.BlobCursor, Limit: remaining,
		})
		if listErr != nil {
			workErrors = append(workErrors, listErr)
		} else if page.Epoch == "" || (checkpoint.BlobEpoch != "" && page.Epoch != checkpoint.BlobEpoch) ||
			len(page.Objects) > remaining || (page.Done && page.NextCursor != "") ||
			(!page.Done && (page.NextCursor == "" || page.NextCursor == checkpoint.BlobCursor)) {
			workErrors = append(workErrors, ErrStorageCorruption)
		} else {
			if page.Done {
				checkpoint.BlobEpoch = ""
				checkpoint.BlobCursor = ""
			} else {
				checkpoint.BlobEpoch = page.Epoch
				checkpoint.BlobCursor = page.NextCursor
			}
			cutoff := now.Add(-service.gcGrace)
			for _, object := range page.Objects {
				if object.Key == "" || object.Version == "" || !validDigest(object.Digest) || object.Size < 0 || object.CreatedAt.IsZero() {
					workErrors = append(workErrors, ErrStorageCorruption)
					continue
				}
				if object.CreatedAt.After(cutoff) {
					continue
				}
				claim, claimed, claimErr := service.repository.ClaimSweepLeased(
					operationCtx, lease, object.Key, object.Version, cutoff,
				)
				if claimErr != nil {
					workErrors = append(workErrors, claimErr)
					continue
				}
				if claimed {
					claims = append(claims, claim)
				}
			}
		}
	}

	for _, claim := range claims {
		head, headErr := service.blobs.Head(operationCtx, claim.ObjectKey)
		deleted := errors.Is(headErr, ErrBlobNotFound)
		if headErr != nil && !deleted {
			unresolvedSweep = true
			workErrors = append(workErrors, fmt.Errorf("reconcile artifact object %q: %w", claim.ObjectKey, headErr))
			continue
		}
		if !deleted {
			if claim.ObjectVersion == "" || head.Key != claim.ObjectKey || head.Version == "" ||
				!validDigest(head.Digest) || head.Size < 0 || head.CreatedAt.IsZero() {
				unresolvedSweep = true
				workErrors = append(workErrors, fmt.Errorf("%w: blob changed during sweep", ErrStorageCorruption))
				continue
			}
			if head.Version != claim.ObjectVersion {
				if retireErr := service.repository.RetireSweepLeased(operationCtx, lease, claim); retireErr != nil {
					unresolvedSweep = true
					workErrors = append(workErrors, retireErr)
				}
				continue
			}
			deleteErr := service.blobs.DeleteIfVersion(operationCtx, claim.ObjectKey, claim.ObjectVersion)
			deleted = deleteErr == nil || errors.Is(deleteErr, ErrBlobNotFound)
			if errors.Is(deleteErr, ErrBlobVersionConflict) {
				if retireErr := service.repository.RetireSweepLeased(operationCtx, lease, claim); retireErr != nil {
					unresolvedSweep = true
					workErrors = append(workErrors, retireErr)
				}
				continue
			}
			if !deleted {
				// Any error after dispatch is uncertain. Keep the durable claim so
				// BeginCreate remains fenced until a later linearizable Head resolves it.
				unresolvedSweep = true
				workErrors = append(workErrors, fmt.Errorf("delete artifact object %q: %w", claim.ObjectKey, deleteErr))
				continue
			}
		}
		purged, finishErr := service.repository.FinishSweepLeased(operationCtx, lease, claim, true, now)
		if finishErr != nil {
			unresolvedSweep = true
			workErrors = append(workErrors, finishErr)
			continue
		}
		result.DeletedObjects++
		result.PurgedArtifacts += purged
	}
	if unresolvedSweep {
		// A failed claim can sort before the persisted cursor, including a claim
		// created from the current blob page. Restart the bounded pending scan so
		// continuous arrivals cannot strand its object fence indefinitely.
		checkpoint.SweepCursor = ""
	}

	cancelOperation()
	heartbeatErr := <-heartbeatDone
	if heartbeatErr != nil {
		workErrors = append(workErrors, heartbeatErr)
	}
	if releaseErr := service.repository.ReleaseGC(ctx, lease, checkpoint); releaseErr != nil {
		workErrors = append(workErrors, releaseErr)
	}
	return result, errors.Join(workErrors...)
}

func validateAccess(access AccessContext) error {
	fields := []struct {
		kind  identity.Kind
		value string
	}{
		{kind: identity.Tenant, value: access.TenantID},
		{kind: identity.Subject, value: access.SubjectID},
		{kind: identity.Session, value: access.SessionID},
		{kind: identity.Workspace, value: access.WorkspaceID},
	}
	for _, field := range fields {
		if _, err := identity.Parse(field.kind, field.value); err != nil {
			return fmt.Errorf("%w: access scope: %v", ErrInvalidRequest, err)
		}
	}
	return nil
}

func validateWorkspacePath(value string) error {
	if value == "" || !utf8.ValidString(value) || norm.NFC.String(value) != value || strings.HasPrefix(value, "/") || len(value) > maximumWorkspacePathBytes {
		return fmt.Errorf("%w: source path is not canonical", ErrInvalidRequest)
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." || len(component) > maximumWorkspaceComponentBytes {
			return fmt.Errorf("%w: source path is not canonical", ErrInvalidRequest)
		}
		for _, character := range component {
			if unicode.IsControl(character) {
				return fmt.Errorf("%w: source path contains control characters", ErrInvalidRequest)
			}
		}
	}
	return nil
}

func digestMetadata(metadata Metadata, contentDigest string, size int64) (string, error) {
	attributes := canonical.Map{}
	for key, value := range metadata.Attributes {
		attributes[key] = value
	}
	return canonical.StructuredDigest("artifact.metadata", 1, canonical.Map{
		"name": metadata.Name, "mediaType": metadata.MediaType,
		"retainForNanoseconds": metadata.RetainFor.Nanoseconds(), "attributes": attributes,
		"contentDigest": contentDigest, "size": size,
	})
}

func validArtifactRecord(record ArtifactRecord, maximumBytes int64) bool {
	if _, err := identity.Parse(identity.Artifact, record.ArtifactID); err != nil {
		return false
	}
	for kind, value := range map[identity.Kind]string{
		identity.Tenant: record.TenantID, identity.Session: record.SessionID,
		identity.Workspace: record.WorkspaceID, identity.Invocation: record.InvocationID,
	} {
		if _, err := identity.Parse(kind, value); err != nil {
			return false
		}
	}
	if !validDigest(record.RequestDigest) || !validDigest(record.SourceRevisionID) ||
		!validDigest(record.ContentDigest) || !validDigest(record.MetadataDigest) ||
		record.Size < 0 || record.Size > maximumBytes || record.CreatedAt.IsZero() ||
		!record.RetainUntil.After(record.CreatedAt) || record.RetainUntil.Sub(record.CreatedAt) != record.Metadata.RetainFor {
		return false
	}
	if err := validateWorkspacePath(record.SourcePath); err != nil {
		return false
	}
	hexDigest := strings.TrimPrefix(record.ContentDigest, "sha256:")
	if record.ObjectKey != record.TenantID+"/sha256/"+hexDigest[:2]+"/"+hexDigest[2:4]+"/"+hexDigest {
		return false
	}
	metadataDigest, err := digestMetadata(record.Metadata, record.ContentDigest, record.Size)
	if err != nil || metadataDigest != record.MetadataDigest {
		return false
	}
	switch record.State {
	case ArtifactActive:
		return record.TombstonedAt == nil && record.PurgedAt == nil
	case ArtifactTombstoned:
		return record.TombstonedAt != nil && record.PurgedAt == nil
	case ArtifactPurged:
		return record.TombstonedAt != nil && record.PurgedAt != nil && !record.PurgedAt.Before(*record.TombstonedAt)
	default:
		return false
	}
}

func artifactRefFromRecord(record ArtifactRecord) ArtifactRef {
	return ArtifactRef{
		ArtifactID: record.ArtifactID, ContentDigest: record.ContentDigest,
		MetadataDigest: record.MetadataDigest, ObjectKey: record.ObjectKey, Size: record.Size,
		CreatedAt: record.CreatedAt, RetainUntil: record.RetainUntil,
	}
}

func cloneMetadata(metadata Metadata) Metadata {
	copy := metadata
	copy.Attributes = make(map[string]string, len(metadata.Attributes))
	for key, value := range metadata.Attributes {
		copy.Attributes[key] = value
	}
	return copy
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}
