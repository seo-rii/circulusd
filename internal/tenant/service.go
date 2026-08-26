package tenant

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/hancomac/circulusd/internal/identity"
)

func NewService(configuration ServiceConfig) (*Service, error) {
	if configuration.Repository == nil {
		return nil, fmt.Errorf("%w: repository is required", ErrInvalidConfiguration)
	}
	repositoryValue := reflect.ValueOf(configuration.Repository)
	switch repositoryValue.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if repositoryValue.IsNil() {
			return nil, fmt.Errorf("%w: repository is required", ErrInvalidConfiguration)
		}
	}
	if configuration.Lifecycle == nil {
		return nil, fmt.Errorf("%w: lifecycle verifier is required", ErrInvalidConfiguration)
	}
	lifecycleValue := reflect.ValueOf(configuration.Lifecycle)
	switch lifecycleValue.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if lifecycleValue.IsNil() {
			return nil, fmt.Errorf("%w: lifecycle verifier is required", ErrInvalidConfiguration)
		}
	}

	durability := configuration.Repository.Durability()
	durable := durability.CrashDurable && durability.AtomicExpectedVersionCAS && durability.AtomicMutationReceipt
	if !durable {
		_, memoryRepository := configuration.Repository.(*MemoryRepository)
		if !configuration.AllowReferenceMemory || !memoryRepository {
			return nil, ErrRepositoryNotDurable
		}
	}

	return &Service{
		repository: configuration.Repository,
		lifecycle:  configuration.Lifecycle,
		reference:  !durable,
	}, nil
}

// Release refunds a consumed live-resource reservation only after the owning
// lifecycle journal proves destruction of the exact bound incarnation. A
// merely reserved allocation can be cancelled directly with Repository.Release
// and does not pass through this proof-bearing path.
func (service *Service) Release(ctx context.Context, request ReleaseRequest) (Receipt, error) {
	if service == nil || service.repository == nil || service.lifecycle == nil {
		return Receipt{}, fmt.Errorf("%w: service is not initialized", ErrInvalidConfiguration)
	}
	if err := validateMutationHeader(request.OperationID, request.ExpectedVersion); err != nil {
		return Receipt{}, err
	}
	if !validID(request.ReservationID, identity.Operation) || request.ReservationVersion == 0 {
		return Receipt{}, fmt.Errorf("%w: reservation identity or version is invalid", ErrInvalidRequest)
	}
	authorization := AuthorizationRequest{Principal: request.Principal, Resource: request.Resource, Action: request.Action}
	if err := validateAuthorizationRequest(authorization); err != nil {
		return Receipt{}, err
	}
	if !actionRequiresTeardown(request.Action) || !validResourceInstance(request.Instance) {
		return Receipt{}, fmt.Errorf("%w: release requires a live resource instance", ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	// Authorize before consulting the lifecycle owner. Besides reducing the
	// confused-deputy surface, this prevents unauthorized callers from using
	// teardown verification as a cross-tenant resource-existence oracle. The
	// repository repeats authorization inside the release CAS to close races.
	if _, err := service.repository.Authorize(ctx, authorization); err != nil {
		return Receipt{}, err
	}
	// Recover before asking the lifecycle owner again. The release mutation and
	// receipt share one durable transaction, so an exact replay (including a
	// response-lost retry) can complete while the resource owner is offline.
	recovery, err := service.repository.Recover(ctx, RecoveryRequest{
		OperationID: request.OperationID,
		Principal:   request.Principal,
		Resource:    request.Resource,
		Action:      request.Action,
	})
	switch {
	case err == nil:
		receipt := recovery.Receipt
		if receipt.OperationID != request.OperationID || receipt.Kind != OperationRelease ||
			receipt.SubjectID != request.Principal.SubjectID || receipt.TenantID != request.Resource.TenantID ||
			receipt.WorkspaceID != request.Resource.WorkspaceID || receipt.Action != request.Action ||
			receipt.ReservationID != request.ReservationID || receipt.ReservationVersion != request.ReservationVersion ||
			receipt.Instance != request.Instance {
			return Receipt{}, ErrOperationConflict
		}
		if receipt.State != ReservationReleased || recovery.CurrentState != ReservationReleased ||
			len(receipt.TeardownProofDigest) != len("sha256:")+64 ||
			!strings.HasPrefix(receipt.TeardownProofDigest, "sha256:") {
			return Receipt{}, ErrTeardownUnproven
		}
		for _, character := range receipt.TeardownProofDigest[len("sha256:"):] {
			if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
				return Receipt{}, ErrTeardownUnproven
			}
		}
		if !service.reference && !receipt.Durable {
			return Receipt{}, ErrRepositoryNotDurable
		}
		return receipt, nil
	case !errors.Is(err, ErrReceiptNotFound):
		return Receipt{}, err
	}

	verification := TeardownVerificationRequest{
		ReleaseOperationID: request.OperationID,
		ReservationID:      request.ReservationID,
		ReservationVersion: request.ReservationVersion,
		TenantID:           request.Resource.TenantID,
		WorkspaceID:        request.Resource.WorkspaceID,
		Action:             request.Action,
		Instance:           request.Instance,
	}
	proof, err := service.lifecycle.VerifyTeardown(ctx, verification)
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return Receipt{}, contextError
		}
		return Receipt{}, ErrTeardownUnproven
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if proof.ReleaseOperationID != verification.ReleaseOperationID ||
		proof.ReservationID != verification.ReservationID ||
		proof.ReservationVersion != verification.ReservationVersion ||
		proof.TenantID != verification.TenantID ||
		proof.WorkspaceID != verification.WorkspaceID ||
		proof.Action != verification.Action || proof.Instance != verification.Instance ||
		proof.State != LifecycleDestroyed || proof.LifecycleGeneration != verification.Instance.Generation ||
		!proof.Durable || proof.Sequence == 0 || len(proof.ProofDigest) != len("sha256:")+64 ||
		!strings.HasPrefix(proof.ProofDigest, "sha256:") {
		return Receipt{}, ErrTeardownUnproven
	}
	for _, character := range proof.ProofDigest[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return Receipt{}, ErrTeardownUnproven
		}
	}

	transition := TransitionRequest{
		OperationID: request.OperationID, ExpectedVersion: request.ExpectedVersion,
		ReservationID: request.ReservationID, Principal: request.Principal,
		Resource: request.Resource, Action: request.Action,
		releaseBinding: &releaseBinding{
			reservationVersion: request.ReservationVersion,
			instance:           request.Instance,
		},
		teardownPermit: &teardownPermit{receipt: proof},
	}
	receipt, err := service.repository.Release(ctx, transition)
	if err != nil {
		return Receipt{}, err
	}
	if receipt.State != ReservationReleased || receipt.ReservationID != request.ReservationID ||
		receipt.ReservationVersion != request.ReservationVersion || receipt.Instance != request.Instance ||
		receipt.TeardownProofDigest != proof.ProofDigest {
		return Receipt{}, ErrTeardownUnproven
	}
	if !service.reference && !receipt.Durable {
		return Receipt{}, ErrRepositoryNotDurable
	}
	return receipt, nil
}
