// Package providerresult connects committed, immutable provider results to the
// Session broker. It contains no provider invocation or effect state machine.
package providerresult

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/stateappbroker"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

type Reader interface {
	ReadProviderResult(context.Context, stateappclient.ProviderResultRequest) (stateappclient.ProviderResult, error)
	dependency.ProductionProbe
}

type Resolver struct {
	reader  Reader
	binding dependency.Verified[Reader]
}

// New retains only an independently qualified operational reader. The caller
// must challenge the resulting Resolver separately before passing it to Store.
func New(binding dependency.Verified[Reader]) (*Resolver, error) {
	reader, descriptor, err := binding.Open()
	if err != nil || nilInterface(reader) || !slices.Contains(descriptor.AtomicGroups, dependency.AtomicEffectLifecycle) {
		return nil, dependency.ErrUnverifiedDependency
	}
	return &Resolver{reader: reader, binding: binding}, nil
}

func (resolver *Resolver) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	if resolver == nil || nilInterface(resolver.reader) {
		return dependency.ProbeResponse{}, dependency.ErrUnverifiedDependency
	}
	if _, _, err := resolver.binding.Open(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	return resolver.reader.ProbeProduction(ctx, challenge)
}

func (resolver *Resolver) ResolveResult(ctx context.Context, request stateappbroker.ResultRequest) (stateappbroker.Result, error) {
	if ctx == nil {
		return stateappbroker.Result{}, broker.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return stateappbroker.Result{}, err
	}
	if resolver == nil || nilInterface(resolver.reader) {
		return stateappbroker.Result{}, dependency.ErrUnverifiedDependency
	}
	wire := requestWire(request)
	if err := stateappclient.ValidateProviderResultRequest(wire); err != nil {
		return stateappbroker.Result{}, broker.ErrInvalidRequest
	}
	result, err := resolver.reader.ReadProviderResult(ctx, wire)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return stateappbroker.Result{}, contextErr
		}
		// A qualified interface still must not leak implementation diagnostics.
		// Preserve fixed lifecycle/error classes, never arbitrary error text.
		for _, safe := range []error{context.Canceled, context.DeadlineExceeded,
			stateappclient.ErrClientClosed, stateappclient.ErrInvalidConfig, stateappclient.ErrInvalidRequest,
			stateappclient.ErrUnauthenticatedResponse, stateappclient.ErrInvalidResponse, stateappclient.ErrRemote} {
			if errors.Is(err, safe) {
				return stateappbroker.Result{}, safe
			}
		}
		return stateappbroker.Result{}, stateappclient.ErrTransport
	}
	if err := ctx.Err(); err != nil {
		return stateappbroker.Result{}, err
	}
	if result.Request != wire {
		return stateappbroker.Result{}, broker.ErrFenceMismatch
	}
	if len(result.CanonicalCBOR) < 1 || len(result.CanonicalCBOR) > stateappclient.MaximumProviderResultBytes {
		return stateappbroker.Result{}, stateappclient.ErrInvalidResponse
	}
	body := bytes.Clone(result.CanonicalCBOR)
	digest := sha256.Sum256(body)
	if !validBody(body) || result.PayloadDigest != fmt.Sprintf("sha256:%x", digest) {
		return stateappbroker.Result{}, stateappclient.ErrInvalidResponse
	}
	return stateappbroker.Result{Request: request, PayloadDigest: broker.Digest(digest), CanonicalCBOR: body}, nil
}

func requestWire(request stateappbroker.ResultRequest) stateappclient.ProviderResultRequest {
	return stateappclient.ProviderResultRequest{TenantID: request.TenantID.String(), WorkspaceID: request.WorkspaceID.String(),
		SessionID: request.SessionID.String(), EffectID: request.EffectID.String(), InvocationID: request.InvocationID.String(),
		RequestDigest: fmt.Sprintf("sha256:%x", request.RequestDigest), ExternalCommitID: request.ExternalCommitID.String(), ResultRef: request.ResultRef.String()}
}

func validBody(body []byte) bool {
	if len(body) < 1 || len(body) > stateappclient.MaximumProviderResultBytes {
		return false
	}
	_, err := canonical.Decode(body, canonical.Options{MaxBytes: stateappclient.MaximumProviderResultBytes, MaxDepth: 64, MaxItems: 100_000})
	return err == nil
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

var _ stateappbroker.ResultResolver = (*Resolver)(nil)
