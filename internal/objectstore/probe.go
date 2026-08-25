package objectstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/hancomac/circulusd/internal/conformance"
)

type ProbeConfig struct {
	Component string
	Mock      bool
	Random    io.Reader
	Open      func(context.Context) (Store, error)
}

// ProbeCAS exercises the complete state-plane object-store admission gate. A
// PASS means the configured endpoint demonstrated conditional create, ETag
// CAS, read-after-write, a single concurrent winner, and persistence through a
// newly opened client. It does not infer capabilities from an S3 version string.
func ProbeCAS(ctx context.Context, config ProbeConfig) conformance.Result {
	evidence := conformance.Evidence{Mock: config.Mock}
	component := config.Component
	validator := conformance.NewCollector()
	if err := validator.Add(conformance.Result{Component: component, Status: conformance.NotRun}); err != nil {
		return conformance.Result{Component: "object-store/cas", Status: conformance.Fail, Reason: "invalid probe component", Evidence: evidence}
	}
	failed := func(stage string, err error) conformance.Result {
		reason := stage
		if err != nil {
			reason += ": " + err.Error()
		}
		return conformance.Result{Component: component, Status: conformance.Fail, Reason: reason, Evidence: evidence}
	}
	if config.Open == nil {
		return failed("restart-capable store opener is required", nil)
	}
	random := config.Random
	if random == nil {
		random = rand.Reader
	}
	var nonce [16]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return failed("generate isolated probe key", err)
	}
	key := ".doctor/cas-" + hex.EncodeToString(nonce[:])
	store, err := config.Open(ctx)
	if err != nil {
		return failed("open object store", err)
	}
	if store == nil {
		return failed("open object store returned nil", nil)
	}
	created := false
	finish := func(result conformance.Result) conformance.Result {
		if !created {
			return result
		}
		cleanupContext := context.WithoutCancel(ctx)
		object, err := store.Get(cleanupContext, BucketCelldState, key)
		if errors.Is(err, ErrNotFound) {
			return result
		}
		if err == nil {
			err = store.DeleteIfMatch(cleanupContext, BucketCelldState, key, object.ETag)
		}
		if err != nil {
			if result.Status == conformance.Pass {
				return failed("clean probe object", err)
			}
			result.Reason += "; cleanup failed: " + err.Error()
		}
		return result
	}

	initialData := append([]byte("circulusd-cas-probe-v1:"), nonce[:]...)
	// A transport error may arrive after the conditional create became durable.
	// From this point onward cleanup must therefore probe for the object even
	// when PutIfAbsent reports an error.
	created = true
	initialETag, err := store.PutIfAbsent(ctx, BucketCelldState, key, initialData)
	if err != nil {
		return finish(failed("conditional object creation", err))
	}
	if initialETag != ETagFor(initialData) {
		return finish(failed("conditional object creation returned a non-content ETag", nil))
	}
	initialObject, err := store.Get(ctx, BucketCelldState, key)
	if err != nil || initialObject.ETag != initialETag || !bytes.Equal(initialObject.Data, initialData) {
		return finish(failed("read object after creation", err))
	}

	secondData := append([]byte("circulusd-cas-probe-v2:"), nonce[:]...)
	secondETag, err := store.CompareAndSwap(ctx, BucketCelldState, key, initialETag, secondData)
	if err != nil {
		return finish(failed("conditional update with the current ETag", err))
	}
	if secondETag != ETagFor(secondData) {
		return finish(failed("conditional update returned a non-content ETag", nil))
	}
	if _, err := store.CompareAndSwap(ctx, BucketCelldState, key, initialETag, []byte("stale-write")); !errors.Is(err, ErrPreconditionFailed) {
		return finish(failed("stale ETag update was not rejected", err))
	}
	if _, err := store.PutIfAbsent(ctx, BucketCelldState, key, []byte("duplicate-create")); !errors.Is(err, ErrPreconditionFailed) {
		return finish(failed("If-None-Match collision was not rejected", err))
	}
	secondObject, err := store.Get(ctx, BucketCelldState, key)
	if err != nil || secondObject.ETag != secondETag || !bytes.Equal(secondObject.Data, secondData) {
		return finish(failed("read object after conditional update", err))
	}

	const contenders = 32
	type attempt struct {
		etag ETag
		err  error
	}
	start := make(chan struct{})
	attempts := make(chan attempt, contenders)
	var wait sync.WaitGroup
	for contender := range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			data := []byte(fmt.Sprintf("circulusd-cas-winner-%02d:%x", contender, nonce))
			etag, err := store.CompareAndSwap(ctx, BucketCelldState, key, secondETag, data)
			attempts <- attempt{etag: etag, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(attempts)
	winners := 0
	losers := 0
	for attempt := range attempts {
		switch {
		case attempt.err == nil && validETag(attempt.etag):
			winners++
		case errors.Is(attempt.err, ErrPreconditionFailed):
			losers++
		default:
			return finish(failed("concurrent conditional update returned an invalid result", attempt.err))
		}
	}
	if winners != 1 || losers != contenders-1 {
		return finish(failed(fmt.Sprintf("concurrent CAS had %d winners and %d losers", winners, losers), nil))
	}
	beforeRestart, err := store.Get(ctx, BucketCelldState, key)
	if err != nil {
		return finish(failed("read concurrent CAS winner", err))
	}

	restarted, err := config.Open(ctx)
	if err != nil {
		return finish(failed("reopen object store for persistence check", err))
	}
	if restarted == nil {
		return finish(failed("reopened object store is nil", nil))
	}
	store = restarted
	afterRestart, err := store.Get(ctx, BucketCelldState, key)
	if err != nil || afterRestart.ETag != beforeRestart.ETag || !bytes.Equal(afterRestart.Data, beforeRestart.Data) {
		return finish(failed("restart persistence/read-after-write check", err))
	}
	return finish(conformance.Result{Component: component, Status: conformance.Pass, Evidence: evidence})
}
