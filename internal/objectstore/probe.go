package objectstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/hancomac/circulusd/internal/conformance"
)

type ProbeConfig struct {
	Component      string
	Mock           bool
	Random         io.Reader
	Open           func(context.Context) (Store, error)
	CleanupTimeout time.Duration
	Observe        func(ProbeObservation)
}

type ProbeObservation struct {
	Stage      string `json:"stage"`
	Passed     bool   `json:"passed"`
	Contenders int    `json:"contenders,omitempty"`
	Winners    int    `json:"winners,omitempty"`
	Losers     int    `json:"losers,omitempty"`
}

// An ETag is an opaque concurrency token. FileStore separately requires its
// sha256 content tokens; remote providers may return quoted native ETags.
func validOpaqueETag(etag ETag) bool {
	if len(etag) == 0 || len(etag) > 1024 || etag == "*" || strings.HasPrefix(string(etag), "W/") {
		return false
	}
	for _, c := range etag {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
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
		if config.Observe != nil {
			config.Observe(ProbeObservation{Stage: stage})
		}
		reason := stage
		if err != nil {
			reason += ": " + err.Error()
		}
		status := conformance.Fail
		if errors.Is(err, ErrUnavailable) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			status = conformance.Unavailable
		}
		return conformance.Result{Component: component, Status: status, Reason: reason, Evidence: evidence}
	}
	if config.Open == nil {
		return failed("restart-capable store opener is required", nil)
	}
	cleanupTimeout := config.CleanupTimeout
	if cleanupTimeout == 0 {
		cleanupTimeout = 5 * time.Second
	}
	if cleanupTimeout < 0 || cleanupTimeout > 30*time.Second {
		return failed("invalid cleanup deadline", nil)
	}
	observed := func(stage string) {
		if config.Observe != nil {
			config.Observe(ProbeObservation{Stage: stage, Passed: true})
		}
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
	clients := []Store{store}
	initialData := append([]byte("circulusd-cas-probe-v1:"), nonce[:]...)
	secondData := append([]byte("circulusd-cas-probe-v2:"), nonce[:]...)
	ownedData := map[string]bool{string(initialData): true, string(secondData): true}
	for contender := range 32 {
		ownedData[fmt.Sprintf("circulusd-cas-winner-%02d:%x", contender, nonce)] = true
	}
	finish := func(result conformance.Result) conformance.Result {
		defer func() {
			for _, client := range clients {
				if closer, ok := client.(io.Closer); ok {
					_ = closer.Close()
				}
			}
		}()
		if !created {
			return result
		}
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cancel()
		object, err := store.Get(cleanupContext, BucketCelldState, key)
		if errors.Is(err, ErrNotFound) {
			return result
		}
		if err == nil && !ownedData[string(object.Data)] {
			err = errors.New("isolated probe object was replaced; cleanup refused")
		}
		if err == nil {
			err = store.DeleteIfMatch(cleanupContext, BucketCelldState, key, object.ETag)
		}
		if err == nil {
			_, readErr := store.Get(cleanupContext, BucketCelldState, key)
			if !errors.Is(readErr, ErrNotFound) {
				err = readErr
				if err == nil {
					err = errors.New("conditional cleanup did not remove isolated object")
				}
			}
		}
		if err != nil {
			if result.Status == conformance.Pass {
				return failed("clean probe object", err)
			}
			result.Reason += "; cleanup failed: " + err.Error()
		}
		if err == nil {
			observed("conditional cleanup")
		}
		return result
	}

	// A transport error may arrive after the conditional create became durable.
	// From this point onward cleanup must therefore probe for the object even
	// when PutIfAbsent reports an error.
	created = true
	initialETag, err := store.PutIfAbsent(ctx, BucketCelldState, key, initialData)
	if err != nil {
		if errors.Is(err, ErrPreconditionFailed) {
			created = false
		}
		return finish(failed("conditional object creation", err))
	}
	if !validOpaqueETag(initialETag) {
		return finish(failed("conditional object creation returned an invalid ETag", nil))
	}
	observed("conditional create")
	initialObject, err := store.Get(ctx, BucketCelldState, key)
	if err != nil || initialObject.ETag != initialETag || !bytes.Equal(initialObject.Data, initialData) {
		return finish(failed("read object after creation", err))
	}
	observed("read after create")

	secondETag, err := store.CompareAndSwap(ctx, BucketCelldState, key, initialETag, secondData)
	if err != nil {
		return finish(failed("conditional update with the current ETag", err))
	}
	if !validOpaqueETag(secondETag) || secondETag == initialETag {
		return finish(failed("conditional update returned an invalid or unchanged ETag", nil))
	}
	observed("conditional update")
	if _, err := store.CompareAndSwap(ctx, BucketCelldState, key, initialETag, []byte("stale-write")); !errors.Is(err, ErrPreconditionFailed) {
		return finish(failed("stale ETag update was not rejected", err))
	}
	observed("stale update rejected")
	if _, err := store.PutIfAbsent(ctx, BucketCelldState, key, []byte("duplicate-create")); !errors.Is(err, ErrPreconditionFailed) {
		return finish(failed("If-None-Match collision was not rejected", err))
	}
	observed("duplicate create rejected")
	secondObject, err := store.Get(ctx, BucketCelldState, key)
	if err != nil || secondObject.ETag != secondETag || !bytes.Equal(secondObject.Data, secondData) {
		return finish(failed("read object after conditional update", err))
	}
	observed("read after update")
	if err := store.DeleteIfMatch(ctx, BucketCelldState, key, initialETag); !errors.Is(err, ErrPreconditionFailed) {
		return finish(failed("stale ETag delete was not rejected", err))
	}
	observed("stale delete rejected")

	const contenders = 32
	type attempt struct {
		etag ETag
		err  error
		data []byte
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
			attempts <- attempt{etag: etag, err: err, data: data}
		}()
	}
	close(start)
	wait.Wait()
	close(attempts)
	winners := 0
	losers := 0
	var winner attempt
	for attempt := range attempts {
		switch {
		case attempt.err == nil && validOpaqueETag(attempt.etag) && attempt.etag != secondETag:
			winners++
			winner = attempt
		case errors.Is(attempt.err, ErrPreconditionFailed):
			losers++
		default:
			return finish(failed("concurrent conditional update returned an invalid result", attempt.err))
		}
	}
	if winners != 1 || losers != contenders-1 {
		return finish(failed(fmt.Sprintf("concurrent CAS had %d winners and %d losers", winners, losers), nil))
	}
	if config.Observe != nil {
		config.Observe(ProbeObservation{Stage: "single concurrent winner", Passed: true, Contenders: contenders, Winners: winners, Losers: losers})
	}
	beforeRestart, err := store.Get(ctx, BucketCelldState, key)
	if err != nil || beforeRestart.ETag != winner.etag || !bytes.Equal(beforeRestart.Data, winner.data) {
		return finish(failed("read concurrent CAS winner", err))
	}
	observed("read concurrent winner")

	restarted, err := config.Open(ctx)
	if err != nil {
		return finish(failed("reopen object store for persistence check", err))
	}
	if restarted == nil {
		return finish(failed("reopened object store is nil", nil))
	}
	clients = append(clients, restarted)
	store = restarted
	afterRestart, err := store.Get(ctx, BucketCelldState, key)
	if err != nil || afterRestart.ETag != beforeRestart.ETag || !bytes.Equal(afterRestart.Data, beforeRestart.Data) {
		return finish(failed("restart persistence/read-after-write check", err))
	}
	observed("fresh client persistence")
	return finish(conformance.Result{Component: component, Status: conformance.Pass, Evidence: evidence})
}
