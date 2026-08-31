// Package platformdaemon owns the common listener and runtime shutdown order
// shared by the separately composed production and development commands.
package platformdaemon

import (
	"context"
	"errors"
	"fmt"
	"reflect"
)

var ErrInvalidConfiguration = errors.New("platform daemon: invalid configuration")

// Server must make Serve return after Close. Close must be concurrency-safe and
// idempotent because cancellation can race a listener failure.
type Server interface {
	Serve(context.Context) error
	Close() error
}

// Runtime owns dependencies constructed before listeners bind. Close must be
// concurrency-safe and idempotent.
type Runtime interface {
	Close()
}

type serveResult struct {
	err error
}

// Serve owns every non-nil argument. Application is closed before the
// diagnostic control server, and the dependency runtime is always closed last.
func Serve(ctx context.Context, control Server, application Server, runtime Runtime) (result error) {
	controlNil := control == nil
	if !controlNil {
		value := reflect.ValueOf(control)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			controlNil = value.IsNil()
		}
	}
	applicationNil := application == nil
	if !applicationNil {
		value := reflect.ValueOf(application)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			applicationNil = value.IsNil()
		}
	}
	runtimeNil := runtime == nil
	if !runtimeNil {
		value := reflect.ValueOf(runtime)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			runtimeNil = value.IsNil()
		}
	}

	controlClosed := controlNil
	applicationClosed := applicationNil
	runtimeClosed := runtimeNil
	defer func() {
		if !applicationClosed {
			result = errors.Join(result, application.Close())
		}
		if !controlClosed {
			result = errors.Join(result, control.Close())
		}
		if !runtimeClosed {
			runtime.Close()
		}
	}()
	if ctx == nil || controlNil {
		return ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if applicationNil {
		// The coordinator translates caller cancellation into Close so a
		// server's context watcher cannot race and discard its Close error.
		serveContext, cancelServe := context.WithCancel(context.WithoutCancel(ctx))
		results := make(chan serveResult, 1)
		go func() {
			results <- serveResult{err: control.Serve(serveContext)}
		}()
		select {
		case served := <-results:
			controlError := control.Close()
			controlClosed = true
			cancelServe()
			if contextErr := ctx.Err(); contextErr != nil {
				return errors.Join(contextErr, served.err, controlError)
			}
			return errors.Join(served.err, controlError)
		case <-ctx.Done():
			controlError := control.Close()
			controlClosed = true
			served := <-results
			cancelServe()
			return errors.Join(ctx.Err(), served.err, controlError)
		}
	}

	// Detaching cancellation preserves context values while making the
	// application -> control shutdown order observable to both servers.
	serveContext, cancelServe := context.WithCancel(context.WithoutCancel(ctx))
	results := make(chan serveResult, 2)
	go func() {
		results <- serveResult{err: control.Serve(serveContext)}
	}()
	go func() {
		results <- serveResult{err: application.Serve(serveContext)}
	}()
	var first serveResult
	received := 0
	select {
	case first = <-results:
		received = 1
	case <-ctx.Done():
		first.err = ctx.Err()
	}
	applicationError := application.Close()
	applicationClosed = true
	controlError := control.Close()
	controlClosed = true
	servedErrors := []error{first.err}
	for received < 2 {
		served := <-results
		received++
		if ctx.Err() == nil && received == 2 &&
			(errors.Is(served.err, context.Canceled) || errors.Is(served.err, context.DeadlineExceeded)) {
			continue
		}
		servedErrors = append(servedErrors, served.err)
	}
	cancelServe()
	if !runtimeClosed {
		runtime.Close()
		runtimeClosed = true
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return errors.Join(append(servedErrors, contextErr, applicationError, controlError)...)
	}
	serveError := errors.Join(servedErrors...)
	if serveError == nil && applicationError == nil && controlError == nil {
		return nil
	}
	return fmt.Errorf("serve platform listeners: %w", errors.Join(
		serveError, applicationError, controlError,
	))
}
