// Package publicbootstrap composes the public admission and event handlers
// from qualified operational dependencies. It creates no listener and does
// not certify the separate engine/provider/isolation execution graph.
package publicbootstrap

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/auth"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/platformauth"
	"github.com/hancomac/circulusd/internal/publicsession"
	"github.com/hancomac/circulusd/internal/sessionadmission"
	"github.com/hancomac/circulusd/internal/sessionevent"
	"github.com/hancomac/circulusd/internal/stateappadmission"
)

const (
	AtomicCredentialAudit  dependency.AtomicGroup = "credential-audit"
	AtomicACLAuthorization dependency.AtomicGroup = "acl-authorization"
)

var ErrInvalidConfiguration = errors.New("public bootstrap: invalid qualified configuration")

type CredentialStore interface {
	auth.PATStore
	dependency.ProductionProbe
}

// SessionAuthorizer must consult the current native membership/authorization
// authority. Its proof shares the Session domain so a stale permit is fenced
// again by the actual admission or event transaction.
type SessionAuthorizer interface {
	sessionevent.Authorizer
	dependency.ProductionProbe
}

type State interface {
	SessionEventReader() dependency.Verified[sessionevent.SessionEventPageReader]
	SessionAdmission(context.Context, stateappadmission.PlannerConfig) (dependency.Verified[sessionadmission.SessionTurnStore], error)
}

type Config struct {
	State               State
	Genesis             dependency.Verified[stateappadmission.GenesisProvider]
	Credentials         dependency.Verified[CredentialStore]
	Authorizer          dependency.Verified[SessionAuthorizer]
	Now                 func() time.Time
	IdempotencySecret   []byte
	CreateTurnScope     string
	ReadEventsScope     string
	MaximumCASRetries   uint32
	MaximumMessageBytes int
	MaximumBodyBytes    int64
	MaximumPageEvents   int
	RequestTimeout      time.Duration
}

func (Config) String() string   { return "qualified-public-config<redacted>" }
func (Config) GoString() string { return "qualified-public-config<redacted>" }

// Graph retains the supplied sources for its lifetime. Closing it prevents
// further HTTP work and cancels active requests; callers own the sources and
// must close them after the public graph. No readiness flag is minted here.
type Graph struct {
	handler        http.Handler
	ctx            context.Context
	cancel         context.CancelFunc
	closeOnce      sync.Once
	requestTimeout time.Duration
}

func (*Graph) String() string   { return "qualified-public-graph<redacted>" }
func (*Graph) GoString() string { return "qualified-public-graph<redacted>" }

func New(ctx context.Context, config Config) (*Graph, error) {
	if ctx == nil || nilState(config.State) || config.Now == nil ||
		len(config.IdempotencySecret) < 32 || len(config.IdempotencySecret) > 4096 ||
		config.MaximumCASRetries < 1 || config.MaximumCASRetries > 256 ||
		config.MaximumMessageBytes < 1 || config.MaximumMessageBytes > 1<<20 ||
		config.MaximumBodyBytes < 1 || config.MaximumBodyBytes > 64<<20 ||
		config.MaximumPageEvents < 1 || config.MaximumPageEvents > 256 ||
		config.RequestTimeout <= 0 || config.RequestTimeout > 5*time.Minute ||
		!validScope(config.CreateTurnScope) || !validScope(config.ReadEventsScope) || config.CreateTurnScope == config.ReadEventsScope {
		return nil, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	credentials, _, err := config.Credentials.Open()
	if err != nil {
		return nil, dependency.ErrUnverifiedDependency
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{AtomicCredentialAudit}, config.Credentials); err != nil {
		return nil, err
	}
	authorizer, _, err := config.Authorizer.Open()
	if err != nil {
		return nil, dependency.ErrUnverifiedDependency
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{AtomicACLAuthorization}, config.Authorizer); err != nil {
		return nil, err
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{dependency.AtomicEngineGenesis}, config.Genesis); err != nil {
		return nil, err
	}
	events := config.State.SessionEventReader()
	groups := []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent}
	if _, err := dependency.RequireAtomicDomain(groups, config.Authorizer, events); err != nil {
		return nil, err
	}
	// Snapshot local immutable inputs before invoking a dependency factory.
	secret := append([]byte(nil), config.IdempotencySecret...)
	defer clear(secret)
	admission, err := config.State.SessionAdmission(ctx, stateappadmission.PlannerConfig{Genesis: config.Genesis})
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	if _, err := dependency.RequireAtomicDomain(groups, admission, events, config.Authorizer); err != nil {
		return nil, err
	}
	pat, err := auth.NewPATService(auth.PATServiceConfig{Store: credentials, Now: config.Now, MaximumCASRetries: config.MaximumCASRetries})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	authenticator, err := platformauth.New(platformauth.Config{PAT: pat, CreateTurnScope: config.CreateTurnScope, ReadEventsScope: config.ReadEventsScope})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	turns, err := publicsession.NewSessionTurnService(publicsession.SessionTurnServiceConfig{
		Store: admission, SessionEvents: events, Authorizer: authorizer,
		IdempotencySecret: secret, MaximumMessageBytes: config.MaximumMessageBytes,
	})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	pages, err := publicsession.NewSessionEventService(publicsession.SessionEventServiceConfig{Reader: events, Authorizer: authorizer, MaximumPageEvents: config.MaximumPageEvents})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	handler, err := publicsession.NewHTTPHandler(publicsession.HTTPConfig{TurnAdmitter: turns, SessionEvents: pages, Authenticator: authenticator, MaximumBodyBytes: config.MaximumBodyBytes})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	graphCtx, cancel := context.WithCancel(ctx)
	return &Graph{handler: handler, ctx: graphCtx, cancel: cancel, requestTimeout: config.RequestTimeout}, nil
}

func (graph *Graph) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if graph == nil || graph.handler == nil || graph.ctx == nil || graph.ctx.Err() != nil {
		http.Error(response, "public service unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), graph.requestTimeout)
	stop := context.AfterFunc(graph.ctx, cancel)
	defer stop()
	defer cancel()
	controller := http.NewResponseController(response)
	deadline, _ := ctx.Deadline()
	if err := controller.SetReadDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		http.Error(response, "public service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer controller.SetReadDeadline(time.Time{})
	if err := controller.SetWriteDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		http.Error(response, "public service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer controller.SetWriteDeadline(time.Time{})
	if request.Body != nil {
		// An HTTP/1.1 Body.Close waits for an in-progress Read and may read
		// the unread body itself, so expire the read deadline first. Wait for
		// the close before the deferred deadline reset can undo it.
		bodyClosed := make(chan struct{})
		stopBody := context.AfterFunc(ctx, func() {
			defer close(bodyClosed)
			_ = controller.SetReadDeadline(time.Now())
			_ = request.Body.Close()
		})
		defer func() {
			if !stopBody() {
				<-bodyClosed
			}
		}()
	}
	// Close may race registration of the cancellation callback.
	if graph.ctx.Err() != nil {
		cancel()
	}
	graph.handler.ServeHTTP(response, request.WithContext(ctx))
}

func (graph *Graph) Close() {
	if graph != nil && graph.cancel != nil {
		graph.closeOnce.Do(graph.cancel)
	}
}

func nilState(state State) bool {
	if state == nil {
		return true
	}
	value := reflect.ValueOf(state)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	}
	return false
}

func validScope(scope string) bool {
	if scope == "" || len(scope) > 256 || !utf8.ValidString(scope) || strings.TrimSpace(scope) != scope {
		return false
	}
	for _, r := range scope {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}
