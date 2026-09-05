// Package stateappclient provides bounded, authenticated platformd-to-state-app
// ingress clients.
package stateappclient

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
	"golang.org/x/text/unicode/norm"
)

const (
	ingressPath         = "/circulusd/state/v1/session-events:read"
	ingressContentType  = "application/vnd.circulusd.state-ingress+cbor"
	ingressProtocol     = "circulus.state-ingress.v1alpha1"
	ingressSchemaDigest = "sha256:6365dfa4e6e73b349508a46688cfcaacdeacece11cd11ed2d7f3e40af49ad3ee"

	hostProtocol     = "circulus.v1alpha1"
	hostSchemaDigest = "sha256:6d9260ac502780b0480ed359ac7a5c368ddb7baa0a2c5772f6a5bc89d5647fba"

	dispatchStartIngressPath         = "/circulusd/state/v1/session-dispatch-start:claim"
	dispatchStartIngressContentType  = "application/vnd.circulusd.state-dispatch-start-ingress+cbor"
	dispatchStartIngressProtocol     = "circulus.state-dispatch-start-ingress.v1alpha1"
	dispatchStartIngressSchemaDigest = "sha256:a86295cc9ad723e50c8729318e4ec4994faa7b4c64c30a718696de8fa6edc724"
	dispatchStartHostSchemaDigest    = "sha256:2b94724f102698a958e5d03593a9f49e1b50665045b22b831d3c0f3538558144"
	dispatchStartRequestMACDomain    = "circulusd.state-dispatch-start-ingress.request.v1"
	dispatchStartResponseMACDomain   = "circulusd.state-dispatch-start-ingress.response.v1"

	keyIDHeader       = "X-Circulus-State-Key-Id"
	signatureHeader   = "X-Circulus-State-Signature"
	requestMACDomain  = "circulusd.state-ingress.request.v1"
	responseMACDomain = "circulusd.state-ingress.response.v1"
	requestKeyDomain  = "circulusd.state-ingress.key.request.v1\x00"
	responseKeyDomain = "circulusd.state-ingress.key.response.v1\x00"

	maximumRequestBytes              = 4_096
	maximumRequestDepth              = 2
	maximumRequestItems              = 32
	maximumDispatchStartRequestBytes = 8_192
	maximumDispatchStartRequestDepth = 4
	maximumDispatchStartRequestItems = 96
	maximumResponseBytes             = 1_048_576 + 65_536
	maximumResponseDepth             = 72
	maximumResponseItems             = 100_000
	maximumResponseHeaderBytes       = 16 << 10
	maximumEventLimit                = 256
	maximumSharedInteger             = uint64(9_007_199_254_740_991)
	maximumTimeout                   = 30 * time.Second
)

var (
	ErrInvalidConfig           = errors.New("state app client: invalid configuration")
	ErrInvalidRequest          = errors.New("state app client: invalid request")
	ErrTransport               = errors.New("state app client: transport failure")
	ErrUnauthenticatedResponse = errors.New("state app client: unauthenticated response")
	ErrInvalidResponse         = errors.New("state app client: invalid response")
	ErrRemote                  = errors.New("state app client: remote failure")
	ErrClientClosed            = errors.New("state app client: closed")

	keyIDPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	signaturePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

var safeHostErrorMessages = map[string]string{
	"INVALID_ARGUMENT":         "The RPC request is invalid.",
	"NOT_FOUND":                "The requested resource was not found.",
	"ALREADY_EXISTS":           "The requested resource already exists.",
	"CONFLICT":                 "The operation conflicts with current state.",
	"IDEMPOTENCY_CONFLICT":     "The idempotency key conflicts with an earlier request.",
	"PERMISSION_DENIED":        "The operation is not permitted.",
	"FAILED_PRECONDITION":      "A required precondition was not satisfied.",
	"STALE_GENERATION":         "The supplied generation is stale.",
	"STALE_DISPATCH_ATTEMPT":   "The supplied dispatch attempt is stale.",
	"DIGEST_MISMATCH":          "A supplied digest does not match its value.",
	"NEEDS_CONFIRMATION":       "The operation requires confirmation.",
	"ABORTED":                  "The operation was aborted.",
	"LEASE_EXPIRED":            "The supplied lease has expired.",
	"RESOURCE_EXHAUSTED":       "The RPC response exceeds its operation limit.",
	"STORAGE_CONTRACT":         "The durable storage contract is unavailable.",
	"CELL_ID_MISMATCH":         "The request was routed to the wrong durable cell.",
	"NOT_INITIALIZED":          "The durable aggregate is not initialized.",
	"INITIALIZATION_CONFLICT":  "The initialization conflicts with stored state.",
	"STRUCTURED_CLONE_FAILED":  "The value cannot cross the durable storage boundary.",
	"CORRUPT_STATE":            "The durable aggregate state is invalid.",
	"INVALID_AGGREGATE_OUTPUT": "The aggregate produced an invalid result.",
	"INTERNAL_ERROR":           "The operation could not be completed.",
}

type Config struct {
	Endpoint             string
	KeyID                string
	RootKey              []byte
	DispatchStartKeyID   string
	DispatchStartRootKey []byte
	Timeout              time.Duration
}

type Request struct {
	TenantID                        string
	ActorSubjectID                  string
	SessionID                       string
	ExpectedAuthorizationGeneration uint64
	AfterSequence                   uint64
	Limit                           int
}

type DispatchStartFence struct {
	TurnLeaseGeneration     uint64
	PlacementGeneration     uint64
	SandboxGeneration       uint64
	AuthorizationGeneration uint64
}

type DispatchPermitClaims struct {
	TenantID                string
	UserID                  string
	SessionID               string
	TurnID                  string
	EffectID                string
	InvocationID            string
	RequestDigest           string
	Service                 string
	Operation               string
	ReplayPolicy            string
	ParentOperationID       string
	Ordinal                 uint64
	DispatchAttempt         uint64
	TurnLeaseGeneration     uint64
	PlacementGeneration     uint64
	SandboxGeneration       uint64
	AuthorizationGeneration uint64
	ProviderRouteDigest     string
	DeadlineUnixMS          uint64
}

type ClaimDispatchStartRequest struct {
	TenantID              string
	WorkspaceID           string
	SessionID             string
	CommandID             string
	ExpectedEventSequence uint64
	TurnID                string
	EffectID              string
	InvocationID          string
	RequestDigest         string
	Fence                 DispatchStartFence
	DispatchAttempt       uint64
	ProviderRequestID     string
	ProviderRouteDigest   string
	DispatchPermitClaims  DispatchPermitClaims
	CommandDigest         string
}

type DispatchStartPermit struct {
	DispatchPermitClaims DispatchPermitClaims
	ProviderRequestID    string
	CommandDigest        string
	ClaimedEventSequence uint64
}

type ClaimDispatchStartResult struct {
	OutcomeFresh bool
	HostReplayed bool
	Version      uint64
	EffectID     string
	Permit       DispatchStartPermit
}

type authenticatedIngressContract struct {
	path                     string
	contentType              string
	requestMACDomain         string
	responseMACDomain        string
	hostSchemaDigest         string
	requestOptions           canonical.Options
	dispatchStartCredentials bool
}

// RemoteError is a validated, allowlisted state-app failure. Message is always
// the locally compiled safe message for Code, never arbitrary remote text.
type RemoteError struct {
	Code    string
	Message string
	Status  int
}

func (failure *RemoteError) Error() string {
	if failure == nil {
		return ErrRemote.Error()
	}
	return fmt.Sprintf("%s: %s", ErrRemote, failure.Code)
}

func (failure *RemoteError) Unwrap() error { return ErrRemote }

type Client struct {
	endpoint                 string
	keyID                    string
	requestKey               [sha256.Size]byte
	responseKey              [sha256.Size]byte
	dispatchStartKeyID       string
	dispatchStartRequestKey  [sha256.Size]byte
	dispatchStartResponseKey [sha256.Size]byte
	timeout                  time.Duration
	clock                    func() time.Time
	newRequestID             func() (string, error)
	sourceGate               chan struct{}
	transport                *http.Transport
	httpClient               *http.Client
	lifecycleMu              sync.Mutex
	closed                   bool
	closeDone                chan struct{}
	nextActiveID             uint64
	active                   sync.WaitGroup
	activeCancel             map[uint64]context.CancelFunc
	connections              map[*trackedConnection]struct{}
}

type trackedConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (connection *trackedConnection) Close() error {
	var err error
	connection.once.Do(func() {
		err = connection.Conn.Close()
		if connection.release != nil {
			connection.release()
		}
	})
	return err
}

func New(config Config) (*Client, error) {
	return newWithSources(config, clientSources{
		clock: time.Now,
		newRequestID: func() (string, error) {
			generated, err := identity.New(identity.Request)
			if err != nil {
				return "", err
			}
			return generated.String(), nil
		},
	})
}

type clientSources struct {
	clock        func() time.Time
	newRequestID func() (string, error)
}

func newWithSources(config Config, sources clientSources) (*Client, error) {
	parsed, err := url.Parse(config.Endpoint)
	var endpointIP net.IP
	var endpointPort uint64
	endpointPortErr := ErrInvalidConfig
	if err == nil {
		endpointIP = net.ParseIP(parsed.Hostname())
		endpointPort, endpointPortErr = strconv.ParseUint(parsed.Port(), 10, 16)
	}
	dispatchStartCredentialsAbsent := config.DispatchStartKeyID == "" && len(config.DispatchStartRootKey) == 0
	dispatchStartCredentialsValid := keyIDPattern.MatchString(config.DispatchStartKeyID) &&
		len(config.DispatchStartRootKey) >= 32 && len(config.DispatchStartRootKey) <= 256 &&
		config.DispatchStartKeyID != config.KeyID && !bytes.Equal(config.DispatchStartRootKey, config.RootKey)
	if err != nil || config.Endpoint == "" || config.Endpoint != strings.TrimSpace(config.Endpoint) ||
		strings.Contains(config.Endpoint, "%") || parsed.Scheme != "http" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" ||
		parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" ||
		parsed.Path != "" || endpointIP == nil || !endpointIP.IsLoopback() ||
		endpointPortErr != nil || endpointPort == 0 || strconv.FormatUint(endpointPort, 10) != parsed.Port() ||
		parsed.Host != net.JoinHostPort(endpointIP.String(), parsed.Port()) || parsed.String() != config.Endpoint ||
		!keyIDPattern.MatchString(config.KeyID) ||
		len(config.RootKey) < 32 || len(config.RootKey) > 256 ||
		!dispatchStartCredentialsAbsent && !dispatchStartCredentialsValid ||
		config.Timeout <= 0 || config.Timeout > maximumTimeout ||
		sources.clock == nil || sources.newRequestID == nil {
		return nil, ErrInvalidConfig
	}
	rootKey := append([]byte(nil), config.RootKey...)
	requestKey := keyedDigest(rootKey, []byte(requestKeyDomain))
	responseKey := keyedDigest(rootKey, []byte(responseKeyDomain))
	clear(rootKey)
	var dispatchStartRequestKey [sha256.Size]byte
	var dispatchStartResponseKey [sha256.Size]byte
	if !dispatchStartCredentialsAbsent {
		dispatchStartRootKey := append([]byte(nil), config.DispatchStartRootKey...)
		dispatchStartRequestKey = keyedDigest(dispatchStartRootKey, []byte(requestKeyDomain))
		dispatchStartResponseKey = keyedDigest(dispatchStartRootKey, []byte(responseKeyDomain))
		clear(dispatchStartRootKey)
	}

	sourceGate := make(chan struct{}, 1)
	sourceGate <- struct{}{}
	client := &Client{
		endpoint:                 config.Endpoint,
		keyID:                    config.KeyID,
		requestKey:               requestKey,
		responseKey:              responseKey,
		dispatchStartKeyID:       config.DispatchStartKeyID,
		dispatchStartRequestKey:  dispatchStartRequestKey,
		dispatchStartResponseKey: dispatchStartResponseKey,
		timeout:                  config.Timeout, clock: sources.clock, newRequestID: sources.newRequestID,
		sourceGate: sourceGate, closeDone: make(chan struct{}),
		activeCancel: make(map[uint64]context.CancelFunc),
		connections:  make(map[*trackedConnection]struct{}),
	}
	client.transport = &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			network := "tcp6"
			if endpointIP.To4() != nil {
				network = "tcp4"
			}
			raw, dialErr := (&net.Dialer{}).DialContext(ctx, network, parsed.Host)
			if dialErr != nil {
				return nil, dialErr
			}
			connection := &trackedConnection{Conn: raw}
			connection.release = func() {
				client.lifecycleMu.Lock()
				delete(client.connections, connection)
				client.lifecycleMu.Unlock()
			}
			client.lifecycleMu.Lock()
			if client.closed {
				client.lifecycleMu.Unlock()
				_ = raw.Close()
				return nil, ErrClientClosed
			}
			client.connections[connection] = struct{}{}
			client.lifecycleMu.Unlock()
			return connection, nil
		},
		DisableCompression:     true,
		ForceAttemptHTTP2:      false,
		MaxIdleConns:           16,
		MaxIdleConnsPerHost:    16,
		MaxConnsPerHost:        64,
		IdleConnTimeout:        config.Timeout,
		ResponseHeaderTimeout:  config.Timeout,
		ExpectContinueTimeout:  config.Timeout,
		MaxResponseHeaderBytes: maximumResponseHeaderBytes,
	}
	client.httpClient = &http.Client{
		Transport: client.transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("state app client: redirects are disabled")
		},
	}
	return client, nil
}

func (client *Client) Close() {
	if client == nil {
		return
	}
	client.lifecycleMu.Lock()
	if client.closeDone == nil || client.transport == nil {
		client.closed = true
		client.lifecycleMu.Unlock()
		return
	}
	if client.closed {
		closed := client.closeDone
		client.lifecycleMu.Unlock()
		<-closed
		return
	}
	client.closed = true
	cancels := make([]context.CancelFunc, 0, len(client.activeCancel))
	for _, cancel := range client.activeCancel {
		cancels = append(cancels, cancel)
	}
	connections := make([]*trackedConnection, 0, len(client.connections))
	for connection := range client.connections {
		connections = append(connections, connection)
	}
	closed := client.closeDone
	client.lifecycleMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	for _, connection := range connections {
		_ = connection.Close()
	}
	client.active.Wait()
	client.transport.CloseIdleConnections()
	client.lifecycleMu.Lock()
	clear(client.requestKey[:])
	clear(client.responseKey[:])
	clear(client.dispatchStartRequestKey[:])
	clear(client.dispatchStartResponseKey[:])
	client.lifecycleMu.Unlock()
	close(closed)
}

func (client *Client) ReadSessionEvents(ctx context.Context, request Request) (canonical.Value, error) {
	if ctx == nil {
		return nil, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if client == nil || client.httpClient == nil {
		return nil, ErrInvalidConfig
	}
	if _, err := identity.Parse(identity.Tenant, request.TenantID); err != nil {
		return nil, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Subject, request.ActorSubjectID); err != nil {
		return nil, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Session, request.SessionID); err != nil ||
		request.ExpectedAuthorizationGeneration < 1 ||
		request.ExpectedAuthorizationGeneration > maximumSharedInteger ||
		request.AfterSequence > maximumSharedInteger ||
		request.Limit < 1 || request.Limit > maximumEventLimit {
		return nil, ErrInvalidRequest
	}
	return client.invokeAuthenticatedIngress(
		ctx,
		authenticatedIngressContract{
			path: ingressPath, contentType: ingressContentType,
			requestMACDomain: requestMACDomain, responseMACDomain: responseMACDomain,
			hostSchemaDigest: hostSchemaDigest,
			requestOptions: canonical.Options{
				MaxBytes: maximumRequestBytes, MaxDepth: maximumRequestDepth, MaxItems: maximumRequestItems,
			},
		},
		func(requestID string, sentAtUnixMS int64) canonical.Map {
			return canonical.Map{
				"protocol": ingressProtocol, "major": int64(1), "minor": int64(0),
				"schemaDigest": ingressSchemaDigest,
				"requestId":    requestID, "sentAtUnixMs": sentAtUnixMS,
				"tenantId": request.TenantID, "actorSubjectId": request.ActorSubjectID,
				"sessionId":                       request.SessionID,
				"expectedAuthorizationGeneration": request.ExpectedAuthorizationGeneration,
				"afterSequence":                   request.AfterSequence, "limit": request.Limit,
			}
		},
	)
}

func (client *Client) ClaimDispatchStart(
	ctx context.Context,
	request ClaimDispatchStartRequest,
) (ClaimDispatchStartResult, error) {
	if ctx == nil {
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return ClaimDispatchStartResult{}, err
	}
	if client == nil || client.httpClient == nil {
		return ClaimDispatchStartResult{}, ErrInvalidConfig
	}
	if client.dispatchStartKeyID == "" {
		return ClaimDispatchStartResult{}, ErrInvalidConfig
	}
	claims := request.DispatchPermitClaims
	if _, err := identity.Parse(identity.Tenant, request.TenantID); err != nil {
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Workspace, request.WorkspaceID); err != nil {
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Session, request.SessionID); err != nil {
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Turn, request.TurnID); err != nil {
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Effect, request.EffectID); err != nil {
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Invocation, request.InvocationID); err != nil {
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}
	if request.ProviderRequestID != "" {
		if _, err := identity.Parse(identity.Request, request.ProviderRequestID); err != nil {
			return ClaimDispatchStartResult{}, ErrInvalidRequest
		}
	}
	if _, err := identity.Parse(identity.Tenant, claims.TenantID); err != nil {
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Subject, claims.UserID); err != nil {
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Session, claims.SessionID); err != nil {
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Turn, claims.TurnID); err != nil {
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Effect, claims.EffectID); err != nil {
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Invocation, claims.InvocationID); err != nil {
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}
	if claims.ParentOperationID != "" {
		if _, err := identity.Parse(identity.Operation, claims.ParentOperationID); err != nil {
			return ClaimDispatchStartResult{}, ErrInvalidRequest
		}
	} else if claims.Ordinal != 0 {
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}
	for _, value := range []string{request.CommandID, claims.Operation} {
		if value == "" || len(value) > 256 || !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) {
			return ClaimDispatchStartResult{}, ErrInvalidRequest
		}
		for _, character := range value {
			if unicode.Is(unicode.Cc, character) {
				return ClaimDispatchStartResult{}, ErrInvalidRequest
			}
		}
	}
	zeroDigest := "sha256:" + strings.Repeat("0", 64)
	for _, candidate := range []struct {
		value   string
		nonzero bool
	}{
		{value: request.RequestDigest, nonzero: true},
		{value: request.ProviderRouteDigest, nonzero: true},
		{value: claims.RequestDigest, nonzero: true},
		{value: claims.ProviderRouteDigest, nonzero: true},
		{value: request.CommandDigest, nonzero: true},
	} {
		if !digestPattern.MatchString(candidate.value) || candidate.nonzero && candidate.value == zeroDigest {
			return ClaimDispatchStartResult{}, ErrInvalidRequest
		}
	}
	switch claims.Service {
	case "model", "workspace", "executor", "mcp", "artifact", "external-tool":
	default:
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}
	switch claims.ReplayPolicy {
	case "safe", "idempotency-key", "never", "confirm":
	default:
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}
	if request.ExpectedEventSequence >= maximumSharedInteger ||
		request.DispatchAttempt < 1 || request.DispatchAttempt > maximumSharedInteger ||
		request.Fence.TurnLeaseGeneration > maximumSharedInteger ||
		request.Fence.PlacementGeneration > maximumSharedInteger ||
		request.Fence.SandboxGeneration > maximumSharedInteger ||
		request.Fence.AuthorizationGeneration > maximumSharedInteger ||
		claims.DispatchAttempt < 1 || claims.DispatchAttempt > maximumSharedInteger ||
		claims.TurnLeaseGeneration > maximumSharedInteger ||
		claims.PlacementGeneration > maximumSharedInteger ||
		claims.SandboxGeneration > maximumSharedInteger ||
		claims.AuthorizationGeneration > maximumSharedInteger ||
		claims.Ordinal > maximumSharedInteger ||
		claims.DeadlineUnixMS < 1 || claims.DeadlineUnixMS > maximumSharedInteger {
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}
	if request.TenantID != claims.TenantID ||
		request.SessionID != claims.SessionID ||
		request.TurnID != claims.TurnID ||
		request.EffectID != claims.EffectID ||
		request.InvocationID != claims.InvocationID ||
		request.RequestDigest != claims.RequestDigest ||
		request.DispatchAttempt != claims.DispatchAttempt ||
		request.ProviderRouteDigest != claims.ProviderRouteDigest ||
		request.Fence.TurnLeaseGeneration != claims.TurnLeaseGeneration ||
		request.Fence.PlacementGeneration != claims.PlacementGeneration ||
		request.Fence.SandboxGeneration != claims.SandboxGeneration ||
		request.Fence.AuthorizationGeneration != claims.AuthorizationGeneration {
		return ClaimDispatchStartResult{}, ErrInvalidRequest
	}

	claimMap := canonical.Map{
		"tenantId": claims.TenantID, "userId": claims.UserID,
		"sessionId": claims.SessionID, "turnId": claims.TurnID,
		"effectId": claims.EffectID, "invocationId": claims.InvocationID,
		"requestDigest": claims.RequestDigest, "service": claims.Service,
		"operation": claims.Operation, "replayPolicy": claims.ReplayPolicy,
		"dispatchAttempt":         int64(claims.DispatchAttempt),
		"turnLeaseGeneration":     int64(claims.TurnLeaseGeneration),
		"placementGeneration":     int64(claims.PlacementGeneration),
		"sandboxGeneration":       int64(claims.SandboxGeneration),
		"authorizationGeneration": int64(claims.AuthorizationGeneration),
		"providerRouteDigest":     claims.ProviderRouteDigest,
		"deadline":                int64(claims.DeadlineUnixMS),
	}
	if claims.ParentOperationID != "" {
		claimMap["parentOperationId"] = claims.ParentOperationID
		claimMap["ordinal"] = int64(claims.Ordinal)
	}
	var providerRequestID canonical.Value
	if request.ProviderRequestID != "" {
		providerRequestID = request.ProviderRequestID
	}
	rawResult, err := client.invokeAuthenticatedIngress(
		ctx,
		authenticatedIngressContract{
			path: dispatchStartIngressPath, contentType: dispatchStartIngressContentType,
			requestMACDomain:  dispatchStartRequestMACDomain,
			responseMACDomain: dispatchStartResponseMACDomain,
			hostSchemaDigest:  dispatchStartHostSchemaDigest,
			requestOptions: canonical.Options{
				MaxBytes: maximumDispatchStartRequestBytes,
				MaxDepth: maximumDispatchStartRequestDepth,
				MaxItems: maximumDispatchStartRequestItems,
			},
			dispatchStartCredentials: true,
		},
		func(requestID string, sentAtUnixMS int64) canonical.Map {
			return canonical.Map{
				"protocol": dispatchStartIngressProtocol, "major": int64(1), "minor": int64(0),
				"schemaDigest": dispatchStartIngressSchemaDigest,
				"requestId":    requestID, "sentAtUnixMs": sentAtUnixMS,
				"tenantId": request.TenantID, "workspaceId": request.WorkspaceID,
				"sessionId": request.SessionID,
				"commandId": request.CommandID, "expectedEventSequence": int64(request.ExpectedEventSequence),
				"turnId": request.TurnID, "effectId": request.EffectID,
				"invocationId": request.InvocationID, "requestDigest": request.RequestDigest,
				"fence": canonical.Map{
					"turnLeaseGeneration":     int64(request.Fence.TurnLeaseGeneration),
					"placementGeneration":     int64(request.Fence.PlacementGeneration),
					"sandboxGeneration":       int64(request.Fence.SandboxGeneration),
					"authorizationGeneration": int64(request.Fence.AuthorizationGeneration),
				},
				"dispatchAttempt":      int64(request.DispatchAttempt),
				"providerRequestId":    providerRequestID,
				"providerRouteDigest":  request.ProviderRouteDigest,
				"dispatchPermitClaims": claimMap,
				"commandDigest":        request.CommandDigest,
			}
		},
	)
	if err != nil {
		return ClaimDispatchStartResult{}, err
	}
	result, ok := rawResult.(canonical.Map)
	if !ok || len(result) != 3 {
		return ClaimDispatchStartResult{}, ErrInvalidResponse
	}
	outcome, outcomeOK := result["outcome"].(canonical.Map)
	version, versionOK := result["version"].(int64)
	hostReplayed, replayedOK := result["replayed"].(bool)
	if !outcomeOK || len(outcome) != 4 || !versionOK || version < 1 || !replayedOK ||
		outcome["kind"] != "dispatch_start_claimed" || outcome["effectId"] != request.EffectID {
		return ClaimDispatchStartResult{}, ErrInvalidResponse
	}
	fresh, freshOK := outcome["fresh"].(bool)
	permit, permitOK := outcome["startPermit"].(canonical.Map)
	if !freshOK || !permitOK || len(permit) != 4 || fresh == hostReplayed {
		return ClaimDispatchStartResult{}, ErrInvalidResponse
	}
	responseClaims, claimsOK := permit["dispatchPermitClaims"].(canonical.Map)
	claimedEventSequence, sequenceOK := permit["claimedEventSequence"].(int64)
	if !claimsOK || !reflect.DeepEqual(responseClaims, claimMap) ||
		permit["providerRequestId"] != providerRequestID ||
		permit["commandDigest"] != request.CommandDigest ||
		!sequenceOK || claimedEventSequence < 1 || uint64(claimedEventSequence) <= request.ExpectedEventSequence ||
		version < claimedEventSequence || fresh && version != claimedEventSequence {
		return ClaimDispatchStartResult{}, ErrInvalidResponse
	}
	return ClaimDispatchStartResult{
		OutcomeFresh: fresh,
		HostReplayed: hostReplayed,
		Version:      uint64(version),
		EffectID:     request.EffectID,
		Permit: DispatchStartPermit{
			DispatchPermitClaims: request.DispatchPermitClaims,
			ProviderRequestID:    request.ProviderRequestID,
			CommandDigest:        request.CommandDigest,
			ClaimedEventSequence: uint64(claimedEventSequence),
		},
	}, nil
}

func (client *Client) invokeAuthenticatedIngress(
	ctx context.Context,
	contract authenticatedIngressContract,
	bodyFor func(string, int64) canonical.Map,
) (canonical.Value, error) {
	keyID := client.keyID
	requestKey := &client.requestKey
	responseKey := &client.responseKey
	if contract.dispatchStartCredentials {
		if client.dispatchStartKeyID == "" {
			return nil, ErrInvalidConfig
		}
		keyID = client.dispatchStartKeyID
		requestKey = &client.dispatchStartRequestKey
		responseKey = &client.dispatchStartResponseKey
	}
	requestContext, finish, err := client.beginActiveRequest(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()

	select {
	case <-requestContext.Done():
		client.lifecycleMu.Lock()
		closed := client.closed
		client.lifecycleMu.Unlock()
		if closed {
			return nil, ErrClientClosed
		}
		return nil, requestContext.Err()
	case <-client.sourceGate:
	}
	requestID, err := client.newRequestID()
	now := time.Time{}
	if err == nil {
		now = client.clock()
	}
	client.sourceGate <- struct{}{}
	if contextErr := requestContext.Err(); contextErr != nil {
		client.lifecycleMu.Lock()
		closed := client.closed
		client.lifecycleMu.Unlock()
		if closed {
			return nil, ErrClientClosed
		}
		return nil, contextErr
	}
	if err != nil {
		return nil, fmt.Errorf("%w: request ID generation failed: %w", ErrInvalidRequest, err)
	}
	if _, err := identity.Parse(identity.Request, requestID); err != nil {
		return nil, fmt.Errorf("%w: generated request ID is invalid", ErrInvalidRequest)
	}
	sentAtUnixMS := now.UnixMilli()
	if sentAtUnixMS < 0 || uint64(sentAtUnixMS) > maximumSharedInteger {
		return nil, fmt.Errorf("%w: clock is outside the shared integer range", ErrInvalidRequest)
	}

	body, err := canonical.Encode(bodyFor(requestID, sentAtUnixMS), contract.requestOptions)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot encode request", ErrInvalidRequest)
	}
	requestDigest := sha256.Sum256(body)
	requestParts := [][]byte{
		[]byte(contract.requestMACDomain), []byte(keyID), []byte(http.MethodPost),
		[]byte(contract.path), requestDigest[:],
	}
	requestFrameLength := 0
	for _, part := range requestParts {
		requestFrameLength += 4 + len(part)
	}
	requestFrame := make([]byte, 0, requestFrameLength)
	var lengthPrefix [4]byte
	for _, part := range requestParts {
		binary.BigEndian.PutUint32(lengthPrefix[:], uint32(len(part)))
		requestFrame = append(requestFrame, lengthPrefix[:]...)
		requestFrame = append(requestFrame, part...)
	}
	signature := keyedDigest(requestKey[:], requestFrame)

	httpRequest, err := http.NewRequestWithContext(
		requestContext, http.MethodPost, client.endpoint+contract.path, bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot construct request", ErrInvalidRequest)
	}
	httpRequest.Header.Set("Content-Type", contract.contentType)
	httpRequest.Header.Set(keyIDHeader, keyID)
	httpRequest.Header.Set(signatureHeader, hex.EncodeToString(signature[:]))

	response, err := client.httpClient.Do(httpRequest)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		client.lifecycleMu.Lock()
		closed := client.closed
		client.lifecycleMu.Unlock()
		if closed {
			return nil, ErrClientClosed
		}
		if ctxErr := requestContext.Err(); ctxErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrTransport, ctxErr)
		}
		return nil, fmt.Errorf("%w: %w", ErrTransport, err)
	}
	defer response.Body.Close()
	contentTypes := response.Header.Values("Content-Type")
	keyIDs := response.Header.Values(keyIDHeader)
	signatures := response.Header.Values(signatureHeader)
	_, hasContentEncoding := response.Header[http.CanonicalHeaderKey("Content-Encoding")]
	if len(contentTypes) != 1 || contentTypes[0] != contract.contentType ||
		len(keyIDs) != 1 || keyIDs[0] != keyID ||
		len(signatures) != 1 || !signaturePattern.MatchString(signatures[0]) ||
		hasContentEncoding {
		return nil, ErrUnauthenticatedResponse
	}
	if response.ContentLength > maximumResponseBytes {
		return nil, fmt.Errorf("%w: body exceeds %d bytes", ErrInvalidResponse, maximumResponseBytes)
	}
	body, err = io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if err != nil {
		client.lifecycleMu.Lock()
		closed := client.closed
		client.lifecycleMu.Unlock()
		if closed {
			return nil, ErrClientClosed
		}
		if ctxErr := requestContext.Err(); ctxErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrTransport, ctxErr)
		}
		return nil, fmt.Errorf("%w: cannot read complete response body", ErrInvalidResponse)
	}
	if len(body) > maximumResponseBytes {
		return nil, fmt.Errorf("%w: body exceeds %d bytes", ErrInvalidResponse, maximumResponseBytes)
	}
	receivedSignature, err := hex.DecodeString(signatures[0])
	if err != nil {
		return nil, ErrUnauthenticatedResponse
	}
	bodyDigest := sha256.Sum256(body)
	responseParts := [][]byte{
		[]byte(contract.responseMACDomain), []byte(keyID), []byte(requestID), requestDigest[:],
		[]byte(strconv.Itoa(response.StatusCode)), []byte(contentTypes[0]), bodyDigest[:],
	}
	responseFrameLength := 0
	for _, part := range responseParts {
		responseFrameLength += 4 + len(part)
	}
	responseFrame := make([]byte, 0, responseFrameLength)
	for _, part := range responseParts {
		binary.BigEndian.PutUint32(lengthPrefix[:], uint32(len(part)))
		responseFrame = append(responseFrame, lengthPrefix[:]...)
		responseFrame = append(responseFrame, part...)
	}
	wantSignature := keyedDigest(responseKey[:], responseFrame)
	if !hmac.Equal(receivedSignature, wantSignature[:]) {
		return nil, ErrUnauthenticatedResponse
	}

	decoded, err := canonical.Decode(body, canonical.Options{
		MaxBytes: maximumResponseBytes, MaxDepth: maximumResponseDepth, MaxItems: maximumResponseItems,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: malformed canonical body", ErrInvalidResponse)
	}
	envelope, ok := decoded.(canonical.Map)
	if !ok || len(envelope) != 6 ||
		envelope["protocol"] != hostProtocol || envelope["major"] != int64(1) || envelope["minor"] != int64(0) ||
		envelope["schemaDigest"] != contract.hostSchemaDigest || envelope["requestId"] != requestID {
		return nil, ErrInvalidResponse
	}
	payload, ok := envelope["payload"].(canonical.Map)
	if !ok {
		return nil, ErrInvalidResponse
	}
	result, hasResult := payload["result"]
	if okValue, isBool := payload["ok"].(bool); isBool && okValue && len(payload) == 2 && hasResult {
		if response.StatusCode != http.StatusOK {
			return nil, ErrInvalidResponse
		}
		return result, nil
	}
	failureValue, hasFailure := payload["error"]
	if okValue, isBool := payload["ok"].(bool); !isBool || okValue || len(payload) != 2 || !hasFailure {
		return nil, ErrInvalidResponse
	}
	failure, ok := failureValue.(canonical.Map)
	if !ok || len(failure) != 2 {
		return nil, ErrInvalidResponse
	}
	code, codeOK := failure["code"].(string)
	message, messageOK := failure["message"].(string)
	safeMessage, known := safeHostErrorMessages[code]
	validStatus := false
	switch response.StatusCode {
	case http.StatusOK:
		validStatus = true
	case http.StatusBadRequest:
		validStatus = code == "INVALID_ARGUMENT"
	case http.StatusInternalServerError:
		validStatus = code == "INTERNAL_ERROR"
	case http.StatusBadGateway:
		validStatus = code == "INTERNAL_ERROR" || code == "RESOURCE_EXHAUSTED"
	}
	if !codeOK || !messageOK || !known || message != safeMessage || !validStatus {
		return nil, ErrInvalidResponse
	}
	return nil, &RemoteError{Code: code, Message: safeMessage, Status: response.StatusCode}
}

func (client *Client) beginActiveRequest(ctx context.Context) (context.Context, func(), error) {
	requestContext, cancel := context.WithTimeout(ctx, client.timeout)
	client.lifecycleMu.Lock()
	if client.closed {
		client.lifecycleMu.Unlock()
		cancel()
		return nil, nil, ErrClientClosed
	}
	client.nextActiveID++
	activeID := client.nextActiveID
	client.active.Add(1)
	client.activeCancel[activeID] = cancel
	client.lifecycleMu.Unlock()
	finish := func() {
		cancel()
		client.lifecycleMu.Lock()
		delete(client.activeCancel, activeID)
		client.lifecycleMu.Unlock()
		client.active.Done()
	}
	return requestContext, finish, nil
}

func keyedDigest(key, value []byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(value)
	var digest [sha256.Size]byte
	copy(digest[:], mac.Sum(nil))
	return digest
}
