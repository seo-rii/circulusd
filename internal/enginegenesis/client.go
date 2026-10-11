package enginegenesis

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/stateappadmission"
	"github.com/hancomac/circulusd/internal/stateappcodec"
)

type ClientConfig struct {
	Endpoint string
	KeyID    string
	RootKey  []byte
	Timeout  time.Duration
}

func (ClientConfig) String() string   { return "engine-genesis-client-config<redacted>" }
func (ClientConfig) GoString() string { return "engine-genesis-client-config<redacted>" }

type Client struct {
	endpoint     string
	keyID        string
	requestKey   [32]byte
	responseKey  [32]byte
	client       *http.Client
	transport    *http.Transport
	clock        func() time.Time
	newRequestID func() (string, error)
	mu           sync.Mutex
	closed       bool
	active       sync.WaitGroup
	lifecycle    context.Context
	cancel       context.CancelFunc
}

var _ Transport = (*Client)(nil)

func (*Client) String() string   { return "engine-genesis-client<redacted>" }
func (*Client) GoString() string { return "engine-genesis-client<redacted>" }

func NewClient(config ClientConfig) (*Client, error) {
	return newClient(config, time.Now, func() (string, error) { id, err := identity.New(identity.Request); return id.String(), err })
}
func newClient(config ClientConfig, clock func() time.Time, newID func() (string, error)) (*Client, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "http" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.Opaque != "" || strings.Contains(config.Endpoint, "%") || config.Endpoint != strings.TrimSpace(config.Endpoint) {
		return nil, ErrInvalidConfig
	}
	ip := net.ParseIP(endpoint.Hostname())
	port, err := strconv.ParseUint(endpoint.Port(), 10, 16)
	if err != nil || port == 0 || ip == nil || !ip.IsLoopback() || strconv.FormatUint(port, 10) != endpoint.Port() || endpoint.Host != net.JoinHostPort(ip.String(), endpoint.Port()) || endpoint.String() != config.Endpoint || !keyPattern.MatchString(config.KeyID) || len(config.RootKey) < 32 || len(config.RootKey) > 256 || config.Timeout <= 0 || config.Timeout > 30*time.Second || clock == nil || newID == nil {
		return nil, ErrInvalidConfig
	}
	address := endpoint.Host
	transport := &http.Transport{Proxy: nil, DisableCompression: true, MaxIdleConnsPerHost: 4, ResponseHeaderTimeout: config.Timeout, MaxResponseHeaderBytes: 16 << 10,
		DialContext: func(ctx context.Context, network, requested string) (net.Conn, error) {
			if network != "tcp" || requested != address {
				return nil, ErrInvalidConfig
			}
			return (&net.Dialer{Timeout: config.Timeout}).DialContext(ctx, "tcp", address)
		}}
	lifecycle, cancel := context.WithCancel(context.Background())
	client := &Client{endpoint: config.Endpoint, keyID: config.KeyID, requestKey: directionalKey(config.RootKey, "request"), responseKey: directionalKey(config.RootKey, "response"), transport: transport, clock: clock, newRequestID: newID, lifecycle: lifecycle, cancel: cancel}
	client.client = &http.Client{Transport: transport, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalidResponse }}
	return client, nil
}
func (client *Client) Close() {
	if client == nil {
		return
	}
	client.mu.Lock()
	if !client.closed {
		client.closed = true
		if client.cancel != nil {
			client.cancel()
		}
	}
	client.mu.Unlock()
	client.active.Wait()
	if client.transport != nil {
		client.transport.CloseIdleConnections()
	}
	client.mu.Lock()
	clear(client.requestKey[:])
	clear(client.responseKey[:])
	client.mu.Unlock()
}
func (client *Client) begin(ctx context.Context) (context.Context, func(), [32]byte, [32]byte, error) {
	var zero [32]byte
	if ctx == nil {
		return nil, nil, zero, zero, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, zero, zero, err
	}
	if client == nil {
		return nil, nil, zero, zero, ErrInvalidConfig
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return nil, nil, zero, zero, ErrClosed
	}
	if client.client == nil || client.lifecycle == nil || client.clock == nil || client.newRequestID == nil {
		return nil, nil, zero, zero, ErrInvalidConfig
	}
	client.active.Add(1)
	active, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(client.lifecycle, cancel)
	return active, func() { stop(); cancel(); client.active.Done() }, client.requestKey, client.responseKey, nil
}
func (client *Client) post(ctx context.Context, path, contentType string, body []byte, headers http.Header, limit int) ([]byte, http.Header, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, 0, ErrInvalidRequest
	}
	request.Header = headers.Clone()
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Accept", contentType)
	request.Header.Set("Cache-Control", "no-store")
	response, err := client.client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		if err := ctx.Err(); err != nil {
			return nil, nil, 0, err
		}
		return nil, nil, 0, ErrUnavailable
	}
	defer response.Body.Close()
	if len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != contentType || len(response.Header.Values("Cache-Control")) != 1 || response.Header.Get("Cache-Control") != "no-store" || len(response.Header.Values("Content-Encoding")) != 0 || response.ContentLength > int64(limit) {
		return nil, nil, 0, ErrInvalidResponse
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		if err := ctx.Err(); err != nil {
			return nil, nil, 0, err
		}
		return nil, nil, 0, ErrInvalidResponse
	}
	if len(encoded) > limit {
		return nil, nil, 0, ErrInvalidResponse
	}
	return encoded, response.Header.Clone(), response.StatusCode, nil
}

func (client *Client) RequestGenesis(ctx context.Context, request stateappadmission.GenesisRequest) (*v1.AgentCheckpoint, error) {
	if ctx == nil {
		return nil, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	owned, body, err := snapshotRequest(request)
	if err != nil {
		return nil, err
	}
	ctx, finish, requestKey, responseKey, err := client.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	id, err := client.newRequestID()
	if err != nil {
		return nil, ErrUnavailable
	}
	if _, err = identity.Parse(identity.Request, id); err != nil {
		return nil, ErrUnavailable
	}
	now := client.clock().UnixMilli()
	if now < 0 || uint64(now) > maximumSharedInteger {
		return nil, ErrUnavailable
	}
	encoded, err := canonical.Encode(canonical.Map{"protocol": genesisProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": genesisSchema, "requestId": id, "sentAtUnixMs": now, "body": body}, wireOptions(maximumRequestBytes))
	if err != nil {
		return nil, ErrInvalidRequest
	}
	headers := http.Header{}
	headers.Set(keyHeader, client.keyID)
	headers.Set(signatureHeader, requestMAC(requestKey, client.keyID, encoded))
	response, headers, status, err := client.post(ctx, genesisPath, genesisType, encoded, headers, maximumResponseBytes)
	if err != nil {
		return nil, err
	}
	if len(headers.Values(keyHeader)) != 1 || headers.Get(keyHeader) != client.keyID || len(headers.Values(signatureHeader)) != 1 || !validMAC(headers.Get(signatureHeader), responseMAC(responseKey, client.keyID, id, encoded, status, response)) {
		return nil, ErrUnauthenticatedResponse
	}
	value, err := canonical.Decode(response, wireOptions(maximumResponseBytes))
	if err != nil {
		return nil, ErrInvalidResponse
	}
	m, ok := value.(canonical.Map)
	digest, hashErr := canonical.StructuredDigest("circulusd.engine.genesis-request", 1, body)
	if !ok || len(m) != 7 || hashErr != nil || m["protocol"] != genesisProtocol || m["major"] != int64(1) || m["minor"] != int64(0) || m["schemaDigest"] != genesisSchema || m["requestId"] != id || m["requestDigest"] != digest {
		return nil, ErrInvalidResponse
	}
	payload, ok := m["payload"].(canonical.Map)
	if !ok {
		return nil, ErrInvalidResponse
	}
	if payload["ok"] == false {
		code, ok := payload["error"].(string)
		if len(payload) != 2 || !ok || (code != "INVALID_ARGUMENT" && code != "UNAVAILABLE" && code != "BAD_SOURCE") || (status != 400 && status != 503) {
			return nil, ErrInvalidResponse
		}
		return nil, ErrUnavailable
	}
	if len(payload) != 3 || payload["ok"] != true || status != 200 {
		return nil, ErrInvalidResponse
	}
	identityBytes, err := canonical.Encode(payload["identity"], wireOptions(4096))
	if err != nil {
		return nil, ErrInvalidResponse
	}
	expectedBytes, err := canonical.Encode(requestIdentity(owned), wireOptions(4096))
	if err != nil || !bytes.Equal(identityBytes, expectedBytes) {
		return nil, ErrInvalidResponse
	}
	checkpoint, err := stateappcodec.CheckpointFromValue(payload["checkpoint"])
	if err != nil {
		return nil, ErrInvalidResponse
	}
	return snapshotCheckpoint(checkpoint, owned)
}

func (client *Client) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	var fail dependency.ProbeResponse
	if len(challenge.Nonce) != dependency.ChallengeBytes {
		return fail, ErrInvalidRequest
	}
	ctx, finish, _, _, err := client.begin(ctx)
	if err != nil {
		return fail, err
	}
	defer finish()
	nonce := append([]byte(nil), challenge.Nonce...)
	request, err := canonical.Encode(canonical.Map{"protocol": probeProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": probeSchema, "nonce": canonical.Bytes(nonce)}, wireOptions(256))
	if err != nil {
		return fail, ErrInvalidRequest
	}
	encoded, headers, status, err := client.post(ctx, probePath, probeType, request, http.Header{}, maximumProbeBytes)
	if err != nil {
		return fail, err
	}
	if status != 200 || len(headers.Values(keyHeader)) != 0 || len(headers.Values(signatureHeader)) != 0 {
		return fail, ErrInvalidResponse
	}
	value, err := canonical.Decode(encoded, wireOptions(maximumProbeBytes))
	if err != nil {
		return fail, ErrInvalidResponse
	}
	return proofFromValue(value, nonce)
}
