package celldbridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celld"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
)

type ClientConfig struct {
	Endpoint string
	KeyID    string
	RootKey  []byte
	Timeout  time.Duration
}

func (ClientConfig) String() string   { return "native-storage-client-config<redacted>" }
func (ClientConfig) GoString() string { return "native-storage-client-config<redacted>" }

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

var _ NativeTransport = (*Client)(nil)

func (*Client) String() string   { return "native-storage-client<redacted>" }
func (*Client) GoString() string { return "native-storage-client<redacted>" }

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
	if err != nil || port == 0 || ip == nil || !ip.IsLoopback() || strconv.FormatUint(port, 10) != endpoint.Port() || endpoint.Host != net.JoinHostPort(ip.String(), endpoint.Port()) || endpoint.String() != config.Endpoint || !keyPattern.MatchString(config.KeyID) || len(config.RootKey) != 32 || config.Timeout <= 0 || config.Timeout > 30*time.Second || clock == nil || newID == nil {
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
	// Close cancels with ErrClosed so an interrupted request does not look
	// like caller cancellation.
	active, cancel := context.WithCancelCause(ctx)
	stop := context.AfterFunc(client.lifecycle, func() { cancel(ErrClosed) })
	return active, func() { stop(); cancel(nil); client.active.Done() }, client.requestKey, client.responseKey, nil
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
			if errors.Is(context.Cause(ctx), ErrClosed) {
				return nil, nil, 0, ErrClosed
			}
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
			if errors.Is(context.Cause(ctx), ErrClosed) {
				return nil, nil, 0, ErrClosed
			}
			return nil, nil, 0, err
		}
		return nil, nil, 0, ErrInvalidResponse
	}
	if len(encoded) > limit {
		return nil, nil, 0, ErrInvalidResponse
	}
	return encoded, response.Header.Clone(), response.StatusCode, nil
}

// call authenticates the complete response before interpreting a conflict.
// A lost or unsigned commit response can never authorize callback replay.
func (client *Client) call(ctx context.Context, operation string, body canonical.Map) (canonical.Map, error) {
	ctx, finish, requestKey, responseKey, err := client.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	id, err := client.newRequestID()
	if err != nil {
		return nil, ErrUnavailable
	}
	if _, err := identity.Parse(identity.Request, id); err != nil {
		return nil, ErrUnavailable
	}
	now := client.clock().UnixMilli()
	if now < 0 || uint64(now) > MaximumRevision {
		return nil, ErrUnavailable
	}
	envelope := canonical.Map{"protocol": storageProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": storageSchema,
		"requestId": id, "sentAtUnixMs": now, "operation": operation, "body": body}
	encoded, err := canonical.Encode(envelope, wireOptions(MaximumTransactionBytes))
	if err != nil {
		return nil, ErrInvalidRequest
	}
	digest, err := storageDigest("circulusd.native.storage.request", envelope)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	headers := http.Header{}
	headers.Set(keyHeader, client.keyID)
	headers.Set(signatureHeader, requestMAC(requestKey, client.keyID, encoded))
	response, headers, status, err := client.post(ctx, transactionPath, transactionType, encoded, headers, MaximumTransactionBytes)
	if err != nil {
		return nil, err
	}
	if len(headers.Values(keyHeader)) != 1 || headers.Get(keyHeader) != client.keyID || len(headers.Values(signatureHeader)) != 1 ||
		!validMAC(headers.Get(signatureHeader), responseMAC(responseKey, client.keyID, id, encoded, status, response)) {
		return nil, ErrUnauthenticatedResponse
	}
	value, err := canonical.Decode(response, wireOptions(MaximumTransactionBytes))
	if err != nil {
		return nil, ErrInvalidResponse
	}
	m, ok := value.(canonical.Map)
	if !ok || len(m) != 7 || m["protocol"] != storageProtocol || m["major"] != int64(1) || m["minor"] != int64(0) ||
		m["schemaDigest"] != storageSchema || m["requestId"] != id || m["requestDigest"] != digest {
		return nil, ErrInvalidResponse
	}
	payload, ok := m["payload"].(canonical.Map)
	if !ok {
		return nil, ErrInvalidResponse
	}
	success, ok := payload["ok"].(bool)
	if !ok {
		return nil, ErrInvalidResponse
	}
	if success {
		result, ok := payload["result"].(canonical.Map)
		if status != 200 || len(payload) != 2 || !ok {
			return nil, ErrInvalidResponse
		}
		return result, nil
	}
	if len(payload) != 3 {
		return nil, ErrInvalidResponse
	}
	code, ok := payload["error"].(string)
	if !ok {
		return nil, ErrInvalidResponse
	}
	notCommitted, ok := payload["notCommitted"].(bool)
	if !ok {
		return nil, ErrInvalidResponse
	}
	switch code {
	case "SNAPSHOT_CONFLICT":
		if status == 409 && notCommitted && (operation == "receipt" || operation == "commit") {
			return nil, ErrSnapshotConflict
		}
	case "RECEIPT_CONFLICT":
		if status == 409 && notCommitted && operation == "commit" {
			return nil, celld.ErrIdempotencyConflict
		}
	case "INVALID_ARGUMENT":
		if status == 400 && notCommitted {
			return nil, ErrInvalidRequest
		}
	case "CORRUPT_STATE":
		if status == 503 && notCommitted {
			return nil, ErrUnavailable
		}
	case "UNAVAILABLE":
		if status == 503 && !notCommitted {
			return nil, ErrUnavailable
		}
	}
	return nil, ErrInvalidResponse
}

func (client *Client) ReadSnapshot(ctx context.Context, request SnapshotRequest) (Snapshot, error) {
	var result Snapshot
	if !validIdentifier(request.ObjectID) {
		return result, ErrInvalidRequest
	}
	value, err := client.call(ctx, "snapshot", canonical.Map{"objectId": request.ObjectID})
	if err != nil {
		return result, err
	}
	if len(value) != 2 {
		return result, ErrInvalidResponse
	}
	ref, err := refFromValue(value["snapshot"])
	if err != nil || ref.ObjectID != request.ObjectID {
		return result, ErrInvalidResponse
	}
	state, ok := value["state"].(canonical.Bytes)
	if !ok || len(state) > MaximumStateBytes || (!ref.Exists && len(state) != 0) || celld.Digest(sha256.Sum256(state)) != ref.StateDigest {
		return result, ErrInvalidResponse
	}
	return Snapshot{SnapshotRef: ref, State: bytes.Clone(state)}, nil
}

func (client *Client) ReadReceipt(ctx context.Context, request ReceiptRequest) (ReceiptResult, error) {
	var result ReceiptResult
	ref, err := refValue(request.Snapshot)
	if err != nil || !validIdentifier(request.CommandID) {
		return result, ErrInvalidRequest
	}
	value, err := client.call(ctx, "receipt", canonical.Map{"snapshot": ref, "commandId": request.CommandID})
	if err != nil {
		return result, err
	}
	if len(value) != 4 {
		return result, ErrInvalidResponse
	}
	result.Snapshot, err = refFromValue(value["snapshot"])
	if err != nil || result.Snapshot != request.Snapshot || value["commandId"] != request.CommandID {
		return ReceiptResult{}, ErrInvalidResponse
	}
	result.CommandID = request.CommandID
	var ok bool
	result.Found, ok = value["found"].(bool)
	if !ok {
		return ReceiptResult{}, ErrInvalidResponse
	}
	if !result.Found {
		if value["receipt"] != nil {
			return ReceiptResult{}, ErrInvalidResponse
		}
		return result, nil
	}
	result.Receipt, err = receiptFromValue(value["receipt"])
	if err != nil {
		return ReceiptResult{}, err
	}
	return result, nil
}

func (client *Client) CompareAndCommit(ctx context.Context, request CommitRequest) (CommitResult, error) {
	var result CommitResult
	body, err := commitValue(request, true)
	if err != nil {
		return result, err
	}
	claimed := body["requestDigest"]
	delete(body, "requestDigest")
	digest, err := storageDigest("circulusd.native.storage.commit", body)
	if err != nil || claimed != digest {
		return result, ErrInvalidRequest
	}
	body["requestDigest"] = claimed
	expected := request.Snapshot
	expected.Exists = true
	expected.Revision++
	if request.StateWritten {
		expected.StateDigest = celld.Digest(sha256.Sum256(body["state"].(canonical.Bytes)))
	}
	value, err := client.call(ctx, "commit", body)
	if err != nil {
		return result, err
	}
	if len(value) != 3 || value["requestDigest"] != claimed {
		return result, ErrInvalidResponse
	}
	result.Snapshot, err = refFromValue(value["snapshot"])
	if err != nil || result.Snapshot != expected {
		return CommitResult{}, ErrInvalidResponse
	}
	result.RequestDigest = request.RequestDigest
	result.Token, err = tokenFromValue(value["token"])
	if err != nil || result.Token.ObjectID != expected.ObjectID || result.Token.Revision != expected.Revision {
		return CommitResult{}, ErrInvalidResponse
	}
	return result, nil
}

func (client *Client) ConfirmBarrier(ctx context.Context, request BarrierRequest) (BarrierResult, error) {
	var result BarrierResult
	token, err := tokenValue(request.Token)
	if err != nil || request.Marker == ([32]byte{}) {
		return result, ErrInvalidRequest
	}
	value, err := client.call(ctx, "barrier", canonical.Map{"token": token, "marker": canonical.Bytes(bytes.Clone(request.Marker[:]))})
	if err != nil {
		return result, err
	}
	if len(value) != 4 {
		return result, ErrInvalidResponse
	}
	result.Token, err = tokenFromValue(value["token"])
	if err != nil || result.Token != request.Token {
		return BarrierResult{}, ErrInvalidResponse
	}
	marker, ok := value["marker"].(canonical.Bytes)
	if !ok || len(marker) != 32 || !bytes.Equal(marker, request.Marker[:]) {
		return BarrierResult{}, ErrInvalidResponse
	}
	copy(result.Marker[:], marker)
	result.ObservedRevision, ok = uintValue(value["observedRevision"])
	if !ok || result.ObservedRevision < request.Token.Revision {
		return BarrierResult{}, ErrInvalidResponse
	}
	result.BarrierSerial, ok = uintValue(value["barrierSerial"])
	if !ok || result.BarrierSerial == 0 {
		return BarrierResult{}, ErrInvalidResponse
	}
	return result, nil
}

func (client *Client) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	var result dependency.ProbeResponse
	if len(challenge.Nonce) != dependency.ChallengeBytes {
		return result, ErrInvalidRequest
	}
	ctx, finish, _, _, err := client.begin(ctx)
	if err != nil {
		return result, err
	}
	defer finish()
	nonce := bytes.Clone(challenge.Nonce)
	request, err := canonical.Encode(canonical.Map{"protocol": probeProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": probeSchema, "nonce": canonical.Bytes(nonce)}, wireOptions(256))
	if err != nil {
		return result, ErrInvalidRequest
	}
	response, headers, status, err := client.post(ctx, probePath, probeType, request, http.Header{}, maximumProbeBytes)
	if err != nil {
		return result, err
	}
	if status != 200 || len(headers.Values(keyHeader)) != 0 || len(headers.Values(signatureHeader)) != 0 {
		return result, ErrInvalidResponse
	}
	value, err := canonical.Decode(response, wireOptions(maximumProbeBytes))
	if err != nil {
		return result, ErrInvalidResponse
	}
	return proofFromValue(value, nonce)
}
