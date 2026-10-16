package mcpgateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const streamableHTTPProtocol = "2025-06-18"

// StreamableHTTPConfig is an immutable, anonymous operator registry. HTTP is
// accepted only for literal loopback addresses; other targets require HTTPS.
// No caller can supply headers, credentials, a client, or a RoundTripper.
type StreamableHTTPConfig struct {
	Targets                   map[string]string
	ProtocolVersion           string
	MaximumRequestBytes       int
	MaximumResponseBytes      int
	MaximumEvents             int
	MaximumConcurrentRequests int
	RequestTimeout            time.Duration
}

func (StreamableHTTPConfig) String() string   { return "mcp-http-config<redacted>" }
func (StreamableHTTPConfig) GoString() string { return "mcp-http-config<redacted>" }

type StreamableHTTPTransport struct {
	config  StreamableHTTPConfig
	targets map[string]*url.URL
	client  *http.Client
	slots   chan struct{}
}

func (*StreamableHTTPTransport) String() string   { return "mcp-http-transport<redacted>" }
func (*StreamableHTTPTransport) GoString() string { return "mcp-http-transport<redacted>" }

func NewStreamableHTTPTransport(config StreamableHTTPConfig) (*StreamableHTTPTransport, error) {
	if config.ProtocolVersion != streamableHTTPProtocol || len(config.Targets) == 0 || len(config.Targets) > 256 ||
		config.MaximumRequestBytes < 128 || config.MaximumRequestBytes > 16<<20 ||
		config.MaximumResponseBytes < 128 || config.MaximumResponseBytes > 16<<20 ||
		config.MaximumEvents < 1 || config.MaximumEvents > 4096 ||
		config.MaximumConcurrentRequests < 1 || config.MaximumConcurrentRequests > 256 ||
		config.RequestTimeout < time.Millisecond || config.RequestTimeout > 5*time.Minute {
		return nil, ErrInvalidConfiguration
	}
	targets := make(map[string]*url.URL, len(config.Targets))
	registry := make(map[string]string, len(config.Targets))
	for ref, raw := range config.Targets {
		u, err := url.Parse(raw)
		if err != nil || !validBoundedText(ref, 512) || u == nil || u.Host == "" || u.User != nil ||
			u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || u.Opaque != "" ||
			(u.Scheme != "https" && u.Scheme != "http") || len(raw) > 4096 {
			return nil, ErrInvalidConfiguration
		}
		if u.Scheme == "http" {
			ip := net.ParseIP(u.Hostname())
			if ip == nil || !ip.IsLoopback() {
				return nil, ErrInvalidConfiguration
			}
		}
		registry[ref], targets[ref] = raw, u
	}
	config.Targets = registry
	// Fresh connections, no GetBody and no idempotency header prevent net/http
	// from replaying an effectful POST after a stale pooled connection fails.
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: config.RequestTimeout}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true,
		DisableCompression: true, ForceAttemptHTTP2: false, MaxResponseHeaderBytes: 16 << 10,
		ResponseHeaderTimeout: config.RequestTimeout, TLSHandshakeTimeout: config.RequestTimeout}
	client := &http.Client{Transport: transport, Timeout: config.RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &StreamableHTTPTransport{config: config, targets: targets, client: client,
		slots: make(chan struct{}, config.MaximumConcurrentRequests)}, nil
}

type mcpRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// decodeMCPMessage rejects duplicate keys, invalid UTF-8, and excessive nesting
// before decoding the envelope. Server requests are never dispatched by this port.
func decodeMCPMessage(data []byte) (mcpRPCMessage, error) {
	var message mcpRPCMessage
	if !utf8.Valid(data) {
		return message, ErrProtocolMismatch
	}
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return ErrProtocolMismatch
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				keys := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return err
					}
					text, ok := key.(string)
					if !ok || keys[text] {
						return ErrProtocolMismatch
					}
					keys[text] = true
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			default:
				return ErrProtocolMismatch
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if walk(0) != nil {
		return message, ErrProtocolMismatch
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return message, ErrProtocolMismatch
	}
	if json.Unmarshal(data, &message) != nil || message.JSONRPC != "2.0" {
		return mcpRPCMessage{}, ErrProtocolMismatch
	}
	return message, nil
}

func validMCPSessionID(id string) bool {
	if len(id) > 512 {
		return false
	}
	for i := range id {
		if id[i] < 0x21 || id[i] > 0x7e {
			return false
		}
	}
	return true
}

// terminateSession releases a completed invocation's remote session. A server
// may decline client-driven termination (405), or another retained handle may
// already have deleted the same session (404). Neither changes its durable result.
func (transport *StreamableHTTPTransport) terminateSession(ctx context.Context, targetRef, session string) error {
	if transport == nil || ctx == nil || session == "" || !validMCPSessionID(session) {
		return ErrInvalidRequest
	}
	target, found := transport.targets[targetRef]
	if !found {
		return ErrInvalidRequest
	}
	ctx, cancel := context.WithTimeout(ctx, transport.config.RequestTimeout)
	defer cancel()
	select {
	case transport.slots <- struct{}{}:
		defer func() { <-transport.slots }()
	case <-ctx.Done():
		return ctx.Err()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, target.String(), nil)
	if err != nil {
		return ErrInvalidRequest
	}
	req.Close = true
	req.Header.Set("MCP-Session-Id", session)
	req.Header.Set("MCP-Protocol-Version", transport.config.ProtocolVersion)
	response, err := transport.client.Do(req)
	if err != nil {
		return ErrProviderUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode >= 200 && response.StatusCode < 300 || response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusMethodNotAllowed {
		return nil
	}
	return ErrProviderUnavailable
}

func (transport *StreamableHTTPTransport) Exchange(ctx context.Context, request MCPWireRequest) (MCPWireResponse, error) {
	if transport == nil || ctx == nil {
		return MCPWireResponse{}, ErrInvalidRequest
	}
	target, found := transport.targets[request.TargetRef]
	if !found || len(request.MessageJSON) > transport.config.MaximumRequestBytes || !validMCPSessionID(request.ConnectionRef) {
		return MCPWireResponse{}, ErrInvalidRequest
	}
	message, err := decodeMCPMessage(request.MessageJSON)
	if err != nil || message.Method == "" || len(message.Result) != 0 || len(message.Error) != 0 {
		return MCPWireResponse{}, ErrProtocolMismatch
	}
	var id string
	if len(message.ID) != 0 && (json.Unmarshal(message.ID, &id) != nil || !validBoundedText(id, 512)) {
		return MCPWireResponse{}, ErrProtocolMismatch
	}
	select {
	case transport.slots <- struct{}{}:
		defer func() { <-transport.slots }()
	case <-ctx.Done():
		return MCPWireResponse{}, ctx.Err()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(request.MessageJSON))
	if err != nil {
		return MCPWireResponse{}, ErrInvalidRequest
	}
	req.GetBody = nil
	req.Close = true
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if message.Method != "initialize" {
		req.Header.Set("MCP-Protocol-Version", transport.config.ProtocolVersion)
	}
	if request.ConnectionRef != "" {
		req.Header.Set("MCP-Session-Id", request.ConnectionRef)
	}
	response, err := transport.client.Do(req)
	if err != nil {
		return MCPWireResponse{}, ErrProviderUnavailable
	}
	defer response.Body.Close()
	session := response.Header.Get("MCP-Session-Id")
	if len(response.Header.Values("MCP-Session-Id")) > 1 || !validMCPSessionID(session) ||
		(message.Method != "initialize" && session != "" && session != request.ConnectionRef) {
		return MCPWireResponse{}, ErrProtocolMismatch
	}
	if session == "" {
		session = request.ConnectionRef
	}
	reader := &io.LimitedReader{R: response.Body, N: int64(transport.config.MaximumResponseBytes) + 1}
	if id == "" {
		body, err := io.ReadAll(reader)
		if err != nil || response.StatusCode != http.StatusAccepted || len(body) != 0 {
			return MCPWireResponse{}, ErrProtocolMismatch
		}
		return MCPWireResponse{ConnectionRef: session}, nil
	}
	if response.StatusCode != http.StatusOK {
		return MCPWireResponse{}, ErrProviderUnavailable
	}
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil {
		return MCPWireResponse{}, ErrProtocolMismatch
	}
	if media == "application/json" {
		data, err := io.ReadAll(reader)
		if err != nil || len(data) > transport.config.MaximumResponseBytes {
			return MCPWireResponse{}, ErrProtocolMismatch
		}
		if validMCPResponse(data, id) != nil {
			return MCPWireResponse{}, ErrProtocolMismatch
		}
		return MCPWireResponse{ConnectionRef: session, MessageJSON: data}, nil
	}
	if media != "text/event-stream" {
		return MCPWireResponse{}, ErrProtocolMismatch
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), transport.config.MaximumResponseBytes+1)
	// SSE recognizes CR, LF, and CRLF. Consume CR immediately so a complete
	// event does not wait for another byte or EOF; swallow its optional LF on
	// the next split, including when the pair crosses an HTTP read boundary.
	skipLF := false
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		start := 0
		if skipLF && len(data) != 0 {
			skipLF = false
			if data[0] == '\n' {
				start = 1
			}
		}
		if end := bytes.IndexAny(data[start:], "\r\n"); end >= 0 {
			end += start
			skipLF = data[end] == '\r'
			return end + 1, data[start:end], nil
		}
		if atEOF && len(data) > start {
			return len(data), data[start:], nil
		}
		return start, nil, nil
	})
	var data []byte
	events := 0
	firstLine := true
	for scanner.Scan() {
		line := scanner.Text()
		if firstLine {
			line = strings.TrimPrefix(line, "\uFEFF")
			firstLine = false
		}
		if line == "" {
			if len(data) == 0 {
				continue
			}
			events++
			if events > transport.config.MaximumEvents || reader.N <= 0 {
				return MCPWireResponse{}, ErrProtocolMismatch
			}
			message, err := decodeMCPMessage(data)
			if err != nil {
				return MCPWireResponse{}, err
			}
			if message.Method != "" {
				if len(message.ID) != 0 || !strings.HasPrefix(message.Method, "notifications/") {
					return MCPWireResponse{}, ErrProtocolMismatch
				}
			} else {
				if validMCPResponse(data, id) != nil {
					return MCPWireResponse{}, ErrProtocolMismatch
				}
				return MCPWireResponse{ConnectionRef: session, MessageJSON: bytes.Clone(data)}, nil
			}
			data = nil
		} else if strings.HasPrefix(line, "data:") {
			part := strings.TrimPrefix(line, "data:")
			part = strings.TrimPrefix(part, " ")
			if len(data) != 0 {
				data = append(data, '\n')
			}
			data = append(data, part...)
			if len(data) > transport.config.MaximumResponseBytes {
				return MCPWireResponse{}, ErrProtocolMismatch
			}
		}
	}
	return MCPWireResponse{}, ErrProtocolMismatch
}

func validMCPResponse(data []byte, id string) error {
	message, err := decodeMCPMessage(data)
	var responseID string
	if err != nil || message.Method != "" || len(message.Params) != 0 || json.Unmarshal(message.ID, &responseID) != nil || responseID != id ||
		(len(message.Result) == 0) == (len(message.Error) == 0) {
		return ErrProtocolMismatch
	}
	return nil
}
