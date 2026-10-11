package providerresult

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/stateappbroker"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

const (
	keyHeader            = "X-Circulus-State-Key-Id"
	signatureHeader      = "X-Circulus-State-Signature"
	probePath            = "/circulusd/state/v1/production:probe"
	probeContentType     = "application/vnd.circulusd.state-production-probe+cbor"
	probeProtocol        = "circulus.state-production-probe.v1alpha1"
	probeSchemaDigest    = "sha256:33c8297cba9d6460e219e31e8c080927ed6275407c6eb159ea1f4d06fc87910f"
	maximumSharedInteger = int64(9_007_199_254_740_991)
)

var keyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type ServerConfig struct {
	Source  dependency.Verified[stateappbroker.ResultResolver]
	KeyID   string
	RootKey []byte
	Timeout time.Duration
}

func (ServerConfig) String() string   { return "provider-result-server-config<redacted>" }
func (ServerConfig) GoString() string { return "provider-result-server-config<redacted>" }

// Server exposes only authenticated immutable reads and the native challenge
// of its exact qualified operational source. It does not turn a reference
// ledger, normalization callback or opaque artifact ID into a qualified source.
// The listener and dedicated credential are supplied by trusted composition.
type Server struct {
	source                  stateappbroker.ResultResolver
	binding                 dependency.Verified[stateappbroker.ResultResolver]
	descriptor              dependency.Descriptor
	keyID                   string
	requestKey, responseKey [32]byte
	timeout                 time.Duration
	clock                   func() time.Time
}

func (*Server) String() string   { return "provider-result-server<redacted>" }
func (*Server) GoString() string { return "provider-result-server<redacted>" }

func NewServer(config ServerConfig) (*Server, error) {
	return newServer(config, time.Now)
}

func newServer(config ServerConfig, clock func() time.Time) (*Server, error) {
	source, descriptor, err := config.Source.Open()
	if err != nil || nilInterface(source) || !slices.Contains(descriptor.AtomicGroups, dependency.AtomicEffectLifecycle) {
		return nil, dependency.ErrUnverifiedDependency
	}
	if !keyPattern.MatchString(config.KeyID) || len(config.RootKey) < 32 || len(config.RootKey) > 256 || clock == nil || config.Timeout <= 0 || config.Timeout > 30*time.Second {
		return nil, dependency.ErrInvalidConfiguration
	}
	root := bytes.Clone(config.RootKey)
	defer clear(root)
	return &Server{source: source, binding: config.Source, descriptor: descriptor,
		keyID: config.KeyID, requestKey: mac(root, []byte("circulusd.state-ingress.key.request.v1\x00")),
		responseKey: mac(root, []byte("circulusd.state-ingress.key.response.v1\x00")), timeout: config.Timeout, clock: clock}, nil
}

func (server *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if server == nil || nilInterface(server.source) {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if _, _, err := server.binding.Open(); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	// Bound the entire HTTP operation, including a client that stalls while
	// sending its body. Request.Body permits Close concurrently with Read and
	// must unblock it; the controller additionally bounds actual socket I/O.
	ctx, cancel := context.WithTimeout(r.Context(), server.timeout)
	defer cancel()
	r = r.WithContext(ctx)
	controller := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	_ = controller.SetReadDeadline(deadline)
	_ = controller.SetWriteDeadline(deadline)
	defer controller.SetReadDeadline(time.Time{})
	defer controller.SetWriteDeadline(time.Time{})
	stopClose := context.AfterFunc(ctx, func() { _ = r.Body.Close() })
	defer stopClose()
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Fragment != "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.URL.Path == probePath {
		server.serveProbe(w, r)
		return
	}
	if r.URL.Path != stateappclient.ProviderResultPath {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if !oneHeader(r.Header, "Content-Type", stateappclient.ProviderResultContentType) ||
		!oneHeader(r.Header, keyHeader, server.keyID) || len(r.Header.Values(signatureHeader)) != 1 || hasHeader(r.Header, "Content-Encoding") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	body, err := readBody(r, 4096)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	requestDigest := sha256.Sum256(body)
	signatureText := r.Header.Get(signatureHeader)
	if len(signatureText) != 64 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	signature, err := hex.DecodeString(signatureText)
	want := mac(server.requestKey[:], frame([]byte(stateappclient.ProviderResultRequestMACDomain), []byte(server.keyID), []byte(r.Method), []byte(r.URL.Path), requestDigest[:]))
	if err != nil || len(signature) != 32 || hex.EncodeToString(signature) != signatureText || !hmac.Equal(signature, want[:]) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	value, err := canonical.Decode(body, canonical.Options{MaxBytes: 4096, MaxDepth: 3, MaxItems: 64})
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	record, ok := value.(canonical.Map)
	if !ok || len(record) != 14 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	requestID, ok := record["requestId"].(string)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, err := identity.Parse(identity.Request, requestID); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	writeError := func() {
		server.writeResponse(w, requestID, requestDigest, canonical.Map{"ok": false, "error": canonical.Map{"code": "INVALID_ARGUMENT", "message": "The RPC request is invalid."}})
	}
	if record["protocol"] != stateappclient.ProviderResultProtocol || record["major"] != int64(1) || record["minor"] != int64(0) || record["schemaDigest"] != stateappclient.ProviderResultSchemaDigest() {
		writeError()
		return
	}
	sentAt, ok := record["sentAtUnixMs"].(int64)
	now := server.clock().UnixMilli()
	if !ok || sentAt < 0 || sentAt > maximumSharedInteger || now < 0 || now > maximumSharedInteger || sentAt < now-30_000 || sentAt > now+30_000 {
		writeError()
		return
	}
	request, err := parseRequest(record)
	if err != nil {
		writeError()
		return
	}
	result, err := server.source.ResolveResult(ctx, request)
	if err != nil || ctx.Err() != nil {
		server.writeResponse(w, requestID, requestDigest, canonical.Map{"ok": false, "error": canonical.Map{"code": "INTERNAL_ERROR", "message": "The operation could not be completed."}})
		return
	}
	if result.Request != request || len(result.CanonicalCBOR) < 1 || len(result.CanonicalCBOR) > stateappclient.MaximumProviderResultBytes {
		server.writeResponse(w, requestID, requestDigest, canonical.Map{"ok": false, "error": canonical.Map{"code": "INTERNAL_ERROR", "message": "The operation could not be completed."}})
		return
	}
	body = bytes.Clone(result.CanonicalCBOR)
	digest := sha256.Sum256(body)
	if result.Request != request || result.PayloadDigest != broker.Digest(digest) || !validBody(body) {
		server.writeResponse(w, requestID, requestDigest, canonical.Map{"ok": false, "error": canonical.Map{"code": "INTERNAL_ERROR", "message": "The operation could not be completed."}})
		return
	}
	server.writeResponse(w, requestID, requestDigest, canonical.Map{"ok": true, "result": canonical.Map{
		"request": requestValue(request), "payloadDigest": fmt.Sprintf("sha256:%x", digest), "canonicalCbor": canonical.Bytes(body),
	}})
}

func (server *Server) writeResponse(w http.ResponseWriter, requestID string, requestDigest [32]byte, payload canonical.Map) {
	body, err := canonical.Encode(canonical.Map{"protocol": "circulus.v1alpha1", "major": int64(1), "minor": int64(0),
		"schemaDigest": stateappclient.ProviderResultSchemaDigest(), "requestId": requestID, "payload": payload},
		canonical.Options{MaxBytes: stateappclient.MaximumProviderResultBytes + 65_536, MaxDepth: 72, MaxItems: 100_000})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	digest := sha256.Sum256(body)
	signature := mac(server.responseKey[:], frame([]byte(stateappclient.ProviderResultResponseMACDomain), []byte(server.keyID), []byte(requestID), requestDigest[:],
		[]byte(strconv.Itoa(http.StatusOK)), []byte(stateappclient.ProviderResultContentType), digest[:]))
	w.Header().Set("Content-Type", stateappclient.ProviderResultContentType)
	w.Header().Set(keyHeader, server.keyID)
	w.Header().Set(signatureHeader, hex.EncodeToString(signature[:]))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func parseRequest(record canonical.Map) (stateappbroker.ResultRequest, error) {
	request := stateappbroker.ResultRequest{}
	for field, target := range map[string]*identity.ID{"tenantId": &request.TenantID, "workspaceId": &request.WorkspaceID,
		"sessionId": &request.SessionID, "effectId": &request.EffectID, "invocationId": &request.InvocationID,
		"externalCommitId": &request.ExternalCommitID, "resultRef": &request.ResultRef} {
		text, ok := record[field].(string)
		if !ok {
			return request, broker.ErrInvalidRequest
		}
		kind := map[string]identity.Kind{"tenantId": identity.Tenant, "workspaceId": identity.Workspace, "sessionId": identity.Session,
			"effectId": identity.Effect, "invocationId": identity.Invocation, "externalCommitId": identity.Commit, "resultRef": identity.Artifact}[field]
		parsed, err := identity.Parse(kind, text)
		if err != nil {
			return request, broker.ErrInvalidRequest
		}
		*target = parsed
	}
	digestText, ok := record["requestDigest"].(string)
	if !ok || len(digestText) != 71 || digestText[:7] != "sha256:" {
		return request, broker.ErrInvalidRequest
	}
	digest, err := hex.DecodeString(digestText[7:])
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != digestText[7:] {
		return request, broker.ErrInvalidRequest
	}
	copy(request.RequestDigest[:], digest)
	if err := stateappclient.ValidateProviderResultRequest(requestWire(request)); err != nil {
		return request, err
	}
	return request, nil
}

func requestValue(request stateappbroker.ResultRequest) canonical.Map {
	wire := requestWire(request)
	return canonical.Map{"tenantId": wire.TenantID, "workspaceId": wire.WorkspaceID, "sessionId": wire.SessionID,
		"effectId": wire.EffectID, "invocationId": wire.InvocationID, "requestDigest": wire.RequestDigest,
		"externalCommitId": wire.ExternalCommitID, "resultRef": wire.ResultRef}
}

// The Ed25519 signature comes only from the qualified source, never this HTTP
// adapter or its read HMAC. Compare its live descriptor to the sealed source.
func (server *Server) serveProbe(w http.ResponseWriter, r *http.Request) {
	if !oneHeader(r.Header, "Content-Type", probeContentType) || hasHeader(r.Header, "Content-Encoding") || hasHeader(r.Header, keyHeader) || hasHeader(r.Header, signatureHeader) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	body, err := readBody(r, 256)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	value, err := canonical.Decode(body, canonical.Options{MaxBytes: 256, MaxDepth: 2, MaxItems: 16})
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	record, ok := value.(canonical.Map)
	if !ok || len(record) != 5 || record["protocol"] != probeProtocol || record["major"] != int64(1) || record["minor"] != int64(0) || record["schemaDigest"] != probeSchemaDigest {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	nonce, ok := record["nonce"].(canonical.Bytes)
	if !ok || len(nonce) != dependency.ChallengeBytes {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	response, err := server.source.ProbeProduction(ctx, dependency.ProbeChallenge{Nonce: bytes.Clone(nonce)})
	want, digestErr := dependency.ProbeSigningDigest(server.descriptor, nonce)
	got, responseErr := dependency.ProbeSigningDigest(response.Descriptor, nonce)
	if err != nil || ctx.Err() != nil || digestErr != nil || responseErr != nil || got != want || response.KeyID != server.descriptor.RuntimeKeyID || len(response.Signature) != ed25519.SignatureSize {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	d := response.Descriptor
	groups := make(canonical.Array, len(d.AtomicGroups))
	for i, group := range d.AtomicGroups {
		groups[i] = string(group)
	}
	body, err = canonical.Encode(canonical.Map{"protocol": probeProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": probeSchemaDigest,
		"algorithm": "ed25519", "keyId": response.KeyID, "signature": canonical.Bytes(bytes.Clone(response.Signature)), "descriptor": canonical.Map{
			"schemaVersion": int64(d.SchemaVersion), "backendKind": d.BackendKind, "buildDigest": d.BuildDigest, "applicationDigest": d.ApplicationDigest,
			"instanceId": d.InstanceID, "transactionDomainId": d.TransactionDomainID, "durabilityClass": d.DurabilityClass,
			"conformanceRunId": d.ConformanceRunID, "conformanceDigest": d.ConformanceDigest, "runtimeKeyId": d.RuntimeKeyID,
			"probeEpoch": d.ProbeEpoch, "productionEligible": d.ProductionEligible, "atomicGroups": groups}},
		canonical.Options{MaxBytes: 32 << 10, MaxDepth: 8, MaxItems: 128})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", probeContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func readBody(r *http.Request, maximum int64) ([]byte, error) {
	if r.ContentLength > maximum {
		return nil, stateappclient.ErrInvalidRequest
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maximum+1))
	if err != nil || int64(len(body)) > maximum {
		return nil, stateappclient.ErrInvalidRequest
	}
	return body, nil
}

func oneHeader(headers http.Header, key, value string) bool {
	values := headers.Values(key)
	return len(values) == 1 && values[0] == value
}
func hasHeader(headers http.Header, key string) bool {
	_, ok := headers[http.CanonicalHeaderKey(key)]
	return ok
}
func mac(key, value []byte) [32]byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(value)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}
func frame(parts ...[]byte) []byte {
	var framed []byte
	for _, part := range parts {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		framed = append(framed, size[:]...)
		framed = append(framed, part...)
	}
	return framed
}
