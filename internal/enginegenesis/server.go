package enginegenesis

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/stateappadmission"
	"github.com/hancomac/circulusd/internal/stateappcodec"
)

type ServerConfig struct {
	KeyID   string
	RootKey []byte
	Source  dependency.Verified[stateappadmission.GenesisProvider]
	Timeout time.Duration
}

func (ServerConfig) String() string   { return "engine-genesis-server-config<redacted>" }
func (ServerConfig) GoString() string { return "engine-genesis-server-config<redacted>" }

type Server struct {
	keyID       string
	requestKey  [32]byte
	responseKey [32]byte
	binding     dependency.Verified[stateappadmission.GenesisProvider]
	source      stateappadmission.GenesisProvider
	clock       func() time.Time
	timeout     time.Duration
}

func (*Server) String() string                       { return "engine-genesis-server<redacted>" }
func (*Server) GoString() string                     { return "engine-genesis-server<redacted>" }
func NewServer(config ServerConfig) (*Server, error) { return newServer(config, time.Now) }
func newServer(config ServerConfig, clock func() time.Time) (*Server, error) {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Timeout <= 0 || config.Timeout > 30*time.Second {
		return nil, ErrInvalidConfig
	}
	source, descriptor, err := config.Source.Open()
	if err != nil {
		return nil, dependency.ErrUnverifiedDependency
	}
	if _, err := dependency.RequireAtomicDomain([]dependency.AtomicGroup{dependency.AtomicEngineGenesis}, config.Source); err != nil {
		return nil, err
	}
	if !keyPattern.MatchString(config.KeyID) || config.KeyID == descriptor.RuntimeKeyID || len(config.RootKey) < 32 || len(config.RootKey) > 256 || clock == nil {
		return nil, ErrInvalidConfig
	}
	return &Server{keyID: config.KeyID, requestKey: directionalKey(config.RootKey, "request"), responseKey: directionalKey(config.RootKey, "response"), binding: config.Source, source: source, clock: clock, timeout: config.Timeout}, nil
}
func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if server == nil || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.RawPath != "" || request.URL.Fragment != "" || (request.URL.Path != genesisPath && request.URL.Path != probePath) {
		writer.WriteHeader(404)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), server.timeout)
	defer cancel()
	request = request.WithContext(ctx)
	controller := http.NewResponseController(writer)
	deadline, _ := ctx.Deadline()
	if err := controller.SetReadDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		writer.WriteHeader(503)
		return
	}
	defer controller.SetReadDeadline(time.Time{})
	if err := controller.SetWriteDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		writer.WriteHeader(503)
		return
	}
	defer controller.SetWriteDeadline(time.Time{})
	if request.Body != nil {
		stop := context.AfterFunc(ctx, func() { _ = request.Body.Close() })
		defer stop()
	}
	if request.Method != http.MethodPost || len(request.Header.Values("Content-Encoding")) != 0 {
		writer.WriteHeader(405)
		return
	}
	contentType, limit := genesisType, maximumRequestBytes
	if request.URL.Path == probePath {
		contentType, limit = probeType, 256
		if len(request.Header.Values(keyHeader)) != 0 || len(request.Header.Values(signatureHeader)) != 0 {
			writer.WriteHeader(400)
			return
		}
	} else if len(request.Header.Values(keyHeader)) != 1 || request.Header.Get(keyHeader) != server.keyID || len(request.Header.Values(signatureHeader)) != 1 || len(request.Header.Get(signatureHeader)) != 64 {
		writer.WriteHeader(401)
		return
	}
	if len(request.Header.Values("Content-Type")) != 1 || request.Header.Get("Content-Type") != contentType || request.ContentLength > int64(limit) {
		writer.WriteHeader(400)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, int64(limit)+1))
	if err != nil || len(body) > limit || request.Context().Err() != nil {
		writer.WriteHeader(400)
		return
	}
	if request.URL.Path == probePath {
		server.probe(writer, request, body)
		return
	}
	if len(request.Header.Values(keyHeader)) != 1 || request.Header.Get(keyHeader) != server.keyID || len(request.Header.Values(signatureHeader)) != 1 || !validMAC(request.Header.Get(signatureHeader), requestMAC(server.requestKey, server.keyID, body)) {
		writer.WriteHeader(401)
		return
	}
	value, err := canonical.Decode(body, wireOptions(maximumRequestBytes))
	if err != nil {
		writer.WriteHeader(400)
		return
	}
	m, ok := value.(canonical.Map)
	if !ok || len(m) != 7 || m["protocol"] != genesisProtocol || m["major"] != int64(1) || m["minor"] != int64(0) || m["schemaDigest"] != genesisSchema {
		writer.WriteHeader(400)
		return
	}
	id, ok := m["requestId"].(string)
	if !ok {
		writer.WriteHeader(400)
		return
	}
	if _, err := identity.Parse(identity.Request, id); err != nil {
		writer.WriteHeader(400)
		return
	}
	sent, ok := safeInteger(m["sentAtUnixMs"], 0)
	now := server.clock().UnixMilli()
	if !ok || now < 0 || uint64(now) > maximumSharedInteger || (sent > uint64(now) && sent-uint64(now) > 30_000) || (sent <= uint64(now) && uint64(now)-sent > 30_000) {
		writer.WriteHeader(400)
		return
	}
	semantic, err := requestFromValue(m["body"])
	if err != nil {
		writer.WriteHeader(400)
		return
	}
	_, ownedBody, err := snapshotRequest(semantic)
	if err != nil {
		writer.WriteHeader(400)
		return
	}
	digest, err := canonical.StructuredDigest("circulusd.engine.genesis-request", 1, ownedBody)
	if err != nil {
		writer.WriteHeader(400)
		return
	}
	failure := func(code string) {
		server.reply(writer, id, digest, body, 503, canonical.Map{"ok": false, "error": code})
	}
	if _, _, err := server.binding.Open(); err != nil {
		failure("UNAVAILABLE")
		return
	}
	retained, _, err := snapshotRequest(semantic)
	if err != nil {
		failure("BAD_SOURCE")
		return
	}
	checkpoint, err := server.source.CreateGenesis(request.Context(), semantic)
	if request.Context().Err() != nil {
		failure("UNAVAILABLE")
		return
	}
	if err != nil {
		failure("UNAVAILABLE")
		return
	}
	checkpoint, err = snapshotCheckpoint(checkpoint, retained)
	if err != nil {
		failure("BAD_SOURCE")
		return
	}
	inline, err := stateappcodec.CheckpointToValue(checkpoint)
	if err != nil {
		failure("BAD_SOURCE")
		return
	}
	server.reply(writer, id, digest, body, 200, canonical.Map{"ok": true, "identity": requestIdentity(retained), "checkpoint": inline})
}
func (server *Server) reply(writer http.ResponseWriter, id, digest string, request []byte, status int, payload canonical.Map) {
	encoded, err := canonical.Encode(canonical.Map{"protocol": genesisProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": genesisSchema, "requestId": id, "requestDigest": digest, "payload": payload}, wireOptions(maximumResponseBytes))
	if err != nil {
		writer.WriteHeader(503)
		return
	}
	writer.Header().Set("Content-Type", genesisType)
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set(keyHeader, server.keyID)
	writer.Header().Set(signatureHeader, responseMAC(server.responseKey, server.keyID, id, request, status, encoded))
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}
func (server *Server) probe(writer http.ResponseWriter, request *http.Request, body []byte) {
	if len(request.Header.Values(keyHeader)) != 0 || len(request.Header.Values(signatureHeader)) != 0 {
		writer.WriteHeader(400)
		return
	}
	value, err := canonical.Decode(body, wireOptions(256))
	if err != nil {
		writer.WriteHeader(400)
		return
	}
	m, ok := value.(canonical.Map)
	if !ok || len(m) != 5 || m["protocol"] != probeProtocol || m["major"] != int64(1) || m["minor"] != int64(0) || m["schemaDigest"] != probeSchema {
		writer.WriteHeader(400)
		return
	}
	nonce, ok := m["nonce"].(canonical.Bytes)
	if !ok || len(nonce) != dependency.ChallengeBytes {
		writer.WriteHeader(400)
		return
	}
	_, descriptor, err := server.binding.Open()
	if err != nil {
		writer.WriteHeader(503)
		return
	}
	proof, err := server.source.ProbeProduction(request.Context(), dependency.ProbeChallenge{Nonce: append([]byte(nil), nonce...)})
	if err != nil || request.Context().Err() != nil || !reflect.DeepEqual(proof.Descriptor, descriptor) {
		writer.WriteHeader(503)
		return
	}
	response, err := proofValue(proof, nonce)
	if err != nil {
		writer.WriteHeader(503)
		return
	}
	encoded, err := canonical.Encode(response, wireOptions(maximumProbeBytes))
	if err != nil {
		writer.WriteHeader(503)
		return
	}
	writer.Header().Set("Content-Type", probeType)
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(200)
	_, _ = writer.Write(encoded)
}
