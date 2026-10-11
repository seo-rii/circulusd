package providerresult

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	proof "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/stateappbroker"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

type resultSource struct {
	*proof.ProductionProofs
	request stateappbroker.ResultRequest
	body    []byte
	mode    string
	calls   atomic.Int32
	probes  atomic.Int32
}

func (source *resultSource) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	source.probes.Add(1)
	response, err := source.ProductionProofs.ProbeProduction(ctx, challenge)
	if source.mode == "descriptor" {
		response.Descriptor.InstanceID = "other-source"
	}
	return response, err
}

func (source *resultSource) ResolveResult(ctx context.Context, request stateappbroker.ResultRequest) (stateappbroker.Result, error) {
	source.calls.Add(1)
	if request != source.request {
		return stateappbroker.Result{}, broker.ErrFenceMismatch
	}
	if source.mode == "context" {
		<-ctx.Done()
		return stateappbroker.Result{}, ctx.Err()
	}
	body := bytes.Clone(source.body)
	if source.mode == "noncanonical" {
		body = []byte{0x18, 0}
	}
	if source.mode == "oversized" {
		body = make([]byte, stateappclient.MaximumProviderResultBytes+1)
	}
	result := stateappbroker.Result{Request: request, PayloadDigest: broker.Digest(sha256.Sum256(body)), CanonicalCBOR: body}
	if source.mode == "identity" {
		result.Request.InvocationID, _ = (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte{2}, 16))}).New(identity.Invocation)
	}
	if source.mode == "digest" {
		result.PayloadDigest = broker.Digest{9}
	}
	if source.mode == "error" {
		return stateappbroker.Result{}, errors.New("secret provider diagnostic")
	}
	return result, nil
}

func tid(t *testing.T, kind identity.Kind, n byte) identity.ID {
	t.Helper()
	id, err := (identity.Generator{Random: bytes.NewReader(bytes.Repeat([]byte{n}, 16))}).New(kind)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func requestFixture(t *testing.T) stateappbroker.ResultRequest {
	return stateappbroker.ResultRequest{TenantID: tid(t, identity.Tenant, 1), WorkspaceID: tid(t, identity.Workspace, 1), SessionID: tid(t, identity.Session, 1),
		EffectID: tid(t, identity.Effect, 1), InvocationID: tid(t, identity.Invocation, 1), RequestDigest: broker.Digest{1}, ExternalCommitID: tid(t, identity.Commit, 1), ResultRef: tid(t, identity.Artifact, 1)}
}

func piBody(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "packages", "protocol-types", "fixtures", "stateapp-pi-codec-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Settlements []struct{ Name, PayloadHex string }
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, s := range fixture.Settlements {
		if s.Name == "model_tool_call" {
			body, err := hex.DecodeString(s.PayloadHex)
			if err != nil {
				t.Fatal(err)
			}
			return body
		}
	}
	t.Fatal("missing actual Pi result")
	return nil
}

func newFixture(t *testing.T) (*resultSource, *Server, *stateappclient.Client, *proof.ProductionProofs) {
	t.Helper()
	groups := []dependency.AtomicGroup{dependency.AtomicEffectLifecycle}
	p := proof.NewProductionProofs(t, groups)
	source := &resultSource{ProductionProofs: p, request: requestFixture(t), body: piBody(t)}
	root := bytes.Repeat([]byte{8}, 32)
	handler, err := NewServer(ServerConfig{Source: proof.Verify[stateappbroker.ResultResolver](t, p, source, groups), KeyID: "provider-read", RootKey: root, Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := stateappclient.New(stateappclient.Config{Endpoint: server.URL, KeyID: "provider-read", RootKey: root, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	clear(root)
	return source, handler, client, p
}

func TestActualPiResultCrossesSignedReadAndIndependentNativeChallenges(t *testing.T) {
	source, _, client, p := newFixture(t)
	reader := proof.Verify[Reader](t, p, client, []dependency.AtomicGroup{dependency.AtomicEffectLifecycle})
	resolver, err := New(reader)
	if err != nil {
		t.Fatal(err)
	}
	verified := proof.Verify[stateappbroker.ResultResolver](t, p, resolver, []dependency.AtomicGroup{dependency.AtomicEffectLifecycle})
	operational, _, err := verified.Open()
	if err != nil {
		t.Fatal(err)
	}
	if source.probes.Load() != 3 {
		t.Fatalf("source, actual client and scoped resolver require separate fresh probes; got %d", source.probes.Load())
	}
	result, err := operational.ResolveResult(context.Background(), source.request)
	if err != nil || result.Request != source.request || !bytes.Equal(result.CanonicalCBOR, source.body) || result.PayloadDigest != broker.Digest(sha256.Sum256(source.body)) {
		t.Fatalf("actual Pi roundtrip: %v", err)
	}
	result.CanonicalCBOR[0] ^= 1
	again, err := operational.ResolveResult(context.Background(), source.request)
	if err != nil || !bytes.Equal(again.CanonicalCBOR, source.body) {
		t.Fatal("caller mutated retained normalized result")
	}
	request := source.request
	request.ResultRef = identity.ID{}
	if _, err = operational.ResolveResult(context.Background(), request); !errors.Is(err, broker.ErrInvalidRequest) {
		t.Fatal(err)
	}
	if source.calls.Load() != 2 {
		t.Fatal("invalid reference reached native source")
	}
	client.Close()
	if _, err = operational.ResolveResult(context.Background(), source.request); !errors.Is(err, stateappclient.ErrClientClosed) {
		t.Fatal(err)
	}
}

func TestNativeResultRejectsChangedSourceAndSanitizesFailure(t *testing.T) {
	for _, mode := range []string{"identity", "digest", "noncanonical", "oversized", "error", "context", "descriptor"} {
		t.Run(mode, func(t *testing.T) {
			source, _, client, _ := newFixture(t)
			source.mode = mode
			if mode == "descriptor" {
				_, err := client.ProbeProduction(context.Background(), dependency.ProbeChallenge{Nonce: bytes.Repeat([]byte{1}, 32)})
				if !errors.Is(err, stateappclient.ErrInvalidResponse) {
					t.Fatal(err)
				}
				return
			}
			result, err := client.ReadProviderResult(context.Background(), requestWire(source.request))
			var remote *stateappclient.RemoteError
			if !errors.As(err, &remote) || remote.Code != "INTERNAL_ERROR" || result.CanonicalCBOR != nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe source result: %v", err)
			}
		})
	}
}

func TestServerRequiresQualifiedOperationalSourceAndStrictAuthBeforeReads(t *testing.T) {
	if _, err := NewServer(ServerConfig{KeyID: "provider-read", RootKey: bytes.Repeat([]byte{8}, 32), Timeout: time.Second}); !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatal(err)
	}
	source, handler, _, _ := newFixture(t)
	request := requestValue(source.request)
	request["protocol"], request["major"], request["minor"], request["schemaDigest"] = stateappclient.ProviderResultProtocol, int64(1), int64(0), stateappclient.ProviderResultSchemaDigest()
	request["requestId"], request["sentAtUnixMs"] = tid(t, identity.Request, 1).String(), time.Now().UnixMilli()
	body, err := canonical.Encode(request, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"no-auth", "domain", "query", "duplicate-header", "body-tamper", "clock", "unknown-field", "bad-identity", "uppercase-digest", "size"} {
		t.Run(mode, func(t *testing.T) {
			m := make(canonical.Map, len(request))
			for k, v := range request {
				m[k] = v
			}
			if mode == "clock" {
				m["sentAtUnixMs"] = int64(0)
			}
			if mode == "unknown-field" {
				m["extra"] = true
			}
			if mode == "bad-identity" {
				m["effectId"] = "wrong"
			}
			if mode == "uppercase-digest" {
				m["requestDigest"] = "sha256:" + strings.Repeat("A", 64)
			}
			encoded, err := canonical.Encode(m, canonical.DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(encoded)
			path := stateappclient.ProviderResultPath
			if mode == "query" {
				path += "?admin=true"
			}
			if mode == "size" {
				encoded = make([]byte, 4097)
			}
			r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
			r.Header.Set("Content-Type", stateappclient.ProviderResultContentType)
			r.Header.Set(keyHeader, "provider-read")
			domain := stateappclient.ProviderResultRequestMACDomain
			if mode == "domain" {
				domain = "circulusd.state-ingress.request.v1"
			}
			signature := mac(handler.requestKey[:], frame([]byte(domain), []byte("provider-read"), []byte(http.MethodPost), []byte(stateappclient.ProviderResultPath), digest[:]))
			r.Header.Set(signatureHeader, hex.EncodeToString(signature[:]))
			if mode == "no-auth" {
				r.Header.Del(signatureHeader)
			}
			if mode == "duplicate-header" {
				r.Header.Add(keyHeader, "provider-read")
			}
			if mode == "body-tamper" {
				r.Body = ioBody(body[:len(body)-1])
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code == 200 {
				value, err := canonical.Decode(w.Body.Bytes(), canonical.DefaultOptions())
				if err != nil {
					t.Fatal(err)
				}
				if value.(canonical.Map)["payload"].(canonical.Map)["ok"] != false {
					t.Fatal("invalid request succeeded")
				}
			}
		})
	}
	if source.calls.Load() != 0 {
		t.Fatal("unauthorized/invalid request reached immutable results")
	}
}

type readClose struct{ *bytes.Reader }

func (*readClose) Close() error  { return nil }
func ioBody(b []byte) *readClose { return &readClose{bytes.NewReader(b)} }

type corruptReader struct {
	*proof.ProductionProofs
	result stateappclient.ProviderResult
	err    error
}

func (r *corruptReader) ReadProviderResult(context.Context, stateappclient.ProviderResultRequest) (stateappclient.ProviderResult, error) {
	return r.result, r.err
}

func TestResolverChecksOpaqueReaderResponsesIndependently(t *testing.T) {
	p := proof.NewProductionProofs(t, []dependency.AtomicGroup{dependency.AtomicEffectLifecycle})
	request := requestFixture(t)
	body := piBody(t)
	for _, mode := range []string{"identity", "digest", "body", "oversized", "diagnostic", "closed-diagnostic"} {
		t.Run(mode, func(t *testing.T) {
			reader := &corruptReader{ProductionProofs: p, result: stateappclient.ProviderResult{Request: requestWire(request), PayloadDigest: fmt.Sprintf("sha256:%x", sha256.Sum256(body)), CanonicalCBOR: body}}
			switch mode {
			case "identity":
				reader.result.Request.WorkspaceID = tid(t, identity.Workspace, 2).String()
			case "digest":
				reader.result.PayloadDigest = "sha256:" + strings.Repeat("9", 64)
			case "body":
				reader.result.CanonicalCBOR = []byte{0x18, 0}
				reader.result.PayloadDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(reader.result.CanonicalCBOR))
			case "oversized":
				reader.result.CanonicalCBOR = make([]byte, stateappclient.MaximumProviderResultBytes+1)
			case "diagnostic":
				reader.err = errors.New("secret provider diagnostic")
			case "closed-diagnostic":
				reader.err = fmt.Errorf("secret provider diagnostic: %w", stateappclient.ErrClientClosed)
			}
			resolver, err := New(proof.Verify[Reader](t, p, reader, []dependency.AtomicGroup{dependency.AtomicEffectLifecycle}))
			if err != nil {
				t.Fatal(err)
			}
			if result, err := resolver.ResolveResult(context.Background(), request); err == nil || result.CanonicalCBOR != nil || strings.Contains(err.Error(), "secret") {
				t.Fatal("corrupt qualified reader accepted")
			}
		})
	}
}

type stalledBody struct {
	done chan struct{}
	once sync.Once
}

func (body *stalledBody) Read([]byte) (int, error) { <-body.done; return 0, errors.New("closed body") }
func (body *stalledBody) Close() error             { body.once.Do(func() { close(body.done) }); return nil }

func TestRequestDeadlineBoundsStalledReadBeforeSource(t *testing.T) {
	for _, path := range []string{stateappclient.ProviderResultPath, probePath} {
		t.Run(path, func(t *testing.T) {
			source, handler, _, _ := newFixture(t)
			body := &stalledBody{done: make(chan struct{})}
			r := httptest.NewRequest(http.MethodPost, path, body)
			if path == probePath {
				r.Header.Set("Content-Type", probeContentType)
			} else {
				r.Header.Set("Content-Type", stateappclient.ProviderResultContentType)
				r.Header.Set(keyHeader, "provider-read")
				r.Header.Set(signatureHeader, strings.Repeat("0", 64))
			}
			done := make(chan struct{})
			go func() { defer close(done); handler.ServeHTTP(httptest.NewRecorder(), r) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				_ = body.Close()
				<-done
				t.Fatal("configured deadline did not unblock stalled body")
			}
			if source.calls.Load() != 0 || source.probes.Load() != 1 {
				t.Fatal("incomplete request reached native source")
			}
		})
	}
}
