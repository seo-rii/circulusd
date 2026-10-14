package enginegenesis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	dependencycontract "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/stateappadmission"
	"github.com/hancomac/circulusd/internal/stateappclient"
	"github.com/hancomac/circulusd/internal/stateappcodec"
	"google.golang.org/protobuf/proto"
)

type fixtureSource struct {
	*dependencycontract.ProductionProofs
	mu          sync.Mutex
	calls       atomic.Int32
	probes      atomic.Int32
	checkpoint  *v1.AgentCheckpoint
	lastRequest stateappadmission.GenesisRequest
	lastProof   dependency.ProbeResponse
	err         error
	block       chan struct{}
}

func (source *fixtureSource) CreateGenesis(ctx context.Context, request stateappadmission.GenesisRequest) (*v1.AgentCheckpoint, error) {
	source.mu.Lock()
	source.calls.Add(1)
	source.lastRequest = request
	checkpoint := source.checkpoint
	err := source.err
	block := source.block
	source.mu.Unlock()
	if block != nil {
		close(block)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	request.Input.(canonical.Map)["messages"].(canonical.Array)[0].(canonical.Map)["content"] = "source owns a separate copy"
	return checkpoint, err
}
func (source *fixtureSource) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	proof, err := source.ProductionProofs.ProbeProduction(ctx, challenge)
	source.mu.Lock()
	source.probes.Add(1)
	source.lastProof = proof
	source.mu.Unlock()
	return proof, err
}

func actualPiFixture(t *testing.T) (stateappadmission.GenesisRequest, *v1.AgentCheckpoint) {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join("..", "..", "packages", "protocol-types", "fixtures", "state-app-admission-plan-v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		RequestHex  string `json:"requestCborHex"`
		ResponseHex string `json:"responseCborHex"`
		GenesisHex  string `json:"genesisCborHex"`
	}
	if err = json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	decode := func(text string) canonical.Value {
		t.Helper()
		data, err := hex.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		value, err := canonical.Decode(data, wireOptions(maximumResponseBytes))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	request := decode(fixture.RequestHex).(canonical.Map)
	result := decode(fixture.ResponseHex).(canonical.Map)["payload"].(canonical.Map)["result"].(canonical.Map)
	runtime := result["runtime"].(canonical.Map)
	genesis := stateappadmission.GenesisRequest{TenantID: request["tenantId"].(string), WorkspaceID: result["workspaceId"].(string), ActorSubjectID: request["actorSubjectId"].(string), SessionID: request["sessionId"].(string), TurnID: request["proposedTurnId"].(string), Input: request["input"], InputDigest: request["inputDigest"].(string), Runtime: stateappclient.AdmissionRuntime{RuntimeRevisionDigest: runtime["runtimeRevisionDigest"].(string), EngineKind: runtime["engineKind"].(string), AdapterABIVersion: uint64(runtime["adapterAbiVersion"].(int64)), CheckpointSchemaVersion: uint64(runtime["checkpointSchemaVersion"].(int64))}}
	checkpoint, err := stateappcodec.CheckpointFromValue(decode(fixture.GenesisHex))
	if err != nil {
		t.Fatal(err)
	}
	return genesis, checkpoint
}

func qualifiedSource(t *testing.T) (*fixtureSource, dependency.Verified[stateappadmission.GenesisProvider]) {
	t.Helper()
	_, checkpoint := actualPiFixture(t)
	proofs := dependencycontract.NewProductionProofs(t, []dependency.AtomicGroup{dependency.AtomicEngineGenesis})
	source := &fixtureSource{ProductionProofs: proofs, checkpoint: checkpoint}
	return source, dependencycontract.Verify[stateappadmission.GenesisProvider](t, proofs, source, []dependency.AtomicGroup{dependency.AtomicEngineGenesis})
}
func nativeClientFixture(t *testing.T, source dependency.Verified[stateappadmission.GenesisProvider]) (*Client, *Server) {
	t.Helper()
	key := bytes.Repeat([]byte{0x9d}, 32)
	handler, err := NewServer(ServerConfig{KeyID: "engine-genesis-1", RootKey: key, Source: source})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := NewClient(ClientConfig{Endpoint: server.URL, KeyID: "engine-genesis-1", RootKey: key, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client, handler
}

func TestNativeGenesisRoundTripPreservesActualExecutablePiAndNativeSourceProof(t *testing.T) {
	source, sealed := qualifiedSource(t)
	client, _ := nativeClientFixture(t, sealed)
	binding := dependencycontract.Verify[Transport](t, source.ProductionProofs, client, []dependency.AtomicGroup{dependency.AtomicEngineGenesis})
	provider, err := NewProvider(binding)
	if err != nil {
		t.Fatal(err)
	}
	// The wrapper gets a separate fresh challenge against that exact native
	// engine source, not the admission transport's unrelated Session identity.
	dependencycontract.Verify[stateappadmission.GenesisProvider](t, source.ProductionProofs, provider, []dependency.AtomicGroup{dependency.AtomicEngineGenesis})
	request, checkpoint := actualPiFixture(t)
	actual, err := provider.CreateGenesis(context.Background(), request)
	if err != nil || !proto.Equal(actual, checkpoint) {
		t.Fatalf("genesis changed err=%v", err)
	}
	source.mu.Lock()
	lastRequest := source.lastRequest
	source.mu.Unlock()
	if source.calls.Load() != 1 || source.probes.Load() != 3 || lastRequest.TenantID != request.TenantID || lastRequest.WorkspaceID != request.WorkspaceID || lastRequest.ActorSubjectID != request.ActorSubjectID || lastRequest.Runtime != request.Runtime {
		t.Fatalf("scope/source identity dropped calls=%d probes=%d", source.calls.Load(), source.probes.Load())
	}
	if request.Input.(canonical.Map)["messages"].(canonical.Array)[0].(canonical.Map)["content"] != "First public message." {
		t.Fatal("source mutation changed caller input")
	}
	actual.PayloadBytes[0] ^= 1
	if proto.Equal(actual, source.checkpoint) {
		t.Fatal("returned checkpoint aliases source bytes")
	}
}

func TestGenesisProviderAndServerRejectUnqualifiedOrUnrelatedCapability(t *testing.T) {
	if _, err := NewProvider(dependency.Verified[Transport]{}); !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatal(err)
	}
	if _, err := NewServer(ServerConfig{KeyID: "genesis-1", RootKey: bytes.Repeat([]byte{1}, 32)}); !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatal(err)
	}
	proofs := dependencycontract.NewProductionProofs(t, []dependency.AtomicGroup{dependency.AtomicEffectLifecycle})
	source := &fixtureSource{ProductionProofs: proofs}
	sealed := dependencycontract.Verify[stateappadmission.GenesisProvider](t, proofs, source, []dependency.AtomicGroup{dependency.AtomicEffectLifecycle})
	if _, err := NewServer(ServerConfig{KeyID: "genesis-1", RootKey: bytes.Repeat([]byte{1}, 32), Source: sealed}); !errors.Is(err, dependency.ErrRequirementMismatch) {
		t.Fatal(err)
	}
	if source.calls.Load() != 0 {
		t.Fatal("unqualified source created genesis")
	}
}

func TestInvalidGenesisScopeInputAndRuntimeNeverReachSource(t *testing.T) {
	source, sealed := qualifiedSource(t)
	client, _ := nativeClientFixture(t, sealed)
	for _, mode := range []string{"tenant", "workspace", "actor", "session", "turn", "runtime", "ABI", "schema", "digest", "oversized input", "wrong role", "non NFC", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			request, _ := actualPiFixture(t)
			ctx := context.Background()
			switch mode {
			case "tenant":
				request.TenantID = request.TurnID
			case "workspace":
				request.WorkspaceID = request.TurnID
			case "actor":
				request.ActorSubjectID = request.TurnID
			case "session":
				request.SessionID = request.TurnID
			case "turn":
				request.TurnID = request.SessionID
			case "runtime":
				request.Runtime.RuntimeRevisionDigest = "untrusted-revision"
			case "ABI":
				request.Runtime.AdapterABIVersion = 1
			case "schema":
				request.Runtime.CheckpointSchemaVersion = 1
			case "digest":
				request.InputDigest = "sha256:" + strings.Repeat("f", 64)
			case "oversized input":
				request.Input = canonical.Map{"messages": canonical.Array{canonical.Map{"role": "user", "content": strings.Repeat("x", (1<<20)+1)}}}
			case "wrong role":
				request.Input = canonical.Map{"messages": canonical.Array{canonical.Map{"role": "assistant", "content": "no"}}}
			case "non NFC":
				request.Input = canonical.Map{"messages": canonical.Array{canonical.Map{"role": "user", "content": "e\u0301"}}}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := client.RequestGenesis(ctx, request); err == nil {
				t.Fatal("invalid input accepted")
			}
			if source.calls.Load() != 0 {
				t.Fatal("invalid input reached source")
			}
		})
	}
}

func TestSignedGenesisRequestRejectsWrongDomainMACSchemaAndNoncanonicalBytes(t *testing.T) {
	source, sealed := qualifiedSource(t)
	_, handler := nativeClientFixture(t, sealed)
	request, _ := actualPiFixture(t)
	_, semantic, _ := snapshotRequest(request)
	id := "req_" + strings.Repeat("A", 26)
	for _, mode := range []string{"wrong key", "wrong domain", "tamper", "wrong schema", "stale clock", "extra fields", "noncanonical"} {
		t.Run(mode, func(t *testing.T) {
			body := canonical.Map{"protocol": genesisProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": genesisSchema, "requestId": id, "sentAtUnixMs": time.Now().UnixMilli(), "body": semantic}
			switch mode {
			case "wrong schema":
				body["schemaDigest"] = "sha256:" + strings.Repeat("f", 64)
			case "stale clock":
				body["sentAtUnixMs"] = int64(0)
			case "extra fields":
				body["arbitraryOperation"] = "execute"
			}
			encoded, err := canonical.Encode(body, wireOptions(maximumRequestBytes))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "noncanonical" {
				encoded = append(encoded, 0)
			}
			signature := requestMAC(handler.requestKey, handler.keyID, encoded)
			if mode == "wrong domain" {
				sum := sha256Bytes(encoded)
				signature = mac(handler.requestKey, []byte("circulusd.state-turn-ingress.request.v1"), []byte(handler.keyID), []byte("POST"), []byte(genesisPath), sum)
			}
			if mode == "tamper" {
				encoded[len(encoded)-1] ^= 1
			}
			httpRequest := httptest.NewRequest(http.MethodPost, genesisPath, bytes.NewReader(encoded))
			httpRequest.Header.Set("Content-Type", genesisType)
			httpRequest.Header.Set(keyHeader, handler.keyID)
			httpRequest.Header.Set(signatureHeader, signature)
			if mode == "wrong key" {
				httpRequest.Header.Set(keyHeader, "admission-role-1")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httpRequest)
			if response.Code != 400 && response.Code != 401 {
				t.Fatalf("bad request status=%d", response.Code)
			}
			if source.calls.Load() != 0 {
				t.Fatal("bad request reached source")
			}
		})
	}
}

func TestGenesisMalformedSourceResultNeverEscapesAuthenticatedBoundary(t *testing.T) {
	for _, mode := range []string{"nil", "empty", "oversized", "wrong turn", "wrong revision", "wrong input", "secret error"} {
		t.Run(mode, func(t *testing.T) {
			source, sealed := qualifiedSource(t)
			client, _ := nativeClientFixture(t, sealed)
			request, _ := actualPiFixture(t)
			switch mode {
			case "nil":
				source.checkpoint = nil
			case "empty":
				source.checkpoint.PayloadBytes = nil
			case "oversized":
				source.checkpoint.PayloadBytes = make([]byte, (4<<20)+1)
			case "wrong turn":
				source.checkpoint.TurnId = source.checkpoint.SessionId
			case "wrong revision":
				source.checkpoint.RuntimeRevisionDigest.Value = bytes.Repeat([]byte{0xff}, 32)
			case "wrong input":
				request.Input = canonical.Map{"messages": canonical.Array{canonical.Map{"role": "user", "content": "Different input"}}}
				request.InputDigest, _ = canonical.StructuredDigest("circulusd.session.turn-input", 1, request.Input)
			case "secret error":
				source.err = errors.New("secret-native-source-credential")
			}
			if _, err := client.RequestGenesis(context.Background(), request); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("bad result escaped %v", err)
			}
		})
	}
}

func TestNativeGenesisCloseCancelsInflightAndClosedClientNeverReachesSource(t *testing.T) {
	source, sealed := qualifiedSource(t)
	source.block = make(chan struct{})
	client, _ := nativeClientFixture(t, sealed)
	request, _ := actualPiFixture(t)
	done := make(chan error, 1)
	go func() { _, err := client.RequestGenesis(context.Background(), request); done <- err }()
	select {
	case <-source.block:
	case <-time.After(2 * time.Second):
		t.Fatal("source did not start")
	}
	client.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Close left request live")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel")
	}
	if _, err := client.RequestGenesis(context.Background(), request); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed client error=%v", err)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.requestKey != ([32]byte{}) || client.responseKey != ([32]byte{}) {
		t.Fatal("Close retained keys")
	}
}

func TestNativeGenesisClientRejectsRedirectAndCredentialDisclosure(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true); w.WriteHeader(500) }))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer origin.Close()
	client, err := NewClient(ClientConfig{Endpoint: origin.URL, KeyID: "genesis-1", RootKey: bytes.Repeat([]byte{1}, 32), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request, _ := actualPiFixture(t)
	if _, err := client.RequestGenesis(context.Background(), request); err == nil || leaked.Load() {
		t.Fatal("redirect leaked credentials")
	}
	for _, endpoint := range []string{"http://localhost:1234", "http://127.0.0.1", "http://127.0.0.1:01234", "http://127.0.0.1:1234/path", "http://127.0.0.1:1234?x=1", "http://192.0.2.1:1234", "https://127.0.0.1:1234"} {
		if _, err := NewClient(ClientConfig{Endpoint: endpoint, KeyID: "genesis-1", RootKey: bytes.Repeat([]byte{1}, 32), Timeout: time.Second}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("unsafe endpoint accepted %q: %v", endpoint, err)
		}
	}
}

// A peer that does not share the root key rejects the request MAC with 401.
// That is a keying failure, not an unavailable source, and must stay distinct
// through the client and the provider.
func TestNativeGenesisRequestAuthenticationRejectionIsDistinct(t *testing.T) {
	source, sealed := qualifiedSource(t)
	handler, err := NewServer(ServerConfig{KeyID: "engine-genesis-1", RootKey: bytes.Repeat([]byte{0x9d}, 32), Source: sealed})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client, err := NewClient(ClientConfig{Endpoint: server.URL, KeyID: "engine-genesis-1", RootKey: bytes.Repeat([]byte{0x9e}, 32), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request, _ := actualPiFixture(t)
	if _, err := client.RequestGenesis(context.Background(), request); !errors.Is(err, ErrUnauthenticatedRequest) {
		t.Fatalf("client error = %v, want ErrUnauthenticatedRequest", err)
	}
	binding := dependencycontract.Verify[Transport](t, source.ProductionProofs, client, []dependency.AtomicGroup{dependency.AtomicEngineGenesis})
	provider, err := NewProvider(binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.CreateGenesis(context.Background(), request); !errors.Is(err, ErrUnauthenticatedRequest) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("provider error = %v, want ErrUnauthenticatedRequest", err)
	}
	if source.calls.Load() != 0 {
		t.Fatal("unauthenticated request reached source")
	}
}

type failingTransport struct {
	*dependencycontract.ProductionProofs
	err error
}

func (transport *failingTransport) RequestGenesis(context.Context, stateappadmission.GenesisRequest) (*v1.AgentCheckpoint, error) {
	return nil, transport.err
}

func TestGenesisProviderKeepsAuthenticationFailuresDistinct(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "response MAC", err: ErrUnauthenticatedResponse, want: ErrUnauthenticatedResponse},
		{name: "request MAC", err: ErrUnauthenticatedRequest, want: ErrUnauthenticatedRequest},
		{name: "invalid response", err: ErrInvalidResponse, want: ErrUnavailable},
		{name: "transport detail", err: errors.New("secret-transport-detail"), want: ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			groups := []dependency.AtomicGroup{dependency.AtomicEngineGenesis}
			proofs := dependencycontract.NewProductionProofs(t, groups)
			transport := &failingTransport{ProductionProofs: proofs, err: test.err}
			provider, err := NewProvider(dependencycontract.Verify[Transport](t, proofs, transport, groups))
			if err != nil {
				t.Fatal(err)
			}
			request, _ := actualPiFixture(t)
			_, err = provider.CreateGenesis(context.Background(), request)
			if !errors.Is(err, test.want) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("CreateGenesis() error = %v, want %v", err, test.want)
			}
			if test.want != ErrUnavailable && errors.Is(err, ErrUnavailable) {
				t.Fatalf("authentication failure %v is also reported as unavailable", err)
			}
		})
	}
}

func sha256Bytes(value []byte) []byte { sum := sha256.Sum256(value); return sum[:] }
