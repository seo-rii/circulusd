package enginegenesis

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	releasecontract "github.com/hancomac/circulusd/internal/release/contracttest"
	"github.com/hancomac/circulusd/internal/stateappadmission"
	"google.golang.org/protobuf/proto"
)

// Synthetic signed protocol fixtures remain test-only; they do not qualify an
// absent native Worker Loader or establish actual production durability.
type nativeProofFixture struct {
	checkpoint     *v1.AgentCheckpoint
	descriptor     dependency.Descriptor
	runtimePrivate ed25519.PrivateKey
	verifier       *dependency.Verifier
	evidence       dependency.Evidence
	requirements   dependency.Requirements
	calls          int
}

func (fixture *nativeProofFixture) CreateGenesis(context.Context, stateappadmission.GenesisRequest) (*v1.AgentCheckpoint, error) {
	fixture.calls++
	return proto.Clone(fixture.checkpoint).(*v1.AgentCheckpoint), nil
}
func (fixture *nativeProofFixture) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	if err := ctx.Err(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	digest, err := dependency.ProbeSigningDigest(fixture.descriptor, challenge.Nonce)
	if err != nil {
		return dependency.ProbeResponse{}, err
	}
	return dependency.ProbeResponse{Descriptor: fixture.descriptor, KeyID: fixture.descriptor.RuntimeKeyID, Signature: ed25519.Sign(fixture.runtimePrivate, []byte(digest))}, nil
}
func newNativeProofFixture(t *testing.T) (*nativeProofFixture, dependency.Verified[stateappadmission.GenesisProvider]) {
	t.Helper()
	_, checkpoint := actualPiFixture(t)
	runtimePublic, runtimePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	conformancePublic, conformancePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := dependency.Descriptor{SchemaVersion: 1, BackendKind: dependency.BackendCelld, BuildDigest: "sha256:" + strings.Repeat("1", 64), ApplicationDigest: "sha256:" + strings.Repeat("2", 64), InstanceID: "engine-native-fixture", TransactionDomainID: "engine-native-fixture-domain", DurabilityClass: dependency.DurabilityCrashRPOZero, ConformanceRunID: "engine-genesis-fixture", ConformanceDigest: "sha256:" + strings.Repeat("3", 64), RuntimeKeyID: "engine-native-fixture-key", ProbeEpoch: 1, ProductionEligible: true, AtomicGroups: []dependency.AtomicGroup{dependency.AtomicEngineGenesis}}
	now := time.Now().UTC()
	evidence := dependency.Evidence{Descriptor: descriptor, IssuedAtUnix: now.Add(-time.Minute).Unix(), ExpiresAtUnix: now.Add(time.Hour).Unix(), KeyID: "engine-conformance-fixture-key"}
	digest, err := dependency.EvidenceSigningDigest(evidence)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Signature = ed25519.Sign(conformancePrivate, []byte(digest))
	verifier, err := dependency.NewVerifier(dependency.VerifierConfig{ConformanceRoots: map[string]ed25519.PublicKey{evidence.KeyID: conformancePublic}, RuntimeRoots: map[string]ed25519.PublicKey{descriptor.RuntimeKeyID: runtimePublic}, Clock: func() time.Time { return now }, Entropy: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	requirements, err := dependency.NewProductionRequirements(releasecontract.StateArtifactDigests(t, descriptor.BuildDigest, descriptor.ApplicationDigest), dependency.ProductionRequirementsConfig{InstanceID: descriptor.InstanceID, TransactionDomainID: descriptor.TransactionDomainID, RequiredAtomicGroups: []dependency.AtomicGroup{dependency.AtomicEngineGenesis}, MinimumProbeEpoch: 1, MaximumEvidenceAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &nativeProofFixture{checkpoint: checkpoint, descriptor: descriptor, runtimePrivate: runtimePrivate, verifier: verifier, evidence: evidence, requirements: requirements}
	sealed, err := dependency.VerifyDependency[stateappadmission.GenesisProvider](context.Background(), verifier, fixture, evidence, requirements)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, sealed
}

func TestGenesisNativeProofTamperingCannotAcquireProviderAuthority(t *testing.T) {
	for _, mode := range []string{"signature", "nonce", "application", "capability", "schema", "extra field"} {
		t.Run(mode, func(t *testing.T) {
			fixture, sealed := newNativeProofFixture(t)
			handler, err := NewServer(ServerConfig{KeyID: "genesis-1", RootKey: bytes.Repeat([]byte{1}, 32), Source: sealed})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, request)
				value, err := canonical.Decode(recorder.Body.Bytes(), wireOptions(maximumProbeBytes))
				if err != nil {
					t.Fatal(err)
				}
				m := value.(canonical.Map)
				switch mode {
				case "signature":
					m["signature"].(canonical.Bytes)[0] ^= 1
				case "nonce":
					m["nonce"].(canonical.Bytes)[0] ^= 1
				case "application":
					m["descriptor"].(canonical.Map)["applicationDigest"] = "sha256:" + strings.Repeat("f", 64)
				case "capability":
					m["descriptor"].(canonical.Map)["atomicGroups"] = canonical.Array{string(dependency.AtomicEffectLifecycle)}
				case "schema":
					m["schemaDigest"] = "sha256:" + strings.Repeat("f", 64)
				case "extra field":
					m["callerProductionEligible"] = true
				}
				encoded, err := canonical.Encode(m, wireOptions(maximumProbeBytes))
				if err != nil {
					t.Fatal(err)
				}
				writer.Header().Set("Content-Type", probeType)
				writer.Header().Set("Cache-Control", "no-store")
				writer.WriteHeader(200)
				writer.Write(encoded)
			}))
			defer server.Close()
			client, err := NewClient(ClientConfig{Endpoint: server.URL, KeyID: "genesis-1", RootKey: bytes.Repeat([]byte{1}, 32), Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if _, err := dependency.VerifyDependency[Transport](context.Background(), fixture.verifier, client, fixture.evidence, fixture.requirements); err == nil {
				t.Fatal("forged native proof obtained provider authority")
			}
			if fixture.calls != 0 {
				t.Fatal("failed native verification invoked genesis")
			}
		})
	}
}

func TestGenesisClientRejectsAuthenticatedMalformedOrOversizedResponses(t *testing.T) {
	for _, mode := range []string{"MAC", "schema", "identity", "request digest", "noncanonical", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			source, sealed := qualifiedSource(t)
			handler, err := NewServer(ServerConfig{KeyID: "genesis-1", RootKey: bytes.Repeat([]byte{1}, 32), Source: sealed})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				raw, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}
				request.Body = io.NopCloser(bytes.NewReader(raw))
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, request)
				value, err := canonical.Decode(recorder.Body.Bytes(), wireOptions(maximumResponseBytes))
				if err != nil {
					t.Fatal(err)
				}
				m := value.(canonical.Map)
				id := m["requestId"].(string)
				switch mode {
				case "schema":
					m["schemaDigest"] = "sha256:" + strings.Repeat("f", 64)
				case "identity":
					m["payload"].(canonical.Map)["identity"].(canonical.Map)["actorSubjectId"] = m["payload"].(canonical.Map)["identity"].(canonical.Map)["turnId"]
				case "request digest":
					m["requestDigest"] = "sha256:" + strings.Repeat("f", 64)
				}
				encoded, err := canonical.Encode(m, wireOptions(maximumResponseBytes))
				if err != nil {
					t.Fatal(err)
				}
				if mode == "noncanonical" {
					encoded = append(encoded, 0)
				}
				if mode == "oversized" {
					encoded = make([]byte, maximumResponseBytes+1)
				}
				signature := responseMAC(handler.responseKey, handler.keyID, id, raw, 200, encoded)
				if mode == "MAC" {
					signature = strings.Repeat("0", 64)
				}
				writer.Header().Set("Content-Type", genesisType)
				writer.Header().Set("Cache-Control", "no-store")
				writer.Header().Set(keyHeader, handler.keyID)
				writer.Header().Set(signatureHeader, signature)
				writer.WriteHeader(200)
				writer.Write(encoded)
			}))
			defer server.Close()
			client, err := NewClient(ClientConfig{Endpoint: server.URL, KeyID: "genesis-1", RootKey: bytes.Repeat([]byte{1}, 32), Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			request, _ := actualPiFixture(t)
			_, err = client.RequestGenesis(context.Background(), request)
			expected := ErrInvalidResponse
			if mode == "MAC" {
				expected = ErrUnauthenticatedResponse
			}
			if !errors.Is(err, expected) {
				t.Fatalf("bad response escaped %v", err)
			}
			if source.calls.Load() != 1 {
				t.Fatal("unexpected native source invocation count")
			}
		})
	}
}
