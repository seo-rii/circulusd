package statebootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	proof "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/platformapi"
	"github.com/hancomac/circulusd/internal/sessionevent"
	"github.com/hancomac/circulusd/internal/stateappadmission"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

type bootstrapGenesis struct{ *proof.ProductionProofs }

func (*bootstrapGenesis) CreateGenesis(context.Context, stateappadmission.GenesisRequest) (*v1.AgentCheckpoint, error) {
	return nil, errors.New("factory test must not create genesis")
}

type foreignEvents struct{ *proof.ProductionProofs }

func (*foreignEvents) ReadSessionEventPage(context.Context, platformapi.AuthorizedSessionEventPageRequest) (platformapi.SessionPublicEventPage, error) {
	return platformapi.SessionPublicEventPage{}, nil
}

func TestSessionAdmissionFactoryChallengesEveryOperationalBoundary(t *testing.T) {
	fixture := newBootstrapFixture(t)
	fixture.descriptor.AtomicGroups = append(fixture.descriptor.AtomicGroups, dependency.AtomicPublicEvent)
	fixture.probe.descriptor = fixture.descriptor
	fixture.evidence.Descriptor = fixture.descriptor
	conformance := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	digest, err := dependency.EvidenceSigningDigest(fixture.evidence)
	if err != nil {
		t.Fatal(err)
	}
	fixture.evidence.Signature = ed25519.Sign(conformance, []byte(digest))
	fixture.verifier, err = dependency.NewVerifier(dependency.VerifierConfig{ConformanceRoots: map[string]ed25519.PublicKey{fixture.evidence.KeyID: conformance.Public().(ed25519.PublicKey)}, RuntimeRoots: map[string]ed25519.PublicKey{fixture.descriptor.RuntimeKeyID: fixture.probe.privateKey.Public().(ed25519.PublicKey)}, Clock: func() time.Time { return time.Unix(1_900_000_000, 0) }, Entropy: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/circulusd/state/v1/production:probe" {
			t.Error("factory attempted operation before qualification")
			w.WriteHeader(400)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 257))
		if err != nil {
			t.Error(err)
			return
		}
		value, err := canonical.Decode(body, canonical.Options{MaxBytes: 256, MaxDepth: 2, MaxItems: 16})
		if err != nil {
			t.Error(err)
			return
		}
		response, err := fixture.probe.response(r.Context(), "admission", dependency.ProbeChallenge{Nonce: value.(canonical.Map)["nonce"].(canonical.Bytes)})
		if err != nil {
			t.Error(err)
			return
		}
		d := response.Descriptor
		groups := make(canonical.Array, len(d.AtomicGroups))
		for i, g := range d.AtomicGroups {
			groups[i] = string(g)
		}
		wire := canonical.Map{"protocol": "circulus.state-production-probe.v1alpha1", "major": int64(1), "minor": int64(0), "schemaDigest": "sha256:33c8297cba9d6460e219e31e8c080927ed6275407c6eb159ea1f4d06fc87910f", "algorithm": "ed25519", "keyId": response.KeyID, "signature": canonical.Bytes(response.Signature), "descriptor": canonical.Map{"schemaVersion": uint64(d.SchemaVersion), "backendKind": d.BackendKind, "buildDigest": d.BuildDigest, "applicationDigest": d.ApplicationDigest, "instanceId": d.InstanceID, "transactionDomainId": d.TransactionDomainID, "durabilityClass": d.DurabilityClass, "conformanceRunId": d.ConformanceRunID, "conformanceDigest": d.ConformanceDigest, "runtimeKeyId": d.RuntimeKeyID, "probeEpoch": d.ProbeEpoch, "productionEligible": d.ProductionEligible, "atomicGroups": groups}}
		encoded, err := canonical.Encode(wire, canonical.DefaultOptions())
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.circulusd.state-production-probe+cbor")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(encoded)
	}))
	defer server.Close()
	fixture.client.Close()
	fixture.client, err = stateappclient.New(stateappclient.Config{Endpoint: server.URL, KeyID: "read", RootKey: bytes.Repeat([]byte{1}, 32), AdmissionKeyID: "admission", AdmissionRootKey: bytes.Repeat([]byte{3}, 32), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	built, err := loadWithSources(context.Background(), testFiles(), newTestSources(t, fixture, &sourceObservation{}))
	if err != nil {
		t.Fatal(err)
	}
	defer built.Close()
	if _, err = built.SessionAdmission(context.Background(), stateappadmission.PlannerConfig{}); !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatalf("unqualified genesis accepted: %v", err)
	}
	p := proof.NewProductionProofs(t, []dependency.AtomicGroup{dependency.AtomicEffectLifecycle})
	config := stateappadmission.PlannerConfig{Genesis: proof.Verify[stateappadmission.GenesisProvider](t, p, &bootstrapGenesis{p}, []dependency.AtomicGroup{dependency.AtomicEffectLifecycle})}
	if _, err = built.SessionAdmission(context.Background(), config); !errors.Is(err, dependency.ErrRequirementMismatch) {
		t.Fatalf("genesis without engine capability accepted: %v", err)
	}
	nonces, _ := fixture.probe.snapshot()
	if len(nonces) != 2 {
		t.Fatal("unqualified genesis reached admission challenge")
	}
	p = proof.NewProductionProofs(t, []dependency.AtomicGroup{dependency.AtomicEngineGenesis})
	config.Genesis = proof.Verify[stateappadmission.GenesisProvider](t, p, &bootstrapGenesis{p}, []dependency.AtomicGroup{dependency.AtomicEngineGenesis})
	verified, err := built.SessionAdmission(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	store, descriptor, err := verified.Open()
	if err != nil || store == nil || !reflect.DeepEqual(descriptor, built.Descriptor()) {
		t.Fatal("factory lost joint Session domain")
	}
	nonces, roles := fixture.probe.snapshot()
	if len(nonces) != 6 {
		t.Fatalf("got %d challenges; expected reader/claimer plus four independent admission challenges", len(nonces))
	}
	seen := make(map[string]bool)
	for i, n := range nonces {
		if seen[string(n)] {
			t.Fatal("reused native challenge")
		}
		seen[string(n)] = true
		if i >= 2 && roles[i] != "admission" {
			t.Fatal("challenged unrelated adapter")
		}
	}
	// A foreign event reader cannot be joined by borrowing the planner's proof.
	p = proof.NewProductionProofs(t, []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle, dependency.AtomicPublicEvent})
	built.(*graph).sessionEventReader = proof.Verify[sessionevent.SessionEventPageReader](t, p, &foreignEvents{p}, p.Descriptor().AtomicGroups)
	if _, err = built.SessionAdmission(context.Background(), config); !errors.Is(err, dependency.ErrTransactionDomainMismatch) {
		t.Fatalf("foreign event domain accepted: %v", err)
	}
	built.Close()
	if _, err = built.SessionAdmission(context.Background(), config); !errors.Is(err, stateappclient.ErrInvalidConfig) {
		t.Fatal("closed private admission client accepted")
	}
}
