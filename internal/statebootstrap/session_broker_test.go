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
	"strings"
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

type bootstrapResultReader struct{ *proof.ProductionProofs }

func (*bootstrapResultReader) ResolveResult(context.Context, stateappbroker.ResultRequest) (stateappbroker.Result, error) {
	return stateappbroker.Result{}, errors.New("test does not resolve provider results")
}

func TestSessionBrokerFactorySealsActualPrivateClientAndRejectsUnqualifiedResults(t *testing.T) {
	fixture := newBootstrapFixture(t)
	var err error
	conformance := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	fixture.verifier, err = dependency.NewVerifier(dependency.VerifierConfig{ConformanceRoots: map[string]ed25519.PublicKey{fixture.evidence.KeyID: conformance.Public().(ed25519.PublicKey)}, RuntimeRoots: map[string]ed25519.PublicKey{fixture.descriptor.RuntimeKeyID: fixture.probe.privateKey.Public().(ed25519.PublicKey)}, Clock: func() time.Time { return time.Unix(1_900_000_000, 0) }, Entropy: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/circulusd/state/v1/production:probe" {
			t.Error("unexpected broker factory operation")
			http.Error(w, "bad operation", 400)
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
		request := value.(canonical.Map)
		response, err := fixture.probe.response(r.Context(), "broker", dependency.ProbeChallenge{Nonce: request["nonce"].(canonical.Bytes)})
		if err != nil {
			t.Error(err)
			return
		}
		d := response.Descriptor
		groups := canonical.Array{}
		for _, group := range d.AtomicGroups {
			groups = append(groups, string(group))
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
	fixture.client, err = stateappclient.New(stateappclient.Config{Endpoint: server.URL, KeyID: "read", RootKey: bytes.Repeat([]byte{1}, 32), BrokerKeyID: "broker", BrokerRootKey: bytes.Repeat([]byte{4}, 32), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	graph, err := loadWithSources(context.Background(), testFiles(), newTestSources(t, fixture, &sourceObservation{}))
	if err != nil {
		t.Fatal(err)
	}
	defer graph.Close()
	id := func(kind identity.Kind) identity.ID {
		id, err := identity.Parse(kind, string(kind)+"_"+strings.Repeat("A", 26))
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	config := stateappbroker.Config{Scope: stateappclient.BrokerScope{TenantID: id(identity.Tenant).String(), WorkspaceID: id(identity.Workspace).String(), SessionID: id(identity.Session).String(), ActorSubjectID: id(identity.Subject).String(), ExpectedAuthorizationGeneration: 1}, UserID: id(identity.Subject), EngineStepLimits: broker.EngineStepBudget{MaximumEvents: 1, MaximumEphemeralBytes: 65536, MaximumWallClock: time.Second}}
	if _, err = graph.SessionBroker(context.Background(), config); !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatalf("unverified results accepted: %v", err)
	}
	nonces, _ := fixture.probe.snapshot()
	if len(nonces) != 2 {
		t.Fatal("unverified result dependency reached broker challenge")
	}
	groups := []dependency.AtomicGroup{dependency.AtomicEffectLifecycle}
	p := proof.NewProductionProofs(t, groups)
	resultReader := &bootstrapResultReader{ProductionProofs: p}
	config.Results = proof.Verify[stateappbroker.ResultResolver](t, p, resultReader, groups)
	verified, err := graph.SessionBroker(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	store, descriptor, err := verified.Open()
	if err != nil || store == nil || !reflect.DeepEqual(descriptor, graph.Descriptor()) {
		t.Fatal("broker factory lost exact atomic domain")
	}
	nonces, roles := fixture.probe.snapshot()
	if len(nonces) != 3 || roles[2] != "broker" || bytes.Equal(nonces[1], nonces[2]) {
		t.Fatal("broker reused earlier probe or challenged unrelated object")
	}
	concrete, err := NativeSessionBroker(context.Background(), graph, config)
	if err != nil {
		t.Fatal(err)
	}
	concreteStore, concreteDescriptor, err := concrete.Open()
	if err != nil || concreteStore == nil || !reflect.DeepEqual(concreteDescriptor, graph.Descriptor()) {
		t.Fatal("concrete broker lost independently verified domain")
	}
	nonces, roles = fixture.probe.snapshot()
	if len(nonces) != 4 || roles[3] != "broker" || bytes.Equal(nonces[2], nonces[3]) {
		t.Fatal("concrete broker reused interface proof")
	}
	if _, err := NativeSessionBroker(context.Background(), nil, config); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("foreign/nil graph exposed concrete broker")
	}
	graph.Close()
	if _, err = graph.SessionBroker(context.Background(), config); !errors.Is(err, stateappclient.ErrInvalidConfig) {
		t.Fatalf("closed private client accepted: %v", err)
	}
	if _, err := NativeSessionBroker(context.Background(), graph, config); !errors.Is(err, stateappclient.ErrInvalidConfig) {
		t.Fatal("closed client exposed concrete broker")
	}
}
