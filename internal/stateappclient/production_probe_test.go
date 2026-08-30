package stateappclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	releasecontract "github.com/hancomac/circulusd/internal/release/contracttest"
)

const (
	testProductionProbePath     = "/circulusd/state/v1/production:probe"
	testProductionProbeType     = "application/vnd.circulusd.state-production-probe+cbor"
	testProductionProbeProtocol = "circulus.state-production-probe.v1alpha1"
	testProductionProbeSchema   = "sha256:33c8297cba9d6460e219e31e8c080927ed6275407c6eb159ea1f4d06fc87910f"
)

func TestProductionProbeUsesExactNativeWireAndReturnsDetachedProof(t *testing.T) {
	descriptor := validProductionProbeDescriptor()
	nonce := bytes.Repeat([]byte{0x5a}, dependency.ChallengeBytes)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	digest, err := dependency.ProbeSigningDigest(descriptor, nonce)
	if err != nil {
		t.Fatalf("ProbeSigningDigest() error = %v", err)
	}
	signature := ed25519.Sign(privateKey, []byte(digest))
	wantSignature := append([]byte(nil), signature...)

	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != testProductionProbePath || request.URL.RawQuery != "" {
			t.Errorf("request target = %s %s, want POST %s", request.Method, request.URL.RequestURI(), testProductionProbePath)
		}
		if values := request.Header.Values("Content-Type"); len(values) != 1 || values[0] != testProductionProbeType {
			t.Errorf("Content-Type = %q, want exact probe media type", values)
		}
		if values := request.Header.Values("Accept"); len(values) != 1 || values[0] != testProductionProbeType {
			t.Errorf("Accept = %q, want exact probe media type", values)
		}
		if values := request.Header.Values("Cache-Control"); len(values) != 1 || values[0] != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store", values)
		}
		if request.Header.Get(testKeyHeader) != "" || request.Header.Get(testSignatureHeader) != "" {
			t.Errorf("probe reused application HMAC headers: key=%q signature=%q", request.Header.Get(testKeyHeader), request.Header.Get(testSignatureHeader))
		}
		if request.Header.Get("Content-Encoding") != "" {
			t.Errorf("unexpected Content-Encoding = %q", request.Header.Get("Content-Encoding"))
		}
		body := mustReadRequest(t, request)
		decoded, decodeErr := canonical.Decode(body, canonical.Options{MaxBytes: 256, MaxDepth: 2, MaxItems: 16})
		if decodeErr != nil {
			t.Fatalf("decode probe request: %v", decodeErr)
		}
		wantRequest := canonical.Map{
			"protocol": testProductionProbeProtocol, "major": int64(1), "minor": int64(0),
			"schemaDigest": testProductionProbeSchema,
			"nonce":        canonical.Bytes(nonce),
		}
		if !reflect.DeepEqual(decoded, wantRequest) {
			t.Errorf("probe request = %#v, want %#v", decoded, wantRequest)
		}

		responseBody := mustEncodeProductionProbe(t, productionProbeResponseMap(descriptor, signature))
		writer.Header()["Content-Type"] = []string{testProductionProbeType}
		writer.Header()["Cache-Control"] = []string{"no-store"}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(responseBody)
	}))

	var sourceCalls atomic.Int64
	client := newTestClient(t, endpoint, bytes.Repeat([]byte{0x31}, 32), func() (string, error) {
		sourceCalls.Add(1)
		return validID("req", 1), nil
	}, time.Second)
	var productionProbe dependency.ProductionProbe = client

	response, err := productionProbe.ProbeProduction(context.Background(), dependency.ProbeChallenge{Nonce: nonce})
	if err != nil {
		t.Fatalf("ProbeProduction() error = %v", err)
	}
	if !reflect.DeepEqual(response.Descriptor, descriptor) || response.KeyID != descriptor.RuntimeKeyID ||
		!bytes.Equal(response.Signature, signature) {
		t.Fatalf("ProbeProduction() = %#v, want signed descriptor", response)
	}
	if sourceCalls.Load() != 0 {
		t.Fatalf("probe invoked application request sources %d times", sourceCalls.Load())
	}
	descriptor.AtomicGroups[0] = "mutated-server-group"
	clear(signature)
	clear(nonce)
	if response.Descriptor.AtomicGroups[0] != dependency.AtomicCommandReceipt ||
		!bytes.Equal(response.Signature, wantSignature) {
		t.Fatalf("probe response aliased server or challenge buffers: %#v", response)
	}
}

func TestProductionProbeRejectsInvalidChallengeBeforeSourcesOrDial(t *testing.T) {
	var sourceCalls atomic.Int64
	client := newTestClient(t, "http://127.0.0.1:1", bytes.Repeat([]byte{0x41}, 32), func() (string, error) {
		sourceCalls.Add(1)
		return validID("req", 1), nil
	}, time.Second)

	tests := []struct {
		name      string
		ctx       context.Context
		challenge dependency.ProbeChallenge
		want      error
	}{
		{name: "nil context", challenge: dependency.ProbeChallenge{Nonce: bytes.Repeat([]byte{1}, dependency.ChallengeBytes)}, want: ErrInvalidRequest},
		{name: "nil nonce", ctx: context.Background(), want: ErrInvalidRequest},
		{name: "short nonce", ctx: context.Background(), challenge: dependency.ProbeChallenge{Nonce: bytes.Repeat([]byte{1}, dependency.ChallengeBytes-1)}, want: ErrInvalidRequest},
		{name: "long nonce", ctx: context.Background(), challenge: dependency.ProbeChallenge{Nonce: bytes.Repeat([]byte{1}, dependency.ChallengeBytes+1)}, want: ErrInvalidRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := client.ProbeProduction(test.ctx, test.challenge)
			if !reflect.DeepEqual(response, dependency.ProbeResponse{}) || !errors.Is(err, test.want) {
				t.Fatalf("ProbeProduction() = %#v, %v; want zero/%v", response, err, test.want)
			}
		})
	}
	if sourceCalls.Load() != 0 {
		t.Fatalf("invalid probes invoked application request sources %d times", sourceCalls.Load())
	}
}

func TestProductionProbeRejectsApplicationHMACHeadersOnNativeResponse(t *testing.T) {
	descriptor := validProductionProbeDescriptor()
	nonce := bytes.Repeat([]byte{0x6b}, dependency.ChallengeBytes)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	digest, err := dependency.ProbeSigningDigest(descriptor, nonce)
	if err != nil {
		t.Fatalf("ProbeSigningDigest() error = %v", err)
	}
	body := mustEncodeProductionProbe(t, productionProbeResponseMap(
		descriptor,
		ed25519.Sign(privateKey, []byte(digest)),
	))
	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header()["Content-Type"] = []string{testProductionProbeType}
		writer.Header()["Cache-Control"] = []string{"no-store"}
		writer.Header()[testKeyHeader] = []string{testKeyID}
		writer.Header()[testSignatureHeader] = []string{strings.Repeat("0", 64)}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(body)
	}))
	client := newTestClient(
		t, endpoint, bytes.Repeat([]byte{0x51}, 32),
		func() (string, error) { return validID("req", 1), nil }, time.Second,
	)

	response, err := client.ProbeProduction(
		context.Background(), dependency.ProbeChallenge{Nonce: nonce},
	)
	if !reflect.DeepEqual(response, dependency.ProbeResponse{}) || !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("ProbeProduction(HMAC response headers) = %#v, %v; want zero/ErrInvalidResponse", response, err)
	}
}

func TestProductionProbeMatchesCrossLanguageGolden(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "packages", "protocol-types", "fixtures", "state-production-probe-v1alpha1.json")
	contents, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read production probe golden: %v", err)
	}
	var fixture productionProbeGolden
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatalf("decode production probe golden: %v", err)
	}
	nonce, err := hex.DecodeString(fixture.NonceHex)
	if err != nil {
		t.Fatalf("decode golden nonce: %v", err)
	}
	requestBody, err := hex.DecodeString(fixture.RequestCBORHex)
	if err != nil {
		t.Fatalf("decode golden request: %v", err)
	}
	responseBody, err := hex.DecodeString(fixture.ResponseCBORHex)
	if err != nil {
		t.Fatalf("decode golden response: %v", err)
	}
	publicKey, err := hex.DecodeString(fixture.RuntimePublicKeyHex)
	if err != nil {
		t.Fatalf("decode golden public key: %v", err)
	}
	signature, err := hex.DecodeString(fixture.SignatureHex)
	if err != nil {
		t.Fatalf("decode golden signature: %v", err)
	}
	descriptor := fixture.Descriptor.dependencyDescriptor()
	wantDigest, err := dependency.ProbeSigningDigest(descriptor, nonce)
	if err != nil || wantDigest != fixture.SigningDigest ||
		!ed25519.Verify(ed25519.PublicKey(publicKey), []byte(wantDigest), signature) {
		t.Fatalf("golden runtime proof is invalid: digest=%q error=%v", wantDigest, err)
	}

	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body := mustReadRequest(t, request)
		if request.Method != fixture.Method || request.URL.Path != fixture.Path || request.URL.RawQuery != "" ||
			request.Header.Get("Content-Type") != fixture.ContentType || request.Header.Get("Accept") != fixture.ContentType ||
			!bytes.Equal(body, requestBody) {
			t.Errorf("probe wire differs from frozen golden")
		}
		writer.Header()["Content-Type"] = []string{fixture.ContentType}
		writer.Header()["Cache-Control"] = []string{"no-store"}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(responseBody)
	}))
	client := newTestClient(
		t, endpoint, bytes.Repeat([]byte{0x71}, 32),
		func() (string, error) { return validID("req", 1), nil }, time.Second,
	)
	response, err := client.ProbeProduction(
		context.Background(), dependency.ProbeChallenge{Nonce: nonce},
	)
	if err != nil || !reflect.DeepEqual(response.Descriptor, descriptor) || response.KeyID != fixture.KeyID ||
		!bytes.Equal(response.Signature, signature) {
		t.Fatalf("ProbeProduction(golden) = %#v, %v", response, err)
	}
}

func TestProductionProbeCopiesChallengeBeforeTransportConsumesBody(t *testing.T) {
	descriptor := validProductionProbeDescriptor()
	nonce := bytes.Repeat([]byte{0x7c}, dependency.ChallengeBytes)
	wantNonce := append([]byte(nil), nonce...)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	requestArrived := make(chan struct{})
	callerMutated := make(chan struct{})
	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(requestArrived)
		<-callerMutated
		body := mustReadRequest(t, request)
		decoded, decodeErr := canonical.Decode(body, canonical.Options{MaxBytes: 256, MaxDepth: 2, MaxItems: 16})
		if decodeErr != nil {
			t.Fatalf("decode probe request: %v", decodeErr)
		}
		gotNonce, ok := decoded.(canonical.Map)["nonce"].(canonical.Bytes)
		if !ok || !bytes.Equal(gotNonce, wantNonce) {
			t.Errorf("transport nonce = %x, want pre-mutation %x", gotNonce, wantNonce)
		}
		digest, digestErr := dependency.ProbeSigningDigest(descriptor, wantNonce)
		if digestErr != nil {
			t.Fatalf("ProbeSigningDigest() error = %v", digestErr)
		}
		responseBody := mustEncodeProductionProbe(t, productionProbeResponseMap(
			descriptor, ed25519.Sign(privateKey, []byte(digest)),
		))
		writer.Header()["Content-Type"] = []string{testProductionProbeType}
		writer.Header()["Cache-Control"] = []string{"no-store"}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(responseBody)
	}))
	client := newTestClient(
		t, endpoint, bytes.Repeat([]byte{0x72}, 32),
		func() (string, error) { return validID("req", 1), nil }, time.Second,
	)
	result := make(chan error, 1)
	go func() {
		_, probeErr := client.ProbeProduction(
			context.Background(), dependency.ProbeChallenge{Nonce: nonce},
		)
		result <- probeErr
	}()
	<-requestArrived
	clear(nonce)
	close(callerMutated)
	if err := <-result; err != nil {
		t.Fatalf("ProbeProduction() error = %v", err)
	}
}

func TestProductionProbeKeepsSixtyFourConcurrentChallengesIsolated(t *testing.T) {
	descriptor := validProductionProbeDescriptor()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	var arrived atomic.Int64
	var releaseOnce sync.Once
	release := make(chan struct{})
	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body := mustReadRequest(t, request)
		decoded, decodeErr := canonical.Decode(body, canonical.Options{MaxBytes: 256, MaxDepth: 2, MaxItems: 16})
		if decodeErr != nil {
			t.Fatalf("decode probe request: %v", decodeErr)
		}
		nonce, ok := decoded.(canonical.Map)["nonce"].(canonical.Bytes)
		if !ok {
			t.Fatal("probe request nonce is not a byte string")
		}
		if arrived.Add(1) == 64 {
			releaseOnce.Do(func() { close(release) })
		}
		<-release
		digest, digestErr := dependency.ProbeSigningDigest(descriptor, nonce)
		if digestErr != nil {
			t.Fatalf("ProbeSigningDigest() error = %v", digestErr)
		}
		responseBody := mustEncodeProductionProbe(t, productionProbeResponseMap(
			descriptor, ed25519.Sign(privateKey, []byte(digest)),
		))
		writer.Header()["Content-Type"] = []string{testProductionProbeType}
		writer.Header()["Cache-Control"] = []string{"no-store"}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(responseBody)
	}))
	client := newTestClient(
		t, endpoint, bytes.Repeat([]byte{0x73}, 32),
		func() (string, error) { return validID("req", 1), nil }, 5*time.Second,
	)
	type probeResult struct {
		index    int
		response dependency.ProbeResponse
		err      error
	}
	results := make(chan probeResult, 64)
	challenges := make([][]byte, 64)
	for index := range challenges {
		challenge := make([]byte, dependency.ChallengeBytes)
		binary.BigEndian.PutUint64(challenge[dependency.ChallengeBytes-8:], uint64(index+1))
		challenges[index] = challenge
		go func(index int, nonce []byte) {
			response, probeErr := client.ProbeProduction(
				context.Background(), dependency.ProbeChallenge{Nonce: nonce},
			)
			results <- probeResult{index: index, response: response, err: probeErr}
		}(index, challenge)
	}
	for range challenges {
		result := <-results
		if result.err != nil {
			t.Fatalf("ProbeProduction(%d) error = %v", result.index, result.err)
		}
		digest, digestErr := dependency.ProbeSigningDigest(
			result.response.Descriptor, challenges[result.index],
		)
		if digestErr != nil || !ed25519.Verify(publicKey, []byte(digest), result.response.Signature) {
			t.Fatalf("ProbeProduction(%d) returned a cross-wired proof", result.index)
		}
	}
}

func TestProductionProbeParticipatesInClientCloseLifecycle(t *testing.T) {
	requestArrived := make(chan struct{})
	endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(requestArrived)
		<-request.Context().Done()
	}))
	client := newTestClient(
		t, endpoint, bytes.Repeat([]byte{0x74}, 32),
		func() (string, error) { return validID("req", 1), nil }, 5*time.Second,
	)
	probeDone := make(chan error, 1)
	go func() {
		_, err := client.ProbeProduction(context.Background(), dependency.ProbeChallenge{
			Nonce: bytes.Repeat([]byte{0x75}, dependency.ChallengeBytes),
		})
		probeDone <- err
	}()
	<-requestArrived
	closeDone := make(chan struct{})
	go func() {
		client.Close()
		close(closeDone)
	}()
	select {
	case err := <-probeDone:
		if !errors.Is(err, ErrClientClosed) {
			t.Fatalf("inflight ProbeProduction() error = %v, want ErrClientClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("inflight ProbeProduction() did not unblock on Close")
	}
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close() did not wait for production probe cleanup")
	}
	response, err := client.ProbeProduction(context.Background(), dependency.ProbeChallenge{
		Nonce: bytes.Repeat([]byte{0x76}, dependency.ChallengeBytes),
	})
	if !reflect.DeepEqual(response, dependency.ProbeResponse{}) || !errors.Is(err, ErrClientClosed) {
		t.Fatalf("ProbeProduction(after Close) = %#v, %v; want zero/ErrClientClosed", response, err)
	}
}

func TestProductionProbeRejectsInvalidNativeHTTPFraming(t *testing.T) {
	descriptor := validProductionProbeDescriptor()
	nonce := bytes.Repeat([]byte{0x81}, dependency.ChallengeBytes)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	digest, err := dependency.ProbeSigningDigest(descriptor, nonce)
	if err != nil {
		t.Fatalf("ProbeSigningDigest() error = %v", err)
	}
	validBody := mustEncodeProductionProbe(t, productionProbeResponseMap(
		descriptor, ed25519.Sign(privateKey, []byte(digest)),
	))
	tests := []struct {
		name       string
		status     int
		body       []byte
		headers    func(http.Header)
		secretBody bool
	}{
		{name: "created status", status: http.StatusCreated, body: validBody},
		{name: "missing content type", status: http.StatusOK, body: validBody, headers: func(header http.Header) { delete(header, "Content-Type") }},
		{name: "duplicate content type", status: http.StatusOK, body: validBody, headers: func(header http.Header) {
			header["Content-Type"] = []string{testProductionProbeType, testProductionProbeType}
		}},
		{name: "parameterized content type", status: http.StatusOK, body: validBody, headers: func(header http.Header) { header.Set("Content-Type", testProductionProbeType+"; charset=binary") }},
		{name: "missing cache control", status: http.StatusOK, body: validBody, headers: func(header http.Header) { delete(header, "Cache-Control") }},
		{name: "duplicate cache control", status: http.StatusOK, body: validBody, headers: func(header http.Header) { header["Cache-Control"] = []string{"no-store", "no-store"} }},
		{name: "encoded body", status: http.StatusOK, body: validBody, headers: func(header http.Header) { header.Set("Content-Encoding", "identity") }},
		{name: "declared oversized body", status: http.StatusOK, headers: func(header http.Header) { header.Set("Content-Length", "32769") }},
		{name: "streamed oversized body", status: http.StatusOK, body: bytes.Repeat([]byte{0xa1}, maximumProductionProbeResponseBytes+1)},
		{name: "malformed secret body", status: http.StatusOK, body: []byte("private-runtime-key-material"), secretBody: true},
		{name: "trailing canonical byte", status: http.StatusOK, body: append(append([]byte(nil), validBody...), 0)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header()["Content-Type"] = []string{testProductionProbeType}
				writer.Header()["Cache-Control"] = []string{"no-store"}
				if test.headers != nil {
					test.headers(writer.Header())
				}
				writer.WriteHeader(test.status)
				_, _ = writer.Write(test.body)
			}))
			client := newTestClient(
				t, endpoint, bytes.Repeat([]byte{0x82}, 32),
				func() (string, error) { return validID("req", 1), nil }, time.Second,
			)
			response, probeErr := client.ProbeProduction(
				context.Background(), dependency.ProbeChallenge{Nonce: nonce},
			)
			if !reflect.DeepEqual(response, dependency.ProbeResponse{}) || !errors.Is(probeErr, ErrInvalidResponse) {
				t.Fatalf("ProbeProduction() = %#v, %v; want zero/ErrInvalidResponse", response, probeErr)
			}
			if test.secretBody && strings.Contains(probeErr.Error(), "private-runtime-key-material") {
				t.Fatalf("ProbeProduction() error disclosed response body: %v", probeErr)
			}
		})
	}
}

func TestProductionProbeRejectsMalformedProofDocuments(t *testing.T) {
	descriptor := validProductionProbeDescriptor()
	nonce := bytes.Repeat([]byte{0x83}, dependency.ChallengeBytes)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	digest, err := dependency.ProbeSigningDigest(descriptor, nonce)
	if err != nil {
		t.Fatalf("ProbeSigningDigest() error = %v", err)
	}
	signature := ed25519.Sign(privateKey, []byte(digest))
	tests := []struct {
		name   string
		mutate func(canonical.Map)
	}{
		{name: "unknown envelope member", mutate: func(record canonical.Map) { record["unknown"] = true }},
		{name: "missing descriptor", mutate: func(record canonical.Map) { delete(record, "descriptor") }},
		{name: "null descriptor", mutate: func(record canonical.Map) { record["descriptor"] = nil }},
		{name: "wrong protocol", mutate: func(record canonical.Map) { record["protocol"] = "circulus.state-production-probe.v2" }},
		{name: "wrong major", mutate: func(record canonical.Map) { record["major"] = int64(2) }},
		{name: "wrong schema", mutate: func(record canonical.Map) { record["schemaDigest"] = "sha256:" + strings.Repeat("9", 64) }},
		{name: "wrong algorithm", mutate: func(record canonical.Map) { record["algorithm"] = "Ed25519" }},
		{name: "mismatched key ID", mutate: func(record canonical.Map) { record["keyId"] = "runtime-root-2" }},
		{name: "short signature", mutate: func(record canonical.Map) {
			record["signature"] = canonical.Bytes(make([]byte, ed25519.SignatureSize-1))
		}},
		{name: "long signature", mutate: func(record canonical.Map) {
			record["signature"] = canonical.Bytes(make([]byte, ed25519.SignatureSize+1))
		}},
		{name: "unknown descriptor member", mutate: func(record canonical.Map) { record["descriptor"].(canonical.Map)["unknown"] = true }},
		{name: "zero epoch", mutate: func(record canonical.Map) { record["descriptor"].(canonical.Map)["probeEpoch"] = int64(0) }},
		{name: "duplicate groups", mutate: func(record canonical.Map) {
			record["descriptor"].(canonical.Map)["atomicGroups"] = canonical.Array{"command-receipt", "command-receipt"}
		}},
		{name: "unsorted groups", mutate: func(record canonical.Map) {
			record["descriptor"].(canonical.Map)["atomicGroups"] = canonical.Array{"effect-lifecycle", "command-receipt"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			responseMap := productionProbeResponseMap(descriptor, signature)
			test.mutate(responseMap)
			body := mustEncodeProductionProbe(t, responseMap)
			endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header()["Content-Type"] = []string{testProductionProbeType}
				writer.Header()["Cache-Control"] = []string{"no-store"}
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write(body)
			}))
			client := newTestClient(
				t, endpoint, bytes.Repeat([]byte{0x84}, 32),
				func() (string, error) { return validID("req", 1), nil }, time.Second,
			)
			response, probeErr := client.ProbeProduction(
				context.Background(), dependency.ProbeChallenge{Nonce: nonce},
			)
			if !reflect.DeepEqual(response, dependency.ProbeResponse{}) || !errors.Is(probeErr, ErrInvalidResponse) {
				t.Fatalf("ProbeProduction() = %#v, %v; want zero/ErrInvalidResponse", response, probeErr)
			}
		})
	}
}

func TestProductionProbeOnlyMintsVerifiedForExactEvidenceAndRuntimeKey(t *testing.T) {
	tests := []struct {
		name               string
		mutateDescriptor   func(*dependency.Descriptor)
		useStaleNonce      bool
		useWrongRuntimeKey bool
		useRandomSignature bool
		wantVerified       bool
	}{
		{name: "exact runtime", wantVerified: true},
		{name: "replayed nonce", useStaleNonce: true},
		{name: "other instance", mutateDescriptor: func(descriptor *dependency.Descriptor) { descriptor.InstanceID = "state-node-2" }},
		{name: "other application", mutateDescriptor: func(descriptor *dependency.Descriptor) {
			descriptor.ApplicationDigest = "sha256:" + strings.Repeat("4", 64)
		}},
		{name: "other groups", mutateDescriptor: func(descriptor *dependency.Descriptor) {
			descriptor.AtomicGroups = append(descriptor.AtomicGroups, dependency.AtomicQuotaSettlement)
		}},
		{name: "wrong runtime key", useWrongRuntimeKey: true},
		{name: "random signature", useRandomSignature: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conformancePublic, conformancePrivate, keyErr := ed25519.GenerateKey(rand.Reader)
			if keyErr != nil {
				t.Fatalf("GenerateKey(conformance) error = %v", keyErr)
			}
			runtimePublic, runtimePrivate, keyErr := ed25519.GenerateKey(rand.Reader)
			if keyErr != nil {
				t.Fatalf("GenerateKey(runtime) error = %v", keyErr)
			}
			_, wrongRuntimePrivate, keyErr := ed25519.GenerateKey(rand.Reader)
			if keyErr != nil {
				t.Fatalf("GenerateKey(wrong runtime) error = %v", keyErr)
			}
			descriptor := validProductionProbeDescriptor()
			now := time.Unix(1_900_000_000, 0).UTC()
			evidence := dependency.Evidence{
				Descriptor: descriptor, IssuedAtUnix: now.Add(-time.Minute).Unix(),
				ExpiresAtUnix: now.Add(time.Hour).Unix(), KeyID: "conformance-root-1",
			}
			evidenceDigest, digestErr := dependency.EvidenceSigningDigest(evidence)
			if digestErr != nil {
				t.Fatalf("EvidenceSigningDigest() error = %v", digestErr)
			}
			evidence.Signature = ed25519.Sign(conformancePrivate, []byte(evidenceDigest))
			challenge := bytes.Repeat([]byte{0x85}, dependency.ChallengeBytes)
			verifier, verifierErr := dependency.NewVerifier(dependency.VerifierConfig{
				ConformanceRoots: map[string]ed25519.PublicKey{"conformance-root-1": conformancePublic},
				RuntimeRoots:     map[string]ed25519.PublicKey{descriptor.RuntimeKeyID: runtimePublic},
				Clock:            func() time.Time { return now },
				Entropy:          bytes.NewReader(challenge),
			})
			if verifierErr != nil {
				t.Fatalf("NewVerifier() error = %v", verifierErr)
			}
			artifacts := releasecontract.StateArtifactDigests(t, descriptor.BuildDigest, descriptor.ApplicationDigest)
			requirements, requirementsErr := dependency.NewProductionRequirements(
				artifacts,
				dependency.ProductionRequirementsConfig{
					InstanceID: descriptor.InstanceID, TransactionDomainID: descriptor.TransactionDomainID,
					RequiredAtomicGroups: append([]dependency.AtomicGroup(nil), descriptor.AtomicGroups...),
					MinimumProbeEpoch:    descriptor.ProbeEpoch, MaximumEvidenceAge: time.Hour,
				},
			)
			if requirementsErr != nil {
				t.Fatalf("NewProductionRequirements() error = %v", requirementsErr)
			}
			endpoint := startLoopbackHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				body := mustReadRequest(t, request)
				decoded, decodeErr := canonical.Decode(body, canonical.Options{MaxBytes: 256, MaxDepth: 2, MaxItems: 16})
				if decodeErr != nil {
					t.Fatalf("decode probe request: %v", decodeErr)
				}
				nonce := decoded.(canonical.Map)["nonce"].(canonical.Bytes)
				responseDescriptor := descriptor
				responseDescriptor.AtomicGroups = append([]dependency.AtomicGroup(nil), descriptor.AtomicGroups...)
				if test.mutateDescriptor != nil {
					test.mutateDescriptor(&responseDescriptor)
				}
				signingNonce := nonce
				if test.useStaleNonce {
					signingNonce = bytes.Repeat([]byte{0x86}, dependency.ChallengeBytes)
				}
				signingDigest, signingErr := dependency.ProbeSigningDigest(responseDescriptor, signingNonce)
				if signingErr != nil {
					t.Fatalf("ProbeSigningDigest() error = %v", signingErr)
				}
				signingKey := runtimePrivate
				if test.useWrongRuntimeKey {
					signingKey = wrongRuntimePrivate
				}
				signature := ed25519.Sign(signingKey, []byte(signingDigest))
				if test.useRandomSignature {
					signature = bytes.Repeat([]byte{0x87}, ed25519.SignatureSize)
				}
				responseBody := mustEncodeProductionProbe(t, productionProbeResponseMap(responseDescriptor, signature))
				writer.Header()["Content-Type"] = []string{testProductionProbeType}
				writer.Header()["Cache-Control"] = []string{"no-store"}
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write(responseBody)
			}))
			client := newTestClient(
				t, endpoint, bytes.Repeat([]byte{0x88}, 32),
				func() (string, error) { return validID("req", 1), nil }, time.Second,
			)
			verified, verifyErr := dependency.VerifyDependency(
				context.Background(), verifier, client, evidence, requirements,
			)
			if test.wantVerified {
				if verifyErr != nil {
					t.Fatalf("VerifyDependency() error = %v", verifyErr)
				}
				opened, openedDescriptor, openErr := verified.Open()
				if openErr != nil || opened != client || !reflect.DeepEqual(openedDescriptor, descriptor) {
					t.Fatalf("Verified.Open() = %#v, %#v, %v", opened, openedDescriptor, openErr)
				}
			} else if !errors.Is(verifyErr, dependency.ErrUnverifiedDependency) {
				t.Fatalf("VerifyDependency() error = %v, want ErrUnverifiedDependency", verifyErr)
			}
		})
	}
}

type productionProbeGolden struct {
	Protocol            string                          `json:"protocol"`
	SchemaDigest        string                          `json:"schemaDigest"`
	Method              string                          `json:"method"`
	Path                string                          `json:"path"`
	ContentType         string                          `json:"contentType"`
	NonceHex            string                          `json:"nonceHex"`
	RequestCBORHex      string                          `json:"requestCborHex"`
	Descriptor          productionProbeGoldenDescriptor `json:"descriptor"`
	KeyID               string                          `json:"keyId"`
	Algorithm           string                          `json:"algorithm"`
	RuntimePublicKeyHex string                          `json:"runtimePublicKeyHex"`
	SigningDigest       string                          `json:"signingDigest"`
	SignatureHex        string                          `json:"signatureHex"`
	ResponseCBORHex     string                          `json:"responseCborHex"`
}

type productionProbeGoldenDescriptor struct {
	SchemaVersion       uint32                   `json:"schemaVersion"`
	BackendKind         string                   `json:"backendKind"`
	BuildDigest         string                   `json:"buildDigest"`
	ApplicationDigest   string                   `json:"applicationDigest"`
	InstanceID          string                   `json:"instanceId"`
	TransactionDomainID string                   `json:"transactionDomainId"`
	DurabilityClass     string                   `json:"durabilityClass"`
	ConformanceRunID    string                   `json:"conformanceRunId"`
	ConformanceDigest   string                   `json:"conformanceDigest"`
	RuntimeKeyID        string                   `json:"runtimeKeyId"`
	ProbeEpoch          uint64                   `json:"probeEpoch"`
	ProductionEligible  bool                     `json:"productionEligible"`
	AtomicGroups        []dependency.AtomicGroup `json:"atomicGroups"`
}

func (descriptor productionProbeGoldenDescriptor) dependencyDescriptor() dependency.Descriptor {
	return dependency.Descriptor{
		SchemaVersion: descriptor.SchemaVersion, BackendKind: descriptor.BackendKind,
		BuildDigest: descriptor.BuildDigest, ApplicationDigest: descriptor.ApplicationDigest,
		InstanceID: descriptor.InstanceID, TransactionDomainID: descriptor.TransactionDomainID,
		DurabilityClass: descriptor.DurabilityClass, ConformanceRunID: descriptor.ConformanceRunID,
		ConformanceDigest: descriptor.ConformanceDigest, RuntimeKeyID: descriptor.RuntimeKeyID,
		ProbeEpoch: descriptor.ProbeEpoch, ProductionEligible: descriptor.ProductionEligible,
		AtomicGroups: append([]dependency.AtomicGroup(nil), descriptor.AtomicGroups...),
	}
}

func validProductionProbeDescriptor() dependency.Descriptor {
	return dependency.Descriptor{
		SchemaVersion: 1, BackendKind: dependency.BackendCelld,
		BuildDigest:       "sha256:" + strings.Repeat("1", 64),
		ApplicationDigest: "sha256:" + strings.Repeat("2", 64),
		InstanceID:        "state-node-1", TransactionDomainID: "state-domain-1",
		DurabilityClass:   dependency.DurabilityCrashRPOZero,
		ConformanceRunID:  "conformance-run-1",
		ConformanceDigest: "sha256:" + strings.Repeat("3", 64),
		RuntimeKeyID:      "runtime-root-1", ProbeEpoch: 7, ProductionEligible: true,
		AtomicGroups: []dependency.AtomicGroup{dependency.AtomicCommandReceipt, dependency.AtomicEffectLifecycle},
	}
}

func productionProbeResponseMap(descriptor dependency.Descriptor, signature []byte) canonical.Map {
	groups := make(canonical.Array, len(descriptor.AtomicGroups))
	for index, group := range descriptor.AtomicGroups {
		groups[index] = string(group)
	}
	return canonical.Map{
		"protocol": testProductionProbeProtocol, "major": int64(1), "minor": int64(0),
		"schemaDigest": testProductionProbeSchema,
		"descriptor": canonical.Map{
			"schemaVersion": int64(descriptor.SchemaVersion), "backendKind": descriptor.BackendKind,
			"buildDigest": descriptor.BuildDigest, "applicationDigest": descriptor.ApplicationDigest,
			"instanceId": descriptor.InstanceID, "transactionDomainId": descriptor.TransactionDomainID,
			"durabilityClass": descriptor.DurabilityClass, "conformanceRunId": descriptor.ConformanceRunID,
			"conformanceDigest": descriptor.ConformanceDigest, "runtimeKeyId": descriptor.RuntimeKeyID,
			"probeEpoch": int64(descriptor.ProbeEpoch), "productionEligible": descriptor.ProductionEligible,
			"atomicGroups": groups,
		},
		"keyId": descriptor.RuntimeKeyID, "algorithm": "ed25519",
		"signature": canonical.Bytes(append([]byte(nil), signature...)),
	}
}

func mustEncodeProductionProbe(t *testing.T, value canonical.Value) []byte {
	t.Helper()
	encoded, err := canonical.Encode(value, canonical.Options{MaxBytes: 32 << 10, MaxDepth: 8, MaxItems: 128})
	if err != nil {
		t.Fatalf("encode production probe: %v", err)
	}
	return encoded
}
