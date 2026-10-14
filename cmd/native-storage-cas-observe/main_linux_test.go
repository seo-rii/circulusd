//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/conformance/celld/issuance"
	"github.com/hancomac/circulusd/internal/objectstore"
)

type conditionalFixture struct {
	mu                sync.Mutex
	data              []byte
	etag              string
	version           int
	gets              int
	puts              int
	deletes           int
	contenders        int
	firstFailure      int
	staleFailure      int
	foreignAfterFresh bool
	// ignorePreconditions models a store that accepts conditional writes
	// without enforcing them.
	ignorePreconditions bool
	requests            []string
}

func (fixture *conditionalFixture) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil || len(body) > 4096 {
		t.Error("request body exceeded fixture limit")
	}
	if !strings.HasPrefix(r.URL.Path, "/qualification/.doctor/raw-cas-") || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		t.Errorf("unexpected unsigned or foreign request: %s", r.URL.Path)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.requests = append(fixture.requests, r.Method)
	failure := func(status int) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(status)
		fmt.Fprintf(w, "<Error><Code>PreconditionFailed</Code><Message>private-provider-message</Message></Error>")
	}
	switch r.Method {
	case http.MethodPut:
		fixture.puts++
		if fixture.puts == 1 && fixture.firstFailure != 0 {
			failure(fixture.firstFailure)
			return
		}
		if strings.HasPrefix(string(body), "circulusd-raw-cas-winner-") {
			fixture.contenders++
		}
		if fixture.ignorePreconditions && (r.Header.Get("If-None-Match") == "*" || r.Header.Get("If-Match") != "") {
			// Accept the write below without checking the precondition.
		} else if r.Header.Get("If-None-Match") == "*" {
			if fixture.data != nil {
				failure(412)
				return
			}
		} else if r.Header.Get("If-Match") != "" {
			if r.Header.Get("If-Match") != fixture.etag {
				status := fixture.staleFailure
				if status == 0 {
					status = 412
				}
				failure(status)
				return
			}
		} else {
			t.Error("unconditional mutation")
			failure(500)
			return
		}
		fixture.data = append([]byte(nil), body...)
		fixture.version++
		fixture.etag = fmt.Sprintf(`"native-token-%d"`, fixture.version)
		w.Header().Set("ETag", fixture.etag)
		w.WriteHeader(200)
	case http.MethodGet:
		fixture.gets++
		if fixture.data == nil {
			failure(404)
			return
		}
		w.Header().Set("ETag", fixture.etag)
		_, _ = w.Write(fixture.data)
		if fixture.foreignAfterFresh && fixture.gets == 4 {
			fixture.data = []byte("unrelated-object")
			fixture.etag = `"foreign-owner-token"`
		}
	case http.MethodDelete:
		fixture.deletes++
		if r.Header.Get("If-Match") == "" || r.Header.Get("If-Match") != fixture.etag {
			failure(412)
			return
		}
		fixture.data = nil
		w.WriteHeader(204)
	default:
		t.Errorf("unexpected method %s", r.Method)
		w.WriteHeader(405)
	}
}

func fixtureOptions(t *testing.T, fixture *conditionalFixture) objectstore.S3StoreOptions {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fixture.serve(t, w, r) }))
	t.Cleanup(server.Close)
	return objectstore.S3StoreOptions{Endpoint: server.URL, Bucket: "qualification", Region: "us-east-1", AccessKeyID: "fixture-access", SecretAccessKey: "fixture-secret", RequestTimeout: time.Second, MaximumObjectBytes: 1 << 20}
}

func TestObserveRecordsNativeConditionalFactsAndFreshRead(t *testing.T) {
	// An unusable ambient proxy must not affect the explicit direct SDK client.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	fixture := &conditionalFixture{}
	facts, err := observe(context.Background(), fixtureOptions(t, fixture), time.Second, bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if facts.Contenders != 32 || facts.Winners != 1 || facts.PreconditionFailures != 31 || facts.InitialETag != `"native-token-1"` || facts.CurrentETag != `"native-token-3"` ||
		facts.StaleUpdateStatus != 412 || facts.DuplicateCreateStatus != 412 || facts.StaleDeleteStatus != 412 ||
		!strings.HasPrefix(facts.ExpectedDataDigest, "sha256:") || facts.ExpectedDataDigest != facts.ObservedDataDigest || facts.ExpectedDataDigest != facts.FreshClientDataDigest {
		t.Fatalf("incorrect native facts: %+v", facts)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.contenders != 32 || fixture.puts != 36 || fixture.gets != 6 || fixture.deletes != 2 || fixture.data != nil {
		t.Fatalf("mutation retries, missing fresh read or unsafe cleanup: %+v", fixture)
	}
}

func TestObserveRequiresExactNative412(t *testing.T) {
	fixture := &conditionalFixture{staleFailure: 409}
	facts, err := observe(context.Background(), fixtureOptions(t, fixture), time.Second, bytes.NewReader(make([]byte, 16)))
	if err == nil || facts.StaleUpdateStatus != 409 || facts.Contenders != 0 {
		t.Fatalf("native 409 was interpreted as observed 412: %+v %v", facts, err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.data != nil {
		t.Fatal("owned failed probe was not cleaned")
	}
}

func TestObserveDoesNotRetryMutationFailure(t *testing.T) {
	fixture := &conditionalFixture{firstFailure: 503}
	_, err := observe(context.Background(), fixtureOptions(t, fixture), time.Second, bytes.NewReader(make([]byte, 16)))
	if err == nil {
		t.Fatal("native service failure produced observations")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.puts != 1 || fixture.deletes != 0 {
		t.Fatalf("failed mutation was retried or deletion guessed: %+v", fixture)
	}
}

func TestObserveRefusesForeignObjectCleanup(t *testing.T) {
	fixture := &conditionalFixture{foreignAfterFresh: true}
	_, err := observe(context.Background(), fixtureOptions(t, fixture), time.Second, bytes.NewReader(make([]byte, 16)))
	if err == nil {
		t.Fatal("foreign object replacement was ignored")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if string(fixture.data) != "unrelated-object" || fixture.deletes != 1 {
		t.Fatalf("foreign object was deleted: %+v", fixture)
	}
}

func TestObserveCleansProbeWrittenDespiteIgnoredPreconditions(t *testing.T) {
	fixture := &conditionalFixture{ignorePreconditions: true}
	facts, err := observe(context.Background(), fixtureOptions(t, fixture), time.Second, bytes.NewReader(make([]byte, 16)))
	if err == nil || facts.StaleUpdateStatus != 0 || facts.DuplicateCreateStatus != 0 || facts.Contenders != 0 {
		t.Fatalf("ignored preconditions produced observations: %+v %v", facts, err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.data != nil {
		t.Fatalf("probe object left behind: %q", fixture.data)
	}
}

func TestReadPrivateJSONRejectsHardLinkedInput(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "credentials.json")
	if err := os.WriteFile(path, []byte(`{"accessKeyId":"fixture","secretAccessKey":"fixture"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var values credentialValues
	if err := readPrivateJSON(path, &values); err != nil {
		t.Fatalf("private input rejected: %v", err)
	}
	if err := os.Link(path, filepath.Join(parent, "alias.json")); err != nil {
		t.Fatal(err)
	}
	if readPrivateJSON(path, &values) == nil {
		t.Fatal("hard-linked private input accepted")
	}
}

func privateConfig(t *testing.T, options objectstore.S3StoreOptions) (string, string) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	credentialsPath := filepath.Join(parent, "credentials.json")
	encoded, _ := json.Marshal(credentialValues{options.AccessKeyID, options.SecretAccessKey, ""})
	if err := os.WriteFile(credentialsPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	config := configuration{SchemaVersion: 1, Endpoint: options.Endpoint, Bucket: options.Bucket, Region: options.Region, RequestTimeoutMillis: 1000, ProbeTimeoutMillis: 10000, CleanupTimeoutMillis: 1000, MaximumObjectBytes: 1 << 20}
	config.Credentials.Source, config.Credentials.File = "file", credentialsPath
	encoded, _ = json.Marshal(config)
	configPath := filepath.Join(parent, "config.json")
	if err := os.WriteFile(configPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	return configPath, filepath.Join(parent, "facts.json")
}

func TestRunRetainsExactFactsExclusivelyAndPrivately(t *testing.T) {
	fixture := &conditionalFixture{}
	configPath, outputPath := privateConfig(t, fixtureOptions(t, fixture))
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "--output", outputPath}, &stdout, &stderr, func(string) string { return "" }); code != 0 {
		t.Fatalf("code %d: %s", code, stderr.String())
	}
	info, _ := os.Stat(outputPath)
	if info.Mode().Perm() != 0600 {
		t.Fatal("report is not private")
	}
	encoded, _ := os.ReadFile(outputPath)
	var facts issuance.CASFacts
	if issuance.DecodeStrict(encoded, &facts) != nil || facts.Winners != 1 || strings.Contains(string(encoded), "PASS") || strings.Contains(stdout.String()+stderr.String(), "fixture-secret") {
		t.Fatal("report does not contain exact safe CAS facts")
	}
	fixture.mu.Lock()
	before := len(fixture.requests)
	fixture.mu.Unlock()
	if code := run(context.Background(), []string{"--config", configPath, "--output", outputPath}, io.Discard, io.Discard, func(string) string { return "" }); code != 1 {
		t.Fatalf("existing report accepted: %d", code)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.requests) != before {
		t.Fatal("provider mutated before exclusive report reservation")
	}
}

func TestRunRejectsAmbiguousPrivateConfigurationBeforeMutation(t *testing.T) {
	fixture := &conditionalFixture{}
	configPath, outputPath := privateConfig(t, fixtureOptions(t, fixture))
	encoded, _ := os.ReadFile(configPath)
	encoded = append([]byte(`{"SCHEMAVERSION":1,`), encoded[1:]...)
	if err := os.WriteFile(configPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if code := run(context.Background(), []string{"--config", configPath, "--output", outputPath}, io.Discard, io.Discard, func(string) string { return "" }); code != 2 {
		t.Fatalf("ambiguous configuration accepted: %d", code)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.requests) != 0 {
		t.Fatal("provider mutated with ambiguous configuration")
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatal("invalid configuration created output")
	}
}

func TestRunFailureDoesNotRetainSuccessfulFactsOrProviderMessages(t *testing.T) {
	fixture := &conditionalFixture{firstFailure: 503}
	configPath, outputPath := privateConfig(t, fixtureOptions(t, fixture))
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "--output", outputPath}, &stdout, &stderr, func(string) string { return "" }); code != 2 {
		t.Fatalf("failed observation accepted: %d", code)
	}
	encoded, _ := os.ReadFile(outputPath)
	if len(encoded) != 0 || stdout.Len() != 0 || strings.Contains(stderr.String(), "private-provider-message") || strings.Contains(stderr.String(), "fixture-secret") {
		t.Fatal("failed observation fabricated facts or disclosed provider text")
	}
}

func TestBoundedTransportRejectsOversizedProviderResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2048")
		w.WriteHeader(500)
	}))
	defer server.Close()
	options := objectstore.S3StoreOptions{Endpoint: server.URL, Region: "us-east-1", Bucket: "qualification", AccessKeyID: "fixture", SecretAccessKey: "fixture", RequestTimeout: time.Second, MaximumObjectBytes: 1024}
	client := openNative(options)
	defer client.transport.CloseIdleConnections()
	if _, err := client.put(context.Background(), ".doctor/raw-cas-test", "", []byte("probe")); err == nil || nativeStatus(err) != 0 {
		t.Fatal("oversized native response was consumed as qualified HTTP status")
	}
}
