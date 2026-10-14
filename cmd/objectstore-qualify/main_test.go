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

	"github.com/hancomac/circulusd/internal/conformance"
)

func fixtureConfiguration(t *testing.T, endpoint string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "qualification.json")
	data, _ := json.Marshal(qualificationConfig{SchemaVersion: 1, Endpoint: endpoint, Region: "us-east-1", Bucket: "existing-bucket", Credentials: credentialConfig{Source: "environment"}, RequestTimeoutMillis: 1000, ProbeTimeoutMillis: 5000, CleanupTimeoutMillis: 100, MaximumObjectBytes: 1 << 20})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func privateTestDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}
func fixtureEnvironment(name string) string {
	switch name {
	case "AWS_ACCESS_KEY_ID":
		return "fixture-access"
	case "AWS_SECRET_ACCESS_KEY":
		return "fixture-secret"
	}
	return ""
}
func readReport(t *testing.T, path string) qualificationReport {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report qualificationReport
	if e := json.Unmarshal(data, &report); e != nil {
		t.Fatal(e)
	}
	return report
}

func TestQualificationAbsentCredentialsIsUnavailableWithoutRequestsAndPrivateOutput(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
	defer server.Close()
	output := filepath.Join(privateTestDirectory(t), "result.json")
	var messages bytes.Buffer
	code := run(context.Background(), []string{"--config", fixtureConfiguration(t, server.URL), "--output", output}, &messages, &messages, func(string) string { return "" })
	report := readReport(t, output)
	if code != 2 || report.Result.Status != conformance.Unavailable || calls != 0 {
		t.Fatalf("code=%d report=%#v calls=%d", code, report, calls)
	}
	info, _ := os.Stat(output)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("output permissions=%v", info.Mode())
	}
	if report.CredentialSource != "environment" || strings.Contains(messages.String(), server.URL) {
		t.Fatalf("unsafe output %q", messages.String())
	}
}

func TestQualificationActualHTTPFixturePassesAndWritesOnlyIsolatedNonceObjects(t *testing.T) {
	var mu sync.Mutex
	objects := map[string][]byte{}
	etags := map[string]string{}
	sequence := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		key := r.URL.Path
		if !strings.HasPrefix(key, "/existing-bucket/.doctor/cas-") || len(strings.TrimPrefix(key, "/existing-bucket/.doctor/cas-")) != 32 {
			t.Errorf("unsafe probe key %q", key)
			w.WriteHeader(400)
			return
		}
		fail := func(code int) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(code)
			io.WriteString(w, "<Error><Code>PreconditionFailed</Code></Error>")
		}
		switch r.Method {
		case "GET":
			data, ok := objects[key]
			if !ok {
				fail(404)
				return
			}
			w.Header().Set("ETag", etags[key])
			w.Write(data)
		case "PUT":
			_, exists := objects[key]
			if r.Header.Get("If-None-Match") == "*" {
				if exists {
					fail(412)
					return
				}
			} else if !exists || r.Header.Get("If-Match") != etags[key] {
				fail(412)
				return
			}
			data, _ := io.ReadAll(r.Body)
			sequence++
			objects[key] = data
			etags[key] = fmt.Sprintf("\"opaque-%d\"", sequence)
			w.Header().Set("ETag", etags[key])
		case "DELETE":
			if r.Header.Get("If-Match") != etags[key] {
				fail(412)
				return
			}
			delete(objects, key)
			delete(etags, key)
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected method %s", r.Method)
			fail(400)
		}
	}))
	defer server.Close()
	output := filepath.Join(privateTestDirectory(t), "result.json")
	var messages bytes.Buffer
	code := run(context.Background(), []string{"--config", fixtureConfiguration(t, server.URL), "--output", output}, &messages, &messages, fixtureEnvironment)
	report := readReport(t, output)
	if code != 0 || report.Result.Status != conformance.Pass || len(report.Observations) != 12 || len(objects) != 0 {
		t.Fatalf("code=%d report=%#v objects=%d", code, report, len(objects))
	}
	data, _ := os.ReadFile(output)
	for _, secret := range []string{"fixture-access", "fixture-secret", server.URL} {
		if bytes.Contains(data, []byte(secret)) || strings.Contains(messages.String(), secret) {
			t.Fatalf("report exposed confidential input")
		}
	}
	if report.EndpointDigest == "" || report.BucketDigest == "" {
		t.Fatal("target hashes missing")
	}
}

func TestQualificationRejectsMalformedConfigurationAndUnsafeCredentialFiles(t *testing.T) {
	for _, input := range []string{`{"schemaVersion":1,"endpoint":"https://secret@example.com","unknown":"secret"}`, `{"schemaVersion":1} trailing`, strings.Repeat("x", 65537)} {
		config := filepath.Join(t.TempDir(), "bad.json")
		os.WriteFile(config, []byte(input), 0600)
		output := filepath.Join(privateTestDirectory(t), "result.json")
		var messages bytes.Buffer
		code := run(context.Background(), []string{"--config", config, "--output", output}, &messages, &messages, fixtureEnvironment)
		if code != 1 || readReport(t, output).Result.Status != conformance.Fail || strings.Contains(messages.String(), "secret") {
			t.Fatalf("invalid configuration response=%d %q", code, messages.String())
		}
	}
	root := t.TempDir()
	credentials := filepath.Join(root, "credentials.json")
	os.WriteFile(credentials, []byte(`{"accessKeyId":"access-secret","secretAccessKey":"secret-value"}`), 0644)
	config := qualificationConfig{SchemaVersion: 1, Endpoint: "https://example.com", Region: "us-east-1", Bucket: "existing-bucket", Credentials: credentialConfig{Source: "file", File: credentials}}
	report := qualify(context.Background(), config, fixtureEnvironment)
	if report.Result.Status != conformance.Fail {
		t.Fatalf("public credentials accepted: %#v", report)
	}
	os.Chmod(credentials, 0600)
	link := filepath.Join(root, "link.json")
	os.Symlink(credentials, link)
	config.Credentials.File = link
	if r := qualify(context.Background(), config, fixtureEnvironment); r.Result.Status != conformance.Fail {
		t.Fatalf("symlink credentials accepted: %#v", r)
	}
}

func TestQualificationDoesNotMutateStoreWhenOutputAlreadyExists(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
	defer server.Close()
	output := filepath.Join(privateTestDirectory(t), "result.json")
	os.WriteFile(output, []byte("preserve"), 0600)
	var messages bytes.Buffer
	if code := run(context.Background(), []string{"--config", fixtureConfiguration(t, server.URL), "--output", output}, &messages, &messages, fixtureEnvironment); code != 1 {
		t.Fatalf("exit=%d", code)
	}
	content, _ := os.ReadFile(output)
	if calls != 0 || string(content) != "preserve" {
		t.Fatal("existing output overwritten or probe started")
	}
}

func TestQualificationRejectsPublicOutputDirectoryBeforeProviderWrites(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
	defer server.Close()
	directory := t.TempDir()
	os.Chmod(directory, 0755)
	output := filepath.Join(directory, "result.json")
	var messages bytes.Buffer
	if code := run(context.Background(), []string{"--config", fixtureConfiguration(t, server.URL), "--output", output}, &messages, &messages, fixtureEnvironment); code != 1 || calls != 0 {
		t.Fatalf("public output code=%d calls=%d", code, calls)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("private report created in public directory")
	}
}

func TestQualificationMissingConfigurationIsUnavailableWithPrivateReport(t *testing.T) {
	output := filepath.Join(privateTestDirectory(t), "result.json")
	var messages bytes.Buffer
	if code := run(context.Background(), []string{"--config", filepath.Join(t.TempDir(), "missing.json"), "--output", output}, &messages, &messages, fixtureEnvironment); code != 2 {
		t.Fatalf("missing input exit=%d", code)
	}
	if report := readReport(t, output); report.Result.Status != conformance.Unavailable || len(report.Observations) != 0 {
		t.Fatalf("missing input report=%#v", report)
	}
}

func TestQualificationRejectsDuplicateJSONFieldsBeforeProviderWrites(t *testing.T) {
	var config qualificationConfig
	path := filepath.Join(t.TempDir(), "duplicate.json")
	os.WriteFile(path, []byte(`{"schemaVersion":0,"schemaVersion":1,"endpoint":"https://example.com","region":"us-east-1","bucket":"existing-bucket","credentials":{"source":"file","source":"environment"}}`), 0600)
	if err := readJSONFile(path, &config, false); err == nil {
		t.Fatal("duplicate qualification fields accepted")
	}
	var values credentialValues
	os.WriteFile(path, []byte(`{"accessKeyId":"first","accessKeyId":"second","secretAccessKey":"fixture-secret"}`), 0600)
	if err := readJSONFile(path, &values, true); err == nil {
		t.Fatal("duplicate credential fields accepted")
	}
}

func TestQualificationRejectsCaseFoldedTargetAndCredentialAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aliases.json")
	for _, input := range []string{`{"endpoint":"https://approved.example.com","Endpoint":"https://other.example.com"}`, `{"credentials":{"source":"file","Source":"environment"}}`, `{"credentials":{"source":"file","\u017Fource":"environment"}}`} {
		os.WriteFile(path, []byte(input), 0600)
		var config qualificationConfig
		if err := readJSONFile(path, &config, false); err == nil {
			t.Fatal("case-folded target or credential alias accepted")
		}
	}
	os.WriteFile(path, []byte(`{"accessKeyId":"first","AccessKeyID":"second","secretAccessKey":"fixture-secret"}`), 0600)
	var values credentialValues
	if err := readJSONFile(path, &values, true); err == nil {
		t.Fatal("case-folded credential value alias accepted")
	}
}

func TestQualificationNetworkUnavailableIsBoundedAndRedacted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>credential-secret</Message></Error>")
	}))
	defer server.Close()
	output := filepath.Join(privateTestDirectory(t), "result.json")
	var messages bytes.Buffer
	start := time.Now()
	code := run(context.Background(), []string{"--config", fixtureConfiguration(t, server.URL), "--output", output}, &messages, &messages, fixtureEnvironment)
	report := readReport(t, output)
	encoded, _ := json.Marshal(report)
	if code != 2 || report.Result.Status != conformance.Unavailable || time.Since(start) > time.Second || bytes.Contains(encoded, []byte("credential-secret")) {
		t.Fatalf("unavailable=%d %#v", code, report)
	}
}
