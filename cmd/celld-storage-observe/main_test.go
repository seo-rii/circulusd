package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	celldconformance "github.com/hancomac/circulusd/internal/conformance/celld"
)

func writeConfig(t *testing.T, dir string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func configFixture() observationConfig {
	digest := "sha256:" + strings.Repeat("1", 64)
	return observationConfig{SchemaVersion: 1, Endpoint: "http://127.0.0.1:29930", KeyID: "qualification", RootKeyHex: strings.Repeat("ab", 32), RunID: strings.Repeat("cd", 32), RequestTimeoutMillis: 1000, TimeoutMillis: 3000,
		ClaimedBinding: celldconformance.ObservationBinding{ReleaseDigest: digest, ExecutableDigest: digest, ApplicationDigest: digest, EffectiveConfigDigest: digest, DurabilityDomain: "qualification", DurabilityEpoch: 1}}
}
func TestPrivateInputRejectsAliasesDuplicatesAndUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	config, _ := json.Marshal(configFixture())
	for _, data := range []string{strings.Replace(string(config), `"endpoint"`, `"Endpoint"`, 1), strings.Replace(string(config), `"schemaVersion":1`, `"schemaVersion":1,"SchemaVersion":1`, 1), string(config) + " {}", `{"schemaVersion":1,"nested":{}}`, strings.Repeat("[", 17) + "0" + strings.Repeat("]", 17)} {
		path := writeConfig(t, dir, []byte(data))
		var parsed observationConfig
		if readPrivateJSON(path, &parsed) == nil {
			t.Fatal("ambiguous input accepted")
		}
	}
	path := writeConfig(t, dir, config)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	var parsed observationConfig
	if readPrivateJSON(path, &parsed) == nil {
		t.Fatal("public key configuration accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "symlink.json")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if readPrivateJSON(symlink, &parsed) == nil {
		t.Fatal("input symlink accepted")
	}
	if err := os.Link(path, filepath.Join(dir, "hardlink.json")); err != nil {
		t.Fatal(err)
	}
	if readPrivateJSON(path, &parsed) == nil {
		t.Fatal("linked input accepted")
	}
}
func TestReportIsPrivateExclusiveAndRejectsSharedParent(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "report.json")
	file, err := openPrivateReport(path)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("report not private")
	}
	if _, err := openPrivateReport(path); err == nil {
		t.Fatal("existing report overwritten")
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openPrivateReport(link); err == nil {
		t.Fatal("report symlink accepted")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := openPrivateReport(filepath.Join(dir, "new.json")); err == nil {
		t.Fatal("shared report directory accepted")
	}
}
func TestResponseDropRelayConsumesOneRealResponseWithoutForwarding(t *testing.T) {
	var count atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("x-private-auth") != "signed" || string(body) != "transaction" {
			t.Error("relay changed signed request")
		}
		w.Header().Set("Content-Type", "application/vnd.circulusd.native-storage+cbor")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("private signed native reply"))
	}))
	defer backend.Close()
	relay, err := newResponseDropRelay(backend.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	request, _ := http.NewRequest(http.MethodPost, relay.endpoint()+"/circulusd/native-storage/v1/transaction", strings.NewReader("transaction"))
	request.Header.Set("x-private-auth", "signed")
	connection, err := net.DialTimeout("tcp4", strings.TrimPrefix(relay.endpoint(), "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := request.Write(connection); err != nil {
		t.Fatal(err)
	}
	received, err := io.ReadAll(connection)
	if err != nil || len(received) != 0 {
		t.Fatalf("HTTP headers or response body reached caller: %d bytes, %v", len(received), err)
	}
	facts := relay.facts()
	if count.Load() != 1 || facts.RequestCount != 1 || facts.BackendStatus != 200 || facts.ReceivedBytes == nil || *facts.ReceivedBytes != 0 {
		t.Fatal("relay did not observe exactly one acknowledged backend response")
	}
	encoded, _ := json.Marshal(facts)
	if !bytes.Contains(encoded, []byte(`"receivedBytes":0`)) {
		t.Fatal("observed zero response bytes were omitted from raw JSON")
	}
	client := http.Client{Timeout: time.Second}
	request, _ = http.NewRequest(http.MethodPost, relay.endpoint()+"/circulusd/native-storage/v1/transaction", strings.NewReader("transaction"))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 409 || count.Load() != 1 || relay.facts().RequestCount != 2 {
		t.Fatal("relay permitted a second backend mutation")
	}
	if delivered := relay.facts().ReceivedBytes; delivered == nil || *delivered == 0 {
		t.Fatal("actual HTTP error headers/body were incorrectly measured as zero bytes")
	}
}
func TestResponseDropRelayRejectsOtherPathsBeforeBackendWrite(t *testing.T) {
	var count atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); w.WriteHeader(200) }))
	defer backend.Close()
	relay, err := newResponseDropRelay(backend.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	for _, target := range []string{"/other", "/circulusd/native-storage/v1/transaction?query=1"} {
		response, err := http.Post(relay.endpoint()+target, "application/octet-stream", strings.NewReader("data"))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 400 {
			t.Fatal("unexpected route accepted")
		}
	}
	if count.Load() != 0 || relay.facts().RequestCount != 0 {
		t.Fatal("invalid request reached backend")
	}
}

type visibleBeforeWriteReturns struct {
	net.Conn
	visible chan struct{}
	release chan struct{}
}

func (connection visibleBeforeWriteReturns) Write(data []byte) (int, error) {
	close(connection.visible)
	<-connection.release
	return len(data), nil
}

func TestResponseByteSnapshotWaitsForActualWritePublication(t *testing.T) {
	relay := new(responseDropRelay)
	relay.connections.Store(1)
	visible, release := make(chan struct{}), make(chan struct{})
	connection := responseObservationConnection{visibleBeforeWriteReturns{visible: visible, release: release}, relay}
	written := make(chan struct{})
	go func() {
		defer close(written)
		_, _ = connection.Write([]byte("HTTP headers visible to peer"))
	}()
	<-visible
	snapshot := make(chan celldconformance.ResponseLossFact, 1)
	go func() { snapshot <- relay.facts() }()
	select {
	case <-snapshot:
		close(release)
		<-written
		t.Fatal("in-flight delivered bytes were reported before their count was published")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-written
	select {
	case facts := <-snapshot:
		if facts.ReceivedBytes == nil || *facts.ReceivedBytes != uint64(len("HTTP headers visible to peer")) {
			t.Fatal("actual write completion did not publish delivered byte count")
		}
	case <-time.After(time.Second):
		t.Fatal("completed write left observation blocked")
	}
}
func TestUnavailableEndpointRecordsRawErrorWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	config := configFixture()
	config.KeyID = "private-observation-auth-key"
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	config.Endpoint = backend.URL
	backend.Close()
	data, _ := json.Marshal(config)
	path := writeConfig(t, dir, data)
	output := filepath.Join(dir, "raw.json")
	var stdout, stderr bytes.Buffer
	exit := run(context.Background(), []string{"--config", path, "--phase", "seed", "--output", output}, &stdout, &stderr)
	if exit != 2 {
		t.Fatalf("exit %d: %s", exit, stderr.String())
	}
	reportBytes, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var report celldconformance.ObservationReport
	if json.Unmarshal(reportBytes, &report) != nil || len(report.Errors) != 1 || report.Errors[0] != "snapshot-before:UNAVAILABLE" {
		t.Fatal("raw unavailable facts missing")
	}
	for _, exposed := range []string{config.RootKeyHex, config.KeyID, "PASS", "admissionReady"} {
		if bytes.Contains(reportBytes, []byte(exposed)) || strings.Contains(stdout.String()+stderr.String(), exposed) {
			t.Fatal("report exposed credentials or granted authority")
		}
	}
}
func TestInvalidConfigOrArgumentsNeverReserveReport(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(configFixture())
	path := writeConfig(t, dir, data)
	output := filepath.Join(dir, "raw.json")
	var stdout, stderr bytes.Buffer
	if run(context.Background(), []string{"--config", path, "--phase", "verify", "--output", output}, &stdout, &stderr) != 1 {
		t.Fatal("verify without seed accepted")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("invalid arguments created report")
	}
	config := configFixture()
	config.ClaimedBinding.DurabilityEpoch = 0
	data, _ = json.Marshal(config)
	writeConfig(t, dir, data)
	if run(context.Background(), []string{"--config", path, "--phase", "seed", "--output", output}, &stdout, &stderr) != 1 {
		t.Fatal("unbound epoch accepted")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("invalid config created report")
	}
}
