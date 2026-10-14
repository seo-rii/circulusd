package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
)

func testConfig(t *testing.T, upstream string) config {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return config{SchemaVersion: 1, ListenAddress: address, UpstreamEndpoint: upstream, Bucket: "qualification", ControlSocket: filepath.Join(parent, "control.sock"), RequestTimeoutMillis: 1000, HoldTimeoutMillis: 2000}
}

func relayRequest(t *testing.T, c config, method, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+c.ListenAddress+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "test-signed-header")
	req.Header.Set("X-Amz-Content-Sha256", digest([]byte(body)))
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestRelayGatesOnlySameCellEpochAfterSuccessfulLTX(t *testing.T) {
	var mu sync.Mutex
	owner := `{"node":"old-session","epoch":7}`
	var cfg config
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Host != cfg.ListenAddress || r.Header.Get("Authorization") != "test-signed-header" || r.Header.Get("X-Amz-Content-Sha256") == "" {
			t.Error("signed Host/header changed")
		}
		if r.URL.Path == "/qualification/cells/native-cell/own.json" {
			mu.Lock()
			defer mu.Unlock()
			w.Header().Set("ETag", `"opaque-owner"`)
			_, _ = io.WriteString(w, owner)
			return
		}
		if r.Method == http.MethodPut {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()
	cfg = testConfig(t, server.URL)
	r, err := newRelay(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if f := r.command(controlRequest{Operation: "arm", CellID: "native-cell", PriorEpoch: 7}); f.Error != "" {
		t.Fatal(f.Error)
	}
	// Ownership reads and PUTs from another cell/epoch cannot arm the proof gate.
	resp := relayRequest(t, cfg, http.MethodGet, "/qualification/cells/native-cell/own.json", "")
	resp.Body.Close()
	for _, p := range []string{"/qualification/cells/another-cell/ltx/e7/one.ltx", "/qualification/cells/native-cell/ltx/e6/one.ltx"} {
		resp = relayRequest(t, cfg, http.MethodPut, p, "native-ltx")
		resp.Body.Close()
	}
	if f := r.command(controlRequest{Operation: "status"}); f.State != "armed" || f.LTXPutStatus != 0 {
		t.Fatalf("false native proof gate: %+v", f)
	}
	resp = relayRequest(t, cfg, http.MethodPut, "/qualification/cells/native-cell/ltx/e7/one.ltx", "native-ltx")
	resp.Body.Close()
	response := make(chan *http.Response, 1)
	go func() {
		response <- relayRequest(t, cfg, http.MethodGet, "/qualification/cells/native-cell/own.json", "")
	}()
	deadline := time.Now().Add(time.Second)
	for r.command(controlRequest{Operation: "status"}).State != "held" {
		if time.Now().After(deadline) {
			t.Fatal("ownership read not held")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-response:
		t.Fatal("proof forwarded before release")
	default:
	}
	before := requests.Load()
	mu.Lock()
	owner = `{"node":"new-session","epoch":8}`
	mu.Unlock()
	if f := r.command(controlRequest{Operation: "release"}); f.Error != "" {
		t.Fatal(f.Error)
	}
	resp = <-response
	payload, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	f := r.command(controlRequest{Operation: "status"})
	if f.State != "completed" || f.HeldRequests != 1 || f.LTXBodyDigest != digest([]byte("native-ltx")) || f.ProofOwnershipRead.ETag != `"opaque-owner"` || f.ProofOwnershipRead.Body != base64.StdEncoding.EncodeToString(payload) || f.OwnershipGetStatus != 200 || requests.Load() != before+1 ||
		f.LTXPutCompletedSequence >= f.OwnershipGetStartedSequence || f.OwnershipGetStartedSequence >= f.OwnershipGetReleasedSequence || f.OwnershipGetReleasedSequence >= f.OwnershipGetCompletedSequence {
		t.Fatalf("incorrect proof transcript: %+v", f)
	}
}

func TestRelayRejectsFailedLTXAndNeverRetriesMutations(t *testing.T) {
	var puts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			puts.Add(1)
			w.WriteHeader(500)
		} else {
			w.Header().Set("ETag", `"old"`)
			_, _ = io.WriteString(w, `{"node":"old","epoch":1}`)
		}
	}))
	defer server.Close()
	c := testConfig(t, server.URL)
	r, err := newRelay(c)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.command(controlRequest{Operation: "arm", CellID: "cell", PriorEpoch: 1})
	resp := relayRequest(t, c, http.MethodPut, "/qualification/cells/cell/ltx/e1/x.ltx", "x")
	resp.Body.Close()
	resp = relayRequest(t, c, http.MethodGet, "/qualification/cells/cell/own.json", "")
	resp.Body.Close()
	f := r.command(controlRequest{Operation: "status"})
	if puts.Load() != 1 || f.HeldRequests != 0 || f.State != "armed" || f.LTXPutStatus != 0 {
		t.Fatalf("failed mutation claimed proof: %+v", f)
	}
}

func TestRelayPreservesCanonicalEscapedNativeCellColon(t *testing.T) {
	var cfg config
	var paths []string
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		paths = append(paths, req.URL.EscapedPath())
		mu.Unlock()
		if req.Host != cfg.ListenAddress || req.Header.Get("Authorization") != "test-signed-header" {
			t.Error("signed authority changed")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	cfg = testConfig(t, server.URL)
	r, err := newRelay(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	encoded := "/qualification/cells/NativeStorageQualificationCell%3A123/ltx/e7/one.ltx"
	response := relayRequest(t, cfg, http.MethodPut, encoded, "native-ltx")
	response.Body.Close()
	mu.Lock()
	if response.StatusCode != 200 || len(paths) != 1 || paths[0] != encoded {
		t.Fatalf("native signed escaped path changed: status=%d paths=%v", response.StatusCode, paths)
	}
	mu.Unlock()
	for _, ambiguous := range []string{
		"/qualification/cells/NativeStorageQualificationCell%3a123/own.json",
		"/qualification/cells/NativeStorageQualificationCell%2F123/own.json",
	} {
		response = relayRequest(t, cfg, http.MethodGet, ambiguous, "")
		response.Body.Close()
		mu.Lock()
		if response.StatusCode != 400 || len(paths) != 1 {
			t.Fatal("accepted ambiguous escaped native key")
		}
		mu.Unlock()
	}
}

func TestUnixControlHasPrivateOwnedSocketAndOneShotState(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	c := testConfig(t, server.URL)
	r, err := newRelay(c)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(c.ControlSocket)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("socket not private")
	}
	f, err := control(context.Background(), c.ControlSocket, controlRequest{Operation: "arm", CellID: "cell", PriorEpoch: 2})
	if err != nil || f.State != "armed" {
		t.Fatalf("arm: %v %+v", err, f)
	}
	f, err = control(context.Background(), c.ControlSocket, controlRequest{Operation: "arm", CellID: "cell", PriorEpoch: 2})
	if err != nil || f.Error == "" {
		t.Fatal("accepted repeated arm")
	}
	f, err = control(context.Background(), c.ControlSocket, controlRequest{Operation: "release"})
	if err != nil || f.Error == "" {
		t.Fatal("accepted release without observed proof")
	}
	r.Close()
	if _, err = os.Lstat(c.ControlSocket); !os.IsNotExist(err) {
		t.Fatal("socket was not cleaned")
	}
}

func TestRelayRejectsExistingControlFilesAndNonLoopbackOrigins(t *testing.T) {
	c := testConfig(t, "http://127.0.0.1:12345")
	for _, endpoint := range []string{"http://example.test:12345", "http://127.0.0.1:12345/path", "http://127.0.0.1:12345?x=1", "http://user@127.0.0.1:12345", "https://127.0.0.1:12345"} {
		bad := c
		bad.UpstreamEndpoint = endpoint
		if validRelayConfig(bad) {
			t.Fatalf("accepted origin %s", endpoint)
		}
	}
	if err := os.WriteFile(c.ControlSocket, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if r, err := newRelay(c); err == nil {
		r.Close()
		t.Fatal("replaced existing control file")
	}
	data, _ := os.ReadFile(c.ControlSocket)
	if string(data) != "preserve" {
		t.Fatal("changed unrelated file")
	}
}

func TestPrivateInputRejectsJSONAliasesMissingFieldsAndUnsafeFiles(t *testing.T) {
	c := testConfig(t, "http://127.0.0.1:12345")
	path := filepath.Join(filepath.Dir(c.ControlSocket), "config.json")
	encoded, _ := json.Marshal(c)
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	var actual config
	if err := readPrivate(path, &actual); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{`{"schemaVersion":1}`, strings.Replace(string(encoded), `"schemaVersion":1`, `"schemaVersion":1,"SchemaVersion":1`, 1), strings.Replace(string(encoded), `"bucket":"qualification"`, `"bucket":null`, 1)} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if readPrivate(path, &actual) == nil {
			t.Fatal("accepted ambiguous input")
		}
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if readPrivate(path, &actual) == nil {
		t.Fatal("accepted readable credentials")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if readPrivate(link, &actual) == nil {
		t.Fatal("accepted symlink")
	}
}

func TestReportCreationDoesNotClobberOrFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "result.json")
	f, err := createPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err = createPrivate(path); err == nil {
		t.Fatal("clobbered prior report")
	}
	link := filepath.Join(dir, "link")
	os.Symlink(path, link)
	if _, err = createPrivate(link); err == nil {
		t.Fatal("followed output symlink")
	}
}

// nativeStorageResponseMAC mirrors the native storage response signature so
// the direct snapshot read that precedes the relayed write authenticates.
func nativeStorageResponseMAC(root []byte, parts ...[]byte) string {
	derive := hmac.New(sha256.New, root)
	derive.Write([]byte("circulusd.native-storage.key.response.v1\x00"))
	mac := hmac.New(sha256.New, derive.Sum(nil))
	for _, part := range parts {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		mac.Write(size[:])
		mac.Write(part)
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func TestCommitReportsRelayFactsOnlyAfterHandlerStops(t *testing.T) {
	for _, mode := range []string{"rejected", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			root := bytes.Repeat([]byte{0x5a}, 32)
			const keyID, objectID, contentType = "observer", "native-owner-object", "application/vnd.circulusd.native-storage+cbor"
			options := canonical.Options{MaxBytes: 1 << 20, MaxDepth: 72, MaxItems: 100_000}
			forwarded := make(chan struct{})
			var forwardOnce sync.Once
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				value, err := canonical.Decode(body, options)
				request, ok := value.(canonical.Map)
				if err != nil || !ok {
					t.Error("invalid native storage request")
					return
				}
				if request["operation"] == "commit" {
					forwardOnce.Do(func() { close(forwarded) })
					if mode == "rejected" {
						http.Error(w, "prior owner fenced", http.StatusServiceUnavailable)
						return
					}
					// Stall the relayed write until the relay abandons it.
					<-r.Context().Done()
					return
				}
				framed, _ := canonical.Encode(canonical.Array{"circulusd.hash", int64(1), "circulusd.native.storage.request", int64(1), request}, options)
				response, _ := canonical.Encode(canonical.Map{"protocol": request["protocol"], "major": int64(1), "minor": int64(0), "schemaDigest": request["schemaDigest"],
					"requestId": request["requestId"], "requestDigest": fmt.Sprintf("sha256:%x", sha256.Sum256(framed)), "payload": canonical.Map{"ok": true, "result": canonical.Map{
						"snapshot": canonical.Map{"objectId": objectID, "exists": false, "revision": int64(0), "stateDigest": fmt.Sprintf("sha256:%x", sha256.Sum256(nil))}, "state": canonical.Bytes{}}}}, options)
				requestSum, responseSum := sha256.Sum256(body), sha256.Sum256(response)
				w.Header().Set("Content-Type", contentType)
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("X-Circulus-Storage-Key-Id", keyID)
				w.Header().Set("X-Circulus-Storage-Signature", nativeStorageResponseMAC(root, []byte("circulusd.native-storage.response.v1"), []byte(keyID),
					[]byte(request["requestId"].(string)), requestSum[:], []byte("200"), []byte(contentType), responseSum[:]))
				_, _ = w.Write(response)
			}))
			defer upstream.Close()
			if mode == "timeout" {
				original := awaitTranscript
				defer func() { awaitTranscript = original }()
				awaitTranscript = func(<-chan struct{}, time.Duration) bool {
					select {
					case <-forwarded:
					case <-time.After(5 * time.Second):
						t.Error("relayed write never reached the native source")
					}
					return false
				}
			}
			cfg := config{SchemaVersion: 1, RequestTimeoutMillis: 200, Endpoint: upstream.URL, KeyID: keyID, RootKeyHex: hex.EncodeToString(root), ObjectID: objectID}
			facts, err := commit(context.Background(), cfg)
			if mode == "rejected" {
				if err != nil || facts.HTTPStatus != http.StatusServiceUnavailable || facts.ClientErrorCode != "HTTP_FAILURE" || facts.Acknowledged || facts.RequestCount != 1 {
					t.Fatalf("rejected write: facts=%+v err=%v", facts, err)
				}
				return
			}
			if err == nil || err.Error() != "pending transcript unavailable" {
				t.Fatalf("commit() error = %v, want pending transcript timeout", err)
			}
			if facts.RequestCount != 1 || facts.StartedSequence == 0 || facts.ResponseSequence < facts.StartedSequence {
				t.Fatalf("timed-out report omitted the relay's facts: %+v", facts)
			}
		})
	}
}
