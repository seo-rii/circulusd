package objectstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/hancomac/circulusd/internal/conformance"
)

func TestS3StoreSignsExactEscapedPathAndConditionalHeaders(t *testing.T) {
	const key = "keys/a b%?#/한글"
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if r.URL.EscapedPath() != "/existing-bucket/keys/a%20b%25%3F%23/%ED%95%9C%EA%B8%80" {
			t.Errorf("escaped path=%q", r.URL.EscapedPath())
		}
		original := r.Header.Get("Authorization")
		expected := r.Clone(context.Background())
		expected.URL.Scheme = "http"
		expected.URL.Host = r.Host
		expected.Header = r.Header.Clone()
		expected.Header.Del("Authorization")
		signingTime, e := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
		if e != nil {
			t.Error(e)
			return
		}
		payload := r.Header.Get("X-Amz-Content-Sha256")
		if payload != "UNSIGNED-PAYLOAD" {
			sum := sha256.Sum256(data)
			if payload != hex.EncodeToString(sum[:]) {
				t.Error("payload signing digest does not match request body")
			}
		}
		e = v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: "fixture-access", SecretAccessKey: "fixture-secret"}, expected, payload, "s3", "us-east-1", signingTime, func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
		if e != nil || original != expected.Header.Get("Authorization") {
			t.Errorf("official re-sign differs (signer error=%v)", e)
		}
		if r.Header.Get("If-None-Match") != "" && !strings.Contains(original, "if-none-match") {
			t.Error("If-None-Match was not signed")
		}
		if r.Header.Get("If-Match") != "" && !strings.Contains(original, "if-match") {
			t.Error("If-Match was not signed")
		}
		seen = append(seen, r.Method)
		w.Header().Set("ETag", "\"opaque-native\"")
		if r.Method == http.MethodDelete {
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	store, e := NewS3Store(s3Options(server.URL))
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	ctx := context.Background()
	if _, e := store.PutIfAbsent(ctx, BucketCelldState, key, []byte("payload")); e != nil {
		t.Fatal(e)
	}
	if _, e := store.CompareAndSwap(ctx, BucketCelldState, key, "\"opaque-native\"", []byte("replacement")); e != nil {
		t.Fatal(e)
	}
	if e := store.DeleteIfMatch(ctx, BucketCelldState, key, "\"opaque-native\""); e != nil {
		t.Fatal(e)
	}
	if strings.Join(seen, ",") != "PUT,PUT,DELETE" {
		t.Fatalf("methods=%v", seen)
	}
}

func TestS3StoreDoesNotRetryPersistedWriteAfterAmbiguousResponse(t *testing.T) {
	var mutations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Error("unexpected method")
			return
		}
		io.Copy(io.Discard, r.Body)
		mutations.Add(1)
		w.WriteHeader(500)
		io.WriteString(w, "<Error><Code>InternalError</Code><Message>response lost after persistence</Message></Error>")
	}))
	defer server.Close()
	store, e := NewS3Store(s3Options(server.URL))
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	if _, e := store.PutIfAbsent(context.Background(), BucketCelldState, "object", []byte("durable")); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("ambiguous write=%v", e)
	}
	if mutations.Load() != 1 {
		t.Fatalf("persisted mutation attempts=%d", mutations.Load())
	}
}

func TestS3StoreBoundsOversizedSDKErrorResponsesAndRejectsPartialBodies(t *testing.T) {
	for _, status := range []int{200, 500} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.Header().Set("ETag", "\"opaque\"")
			w.WriteHeader(status)
			io.WriteString(w, "<Error><Code>InternalError</Code><Message>"+strings.Repeat("provider-secret", 10000)+"</Message></Error>")
		}))
		store, e := NewS3Store(s3Options(server.URL))
		if e != nil {
			t.Fatal(e)
		}
		_, e = store.PutIfAbsent(context.Background(), BucketCelldState, "object", []byte("payload"))
		store.Close()
		server.Close()
		if !errors.Is(e, ErrUnavailable) || strings.Contains(e.Error(), "provider-secret") {
			t.Fatalf("oversized status %d response=%v", status, e)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, buffer, e := w.(http.Hijacker).Hijack()
		if e != nil {
			t.Error(e)
			return
		}
		defer connection.Close()
		io.WriteString(buffer, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nETag: \"opaque\"\r\n\r\nabc")
		buffer.Flush()
	}))
	defer server.Close()
	store, e := NewS3Store(s3Options(server.URL))
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	if object, e := store.Get(context.Background(), BucketCelldState, "object"); !errors.Is(e, ErrUnavailable) || len(object.Data) != 0 {
		t.Fatalf("partial body accepted: %#v %v", object, e)
	}
}

func newS3Fixture(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	objects := map[string]Object{}
	sequence := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/existing-bucket/") || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Errorf("unexpected request method/path or unsigned request")
			http.Error(w, "invalid", 400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		key := strings.TrimPrefix(r.URL.Path, "/existing-bucket/")
		current, exists := objects[key]
		fail := func(status int, code string) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(status)
			fmt.Fprintf(w, "<Error><Code>%s</Code><Message>secret-must-never-appear</Message></Error>", code)
		}
		switch r.Method {
		case "PUT":
			if r.Header.Get("If-None-Match") == "*" {
				if exists {
					fail(412, "PreconditionFailed")
					return
				}
			} else if r.Header.Get("If-Match") == "" {
				fail(412, "PreconditionFailed")
				return
			} else if !exists {
				// AWS answers a conditional update of a missing key with 404.
				fail(404, "NoSuchKey")
				return
			} else if r.Header.Get("If-Match") != string(current.ETag) {
				fail(412, "PreconditionFailed")
				return
			}
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			sequence++
			etag := ETag(fmt.Sprintf("\"native-%03d-multipart\"", sequence))
			objects[key] = Object{Data: data, ETag: etag}
			w.Header().Set("ETag", string(etag))
			w.WriteHeader(200)
		case "GET":
			if !exists {
				fail(404, "NoSuchKey")
				return
			}
			w.Header().Set("ETag", string(current.ETag))
			w.Write(current.Data)
		case "DELETE":
			if !exists || r.Header.Get("If-Match") != string(current.ETag) {
				fail(412, "PreconditionFailed")
				return
			}
			delete(objects, key)
			w.WriteHeader(204)
		default:
			t.Errorf("forbidden API method %s", r.Method)
			w.WriteHeader(400)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func s3Options(endpoint string) S3StoreOptions {
	return S3StoreOptions{Endpoint: endpoint, Region: "us-east-1", Bucket: "existing-bucket", AccessKeyID: "fixture-access", SecretAccessKey: "fixture-secret", RequestTimeout: time.Second, MaximumObjectBytes: 1 << 20}
}

func TestS3StoreQualifiesOpaqueNativeETagsWithSignedConditionalHeaders(t *testing.T) {
	server := newS3Fixture(t)
	var observations []ProbeObservation
	result := ProbeCAS(context.Background(), ProbeConfig{Component: "object-store/s3-cas", Mock: true, Observe: func(o ProbeObservation) { observations = append(observations, o) }, Open: func(context.Context) (Store, error) { return NewS3Store(s3Options(server.URL)) }})
	if result.Status != conformance.Pass {
		t.Fatalf("CAS=%#v", result)
	}
	if len(observations) != 12 {
		t.Fatalf("observations=%#v", observations)
	}
	for _, o := range observations {
		if !o.Passed {
			t.Fatalf("failed observation %#v", o)
		}
		if o.Stage == "single concurrent winner" && (o.Contenders != 32 || o.Winners != 1 || o.Losers != 31) {
			t.Fatalf("incorrect CAS count evidence %#v", o)
		}
	}
}

func TestS3StoreReportsCompareAndSwapOfMissingObjectAsNotFound(t *testing.T) {
	server := newS3Fixture(t)
	store, err := NewS3Store(s3Options(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, e := store.CompareAndSwap(context.Background(), BucketCelldState, "missing", "\"native-001-multipart\"", []byte("data")); !errors.Is(e, ErrNotFound) {
		t.Fatalf("missing-object CAS=%v, want ErrNotFound", e)
	}
	if _, e := store.Get(context.Background(), BucketCelldState, "missing"); !errors.Is(e, ErrNotFound) {
		t.Fatalf("missing-object CAS created the object: %v", e)
	}
}

func TestS3StoreRejectsUnsafeConfigurationWithoutRequests(t *testing.T) {
	for _, endpoint := range []string{"", "http://example.com", "https://user:secret@example.com", "https://example.com/path", "https://example.com?secret=value", "ftp://example.com", "https://example.com#secret"} {
		_, err := NewS3Store(s3Options(endpoint))
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid configuration was accepted or disclosed")
		}
	}
	for _, mutate := range []func(*S3StoreOptions){func(o *S3StoreOptions) { o.Bucket = "other/bucket" }, func(o *S3StoreOptions) { o.AccessKeyID = "" }, func(o *S3StoreOptions) { o.SecretAccessKey = "" }, func(o *S3StoreOptions) { o.RequestTimeout = 31 * time.Second }, func(o *S3StoreOptions) { o.MaximumObjectBytes = 65 << 20 }, func(o *S3StoreOptions) { o.Region = "bad region" }} {
		o := s3Options("https://example.com")
		mutate(&o)
		if _, e := NewS3Store(o); e == nil {
			t.Fatal("invalid option accepted")
		}
	}
}

func TestS3StorePreservesNativeETagRejectsInvalidTokensAndScopesBucket(t *testing.T) {
	server := newS3Fixture(t)
	store, err := NewS3Store(s3Options(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	etag, err := store.PutIfAbsent(context.Background(), BucketCelldState, "a b/key", []byte("one"))
	if err != nil || etag != "\"native-001-multipart\"" {
		t.Fatalf("etag=%q err=%v", etag, err)
	}
	for _, bad := range []ETag{"", "*", "W/\"weak\"", "\"a\"\r\nx-secret: injected", "unquoted", "\"a\"b\""} {
		if _, e := store.CompareAndSwap(context.Background(), BucketCelldState, "a b/key", bad, nil); !errors.Is(e, ErrInvalidETag) {
			t.Fatalf("invalid ETag accepted: %q %v", bad, e)
		}
	}
	if _, e := store.Get(context.Background(), BucketArtifacts, "a b/key"); !errors.Is(e, ErrInvalidBucket) {
		t.Fatalf("wrong logical bucket=%v", e)
	}
	if _, e := store.Get(context.Background(), BucketCelldState, "../escape"); !errors.Is(e, ErrInvalidKey) {
		t.Fatalf("escaping key=%v", e)
	}
	if e := store.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := store.Get(context.Background(), BucketCelldState, "a b/key"); !errors.Is(e, ErrClosed) {
		t.Fatalf("closed client=%v", e)
	}
}

func TestS3StoreBoundsRequestResponseAndRedactsProviderErrors(t *testing.T) {
	for _, status := range []int{403, 500, 412, 404} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>credential-secret-value</Message></Error>")
		}))
		store, e := NewS3Store(s3Options(server.URL))
		if e != nil {
			t.Fatal(e)
		}
		_, e = store.Get(context.Background(), BucketCelldState, "object")
		store.Close()
		server.Close()
		if e == nil || strings.Contains(e.Error(), "credential-secret-value") {
			t.Fatalf("provider error disclosed: %v", e)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "\"opaque\"")
		io.WriteString(w, strings.Repeat("x", 20))
	}))
	defer server.Close()
	options := s3Options(server.URL)
	options.MaximumObjectBytes = 8
	store, e := NewS3Store(options)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	if _, e := store.PutIfAbsent(context.Background(), BucketCelldState, "object", make([]byte, 9)); !errors.Is(e, ErrObjectTooLarge) {
		t.Fatalf("oversized input=%v", e)
	}
	if _, e := store.Get(context.Background(), BucketCelldState, "object"); !errors.Is(e, ErrObjectTooLarge) {
		t.Fatalf("oversized response=%v", e)
	}
}

func TestS3StoreDoesNotFollowRedirectsOrRetryAmbiguousWrites(t *testing.T) {
	var followed atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1); w.WriteHeader(200) }))
	defer destination.Close()
	var calls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	store, e := NewS3Store(s3Options(origin.URL))
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	_, e = store.PutIfAbsent(context.Background(), BucketCelldState, "object", []byte("a"))
	if e == nil || followed.Load() != 0 || calls.Load() != 1 {
		t.Fatalf("redirect/retry: err=%v calls=%d followed=%d", e, calls.Load(), followed.Load())
	}
}

func TestS3StoreHonorsBoundedHTTPTimeoutAndIgnoresProxyEnvironment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	o := s3Options(server.URL)
	o.RequestTimeout = 40 * time.Millisecond
	store, e := NewS3Store(o)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	start := time.Now()
	_, e = store.Get(context.Background(), BucketCelldState, "object")
	if e == nil || time.Since(start) > time.Second {
		t.Fatalf("timeout not bounded: %v", e)
	}
}
