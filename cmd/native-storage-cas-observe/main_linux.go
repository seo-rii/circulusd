//go:build linux

// native-storage-cas-observe records actual S3 conditional responses. It emits
// the CAS member of a raw storage report; it cannot sign or issue conformance.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/hancomac/circulusd/internal/conformance/celld/issuance"
	"github.com/hancomac/circulusd/internal/objectstore"
	"golang.org/x/sys/unix"
)

type configuration struct {
	SchemaVersion int    `json:"schemaVersion"`
	Endpoint      string `json:"endpoint"`
	Region        string `json:"region"`
	Bucket        string `json:"bucket"`
	Credentials   struct {
		Source string `json:"source"`
		File   string `json:"file,omitempty"`
	} `json:"credentials"`
	RequestTimeoutMillis int64 `json:"requestTimeoutMillis,omitempty"`
	ProbeTimeoutMillis   int64 `json:"probeTimeoutMillis,omitempty"`
	CleanupTimeoutMillis int64 `json:"cleanupTimeoutMillis,omitempty"`
	MaximumObjectBytes   int64 `json:"maximumObjectBytes,omitempty"`
}

type credentialValues struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken,omitempty"`
}

type nativeClient struct {
	client    *s3.Client
	transport *http.Transport
	bucket    string
	maximum   int64
}

var errObservation = errors.New("native conditional observation failed")

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	flags := flag.NewFlagSet("native-storage-cas-observe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "owned private JSON configuration")
	outputPath := flags.String("output", "", "new private CAS facts JSON")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *configPath == "" || *outputPath == "" {
		fmt.Fprintln(stderr, "usage: native-storage-cas-observe --config /absolute/private.json --output /absolute/private/cas.json")
		return 2
	}
	var config configuration
	if readPrivateJSON(*configPath, &config) != nil {
		fmt.Fprintln(stderr, "UNAVAILABLE: explicit private CAS configuration is invalid")
		return 2
	}
	options, probeTimeout, cleanupTimeout, err := configuredOptions(config, getenv)
	if err != nil {
		fmt.Fprintln(stderr, "UNAVAILABLE: explicit CAS credentials or bounds are invalid")
		return 2
	}
	output, err := reserveOutput(*outputPath)
	if err != nil {
		fmt.Fprintln(stderr, "FAIL: cannot reserve a new private CAS report")
		return 1
	}
	defer output.Close()
	probeContext, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	facts, err := observe(probeContext, options, cleanupTimeout, rand.Reader)
	if err != nil {
		// Provider errors may contain signed requests or arbitrary server text.
		fmt.Fprintln(stderr, "UNAVAILABLE: native conditional responses or safe cleanup could not be verified")
		return 2
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if encoder.Encode(facts) != nil || output.Sync() != nil || output.Close() != nil {
		fmt.Fprintln(stderr, "FAIL: CAS observations could not be retained")
		return 1
	}
	fmt.Fprintln(stdout, "Native CAS observations retained; conformance has not been issued.")
	return 0
}

func configuredOptions(c configuration, getenv func(string) string) (objectstore.S3StoreOptions, time.Duration, time.Duration, error) {
	if c.SchemaVersion != 1 || (c.Credentials.Source != "file" && c.Credentials.Source != "environment") ||
		(c.Credentials.Source == "file" && c.Credentials.File == "") || (c.Credentials.Source == "environment" && c.Credentials.File != "") {
		return objectstore.S3StoreOptions{}, 0, 0, errObservation
	}
	requestMillis, probeMillis, cleanupMillis := c.RequestTimeoutMillis, c.ProbeTimeoutMillis, c.CleanupTimeoutMillis
	if requestMillis == 0 {
		requestMillis = 5000
	}
	if probeMillis == 0 {
		probeMillis = 30000
	}
	if cleanupMillis == 0 {
		cleanupMillis = 5000
	}
	maximum := c.MaximumObjectBytes
	if maximum == 0 {
		maximum = 1 << 20
	}
	if requestMillis < 1 || requestMillis > 30000 || probeMillis < 1 || probeMillis > 120000 || cleanupMillis < 1 || cleanupMillis > 30000 || maximum < 128 || maximum > 1<<20 {
		return objectstore.S3StoreOptions{}, 0, 0, errObservation
	}
	var values credentialValues
	if c.Credentials.Source == "file" {
		if readPrivateJSON(c.Credentials.File, &values) != nil {
			return objectstore.S3StoreOptions{}, 0, 0, errObservation
		}
	} else {
		values = credentialValues{getenv("AWS_ACCESS_KEY_ID"), getenv("AWS_SECRET_ACCESS_KEY"), getenv("AWS_SESSION_TOKEN")}
	}
	options := objectstore.S3StoreOptions{
		Endpoint: c.Endpoint, Region: c.Region, Bucket: c.Bucket,
		AccessKeyID: values.AccessKeyID, SecretAccessKey: values.SecretAccessKey, SessionToken: values.SessionToken,
		RequestTimeout: time.Duration(requestMillis) * time.Millisecond, MaximumObjectBytes: maximum,
	}
	// Reuse the production provider's complete endpoint/credential validation.
	validation, err := objectstore.NewS3Store(options)
	if err != nil {
		return objectstore.S3StoreOptions{}, 0, 0, errObservation
	}
	validation.Close()
	return options, time.Duration(probeMillis) * time.Millisecond, time.Duration(cleanupMillis) * time.Millisecond, nil
}

func openNative(options objectstore.S3StoreOptions) *nativeClient {
	endpoint, _ := url.Parse(options.Endpoint) // configuredOptions validated it.
	dialer := &net.Dialer{Timeout: options.RequestTimeout, KeepAlive: 30 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if endpoint.Scheme == "http" && endpoint.Hostname() == "localhost" {
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, errObservation
			}
			address = net.JoinHostPort("127.0.0.1", port)
		}
		return dialer.DialContext(ctx, network, address)
	}
	transport.ResponseHeaderTimeout = options.RequestTimeout
	transport.TLSHandshakeTimeout = options.RequestTimeout
	transport.MaxResponseHeaderBytes = 64 << 10
	transport.MaxConnsPerHost = 64
	transport.MaxIdleConnsPerHost = 32
	httpClient := &http.Client{Transport: boundedTransport{transport, endpoint.Scheme, endpoint.Host, options.MaximumObjectBytes}, Timeout: options.RequestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	client := s3.New(s3.Options{
		Region: options.Region, BaseEndpoint: aws.String(strings.TrimSuffix(options.Endpoint, "/")), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider(options.AccessKeyID, options.SecretAccessKey, options.SessionToken),
		HTTPClient:  httpClient, Retryer: aws.NopRetryer{}, DisableMultiRegionAccessPoints: true,
		DisableS3ExpressSessionAuth: aws.Bool(true), RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
	return &nativeClient{client: client, transport: transport, bucket: options.Bucket, maximum: options.MaximumObjectBytes}
}

type boundedTransport struct {
	base         *http.Transport
	scheme, host string
	maximum      int64
}

func (transport boundedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != transport.scheme || request.URL.Host != transport.host || request.URL.User != nil {
		return nil, errObservation
	}
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > transport.maximum {
		response.Body.Close()
		return nil, errObservation
	}
	response.Body = struct {
		io.Reader
		io.Closer
	}{io.LimitReader(response.Body, transport.maximum+1), response.Body}
	return response, nil
}

func (client *nativeClient) put(ctx context.Context, key, expected string, data []byte) (string, error) {
	input := &s3.PutObjectInput{Bucket: aws.String(client.bucket), Key: aws.String(key), Body: bytes.NewReader(data)}
	if expected == "" {
		input.IfNoneMatch = aws.String("*")
	} else {
		input.IfMatch = aws.String(expected)
	}
	output, err := client.client.PutObject(ctx, input)
	if err != nil {
		return "", err
	}
	etag := aws.ToString(output.ETag)
	if !validETag(etag) {
		return "", errObservation
	}
	return etag, nil
}

func (client *nativeClient) get(ctx context.Context, key string) (string, []byte, error) {
	output, err := client.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(client.bucket), Key: aws.String(key)})
	if err != nil {
		return "", nil, err
	}
	defer output.Body.Close()
	if output.ContentLength != nil && *output.ContentLength > client.maximum {
		return "", nil, errObservation
	}
	data, err := io.ReadAll(io.LimitReader(output.Body, client.maximum+1))
	etag := aws.ToString(output.ETag)
	if err != nil || int64(len(data)) > client.maximum || !validETag(etag) {
		return "", nil, errObservation
	}
	return etag, data, nil
}

func (client *nativeClient) delete(ctx context.Context, key, expected string) error {
	_, err := client.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(client.bucket), Key: aws.String(key), IfMatch: aws.String(expected)})
	return err
}

func nativeStatus(err error) uint32 {
	var response *smithyhttp.ResponseError
	if errors.As(err, &response) {
		return uint32(response.HTTPStatusCode())
	}
	return 0
}

func validETag(value string) bool {
	if len(value) < 3 || len(value) > 1024 || value[0] != '"' || value[len(value)-1] != '"' || strings.ContainsAny(value[1:len(value)-1], "\"*") {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

func dataDigest(data []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data))
}

func observe(ctx context.Context, options objectstore.S3StoreOptions, cleanupTimeout time.Duration, random io.Reader) (facts issuance.CASFacts, resultErr error) {
	var nonce [16]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return facts, errObservation
	}
	key := ".doctor/raw-cas-" + hex.EncodeToString(nonce[:])
	initial := []byte(fmt.Sprintf("circulusd-raw-cas-initial:%x", nonce))
	updated := []byte(fmt.Sprintf("circulusd-raw-cas-updated:%x", nonce))
	// A store that ignores a precondition keeps the rejected write, so those
	// payloads must also be recognizable for cleanup.
	stale := []byte(fmt.Sprintf("circulusd-raw-cas-stale:%x", nonce))
	duplicate := []byte(fmt.Sprintf("circulusd-raw-cas-duplicate:%x", nonce))
	owned := map[string]bool{string(initial): true, string(updated): true, string(stale): true, string(duplicate): true}
	for contender := range 32 {
		owned[fmt.Sprintf("circulusd-raw-cas-winner-%02d:%x", contender, nonce)] = true
	}
	client := openNative(options)
	clients := []*nativeClient{client}
	created := false
	defer func() {
		defer func() {
			for _, opened := range clients {
				opened.transport.CloseIdleConnections()
			}
		}()
		if !created {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cancel()
		etag, data, err := client.get(cleanup, key)
		if nativeStatus(err) == 404 {
			return
		}
		if err != nil || !owned[string(data)] {
			resultErr = errObservation
			return
		}
		if client.delete(cleanup, key, etag) != nil {
			resultErr = errObservation
			return
		}
		if _, _, err := client.get(cleanup, key); nativeStatus(err) != 404 {
			resultErr = errObservation
		}
	}()
	// A failed transport may still have created our object. Probe for it during
	// cleanup, except when a native precondition proves another object exists.
	created = true
	initialETag, err := client.put(ctx, key, "", initial)
	if err != nil {
		if nativeStatus(err) == 412 {
			created = false
		}
		return facts, errObservation
	}
	facts.InitialETag = initialETag
	readETag, readData, err := client.get(ctx, key)
	if err != nil || readETag != initialETag || !bytes.Equal(readData, initial) {
		return facts, errObservation
	}
	updatedETag, err := client.put(ctx, key, initialETag, updated)
	if err != nil || updatedETag == initialETag {
		return facts, errObservation
	}
	_, err = client.put(ctx, key, initialETag, stale)
	facts.StaleUpdateStatus = nativeStatus(err)
	_, err = client.put(ctx, key, "", duplicate)
	facts.DuplicateCreateStatus = nativeStatus(err)
	facts.StaleDeleteStatus = nativeStatus(client.delete(ctx, key, initialETag))
	if facts.StaleUpdateStatus != 412 || facts.DuplicateCreateStatus != 412 || facts.StaleDeleteStatus != 412 {
		return facts, errObservation
	}
	readETag, readData, err = client.get(ctx, key)
	if err != nil || readETag != updatedETag || !bytes.Equal(readData, updated) {
		return facts, errObservation
	}
	type attempt struct {
		etag string
		data []byte
		err  error
	}
	start := make(chan struct{})
	attempts := make(chan attempt, 32)
	var wait sync.WaitGroup
	for contender := range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			data := []byte(fmt.Sprintf("circulusd-raw-cas-winner-%02d:%x", contender, nonce))
			etag, err := client.put(ctx, key, updatedETag, data)
			attempts <- attempt{etag, data, err}
		}()
	}
	close(start)
	wait.Wait()
	close(attempts)
	var winner attempt
	for attempt := range attempts {
		facts.Contenders++
		switch {
		case attempt.err == nil && attempt.etag != updatedETag:
			facts.Winners++
			winner = attempt
		case nativeStatus(attempt.err) == 412:
			facts.PreconditionFailures++
		default:
			resultErr = errObservation
		}
	}
	if resultErr != nil || facts.Winners != 1 || facts.PreconditionFailures != 31 {
		return facts, errObservation
	}
	facts.CurrentETag = winner.etag
	facts.ExpectedDataDigest = dataDigest(winner.data)
	readETag, readData, err = client.get(ctx, key)
	if err != nil || readETag != winner.etag || !bytes.Equal(readData, winner.data) {
		return facts, errObservation
	}
	facts.ObservedDataDigest = dataDigest(readData)
	// A new transport/client rules out an SDK-local value serving the read.
	client = openNative(options)
	clients = append(clients, client)
	readETag, readData, err = client.get(ctx, key)
	if err != nil || readETag != winner.etag || !bytes.Equal(readData, winner.data) {
		return facts, errObservation
	}
	facts.FreshClientDataDigest = dataDigest(readData)
	return facts, nil
}

func readPrivateJSON(path string, value any) error {
	if !filepath.IsAbs(path) {
		return errObservation
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return errObservation
	}
	file := os.NewFile(uintptr(descriptor), "native-cas-input")
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(descriptor, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 || stat.Nlink != 1 || stat.Size < 1 || stat.Size > 65536 {
		return errObservation
	}
	encoded, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(encoded) > 65536 || issuance.DecodeStrict(encoded, value) != nil {
		return errObservation
	}
	return nil
}

func reserveOutput(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errObservation
	}
	parent, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errObservation
	}
	defer unix.Close(parent)
	var stat unix.Stat_t
	if unix.Fstat(parent, &stat) != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 {
		return nil, errObservation
	}
	descriptor, err := unix.Openat(parent, filepath.Base(path), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errObservation
	}
	return os.NewFile(uintptr(descriptor), "native-cas-output"), nil
}
