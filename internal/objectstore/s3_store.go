package objectstore

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"golang.org/x/text/unicode/norm"
)

var (
	ErrUnavailable          = errors.New("objectstore: configured endpoint unavailable")
	ErrInvalidConfiguration = errors.New("objectstore: invalid S3 configuration")
	ErrClosed               = errors.New("objectstore: client closed")
	errResponseTooLarge     = errors.New("objectstore: response exceeds limit")
	s3BucketPattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	s3RegionPattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// S3StoreOptions targets a single existing, general-purpose bucket. Credentials
// are explicit; SDK default configuration, metadata credentials, region
// discovery, redirects, environment proxies and retry are never enabled.
type S3StoreOptions struct {
	Endpoint           string
	Region             string
	Bucket             string
	AccessKeyID        string
	SecretAccessKey    string
	SessionToken       string
	RequestTimeout     time.Duration
	MaximumObjectBytes int64
}

type S3Store struct {
	client             *s3.Client
	bucket             string
	maximumObjectBytes int64
	transport          *http.Transport
	closed             atomic.Bool
}

func NewS3Store(options S3StoreOptions) (*S3Store, error) {
	endpoint, err := url.Parse(options.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.RawFragment != "" || (endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawPath != "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
		return nil, ErrInvalidConfiguration
	}
	hostname := endpoint.Hostname()
	if hostname == "" || strings.ContainsAny(hostname, "\\% \r\n\t") {
		return nil, ErrInvalidConfiguration
	}
	if endpoint.Scheme == "http" {
		ip := net.ParseIP(hostname)
		if hostname != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, ErrInvalidConfiguration
		}
	}
	if !s3BucketPattern.MatchString(options.Bucket) || strings.Contains(options.Bucket, "..") || net.ParseIP(options.Bucket) != nil || strings.HasSuffix(options.Bucket, "--x-s3") || !s3RegionPattern.MatchString(options.Region) || !credentialValue(options.AccessKeyID, 256) || !credentialValue(options.SecretAccessKey, 4096) || (options.SessionToken != "" && !credentialValue(options.SessionToken, 16384)) {
		return nil, ErrInvalidConfiguration
	}
	timeout := options.RequestTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if timeout < 0 || timeout > 30*time.Second {
		return nil, ErrInvalidConfiguration
	}
	maximum := options.MaximumObjectBytes
	if maximum == 0 {
		maximum = defaultMaximumObjectBytes
	}
	if maximum < 0 || maximum > defaultMaximumObjectBytes {
		return nil, ErrInvalidConfiguration
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.ResponseHeaderTimeout = timeout
	transport.TLSHandshakeTimeout = timeout
	transport.MaxResponseHeaderBytes = 64 << 10
	transport.MaxConnsPerHost = 64
	transport.MaxIdleConnsPerHost = 32
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if endpoint.Scheme == "http" && hostname == "localhost" {
			_, port, e := net.SplitHostPort(address)
			if e != nil {
				return nil, ErrUnavailable
			}
			address = net.JoinHostPort("127.0.0.1", port)
		}
		return dialer.DialContext(ctx, network, address)
	}
	httpClient := &http.Client{Transport: &s3BoundedTransport{base: transport, scheme: endpoint.Scheme, host: endpoint.Host, maximum: maximum}, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	client := s3.New(s3.Options{
		Region: options.Region, BaseEndpoint: aws.String(strings.TrimSuffix(options.Endpoint, "/")), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider(options.AccessKeyID, options.SecretAccessKey, options.SessionToken),
		HTTPClient:  httpClient, Retryer: aws.NopRetryer{}, DisableMultiRegionAccessPoints: true,
		DisableS3ExpressSessionAuth: aws.Bool(true),
		RequestChecksumCalculation:  aws.RequestChecksumCalculationWhenRequired, ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
	return &S3Store{client: client, bucket: options.Bucket, maximumObjectBytes: maximum, transport: transport}, nil
}

func credentialValue(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, c := range value {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func validS3ETag(etag ETag) bool {
	if !validOpaqueETag(etag) || len(etag) < 3 || etag[0] != '"' || etag[len(etag)-1] != '"' {
		return false
	}
	return !strings.ContainsAny(string(etag[1:len(etag)-1]), "\"*")
}

func (store *S3Store) validate(ctx context.Context, bucket Bucket, key string) error {
	if store.closed.Load() {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if bucket != BucketCelldState {
		return ErrInvalidBucket
	}
	if key == "" || !utf8.ValidString(key) || norm.NFC.String(key) != key || len(key) > maximumKeyBytes || strings.ContainsRune(key, '\\') || path.IsAbs(key) || path.Clean(key) != key {
		return ErrInvalidKey
	}
	for _, segment := range strings.Split(key, "/") {
		if len(segment) == 0 || len(segment) > 255 || segment == "." || segment == ".." {
			return ErrInvalidKey
		}
		for _, c := range segment {
			if c < 0x20 || c == 0x7f {
				return ErrInvalidKey
			}
		}
	}
	return nil
}

func (store *S3Store) Get(ctx context.Context, bucket Bucket, key string) (Object, error) {
	if err := store.validate(ctx, bucket, key); err != nil {
		return Object{}, err
	}
	output, err := store.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(key)})
	if err != nil {
		return Object{}, s3Error(ctx, err, "get")
	}
	defer output.Body.Close()
	if output.ContentLength != nil && *output.ContentLength > store.maximumObjectBytes {
		return Object{}, ErrObjectTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(output.Body, store.maximumObjectBytes+1))
	if int64(len(data)) > store.maximumObjectBytes || errors.Is(err, errResponseTooLarge) {
		return Object{}, ErrObjectTooLarge
	}
	if err != nil {
		return Object{}, s3Error(ctx, err, "get")
	}
	etag := ETag(aws.ToString(output.ETag))
	if !validS3ETag(etag) {
		return Object{}, ErrInvalidETag
	}
	return Object{Data: data, ETag: etag}, nil
}

func (store *S3Store) PutIfAbsent(ctx context.Context, bucket Bucket, key string, data []byte) (ETag, error) {
	return store.put(ctx, bucket, key, "", data)
}
func (store *S3Store) CompareAndSwap(ctx context.Context, bucket Bucket, key string, expected ETag, data []byte) (ETag, error) {
	if !validS3ETag(expected) {
		return "", ErrInvalidETag
	}
	return store.put(ctx, bucket, key, expected, data)
}
func (store *S3Store) put(ctx context.Context, bucket Bucket, key string, expected ETag, data []byte) (ETag, error) {
	if err := store.validate(ctx, bucket, key); err != nil {
		return "", err
	}
	if int64(len(data)) > store.maximumObjectBytes {
		return "", ErrObjectTooLarge
	}
	input := &s3.PutObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(key), Body: bytes.NewReader(data)}
	if expected == "" {
		input.IfNoneMatch = aws.String("*")
	} else {
		input.IfMatch = aws.String(string(expected))
	}
	output, err := store.client.PutObject(ctx, input)
	if err != nil {
		return "", s3Error(ctx, err, "put")
	}
	etag := ETag(aws.ToString(output.ETag))
	if !validS3ETag(etag) {
		return "", ErrInvalidETag
	}
	return etag, nil
}

func (store *S3Store) DeleteIfMatch(ctx context.Context, bucket Bucket, key string, expected ETag) error {
	if !validS3ETag(expected) {
		return ErrInvalidETag
	}
	if err := store.validate(ctx, bucket, key); err != nil {
		return err
	}
	_, err := store.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(key), IfMatch: aws.String(string(expected))})
	if err != nil {
		return s3Error(ctx, err, "delete")
	}
	return nil
}

func (store *S3Store) Close() error {
	if !store.closed.Swap(true) {
		store.transport.CloseIdleConnections()
	}
	return nil
}

// AWS errors can contain the endpoint, signed headers and untrusted provider
// messages. Return fixed public errors without wrapping those strings.
func s3Error(ctx context.Context, err error, operation string) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	var response *smithyhttp.ResponseError
	if errors.As(err, &response) {
		switch response.HTTPStatusCode() {
		case 412, 409:
			return ErrPreconditionFailed
		case 404:
			if operation == "get" || operation == "delete" {
				return ErrNotFound
			}
		}
	}
	return ErrUnavailable
}

type s3BoundedTransport struct {
	base         *http.Transport
	scheme, host string
	maximum      int64
}

func (transport *s3BoundedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != transport.scheme || request.URL.Host != transport.host || request.URL.User != nil {
		return nil, ErrInvalidConfiguration
	}
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	limit := transport.maximum + 1
	if request.Method != http.MethodGet || response.StatusCode >= 300 {
		limit = 64 << 10
	}
	response.Body = &s3BoundedBody{ReadCloser: response.Body, remaining: limit}
	return response, nil
}

type s3BoundedBody struct {
	io.ReadCloser
	remaining int64
}

func (body *s3BoundedBody) Read(p []byte) (int, error) {
	if body.remaining == 0 {
		var probe [1]byte
		n, err := body.ReadCloser.Read(probe[:])
		if n > 0 {
			return 0, errResponseTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > body.remaining {
		p = p[:body.remaining]
	}
	n, err := body.ReadCloser.Read(p)
	body.remaining -= int64(n)
	return n, err
}
