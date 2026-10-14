// native-owner-observe controls an explicitly selected local S3 relay and
// records one authenticated pending write. It does not issue qualification
// evidence or start, signal, or stop any native owner process.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hancomac/circulusd/internal/celldbridge"
	"github.com/hancomac/circulusd/internal/conformance/celld/issuance"
	"golang.org/x/sys/unix"
)

type config struct {
	SchemaVersion        int    `json:"schemaVersion"`
	ListenAddress        string `json:"listenAddress"`
	UpstreamEndpoint     string `json:"upstreamEndpoint"`
	Bucket               string `json:"bucket"`
	KeyPrefix            string `json:"keyPrefix"`
	ControlSocket        string `json:"controlSocket"`
	RequestTimeoutMillis int64  `json:"requestTimeoutMillis"`
	HoldTimeoutMillis    int64  `json:"holdTimeoutMillis"`
	Endpoint             string `json:"endpoint"`
	KeyID                string `json:"keyId"`
	RootKeyHex           string `json:"rootKeyHex"`
	ObjectID             string `json:"objectId"`
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("native-owner-observe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "", "relay, control or commit")
	configPath := flags.String("config", "", "private configuration")
	operation := flags.String("operation", "", "arm, status or release")
	cell := flags.String("cell-id", "", "exact native cell ID")
	epoch := flags.Uint64("prior-epoch", 0, "exact prior native cell epoch")
	output := flags.String("output", "", "new private report")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *configPath == "" {
		fmt.Fprintln(stderr, "native owner observation: invalid arguments")
		return 1
	}
	var cfg config
	if readPrivate(*configPath, &cfg) != nil || cfg.SchemaVersion != 1 || cfg.RequestTimeoutMillis <= 0 || cfg.RequestTimeoutMillis > 30000 {
		fmt.Fprintln(stderr, "native owner observation: invalid private configuration")
		return 1
	}
	switch *mode {
	case "relay":
		if *operation != "" || *cell != "" || *epoch != 0 || *output != "" || !validRelayConfig(cfg) {
			break
		}
		r, err := newRelay(cfg)
		if err != nil {
			break
		}
		defer r.Close()
		fmt.Fprintln(stdout, "native owner relay: listening; no qualification verdict")
		select {
		case <-ctx.Done():
			return 0
		case <-r.failed:
			return 1
		}
	case "control":
		if *output != "" || !validRelayConfig(cfg) || (*operation != "arm" && *operation != "status" && *operation != "release") ||
			(*operation == "arm" && (!identifier.MatchString(*cell) || *epoch == 0)) || (*operation != "arm" && (*cell != "" || *epoch != 0)) {
			break
		}
		result, err := control(ctx, cfg.ControlSocket, controlRequest{Operation: *operation, CellID: *cell, PriorEpoch: *epoch})
		if err != nil {
			break
		}
		if json.NewEncoder(stdout).Encode(result) != nil || result.Error != "" {
			return 1
		}
		return 0
	case "commit":
		if *operation != "" || *cell != "" || *epoch != 0 || *output == "" || !identifier.MatchString(cfg.ObjectID) || !hexKey.MatchString(cfg.RootKeyHex) {
			break
		}
		file, err := createPrivate(*output)
		if err != nil {
			break
		}
		defer file.Close()
		facts, err := commit(ctx, cfg)
		if json.NewEncoder(file).Encode(facts) != nil || file.Sync() != nil {
			return 1
		}
		fmt.Fprintln(stdout, "native owner write: facts recorded; no qualification verdict")
		if err != nil {
			return 2
		}
		return 0
	}
	fmt.Fprintln(stderr, "native owner observation: invalid configuration or unavailable operation")
	return 1
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var hexKey = regexp.MustCompile(`^[0-9a-f]{64}$`)
var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func loopbackEndpoint(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != endpoint {
		return nil, errors.New("invalid origin")
	}
	ip := net.ParseIP(u.Hostname())
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 || ip == nil || !ip.IsLoopback() || u.Host != net.JoinHostPort(ip.String(), strconv.FormatUint(port, 10)) {
		return nil, errors.New("invalid origin")
	}
	return u, nil
}

func validRelayConfig(c config) bool {
	listen, err := loopbackEndpoint("http://" + c.ListenAddress)
	upstream, upErr := loopbackEndpoint(c.UpstreamEndpoint)
	return err == nil && upErr == nil && listen.Host != upstream.Host && bucketName.MatchString(c.Bucket) &&
		(c.KeyPrefix == "" || (strings.HasSuffix(c.KeyPrefix, "/") && !strings.Contains(c.KeyPrefix, "//") && !strings.Contains(c.KeyPrefix, "..") && regexp.MustCompile(`^[A-Za-z0-9._:/-]+/$`).MatchString(c.KeyPrefix))) &&
		filepath.IsAbs(c.ControlSocket) && len(c.ControlSocket) < 100 && c.HoldTimeoutMillis > 0 && c.HoldTimeoutMillis <= 120000
}

func readPrivate(path string, out any) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "private-native-owner-input")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 || st.Nlink != 1 || st.Size > 65536 {
		return errors.New("invalid private file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(data) > 65536 {
		return errors.New("invalid bounded input")
	}
	return issuance.DecodeStrict(data, out)
}

func privateParent(path string) (int, error) {
	if !filepath.IsAbs(path) {
		return -1, errors.New("absolute private path required")
	}
	fd, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		unix.Close(fd)
		return -1, errors.New("parent not private")
	}
	return fd, nil
}
func createPrivate(path string) (*os.File, error) {
	parent, err := privateParent(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, filepath.Base(path), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "private-native-owner-report"), nil
}

type commitFacts struct {
	SchemaVersion     int    `json:"schemaVersion"`
	Kind              string `json:"kind"`
	ObjectID          string `json:"objectId"`
	RequestDigest     string `json:"requestDigest"`
	StartedSequence   uint64 `json:"startedSequence"`
	ResponseSequence  uint64 `json:"responseSequence"`
	HTTPStatus        int    `json:"httpStatus"`
	ResponseBody      string `json:"responseBody"`
	ClientErrorCode   string `json:"clientErrorCode"`
	RequestCount      int    `json:"requestCount"`
	Acknowledged      bool   `json:"acknowledged"`
	BeforeRevision    uint64 `json:"beforeRevision"`
	BeforeStateDigest string `json:"beforeStateDigest"`
}

func commit(ctx context.Context, cfg config) (commitFacts, error) {
	facts := commitFacts{SchemaVersion: 1, Kind: "circulusd.native-owner-write-observation/v1", ObjectID: cfg.ObjectID, ClientErrorCode: "NONE"}
	key, err := hex.DecodeString(cfg.RootKeyHex)
	if err != nil {
		return facts, err
	}
	defer clear(key)
	clientConfig := celldbridge.ClientConfig{Endpoint: cfg.Endpoint, KeyID: cfg.KeyID, RootKey: key, Timeout: time.Duration(cfg.RequestTimeoutMillis) * time.Millisecond}
	client, err := celldbridge.NewClient(clientConfig)
	if err != nil {
		return facts, err
	}
	defer client.Close()
	before, err := client.ReadSnapshot(ctx, celldbridge.SnapshotRequest{ObjectID: cfg.ObjectID})
	if err != nil {
		return facts, err
	}
	facts.BeforeRevision, facts.BeforeStateDigest = before.Revision, "sha256:"+hex.EncodeToString(before.StateDigest[:])
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return facts, err
	}
	request := celldbridge.CommitRequest{Snapshot: before.SnapshotRef, StateWritten: true, State: append([]byte("native-prior-owner-pending\x00"), nonce...)}
	request.RequestDigest, err = celldbridge.CommitDigest(request)
	if err != nil {
		return facts, err
	}
	facts.RequestDigest = "sha256:" + hex.EncodeToString(request.RequestDigest[:])
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return facts, err
	}
	u, err := loopbackEndpoint(cfg.Endpoint)
	if err != nil {
		listener.Close()
		return facts, err
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, ResponseHeaderTimeout: clientConfig.Timeout, MaxResponseHeaderBytes: 16 << 10}
	defer transport.CloseIdleConnections()
	var captureErr error
	var captureMu sync.Mutex
	var completedOnce sync.Once
	completed := make(chan struct{})
	server := &http.Server{ReadHeaderTimeout: clientConfig.Timeout, ReadTimeout: clientConfig.Timeout, WriteTimeout: clientConfig.Timeout, MaxHeaderBytes: 16 << 10, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captureMu.Lock()
		defer captureMu.Unlock()
		defer completedOnce.Do(func() { close(completed) })
		facts.RequestCount++
		facts.StartedSequence = uint64(time.Now().UnixNano())
		if facts.RequestCount != 1 || r.Method != http.MethodPost || r.URL.Path != "/circulusd/native-storage/v1/transaction" || r.URL.RawQuery != "" {
			http.Error(w, "invalid pending write", 400)
			return
		}
		body, readErr := io.ReadAll(io.LimitReader(r.Body, celldbridge.MaximumTransactionBytes+1))
		if readErr != nil || len(body) > celldbridge.MaximumTransactionBytes {
			captureErr = errors.New("request bound")
			http.Error(w, "request bound", 400)
			return
		}
		forward := r.Clone(r.Context())
		forward.URL.Scheme = u.Scheme
		forward.URL.Host = u.Host
		forward.RequestURI = ""
		forward.Host = u.Host
		forward.Body = io.NopCloser(bytes.NewReader(body))
		forward.GetBody = nil
		resp, roundErr := transport.RoundTrip(forward)
		facts.ResponseSequence = uint64(time.Now().UnixNano())
		if roundErr != nil {
			captureErr = roundErr
			conn, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				conn.Close()
			}
			return
		}
		defer resp.Body.Close()
		payload, readErr := io.ReadAll(io.LimitReader(resp.Body, celldbridge.MaximumTransactionBytes+1))
		if readErr != nil || len(payload) > celldbridge.MaximumTransactionBytes {
			captureErr = errors.New("response bound")
			http.Error(w, "response bound", 502)
			return
		}
		facts.HTTPStatus = resp.StatusCode
		if len(payload) <= 4096 {
			facts.ResponseBody = base64.StdEncoding.EncodeToString(payload)
		} else {
			captureErr = errors.New("response transcript bound")
		}
		for k, v := range resp.Header {
			w.Header()[k] = append([]string(nil), v...)
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(payload)
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	clientConfig.Endpoint = "http://" + listener.Addr().String()
	through, err := celldbridge.NewClient(clientConfig)
	if err != nil {
		return facts, err
	}
	defer through.Close()
	_, operationErr := through.CompareAndCommit(ctx, request)
	transcribed := awaitTranscript(completed, clientConfig.Timeout+time.Second)
	// A handler holds captureMu until it returns, and closing the relay aborts
	// its pending I/O, so facts is read only after every handler write.
	_ = server.Close()
	captureMu.Lock()
	defer captureMu.Unlock()
	if !transcribed {
		return facts, errors.New("pending transcript unavailable")
	}
	facts.Acknowledged = operationErr == nil
	if facts.HTTPStatus == 500 || facts.HTTPStatus == 503 {
		facts.ClientErrorCode = "HTTP_FAILURE"
	} else if errors.Is(operationErr, celldbridge.ErrUnavailable) {
		facts.ClientErrorCode = "UNAVAILABLE"
	} else if errors.Is(operationErr, celldbridge.ErrInvalidResponse) {
		facts.ClientErrorCode = "INVALID_RESPONSE"
	} else if operationErr != nil {
		facts.ClientErrorCode = "ERROR"
	}
	if captureErr != nil && facts.HTTPStatus != 0 {
		return facts, captureErr
	}
	if facts.RequestCount != 1 || facts.Acknowledged {
		return facts, errors.New("prior native write was not rejected")
	}
	return facts, nil
}

// awaitTranscript reports whether the relayed write finished within wait.
// Tests replace it to take the timeout path deterministically.
var awaitTranscript = func(completed <-chan struct{}, wait time.Duration) bool {
	select {
	case <-completed:
		return true
	case <-time.After(wait):
		return false
	}
}

func digest(body []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(body)) }
