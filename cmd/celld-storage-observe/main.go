// celld-storage-observe records bounded authenticated HTTP facts from one
// explicitly configured local celld. It never issues durability evidence,
// starts/stops a process, provisions a bucket, or dispatches an external effect.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hancomac/circulusd/internal/celldbridge"
	celldconformance "github.com/hancomac/circulusd/internal/conformance/celld"
	"golang.org/x/sys/unix"
)

type observationConfig struct {
	SchemaVersion        int                                 `json:"schemaVersion"`
	Endpoint             string                              `json:"endpoint"`
	KeyID                string                              `json:"keyId"`
	RootKeyHex           string                              `json:"rootKeyHex"`
	RunID                string                              `json:"runId"`
	RequestTimeoutMillis int64                               `json:"requestTimeoutMillis"`
	TimeoutMillis        int64                               `json:"timeoutMillis"`
	ClaimedBinding       celldconformance.ObservationBinding `json:"claimedBinding"`
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("celld-storage-observe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "owned 0600 JSON configuration")
	phase := flags.String("phase", "", "seed, verify, stale-cas or response-loss")
	seedPath := flags.String("seed", "", "prior seed phase report")
	outputPath := flags.String("output", "", "new private raw report")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *configPath == "" || *outputPath == "" ||
		(*phase != "seed" && *phase != "verify" && *phase != "stale-cas" && *phase != "response-loss") ||
		(*phase == "seed" && *seedPath != "") || (*phase != "seed" && *seedPath == "") {
		fmt.Fprintln(stderr, "storage observation: --config, --phase and --output required; non-seed phases also require --seed")
		return 1
	}
	var config observationConfig
	if readPrivateJSON(*configPath, &config) != nil || !validConfig(config) {
		fmt.Fprintln(stderr, "storage observation: invalid private configuration")
		return 1
	}
	rootKey, _ := hex.DecodeString(config.RootKeyHex)
	defer clear(rootKey)
	clientConfig := celldbridge.ClientConfig{Endpoint: config.Endpoint, KeyID: config.KeyID, RootKey: rootKey, Timeout: time.Duration(config.RequestTimeoutMillis) * time.Millisecond}
	client, err := celldbridge.NewClient(clientConfig)
	if err != nil {
		fmt.Fprintln(stderr, "storage observation: invalid loopback endpoint or authentication configuration")
		return 1
	}
	defer client.Close()
	var seed celldconformance.ObservationReport
	if *phase != "seed" && readPrivateJSON(*seedPath, &seed) != nil {
		fmt.Fprintln(stderr, "storage observation: invalid private seed report")
		return 1
	}
	output, err := openPrivateReport(*outputPath)
	if err != nil {
		fmt.Fprintln(stderr, "storage observation: cannot reserve new private report")
		return 1
	}
	defer output.Close()
	report := celldconformance.NewObservation(*phase, config.RunID, config.Endpoint, config.ClaimedBinding)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(config.TimeoutMillis)*time.Millisecond)
	defer cancel()
	switch *phase {
	case "seed":
		err = celldconformance.SeedObservation(ctx, client, &report)
	case "verify":
		err = celldconformance.VerifyObservation(ctx, client, &report, seed)
	case "stale-cas":
		err = celldconformance.StaleCASObservation(ctx, client, &report, seed)
	case "response-loss":
		var relay *responseDropRelay
		relay, err = newResponseDropRelay(config.Endpoint, clientConfig.Timeout)
		if err == nil {
			defer relay.Close()
			lostConfig := clientConfig
			lostConfig.Endpoint = relay.endpoint()
			var lostClient *celldbridge.Client
			lostClient, err = celldbridge.NewClient(lostConfig)
			if err == nil {
				defer lostClient.Close()
				err = celldconformance.ResponseLossObservation(ctx, client, lostClient, relay.facts, &report, seed)
			}
		}
	}
	if err != nil && len(report.Errors) == 0 {
		report.Errors = append(report.Errors, "observer:ERROR")
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if encoder.Encode(report) != nil || output.Sync() != nil || output.Close() != nil {
		fmt.Fprintln(stderr, "storage observation: report persistence failed")
		return 1
	}
	if len(report.Errors) != 0 {
		fmt.Fprintf(stdout, "storage observation: %s recorded operation errors; no durability verdict\n", *phase)
		for _, code := range report.Errors {
			if strings.HasSuffix(code, ":UNAVAILABLE") || strings.HasSuffix(code, ":TIMEOUT") {
				return 2
			}
		}
		return 1
	}
	fmt.Fprintf(stdout, "storage observation: %s facts recorded; no durability verdict\n", *phase)
	return 0
}

var hexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var domainPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func validConfig(c observationConfig) bool {
	b := c.ClaimedBinding
	return c.SchemaVersion == 1 && hexPattern.MatchString(c.RootKeyHex) && hexPattern.MatchString(c.RunID) &&
		c.RequestTimeoutMillis > 0 && c.RequestTimeoutMillis <= 30000 && c.TimeoutMillis > 0 && c.TimeoutMillis <= 120000 &&
		digestPattern.MatchString(b.ReleaseDigest) && digestPattern.MatchString(b.ExecutableDigest) && digestPattern.MatchString(b.ApplicationDigest) && digestPattern.MatchString(b.EffectiveConfigDigest) &&
		domainPattern.MatchString(b.DurabilityDomain) && b.DurabilityEpoch > 0 && b.DurabilityEpoch <= celldbridge.MaximumRevision
}

// responseDropRelay forwards one complete signed native transaction, consumes
// its bounded response, and closes the caller connection without a response.
// The direct client then verifies the actual persisted state/receipt and barrier.
type responseDropRelay struct {
	listener    net.Listener
	server      *http.Server
	transport   *http.Transport
	endpointURL string
	mu          sync.Mutex
	observed    celldconformance.ResponseLossFact
	finished    chan struct{}
	connections atomic.Uint64
	writeMu     sync.Mutex
	written     atomic.Uint64
}

func newResponseDropRelay(endpoint string, timeout time.Duration) (*responseDropRelay, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("cannot listen on response-loss relay")
	}
	r := &responseDropRelay{listener: listener, endpointURL: "http://" + listener.Addr().String(), finished: make(chan struct{})}
	r.transport = &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 16 << 10,
		DialContext: func(ctx context.Context, network, requested string) (net.Conn, error) {
			if network != "tcp" || requested != strings.TrimPrefix(endpoint, "http://") {
				return nil, errors.New("unexpected relay origin")
			}
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", requested)
		}}
	r.server = &http.Server{ReadHeaderTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout, MaxHeaderBytes: 16 << 10, Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/circulusd/native-storage/v1/transaction" || request.URL.RawQuery != "" {
			http.Error(w, "invalid relay request", http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		r.observed.RequestCount++
		count := r.observed.RequestCount
		r.mu.Unlock()
		if count != 1 {
			http.Error(w, "only one transaction permitted", http.StatusConflict)
			return
		}
		body, readErr := io.ReadAll(io.LimitReader(request.Body, celldbridge.MaximumTransactionBytes+1))
		if readErr != nil || len(body) > celldbridge.MaximumTransactionBytes {
			http.Error(w, "invalid transaction size", http.StatusBadRequest)
			return
		}
		forward, forwardErr := http.NewRequestWithContext(request.Context(), http.MethodPost, endpoint+request.URL.Path, bytes.NewReader(body))
		if forwardErr != nil {
			http.Error(w, "cannot forward request", http.StatusBadGateway)
			return
		}
		forward.Header = request.Header.Clone()
		forward.Header.Del("Connection")
		forward.Header.Del("Proxy-Connection")
		response, forwardErr := r.transport.RoundTrip(forward)
		if forwardErr != nil {
			http.Error(w, "native response unavailable", http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, celldbridge.MaximumTransactionBytes+1))
		if readErr != nil || len(payload) > celldbridge.MaximumTransactionBytes {
			http.Error(w, "invalid native response", http.StatusBadGateway)
			return
		}
		r.mu.Lock()
		r.observed.BackendStatus = response.StatusCode
		r.mu.Unlock()
		connection, _, hijackErr := w.(http.Hijacker).Hijack()
		if hijackErr == nil {
			connection.Close()
		}
	})}
	go func() { defer close(r.finished); _ = r.server.Serve(responseObservationListener{listener, r}) }()
	return r, nil
}
func (r *responseDropRelay) endpoint() string { return r.endpointURL }
func (r *responseDropRelay) facts() celldconformance.ResponseLossFact {
	r.mu.Lock()
	defer r.mu.Unlock()
	facts := r.observed
	if r.connections.Load() != 0 {
		// The peer can read bytes before the writer goroutine returns from its
		// syscall. Wait for any in-flight write to publish its actual count.
		r.writeMu.Lock()
		bytes := r.written.Load()
		r.writeMu.Unlock()
		facts.ReceivedBytes = &bytes
	}
	return facts
}

// Count actual TCP writes, including any HTTP headers or error response that
// net/http itself may send. Merely choosing not to write a body is insufficient.
type responseObservationListener struct {
	net.Listener
	relay *responseDropRelay
}

func (listener responseObservationListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	listener.relay.connections.Add(1)
	return responseObservationConnection{connection, listener.relay}, nil
}

type responseObservationConnection struct {
	net.Conn
	relay *responseDropRelay
}

func (connection responseObservationConnection) Write(data []byte) (int, error) {
	connection.relay.writeMu.Lock()
	defer connection.relay.writeMu.Unlock()
	n, err := connection.Conn.Write(data)
	connection.relay.written.Add(uint64(n))
	return n, err
}
func (r *responseDropRelay) Close() {
	_ = r.server.Close()
	r.transport.CloseIdleConnections()
	<-r.finished
}

func openPrivateReport(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	parent, err := unix.Open(filepath.Dir(absolute), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	var stat unix.Stat_t
	if unix.Fstat(parent, &stat) != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 {
		return nil, errors.New("report parent not private")
	}
	fd, err := unix.Openat(parent, filepath.Base(absolute), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "raw-observation-report"), nil
}

func readPrivateJSON(path string, destination any) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "raw-observation-input")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
		return errors.New("invalid input file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || info.Mode().Perm()&0077 != 0 {
		return errors.New("input must be private owned regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(data) > 65536 {
		return errors.New("input exceeds limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := strictJSONValue(decoder, 0)
	if err != nil {
		return err
	}
	if _, err = decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	if err = exactJSONFields(value, reflect.TypeOf(destination).Elem(), 0); err != nil {
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination)
}

func strictJSONValue(d *json.Decoder, depth int) (any, error) {
	if depth > 16 {
		return nil, errors.New("JSON too deep")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		object := make(map[string]any)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, errors.New("invalid JSON key")
			}
			for previous := range object {
				if strings.EqualFold(previous, name) {
					return nil, errors.New("duplicate JSON field")
				}
			}
			value, err := strictJSONValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			object[name] = value
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("invalid JSON object")
		}
		return object, nil
	case json.Delim('['):
		array := []any{}
		for d.More() {
			value, err := strictJSONValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("invalid JSON array")
		}
		return array, nil
	default:
		return token, nil
	}
}
func exactJSONFields(value any, kind reflect.Type, depth int) error {
	if depth > 16 {
		return errors.New("JSON too deep")
	}
	for kind.Kind() == reflect.Pointer {
		if value == nil {
			return nil
		}
		kind = kind.Elem()
	}
	switch kind.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return errors.New("invalid JSON object")
		}
		fields := make(map[string]reflect.Type)
		for i := 0; i < kind.NumField(); i++ {
			field := kind.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			fields[name] = field.Type
		}
		for name, nested := range object {
			field, ok := fields[name]
			if !ok {
				return errors.New("unexpected JSON field")
			}
			if err := exactJSONFields(nested, field, depth+1); err != nil {
				return err
			}
		}
	case reflect.Slice:
		array, ok := value.([]any)
		if !ok {
			return errors.New("invalid JSON array")
		}
		for _, nested := range array {
			if err := exactJSONFields(nested, kind.Elem(), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
