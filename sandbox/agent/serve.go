//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
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
	"sync"
	"syscall"
	"time"
)

const (
	// sandboxd's ledger holds 4096 keys per generation (sandboxrpc
	// maximumIdempotencyKeys); the default budget leaves room for the last
	// run's spawn, stdin chunks, close-stdin and a cancel.
	defaultLedgerBudget = 3800
	defaultMaxSessions  = 16
	defaultSessionIdle  = time.Hour
)

type readyPayload struct {
	Ready             bool           `json:"ready"`
	Host              string         `json:"host"`
	Port              int            `json:"port"`
	Token             string         `json:"token"`
	Backend           string         `json:"backend"`
	Launcher          string         `json:"launcher"`
	EnvironmentDigest string         `json:"environmentDigest"`
	SandboxdDigest    string         `json:"sandboxdDigest"`
	Python            pythonInfo     `json:"python"`
	Kernel            string         `json:"kernel"`
	Distro            string         `json:"distro"`
	StateDir          string         `json:"stateDir"`
	MaxSessions       int            `json:"maxSessions"`
	SessionIdleMs     int64          `json:"sessionIdleMs"`
	LedgerBudget      int            `json:"ledgerBudget"`
	ProbeMs           int64          `json:"probeMs"`
	Extra             map[string]any `json:"extra,omitempty"`
}

func runServe(args []string) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	var options launchOptions
	home, _ := os.UserHomeDir()
	flags.StringVar(&options.sandboxd, "sandboxd", "", "path to the Linux sandboxd binary (required)")
	flags.StringVar(&options.stateDir, "state-dir", filepath.Join(home, ".cache", "circulusd-test", "sandbox"), "instance state directory")
	flags.StringVar(&options.launcher, "launcher", "auto", "auto|nsjail|docker|unshare")
	flags.StringVar(&options.backend, "backend", "", "sandboxd launch backend label (default: docker for the docker launcher, nsjail otherwise)")
	flags.StringVar(&options.python, "python", "/usr/bin/python3", "interpreter for the namespace launchers")
	flags.StringVar(&options.image, "image", "", "container image for the docker launcher (default "+dockerDefaultImage+")")
	flags.StringVar(&options.workspaceSize, "workspace-size", defaultWorkspaceSize, "tmpfs size of /workspace")
	flags.StringVar(&options.bindHost, "bind-host", "127.0.0.1", "address for the local JSON API")
	flags.IntVar(&options.maxSessions, "max-sessions", defaultMaxSessions, "maximum number of session sandboxes kept at once (LRU idle eviction)")
	flags.DurationVar(&options.sessionIdle, "session-idle", defaultSessionIdle, "stop a session's sandbox after this idle time (0 = never)")
	flags.IntVar(&options.ledgerBudget, "ledger-budget", defaultLedgerBudget, "keyed RPCs per sandboxd generation before it is relaunched")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if options.sandboxd == "" {
		fmt.Fprintln(os.Stderr, "serve: --sandboxd is required")
		return 2
	}
	switch options.launcher {
	case "auto", "nsjail", "docker", "unshare":
	default:
		fmt.Fprintf(os.Stderr, "serve: unknown launcher %q\n", options.launcher)
		return 2
	}
	if options.maxSessions < 1 || options.ledgerBudget < 1 || options.ledgerBudget > 4000 {
		fmt.Fprintln(os.Stderr, "serve: --max-sessions must be >= 1 and --ledger-budget in 1..4000")
		return 2
	}

	plan, err := preparePlan(options)
	if err != nil {
		logf("%v", err)
		return 1
	}
	sandboxes := newPool(plan)
	probeCtx, cancelProbe := context.WithTimeout(context.Background(), 2*time.Minute)
	probeDuration, err := sandboxes.probe(probeCtx)
	cancelProbe()
	if err != nil {
		logf("sandbox probe failed: %v", err)
		return 1
	}
	logf("probe ok in %s (%s launcher, python %s)", probeDuration.Round(time.Millisecond), plan.Launcher, plan.Python.Version)

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		logf("token: %v", err)
		return 1
	}
	token := hex.EncodeToString(tokenBytes)

	listener, err := net.Listen("tcp", net.JoinHostPort(options.bindHost, "0"))
	if err != nil {
		logf("listen: %v", err)
		sandboxes.close()
		return 1
	}
	ready := readyPayload{
		Ready:             true,
		Host:              options.bindHost,
		Port:              listener.Addr().(*net.TCPAddr).Port,
		Token:             token,
		Backend:           plan.Backend,
		Launcher:          plan.Launcher,
		EnvironmentDigest: plan.EnvironmentDigest,
		SandboxdDigest:    plan.SandboxdDigest,
		Python:            plan.Python,
		Kernel:            kernelRelease(),
		Distro:            distroName(),
		StateDir:          plan.StateDir,
		MaxSessions:       options.maxSessions,
		SessionIdleMs:     options.sessionIdle.Milliseconds(),
		LedgerBudget:      options.ledgerBudget,
		ProbeMs:           probeDuration.Milliseconds(),
		Extra:             plan.Extra,
	}

	// Only the process that read the ready line (the backend) knows the token;
	// WSL2 publishes this loopback port to every process on the Windows host.
	authorized := func(next http.HandlerFunc) http.HandlerFunc {
		expected := []byte("Bearer " + token)
		return func(response http.ResponseWriter, request *http.Request) {
			if subtle.ConstantTimeCompare([]byte(request.Header.Get("Authorization")), expected) != 1 {
				writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			next(response, request)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/ready", authorized(func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, ready)
	}))
	mux.HandleFunc("POST /v1/run", authorized(func(response http.ResponseWriter, request *http.Request) {
		var body runRequest
		if err := json.NewDecoder(io.LimitReader(request.Body, 4<<20)).Decode(&body); err != nil {
			writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
			return
		}
		result, err := sandboxes.run(request.Context(), body)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, errInvalidRequest) {
				status = http.StatusBadRequest
			}
			writeJSON(response, status, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(response, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /v1/sessions", authorized(func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, map[string]any{"sessions": sandboxes.list()})
	}))
	mux.HandleFunc("DELETE /v1/sessions/{session}", authorized(func(response http.ResponseWriter, request *http.Request) {
		key := safeDirectory(request.PathValue("session"))
		if !sandboxes.closeSession(key) {
			writeJSON(response, http.StatusNotFound, map[string]string{"error": "no sandbox for session " + key})
			return
		}
		writeJSON(response, http.StatusAccepted, map[string]string{"status": "stopping"})
	}))
	mux.HandleFunc("/", authorized(func(response http.ResponseWriter, request *http.Request) {
		writeJSON(response, http.StatusNotFound, map[string]string{"error": "no route for " + request.Method + " " + request.URL.Path})
	}))
	// Every request context descends from serveCtx, so cancelling it at
	// shutdown makes in-flight runs cancel their sandbox process and return
	// instead of holding their session lock until the process deadline.
	serveCtx, cancelServe := context.WithCancel(context.Background())
	defer cancelServe()
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return serveCtx },
	}

	var once sync.Once
	stopped := make(chan string, 1)
	requestStop := func(reason string) {
		once.Do(func() { stopped <- reason })
	}
	go func() {
		// The backend keeps our stdin open; EOF means it went away.
		_, _ = io.Copy(io.Discard, os.Stdin)
		requestStop("backend closed the agent")
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		received := <-signals
		requestStop("signal " + received.String())
	}()
	go func() {
		_ = server.Serve(listener)
	}()
	reaperStop := make(chan struct{})
	go sandboxes.runReaper(options.sessionIdle, reaperStop)

	encoded, _ := json.Marshal(ready)
	fmt.Println(string(encoded))

	reason := <-stopped
	logf("stopping: %s", reason)
	close(reaperStop)
	cancelServe()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	_ = server.Shutdown(shutdownCtx)
	cancelShutdown()
	sandboxes.close()
	return 0
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
