package workerd

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/hancomac/circulusd/internal/agent"
)

// resourceReadinessResponse is the bounded SessionHost readiness envelope the
// qualification fixture returns over the private Unix socket.
type resourceReadinessResponse struct {
	SchemaVersion  int    `json:"schemaVersion"`
	Nonce          string `json:"nonce"`
	HostInstance   string `json:"hostInstance"`
	ArtifactDigest string `json:"artifactDigest"`
	ConfigDigest   string `json:"configDigest"`
	WorkerdRelease string `json:"workerdRelease"`
	LoaderABI      int    `json:"loaderAbi"`
}

const maximumResourceReadinessBodyBytes = 4 << 10

// resourceReadinessProbe gates shard publication on a nonce challenge over the
// fixture's private Unix socket. A ready response must echo the exact nonce and
// carry the materialized fixture's artifact and configuration digests plus the
// bound workerd release, so a stale or wrong process can never satisfy it.
type resourceReadinessProbe struct {
	socketPath     string
	artifactDigest string
	configDigest   string
	workerdRelease string
	pollInterval   time.Duration
	newNonce       func() (string, error)
}

func newResourceReadinessProbe(fixture resourceFixtureRendering) *resourceReadinessProbe {
	return &resourceReadinessProbe{
		socketPath:     fixture.SocketPath,
		artifactDigest: fixture.ArtifactDigest,
		configDigest:   fixture.ConfigDigest,
		workerdRelease: fixture.WorkerdRelease,
		pollInterval:   25 * time.Millisecond,
		newNonce:       newResourceReadinessNonce,
	}
}

func newResourceReadinessNonce() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// WaitReady polls /ready until the fixture returns a valid, digest-bound
// readiness envelope, the context is done, or its deadline elapses. A transient
// dial failure (the process is still binding its socket) is retried; a served
// but invalid response fails closed immediately, because a reachable process
// that answers wrongly is a contract violation, not a race.
func (probe *resourceReadinessProbe) WaitReady(ctx context.Context, _ agent.WorkerdProcessInfo) error {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(dialContext context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(dialContext, "unix", probe.socketPath)
			},
			DisableKeepAlives: true,
		},
	}
	defer client.CloseIdleConnections()

	interval := probe.pollInterval
	if interval <= 0 {
		interval = 25 * time.Millisecond
	}
	for {
		served, err := probe.attempt(ctx, client)
		if err == nil {
			return nil
		}
		if served {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("workerd resource qualification: readiness not reached: %w", ctx.Err())
		case <-time.After(interval):
		}
	}
}

// attempt performs one readiness request. The boolean reports whether the
// process served an HTTP response at all: a false value means the socket was
// not yet accepting (retryable), while a true value with a non-nil error means
// the process answered but violated the readiness contract (terminal).
func (probe *resourceReadinessProbe) attempt(ctx context.Context, client *http.Client) (served bool, err error) {
	nonce, err := probe.newNonce()
	if err != nil {
		return false, fmt.Errorf("generate readiness nonce: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/ready?nonce="+nonce, nil)
	if err != nil {
		return false, err
	}
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumResourceReadinessBodyBytes+1))
	if err != nil {
		return true, fmt.Errorf("read readiness body: %w", err)
	}
	if len(body) > maximumResourceReadinessBodyBytes {
		return true, fmt.Errorf("workerd resource qualification: readiness body exceeds %d bytes", maximumResourceReadinessBodyBytes)
	}
	if response.StatusCode != http.StatusOK {
		return true, fmt.Errorf("workerd resource qualification: readiness status %d", response.StatusCode)
	}
	var payload resourceReadinessResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return true, fmt.Errorf("decode readiness body: %w", err)
	}
	if err := probe.verify(payload, nonce); err != nil {
		return true, err
	}
	return true, nil
}

func (probe *resourceReadinessProbe) verify(payload resourceReadinessResponse, nonce string) error {
	if payload.SchemaVersion != 1 || payload.LoaderABI != 1 {
		return fmt.Errorf("workerd resource qualification: readiness schema/abi mismatch (schema=%d abi=%d)", payload.SchemaVersion, payload.LoaderABI)
	}
	if subtle.ConstantTimeCompare([]byte(payload.Nonce), []byte(nonce)) != 1 {
		return fmt.Errorf("workerd resource qualification: readiness nonce was not echoed")
	}
	if payload.ArtifactDigest != probe.artifactDigest {
		return fmt.Errorf("workerd resource qualification: readiness artifact digest does not match the materialized fixture")
	}
	if payload.ConfigDigest != probe.configDigest {
		return fmt.Errorf("workerd resource qualification: readiness config digest does not match the materialized fixture")
	}
	if payload.WorkerdRelease != probe.workerdRelease {
		return fmt.Errorf("workerd resource qualification: readiness workerd release does not match the bound release")
	}
	if !resourceEvidenceHexIdentity.MatchString(payload.HostInstance) {
		return fmt.Errorf("workerd resource qualification: readiness host instance is not a 128-bit hex value")
	}
	return nil
}
