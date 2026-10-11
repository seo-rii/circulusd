package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hancomac/circulusd/internal/conformance/celld/issuance"
	"golang.org/x/sys/unix"
)

const relayPayloadLimit = 64 << 20

type controlRequest struct {
	Operation  string `json:"operation"`
	CellID     string `json:"cellId"`
	PriorEpoch uint64 `json:"priorEpoch"`
}
type relayFacts struct {
	SchemaVersion                 int                      `json:"schemaVersion"`
	Kind                          string                   `json:"kind"`
	State                         string                   `json:"state"`
	CellID                        string                   `json:"cellId"`
	PriorEpoch                    uint64                   `json:"priorEpoch"`
	OwnershipKeyDigest            string                   `json:"ownershipKeyDigest"`
	LTXKeyDigest                  string                   `json:"ltxKeyDigest"`
	LTXBodyDigest                 string                   `json:"ltxBodyDigest"`
	LTXPutStatus                  int                      `json:"ltxPutStatus"`
	LTXPutCompletedSequence       uint64                   `json:"ltxPutCompletedSequence"`
	OwnershipGetStartedSequence   uint64                   `json:"ownershipGetStartedSequence"`
	OwnershipGetReleasedSequence  uint64                   `json:"ownershipGetReleasedSequence"`
	OwnershipGetCompletedSequence uint64                   `json:"ownershipGetCompletedSequence"`
	OwnershipGetStatus            int                      `json:"ownershipGetStatus"`
	ProofOwnershipRead            issuance.OwnershipRecord `json:"proofOwnershipRead"`
	HeldRequests                  int                      `json:"heldRequests"`
	Error                         string                   `json:"error"`
}
type relay struct {
	cfg             config
	mu              sync.Mutex
	facts           relayFacts
	ownPath         string
	ltxPrefix       string
	release         chan struct{}
	server          *http.Server
	listener        net.Listener
	controlListener net.Listener
	transport       *http.Transport
	upstream        *url.URL
	failed          chan struct{}
	closed          chan struct{}
	closeOnce       sync.Once
	socketInfo      os.FileInfo
}

func newRelay(cfg config) (*relay, error) {
	if !validRelayConfig(cfg) {
		return nil, errors.New("invalid relay configuration")
	}
	parent, err := privateParent(cfg.ControlSocket)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	// Refuse existing socket/files, and bind under the held parent directory.
	var st unix.Stat_t
	if unix.Fstatat(parent, filepath.Base(cfg.ControlSocket), &st, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
		return nil, errors.New("control path exists")
	}
	controlListener, err := net.Listen("unix", "/proc/self/fd/"+itoa(parent)+"/"+filepath.Base(cfg.ControlSocket))
	if err != nil {
		return nil, err
	}
	// The held parent fd closes before listener shutdown. Never let the net
	// package unlink through a possibly reused /proc/self/fd number.
	controlListener.(*net.UnixListener).SetUnlinkOnClose(false)
	if err = unix.Fchmodat(parent, filepath.Base(cfg.ControlSocket), 0600, 0); err != nil {
		controlListener.Close()
		return nil, err
	}
	info, err := os.Lstat(cfg.ControlSocket)
	if err != nil {
		controlListener.Close()
		return nil, err
	}
	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		controlListener.Close()
		os.Remove(cfg.ControlSocket)
		return nil, err
	}
	u, _ := loopbackEndpoint(cfg.UpstreamEndpoint)
	r := &relay{cfg: cfg, upstream: u, listener: listener, controlListener: controlListener, failed: make(chan struct{}), closed: make(chan struct{}), socketInfo: info,
		facts: relayFacts{SchemaVersion: 1, Kind: "circulusd.native-owner-relay-observation/v1", State: "idle"}}
	timeout := time.Duration(cfg.RequestTimeoutMillis) * time.Millisecond
	r.transport = &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 16 << 10, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != u.Host {
			return nil, errors.New("unexpected relay origin")
		}
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, address)
	}}
	r.server = &http.Server{Handler: http.HandlerFunc(r.serve), ReadHeaderTimeout: timeout, ReadTimeout: timeout, WriteTimeout: time.Duration(cfg.HoldTimeoutMillis+cfg.RequestTimeoutMillis) * time.Millisecond, MaxHeaderBytes: 16 << 10}
	go func() {
		err := r.server.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			close(r.failed)
		}
	}()
	go r.serveControl()
	return r, nil
}

func itoa(value int) string { return strconv.Itoa(value) }

func (r *relay) Close() {
	r.closeOnce.Do(func() {
		close(r.closed)
		_ = r.server.Close()
		_ = r.controlListener.Close()
		r.transport.CloseIdleConnections()
		if current, err := os.Lstat(r.cfg.ControlSocket); err == nil && os.SameFile(current, r.socketInfo) {
			_ = os.Remove(r.cfg.ControlSocket)
		}
	})
}

func (r *relay) serveControl() {
	for {
		conn, err := r.controlListener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			data, readErr := io.ReadAll(io.LimitReader(conn, 4097))
			var req controlRequest
			if readErr != nil || len(data) > 4096 || issuance.DecodeStrict(data, &req) != nil {
				_ = json.NewEncoder(conn).Encode(relayFacts{Error: "invalid control request"})
				return
			}
			_ = json.NewEncoder(conn).Encode(r.command(req))
		}()
	}
}
func (r *relay) command(req controlRequest) relayFacts {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch req.Operation {
	case "arm":
		if r.facts.State != "idle" || !identifier.MatchString(req.CellID) || req.PriorEpoch == 0 {
			result := r.facts
			result.Error = "cannot arm"
			return result
		}
		r.ownPath = "/" + r.cfg.Bucket + "/" + r.cfg.KeyPrefix + "cells/" + req.CellID + "/own.json"
		r.ltxPrefix = "/" + r.cfg.Bucket + "/" + r.cfg.KeyPrefix + "cells/" + req.CellID + "/ltx/e" + strconv.FormatUint(req.PriorEpoch, 10) + "/"
		r.release = make(chan struct{})
		r.facts.State = "armed"
		r.facts.CellID = req.CellID
		r.facts.PriorEpoch = req.PriorEpoch
		r.facts.OwnershipKeyDigest = digest([]byte(r.cfg.KeyPrefix + "cells/" + req.CellID + "/own.json"))
	case "status":
		if req.CellID != "" || req.PriorEpoch != 0 {
			result := r.facts
			result.Error = "invalid status"
			return result
		}
	case "release":
		if r.facts.State != "held" || req.CellID != "" || req.PriorEpoch != 0 {
			result := r.facts
			result.Error = "nothing held"
			return result
		}
		r.facts.State = "released"
		r.facts.OwnershipGetReleasedSequence = uint64(time.Now().UnixNano())
		close(r.release)
	default:
		result := r.facts
		result.Error = "unknown operation"
		return result
	}
	return r.facts
}

func (r *relay) serve(w http.ResponseWriter, req *http.Request) {
	// The original Host participates in SigV4. Only the dial/URL destination
	// changes; method, escaped path, query, Host and signed headers stay exact.
	if req.Host != r.cfg.ListenAddress || req.URL.Scheme != "" || req.URL.Host != "" ||
		(req.URL.RawPath != "" && req.URL.RawPath != strings.ReplaceAll(req.URL.Path, ":", "%3A")) || req.URL.Fragment != "" ||
		!strings.HasPrefix(req.URL.Path, "/"+r.cfg.Bucket) || (req.URL.Path != "/"+r.cfg.Bucket && !strings.HasPrefix(req.URL.Path, "/"+r.cfg.Bucket+"/")) ||
		(req.Method != http.MethodGet && req.Method != http.MethodHead && req.Method != http.MethodPut && req.Method != http.MethodDelete) {
		http.Error(w, "invalid S3 relay request", 400)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, relayPayloadLimit+1))
	if err != nil || len(body) > relayPayloadLimit {
		http.Error(w, "S3 request bound", 400)
		return
	}
	if req.Method == http.MethodGet && req.URL.RawQuery == "" {
		r.mu.Lock()
		held := req.URL.Path == r.ownPath && r.facts.LTXPutStatus >= 200 && r.facts.LTXPutStatus < 300 && r.facts.State == "armed"
		duplicate := req.URL.Path == r.ownPath && (r.facts.State == "held" || r.facts.State == "released")
		if held {
			r.facts.State = "held"
			r.facts.HeldRequests++
			r.facts.OwnershipGetStartedSequence = uint64(time.Now().UnixNano())
		}
		if duplicate {
			r.facts.HeldRequests++
			r.facts.Error = "duplicate ownership proof read"
		}
		release := r.release
		r.mu.Unlock()
		if duplicate {
			http.Error(w, "ambiguous duplicate ownership read", 409)
			return
		}
		if held {
			timer := time.NewTimer(time.Duration(r.cfg.HoldTimeoutMillis) * time.Millisecond)
			defer timer.Stop()
			select {
			case <-release:
			case <-req.Context().Done():
				r.fail("held ownership read cancelled")
				return
			case <-r.closed:
				return
			case <-timer.C:
				r.fail("held ownership read timed out")
				http.Error(w, "hold timed out", 504)
				return
			}
		}
	}
	forward := req.Clone(req.Context())
	forward.URL.Scheme = r.upstream.Scheme
	forward.URL.Host = r.upstream.Host
	forward.Host = req.Host
	forward.RequestURI = ""
	forward.Body = io.NopCloser(bytes.NewReader(body))
	forward.GetBody = nil
	resp, err := r.transport.RoundTrip(forward)
	if err != nil {
		r.failIfRelevant(req, "upstream unavailable")
		http.Error(w, "S3 upstream unavailable", 502)
		return
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, relayPayloadLimit+1))
	if err != nil || len(payload) > relayPayloadLimit {
		r.failIfRelevant(req, "response bound")
		http.Error(w, "S3 response bound", 502)
		return
	}
	r.mu.Lock()
	if req.Method == http.MethodPut && req.URL.RawQuery == "" && r.facts.State == "armed" && strings.HasPrefix(req.URL.Path, r.ltxPrefix) && strings.HasSuffix(req.URL.Path, ".ltx") && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		r.facts.LTXPutStatus = resp.StatusCode
		r.facts.LTXKeyDigest = digest([]byte(strings.TrimPrefix(req.URL.Path, "/"+r.cfg.Bucket+"/")))
		r.facts.LTXBodyDigest = digest(body)
		r.facts.LTXPutCompletedSequence = uint64(time.Now().UnixNano())
	}
	if req.Method == http.MethodGet && req.URL.Path == r.ownPath && req.URL.RawQuery == "" && r.facts.State == "released" {
		r.facts.OwnershipGetStatus = resp.StatusCode
		r.facts.OwnershipGetCompletedSequence = uint64(time.Now().UnixNano())
		if resp.StatusCode == 200 && len(payload) > 0 && len(payload) <= 1024 && len(resp.Header.Values("ETag")) == 1 {
			r.facts.ProofOwnershipRead = issuance.OwnershipRecord{Body: base64.StdEncoding.EncodeToString(payload), ETag: resp.Header.Get("ETag")}
			r.facts.State = "completed"
		} else {
			r.facts.State = "failed"
			r.facts.Error = "invalid ownership proof response"
		}
	}
	r.mu.Unlock()
	for name, values := range resp.Header {
		w.Header()[name] = append([]string(nil), values...)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(payload)
}
func (r *relay) fail(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.facts.State = "failed"
	r.facts.Error = reason
}
func (r *relay) failIfRelevant(req *http.Request, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if req.URL.Path == r.ownPath {
		r.facts.State = "failed"
		r.facts.Error = reason
	}
}

func control(ctx context.Context, socket string, req controlRequest) (relayFacts, error) {
	parent, err := privateParent(socket)
	if err != nil {
		return relayFacts{}, err
	}
	defer unix.Close(parent)
	var st unix.Stat_t
	if unix.Fstatat(parent, filepath.Base(socket), &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		return relayFacts{}, errors.New("invalid private control socket")
	}
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", "/proc/self/fd/"+itoa(parent)+"/"+filepath.Base(socket))
	if err != nil {
		return relayFacts{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err = json.NewEncoder(conn).Encode(req); err != nil {
		return relayFacts{}, err
	}
	if unixConn, ok := conn.(*net.UnixConn); ok {
		_ = unixConn.CloseWrite()
	}
	data, err := io.ReadAll(io.LimitReader(conn, 16385))
	var result relayFacts
	if err != nil || len(data) > 16384 || issuance.DecodeStrict(data, &result) != nil {
		return result, errors.New("invalid control response")
	}
	return result, nil
}
