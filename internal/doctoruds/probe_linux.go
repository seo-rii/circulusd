//go:build linux

// Package doctoruds builds a fail-closed doctor probe for the private daemon
// control sockets. Descriptor evidence proves protocol compatibility; it is
// deliberately not represented as a daemon binary digest.
package doctoruds

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/conformance"
	"github.com/hancomac/circulusd/internal/controlrpc"
	"github.com/hancomac/circulusd/internal/doctor"
)

const (
	Component = "uds.protocol"

	Platformd = "platformd"
	Agentd    = "agentd"
	Executord = "executord"

	MaximumProbeTimeout = 30 * time.Second

	expectedDescriptorSHA256 = "693b865cbe6eadb0e6d43910707f8bd0cde0bd892642487e514416e8c0ebc1e0"
	maximumSocketPathBytes   = 107
)

var expectedDescriptor = mustDecodeDescriptor(expectedDescriptorSHA256)

// Endpoint binds a stable daemon name and socket path to the server role that
// the authenticated control handshake must prove.
type Endpoint struct {
	Name               string
	SocketPath         string
	ExpectedServerPeer v1.ProtocolPeer
}

// Query obtains one authenticated capability response. Tests and composed
// callers can inject it without weakening BuildProbe's response validation.
type Query func(context.Context, Endpoint) (*v1.GetCapabilitiesResponse, error)

type Config struct {
	Endpoints []Endpoint
	Timeout   time.Duration
	Query     Query
}

// BuildProbe validates and snapshots the complete endpoint set before it
// returns an executable probe.
func BuildProbe(config Config) (doctor.Probe, error) {
	endpoints, err := canonicalEndpoints(config.Endpoints)
	if err != nil {
		return doctor.Probe{}, err
	}
	if config.Timeout <= 0 || config.Timeout > MaximumProbeTimeout {
		return doctor.Probe{}, fmt.Errorf("doctoruds: timeout must be positive and at most %s", MaximumProbeTimeout)
	}
	query := config.Query
	if query == nil {
		query = ControlRPCQuery
	}

	timeout := config.Timeout
	return doctor.Probe{
		Component: Component,
		Run: func(ctx context.Context) conformance.Result {
			return run(ctx, endpoints, timeout, query)
		},
	}, nil
}

// ControlRPCQuery is the production query implementation. The control client
// authenticates platformctl as the caller and binds the handshake proof to the
// endpoint's exact expected server role.
func ControlRPCQuery(ctx context.Context, endpoint Endpoint) (*v1.GetCapabilitiesResponse, error) {
	if ctx == nil {
		return nil, fmt.Errorf("doctoruds: query context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validEndpoint(endpoint) {
		return nil, fmt.Errorf("doctoruds: query endpoint is invalid")
	}
	client, err := controlrpc.NewClient(controlrpc.ClientConfig{
		SocketPath:         endpoint.SocketPath,
		Peer:               v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL,
		ExpectedServerPeer: endpoint.ExpectedServerPeer,
	})
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.GetCapabilities(ctx)
}

func run(ctx context.Context, endpoints []Endpoint, timeout time.Duration, query Query) conformance.Result {
	if ctx == nil || ctx.Err() != nil {
		return result(conformance.NotRun, "daemon protocol probe canceled", nil)
	}
	probeContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	artifacts := make([]conformance.ArtifactReference, 0, len(endpoints))
	for _, endpoint := range endpoints {
		response, err := query(probeContext, endpoint)
		if err != nil {
			return queryFailure(ctx, probeContext, err)
		}
		if ctx.Err() != nil {
			return result(conformance.NotRun, "daemon protocol probe canceled", nil)
		}
		if probeContext.Err() != nil {
			return result(conformance.Unavailable, "daemon protocol probe timed out", nil)
		}
		if !validCapabilitiesResponse(endpoint, response) {
			return result(conformance.Fail, "daemon protocol evidence is invalid", nil)
		}
		artifacts = append(artifacts, conformance.ArtifactReference{
			Name:   "uds-" + endpoint.Name + "-protocol-descriptor",
			Digest: "sha256:" + hex.EncodeToString(response.GetDescriptorDigest().GetValue()),
		})
	}
	return result(conformance.Pass, "", artifacts)
}

func queryFailure(parent, bounded context.Context, err error) conformance.Result {
	if parent.Err() != nil {
		return result(conformance.NotRun, "daemon protocol probe canceled", nil)
	}
	if bounded.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		return result(conformance.Unavailable, "daemon protocol probe timed out", nil)
	}
	if code := connect.CodeOf(err); code != connect.CodeUnknown && code != connect.CodeUnavailable {
		return result(conformance.Fail, "daemon protocol verification failed", nil)
	}
	if connect.CodeOf(err) == connect.CodeUnavailable || errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return result(conformance.Unavailable, "daemon protocol endpoint is unavailable", nil)
	}
	return result(conformance.Fail, "daemon protocol verification failed", nil)
}

func result(status conformance.Status, reason string, artifacts []conformance.ArtifactReference) conformance.Result {
	clonedArtifacts := append([]conformance.ArtifactReference(nil), artifacts...)
	if clonedArtifacts == nil {
		clonedArtifacts = make([]conformance.ArtifactReference, 0)
	}
	evidence := conformance.Evidence{
		Class:              conformance.EvidenceClassExternal,
		ArtifactReferences: clonedArtifacts,
	}
	if status == conformance.Pass {
		evidence.Version = "1.0"
	}
	return conformance.Result{
		Component: Component,
		Status:    status,
		Reason:    reason,
		Evidence:  evidence,
	}
}

func canonicalEndpoints(configured []Endpoint) ([]Endpoint, error) {
	want := []struct {
		name string
		peer v1.ProtocolPeer
	}{
		{name: Platformd, peer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD},
		{name: Agentd, peer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD},
		{name: Executord, peer: v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD},
	}
	if len(configured) != len(want) {
		return nil, fmt.Errorf("doctoruds: exactly three daemon endpoints are required")
	}

	byName := make(map[string]Endpoint, len(configured))
	paths := make(map[string]struct{}, len(configured))
	for _, endpoint := range configured {
		if _, duplicate := byName[endpoint.Name]; duplicate {
			return nil, fmt.Errorf("doctoruds: daemon endpoint is duplicated")
		}
		if !canonicalSocketPath(endpoint.SocketPath) {
			return nil, fmt.Errorf("doctoruds: daemon socket path must be canonical and absolute")
		}
		if _, duplicate := paths[endpoint.SocketPath]; duplicate {
			return nil, fmt.Errorf("doctoruds: daemon socket path is duplicated")
		}
		paths[endpoint.SocketPath] = struct{}{}
		byName[endpoint.Name] = endpoint
	}

	canonical := make([]Endpoint, 0, len(want))
	for _, expected := range want {
		endpoint, found := byName[expected.name]
		if !found || endpoint.ExpectedServerPeer != expected.peer {
			return nil, fmt.Errorf("doctoruds: daemon endpoint role set is invalid")
		}
		canonical = append(canonical, endpoint)
	}
	return canonical, nil
}

func canonicalSocketPath(path string) bool {
	return path != "" &&
		utf8.ValidString(path) &&
		strings.IndexFunc(path, unicode.IsControl) < 0 &&
		filepath.IsAbs(path) &&
		filepath.Clean(path) == path &&
		path != string(filepath.Separator) &&
		len(path) <= maximumSocketPathBytes
}

func validEndpoint(endpoint Endpoint) bool {
	if !canonicalSocketPath(endpoint.SocketPath) {
		return false
	}
	switch endpoint.Name {
	case Platformd:
		return endpoint.ExpectedServerPeer == v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD
	case Agentd:
		return endpoint.ExpectedServerPeer == v1.ProtocolPeer_PROTOCOL_PEER_AGENTD
	case Executord:
		return endpoint.ExpectedServerPeer == v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD
	default:
		return false
	}
}

func validCapabilitiesResponse(endpoint Endpoint, response *v1.GetCapabilitiesResponse) bool {
	if response == nil || response.GetMeta() == nil ||
		response.GetProtocolVersion().GetMajor() != 1 ||
		response.GetProtocolVersion().GetMinor() != 0 ||
		len(response.GetMeta().GetRequestId().GetValue()) != 16 ||
		response.GetMeta().GetServerSequence() == 0 ||
		!validDescriptor(response.GetDescriptorDigest()) ||
		!validDescriptor(response.GetMeta().GetDescriptorDigest()) ||
		!bytes.Equal(response.GetDescriptorDigest().GetValue(), response.GetMeta().GetDescriptorDigest().GetValue()) {
		return false
	}

	requiredRoleCapability := ""
	if endpoint.Name != Platformd {
		requiredRoleCapability = "daemon." + endpoint.Name
	}
	controlAvailable := false
	roleAvailable := requiredRoleCapability == ""
	seen := make(map[string]struct{}, len(response.GetCapabilities()))
	for _, capability := range response.GetCapabilities() {
		if capability == nil || capability.GetName() == "" || len(capability.GetName()) > 256 {
			return false
		}
		for _, character := range capability.GetName() {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
				character != '.' && character != '_' && character != ':' && character != '/' && character != '-' {
				return false
			}
		}
		if _, duplicate := seen[capability.GetName()]; duplicate {
			return false
		}
		seen[capability.GetName()] = struct{}{}
		available := capability.GetAvailability() == v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE
		switch capability.GetAvailability() {
		case v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE:
			if capability.GetUnavailableReason() != nil {
				return false
			}
		case v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_UNAVAILABLE,
			v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_DEGRADED,
			v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_FORBIDDEN:
			reason := capability.GetUnavailableReason()
			if reason == nil || reason.GetCode() <= v1.ErrorCode_ERROR_CODE_UNSPECIFIED ||
				reason.GetCode() > v1.ErrorCode_ERROR_CODE_NEEDS_CONFIRMATION ||
				reason.GetReason() == "" || reason.GetReason() != strings.TrimSpace(reason.GetReason()) ||
				reason.GetMessage() == "" || !utf8.ValidString(reason.GetReason()) ||
				!utf8.ValidString(reason.GetMessage()) || len(reason.GetReason()) > 256 ||
				len(reason.GetMessage()) > 1024 || strings.IndexFunc(reason.GetReason(), unicode.IsControl) >= 0 ||
				strings.IndexFunc(reason.GetMessage(), unicode.IsControl) >= 0 || len(reason.GetMetadata()) > 32 ||
				reason.GetRequestId() != nil && len(reason.GetRequestId().GetValue()) != 16 {
				return false
			}
			for key, value := range reason.GetMetadata() {
				if key == "" || !utf8.ValidString(key) || !utf8.ValidString(value) || len(key) > 256 ||
					len(value) > 1024 || strings.IndexFunc(key, unicode.IsControl) >= 0 ||
					strings.IndexFunc(value, unicode.IsControl) >= 0 {
					return false
				}
			}
		default:
			return false
		}
		if len(capability.GetAttributes()) > 32 {
			return false
		}
		for key, value := range capability.GetAttributes() {
			if key == "" || !utf8.ValidString(key) || !utf8.ValidString(value) || len(key) > 256 ||
				len(value) > 1024 || strings.IndexFunc(key, unicode.IsControl) >= 0 ||
				strings.IndexFunc(value, unicode.IsControl) >= 0 {
				return false
			}
		}
		switch capability.GetName() {
		case "control.protocol":
			controlAvailable = available
		case requiredRoleCapability:
			roleAvailable = available
		}
	}
	return controlAvailable && roleAvailable
}

func validDescriptor(digest *v1.Digest) bool {
	return digest != nil &&
		digest.GetAlgorithm() == v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256 &&
		bytes.Equal(digest.GetValue(), expectedDescriptor)
}

func mustDecodeDescriptor(encoded string) []byte {
	digest, err := hex.DecodeString(encoded)
	if err != nil {
		panic("doctoruds: compiled descriptor digest is invalid")
	}
	return digest
}
