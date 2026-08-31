//go:build linux

package doctoruds

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/conformance"
)

func TestBuildProbeRejectsInvalidConfigurationBeforeQuery(t *testing.T) {
	queryCalls := 0
	query := func(context.Context, Endpoint) (*v1.GetCapabilitiesResponse, error) {
		queryCalls++
		return nil, errors.New("must not be called")
	}
	valid := testEndpoints()
	tooLongPath := "/" + strings.Repeat("a", 107)
	tests := []struct {
		name      string
		endpoints []Endpoint
		timeout   time.Duration
	}{
		{name: "empty endpoint set", endpoints: nil, timeout: time.Second},
		{name: "missing daemon", endpoints: valid[:2], timeout: time.Second},
		{name: "extra daemon", endpoints: append(append([]Endpoint(nil), valid...), Endpoint{Name: "sandboxd", SocketPath: "/run/pi-platform/sandboxd.sock", ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_SANDBOXD}), timeout: time.Second},
		{name: "duplicate daemon", endpoints: []Endpoint{valid[0], valid[1], valid[1]}, timeout: time.Second},
		{name: "wrong platformd role", endpoints: replaceEndpoint(valid, 0, Endpoint{Name: Platformd, SocketPath: valid[0].SocketPath, ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD}), timeout: time.Second},
		{name: "wrong agentd role", endpoints: replaceEndpoint(valid, 1, Endpoint{Name: Agentd, SocketPath: valid[1].SocketPath, ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD}), timeout: time.Second},
		{name: "wrong executord role", endpoints: replaceEndpoint(valid, 2, Endpoint{Name: Executord, SocketPath: valid[2].SocketPath, ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD}), timeout: time.Second},
		{name: "relative path", endpoints: replaceEndpoint(valid, 0, Endpoint{Name: Platformd, SocketPath: "run/platformd.sock", ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD}), timeout: time.Second},
		{name: "unclean path", endpoints: replaceEndpoint(valid, 0, Endpoint{Name: Platformd, SocketPath: "/run/../run/platformd.sock", ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD}), timeout: time.Second},
		{name: "root path", endpoints: replaceEndpoint(valid, 0, Endpoint{Name: Platformd, SocketPath: "/", ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD}), timeout: time.Second},
		{name: "nul path", endpoints: replaceEndpoint(valid, 0, Endpoint{Name: Platformd, SocketPath: "/run/pi-platform/platformd.sock\x00suffix", ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD}), timeout: time.Second},
		{name: "control path", endpoints: replaceEndpoint(valid, 0, Endpoint{Name: Platformd, SocketPath: "/run/pi-platform/platformd.sock\n", ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD}), timeout: time.Second},
		{name: "invalid UTF-8 path", endpoints: replaceEndpoint(valid, 0, Endpoint{Name: Platformd, SocketPath: "/run/pi-platform/\xff.sock", ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD}), timeout: time.Second},
		{name: "long path", endpoints: replaceEndpoint(valid, 0, Endpoint{Name: Platformd, SocketPath: tooLongPath, ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD}), timeout: time.Second},
		{name: "duplicate path", endpoints: replaceEndpoint(valid, 2, Endpoint{Name: Executord, SocketPath: valid[1].SocketPath, ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD}), timeout: time.Second},
		{name: "zero timeout", endpoints: valid, timeout: 0},
		{name: "negative timeout", endpoints: valid, timeout: -time.Second},
		{name: "excessive timeout", endpoints: valid, timeout: MaximumProbeTimeout + time.Nanosecond},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildProbe(Config{Endpoints: test.endpoints, Timeout: test.timeout, Query: query}); err == nil {
				t.Fatal("BuildProbe() accepted invalid configuration")
			}
		})
	}
	if queryCalls != 0 {
		t.Fatalf("query calls during validation = %d, want 0", queryCalls)
	}
}

func TestInjectedProbeQueriesCanonicalDaemonOrderAndReturnsExternalEvidence(t *testing.T) {
	configured := []Endpoint{testEndpoints()[2], testEndpoints()[0], testEndpoints()[1]}
	original := append([]Endpoint(nil), configured...)
	var gotEndpoints []Endpoint
	var gotDeadlines []time.Time
	query := func(ctx context.Context, endpoint Endpoint) (*v1.GetCapabilitiesResponse, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("query context has no deadline")
		}
		gotDeadlines = append(gotDeadlines, deadline)
		gotEndpoints = append(gotEndpoints, endpoint)
		return testCapabilitiesResponse(endpoint.Name), nil
	}
	probe, err := BuildProbe(Config{Endpoints: configured, Timeout: time.Second, Query: query})
	if err != nil {
		t.Fatalf("BuildProbe() error = %v", err)
	}
	if probe.Component != Component {
		t.Fatalf("probe component = %q, want %q", probe.Component, Component)
	}
	configured[0].Name = "mutated"
	configured[1].SocketPath = "/mutated.sock"
	configured[2].ExpectedServerPeer = v1.ProtocolPeer_PROTOCOL_PEER_SANDBOXD

	result := probe.Run(context.Background())
	if result.Component != Component || result.Status != conformance.Pass || result.Reason != "" {
		t.Fatalf("probe result = %+v, want PASS", result)
	}
	wantOrder := []Endpoint{original[1], original[2], original[0]}
	if !slices.Equal(gotEndpoints, wantOrder) {
		t.Fatalf("queried endpoints = %+v, want canonical order %+v", gotEndpoints, wantOrder)
	}
	if len(gotDeadlines) != 3 || !gotDeadlines[0].Equal(gotDeadlines[1]) || !gotDeadlines[1].Equal(gotDeadlines[2]) {
		t.Fatalf("query deadlines = %v, want one shared bounded deadline", gotDeadlines)
	}
	if result.Evidence.Class != conformance.EvidenceClassExternal || result.Evidence.Version != "1.0" {
		t.Fatalf("evidence identity = %+v, want external protocol 1.0", result.Evidence)
	}
	if result.Evidence.BinaryDigest != "" {
		t.Fatalf("binaryDigest = %q, descriptor evidence must not be labeled as a component binary", result.Evidence.BinaryDigest)
	}
	wantArtifactNames := []string{
		"uds-platformd-protocol-descriptor",
		"uds-agentd-protocol-descriptor",
		"uds-executord-protocol-descriptor",
	}
	if len(result.Evidence.ArtifactReferences) != len(wantArtifactNames) {
		t.Fatalf("artifact references = %+v, want %d", result.Evidence.ArtifactReferences, len(wantArtifactNames))
	}
	for index, artifact := range result.Evidence.ArtifactReferences {
		if artifact.Name != wantArtifactNames[index] || artifact.Digest != "sha256:"+expectedDescriptorSHA256 {
			t.Errorf("artifact %d = %+v", index, artifact)
		}
	}
}

func TestInjectedProbeFailsClosedOnInvalidProtocolEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*v1.GetCapabilitiesResponse)
	}{
		{name: "missing response", mutate: func(response *v1.GetCapabilitiesResponse) { *response = v1.GetCapabilitiesResponse{} }},
		{name: "missing metadata", mutate: func(response *v1.GetCapabilitiesResponse) { response.Meta = nil }},
		{name: "missing request ID", mutate: func(response *v1.GetCapabilitiesResponse) { response.Meta.RequestId = nil }},
		{name: "short request ID", mutate: func(response *v1.GetCapabilitiesResponse) { response.Meta.RequestId.Value = []byte{1} }},
		{name: "zero sequence", mutate: func(response *v1.GetCapabilitiesResponse) { response.Meta.ServerSequence = 0 }},
		{name: "wrong version", mutate: func(response *v1.GetCapabilitiesResponse) { response.ProtocolVersion.Minor = 1 }},
		{name: "wrong body algorithm", mutate: func(response *v1.GetCapabilitiesResponse) {
			response.DescriptorDigest.Algorithm = v1.DigestAlgorithm_DIGEST_ALGORITHM_UNSPECIFIED
		}},
		{name: "wrong body digest", mutate: func(response *v1.GetCapabilitiesResponse) { response.DescriptorDigest.Value[0] ^= 0xff }},
		{name: "wrong metadata digest", mutate: func(response *v1.GetCapabilitiesResponse) { response.Meta.DescriptorDigest.Value[0] ^= 0xff }},
		{name: "missing control capability", mutate: func(response *v1.GetCapabilitiesResponse) { response.Capabilities = response.Capabilities[1:] }},
		{name: "unavailable control capability", mutate: func(response *v1.GetCapabilitiesResponse) {
			response.Capabilities[0].Availability = v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_UNAVAILABLE
		}},
		{name: "available control capability with failure reason", mutate: func(response *v1.GetCapabilitiesResponse) {
			response.Capabilities[0].UnavailableReason = &v1.PublicError{
				Code:    v1.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Reason:  "CONTRADICTORY",
				Message: "must not accompany an available capability",
			}
		}},
		{name: "duplicate control capability", mutate: func(response *v1.GetCapabilitiesResponse) {
			response.Capabilities = append(response.Capabilities, response.Capabilities[0])
		}},
		{name: "malformed unavailable capability", mutate: func(response *v1.GetCapabilitiesResponse) {
			response.Capabilities = append(response.Capabilities, &v1.CapabilityStatus{
				Name:              "bad name",
				Availability:      v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_UNAVAILABLE,
				UnavailableReason: &v1.PublicError{},
			})
		}},
		{name: "invalid capability attributes", mutate: func(response *v1.GetCapabilitiesResponse) {
			response.Capabilities[0].Attributes = map[string]string{"bad\nkey": "value"}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			probe, err := BuildProbe(Config{
				Endpoints: testEndpoints(),
				Timeout:   time.Second,
				Query: func(_ context.Context, endpoint Endpoint) (*v1.GetCapabilitiesResponse, error) {
					response := testCapabilitiesResponse(endpoint.Name)
					test.mutate(response)
					return response, nil
				},
			})
			if err != nil {
				t.Fatalf("BuildProbe() error = %v", err)
			}
			result := probe.Run(context.Background())
			if result.Status != conformance.Fail || result.Reason != "daemon protocol evidence is invalid" {
				t.Fatalf("result = %+v, want generic FAIL", result)
			}
			assertNoSensitiveReason(t, result.Reason)
		})
	}
}

func TestInjectedProbeRequiresRoleCapabilityFromAgentdAndExecutord(t *testing.T) {
	for _, daemon := range []string{Agentd, Executord} {
		t.Run(daemon, func(t *testing.T) {
			probe, err := BuildProbe(Config{
				Endpoints: testEndpoints(),
				Timeout:   time.Second,
				Query: func(_ context.Context, endpoint Endpoint) (*v1.GetCapabilitiesResponse, error) {
					response := testCapabilitiesResponse(endpoint.Name)
					if endpoint.Name == daemon {
						response.Capabilities[1].Availability = v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_UNAVAILABLE
					}
					return response, nil
				},
			})
			if err != nil {
				t.Fatalf("BuildProbe() error = %v", err)
			}
			if result := probe.Run(context.Background()); result.Status != conformance.Fail {
				t.Fatalf("result = %+v, want FAIL", result)
			}
		})
	}
}

func TestInjectedProbeClassifiesCancellationTimeoutAndQueryFailureWithoutDetails(t *testing.T) {
	tests := []struct {
		name       string
		ctx        func() context.Context
		timeout    time.Duration
		query      Query
		wantStatus conformance.Status
		wantReason string
	}{
		{
			name: "canceled before query", ctx: canceledContext, timeout: time.Second,
			query: func(context.Context, Endpoint) (*v1.GetCapabilitiesResponse, error) {
				t.Fatal("query called after cancellation")
				return nil, nil
			},
			wantStatus: conformance.NotRun, wantReason: "daemon protocol probe canceled",
		},
		{
			name: "remote query cancellation", ctx: context.Background, timeout: time.Second,
			query: func(context.Context, Endpoint) (*v1.GetCapabilitiesResponse, error) {
				return nil, context.Canceled
			},
			wantStatus: conformance.Fail, wantReason: "daemon protocol verification failed",
		},
		{
			name: "probe timeout", ctx: context.Background, timeout: 5 * time.Millisecond,
			query: func(ctx context.Context, _ Endpoint) (*v1.GetCapabilitiesResponse, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
			wantStatus: conformance.Unavailable, wantReason: "daemon protocol probe timed out",
		},
		{
			name: "missing endpoint", ctx: context.Background, timeout: time.Second,
			query: func(context.Context, Endpoint) (*v1.GetCapabilitiesResponse, error) {
				return nil, os.ErrNotExist
			},
			wantStatus: conformance.Unavailable, wantReason: "daemon protocol endpoint is unavailable",
		},
		{
			name: "local authority contradiction", ctx: context.Background, timeout: time.Second,
			query: func(context.Context, Endpoint) (*v1.GetCapabilitiesResponse, error) {
				return nil, errors.New("secret socket path and peer details")
			},
			wantStatus: conformance.Fail, wantReason: "daemon protocol verification failed",
		},
		{
			name: "authenticated protocol mismatch", ctx: context.Background, timeout: time.Second,
			query: func(context.Context, Endpoint) (*v1.GetCapabilitiesResponse, error) {
				return nil, connect.NewError(connect.CodeDataLoss, errors.New("secret peer transcript"))
			},
			wantStatus: conformance.Fail, wantReason: "daemon protocol verification failed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			probe, err := BuildProbe(Config{Endpoints: testEndpoints(), Timeout: test.timeout, Query: test.query})
			if err != nil {
				t.Fatalf("BuildProbe() error = %v", err)
			}
			result := probe.Run(test.ctx())
			if result.Status != test.wantStatus || result.Reason != test.wantReason {
				t.Fatalf("result = %+v, want %s/%q", result, test.wantStatus, test.wantReason)
			}
			assertNoSensitiveReason(t, result.Reason)
			if result.Evidence.Class != conformance.EvidenceClassExternal || result.Evidence.ArtifactReferences == nil {
				t.Fatalf("failure evidence = %+v, want normalized external evidence", result.Evidence)
			}
		})
	}
}

func TestInjectedProbeCanRunConcurrentlyWithoutSharingMutableEvidence(t *testing.T) {
	probe, err := BuildProbe(Config{
		Endpoints: testEndpoints(),
		Timeout:   time.Second,
		Query: func(_ context.Context, endpoint Endpoint) (*v1.GetCapabilitiesResponse, error) {
			return testCapabilitiesResponse(endpoint.Name), nil
		},
	})
	if err != nil {
		t.Fatalf("BuildProbe() error = %v", err)
	}

	const runs = 16
	results := make(chan conformance.Result, runs)
	var group sync.WaitGroup
	for range runs {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- probe.Run(context.Background())
		}()
	}
	group.Wait()
	close(results)
	for result := range results {
		if result.Status != conformance.Pass {
			t.Fatalf("concurrent result = %+v, want PASS", result)
		}
		result.Evidence.ArtifactReferences[0].Name = "mutated"
	}
	final := probe.Run(context.Background())
	if final.Status != conformance.Pass || final.Evidence.ArtifactReferences[0].Name == "mutated" {
		t.Fatalf("later result reused mutable evidence: %+v", final)
	}
}

func testEndpoints() []Endpoint {
	return []Endpoint{
		{Name: Platformd, SocketPath: "/run/pi-platform/platformd.sock", ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD},
		{Name: Agentd, SocketPath: "/run/pi-platform/agentd.sock", ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_AGENTD},
		{Name: Executord, SocketPath: "/run/pi-platform/executord.sock", ExpectedServerPeer: v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD},
	}
}

func replaceEndpoint(endpoints []Endpoint, index int, replacement Endpoint) []Endpoint {
	cloned := append([]Endpoint(nil), endpoints...)
	cloned[index] = replacement
	return cloned
}

func testCapabilitiesResponse(name string) *v1.GetCapabilitiesResponse {
	digest := testDescriptorDigest()
	capabilities := []*v1.CapabilityStatus{{
		Name:         "control.protocol",
		Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
	}}
	if name != Platformd {
		capabilities = append(capabilities, &v1.CapabilityStatus{
			Name:         "daemon." + name,
			Availability: v1.CapabilityAvailability_CAPABILITY_AVAILABILITY_AVAILABLE,
		})
	}
	return &v1.GetCapabilitiesResponse{
		Meta: &v1.RpcResponseMeta{
			RequestId:        &v1.OpaqueId{Value: bytes.Repeat([]byte{0x11}, 16)},
			ServerSequence:   1,
			DescriptorDigest: testDescriptorDigest(),
		},
		Capabilities:     capabilities,
		ProtocolVersion:  &v1.ProtocolVersion{Major: 1, Minor: 0},
		DescriptorDigest: digest,
	}
}

func testDescriptorDigest() *v1.Digest {
	return &v1.Digest{
		Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256,
		Value: []byte{
			0x69, 0x3b, 0x86, 0x5c, 0xbe, 0x6e, 0xad, 0xb0,
			0xe6, 0xd4, 0x39, 0x10, 0x70, 0x7f, 0x8b, 0xd0,
			0xcd, 0xe0, 0xbd, 0x89, 0x26, 0x42, 0x48, 0x7e,
			0x51, 0x44, 0x16, 0xe8, 0xc0, 0xeb, 0xc1, 0xe0,
		},
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func assertNoSensitiveReason(t *testing.T, reason string) {
	t.Helper()
	for _, sensitive := range []string{"secret", "socket path", "peer details", "/run/"} {
		if strings.Contains(reason, sensitive) {
			t.Fatalf("reason %q exposes %q", reason, sensitive)
		}
	}
}
