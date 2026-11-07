package providerresult

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	proof "github.com/hancomac/circulusd/internal/dependency/contracttest"
	"github.com/hancomac/circulusd/internal/effectledger"
	"github.com/hancomac/circulusd/internal/identity"
	"github.com/hancomac/circulusd/internal/mcpgateway"
	"github.com/hancomac/circulusd/internal/modelgateway"
	"github.com/hancomac/circulusd/internal/stateappbroker"
	"github.com/hancomac/circulusd/internal/stateappclient"
)

type committedRecordsFixture struct {
	*proof.ProductionProofs
	record     CommittedRecord
	readError  error
	probeError error
	onRead     func(context.Context)
	reads      atomic.Int32
	probes     atomic.Int32
}

func (source *committedRecordsFixture) ProbeProduction(ctx context.Context, challenge dependency.ProbeChallenge) (dependency.ProbeResponse, error) {
	source.probes.Add(1)
	if source.probeError != nil {
		return dependency.ProbeResponse{}, source.probeError
	}
	return source.ProductionProofs.ProbeProduction(ctx, challenge)
}

func (source *committedRecordsFixture) ReadCommittedResult(ctx context.Context, request stateappbroker.ResultRequest) (CommittedRecord, error) {
	source.reads.Add(1)
	if source.onRead != nil {
		source.onRead(ctx)
	}
	if source.readError != nil {
		return CommittedRecord{}, source.readError
	}
	// Deliberately return shared slices: the resolver must own the copy that it
	// returns without relying on a friendly test reader to copy it beforehand.
	return source.record, nil
}

func recordsFixture(t *testing.T, name string, enableMCP bool) (*committedRecordsFixture, *RecordResolver) {
	t.Helper()
	groups := []dependency.AtomicGroup{dependency.AtomicEffectLifecycle}
	p := proof.NewProductionProofs(t, groups)
	body := recordsPiBody(t, name)
	source := &committedRecordsFixture{ProductionProofs: p, record: CommittedRecord{
		Request: requestFixture(t), Status: effectledger.TerminalCommitted, CanonicalCBOR: body,
		PayloadDigest: broker.Digest(sha256.Sum256(body)),
	}}
	if name == "tool_result" {
		source.record.Service = broker.ServiceMCP
		source.record.LedgerResult = recordsMCPLedger(t, body)
	} else {
		source.record.Service = broker.ServiceModel
		source.record.LedgerResult = recordsModelLedger(t, body)
	}
	config := RecordResolverConfig{}
	if enableMCP {
		bounds := recordsMCPBounds()
		config.MCPBounds = &bounds
	}
	resolver, err := NewRecordResolver(proof.Verify[Records](t, p, source, groups), config)
	if err != nil {
		t.Fatal(err)
	}
	return source, resolver
}

func TestRecordResolverChecksActualPiModelAndToolBodies(t *testing.T) {
	for _, name := range []string{"model_tool_call", "model_final", "tool_result"} {
		t.Run(name, func(t *testing.T) {
			source, resolver := recordsFixture(t, name, name == "tool_result")
			binding := proof.Verify[stateappbroker.ResultResolver](t, source.ProductionProofs, resolver, []dependency.AtomicGroup{dependency.AtomicEffectLifecycle})
			operational, _, err := binding.Open()
			if err != nil || source.probes.Load() != 2 {
				t.Fatalf("records and resolver did not receive independent probes: %v", err)
			}
			result, err := operational.ResolveResult(context.Background(), source.record.Request)
			if err != nil || result.Request != source.record.Request || result.PayloadDigest != source.record.PayloadDigest || !bytes.Equal(result.CanonicalCBOR, source.record.CanonicalCBOR) {
				t.Fatalf("actual Pi body or immutable identity changed: %v", err)
			}
			result.CanonicalCBOR[0] ^= 0xff
			again, err := operational.ResolveResult(context.Background(), source.record.Request)
			if err != nil || !bytes.Equal(again.CanonicalCBOR, source.record.CanonicalCBOR) {
				t.Fatal("returned result aliases immutable source storage")
			}
		})
	}
}

func TestRecordResolverRequiresQualifiedSameOperationalRecordsAndPolicy(t *testing.T) {
	if _, err := NewRecordResolver(dependency.Verified[Records]{}, RecordResolverConfig{}); !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatal("unsealed reader accepted")
	}
	p := proof.NewProductionProofs(t, []dependency.AtomicGroup{dependency.AtomicCommandReceipt})
	source := &committedRecordsFixture{ProductionProofs: p}
	sealed := proof.Verify[Records](t, p, source, []dependency.AtomicGroup{dependency.AtomicCommandReceipt})
	if _, err := NewRecordResolver(sealed, RecordResolverConfig{}); !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatal("reader without independently attested effect-lifecycle accepted")
	}
	source, _ = recordsFixture(t, "tool_result", true)
	sealed = proof.Verify[Records](t, source.ProductionProofs, source, []dependency.AtomicGroup{dependency.AtomicEffectLifecycle})
	for _, edit := range []func(*mcpgateway.Bounds){
		func(b *mcpgateway.Bounds) { *b = mcpgateway.Bounds{} },
		func(b *mcpgateway.Bounds) { b.MaxOutputBytes = 0 },
		func(b *mcpgateway.Bounds) { b.MaxInputDepth = 1000 },
		func(b *mcpgateway.Bounds) { b.MaxChunkBytes = b.MaxOutputBytes + 1 },
		func(b *mcpgateway.Bounds) { b.CancelTimeout = time.Hour },
	} {
		bounds := recordsMCPBounds()
		edit(&bounds)
		if _, err := NewRecordResolver(sealed, RecordResolverConfig{MCPBounds: &bounds}); !errors.Is(err, dependency.ErrInvalidConfiguration) {
			t.Fatal("invalid MCP policy accepted")
		}
	}
	bounds := recordsMCPBounds()
	resolver, err := NewRecordResolver(sealed, RecordResolverConfig{MCPBounds: &bounds})
	if err != nil {
		t.Fatal(err)
	}
	bounds = mcpgateway.Bounds{}
	if _, err := resolver.ResolveResult(context.Background(), source.record.Request); err != nil {
		t.Fatal("caller mutation changed retained MCP bounds")
	}
	source, resolver = recordsFixture(t, "tool_result", false)
	if _, err := resolver.ResolveResult(context.Background(), source.record.Request); !errors.Is(err, ErrUnsupportedService) {
		t.Fatal("nil MCP policy enabled a generic fallback")
	}
}

func TestRecordResolverRejectsEveryChangedIdentityBeforeReturningBody(t *testing.T) {
	for _, field := range []string{"tenant", "workspace", "session", "effect", "invocation", "request digest", "external commit", "result ref"} {
		t.Run(field, func(t *testing.T) {
			source, resolver := recordsFixture(t, "model_final", false)
			request := source.record.Request
			switch field {
			case "tenant":
				source.record.Request.TenantID = tid(t, identity.Tenant, 2)
			case "workspace":
				source.record.Request.WorkspaceID = tid(t, identity.Workspace, 2)
			case "session":
				source.record.Request.SessionID = tid(t, identity.Session, 2)
			case "effect":
				source.record.Request.EffectID = tid(t, identity.Effect, 2)
			case "invocation":
				source.record.Request.InvocationID = tid(t, identity.Invocation, 2)
			case "request digest":
				source.record.Request.RequestDigest = broker.Digest{2}
			case "external commit":
				source.record.Request.ExternalCommitID = tid(t, identity.Commit, 2)
			case "result ref":
				source.record.Request.ResultRef = tid(t, identity.Artifact, 2)
			}
			// Wrong identity must win even if the provider body is invalid.
			source.record.CanonicalCBOR = nil
			if result, err := resolver.ResolveResult(context.Background(), request); result.CanonicalCBOR != nil || !errors.Is(err, broker.ErrFenceMismatch) {
				t.Fatalf("wrong immutable identity returned a result: %v", err)
			}
		})
	}
}

func TestRecordResolverRejectsIncompleteAndUncorrelatedRecords(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*CommittedRecord)
		want error
	}{
		{"failed", func(r *CommittedRecord) { r.Status = effectledger.TerminalFailed }, broker.ErrInvalidEffectState},
		{"unknown", func(r *CommittedRecord) { r.Status = effectledger.TerminalUnknown }, broker.ErrInvalidEffectState},
		{"no status", func(r *CommittedRecord) { r.Status = "" }, broker.ErrInvalidEffectState},
		{"unsupported service", func(r *CommittedRecord) { r.Service = broker.ServiceWorkspace }, ErrUnsupportedService},
		{"no ledger", func(r *CommittedRecord) { r.LedgerResult = nil }, stateappclient.ErrInvalidResponse},
		{"oversized ledger", func(r *CommittedRecord) { r.LedgerResult = make([]byte, MaximumCommittedLedgerResultBytes+1) }, stateappclient.ErrInvalidResponse},
		{"oversized body", func(r *CommittedRecord) { r.CanonicalCBOR = make([]byte, stateappclient.MaximumProviderResultBytes+1) }, stateappclient.ErrInvalidResponse},
		{"digest mismatch", func(r *CommittedRecord) { r.PayloadDigest = broker.Digest{9} }, stateappclient.ErrInvalidResponse},
		{"wrong ledger", func(r *CommittedRecord) { r.LedgerResult = []byte(`{"ok":true}`) }, stateappclient.ErrInvalidResponse},
		{"uncorrelated text", func(r *CommittedRecord) {
			value := recordsDecode(t, r.CanonicalCBOR)
			value["message"].(canonical.Map)["content"] = canonical.Array{canonical.Map{"type": "text", "text": "different response"}}
			recordsReplaceBody(t, r, value)
		}, stateappclient.ErrInvalidResponse},
		{"invalid cost", func(r *CommittedRecord) {
			value := recordsDecode(t, r.CanonicalCBOR)
			value["message"].(canonical.Map)["usage"].(canonical.Map)["cost"].(canonical.Map)["input"] = "0.000001250"
			recordsReplaceBody(t, r, value)
		}, stateappclient.ErrInvalidResponse},
		{"missing model", func(r *CommittedRecord) {
			value := recordsDecode(t, r.CanonicalCBOR)
			delete(value["message"].(canonical.Map), "model")
			recordsReplaceBody(t, r, value)
		}, stateappclient.ErrInvalidResponse},
		{"noncanonical body", func(r *CommittedRecord) {
			r.CanonicalCBOR = []byte{0x18, 0}
			r.PayloadDigest = broker.Digest(sha256.Sum256(r.CanonicalCBOR))
		}, stateappclient.ErrInvalidResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, resolver := recordsFixture(t, "model_final", false)
			test.edit(&source.record)
			if result, err := resolver.ResolveResult(context.Background(), source.record.Request); result.CanonicalCBOR != nil || !errors.Is(err, test.want) {
				t.Fatalf("invalid committed record accepted: %v, want %v", err, test.want)
			}
		})
	}
	source, resolver := recordsFixture(t, "tool_result", true)
	source.record.LedgerResult = recordsMCPLedger(t, []byte(`{"ok":true}`))
	if result, err := resolver.ResolveResult(context.Background(), source.record.Request); result.CanonicalCBOR != nil || !errors.Is(err, stateappclient.ErrInvalidResponse) {
		t.Fatal("generic MCP output converted into an unretained Pi body")
	}
}

func TestRecordResolverRejectsInvalidContextAndRequestBeforeRead(t *testing.T) {
	source, resolver := recordsFixture(t, "model_final", false)
	request := source.record.Request
	if _, err := resolver.ResolveResult(nil, request); !errors.Is(err, broker.ErrInvalidRequest) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.ResolveResult(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	request.ResultRef = identity.ID{}
	if _, err := resolver.ResolveResult(context.Background(), request); !errors.Is(err, broker.ErrInvalidRequest) {
		t.Fatal(err)
	}
	if source.reads.Load() != 0 {
		t.Fatal("invalid context/reference reached record storage")
	}
	var zero *RecordResolver
	if _, err := zero.ResolveResult(context.Background(), source.record.Request); !errors.Is(err, dependency.ErrUnverifiedDependency) {
		t.Fatal("zero resolver served a record")
	}
	ctx, cancel = context.WithCancel(context.Background())
	source.onRead = func(context.Context) { cancel() }
	if result, err := resolver.ResolveResult(ctx, source.record.Request); result.CanonicalCBOR != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled read returned cached/late result")
	}
}

func TestRecordResolverSanitizesReadAndProbeDiagnostics(t *testing.T) {
	for _, target := range []string{"read", "probe"} {
		for _, underlying := range []error{errors.New("secret provider diagnostic"), stateappclient.ErrClientClosed, context.Canceled} {
			t.Run(target+"/"+underlying.Error(), func(t *testing.T) {
				source, resolver := recordsFixture(t, "model_final", false)
				err := fmt.Errorf("secret implementation details: %w", underlying)
				if target == "read" {
					source.readError = err
					_, err = resolver.ResolveResult(context.Background(), source.record.Request)
				} else {
					source.probeError = err
					_, err = resolver.ProbeProduction(context.Background(), dependency.ProbeChallenge{Nonce: bytes.Repeat([]byte{1}, dependency.ChallengeBytes)})
				}
				if err == nil || strings.Contains(err.Error(), "secret") {
					t.Fatal("qualified record diagnostics escaped")
				}
				want := underlying
				if targetError := underlying; targetError != stateappclient.ErrClientClosed && targetError != context.Canceled {
					want = stateappclient.ErrTransport
				}
				if !errors.Is(err, want) {
					t.Fatalf("lost fixed lifecycle class: %v", err)
				}
			})
		}
	}
}

func TestRecordResolverKeepsFixedRecordClasses(t *testing.T) {
	for _, underlying := range []error{ErrRecordUnavailable, ErrRecordConflict, broker.ErrFenceMismatch} {
		t.Run(underlying.Error(), func(t *testing.T) {
			source, resolver := recordsFixture(t, "model_final", false)
			source.readError = fmt.Errorf("secret implementation details: %w", underlying)
			if _, err := resolver.ResolveResult(context.Background(), source.record.Request); err != underlying {
				t.Fatalf("ResolveResult() error = %v, want only %v", err, underlying)
			}
		})
	}
}

func TestQualifiedRecordResolverNormalizesBeforeNativeHTTPResultRead(t *testing.T) {
	for _, name := range []string{"model_tool_call", "tool_result"} {
		t.Run(name, func(t *testing.T) {
			source, resolver := recordsFixture(t, name, name == "tool_result")
			groups := []dependency.AtomicGroup{dependency.AtomicEffectLifecycle}
			sealed := proof.Verify[stateappbroker.ResultResolver](t, source.ProductionProofs, resolver, groups)
			root := bytes.Repeat([]byte{9}, 32)
			handler, err := NewServer(ServerConfig{Source: sealed, KeyID: "provider-record-read", RootKey: root, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(handler)
			t.Cleanup(server.Close)
			client, err := stateappclient.New(stateappclient.Config{Endpoint: server.URL, KeyID: "provider-record-read", RootKey: root, Timeout: time.Second})
			clear(root)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.Close)
			reader := proof.Verify[Reader](t, source.ProductionProofs, client, groups)
			remoteResolver, err := New(reader)
			if err != nil {
				t.Fatal(err)
			}
			remote := proof.Verify[stateappbroker.ResultResolver](t, source.ProductionProofs, remoteResolver, groups)
			operational, _, err := remote.Open()
			if err != nil || source.probes.Load() != 4 {
				t.Fatalf("same operational records must answer four fresh independent challenges: %v", err)
			}
			result, err := operational.ResolveResult(context.Background(), source.record.Request)
			if err != nil || !bytes.Equal(result.CanonicalCBOR, source.record.CanonicalCBOR) || result.PayloadDigest != source.record.PayloadDigest {
				t.Fatalf("qualified native HTTP path did not retain Pi result: %v", err)
			}
			// Preserve a valid canonical body and its authenticated SHA while
			// breaking its terminal correlation. Server/client CBOR checks alone
			// would accept this; the record resolver's normalizer must reject it.
			if name == "tool_result" {
				source.record.LedgerResult = recordsMCPLedger(t, []byte(`{"ok":true}`))
			} else {
				value := recordsDecode(t, source.record.CanonicalCBOR)
				value["message"].(canonical.Map)["usage"].(canonical.Map)["cost"].(canonical.Map)["total"] = "0.000003750"
				recordsReplaceBody(t, &source.record, value)
			}
			if result, err := operational.ResolveResult(context.Background(), source.record.Request); result.CanonicalCBOR != nil || !errors.Is(err, stateappclient.ErrRemote) {
				t.Fatalf("normalizer did not reject invalid committed result before signing HTTP response: %v", err)
			}
		})
	}
}

func recordsReplaceBody(t *testing.T, record *CommittedRecord, value canonical.Value) {
	t.Helper()
	body, err := canonical.Encode(value, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	record.CanonicalCBOR, record.PayloadDigest = body, broker.Digest(sha256.Sum256(body))
}

func recordsDecode(t *testing.T, body []byte) canonical.Map {
	t.Helper()
	value, err := canonical.Decode(body, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	return value.(canonical.Map)
}

func recordsMCPBounds() mcpgateway.Bounds {
	return mcpgateway.Bounds{MaxAuthorityBytes: 1024, MaxServerIDBytes: 128, MaxToolNameBytes: 128,
		MaxTargetRefBytes: 256, MaxProtocolVersionBytes: 64, MaxCredentialHandleBytes: 256, MaxAudienceBytes: 128,
		MaxInputBytes: 4096, MaxInputDepth: 16, MaxProviderRequestIDBytes: 256, MaxExternalCommitIDBytes: 256,
		MaxChunkBytes: 1024, MaxChunks: 32, MaxOutputBytes: stateappclient.MaximumProviderResultBytes,
		MaxFailureBytes: 512, MaxEvents: 128, CancelTimeout: time.Second}
}

func recordsMCPLedger(t *testing.T, body []byte) []byte {
	t.Helper()
	encoded, err := canonical.Encode(canonical.Map{"version": int64(1), "output": canonical.Bytes(body), "externalCommitId": "provider-record-commit"}, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func recordsModelLedger(t *testing.T, body []byte) []byte {
	t.Helper()
	// Match the existing Session terminal encoder's JSON wire, including the
	// original canonical tool argument bytes. This is fixture data only; it
	// deliberately does not create a production record-store implementation.
	type tool struct {
		ID, Name  string
		Arguments []byte
		Order     modelgateway.ToolCallOrder
	}
	type response struct {
		Text         string
		FinishReason modelgateway.FinishReason
		Usage        modelgateway.Usage
		ToolCalls    []tool
	}
	message := recordsDecode(t, body)["message"].(canonical.Map)
	r := &response{Usage: modelgateway.Usage{InputTokens: 1000, OutputTokens: 2000}, ToolCalls: []tool{}}
	for _, value := range message["content"].(canonical.Array) {
		block := value.(canonical.Map)
		if block["type"] == "text" {
			r.Text += block["text"].(string)
		} else if block["type"] == "toolCall" {
			arguments, err := canonical.Encode(block["arguments"], canonical.DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			r.ToolCalls = append(r.ToolCalls, tool{ID: block["id"].(string), Name: block["name"].(string), Arguments: arguments,
				Order: modelgateway.ToolCallOrder{Declared: true, Index: uint32(len(r.ToolCalls))}})
		}
	}
	if message["stopReason"] == "toolUse" {
		r.FinishReason = modelgateway.FinishReasonToolCalls
	} else {
		r.FinishReason = modelgateway.FinishReasonStop
	}
	const requestID = "provider-record-request"
	eventBytes := uint64(len(requestID) + len(r.Text) + len(r.FinishReason))
	for _, call := range r.ToolCalls {
		eventBytes += uint64(len(call.ID) + len(call.Name) + len(call.Arguments) + 9)
	}
	wire := struct {
		Version           uint64
		State             modelgateway.State
		Outcome           modelgateway.Outcome
		Revision          uint64
		Attempt           uint32
		EventCount        uint32
		EventBytes        uint64
		StreamBytes       uint64
		ProviderRequestID string
		PartialOutput     bool
		FailureReason     string
		Response          *response
	}{Version: 1, State: modelgateway.StateCompleted, Outcome: modelgateway.OutcomeCompleted,
		Revision: 4, Attempt: 1, EventCount: 3, EventBytes: eventBytes, ProviderRequestID: requestID, Response: r}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func recordsPiBody(t *testing.T, name string) []byte {
	t.Helper()
	encoded, err := os.ReadFile("../../packages/protocol-types/fixtures/stateapp-pi-codec-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version     int
		Settlements []struct{ Name, PayloadHex string }
	}
	if err := json.Unmarshal(encoded, &fixture); err != nil || fixture.Version != 1 {
		t.Fatalf("invalid actual Pi fixture: %v", err)
	}
	for _, item := range fixture.Settlements {
		if item.Name == name {
			body, err := hex.DecodeString(item.PayloadHex)
			if err != nil {
				t.Fatal(err)
			}
			return body
		}
	}
	t.Fatalf("missing actual Pi fixture: %s", name)
	return nil
}
