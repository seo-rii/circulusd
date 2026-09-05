package modelgateway

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/effectledger"
)

func TestSessionModelStarterRejectsIncompatibleLedgerCapacity(t *testing.T) {
	t.Parallel()
	fixture := newSessionDispatchTest(t, nil, nil, false)
	required := requiredSessionDispatchLedgerLimits(fixture.gateway.bounds)
	for _, test := range []struct {
		name   string
		limits effectledger.ReferenceLimits
		valid  bool
	}{
		{name: "payload one byte short", limits: effectledger.ReferenceLimits{
			MaximumPayloadBytes: required.MaximumPayloadBytes - 1, MaximumResultBytes: required.MaximumResultBytes,
		}},
		{name: "result one byte short", limits: effectledger.ReferenceLimits{
			MaximumPayloadBytes: required.MaximumPayloadBytes, MaximumResultBytes: required.MaximumResultBytes - 1,
		}},
		{name: "exact capacity", limits: required, valid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ledger, err := effectledger.NewReferenceLedger(effectledger.NewReferenceStore(), broker.ServiceModel,
				fixture.dispatch.ProviderRouteDigest, test.limits)
			if err != nil {
				t.Fatal(err)
			}
			starter, err := NewReferenceSessionDispatchStarter(fixture.gateway, ledger, fixture.dispatch.ProviderRouteDigest)
			if test.valid {
				if err != nil || starter == nil {
					t.Fatalf("compatible constructor = %v, %v", starter, err)
				}
			} else if !errors.Is(err, ErrInvalidConfiguration) || starter != nil {
				t.Fatalf("incompatible constructor = %v, %v", starter, err)
			}
		})
	}
	if _, calls := fixture.provider.snapshot(); calls != 0 {
		t.Fatalf("constructor reached provider %d times", calls)
	}
}

func TestSessionModelJSONEnvelopeBudgetsCoverMaximumMetadata(t *testing.T) {
	t.Parallel()
	fixture := newSessionDispatchTest(t, nil, nil, false)
	scope := fixture.transition.Effect.Scope
	scope.Generations = Generations{TurnLease: math.MaxUint64, Placement: math.MaxUint64, Policy: math.MaxUint64}
	quota := fixture.transition.Effect.QuotaPermit
	quota.ReservationID = "" // Variable strings are charged separately.
	quota.Durable = false
	quota.Generations = scope.Generations
	quota.ContextTokens, quota.OutputTokens = math.MaxUint64, math.MaxUint64
	var digest Digest
	for index := range digest {
		digest[index] = math.MaxUint8
	}
	quota.RequestDigest = digest
	payload := sessionDispatchPayload{
		Version: math.MaxUint64, Scope: scope, RequestDigest: digest, QuotaPermit: quota,
		Request:       ModelRequest{MaxOutputTokens: math.MaxUint64, Reasoning: ReasoningOptions{Effort: ReasoningEffortDisabled}},
		ContextTokens: math.MaxUint64, RequestedOutputTokens: math.MaxUint64,
		MaxContextTokens: math.MaxUint64, MaxTotalTokens: math.MaxUint64, MaxPreDispatchRetries: math.MaxUint32,
		State: StateDispatching, Revision: math.MaxUint64, Attempt: math.MaxUint32,
		EventCount: math.MaxUint32, EventBytes: math.MaxUint64, StreamBytes: math.MaxUint64,
	}
	result := sessionDispatchResultWire{
		Version: math.MaxUint64, State: StateCancellationPending, Outcome: OutcomeCompleted,
		Revision: math.MaxUint64, Attempt: math.MaxUint32, EventCount: math.MaxUint32,
		EventBytes: math.MaxUint64, StreamBytes: math.MaxUint64,
		Response: &sessionModelResponseWire{Usage: Usage{InputTokens: math.MaxUint64, OutputTokens: math.MaxUint64}},
	}
	for _, test := range []struct {
		name   string
		value  any
		budget int
	}{
		{name: "payload", value: payload, budget: sessionDispatchPayloadEnvelopeBytes},
		{name: "result", value: result, budget: sessionDispatchResultEnvelopeBytes},
		{name: "message", value: Message{Role: RoleAssistant}, budget: sessionDispatchMessageEnvelopeBytes},
		{name: "tool", value: sessionToolCallWire{Arguments: []byte{}, Order: ToolCallOrder{Index: math.MaxUint32}}, budget: sessionDispatchToolEnvelopeBytes},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded)+1 > test.budget { // Include a separator in repeated arrays.
				t.Fatalf("encoded metadata = %d bytes, budget = %d", len(encoded)+1, test.budget)
			}
		})
	}

	bounds := fixture.gateway.bounds
	payload.QuotaPermit.ReservationID = strings.Repeat("<", 256)
	payload.Request.Model = strings.Repeat("m", int(bounds.MaxModelBytes))
	payload.ProviderID = strings.Repeat("p", int(bounds.MaxProviderIDBytes))
	for range bounds.MaxMessages {
		payload.Request.Messages = append(payload.Request.Messages, Message{
			Role: RoleAssistant, Content: strings.Repeat("<", int(bounds.MaxInputBytes/uint64(bounds.MaxMessages))),
		})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > requiredSessionDispatchLedgerLimits(bounds).MaximumPayloadBytes {
		t.Fatalf("escaped messages and maximum quota metadata exceed payload capacity: %d bytes", len(encoded))
	}

	bounds.MaxEventBytes, bounds.MaxResponseBytes = 4096, 4096
	arguments, err := NewCanonicalToolArguments(nil)
	if err != nil {
		t.Fatal(err)
	}
	calls := make([]ToolCall, 256)
	for index := range calls {
		calls[index] = ToolCall{ID: "c" + strconv.Itoa(index), Name: "t", Arguments: arguments,
			Order: ToolCallOrder{Declared: true, Index: uint32(index)}}
		result.Response.ToolCalls = append(result.Response.ToolCalls, sessionToolCallWire{
			ID: calls[index].ID, Name: calls[index].Name, Arguments: arguments.Bytes(), Order: calls[index].Order,
		})
	}
	if _, rawBytes, err := normalizeToolCalls(calls); err != nil || rawBytes > bounds.MaxResponseBytes {
		t.Fatalf("dense tool-call fixture exceeds raw response bound: %d, %v", rawBytes, err)
	}
	result.ProviderRequestID = strings.Repeat("<", int(bounds.MaxProviderRequestIDBytes))
	result.FailureReason = strings.Repeat("<", int(bounds.MaxReasonBytes))
	encoded, err = json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > requiredSessionDispatchLedgerLimits(bounds).MaximumResultBytes {
		t.Fatalf("dense JSON tool envelopes and padded base64 arguments exceed result capacity: %d bytes", len(encoded))
	}
}

func TestSessionModelRetainsEscapedCompletionAndBase64ToolArguments(t *testing.T) {
	t.Parallel()
	arguments, err := NewCanonicalToolArguments(canonical.Map{"text": strings.Repeat("<", 200_000)})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		text  string
		calls []ToolCall
	}{
		{name: "escaped text", text: strings.Repeat("<", 200_000)},
		{name: "base64 arguments", text: "done", calls: []ToolCall{{ID: "call-a", Name: "tool-a", Arguments: arguments}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := completedSessionProviderEvent()
			event.Response.Text, event.Response.ToolCalls = test.text, test.calls
			fixture := newSessionDispatchTest(t, &scriptedSessionProviderStream{events: []ProviderEvent{event}}, nil, true)
			configuration := fixture.model.configuration()
			configuration.Bounds.MaxEventBytes, configuration.Bounds.MaxResponseBytes = 1<<20, 1<<20
			dependencies := fixture.model.dependencies()
			dependencies.Providers = map[string]Provider{"provider-a": fixture.provider}
			gateway, err := NewGateway(configuration, dependencies)
			if err != nil {
				t.Fatal(err)
			}
			if starter, err := NewReferenceSessionDispatchStarter(gateway, fixture.ledger, fixture.dispatch.ProviderRouteDigest); !errors.Is(err, ErrInvalidConfiguration) || starter != nil {
				t.Fatalf("1 MiB result cap accepted for escaped 1 MiB response bound: %v, %v", starter, err)
			}
			ledger, err := effectledger.NewReferenceLedger(effectledger.NewReferenceStore(), broker.ServiceModel,
				fixture.dispatch.ProviderRouteDigest, requiredSessionDispatchLedgerLimits(gateway.bounds))
			if err != nil {
				t.Fatal(err)
			}
			starter, err := NewReferenceSessionDispatchStarter(gateway, ledger, fixture.dispatch.ProviderRouteDigest)
			if err != nil {
				t.Fatal(err)
			}
			fixture.gateway, fixture.ledger, fixture.starter = gateway, ledger, starter
			digest, err := starter.Prepare(context.Background(), fixture.dispatch, fixture.transition)
			if err != nil {
				t.Fatal(err)
			}
			consumer, _ := fixture.consumer(t, digest)
			if _, err := consumer.StartExactAttempt(context.Background(), fixture.startRequest(digest)); err != nil {
				t.Fatal(err)
			}
			facts, err := ledger.Inspect(context.Background(), sessionLookup(fixture.dispatch))
			if err != nil || facts.State != effectledger.StateTerminal || facts.Terminal.Status != effectledger.TerminalCommitted {
				t.Fatalf("terminal facts = %v, %v", facts, err)
			}
			result, err := DecodeSessionDispatchResult(facts.Terminal.Result)
			if err != nil || result.Response == nil || result.Response.Text != test.text || !equalToolCalls(result.Response.ToolCalls, test.calls) {
				t.Fatalf("completed response did not survive ledger encoding: %v", err)
			}
			if test.name == "escaped text" && len(facts.Terminal.Result) <= 1<<20 {
				t.Fatal("regression fixture did not cross the original 1 MiB result cap")
			}
			if _, err := consumer.StartExactAttempt(context.Background(), fixture.startRequest(digest)); !errors.Is(err, broker.ErrDispatchAlreadyStarted) {
				t.Fatalf("replayed dispatch = %v", err)
			}
			if _, calls := fixture.provider.snapshot(); calls != 1 {
				t.Fatalf("provider calls = %d, want one", calls)
			}
		})
	}
}
