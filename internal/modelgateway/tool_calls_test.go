package modelgateway

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
)

func TestCompletedResponseNormalizesMultipleToolCallsDeterministically(t *testing.T) {
	t.Parallel()
	argumentsA, err := NewCanonicalToolArguments(canonical.Map{"city": "Seoul"})
	if err != nil {
		t.Fatalf("NewCanonicalToolArguments(A) error = %v", err)
	}
	argumentsB, err := NewCanonicalToolArguments(canonical.Map{"unit": "celsius"})
	if err != nil {
		t.Fatalf("NewCanonicalToolArguments(B) error = %v", err)
	}

	t.Run("declared order", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.bounds.MaxEventBytes = 512
		fixture.bounds.MaxResponseBytes = 512
		gateway := fixture.gateway(t)
		effect := fixture.admit(t, gateway)
		effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
		effect = apply(t, gateway, effect, Event{
			ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "provider-request-1",
		}).Effect
		transition := apply(t, gateway, effect, Event{
			ExpectedRevision: effect.Revision,
			Kind:             EventResponseCompleted,
			Response: &ModelResponse{FinishReason: "tool_calls", Usage: Usage{InputTokens: 11, OutputTokens: 2}, ToolCalls: []ToolCall{
				{ID: "call-b", Name: "weather.lookup", Arguments: argumentsB, Order: ToolCallOrder{Declared: true, Index: 0}},
				{ID: "call-a", Name: "location.resolve", Arguments: argumentsA, Order: ToolCallOrder{Declared: true, Index: 1}},
			}},
		})
		calls := transition.Effect.Response.ToolCalls
		if len(calls) != 2 || calls[0].ID != "call-b" || calls[1].ID != "call-a" || calls[0].Order.Index != 0 || calls[1].Order.Index != 1 {
			t.Fatalf("normalized declared calls = %#v", calls)
		}

		encoded := calls[0].Arguments.Bytes()
		encoded[0] ^= 0xff
		if bytes.Equal(encoded, calls[0].Arguments.Bytes()) {
			t.Fatal("CanonicalToolArguments.Bytes() returned shared storage")
		}
	})

	t.Run("missing order metadata", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.bounds.MaxEventBytes = 512
		fixture.bounds.MaxResponseBytes = 512
		gateway := fixture.gateway(t)
		effect := fixture.admit(t, gateway)
		effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
		effect = apply(t, gateway, effect, Event{
			ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "provider-request-1",
		}).Effect
		transition := apply(t, gateway, effect, Event{
			ExpectedRevision: effect.Revision,
			Kind:             EventResponseCompleted,
			Response: &ModelResponse{FinishReason: "tool_calls", Usage: Usage{InputTokens: 11, OutputTokens: 2}, ToolCalls: []ToolCall{
				{ID: "call-z", Name: "weather.lookup", Arguments: argumentsB},
				{ID: "call-a", Name: "location.resolve", Arguments: argumentsA},
			}},
		})
		calls := transition.Effect.Response.ToolCalls
		if len(calls) != 2 || calls[0].ID != "call-a" || calls[1].ID != "call-z" || calls[0].Order.Declared || calls[1].Order.Declared {
			t.Fatalf("fallback-normalized calls = %#v", calls)
		}
	})
}

func TestCompletedResponseRejectsAmbiguousToolCallOrder(t *testing.T) {
	t.Parallel()
	arguments, err := NewCanonicalToolArguments(canonical.Map{"ok": true})
	if err != nil {
		t.Fatalf("NewCanonicalToolArguments() error = %v", err)
	}
	fixture := newFixture(t)
	fixture.bounds.MaxEventBytes = 512
	fixture.bounds.MaxResponseBytes = 512
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
	effect = apply(t, gateway, effect, Event{
		ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "provider-request-1",
	}).Effect

	_, err = gateway.Apply(effect, Event{
		ExpectedRevision: effect.Revision,
		Kind:             EventResponseCompleted,
		Response: &ModelResponse{FinishReason: "tool_calls", Usage: Usage{InputTokens: 11, OutputTokens: 2}, ToolCalls: []ToolCall{
			{ID: "call-a", Name: "one", Arguments: arguments, Order: ToolCallOrder{Declared: true}},
			{ID: "call-b", Name: "two", Arguments: arguments},
		}},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Apply(mixed order metadata) error = %v, want ErrInvalidRequest", err)
	}
}

func TestNormalizedProviderResponseDefensivelyCopiesToolCalls(t *testing.T) {
	t.Parallel()
	arguments, err := NewCanonicalToolArguments(canonical.Map{"city": "Seoul"})
	if err != nil {
		t.Fatalf("NewCanonicalToolArguments() error = %v", err)
	}
	wantArguments := arguments.Bytes()
	providerResponse := &ProviderResponse{
		Text: "answer", FinishReason: string(FinishReasonToolCalls),
		Usage: Usage{InputTokens: 11, OutputTokens: 2},
		ToolCalls: []ToolCall{{
			ID: "call-a", Name: "weather.lookup", Arguments: arguments,
			Order: ToolCallOrder{Declared: true, Index: 0},
		}},
	}
	fixture := newFixture(t)
	fixture.bounds.MaxEventBytes = 512
	fixture.bounds.MaxResponseBytes = 512
	fixture.provider.stream = &singleEventProviderStream{event: ProviderEvent{
		Kind: ProviderEventResponseCompleted, Response: providerResponse,
	}}
	gateway := fixture.gateway(t)
	effect := fixture.admit(t, gateway)
	begin := apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch})
	execution, err := gateway.ExecuteDispatch(context.Background(), OpaqueAuthority("owner"), begin)
	if err != nil {
		t.Fatalf("ExecuteDispatch() error = %v", err)
	}
	event, err := execution.Stream.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error = %v", err)
	}

	providerResponse.Text = "mutated"
	providerResponse.FinishReason = "mutated"
	providerResponse.Usage = Usage{}
	providerResponse.ToolCalls[0].ID = "mutated"
	providerResponse.ToolCalls[0].Name = "mutated"
	providerResponse.ToolCalls[0].Arguments.encoded[0] ^= 0xff

	if event.Response == nil || event.Response.Text != "answer" || event.Response.FinishReason != FinishReasonToolCalls ||
		event.Response.Usage != (Usage{InputTokens: 11, OutputTokens: 2}) || len(event.Response.ToolCalls) != 1 ||
		event.Response.ToolCalls[0].ID != "call-a" || event.Response.ToolCalls[0].Name != "weather.lookup" ||
		!bytes.Equal(event.Response.ToolCalls[0].Arguments.Bytes(), wantArguments) {
		t.Fatalf("normalized response changed through provider alias: %#v", event.Response)
	}
}

func TestToolCallsAndOrderBindTheTerminalSettlementDigest(t *testing.T) {
	t.Parallel()
	argumentsA, err := NewCanonicalToolArguments(canonical.Map{"value": "a"})
	if err != nil {
		t.Fatalf("NewCanonicalToolArguments(A) error = %v", err)
	}
	argumentsB, err := NewCanonicalToolArguments(canonical.Map{"value": "b"})
	if err != nil {
		t.Fatalf("NewCanonicalToolArguments(B) error = %v", err)
	}
	argumentsChanged, err := NewCanonicalToolArguments(canonical.Map{"value": "changed"})
	if err != nil {
		t.Fatalf("NewCanonicalToolArguments(changed) error = %v", err)
	}

	settlementDigest := func(t *testing.T, calls []ToolCall) Digest {
		t.Helper()
		fixture := newFixture(t)
		fixture.bounds.MaxEventBytes = 512
		fixture.bounds.MaxResponseBytes = 512
		gateway := fixture.gateway(t)
		effect := fixture.admit(t, gateway)
		effect = apply(t, gateway, effect, Event{ExpectedRevision: effect.Revision, Kind: EventBeginDispatch}).Effect
		effect = apply(t, gateway, effect, Event{
			ExpectedRevision: effect.Revision, Kind: EventProviderAccepted, ProviderRequestID: "provider-request-1",
		}).Effect
		effect = apply(t, gateway, effect, Event{
			ExpectedRevision: effect.Revision,
			Kind:             EventResponseCompleted,
			Response:         &ModelResponse{FinishReason: "tool_calls", Usage: Usage{InputTokens: 11, OutputTokens: 2}, ToolCalls: calls},
		}).Effect
		settlement, err := gateway.AuthorizeSettlement(context.Background(), effect, OpaqueAuthority("renewed"))
		if err != nil {
			t.Fatalf("AuthorizeSettlement() error = %v", err)
		}
		if len(settlement.Response.ToolCalls) != 2 {
			t.Fatalf("settled tool calls = %#v", settlement.Response.ToolCalls)
		}
		digest := fixture.authority.lastSettlement.TerminalDigest
		if settlement.QuotaReceipt.Authorization.TerminalDigest != digest {
			t.Fatalf("quota settlement digest = %x, authority digest = %x", settlement.QuotaReceipt.Authorization.TerminalDigest, digest)
		}
		return digest
	}

	base := settlementDigest(t, []ToolCall{
		{ID: "call-a", Name: "one", Arguments: argumentsA, Order: ToolCallOrder{Declared: true, Index: 0}},
		{ID: "call-b", Name: "two", Arguments: argumentsB, Order: ToolCallOrder{Declared: true, Index: 1}},
	})
	changedArguments := settlementDigest(t, []ToolCall{
		{ID: "call-a", Name: "one", Arguments: argumentsChanged, Order: ToolCallOrder{Declared: true, Index: 0}},
		{ID: "call-b", Name: "two", Arguments: argumentsB, Order: ToolCallOrder{Declared: true, Index: 1}},
	})
	changedOrder := settlementDigest(t, []ToolCall{
		{ID: "call-b", Name: "two", Arguments: argumentsB, Order: ToolCallOrder{Declared: true, Index: 0}},
		{ID: "call-a", Name: "one", Arguments: argumentsA, Order: ToolCallOrder{Declared: true, Index: 1}},
	})
	if base == changedArguments || base == changedOrder || changedArguments == changedOrder {
		t.Fatalf("terminal digests did not bind tool arguments/order: base=%x args=%x order=%x", base, changedArguments, changedOrder)
	}
}
