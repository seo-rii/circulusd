package modelgateway

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hancomac/circulusd/internal/broker"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/effectledger"
)

type piJSONNumberFixture struct {
	Version    int    `json:"version"`
	WrapperKey string `json:"wrapperKey"`
	Numbers    []struct {
		Name    string          `json:"name"`
		BitsHex string          `json:"bitsHex"`
		Decimal string          `json:"decimal"`
		Encoded json.RawMessage `json:"encoded"`
		CBORHex string          `json:"cborHex"`
	} `json:"numbers"`
	InvalidWrappers []struct {
		Name  string          `json:"name"`
		Value json.RawMessage `json:"value"`
	} `json:"invalidWrappers"`
	InvalidRaw []struct {
		Name  string          `json:"name"`
		Value json.RawMessage `json:"value"`
	} `json:"invalidRaw"`
	InvalidNumbers []struct {
		Name    string `json:"name"`
		BitsHex string `json:"bitsHex"`
	} `json:"invalidNumbers"`
}

func readPiJSONNumberFixture(t *testing.T) piJSONNumberFixture {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "..", "packages", "protocol-types", "fixtures", "pi-json-numbers-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture piJSONNumberFixture
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 || fixture.WrapperKey != piNumberWrapperKey || len(fixture.Numbers) < 20 {
		t.Fatal("invalid or incomplete Pi JSON number fixture")
	}
	return fixture
}

func TestFractionalToolArgumentsMatchSharedBinary64Vectors(t *testing.T) {
	fixture := readPiJSONNumberFixture(t)
	for _, vector := range fixture.Numbers {
		t.Run(vector.Name, func(t *testing.T) {
			bits, err := strconv.ParseUint(vector.BitsHex, 16, 64)
			if err != nil {
				t.Fatal(err)
			}
			arguments, err := NewCanonicalToolArguments(math.Float64frombits(bits))
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(arguments.Bytes()); got != vector.CBORHex {
				t.Fatalf("canonical CBOR = %s, want shared %s", got, vector.CBORHex)
			}
			var encodedValue any
			if err := json.Unmarshal(vector.Encoded, &encodedValue); err != nil {
				t.Fatal(err)
			}
			fixtureBytes, err := canonical.Encode(fixtureProtocolValue(t, encodedValue), canonical.DefaultOptions())
			if err != nil || !bytes.Equal(fixtureBytes, arguments.Bytes()) {
				t.Fatalf("fixture encoded value and CBOR disagree: %v", err)
			}
			restored, err := ParseCanonicalToolArguments(arguments.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			providerJSON, err := restored.ProviderJSON()
			if err != nil || string(providerJSON) != vector.Decimal {
				t.Fatalf("provider JSON = %s, %v; want ECMAScript %s", providerJSON, err, vector.Decimal)
			}
			var number float64
			if err := json.Unmarshal(providerJSON, &number); err != nil || math.Float64bits(number) != bits {
				t.Fatalf("provider number changed binary64 bits: got %016x, want %016x (%v)", math.Float64bits(number), bits, err)
			}
		})
	}
}

func TestFractionalToolArgumentsRejectSharedInvalidVectors(t *testing.T) {
	fixture := readPiJSONNumberFixture(t)
	for _, vector := range fixture.InvalidWrappers {
		t.Run(vector.Name, func(t *testing.T) {
			var value any
			if err := json.Unmarshal(vector.Value, &value); err != nil {
				t.Fatal(err)
			}
			encoded, err := canonical.Encode(fixtureProtocolValue(t, value), canonical.DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseCanonicalToolArguments(encoded); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("ParseCanonicalToolArguments(invalid wrapper) = %v", err)
			}
			// Even internally forged values must be refused before a caller can
			// obtain JSON for provider execution.
			forged := CanonicalToolArguments{encoded: encoded}
			if value, err := forged.ProviderJSON(); value != nil || !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("forged ProviderJSON() = %s, %v", value, err)
			}
		})
	}
	for _, vector := range fixture.InvalidRaw {
		t.Run(vector.Name, func(t *testing.T) {
			var value any
			if err := json.Unmarshal(vector.Value, &value); err != nil {
				t.Fatal(err)
			}
			if _, err := NewCanonicalToolArguments(value); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("NewCanonicalToolArguments(raw collision) = %v", err)
			}
		})
	}
	for _, vector := range fixture.InvalidNumbers {
		t.Run(vector.Name, func(t *testing.T) {
			bits, err := strconv.ParseUint(vector.BitsHex, 16, 64)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewCanonicalToolArguments(math.Float64frombits(bits)); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("NewCanonicalToolArguments(invalid number) = %v", err)
			}
		})
	}
}

func TestToolArgumentJSONPreservesIntegerOnlyCanonicalBytes(t *testing.T) {
	for _, value := range []canonical.Value{
		nil, true, "cafe\u0301", int64(0), uint64(maxCanonicalInteger), -int64(maxCanonicalInteger),
		canonical.Map{"count": 42, "nested": canonical.Array{int8(-3), uint16(8), false, nil}},
		canonical.Map{"e\u0301": canonical.Map{"other": "value"}},
	} {
		want, err := canonical.Encode(value, canonical.DefaultOptions())
		if err != nil {
			t.Fatal(err)
		}
		arguments, err := NewCanonicalToolArguments(value)
		if err != nil || !bytes.Equal(arguments.Bytes(), want) {
			t.Fatalf("integer-only JSON changed its canonical representation: %v", err)
		}
	}
	if _, err := canonical.Encode(canonical.Map{"fraction": 0.1}, canonical.DefaultOptions()); err == nil {
		t.Fatal("shared canonical encoder must remain integer-only")
	}
}

func TestToolArgumentJSONBoundsAndRejectsNonJSONTypes(t *testing.T) {
	cyclicMap := canonical.Map{}
	cyclicMap["self"] = cyclicMap
	cyclicArray := canonical.Array{nil}
	cyclicArray[0] = cyclicArray
	for _, value := range []canonical.Value{
		canonical.Bytes{1}, []byte{1}, canonical.Map{"nested": canonical.Bytes{1}},
		json.RawMessage(`{"x":1}`), json.Number("0.1"), &struct{ X int }{1},
		int64(maxCanonicalInteger) + 1, uint64(maxCanonicalInteger) + 1,
		string([]byte{0xff}), toolJSONForbiddenMarshaler{}, cyclicMap, cyclicArray,
		strings.Repeat("x", hardMaxEventBytes+1), make(canonical.Array, canonical.DefaultOptions().MaxItems),
	} {
		if _, err := NewCanonicalToolArguments(value); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("unsupported or unbounded %T arguments error = %v", value, err)
		}
	}
	for _, encoded := range [][]byte{
		{}, {0x18, 0x01}, {0xa2, 0x61, 'b', 0x01, 0x61, 'a', 0x02},
		{0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0}, {0x41, 0x01}, {0x00, 0x00},
	} {
		if _, err := ParseCanonicalToolArguments(encoded); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid canonical JSON CBOR %x error = %v", encoded, err)
		}
	}
}

type toolJSONForbiddenMarshaler struct{}

func (toolJSONForbiddenMarshaler) MarshalJSON() ([]byte, error) {
	panic("custom argument marshaler must not execute")
}

func TestFractionalArgumentsSurviveSessionProviderAndDurableRecovery(t *testing.T) {
	arguments, err := NewCanonicalToolArguments(map[string]any{
		"temperature": 0.1, "steps": float64(3),
		"nested": []any{math.SmallestNonzeroFloat64, -1.25},
	})
	if err != nil {
		t.Fatal(err)
	}
	event := completedSessionProviderEvent()
	event.Response.FinishReason = "tool_calls"
	event.Response.ToolCalls = []ToolCall{{ID: "call-a", Name: "temperature.set", Arguments: arguments}}
	fixture := newSessionDispatchTest(t, &scriptedSessionProviderStream{events: []ProviderEvent{event}}, nil, true)
	configuration := fixture.model.configuration()
	configuration.Bounds.MaxEventBytes, configuration.Bounds.MaxResponseBytes = 512, 512
	dependencies := fixture.model.dependencies()
	dependencies.Providers = map[string]Provider{"provider-a": fixture.provider}
	gateway, err := NewGateway(configuration, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	starter, err := NewReferenceSessionDispatchStarter(gateway, fixture.ledger, fixture.dispatch.ProviderRouteDigest)
	if err != nil {
		t.Fatal(err)
	}
	fixture.gateway, fixture.starter = gateway, starter
	commandDigest, err := fixture.starter.Prepare(context.Background(), fixture.dispatch, fixture.transition)
	if err != nil {
		t.Fatal(err)
	}
	consumer, _ := fixture.consumer(t, commandDigest)
	if _, err := consumer.StartExactAttempt(context.Background(), fixture.startRequest(commandDigest)); err != nil {
		t.Fatal(err)
	}
	facts, err := fixture.ledger.Inspect(context.Background(), sessionLookup(fixture.dispatch))
	if err != nil || facts.State != effectledger.StateTerminal || facts.Terminal.Status != effectledger.TerminalCommitted {
		t.Fatalf("fractional provider result state=%v terminal=%v error=%v", facts.State, facts.Terminal.Status, err)
	}
	result, err := DecodeSessionDispatchResult(facts.Terminal.Result)
	if err != nil || result.Response == nil || len(result.Response.ToolCalls) != 1 {
		t.Fatalf("decode durable fractional provider result: %v", err)
	}
	if !bytes.Equal(result.Response.ToolCalls[0].Arguments.Bytes(), arguments.Bytes()) {
		t.Fatal("durable recovery changed canonical tool argument bytes")
	}
	providerJSON, err := result.Response.ToolCalls[0].Arguments.ProviderJSON()
	if err != nil {
		t.Fatal(err)
	}
	var toolRequest struct {
		Temperature float64   `json:"temperature"`
		Steps       int       `json:"steps"`
		Nested      []float64 `json:"nested"`
	}
	if err := json.Unmarshal(providerJSON, &toolRequest); err != nil ||
		math.Float64bits(toolRequest.Temperature) != math.Float64bits(0.1) || toolRequest.Steps != 3 ||
		len(toolRequest.Nested) != 2 || math.Float64bits(toolRequest.Nested[0]) != 1 || toolRequest.Nested[1] != -1.25 {
		t.Fatalf("typed provider request did not restore actual numbers: %#v, %v", toolRequest, err)
	}
	if _, err := consumer.StartExactAttempt(context.Background(), fixture.startRequest(commandDigest)); !errors.Is(err, broker.ErrDispatchAlreadyStarted) {
		t.Fatalf("durable result recovery permitted repeated model dispatch: %v", err)
	}
	if _, calls := fixture.provider.snapshot(); calls != 1 {
		t.Fatalf("provider calls = %d, want one", calls)
	}

	var wire sessionDispatchResultWire
	if err := json.Unmarshal(facts.Terminal.Result, &wire); err != nil {
		t.Fatal(err)
	}
	malformed, err := canonical.Encode(canonical.Map{piNumberWrapperKey: "0.10"}, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	wire.Response.ToolCalls[0].Arguments = malformed
	forged, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSessionDispatchResult(forged); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("durable malformed wrapper reached provider JSON boundary: %v", err)
	}
}

func fixtureProtocolValue(t *testing.T, value any) canonical.Value {
	t.Helper()
	switch value := value.(type) {
	case nil, bool, string:
		return value
	case float64:
		if math.Trunc(value) != value || math.Abs(value) > float64(maxCanonicalInteger) {
			t.Fatal("fixture contains a noncanonical native number")
		}
		return int64(value)
	case []any:
		result := make(canonical.Array, len(value))
		for index, entry := range value {
			result[index] = fixtureProtocolValue(t, entry)
		}
		return result
	case map[string]any:
		result := make(canonical.Map, len(value))
		for key, entry := range value {
			result[key] = fixtureProtocolValue(t, entry)
		}
		return result
	default:
		t.Fatalf("unsupported fixture type %T", value)
		return nil
	}
}

func TestToolArgumentJSONRejectsTextThatXTextNormalizesIncorrectly(t *testing.T) {
	for _, value := range []canonical.Value{
		"\u00e1" + strings.Repeat("\u0301", 30),
		canonical.Map{"\U00010041" + strings.Repeat("\u0301", 31): int64(1)},
		canonical.Array{"\u00e1" + strings.Repeat("\u0301", 30)},
		"a" + strings.Repeat("\u0301", 31),
	} {
		if arguments, err := NewCanonicalToolArguments(value); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("NewCanonicalToolArguments(%+q) = %x, %v, want ErrInvalidRequest", value, arguments.Bytes(), err)
		}
	}
}
