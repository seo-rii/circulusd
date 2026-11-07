package mcpgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/modelgateway"
)

func TestNativeHTTPProviderRestoresCanonicalToolNumbers(t *testing.T) {
	arguments, err := modelgateway.NewCanonicalToolArguments(canonical.Map{
		"scale": 1.25, "nested": canonical.Array{0.1, 1e30, int64(7), "1.25"},
	})
	if err != nil {
		t.Fatal(err)
	}
	input, err := canonical.Decode(arguments.Bytes(), canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	want, err := arguments.ProviderJSON()
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan json.RawMessage, 1)
	server := nativeHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rpc, err := decodeMCPMessage(body)
		if err != nil {
			t.Error(err)
			return
		}
		var params struct {
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(rpc.Params, &params); err != nil {
			t.Error(err)
		}
		received <- bytes.Clone(params.Arguments)
		r.Body = io.NopCloser(bytes.NewReader(body))
		nativeHTTPResult(w, r)
	})
	fixture := newNativeHTTPFixture(t, server.URL)
	call := CallRequest{ServerID: fixture.effect.ServerID, ToolName: fixture.effect.ToolName, Input: input}
	encoded, digest, err := canonicalizeCall(call, fixture.configuration.Bounds)
	if err != nil {
		t.Fatal(err)
	}
	fixture.effect.InputCanonical, fixture.effect.RequestDigest, fixture.grant.RequestDigest = encoded, digest, digest
	_, command, _ := prepareNativeHTTPCommand(t, fixture)
	result, err := fixture.factory.providers[fixture.effect.ProviderID].Start(context.Background(), command)
	if err != nil || result.Call == nil {
		t.Fatalf("start: %v", err)
	}
	defer result.Call.Close(context.Background())
	got := <-received
	if !bytes.Equal(got, want) {
		t.Fatalf("MCP arguments = %s, want provider JSON %s", got, want)
	}
	if !bytes.Equal(command.InputCanonical, arguments.Bytes()) {
		t.Fatal("outbound conversion changed the canonical request")
	}
}

func TestNativeHTTPProviderRejectsMalformedNumberWrappersBeforeDispatch(t *testing.T) {
	for _, value := range []canonical.Value{
		canonical.Map{"$pi.number.v1": "1.250"},
		canonical.Map{"$pi.number.v1": "1"},
		canonical.Map{"$pi.number.v1": "NaN"},
		canonical.Map{"$pi.number.v1": "1.25", "extra": true},
		canonical.Bytes("not JSON"),
	} {
		encoded, err := canonical.Encode(canonical.Map{"value": value}, canonical.DefaultOptions())
		if err != nil {
			t.Fatal(err)
		}
		provider := &nativeHTTPProvider{}
		if _, err := provider.Start(context.Background(), ProviderCommand{InputCanonical: encoded}); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("malformed arguments reached provider authority: %v", err)
		}
	}
	encoded, err := canonical.Encode(canonical.Map{"$pi.number.v1": "1.25"}, canonical.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&nativeHTTPProvider{}).Start(context.Background(), ProviderCommand{InputCanonical: encoded}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("numeric arguments root reached provider authority: %v", err)
	}
}
