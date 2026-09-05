// This local JSONL probe is test data, so go test ./... and production builds do
// not include it. The Node differential harness invokes both real CBOR codecs.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/hancomac/circulusd/internal/canonical"
)

type wireValue struct {
	Kind    string      `json:"kind"`
	Boolean bool        `json:"boolean"`
	Integer int64       `json:"integer"`
	Text    string      `json:"text"`
	Hex     string      `json:"hex"`
	Items   []wireValue `json:"items"`
	Entries []wireEntry `json:"entries"`
}

type wireEntry struct {
	Key   string    `json:"key"`
	Value wireValue `json:"value"`
}

type request struct {
	Operation string    `json:"operation"`
	Value     wireValue `json:"value"`
	Hex       string    `json:"hex"`
	Options   struct {
		MaxDepth int `json:"maxDepth"`
		MaxBytes int `json:"maxBytes"`
		MaxItems int `json:"maxItems"`
	} `json:"options"`
}

type response struct {
	Accepted       bool   `json:"accepted"`
	CanonicalHex   string `json:"canonicalHex,omitempty"`
	CodecError     string `json:"codecError,omitempty"`
	InvariantError string `json:"invariantError,omitempty"`
	RequestError   string `json:"requestError,omitempty"`
}

func (value wireValue) materialize() (canonical.Value, error) {
	switch value.Kind {
	case "null":
		return nil, nil
	case "boolean":
		return value.Boolean, nil
	case "integer":
		return value.Integer, nil
	case "text":
		return value.Text, nil
	case "bytes":
		decoded, err := hex.DecodeString(value.Hex)
		return canonical.Bytes(decoded), err
	case "array":
		result := make(canonical.Array, len(value.Items))
		for index, item := range value.Items {
			converted, err := item.materialize()
			if err != nil {
				return nil, err
			}
			result[index] = converted
		}
		return result, nil
	case "map":
		result := make(canonical.Map, len(value.Entries))
		for _, entry := range value.Entries {
			if _, exists := result[entry.Key]; exists {
				return nil, errors.New("wire map contains a duplicate key")
			}
			converted, err := entry.Value.materialize()
			if err != nil {
				return nil, err
			}
			result[entry.Key] = converted
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unknown wire value kind %q", value.Kind)
	}
}

func evaluate(input request) response {
	options := canonical.Options{
		MaxDepth: input.Options.MaxDepth, MaxBytes: input.Options.MaxBytes, MaxItems: input.Options.MaxItems,
	}
	var value canonical.Value
	var encoded []byte
	var err error
	switch input.Operation {
	case "value":
		value, err = input.Value.materialize()
		if err != nil {
			return response{RequestError: err.Error()}
		}
		encoded, err = canonical.Encode(value, options)
	case "bytes":
		encoded, err = hex.DecodeString(input.Hex)
		if err != nil {
			return response{RequestError: err.Error()}
		}
		value, err = canonical.Decode(encoded, options)
	default:
		return response{RequestError: "unknown operation"}
	}
	if err != nil {
		return response{CodecError: err.Error()}
	}
	decoded, err := canonical.Decode(encoded, options)
	if err != nil {
		return response{Accepted: true, InvariantError: "accepted value cannot decode: " + err.Error()}
	}
	reencoded, err := canonical.Encode(decoded, options)
	if err != nil {
		return response{Accepted: true, InvariantError: "accepted value cannot encode: " + err.Error()}
	}
	if hex.EncodeToString(reencoded) != hex.EncodeToString(encoded) {
		return response{Accepted: true, InvariantError: "accepted bytes differ after round trip"}
	}
	return response{Accepted: true, CanonicalHex: hex.EncodeToString(encoded)}
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 128<<10)
	output := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var input request
		var result response
		if err := json.Unmarshal(scanner.Bytes(), &input); err != nil {
			result.RequestError = err.Error()
		} else {
			result = evaluate(input)
		}
		if err := output.Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
