package modelgateway

import (
	"fmt"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/pijson"
)

const piNumberWrapperKey = pijson.NumberWrapperKey

func decodeToolArgumentJSON(encoded []byte) (canonical.Value, error) {
	if len(encoded) == 0 || len(encoded) > hardMaxEventBytes {
		return nil, ErrInvalidRequest
	}
	options := canonical.DefaultOptions()
	options.MaxBytes = hardMaxEventBytes
	value, err := canonical.Decode(encoded, options)
	if err != nil {
		return nil, fmt.Errorf("%w: tool arguments are not canonical CBOR", ErrInvalidRequest)
	}
	return transformToolArgumentJSON(value, true)
}

func transformToolArgumentJSON(value canonical.Value, decode bool) (canonical.Value, error) {
	options := canonical.DefaultOptions()
	options.MaxBytes = hardMaxEventBytes
	var result canonical.Value
	var err error
	if decode {
		result, err = pijson.DecodeValue(value, options)
	} else {
		result, err = pijson.EncodeValue(value, options)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	return result, nil
}
