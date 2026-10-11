package issuance

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
)

// DecodeStrict rejects duplicate keys, aliases accepted by encoding/json,
// omitted fields, nulls and unknown members throughout a bounded typed input.
func DecodeStrict(encoded []byte, destination any) error {
	if len(encoded) == 0 || len(encoded) > MaximumReportBytes {
		return ErrInvalidReport
	}
	d := json.NewDecoder(bytes.NewReader(encoded))
	d.UseNumber()
	var parse func(int) (any, error)
	parse = func(depth int) (any, error) {
		if depth > 16 {
			return nil, ErrInvalidReport
		}
		token, err := d.Token()
		if err != nil || token == nil {
			return nil, ErrInvalidReport
		}
		delim, container := token.(json.Delim)
		if !container {
			return token, nil
		}
		switch delim {
		case '{':
			values := make(map[string]any)
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, ErrInvalidReport
				}
				name, ok := key.(string)
				if !ok {
					return nil, ErrInvalidReport
				}
				if _, exists := values[name]; exists {
					return nil, ErrInvalidReport
				}
				v, err := parse(depth + 1)
				if err != nil {
					return nil, err
				}
				values[name] = v
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, ErrInvalidReport
			}
			return values, nil
		case '[':
			values := make([]any, 0)
			for d.More() {
				v, err := parse(depth + 1)
				if err != nil {
					return nil, err
				}
				values = append(values, v)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, ErrInvalidReport
			}
			return values, nil
		default:
			return nil, ErrInvalidReport
		}
	}
	actual, err := parse(0)
	if err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalidReport
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidReport
	}
	typed, err := json.Marshal(destination)
	if err != nil {
		return ErrInvalidReport
	}
	var expected any
	canonicalDecoder := json.NewDecoder(bytes.NewReader(typed))
	canonicalDecoder.UseNumber()
	if canonicalDecoder.Decode(&expected) != nil || !reflect.DeepEqual(actual, expected) {
		return ErrInvalidReport
	}
	return nil
}
