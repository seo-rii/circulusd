// Package strictjson decodes data documents without duplicate members or
// encoding/json's case-insensitive aliases for struct field names.
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// Decode reads exactly one JSON value into destination. Struct fields must use
// their exact JSON tag (or exact Go name if untagged); map keys remain data.
// Schemas use ordinary fields, structs, maps, slices and pointers. Untagged
// embedded fields are unsupported. Callers must bound input size and perform
// any domain-specific string and value validation separately.
func Decode(encoded []byte, destination any) error {
	target := reflect.ValueOf(destination)
	if target.Kind() != reflect.Pointer || target.IsNil() {
		return fmt.Errorf("JSON destination must be a non-nil pointer")
	}
	scanner := validator{
		decoder: json.NewDecoder(bytes.NewReader(encoded)),
		fields:  make(map[reflect.Type]map[string]reflect.Type),
	}
	scanner.decoder.UseNumber()
	if err := scanner.value(target.Type().Elem(), 0); err != nil {
		return err
	}
	if _, err := scanner.decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination)
}

type validator struct {
	decoder *json.Decoder
	fields  map[reflect.Type]map[string]reflect.Type
}

func (v *validator) value(schema reflect.Type, depth int) error {
	if depth > 64 {
		return fmt.Errorf("JSON maximum depth 64 exceeded")
	}
	for schema != nil && schema.Kind() == reflect.Pointer {
		schema = schema.Elem()
	}
	token, err := v.decoder.Token()
	if err != nil {
		return err
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return nil // The final Decode checks scalar types and ranges.
	}
	switch delimiter {
	case '{':
		var fields map[string]reflect.Type
		var element reflect.Type
		if schema != nil {
			switch schema.Kind() {
			case reflect.Struct:
				fields, err = v.structFields(schema)
				if err != nil {
					return err
				}
			case reflect.Map:
				element = schema.Elem()
			}
		}
		keys := make(map[string]struct{})
		for v.decoder.More() {
			token, err := v.decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return fmt.Errorf("JSON object key is not a string")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate JSON member %q", key)
			}
			keys[key] = struct{}{}
			child := element
			if fields != nil {
				child, ok = fields[key]
				if !ok {
					return fmt.Errorf("unknown JSON member %q", key)
				}
			}
			if err := v.value(child, depth+1); err != nil {
				return err
			}
		}
		closing, err := v.decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("incomplete JSON object")
		}
	case '[':
		var element reflect.Type
		if schema != nil && (schema.Kind() == reflect.Array || schema.Kind() == reflect.Slice) {
			element = schema.Elem()
		}
		for v.decoder.More() {
			if err := v.value(element, depth+1); err != nil {
				return err
			}
		}
		closing, err := v.decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("incomplete JSON array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	return nil
}

func (v *validator) structFields(schema reflect.Type) (map[string]reflect.Type, error) {
	if fields, ok := v.fields[schema]; ok {
		return fields, nil
	}
	fields := make(map[string]reflect.Type)
	for index := 0; index < schema.NumField(); index++ {
		field := schema.Field(index)
		if !field.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			if field.Anonymous {
				return nil, fmt.Errorf("JSON schema has an untagged embedded field %s", field.Name)
			}
			name = field.Name
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, fmt.Errorf("JSON schema has duplicate field %q", name)
		}
		fields[name] = field.Type
	}
	v.fields[schema] = fields
	return fields, nil
}
