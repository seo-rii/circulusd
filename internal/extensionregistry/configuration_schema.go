package extensionregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/dlclark/regexp2/v2"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const extensionConfigurationDialect = "https://json-schema.org/draft/2020-12/schema"

type schemaRegexBudgetFailure struct{}

// The shared regex callbacks need one deadline for the whole validation. The
// mutex keeps each call's budget separate, including concurrent compilations.
type configurationSchemaValidator struct {
	schema   *jsonschema.Schema
	mu       sync.Mutex
	deadline time.Time
}

func (validator *configurationSchemaValidator) Validate(value any) (err error) {
	validator.mu.Lock()
	defer validator.mu.Unlock()
	validator.deadline = time.Now().Add(time.Second)
	defer func() {
		validator.deadline = time.Time{}
		if failure := recover(); failure != nil {
			if _, expected := failure.(schemaRegexBudgetFailure); !expected {
				panic(failure)
			}
			err = fmt.Errorf("configuration schema regex execution exceeded its budget")
		}
	}()
	return validator.schema.Validate(value)
}

type boundedSchemaRegexp struct {
	regexp *regexp2.Regexp
	owner  *configurationSchemaValidator
}

func (expression *boundedSchemaRegexp) String() string { return expression.regexp.String() }

func (expression *boundedSchemaRegexp) MatchString(value string) bool {
	if !expression.owner.deadline.IsZero() && time.Now().After(expression.owner.deadline) {
		panic(schemaRegexBudgetFailure{})
	}
	matched, err := expression.regexp.MatchString(value)
	// A plain false would be inverted into success by not/oneOf. Any regex
	// execution error must abort the ENTIRE validator with a sanitized error.
	if err != nil || (!expression.owner.deadline.IsZero() && time.Now().After(expression.owner.deadline)) {
		panic(schemaRegexBudgetFailure{})
	}
	return matched
}

func (validator *configurationSchemaValidator) compileRegexp(pattern string) (jsonschema.Regexp, error) {
	// regexp2 also implements .NET group extensions. Those constructs are not
	// valid ECMAScript patterns, even when its ECMAScript matching flag is set.
	inClass := false
	for index := 0; index < len(pattern); index++ {
		if pattern[index] == '\\' {
			index++
			if index < len(pattern) && strings.ContainsRune("AGZz", rune(pattern[index])) {
				return nil, fmt.Errorf("unsupported non-ECMAScript anchor escape")
			}
			continue
		}
		if pattern[index] == '[' {
			inClass = true
			continue
		}
		if pattern[index] == ']' {
			if !inClass {
				return nil, fmt.Errorf("unmatched ECMAScript character-class close")
			}
			inClass = false
			continue
		}
		if inClass || pattern[index] != '(' || index+2 >= len(pattern) || pattern[index+1] != '?' {
			continue
		}
		switch pattern[index+2] {
		case ':', '=', '!', '<':
			// ECMAScript non-capturing, lookaround, and named capture groups.
		case 'i', 'm', 's', '-':
			// Current ECMAScript supports modifier GROUPS (?i:a), but never
			// .NET option-only groups (?i) or x/n/etc flags.
			seen, minus, flags, closed := map[byte]bool{}, false, 0, false
			for cursor := index + 2; cursor < len(pattern); cursor++ {
				character := pattern[cursor]
				if character == ':' {
					closed = flags > 0 && pattern[cursor-1] != '-'
					break
				}
				if character == '-' && !minus {
					minus = true
					continue
				}
				if !strings.ContainsRune("ims", rune(character)) || seen[character] {
					break
				}
				seen[character] = true
				flags++
			}
			if !closed {
				return nil, fmt.Errorf("unsupported non-ECMAScript modifier syntax")
			}
		default:
			return nil, fmt.Errorf("unsupported non-ECMAScript group syntax")
		}
	}
	expression, err := regexp2.Compile(pattern, regexp2.ECMAScript|regexp2.Unicode, regexp2.OptionMaxBacktrackingStackSize(200_000))
	if err != nil {
		return nil, err
	}
	expression.MatchTimeout = 100 * time.Millisecond
	return &boundedSchemaRegexp{regexp: expression, owner: validator}, nil
}

// encoding/json replaces escaped lone surrogates with U+FFFD. The TS JSON
// boundary rejects them, so validate escapes before that information is lost.
func validateSchemaUnicodeEscapes(raw []byte) error {
	inString := false
	for index := 0; index < len(raw); index++ {
		if raw[index] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[index] != '\\' {
			continue
		}
		index++
		if index >= len(raw) {
			return fmt.Errorf("invalid JSON escape")
		}
		if raw[index] != 'u' {
			continue
		}
		if index+4 >= len(raw) {
			return fmt.Errorf("invalid JSON Unicode escape")
		}
		code, err := strconv.ParseUint(string(raw[index+1:index+5]), 16, 16)
		if err != nil {
			return fmt.Errorf("invalid JSON Unicode escape")
		}
		index += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return fmt.Errorf("JSON text must contain Unicode scalar values")
		}
		if code >= 0xd800 && code <= 0xdbff {
			if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
				return fmt.Errorf("JSON text must contain Unicode scalar values")
			}
			next, err := strconv.ParseUint(string(raw[index+3:index+7]), 16, 16)
			if err != nil || next < 0xdc00 || next > 0xdfff {
				return fmt.Errorf("JSON text must contain Unicode scalar values")
			}
			index += 6
		}
	}
	return nil
}

type offlineExtensionSchemaLoader struct{}

func (offlineExtensionSchemaLoader) Load(string) (any, error) {
	return nil, fmt.Errorf("extension schema loading is offline and local fragments only")
}

func configurationSchemaDigest(bytes []byte) string {
	digest := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func compileConfigurationSchema(raw []byte) (*configurationSchemaValidator, error) {
	if len(raw) == 0 || len(raw) > 262_144 || !utf8.Valid(raw) {
		return nil, fmt.Errorf("configuration schema must be bounded UTF-8 JSON")
	}
	if err := validateSchemaUnicodeEscapes(raw); err != nil {
		return nil, err
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("configuration schema must contain valid JSON")
	}
	if _, object := value.(map[string]any); !object {
		return nil, fmt.Errorf("configuration schema root must be an object")
	}
	normalized, _, err := normalizeExtensionJSON(value)
	if err != nil {
		return nil, err
	}
	value = extensionJSONInstance(normalized)
	var check func(any) error
	check = func(value any) error {
		if _, boolean := value.(bool); boolean {
			return nil
		}
		object, valid := value.(map[string]any)
		if !valid {
			return fmt.Errorf("schema must be an object or boolean")
		}
		if dialect, present := object["$schema"]; present && dialect != extensionConfigurationDialect {
			return fmt.Errorf("extension schemas require JSON Schema draft 2020-12")
		}
		if _, present := object["$vocabulary"]; present {
			return fmt.Errorf("extension schemas cannot override the pinned dialect vocabulary")
		}
		for _, name := range []string{"$ref", "$dynamicRef"} {
			if raw, present := object[name]; present {
				ref, text := raw.(string)
				if !text || !strings.HasPrefix(ref, "#") {
					return fmt.Errorf("extension schema references must be local fragments")
				}
			}
		}
		for _, name := range []string{"$defs", "definitions", "properties", "patternProperties", "dependentSchemas"} {
			if children, valid := object[name].(map[string]any); valid {
				for _, child := range children {
					if err := check(child); err != nil {
						return err
					}
				}
			}
		}
		for _, name := range []string{"allOf", "anyOf", "oneOf", "prefixItems"} {
			if children, valid := object[name].([]any); valid {
				for _, child := range children {
					if err := check(child); err != nil {
						return err
					}
				}
			}
		}
		for _, name := range []string{"additionalProperties", "unevaluatedProperties", "items", "unevaluatedItems", "contains", "propertyNames", "not", "if", "then", "else"} {
			if child, present := object[name]; present {
				if err := check(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := check(value); err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	validator := &configurationSchemaValidator{}
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(offlineExtensionSchemaLoader{})
	compiler.UseRegexpEngine(validator.compileRegexp)
	const local = "https://circulusd.invalid/extension-configuration.schema.json"
	if err := compiler.AddResource(local, value); err != nil {
		return nil, err
	}
	validator.schema, err = compiler.Compile(local)
	return validator, err
}

func extensionJSONInstance(value canonical.Value) any {
	switch current := value.(type) {
	case canonical.Array:
		output := make([]any, len(current))
		for index, item := range current {
			output[index] = extensionJSONInstance(item)
		}
		return output
	case canonical.Map:
		output := make(map[string]any, len(current))
		for key, item := range current {
			output[key] = extensionJSONInstance(item)
		}
		return output
	default:
		return current
	}
}
