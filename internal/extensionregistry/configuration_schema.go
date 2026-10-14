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

// The regex callbacks of a compiled schema share one deadline for the whole
// validation, so a compiled copy serves one validation at a time. Concurrent
// validations take separate copies from a pool instead of waiting for each
// other's regex budget.
type configurationSchemaValidator struct {
	document any // the checked schema resource; never mutated after compilation
	copies   sync.Pool
}

type compiledConfigurationSchema struct {
	schema   *jsonschema.Schema
	deadline time.Time
}

func (validator *configurationSchemaValidator) Validate(value any) (err error) {
	compiled, _ := validator.copies.Get().(*compiledConfigurationSchema)
	if compiled == nil {
		// The document already compiled once at install time.
		if compiled, err = compileConfigurationSchemaCopy(validator.document); err != nil {
			return fmt.Errorf("configuration schema could not be compiled")
		}
	}
	compiled.deadline = time.Now().Add(time.Second)
	defer func() {
		compiled.deadline = time.Time{}
		if failure := recover(); failure != nil {
			if _, expected := failure.(schemaRegexBudgetFailure); !expected {
				panic(failure)
			}
			err = fmt.Errorf("configuration schema regex execution exceeded its budget")
		}
		validator.copies.Put(compiled)
	}()
	return compiled.schema.Validate(value)
}

type boundedSchemaRegexp struct {
	regexp *regexp2.Regexp
	owner  *compiledConfigurationSchema
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

func (compiled *compiledConfigurationSchema) compileRegexp(pattern string) (jsonschema.Regexp, error) {
	// regexp2 also implements .NET group extensions and accepts escapes and
	// braces that Ajv's Unicode-mode (u flag) ECMAScript parser rejects. Check
	// that syntax here before regexp2 compiles the pattern.
	groups := countCapturingGroups(pattern)
	inClass := false
	// classAtoms records the current class's atoms: 'd' for a class escape such
	// as \d, '-' for an unescaped dash and 0 for anything else.
	var classAtoms []byte
	for index := 0; index < len(pattern); index++ {
		if pattern[index] == '\\' {
			length, classEscape, err := checkUnicodeModeEscape(pattern[index+1:], inClass, groups)
			if err != nil {
				return nil, err
			}
			index += length
			if inClass {
				if classEscape {
					classAtoms = append(classAtoms, 'd')
				} else {
					classAtoms = append(classAtoms, 0)
				}
			}
			continue
		}
		if inClass {
			switch pattern[index] {
			case ']':
				for atom := 0; atom+2 < len(classAtoms); atom++ {
					if classAtoms[atom+1] == '-' {
						if classAtoms[atom] == 'd' || classAtoms[atom+2] == 'd' {
							return nil, fmt.Errorf("ECMAScript Unicode mode forbids class escapes in ranges")
						}
						atom += 2
					}
				}
				inClass = false
			case '-':
				classAtoms = append(classAtoms, '-')
			case '^':
				if len(classAtoms) > 0 || pattern[index-1] != '[' {
					classAtoms = append(classAtoms, 0)
				}
			default:
				if pattern[index] < utf8.RuneSelf || utf8.RuneStart(pattern[index]) {
					classAtoms = append(classAtoms, 0)
				}
			}
			continue
		}
		switch pattern[index] {
		case '[':
			inClass = true
			classAtoms = classAtoms[:0]
			continue
		case ']':
			return nil, fmt.Errorf("unmatched ECMAScript character-class close")
		case '{':
			// Unicode mode has no literal braces: { must start {n}, {n,} or {n,m}.
			cursor, digits := index+1, 0
			for ; cursor < len(pattern) && pattern[cursor] >= '0' && pattern[cursor] <= '9'; cursor++ {
				digits++
			}
			if digits > 0 && cursor < len(pattern) && pattern[cursor] == ',' {
				cursor++
				for cursor < len(pattern) && pattern[cursor] >= '0' && pattern[cursor] <= '9' {
					cursor++
				}
			}
			if digits == 0 || cursor >= len(pattern) || pattern[cursor] != '}' {
				return nil, fmt.Errorf("ECMAScript Unicode mode requires braces to form a quantifier")
			}
			index = cursor
			continue
		case '}':
			return nil, fmt.Errorf("ECMAScript Unicode mode requires braces to form a quantifier")
		}
		if pattern[index] != '(' || index+2 >= len(pattern) || pattern[index+1] != '?' {
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
	return &boundedSchemaRegexp{regexp: expression, owner: compiled}, nil
}

// checkUnicodeModeEscape allows only the escapes that ECMAScript accepts in
// Unicode mode. escape starts after the backslash. It returns how many bytes
// of escape the escape uses and whether it is a class escape (\d, \p{...}).
// Property names and \k group names are left to regexp2, which rejects the
// same names as ECMAScript.
func checkUnicodeModeEscape(escape string, inClass bool, groups int) (int, bool, error) {
	if escape != "" {
		character := escape[0]
		switch {
		case strings.IndexByte(`^$\.*+?()[]{}|/`, character) >= 0, character == '-' && inClass:
			return 1, false, nil
		case strings.IndexByte("dDwWsS", character) >= 0:
			return 1, true, nil
		case character == 'p' || character == 'P':
			if end := strings.IndexByte(escape, '}'); len(escape) > 1 && escape[1] == '{' && end > 2 {
				return end + 1, true, nil
			}
		case strings.IndexByte("fnrtvb", character) >= 0, character == 'B' && !inClass:
			return 1, false, nil
		case character == 'c':
			if len(escape) > 1 && (escape[1]|0x20) >= 'a' && (escape[1]|0x20) <= 'z' {
				return 2, false, nil
			}
		case character == '0':
			if len(escape) == 1 || escape[1] < '0' || escape[1] > '9' {
				return 1, false, nil
			}
		case character >= '1' && character <= '9' && !inClass:
			length := 1
			for length < len(escape) && escape[length] >= '0' && escape[length] <= '9' {
				length++
			}
			if reference, err := strconv.Atoi(escape[:length]); err == nil && reference <= groups {
				return length, false, nil
			}
		case character == 'k' && !inClass:
			if len(escape) > 1 && escape[1] == '<' {
				return 1, false, nil
			}
		case character == 'x':
			if len(escape) >= 3 {
				if _, err := strconv.ParseUint(escape[1:3], 16, 8); err == nil {
					return 3, false, nil
				}
			}
		case character == 'u':
			if len(escape) >= 5 {
				if _, err := strconv.ParseUint(escape[1:5], 16, 16); err == nil {
					return 5, false, nil
				}
			}
			if end := strings.IndexByte(escape, '}'); len(escape) > 1 && escape[1] == '{' && end > 2 {
				if value, err := strconv.ParseUint(escape[2:end], 16, 32); err == nil && value <= utf8.MaxRune {
					return end + 1, false, nil
				}
			}
		}
	}
	return 0, false, fmt.Errorf("unsupported escape in ECMAScript Unicode mode")
}

// countCapturingGroups counts numbered and named capturing groups, which
// decimal backreferences may name in any position.
func countCapturingGroups(pattern string) int {
	groups, inClass := 0, false
	for index := 0; index < len(pattern); index++ {
		switch {
		case pattern[index] == '\\':
			index++
		case inClass:
			inClass = pattern[index] != ']'
		case pattern[index] == '[':
			inClass = true
		case pattern[index] == '(':
			rest := pattern[index+1:]
			if !strings.HasPrefix(rest, "?") || (strings.HasPrefix(rest, "?<") && !strings.HasPrefix(rest, "?<=") && !strings.HasPrefix(rest, "?<!")) {
				groups++
			}
		}
	}
	return groups
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
	compiled, err := compileConfigurationSchemaCopy(value)
	if err != nil {
		return nil, err
	}
	validator := &configurationSchemaValidator{document: value}
	validator.copies.Put(compiled)
	return validator, nil
}

// compileConfigurationSchemaCopy compiles a checked schema document into a
// copy whose regex callbacks use only that copy's deadline.
func compileConfigurationSchemaCopy(document any) (*compiledConfigurationSchema, error) {
	compiled := &compiledConfigurationSchema{}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(offlineExtensionSchemaLoader{})
	compiler.UseRegexpEngine(compiled.compileRegexp)
	const local = "https://circulusd.invalid/extension-configuration.schema.json"
	if err := compiler.AddResource(local, document); err != nil {
		return nil, err
	}
	schema, err := compiler.Compile(local)
	if err != nil {
		return nil, err
	}
	compiled.schema = schema
	return compiled, nil
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
