package extensionregistry

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hancomac/circulusd/internal/canonical"
)

func TestRegistryRequiresBoundSignedValidOfflineConfigurationSchemas(t *testing.T) {
	t.Parallel()
	for _, schema := range []string{
		`{"type":"invalid"}`,
		`{"type":"object","required":"temperature"}`,
		`{"$ref":"#/$defs/missing"}`,
		`{"$ref":"https://example.invalid/schema.json"}`,
		`{"$ref":"other.schema.json"}`,
		`{"$schema":"http://json-schema.org/draft-07/schema#","type":"object"}`,
		`{"$vocabulary":{"https://example.invalid/custom":true}}`,
		`{"type":"object","description":"\ud800"}`,
		`{"type":"object","description":"\udc00"}`,
		`{"type":"object","properties":{"value":{"pattern":"(?i)^a$"}}}`,
		`{"type":"object","properties":{"value":{"pattern":"(?>a)"}}}`,
		`{"type":"object","properties":{"value":{"pattern":"(?(1)a|b)"}}}`,
		`{"type":"object","properties":{"value":{"pattern":"\\A"}}}`,
		`{"type":"object","properties":{"value":{"pattern":"\\G"}}}`,
		`{"type":"object","properties":{"value":{"pattern":"\\Z"}}}`,
		`{"type":"object","properties":{"value":{"pattern":"\\z"}}}`,
		`{"type":"object","properties":{"value":{"pattern":"[a-z-[aeiou]]"}}}`,
	} {
		fixture := newFixture(t)
		record := cloneSignedRevision(fixture.pdf)
		record.Revision.ConfigurationSchema = []byte(schema)
		record.Revision.ConfigurationSchemaDigest = configurationSchemaDigest(record.Revision.ConfigurationSchema)
		record = fixture.signRecord(t, record.Revision, record.Assessment)
		if _, err := New(fixture.roots, []SignedRevision{record}, fixture.resolver); !errors.Is(err, ErrInvalidRecord) {
			t.Fatalf("schema %s: install error=%v, want ErrInvalidRecord", schema, err)
		}
	}
	fixture := newFixture(t)
	for _, raw := range [][]byte{nil, []byte(`{"type":"string"}`)} {
		record := cloneSignedRevision(fixture.pdf)
		record.Revision.ConfigurationSchema = raw
		if _, err := New(fixture.roots, []SignedRevision{record}, fixture.resolver); !errors.Is(err, ErrInvalidRecord) {
			t.Fatalf("missing or mismatched signed schema error=%v", err)
		}
	}
}

func TestNativeSchemaUsesECMAScriptUnicodeRegexSemantics(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		pattern string
		valid   string
		invalid string
	}{
		{`^(?=a)a$`, "a", "b"},
		{`^a$`, "a", "a\n"},
		{`^\u{1F600}$`, "😀", "a"},
		{`^(?i:a)$`, "A", "b"},
		{`^\(\?>a\)$`, "(?>a)", "b"},
		{`^[-[]$`, "[", "b"},
	} {
		raw, err := json.Marshal(map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"type": "string", "pattern": test.pattern}}})
		if err != nil {
			t.Fatal(err)
		}
		schema, err := compileConfigurationSchema(raw)
		if err != nil {
			t.Fatalf("ECMAScript pattern rejected: %v", err)
		}
		if err := schema.Validate(map[string]any{"value": test.valid}); err != nil {
			t.Fatalf("ECMAScript matching value rejected: %v", err)
		}
		if err := schema.Validate(map[string]any{"value": test.invalid}); err == nil {
			t.Fatal("ECMAScript non-matching value accepted")
		}
	}
}

// Ajv compiles "pattern" with new RegExp(pattern, "u"). Each expectation below
// was checked against Node 24.1. The rejected patterns are ones regexp2 accepted
// before this check.
func TestSchemaPatternsUseECMAScriptUnicodeModeSyntax(t *testing.T) {
	t.Parallel()
	compile := func(pattern string) error {
		raw, err := json.Marshal(map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"type": "string", "pattern": pattern}}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = compileConfigurationSchema(raw)
		return err
	}
	for _, pattern := range []string{
		// Identity escapes outside SyntaxCharacter and "/" are errors.
		`\R`, `\a`, `\e`, `\Q`, `\E`, `\K`, `\h`, `\H`, `\V`, `\N`, `\X`, `\i`, `\g`, `\-`, `\_`, `\"`, `\ `, `\#`,
		`\c`, `\c1`, `\c_`, `\00`, `\01`, `\8`, `\x4`, `\xGG`, `\x{41}`, `\u004`,
		// Backreferences must name an existing group.
		`\1`, `(a)\2`, `(a)\10`,
		// Class escapes are restricted inside a class and cannot bound a range.
		`[\R]`, `[\a]`, `[\e]`, `[\B]`, `[\1]`, `[\8]`, `[\k]`, `[\c1]`, `[\c_]`, `[\_]`, `[\ ]`, `[\00]`, `[\01]`, `[\q{a}]`,
		`[\d-z]`, `[a-\d]`, `[\s-\S]`, `[\d-\d]`, `[\W-a]`, `[a-\s]`, `[\p{L}-z]`,
		// Braces are only quantifiers.
		`x{,3}`, `x{3`, `x{ }`, `a{,}`, `a{`, `a}`, `x{1,2`, `{`, `}`,
	} {
		if err := compile(pattern); err == nil {
			t.Errorf("pattern %q compiled, but ECMAScript Unicode mode rejects it", pattern)
		}
	}
	for _, pattern := range []string{
		`\/`, `\.`, `\^\$\\\*\+\?\(\)\[\]\{\}\|`, `\d\D\w\W\s\S\b\B`, `\f\n\r\t\v`, `\cz`, `\0`, `\x41`, `\u0041`, `\u{1F600}`, `\uD83D\uDE00`,
		`(a)\1`, `\1(a)`, `(a)|\1`, `(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)\10`, `(?<a>x)\k<a>`, `\k<a>(?<a>x)`,
		`\p{L}`, `\P{L}`, `\p{Lu}`, `\p{Script=Latin}`, `\p{gc=Lu}`, `[\p{L}-]`, `[-\p{L}]`,
		`[\-]`, `[\b-\n]`, `[a\-z]`, `[\/]`, `[\0]`, `[\cz]`, `[\w-]`, `[-\w]`, `[^\d]`, `[a-b-c]`, `[\x41-\x5a]`, `[\u{1F600}-\u{1F64F}]`, `[{}]`,
		`a{0}`, `a{01}`, `a{1,1}`, `a{2,}`, `a{1,2}?`, `(?:a){2}`, `(?<=ab)c`, `(?<!a+)b`,
	} {
		if err := compile(pattern); err != nil {
			t.Errorf("pattern %q rejected, but ECMAScript Unicode mode accepts it: %v", pattern, err)
		}
	}
}

func TestSchemaRegexFailureCannotBecomeSuccessThroughNegationOrOneOf(t *testing.T) {
	t.Parallel()
	for _, constraint := range []string{
		`{"not":{"pattern":"^(a+)+$"}}`,
		`{"oneOf":[{"pattern":"^(a+)+$"},{"type":"string"}]}`,
	} {
		schema, err := compileConfigurationSchema([]byte(`{"type":"object","properties":{"value":` + constraint + `}}`))
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		if err := schema.Validate(map[string]any{"value": strings.Repeat("a", 4_000) + "!"}); err == nil || err.Error() != "configuration schema regex execution exceeded its budget" {
			t.Fatalf("regex timeout became a schema result: %v", err)
		}
		if time.Since(started) > 2*time.Second {
			t.Fatal("regex failure exceeded its bounded lifetime")
		}
		var pending sync.WaitGroup
		for range 8 {
			pending.Go(func() {
				if err := schema.Validate(map[string]any{"value": "b"}); err != nil {
					t.Errorf("earlier budget failure poisoned a later/concurrent validation: %v", err)
				}
			})
		}
		pending.Wait()
	}
}

// Each validation has its own regex budget. Concurrent validations of one
// schema must not queue behind each other's budget: sixteen validations that
// each run into the 100 ms regex timeout take at least 1.6 s one at a time,
// and about one timeout when they run side by side.
func TestConcurrentSchemaValidationsDoNotWaitForEachOthersRegexBudget(t *testing.T) {
	t.Parallel()
	schema, err := compileConfigurationSchema([]byte(`{"type":"object","properties":{"value":{"pattern":"^(a+)+$"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	pathological := map[string]any{"value": strings.Repeat("a", 4_000) + "!"}
	started := time.Now()
	var pending sync.WaitGroup
	for range 16 {
		pending.Go(func() {
			if err := schema.Validate(pathological); err == nil || err.Error() != "configuration schema regex execution exceeded its budget" {
				t.Errorf("Validate() error = %v, want the regex budget failure", err)
			}
		})
	}
	pending.Wait()
	if elapsed := time.Since(started); elapsed >= 1600*time.Millisecond {
		t.Fatalf("16 concurrent validations took %v; they ran one at a time", elapsed)
	}
	if err := schema.Validate(map[string]any{"value": "aaa"}); err != nil {
		t.Fatalf("Validate(after concurrent budget failures) error = %v", err)
	}
}

func TestRuntimeValidatesCompleteConfigurationAgainstImmutableSignedSchema(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	record := cloneSignedRevision(fixture.pdf)
	record.Revision.ConfigurationSchema = []byte(`{
		"$schema":"https://json-schema.org/draft/2020-12/schema",
		"type":"object","required":["temperature","apiProfile"],"additionalProperties":false,
		"$defs":{"temperature":{"type":"number","minimum":0,"maximum":2}},
		"properties":{"temperature":{"$ref":"#/$defs/temperature"},"prefix":{"enum":[""]},"apiProfile":{"type":"string"}}
	}`)
	record.Revision.ConfigurationSchemaDigest = configurationSchemaDigest(record.Revision.ConfigurationSchema)
	record = fixture.signRecord(t, record.Revision, record.Assessment)
	registry := fixture.registry(t, []SignedRevision{record, fixture.python})
	// Mutation after install cannot replace the validator or its signed source.
	for index := range record.Revision.ConfigurationSchema {
		record.Revision.ConfigurationSchema[index] = ' '
	}
	valid := canonical.Map{"temperature": 0.5, "prefix": "", "apiProfile": "local"}
	request := fixture.compileRequest()
	request.Configuration["official/pdf"] = valid
	runtime, err := registry.CompileRuntime(request)
	if err != nil || runtime.ConfigurationDigest == "" {
		t.Fatalf("CompileRuntime(finite decimal/empty final config) = %#v, %v", runtime, err)
	}
	for _, configuration := range []canonical.Value{
		canonical.Map{"temperature": 0.5}, // partial defaults are not a final snapshot
		canonical.Map{"temperature": "hot", "apiProfile": "local"},
		canonical.Map{"temperature": 3, "apiProfile": "local"},
		canonical.Map{"temperature": 0.5, "apiProfile": "local", "unexpected": true},
		canonical.Map{"temperature": 0.5, "apiProfile": "local", "prefix": "not-empty"},
	} {
		request.Configuration["official/pdf"] = configuration
		if _, err := registry.CompileRuntime(request); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("CompileRuntime(schema-violating final override) error=%v, want ErrInvalidRequest", err)
		}
	}
	request.Configuration["official/pdf"] = valid
	again, err := registry.CompileRuntime(request)
	if err != nil || again.Digest != runtime.Digest {
		t.Fatalf("valid final config failed after rejected overrides: %v", err)
	}
}

func TestRuntimeKeepsOriginalOneOfAndConditionalFinalConstraints(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		schema  string
		valid   canonical.Map
		invalid canonical.Map
	}{
		{"oneOf", `{"type":"object","oneOf":[{"required":["left"],"properties":{"left":{"type":"number"}}},{"required":["right"],"properties":{"right":{"type":"number"}}}]}`,
			canonical.Map{"left": 0.5}, canonical.Map{"left": 0.5, "right": 0.5}},
		{"conditional", `{"type":"object","required":["mode"],"properties":{"temperature":{"type":"number"}},"if":{"required":["mode"],"properties":{"mode":{"const":"strict"}}},"then":{"properties":{"temperature":{"maximum":1}}},"else":{"properties":{"temperature":{"maximum":10}}}}`,
			canonical.Map{"mode": "relaxed", "temperature": int64(5)}, canonical.Map{"mode": "strict", "temperature": int64(5)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			record := cloneSignedRevision(fixture.pdf)
			record.Revision.ConfigurationSchema = []byte(test.schema)
			record.Revision.ConfigurationSchemaDigest = configurationSchemaDigest(record.Revision.ConfigurationSchema)
			record = fixture.signRecord(t, record.Revision, record.Assessment)
			registry := fixture.registry(t, []SignedRevision{record, fixture.python})
			request := fixture.compileRequest()
			request.Configuration["official/pdf"] = test.valid
			if _, err := registry.CompileRuntime(request); err != nil {
				t.Fatalf("valid final configuration rejected: %v", err)
			}
			request.Configuration["official/pdf"] = test.invalid
			if _, err := registry.CompileRuntime(request); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("invalid final original-schema constraint: %v", err)
			}
		})
	}
}
