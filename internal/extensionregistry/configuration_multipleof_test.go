package extensionregistry

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hancomac/circulusd/internal/canonical"
)

func TestRuntimeDecimalMultipleOfMatchesCrossLanguageFixture(t *testing.T) {
	t.Parallel()
	contents, err := os.ReadFile(filepath.Join("..", "..", "packages", "extension-manifest", "fixtures", "configuration-multipleof-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Cases []struct {
			Name       string  `json:"name"`
			MultipleOf float64 `json:"multipleOf"`
			Value      float64 `json:"value"`
			Valid      bool    `json:"valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(contents, &golden); err != nil {
		t.Fatal(err)
	}
	if len(golden.Cases) == 0 {
		t.Fatal("cross-language multipleOf fixture has no cases")
	}
	for _, entry := range golden.Cases {
		t.Run(entry.Name, func(t *testing.T) {
			t.Parallel()
			fixture := newFixture(t)
			record := cloneSignedRevision(fixture.pdf)
			// Decode both numbers as binary64, as TypeScript does. Marshaling
			// retains their shortest decimal values even at the finite limits.
			schema, err := json.Marshal(map[string]any{
				"type":                 "object",
				"required":             []string{"value"},
				"additionalProperties": false,
				"properties": map[string]any{
					"value": map[string]any{"type": "number", "multipleOf": entry.MultipleOf},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			record.Revision.ConfigurationSchema = schema
			record.Revision.ConfigurationSchemaDigest = configurationSchemaDigest(record.Revision.ConfigurationSchema)
			record = fixture.signRecord(t, record.Revision, record.Assessment)
			registry := fixture.registry(t, []SignedRevision{record, fixture.python})
			request := fixture.compileRequest()
			request.Configuration["official/pdf"] = canonical.Map{"value": entry.Value}
			runtime, err := registry.CompileRuntime(request)
			if entry.Valid {
				if err != nil || runtime.ConfigurationDigest == "" {
					t.Fatalf("CompileRuntime(value=%v, multipleOf=%v) digest=%q, error=%v; want acceptance", entry.Value, entry.MultipleOf, runtime.ConfigurationDigest, err)
				}
			} else if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("CompileRuntime(value=%v, multipleOf=%v) error=%v, want ErrInvalidRequest", entry.Value, entry.MultipleOf, err)
			}
		})
	}
}
