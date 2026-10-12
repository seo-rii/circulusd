package extensionregistry

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeLocalDynamicReferencesMatchCrossLanguageFixture(t *testing.T) {
	t.Parallel()
	contents, err := os.ReadFile(filepath.Join("..", "..", "packages", "extension-manifest", "fixtures", "configuration-dynamicref-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Cases []struct {
			Name        string          `json:"name"`
			Schema      json.RawMessage `json:"schema"`
			SchemaValid bool            `json:"schemaValid"`
			Instances   []struct {
				Name  string `json:"name"`
				Value any    `json:"value"`
				Valid bool   `json:"valid"`
			} `json:"instances"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(contents, &golden); err != nil {
		t.Fatal(err)
	}
	if len(golden.Cases) == 0 {
		t.Fatal("cross-language dynamicRef fixture has no cases")
	}
	for _, entry := range golden.Cases {
		t.Run(entry.Name, func(t *testing.T) {
			t.Parallel()
			fixture := newFixture(t)
			record := cloneSignedRevision(fixture.pdf)
			record.Revision.ConfigurationSchema = entry.Schema
			record.Revision.ConfigurationSchemaDigest = configurationSchemaDigest(entry.Schema)
			record = fixture.signRecord(t, record.Revision, record.Assessment)
			registry, err := New(fixture.roots, []SignedRevision{record, fixture.python}, fixture.resolver)
			if !entry.SchemaValid {
				if !errors.Is(err, ErrInvalidRecord) {
					t.Fatalf("New(invalid schema) error=%v, want ErrInvalidRecord", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(valid schema): %v", err)
			}
			for _, instance := range entry.Instances {
				t.Run(instance.Name, func(t *testing.T) {
					value, _, err := normalizeExtensionJSON(instance.Value)
					if err != nil {
						t.Fatal(err)
					}
					request := fixture.compileRequest()
					request.Configuration["official/pdf"] = value
					runtime, err := registry.CompileRuntime(request)
					if instance.Valid {
						if err != nil || runtime.ConfigurationDigest == "" {
							t.Fatalf("CompileRuntime(valid) digest=%q, error=%v", runtime.ConfigurationDigest, err)
						}
					} else if !errors.Is(err, ErrInvalidRequest) {
						t.Fatalf("CompileRuntime(invalid) error=%v, want ErrInvalidRequest", err)
					}
				})
			}
		})
	}
}
