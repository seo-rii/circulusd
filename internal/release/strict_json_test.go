package release

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsCaseAliasedSchemaVersion(t *testing.T) {
	data, err := os.ReadFile("../../deploy/airgap/release-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"schemaVersion": 1`), []byte(`"schemaVersion": 999, "SchemaVersion": 1`), 1)
	if !bytes.Contains(data, []byte(`"SchemaVersion"`)) {
		t.Fatal("schema version fixture was not replaced")
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if manifest, err := Load(path); err == nil {
		t.Fatalf("Load accepted an aliased schemaVersion: %d", manifest.SchemaVersion)
	}
}

func TestDecodeStrictJSONRequiresExactNestedFields(t *testing.T) {
	for _, document := range []string{
		`{"SchemaVersion":1}`,
		`{"release":{"Version":"1.0.0"}}`,
		`{"components":[{"Artifacts":[{}]}]}`,
		`{"components":[{"artifacts":[{"signature":{"KeyId":"root"}}]}]}`,
		`{"protocolCompatibility":[{"minimum":{"Major":1}}]}`,
		`{"signatures":[{"keyId":"first","KEYID":"second"}]}`,
	} {
		var manifest Manifest
		if err := decodeStrictJSON([]byte(document), "manifest", &manifest); err == nil {
			t.Errorf("accepted noncanonical field name in %s", document)
		}
	}
	// Map entries are data, so their casing remains significant and unrestricted.
	var manifest Manifest
	if err := decodeStrictJSON([]byte(`{"toolchains":{"go":"one","Go":"two"},"components":[{"artifacts":[{"signature":{"keyId":"root"},"sizeBytes":1}]}]}`), "manifest", &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Toolchains) != 2 || manifest.Toolchains["Go"] != "two" {
		t.Fatalf("map data was changed: %#v", manifest.Toolchains)
	}
}
