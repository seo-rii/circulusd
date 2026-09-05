package release

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadTrustStoreVerifiesPromotionFromStrictOfflineFile(t *testing.T) {
	t.Parallel()

	manifest, publicKey := signedPromotion(t, "production")
	encoded, err := json.Marshal(map[string]any{
		"schemaVersion": 1,
		"roots": []map[string]string{{
			"keyId":     "release-root-1",
			"algorithm": "ed25519",
			"publicKey": base64.StdEncoding.EncodeToString(publicKey),
		}},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "release-trust-roots.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	store, err := LoadTrustStore(path)
	if err != nil {
		t.Fatalf("LoadTrustStore() error = %v", err)
	}
	if err := store.VerifyPromotion(manifest); err != nil {
		t.Fatalf("VerifyPromotion() error = %v", err)
	}
	for index := range publicKey {
		publicKey[index] ^= 0xff
	}
	if err := store.VerifyPromotion(manifest); err != nil {
		t.Fatalf("VerifyPromotion() after caller key mutation error = %v", err)
	}
}

func TestLoadTrustStoreRejectsAmbiguousAndUnboundedFiles(t *testing.T) {
	t.Parallel()

	publicKey := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	validRoot := `{"keyId":"release-root-1","algorithm":"ed25519","publicKey":"` +
		publicKey + `"}`
	tests := map[string][]byte{
		"case alias":         []byte(`{"SchemaVersion":1,"roots":[` + validRoot + `]}`),
		"nested case alias":  []byte(`{"schemaVersion":1,"roots":[` + strings.Replace(validRoot, `"keyId"`, `"KeyId"`, 1) + `]}`),
		"unknown field":      []byte(`{"schemaVersion":1,"roots":[` + validRoot + `],"extra":true}`),
		"duplicate member":   []byte(`{"schemaVersion":1,"schemaVersion":1,"roots":[` + validRoot + `]}`),
		"trailing value":     []byte(`{"schemaVersion":1,"roots":[` + validRoot + `]} {}`),
		"unsupported schema": []byte(`{"schemaVersion":2,"roots":[` + validRoot + `]}`),
		"empty roots":        []byte(`{"schemaVersion":1,"roots":[]}`),
		"duplicate key ID":   []byte(`{"schemaVersion":1,"roots":[` + validRoot + `,` + validRoot + `]}`),
		"wrong algorithm":    []byte(`{"schemaVersion":1,"roots":[{"keyId":"release-root-1","algorithm":"rsa","publicKey":"` + publicKey + `"}]}`),
		"wrong key size":     []byte(`{"schemaVersion":1,"roots":[{"keyId":"release-root-1","algorithm":"ed25519","publicKey":"` + base64.StdEncoding.EncodeToString([]byte{1}) + `"}]}`),
		"oversized":          bytes.Repeat([]byte{' '}, 1_048_577),
	}
	for name, contents := range tests {
		name, contents := name, contents
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "roots.json")
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			if _, err := LoadTrustStore(path); err == nil ||
				strings.Contains(err.Error(), string(contents)) {
				t.Fatalf("LoadTrustStore() error = %v", err)
			}
		})
	}
}
