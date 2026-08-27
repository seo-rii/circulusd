package release

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

const (
	maxTrustStoreBytes = 1 << 20
	maxTrustRoots      = 64
)

type trustStoreFile struct {
	SchemaVersion int             `json:"schemaVersion"`
	Roots         []trustRootFile `json:"roots"`
}

type trustRootFile struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKey"`
}

func LoadTrustStore(path string) (*TrustStore, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open release trust store: %w", err)
	}
	defer file.Close()

	encoded, err := io.ReadAll(io.LimitReader(file, maxTrustStoreBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read release trust store: %w", err)
	}
	if len(encoded) > maxTrustStoreBytes {
		return nil, fmt.Errorf("release trust store exceeds %d bytes", maxTrustStoreBytes)
	}
	if len(bytes.TrimSpace(encoded)) == 0 {
		return nil, fmt.Errorf("release trust store is empty")
	}

	var document trustStoreFile
	if err := decodeStrictJSON(encoded, "release trust store", &document); err != nil {
		return nil, err
	}
	if document.SchemaVersion != 1 {
		return nil, fmt.Errorf("release trust store schemaVersion %d is unsupported", document.SchemaVersion)
	}
	if len(document.Roots) == 0 || len(document.Roots) > maxTrustRoots {
		return nil, fmt.Errorf("release trust store must contain 1 to %d roots", maxTrustRoots)
	}

	roots := make(map[string]ed25519.PublicKey, len(document.Roots))
	for index, root := range document.Roots {
		if root.Algorithm != "ed25519" || !signingKeyPattern.MatchString(root.KeyID) {
			return nil, fmt.Errorf("release trust root[%d] has invalid metadata", index)
		}
		if _, duplicate := roots[root.KeyID]; duplicate {
			return nil, fmt.Errorf("release trust root key ID %q is duplicated", root.KeyID)
		}
		publicKey, err := base64.StdEncoding.Strict().DecodeString(root.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("release trust root[%d] has an invalid Ed25519 public key", index)
		}
		roots[root.KeyID] = ed25519.PublicKey(publicKey)
	}
	return NewTrustStore(roots)
}
