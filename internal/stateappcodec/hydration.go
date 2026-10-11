package stateappcodec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

// Scope is an immutable comparison binding after New copies it. The caller must
// independently qualify the authority of the authenticated reader. A codec is
// not an authority minter or proof of production qualification.
type Scope struct {
	TenantID                string
	ActorSubjectID          string
	SessionID               string
	AuthorizationGeneration uint64
}
type BlobRequest struct {
	Scope
	Digest string
}
type Blob struct {
	Digest       string
	EncodedBytes int
	Bytes        []byte
}
type BlobReadFunc func(context.Context, BlobRequest) (*Blob, error)
type Codec struct {
	scope    Scope
	readBlob BlobReadFunc
}

func New(scope Scope, readBlob BlobReadFunc) (*Codec, error) {
	for kind, value := range map[identity.Kind]string{identity.Tenant: scope.TenantID, identity.Subject: scope.ActorSubjectID, identity.Session: scope.SessionID} {
		if _, err := identity.Parse(kind, value); err != nil {
			return nil, ErrInvalidScope
		}
	}
	// This is the existing authenticated blob ingress generation contract, not a
	// blanket restriction on broker placement/sandbox generation zero.
	if scope.AuthorizationGeneration < 1 || scope.AuthorizationGeneration > MaximumSafeInteger || readBlob == nil {
		return nil, ErrInvalidScope
	}
	return &Codec{scope: scope, readBlob: readBlob}, nil
}

// HydrateCheckpoint checks metadata before I/O and verifies blob hash/length
// separately from the chain hash over the reconstructed inline checkpoint.
// Legacy inline checkpoints may omit expectedChainDigest. External ones may not.
func (c *Codec) HydrateCheckpoint(ctx context.Context, stored canonical.Value, expectedChainDigest string) (*v1.AgentCheckpoint, error) {
	if c == nil || ctx == nil {
		return nil, ErrInvalidScope
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, ok := stored.(canonical.Map)
	if !ok {
		return nil, ErrInvalidCheckpoint
	}
	_, external := m["payloadSize"]
	checkpoint, err := parseCheckpoint(m, external)
	if err != nil {
		return nil, err
	}
	if string(checkpoint.SessionId.Value) != c.scope.SessionID {
		return nil, ErrInvalidScope
	}
	if _, ok := parseDigest(expectedChainDigest); !ok && (external || expectedChainDigest != "") {
		return nil, ErrInvalidCheckpoint
	}
	if external {
		// All values used after the reader returns come from validated copies.
		size, _ := safeUint(m["payloadSize"], 1)
		digest, _ := digestText(checkpoint.PayloadDigest)
		body, err := c.read(ctx, digest, int(size))
		if err != nil {
			return nil, err
		}
		checkpoint.PayloadBytes = body
	}
	if expectedChainDigest != "" {
		digest, err := CheckpointDigest(checkpoint)
		if err != nil || "sha256:"+hex.EncodeToString(digest[:]) != expectedChainDigest {
			return nil, ErrInvalidCheckpoint
		}
	}
	return checkpoint, nil
}

// HydrateSettlement accepts the authoritative stored outcome, never an artifact
// ID in its place. Pi decimal/cost wrappers and byte strings stay canonical and
// are decoded by the existing Pi consumer at the actual provider/tool boundary.
func (c *Codec) HydrateSettlement(ctx context.Context, requestDigest string, storedOutcome canonical.Value) (canonical.Map, error) {
	if c == nil || ctx == nil {
		return nil, ErrInvalidScope
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, ok := parseDigest(requestDigest); !ok {
		return nil, ErrInvalidSettlement
	}
	m, ok := storedOutcome.(canonical.Map)
	if !ok {
		return nil, ErrInvalidSettlement
	}
	var outcome canonical.Map
	switch m["kind"] {
	case "success":
		if len(m) != 2 {
			return nil, ErrInvalidSettlement
		}
		result, inline := m["result"]
		reference, external := m["resultPayloadRef"]
		if inline == external {
			return nil, ErrInvalidSettlement
		}
		if external {
			var err error
			result, err = c.readPayload(ctx, reference)
			if err != nil {
				return nil, err
			}
		} else {
			var err error
			result, err = cloneValue(result, maximumValueBytes)
			if err != nil {
				return nil, ErrInvalidSettlement
			}
		}
		outcome = canonical.Map{"kind": "success", "result": result}
	case "error":
		code, codeOK := identifier(m["code"])
		message, messageOK := identifier(m["message"])
		retry, retryOK := m["retryable"].(bool)
		if len(m) != 4 || !codeOK || !messageOK || !retryOK {
			return nil, ErrInvalidSettlement
		}
		outcome = canonical.Map{"kind": "error", "code": code, "message": message, "retryable": retry}
	case "interrupted_unknown", "abandoned":
		reason, ok := identifier(m["reason"])
		if len(m) != 2 || !ok {
			return nil, ErrInvalidSettlement
		}
		outcome = canonical.Map{"kind": m["kind"], "reason": reason}
	default:
		return nil, ErrInvalidSettlement
	}
	return canonical.Map{"requestDigest": requestDigest, "outcome": outcome}, nil
}

func (c *Codec) readPayload(ctx context.Context, reference canonical.Value) (canonical.Value, error) {
	m, ok := reference.(canonical.Map)
	if !ok || len(m) != 4 || m["encoding"] != "canonical-cbor-v1" {
		return nil, ErrInvalidSettlement
	}
	digest, ok := m["digest"].(string)
	if !ok {
		return nil, ErrInvalidSettlement
	}
	if _, ok := parseDigest(digest); !ok {
		return nil, ErrInvalidSettlement
	}
	size, ok := safeUint(m["encodedBytes"], 1)
	if !ok || size > maximumValueBytes {
		return nil, ErrInvalidSettlement
	}
	items, ok := safeUint(m["encodedItems"], 1)
	if !ok || items > size {
		return nil, ErrInvalidSettlement
	}
	body, err := c.read(ctx, digest, int(size))
	if err != nil {
		return nil, err
	}
	value, err := canonical.Decode(body, canonical.Options{MaxBytes: int(size), MaxDepth: 64, MaxItems: int(items)})
	if err != nil || itemCount(value) != int(items) {
		return nil, ErrInvalidBlob
	}
	return value, nil
}

func (c *Codec) read(ctx context.Context, digest string, size int) ([]byte, error) {
	blob, err := c.readBlob(ctx, BlobRequest{Scope: c.scope, Digest: digest})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if blob == nil || blob.Digest != digest || blob.EncodedBytes != size || len(blob.Bytes) != size {
		return nil, ErrInvalidBlob
	}
	body := append([]byte(nil), blob.Bytes...)
	if sum := sha256.Sum256(body); "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return nil, ErrInvalidBlob
	}
	return body, nil
}
func cloneValue(value canonical.Value, maxBytes int) (canonical.Value, error) {
	options := canonical.Options{MaxBytes: maxBytes, MaxDepth: 64, MaxItems: 1_000_000}
	body, err := canonical.Encode(value, options)
	if err != nil {
		return nil, err
	}
	return canonical.Decode(body, options)
}
func itemCount(value canonical.Value) int {
	n := 1
	switch v := value.(type) {
	case canonical.Array:
		for _, item := range v {
			n += itemCount(item)
		}
	case canonical.Map:
		for _, item := range v {
			n += 1 + itemCount(item)
		}
	}
	return n
}
