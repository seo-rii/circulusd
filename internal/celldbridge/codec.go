package celldbridge

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"unicode"
	"unicode/utf8"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/celld"
	"golang.org/x/text/unicode/norm"
)

const (
	transactionPath   = "/circulusd/native-storage/v1/transaction"
	probePath         = "/circulusd/native-storage/v1/production:probe"
	transactionType   = "application/vnd.circulusd.native-storage+cbor"
	probeType         = "application/vnd.circulusd.native-storage-probe+cbor"
	storageProtocol   = "circulus.native-storage.v1alpha1"
	probeProtocol     = "circulus.native-storage-probe.v1alpha1"
	storageSchemaText = "circulus.native-storage.v1alpha1|major=1|minor=0|snapshot=objectId,exists,revision,stateDigest,state|receipt=pinned-snapshot,commandId,immutable-response-claims|commit=pinned-snapshot,stateWritten,state,sorted-receipts,requestDigest|commitRevision=expected+1-always|barrier=token,marker32,observedRevision,barrierSerial|native=DO-fetch-output-gate-with-active-replicator|stateMax=16777216|responseMax=4194304|claimsMax=64|claimBytesMax=1048576|receiptWritesMax=64|wireMax=33554432|depth=72|items=100000"
	probeSchemaText   = "circulus.native-storage-probe.v1alpha1|major=1|minor=0|native-ed25519|nonce=32|capability=native-storage,command-receipt|descriptor=production-dependency-v1|maxBytes=32768"
	keyHeader         = "x-circulus-storage-key-id"
	signatureHeader   = "x-circulus-storage-signature"
	maximumProbeBytes = 32 << 10
)

var (
	storageSchema = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(storageSchemaText)))
	probeSchema   = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(probeSchemaText)))
	keyPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

func wireOptions(limit int) canonical.Options {
	return canonical.Options{MaxBytes: limit, MaxDepth: 72, MaxItems: 100_000}
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func digestText(digest celld.Digest) string { return fmt.Sprintf("sha256:%x", digest[:]) }
func parseDigest(value canonical.Value) (celld.Digest, error) {
	var result celld.Digest
	text, ok := value.(string)
	if !ok || len(text) != 71 || text[:7] != "sha256:" {
		return result, ErrInvalidResponse
	}
	decoded, err := hex.DecodeString(text[7:])
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != text[7:] {
		return result, ErrInvalidResponse
	}
	copy(result[:], decoded)
	return result, nil
}

func uintValue(value canonical.Value) (uint64, bool) {
	switch number := value.(type) {
	case int64:
		if number >= 0 && uint64(number) <= MaximumRevision {
			return uint64(number), true
		}
	case uint64:
		if number <= MaximumRevision {
			return number, true
		}
	case int:
		if number >= 0 && uint64(number) <= MaximumRevision {
			return uint64(number), true
		}
	}
	return 0, false
}

func refValue(ref SnapshotRef) (canonical.Map, error) {
	if !validIdentifier(ref.ObjectID) || ref.Revision > MaximumRevision || (ref.Exists && ref.Revision == 0) ||
		(!ref.Exists && (ref.Revision != 0 || ref.StateDigest != celld.Digest(sha256.Sum256(nil)))) {
		return nil, ErrInvalidRequest
	}
	return canonical.Map{"objectId": ref.ObjectID, "exists": ref.Exists, "revision": ref.Revision, "stateDigest": digestText(ref.StateDigest)}, nil
}
func refFromValue(value canonical.Value) (SnapshotRef, error) {
	var result SnapshotRef
	m, ok := value.(canonical.Map)
	if !ok || len(m) != 4 {
		return result, ErrInvalidResponse
	}
	result.ObjectID, ok = m["objectId"].(string)
	if !ok {
		return result, ErrInvalidResponse
	}
	result.Exists, ok = m["exists"].(bool)
	if !ok {
		return result, ErrInvalidResponse
	}
	result.Revision, ok = uintValue(m["revision"])
	if !ok {
		return result, ErrInvalidResponse
	}
	var err error
	result.StateDigest, err = parseDigest(m["stateDigest"])
	if err != nil {
		return result, err
	}
	if _, err := refValue(result); err != nil {
		return result, ErrInvalidResponse
	}
	return result, nil
}
func tokenValue(token celld.CommitToken) (canonical.Map, error) {
	if !validIdentifier(token.ObjectID) || token.Revision == 0 || token.Revision > MaximumRevision {
		return nil, ErrInvalidRequest
	}
	return canonical.Map{"objectId": token.ObjectID, "revision": token.Revision}, nil
}
func tokenFromValue(value canonical.Value) (celld.CommitToken, error) {
	var result celld.CommitToken
	m, ok := value.(canonical.Map)
	if !ok || len(m) != 2 {
		return result, ErrInvalidResponse
	}
	result.ObjectID, ok = m["objectId"].(string)
	if !ok {
		return result, ErrInvalidResponse
	}
	result.Revision, ok = uintValue(m["revision"])
	if !ok {
		return result, ErrInvalidResponse
	}
	if _, err := tokenValue(result); err != nil {
		return result, ErrInvalidResponse
	}
	return result, nil
}

func receiptValue(receipt celld.StoredReceipt) (canonical.Map, error) {
	if len(receipt.Response) > MaximumReceiptResponseBytes || len(receipt.CapabilityClaims) > MaximumCapabilityClaims {
		return nil, ErrInvalidRequest
	}
	claims := make(canonical.Array, 0, len(receipt.CapabilityClaims))
	total := 0
	for _, claim := range receipt.CapabilityClaims {
		if !validIdentifier(claim.Kind) || len(claim.Payload) > MaximumCapabilityClaimBytes-total {
			return nil, ErrInvalidRequest
		}
		total += len(claim.Payload)
		claims = append(claims, canonical.Map{"kind": claim.Kind, "payload": canonical.Bytes(bytes.Clone(claim.Payload))})
	}
	return canonical.Map{"commandDigest": digestText(receipt.CommandDigest), "response": canonical.Bytes(bytes.Clone(receipt.Response)), "capabilityClaims": claims}, nil
}
func receiptFromValue(value canonical.Value) (celld.StoredReceipt, error) {
	var result celld.StoredReceipt
	m, ok := value.(canonical.Map)
	if !ok || len(m) != 3 {
		return result, ErrInvalidResponse
	}
	var err error
	result.CommandDigest, err = parseDigest(m["commandDigest"])
	if err != nil {
		return result, err
	}
	response, ok := m["response"].(canonical.Bytes)
	if !ok || len(response) > MaximumReceiptResponseBytes {
		return result, ErrInvalidResponse
	}
	claims, ok := m["capabilityClaims"].(canonical.Array)
	if !ok || len(claims) > MaximumCapabilityClaims {
		return result, ErrInvalidResponse
	}
	result.Response = bytes.Clone(response)
	total := 0
	for _, value := range claims {
		claim, ok := value.(canonical.Map)
		if !ok || len(claim) != 2 {
			return result, ErrInvalidResponse
		}
		kind, ok := claim["kind"].(string)
		if !ok || !validIdentifier(kind) {
			return result, ErrInvalidResponse
		}
		payload, ok := claim["payload"].(canonical.Bytes)
		if !ok || len(payload) > MaximumCapabilityClaimBytes-total {
			return result, ErrInvalidResponse
		}
		total += len(payload)
		result.CapabilityClaims = append(result.CapabilityClaims, celld.RawCapabilityClaims{Kind: kind, Payload: bytes.Clone(payload)})
	}
	return result, nil
}

func commitValue(request CommitRequest, withDigest bool) (canonical.Map, error) {
	ref, err := refValue(request.Snapshot)
	if err != nil || request.Snapshot.Revision == MaximumRevision || len(request.State) > MaximumStateBytes ||
		(!request.StateWritten && len(request.State) != 0) || len(request.Receipts) > MaximumReceiptWrites {
		return nil, ErrInvalidRequest
	}
	receipts := make(canonical.Array, 0, len(request.Receipts))
	previous := ""
	for _, write := range request.Receipts {
		if !validIdentifier(write.CommandID) || (previous != "" && write.CommandID <= previous) {
			return nil, ErrInvalidRequest
		}
		previous = write.CommandID
		receipt, err := receiptValue(write.Receipt)
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, canonical.Map{"commandId": write.CommandID, "receipt": receipt})
	}
	value := canonical.Map{"snapshot": ref, "stateWritten": request.StateWritten, "state": canonical.Bytes(bytes.Clone(request.State)), "receipts": receipts}
	if withDigest {
		value["requestDigest"] = digestText(request.RequestDigest)
	}
	if _, err := canonical.Encode(value, wireOptions(MaximumTransactionBytes)); err != nil {
		return nil, ErrInvalidRequest
	}
	return value, nil
}

// CommitDigest binds the complete CAS tuple and staged write set. RequestDigest
// itself is excluded so the same Go and native kernel calculate the same value.
func CommitDigest(request CommitRequest) (celld.Digest, error) {
	value, err := commitValue(request, false)
	if err != nil {
		return celld.Digest{}, err
	}
	text, err := storageDigest("circulusd.native.storage.commit", value)
	if err != nil {
		return celld.Digest{}, ErrInvalidRequest
	}
	return parseDigest(text)
}

// The standard shared framing is retained with this protocol's explicit wire
// bound; canonical.StructuredDigest's default 16 MiB bound is too small for a
// maximum-size state plus its CAS envelope.
func storageDigest(domain string, payload canonical.Value) (string, error) {
	encoded, err := canonical.Encode(canonical.Array{"circulusd.hash", int64(1), domain, int64(1), payload}, wireOptions(MaximumTransactionBytes))
	if err != nil {
		return "", ErrInvalidRequest
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(encoded)), nil
}

func directionalKey(root []byte, direction string) [32]byte {
	hash := hmac.New(sha256.New, root)
	hash.Write([]byte("circulusd.native-storage.key." + direction + ".v1\x00"))
	var key [32]byte
	copy(key[:], hash.Sum(nil))
	return key
}
func mac(key [32]byte, parts ...[]byte) string {
	hash := hmac.New(sha256.New, key[:])
	for _, part := range parts {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		hash.Write(size[:])
		hash.Write(part)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
func requestMAC(key [32]byte, keyID string, body []byte) string {
	sum := sha256.Sum256(body)
	return mac(key, []byte("circulusd.native-storage.request.v1"), []byte(keyID), []byte("POST"), []byte(transactionPath), sum[:])
}
func responseMAC(key [32]byte, keyID, id string, request []byte, status int, body []byte) string {
	req := sha256.Sum256(request)
	resp := sha256.Sum256(body)
	return mac(key, []byte("circulusd.native-storage.response.v1"), []byte(keyID), []byte(id), req[:], []byte(fmt.Sprint(status)), []byte(transactionType), resp[:])
}
func validMAC(actual, expected string) bool {
	left, err := hex.DecodeString(actual)
	if err != nil || len(left) != 32 || hex.EncodeToString(left) != actual {
		return false
	}
	right, err := hex.DecodeString(expected)
	return err == nil && hmac.Equal(left, right)
}
