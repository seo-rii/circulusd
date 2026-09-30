package main

// Mirrors the parts of circulusd/internal/sandboxrpc/protocol.go that a
// client needs. They cannot be imported (Go internal package), so they are
// kept here verbatim in spirit and pinned by protocol_test.go against vectors
// produced by circulusd's own generated types.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	descriptorSHA256       = "693b865cbe6eadb0e6d43910707f8bd0cde0bd892642487e514416e8c0ebc1e0"
	maximumMessageBytes    = 1 << 20
	maximumStdinChunkBytes = 64 << 10
	maximumRPCDeadline     = 5 * time.Minute
	defaultRequestTimeout  = 30 * time.Second
	handshakeNonceBytes    = 32
	sessionHeader          = "Circulus-Sandbox-Session"

	rpcDigestDomain  = "circulusd.sandboxrpc.request.v1\x00"
	nonceProofDomain = "circulusd.sandboxrpc.HandshakeNonce.v1\x00"
)

func protocolVersion() *v1.ProtocolVersion {
	return &v1.ProtocolVersion{Major: 1, Minor: 0}
}

func isProtocolVersion(version *v1.ProtocolVersion) bool {
	return version != nil && version.GetMajor() == 1 && version.GetMinor() == 0
}

func descriptorDigest() *v1.Digest {
	value, err := hex.DecodeString(descriptorSHA256)
	if err != nil {
		panic("invalid descriptor digest constant")
	}
	return &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: value}
}

func sha256Digest(value []byte) *v1.Digest {
	sum := sha256.Sum256(value)
	return &v1.Digest{Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256, Value: append([]byte(nil), sum[:]...)}
}

func isSHA256Digest(digest *v1.Digest) bool {
	return digest != nil && digest.GetAlgorithm() == v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256 && len(digest.GetValue()) == sha256.Size
}

func isDescriptorDigest(digest *v1.Digest) bool {
	return isSHA256Digest(digest) && hex.EncodeToString(digest.GetValue()) == descriptorSHA256
}

func digestProto(domain string, message proto.Message) (*v1.Digest, error) {
	wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	name := string(message.ProtoReflect().Descriptor().FullName())
	payload := make([]byte, 0, len(domain)+len(name)+1+len(wire))
	payload = append(payload, domain...)
	payload = append(payload, name...)
	payload = append(payload, 0)
	payload = append(payload, wire...)
	return sha256Digest(payload), nil
}

// requestDigest hashes the request with meta.request_digest cleared.
func requestDigest(message proto.Message) (*v1.Digest, error) {
	cloned := proto.Clone(message)
	meta, err := requestMeta(cloned)
	if err != nil {
		return nil, err
	}
	meta.RequestDigest = nil
	return digestProto(rpcDigestDomain, cloned)
}

func requestMeta(message proto.Message) (*v1.RpcRequestMeta, error) {
	reflection := message.ProtoReflect()
	field := reflection.Descriptor().Fields().ByName("meta")
	if field == nil || !reflection.Has(field) {
		return nil, errors.New("request metadata is missing")
	}
	meta, ok := reflection.Get(field).Message().Interface().(*v1.RpcRequestMeta)
	if !ok || meta == nil {
		return nil, errors.New("request metadata has an invalid type")
	}
	return meta, nil
}

func nonceProof(nonce, sandboxID []byte, generation uint64, serverPeer v1.ProtocolPeer) []byte {
	mac := hmac.New(sha256.New, nonce)
	_, _ = mac.Write([]byte(nonceProofDomain))
	_, _ = mac.Write(descriptorDigest().GetValue())
	var encodedPeer [4]byte
	binary.BigEndian.PutUint32(encodedPeer[:], uint32(serverPeer))
	_, _ = mac.Write(encodedPeer[:])
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(sandboxID)))
	_, _ = mac.Write(length[:])
	_, _ = mac.Write(sandboxID)
	var encodedGeneration [8]byte
	binary.BigEndian.PutUint64(encodedGeneration[:], generation)
	_, _ = mac.Write(encodedGeneration[:])
	return mac.Sum(nil)
}

// prepareRequest fills RpcRequestMeta like sandboxrpc.prepareRequest: fresh
// request id, bounded deadline, caller-supplied idempotency key, protocol
// version, then the request digest over the result.
func prepareRequest(ctx context.Context, message proto.Message, idempotencyKey []byte) (proto.Message, []byte, error) {
	if len(idempotencyKey) < 16 || len(idempotencyKey) > 64 {
		return nil, nil, errors.New("idempotency key must be 16..64 bytes")
	}
	cloned := proto.Clone(message)
	meta, err := requestMeta(cloned)
	if err != nil {
		return nil, nil, err
	}
	requestID := make([]byte, 16)
	if _, err := rand.Read(requestID); err != nil {
		return nil, nil, err
	}
	now := time.Now()
	deadline := now.Add(defaultRequestTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if maximum := now.Add(maximumRPCDeadline); deadline.After(maximum) {
		deadline = maximum
	}
	if !now.Before(deadline) {
		return nil, nil, context.DeadlineExceeded
	}
	meta.RequestId = &v1.OpaqueId{Value: requestID}
	meta.RequestDigest = nil
	meta.DeadlineUnixMs = uint64(deadline.UnixMilli())
	meta.IdempotencyKey = append([]byte(nil), idempotencyKey...)
	meta.ProtocolVersion = protocolVersion()
	digest, err := requestDigest(cloned)
	if err != nil {
		return nil, nil, err
	}
	meta.RequestDigest = digest
	return cloned, requestID, nil
}

func validateResponse(message proto.Message, meta *v1.RpcResponseMeta, requestID []byte) error {
	if hasUnknownFields(message) || meta == nil || !equalBytes(meta.GetRequestId().GetValue(), requestID) ||
		meta.GetServerSequence() == 0 || !isDescriptorDigest(meta.GetDescriptorDigest()) {
		return errors.New("response metadata failed protocol validation")
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	return string(a) == string(b)
}

func newIdempotencyKey() []byte {
	key := make([]byte, 24)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

func hasUnknownFields(message proto.Message) bool {
	if message == nil {
		return false
	}
	return reflectHasUnknown(message.ProtoReflect())
}

func reflectHasUnknown(message protoreflect.Message) bool {
	if len(message.GetUnknown()) != 0 {
		return true
	}
	found := false
	message.Range(func(descriptor protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case descriptor.IsMap():
			if descriptor.MapValue().Kind() == protoreflect.MessageKind {
				value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
					found = reflectHasUnknown(item.Message())
					return !found
				})
			}
		case descriptor.IsList():
			if descriptor.Kind() == protoreflect.MessageKind {
				list := value.List()
				for index := 0; index < list.Len() && !found; index++ {
					found = reflectHasUnknown(list.Get(index).Message())
				}
			}
		case descriptor.Kind() == protoreflect.MessageKind:
			found = reflectHasUnknown(value.Message())
		}
		return !found
	})
	return found
}
