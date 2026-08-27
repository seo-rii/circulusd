package sandboxrpc

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
	"unicode/utf8"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	descriptorSHA256       = "ff942ae0643b6fa2a8b8ccee97e1593e0d4b56cd414ee771ad0b731ff5854f63"
	maximumMessageBytes    = 1 << 20
	maximumStdinChunkBytes = 64 << 10
	maximumOutputBytes     = 64 << 20
	maximumTimeout         = 24 * time.Hour
	maximumRPCDeadline     = 5 * time.Minute
	defaultRequestTimeout  = 30 * time.Second
	handshakeNonceBytes    = 32
	sessionBytes           = 32
	sessionHeader          = "Circulus-Sandbox-Session"
	maximumIdempotencyKeys = 4096

	rpcDigestDomain     = "circulusd.sandboxrpc.request.v1\x00"
	logicalDigestDomain = "circulusd.sandboxrpc.operation.v1\x00"
	nonceProofDomain    = "circulusd.sandboxrpc.HandshakeNonce.v1\x00"
	processIDDomain     = "circulusd.sandboxrpc.ProcessID.v1\x00"
)

func protocolVersion() *v1.ProtocolVersion {
	return &v1.ProtocolVersion{Major: 1, Minor: 0}
}

func descriptorDigest() *v1.Digest {
	value, err := hex.DecodeString(descriptorSHA256)
	if err != nil {
		panic("sandboxrpc: invalid compiled descriptor digest")
	}
	return &v1.Digest{
		Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256,
		Value:     value,
	}
}

func sha256Digest(value []byte) *v1.Digest {
	digest := sha256.Sum256(value)
	return &v1.Digest{
		Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256,
		Value:     append([]byte(nil), digest[:]...),
	}
}

func isSHA256Digest(digest *v1.Digest) bool {
	return digest != nil &&
		digest.GetAlgorithm() == v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256 &&
		len(digest.GetValue()) == sha256.Size
}

func isDescriptorDigest(digest *v1.Digest) bool {
	expected := descriptorDigest()
	return isSHA256Digest(digest) && bytes.Equal(digest.GetValue(), expected.GetValue())
}

func isProtocolVersion(version *v1.ProtocolVersion) bool {
	return version != nil && version.GetMajor() == 1 && version.GetMinor() == 0
}

func requestDigest(message proto.Message) (*v1.Digest, error) {
	cloned := proto.Clone(message)
	if cloned == nil {
		return nil, fmt.Errorf("sandboxrpc: request is nil")
	}
	reflection := cloned.ProtoReflect()
	metaField := reflection.Descriptor().Fields().ByName("meta")
	if metaField == nil || !reflection.Has(metaField) {
		return nil, fmt.Errorf("sandboxrpc: request metadata is missing")
	}
	meta, ok := reflection.Get(metaField).Message().Interface().(*v1.RpcRequestMeta)
	if !ok || meta == nil {
		return nil, fmt.Errorf("sandboxrpc: request metadata has an invalid type")
	}
	meta.RequestDigest = nil
	return digestProto(rpcDigestDomain, cloned)
}

func logicalRequestDigest(message proto.Message) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	cloned := proto.Clone(message)
	if cloned == nil {
		return result, fmt.Errorf("sandboxrpc: request is nil")
	}
	reflection := cloned.ProtoReflect()
	metaField := reflection.Descriptor().Fields().ByName("meta")
	if metaField == nil {
		return result, fmt.Errorf("sandboxrpc: request has no metadata field")
	}
	reflection.Clear(metaField)
	digest, err := digestProto(logicalDigestDomain, cloned)
	if err != nil {
		return result, err
	}
	copy(result[:], digest.GetValue())
	return result, nil
}

func digestProto(domain string, message proto.Message) (*v1.Digest, error) {
	wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("sandboxrpc: marshal request: %w", err)
	}
	name := string(message.ProtoReflect().Descriptor().FullName())
	payload := make([]byte, 0, len(domain)+len(name)+1+len(wire))
	payload = append(payload, domain...)
	payload = append(payload, name...)
	payload = append(payload, 0)
	payload = append(payload, wire...)
	return sha256Digest(payload), nil
}

func nonceProof(nonce, sandboxID []byte, generation uint64) []byte {
	mac := hmac.New(sha256.New, nonce)
	_, _ = mac.Write([]byte(nonceProofDomain))
	_, _ = mac.Write(descriptorDigest().GetValue())
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(sandboxID)))
	_, _ = mac.Write(length[:])
	_, _ = mac.Write(sandboxID)
	var encodedGeneration [8]byte
	binary.BigEndian.PutUint64(encodedGeneration[:], generation)
	_, _ = mac.Write(encodedGeneration[:])
	return mac.Sum(nil)
}

func deriveProcessID(key [sha256.Size]byte, idempotencyKey []byte, digest [sha256.Size]byte) []byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(processIDDomain))
	_, _ = mac.Write(idempotencyKey)
	_, _ = mac.Write(digest[:])
	return append([]byte(nil), mac.Sum(nil)[:16]...)
}

func validOpaqueID(value []byte, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum
}

func validProcessString(value string, maximum int) bool {
	return len(value) <= maximum && utf8.ValidString(value) && !bytes.ContainsRune([]byte(value), 0)
}

func hasUnknownFields(message proto.Message) bool {
	if message == nil {
		return false
	}
	return reflectMessageHasUnknownFields(message.ProtoReflect())
}

func reflectMessageHasUnknownFields(message protoreflect.Message) bool {
	if len(message.GetUnknown()) != 0 {
		return true
	}
	found := false
	message.Range(func(descriptor protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if descriptor.IsMap() {
			if descriptor.MapValue().Kind() != protoreflect.MessageKind && descriptor.MapValue().Kind() != protoreflect.GroupKind {
				return true
			}
			value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
				if reflectMessageHasUnknownFields(item.Message()) {
					found = true
					return false
				}
				return true
			})
			return !found
		}
		if descriptor.IsList() {
			if descriptor.Kind() != protoreflect.MessageKind && descriptor.Kind() != protoreflect.GroupKind {
				return true
			}
			list := value.List()
			for index := 0; index < list.Len(); index++ {
				if reflectMessageHasUnknownFields(list.Get(index).Message()) {
					found = true
					return false
				}
			}
			return true
		}
		if descriptor.Kind() == protoreflect.MessageKind || descriptor.Kind() == protoreflect.GroupKind {
			found = reflectMessageHasUnknownFields(value.Message())
			return !found
		}
		return true
	})
	return found
}
