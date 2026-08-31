package controlrpc

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	v1 "github.com/hancomac/circulusd/api/generated/circulus/v1alpha"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	descriptorSHA256    = "693b865cbe6eadb0e6d43910707f8bd0cde0bd892642487e514416e8c0ebc1e0"
	maximumMessageBytes = 1 << 20
	handshakeNonceBytes = 32
	sessionHeader       = "Circulus-Protocol-Session"

	requestDigestDomain = "circulusd.controlrpc.GetCapabilities.v1\x00"
	nonceProofDomain    = "circulusd.controlrpc.HandshakeNonce.v1\x00"
)

func protocolVersion() *v1.ProtocolVersion {
	return &v1.ProtocolVersion{Major: 1, Minor: 0}
}

func descriptorDigest() *v1.Digest {
	value, err := hex.DecodeString(descriptorSHA256)
	if err != nil {
		panic("controlrpc: invalid compiled descriptor digest")
	}
	return &v1.Digest{
		Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256,
		Value:     value,
	}
}

func sha256Digest(payload []byte) *v1.Digest {
	digest := sha256.Sum256(payload)
	return &v1.Digest{
		Algorithm: v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256,
		Value:     append([]byte(nil), digest[:]...),
	}
}

func getCapabilitiesRequestDigest(request *v1.GetCapabilitiesRequest) (*v1.Digest, error) {
	if request == nil {
		return nil, fmt.Errorf("controlrpc: capabilities request is nil")
	}
	cloned, ok := proto.Clone(request).(*v1.GetCapabilitiesRequest)
	if !ok || cloned == nil {
		return nil, fmt.Errorf("controlrpc: cannot clone capabilities request")
	}
	if cloned.Meta != nil {
		cloned.Meta.RequestDigest = nil
	}
	wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(cloned)
	if err != nil {
		return nil, fmt.Errorf("controlrpc: marshal capabilities request: %w", err)
	}
	payload := make([]byte, 0, len(requestDigestDomain)+len(wire))
	payload = append(payload, requestDigestDomain...)
	payload = append(payload, wire...)
	return sha256Digest(payload), nil
}

func nonceProof(nonce []byte, serverPeer v1.ProtocolPeer) []byte {
	descriptor := descriptorDigest().GetValue()
	payload := make([]byte, 0, len(nonceProofDomain)+len(descriptor)+4+len(nonce))
	payload = append(payload, nonceProofDomain...)
	payload = append(payload, descriptor...)
	var encodedPeer [4]byte
	binary.BigEndian.PutUint32(encodedPeer[:], uint32(serverPeer))
	payload = append(payload, encodedPeer[:]...)
	payload = append(payload, nonce...)
	digest := sha256.Sum256(payload)
	return append([]byte(nil), digest[:]...)
}

func isProtocolVersion(version *v1.ProtocolVersion) bool {
	return version != nil && version.GetMajor() == 1 && version.GetMinor() == 0
}

func isDescriptorDigest(digest *v1.Digest) bool {
	expected := descriptorDigest()
	return digest != nil &&
		digest.GetAlgorithm() == v1.DigestAlgorithm_DIGEST_ALGORITHM_SHA256 &&
		bytes.Equal(digest.GetValue(), expected.GetValue())
}

func cloneCapabilities(capabilities []*v1.CapabilityStatus) ([]*v1.CapabilityStatus, error) {
	cloned := make([]*v1.CapabilityStatus, len(capabilities))
	for index, capability := range capabilities {
		if capability == nil {
			return nil, fmt.Errorf("controlrpc: capability %d is nil", index)
		}
		if hasUnknownFields(capability) {
			return nil, fmt.Errorf("controlrpc: capability %d contains unknown protocol fields", index)
		}
		copy, ok := proto.Clone(capability).(*v1.CapabilityStatus)
		if !ok || copy == nil {
			return nil, fmt.Errorf("controlrpc: cannot clone capability %d", index)
		}
		cloned[index] = copy
	}
	return cloned, nil
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

func isKnownPeer(peer v1.ProtocolPeer) bool {
	switch peer {
	case v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMD,
		v1.ProtocolPeer_PROTOCOL_PEER_AGENTD,
		v1.ProtocolPeer_PROTOCOL_PEER_EXECUTORD,
		v1.ProtocolPeer_PROTOCOL_PEER_SANDBOXD,
		v1.ProtocolPeer_PROTOCOL_PEER_PLATFORMCTL,
		v1.ProtocolPeer_PROTOCOL_PEER_STATE_APP,
		v1.ProtocolPeer_PROTOCOL_PEER_SESSION_HOST:
		return true
	default:
		return false
	}
}
