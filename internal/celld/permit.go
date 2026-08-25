package celld

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	permitFormatVersion       = 1
	permitMACSize             = sha256.Size
	permitMaximumKindBytes    = 256
	permitMaximumPayloadBytes = 1 << 20
	permitMaximumEncodedBytes = permitMaximumPayloadBytes + 2048
	permitMACDomain           = "circulusd.celld.sealed-permit.v1\x00"
)

// SealedPermit is an opaque bearer value. MarshalBinary is provided for wire
// transport, while String and GoString deliberately redact its bytes.
type SealedPermit struct {
	token []byte
}

func ParseSealedPermit(encoded []byte) (SealedPermit, error) {
	if len(encoded) <= permitMACSize || len(encoded) > permitMaximumEncodedBytes {
		return SealedPermit{}, ErrInvalidPermit
	}
	return SealedPermit{token: append([]byte(nil), encoded...)}, nil
}

func (permit SealedPermit) MarshalBinary() ([]byte, error) {
	if len(permit.token) <= permitMACSize || len(permit.token) > permitMaximumEncodedBytes {
		return nil, ErrInvalidPermit
	}
	return append([]byte(nil), permit.token...), nil
}

func (SealedPermit) String() string { return "sealed-permit<redacted>" }

func (SealedPermit) GoString() string { return "sealed-permit<redacted>" }

// PermitCodec deterministically authenticates raw claims and their receipt
// binding. It intentionally has no clock: live generations and deadlines are
// checked by the aggregate/broker when the permit is consumed.
type PermitCodec struct {
	secret []byte
}

func NewPermitCodec(secret []byte) (*PermitCodec, error) {
	if len(secret) < sha256.Size {
		return nil, fmt.Errorf("%w: permit secret must contain at least %d bytes", ErrInvalidConfig, sha256.Size)
	}
	return &PermitCodec{secret: append([]byte(nil), secret...)}, nil
}

func (codec *PermitCodec) Seal(
	ctx context.Context,
	binding PermitBinding,
	claims RawCapabilityClaims,
) (SealedPermit, error) {
	if err := ctx.Err(); err != nil {
		return SealedPermit{}, err
	}
	if codec == nil || len(codec.secret) < sha256.Size || !validProtocolIdentifier(binding.ObjectID) || !validProtocolIdentifier(binding.CommandID) || !validProtocolIdentifier(claims.Kind) || len(claims.Kind) > permitMaximumKindBytes || len(claims.Payload) == 0 {
		return SealedPermit{}, ErrInvalidPermit
	}
	if len(claims.Payload) > permitMaximumPayloadBytes {
		return SealedPermit{}, ErrPermitTooLarge
	}

	body := bytes.NewBuffer(make([]byte, 0, len(claims.Payload)+512))
	body.WriteByte(permitFormatVersion)
	var shortLength [2]byte
	binary.BigEndian.PutUint16(shortLength[:], uint16(len(binding.ObjectID)))
	body.Write(shortLength[:])
	body.WriteString(binding.ObjectID)
	binary.BigEndian.PutUint16(shortLength[:], uint16(len(binding.CommandID)))
	body.Write(shortLength[:])
	body.WriteString(binding.CommandID)
	body.Write(binding.CommandDigest[:])
	var claimIndex [4]byte
	binary.BigEndian.PutUint32(claimIndex[:], binding.ClaimIndex)
	body.Write(claimIndex[:])
	binary.BigEndian.PutUint16(shortLength[:], uint16(len(claims.Kind)))
	body.Write(shortLength[:])
	body.WriteString(claims.Kind)
	var payloadLength [4]byte
	binary.BigEndian.PutUint32(payloadLength[:], uint32(len(claims.Payload)))
	body.Write(payloadLength[:])
	body.Write(claims.Payload)

	mac := hmac.New(sha256.New, codec.secret)
	_, _ = mac.Write([]byte(permitMACDomain))
	_, _ = mac.Write(body.Bytes())
	token := append(append([]byte(nil), body.Bytes()...), mac.Sum(nil)...)
	if len(token) > permitMaximumEncodedBytes {
		return SealedPermit{}, ErrPermitTooLarge
	}
	return SealedPermit{token: token}, nil
}

// Open authenticates the complete token before parsing claims and requires the
// caller's exact expected binding. Returned claim bytes are a defensive copy.
func (codec *PermitCodec) Open(permit SealedPermit, expected PermitBinding) (RawCapabilityClaims, error) {
	if codec == nil || len(codec.secret) < sha256.Size || !validProtocolIdentifier(expected.ObjectID) || !validProtocolIdentifier(expected.CommandID) || len(permit.token) <= permitMACSize || len(permit.token) > permitMaximumEncodedBytes {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}
	body := permit.token[:len(permit.token)-permitMACSize]
	receivedMAC := permit.token[len(permit.token)-permitMACSize:]
	mac := hmac.New(sha256.New, codec.secret)
	_, _ = mac.Write([]byte(permitMACDomain))
	_, _ = mac.Write(body)
	if !hmac.Equal(receivedMAC, mac.Sum(nil)) {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}

	reader := bytes.NewReader(body)
	version, err := reader.ReadByte()
	if err != nil || version != permitFormatVersion {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}
	var shortLength [2]byte
	if _, err := io.ReadFull(reader, shortLength[:]); err != nil {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}
	objectLength := int(binary.BigEndian.Uint16(shortLength[:]))
	if objectLength > maxProtocolIdentifierBytes || objectLength > reader.Len() {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}
	objectID := make([]byte, objectLength)
	if _, err := io.ReadFull(reader, objectID); err != nil {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}
	if _, err := io.ReadFull(reader, shortLength[:]); err != nil {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}
	commandLength := int(binary.BigEndian.Uint16(shortLength[:]))
	if commandLength > maxProtocolIdentifierBytes || commandLength > reader.Len() {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}
	commandID := make([]byte, commandLength)
	if _, err := io.ReadFull(reader, commandID); err != nil {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}
	var digest Digest
	if _, err := io.ReadFull(reader, digest[:]); err != nil {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}
	var claimIndex [4]byte
	if _, err := io.ReadFull(reader, claimIndex[:]); err != nil {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}
	if _, err := io.ReadFull(reader, shortLength[:]); err != nil {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}
	kindLength := int(binary.BigEndian.Uint16(shortLength[:]))
	if kindLength > permitMaximumKindBytes || kindLength > reader.Len() {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}
	kind := make([]byte, kindLength)
	if _, err := io.ReadFull(reader, kind); err != nil {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}
	var payloadLength [4]byte
	if _, err := io.ReadFull(reader, payloadLength[:]); err != nil {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}
	payloadSize := uint64(binary.BigEndian.Uint32(payloadLength[:]))
	if payloadSize > permitMaximumPayloadBytes || payloadSize > uint64(reader.Len()) {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}
	payload := make([]byte, int(payloadSize))
	if _, err := io.ReadFull(reader, payload); err != nil || reader.Len() != 0 {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}
	if string(objectID) != expected.ObjectID || string(commandID) != expected.CommandID || !hmac.Equal(digest[:], expected.CommandDigest[:]) || binary.BigEndian.Uint32(claimIndex[:]) != expected.ClaimIndex || !validProtocolIdentifier(string(kind)) || len(payload) == 0 {
		return RawCapabilityClaims{}, ErrInvalidPermit
	}
	return RawCapabilityClaims{Kind: string(kind), Payload: append([]byte(nil), payload...)}, nil
}
