package celldbridge

import (
	"bytes"
	"crypto/ed25519"
	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
	"slices"
)

func descriptorValue(descriptor dependency.Descriptor) canonical.Map {
	groups := make(canonical.Array, len(descriptor.AtomicGroups))
	for i, group := range descriptor.AtomicGroups {
		groups[i] = string(group)
	}
	return canonical.Map{"schemaVersion": descriptor.SchemaVersion, "backendKind": descriptor.BackendKind, "buildDigest": descriptor.BuildDigest, "applicationDigest": descriptor.ApplicationDigest, "instanceId": descriptor.InstanceID, "transactionDomainId": descriptor.TransactionDomainID, "durabilityClass": descriptor.DurabilityClass, "conformanceRunId": descriptor.ConformanceRunID, "conformanceDigest": descriptor.ConformanceDigest, "runtimeKeyId": descriptor.RuntimeKeyID, "probeEpoch": descriptor.ProbeEpoch, "productionEligible": descriptor.ProductionEligible, "atomicGroups": groups}
}
func proofValue(proof dependency.ProbeResponse, nonce []byte) (canonical.Map, error) {
	if len(nonce) != dependency.ChallengeBytes || proof.KeyID != proof.Descriptor.RuntimeKeyID || len(proof.Signature) != ed25519.SignatureSize || (!slices.Contains(proof.Descriptor.AtomicGroups, AtomicNativeStorage) || !slices.Contains(proof.Descriptor.AtomicGroups, dependency.AtomicCommandReceipt)) {
		return nil, ErrInvalidResponse
	}
	if _, err := dependency.ProbeSigningDigest(proof.Descriptor, nonce); err != nil {
		return nil, ErrInvalidResponse
	}
	return canonical.Map{"protocol": probeProtocol, "major": int64(1), "minor": int64(0), "schemaDigest": probeSchema, "nonce": canonical.Bytes(append([]byte(nil), nonce...)), "descriptor": descriptorValue(proof.Descriptor), "keyId": proof.KeyID, "signature": canonical.Bytes(append([]byte(nil), proof.Signature...))}, nil
}
func proofFromValue(value canonical.Value, nonce []byte) (dependency.ProbeResponse, error) {
	var proof dependency.ProbeResponse
	m, ok := value.(canonical.Map)
	if !ok || len(m) != 8 || m["protocol"] != probeProtocol || m["major"] != int64(1) || m["minor"] != int64(0) || m["schemaDigest"] != probeSchema {
		return proof, ErrInvalidResponse
	}
	echo, ok := m["nonce"].(canonical.Bytes)
	if !ok || !bytes.Equal(echo, nonce) {
		return proof, ErrInvalidResponse
	}
	d, ok := m["descriptor"].(canonical.Map)
	if !ok || len(d) != 13 {
		return proof, ErrInvalidResponse
	}
	strings := map[string]*string{"backendKind": &proof.Descriptor.BackendKind, "buildDigest": &proof.Descriptor.BuildDigest, "applicationDigest": &proof.Descriptor.ApplicationDigest, "instanceId": &proof.Descriptor.InstanceID, "transactionDomainId": &proof.Descriptor.TransactionDomainID, "durabilityClass": &proof.Descriptor.DurabilityClass, "conformanceRunId": &proof.Descriptor.ConformanceRunID, "conformanceDigest": &proof.Descriptor.ConformanceDigest, "runtimeKeyId": &proof.Descriptor.RuntimeKeyID}
	for key, target := range strings {
		text, ok := d[key].(string)
		if !ok {
			return proof, ErrInvalidResponse
		}
		*target = text
	}
	version, ok := uintValue(d["schemaVersion"])
	if !ok || version != 1 {
		return proof, ErrInvalidResponse
	}
	proof.Descriptor.SchemaVersion = 1
	if proof.Descriptor.ProbeEpoch, ok = uintValue(d["probeEpoch"]); !ok || proof.Descriptor.ProbeEpoch == 0 {
		return proof, ErrInvalidResponse
	}
	proof.Descriptor.ProductionEligible, ok = d["productionEligible"].(bool)
	if !ok {
		return proof, ErrInvalidResponse
	}
	groups, ok := d["atomicGroups"].(canonical.Array)
	if !ok || len(groups) > 64 {
		return proof, ErrInvalidResponse
	}
	for _, value := range groups {
		text, ok := value.(string)
		if !ok {
			return proof, ErrInvalidResponse
		}
		proof.Descriptor.AtomicGroups = append(proof.Descriptor.AtomicGroups, dependency.AtomicGroup(text))
	}
	proof.KeyID, ok = m["keyId"].(string)
	if !ok {
		return proof, ErrInvalidResponse
	}
	sig, ok := m["signature"].(canonical.Bytes)
	if !ok {
		return proof, ErrInvalidResponse
	}
	proof.Signature = append([]byte(nil), sig...)
	if _, err := proofValue(proof, nonce); err != nil {
		return proof, err
	}
	return proof, nil
}
