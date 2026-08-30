package stateappclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/dependency"
)

const (
	productionProbePath         = "/circulusd/state/v1/production:probe"
	productionProbeContentType  = "application/vnd.circulusd.state-production-probe+cbor"
	productionProbeProtocol     = "circulus.state-production-probe.v1alpha1"
	productionProbeSchemaDigest = "sha256:33c8297cba9d6460e219e31e8c080927ed6275407c6eb159ea1f4d06fc87910f"

	maximumProductionProbeRequestBytes  = 256
	maximumProductionProbeRequestDepth  = 2
	maximumProductionProbeRequestItems  = 16
	maximumProductionProbeResponseBytes = 32 << 10
	maximumProductionProbeResponseDepth = 8
	maximumProductionProbeResponseItems = 128
	maximumProductionProbeAtomicGroups  = 64
)

// ProbeProduction challenges the celld-native runtime identity endpoint on
// the exact pinned origin and lifecycle owned by this Client. The request does
// not reuse read or dispatch HMAC authority: authenticity is established only
// when dependency.Verifier checks the returned Ed25519 proof.
func (client *Client) ProbeProduction(
	ctx context.Context,
	challenge dependency.ProbeChallenge,
) (dependency.ProbeResponse, error) {
	if ctx == nil || len(challenge.Nonce) != dependency.ChallengeBytes {
		return dependency.ProbeResponse{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return dependency.ProbeResponse{}, err
	}
	if client == nil || client.httpClient == nil {
		return dependency.ProbeResponse{}, ErrInvalidConfig
	}
	nonce := append([]byte(nil), challenge.Nonce...)
	body, err := canonical.Encode(canonical.Map{
		"protocol": productionProbeProtocol, "major": int64(1), "minor": int64(0),
		"schemaDigest": productionProbeSchemaDigest,
		"nonce":        canonical.Bytes(nonce),
	}, canonical.Options{
		MaxBytes: maximumProductionProbeRequestBytes,
		MaxDepth: maximumProductionProbeRequestDepth,
		MaxItems: maximumProductionProbeRequestItems,
	})
	if err != nil {
		return dependency.ProbeResponse{}, ErrInvalidRequest
	}

	requestContext, finish, err := client.beginActiveRequest(ctx)
	if err != nil {
		return dependency.ProbeResponse{}, err
	}
	defer finish()
	httpRequest, err := http.NewRequestWithContext(
		requestContext,
		http.MethodPost,
		client.endpoint+productionProbePath,
		bytes.NewReader(body),
	)
	if err != nil {
		return dependency.ProbeResponse{}, ErrInvalidRequest
	}
	httpRequest.Header.Set("Accept", productionProbeContentType)
	httpRequest.Header.Set("Cache-Control", "no-store")
	httpRequest.Header.Set("Content-Type", productionProbeContentType)

	response, err := client.httpClient.Do(httpRequest)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		client.lifecycleMu.Lock()
		closed := client.closed
		client.lifecycleMu.Unlock()
		if closed {
			return dependency.ProbeResponse{}, ErrClientClosed
		}
		if contextErr := requestContext.Err(); contextErr != nil {
			return dependency.ProbeResponse{}, fmt.Errorf("%w: %w", ErrTransport, contextErr)
		}
		return dependency.ProbeResponse{}, fmt.Errorf("%w: native production probe", ErrTransport)
	}
	defer response.Body.Close()
	contentTypes := response.Header.Values("Content-Type")
	cacheControls := response.Header.Values("Cache-Control")
	_, hasContentEncoding := response.Header[http.CanonicalHeaderKey("Content-Encoding")]
	_, hasApplicationKeyID := response.Header[http.CanonicalHeaderKey(keyIDHeader)]
	_, hasApplicationSignature := response.Header[http.CanonicalHeaderKey(signatureHeader)]
	if response.StatusCode != http.StatusOK ||
		len(contentTypes) != 1 || contentTypes[0] != productionProbeContentType ||
		len(cacheControls) != 1 || cacheControls[0] != "no-store" || hasContentEncoding ||
		hasApplicationKeyID || hasApplicationSignature {
		return dependency.ProbeResponse{}, ErrInvalidResponse
	}
	if response.ContentLength > maximumProductionProbeResponseBytes {
		return dependency.ProbeResponse{}, fmt.Errorf(
			"%w: production probe body exceeds %d bytes",
			ErrInvalidResponse,
			maximumProductionProbeResponseBytes,
		)
	}
	body, err = io.ReadAll(io.LimitReader(response.Body, maximumProductionProbeResponseBytes+1))
	if err != nil {
		client.lifecycleMu.Lock()
		closed := client.closed
		client.lifecycleMu.Unlock()
		if closed {
			return dependency.ProbeResponse{}, ErrClientClosed
		}
		if contextErr := requestContext.Err(); contextErr != nil {
			return dependency.ProbeResponse{}, fmt.Errorf("%w: %w", ErrTransport, contextErr)
		}
		return dependency.ProbeResponse{}, fmt.Errorf("%w: incomplete production probe body", ErrInvalidResponse)
	}
	if len(body) > maximumProductionProbeResponseBytes {
		return dependency.ProbeResponse{}, fmt.Errorf(
			"%w: production probe body exceeds %d bytes",
			ErrInvalidResponse,
			maximumProductionProbeResponseBytes,
		)
	}
	decoded, err := canonical.Decode(body, canonical.Options{
		MaxBytes: maximumProductionProbeResponseBytes,
		MaxDepth: maximumProductionProbeResponseDepth,
		MaxItems: maximumProductionProbeResponseItems,
	})
	if err != nil {
		return dependency.ProbeResponse{}, fmt.Errorf("%w: malformed production probe body", ErrInvalidResponse)
	}
	probe, err := decodeProductionProbeResponse(decoded, nonce)
	if err != nil {
		return dependency.ProbeResponse{}, err
	}
	if contextErr := requestContext.Err(); contextErr != nil {
		return dependency.ProbeResponse{}, contextErr
	}
	return probe, nil
}

func decodeProductionProbeResponse(
	value canonical.Value,
	nonce []byte,
) (dependency.ProbeResponse, error) {
	record, ok := value.(canonical.Map)
	if !ok || len(record) != 8 ||
		record["protocol"] != productionProbeProtocol ||
		record["major"] != int64(1) || record["minor"] != int64(0) ||
		record["schemaDigest"] != productionProbeSchemaDigest ||
		record["algorithm"] != "ed25519" {
		return dependency.ProbeResponse{}, ErrInvalidResponse
	}
	descriptorRecord, ok := record["descriptor"].(canonical.Map)
	if !ok || len(descriptorRecord) != 13 {
		return dependency.ProbeResponse{}, ErrInvalidResponse
	}
	schemaVersion, schemaVersionOK := descriptorRecord["schemaVersion"].(int64)
	backendKind, backendKindOK := descriptorRecord["backendKind"].(string)
	buildDigest, buildDigestOK := descriptorRecord["buildDigest"].(string)
	applicationDigest, applicationDigestOK := descriptorRecord["applicationDigest"].(string)
	instanceID, instanceIDOK := descriptorRecord["instanceId"].(string)
	transactionDomainID, transactionDomainIDOK := descriptorRecord["transactionDomainId"].(string)
	durabilityClass, durabilityClassOK := descriptorRecord["durabilityClass"].(string)
	conformanceRunID, conformanceRunIDOK := descriptorRecord["conformanceRunId"].(string)
	conformanceDigest, conformanceDigestOK := descriptorRecord["conformanceDigest"].(string)
	runtimeKeyID, runtimeKeyIDOK := descriptorRecord["runtimeKeyId"].(string)
	probeEpoch, probeEpochOK := descriptorRecord["probeEpoch"].(int64)
	productionEligible, productionEligibleOK := descriptorRecord["productionEligible"].(bool)
	groupValues, groupsOK := descriptorRecord["atomicGroups"].(canonical.Array)
	if !schemaVersionOK || schemaVersion != 1 || !backendKindOK || !buildDigestOK ||
		!applicationDigestOK || !instanceIDOK || !transactionDomainIDOK || !durabilityClassOK ||
		!conformanceRunIDOK || !conformanceDigestOK || !runtimeKeyIDOK || !probeEpochOK ||
		probeEpoch < 1 || !productionEligibleOK || !groupsOK || len(groupValues) == 0 ||
		len(groupValues) > maximumProductionProbeAtomicGroups {
		return dependency.ProbeResponse{}, ErrInvalidResponse
	}
	groups := make([]dependency.AtomicGroup, len(groupValues))
	for index, value := range groupValues {
		group, groupOK := value.(string)
		if !groupOK {
			return dependency.ProbeResponse{}, ErrInvalidResponse
		}
		groups[index] = dependency.AtomicGroup(group)
	}
	descriptor := dependency.Descriptor{
		SchemaVersion:       uint32(schemaVersion),
		BackendKind:         backendKind,
		BuildDigest:         buildDigest,
		ApplicationDigest:   applicationDigest,
		InstanceID:          instanceID,
		TransactionDomainID: transactionDomainID,
		DurabilityClass:     durabilityClass,
		ConformanceRunID:    conformanceRunID,
		ConformanceDigest:   conformanceDigest,
		RuntimeKeyID:        runtimeKeyID,
		ProbeEpoch:          uint64(probeEpoch),
		ProductionEligible:  productionEligible,
		AtomicGroups:        groups,
	}
	keyID, keyIDOK := record["keyId"].(string)
	signature, signatureOK := record["signature"].(canonical.Bytes)
	if !keyIDOK || keyID != descriptor.RuntimeKeyID || !signatureOK ||
		len(signature) != ed25519.SignatureSize {
		return dependency.ProbeResponse{}, ErrInvalidResponse
	}
	if _, err := dependency.ProbeSigningDigest(descriptor, nonce); err != nil {
		return dependency.ProbeResponse{}, ErrInvalidResponse
	}
	return dependency.ProbeResponse{
		Descriptor: descriptor,
		KeyID:      keyID,
		Signature:  append([]byte(nil), signature...),
	}, nil
}

var _ dependency.ProductionProbe = (*Client)(nil)
