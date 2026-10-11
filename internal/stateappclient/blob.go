package stateappclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

const (
	blobIngressPath          = "/circulusd/state/v1/session-blob:read"
	blobIngressContentType   = "application/vnd.circulusd.state-blob-ingress+cbor"
	blobIngressProtocol      = "circulus.state-blob-ingress.v1alpha1"
	blobIngressSchemaDigest  = "sha256:d9402c455a2d37e51885684aa26ade9d26ff444cc5a15fb89c2ce2af372e40e5"
	blobHostSchemaDigest     = "sha256:40be7ec7d4352285f697f042acf8bf38f8f30def0c0569ec8ff08535df0737a2"
	blobRequestMACDomain     = "circulusd.state-blob-ingress.request.v1"
	blobResponseMACDomain    = "circulusd.state-blob-ingress.response.v1"
	maximumSessionBlobBytes  = 4 << 20
	maximumBlobResponseBytes = maximumSessionBlobBytes + 65_536
)

type ReadSessionBlobRequest struct {
	TenantID                        string
	ActorSubjectID                  string
	SessionID                       string
	ExpectedAuthorizationGeneration uint64
	Digest                          string
}

// SessionBlob contains authenticated bytes whose length and SHA-256 digest have
// been checked against the request. Bytes is an independently owned snapshot of
// the stored payload; its encoding is defined by the payload's producer.
type SessionBlob struct {
	Digest       string
	EncodedBytes int
	Bytes        []byte
}

// ReadSessionBlob reads a blob authorized by the current session generation.
// A nil result and nil error mean the authorized session has no such blob.
func (client *Client) ReadSessionBlob(ctx context.Context, request ReadSessionBlobRequest) (*SessionBlob, error) {
	if ctx == nil {
		return nil, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if client == nil || client.httpClient == nil {
		return nil, ErrInvalidConfig
	}
	if _, err := identity.Parse(identity.Tenant, request.TenantID); err != nil {
		return nil, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Subject, request.ActorSubjectID); err != nil {
		return nil, ErrInvalidRequest
	}
	if _, err := identity.Parse(identity.Session, request.SessionID); err != nil ||
		request.ExpectedAuthorizationGeneration < 1 ||
		request.ExpectedAuthorizationGeneration > maximumSharedInteger ||
		!digestPattern.MatchString(request.Digest) ||
		request.Digest == "sha256:"+strings.Repeat("0", 64) {
		return nil, ErrInvalidRequest
	}

	rawResult, err := client.invokeAuthenticatedIngress(ctx, authenticatedIngressContract{
		path: blobIngressPath, contentType: blobIngressContentType,
		requestMACDomain: blobRequestMACDomain, responseMACDomain: blobResponseMACDomain,
		hostSchemaDigest: blobHostSchemaDigest,
		requestOptions: canonical.Options{
			MaxBytes: maximumRequestBytes, MaxDepth: maximumRequestDepth, MaxItems: maximumRequestItems,
		},
		maximumResponseBytes: maximumBlobResponseBytes,
	}, func(requestID string, sentAtUnixMS int64) canonical.Map {
		return canonical.Map{
			"protocol": blobIngressProtocol, "major": int64(1), "minor": int64(0),
			"schemaDigest": blobIngressSchemaDigest,
			"requestId":    requestID, "sentAtUnixMs": sentAtUnixMS,
			"tenantId": request.TenantID, "actorSubjectId": request.ActorSubjectID,
			"sessionId":                       request.SessionID,
			"expectedAuthorizationGeneration": request.ExpectedAuthorizationGeneration,
			"digest":                          request.Digest,
		}
	})
	if err != nil || rawResult == nil {
		return nil, err
	}
	result, ok := rawResult.(canonical.Map)
	if !ok || len(result) != 3 {
		return nil, ErrInvalidResponse
	}
	digest, digestOK := result["digest"].(string)
	encodedBytes, lengthOK := result["encodedBytes"].(int64)
	blob, bytesOK := result["bytes"].(canonical.Bytes)
	if !digestOK || digest != request.Digest || !lengthOK ||
		encodedBytes < 1 || encodedBytes > maximumSessionBlobBytes ||
		!bytesOK || int64(len(blob)) != encodedBytes {
		return nil, ErrInvalidResponse
	}
	sum := sha256.Sum256(blob)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return nil, ErrInvalidResponse
	}
	return &SessionBlob{Digest: digest, EncodedBytes: int(encodedBytes), Bytes: []byte(blob)}, nil
}
