package stateappclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/hancomac/circulusd/internal/canonical"
	"github.com/hancomac/circulusd/internal/identity"
)

const (
	ProviderResultPath              = "/circulusd/state/v1/provider-result:read"
	ProviderResultContentType       = "application/vnd.circulusd.provider-result+cbor"
	ProviderResultProtocol          = "circulus.provider-result.v1alpha1"
	ProviderResultRequestMACDomain  = "circulusd.provider-result.request.v1"
	ProviderResultResponseMACDomain = "circulusd.provider-result.response.v1"
	MaximumProviderResultBytes      = 1 << 20
	providerResultDescriptor        = "circulus.provider-result.v1alpha1|major=1|minor=0|immutable-committed-normalized-result|fields=protocol,major,minor,schemaDigest,requestId,sentAtUnixMs,tenantId,workspaceId,sessionId,effectId,invocationId,requestDigest,externalCommitId,resultRef|result=request,payloadDigest,canonicalCbor|maxRequestBytes=4096|maxPayloadBytes=1048576"
)

var providerResultSchemaDigest = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(providerResultDescriptor)))

// ProviderResultSchemaDigest identifies this fixed read-only wire contract.
func ProviderResultSchemaDigest() string { return providerResultSchemaDigest }

type ProviderResultRequest struct {
	TenantID, WorkspaceID, SessionID, EffectID, InvocationID string
	RequestDigest, ExternalCommitID, ResultRef               string
}

type ProviderResult struct {
	Request       ProviderResultRequest
	PayloadDigest string
	CanonicalCBOR []byte
}

func (ProviderResultRequest) String() string { return "provider-result-request<redacted>" }
func (ProviderResult) String() string        { return "provider-result<redacted>" }
func (ProviderResult) GoString() string      { return "provider-result<redacted>" }

func ValidateProviderResultRequest(request ProviderResultRequest) error {
	for kind, value := range map[identity.Kind]string{
		identity.Tenant: request.TenantID, identity.Workspace: request.WorkspaceID,
		identity.Session: request.SessionID, identity.Effect: request.EffectID,
		identity.Invocation: request.InvocationID, identity.Commit: request.ExternalCommitID,
		identity.Artifact: request.ResultRef,
	} {
		if _, err := identity.Parse(kind, value); err != nil {
			return ErrInvalidRequest
		}
	}
	if !digestPattern.MatchString(request.RequestDigest) || request.RequestDigest == "sha256:"+fmt.Sprintf("%064x", 0) {
		return ErrInvalidRequest
	}
	return nil
}

// ReadProviderResult reads already committed, normalized bytes. It performs no
// provider invocation, artifact mutation, retry, or settlement. The same Client
// owns its pinned origin, request lifecycle and native production challenge.
// Use a separately configured provider endpoint/credential; a Session read key
// and a test endpoint do not qualify a provider's durable result implementation.
func (client *Client) ReadProviderResult(ctx context.Context, request ProviderResultRequest) (ProviderResult, error) {
	if ctx == nil {
		return ProviderResult{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return ProviderResult{}, err
	}
	if client == nil || client.httpClient == nil {
		return ProviderResult{}, ErrInvalidConfig
	}
	if err := ValidateProviderResultRequest(request); err != nil {
		return ProviderResult{}, err
	}
	value, err := client.invokeAuthenticatedIngress(ctx, authenticatedIngressContract{
		path: ProviderResultPath, contentType: ProviderResultContentType,
		requestMACDomain: ProviderResultRequestMACDomain, responseMACDomain: ProviderResultResponseMACDomain,
		hostSchemaDigest: providerResultSchemaDigest,
		requestOptions:   canonical.Options{MaxBytes: 4096, MaxDepth: 3, MaxItems: 64},
	}, func(requestID string, sentAt int64) canonical.Map {
		body := providerResultRequestValue(request)
		body["protocol"], body["major"], body["minor"] = ProviderResultProtocol, int64(1), int64(0)
		body["schemaDigest"], body["requestId"], body["sentAtUnixMs"] = providerResultSchemaDigest, requestID, sentAt
		return body
	})
	if err != nil {
		return ProviderResult{}, err
	}
	record, ok := value.(canonical.Map)
	if !ok || len(record) != 3 {
		return ProviderResult{}, ErrInvalidResponse
	}
	echo, ok := record["request"].(canonical.Map)
	if !ok || len(echo) != 8 {
		return ProviderResult{}, ErrInvalidResponse
	}
	for key, value := range providerResultRequestValue(request) {
		text, ok := echo[key].(string)
		if !ok || text != value {
			return ProviderResult{}, ErrInvalidResponse
		}
	}
	digest, ok := record["payloadDigest"].(string)
	if !ok || !digestPattern.MatchString(digest) {
		return ProviderResult{}, ErrInvalidResponse
	}
	payload, ok := record["canonicalCbor"].(canonical.Bytes)
	if !ok || len(payload) < 1 || len(payload) > MaximumProviderResultBytes || fmt.Sprintf("sha256:%x", sha256.Sum256(payload)) != digest {
		return ProviderResult{}, ErrInvalidResponse
	}
	if _, err := canonical.Decode(payload, canonical.Options{MaxBytes: MaximumProviderResultBytes, MaxDepth: 64, MaxItems: 100_000}); err != nil {
		return ProviderResult{}, ErrInvalidResponse
	}
	return ProviderResult{Request: request, PayloadDigest: digest, CanonicalCBOR: bytes.Clone(payload)}, nil
}

func providerResultRequestValue(request ProviderResultRequest) canonical.Map {
	return canonical.Map{"tenantId": request.TenantID, "workspaceId": request.WorkspaceID, "sessionId": request.SessionID,
		"effectId": request.EffectID, "invocationId": request.InvocationID, "requestDigest": request.RequestDigest,
		"externalCommitId": request.ExternalCommitID, "resultRef": request.ResultRef}
}
