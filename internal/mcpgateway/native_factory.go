package mcpgateway

import "context"

// MCPWireTransport is the lowest-level port reserved for an actual MCP
// transport. It handles bounded JSON-RPC bytes for an operator registry target,
// and has no admission, start-permit, cancellation or ledger authority.
// Arbitrary implementations are never accepted by NativeFactory. Its real
// anonymous HTTP adapter is constructed from an immutable concrete config.
type MCPWireTransport interface {
	Exchange(context.Context, MCPWireRequest) (MCPWireResponse, error)
}

type MCPWireRequest struct {
	TargetRef     string
	ConnectionRef string
	MessageJSON   []byte
}
type MCPWireResponse struct {
	ConnectionRef string
	MessageJSON   []byte
}

func (MCPWireRequest) String() string    { return "mcp-wire-request<redacted>" }
func (MCPWireRequest) GoString() string  { return "mcp-wire-request<redacted>" }
func (MCPWireResponse) String() string   { return "mcp-wire-response<redacted>" }
func (MCPWireResponse) GoString() string { return "mcp-wire-response<redacted>" }
