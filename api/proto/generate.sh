#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
API_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
REPOSITORY_ROOT=$(cd -- "$API_ROOT/.." && pwd)
GENERATED_ROOT="$API_ROOT/generated"
DESCRIPTOR_PATH="$API_ROOT/descriptors/circulus.v1alpha.pb"
DIGEST_PATH="$API_ROOT/descriptors/circulus.v1alpha.pb.sha256"

PROTOC_VERSION="libprotoc 3.21.12"
PROTOC_GEN_GO_VERSION="v1.36.10"
PROTOC_GEN_CONNECT_GO_VERSION="v1.19.1"

if [[ $(protoc --version) != "$PROTOC_VERSION" ]]; then
  echo "expected $PROTOC_VERSION, found $(protoc --version)" >&2
  exit 1
fi

TOOL_DIR=$(mktemp -d -t circulusd-proto-tools.XXXXXXXX)
BASELINE_DESCRIPTOR="$TOOL_DIR/baseline.pb"
cleanup() {
  rm -rf -- "$TOOL_DIR"
}
trap cleanup EXIT

if [[ -f "$DESCRIPTOR_PATH" ]]; then
  cp -- "$DESCRIPTOR_PATH" "$BASELINE_DESCRIPTOR"
fi

GOBIN="$TOOL_DIR" go install "google.golang.org/protobuf/cmd/protoc-gen-go@$PROTOC_GEN_GO_VERSION"
GOBIN="$TOOL_DIR" go install "connectrpc.com/connect/cmd/protoc-gen-connect-go@$PROTOC_GEN_CONNECT_GO_VERSION"

CHECK_ARGUMENTS=(
  --descriptor-out "$DESCRIPTOR_PATH"
  --digest-out "$DIGEST_PATH"
)
if [[ -f "$BASELINE_DESCRIPTOR" ]]; then
  CHECK_ARGUMENTS+=(--against "$BASELINE_DESCRIPTOR")
fi
python3 "$SCRIPT_DIR/check_contract.py" "${CHECK_ARGUMENTS[@]}"

mkdir -p -- "$GENERATED_ROOT"
protoc \
  --proto_path="$SCRIPT_DIR" \
  --plugin="protoc-gen-go=$TOOL_DIR/protoc-gen-go" \
  --plugin="protoc-gen-connect-go=$TOOL_DIR/protoc-gen-connect-go" \
  --go_out="$GENERATED_ROOT" \
  --go_opt=paths=source_relative \
  --connect-go_out="$GENERATED_ROOT" \
  --connect-go_opt=paths=source_relative \
  circulus/v1alpha/common.proto \
  circulus/v1alpha/session.proto \
  circulus/v1alpha/workspace.proto \
  circulus/v1alpha/sandbox.proto

gofmt -w "$GENERATED_ROOT"

echo "generated v1alpha API from pinned tools in $REPOSITORY_ROOT"
