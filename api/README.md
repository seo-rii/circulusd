# api

The versioned `v1alpha` wire contract: protobuf services and messages, the
generated Go code, the checked-in descriptor set, and the JSON Schemas for
machine-readable documents.

## Layout

| Path | Contents |
|---|---|
| `proto/circulus/v1alpha/*.proto` | Protobuf package `circulus.api.v1alpha`. These are the source of truth. |
| `generated/circulus/v1alpha/` | Go code from `protoc-gen-go`. Do not edit. |
| `generated/circulus/v1alpha/circulusv1alphaconnect/` | Go Connect code from `protoc-gen-connect-go`. Do not edit. |
| `descriptors/circulus.v1alpha.pb` and `.pb.sha256` | Compiled descriptor set and its SHA-256. |
| `json-schema/v1alpha/*.schema.json` | JSON Schema (draft 2020-12) documents, listed below. |
| `proto/check_contract.py` | Contract checker. `check_contract_test.py` holds its unit tests. |
| `proto/generate.sh` | Regenerates the descriptor and the Go code with pinned tools. |

The JSON Schemas are:

- `capabilities-response`
- `development-status`
- `doctor-report`
- `public-error`
- `release-manifest`
- `rpc-envelope`

## Services

| Service | File | Go implementation |
|---|---|---|
| `ControlService` | `common.proto` | server and client in `internal/controlrpc`; `internal/sandboxrpc` also serves it on the sandbox socket |
| `SandboxProcessService` | `sandbox.proto` | server and client in `internal/sandboxrpc` |
| `ReferenceWorkloadService` | `session.proto` | reference-only, in `internal/controlrpc`; no command enables it |
| `ExecutionProviderService` | `sandbox.proto` | none yet |
| `SessionStateService` | `session.proto` | none yet |
| `WorkspaceStateService` | `workspace.proto` | none yet |

Go code also uses messages from all four files directly, for example
`AgentCheckpoint` from `session.proto`.

## Descriptor digest

The SHA-256 in `descriptors/circulus.v1alpha.pb.sha256` is also hard-coded in
these files:

- `internal/controlrpc/protocol.go`
- `internal/sandboxrpc/protocol.go`
- `internal/doctoruds/probe_linux.go`
- `cmd/platformctl/main_test.go`

Peers reject a handshake whose descriptor digest differs. `generate.sh` does
not update these copies, so update them by hand after the descriptor changes.

## Check and regenerate

```sh
python3 api/proto/check_contract.py                 # validate; checks that the descriptor is current
python3 -m unittest api.proto.check_contract_test   # run from the repository root
api/proto/generate.sh                               # regenerate descriptor, digest and Go code
```

`check_contract.py` needs `protoc` and the Python `protobuf` package. If the
`jsonschema` package is missing, it skips the steps that use it.

`generate.sh` requires `protoc` to report exactly `libprotoc 3.21.12` (pinned
in `.tool-versions`). It installs `protoc-gen-go` v1.36.10 and
`protoc-gen-connect-go` v1.19.1 into a temporary directory. It then runs the
checker against the previous descriptor to check backward compatibility, and
finally runs `gofmt` on the generated tree.
