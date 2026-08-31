#!/usr/bin/env python3
"""Compile and validate the v1alpha wire contract.

The checker deliberately uses descriptor data instead of matching source text.  It
also performs a conservative backward-compatibility comparison when passed an old
descriptor set with ``--against``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from google.protobuf import descriptor_pb2


API_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = API_ROOT.parent
PROTO_ROOT = API_ROOT / "proto"
SCHEMA_ROOT = API_ROOT / "json-schema" / "v1alpha"
CHECKED_DESCRIPTOR = API_ROOT / "descriptors" / "circulus.v1alpha.pb"
CHECKED_DIGEST = API_ROOT / "descriptors" / "circulus.v1alpha.pb.sha256"

PROTO_FILES = (
    "circulus/v1alpha/common.proto",
    "circulus/v1alpha/session.proto",
    "circulus/v1alpha/workspace.proto",
    "circulus/v1alpha/sandbox.proto",
)

SCHEMA_FILES = (
    "public-error.schema.json",
    "capabilities-response.schema.json",
    "development-status.schema.json",
    "rpc-envelope.schema.json",
    "release-manifest.schema.json",
)


class ContractError(RuntimeError):
    pass


def compile_descriptor(output: Path) -> descriptor_pb2.FileDescriptorSet:
    missing = [name for name in PROTO_FILES if not (PROTO_ROOT / name).is_file()]
    if missing:
        raise ContractError(f"missing proto files: {', '.join(missing)}")

    command = [
        "protoc",
        f"--proto_path={PROTO_ROOT}",
        "--include_imports",
        "--include_source_info",
        f"--descriptor_set_out={output}",
        *PROTO_FILES,
    ]
    completed = subprocess.run(command, cwd=PROTO_ROOT, capture_output=True, text=True)
    if completed.returncode:
        raise ContractError(completed.stderr.strip() or "protoc failed")

    descriptor_set = descriptor_pb2.FileDescriptorSet()
    descriptor_set.ParseFromString(output.read_bytes())
    return descriptor_set


def all_messages(descriptor_set: descriptor_pb2.FileDescriptorSet):
    result = {}

    def visit(prefix: str, messages):
        for message in messages:
            full_name = f"{prefix}.{message.name}"
            result[full_name] = message
            visit(full_name, message.nested_type)

    for file in descriptor_set.file:
        prefix = f".{file.package}" if file.package else ""
        visit(prefix, file.message_type)
    return result


def all_enums(descriptor_set: descriptor_pb2.FileDescriptorSet):
    result = {}

    def visit_message(prefix: str, messages):
        for message in messages:
            full_name = f"{prefix}.{message.name}"
            for enum in message.enum_type:
                result[f"{full_name}.{enum.name}"] = enum
            visit_message(full_name, message.nested_type)

    for file in descriptor_set.file:
        prefix = f".{file.package}" if file.package else ""
        for enum in file.enum_type:
            result[f"{prefix}.{enum.name}"] = enum
        visit_message(prefix, file.message_type)
    return result


def all_services(descriptor_set: descriptor_pb2.FileDescriptorSet):
    return {
        f".{file.package}.{service.name}": service
        for file in descriptor_set.file
        for service in file.service
    }


def field(message, name: str):
    for candidate in message.field:
        if candidate.name == name:
            return candidate
    raise ContractError(f"{message.name}.{name} is required")


def require_type(messages, message_name: str, field_name: str, expected_type: int):
    try:
        message = messages[message_name]
    except KeyError as error:
        raise ContractError(f"required message missing: {message_name}") from error
    actual = field(message, field_name).type
    if actual != expected_type:
        raise ContractError(
            f"{message_name}.{field_name} has descriptor type {actual}, expected {expected_type}"
        )


def require_type_name(messages, message_name: str, field_name: str, expected_name: str):
    try:
        message = messages[message_name]
    except KeyError as error:
        raise ContractError(f"required message missing: {message_name}") from error
    actual = field(message, field_name).type_name
    if actual != expected_name:
        raise ContractError(
            f"{message_name}.{field_name} has descriptor type {actual}, expected {expected_name}"
        )


def require_enum_values(enums, enum_name: str, expected_values: set[str]):
    try:
        enum = enums[enum_name]
    except KeyError as error:
        raise ContractError(f"required enum missing: {enum_name}") from error
    actual_values = {
        item.name for item in enum.value if not item.name.endswith("_UNSPECIFIED")
    }
    if actual_values != expected_values:
        raise ContractError(
            f"{enum_name} values are {sorted(actual_values)}, expected {sorted(expected_values)}"
        )


def validate_contract(descriptor_set: descriptor_pb2.FileDescriptorSet) -> None:
    messages = all_messages(descriptor_set)
    enums = all_enums(descriptor_set)
    services = all_services(descriptor_set)

    required_services = {
        ".circulus.api.v1alpha.ControlService",
        ".circulus.api.v1alpha.SessionStateService",
        ".circulus.api.v1alpha.WorkspaceStateService",
        ".circulus.api.v1alpha.ExecutionProviderService",
        ".circulus.api.v1alpha.SandboxProcessService",
    }
    missing_services = sorted(required_services - services.keys())
    if missing_services:
        raise ContractError(f"required services missing: {', '.join(missing_services)}")

    # Security identities, capabilities, and content digests remain opaque bytes.
    for message_name in (
        ".circulus.api.v1alpha.OpaqueId",
        ".circulus.api.v1alpha.Digest",
        ".circulus.api.v1alpha.EffectPreparationPermit",
        ".circulus.api.v1alpha.DispatchPermit",
        ".circulus.api.v1alpha.WorkspaceProtectionPermit",
    ):
        require_type(messages, message_name, "value", descriptor_pb2.FieldDescriptorProto.TYPE_BYTES)

    # Monotonic sequences, attempts, generations, limits, and deadlines have an
    # explicit unsigned 64-bit wire representation.
    for message_name, field_name in (
        (".circulus.api.v1alpha.HandshakeRequest", "maximum_frame_size"),
        (".circulus.api.v1alpha.SessionState", "event_sequence"),
        (".circulus.api.v1alpha.TurnLease", "lease_generation"),
        (".circulus.api.v1alpha.AgentCheckpoint", "checkpoint_sequence"),
        (".circulus.api.v1alpha.EngineStepBudget", "maximum_events"),
        (".circulus.api.v1alpha.EffectRecord", "dispatch_attempt"),
        (".circulus.api.v1alpha.DispatchPermit", "turn_lease_generation"),
        (".circulus.api.v1alpha.DispatchPermit", "dispatch_attempt"),
        (".circulus.api.v1alpha.DispatchPermit", "sandbox_generation"),
        (".circulus.api.v1alpha.DispatchPermit", "authorization_generation"),
        (".circulus.api.v1alpha.WorkspaceWriteLease", "lease_generation"),
        (".circulus.api.v1alpha.WorkspaceWriteLease", "renewal_sequence"),
        (".circulus.api.v1alpha.WorkspaceInvocationRecord", "base_revision"),
        (".circulus.api.v1alpha.ProcessHandle", "generation"),
        (".circulus.api.v1alpha.SpawnProcessRequest", "output_limit_bytes"),
    ):
        require_type(messages, message_name, field_name, descriptor_pb2.FieldDescriptorProto.TYPE_UINT64)

    require_enum_values(
        enums,
        ".circulus.api.v1alpha.CheckpointKind",
        {"CHECKPOINT_KIND_GENESIS", "CHECKPOINT_KIND_ENGINE"},
    )
    require_enum_values(
        enums,
        ".circulus.api.v1alpha.CheckpointPayloadEncoding",
        {
            "CHECKPOINT_PAYLOAD_ENCODING_PROTOBUF",
            "CHECKPOINT_PAYLOAD_ENCODING_CANONICAL_CBOR",
            "CHECKPOINT_PAYLOAD_ENCODING_OPAQUE_V1",
        },
    )
    require_enum_values(
        enums,
        ".circulus.api.v1alpha.TurnStatus",
        {
            "TURN_STATUS_QUEUED",
            "TURN_STATUS_ACTIVE",
            "TURN_STATUS_NEEDS_CONFIRMATION",
            "TURN_STATUS_COMPLETED",
            "TURN_STATUS_FAILED",
            "TURN_STATUS_ABORTED",
        },
    )
    require_enum_values(
        enums,
        ".circulus.api.v1alpha.EffectState",
        {
            "EFFECT_STATE_PREPARED",
            "EFFECT_STATE_DISPATCHED",
            "EFFECT_STATE_EXTERNALLY_COMMITTED",
            "EFFECT_STATE_SETTLED",
            "EFFECT_STATE_BLOCKED",
        },
    )

    checkpoint_name = ".circulus.api.v1alpha.AgentCheckpoint"
    expected_checkpoint_fields = {
        "kind",
        "engine_kind",
        "adapter_abi_version",
        "checkpoint_schema_version",
        "runtime_revision_digest",
        "session_id",
        "turn_id",
        "checkpoint_sequence",
        "predecessor_digest",
        "payload_encoding",
        "payload_bytes",
        "payload_digest",
    }
    actual_checkpoint_fields = {item.name for item in messages[checkpoint_name].field}
    if actual_checkpoint_fields != expected_checkpoint_fields:
        raise ContractError(
            "AgentCheckpoint fields do not match the protocol-types genesis/engine shape"
        )
    require_type(
        messages,
        checkpoint_name,
        "payload_bytes",
        descriptor_pb2.FieldDescriptorProto.TYPE_BYTES,
    )
    require_type_name(
        messages,
        checkpoint_name,
        "predecessor_digest",
        ".circulus.api.v1alpha.Digest",
    )
    for field_name in ("session_id", "turn_id"):
        require_type_name(
            messages,
            checkpoint_name,
            field_name,
            ".circulus.api.v1alpha.OpaqueId",
        )
    require_type_name(
        messages,
        checkpoint_name,
        "kind",
        ".circulus.api.v1alpha.CheckpointKind",
    )
    require_type_name(
        messages,
        checkpoint_name,
        "engine_kind",
        ".circulus.api.v1alpha.EngineKind",
    )
    require_type_name(
        messages,
        checkpoint_name,
        "payload_encoding",
        ".circulus.api.v1alpha.CheckpointPayloadEncoding",
    )

    require_type_name(
        messages,
        ".circulus.api.v1alpha.TurnState",
        "status",
        ".circulus.api.v1alpha.TurnStatus",
    )
    require_type_name(
        messages,
        ".circulus.api.v1alpha.EffectRecord",
        "state",
        ".circulus.api.v1alpha.EffectState",
    )

    session = messages[".circulus.api.v1alpha.SessionState"]
    session_fields = {item.name for item in session.field}
    for required in (
        "policy_snapshot_digest",
        "authorization_generation",
        "emergency_overlay_digest",
    ):
        if required not in session_fields:
            raise ContractError(f"SessionState.{required} is required by ADR-008")
    require_type_name(
        messages,
        ".circulus.api.v1alpha.SessionState",
        "policy_snapshot_digest",
        ".circulus.api.v1alpha.Digest",
    )
    require_type(
        messages,
        ".circulus.api.v1alpha.SessionState",
        "authorization_generation",
        descriptor_pb2.FieldDescriptorProto.TYPE_UINT64,
    )
    require_type_name(
        messages,
        ".circulus.api.v1alpha.SessionState",
        "emergency_overlay_digest",
        ".circulus.api.v1alpha.Digest",
    )
    for message_name, message in messages.items():
        if any(item.name == "policy_generation" for item in message.field):
            raise ContractError(
                f"{message_name}.policy_generation conflates immutable policy and live fencing"
            )

    required_dispatch_fields = {
        "tenant_id",
        "user_id",
        "session_id",
        "turn_id",
        "effect_id",
        "invocation_id",
        "request_digest",
        "service",
        "operation",
        "replay_policy",
        "dispatch_attempt",
        "turn_lease_generation",
        "placement_generation",
        "sandbox_generation",
        "authorization_generation",
        "deadline_unix_ms",
    }
    dispatch_fields = {
        item.name for item in messages[".circulus.api.v1alpha.DispatchPermit"].field
    }
    if not required_dispatch_fields <= dispatch_fields:
        missing = sorted(required_dispatch_fields - dispatch_fields)
        raise ContractError(f"dispatch permit is missing ADR-002 fields: {', '.join(missing)}")
    preparation_fields = {
        item.name
        for item in messages[".circulus.api.v1alpha.EffectPreparationPermit"].field
    }
    if not required_dispatch_fields <= preparation_fields:
        missing = sorted(required_dispatch_fields - preparation_fields)
        raise ContractError(
            f"effect preparation permit is missing bound claims: {', '.join(missing)}"
        )
    record_fields = {
        item.name for item in messages[".circulus.api.v1alpha.EffectRecord"].field
    }
    if not required_dispatch_fields <= record_fields:
        missing = sorted(required_dispatch_fields - record_fields)
        raise ContractError(f"effect record is missing ADR-002 fields: {', '.join(missing)}")

    engine_methods = {
        method.name
        for method in services[".circulus.api.v1alpha.SessionStateService"].method
    }
    for required in (
        "AcquireEngineStep",
        "CommitEngineEvent",
        "PrepareEffectRetry",
        "MarkEffectDispatched",
    ):
        if required not in engine_methods:
            raise ContractError(f"SessionStateService.{required} is required")
    if "PrepareEffect" in engine_methods:
        raise ContractError("PrepareEffect bypasses atomic checkpoint consumption/preparation")
    retry_response = messages[".circulus.api.v1alpha.PrepareEffectRetryResponse"]
    if field(retry_response, "preparation_permit").type_name != (
        ".circulus.api.v1alpha.EffectPreparationPermit"
    ):
        raise ContractError("effect retry recovery must return a preparation permit")

    commit_request_name = ".circulus.api.v1alpha.CommitEngineEventRequest"
    commit_request = messages[commit_request_name]
    require_type_name(
        messages,
        commit_request_name,
        "boundary",
        ".circulus.api.v1alpha.EngineStepBoundary",
    )
    if any(item.name in {"event", "assistant_delta"} for item in commit_request.field):
        raise ContractError("CommitEngineEvent cannot accept AgentEvent or assistant_delta")

    boundary_name = ".circulus.api.v1alpha.EngineStepBoundary"
    boundary = messages[boundary_name]
    if len(boundary.oneof_decl) != 1:
        raise ContractError("EngineStepBoundary must contain exactly one boundary oneof")
    boundary_fields = {
        item.name
        for item in boundary.field
        if item.HasField("oneof_index") and item.oneof_index == 0
    }
    expected_boundaries = {
        "checkpoint_only",
        "effect_request",
        "turn_complete",
        "turn_error",
    }
    if boundary_fields != expected_boundaries:
        raise ContractError(
            "EngineStepBoundary must be exactly checkpoint/effect_request/turn_complete/turn_error"
        )
    for field_name, type_name in (
        ("checkpoint_only", ".circulus.api.v1alpha.Empty"),
        ("effect_request", ".circulus.api.v1alpha.EffectIntent"),
        ("turn_complete", ".circulus.api.v1alpha.TurnResult"),
        ("turn_error", ".circulus.api.v1alpha.AgentError"),
    ):
        require_type_name(messages, boundary_name, field_name, type_name)
    require_type_name(
        messages,
        boundary_name,
        "checkpoint",
        ".circulus.api.v1alpha.AgentCheckpoint",
    )
    if field(boundary, "checkpoint").HasField("oneof_index"):
        raise ContractError("every boundary must carry checkpoint outside the boundary oneof")

    commit_response = messages[".circulus.api.v1alpha.CommitEngineEventResponse"]
    if field(commit_response, "preparation_permit").type_name != (
        ".circulus.api.v1alpha.EffectPreparationPermit"
    ) or field(commit_response, "prepared_effect").type_name != (
        ".circulus.api.v1alpha.EffectRecord"
    ):
        raise ContractError("effect preparation must share the checkpoint-consumption transaction")
    dispatch_response = messages[".circulus.api.v1alpha.MarkEffectDispatchedResponse"]
    if field(dispatch_response, "dispatch_permit").type_name != (
        ".circulus.api.v1alpha.DispatchPermit"
    ):
        raise ContractError("dispatch permit must be minted by the dispatched-state commit")
    permit_issuing_methods = set()
    for service_name, service in services.items():
        for method in service.method:
            output = messages.get(method.output_type)
            if output is not None and any(
                item.type_name == ".circulus.api.v1alpha.DispatchPermit"
                for item in output.field
            ):
                permit_issuing_methods.add(f"{service_name}.{method.name}")
    expected_issuer = {
        ".circulus.api.v1alpha.SessionStateService.MarkEffectDispatched"
    }
    if permit_issuing_methods != expected_issuer:
        raise ContractError(
            "only the MarkEffectDispatched durability barrier may issue DispatchPermit"
        )

    required_lease_fields = {
        "invocation_id",
        "request_digest",
        "effect_id",
        "session_id",
        "sandbox_id",
        "dispatch_attempt",
        "turn_lease_generation",
        "sandbox_generation",
        "projection_generation",
        "authorization_generation",
        "issued_at_unix_ms",
        "expires_at_unix_ms",
        "maximum_hold_deadline_unix_ms",
        "renewal_sequence",
        "enqueue_sequence",
    }
    lease_fields = {
        item.name for item in messages[".circulus.api.v1alpha.WorkspaceWriteLease"].field
    }
    if not required_lease_fields <= lease_fields:
        missing = sorted(required_lease_fields - lease_fields)
        raise ContractError(f"workspace lease is missing ADR-005 fields: {', '.join(missing)}")
    protection_fields = {
        item.name
        for item in messages[".circulus.api.v1alpha.WorkspaceProtectionPermit"].field
    }
    if not required_lease_fields <= protection_fields:
        missing = sorted(required_lease_fields - protection_fields)
        raise ContractError(
            f"workspace protection permit is missing lease fencing fields: {', '.join(missing)}"
        )
    for message_name in (
        ".circulus.api.v1alpha.WorkspaceWriteLease",
        ".circulus.api.v1alpha.WorkspaceProtectionPermit",
    ):
        for field_name in (
            "dispatch_attempt",
            "turn_lease_generation",
            "sandbox_generation",
            "projection_generation",
            "authorization_generation",
            "issued_at_unix_ms",
            "expires_at_unix_ms",
            "maximum_hold_deadline_unix_ms",
            "renewal_sequence",
            "enqueue_sequence",
        ):
            require_type(
                messages,
                message_name,
                field_name,
                descriptor_pb2.FieldDescriptorProto.TYPE_UINT64,
            )
    require_type(
        messages,
        ".circulus.api.v1alpha.RenewWorkspaceLeaseRequest",
        "next_renewal_sequence",
        descriptor_pb2.FieldDescriptorProto.TYPE_UINT64,
    )
    require_type(
        messages,
        ".circulus.api.v1alpha.WorkspaceLeaseQueued",
        "enqueue_sequence",
        descriptor_pb2.FieldDescriptorProto.TYPE_UINT64,
    )
    acquire_response = messages[".circulus.api.v1alpha.AcquireWorkspaceProtectionResponse"]
    if "queued" not in {item.name for item in acquire_response.field}:
        raise ContractError("workspace lease acquisition must expose its FIFO queued outcome")
    renew_response = messages[".circulus.api.v1alpha.RenewWorkspaceLeaseResponse"]
    require_type(
        messages,
        ".circulus.api.v1alpha.RenewWorkspaceLeaseResponse",
        "idempotent_retry",
        descriptor_pb2.FieldDescriptorProto.TYPE_BOOL,
    )

    process_methods = {
        method.name
        for method in services[".circulus.api.v1alpha.SandboxProcessService"].method
    }
    for required in ("Spawn", "Attach", "WriteStdin", "CloseStdin", "Signal", "Wait"):
        if required not in process_methods:
            raise ContractError(f"SandboxProcessService.{required} is required")


def in_reserved_range(message, number: int) -> bool:
    return any(item.start <= number < item.end for item in message.reserved_range)


def compare_compatible(
    baseline: descriptor_pb2.FileDescriptorSet,
    candidate: descriptor_pb2.FileDescriptorSet,
) -> None:
    old_messages = all_messages(baseline)
    new_messages = all_messages(candidate)
    for name, old_message in old_messages.items():
        if name not in new_messages:
            raise ContractError(f"backward incompatible: removed message {name}")
        new_message = new_messages[name]
        new_by_number = {item.number: item for item in new_message.field}
        for old_field in old_message.field:
            new_field = new_by_number.get(old_field.number)
            if new_field is None:
                if not in_reserved_range(new_message, old_field.number):
                    raise ContractError(
                        f"backward incompatible: {name} removed field {old_field.number} "
                        "without reserving its number"
                    )
                continue
            if (
                new_field.name != old_field.name
                or new_field.type != old_field.type
                or new_field.type_name != old_field.type_name
                or new_field.label != old_field.label
            ):
                raise ContractError(
                    f"backward incompatible: changed {name} field {old_field.number}"
                )

    old_enums = all_enums(baseline)
    new_enums = all_enums(candidate)
    for name, old_enum in old_enums.items():
        if name not in new_enums:
            raise ContractError(f"backward incompatible: removed enum {name}")
        current = {(item.name, item.number) for item in new_enums[name].value}
        for item in old_enum.value:
            if (item.name, item.number) not in current:
                raise ContractError(
                    f"backward incompatible: removed enum value {name}.{item.name}={item.number}"
                )

    old_services = all_services(baseline)
    new_services = all_services(candidate)
    for name, old_service in old_services.items():
        if name not in new_services:
            raise ContractError(f"backward incompatible: removed service {name}")
        new_methods = {item.name: item for item in new_services[name].method}
        for old_method in old_service.method:
            current = new_methods.get(old_method.name)
            if current is None:
                raise ContractError(
                    f"backward incompatible: removed method {name}.{old_method.name}"
                )
            old_shape = (
                old_method.input_type,
                old_method.output_type,
                old_method.client_streaming,
                old_method.server_streaming,
            )
            new_shape = (
                current.input_type,
                current.output_type,
                current.client_streaming,
                current.server_streaming,
            )
            if new_shape != old_shape:
                raise ContractError(
                    f"backward incompatible: changed method shape {name}.{old_method.name}"
                )


def self_test_compatibility(candidate: descriptor_pb2.FileDescriptorSet) -> None:
    incompatible = descriptor_pb2.FileDescriptorSet()
    incompatible.CopyFrom(candidate)
    opaque_id = all_messages(incompatible)[".circulus.api.v1alpha.OpaqueId"]
    del opaque_id.field[:]
    try:
        compare_compatible(candidate, incompatible)
    except ContractError:
        pass
    else:
        raise ContractError("compatibility checker accepted an unreserved field removal")


def self_test_contract(candidate: descriptor_pb2.FileDescriptorSet) -> None:
    def expect_rejection(broken: descriptor_pb2.FileDescriptorSet, description: str):
        try:
            validate_contract(broken)
        except ContractError:
            return
        raise ContractError(f"contract self-test accepted {description}")

    missing_dispatch_attempt = descriptor_pb2.FileDescriptorSet()
    missing_dispatch_attempt.CopyFrom(candidate)
    dispatch = all_messages(missing_dispatch_attempt)[
        ".circulus.api.v1alpha.DispatchPermit"
    ]
    kept_fields = [item for item in dispatch.field if item.name != "dispatch_attempt"]
    del dispatch.field[:]
    dispatch.field.extend(kept_fields)
    expect_rejection(missing_dispatch_attempt, "a permit without dispatch_attempt")

    missing_checkpoint = descriptor_pb2.FileDescriptorSet()
    missing_checkpoint.CopyFrom(candidate)
    boundary = all_messages(missing_checkpoint)[
        ".circulus.api.v1alpha.EngineStepBoundary"
    ]
    kept_fields = [item for item in boundary.field if item.name != "checkpoint"]
    del boundary.field[:]
    boundary.field.extend(kept_fields)
    expect_rejection(missing_checkpoint, "a durable boundary without checkpoint")

    durable_delta = descriptor_pb2.FileDescriptorSet()
    durable_delta.CopyFrom(candidate)
    boundary = all_messages(durable_delta)[".circulus.api.v1alpha.EngineStepBoundary"]
    assistant_delta = boundary.field.add()
    assistant_delta.name = "assistant_delta"
    assistant_delta.number = 99
    assistant_delta.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    assistant_delta.type = descriptor_pb2.FieldDescriptorProto.TYPE_BYTES
    assistant_delta.oneof_index = 0
    expect_rejection(durable_delta, "a durable assistant_delta boundary")

    invalid_effect_state = descriptor_pb2.FileDescriptorSet()
    invalid_effect_state.CopyFrom(candidate)
    effect_state = all_enums(invalid_effect_state)[".circulus.api.v1alpha.EffectState"]
    unknown = effect_state.value.add()
    unknown.name = "EFFECT_STATE_UNKNOWN"
    unknown.number = 99
    expect_rejection(invalid_effect_state, "an UNKNOWN effect state")

    missing_renewal_fence = descriptor_pb2.FileDescriptorSet()
    missing_renewal_fence.CopyFrom(candidate)
    lease = all_messages(missing_renewal_fence)[
        ".circulus.api.v1alpha.WorkspaceWriteLease"
    ]
    kept_fields = [item for item in lease.field if item.name != "renewal_sequence"]
    del lease.field[:]
    lease.field.extend(kept_fields)
    expect_rejection(missing_renewal_fence, "a workspace lease without renewal_sequence")


def validate_json_schemas() -> None:
    missing = [name for name in SCHEMA_FILES if not (SCHEMA_ROOT / name).is_file()]
    if missing:
        raise ContractError(f"missing JSON Schemas: {', '.join(missing)}")

    try:
        import jsonschema
    except ImportError:
        jsonschema = None

    schemas = {}
    for name in SCHEMA_FILES:
        path = SCHEMA_ROOT / name
        with path.open(encoding="utf-8") as source:
            schema = json.load(source)
        schemas[name] = schema
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise ContractError(f"{name}: expected JSON Schema draft 2020-12")
        if not str(schema.get("$id", "")).endswith(f"/v1alpha/{name}"):
            raise ContractError(f"{name}: versioned canonical $id is required")
        if jsonschema is not None:
            jsonschema.Draft202012Validator.check_schema(schema)

        nodes: list[tuple[str, object]] = [("$", schema)]
        while nodes:
            node_path, node = nodes.pop()
            if isinstance(node, dict):
                if node.get("type") == "integer":
                    maximum = node.get("maximum")
                    if (
                        not isinstance(maximum, int)
                        or isinstance(maximum, bool)
                        or maximum > 9_007_199_254_740_991
                    ):
                        raise ContractError(
                            f"{name}:{node_path} must cap integers at the "
                            "TypeScript safe-integer maximum"
                        )
                nodes.extend(
                    (f"{node_path}.{key}", child) for key, child in node.items()
                )
            elif isinstance(node, list):
                nodes.extend(
                    (f"{node_path}[{index}]", child)
                    for index, child in enumerate(node)
                )

    release_statuses = set(
        schemas["release-manifest.schema.json"]["properties"]["release"]["properties"][
            "status"
        ]["enum"]
    )
    expected_release_statuses = {"development", "candidate", "production"}
    if release_statuses != expected_release_statuses:
        raise ContractError(
            "release-manifest.schema.json status must match the Go release contract"
        )

    if jsonschema is not None:
        digest = "sha256:" + ("0" * 64)
        examples = {
            "public-error.schema.json": {
                "apiVersion": "v1alpha",
                "code": "stale_generation",
                "reason": "STALE_PLACEMENT_GENERATION",
                "message": "the caller no longer owns this placement",
                "retryable": False,
                "requestId": "req_example",
            },
            "capabilities-response.schema.json": {
                "apiVersion": "v1alpha",
                "protocol": {
                    "major": 1,
                    "minor": 0,
                    "descriptorDigest": digest,
                    "maximumFrameSize": 1048576,
                },
                "agentIsolation": [],
                "executionBackends": {
                    "nsjail": {
                        "status": {"availability": "available"},
                        "hostKernelShared": True,
                        "features": ["process-streaming"],
                    },
                    "docker": {
                        "status": {
                            "availability": "unavailable",
                            "reason": "Docker is not installed",
                        },
                        "hostKernelShared": True,
                        "features": [],
                    },
                    "firecracker": {
                        "status": {
                            "availability": "unavailable",
                            "reason": "KVM is not available",
                        },
                        "hostKernelShared": False,
                        "features": [],
                    },
                },
                "executionEnvironments": [],
                "resourceProfiles": [],
                "extensions": [],
                "models": [],
                "mcpServers": [],
            },
            "development-status.schema.json": {
                "apiVersion": "v1alpha",
                "profile": "development-reference",
                "mode": "diagnostic-only",
                "productionEligible": False,
                "admissionEnabled": False,
                "state": {
                    "availability": "unavailable",
                    "reason": "NOT_WIRED",
                    "implementation": "none",
                    "durability": "none",
                },
                "execution": {
                    "availability": "unavailable",
                    "reason": "NOT_WIRED",
                    "provider": "none",
                    "isolationConformance": "NOT_RUN",
                },
            },
            "rpc-envelope.schema.json": {
                "apiVersion": "v1alpha",
                "kind": "request",
                "requestId": "req_example",
                "protocolVersion": {"major": 1, "minor": 0},
                "descriptorDigest": digest,
                "requestDigest": digest,
                "deadlineUnixMs": 1000,
                "payload": {},
            },
        }
        for name, example in examples.items():
            try:
                jsonschema.Draft202012Validator(schemas[name]).validate(example)
            except jsonschema.ValidationError as error:
                raise ContractError(f"{name}: valid example rejected: {error.message}") from error

        unsafe_error = dict(examples["public-error.schema.json"])
        unsafe_error["capability"] = "raw-secret"
        if jsonschema.Draft202012Validator(
            schemas["public-error.schema.json"]
        ).is_valid(unsafe_error):
            raise ContractError("public-error.schema.json accepted an unknown sensitive field")

        development_validator = jsonschema.Draft202012Validator(
            schemas["development-status.schema.json"]
        )
        dishonest_statuses = []
        for field in ("productionEligible", "admissionEnabled"):
            status = json.loads(json.dumps(examples["development-status.schema.json"]))
            status[field] = True
            dishonest_statuses.append(status)
        wired_state = json.loads(
            json.dumps(examples["development-status.schema.json"])
        )
        wired_state["state"]["implementation"] = "memory"
        dishonest_statuses.append(wired_state)
        for status in dishonest_statuses:
            if development_validator.is_valid(status):
                raise ContractError(
                    "development-status.schema.json accepted a production or wired claim"
                )

    release_manifest = REPOSITORY_ROOT / "deploy" / "airgap" / "release-manifest.json"
    if jsonschema is not None and release_manifest.is_file():
        release_schema = schemas["release-manifest.schema.json"]
        release_instance = json.loads(release_manifest.read_text())
        validator = jsonschema.Draft202012Validator(
            release_schema,
            format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER,
        )
        try:
            validator.validate(release_instance)
        except jsonschema.ValidationError as error:
            raise ContractError(
                f"deploy/airgap/release-manifest.json: {error.message}"
            ) from error

        signed_release = json.loads(json.dumps(release_instance))
        valid_signature = {
            "algorithm": "ed25519",
            "keyId": "test-release-key",
            "value": ("A" * 86) + "==",
        }
        signed_release["toolchains"]["protocGenGo"] = "1.36.10"
        signed_release["toolchains"]["protocGenConnectGo"] = "1.19.1"
        existing_components = {
            component["name"] for component in signed_release["components"]
        }
        component_template = json.loads(json.dumps(signed_release["components"][0]))
        for component_name in (
            "platformd",
            "agentd",
            "executord",
            "sandboxd",
            "workerd",
            "celld",
        ):
            if component_name not in existing_components:
                component = json.loads(json.dumps(component_template))
                component["name"] = component_name
                component["version"] = "0.3.0"
                component["source"] = f"https://example.invalid/{component_name}"
                signed_release["components"].append(component)
        for component in signed_release["components"]:
            if not component["artifacts"]:
                component["artifacts"] = [
                    {
                        "architecture": "any",
                        "name": f"{component['name']}.tar.zst",
                        "sha256": "0" * 64,
                        "signature": valid_signature,
                    }
                ]
            else:
                for artifact in component["artifacts"]:
                    artifact["signature"] = valid_signature
        signed_release["protocolCompatibility"] = [
            {
                "pair": pair,
                "minimum": {"major": 1, "minor": 0},
                "maximum": {"major": 1, "minor": 0},
                "descriptorSha256": "0" * 64,
            }
            for pair in (
                "platformd-agentd",
                "platformd-executord",
                "session-host-dynamic-worker",
                "executord-sandboxd",
                "state-app-schema",
            )
        ]
        signed_release["signatures"] = [valid_signature]
        signed_release["unresolvedArtifacts"] = []

        for status in ("candidate", "production"):
            gated_release = json.loads(json.dumps(signed_release))
            gated_release["release"]["status"] = status
            try:
                validator.validate(gated_release)
            except jsonschema.ValidationError as error:
                raise ContractError(
                    f"release-manifest.schema.json rejected signed {status}: {error.message}"
                ) from error
            del gated_release["signatures"]
            if validator.is_valid(gated_release):
                raise ContractError(
                    f"release-manifest.schema.json accepted unsigned {status} release"
                )

        duplicate_pair_release = json.loads(json.dumps(signed_release))
        duplicate_pair_release["release"]["status"] = "candidate"
        duplicate_pair_release["protocolCompatibility"][-1]["pair"] = (
            duplicate_pair_release["protocolCompatibility"][0]["pair"]
        )
        duplicate_pair_release["protocolCompatibility"][-1][
            "descriptorSha256"
        ] = "1" * 64
        if validator.is_valid(duplicate_pair_release):
            raise ContractError(
                "release-manifest.schema.json accepted duplicate protocol pairs"
            )

        unresolved_release = json.loads(json.dumps(signed_release))
        unresolved_release["release"]["status"] = "candidate"
        unresolved_release["unresolvedArtifacts"] = ["missing sandbox rootfs"]
        if validator.is_valid(unresolved_release):
            raise ContractError(
                "release-manifest.schema.json accepted unresolved candidate artifacts"
            )

        artifactless_release = json.loads(json.dumps(signed_release))
        artifactless_release["release"]["status"] = "production"
        artifactless_release["components"][0]["artifacts"] = []
        if validator.is_valid(artifactless_release):
            raise ContractError(
                "release-manifest.schema.json accepted an artifactless production component"
            )

        unsigned_artifact_release = json.loads(json.dumps(signed_release))
        unsigned_artifact_release["release"]["status"] = "candidate"
        del unsigned_artifact_release["components"][0]["artifacts"][0]["signature"]
        if validator.is_valid(unsigned_artifact_release):
            raise ContractError(
                "release-manifest.schema.json accepted an unsigned candidate artifact"
            )

        short_signature_release = json.loads(json.dumps(signed_release))
        short_signature_release["release"]["status"] = "production"
        short_signature_release["signatures"][0]["value"] = "AA=="
        if validator.is_valid(short_signature_release):
            raise ContractError(
                "release-manifest.schema.json accepted a malformed Ed25519 signature"
            )

        missing_generator_release = json.loads(json.dumps(signed_release))
        missing_generator_release["release"]["status"] = "candidate"
        del missing_generator_release["toolchains"]["protocGenGo"]
        if validator.is_valid(missing_generator_release):
            raise ContractError(
                "release-manifest.schema.json accepted a candidate without pinned generators"
            )

        invalid_components = []
        missing_commit_release = json.loads(json.dumps(release_instance))
        del missing_commit_release["components"][0]["commit"]
        invalid_components.append(("a component without commit", missing_commit_release))
        non_https_release = json.loads(json.dumps(release_instance))
        non_https_release["components"][0]["source"] = "ftp://example.invalid/source"
        invalid_components.append(("a non-HTTPS source", non_https_release))
        backslash_artifact_release = json.loads(json.dumps(release_instance))
        backslash_artifact_release["components"][0]["artifacts"][0]["name"] = (
            "directory\\artifact.tar.zst"
        )
        invalid_components.append(
            ("a backslash-containing artifact name", backslash_artifact_release)
        )
        for description, invalid_release in invalid_components:
            if validator.is_valid(invalid_release):
                raise ContractError(
                    f"release-manifest.schema.json accepted {description}"
                )


def validate_checked_descriptor(descriptor_bytes: bytes) -> None:
    if not CHECKED_DESCRIPTOR.is_file() or not CHECKED_DIGEST.is_file():
        raise ContractError("checked descriptor set or its digest is missing; run generate.sh")
    if CHECKED_DESCRIPTOR.read_bytes() != descriptor_bytes:
        raise ContractError("checked descriptor set is stale; run generate.sh")

    digest = hashlib.sha256(descriptor_bytes).hexdigest()
    digest_line = CHECKED_DIGEST.read_text(encoding="ascii").strip()
    expected_line = f"{digest}  circulus.v1alpha.pb"
    if digest_line != expected_line:
        raise ContractError("checked descriptor digest is stale or malformed; run generate.sh")


def load_descriptor(path: Path) -> descriptor_pb2.FileDescriptorSet:
    descriptor_set = descriptor_pb2.FileDescriptorSet()
    descriptor_set.ParseFromString(path.read_bytes())
    return descriptor_set


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--against", type=Path, help="old descriptor set to compare")
    parser.add_argument("--descriptor-out", type=Path, help="write the compiled descriptor set")
    parser.add_argument("--digest-out", type=Path, help="write the descriptor SHA-256")
    arguments = parser.parse_args()

    try:
        with tempfile.TemporaryDirectory(prefix="circulus-api-") as directory:
            temporary_descriptor = Path(directory) / "circulus.v1alpha.pb"
            candidate = compile_descriptor(temporary_descriptor)
            validate_contract(candidate)
            self_test_contract(candidate)
            self_test_compatibility(candidate)
            validate_json_schemas()
            if arguments.against:
                compare_compatible(load_descriptor(arguments.against), candidate)

            descriptor_bytes = temporary_descriptor.read_bytes()
            if not arguments.descriptor_out and not arguments.digest_out:
                validate_checked_descriptor(descriptor_bytes)
            if arguments.descriptor_out:
                arguments.descriptor_out.parent.mkdir(parents=True, exist_ok=True)
                arguments.descriptor_out.write_bytes(descriptor_bytes)
            if arguments.digest_out:
                digest = hashlib.sha256(descriptor_bytes).hexdigest()
                arguments.digest_out.parent.mkdir(parents=True, exist_ok=True)
                arguments.digest_out.write_text(f"{digest}  circulus.v1alpha.pb\n", encoding="ascii")
    except (ContractError, OSError, ValueError) as error:
        print(f"contract check failed: {error}", file=sys.stderr)
        return 1

    print("v1alpha API contract is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
