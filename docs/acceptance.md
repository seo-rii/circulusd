# Acceptance ledger

This ledger maps `SPEC.md` section 53 to its required evidence. Status is intentionally conservative:

- `PASS`: the exact required real implementation and environment passed;
- `FAIL`: the gate ran and failed;
- `UNAVAILABLE`: the gate cannot run in the current environment, with a reason;
- `NOT_RUN`: implementation or runner is not ready.

Only `PASS` satisfies a required release profile. Development fakes and unit launch-plan tests do not upgrade a real conformance status.

| SPEC | Area | Required evidence | Current status |
|---|---|---|---|
| §53.1 | Session/Pi/extension isolation | stock workerd, two sessions, eviction and stale generation suite | NOT_RUN |
| §53.2 | Single durable state machine | Session aggregate model/property tests and multi-tool serialization | NOT_RUN |
| §53.3 | Worker Loader | pinned workerd Loader ABI, outbound denial, cgroup and identity suite | NOT_RUN: pinned stock workerd passed content-addressed replacement, Dynamic Worker, isolate-separation, outbound-denial, and actual Pi `0.84.3` adapter checkpoint-reconstruction probes; stable broker binding and shard process recycle/cgroup pressure remain NOT_RUN |
| §53.4 | TurnAuthority/capability | generation, expiry, renewal and forged-scope suite | NOT_RUN |
| §53.5 | Effect recovery | kill-before/after full durable boundary matrix | NOT_RUN |
| §53.6 | Runtime Revision | candidate, migration, CAS activation and rollback suite | NOT_RUN |
| §53.7 | Environment resolution | conflict, artifact availability and immutable digest suite | NOT_RUN |
| §53.8 | Workspace filesystem | manifest, symlink, lease, read-only, overlay/full-scan suite | NOT_RUN |
| §53.9 | Workspace cross-DO commit | Workspace-ledger crash recovery without re-execution | NOT_RUN |
| §53.10 | NsJail | real namespace/seccomp/cgroup/network/cleanup suite | UNAVAILABLE: NsJail is not installed on this host |
| §53.11 | Docker | real daemon hardening/process/workspace suite | NOT_RUN: CLI exists; daemon access is unverified |
| §53.12 | Firecracker | real jailer/KVM/vsock/no-NIC/cleanup suite | UNAVAILABLE: Firecracker, jailer and `/dev/kvm` are absent |
| §53.13 | Backend coexistence | three real providers sharing one Workspace authority | NOT_RUN |
| §53.14 | MCP | selected-backend stdio and protocol/filter/restart suite | NOT_RUN |
| §53.15 | Secret | exposure-class, cleanup, audit and cache isolation suite | NOT_RUN |
| §53.16 | API/SSE | idempotency concurrency and durable replay suite | NOT_RUN |
| §53.17 | ACL/quota | cross-tenant, role and atomic quota rejection suite | NOT_RUN |
| §53.18 | Install/upgrade | clean network-denied profile installs and rollback suite | NOT_RUN |

## External qualification notes

- Pi Agent Core `0.84.3` and workerd `v1.20260825.1` remain short of the complete bounded-step Phase 0A gate. The digest-pinned stock workerd binary ran the actual ABI/state-v2 Pi adapter across four fresh engine/core instances over the checkpoint sequence `model -> external-tool -> model -> complete` and observed the complete extension hook sequence without Node compatibility flags. Model/tool settlements are injected inline by the fixture rather than dispatched through stable broker service bindings; no Dynamic Worker kill/recreation, shard recycle, cgroup pressure, CPU-limit, or RSS/cold-start gate has run. Those boundaries remain explicitly `NOT_RUN`.
- celld `v0.3.0` is pinned but remains alpha; its durability and ownership contract is a separate hard gate.
- SeaweedFS `4.44` is provisional. No self-hosted offline object store is currently qualified by celld, and MinIO Community Edition does not satisfy the required conditional-write contract.
- Release pins and known missing artifacts are recorded in `deploy/airgap/release-manifest.json`.
