# Unit 10 external resource qualification — operator guide

This is the operator runbook for the Phase 0A workerd resource qualification
gate. The gate is `TestStockWorkerdResourceQualification` in
`internal/conformance/workerd`. It is explicit and off by default: it runs only
when `CIRCULUSD_WORKERD_QUALIFICATION_CONFIG` points at a private operator
qualification document on a provisioned host, and it skips otherwise (a skip is
never a PASS).

The gate certifies the **kernel-enforced** resource safety boundary — cgroup-v2
`cpu.max` throttling, `memory.max` OOM, and pidfd whole-shard `SIGKILL` with
reconstruction — because the pinned workerd's in-isolate limits are advisory
only (`limits.cpuMs` is parsed but not enforced, and no reachable in-isolate
fault destroys a Worker Loader isolate). See
[`workerd-cpums-not-enforced`](../SPEC.md) context and
`docs/implementation-plan.md`.

## Achievable bar

The gate exits successfully only when the four required results are non-mock
external `PASS` and the recorded residual-gap result is an honest `FAIL`, all
from one release-, config-, host-, boot-, cgroup-, runner-, and run-bound
evidence envelope:

| Result | Required | What it certifies |
|---|---|---|
| `workerd.cpu-limit` | PASS | exact `cpu.max` readback + observed `cpu.stat` throttling under a runaway worker + supervisor SIGKILL/recycle; records that in-isolate `cpuMs` did not fire |
| `workerd.rss-cold-start` | PASS | ≥5 cold starts, each with a nonzero pidfd-verified process RSS and a distinct nonzero cgroup memory charge at the exact shard identity |
| `workerd.shard-pressure-recycle` | PASS | real cgroup memory pressure driven to OOM at `memory.max`, then reconstruction from the acknowledged checkpoint into a new isolate |
| `workerd.shard-kill-reconstruction` | PASS | explicit whole-shard SIGKILL, then reconstruction from the acknowledged checkpoint into a new isolate |
| `workerd.dynamic-worker-reconstruction` | recorded FAIL | stock workerd does not reconstruct a Worker Loader isolate after an in-isolate fault; recorded, never skipped or promoted |

`AdmissionReady` stays false while the recorded per-isolate gap stands. Closing
it requires a re-pinned or rebuilt workerd that enforces per-isolate limits in
serve mode — separate, authorized infrastructure work.

## Host provisioning

The operator provisions the delegated cgroup-v2 root before the run; the harness
never creates or relaxes it. The root's ancestors are root-owned and
non-writable, the target is an empty cgroup-v2 domain owned by the runner's
effective UID/GID with mode `0700`, and `cpu`, `memory`, and `pids` are enabled
in its `cgroup.subtree_control`. Provision and run in **one** shell invocation —
manually created cgroups do not survive across separate sessions.

```sh
# as the runner (root here, for a single-host smoke)
echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
mkdir /sys/fs/cgroup/pi-qual
chown <uid>:<gid> /sys/fs/cgroup/pi-qual
chmod 0700 /sys/fs/cgroup/pi-qual
echo '+cpu +memory +pids' > /sys/fs/cgroup/pi-qual/cgroup.subtree_control
```

The host also needs cgroup-v2 `memory.max` enforcement with OOM (the pressure
probe drives a real OOM-kill), `clone3(CLONE_INTO_CGROUP)`, pidfd, and
`memfd_create` support. The evidence output directory must be canonical,
absolute, caller-owned, and mode `0700` (not group/other accessible).

## Qualification document

A private JSON document supplies only operator and host inputs — never
compatibility metadata, identities, or launch arguments. Bounds are enforced by
the parser.

```json
{
  "schemaVersion": 1,
  "releaseManifestPath": "/etc/pi-platform/release-manifest.json",
  "releaseTrustRootsPath": "/etc/pi-platform/release-trust-roots.json",
  "installedWorkerdPath": "/usr/lib/pi-platform/bin/workerd",
  "architecture": "x86_64",
  "cgroupRootPath": "/sys/fs/cgroup/pi-qual",
  "evidenceOutputDirectory": "/var/lib/pi-platform/qualification",
  "limits": {
    "cpuMaxQuotaMicros": 50000,
    "cpuMaxPeriodMicros": 100000,
    "memoryMaxBytes": 268435456,
    "memorySwapMaxBytes": 0,
    "pidsMax": 128
  },
  "timeoutsMillis": { "readiness": 15000, "probe": 60000, "drain": 20000, "total": 600000 },
  "coldStartSamples": 5
}
```

`installedWorkerdPath` must be a regular, executable, non-group/other-writable
file whose extracted digest matches the `workerd` artifact in the pinned release
manifest. Set `memoryMaxBytes` low enough that the pressure probe can reach OOM
(256 MiB is comfortable for stock workerd, whose serve RSS is ~50 MiB) and
`memorySwapMaxBytes` to 0 so anonymous growth cannot be swapped away from the
cap.

## Running the gate

```sh
env CIRCULUSD_WORKERD_QUALIFICATION_CONFIG=/private/path/workerd-qualification-v1.json \
  go test -count=1 \
  -run '^TestStockWorkerdResourceQualification$' \
  ./internal/conformance/workerd
```

On success the run retains a deterministic canonical-CBOR evidence artifact,
`workerd-resource-observation-v1.cbor`, in the evidence output directory (mode
`0600`, atomically via `renameat2(RENAME_NOREPLACE)`/`linkat`, read-back
verified). A run never replaces an existing artifact.

## What the gate does not do

- It does not promote §53.1, §53.3, §53.4, or any production install profile;
  the Session, checkpoint, and placement fixtures remain reference-only.
- It does not change `cmd/agentd` from diagnostic-only or make `AdmissionReady`
  true.
- The retained envelope is historical qualification evidence, not startup
  authority; no daemon consumes it to admit workloads.

## Negative control (the workerd-test path cannot satisfy this gate)

The older `workerd test` conformance path — `internal/conformance/workerd`'s
`Harness.Run` selected by the three binary environment variables
`CIRCULUSD_WORKERD_PATH`, `CIRCULUSD_WORKERD_SHA256`, and
`CIRCULUSD_WORKERD_VERSION` — reports every resource result as `NOT_RUN`; it has
no Manager/launcher/cgroup composition and its bounded test fixture carries no
spin, allocate, or state routes. Only the fully configured, provisioned resource
gate above produces the required resource results. This is asserted by
`TestResourceGateIsNotSatisfiedByTheWorkerdTestPath`.
