# Unit 11 external celld durability qualification — operator guide

This is the operator runbook for the Phase 0B celld durability qualification
gate — the single external blocker for closing Unit 11's §53.2/§53.5 promotions
and, through it, Unit 12's durable public Repository (U12.4) and served listener
(U12.5). The gate is `Qualify` in `internal/conformance/celld` (component
`state.celld`); it is explicit and off by default. Without a provisioned,
pinned celld process driving a real `DurabilityProbe` it returns `UNAVAILABLE`,
never `PASS`, and a reference or mock probe can only produce reference-only
(non-promotable) evidence. `UNAVAILABLE`/reference is never a `PASS`.

The gate certifies the **celld durability and single-writer contract**
(`SPEC.md` §15.8) and the **object-store conditional-write/CAS contract**
(§16.1) that the durable state plane depends on. The reference-first Session and
public-Repository aggregates (`internal/sessionstate`, `internal/platformapi/celldrepo`)
prove the recovery and idempotency LOGIC host-independently over an in-memory
reference `celld.Storage`, but that storage commits at transaction time and does
not prove an fsync-equivalent barrier. Only this gate, run against a real celld,
attests durability.

## Required durability checks

`celld.RequiredChecks()` enumerates the properties a provisioned celld must
prove; all must hold for the gate to `PASS`.

| Check | SPEC | What it certifies |
|---|---|---|
| `single-writer` | §15.8 | one writer owns each object; a late write from a prior owner is rejected |
| `atomic-durable-commit` | §15.8 | a committed transaction is atomic and durable (fsync-equivalent) before the commit is acknowledged |
| `durability-barrier` | §15.8 | the commit-before-dispatch barrier confirms success only after the commit is durable |
| `object-store-cas` | §16.1 | object-store conditional-write / ETag compare-and-set is proven end to end |
| `read-your-writes` | §15.8 | a committed write is visible to a subsequent read on the same object |

A check that cannot run yields `UNAVAILABLE`; a check that does not hold yields
`FAIL`; all checks holding yields `PASS` with evidence whose class reflects
whether the probe was a real external host (`external`) or a reference one
(`reference-only`, `mock:true`, rejected by any production profile).

## Host provisioning

The operator provisions, before the run, a pinned celld process and a real
object store the harness never creates or relaxes:

- **celld** `v0.3.0` is the current pin (alpha; its durability and ownership
  contract is a separate hard gate — see `docs/acceptance.md` and
  `deploy/airgap/release-manifest.json`). The process must expose its
  celld-native runtime identity endpoint (the signed production-probe path
  challenged by `internal/stateappclient`), and its build digest must match the
  `celld` artifact in the pinned release manifest.
- **object store** with a real conditional-write/CAS contract for §16.1.
  SeaweedFS `4.44` is provisional; MinIO Community Edition does **not** satisfy
  the required conditional-write contract, so it cannot back this gate. No
  self-hosted offline object store is currently qualified.

The durability check that drives `atomic-durable-commit` and `durability-barrier`
must observe a real crash window (power-loss-equivalent), so the host must
support the fault-injection the probe uses to kill celld between commit and
barrier and confirm the acknowledged state survives.

## Production admission wiring

A durability `PASS` is consumed by the fail-closed production bootstrap
(`internal/statebootstrap`), not by a standalone flag. The state stanza selects
celld and points at the signed evidence and trust roots:

```yaml
state:
  provider: celld
  endpoint: http://127.0.0.1:8080        # or unix:///run/pi-platform/celld.sock
  instanceId: <celld instance id>
  transactionDomainId: <transaction domain id>
  minimumProbeEpoch: <monotone floor>
  maximumEvidenceAge: 24h
  productionEvidenceFile: /etc/pi-platform/state/celld-evidence.json
  conformanceRootsFile: /etc/pi-platform/state/conformance-roots.json
  runtimeRootsFile: /etc/pi-platform/state/runtime-roots.json
  readKeyId: <read authority key id>
  readRootKeyFile: /etc/pi-platform/state/read-roots.json
  dispatchStartKeyId: <dispatch-start authority key id>
  dispatchStartRootKeyFile: /etc/pi-platform/state/dispatch-start-roots.json
```

At startup the bootstrap authenticates the pinned release artifacts, seals the
production requirements — including the required atomic domain
(`command-receipt` + `effect-lifecycle`), the instance and transaction-domain
identities, the minimum probe epoch, and the maximum evidence age — loads the
production proof from `productionEvidenceFile`/`conformanceRootsFile`/`runtimeRootsFile`,
constructs the state-app client, and challenges the celld-native production
probe. The probe must return a signed Ed25519 `Descriptor` whose
`durabilityClass`, `conformanceRunId`/`conformanceDigest`, `atomicGroups`, and
`productionEligible` satisfy the sealed requirements. Any missing, stale
(epoch/age), or unmet field fails startup closed, leaving only the diagnostic
control plane.

The durability qualification `PASS` from this gate is the out-of-band evidence
that a compliant `celld-evidence.json` attests. This gate proves the durability
contract; the bootstrap proves the served graph consumes only a signed,
fresh, requirement-meeting attestation of it.

## What the gate does not do

- It does not promote §53.2, §53.4, §53.5, or §53.16 by itself; the Session,
  checkpoint, placement, and public-Repository fixtures remain reference-only
  until a real external `PASS` is produced and consumed by a served graph.
- It does not wire `state.celld` (`state.celld` stays `NOT_WIRED`), and it does
  not make `AdmissionReady` true. `AdmissionReady` stays false until this gate
  returns a fresh external `PASS`, the real `broker.DurableStore`/celld-backed
  `platformapi.Repository` composition closes, and the public HTTP/SSE listener
  is served (U12.5).
- The reference-first aggregates (`internal/sessionstate`,
  `internal/platformapi/celldrepo`) and the durable-Repository conformance gate
  (`internal/conformance/publicrepo`) exercise the LOGIC only; they cannot
  satisfy this gate and never carry external evidence.

## Negative control (a reference or mock probe cannot satisfy this gate)

`celld.Qualify(ctx, nil)` returns `UNAVAILABLE`, and a probe whose `Provenance`
marks it a reference sets `mock:true`, `evidenceClass: reference-only`, and
clears the binary/environment digests, so any production profile rejects it
(`conformance.Collector.Evaluate`). The same rejection applies to the durable
public Repository: `internal/platformapi/celldrepo` run over the reference
`celld.Storage` reports `CrashDurable:false` and FAILs the `crash-durable`
check of `internal/conformance/publicrepo`. Only a real celld host with a real
object store, producing an `external` `PASS`, promotes anything.
