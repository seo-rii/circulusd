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

### Native completion sequence

The user selected this machine for isolated qualification. A dedicated
loopback SeaweedFS 4.44 service and private bucket now hold an actual stock
celld v0.3.0 deployment. The service uses a new owner-only directory on `/data`;
existing containers, buckets and deployment targets are outside this run.
Actual stock CAS, process recovery and response-loss observations are retained
separately from the completed storage-only native-fork qualification described
below. A passing stock experiment does not authorize production admission.

The stock runtime must first be measured with a real bucket deployment. Do not
use `CELLD_TEST_SCRIPT_PATH`: that path starts without replication, and its
native durability wait can acknowledge immediately. Select bucket durability,
an active replicator and the fetch output gate, then verify acknowledged writes
after process kill/restart and after restoration into an empty local directory.
Conditional-write conformance must use the provider's actual opaque ETag, not
the reference filesystem Store's SHA-256 content identifier.

The stock peer probe signs node/advertise/challenge under a different domain.
It cannot supply circulusd's production descriptor. Under the current SPEC,
the native runtime must handle the reserved state and native-storage probe
routes before WebSocket or Worker dispatch, using their distinct frozen CBOR
envelopes. A separate proxy signer cannot replace that requirement. A reviewed
native patch is therefore required to finish source qualification. Such a fork
is a new release artifact; do not assign it the stock archive SHA or silently
replace the existing signed release selection.

The minimal patch must retain the full SHA of the actually loaded application
bytes and its effective binding/configuration graph, seal an immutable native
snapshot before runtime publication, handle bounded native probe requests,
and invalidate it on application/key/domain/lifecycle changes. The upstream
16-character deployment version is not a full application digest. Keep native
private keys outside Worker vars and require independently verified fresh
conformance evidence; caller-provided eligibility, atomic groups or PASS flags
cannot establish native authority.

An independent driver first measures the exact executable/extraction,
application and storage configuration while admission stays closed. Its raw
fault results form a report digest that excludes the later evidence envelope
and live challenge. A separate issuer verifies that report and the selected
release, source/domain and reserved fresh epoch. Native boot rechecks the
measurements and evidence before publishing its snapshot. Restart then closes
the entire consumer graph and fences the prior operation credentials before
fresh evidence/bootstrap; changing an epoch or closing TCP alone does not stop
an old HTTP client from reconnecting.

### Preparing a selected isolated target

`go run ./cmd/objectstore-qualify --config /absolute/path/s3-probe.json
--output /absolute/private/directory/new-report.json` checks an explicitly
selected existing S3 bucket. It creates a nonce-scoped `.doctor/cas-*` object,
performs conditional writes and a 32-contender CAS, opens a fresh client and
conditionally cleans up only its own observed data. The report directory must
be owner-only and the output must be new. The command provisions no bucket and
uses only the configured credential file or named AWS environment variables;
it performs real bucket writes when executed.

The configuration is an exact JSON object:

```json
{
  "schemaVersion": 1,
  "endpoint": "http://127.0.0.1:29931",
  "region": "us-east-1",
  "bucket": "circulusd-native-qualification",
  "credentials": { "source": "file", "file": "/absolute/private/s3-credentials.json" },
  "requestTimeoutMillis": 5000,
  "probeTimeoutMillis": 30000,
  "cleanupTimeoutMillis": 5000,
  "maximumObjectBytes": 1048576
}
```

These are example local target values; use the selected run's private bucket
and credentials, never a shared bucket by substitution. The private credential JSON contains `accessKeyId`,
`secretAccessKey` and optional `sessionToken`; its owner and permissions are
checked. An alternative `credentials: { "source": "environment" }` reads only
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and optional `AWS_SESSION_TOKEN`.
No SDK default credential discovery, proxy or redirect is used. SDK retries
are disabled, and an ambiguous mutation is not retried.
The SDK preserves native quoted ETags. Cleanup confirms logical absence; a
versioned bucket may still retain old versions. A CAS report does not certify
celld process durability, prove server-restart persistence or enable admission.

`node scripts/prepare-native-storage.mjs --config /absolute/private/storage.json
--output /absolute/private/new-project` builds a self-contained Worker and
native Durable Object deployment project without deploying it. Its private
configuration contains exactly `schemaVersion: 1`, `keyId`, `rootKeyHex` (the
32-byte operational HMAC key), all seven `bounds` fields, `timeoutMs`, a real
`compatibilityDate` and sorted unique modeled `compatibilityFlags`. It accepts
no native signer key, proof or descriptor. Input must be an owner-only regular
file; output must be a new directory under an owned parent that is not writable
by other users. The
generated project directory is 0700 and its bundle, Wrangler configuration
and manifest files are 0600. Both reserved probe paths return unsigned 404
when called directly on the Worker.

The builder's `bundleDigest` measures its prepared file only. `celld deploy`
runs esbuild again; native qualification must separately measure the exact
bytes actually deployed and loaded. The manifest explicitly says
`PREPARATION_ONLY`, `stockCelldSufficient: false` and `admissionReady: false`.
After target selection, create the dedicated object store and bucket, perform
CAS qualification, deploy this project through the verified native CLI, then
start bucket-backed nodes and run the actual process-fault matrix. The stock
runtime and native fork require separately measured release selections.

### Selected-machine observations and native handoff

The private run `.codex/native-storage-qualification/local/run-v37k2up7`
uses S3 `127.0.0.1:29931` and celld `127.0.0.1:29932`. Anonymous S3 requests
are rejected. The store's loopback/owner-only Unix peers are explicitly allowed,
and its 64 MB volume size retains the 1 GiB free-space floor. The private store
now permits four volume slots, including space for system metadata. The initial
root-disk capacity failure caused real native self-fencing; it was not recorded
as a successful injected SIGKILL. Only this run's store files were copied to a
new private `/data` directory with every copied file's digest checked.

The actual deployed main module is 59,617 bytes with full SHA
`sha256:1719d6592159027b446b5434af31f59879199662b63217108e43b3efb0b2a7ef`.
This differs from the prepared bundle's digest. Native conditional-write checks
passed against the running store. Actual stock state/receipt/barrier recovery
passed after a SIGKILL with the same local directory, after restoration into an
empty directory, and again after the machine reboot. A second actual SIGKILL
followed by empty-directory recovery also passed. An immediate startup request
failed before readiness; the later successful read is retained separately.
Application stale-CAS rejection and one dropped successful backend response
were observed directly. The response-loss driver recovered committed state,
receipt and a fresh barrier; it does not qualify provider effect dispatch.

`cmd/celld-storage-observe` records bounded raw phase facts, while
`cmd/native-owner-observe` holds an actual native ownership read after an LTX
upload so an independent owner can take over. The latter experiment must reject
the still-live prior writer and retain actual native ownership bodies/ETags and
process observations. A stale application revision or stale S3 ETag cannot
stand in for that ownership experiment.

The stock owner experiment completed in 12.37 seconds. The prior owner uploaded
an actual LTX with HTTP 200; exactly one following ownership GET was held. After
SIGSTOP and lease expiry, the new owner claimed CELL epoch 6→7 and committed
revision 3→4. The ownership read was released while the prior process remained
stopped and returned the new owner's exact body/ETag. Resuming the prior process
produced a native `SELF-FENCE` exit 3 and one unacknowledged client request; the
new owner's revision and state SHA remained unchanged after a fresh barrier.
`owner-experiment/experiment-with-termination.json` retains these stock-only
facts, including the actual termination line. The relay preserves canonical
`%3A` in real native CELL keys and the original signed Host/path. A later bounded
capacity pilot admitted 20 additional CELLs, leaving 16 owned by B and five by A;
it did not release the seed CELL and supplied no capacity-handoff PASS.

`deploy/native-celld` contains the separately built, measured native producer.
`cmd/celld-storage-issue` accepts independently signed raw observations and a
separate storage-only executable selection. Four distinct release, observation,
conformance and runtime roots are configured privately for this run. Its final
process starts in `attest` mode without evidence, writes an actual boot
measurement and initially serves unsigned 404. The independent issuer must
verify all faults and the still-running final process before a one-time report
and evidence handoff publishes the native descriptor without restart. Every
restart burns a larger epoch and requires new facts. The existing nine-part
platform release and full served graph remain separate admission gates.

The first full fork build was stopped by its memory budget; focused native
proof tests passed but supplied no full executable. After the machine reboot,
the pinned build was restarted with a private disk cache and completed with
exit 0 in 15 minutes 32 seconds. The new 63,319,056-byte raw executable has SHA
`sha256:292c6753b45bf0a1bc42c5928c49be0ed048fb32fb43c00e697ccc10ece64adc`.
A separate signed storage-only selection pins it and the actual loaded module.
The fork served one actual acknowledged seed/state/receipt/barrier observation:
native generation 16, PID 747699, revision 1, state SHA
`sha256:d1a480f031438ddc8d676ec875ebf94ac8e41e5fded274fb247e61b03e0ae5c4`.
That seed is retained in `reports/native-seed-0e0efd9ab5211616.json` and does not
establish crash durability. Native generations 9, 16 and 17 all terminated with
`SELF-FENCE` exit 3 after an ambiguous lease-renewal attempt of about 2,501 ms,
including attempts with 10-second and 15-second lease TTLs. These exits are not
injected SIGKILLs or successful recovery observations. Generation 18 also
self-fenced after its unsigned state and native-storage probes both correctly
returned 404; the negative controls do not establish signed probe publication.

The repeated lease failures are now traced to the dedicated SeaweedFS store's
volume-slot exhaustion. Its two bucket volumes filled `-volume.max=2`, leaving
no writable volume in the default collection used for system metadata logs.
The actual provider binary identifies commit
`3563738699f29fd1c9efde6fcbf4ba253439cac8`, with `vcs.modified=false`.
The pinned source assigns metadata uploads by
[collection](https://github.com/seaweedfs/seaweedfs/blob/3563738699f29fd1c9efde6fcbf4ba253439cac8/weed/filer/filer_notify_append.go),
retries failed flushes every
[737 ms](https://github.com/seaweedfs/seaweedfs/blob/3563738699f29fd1c9efde6fcbf4ba253439cac8/weed/filer/filer_notify.go),
and blocks producers when its
[16-window queue](https://github.com/seaweedfs/seaweedfs/blob/3563738699f29fd1c9efde6fcbf4ba253439cac8/weed/util/log_buffer/log_buffer.go)
fills. `ObjectTransaction` retains an exclusive path lock across mutation and
metadata notification; GET needs the same lock in
[shared mode](https://github.com/seaweedfs/seaweedfs/blob/3563738699f29fd1c9efde6fcbf4ba253439cac8/weed/server/filer_grpc_server.go).
The completed diagnostic dump shows seven transaction writers blocked in
`queueFlush`. An independent 90-GET trace initially recorded 30 successes in
1–4 ms, then two-second timeouts that continued after native celld exited.
This establishes the provider capacity cause; isolate-retirement timing alone
does not establish an isolate-runtime cause.

Only this run's private store controller was changed to `-volume.max=4`, whose
[limit counts volumes](https://github.com/seaweedfs/seaweedfs/blob/3563738699f29fd1c9efde6fcbf4ba253439cac8/weed/command/server.go).
Existing volume files and the free-space floor were preserved. The old store
blocked during SIGTERM and completed an intentional diagnostic SIGQUIT with
exit 2; its dump is `/home/seorii/logs/circulusd-local-store-qe25i6by.log`.
The replacement store, PID 775008, created writable default-collection volumes
27/28. Native generation 19, PID 988299, with resident limit 2, TTL 15 seconds
and two Tokio threads, completed a 204.11-second diagnostic and exited 0 after
an owned SIGTERM. All 41 lease attempts applied, with no ambiguous result and
a maximum duration of 12 ms. The root isolate was freed without self-fencing.
The two default volumes grew to 9,851/26,967 bytes, confirming metadata flushes.
A new actual 32-contender provider CAS run also passed with one winner,
31 precondition failures and three stale-operation 412 results.
The native executable, application graph and lease checks are unchanged.
The fresh native fault chain completed with exit 0: generation 20, actual
PID 2291966, acknowledged seed revision 1 and was SIGKILLed; generation 21,
PID 2581521, recovered the state/receipt/barrier using watch 20 and was
SIGKILLed; generation 23, PID 2835395, recovered using a fresh watch. All five
seed/recovery/stale-CAS/response-loss phases retained no errors. Its unsigned
state/native-storage probes both returned 404. The manifest is
`reports/native-fault-chain-d76e45d4ce58.json`; its new seed is
`reports/native-seed-78546e676d4c81d8.json`. Final B's response-loss phase
advanced seed revision 1→2 before the owner trial.

The actual native owner trial then completed in 12.15 seconds. With A absent,
exactly two nonce-scoped disposable objects induced real demand shedding:
the seed's `own.json` changed from B/epoch 3 to an empty node/epoch 3. Newly
measured A22, PID 1601344, reclaimed the same CELL at epoch 4 by read/barrier,
preserving revision 2/state. B explicitly evicted one disposable, retaining its
owner record, and freed a resident slot. A's real LTX upload returned 200;
exactly one following proof GET was held. A was SIGSTOPped, its actual lease
expiry was observed, and still-running B23 took epoch 5 and committed revision
3→4. Releasing the proof GET while A remained stopped returned B's exact
body/ETag. CONT produced actual SELF-FENCE exit 3 and one HTTP 0/UNAVAILABLE
request without acknowledgement. B's revision 4/state remained unchanged
after a fresh barrier, serial 8→9.
`owner-native/owner-trial-result.json` retains the protocol/process facts and
actual termination bytes. A and the relay have exited; B remained live for the
independent issuer and subsequent native publication.

Stage 1 storage-only qualification on this machine is complete. Independent
raw assembly, observation signing, conformance issuance, immutable publication
and live verification all exited 0. The final verifier, actual PID 3946724
(supervisor 3945880), verified fresh independent nonces and signatures with
HTTP 200 from both `/circulusd/state/v1/production:probe` and
`/circulusd/native-storage/v1/production:probe`. Both described the same live
B23/PID 2835395, process-start tick 454970 and runtime probe epoch 23. The
retained report is `reports/native-probe-verify-575896e0b8.json`; its status is
`jobs/native-probe-verify-fdc84599e6.json`, exit 0, and completed log is
`/home/seorii/logs/circulusd-local-native-probe-verify-ehbm_j7_.log`.
The raw report digest is
`sha256:6a316ce7137620a368b069a1bf4bea1333165f0bea9590cac0a18217270b5ae4`;
the issued evidence digest is
`sha256:6c2a870e21759f4407e2061de1f988fa716edf5ebd488e909c615eb5895795e3`.
`native-23/issued-evidence.json` records issue time 1791649636 and expiry
1791734416 (Unix seconds). Its exact atomic groups are `command-receipt` and
`native-storage`; `productionEligible` applies to that measured storage source.
The verification report retains `platformAdmissionReady: false` and
`productionDependencyMinted: false`. It does not qualify the full Session app,
Loader execution, provider sources or nine-part platform release, and promotes
no full §53 profile. Production admission remains closed.

The independent issuer requires response-loss to start from the original seed
revision/state. Run seed, the two recoveries, stale-CAS and response-loss before
the pending-owner write experiment; do not replace the retained baseline with
later state. If an empty-directory frontdoor forwards to a separately restored
owner, retain the owner's actual boot/root and readback facts and describe that
route explicitly; an HTTP success alone does not prove frontdoor-local restore.
The complete local Go race/vet/diff gate now covers 88 packages and passed.
Production admission remains closed. The selected machine's storage-only stage
is complete; served execution and operational enforcement have not started.

## Production admission wiring

A durability `PASS` is consumed by the fail-closed production bootstrap
(`internal/statebootstrap`), not by a standalone flag. The state stanza selects
celld and points at the signed evidence and trust roots:

```yaml
state:
  provider: celld
  endpoint: http://127.0.0.1:8080
  instanceId: <celld instance id>
  transactionDomainId: <transaction domain id>
  minimumProbeEpoch: <monotone floor>
  maximumEvidenceAge: 24h
  productionEvidenceFile: /etc/pi-platform/state/celld-evidence.json
  conformanceRootsFile: /etc/pi-platform/state/conformance-roots.json
  runtimeRootsFile: /etc/pi-platform/state/runtime-roots.json
  readKeyId: <read authority key id>
  readRootKeyFile: /run/credentials/pi-platform/state-read.key
  dispatchStartKeyId: <dispatch-start authority key id>
  dispatchStartRootKeyFile: /run/credentials/pi-platform/state-dispatch-start.key
  admissionKeyId: <turn-admission authority key id>
  admissionRootKeyFile: /run/credentials/pi-platform/state-admission.key
  brokerKeyId: <internal broker authority key id>
  brokerRootKeyFile: /run/credentials/pi-platform/state-broker.key
  httpTimeout: 5s
  dispatchStartTimeout: 30s
```

The four operation credential files contain separate canonical hexadecimal
root keys, not trust-root JSON. They must use distinct key IDs, files/inodes,
and key material. Admission credentials authorize the typed public-turn
planning and admission operations. Broker credentials authorize the fixed Session broker operations;
they do not expand the read, dispatch-start or public-admission key roles.
Loading credentials does not qualify an executable genesis provider or enable
the public listener. The current transport accepts a literal
loopback HTTP endpoint; Unix endpoints are not supported by this client.

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

## Complete Session broker adapter

`internal/stateappbroker.Store` implements every `broker.DurableStore` operation
through the fixed signed endpoint
`POST /circulusd/state/v1/session-broker:execute`. The fourth credential role is
exclusive to this operation union. Configure its current/previous IDs and key
material under `CIRCULUSD_STATE_BROKER_{CURRENT,PREVIOUS}_KEY_ID` and `_KEY`;
configured read, dispatch-start, admission and broker roles may not alias IDs
or material. This describes configuration inputs, not a provisioning action.

The trusted host also requires `CIRCULUSD_STATE_BROKER_POLICY`, as an immutable
object or JSON string with exactly this shape:

```json
{"engineStepLimits":{"maximumEvents":1,"maximumEphemeralBytes":1048576,"maximumWallClockMs":5000},"preparationTTLms":30000}
```

Missing policy fails closed. The Store's immutable limits must match this host
policy. Times and budgets use integral milliseconds; callers must supply
millisecond-aligned clocks rather than rely on truncation. All scope IDs are
typed, and the immutable actor/user and authorization generation must match the
Session. PublicError strings and metadata must already be NFC: the adapter
rejects values that would otherwise change during canonical encoding.

`statebootstrap.Graph.SessionBroker(ctx, config)` constructs a scoped Store,
performs a fresh native challenge on its actual private client, and requires the
same verified command-receipt/effect-lifecycle domain as the event reader. A
success settlement additionally requires an independently verified
`ResultResolver` for the full tenant/workspace/session/effect/invocation/request/
external-commit/artifact identity. Its canonical body and digest are checked
before the Session mutation. The authenticated read transport and qualified
record-to-Pi resolver are described below. A crash-durable provider record/body
backend with fresh signed qualification is still required; reference fixture
seals do not fill that gap.

Schema 7 stores grants, retry reservations, original opaque permits and bounded
hot receipts in the authoritative Session transaction, with archived receipt
lookup and indefinite transitive blob pins. Acquisition does not advance the
event cursor. Commit atomically consumes its exact grant; a retry reservation
excludes starting the previous attempt. Actual checkpoints and settlements
hydrate through the authenticated blob reader, including Pi decimal wrappers.
The legacy dispatch-start adapter explicitly rejects raw Pi parent IDs; the
complete broker path preserves their original strings and ordinal.

These adapters and their local Cell/Coordinator tests do not satisfy the live
celld/object-store gates or construct the remaining durable auth/audit/ACL and
served execution graph. `AdmissionReady` stays false.

## Session admission planning

`POST /circulusd/state/v1/session-turn:plan` uses the existing admission
credential with distinct request/response MAC domains. It accepts only the
complete public user-message input, both semantic digests, scoped principal,
authorization generation, proposed turn ID and idempotency digest. It does not
accept a checkpoint, runtime override, CAS version, lease or policy from the
caller. Configure `CIRCULUSD_STATE_ADMISSION_POLICY` as an immutable object or
JSON string containing exactly `{"turnLeaseTTLms":120000}`; permitted TTLs are
1–300000 milliseconds. Missing or malformed policy prevents planning.

The authoritative Session transaction checks scope/current authorization and
digests before archived receipt lookup. A replay returns the original accepted
turn and skips genesis creation and admission. A new plan returns the current
CAS version, exact runtime/engine ABI/schema and host-time lease; a concurrent
mutation or expired lease is still rejected by the existing admit transaction.

`stateappadmission.NewPlanner` requires independently verified planning and
`GenesisProvider` objects. Genesis must have the signed `engine-genesis` atomic
capability in its own domain, and must return bounded, executable checkpoint
bytes for the exact planned runtime, turn and complete input. Current low-level
Pi genesis uses ABI/schema 2 and its actual ready core state; an empty payload
or a protocol-valid checkpoint for another prompt cannot satisfy this contract.
The Pi core accepts the exact public `messages` input without merging messages
or losing their order. Its deterministic timestamp zero records the public
codec convention; it does not represent observed host admission time.

`statebootstrap.Graph.SessionAdmission(ctx, PlannerConfig)` challenges the
planning client, planner, mutation client and complete admitter separately,
then requires the same command-receipt/effect/public-event domain as the actual
event reader. The native executable-genesis transport/provider and its fresh
qualification must still be supplied. No public listener is enabled by this
factory.
The durable admission contract lives in `internal/sessionadmission`, which
contains no reference store. Public API aliases retain type and error identity
without importing the memory repository into the production graph.

## Immutable provider result reads

`stateappclient.Client.ReadProviderResult` reads through
`POST /circulusd/state/v1/provider-result:read`. Use a dedicated provider
loopback origin and read credential; this is a separate service authority from
the Session's operation keys. The fixed read protocol binds tenant, workspace,
Session, effect, invocation, request digest, external commit and artifact ID.
The response repeats every field and contains the original canonical CBOR body
plus its SHA256. The body limit is 1 MiB; malformed/noncanonical/oversized data,
changed identity, wrong MAC domain or a replay from another request fails.

`providerresult.Server` requires a verified operational `ResultResolver` with
the effect-lifecycle atomic group. It bounds the whole HTTP request, including
body/socket I/O, and exposes no provider invocation, retry or settlement method.
Its native production-probe route forwards only that same source's challenge
and rejects a changed descriptor. A read HMAC cannot substitute for the native
Ed25519 proof. The server constructor creates no listener or infrastructure.

`providerresult.NewRecordResolver` bridges an independently qualified
`Records` reader to the server/source contract. A committed record must repeat
the complete original request and contain the immutable ledger observation,
normalized Pi body and digest. Model validation preserves original decimal
costs, cache counters and fractional tool arguments while matching the completed
ledger's text, tool order/arguments and finish reason. MCP is enabled only by an
explicit immutable bounds policy and requires ledger Output already containing
the exact Pi tool-result envelope. Generic MCP bytes and model records missing
Pi metadata cannot be completed with invented timestamps, models or costs.

`providerresult.New` retains a verified native reader and implements the broker's
`ResultResolver`; separately challenge this operational resolver before passing
its seal to `Graph.SessionBroker`. The concrete writer and Storage bridge below
still require native source qualification and fresh crash-durability evidence.
Local signed fixtures exercise
these contracts only and do not promote §53 or `AdmissionReady`.

## Native result persistence and genesis transport

`providerresult.NewPersistentRecords` accepts a separately verified
`TransactionStorage` combining `celld.Storage` and its own native probe. Both
`command-receipt` and `effect-lifecycle` groups must attest that exact source.
`WriteCommittedResult` is a trusted terminal-producer operation: authenticate
the original provider facts and references before calling it. The adapter
stores the complete terminal ledger, normalized Pi body, digest and immutable
publication receipt atomically. Its occurrence key prevents a changed request,
commit or artifact from creating a parallel result. Every successful new write,
replay and read confirms the same source's exact durability token. It grants no
provider-start, retry or Session-settlement authority. Native transaction source
qualification, terminal producer authentication and actual crash evidence are
still required.

`enginegenesis.NewClient` uses a dedicated numeric loopback origin and genesis
credential for `POST /circulusd/engine/v1/genesis:create`. Its distinct native
challenge route is `/circulusd/engine/v1/production:probe`. Client timeout must
be positive and at most 30 seconds. Snapshot and native proof identities cannot
borrow state-app credentials or Session qualification. Independently verify
the actual client as `enginegenesis.Transport`, construct `NewProvider`, then
independently verify that provider as `stateappadmission.GenesisProvider` before
passing it to admission bootstrap.

`enginegenesis.NewServer` accepts only an independently qualified native
executable-genesis source with the `engine-genesis` group. It forwards that
source's actual proof and exact Pi checkpoint bytes. Server timeout defaults
to 30 seconds and must not exceed it; the deadline covers body/socket I/O and
the source operation on both routes. The server owns no listener. The real
signed WorkerLoader source, its measured runtime proof endpoint, release
evidence and dedicated service wiring remain required.

## Actual Pi genesis and the celld Loader adapter

`workers/pi-runtime/src/genesis.ts` generates the initial checkpoint with the
existing `LowLevelPiAgentEngine` and real Pi Agent Core adapter. The complete
ordered user-message input, tenant/workspace/actor/Session/turn, input digest and
ABI/state-v2 runtime identity are validated and bound to the reply. It generates
no native production proof.

`createPiGenesisEntrypointClass` accepts the actual `WorkerEntrypoint` base from
the trusted deployment wrapper. `CelldPiGenesisSource.create` requires a trusted
runtime verifier to attest the exact computed module/configuration artifact
digest for the immutable Session runtime revision. That digest covers the
pinned celld commit, module SHAs, fixed real entrypoint wrapper, compatibility
date/flags and complete Pi configuration. A caller-supplied digest alone cannot
authorize Loader access.

Bundle `genesis-entrypoint.ts` as `PI_GENESIS_CORE_MODULE`; map the fixed
`PI_GENESIS_ENTRY_SOURCE` to `PI_GENESIS_ENTRY_MODULE`. Supply the actual Loader
binding configured by `CELLD_WORKER_LOADER`, trusted scope/runtime definition
and signed revision-to-artifact mapping verifier to
`CelldPiGenesisSource.create({ scope, runtime, loader, verifier })`.

The concrete verifier is `SignedPiGenesisRuntimeVerifier` in
`workers/pi-runtime/src/genesis-runtime-mapping.ts`. Prepare the immutable
runtime definition, then call `piGenesisRuntimeArtifactDigest(runtime)` for its
exact artifact digest. This helper validates/snapshots the same module bytes,
configuration, flags, dates, main module and pinned celld/ABI/schema as the
actual source; it neither calls Loader nor authorizes that artifact by itself.

The signed canonical-CBOR document is exactly `{claims, algorithm, signature}`
with `algorithm: "ed25519"` and a 64-byte signature. Claims contain exactly
`schemaVersion: 1`, `celldCommit`, `adapterAbiVersion: 2`,
`checkpointSchemaVersion: 2`, `runtimeRevisionDigest`, `artifactDigest` and
`keyId`. The commit must match `CELLD_GENESIS_COMMIT`. Key IDs use lowercase
`[a-z0-9][a-z0-9._-]{0,63}`. Document limits are 4096 bytes, depth 16 and 64
items. Unknown fields, duplicate/trailing/noncanonical CBOR and unsupported
algorithm/versions are rejected.

An independent offline signer signs the ASCII 71-byte `sha256:…` digest of
`["circulusd.hash", 1, "circulusd.pi.genesis-runtime-mapping", 1, claims]`.
Go's `enginegenesis.RuntimeMappingSigningDigest` prepares that digest without
accepting a private key; `EncodeSignedRuntimeMapping` packages a supplied
signature and does not confer trust. `VerifySignedRuntimeMapping` checks the
document against both its operator-pinned digest and copied independent roots.
Its returned binding exposes owned value claims only. These APIs create no
private keys, signatures, evidence or deployment configuration.

Provision the selected `expectedMappingDigest` and the independent signer root
separately from the document, then call
`SignedPiGenesisRuntimeVerifier.create({ document, expectedMappingDigest,
trustRoots: [{ keyId, publicKey }] })` and pass that exact verifier to
`CelldPiGenesisSource.create`. Both implementations copy inputs, require 1–64
roots, reject duplicate root IDs/material and require canonical nonidentity
prime-order Ed25519 public keys. TypeScript uses pinned `@noble/ed25519` 3.0.0 public
[point validation](https://github.com/paulmillr/noble-ed25519/blob/3.0.0/index.ts#L190-L212)
and [subgroup checks](https://github.com/paulmillr/noble-ed25519/blob/3.0.0/index.ts#L359-L366),
then native WebCrypto Ed25519 verifies the actual signature. Unsupported crypto
fails closed. The constructor owns all mutable input before asynchronous crypto;
each `verify` call accepts only the sealed exact revision/artifact pair.

Mappings are immutable and have no wall-clock expiry so original Session runtime
replay can retain its exact artifact. Replacement/revocation requires a newly
trusted composition and explicit mapping/root selection. Keep this signing
authority independent of the operational HTTP key and native runtime probe
authority. The mapping does not attest the native Loader, object store,
isolation or resource/termination limits, and cannot enable `AdmissionReady`.
`packages/protocol-types/fixtures/pi-genesis-runtime-mapping-v1alpha1.json`
contains public deterministic test material only, including invalid key vectors.

The adapter sends the pinned celld Loader an ESM source map, JSON-only scoped
configuration and `globalOutbound: null`, then calls only
`getEntrypoint().createGenesis(...)`. It verifies the full request binding and
actual initial Pi state in the reply. This genesis path retains the existing
SessionHost implementation, broker capability bindings and resource defaults.
A canceled call stops the caller's pending Loader/RPC wait and rejects late
results. The pinned ABI does not propagate cancellation into the remote isolate;
the native host remains responsible for termination and resource enforcement.
`createCelldPiGenesisWorker` in `src/genesis-worker.ts` now exposes that retained
source through the existing Go HTTP contract. Its configuration supplies the
actual `CelldPiGenesisSource` (or a trusted scoped native source factory), a
dedicated key ID and 32–256-byte operational root, a positive timeout of at most
30 seconds, and an optional trusted native challenge forwarder. The constructor
captures the source method, credentials, clock and probe callback once. A
direct `CelldPiGenesisSource` retains one exact Session scope/runtime; serving
multiple Sessions requires an authoritative scoped source factory, not a
permissive scope rewrite. No deployment wrapper, listener or resource is created.

The HTTP wrapper accepts only exact routes/MIME types and canonical CBOR, with
2 MiB requests, 4 MiB plus 64 KiB replies and 32 KiB native proofs. Request
freshness is ±30 seconds. Request digest binds the complete ordered public input
and all eight semantic request fields; transport request ID/time remain bound
by the exact-byte MAC. Success returns the exact scoped identity and actual
Pi genesis checkpoint. Source failures produce authenticated `UNAVAILABLE`;
changed or invalid checkpoints produce `BAD_SOURCE`. Both return no checkpoint.
After cancellation or deadline expiry the wrapper returns an unsigned 503.
The limit covers streamed body reads, all crypto/semantic checks, source calls,
native-probe forwarding and final response signing. Source result identity and
payload bounds are checked before asynchronous hashing or large cloning.

The trusted `nativeProbe` callback must forward the same measured native
Loader/source's original Ed25519 challenge bytes. The wrapper checks exact nonce,
production descriptor/group/key shape and pins the complete descriptor across
probes. The native runtime key ID must differ from the operational key ID. It
creates no Ed25519 signature, private runtime key or production eligibility.
Missing or changed proof yields 503. Go still independently verifies the native
signature against operator-pinned evidence/roots, verifies the actual client,
constructs `NewProvider`, then separately verifies that exact provider for
admission. A shape check or descriptor pin is insufficient evidence.

`packages/protocol-types/fixtures/engine-genesis-v1alpha1.json` contains public
test keys and byte-exact actual Pi success/operational-error vectors shared by
Go and TypeScript. The local HTTP/Loader test executes the real bundled genesis
entrypoint, checks wire bytes, and reconstructs its first Pi model boundary.
The signed mapping continuation uses the concrete verifier and test-only signer;
its native base and Loader remain contract fixtures. Actual pinned Loader wiring,
operator-provisioned signed revision-to-artifact mappings, same-source native proof,
remote-isolate deadlines and dedicated-host evidence remain required. The local
runtime mapping verifier and this HTTP wrapper do not qualify the celld binary,
isolation, storage or native `engine-genesis` capability, and do not implement
the complete SessionHost/broker execution bridge.

## Pi execution and the celld Loader composition

`workers/pi-runtime/src/execution-rpc.ts` defines `PiExecutionBinding`, the
request/reply unions and `PiExecutionTransport.exchange(request)`. Import
`PiExecutionProxy` directly from `src/execution-proxy.ts` and
`PiExecutionEndpoint` directly from `src/execution-endpoint.ts`; they are not
exported by the package index. The host constructs
`new PiExecutionProxy({ binding, transport, timeoutMs })` as a
`SessionHost.AgentEngine`. The receiver constructs
`new PiExecutionEndpoint({ binding, createEngine, maximumExecutions,
maximumLifetimeExecutions })`; its trusted factory must supply a fresh
`LowLevelPiSessionHostAdapter` and scoped engine for each start/resume.
These lower-level ports remain available independently of the concrete Loader
adapter below. Import the new APIs from their source modules directly.

Bundle `src/execution-entrypoint.ts` as
`PI_EXECUTION_CORE_MODULE` (`circulusd/pi-execution-core.mjs`) and map the fixed
`PI_EXECUTION_ENTRY_SOURCE` to `PI_EXECUTION_ENTRY_MODULE`
(`circulusd/pi-execution-entry.mjs`). The wrapper imports the actual
`WorkerEntrypoint` and exposes `exchange`; the scoped entrypoint checks its
configuration digest and constructs the actual Pi core and bounded endpoint.
`CelldPiExecutionEngine` in `src/celld-execution.ts` implements
`SessionHost.AgentEngine`. Construct it with
`await CelldPiExecutionEngine.create({ loader, verifier, scope, runtime,
timeoutMs }, signal)`, supplying the actual `CELLD_WORKER_LOADER` binding and
ABI/state-v2 `PiExecutionRuntimeDefinition`. It sends a module-name-to-ESM-string
map, JSON configuration, compatibility date/flags and `globalOutbound: null`.
Broker bindings stay on SessionHost. The pinned Loader does not enforce
per-worker CPU/subrequest limits; qualified native resource enforcement is
still required.

`piExecutionRuntimeArtifactDigest(runtime)` prepares the exact digest for an
independent signer without calling Loader or granting authority. The artifact
binds pinned commit `89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9`, ABI/state-v2,
the fixed main module, sorted module SHAs, compatibility settings and the full
configuration. Runtime snapshots finish synchronously before the first await;
intrinsic typed-array reads enforce actual byte bounds before copying and
never invoke shadowed getters. There are at most 256 modules, 8 MiB per module
and 32 MiB total; the JSON environment is bounded to 1 MiB. The independent
schema-1 hash domains are:

| Purpose | Domain |
| --- | --- |
| Configuration | `circulusd.pi.execution-configuration` |
| Module/configuration artifact | `circulusd.pi.execution-runtime-artifact` |
| Signed revision-to-artifact mapping | `circulusd.pi.execution-runtime-mapping` |

`SignedPiExecutionRuntimeVerifier` in `src/execution-runtime-mapping.ts`
verifies exactly `{claims, algorithm: "ed25519", signature}`. Claims contain
exactly `schemaVersion: 1`, the pinned `celldCommit`, `adapterAbiVersion: 2`,
`checkpointSchemaVersion: 2`, `runtimeRevisionDigest`, `artifactDigest` and
`keyId`. Limits are 4096 canonical-CBOR bytes, depth 16 and 64 items. The signer
signs the ASCII 71-byte domain-separated `sha256:…` claims digest.
`internal/engineexecution` supplies `RuntimeMappingSigningDigest`,
`EncodeSignedRuntimeMapping` and `VerifySignedRuntimeMapping` for independent
offline preparation/verification; a verified binding exposes `Claims()`,
`MappingDigest()` and the execution-only `MappingDomain()`.

Create the verifier with `{ document, expectedMappingDigest, trustRoots }`,
pinning the digest and public roots independently of the document. Inputs are
copied before crypto; roots must be distinct canonical nonidentity prime-order
Ed25519 keys, with 1–64 roots and lowercase key IDs as in the genesis contract.
Sealed constructors prevent direct unverified instantiation. Mappings remain
immutable for original Session replay; replacement/revocation requires new
trusted pin/root selection. `verify` accepts only the exact revision/artifact
pair and returns that pair plus
`mappingDomain: "circulusd.pi.execution-runtime-mapping"`. The Loader adapter
checks all three fields. Even identical claims and the same trusted public key
cannot make a genesis-domain signature or verifier authorize execution. The
public `pi-execution-runtime-mapping-v1alpha1.json` fixture includes this
cross-purpose control; production APIs accept no private signing key and
create no native qualification proof.

The protocol carries plain structured-clone values, including `Uint8Array`
authority/checkpoint bytes and finite fractional resume settlements for remote
Pi normalization. It does not JSON-stringify these bytes or export an
`OpaqueTurnAuthority`. This differs from the Loader's JSON environment: the
pinned [Loader configuration and RPC path](https://github.com/denoland/celld/blob/89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9/crates/celld/js/harness.js#L1547-L1657)
serializes its configuration as JSON but sends single-method RPC arguments
through the [structured-clone marshaller](https://github.com/denoland/celld/blob/89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9/crates/celld/js/harness.js#L1793-L1806).
The bridge accepts no capability objects. The concrete adapter captures and
invokes native callable RPC pipeline nodes with `Reflect.apply`; using their
`.bind`, `.call` or `.apply` properties would create an unsupported deeper path.
This implements the pinned Loader ABI locally and supplies no HTTP listener.

Every operation binds the complete tenant/workspace/actor/Session scope,
runtime revision, execution artifact digest, turn and execution ID. Requests
use protocol `circulusd.pi.execution`, version 1. `start`, `resume`, `close`
and `abort` use sequence 0; each `pull` requires the next sequence starting
at 1. Responses echo these exact headers and carry only the permitted status
and optional event; they have no authority field. The proxy verifies
checkpoint payload SHA, immediate successor chain, ABI/state-v2 identity and
effect-request digest/service before exposing a durable event.

Start/resume snapshots the caller's input synchronously, but opens no remote
execution until the first iterator pull. Each subsequent `next()` sends one
pull and receives at most one event; concurrent pulls are rejected and no
prefetch occurs. Thus SessionHost still waits for its ephemeral sink or durable
commit before requesting the next event. Model/tool boundaries contain effect
intents only. The existing `STATE`, `WORKSPACE`, `MODEL`, `MCP`, `EXECUTOR`,
`ARTIFACTS` and `EVENTS` capabilities stay on the host, and this bridge grants
no provider-dispatch or durable Session authority.

Snapshot budgets are conservative pre-clone size estimates: 6 MiB per request,
2 MiB per reply, depth 64 and at most 1,000,000 items. Authority contains
1–4096 bytes; proxy assistant deltas retain the 64 KiB protocol limit.
Object/array accessor fields, cycles, unsupported object types, nonfinite
numbers and negative zero are rejected. Typed-array bytes are copied through
intrinsics without invoking caller-shadowed accessors. The proxy admits at
most 64 resident executions. The endpoint defaults to 64 residents and 1024
lifetime execution identities;
configured limits may be lower, with a lifetime maximum of 4096. Retired
execution IDs and preemptive close/abort IDs remain tombstones without eviction
so a delayed open cannot revive them. Lifetime exhaustion requires a fresh
endpoint. Resident ownership is released only after cooperative cleanup
succeeds; stalled cleanup retains its slot, and failed cleanup disposes the
endpoint and retires its peers, including peers already closing. Existing
scoped close/abort controls remain available after disposal; new work is
rejected. Stale controls cannot interrupt a replacement execution.

Factory acquisition and the proxy default to 5000 ms deadlines; `timeoutMs`
must be an integer from 1 through 30000. Creation covers snapshots, hashes,
the verifier and Loader acquisition; later deadlines apply per exchange or
asynchronous validation. The optional `AbortSignal` bounds only
initial acquisition and is detached after creation. Each composition uses a
fresh UUID suffix after its scoped artifact identity: the pinned Loader caches
`get()` by name, so a fresh composition must not reuse an endpoint's failures
or lifetime tombstones. A synchronous Loader stub does not prove successful
compilation; the first `exchange` also covers loading and initialization.
An ambiguous transport failure, timeout or invalid reply poisons the entire proxy, rejects
active work and prevents new execution through it. There are no automatic
retries. Iterator return and abort issue bounded best-effort owned cleanup;
late events are discarded. Endpoint cleanup/disposal is cooperative and may
remain pending. None of these acknowledgements proves native isolate
termination, cancellation propagation or CPU/RSS enforcement; those remain
the qualified native host's responsibility. `CelldPiExecutionEngine.dispose()`
returns `void`: it cancels local waits and schedules the owned native stub's
release once. It sends no cooperative cleanup RPC and returns no termination
acknowledgement; already captured native work may outlive it.

The local bundled test reconstructs the actual Pi model → fractional tool →
model → complete chain using committed checkpoints, fresh endpoints/engines
and test-produced settlements. Explicit bounded core fixtures test
assistant-delta backpressure and intermediate checkpoint commit success/failure:
the next engine step waits for the commit, and a failed commit aborts without
that step. The pinned Pi adapter does not emit assistant deltas from its
completed model settlement. The concrete signed mapping/Loader tests execute
the real bundled entrypoint through a native-base/Loader contract fixture and
check fresh names, single-hop RPC and owned disposal. These local tests create
no native evidence. Operators still need actual pinned celld Loader/binary and
same-source signed proof, real execution artifact documents and independent
pins/roots, conditional-write object storage, resource/lifetime qualification,
qualified host brokers and the served native graph. Genesis's mapping/artifact
cannot be reused for execution. `AdmissionReady` remains false.

## Qualified credentials and public composition

`authstate.New` binds one typed tenant to a separately verified native
transaction source with the `credential-audit` group. PAT records and their
monotonic chained audit outbox share one object and one CAS transaction; every
successful read or mutation confirms a native durability barrier. The store
rechecks current version, identity, scope, expiry and revocation before
committing an authentication use. Explicit record/row/state caps reject growth
atomically. Audit reads return the exact tenant/object, sequence, chain head
and transaction snapshot digest. They do not remove or acknowledge outbox rows.

`authstate.NewAccountStore` uses a separate per-tenant account object and the
independent `account-audit` group. Trusted provisioning creates an initial
account; public login never provisions one. Password PHC cost and lockout
policy are persisted immutable configuration. Each login recomputes the
existing authentication transition against current account state and appends
its chained audit row atomically before the native barrier. Unknown, disabled
and locked accounts retain audited generic failure behavior. Reopening under
a changed policy fails until an explicit native migration exists. No password
hashes or credential digests appear in audit exports.

`authstate.NewAuthorizer` retains a separately qualified native current
membership/authorization source. Its `acl-authorization` group and Session
command/effect/public-event groups must share the Session domain. The adapter
checks the exact operation, principal, Session, generation and original opaque
proof; it cannot substitute a permissive local membership rule.

`publicbootstrap.New` composes scoped PAT authentication, authoritative turn
admission and the actual durable event-page reader. It requires independently
verified credentials, current ACL authority and executable genesis before
calling the admission factory; admission, ACL and event readers must share the
Session domain. Limits and the idempotency secret are immutable snapshots.
Authentication or audit-barrier failure stops before ACL or Session I/O;
authorization failure stops before Session I/O. The finite HTTP request limit
covers body/socket reads and writes. Closing the graph cancels active requests;
the caller retains ownership of native dependencies. This public subgraph
does not certify TLS, engine/provider execution, secrets, scheduling or the
profile's live resource gates and does not enable `cmd/platformd` admission.

## Signed audit checkpoints

`auditcheckpoint.New` accepts a verified PAT/account `AuditReader`, a verified
native `authstate.Source`, and a separately verified native signing service.
The reader and storage must share the corresponding `credential-audit` or
`account-audit` transaction domain and concrete source identity. Checkpoint
storage also requires `command-receipt`; the signer needs the independent
`audit-checkpoint-signing` group plus an operator-pinned public key/key ID.
The package generates no private runtime key.

`Publisher.Publish` reads the exact tenant/object snapshot, signs canonical
claims containing its source identity, chain sequence/head, full raw-state SHA
and signer identity, then compares that snapshot inside the same native
transaction before publishing an immutable receipt. A changed snapshot fails
without a checkpoint write. Exact replay returns the original verified
signature without signing again. The same source's receipt barrier must pass
before returning a checkpoint. Later audit activity does not make a historical
checkpoint current authority. Periodic scheduling, native key management,
immutable external anchoring and actual audit conformance remain required.

## Pinned celld bridge prerequisites

The celld v0.3.0 manifest pins source commit
`89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9`. Its
[storage limitations](https://github.com/denoland/celld/blob/89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9/docs/limitations.md#L5-L9)
require conditional-write object storage, including on a laptop; a local SQLite
directory alone is insufficient. Its experimental
[Loader contract](https://github.com/denoland/celld/blob/89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9/docs/cloudflare-compat.md#L192-L203)
accepts ESM source maps, JSON environment values and single RPC calls, but not
broker capability stubs. A genesis-only adapter must not replace SessionHost's
full broker bindings or its resource defaults.

`internal/celldbridge` now implements this Storage bridge. Construct
`NewClient` with a dedicated numeric loopback HTTP origin, key ID, exact 32-byte
operational root key and a positive timeout of at most 30 seconds. The client
disables proxies, redirects and compression. Its authenticated transaction
route is `POST /circulusd/native-storage/v1/transaction`; the independent native
challenge route is `POST /circulusd/native-storage/v1/production:probe`.
Directional HMAC keys protect exact canonical-CBOR request/response bytes and
request identity. They cannot sign or replace the native Ed25519 challenge.
The shared `packages/protocol-types/fixtures/native-storage-v1alpha1.json`
contains public test credentials and nine byte-exact contract cases only.

Independently verify the actual client as `celldbridge.NativeTransport`,
requiring `native-storage`, `command-receipt` and the consumer's additional
atomic groups. Construct `celldbridge.New` with that seal, explicit positive
`Bounds` and `MaximumAttempts` between 1 and 8. Independently verify this exact
Storage adapter again as the consumer's transaction-source interface; keep the
same native descriptor, source identity and transaction domain. The caller
owns the client and must close it after consumers stop. Closing cancels owned
HTTP requests and clears retained directional keys.

Callbacks run against an exact object/existence/revision/raw-state-SHA snapshot.
Receipt lookups are lazy and pinned to that snapshot. State, response bytes and
ordered capability claims stage locally; the callback closes before native CAS.
Only an authenticated definite `SNAPSHOT_CONFLICT` permits a bounded callback
retry. Timeouts, lost replies and unknown commit outcomes fail without retry.
Every successful native CAS, including a read-only callback, increments the
logical revision. Result/checkpoint consumers require the final callback to
have completed; an earlier receipt conflict does not invalidate a later success.

The Go upper bounds are 16 MiB state, 4 MiB per receipt response, 64 claims with
at most 1 MiB combined payload per receipt, 64 receipt lookups/writes and 32 MiB
for the complete wire transaction; the wire bound also limits their combined
size. Choose matching
Go/TypeScript limits and measured runtime caps. These limits cover the complete
encoded persisted state: provider ledger and normalized body limits cannot each
consume the full 16 MiB independently, and the generic Host's 32 MiB default
cannot be used unchanged. Oversized operations reject atomically.

The trusted deployment wrapper imports
`createNativeStorageWorker` and `createNativeStorageDurableObjectClass` from
`workers/state-app/src/native-storage/worker.ts`, supplies the actual native
`DurableObject` base, immutable credentials/bounds and a dedicated
`NATIVE_STORAGE` namespace. It supplies a real native challenge forwarder;
without it the probe route returns 503. The wrapper creates no production proof
and this change supplies no deployment or resource configuration. This namespace
uses its own physical object names and chunk layout; it does not migrate or
replace existing SessionHost/state-app objects.

The kernel binds the logical object ID to the actual `state.id` and namespace
identity before storage I/O. One native `storage.transaction` atomically commits
state, immutable receipts and anchored metadata. State and receipt payloads use
1 MiB chunks with exact SHA/length manifests. Missing chunks, copied anchors and
requested orphan receipts fail closed. A barrier always writes a new serial and
fresh marker to that same native object while preserving the logical revision.
The reply must echo the exact requested token and marker; historical tokens
require an observed revision at least as high. There is no process-local token
registry or invented native SQLite write position.

The root worker routes only through native DO `stub.fetch` and signs a reply
after that fetch's response gate and exact reply validation. The pinned
[inline fetch gate](https://github.com/denoland/celld/blob/89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9/crates/celld/js/harness.js#L3259-L3315)
samples native committed writes. Its
[inline RPC path](https://github.com/denoland/celld/blob/89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9/crates/celld/js/harness.js#L3342-L3373)
does not perform that sampling/gate wait, so replacing `stub.fetch` with RPC
would break this bridge's durability argument. The whole local request deadline
covers body reads, native waits, reply validation and final response signing.
After cancellation or timeout it returns an unsigned 503 rather than a success
or definite-conflict acknowledgement. This bounds the caller's asynchronous
wait; actual remote transaction termination remains the native host's duty.

The pinned [storage.sync implementation](https://github.com/denoland/celld/blob/89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9/crates/celld/js/harness.js#L974-L977)
flushes pending local writes only. The native
[response output gate](https://github.com/denoland/celld/blob/89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9/crates/celld/main.rs#L444-L458)
holds write responses until durability is proved and performs an
[ownership check](https://github.com/denoland/celld/blob/89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9/crates/celld/actor.rs#L2205-L2244).
Qualification must measure that actual gate and configuration, including an
active replicator: the pinned
[runtime without replication](https://github.com/denoland/celld/blob/89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9/crates/celld/runtime.rs#L880-L900)
immediately acknowledges durability. `CELLD_OUTPUT_GATE=1` alone is insufficient.
Coverage of a logical historical token by the fresh marker write is an inference
that requires the same qualified object/source, active RPO0 replication and
measured monotonic write/output-gate behavior. JS `sync()`, sequential HTTP
writes, fixture keys and an unqualified loopback service cannot substitute for
those conditions. Actual native probe integration, configured object storage,
source/build/configuration evidence and kill/restart tests remain prerequisites
for served production admission. The stock native runtime does not provide the
circulusd signed challenge endpoint by itself.

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
