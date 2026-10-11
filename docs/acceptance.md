# Acceptance ledger

This ledger maps `SPEC.md` section 53 to its required evidence. Status is intentionally conservative:

- `PASS`: the exact required real implementation and environment passed;
- `FAIL`: the gate ran and failed;
- `UNAVAILABLE`: the gate cannot run in the current environment, with a reason;
- `NOT_RUN`: implementation or runner is not ready.

Only `PASS` satisfies a required release profile. Development fakes and unit launch-plan tests do not upgrade a real conformance status.

The 2026-10-08 continuation completed the local Session broker contract: schema 7
durable grants, retry reservations, original opaque receipt archival, the full
signed Go `DurableStore`, Pi checkpoint/result hydration, and independently
challenged bootstrap composition. The actual SessionCell fixture contains 39
responses/four blobs; Go Coordinator tests compare the exact outgoing CBOR and
exercise fresh/replayed start, confirmation, settlement/replay and resume. The
state-app suite passed 417 tests; focused Go race/vet and root type/lint passed.
Logs: `/home/seorii/logs/circulusd-broker-worker-full-bgq56fex.log`,
`/home/seorii/logs/circulusd-broker-composition-final-7aljyo3q.log` and
`/home/seorii/logs/circulusd-broker-types-lint-9xnk8u4f.log` (each exit 0).
The final complete Go gate passed all 74 tested packages with
`go test -race -p=1 ./...`, followed by `go vet -p=1 ./...` and
`git diff --check`: PID 314115, exit 0, log
`/home/seorii/logs/circulusd-continued-full-go-qtxm6upt.log`.
The result reader uses signed test fixtures in these checks; native provider
retrieval, real celld/object-store durability and the served production graph
remain open. No §53 status or `AdmissionReady` is promoted by this evidence.

The admission/result-read continuation implements authoritative signed turn
planning, exact ordered public Pi input, independently qualified admission
bootstrap, and immutable committed provider-result transport/normalization.
Actual SessionCell planning fixtures include archived replay, cold Pi genesis
and stale-CAS rejection. Model/MCP record-to-server-to-reader tests retain the
original ledger identity and canonical Pi body without fabricated metadata.
Final local validation passed on 2026-10-08:

- All 75 tested Go packages passed `go test -race -p=1 ./...`, followed by
  `go vet -p=1 ./...` and `git diff --check`: PID 1135635, exit 0,
  `/home/seorii/logs/circulusd-admission-result-final-go-uwpk03a1.log`.
- Standard root `pnpm test:unit` passed all 765 tests across 56 files
  (protocol 56, extension manifest 47, Pi 185, SessionHost 55, state-app 422),
  followed by root `pnpm check` and `pnpm lint`: PID 1135559, exit 0,
  `/home/seorii/logs/circulusd-admission-result-final-workers-mlt6v2jq.log`.
  The existing large-blob regression still compares every byte; native byte
  comparison replaces the deep array assertion that exceeded its timeout.
- The rebuilt Pi fixture passed `TestStockWorkerdFixture` against the same
  manifest-pinned installed executable: PID 1135587, exit 0,
  `/home/seorii/logs/circulusd-admission-result-final-stock-workerd-tz8dtbi1.log`.
  Stable-broker bindings remain mock and resource/recovery components remain
  `NOT_RUN`.

The unchanged production dependency guard passes after separating pure
admission contracts from the reference-memory public API package. Native
committed-record backends, executable-genesis providers, durable credentials/
audit/ACL and the served graph remain incomplete. These local checks do not
qualify celld/object-store/NsJail or promote any §53 status or `AdmissionReady`.

The ordered native-composition continuation adds concrete immutable provider
result persistence, bounded authenticated native-genesis transport, durable
PAT/account and chained audit adapters, current ACL proof forwarding, qualified
public HTTP composition, and an independently signed audit-checkpoint
publisher. Actual Pi genesis generation and the pinned celld Loader adapter
also execute the real entrypoint bundle in local tests, then reconstruct its
checkpoint in a cold Pi engine to the first model boundary with the complete
ordered Korean/English input. Pending Loader and RPC waits reject cancellation;
remote isolate termination remains a native host responsibility. These
adapters require sealed operational sources and exact native
barriers; their local tests never create production authority. The pure public
HTTP/Session implementation is separated from legacy memory repositories,
preserving the unchanged production dependency guard.

Focused race/vet gates passed for persistence, genesis transport and complete
HTTP deadlines, credentials/accounts, signed checkpoints and public-package
compatibility. Tests cover concurrent/reopened adapters, ambiguous responses,
stale or corrupted snapshots, expiry/revocation and barrier failure before
public Session I/O. Native storage, ACL and signing services, real celld
transaction/output-gate and execution bridges, terminal producer authentication,
TLS and the complete served runtime still remain prerequisites. The operator
contracts are in `docs/unit11-operator.md`; none of this evidence changes §53
status or `AdmissionReady`.

The final native-composition Go gate passed all 80 tested packages under
`go test -race -p=1 ./...`, then `go vet -p=1 ./...` and `git diff --check`:
PID 1384074, exit 0,
`/home/seorii/logs/circulusd-native-composition-full-go-w0ptsvv_.log`.
The final root Worker/protocol gate passed all 777 tests across 58 files
(protocol 56, extension manifest 47, Pi 197, SessionHost 55, state-app 422),
followed by `pnpm check`, `pnpm lint` and `git diff --check`: PID 315037,
exit 0, `/home/seorii/logs/circulusd-native-composition-full-workers-1h_af8p0.log`.
The genesis-only source uses new direct-import modules; existing SessionHost
bindings, resource defaults, RPC fixtures and generated stock-workerd Pi bundle
are unchanged. The bundle SHA remains
`fc666a4fc75c7dd3e873e31e78b7b7124e00770b901ff0a12f4b0f2eafd7d549`.
The new Loader test executes the actual bundle through a local ABI fixture;
it does not claim a native celld run or a new stock-workerd qualification.

The native Storage continuation adds `internal/celldbridge` and the separate
state-app native DO kernel/router. Nine shared byte-exact canonical-CBOR fixtures
cover absent/stored snapshots, immutable and missing receipts, CAS publication,
read-only revision advancement, historical/fresh barriers and definite stale
CAS. Go tests separately verify transport MACs, immutable native proof, source
qualification, bounded retries, cold historical tokens, oversized state and
owned client cancellation. Actual PAT-to-signed-checkpoint integration exercises
a receipt conflict during an earlier callback attempt. Result/checkpoint guards
accept a later completed attempt and reject a skipped or incomplete final one.

The TypeScript tests simulate actual native transaction and fetch contracts:
chunked state/receipt rollback and corruption, physical route/metadata anchors,
orphan receipts, lost replies/reopened kernels, fresh barrier writes, and pending
output gates. The external reply is signed only after gated fetch resolution.
Stalled body/native/probe/signature waits are bounded; an expired request exposes
no signed success or conflict response. These checks use local contract fixtures,
not a real native celld process, active replicator, object store or crash test.
An independently signed native probe and measured code/configuration/output gate
remain necessary. No production status or `AdmissionReady` is promoted.

The final native Storage Go gate passed all 81 tested packages under
`go test -race -p=1 ./...`, then `go vet -p=1 ./...` and `git diff --check`:
PID 4016950, exit 0,
`/home/seorii/logs/circulusd-native-storage-full-go-tqorm_no.log`.
After the final orphan-receipt guard, the root Worker/protocol gate passed all
809 tests across 60 files (protocol 56, extension manifest 47, Pi 197,
SessionHost 55, state-app 454), followed by `pnpm check`, `pnpm lint` and
`git diff --check`: PID 1353956, exit 0,
`/home/seorii/logs/circulusd-native-storage-final-workers-rrbx00dh.log`.
Existing SessionHost/state-app source contracts, RPC identities, deployment
configuration and generated stock-workerd Pi bundle were not changed by this
Storage unit. The normal state-app typecheck now includes the new direct-import
native Storage source modules; no stock-workerd/native-runtime run is claimed.

The genesis HTTP continuation now connects the retained Pi source to the
existing Go native-genesis contract. Shared public-test-key fixtures bind exact
request/response CBOR, directional keys/MACs, semantic request digest, actual
Pi checkpoint and authenticated source-error replies. Go tests verify actual
server equality and loopback Client consumption. TypeScript verifies the same
vectors and checks immutable original scope/input/checkpoint validation before
hashing, fresh timestamps, MAC separation and exact native probe framing.
The HTTP wrapper captures source methods/configuration and pins the full native
descriptor; neither operation creates source authority. Actual native probes,
signed Loader artifact mapping, remote termination/resource limits and the full
SessionHost execution graph remain external prerequisites. `AdmissionReady`
remains false.

The final genesis HTTP Go gate passed all 81 tested packages under
`go test -race -p=1 ./...`, then `go vet -p=1 ./...` and `git diff --check`:
PID 2784983, exit 0,
`/home/seorii/logs/circulusd-genesis-http-full-go-tt482_et.log`.
The final root Worker/protocol gate passed 843 tests across 62 files (protocol
56, extension manifest 47, Pi 231, SessionHost 55, state-app 454), followed by
`pnpm check`, `pnpm lint` and `git diff --check`: PID 2179936, exit 0,
`/home/seorii/logs/circulusd-genesis-http-full-workers-_4hzbex6.log`.
All 34 added TypeScript tests use new direct-import modules. The HTTP integration
invokes the actual `CelldPiGenesisSource` and esbuild Pi entrypoint with a local
Loader/base/verifier fixture, matches exact Go golden response bytes/MAC, and
cold-reconstructs the first model boundary with the complete original messages.
Source runtime mismatch performs no extra Loader access. Existing RPC/source
identities, deployment configuration and the generated stock-workerd Pi bundle
SHA `fc666a4fc75c7dd3e873e31e78b7b7124e00770b901ff0a12f4b0f2eafd7d549`
remain unchanged by this continuation. No actual native celld/proof qualification
or fresh stock-workerd resource/recovery run is claimed.

The signed runtime mapping continuation implements independent digest/root
pinning for the exact Pi revision/artifact pair. Go and TypeScript agree on the
bounded canonical claim document and ASCII signing digest, exact public fixture
signature, and rejection of weak/noncanonical Ed25519 roots. Tests cover valid
signatures under wrong pins/roots, changed claims/artifacts, malformed documents,
caller mutation during asynchronous crypto, unsupported crypto and fabricated
verifiers, including direct JavaScript construction and missing private-field
brands. A module-private constructor seal is checked at runtime after signature
verification. The pure artifact helper and actual Loader source share one snapshot
and digest implementation. Signed test mappings exercise the real Pi source and
HTTP/cold reconstruction path; local test signers and Loader fixtures supply no
production roots, native proof or resource evidence. `AdmissionReady` stays false.

The signed mapping Go gate passed all 81 tested packages under
`go test -race -p=1 ./...`, followed by `go vet -p=1 ./...`: PID 1282896,
exit 0, `/home/seorii/logs/circulusd-signed-genesis-mapping-full-go-tx4s0p16.log`.

The concurrent post-seal root Worker run passed all 258 Pi tests but exited 1
because the existing native Storage response-signing test did not reach its
expected signing checkpoint within its 50 ms request limit: PID 1503971,
`/home/seorii/logs/circulusd-signed-genesis-mapping-final-workers-cfkpoq08.log`.
The unchanged Storage test file passed all 17 tests with one Vitest worker:
PID 1654556, exit 0,
`/home/seorii/logs/circulusd-signed-genesis-storage-deadline-focused-bccbeb2u.log`.
This timing-sensitive check must not be reported as a clean concurrent gate.

Complete validation then passed 870 Worker/protocol tests across 64 files
(protocol 56, extension manifest 47, Pi 258, SessionHost 55, state-app 454)
using `pnpm -r --workspace-concurrency=1 --if-present test:unit --maxWorkers=1
--no-file-parallelism`, followed by `pnpm check`, `pnpm lint` and
`git diff --check`: PID 1654569, exit 0,
`/home/seorii/logs/circulusd-signed-genesis-mapping-serial-workers-_4ii3i19.log`.
The mapping continuation adds 21 mapping tests and six signed-artifact/actual
Loader integration tests. The runtime constructor seal was also independently
checked against six JavaScript fabrication routes, all rejected. No existing
Storage code or tests were changed to obtain this result. The generated
stock-workerd Pi bundle SHA remains unchanged.

The execution continuation implements a transport-neutral primitive pull RPC
around the existing SessionHost engine interface. Owned request/reply snapshots
bind all four Session scope fields, revision/artifact, turn/execution and ordered
pull sequence. They preserve finite fractional Pi settlements and reject
capabilities, object/array accessor fields, unsupported values and oversized
payloads. Typed-array copies use intrinsics without invoking caller accessors.
The host proxy validates complete checkpoint successors and effect digests before
exposing durable events; it retains host broker capabilities. Ambiguous
transport/validation failures poison the proxy without retries. Endpoint
execution identities remain bounded tombstones, resident capacity includes
pending cleanup, and failed cleanup retires peers while retaining its fence.
Both sides use cancellation signals for current work only, avoiding retained
reaction histories on lifetime unresolved promises.

Six bundled bridge tests cover actual pinned Pi model → fractional tool → model
→ complete reconstruction across fresh endpoints, terminal commit waits and
owned abort on commit failure. Explicit bounded core fixtures cover delta
backpressure and nonterminal checkpoint commit success/failure; advance count
stays one while a commit is blocked and cannot reach two after failure. The
pinned actual Pi adapter does not emit deltas from completed model settlements.
An initial integration gate exposed two incorrect test expectations (that delta
emission and `close` after commit failure, where SessionHost actually aborts):
PID 2093653, exit 1,
`/home/seorii/logs/circulusd-native-execution-integration-vja1fbik.log`.
The corrected bridge/checkpoint gate passed all six tests and normal Pi type
checking: PID 2805217, exit 0,
`/home/seorii/logs/circulusd-native-execution-bridge-checkpoint-h32r4018.log`.

Independent code review found and resolved cleanup of failed/closing peers,
resident capacity release and long-lived Promise reaction retention. Endpoint
27 tests, focused lint and diff checks passed: PID 1687041, exit 0,
`/home/seorii/logs/circulusd-execution-endpoint-peer-cleanup-ved7hxae.log`.
Proxy 46 tests, normal Pi type checking, focused lint and diff checks passed:
PID 2198605, exit 0,
`/home/seorii/logs/circulusd-native-execution-proxy-reviewed-yvvhg_19.log`.
The shared wire's 13 tests and preceding four bridge tests passed with normal
Pi type/lint checks: PID 1464153, exit 0,
`/home/seorii/logs/circulusd-native-execution-integration-reviewed-tdsrv0nm.log`.

Final validation passed 962 Worker/protocol tests across 68 files
(protocol 56, extension manifest 47, Pi 350, SessionHost 55, state-app 454)
using `pnpm -r --workspace-concurrency=1 --if-present test:unit --maxWorkers=1
--no-file-parallelism`, then `pnpm check`, `pnpm lint` and `git diff --check`:
PID 3302922, exit 0,
`/home/seorii/logs/circulusd-native-execution-final-workers-lomvvzkr.log`.
This adds 92 tests in four files: wire 13, endpoint 27, proxy 46 and bundled
bridge six. Go sources are unchanged; their preceding 81-package race/vet gate
remains the latest complete Go result. The stock-workerd Pi bundle SHA remains
`fc666a4fc75c7dd3e873e31e78b7b7124e00770b901ff0a12f4b0f2eafd7d549`.

The additional `gpt-pro-consult` design review produced no validated response:
its shared authenticated browser startup navigation timed out, and fallback CDP
connection also timed out. Network access was enabled and DNS resolved; browser
authentication could not be established through the failed connection. PID
4053424, exit 1,
`/home/seorii/logs/circulusd-native-execution-pro-design-0y_sl55x.log`.
Implementation was reviewed independently against pinned source/repository
contracts without attributing any verdict to Pro.

The preceding pull-only bridge uses a local structured-clone transport fixture
and supplies no native Loader binding, signed execution deployment artifact,
runtime proof or remote termination/resource evidence. The existing genesis-only
mapping cannot authorize a distinct execution artifact. Actual native Loader
qualification and qualified host broker composition remain open;
`AdmissionReady` stays false.

The Loader execution continuation now adds the fixed
`createPiExecutionEntrypointClass` wrapper and `CelldPiExecutionEngine` adapter.
The actual bundled Pi core reconstructs model → fractional tool → model →
complete across fresh Loader compositions, using the concrete signed execution
mapping verifier and a local native-shaped Loader/base fixture. Its callable
RPC node rejects deeper `.bind`/`.call`/`.apply` paths, so the test validates
the pinned one-hop `Reflect.apply` invocation. Binary authority/checkpoints
remain structured-clone RPC values; scoped environment/configuration remain
JSON, and `globalOutbound` is explicitly null. Brokers stay on SessionHost.

Execution configuration/artifact/mapping use separate hash domains. The
sealed verifier requires independent document-digest and public-root pins;
its exact three-field binding includes the execution mapping domain. A valid
genesis verifier for identical execution claims/root/artifact is rejected
before Loader access. `internal/engineexecution` prepares/verifies the same
canonical document, and the public fixture includes both independently valid
purpose signatures to prove cross-purpose rejection. Production APIs accept
no private signing key or native evidence. The new Go package passed its
focused race/vet gate: PID 2643383, exit 0,
`/home/seorii/logs/circulusd-native-execution-mapping-go-5sy3_wo9.log`.
Its 23 TypeScript tests, normal Pi type checking and focused lint passed:
PID 3927324, exit 0,
`/home/seorii/logs/circulusd-native-execution-mapping-ts-final-j5_7xysy.log`.

The entrypoint's 15 tests cover actual Pi cold continuation, complete scope
checks before shared initialization, owned environment/request snapshots,
overlapping calls, tombstones/stale controls and no cross-pull `waitUntil`:
PID 3305320, exit 0,
`/home/seorii/logs/circulusd-execution-entrypoint-final-ozxhtj93.log`.
The adapter's 19 tests, normal Pi type/lint and diff checks passed:
PID 591486, exit 0,
`/home/seorii/logs/circulusd-loader-execution-adapter-reviewed-jjecui4w.log`.
Independent review resolved deferred same-turn artifact copying and an
unobserved late load rejection when Loader synchronously cancels factory
acquisition. Regression tests exercise both failure paths.

Final validation passed all 1,019 Worker/protocol tests across 71 files
(protocol 56, extension manifest 47, Pi 407, SessionHost 55, state-app 454)
using serial package/file collection, followed by `pnpm check`, `pnpm lint`,
`go test -race -p=1 ./...`, `go vet -p=1 ./...` and `git diff --check`.
All 82 tested Go packages passed. The 57 added TypeScript tests are in three
new files, and the new Go mapping package adds one tested package.
PID 955259, exit 0,
`/home/seorii/logs/circulusd-loader-execution-final-j8w4br2i.log`.
The generated stock-workerd Pi bundle is unchanged at
`sha256:fc666a4fc75c7dd3e873e31e78b7b7124e00770b901ff0a12f4b0f2eafd7d549`.

Every composition uses a fresh UUID after its scoped artifact identity, since
native Loader names remain cached after stub disposal. Factory success means
verified artifact and owned native stubs, not completed compilation or native
readiness; compilation/entrypoint initialization occurs on the bounded first
exchange. Factory cancellation ends at publication. Separate lifetime disposal
rejects local waits and schedules native registry release once, without
claiming cooperative engine cleanup or native-stop acknowledgement. Native
in-flight work may still finish. Real cross-RPC continuation/timer behavior,
measured code/runtime proof, configured object storage, resource/termination
enforcement and the qualified served broker graph remain unverified. Read-only
host checks still find neither celld nor NsJail on PATH. `AdmissionReady` stays
false, and no infrastructure was provisioned.

The requested storage → served execution → operational authority/resource
sequence initially started with storage preparation only. Its later storage-only
completion on this machine is recorded below. The new actual S3 client
uses the official AWS SDK v2, an explicit existing bucket and credential source,
native opaque ETags, bounded HTTP requests and no SDK mutation retries. Its
qualification command writes a private exclusive report with endpoint/bucket
digests and stage observations. Generic CAS cleanup now verifies run-owned
payloads, handles nonce collisions without deleting foreign objects and checks
logical absence after conditional deletion. Regression tests reject no-op
deletion, ambiguous persisted writes followed by HTTP 500, unsafe report parents,
JSON case-fold aliases and incorrect SigV4/header/path behavior. The 22 new Go
tests passed focused race/vet/diff: PID 1897092, exit 0,
`/home/seorii/logs/circulusd-s3-native-cas-reviewed-owxfqzvn.log`.
These HTTP fixtures do not qualify an actual endpoint or celld durability.

The final Go regression passed all 83 tested packages under
`go test -race -p=1 ./...`, followed by `go vet -p=1 ./...` and
`git diff --check`: PID 2161461, exit 0,
`/home/seorii/logs/circulusd-native-storage-preparation-final-03lczlro.log`.
The new qualification command adds one tested Go package. Worker source and
the generated stock-workerd bundle were unchanged in this preparation unit;
the preceding 1,019-test Worker result was not rerun or relabeled as live proof.

The native Storage project builder emits an actual bundled Worker/DO pair with
the existing transaction kernel, dedicated namespace and private operational
HMAC configuration. Its eight tests cover malformed/private inputs, exclusive
outputs, digest-only public metadata, actual snapshot/commit/barrier/read and
unsigned 404 for both reserved native probe paths. Syntax, focused lint and
diff checks passed: PID 989822, exit 0,
`/home/seorii/logs/circulusd-native-storage-builder-reviewed-uk5kwo6h.log`.
The prepared bundle SHA is not the subsequently re-bundled/loaded deployment
SHA, and its manifest explicitly remains `PREPARATION_ONLY`/not admission-ready.

Pinned x86_64 celld 0.3.0 and SeaweedFS 4.44 release archives were downloaded,
verified against the existing manifest and extracted without starting services:
PID 2889969, exit 0,
`/home/seorii/logs/circulusd-native-storage-artifacts-6pjiust2.log`.
Private archive/executable provenance is retained under
`.codex/native-storage-qualification/artifacts/provenance.json`.
Read-only Docker discovery found a responding 29.1.2 server. At that preparation
checkpoint, no bucket, container, native node, deployment or trust root had been
provisioned; the actual mutation/fault-test target awaited selection and native
signer/issuer/durability qualification remained incomplete. The later selected-
machine observations and storage-only completion are retained below. Served
graph and operational authority/resource work have not started.

The new native signer design consultation failed before producing a response:
PID 586058, exit 1, model picker not found,
`/home/seorii/logs/circulusd-storage-native-design-525j_4kh.log`.
Independent source-boundary reviewers confirmed that the current SPEC requires
a minimal measured celld fork, separate signed artifact selection, raw fault
observations before conformance issuance and full graph/credential generation
fencing on restart. No verdict is attributed to Pro. Exact completion and
prepared-tool contracts are in `docs/unit11-operator.md`; `AdmissionReady`
remains false.

The selected-machine storage continuation (2026-10-11) has provisioned only
its dedicated loopback SeaweedFS service, private bucket and stock celld
application. The actual loaded main module is 59,617 bytes with SHA
`sha256:1719d6592159027b446b5434af31f59879199662b63217108e43b3efb0b2a7ef`;
the prepared file has a different digest. The raw reports are retained under
`.codex/native-storage-qualification/local/run-v37k2up7/reports`.

Actual provider CAS passed with its opaque ETags. The later raw CAS observer
also recorded exactly 32 contenders, one winner and 31 native HTTP 412
responses; stale update, duplicate create and stale delete each returned 412.
The winner, ordinary read and fresh-client read have the same full SHA. This
run exited 0 (PID 173860,
`/home/seorii/logs/circulusd-native-storage-cas-actual-k7jvbffr.log`), with
`reports/native-cas-raw.json` retaining the exact statuses, ETags and digests.
Its eight focused regression tests, race detector, vet and diff checks exited
0 (PID 140117,
`/home/seorii/logs/circulusd-native-storage-cas-observer-sqyn9pc5.log`).

Stock state/receipt/barrier observations include these actual fault runs:

| Observation | Process/result | Retained log |
|---|---|---|
| Initial acknowledged commit and readback | PID 2671962, exit 0 | `/home/seorii/logs/circulusd-local-observe-seed-06efhxhh.log` |
| SIGKILL followed by same-directory recovery | Native PID 2362464, exit -9; observer PID 3352238, exit 0 | `/home/seorii/logs/circulusd-local-observe-verify-ltdaxt3a.log` |
| Empty-directory recovery | Observer PID 3961172, exit 0 | `/home/seorii/logs/circulusd-local-observe-verify-3fkrrimb.log` |
| Empty-directory read after the machine reboot | Observer PID 85379, exit 0 | `/home/seorii/logs/circulusd-local-observe-verify-_wfpk2y2.log` |
| Second actual SIGKILL followed by empty-directory recovery | Native PID 79665, exit -9; observer PID 101276, exit 0 | `/home/seorii/logs/circulusd-local-observe-verify-ws8mqm4q.log` |
| Stale application revision rejection and unchanged readback | Observer PID 99366, exit 0 | `/home/seorii/logs/circulusd-local-observe-stale-cas-ykaapq0e.log` |
| One dropped successful response, then committed state/receipt/barrier readback | Observer PID 106619, exit 0 | `/home/seorii/logs/circulusd-local-observe-loss-tb4hvosa.log` |

An immediate post-startup recovery request failed (`snapshot-after:UNAVAILABLE`,
PID 93196, exit 1,
`/home/seorii/logs/circulusd-local-observe-verify-tfyybamg.log`); its raw failure
is retained and the later successful read is a separate report. Real root-disk
exhaustion also made the store read-only and caused native self-fencing, which
was not counted as a second injected SIGKILL. Only this run's 63 store files
were copied to a new private `/data` directory with matching SHA values; the
store and the original acknowledged state survived the later host reboot.
These stock observations have host-claimed bindings and are rejected by the
final native issuer. Neither stale application CAS nor provider CAS proves a
still-live prior native owner's late-write rejection.

The separate stock live-owner experiment completed in 12.37 seconds. Prior
native PID 249415 owned CELL epoch 6, uploaded an actual LTX with HTTP 200 and
had exactly one subsequent ownership GET held by the local relay. After SIGSTOP
and lease expiry, native PID 264409 claimed epoch 7 and committed revision 3→4.
The held GET was released while the prior process remained stopped and returned
the new owner's actual body/ETag. The resumed prior process exited 3 with a
retained `SELF-FENCE` line; its one request received no acknowledgement
(`UNAVAILABLE`, HTTP status 0). The new owner's revision 4 and state SHA
`sha256:8c464922542235390a36c9862f18e5049d657232eb5a0fe3064d96c49431a2a9`
remained unchanged, with fresh barrier serial 9→10. The raw protocol and process
facts are in `owner-experiment/experiment-with-termination.json`; the completed
prior-process log is `/home/seorii/logs/circulusd-local-node-j2_voevu.log`.
This is stock-only evidence and cannot qualify the separately selected fork.

The real native CELL `%3A` escaped-path relay regression, seven focused tests,
race detector, vet and diff checks passed (PID 229723, exit 0,
`/home/seorii/logs/circulusd-native-owner-escaped-path-72kfmaxv.log`). A later
bounded capacity pilot admitted exactly 20 additional native CELLs; B held 16
CELLs and A five, with the seed still owned by B. B remained live, but seed
release/takeover was not observed. `owner-experiment/capacity-result.json`
retains that negative result; no capacity-handoff PASS is claimed.

The reviewed minimal native fork and independent storage-only issuer are now
implemented. Focused proof-crate tests/clippy/formatting exited 0 (PID 3314501,
`/home/seorii/logs/circulusd-native-celld-proof-final-8_oco05a.log`); the
issuer's 17 focused cases/race/vet exited 0 (PID 3587980,
`/home/seorii/logs/circulusd-native-storage-issuer-owner-transcript-jbgld73m.log`).
The first full native build was terminated by its memory budget, exit -15,
`/home/seorii/logs/circulusd-native-celld-build-9op7w_sp.log`. The post-reboot
private disk-cache retry passed in 15 minutes 32 seconds, supervisor PID 64435,
Cargo PID 64652, exit 0,
`/home/seorii/logs/circulusd-native-celld-build-2v_mocim.log`; its authoritative
result is in the adjacent `.log.status.json` file. The separately selected
63,319,056-byte raw executable has SHA
`sha256:292c6753b45bf0a1bc42c5928c49be0ed048fb32fb43c00e697ccc10ece64adc`.
Pinned source, patch, proof and lockfile hashes were rechecked after compilation.
This successful full build does not establish signed native live probes.

The actual fork generation-16 seed observed an acknowledged state/receipt and
fresh barrier with native PID 747699, revision 1 and state SHA
`sha256:d1a480f031438ddc8d676ec875ebf94ac8e41e5fded274fb247e61b03e0ae5c4`.
Its report is `reports/native-seed-0e0efd9ab5211616.json`. Native generations 9,
16 and 17 all subsequently SELF-FENCE exited 3 after lease renewal became
ambiguous at about 2,501 ms, including the 10-second and 15-second TTL attempts.
Generation 16's completed log is
`/home/seorii/logs/circulusd-local-native-node-rpkh683q.log`; generation 17,
PID 1223355, exited 3 in
`/home/seorii/logs/circulusd-local-native-node-u_rmmpg_.log`.
An acknowledged seed is not a crash test, and these self-fencing exits are not
injected SIGKILLs. Those early attempts supplied no actual fork recovery or
native owner qualification; the later fresh run is recorded below.

Generation 18's actual unsigned state and native-storage probes both returned
404 (observer PID 3611053, exit 0,
`/home/seorii/logs/circulusd-local-native-probe-unsigned-tm1eh0qv.log`, report
`reports/native-probe-unsigned-5fd0dd7123.json`); the native process later
self-fenced with exit 3. These are negative controls, not signed probe PASS.
An independent 90-GET SDK trace recorded 30 initial successes in 1–4 ms, then
two-second timeouts persisting after native exit (supervised diagnostic
PID 3242347, exit 0,
`/home/seorii/logs/circulusd-local-lease-diagnosis-aq2w846w.log`). The diagnostic
exit 0 means observations were retained, not that all GETs succeeded.

The actual SeaweedFS binary identifies commit
`3563738699f29fd1c9efde6fcbf4ba253439cac8`, `vcs.modified=false`.
Its completed dump and exact source confirmed volume-slot exhaustion: the two
bucket volumes consumed `-volume.max=2`, leaving no default-collection system
metadata volume. Repeated metadata-flush failures filled the 16-window queue;
transaction writers retained exclusive per-key locks and blocked subsequent
GETs. The seven blocked writers and flush retry are retained in
`/home/seorii/logs/circulusd-local-store-qe25i6by.log`. This confirms provider
capacity as the cause of the repeated lease failures; the source links and
lock/flush chain are in `docs/unit11-operator.md`.

The owned store PID 69518 blocked on SIGTERM and exited 2 after the intentional
diagnostic SIGQUIT. Only its private controller limit was changed to
`-volume.max=4`; existing volume files and the 1 GiB free-space floor were
preserved. Replacement PID 775008, job `jobs/store-eb87bb8045.json`, created
default-collection volumes 27/28 with `readOnly:false`. Its log is
`/home/seorii/logs/circulusd-local-store-q2xydw3q.log`.
Native generation 19, actual PID 988299, used resident limit 2, TTL 15 seconds
and two Tokio threads, completed a 204.109891-second diagnostic and exited 0
after owned SIGTERM. All 41 lease attempts applied; none became ambiguous, and
the maximum measured duration was 12 ms. The root isolate was freed and no
SELF-FENCE occurred. Default volumes 27/28 grew to 9,851/26,967 bytes, proving
system metadata flushes. The completed report is
`reports/native-19-post-capacity-diagnostic.json`; its completed log is
`/home/seorii/logs/circulusd-local-native-node-krdjxuti.log`.
The native build SHA, application graph and lease checks were not changed.

The fresh post-capacity provider CAS run passed with 32 contenders, one winner
and 31 actual precondition failures. Three stale operations each returned 412;
fresh-client bytes/digest matched and bounded cleanup completed. Supervisor
PID 1584549, child PID 1585016, exited 0; report
`reports/native-cas-post-capacity-1791648016150627376.json`, log
`/home/seorii/logs/circulusd-native-storage-cas-post-capacity-hp0wkepm.log`.
This proves the new provider observations; it does not supply the native owner
fence or crash-recovery evidence.

A fresh native fault chain completed with exit 0: generation 20,
actual PID 2291966, and generation 21, PID 2581521, were each SIGKILLed
(exit -9); generation 21 used watch 20, then B23/PID 2835395 recovered with a
fresh watch. All five phase reports retained `errors: []`: seed, same-watch
verify, fresh-watch verify, stale-CAS and response-loss. Native20's unsigned
state/native-storage probes both returned 404. Supervisor PID 2287697,
child PID 2288666, status `jobs/native-fault-chain-f79a054a6e.json`, log
`/home/seorii/logs/circulusd-local-native-fault-chain-jit1k4rm.log`.
The manifest is `reports/native-fault-chain-d76e45d4ce58.json`; the actual seed
is `reports/native-seed-78546e676d4c81d8.json`, revision 1/state SHA
`sha256:0782b3ff928081078e3f12c34a8772cb5990f17d107a89b690397bc166a21068`.
Final B's response-loss report is `reports/native-response-loss-682dd276e2.json`:
one backend 200, explicit receivedBytes 0, committed revision 2/state SHA
`sha256:8ace22902b047db5e835952e3a3bc6625481cbd2be434ab136d07ebd1c65163b`,
receipt and a fresh barrier. It precedes the owner fault and retains the
original revision-1 baseline.

The actual native capacity phase committed exactly two nonce-scoped disposable
objects through B23, with A absent. Actual seed CELL
`NativeStorageQualificationCell:a832a93d22b818c04437f06c6743c7111204f8c0b16ce80303ec502d49d8bdc8`
changed from B/epoch 3 to an empty-node/epoch-3 own.json with changed ETag;
the seed was absent from B's two residents. B remained live.
`owner-native/capacity-native-result.json` retains these facts; supervised
PID 985226 exited 0, log
`/home/seorii/logs/circulusd-native-owner-capacity-iaqc7220.log`.
New A22/PID 1601344 reclaimed the seed at CELL epoch 4 by read + fresh barrier,
keeping revision 2/state unchanged. B explicitly evicted a replicated disposable,
reducing occupied slots 2→1 while retaining its exact own.json body/ETag.

The actual native owner trial completed in 12.150896465 seconds, supervised
PID 4123245, exit 0, log
`/home/seorii/logs/circulusd-native-owner-trial-cdp0x4i2.log`.
A's actual LTX PUT returned 200 and exactly one following proof GET was held.
Pinned SIGSTOP observed process state T; the retained post-STOP lease determined
the 10.699-second expiry wait. B23 claimed CELL epoch 5, saw the unacknowledged
uploaded revision 3, and committed revision 4. The proof GET was released while
A remained stopped and returned B's exact owner body/ETag. CONT produced actual
SELF-FENCE exit 3 and one HTTP 0/UNAVAILABLE request without acknowledgement;
pending driver PID 4125071 exited 0 after retaining the failure facts.
B revision 4/state SHA
`sha256:1e6f24fcccb23c81b28e4376b3f734f05b535d23e260920156b83d2a9edf318a`
remained unchanged after fresh barrier 8→9. Actual protocol/process sequences,
responses and raw termination bytes are retained in
`owner-native/owner-trial-result.json` and `owner-native/prior-termination-log.json`.
A's completed log is `/home/seorii/logs/circulusd-local-native-node-r2ociwog.log`;
its STOP/CONT transcripts are `reports/process-fault-589bd605665a.json` and
`reports/process-fault-798174b7d732.json`. Runtime probe epochs 22→23 are
separate from CELL epochs 4→5; actual proxy/direct configuration digests remain
distinct. Only the owned relay PID 1448343 was terminated after the trial,
exit 0; A had already exited 3. B23 remains live and the store was untouched.
Independent raw assembly, observation signing, conformance issuance and native
immutable publication then completed with exit 0. The exact canonical native
owner record is `owner-native/owner-observation.json`, digest
`sha256:d137481a2e96f1f777f14fa29aad6b878103bb6888ba8042569dcbb0bd4107dd`.
Final live verification also exited 0: actual verifier PID 3946724, supervisor
3945880, status `jobs/native-probe-verify-fdc84599e6.json`, completed log
`/home/seorii/logs/circulusd-local-native-probe-verify-ehbm_j7_.log`.
`reports/native-probe-verify-575896e0b8.json` records HTTP 200 and independently
verified fresh nonce signatures from both `/circulusd/state/v1/production:probe`
and `/circulusd/native-storage/v1/production:probe`, describing unchanged
B23/PID 2835395, start tick 454970 and runtime probe epoch 23.
The raw report digest is
`sha256:6a316ce7137620a368b069a1bf4bea1333165f0bea9590cac0a18217270b5ae4`;
the issued evidence digest is
`sha256:6c2a870e21759f4407e2061de1f988fa716edf5ebd488e909c615eb5895795e3`.
`native-23/issued-evidence.json` records issue time 1791649636 and expiry
1791734416 (Unix seconds). Exact atomic groups are `command-receipt` and
`native-storage`. The source's `productionEligible: true` qualifies only this
measured storage source; the verifier records `platformAdmissionReady: false`
and `productionDependencyMinted: false`. This completes stage 1 on the selected
machine, without qualifying the full Session app, served execution graph,
operational enforcement or production release, and without promoting any full
§53 profile below. Earlier failures and stock-only results remain retained.

Raw response-loss facts now retain the explicit `receivedBytes: 0` value after
completed publication under the observation mutex. The two publication
regressions passed 20 repetitions with race detection, followed by focused
Storage observer/issuer race/vet/diff checks (PID 394531, exit 0,
`/home/seorii/logs/circulusd-native-storage-byte-publication-wkp46q5u.log`).
The latest complete Go gate passed all 88 packages with race detection and
serial package execution, followed by vet and diff checks (PID 469764, exit 0,
`/home/seorii/logs/circulusd-local-go-gate-2psuxwlx.log`). These local checks
do not supply runtime qualification. The independent actual native observations,
issuance and signed live probes above complete stage 1 storage-only
qualification on this machine. Stage 2 served execution and stage 3 operational
enforcement have not begun. Admission remains closed.

The native NsJail qualification driver now measures all 13 isolation checks,
including a curated syscall denial and separate CPU/memory/PID pressure runs.
Signed inventory bounds, sealed executable bytes, authenticated READY/GO,
pinned cgroup descriptors/counters and owned cleanup are exercised by local
fault tests. Focused race/vet, diagnostic dependency checks, native helper and
arm64 helper/executor test-binary builds passed in
`/home/seorii/logs/circulusd-nsjail-enforcement-gate-gt8r6n40.log` and
`/home/seorii/logs/circulusd-nsjail-enforcement-final-tbqxxwnj.log` (exit 0).
The actual jail/helper was not run on this host; injected observations are
reference-only, and the live gate still needs provisioned signed artifacts and
dedicated roots. §53.10 remains UNAVAILABLE. The operator contract is in the
Unit 13 native-driver section of `docs/implementation-plan.md`.

| SPEC | Area | Required evidence | Current status |
|---|---|---|---|
| §53.1 | Session/Pi/extension isolation | stock workerd, two sessions, eviction and stale generation suite | NOT_RUN |
| §53.2 | Single durable state machine | Session aggregate model/property tests and multi-tool serialization | NOT_RUN: the `internal/conformance/state` gate emits the per-check `state.*` components the doctor profile requires (the §44.3 celld/state-app conformance list) and returns UNAVAILABLE for each without a provisioned celld/state host |
| §53.3 | Worker Loader | pinned workerd Loader ABI, outbound denial, cgroup and identity suite | NOT_RUN: pinned stock workerd passed content-addressed replacement, Dynamic Worker, isolate-separation, outbound-denial, and actual Pi `0.84.3` adapter checkpoint-reconstruction probes; a mock MODEL/MCP service-binding probe also passed for two concurrent content-addressed identities, while production broker authority, shard process recycle, and cgroup pressure remain NOT_RUN |
| §53.4 | TurnAuthority/capability | generation, expiry, renewal and forged-scope suite | NOT_RUN |
| §53.5 | Effect recovery | kill-before/after full durable boundary matrix | NOT_RUN |
| §53.6 | Runtime Revision | candidate, migration, CAS activation and rollback suite | NOT_RUN: the `internal/conformance/revision` gate enumerates the required §53.6 checks and returns UNAVAILABLE without a provisioned Worker Loader |
| §53.7 | Environment resolution | conflict, artifact availability and immutable digest suite | NOT_RUN: the `internal/conformance/environment` gate enumerates the required §53.7 checks and returns UNAVAILABLE without a provisioned resolver |
| §53.8 | Workspace filesystem | manifest, symlink, lease, read-only, overlay/full-scan suite | NOT_RUN: the `internal/conformance/filesystem` gate enumerates the required §53.8 checks and returns UNAVAILABLE without a provisioned sandbox/manifest pipeline |
| §53.9 | Workspace cross-DO commit | Workspace-ledger crash recovery without re-execution | NOT_RUN |
| §53.10 | NsJail | real namespace/seccomp/cgroup/network/cleanup suite | UNAVAILABLE: NsJail is not installed on this host; the `internal/conformance/nsjail` gate emits the per-check `nsjail.*` components the doctor profile requires and returns UNAVAILABLE for each without a provisioned NsJail host |
| §53.11 | Docker | real daemon hardening/process/workspace suite | NOT_RUN: CLI exists; daemon access is unverified; the `internal/conformance/docker` gate emits the per-check `docker.*` components the doctor profile requires and returns UNAVAILABLE for each without a provisioned daemon |
| §53.12 | Firecracker | real jailer/KVM/vsock/no-NIC/cleanup suite | UNAVAILABLE: Firecracker, jailer and `/dev/kvm` are absent; the `internal/conformance/firecracker` gate emits the per-check `firecracker.*` components the doctor profile requires and returns UNAVAILABLE for each without a provisioned host |
| §53.13 | Backend coexistence | three real providers sharing one Workspace authority | NOT_RUN: the cross-backend Workspace-authority logic (single mutable lease, concurrent cross-backend reads, revision visibility to the next backend) is proven reference-first in `workspace.backend-coexistence.test.ts`; the three-real-provider integration and cache-key class reuse remain external |
| §53.14 | MCP | selected-backend stdio and protocol/filter/restart suite | NOT_RUN: the broker/protocol/filter/cancellation/restart logic is implemented and tested in `internal/mcpgateway`; the `internal/conformance/mcp` gate enumerates the required §53.14 checks and returns UNAVAILABLE without a real MCP server running inside a provisioned backend |
| §53.15 | Secret | exposure-class, cleanup, audit and cache isolation suite | NOT_RUN: the `internal/conformance/secret` gate enumerates the required §53.15 checks and returns UNAVAILABLE without a provisioned secret proxy/sandbox/audit host |
| §53.16 | API/SSE | idempotency concurrency and durable replay suite | NOT_RUN |
| §53.17 | ACL/quota | cross-tenant, role and atomic quota rejection suite | NOT_RUN: the `internal/conformance/aclquota` gate enumerates the required §53.17 checks and returns UNAVAILABLE without a provisioned multi-tenant control plane |
| §53.18 | Install/upgrade | clean network-denied profile installs and rollback suite | NOT_RUN: the `internal/conformance/install` gate enumerates the required §53.18 checks and returns UNAVAILABLE without a provisioned clean network-denied host |

## Planned qualification work

Unit 10 is fixed in `docs/implementation-plan.md` as the Phase 0A workerd
resource-qualification unit. It separates CPU enforcement, RSS/cold-start,
Dynamic Worker reconstruction, pressure-driven shard recycle, and explicit
shard-kill reconstruction into independently required results while keeping
`cmd/agentd` diagnostic-only. It was re-scoped (2026-09-02) to certify the
kernel-enforced resource boundary — four required `PASS` plus one recorded
`FAIL` for the per-isolate reconstruction that stock workerd cannot perform on
the current pin — because the pinned workerd's in-isolate limits are advisory
only. The gate has now executed on a provisioned development host (recorded in
the Unit 10 bullet under external qualification notes and in
`docs/unit10-operator.md`). Its Session/checkpoint/placement fixtures remain
reference-only, so even the executed gate does not by itself satisfy §53.1,
§53.3, or §53.4, and it does not change any status in the table above.

## External qualification notes

- 2026-10-11 stage 2 integration gate: all 97 Go packages (88 with tests, nine
  without tests) passed `go test -race -p=1 ./...`, followed by
  `go vet -p=1 ./...` and `git diff --check`. Runner PID 86125 exited 0;
  completed log `/home/seorii/logs/circulusd-platform-go-gate-j9rrfq_y.log`,
  private status
  `.codex/native-platform-qualification/run-ktvkxeee/jobs/go-gate-5dede8d860.json`.
  The gate checked the exact same 526 Go source/module-file hashes before and
  after execution. Final independent reviews passed for the frozen native
  quota projection and MCP provider units. This is regression evidence;
  the actual model endpoint, Pi terminal bridge, trusted SessionHost/broker
  composition, engine/full-Session source issuance and operational stage
  remain open. No production acceptance status is promoted.

- 2026-10-11 stage 2 progress: the private full Session app builder passed six
  tests and focused static checks (PID 1850312, exit 0,
  `/home/seorii/logs/circulusd-native-state-app-builder-jhq2l36j.log`). The
  independent Pi preparation builder passed three tests, including bundled
  genesis-to-first-model execution; its initial combined gate stopped on a lint
  warning, and the corrected focused lint/diff checks passed separately. The
  native effect ledger, MCP repository/factory and model authority/quota state
  passed package race/vet checks with completed logs
  `/home/seorii/logs/circulusd-native-effect-ledger-gate-3rrwlg18.log`,
  `/home/seorii/logs/circulusd-native-mcp-final-1jozw3oi.log`, and
  `/home/seorii/logs/circulusd-native-model-primitives-gate-9t0xxfql.log`.
  These are source and local contract checks; their required atomic groups
  exceed the two groups qualified by the retained B23 storage source.
- 2026-10-11 native RPC preparation: seven harness tests verify owned-CELL
  response gating after serialization, rejection on gate failure and the
  unchanged routed path (PID 123956, exit 0,
  `/home/seorii/logs/circulusd-native-rpc-output-gate-ujflxinb.log`). Four
  isolated Git fixtures verify the exact build patch, including staged and
  unstaged tampering. The new native build exited 0 (Cargo PID 817762,
  `/home/seorii/logs/circulusd-native-celld-build-s6sbi1n7.log`) with executable
  digest `sha256:c13566938e206b3aecd72bc38c1a804416d498d35c1fbf86c52d181eec0bb61c`.
  A separate loopback bucket passed actual object-store CAS and now hosts the
  full Session app, loaded digest
  `sha256:27012482008ea862c1a93b26917f4b270cd2fa32c8f3e4a80290e8a99684579c`,
  in unsigned measurement mode (PID 2616751, start tick 799737). Its private
  root is `.codex/native-platform-qualification/run-ktvkxeee`. The retained
  storage-only B23 source is unchanged. The new graph has no independently
  issued conformance proof, served Loader/provider chain or fault qualification;
  no acceptance-table status or production capability is promoted.
- 2026-10-11 actual Session bootstrap recovery: the separately built private
  operator driver passed six tests, vet and build (PID 897776, exit 0,
  `/home/seorii/logs/circulusd-native-session-driver-final-pins-x_2mcqbv.log`).
  Its actual authenticated internal initialization returned HTTP 200 with a
  fresh version-0 result; that peer transport has no response MAC, which the
  report explicitly records. Three served read requests returned HTTP 200 with
  verified response MACs. The exact new native PID 2616751 was then killed via
  pidfd (exit -9), and a fresh local directory/process, PID 2872193/start tick
  930557/runtime epoch 2, recovered the initialized Session. Three further
  authenticated reads retained the same canonical result digest, with exact
  before/after process, boot, build, prepared/deployed artifact and measurement
  checks. The private combined report is
  `.codex/native-platform-qualification/run-ktvkxeee/reports/session-bootstrap-recovery.json`,
  digest `sha256:354096b0b4cf133f85b20e9f8b728cc73104300ed2db1224e50ad697cbfaef14`.
  Initialization/read/recovery driver PIDs 1645217, 1846332 and 3452676 all
  exited 0; their completed logs are
  `/home/seorii/logs/circulusd-platform-session-init-xz10ayu4.log`,
  `/home/seorii/logs/circulusd-platform-session-read-7z621p2k.log`, and
  `/home/seorii/logs/circulusd-platform-session-read-cold-32ipiq92.log`.
  This partial observation contains no admitted turn, provider dispatch or
  committed engine checkpoint/public-event lifecycle and does not qualify the
  full Session source, owned-RPC write fault semantics or served graph.
- 2026-10-11 provider/accounting continuation: the concrete anonymous MCP
  `2025-06-18` HTTP/SSE transport and native provider adapter passed their
  focused race/vet gates. The final provider gate exited 0 (supervisor 1277557,
  `/home/seorii/logs/circulusd-native-mcp-http-frozen-vkgtqrgv.log`). Owned
  HTTP fixtures verify single-winner calls, response loss without replay,
  cancellation/RPC-error uncertainty, cold lookup/tombstones, reference-permit
  rejection and shared concrete Storage/NativeLedger Session dispatch. The
  native Storage fixture is local contract evidence, not a qualified live
  native source. Generic MCP JSON cannot satisfy the existing Pi result
  normalizer; the authenticated Pi terminal publication remains unwired.
  The native Session quota projection passed model/bootstrap race/vet checks
  and independent frozen-source review (supervisor 773324, exit 0,
  `/home/seorii/logs/circulusd-native-session-quota-gate-pjvy2t8d.log`). It
  reads authenticated concrete Session/ledger facts, preserves original
  reservation replay after takeover, releases only pre-dispatch failure, and
  retains ambiguous charge. Commit/barrier loss and canonical v1-to-v2
  conversion pass locally. Cross-object atomic settlement remains false;
  no live provider execution, atomic quota or §53 status is promoted.

- 2026-10-08 final Go and static gate: `go test -race -p=1 ./...`,
  `go vet -p=1 ./...` and `git diff --check` all exited 0 in
  `/home/seorii/logs/circulusd-final-go-green-5w7inb_t.log`. Root `pnpm check`
  and `pnpm lint` also exited 0 in
  `/home/seorii/logs/circulusd-final-types-lint-3rffapt7.log`. An initial full
  Go run caught a diagnostic dependency regression; separating broker-aware
  workload adapters into `internal/referenceworkload` fixed it while retaining
  the existing executable dependency guards and the UDS recovery regressions.
  These commands are local regression gates, not production qualification.

- 2026-10-08 final Worker regression: all 690 tests across 50 files passed
  (state-app 396, SessionHost 55, Pi 183, protocol 56). The state-app log is
  `/home/seorii/logs/circulusd-final-worker-state-app-wu6ky85f.log` (exit 0).
  This includes six reference orchestration cases using the actual Session and
  Workspace Cells, cold Pi reconstruction, and commit-response-loss recovery.
  The operation and Pi core are reference implementations; no sandbox provider
  or native command ran in those cases. The signed-registry configuration
  planner also passed the real declarative NsJail launch-plan checks under Go
  race testing. It grants no admission or live-isolation authority.

- 2026-10-08 harness regression: 27 Node tests passed and the one unrequested
  live sandbox test skipped. Explicit startup selection now fails on missing
  binaries or backend failure; a separate process using an empty temporary
  sandbox directory proved exit 1 before any launch. The Go harness now uses
  the shared sandbox RPC client and passed real private-UDS race tests, the
  standard build/test commands, Windows test compilation and Linux ARM64
  compilation. No NsJail, Docker or unshare launcher ran during these checks.
  These results do not qualify an isolation backend or upgrade a §53 status.

- 2026-10-08 local composition evidence: separate signed public admission,
  canonical message preservation, same-domain HTTP/SSE composition and scoped
  PAT authentication passed their focused tests. The source-derived host wire
  regression passed 113 tests; Go state client/admission/bootstrap/public API
  race tests and root type/lint checks passed. The explicitly reference UDS
  workload transport passed controlrpc/broker race tests and the proto contract
  suite, including concurrent starts, response loss, malformed identities,
  role/boot rejection and no authentication retry. Its callback executor and
  process-local guards are reference evidence only. Production still lacks the
  complete grant/retry/result-body store adapter, qualified native admission
  planner, durable credential/audit/ACL composition and served runtime gates.
  No public production listener was enabled and no §53 status was promoted.

- 2026-10-08: `TestStockWorkerdFixture` passed against the locally installed
  workerd `2026-08-25` executable with SHA-256
  `b805ed481caa643953357d38146b82c118addcb525eb87e3d190b5617c82bc75`, matching the
  release manifest's extracted x86_64 pin. The live fixture exited 0; its log is
  `/home/seorii/logs/circulusd-stock-workerd-live-LZhMrehR.log`. The five
  resource/recovery components remained `NOT_RUN`, and stable-broker-binding
  remains mock. No current dedicated resource qualification configuration or
  real celld/object-store environment and signed evidence was available. This
  semantic fixture does not upgrade a §53 status or `AdmissionReady`.

- Pi Agent Core `0.84.3` and workerd `v1.20260825.1` remain short of the complete bounded-step Phase 0A gate. The digest-pinned stock workerd binary ran the actual ABI/state-v2 Pi adapter across four fresh engine/core instances over the checkpoint sequence `model -> external-tool -> model -> complete` and observed the complete extension hook sequence without Node compatibility flags. A separate probe rendezvoused the first model settlements and ran that trace concurrently for two distinct content-addressed Dynamic Workers through real Workerd service bindings backed by a deterministic mock MODEL/MCP worker; effect digests, identities, stages, bounded retry, and missing bindings were checked, and its evidence remains `mock: true`. This proves the binding and correlation shape, not production broker authorization, durable delivery, or recovery. The separately-run Unit 10 resource gate now covers the Dynamic Worker kill/recreation, shard recycle, cgroup pressure, and CPU/RSS boundaries on a provisioned host (recorded in the Unit 10 bullet below); it does not promote this §53.3 status.
- Unit 10 external resource qualification (`TestStockWorkerdResourceQualification`) reached its achievable bar on a provisioned WSL2 cgroup-v2 host against the digest-pinned stock workerd `1.20260825.1`. Four required results are non-mock external `PASS` and the fifth is a recorded honest `FAIL`, all from one release-, config-, host-, boot-, cgroup-, runner-, and run-bound canonical-CBOR envelope (`workerd-resource-observation-v1.cbor`): `workerd.cpu-limit` (kernel `cpu.max` 50000/100000 enforced — ~20 throttled periods / ~0.97 s under a runaway worker — plus supervisor SIGKILL + recycle; the in-isolate `cpuMs` limit was confirmed not to fire and is recorded as non-enforced), `workerd.rss-cold-start` (five cold starts, each ~48 MiB pidfd-verified process RSS with a distinct nonzero cgroup memory charge at the exact shard identity), `workerd.shard-pressure-recycle` (memory.current driven to ~245 MiB of a 256 MiB `memory.max` cap, OOM-killed, then reconstructed into a new isolate replaying the acknowledged checkpoint), and `workerd.shard-kill-reconstruction` (explicit whole-shard SIGKILL, then reconstruction into a new isolate replaying the acknowledged checkpoint). The recorded `FAIL` is `workerd.dynamic-worker-reconstruction`: the designated in-isolate cpuMs runaway is never aborted, so stock workerd performs no per-isolate reconstruction on this pin — a documented residual gap, never a skip or a PASS. This certifies only the kernel-enforced resource safety boundary observed on this development host; it is not a production install-profile run. The Session, checkpoint, and placement fixtures remain reference-only, `AdmissionReady` stays false while the recorded gap and every production dependency are open, `cmd/agentd` stays diagnostic-only, and §53.1, §53.3, and §53.4 remain `NOT_RUN`. Closing the per-isolate gap requires a re-pinned/rebuilt workerd that enforces isolate limits in serve mode. See `docs/unit10-operator.md`.
- The Unit 10 local closure gate passed on 2026-09-03 (native ext4 clone at `d05c9a7`): `go vet ./...` clean, `go test ./...` all packages ok, and `go test -race` (CGO_ENABLED=1) clean on `internal/agent`, the workerd conformance harness (`internal/conformance/workerd`), `internal/doctor`, `internal/broker`, and `internal/controlrpc`, with the host-independent contract packages (`internal/agent`, the workerd harness, `cmd/agentd`) additionally green under `go test -race -shuffle=on -count=5`; the TypeScript gates were also green — `pnpm check` across all five workspace projects, `pnpm lint` (oxlint `--deny-warnings`) clean, and all 507 TypeScript unit tests. This is local build/test evidence only: it does not perform the production install-profile run, does not close the recorded `workerd.dynamic-worker-reconstruction` gap, and upgrades no §53 status. `AdmissionReady` stays false.
- Production Session-read and dispatch-start consumers now accept only signed `Verified` bindings and independently enforce the `command-receipt` plus `effect-lifecycle` atomic domain before authorization, state reads, durable claims, or provider starts. Adapter tests prove that each narrow operation and its live probe use the same immutable state-app client object. The platformd bootstrap now derives one signed release pair, seals fixed requirements, loads one pinned proof bundle and credential client, verifies both interface-typed adapters sequentially, jointly checks their atomic domain, and owns concurrent-safe shutdown; bootstrap failure leaves only the diagnostic control plane available. This remains unit-level admission evidence: the pinned celld native signer, celld/state-app replacement disposal and re-challenge, durable ACL/admission/provider composition, and real crash-durability conformance are incomplete, so §53.2, §53.5, and §53.16 stay `NOT_RUN` and `state.celld` stays `NOT_WIRED`.
- The development-only subordinate ledger and deterministic fake-effect slice bind an immutable command to the complete non-secret Session dispatch identity, strip opaque dispatch/start bearers before storage and provider delivery, atomically admit one claimed start under concurrency, preserve acceptance/terminal facts across reconstruction over the same process-local store, and expose exact `absent` identities to broker recovery. These are reference fault-injection tests, not process-kill or durable-provider evidence; §53.2 and §53.5 remain `NOT_RUN`, and no production model/MCP/effect capability is promoted by them.
- The reference model Session adapter prepares a bounded `model.generate` command without caller authority, consumes only a sealed fresh Session start claim, bypasses the model gateway's independent dispatch-claim path, records provider acceptance before a bounded terminal fact write, and drains normalized streams without internal retry. Exact identity/generation/route/operation rejection and a 64-way race prove one provider call in process; durable model retrieval, quota recovery, process-kill evidence, and production composition remain `NOT_RUN`/`NOT_WIRED`.
- The reference MCP Session adapter keeps prepare free of policy, credential, provider, and repository calls, then consumes the sealed claim before authorization, availability, credential resolution, negotiation, and one provider start. It passes only a package-sealed non-secret binding, preserves provider acceptance plus external commit/output terminal facts across same-process reconstruction, rejects all four stale generations, and uses bounded cleanup writes without internal retry. Real MCP process/network kill recovery, durable negotiation, provider-ledger reconciliation, and production composition remain `NOT_RUN`/`NOT_WIRED`.
- The Unit 7 local reference gate passed `go test -race -p=1 ./...`, `go vet ./...`, TypeScript check/lint, all 507 TypeScript unit tests, and the focused 47-test Session dispatch/recovery fault matrix. This covers in-process prepare, claim, acceptance, terminal, settlement, concurrency, and four-generation rotation behavior; it is not real process-kill or durable-runtime evidence and does not change any release-profile status above.
- The Unit 8 bootstrap split keeps production and development dependency graphs in separate commands. Production now has an explicit public-listener gate, treats the current state-only candidate graph as incomplete, closes partial resources in deterministic reverse-construction order, and retains only the diagnostic UDS on failure. `platformd-dev` rejects production flags and every noncanonical/non-loopback address before construction, rechecks the bound endpoint, serves immutable diagnostic-only status and capability metadata, and passes 64 concurrent status requests. This is local lifecycle and boundary evidence only: no production public API, authentication, audit, TLS, object-store, scheduler, model, MCP, secret, state durability, or execution gate has passed, so the release statuses above remain unchanged.
- The closing Unit 8 gate passed `go test -race -p=1 ./...`, `go vet ./...`, TypeScript check/lint, all 507 TypeScript unit tests, four JSON-schema contract tests, the complete v1alpha contract checker, and isolated builds of both daemon commands. Focused race/shuffle runs also covered listener shutdown, partial/typed-nil construction, 64-way status access, concurrent close, and the bounded diagnostic HTTP/UDS surfaces.
- Unit 9 adds control-only `agentd` and `executord` shells with explicit UID-role authorities and honest diagnostic capability snapshots. Neither shell imports a workerd manager, execution provider, public listener, Docker/KVM authority, or workload route. Live local UDS integration covers platformd, agentd, and executord in canonical order and rejects a wrong server-role binding or unauthorized platformctl UID-role pair. Focused probe tests additionally cover invalid protocol evidence, timeout, cancellation, and concurrent evidence isolation. A passing `uds.protocol` result means only that those exact local endpoints completed the credentialed v1.0 role/descriptor/capability exchange. The default `/run/pi-platform` socket set is a local single-node convention; custom doctor UDS paths are not retained as component identity, and neither they nor diagnostic-shell reachability are startup authority. The 30-second shared probe deadline is not a wall-clock hard bound because synchronous, context-free path metadata validation can still block on a custom FUSE/NFS-backed path.
- Unit 9 also freezes the `sandboxd` backend and canonical execution-environment digest from mandatory launch inputs before listener construction. Sandbox RPC rejects a mismatched launch handle or permit binding before runner start, and subsequent process operations resolve only within the server-local binding created by that validated Spawn. Control and sandbox RPC servers reject metadata deadlines beyond five minutes, bound request reads to five seconds, and use a five-minute-five-second write horizon so slow response consumption cannot erase the post-deadline write margin. These are protocol and in-process fault-test results, not real NsJail, Docker, or Firecracker launch qualification.
- The versioned Unit 9 doctor report records the probe run, selected profile and required components, configuration/release/host identity, reporting `platformctl` binary digest, target boot instance, timestamps, evidence classes, and canonically name-sorted descriptor artifact references. UDS evidence intentionally has no daemon binary digest: the handshake binds the server-role label and checked protocol descriptor but does not attest a component build or release. The JSON Schema validates structure only; `internal/doctor.ValidateCurrent` performs the supplemental identity and semantic checks, measures freshness from `StartedAt`, and rejects future `FinishedAt`/`ObservedAt` values and evidence windows over 24 hours. The report is an unsigned diagnostic snapshot and no daemon consumes it as startup authority; its derived `profileQualified` or `productionEligible` field cannot replace current authenticated startup gates. Accordingly, no §53 status in the table above is upgraded by this local shell and reporting work.
- Unit 11 reference-first slices landed (host-independent). `internal/sessionstate` implements the SPEC §15.2-15.4 turn/effect state machine as a `celld.Aggregate` over a fault-injecting reference `celld.Storage`: sequential turn admission with a monotone event sequence and single active turn, the model and tool effect ladders with at-most-once dispatch and the §15.3 serial-effect invariant, commit-before-settle ordering, turn-lease plus placement/policy generation fencing with rotation rejection (§53.4 shape), and a kill/restart fault matrix that injects a crash before and after every durable transition of a complete turn (45 scenarios) and always recovers to the identical final state with no lost or duplicated transition. `internal/conformance/celld` enumerates the §15.8/§16.1 durability properties (single-writer/late-write rejection, atomic-durable commit, the commit-before-dispatch barrier, object-store CAS, read-your-writes) a provisioned celld must prove and returns `UNAVAILABLE` without a real celld host — a reference or mock probe can only produce reference-only, non-promotable evidence. This proves the recovery LOGIC only; it promotes nothing. §53.2, §53.4, and §53.5 stay `NOT_RUN`, `state.celld` stays `NOT_WIRED`, and `AdmissionReady` stays false until the celld durability gate returns a fresh external PASS from a provisioned host and the real `broker.DurableStore` composition closes. The operator runbook for that external gate — the required §15.8/§16.1 durability checks, host/object-store provisioning, and the fail-closed production admission wiring it feeds — is `docs/unit11-operator.md`.
- Unit 12 reference-first slices landed (host-independent). The §53.16 idempotency concurrency suite (`internal/platformapi`) proves, against the race-safe non-durable `MemoryStore`, that distinct and duplicate `Idempotency-Key`s racing together create exactly one durable turn per key with every duplicate converging on that key's single turn ID and no cross-key turn-ID collision, and that a single key with two distinct bodies racing yields exactly one winning turn while every caller of the losing body is rejected with an idempotency conflict. The SSE disconnect/reconnect suite proves that reconnecting from the last durable cursor with a page limit smaller than the journal covers the whole turn/effect ladder — the union of replayed events across every reconnect is exactly the contiguous durable sequence with no gap and no duplication, each reconnect carries the current snapshot, and only the caught-up page opens a live subscription — and that an ephemeral delta dropped by a disconnect never enters the durable journal, never advances the durable cursor, and never consumes a durable slot. `internal/conformance/publicrepo` pins the durable `Repository` contract and adds the reference conformance gate any celld-backed `Repository` must pass (atomic idempotency, event-sequence fencing, replay+subscribe atomicity, authorization-generation fencing, crash-durable self-report); it returns `UNAVAILABLE` without a durable harness, FAILs the non-durable `MemoryStore` on crash-durability, and marks any reference/mock PASS as non-promotable. This proves the idempotency/replay LOGIC only; it promotes nothing. §53.16 stays `NOT_RUN`, the public turn API and SSE listener stay unwired (the `cmd/platformd` `listenPublic` stub is unchanged, still enforced by `TestPlatformdProductionDependenciesExcludeReferenceProviders`), and `AdmissionReady` stays false until a durable celld-backed `Repository` (U12.4) reports crash durability and passes this gate from a served public graph (U12.5), both external-gated on Unit 11.
- Unit 12.4 celld-backed Repository composition landed (host-independent, reference-first). `internal/platformapi/celldrepo` expresses the public turn/event durable record as a pure `celld.Aggregate` (registration, per-key creation receipts, turns, the durable event journal, and the replay snapshot in canonical CBOR) applying register/create-turn/append-event with idempotent dedup, expected-sequence fencing, the turn-status transition ladder, and placement/authorization generation fencing; a kill/restart test replays the committed record through a fresh `celld.Host`. A `platformapi.Repository` adapter runs those durable writes through the celld host and serves live durable fan-out and ephemeral delivery in process, with a single mutex serializing append+publish against open+subscribe. Run against the U12.3 durable Repository conformance gate the composition passes every atomic behavioral check (idempotency, event-sequence fencing, replay+subscribe atomicity, authorization-generation fencing) and FAILs only crash-durable, because the reference `celld.Storage` is not durable; the adapter reports `CrashDurable:false`. This proves the celld composition and recovery LOGIC only; it promotes nothing. A promotable Repository requires the real crash-durable celld substrate (celld durability gate, Unit 11.6) so it reports `CrashDurable:true`, plus the served `cmd/platformd` wiring (U12.5); both stay external-gated and §53.16 stays `NOT_RUN` with `AdmissionReady` false.
- The NsJail sandbox conformance gate landed (host-independent, reference-first). `internal/conformance/nsjail` is the sandbox analogue of `internal/conformance/celld`: it enumerates the thirteen §53.10 runtime isolation properties a provisioned NsJail launcher and kernel must prove (namespace isolation, UID/GID mapping, read-only rootfs, write confinement, host-path non-exposure, `no_new_privs`, no retained capabilities, seccomp deny, cgroup CPU/memory/PID limits, default network deny, timeout/cancel teardown, sandboxd-private-UDS reachability, and post-destroy namespace/cgroup/veth/scratch cleanup) and evaluates an `IsolationProbe` fail-closed, emitting one `conformance.Result` per check via `QualifyReport` keyed by the per-check component id `internal/doctor`'s production `ConformanceProfile` requires (`nsjail.namespace`, `nsjail.seccomp`, `nsjail.workspace-roundtrip`, …) — the same granularity the wired workerd gate uses, so a real host run feeds the doctor profile directly (the `host.nftables-tool` property comes from a host probe, not this gate). A nil probe (no provisioned NsJail host) yields UNAVAILABLE for every component, a check that cannot run yields UNAVAILABLE for that component, an unmet check yields FAIL for that component alone, and a reference/mock probe's PASS is marked `reference-only`/`mock:true` and rejected by any production profile. A cross-package test in `internal/doctor` guards the gate's component set against profile drift. This defines the §53.10 contract and the probe boundary; it promotes nothing. §53.10 stays UNAVAILABLE (NsJail is absent on this host) until a real NsJail host returns an external PASS through this gate. The executor's launch-plan tests (`internal/executor/nsjail`) verify the declarative NsJail config only and never satisfy this gate. Unit 13.1 adds `internal/executor/nsjail.VerifyLaunchPlanIsolation`, a host-independent static verifier that proves the compiled `LaunchPlan` configuration encodes each of the thirteen §53.10 checks (RED-verified: a weakened config — retained caps, writable rootfs, disabled seccomp, shared net namespace, exposed docker socket, unbounded cgroup, non-ONCE jail — fails the matching check); it proves the plan encodes the boundary a real kernel then enforces, and still never promotes §53.10.
- The sibling Docker and Firecracker sandbox conformance gates landed on the same pattern (host-independent, reference-first). `internal/conformance/docker` enumerates the nine §53.11 container-hardening properties keyed by the doctor's `docker.*` components (container lifecycle/creation, non-root UID, Docker-socket invisibility, read-only rootfs, cap-drop-all + no-new-privileges hardening, cgroup CPU/memory/PID limits, default network deny, sandboxd-private-UDS reachability, and workspace-projection roundtrip); `internal/conformance/firecracker` enumerates the nine §53.12 microVM properties keyed by the doctor's `firecracker.*` components (guest boot with no silent `/dev/kvm` fallback, in-guest command execution, jailer launch restricting the API socket, vCPU/memory/scratch limits, no guest NIC in mode none, scratch cleanup after shutdown, unique per-microVM UID/GID, vsock control channel to sandboxd, and workspace-projection roundtrip). Both emit one `conformance.Result` per check via `QualifyReport`, mark a reference/mock PASS non-promotable exactly like the NsJail and celld gates, and produce exactly the per-backend component set the doctor profile requires (the `host.nftables-tool`/`host.kvm-access` host properties come from host probes) — guarded against drift by the same `internal/doctor` cross-package test. They define the §53.11/§53.12 contracts and probe boundaries; they promote nothing. §53.11 stays NOT_RUN and §53.12 stays UNAVAILABLE until a provisioned daemon/host returns an external PASS through each gate.
- The §53.13 backend-coexistence Workspace-authority logic landed reference-first (host-independent). `workers/state-app/test/workspace.backend-coexistence.test.ts` proves against the durable Workspace aggregate that exactly one mutable write lease exists regardless of which backend requests it (an nsjail holder makes a docker acquire conflict), that different backends read one shared workspace concurrently without touching the lease, that a commit publishes a new revision and releases the lease, and that the next backend both reads the latest committed revision and can take the now-free mutable lease. This proves the cross-backend authority LOGIC only (SPEC §53.13 bullets 1-3); it promotes nothing. The real three-provider integration and the cache-key network/environment/security-class reuse rules (§53.13 bullets 4-5) remain external, so §53.13 stays NOT_RUN. Those single-backend isolation contracts are held by the sandbox conformance gates (`internal/conformance/{nsjail,docker,firecracker}`).
- The MCP execution conformance gate landed (host-independent, reference-first). `internal/conformance/mcp` is the MCP analogue of the sandbox gates: it enumerates the ten §53.14 properties a provisioned stdio MCP server running inside a selected backend must prove (stdio-in-selected-backend; no server-process escape under NsJail, Docker, or Firecracker; long-lived JSON-RPC multiplexing; cancellation and server death; denied-tool rejection at the call stage; credential-raw-value non-exposure to the Pi Worker; server-initiated sampling/elicitation default-deny with audit; protocol-version-pin fail-closed) and evaluates an `ExecutionProbe` fail-closed, marking a reference/mock PASS non-promotable. The broker, protocol, filter, cancellation, and restart LOGIC is already implemented and covered by `internal/mcpgateway`'s in-process suites; this gate defines the external §53.14 contract and probe boundary — the backend-confinement checks are exactly what those unit tests cannot prove — so §53.14 stays NOT_RUN until a real MCP server inside a provisioned backend returns an external PASS.
- The secret (§53.15), ACL/quota (§53.17), and install/upgrade (§53.18) conformance gates landed on the same reference-first pattern. `internal/conformance/secret` enumerates the four §53.15 properties (proxy-only raw-value absence in sandbox/Worker, sandbox-env/file secret-use audit, temp-file cleanup, exposure-class reuse policy); `internal/conformance/aclquota` enumerates the four §53.17 properties (cross-tenant access denial, workspace member/owner role enforcement, quota-exceeded admission denial, no partial durable mutation on quota rejection); `internal/conformance/install` enumerates the eight §53.18 properties (offline lightweight install, Docker-without-KVM, Firecracker-without-Docker, full-profile independent backend verification, object-store CAS failure blocking state-plane start, unsupported-protocol fail-closed, upgrade rollback-window artifact retention, post-install doctor end-to-end turn). Each evaluates its probe fail-closed and marks a reference/mock PASS non-promotable. They define the §53.15/§53.17/§53.18 contracts and probe boundaries; they promote nothing. §53.15/§53.17/§53.18 stay NOT_RUN until a provisioned host returns an external PASS through each gate.
- The runtime-revision (§53.6), environment-resolution (§53.7), and workspace-filesystem (§53.8) conformance gates landed on the same reference-first pattern, completing dedicated external contracts for the state/runtime §53 areas. `internal/conformance/revision` enumerates the five §53.6 properties (candidate-health-fail keeps active, migration-fail keeps old state, no admission before CAS activation, old-Worker admission rejected after activation, rollback changes only the next turn); `internal/conformance/environment` enumerates the five §53.7 properties (requirement union resolves one curated environment, version conflict fails session creation, missing backend artifact blocks selection, environment-digest change forces a sandbox cache miss, no extension-specified raw image/rootfs/path); `internal/conformance/filesystem` enumerates the eleven §53.8 properties (durable-revision direct write, manifest diff for create/modify/delete/rename/chmod, absolute-symlink rejection, escaping-symlink rejection, special-file commit rejection, large blob upload, sandbox-kill revision restore, stale-sandbox commit rejection, single mutable writer lease, no-lease `/workspace` write block, overlay/full-scan diff equality). Each evaluates its probe fail-closed and marks a reference/mock PASS non-promotable. They define the §53.6/§53.7/§53.8 contracts and probe boundaries; the in-process state-app runtime-revision, `internal/environment`, and `internal/workspace` unit suites exercise the resolvable logic but never satisfy these gates. They promote nothing; §53.6/§53.7/§53.8 stay NOT_RUN until a provisioned host returns an external PASS.
- The state-plane (§44.3), audit-sink (§48.3), durable-credentials (§27.4), and fail-closed-configuration (§43.5) conformance gates landed on the same reference-first pattern, closing the last doctor-profile components that had no producer. `internal/conformance/state` emits the seven per-check `state.*` components the doctor profile requires (object-creation, sqlite-transaction, ownership-fencing, session-turn, recovery, kill-durability, replication-rpo) — the §44.3 celld/state-app conformance list underlying §53.1–5 — and is distinct from `internal/conformance/celld`, which proves the collapsed §15.8/§16.1 durability contract as the single `state.celld` aggregate. `internal/conformance/audit` emits `audit.durable-chain` and `audit.signed-checkpoint` (the §48.3 monotonic hash-chain + periodic-signed-checkpoint audit-integrity requirement); `internal/conformance/auth` emits `auth.durable-credentials` (§27.4 credentials loaded from durable key material, surviving restart, honoring rotation/expiry); `internal/conformance/configuration` emits `configuration.fail-closed` (§43.5 loader rejecting an invalid production configuration rather than continuing on a permissive default). Each evaluates its probe fail-closed via `QualifyReport`, returns UNAVAILABLE per component without a provisioned host, and marks a reference/mock PASS `reference-only`/`mock:true` and non-promotable exactly like the sandbox and celld gates; a new `internal/doctor` cross-package test (`profile_base_gates_test.go`) guards the four component families against profile drift, the sibling of the sandbox drift guard. With these, every component the production doctor profile requires now has a producer gate — the base families (`host.*`, `object-store.*`, `effect-recovery.*`, `release.*`, `uds.*`, `workerd.*`) plus these four. They promote nothing; §53.1–5 and the base audit/credential/configuration requirements stay UNAVAILABLE until a provisioned host returns an external PASS through each gate.
- celld `v0.3.0` is pinned but remains alpha; its durability and ownership contract is a separate hard gate.
- SeaweedFS `4.44` is provisional. No self-hosted offline object store is currently qualified by celld, and MinIO Community Edition does not satisfy the required conditional-write contract.
- Release pins and known missing artifacts are recorded in `deploy/airgap/release-manifest.json`.
