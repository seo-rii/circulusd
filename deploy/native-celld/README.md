# Native celld proof fork

This is a separate fork of celld source commit
`89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9`. It is not the stock v0.3.0 artifact.
The proof crate has independent wire/signature tests; a successful crate test
does not certify celld durability or grant platform admission.

`apply.py --source /absolute/pinned-clean-checkout` checks the exact Git commit
and clean tree before applying `celld-native.patch` and copying the proof crate.
The patch adds no Worker signing key or application-authenticated probe.

The owned Durable Object RPC path waits for the existing native output gate
after serializing its reply, including writes performed during serialization.
It retains the actor event until the gate succeeds; a gate failure rejects the
call. Routed RPC keeps its existing host output gate. The reviewed patch and
build validation include `crates/celld/js/harness.js`, including staged edits.
The prior storage-only fetch qualification does not qualify this Session RPC
path or any newly built executable.

The native public listener reserves both production probe paths before
WebSocket upgrades and Worker dispatch. Valid canonical challenges receive
unsigned `404` until an independent conformance proof is published. Successful
proofs use the existing exact Go protocol and sign the ASCII structured digest.
The state route includes `algorithm`; the native-storage route echoes `nonce`.

Set `CELLD_CIRCULUSD_NATIVE_CONFIG` to a private absolute JSON file:

```json
{
  "schemaVersion": 1,
  "mode": "attest",
  "measurementOutput": "/absolute/private/run/native-measurement.json",
  "runtimeKeyFile": "/absolute/private/runtime-seed.hex",
  "runtimeKeyId": "native-runtime-1",
  "instanceId": "storage-instance-1",
  "transactionDomainId": "storage-domain-1",
  "probeEpoch": 1,
  "epochGuardFile": "/absolute/private/epoch-reservation",
  "evidenceFile": "/absolute/private/run/evidence.json",
  "conformanceRootsFile": "/absolute/private/conformance-roots.json",
  "conformanceReportFile": "/absolute/private/run/raw-observations.json"
}
```

All paths are distinct and canonical. Every parent is root-owned or owned by
the effective UID and has no group/other write permission. Final input files
are owned regular files with one link and mode `0400` or `0600`; symlinks and
magic links are rejected. The runtime seed is exactly 64 lowercase hex bytes
encoding a 32-byte Ed25519 seed, without whitespace or newline. Its key is
never included in Worker configuration. Conformance roots use the existing
`conformance-evidence` envelope and must differ from the runtime ID and key.

`mode: "measure"` omits all three proof paths and permanently serves unsigned
probes. `mode: "attest"` pins the roots and key at boot; the report and evidence
files may initially be absent. Once both exist the native process reads them
through held descriptors, validates the independent evidence signature,
freshness, exact report-byte digest, report run ID and host boot ID, and exact
current measurement including PID/start ticks. It rehashes the actual executable
and publishes the immutable descriptor once. Invalid handoff exits `78`;
later file changes cannot replace the published authority.

The measurement hashes the actual `/proc/self/exe` raw executable and the
actual loaded main bundle bytes. It also hashes the complete loaded/cohosted
Worker options: sibling bytes and types, bindings, variables, compatibility,
services, metadata and crons, plus effective bucket/endpoint/region/listener,
Loader binding and authority environment. Values remain private; only their
digests appear in the measurement. Dynamic per-boot native config path, local
cache directory and node ID are excluded from the stable graph digest.

The epoch guard takes a nonblocking exclusive lock for the process lifetime.
Each startup requires a larger epoch than its persisted decimal reservation;
it fsyncs the file and the same held parent directory before proceeding. Each
startup must use a fresh measurement output path. Process restart requires new
observations and evidence for its exact measured PID, start ticks and epoch.

Qualification mode accepts only the actual deployment-from-bucket branch with
active replication, storage CAS probing, output gate and explicit
`CELLD_DURABILITY=bucket`. Control-plane deployment mutation, test-script
branches, test overrides and unsafe forwarded/public advertisements are refused.
Native re-exec exits `75` so an external supervisor discards the whole consumer
graph and performs fresh verification. Evidence expires under both wall and
monotonic clocks.

Build this fork as a separately selected raw executable artifact; its selected
artifact digest is its exact executable digest. Independently signed selection,
the external fault report, operational authority and served graph are separate
gates. Do not reuse the stock gzip archive digest or change the existing release
manifest to imply that the stock celld binary has this producer.

Focused validation:

```sh
python3 -m unittest discover -s deploy/native-celld -p test_build.py -v
CIRCULUSD_NATIVE_CELLD_SOURCE=/absolute/patched-checkout node --test scripts/tests/native-rpc-output-gate.test.mjs
cargo +1.97.0 test --offline --manifest-path deploy/native-celld/Cargo.toml --jobs 1
cargo +1.97.0 clippy --offline --manifest-path deploy/native-celld/Cargo.toml --all-targets --jobs 1 -- -D warnings
```

The RPC tests run the complete selected harness with controlled native-op
fixtures. They verify reply ordering and gate failures; they do not certify an
actual storage provider, native Loader, process isolation or served graph.

The fork build uses Rust 1.97.0, satisfies upstream's minimum 1.94.1, and uses
one Cargo job with release debug disabled, incremental compilation disabled and
LTO disabled to bound memory. Compilation logs, source/binary digests and
resource limits must be retained separately from qualification evidence.

`build.py --source /absolute/patched-checkout --output /absolute/new-artifact-directory`
starts a persistent background build and immediately reports its PID, private
log and final status path. It defaults to a unique executable tmpfs Cargo cache
with one CPU and job, and stops the build if available RAM falls below 1.5 GiB or
cache filesystem free space falls below 6 GiB. The background build removes that
default cache when it finishes, after publishing any artifact, and records
`buildRootRemoved` in its status. `--build-root` accepts an owned
mode `0700` cache named `circulusd-native-celld-build-*` directly under `/dev/shm`
or the pinned source checkout's parent. A disk cache avoids charging compiler
output against host RAM and can be reused after its prior process fully exits.
The source lockfile must already
include the added proof crate; Cargo runs with `--locked`. Validation rejects
untracked source files other than the copied proof crate and
`circulusd-native-source.json`. Cargo does not inherit `CARGO_*`, `RUSTFLAGS`,
`RUSTC*` or `RUSTDOC*` settings, except network-only `CARGO_NET_*` and
`CARGO_HTTP_*`. A successful build
retains a mode `0700` executable and mode `0600` provenance, without claiming
qualification. The final status JSON is the authoritative process result.
