# Command reference

This page describes the 11 commands under `cmd/`: what each one does, its flags
and defaults, and its exit codes. Everything here comes from the flag
definitions and command code. It describes the current behavior, not the
target state in `SPEC.md` (for example, SPEC §43 also lists `platformctl`
subcommands that do not exist yet).

| Command | Kind | Platform |
|---|---|---|
| [`platformd`](#platformd) | production platform daemon (control socket only today) | Linux |
| [`platformd-dev`](#platformd-dev) | development diagnostic daemon | Linux |
| [`agentd`](#agentd) | diagnostic-only control shell | Linux |
| [`executord`](#executord) | diagnostic-only control shell | Linux |
| [`sandboxd`](#sandboxd) | in-sandbox process supervisor, started by a launcher | Linux |
| [`platformctl`](#platformctl) | operator CLI (`capabilities`, `doctor`) | Linux |
| [`objectstore-qualify`](#objectstore-qualify) | S3 conditional-write probe | Linux and other Unix systems |
| [`native-storage-cas-observe`](#native-storage-cas-observe) | raw S3 conditional-response observation | Linux |
| [`celld-storage-observe`](#celld-storage-observe) | raw celld storage observations | Linux and other Unix systems |
| [`native-owner-observe`](#native-owner-observe) | native ownership hand-off observation | Linux and other Unix systems |
| [`celld-storage-issue`](#celld-storage-issue) | native storage evidence issuer | Linux |

Commands marked Linux build only on Linux, because they depend on code that
exists only in `_linux.go` files. The other three use
`golang.org/x/sys/unix` and also build for `GOOS=darwin`.

## Common conventions

- **Building.** Build all commands with `go build -o <dir>/ ./cmd/...`, or run
  one with `go run ./cmd/<name>`.
- **Flags.** Every command uses Go's `flag` package. `-name value`,
  `--name value` and `--name=value` are equivalent. Apart from the
  `platformctl` subcommand, no command accepts positional arguments.
- **Repeatable flags.** Flags described as repeatable take one value per
  occurrence. A UID must be a canonical decimal unsigned 32-bit integer.
  Repeating the same UID is an error, and each list holds at most 64 UIDs.
- **Single-use flags.** In `agentd`, `executord` and `sandboxd`, flags that are
  not repeatable may be given only once.
- **Signals.** The daemons stop on `SIGINT` or `SIGTERM` and then exit `0`.
- **Help.** `-h` prints flag help and exits `2` for `platformd`,
  `platformd-dev`, `agentd`, `executord`, `sandboxd` and each `platformctl`
  subcommand. The other five commands discard flag help and print a one-line
  error.

### Control sockets

`platformd`, `platformd-dev`, `agentd` and `executord` serve the private
control protocol (package `internal/controlrpc`, `ControlService` in
`api/proto/circulus/v1alpha/common.proto`). The server enforces these rules:

- **Path.** The socket path must be canonical and absolute, and at most
  107 bytes.
- **Parent directory.** The parent directory path must contain no symbolic
  link. The directory must be owned by the daemon's effective UID and must not
  be writable by group or others. A socket placed directly in `/tmp`
  therefore fails.
- **Socket file.** The socket file must not already exist. The daemon creates
  it with mode `0600` and removes it on shutdown.
- **Peers.** Each connection is authenticated by the peer UID from
  `SO_PEERCRED`. A UID may use only the protocol roles granted to it.

### `pi-platform` and `circulusd` names

The repository, Go module and Helm chart are named `circulusd`. `SPEC.md` and
the platform daemons' default paths use the name `pi-platform`:

- `/etc/pi-platform/config.yaml`
- `/etc/pi-platform/release-trust-roots.json`
- `/usr/lib/pi-platform/release-manifest.json`
- `/run/pi-platform/*.sock`

`sandboxd` is the exception: its defaults are under `/etc/circulusd` and
`/run/circulusd`. Nothing discovers these paths at run time. They are only
flag defaults, so pass explicit flags for any other layout.

## platformd

The production platform daemon.

```text
platformd [--socket PATH] [--config PATH] [--release-manifest PATH]
          [--release-trust-roots PATH] [--allow-uid UID]...
```

| Flag | Default | Meaning |
|---|---|---|
| `--socket` | `/run/pi-platform/platformd.sock` | Control socket path. |
| `--config` | `/etc/pi-platform/config.yaml` | Platform configuration. |
| `--release-manifest` | `/usr/lib/pi-platform/release-manifest.json` | Signed release manifest. |
| `--release-trust-roots` | `/etc/pi-platform/release-trust-roots.json` | Offline release trust roots. |
| `--allow-uid` | the daemon's effective UID | Peer UID allowed to use the control socket as `platformctl`. Repeatable. |

**Paths.** All four paths must be canonical, absolute and free of control
characters.

**Startup.** `platformd` runs the production state bootstrap
(`internal/statebootstrap`) with the configuration, release manifest and trust
roots. The production graph is not composed yet, so this step always ends with
`platformd: production graph is unavailable` on stderr. The daemon keeps
running and serves only the control socket. It serves no public API.

**Capabilities.** The control socket reports `control.protocol` as available.
It reports these capabilities as unavailable with reason `NOT_WIRED`:

- `agent.isolation`, `api.public`
- `execution.docker`, `execution.environments`, `execution.firecracker`,
  `execution.nsjail`
- `extension.registry`, `mcp.gateway`, `model.gateway`
- `resource.profiles`, `state.celld`

**Configuration.** The configuration file is YAML parsed by `internal/config`.
`SPEC.md` §45 has a production-shaped example.

**Exit codes:**

- `0`: stopped by a signal.
- `1`: the control socket could not be opened or served.
- `2`: invalid flags, positional arguments or paths.

## platformd-dev

The development daemon. It is diagnostic-only and accepts no production
configuration or release inputs.

```text
platformd-dev [--listen ADDR] [--socket PATH] [--allow-uid UID]...
```

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `127.0.0.1:8081` | HTTP listen address. |
| `--socket` | `/run/pi-platform/platformd-dev.sock` | Control socket path. |
| `--allow-uid` | the daemon's effective UID | Peer UID allowed to use the control socket as `platformctl`. Repeatable. |

**Listen address.** `--listen` must be a canonical literal loopback address with
a nonzero port, such as `127.0.0.1:8081` or `[::1]:8081`. Host names, wildcard
addresses, zones and IPv4-mapped IPv6 addresses are rejected.

**HTTP.** The HTTP listener serves only `GET /v1/status`. It returns a fixed JSON
document with `"profile":"development-reference"`,
`"mode":"diagnostic-only"`, `"productionEligible":false` and
`"admissionEnabled":false`. The document also reports `NOT_WIRED` state and
execution. `api/json-schema/v1alpha/development-status.schema.json` defines
its shape. Other paths return `404`. Other methods on `/v1/status` return
`405` with `Allow: GET`.

**Capabilities.** The control socket reports `control.protocol` and
`api.development-status` as available. It reports these capabilities as
unavailable with reason `NOT_WIRED`:

- `agent.isolation`, `api.public`, `execution.environments`
- `mcp.gateway`, `model.gateway`, `state.celld`

**Exit codes:**

- `0`: stopped by a signal.
- `1`: a listener could not be opened or served.
- `2`: invalid flags, listen address or socket path.

## agentd

A diagnostic-only control shell for the agentd role. It starts no workerd and
admits no workload (package `internal/daemonshell`).

```text
agentd [--socket PATH] [--allow-platformd-uid UID]... [--allow-platformctl-uid UID]...
```

| Flag | Default | Meaning |
|---|---|---|
| `--socket` | `/run/pi-platform/agentd.sock` | Control socket path. Given at most once. |
| `--allow-platformd-uid` | none | Peer UID that may authenticate as `platformd`. Repeatable. |
| `--allow-platformctl-uid` | none | Peer UID that may authenticate as `platformctl`. Repeatable. |

**Required UIDs.** At least one UID flag is required. Each UID gets exactly the
role of the flag that names it. Giving one UID both roles is allowed.

**Capabilities.** The socket reports `control.protocol` and `daemon.agentd` as
available. It reports `agent.isolation` and `agent.workerd` as unavailable
with reason `NOT_WIRED`. Every capability carries these attributes:

- `admissionEnabled=false`
- `daemonRole=agentd`
- `productionEligible=false`
- `runtimeProfile=diagnostic-only`

**Querying.** Use `platformctl capabilities --server-role agentd` to query this
socket. Without that flag, `platformctl capabilities` expects `platformd` and
fails with `code=data_loss`. `platformctl doctor` probes this socket with the
expected `AGENTD` role.

**Exit codes:**

- `0`: stopped by a signal.
- `1`: the socket could not be opened or served.
- `2`: invalid flags or socket path, or no UID authority.

## executord

A diagnostic-only control shell for the executord role. It constructs no
execution provider (package `internal/daemonshell`).

```text
executord [--socket PATH] [--allow-platformd-uid UID]... [--allow-platformctl-uid UID]...
```

| Flag | Default | Meaning |
|---|---|---|
| `--socket` | `/run/pi-platform/executord.sock` | Control socket path. Given at most once. |
| `--allow-platformd-uid` | none | Peer UID that may authenticate as `platformd`. Repeatable. |
| `--allow-platformctl-uid` | none | Peer UID that may authenticate as `platformctl`. Repeatable. |

**Behavior.** The rules, attributes (with `daemonRole=executord`) and exit
codes are the same as for [`agentd`](#agentd). Query it with
`platformctl capabilities --server-role executord`.

**Capabilities.** The socket reports `control.protocol` and `daemon.executord`
as available. It reports these capabilities as unavailable with reason
`NOT_WIRED`:

- `execution.docker`, `execution.environments`
- `execution.firecracker`, `execution.nsjail`

## sandboxd

The process supervisor that runs inside a sandbox. A launcher starts it with
launch-time authority. It serves `SandboxProcessService` (package
`internal/sandboxrpc`) to the executord peer.

```text
sandboxd --sandbox-id ID --generation N --backend nsjail|docker|firecracker \
         --execution-environment-digest sha256:HEX --protocol-version 1 \
         --command-manifest-owner-uid UID --allow-client-uid UID... \
         [--control-socket PATH] [--command-manifest PATH]  3<NONCE_PIPE
```

| Flag | Default | Meaning |
|---|---|---|
| `--control-socket` | `/run/circulusd/control/control.sock` | Private socket path. Canonical, absolute, at most 107 bytes. |
| `--command-manifest` | `/etc/circulusd/commands.json` | Sealed command manifest. Canonical and absolute. |
| `--command-manifest-owner-uid` | required | Expected owner UID of the manifest. Not `0` or `4294967295`. |
| `--sandbox-id` | required | Sandbox identity, for example `sandbox_` followed by 26 base32 characters. |
| `--generation` | required | Canonical decimal from 1 to 2^53-1. |
| `--backend` | required | `nsjail`, `docker` or `firecracker`. |
| `--execution-environment-digest` | required | `sha256:` followed by 64 lowercase hex digits. |
| `--protocol-version` | required | Must be `1`. |
| `--allow-client-uid` | required | Peer UID allowed to use the socket. Repeatable. |

Every flag except `--allow-client-uid` may be given only once.

**Launch nonce.** File descriptor 3 must be a pipe (FIFO) that delivers
exactly 32 bytes: the one-time launch nonce for the handshake.

**Command manifest.** The manifest must meet all of these conditions:

- It is a regular file with one link, owned by `--command-manifest-owner-uid`.
- It is not writable by group or others, and its size is at most 1 MiB.
- It is strict JSON: `{"schemaVersion": 1, "commands": [{"name": ..., "path": ...}]}`.
- It lists 1 to 1024 commands, with unique names in sorted order. A name is
  1 to 128 bytes, is not `.` or `..`, and contains no `/`, `\` or NUL.
- Each path is canonical and absolute, and is not under `/workspace`,
  `/scratch`, `/tmp`, `/run`, `/proc`, `/dev` or `/sys`.

**Socket.** The socket's parent directory path must contain no symbolic link.
The directory must have mode exactly `0700` and be owned by sandboxd's
effective UID. The socket file must not already exist.

**Process runner.** The bundled runner uses `os/exec` with workspace root
`/workspace`. The surrounding NsJail, Docker or Firecracker sandbox provides
isolation.

**Exit codes:**

- `0`: the server stopped cleanly.
- `1`: the manifest, nonce, supervisor or socket failed.
- `2`: invalid flags or launch authority.

## platformctl

The operator CLI. It has two subcommands. `platformctl` with no subcommand, or
an unknown one, prints `usage: platformctl <doctor|capabilities> [options]` and
exits `2`.

### platformctl capabilities

This subcommand queries a control socket as the `platformctl` role and prints
the capability list as one JSON document on stdout. The document contains:

- `apiVersion`
- `protocol`: the major and minor version and the descriptor digest
- `serverSequence`
- `capabilities`: sorted by name

```text
platformctl capabilities [--server-role ROLE] [--socket PATH] [--timeout DURATION]
```

| Flag | Default | Meaning |
|---|---|---|
| `--server-role` | `platformd` | Role the server must authenticate as: `platformd`, `agentd` or `executord`. |
| `--socket` | the role's socket | Control socket path. Canonical and absolute. Defaults to `/run/pi-platform/platformd.sock`, `/run/pi-platform/agentd.sock` or `/run/pi-platform/executord.sock` for the selected role. |
| `--timeout` | `30s` | Request timeout. Must be greater than 0 and at most `5m`. |

**Server role.** The server must authenticate as the role given by
`--server-role`. `platformd` and `platformd-dev` both identify as `platformd`.
Any other role value exits `2`.

**Exit codes:**

- `0`: success.
- `1`: the query failed (stderr shows the Connect code) or the response was
  invalid.
- `2`: invalid flags.

### platformctl doctor

This subcommand runs the doctor probes for an install profile and prints the
doctor report as JSON on stdout. The probes are:

- **`host.*`:** host checks, including at least 5 GiB of free space and
  100,000 free inodes in the configured `server.dataDirectory`;
- **`release.signature`;**
- **`uds.protocol`:** this probe checks the three daemon sockets.

```text
platformctl doctor [--config PATH] [--profile NAME] [--release-manifest PATH]
                   [--release-trust-roots PATH] [--platformd-socket PATH]
                   [--agentd-socket PATH] [--executord-socket PATH]
                   [--uds-timeout DURATION]
```

| Flag | Default | Meaning |
|---|---|---|
| `--config` | `/etc/pi-platform/config.yaml` | Platform configuration. Canonical and absolute. |
| `--profile` | `full` | `lightweight`, `docker`, `full`, `firecracker` or `development`. |
| `--release-manifest` | `/usr/lib/pi-platform/release-manifest.json` | Release manifest. Canonical and absolute. |
| `--release-trust-roots` | `/etc/pi-platform/release-trust-roots.json` | Offline release trust roots. Canonical and absolute. |
| `--platformd-socket` | `/run/pi-platform/platformd.sock` | Socket expected to answer as `PLATFORMD`. |
| `--agentd-socket` | `/run/pi-platform/agentd.sock` | Socket expected to answer as `AGENTD`. |
| `--executord-socket` | `/run/pi-platform/executord.sock` | Socket expected to answer as `EXECUTORD`. |
| `--uds-timeout` | `30s` | Total budget for the socket probe. Must be greater than 0 and at most `30s`. |

The three socket paths must be distinct, canonical and absolute, at most 107
bytes, and free of control characters.

**Configuration and profile.** The configuration is parsed and validated for
`--profile`. The profile must match `execution.allowedBackends`:

| Profile | Allowed backends |
|---|---|
| `lightweight` | NsJail only |
| `docker` | Docker only |
| `firecracker` | Firecracker only |
| `full` | NsJail or Docker; Firecracker optional |
| `development` | NsJail or Docker, without Firecracker |

Every profile except `development` is a production profile. A release
manifest that cannot be loaded or validated stops the command with exit `1`
before a report is produced.

**`release.signature` result:**

| Release manifest | Profile | Result |
|---|---|---|
| status `development` | non-production (`development`) | `PASS`, as reference-only mock evidence |
| status `development` | production | `FAIL` |
| any other status | trust-roots file missing | `NOT_RUN` |
| any other status | trust roots invalid or verification failed | `FAIL` |
| any other status | trust roots valid and verification passed | `PASS` |

**Report.** The report binds the run to these digests and identities:

- the SHA-256 digest of the configuration file;
- the release manifest's signing digest (`release.ManifestSigningDigest`);
- the host identity, a hash of `/etc/machine-id`;
- the `platformctl` binary, a hash of `/proc/self/exe`;
- the boot identity, a hash of `/proc/sys/kernel/random/boot_id`.

`api/json-schema/v1alpha/doctor-report.schema.json` describes the report
structure.

**Exit codes:**

- `0`: the report says the profile is qualified.
- `1`: the report was printed but the profile is not qualified, or an error
  occurred before the report. Examples are an unreadable configuration and a
  profile that does not match the configured backends.
- `2`: invalid flags, paths or timeout, or an unknown profile name.

## objectstore-qualify

This command checks native S3 conditional-write behavior in one existing bucket
that you configure explicitly. It writes and conditionally removes only its own
nonce-named `.doctor/cas-*` probe object. It provisions nothing and does not use the AWS
SDK's default credential discovery.

```text
objectstore-qualify --config PATH --output PATH
```

| Flag | Default | Meaning |
|---|---|---|
| `--config` | required | JSON configuration, at most 64 KiB, with no unknown or duplicate fields. |
| `--output` | required | New report file. Its directory must be owned by the caller and not accessible to group or others. The file is created with mode `0600` and must not exist. |

**Configuration fields:**

- `schemaVersion: 1`
- `endpoint`, `region` and `bucket`
- `credentials`: one of these two forms:
  - `{"source": "file", "file": PATH}`: a private JSON file with `accessKeyId`,
    `secretAccessKey` and optional `sessionToken`;
  - `{"source": "environment"}`: reads `AWS_ACCESS_KEY_ID`,
    `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`.
- optional limits:
  - `requestTimeoutMillis`, at most 30000;
  - `probeTimeoutMillis`, default 30000, at most 120000;
  - `cleanupTimeoutMillis`, default 5000, at most 30000;
  - `maximumObjectBytes`.

[`unit11-operator.md`](../unit11-operator.md) has a full example.

**Output.** The command writes the report, then prints the status and the
credential source on stdout.

**Exit codes:**

- `0`: `PASS`.
- `2`: `UNAVAILABLE`, such as a missing configuration file or missing
  credentials.
- `1`: any other result, including usage errors.

## native-storage-cas-observe

This command records actual S3 conditional responses against one configured
bucket. It writes a nonce-scoped `.doctor/raw-cas-*` object and cleans it up.
Its output is the raw CAS observation for a native storage report. It does not
sign or issue conformance.

```text
native-storage-cas-observe --config PATH --output PATH
```

| Flag | Default | Meaning |
|---|---|---|
| `--config` | required | Private JSON configuration: a regular file owned by the caller, with no group or other permissions, at most 64 KiB. |
| `--output` | required | New private facts file. |

**Configuration fields.** The fields are the same as for
[`objectstore-qualify`](#objectstore-qualify), with these defaults and bounds:

- `requestTimeoutMillis`: default 5000, from 1 to 30000;
- `probeTimeoutMillis`: default 30000, from 1 to 120000;
- `cleanupTimeoutMillis`: default 5000, from 1 to 30000;
- `maximumObjectBytes`: default 1 MiB, from 128 bytes to 1 MiB.

**Exit codes:**

- `0`: observations retained.
- `2`: usage error, invalid configuration or credentials, or unverifiable
  provider responses (`UNAVAILABLE`).
- `1`: the report could not be reserved or written (`FAIL`).

## celld-storage-observe

This command records bounded, authenticated HTTP facts from one explicitly
configured local celld. It gives no durability verdict, starts or stops no
process, and provisions nothing.

```text
celld-storage-observe --config PATH --phase PHASE --output PATH [--seed PATH]
```

| Flag | Default | Meaning |
|---|---|---|
| `--config` | required | Private JSON configuration (see below). |
| `--phase` | required | `seed`, `verify`, `stale-cas` or `response-loss`. |
| `--seed` | none | Report from an earlier `seed` phase. Required for every phase except `seed`, and not allowed with `seed`. |
| `--output` | required | New private raw report. |

**Configuration fields:**

- `schemaVersion: 1`
- `endpoint`: a loopback celld endpoint
- `keyId`
- `rootKeyHex` and `runId`: 64 lowercase hex digits each
- `requestTimeoutMillis`: 1 to 30000
- `timeoutMillis`: 1 to 120000
- `claimedBinding`: `releaseDigest`, `executableDigest`, `applicationDigest`,
  `effectiveConfigDigest`, `durabilityDomain` and `durabilityEpoch`

In the `response-loss` phase the command places a local relay in front of
celld. The relay drops one response.

**Exit codes:**

- `0`: facts recorded.
- `2`: the recorded errors include an `UNAVAILABLE` or `TIMEOUT` code.
- `1`: usage or configuration errors, or other recorded errors.

## native-owner-observe

This command controls a local S3 relay that you select explicitly, and records
one authenticated pending write. It is used for the native ownership hand-off
experiment. It does not issue evidence or start, signal or stop any owner
process.

```text
native-owner-observe --config PATH --mode relay
native-owner-observe --config PATH --mode control --operation arm --cell-id ID --prior-epoch N
native-owner-observe --config PATH --mode control --operation status|release
native-owner-observe --config PATH --mode commit --output PATH
```

| Flag | Default | Meaning |
|---|---|---|
| `--config` | required | Private JSON configuration. |
| `--mode` | none | `relay`, `control` or `commit`. |
| `--operation` | none | For `control`: `arm`, `status` or `release`. |
| `--cell-id` | none | For `control --operation arm`: the exact native cell ID. |
| `--prior-epoch` | `0` | For `control --operation arm`: the exact prior cell epoch. Must be nonzero. |
| `--output` | none | For `commit`: a new private facts file. |

**Configuration fields.** Every mode needs `schemaVersion: 1` and
`requestTimeoutMillis` (1 to 30000). The modes then need these fields:

- **`relay` and `control`:**
  - `listenAddress` and `upstreamEndpoint`: both loopback, with different
    `host:port` values
  - `bucket` and an optional `keyPrefix`
  - `controlSocket`: absolute, under 100 bytes
  - `holdTimeoutMillis`: 1 to 120000
- **`commit`:** `endpoint`, `keyId`, `rootKeyHex` and `objectId`.

**Modes:**

- `relay` runs until `SIGINT` or `SIGTERM`.
- `control` prints the relay's JSON reply on stdout.
- `commit` writes its facts to `--output`.

**Exit codes:**

- `0`: success.
- `2`: `commit` recorded its facts but the write failed.
- `1`: anything else, including invalid arguments.

## celld-storage-issue

This command consumes independently signed raw observations and issues native
storage evidence. It runs no service, generates no key, writes no bucket and
promotes no platform release.

```text
celld-storage-issue --config PATH --output PATH
```

| Flag | Default | Meaning |
|---|---|---|
| `--config` | required | Private issuer configuration. |
| `--output` | required | New evidence file in a directory owned by the caller. |

**Configuration fields:**

- `schemaVersion: 1`
- `lifetimeSeconds`: 1 to 86400
- the paths of the input files:
  - `selectionFile`
  - `releaseRootsFile`, `observerRootsFile` and `runtimeRootsFile`
  - `conformanceSeedFile`
  - `measurementFile`, `rawReportFile` and `ownerObservationFile`
  - `executableFile`, `applicationFile`, `hostBootIdFile` and `driverFile`
- the signing key IDs `conformanceKeyId` and `runtimeKeyId`

**Output.** On success the command writes the evidence and prints a JSON summary
on stdout:

```json
{"schemaVersion":1,"kind":"circulusd.native-storage-issued/v1","evidenceDigest":"sha256:...","platformAdmissionReady":false}
```

**Exit codes:**

- `0`: evidence issued.
- `2`: usage error, invalid configuration, or incomplete fault observations
  (`UNAVAILABLE`).
- `1`: verification failed, or the output could not be written (`FAIL`).
