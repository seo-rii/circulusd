# State-app credentials and policies

The state-app Worker accepts signed requests on six ingress paths. Each request
is authenticated with an HMAC root key that belongs to one of four credential
roles. This page lists the Worker bindings for those roles and the two host
policies. It also covers the matching Go configuration, the native preparation
input, and how to rotate a key.

Sources: `workers/state-app/src/host/ingress.ts`, `host/cells.ts`,
`host/admission.ts`, `session/broker-validation.ts`, `internal/config`,
`internal/stateappclient/credential_files_linux.go` and
`scripts/prepare-native-state-app.mjs`.

## Roles

| Role | Worker binding prefix | Signed paths (`POST`) | Go `state` fields |
|---|---|---|---|
| read | `CIRCULUSD_STATE_INGRESS_` | `/circulusd/state/v1/session-events:read`, `/circulusd/state/v1/session-blob:read` | `readKeyId`, `readRootKeyFile` |
| dispatch start | `CIRCULUSD_STATE_DISPATCH_START_` | `/circulusd/state/v1/session-dispatch-start:claim` | `dispatchStartKeyId`, `dispatchStartRootKeyFile` |
| admission | `CIRCULUSD_STATE_ADMISSION_` | `/circulusd/state/v1/session-turn:admit`, `/circulusd/state/v1/session-turn:plan` | `admissionKeyId`, `admissionRootKeyFile` |
| broker | `CIRCULUSD_STATE_BROKER_` | `/circulusd/state/v1/session-broker:execute` | `brokerKeyId`, `brokerRootKeyFile` |

Each role has four Worker bindings: `<prefix>CURRENT_KEY_ID`,
`<prefix>CURRENT_KEY`, `<prefix>PREVIOUS_KEY_ID` and `<prefix>PREVIOUS_KEY`.
Together with the two policies below, that makes 18 bindings.

The Go side holds one key per role. The Worker's previous key exists only so
that a key can be rotated without downtime (see [Rotating a key](#rotating-a-key)).

## Key format

- **Key ID:** matches `^[a-z0-9][a-z0-9._-]{0,63}$` on both sides.
- **Key material:** canonical lowercase hexadecimal of 32–256 bytes, which is
  64–512 hex characters. The Worker binding holds this hex string, and the Go
  key file holds the same string.
- **Derived keys:** both sides derive separate request and response HMAC keys
  from the root key, so request and response signatures never share a key.
- **Headers:** a request names its key in `x-circulus-state-key-id` and carries
  a 64-character lowercase hex HMAC in `x-circulus-state-signature`. The Worker
  signs its response with the key the request selected.

### Go key files

`platformd` loads the four files once, when it builds the state graph at
startup. A file is rejected unless all of the following hold:

- The path is absolute and canonical. No component is a symbolic link.
- Every parent directory is owned by root or by the process's effective UID.
  It must not be group- or world-writable, except a root-owned directory with
  the sticky bit set.
- The file is a regular file with one hard link, is owned by the process's
  effective UID, and has mode `0400` or `0600`.
- The contents are exactly the lowercase hex string. A trailing newline makes
  the file invalid.
- The four role files are different files, and the configured key IDs differ
  from each other.

A valid file can be written like this:

```sh
umask 077
openssl rand -hex 32 | tr -d '\n' > /etc/pi-platform/state/read.key
```

## What the Worker checks

- **Configured roles:** a role counts as configured when any of its four
  bindings is set. The role that serves the request must always be configured.
- **Current and previous keys:** a configured role needs a valid current ID and
  key. The previous pair is optional. If either previous binding is set, both
  must be valid.
- **Uniqueness:** no key ID and no key material may appear twice across all
  configured roles and both generations.
- **Failure scope:** any violation in any configured role makes *every* signed
  request return an unsigned `503`, not only requests for the broken role.
- **Unknown key:** a request whose key ID matches neither key of its own role
  gets an unsigned `401`. So does a request with a missing or malformed key ID
  or signature header.

## Host policies

| Binding | Exact shape | Limits |
|---|---|---|
| `CIRCULUSD_STATE_ADMISSION_POLICY` | `{"turnLeaseTTLms":120000}` | integer, 1–300000 ms |
| `CIRCULUSD_STATE_BROKER_POLICY` | `{"engineStepLimits":{"maximumEvents":1,"maximumEphemeralBytes":1048576,"maximumWallClockMs":5000},"preparationTTLms":30000}` | `maximumEvents` must be 1; the others are safe integers ≥ 1 |

Each policy is an object or a JSON string of that object. Both are exact: an
extra or missing field is invalid. The broker Store's limits must match the
broker policy (see `docs/unit11-operator.md`).

- **Missing policy:** turn planning (admission policy) or broker calls (broker
  policy) fail with `FAILED_PRECONDITION`. Other Session requests still work.
- **Malformed policy:** the `SessionCell` constructor throws. Every Session
  request then fails, not only planning or broker calls. Check the JSON before
  deploying.

## Native celld preparation

`scripts/prepare-native-state-app.mjs` builds a private Worker bundle for the
native celld host. It deploys nothing.

```sh
node scripts/prepare-native-state-app.mjs --config /abs/path/config.json --output /abs/path/new-dir
```

The configuration file must be owned by the caller, have one hard link, have
mode `0400` or `0600`, and be at most 64 KiB. It holds one JSON object with these
fields and no others (placeholders in angle brackets):

```json
{
  "schemaVersion": 1,
  "compatibilityDate": "2026-08-01",
  "compatibilityFlags": ["js_rpc"],
  "ingressCredentials": {
    "read": { "current": { "keyId": "read-2026-10", "rootKeyHex": "<hex>" }, "previous": null },
    "dispatchStart": { "current": { "keyId": "dispatch-2026-10", "rootKeyHex": "<hex>" }, "previous": null },
    "admission": { "current": { "keyId": "admission-2026-10", "rootKeyHex": "<hex>" }, "previous": null },
    "broker": { "current": { "keyId": "broker-2026-10", "rootKeyHex": "<hex>" }, "previous": null }
  },
  "admissionPolicy": { "turnLeaseTTLms": 120000 },
  "brokerPolicy": {
    "engineStepLimits": { "maximumEvents": 1, "maximumEphemeralBytes": 1048576, "maximumWallClockMs": 5000 },
    "preparationTTLms": 30000
  },
  "nativeStorage": {
    "keyId": "storage-2026-10",
    "rootKeyHex": "<exactly 64 hex characters>",
    "bounds": {
      "maxStateBytes": 16777216, "maxReceiptResponseBytes": 4194304, "maxCapabilityClaims": 64,
      "maxCapabilityClaimBytes": 1048576, "maxReceiptLookups": 64, "maxReceiptWrites": 64,
      "maxTransactionBytes": 33554432
    },
    "timeoutMs": 30000
  }
}
```

- **Flags:** `compatibilityFlags` must be sorted, must not repeat, and must
  include `js_rpc`. The supported flags are `delete_all_deletes_alarm`,
  `fetcher_no_get_put_delete`, `js_rpc`, `sqlite_vec` and
  `websocket_standard_binary_type`.
- **Credentials:** all four roles need a current key, and `previous` is a key
  or `null`. Key IDs and key material must be unique across every role,
  generation and the native-storage key. The native-storage key is exactly 32
  bytes.
- **Bounds:** each bound is an integer from 1 up to the value shown above, and
  `timeoutMs` is at most 30000.
- **Output:** the output directory must not exist yet, and its parent must be
  owned by the caller and not group- or world-writable. The script creates it
  with mode `0700` and writes `native-state-app.mjs`, `wrangler.json` and
  `manifest.json` with mode `0600`.
- **Where the values go:** the ingress keys and the native-storage key are
  compiled into `native-state-app.mjs`, so treat the bundle as a secret. The two
  policies go into `wrangler.json` as `vars`. Changing a key or a policy needs
  a new preparation.

## Rotating a key

The steps below rotate one role. Repeat them for each role you rotate.

1. **Make a key.** Generate a new key file as shown above, and pick a key ID
   that no role uses. Do not reuse a retired ID or key.
2. **Accept both keys.** On the Worker, move the old pair to the `PREVIOUS`
   bindings and set the new pair as `CURRENT`. With native celld, run the
   preparation again with `previous` set to the old key, then deploy the new
   bundle. The Worker now accepts both IDs for that role.
3. **Switch Go.** Point `<role>KeyId` and `<role>RootKeyFile` at the new key,
   and restart `platformd`.
4. **Retire the old key.** Once no running `platformd` uses the old key,
   remove the `PREVIOUS` pair (or prepare again with `previous: null`), then
   delete the old key file.

Between steps 2 and 4, every configured role must still pass the checks in
[What the Worker checks](#what-the-worker-checks). One malformed binding makes
every signed request fail.
