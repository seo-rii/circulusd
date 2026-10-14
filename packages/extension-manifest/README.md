# @circulusd/extension-manifest

This package validates and compiles Pi extension manifests in TypeScript. A
manifest has `apiVersion: pi.platform/v1alpha2` and `kind: Extension`
(`SPEC.md` §13).

## What it does

- **`compileExtensionManifest(manifest, bundleFiles)`** validates a manifest
  and its bundle files and returns a `CompiledExtensionRevision`. It checks:
  - ids, versions, hooks, tools and permissions
  - module and schema paths
  - size limits
  - that `metadata.digest` matches the computed content digest

  It scans module imports with the TypeScript AST API (`typescript/unstable`)
  and returns the module graph, the schema digests and a revision digest.
- **`computeExtensionContentDigest`** computes only the content digest.
- **Configuration JSON** (`src/configuration-*.ts`):
  - normalizes extension configuration values and digests them as extension
    JSON;
  - validates configuration schemas as JSON Schema draft 2020-12 with Ajv,
    including local `$dynamicRef` handling.

The package has no build step. `exports` points at `src/index.ts`.

## Contract

The Go counterpart is `internal/extensionregistry`. The JSON vectors in
`fixtures/` are read by both test suites:

- `configuration-json-v2.json`
- `configuration-dynamicref-v1.json`
- `configuration-multipleof-v1.json`

On the Go side the readers are `configuration_codec_test.go`,
`configuration_dynamicref_test.go` and `configuration_multipleof_test.go`.

## Test

```sh
pnpm --filter @circulusd/extension-manifest test    # vitest
pnpm --filter @circulusd/extension-manifest check   # tsc
go test ./internal/extensionregistry                # Go side of the shared fixtures
```
