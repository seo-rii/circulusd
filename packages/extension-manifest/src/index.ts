import { digestBytes, digestStructuredValue } from "@circulusd/protocol-types";
import type { Digest } from "@circulusd/protocol-types";
import * as ts from "typescript/unstable/ast";
import { createVirtualFileSystem } from "typescript/unstable/fs";
import { API as TypeScriptAPI } from "typescript/unstable/sync";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const ZERO_DIGEST = `sha256:${"0".repeat(64)}` as Digest;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const EXTENSION_ID_PATTERN = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?\/[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/;
const SIMPLE_ID_PATTERN = /^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/;
const TOOL_NAME_PATTERN = /^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+$/;
const COMMAND_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,126}[A-Za-z0-9])?$/;
const BUNDLE_SEGMENT_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,127})?$/;
const SEMVER_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:(?:0|[1-9]\d*)|[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:(?:0|[1-9]\d*)|[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const VERSION_RANGE_PATTERN = /^(?:(?:(?:<=|>=|<|>|=|~|\^)?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))(?: +(?:<=|>=|<|>|=|~|\^)?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))*|(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))?\.x)$/;

const MAX_MANIFEST_ITEMS = 10_000;
const MAX_FILES = 512;
const MAX_FILE_BYTES = 1_048_576;
const MAX_SCHEMA_BYTES = 262_144;
const MAX_BUNDLE_BYTES = 8 * 1_048_576;
const MAX_PATH_BYTES = 256;
const MAX_SOURCE_IMPORTS = 256;
const MAX_AST_NODES = 10_000;
const MAX_AST_DEPTH = 256;

const COMPATIBILITY = [
  "worker",
  "pi-server",
  "node-compatible",
  "legacy-node",
  "native-sidecar",
] as const;
const HOOKS = [
  "initialize",
  "beforeAgentStart",
  "beforeTurn",
  "beforeModelRequest",
  "afterModelResponse",
  "beforeToolCall",
  "afterToolCall",
  "afterTurn",
  "snapshot",
  "shutdown",
] as const;
const REPLAY_MODES = ["safe", "idempotency-key", "confirm", "never"] as const;
const STATE_SCOPES = ["user", "workspace", "session"] as const;
const BACKENDS = ["nsjail", "docker", "firecracker"] as const;
const PROCESS_SCOPES = ["shared", "tenant", "session"] as const;
const OUTER_ISOLATIONS = ["none", "nsjail", "docker", "firecracker"] as const;
const NETWORK_MODES = ["none", "mcp-only", "lan-allowlist", "proxy", "custom"] as const;
const MODULE_EXTENSIONS = [".mjs", ".js", ".mts", ".ts"] as const;

export class ExtensionManifestError extends Error {
  readonly path: string;

  constructor(path: string, message: string) {
    super(`${path}: ${message}`);
    this.name = "ExtensionManifestError";
    this.path = path;
  }
}

type Compatibility = (typeof COMPATIBILITY)[number];
type Hook = (typeof HOOKS)[number];
type ReplayMode = (typeof REPLAY_MODES)[number];
type StateScope = (typeof STATE_SCOPES)[number];
type Backend = (typeof BACKENDS)[number];
type ProcessScope = (typeof PROCESS_SCOPES)[number];
type OuterIsolation = (typeof OUTER_ISOLATIONS)[number];
type NetworkMode = (typeof NETWORK_MODES)[number];

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

export interface NormalizedExtensionManifest {
  readonly apiVersion: "pi.platform/v1alpha2";
  readonly kind: "Extension";
  readonly metadata: {
    readonly id: string;
    readonly version: string;
    readonly publisher: string;
    readonly digest: Digest;
  };
  readonly runtime: {
    readonly compatibility: Compatibility;
    readonly entry: string;
    readonly piApiVersion: "v1";
    readonly priority: number;
  };
  readonly configuration: {
    readonly schema: string;
    readonly defaults: JsonValue;
  };
  readonly hooks: readonly Hook[];
  readonly tools: readonly {
    readonly name: string;
    readonly inputSchema: string;
    readonly outputSchema: string;
    readonly replay: { readonly mode: ReplayMode };
  }[];
  readonly permissions: {
    readonly workspace: { readonly read: boolean; readonly write: boolean };
    readonly execution: {
      readonly required: boolean;
      readonly commands: readonly string[];
      readonly packages: readonly { readonly id: string; readonly version: string }[];
    };
    readonly network: { readonly mode: NetworkMode };
    readonly mcp: { readonly servers: readonly string[] };
    readonly secrets: readonly string[];
  };
  readonly state: {
    readonly scope: StateScope;
    readonly schemaVersion: number;
    readonly migrationsFrom: readonly number[];
  };
  readonly execution: { readonly supportedBackends: readonly Backend[] };
  readonly security: {
    readonly requestedMinimumAgentIsolation: {
      readonly processScope: ProcessScope;
      readonly outerIsolation: OuterIsolation;
    };
  };
}

export interface CompiledExtensionRevision {
  readonly manifest: NormalizedExtensionManifest;
  readonly contentDigest: Digest;
  readonly revisionDigest: Digest;
  readonly moduleGraph: readonly {
    readonly path: string;
    readonly imports: readonly string[];
    readonly digest: Digest;
  }[];
  readonly schemaDigests: readonly { readonly path: string; readonly digest: Digest }[];
}

export type ExtensionBundleFiles = Readonly<Record<string, string | Uint8Array>>;

interface SnapshotFile {
  readonly path: string;
  readonly bytes: Uint8Array;
}

interface PreparedExtension {
  readonly manifest: NormalizedExtensionManifest;
  readonly files: readonly SnapshotFile[];
  readonly moduleGraph: readonly { readonly path: string; readonly imports: readonly string[] }[];
  readonly schemas: readonly { readonly path: string; readonly value: JsonValue }[];
}

function fail(path: string, message: string): never {
  throw new ExtensionManifestError(path, message);
}

function plainRecord(value: unknown, path: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(path, "must be a plain object");
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    fail(path, "must be a plain object with Object.prototype");
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") {
      fail(path, "symbol keys are not allowed");
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
      fail(`${path}.${key}`, "must be an enumerable data property");
    }
  }
  return value as Record<string, unknown>;
}

function exactRecord(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
  path: string,
): Record<string, unknown> {
  const record = plainRecord(value, path);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      fail(`${path}.${key}`, `unknown field ${JSON.stringify(key)}`);
    }
  }
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) {
      fail(`${path}.${key}`, "is required");
    }
  }
  return record;
}

function boundedString(
  value: unknown,
  path: string,
  maxBytes: number,
  options: { readonly allowControls?: boolean; readonly requireNfc?: boolean } = {},
): string {
  if (typeof value !== "string" || value.length === 0) {
    fail(path, "must be a non-empty string");
  }
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        fail(path, "must contain only Unicode scalar values");
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      fail(path, "must contain only Unicode scalar values");
    }
  }
  if (options.requireNfc !== false && value !== value.normalize("NFC")) {
    fail(path, "must be NFC-normalized");
  }
  if (options.allowControls !== true && /\p{Cc}/u.test(value)) {
    fail(path, "must not contain control characters");
  }
  if (textEncoder.encode(value).byteLength > maxBytes) {
    fail(path, `must not exceed ${maxBytes} UTF-8 bytes`);
  }
  return value;
}

function literal<T extends string>(value: unknown, expected: T, path: string): T {
  if (value !== expected) {
    fail(path, `must be ${JSON.stringify(expected)}`);
  }
  return expected;
}

function oneOf<const T extends readonly string[]>(
  value: unknown,
  allowed: T,
  path: string,
): T[number] {
  if (typeof value !== "string" || !allowed.includes(value)) {
    fail(path, `must be one of ${allowed.join(", ")}`);
  }
  return value;
}

function booleanValue(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") {
    fail(path, "must be a boolean");
  }
  return value;
}

function boundedInteger(value: unknown, path: string, minimum: number, maximum: number): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    fail(path, `must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function boundedArray(value: unknown, path: string, maximum: number): readonly unknown[] {
  if (!Array.isArray(value)) {
    fail(path, "must be an array");
  }
  if (Object.getPrototypeOf(value) !== Array.prototype) {
    fail(path, "must be a plain array");
  }
  if (value.length > maximum) {
    fail(path, `must have at most ${maximum} entries`);
  }
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor)) {
      fail(`${path}[${index}]`, "must be a dense data element");
    }
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key === "symbol") {
      fail(path, "symbol properties are not allowed");
    }
    if (typeof key === "string" && key !== "length" && !/^(?:0|[1-9]\d*)$/.test(key)) {
      fail(`${path}.${key}`, "array properties are not allowed");
    }
  }
  return value;
}

function manifestPath(value: unknown, path: string, requiredExtension?: string): string {
  const result = boundedString(value, path, MAX_PATH_BYTES);
  if (result.startsWith("/") || result.includes("\\") || result.includes("?") || result.includes("#")) {
    fail(path, "must be a canonical bundle-relative POSIX path");
  }
  const segments = result.split("/");
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    fail(path, "must not contain empty, dot, or parent segments");
  }
  if (segments.some((segment) => !BUNDLE_SEGMENT_PATTERN.test(segment))) {
    fail(path, "must contain only canonical ASCII bundle path segments");
  }
  if (requiredExtension !== undefined && !result.endsWith(requiredExtension)) {
    fail(path, `must end with ${requiredExtension}`);
  }
  return result;
}

function uniqueSortedStrings(
  value: unknown,
  path: string,
  maximum: number,
  validate: (entry: unknown, entryPath: string) => string,
): readonly string[] {
  const entries = boundedArray(value, path, maximum);
  const result = entries.map((entry, index) => validate(entry, `${path}[${index}]`));
  const seen = new Set<string>();
  for (const entry of result) {
    if (seen.has(entry)) {
      fail(path, `contains duplicate entry ${JSON.stringify(entry)}`);
    }
    seen.add(entry);
  }
  return result.sort();
}

function normalizeJson(value: unknown, path: string): JsonValue {
  let items = 0;
  const visit = (current: unknown, currentPath: string, depth: number): JsonValue => {
    items += 1;
    if (items > MAX_MANIFEST_ITEMS) {
      fail(path, `must contain at most ${MAX_MANIFEST_ITEMS} JSON values`);
    }
    if (depth > 64) {
      fail(currentPath, "must not exceed 64 levels");
    }
    if (current === null || typeof current === "boolean") {
      return current;
    }
    if (typeof current === "number") {
      if (!Number.isFinite(current) || Object.is(current, -0)) {
        fail(currentPath, "must be a finite JSON number other than negative zero");
      }
      return current;
    }
    if (typeof current === "string") {
      return boundedString(current, currentPath, 65_536);
    }
    if (Array.isArray(current)) {
      return boundedArray(current, currentPath, MAX_MANIFEST_ITEMS).map((entry, index) =>
        visit(entry, `${currentPath}[${index}]`, depth + 1),
      );
    }
    const record = plainRecord(current, currentPath);
    const normalized: Record<string, JsonValue> = {};
    for (const key of Object.keys(record).sort()) {
      boundedString(key, `${currentPath}.$key`, 256);
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        fail(`${currentPath}.${key}`, "dangerous object key is not allowed");
      }
      normalized[key] = visit(record[key], `${currentPath}.${key}`, depth + 1);
    }
    return normalized;
  };
  return visit(value, path, 0);
}

function normalizeManifest(value: unknown): NormalizedExtensionManifest {
  const root = exactRecord(
    value,
    [
      "apiVersion",
      "kind",
      "metadata",
      "runtime",
      "configuration",
      "hooks",
      "tools",
      "permissions",
      "state",
      "execution",
      "security",
    ],
    [],
    "$manifest",
  );
  const metadata = exactRecord(
    root.metadata,
    ["id", "version", "publisher", "digest"],
    [],
    "$manifest.metadata",
  );
  const id = boundedString(metadata.id, "$manifest.metadata.id", 128);
  if (!EXTENSION_ID_PATTERN.test(id)) {
    fail("$manifest.metadata.id", "must be a canonical two-segment extension ID");
  }
  const version = boundedString(metadata.version, "$manifest.metadata.version", 64);
  if (!SEMVER_PATTERN.test(version)) {
    fail("$manifest.metadata.version", "must be a strict semantic version");
  }
  const publisher = boundedString(metadata.publisher, "$manifest.metadata.publisher", 128);
  if (!SIMPLE_ID_PATTERN.test(publisher)) {
    fail("$manifest.metadata.publisher", "must be a canonical publisher ID");
  }
  if (typeof metadata.digest !== "string" || !DIGEST_PATTERN.test(metadata.digest)) {
    fail("$manifest.metadata.digest", "must be sha256: followed by 64 lowercase hexadecimal characters");
  }

  const runtime = exactRecord(
    root.runtime,
    ["compatibility", "entry", "piApiVersion", "priority"],
    [],
    "$manifest.runtime",
  );
  const entry = manifestPath(runtime.entry, "$manifest.runtime.entry");
  if (!MODULE_EXTENSIONS.some((extension) => entry.endsWith(extension))) {
    fail("$manifest.runtime.entry", "must name a JavaScript or TypeScript ESM module");
  }

  const configuration = exactRecord(
    root.configuration,
    ["schema", "defaults"],
    [],
    "$manifest.configuration",
  );
  const hooks = uniqueSortedStrings(root.hooks, "$manifest.hooks", HOOKS.length, (hook, path) =>
    oneOf(hook, HOOKS, path),
  ) as readonly Hook[];

  const toolInputs = boundedArray(root.tools, "$manifest.tools", 128);
  const toolNames = new Set<string>();
  const tools = toolInputs.map((value, index) => {
    const path = `$manifest.tools[${index}]`;
    const tool = exactRecord(
      value,
      ["name", "inputSchema", "outputSchema", "replay"],
      [],
      path,
    );
    const name = boundedString(tool.name, `${path}.name`, 128);
    if (!TOOL_NAME_PATTERN.test(name)) {
      fail(`${path}.name`, "must be a dot-separated canonical tool name");
    }
    if (toolNames.has(name)) {
      fail(`${path}.name`, `duplicate tool ${JSON.stringify(name)}`);
    }
    toolNames.add(name);
    const replay = exactRecord(tool.replay, ["mode"], [], `${path}.replay`);
    return {
      name,
      inputSchema: manifestPath(tool.inputSchema, `${path}.inputSchema`, ".json"),
      outputSchema: manifestPath(tool.outputSchema, `${path}.outputSchema`, ".json"),
      replay: { mode: oneOf(replay.mode, REPLAY_MODES, `${path}.replay.mode`) },
    };
  });
  tools.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));

  const permissions = exactRecord(
    root.permissions,
    ["workspace", "execution", "network", "mcp", "secrets"],
    [],
    "$manifest.permissions",
  );
  const workspace = exactRecord(
    permissions.workspace,
    ["read", "write"],
    [],
    "$manifest.permissions.workspace",
  );
  const executionPermission = exactRecord(
    permissions.execution,
    ["required", "commands", "packages"],
    [],
    "$manifest.permissions.execution",
  );
  const commands = uniqueSortedStrings(
    executionPermission.commands,
    "$manifest.permissions.execution.commands",
    128,
    (command, path) => {
      const result = boundedString(command, path, 128);
      if (!COMMAND_PATTERN.test(result)) {
        fail(path, "must be a command name, not a path");
      }
      return result;
    },
  );
  const packageInputs = boundedArray(
    executionPermission.packages,
    "$manifest.permissions.execution.packages",
    128,
  );
  const packageIds = new Set<string>();
  const packages = packageInputs.map((value, index) => {
    const path = `$manifest.permissions.execution.packages[${index}]`;
    const requirement = exactRecord(value, ["id", "version"], [], path);
    const packageId = boundedString(requirement.id, `${path}.id`, 128);
    if (!SIMPLE_ID_PATTERN.test(packageId)) {
      fail(`${path}.id`, "must be a canonical curated package ID");
    }
    if (packageIds.has(packageId)) {
      fail(`${path}.id`, `duplicate package requirement ${JSON.stringify(packageId)}`);
    }
    packageIds.add(packageId);
    const range = boundedString(requirement.version, `${path}.version`, 128);
    if (!VERSION_RANGE_PATTERN.test(range)) {
      fail(`${path}.version`, "must be a bounded semantic-version comparator range");
    }
    return { id: packageId, version: range };
  });
  packages.sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
  const network = exactRecord(
    permissions.network,
    ["mode"],
    [],
    "$manifest.permissions.network",
  );
  const mcp = exactRecord(permissions.mcp, ["servers"], [], "$manifest.permissions.mcp");
  const servers = uniqueSortedStrings(
    mcp.servers,
    "$manifest.permissions.mcp.servers",
    128,
    (server, path) => {
      const result = boundedString(server, path, 128);
      if (!SIMPLE_ID_PATTERN.test(result)) {
        fail(path, "must be a canonical MCP server ID");
      }
      return result;
    },
  );
  const secrets = uniqueSortedStrings(
    permissions.secrets,
    "$manifest.permissions.secrets",
    128,
    (secret, path) => {
      const result = boundedString(secret, path, 128);
      if (!SIMPLE_ID_PATTERN.test(result)) {
        fail(path, "must be a canonical secret handle ID");
      }
      return result;
    },
  );

  const state = exactRecord(
    root.state,
    ["scope", "schemaVersion", "migrationsFrom"],
    [],
    "$manifest.state",
  );
  const schemaVersion = boundedInteger(
    state.schemaVersion,
    "$manifest.state.schemaVersion",
    1,
    1_000_000,
  );
  const migrationInputs = boundedArray(
    state.migrationsFrom,
    "$manifest.state.migrationsFrom",
    1_000,
  );
  const migrationsFrom = migrationInputs.map((migration, index) => {
    const versionValue = boundedInteger(
      migration,
      `$manifest.state.migrationsFrom[${index}]`,
      1,
      1_000_000,
    );
    if (versionValue >= schemaVersion) {
      fail(
        `$manifest.state.migrationsFrom[${index}]`,
        "must be lower than the current schemaVersion",
      );
    }
    return versionValue;
  });
  if (new Set(migrationsFrom).size !== migrationsFrom.length) {
    fail("$manifest.state.migrationsFrom", "must not contain duplicate versions");
  }
  migrationsFrom.sort((left, right) => left - right);

  const execution = exactRecord(
    root.execution,
    ["supportedBackends"],
    [],
    "$manifest.execution",
  );
  const supportedBackends = uniqueSortedStrings(
    execution.supportedBackends,
    "$manifest.execution.supportedBackends",
    BACKENDS.length,
    (backend, path) => oneOf(backend, BACKENDS, path),
  ) as readonly Backend[];
  if (supportedBackends.length === 0) {
    fail("$manifest.execution.supportedBackends", "must name at least one backend");
  }

  const security = exactRecord(
    root.security,
    ["requestedMinimumAgentIsolation"],
    [],
    "$manifest.security",
  );
  const isolation = exactRecord(
    security.requestedMinimumAgentIsolation,
    ["processScope", "outerIsolation"],
    [],
    "$manifest.security.requestedMinimumAgentIsolation",
  );

  return {
    apiVersion: literal(root.apiVersion, "pi.platform/v1alpha2", "$manifest.apiVersion"),
    kind: literal(root.kind, "Extension", "$manifest.kind"),
    metadata: { id, version, publisher, digest: metadata.digest as Digest },
    runtime: {
      compatibility: oneOf(
        runtime.compatibility,
        COMPATIBILITY,
        "$manifest.runtime.compatibility",
      ),
      entry,
      piApiVersion: literal(runtime.piApiVersion, "v1", "$manifest.runtime.piApiVersion"),
      priority: boundedInteger(runtime.priority, "$manifest.runtime.priority", -1_000_000, 1_000_000),
    },
    configuration: {
      schema: manifestPath(
        configuration.schema,
        "$manifest.configuration.schema",
        ".json",
      ),
      defaults: normalizeJson(configuration.defaults, "$manifest.configuration.defaults"),
    },
    hooks,
    tools,
    permissions: {
      workspace: {
        read: booleanValue(workspace.read, "$manifest.permissions.workspace.read"),
        write: booleanValue(workspace.write, "$manifest.permissions.workspace.write"),
      },
      execution: {
        required: booleanValue(
          executionPermission.required,
          "$manifest.permissions.execution.required",
        ),
        commands,
        packages,
      },
      network: {
        mode: oneOf(network.mode, NETWORK_MODES, "$manifest.permissions.network.mode"),
      },
      mcp: { servers },
      secrets,
    },
    state: {
      scope: oneOf(state.scope, STATE_SCOPES, "$manifest.state.scope"),
      schemaVersion,
      migrationsFrom,
    },
    execution: { supportedBackends },
    security: {
      requestedMinimumAgentIsolation: {
        processScope: oneOf(
          isolation.processScope,
          PROCESS_SCOPES,
          "$manifest.security.requestedMinimumAgentIsolation.processScope",
        ),
        outerIsolation: oneOf(
          isolation.outerIsolation,
          OUTER_ISOLATIONS,
          "$manifest.security.requestedMinimumAgentIsolation.outerIsolation",
        ),
      },
    },
  };
}

function snapshotFiles(value: ExtensionBundleFiles): readonly SnapshotFile[] {
  const record = plainRecord(value, "$files");
  const paths = Object.keys(record).sort();
  if (paths.length > MAX_FILES) {
    fail("$files", `must contain at most ${MAX_FILES} files`);
  }
  let totalBytes = 0;
  return paths.map((rawPath) => {
    const path = manifestPath(rawPath, `$files[${JSON.stringify(rawPath)}]`);
    if (path.endsWith(".node")) {
      fail(`$files[${JSON.stringify(rawPath)}]`, "native addons are forbidden");
    }
    const raw = record[rawPath];
    let bytes: Uint8Array;
    if (typeof raw === "string") {
      boundedString(raw, `$files[${JSON.stringify(rawPath)}]`, MAX_FILE_BYTES, {
        allowControls: true,
        requireNfc: false,
      });
      bytes = textEncoder.encode(raw);
    } else if (raw instanceof Uint8Array && Object.getPrototypeOf(raw) === Uint8Array.prototype) {
      bytes = Uint8Array.from(raw);
    } else {
      fail(`$files[${JSON.stringify(rawPath)}]`, "must be a string or exact Uint8Array");
    }
    if (bytes.byteLength > MAX_FILE_BYTES) {
      fail(`$files[${JSON.stringify(rawPath)}]`, `must not exceed ${MAX_FILE_BYTES} bytes`);
    }
    totalBytes += bytes.byteLength;
    if (totalBytes > MAX_BUNDLE_BYTES) {
      fail("$files", `must not exceed ${MAX_BUNDLE_BYTES} bytes in total`);
    }
    return { path, bytes };
  });
}

function prepareExtension(value: unknown, bundleFiles: ExtensionBundleFiles): PreparedExtension {
  const manifest = normalizeManifest(value);
  const files = snapshotFiles(bundleFiles);
  const fileByPath = new Map(files.map((file) => [file.path, file]));
  if (!fileByPath.has(manifest.runtime.entry)) {
    fail("$manifest.runtime.entry", "does not exist in the bundle");
  }

  const resolveImport = (importer: string, specifierValue: string): string => {
    const specifier = boundedString(specifierValue, `$files[${JSON.stringify(importer)}].import`, 256);
    if (!specifier.startsWith("./") && !specifier.startsWith("../")) {
      fail(
        `$files[${JSON.stringify(importer)}].import`,
        `import ${JSON.stringify(specifier)} must be relative`,
      );
    }
    if (specifier.includes("\\") || specifier.includes("?") || specifier.includes("#")) {
      fail(`$files[${JSON.stringify(importer)}].import`, "must be a canonical relative path");
    }
    const specifierSegments = specifier.split("/");
    let sawNamedSegment = false;
    for (let index = 0; index < specifierSegments.length; index += 1) {
      const segment = specifierSegments[index];
      if (segment === "" || (segment === "." && index !== 0)) {
        fail(`$files[${JSON.stringify(importer)}].import`, "must be a canonical relative path");
      }
      if (segment === "..") {
        if (sawNamedSegment) {
          fail(`$files[${JSON.stringify(importer)}].import`, "must be a canonical relative path");
        }
      } else if (segment !== ".") {
        if (segment === undefined || !BUNDLE_SEGMENT_PATTERN.test(segment)) {
          fail(`$files[${JSON.stringify(importer)}].import`, "must be a canonical relative path");
        }
        sawNamedSegment = true;
      }
    }
    const segments = importer.split("/");
    segments.pop();
    for (const segment of specifierSegments) {
      if (segment === "." || segment === "") {
        continue;
      }
      if (segment === "..") {
        if (segments.length === 0) {
          fail(`$files[${JSON.stringify(importer)}].import`, "escapes the extension root");
        }
        segments.pop();
      } else {
        segments.push(segment);
      }
    }
    const resolved = manifestPath(
      segments.join("/"),
      `$files[${JSON.stringify(importer)}].import`,
    );
    if (resolved.endsWith(".node")) {
      fail(`$files[${JSON.stringify(importer)}].import`, "native addons are forbidden");
    }
    if (
      !MODULE_EXTENSIONS.some((extension) => resolved.endsWith(extension)) &&
      !resolved.endsWith(".wasm")
    ) {
      fail(
        `$files[${JSON.stringify(importer)}].import`,
        "must use an explicit supported ESM or Wasm extension",
      );
    }
    if (!fileByPath.has(resolved)) {
      fail(
        `$files[${JSON.stringify(importer)}].import`,
        `module ${JSON.stringify(resolved)} is missing`,
      );
    }
    return resolved;
  };

  const virtualSources: Record<string, string> = {
    "/extension/tsconfig.json": JSON.stringify({
      compilerOptions: {
        allowJs: true,
        checkJs: false,
        module: "preserve",
        noLib: true,
        target: "esnext",
      },
      include: ["**/*.js", "**/*.mjs", "**/*.ts", "**/*.mts"],
    }),
  };
  for (const file of files) {
    if (!MODULE_EXTENSIONS.some((extension) => file.path.endsWith(extension))) {
      continue;
    }
    try {
      virtualSources[`/extension/${file.path}`] = textDecoder.decode(file.bytes);
    } catch {
      fail(`$files[${JSON.stringify(file.path)}]`, "module must be valid UTF-8");
    }
  }
  const typeScript = new TypeScriptAPI({
    cwd: "/extension",
    fs: createVirtualFileSystem(virtualSources),
  });
  const snapshot = typeScript.updateSnapshot({ openProjects: ["/extension/tsconfig.json"] });
  const project = snapshot.getProjects()[0];
  if (project === undefined) {
    snapshot.dispose();
    typeScript.close();
    fail("$files", "TypeScript could not create the hermetic module project");
  }

  const graph = new Map<string, readonly string[]>();
  let astNodes = 0;
  const visitModule = (path: string): void => {
    if (graph.has(path)) {
      return;
    }
    const file = fileByPath.get(path);
    if (file === undefined) {
      fail(`$files[${JSON.stringify(path)}]`, "module is missing");
    }
    if (path.endsWith(".wasm")) {
      graph.set(path, []);
      return;
    }
    const absolutePath = `/extension/${path}`;
    const sourceFile = project.program.getSourceFile(absolutePath);
    if (sourceFile === undefined) {
      fail(`$files[${JSON.stringify(path)}]`, "TypeScript could not parse the module");
    }
    if (project.program.getSyntacticDiagnostics(absolutePath).length > 0) {
      fail(`$files[${JSON.stringify(path)}]`, "contains invalid ECMAScript syntax");
    }
    const imports: string[] = [];
    const addImport = (specifier: ts.Expression): void => {
      if (!ts.isStringLiteral(specifier)) {
        fail(`$files[${JSON.stringify(path)}].import`, "static import must use a string literal");
      }
      imports.push(resolveImport(path, specifier.text));
      if (imports.length > MAX_SOURCE_IMPORTS) {
        fail(`$files[${JSON.stringify(path)}]`, `must not import more than ${MAX_SOURCE_IMPORTS} modules`);
      }
    };
    const calledName = (expression: ts.Expression): string | undefined => {
      let current = expression;
      while (ts.isParenthesizedExpression(current)) {
        current = current.expression;
      }
      if (ts.isIdentifier(current)) {
        return current.text;
      }
      if (ts.isPropertyAccessExpression(current)) {
        return current.name.text;
      }
      if (
        ts.isElementAccessExpression(current) &&
        current.argumentExpression !== undefined &&
        ts.isStringLiteral(current.argumentExpression)
      ) {
        return current.argumentExpression.text;
      }
      return undefined;
    };
    const walk = (node: ts.Node, depth: number): void => {
      astNodes += 1;
      if (astNodes > MAX_AST_NODES) {
        fail("$files", `bundle module graph must not exceed ${MAX_AST_NODES} AST nodes`);
      }
      if (depth > MAX_AST_DEPTH) {
        fail(`$files[${JSON.stringify(path)}]`, `must not exceed AST depth ${MAX_AST_DEPTH}`);
      }
      if (
        ts.isIdentifier(node) &&
        (node.text === "require" || node.text === "eval" || node.text === "Function")
      ) {
        fail(`$files[${JSON.stringify(path)}]`, `${node.text} is forbidden`);
      }
      if (
        (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) &&
        (node.text === "require" || node.text === "eval" || node.text === "Function")
      ) {
        fail(`$files[${JSON.stringify(path)}]`, `${node.text} is forbidden`);
      }
      if (
        ts.isElementAccessExpression(node) &&
        ts.isStringLiteral(node.argumentExpression) &&
        (node.argumentExpression.text === "require" ||
          node.argumentExpression.text === "eval" ||
          node.argumentExpression.text === "Function")
      ) {
        fail(
          `$files[${JSON.stringify(path)}]`,
          `${node.argumentExpression.text} is forbidden`,
        );
      }
      if (ts.isImportDeclaration(node)) {
        addImport(node.moduleSpecifier);
      } else if (ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined) {
        addImport(node.moduleSpecifier);
      } else if (ts.isImportEqualsDeclaration(node)) {
        fail(`$files[${JSON.stringify(path)}]`, "TypeScript import-equals is forbidden");
      } else if (ts.isCallExpression(node)) {
        if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
          fail(`$files[${JSON.stringify(path)}]`, "dynamic import is forbidden");
        }
        const name = calledName(node.expression);
        if (name === "require" || name === "eval" || name === "Function") {
          fail(`$files[${JSON.stringify(path)}]`, `${name} is forbidden`);
        }
      } else if (ts.isNewExpression(node)) {
        const name = calledName(node.expression);
        if (name === "Function") {
          fail(`$files[${JSON.stringify(path)}]`, "Function is forbidden");
        }
      }
      node.forEachChild((child) => walk(child, depth + 1));
    };
    walk(sourceFile, 0);
    imports.sort();
    for (let index = 1; index < imports.length; index += 1) {
      if (imports[index] === imports[index - 1]) {
        imports.splice(index, 1);
        index -= 1;
      }
    }
    graph.set(path, imports);
    for (const imported of imports) {
      visitModule(imported);
    }
  };
  try {
    visitModule(manifest.runtime.entry);
  } finally {
    snapshot.dispose();
    typeScript.close();
  }

  const visiting = new Set<string>();
  const visited = new Set<string>();
  const detectCycle = (path: string): void => {
    if (visiting.has(path)) {
      fail("$files", `module cycle detected at ${JSON.stringify(path)}`);
    }
    if (visited.has(path)) {
      return;
    }
    visiting.add(path);
    for (const imported of graph.get(path) ?? []) {
      detectCycle(imported);
    }
    visiting.delete(path);
    visited.add(path);
  };
  detectCycle(manifest.runtime.entry);

  const schemaPaths = new Set<string>([manifest.configuration.schema]);
  for (const tool of manifest.tools) {
    schemaPaths.add(tool.inputSchema);
    schemaPaths.add(tool.outputSchema);
  }
  const schemas = [...schemaPaths]
    .sort()
    .map((path) => {
      const file = fileByPath.get(path);
      if (file === undefined) {
        fail(`$files[${JSON.stringify(path)}]`, "referenced JSON Schema is missing");
      }
      if (file.bytes.byteLength > MAX_SCHEMA_BYTES) {
        fail(`$files[${JSON.stringify(path)}]`, `JSON Schema must not exceed ${MAX_SCHEMA_BYTES} bytes`);
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(textDecoder.decode(file.bytes)) as unknown;
      } catch {
        fail(`$files[${JSON.stringify(path)}]`, "must contain valid UTF-8 JSON");
      }
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        fail(`$files[${JSON.stringify(path)}]`, "JSON Schema root must be an object");
      }
      return { path, value: normalizeJson(parsed, `$files[${JSON.stringify(path)}]`) };
    });

  return {
    manifest,
    files,
    moduleGraph: [...graph.entries()]
      .map(([path, imports]) => ({ path, imports }))
      .sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0)),
    schemas,
  };
}

function deepFreeze(value: unknown): void {
  if (value === null || typeof value !== "object" || ArrayBuffer.isView(value) || Object.isFrozen(value)) {
    return;
  }
  for (const key of Reflect.ownKeys(value)) {
    deepFreeze((value as Record<PropertyKey, unknown>)[key]);
  }
  Object.freeze(value);
}

async function contentDigest(prepared: PreparedExtension): Promise<Digest> {
  const fileDigests: { path: string; size: number; digest: Digest }[] = [];
  for (const file of prepared.files) {
    fileDigests.push({
      path: file.path,
      size: file.bytes.byteLength,
      digest: await digestBytes(file.bytes),
    });
  }
  const manifestWithoutDigest = {
    ...prepared.manifest,
    metadata: { ...prepared.manifest.metadata, digest: ZERO_DIGEST },
  };
  return digestStructuredValue("circulusd.extension.content", 1, {
    manifest: manifestWithoutDigest,
    files: fileDigests,
  });
}

export async function computeExtensionContentDigest(
  value: unknown,
  bundleFiles: ExtensionBundleFiles,
): Promise<Digest> {
  const prepared = prepareExtension(value, bundleFiles);
  deepFreeze(prepared.manifest);
  return contentDigest(prepared);
}

export async function compileExtensionManifest(
  value: unknown,
  bundleFiles: ExtensionBundleFiles,
): Promise<CompiledExtensionRevision> {
  const prepared = prepareExtension(value, bundleFiles);
  const computedContentDigest = await contentDigest(prepared);
  if (computedContentDigest !== prepared.manifest.metadata.digest) {
    fail(
      "$manifest.metadata.digest",
      `does not match computed extension content digest ${computedContentDigest}`,
    );
  }

  const fileByPath = new Map(prepared.files.map((file) => [file.path, file]));
  const moduleGraph: {
    path: string;
    imports: readonly string[];
    digest: Digest;
  }[] = [];
  for (const module of prepared.moduleGraph) {
    const file = fileByPath.get(module.path);
    if (file === undefined) {
      fail(`$files[${JSON.stringify(module.path)}]`, "module disappeared from snapshot");
    }
    moduleGraph.push({
      path: module.path,
      imports: [...module.imports],
      digest: await digestBytes(file.bytes),
    });
  }
  const schemaDigests: { path: string; digest: Digest }[] = [];
  for (const schema of prepared.schemas) {
    const file = fileByPath.get(schema.path);
    if (file === undefined) {
      fail(`$files[${JSON.stringify(schema.path)}]`, "schema disappeared from snapshot");
    }
    schemaDigests.push({ path: schema.path, digest: await digestBytes(file.bytes) });
  }
  const revisionDigest = await digestStructuredValue("circulusd.extension.revision", 1, {
    manifest: prepared.manifest,
    moduleGraph,
    schemaDigests,
  });
  const result: CompiledExtensionRevision = {
    manifest: prepared.manifest,
    contentDigest: computedContentDigest,
    revisionDigest,
    moduleGraph,
    schemaDigests,
  };
  deepFreeze(result);
  return result;
}
