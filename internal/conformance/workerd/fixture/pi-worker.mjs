// workers/pi-runtime/src/errors.ts
var PiRuntimeError = class extends Error {
  code;
  constructor(code, message, options) {
    super(message, options);
    this.name = "PiRuntimeError";
    this.code = code;
  }
};
var BoundaryFault = class extends Error {
  code;
  constructor(code, message, options) {
    super(message, options);
    this.name = "BoundaryFault";
    this.code = code;
  }
};

// workers/pi-runtime/src/authority.ts
var MAX_AUTHORITY_BYTES = 4096;
var OpaqueTurnAuthority = class {
  #token;
  constructor(token) {
    if (!(token instanceof Uint8Array) || Object.getPrototypeOf(token) !== Uint8Array.prototype || token.byteLength === 0 || token.byteLength > MAX_AUTHORITY_BYTES) {
      throw new PiRuntimeError(
        "INVALID_CONTEXT",
        `turn authority must contain 1..${MAX_AUTHORITY_BYTES} opaque bytes`
      );
    }
    this.#token = new Uint8Array(token);
    Object.freeze(this);
  }
  toString() {
    return "[OpaqueTurnAuthority REDACTED]";
  }
  toJSON() {
    return "[OpaqueTurnAuthority REDACTED]";
  }
  isPresent() {
    return this.#token.byteLength > 0;
  }
};
function createOpaqueTurnAuthority(token) {
  return new OpaqueTurnAuthority(token);
}

// packages/protocol-types/src/errors.ts
var ProtocolValidationError = class extends Error {
  path;
  constructor(path, message) {
    super(`${path}: ${message}`);
    this.name = "ProtocolValidationError";
    this.path = path;
  }
};
function validationError(path, message) {
  throw new ProtocolValidationError(path, message);
}

// packages/protocol-types/src/text.ts
function assertUnicodeScalarString(value, path) {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 55296 && codeUnit <= 56319) {
      const following = value.charCodeAt(index + 1);
      if (!(following >= 56320 && following <= 57343)) {
        validationError(path, "must contain only valid Unicode scalar values");
      }
      index += 1;
      continue;
    }
    if (codeUnit >= 56320 && codeUnit <= 57343) {
      validationError(path, "must contain only valid Unicode scalar values");
    }
  }
  return value;
}

// packages/protocol-types/src/cbor.ts
var DEFAULT_MAX_DEPTH = 64;
var textEncoder = new TextEncoder();
var textDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
function checkedLimit(value, fallback, name) {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 0) {
    validationError(`options.${name}`, "must be a non-negative safe integer");
  }
  return resolved;
}
function normalize(value, path, depth, maxDepth, itemBudget, seen) {
  if (depth > maxDepth) {
    validationError(path, `maximum depth ${maxDepth} exceeded`);
  }
  if (itemBudget.items >= itemBudget.maxItems) {
    validationError(path, `encoded item limit ${itemBudget.maxItems} exceeded`);
  }
  itemBudget.items += 1;
  if (value === null || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "string") {
    assertUnicodeScalarString(value, path);
    return value.normalize("NFC");
  }
  if (typeof value === "number") {
    if (Object.is(value, -0)) {
      validationError(path, "negative zero is unsupported");
    }
    if (!Number.isSafeInteger(value)) {
      validationError(path, "numbers must be safe integers; floating-point values are unsupported");
    }
    return value;
  }
  if (value instanceof Uint8Array) {
    if (Object.getPrototypeOf(value) !== Uint8Array.prototype) {
      validationError(path, "bytes must be an exact Uint8Array");
    }
    const backing = value.buffer;
    if (!(backing instanceof ArrayBuffer) || Object.getPrototypeOf(backing) !== ArrayBuffer.prototype) {
      validationError(path, "bytes must use an ordinary ArrayBuffer");
    }
    if (value.byteOffset !== 0 || value.byteLength !== backing.byteLength) {
      validationError(path, "bytes must cover their full backing buffer");
    }
    if (seen.has(value)) {
      validationError(path, "cyclic or repeated object references are unsupported");
    }
    if (seen.has(backing)) {
      validationError(path, "repeated byte storage is unsupported");
    }
    seen.add(value);
    seen.add(backing);
    return new Uint8Array(value);
  }
  if (typeof value !== "object") {
    validationError(path, `unsupported value type ${typeof value}`);
  }
  if (seen.has(value)) {
    validationError(path, "cyclic or repeated object references are unsupported");
  }
  seen.add(value);
  if (Array.isArray(value)) {
    const ownKeys = Reflect.ownKeys(value);
    for (const key of ownKeys) {
      if (key === "length") {
        continue;
      }
      if (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/.test(key)) {
        validationError(path, "arrays cannot have custom properties");
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === void 0 || !descriptor.enumerable || !("value" in descriptor)) {
        validationError(`${path}[${key}]`, "must be an enumerable data property");
      }
    }
    if (Object.keys(value).length !== value.length) {
      validationError(path, "sparse arrays are unsupported");
    }
    return value.map(
      (entry, index) => normalize(entry, `${path}[${index}]`, depth + 1, maxDepth, itemBudget, seen)
    );
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    validationError(path, "must be a plain object");
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") {
      validationError(path, "symbol keys are unsupported");
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === void 0 || !descriptor.enumerable || !("value" in descriptor)) {
      validationError(`${path}.${key}`, "must be an enumerable data property");
    }
  }
  const record = value;
  const result = {};
  const normalizedKeys = /* @__PURE__ */ new Set();
  for (const key of Object.keys(record)) {
    if (itemBudget.items >= itemBudget.maxItems) {
      validationError(path, `encoded item limit ${itemBudget.maxItems} exceeded`);
    }
    itemBudget.items += 1;
    assertUnicodeScalarString(key, `${path}.${key}`);
    const normalizedKey = key.normalize("NFC");
    if (normalizedKeys.has(normalizedKey)) {
      validationError(path, `duplicate normalized key ${JSON.stringify(normalizedKey)}`);
    }
    normalizedKeys.add(normalizedKey);
    Object.defineProperty(result, normalizedKey, {
      configurable: true,
      enumerable: true,
      value: normalize(
        record[key],
        `${path}.${key}`,
        depth + 1,
        maxDepth,
        itemBudget,
        seen
      ),
      writable: true
    });
  }
  return result;
}
function normalizeProtocolValue(value, options = {}) {
  const maxDepth = checkedLimit(options.maxDepth, DEFAULT_MAX_DEPTH, "maxDepth");
  const maxItems = checkedLimit(
    options.maxItems,
    Number.MAX_SAFE_INTEGER,
    "maxItems"
  );
  return normalize(
    value,
    "$",
    0,
    maxDepth,
    { items: 0, maxItems },
    /* @__PURE__ */ new WeakSet()
  );
}
var ByteWriter = class {
  #chunks = [];
  #maxBytes;
  #pendingBytes = [];
  #length = 0;
  constructor(maxBytes) {
    this.#maxBytes = maxBytes;
  }
  push(byte) {
    if (this.#length >= this.#maxBytes) {
      validationError("$", `encoded size exceeds ${this.#maxBytes} bytes`);
    }
    this.#pendingBytes.push(byte);
    this.#length += 1;
  }
  pushBytes(bytes) {
    if (this.#length + bytes.byteLength > this.#maxBytes) {
      validationError("$", `encoded size exceeds ${this.#maxBytes} bytes`);
    }
    if (bytes.byteLength === 0) {
      return;
    }
    this.#flushPendingBytes();
    this.#chunks.push(bytes);
    this.#length += bytes.byteLength;
  }
  finish() {
    this.#flushPendingBytes();
    const result = new Uint8Array(this.#length);
    let offset = 0;
    for (const chunk of this.#chunks) {
      result.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return result;
  }
  #flushPendingBytes() {
    if (this.#pendingBytes.length === 0) {
      return;
    }
    this.#chunks.push(Uint8Array.from(this.#pendingBytes));
    this.#pendingBytes.length = 0;
  }
};
function writeArgument(writer, major, argument) {
  const prefix = major << 5;
  if (argument < 24n) {
    writer.push(prefix | Number(argument));
    return;
  }
  if (argument <= 0xffn) {
    writer.push(prefix | 24);
    writer.push(Number(argument));
    return;
  }
  if (argument <= 0xffffn) {
    writer.push(prefix | 25);
    writer.push(Number(argument >> 8n));
    writer.push(Number(argument & 0xffn));
    return;
  }
  if (argument <= 0xffffffffn) {
    writer.push(prefix | 26);
    for (let shift = 24n; shift >= 0n; shift -= 8n) {
      writer.push(Number(argument >> shift & 0xffn));
    }
    return;
  }
  writer.push(prefix | 27);
  for (let shift = 56n; shift >= 0n; shift -= 8n) {
    writer.push(Number(argument >> shift & 0xffn));
  }
}
function compareBytes(left, right) {
  const length = Math.min(left.byteLength, right.byteLength);
  for (let index = 0; index < length; index += 1) {
    const leftByte = left[index];
    const rightByte = right[index];
    if (leftByte === void 0 || rightByte === void 0) {
      validationError("$", "internal byte comparison exceeded its input");
    }
    const difference = leftByte - rightByte;
    if (difference !== 0) {
      return difference;
    }
  }
  return left.byteLength - right.byteLength;
}
function writeValue(writer, value) {
  if (value === null) {
    writer.push(246);
    return;
  }
  if (typeof value === "boolean") {
    writer.push(value ? 245 : 244);
    return;
  }
  if (typeof value === "number") {
    if (value >= 0) {
      writeArgument(writer, 0, BigInt(value));
    } else {
      writeArgument(writer, 1, BigInt(-1 - value));
    }
    return;
  }
  if (typeof value === "string") {
    const bytes = textEncoder.encode(value);
    writeArgument(writer, 3, BigInt(bytes.byteLength));
    writer.pushBytes(bytes);
    return;
  }
  if (value instanceof Uint8Array) {
    writeArgument(writer, 2, BigInt(value.byteLength));
    writer.pushBytes(value);
    return;
  }
  if (Array.isArray(value)) {
    writeArgument(writer, 4, BigInt(value.length));
    for (const entry of value) {
      writeValue(writer, entry);
    }
    return;
  }
  const entries = Object.keys(value).map((key) => {
    const keyBytes = textEncoder.encode(key);
    const keyWriter = new ByteWriter(Number.MAX_SAFE_INTEGER);
    writeArgument(keyWriter, 3, BigInt(keyBytes.byteLength));
    keyWriter.pushBytes(keyBytes);
    return { encodedKey: keyWriter.finish(), key };
  });
  entries.sort((left, right) => {
    const lengthDifference = left.encodedKey.byteLength - right.encodedKey.byteLength;
    return lengthDifference === 0 ? compareBytes(left.encodedKey, right.encodedKey) : lengthDifference;
  });
  writeArgument(writer, 5, BigInt(entries.length));
  for (const entry of entries) {
    writer.pushBytes(entry.encodedKey);
    const item = value[entry.key];
    if (item === void 0) {
      validationError(`$.${entry.key}`, "unsupported undefined value");
    }
    writeValue(writer, item);
  }
}
function encodeCanonicalCbor(value, options = {}) {
  const maxDepth = checkedLimit(options.maxDepth, DEFAULT_MAX_DEPTH, "maxDepth");
  const maxBytes = checkedLimit(options.maxBytes, Number.MAX_SAFE_INTEGER, "maxBytes");
  const maxItems = checkedLimit(
    options.maxItems,
    Number.MAX_SAFE_INTEGER,
    "maxItems"
  );
  const normalized = normalizeProtocolValue(value, { maxDepth, maxItems });
  const writer = new ByteWriter(maxBytes);
  writeValue(writer, normalized);
  return writer.finish();
}
function encodeHex(bytes) {
  let result = "";
  for (const byte of bytes) {
    result += byte.toString(16).padStart(2, "0");
  }
  return result;
}

// packages/protocol-types/src/digest.ts
var DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
function isDigest(value) {
  return typeof value === "string" && DIGEST_PATTERN.test(value);
}
function parseDigest(value, path = "$digest") {
  if (!isDigest(value)) {
    validationError(path, "must be sha256: followed by 64 lowercase hexadecimal characters");
  }
  return value;
}
async function digestBytes(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    validationError("$bytes", "must be a Uint8Array");
  }
  const input = Uint8Array.from(bytes);
  const result = await globalThis.crypto.subtle.digest("SHA-256", input);
  return `sha256:${encodeHex(new Uint8Array(result))}`;
}
async function digestStructuredValue(domain, schemaVersion, normalizedPayload) {
  if (typeof domain !== "string" || domain.length === 0) {
    validationError("$domain", "must be a non-empty string");
  }
  assertUnicodeScalarString(domain, "$domain");
  if (domain !== domain.normalize("NFC")) {
    validationError("$domain", "must be NFC-normalized");
  }
  if (!Number.isSafeInteger(schemaVersion) || schemaVersion < 1) {
    validationError("$schemaVersion", "must be a positive safe integer");
  }
  return digestBytes(
    encodeCanonicalCbor(
      ["circulusd.hash", 1, domain, schemaVersion, normalizedPayload],
      { maxDepth: 72 }
    )
  );
}

// packages/protocol-types/src/types.ts
var EFFECT_SERVICES = [
  "model",
  "workspace",
  "executor",
  "mcp",
  "artifact",
  "external-tool"
];
var REPLAY_POLICIES = ["safe", "idempotency-key", "never", "confirm"];

// packages/protocol-types/src/validation.ts
var MAX_IDENTIFIER_BYTES = 256;
var MAX_OPERATION_BYTES = 256;
var MAX_CHECKPOINT_PAYLOAD_BYTES = 4 * 1048576;
var textEncoder2 = new TextEncoder();
var hasOwn = (record, key) => Object.prototype.hasOwnProperty.call(record, key);
function plainRecord(value, path) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    validationError(path, "must be a plain object");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    validationError(path, "must be a plain object");
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") {
      validationError(path, "symbol keys are unsupported");
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === void 0 || !descriptor.enumerable || !("value" in descriptor)) {
      validationError(`${path}.${key}`, "must be an enumerable data property");
    }
  }
  return value;
}
function exactRecord(value, required, optional, path) {
  const record = plainRecord(value, path);
  const allowed = /* @__PURE__ */ new Set([...required, ...optional]);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      validationError(`${path}.${key}`, `unknown field ${JSON.stringify(key)}`);
    }
  }
  for (const key of required) {
    if (!hasOwn(record, key)) {
      validationError(`${path}.${key}`, `missing required field ${JSON.stringify(key)}`);
    }
  }
  return record;
}
function nfcString(value, path, options) {
  if (typeof value !== "string") {
    validationError(path, "must be a string");
  }
  assertUnicodeScalarString(value, path);
  if (value !== value.normalize("NFC")) {
    validationError(path, "must be NFC-normalized");
  }
  if (options.allowEmpty !== true && value.length === 0) {
    validationError(path, "must not be empty");
  }
  if (textEncoder2.encode(value).byteLength > options.maxBytes) {
    validationError(path, `must not exceed ${options.maxBytes} UTF-8 bytes`);
  }
  if (/\p{Cc}/u.test(value)) {
    validationError(path, "must not contain control characters");
  }
  return value;
}
function identifier(value, path) {
  return nfcString(value, path, { maxBytes: MAX_IDENTIFIER_BYTES });
}
function operation(value, path) {
  return nfcString(value, path, { maxBytes: MAX_OPERATION_BYTES });
}
function safeInteger(value, path, minimum) {
  if (!Number.isSafeInteger(value) || typeof value !== "number" || value < minimum) {
    validationError(path, `must be a safe integer greater than or equal to ${minimum}`);
  }
  return value;
}
function exactLiteral(value, expected, path) {
  if (value !== expected) {
    validationError(path, `must be ${JSON.stringify(expected)}`);
  }
  return expected;
}
function oneOf(value, allowed, path) {
  if (typeof value !== "string" || !allowed.includes(value)) {
    validationError(path, `must be one of ${allowed.join(", ")}`);
  }
  return value;
}
var CHECKPOINT_FIELDS = [
  "kind",
  "engineKind",
  "adapterAbiVersion",
  "checkpointSchemaVersion",
  "runtimeRevisionDigest",
  "sessionId",
  "turnId",
  "checkpointSequence",
  "predecessorDigest",
  "payloadEncoding",
  "payloadBytes",
  "payloadDigest"
];
function parseAgentCheckpoint(value) {
  const record = exactRecord(value, CHECKPOINT_FIELDS, [], "$checkpoint");
  if (!(record.payloadBytes instanceof Uint8Array) || Object.getPrototypeOf(record.payloadBytes) !== Uint8Array.prototype) {
    validationError("$checkpoint.payloadBytes", "must be an exact Uint8Array");
  }
  if (record.payloadBytes.byteLength > MAX_CHECKPOINT_PAYLOAD_BYTES) {
    validationError(
      "$checkpoint.payloadBytes",
      `must not exceed ${MAX_CHECKPOINT_PAYLOAD_BYTES} bytes`
    );
  }
  const common = {
    engineKind: oneOf(
      record.engineKind,
      ["low-level", "agent-harness"],
      "$checkpoint.engineKind"
    ),
    adapterAbiVersion: safeInteger(record.adapterAbiVersion, "$checkpoint.adapterAbiVersion", 1),
    checkpointSchemaVersion: safeInteger(
      record.checkpointSchemaVersion,
      "$checkpoint.checkpointSchemaVersion",
      1
    ),
    runtimeRevisionDigest: parseDigest(
      record.runtimeRevisionDigest,
      "$checkpoint.runtimeRevisionDigest"
    ),
    sessionId: identifier(record.sessionId, "$checkpoint.sessionId"),
    turnId: identifier(record.turnId, "$checkpoint.turnId"),
    payloadEncoding: oneOf(
      record.payloadEncoding,
      ["protobuf", "canonical-cbor", "opaque-v1"],
      "$checkpoint.payloadEncoding"
    ),
    payloadBytes: new Uint8Array(record.payloadBytes),
    payloadDigest: parseDigest(record.payloadDigest, "$checkpoint.payloadDigest")
  };
  if (record.kind === "genesis") {
    exactLiteral(record.checkpointSequence, 0, "$checkpoint.checkpointSequence");
    if (record.predecessorDigest !== null) {
      validationError("$checkpoint.predecessorDigest", "must be null for a genesis checkpoint");
    }
    return {
      kind: "genesis",
      ...common,
      checkpointSequence: 0,
      predecessorDigest: null
    };
  }
  if (record.kind === "engine") {
    return {
      kind: "engine",
      ...common,
      checkpointSequence: safeInteger(
        record.checkpointSequence,
        "$checkpoint.checkpointSequence",
        1
      ),
      predecessorDigest: parseDigest(
        record.predecessorDigest,
        "$checkpoint.predecessorDigest"
      )
    };
  }
  validationError("$checkpoint.kind", "must be genesis or engine");
}
async function assertCheckpointPayloadDigest(checkpoint) {
  const actual = await digestBytes(checkpoint.payloadBytes);
  if (actual !== checkpoint.payloadDigest) {
    validationError("$checkpoint.payloadDigest", "does not match payloadBytes");
  }
}
async function validateAgentCheckpoint(value) {
  const checkpoint = parseAgentCheckpoint(value);
  await assertCheckpointPayloadDigest(checkpoint);
  return checkpoint;
}
var EFFECT_REQUIRED_FIELDS = [
  "tenantId",
  "userId",
  "sessionId",
  "turnId",
  "effectId",
  "invocationId",
  "requestDigest",
  "service",
  "operation",
  "replayPolicy"
];
var EFFECT_OPTIONAL_FIELDS = ["parentOperationId", "ordinal"];
function parseEffectService(value, path) {
  return oneOf(value, EFFECT_SERVICES, path);
}
function parseReplayPolicy(value, path) {
  return oneOf(value, REPLAY_POLICIES, path);
}
function compositeFields(record, path) {
  const hasParent = hasOwn(record, "parentOperationId");
  const hasOrdinal = hasOwn(record, "ordinal");
  if (hasParent !== hasOrdinal) {
    validationError(path, "parentOperationId and ordinal must appear together");
  }
  if (!hasParent) {
    return {};
  }
  return {
    parentOperationId: identifier(record.parentOperationId, `${path}.parentOperationId`),
    ordinal: safeInteger(record.ordinal, `${path}.ordinal`, 0)
  };
}
var PERMIT_FIELDS = [
  ...EFFECT_REQUIRED_FIELDS,
  "dispatchAttempt",
  "turnLeaseGeneration",
  "placementGeneration",
  "sandboxGeneration",
  "authorizationGeneration",
  "deadline"
];
function parseEngineStepResult(value) {
  const preliminary = plainRecord(value, "$engineStepResult");
  switch (preliminary.kind) {
    case "checkpoint": {
      const record = exactRecord(
        preliminary,
        ["kind", "checkpoint"],
        [],
        "$engineStepResult"
      );
      return { kind: "checkpoint", checkpoint: parseAgentCheckpoint(record.checkpoint) };
    }
    case "effect_request": {
      const record = exactRecord(
        preliminary,
        ["kind", "checkpoint", "request"],
        [],
        "$engineStepResult"
      );
      const request = exactRecord(
        record.request,
        ["service", "operation", "replayPolicy", "requestDigest", "payload"],
        EFFECT_OPTIONAL_FIELDS,
        "$engineStepResult.request"
      );
      return {
        kind: "effect_request",
        checkpoint: parseAgentCheckpoint(record.checkpoint),
        request: {
          service: parseEffectService(
            request.service,
            "$engineStepResult.request.service"
          ),
          operation: operation(request.operation, "$engineStepResult.request.operation"),
          replayPolicy: parseReplayPolicy(
            request.replayPolicy,
            "$engineStepResult.request.replayPolicy"
          ),
          requestDigest: parseDigest(
            request.requestDigest,
            "$engineStepResult.request.requestDigest"
          ),
          payload: normalizeProtocolValue(request.payload),
          ...compositeFields(request, "$engineStepResult.request")
        }
      };
    }
    case "turn_complete": {
      const record = exactRecord(
        preliminary,
        ["kind", "checkpoint", "result"],
        [],
        "$engineStepResult"
      );
      return {
        kind: "turn_complete",
        checkpoint: parseAgentCheckpoint(record.checkpoint),
        result: normalizeProtocolValue(record.result)
      };
    }
    case "turn_error": {
      const record = exactRecord(
        preliminary,
        ["kind", "checkpoint", "error"],
        [],
        "$engineStepResult"
      );
      const error = exactRecord(
        record.error,
        ["code", "message", "retryable"],
        ["details"],
        "$engineStepResult.error"
      );
      if (typeof error.retryable !== "boolean") {
        validationError("$engineStepResult.error.retryable", "must be a boolean");
      }
      const parsedError = {
        code: operation(error.code, "$engineStepResult.error.code"),
        message: nfcString(error.message, "$engineStepResult.error.message", {
          maxBytes: 4096
        }),
        retryable: error.retryable
      };
      return {
        kind: "turn_error",
        checkpoint: parseAgentCheckpoint(record.checkpoint),
        error: hasOwn(error, "details") ? { ...parsedError, details: normalizeProtocolValue(error.details) } : parsedError
      };
    }
    default:
      validationError(
        "$engineStepResult.kind",
        "must be checkpoint, effect_request, turn_complete, or turn_error"
      );
  }
}
async function validateEngineStepResult(value) {
  const result = parseEngineStepResult(value);
  await assertCheckpointPayloadDigest(result.checkpoint);
  return result;
}

// workers/pi-runtime/src/codec.ts
var textDecoder2 = new TextDecoder("utf-8", { fatal: true });
var CanonicalCborReader = class {
  #bytes;
  #maxDepth;
  #offset = 0;
  constructor(bytes, maxDepth) {
    this.#bytes = bytes;
    this.#maxDepth = maxDepth;
  }
  read(depth = 0) {
    if (depth > this.#maxDepth || this.#offset >= this.#bytes.byteLength) {
      throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR is truncated or too deep");
    }
    const initial = this.#bytes[this.#offset];
    if (initial === void 0) {
      throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR is truncated");
    }
    this.#offset += 1;
    const major = initial >> 5;
    const additional = initial & 31;
    let argument;
    if (additional < 24) {
      argument = BigInt(additional);
    } else {
      const byteCount = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
      if (byteCount === 0 || this.#offset + byteCount > this.#bytes.byteLength) {
        throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR has an invalid argument");
      }
      argument = 0n;
      for (let index = 0; index < byteCount; index += 1) {
        const byte = this.#bytes[this.#offset];
        if (byte === void 0) {
          throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR is truncated");
        }
        this.#offset += 1;
        argument = argument << 8n | BigInt(byte);
      }
      const minimum = byteCount === 1 ? 24n : byteCount === 2 ? 256n : byteCount === 4 ? 65536n : 4294967296n;
      if (argument < minimum) {
        throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR is not minimally encoded");
      }
    }
    if (argument > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR integer exceeds safe range");
    }
    const length = Number(argument);
    if (major === 0) return length;
    if (major === 1) return -1 - length;
    if (major === 2 || major === 3) {
      if (this.#offset + length > this.#bytes.byteLength) {
        throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR byte string is truncated");
      }
      const value = this.#bytes.slice(this.#offset, this.#offset + length);
      this.#offset += length;
      if (major === 2) return value;
      try {
        const text = textDecoder2.decode(value);
        if (text !== text.normalize("NFC")) {
          throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR text is not NFC");
        }
        return text;
      } catch (error) {
        if (error instanceof PiRuntimeError) throw error;
        throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR text is invalid UTF-8", {
          cause: error
        });
      }
    }
    if (major === 4) {
      const values = [];
      for (let index = 0; index < length; index += 1) values.push(this.read(depth + 1));
      return values;
    }
    if (major === 5) {
      const result = {};
      for (let index = 0; index < length; index += 1) {
        const key = this.read(depth + 1);
        if (typeof key !== "string" || Object.prototype.hasOwnProperty.call(result, key)) {
          throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR map key is invalid");
        }
        Object.defineProperty(result, key, {
          configurable: true,
          enumerable: true,
          value: this.read(depth + 1),
          writable: true
        });
      }
      return result;
    }
    if (major === 7 && additional === 20) return false;
    if (major === 7 && additional === 21) return true;
    if (major === 7 && additional === 22) return null;
    throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint CBOR contains an unsupported type");
  }
  atEnd() {
    return this.#offset === this.#bytes.byteLength;
  }
};
function decodeCanonicalCheckpointPayload(bytes, maxBytes) {
  if (!(bytes instanceof Uint8Array) || Object.getPrototypeOf(bytes) !== Uint8Array.prototype || bytes.byteLength > maxBytes) {
    throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint payload exceeds its byte budget");
  }
  const copy = new Uint8Array(bytes);
  const reader = new CanonicalCborReader(copy, 64);
  const decoded = reader.read();
  if (!reader.atEnd()) {
    throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint payload has trailing CBOR bytes");
  }
  let canonical;
  try {
    canonical = encodeCanonicalCbor(normalizeProtocolValue(decoded), { maxBytes });
  } catch (error) {
    if (error instanceof ProtocolValidationError) {
      throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint payload is invalid", {
        cause: error
      });
    }
    throw error;
  }
  if (canonical.byteLength !== copy.byteLength || canonical.some((byte, index) => byte !== copy[index])) {
    throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint payload CBOR is not canonical");
  }
  return decoded;
}

// workers/pi-runtime/src/types.ts
var EFFECT_SERVICE_VALUES = [
  "model",
  "workspace",
  "executor",
  "mcp",
  "artifact",
  "external-tool"
];
var REPLAY_POLICY_VALUES = [
  "safe",
  "idempotency-key",
  "never",
  "confirm"
];

// workers/pi-runtime/src/validation.ts
var textEncoder3 = new TextEncoder();
function validationFailure(code, message, cause) {
  if (code === "CORE_OUTPUT_INVALID" || code === "CORE_EXECUTION_FAILED" || code === "EXTENSION_OUTPUT_INVALID" || code === "EXTENSION_HOOK_FAILED" || code === "EVENT_BUDGET_EXCEEDED" || code === "STEP_TIMEOUT" || code === "TURN_ABORTED") {
    throw new BoundaryFault(code, message, cause === void 0 ? void 0 : { cause });
  }
  throw new PiRuntimeError(code, message, cause === void 0 ? void 0 : { cause });
}
function exactRecord2(value, required, optional, path, code) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    validationFailure(code, `${path} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    validationFailure(code, `${path} must be a plain object`);
  }
  const allowed = /* @__PURE__ */ new Set([...required, ...optional]);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || !allowed.has(key)) {
      validationFailure(code, `${path} has unknown field ${String(key)}`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === void 0 || !descriptor.enumerable || !("value" in descriptor)) {
      validationFailure(code, `${path}.${key} must be an enumerable data property`);
    }
  }
  const record = value;
  for (const field of required) {
    if (!Object.prototype.hasOwnProperty.call(record, field)) {
      validationFailure(code, `${path} is missing field ${field}`);
    }
  }
  return record;
}
function boundedIdentifier(value, path, code) {
  if (typeof value !== "string" || value.length === 0 || value !== value.normalize("NFC") || textEncoder3.encode(value).byteLength > 256 || /\p{Cc}/u.test(value)) {
    validationFailure(code, `${path} must be a non-empty bounded NFC identifier`);
  }
  return value;
}
function boundedSafeInteger(value, minimum, path, code) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
    validationFailure(code, `${path} must be a safe integer >= ${minimum}`);
  }
  return value;
}
function boundedProtocolValue(value, maxBytes, path, code) {
  try {
    const normalized = normalizeProtocolValue(value);
    encodeCanonicalCbor(normalized, { maxBytes });
    return normalized;
  } catch (error) {
    if (error instanceof ProtocolValidationError) {
      validationFailure(code, `${path} is not a bounded protocol value: ${error.message}`, error);
    }
    throw error;
  }
}
function parseEffectRequestDraft(value, maxBytes, path, code) {
  const record = exactRecord2(
    value,
    ["service", "operation", "replayPolicy", "payload"],
    ["parentOperationId", "ordinal"],
    path,
    code
  );
  if (typeof record.service !== "string" || !EFFECT_SERVICE_VALUES.includes(record.service)) {
    validationFailure(code, `${path}.service is unsupported`);
  }
  if (typeof record.replayPolicy !== "string" || !REPLAY_POLICY_VALUES.includes(record.replayPolicy)) {
    validationFailure(code, `${path}.replayPolicy is unsupported`);
  }
  const hasParent = Object.prototype.hasOwnProperty.call(record, "parentOperationId");
  const hasOrdinal = Object.prototype.hasOwnProperty.call(record, "ordinal");
  if (hasParent !== hasOrdinal) {
    validationFailure(code, `${path} must provide parentOperationId and ordinal together`);
  }
  const draft = {
    service: record.service,
    operation: boundedIdentifier(record.operation, `${path}.operation`, code),
    replayPolicy: record.replayPolicy,
    payload: boundedProtocolValue(record.payload, maxBytes, `${path}.payload`, code),
    ...hasParent ? {
      parentOperationId: boundedIdentifier(
        record.parentOperationId,
        `${path}.parentOperationId`,
        code
      ),
      ordinal: boundedSafeInteger(record.ordinal, 0, `${path}.ordinal`, code)
    } : {}
  };
  boundedProtocolValue(draft, maxBytes, path, code);
  return draft;
}
function parseEffectIntent(value, maxBytes, path, code) {
  const record = exactRecord2(
    value,
    ["service", "operation", "replayPolicy", "requestDigest", "payload"],
    ["parentOperationId", "ordinal"],
    path,
    code
  );
  const draft = parseEffectRequestDraft(
    {
      service: record.service,
      operation: record.operation,
      replayPolicy: record.replayPolicy,
      payload: record.payload,
      ...Object.prototype.hasOwnProperty.call(record, "parentOperationId") ? { parentOperationId: record.parentOperationId, ordinal: record.ordinal } : {}
    },
    maxBytes,
    path,
    code
  );
  return {
    ...draft,
    requestDigest: parseDigestForBoundary(record.requestDigest, `${path}.requestDigest`, code)
  };
}
function parseSettlementOutcome(value, maxBytes, path, code) {
  const preliminary = exactRecord2(value, ["kind"], ["result", "code", "message", "retryable", "reason"], path, code);
  switch (preliminary.kind) {
    case "success": {
      const record = exactRecord2(value, ["kind", "result"], [], path, code);
      return {
        kind: "success",
        result: boundedProtocolValue(record.result, maxBytes, `${path}.result`, code)
      };
    }
    case "error": {
      const record = exactRecord2(
        value,
        ["kind", "code", "message", "retryable"],
        [],
        path,
        code
      );
      if (typeof record.retryable !== "boolean") {
        validationFailure(code, `${path}.retryable must be a boolean`);
      }
      return {
        kind: "error",
        code: boundedIdentifier(record.code, `${path}.code`, code),
        message: boundedIdentifier(record.message, `${path}.message`, code),
        retryable: record.retryable
      };
    }
    case "interrupted_unknown":
    case "abandoned": {
      const record = exactRecord2(value, ["kind", "reason"], [], path, code);
      return {
        kind: preliminary.kind,
        reason: boundedIdentifier(record.reason, `${path}.reason`, code)
      };
    }
    default:
      validationFailure(code, `${path}.kind is unsupported`);
  }
}
function parseEngineSettlement(value, maxBytes, path) {
  const record = exactRecord2(
    value,
    ["requestDigest", "outcome"],
    [],
    path,
    "INVALID_CONTEXT"
  );
  let requestDigest;
  try {
    requestDigest = parseDigest(record.requestDigest, `${path}.requestDigest`);
  } catch (error) {
    validationFailure("INVALID_CONTEXT", `${path}.requestDigest is invalid`, error);
  }
  return {
    requestDigest,
    outcome: parseSettlementOutcome(
      record.outcome,
      maxBytes,
      `${path}.outcome`,
      "INVALID_CONTEXT"
    )
  };
}
function frozenProtocolClone(value) {
  const cloned = structuredClone(value);
  const pending = [];
  if (cloned !== null && typeof cloned === "object") pending.push(cloned);
  const visited = /* @__PURE__ */ new WeakSet();
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === void 0 || visited.has(current)) continue;
    visited.add(current);
    if (current instanceof Uint8Array) continue;
    for (const entry of Object.values(current)) {
      if (entry !== null && typeof entry === "object") pending.push(entry);
    }
    Object.freeze(current);
  }
  return cloned;
}
function frozenSignalContext(value) {
  const cloned = {};
  for (const [key, entry] of Object.entries(value)) {
    Object.defineProperty(cloned, key, {
      enumerable: true,
      value: key === "signal" ? entry : frozenProtocolClone(entry)
    });
  }
  return Object.freeze(cloned);
}
function parseDigestForBoundary(value, path, code) {
  try {
    return parseDigest(value, path);
  } catch (error) {
    validationFailure(code, `${path} is invalid`, error);
  }
}

// workers/pi-runtime/src/lifecycle.ts
var PATCHABLE_HOOKS = [
  "beforeModelRequest",
  "afterModelResponse",
  "beforeToolCall",
  "afterToolCall"
];
var REQUEST_PATCH_FIELDS = ["operation", "replayPolicy", "payload"];
var RESULT_PATCH_FIELDS = ["result"];
var HookDispatcher = class {
  #identity;
  #maxOutputBytes;
  #registrations = [];
  #active = [];
  #sealed = false;
  #initializing = false;
  #initialized = false;
  constructor(identity, maxOutputBytes) {
    this.#identity = identity;
    this.#maxOutputBytes = maxOutputBytes;
  }
  register(registration) {
    if (this.#sealed || this.#initializing || this.#initialized) {
      throw new PiRuntimeError(
        "HOOK_REGISTRY_FROZEN",
        "extension hook registry is frozen once initialization starts"
      );
    }
    const registrationRecord = exactRecord2(
      registration,
      ["manifest", "create"],
      [],
      "extensionRegistration",
      "INVALID_CONFIGURATION"
    );
    if (typeof registrationRecord.create !== "function") {
      throw new PiRuntimeError("INVALID_CONFIGURATION", "extension create must be a factory");
    }
    const manifestRecord = exactRecord2(
      registrationRecord.manifest,
      ["id", "priority", "tools", "patchableFields"],
      ["configuration"],
      "extensionManifest",
      "INVALID_CONFIGURATION"
    );
    boundedProtocolValue(
      registrationRecord.manifest,
      this.#maxOutputBytes,
      "extensionManifest",
      "INVALID_CONFIGURATION"
    );
    const id = boundedIdentifier(
      manifestRecord.id,
      "extensionManifest.id",
      "INVALID_CONFIGURATION"
    );
    if (!/^[a-z0-9][a-z0-9._/-]*$/.test(id)) {
      throw new PiRuntimeError(
        "INVALID_CONFIGURATION",
        "extensionManifest.id must use the canonical lowercase extension-id syntax"
      );
    }
    if (typeof manifestRecord.priority !== "number" || !Number.isSafeInteger(manifestRecord.priority)) {
      throw new PiRuntimeError(
        "INVALID_CONFIGURATION",
        "extensionManifest.priority must be a safe integer"
      );
    }
    if (!Array.isArray(manifestRecord.tools)) {
      throw new PiRuntimeError("INVALID_CONFIGURATION", "extensionManifest.tools must be an array");
    }
    const tools = manifestRecord.tools.map(
      (tool, index) => boundedIdentifier(tool, `extensionManifest.tools[${index}]`, "INVALID_CONFIGURATION")
    );
    if (new Set(tools).size !== tools.length) {
      throw new PiRuntimeError(
        "TOOL_NAME_COLLISION",
        `extension ${id} declares the same tool more than once`
      );
    }
    const patchableRecord = exactRecord2(
      manifestRecord.patchableFields,
      [],
      PATCHABLE_HOOKS,
      "extensionManifest.patchableFields",
      "INVALID_CONFIGURATION"
    );
    const patchableFields = {};
    for (const hook of PATCHABLE_HOOKS) {
      if (!Object.prototype.hasOwnProperty.call(patchableRecord, hook)) continue;
      const fields = patchableRecord[hook];
      if (!Array.isArray(fields)) {
        throw new PiRuntimeError(
          "INVALID_CONFIGURATION",
          `extensionManifest.patchableFields.${hook} must be an array`
        );
      }
      const allowed = hook === "beforeModelRequest" || hook === "beforeToolCall" ? REQUEST_PATCH_FIELDS : RESULT_PATCH_FIELDS;
      const validated = fields.map((field) => {
        if (typeof field !== "string" || !allowed.includes(field)) {
          throw new PiRuntimeError(
            "INVALID_CONFIGURATION",
            `${String(field)} is not patchable by ${hook}`
          );
        }
        return field;
      });
      if (new Set(validated).size !== validated.length) {
        throw new PiRuntimeError(
          "INVALID_CONFIGURATION",
          `extensionManifest.patchableFields.${hook} contains duplicates`
        );
      }
      Object.defineProperty(patchableFields, hook, {
        enumerable: true,
        value: Object.freeze([...validated])
      });
    }
    const configuration = Object.prototype.hasOwnProperty.call(manifestRecord, "configuration") ? boundedProtocolValue(
      manifestRecord.configuration,
      this.#maxOutputBytes,
      "extensionManifest.configuration",
      "INVALID_CONFIGURATION"
    ) : null;
    const manifest = Object.freeze({
      id,
      priority: manifestRecord.priority,
      tools: Object.freeze(tools),
      configuration: frozenProtocolClone(configuration),
      patchableFields: Object.freeze(patchableFields)
    });
    this.#registrations.push({
      manifest,
      create: registrationRecord.create,
      registrationIndex: this.#registrations.length
    });
  }
  seal() {
    this.#sealed = true;
  }
  async initialize() {
    this.seal();
    if (this.#initialized) return;
    if (this.#initializing) {
      throw new PiRuntimeError(
        "INITIALIZATION_FAILED",
        "extension initialization was invoked concurrently"
      );
    }
    this.#initializing = true;
    try {
      const ordered = [...this.#registrations].sort(
        (left, right) => left.manifest.priority !== right.manifest.priority ? left.manifest.priority - right.manifest.priority : left.manifest.id !== right.manifest.id ? left.manifest.id < right.manifest.id ? -1 : 1 : left.registrationIndex - right.registrationIndex
      );
      const toolOwners = /* @__PURE__ */ new Map();
      for (const registration of ordered) {
        for (const tool of registration.manifest.tools) {
          const existing = toolOwners.get(tool);
          if (existing !== void 0) {
            throw new PiRuntimeError(
              "TOOL_NAME_COLLISION",
              `tool ${tool} is declared by both ${existing} and ${registration.manifest.id}`
            );
          }
          toolOwners.set(tool, registration.manifest.id);
        }
      }
      const active = ordered.map((registration) => ({
        manifest: registration.manifest,
        instance: registration.create(),
        registrationIndex: registration.registrationIndex
      }));
      const controller = new AbortController();
      for (const extension of active) {
        const result = await extension.instance.initialize?.(
          frozenProtocolClone({
            sessionId: this.#identity.sessionId,
            runtimeRevisionDigest: this.#identity.runtimeRevisionDigest,
            extensionId: extension.manifest.id,
            configuration: extension.manifest.configuration ?? null
          })
        );
        if (result !== void 0) {
          throw new PiRuntimeError(
            "INITIALIZATION_FAILED",
            `extension ${extension.manifest.id} initialize returned data from a void hook`
          );
        }
      }
      for (const extension of active) {
        const result = await extension.instance.beforeAgentStart?.(
          frozenSignalContext({
            sessionId: this.#identity.sessionId,
            runtimeRevisionDigest: this.#identity.runtimeRevisionDigest,
            signal: controller.signal
          })
        );
        if (result !== void 0) {
          throw new PiRuntimeError(
            "INITIALIZATION_FAILED",
            `extension ${extension.manifest.id} beforeAgentStart returned data from a void hook`
          );
        }
      }
      this.#active = Object.freeze(active);
      this.#initialized = true;
    } catch (error) {
      if (error instanceof PiRuntimeError) throw error;
      throw new PiRuntimeError("INITIALIZATION_FAILED", "extension initialization failed", {
        cause: error
      });
    } finally {
      this.#initializing = false;
    }
  }
  async beforeTurn(turnId, input, signal) {
    await this.#runVoidHook("beforeTurn", { sessionId: this.#identity.sessionId, turnId, input, signal });
  }
  async beforeModelRequest(turnId, request, signal) {
    return this.#patchRequest("beforeModelRequest", turnId, request, signal);
  }
  async afterModelResponse(turnId, request, result, signal) {
    return this.#patchResult("afterModelResponse", turnId, request, result, signal);
  }
  async beforeToolCall(turnId, request, signal) {
    return this.#patchRequest("beforeToolCall", turnId, request, signal);
  }
  async afterToolCall(turnId, request, result, signal) {
    return this.#patchResult("afterToolCall", turnId, request, result, signal);
  }
  async afterTurn(turnId, result, signal) {
    await this.#runVoidHook("afterTurn", { sessionId: this.#identity.sessionId, turnId, result, signal });
  }
  async #runVoidHook(hook, event) {
    for (const extension of this.#active) {
      const callback = extension.instance[hook];
      if (callback === void 0) continue;
      try {
        const result = await callback.call(extension.instance, frozenSignalContext(event));
        if (result !== void 0) {
          throw new BoundaryFault(
            "EXTENSION_OUTPUT_INVALID",
            `extension ${extension.manifest.id} returned data from void hook ${hook}`
          );
        }
      } catch (error) {
        if (error instanceof BoundaryFault) throw error;
        throw new BoundaryFault(
          "EXTENSION_HOOK_FAILED",
          `extension ${extension.manifest.id} failed in ${hook}`,
          { cause: error }
        );
      }
    }
  }
  async #patchRequest(hook, turnId, initial, signal) {
    let request = frozenProtocolClone(initial);
    for (const extension of this.#active) {
      const callback = extension.instance[hook];
      if (callback === void 0) continue;
      let output;
      try {
        output = await callback.call(
          extension.instance,
          frozenSignalContext({
            sessionId: this.#identity.sessionId,
            turnId,
            request,
            signal
          })
        );
      } catch (error) {
        throw new BoundaryFault(
          "EXTENSION_HOOK_FAILED",
          `extension ${extension.manifest.id} failed in ${hook}`,
          { cause: error }
        );
      }
      if (output === void 0) continue;
      const patch = exactRecord2(
        output,
        [],
        REQUEST_PATCH_FIELDS,
        `${extension.manifest.id}.${hook}.patch`,
        "EXTENSION_OUTPUT_INVALID"
      );
      boundedProtocolValue(
        patch,
        this.#maxOutputBytes,
        `${extension.manifest.id}.${hook}.patch`,
        "EXTENSION_OUTPUT_INVALID"
      );
      const allowed = new Set(extension.manifest.patchableFields[hook] ?? []);
      for (const field of Object.keys(patch)) {
        if (!allowed.has(field)) {
          throw new BoundaryFault(
            "EXTENSION_OUTPUT_INVALID",
            `extension ${extension.manifest.id} cannot patch ${field} in ${hook}`
          );
        }
      }
      request = frozenProtocolClone({
        ...request,
        ...Object.prototype.hasOwnProperty.call(patch, "operation") ? {
          operation: boundedIdentifier(
            patch.operation,
            `${extension.manifest.id}.${hook}.patch.operation`,
            "EXTENSION_OUTPUT_INVALID"
          )
        } : {},
        ...Object.prototype.hasOwnProperty.call(patch, "replayPolicy") ? { replayPolicy: patch.replayPolicy } : {},
        ...Object.prototype.hasOwnProperty.call(patch, "payload") ? {
          payload: boundedProtocolValue(
            patch.payload,
            this.#maxOutputBytes,
            `${extension.manifest.id}.${hook}.patch.payload`,
            "EXTENSION_OUTPUT_INVALID"
          )
        } : {}
      });
    }
    return request;
  }
  async #patchResult(hook, turnId, request, initial, signal) {
    let result = frozenProtocolClone(initial);
    for (const extension of this.#active) {
      const callback = extension.instance[hook];
      if (callback === void 0) continue;
      let output;
      try {
        output = await callback.call(
          extension.instance,
          frozenSignalContext({
            sessionId: this.#identity.sessionId,
            turnId,
            request,
            result,
            signal
          })
        );
      } catch (error) {
        throw new BoundaryFault(
          "EXTENSION_HOOK_FAILED",
          `extension ${extension.manifest.id} failed in ${hook}`,
          { cause: error }
        );
      }
      if (output === void 0) continue;
      const patch = exactRecord2(
        output,
        [],
        RESULT_PATCH_FIELDS,
        `${extension.manifest.id}.${hook}.patch`,
        "EXTENSION_OUTPUT_INVALID"
      );
      boundedProtocolValue(
        patch,
        this.#maxOutputBytes,
        `${extension.manifest.id}.${hook}.patch`,
        "EXTENSION_OUTPUT_INVALID"
      );
      const allowed = new Set(extension.manifest.patchableFields[hook] ?? []);
      for (const field of Object.keys(patch)) {
        if (!allowed.has(field)) {
          throw new BoundaryFault(
            "EXTENSION_OUTPUT_INVALID",
            `extension ${extension.manifest.id} cannot patch ${field} in ${hook}`
          );
        }
      }
      if (Object.prototype.hasOwnProperty.call(patch, "result")) {
        result = boundedProtocolValue(
          patch.result,
          this.#maxOutputBytes,
          `${extension.manifest.id}.${hook}.patch.result`,
          "EXTENSION_OUTPUT_INVALID"
        );
      }
    }
    return result;
  }
};

// workers/pi-runtime/src/engine.ts
var CHECKPOINT_STATE_VERSION = 1;
var CHECKPOINT_DIGEST_DOMAIN = "circulusd.session.agent-checkpoint";
var EFFECT_REQUEST_DIGEST_DOMAIN = "circulusd.session.effect-request";
var TOOL_BATCH_DIGEST_DOMAIN = "circulusd.session.tool-batch";
var DIGEST_SCHEMA_VERSION = 1;
var MAX_PENDING_ABORT_TURNS = 64;
var DEFAULT_ENGINE_BUDGETS = Object.freeze({
  maxStepInputBytes: 5 * 1048576,
  maxCoreOutputBytes: 1048576,
  maxExtensionOutputBytes: 262144,
  maxCheckpointBytes: 1048576,
  maxAssistantDeltaBytes: 65536,
  maxEventsPerStep: 256,
  maxPendingToolCalls: 64,
  maxWallClockMs: 3e4
});
var SystemEngineClock = class {
  now() {
    return performance.now();
  }
  setTimeout(callback, delayMs) {
    return globalThis.setTimeout(callback, delayMs);
  }
  clearTimeout(handle) {
    if (typeof handle === "number") globalThis.clearTimeout(handle);
  }
};
function parseBudgets(value) {
  const record = value === void 0 ? {} : exactRecord2(
    value,
    [],
    Object.keys(DEFAULT_ENGINE_BUDGETS),
    "options.budgets",
    "INVALID_CONFIGURATION"
  );
  const resolved = { ...DEFAULT_ENGINE_BUDGETS, ...record };
  for (const [name, budget] of Object.entries(resolved)) {
    if (typeof budget !== "number" || !Number.isSafeInteger(budget) || budget < 1) {
      throw new PiRuntimeError(
        "INVALID_CONFIGURATION",
        `options.budgets.${name} must be a positive safe integer`
      );
    }
  }
  return Object.freeze({
    maxStepInputBytes: Number(resolved.maxStepInputBytes),
    maxCoreOutputBytes: Number(resolved.maxCoreOutputBytes),
    maxExtensionOutputBytes: Number(resolved.maxExtensionOutputBytes),
    maxCheckpointBytes: Number(resolved.maxCheckpointBytes),
    maxAssistantDeltaBytes: Number(resolved.maxAssistantDeltaBytes),
    maxEventsPerStep: Number(resolved.maxEventsPerStep),
    maxPendingToolCalls: Number(resolved.maxPendingToolCalls),
    maxWallClockMs: Number(resolved.maxWallClockMs)
  });
}
function parseIdentity(value) {
  const record = exactRecord2(
    value,
    ["sessionId", "runtimeRevisionDigest", "adapterAbiVersion", "checkpointSchemaVersion"],
    [],
    "identity",
    "INVALID_CONFIGURATION"
  );
  return Object.freeze({
    sessionId: boundedIdentifier(record.sessionId, "identity.sessionId", "INVALID_CONFIGURATION"),
    runtimeRevisionDigest: parseDigestForBoundary(
      record.runtimeRevisionDigest,
      "identity.runtimeRevisionDigest",
      "INVALID_CONFIGURATION"
    ),
    adapterAbiVersion: boundedSafeInteger(
      record.adapterAbiVersion,
      1,
      "identity.adapterAbiVersion",
      "INVALID_CONFIGURATION"
    ),
    checkpointSchemaVersion: boundedSafeInteger(
      record.checkpointSchemaVersion,
      1,
      "identity.checkpointSchemaVersion",
      "INVALID_CONFIGURATION"
    )
  });
}
function parseAdapterState(value, budgets) {
  const record = exactRecord2(
    value,
    [
      "version",
      "status",
      "coreState",
      "turnInput",
      "beforeTurnCompleted",
      "awaiting",
      "pendingTools",
      "completedTools",
      "terminalCode"
    ],
    [],
    "checkpoint.state",
    "INVALID_CHECKPOINT"
  );
  if (record.version !== CHECKPOINT_STATE_VERSION) {
    throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint state version is unsupported");
  }
  if (record.status !== "ready" && record.status !== "waiting_effect" && record.status !== "terminal") {
    throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint state status is unsupported");
  }
  if (typeof record.beforeTurnCompleted !== "boolean") {
    throw new PiRuntimeError(
      "INVALID_CHECKPOINT",
      "checkpoint beforeTurnCompleted must be a boolean"
    );
  }
  const coreState = boundedProtocolValue(
    record.coreState,
    budgets.maxCheckpointBytes,
    "checkpoint.state.coreState",
    "INVALID_CHECKPOINT"
  );
  const turnInput = record.turnInput === null ? null : boundedProtocolValue(
    record.turnInput,
    budgets.maxCheckpointBytes,
    "checkpoint.state.turnInput",
    "INVALID_CHECKPOINT"
  );
  let awaiting = null;
  if (record.awaiting !== null) {
    const awaitingRecord = exactRecord2(
      record.awaiting,
      ["kind", "request"],
      [],
      "checkpoint.state.awaiting",
      "INVALID_CHECKPOINT"
    );
    if (awaitingRecord.kind !== "model" && awaitingRecord.kind !== "tool") {
      throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint awaiting kind is unsupported");
    }
    awaiting = {
      kind: awaitingRecord.kind,
      request: parseEffectIntent(
        awaitingRecord.request,
        budgets.maxCheckpointBytes,
        "checkpoint.state.awaiting.request",
        "INVALID_CHECKPOINT"
      )
    };
  }
  if (!Array.isArray(record.pendingTools) || !Array.isArray(record.completedTools)) {
    throw new PiRuntimeError(
      "INVALID_CHECKPOINT",
      "checkpoint pendingTools and completedTools must be arrays"
    );
  }
  if (record.pendingTools.length > budgets.maxPendingToolCalls || record.completedTools.length > budgets.maxPendingToolCalls) {
    throw new PiRuntimeError("INVALID_CHECKPOINT", "checkpoint tool queue exceeds its budget");
  }
  const pendingTools = record.pendingTools.map(
    (request, index) => parseEffectRequestDraft(
      request,
      budgets.maxCheckpointBytes,
      `checkpoint.state.pendingTools[${index}]`,
      "INVALID_CHECKPOINT"
    )
  );
  const completedTools = record.completedTools.map((entry, index) => {
    const completedRecord = exactRecord2(
      entry,
      ["request", "settlement"],
      [],
      `checkpoint.state.completedTools[${index}]`,
      "INVALID_CHECKPOINT"
    );
    return {
      request: parseEffectIntent(
        completedRecord.request,
        budgets.maxCheckpointBytes,
        `checkpoint.state.completedTools[${index}].request`,
        "INVALID_CHECKPOINT"
      ),
      settlement: parseSettlementOutcome(
        completedRecord.settlement,
        budgets.maxCheckpointBytes,
        `checkpoint.state.completedTools[${index}].settlement`,
        "INVALID_CHECKPOINT"
      )
    };
  });
  const terminalCode = record.terminalCode === null ? null : boundedIdentifier(
    record.terminalCode,
    "checkpoint.state.terminalCode",
    "INVALID_CHECKPOINT"
  );
  if (record.status === "ready") {
    if (awaiting !== null || pendingTools.length !== 0 || completedTools.length !== 0 || terminalCode !== null) {
      throw new PiRuntimeError("INVALID_CHECKPOINT", "ready checkpoint contains pending state");
    }
    if (turnInput === null !== record.beforeTurnCompleted) {
      throw new PiRuntimeError(
        "INVALID_CHECKPOINT",
        "ready checkpoint turn input and lifecycle position disagree"
      );
    }
  } else if (record.status === "waiting_effect") {
    if (awaiting === null || turnInput !== null || !record.beforeTurnCompleted || terminalCode !== null || awaiting.kind === "model" && (pendingTools.length !== 0 || completedTools.length !== 0)) {
      throw new PiRuntimeError("INVALID_CHECKPOINT", "waiting checkpoint invariants are invalid");
    }
  } else if (awaiting !== null || turnInput !== null || pendingTools.length !== 0 || completedTools.length !== 0 || terminalCode === null || !record.beforeTurnCompleted) {
    throw new PiRuntimeError("INVALID_CHECKPOINT", "terminal checkpoint invariants are invalid");
  }
  const state = {
    version: CHECKPOINT_STATE_VERSION,
    status: record.status,
    coreState,
    turnInput,
    beforeTurnCompleted: record.beforeTurnCompleted,
    awaiting,
    pendingTools,
    completedTools,
    terminalCode
  };
  boundedProtocolValue(
    state,
    budgets.maxCheckpointBytes,
    "checkpoint.state",
    "INVALID_CHECKPOINT"
  );
  return state;
}
function parseCoreTransition(value, budgets) {
  const preliminary = exactRecord2(
    value,
    ["kind", "state"],
    ["assistantDeltas", "request", "requests", "result", "error"],
    "core.output",
    "CORE_OUTPUT_INVALID"
  );
  boundedProtocolValue(
    value,
    budgets.maxCoreOutputBytes,
    "core.output",
    "CORE_OUTPUT_INVALID"
  );
  const state = boundedProtocolValue(
    preliminary.state,
    budgets.maxCoreOutputBytes,
    "core.output.state",
    "CORE_OUTPUT_INVALID"
  );
  let assistantDeltas;
  if (Object.prototype.hasOwnProperty.call(preliminary, "assistantDeltas")) {
    if (!Array.isArray(preliminary.assistantDeltas)) {
      throw new BoundaryFault("CORE_OUTPUT_INVALID", "core.output.assistantDeltas must be an array");
    }
    if (preliminary.assistantDeltas.length + 1 > budgets.maxEventsPerStep) {
      throw new BoundaryFault(
        "EVENT_BUDGET_EXCEEDED",
        `core output exceeds ${budgets.maxEventsPerStep} events in one bounded step`
      );
    }
    assistantDeltas = preliminary.assistantDeltas.map(
      (delta, index) => boundedProtocolValue(
        delta,
        budgets.maxAssistantDeltaBytes,
        `core.output.assistantDeltas[${index}]`,
        "CORE_OUTPUT_INVALID"
      )
    );
  }
  const common = assistantDeltas === void 0 ? { state } : { state, assistantDeltas };
  switch (preliminary.kind) {
    case "checkpoint_only": {
      exactRecord2(value, ["kind", "state"], ["assistantDeltas"], "core.output", "CORE_OUTPUT_INVALID");
      return { kind: "checkpoint_only", ...common };
    }
    case "model_request": {
      const record = exactRecord2(
        value,
        ["kind", "state", "request"],
        ["assistantDeltas"],
        "core.output",
        "CORE_OUTPUT_INVALID"
      );
      const request = parseEffectRequestDraft(
        record.request,
        budgets.maxCoreOutputBytes,
        "core.output.request",
        "CORE_OUTPUT_INVALID"
      );
      if (request.service !== "model") {
        throw new BoundaryFault("CORE_OUTPUT_INVALID", "model_request must target model service");
      }
      return { kind: "model_request", ...common, request };
    }
    case "tool_requests": {
      const record = exactRecord2(
        value,
        ["kind", "state", "requests"],
        ["assistantDeltas"],
        "core.output",
        "CORE_OUTPUT_INVALID"
      );
      if (!Array.isArray(record.requests) || record.requests.length === 0 || record.requests.length > budgets.maxPendingToolCalls) {
        throw new BoundaryFault(
          "CORE_OUTPUT_INVALID",
          `tool_requests must contain 1..${budgets.maxPendingToolCalls} requests`
        );
      }
      const requests = record.requests.map((request, index) => {
        const parsed = parseEffectRequestDraft(
          request,
          budgets.maxCoreOutputBytes,
          `core.output.requests[${index}]`,
          "CORE_OUTPUT_INVALID"
        );
        if (parsed.service === "model") {
          throw new BoundaryFault("CORE_OUTPUT_INVALID", "tool_requests cannot target model service");
        }
        return parsed;
      });
      return { kind: "tool_requests", ...common, requests };
    }
    case "turn_complete": {
      const record = exactRecord2(
        value,
        ["kind", "state", "result"],
        ["assistantDeltas"],
        "core.output",
        "CORE_OUTPUT_INVALID"
      );
      return {
        kind: "turn_complete",
        ...common,
        result: boundedProtocolValue(
          record.result,
          budgets.maxCoreOutputBytes,
          "core.output.result",
          "CORE_OUTPUT_INVALID"
        )
      };
    }
    case "turn_error": {
      const record = exactRecord2(
        value,
        ["kind", "state", "error"],
        ["assistantDeltas"],
        "core.output",
        "CORE_OUTPUT_INVALID"
      );
      const errorRecord = exactRecord2(
        record.error,
        ["code", "message", "retryable"],
        ["details"],
        "core.output.error",
        "CORE_OUTPUT_INVALID"
      );
      if (typeof errorRecord.retryable !== "boolean") {
        throw new BoundaryFault("CORE_OUTPUT_INVALID", "core.output.error.retryable must be boolean");
      }
      const error = {
        code: boundedIdentifier(errorRecord.code, "core.output.error.code", "CORE_OUTPUT_INVALID"),
        message: boundedIdentifier(
          errorRecord.message,
          "core.output.error.message",
          "CORE_OUTPUT_INVALID"
        ),
        retryable: errorRecord.retryable,
        ...Object.prototype.hasOwnProperty.call(errorRecord, "details") ? {
          details: boundedProtocolValue(
            errorRecord.details,
            budgets.maxCoreOutputBytes,
            "core.output.error.details",
            "CORE_OUTPUT_INVALID"
          )
        } : {}
      };
      return { kind: "turn_error", ...common, error };
    }
    default:
      throw new BoundaryFault("CORE_OUTPUT_INVALID", "core.output.kind is unsupported");
  }
}
var LowLevelPiAgentEngine = class {
  #identity;
  #budgets;
  #clock;
  #coreFactory;
  #coreFactoryContext;
  #hooks;
  #initialization = null;
  #activeStep = null;
  #pendingAbortTurnIds = /* @__PURE__ */ new Set();
  #stepClaimed = false;
  #poisoned = false;
  constructor(identity, coreFactory, options = {}) {
    this.#identity = parseIdentity(identity);
    this.#budgets = parseBudgets(options.budgets);
    this.#clock = options.clock ?? new SystemEngineClock();
    if (typeof this.#clock.now !== "function" || typeof this.#clock.setTimeout !== "function" || typeof this.#clock.clearTimeout !== "function") {
      throw new PiRuntimeError("INVALID_CONFIGURATION", "engine clock is invalid");
    }
    if (typeof coreFactory !== "function") {
      throw new PiRuntimeError("INVALID_CONFIGURATION", "AgentCore factory is required");
    }
    this.#coreFactory = coreFactory;
    this.#coreFactoryContext = frozenProtocolClone({
      sessionId: this.#identity.sessionId,
      runtimeRevisionDigest: this.#identity.runtimeRevisionDigest,
      adapterAbiVersion: this.#identity.adapterAbiVersion,
      checkpointSchemaVersion: this.#identity.checkpointSchemaVersion
    });
    this.#hooks = new HookDispatcher(this.#identity, this.#budgets.maxExtensionOutputBytes);
  }
  registerExtension(registration) {
    this.#hooks.register(registration);
  }
  initialize() {
    if (this.#initialization === null) {
      const timeout = Promise.withResolvers();
      const timeoutHandle = this.#clock.setTimeout(
        () => timeout.reject(
          new PiRuntimeError(
            "INITIALIZATION_FAILED",
            `extension initialization exceeded ${this.#budgets.maxWallClockMs}ms`
          )
        ),
        this.#budgets.maxWallClockMs
      );
      this.#initialization = Promise.race([this.#hooks.initialize(), timeout.promise]).finally(
        () => this.#clock.clearTimeout(timeoutHandle)
      );
    }
    return this.#initialization;
  }
  async createGenesisCheckpoint(input) {
    const record = exactRecord2(
      input,
      ["turnId", "input", "initialCoreState"],
      [],
      "genesis",
      "INVALID_CONTEXT"
    );
    const turnId = boundedIdentifier(record.turnId, "genesis.turnId", "INVALID_CONTEXT");
    const state = parseAdapterState(
      {
        version: CHECKPOINT_STATE_VERSION,
        status: "ready",
        coreState: boundedProtocolValue(
          record.initialCoreState,
          this.#budgets.maxCheckpointBytes,
          "genesis.initialCoreState",
          "INVALID_CONTEXT"
        ),
        turnInput: boundedProtocolValue(
          record.input,
          this.#budgets.maxCheckpointBytes,
          "genesis.input",
          "INVALID_CONTEXT"
        ),
        beforeTurnCompleted: false,
        awaiting: null,
        pendingTools: [],
        completedTools: [],
        terminalCode: null
      },
      this.#budgets
    );
    const payloadBytes = encodeCanonicalCbor(state, {
      maxBytes: this.#budgets.maxCheckpointBytes
    });
    const checkpoint = {
      kind: "genesis",
      engineKind: "low-level",
      adapterAbiVersion: this.#identity.adapterAbiVersion,
      checkpointSchemaVersion: this.#identity.checkpointSchemaVersion,
      runtimeRevisionDigest: this.#identity.runtimeRevisionDigest,
      sessionId: this.#identity.sessionId,
      turnId,
      checkpointSequence: 0,
      predecessorDigest: null,
      payloadEncoding: "canonical-cbor",
      payloadBytes,
      payloadDigest: await digestBytes(payloadBytes)
    };
    return validateAgentCheckpoint(checkpoint);
  }
  async step(context) {
    if (this.#poisoned) {
      throw new PiRuntimeError(
        "ENGINE_POISONED",
        "engine must be reconstructed after an interrupted bounded step"
      );
    }
    if (this.#stepClaimed) {
      throw new PiRuntimeError("STEP_IN_PROGRESS", "a bounded step is already in progress");
    }
    this.#stepClaimed = true;
    this.#hooks.seal();
    try {
      const contextRecord = exactRecord2(
        context,
        ["authority", "checkpoint"],
        ["settlement", "emitDelta"],
        "stepContext",
        "INVALID_CONTEXT"
      );
      if (!(contextRecord.authority instanceof OpaqueTurnAuthority) || !contextRecord.authority.isPresent()) {
        throw new PiRuntimeError("INVALID_CONTEXT", "stepContext.authority must be opaque");
      }
      if (Object.prototype.hasOwnProperty.call(contextRecord, "emitDelta") && typeof contextRecord.emitDelta !== "function") {
        throw new PiRuntimeError("INVALID_CONTEXT", "stepContext.emitDelta must be a function");
      }
      let checkpoint;
      try {
        checkpoint = await validateAgentCheckpoint(contextRecord.checkpoint);
      } catch (error) {
        if (error instanceof ProtocolValidationError) {
          throw new PiRuntimeError("INVALID_CHECKPOINT", `checkpoint is invalid: ${error.message}`, {
            cause: error
          });
        }
        throw error;
      }
      if (checkpoint.engineKind !== "low-level" || checkpoint.sessionId !== this.#identity.sessionId || checkpoint.runtimeRevisionDigest !== this.#identity.runtimeRevisionDigest || checkpoint.adapterAbiVersion !== this.#identity.adapterAbiVersion || checkpoint.checkpointSchemaVersion !== this.#identity.checkpointSchemaVersion || checkpoint.payloadEncoding !== "canonical-cbor") {
        throw new PiRuntimeError(
          "CHECKPOINT_IDENTITY_MISMATCH",
          "checkpoint does not belong to this exact runtime identity"
        );
      }
      const state = parseAdapterState(
        decodeCanonicalCheckpointPayload(
          checkpoint.payloadBytes,
          this.#budgets.maxCheckpointBytes
        ),
        this.#budgets
      );
      if (state.status === "terminal") {
        throw new PiRuntimeError("ENGINE_TERMINAL", "checkpoint is already terminal");
      }
      const hasSettlement = Object.prototype.hasOwnProperty.call(contextRecord, "settlement");
      const settlement = hasSettlement ? parseEngineSettlement(
        contextRecord.settlement,
        this.#budgets.maxStepInputBytes,
        "stepContext.settlement"
      ) : null;
      boundedProtocolValue(
        { checkpoint, settlement },
        this.#budgets.maxStepInputBytes,
        "stepContext",
        "INVALID_CONTEXT"
      );
      if (state.status === "waiting_effect" && settlement === null) {
        throw new PiRuntimeError(
          "SETTLEMENT_REQUIRED",
          "the pending external effect must settle before the next engine step"
        );
      }
      if (state.status !== "waiting_effect" && settlement !== null) {
        throw new PiRuntimeError(
          "UNEXPECTED_SETTLEMENT",
          "checkpoint has no external effect settlement to consume"
        );
      }
      if (state.awaiting !== null && settlement !== null && state.awaiting.request.requestDigest !== settlement.requestDigest) {
        throw new PiRuntimeError(
          "SETTLEMENT_MISMATCH",
          "settlement requestDigest does not match the checkpointed external effect"
        );
      }
      let core;
      try {
        core = this.#coreFactory(this.#coreFactoryContext);
      } catch (error) {
        throw new PiRuntimeError(
          "INVALID_CONFIGURATION",
          "AgentCore factory failed while reconstructing a bounded step",
          { cause: error }
        );
      }
      if (core === null || typeof core !== "object" || typeof core.advance !== "function") {
        throw new PiRuntimeError("INVALID_CONFIGURATION", "AgentCore factory returned an invalid core");
      }
      const controller = new AbortController();
      const activeStep = {
        turnId: checkpoint.turnId,
        controller,
        core,
        interruptPromise: null
      };
      this.#activeStep = activeStep;
      const startedAt = this.#clock.now();
      const abortSignal = Promise.withResolvers();
      const onAbort = () => {
        const reason = controller.signal.reason;
        abortSignal.reject(
          reason instanceof BoundaryFault ? reason : new BoundaryFault("TURN_ABORTED", "bounded engine step was aborted")
        );
      };
      controller.signal.addEventListener("abort", onAbort, { once: true });
      const timeoutHandle = this.#clock.setTimeout(() => {
        controller.abort(
          new BoundaryFault(
            "STEP_TIMEOUT",
            `bounded engine step exceeded ${this.#budgets.maxWallClockMs}ms`
          )
        );
        void this.#interruptActiveStep(activeStep);
      }, this.#budgets.maxWallClockMs);
      try {
        if (this.#pendingAbortTurnIds.delete(checkpoint.turnId)) {
          controller.abort(
            new BoundaryFault("TURN_ABORTED", `turn ${checkpoint.turnId} was aborted`)
          );
          void this.#interruptActiveStep(activeStep);
        }
        this.#pendingAbortTurnIds.clear();
        await Promise.race([this.initialize(), abortSignal.promise]);
        this.#throwIfAborted(controller.signal);
        const execution = this.#execute(
          core,
          state,
          settlement,
          checkpoint.turnId,
          checkpoint.checkpointSequence,
          controller.signal,
          contextRecord.emitDelta
        );
        const executed = await Promise.race([execution, abortSignal.promise]);
        if (this.#clock.now() - startedAt > this.#budgets.maxWallClockMs) {
          throw new BoundaryFault(
            "STEP_TIMEOUT",
            `bounded engine step exceeded ${this.#budgets.maxWallClockMs}ms`
          );
        }
        const nextCheckpoint = await this.#createSuccessorCheckpoint(checkpoint, executed.state);
        this.#throwIfAborted(controller.signal);
        const result = await this.#attachCheckpoint(nextCheckpoint, executed.boundary);
        this.#throwIfAborted(controller.signal);
        return result;
      } catch (error) {
        if (error instanceof PiRuntimeError && error.code === "INITIALIZATION_FAILED") {
          throw error;
        }
        const fault = error instanceof BoundaryFault ? error : new BoundaryFault("CORE_EXECUTION_FAILED", "bounded engine step failed", {
          cause: error
        });
        if (fault.code === "STEP_TIMEOUT" || fault.code === "TURN_ABORTED") {
          this.#poisoned = true;
          void this.#interruptActiveStep(activeStep);
        }
        controller.abort(fault);
        const terminalState = {
          version: CHECKPOINT_STATE_VERSION,
          status: "terminal",
          coreState: state.coreState,
          turnInput: null,
          beforeTurnCompleted: true,
          awaiting: null,
          pendingTools: [],
          completedTools: [],
          terminalCode: fault.code
        };
        const nextCheckpoint = await this.#createSuccessorCheckpoint(checkpoint, terminalState);
        return this.#attachCheckpoint(nextCheckpoint, {
          kind: "turn_error",
          error: { code: fault.code, message: fault.message, retryable: false }
        });
      } finally {
        this.#clock.clearTimeout(timeoutHandle);
        controller.signal.removeEventListener("abort", onAbort);
        this.#activeStep = null;
      }
    } finally {
      this.#stepClaimed = false;
      this.#pendingAbortTurnIds.clear();
    }
  }
  async abortTurn(turnId) {
    boundedIdentifier(turnId, "turnId", "INVALID_CONTEXT");
    const activeStep = this.#activeStep;
    if (activeStep === null) {
      if (this.#stepClaimed) {
        if (this.#pendingAbortTurnIds.size >= MAX_PENDING_ABORT_TURNS && !this.#pendingAbortTurnIds.has(turnId)) {
          this.#pendingAbortTurnIds.clear();
        }
        this.#pendingAbortTurnIds.add(turnId);
      }
      return;
    }
    if (activeStep.turnId !== turnId) return;
    activeStep.controller.abort(
      new BoundaryFault("TURN_ABORTED", `turn ${turnId} was aborted`)
    );
    await this.#interruptActiveStep(activeStep);
  }
  #interruptActiveStep(activeStep) {
    if (activeStep.interruptPromise !== null) return activeStep.interruptPromise;
    const finished = Promise.withResolvers();
    activeStep.interruptPromise = finished.promise;
    if (activeStep.core.abortTurn === void 0) {
      finished.resolve();
      return finished.promise;
    }
    const timeout = Promise.withResolvers();
    const timeoutHandle = this.#clock.setTimeout(
      () => timeout.resolve(),
      this.#budgets.maxWallClockMs
    );
    let interrupt;
    try {
      interrupt = Promise.resolve(activeStep.core.abortTurn(activeStep.turnId));
    } catch {
      interrupt = Promise.resolve();
    }
    void Promise.race([timeout.promise, interrupt]).then(
      () => {
        this.#clock.clearTimeout(timeoutHandle);
        finished.resolve();
      },
      () => {
        this.#clock.clearTimeout(timeoutHandle);
        finished.resolve();
      }
    );
    return finished.promise;
  }
  async #execute(core, initial, settlement, turnId, checkpointSequence, signal, emitDelta) {
    let coreInput;
    let coreState = initial.coreState;
    if (settlement !== null) {
      const awaiting = initial.awaiting;
      if (awaiting === null) {
        throw new PiRuntimeError("UNEXPECTED_SETTLEMENT", "checkpoint has no awaiting effect");
      }
      let outcome = settlement.outcome;
      if (outcome.kind === "success" && awaiting.kind === "model") {
        outcome = {
          kind: "success",
          result: await this.#hooks.afterModelResponse(
            turnId,
            awaiting.request,
            outcome.result,
            signal
          )
        };
      }
      if (outcome.kind === "success" && awaiting.kind === "tool") {
        outcome = {
          kind: "success",
          result: await this.#hooks.afterToolCall(
            turnId,
            awaiting.request,
            outcome.result,
            signal
          )
        };
      }
      this.#throwIfAborted(signal);
      if (awaiting.kind === "tool") {
        const completedTools = [
          ...initial.completedTools,
          { request: awaiting.request, settlement: outcome }
        ];
        if (initial.pendingTools.length > 0) {
          return this.#issueToolBoundary(
            turnId,
            coreState,
            initial.pendingTools,
            completedTools,
            signal
          );
        }
        coreInput = {
          kind: "tool_settlements",
          results: frozenProtocolClone(completedTools)
        };
      } else {
        coreInput = {
          kind: "effect_settlement",
          request: frozenProtocolClone(awaiting.request),
          settlement: frozenProtocolClone(outcome)
        };
      }
    } else if (initial.turnInput !== null) {
      await this.#hooks.beforeTurn(turnId, initial.turnInput, signal);
      this.#throwIfAborted(signal);
      coreInput = { kind: "turn_start", input: frozenProtocolClone(initial.turnInput) };
    } else {
      coreInput = { kind: "continue" };
    }
    let rawTransition;
    try {
      rawTransition = await core.advance(
        frozenSignalContext({
          sessionId: this.#identity.sessionId,
          turnId,
          runtimeRevisionDigest: this.#identity.runtimeRevisionDigest,
          state: coreState,
          input: coreInput,
          signal
        })
      );
    } catch (error) {
      if (error instanceof BoundaryFault) throw error;
      if (signal.aborted) throw signal.reason;
      throw new BoundaryFault("CORE_EXECUTION_FAILED", "AgentCore.advance failed", {
        cause: error
      });
    }
    this.#throwIfAborted(signal);
    const transition = parseCoreTransition(rawTransition, this.#budgets);
    coreState = transition.state;
    if (transition.assistantDeltas !== void 0 && emitDelta !== void 0) {
      for (const delta of transition.assistantDeltas) {
        this.#throwIfAborted(signal);
        try {
          await emitDelta(frozenProtocolClone(delta));
        } catch {
        }
      }
    }
    this.#throwIfAborted(signal);
    switch (transition.kind) {
      case "checkpoint_only":
        return {
          boundary: { kind: "checkpoint" },
          state: this.#readyState(coreState)
        };
      case "model_request": {
        const patched = parseEffectRequestDraft(
          await this.#hooks.beforeModelRequest(turnId, transition.request, signal),
          this.#budgets.maxCoreOutputBytes,
          "patched.modelRequest",
          "EXTENSION_OUTPUT_INVALID"
        );
        if (patched.service !== "model") {
          throw new BoundaryFault(
            "EXTENSION_OUTPUT_INVALID",
            "beforeModelRequest cannot change the model service"
          );
        }
        const request = await this.#intent(patched);
        return {
          boundary: { kind: "effect_request", request },
          state: {
            ...this.#readyState(coreState),
            status: "waiting_effect",
            awaiting: { kind: "model", request }
          }
        };
      }
      case "tool_requests": {
        const generatedParentOperationId = await digestStructuredValue(
          TOOL_BATCH_DIGEST_DOMAIN,
          DIGEST_SCHEMA_VERSION,
          {
            sessionId: this.#identity.sessionId,
            turnId,
            checkpointSequence
          }
        );
        const occurrenceKeys = /* @__PURE__ */ new Set();
        const requests = transition.requests.map((request, ordinal) => {
          const occurrence = request.parentOperationId === void 0 ? { ...request, parentOperationId: generatedParentOperationId, ordinal } : request;
          const occurrenceKey = `${occurrence.parentOperationId}\0${occurrence.ordinal}`;
          if (occurrenceKeys.has(occurrenceKey)) {
            throw new BoundaryFault(
              "CORE_OUTPUT_INVALID",
              "tool_requests contains a duplicate parentOperationId and ordinal occurrence"
            );
          }
          occurrenceKeys.add(occurrenceKey);
          return occurrence;
        });
        return this.#issueToolBoundary(
          turnId,
          coreState,
          requests,
          [],
          signal
        );
      }
      case "turn_complete": {
        await this.#hooks.afterTurn(turnId, transition.result, signal);
        this.#throwIfAborted(signal);
        return {
          boundary: { kind: "turn_complete", result: transition.result },
          state: this.#terminalState(coreState, "TURN_COMPLETE")
        };
      }
      case "turn_error":
        return {
          boundary: { kind: "turn_error", error: transition.error },
          state: this.#terminalState(coreState, transition.error.code)
        };
    }
  }
  async #issueToolBoundary(turnId, coreState, queue, completedTools, signal) {
    const [head, ...pendingTools] = queue;
    if (head === void 0) {
      throw new BoundaryFault("CORE_OUTPUT_INVALID", "tool queue unexpectedly became empty");
    }
    const patched = parseEffectRequestDraft(
      await this.#hooks.beforeToolCall(turnId, head, signal),
      this.#budgets.maxCoreOutputBytes,
      "patched.toolRequest",
      "EXTENSION_OUTPUT_INVALID"
    );
    if (patched.service === "model") {
      throw new BoundaryFault(
        "EXTENSION_OUTPUT_INVALID",
        "beforeToolCall cannot change a tool request into a model request"
      );
    }
    this.#throwIfAborted(signal);
    const request = await this.#intent(patched);
    return {
      boundary: { kind: "effect_request", request },
      state: {
        version: CHECKPOINT_STATE_VERSION,
        status: "waiting_effect",
        coreState,
        turnInput: null,
        beforeTurnCompleted: true,
        awaiting: { kind: "tool", request },
        pendingTools,
        completedTools,
        terminalCode: null
      }
    };
  }
  async #intent(draft) {
    const digestPayload = {
      service: draft.service,
      operation: draft.operation,
      replayPolicy: draft.replayPolicy,
      payload: draft.payload,
      ...draft.parentOperationId === void 0 ? {} : { parentOperationId: draft.parentOperationId, ordinal: draft.ordinal }
    };
    return {
      ...draft,
      requestDigest: await digestStructuredValue(
        EFFECT_REQUEST_DIGEST_DOMAIN,
        DIGEST_SCHEMA_VERSION,
        digestPayload
      )
    };
  }
  #readyState(coreState) {
    return {
      version: CHECKPOINT_STATE_VERSION,
      status: "ready",
      coreState,
      turnInput: null,
      beforeTurnCompleted: true,
      awaiting: null,
      pendingTools: [],
      completedTools: [],
      terminalCode: null
    };
  }
  #terminalState(coreState, terminalCode) {
    return {
      version: CHECKPOINT_STATE_VERSION,
      status: "terminal",
      coreState,
      turnInput: null,
      beforeTurnCompleted: true,
      awaiting: null,
      pendingTools: [],
      completedTools: [],
      terminalCode
    };
  }
  #throwIfAborted(signal) {
    if (signal.aborted) {
      throw signal.reason instanceof BoundaryFault ? signal.reason : new BoundaryFault("TURN_ABORTED", "bounded engine step was aborted");
    }
  }
  async #createSuccessorCheckpoint(predecessor, state) {
    parseAdapterState(state, this.#budgets);
    const payloadBytes = encodeCanonicalCbor(state, {
      maxBytes: this.#budgets.maxCheckpointBytes
    });
    const checkpoint = {
      kind: "engine",
      engineKind: "low-level",
      adapterAbiVersion: this.#identity.adapterAbiVersion,
      checkpointSchemaVersion: this.#identity.checkpointSchemaVersion,
      runtimeRevisionDigest: this.#identity.runtimeRevisionDigest,
      sessionId: this.#identity.sessionId,
      turnId: predecessor.turnId,
      checkpointSequence: predecessor.checkpointSequence + 1,
      predecessorDigest: await digestStructuredValue(
        CHECKPOINT_DIGEST_DOMAIN,
        DIGEST_SCHEMA_VERSION,
        predecessor
      ),
      payloadEncoding: "canonical-cbor",
      payloadBytes,
      payloadDigest: await digestBytes(payloadBytes)
    };
    return validateAgentCheckpoint(checkpoint);
  }
  async #attachCheckpoint(checkpoint, boundary) {
    let result;
    switch (boundary.kind) {
      case "checkpoint":
        result = { kind: "checkpoint", checkpoint };
        break;
      case "effect_request":
        result = { kind: "effect_request", checkpoint, request: boundary.request };
        break;
      case "turn_complete":
        result = { kind: "turn_complete", checkpoint, result: boundary.result };
        break;
      case "turn_error":
        result = { kind: "turn_error", checkpoint, error: boundary.error };
        break;
    }
    return validateEngineStepResult(result);
  }
};

// internal/conformance/workerd/fixture/pi-worker.entry.ts
var counter = 0;
async function denied(operation2) {
  try {
    await operation2();
    return false;
  } catch {
    return true;
  }
}
async function runAgentTurn() {
  const hooks = [];
  let modelRequests = 0;
  let toolRequests = 0;
  const coreFactory = () => ({
    async advance(context) {
      if (context.input.kind === "turn_start") {
        modelRequests += 1;
        return {
          kind: "model_request",
          state: { phase: "model" },
          request: {
            service: "model",
            operation: "complete",
            replayPolicy: "safe",
            payload: { prompt: context.input.input }
          }
        };
      }
      if (context.input.kind === "effect_settlement") {
        toolRequests += 1;
        return {
          kind: "tool_requests",
          state: { phase: "tool" },
          requests: [{
            service: "external-tool",
            operation: "echo",
            replayPolicy: "safe",
            payload: { model: context.input.settlement }
          }]
        };
      }
      if (context.input.kind === "tool_settlements") {
        return {
          kind: "turn_complete",
          state: { phase: "complete" },
          result: { tool: context.input.results[0]?.settlement ?? null }
        };
      }
      throw new Error(`unexpected core input ${context.input.kind}`);
    }
  });
  const identity = {
    sessionId: "session_phase0",
    runtimeRevisionDigest: `sha256:${"a".repeat(64)}`,
    adapterAbiVersion: 1,
    checkpointSchemaVersion: 1
  };
  const registration = (id, priority) => ({
    manifest: { id, priority, tools: [], patchableFields: {} },
    create: () => ({
      async initialize() {
        hooks.push(`${id}:initialize`);
      },
      async beforeAgentStart() {
        hooks.push(`${id}:beforeAgentStart`);
      },
      async beforeTurn() {
        hooks.push(`${id}:beforeTurn`);
      },
      async beforeModelRequest() {
        hooks.push(`${id}:beforeModelRequest`);
      },
      async afterModelResponse() {
        hooks.push(`${id}:afterModelResponse`);
      },
      async beforeToolCall() {
        hooks.push(`${id}:beforeToolCall`);
      },
      async afterToolCall() {
        hooks.push(`${id}:afterToolCall`);
      },
      async afterTurn() {
        hooks.push(`${id}:afterTurn`);
      }
    })
  });
  const engine = new LowLevelPiAgentEngine(identity, coreFactory);
  engine.registerExtension(registration("b", 20));
  engine.registerExtension(registration("a", 10));
  const authority = () => createOpaqueTurnAuthority(new Uint8Array([1, 2, 3]));
  const genesis = await engine.createGenesisCheckpoint({
    turnId: "turn_phase0",
    input: { prompt: "hello" },
    initialCoreState: { phase: "initial" }
  });
  const model = await engine.step({ authority: authority(), checkpoint: genesis });
  if (model.kind !== "effect_request" || model.request.service !== "model") {
    throw new Error("low-level engine did not emit the model boundary");
  }
  const tool = await engine.step({
    authority: authority(),
    checkpoint: model.checkpoint,
    settlement: {
      requestDigest: model.request.requestDigest,
      outcome: { kind: "success", result: { text: "model response" } }
    }
  });
  if (tool.kind !== "effect_request" || tool.request.service === "model") {
    throw new Error("low-level engine did not emit the tool boundary");
  }
  const completed = await engine.step({
    authority: authority(),
    checkpoint: tool.checkpoint,
    settlement: {
      requestDigest: tool.request.requestDigest,
      outcome: { kind: "success", result: { text: "tool response" } }
    }
  });
  return { completed: completed.kind === "turn_complete", modelRequests, toolRequests, hooks };
}
var pi_worker_entry_default = {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (path === "/identity") {
      return Response.json({ marker: env.MARKER });
    }
    if (path === "/counter") {
      counter += 1;
      return Response.json({ count: counter });
    }
    if (path === "/agent-turn") {
      return Response.json(await runAgentTurn());
    }
    if (path === "/outbound") {
      const fetchDenied = await denied(
        () => fetch("https://192.0.2.1/", { signal: AbortSignal.timeout(250) })
      );
      const webSocketDenied = await denied(
        () => new Promise((resolve, reject) => {
          const socket = new WebSocket("wss://192.0.2.1/");
          const timeout = setTimeout(() => {
            socket.close();
            reject(new Error("WebSocket did not settle"));
          }, 250);
          socket.addEventListener("open", () => {
            clearTimeout(timeout);
            resolve();
          }, { once: true });
          socket.addEventListener("error", () => {
            clearTimeout(timeout);
            reject(new Error("WebSocket denied"));
          }, { once: true });
        })
      );
      const rawSocketDenied = await denied(async () => {
        const { connect } = await import("cloudflare:sockets");
        const socket = connect({ hostname: "192.0.2.1", port: 9 });
        await Promise.race([
          socket.opened,
          new Promise(
            (_resolve, reject) => setTimeout(() => reject(new Error("raw socket did not settle")), 250)
          )
        ]);
        await socket.close();
      });
      return Response.json({ fetchDenied, webSocketDenied, rawSocketDenied });
    }
    return new Response("not found", { status: 404 });
  }
};
export {
  pi_worker_entry_default as default
};
