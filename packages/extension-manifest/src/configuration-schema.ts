import Ajv2020 from "ajv/dist/2020.js";
import type { JsonValue } from "./configuration-codec.ts";

/**
 * Schemas without $schema use this pinned dialect; other dialects are rejected.
 * Only same-document fragment refs are supported. No network/file/bundle schema
 * loader is provided. Format is an annotation, matching draft 2020-12 defaults.
 * https://json-schema.org/draft/2020-12/schema
 */
export const EXTENSION_CONFIGURATION_DIALECT = "https://json-schema.org/draft/2020-12/schema";

const schemaMaps = new Set(["$defs", "definitions", "properties", "patternProperties", "dependentSchemas"]);
const schemaArrays = new Set(["allOf", "anyOf", "oneOf", "prefixItems"]);
const schemaValues = new Set(["additionalProperties", "unevaluatedProperties", "items", "unevaluatedItems", "contains", "propertyNames", "not", "if", "then", "else"]);

// Traverse schema positions, never enum/const/example instance data.
function checkOfflineSchema(value: JsonValue): void {
  if (typeof value === "boolean") return;
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("schema must be an object or boolean");
  for (const [key, item] of Object.entries(value)) {
    if (key === "$schema" && item !== EXTENSION_CONFIGURATION_DIALECT) throw new Error("extension schemas require JSON Schema draft 2020-12");
    if ((key === "$ref" || key === "$dynamicRef") && (typeof item !== "string" || !item.startsWith("#"))) throw new Error("extension schema references must be local fragments");
    if (key === "$vocabulary") throw new Error("extension schemas cannot override the pinned dialect vocabulary");
    if (schemaMaps.has(key) && item !== null && typeof item === "object" && !Array.isArray(item)) {
      for (const child of Object.values(item)) checkOfflineSchema(child);
    } else if (schemaArrays.has(key) && Array.isArray(item)) {
      for (const child of item) checkOfflineSchema(child);
    } else if (schemaValues.has(key)) checkOfflineSchema(item);
  }
}

/**
 * Install validates the original schema, then supplied COMPLETE defaults against
 * that original schema, including required/oneOf/if/not. Defaults may be omitted.
 * The runtime caller combines defaults and overrides into a complete selected
 * snapshot; Go CompileRuntime validates it against the original signed schema.
 */
export function validateExtensionSchema(schema: JsonValue, defaults?: JsonValue): void {
  checkOfflineSchema(schema);
  const ajv = new Ajv2020({ strict: false, validateFormats: false, allErrors: false, ownProperties: true, addUsedSchema: false });
  if (!ajv.validateSchema(schema as object)) throw new Error(`invalid draft 2020-12 schema: ${ajv.errorsText()}`);
  // Compile even without defaults so unresolved refs and invalid regexes cannot
  // hide behind configuration fields that have not been supplied yet.
  const validate = ajv.compile(schema as object);
  if (defaults !== undefined && !validate(defaults)) {
    throw new Error(`configuration defaults violate their schema: ${ajv.errorsText(validate.errors)}`);
  }
}
