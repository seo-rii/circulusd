import type Ajv2020 from "ajv/dist/2020.js";
import type { AnySchema, AnySchemaObject, KeywordCxt } from "ajv";
import { resolveRef, SchemaEnv } from "ajv/dist/compile/index.js";
import { normalizeId, resolveUrl } from "ajv/dist/compile/resolve.js";
import { _, getProperty, Name } from "ajv/dist/compile/codegen/index.js";
import { callRef, getValidate } from "ajv/dist/vocabularies/core/ref.js";
import { dynamicAnchor } from "ajv/dist/vocabularies/dynamic/dynamicAnchor.js";
import { dynamicRef } from "ajv/dist/vocabularies/dynamic/dynamicRef.js";

const schemaMaps = new Set(["$defs", "definitions", "properties", "patternProperties", "dependentSchemas"]);
const schemaArrays = new Set(["allOf", "anyOf", "oneOf", "prefixItems"]);
const schemaValues = new Set(["additionalProperties", "unevaluatedProperties", "items", "unevaluatedItems", "contains", "propertyNames", "not", "if", "then", "else"]);

interface ResourceIndex {
  readonly positions: WeakMap<AnySchemaObject, readonly string[]>;
  readonly anchors: Map<string, Map<string, AnySchemaObject>>;
}

// Dynamic scope includes every anchor in an active resource, including $defs
// that has not been evaluated. A nested $id starts a separate resource.
function indexResources(ajv: Ajv2020, root: SchemaEnv): ResourceIndex {
  const positions = new WeakMap<AnySchemaObject, readonly string[]>();
  const anchors = new Map<string, Map<string, AnySchemaObject>>();
  function visit(schema: AnySchema, parents: readonly string[], isRoot = false): void {
    if (typeof schema === "boolean") return;
    const parent = parents.at(-1)!;
    const id = !isRoot && typeof schema.$id === "string" && schema.$id !== ""
      ? normalizeId(resolveUrl(ajv.opts.uriResolver, parent, schema.$id)) : parent;
    const resources = id === parent ? parents : [...parents, id];
    positions.set(schema, resources);
    let resourceAnchors = anchors.get(id);
    if (resourceAnchors === undefined) anchors.set(id, resourceAnchors = new Map());
    if (typeof schema.$dynamicAnchor === "string") resourceAnchors.set(schema.$dynamicAnchor, schema);
    for (const [key, item] of Object.entries(schema)) {
      if (schemaMaps.has(key) && item !== null && typeof item === "object" && !Array.isArray(item)) {
        for (const child of Object.values(item)) visit(child as AnySchema, resources);
      } else if (schemaArrays.has(key) && Array.isArray(item)) {
        for (const child of item) visit(child as AnySchema, resources);
      } else if (schemaValues.has(key)) visit(item as AnySchema, resources);
    }
  }
  visit(root.schema, [normalizeId(root.baseId)], true);
  return { positions, anchors };
}

/**
 * Adapter for pinned Ajv 8.20. Resolve the initial dynamicRef target through its
 * ordinary URI/base-ID resolver, and keep resource scope local to each reference
 * branch. Reuse callRef for recursive validators and evaluated annotations.
 * Original schema bytes are never rewritten. Dialect meta-schemas retain Ajv's
 * existing keyword implementations.
 */
export function installLocalDynamicRef(ajv: Ajv2020): void {
  // Default imports of these CommonJS internals differ under native ESM/bundlers.
  const reference = ajv.getKeyword("$ref");
  if (typeof reference !== "object" || !("code" in reference)) throw new Error("Ajv ordinary-reference compiler is unavailable");
  const dynamicAnchors = new Name("dynamicAnchors");
  const errors = new Name("errors");
  const indices = new WeakMap<SchemaEnv, ResourceIndex>();

  function withResourceScope(cxt: KeywordCxt, compile: () => void): void {
    const { gen, it } = cxt;
    const { root } = it.schemaEnv;
    let index = indices.get(root);
    if (index === undefined) indices.set(root, index = indexResources(ajv, root));
    const positions = typeof it.schema === "boolean" ? undefined : index.positions.get(it.schema);
    const entry = typeof it.schemaEnv.schema === "boolean" ? undefined : index.positions.get(it.schemaEnv.schema);
    // Inline applicators may descend directly into a nested $id. Include those
    // resources in order, starting at this validator's resource; lexical parents
    // of a separately referenced validator are already supplied by its caller.
    const start = positions?.lastIndexOf(entry?.at(-1) ?? normalizeId(it.schemaEnv.baseId)) ?? -1;
    const active = positions?.slice(Math.max(0, start)) ?? [normalizeId(it.baseId)];
    const previous = gen.let("previousDynamicScope", dynamicAnchors);
    gen.assign(dynamicAnchors, _`Object.assign(Object.create(null), ${dynamicAnchors})`);
    for (const id of active) {
      for (const [anchor, schema] of index.anchors.get(id) ?? []) {
        const binding = _`${dynamicAnchors}${getProperty(anchor)}`;
        let validate;
        if (schema === it.schemaEnv.schema) validate = it.validateName;
        else {
          const target = resolveRef.call(it.self, root, id, `#${anchor}`);
          if (!(target instanceof SchemaEnv)) throw new Error(`dynamic anchor ${JSON.stringify(anchor)} must resolve to a validator`);
          validate = getValidate(cxt, target);
        }
        gen.if(_`!Object.prototype.hasOwnProperty.call(${dynamicAnchors}, ${anchor})`, () => gen.assign(binding, validate));
      }
    }
    // A failed anyOf/oneOf reference can return early. Finally also restores its
    // scope in that case, so no completed branch supplies sibling overrides.
    const previousErrors = gen.const("dynamicScopeErrors", errors);
    // callRef leaves its success branch open for subsequent keywords. Balance
    // that branch inside try, then re-establish its short-circuit guard outside.
    gen.try(() => gen.block(compile), undefined, () => gen.assign(dynamicAnchors, previous));
    cxt.ok(_`${errors} === ${previousErrors}`);
  }

  ajv.removeKeyword("$dynamicAnchor");
  ajv.addKeyword({
    keyword: "$dynamicAnchor", schemaType: "string",
    code(cxt) {
      if (cxt.it.schemaEnv.root.meta) dynamicAnchor(cxt, cxt.schema);
      // User-schema anchors are registered per resource, not by node visits.
    },
  });
  ajv.removeKeyword("$ref");
  ajv.addKeyword({
    ...reference,
    code(cxt) {
      if (cxt.it.schemaEnv.root.meta) return reference.code(cxt);
      withResourceScope(cxt, () => reference.code(cxt));
    },
  });
  ajv.removeKeyword("$dynamicRef");
  ajv.addKeyword({
    keyword: "$dynamicRef", schemaType: "string",
    code(cxt) {
      const { gen, it, schema: ref } = cxt;
      const { baseId, schemaEnv: { root }, self } = it;
      if (root.meta) return dynamicRef(cxt, ref);
      withResourceScope(cxt, () => {
        // Empty fragments and pointers have ordinary reference semantics even
        // when their target happens to declare a dynamicAnchor.
        if (ref === "#" && baseId === root.baseId) return reference.code(cxt);
        const target = resolveRef.call(self, root, baseId, ref);
        if (target === undefined) throw new Error(`can't resolve reference ${JSON.stringify(ref)} from id ${JSON.stringify(baseId)}`);
        const schema = target instanceof SchemaEnv ? target.schema : target;
        const fragment = decodeURIComponent(ref.slice(1));
        if (typeof schema === "boolean" || fragment === "" || fragment.startsWith("/") || schema.$dynamicAnchor !== fragment) return reference.code(cxt);
        if (!(target instanceof SchemaEnv)) throw new Error("dynamic anchor target must have a compiled validator");
        const validate = gen.let("dynamicRef", getValidate(cxt, target));
        const override = _`${dynamicAnchors}${getProperty(fragment)}`;
        gen.if(_`Object.prototype.hasOwnProperty.call(${dynamicAnchors}, ${fragment})`, () => gen.assign(validate, override));
        // A scope-selected validator can supply different evaluated annotations.
        callRef(cxt, validate, undefined, target.$async);
      });
    },
  });
}
