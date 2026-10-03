// Serialization: an object, and the objects it contains, as a sequence
// of bytes in the canonical format, and back again.
//
// The canonical format is the representation of the object with three
// additions: the value is contained within it, the children of a
// container object hold the complete representation of each child
// rather than its name, and the metadata the object inherits is
// written at the top level, so that what applied to the object where
// it was serialized still applies where it is deserialized.
//
// The point of the format is that a sequence of bytes produced by one
// CDMI server, transferred without alteration, produces equivalent
// objects at another. Everything here is therefore written against the
// document rather than against what this server happens to store: a
// field this server does not use is carried through untouched.

import { isDefinedField } from "./fields.ts";
import { reservedName, type Meta, type Node, type Store } from "./store.ts";
import { invalidField, malformed } from "./problems.ts";

export const MT_OBJECT = "application/cdmi-object";
export const MT_QUEUE = "application/cdmi-queue";
export const MT_DOMAIN = "application/cdmi-domain";
export const MT_CONTAINER = "application/cdmi-container";

/** One object in the canonical format. */
export interface Canonical {
  /**
   * The media type of the object. A reference carries none: it "shall be
   * represented in the canonical format as a JSON object holding an
   * objectName member ... and a reference member" and nothing else
   * (revision 327), a reference not being an object.
   */
  objectType?: string;
  /** The designators of the values a queue object carries. */
  queueValues?: string;
  objectName?: string;
  domainURI?: string;
  metadata?: Record<string, unknown>;
  // A queue object carries an array in each of the four, one entry per
  // value; a data object carries one of each.
  mimetype?: string | string[];
  valuetransferencoding?: string | string[];
  value?: unknown;
  valuerange?: string | string[];
  children?: Canonical[];
  childrenrange?: string;
  exports?: Record<string, unknown>;
  imports?: unknown[];
  rel?: Record<string, unknown>;
  /** Where the object is version-enabled, its versions oldest first. */
  versions?: Canonical[];
  [field: string]: unknown;
}

export interface SerializeContext {
  store: Store;
  /** The namespace path of the domain that owns an object. */
  domainURI: (node: Node) => string;
  /** Whether the principal may read an object, which every one must be. */
  mayRead: (node: Node) => boolean;
  /** The metadata an object inherits from the containers above it. */
  inherited: (node: Node) => Record<string, unknown>;
}

export class SerializeError extends Error {}

/**
 * Serializes an object and everything it contains. The metadata the
 * object inherits is written into the object at the top level alone,
 * which is what makes the serialization self-contained.
 */
export async function serialize(ctx: SerializeContext, node: Node,
  top = true): Promise<Canonical> {
  if (!ctx.mayRead(node)) {
    throw new SerializeError("the object to be serialized cannot be read");
  }
  const m = ctx.store.meta(node);
  const out: Canonical = {
    objectType: m.isDomain
      ? MT_DOMAIN
      : node.isContainer
      ? MT_CONTAINER
      : (m.isQueue ? MT_QUEUE : MT_OBJECT),
    objectName: m.name + (node.isContainer ? "/" : ""),
    domainURI: ctx.domainURI(node),
    completionStatus: "Complete",
    metadata: top
      ? { ...ctx.inherited(node), ...m.metadata }
      : { ...m.metadata },
  };
  // The exports field is preserved and is not applied on
  // deserialization; the imports field and the rel field are ordinary
  // fields of the object.
  if (m.exports !== undefined) out.exports = m.exports;
  if (m.imports !== undefined) out.imports = m.imports;
  if (m.rel !== undefined) out.rel = m.rel;
  // "preserve the field when the object is serialized, and restore it when the
  // object is deserialized" (Extension fields). Not written before 0.52.
  for (const [k, v] of Object.entries(m.extensions ?? {})) out[k] = v;
  // "A reference a container object contains shall be represented in the
  // canonical format as a JSON object holding an objectName member, the
  // name of the reference with its trailing "?", and a reference member,
  // the destination as stored and with its fragment component" (revision
  // 327). A reference is not an object and has no representation of its
  // own, so nothing else of one is written: this server wrote a whole data
  // object representation around it before 0.71.
  if (m.reference !== null && m.reference !== undefined) {
    return { objectName: `${m.name}?`, reference: m.reference };
  }

  // A name may denote more than one representation of one object, and a
  // serialization carries the object: the children of its container object
  // representation and the value of its data object representation travel
  // in one document, the schema admitting both. Serializing one
  // representation carried that one alone before 0.69, so the other was
  // lost in a move between CDMI servers (weedmi OPER-042, ECR-160B).
  const alongside = siblingsOf(ctx, node, m);
  const container = node.isContainer ? node : alongside.container;
  const data = node.isContainer ? alongside.data : (m.isQueue ? undefined : node);
  if (container !== undefined) {
    const kids = ctx.store.children(container).filter((c) => !reservedName(c.name));
    out.children = [];
    for (const child of kids) {
      out.children.push(await serialize(ctx, child.node, false));
    }
    out.childrenrange = kids.length === 0 ? "" : `0-${kids.length - 1}`;
  }
  if (node.isContainer) {
    // The object is addressed by its container object representation: its
    // value, where it has a data object representation, follows the
    // children in the same document.
    if (data !== undefined) {
      out.mimetype = ctx.store.meta(data).mimetype;
      await putValue(ctx, data, out);
    }
    return out;
  }

  if (m.isQueue) {
    // The values a queue object holds are contained within the
    // representation, as the value of a data object is. The four
    // arrays describe the same values and hold the same number of
    // entries, and the designators are not carried: they are unique
    // within a queue object, and a deserialization makes another.
    const values = ctx.store.queueValues(node);
    out.mimetype = values.map((v) => v.mimetype);
    out.valuetransferencoding = values.map((v) => v.vte);
    out.valuerange = values.map((v) =>
      v.body.length === 0 ? "" : `0-${v.body.length - 1}`);
    out.value = values.map((v) =>
      v.vte === "json"
        ? JSON.parse(v.body.toString("utf8"))
        : v.vte === "base64"
        ? v.body.toString("base64")
        : v.body.toString("utf8"));
    out.queueValues = values.length === 0
      ? ""
      : `${values[0].designator}-${values[values.length - 1].designator}`;
    return out;
  }

  out.mimetype = m.mimetype;
  await putValue(ctx, node, out);

  // A version-enabled data object is serialized together with its
  // versions, so that they are preserved when the object is moved
  // between CDMI servers. The value field of the object carries the
  // array; the versions are ordered from oldest to newest.
  const versions = ctx.store.versionsOf(node);
  if (versions.length > 0) {
    const serialized: Canonical[] = [];
    for (const v of versions) {
      const vm = ctx.store.meta(v);
      const one: Canonical = {
        objectType: MT_OBJECT,
        mimetype: vm.mimetype,
        metadata: { ...vm.metadata },
        completionStatus: "Complete",
      };
      await putValue(ctx, v, one);
      serialized.push(one);
    }
    // "place those serialized versions in a JSON array, ordered from oldest
    // to newest ... and replace the value field of that serialization with
    // the JSON array produced" (13.4.7). This server put the array in a
    // field named "versions", which the canonical format does not define,
    // so the versions were not carried between CDMI servers
    // (weedmi DMGT-009).
    out.value = serialized;
    out.valuetransferencoding = "json";
    out.valuerange = "";
  }
  return out;
}

/**
 * The other representations of the name this node is one of: a name denotes
 * one object, and a serialization carries every representation of it.
 */
function siblingsOf(ctx: SerializeContext, node: Node, m: { parent: number | null; name: string }):
  { data?: Node; container?: Node } {
  if (m.parent === null) return {};
  const parent = { id: m.parent, isContainer: true };
  const data = ctx.store.lookupKind(parent, m.name, "data");
  const container = ctx.store.lookupKind(parent, m.name, "container");
  return {
    data: data !== undefined && data.id !== node.id ? data : (node.isContainer ? undefined : node),
    container: container !== undefined && container.id !== node.id
      ? container
      : (node.isContainer ? node : undefined),
  };
}

/** Puts the value of a data object into its serialization. */
async function putValue(ctx: SerializeContext, node: Node,
  into: Canonical): Promise<void> {
  const data = await ctx.store.readValue(node);
  const utf8 = data.toString("utf8");
  // A value that is not a valid UTF-8 string is transported as base 64.
  const printable = Buffer.from(utf8, "utf8").equals(data);
  into.valuetransferencoding = printable ? "utf-8" : "base64";
  into.value = printable ? utf8 : data.toString("base64");
  into.valuerange = data.length === 0 ? "" : `0-${data.length - 1}`;
}

/**
 * Reads a canonical format and checks that it conforms far enough to
 * be applied. Where it does not, no object is created.
 */
export function parseCanonical(text: string): Canonical {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw malformed("the canonical format is not well formed JSON");
  }
  return checkCanonical(doc, "");
}

function checkCanonical(doc: unknown, at: string): Canonical {
  const where = at === "" ? "the canonical format" : at;
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    throw invalidField(at || "value", "%s shall be a JSON object", where);
  }
  const c = doc as Canonical;
  // "A deserialization creates the reference with that destination,
  // unchanged" (revision 327): a reference carries an objectName and a
  // reference member and no object type, being no object.
  if (c.objectType === undefined && typeof (c as { reference?: unknown }).reference === "string") {
    if (typeof c.objectName !== "string" || !c.objectName.endsWith("?")) {
      throw invalidField(`${at}/objectName`,
        "%s represents a reference, whose name carries a trailing \"?\"", where);
    }
    return c;
  }
  // A domain object is deserialized too, into the domain hierarchy
  // rather than into the namespace.
  if (c.objectType !== MT_OBJECT && c.objectType !== MT_CONTAINER &&
    c.objectType !== MT_QUEUE && c.objectType !== MT_DOMAIN) {
    throw invalidField(`${at}/objectType`,
      "%s reports the object type %j, which this CDMI server does not deserialize",
      where, String(c.objectType));
  }
  if (c.metadata !== undefined &&
    (c.metadata === null || typeof c.metadata !== "object" ||
      Array.isArray(c.metadata))) {
    throw invalidField(`${at}/metadata`, "the metadata field shall be a JSON object");
  }
  if (c.objectType === MT_QUEUE) {
    // The four arrays describe the same values and hold the same
    // number of entries.
    const arrays: [string, unknown][] = [
      ["mimetype", c.mimetype], ["valuetransferencoding", c.valuetransferencoding],
      ["valuerange", c.valuerange], ["value", c.value],
    ];
    const lengths = new Set<number>();
    for (const [field, v] of arrays) {
      if (v === undefined) continue;
      if (!Array.isArray(v)) {
        throw invalidField(`${at}/${field}`,
          "the %j field of a queue object in the canonical format is a JSON array",
          field);
      }
      lengths.add(v.length);
    }
    if (lengths.size > 1) {
      throw invalidField(`${at}/value`,
        "the arrays describing the values of a queue object hold the same number of " +
        "entries, and these hold %s",
        [...lengths].sort((a, b) => a - b).join(" and "));
    }
    return c;
  }
  if (c.objectType === MT_CONTAINER) {
    if (c.children !== undefined) {
      if (!Array.isArray(c.children)) {
        throw invalidField(`${at}/children`,
          "the children of a container object in the canonical format are the " +
          "representation of each child");
      }
      c.children.forEach((child, i) => checkCanonical(child, `${at}/children/${i}`));
    }
    return c;
  }
  if (c.versions !== undefined) {
    if (!Array.isArray(c.versions)) {
      throw invalidField(`${at}/versions`,
        "the versions of a version-enabled data object are a JSON array");
    }
    c.versions.forEach((v, i) => checkCanonical(v, `${at}/versions/${i}`));
  }
  return c;
}

/** The value a canonical format holds, decoded. */
export function valueOf(c: Canonical): Buffer {
  if (typeof c.value !== "string") return Buffer.alloc(0);
  return c.valuetransferencoding === "base64"
    ? Buffer.from(c.value, "base64")
    : Buffer.from(c.value, "utf8");
}

/** The name a child of the canonical format takes. */
export function nameOf(c: Canonical, at: string): string {
  const name = typeof c.objectName === "string" ? c.objectName : "";
  const trimmed = name.replace(/\/$/, "");
  if (trimmed === "" || trimmed.includes("/")) {
    throw invalidField(`${at}/objectName`,
      "a child of the canonical format takes its name from its objectName field, and " +
      "%j is not a name", name);
  }
  return trimmed;
}

/**
 * The fields of a canonical format that a CDMI server populates, and
 * which are therefore not applied when it is deserialized.
 */
export const NOT_APPLIED = [
  "objectID", "parentID", "parentURI", "capabilitiesURI", "objectType",
  "objectName", "children", "childrenrange", "value", "valuerange",
  "valuetransferencoding", "versions", "domainURI", "metadata", "mimetype",
  "completionStatus", "percentComplete", "exports",
];

/**
 * The extension fields of a canonical format: those whose names the draft does
 * not define, which "shall be stored with the object created" as fields of it
 * (the Serialization subclause). A name the draft defines for any
 * representation is not one, whatever the format holds (fields.ts).
 */
export function extensionFields(c: Canonical): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(c)) {
    if (NOT_APPLIED.includes(k) || isDefinedField(k)) continue;
    if (k === "imports" || k === "rel" || k === "reference" || k === "versions") continue;
    out[k] = v;
  }
  return out;
}

/** The storage system metadata a deserialization does not carry over. */
export function deserializableMetadata(m: Record<string, unknown> | undefined):
  Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(m ?? {})) {
    // The items the CDMI server generates are generated again for the
    // object created; the items a client sets are carried.
    if (k.startsWith("cdmi_") && !CARRIED.includes(k)) continue;
    out[k] = v;
  }
  return out;
}

const CARRIED = [
  "cdmi_acl", "cdmi_owner", "cdmi_group",
  // A CDMI server that deserializes an object shall place it under the
  // retention and hold the serialized form specifies.
  "cdmi_retention_id", "cdmi_retention_period", "cdmi_retention_autodelete",
  "cdmi_hold_id",
  "cdmi_versioning", "cdmi_versions_count", "cdmi_versions_age", "cdmi_versions_size",
  "cdmi_cors_origins", "cdmi_cors_methods", "cdmi_cors_headers",
  "cdmi_domain_enabled", "cdmi_authentication_methods",
];

export type { Meta };
