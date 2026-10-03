// The fields of a request body: which a client may supply for an object type,
// which are the CDMI server's to populate and are ignored, which the draft
// defines for another type or operation and are refused, and which are
// extension fields, stored with the object (Extension fields, revision 247).
//
// Before 0.52 every field this server did not read was ignored: an extension
// field was accepted and dropped, and a field of another object type (the
// draft's own example is "mimetype" in an update of a container object) was
// accepted without effect.

import { invalidField, malformed } from "./problems.ts";

export type ObjectKind = "data" | "container" | "queue" | "domain";

/** The fields of every representation of Clause 6 (the common fields). */
const COMMON = ["objectType", "objectID", "objectName", "parentID", "parentURI", "capabilitiesURI", "domainURI",
  "metadata", "completionStatus", "completionError", "percentComplete", "rel", "exports", "imports",
  "exportsProvided", "importsProvided"];

/** The fields of each representation: those of the common table and of the type's own. */
const REPRESENTATION: Record<ObjectKind, Set<string>> = {
  data: new Set([...COMMON, "mimetype", "value", "valuerange", "valuetransferencoding"]),
  container: new Set([...COMMON, "children", "childrenrange", "snapshots"]),
  queue: new Set([...COMMON, "mimetype", "queueValues", "value", "valuerange", "valuetransferencoding"]),
  // A domain object's representation holds the common fields and its children.
  domain: new Set([...COMMON, "children", "childrenrange"]),
};

/**
 * What a client may supply for each type, in a create or an update: the rows
 * of the create table (tbl_cdmi_create_fields) and the update table
 * (tbl_cdmi_update_fields), with the declarative request fields
 * (tbl_cdmi_operation_fields) each applies to.
 */
const SUPPLIABLE: Record<ObjectKind, Set<string>> = {
  data: new Set(["metadata", "domainURI", "exports", "imports", "rel", "mimetype", "valuetransferencoding", "value",
    "copy", "move", "reference", "deserialize", "deserializevalue", "serialize"]),
  container: new Set(["metadata", "domainURI", "exports", "imports", "rel", "snapshot",
    "copy", "move", "reference", "deserialize", "deserializevalue"]),
  queue: new Set(["metadata", "domainURI", "exports", "imports", "rel", "valuetransferencoding", "value",
    "copy", "move", "reference", "deserialize", "deserializevalue"]),
  // "All other than capability": metadata and rel, and the declarative fields
  // a domain object is created or replaced by.
  domain: new Set(["metadata", "rel", "copy", "move", "deserialize", "deserializevalue"]),
};

/** Every field name the draft defines for a representation or as a request field. */
const DEFINED = new Set([...REPRESENTATION.data, ...REPRESENTATION.container, ...REPRESENTATION.queue,
  ...SUPPLIABLE.data, ...SUPPLIABLE.container, ...SUPPLIABLE.queue, "capabilities"]);

const NOUN: Record<ObjectKind, string> = { data: "a data object", container: "a container object",
  queue: "a queue object", domain: "a domain object" };

/** Whether a value holds null at any depth. */
function holdsNull(v: unknown): boolean {
  if (v === null) return true;
  if (Array.isArray(v)) return v.some(holdsNull);
  if (typeof v === "object") return Object.values(v as Record<string, unknown>).some(holdsNull);
  return false;
}

/**
 * The extension fields of a request body for an object of the kind given, each
 * with the value supplied, null being a removal. Refuses what is not one:
 *
 * - "A field name that is defined in this clause, but that is not part of the
 *   representation of the object addressed by the request or is not permitted in
 *   the operation being performed, is not an extension field. A CDMI server shall
 *   report the invalid field condition";
 * - "An extension field name shall not begin with cdmi_, which is reserved";
 * - "The value of an extension field shall not contain null, at any depth", the
 *   malformed request condition being reported.
 *
 * A field of the type's representation that the client does not supply is the
 * server's to populate, and "A CDMI server shall ignore" it.
 */
export function extensionFields(body: Record<string, unknown>, kind: ObjectKind): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(body)) {
    if (SUPPLIABLE[kind].has(k) || REPRESENTATION[kind].has(k)) continue;
    if (DEFINED.has(k)) {
      throw invalidField(`/${k}`, "the %j field is not defined for %s in this operation", k, NOUN[kind]);
    }
    if (k.startsWith("cdmi_")) {
      throw invalidField(`/${k}`, "a field name beginning cdmi_ is reserved by the draft, and %j is not one it defines", k);
    }
    // A null at the top level removes the field; one within it cannot be stored.
    if (v !== null && holdsNull(v)) {
      throw malformed("the value of the extension field %j contains null, which an extension field's value shall not " +
        "contain at any depth", k);
    }
    out[k] = v;
  }
  return out;
}

/**
 * The extension fields an object holds after a create or update supplied some:
 * each supplied replaces the one held, "and shall not merge it with the stored
 * value", and null removes it. A complete replacement assigns them, removing
 * those not supplied.
 */
export function mergedExtensions(held: Record<string, unknown> | undefined, supplied: Record<string, unknown>,
  replace: boolean): Record<string, unknown> {
  const next: Record<string, unknown> = replace ? {} : { ...(held ?? {}) };
  for (const [k, v] of Object.entries(supplied)) {
    if (v === null) delete next[k];
    else next[k] = v;
  }
  return next;
}

/** Whether a name is one the draft defines, and so not an extension field whatever it holds. */
export function isDefinedField(name: string): boolean {
  return DEFINED.has(name) || name.startsWith("cdmi_");
}
