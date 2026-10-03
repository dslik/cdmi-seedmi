// The error conditions of the draft, reported as problem details documents
// (RFC 9457). A condition carries its HTTP status code, so the protocol
// binding maps a condition to a response without a second table, and the
// NFS server maps the same condition to an NFS4ERR value.

export const PROBLEM_BASE = "https://www.snia.org/cdmi/problems/";

/**
 * Where seedmi's own conditions are identified. Annex C reserves
 * https://www.snia.org/cdmi/ to the URIs the document defines: "a URI
 * that identifies a condition this document does not define shall not
 * begin with that prefix". seedmi controls no domain, so it uses the
 * .invalid top-level domain, which RFC 6761 guarantees is never
 * delegated and so cannot collide. Before 0.3 seedmi put conditions of
 * its own under the reserved prefix.
 */
export const SEEDMI_PROBLEM_BASE = "https://seedmi.invalid/problems/";

/** A problem details document, as recorded in a last_problems field. */
export interface Problem {
  type: string;
  title?: string;
  detail?: string;
  /** Extension members. A member the draft does not define may not begin "cdmi_". */
  [member: string]: unknown;
}

/**
 * A condition reported in response to an operation. The extension members
 * identify what the condition is about: cdmi_field a field of a
 * representation, cdmi_import an entry with cdmi_import_definition_uri the
 * object whose imports field holds it, cdmi_export an export entry.
 */
export class Condition extends Error {
  status: number;
  type: string;
  title: string;
  detail: string;
  members: Record<string, unknown>;
  /** Header fields the response carries with the problem, such as a challenge. */
  headers: Record<string, string> = {};

  constructor(status: number, type: string, title: string, detail: string) {
    super(detail || title);
    this.status = status;
    this.type = type ? PROBLEM_BASE + type : "about:blank";
    this.title = title;
    this.detail = detail;
    this.members = {};
  }

  /** Adds an extension member, returning this so calls can be chained. */
  with(member: string, value: unknown): this {
    if (value !== undefined) this.members[member] = value;
    return this;
  }

  /** Identifies the import entry at position index of the object at ns. */
  atImport(index: number, ns: string): this {
    return this.with("cdmi_import", String(index)).with("cdmi_import_definition_uri", ns);
  }

  /**
   * The URI of this occurrence: the effective request URI, which is
   * what identifies the occurrence to the client that made it. The
   * detail member explains the occurrence in words a client shall not
   * rely on; this member is the machine-readable counterpart.
   */
  instance?: string;

  /** Records the request this condition arose from. */
  at(instance: string | undefined): this {
    if (instance !== undefined) this.instance = instance;
    return this;
  }

  toProblem(): Problem {
    return {
      type: this.type,
      title: this.title,
      detail: this.detail,
      ...(this.instance === undefined ? {} : { instance: this.instance }),
      ...this.members,
    };
  }
}

export const isCondition = (err: unknown): err is Condition => err instanceof Condition;

/**
 * Substitutes the arguments into a detail message. One pass, so that a
 * message mixing the two kinds takes its arguments in the order written:
 * two passes would consume every %s before the first %j.
 */
const f = (s: string, ...a: unknown[]) =>
  s.replace(/%[sj]/g, (kind) => {
    const v = a.shift();
    return kind === "%j" ? JSON.stringify(v) : String(v);
  });

export const malformed = (detail: string, ...a: unknown[]) =>
  new Condition(400, "malformed-request", "The request is malformed.", f(detail, ...a));

/**
 * The cdmi_field member of a condition: "A JSON Pointer, as specified in RFC
 * 6901, identifying the field of a representation to which the condition
 * relates ... A field of the representation is identified as "/mimetype", and
 * a member of another field as "/metadata/cdmi_size"" (revision 211).
 *
 * This server names a field by its path within the representation, the
 * segments separated by a solidus, and this converts that to a pointer: a
 * leading solidus, and the escapes RFC 6901 defines for "~" and for a solidus
 * within a segment. A caller that already supplies a pointer is left alone.
 */
export function fieldPointer(field: string): string {
  if (field === "") return "";
  const segments = field.replace(/^\//, "").split("/");
  return segments.map((seg) => `/${seg.replace(/~/g, "~0")}`).join("");
}

export const invalidField = (field: string, detail: string, ...a: unknown[]) =>
  new Condition(400, "invalid-field", "A field is invalid.", f(detail, ...a))
    .with("cdmi_field", fieldPointer(field));

/**
 * A limit of the CDMI server would be exceeded (Annex C, Limit exceeded). The
 * extension members are those the annex gives: the limit, its value, and the
 * field to which it applies.
 */
export const limitExceeded = (field: string, detail: string, ...a: unknown[]) =>
  new Condition(413, "limit-exceeded", "A limit would be exceeded.", f(detail, ...a))
    .with("cdmi_field", fieldPointer(field));

export const conflictingFields = (field: string, detail: string, ...a: unknown[]) =>
  new Condition(400, "conflicting-fields", "Two fields conflict.", f(detail, ...a))
    .with("cdmi_field", fieldPointer(field));

export const invalidSelection = (selection: string, detail: string, ...a: unknown[]) =>
  new Condition(400, "invalid-selection", "A selection is invalid.", f(detail, ...a))
    .with("cdmi_selection", selection);

/**
 * The capability not present condition: "501 Not Implemented - The request was
 * well formed and the CDMI server does not implement what it requires, so the
 * fault is not in the request. A CDMI server shall include a Cache-Control
 * header field containing no-store in the response, because RFC 9110 permits a
 * response of this status code to be stored by a cache and a capability may be
 * present for an object later" (the binding's status table, revision 245).
 * seedmi answered 400 before 0.45.
 */
export function capabilityCondition(detail: string): Condition {
  const c = new Condition(501, "capability-not-present", "A capability is not present.", detail);
  c.headers["Cache-Control"] = "no-store";
  return c;
}

export const capabilityNotPresent = (capability: string, uri: string,
  detail: string, ...a: unknown[]) =>
  capabilityCondition(f(detail, ...a))
    .with("cdmi_capability", capability).with("cdmi_capability_uri", uri);

/**
 * The capability withheld condition (revision 269): "The capability required by
 * the operation is present and withheld, with the CDMI server supporting the
 * functionality and not offering it for the object or to the principal", which
 * the binding answers "403 Forbidden". A capability is withheld where it is
 * published as "false" or as an empty string, array or object; the capability
 * not present condition remains for one that is absent.
 */
export const capabilityWithheld = (capability: string, uri: string, detail: string, ...a: unknown[]) =>
  new Condition(403, "capability-withheld", "A capability is withheld.", f(detail, ...a))
    .with("cdmi_capability", capability).with("cdmi_capability_uri", uri);

/**
 * "The operation is not permitted for the object type": an operation the
 * draft defines for some object types and not for the one addressed, such as
 * a write to a capability object (weedmi CAPS-006).
 */
export const notPermittedForObjectType = (detail: string, allow: string, ...a: unknown[]): Condition => {
  const c = new Condition(405, "not-permitted-for-object-type",
    "The operation is not permitted for this object type.", f(detail, ...a));
  // "The response shall include an Allow header field listing the methods
  // that apply to the object addressed" (Table 8.8; weedmi BHTP-015).
  c.headers.Allow = allow;
  return c;
};

/**
 * "The name the export entry specifies is already in use by an export the
 * CDMI server serves." A CDMI export establishes a base URI, and "a CDMI
 * server shall serve only one CDMI export at a base URI, so that a base
 * URI names one root container object" (revision 327).
 */
/**
 * "An operation refused because an object is locked: the lock conflict
 * condition", and "a lock that cannot be applied because a lock held on an
 * object it would cover does not permit it: the lock conflict condition"
 * (revision 347). This server reported the general conflict condition for
 * the first and had neither of these before 0.79.
 */
export const lockConflict = (detail: string, ...a: unknown[]) =>
  new Condition(409, "lock-conflict", "A lock does not permit this.", f(detail, ...a));

/**
 * "A lock that cannot be applied because the principal is not permitted to
 * update the metadata of an object it would cover: the lock forbidden
 * condition."
 */
export const lockForbidden = (detail: string, ...a: unknown[]) =>
  new Condition(403, "lock-forbidden",
    "The principal may not lock what the lock would cover.", f(detail, ...a));

export const exportNameInUse = (detail: string, ...a: unknown[]) =>
  new Condition(409, "exports/name-in-use", "The name is already in use by an export.",
    f(detail, ...a));

/**
 * "The address at which the export is to be served is not available to the
 * CDMI server": an origin this server does not serve.
 */
export const exportAddressUnavailable = (detail: string, ...a: unknown[]) =>
  new Condition(409, "exports/address-unavailable",
    "The address of the export is not available.", f(detail, ...a));

export const forbidden = (detail: string, ...a: unknown[]) =>
  new Condition(403, "forbidden", "The operation is not permitted.", f(detail, ...a));

export const notFound = (what: string) =>
  new Condition(404, "not-found", "No object is addressed.", `no object is addressed by ${what}`);

export const conflict = (detail: string, ...a: unknown[]) =>
  new Condition(409, "conflict", "The operation conflicts with the state of the object.",
    f(detail, ...a));

/**
 * An operation refused by the retention or the hold metadata of an object.
 *
 * "Every refusal this subclause requires is reported with the conflict
 * condition ... and a CDMI server may report the more specific
 * .../problems/conflict/retention URI ... in place of it. A refusal this
 * subclause requires arises from the state of the object and not from the access
 * the principal holds ... A CDMI server shall not report the forbidden condition
 * for such a refusal, since that condition reports that the principal is not
 * permitted to perform the operation." This server reported the general
 * condition until 0.109, so a CDMI client could not tell a refusal by retention
 * from any other conflict without reading the detail.
 */
export const retentionConflict = (detail: string, ...a: unknown[]) =>
  new Condition(409, "conflict/retention",
    "Retention or hold does not permit this.", f(detail, ...a));

/** An operation denied by a layer above the write target. */
export const conflictImportLayer = (index: number, ns: string, detail: string, ...a: unknown[]) =>
  new Condition(409, "conflict/import-layer",
    "The object is held by a layer above the write target.", f(detail, ...a))
    .atImport(index, ns);

/** An operation that depends on an import whose entry is disabled. */
export const importDisabled = (index: number, ns: string, detail: string, ...a: unknown[]) =>
  new Condition(409, "conflict/import-disabled",
    "The operation depends on a disabled import.", f(detail, ...a))
    .atImport(index, ns);

/** An operation that depends on an import whose source cannot be reached. */
export const sourceUnavailable = (index: number, ns: string, detail: string, ...a: unknown[]) =>
  new Condition(503, "source-unavailable", "An import source is unavailable.", f(detail, ...a))
    .atImport(index, ns);

export const alreadyExists = (detail: string, ...a: unknown[]) =>
  // The already exists condition answers 409 where it is not the failure of a
  // precondition: "Where a snapshot of the supplied name already exists, 409
  // Conflict shall be returned", and a name taken by a deserialization.
  new Condition(409, "already-exists", "The object already exists.", f(detail, ...a));

/**
 * The already exists condition of a request made conditional on the absence
 * of the object: the binding answers it 412, "Returned where the request
 * contained an If-None-Match header field". This server answered 409 before
 * 0.44.
 */
export const alreadyExistsPrecondition = (detail: string, ...a: unknown[]) =>
  new Condition(412, "already-exists", "The object already exists.", f(detail, ...a));

export const notAcceptable = (detail: string, ...a: unknown[]) =>
  // The binding: 406 "does not correspond to a condition", so the type
  // is about:blank, as RFC 9457 provides for a status code alone.
  new Condition(406, "", "No acceptable representation is available.",
    f(detail, ...a));

export const serverError = (detail: string, ...a: unknown[]) =>
  new Condition(500, "server-error", "The CDMI server encountered an error.", f(detail, ...a));

/** A problem recorded in a last_problems field rather than returned. */
export function problem(type: string, title: string, detail: string,
  members: Record<string, unknown> = {}): Problem {
  return { type: PROBLEM_BASE + type, title, detail, ...members };
}

/** A condition seedmi reports that the document does not define. */
export function seedmiProblem(type: string, title: string, detail: string,
  members: Record<string, unknown> = {}): Problem {
  return { type: SEEDMI_PROBLEM_BASE + type, title, detail, ...members };
}

/** The time form of the draft: an ISO 8601 UTC date-time to microseconds. */
export function cdmiTime(ms: number = Date.now()): string {
  return new Date(ms).toISOString().replace("Z", "000Z");
}

/**
 * Credentials presented that this server does not accept: "the CDMI server
 * shall report the unauthenticated condition ... whether or not it requires
 * authentication for the request, and shall not perform the request as the
 * anonymous principal." A 401 carries a challenge (RFC 9110 11.6.1).
 */
export function unauthenticated(detail: string, schemes: string[] = ["Basic"]): Condition {
  const c = new Condition(401, "unauthenticated", "The credentials presented are not accepted.", detail);
  c.headers["WWW-Authenticate"] = schemes.map((s) => `${s} realm="seedmi"`).join(", ");
  return c;
}
