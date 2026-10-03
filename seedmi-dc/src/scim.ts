// SCIM 2.0: RFC 7644 for the protocol, RFC 7643 for the schema.
//
// Served under /scim/v2/ on the HTTPS listener that already serves /token and
// /jwks. The second front end of DESIGN-admin.md §2, and like the first it holds
// no rule of the realm: it translates a request into a call on the one write path
// and a refusal into a SCIM error. What it does hold is the mapping between a
// SCIM resource and a principal of this directory (§7), which is the interesting
// part — SCIM and LDAP disagree about enough that the mapping is where the work
// is, and `NOTES-on-scim.md` records what the specification left open.
//
// Authorization is a bearer token this controller issued, carrying "dc.read" to
// read and "dc.admin" to write, checked before a body is read or a name is
// looked up: a token for the wrong audience or without the scope learns nothing
// about what exists — and the audience is now actually checked, which it was not
// when that sentence was first written; see `allowed` at the end of this file.
//
// Not served: /Bulk, which /ServiceProviderConfig says plainly rather than
// leaving a client to discover by a 404.
//
// The "filter" parameter on a single resource *is* now refused, with
// invalidFilter. This comment used to say RFC 7644 section 3.4.2.2 "says a server
// MAY reject" it; that sentence is not in the document — the only rejection it
// mandates is section 3.4.2.1's "SHALL reject ... tooMany", about the size of a
// result set — and the code did not reject it either, so a client using a filter
// as a guard on `GET /Users/<id>` was handed the resource whatever the filter
// said. Section 3.4.2.1 lists "/Users/{id}" among the query endpoints, so a filter
// there is legitimate; what it would mean is a resource that either is or is not
// returned, and this server has no way to answer "it is there and does not match"
// other than 404, which a client would read as "it is not there". Refusing says
// which, and the client asks the collection instead.

import type { Directory } from "./dc-directory.ts";
import { SCOPES, type TokenService } from "./tokens.ts";
import { prepareScim } from "./prepare.ts";

/** The schema URNs of RFC 7643, and the extension of this controller (§7). */
export const SCHEMA = Object.freeze({
  user: "urn:ietf:params:scim:schemas:core:2.0:User",
  group: "urn:ietf:params:scim:schemas:core:2.0:Group",
  // The two of this server's own. RFC 7643 §10.2.1 declares the structure every
  // SCIM schema URI has: "The Namespace Specific String (NSS) of all URNs that use
  // the 'scim' Namespace ID shall have the following structure:
  // urn:ietf:params:scim:{type}:{name}{:other}", where `name` is "a required
  // US-ASCII string ... that defines a major namespace of a schema used within SCIM
  // (e.g., 'core', which is reserved for SCIM specifications). The value MAY also
  // be an industry name or organization name." So an organization's own schema goes
  // under the registered `scim` namespace with its own name in that position, and
  // these two were written `urn:seedmi:params:scim:…` — an unregistered namespace
  // identifier with SCIM's structure inside it, which is not a URN anyone may
  // register and which a client recognizing a SCIM schema by its prefix would not
  // classify as one at all.
  /** An organizational unit: a resource of this server's own, §5 having no SCIM one. */
  ou: "urn:ietf:params:scim:schemas:seedmi:2.0:Ou",
  /** The extension carried on a User and a Group. */
  extension: "urn:ietf:params:scim:schemas:extension:seedmi:2.0:Principal",
  listResponse: "urn:ietf:params:scim:api:messages:2.0:ListResponse",
  patchOp: "urn:ietf:params:scim:api:messages:2.0:PatchOp",
  error: "urn:ietf:params:scim:api:messages:2.0:Error",
  serviceProviderConfig: "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
  resourceType: "urn:ietf:params:scim:schemas:core:2.0:ResourceType",
  searchRequest: "urn:ietf:params:scim:api:messages:2.0:SearchRequest",
  /** The schema a Schema resource itself names (§7). */
  schema: "urn:ietf:params:scim:schemas:core:2.0:Schema",
});

/** The media type SCIM uses (RFC 7644 section 3.1). */
export const SCIM_TYPE = "application/scim+json";

/** The largest page a client may ask for, reported in /ServiceProviderConfig. */
export const MAX_RESULTS = 200;

/** A reply: what the caller writes to the response. */
export interface ScimReply {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
  /** What the log records, where there is anything worth recording. */
  log?: Record<string, unknown>;
}

/**
 * A refusal, carrying the scimType of RFC 7644 section 3.12. The type is what a
 * client acts on: "uniqueness" is retry with another name, "mutability" is stop,
 * "invalidFilter" is fix the filter.
 */
export class ScimError extends Error {
  readonly status: number;
  readonly scimType?: string;
  /**
   * The error code of RFC 6750 section 3.1 for the challenge, where a request
   * presented a token that was not accepted. A request that presented none
   * carries no code: "If the request lacks any authentication information ... the
   * resource server SHOULD NOT include an error code".
   */
  readonly bearerError?: string;
  constructor(status: number, message: string, scimType?: string, bearerError?: string) {
    super(message);
    this.status = status;
    this.scimType = scimType;
    this.bearerError = bearerError;
  }
}

const bad = (message: string, scimType = "invalidValue") => new ScimError(400, message, scimType);



/** The body of an error (RFC 7644 section 3.12). */
export function errorBody(e: ScimError): Record<string, unknown> {
  return {
    schemas: [SCHEMA.error],
    status: String(e.status),
    ...(e.scimType === undefined ? {} : { scimType: e.scimType }),
    detail: e.message,
  };
}

// ---------------------------------------------------------------------------
// Filters (RFC 7644 section 3.4.2.2)

/** An expression of the subset of the filter grammar this server evaluates. */
export type Filter =
  // "and" and "or" are two members rather than one with a union discriminant,
  // because narrowing a union member away by a disjunction of its discriminants
  // is not something the checker does.
  | { op: "and"; left: Filter; right: Filter }
  | { op: "or"; left: Filter; right: Filter }
  | { op: "not"; of: Filter }
  | { op: "pr"; path: string }
  | { op: "eq" | "ne" | "co" | "sw" | "ew" | "gt" | "ge" | "lt" | "le"; path: string; value: string | boolean };

/**
 * The attributes a filter may name, and how each is read from a resource. A
 * filter naming anything else is refused with "invalidFilter" rather than
 * matching nothing: a client whose filter quietly matched nothing would read an
 * empty list as "no such user" and create a second one.
 */
export type Fields = Record<string, (r: Record<string, unknown>) => string | boolean | undefined>;

/** Reads a filter. One pass, left to right, with parentheses. */
export function parseFilter(text: string, fields: Fields): Filter {
  let at = 0;
  const ws = () => { while (at < text.length && text[at] === " ") at++; };
  const word = (): string => {
    ws();
    const start = at;
    while (at < text.length && /[A-Za-z0-9._:\-]/.test(text[at])) at++;
    if (at === start) throw invalidFilter(text, `a name or an operator was expected at ${at}`);
    return text.slice(start, at);
  };
  const value = (): string | boolean => {
    ws();
    if (text[at] === '"') {
      // A JSON string, as the grammar says a comparison value is.
      let out = "";
      at++;
      while (at < text.length && text[at] !== '"') {
        if (text[at] === "\\") {
          at++;
          const c = text[at++];
          out += c === "n" ? "\n" : c === "t" ? "\t" : c;
          continue;
        }
        out += text[at++];
      }
      if (text[at] !== '"') throw invalidFilter(text, "a value begins with a quotation mark and ends with one");
      at++;
      return out;
    }
    const w = word();
    if (w === "true") return true;
    if (w === "false") return false;
    // A number or an unquoted word: compared as text, which is what every
    // attribute this server filters on holds.
    return w;
  };
  const primary = (): Filter => {
    ws();
    if (text[at] === "(") {
      at++;
      const inner = expression();
      ws();
      if (text[at] !== ")") throw invalidFilter(text, "a parenthesis is not closed");
      at++;
      return inner;
    }
    const first = word();
    if (first.toLowerCase() === "not") {
      ws();
      if (text[at] !== "(") throw invalidFilter(text, '"not" is followed by a parenthesized filter');
      return { op: "not", of: primary() };
    }
    const path = canonical(first, fields, text);
    const op = word().toLowerCase();
    if (op === "pr") return { op: "pr", path };
    if (!["eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"].includes(op)) {
      throw invalidFilter(text, `${op} is not an operator this server evaluates`);
    }
    return { op: op as "eq", path, value: value() };
  };
  const expression = (): Filter => {
    let left = primary();
    for (;;) {
      ws();
      const save = at;
      if (at >= text.length || text[at] === ")") return left;
      const op = word().toLowerCase();
      if (op !== "and" && op !== "or") {
        at = save;
        return left;
      }
      const right = primary();
      left = op === "and" ? { op: "and", left, right } : { op: "or", left, right };
    }
  };
  const out = expression();
  ws();
  if (at !== text.length) throw invalidFilter(text, `${JSON.stringify(text.slice(at))} was not expected`);
  return out;
}

const invalidFilter = (text: string, why: string) =>
  new ScimError(400, `the filter ${JSON.stringify(text)} is not one this server evaluates: ${why}`,
    "invalidFilter");

/** The attribute a path names, as this server spells it, or a refusal. */
function canonical(path: string, fields: Fields, text: string): string {
  const found = Object.keys(fields).find((k) => k.toLowerCase() === path.toLowerCase());
  if (found === undefined) {
    throw invalidFilter(text,
      `${path} is not an attribute this server filters on; those are ${Object.keys(fields).sort().join(", ")}`);
  }
  return found;
}

/**
 * The attributes whose values are compared **with** their case. RFC 7643 §7 of
 * `caseExact`: "A Boolean value that specifies whether or not a string attribute
 * is case sensitive. The server SHALL use case sensitivity when evaluating
 * filters." §3.1 gives both `id` and `externalId` `caseExact` as `true`, so both
 * belong here. While everything was folded to lower case, `id eq "ENG"` found the
 * unit `eng` and `id eq "2819C223-…"` found `2819c223-…`: false matches on the one
 * attribute the specification makes case-exact, which is exactly what a client
 * de-duplicating by identifier must not be told.
 *
 * `meta.lastModified` stays case-insensitive: it is a DateTime, and §2.3.5 says
 * "a date time format has no case sensitivity or uniqueness", so a client writing
 * `…t00:00:00z` is not wrong. It is compared as text rather than chronologically,
 * which NOTES-on-scim.md records.
 */
const CASE_EXACT = new Set(["id", "externalId"]);

/** Whether a resource matches a filter. */
export function matches(r: Record<string, unknown>, f: Filter, fields: Fields): boolean {
  if (f.op === "and") return matches(r, f.left, fields) && matches(r, f.right, fields);
  if (f.op === "or") return matches(r, f.left, fields) || matches(r, f.right, fields);
  if (f.op === "not") return !matches(r, f.of, fields);
  const held = fields[f.path](r);
  if (f.op === "pr") return held !== undefined && held !== "";
  if (held === undefined) return false;
  if (typeof held === "boolean" || typeof f.value === "boolean") {
    // "true" and "false" compare as themselves, and only eq and ne apply.
    const want = typeof f.value === "boolean" ? f.value : f.value === "true";
    if (f.op === "eq") return held === want;
    if (f.op === "ne") return held !== want;
    // RFC 7644 §3.4.2.2, Table 3, under each of gt, ge, lt and le: "Boolean and
    // Binary attributes SHALL cause a failed response (HTTP status code 400)
    // with 'scimType' of 'invalidFilter'." Returning no match instead, as this
    // did, tells a client "no active users" where the answer is "that filter
    // means nothing" — the failure this interface set out to avoid everywhere
    // else (NOTES-on-scim.md §10).
    throw new ScimError(400,
      `${f.path} is a boolean and ${f.op} does not apply to one; eq and ne do`, "invalidFilter");
  }
  // "Attribute names and attribute operators used in filters are case
  // insensitive ... the attribute value's case sensitivity is determined by
  // the attribute's ... caseExact".
  //
  // A case-insensitive comparison is not `toLowerCase`. RFC 7644 §7.8: "When comparing
  // Unicode strings such as those in query filters or testing for uniqueness of
  // usernames and passwords, strings MUST be appropriately prepared before comparison",
  // pointing at §5 and PRECIS. Nothing was prepared, so `displayName eq "café"` written
  // in Form D found nothing where the stored value was Form C, and U+00DF never folded
  // to "ss" — ten inputs that the LDAP front end matched and this one did not, against
  // one directory. `prepareScim` says what it does and does not do of PRECIS.
  //
  // A caseExact attribute is still **normalized**: §7.8's MUST is about comparison and
  // not about case, and two spellings of one character are one value whether or not the
  // comparison regards case. `id` and `externalId` are the caseExact ones and both are
  // in practice ASCII, so this changes nothing for them and is right in principle.
  const exact = CASE_EXACT.has(f.path);
  const a = exact ? held.normalize("NFC") : prepareScim(held);
  const b = exact ? f.value.normalize("NFC") : prepareScim(f.value);
  switch (f.op) {
    case "eq": return a === b;
    case "ne": return a !== b;
    case "co": return a.includes(b);
    case "sw": return a.startsWith(b);
    case "ew": return a.endsWith(b);
    case "gt": return a > b;
    case "ge": return a >= b;
    case "lt": return a < b;
    case "le": return a <= b;
  }
}

// ---------------------------------------------------------------------------
// The resources

/** A time as SCIM writes one: xsd:dateTime, which is what toISOString gives. */
const scimTime = (when: Date): string => when.toISOString();

/** What a session may do, from the scopes of its token. */
export interface Allowed {
  read: boolean;
  write: boolean;
  /** The subject of the token, for /Me. */
  subject?: string;
}

/**
 * The directory as SCIM resources. Reading is this half; writing is
 * dc-scim-writes.ts, which shares the mapping below.
 */
export class ScimRead {
  protected readonly directory: () => Directory;
  protected readonly domain: string;
  protected readonly domainSid: string;

  constructor(directory: () => Directory, domain: string, domainSid = "") {
    this.directory = directory;
    this.domain = domain;
    this.domainSid = domainSid;
  }

  /** A user as a SCIM resource. */
  user(name: string): Record<string, unknown> | undefined {
    const d = this.directory();
    const held = d.user(name);
    if (held === undefined) return undefined;
    const groups = d.groupsOf(held.name);
    const times = d.timesOf(held.name);
    return {
      schemas: [SCHEMA.user, SCHEMA.extension],
      id: d.idOf(held.name) ?? held.name,
      userName: held.name,
      // "A Boolean value indicating the User's administrative status": the
      // inverse of disabled, since SCIM says active and this directory says not.
      active: !held.disabled,
      ...(d.displayNameOf(held.name) === undefined ? {} : { displayName: d.displayNameOf(held.name) }),
      // Read-only: "the groups ... this attribute has a mutability of readOnly"
      // (RFC 7643 section 4.1.2), membership being written on the Group.
      ...(groups.length === 0 ? {} : {
        groups: groups.map((g) => ({
          value: d.idOf(g) ?? g,
          display: g,
          $ref: `/scim/v2/Groups/${d.idOf(g) ?? g}`,
          type: d.directGroupsOf(held.name).includes(g) ? "direct" : "indirect",
        })),
      }),
      [SCHEMA.extension]: this.extension(held.name, "user"),
      meta: this.meta("User", d.idOf(held.name) ?? held.name, times),
    };
  }

  /** A group as a SCIM resource. */
  group(name: string): Record<string, unknown> | undefined {
    const d = this.directory();
    const held = d.group(name);
    if (held === undefined) return undefined;
    const members = d.membersOf(held);
    const times = d.timesOf(held);
    return {
      schemas: [SCHEMA.group, SCHEMA.extension],
      id: d.idOf(held) ?? held,
      // **The realm's name, always.** NOTES-on-scim.md §2 records the decision this
      // interface is built on: "This server maps a Group's `displayName` onto the
      // realm's name, so a `PUT` or a `PATCH` of `displayName` is a rename", the
      // alternative having been rejected because every SCIM client displays
      // `displayName`. The write path does exactly that — `create` and `replace` take
      // the Group's `displayName` as the name — and this line did not: it reported the
      // *stored* display name where there was one, so the attribute a `PUT` renames by
      // was not the attribute a `GET` returned.
      //
      // The consequence was a **silent rename from a read-modify-write**. A client
      // that read a group with a stored display name of `allstaff` and put the body
      // back unchanged renamed the principal from `staff` to `allstaff` — its Kerberos
      // principal, the `cn` of its LDAP entry, and whatever an access control list
      // records. Where the stored display name was not a legal name ("All Staff"), the
      // same round trip was refused with 400 instead, so such a group could not be
      // updated over this interface at all. RFC 7644 §3.5.1 is written for precisely
      // this: the body of a PUT is the resource as the client read it.
      //
      // A group's own display name is a real field — the store holds it and LDAP
      // serves and writes it as `displayName` on the entry — and it has no SCIM core
      // attribute on a Group, so it is in the extension, where this server's own
      // attributes live.
      displayName: held,
      members: [
        ...members.users.map((u) => ({ value: d.idOf(u) ?? u, display: u, $ref: `/scim/v2/Users/${d.idOf(u) ?? u}`, type: "User" })),
        ...members.groups.map((g) => ({ value: d.idOf(g) ?? g, display: g, $ref: `/scim/v2/Groups/${d.idOf(g) ?? g}`, type: "Group" })),
      ],
      [SCHEMA.extension]: this.extension(held, "group"),
      meta: this.meta("Group", d.idOf(held) ?? held, times),
    };
  }

  /**
   * The path of the unit an identifier names. The identifier is the store's UUID
   * for the unit; a **path** is also accepted, because that is what this interface
   * used as the identifier before and a client may hold one. Which it was is not
   * ambiguous: a path cannot be a UUID, `NAME` admitting no hyphen in that shape.
   */
  unitPath(id: string): string | undefined {
    const d = this.directory();
    if (d.units().includes(id)) return id;
    return d.units().find((p) => d.unitId(p) === id);
  }

  /** An organizational unit as a resource of this server's own. */
  unit(id: string): Record<string, unknown> | undefined {
    const d = this.directory();
    const path = this.unitPath(id);
    if (path === undefined) return undefined;
    const parts = path.split("/");
    // The store's UUID for the unit. RFC 7643 §3.1 of `id`: "It MUST be a stable,
    // non-reassignable identifier that does not change when the same resource is
    // returned in subsequent requests." The path was the identifier, so a rename
    // moved it — a cached `/Ous/eng` 404'd afterwards and two listings either side
    // of a rename could not be correlated. NOTES-on-scim.md §3 recorded that as a
    // violation with the remedy named, and this is it. A unit of a directory held in
    // the configuration has no stored identifier, so its path is still its id;
    // nothing there can be renamed either, so nothing moves.
    const held = d.unitId(path) ?? path;
    return {
      schemas: [SCHEMA.ou],
      id: held,
      name: parts.at(-1),
      path,
      ...(parts.length === 1 ? {} : { parent: parts.slice(0, -1).join("/") }),
      ...(d.unitDescription(path) === undefined ? {} : { description: d.unitDescription(path) }),
      // The same meta as every other resource, times and version included. It
      // used to carry resourceType and location alone, which RFC 7643 §3.1
      // forbids — "the attributes 'id' and 'meta' (and its associated
      // sub-attributes) MUST be assigned values by the service provider" — and
      // which left a client no lastModified to synchronize by and no version for
      // If-Match to compare. The store had no times for a unit to give; it does
      // now (schema 3).
      meta: {
        ...this.meta("Ou", encodeURIComponent(held), d.unitTimes(path)),
        location: `/scim/v2/Ous/${encodeURIComponent(held)}`,
      },
    };
  }

  /** The extension both a User and a Group carry (§7). */
  private extension(name: string, kind: "user" | "group"): Record<string, unknown> {
    const d = this.directory();
    const posix = d.posixOf(name);
    const unit = d.unitOf(name);
    return {
      name,
      // A group's own display name, which has no SCIM core attribute on a Group:
      // there, `displayName` is the realm's name (§2 of NOTES-on-scim.md). A user's
      // display name is the core `displayName`, as RFC 7643 §4.1.1 intends, and is
      // not repeated here.
      ...(kind === "group" && d.displayNameOf(name) !== undefined
        ? { displayName: d.displayNameOf(name) } : {}),
      // **Which groups a group belongs to.** RFC 7643 §4.1.2 gives `groups` to the
      // User and there is no such attribute on a Group, so this is the extension's,
      // read-only, in the same shape as a User's `groups` so that a client already
      // handling one handles this. LDAP serves it as `memberOf` on the group entry;
      // over SCIM it was **unobtainable** — not on the resource, and not by filter
      // either, `members.value` not being one this server filters on, so a client
      // resolving nested groups over SCIM could not do it at all while the same
      // directory told an LDAP client plainly. Found by the read-side conformance
      // test, which compares what the two front ends say about one store.
      //
      // Direct parents, which is what LDAP serves here too: a group names the groups
      // it is in and a client follows them. A *user's* `groups` is the transitive set
      // with each entry marked direct or indirect, which is the asymmetry
      // NOTES-on-scim.md §2a records rather than smooths over.
      ...(kind === "group" && d.parentsOf(name).length > 0
        ? { groups: d.parentsOf(name).map((g) => ({
          value: d.idOf(g) ?? g, display: g, $ref: `/scim/v2/Groups/${d.idOf(g) ?? g}`,
          type: "direct",
        })) } : {}),
      ...(unit === undefined ? {} : { ou: unit }),
      ...(posix === undefined ? {} : (kind === "user" ? { uidNumber: posix } : { gidNumber: posix })),
      // A user's gidNumber is its primary group's number, which RFC 2307's
      // `posixAccount` MUSTs; `primaryGroup` names the group, because the number is
      // the group's and follows it. A group's own gidNumber is the line above.
      ...(kind === "user" && d.primaryGroupOf(name) !== undefined
        ? { primaryGroup: d.primaryGroupOf(name), gidNumber: d.primaryGidOf(name) } : {}),
      ...(this.domainSid === "" ? {} : { objectSid: `${this.domainSid}-${d.ridOf(name)}` }),
      ...(kind === "user" && d.homeOf(name) !== undefined ? { home: d.homeOf(name) } : {}),
      // When the account expires, which SCIM has no core attribute for: a
      // principal can be unusable here in two ways, and "active" reports one.
      // NOTES-on-scim.md section 6 says what a client reading "active" alone misses.
      ...(kind === "user" && d.expiresOf(name) !== undefined
        ? { expires: d.expiresOf(name)!.toISOString() } : {}),
      // The public material of the credentials, which is all there is to report:
      // a certificate is held as its fingerprint and an S3 key as its identifier,
      // the secrets being at the key management server.
      ...(kind === "user" ? this.credentials(name) : {}),
    };
  }

  /** The credentials of a user, as public material (§7). */
  private credentials(name: string): Record<string, unknown> {
    const held = this.directory().credentialsOf(name);
    return {
      ...(held.certificates.length === 0 ? {} : {
        certificates: held.certificates.map((c) => ({
          value: c.fingerprint,
          ...(c.subject === undefined ? {} : { display: c.subject }),
          // The certificate itself, base 64 of its DER, where the store has it —
          // which is where a client wrote it as a `userCertificate` rather than
          // naming a fingerprint. RFC 7643 §2.3.6 of the binary type: "Binary ...
          // attribute values ... MUST be base64 encoded."
          ...(c.certificate === undefined ? {} : { certificate: c.certificate }),
          ...(c.created === undefined ? {} : { created: c.created.toISOString() }),
        })),
      }),
      ...(held.s3Keys.length === 0 ? {} : {
        // The secret is not here and never will be: it is returned once, when the
        // key pair is created, and this is the identifier that names it.
        s3Keys: held.s3Keys.map((k) => ({
          value: k.accessKeyId,
          ...(k.created === undefined ? {} : { created: k.created.toISOString() }),
        })),
      }),
    };
  }

  /** The meta of a resource (RFC 7643 section 3.1). */
  private meta(type: string, id: string, times: { created?: Date; modified?: Date }): Record<string, unknown> {
    return {
      resourceType: type,
      ...(times.created === undefined ? {} : { created: scimTime(times.created) }),
      ...(times.modified === undefined ? {} : { lastModified: scimTime(times.modified) }),
      location: `/scim/v2/${type}s/${id}`,
      // The ETag of §7. A store records a version per principal; where none is
      // recorded the resource has no version and If-Match on it is refused,
      // which is better than an ETag that does not change.
      ...(times.modified === undefined ? {} : { version: etagOf(times.modified) }),
    };
  }

  /** The principal an identifier names: the store's id, or the name itself. */
  nameOf(id: string, kind: "user" | "group"): string | undefined {
    const d = this.directory();
    const names = kind === "user" ? d.userNames() : d.groupList();
    const byId = names.find((n) => d.idOf(n) === id);
    if (byId !== undefined) return byId;
    // A client that holds a name rather than an identifier is served, since a
    // directory with no store has no identifier to hold.
    const direct = kind === "user" ? d.user(id)?.name : d.group(id);
    return direct;
  }

  /** Every user as a resource, for a list. */
  users(): Record<string, unknown>[] {
    return this.directory().userNames().map((n) => this.user(n)!);
  }

  /** Every group as a resource. */
  groups(): Record<string, unknown>[] {
    return this.directory().groupList().map((n) => this.group(n)!);
  }

  /** Every unit as a resource. */
  units(): Record<string, unknown>[] {
    return this.directory().units().map((p) => this.unit(p)!);
  }
}

/**
 * The ETag a version becomes. Weak, because two representations of one resource
 * can differ in the attributes a request asked for while the resource itself has
 * not changed: "the ETag ... MAY be weak" (RFC 7644 section 3.14).
 */
export const etagOf = (modified: Date): string => `W/"${modified.getTime().toString(36)}"`;

/** The fields a User may be filtered on (§7). */
export const USER_FIELDS: Fields = {
  userName: (r) => r.userName as string,
  displayName: (r) => r.displayName as string | undefined,
  active: (r) => r.active as boolean,
  externalId: (r) => r.externalId as string | undefined,
  id: (r) => r.id as string,
  "meta.lastModified": (r) => (r.meta as Record<string, string>).lastModified,
  [`${SCHEMA.extension}:ou`]: (r) => (r[SCHEMA.extension] as Record<string, string>)?.ou,
};

/** The fields a Group may be filtered on. */
export const GROUP_FIELDS: Fields = {
  displayName: (r) => r.displayName as string,
  externalId: (r) => r.externalId as string | undefined,
  id: (r) => r.id as string,
  "meta.lastModified": (r) => (r.meta as Record<string, string>).lastModified,
  [`${SCHEMA.extension}:ou`]: (r) => (r[SCHEMA.extension] as Record<string, string>)?.ou,
};

/** The fields an Ou may be filtered on. */
export const OU_FIELDS: Fields = {
  name: (r) => r.name as string,
  path: (r) => r.path as string,
  parent: (r) => r.parent as string | undefined,
  id: (r) => r.id as string,
};

// ---------------------------------------------------------------------------
// Pagination, and the attributes a client asked for

/** A page of a list, as RFC 7644 section 3.4.2.4 numbers one: from 1. */
export function page(all: Record<string, unknown>[], params: URLSearchParams): Record<string, unknown> {
  const whole = (name: string, fallback: number): number => {
    const raw = params.get(name);
    if (raw === null || raw === "") return fallback;
    const n = Number(raw);
    if (!Number.isInteger(n)) throw bad(`${name} is a whole number`, "invalidValue");
    return n;
  };
  // "A value less than 1 SHALL be interpreted as 1"; "a negative value SHALL be
  // interpreted as 0", and a count of 0 returns no resources and the total.
  const startIndex = Math.max(1, whole("startIndex", 1));
  const asked = whole("count", MAX_RESULTS);
  const count = Math.min(Math.max(0, asked), MAX_RESULTS);
  const slice = all.slice(startIndex - 1, startIndex - 1 + count);
  return {
    schemas: [SCHEMA.listResponse],
    totalResults: all.length,
    itemsPerPage: slice.length,
    startIndex,
    Resources: slice,
  };
}

/**
 * A resource with the attributes a request asked for: "attributes" keeps the ones
 * named and the always-returned ones, "excludedAttributes" drops the ones named
 * (RFC 7644 section 3.9).
 *
 * **Only `id` and `schemas` are always returned.** RFC 7644 §3.4.2.5: "This
 * parameter SHALL have no effect on attributes whose schema 'returned' setting is
 * 'always'", and RFC 7643 §3.1 gives that characteristic to `id` alone — of `meta`
 * it says "all of these sub-attributes have a 'returned' characteristic of
 * 'default'", and of `externalId` it states no `returned` at all, so §2.2's default
 * applies. `schemas` is kept because §3 of RFC 7643 makes it REQUIRED in every
 * representation, so dropping it would leave a body no SCIM client can classify.
 *
 * `meta` and `externalId` were in this set, with a comment saying the returned
 * characteristic of each put them there. It does not: `?excludedAttributes=meta`
 * returned `meta` anyway, so a client trimming a large synchronization got no
 * reduction and no way to tell the parameter had been ignored. The RFC's own
 * example in §3.9 returns `schemas`, `id` and `userName` and nothing else.
 */
export function project(r: Record<string, unknown>, params: URLSearchParams): Record<string, unknown> {
  const list = (name: string) => (params.get(name) ?? "").split(",").map((s) => s.trim()).filter((s) => s !== "");
  const wanted = list("attributes"), excluded = list("excludedAttributes");
  if (wanted.length > 0 && excluded.length > 0) {
    throw bad("attributes and excludedAttributes are not both given", "invalidValue");
  }
  if (wanted.length === 0 && excluded.length === 0) return r;
  const always = new Set(["id", "schemas"]);
  const keep = (k: string): boolean => {
    if (always.has(k)) return true;
    // A sub-attribute names its parent, so naming one keeps the parent. Both
    // separators count: "name.familyName" within a schema, and the colon of
    // RFC 7644 §3.10's fully qualified form, by which an extension's attribute is
    // "urn:…:Principal:ou". Only the dot was recognized, so naming an extension's
    // attribute dropped the whole extension — the opposite of what was asked.
    const named = (l: string[]) => l.some((a) => {
      const want = a.toLowerCase(), key = k.toLowerCase();
      return want === key || want.startsWith(`${key}.`) || want.startsWith(`${key}:`);
    });
    return wanted.length > 0 ? named(wanted) : !named(excluded);
  };
  const out = Object.fromEntries(Object.entries(r).filter(([k]) => keep(k)));
  // The `schemas` attribute is kept, but its value describes what is left: RFC 7643
  // §3 says it holds "value(s) of the URIs supported by that representation", and a
  // representation from which the extension's attributes have been projected away
  // no longer supports the extension's schema. Leaving the URI there told a client
  // to look for an object that is not in the body. This is a reading rather than a
  // rule the specification spells out; NOTES-on-scim.md §11 says so.
  if (Array.isArray(out.schemas)) {
    const base = out.schemas[0];
    out.schemas = (out.schemas as string[]).filter((u) => u === base || out[u] !== undefined);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Discovery

/** /ServiceProviderConfig (RFC 7643 section 5). */
export function serviceProviderConfig(write: boolean): Record<string, unknown> {
  return {
    schemas: [SCHEMA.serviceProviderConfig],
    documentationUri: "https://github.com/seedmi/seedmi-dc#scim",
    patch: { supported: true },
    // Said plainly rather than left to a 404, as §7 asks.
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: MAX_RESULTS },
    changePassword: { supported: write },
    sort: { supported: false },
    etag: { supported: true },
    authenticationSchemes: [{
      type: "oauthbearertoken",
      name: "OAuth Bearer Token",
      description: "A bearer token this controller issued, carrying dc.read to read or dc.admin to write",
      specUri: "https://www.rfc-editor.org/info/rfc6750",
    }],
    meta: { resourceType: "ServiceProviderConfig", location: "/scim/v2/ServiceProviderConfig" },
  };
}

/** /ResourceTypes (RFC 7643 section 6). */
export function resourceTypes(): Record<string, unknown>[] {
  const one = (name: string, schema: string, extension = true) => ({
    schemas: [SCHEMA.resourceType],
    id: name,
    name,
    endpoint: `/${name}s`,
    description: `A ${name} of this realm`,
    schema,
    ...(extension ? {
      schemaExtensions: [{ schema: SCHEMA.extension, required: false }],
    } : {}),
    meta: { resourceType: "ResourceType", location: `/scim/v2/ResourceTypes/${name}` },
  });
  return [
    one("User", SCHEMA.user),
    one("Group", SCHEMA.group),
    // The resource §5 gives this server for a container SCIM does not define. It
    // is listed here so that a client discovers it rather than guessing.
    one("Ou", SCHEMA.ou, false),
  ];
}

/**
 * /Schemas: the attributes of each resource, so a client discovers them rather
 * than reading a README (RFC 7643 §7).
 *
 * Three things the first version of this got wrong, all found by reading §7
 * against what the endpoint returned:
 *
 *  * **`description` was absent.** "The attribute's human-readable description.
 *    When applicable, service providers MUST specify the description", and §7 adds
 *    that in a Schema resource "all attributes are REQUIRED unless otherwise
 *    specified". Every attribute now carries one.
 *  * **`subAttributes` was absent from every complex attribute.** "When an
 *    attribute is of type 'complex', there SHOULD be a corresponding schema
 *    attribute 'subAttributes' defined, listing the sub-attributes of the
 *    attribute." A client reading this to build a `POST /Groups` body learned only
 *    that `members` was a complex array, sent whatever shape it guessed, and was
 *    refused for missing the one sub-attribute — `value` — that the schema never
 *    mentioned.
 *  * **`meta` carried a `name` sub-attribute**, which §3.1 does not define: it
 *    lists resourceType, created, lastModified, location and version and no other.
 *    Each schema already has a top-level `name`, which is where it belongs.
 *
 * `caseExact` and `uniqueness` are left off the types that do not have them: "a
 * complex attribute has no uniqueness or case sensitivity" (§2.3.8), and §§2.3.2
 * and 2.3.5 say the same of a boolean and of a date time. The examples of §8.7.1
 * omit them there too.
 */
export function schemas(): Record<string, unknown>[] {
  /** The sub-attributes a multi-valued reference carries (§2.4, §4.1, §4.2). */
  const reference = (what: string, canonical?: string[]) => [
    attr("value", "string", { description: `The identifier of the ${what}.` }),
    attr("$ref", "reference", { description: `The URI of the ${what}.`,
      referenceTypes: ["User", "Group"] }),
    attr("display", "string", { description: `A human-readable name for the ${what}.`,
      mutability: "readOnly" }),
    ...(canonical === undefined ? [] : [attr("type", "string", {
      description: `What kind of ${what} this is.`, canonicalValues: canonical })]),
  ];
  return [
    {
      schemas: [SCHEMA.schema],
      id: SCHEMA.user, name: "User", description: "A principal of this realm",
      attributes: [
        attr("userName", "string", { required: true, uniqueness: "server",
          description: "The name of the principal, which is its Kerberos principal name and " +
            "is unique across the users and groups of this realm, whatever its case." }),
        attr("displayName", "string",
          { description: "The name of the principal as it is shown to a person." }),
        attr("active", "boolean",
          { description: "Whether the principal may authenticate. A disabled principal is " +
            "refused a bind, a token and a ticket." }),
        attr("password", "string", { mutability: "writeOnly", returned: "never",
          description: "A password to set. It is never returned: what is kept is a scrypt " +
            "verifier and a Kerberos key for each enctype of the realm." }),
        attr("groups", "complex", { multiValued: true, mutability: "readOnly",
          description: "The groups the principal belongs to, transitively. Read-only: a " +
            "membership is changed on the group, through its members attribute.",
          subAttributes: reference("group this principal belongs to", ["direct", "indirect"]) }),
      ],
      meta: meta(SCHEMA.user),
    },
    {
      schemas: [SCHEMA.schema],
      id: SCHEMA.group, name: "Group", description: "A group of this realm",
      attributes: [
        attr("displayName", "string", { required: true, uniqueness: "server",
          description: "The name of the group, which this realm takes as its name: it is " +
            "unique across the users and groups of the realm, whatever its case." }),
        attr("members", "complex", { multiValued: true,
          description: "The members of the group, each named by the value sub-attribute: a " +
            "user or another group, so groups nest.",
          subAttributes: reference("member", ["User", "Group"]) }),
      ],
      meta: meta(SCHEMA.group),
    },
    {
      schemas: [SCHEMA.schema],
      id: SCHEMA.ou, name: "Ou", description: "An organizational unit of this realm",
      attributes: [
        attr("name", "string", { required: true,
          description: "The name of the unit within its parent, unique among its siblings." }),
        attr("path", "string", { mutability: "readOnly",
          description: "The unit's place in the tree, as eng/platform. It is also the id." }),
        attr("parent", "string",
          { description: "The path of the unit this one is in, absent for a unit at the top." }),
        attr("description", "string",
          { description: "What the unit is for. Served over LDAP as the description attribute." }),
      ],
      meta: meta(SCHEMA.ou),
    },
    {
      schemas: [SCHEMA.schema],
      id: SCHEMA.extension, name: "Principal",
      description: "What this directory holds that RFC 7643 has no attribute for",
      attributes: [
        attr("name", "string", { mutability: "readOnly",
          description: "The principal's name, which is its userName or displayName." }),
        attr("displayName", "string",
          { description: "A group's own human-readable label, which the core displayName of " +
            "a Group cannot hold: there, displayName is the realm's name, so writing it " +
            "renames the group. Absent on a User, whose core displayName is this." }),
        attr("groups", "complex", { multiValued: true, mutability: "readOnly",
          description: "The groups a group belongs to, directly. RFC 7643 gives no such " +
            "attribute to a Group; a User's core groups attribute is the transitive set. " +
            "Membership is written on the containing Group's members.",
          subAttributes: [
            attr("value", "string", { mutability: "readOnly",
              description: "The id of the containing group." }),
            attr("display", "string", { mutability: "readOnly",
              description: "Its name in this realm." }),
            attr("$ref", "reference", { mutability: "readOnly",
              description: "The URI of the containing group." }),
            attr("type", "string", { mutability: "readOnly",
              description: "Always direct here: a group names the groups it is in." }),
          ] }),
        attr("ou", "string",
          { description: "The path of the organizational unit the principal is in." }),
        attr("uidNumber", "integer", { mutability: "readOnly",
          description: "The POSIX user number, allocated by this server, by which an NFS " +
            "server resolves a sys identity." }),
        attr("gidNumber", "integer", { mutability: "readOnly",
          description: "A group's own POSIX number, allocated by this server; on a user, the " +
            "number of its primary group, which follows that group." }),
        attr("primaryGroup", "string",
          { description: "The group whose POSIX number is this user's gidNumber. Without one a " +
            "user bears no posixAccount over LDAP, that class requiring a gidNumber." }),
        attr("objectSid", "string", { mutability: "readOnly",
          description: "The security identifier, in its text form, by which a CDMI server " +
            "maps the identifiers of a ticket's privilege attribute certificate to names." }),
        attr("home", "string",
          { description: "The home directory of the principal on a UNIX deployment." }),
        attr("expires", "dateTime",
          { description: "When the principal stops being able to authenticate." }),
        attr("certificates", "complex", { multiValued: true,
          description: "The client certificates the principal may authenticate with, each " +
            "held as a SHA-256 fingerprint and, where it was given, as the certificate itself.",
          subAttributes: [
            attr("value", "string", { description: "The SHA-256 fingerprint, as sha256:<hex>. " +
              "A client may write either this or the certificate itself in certificate; where " +
              "both are written they must agree." }),
            attr("display", "string",
              { description: "The subject of the certificate, as it was given." }),
            attr("certificate", "binary",
              { description: "The certificate itself: base 64 of its DER, which is what RFC " +
                "4523 defines as a value of the Certificate syntax. Absent where only a " +
                "fingerprint was given, in which case the certificate cannot be read back." }),
          ] }),
        attr("s3Keys", "complex", { multiValued: true, mutability: "readOnly",
          description: "The S3 access keys of the principal. Read-only here: a key pair is " +
            "created at /Users/<id>/s3Keys, whose answer carries the secret once.",
          subAttributes: [
            attr("value", "string",
              { description: "The access key identifier. The secret is never returned here." }),
            attr("display", "string", { description: "What the key was created for." }),
          ] }),
      ],
      meta: meta(SCHEMA.extension),
    },
  ];
}

/**
 * One attribute of a published schema (RFC 7643 §7). The characteristics a type
 * does not have are left off rather than asserted: §2.3.8 of a complex attribute,
 * §2.3.2 of a boolean and §2.3.5 of a date time each say it has "no case
 * sensitivity or uniqueness".
 */
function attr(name: string, type = "string", opts: Record<string, unknown> = {}):
  Record<string, unknown> {
  const stringly = type === "string" || type === "reference";
  return {
    name, type, multiValued: false, required: false,
    // "A binary is case exact and has no uniqueness" (§2.3.6), so it carries
    // caseExact and not uniqueness — the one type where the two part company.
    ...(stringly ? { caseExact: false } : type === "binary" ? { caseExact: true } : {}),
    mutability: "readWrite", returned: "default",
    ...(stringly || type === "integer" ? { uniqueness: "none" } : {}),
    ...opts,
  };
}

/** The meta of a Schema resource. §3.1 defines no `name` sub-attribute. */
const meta = (id: string) =>
  ({ resourceType: "Schema", location: `/scim/v2/Schemas/${id}` });

// ---------------------------------------------------------------------------
// Authorization

/**
 * What a request may do. The token is this controller's own, verified by the
 * service that issued it, **and issued for this interface**.
 *
 * This comment used to read: "the audience is not checked here because a token is
 * issued for an audience the client named and this interface is reached at the
 * controller's own address, which is that audience." The premise is false. A
 * `[[client]]` names whatever audiences a deployment gives it, with no relation to
 * this controller's address — the example configuration's own CDMI client names
 * `https://127.0.0.1:8443/cdmi/3.0.0/` — so "the audience the client named" is
 * routinely some other service. Nothing checked `aud`, and a `dc.admin` token
 * issued to a storage node for its own audience created a user through this
 * interface; that was run against a live controller, not argued about. RFC 8725
 * §3.9 makes the check a MUST, and the file header's claim that "a token for the
 * wrong audience ... learns nothing about what exists" was simply untrue.
 *
 * The audience required is `TokenService.scimAudience`, derived from the issuer.
 * A token that does not name it is `invalid_token`, like any other token this
 * interface will not accept: which of the reasons applied is the log's business,
 * not a client's.
 */
export function allowed(authorization: string | undefined, tokens: TokenService | undefined,
  now = Date.now()): Allowed {
  if (tokens === undefined) {
    throw new ScimError(503,
      "this controller runs no token service, so no token can be verified: configure [tokens]");
  }
  const m = /^Bearer\s+(\S+)$/i.exec(authorization ?? "");
  if (m === null) {
    // "If the request lacks any authentication information ... the resource
    // server SHOULD NOT include an error code or other error information" (RFC
    // 6750 section 3.1): a client that sent no token is told what to send, and
    // not that what it sent was invalid.
    throw new ScimError(401, "a bearer token this controller issued is given");
  }
  const claims = tokens.verify(m[1], now, tokens.scimAudience);
  if (claims === undefined) {
    throw new ScimError(401,
      `the token is not one this controller issued for ${tokens.scimAudience}, or has expired`,
      undefined, "invalid_token");
  }
  const scopes = (claims.scope as string | undefined)?.split(/\s+/).filter((s) => s !== "") ?? [];
  const write = scopes.includes(SCOPES.admin);
  const read = write || scopes.includes(SCOPES.read);
  if (!read) {
    // "insufficient_scope: The request requires higher privileges than provided
    // by the access token" (RFC 6750 section 3.1).
    throw new ScimError(403,
      `the token carries no scope of this interface; ${SCOPES.read} reads and ${SCOPES.admin} writes`,
      undefined, "insufficient_scope");
  }
  return { read, write, ...(typeof claims.sub === "string" ? { subject: claims.sub } : {}) };
}
