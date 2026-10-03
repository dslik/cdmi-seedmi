// SCIM's requests, routed and answered.
//
// scim.ts holds the mapping and the reading; this module is the protocol: the
// methods, the paths, the conditional requests, and the writes translated into
// calls on the one write path (DESIGN-admin.md §2). It is the SCIM counterpart of
// dc-ldap-writes.ts, and the two deliberately share nothing but `dc-write.ts`:
// phase E's conformance test runs one change through both and compares the
// stores, which only means something if neither borrowed the other's translation.

import type { Directory } from "./dc-directory.ts";
import { WriteError, Writer, type Fields as WriteFields } from "./dc-write.ts";
import {
  allowed, type Allowed, errorBody, etagOf, GROUP_FIELDS, matches, MAX_RESULTS, OU_FIELDS,
  page, parseFilter, project, resourceTypes, SCHEMA, ScimError, ScimRead, type ScimReply,
  SCIM_TYPE, schemas, serviceProviderConfig, USER_FIELDS,
} from "./scim.ts";
import { SCOPES, type TokenService } from "./tokens.ts";

/** What a request carries. */
export interface ScimRequest {
  method: string;
  /** The path beneath /scim/v2, with no leading slash: "Users/abc". */
  path: string;
  query: URLSearchParams;
  authorization?: string;
  contentType?: string;
  ifMatch?: string;
  ifNoneMatch?: string;
  body?: string;
}

const bad = (message: string, scimType = "invalidValue") => new ScimError(400, message, scimType);

/** A fingerprint as the extension's `certificates` names one. */
const FINGERPRINT = /^sha256:[0-9a-f]{64}$/;

/** A certificate as a request names it: its fingerprint, and itself where given. */
type Certificate = { value: string; der?: Buffer; display?: string };

/** One operation of a PATCH (RFC 7644 section 3.5.2). */
interface PatchOperation {
  op: "add" | "remove" | "replace";
  path?: string;
  value?: unknown;
}

export class ScimService extends ScimRead {
  private readonly tokens: () => TokenService | undefined;
  /** The write path, where this controller has one. */
  private readonly writer: (() => Writer) | undefined;
  private readonly rebuilt: () => Promise<void>;

  constructor(directory: () => Directory, domain: string, domainSid: string,
    tokens: () => TokenService | undefined, writer?: () => Writer,
    rebuilt: () => Promise<void> = () => Promise.resolve()) {
    super(directory, domain, domainSid);
    this.tokens = tokens;
    this.writer = writer;
    this.rebuilt = rebuilt;
  }

  /** Answers a request, turning any refusal into a SCIM error body. */
  async handle(r: ScimRequest, now = Date.now()): Promise<ScimReply> {
    try {
      return await this.route(r, now);
    } catch (e) {
      const err = e instanceof ScimError ? e : this.scimErrorOf(e);
      return {
        status: err.status,
        body: errorBody(err),
        headers: {
          "Content-Type": SCIM_TYPE,
          // The challenge of RFC 6750 section 3, on a 401 and on a 403 that was
          // refused for want of a scope. The error code is present only where the
          // request presented something to be wrong about.
          ...(err.status === 401 || err.bearerError !== undefined
            ? {
              "WWW-Authenticate": `Bearer realm="${this.domain}"` +
                (err.bearerError === undefined ? "" : `, error="${err.bearerError}"`) +
                (err.bearerError === "insufficient_scope" ? `, scope="${SCOPES.read} ${SCOPES.admin}"` : ""),
            }
            : {}),
        },
        log: { event: "scim refused", method: r.method, path: r.path, status: err.status,
          ...(err.scimType === undefined ? {} : { scimType: err.scimType }), detail: err.message },
      };
    }
  }

  private async route(r: ScimRequest, now: number): Promise<ScimReply> {
    const parts = r.path.split("/").filter((p) => p !== "").map((p) => decodeURIComponent(p));
    const resource = parts[0] ?? "";
    // /Users/<id>/s3Keys, the one sub-resource: a key pair whose secret is
    // returned once, which no representation of the User may ever carry.
    const s3 = resource === "Users" && parts.length === 3 && parts[2].toLowerCase() === "s3keys";
    // "/.search" on the end of an endpoint makes a POST a query, not a creation
    // (RFC 7644 §3.4.3). It is recognized before `id` is formed, since otherwise
    // ".search" reads as the identifier of a resource.
    // At the root it is the only element of the path; on an endpoint it is the
    // second. Either way the resource is what precedes it.
    const searching = parts.at(-1) === ".search" && parts.length <= 2;
    const id = s3 || searching ? (searching ? "" : parts[1]) : parts.slice(1).join("/");
    if (parts.length > 2 && resource !== "Ous" && !s3) {
      throw new ScimError(404, `${r.path} is not an endpoint of this interface`);
    }
    // The discovery documents are read by any token this interface accepts: a
    // client reads them to learn what it may do at all.
    const may = allowed(r.authorization, this.tokens(), now);
    if (r.method === "GET" || r.method === "HEAD") {
      switch (resource) {
        case "ServiceProviderConfig":
          return this.ok(serviceProviderConfig(may.write));
        case "ResourceTypes":
          return id === ""
            ? this.list(resourceTypes(), r.query, {})
            : this.one(resourceTypes().find((t) => t.id === id), r, `no resource type is ${id}`);
        case "Schemas":
          return id === ""
            ? this.list(schemas(), r.query, {})
            : this.one(schemas().find((t) => t.id === id), r, `no schema is ${id}`);
        case "Me":
          return this.me(may, r);
      }
    }
    // A search is a read, whatever verb carries it, so it is answered before the
    // write scope below is asked for: a dc.read token may POST to /.search.
    if (searching && r.method === "POST" && ["Users", "Groups", "Ous"].includes(resource)) {
      return this.search(resource, r);
    }
    if (searching && (resource === "" || resource === ".search")) {
      // §3.4.3 allows a search from the server root, which returns resources of
      // every type in one list. This server does not: the three resources have no
      // common ordering and no common filter, and a list mixing them would be a
      // page of something a client cannot page through. Said, rather than left to
      // a 404 that reads as "no such endpoint".
      throw new ScimError(501,
        "a search from the root would mix Users, Groups and Ous in one list, which this server " +
        "does not page; search /Users/.search, /Groups/.search or /Ous/.search");
    }
    // Anything other than a GET on /Me. §3.11: "A service provider that does NOT
    // support this feature SHOULD respond with HTTP status code 501 (Not
    // Implemented)", and the useful answer is about the method rather than the
    // endpoint, which a 404 made it look like.
    if (resource === "Me") {
      throw new ScimError(501,
        `${r.method} on /Me is not served; /Me reads the authenticated subject, and a change ` +
        "goes to the subject's own resource, whose URL the Location header of a GET gives");
    }
    if (!["Users", "Groups", "Ous"].includes(resource)) {
      throw new ScimError(404, `${r.path} is not an endpoint of this interface; ` +
        "the resources are Users, Groups and Ous, and /Me, /ServiceProviderConfig, /ResourceTypes and /Schemas");
    }
    // A write needs the scope, checked before a body is read or a name looked up.
    const writing = ["POST", "PUT", "PATCH", "DELETE"].includes(r.method);
    if (writing) {
      if (!may.write) {
        throw new ScimError(403, "the token carries dc.read, which does not write; dc.admin writes");
      }
      if (this.writer === undefined) {
        throw new ScimError(501,
          "this controller's directory is its configuration and is not written through this " +
          "interface; a directory that is written is kept in a store ([directory].store)");
      }
    }
    if (s3) return await this.s3Keys(id, r);
    switch (r.method) {
      case "GET":
      case "HEAD":
        return id === "" ? this.listOf(resource, r) : this.oneOf(resource, id, r);
      case "POST":
        return await this.create(resource, r);
      case "PUT":
        return await this.replace(resource, id, r);
      case "PATCH":
        return await this.patch(resource, id, r);
      case "DELETE":
        return await this.remove(resource, id, r);
      default:
        throw new ScimError(405, `${r.method} is not a method of ${r.path}`);
    }
  }

  // -------------------------------------------------------------------
  // Reading

  private ok(body: unknown, headers: Record<string, string> = {}): ScimReply {
    return { status: 200, body, headers: { "Content-Type": SCIM_TYPE, ...headers } };
  }

  private one(found: Record<string, unknown> | undefined, r: ScimRequest, why: string): ScimReply {
    if (found === undefined) throw new ScimError(404, why);
    const version = (found.meta as Record<string, string> | undefined)?.version;
    // "If-None-Match ... 304" (RFC 7644 section 3.14): a client that already
    // holds this version is told so rather than sent it again.
    if (version !== undefined && this.matchesAny(r.ifNoneMatch, version)) {
      return { status: 304, headers: { ETag: version } };
    }
    // "In any response, the HTTP 'Location' header MUST be the permanent location
    // of the aliased resource associated with the authenticated subject" (RFC 7644
    // §3.11, of /Me) — and a client reading any single resource has the same use
    // for it. No reply carried one, so a client that read /Me to learn its own
    // resource's URL had to guess from meta.location.
    const location = (found.meta as Record<string, string> | undefined)?.location;
    return this.ok(project(found, r.query), {
      ...(version === undefined ? {} : { ETag: version }),
      ...(location === undefined ? {} : { Location: location }),
    });
  }

  /**
   * A query by POST to `<endpoint>/.search` (RFC 7644 §3.4.3): "The inclusion of
   * '/.search' on the end of a valid SCIM endpoint SHALL be used to indicate that
   * the HTTP POST verb is intended to be a query operation." The body carries the
   * parameters a GET would carry in the URL, which is the whole point — a filter
   * long enough to be awkward in a query string, or one a client would rather not
   * have in a log.
   *
   * Before this existed the path fell through to the create route, so
   * `POST /Users/.search` was answered "userName is given" — and a SearchRequest
   * that happened to carry a `userName` would have created a user.
   */
  private search(resource: string, r: ScimRequest): ScimReply {
    const body = this.body(r);
    const schemasIn = Array.isArray(body.schemas) ? body.schemas as string[] : [];
    if (!schemasIn.includes(SCHEMA.searchRequest)) {
      throw bad(`the body of a search names the schema ${SCHEMA.searchRequest}`, "invalidSyntax");
    }
    // The parameters of §3.4.2 as a query string, so that one implementation
    // answers both ways of asking and they cannot drift apart.
    const query = new URLSearchParams();
    for (const k of ["filter", "attributes", "excludedAttributes", "sortBy", "sortOrder",
      "startIndex", "count"]) {
      const v = body[k];
      if (v === undefined || v === null) continue;
      query.set(k, Array.isArray(v) ? v.join(",") : String(v));
    }
    return this.listOf(resource, { ...r, query });
  }

  private list(all: Record<string, unknown>[], query: URLSearchParams,
    fields: Record<string, (r: Record<string, unknown>) => string | boolean | undefined>): ScimReply {
    const filter = query.get("filter");
    let found = all;
    if (filter !== null && filter !== "") {
      if (Object.keys(fields).length === 0) {
        throw new ScimError(400, "this endpoint takes no filter", "invalidFilter");
      }
      const f = parseFilter(filter, fields);
      found = all.filter((x) => matches(x, f, fields));
    }
    if (query.get("sortBy") !== null) {
      // /ServiceProviderConfig says sort is not supported, and a request that
      // sorts anyway is refused rather than answered in an order of this server's
      // choosing that the client will read as sorted.
      throw new ScimError(400, "this server does not sort; /ServiceProviderConfig says so", "invalidValue");
    }
    const body = page(found, query);
    body.Resources = (body.Resources as Record<string, unknown>[]).map((x) => project(x, query));
    return this.ok(body);
  }

  private listOf(resource: string, r: ScimRequest): ScimReply {
    if (resource === "Users") return this.list(this.users(), r.query, USER_FIELDS);
    if (resource === "Groups") return this.list(this.groups(), r.query, GROUP_FIELDS);
    return this.list(this.units(), r.query, OU_FIELDS);
  }

  private oneOf(resource: string, id: string, r: ScimRequest): ScimReply {
    // A filter on a single resource: refused, not ignored. See the note at the top
    // of scim.ts for why this server cannot answer one usefully.
    if ((r.query.get("filter") ?? "") !== "") {
      throw new ScimError(400,
        "a filter on one resource is not evaluated here: this endpoint answers whether that " +
        `resource exists, and a filter that did not match could only be a 404. Ask /${resource} ` +
        "with the filter instead", "invalidFilter");
    }
    if (resource === "Ous") return this.one(this.unit(id), r, `no organizational unit is ${id}`);
    const kind = resource === "Users" ? "user" : "group";
    const name = this.nameOf(id, kind);
    const found = name === undefined ? undefined : (kind === "user" ? this.user(name) : this.group(name));
    return this.one(found, r, `no ${kind} of this realm is ${id}`);
  }

  /**
   * /Me: "an alternate way to access the current authenticated subject"
   * (RFC 7644 section 3.11). The subject of a token issued by the client
   * credentials grant is the client, which is not a principal of this
   * directory — so /Me is served only where the subject is one, and a client
   * token is told so rather than given a 404 that reads as "you do not exist".
   */
  private me(may: Allowed, r: ScimRequest): ScimReply {
    const subject = may.subject;
    const name = subject === undefined ? undefined : (this.nameOf(subject, "user") ?? this.directory().user(subject)?.name);
    if (name === undefined) {
      throw new ScimError(404,
        `the subject of this token, ${JSON.stringify(subject ?? "")}, is not a user of this realm: ` +
        "a token issued to a client names the client, and /Me is the endpoint of a user");
    }
    return this.one(this.user(name), r, "the subject is not a user of this realm");
  }

  // -------------------------------------------------------------------
  // Writing

  private body(r: ScimRequest): Record<string, unknown> {
    if (r.contentType !== undefined && r.contentType !== "") {
      const type = r.contentType.split(";")[0].trim().toLowerCase();
      if (type !== SCIM_TYPE && type !== "application/json") {
        throw new ScimError(415, `the body of a request is ${SCIM_TYPE}`);
      }
    }
    if (r.body === undefined || r.body.trim() === "") throw bad("a body is given", "invalidSyntax");
    let held: unknown;
    try {
      held = JSON.parse(r.body);
    } catch (e) {
      throw bad(`the body is not JSON: ${(e as Error).message}`, "invalidSyntax");
    }
    if (held === null || typeof held !== "object" || Array.isArray(held)) {
      throw bad("the body is a JSON object", "invalidSyntax");
    }
    return held as Record<string, unknown>;
  }

  private async create(resource: string, r: ScimRequest): Promise<ScimReply> {
    const body = this.body(r);
    const w = this.writer!();
    if (resource === "Ous") {
      const name = this.text(body, "name", true)!;
      const parent = this.text(body, "parent");
      // The description, which a unit serves and which this used to discard: the
      // resource carried a `description` a client could read and never set, and
      // the published Ou schema did not declare it at all.
      const description = this.text(body, "description");
      await this.apply(() => void w.createUnit(name, parent, description));
      const path = parent === undefined ? name : `${parent}/${name}`;
      const made = this.unit(path)!;
      return { status: 201, body: project(made, r.query),
        headers: { "Content-Type": SCIM_TYPE,
          Location: (made.meta as Record<string, string>).location },
        log: { event: "scim create", resource, name: path } };
    }
    const kind = resource === "Users" ? "user" : "group";
    // "userName ... REQUIRED"; a Group is named by displayName, which this realm
    // takes as the name as well, there being no other field for it.
    const name = kind === "user" ? this.text(body, "userName", true)! : this.text(body, "displayName", true)!;
    const fields = this.fieldsOf(body, kind);
    const password = this.text(body, "password");
    const members = kind === "group" ? this.members(body) : undefined;
    // **All of it or none.** A create writes more than one row — the principal, then its
    // members or its certificates and its password — and without the transaction a
    // `POST /Users` carrying a certificate another principal already holds answered 409
    // and **created the user anyway**. RFC 7644 §3.3: "If the service provider
    // determines that the creation of the requested resource conflicts with existing
    // resources ... the service provider MUST return HTTP status code 409 (Conflict)".
    // A 409 for a creation that happened contradicts the word: the client is told the
    // resource was not created, will retry, will be refused again for the name it now
    // holds, and has no identifier for the thing it does not know exists.
    //
    // This is the defect phase D′ found in `PATCH` (§11 of NOTES-on-scim.md), in the
    // operation nobody then checked, and the LDAP front end had it in its Add for the
    // same reason. Both are found by the refusal conformance test, which asks of a
    // change the realm does not admit whether the store is unchanged afterwards.
    await this.apply(() => w.atomic(async () => {
      w.create(kind, name, fields);
      if (members !== undefined && members.length > 0) w.setMembers(name, members);
      if (password !== undefined) await w.setPassword(w.principal(name).id, password);
      for (const c of this.certificates(body)) w.addCertificate(w.principal(name).id, c.value, c.display, c.der);
    }));
    const made = kind === "user" ? this.user(name)! : this.group(name)!;
    return {
      status: 201,
      // Subject to "attributes" as every other resource-returning reply is (§3.9).
      body: project(made, r.query),
      headers: {
        "Content-Type": SCIM_TYPE,
        Location: (made.meta as Record<string, string>).location,
        ...((made.meta as Record<string, string>).version === undefined
          ? {} : { ETag: (made.meta as Record<string, string>).version }),
      },
      log: { event: "scim create", resource, name },
    };
  }

  private async replace(resource: string, id: string, r: ScimRequest): Promise<ScimReply> {
    const body = this.body(r);
    const w = this.writer!();
    if (resource === "Ous") {
      const held = this.unit(id);
      if (held === undefined) throw new ScimError(404, `no organizational unit is ${id}`);
      // The identifier is the store's UUID; the write path names a unit by its
      // path, so it is resolved here and not guessed from the identifier.
      const at = this.unitPath(id)!;
      this.checkVersion(r, "unit", at);
      const name = this.text(body, "name", true)!;
      const parent = this.text(body, "parent");
      // PUT replaces, so a description the body omits is cleared, as it is for a
      // principal.
      const description = this.text(body, "description") ?? null;
      await this.apply(() => void w.moveUnit(at, {
        name,
        parent: parent === undefined ? null : parent,
        description,
      }));
      // The unit keeps its identifier through a rename, which is the point of its
      // being the store's UUID, so the result is read back by that and not by a path.
      const made = this.unit(id)!;
      const meta = made.meta as Record<string, string>;
      return this.ok(project(made, r.query), {
        ...(meta.version === undefined ? {} : { ETag: meta.version }),
        Location: meta.location,
      });
    }
    const kind = resource === "Users" ? "user" : "group";
    const name = this.nameOf(id, kind);
    if (name === undefined) throw new ScimError(404, `no ${kind} of this realm is ${id}`);
    this.checkVersion(r, kind, name);
    // PUT replaces the resource: an attribute absent from the body is cleared,
    // which is what "replace" means and what distinguishes it from PATCH.
    const wanted = kind === "user" ? this.text(body, "userName", true)! : this.text(body, "displayName", true)!;
    const fields = this.fieldsOf(body, kind, true);
    if (wanted.toLowerCase() !== name.toLowerCase()) fields.name = wanted;
    const members = kind === "group" ? this.members(body) : undefined;
    const password = this.text(body, "password");
    await this.apply(async () => {
      w.update(w.principal(name).id, fields);
      if (members !== undefined) w.setMembers(wanted, members);
      if (password !== undefined) await w.setPassword(w.principal(wanted).id, password);
    });
    return this.answer(kind, wanted, { event: "scim replace", resource, name: wanted }, r.query);
  }

  private async patch(resource: string, id: string, r: ScimRequest): Promise<ScimReply> {
    const body = this.body(r);
    const w = this.writer!();
    const schemasIn = Array.isArray(body.schemas) ? body.schemas as string[] : [];
    if (!schemasIn.includes(SCHEMA.patchOp)) {
      throw bad(`the body of a PATCH names the schema ${SCHEMA.patchOp}`, "invalidSyntax");
    }
    if (!Array.isArray(body.Operations) || body.Operations.length === 0) {
      throw bad("a PATCH holds at least one operation", "invalidSyntax");
    }
    const ops: PatchOperation[] = (body.Operations as Record<string, unknown>[]).map((o, i) => {
      const op = String(o.op ?? "").toLowerCase();
      if (!["add", "remove", "replace"].includes(op)) {
        throw bad(`operation ${i} is add, remove or replace, not ${JSON.stringify(o.op)}`, "invalidSyntax");
      }
      if (op === "remove" && o.path === undefined) {
        // "The 'path' attribute is REQUIRED for 'remove' operations."
        throw bad(`operation ${i} removes and names no path`, "noTarget");
      }
      return {
        op: op as "add",
        ...(o.path === undefined ? {} : { path: String(o.path) }),
        ...(o.value === undefined ? {} : { value: o.value }),
      };
    });
    if (resource === "Ous") return await this.patchUnit(id, ops, r);
    const kind = resource === "Users" ? "user" : "group";
    const name = this.nameOf(id, kind);
    if (name === undefined) throw new ScimError(404, `no ${kind} of this realm is ${id}`);
    this.checkVersion(r, kind, name);
    // A rename within a PATCH changes the name the later operations name, so the
    // current name is tracked as the operations are applied.
    let at = name;
    // "A PATCH request, regardless of the number of operations, SHALL be treated
    // as atomic. If a single operation encounters an error condition, the original
    // SCIM resource MUST be restored, and a failure status SHALL be returned"
    // (RFC 7644 §3.5.2). Each writer opens a transaction of its own, so without
    // the outer one a PATCH whose second operation failed left the first applied:
    // the client's view of the resource and this server's diverged for good, and a
    // retry applied the first operation twice.
    await this.apply(() => w.atomic(async () => {
      for (const op of ops) at = await this.onePatch(w, kind, at, op);
    }));
    return this.answer(kind, at, { event: "scim patch", resource, name: at, operations: ops.length },
      r.query);
  }

  /**
   * PATCH of an `Ou`. The three writable attributes are `name`, `parent` and
   * `description`; `path` and `id` are derived. This was 501 — "an organizational
   * unit is changed with PUT; PATCH of one is not implemented" — which `PATCH` of a
   * unit over the other front end was equally unable to do, so neither interface
   * could change a description the store had held since phase A.
   *
   * Atomic over the whole list, as §3.5.2 requires: the operations are folded into
   * one `moveUnit`, so a list whose third operation is refused changes nothing.
   */
  private async patchUnit(id: string, ops: PatchOperation[], r: ScimRequest): Promise<ScimReply> {
    const w = this.writer!();
    const held = this.unit(id);
    if (held === undefined) throw new ScimError(404, `no organizational unit is ${id}`);
    const at = this.unitPath(id)!;
    this.checkVersion(r, "unit", at);
    let name = held.name as string;
    let parent = held.parent as string | undefined;
    let description = held.description as string | undefined;
    for (const op of ops) {
      const path = (op.path ?? "").trim().toLowerCase();
      if (path === "") {
        // "If 'path' is unspecified, the operation fails" for a remove (§3.5.2.2);
        // for add and replace the value is a partial resource (§3.5.2.1).
        if (op.op === "remove") throw bad("a remove names a path", "noTarget");
        if (op.value === null || typeof op.value !== "object" || Array.isArray(op.value)) {
          throw bad("an operation with no path carries an object of attributes", "invalidValue");
        }
        for (const [k, v] of Object.entries(op.value as Record<string, unknown>)) {
          if (k === "schemas") continue;
          ({ name, parent, description } = this.onUnit({ name, parent, description },
            { op: op.op, path: k, value: v }));
        }
        continue;
      }
      ({ name, parent, description } = this.onUnit({ name, parent, description }, op));
    }
    await this.apply(() => void w.moveUnit(at, {
      name, parent: parent === undefined ? null : parent,
      description: description === undefined ? null : description,
    }));
    const made = this.unit(id)!;
    const meta = made.meta as Record<string, string>;
    return { status: 200, body: project(made, r.query),
      headers: { "Content-Type": SCIM_TYPE,
        ...(meta.version === undefined ? {} : { ETag: meta.version }),
        Location: meta.location },
      log: { event: "scim patch", resource: "Ous", name: made.path as string, operations: ops.length } };
  }

  /** One operation of a PATCH of an `Ou`, applied to the attributes so far. */
  private onUnit(at: { name: string; parent?: string; description?: string },
    op: PatchOperation): { name: string; parent?: string; description?: string } {
    const path = (op.path ?? "").trim().toLowerCase();
    const clearing = op.op === "remove";
    const text = (): string | undefined => {
      if (clearing) return undefined;
      if (typeof op.value !== "string" || op.value === "") {
        throw bad(`the value of an operation on ${op.path} is a non-empty string`, "invalidValue");
      }
      return op.value;
    };
    switch (path) {
      case "name": {
        // "readWrite" and required, so it cannot be removed, only replaced.
        if (clearing) throw bad("name is required and is not removed", "mutability");
        return { ...at, name: text()! };
      }
      case "parent": {
        const to = text();
        return { ...at, ...(to === undefined ? { parent: undefined } : { parent: to }) };
      }
      case "description": {
        const to = text();
        return { ...at, ...(to === undefined ? { description: undefined } : { description: to }) };
      }
      case "path":
      case "id":
        // "attributes whose mutability is 'readOnly' ... SHALL return ...
        // mutability" when a PATCH names one by path (§3.5.2).
        throw bad(`${op.path} is derived from name and parent and is not written`, "mutability");
      default:
        throw bad(`${op.path} is not an attribute of an organizational unit`, "invalidPath");
    }
  }

  /**
   * The members a value selection filter picks out of a group, as names of this
   * realm. "If the target location is a multi-valued attribute for which a value
   * selection filter ('valuePath') has been supplied and no record match was made,
   * the service provider SHALL indicate failure by returning HTTP status code 400
   * and a 'scimType' error code of 'noTarget'" (RFC 7644 §3.5.2.3; §3.5.2.2 says
   * the same of a remove), so an empty selection is that refusal and never a
   * silent success.
   */
  private selected(group: string, filter: string): string[] {
    const wanted = /^value\s+eq\s+"?([^"]+)"?$/i.exec(filter);
    if (wanted === null) {
      throw bad(`${filter} is not a value filter this server evaluates; ` +
        'members[value eq "<id>"] is', "invalidFilter");
    }
    const found = this.nameOf(wanted[1], "user") ?? this.nameOf(wanted[1], "group");
    const held = this.directory().membersOf(group);
    const matched = found === undefined
      ? []
      : [...held.users, ...held.groups].filter((m) => m.toLowerCase() === found.toLowerCase());
    if (matched.length === 0) {
      throw new ScimError(400,
        `no member of ${group} is ${wanted[1]}`, "noTarget");
    }
    return matched;
  }

  /** One operation of a PATCH; the name the entry has afterwards. */
  private async onePatch(w: Writer, kind: "user" | "group", name: string,
    op: PatchOperation): Promise<string> {
    const path = (op.path ?? "").trim();
    // A value filter, which RFC 7644 allows on a multi-valued path:
    // members[value eq "x"]. Only members takes one here.
    const filtered = /^(\w+)\[(.+)\]$/.exec(path);
    const attribute = (filtered === null ? path : filtered[1]).toLowerCase();
    const value = op.value;
    const asText = (): string => {
      if (typeof value === "string") return value;
      throw bad(`the value of an operation on ${path} is a string`, "invalidValue");
    };
    // No path: "the value parameter SHALL contain ... attributes to be added or
    // replaced", as a partial resource.
    if (path === "") {
      if (op.op === "remove") throw bad("a remove names a path", "noTarget");
      if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw bad("an operation with no path carries an object of attributes", "invalidValue");
      }
      const body = value as Record<string, unknown>;
      let out = name;
      for (const [k, v] of Object.entries(body)) {
        if (k === "schemas") continue;
        out = await this.onePatch(w, kind, out, { op: op.op, path: k, value: v });
      }
      return out;
    }
    if (attribute === "members") {
      if (kind !== "group") throw bad("members is an attribute of a Group", "invalidPath");
      const named = (): string[] => {
        const list = Array.isArray(value) ? value : (value === undefined ? [] : [value]);
        return list.map((m) => {
          const held = (m as Record<string, unknown>)?.value ?? m;
          if (typeof held !== "string") throw bad("a member is named by its value", "invalidValue");
          const found = this.nameOf(held, "user") ?? this.nameOf(held, "group");
          if (found === undefined) throw bad(`${held} is not a member of this realm`, "invalidValue");
          return found;
        });
      };
      // A value selection filter, where one was given. RFC 7644 §3.5.2.3 for a
      // replace: "If the target location is a multi-valued attribute and a value
      // selection ('valuePath') filter is specified that matches one or more values
      // of the multi-valued attribute, then all matching record values SHALL be
      // replaced", and "if ... no record match was made, the service provider SHALL
      // indicate failure by returning HTTP status code 400 and a 'scimType' error
      // code of 'noTarget'". The filter was parsed and then consulted only on a
      // remove: `replace` on `members[value eq "<alice>"]` ran setMembers, which
      // clears the membership first, so a request to swap one member for another
      // silently deleted every other member of the group.
      const selected = filtered === null ? undefined : this.selected(name, filtered[2]);
      if (op.op === "add") {
        if (selected !== undefined) {
          // §3.5.2.1 gives no meaning to a valuePath on an add: an add to a
          // multi-valued attribute appends, and a filter selects what is already
          // there. Saying so beats guessing which it meant.
          throw bad(`members[${filtered![2]}] selects values that are already there; ` +
            "an add names the members to add in its value and takes no filter", "invalidPath");
        }
        for (const m of named()) w.addMember(name, m);
        return name;
      }
      if (op.op === "replace") {
        if (selected !== undefined) {
          // The matching values, and only those, become what the value names.
          const held = this.directory().membersOf(name);
          const all = [...held.users, ...held.groups];
          const kept = all.filter((m) => !selected.includes(m));
          w.setMembers(name, [...kept, ...named()]);
          return name;
        }
        w.setMembers(name, named());
        return name;
      }
      // remove. With a value filter, those it names; with none, every member —
      // the corner §7 calls out, and NOTES-on-scim.md records this choice.
      if (selected !== undefined) {
        for (const m of selected) w.removeMember(name, m);
        return name;
      }
      if (value !== undefined) {
        for (const m of named()) w.removeMember(name, m);
        return name;
      }
      w.setMembers(name, []);
      return name;
    }
    const held = w.principal(name);
    const clearing = op.op === "remove";
    switch (attribute) {
      case "username":
      case "displayname": {
        if (attribute === "username" && kind !== "user") {
          throw bad("userName is an attribute of a User", "invalidPath");
        }
        // A Group's displayName is its name here; a User's is a separate field.
        if (attribute === "username" || kind === "group") {
          if (clearing) throw new ScimError(400, "a name is changed and not removed", "mutability");
          w.update(held.id, { name: asText() });
          return asText();
        }
        w.update(held.id, { displayName: clearing ? null : asText() });
        return name;
      }
      case "active": {
        if (clearing) throw new ScimError(400, "active is true or false and is not removed", "mutability");
        if (typeof value !== "boolean") throw bad("active is true or false", "invalidValue");
        w.update(held.id, { disabled: !value });
        return name;
      }
      case "password": {
        if (clearing) {
          throw new ScimError(400,
            "a password is changed and not removed; set active to false to disable the account",
            "mutability");
        }
        await w.setPassword(held.id, asText());
        return name;
      }
      case "groups":
        throw new ScimError(400,
          "groups is read-only on a User: membership is written on the Group, as RFC 7643 " +
          "section 4.1.2 makes it readOnly", "mutability");
      case "id":
      case "meta":
        throw new ScimError(400, `${attribute} is set by this server`, "mutability");
      default: {
        // The extension's attributes, named either on their own or with the URN.
        const inner = path.includes(":") ? path.slice(path.lastIndexOf(":") + 1).toLowerCase() : attribute;
        if (inner === "ou") {
          w.update(held.id, { ou: clearing ? null : asText() });
          return name;
        }
        if (inner === "home") {
          w.update(held.id, { home: clearing ? null : asText() });
          return name;
        }
        if (inner === "displayname") {
          // A group's own label. On a User the core `displayName` is this, and the
          // case above handles it; the extension does not carry a second one, so
          // naming it there on a User is told rather than quietly applied.
          if (held.kind !== "group") {
            throw new ScimError(400,
              "displayName of the extension is a group's own label; a User's display name " +
              "is the core displayName (RFC 7643 section 4.1.1)", "invalidPath");
          }
          w.update(held.id, { displayName: clearing ? null : asText() });
          return name;
        }
        if (inner === "primarygroup") {
          w.update(held.id, { primaryGroup: clearing ? null : asText() });
          return name;
        }
        if (inner === "expires") {
          w.update(held.id, { expires: clearing ? null : asText() });
          return name;
        }
        if (inner === "certificates") {
          if (clearing) {
            for (const c of w.credentials(held.id).filter((x) => x.kind === "certificate")) {
              await w.removeCredential(c.id);
            }
            return name;
          }
          if (op.op === "replace") {
            for (const c of w.credentials(held.id).filter((x) => x.kind === "certificate")) {
              await w.removeCredential(c.id);
            }
          }
          for (const c of this.certificateList(value)) {
            w.addCertificate(held.id, c.value, c.display, c.der);
          }
          return name;
        }
        if (inner === "s3keys") {
          // A key pair is created by POSTing to the collection, not by a PATCH:
          // its secret is returned once, and a PATCH's answer is the resource,
          // which would then carry a secret in a representation a client caches.
          // NOTES-on-scim.md records this.
          throw new ScimError(400,
            "an S3 key pair is created at /scim/v2/Users/<id>/s3Keys, whose answer carries the " +
            "secret once; it is not written through PATCH, whose answer is the resource",
            "mutability");
        }
        if (["uidnumber", "gidnumber", "objectsid", "name"].includes(inner)) {
          throw new ScimError(400, `${inner} is allocated by this server and is not written`, "mutability");
        }
        throw new ScimError(400, `${path} is not an attribute of this resource`, "invalidPath");
      }
    }
  }

  private async remove(resource: string, id: string, r: ScimRequest): Promise<ScimReply> {
    const w = this.writer!();
    if (resource === "Ous") {
      const at = this.unitPath(id);
      if (at === undefined) throw new ScimError(404, `no organizational unit is ${id}`);
      this.checkVersion(r, "unit", at);
      await this.apply(() => w.deleteUnit(at));
      return { status: 204, log: { event: "scim delete", resource, name: id } };
    }
    const kind = resource === "Users" ? "user" : "group";
    const name = this.nameOf(id, kind);
    if (name === undefined) throw new ScimError(404, `no ${kind} of this realm is ${id}`);
    this.checkVersion(r, kind, name);
    await this.apply(() => w.remove(w.principal(name).id));
    return { status: 204, log: { event: "scim delete", resource, name } };
  }

  /**
   * /Users/<id>/s3Keys: the collection of a user's S3 key pairs, and a POST that
   * creates one. Its own endpoint because the secret is returned **once**, in the
   * answer to the request that created it (§4a), and a resource's representation
   * must never carry it: a client that re-read the User, or a server that logged
   * the body, would have the long-term secret of a principal.
   */
  private async s3Keys(id: string, r: ScimRequest): Promise<ScimReply> {
    const name = this.nameOf(id, "user");
    if (name === undefined) throw new ScimError(404, `no user of this realm is ${id}`);
    const w = this.writer!;
    if (r.method === "GET" || r.method === "HEAD") {
      const held = this.directory().credentialsOf(name).s3Keys;
      return this.ok({
        schemas: [SCHEMA.listResponse],
        totalResults: held.length,
        itemsPerPage: held.length,
        startIndex: 1,
        Resources: held.map((k) => ({
          value: k.accessKeyId,
          ...(k.created === undefined ? {} : { created: k.created.toISOString() }),
        })),
      });
    }
    if (r.method !== "POST") {
      throw new ScimError(405, `${r.method} is not a method of this collection; POST creates a key pair`);
    }
    let made: { accessKeyId: string; secret: string } | undefined;
    await this.apply(async () => { made = await w().createS3Key(w().principal(name).id); });
    return {
      status: 201,
      body: {
        value: made!.accessKeyId,
        // Returned once. Nothing reads it back, here or anywhere.
        secret: made!.secret,
        $ref: `/scim/v2/Users/${id}/s3Keys`,
      },
      headers: { "Content-Type": SCIM_TYPE, "Cache-Control": "no-store" },
      log: { event: "scim s3 key created", name, accessKeyId: made!.accessKeyId },
    };
  }

  // -------------------------------------------------------------------
  // Helpers

  /**
   * The body of a successful PUT or PATCH: "the server either MUST return a 200 OK
   * response code and the entire resource within the response body, **subject to
   * the 'attributes' query parameter** (see Section 3.9)" (RFC 7644 §3.5.2, and
   * §3.5.1 for PUT). §3.9 extends that to "any operation that returns a resource
   * within the response", so the parameter is honoured here as it is on a read. It
   * was ignored, so a client that PATCHed a group with `excludedAttributes=members`
   * to avoid pulling back a large membership got the whole list anyway.
   */
  private answer(kind: "user" | "group", name: string, log: Record<string, unknown>,
    query: URLSearchParams): ScimReply {
    const made = kind === "user" ? this.user(name)! : this.group(name)!;
    const meta = made.meta as Record<string, string>;
    return { status: 200, body: project(made, query),
      headers: { "Content-Type": SCIM_TYPE,
        ...(meta.version === undefined ? {} : { ETag: meta.version }),
        ...(meta.location === undefined ? {} : { Location: meta.location }) },
      log };
  }

  /** The fields of a principal a body carries. */
  private fieldsOf(body: Record<string, unknown>, kind: "user" | "group", replacing = false): WriteFields {
    const extension = (body[SCHEMA.extension] ?? {}) as Record<string, unknown>;
    const ext = (k: string): string | undefined => {
      const v = extension[k];
      if (v === undefined || v === null) return undefined;
      if (typeof v !== "string") throw bad(`${k} of the extension is a string`, "invalidValue");
      return v;
    };
    // A read-only attribute in the body of a POST or a PUT is **ignored**, not
    // refused: "attributes whose mutability is 'readOnly' ... SHALL be ignored"
    // (RFC 7644 sections 3.3 and 3.5.1). The body of a PUT is the whole resource,
    // so it necessarily carries them — refusing made an ordinary
    // read-modify-write fail, which is how this was found. A PATCH names one
    // deliberately and is refused with "mutability", as section 3.5.2 provides.
    //
    // **`id` is one of the read-only ones**, and so is ignored here like the rest.
    // This used to refuse a body whose `id` differed, calling the attribute
    // immutable; RFC 7643 §3.1 says otherwise in as many words: "The value of the
    // 'id' attribute is always issued by the service provider and MUST NOT be
    // specified by the client ... The attribute characteristics are 'caseExact' as
    // 'true', a mutability of 'readOnly', and a 'returned' characteristic of
    // 'always'." RFC 7644 §3.5.1 of readOnly: "Any values provided SHALL be
    // ignored." The refusal was therefore wrong, and `NOTES-on-scim.md` recorded
    // the wrong reading as the rule. It was wrong in a second way as well: it
    // looked the existing value up from the body's own userName, so a PUT that
    // renamed the principal found nothing to compare and skipped the check it was
    // there to make.
    //
    // No attribute of this interface is `immutable`. If one is ever added, the rule
    // for that is different — "attempting to modify an immutable attribute with a
    // different value SHALL return 400 with mutability" — and belongs here.
    const displayName = kind === "user" ? this.text(body, "displayName") : undefined;
    const active = body.active;
    if (active !== undefined && typeof active !== "boolean") throw bad("active is true or false");
    // `active` is an attribute of a User and not of a Group: RFC 7643 §4.2 gives a
    // Group `displayName` and `members` and nothing else of this sort, and §4.1.1
    // gives `active` to the User. A client sending one on a Group is told so rather
    // than having it quietly dropped, which is how this interface treats an attribute
    // it does not have everywhere else (a PATCH gets `invalidPath` with "is not an
    // attribute of this resource").
    if (kind === "group" && active !== undefined) {
      throw bad("active is an attribute of a User and not of a Group (RFC 7643 section 4.2)");
    }
    // A PUT replaces: what the body does not carry is cleared. A POST creates,
    // and a field it does not carry is simply not set.
    const orNull = (v: string | undefined) => v === undefined ? (replacing ? null : undefined) : v;
    return {
      // A user's display name is the core `displayName`; a group's is the extension's,
      // the core one on a Group being the realm's name (NOTES-on-scim.md §2).
      ...(kind === "user"
        ? { displayName: orNull(displayName) }
        : { displayName: orNull(ext("displayName")) }),
      ou: orNull(ext("ou")),
      ...(kind === "user" ? { home: orNull(ext("home")) } : {}),
      // The primary group, by name: the extension's own attribute, so it names the
      // group rather than its number as RFC 2307's gidNumber does over LDAP.
      ...(kind === "user" ? { primaryGroup: orNull(ext("primaryGroup")) } : {}),
      ...(kind === "user" ? { expires: orNull(ext("expires")) } : {}),
      // Only for a user, like every field above it. This line used to run for a group
      // too, so a `PUT /Groups/<id>` — whose body necessarily carries no `active`,
      // there being no such attribute on a Group — sent `disabled: false` to the write
      // path for a principal that has no such field. It was written and then dropped,
      // because `GroupSpec` of `dc-directory.ts` does not carry it, so nothing read it
      // back and nothing acted on it. `Writer.checkKind` now refuses it, which is what
      // turned this line into a failing request and is how it was found.
      ...(kind === "user"
        ? (active === undefined ? (replacing ? { disabled: false } : {}) : { disabled: !active })
        : {}),
    };
  }

  /** The members a Group's body names, as names of this realm. */
  private members(body: Record<string, unknown>): string[] | undefined {
    if (body.members === undefined) return undefined;
    if (!Array.isArray(body.members)) throw bad("members is an array", "invalidSyntax");
    return body.members.map((m) => {
      const value = (m as Record<string, unknown>)?.value;
      if (typeof value !== "string") throw bad("a member carries the value of the resource it names", "invalidValue");
      const found = this.nameOf(value, "user") ?? this.nameOf(value, "group");
      if (found === undefined) throw bad(`${value} is not a user or a group of this realm`, "invalidValue");
      return found;
    });
  }

  /** The certificates a body's extension carries. */
  private certificates(body: Record<string, unknown>): Certificate[] {
    const extension = (body[SCHEMA.extension] ?? {}) as Record<string, unknown>;
    return this.certificateList(extension.certificates);
  }

  /**
   * A list of certificates as a body or a PATCH value gives it.
   *
   * A certificate is named **either** by its fingerprint in `value` or by the
   * certificate itself — base 64 of its DER in `certificate`, or PEM in either —
   * and where the certificate itself is given it is kept, which RFC 4523 §2.1
   * requires of a value of that syntax.
   *
   * `certificate` used to be read-only here, so this front end could record only a
   * fingerprint while the LDAP one recorded the certificate, and a store written
   * over SCIM could not be made equal to the same store written over LDAP. That is
   * the first thing the phase E conformance test found, and it is a divergence of
   * exactly the shape DESIGN-admin.md §2 forbids: the rule for what a certificate
   * value is sat in the LDAP translation, where this one could not reach it, so
   * this one invented a narrower rule. The rule is now `Writer.certificateValue`.
   */
  private certificateList(held: unknown): Certificate[] {
    if (held === undefined || held === null) return [];
    const list = Array.isArray(held) ? held : [held];
    return list.map((c) => {
      const each = typeof c === "string" ? { value: c } : (c ?? {}) as Record<string, unknown>;
      const value = each.value;
      const itself = each.certificate;
      if (itself !== undefined && typeof itself !== "string") {
        throw bad("a certificate's certificate is base 64 of its DER, or PEM", "invalidValue");
      }
      if (value !== undefined && typeof value !== "string") {
        throw bad("a certificate carries its fingerprint, or itself, as value", "invalidValue");
      }
      const display = typeof each.display === "string" ? { display: each.display } : {};
      // What names the certificate: `certificate` where it is given, else `value`
      // unless `value` is a fingerprint, which names it without carrying it.
      const given = itself ?? (value !== undefined && !FINGERPRINT.test(value) ? value : undefined);
      if (given === undefined) {
        if (typeof value !== "string") {
          throw bad("a certificate carries its fingerprint, or itself, as value", "invalidValue");
        }
        return { value, ...display };
      }
      let der: Buffer;
      let fingerprint: string;
      try {
        // Base 64 of the DER is what the schema says `certificate` is; PEM, which
        // is also base 64, survives the round trip through latin-1 either way.
        const raw = /-----BEGIN CERTIFICATE-----/.test(given)
          ? Buffer.from(given, "latin1")
          : Buffer.from(given, "base64");
        ({ der, fingerprint } = Writer.certificateValue(raw));
      } catch (e) {
        throw bad(e instanceof Error ? e.message : "a certificate is not a certificate",
          "invalidValue");
      }
      if (typeof value === "string" && FINGERPRINT.test(value) && value !== fingerprint) {
        throw bad("the fingerprint given is not that of the certificate given", "invalidValue");
      }
      return { value: fingerprint, der, ...display };
    });
  }

  private text(body: Record<string, unknown>, key: string, required = false): string | undefined {
    const v = body[key];
    if (v === undefined || v === null) {
      if (required) throw bad(`${key} is given`, "invalidValue");
      return undefined;
    }
    if (typeof v !== "string" || v === "") throw bad(`${key} is a string, not empty`, "invalidValue");
    return v;
  }

  /** Whether an If-Match or If-None-Match value names a version. */
  private matchesAny(header: string | undefined, version: string): boolean {
    if (header === undefined || header === "") return false;
    if (header.trim() === "*") return true;
    // Compared weakly: "W/" is dropped on each side, as a weak comparison does.
    const weak = (s: string) => s.trim().replace(/^W\//, "");
    return header.split(",").some((h) => weak(h) === weak(version));
  }

  /**
   * If-Match on a write (RFC 7644 section 3.14): a mismatch is 412, so that two
   * administrators changing one principal do not silently overwrite each other.
   */
  private checkVersion(r: ScimRequest, kind: "user" | "group" | "unit", name: string): void {
    if (r.ifMatch === undefined || r.ifMatch === "") return;
    // A unit has its own times, as a principal does (store schema 3). While it had
    // none, PUT and DELETE of an Ou returned before this was ever reached, so
    // If-Match on one was accepted and ignored: two administrators could each
    // rename a unit under an ETag taken from their own read and the second silently
    // overwrote the first, which is the lost update the header exists to prevent.
    const times = kind === "unit" ? this.directory().unitTimes(name) : this.directory().timesOf(name);
    if (times.modified === undefined) {
      throw new ScimError(412,
        "this resource carries no version, so If-Match cannot be honoured: a directory kept " +
        "in the configuration records no history");
    }
    if (!this.matchesAny(r.ifMatch, etagOf(times.modified))) {
      throw new ScimError(412, `the resource has changed since ${r.ifMatch}`);
    }
  }

  /** Applies a change and rebuilds the directory every reader sees. */
  private async apply(change: () => Promise<void> | void): Promise<void> {
    try {
      await change();
    } finally {
      await this.rebuilt();
    }
  }

  /** A refusal of the write path as a SCIM error (RFC 7644 section 3.12). */
  private scimErrorOf(e: unknown): ScimError {
    if (e instanceof WriteError) {
      switch (e.code) {
        case "taken":
          return new ScimError(409, e.message, "uniqueness");
        case "absent":
          return new ScimError(404, e.message);
        case "invalid":
          return new ScimError(400, e.message, "invalidValue");
        case "conflict":
          return new ScimError(400, e.message, "invalidValue");
        case "limit":
          return new ScimError(400, e.message, "tooMany");
      }
    }
    return new ScimError(500, `this server could not apply the change: ${(e as Error).message}`);
  }
}

/** What the maximum page size is, for a caller reporting it. */
export const SCIM_MAX_RESULTS = MAX_RESULTS;
