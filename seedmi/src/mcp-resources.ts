// CDMI over MCP: resources.
//
// The Model Context Protocol calls a piece of context addressed by a URI a
// resource, and gives a client three methods over them: resources/list,
// resources/templates/list and resources/read. The CDMI over MCP subclause
// standardized the five tools and left resources out, so what is here is an
// extension of this server's and not a requirement of the document — offered as
// a proposal for a future revision of the subclause (cvwm R3).
//
// There is no CDMI URI scheme to invent. Every object of a CDMI server is
// already addressed by an http or https URI, being the base URI and the
// namespace path, and that is the URI a client would GET over the HTTP protocol
// binding or supply as the uri argument of a tool. So a resource of this server
// is that URI, which means one address serves all three protocol bindings and a
// client that reads a resource and then calls a tool on it resolves both
// against the same base.
//
// The revision says of the https scheme that a server "SHOULD use this scheme
// only when the client is able to fetch and load the resource directly from the
// web on its own — that is, it doesn't need to read the resource via the MCP
// server". That holds here: a client holding the access token it presented to
// this endpoint can GET the same URI over the HTTP protocol binding and be
// served the same representation by the same access control evaluation. The
// resource URI is not a private name for something only this channel can reach.
//
// A resources/read is an ordinary authenticated, authorized operation. It is
// performed by dispatching a cdmi_read against the same principal, through the
// same path a tools/call takes, so the token resolution, the scope check, the
// access control lists and the conditions are that path's. Nothing about this
// channel is a way around access control, and there is no second place for a
// rule to be forgotten.
import { PROBLEM_BASE } from "./problems.ts";

/** The media types of the representations, for what a read reports. */
const CDMI_TYPES = [
  "application/cdmi-object", "application/cdmi-container", "application/cdmi-queue",
  "application/cdmi-domain", "application/cdmi-capability",
];

/**
 * The paths this server lists as resources: the entry points of the namespace,
 * and not the namespace itself.
 *
 * A CDMI namespace is unbounded, so a complete listing is not a thing a server
 * can return, and the revision requires the listed set not to "vary
 * per-connection or as a side effect of other requests on the connection".
 * These three are fixed for every client of every deployment: the root of the
 * namespace, the capability objects a client reads to learn what the server
 * implements, and the domain objects. Everything beneath them is reached
 * through the template of resourceTemplates and read by resources/read, and the
 * children of a container come back in the representation of that container, so
 * a browsing client walks the tree by reading it.
 */
const ENTRY_POINTS: { path: string; name: string; title: string; description: string; type: string }[] = [
  {
    path: "",
    name: "namespace",
    title: "The CDMI namespace",
    description: "The root container object, whose representation lists its children.",
    type: "application/cdmi-container",
  },
  {
    path: "cdmi_capabilities/",
    name: "capabilities",
    title: "Capabilities",
    description: "The capability objects, which report what this CDMI server implements. " +
      "A client reads these before it relies on an operation.",
    type: "application/cdmi-capability",
  },
  {
    path: "cdmi_domains/",
    name: "domains",
    title: "Domains",
    description: "The domain objects, which hold the accounting and the principals of a domain.",
    type: "application/cdmi-domain",
  },
];

/** The absolute form of a base URI, or undefined where it is a path alone. */
const absolute = (base: string): string | undefined =>
  /^https?:\/\//i.test(base) ? base.replace(/\/+$/, "/") : undefined;

/**
 * The resources this server lists. Where a base URI is a path rather than an
 * absolute URI — which the base of this server's own namespace is until an
 * export establishes one — it is not listed, a resource being addressed by URI
 * and a client having nothing to resolve a bare path against.
 */
export function resourceList(baseUris: string[]): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const base of baseUris) {
    const root = absolute(base);
    if (root === undefined) continue;
    for (const e of ENTRY_POINTS) {
      out.push({
        uri: `${root}${e.path}`,
        name: e.name,
        title: e.title,
        description: e.description,
        mimeType: e.type,
      });
    }
  }
  return out;
}

/**
 * The templates by which any other object is addressed. One per base URI, with
 * "{+path}" for the namespace path: the reserved expansion of RFC 6570, because
 * a namespace path contains the solidus that separates its segments and the
 * simple expansion would escape them.
 *
 * A second template carries a query component, the selections of the HTTP
 * protocol binding being valid in a resource URI exactly as they are in the uri
 * argument of a tool — so a client that wants one field of an object asks for
 * that field rather than reading the whole representation.
 */
export function resourceTemplates(baseUris: string[]): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const base of baseUris) {
    const root = absolute(base);
    if (root === undefined) continue;
    out.push({
      uriTemplate: `${root}{+path}`,
      name: "object",
      title: "Any object by namespace path",
      description: "An object of this CDMI server, addressed by its namespace path. A path " +
        "naming a container object, a capability object or a domain object ends with a solidus.",
      mimeType: "application/cdmi-object",
    });
    out.push({
      uriTemplate: `${root}{+path}?{selection}`,
      name: "selection",
      title: "Selected fields of an object",
      description: "The fields of an object a selection names, in the form the HTTP protocol " +
        'binding defines, as "metadata&mimetype" or "value=0-1023".',
      mimeType: "application/cdmi-object",
    });
  }
  return out;
}

/**
 * The namespace path and selection a resource URI names, against the base URIs
 * this server serves, or undefined where the URI is not of this server.
 *
 * A URI that is not beneath a base URI this server reports is not refused for
 * being unreachable but for naming something this endpoint does not serve: the
 * revision permits a client to fetch an https resource itself, so a client that
 * holds such a URI has a way to read it that does not involve this method.
 */
export function pathOfResource(uri: string, baseUris: string[]):
  { uri: string; base: string } | undefined {
  for (const base of baseUris) {
    const root = absolute(base);
    if (root === undefined) continue;
    if (!uri.startsWith(root)) continue;
    const rest = uri.slice(root.length - 1);
    return { uri: rest === "" ? "/" : rest, base };
  }
  return undefined;
}

/**
 * The contents of a read, from the representation the operation returned.
 *
 * A data object's value is the resource's content, carried as text or as a blob
 * according to the transfer encoding the representation states — "resources can
 * contain either text or binary data", and a value this server holds as base 64
 * is binary by the same token. Every other object type has no value, so its
 * representation is the content, as the JSON document it is.
 */
export function contentsOf(uri: string, object: Record<string, unknown>):
  Record<string, unknown>[] {
  const type = String(object.objectType ?? "");
  const value = object.value;
  if (type === "application/cdmi-object" && typeof value === "string") {
    const binary = String(object.valuetransferencoding ?? "utf-8") === "base64";
    return [{
      uri,
      mimeType: String(object.mimetype ?? "application/octet-stream"),
      ...(binary ? { blob: value } : { text: value }),
    }];
  }
  return [{
    uri,
    mimeType: CDMI_TYPES.includes(type) ? type : "application/json",
    text: JSON.stringify(object, undefined, 2),
  }];
}

/**
 * The JSON-RPC error code for a condition the operation reported.
 *
 * "If the requested resource does not exist, servers MUST return a JSON-RPC
 * error with code -32602 (Invalid Params). Servers SHOULD return -32603 for
 * internal errors." There is no resources/read result that reports a condition
 * — unlike a tool result, which carries isError — so every condition of this
 * method is a JSON-RPC error, and the problem details document goes in the data
 * member as it does for every other error of this binding. The condition itself
 * decides which of the two codes: one attributable to the request is the first,
 * and one this server owns is the second.
 */
export function codeOfProblem(problem: Record<string, unknown> | undefined): number {
  const type = String(problem?.type ?? "");
  if (!type.startsWith(PROBLEM_BASE)) return -32603;
  const condition = type.slice(PROBLEM_BASE.length);
  // The conditions this server reports of itself rather than of the request.
  return ["internal-error", "unavailable", "delegation-unavailable"].includes(condition)
    ? -32603
    : -32602;
}
