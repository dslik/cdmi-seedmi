// Cross-origin requests.
//
// Cross-origin resource sharing is not access control. It decides
// whether a browser makes a response available to the application that
// made the request; it does not decide whether the server performs the
// operation. Every cross-origin request is authenticated and authorised
// exactly as any other, and the header fields here are added to a
// response that was already going to be sent.
//
// The configuration is three data system metadata items on the object
// operated on. Data system metadata is inherited, so an item set on a
// container object configures everything within it, and one set of
// items configures a whole export.

import type { IncomingMessage, ServerResponse } from "node:http";
import type { Node, Store } from "./store.ts";

export const CORS_ORIGINS = "cdmi_cors_origins";
export const CORS_METHODS = "cdmi_cors_methods";
export const CORS_HEADERS = "cdmi_cors_headers";

/** How long a browser may reuse a preflight response, in seconds. */
const MAX_AGE = 600;

/**
 * The header fields of a response that this document defines or
 * requires. A browser makes none but the safelisted ones available to
 * an application unless they are named, so without this a client could
 * not read the Location of a create or the ETag of a read.
 */
const EXPOSED = [
  "Location", "ETag", "Last-Modified", "Content-Range", "Accept-Ranges",
  "X-CDMI-Specification-Version", "Allow", "Content-Type", "Content-Length",
  "Cache-Control", "Vary",
];

/** The three items, as they apply to one object. */
export interface CorsConfig {
  origins: string[];
  methods: string[];
  headers: string[];
}

/**
 * The items that apply to the object at a namespace path. Data system
 * metadata is inherited from the parent container object where it is
 * not specified, so the walk goes up until an item is found or the
 * root is passed.
 */
export function corsConfigOf(store: Store, ns: string): CorsConfig {
  const out: CorsConfig = { origins: [], methods: [], headers: [] };
  const want: [keyof CorsConfig, string][] = [
    ["origins", CORS_ORIGINS], ["methods", CORS_METHODS], ["headers", CORS_HEADERS],
  ];
  let node: Node | undefined = nearest(store, ns);
  const found = new Set<string>();
  while (node && found.size < want.length) {
    let m;
    try {
      m = store.meta(node);
    } catch {
      break;
    }
    for (const [key, item] of want) {
      if (found.has(key)) continue;
      const v = m.metadata[item];
      if (v === undefined) continue;
      found.add(key);
      if (Array.isArray(v)) {
        out[key] = v.filter((x): x is string => typeof x === "string");
      }
    }
    node = m.parent === null ? undefined : { id: m.parent, isContainer: true };
  }
  return out;
}

/**
 * The object a request addresses, or the nearest ancestor container
 * object that exists. A preflight response is answered from the nearest
 * ancestor where the object is absent, so that it does not disclose
 * whether the object is there.
 */
function nearest(store: Store, ns: string): Node | undefined {
  let path = ns;
  for (;;) {
    try {
      return store.resolve(path);
    } catch {
      if (path === "/" || path === "") return undefined;
      const trimmed = path.replace(/\/$/, "");
      const cut = trimmed.lastIndexOf("/");
      path = cut <= 0 ? "/" : trimmed.slice(0, cut + 1);
    }
  }
}

/** The origin of a request, where it states one. */
export function originOf(req: IncomingMessage): string | undefined {
  const o = req.headers.origin as string | undefined;
  return o === undefined || o === "" || o === "null" ? undefined : o;
}

/** Whether a request presents credentials of any kind. */
export function credentialed(req: IncomingMessage): boolean {
  return req.headers.authorization !== undefined || req.headers.cookie !== undefined;
}

/** Whether a request is a preflight request. */
export function isPreflight(req: IncomingMessage): boolean {
  return (req.method ?? "GET") === "OPTIONS" &&
    originOf(req) !== undefined &&
    req.headers["access-control-request-method"] !== undefined;
}

/**
 * The value of the Access-Control-Allow-Origin header field, or
 * undefined where the request is not permitted. A value of "*" permits
 * a request that presents no credentials only: a browser rejects a
 * credentialed response carrying the wildcard, and reflecting the
 * origin in its place would grant every origin credentialed access.
 */
export function allowedOrigin(config: CorsConfig, origin: string,
  withCredentials: boolean): string | undefined {
  if (config.origins.includes(origin)) return origin;
  if (config.origins.includes("*")) return withCredentials ? undefined : "*";
  return undefined;
}

/**
 * Answers a preflight request. A preflight request is not
 * authenticated and the access control lists of the object are not
 * evaluated, because a browser presents no credentials on one.
 */
export function answerPreflight(store: Store, req: IncomingMessage, res: ServerResponse,
  ns: string, methodsOfObject: string[]): void {
  const origin = originOf(req)!;
  const config = corsConfigOf(store, ns);
  // A preflight request carries no credentials, so the wildcard applies.
  const allow = allowedOrigin(config, origin, false);
  const wanted = String(req.headers["access-control-request-method"] ?? "").toUpperCase();
  const methods = config.methods
    .map((m) => m.toUpperCase())
    .filter((m) => m === wanted && methodsOfObject.includes(m));

  if (allow === undefined || methods.length === 0) {
    // Without any Access-Control- header field the browser fails the
    // request, which is the answer where the origin or the method is
    // not permitted.
    res.writeHead(204, { Vary: "Origin", "Content-Length": "0" });
    res.end();
    return;
  }

  const asked = String(req.headers["access-control-request-headers"] ?? "")
    .split(",").map((h) => h.trim()).filter(Boolean);
  const permitted = new Set(config.headers.map((h) => h.toLowerCase()));
  const headers = asked.filter((h) => permitted.has(h.toLowerCase()));

  const out: Record<string, string> = {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": methods.join(", "),
    "Access-Control-Max-Age": String(MAX_AGE),
    Vary: "Origin",
    "Content-Length": "0",
  };
  if (headers.length > 0) out["Access-Control-Allow-Headers"] = headers.join(", ");
  // The wildcard is never combined with credentials.
  if (allow !== "*" && config.origins.includes(origin)) {
    out["Access-Control-Allow-Credentials"] = "true";
  }
  res.writeHead(204, out);
  res.end();
}

/**
 * Sets the header fields a cross-origin request that is not a preflight
 * request carries. The operation is performed whatever this decides:
 * where the origin is not permitted no header field is set, and the
 * browser withholds the response from the application that made it.
 */
export function applyCors(store: Store, req: IncomingMessage, res: ServerResponse,
  ns: string): void {
  const origin = originOf(req);
  if (origin === undefined) return;
  // Vary names Origin whether or not the request is permitted, so that
  // a cache does not return a response prepared for one origin to a
  // request from another.
  addVary(res, "Origin");
  const withCredentials = credentialed(req);
  const config = corsConfigOf(store, ns);
  const allow = allowedOrigin(config, origin, withCredentials);
  if (allow === undefined) return;
  res.setHeader("Access-Control-Allow-Origin", allow);
  if (withCredentials && config.origins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Access-Control-Expose-Headers", EXPOSED.join(", "));
}

/** Adds a field name to the Vary header field of a response. */
export function addVary(res: ServerResponse, name: string): void {
  const current = String(res.getHeader("Vary") ?? "");
  const names = current.split(",").map((s) => s.trim()).filter(Boolean);
  if (!names.some((n) => n.toLowerCase() === name.toLowerCase())) names.push(name);
  res.setHeader("Vary", names.join(", "));
}

/**
 * Whether the three items are well formed. They are data system
 * metadata, so a client supplies them in the metadata field, and a
 * value that is not an array of strings is an invalid field.
 */
export function checkCorsItems(metadata: Record<string, unknown>):
  { item: string; why: string } | undefined {
  for (const item of [CORS_ORIGINS, CORS_METHODS, CORS_HEADERS]) {
    const v = metadata[item];
    if (v === undefined || v === null) continue;
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
      return { item, why: "shall be a JSON array of JSON strings" };
    }
    if (item === CORS_METHODS) {
      for (const m of v as string[]) {
        if (!/^[A-Za-z]+$/.test(m)) {
          return { item, why: `${JSON.stringify(m)} is not an HTTP method name` };
        }
      }
    }
    if (item === CORS_HEADERS) {
      for (const h of v as string[]) {
        if (!/^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(h)) {
          return { item, why: `${JSON.stringify(h)} is not a header field name` };
        }
      }
    }
  }
  return undefined;
}

// --- listeners of this server's own -------------------------------------------
//
// The CDMI over MCP endpoint and the built-in authorization server are
// listeners of their own, not objects, so the three data system metadata items
// above do not configure them: what they answer is configured, in [mcp].origins
// and [oauth].server_origins.
//
// Neither returned a single Access-Control- header field before 0.92, and
// neither answered a preflight request. A browser therefore withheld every
// response from the application that made the request — which is every client
// that runs in a browser, the whole reason this endpoint is reached
// cross-origin at all. Validating the Origin field, which 0.90 added, decides
// whether the server answers; these fields decide whether the browser hands
// that answer to the page. A server that does the first and not the second
// refuses nothing and is readable by nobody.

/** How long a browser may reuse a preflight response of a listener, in seconds. */
const LISTENER_MAX_AGE = 600;

/**
 * Whether an origin is one a listener answers, given what it was configured
 * with and the origin it is served at.
 */
export function listenerAllows(permitted: string[], origin: string, own?: string): boolean {
  if (permitted.includes("*") || permitted.includes(origin)) return true;
  if (permitted.length > 0) return false;
  // Where none is configured, a listener answers its own origin: a page served
  // from where the listener is served is not the cross-origin case at all.
  if (own === undefined) return false;
  try {
    return origin === new URL(own).origin;
  } catch {
    return false;
  }
}

/**
 * The header fields a listener returns on an ordinary response.
 *
 * The origin is echoed where it was named, and the wildcard returned where the
 * wildcard was configured. The two differ in one way that matters: a browser
 * refuses a response carrying the wildcard to a request made in the credentials
 * mode that sends cookies, so only a named origin is told that credentials are
 * allowed. A bearer token in an Authorization header field is not that mode —
 * it is a header the page sets — so the wildcard serves a token-bearing client
 * perfectly well, and only a client that sends cookies needs its origin named.
 */
export function listenerCors(permitted: string[], origin: string | undefined,
  opts: { own?: string; expose?: string[]; cookie?: boolean } = {}): Record<string, string> | undefined {
  if (origin === undefined || !listenerAllows(permitted, origin, opts.own)) return undefined;
  // The origin is echoed even where the wildcard permitted it, and credentials
  // are allowed with it.
  //
  // A literal "*" is refused by a browser for a request made in the credentials
  // mode that sends cookies, and some clients make every request in that mode.
  // Emitting "*" therefore broke a client that a configured "*" was meant to
  // serve. Echoing the origin instead costs nothing here: these listeners
  // authenticate by a header field the page sets — Bearer, Basic or Negotiate —
  // and by no cookie anywhere, so "Allow-Credentials" hands out no ambient
  // authority that an origin did not already have to supply for itself.
  //
  // The exception keeps that true rather than merely observing it: where the
  // request does carry a cookie and only the wildcard permitted the origin, the
  // literal wildcard is emitted, which a browser will not combine with
  // credentials. A configured wildcard is then never the reason a cookie was
  // readable by an arbitrary origin, whatever some later surface may add.
  const wildcardOnly = !permitted.includes(origin) && permitted.includes("*");
  const bare = wildcardOnly && opts.cookie === true;
  return {
    "Access-Control-Allow-Origin": bare ? "*" : origin,
    ...(bare ? {} : { "Access-Control-Allow-Credentials": "true" }),
    // A browser makes no header field but the safelisted ones available to the
    // application unless it is named here. WWW-Authenticate is the one that
    // matters: a client meeting a 401 reads the resource_metadata parameter
    // from it to find where to obtain a token, which is the whole of the
    // discovery RFC 9728 defines. Unexposed, a browser client meets a 401 it
    // cannot read and has nowhere to go.
    ...(opts.expose === undefined || opts.expose.length === 0
      ? {}
      : { "Access-Control-Expose-Headers": opts.expose.join(", ") }),
    // Whether the request is permitted or not, so that a cache does not hand a
    // response prepared for one origin to a request from another.
    Vary: "Origin",
  };
}

/**
 * The cross-origin fields of a listener's response, with Vary named whenever an
 * origin was presented.
 *
 * Vary names Origin whether or not the request is permitted, so that a cache
 * does not hand a response prepared for one origin — including a refusal — to a
 * request from another.
 */
export function listenerCorsOrVary(permitted: string[], origin: string | undefined,
  opts: { own?: string; expose?: string[]; cookie?: boolean } = {}): Record<string, string> {
  if (origin === undefined) return {};
  return listenerCors(permitted, origin, opts) ?? { Vary: "Origin" };
}

/**
 * Answers a preflight request to a listener of this server's own.
 *
 * A preflight carries no credentials — a browser never sends an Authorization
 * header field on one — so it is answered before anything is authenticated.
 * A server that required a token here would refuse the request that asks
 * whether the real request may be sent, and the real request would never be
 * made.
 */
export function answerListenerPreflight(permitted: string[], req: IncomingMessage,
  res: ServerResponse, opts: { own?: string; methods: string[]; headers: string[]; expose?: string[] }): void {
  const origin = originOf(req);
  // A preflight carries no cookie, a browser sending none on one.
  const fields = listenerCors(permitted, origin, { ...(opts.own === undefined ? {} : { own: opts.own }),
    ...(opts.expose === undefined ? {} : { expose: opts.expose }) });
  if (fields === undefined) {
    // Without any Access-Control- header field the browser fails the request,
    // which is the answer where the origin is not one this listener answers.
    res.writeHead(204, { Vary: "Origin", "Content-Length": "0" }).end();
    return;
  }

  const asked = String(req.headers["access-control-request-headers"] ?? "")
    .split(",").map((h) => h.trim()).filter(Boolean);
  const permittedHeaders = new Set(opts.headers.map((h) => h.toLowerCase()));
  // The header fields this listener reads, and any the transport lets a server
  // designate for itself. A wildcard is not used: the Fetch standard excludes
  // Authorization from it, so a wildcard would refuse the one field every
  // request to these listeners carries.
  const allowed = asked.filter((h) =>
    permittedHeaders.has(h.toLowerCase()) || h.toLowerCase().startsWith("mcp-param-"));
  res.writeHead(204, {
    ...fields,
    "Access-Control-Allow-Methods": opts.methods.join(", "),
    ...(allowed.length === 0 ? {} : { "Access-Control-Allow-Headers": allowed.join(", ") }),
    "Access-Control-Max-Age": String(LISTENER_MAX_AGE),
    "Content-Length": "0",
  }).end();
}
