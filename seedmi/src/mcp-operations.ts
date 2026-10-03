// The operations of the CDMI over MCP binding.
//
// "The CDMI server shall be the MCP server. The two are one server: the
// endpoint that accepts an MCP request is the endpoint that performs the
// operation, evaluates the access control lists that apply to it, and
// returns the result" (revision 347).
//
// Each tool is performed by the path that performs the operation for the
// protocol binding of clause 8's HTTP binding: a request is composed from
// the arguments of the call and handed to the same entry point, and the
// answer is read back into the result this subclause defines. The reason is
// not economy. Two paths would drift, and a defect fixed in one would stand
// in the other, which is the failure this implementation has already had
// five times with access control; here there is one path and no second
// place for a rule to be forgotten.
import { EventEmitter } from "node:events";
import type { IncomingMessage, ServerResponse } from "node:http";


/** What a call was answered with, before it becomes a tool result. */
export interface Answer {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/**
 * A request that did not arrive over a socket. Node's own types are
 * satisfied because the object is one: an IncomingMessage over a socket
 * that is never connected, whose method, url and headers are set here.
 */
export function composeRequest(method: string, url: string,
  headers: Record<string, string>, body?: string): IncomingMessage {
  // No socket: the request did not arrive over one, and the paths this
  // request is given to read only the address, which is this server.
  const socket = { remoteAddress: "127.0.0.1", remotePort: 0, destroy() {} };
  // A readable stream, not a bare emitter: the paths this request is
  // given may attach a reader after awaiting something, and an emitter
  // that has already emitted its body leaves such a reader waiting for
  // ever. A stream holds what was pushed until it is read.
  const req = new EventEmitter() as unknown as IncomingMessage;
  Object.assign(req, {
    method,
    url,
    headers: { ...headers, host: headers.host ?? "mcp.invalid" },
    httpVersion: "1.1",
    httpVersionMajor: 1,
    httpVersionMinor: 1,
    socket,
    connection: socket,
    complete: true,
    rawHeaders: Object.entries(headers).flat(),
  });
  // The body is held until a reader asks for it. A reader may attach
  // after awaiting something, so emitting at once would leave it waiting
  // for ever; these deliver on the turn after the listener arrives, and
  // "data" is emitted only once whichever way the body is read.
  let delivered = false;
  const deliver = () => {
    if (delivered) return;
    delivered = true;
    queueMicrotask(() => {
      if (body !== undefined && body !== "") req.emit("data", Buffer.from(body, "utf8"));
      req.emit("end");
    });
  };
  (req as unknown as EventEmitter).on("newListener", (event: string) => {
    if (event === "data" || event === "end" || event === "readable") deliver();
  });
  Object.assign(req, {
    setEncoding() { return req; },
    resume() { deliver(); return req; },
    pause() { return req; },
    read: () => null,
  });
  return req;
}

/** A response that collects what was written instead of sending it. */
export function collectResponse(): { res: ServerResponse; done: Promise<Answer> } {
  const parts: Buffer[] = [];
  let status = 200;
  const headers: Record<string, string> = {};
  let finish: (a: Answer) => void;
  const done = new Promise<Answer>((resolve) => { finish = resolve; });
  const res = new EventEmitter() as unknown as ServerResponse;
  const add = (v: unknown) => {
    if (v === undefined || v === null) return;
    for (const [k, value] of Object.entries(v as Record<string, unknown>)) {
      headers[k.toLowerCase()] = Array.isArray(value) ? value.join(", ") : String(value);
    }
  };
  Object.assign(res, {
    writeHead(code: number, a?: unknown, b?: unknown) {
      status = code;
      add(typeof a === "string" ? b : a);
      return res;
    },
    setHeader(k: string, v: unknown) {
      headers[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v);
      return res;
    },
    getHeader: (k: string) => headers[k.toLowerCase()],
    removeHeader(k: string) { delete headers[k.toLowerCase()]; },
    hasHeader: (k: string) => k.toLowerCase() in headers,
    flushHeaders() {},
    write(chunk: unknown) {
      if (chunk !== undefined) parts.push(Buffer.from(chunk as Buffer));
      return true;
    },
    end(chunk?: unknown) {
      if (chunk !== undefined && typeof chunk !== "function") {
        parts.push(Buffer.from(chunk as Buffer));
      }
      finish({ status, headers, body: Buffer.concat(parts).toString("utf8") });
      return res;
    },
    headersSent: false,
    statusCode: 200,
  });
  return { res, done };
}

/**
 * The address a call names. "The uri argument shall be a namespace path
 * ... resolved against the base URI", optionally carrying a query
 * component whose selections are those of the HTTP protocol binding, "so
 * that a CDMI client that knows one knows the other".
 */
export function addressOf(baseUri: string, uri: string): { path: string; query: string } {
  const hash = uri.indexOf("#");
  const bare = hash === -1 ? uri : uri.slice(0, hash);
  const q = bare.indexOf("?");
  const path = q === -1 ? bare : bare.slice(0, q);
  const query = q === -1 ? "" : bare.slice(q);
  const base = baseUri.endsWith("/") ? baseUri.slice(0, -1) : baseUri;
  return { path: `${base}${path.startsWith("/") ? path : `/${path}`}`, query };
}

/**
 * The result of a call that succeeded, in the members the subclause
 * defines. What is not known is left out rather than guessed at: a member
 * absent says the server reported nothing, which a client distinguishes
 * from a member holding an empty value.
 */
export function resultOf(args: {
  uri: string;
  representation: string | undefined;
  object: unknown;
  baseUri: string;
  correctedUri?: string;
  validator?: string;
  reference?: string;
  remote?: string[];
}): Record<string, unknown> {
  return {
    uri: args.uri,
    ...(args.representation === undefined ? {} : { representation: args.representation }),
    ...(args.object === undefined ? {} : { object: args.object }),
    ...(args.reference === undefined ? {} : { reference: args.reference }),
    baseUri: args.baseUri,
    ...(args.correctedUri === undefined ? {} : { correctedUri: args.correctedUri }),
    ...(args.remote === undefined ? {} : { remote: args.remote }),
    ...(args.validator === undefined ? {} : { validator: args.validator }),
  };
}

/**
 * An address the operation returned, as a namespace path of the base URI
 * the call was resolved against. A CDMI client of this protocol binding
 * supplies namespace paths and is answered with them; an absolute URI of
 * another base is left as it stands, since no path of this base names it.
 */
export function relativeToBase(location: string, baseUri: string,
  origin?: string): string {
  const absolute = /^https?:\/\//i.test(location);
  const path = absolute && origin !== undefined && location.startsWith(origin)
    ? location.slice(origin.length)
    : location;
  if (/^https?:\/\//i.test(path)) return path;
  const base = baseUri.replace(/^https?:\/\/[^/]+/i, "");
  const trimmed = base.endsWith("/") ? base.slice(0, -1) : base;
  return trimmed !== "" && path.startsWith(trimmed) ? path.slice(trimmed.length) : path;
}

/**
 * The number of children or values a selection asks for, where it asks
 * for a range of them. A selection naming no range asks for everything,
 * which the bound applies to silently; a range asks for a count, which is
 * refused where it exceeds the bound.
 */
export function rangeAsked(query: string): number | undefined {
  const m = /(?:children|value)=([0-9]+)-([0-9]+)/.exec(query);
  if (m === null) return undefined;
  return Number(m[2]) - Number(m[1]) + 1;
}

/**
 * The media type a representation argument names. "The type of the
 * representation, specified as the media type of the representations
 * table without the application/ prefix, for example cdmi-object": the
 * prefix is added back for the operation, which speaks media types, and
 * a value that already carries it is taken as given rather than refused.
 */
export function mediaTypeOf(representation: unknown): string | undefined {
  if (typeof representation !== "string" || representation === "") return undefined;
  return representation.includes("/") ? representation : `application/${representation}`;
}

/** And the other way, for the representation a result reports. */
export function representationOf(mediaType: string | undefined): string | undefined {
  if (mediaType === undefined) return undefined;
  return mediaType.startsWith("application/")
    ? mediaType.slice("application/".length)
    : mediaType;
}

/**
 * The addresses a result reports that are of another CDMI server: "a JSON
 * array of the absolute URIs so reported. A CDMI client reaches such an
 * address through the endpoint of that CDMI server", so that a client can
 * tell which addresses this endpoint will not serve. An address beneath a
 * base URI this server itself reports is its own and is not among them.
 */
export function remoteAddresses(object: Record<string, unknown>, ours: string[]): string[] {
  const found = new Set<string>();
  const mine = ours.filter((b) => /^https?:\/\//i.test(b));
  const walk = (v: unknown, depth = 0): void => {
    if (depth > 8) return;
    if (typeof v === "string") {
      if (/^https?:\/\//i.test(v) && !mine.some((b) => v.startsWith(b))) found.add(v);
      return;
    }
    if (Array.isArray(v)) {
      for (const e of v) walk(e, depth + 1);
      return;
    }
    if (typeof v === "object" && v !== null) {
      for (const e of Object.values(v as Record<string, unknown>)) walk(e, depth + 1);
    }
  };
  // The fields that carry an address of an object: a reference's
  // destination, the children of a listing, and the layers a result names.
  for (const f of ["reference", "children", "importsProvided", "exportsProvided", "domainURI"]) {
    walk(object[f]);
  }
  return [...found];
}
