// Requests a CDMI server originates: a request this server makes of its own to
// a URI a CDMI client supplied. The subclause "Requests a CDMI server
// originates" of the CDMI 3.0 draft (revision 211) governs each of them:
//
//   * a copy operation and a move operation whose source object is stored by
//     another CDMI server;
//   * a deserialization whose source object is stored by another CDMI server;
//   * an import, whose "import_uri" field addresses the import source; and
//   * a delegated access control request, whose "cdmi_dac_uri" metadata item
//     addresses the delegated access control provider.
//
// "A CDMI server shall make a server-originated request only to a URI that it
// is configured to permit. It shall determine that from a statement of the URIs
// permitted, and shall not determine it from a statement of the URIs
// forbidden". This server therefore permits nothing until it is configured, and
// `[[permit]]` tables of the configuration file state what it may reach.
//
// The subclause also requires that the address resolved be permitted and not
// the authority alone, that each redirection be permitted and their number
// limited, that the response read and the time waited be limited, and that
// nothing a CDMI client can read disclose the address resolved, the reason a
// request failed at the network layer, or the time it took. The last of those
// is why every failure here reports the same thing.

import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { lookup } from "node:dns/promises";
import { invalidField, limitExceeded } from "./problems.ts";

/** One entry of the permitted set: a URI prefix, and the addresses it may resolve to. */
export interface PermittedOrigin {
  /**
   * An absolute URI that a permitted URI begins with, compared after both are
   * normalized. A prefix ending in a solidus permits the subtree beneath it; one
   * that is an origin alone permits every URI of that origin. A port of "*"
   * permits every port of that host, which a deployment uses where the
   * counterparty's port is not fixed.
   */
  uri: string;
  /**
   * The addresses the authority of that URI may resolve to, each an address or
   * a CIDR range. Where the authority is an address literal, that address is
   * permitted without being stated here.
   */
  addresses: string[];
}

export interface OriginatedPolicy {
  permitted: PermittedOrigin[];
  /** Redirections followed; none by default. */
  maxRedirects: number;
  /** Octets read of a response; a longer response is the limit exceeded condition. */
  maxResponseBytes: number;
  /** Milliseconds waited for a response. */
  timeoutMs: number;
}

/** Nothing is permitted until the server is configured (the subclause's rule). */
export const DENY_ALL: OriginatedPolicy = Object.freeze({
  permitted: [], maxRedirects: 0, maxResponseBytes: 16 * 1024 * 1024, timeoutMs: 5000,
});

let policy: OriginatedPolicy = DENY_ALL;

/** Sets the policy; main.ts does this at start from the configuration. */
export function setOriginatedPolicy(p: OriginatedPolicy): void {
  policy = p;
}

export const originatedPolicy = (): OriginatedPolicy => policy;

/** Restores the deny-everything default, for a test that set one. */
export function forgetOriginatedPolicy(): void {
  policy = DENY_ALL;
}

// ---------------------------------------------------------------------------
// Addresses

/** Whether an address is within an address or CIDR range, for IPv4 and IPv6. */
export function withinRange(address: string, range: string): boolean {
  const [net, bitsText] = range.split("/");
  const a = octetsOf(address);
  const n = octetsOf(net);
  if (a === undefined || n === undefined || a.length !== n.length) return false;
  const bits = bitsText === undefined ? a.length * 8 : Number(bitsText);
  if (!Number.isInteger(bits) || bits < 0 || bits > a.length * 8) return false;
  for (let i = 0; i < a.length; i++) {
    const take = Math.min(8, Math.max(0, bits - i * 8));
    if (take === 0) break;
    const mask = 0xff << (8 - take) & 0xff;
    if ((a[i] & mask) !== (n[i] & mask)) return false;
  }
  return true;
}

/** An address as its octets: four for IPv4, sixteen for IPv6. */
function octetsOf(address: string): number[] | undefined {
  const kind = isIP(address);
  if (kind === 4) return address.split(".").map(Number);
  if (kind !== 6) return undefined;
  // An IPv6 address, with one "::" run and an optional trailing IPv4 form.
  let text = address;
  let tail: number[] = [];
  const dotted = /:((\d{1,3}\.){3}\d{1,3})$/.exec(text);
  if (dotted) {
    tail = dotted[1].split(".").map(Number);
    text = text.slice(0, dotted.index + 1);
  }
  const [left, right] = text.split("::") as [string, string | undefined];
  const parts = (s: string) => s.split(":").filter((p) => p !== "").map((p) => parseInt(p, 16));
  const head = parts(left);
  const rest = right === undefined ? [] : parts(right);
  const groups = 8 - tail.length / 2;
  const middle = new Array(Math.max(0, groups - head.length - rest.length)).fill(0);
  const all = [...head, ...middle, ...rest];
  const out: number[] = [];
  for (const g of all) out.push(g >> 8 & 0xff, g & 0xff);
  return [...out, ...tail];
}

// ---------------------------------------------------------------------------
// The permitted set

const normalize = (uri: string): string => {
  try {
    const u = new URL(uri);
    // The default port of a scheme is written by neither form.
    return `${u.protocol}//${u.host}${u.pathname}${u.search}`;
  } catch {
    return uri;
  }
};

/** The entry that permits a URI, or undefined where none does. */
export function permitting(uri: string, p: OriginatedPolicy = policy): PermittedOrigin | undefined {
  const target = normalize(uri);
  return p.permitted.find((entry) => {
    let prefix = normalize(entry.uri);
    if (prefix.includes(":*")) {
      // A wildcard port: the scheme, host and path are compared, and the port
      // of the target is whatever it may be.
      const [scheme, rest] = prefix.split("//");
      const [hostWithPort, ...path] = rest.split("/");
      const host = hostWithPort.slice(0, hostWithPort.lastIndexOf(":*"));
      const at = `${scheme}//${host}`;
      if (!target.startsWith(at)) return false;
      const after = target.slice(at.length);
      const port = /^(:\d+)?/.exec(after)![0];
      prefix = `${at}${port}${path.length > 0 ? "/" + path.join("/") : ""}`;
    }
    if (!target.startsWith(prefix)) return false;
    // A prefix that is an origin alone, or ends in a solidus, permits what lies
    // beneath it; any other prefix permits the URI it names and its subtree.
    const rest = target.slice(prefix.length);
    return prefix.endsWith("/") || rest === "" || rest.startsWith("/") || rest.startsWith("?");
  });
}

/**
 * Checks a URI a CDMI client supplied, before anything is done with it. "Where a
 * CDMI client supplies a URI the CDMI server is not configured to permit, the
 * CDMI server shall report the invalid field condition ..., naming the field
 * that carries the URI." The message says that the URI is not permitted and
 * nothing else.
 */
export function checkPermitted(uri: string, field: string): void {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw invalidField(field, "%j is not an absolute URI", uri);
  }
  // The schemes a mechanism defines are that mechanism's to state; this
  // subclause governs which URIs may be reached, whatever the scheme.
  void parsed;
  if (permitting(uri) === undefined) {
    throw invalidField(field, "this server is not configured to make a request to %j", uri);
  }
}

/** Whether a URI is permitted, without reporting. */
export const isPermitted = (uri: string): boolean => permitting(uri) !== undefined;

// ---------------------------------------------------------------------------
// Making the request

/**
 * A request this server originates failed. The message names no address, no
 * network-layer reason and no timing, because "a CDMI client that can observe
 * the address resolved on outgoing server connections, the reason for a
 * network-layer failure, or the time a request took, can use this information
 * to learn which endpoints are reachable from the CDMI server".
 */
export class OriginatedError extends Error {
  constructor(message = "the request could not be completed") {
    super(message);
    this.name = "OriginatedError";
  }
}

export interface Resolved {
  /** The address to connect to, which is the one checked. */
  address: string;
  family: 4 | 6;
}

/**
 * Resolves the authority of a URI and checks the address against the entry that
 * permits the URI. The address returned is the one the caller connects to, so
 * that the address checked and the address used are the same and a second
 * resolution cannot return another.
 */
export async function resolveAndCheck(uri: string, p: OriginatedPolicy = policy): Promise<Resolved> {
  const entry = permitting(uri, p);
  if (entry === undefined) throw new OriginatedError("the URI is not permitted");
  const host = new URL(uri).hostname.replace(/^\[|\]$/g, "");
  let address: string;
  let family: 4 | 6;
  if (isIP(host) !== 0) {
    address = host;
    family = isIP(host) === 4 ? 4 : 6;
  } else {
    try {
      const r = await lookup(host);
      address = r.address;
      family = r.family === 6 ? 6 : 4;
    } catch {
      // Not "no such host", which tells a CDMI client what does not resolve.
      throw new OriginatedError();
    }
  }
  // An authority that is an address literal is permitted by the entry that
  // permits the URI; any other authority resolves to an address the entry
  // states. The authority alone is never enough.
  const permittedAddress = isIP(host) !== 0
    ? entry.addresses.length === 0 || entry.addresses.some((r) => withinRange(address, r))
    : entry.addresses.some((r) => withinRange(address, r));
  if (!permittedAddress) throw new OriginatedError("the URI is not permitted");
  return { address, family };
}

export interface OriginatedResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  /** The URI finally requested, after any redirection. */
  uri: string;
}

/**
 * Checks a redirection: the URI named must be permitted, of a scheme the
 * mechanism defines, and within the number of redirections configured.
 */
export function checkRedirection(from: string, location: string, followed: number, p: OriginatedPolicy = policy): string {
  if (followed >= p.maxRedirects) throw new OriginatedError("the request could not be completed");
  let next: string;
  try {
    next = new URL(location, from).toString();
  } catch {
    throw new OriginatedError();
  }
  const scheme = new URL(next).protocol;
  if (scheme !== "http:" && scheme !== "https:") throw new OriginatedError("the URI is not permitted");
  if (permitting(next, p) === undefined) throw new OriginatedError("the URI is not permitted");
  return next;
}

/**
 * Submits a request this server originates and returns the response, applying
 * every rule of the subclause: the URI is permitted, the address resolved is
 * permitted and is the address connected to, the wait and the response read
 * are limited, and a redirection is followed only where it is permitted and
 * within the number configured. A failure names no address, no network-layer
 * reason and no timing.
 */
export async function submitOriginated(uri: string, req: {
  method?: string;
  body?: Buffer;
  contentType?: string;
  accept?: string;
  /** Header fields the caller sets, such as Authorization or a conditional field. */
  headers?: Record<string, string>;
  /** Trust anchors for a TLS connection, in PEM, where the default set is not used. */
  ca?: string;
}, p: OriginatedPolicy = policy): Promise<OriginatedResponse> {
  let target = uri;
  for (let followed = 0; ; followed++) {
    const answer = await once(target, req, p);
    const location = answer.status >= 300 && answer.status < 400
      ? (answer.headers.location as string | undefined) : undefined;
    if (location === undefined || location === "") return answer;
    target = checkRedirection(target, location, followed, p);
  }
}

async function once(target: string, req: {
  method?: string; body?: Buffer; contentType?: string; accept?: string; ca?: string;
  headers?: Record<string, string>;
}, p: OriginatedPolicy): Promise<OriginatedResponse> {
  const url = new URL(target);
  const secure = url.protocol === "https:";
  if (!secure && url.protocol !== "http:") throw new OriginatedError("the URI is not permitted");
  const at = await resolveAndCheck(target, p);
  const headers: Record<string, string> = { Host: url.host };
  if (req.body !== undefined) {
    headers["Content-Type"] = req.contentType ?? "application/json";
    headers["Content-Length"] = String(req.body.length);
  }
  if (req.accept !== undefined) headers.Accept = req.accept;
  // Header fields the caller sets: the Authorization an import presents to
  // an origin server, and the conditional fields that revalidate a value.
  // The Host and the fields above are this mechanism's and are not
  // overridden.
  for (const [k, v] of Object.entries(req.headers ?? {})) {
    if (!["host", "content-type", "content-length"].includes(k.toLowerCase())) headers[k] = v;
  }
  const send = secure ? httpsRequest : httpRequest;
  return new Promise<OriginatedResponse>((resolve, reject) => {
    const request = send({
      protocol: url.protocol,
      hostname: at.address,
      ...(secure ? { servername: url.hostname, ...(req.ca === undefined ? {} : { ca: req.ca }) } : {}),
      port: url.port === "" ? undefined : Number(url.port),
      path: url.pathname + url.search,
      method: req.method ?? "GET",
      headers,
    }, (res: {
      statusCode: number;
      headers: Record<string, string | string[] | undefined>;
      on: (e: string, f: (c?: Buffer) => void) => void;
      destroy: () => void;
    }) => {
      const chunks: Buffer[] = [];
      let read = 0;
      let stopped = false;
      res.on("data", (c?: Buffer) => {
        if (stopped) return;
        const chunk = c as Buffer;
        read += chunk.length;
        if (read > p.maxResponseBytes) {
          stopped = true;
          res.destroy();
          reject(new OriginatedTooLarge());
          return;
        }
        chunks.push(chunk);
      });
      res.on("end", () => {
        if (stopped) return;
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks), uri: target });
      });
    });
    request.setTimeout(p.timeoutMs, () => {
      request.destroy();
      reject(new OriginatedError());
    });
    request.on("error", () => reject(new OriginatedError()));
    if (req.body !== undefined) request.write(req.body);
    request.end();
  });
}

/** The response exceeded the size this server reads (the limit exceeded condition). */
export class OriginatedTooLarge extends OriginatedError {
  constructor() {
    super("the response exceeded the size this server reads");
    this.name = "OriginatedTooLarge";
  }
}

/** The condition reported where a response exceeds what this server reads. */
export const responseTooLarge = (field: string) =>
  limitExceeded(field, "the response exceeded the size this server reads");
