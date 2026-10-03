// seedmi pipes (PLAN-pipe.md, RELAY-draft-2.md): the decisions, apart from any
// protocol. A pipe is a queue object whose cdmi_queue_type is "seedmi_pipe";
// a connection through it names its destination in a ticket request, and is
// made when a WebSocket presents the ticket.
//
// This module decides: which [[pipe_permit]] admits a principal to a
// destination; whether every address the destination's name resolves to is
// within that permit; which address is pinned; the tickets, single-use,
// short-lived and bound to the principal, the pipe, the destination, the address
// and the origin; and the limits, per principal, per pipe and in total, tickets
// not yet used counted with connections open.
//
// Nothing it returns to a client says why a request was refused, what was
// resolved, or how a connection failed: "a CDMI server shall not report ... the
// address it resolved, the reason a server-originated request failed at the
// network layer, or the time a server-originated request took". The reasons are
// for the log alone.

import { randomBytes } from "node:crypto";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import type { Principal } from "./acl.ts";
import { withinRange } from "./originated.ts";

export const PIPE_QUEUE_TYPE = "seedmi_pipe";
export const TICKET_MEDIA_TYPE = "application/vnd.seedmi.pipe-ticket+json";
export const SUBPROTOCOL = "seedmi-pipe.v1";

export interface PipePermit {
  name: string;
  /** DNS names; a wildcard is the leftmost label alone, and matches one label. */
  hosts: string[];
  /**
   * The ports permitted, or "*" for any port.
   *
   * A wildcard was refused, on the reasoning that a permit should name what it
   * admits. It is accepted since 0.86: a destination reached through a pipe is
   * already confined by the host names and by the address ranges every resolved
   * address must be within, and a deployment that must list every port a
   * service may answer on either enumerates thousands of them or gives up on
   * pipes. The addresses remain the control that matters, and the wildcard says
   * so in the configuration rather than being approximated by a long list.
   */
  ports: number[] | "*";
  /** Address ranges every resolved address must be within. */
  addresses: string[];
  /** Where given, the principals admitted, and members of the groups admitted. */
  principals?: string[];
  groups?: string[];
  /** Where given, the domains through whose pipes alone the permit is used. */
  domains?: string[];
}

export interface PipesConfig {
  enabled: boolean;
  allowAnonymous: boolean;
  /** Seconds. */
  ticketTtl: number;
  connectTimeout: number;
  idleTimeout: number;
  maxLifetime: number;
  maxConnections: number;
  maxConnectionsPerPipe: number;
  maxConnectionsTotal: number;
  /** Octets: the largest WebSocket frame or message read. */
  maxFrame: number;
  permits: PipePermit[];
}

export const PIPE_DEFAULTS: Omit<PipesConfig, "permits"> = {
  enabled: false, allowAnonymous: false, ticketTtl: 30, connectTimeout: 10, idleTimeout: 600, maxLifetime: 43200,
  maxConnections: 32, maxConnectionsPerPipe: 64, maxConnectionsTotal: 256, maxFrame: 1 << 20,
};

/** The addresses a name resolves to; replaced in a test. */
export type Resolve = (host: string) => Promise<string[]>;
export const resolveAll: Resolve = async (host) => (await lookup(host, { all: true, verbatim: true })).map((a) => a.address);

export interface Ticket {
  id: string;
  principal: Principal;
  pipe: number;
  domain: string;
  host: string;
  port: number;
  address: string;
  origin: string | undefined;
  expires: number;
  permit: string;
}

/** A refusal: the status, and the reason, for the log alone. */
export interface Refused { ok: false; status: 400 | 403 | 429; reason: string }

const ANONYMOUS = "ANONYMOUS@";
/** A DNS name: labels of letters, digits and hyphens, not beginning or ending with a hyphen. */
const HOSTNAME = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$/;

/** Whether a host matches a permit's name: exactly, or a wildcard standing for its leftmost label alone. */
export function hostMatches(pattern: string, host: string): boolean {
  const p = pattern.toLowerCase().replace(/\.$/, ""), h = host.toLowerCase().replace(/\.$/, "");
  if (!p.startsWith("*.")) return p === h;
  const rest = p.slice(2), dot = h.indexOf(".");
  return dot > 0 && h.slice(dot + 1) === rest;
}

export class PipeService {
  private config: PipesConfig;
  private readonly resolve: Resolve;
  private readonly now: () => number;
  private readonly tickets = new Map<string, Ticket>();
  /** Connections open, by pipe: each a way to close it. */
  private readonly open = new Map<number, Map<object, (code: number, reason: string) => void>>();
  private readonly openBy = new Map<string, number>();
  private openTotal = 0;

  constructor(config: PipesConfig, resolve: Resolve = resolveAll, now: () => number = Date.now) {
    this.config = config;
    this.resolve = resolve;
    this.now = now;
  }

  get settings(): PipesConfig { return this.config; }
  /** The configuration read again; permits apply from the next ticket and the next connection. */
  update(config: PipesConfig): void { this.config = config; }

  private sweep(): void {
    const t = this.now();
    for (const [id, ticket] of this.tickets) if (ticket.expires <= t) this.tickets.delete(id);
  }
  private outstanding(pred: (t: Ticket) => boolean): number {
    let n = 0;
    for (const t of this.tickets.values()) if (pred(t)) n++;
    return n;
  }

  /** The permit admitting a principal to a host and port through a pipe of a domain, addresses aside. */
  permitFor(host: string, port: number, principal: Principal, domain: string): PipePermit | undefined {
    const at = domain.endsWith("/") ? domain : `${domain}/`;
    return this.config.permits.find((p) =>
      p.hosts.some((h) => hostMatches(h, host)) && (p.ports === "*" || p.ports.includes(port)) &&
      (p.domains === undefined || p.domains.includes(at)) &&
      (p.principals === undefined && p.groups === undefined
        ? true
        : (p.principals ?? []).includes(principal.name) || principal.groups.some((g) => (p.groups ?? []).includes(g))));
  }

  /**
   * A ticket for a principal the pipe's list admits, to a destination it names.
   * The status of a refusal is the whole of what the client is told.
   */
  async issue(r: { principal: Principal; pipe: number; domain: string; host: unknown; port: unknown; origin: string | undefined }):
    Promise<{ ok: true; ticket: Ticket } | Refused> {
    this.sweep();
    const c = this.config;
    if (typeof r.host !== "string" || !HOSTNAME.test(r.host) || isIP(r.host) !== 0) {
      return { ok: false, status: 400, reason: "the host is not a DNS name" };
    }
    if (typeof r.port !== "number" || !Number.isInteger(r.port) || r.port < 1 || r.port > 65535) {
      return { ok: false, status: 400, reason: "the port is not a port number" };
    }
    const host = r.host.toLowerCase().replace(/\.$/, ""), port = r.port;
    if (r.principal.name === ANONYMOUS && !c.allowAnonymous) return { ok: false, status: 403, reason: "anonymous use is not configured" };
    // Tickets not yet used count with connections open, so that tickets cannot be stockpiled.
    const who = r.principal.name;
    if ((this.openBy.get(who) ?? 0) + this.outstanding((t) => t.principal.name === who) >= c.maxConnections) {
      return { ok: false, status: 429, reason: "the principal's limit" };
    }
    if ((this.open.get(r.pipe)?.size ?? 0) + this.outstanding((t) => t.pipe === r.pipe) >= c.maxConnectionsPerPipe) {
      return { ok: false, status: 429, reason: "the pipe's limit" };
    }
    if (this.openTotal + this.tickets.size >= c.maxConnectionsTotal) return { ok: false, status: 429, reason: "the total limit" };
    const permit = this.permitFor(host, port, r.principal, r.domain);
    if (permit === undefined) return { ok: false, status: 403, reason: "no permit admits the principal to the destination" };
    let addresses: string[];
    try {
      addresses = await this.resolve(host);
    } catch {
      return { ok: false, status: 403, reason: "the host does not resolve" };
    }
    if (addresses.length === 0) return { ok: false, status: 403, reason: "the host resolves to no address" };
    // Every address, so that a name resolving to a permitted and an unpermitted address cannot reach the second.
    const outside = addresses.find((a) => !permit.addresses.some((range) => withinRange(a, range)));
    if (outside !== undefined) return { ok: false, status: 403, reason: `the host resolves to ${outside}, outside the permit ${permit.name}` };
    const ticket: Ticket = {
      id: randomBytes(32).toString("base64url"), principal: r.principal, pipe: r.pipe, domain: r.domain, host, port,
      address: addresses[0], origin: r.origin, expires: this.now() + c.ticketTtl * 1000, permit: permit.name,
    };
    this.tickets.set(ticket.id, ticket);
    return { ok: true, ticket };
  }

  /**
   * Takes a ticket presented on a WebSocket: consumed whether or not the
   * connection is then made, and only for the pipe and the origin it was issued for.
   */
  consume(id: unknown, pipe: number, origin: string | undefined): Ticket | undefined {
    this.sweep();
    if (typeof id !== "string") return undefined;
    const t = this.tickets.get(id);
    if (t === undefined) return undefined;
    this.tickets.delete(id);
    if (t.pipe !== pipe || t.origin !== origin) return undefined;
    return t;
  }

  /** Whether a permit still admits a ticket's principal to its destination and pinned address (RELAY-draft-2 section 5.4). */
  stillPermitted(t: Ticket): boolean {
    const p = this.permitFor(t.host, t.port, t.principal, t.domain);
    return p !== undefined && p.addresses.some((range) => withinRange(t.address, range));
  }

  /** Whether a connection may open now, within the limits; if so it is counted, and a way to close it held. */
  opened(t: Ticket, close: (code: number, reason: string) => void): object | undefined {
    const c = this.config;
    if ((this.openBy.get(t.principal.name) ?? 0) >= c.maxConnections || (this.open.get(t.pipe)?.size ?? 0) >= c.maxConnectionsPerPipe ||
        this.openTotal >= c.maxConnectionsTotal) {
      return undefined;
    }
    const handle = {};
    if (!this.open.has(t.pipe)) this.open.set(t.pipe, new Map());
    this.open.get(t.pipe)!.set(handle, close);
    this.openBy.set(t.principal.name, (this.openBy.get(t.principal.name) ?? 0) + 1);
    this.openTotal++;
    return handle;
  }

  closed(t: Ticket, handle: object): void {
    const m = this.open.get(t.pipe);
    if (m === undefined || !m.delete(handle)) return;
    if (m.size === 0) this.open.delete(t.pipe);
    const n = (this.openBy.get(t.principal.name) ?? 1) - 1;
    if (n <= 0) this.openBy.delete(t.principal.name); else this.openBy.set(t.principal.name, n);
    this.openTotal--;
  }

  /** Closes every connection through a pipe deleted or switched off, and forgets its tickets. */
  closePipe(pipe: number, code: number, reason: string): void {
    for (const [id, t] of this.tickets) if (t.pipe === pipe) this.tickets.delete(id);
    for (const close of [...(this.open.get(pipe)?.values() ?? [])]) close(code, reason);
  }

  /**
   * Closes every connection, with RFC 6455's 1001, "going away": at shutdown.
   * A connection whose WebSocket is held by backpressure does not read, and so
   * does not notice its client leaving until the destination drains or the idle
   * limit is reached; this ends it at once.
   */
  closeAll(): void {
    this.tickets.clear();
    for (const pipe of [...this.open.keys()]) this.closePipe(pipe, 1001, "going-away");
  }

  /** How many connections are open: for the tests and the log. */
  counts(): { total: number; tickets: number } { this.sweep(); return { total: this.openTotal, tickets: this.tickets.size }; }
}
