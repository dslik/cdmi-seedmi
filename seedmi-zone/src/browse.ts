// Browsing the link: what CDMI servers are advertising themselves here.
//
// This is the querying half of DNS-SD, and it keeps a view of the link rather
// than asking a question each time one is put to it. That is the whole reason
// the push shape beats a bridge that answers DoH queries by performing mDNS on
// demand: multicast DNS answers asynchronously, from several responders, with
// no "no such name" at all — absence is silence. A querier that holds a view
// absorbs that in the background, and what reads the view reads something
// settled.
//
// What is held here is what the link said. Nothing in this file decides whether
// any of it deserves to be published: an unauthenticated announcement is
// exactly what mDNS carries, and promoting one into a real zone is what the
// gate exists to prevent.

import {
  CLASS, decodeMessage, DnsError, encodeMessage, type Message, message, type Name, presentation,
  type Question, type ResourceRecord, sameName, TYPE, within,
} from "./dns.ts";

export const MDNS_PORT = 5353;
export const SERVICE = ["_cdmi", "_tcp"];

export interface Peer { address: string; port: number; family: "IPv4" | "IPv6" }

export interface Link {
  send(bytes: Uint8Array, to?: Peer): void;
  close(): void;
}

export interface Clock {
  now(): number;
  after(ms: number, fn: () => void): () => void;
}

export const systemClock: Clock = {
  now: () => Date.now(),
  after: (ms, fn) => {
    const t = setTimeout(fn, ms);
    if (typeof t.unref === "function") t.unref();
    return () => clearTimeout(t);
  },
};

/** One service instance as the link describes it. */
export interface Instance {
  /** The full name, <label>._cdmi._tcp.<domain>. */
  name: Name;
  label: string;
  domain: Name;
  target: Name;
  port: number;
  txt: string[];
  addresses: string[];
  /** When what is known of it stops being believable, from the lifetimes given. */
  expires: number;
  /** Whether the SRV and TXT have both arrived: an instance with neither is a name and nothing more. */
  complete: boolean;
}

interface Held {
  name: Name;
  domain: Name;
  srv?: { target: Name; port: number; expires: number };
  txt?: { strings: string[]; expires: number };
  ptrExpires: number;
}

export interface BrowserOptions {
  link: Link;
  /** The browsing domains queried, normally ["local"]. */
  domains: Name[];
  clock?: Clock;
  log?: (event: Record<string, unknown>) => void;
  /** How often the service type is asked for again. */
  queryIntervalMs?: number;
}

export class Browser {
  private readonly link: Link;
  private readonly clock: Clock;
  private readonly log: (event: Record<string, unknown>) => void;
  private readonly domains: Name[];
  private readonly queryIntervalMs: number;
  private readonly held = new Map<string, Held>();
  /** Addresses by host name, from the A and AAAA records the link carries. */
  private readonly addresses = new Map<string, { address: string; expires: number }[]>();
  private readonly timers = new Set<() => void>();
  private closed = false;

  constructor(opts: BrowserOptions) {
    this.link = opts.link;
    this.clock = opts.clock ?? systemClock;
    this.log = opts.log ?? (() => { /* silent */ });
    this.domains = opts.domains;
    this.queryIntervalMs = opts.queryIntervalMs ?? 60_000;
  }

  start(): void {
    this.ask();
  }

  close(): void {
    this.closed = true;
    for (const cancel of this.timers) cancel();
    this.timers.clear();
  }

  private timer(ms: number, fn: () => void): void {
    if (this.closed) return;
    let cancel: () => void = () => { /* replaced */ };
    cancel = this.clock.after(ms, () => {
      this.timers.delete(cancel);
      if (!this.closed) fn();
    });
    this.timers.add(cancel);
  }

  /** Asks for the service type, and for what is missing from each instance held. */
  private ask(): void {
    const questions: Question[] = this.domains.map((d) => ({
      name: [...SERVICE, ...d], type: TYPE.PTR, class: CLASS.IN,
    }));
    for (const h of this.held.values()) {
      if (h.srv === undefined) questions.push({ name: h.name, type: TYPE.SRV, class: CLASS.IN });
      if (h.txt === undefined) questions.push({ name: h.name, type: TYPE.TXT, class: CLASS.IN });
    }
    for (const h of this.held.values()) {
      if (h.srv === undefined) continue;
      const key = presentation(h.srv.target).toLowerCase();
      // Only a target on the link is asked about: a target elsewhere is
      // resolved by ordinary DNS, and asking the link for it would be asking
      // every host here to answer for somebody else's name.
      if (this.addresses.has(key) || !this.domains.some((d) => within(h.srv!.target, d))) continue;
      questions.push({ name: h.srv.target, type: TYPE.A, class: CLASS.IN });
      questions.push({ name: h.srv.target, type: TYPE.AAAA, class: CLASS.IN });
    }
    // The known-answer list: what is held and still fresh, so that a responder
    // with nothing new to say stays quiet.
    const known: ResourceRecord[] = [];
    const now = this.clock.now();
    for (const h of this.held.values()) {
      if (h.ptrExpires <= now) continue;
      known.push({
        name: [...SERVICE, ...h.domain], type: TYPE.PTR, class: CLASS.IN,
        ttl: Math.max(1, Math.floor((h.ptrExpires - now) / 1000)),
        data: { kind: "PTR", name: h.name },
      });
    }
    this.link.send(encodeMessage(message({ questions, answers: known })));
    this.timer(this.queryIntervalMs, () => this.ask());
  }

  /** Asks once, now, without the known-answer list: used when a caller wants a fresh view. */
  refresh(): void {
    this.link.send(encodeMessage(message({
      questions: this.domains.map((d) => ({ name: [...SERVICE, ...d], type: TYPE.PTR, class: CLASS.IN })),
    })));
  }

  receive(bytes: Uint8Array, from: Peer): void {
    if (this.closed) return;
    let m: Message;
    try {
      m = decodeMessage(bytes);
    } catch (e) {
      this.log({ event: "malformed", from: from.address, why: e instanceof DnsError ? e.message : String(e) });
      return;
    }
    // A question is not ours to answer: this program browses and does not
    // respond. Its answers, and the extra records that come with them, are.
    for (const r of [...m.answers, ...m.authority, ...m.additional]) this.take(r);
  }

  private take(r: ResourceRecord): void {
    const now = this.clock.now();
    const until = now + r.ttl * 1000;
    // "A lifetime of zero is a goodbye": the record is going away, and the
    // right response is to stop believing it rather than to believe it for
    // another moment.
    const goodbye = r.ttl === 0;
    switch (r.data.kind) {
      case "PTR": {
        if (!this.domains.some((d) => sameName(r.name, [...SERVICE, ...d]))) return;
        const domain = r.name.slice(SERVICE.length);
        const key = presentation(r.data.name).toLowerCase();
        if (goodbye) {
          if (this.held.delete(key)) this.log({ event: "gone", instance: presentation(r.data.name) });
          return;
        }
        const held = this.held.get(key);
        if (held === undefined) {
          this.held.set(key, { name: r.data.name, domain, ptrExpires: until });
          this.log({ event: "found", instance: presentation(r.data.name) });
          // What was just learnt of is asked about at once rather than at the
          // next sweep: a host that appears should appear in the zone now.
          this.timer(0, () => this.ask());
        } else {
          held.ptrExpires = until;
        }
        return;
      }
      case "SRV": {
        const held = this.held.get(presentation(r.name).toLowerCase());
        if (held === undefined) return;
        if (goodbye) delete held.srv;
        else held.srv = { target: r.data.target, port: r.data.port, expires: until };
        return;
      }
      case "TXT": {
        const held = this.held.get(presentation(r.name).toLowerCase());
        if (held === undefined) return;
        if (goodbye) delete held.txt;
        else held.txt = { strings: r.data.strings, expires: until };
        return;
      }
      case "A":
      case "AAAA": {
        const key = presentation(r.name).toLowerCase();
        const address = r.data.address;
        const kept = (this.addresses.get(key) ?? []).filter((a) => a.address !== address);
        if (!goodbye) kept.push({ address, expires: until });
        if (kept.length === 0) this.addresses.delete(key);
        else this.addresses.set(key, kept);
        return;
      }
      default:
        return;
    }
  }

  /**
   * The instances the link is offering, as of now. An instance whose lifetime
   * has run out is dropped: a responder that goes away without a goodbye —
   * a machine unplugged, a process killed — is forgotten by the clock instead.
   */
  instances(): Instance[] {
    const now = this.clock.now();
    const out: Instance[] = [];
    for (const [key, h] of [...this.held]) {
      if (h.ptrExpires <= now) {
        this.held.delete(key);
        this.log({ event: "expired", instance: presentation(h.name) });
        continue;
      }
      if (h.srv !== undefined && h.srv.expires <= now) delete h.srv;
      if (h.txt !== undefined && h.txt.expires <= now) delete h.txt;
      const target = h.srv?.target;
      const addresses = target === undefined
        ? []
        : (this.addresses.get(presentation(target).toLowerCase()) ?? [])
          .filter((a) => a.expires > now).map((a) => a.address);
      out.push({
        name: h.name,
        label: h.name[0] ?? "",
        domain: h.domain,
        target: target ?? [],
        port: h.srv?.port ?? 0,
        txt: h.txt?.strings ?? [],
        addresses,
        expires: Math.min(h.ptrExpires, h.srv?.expires ?? Infinity),
        complete: h.srv !== undefined && h.txt !== undefined,
      });
    }
    return out.sort((a, b) => presentation(a.name).localeCompare(presentation(b.name)));
  }
}
