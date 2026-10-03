// The multicast DNS responder: what makes a CDMI server visible on a link.
//
// A CDMI server is advertised as a DNS-SD service instance of the type
// _cdmi._tcp (ECR-224A). A client browsing the link finds the instances, takes
// each one's host and port from its SRV record, reads that host's
// /.well-known/cdmi/cdmi_namespaces/ tree, and mounts a base URI. The instance
// identifies the host and nothing else: it carries no path and no base URI.
//
// The obligations of RFC 6762 are kept rather than the happy path. A responder
// that answers every query and never probes works perfectly until a second one
// appears with the same instance name, and then both answer for it and a
// browser sees one instance with two hosts behind it — a failure that shows up
// on someone else's network and not on the author's. So the unique records are
// probed for before they are claimed, a conflict is resolved by renaming, a
// repeated conflict is backed off from, the records are announced twice, and a
// goodbye is sent when the server goes away.
//
// This file speaks the protocol and owns no socket. The link is passed in, so
// that the conflict and suppression rules can be exercised without multicast,
// which a container does not have.

import {
  CLASS, decodeMessage, DnsError, encodeMessage, labels, message, type Message, type Name,
  presentation, type Question, type ResourceRecord, sameName, TYPE,
} from "./dns.ts";

export const MDNS_PORT = 5353;
export const MDNS_IPV4 = "224.0.0.251";
export const MDNS_IPV6 = "ff02::fb";

/** The service type this responder advertises, and the DNS-SD meta-query. */
export const SERVICE = ["_cdmi", "_tcp"];
export const SERVICES_META = ["_services", "_dns-sd", "_udp"];

/**
 * The lifetimes RFC 6762 gives. A record naming the host — an address, and the
 * SRV that points at it — is short lived, because a host that moves or goes
 * away should stop being believed quickly; the rest live long, because they
 * change only when a service does.
 */
export const TTL_HOST = 120;
export const TTL_OTHER = 4500;
/** A legacy unicast response is capped at ten seconds, the querier having no cache of ours. */
export const TTL_LEGACY = 10;

export interface Peer { address: string; port: number; family: "IPv4" | "IPv6" }

/** A link the responder sends on and receives from. */
export interface Link {
  /** Sends to the multicast group where no peer is given, and to the peer otherwise. */
  send(bytes: Uint8Array, to?: Peer): void;
  close(): void;
}

/** What the responder is told about the world, so that tests can tell it something else. */
export interface Clock {
  now(): number;
  /** Runs after the delay, returning a handle that cancels it. */
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

/** One advertised CDMI server. */
export interface Advertisement {
  /** The DNS-SD instance label, before any renaming a conflict forces. */
  instance: string;
  /** The browsing domain the instance is published in, normally ["local"]. */
  domain: Name;
  /** The SRV target: the host name a client connects to, and the certificate it must match. */
  target: Name;
  port: number;
  /** The TXT key/value pairs, txtvers first. */
  txt: string[];
  /** Addresses published for the target, where the target is this host's own name. */
  addresses: string[];
}

interface Live extends Advertisement {
  /** The label in use, which a conflict may have renamed. */
  label: string;
  state: "probing" | "live" | "withdrawn";
  /** Suppressed while the server it advertises does not answer. */
  up: boolean;
  /**
   * Which attempt at claiming a name is the current one. A rename leaves the
   * probe timers of the name it abandoned still scheduled, and one of those
   * firing afterwards claims the old name and announces it — so each attempt
   * carries its number and a probe from an earlier one does nothing. Found by
   * the test for the renaming back-off, where a probe chain from a rename
   * fifteen conflicts earlier declared the instance live during the wait.
   */
  generation: number;
}

export interface ResponderOptions {
  link: Link;
  advertisements: Advertisement[];
  clock?: Clock;
  /** Recorded rather than printed, so the daemon decides the format. */
  log?: (event: Record<string, unknown>) => void;
  /** RFC 6762 gives 250 ms between probes and 1 s between announcements. */
  probeIntervalMs?: number;
  announceIntervalMs?: number;
}

/** A name that is this responder's to claim: a conflict over it is resolved by renaming. */
const uniqueNames = (a: Live): Name[] => {
  const service = [a.label, ...SERVICE, ...a.domain];
  return a.addresses.length > 0 ? [service, a.target] : [service];
};

const instanceName = (a: Live): Name => [a.label, ...SERVICE, ...a.domain];
const serviceName = (a: Live): Name => [...SERVICE, ...a.domain];

/**
 * The label a conflict renames to: "seedmi" becomes "seedmi (2)", and "(2)"
 * becomes "(3)". RFC 6762 asks for "a human-friendly name" that a person
 * recognizes as the same service, rather than a random string.
 */
export function renamed(label: string): string {
  const m = /^(.*) \((\d+)\)$/.exec(label);
  if (m !== null) return `${m[1]} (${Number(m[2]) + 1})`;
  return `${label} (2)`;
};

export class Responder {
  private readonly link: Link;
  private readonly clock: Clock;
  private readonly log: (event: Record<string, unknown>) => void;
  private readonly probeIntervalMs: number;
  private readonly announceIntervalMs: number;
  private readonly live: Live[];
  private readonly timers = new Set<() => void>();
  /** When each conflict was seen, for the rate limit RFC 6762 requires. */
  private conflicts: number[] = [];
  private closed = false;

  constructor(opts: ResponderOptions) {
    this.link = opts.link;
    this.clock = opts.clock ?? systemClock;
    this.log = opts.log ?? (() => { /* silent by default */ });
    this.probeIntervalMs = opts.probeIntervalMs ?? 250;
    this.announceIntervalMs = opts.announceIntervalMs ?? 1000;
    this.live = opts.advertisements.map((a) => ({ ...a, label: a.instance, state: "probing", up: true, generation: 0 }));
  }

  /** The instances as they stand, for the daemon's log and for tests. */
  instances(): { label: string; name: string; state: string; up: boolean }[] {
    return this.live.map((a) => ({
      label: a.label, name: presentation(instanceName(a)), state: a.state, up: a.up,
    }));
  }

  /** Begins probing for every instance. */
  start(): void {
    for (const a of this.live) this.probe(a, 0, a.generation);
  }

  /**
   * Says whether the CDMI server an instance fronts is answering. An instance
   * whose server is down is withdrawn with a goodbye and stops being answered
   * for, rather than left in place for a browser to offer and a click to fail
   * on: the responder runs as its own program and outlives the server it
   * advertises, which the in-process case never had to consider.
   */
  setUp(label: string, up: boolean): void {
    const a = this.live.find((x) => x.instance === label || x.label === label);
    if (a === undefined || a.up === up) return;
    a.up = up;
    this.log({ event: up ? "instance up" : "instance down", instance: presentation(instanceName(a)) });
    if (up) {
      a.state = "probing";
      a.generation += 1;
      this.probe(a, 0, a.generation);
    } else if (a.state === "live") {
      a.generation += 1;
      this.goodbye(a);
      a.state = "withdrawn";
    }
  }

  // -------------------------------------------------------------------------
  // Probing and announcing

  private timer(ms: number, fn: () => void): void {
    if (this.closed) return;
    let cancel: () => void = () => { /* replaced below */ };
    cancel = this.clock.after(ms, () => {
      this.timers.delete(cancel);
      if (!this.closed) fn();
    });
    this.timers.add(cancel);
  }

  /**
   * "The host should send its probes ... three times, 250 ms apart", each
   * carrying the proposed records in the authority section so that a
   * simultaneous prober can compare and one of the two back down.
   */
  private probe(a: Live, n: number, generation: number): void {
    if (!a.up || generation !== a.generation) return;
    if (n >= 3) {
      a.state = "live";
      this.log({ event: "claimed", instance: presentation(instanceName(a)) });
      this.announce(a, 0, generation);
      return;
    }
    const names = uniqueNames(a);
    const m = message({
      questions: names.map((name): Question => ({ name, type: TYPE.ANY, class: CLASS.IN, unicast: n === 0 })),
      // The proposed records, which are not yet claimed and so are not answers.
      authority: names.flatMap((name) => this.recordsAt(a, name, false)),
    });
    this.link.send(encodeMessage(m));
    this.timer(this.probeIntervalMs, () => this.probe(a, n + 1, generation));
  }

  /** "Send ... at least two unsolicited responses, one second apart." */
  private announce(a: Live, n: number, generation: number): void {
    if (!a.up || a.state !== "live" || n >= 2 || generation !== a.generation) return;
    this.link.send(encodeMessage(message({
      qr: true, aa: true, answers: this.allRecords(a, true),
    })));
    this.timer(this.announceIntervalMs, () => this.announce(a, n + 1, generation));
  }

  /** A goodbye is the same records with a lifetime of zero. */
  private goodbye(a: Live): void {
    this.link.send(encodeMessage(message({
      qr: true, aa: true, answers: this.allRecords(a, true).map((r) => ({ ...r, ttl: 0 })),
    })));
  }

  // -------------------------------------------------------------------------
  // The records

  private allRecords(a: Live, flush: boolean): ResourceRecord[] {
    const name = instanceName(a);
    const out: ResourceRecord[] = [
      // Shared: several responders each contribute their own instance, and
      // none of them conflict, which is why a link carries many CDMI servers
      // without any of this needing to know about the others.
      { name: serviceName(a), type: TYPE.PTR, class: CLASS.IN, ttl: TTL_OTHER,
        data: { kind: "PTR", name } },
      // So that a client browsing for service types at all finds this one.
      { name: [...SERVICES_META, ...a.domain], type: TYPE.PTR, class: CLASS.IN, ttl: TTL_OTHER,
        data: { kind: "PTR", name: serviceName(a) } },
      ...this.recordsAt(a, name, flush),
    ];
    if (a.addresses.length > 0) out.push(...this.recordsAt(a, a.target, flush));
    return out;
  }

  /** The unique records held at one name. */
  private recordsAt(a: Live, name: Name, flush: boolean): ResourceRecord[] {
    const mark = flush ? { flush: true } : {};
    if (sameName(name, a.target) && a.addresses.length > 0) {
      return a.addresses.map((address): ResourceRecord => ({
        name: a.target,
        type: address.includes(":") ? TYPE.AAAA : TYPE.A,
        class: CLASS.IN, ttl: TTL_HOST,
        data: address.includes(":") ? { kind: "AAAA", address } : { kind: "A", address },
        ...mark,
      }));
    }
    return [
      { name, type: TYPE.SRV, class: CLASS.IN, ttl: TTL_HOST,
        data: { kind: "SRV", priority: 0, weight: 0, port: a.port, target: a.target }, ...mark },
      { name, type: TYPE.TXT, class: CLASS.IN, ttl: TTL_OTHER,
        data: { kind: "TXT", strings: a.txt }, ...mark },
    ];
  }

  // -------------------------------------------------------------------------
  // Receiving

  receive(bytes: Uint8Array, from: Peer): void {
    if (this.closed) return;
    let m: Message;
    try {
      m = decodeMessage(bytes);
    } catch (e) {
      // A malformed message arrives from any host on the link, and is the
      // ordinary case rather than an error to stop for.
      this.log({ event: "malformed", from: from.address, why: e instanceof DnsError ? e.message : String(e) });
      return;
    }
    if (m.qr) {
      this.checkConflict(m.answers);
      return;
    }
    // A probe carries its proposed records in the authority section. Answering
    // one while probing for the same name ourselves is the simultaneous case,
    // and is settled by comparing the records rather than by whoever is faster.
    if (m.authority.length > 0) this.checkProbe(m);
    this.answer(m, from);
  }

  /**
   * A response claiming one of our unique names with different data is a
   * conflict, and the rule is to rename and probe again — not to keep
   * answering, which is what leaves a browser with one instance and two hosts.
   */
  private checkConflict(answers: ResourceRecord[]): void {
    for (const a of this.live) {
      if (a.state === "withdrawn") continue;
      const ours = this.allRecords(a, false);
      const clash = answers.some((r) =>
        uniqueNames(a).some((n) => sameName(r.name, n)) &&
        ours.some((o) => sameName(o.name, r.name) && o.type === r.type) &&
        !ours.some((o) => sameName(o.name, r.name) && o.type === r.type &&
          JSON.stringify(o.data) === JSON.stringify(r.data)));
      if (clash) this.rename(a);
    }
  }

  private checkProbe(m: Message): void {
    for (const a of this.live) {
      if (a.state !== "probing") continue;
      const contested = m.authority.some((r) => uniqueNames(a).some((n) => sameName(r.name, n)));
      if (!contested) continue;
      // "The host compares the record data ... lexicographically, and the
      // host with the lexicographically later data wins." Comparing the
      // encoded records is the comparison the rule describes, and it settles
      // the tie the same way at both ends, which is the whole point of it.
      const theirs = m.authority.filter((r) => uniqueNames(a).some((n) => sameName(r.name, n)));
      const mine = uniqueNames(a).flatMap((n) => this.recordsAt(a, n, false));
      if (compareRecordSets(mine, theirs) < 0) this.rename(a);
    }
  }

  private rename(a: Live): void {
    const now = this.clock.now();
    this.conflicts = this.conflicts.filter((t) => now - t < 10_000);
    this.conflicts.push(now);
    const was = a.label;
    a.label = renamed(a.label);
    a.state = "probing";
    a.generation += 1;
    this.log({ event: "renamed", from: was, to: a.label });
    // "If a host has to rename more than fifteen times in ten seconds, it
    // should slow down": a pair of responders both renaming as fast as they
    // can is a storm on a link everybody else is using too.
    const wait = this.conflicts.length > 15 ? 5000 : 0;
    const generation = a.generation;
    if (wait === 0) this.probe(a, 0, generation);
    else this.timer(wait, () => this.probe(a, 0, generation));
  }

  /**
   * Answers a query. A response is sent to the group, unless the querier asked
   * for unicast or is a legacy resolver — one whose source port is not 5353,
   * which has no multicast listener to hear the answer.
   */
  private answer(m: Message, from: Peer): void {
    const legacy = from.port !== MDNS_PORT;
    const answers: ResourceRecord[] = [];
    const additional: ResourceRecord[] = [];
    for (const q of m.questions) {
      for (const a of this.live) {
        if (a.state !== "live" || !a.up) continue;
        for (const r of this.allRecords(a, !legacy)) {
          if (!sameName(r.name, q.name)) continue;
          if (q.type !== TYPE.ANY && q.type !== r.type) continue;
          if (q.class !== CLASS.ANY && q.class !== r.class) continue;
          if (answers.some((x) => same(x, r))) continue;
          // "A responder should omit an answer the querier already has, where
          // the record it holds has at least half the lifetime ours would
          // give it": the known-answer list is how a link with many browsers
          // stays quiet.
          if (m.answers.some((k) => same(k, r) && k.ttl >= r.ttl / 2)) continue;
          answers.push(r);
          // A PTR answer carries what the querier will ask for next, so that
          // browsing a service type costs one exchange and not three.
          if (r.type === TYPE.PTR && sameName(r.name, serviceName(a))) {
            for (const extra of this.allRecords(a, !legacy)) {
              if (extra.type === TYPE.SRV || extra.type === TYPE.TXT ||
                  extra.type === TYPE.A || extra.type === TYPE.AAAA) {
                if (!additional.some((x) => same(x, extra))) additional.push(extra);
              }
            }
          }
        }
      }
    }
    if (answers.length === 0) return;
    const response = message({
      // A legacy querier matches the response to its question by the message
      // identifier and the question echoed back; a multicast responder sends
      // neither, the response standing on its own.
      id: legacy ? m.id : 0,
      qr: true, aa: true,
      questions: legacy ? m.questions : [],
      answers: legacy ? answers.map(asLegacy) : answers,
      // The extra records go to a legacy querier too. RFC 6762 asks only that
      // a legacy response echo the question, cap the lifetime and leave the
      // cache-flush bit alone; withholding the SRV and the addresses would
      // make a browse cost three exchanges instead of one for exactly the
      // client this exists to serve — a discovery proxy asking on behalf of
      // something that cannot ask for itself.
      additional: (legacy ? additional.map(asLegacy) : additional)
        .filter((r) => !(legacy ? answers.map(asLegacy) : answers).some((x) => same(x, r))),
    });
    this.link.send(encodeMessage(response), legacy || m.questions.some((q) => q.unicast) ? from : undefined);
  }

  /** Withdraws every instance with a goodbye, and stops. */
  close(): void {
    if (this.closed) return;
    for (const a of this.live) {
      if (a.state === "live") this.goodbye(a);
      a.state = "withdrawn";
    }
    this.closed = true;
    for (const cancel of this.timers) cancel();
    this.timers.clear();
  }
}

/**
 * A record as a legacy querier takes it: the lifetime capped, because that
 * querier keeps no cache of ours to correct, and the cache-flush bit cleared,
 * because it is the top bit of the class field and a resolver that does not
 * know multicast DNS reads 0x8001 where IN was meant.
 */
const asLegacy = (r: ResourceRecord): ResourceRecord => ({
  ...r, ttl: Math.min(r.ttl, TTL_LEGACY), flush: false,
});

const same = (a: ResourceRecord, b: ResourceRecord): boolean =>
  a.type === b.type && a.class === b.class && sameName(a.name, b.name) &&
  JSON.stringify(a.data) === JSON.stringify(b.data);

/**
 * The lexical comparison RFC 6762 settles a simultaneous probe with, applied
 * to the two sets of records: each set is sorted by its records written out,
 * and the sets are compared record by record. A set that is a prefix of the
 * other loses, which is the rule for "fewer records".
 */
export function compareRecordSets(mine: ResourceRecord[], theirs: ResourceRecord[]): number {
  const written = (rs: ResourceRecord[]) => rs
    .map((r) => encodeMessage(message({ qr: true, answers: [{ ...r, flush: false }] })).slice(12))
    .map((b) => Buffer.from(b).toString("hex"))
    .sort();
  const a = written(mine);
  const b = written(theirs);
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i]! < b[i]!) return -1;
    if (a[i]! > b[i]!) return 1;
  }
  return a.length - b.length;
}

export { labels, presentation };
