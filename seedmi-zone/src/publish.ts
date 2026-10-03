// Writing the zone: the records this program wants to exist, and the two ways
// of making them exist.
//
// The subtree under the configured zone prefix belongs to this program and to
// nothing else. One writer per subtree is the rule the deployment keeps, and it
// is what makes reconciliation simple: each sweep says what the subtree should
// hold, and the difference against what it held last is written. Two writers on
// one subtree flap — one deletes what the other has just seen — which is why
// the prefix is per link and the README says so.
//
// Two mechanisms, because the deployments differ. RFC 2136 UPDATE with TSIG is
// the standard one and works with BIND, Knot and PowerDNS; unbound-control is
// the tight fit on a machine where Unbound is also the DoH server, since the
// records then live in the resolver that serves them.

import {
  CLASS, encodeMessage, type Name, OPCODE, presentation, RCODE, type ResourceRecord, sameName, TYPE,
} from "./dns.ts";
import { message } from "./dns.ts";
import { sign, type TsigKey, TsigError, verify } from "./tsig.ts";
import { connect, type Socket } from "node:net";
import { execFileSync } from "node:child_process";

export class PublishError extends Error {}

/** What a sweep decided the subtree should hold. */
export interface Desired {
  records: ResourceRecord[];
}

/** Where the records go. */
export interface Publisher {
  /** Replaces the contents of each name given with the records given for it. */
  apply(add: ResourceRecord[], remove: Name[]): Promise<void>;
  describe(): string;
}

// ---------------------------------------------------------------------------
// RFC 2136

export interface UpdateOptions {
  /** The name server the update is sent to. */
  host: string;
  port: number;
  /** The zone the update names, which every record must lie within. */
  zone: Name;
  key: TsigKey;
  timeoutMs?: number;
}

const RCODE_NAME: Record<number, string> = {
  [RCODE.FORMERR]: "the name server could not read the update",
  [RCODE.SERVFAIL]: "the name server failed",
  [RCODE.NXDOMAIN]: "a prerequisite named a zone that does not exist",
  [RCODE.NOTIMP]: "the name server does not implement dynamic update",
  [RCODE.REFUSED]: "the name server refused the update: the key may not be permitted to write these names",
  [RCODE.YXDOMAIN]: "a name a prerequisite said must not exist does exist",
  [RCODE.YXRRSET]: "records a prerequisite said must not exist do exist",
  [RCODE.NXRRSET]: "records a prerequisite required are not there",
  [RCODE.NOTAUTH]: "the name server is not authoritative for the zone, or would not accept the key",
  [RCODE.NOTZONE]: "a record lies outside the zone the update named",
};

export class UpdatePublisher implements Publisher {
  private readonly opts: UpdateOptions;
  constructor(opts: UpdateOptions) {
    this.opts = opts;
  }

  describe(): string {
    return `DNS UPDATE to ${this.opts.host}:${this.opts.port} for ${presentation(this.opts.zone)}, ` +
      `signed as ${presentation(this.opts.key.name)}`;
  }

  async apply(add: ResourceRecord[], remove: Name[]): Promise<void> {
    if (add.length === 0 && remove.length === 0) return;
    for (const r of [...add.map((x) => x.name), ...remove]) {
      if (!within(r, this.opts.zone)) {
        throw new PublishError(`${presentation(r)} lies outside ${presentation(this.opts.zone)}`);
      }
    }
    // A delete of every record set at a name is class ANY, type ANY, lifetime
    // zero and empty data; the additions follow, so that a name whose records
    // have changed is replaced rather than accumulated.
    const empty = { kind: "OPAQUE" as const, octets: new Uint8Array(0) };
    const updates: ResourceRecord[] = [
      ...remove.map((name): ResourceRecord => ({
        name, type: TYPE.ANY, class: CLASS.ANY, ttl: 0, data: empty,
      })),
      ...[...new Set(add.map((r) => presentation(r.name)))].map((n): ResourceRecord => ({
        name: add.find((r) => presentation(r.name) === n)!.name,
        type: TYPE.ANY, class: CLASS.ANY, ttl: 0, data: empty,
      })),
      ...add,
    ];
    const m = message({
      id: Math.floor(Math.random() * 0x10000),
      opcode: OPCODE.UPDATE,
      questions: [{ name: this.opts.zone, type: TYPE.SOA, class: CLASS.IN }],
      authority: updates,
    });
    const signed = sign(m, this.opts.key);
    const answer = await this.exchange(signed.bytes);
    let verified;
    try {
      verified = verify(answer, this.opts.key, signed.mac);
    } catch (e) {
      // An answer that does not verify is not an answer. Reporting it as a
      // failure to write is right: what the zone now holds is unknown, and the
      // next sweep will say so again.
      throw new PublishError(e instanceof TsigError
        ? `the name server's answer was not authenticated: ${e.message}`
        : (e as Error).message);
    }
    if (verified.error !== 0) {
      throw new PublishError(`the name server rejected the signature (TSIG error ${verified.error})`);
    }
    if (verified.message.rcode !== RCODE.NOERROR) {
      throw new PublishError(RCODE_NAME[verified.message.rcode] ??
        `the name server answered with rcode ${verified.message.rcode}`);
    }
  }

  /**
   * One update over TCP. An update is sent over TCP rather than UDP: it is
   * larger than a query, it must not be answered by whoever replies first, and
   * the answer is the only evidence that the zone changed.
   */
  private exchange(bytes: Uint8Array): Promise<Uint8Array> {
    const { host, port } = this.opts;
    const timeout = this.opts.timeoutMs ?? 5000;
    return new Promise((resolve, reject) => {
      let socket: Socket;
      let settled = false;
      const fail = (why: string) => {
        if (settled) return;
        settled = true;
        socket?.destroy();
        reject(new PublishError(why));
      };
      try {
        socket = connect({ host, port });
      } catch (e) {
        fail((e as Error).message);
        return;
      }
      socket.setTimeout(timeout);
      socket.on("timeout", () => fail(`${host}:${port} did not answer within ${timeout} ms`));
      socket.on("error", (e) => fail(`${host}:${port}: ${(e as Error).message}`));
      socket.on("connect", () => {
        // A message on TCP is preceded by its length in two octets.
        socket.write(Buffer.from([(bytes.length >> 8) & 0xff, bytes.length & 0xff, ...bytes]));
      });
      let held = Buffer.alloc(0);
      socket.on("data", (chunk) => {
        held = Buffer.concat([held, chunk]);
        if (held.length < 2) return;
        const length = (held[0]! << 8) | held[1]!;
        if (held.length < length + 2) return;
        settled = true;
        const answer = new Uint8Array(held.subarray(2, length + 2));
        socket.end();
        resolve(answer);
      });
      socket.on("close", () => fail(`${host}:${port} closed the connection before answering`));
    });
  }
}

const within = (name: Name, zone: Name): boolean =>
  name.length >= zone.length && sameName(name.slice(name.length - zone.length), zone);

// ---------------------------------------------------------------------------
// unbound-control

export interface UnboundOptions {
  /** The unbound-control binary, and any arguments that reach the right server. */
  command: string;
  args: string[];
  zone: Name;
  timeoutMs?: number;
}

/**
 * Records injected into a running Unbound, which is the tight fit where
 * Unbound is also the DoH server the browser talks to: the records then live in
 * the resolver that serves them, with no second daemon and no zone file.
 *
 * Unbound's local data is not a zone and has no dynamic-update protocol, so the
 * records are handed to unbound-control as zone-file lines.
 */
export class UnboundPublisher implements Publisher {
  private readonly opts: UnboundOptions;
  private zoned = false;
  constructor(opts: UnboundOptions) {
    this.opts = opts;
  }

  describe(): string {
    return `${this.opts.command} local_data under ${presentation(this.opts.zone)}`;
  }

  async apply(add: ResourceRecord[], remove: Name[]): Promise<void> {
    if (!this.zoned) {
      // "transparent" so that a name beneath the zone which this program has
      // nothing to say about is still resolved as usual, rather than answered
      // with a refusal by the local zone's existence alone.
      this.run(["local_zone", `${presentation(this.opts.zone)}.`, "transparent"]);
      this.zoned = true;
    }
    // A Set of names would not deduplicate, a name being an array; the
    // presentation form is what two records at one name have in common.
    const names = new Map<string, Name>();
    for (const name of [...remove, ...add.map((r) => r.name)]) {
      names.set(presentation(name).toLowerCase(), name);
    }
    for (const name of names.values()) this.run(["local_data_remove", `${presentation(name)}.`]);
    for (const r of add) this.run(["local_data", zoneLine(r)]);
    await Promise.resolve();
  }

  private run(args: string[]): void {
    try {
      execFileSync(this.opts.command, [...this.opts.args, ...args],
        { stdio: ["ignore", "ignore", "pipe"], timeout: this.opts.timeoutMs ?? 5000 });
    } catch (e) {
      throw new PublishError(`${this.opts.command} ${args[0]} failed: ${(e as Error).message}`);
    }
  }
}

/** A record as a zone file writes it, which is what unbound-control takes. */
export function zoneLine(r: ResourceRecord): string {
  const name = `${presentation(r.name)}.`;
  const head = `${name} ${r.ttl} IN`;
  switch (r.data.kind) {
    case "A": return `${head} A ${r.data.address}`;
    case "AAAA": return `${head} AAAA ${r.data.address}`;
    case "PTR": return `${head} PTR ${presentation(r.data.name)}.`;
    case "SRV":
      return `${head} SRV ${r.data.priority} ${r.data.weight} ${r.data.port} ${presentation(r.data.target)}.`;
    case "TXT":
      return `${head} TXT ${r.data.strings.map((s) => `"${s.replace(/(["\\])/g, "\\$1")}"`).join(" ")}`;
    default:
      throw new PublishError(`a ${r.data.kind} record is not written to a zone file by this program`);
  }
}

// ---------------------------------------------------------------------------
// Reconciling

/** A record written out, for comparing one sweep's view against the last. */
export const keyOf = (r: ResourceRecord): string =>
  Buffer.from(encodeMessage(message({ qr: true, answers: [{ ...r, flush: false, ttl: 0 }] }))).toString("hex");

/**
 * What to add and what to take away, given what the subtree should hold and
 * what it held after the last sweep.
 *
 * A name whose records have changed at all is rewritten whole: the record sets
 * are small, and replacing a set is one thing that either happened or did not,
 * where adding and removing within it is two things that can half happen.
 */
export function reconcile(desired: ResourceRecord[], published: ResourceRecord[]):
{ add: ResourceRecord[]; remove: Name[] } {
  const byName = (rs: ResourceRecord[]) => {
    const out = new Map<string, ResourceRecord[]>();
    for (const r of rs) {
      const k = presentation(r.name).toLowerCase();
      out.set(k, [...(out.get(k) ?? []), r]);
    }
    return out;
  };
  const want = byName(desired);
  const have = byName(published);
  const add: ResourceRecord[] = [];
  const remove: Name[] = [];
  for (const [name, records] of want) {
    const held = have.get(name) ?? [];
    const same = held.length === records.length &&
      records.map(keyOf).sort().join() === held.map(keyOf).sort().join();
    if (!same) add.push(...records);
  }
  for (const [name, records] of have) {
    if (!want.has(name)) remove.push(records[0]!.name);
  }
  return { add, remove };
}
