// DNS messages: the wire format, read and written.
//
// One codec serves three jobs in these two programs. seedmi-mdns answers
// multicast DNS queries (RFC 6762), which are DNS messages on port 5353 with a
// few bits given other meanings. seedmi-zone asks the same questions of the
// link and sends DNS UPDATE messages (RFC 2136) to a name server, authenticated
// by TSIG (RFC 8945); an UPDATE is an ordinary message with another opcode, its
// four sections read as zone, prerequisite, update and additional.
//
// A name is a list of labels and not a string. A DNS-SD instance label is
// "any user-friendly text" (RFC 6763) and may hold a dot, a space or any other
// octet; the presentation form escapes those, and every implementation that
// carries a name as a dotted string has to escape and unescape it at each
// boundary. Carrying the labels is the same information without the escaping,
// and presentation() is used where a name is shown to a person.

/** Resource record types, by the numbers IANA gives them. */
export const TYPE = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, HINFO: 13, TXT: 16, AAAA: 28, SRV: 33,
  OPT: 41, TSIG: 250, AXFR: 252, ANY: 255,
} as const;

/** Classes. NONE and ANY are the UPDATE prerequisite classes of RFC 2136. */
export const CLASS = { IN: 1, NONE: 254, ANY: 255 } as const;

/** Opcodes. */
export const OPCODE = { QUERY: 0, UPDATE: 5 } as const;

/** Response codes, including the ones RFC 2136 adds for an UPDATE. */
export const RCODE = {
  NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, NOTIMP: 4, REFUSED: 5,
  YXDOMAIN: 6, YXRRSET: 7, NXRRSET: 8, NOTAUTH: 9, NOTZONE: 10,
} as const;

/** A domain name, as its labels, each holding the octets of one label. */
export type Name = string[];

export interface Question {
  name: Name;
  type: number;
  class: number;
  /**
   * The top bit of the class field of a question. In multicast DNS it is the
   * unicast-response bit: "a responder ... should respond via unicast"
   * (RFC 6762). It has no meaning in unicast DNS and is not set there.
   */
  unicast?: boolean;
}

export type RData =
  | { kind: "A"; address: string }
  | { kind: "AAAA"; address: string }
  | { kind: "PTR"; name: Name }
  | { kind: "NS"; name: Name }
  | { kind: "CNAME"; name: Name }
  | { kind: "SRV"; priority: number; weight: number; port: number; target: Name }
  | { kind: "TXT"; strings: string[] }
  | { kind: "TSIG"; algorithm: Name; timeSigned: number; fudge: number; mac: Uint8Array;
      originalID: number; error: number; other: Uint8Array }
  /** Anything else, and the empty rdata of an UPDATE prerequisite. */
  | { kind: "OPAQUE"; octets: Uint8Array };

export interface ResourceRecord {
  name: Name;
  type: number;
  class: number;
  ttl: number;
  data: RData;
  /**
   * The top bit of the class field of a record. In multicast DNS it is the
   * cache-flush bit: the record "is the new authoritative set" and a receiver
   * discards what it held for that name and type. It is not a class, and a
   * record carried out of multicast into unicast DNS must not keep it — a
   * receiver that reads the field as a class sees 0x8001 where IN was meant.
   */
  flush?: boolean;
}

export interface Message {
  id: number;
  /** A response, rather than a query. */
  qr: boolean;
  opcode: number;
  /** Authoritative answer. */
  aa: boolean;
  /** Truncated. */
  tc: boolean;
  /** Recursion desired, and recursion available. */
  rd: boolean;
  ra: boolean;
  rcode: number;
  questions: Question[];
  answers: ResourceRecord[];
  authority: ResourceRecord[];
  additional: ResourceRecord[];
}

/** An empty message of the given kind, for a caller to fill in. */
export const message = (m: Partial<Message> = {}): Message => ({
  id: 0, qr: false, opcode: OPCODE.QUERY, aa: false, tc: false, rd: false, ra: false,
  rcode: RCODE.NOERROR, questions: [], answers: [], authority: [], additional: [], ...m,
});

export class DnsError extends Error {}

// ---------------------------------------------------------------------------
// Names

/**
 * The labels of a name written in presentation form, where "\." is a dot
 * within a label and "\065" is an octet by its decimal value (RFC 1035). A
 * trailing dot is the root and is dropped, so "local" and "local." give the
 * same labels.
 */
export function labels(s: string): Name {
  if (s === "" || s === ".") return [];
  const out: Name = [];
  let label = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === "\\") {
      const d = s.slice(i + 1, i + 4);
      if (/^[0-9]{3}$/.test(d)) {
        label += String.fromCharCode(Number(d));
        i += 3;
      } else {
        label += s[i + 1] ?? "";
        i += 1;
      }
    } else if (c === ".") {
      out.push(label);
      label = "";
    } else {
      label += c;
    }
  }
  if (label !== "") out.push(label);
  else if (out.length === 0) return [];
  return out;
}

/** A name in presentation form, escaping what would otherwise be read as structure. */
export function presentation(name: Name): string {
  if (name.length === 0) return ".";
  return name.map((l) => [...l].map((c) => {
    const code = c.codePointAt(0)!;
    if (c === "." || c === "\\") return `\\${c}`;
    if (code < 0x20 || code === 0x7f) return `\\${String(code).padStart(3, "0")}`;
    return c;
  }).join("")).join(".");
}

/** Whether two names are the same, comparing ASCII case-insensitively as DNS does. */
export const sameName = (a: Name, b: Name): boolean =>
  a.length === b.length && a.every((l, i) => l.toLowerCase() === b[i]!.toLowerCase());

/** Whether a name lies within another, which is the zone test of an UPDATE. */
export const within = (name: Name, zone: Name): boolean =>
  name.length >= zone.length && sameName(name.slice(name.length - zone.length), zone);

// ---------------------------------------------------------------------------
// Writing

class Writer {
  bytes: number[] = [];
  /** Where each name written so far begins, for compression. */
  private seen = new Map<string, number>();

  u8(v: number): void { this.bytes.push(v & 0xff); }
  u16(v: number): void { this.bytes.push((v >> 8) & 0xff, v & 0xff); }
  u32(v: number): void { this.bytes.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff); }
  raw(b: Uint8Array): void { for (const x of b) this.bytes.push(x); }

  /**
   * A name, compressed against the names already written where it may be: a
   * pointer holds a 14-bit offset, so a suffix that begins beyond 0x3fff is
   * written out in full.
   */
  name(name: Name, compress = true): void {
    for (let i = 0; i < name.length; i++) {
      const suffix = name.slice(i);
      const key = suffix.map((l) => l.toLowerCase()).join("\u0000");
      const at = this.seen.get(key);
      if (compress && at !== undefined) {
        this.u16(0xc000 | at);
        return;
      }
      if (this.bytes.length <= 0x3fff) this.seen.set(key, this.bytes.length);
      const octets = encodeLabel(name[i]!);
      if (octets.length === 0) throw new DnsError("a label of a name is empty");
      if (octets.length > 63) throw new DnsError(`a label of ${presentation(name)} is longer than 63 octets`);
      this.u8(octets.length);
      this.raw(octets);
    }
    this.u8(0);
  }
}

const encodeLabel = (l: string): Uint8Array => new TextEncoder().encode(l);

function writeRData(w: Writer, d: RData): void {
  // The length is written once the data is, so the position is kept and the
  // two octets filled in afterwards. A name within rdata is written
  // uncompressed except where the record type is one RFC 3597 allows
  // compression in; SRV is not among them, and a target written as a pointer
  // is a target some resolvers will not follow.
  const at = w.bytes.length;
  w.u16(0);
  const start = w.bytes.length;
  switch (d.kind) {
    case "A": {
      const parts = d.address.split(".").map(Number);
      if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
        throw new DnsError(`${d.address} is not an IPv4 address`);
      }
      for (const p of parts) w.u8(p);
      break;
    }
    case "AAAA":
      w.raw(encodeIPv6(d.address));
      break;
    case "PTR":
    case "NS":
    case "CNAME":
      w.name(d.name, true);
      break;
    case "SRV":
      w.u16(d.priority);
      w.u16(d.weight);
      w.u16(d.port);
      w.name(d.target, false);
      break;
    case "TXT": {
      // "Each character string is a length octet followed by that number of
      // characters", and an empty TXT record holds one empty string rather
      // than nothing at all (RFC 6763).
      const strings = d.strings.length === 0 ? [""] : d.strings;
      for (const s of strings) {
        const octets = new TextEncoder().encode(s);
        if (octets.length > 255) throw new DnsError("a character string is longer than 255 octets");
        w.u8(octets.length);
        w.raw(octets);
      }
      break;
    }
    case "TSIG":
      w.name(d.algorithm, false);
      // The time signed is 48 bits, which no 32-bit write holds.
      w.u16(Math.floor(d.timeSigned / 0x100000000));
      w.u32(d.timeSigned >>> 0);
      w.u16(d.fudge);
      w.u16(d.mac.length);
      w.raw(d.mac);
      w.u16(d.originalID);
      w.u16(d.error);
      w.u16(d.other.length);
      w.raw(d.other);
      break;
    case "OPAQUE":
      w.raw(d.octets);
      break;
  }
  const length = w.bytes.length - start;
  w.bytes[at] = (length >> 8) & 0xff;
  w.bytes[at + 1] = length & 0xff;
}

function encodeIPv6(address: string): Uint8Array {
  const out = new Uint8Array(16);
  const [head, tail] = address.split("::");
  const parse = (s: string): number[] => s === "" ? [] : s.split(":").map((g) => {
    const v = parseInt(g, 16);
    if (!/^[0-9a-fA-F]{1,4}$/.test(g) || Number.isNaN(v)) throw new DnsError(`${address} is not an IPv6 address`);
    return v;
  });
  const left = parse(head ?? "");
  const right = tail === undefined ? [] : parse(tail);
  if (tail === undefined && left.length !== 8) throw new DnsError(`${address} is not an IPv6 address`);
  if (left.length + right.length > 8) throw new DnsError(`${address} is not an IPv6 address`);
  const groups = [...left, ...new Array(8 - left.length - right.length).fill(0), ...right];
  groups.forEach((g, i) => {
    out[i * 2] = (g >> 8) & 0xff;
    out[i * 2 + 1] = g & 0xff;
  });
  return out;
}

function writeRecord(w: Writer, r: ResourceRecord): void {
  w.name(r.name);
  w.u16(r.type);
  w.u16((r.flush ? 0x8000 : 0) | r.class);
  w.u32(r.ttl);
  writeRData(w, r.data);
}

export function encodeMessage(m: Message): Uint8Array {
  const w = new Writer();
  w.u16(m.id);
  w.u16((m.qr ? 0x8000 : 0) | ((m.opcode & 0xf) << 11) | (m.aa ? 0x0400 : 0) |
    (m.tc ? 0x0200 : 0) | (m.rd ? 0x0100 : 0) | (m.ra ? 0x0080 : 0) | (m.rcode & 0xf));
  w.u16(m.questions.length);
  w.u16(m.answers.length);
  w.u16(m.authority.length);
  w.u16(m.additional.length);
  for (const q of m.questions) {
    w.name(q.name);
    w.u16(q.type);
    w.u16((q.unicast ? 0x8000 : 0) | q.class);
  }
  for (const r of [...m.answers, ...m.authority, ...m.additional]) writeRecord(w, r);
  return new Uint8Array(w.bytes);
}

// ---------------------------------------------------------------------------
// Reading

class Reader {
  readonly b: Uint8Array;
  at: number;
  constructor(b: Uint8Array, at = 0) {
    this.b = b;
    this.at = at;
  }

  need(n: number): void {
    if (this.at + n > this.b.length) throw new DnsError("the message ends within a field");
  }

  u8(): number { this.need(1); return this.b[this.at++]!; }
  u16(): number { return (this.u8() << 8) | this.u8(); }
  u32(): number { return ((this.u16() * 0x10000) + this.u16()) >>> 0; }
  raw(n: number): Uint8Array { this.need(n); const out = this.b.slice(this.at, this.at + n); this.at += n; return out; }

  /**
   * A name, following compression pointers. A pointer may only point
   * backwards, which every message a conforming implementation writes obeys
   * and which is what stops a crafted message from looping for ever; the jump
   * count is bounded as well, so that a chain of pointers cannot be used to
   * make a small message expensive to read.
   */
  name(): Name {
    const out: Name = [];
    let at = this.at;
    let jumps = 0;
    let after: number | undefined;
    for (;;) {
      if (at >= this.b.length) throw new DnsError("the message ends within a name");
      const len = this.b[at]!;
      if ((len & 0xc0) === 0xc0) {
        if (at + 1 >= this.b.length) throw new DnsError("the message ends within a compression pointer");
        const target = ((len & 0x3f) << 8) | this.b[at + 1]!;
        if (target >= at) throw new DnsError("a compression pointer does not point backwards");
        if (++jumps > 64) throw new DnsError("a name follows too many compression pointers");
        if (after === undefined) after = at + 2;
        at = target;
        continue;
      }
      if ((len & 0xc0) !== 0) throw new DnsError("a label length has reserved bits set");
      at += 1;
      if (len === 0) break;
      if (at + len > this.b.length) throw new DnsError("the message ends within a label");
      out.push(new TextDecoder().decode(this.b.slice(at, at + len)));
      at += len;
      if (out.length > 128) throw new DnsError("a name holds too many labels");
    }
    this.at = after ?? at;
    return out;
  }
}

function readRData(r: Reader, type: number, length: number): RData {
  const end = r.at + length;
  if (end > r.b.length) throw new DnsError("a record claims more data than the message holds");
  const data = ((): RData => {
    switch (type) {
      case TYPE.A: {
        if (length !== 4) throw new DnsError("an A record does not hold four octets");
        return { kind: "A", address: [...r.raw(4)].join(".") };
      }
      case TYPE.AAAA: {
        if (length !== 16) throw new DnsError("an AAAA record does not hold sixteen octets");
        return { kind: "AAAA", address: decodeIPv6(r.raw(16)) };
      }
      case TYPE.PTR: return { kind: "PTR", name: r.name() };
      case TYPE.NS: return { kind: "NS", name: r.name() };
      case TYPE.CNAME: return { kind: "CNAME", name: r.name() };
      case TYPE.SRV: {
        const priority = r.u16();
        const weight = r.u16();
        const port = r.u16();
        return { kind: "SRV", priority, weight, port, target: r.name() };
      }
      case TYPE.TXT: {
        const strings: string[] = [];
        while (r.at < end) {
          const n = r.u8();
          if (r.at + n > end) throw new DnsError("a character string runs past the end of its record");
          strings.push(new TextDecoder().decode(r.raw(n)));
        }
        return { kind: "TXT", strings };
      }
      case TYPE.TSIG: {
        const algorithm = r.name();
        const high = r.u16();
        const low = r.u32();
        const fudge = r.u16();
        const mac = r.raw(r.u16());
        const originalID = r.u16();
        const error = r.u16();
        const other = r.raw(r.u16());
        return { kind: "TSIG", algorithm, timeSigned: high * 0x100000000 + low, fudge, mac, originalID, error, other };
      }
      default:
        return { kind: "OPAQUE", octets: r.raw(length) };
    }
  })();
  // A record whose rdata is shorter or longer than its length said is a
  // malformed message and not a record to guess at.
  if (r.at !== end) throw new DnsError("a record's data does not fill the length it declared");
  return data;
}

const decodeIPv6 = (b: Uint8Array): string => {
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push((b[i]! << 8) | b[i + 1]!);
  // The longest run of zeroes is written "::", as RFC 5952 requires, so that a
  // decoded address compares equal to the same address written by anything else.
  let bestAt = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) { bestLen = j - i; bestAt = i; }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLen < 2) return hex.join(":");
  return `${hex.slice(0, bestAt).join(":")}::${hex.slice(bestAt + bestLen).join(":")}`;
};

function readRecord(r: Reader): ResourceRecord {
  const name = r.name();
  const type = r.u16();
  const cls = r.u16();
  const ttl = r.u32();
  const length = r.u16();
  return {
    name, type, class: cls & 0x7fff, ttl, data: readRData(r, type, length),
    ...((cls & 0x8000) !== 0 ? { flush: true } : {}),
  };
}

export function decodeMessage(b: Uint8Array): Message {
  const r = new Reader(b);
  const id = r.u16();
  const flags = r.u16();
  const counts = [r.u16(), r.u16(), r.u16(), r.u16()];
  const m: Message = {
    id,
    qr: (flags & 0x8000) !== 0,
    opcode: (flags >> 11) & 0xf,
    aa: (flags & 0x0400) !== 0,
    tc: (flags & 0x0200) !== 0,
    rd: (flags & 0x0100) !== 0,
    ra: (flags & 0x0080) !== 0,
    rcode: flags & 0xf,
    questions: [], answers: [], authority: [], additional: [],
  };
  for (let i = 0; i < counts[0]!; i++) {
    const name = r.name();
    const type = r.u16();
    const cls = r.u16();
    m.questions.push({
      name, type, class: cls & 0x7fff,
      ...((cls & 0x8000) !== 0 ? { unicast: true } : {}),
    });
  }
  const sections: (keyof Pick<Message, "answers" | "authority" | "additional">)[] =
    ["answers", "authority", "additional"];
  sections.forEach((section, i) => {
    for (let n = 0; n < counts[i + 1]!; n++) m[section].push(readRecord(r));
  });
  return m;
}
