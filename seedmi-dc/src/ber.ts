// BER, as LDAP uses it (RFC 4511 section 5.1; ITU-T X.690).
//
// "Only the definite form of length encoding is used", tags are the low-number
// form LDAP needs (a number below 31), and a value is read whole or refused. A
// read that runs past the end of what it was given is not an error but the
// signal that more octets are needed, since a message arrives over a stream.

export class BerError extends Error {}
/** More octets are needed than were given. */
export class Incomplete extends Error {}

export const UNIVERSAL = 0x00, APPLICATION = 0x40, CONTEXT = 0x80;
export const CONSTRUCTED = 0x20;
export const T = { BOOLEAN: 0x01, INTEGER: 0x02, OCTET_STRING: 0x04, NULL: 0x05, ENUMERATED: 0x0a, SEQUENCE: 0x30, SET: 0x31 };

/** One element: its identifier octet and its contents. */
export interface Element { tag: number; content: Buffer }

/** Reads one element at an offset, returning it and the offset after it. */
export function readElement(b: Buffer, at = 0): { el: Element; next: number } {
  if (at >= b.length) throw new Incomplete("an element");
  const tag = b[at];
  if ((tag & 0x1f) === 0x1f) throw new BerError("a tag number of 31 or more, which LDAP does not use");
  if (at + 1 >= b.length) throw new Incomplete("a length");
  let len = b[at + 1];
  let head = 2;
  if (len === 0x80) throw new BerError("the indefinite form of length, which LDAP does not use");
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n > 4) throw new BerError("a length of more than four octets");
    if (at + 2 + n > b.length) throw new Incomplete("a length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[at + 2 + i];
    head += n;
  }
  if (at + head + len > b.length) throw new Incomplete("contents");
  return { el: { tag, content: b.subarray(at + head, at + head + len) }, next: at + head + len };
}

/** The elements within a constructed element's contents, every octet accounted for. */
export function children(content: Buffer): Element[] {
  const out: Element[] = [];
  let at = 0;
  while (at < content.length) {
    let r;
    try {
      r = readElement(content, at);
    } catch (e) {
      // Within an element already read whole, running out is malformed, not incomplete.
      if (e instanceof Incomplete) throw new BerError("an element runs past the end of the one containing it");
      throw e;
    }
    out.push(r.el);
    at = r.next;
  }
  return out;
}

/** An INTEGER or ENUMERATED: two's complement, the sign in the first octet's top bit. */
export function integer(el: Element): number {
  const c = el.content;
  if (c.length === 0 || c.length > 4) throw new BerError("an integer of 1 to 4 octets");
  // Built unsigned, then the sign applied: for a negative value, subtract 2^(8 * length).
  let u = 0;
  for (const o of c) u = u * 256 + o;
  return (c[0] & 0x80) ? u - 2 ** (8 * c.length) : u;
}
export function boolean(el: Element): boolean {
  if (el.content.length !== 1) throw new BerError("a boolean of one octet");
  return el.content[0] !== 0;
}
export function text(el: Element): string {
  return el.content.toString("utf8");
}

// --- encoding -----------------------------------------------------------------

function lengthOctets(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
export function tlv(tag: number, content: Buffer | Buffer[]): Buffer {
  const c = Array.isArray(content) ? Buffer.concat(content) : content;
  return Buffer.concat([Buffer.from([tag]), lengthOctets(c.length), c]);
}
/** An INTEGER (or ENUMERATED, by its tag) in the fewest octets, as X.690 requires. */
export function int(v: number, tag = T.INTEGER): Buffer {
  const out: number[] = [];
  let n = v;
  do {
    out.unshift(n & 0xff);
    n >>= 8;
  } while (!(n === 0 && (out[0] & 0x80) === 0) && !(n === -1 && (out[0] & 0x80) !== 0));
  return tlv(tag, Buffer.from(out));
}
export const octets = (s: string | Buffer, tag = T.OCTET_STRING) => tlv(tag, typeof s === "string" ? Buffer.from(s, "utf8") : s);
export const seq = (items: Buffer[], tag = T.SEQUENCE) => tlv(tag, items);
