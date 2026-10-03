// Distinguished Encoding Rules.
//
// CMS is defined in ASN.1 and carried in DER, which Node's standard
// library does not encode or decode, so this module does. DER is a
// canonical subset of BER: every value has one encoding, lengths are
// definite and minimal, and a SET OF is sorted. That canonicity is
// what makes a signature over a structure verifiable, so the
// encoder produces the canonical form rather than a form that
// happens to parse.

/** The universal tag numbers this module reads and writes. */
export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
} as const;

/** The classes of a tag, in the two high bits of the identifier octet. */
export const CLASS = {
  UNIVERSAL: 0x00,
  APPLICATION: 0x40,
  CONTEXT: 0x80,
  PRIVATE: 0xc0,
} as const;

/** A value read from a DER encoding. */
export interface Element {
  /** The identifier octet, class and constructed bit included. */
  tag: number;
  /** The contents, without the identifier or the length. */
  content: Buffer;
  /** The whole element, for a signature computed over it as it stood. */
  raw: Buffer;
}

export class DERError extends Error {}

// ---------------------------------------------------------------------
// Lengths

/** The definite length in its shortest form, as DER requires. */
export function encodeLength(n: number): Buffer {
  if (n < 0) throw new DERError("a length is not negative");
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  if (bytes.length > 0x7e) throw new DERError("a length of that size is not encoded");
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** Reads a length, refusing the forms DER excludes. */
export function readLength(b: Buffer, at: number):
  { length: number; next: number } {
  if (at >= b.length) throw new DERError("a length is truncated");
  const first = b[at];
  if (first === 0x80) {
    throw new DERError("an indefinite length is not a distinguished encoding");
  }
  if (first < 0x80) return { length: first, next: at + 1 };
  const count = first & 0x7f;
  if (count === 0x7f) throw new DERError("a reserved length form");
  if (at + 1 + count > b.length) throw new DERError("a length is truncated");
  // DER requires the shortest form, so a long form encoding a value
  // below 128, or with a leading zero, is not a distinguished
  // encoding.
  if (b[at + 1] === 0x00) throw new DERError("a length is not in its shortest form");
  let length = 0;
  for (let i = 0; i < count; i++) length = length * 256 + b[at + 1 + i];
  if (length < 0x80) throw new DERError("a length is not in its shortest form");
  if (!Number.isSafeInteger(length)) throw new DERError("a length is too large");
  return { length, next: at + 1 + count };
}

// ---------------------------------------------------------------------
// Elements

/** An element of a tag and its contents. */
export function encode(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

/** Reads one element, reporting where the next begins. */
export function read(b: Buffer, at = 0): { element: Element; next: number } {
  if (at >= b.length) throw new DERError("an element is truncated");
  const tag = b[at];
  // A tag number of 31 begins a multi-octet tag, which nothing in
  // CMS uses.
  if ((tag & 0x1f) === 0x1f) throw new DERError("a multi-octet tag is not read");
  const { length, next } = readLength(b, at + 1);
  const end = next + length;
  if (end > b.length) throw new DERError("an element is truncated");
  return {
    element: { tag, content: b.subarray(next, end), raw: b.subarray(at, end) },
    next: end,
  };
}

/** Every element of a buffer, which is the contents of a constructed one. */
export function readAll(b: Buffer): Element[] {
  const out: Element[] = [];
  let at = 0;
  while (at < b.length) {
    const { element, next } = read(b, at);
    out.push(element);
    at = next;
  }
  return out;
}

/** Reads one element and refuses anything after it. */
export function readOne(b: Buffer): Element {
  const { element, next } = read(b, 0);
  if (next !== b.length) throw new DERError("an element is followed by more bytes");
  return element;
}

/** Whether an element carries the constructed bit. */
export const isConstructed = (e: Element): boolean => (e.tag & 0x20) !== 0;

/** The tag number of an element, without its class or constructed bit. */
export const tagNumber = (e: Element): number => e.tag & 0x1f;

// ---------------------------------------------------------------------
// The primitive types

/**
 * An integer, in the two's complement form DER requires: the
 * shortest encoding, with a leading zero where the high bit of the
 * first octet would otherwise make the value negative.
 */
export function encodeInteger(value: number | bigint): Buffer {
  let v = typeof value === "bigint" ? value : BigInt(value);
  const negative = v < 0n;
  if (v === 0n) return encode(TAG.INTEGER, Buffer.from([0x00]));
  const bytes: number[] = [];
  if (negative) {
    // Two's complement of the magnitude, widened until the high bit
    // is set.
    let width = 1;
    while (v < -(1n << BigInt(8 * width - 1))) width += 1;
    v = (1n << BigInt(8 * width)) + v;
    for (let i = width - 1; i >= 0; i--) {
      bytes.push(Number((v >> BigInt(8 * i)) & 0xffn));
    }
  } else {
    while (v > 0n) {
      bytes.unshift(Number(v & 0xffn));
      v >>= 8n;
    }
    if ((bytes[0] & 0x80) !== 0) bytes.unshift(0x00);
  }
  return encode(TAG.INTEGER, Buffer.from(bytes));
}

/** Reads an integer, refusing an encoding that is not the shortest. */
export function decodeInteger(e: Element): bigint {
  const b = e.content;
  if (b.length === 0) throw new DERError("an integer has no contents");
  if (b.length > 1) {
    const redundant = (b[0] === 0x00 && (b[1] & 0x80) === 0) ||
      (b[0] === 0xff && (b[1] & 0x80) !== 0);
    if (redundant) throw new DERError("an integer is not in its shortest form");
  }
  let v = 0n;
  for (const byte of b) v = (v << 8n) | BigInt(byte);
  // A high bit in the first octet means the value is negative.
  if ((b[0] & 0x80) !== 0) v -= 1n << BigInt(8 * b.length);
  return v;
}

export const encodeOctetString = (b: Buffer): Buffer => encode(TAG.OCTET_STRING, b);
export const encodeNull = (): Buffer => encode(TAG.NULL, Buffer.alloc(0));

/** A boolean, which DER encodes as zero or all ones. */
export function encodeBoolean(v: boolean): Buffer {
  return encode(TAG.BOOLEAN, Buffer.from([v ? 0xff : 0x00]));
}

export function decodeBoolean(e: Element): boolean {
  if (e.content.length !== 1) throw new DERError("a boolean is one octet");
  if (e.content[0] !== 0x00 && e.content[0] !== 0xff) {
    throw new DERError("a boolean is 0 or 255 in a distinguished encoding");
  }
  return e.content[0] === 0xff;
}

/**
 * A bit string of whole octets, which is every use CMS makes of one:
 * the first content octet counts the unused bits of the last octet.
 */
export function encodeBitString(b: Buffer, unused = 0): Buffer {
  if (unused < 0 || unused > 7) throw new DERError("an unused bit count is 0 to 7");
  return encode(TAG.BIT_STRING, Buffer.concat([Buffer.from([unused]), b]));
}

export function decodeBitString(e: Element): { bytes: Buffer; unused: number } {
  if (e.content.length === 0) throw new DERError("a bit string has no contents");
  const unused = e.content[0];
  if (unused > 7) throw new DERError("an unused bit count is 0 to 7");
  return { bytes: e.content.subarray(1), unused };
}

// ---------------------------------------------------------------------
// Object identifiers

/**
 * An object identifier. The first two arcs are combined into one
 * octet group as 40 times the first plus the second, and each group
 * is base 128 with the high bit set on every octet but the last.
 */
export function encodeOID(oid: string): Buffer {
  const arcs = oid.split(".").map((a) => {
    const n = Number(a);
    if (!Number.isInteger(n) || n < 0) {
      throw new DERError(`an object identifier arc is a whole number: ${a}`);
    }
    return n;
  });
  if (arcs.length < 2) throw new DERError("an object identifier has two arcs or more");
  if (arcs[0] > 2) throw new DERError("the first arc of an object identifier is 0 to 2");
  if (arcs[0] < 2 && arcs[1] >= 40) {
    throw new DERError("the second arc is below 40 where the first is 0 or 1");
  }
  const groups = [arcs[0] * 40 + arcs[1], ...arcs.slice(2)];
  const out: number[] = [];
  for (const g of groups) {
    const bytes: number[] = [g & 0x7f];
    let v = Math.floor(g / 128);
    while (v > 0) {
      bytes.unshift((v & 0x7f) | 0x80);
      v = Math.floor(v / 128);
    }
    out.push(...bytes);
  }
  return encode(TAG.OID, Buffer.from(out));
}

export function decodeOID(e: Element): string {
  const b = e.content;
  if (b.length === 0) throw new DERError("an object identifier has no contents");
  const groups: number[] = [];
  let v = 0;
  let started = false;
  for (const byte of b) {
    // A leading octet of 0x80 would be a group with a redundant
    // leading zero, which DER excludes.
    if (!started && byte === 0x80) {
      throw new DERError("an object identifier arc is not in its shortest form");
    }
    started = true;
    v = v * 128 + (byte & 0x7f);
    if (!Number.isSafeInteger(v)) throw new DERError("an arc is too large");
    if ((byte & 0x80) === 0) {
      groups.push(v);
      v = 0;
      started = false;
    }
  }
  if (started) throw new DERError("an object identifier is truncated");
  const first = groups[0] < 40 ? 0 : groups[0] < 80 ? 1 : 2;
  const second = groups[0] - first * 40;
  return [first, second, ...groups.slice(1)].join(".");
}

// ---------------------------------------------------------------------
// Constructed types

/** A sequence of elements, already encoded. */
export function sequence(...parts: Buffer[]): Buffer {
  return encode(TAG.SEQUENCE, Buffer.concat(parts));
}

/**
 * A set of elements. DER sorts the members of a SET OF by their
 * encodings, which is what makes a set canonical and therefore
 * signable.
 */
export function setOf(...parts: Buffer[]): Buffer {
  const sorted = [...parts].sort(compareEncodings);
  return encode(TAG.SET, Buffer.concat(sorted));
}

/** Compares two encodings as DER orders the members of a SET OF. */
export function compareEncodings(a: Buffer, b: Buffer): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  // The shorter is treated as padded with zero octets, so it sorts
  // first where one is a prefix of the other.
  return a.length - b.length;
}

/**
 * A context-specific element. An implicit tag replaces the tag of
 * the value; an explicit tag wraps it, which is why the constructed
 * bit is set for one and taken from the value for the other.
 */
export function contextTag(number: number, content: Buffer,
  explicit = true): Buffer {
  if (number < 0 || number > 30) {
    throw new DERError("a context tag number of 0 to 30 is encoded in one octet");
  }
  if (explicit) {
    return encode(CLASS.CONTEXT | 0x20 | number, content);
  }
  // Implicit: the tag of the value is replaced, and its constructed
  // bit is kept.
  const inner = readOne(content);
  return encode(CLASS.CONTEXT | (inner.tag & 0x20) | number, inner.content);
}

/** Whether an element carries a particular context tag number. */
export function isContext(e: Element, number: number): boolean {
  return (e.tag & 0xc0) === CLASS.CONTEXT && (e.tag & 0x1f) === number;
}

// ---------------------------------------------------------------------
// Time

/**
 * A time, as CMS carries one: UTCTime through 2049 and
 * GeneralizedTime from 2050, each to a second and in Zulu.
 */
export function encodeTime(at: Date): Buffer {
  const iso = at.toISOString();
  const year = Number(iso.slice(0, 4));
  const rest = iso.slice(5, 7) + iso.slice(8, 10) + iso.slice(11, 13) +
    iso.slice(14, 16) + iso.slice(17, 19) + "Z";
  if (year >= 1950 && year <= 2049) {
    return encode(TAG.UTC_TIME, Buffer.from(iso.slice(2, 4) + rest, "ascii"));
  }
  return encode(TAG.GENERALIZED_TIME, Buffer.from(String(year) + rest, "ascii"));
}

export function decodeTime(e: Element): Date {
  const s = e.content.toString("ascii");
  const n = tagNumber(e);
  if (n === TAG.UTC_TIME) {
    if (!/^\d{12}Z$/.test(s)) throw new DERError("a UTCTime is YYMMDDHHMMSSZ");
    const yy = Number(s.slice(0, 2));
    // The convention of RFC 5280: 50 and above is the 20th century.
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return new Date(`${year}-${s.slice(2, 4)}-${s.slice(4, 6)}T` +
      `${s.slice(6, 8)}:${s.slice(8, 10)}:${s.slice(10, 12)}Z`);
  }
  if (n === TAG.GENERALIZED_TIME) {
    if (!/^\d{14}Z$/.test(s)) {
      throw new DERError("a GeneralizedTime is YYYYMMDDHHMMSSZ in this profile");
    }
    return new Date(`${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T` +
      `${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z`);
  }
  throw new DERError("an element that is not a time");
}

// ---------------------------------------------------------------------
// Reading a structure

/** Reads the elements of a constructed element, refusing a primitive one. */
export function contentsOf(e: Element): Element[] {
  if (!isConstructed(e)) throw new DERError("a primitive element has no elements");
  return readAll(e.content);
}

/** Reads an element, requiring a tag. */
export function expect(e: Element, tag: number): Element {
  if (e.tag !== tag) {
    throw new DERError(
      `expected tag 0x${tag.toString(16)} and read 0x${e.tag.toString(16)}`);
  }
  return e;
}
