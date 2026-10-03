// The TTLV encoding of the Key Management Interoperability Protocol,
// version 1.4, section 9.1. Every KMIP message on the wire is one TTLV
// item: a Request Message or a Response Message structure.
//
// This module encodes and decodes items and nothing else. It knows the
// item types and their lengths, and it knows tags only as numbers; names
// come from kmip-registry.ts, which is generated from the document.
//
// Decisions the document leaves open, recorded in NOTES-on-kmip.md:
//
// * The value of a padding byte is not stated ("padded with the minimal
//   number of bytes"). Zero is written, and any value is accepted.
// * A Big Integer of value zero is written as eight zero bytes; the
//   minimal two's complement form is one byte, padded to eight.
// * A Text String that is not valid UTF-8 is refused: the document
//   defines the type as UTF-8 [RFC3629].

import { KMIP_ENUM, KMIP_TAG } from "./kmip-registry.ts";

/**
 * The item types of Table 286. They are written as literals so that the
 * type of an item's value follows from its type; each is checked against
 * the generated registry when this module loads.
 */
export const TYPE = Object.freeze({
  Structure: 0x01,
  Integer: 0x02,
  LongInteger: 0x03,
  BigInteger: 0x04,
  Enumeration: 0x05,
  Boolean: 0x06,
  TextString: 0x07,
  ByteString: 0x08,
  DateTime: 0x09,
  Interval: 0x0a,
} as const);

{
  const table = KMIP_ENUM["Item Type"];
  const names: Record<keyof typeof TYPE, string> = {
    Structure: "Structure", Integer: "Integer", LongInteger: "Long Integer",
    BigInteger: "Big Integer", Enumeration: "Enumeration", Boolean: "Boolean",
    TextString: "Text String", ByteString: "Byte String", DateTime: "Date-Time",
    Interval: "Interval",
  };
  for (const [key, name] of Object.entries(names) as [keyof typeof TYPE, string][]) {
    if (table?.[name] !== TYPE[key]) {
      throw new Error(`item type ${name} is ${TYPE[key]} here and ${table?.[name]} in the registry`);
    }
  }
}

export type Item =
  | { tag: number; type: typeof TYPE.Structure; value: Item[] }
  | { tag: number; type: typeof TYPE.Integer | typeof TYPE.Enumeration | typeof TYPE.Interval; value: number }
  | { tag: number; type: typeof TYPE.LongInteger | typeof TYPE.BigInteger | typeof TYPE.DateTime; value: bigint }
  | { tag: number; type: typeof TYPE.Boolean; value: boolean }
  | { tag: number; type: typeof TYPE.TextString; value: string }
  | { tag: number; type: typeof TYPE.ByteString; value: Buffer };

/** A malformed item, with the offset in the input at which it was found. */
export class TtlvError extends Error {
  readonly offset: number;
  constructor(message: string, offset: number) {
    super(`${message} (at offset ${offset})`);
    this.name = "TtlvError";
    this.offset = offset;
  }
}

/** The length of the header of every item: tag, type and length. */
export const HEADER = 8;

/** The deepest nesting of structures decoded; a bound, not a protocol rule. */
export const MAX_DEPTH = 32;

const pad8 = (n: number) => (8 - (n % 8)) % 8;
const INT32_MIN = -0x80000000;
const INT32_MAX = 0x7fffffff;
const UINT32_MAX = 0xffffffff;
const INT64_MIN = -(1n << 63n);
const INT64_MAX = (1n << 63n) - 1n;

// Section 9.1.1.1: "all tags SHALL contain either the value 42 in hex or the
// value 54 in hex as the high order (first) byte".
function checkTag(tag: number, offset: number): void {
  const first = tag >>> 16;
  if (!Number.isInteger(tag) || tag < 0 || tag > 0xffffff || (first !== 0x42 && first !== 0x54)) {
    throw new TtlvError(`tag 0x${tag.toString(16)} is not a tag of KMIP or of an extension`, offset);
  }
}

// ---------------------------------------------------------------------------
// Encoding

/** Encodes one item, and everything within it, as TTLV. */
export function encode(item: Item): Buffer {
  const parts: Buffer[] = [];
  write(item, parts, 0);
  return Buffer.concat(parts);
}

function header(tag: number, type: number, length: number): Buffer {
  const h = Buffer.alloc(HEADER);
  h.writeUInt8((tag >>> 16) & 0xff, 0);
  h.writeUInt16BE(tag & 0xffff, 1);
  h.writeUInt8(type, 3);
  h.writeUInt32BE(length, 4);
  return h;
}

function write(item: Item, parts: Buffer[], depth: number): number {
  checkTag(item.tag, 0);
  switch (item.type) {
    case TYPE.Structure: {
      if (depth >= MAX_DEPTH) throw new TtlvError("structures nest too deeply", 0);
      const at = parts.length;
      parts.push(Buffer.alloc(0)); // the header, once the length is known
      let length = 0;
      for (const child of item.value) length += write(child, parts, depth + 1);
      parts[at] = header(item.tag, item.type, length);
      return HEADER + length;
    }
    case TYPE.Integer: {
      const v = item.value;
      if (!Number.isInteger(v) || v < INT32_MIN || v > INT32_MAX) {
        throw new TtlvError(`${v} is not a 32-bit signed integer`, 0);
      }
      const b = Buffer.alloc(8);
      b.writeInt32BE(v, 0);
      parts.push(header(item.tag, item.type, 4), b);
      return 16;
    }
    case TYPE.Enumeration:
    case TYPE.Interval: {
      const v = item.value;
      if (!Number.isInteger(v) || v < 0 || v > UINT32_MAX) {
        throw new TtlvError(`${v} is not a 32-bit unsigned integer`, 0);
      }
      const b = Buffer.alloc(8);
      b.writeUInt32BE(v, 0);
      parts.push(header(item.tag, item.type, 4), b);
      return 16;
    }
    case TYPE.LongInteger:
    case TYPE.DateTime: {
      const v = item.value;
      if (typeof v !== "bigint" || v < INT64_MIN || v > INT64_MAX) {
        throw new TtlvError(`${String(v)} is not a 64-bit signed integer`, 0);
      }
      const b = Buffer.alloc(8);
      b.writeBigInt64BE(v, 0);
      parts.push(header(item.tag, item.type, 8), b);
      return 16;
    }
    case TYPE.BigInteger: {
      const b = bigToBytes(item.value);
      parts.push(header(item.tag, item.type, b.length), b);
      return HEADER + b.length;
    }
    case TYPE.Boolean: {
      const b = Buffer.alloc(8);
      if (item.value) b.writeUInt8(1, 7);
      parts.push(header(item.tag, item.type, 8), b);
      return 16;
    }
    case TYPE.TextString:
    case TYPE.ByteString: {
      const raw = item.type === TYPE.TextString
        ? Buffer.from(item.value, "utf8")
        : item.value;
      if (item.type === TYPE.ByteString && !Buffer.isBuffer(raw)) {
        throw new TtlvError("a Byte String value is a Buffer", 0);
      }
      parts.push(header(item.tag, item.type, raw.length), raw, Buffer.alloc(pad8(raw.length)));
      return HEADER + raw.length + pad8(raw.length);
    }
    default:
      throw new TtlvError(`item type ${(item as { type: number }).type} is not defined`, 0);
  }
}

// Section 9.1.1.4: "Big Integers are encoded as a sequence of eight-bit bytes, in
// two's complement notation, transmitted big-endian. If the length of the
// sequence is not a multiple of eight bytes, then Big Integers SHALL be
// padded with the minimal number of leading sign-extended bytes to make
// the length a multiple of eight bytes."
function bigToBytes(v: bigint): Buffer {
  if (typeof v !== "bigint") throw new TtlvError("a Big Integer value is a bigint", 0);
  // The fewest bytes whose two's complement holds v.
  let n = 1;
  while (v < -(1n << BigInt(8 * n - 1)) || v >= (1n << BigInt(8 * n - 1))) n++;
  const len = n + pad8(n);
  const out = Buffer.alloc(len);
  let x = v < 0n ? (1n << BigInt(8 * len)) + v : v;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function bytesToBig(b: Buffer): bigint {
  let x = 0n;
  for (const byte of b) x = (x << 8n) | BigInt(byte);
  if (b.length > 0 && (b[0] & 0x80) !== 0) x -= 1n << BigInt(8 * b.length);
  return x;
}

// ---------------------------------------------------------------------------
// Decoding

/**
 * Decodes the item at the start of `buf`, returning it and the number of
 * bytes it occupies with its padding. Bytes after it are not examined.
 */
export function decodeOne(buf: Buffer, offset = 0): { item: Item; size: number } {
  return read(buf, offset, buf.length, 0);
}

/** Decodes a buffer holding exactly one item and nothing after it. */
export function decode(buf: Buffer): Item {
  const { item, size } = read(buf, 0, buf.length, 0);
  if (size !== buf.length) {
    throw new TtlvError(`${buf.length - size} bytes follow the item`, size);
  }
  return item;
}

const decoder = new TextDecoder("utf-8", { fatal: true });

function read(buf: Buffer, at: number, end: number, depth: number): { item: Item; size: number } {
  if (end - at < HEADER) throw new TtlvError("an item header is truncated", at);
  const tag = (buf.readUInt8(at) << 16) | buf.readUInt16BE(at + 1);
  const type = buf.readUInt8(at + 3);
  const length = buf.readUInt32BE(at + 4);
  checkTag(tag, at);
  const v = at + HEADER;

  // Table 287, "Allowed Item Length Values".
  const fixed = (n: number) => {
    if (length !== n) {
      throw new TtlvError(`an item of type ${type} has length ${length}, not ${n}`, at);
    }
  };
  const need = (n: number) => {
    if (end - v < n) throw new TtlvError("an item value is truncated", at);
  };

  switch (type) {
    case TYPE.Structure: {
      if (length % 8 !== 0) {
        throw new TtlvError(`a Structure has length ${length}, not a multiple of 8`, at);
      }
      if (depth >= MAX_DEPTH) throw new TtlvError("structures nest too deeply", at);
      need(length);
      const children: Item[] = [];
      let p = v;
      while (p < v + length) {
        const child = read(buf, p, v + length, depth + 1);
        children.push(child.item);
        p += child.size;
      }
      return { item: { tag, type, value: children }, size: HEADER + length };
    }
    case TYPE.Integer:
    case TYPE.Enumeration:
    case TYPE.Interval: {
      fixed(4);
      need(8); // the value and its four bytes of padding
      const value = type === TYPE.Integer ? buf.readInt32BE(v) : buf.readUInt32BE(v);
      return { item: { tag, type, value } as Item, size: 16 };
    }
    case TYPE.LongInteger:
    case TYPE.DateTime: {
      fixed(8);
      need(8);
      return { item: { tag, type, value: buf.readBigInt64BE(v) } as Item, size: 16 };
    }
    case TYPE.BigInteger: {
      if (length === 0 || length % 8 !== 0) {
        throw new TtlvError(`a Big Integer has length ${length}, not a positive multiple of 8`, at);
      }
      need(length);
      return {
        item: { tag, type, value: bytesToBig(buf.subarray(v, v + length)) },
        size: HEADER + length,
      };
    }
    case TYPE.Boolean: {
      fixed(8);
      need(8);
      const x = buf.readBigUInt64BE(v);
      if (x !== 0n && x !== 1n) {
        throw new TtlvError(`a Boolean holds 0x${x.toString(16)}, neither 0 nor 1`, at);
      }
      return { item: { tag, type, value: x === 1n }, size: 16 };
    }
    case TYPE.TextString:
    case TYPE.ByteString: {
      const padded = length + pad8(length);
      need(padded);
      const raw = buf.subarray(v, v + length);
      if (type === TYPE.ByteString) {
        return { item: { tag, type, value: Buffer.from(raw) }, size: HEADER + padded };
      }
      let text: string;
      try {
        text = decoder.decode(raw);
      } catch {
        throw new TtlvError("a Text String is not valid UTF-8", at);
      }
      return { item: { tag, type, value: text }, size: HEADER + padded };
    }
    default:
      throw new TtlvError(`item type ${type} is not defined`, at);
  }
}

// ---------------------------------------------------------------------------
// Framing

/**
 * The size of the message whose header begins `head`, which holds at
 * least HEADER bytes. A message is a Structure, which carries no padding
 * after it, so its size is its header and its length.
 */
export function messageSize(head: Buffer): number {
  if (head.length < HEADER) throw new TtlvError("a message header is truncated", 0);
  const type = head.readUInt8(3);
  if (type !== TYPE.Structure) {
    throw new TtlvError(`a message is a Structure, and this item is of type ${type}`, 0);
  }
  return HEADER + head.readUInt32BE(4);
}

/**
 * Collects whole messages from a byte stream delivered in arbitrary
 * pieces. A message larger than `limit` is refused before it is read.
 */
export class MessageReader {
  private held: Buffer = Buffer.alloc(0);
  private readonly limit: number;
  constructor(limit = 16 * 1024 * 1024) {
    this.limit = limit;
  }

  /**
   * Adds bytes, and returns the bytes of every message they complete, without
   * decoding them. A header that cannot be read, or a length beyond the limit,
   * throws, since the messages after it cannot be separated; a message whose
   * content does not decode is returned for its reader to answer.
   */
  frames(chunk: Buffer): Buffer[] {
    this.held = this.held.length === 0 ? chunk : Buffer.concat([this.held, chunk]);
    const out: Buffer[] = [];
    for (;;) {
      if (this.held.length < HEADER) return out;
      const size = messageSize(this.held);
      if (size > this.limit) {
        throw new TtlvError(`a message of ${size} bytes exceeds the limit of ${this.limit}`, 0);
      }
      if (this.held.length < size) return out;
      out.push(Buffer.from(this.held.subarray(0, size)));
      this.held = this.held.subarray(size);
    }
  }

  /** Adds bytes, and returns every message they complete. */
  push(chunk: Buffer): Item[] {
    this.held = this.held.length === 0 ? chunk : Buffer.concat([this.held, chunk]);
    const out: Item[] = [];
    for (;;) {
      if (this.held.length < HEADER) return out;
      const size = messageSize(this.held);
      if (size > this.limit) {
        throw new TtlvError(`a message of ${size} bytes exceeds the limit of ${this.limit}`, 0);
      }
      if (this.held.length < size) return out;
      out.push(decode(this.held.subarray(0, size)));
      this.held = this.held.subarray(size);
    }
  }

  /** Whether part of a message is held. */
  get pending(): boolean {
    return this.held.length > 0;
  }
}

// ---------------------------------------------------------------------------
// Building and reading items by name

/** The tag of a name the document defines, refusing a name it does not. */
export function tagOf(name: string): number {
  const t = KMIP_TAG[name];
  if (t === undefined) throw new Error(`KMIP defines no tag named ${JSON.stringify(name)}`);
  return t;
}

/** The value of a name within an enumeration the document defines. */
export function enumOf(enumeration: string, name: string): number {
  const e = KMIP_ENUM[enumeration];
  if (e === undefined) throw new Error(`KMIP defines no enumeration named ${JSON.stringify(enumeration)}`);
  const v = e[name];
  if (v === undefined) {
    throw new Error(`the ${enumeration} enumeration has no value named ${JSON.stringify(name)}`);
  }
  return v;
}

let tagNames: Map<number, string> | undefined;
/** The name of a tag, or its hexadecimal value where the document names none. */
export function nameOf(tag: number): string {
  tagNames ??= new Map(Object.entries(KMIP_TAG).map(([n, t]) => [t, n]));
  return tagNames.get(tag) ?? `0x${tag.toString(16).toUpperCase()}`;
}

export const k = {
  struct: (name: string, value: Item[]): Item => ({ tag: tagOf(name), type: TYPE.Structure, value }),
  int: (name: string, value: number): Item => ({ tag: tagOf(name), type: TYPE.Integer, value }),
  long: (name: string, value: bigint): Item => ({ tag: tagOf(name), type: TYPE.LongInteger, value }),
  big: (name: string, value: bigint): Item => ({ tag: tagOf(name), type: TYPE.BigInteger, value }),
  enum: (name: string, enumeration: string, value: string): Item =>
    ({ tag: tagOf(name), type: TYPE.Enumeration, value: enumOf(enumeration, value) }),
  bool: (name: string, value: boolean): Item => ({ tag: tagOf(name), type: TYPE.Boolean, value }),
  text: (name: string, value: string): Item => ({ tag: tagOf(name), type: TYPE.TextString, value }),
  bytes: (name: string, value: Buffer): Item => ({ tag: tagOf(name), type: TYPE.ByteString, value }),
  /** A Date Time, from milliseconds since the epoch; the item holds seconds. */
  date: (name: string, ms: number): Item =>
    ({ tag: tagOf(name), type: TYPE.DateTime, value: BigInt(Math.floor(ms / 1000)) }),
  interval: (name: string, seconds: number): Item => ({ tag: tagOf(name), type: TYPE.Interval, value: seconds }),
};

/** The children of a structure bearing a tag. */
export function children(s: Item, name: string): Item[] {
  if (s.type !== TYPE.Structure) return [];
  const t = tagOf(name);
  return s.value.filter((c) => c.tag === t);
}

/** The one child of a structure bearing a tag, or undefined. */
export function child(s: Item, name: string): Item | undefined {
  return children(s, name)[0];
}

/** A textual dump of an item, for diagnostics and test failures. */
export function dump(item: Item, indent = ""): string {
  const head = `${indent}${nameOf(item.tag)}`;
  if (item.type === TYPE.Structure) {
    return [head, ...item.value.map((c) => dump(c, indent + "  "))].join("\n");
  }
  const v = item.type === TYPE.ByteString
    ? item.value.toString("hex")
    : typeof item.value === "bigint" ? `${item.value}n` : JSON.stringify(item.value);
  return `${head} = ${v}`;
}
