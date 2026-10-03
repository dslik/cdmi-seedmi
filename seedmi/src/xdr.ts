// XDR, the external data representation of RFC 4506, in which every ONC
// RPC message and every NFS structure is encoded.
//
// Two rules account for most of it: everything is a multiple of four
// bytes, and everything is big-endian. Opaque data and strings are
// padded to four with zero bytes, and the padding is not counted in the
// length that precedes them.
//
// A 64-bit XDR integer becomes a bigint here rather than a number,
// because NFS uses the full range for offsets, file identifiers, client
// identifiers and the change attribute, and a JavaScript number is exact
// only to 2^53. The reader throws rather than silently losing a value.

export class XDRError extends Error {}

const MAX_LENGTH = 64 << 20; // a sanity bound on any length read

export class XDRWriter {
  private chunks: Buffer[] = [];
  private length = 0;

  /** The bytes written so far. */
  bytes(): Buffer {
    return Buffer.concat(this.chunks, this.length);
  }

  get size(): number {
    return this.length;
  }

  private push(b: Buffer): void {
    this.chunks.push(b);
    this.length += b.length;
  }

  raw(b: Buffer): this {
    this.push(b);
    return this;
  }

  int(v: number): this {
    const b = Buffer.alloc(4);
    // A signed 32-bit value, written as two's complement.
    b.writeInt32BE(v | 0, 0);
    this.push(b);
    return this;
  }

  uint(v: number): this {
    if (!Number.isInteger(v) || v < 0 || v > 0xffffffff) {
      throw new XDRError(`${v} is not an unsigned 32-bit integer`);
    }
    const b = Buffer.alloc(4);
    b.writeUInt32BE(v, 0);
    this.push(b);
    return this;
  }

  hyper(v: bigint): this {
    const b = Buffer.alloc(8);
    b.writeBigInt64BE(v, 0);
    this.push(b);
    return this;
  }

  uhyper(v: bigint): this {
    if (v < 0n || v > 0xffffffffffffffffn) {
      throw new XDRError(`${v} is not an unsigned 64-bit integer`);
    }
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(v, 0);
    this.push(b);
    return this;
  }

  bool(v: boolean): this {
    return this.uint(v ? 1 : 0);
  }

  /** Opaque data of a fixed length, padded to a multiple of four. */
  fixed(b: Buffer): this {
    this.push(b);
    const pad = (4 - (b.length % 4)) % 4;
    if (pad > 0) this.push(Buffer.alloc(pad));
    return this;
  }

  /** Opaque data of a variable length, preceded by that length. */
  opaque(b: Buffer): this {
    this.uint(b.length);
    return this.fixed(b);
  }

  /** A string, encoded in UTF-8 as NFSv4 requires. */
  string(s: string): this {
    return this.opaque(Buffer.from(s, "utf8"));
  }

  /** An array, preceded by its count. */
  array<T>(items: readonly T[], write: (w: XDRWriter, item: T) => void): this {
    this.uint(items.length);
    for (const item of items) write(this, item);
    return this;
  }

  /** An optional value, encoded as a boolean followed by the value. */
  optional<T>(value: T | undefined, write: (w: XDRWriter, v: T) => void): this {
    if (value === undefined) return this.bool(false);
    this.bool(true);
    write(this, value);
    return this;
  }

  /** A bitmap4: a counted array of 32-bit words, least significant first. */
  bitmap(bits: readonly number[]): this {
    const words: number[] = [];
    for (const bit of bits) {
      const word = bit >>> 5;
      while (words.length <= word) words.push(0);
      words[word] |= 1 << (bit & 31);
    }
    return this.array(words, (w, word) => w.uint(word >>> 0));
  }
}

export class XDRReader {
  private readonly buf: Buffer;
  private at: number;

  constructor(buf: Buffer, offset = 0) {
    this.buf = buf;
    this.at = offset;
  }

  get offset(): number {
    return this.at;
  }

  /** An independent reader over the same bytes, from an offset. */
  from(offset: number): XDRReader {
    return new XDRReader(this.buf, offset);
  }

  /** Moves past a number of bytes without decoding them. */
  skip(n: number): void {
    this.take(n);
  }

  get remaining(): number {
    return this.buf.length - this.at;
  }

  get atEnd(): boolean {
    return this.remaining <= 0;
  }

  private take(n: number): Buffer {
    if (n < 0 || this.at + n > this.buf.length) {
      throw new XDRError(
        `a read of ${n} bytes at ${this.at} runs past the end of ${this.buf.length} bytes`);
    }
    const out = this.buf.subarray(this.at, this.at + n);
    this.at += n;
    return out;
  }

  int(): number {
    return this.take(4).readInt32BE(0);
  }

  uint(): number {
    return this.take(4).readUInt32BE(0);
  }

  hyper(): bigint {
    return this.take(8).readBigInt64BE(0);
  }

  uhyper(): bigint {
    return this.take(8).readBigUInt64BE(0);
  }

  bool(): boolean {
    const v = this.uint();
    if (v > 1) throw new XDRError(`${v} is not a boolean`);
    return v === 1;
  }

  fixed(n: number): Buffer {
    const out = Buffer.from(this.take(n));
    const pad = (4 - (n % 4)) % 4;
    if (pad > 0) this.take(pad);
    return out;
  }

  opaque(max = MAX_LENGTH): Buffer {
    const n = this.uint();
    if (n > max) throw new XDRError(`a length of ${n} exceeds the limit of ${max}`);
    return this.fixed(n);
  }

  string(max = MAX_LENGTH): string {
    return this.opaque(max).toString("utf8");
  }

  array<T>(read: (r: XDRReader) => T, max = 1 << 20): T[] {
    const n = this.uint();
    if (n > max) throw new XDRError(`a count of ${n} exceeds the limit of ${max}`);
    const out: T[] = [];
    for (let i = 0; i < n; i++) out.push(read(this));
    return out;
  }

  optional<T>(read: (r: XDRReader) => T): T | undefined {
    return this.bool() ? read(this) : undefined;
  }

  /** A bitmap4, returned as the numbers of the bits that are set. */
  bitmap(): number[] {
    const words = this.array((r) => r.uint(), 1 << 10);
    const bits: number[] = [];
    words.forEach((word, i) => {
      for (let b = 0; b < 32; b++) {
        if ((word & (1 << b)) !== 0) bits.push(i * 32 + b);
      }
    });
    return bits;
  }
}

/** Encodes with a writer and returns the bytes. */
export function encode(write: (w: XDRWriter) => void): Buffer {
  const w = new XDRWriter();
  write(w);
  return w.bytes();
}

/** Decodes a complete message, requiring every byte to be consumed. */
export function decode<T>(b: Buffer, read: (r: XDRReader) => T): T {
  const r = new XDRReader(b);
  const out = read(r);
  if (!r.atEnd) {
    throw new XDRError(`${r.remaining} bytes remain after decoding`);
  }
  return out;
}
