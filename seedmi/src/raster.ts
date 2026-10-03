// Raster images: PNG and baseline JPEG, decoded to pixels and encoded from them.
//
// This module knows nothing of CDMI. It exists so that a data object whose value
// is a JPEG can also have a PNG representation and the reverse, as
// ref_http_representation_selection provides and as EXAMPLE 11.1 of the metadata
// clause illustrates with that very pair.
//
// It is written here because this server has no dependencies and Node ships no
// image codec. node:zlib supplies PNG's compression; everything else is below.
//
// What it will not do, in each case refusing rather than guessing:
//
//   * progressive, arithmetic-coded, hierarchical, 12-bit and lossless JPEG. Only
//     the baseline sequential DCT of SOF0 is decoded, which is what a JPEG on the
//     web is;
//   * a PNG of 16 bits per sample, and an interlaced PNG;
//   * anything whose header does not parse. A value that is not the media type
//     its "mimetype" claims has no second representation, which is not an error
//     of the object.
//
// Pixels are always RGBA, four octets per pixel, row-major, no padding. That is
// one representation in memory for both formats, so a conversion is a decode and
// an encode and never a special case per pair.

import { deflateSync, inflateSync } from "node:zlib";

export const PNG = "image/png";
export const JPEG = "image/jpeg";

/** A decoded image: RGBA, four octets per pixel, row-major. */
export interface Raster {
  width: number;
  height: number;
  pixels: Buffer;
}

/** A value that is not the image it claims to be, or is one this module declines. */
export class RasterError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RasterError";
  }
}

const fail = (why: string): never => {
  throw new RasterError(why);
};

// --- the media type of a value, by its signature -------------------------------

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/**
 * The media type a value is, by its leading octets, or nothing where it is
 * neither. The signature and not the "mimetype": a value whose mimetype says
 * image/png and whose octets are a JPEG is a JPEG, and the item reports what the
 * server can actually produce.
 */
export function sniff(bytes: Buffer): string | undefined {
  if (bytes.length >= 8 && bytes.subarray(0, 8).equals(PNG_SIGNATURE)) return PNG;
  // SOI, then a marker: every JPEG begins FF D8 FF.
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return JPEG;
  return undefined;
}

// --- CRC32, for PNG chunks -----------------------------------------------------

const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(b: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < b.length; i++) c = CRC_TABLE[(c ^ b[i]!) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// --- PNG -----------------------------------------------------------------------

/** The octets each pixel of a colour type occupies, at eight bits per sample. */
const PNG_CHANNELS: Record<number, number> = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };

function unfilter(raw: Buffer, width: number, height: number, bpp: number): Buffer {
  const stride = width * bpp;
  const out = Buffer.alloc(stride * height);
  let at = 0;
  for (let y = 0; y < height; y++) {
    const type = raw[at++];
    if (type === undefined) fail("the PNG image data end before the last scanline");
    const line = raw.subarray(at, at + stride);
    if (line.length < stride) fail("a PNG scanline is short");
    at += stride;
    const row = out.subarray(y * stride, (y + 1) * stride);
    const prior = y === 0 ? undefined : out.subarray((y - 1) * stride, y * stride);
    for (let i = 0; i < stride; i++) {
      const x = line[i]!;
      const a = i >= bpp ? row[i - bpp]! : 0;
      const b = prior ? prior[i]! : 0;
      const c = prior && i >= bpp ? prior[i - bpp]! : 0;
      let v: number;
      switch (type) {
        case 0: v = x; break;
        case 1: v = x + a; break;
        case 2: v = x + b; break;
        case 3: v = x + ((a + b) >> 1); break;
        case 4: {
          // Paeth: the neighbour nearest the linear prediction a + b - c.
          const p = a + b - c;
          const pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
          v = x + (pa <= pb && pa <= pc ? a : pb <= pc ? b : c);
          break;
        }
        default: return fail(`the PNG filter type ${type} is not one of the five defined`);
      }
      row[i] = v & 0xff;
    }
  }
  return out;
}

function decodePng(bytes: Buffer): Raster {
  if (bytes.length < 8 || !bytes.subarray(0, 8).equals(PNG_SIGNATURE)) {
    fail("the value does not begin with the PNG signature");
  }
  let at = 8;
  let width = 0, height = 0, depth = 0, colour = -1;
  let palette: Buffer | undefined;
  let alpha: Buffer | undefined;
  const idat: Buffer[] = [];
  let seenHeader = false;
  while (at + 8 <= bytes.length) {
    const length = bytes.readUInt32BE(at);
    const kind = bytes.toString("latin1", at + 4, at + 8);
    const from = at + 8;
    if (from + length + 4 > bytes.length) fail(`the PNG chunk ${kind} runs past the end of the value`);
    const data = bytes.subarray(from, from + length);
    const stated = bytes.readUInt32BE(from + length);
    if (crc32(bytes.subarray(at + 4, from + length)) !== stated) {
      fail(`the PNG chunk ${kind} does not match its CRC`);
    }
    at = from + length + 4;
    if (kind === "IHDR") {
      if (length !== 13) fail("the PNG IHDR chunk is not 13 octets");
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      depth = data[8]!;
      colour = data[9]!;
      if (data[10] !== 0) fail("the PNG compression method is not the one defined");
      if (data[11] !== 0) fail("the PNG filter method is not the one defined");
      if (data[12] !== 0) fail("an interlaced PNG is not decoded by this server");
      if (depth !== 8) fail(`a PNG of ${depth} bits per sample is not decoded by this server`);
      if (PNG_CHANNELS[colour] === undefined) fail(`the PNG colour type ${colour} is not defined`);
      if (width === 0 || height === 0) fail("a PNG of no extent");
      seenHeader = true;
    } else if (kind === "PLTE") {
      palette = Buffer.from(data);
    } else if (kind === "tRNS") {
      alpha = Buffer.from(data);
    } else if (kind === "IDAT") {
      idat.push(Buffer.from(data));
    } else if (kind === "IEND") {
      break;
    }
  }
  if (!seenHeader) fail("the value holds no PNG IHDR chunk");
  if (idat.length === 0) fail("the value holds no PNG image data");
  let raw: Buffer;
  try {
    raw = inflateSync(Buffer.concat(idat));
  } catch (e) {
    return fail(`the PNG image data do not decompress: ${(e as Error).message}`);
  }
  const channels = PNG_CHANNELS[colour]!;
  const rows = unfilter(raw, width, height, channels);
  const pixels = Buffer.alloc(width * height * 4);
  for (let i = 0, n = width * height; i < n; i++) {
    const s = i * channels;
    const d = i * 4;
    switch (colour) {
      case 0:
        pixels[d] = pixels[d + 1] = pixels[d + 2] = rows[s]!;
        pixels[d + 3] = 255;
        break;
      case 2:
        pixels[d] = rows[s]!; pixels[d + 1] = rows[s + 1]!; pixels[d + 2] = rows[s + 2]!;
        pixels[d + 3] = 255;
        break;
      case 3: {
        const index = rows[s]!;
        if (palette === undefined) fail("a PNG of the palette colour type holds no PLTE chunk");
        if (index * 3 + 2 >= palette!.length) fail("a PNG palette index names no entry");
        pixels[d] = palette![index * 3]!;
        pixels[d + 1] = palette![index * 3 + 1]!;
        pixels[d + 2] = palette![index * 3 + 2]!;
        pixels[d + 3] = alpha !== undefined && index < alpha.length ? alpha[index]! : 255;
        break;
      }
      case 4:
        pixels[d] = pixels[d + 1] = pixels[d + 2] = rows[s]!;
        pixels[d + 3] = rows[s + 1]!;
        break;
      default:
        pixels[d] = rows[s]!; pixels[d + 1] = rows[s + 1]!; pixels[d + 2] = rows[s + 2]!;
        pixels[d + 3] = rows[s + 3]!;
        break;
    }
  }
  return { width, height, pixels };
}

function chunk(kind: string, data: Buffer): Buffer {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length, 0);
  head.write(kind, 4, "latin1");
  const tail = Buffer.alloc(4);
  tail.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), data])), 0);
  return Buffer.concat([head, data, tail]);
}

function encodePng(r: Raster): Buffer {
  // Truecolour without alpha where every pixel is opaque, so that a JPEG turned
  // into a PNG does not carry an alpha channel of nothing but 255.
  let opaque = true;
  for (let i = 3; i < r.pixels.length; i += 4) {
    if (r.pixels[i] !== 255) { opaque = false; break; }
  }
  const channels = opaque ? 3 : 4;
  const stride = r.width * channels;
  // Each scanline is filtered with Paeth, which predicts from the three
  // neighbours and compresses a photograph far better than no filter at all.
  const raw = Buffer.alloc((stride + 1) * r.height);
  let out = 0;
  const row = Buffer.alloc(stride);
  const prior = Buffer.alloc(stride);
  for (let y = 0; y < r.height; y++) {
    for (let x = 0; x < r.width; x++) {
      const s = (y * r.width + x) * 4;
      const d = x * channels;
      row[d] = r.pixels[s]!;
      row[d + 1] = r.pixels[s + 1]!;
      row[d + 2] = r.pixels[s + 2]!;
      if (channels === 4) row[d + 3] = r.pixels[s + 3]!;
    }
    raw[out++] = 4;
    for (let i = 0; i < stride; i++) {
      const a = i >= channels ? row[i - channels]! : 0;
      const b = prior[i]!;
      const c = i >= channels ? prior[i - channels]! : 0;
      const p = a + b - c;
      const pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
      const pred = pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
      raw[out++] = (row[i]! - pred) & 0xff;
    }
    row.copy(prior);
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(r.width, 0);
  header.writeUInt32BE(r.height, 4);
  header[8] = 8;
  header[9] = opaque ? 2 : 6;
  return Buffer.concat([
    PNG_SIGNATURE,
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

// --- the two entry points ------------------------------------------------------

/** Decodes a value of one of the two media types into pixels. */
export function decode(bytes: Buffer, type: string): Raster {
  if (type === PNG) return decodePng(bytes);
  if (type === JPEG) return decodeJpeg(bytes);
  return fail(`${type} is not a raster media type this server decodes`);
}

/**
 * Encodes pixels as one of the two media types.
 *
 * A JPEG carries no alpha channel, so a pixel that is not opaque is composited
 * onto white. That is a loss, and it is the loss a JPEG of a transparent image
 * necessarily is; the PNG representation of the same object keeps the alpha.
 */
export function encode(r: Raster, type: string, opts: { quality?: number } = {}): Buffer {
  if (r.pixels.length !== r.width * r.height * 4) {
    fail("the pixels do not match the extent");
  }
  if (type === PNG) return encodePng(r);
  if (type === JPEG) return encodeJpeg(r, opts.quality ?? 85);
  return fail(`${type} is not a raster media type this server encodes`);
}

// --- JPEG: the shared tables ---------------------------------------------------

/** The zigzag order of Annex A: the index in a block of each coefficient in order. */
const ZIGZAG = [
  0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5,
  12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
  35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
  58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

/** The luminance and chrominance quantization tables of Annex K, at quality 50. */
const Q_LUMA = [
  16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55,
  14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62,
  18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92,
  49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
];
const Q_CHROMA = [
  17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99,
  24, 26, 56, 99, 99, 99, 99, 99, 47, 66, 99, 99, 99, 99, 99, 99,
  99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
  99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
];

/** The Huffman tables of Annex K, as counts of codes per length and the values. */
const K_DC_LUMA_BITS = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0];
const K_DC_LUMA_VALS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
const K_DC_CHROMA_BITS = [0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0];
const K_DC_CHROMA_VALS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
const K_AC_LUMA_BITS = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d];
const K_AC_LUMA_VALS = [
  0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
  0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0,
  0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
  0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
  0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
  0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
  0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
  0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5,
  0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
  0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
  0xf9, 0xfa,
];
const K_AC_CHROMA_BITS = [0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 0x77];
const K_AC_CHROMA_VALS = [
  0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61, 0x71,
  0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91, 0xa1, 0xb1, 0xc1, 0x09, 0x23, 0x33, 0x52, 0xf0,
  0x15, 0x62, 0x72, 0xd1, 0x0a, 0x16, 0x24, 0x34, 0xe1, 0x25, 0xf1, 0x17, 0x18, 0x19, 0x1a, 0x26,
  0x27, 0x28, 0x29, 0x2a, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
  0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
  0x69, 0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
  0x88, 0x89, 0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5,
  0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3,
  0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
  0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
  0xf9, 0xfa,
];

const clamp = (v: number): number => (v < 0 ? 0 : v > 255 ? 255 : v | 0);

/**
 * The inverse DCT of one eight by eight block, separable and in floating point.
 *
 * A fixed-point integer transform is faster and is what a codec of this kind
 * usually carries; this one is written for being obviously the transform Annex A
 * defines, since what it is here for is correctness of a conversion and not
 * throughput.
 */
const COS = (() => {
  const t = new Float64Array(64);
  for (let u = 0; u < 8; u++) {
    for (let x = 0; x < 8; x++) {
      t[u * 8 + x] = (u === 0 ? Math.SQRT1_2 : 1) * Math.cos(((2 * x + 1) * u * Math.PI) / 16);
    }
  }
  return t;
})();

function idct(block: Float64Array, out: Uint8ClampedArray): void {
  const tmp = new Float64Array(64);
  // Rows, then columns.
  for (let y = 0; y < 8; y++) {
    for (let x = 0; x < 8; x++) {
      let s = 0;
      for (let u = 0; u < 8; u++) s += COS[u * 8 + x]! * block[y * 8 + u]!;
      tmp[y * 8 + x] = s / 2;
    }
  }
  for (let x = 0; x < 8; x++) {
    for (let y = 0; y < 8; y++) {
      let s = 0;
      for (let v = 0; v < 8; v++) s += COS[v * 8 + y]! * tmp[v * 8 + x]!;
      out[y * 8 + x] = Math.round(s / 2) + 128;
    }
  }
}

function fdct(block: Float64Array): void {
  const tmp = new Float64Array(64);
  for (let y = 0; y < 8; y++) {
    for (let u = 0; u < 8; u++) {
      let s = 0;
      for (let x = 0; x < 8; x++) s += COS[u * 8 + x]! * block[y * 8 + x]!;
      tmp[y * 8 + u] = s / 2;
    }
  }
  for (let u = 0; u < 8; u++) {
    for (let v = 0; v < 8; v++) {
      let s = 0;
      for (let y = 0; y < 8; y++) s += COS[v * 8 + y]! * tmp[y * 8 + u]!;
      block[v * 8 + u] = s / 2;
    }
  }
}

// --- JPEG decoding -------------------------------------------------------------

interface HuffTable {
  /** The value of a code, by length then by the code's offset within that length. */
  lookup: Map<number, number>;
}

function huffTable(counts: number[], values: number[]): HuffTable {
  const lookup = new Map<number, number>();
  let code = 0;
  let k = 0;
  for (let length = 1; length <= 16; length++) {
    for (let i = 0; i < (counts[length - 1] ?? 0); i++) {
      // The key is the length and the code together, which is unique because a
      // Huffman code is a prefix code.
      lookup.set((length << 16) | code, values[k++]!);
      code++;
    }
    code <<= 1;
  }
  return { lookup };
}

/** A reader of the entropy-coded segment: bits, with the byte stuffing removed. */
class BitReader {
  private readonly bytes: Buffer;
  private at: number;
  private bits = 0;
  private held = 0;

  constructor(bytes: Buffer, at: number) {
    this.bytes = bytes;
    this.at = at;
  }

  /** Where the reader has reached, for finding the next marker. */
  get position(): number {
    return this.at;
  }

  /** Discards any part-read octet, as a restart interval requires. */
  align(): void {
    this.bits = 0;
    this.held = 0;
  }

  bit(): number {
    if (this.bits === 0) {
      let b = this.bytes[this.at++];
      if (b === undefined) b = 0;
      if (b === 0xff) {
        const next = this.bytes[this.at];
        // "FF 00" is a stuffed FF; any other FF is a marker, and the scan ends.
        if (next === 0x00) this.at++;
        else if (next !== undefined && next >= 0xd0 && next <= 0xd7) {
          // A restart marker reached by the bit reader: step over it.
          this.at++;
          b = this.bytes[this.at++] ?? 0;
        } else {
          this.at--;
          b = 0;
        }
      }
      this.held = b;
      this.bits = 8;
    }
    this.bits--;
    return (this.held >> this.bits) & 1;
  }

  bitsOf(n: number): number {
    let v = 0;
    for (let i = 0; i < n; i++) v = (v << 1) | this.bit();
    return v;
  }

  decode(table: HuffTable): number {
    let code = 0;
    for (let length = 1; length <= 16; length++) {
      code = (code << 1) | this.bit();
      const v = table.lookup.get((length << 16) | code);
      if (v !== undefined) return v;
    }
    return fail("a JPEG Huffman code of more than sixteen bits");
  }
}

/** The signed value of n additional bits, as Annex F defines the extension. */
const extend = (v: number, n: number): number => (n === 0 ? 0 : v < 1 << (n - 1) ? v - (1 << n) + 1 : v);

interface Component {
  id: number;
  h: number;
  v: number;
  quant: number;
  dcTable: number;
  acTable: number;
  /** The samples of this component, at its own resolution. */
  data: Uint8ClampedArray;
  lineWidth: number;
  lines: number;
}

function decodeJpeg(bytes: Buffer): Raster {
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) {
    fail("the value does not begin with a JPEG start of image marker");
  }
  const quant: (Int32Array | undefined)[] = [];
  const dc: (HuffTable | undefined)[] = [];
  const ac: (HuffTable | undefined)[] = [];
  let width = 0, height = 0;
  let components: Component[] = [];
  let restart = 0;
  let at = 2;
  let hMax = 1, vMax = 1;

  while (at + 1 < bytes.length) {
    if (bytes[at] !== 0xff) { at++; continue; }
    const marker = bytes[at + 1]!;
    at += 2;
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
    if (marker === 0xd9) break;
    if (at + 2 > bytes.length) fail("a JPEG segment has no length");
    const length = bytes.readUInt16BE(at);
    const seg = bytes.subarray(at + 2, at + length);
    if (marker === 0xc0 || marker === 0xc1) {
      // SOF0 baseline and SOF1 extended sequential, which decode alike.
      if (seg[0] !== 8) fail(`a JPEG of ${seg[0]} bits per sample is not decoded by this server`);
      height = seg.readUInt16BE(1);
      width = seg.readUInt16BE(3);
      const n = seg[5]!;
      components = [];
      for (let i = 0; i < n; i++) {
        const o = 6 + i * 3;
        components.push({
          id: seg[o]!, h: seg[o + 1]! >> 4, v: seg[o + 1]! & 15, quant: seg[o + 2]!,
          dcTable: 0, acTable: 0, data: new Uint8ClampedArray(0), lineWidth: 0, lines: 0,
        });
      }
      if (components.length !== 1 && components.length !== 3) {
        fail(`a JPEG of ${components.length} components is not decoded by this server`);
      }
      hMax = Math.max(...components.map((c) => c.h));
      vMax = Math.max(...components.map((c) => c.v));
    } else if (marker >= 0xc2 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
      return fail("a JPEG that is not baseline sequential is not decoded by this server: " +
        `the frame marker is FF${marker.toString(16).toUpperCase()}`);
    } else if (marker === 0xdb) {
      let o = 0;
      while (o < seg.length) {
        const pq = seg[o]! >> 4, tq = seg[o]! & 15;
        o++;
        const t = new Int32Array(64);
        for (let i = 0; i < 64; i++) {
          t[ZIGZAG[i]!] = pq === 0 ? seg[o + i]! : seg.readUInt16BE(o + i * 2);
        }
        o += pq === 0 ? 64 : 128;
        quant[tq] = t;
      }
    } else if (marker === 0xc4) {
      let o = 0;
      while (o < seg.length) {
        const tc = seg[o]! >> 4, th = seg[o]! & 15;
        o++;
        const counts: number[] = [];
        let total = 0;
        for (let i = 0; i < 16; i++) { counts.push(seg[o + i]!); total += seg[o + i]!; }
        o += 16;
        const values: number[] = [];
        for (let i = 0; i < total; i++) values.push(seg[o + i]!);
        o += total;
        (tc === 0 ? dc : ac)[th] = huffTable(counts, values);
      }
    } else if (marker === 0xdd) {
      restart = seg.readUInt16BE(0);
    } else if (marker === 0xda) {
      const n = seg[0]!;
      for (let i = 0; i < n; i++) {
        const id = seg[1 + i * 2]!;
        const tables = seg[2 + i * 2]!;
        const c = components.find((x) => x.id === id);
        if (c === undefined) fail("a JPEG scan names a component the frame does not");
        c!.dcTable = tables >> 4;
        c!.acTable = tables & 15;
      }
      at = decodeScan(bytes, at + length, components, quant, dc, ac, restart, hMax, vMax, width, height);
      continue;
    }
    at += length;
  }
  if (width === 0 || height === 0 || components.length === 0) {
    fail("the value holds no JPEG frame header");
  }
  return toRgba(components, width, height, hMax, vMax);
}

function decodeScan(bytes: Buffer, from: number, components: Component[],
  quant: (Int32Array | undefined)[], dc: (HuffTable | undefined)[], ac: (HuffTable | undefined)[],
  restart: number, hMax: number, vMax: number, width: number, height: number): number {
  const mcusX = Math.ceil(width / (8 * hMax));
  const mcusY = Math.ceil(height / (8 * vMax));
  for (const c of components) {
    c.lineWidth = mcusX * c.h * 8;
    c.lines = mcusY * c.v * 8;
    c.data = new Uint8ClampedArray(c.lineWidth * c.lines);
  }
  const reader = new BitReader(bytes, from);
  const predictor = new Map<number, number>();
  for (const c of components) predictor.set(c.id, 0);
  const block = new Float64Array(64);
  const out = new Uint8ClampedArray(64);
  let sinceRestart = 0;
  for (let my = 0; my < mcusY; my++) {
    for (let mx = 0; mx < mcusX; mx++) {
      if (restart > 0 && sinceRestart === restart) {
        reader.align();
        for (const c of components) predictor.set(c.id, 0);
        sinceRestart = 0;
      }
      sinceRestart++;
      for (const c of components) {
        const q = quant[c.quant];
        if (q === undefined) fail("a JPEG component names a quantization table the value does not hold");
        const dcT = dc[c.dcTable], acT = ac[c.acTable];
        if (dcT === undefined || acT === undefined) {
          fail("a JPEG scan names a Huffman table the value does not hold");
        }
        for (let by = 0; by < c.v; by++) {
          for (let bx = 0; bx < c.h; bx++) {
            block.fill(0);
            const t = reader.decode(dcT!);
            const diff = extend(reader.bitsOf(t), t);
            const value = predictor.get(c.id)! + diff;
            predictor.set(c.id, value);
            block[0] = value * q![0]!;
            let k = 1;
            while (k < 64) {
              const rs = reader.decode(acT!);
              const run = rs >> 4, size = rs & 15;
              if (size === 0) {
                if (run !== 15) break;
                k += 16;
                continue;
              }
              k += run;
              if (k > 63) break;
              const z = ZIGZAG[k]!;
              block[z] = extend(reader.bitsOf(size), size) * q![z]!;
              k++;
            }
            idct(block, out);
            const ox = (mx * c.h + bx) * 8;
            const oy = (my * c.v + by) * 8;
            for (let y = 0; y < 8; y++) {
              const row = (oy + y) * c.lineWidth + ox;
              for (let x = 0; x < 8; x++) c.data[row + x] = out[y * 8 + x]!;
            }
          }
        }
      }
    }
  }
  // The next marker after the scan: skip the stuffed data the reader consumed.
  let at = reader.position;
  while (at + 1 < bytes.length && !(bytes[at] === 0xff && bytes[at + 1] !== 0x00 &&
    !(bytes[at + 1]! >= 0xd0 && bytes[at + 1]! <= 0xd7))) at++;
  return at;
}

function toRgba(components: Component[], width: number, height: number,
  hMax: number, vMax: number): Raster {
  const pixels = Buffer.alloc(width * height * 4);
  /**
   * A component's sample at a full-resolution position, interpolated.
   *
   * A subsampled component is upsampled with the triangular filter, which is
   * what the common decoders do by default. Taking the nearest sample instead is
   * a legitimate reading of the standard — it mandates no filter — and it was
   * what this decoder did first; measured against an independent decoder, a
   * 4:2:0 photograph then differed by as much as 59 of 255 at a hard chroma
   * edge, against 5 on a smooth one. The decode was right and the blockiness was
   * the filter, which nobody comparing this server's PNG of a JPEG against
   * another tool's would read as anything but a defect.
   */
  const sample = (c: Component, x: number, y: number): number => {
    if (c.h === hMax && c.v === vMax) {
      const sx = Math.min(x, c.lineWidth - 1);
      const sy = Math.min(y, c.lines - 1);
      return c.data[sy * c.lineWidth + sx]!;
    }
    // The position of this output pixel's centre in the component's own grid.
    const fx = ((x + 0.5) * c.h) / hMax - 0.5;
    const fy = ((y + 0.5) * c.v) / vMax - 0.5;
    const x0 = Math.floor(fx), y0 = Math.floor(fy);
    const tx = fx - x0, ty = fy - y0;
    const at = (px: number, py: number): number => {
      const cx = px < 0 ? 0 : px >= c.lineWidth ? c.lineWidth - 1 : px;
      const cy = py < 0 ? 0 : py >= c.lines ? c.lines - 1 : py;
      return c.data[cy * c.lineWidth + cx]!;
    };
    const top = at(x0, y0) * (1 - tx) + at(x0 + 1, y0) * tx;
    const bottom = at(x0, y0 + 1) * (1 - tx) + at(x0 + 1, y0 + 1) * tx;
    return top * (1 - ty) + bottom * ty;
  };
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const d = (y * width + x) * 4;
      if (components.length === 1) {
        const g = sample(components[0]!, x, y);
        pixels[d] = pixels[d + 1] = pixels[d + 2] = g;
      } else {
        const Y = sample(components[0]!, x, y);
        const cb = sample(components[1]!, x, y) - 128;
        const cr = sample(components[2]!, x, y) - 128;
        pixels[d] = clamp(Y + 1.402 * cr);
        pixels[d + 1] = clamp(Y - 0.344136 * cb - 0.714136 * cr);
        pixels[d + 2] = clamp(Y + 1.772 * cb);
      }
      pixels[d + 3] = 255;
    }
  }
  return { width, height, pixels };
}

// --- JPEG encoding -------------------------------------------------------------

/** A writer of the entropy-coded segment: bits, with FF stuffed as FF 00. */
class BitWriter {
  private readonly out: number[] = [];
  private held = 0;
  private bits = 0;

  write(code: number, length: number): void {
    for (let i = length - 1; i >= 0; i--) {
      this.held = (this.held << 1) | ((code >> i) & 1);
      this.bits++;
      if (this.bits === 8) {
        this.out.push(this.held & 0xff);
        if ((this.held & 0xff) === 0xff) this.out.push(0x00);
        this.held = 0;
        this.bits = 0;
      }
    }
  }

  /** Pads with one bits to the octet boundary, as Annex F requires at the end. */
  finish(): Buffer {
    while (this.bits !== 0) this.write(1, 1);
    return Buffer.from(this.out);
  }
}

/** The code and length of each value of a Huffman table, for encoding. */
function huffCodes(counts: number[], values: number[]): Map<number, [number, number]> {
  const out = new Map<number, [number, number]>();
  let code = 0, k = 0;
  for (let length = 1; length <= 16; length++) {
    for (let i = 0; i < (counts[length - 1] ?? 0); i++) {
      out.set(values[k++]!, [code, length]);
      code++;
    }
    code <<= 1;
  }
  return out;
}

/** The magnitude category of a coefficient, and the bits that follow it. */
function category(v: number): [number, number] {
  const a = Math.abs(v);
  let size = 0;
  while ((1 << size) <= a) size++;
  return [size, v < 0 ? v + (1 << size) - 1 : v];
}

function scaled(table: number[], quality: number): Int32Array {
  // The scaling of the reference implementation: quality 50 is the table itself.
  const q = Math.min(100, Math.max(1, Math.round(quality)));
  const factor = q < 50 ? 5000 / q : 200 - q * 2;
  const out = new Int32Array(64);
  for (let i = 0; i < 64; i++) {
    out[i] = Math.min(255, Math.max(1, Math.round((table[i]! * factor + 50) / 100)));
  }
  return out;
}

function segment(marker: number, body: Buffer): Buffer {
  const head = Buffer.alloc(4);
  head[0] = 0xff;
  head[1] = marker;
  head.writeUInt16BE(body.length + 2, 2);
  return Buffer.concat([head, body]);
}

function encodeJpeg(r: Raster, quality: number): Buffer {
  const qL = scaled(Q_LUMA, quality);
  const qC = scaled(Q_CHROMA, quality);
  // Three components at full resolution: no chroma subsampling, so the encoder
  // needs no downsampling and a conversion loses nothing beyond the quantization.
  const n = r.width * r.height;
  const Y = new Float64Array(n), Cb = new Float64Array(n), Cr = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    const s = i * 4;
    const a = r.pixels[s + 3]! / 255;
    // A JPEG carries no alpha, so a pixel that is not opaque is composited onto
    // white. The PNG representation of the same object keeps the alpha.
    const red = r.pixels[s]! * a + 255 * (1 - a);
    const green = r.pixels[s + 1]! * a + 255 * (1 - a);
    const blue = r.pixels[s + 2]! * a + 255 * (1 - a);
    Y[i] = 0.299 * red + 0.587 * green + 0.114 * blue - 128;
    Cb[i] = -0.168736 * red - 0.331264 * green + 0.5 * blue;
    Cr[i] = 0.5 * red - 0.418688 * green - 0.081312 * blue;
  }
  const dcL = huffCodes(K_DC_LUMA_BITS, K_DC_LUMA_VALS);
  const acL = huffCodes(K_AC_LUMA_BITS, K_AC_LUMA_VALS);
  const dcC = huffCodes(K_DC_CHROMA_BITS, K_DC_CHROMA_VALS);
  const acC = huffCodes(K_AC_CHROMA_BITS, K_AC_CHROMA_VALS);
  const writer = new BitWriter();
  const block = new Float64Array(64);
  const planes: [Float64Array, Int32Array, Map<number, [number, number]>, Map<number, [number, number]>][] = [
    [Y, qL, dcL, acL], [Cb, qC, dcC, acC], [Cr, qC, dcC, acC],
  ];
  const predictor = [0, 0, 0];
  for (let by = 0; by < Math.ceil(r.height / 8); by++) {
    for (let bx = 0; bx < Math.ceil(r.width / 8); bx++) {
      for (let p = 0; p < 3; p++) {
        const [plane, q, dcT, acT] = planes[p]!;
        for (let y = 0; y < 8; y++) {
          for (let x = 0; x < 8; x++) {
            // A block past the edge repeats the last row or column, which is
            // what keeps the edge from ringing against black.
            const sx = Math.min(bx * 8 + x, r.width - 1);
            const sy = Math.min(by * 8 + y, r.height - 1);
            block[y * 8 + x] = plane[sy * r.width + sx]!;
          }
        }
        fdct(block);
        const zz = new Int32Array(64);
        for (let i = 0; i < 64; i++) {
          const z = ZIGZAG[i]!;
          zz[i] = Math.round(block[z]! / q[z]!);
        }
        const diff = zz[0]! - predictor[p]!;
        predictor[p] = zz[0]!;
        const [size, bits] = category(diff);
        const dcCode = dcT.get(size);
        if (dcCode === undefined) fail("a JPEG DC category outside the standard table");
        writer.write(dcCode![0], dcCode![1]);
        if (size > 0) writer.write(bits, size);
        let run = 0;
        for (let k = 1; k < 64; k++) {
          if (zz[k] === 0) { run++; continue; }
          while (run > 15) {
            const zrl = acT.get(0xf0)!;
            writer.write(zrl[0], zrl[1]);
            run -= 16;
          }
          const [s, b] = category(zz[k]!);
          const code = acT.get((run << 4) | s);
          if (code === undefined) fail("a JPEG AC symbol outside the standard table");
          writer.write(code![0], code![1]);
          writer.write(b, s);
          run = 0;
        }
        if (run > 0) {
          const eob = acT.get(0x00)!;
          writer.write(eob[0], eob[1]);
        }
      }
    }
  }
  const dqt = (id: number, q: Int32Array): Buffer => {
    const body = Buffer.alloc(65);
    body[0] = id;
    for (let i = 0; i < 64; i++) body[1 + i] = q[ZIGZAG[i]!]!;
    return segment(0xdb, body);
  };
  const dht = (id: number, counts: number[], values: number[]): Buffer =>
    segment(0xc4, Buffer.concat([Buffer.from([id]), Buffer.from(counts), Buffer.from(values)]));
  const sof = Buffer.alloc(15);
  sof[0] = 8;
  sof.writeUInt16BE(r.height, 1);
  sof.writeUInt16BE(r.width, 3);
  sof[5] = 3;
  for (let i = 0; i < 3; i++) {
    sof[6 + i * 3] = i + 1;
    sof[7 + i * 3] = 0x11;
    sof[8 + i * 3] = i === 0 ? 0 : 1;
  }
  const sos = Buffer.from([3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0]);
  return Buffer.concat([
    Buffer.from([0xff, 0xd8]),
    segment(0xe0, Buffer.concat([Buffer.from("JFIF\0", "latin1"),
      Buffer.from([1, 1, 0, 0, 1, 0, 1, 0, 0])])),
    dqt(0, qL), dqt(1, qC),
    segment(0xc0, sof),
    dht(0x00, K_DC_LUMA_BITS, K_DC_LUMA_VALS),
    dht(0x10, K_AC_LUMA_BITS, K_AC_LUMA_VALS),
    dht(0x01, K_DC_CHROMA_BITS, K_DC_CHROMA_VALS),
    dht(0x11, K_AC_CHROMA_BITS, K_AC_CHROMA_VALS),
    segment(0xda, sos),
    writer.finish(),
    Buffer.from([0xff, 0xd9]),
  ]);
}
