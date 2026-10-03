// Partition tables. An image import may name a partition of the image
// rather than a file system beginning at its first byte, so the driver has
// to read the table to find where that partition begins.
//
// Both schemes are read: the MBR table of four entries in the boot sector,
// and the GPT, whose protective MBR holds a single entry of type 0xEE.

import type { Image } from "./fat.ts";

export interface Partition {
  /** Its position in the table, counting from one, as the draft counts. */
  number: number;
  /** The first byte of the partition within the image. */
  offset: number;
  /** Its length in bytes. */
  bytes: number;
  /** The MBR type byte, or the GPT type GUID. */
  type: string;
  /** The partition name, where the scheme records one. */
  name?: string;
}

export type Scheme = "MBR" | "GPT" | "none";

const SECTOR = 512;
const MBR_TYPE_GPT_PROTECTIVE = 0xee;

/** The partitions of an image, and the scheme that describes them. */
export async function partitions(img: Image):
  Promise<{ scheme: Scheme; partitions: Partition[] }> {
  const size = await img.size();
  if (size < 2 * SECTOR) return { scheme: "none", partitions: [] };
  const boot = await img.read(0, SECTOR);
  if (boot.length < SECTOR || boot.readUInt16LE(510) !== 0xaa55) {
    return { scheme: "none", partitions: [] };
  }

  const mbr: Partition[] = [];
  let protective = false;
  for (let i = 0; i < 4; i++) {
    const e = boot.subarray(446 + i * 16, 446 + (i + 1) * 16);
    const type = e[4];
    const first = e.readUInt32LE(8);
    const count = e.readUInt32LE(12);
    if (type === 0 || count === 0) continue;
    if (type === MBR_TYPE_GPT_PROTECTIVE) {
      protective = true;
      continue;
    }
    mbr.push({
      number: i + 1,
      offset: first * SECTOR,
      bytes: count * SECTOR,
      type: `0x${type.toString(16).padStart(2, "0")}`,
    });
  }

  if (protective || (mbr.length === 0 && await hasGPT(img))) {
    const gpt = await readGPT(img, size);
    if (gpt.length > 0) return { scheme: "GPT", partitions: gpt };
  }
  if (mbr.length > 0) return { scheme: "MBR", partitions: mbr };
  return { scheme: "none", partitions: [] };
}

async function hasGPT(img: Image): Promise<boolean> {
  const header = await img.read(SECTOR, 8);
  return header.length === 8 && header.toString("latin1") === "EFI PART";
}

async function readGPT(img: Image, size: number): Promise<Partition[]> {
  const header = await img.read(SECTOR, 92);
  if (header.length < 92 || header.subarray(0, 8).toString("latin1") !== "EFI PART") {
    return [];
  }
  const tableLBA = readU64LE(header, 72);
  const count = header.readUInt32LE(80);
  const entrySize = header.readUInt32LE(84);
  if (entrySize < 128 || count === 0 || count > 4096) return [];

  const at = tableLBA * SECTOR;
  const bytes = Math.min(count * entrySize, Math.max(size - at, 0));
  if (bytes <= 0) return [];
  const table = await img.read(at, bytes);

  const out: Partition[] = [];
  for (let i = 0; i < count && (i + 1) * entrySize <= table.length; i++) {
    const e = table.subarray(i * entrySize, (i + 1) * entrySize);
    if (e.subarray(0, 16).every((b: number) => b === 0)) continue;
    const firstLBA = readU64LE(e, 32);
    const lastLBA = readU64LE(e, 40);
    if (lastLBA < firstLBA) continue;
    out.push({
      number: i + 1,
      offset: firstLBA * SECTOR,
      bytes: (lastLBA - firstLBA + 1) * SECTOR,
      type: guid(e.subarray(0, 16)),
      name: decodeName(e.subarray(56, 128)),
    });
  }
  return out;
}

function readU64LE(b: Buffer, at: number): number {
  const value = b.readBigUInt64LE(at);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("a partition offset beyond the range of an exact integer");
  }
  return Number(value);
}

/** A GUID in the mixed-endian form the tables use. */
function guid(b: Buffer): string {
  const hex = (from: number, to: number, reverse: boolean) => {
    const part = Array.from(b.subarray(from, to));
    if (reverse) part.reverse();
    return part.map((x) => x.toString(16).padStart(2, "0")).join("");
  };
  return [hex(0, 4, true), hex(4, 6, true), hex(6, 8, true), hex(8, 10, false),
    hex(10, 16, false)].join("-");
}

function decodeName(b: Buffer): string | undefined {
  let out = "";
  for (let i = 0; i + 1 < b.length; i += 2) {
    const code = b.readUInt16LE(i);
    if (code === 0) break;
    out += String.fromCharCode(code);
  }
  return out === "" ? undefined : out;
}

/** An image restricted to one partition, so the driver sees its bytes alone. */
export class PartitionImage implements Image {
  private readonly inner: Image;
  private readonly at: number;
  private readonly length: number;

  constructor(inner: Image, offset: number, bytes: number) {
    this.inner = inner;
    this.at = offset;
    this.length = bytes;
  }

  async size(): Promise<number> {
    return this.length;
  }

  async read(offset: number, length: number): Promise<Buffer> {
    const from = Math.max(offset, 0);
    const want = Math.max(Math.min(length, this.length - from), 0);
    if (want === 0) return Buffer.alloc(0);
    return this.inner.read(this.at + from, want);
  }

  async write(offset: number, data: Buffer): Promise<void> {
    if (offset < 0 || offset + data.length > this.length) {
      throw new Error("a write beyond the end of the partition");
    }
    return this.inner.write(this.at + offset, data);
  }
}
