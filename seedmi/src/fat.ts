// A FAT file system held in a sequence of bytes, which an image import
// presents as a namespace. The layout follows the Microsoft FAT
// specification: a BPB in the boot sector, one or two file allocation
// tables, and a data region of clusters, with long names carried in the
// directory entries that precede each short one.
//
// FAT12, FAT16 and FAT32 differ in three places, and are otherwise one
// format, so this driver presents them under the single identifier "FAT"
// and determines which it is looking at the way the specification says: by
// counting the data clusters. The differences are the width of a FAT entry,
// the value that ends a chain, and the root directory, which on FAT12 and
// FAT16 is a fixed region of sectors rather than a cluster chain.
//
// The driver reads and writes through an Image, so the same code serves an
// image held in the value of a data object and one held in a buffer in a
// test.

/** A byte-addressable image. Offsets are from the start of the file system. */
export interface Image {
  size(): Promise<number>;
  read(offset: number, length: number): Promise<Buffer>;
  write(offset: number, data: Buffer): Promise<void>;
}

/**
 * An image held in memory. It records the ranges written, so that a
 * caller holding the image on behalf of something slower, such as the
 * value of a data object, can write back what changed rather than the
 * whole of it.
 */
export class BufferImage implements Image {
  buffer: Buffer;
  private dirty: { from: number; to: number }[] = [];

  constructor(bytes: number | Buffer) {
    this.buffer = typeof bytes === "number" ? Buffer.alloc(bytes) : bytes;
  }

  /** The ranges written since they were last taken, merged and in order. */
  takeDirty(): { from: number; to: number }[] {
    const ranges = this.dirty.slice().sort((a, b) => a.from - b.from);
    this.dirty = [];
    const merged: { from: number; to: number }[] = [];
    for (const r of ranges) {
      const last = merged[merged.length - 1];
      if (last && r.from <= last.to) {
        last.to = Math.max(last.to, r.to);
      } else {
        merged.push({ ...r });
      }
    }
    return merged;
  }

  get hasDirty(): boolean {
    return this.dirty.length > 0;
  }

  async size(): Promise<number> {
    return this.buffer.length;
  }

  async read(offset: number, length: number): Promise<Buffer> {
    return Buffer.from(this.buffer.subarray(offset, offset + length));
  }

  async write(offset: number, data: Buffer): Promise<void> {
    if (offset + data.length > this.buffer.length) {
      throw new FATError("a write beyond the end of the image");
    }
    data.copy(this.buffer, offset);
    this.dirty.push({ from: offset, to: offset + data.length });
  }
}

export class FATError extends Error {}

export const ATTR_READ_ONLY = 0x01;
export const ATTR_HIDDEN = 0x02;
export const ATTR_SYSTEM = 0x04;
export const ATTR_VOLUME_ID = 0x08;
export const ATTR_DIRECTORY = 0x10;
export const ATTR_ARCHIVE = 0x20;
export const ATTR_LONG_NAME = 0x0f;

const FREE = 0x00000000;
const ENTRY_SIZE = 32;
const DELETED = 0xe5;

/** The three widths of the file allocation table. */
export type FATType = "FAT12" | "FAT16" | "FAT32";

/** The single identifier under which seedmi offers all three. */
export const FILESYSTEM_NAME = "FAT";

/** The value at or above which a FAT entry ends a chain. */
const EOC_OF: Record<FATType, number> = {
  FAT12: 0x0ff8,
  FAT16: 0xfff8,
  FAT32: 0x0ffffff8,
};

/** The value that marks a cluster bad. */
const BAD_OF: Record<FATType, number> = {
  FAT12: 0x0ff7,
  FAT16: 0xfff7,
  FAT32: 0x0ffffff7,
};

/** The end-of-chain value written into the table. */
const END_OF: Record<FATType, number> = {
  FAT12: 0x0fff,
  FAT16: 0xffff,
  FAT32: 0x0fffffff,
};

/**
 * The root directory of a FAT12 or FAT16 file system is a fixed region
 * rather than a chain, and is named by this cluster number, which no data
 * cluster can take.
 */
export const FIXED_ROOT = 0;

/** The fields of the BPB this driver uses. */
export interface BPB {
  bytesPerSector: number;
  sectorsPerCluster: number;
  reservedSectors: number;
  numberOfFATs: number;
  totalSectors: number;
  sectorsPerFAT: number;
  /** The first cluster of the root on FAT32; FIXED_ROOT on FAT12 and FAT16. */
  rootCluster: number;
  /** The number of 32-byte entries in the fixed root; zero on FAT32. */
  rootEntryCount: number;
  fsInfoSector: number;
  label: string;
}

/** One entry of a directory. */
export interface DirEntry {
  /** The name as presented: the long name where there is one. */
  name: string;
  /** The 8.3 name, as stored. */
  shortName: string;
  attr: number;
  cluster: number;
  size: number;
  mtime: Date;
  ctime: Date;
  atime: Date;
  /** Where the entry begins in its directory, in 32-byte slots. */
  slot: number;
  /** How many slots it occupies, including its long name entries. */
  slots: number;
}

export const isDirectory = (e: DirEntry) => (e.attr & ATTR_DIRECTORY) !== 0;
export const isReadOnly = (e: DirEntry) => (e.attr & ATTR_READ_ONLY) !== 0;

// ---------------------------------------------------------------------------
// Times

function fatDate(d: Date): number {
  const year = Math.max(d.getUTCFullYear() - 1980, 0);
  return ((year & 0x7f) << 9) | (((d.getUTCMonth() + 1) & 0x0f) << 5) |
    (d.getUTCDate() & 0x1f);
}

function fatTime(d: Date): number {
  return ((d.getUTCHours() & 0x1f) << 11) | ((d.getUTCMinutes() & 0x3f) << 5) |
    ((d.getUTCSeconds() >> 1) & 0x1f);
}

function fromFAT(date: number, time: number): Date {
  return new Date(Date.UTC(
    1980 + ((date >> 9) & 0x7f),
    Math.max(((date >> 5) & 0x0f) - 1, 0),
    Math.max(date & 0x1f, 1),
    (time >> 11) & 0x1f,
    (time >> 5) & 0x3f,
    (time & 0x1f) * 2,
  ));
}

// ---------------------------------------------------------------------------
// Names

/** The checksum of an 8.3 name, which ties long name entries to it. */
export function shortNameChecksum(short: Buffer): number {
  let sum = 0;
  for (let i = 0; i < 11; i++) {
    sum = (((sum & 1) ? 0x80 : 0) + (sum >> 1) + short[i]) & 0xff;
  }
  return sum;
}

const INVALID_SHORT = new Set(Array.from('"*+,./:;<=>?[\\]|'));

/** Whether a name fits in an 8.3 field without a long name entry. */
export function fitsShortName(name: string): boolean {
  if (name === "" || name === "." || name === "..") return false;
  if (name !== name.toUpperCase()) return false;
  const dot = name.lastIndexOf(".");
  const base = dot < 0 ? name : name.slice(0, dot);
  const ext = dot < 0 ? "" : name.slice(dot + 1);
  if (base.length === 0 || base.length > 8 || ext.length > 3) return false;
  if (name.slice(0, dot < 0 ? name.length : dot).includes(".")) return false;
  for (const ch of base + ext) {
    if (ch.charCodeAt(0) < 0x20 || ch.charCodeAt(0) > 0x7e) return false;
    if (ch === " " || INVALID_SHORT.has(ch)) return false;
  }
  return true;
}

function encodeShortName(name: string): Buffer {
  const out = Buffer.alloc(11, 0x20);
  const dot = name.lastIndexOf(".");
  const base = (dot < 0 ? name : name.slice(0, dot)).slice(0, 8);
  const ext = (dot < 0 ? "" : name.slice(dot + 1)).slice(0, 3);
  out.write(base.padEnd(8, " "), 0, "latin1");
  out.write(ext.padEnd(3, " "), 8, "latin1");
  return out;
}

function decodeShortName(raw: Buffer): string {
  const base = raw.subarray(0, 8).toString("latin1").replace(/ +$/, "");
  const ext = raw.subarray(8, 11).toString("latin1").replace(/ +$/, "");
  const name = ext === "" ? base : `${base}.${ext}`;
  return name.startsWith("\u0005") ? "\u00e5" + name.slice(1) : name;
}

/**
 * The 8.3 name to store for a long name: the name stripped of characters
 * a short name cannot hold, upper-cased, with a numeric tail to keep it
 * distinct from the names already present.
 */
export function generateShortName(name: string, taken: Set<string>): string {
  if (fitsShortName(name) && !taken.has(name)) return name;
  const cleaned = Array.from(name.toUpperCase())
    .filter((c) => c !== " " && c !== ".")
    .map((c) => (c.charCodeAt(0) > 0x7e || c.charCodeAt(0) < 0x20 ||
      INVALID_SHORT.has(c) ? "_" : c))
    .join("");
  const dot = name.lastIndexOf(".");
  const ext = dot < 0 ? "" : name.slice(dot + 1).toUpperCase()
    .replace(/[^A-Z0-9_~!#$%&'()@^{}-]/g, "_").slice(0, 3);
  const stem = (dot <= 0 ? cleaned : cleaned.slice(0, cleaned.length - ext.length)) || "FILE";
  for (let n = 1; n < 1_000_000; n++) {
    const tail = `~${n}`;
    const candidate = stem.slice(0, Math.max(8 - tail.length, 1)) + tail +
      (ext === "" ? "" : `.${ext}`);
    if (!taken.has(candidate)) return candidate;
  }
  throw new FATError(`no short name is available for ${JSON.stringify(name)}`);
}

/**
 * Whether a name can be stored in a FAT file system at all. The names a
 * CDMI object may not have are filtered separately, by the caller.
 */
export function storableName(name: string): boolean {
  if (name === "" || name === "." || name === "..") return false;
  if (name.length > 255) return false;
  if (name.endsWith(" ") || name.endsWith(".")) return false;
  for (const ch of name) {
    const c = ch.charCodeAt(0);
    if (c < 0x20 || c === 0x7f) return false;
    if ('"*/:<>?\\|'.includes(ch)) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------

export class FAT {
  readonly img: Image;
  readonly base: number;
  readonly bpb: BPB;
  readonly type: FATType;
  private readonly firstDataSector: number;
  private readonly rootDirSectors: number;
  readonly clusterSize: number;
  readonly countOfClusters: number;

  private constructor(img: Image, base: number, bpb: BPB) {
    this.img = img;
    this.base = base;
    this.bpb = bpb;
    // The fixed root of FAT12 and FAT16 lies between the tables and the
    // data region, and rounds up to a whole number of sectors.
    this.rootDirSectors = Math.ceil(
      (bpb.rootEntryCount * ENTRY_SIZE) / bpb.bytesPerSector);
    this.firstDataSector =
      bpb.reservedSectors + bpb.numberOfFATs * bpb.sectorsPerFAT + this.rootDirSectors;
    this.clusterSize = bpb.bytesPerSector * bpb.sectorsPerCluster;
    this.countOfClusters =
      Math.floor((bpb.totalSectors - this.firstDataSector) / bpb.sectorsPerCluster);
    // The specification determines the type by the cluster count alone,
    // and by nothing else: not by the file system type string, which is
    // advisory, and not by the size of the volume.
    this.type = this.countOfClusters < 4085
      ? "FAT12"
      : this.countOfClusters < 65525 ? "FAT16" : "FAT32";
  }

  /** Whether the root directory is a fixed region rather than a chain. */
  get fixedRoot(): boolean {
    return this.type !== "FAT32";
  }

  /** The cluster number that names the root directory. */
  get rootDirectory(): number {
    return this.fixedRoot ? FIXED_ROOT : this.bpb.rootCluster;
  }

  /** Opens the file system beginning at base within the image. */
  static async open(img: Image, base = 0): Promise<FAT> {
    const boot = await img.read(base, 512);
    if (boot.length < 512 || boot.readUInt16LE(510) !== 0xaa55) {
      throw new FATError("no boot sector signature: this is not a FAT file system");
    }
    const bytesPerSector = boot.readUInt16LE(11);
    if (![512, 1024, 2048, 4096].includes(bytesPerSector)) {
      throw new FATError(`${bytesPerSector} is not a valid sector size`);
    }
    // FAT12 and FAT16 carry the table size and the sector count in 16-bit
    // fields, and fall back to the 32-bit fields where they do not fit.
    const sectorsPerFAT16 = boot.readUInt16LE(22);
    const totalSectors16 = boot.readUInt16LE(19);
    const bpb: BPB = {
      bytesPerSector,
      sectorsPerCluster: boot.readUInt8(13),
      reservedSectors: boot.readUInt16LE(14),
      numberOfFATs: boot.readUInt8(16),
      totalSectors: totalSectors16 !== 0 ? totalSectors16 : boot.readUInt32LE(32),
      sectorsPerFAT: sectorsPerFAT16 !== 0 ? sectorsPerFAT16 : boot.readUInt32LE(36),
      rootCluster: sectorsPerFAT16 !== 0 ? FIXED_ROOT : boot.readUInt32LE(44),
      rootEntryCount: boot.readUInt16LE(17),
      fsInfoSector: sectorsPerFAT16 !== 0 ? 0 : boot.readUInt16LE(48),
      label: (sectorsPerFAT16 !== 0 ? boot.subarray(43, 54) : boot.subarray(71, 82))
        .toString("latin1").replace(/ +$/, ""),
    };
    if (bpb.sectorsPerCluster === 0 || bpb.numberOfFATs === 0 || bpb.sectorsPerFAT === 0 ||
      bpb.totalSectors === 0) {
      throw new FATError("the BPB is not consistent");
    }
    const fs = new FAT(img, base, bpb);
    if (fs.countOfClusters < 1) throw new FATError("the BPB describes no data clusters");
    if (!fs.fixedRoot && bpb.rootCluster < 2) {
      throw new FATError("the root cluster of a FAT32 file system is not valid");
    }
    return fs;
  }

  /**
   * Writes a new, empty file system over the image. The type follows from
   * the cluster count, as the specification requires, so the caller
   * chooses it by choosing the cluster size, or names it and lets this
   * pick a cluster size that reaches the right count.
   */
  static async format(img: Image, opts: {
    base?: number;
    bytes?: number;
    bytesPerSector?: number;
    sectorsPerCluster?: number;
    type?: FATType;
    label?: string;
  } = {}): Promise<FAT> {
    const base = opts.base ?? 0;
    const bytes = opts.bytes ?? (await img.size()) - base;
    const bytesPerSector = opts.bytesPerSector ?? 512;
    const totalSectors = Math.floor(bytes / bytesPerSector);
    const wanted = opts.type ?? "FAT32";
    if (wanted === "FAT12") {
      throw new FATError("seedmi reads FAT12 but does not create it");
    }
    const fat32 = wanted === "FAT32";
    const numberOfFATs = 2;
    const rootEntryCount = fat32 ? 0 : 512;
    const rootDirSectors = Math.ceil((rootEntryCount * ENTRY_SIZE) / bytesPerSector);
    const reservedSectors = fat32 ? 32 : 1;

    // Choose a cluster size that puts the cluster count in the range of
    // the type asked for: at least 65525 for FAT32, and between 4085 and
    // 65524 for FAT16.
    const clustersFor = (spc: number, fatSectors: number) => Math.floor(
      (totalSectors - reservedSectors - numberOfFATs * fatSectors - rootDirSectors) / spc);
    const fatSectorsFor = (spc: number) => {
      const entryBytes = fat32 ? 4 : 2;
      const perSector = bytesPerSector / entryBytes;
      const data = totalSectors - reservedSectors - rootDirSectors;
      return Math.max(Math.ceil(data / (spc * perSector + numberOfFATs)), 1);
    };
    let sectorsPerCluster = opts.sectorsPerCluster ?? 0;
    if (sectorsPerCluster === 0) {
      for (const spc of [1, 2, 4, 8, 16, 32, 64, 128]) {
        const n = clustersFor(spc, fatSectorsFor(spc));
        if (fat32 ? n >= 65525 : n >= 4085 && n < 65525) {
          sectorsPerCluster = spc;
          break;
        }
      }
      if (sectorsPerCluster === 0) {
        throw new FATError(
          `no cluster size gives a ${wanted} file system in ${bytes} bytes`);
      }
    }
    const sectorsPerFAT = fatSectorsFor(sectorsPerCluster);
    const clusters = clustersFor(sectorsPerCluster, sectorsPerFAT);
    if (fat32 && clusters < 65525) {
      throw new FATError(
        `a FAT32 file system needs at least 65525 clusters; this image holds ${clusters}`);
    }
    if (!fat32 && (clusters < 4085 || clusters >= 65525)) {
      throw new FATError(
        `a FAT16 file system holds between 4085 and 65524 clusters; this image holds ${clusters}`);
    }

    const boot = Buffer.alloc(bytesPerSector);
    boot[0] = 0xeb;
    boot[1] = fat32 ? 0x58 : 0x3c;
    boot[2] = 0x90;
    boot.write("seedmi  ", 3, "latin1");
    boot.writeUInt16LE(bytesPerSector, 11);
    boot.writeUInt8(sectorsPerCluster, 13);
    boot.writeUInt16LE(reservedSectors, 14);
    boot.writeUInt8(numberOfFATs, 16);
    boot.writeUInt16LE(rootEntryCount, 17);
    boot.writeUInt16LE(totalSectors < 0x10000 && !fat32 ? totalSectors : 0, 19);
    boot.writeUInt8(0xf8, 21); // media: fixed disk
    boot.writeUInt16LE(fat32 ? 0 : sectorsPerFAT, 22);
    boot.writeUInt16LE(63, 24);
    boot.writeUInt16LE(255, 26);
    boot.writeUInt32LE(0, 28);
    boot.writeUInt32LE(totalSectors < 0x10000 && !fat32 ? 0 : totalSectors, 32);
    const label = (opts.label ?? "NO NAME").toUpperCase().padEnd(11, " ").slice(0, 11);
    if (fat32) {
      boot.writeUInt32LE(sectorsPerFAT, 36);
      boot.writeUInt16LE(0, 40); // every table is mirrored
      boot.writeUInt16LE(0, 42); // version
      boot.writeUInt32LE(2, 44); // the root begins at cluster 2
      boot.writeUInt16LE(1, 48); // FSInfo
      boot.writeUInt16LE(6, 50); // the backup boot sector
      boot.writeUInt8(0x80, 64);
      boot.writeUInt8(0x29, 66);
      boot.writeUInt32LE(Math.floor(Date.now() / 1000) >>> 0, 67);
      boot.write(label, 71, "latin1");
      boot.write("FAT32   ", 82, "latin1");
    } else {
      // Before FAT32 the extended fields sit at offset 36.
      boot.writeUInt8(0x80, 36);
      boot.writeUInt8(0x29, 38);
      boot.writeUInt32LE(Math.floor(Date.now() / 1000) >>> 0, 39);
      boot.write(label, 43, "latin1");
      boot.write("FAT16   ", 54, "latin1");
    }
    boot.writeUInt16LE(0xaa55, 510);
    await img.write(base, boot);
    if (fat32) await img.write(base + 6 * bytesPerSector, boot);

    if (fat32) {
      const fsInfo = Buffer.alloc(bytesPerSector);
      fsInfo.writeUInt32LE(0x41615252, 0);
      fsInfo.writeUInt32LE(0x61417272, 484);
      fsInfo.writeUInt32LE(clusters - 1, 488); // the root takes one
      fsInfo.writeUInt32LE(3, 492);
      fsInfo.writeUInt32LE(0xaa550000, 508);
      await img.write(base + bytesPerSector, fsInfo);
    }

    // The tables: the two reserved entries, then the root chain on FAT32.
    const fatStart = base + reservedSectors * bytesPerSector;
    const head = Buffer.alloc(bytesPerSector);
    if (fat32) {
      head.writeUInt32LE(0x0ffffff8, 0);
      head.writeUInt32LE(0x0fffffff, 4);
      head.writeUInt32LE(0x0fffffff, 8); // cluster 2: the root
    } else {
      head.writeUInt16LE(0xfff8, 0);
      head.writeUInt16LE(0xffff, 2);
    }
    const blank = Buffer.alloc(bytesPerSector);
    for (let f = 0; f < numberOfFATs; f++) {
      const at = fatStart + f * sectorsPerFAT * bytesPerSector;
      await img.write(at, head);
      for (let sec = 1; sec < sectorsPerFAT; sec++) {
        await img.write(at + sec * bytesPerSector, blank);
      }
    }
    // The fixed root region begins empty.
    if (!fat32) {
      const rootAt = fatStart + numberOfFATs * sectorsPerFAT * bytesPerSector;
      for (let sec = 0; sec < rootDirSectors; sec++) {
        await img.write(rootAt + sec * bytesPerSector, blank);
      }
    }

    const fs = new FAT(img, base, {
      bytesPerSector, sectorsPerCluster, reservedSectors, numberOfFATs, totalSectors,
      sectorsPerFAT, rootCluster: fat32 ? 2 : FIXED_ROOT, rootEntryCount,
      fsInfoSector: fat32 ? 1 : 0, label: opts.label ?? "NO NAME",
    });
    if (fs.type !== wanted) {
      throw new FATError(`the geometry gives ${fs.type}, not ${wanted}`);
    }
    if (fat32) await fs.zeroCluster(2);
    return fs;
  }

  // -----------------------------------------------------------------
  // Clusters and the allocation table

  private clusterOffset(cluster: number): number {
    return this.base + (this.firstDataSector +
      (cluster - 2) * this.bpb.sectorsPerCluster) * this.bpb.bytesPerSector;
  }

  /** The first byte of the table, for the copy numbered f. */
  private fatStart(f = 0): number {
    return this.base + this.bpb.reservedSectors * this.bpb.bytesPerSector +
      f * this.bpb.sectorsPerFAT * this.bpb.bytesPerSector;
  }

  /** The byte at which the entry for a cluster begins, and its width. */
  private fatEntryAt(cluster: number, f = 0): { at: number; width: number } {
    switch (this.type) {
      // A FAT12 entry is twelve bits, so two entries share three bytes.
      case "FAT12": return { at: this.fatStart(f) + cluster + (cluster >> 1), width: 2 };
      case "FAT16": return { at: this.fatStart(f) + cluster * 2, width: 2 };
      default: return { at: this.fatStart(f) + cluster * 4, width: 4 };
    }
  }

  async getFAT(cluster: number): Promise<number> {
    const { at, width } = this.fatEntryAt(cluster);
    const b = await this.img.read(at, width);
    switch (this.type) {
      case "FAT12": {
        const pair = b.readUInt16LE(0);
        return (cluster & 1) === 0 ? pair & 0x0fff : pair >> 4;
      }
      case "FAT16": return b.readUInt16LE(0);
      default: return b.readUInt32LE(0) & 0x0fffffff;
    }
  }

  async setFAT(cluster: number, value: number): Promise<void> {
    for (let f = 0; f < this.bpb.numberOfFATs; f++) {
      const { at, width } = this.fatEntryAt(cluster, f);
      const cur = await this.img.read(at, width);
      const next = Buffer.alloc(width);
      switch (this.type) {
        case "FAT12": {
          // The neighbouring entry shares a byte and is preserved.
          const pair = cur.readUInt16LE(0);
          next.writeUInt16LE((cluster & 1) === 0
            ? (pair & 0xf000) | (value & 0x0fff)
            : (pair & 0x000f) | ((value & 0x0fff) << 4), 0);
          break;
        }
        case "FAT16":
          next.writeUInt16LE(value & 0xffff, 0);
          break;
        default:
          // The high four bits of a FAT32 entry are reserved.
          next.writeUInt32LE((cur.readUInt32LE(0) & 0xf0000000) | (value & 0x0fffffff), 0);
      }
      await this.img.write(at, next);
    }
  }

  async zeroCluster(cluster: number): Promise<void> {
    await this.img.write(this.clusterOffset(cluster), Buffer.alloc(this.clusterSize));
  }

  /** The clusters of a chain, in order. */
  async chain(first: number): Promise<number[]> {
    const out: number[] = [];
    let c = first;
    while (c >= 2 && c < EOC_OF[this.type] && out.length <= this.countOfClusters) {
      out.push(c);
      c = await this.getFAT(c);
      if (c === BAD_OF[this.type]) throw new FATError("the chain reaches a bad cluster");
    }
    return out;
  }

  /** Allocates one cluster, chaining it after previous where given. */
  async allocate(previous?: number): Promise<number> {
    for (let c = 2; c < this.countOfClusters + 2; c++) {
      if (await this.getFAT(c) !== FREE) continue;
      await this.setFAT(c, END_OF[this.type]);
      if (previous !== undefined) await this.setFAT(previous, c);
      await this.zeroCluster(c);
      await this.adjustFreeCount(-1);
      return c;
    }
    throw new FATError("the file system is full");
  }

  private async freeChain(first: number): Promise<void> {
    if (first < 2) return;
    const clusters = await this.chain(first);
    for (const c of clusters) await this.setFAT(c, FREE);
    await this.adjustFreeCount(clusters.length);
  }

  private async adjustFreeCount(by: number): Promise<void> {
    if (this.fixedRoot) return; // there is no FSInfo sector before FAT32
    const at = this.base + this.bpb.fsInfoSector * this.bpb.bytesPerSector;
    const info = await this.img.read(at, 512);
    if (info.readUInt32LE(0) !== 0x41615252) return;
    const free = info.readUInt32LE(488);
    if (free === 0xffffffff) return;
    const next = Buffer.alloc(4);
    next.writeUInt32LE(Math.max(free + by, 0) >>> 0, 0);
    await this.img.write(at + 488, next);
  }

  /** The free space in bytes, from the FSInfo sector. */
  async freeBytes(): Promise<number> {
    if (!this.fixedRoot) {
      const at = this.base + this.bpb.fsInfoSector * this.bpb.bytesPerSector;
      const info = await this.img.read(at, 512);
      if (info.readUInt32LE(0) === 0x41615252) {
        const free = info.readUInt32LE(488);
        if (free !== 0xffffffff) return free * this.clusterSize;
      }
    }
    // Before FAT32 there is no free count, so the table is counted.
    let free = 0;
    for (let c = 2; c < this.countOfClusters + 2; c++) {
      if (await this.getFAT(c) === FREE) free++;
    }
    return free * this.clusterSize;
  }

  // -----------------------------------------------------------------
  // Directories

  /** The byte range of the fixed root region, before FAT32. */
  private fixedRootRange(): { at: number; bytes: number } {
    const at = this.base +
      (this.bpb.reservedSectors + this.bpb.numberOfFATs * this.bpb.sectorsPerFAT) *
      this.bpb.bytesPerSector;
    return { at, bytes: this.bpb.rootEntryCount * ENTRY_SIZE };
  }

  private isFixedRoot(cluster: number): boolean {
    return this.fixedRoot && cluster === FIXED_ROOT;
  }

  private async readDirectory(cluster: number): Promise<Buffer> {
    if (this.isFixedRoot(cluster)) {
      const { at, bytes } = this.fixedRootRange();
      return this.img.read(at, bytes);
    }
    const clusters = await this.chain(cluster);
    const parts: Buffer[] = [];
    for (const c of clusters) {
      parts.push(await this.img.read(this.clusterOffset(c), this.clusterSize));
    }
    return Buffer.concat(parts);
  }

  private async writeDirectorySlot(cluster: number, slot: number,
    data: Buffer): Promise<void> {
    if (this.isFixedRoot(cluster)) {
      const { at, bytes } = this.fixedRootRange();
      if (slot * ENTRY_SIZE >= bytes) {
        throw new FATError("the root directory is full");
      }
      return this.img.write(at + slot * ENTRY_SIZE, data);
    }
    const perCluster = this.clusterSize / ENTRY_SIZE;
    const clusters = await this.chain(cluster);
    const which = Math.floor(slot / perCluster);
    if (which >= clusters.length) throw new FATError("a directory slot is out of range");
    const within = (slot % perCluster) * ENTRY_SIZE;
    await this.img.write(this.clusterOffset(clusters[which]) + within, data);
  }

  /** The entries of the directory beginning at cluster. */
  async list(cluster: number): Promise<DirEntry[]> {
    const raw = await this.readDirectory(cluster);
    const out: DirEntry[] = [];
    let longParts: (string | undefined)[] = [];
    let longChecksum = -1;
    let firstSlot = -1;

    for (let slot = 0; slot * ENTRY_SIZE < raw.length; slot++) {
      const e = raw.subarray(slot * ENTRY_SIZE, (slot + 1) * ENTRY_SIZE);
      if (e[0] === 0x00) break; // no entry follows
      if (e[0] === DELETED) {
        longParts = [];
        firstSlot = -1;
        continue;
      }
      const attr = e[11];
      if ((attr & ATTR_LONG_NAME) === ATTR_LONG_NAME) {
        const ord = e[0] & 0x3f;
        if ((e[0] & 0x40) !== 0) {
          longParts = [];
          longChecksum = e[13];
          firstSlot = slot;
        }
        if (longChecksum !== e[13]) {
          longParts = [];
          firstSlot = -1;
          continue;
        }
        longParts[ord - 1] = decodeLongPart(e);
        continue;
      }
      if ((attr & ATTR_VOLUME_ID) !== 0) {
        longParts = [];
        firstSlot = -1;
        continue;
      }
      const shortName = decodeShortName(e.subarray(0, 11));
      let name = shortName;
      const assembled = longParts.every((p) => p !== undefined) && longParts.length > 0
        ? longParts.join("")
        : undefined;
      if (assembled !== undefined &&
        longChecksum === shortNameChecksum(e.subarray(0, 11))) {
        name = assembled.replace(/\u0000.*$/s, "");
      }
      const start = firstSlot >= 0 && assembled !== undefined ? firstSlot : slot;
      out.push({
        name,
        shortName,
        attr,
        cluster: (e.readUInt16LE(20) << 16) | e.readUInt16LE(26),
        size: e.readUInt32LE(28),
        ctime: fromFAT(e.readUInt16LE(16), e.readUInt16LE(14)),
        atime: fromFAT(e.readUInt16LE(18), 0),
        mtime: fromFAT(e.readUInt16LE(24), e.readUInt16LE(22)),
        slot: start,
        slots: slot - start + 1,
      });
      longParts = [];
      firstSlot = -1;
    }
    return out;
  }

  /** The entry of a name within a directory, compared without case. */
  async find(cluster: number, name: string): Promise<DirEntry | undefined> {
    const lower = name.toLowerCase();
    for (const e of await this.list(cluster)) {
      if (e.name.toLowerCase() === lower || e.shortName.toLowerCase() === lower) return e;
    }
    return undefined;
  }

  /** Resolves a path from the root, returning its entry. */
  async resolve(path: string): Promise<DirEntry | undefined> {
    let cluster = this.rootDirectory;
    let entry: DirEntry | undefined;
    for (const seg of path.split("/")) {
      if (seg === "") continue;
      entry = await this.find(cluster, seg);
      if (!entry) return undefined;
      cluster = entry.cluster;
    }
    return entry;
  }

  /** The cluster of the directory at a path. */
  async directoryAt(path: string): Promise<number> {
    if (path === "" || path === "/") return this.rootDirectory;
    const e = await this.resolve(path);
    if (!e || !isDirectory(e)) throw new FATError(`${path} is not a directory`);
    return e.cluster;
  }

  // -----------------------------------------------------------------
  // Reading and writing values

  async readFile(entry: DirEntry, offset = 0, length?: number): Promise<Buffer> {
    const want = Math.max(Math.min(length ?? entry.size - offset, entry.size - offset), 0);
    if (want === 0 || entry.cluster < 2) return Buffer.alloc(0);
    const clusters = await this.chain(entry.cluster);
    const out = Buffer.alloc(want);
    let done = 0;
    let pos = 0;
    for (const c of clusters) {
      const end = pos + this.clusterSize;
      if (end > offset) {
        const from = Math.max(offset - pos, 0);
        const to = Math.min(this.clusterSize, offset + want - pos);
        if (to > from) {
          const part = await this.img.read(this.clusterOffset(c) + from, to - from);
          part.copy(out, done);
          done += to - from;
        }
      }
      pos = end;
      if (done >= want) break;
    }
    return out;
  }

  /** Writes at an offset within a file, extending it where needed. */
  async writeFile(dirCluster: number, entry: DirEntry, offset: number,
    data: Buffer): Promise<DirEntry> {
    if (data.length === 0) return entry;
    const needed = Math.ceil((offset + data.length) / this.clusterSize);
    let first = entry.cluster;
    let clusters = first >= 2 ? await this.chain(first) : [];
    while (clusters.length < needed) {
      const c = await this.allocate(clusters.length > 0
        ? clusters[clusters.length - 1]
        : undefined);
      if (clusters.length === 0) first = c;
      clusters.push(c);
    }
    let written = 0;
    for (let i = 0; i < clusters.length && written < data.length; i++) {
      const clusterStart = i * this.clusterSize;
      const clusterEnd = clusterStart + this.clusterSize;
      const from = Math.max(offset - clusterStart, 0);
      if (offset + data.length <= clusterStart || clusterEnd <= offset) continue;
      const to = Math.min(this.clusterSize, offset + data.length - clusterStart);
      const chunk = data.subarray(written, written + (to - from));
      await this.img.write(this.clusterOffset(clusters[i]) + from, chunk);
      written += chunk.length;
    }
    const size = Math.max(entry.size, offset + data.length);
    const updated: DirEntry = { ...entry, cluster: first, size, mtime: new Date() };
    await this.updateEntry(dirCluster, updated);
    return updated;
  }

  /** Replaces the whole value of a file. */
  async setFile(dirCluster: number, entry: DirEntry, data: Buffer): Promise<DirEntry> {
    if (entry.cluster >= 2) await this.freeChain(entry.cluster);
    const emptied: DirEntry = { ...entry, cluster: 0, size: 0 };
    if (data.length === 0) {
      const updated = { ...emptied, mtime: new Date() };
      await this.updateEntry(dirCluster, updated);
      return updated;
    }
    return this.writeFile(dirCluster, emptied, 0, data);
  }

  async truncateFile(dirCluster: number, entry: DirEntry, size: number): Promise<DirEntry> {
    if (size >= entry.size) {
      if (size === entry.size) return entry;
      const pad = Buffer.alloc(size - entry.size);
      return this.writeFile(dirCluster, entry, entry.size, pad);
    }
    const keep = Math.ceil(size / this.clusterSize);
    const clusters = entry.cluster >= 2 ? await this.chain(entry.cluster) : [];
    if (clusters.length > keep) {
      if (keep === 0) {
        await this.freeChain(entry.cluster);
      } else {
        const tail = clusters[keep];
        await this.setFAT(clusters[keep - 1], END_OF[this.type]);
        await this.freeChain(tail);
      }
    }
    const updated: DirEntry = {
      ...entry,
      size,
      cluster: keep === 0 ? 0 : entry.cluster,
      mtime: new Date(),
    };
    await this.updateEntry(dirCluster, updated);
    return updated;
  }

  // -----------------------------------------------------------------
  // Creating and removing

  /** Creates an empty file, returning its entry. */
  async createFile(dirCluster: number, name: string, attr = ATTR_ARCHIVE): Promise<DirEntry> {
    return this.createEntry(dirCluster, name, attr, 0);
  }

  /** Creates a subdirectory, with its dot entries. */
  async createDirectory(dirCluster: number, name: string): Promise<DirEntry> {
    const cluster = await this.allocate();
    const entry = await this.createEntry(dirCluster, name, ATTR_DIRECTORY, cluster);
    // "." refers to the directory itself and ".." to its parent, which is
    // recorded as cluster zero where the parent is the root.
    // The dot entries hold their names in the 11-byte field directly;
    // they are not 8.3 names and are not encoded as such.
    const dot = this.rawEntry(Buffer.from(".".padEnd(11, " "), "latin1"),
      ATTR_DIRECTORY, cluster, 0);
    const dotdot = this.rawEntry(Buffer.from("..".padEnd(11, " "), "latin1"),
      ATTR_DIRECTORY, dirCluster === this.rootDirectory ? 0 : dirCluster, 0);
    await this.img.write(this.clusterOffset(cluster), Buffer.concat([dot, dotdot]));
    return entry;
  }

  private rawEntry(short: Buffer, attr: number, cluster: number, size: number): Buffer {
    const now = new Date();
    const e = Buffer.alloc(ENTRY_SIZE);
    short.copy(e, 0);
    e.writeUInt8(attr, 11);
    e.writeUInt16LE(fatTime(now), 14);
    e.writeUInt16LE(fatDate(now), 16);
    e.writeUInt16LE(fatDate(now), 18);
    e.writeUInt16LE((cluster >>> 16) & 0xffff, 20);
    e.writeUInt16LE(fatTime(now), 22);
    e.writeUInt16LE(fatDate(now), 24);
    e.writeUInt16LE(cluster & 0xffff, 26);
    e.writeUInt32LE(size, 28);
    return e;
  }

  private async createEntry(dirCluster: number, name: string, attr: number,
    cluster: number): Promise<DirEntry> {
    if (!storableName(name)) {
      throw new FATError(`${JSON.stringify(name)} cannot be stored in a FAT file system`);
    }
    const existing = await this.list(dirCluster);
    if (existing.some((e) => e.name.toLowerCase() === name.toLowerCase())) {
      throw new FATError(`${JSON.stringify(name)} already exists`);
    }
    const taken = new Set(existing.map((e) => e.shortName));
    const shortName = generateShortName(name, taken);
    const short = encodeShortName(shortName);
    const needsLong = shortName !== name;
    const longEntries = needsLong ? encodeLongName(name, shortNameChecksum(short)) : [];
    const slots = longEntries.length + 1;

    const at = await this.findFreeSlots(dirCluster, slots);
    const buf = Buffer.concat([...longEntries, this.rawEntry(short, attr, cluster, 0)]);
    for (let i = 0; i < slots; i++) {
      await this.writeDirectorySlot(dirCluster, at + i,
        buf.subarray(i * ENTRY_SIZE, (i + 1) * ENTRY_SIZE));
    }
    const entry = await this.find(dirCluster, name);
    if (!entry) throw new FATError("the entry just created cannot be found");
    return entry;
  }

  /** Finds, and makes if necessary, a run of free slots in a directory. */
  private async findFreeSlots(dirCluster: number, count: number): Promise<number> {
    const raw = await this.readDirectory(dirCluster);
    const total = raw.length / ENTRY_SIZE;
    let run = 0;
    for (let slot = 0; slot < total; slot++) {
      const first = raw[slot * ENTRY_SIZE];
      if (first === 0x00 || first === DELETED) {
        run++;
        if (run === count) return slot - count + 1;
      } else {
        run = 0;
      }
    }
    // The free slots at the end of the directory are contiguous with the
    // slots of the cluster about to be added, so the entry begins at the
    // start of that trailing run. Beginning it after the run instead would
    // leave a slot holding zero before it, and a directory scan stops at
    // the first such slot, so the entry would never be found again.
    const trailing = run;
    if (this.isFixedRoot(dirCluster)) {
      // The root of a FAT12 or FAT16 file system is a fixed region and
      // cannot be extended.
      throw new FATError("the root directory is full");
    }
    // Extend the directory by one cluster.
    const clusters = await this.chain(dirCluster);
    await this.allocate(clusters[clusters.length - 1]);
    return total - trailing;
  }

  /** Removes an entry, freeing its clusters. A directory must be empty. */
  async remove(dirCluster: number, entry: DirEntry): Promise<void> {
    if (isDirectory(entry)) {
      const inside = (await this.list(entry.cluster))
        .filter((e) => e.name !== "." && e.name !== "..");
      if (inside.length > 0) throw new FATError("the directory is not empty");
    }
    if (entry.cluster >= 2) await this.freeChain(entry.cluster);
    const mark = Buffer.alloc(ENTRY_SIZE);
    for (let i = 0; i < entry.slots; i++) {
      const slot = entry.slot + i;
      const cur = await this.slotBytes(dirCluster, slot);
      cur.copy(mark);
      mark[0] = DELETED;
      await this.writeDirectorySlot(dirCluster, slot, mark);
    }
  }

  private async slotBytes(dirCluster: number, slot: number): Promise<Buffer> {
    const raw = await this.readDirectory(dirCluster);
    return Buffer.from(raw.subarray(slot * ENTRY_SIZE, (slot + 1) * ENTRY_SIZE));
  }

  /** Writes the cluster, size and times of an entry back to its directory. */
  private async updateEntry(dirCluster: number, entry: DirEntry): Promise<void> {
    const slot = entry.slot + entry.slots - 1;
    const e = await this.slotBytes(dirCluster, slot);
    e.writeUInt16LE((entry.cluster >>> 16) & 0xffff, 20);
    e.writeUInt16LE(entry.cluster & 0xffff, 26);
    e.writeUInt32LE(entry.size, 28);
    e.writeUInt16LE(fatTime(entry.mtime), 22);
    e.writeUInt16LE(fatDate(entry.mtime), 24);
    e.writeUInt8(entry.attr, 11);
    await this.writeDirectorySlot(dirCluster, slot, e);
  }

  /** Sets the attribute byte of an entry. */
  async setAttr(dirCluster: number, entry: DirEntry, attr: number): Promise<void> {
    await this.updateEntry(dirCluster, { ...entry, attr });
  }
}

// ---------------------------------------------------------------------------
// Long names

const LONG_OFFSETS = [[1, 5], [14, 6], [28, 2]] as const;

function decodeLongPart(e: Buffer): string {
  let out = "";
  for (const [at, count] of LONG_OFFSETS) {
    for (let i = 0; i < count; i++) {
      const code = e.readUInt16LE(at + i * 2);
      if (code === 0x0000 || code === 0xffff) return out;
      out += String.fromCharCode(code);
    }
  }
  return out;
}

/** The long name entries for a name, in the order they are stored. */
export function encodeLongName(name: string, checksum: number): Buffer[] {
  const codes: number[] = [];
  for (const ch of name) {
    const s = ch;
    for (let i = 0; i < s.length; i++) codes.push(s.charCodeAt(i));
  }
  const parts = Math.ceil(codes.length / 13);
  const out: Buffer[] = [];
  for (let p = parts - 1; p >= 0; p--) {
    const e = Buffer.alloc(ENTRY_SIZE, 0xff);
    e[0] = (p + 1) | (p === parts - 1 ? 0x40 : 0);
    e[11] = ATTR_LONG_NAME;
    e[12] = 0;
    e[13] = checksum;
    e.writeUInt16LE(0, 26);
    let k = p * 13;
    for (const [at, count] of LONG_OFFSETS) {
      for (let i = 0; i < count; i++) {
        const code = k < codes.length ? codes[k] : (k === codes.length ? 0 : 0xffff);
        e.writeUInt16LE(code, at + i * 2);
        k++;
      }
    }
    out.push(e);
  }
  return out;
}
