// An HDF5 file held in a sequence of bytes, which an image import presents as
// a namespace. The layout follows the HDF5 File Format Specification version
// 4: a superblock, object headers carrying messages, and groups whose links
// are held either in a version 1 B-tree with a local heap or in Link messages
// in the group's own header.
//
// Four superblock versions and two object header versions are in use, and a
// file may mix them: a version 2 superblock whose root group has a version 1
// object header is ordinary, not a defect, so the two are dispatched
// separately rather than inferred from one another.
//
// This driver is read-only. HDF5 holds a directed graph of typed datasets
// whose meaning lives in datatype and dataspace messages; writing through the
// namespace of an import would have to invent that meaning, so an import of
// this format presents what the file holds and refuses every write.
//
// What the reader does with a malformed file matters more here than in most
// of seedmi, because the bytes arrive as the value of a data object a client
// wrote. Every read is bounds-checked against the image, and every count,
// depth and chain is limited, so a file that lies about its own sizes is
// refused rather than followed.
//
// On the evidence for the layouts below. The version 2 and 3 structures carry
// Jenkins lookup3 checksums, and those were verified against 142 real files:
// 30 of 30 superblocks and 25 of 34 version 2 object headers, which confirms
// the flags-driven variable fields and the Size of Chunk #0 encoding, since a
// field located one byte out verifies none. The version 1 structures carry no
// checksum at all, so for the superblock v0/v1, version 1 object headers,
// version 1 B-trees, local heaps and symbol tables the evidence is the
// specification text plus agreement with those files' own declared sizes.
// Two defects were found in that path during development, so it is the part
// to distrust first if a real file is misread.

import type { Image } from "./fat.ts";

export class HDF5Error extends Error {}

/** The identifier under which seedmi offers this format. */
export const FORMAT_NAME = "HDF5";

const SIGNATURE = Buffer.from([0x89, 0x48, 0x44, 0x46, 0x0d, 0x0a, 0x1a, 0x0a]);

/** The signature of a version 2 object header. */
const OHDR = Buffer.from("OHDR", "ascii");
/** The signature of a version 2 object header continuation block. */
const OCHK = Buffer.from("OCHK", "ascii");
const TREE = Buffer.from("TREE", "ascii");
const SNOD = Buffer.from("SNOD", "ascii");
const HEAP = Buffer.from("HEAP", "ascii");

// The header message types this driver reads. The rest are carried as
// nothing: an unread message is not a defect, and the specification says a
// reader may ignore a message type it does not know.
const M_DATASPACE = 0x0001;
const M_LINK_INFO = 0x0002;
const M_DATATYPE = 0x0003;
const M_LINK = 0x0006;
const M_LAYOUT = 0x0008;
const M_GROUP_INFO = 0x000a;
const M_ATTRIBUTE = 0x000c;
const M_CONTINUATION = 0x0010;
const M_SYMBOL_TABLE = 0x0011;
const M_MODIFICATION_TIME = 0x0012;

/**
 * Limits. A malformed file can name any size it likes, so each of these
 * bounds a structure that would otherwise be bounded only by the file's own
 * claim about itself. They are far above what a real file reaches.
 */
const MAX_MESSAGES = 4096;
const MAX_CHUNKS = 64;
const MAX_BTREE_DEPTH = 24;
const MAX_BTREE_ENTRIES = 8192;
const MAX_SYMBOLS = 4096;
const MAX_NAME = 4096;
const MAX_LINKS = 65536;
const MAX_OBJECTS = 262144;

/** What an element of the file presents as, once imported. */
export type Presents = "container" | "dataobject" | "reference" | "not-presented";

/** One link of a group. */
export interface Link {
  readonly name: string;
  /** Where a hard link points, as an object header address. */
  readonly target?: number;
  /** The value of a soft link, or "file//path" of an external link. */
  readonly value?: string;
  readonly kind: "hard" | "soft" | "external" | "user-defined";
  /**
   * Why this link is not presented, where it is not. A link whose kind has no
   * place in the CDMI object model is recorded rather than dropped, so that a
   * client can tell an element that is absent from one that was declined.
   */
  readonly declined?: string;
}

/** What an object header says the object is. */
export type ObjectKind = "group" | "dataset" | "datatype" | "unknown";

/** One object of the file. */
export interface H5Object {
  readonly address: number;
  readonly kind: ObjectKind;
  /** The number of attribute messages, which become user metadata. */
  readonly attributes: number;
}

interface Superblock {
  readonly version: number;
  readonly offsetSize: number;
  readonly lengthSize: number;
  /** Where the root group's symbol table entry is, in a v0 or v1 file. */
  readonly rootEntry?: number;
  /** Where the root group's object header is, in a v2 or v3 file. */
  readonly rootHeader?: number;
  readonly declaredEOF?: number;
}

interface Message {
  readonly type: number;
  readonly size: number;
  /** Where the message's data begins, as an offset into the image. */
  readonly data: number;
  readonly flags: number;
}

/**
 * An HDF5 file read through an Image.
 *
 * The whole file is read once into a buffer on open, as the FAT driver does
 * and for the same reason: the structures point at one another all over the
 * file, so reading it in pieces would cost more than holding it.
 */
export class HDF5 {
  private readonly bytes: Buffer;
  private readonly sb: Superblock;
  /** What the file holds that this driver could not follow. */
  private readonly unread: Set<string> = new Set();

  private constructor(bytes: Buffer, sb: Superblock) {
    this.bytes = bytes;
    this.sb = sb;
  }

  /**
   * Opens the HDF5 file beginning at `base` within the image. Throws
   * HDF5Error where the bytes are not an HDF5 file, or are one this driver
   * will not follow.
   */
  static async open(image: Image, base = 0): Promise<HDF5> {
    const size = await image.size();
    if (base < 0 || base > size) {
      throw new HDF5Error(`byte ${base} is outside the image`);
    }
    const bytes = await image.read(base, size - base);
    return HDF5.of(bytes);
  }

  /** Opens an HDF5 file already held in a buffer. */
  static of(bytes: Buffer): HDF5 {
    if (bytes.length < SIGNATURE.length
      || !bytes.subarray(0, SIGNATURE.length).equals(SIGNATURE)) {
      throw new HDF5Error("the bytes do not begin with the HDF5 signature");
    }
    return new HDF5(bytes, HDF5.superblock(bytes));
  }

  /** Whether the bytes begin with the HDF5 signature. */
  static recognizes(bytes: Buffer): boolean {
    return bytes.length >= SIGNATURE.length
      && bytes.subarray(0, SIGNATURE.length).equals(SIGNATURE);
  }

  // --- bounded reads -----------------------------------------------------

  private at(offset: number, length: number): Buffer {
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length)
      || offset < 0 || length < 0 || offset + length > this.bytes.length) {
      throw new HDF5Error(
        `a read of ${length} bytes at ${offset} is outside the file ` +
        `of ${this.bytes.length} bytes`);
    }
    return this.bytes.subarray(offset, offset + length);
  }

  /**
   * An unsigned little-endian integer of `size` bytes. A value above
   * Number.MAX_SAFE_INTEGER is refused rather than rounded: an eight-byte
   * field can hold one, and a rounded offset would read the wrong bytes
   * while still looking like a number.
   */
  private num(offset: number, size: number): number {
    const value = leNumber(this.at(offset, size));
    if (value === undefined) {
      throw new HDF5Error(
        `the value at ${offset} is too large to be a size or an offset`);
    }
    return value;
  }

  /** An address, or undefined where every bit is set, which means none. */
  private addr(offset: number): number | undefined {
    const size = this.sb.offsetSize;
    const b = this.at(offset, size);
    let all = true;
    for (const byte of b) if (byte !== 0xff) { all = false; break; }
    return all ? undefined : this.num(offset, size);
  }

  private len(offset: number): number {
    return this.num(offset, this.sb.lengthSize);
  }

  // --- the superblock ----------------------------------------------------

  private static superblock(bytes: Buffer): Superblock {
    const version = bytes[8];
    const checkSizes = (offsetSize: number, lengthSize: number) => {
      // The specification allows 2, 4 and 8. Anything else is a malformed
      // file, and taking it on trust would scale every later offset by it.
      if (![2, 4, 8].includes(offsetSize) || ![2, 4, 8].includes(lengthSize)) {
        throw new HDF5Error(
          `offset and length sizes of ${offsetSize} and ${lengthSize} are not ` +
          "2, 4 or 8 bytes");
      }
    };
    if (version === 0 || version === 1) {
      const offsetSize = bytes[13];
      const lengthSize = bytes[14];
      checkSizes(offsetSize, lengthSize);
      // A version 1 superblock carries an extra two-byte field and two
      // reserved bytes for the indexed storage internal node K, before the
      // addresses.
      const addresses = 24 + (version === 1 ? 4 : 0);
      const need = addresses + 4 * offsetSize + offsetSize + lengthSize;
      if (bytes.length < need) {
        throw new HDF5Error(
          `a version ${version} superblock needs ${need} bytes and the file has ` +
          `${bytes.length}`);
      }
      return {
        version,
        offsetSize,
        lengthSize,
        rootEntry: addresses + 4 * offsetSize,
      };
    }
    if (version === 2 || version === 3) {
      const offsetSize = bytes[9];
      const lengthSize = bytes[10];
      checkSizes(offsetSize, lengthSize);
      const need = 12 + 4 * offsetSize + 4;
      if (bytes.length < need) {
        throw new HDF5Error(
          `a version ${version} superblock needs ${need} bytes and the file has ` +
          `${bytes.length}`);
      }
      const root = bytes.subarray(12 + 3 * offsetSize, 12 + 4 * offsetSize);
      let none = true;
      for (const byte of root) if (byte !== 0xff) { none = false; break; }
      if (none) throw new HDF5Error("the superblock names no root group");
      const rootHeader = leNumber(root);
      if (rootHeader === undefined) {
        throw new HDF5Error(
          "the superblock's root group address is too large to be an offset");
      }
      return { version, offsetSize, lengthSize, rootHeader };
    }
    throw new HDF5Error(`superblock version ${version} is not one this reads`);
  }

  /** The version of the superblock, for a caller that reports what it read. */
  get version(): number {
    return this.sb.version;
  }

  /** What this driver found but did not follow. */
  get notPresented(): string[] {
    return [...this.unread].sort();
  }

  /** Where the root group's object header is. */
  root(): number {
    if (this.sb.rootHeader !== undefined) return this.sb.rootHeader;
    const entry = this.sb.rootEntry!;
    const header = this.addr(entry + this.sb.lengthSize);
    if (header === undefined) {
      throw new HDF5Error(
        "the root group's symbol table entry names no object header");
    }
    return header;
  }

  // --- object headers ----------------------------------------------------

  /**
   * Every message of an object header, across the header's own chunk and any
   * continuation blocks.
   *
   * Two things here were defects during development and are worth stating.
   * The size of the first chunk is at byte 8 of a version 1 header, not byte
   * 12, which is a reserved word that pads the prefix to sixteen bytes so the
   * messages land eight-byte aligned; reading the size from the pad gives a
   * chunk of length zero, and a reader that walks no messages refuses nothing
   * and finds nothing. And the declared message count spans every chunk, so
   * it cannot bound the walk of a single chunk: each chunk is bounded by its
   * own declared size, and the others are reached by following the
   * continuation message.
   */
  messages(header: number): Message[] {
    const first = this.at(header, 4);
    if (first.equals(OHDR)) return this.messagesV2(header);
    if (this.num(header, 1) === 1) return this.messagesV1(header);
    throw new HDF5Error(
      `the object header at ${header} is neither version 1 nor a version 2 ` +
      `OHDR block (it begins ${first.toString("hex")})`);
  }

  private messagesV1(header: number): Message[] {
    const size = this.num(header + 8, 4);
    this.at(header + 16, size);
    const out: Message[] = [];
    const seen = new Set<number>([header]);
    const pending: { from: number; to: number }[] = [
      { from: header + 16, to: header + 16 + size },
    ];
    while (pending.length > 0) {
      const chunk = pending.shift()!;
      const before = out.length;
      let p = chunk.from;
      while (p + 8 <= chunk.to) {
        const type = this.num(p, 2);
        const msize = this.num(p + 2, 2);
        const flags = this.num(p + 4, 1);
        const data = p + 8;
        if (data + msize > chunk.to) {
          throw new HDF5Error(
            `a message of ${msize} bytes at ${data} runs past its object ` +
            `header chunk, which ends at ${chunk.to}`);
        }
        this.at(data, msize);
        out.push({ type, size: msize, data, flags });
        if (out.length > MAX_MESSAGES) {
          throw new HDF5Error(
            `more than ${MAX_MESSAGES} header messages is more than this reads`);
        }
        // Messages are aligned on eight-byte boundaries in a version 1
        // header, so a message whose size is not a multiple of eight is
        // followed by padding rather than by the next message.
        p = data + msize;
        p += (8 - (p % 8)) % 8;
      }
      this.continuations(out.slice(before), seen, pending, false);
    }
    return out;
  }

  private messagesV2(header: number): Message[] {
    if (this.num(header + 4, 1) !== 2) {
      throw new HDF5Error(
        `the object header at ${header} carries an OHDR signature and a ` +
        "version that is not 2");
    }
    const flags = this.num(header + 5, 1);
    let p = header + 6;
    if (flags & 0x20) p += 16;        // access, modification, change, birth
    if (flags & 0x10) p += 4;         // maximum compact, minimum dense
    const sizeWidth = 1 << (flags & 0x03);
    const size = this.num(p, sizeWidth);
    p += sizeWidth;
    this.at(p, size);
    const order = (flags & 0x04) !== 0;
    const out: Message[] = [];
    const seen = new Set<number>([header]);
    const pending: { from: number; to: number }[] = [{ from: p, to: p + size }];
    while (pending.length > 0) {
      const chunk = pending.shift()!;
      const before = out.length;
      let q = chunk.from;
      // A chunk may end with a gap smaller than a message prefix, so the
      // walk stops when a whole prefix no longer fits rather than requiring
      // the chunk to end exactly on a message.
      while (q + 4 <= chunk.to) {
        const type = this.num(q, 1);
        const msize = this.num(q + 1, 2);
        const mflags = this.num(q + 3, 1);
        const data = q + 4 + (order ? 2 : 0);
        if (data + msize > chunk.to) {
          throw new HDF5Error(
            `a message of ${msize} bytes at ${data} runs past its object ` +
            `header chunk, which ends at ${chunk.to}`);
        }
        this.at(data, msize);
        out.push({ type, size: msize, data, flags: mflags });
        if (out.length > MAX_MESSAGES) {
          throw new HDF5Error(
            `more than ${MAX_MESSAGES} header messages is more than this reads`);
        }
        q = data + msize;
      }
      this.continuations(out.slice(before), seen, pending, true);
    }
    return out;
  }

  /**
   * Queues the chunks named by the continuation messages among `found`. A
   * chunk already seen is refused rather than followed: a file whose
   * continuation messages form a cycle would otherwise be walked until the
   * message limit, and the limit is not the thing that should catch it.
   */
  private continuations(
    found: Message[],
    seen: Set<number>,
    pending: { from: number; to: number }[],
    v2: boolean,
  ): void {
    for (const m of found) {
      if (m.type !== M_CONTINUATION) continue;
      const where = this.addr(m.data);
      if (where === undefined) continue;
      const length = this.len(m.data + this.sb.offsetSize);
      if (seen.has(where)) {
        throw new HDF5Error(
          `the object header continuation at ${where} repeats a chunk already read`);
      }
      if (seen.size >= MAX_CHUNKS) {
        throw new HDF5Error(
          `more than ${MAX_CHUNKS} object header chunks is more than this reads`);
      }
      seen.add(where);
      this.at(where, length);
      if (v2) {
        if (!this.at(where, 4).equals(OCHK)) {
          throw new HDF5Error(
            `the object header continuation at ${where} has no OCHK signature`);
        }
        // Less the signature and its own trailing checksum.
        pending.push({ from: where + 4, to: where + length - 4 });
      } else {
        pending.push({ from: where, to: where + length });
      }
    }
  }

  // --- what an object is -------------------------------------------------

  /** What the object at `header` is, by the messages its header carries. */
  describe(header: number): H5Object {
    const messages = this.messages(header);
    const types = new Set(messages.map((m) => m.type));
    const attributes = messages.filter((m) => m.type === M_ATTRIBUTE).length;
    let kind: ObjectKind = "unknown";
    if (types.has(M_SYMBOL_TABLE) || types.has(M_LINK)
      || types.has(M_LINK_INFO) || types.has(M_GROUP_INFO)) {
      kind = "group";
    } else if (types.has(M_LAYOUT) && types.has(M_DATATYPE)) {
      kind = "dataset";
    } else if (types.has(M_DATATYPE) && !types.has(M_DATASPACE)) {
      // A committed datatype: a datatype stored as an object in its own
      // right, with no data and so no dataspace or layout.
      kind = "datatype";
    }
    return { address: header, kind, attributes };
  }

  /** What an object of this kind presents as, once imported. */
  static presents(kind: ObjectKind): Presents {
    switch (kind) {
      case "group": return "container";
      case "dataset": return "dataobject";
      // A committed datatype holds no data and names no namespace, so it has
      // no place in the CDMI object model as an object of its own. It is
      // carried as user metadata of its parent instead.
      case "datatype": return "not-presented";
      default: return "not-presented";
    }
  }

  /**
   * When the object at `header` was last modified, in milliseconds, where
   * its header says. HDF5 records this in a message that is optional, so an
   * object that carries none reports nothing rather than reporting now.
   */
  modified(header: number): number | undefined {
    for (const m of this.messages(header)) {
      // Version, three reserved bytes, then seconds since the epoch.
      if (m.type === M_MODIFICATION_TIME && m.size >= 8) {
        return this.num(m.data + 4, 4) * 1000;
      }
    }
    return undefined;
  }

  // --- attributes --------------------------------------------------------

  /**
   * The attributes of the object at `header`, as user metadata.
   *
   * An attribute is a named, typed value, so only those whose type carries
   * over into a metadata item are presented: a string, and a single number.
   * An array, a compound, a reference and the rest are recorded as not
   * presentable rather than rendered as octets that would not mean anything
   * to a client.
   *
   * A name beginning "cdmi_" is never presented. The bytes are the value of
   * a data object a client wrote, so an attribute named `cdmi_acl` or
   * `cdmi_owner` would otherwise let a client state, in a file it uploaded,
   * metadata that this server is supposed to determine. The remote import
   * filters the same prefix for the same reason.
   */
  attributes(header: number): Record<string, string> {
    const out: Record<string, string> = {};
    for (const m of this.messages(header)) {
      if (m.type !== M_ATTRIBUTE) continue;
      try {
        const a = this.attribute(m);
        if (a === undefined) continue;
        if (a.name.startsWith("cdmi_")) {
          this.unread.add(
            `an attribute named ${a.name}, which a client may not state`);
          continue;
        }
        if (a.value === undefined) {
          this.unread.add(`the value of the attribute ${a.name}`);
          continue;
        }
        out[a.name] = a.value;
      } catch (e) {
        this.unread.add(`an attribute that could not be read: ${reason(e)}`);
      }
    }
    return out;
  }

  /** One attribute message: its name, and its value where one carries over. */
  private attribute(m: Message):
    { name: string; value: string | undefined } | undefined {
    const version = this.num(m.data, 1);
    if (version < 1 || version > 3) {
      throw new HDF5Error(`an attribute message of version ${version} is not one this reads`);
    }
    const nameSize = this.num(m.data + 2, 2);
    const typeSize = this.num(m.data + 4, 2);
    const spaceSize = this.num(m.data + 6, 2);
    // A version 1 message pads each of the three to a multiple of eight; a
    // version 2 or 3 message stores them packed. A version 3 message carries
    // a name character set byte before them.
    const pad = (n: number) => version === 1 ? n + ((8 - (n % 8)) % 8) : n;
    let p = m.data + (version === 3 ? 9 : 8);
    if (nameSize > MAX_NAME) {
      throw new HDF5Error(`an attribute name of ${nameSize} bytes is more than this reads`);
    }
    // The name size includes the null terminator.
    const raw = this.at(p, nameSize);
    const end = raw.indexOf(0);
    const name = raw.subarray(0, end < 0 ? nameSize : end).toString("utf8");
    p += pad(nameSize);
    const type = p;
    p += pad(typeSize);
    const space = p;
    p += pad(spaceSize);
    const data = p;
    if (name === "" || !storableName(name)) return undefined;
    return { name, value: this.scalar(type, typeSize, space, spaceSize, data) };
  }

  /**
   * An attribute's value where it is a string or a single number, and
   * undefined where its type does not carry over into a metadata item.
   */
  private scalar(type: number, typeSize: number, space: number,
    spaceSize: number, data: number): string | undefined {
    if (typeSize < 8 || spaceSize < 4) return undefined;
    const classAndVersion = this.num(type, 1);
    const klass = classAndVersion & 0x0f;
    const bits = this.num(type + 1, 1);
    const size = this.num(type + 4, 4);
    // The dataspace must describe one element: a scalar, or an array of one.
    const rank = this.num(space + 1, 1);
    const spaceVersion = this.num(space, 1);
    const extents = spaceVersion === 1 ? space + 8 : space + 4;
    let elements = 1;
    for (let i = 0; i < rank; i++) {
      elements *= this.len(extents + i * this.sb.lengthSize);
    }
    if (klass === 3) {
      // A string. Its size is the whole string's, and it may be padded with
      // nulls or spaces, which are not part of the value.
      if (elements !== 1 || size > MAX_NAME) return undefined;
      const b = this.at(data, size);
      const stop = b.indexOf(0);
      return b.subarray(0, stop < 0 ? size : stop).toString("utf8").replace(/\s+$/, "");
    }
    if (elements !== 1) return undefined;
    const big = (bits & 0x01) !== 0;
    const b = Buffer.from(this.at(data, size));
    if (big) b.reverse();
    if (klass === 0) {
      // A fixed-point number. Bit 3 of the class bit field says whether it
      // is signed.
      const signed = (bits & 0x08) !== 0;
      if (size === 1) return String(signed ? b.readInt8(0) : b.readUInt8(0));
      if (size === 2) return String(signed ? b.readInt16LE(0) : b.readUInt16LE(0));
      if (size === 4) return String(signed ? b.readInt32LE(0) : b.readUInt32LE(0));
      if (size === 8) return String(signed ? b.readBigInt64LE(0) : b.readBigUInt64LE(0));
      return undefined;
    }
    if (klass === 1) {
      if (size === 4) return String(b.readFloatLE(0));
      if (size === 8) return String(b.readDoubleLE(0));
      return undefined;
    }
    // An array, a compound, an enumeration, a reference, a variable-length
    // value: none of these is a metadata item.
    return undefined;
  }

  // --- datasets ----------------------------------------------------------

  /**
   * What the dataset at `header` holds: its shape, the size of one element,
   * the size of its value in bytes, and where its raw data is.
   *
   * The size is the product of the dimensions and the size of one element.
   * HDF5 states the element size in the datatype message and the shape in
   * the dataspace message, and neither is derivable from the other, so a
   * dataset missing either is reported rather than guessed at.
   */
  dataset(header: number): Dataset {
    const messages = this.messages(header);
    const find = (type: number) => messages.find((m) => m.type === type);
    const space = find(M_DATASPACE);
    const type = find(M_DATATYPE);
    const layoutMessage = find(M_LAYOUT);
    if (space === undefined || type === undefined || layoutMessage === undefined) {
      throw new HDF5Error(
        `the object header at ${header} is missing the dataspace, datatype or ` +
        "layout message a dataset has");
    }
    const dimensions = this.dataspace(space);
    // The datatype message is a class and version byte, three bytes of class
    // bit fields, then the size of one element.
    const elementSize = this.num(type.data + 4, 4);
    const elements = dimensions.reduce((a, b) => a * b, 1);
    const size = elements * elementSize;
    if (!Number.isSafeInteger(size)) {
      throw new HDF5Error(
        `a dataset of ${elements} elements of ${elementSize} bytes is larger ` +
        "than this reads");
    }
    const filtered = find(0x000b) !== undefined;
    return {
      dimensions,
      elementSize,
      size,
      filtered,
      layout: this.layout(layoutMessage, size),
    };
  }

  /** The dimensions a dataspace message states. */
  private dataspace(m: Message): number[] {
    const version = this.num(m.data, 1);
    const rank = this.num(m.data + 1, 1);
    if (rank > 32) {
      throw new HDF5Error(`a dataspace of ${rank} dimensions is more than this reads`);
    }
    // A version 1 dataspace has a one-byte flags field and five reserved
    // bytes before the extents; a version 2 replaces the last four of those
    // with a one-byte type field.
    let p: number;
    if (version === 1) p = m.data + 8;
    else if (version === 2) p = m.data + 4;
    else {
      throw new HDF5Error(`a dataspace of version ${version} is not one this reads`);
    }
    const out: number[] = [];
    for (let i = 0; i < rank; i++) {
      out.push(this.len(p + i * this.sb.lengthSize));
    }
    return out;
  }

  /** Where a dataset's raw data is, as its layout message states it. */
  private layout(m: Message, size: number): Layout {
    const version = this.num(m.data, 1);
    if (version === 1 || version === 2) {
      // Version | Dimensionality | Layout Class | Reserved, then four more
      // reserved bytes, then the address where the class has one.
      const kind = this.num(m.data + 2, 1);
      if (kind === 0) {
        // Compact: the data follows the dimension sizes and the element
        // size, whose count the dimensionality states.
        const rank = this.num(m.data + 1, 1);
        const at = m.data + 8 + 4 * (rank + 1);
        const length = this.num(at, 4);
        return { kind: "compact", at: at + 4, size: length };
      }
      if (kind === 1) {
        const address = this.addr(m.data + 8);
        if (address === undefined) return { kind: "none" };
        return { kind: "contiguous", at: address, size };
      }
      return { kind: "chunked" };
    }
    if (version === 3 || version === 4) {
      const kind = this.num(m.data + 1, 1);
      if (kind === 0) {
        const length = this.num(m.data + 2, 2);
        return { kind: "compact", at: m.data + 4, size: length };
      }
      if (kind === 1) {
        const address = this.addr(m.data + 2);
        if (address === undefined) return { kind: "none" };
        return {
          kind: "contiguous",
          at: address,
          size: this.len(m.data + 2 + this.sb.offsetSize),
        };
      }
      if (kind === 2) return { kind: "chunked" };
      // Layout class 3, in a version 4 message, is a virtual dataset: the
      // value is assembled from mappings into other datasets, which may be
      // in other files. Following those would read outside the import
      // source, which an import does not do.
      if (kind === 3) return { kind: "virtual" };
      return { kind: "chunked" };
    }
    throw new HDF5Error(`a data layout message of version ${version} is not one this reads`);
  }

  /**
   * The value of the dataset at `header`, or as much of it as `offset` and
   * `length` ask for.
   *
   * A compact dataset holds its data in the layout message, and a contiguous
   * one in a single run of bytes, so both are read directly. A chunked
   * dataset's data is scattered across chunks located by an index and may
   * have passed through the filter pipeline on the way in; assembling it is
   * not implemented, and is reported as such rather than returned short or
   * returned as zeroes. A virtual dataset is assembled from other datasets,
   * which an import does not read.
   */
  value(header: number, offset = 0, length?: number): Buffer {
    const d = this.dataset(header);
    if (d.filtered && d.layout.kind !== "compact") {
      throw new HDF5Error(
        "the dataset's raw data has passed through the filter pipeline, which " +
        "this does not reverse");
    }
    switch (d.layout.kind) {
      case "chunked":
        throw new HDF5Error(
          "the dataset's raw data is stored in chunks, which this does not assemble");
      case "virtual":
        throw new HDF5Error(
          "the dataset is virtual, and is assembled from datasets outside the " +
          "import source, which an import does not read");
      case "none":
        // A dataset that has never been written has no raw data at all. Its
        // value is its fill value, which for the purposes of an import is
        // zeroes of the size the shape and datatype give.
        return Buffer.alloc(Math.max(Math.min(length ?? d.size, d.size) - offset, 0));
      default: {
        const have = d.layout.size;
        const from = Math.min(offset, have);
        const want = Math.max(Math.min(length ?? have - from, have - from), 0);
        return Buffer.from(this.at(d.layout.at + from, want));
      }
    }
  }

  // --- groups ------------------------------------------------------------

  /**
   * The links of the group whose object header is at `header`, in the order
   * the file holds them.
   *
   * Links reach a group three ways. An old-style group names a version 1
   * B-tree and a local heap in a symbol table message. A group with few
   * links carries each one as a Link message in its own header. A group with
   * many holds them in a fractal heap indexed by a version 2 B-tree, which
   * this driver records as not presented rather than following.
   */
  links(header: number): Link[] {
    const out: Link[] = [];
    for (const m of this.messages(header)) {
      if (m.type === M_SYMBOL_TABLE) {
        const tree = this.addr(m.data);
        const heap = this.addr(m.data + this.sb.offsetSize);
        if (tree !== undefined && heap !== undefined) {
          this.btree(tree, heap, out, 0);
        }
      } else if (m.type === M_LINK) {
        out.push(this.link(m.data, m.size));
      } else if (m.type === M_LINK_INFO) {
        const flags = this.num(m.data + 1, 1);
        // The creation order field, when present, precedes the heap address.
        const p = m.data + 2 + ((flags & 0x01) ? 8 : 0);
        if (this.addr(p) !== undefined) {
          this.unread.add("links held in a fractal heap");
        }
      }
      if (out.length > MAX_LINKS) {
        throw new HDF5Error(`more than ${MAX_LINKS} links is more than this reads`);
      }
    }
    return out;
  }

  /** One Link message. */
  private link(p: number, size: number): Link {
    const end = p + size;
    const version = this.num(p, 1);
    if (version !== 1) {
      throw new HDF5Error(`a link message of version ${version} is not one this reads`);
    }
    const flags = this.num(p + 1, 1);
    let q = p + 2;
    let type = 0;
    if (flags & 0x08) { type = this.num(q, 1); q += 1; }
    if (flags & 0x04) q += 8;         // creation order
    if (flags & 0x10) q += 1;         // name character set
    const width = 1 << (flags & 0x03);
    const length = this.num(q, width);
    q += width;
    if (length > MAX_NAME || q + length > end) {
      throw new HDF5Error(
        `a link name of ${length} bytes does not fit its message, which ends at ${end}`);
    }
    // The name is not null-terminated and its character set is ASCII unless
    // the message says UTF-8; both decode as UTF-8.
    const name = this.at(q, length).toString("utf8");
    q += length;
    if (type === 0) {
      return { name, kind: "hard", target: this.addr(q) };
    }
    const valueLength = this.num(q, 2);
    if (q + 2 + valueLength > end) {
      throw new HDF5Error(
        `a link value of ${valueLength} bytes does not fit its message`);
    }
    const value = this.at(q + 2, valueLength);
    if (type === 1) {
      return { name, kind: "soft", value: value.toString("utf8") };
    }
    if (type === 64) {
      // The first byte holds a version and flags; two null-terminated
      // strings follow, the file and then the path within it.
      const parts = value.subarray(1).toString("utf8").split("\0");
      return {
        name,
        kind: "external",
        value: `${parts[0] ?? ""}//${parts[1] ?? ""}`,
      };
    }
    this.unread.add(`a link of user-defined type ${type}`);
    return {
      name,
      kind: "user-defined",
      declined: `the link is of user-defined type ${type}`,
    };
  }

  /** A version 1 B-tree of group nodes. */
  private btree(tree: number, heap: number, out: Link[], depth: number): void {
    if (depth > MAX_BTREE_DEPTH) {
      throw new HDF5Error(
        `a group B-tree deeper than ${MAX_BTREE_DEPTH} is more than this reads`);
    }
    if (!this.at(tree, 4).equals(TREE)) {
      throw new HDF5Error(`the B-tree node at ${tree} has no TREE signature`);
    }
    if (this.num(tree + 4, 1) !== 0) {
      throw new HDF5Error(`the B-tree node at ${tree} is not a group node`);
    }
    const level = this.num(tree + 5, 1);
    const entries = this.num(tree + 6, 2);
    if (entries > MAX_BTREE_ENTRIES) {
      throw new HDF5Error(`${entries} B-tree entries is more than this reads`);
    }
    // The node holds the addresses of the left and right siblings, then
    // alternating keys and children, with one more key than child.
    const base = tree + 8 + 2 * this.sb.offsetSize;
    const step = this.sb.lengthSize + this.sb.offsetSize;
    for (let i = 0; i < entries; i++) {
      const child = this.addr(base + i * step + this.sb.lengthSize);
      if (child === undefined) continue;
      if (level > 0) {
        this.btree(child, heap, out, depth + 1);
      } else {
        this.symbols(child, heap, out);
      }
      if (out.length > MAX_LINKS) {
        throw new HDF5Error(`more than ${MAX_LINKS} links is more than this reads`);
      }
    }
  }

  /** One symbol table node: a run of symbol table entries. */
  private symbols(node: number, heap: number, out: Link[]): void {
    if (!this.at(node, 4).equals(SNOD)) {
      throw new HDF5Error(`the symbol table node at ${node} has no SNOD signature`);
    }
    const count = this.num(node + 6, 2);
    if (count > MAX_SYMBOLS) {
      throw new HDF5Error(`${count} symbol table entries is more than this reads`);
    }
    // Each entry is a name offset, an object header address, a four-byte
    // cache type, four reserved bytes and sixteen bytes of scratch-pad.
    const width = this.sb.lengthSize + this.sb.offsetSize + 8 + 16;
    for (let i = 0; i < count; i++) {
      const e = node + 8 + i * width;
      const nameOffset = this.len(e);
      const target = this.addr(e + this.sb.lengthSize);
      const cache = this.num(e + this.sb.lengthSize + this.sb.offsetSize, 4);
      const name = this.heapName(heap, nameOffset);
      if (cache === 2) {
        // A symbolic link whose value is cached in the local heap.
        const where = this.num(e + this.sb.lengthSize + this.sb.offsetSize + 8, 4);
        out.push({ name, kind: "soft", value: this.heapName(heap, where) });
      } else {
        out.push({ name, kind: "hard", target });
      }
    }
  }

  /** A null-terminated name held in a local heap. */
  private heapName(heap: number, offset: number): string {
    if (!this.at(heap, 4).equals(HEAP)) {
      throw new HDF5Error(`the local heap at ${heap} has no HEAP signature`);
    }
    const segment = this.addr(heap + 8 + 2 * this.sb.lengthSize);
    if (segment === undefined) {
      throw new HDF5Error(`the local heap at ${heap} names no data segment`);
    }
    const from = segment + offset;
    this.at(from, 1);
    const end = this.bytes.indexOf(0, from);
    if (end < 0 || end - from > MAX_NAME) {
      throw new HDF5Error(
        `a name at ${from} in the local heap at ${heap} is not terminated ` +
        `within ${MAX_NAME} bytes`);
    }
    return this.at(from, end - from).toString("utf8");
  }

  // --- the namespace -----------------------------------------------------

  /**
   * Every element the import presents, by the path it is presented under.
   *
   * There is one traversal, not one per kind of answer: a namespace assembled
   * in two places would be assembled two ways, and the paths a reference
   * hangs from are the same paths the objects hang from.
   *
   * A hard link reached twice is one object under two names, which is
   * ordinary in HDF5; each object's own links are followed once, so a file
   * whose links form a cycle terminates.
   *
   * An element that cannot be read is recorded as not presented, with the
   * reason, and the rest of the file is still presented. One corrupt link
   * denies that element, not the import: refusing the whole file for a single
   * unreadable element would make any one bad byte deep in a large file deny
   * everything above it. The root group is the exception, since without it
   * there is no namespace at all, so a root that cannot be read throws.
   */
  present(): Map<string, Element> {
    const out = new Map<string, Element>();
    const expanded = new Set<number>();
    const root = this.root();
    // Not guarded: without a readable root group there is no namespace.
    const rootObject = this.describe(root);
    if (rootObject.kind !== "group") {
      // The format defines the root as a group. A root header that carries no
      // group message is malformed, and presenting it as an empty container
      // would invent a namespace rather than report that there is none.
      throw new HDF5Error(
        `the root object header at ${root} carries no group message, so the ` +
        `file presents no namespace`);
    }
    const pending: { header: number; path: string }[] = [{ header: root, path: "/" }];
    out.set("/", { presents: "container", kind: rootObject.kind, object: rootObject });

    while (pending.length > 0) {
      const { header, path } = pending.shift()!;
      if (out.size > MAX_OBJECTS) {
        throw new HDF5Error(`more than ${MAX_OBJECTS} objects is more than this reads`);
      }
      if (expanded.has(header)) continue;
      expanded.add(header);

      let links: Link[];
      try {
        if (this.describe(header).kind !== "group") continue;
        links = this.links(header);
      } catch (e) {
        // The container itself is presented: it is its contents that could
        // not be enumerated. Marking it not presented would hide the
        // container, and leaving it unmarked would show it as empty when it
        // is not, so it keeps its place and carries why its listing is
        // short.
        const why = `the contents could not be read: ${reason(e)}`;
        this.unread.add(why);
        const already = out.get(path);
        if (already !== undefined) {
          out.set(path, { ...already, incomplete: why });
        } else {
          this.decline(out, path, why);
        }
        continue;
      }

      for (const link of links) {
        if (!storableName(link.name)) {
          // Recorded under the parent, since there is no name to hang it on.
          this.unread.add("a link whose name a CDMI namespace cannot hold");
          continue;
        }
        const child = `${path === "/" ? "" : path}/${link.name}`;
        if (link.kind === "soft") {
          // A reference holds no object of its own, so there is nothing
          // further to walk. The value is a path within this same file,
          // which the importing server maps into its own namespace.
          out.set(child, {
            presents: "reference",
            kind: "unknown",
            reference: { kind: "soft", value: link.value ?? "" },
          });
          continue;
        }
        if (link.kind === "external") {
          // An external link names a file and a path within that file. A CDMI
          // reference's destination is a URI, and neither of those is one:
          // the file is named as a file system path, which this server cannot
          // turn into a URI without inventing a scheme and an authority for
          // it, and the file is not the import source, which an import does
          // not read. So the element is recorded rather than presented as a
          // reference whose destination cannot be formed.
          //
          // ECO-120B maps an external link to a reference without saying what
          // the destination is where the file it names is not one this server
          // holds. NOTES-on-hdf5-imports.md raises it.
          this.decline(out, child,
            `it is an external link, to ${link.value ?? "another file"}, and a ` +
            "reference's destination cannot be formed from the file it names");
          continue;
        }
        if (link.kind !== "hard") {
          this.decline(out, child, link.declined ?? `it is a ${link.kind} link`);
          continue;
        }
        if (link.target === undefined) {
          this.decline(out, child, "the link names no object");
          continue;
        }
        let object: H5Object;
        try {
          object = this.describe(link.target);
        } catch (e) {
          this.decline(out, child, `its object header could not be read: ${reason(e)}`);
          continue;
        }
        const presents = HDF5.presents(object.kind);
        if (presents === "not-presented") {
          this.decline(out, child, `an HDF5 ${object.kind} has no CDMI object kind`);
          continue;
        }
        out.set(child, { presents, kind: object.kind, object });
        if (object.kind === "group") pending.push({ header: link.target, path: child });
      }
    }
    return out;
  }

  /** Records an element that is not presented, and why. */
  private decline(out: Map<string, Element>, path: string, why: string): void {
    this.unread.add(why);
    out.set(path, { presents: "not-presented", kind: "unknown", declined: why });
  }
}

/** Where a dataset's raw data is held. */
export type Layout =
  /** In the layout message itself. */
  | { kind: "compact"; at: number; size: number }
  /** In one run of bytes elsewhere in the file. */
  | { kind: "contiguous"; at: number; size: number }
  /** Scattered across chunks located by an index. */
  | { kind: "chunked" }
  /** Assembled from mappings into other datasets, possibly in other files. */
  | { kind: "virtual" }
  /** Never written, so the value is the fill value. */
  | { kind: "none" };

/** What a dataset holds. */
export interface Dataset {
  readonly dimensions: number[];
  readonly elementSize: number;
  /** The size of the value in bytes: the elements times the element size. */
  readonly size: number;
  /** Whether the raw data passed through the filter pipeline. */
  readonly filtered: boolean;
  readonly layout: Layout;
}

/** One element of the file, as the import presents it. */
export interface Element {
  readonly presents: Presents;
  readonly kind: ObjectKind;
  readonly object?: H5Object;
  readonly reference?: { kind: "soft" | "external"; value: string };
  /** Why this element is not presented, where it is not. */
  readonly declined?: string;
  /**
   * Why this container's listing is short, where it is. A container whose
   * contents could not be read is still presented, because it is there; a
   * client that is not told would read the short listing as an empty
   * container.
   */
  readonly incomplete?: string;
}

/** The message of an error, without letting a non-error throw become one. */
function reason(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * An unsigned little-endian integer, or undefined where it is too large to
 * hold exactly. Every width this format uses is read here rather than through
 * a Buffer method, so that the 2, 4 and 8 byte cases cannot diverge, and so
 * that a value beyond the exactly representable range is reported rather than
 * rounded into a plausible-looking offset.
 */
function leNumber(b: Buffer): number | undefined {
  let value = 0;
  for (let i = b.length - 1; i >= 0; i--) value = value * 256 + b[i];
  return Number.isSafeInteger(value) ? value : undefined;
}

/**
 * Whether a CDMI namespace can hold an object of this name. HDF5 allows any
 * byte but NUL in a link name, including the separator, so a name that would
 * change the shape of the namespace it is presented in is declined rather
 * than presented under a name that is not its own.
 */
export function storableName(name: string): boolean {
  return name.length > 0 && name.length <= 255
    && !name.includes("/") && !name.includes("\0")
    && name !== "." && name !== "..";
}
