/**
 * The information levels of [MS-FSCC] that an SMB export answers: the
 * ones a directory listing carries, and the ones QUERY_INFO asks for.
 * Each is a fixed part followed by a name, and the offsets are those
 * the document gives.
 */

import { utf16 } from "./smb-wire.ts";
import { FILE_ATTRIBUTE, type Entry } from "./smb-fs.ts";

/** The classes a directory listing may be asked for. */
export const DIR_CLASS = {
  FileDirectoryInformation: 0x01,
  FileFullDirectoryInformation: 0x02,
  FileBothDirectoryInformation: 0x03,
  FileNamesInformation: 0x0c,
  FileIdBothDirectoryInformation: 0x25,
  FileIdFullDirectoryInformation: 0x26,
} as const;

/** The classes QUERY_INFO may ask for, of an information type of one. */
export const FILE_CLASS = {
  FileBasicInformation: 0x04,
  FileStandardInformation: 0x05,
  FileInternalInformation: 0x06,
  FileEaInformation: 0x07,
  FileFullEaInformation: 0x0f,
  FileAccessInformation: 0x08,
  FileNameInformation: 0x09,
  FileRenameInformation: 0x0a,
  FileLinkInformation: 0x0b,
  FileDispositionInformation: 0x0d,
  FilePositionInformation: 0x0e,
  FileModeInformation: 0x10,
  FileAlignmentInformation: 0x11,
  FileAllInformation: 0x12,
  FileAllocationInformation: 0x13,
  FileEndOfFileInformation: 0x14,
  FileStreamInformation: 0x16,
  FileNetworkOpenInformation: 0x22,
  FileAttributeTagInformation: 0x23,
} as const;

/** The classes of an information type of two, the file system. */
export const FS_CLASS = {
  FileFsVolumeInformation: 0x01,
  FileFsSizeInformation: 0x03,
  FileFsDeviceInformation: 0x04,
  FileFsAttributeInformation: 0x05,
  FileFsFullSizeInformation: 0x07,
} as const;

/** The information types of a QUERY_INFO. */
export const INFO_TYPE = { FILE: 0x01, FILESYSTEM: 0x02, SECURITY: 0x03, QUOTA: 0x04 };

/** The allocation of an object, rounded to the block size reported. */
export const BLOCK = 4096;
export const allocationOf = (size: number): bigint =>
  BigInt(Math.ceil(size / BLOCK) * BLOCK);

const times = (b: Buffer, at: number, e: Entry): void => {
  b.writeBigUInt64LE(e.created, at);
  b.writeBigUInt64LE(e.accessed, at + 8);
  b.writeBigUInt64LE(e.written, at + 16);
  b.writeBigUInt64LE(e.changed, at + 24);
};

/**
 * One entry of a directory listing. The fixed part depends on the
 * class, and the name follows it; NextEntryOffset is filled in by the
 * caller, which knows whether another entry follows.
 */
export function directoryEntry(cls: number, e: Entry, index: number):
  Buffer | undefined {
  const name = utf16(e.name);
  const fixed = {
    [DIR_CLASS.FileDirectoryInformation]: 64,
    [DIR_CLASS.FileFullDirectoryInformation]: 68,
    [DIR_CLASS.FileBothDirectoryInformation]: 94,
    [DIR_CLASS.FileNamesInformation]: 12,
    [DIR_CLASS.FileIdBothDirectoryInformation]: 104,
    [DIR_CLASS.FileIdFullDirectoryInformation]: 80,
  }[cls];
  if (fixed === undefined) return undefined;

  const b = Buffer.alloc(fixed + name.length);
  b.writeUInt32LE(0, 0); // NextEntryOffset, filled in by the caller
  b.writeUInt32LE(index, 4);
  if (cls === DIR_CLASS.FileNamesInformation) {
    b.writeUInt32LE(name.length, 8);
    name.copy(b, 12);
    return b;
  }
  times(b, 8, e);
  b.writeBigUInt64LE(BigInt(e.size), 40); // EndOfFile
  b.writeBigUInt64LE(allocationOf(e.size), 48);
  b.writeUInt32LE(e.attributes, 56);
  b.writeUInt32LE(name.length, 60);
  if (cls === DIR_CLASS.FileDirectoryInformation) {
    name.copy(b, 64);
    return b;
  }
  // Every other class carries the size of the extended attributes,
  // which for this export is the size of the user metadata as an SMB
  // client would see it; nothing is presented yet, so it is zero.
  b.writeUInt32LE(0, 64);
  if (cls === DIR_CLASS.FileFullDirectoryInformation) {
    name.copy(b, 68);
    return b;
  }
  if (cls === DIR_CLASS.FileIdFullDirectoryInformation) {
    b.writeUInt32LE(0, 68); // Reserved
    b.writeBigUInt64LE(e.fileId, 72);
    name.copy(b, 80);
    return b;
  }
  // The two classes that carry a short name, which this export does
  // not form: a CDMI object name has no 8.3 equivalent, and a client
  // that needs one is told there is none by a length of zero.
  b.writeUInt8(0, 68); // ShortNameLength
  b.writeUInt8(0, 69); // Reserved
  if (cls === DIR_CLASS.FileBothDirectoryInformation) {
    name.copy(b, 94);
    return b;
  }
  b.writeUInt16LE(0, 94); // Reserved2
  b.writeBigUInt64LE(e.fileId, 96);
  name.copy(b, 104);
  return b;
}

/** Joins directory entries, filling in the offset of each. */
export function directoryBuffer(entries: Buffer[]): Buffer {
  const out: Buffer[] = [];
  entries.forEach((e, i) => {
    // Each entry but the last is padded to a multiple of eight and
    // names the offset of the one that follows.
    if (i === entries.length - 1) {
      out.push(e);
      return;
    }
    const padded = (e.length + 7) & ~7;
    const b = Buffer.alloc(padded);
    e.copy(b, 0);
    b.writeUInt32LE(padded, 0);
    out.push(b);
  });
  return Buffer.concat(out);
}

/** The answer to a QUERY_INFO of an information type of one. */
export function fileInformation(cls: number, e: Entry, path: string):
  Buffer | undefined {
  switch (cls) {
    case FILE_CLASS.FileBasicInformation: {
      const b = Buffer.alloc(40);
      times(b, 0, e);
      b.writeUInt32LE(e.attributes, 32);
      return b;
    }
    case FILE_CLASS.FileStandardInformation:
      return standard(e);
    case FILE_CLASS.FileInternalInformation: {
      const b = Buffer.alloc(8);
      b.writeBigUInt64LE(e.fileId);
      return b;
    }
    case FILE_CLASS.FileEaInformation:
      return Buffer.alloc(4);
    case FILE_CLASS.FileAccessInformation:
      return Buffer.alloc(4);
    case FILE_CLASS.FilePositionInformation:
      return Buffer.alloc(8);
    case FILE_CLASS.FileModeInformation:
      return Buffer.alloc(4);
    case FILE_CLASS.FileAlignmentInformation:
      return Buffer.alloc(4); // FILE_BYTE_ALIGNMENT
    case FILE_CLASS.FileNameInformation:
      return nameInformation(path);
    case FILE_CLASS.FileNetworkOpenInformation: {
      const b = Buffer.alloc(56);
      times(b, 0, e);
      b.writeBigUInt64LE(allocationOf(e.size), 32);
      b.writeBigUInt64LE(BigInt(e.size), 40);
      b.writeUInt32LE(e.attributes, 48);
      return b;
    }
    case FILE_CLASS.FileAttributeTagInformation: {
      const b = Buffer.alloc(8);
      b.writeUInt32LE(e.attributes, 0);
      // A reference is a reparse point of the symbolic link tag, and
      // an object that is not one carries no tag.
      b.writeUInt32LE(e.reference === undefined ? 0 : 0xa000000c, 4);
      return b;
    }
    case FILE_CLASS.FileAllInformation: {
      const basic = Buffer.alloc(40);
      times(basic, 0, e);
      basic.writeUInt32LE(e.attributes, 32);
      const name = nameInformation(path);
      return Buffer.concat([
        basic,
        standard(e),
        (() => {
          const b = Buffer.alloc(8);
          b.writeBigUInt64LE(e.fileId);
          return b;
        })(),
        Buffer.alloc(4), // FileEaInformation
        Buffer.alloc(4), // FileAccessInformation
        Buffer.alloc(8), // FilePositionInformation
        Buffer.alloc(4), // FileModeInformation
        Buffer.alloc(4), // FileAlignmentInformation
        name,
      ]);
    }
    default:
      return undefined;
  }
}

function standard(e: Entry): Buffer {
  const b = Buffer.alloc(24);
  b.writeBigUInt64LE(allocationOf(e.size), 0);
  b.writeBigUInt64LE(BigInt(e.size), 8);
  // One link: this document defines no object for a hard link, so
  // every object of an SMB export has exactly one name.
  b.writeUInt32LE(1, 16);
  b.writeUInt8(0, 20); // DeletePending
  b.writeUInt8(e.isContainer ? 1 : 0, 21);
  return b;
}

function nameInformation(path: string): Buffer {
  const name = utf16(path === "" ? "\\" : `\\${path}`);
  const b = Buffer.alloc(4 + name.length);
  b.writeUInt32LE(name.length, 0);
  name.copy(b, 4);
  return b;
}

/** The answer to a QUERY_INFO of an information type of two. */
export function filesystemInformation(cls: number, label: string):
  Buffer | undefined {
  switch (cls) {
    case FS_CLASS.FileFsVolumeInformation: {
      const name = utf16(label);
      const b = Buffer.alloc(18 + name.length);
      b.writeBigUInt64LE(0n, 0); // VolumeCreationTime
      b.writeUInt32LE(0x63646d69, 8); // VolumeSerialNumber
      b.writeUInt32LE(name.length, 12);
      b.writeUInt8(0, 16); // SupportsObjects
      name.copy(b, 18);
      return b;
    }
    case FS_CLASS.FileFsSizeInformation: {
      // A CDMI container object has no size of its own, so what is
      // reported is what the export can be told: the units, and a
      // total this server does not bound.
      const b = Buffer.alloc(24);
      b.writeBigUInt64LE(0n, 0);
      b.writeBigUInt64LE(0n, 8);
      b.writeUInt32LE(1, 16);
      b.writeUInt32LE(BLOCK, 20);
      return b;
    }
    case FS_CLASS.FileFsFullSizeInformation: {
      const b = Buffer.alloc(32);
      b.writeUInt32LE(1, 24);
      b.writeUInt32LE(BLOCK, 28);
      return b;
    }
    case FS_CLASS.FileFsDeviceInformation: {
      const b = Buffer.alloc(8);
      b.writeUInt32LE(0x00000007, 0); // FILE_DEVICE_DISK
      b.writeUInt32LE(0x00000020, 4); // FILE_REMOTE_DEVICE
      return b;
    }
    case FS_CLASS.FileFsAttributeInformation: {
      const name = utf16("CDMI");
      const b = Buffer.alloc(12 + name.length);
      // Unicode names, and the case of a name is preserved and
      // significant, which is true of a CDMI object name and is the
      // one place this file system differs from what a client expects.
      b.writeUInt32LE(0x00000001 | 0x00000002 | 0x00000004 | 0x00000080, 0);
      b.writeUInt32LE(255, 4);
      b.writeUInt32LE(name.length, 8);
      name.copy(b, 12);
      return b;
    }
    default:
      return undefined;
  }
}

export { FILE_ATTRIBUTE };


/**
 * The limits an SMB export is able to carry, reported by the
 * cdmi_export_smb_ea_maxname and cdmi_export_smb_ea_maxsize
 * capabilities. The name length of FILE_FULL_EA_INFORMATION is one
 * octet and the value length is two, so those are the bounds the
 * exported protocol imposes.
 */
export const EA_MAXNAME = 255;
export const EA_MAXSIZE = 65535;

/** One extended attribute: a name and the octets of its value. */
export interface Ea {
  name: string;
  value: Buffer;
}

/**
 * Encodes extended attributes as FILE_FULL_EA_INFORMATION, defined in
 * section 2.4.15 of [MS-FSCC]. Each entry is aligned to four octets
 * and the last carries a next entry offset of zero.
 */
export function encodeFullEas(eas: Ea[]): Buffer {
  if (eas.length === 0) return Buffer.alloc(0);
  const parts: Buffer[] = [];
  for (const [i, ea] of eas.entries()) {
    const name = Buffer.from(ea.name, "ascii");
    // The name is followed by a NUL that the name length does not
    // count, and the entry is padded to a multiple of four.
    const bare = 8 + name.length + 1 + ea.value.length;
    const last = i === eas.length - 1;
    const size = last ? bare : Math.ceil(bare / 4) * 4;
    const b = Buffer.alloc(size);
    b.writeUInt32LE(last ? 0 : size, 0);
    b.writeUInt8(0, 4); // Flags
    b.writeUInt8(name.length, 5);
    b.writeUInt16LE(ea.value.length, 6);
    name.copy(b, 8);
    ea.value.copy(b, 8 + name.length + 1);
    parts.push(b);
  }
  return Buffer.concat(parts);
}

/**
 * Reads FILE_FULL_EA_INFORMATION. An attribute whose value is empty
 * is a removal, as [MS-FSCC] specifies.
 */
export function decodeFullEas(data: Buffer): Ea[] {
  const out: Ea[] = [];
  let at = 0;
  for (;;) {
    if (at + 8 > data.length) break;
    const next = data.readUInt32LE(at);
    const nameLength = data.readUInt8(at + 5);
    const valueLength = data.readUInt16LE(at + 6);
    if (at + 8 + nameLength + 1 + valueLength > data.length) break;
    out.push({
      name: data.subarray(at + 8, at + 8 + nameLength).toString("ascii"),
      value: Buffer.from(
        data.subarray(at + 8 + nameLength + 1, at + 8 + nameLength + 1 + valueLength)),
    });
    if (next === 0) break;
    at += next;
  }
  return out;
}
