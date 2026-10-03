/**
 * The two structures phase five needs: the reparse point that presents
 * a reference, of [MS-FSCC], and the security descriptor that presents
 * an access control list, of [MS-DTYP].
 *
 * The first is specified by the CDMI clause down to the substitute
 * name. The second is not specified at all: see Q15 in NOTES-on-smb.md.
 */

import { createHash } from "node:crypto";
import { utf16 } from "./smb-wire.ts";
import { maskToString, parseFlags, parseMask } from "./acl.ts";
import type { ACE } from "./store.ts";

/** The control codes an SMB export answers. */
export const FSCTL = {
  GET_REPARSE_POINT: 0x000900a8,
  SET_REPARSE_POINT: 0x000900a4,
  DELETE_REPARSE_POINT: 0x000900ac,
} as const;

/** The reparse tag of a symbolic link, which is how a reference appears. */
export const IO_REPARSE_TAG_SYMLINK = 0xa000000c;

/** The flag that marks a substitute name as relative. */
export const SYMLINK_FLAG_RELATIVE = 0x00000001;

/** The status a client is given when it opens a reference it did not ask for. */
export const STATUS_STOPPED_ON_SYMLINK = 0x8000002d;

/**
 * The reparse data buffer of a symbolic link, of [MS-FSCC] section
 * 2.1.2.4. The substitute name is what the clause forms from the
 * destination of the reference; the print name is the same text,
 * being what a client displays.
 */
export function symlinkReparseData(substitute: string, relative: boolean): Buffer {
  const sub = utf16(substitute);
  const print = utf16(substitute);
  const pathBuffer = Buffer.concat([sub, print]);
  const dataLength = 12 + pathBuffer.length;
  const b = Buffer.alloc(8 + dataLength);
  b.writeUInt32LE(IO_REPARSE_TAG_SYMLINK, 0);
  b.writeUInt16LE(dataLength, 4);
  b.writeUInt16LE(0, 6); // Reserved
  b.writeUInt16LE(0, 8); // SubstituteNameOffset
  b.writeUInt16LE(sub.length, 10);
  b.writeUInt16LE(sub.length, 12); // PrintNameOffset
  b.writeUInt16LE(print.length, 14);
  b.writeUInt32LE(relative ? SYMLINK_FLAG_RELATIVE : 0, 16);
  pathBuffer.copy(b, 20);
  return b;
}

/** The substitute name a reparse data buffer carries. */
export function readSymlinkReparseData(b: Buffer):
  { substitute: string; relative: boolean } | undefined {
  if (b.length < 20) return undefined;
  if (b.readUInt32LE(0) !== IO_REPARSE_TAG_SYMLINK) return undefined;
  const offset = b.readUInt16LE(8);
  const length = b.readUInt16LE(10);
  if (20 + offset + length > b.length) return undefined;
  return {
    substitute: b.subarray(20 + offset, 20 + offset + length).toString("utf16le"),
    relative: (b.readUInt32LE(16) & SYMLINK_FLAG_RELATIVE) !== 0,
  };
}

/**
 * The symbolic link error response of [MS-SMB2] section 2.2.2.2.1,
 * which a CREATE answers where the path met a reference and the client
 * did not ask to open one. The unparsed length is the part of the path
 * beyond the reference, in octets of UTF-16.
 */
export function symlinkErrorResponse(
  substitute: string,
  relative: boolean,
  unparsed: number,
): Buffer {
  const sub = utf16(substitute);
  const print = utf16(substitute);
  const pathBuffer = Buffer.concat([sub, print]);
  const symLinkLength = 24 + pathBuffer.length;
  const data = Buffer.alloc(4 + symLinkLength);
  data.writeUInt32LE(symLinkLength, 0);
  data.writeUInt32LE(0x4c4d5953, 4); // SymLinkErrorTag, "SYML"
  data.writeUInt32LE(IO_REPARSE_TAG_SYMLINK, 8);
  data.writeUInt16LE(12 + pathBuffer.length, 12); // ReparseDataLength
  data.writeUInt16LE(unparsed, 14);
  data.writeUInt16LE(0, 16); // SubstituteNameOffset
  data.writeUInt16LE(sub.length, 18);
  data.writeUInt16LE(sub.length, 20); // PrintNameOffset
  data.writeUInt16LE(print.length, 22);
  data.writeUInt32LE(relative ? SYMLINK_FLAG_RELATIVE : 0, 24);
  pathBuffer.copy(data, 28);

  // The error response that carries it: one error context, whose data
  // is the structure above.
  const out = Buffer.alloc(8 + data.length);
  out.writeUInt16LE(9, 0);
  out.writeUInt8(0, 2); // ErrorContextCount
  out.writeUInt8(0, 3); // Reserved
  out.writeUInt32LE(data.length, 4);
  data.copy(out, 8);
  return out;
}

// ---------------------------------------------------------------------------
// Security descriptors

/** The parts of a descriptor a request asks for. */
export const SECURITY_INFORMATION = {
  OWNER: 0x00000001,
  GROUP: 0x00000002,
  DACL: 0x00000004,
  SACL: 0x00000008,
} as const;

const SE_DACL_PRESENT = 0x0004;
/**
 * The list is protected: the inheritance of this document is applied
 * when an object is created and is not the automatic inheritance a
 * client would otherwise recompute from the parent.
 */
const SE_DACL_PROTECTED = 0x1000;
const SE_SELF_RELATIVE = 0x8000;

/**
 * The special identifiers of this document and the well-known
 * security identifier of each, as the SMB export clause states them.
 * OWNER@ and GROUP@ are not here: they correspond to the owner and
 * the group the descriptor itself names, and not to a well-known
 * identifier.
 */
const WELL_KNOWN: Record<string, string> = {
  "EVERYONE@": "S-1-1-0",
  "ANONYMOUS@": "S-1-5-7",
  "AUTHENTICATED@": "S-1-5-11",
  "ADMINISTRATOR@": "S-1-5-32-544",
  "ADMINUSERS@": "S-1-5-32-544",
};

/** The security identifier of the anonymous logon. */
export const ANONYMOUS_SID = "S-1-5-7";

/**
 * The mapping between a name of this document and a name of the
 * identity domain of the SMB server, from the usermap and groupmap
 * fields of the export entry. Each entry is directional: "-->" maps a
 * CDMI name outward, "<--" maps an SMB name inward, and "<-->" both.
 */
export class PrincipalMap {
  private readonly outward = new Map<string, string>();
  private readonly inward = new Map<string, string>();

  constructor(entries: string[][] = []) {
    for (const [cdmi, operator, smb] of entries) {
      if (operator === "-->" || operator === "<-->") this.outward.set(cdmi, smb);
      if (operator === "<--" || operator === "<-->") this.inward.set(smb, cdmi);
    }
  }

  /** The name of the identity domain of the SMB server, for a CDMI name. */
  toSmb(cdmi: string): string {
    return this.outward.get(cdmi) ?? cdmi;
  }

  /** The name of this document, for a name of the SMB identity domain. */
  toCdmi(smb: string): string | undefined {
    if (this.inward.has(smb)) return this.inward.get(smb);
    // A name this document holds and the map does not mention is
    // carried unchanged in both directions, which is the default
    // mapping policy of this server.
    return this.outward.has(smb) || this.inward.size === 0 ? smb : undefined;
  }

  /** Every name that may appear in a descriptor this export presents. */
  names(): string[] {
    return [...new Set([...this.outward.values(), ...this.inward.keys()])];
  }
}

/**
 * The SID that stands for a CDMI identifier. The special identifiers
 * have well-known counterparts; a named principal has none, and this
 * document requires no name service that would supply one, so a SID is
 * derived from the name. Such a SID is stable and unique, and it names
 * nothing a client can look up, and it cannot be turned back into the
 * name. See Q15.
 */
export function sidFor(identifier: string, authority?: string): Buffer {
  const known = WELL_KNOWN[identifier.toUpperCase()];
  if (known !== undefined) return parseSid(known);
  // Where no domain is configured, the CDMI server is the authority
  // for the principals of the export. The identifier authority value
  // is derived from something stable that belongs to the export, so
  // that two exports do not assign one identifier to two principals,
  // and the value is not one [MS-DTYP] defines as well known and not
  // one of a domain this server does not hold.
  const base = createHash("sha256").update(authority ?? "seedmi").digest();
  const h = createHash("sha256").update(identifier).digest();
  const parts = [
    // The first subauthority is not 21: that value introduces a
    // domain identifier, and this server holds no domain.
    0x10000000 | (base.readUInt32LE(0) & 0x0fffffff),
    base.readUInt32LE(4),
    base.readUInt32LE(8),
    h.readUInt32LE(0),
    h.readUInt32LE(4),
  ];
  return buildSid(5, parts);
}

/** A SID in the string form of [MS-DTYP] section 2.4.2.1. */
export function parseSid(s: string): Buffer {
  const parts = s.split("-");
  const authority = Number(parts[2]);
  const sub = parts.slice(3).map(Number);
  return buildSid(authority, sub);
}

function buildSid(authority: number, sub: number[]): Buffer {
  const b = Buffer.alloc(8 + sub.length * 4);
  b.writeUInt8(1, 0); // Revision
  b.writeUInt8(sub.length, 1);
  // The identifier authority is six octets in network order.
  b.writeUInt32BE(authority, 4);
  sub.forEach((v, i) => b.writeUInt32LE(v >>> 0, 8 + i * 4));
  return b;
}

/** The string form of a SID a buffer holds. */
export function sidToString(b: Buffer): string {
  const count = b.readUInt8(1);
  // The identifier authority is six octets; this server uses only
  // values that fit the low four.
  const authority = b.readUInt32BE(4);
  const sub: number[] = [];
  for (let i = 0; i < count; i++) sub.push(b.readUInt32LE(8 + i * 4));
  return ["S", b.readUInt8(0), authority, ...sub].join("-");
}

/** The length of the SID at the start of a buffer. */
export const sidLength = (b: Buffer): number => 8 + b.readUInt8(1) * 4;

/**
 * A self-relative security descriptor formed from an access control
 * list. The mask of each entry is carried unchanged, the two masks
 * sharing a layout; the flags are carried unchanged for the same
 * reason; the identifier becomes a SID.
 */
export function securityDescriptor(
  acl: ACE[] | null,
  owner: string,
  group: string,
  isContainer: boolean,
  wanted: number,
  authority?: string,
  names?: PrincipalMap,
): Buffer {
  const parts: Buffer[] = [];
  const map = names ?? new PrincipalMap();
  const sidOf = (identifier: string) =>
    sidFor(WELL_KNOWN[identifier.toUpperCase()] === undefined
      ? map.toSmb(identifier)
      : identifier, authority);
  // OWNER@ and GROUP@ name the owner and the group of the object
  // itself, so the descriptor carries those principals rather than a
  // well-known identifier standing for them.
  const ownerSid = sidOf(owner === "" ? "ANONYMOUS@" : owner);
  const groupSid = sidOf(group === "" ? "ANONYMOUS@" : group);

  const entries: ACE[] = [];
  for (const ace of acl ?? []) {
    const who = ace.identifier.toUpperCase();
    entries.push(who === "OWNER@"
      ? { ...ace, identifier: owner === "" ? "ANONYMOUS@" : owner }
      : who === "GROUP@"
      ? { ...ace, identifier: group === "" ? "ANONYMOUS@" : group }
      : ace);
    // A Windows client excludes an anonymous logon from EVERYONE by
    // default, so an entry granting EVERYONE@ is accompanied by one
    // granting the anonymous identifier the same access. Without it
    // the access would be narrower through the export than through a
    // protocol binding.
    if (who === "EVERYONE@") {
      entries.push({ ...ace, identifier: "ANONYMOUS@" });
    }
  }

  const aces: Buffer[] = [];
  for (const ace of entries) {
    const sid = sidOf(ace.identifier);
    const size = 8 + sid.length;
    const b = Buffer.alloc(size);
    // The two types this document defines, and no other.
    b.writeUInt8(ace.acetype.toUpperCase() === "DENY" ? 0x01 : 0x00, 0);
    // An entry a CDMI server holds is an entry of the object that
    // holds it however it came to be there, so it is not presented as
    // inherited.
    b.writeUInt8(parseFlags(ace.aceflags) & 0xff & ~0x10, 1);
    b.writeUInt16LE(size, 2);
    b.writeUInt32LE(parseMask(ace.acemask, isContainer) >>> 0, 4);
    sid.copy(b, 8);
    aces.push(b);
  }
  const aceBuffer = Buffer.concat(aces);
  const dacl = Buffer.alloc(8 + aceBuffer.length);
  dacl.writeUInt8(2, 0); // ACL_REVISION
  dacl.writeUInt16LE(dacl.length, 2);
  dacl.writeUInt16LE(aces.length, 4);
  aceBuffer.copy(dacl, 8);

  const wantOwner = (wanted & SECURITY_INFORMATION.OWNER) !== 0;
  const wantGroup = (wanted & SECURITY_INFORMATION.GROUP) !== 0;
  const wantDacl = (wanted & SECURITY_INFORMATION.DACL) !== 0 || wanted === 0;

  let at = 20;
  let ownerOffset = 0;
  let groupOffset = 0;
  let daclOffset = 0;
  if (wantOwner) {
    ownerOffset = at;
    parts.push(ownerSid);
    at += ownerSid.length;
  }
  if (wantGroup) {
    groupOffset = at;
    parts.push(groupSid);
    at += groupSid.length;
  }
  if (wantDacl) {
    daclOffset = at;
    parts.push(dacl);
    at += dacl.length;
  }

  const head = Buffer.alloc(20);
  head.writeUInt8(1, 0); // Revision
  head.writeUInt8(0, 1); // Sbz1
  head.writeUInt16LE(
    SE_SELF_RELATIVE | (wantDacl ? SE_DACL_PRESENT | SE_DACL_PROTECTED : 0), 2);
  head.writeUInt32LE(ownerOffset, 4);
  head.writeUInt32LE(groupOffset, 8);
  head.writeUInt32LE(0, 12); // OffsetSacl: no system list is presented
  head.writeUInt32LE(daclOffset, 16);
  return Buffer.concat([head, ...parts]);
}

/**
 * The entries a self-relative descriptor carries, as this document
 * would express them. A SID that stands for a named principal cannot
 * be turned back into the name, so an entry carrying one is answered
 * as its string form and the caller decides what to do about it.
 */
export function readDacl(descriptor: Buffer, isContainer: boolean):
  { entries: ACE[]; unnamed: string[] } | undefined {
  if (descriptor.length < 20 || descriptor.readUInt8(0) !== 1) return undefined;
  const offset = descriptor.readUInt32LE(16);
  if (offset === 0 || offset + 8 > descriptor.length) return { entries: [], unnamed: [] };
  const count = descriptor.readUInt16LE(offset + 4);
  const entries: ACE[] = [];
  const unnamed: string[] = [];
  let at = offset + 8;
  const byName = new Map<string, string>();
  for (const name of Object.keys(WELL_KNOWN)) {
    byName.set(sidToString(parseSid(WELL_KNOWN[name])), name);
  }
  for (let i = 0; i < count; i++) {
    if (at + 8 > descriptor.length) return undefined;
    const type = descriptor.readUInt8(at);
    const flags = descriptor.readUInt8(at + 1);
    const size = descriptor.readUInt16LE(at + 2);
    const mask = descriptor.readUInt32LE(at + 4);
    const sid = descriptor.subarray(at + 8, at + size);
    const text = sidToString(sid);
    const identifier = byName.get(text);
    if (identifier === undefined) unnamed.push(text);
    entries.push({
      acetype: type === 0x01 ? "DENY" : "ALLOW",
      identifier: identifier ?? text,
      aceflags: flagsToText(flags),
      acemask: maskToString(mask, isContainer),
    });
    at += size;
  }
  return { entries, unnamed };
}

/** A security identifier a CDMI server is unable to translate. */
export class UnmappedSid extends Error {
  readonly sid: string;

  constructor(sid: string) {
    super(`no identifier of this document corresponds to ${sid}`);
    this.sid = sid;
  }
}

/**
 * The access control list of this document that a security descriptor
 * an SMB client wrote corresponds to.
 *
 * A security identifier the CDMI server is unable to translate is
 * refused: the entry carrying it is neither stored with the identifier
 * nor discarded, since either would present the CDMI client with a
 * list it did not write.
 */
export function aclFromDescriptor(
  descriptor: Buffer,
  isContainer: boolean,
  authority: string,
  map: PrincipalMap,
  owner: string,
  group: string,
): { acl: ACE[]; owner?: string; group?: string } {
  if (descriptor.length < 20 || descriptor.readUInt8(0) !== 1) {
    throw new SmbDescriptorError("the descriptor is not of revision 1");
  }
  const control = descriptor.readUInt16LE(2);
  if ((control & 0x0010) !== 0) {
    // A system access control list: this document defines none.
    throw new SmbDescriptorError("this document defines no system access control list");
  }

  // Every name that may appear, and the identifier each stands for.
  const back = new Map<string, string>();
  for (const [name, sid] of Object.entries(WELL_KNOWN)) {
    // ADMINISTRATOR@ and ADMINUSERS@ share one identifier; the first
    // is what a list formed from a descriptor names.
    if (!back.has(sidToString(parseSid(sid)))) {
      back.set(sidToString(parseSid(sid)), name);
    }
  }
  for (const smb of [...map.names(), owner, group]) {
    if (smb === "") continue;
    const cdmi = map.toCdmi(smb);
    if (cdmi === undefined) continue;
    back.set(sidToString(sidFor(smb, authority)), cdmi);
  }

  const identifierAt = (at: number): string => {
    const text = sidToString(descriptor.subarray(at));
    const known = back.get(text);
    if (known === undefined) throw new UnmappedSid(text);
    return known;
  };

  const ownerOffset = descriptor.readUInt32LE(4);
  const groupOffset = descriptor.readUInt32LE(8);
  const daclOffset = descriptor.readUInt32LE(16);
  const out: { acl: ACE[]; owner?: string; group?: string } = { acl: [] };
  if (ownerOffset !== 0) out.owner = identifierAt(ownerOffset);
  if (groupOffset !== 0) out.group = identifierAt(groupOffset);
  if (daclOffset === 0) return out;

  const count = descriptor.readUInt16LE(daclOffset + 4);
  let at = daclOffset + 8;
  const entries: ACE[] = [];
  for (let i = 0; i < count; i++) {
    if (at + 8 > descriptor.length) {
      throw new SmbDescriptorError("an entry of the list runs past the descriptor");
    }
    const type = descriptor.readUInt8(at);
    if (type !== 0x00 && type !== 0x01) {
      // This document defines the two types and no other.
      throw new SmbDescriptorError(
        `an access control entry of type ${type} is not one this document defines`);
    }
    const size = descriptor.readUInt16LE(at + 2);
    entries.push({
      acetype: type === 0x01 ? "DENY" : "ALLOW",
      identifier: identifierAt(at + 8),
      aceflags: flagsToText(descriptor.readUInt8(at + 1) & ~0x10),
      acemask: maskToString(descriptor.readUInt32LE(at + 4), isContainer),
    });
    at += size;
  }

  // An entry granting EVERYONE@ is presented with one granting the
  // anonymous identifier the same access; the two are taken together
  // as one entry granting EVERYONE@.
  const acl: ACE[] = [];
  for (const [i, e] of entries.entries()) {
    const next = entries[i + 1];
    if (e.identifier === "ANONYMOUS@" && i > 0) {
      const before = entries[i - 1];
      if (before.identifier === "EVERYONE@" && before.acetype === e.acetype &&
        before.acemask === e.acemask && before.aceflags === e.aceflags) {
        continue;
      }
    }
    void next;
    acl.push(e);
  }
  out.acl = acl;
  return out;
}

/** A descriptor this CDMI server is unable to accept. */
export class SmbDescriptorError extends Error {}

const FLAG_NAMES: [number, string][] = [
  [0x01, "OBJECT_INHERIT"],
  [0x02, "CONTAINER_INHERIT"],
  [0x04, "NO_PROPAGATE"],
  [0x08, "INHERIT_ONLY"],
  [0x10, "INHERITED"],
];

const flagsToText = (flags: number): string =>
  FLAG_NAMES.filter(([bit]) => (flags & bit) !== 0).map(([, name]) => name).join(",");
