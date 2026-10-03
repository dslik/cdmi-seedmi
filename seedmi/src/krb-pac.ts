// The privilege attribute certificate ([MS-PAC]; PLAN-auth.md, phase 5): the
// authorization data a Kerberos realm puts in a ticket, from which a CDMI
// server takes the groups of the principal that presented it, rather than
// searching the directory for them (revision 282 of the draft, which requires
// the groups of a principal to be those of every path).
//
//   AuthorizationData
//     AD-IF-RELEVANT (1)
//       AD-WIN2K-PAC (128)
//         PACTYPE { cBuffers, Version, PAC_INFO_BUFFER[] }
//           type 1  logon information (KERB_VALIDATION_INFO, NDR)
//           type 10 client name and ticket information
//           type 6  server signature, keyed with the service's own key
//           type 7  KDC signature
//
// "The signature of a PAC prevents elevation of privilege attacks. The
// signature has to be verified to avoid these attacks": the server signature
// is a keyed hash "of the entire PAC message, with the Signature fields of
// both PAC_SIGNATURE_DATA structures set to zero", at key usage 17, which is
// KERB_NON_KERB_CKSUM_SALT.

import { checksum as krbChecksum, MAC } from "./krb-crypto.ts";
import { type Element, readAll, readOne } from "./der.ts";

/** The buffer types of [MS-PAC] section 2.4 this server reads. */
export const PAC_BUFFER = {
  logonInformation: 1,
  serverSignature: 6,
  kdcSignature: 7,
  clientInformation: 10,
  upnDnsInformation: 12,
} as const;

/** The key usage of a PAC signature: KERB_NON_KERB_CKSUM_SALT. */
export const PAC_CHECKSUM_USAGE = 17;

/** The signature types of section 2.8, with the length of each signature. */
export const SIGNATURE_LENGTH: Record<number, number> = {
  0xffffff76: 16, // KERB_CHECKSUM_HMAC_MD5
  0x0000000f: 12, // HMAC_SHA1_96_AES128
  0x00000010: 12, // HMAC_SHA1_96_AES256
};

export class PacError extends Error {}

/** A group of the account domain: its relative identifier, and its attributes. */
export interface PacGroup { rid: number; attributes: number }

/** What this server takes from a privilege attribute certificate. */
export interface Pac {
  /** The account name, as the domain controller holds it (EffectiveName). */
  name: string;
  /** The NetBIOS name of the domain the account belongs to. */
  domain: string;
  /** The security identifier of that domain, in its text form. */
  domainSid: string;
  /** The relative identifier of the account. */
  userId: number;
  /** The relative identifier of the primary group. */
  primaryGroupId: number;
  /** The groups of the account domain, by relative identifier. */
  groups: PacGroup[];
  /** The security identifiers of groups of other domains (ExtraSids). */
  extraSids: string[];
  /** Every group as a security identifier: the domain's groups and the others. */
  sids: string[];
}

// --- the authorization data ------------------------------------------------

/**
 * The PAC within the authorization data of a ticket, or undefined where there
 * is none: "[MS-KILE] also requires that the PAC information be enclosed in an
 * AD-IF-RELEVANT AuthorizationData element, since this information is
 * noncritical authorization data."
 */
export function pacIn(authorizationData: Element[] | undefined): Buffer | undefined {
  if (authorizationData === undefined) return undefined;
  // AuthorizationData ::= SEQUENCE OF SEQUENCE { ad-type [0] Int32, ad-data [1] OCTET STRING },
  // so a list of entries arrives either as the sequence itself or as its members.
  // A list of entries may arrive as the SEQUENCE OF itself or as its members.
  // The two are told apart by what the first child is: an entry begins with
  // its ad-type, which is [0], and the sequence begins with an entry.
  const first = authorizationData.length === 1 && authorizationData[0].tag === 0x30
    ? readAll(authorizationData[0].content)[0]
    : undefined;
  const entries = first !== undefined && first.tag === 0x30
    ? readAll(authorizationData[0].content)
    : authorizationData;
  for (const entry of entries) {
    if (entry.tag !== 0x30) continue;
    const fields = new Map<number, Element>();
    for (const m of readAll(entry.content)) fields.set(m.tag & 0x1f, readOne(m.content));
    const type = fields.get(0);
    const data = fields.get(1);
    if (type === undefined || data === undefined) continue;
    let kind = 0;
    for (const octet of type.content) kind = (kind << 8) | octet;
    // AD-WIN2K-PAC holds the PAC; AD-IF-RELEVANT holds elements to consider in
    // turn, and is where [MS-KILE] requires the PAC to be enclosed. No other
    // element is descended into.
    if (kind === 128) return data.content;
    if (kind === 1) {
      const within = pacIn(readAll(data.content));
      if (within !== undefined) return within;
    }
  }
  return undefined;
}

// --- the buffers -----------------------------------------------------------

export interface PacBuffer { type: number; at: number; length: number; content: Buffer }

/** The buffers of a PAC: "The PAC_INFO_BUFFER array has no defined ordering." */
export function pacBuffers(pac: Buffer): PacBuffer[] {
  if (pac.length < 8) throw new PacError("the PAC is shorter than its header");
  const count = pac.readUInt32LE(0);
  if (pac.readUInt32LE(4) !== 0) throw new PacError("the PAC version is not 0");
  if (count > 64 || 8 + count * 16 > pac.length) throw new PacError("the PAC declares more buffers than it holds");
  const out: PacBuffer[] = [];
  for (let i = 0; i < count; i++) {
    const at = 8 + i * 16;
    const type = pac.readUInt32LE(at);
    const length = pac.readUInt32LE(at + 4);
    const offset = Number(pac.readBigUInt64LE(at + 8));
    if (offset % 8 !== 0) throw new PacError("a PAC buffer does not begin on an eight-octet boundary");
    if (offset + length > pac.length) throw new PacError("a PAC buffer reaches beyond the PAC");
    out.push({ type, at: offset, length, content: pac.subarray(offset, offset + length) });
  }
  return out;
}

/**
 * Verifies the server signature with the key of the service the ticket is
 * for: the hash is taken "of the entire PAC message, with the Signature fields
 * of both PAC_SIGNATURE_DATA structures set to zero". The KDC signature is not
 * verified here, its key being the realm's and not this server's.
 */
export function verifyPacSignature(pac: Buffer, serviceKey: Buffer): void {
  const buffers = pacBuffers(pac);
  const server = buffers.find((b) => b.type === PAC_BUFFER.serverSignature);
  if (server === undefined) throw new PacError("the PAC carries no server signature");
  if (server.length < 4) throw new PacError("the server signature is malformed");
  const type = server.content.readUInt32LE(0);
  const length = SIGNATURE_LENGTH[type];
  if (length === undefined) throw new PacError(`the signature type ${type} is not one this server verifies`);
  if (length !== MAC) throw new PacError(`the signature type ${type} is not of this key`);
  if (server.length < 4 + length) throw new PacError("the server signature is shorter than its type gives");
  const given = Buffer.from(server.content.subarray(4, 4 + length));
  // Every signature is zeroed for the hash, this one and the KDC's.
  const zeroed = Buffer.from(pac);
  for (const b of buffers) {
    if (b.type !== PAC_BUFFER.serverSignature && b.type !== PAC_BUFFER.kdcSignature) continue;
    const size = SIGNATURE_LENGTH[zeroed.readUInt32LE(b.at)] ?? 0;
    zeroed.fill(0, b.at + 4, b.at + 4 + size);
  }
  const wanted = krbChecksum(serviceKey, PAC_CHECKSUM_USAGE, zeroed);
  if (!given.equals(wanted)) throw new PacError("the server signature of the PAC does not verify");
}

// --- the logon information (NDR) -------------------------------------------

/**
 * A reader of the Network Data Representation the logon information is
 * marshalled in ([MS-RPCE]): the fixed part of the structure first, with a
 * referent identifier in place of each pointer, and then the data pointed at,
 * in the order the pointers appeared.
 */
class Ndr {
  private at: number;
  private readonly b: Buffer;
  constructor(b: Buffer, at: number) {
    this.b = b;
    this.at = at;
  }
  align(n: number): void {
    const over = this.at % n;
    if (over !== 0) this.at += n - over;
  }
  u16(): number {
    const v = this.b.readUInt16LE(this.at);
    this.at += 2;
    return v;
  }
  u32(): number {
    this.align(4);
    const v = this.b.readUInt32LE(this.at);
    this.at += 4;
    return v;
  }
  /**
   * A FILETIME: two 32-bit values, so it aligns to four and not to eight
   * ([MS-DTYP]); reading it as a 64-bit value would align it to eight and
   * shift everything after it.
   */
  filetime(): bigint {
    const lo = BigInt(this.u32());
    const hi = BigInt(this.u32());
    return (hi << 32n) | lo;
  }
  skip(n: number): void {
    this.at += n;
  }
  get position(): number {
    return this.at;
  }
  /** A conformant and varying string: its sizes, and then its characters. */
  string(): string {
    const max = this.u32();
    const offset = this.u32();
    const actual = this.u32();
    if (offset !== 0 || actual > max) throw new PacError("a string of the PAC is malformed");
    const start = this.at;
    this.at += actual * 2;
    this.align(4);
    return this.b.subarray(start, start + actual * 2).toString("utf16le").replace(/\0+$/, "");
  }
  /** An RPC_SID: its element count, then the identifier authority and sub-authorities. */
  sid(): string {
    const count = this.u32();
    const revision = this.b[this.at];
    const subAuthorities = this.b[this.at + 1];
    if (revision !== 1 || subAuthorities !== count) throw new PacError("a security identifier of the PAC is malformed");
    let authority = 0;
    for (let i = 0; i < 6; i++) authority = authority * 256 + this.b[this.at + 2 + i];
    this.at += 8;
    const parts: number[] = [];
    for (let i = 0; i < subAuthorities; i++) {
      parts.push(this.b.readUInt32LE(this.at));
      this.at += 4;
    }
    return `S-${revision}-${authority}${parts.map((p) => `-${p}`).join("")}`;
  }
}

/** A pointer field: the referent identifier, zero where the pointer is null. */
interface Referent { id: number }

/**
 * The logon information of a PAC, as much of it as this server uses: the
 * account's name and domain, its groups by relative identifier, and the
 * groups of other domains by security identifier.
 */
export function readLogonInformation(buffer: Buffer): Pac {
  // "The first 8 bytes ... comprise the common RPC header for type
  // marshalling. The next 8 bytes ... comprise the RPC type marshalling
  // private header for constructed types", and then a referent for the
  // pointer to the structure itself.
  // "The next 8 bytes ... comprise the RPC type marshalling private header for
  // constructed types", whose first four hold the length of what follows it.
  if (buffer.length < 24) throw new PacError("the logon information is shorter than its headers");
  const declared = buffer.readUInt32LE(8);
  if (declared + 16 > buffer.length) throw new PacError("the logon information declares more octets than it holds");
  const r = new Ndr(buffer, 0);
  r.skip(20);
  // Six FILETIME values: the times of the logon and of the password.
  for (let i = 0; i < 6; i++) r.filetime();
  /** An RPC_UNICODE_STRING: its length, its maximum, and a referent. */
  const str = (): Referent => {
    r.u16();
    r.u16();
    return { id: r.u32() };
  };
  const effectiveName = str(), fullName = str(), logonScript = str();
  const profilePath = str(), homeDirectory = str(), homeDirectoryDrive = str();
  r.u16(); // LogonCount
  r.u16(); // BadPasswordCount
  const userId = r.u32();
  const primaryGroupId = r.u32();
  const groupCount = r.u32();
  const groupIds: Referent = { id: r.u32() };
  r.u32(); // UserFlags
  r.skip(16); // UserSessionKey
  const logonServer = str(), logonDomainName = str();
  const logonDomainId: Referent = { id: r.u32() };
  r.skip(8); // Reserved1[2]
  r.u32(); // UserAccountControl
  r.u32(); // SubAuthStatus
  r.filetime(); // LastSuccessfulILogon
  r.filetime(); // LastFailedILogon
  r.u32(); // FailedILogonCount
  r.u32(); // Reserved3
  const sidCount = r.u32();
  const extraSids: Referent = { id: r.u32() };
  const resourceGroupDomainSid: Referent = { id: r.u32() };
  const resourceGroupCount = r.u32();
  const resourceGroupIds: Referent = { id: r.u32() };

  // The data pointed at, in the order the pointers appeared.
  const text = (p: Referent) => (p.id === 0 ? "" : r.string());
  const name = text(effectiveName);
  text(fullName);
  text(logonScript);
  text(profilePath);
  text(homeDirectory);
  text(homeDirectoryDrive);
  const groups: PacGroup[] = [];
  if (groupIds.id !== 0) {
    const max = r.u32();
    if (max < groupCount) throw new PacError("the PAC declares more groups than it holds");
    for (let i = 0; i < groupCount; i++) groups.push({ rid: r.u32(), attributes: r.u32() });
  }
  text(logonServer);
  const domain = text(logonDomainName);
  const domainSid = logonDomainId.id === 0 ? "" : r.sid();
  const others: string[] = [];
  if (extraSids.id !== 0) {
    const max = r.u32();
    if (max < sidCount) throw new PacError("the PAC declares more identifiers than it holds");
    // The array of KERB_SID_AND_ATTRIBUTES: a referent and the attributes, and
    // then the identifiers themselves.
    const pointers: number[] = [];
    for (let i = 0; i < sidCount; i++) {
      pointers.push(r.u32());
      r.u32();
    }
    for (const p of pointers) if (p !== 0) others.push(r.sid());
  }
  void resourceGroupDomainSid;
  void resourceGroupCount;
  void resourceGroupIds;
  return {
    name,
    domain,
    domainSid,
    userId,
    primaryGroupId,
    groups,
    extraSids: others,
    // Every group of the principal, as an access control decision names them.
    sids: [...groups.map((g) => `${domainSid}-${g.rid}`), ...others],
  };
}

/** The client name of a PAC (section 2.7), by which the PAC is matched to the ticket. */
export function readClientInformation(buffer: Buffer): { name: string; authtime: number } {
  if (buffer.length < 10) throw new PacError("the client information is malformed");
  // A FILETIME: hundreds of nanoseconds since 1601, which is 11644473600 seconds before 1970.
  const filetime = buffer.readBigUInt64LE(0);
  const authtime = Number(filetime / 10000n) - 11644473600000;
  const length = buffer.readUInt16LE(8);
  if (10 + length > buffer.length) throw new PacError("the client name reaches beyond the buffer");
  return { name: buffer.subarray(10, 10 + length).toString("utf16le"), authtime };
}

/**
 * The groups of a principal from the PAC of its ticket, where it carries one,
 * verified with this service's key. Undefined where the ticket carries none,
 * which leaves the groups to be searched for in the directory.
 */
export function groupsFromPac(authorizationData: Element[] | undefined, serviceKey: Buffer): Pac | undefined {
  const pac = pacIn(authorizationData);
  if (pac === undefined) return undefined;
  verifyPacSignature(pac, serviceKey);
  const logon = pacBuffers(pac).find((b) => b.type === PAC_BUFFER.logonInformation);
  if (logon === undefined) throw new PacError("the PAC carries no logon information");
  return readLogonInformation(logon.content);
}
