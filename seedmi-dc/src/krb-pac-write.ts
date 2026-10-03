// Writing a privilege attribute certificate ([MS-PAC]; PLAN-auth.md, phase 5).
// A realm puts one in each ticket it issues, so that a service learns the
// groups of the principal from the ticket rather than by searching the
// directory: "The PAC was created to provide this authorization data for
// Kerberos Protocol Extensions".
//
// What is written: the logon information (type 1), the client name and the
// time of the initial ticket (type 10), the server signature (type 6), keyed
// with the service's own key, and the KDC signature (type 7), keyed with the
// realm's. What is not: credentials, claims, device information, the ticket
// and extended KDC signatures, and the delegation information of [MS-SFU],
// none of which this realm produces.
//
// The signatures are of the whole PAC with every signature zeroed, at key
// usage 17 (KERB_NON_KERB_CKSUM_SALT), and "The server signature MUST be
// generated AFTER the extended KDC signature", of which there is none here,
// and the KDC signature is of the server signature.

import { checksum as krbChecksum, type Etype, MAC } from "./krb-crypto.ts";
import { PAC_BUFFER, PAC_CHECKSUM_USAGE } from "./krb-pac.ts";

/** The signature type of the AES profiles: HMAC_SHA1_96_AES256 (section 2.8). */
const HMAC_SHA1_96_AES256 = 0x00000010;
const HMAC_SHA1_96_AES128 = 0x0000000f;

/** What the realm knows of a principal, to put in the certificate. */
export interface PacAccount {
  /** The account name, as the directory holds it. */
  name: string;
  /** The NetBIOS name of the domain. */
  domain: string;
  /** The security identifier of the domain, as "S-1-5-21-...". */
  domainSid: string;
  /** The relative identifier of the account. */
  userId: number;
  /** The relative identifier of its primary group. */
  primaryGroupId: number;
  /** The groups of the domain the account belongs to, by relative identifier. */
  groups: number[];
  /** When the initial ticket was issued. */
  authtime: number;
}

const u16 = (v: number) => { const b = Buffer.alloc(2); b.writeUInt16LE(v, 0); return b; };
const u32 = (v: number) => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0, 0); return b; };
/** A FILETIME: hundreds of nanoseconds since 1601, as two 32-bit values. */
const filetime = (ms: number) => {
  const v = BigInt(Math.round(ms + 11644473600000)) * 10000n;
  const b = Buffer.alloc(8);
  b.writeUInt32LE(Number(v & 0xffffffffn), 0);
  b.writeUInt32LE(Number(v >> 32n), 4);
  return b;
};
const pad4 = (b: Buffer) => (b.length % 4 === 0 ? b : Buffer.concat([b, Buffer.alloc(4 - (b.length % 4))]));

/** A conformant and varying string: its sizes, its characters, and padding to four. */
function ndrString(s: string): Buffer {
  const chars = Buffer.from(s, "utf16le");
  const n = s.length;
  return pad4(Buffer.concat([u32(n), u32(0), u32(n), chars]));
}

/** An RPC_SID: the count of sub-authorities, then the identifier itself. */
function ndrSid(sid: string): Buffer {
  const parts = sid.split("-");
  if (parts[0] !== "S" || parts.length < 3) throw new Error(`${sid} is not a security identifier`);
  const revision = Number(parts[1]);
  const authority = Number(parts[2]);
  const subs = parts.slice(3).map(Number);
  const head = Buffer.alloc(8);
  head[0] = revision;
  head[1] = subs.length;
  // The identifier authority: six octets, big-endian.
  for (let i = 0; i < 6; i++) head[7 - i] = (authority / 256 ** i) & 0xff;
  return Buffer.concat([u32(subs.length), head, ...subs.map(u32)]);
}

/** An RPC_UNICODE_STRING in the fixed part: its length, its maximum, and a referent. */
const ndrStringHeader = (s: string, referent: number) =>
  Buffer.concat([u16(s.length * 2), u16(s.length * 2), u32(s === "" ? 0 : referent)]);

/** The logon information (KERB_VALIDATION_INFO), marshalled as [MS-RPCE] gives it. */
export function writeLogonInformation(a: PacAccount): Buffer {
  let referent = 0x00020000;
  const next = () => (referent += 4);
  const names = ["", "", "", "", "", ""]; // the six strings of the account's profile
  names[0] = a.name;
  const groupsReferent = next();
  const domainReferent = next();
  const fixed = Buffer.concat([
    // The common header of type marshalling, the private header, and the
    // referent of the structure itself; the private header's length is filled
    // in at the end.
    Buffer.from([0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc]),
    Buffer.alloc(8),
    u32(0x00020000),
    // LogonTime, LogoffTime, KickOffTime, PasswordLastSet, PasswordCanChange,
    // PasswordMustChange: the times this realm keeps, and "never" for the rest.
    filetime(a.authtime), NEVER, NEVER, filetime(a.authtime), Buffer.alloc(8), NEVER,
    ndrStringHeader(names[0], 0x00030000),
    ndrStringHeader("", 0), ndrStringHeader("", 0), ndrStringHeader("", 0),
    ndrStringHeader("", 0), ndrStringHeader("", 0),
    u16(0), u16(0), // LogonCount, BadPasswordCount
    u32(a.userId), u32(a.primaryGroupId), u32(a.groups.length), u32(groupsReferent),
    u32(0), // UserFlags
    Buffer.alloc(16), // UserSessionKey, zero for Kerberos
    ndrStringHeader("", 0), ndrStringHeader(a.domain, 0x00030004),
    u32(domainReferent),
    Buffer.alloc(8), // Reserved1[2]
    u32(0), // UserAccountControl
    u32(0), // SubAuthStatus
    NEVER, NEVER, // LastSuccessfulILogon, LastFailedILogon
    u32(0), u32(0), // FailedILogonCount, Reserved3
    u32(0), u32(0), // SidCount, ExtraSids: none from this realm
    u32(0), u32(0), u32(0), // ResourceGroupDomainSid, ResourceGroupCount, ResourceGroupIds
  ]);
  // The data pointed at, in the order the pointers appeared.
  const deferred = Buffer.concat([
    ndrString(names[0]),
    // The groups: the count again, then each relative identifier with its
    // attributes, which are mandatory, enabled by default and enabled.
    u32(a.groups.length),
    ...a.groups.map((rid) => Buffer.concat([u32(rid), u32(7)])),
    ndrString(a.domain),
    ndrSid(a.domainSid),
  ]);
  const out = Buffer.concat([fixed, deferred]);
  // The private header holds the length of what follows it.
  out.writeUInt32LE(out.length - 16, 8);
  return out;
}

const NEVER = Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);

/** The client name and the time of the initial ticket (section 2.7). */
export function writeClientInformation(a: PacAccount): Buffer {
  const name = Buffer.from(a.name, "utf16le");
  return Buffer.concat([filetime(a.authtime), u16(name.length), name]);
}

/**
 * A whole PAC for an account, signed with the service's key and the realm's.
 * The buffers are placed on eight-octet boundaries, as section 2.4 requires,
 * and the signatures are computed last, over the PAC with both zeroed.
 */
export function writePac(a: PacAccount, keys: { service: Buffer; kdc: Buffer; etype: Etype }): Buffer {
  const signatureType = keys.etype === 17 ? HMAC_SHA1_96_AES128 : HMAC_SHA1_96_AES256;
  const empty = Buffer.concat([u32(signatureType), Buffer.alloc(MAC)]);
  const parts = [
    { type: PAC_BUFFER.logonInformation, content: writeLogonInformation(a) },
    { type: PAC_BUFFER.clientInformation, content: writeClientInformation(a) },
    { type: PAC_BUFFER.serverSignature, content: Buffer.from(empty) },
    { type: PAC_BUFFER.kdcSignature, content: Buffer.from(empty) },
  ];
  const header = Buffer.concat([u32(parts.length), u32(0)]);
  let at = header.length + parts.length * 16;
  const descriptors: Buffer[] = [];
  const bodies: Buffer[] = [];
  const offsets: number[] = [];
  for (const p of parts) {
    const over = at % 8;
    if (over !== 0) {
      bodies.push(Buffer.alloc(8 - over));
      at += 8 - over;
    }
    offsets.push(at);
    const size = Buffer.alloc(8);
    size.writeBigUInt64LE(BigInt(at), 0);
    descriptors.push(Buffer.concat([u32(p.type), u32(p.content.length), size]));
    bodies.push(p.content);
    at += p.content.length;
  }
  const pac = Buffer.concat([header, ...descriptors, ...bodies]);
  // "The server signature is a keyed hash of the entire PAC message, with the
  // Signature fields of both PAC_SIGNATURE_DATA structures set to zero."
  const server = krbChecksum(keys.service, PAC_CHECKSUM_USAGE, pac);
  server.copy(pac, offsets[2] + 4);
  // "The KDC signature is a keyed hash of the Server Signature field."
  const kdc = krbChecksum(keys.kdc, PAC_CHECKSUM_USAGE, server);
  kdc.copy(pac, offsets[3] + 4);
  return pac;
}
