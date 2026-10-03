// The Negotiate scheme (PLAN-auth.md, phase 3): what a CDMI server accepts in
// an "Authorization: Negotiate" header field (RFC 4559), which is a GSS-API
// token (RFC 2743) carrying either the Kerberos V5 mechanism of RFC 4121
// directly or SPNEGO (RFC 4178) with that mechanism within it.
//
//   Authorization: Negotiate <base64 of one of>
//     InitialContextToken [APPLICATION 0] { thisMech OID, innerToken }
//       thisMech 1.2.840.113554.1.2.2 (krb5)    innerToken 01 00 || AP-REQ
//       thisMech 1.3.6.1.5.5.2 (SPNEGO)         innerToken NegTokenInit
//                                                 mechToken [2] = the krb5 token above
//     NegTokenResp [1] (a continuation, which this server does not need)
//
// "The innerToken field starts with a two-octet token-identifier (TOK_ID)
// expressed in big-endian order, followed by a Kerberos message", and the
// identifiers are "KRB_AP_REQ 01 00" and "KRB_AP_REP 02 00" (RFC 4121).
//
// Where the client asks for mutual authentication, the answer carries an AP-REP
// in the same shape, which the client verifies with the session key, so that it
// knows it reached the service and not an impostor. The answer goes in
// "WWW-Authenticate: Negotiate", base64 as RFC 4559 provides.

import { encrypt, type Etype } from "./krb-crypto.ts";
import { decodeInteger, encode, encodeInteger, type Element, read, readAll, readOne } from "./der.ts";
import { KrbError, type ReplayCache, USAGE, type Verified, verifyApReq, writeTime } from "./krb-ticket.ts";

/** The mechanisms, by their object identifiers. */
export const OID = { krb5: "1.2.840.113554.1.2.2", spnego: "1.3.6.1.5.5.2" } as const;
export const TOK = { apReq: Buffer.from([0x01, 0x00]), apRep: Buffer.from([0x02, 0x00]) } as const;

const APPLICATION0 = 0x60;
const OBJECT_IDENTIFIER = 0x06;
const SEQUENCE = 0x30;
const OCTET_STRING = 0x04;
const ENUMERATED = 0x0a;
const ctx = (n: number, content: Buffer) => encode(0xa0 | n, content);

/** An object identifier, written in the usual way: the first two arcs in one octet, then base 128. */
export function encodeOid(oid: string): Buffer {
  const arcs = oid.split(".").map(Number);
  const out = [arcs[0] * 40 + arcs[1]];
  for (const arc of arcs.slice(2)) {
    const bytes: number[] = [arc & 0x7f];
    let rest = Math.floor(arc / 128);
    while (rest > 0) {
      bytes.unshift((rest & 0x7f) | 0x80);
      rest = Math.floor(rest / 128);
    }
    out.push(...bytes);
  }
  return encode(OBJECT_IDENTIFIER, Buffer.from(out));
}

export function decodeOid(e: Element): string {
  const b = e.content;
  const arcs = [Math.floor(b[0] / 40), b[0] % 40];
  let value = 0;
  for (const octet of b.subarray(1)) {
    value = value * 128 + (octet & 0x7f);
    if ((octet & 0x80) === 0) {
      arcs.push(value);
      value = 0;
    }
  }
  return arcs.join(".");
}

/** What a Negotiate token carried: the AP-REQ, and whether SPNEGO wrapped it. */
export interface NegotiateToken {
  apReq: Buffer;
  spnego: boolean;
}

/**
 * The AP-REQ a Negotiate token carries, however it is wrapped. A token this
 * server cannot read is refused rather than guessed at.
 */
export function readNegotiate(token: Buffer): NegotiateToken {
  const outer = readOne(token);
  if (outer.tag !== APPLICATION0) {
    // A NegTokenResp, [1], continues an exchange this server does not begin.
    throw new KrbError("KRB_AP_ERR_MSG_TYPE", "the token is not an initial context token");
  }
  // The content is the mechanism's identifier, and then the mechanism's token.
  const { element: oid, next } = read(outer.content, 0);
  if (oid.tag !== OBJECT_IDENTIFIER) throw new KrbError("KRB_AP_ERR_MSG_TYPE", "the initial context token names no mechanism");
  const mech = decodeOid(oid);
  const inner = outer.content.subarray(next);
  if (mech === OID.krb5) return { apReq: krb5Inner(inner), spnego: false };
  if (mech !== OID.spnego) throw new KrbError("KRB_AP_ERR_MSG_TYPE", `the mechanism ${mech} is not supported`);
  // SPNEGO: NegTokenInit [0], whose mechToken [2] holds the mechanism's token.
  const negotiation = readOne(inner);
  if (negotiation.tag !== 0xa0) throw new KrbError("KRB_AP_ERR_MSG_TYPE", "the SPNEGO token is not a NegTokenInit");
  const fields = new Map<number, Element>();
  for (const m of readAll(readOne(negotiation.content).content)) fields.set(m.tag & 0x1f, readOne(m.content));
  const offered = fields.get(0);
  if (offered !== undefined && !readAll(offered.content).some((o) => decodeOid(o) === OID.krb5)) {
    throw new KrbError("KRB_AP_ERR_MSG_TYPE", "the client offers no mechanism this server speaks");
  }
  const mechToken = fields.get(2);
  if (mechToken === undefined) throw new KrbError("KRB_AP_ERR_MSG_TYPE", "the NegTokenInit carries no mechanism token");
  // The mechanism's token is itself an initial context token, as a browser sends it.
  const within = mechToken.content;
  if (within[0] === APPLICATION0) return { apReq: readNegotiate(within).apReq, spnego: true };
  return { apReq: krb5Inner(within), spnego: true };
}

/** A krb5 token's inner part: the two-octet identifier, then the Kerberos message. */
function krb5Inner(inner: Buffer): Buffer {
  if (!inner.subarray(0, 2).equals(TOK.apReq)) {
    throw new KrbError("KRB_AP_ERR_MSG_TYPE", `the token identifier ${inner.subarray(0, 2).toString("hex")} is not that of an AP-REQ`);
  }
  return inner.subarray(2);
}

/** An initial context token for a mechanism (RFC 2743): [APPLICATION 0] { thisMech, innerToken }. */
export const initialContextToken = (oid: string, inner: Buffer): Buffer =>
  encode(APPLICATION0, Buffer.concat([encodeOid(oid), inner]));

/** The krb5 token for an AP-REQ, as a client sends it. */
export const krb5ApReq = (apReq: Buffer): Buffer => initialContextToken(OID.krb5, Buffer.concat([TOK.apReq, apReq]));

/** The same within SPNEGO, as a browser sends it. */
export function spnegoApReq(apReq: Buffer): Buffer {
  const negTokenInit = encode(SEQUENCE, Buffer.concat([
    ctx(0, encode(SEQUENCE, encodeOid(OID.krb5))),
    ctx(2, encode(OCTET_STRING, krb5ApReq(apReq))),
  ]));
  return initialContextToken(OID.spnego, ctx(0, negTokenInit));
}

/**
 * The answer to a client that asked for mutual authentication: an AP-REP, whose
 * encrypted part carries the time of the authenticator, sealed with the session
 * key at key usage 12, wrapped as the request was.
 *
 *   AP-REP ::= [APPLICATION 15] SEQUENCE { pvno [0], msg-type [1] (15), enc-part [2] EncryptedData }
 *   EncAPRepPart ::= [APPLICATION 27] SEQUENCE { ctime [0], cusec [1], subkey [2] OPTIONAL, seq-number [3] OPTIONAL }
 */
export function apRep(verified: Verified, spnego: boolean): Buffer {
  const part = encode(0x60 | 27, encode(SEQUENCE, Buffer.concat([
    ctx(0, encode(0x1b, Buffer.from(writeTime(verified.authenticator.ctime), "utf8"))),
    ctx(1, encodeInteger(verified.authenticator.cusec)),
  ])));
  const sealed = encrypt(verified.sessionKey.value, USAGE.apRepPart, part);
  const message = encode(0x60 | 15, encode(SEQUENCE, Buffer.concat([
    ctx(0, encodeInteger(5)),
    ctx(1, encodeInteger(15)),
    ctx(2, encode(SEQUENCE, Buffer.concat([
      ctx(0, encodeInteger(verified.sessionKey.etype)),
      ctx(2, encode(OCTET_STRING, sealed)),
    ]))),
  ])));
  const krb5 = initialContextToken(OID.krb5, Buffer.concat([TOK.apRep, message]));
  if (!spnego) return krb5;
  // NegTokenResp { negState accept-completed, supportedMech krb5, responseToken }
  return encode(0xa1, encode(SEQUENCE, Buffer.concat([
    ctx(0, encode(ENUMERATED, Buffer.from([0]))),
    ctx(1, encodeOid(OID.krb5)),
    ctx(2, encode(OCTET_STRING, krb5)),
  ])));
}

/** Whether the client asked for mutual authentication: bit 2 of the AP-options (RFC 4120). */
export function mutualRequired(token: Buffer): boolean {
  try {
    const req = readNegotiate(token).apReq;
    const fields = new Map<number, Element>();
    for (const m of readAll(readOne(readOne(req).content).content)) fields.set(m.tag & 0x1f, readOne(m.content));
    const options = fields.get(2);
    if (options === undefined) return false;
    // A BIT STRING: the first octet counts unused bits.
    const flags = options.content.subarray(1);
    return flags.length > 0 && ((flags[0] >> (7 - 2)) & 1) === 1;
  } catch {
    return false;
  }
}

/**
 * Accepts an "Authorization: Negotiate" credential: the principal it
 * authenticates, and the answer for "WWW-Authenticate: Negotiate" where the
 * client asked for mutual authentication.
 */
export function acceptNegotiate(credentials: string, service: { key: Buffer; etype: Etype; names?: string[][] },
  cache: ReplayCache, now = Date.now()): { verified: Verified; answer?: string } {
  let token: Buffer;
  try {
    token = Buffer.from(credentials, "base64");
  } catch {
    throw new KrbError("KRB_AP_ERR_MSG_TYPE", "the credentials are not base64");
  }
  const read = readNegotiate(token);
  const verified = verifyApReq(read.apReq, service, cache, now);
  if (!mutualRequired(token)) return { verified };
  return { verified, answer: apRep(verified, read.spnego).toString("base64") };
}

/** The value of decodeInteger, for a caller that wants it without importing der.ts. */
export const asInteger = (e: Element): number => Number(decodeInteger(e));

// --- per-message tokens (RFC 4121 section 4.2.6.2) ---------------------------
//
// The SASL mechanism of RFC 4752 negotiates its security layer by exchanging
// four octets under GSS_Wrap with confidentiality off, so a Wrap token of that
// form is needed on both sides (PLAN-auth.md, phase 7).
//
//   0..1 TOK_ID 05 04   2 Flags   3 Filler FF   4..5 EC   6..7 RRC
//   8..15 SND_SEQ       16.. plaintext, then the checksum
//
// "In Wrap tokens that do not provide for confidentiality, the checksum SHALL
// be calculated first over the to-be-signed plaintext data, and then over the
// first 16 octets of the Wrap token (the header) ... Both the EC field and the
// RRC field in the token header SHALL be filled with zeroes for the purpose of
// calculating the checksum."

import { checksum as krbChecksum, MAC } from "./krb-crypto.ts";

/** The key usages of RFC 4121 section 2, by who sends the token. */
export const KG = { acceptorSeal: 22, acceptorSign: 23, initiatorSeal: 24, initiatorSign: 25 } as const;
/** The flags of the Wrap header: sent by the acceptor, sealed, and an acceptor subkey. */
export const WRAP_FLAG = { sentByAcceptor: 0x01, sealed: 0x02, acceptorSubkey: 0x04 } as const;

const WRAP_TOK = Buffer.from([0x05, 0x04]);

/**
 * A Wrap token without confidentiality, carrying the plaintext and a checksum.
 * The right rotation count is left at zero, which a receiver undoes trivially.
 */
export function wrapToken(key: Buffer, plaintext: Buffer, opts: { acceptor: boolean; sequence: number }): Buffer {
  const header = Buffer.alloc(16);
  WRAP_TOK.copy(header);
  header[2] = opts.acceptor ? WRAP_FLAG.sentByAcceptor : 0;
  header[3] = 0xff;
  // EC and RRC are zero here, as they are for the checksum.
  header.writeUInt32BE(0, 8);
  header.writeUInt32BE(opts.sequence >>> 0, 12);
  const usage = opts.acceptor ? KG.acceptorSeal : KG.initiatorSeal;
  const mac = krbChecksum(key, usage, Buffer.concat([plaintext, header]));
  return Buffer.concat([header, plaintext, mac]);
}

/** The plaintext of such a token, or an error where it is not one or does not verify. */
export function unwrapToken(key: Buffer, token: Buffer, opts: { acceptor: boolean }): Buffer {
  if (token.length < 16 + MAC || !token.subarray(0, 2).equals(WRAP_TOK)) {
    throw new KrbError("KRB_AP_ERR_MSG_TYPE", "the token is not a Wrap token");
  }
  const header = Buffer.from(token.subarray(0, 16));
  const fromAcceptor = (header[2] & WRAP_FLAG.sentByAcceptor) !== 0;
  if (fromAcceptor !== opts.acceptor) {
    throw new KrbError("KRB_AP_ERR_BADDIRECTION", "the token was sent in the other direction");
  }
  if ((header[2] & WRAP_FLAG.sealed) !== 0) {
    throw new KrbError("KRB_AP_ERR_MSG_TYPE", "the token provides confidentiality, which is not used here");
  }
  const ec = header.readUInt16BE(4), rrc = header.readUInt16BE(6);
  // "the resulting Wrap token ... is rotated to the right by RRC octets", so it is rotated back.
  let body = token.subarray(16);
  if (rrc > 0) {
    const n = rrc % body.length;
    body = Buffer.concat([body.subarray(n), body.subarray(0, n)]);
  }
  if (body.length < MAC + ec) throw new KrbError("KRB_AP_ERR_MSG_TYPE", "the token is shorter than its checksum");
  const plaintext = body.subarray(0, body.length - MAC - ec);
  const given = body.subarray(body.length - MAC);
  // The checksum was taken with EC and RRC zero.
  header.writeUInt16BE(0, 4);
  header.writeUInt16BE(0, 6);
  const usage = fromAcceptor ? KG.acceptorSeal : KG.initiatorSeal;
  const wanted = krbChecksum(key, usage, Buffer.concat([plaintext, header]));
  if (!given.equals(wanted)) throw new KrbError("KRB_AP_ERR_BAD_INTEGRITY", "the checksum of the Wrap token does not verify");
  return plaintext;
}
