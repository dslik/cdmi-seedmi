// A key distribution centre (PLAN-auth.md, phase 6): the AS exchange of RFC
// 4120, so that a realm this controller serves issues tickets, and a CDMI
// server verifying one is tested against a ticket it did not make itself.
//
//   AS-REQ  [APPLICATION 10] KDC-REQ    the client asks for a ticket
//     padata [3]   PA-ENC-TIMESTAMP (2), the time encrypted with the client's key
//     req-body [4] cname, realm, sname, till, nonce, etype
//   AS-REP  [APPLICATION 11] KDC-REP    the ticket, and the part for the client
//     ticket   [5] encrypted to the service's key, key usage 2
//     enc-part [6] encrypted to the client's key, key usage 3
//   KRB-ERROR [APPLICATION 30]          where it will not issue one
//
// A client that sends no pre-authentication is answered KDC_ERR_PREAUTH_REQUIRED,
// as a realm requiring it does. The keys come from the passwords of the
// directory, by the string-to-key of RFC 3962 with the usual salt, the realm
// followed by the components of the principal's name.
//
// What is not here: the TGS exchange, renewals, forwarding, and cross-realm
// referrals. An AS-REQ names the service it wants, which suffices to test a
// CDMI server, and the rest is phase 6 of PLAN-dcd.md.

import { writePac } from "./krb-pac-write.ts";
import { randomBytes } from "node:crypto";
import { decrypt, encrypt, ETYPE, type Etype, keySize, stringToKey } from "./krb-crypto.ts";
import { decodeInteger, encode, encodeInteger, type Element, readAll, readOne } from "./der.ts";
import { type PrincipalName, readTime, SKEW_MS, USAGE, writeEncTicketPart, writeTime } from "./krb-ticket.ts";

export { KDC_ERR, KdcRefusal, asReq, readAsRep, saltOf, serviceTicket, ticketParts } from "./krb-client.ts";
import { KDC_ERR, KdcRefusal, PA_ENC_TIMESTAMP, saltOf } from "./krb-client.ts";

const ctx = (n: number, content: Buffer) => encode(0xa0 | n, content);
const app = (n: number, content: Buffer) => encode(0x60 | n, content);
const SEQUENCE = 0x30;
const OCTET_STRING = 0x04;
const GENERAL_STRING = 0x1b;
const BIT_STRING = 0x03;
const gstring = (s: string) => encode(GENERAL_STRING, Buffer.from(s, "utf8"));
const principalName = (p: PrincipalName) =>
  encode(SEQUENCE, Buffer.concat([ctx(0, encodeInteger(p.type)), ctx(1, encode(SEQUENCE, Buffer.concat(p.parts.map(gstring))))]));

function fields(e: Element): Map<number, Element> {
  const out = new Map<number, Element>();
  for (const m of readAll(e.content)) out.set(m.tag & 0x1f, readOne(m.content));
  return out;
}
const asInt = (e: Element): number => Number(decodeInteger(e));
const readPrincipalName = (e: Element): PrincipalName => {
  const f = fields(e);
  return { type: asInt(f.get(0)!), parts: readAll(f.get(1)!.content).map((x) => x.content.toString("utf8")) };
};

/**
 * A principal of the realm: its name, and either the password its key is made
 * from or the keys themselves. A configuration gives a password; a store gives
 * keys, read from the key management server, because once a password has been
 * written through the administrative interface no cleartext of it is kept
 * (DESIGN-admin.md §3). One of the two is given.
 */
export interface KdcPrincipal {
  /** The components of the name: ["alice"], or ["HTTP", "cdmi.eu.example"]. */
  parts: string[];
  password?: string;
  /** The long-term keys of the principal, by enctype, where they are held. */
  keys?: { etype: number; key: Buffer }[];
  type?: number;
  /** The relative identifier of the principal within the domain ([MS-PAC]). */
  rid?: number;
  /** The relative identifiers of the groups it belongs to. */
  groups?: number[];
}

export interface KdcConfig {
  realm: string;
  /** The security identifier of the domain, which a certificate carries. */
  domainSid?: string;
  /** The NetBIOS name of the domain, as the certificate reports it. */
  netbios?: string;
  principals: KdcPrincipal[];
  /** How long a ticket lasts, in seconds. */
  lifetime: number;
  etype: Etype;
  /**
   * Whether a name is a principal of this realm whose Kerberos keys could not be
   * read — the key server is away, or the material is gone. Such a principal is
   * **not** in `principals`, since there is no key to issue a ticket with, and
   * answering `C_PRINCIPAL_UNKNOWN` would tell an operator the principal does not
   * exist and send them to look for a typo. `DESIGN-admin.md` §4 recorded that as
   * the wrong answer and left it open; this is how it is told apart.
   */
  keysUnavailable?: (name: string) => boolean;
}

/**
 * The key of a principal: the one held for the enctype this realm issues, or one
 * made from the password where a password is what is held. A principal with
 * neither is refused rather than answered with a key made from nothing, since a
 * key made from nothing would decrypt no pre-authentication and the client would
 * be told the wrong thing.
 */
export const keyOf = (config: KdcConfig, p: KdcPrincipal): Buffer => {
  const held = p.keys?.find((k) => k.etype === config.etype);
  if (held !== undefined) return held.key;
  if (p.password === undefined) {
    throw new KdcRefusal(KDC_ERR.ETYPE_NOSUPP,
      `no key of enctype ${config.etype} is held for ${p.parts.join("/")}`);
  }
  return stringToKey(p.password, saltOf(config.realm, p.parts), config.etype);
};

/** A KRB-ERROR, which a client reads to learn why it was refused. */
export function krbError(config: KdcConfig, code: number, text: string, sname: PrincipalName, now: number): Buffer {
  return app(30, encode(SEQUENCE, Buffer.concat([
    ctx(0, encodeInteger(5)),
    ctx(1, encodeInteger(30)),
    ctx(4, gstring(writeTime(now))),
    ctx(5, encodeInteger(0)),
    ctx(6, encodeInteger(code)),
    ctx(9, gstring(config.realm)),
    ctx(10, principalName(sname)),
    ctx(11, gstring(text)),
  ])));
}

/**
 * Answers an AS-REQ: the ticket for the service it names, encrypted to that
 * service's key, and the part for the client, encrypted to the client's key.
 * Throws a KdcRefusal where it will not, which the caller turns into a KRB-ERROR.
 */
/**
 * The key of the realm, with which the KDC signature of a certificate is
 * made. A Windows realm uses the key of the krbtgt account; this controller
 * derives one from the realm and its domain identifier, since no party but
 * this controller verifies that signature.
 */
function realmKey(config: KdcConfig): Buffer {
  return stringToKey(`krbtgt\u0000${config.domainSid ?? ""}`, saltOf(config.realm, ["krbtgt", config.realm]), config.etype);
}

export function answerAsReq(config: KdcConfig, message: Buffer, now = Date.now(),
  sessionKey = randomBytes(keySize(config.etype))): Buffer {
  const outer = readOne(message);
  if (outer.tag !== (0x60 | 10)) throw new KdcRefusal(KDC_ERR.PREAUTH_FAILED, "the message is not an AS-REQ");
  const f = fields(readOne(outer.content));
  if (asInt(f.get(1)!) !== 5) throw new KdcRefusal(KDC_ERR.PREAUTH_FAILED, "the protocol version is not 5");
  if (asInt(f.get(2)!) !== 10) throw new KdcRefusal(KDC_ERR.PREAUTH_FAILED, "the message type is not that of an AS-REQ");
  const body = fields(f.get(4)!);
  const realm = body.get(2)!.content.toString("utf8");
  if (realm !== config.realm) throw new KdcRefusal(KDC_ERR.C_PRINCIPAL_UNKNOWN, `${realm} is not this realm`);
  const cname = readPrincipalName(body.get(1)!);
  const sname = readPrincipalName(body.get(3)!);
  const nonce = asInt(body.get(7)!);
  const till = readTime(body.get(5)!);
  const etypes = readAll(body.get(8)!.content).map((e) => Number(decodeInteger(e)));
  if (!etypes.includes(config.etype)) {
    throw new KdcRefusal(KDC_ERR.ETYPE_NOSUPP, `this realm issues ${config.etype}, which the client does not ask for`);
  }
  const client = find(config, cname.parts);
  if (client === undefined) {
    // A principal that exists and whose key cannot be read now is a different
    // refusal from one that does not exist. The code is still
    // C_PRINCIPAL_UNKNOWN — RFC 4120's KDC_ERR table has none for "this realm
    // cannot reach its key store", and KDC_ERR_SVC_UNAVAILABLE (29) is about the
    // service rather than its keys — but the e-text a KRB-ERROR carries says which,
    // and so does the log. A wrong code with a true reason beats a wrong code with
    // a false one. Noted in NOTES-on-ldap.md as an answer still worth improving if
    // RFC 4120 offers something better.
    const name = cname.parts.join("/");
    throw new KdcRefusal(KDC_ERR.C_PRINCIPAL_UNKNOWN,
      config.keysUnavailable?.(name) === true
        ? `${name} is a principal of this realm whose Kerberos keys could not be read: the key ` +
          "management server is away or the key material is gone, and no ticket can be issued " +
          "until it is reachable. The principal exists."
        : `${name} is not a principal of this realm`);
  }
  const server = find(config, sname.parts);
  if (server === undefined) throw new KdcRefusal(KDC_ERR.S_PRINCIPAL_UNKNOWN, `${sname.parts.join("/")} is not a service of this realm`);
  const clientKey = keyOf(config, client);

  // "pa-enc-timestamp DER encoding of PA-ENC-TIMESTAMP": the time, encrypted
  // with the client's key at key usage 1. Where none is sent, the client is
  // told that this realm requires it.
  const padata = f.get(3);
  const stamp = padata === undefined ? undefined : readAll(padata.content).map(fields)
    .find((p) => asInt(p.get(1)!) === PA_ENC_TIMESTAMP);
  if (stamp === undefined) throw new KdcRefusal(KDC_ERR.PREAUTH_REQUIRED, "this realm requires pre-authentication");
  const encrypted = fields(readOne(stamp.get(2)!.content));
  let patimestamp: number;
  try {
    const opened = readOne(decrypt(clientKey, 1, encrypted.get(2)!.content));
    patimestamp = readTime(fields(opened).get(0)!);
  } catch {
    throw new KdcRefusal(KDC_ERR.PREAUTH_FAILED, "the pre-authentication does not decrypt with the principal's key");
  }
  if (Math.abs(now - patimestamp) > SKEW_MS) throw new KdcRefusal(KDC_ERR.SKEW, "the time of the pre-authentication is outside the skew");

  // The ticket, for the service, and the part for the client.
  const endtime = Math.min(till, now + config.lifetime * 1000);
  // The privilege attribute certificate, where the realm knows the identifiers
  // of the principal: "The PAC was created to provide this authorization data"
  // ([MS-PAC]; PLAN-auth.md, phase 5). It is enclosed in AD-IF-RELEVANT, as
  // [MS-KILE] requires, and signed with the service's key and the realm's.
  const pac = config.domainSid === undefined || client.rid === undefined
    ? undefined
    : writePac({
      name: cname.parts.join("/"),
      domain: config.netbios ?? config.realm.split(".")[0],
      domainSid: config.domainSid,
      userId: client.rid,
      primaryGroupId: client.groups?.[0] ?? client.rid,
      groups: client.groups ?? [],
      authtime: now,
    }, { service: keyOf(config, server), kdc: realmKey(config), etype: config.etype });
  const ticketPart = writeEncTicketPart({
    // Bit 0 is reserved; the ticket is initial, bit 1 (RFC 4120 section 5.3).
    flags: Buffer.from([0x40, 0, 0, 0]),
    key: { etype: config.etype, value: sessionKey },
    crealm: config.realm, cname,
    authtime: now, starttime: now, endtime,
    ...(pac === undefined ? {} : {
      authorizationDataToWrite: [{
        type: 1, // AD-IF-RELEVANT
        data: encode(SEQUENCE, encode(SEQUENCE, Buffer.concat([
          ctx(0, encodeInteger(128)), // AD-WIN2K-PAC
          ctx(1, encode(OCTET_STRING, pac)),
        ]))),
      }],
    }),
  });
  const ticket = app(1, encode(SEQUENCE, Buffer.concat([
    ctx(0, encodeInteger(5)),
    ctx(1, gstring(config.realm)),
    ctx(2, principalName(sname)),
    ctx(3, encryptedData(config.etype, encrypt(keyOf(config, server), USAGE.ticket, ticketPart))),
  ])));
  // EncASRepPart [APPLICATION 25]: the session key, the times, and the service it is for.
  const encPart = app(25, encode(SEQUENCE, Buffer.concat([
    ctx(0, encode(SEQUENCE, Buffer.concat([ctx(0, encodeInteger(config.etype)), ctx(1, encode(OCTET_STRING, sessionKey))]))),
    ctx(1, encode(SEQUENCE, Buffer.alloc(0))),
    ctx(2, encodeInteger(nonce)),
    ctx(4, encode(BIT_STRING, Buffer.from([0, 0x40, 0, 0, 0]))),
    ctx(5, gstring(writeTime(now))),
    ctx(6, gstring(writeTime(now))),
    ctx(7, gstring(writeTime(endtime))),
    ctx(9, gstring(config.realm)),
    ctx(10, principalName(sname)),
  ])));
  return app(11, encode(SEQUENCE, Buffer.concat([
    ctx(0, encodeInteger(5)),
    ctx(1, encodeInteger(11)),
    ctx(3, gstring(config.realm)),
    ctx(4, principalName(cname)),
    ctx(5, ticket),
    ctx(6, encryptedData(config.etype, encrypt(clientKey, 3, encPart))),
  ])));
}

const encryptedData = (etype: number, cipher: Buffer) =>
  encode(SEQUENCE, Buffer.concat([ctx(0, encodeInteger(etype)), ctx(2, encode(OCTET_STRING, cipher))]));

const find = (config: KdcConfig, parts: string[]): KdcPrincipal | undefined =>
  config.principals.find((p) => p.parts.length === parts.length && p.parts.every((x, i) => x.toLowerCase() === parts[i].toLowerCase()));

/** Answers a request, a KRB-ERROR where it is refused: what the listener writes back. */
export function answer(config: KdcConfig, message: Buffer, now = Date.now()): Buffer {
  try {
    return answerAsReq(config, message, now);
  } catch (e) {
    const refusal = e instanceof KdcRefusal ? e : new KdcRefusal(KDC_ERR.PREAUTH_FAILED, (e as Error).message);
    let sname: PrincipalName = { type: 1, parts: ["krbtgt", config.realm] };
    try {
      sname = readPrincipalName(fields(fields(readOne(readOne(message).content)).get(4)!).get(3)!);
    } catch { /* the request could not be read that far */ }
    return krbError(config, refusal.code, refusal.message, sname, now);
  }
}

