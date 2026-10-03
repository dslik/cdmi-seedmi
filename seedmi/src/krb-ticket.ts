// Kerberos tickets (PLAN-auth.md, phase 2): the structures of RFC 4120 a
// service needs, and the verification of an AP-REQ with the service's own key.
// A CDMI server authenticating the principals of a domain against the Kerberos
// realm its cdmi_domain_auth item names (revision 282) does this for every
// ticket presented, whether by the Negotiate scheme of the protocol binding
// (phase 3), by SMB, or by the temporary credentials of an S3 export.
//
//   AP-REQ  [APPLICATION 14]  the message a client presents
//     ticket         [APPLICATION 1]   named for this service, encrypted to its key
//       enc-part -> EncTicketPart [APPLICATION 3]  key usage 2
//     authenticator  encrypted to the session key, key usage 11
//       -> Authenticator [APPLICATION 2]
//
// The service decrypts the ticket with its own key, takes the client's name and
// the session key from it, decrypts the authenticator with that session key, and
// checks the times and the replay cache as section 5.5.1 requires.

import { decrypt, encrypt, type Etype } from "./krb-crypto.ts";
import { encode, encodeInteger, decodeInteger, type Element, readAll, readOne } from "./der.ts";

/** The key usages of RFC 4120 section 7.5.1 this module needs. */
export const USAGE = { ticket: 2, authenticator: 11, apRepPart: 12 } as const;

/** The allowable clock skew, five minutes, which section 5.5.1 takes as usual. */
export const SKEW_MS = 5 * 60 * 1000;

const CONTEXT = 0xa0; // context-specific, constructed
const APPLICATION = 0x60; // application, constructed
const SEQUENCE = 0x30;
const GENERAL_STRING = 0x1b;
const OCTET_STRING = 0x04;
const BIT_STRING = 0x03;

export class KrbError extends Error {
  /** The error of RFC 4120 section 5.9.1 this corresponds to, such as KRB_AP_ERR_TKT_EXPIRED. */
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

/** A principal's name: its type, and the components of the name. */
export interface PrincipalName { type: number; parts: string[] }

export interface Ticket {
  realm: string;
  sname: PrincipalName;
  etype: number;
  kvno?: number;
  cipher: Buffer;
}

export interface EncTicketPart {
  flags: Buffer;
  key: { etype: number; value: Buffer };
  crealm: string;
  cname: PrincipalName;
  authtime: number;
  starttime?: number;
  endtime: number;
  /** The authorization data, whose privilege attribute certificate phase 5 reads. */
  authorizationData?: Element[];
  /** The authorization data to write, each an element type and its octets. */
  authorizationDataToWrite?: { type: number; data: Buffer }[];
}

export interface Authenticator {
  crealm: string;
  cname: PrincipalName;
  cusec: number;
  ctime: number;
  subkey?: { etype: number; value: Buffer };
  seqNumber?: number;
}

// --- reading ----------------------------------------------------------------

const context = (n: number) => CONTEXT | n;

/** The members of a SEQUENCE by their context tag numbers. */
function fields(e: Element): Map<number, Element> {
  const out = new Map<number, Element>();
  for (const m of readAll(e.content)) out.set(m.tag & 0x1f, readOne(m.content));
  return out;
}

const need = (f: Map<number, Element>, n: number, what: string): Element => {
  const e = f.get(n);
  if (e === undefined) throw new KrbError("KRB_AP_ERR_MSG_TYPE", `the ${what} is missing`);
  return e;
};

const asInt = (e: Element): number => Number(decodeInteger(e));
const asString = (e: Element): string => e.content.toString("utf8");

/** A KerberosTime, "yyyymmddhhmmssZ", as milliseconds. */
export function readTime(e: Element): number {
  const s = asString(e);
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
  if (m === null) throw new KrbError("KRB_AP_ERR_MSG_TYPE", `${JSON.stringify(s)} is not a KerberosTime`);
  return Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
}

/** The same, written: "yyyymmddhhmmssZ", with no separators. */
export const writeTime = (ms: number): string => new Date(ms).toISOString().replace(/[-:T]|\.\d{3}/g, "");

function readPrincipalName(e: Element): PrincipalName {
  const f = fields(e);
  return { type: asInt(need(f, 0, "name-type")), parts: readAll(need(f, 1, "name-string").content).map((x) => x.content.toString("utf8")) };
}

/** The body of a structure tagged [APPLICATION n], whose content is one SEQUENCE. */
function application(b: Buffer, n: number, what: string): Element {
  const e = readOne(b);
  if (e.tag !== (APPLICATION | n)) throw new KrbError("KRB_AP_ERR_MSG_TYPE", `the message is not ${what}`);
  return readOne(e.content);
}

function readEncryptedData(e: Element): { etype: number; kvno?: number; cipher: Buffer } {
  const f = fields(e);
  const kvno = f.get(1);
  return {
    etype: asInt(need(f, 0, "etype")),
    ...(kvno === undefined ? {} : { kvno: asInt(kvno) }),
    cipher: need(f, 2, "cipher").content,
  };
}

/** An AP-REQ: the ticket and the encrypted authenticator. */
export function readApReq(b: Buffer): { options: Buffer; ticket: Ticket; authenticator: { etype: number; cipher: Buffer } } {
  const f = fields(application(b, 14, "an AP-REQ"));
  if (asInt(need(f, 0, "pvno")) !== 5) throw new KrbError("KRB_AP_ERR_BADVERSION", "the protocol version is not 5");
  if (asInt(need(f, 1, "msg-type")) !== 14) throw new KrbError("KRB_AP_ERR_MSG_TYPE", "the message is not an AP-REQ");
  // The ticket is [APPLICATION 1] within the context tag, and holds one SEQUENCE.
  const t = fields(readOne(need(f, 3, "ticket").content));
  if (asInt(need(t, 0, "tkt-vno")) !== 5) throw new KrbError("KRB_AP_ERR_BADVERSION", "the ticket version is not 5");
  const enc = readEncryptedData(need(t, 3, "enc-part"));
  const auth = readEncryptedData(need(f, 4, "authenticator"));
  return {
    options: need(f, 2, "ap-options").content,
    ticket: { realm: asString(need(t, 1, "realm")), sname: readPrincipalName(need(t, 2, "sname")), ...enc },
    authenticator: { etype: auth.etype, cipher: auth.cipher },
  };
}

export function readEncTicketPart(b: Buffer): EncTicketPart {
  const f = fields(application(b, 3, "an EncTicketPart"));
  const starttime = f.get(6), authz = f.get(10);
  return {
    // A BIT STRING, whose first octet counts the unused bits of the last.
    flags: need(f, 0, "flags").content.subarray(1),
    key: (() => {
      const k = fields(need(f, 1, "key"));
      return { etype: asInt(need(k, 0, "keytype")), value: need(k, 1, "keyvalue").content };
    })(),
    crealm: asString(need(f, 2, "crealm")),
    cname: readPrincipalName(need(f, 3, "cname")),
    authtime: readTime(need(f, 5, "authtime")),
    ...(starttime === undefined ? {} : { starttime: readTime(starttime) }),
    endtime: readTime(need(f, 7, "endtime")),
    ...(authz === undefined ? {} : { authorizationData: readAll(authz.content) }),
  };
}

export function readAuthenticator(b: Buffer): Authenticator {
  const f = fields(application(b, 2, "an Authenticator"));
  if (asInt(need(f, 0, "authenticator-vno")) !== 5) throw new KrbError("KRB_AP_ERR_BADVERSION", "the authenticator version is not 5");
  const subkey = f.get(6), seq = f.get(7);
  return {
    crealm: asString(need(f, 1, "crealm")),
    cname: readPrincipalName(need(f, 2, "cname")),
    cusec: asInt(need(f, 4, "cusec")),
    ctime: readTime(need(f, 5, "ctime")),
    ...(subkey === undefined ? {} : { subkey: (() => {
      const k = fields(subkey);
      return { etype: asInt(need(k, 0, "keytype")), value: need(k, 1, "keyvalue").content };
    })() }),
    ...(seq === undefined ? {} : { seqNumber: asInt(seq) }),
  };
}

// --- writing (for the tests, and for the controller of phase 6) --------------

const tagged = (n: number, content: Buffer) => encode(context(n), content);
const gstring = (s: string) => encode(GENERAL_STRING, Buffer.from(s, "utf8"));
const principalName = (p: PrincipalName) =>
  encode(SEQUENCE, Buffer.concat([tagged(0, encodeInteger(p.type)), tagged(1, encode(SEQUENCE, Buffer.concat(p.parts.map(gstring))))]));
const encryptedData = (etype: number, cipher: Buffer, kvno?: number) =>
  encode(SEQUENCE, Buffer.concat([
    tagged(0, encodeInteger(etype)),
    ...(kvno === undefined ? [] : [tagged(1, encodeInteger(kvno))]),
    tagged(2, encode(OCTET_STRING, cipher)),
  ]));

export function writeEncTicketPart(p: EncTicketPart): Buffer {
  const body = Buffer.concat([
    tagged(0, encode(BIT_STRING, Buffer.concat([Buffer.from([0]), p.flags]))),
    tagged(1, encode(SEQUENCE, Buffer.concat([tagged(0, encodeInteger(p.key.etype)), tagged(1, encode(OCTET_STRING, p.key.value))]))),
    tagged(2, gstring(p.crealm)),
    tagged(3, principalName(p.cname)),
    // transited: an empty encoding, this ticket having crossed no realm.
    tagged(4, encode(SEQUENCE, Buffer.concat([tagged(0, encodeInteger(0)), tagged(1, encode(OCTET_STRING, Buffer.alloc(0)))]))),
    tagged(5, gstring(writeTime(p.authtime))),
    ...(p.starttime === undefined ? [] : [tagged(6, gstring(writeTime(p.starttime)))]),
    tagged(7, gstring(writeTime(p.endtime))),
    // authorization-data [10]: the privilege attribute certificate of a
    // Kerberos realm is carried here ([MS-PAC]; krb-pac.ts).
    ...(p.authorizationDataToWrite === undefined || p.authorizationDataToWrite.length === 0
      ? []
      : [tagged(10, encode(SEQUENCE, Buffer.concat(p.authorizationDataToWrite.map((e) =>
        encode(SEQUENCE, Buffer.concat([tagged(0, encodeInteger(e.type)), tagged(1, encode(OCTET_STRING, e.data))]))))))]),
  ]);
  return encode(APPLICATION | 3, encode(SEQUENCE, body));
}

export function writeAuthenticator(a: Authenticator): Buffer {
  const body = Buffer.concat([
    tagged(0, encodeInteger(5)),
    tagged(1, gstring(a.crealm)),
    tagged(2, principalName(a.cname)),
    tagged(4, encodeInteger(a.cusec)),
    tagged(5, gstring(writeTime(a.ctime))),
    ...(a.subkey === undefined ? [] : [tagged(6, encode(SEQUENCE, Buffer.concat([
      tagged(0, encodeInteger(a.subkey.etype)), tagged(1, encode(OCTET_STRING, a.subkey.value))])))]),
    ...(a.seqNumber === undefined ? [] : [tagged(7, encodeInteger(a.seqNumber))]),
  ]);
  return encode(APPLICATION | 2, encode(SEQUENCE, body));
}

/** An AP-REQ carrying a ticket and an authenticator, for the tests and the controller. */
export function writeApReq(t: { realm: string; sname: PrincipalName; etype: number; cipher: Buffer; kvno?: number },
  authenticator: { etype: number; cipher: Buffer }, options = Buffer.alloc(4)): Buffer {
  const ticket = encode(APPLICATION | 1, encode(SEQUENCE, Buffer.concat([
    tagged(0, encodeInteger(5)),
    tagged(1, gstring(t.realm)),
    tagged(2, principalName(t.sname)),
    tagged(3, encryptedData(t.etype, t.cipher, t.kvno)),
  ])));
  const body = Buffer.concat([
    tagged(0, encodeInteger(5)),
    tagged(1, encodeInteger(14)),
    tagged(2, encode(BIT_STRING, Buffer.concat([Buffer.from([0]), options]))),
    tagged(3, ticket),
    tagged(4, encryptedData(authenticator.etype, authenticator.cipher)),
  ]);
  return encode(APPLICATION | 14, encode(SEQUENCE, body));
}

// --- verifying ---------------------------------------------------------------

/** The name of a principal, as a realm qualifies it: alice@EU.EXAMPLE. */
export const principalOf = (name: PrincipalName, realm: string): string => `${name.parts.join("/")}@${realm}`;

/** An authenticator already seen, by client, time and microsecond (section 5.5.1). */
export class ReplayCache {
  private readonly seen = new Map<string, number>();
  private readonly now: () => number;
  constructor(now: () => number = Date.now) {
    this.now = now;
  }
  /** True where this is the first sight of it; false where it is a replay. */
  first(client: string, ctime: number, cusec: number): boolean {
    const t = this.now();
    for (const [k, when] of this.seen) if (when < t - SKEW_MS) this.seen.delete(k);
    const key = `${client}\u0000${ctime}\u0000${cusec}`;
    if (this.seen.has(key)) return false;
    this.seen.set(key, t);
    return true;
  }
}

export interface Verified {
  /** The principal, qualified by its realm. */
  principal: string;
  crealm: string;
  cname: PrincipalName;
  /** The session key of the ticket, which signs an S3 request and encrypts an AP-REP. */
  sessionKey: { etype: number; value: Buffer };
  /** The subkey the authenticator carried, where it carried one. */
  subkey?: { etype: number; value: Buffer };
  ticket: EncTicketPart;
  authenticator: Authenticator;
}

/**
 * Verifies an AP-REQ with the key of the service it is addressed to (section
 * 5.5.1): the ticket decrypted with that key, the authenticator with the
 * session key the ticket holds, the client of the two the same, the times
 * within the allowable skew, the ticket in date, and the authenticator not a
 * replay.
 */
export function verifyApReq(message: Buffer, service: {
  /** The service's own key, and its encryption type. */
  key: Buffer;
  etype: Etype;
  /** The names this service answers to, as an AP-REQ spells them, or undefined to accept any. */
  names?: string[][];
}, cache: ReplayCache, now = Date.now()): Verified {
  const req = readApReq(message);
  if (service.names !== undefined &&
      !service.names.some((n) => n.length === req.ticket.sname.parts.length && n.every((p, i) => p === req.ticket.sname.parts[i]))) {
    throw new KrbError("KRB_AP_ERR_NOT_US", `the ticket is for ${req.ticket.sname.parts.join("/")}, not this service`);
  }
  let ticket: EncTicketPart;
  try {
    ticket = readEncTicketPart(decrypt(service.key, USAGE.ticket, req.ticket.cipher));
  } catch (e) {
    throw new KrbError("KRB_AP_ERR_BAD_INTEGRITY", `the ticket does not decrypt with this service's key: ${(e as Error).message}`);
  }
  let authenticator: Authenticator;
  try {
    authenticator = readAuthenticator(decrypt(ticket.key.value, USAGE.authenticator, req.authenticator.cipher));
  } catch (e) {
    throw new KrbError("KRB_AP_ERR_BAD_INTEGRITY", `the authenticator does not decrypt with the session key: ${(e as Error).message}`);
  }
  // "the name and realm of the client from the ticket are compared against the
  // same fields in the authenticator" (section 5.5.1).
  if (authenticator.crealm !== ticket.crealm ||
      authenticator.cname.parts.join("/") !== ticket.cname.parts.join("/")) {
    throw new KrbError("KRB_AP_ERR_BADMATCH", "the client of the authenticator is not the client of the ticket");
  }
  const principal = principalOf(ticket.cname, ticket.crealm);
  if (Math.abs(now - authenticator.ctime) > SKEW_MS) {
    throw new KrbError("KRB_AP_ERR_SKEW", "the time of the authenticator is outside the allowable clock skew");
  }
  // "if a matching tuple is found, the KRB_AP_ERR_REPEAT error is returned".
  if (!cache.first(principal, authenticator.ctime, authenticator.cusec)) {
    throw new KrbError("KRB_AP_ERR_REPEAT", "the authenticator has been presented already");
  }
  // "If the starttime is later than the current time by more than the allowable
  // clock skew, or if the INVALID flag is set in the ticket", and expiry.
  if (ticket.starttime !== undefined && ticket.starttime - now > SKEW_MS) {
    throw new KrbError("KRB_AP_ERR_TKT_NYV", "the ticket is not yet valid");
  }
  if (invalidFlag(ticket.flags)) throw new KrbError("KRB_AP_ERR_TKT_NYV", "the ticket is marked invalid");
  if (now - ticket.endtime > SKEW_MS) throw new KrbError("KRB_AP_ERR_TKT_EXPIRED", "the ticket has expired");
  return {
    principal, crealm: ticket.crealm, cname: ticket.cname,
    sessionKey: ticket.key,
    ...(authenticator.subkey === undefined ? {} : { subkey: authenticator.subkey }),
    ticket, authenticator,
  };
}

/** The INVALID flag, bit 5 of the ticket flags, the unused-bits octet already removed (section 5.3). */
const invalidFlag = (flags: Buffer): boolean => flags.length > 0 && ((flags[0] >> (7 - 5)) & 1) === 1;

/** Encrypts a part for a key usage: used by the tests and by the controller of phase 6. */
export const sealed = (key: Buffer, usage: number, part: Buffer): Buffer => encrypt(key, usage, part);
