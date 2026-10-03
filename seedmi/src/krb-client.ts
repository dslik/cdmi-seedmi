// The client side of the AS exchange (RFC 4120), shared by the reference
// controller and by a CDMI server that must obtain a ticket of its own: to bind
// to a directory by the SASL mechanism of RFC 4752, a CDMI server presents a
// ticket for that directory's service principal (PLAN-auth.md, phase 7).

import { connect as netConnect } from "node:net";
import { decrypt, encrypt, ETYPE, type Etype } from "./krb-crypto.ts";
import { decodeInteger, encode, encodeInteger, type Element, readAll, readOne } from "./der.ts";
import { type PrincipalName, readTime, writeTime } from "./krb-ticket.ts";

/** The error codes of RFC 4120 section 7.5.9 a client is told. */
export const KDC_ERR = {
  C_PRINCIPAL_UNKNOWN: 6,
  S_PRINCIPAL_UNKNOWN: 7,
  PREAUTH_FAILED: 24,
  PREAUTH_REQUIRED: 25,
  ETYPE_NOSUPP: 14,
  SKEW: 37,
} as const;

/** The pre-authentication type of an encrypted timestamp. */
export const PA_ENC_TIMESTAMP = 2;

export class KdcRefusal extends Error {
  readonly code: number;
  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

/** The salt of the string-to-key: the realm, then the components of the name (RFC 4120 section 4). */
export const saltOf = (realm: string, parts: string[]): string => realm + parts.join("");

const ctx = (n: number, content: Buffer) => encode(0xa0 | n, content);
const app = (n: number, content: Buffer) => encode(0x60 | n, content);
const SEQUENCE = 0x30;
const OCTET_STRING = 0x04;
const GENERAL_STRING = 0x1b;
const BIT_STRING = 0x03;
const gstring = (s: string) => encode(GENERAL_STRING, Buffer.from(s, "utf8"));
const principalName = (p: PrincipalName) =>
  encode(SEQUENCE, Buffer.concat([ctx(0, encodeInteger(p.type)), ctx(1, encode(SEQUENCE, Buffer.concat(p.parts.map(gstring))))]));
const encryptedData = (etype: number, cipher: Buffer) =>
  encode(SEQUENCE, Buffer.concat([ctx(0, encodeInteger(etype)), ctx(2, encode(OCTET_STRING, cipher))]));

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
void readPrincipalName;


/** An AS-REQ for a service, with the pre-authentication a realm requires. */
export function asReq(realm: string, cname: PrincipalName, sname: PrincipalName, clientKey: Buffer, opts: {
  now?: number; till?: number; nonce?: number; etype?: Etype; preauth?: boolean;
} = {}): Buffer {
  const now = opts.now ?? Date.now();
  const etype = opts.etype ?? ETYPE.aes256;
  // PA-ENC-TS-ENC ::= SEQUENCE { patimestamp [0] KerberosTime, pausec [1] Microseconds OPTIONAL }
  const tsEnc = encode(SEQUENCE, Buffer.concat([ctx(0, gstring(writeTime(now))), ctx(1, encodeInteger(0))]));
  const padata = opts.preauth === false ? [] : [encode(SEQUENCE, Buffer.concat([
    ctx(1, encodeInteger(PA_ENC_TIMESTAMP)),
    ctx(2, encode(OCTET_STRING, encryptedData(etype, encrypt(clientKey, 1, tsEnc)))),
  ]))];
  const body = encode(SEQUENCE, Buffer.concat([
    ctx(0, encode(BIT_STRING, Buffer.from([0, 0, 0, 0, 0]))),
    ctx(1, principalName(cname)),
    ctx(2, gstring(realm)),
    ctx(3, principalName(sname)),
    ctx(5, gstring(writeTime(opts.till ?? now + 8 * 3600_000))),
    ctx(7, encodeInteger(opts.nonce ?? 1)),
    ctx(8, encode(SEQUENCE, encodeInteger(etype))),
  ]));
  return app(10, encode(SEQUENCE, Buffer.concat([
    ctx(1, encodeInteger(5)),
    ctx(2, encodeInteger(10)),
    ...(padata.length === 0 ? [] : [ctx(3, encode(SEQUENCE, Buffer.concat(padata)))]),
    ctx(4, body),
  ])));
}

/** The parts of a ticket a client needs to put it in an AP-REQ. */
export function ticketParts(ticket: Buffer): { realm: string; sname: PrincipalName; etype: number; cipher: Buffer } {
  const t = fields(readOne(readOne(ticket).content));
  const enc = fields(t.get(3)!);
  return {
    realm: t.get(1)!.content.toString("utf8"),
    sname: readPrincipalName(t.get(2)!),
    etype: asInt(enc.get(0)!),
    cipher: enc.get(2)!.content,
  };
}

/** What an AS-REP gives a client: the ticket to present, and the session key within it. */
export function readAsRep(message: Buffer, clientKey: Buffer): { ticket: Buffer; sessionKey: Buffer; endtime: number } {
  const outer = readOne(message);
  if (outer.tag === (0x60 | 30)) {
    const e = fields(readOne(outer.content));
    throw new KdcRefusal(asInt(e.get(6)!), (e.get(11)?.content ?? Buffer.from("refused")).toString("utf8"));
  }
  if (outer.tag !== (0x60 | 11)) throw new Error("the message is not an AS-REP");
  const f = fields(readOne(outer.content));
  const encPart = fields(f.get(6)!);
  // EncASRepPart [APPLICATION 25], and then the SEQUENCE within it.
  const part = fields(readOne(readOne(decrypt(clientKey, 3, encPart.get(2)!.content)).content));
  const key = fields(part.get(0)!);
  return {
    // The ticket as it stands, [APPLICATION 1] and its content, to put in an AP-REQ.
    ticket: encode(0x61, f.get(5)!.content),
    sessionKey: key.get(1)!.content,
    endtime: readTime(part.get(7)!),
  };
}

/**
 * A ticket for a service of a realm, by an AS exchange with its key
 * distribution centre over TCP: each message is prefixed by its length in four
 * octets (RFC 4120 section 7.2.2).
 */
export function serviceTicket(kdc: string, realm: string, client: PrincipalName, service: PrincipalName,
  clientKey: Buffer, timeoutMs = 5000): Promise<{ ticket: Buffer; sessionKey: Buffer; endtime: number }> {
  const [host, port] = splitHostPort(kdc);
  const message = asReq(realm, client, service, clientKey);
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = (f: () => void) => { if (!done) { done = true; f(); socket.end(); } };
    const socket = netConnect({ host, port }, () => {
      const length = Buffer.alloc(4);
      length.writeUInt32BE(message.length, 0);
      socket.write(Buffer.concat([length, message]));
    });
    socket.setTimeout(timeoutMs, () => finish(() => reject(new Error(`the key distribution centre at ${kdc} did not answer in time`))));
    socket.on("error", (e: Error) => finish(() => reject(new Error(`the key distribution centre at ${kdc} cannot be reached: ${e.message}`))));
    let held = Buffer.alloc(0);
    socket.on("data", (d: Buffer) => {
      held = Buffer.concat([held, d]);
      if (held.length < 4 || held.length < 4 + held.readUInt32BE(0)) return;
      const reply = held.subarray(4, 4 + held.readUInt32BE(0));
      finish(() => {
        try {
          resolve(readAsRep(reply, clientKey));
        } catch (e) {
          reject(e as Error);
        }
      });
    });
  });
}

/** "host:port", the port being 88 where none is given. */
export function splitHostPort(at: string): [string, number] {
  const m = /^\[([^\]]+)\](?::(\d+))?$|^([^:]+)(?::(\d+))?$/.exec(at);
  if (m === null) throw new Error(`${JSON.stringify(at)} is not a host and port`);
  return [m[1] ?? m[3], Number(m[2] ?? m[4] ?? 88)];
}
