// TSIG: the shared-key authentication a name server requires of a dynamic
// update (RFC 8945).
//
// An update that writes a real zone is a write anyone on the path would like to
// make, so it is signed, and the answer is verified. Verifying the answer is
// not optional politeness: an unverified "the update succeeded" is a spoofable
// claim, and this program's whole job is to believe what it is told about a
// zone and act on it.
//
// What is signed is the message before the TSIG record joins it, followed by
// the variable parts of that record — the key name, class, lifetime, algorithm,
// the time and the fudge, the error and any other data — but not the MAC
// itself, the MAC size, or the original identifier. Names within that run are
// written in canonical form: lower case and never compressed.

import { createHmac, timingSafeEqual } from "node:crypto";
import {
  CLASS, decodeMessage, encodeMessage, labels, type Message, type Name, presentation, type ResourceRecord,
  sameName, TYPE,
} from "./dns.ts";

export class TsigError extends Error {}

/** The algorithms this program signs with, by the name that travels in the record. */
export const ALGORITHMS: Record<string, string> = {
  "hmac-sha256": "sha256",
  "hmac-sha384": "sha384",
  "hmac-sha512": "sha512",
  "hmac-sha1": "sha1",
};

export interface TsigKey {
  /** The key name, as the name server knows it. */
  name: Name;
  /** One of ALGORITHMS. */
  algorithm: string;
  /** The shared secret, base64 as a name server's configuration writes it. */
  secret: Uint8Array;
  /** How far apart the clocks may be, in seconds. */
  fudgeSeconds?: number;
}

/** The TSIG error codes, which travel in the record rather than in the header. */
export const TSIG_ERROR: Record<number, string> = {
  0: "no error", 16: "the signature did not verify", 17: "the key is not known",
  18: "the time signed is outside the fudge",
};

const canonical = (name: Name): Uint8Array => {
  const out: number[] = [];
  for (const label of name) {
    const octets = new TextEncoder().encode(label.toLowerCase());
    out.push(octets.length, ...octets);
  }
  out.push(0);
  return new Uint8Array(out);
};

const u16 = (v: number): number[] => [(v >> 8) & 0xff, v & 0xff];
const u48 = (v: number): number[] => [
  Math.floor(v / 0x10000000000) & 0xff, Math.floor(v / 0x100000000) & 0xff,
  (v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff,
];

/**
 * The variable parts of a TSIG record, as the digest takes them: the record's
 * owner name, class and lifetime, then the algorithm, the time, the fudge, the
 * error and the other data. The MAC, its size and the original identifier are
 * not among them.
 */
function tsigVariables(key: TsigKey, timeSigned: number, fudge: number,
  error = 0, other: Uint8Array = new Uint8Array(0)): Uint8Array {
  return new Uint8Array([
    ...canonical(key.name),
    ...u16(CLASS.ANY),
    0, 0, 0, 0,
    ...canonical(labels(key.algorithm)),
    ...u48(timeSigned),
    ...u16(fudge),
    ...u16(error),
    ...u16(other.length),
    ...other,
  ]);
}

const digestOf = (key: TsigKey, parts: Uint8Array[]): Uint8Array => {
  const hash = ALGORITHMS[key.algorithm];
  if (hash === undefined) throw new TsigError(`${key.algorithm} is not an algorithm this program signs with`);
  const h = createHmac(hash, Buffer.from(key.secret));
  for (const p of parts) h.update(Buffer.from(p));
  return new Uint8Array(h.digest());
};

export interface Signed {
  bytes: Uint8Array;
  /** Kept to verify the answer, which signs the request's MAC before its own message. */
  mac: Uint8Array;
  timeSigned: number;
}

/** Signs a message, returning the bytes to send with the TSIG record appended. */
export function sign(m: Message, key: TsigKey, now = Math.floor(Date.now() / 1000)): Signed {
  const fudge = key.fudgeSeconds ?? 300;
  const body = encodeMessage(m);
  const mac = digestOf(key, [body, tsigVariables(key, now, fudge)]);
  const record: ResourceRecord = {
    name: key.name, type: TYPE.TSIG, class: CLASS.ANY, ttl: 0,
    data: {
      kind: "TSIG", algorithm: labels(key.algorithm), timeSigned: now, fudge, mac,
      originalID: m.id, error: 0, other: new Uint8Array(0),
    },
  };
  return {
    bytes: encodeMessage({ ...m, additional: [...m.additional, record] }),
    mac,
    timeSigned: now,
  };
}

export interface Verified {
  message: Message;
  /** The TSIG error the answer carried, 0 where it carried none. */
  error: number;
}

/**
 * Verifies the TSIG of an answer against the request's MAC, and returns the
 * message with the record removed.
 *
 * A name server that could not verify our signature answers with a TSIG whose
 * MAC is empty and whose error says why; that answer cannot be verified and is
 * reported by its error rather than treated as a forgery.
 */
export function verify(bytes: Uint8Array, key: TsigKey, requestMac: Uint8Array,
  now = Math.floor(Date.now() / 1000)): Verified {
  const m = decodeMessage(bytes);
  const last = m.additional[m.additional.length - 1];
  if (last === undefined || last.type !== TYPE.TSIG) {
    throw new TsigError("the answer carries no TSIG record, and this program signs every request");
  }
  if (!sameName(last.name, key.name)) {
    throw new TsigError(`the answer is signed under ${presentation(last.name)}, not ${presentation(key.name)}`);
  }
  if (last.data.kind !== "TSIG") throw new TsigError("the TSIG record does not parse");
  const t = last.data;
  const stripped: Message = { ...m, additional: m.additional.slice(0, -1) };
  if (t.error !== 0) {
    // The name server is telling us why it refused, not answering our question.
    return { message: stripped, error: t.error };
  }
  if (Math.abs(now - t.timeSigned) > t.fudge) {
    throw new TsigError(`the answer was signed ${Math.abs(now - t.timeSigned)} seconds from now, ` +
      `and the fudge is ${t.fudge}`);
  }
  // The identifier travels in the record so that a forwarder may rewrite the
  // header's; the digest is taken over the message as it was signed.
  const body = encodeMessage({ ...stripped, id: t.originalID });
  const expected = digestOf(key, [
    new Uint8Array([...u16(requestMac.length), ...requestMac]),
    body,
    tsigVariables({ ...key, algorithm: presentation(t.algorithm) }, t.timeSigned, t.fudge, t.error, t.other),
  ]);
  const got = t.mac;
  if (got.length !== expected.length ||
      !timingSafeEqual(got, expected)) {
    throw new TsigError("the answer's signature does not verify");
  }
  return { message: stripped, error: 0 };
}
