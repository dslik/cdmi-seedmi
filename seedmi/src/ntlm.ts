/**
 * NTLMSSP, the authentication a client of an SMB export presents where
 * Kerberos is not in use, as [MS-NLMP] defines it.
 *
 * Two primitives are written out here. The NT hash is MD4 of the
 * password as UTF-16LE, and MD4 is not offered by the cryptography
 * library of this runtime, whose provider withdrew it. Key exchange
 * encrypts the session key with RC4, which was withdrawn with it.
 * Neither is used for confidentiality: MD4 forms a hash the protocol
 * defines, and RC4 covers a key already protected by the transport
 * where the transport protects anything.
 */

import { createHmac, randomBytes } from "node:crypto";
import { utf16 } from "./smb-wire.ts";

// ---------------------------------------------------------------------------
// MD4, RFC 1320

const rotl = (x: number, n: number): number => ((x << n) | (x >>> (32 - n))) >>> 0;

/** The digest of RFC 1320, sixteen octets. */
export function md4(data: Uint8Array): Buffer {
  // The message is padded with a one bit, then zeroes, then the length
  // in bits as a 64-bit little-endian quantity.
  const bits = BigInt(data.length) * 8n;
  const padded = Buffer.alloc(((data.length + 8) >> 6 << 6) + 64);
  Buffer.from(data).copy(padded, 0);
  padded[data.length] = 0x80;
  padded.writeBigUInt64LE(bits, padded.length - 8);

  let [a, b, c, d] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
  const x = new Array<number>(16);
  for (let at = 0; at < padded.length; at += 64) {
    for (let i = 0; i < 16; i++) x[i] = padded.readUInt32LE(at + i * 4);
    const [aa, bb, cc, dd] = [a, b, c, d];

    // Round one: F(x, y, z) = (x & y) | (~x & z).
    const f = (p: number, q: number, r: number) => (p & q) | (~p & r);
    const r1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const s1 = [3, 7, 11, 19];
    for (let i = 0; i < 16; i++) {
      const s = s1[i % 4];
      if (i % 4 === 0) a = rotl((a + f(b, c, d) + x[r1[i]]) >>> 0, s);
      else if (i % 4 === 1) d = rotl((d + f(a, b, c) + x[r1[i]]) >>> 0, s);
      else if (i % 4 === 2) c = rotl((c + f(d, a, b) + x[r1[i]]) >>> 0, s);
      else b = rotl((b + f(c, d, a) + x[r1[i]]) >>> 0, s);
    }

    // Round two: G(x, y, z) = (x & y) | (x & z) | (y & z), constant 0x5a827999.
    const g = (p: number, q: number, r: number) => (p & q) | (p & r) | (q & r);
    const r2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
    const s2 = [3, 5, 9, 13];
    for (let i = 0; i < 16; i++) {
      const s = s2[i % 4];
      const k = (x[r2[i]] + 0x5a827999) >>> 0;
      if (i % 4 === 0) a = rotl((a + g(b, c, d) + k) >>> 0, s);
      else if (i % 4 === 1) d = rotl((d + g(a, b, c) + k) >>> 0, s);
      else if (i % 4 === 2) c = rotl((c + g(d, a, b) + k) >>> 0, s);
      else b = rotl((b + g(c, d, a) + k) >>> 0, s);
    }

    // Round three: H(x, y, z) = x ^ y ^ z, constant 0x6ed9eba1.
    const h = (p: number, q: number, r: number) => p ^ q ^ r;
    const r3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
    const s3 = [3, 9, 11, 15];
    for (let i = 0; i < 16; i++) {
      const s = s3[i % 4];
      const k = (x[r3[i]] + 0x6ed9eba1) >>> 0;
      if (i % 4 === 0) a = rotl((a + h(b, c, d) + k) >>> 0, s);
      else if (i % 4 === 1) d = rotl((d + h(a, b, c) + k) >>> 0, s);
      else if (i % 4 === 2) c = rotl((c + h(d, a, b) + k) >>> 0, s);
      else b = rotl((b + h(c, d, a) + k) >>> 0, s);
    }

    a = (a + aa) >>> 0;
    b = (b + bb) >>> 0;
    c = (c + cc) >>> 0;
    d = (d + dd) >>> 0;
  }
  const out = Buffer.alloc(16);
  out.writeUInt32LE(a, 0);
  out.writeUInt32LE(b, 4);
  out.writeUInt32LE(c, 8);
  out.writeUInt32LE(d, 12);
  return out;
}

// ---------------------------------------------------------------------------
// RC4, for the key exchange of [MS-NLMP] section 3.1.5.1.2

export function rc4(key: Uint8Array, data: Uint8Array): Buffer {
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i++) s[i] = i;
  for (let i = 0, j = 0; i < 256; i++) {
    j = (j + s[i] + key[i % key.length]) & 0xff;
    [s[i], s[j]] = [s[j], s[i]];
  }
  const out = Buffer.alloc(data.length);
  for (let n = 0, i = 0, j = 0; n < data.length; n++) {
    i = (i + 1) & 0xff;
    j = (j + s[i]) & 0xff;
    [s[i], s[j]] = [s[j], s[i]];
    out[n] = data[n] ^ s[(s[i] + s[j]) & 0xff];
  }
  return out;
}

// ---------------------------------------------------------------------------
// The messages of NTLMSSP

const SIGNATURE = Buffer.from("NTLMSSP\0", "latin1");

export const NEGOTIATE_FLAGS = {
  UNICODE: 0x00000001,
  OEM: 0x00000002,
  REQUEST_TARGET: 0x00000004,
  SIGN: 0x00000010,
  SEAL: 0x00000020,
  ANONYMOUS: 0x00000800,
  NTLM: 0x00000200,
  ALWAYS_SIGN: 0x00008000,
  TARGET_TYPE_SERVER: 0x00020000,
  EXTENDED_SESSIONSECURITY: 0x00080000,
  TARGET_INFO: 0x00800000,
  VERSION: 0x02000000,
  KEY_EXCH: 0x40000000,
  KEY_128: 0x20000000,
  KEY_56: 0x80000000,
} as const;

/** Whether a buffer holds a raw NTLMSSP message. */
export const isNtlmssp = (b: Buffer): boolean =>
  b.length >= 12 && b.subarray(0, 8).equals(SIGNATURE);

/** The message type of an NTLMSSP message: 1, 2 or 3. */
export const ntlmType = (b: Buffer): number => b.readUInt32LE(8);

/** A field of an NTLMSSP message: length, capacity, offset. */
const readField = (b: Buffer, at: number): Buffer => {
  const len = b.readUInt16LE(at);
  const off = b.readUInt32LE(at + 4);
  if (len === 0 || off + len > b.length) return Buffer.alloc(0);
  return Buffer.from(b.subarray(off, off + len));
};

/** The negotiate message, type 1, which a client sends first. */
export function negotiateMessage(flags: number): Buffer {
  const b = Buffer.alloc(32);
  SIGNATURE.copy(b, 0);
  b.writeUInt32LE(1, 8);
  b.writeUInt32LE(flags >>> 0, 12);
  return b;
}

/** The pairs of an AV_PAIR list, of [MS-NLMP] section 2.2.2.1. */
export const AV = {
  EOL: 0x0000,
  NB_COMPUTER_NAME: 0x0001,
  NB_DOMAIN_NAME: 0x0002,
  DNS_COMPUTER_NAME: 0x0003,
  DNS_DOMAIN_NAME: 0x0004,
  TIMESTAMP: 0x0007,
  FLAGS: 0x0006,
  TARGET_NAME: 0x0009,
} as const;

function avPairs(pairs: [number, Buffer][]): Buffer {
  const parts: Buffer[] = [];
  for (const [id, value] of pairs) {
    const head = Buffer.alloc(4);
    head.writeUInt16LE(id, 0);
    head.writeUInt16LE(value.length, 2);
    parts.push(head, value);
  }
  const end = Buffer.alloc(4);
  parts.push(end);
  return Buffer.concat(parts);
}

/** The challenge message, type 2, which the server answers with. */
export function challengeMessage(
  target: string,
  challenge: Buffer,
  flags: number,
  now: bigint,
): Buffer {
  const targetName = utf16(target);
  const info = avPairs([
    [AV.NB_DOMAIN_NAME, targetName],
    [AV.NB_COMPUTER_NAME, targetName],
    [AV.TIMESTAMP, (() => {
      const t = Buffer.alloc(8);
      t.writeBigUInt64LE(now);
      return t;
    })()],
  ]);
  const b = Buffer.alloc(48 + targetName.length + info.length);
  SIGNATURE.copy(b, 0);
  b.writeUInt32LE(2, 8);
  b.writeUInt16LE(targetName.length, 12);
  b.writeUInt16LE(targetName.length, 14);
  b.writeUInt32LE(48, 16);
  b.writeUInt32LE(flags >>> 0, 20);
  challenge.copy(b, 24, 0, 8);
  b.writeUInt16LE(info.length, 40);
  b.writeUInt16LE(info.length, 42);
  b.writeUInt32LE(48 + targetName.length, 44);
  targetName.copy(b, 48);
  info.copy(b, 48 + targetName.length);
  return b;
}

/** What a challenge message carries. */
export function readChallenge(b: Buffer):
  { challenge: Buffer; flags: number; targetInfo: Buffer } {
  return {
    challenge: Buffer.from(b.subarray(24, 32)),
    flags: b.readUInt32LE(20),
    targetInfo: readField(b, 40),
  };
}

/** What an authenticate message, type 3, carries. */
export interface Authenticate {
  lmResponse: Buffer;
  ntResponse: Buffer;
  domain: string;
  user: string;
  workstation: string;
  sessionKey: Buffer;
  flags: number;
  mic?: Buffer;
}

export function readAuthenticate(b: Buffer): Authenticate | undefined {
  if (b.length < 64) return undefined;
  const flags = b.readUInt32LE(60);
  return {
    lmResponse: readField(b, 12),
    ntResponse: readField(b, 20),
    domain: readField(b, 28).toString("utf16le"),
    user: readField(b, 36).toString("utf16le"),
    workstation: readField(b, 44).toString("utf16le"),
    sessionKey: readField(b, 52),
    flags,
  };
}

/** Builds an authenticate message from the parts a client computed. */
export function authenticateMessage(a: Authenticate): Buffer {
  const parts: [Buffer, number][] = [];
  const domain = utf16(a.domain);
  const user = utf16(a.user);
  const workstation = utf16(a.workstation);
  const payload = [a.lmResponse, a.ntResponse, domain, user, workstation, a.sessionKey];
  let offset = 64;
  for (const p of payload) {
    parts.push([p, offset]);
    offset += p.length;
  }
  const b = Buffer.alloc(offset);
  SIGNATURE.copy(b, 0);
  b.writeUInt32LE(3, 8);
  const write = (at: number, i: number) => {
    b.writeUInt16LE(payload[i].length, at);
    b.writeUInt16LE(payload[i].length, at + 2);
    b.writeUInt32LE(parts[i][1], at + 4);
    payload[i].copy(b, parts[i][1]);
  };
  write(12, 0); // LmChallengeResponse
  write(20, 1); // NtChallengeResponse
  write(28, 2); // DomainName
  write(36, 3); // UserName
  write(44, 4); // Workstation
  write(52, 5); // EncryptedRandomSessionKey
  b.writeUInt32LE(a.flags >>> 0, 60);
  return b;
}

// ---------------------------------------------------------------------------
// NTLMv2

const hmacMd5 = (key: Uint8Array, data: Uint8Array): Buffer =>
  createHmac("md5", key).update(data).digest();

/** The NT hash of a password: MD4 of the password as UTF-16LE. */
export const ntHash = (password: string): Buffer => md4(utf16(password));

/**
 * The NTLMv2 hash: HMAC-MD5 of the user name in upper case followed by
 * the domain, keyed by the NT hash. The user name is upper-cased and
 * the domain is not, which [MS-NLMP] states and which is the mistake
 * an implementation of this makes.
 */
export const ntlmv2Hash = (password: string, user: string, domain: string): Buffer =>
  hmacMd5(ntHash(password), utf16(user.toUpperCase() + domain));

/** The blob of an NTLMv2 response, of [MS-NLMP] section 2.2.2.7. */
export function blob(now: bigint, clientChallenge: Buffer, targetInfo: Buffer): Buffer {
  const b = Buffer.alloc(28 + targetInfo.length + 4);
  b.writeUInt8(0x01, 0); // RespType
  b.writeUInt8(0x01, 1); // HiRespType
  b.writeBigUInt64LE(now, 8);
  clientChallenge.copy(b, 16, 0, 8);
  targetInfo.copy(b, 28);
  return b;
}

/**
 * The response a client computes and a server recomputes: the proof
 * string followed by the blob, and the session base key.
 */
export function ntlmv2Response(
  hash: Buffer,
  serverChallenge: Buffer,
  theBlob: Buffer,
): { response: Buffer; sessionBaseKey: Buffer } {
  const proof = hmacMd5(hash, Buffer.concat([serverChallenge, theBlob]));
  return {
    response: Buffer.concat([proof, theBlob]),
    sessionBaseKey: hmacMd5(hash, proof),
  };
}

/**
 * Verifies an authenticate message against a password, answering the
 * session key where it holds and undefined where it does not. The
 * response carries the blob it was computed over, so the server
 * recomputes the proof string from it rather than reconstructing it.
 */
export function verify(
  a: Authenticate,
  password: string,
  serverChallenge: Buffer,
): Buffer | undefined {
  if (a.ntResponse.length < 24) return undefined;
  const proof = a.ntResponse.subarray(0, 16);
  const theBlob = a.ntResponse.subarray(16);
  for (const domain of [a.domain, ""]) {
    // A client that names no domain hashes an empty one, and one that
    // names a domain hashes what it named; both are tried, because the
    // server cannot tell which the client used.
    const hash = ntlmv2Hash(password, a.user, domain);
    const mine = hmacMd5(hash, Buffer.concat([serverChallenge, theBlob]));
    if (mine.equals(proof)) {
      const sessionBaseKey = hmacMd5(hash, proof);
      if ((a.flags & NEGOTIATE_FLAGS.KEY_EXCH) !== 0 && a.sessionKey.length === 16) {
        return rc4(sessionBaseKey, a.sessionKey);
      }
      return sessionBaseKey;
    }
  }
  return undefined;
}

/**
 * Whether an authenticate message is the anonymous one: [MS-NLMP]
 * states a zero-length NT response, and the flag where the client
 * sets it.
 */
export const isAnonymous = (a: Authenticate): boolean =>
  a.ntResponse.length === 0 &&
  (a.lmResponse.length === 0 || (a.lmResponse.length === 1 && a.lmResponse[0] === 0));

/** A client's authenticate message for a password, with key exchange. */
export function clientAuthenticate(
  user: string,
  domain: string,
  password: string,
  workstation: string,
  challenge: Buffer,
  targetInfo: Buffer,
  now: bigint,
  flags: number,
): { message: Buffer; sessionKey: Buffer } {
  const hash = ntlmv2Hash(password, user, domain);
  const theBlob = blob(now, randomBytes(8), targetInfo);
  const { response, sessionBaseKey } = ntlmv2Response(hash, challenge, theBlob);
  const exported = randomBytes(16);
  const exchanging = (flags & NEGOTIATE_FLAGS.KEY_EXCH) !== 0;
  return {
    message: authenticateMessage({
      lmResponse: Buffer.alloc(24),
      ntResponse: response,
      domain,
      user,
      workstation,
      sessionKey: exchanging ? rc4(sessionBaseKey, exported) : Buffer.alloc(0),
      flags,
    }),
    sessionKey: exchanging ? exported : sessionBaseKey,
  };
}

/** A client's anonymous authenticate message. */
export const clientAnonymous = (workstation: string, flags: number): Buffer =>
  authenticateMessage({
    lmResponse: Buffer.from([0]),
    ntResponse: Buffer.alloc(0),
    domain: "",
    user: "",
    workstation,
    sessionKey: Buffer.alloc(0),
    flags: (flags | NEGOTIATE_FLAGS.ANONYMOUS) >>> 0,
  });
