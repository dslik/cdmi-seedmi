/**
 * The cryptography of an SMB2 session: the signing key derivation of
 * [MS-SMB2] section 3.1.4.2, and the signature of section 3.1.4.1.
 *
 * The dialect decides the algorithm. SMB 2.0.2 and 2.1 sign with
 * HMAC-SHA256 keyed by the session key, and take the first sixteen
 * octets. The 3.x family derives a key and signs with AES-128-CMAC,
 * which is written out here because the cryptography library of this
 * runtime offers the cipher and not the mode.
 */

import { createCipheriv, createHash, createHmac } from "node:crypto";
import { encodeHeader, FLAG, HEADER_SIZE, isSmb3, type Header } from "./smb-wire.ts";

/** The block cipher, one block, with no padding. */
function aesBlock(key: Uint8Array, block: Uint8Array): Buffer {
  const c = createCipheriv("aes-128-ecb", key, null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(block), c.final()]);
}

/** Doubles a block in the field of RFC 4493, for the subkeys. */
function double(b: Buffer): Buffer {
  const out = Buffer.alloc(16);
  let carry = 0;
  for (let i = 15; i >= 0; i--) {
    const v = (b[i] << 1) | carry;
    out[i] = v & 0xff;
    carry = (v >> 8) & 1;
  }
  if ((b[0] & 0x80) !== 0) out[15] ^= 0x87;
  return out;
}

/** AES-128-CMAC of RFC 4493, sixteen octets. */
export function aesCmac(key: Uint8Array, message: Uint8Array): Buffer {
  const zero = Buffer.alloc(16);
  const l = aesBlock(key, zero);
  const k1 = double(l);
  const k2 = double(k1);

  const n = Math.ceil(message.length / 16);
  const complete = n > 0 && message.length % 16 === 0;
  const blocks = Math.max(n, 1);

  let x = Buffer.alloc(16);
  for (let i = 0; i < blocks - 1; i++) {
    const block = Buffer.from(message.subarray(i * 16, i * 16 + 16));
    for (let j = 0; j < 16; j++) block[j] ^= x[j];
    x = aesBlock(key, block);
  }

  // The last block is padded where it is short, and each is combined
  // with the subkey its completeness selects.
  const rest = Buffer.from(message.subarray((blocks - 1) * 16));
  const last = Buffer.alloc(16);
  rest.copy(last, 0);
  if (!complete) last[rest.length] = 0x80;
  const subkey = complete ? k1 : k2;
  for (let j = 0; j < 16; j++) last[j] ^= x[j] ^ subkey[j];
  return aesBlock(key, last);
}

/**
 * The key derivation of SP800-108 in counter mode with HMAC-SHA256,
 * one iteration, producing the sixteen octets [MS-SMB2] asks for.
 */
export function kdf(key: Uint8Array, label: string, context: Uint8Array): Buffer {
  const l = Buffer.alloc(4);
  l.writeUInt32BE(128); // the length of the derived key, in bits
  const i = Buffer.alloc(4);
  i.writeUInt32BE(1);
  const input = Buffer.concat([
    i,
    Buffer.from(`${label}\0`, "latin1"),
    Buffer.from([0]),
    Buffer.from(context),
    l,
  ]);
  return createHmac("sha256", key).update(input).digest().subarray(0, 16);
}

/**
 * The signing key of a session. The label and the context differ by
 * dialect: 3.1.1 keys "SMBSigningKey" with the preauthentication
 * integrity hash of the session, and the earlier 3.x dialects key
 * "SMB2AESCMAC" with "SmbSign".
 */
export function signingKey(
  dialect: number,
  sessionKey: Buffer,
  preauth: Buffer,
): Buffer {
  if (!isSmb3(dialect)) return sessionKey;
  return dialect === 0x0311
    ? kdf(sessionKey, "SMBSigningKey", preauth)
    : kdf(sessionKey, "SMB2AESCMAC", Buffer.from("SmbSign\0", "latin1"));
}

/**
 * Signs a message: the signature field is zeroed, the flag is set, and
 * the hash is computed over the whole message including the header.
 */
export function sign(dialect: number, key: Buffer, h: Header, body: Buffer): Buffer {
  const flagged = { ...h, flags: (h.flags | FLAG.SIGNED) >>> 0, signature: Buffer.alloc(16) };
  const message = Buffer.concat([encodeHeader(flagged), body]);
  const signature = isSmb3(dialect)
    ? aesCmac(key, message)
    : createHmac("sha256", key).update(message).digest().subarray(0, 16);
  signature.copy(message, 48);
  return message;
}

/** Whether the signature a message carries is the one the key produces. */
export function verifySignature(dialect: number, key: Buffer, message: Buffer): boolean {
  if (message.length < HEADER_SIZE) return false;
  const given = Buffer.from(message.subarray(48, 64));
  const zeroed = Buffer.from(message);
  zeroed.fill(0, 48, 64);
  const mine = isSmb3(dialect)
    ? aesCmac(key, zeroed)
    : createHmac("sha256", key).update(zeroed).digest().subarray(0, 16);
  // A comparison of two values the sender already knows; there is
  // nothing here for a timing observation to recover.
  return mine.equals(given);
}

/**
 * The preauthentication integrity hash of [MS-SMB2] section 3.1.5.2:
 * the running SHA-512 of the previous value followed by the message.
 */
export const preauthHash = (previous: Buffer, message: Buffer): Buffer =>
  createHash("sha512").update(Buffer.concat([previous, message])).digest();

/** The initial value of that hash, sixty-four zero octets. */
export const PREAUTH_ZERO = Buffer.alloc(64);
