// Kerberos cryptography (PLAN-auth.md, phase 1): the AES encryption and
// checksum profiles of RFC 3962, on the simplified profile of RFC 3961, which
// a CDMI server needs to verify the tickets of the realm a domain's
// cdmi_domain_auth item names (revision 282).
//
// What is here: n-fold (RFC 3961 section 5.1); AES in CBC with ciphertext
// stealing (RFC 3962 section 5); the key derivation DK and DR of RFC 3961
// section 5.1; the string-to-key of RFC 3962 section 4, PBKDF2-HMAC-SHA1 and
// then DK; and the encryption and checksum of the two enctypes RFC 3962
// defines, aes128-cts-hmac-sha1-96 (17) and aes256-cts-hmac-sha1-96 (18).
//
// Written to the test vectors the two RFCs publish (krb-crypto.test.ts), not to
// what this implementation happens to produce.

import { createCipheriv, createDecipheriv, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";

/** The encryption types of RFC 3962, by the numbers Kerberos gives them. */
export const ETYPE = { aes128: 17, aes256: 18 } as const;
export type Etype = typeof ETYPE[keyof typeof ETYPE];

/** The key size of each, in octets. */
export const keySize = (etype: Etype): number => (etype === ETYPE.aes128 ? 16 : 32);

const BLOCK = 16;
/** The checksum carried with a message: "HMAC output size, h 12 octets (96 bits)". */
export const MAC = 12;

/**
 * n-fold (RFC 3961 section 5.1): the octets replicated and added with
 * end-around carry until they fill n bits, n being a multiple of 8 here.
 */
export function nfold(input: Buffer, bits: number): Buffer {
  const n = bits / 8;
  if (!Number.isInteger(n) || n <= 0) throw new Error("n-fold is to a whole number of octets");
  const m = input.length;
  const lcm = (n * m) / gcd(n, m);
  const out = Buffer.alloc(n);
  let carry = 0;
  const sum = new Array<number>(n).fill(0);
  // The input replicated, each copy rotated right by a further 13 bits, and the
  // n-octet chunks of it added with end-around carry.
  const replicated = Buffer.alloc(lcm);
  for (let i = 0; i < lcm; i++) {
    // Bit position of this octet within the rotated copies.
    const copy = Math.floor(i / m);
    const rotation = (13 * copy) % (m * 8);
    replicated[i] = rotatedOctet(input, i % m, rotation);
  }
  for (let chunk = lcm / n - 1; chunk >= 0; chunk--) {
    for (let i = n - 1; i >= 0; i--) {
      const s = sum[i] + replicated[chunk * n + i] + carry;
      sum[i] = s & 0xff;
      carry = s >> 8;
    }
  }
  // The carry out of the most significant octet is added back in.
  while (carry !== 0) {
    for (let i = n - 1; i >= 0; i--) {
      const s = sum[i] + carry;
      sum[i] = s & 0xff;
      carry = s >> 8;
      if (carry === 0) break;
    }
  }
  for (let i = 0; i < n; i++) out[i] = sum[i];
  return out;
}

/** The octet at a position of the input rotated right by a number of bits. */
function rotatedOctet(input: Buffer, index: number, rotation: number): number {
  const bits = input.length * 8;
  const from = (index * 8 - rotation + bits * 8) % bits;
  let out = 0;
  for (let b = 0; b < 8; b++) {
    const at = (from + b) % bits;
    const bit = (input[Math.floor(at / 8)] >> (7 - (at % 8))) & 1;
    out = (out << 1) | bit;
  }
  return out;
}

const gcd = (a: number, b: number): number => (b === 0 ? a : gcd(b, a % b));

/**
 * AES in CBC with ciphertext stealing (RFC 3962 section 5): "For consistency,
 * ciphertext stealing is always used for the last two blocks of the data to be
 * encrypted ... If the data length is a multiple of the block size, this is
 * equivalent to plain CBC mode with the last two ciphertext blocks swapped."
 *
 * "If exactly one block is to be encrypted, that block is simply encrypted with
 * AES (also known as ECB mode). Input smaller than one block is padded at the
 * end to one block": with the all-zero initial vector these profiles use, that
 * is the same as the general path below, so the two cannot be told apart here.
 * Whether a non-zero initial vector is applied to a single block is not stated,
 * and no such use arises: every call here passes zeroes.
 */
export function ctsEncrypt(key: Buffer, iv: Buffer, plaintext: Buffer): Buffer {
  const alg = key.length === 16 ? "aes-128-cbc" : "aes-256-cbc";
  if (plaintext.length <= BLOCK) {
    const padded = Buffer.alloc(BLOCK);
    plaintext.copy(padded);
    const c = createCipheriv(alg, key, iv);
    c.setAutoPadding(false);
    return Buffer.concat([c.update(padded), c.final()]);
  }
  const whole = Math.ceil(plaintext.length / BLOCK) * BLOCK;
  const padded = Buffer.alloc(whole);
  plaintext.copy(padded);
  const c = createCipheriv(alg, key, iv);
  c.setAutoPadding(false);
  const out = Buffer.concat([c.update(padded), c.final()]);
  // The last two blocks are swapped, and the final one truncated to the length of the plaintext's tail.
  const blocks = out.length / BLOCK;
  const lastFull = out.subarray((blocks - 2) * BLOCK, (blocks - 1) * BLOCK);
  const last = out.subarray((blocks - 1) * BLOCK);
  const tail = plaintext.length - (blocks - 1) * BLOCK;
  return Buffer.concat([out.subarray(0, (blocks - 2) * BLOCK), last, lastFull.subarray(0, tail)]);
}

/** The inverse of ctsEncrypt. */
export function ctsDecrypt(key: Buffer, iv: Buffer, ciphertext: Buffer): Buffer {
  const alg = key.length === 16 ? "aes-128-cbc" : "aes-256-cbc";
  const raw = (input: Buffer, vector: Buffer) => {
    const d = createDecipheriv(alg, key, vector);
    d.setAutoPadding(false);
    return Buffer.concat([d.update(input), d.final()]);
  };
  if (ciphertext.length <= BLOCK) return raw(ciphertext, iv);
  const blocks = Math.ceil(ciphertext.length / BLOCK);
  const tail = ciphertext.length - (blocks - 1) * BLOCK;
  const head = ciphertext.subarray(0, (blocks - 2) * BLOCK);
  const secondLast = ciphertext.subarray((blocks - 2) * BLOCK, (blocks - 1) * BLOCK);
  const lastPartial = ciphertext.subarray((blocks - 1) * BLOCK);
  // The block before the stolen pair, which is the vector for them.
  const before = blocks >= 3 ? ciphertext.subarray((blocks - 3) * BLOCK, (blocks - 2) * BLOCK) : iv;
  // Decrypting the second-to-last ciphertext block with a zero vector gives the
  // octets the last block's ciphertext was stolen from.
  const stolen = raw(secondLast, Buffer.alloc(BLOCK));
  const lastFull = Buffer.concat([lastPartial, stolen.subarray(tail)]);
  const plainHead = head.length === 0 ? Buffer.alloc(0) : raw(head, iv);
  const plainSecondLast = xor(raw(lastFull, Buffer.alloc(BLOCK)), before);
  const plainLast = xor(stolen.subarray(0, tail), lastFull.subarray(0, tail));
  return Buffer.concat([plainHead, plainSecondLast, plainLast]);
}

const xor = (a: Buffer, b: Buffer): Buffer => Buffer.from(a.map((x, i) => x ^ b[i]));

/**
 * DR, the random octets derived from a key and a constant, and DK, the key
 * derived from them (RFC 3961 section 5.1). The constant is n-folded to the
 * cipher block size and encrypted in turn until enough octets are had.
 */
export function dr(key: Buffer, constant: Buffer): Buffer {
  const need = key.length;
  let block = constant.length === BLOCK ? Buffer.from(constant) : nfold(constant, BLOCK * 8);
  const out: Buffer[] = [];
  let have = 0;
  while (have < need) {
    block = ctsEncrypt(key, Buffer.alloc(BLOCK), block);
    out.push(block);
    have += block.length;
  }
  return Buffer.concat(out).subarray(0, need);
}

/** DK(key, constant): the derived key, which for these profiles is DR itself, the random-to-key function being the identity. */
export const dk = (key: Buffer, constant: Buffer): Buffer => dr(key, constant);

/** The key usage constants of a derived key: the usage, then the octet that says which key. */
const usageConstant = (usage: number, kind: 0xaa | 0x55 | 0x99): Buffer => {
  const b = Buffer.alloc(5);
  b.writeUInt32BE(usage >>> 0, 0);
  b[4] = kind;
  return b;
};

/** The encryption key derived for a usage. */
export const keyForEncryption = (key: Buffer, usage: number): Buffer => dk(key, usageConstant(usage, 0xaa));
/** The integrity key derived for a usage. */
export const keyForChecksum = (key: Buffer, usage: number): Buffer => dk(key, usageConstant(usage, 0x99));

/**
 * string-to-key (RFC 3962 section 4): PBKDF2 with HMAC-SHA1 over the pass
 * phrase and salt, the iteration count from the string-to-key parameters, and
 * then DK with the constant "kerberos". The default count is 4096, the default
 * parameters being 00 00 10 00.
 */
export function stringToKey(password: string, salt: string, etype: Etype, iterations = 4096): Buffer {
  const size = keySize(etype);
  const tkey = pbkdf2Sync(Buffer.from(password, "utf8"), Buffer.from(salt, "utf8"), iterations, size, "sha1");
  return dk(tkey, Buffer.from("kerberos", "utf8"));
}

/** The iteration count of the string-to-key parameters, four octets, big-endian. */
export function iterationsOf(params: Buffer | undefined): number {
  if (params === undefined || params.length !== 4) return 4096;
  const n = params.readUInt32BE(0);
  return n === 0 ? 4294967296 : n;
}

/**
 * The encryption of a message for a key usage: a confounder of one block, the
 * plaintext, encrypted with the derived encryption key, and the first 96 bits
 * of the HMAC-SHA1 of the confounder and plaintext under the derived integrity
 * key appended.
 */
export function encrypt(key: Buffer, usage: number, plaintext: Buffer, confounder = randomBytes(BLOCK)): Buffer {
  const ke = keyForEncryption(key, usage), ki = keyForChecksum(key, usage);
  const body = Buffer.concat([confounder, plaintext]);
  const ciphertext = ctsEncrypt(ke, Buffer.alloc(BLOCK), body);
  return Buffer.concat([ciphertext, hmacSha196(ki, body)]);
}

/** The inverse: the plaintext, or an error where the checksum does not verify. */
export function decrypt(key: Buffer, usage: number, message: Buffer): Buffer {
  if (message.length < BLOCK + MAC) throw new Error("the message is too short to hold a confounder and a checksum");
  const ke = keyForEncryption(key, usage), ki = keyForChecksum(key, usage);
  const ciphertext = message.subarray(0, message.length - MAC);
  const given = message.subarray(message.length - MAC);
  const body = ctsDecrypt(ke, Buffer.alloc(BLOCK), ciphertext);
  const wanted = hmacSha196(ki, body);
  if (given.length !== wanted.length || !timingSafeEqual(given, wanted)) throw new Error("the checksum does not verify");
  return body.subarray(BLOCK);
}

/** HMAC-SHA1 truncated to 96 bits, the checksum of these profiles. */
export const hmacSha196 = (key: Buffer, data: Buffer): Buffer => createHmac("sha1", key).update(data).digest().subarray(0, MAC);

/** The checksum of a message for a key usage: hmac-sha1-96-aes128 and -aes256. */
export const checksum = (key: Buffer, usage: number, data: Buffer): Buffer => hmacSha196(keyForChecksum(key, usage), data);
