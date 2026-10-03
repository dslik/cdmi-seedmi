// The AES key wrap of RFC 3394, which JWE's ECDH-ES+A*KW algorithms use. Taken
// from seedmi (cms-envelope.ts), whose tests check it against RFC 3394's vectors,
// as aes-kw.test.ts does here: this program shares no file with seedmi.

import { createCipheriv, createDecipheriv } from "node:crypto";

function xorCounter(a: Buffer, t: number): void {
  for (let k = 0; k < 4; k++) {
    a[7 - k] ^= (t >>> (8 * k)) & 0xff;
  }
}

/** The initial value of the key wrap of RFC 3394. */
const KEY_WRAP_IV = Buffer.from([0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6]);

/**
 * The key wrap of RFC 3394, which Node exposes only as the raw
 * block cipher, so the wrapping itself is written here.
 */
export function aesKeyWrap(kek: Buffer, plain: Buffer): Buffer {
  if (plain.length % 8 !== 0 || plain.length < 16) {
    throw new Error("a wrapped key is a whole number of 8-octet blocks, 16 or more");
  }
  const n = plain.length / 8;
  let a = Buffer.from(KEY_WRAP_IV);
  const r: Buffer[] = [];
  for (let i = 0; i < n; i++) r.push(Buffer.from(plain.subarray(i * 8, i * 8 + 8)));
  const cipher = () => createCipheriv(`aes-${kek.length * 8}-ecb`, kek, null)
    .setAutoPadding(false);
  for (let j = 0; j < 6; j++) {
    for (let i = 0; i < n; i++) {
      const c = cipher();
      const b = Buffer.concat([c.update(Buffer.concat([a, r[i]])), c.final()]);
      a = Buffer.from(b.subarray(0, 8));
      r[i] = Buffer.from(b.subarray(8, 16));
      // The counter is exclusive-ored into the trailing octets of
      // A. It is treated as 64 bits, and the upper 32 are always
      // zero: a shift of 32 or more is not written, JavaScript
      // taking the shift count modulo 32 and producing the low
      // octets again.
      xorCounter(a, j * n + i + 1);
    }
  }
  return Buffer.concat([a, ...r]);
}

/** The inverse, which fails where the integrity check does not hold. */
export function aesKeyUnwrap(kek: Buffer, wrapped: Buffer): Buffer {
  if (wrapped.length % 8 !== 0 || wrapped.length < 24) {
    throw new Error("a wrapped key is a whole number of 8-octet blocks, 24 or more");
  }
  const n = wrapped.length / 8 - 1;
  let a = Buffer.from(wrapped.subarray(0, 8));
  const r: Buffer[] = [];
  for (let i = 0; i < n; i++) {
    r.push(Buffer.from(wrapped.subarray(8 + i * 8, 16 + i * 8)));
  }
  const decipher = () => createDecipheriv(`aes-${kek.length * 8}-ecb`, kek, null)
    .setAutoPadding(false);
  for (let j = 5; j >= 0; j--) {
    for (let i = n - 1; i >= 0; i--) {
      const av = Buffer.from(a);
      xorCounter(av, j * n + i + 1);
      const d = decipher();
      const b = Buffer.concat([d.update(Buffer.concat([av, r[i]])), d.final()]);
      a = Buffer.from(b.subarray(0, 8));
      r[i] = Buffer.from(b.subarray(8, 16));
    }
  }
  // The integrity check: the initial value is recovered where the
  // key encryption key was the right one.
  if (!a.equals(KEY_WRAP_IV)) {
    throw new Error("the wrapped key did not unwrap under this key");
  }
  return Buffer.concat(r);
}
