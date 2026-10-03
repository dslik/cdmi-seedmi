// Encrypting, decrypting and re-encrypting the value of an object in place,
// as the encrypted objects subclause defines those operations.
//
// "The managed object the cdmi_enc_key_id item addresses is a key encryption
// key. The key that encrypts the value of the object is generated for that
// object, and is carried wrapped under that key encryption key in the
// structure stored as the value: in the JWE Encrypted Key of a recipient of
// a JWE structure". So the content key is made here, used once, and
// discarded; the key encryption key stays at the key management server,
// which wraps and unwraps on request. "A CDMI server shall not retain a key
// after the operation that required it has completed", which this module
// keeps to by holding the content key in a local and letting it go.
import {
  constants, createCipheriv, createDecipheriv, createPublicKey, type KeyObject,
  publicEncrypt, randomBytes,
} from "node:crypto";
import type { KeyManagement } from "./kms.ts";
import { b64u, REFUSED_ALGORITHMS, unb64u, verifyJws } from "./jose.ts";
import { child } from "./kmip-ttlv.ts";
import { EncryptedValueError } from "./encrypted.ts";

/** The content encryption the value is protected with. */
const ENC = "A256GCM";

/**
 * The JOSE algorithms this server uses for JSON Web Encryption, which the
 * cdmi_jwe_alg and cdmi_jwe_enc capabilities report: the key management
 * algorithms that wrap the content key, and the content encryption
 * algorithms that encrypt the value.
 *
 * "A CDMI server reports the algorithms that are enabled, and not those it
 * implements but that are not enabled, in the ... cdmi_jwe_enc, cdmi_jwe_alg
 * and cdmi_jws_alg capabilities ... so that a CDMI client determines what a
 * CDMI server accepts before it constructs a structure." These lists are
 * therefore what a received structure is checked against, and not a separate
 * statement about this server: a structure naming an algorithm absent from
 * them is refused, so the capability cannot promise what the code will not
 * accept.
 *
 * RSA-OAEP-256 is one of the two key management algorithms the security
 * subclause makes mandatory to implement. This server published A256KW
 * alone, which is neither of them, until 0.83. ECDH-ES+A128KW, the other, is
 * not offered here: the ephemeral-static agreement needs the private half of
 * the key encryption key, which stays at the key management server, and KMIP
 * 1.4 offers no derivation this server can drive for it. Annex B admits that
 * — a CDMI server "reports the algorithms that are enabled" — and
 * PLAN-encryption.md records why.
 */
export const JWE_ALG = ["RSA-OAEP-256", "A256KW"];
export const JWE_ENC = [ENC];

/**
 * "A CDMI server shall not use any of the algorithms and key sizes listed
 * below, and shall reject on receipt a structure that uses any of them: the
 * RSA1_5 key management algorithm; a content encryption algorithm of the
 * Triple Data Encryption Algorithm or of RC2; SHA-1 as the digest of a
 * signature; an RSA key of fewer than 2048 bits; and an elliptic curve of
 * fewer than 256 bits."
 *
 * Each of these is refused by name, and with the reason, rather than falling
 * through the check below as an algorithm this server merely does not offer:
 * a CDMI client that is told "not offered" may reasonably try another
 * deployment, and one told that the algorithm is refused knows not to.
 */
const REFUSED = REFUSED_ALGORITHMS;

/**
 * The wrapping performed at the key management server, where the key
 * encryption key is a symmetric managed object: AES Key Wrap, one managed
 * object serving as the key encryption key, which is what a credential
 * reference addresses.
 */
const WRAP = { algorithm: "AES", blockCipherMode: "NISTKeyWrap" } as never;

/**
 * The unwrapping performed at the key management server, where the key
 * encryption key is an RSA key pair: the content key was encrypted to the
 * public half here, and the private half never leaves the server.
 */
const OAEP = { algorithm: "RSA", paddingMethod: "OAEP", hashingAlgorithm: "SHA-256" } as never;

export class EncryptionUnavailable extends Error {}

/**
 * The key management algorithm a key encryption key admits, read from the
 * managed object rather than assumed: a symmetric key wraps with AES Key
 * Wrap, an RSA key pair with RSA-OAEP-256. The algorithm named in the
 * structure is then this one, and a structure naming another is refused.
 */
async function algorithmOf(kms: KeyManagement, keyID: string): Promise<string> {
  let objectType = "Symmetric Key";
  try {
    objectType = (await kms.get(keyID)).objectType;
  } catch {
    // A key encryption key this server may not read the object of is a
    // symmetric key wrapped at the server, which is the case this server
    // served before it offered any other.
    return "A256KW";
  }
  if (objectType === "Public Key" || objectType === "Private Key") return "RSA-OAEP-256";
  return "A256KW";
}

/**
 * Encrypts a value under a key encryption key held at a key management
 * server, producing a JWE in the JSON serialization with one recipient. The
 * media type of the plaintext is carried in the protected header, as the
 * subclause requires of it.
 */
export async function encryptValue(kms: KeyManagement, keyID: string,
  plaintext: Buffer, plaintextType: string, kid?: string): Promise<Buffer> {
  const alg = await algorithmOf(kms, keyID);
  const cek = randomBytes(32);
  try {
    // The kid header parameter, where the caller gives one, names the key
    // encryption key as a CDMI client refers to it.
    const head = kid === undefined
      ? { alg, enc: ENC, cty: plaintextType }
      : { alg, enc: ENC, cty: plaintextType, kid };
    const protectedHeader = b64u(Buffer.from(JSON.stringify(head), "utf8"));
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", cek, iv);
    cipher.setAAD(Buffer.from(protectedHeader, "ascii"));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    // The content key is wrapped under the key encryption key. Under
    // A256KW the key management server wraps it, holding the key encryption
    // key throughout: this server never sees it. Under RSA-OAEP-256 the
    // content key is encrypted to the public half here, which is not a
    // secret and which the key management server hands over; the private
    // half stays there and unwraps on request.
    const wrapped = alg === "A256KW"
      ? (await kms.encrypt(keyID, { params: WRAP, data: cek })).data
      : publicEncrypt({
        key: await verificationKey(kms, keyID),
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        // RSA-OAEP-256 is OAEP with SHA-256, which is what distinguishes it
        // from RSA-OAEP, an algorithm this server reads and does not produce.
        oaepHash: "sha256",
      } as never, cek);
    return Buffer.from(JSON.stringify({
      protected: protectedHeader,
      recipients: [{ encrypted_key: b64u(wrapped) }],
      iv: b64u(iv),
      ciphertext: b64u(ciphertext),
      tag: b64u(tag),
    }), "utf8");
  } finally {
    cek.fill(0);
  }
}

/**
 * Decrypts the value of an encrypted object, returning the plaintext and the
 * media type its protected header carries. The wrapped content key is
 * unwrapped by the key management server.
 */
export async function decryptValue(kms: KeyManagement, keyID: string,
  value: Buffer): Promise<{ plaintext: Buffer; plaintextType: string }> {
  const s = JSON.parse(value.toString("utf8")) as Record<string, unknown>;
  const protectedHeader = typeof s.protected === "string" ? s.protected : "";
  const head = JSON.parse(unb64u(protectedHeader).toString("utf8")) as Record<string, unknown>;
  const cty = typeof head.cty === "string" ? head.cty : undefined;
  if (cty === undefined) {
    throw new EncryptedValueError("the protected header carries no cty header parameter");
  }
  // The algorithms the structure names are checked before anything is
  // unwrapped. This server read neither header parameter before 0.83: it
  // unwrapped with AES Key Wrap and decrypted with AES-256-GCM whatever the
  // header said, so a structure naming RSA1_5 — which this document requires
  // a CDMI server to reject on receipt — was not rejected but merely failed,
  // and the published capabilities said what this server accepted while the
  // code accepted something else.
  const alg = typeof head.alg === "string" ? head.alg : "";
  const enc = typeof head.enc === "string" ? head.enc : "";
  for (const [named, offered, what] of
    [[alg, JWE_ALG, "key management"], [enc, JWE_ENC, "content encryption"]] as
    [string, string[], string][]) {
    const refused = REFUSED[named];
    if (refused !== undefined) throw new EncryptedValueError(refused);
    if (!offered.includes(named)) {
      throw new EncryptedValueError(
        `${named === "" ? "no algorithm" : named} is not a ${what} algorithm this ` +
        `CDMI server accepts; it accepts ${offered.join(", ")}`);
    }
  }
  const recipients = Array.isArray(s.recipients) ? s.recipients as Record<string, unknown>[] : [];
  const first = recipients.find((r) => typeof r.encrypted_key === "string");
  const wrapped = typeof first?.encrypted_key === "string"
    ? first.encrypted_key
    : (typeof s.encrypted_key === "string" ? s.encrypted_key : undefined);
  if (wrapped === undefined) {
    throw new EncryptedValueError("the structure holds no wrapped key for any recipient");
  }
  // Unwrapped by the algorithm the structure names, which is one of those
  // above: the key management server holds the key encryption key under
  // either, the symmetric key for AES Key Wrap and the private half of the
  // pair for RSA-OAEP-256.
  const cek = await kms.decrypt(keyID, {
    params: alg === "A256KW" ? WRAP : OAEP,
    data: unb64u(wrapped),
  });
  try {
    if (cek.length !== 32) {
      throw new EncryptedValueError("the wrapped key is not a 256 bit content encryption key");
    }
    const decipher = createDecipheriv("aes-256-gcm", cek,
      unb64u(typeof s.iv === "string" ? s.iv : ""));
    decipher.setAAD(Buffer.from(protectedHeader, "ascii"));
    decipher.setAuthTag(unb64u(typeof s.tag === "string" ? s.tag : ""));
    const plaintext = Buffer.concat([
      decipher.update(unb64u(typeof s.ciphertext === "string" ? s.ciphertext : "")),
      decipher.final(),
    ]);
    return { plaintext, plaintextType: cty };
  } finally {
    cek.fill(0);
  }
}

/**
 * The public key a managed object holds, fetched from the key management
 * server. A verification key is not a secret, so it is fetched and used
 * here, where a key encryption key stays at the server and wraps there.
 */
export async function verificationKey(kms: KeyManagement, id: string): Promise<KeyObject> {
  const got = await kms.get(id);
  const block = child(got.object, "Key Block");
  if (block === undefined) throw new EncryptedValueError("the managed object holds no key block");
  const material = child(child(block, "Key Value")!, "Key Material")?.value as Buffer | undefined;
  const format = child(block, "Key Format Type")?.value;
  if (material === undefined) throw new EncryptedValueError("the key block holds no key material");
  return createPublicKey({
    key: material,
    format: "der",
    type: format === 3 ? "pkcs1" : "spki",
  });
}

/**
 * Verifies a value that is a JWS and returns what it signs. "Where a CDMI
 * server decrypts a value that contains a signature, it shall verify that
 * signature using the verification key the corresponding metadata item
 * identifies. Where verification does not succeed, the CDMI server shall
 * not return the plaintext and shall report the condition, so that a value
 * that has been altered is not presented as though it were intact."
 */
export function verifiedPayload(value: Buffer, key: KeyObject):
  { payload: Buffer; plaintextType?: string } {
  const text = value.toString("utf8");
  const jws: string | Record<string, unknown> = text.trim().startsWith("{")
    ? JSON.parse(text) as Record<string, unknown>
    : text.trim();
  const got = verifyJws(jws, key);
  const cty = got.header.cty;
  return { payload: got.payload, plaintextType: typeof cty === "string" ? cty : undefined };
}

/** Whether a value is a JWS, and so carries a signature to verify. */
export function isSignedValue(value: Buffer): boolean {
  const text = value.toString("utf8").trim();
  if (text.startsWith("{")) {
    try {
      const s = JSON.parse(text) as Record<string, unknown>;
      return "payload" in s && ("signature" in s || Array.isArray(s.signatures));
    } catch {
      return false;
    }
  }
  return /^[\w-]+\.[\w-]+\.[\w-]+$/.test(text);
}
