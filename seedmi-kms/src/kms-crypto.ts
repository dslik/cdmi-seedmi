// The cryptography behind the KMIP operations performed with a managed
// object: key material to Node key objects, and encryption, decryption,
// signature, MAC and key wrap by the Cryptographic Parameters KMIP gives.
// Pure functions: the state and usage mask of an object are checked in
// kms-core.ts before any of these is called.
//
// Section and table numbers are those of KMIP 1.4.

import {
  createCipheriv, createDecipheriv, createHmac, createPrivateKey, createPublicKey, constants,
  type KeyObject, privateDecrypt, publicEncrypt, randomBytes, sign as nodeSign, timingSafeEqual,
  verify as nodeVerify, X509Certificate,
} from "node:crypto";
import { aesKeyUnwrap, aesKeyWrap } from "./cms-envelope.ts";
import { enumName } from "./kmip-message.ts";
import { child, type Item, k, TYPE } from "./kmip-ttlv.ts";
import { KmsError } from "./kms-core-error.ts";

// ---------------------------------------------------------------------------
// Cryptographic Parameters (3.6)

export interface CryptoParams {
  blockCipherMode?: string;
  paddingMethod?: string;
  hashingAlgorithm?: string;
  digitalSignatureAlgorithm?: string;
  cryptographicAlgorithm?: string;
  randomIV?: boolean;
  ivLength?: number;
  tagLength?: number;
}

const ENUM_FIELDS: [keyof CryptoParams, string][] = [
  ["blockCipherMode", "Block Cipher Mode"], ["paddingMethod", "Padding Method"],
  ["hashingAlgorithm", "Hashing Algorithm"], ["digitalSignatureAlgorithm", "Digital Signature Algorithm"],
  ["cryptographicAlgorithm", "Cryptographic Algorithm"],
];

/** Reads a Cryptographic Parameters structure. */
export function readParams(item: Item | undefined): CryptoParams {
  const p: CryptoParams = {};
  if (item === undefined) return p;
  for (const [key, name] of ENUM_FIELDS) {
    const f = child(item, name);
    if (f?.type === TYPE.Enumeration) (p as Record<string, unknown>)[key] = enumName(name, f.value);
  }
  const random = child(item, "Random IV");
  if (random?.type === TYPE.Boolean) p.randomIV = random.value;
  const iv = child(item, "IV Length");
  if (iv?.type === TYPE.Integer) p.ivLength = iv.value;
  const tag = child(item, "Tag Length");
  if (tag?.type === TYPE.Integer) p.tagLength = tag.value;
  return p;
}

/** A Cryptographic Parameters structure of the fields given, in the order of Table 65. */
export function writeParams(p: CryptoParams): Item {
  return k.struct("Cryptographic Parameters", [
    ...(p.blockCipherMode ? [k.enum("Block Cipher Mode", "Block Cipher Mode", p.blockCipherMode)] : []),
    ...(p.paddingMethod ? [k.enum("Padding Method", "Padding Method", p.paddingMethod)] : []),
    ...(p.hashingAlgorithm ? [k.enum("Hashing Algorithm", "Hashing Algorithm", p.hashingAlgorithm)] : []),
    ...(p.digitalSignatureAlgorithm
      ? [k.enum("Digital Signature Algorithm", "Digital Signature Algorithm", p.digitalSignatureAlgorithm)] : []),
    ...(p.cryptographicAlgorithm
      ? [k.enum("Cryptographic Algorithm", "Cryptographic Algorithm", p.cryptographicAlgorithm)] : []),
    ...(p.randomIV === undefined ? [] : [k.bool("Random IV", p.randomIV)]),
    ...(p.ivLength === undefined ? [] : [k.int("IV Length", p.ivLength)]),
    ...(p.tagLength === undefined ? [] : [k.int("Tag Length", p.tagLength)]),
  ]);
}

/** The fields of the request's parameters over those of the object's attribute. */
export const mergeParams = (fromObject: CryptoParams, fromRequest: CryptoParams): CryptoParams =>
  ({ ...fromObject, ...fromRequest });

/** Whether every field a request gives matches an attribute instance. */
export const paramsMatch = (given: CryptoParams, instance: CryptoParams): boolean =>
  (Object.keys(given) as (keyof CryptoParams)[]).every((key) => given[key] === instance[key]);

// ---------------------------------------------------------------------------
// Key material

export interface Material {
  format: string;
  bytes: Buffer;
  algorithm?: string;
}

/** The Key Format Type, key bytes and algorithm of an object's Key Block. */
export function keyMaterial(value: Item): Material {
  const block = child(value, "Key Block");
  if (block === undefined) throw new KmsError("Permission Denied", "the object holds no Key Block");
  const format = enumName("Key Format Type", child(block, "Key Format Type")!.value as number);
  const kv = child(block, "Key Value");
  if (kv === undefined) throw new KmsError("Key Value Not Present", "the Key Block holds no Key Value");
  if (kv.type === TYPE.ByteString || child(block, "Key Wrapping Data") !== undefined) {
    // The core unwraps an object before using it (kms-core.ts plainValue).
    throw new KmsError("Feature Not Supported", "the key is held wrapped");
  }
  const km = child(kv, "Key Material")!;
  let bytes: Buffer;
  if (km.type === TYPE.ByteString) bytes = km.value;
  else if (format === "Transparent Symmetric Key" && child(km, "Key")?.type === TYPE.ByteString) {
    bytes = child(km, "Key")!.value as Buffer;
  } else {
    throw new KmsError("Key Format Type Not Supported", `keys held as ${format} are not used here`);
  }
  const alg = child(block, "Cryptographic Algorithm");
  return { format, bytes, ...(alg ? { algorithm: enumName("Cryptographic Algorithm", alg.value as number) } : {}) };
}

/** A private key object from its Key Block, in the formats of 9.1.3.2.3 that Node reads. */
export function privateKeyOf(m: Material): KeyObject {
  const type = { "PKCS#1": "pkcs1", "PKCS#8": "pkcs8", "ECPrivateKey": "sec1" }[m.format];
  if (type === undefined) throw new KmsError("Key Format Type Not Supported", `a private key held as ${m.format}`);
  try {
    return createPrivateKey({ key: m.bytes, format: "der", type });
  } catch {
    throw new KmsError("Cryptographic Failure", `the ${m.format} private key does not parse`);
  }
}

/** A public key object from a Public Key's Key Block or a Certificate's value. */
export function publicKeyOf(value: Item, objectType: string): KeyObject {
  try {
    if (objectType === "Certificate") {
      return new X509Certificate(child(value, "Certificate Value")!.value as Buffer).publicKey;
    }
    const m = keyMaterial(value);
    const type = { "PKCS#1": "pkcs1", "X.509": "spki" }[m.format];
    if (type === undefined) throw new KmsError("Key Format Type Not Supported", `a public key held as ${m.format}`);
    return createPublicKey({ key: m.bytes, format: "der", type });
  } catch (e) {
    if (e instanceof KmsError) throw e;
    throw new KmsError("Cryptographic Failure", "the public key does not parse");
  }
}

// ---------------------------------------------------------------------------
// Hashes and signatures

const HASHES: Record<string, string> = {
  "SHA-1": "sha1", "SHA-224": "sha224", "SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512",
  "SHA-3-256": "sha3-256", "SHA-3-384": "sha3-384", "SHA-3-512": "sha3-512",
};

function hashOf(name: string | undefined, fallback?: string): string {
  const h = HASHES[name ?? fallback ?? ""];
  if (h === undefined) {
    throw new KmsError("Feature Not Supported", `the hashing algorithm ${name ?? "(none)"} is not supported`);
  }
  return h;
}

/** Digital Signature Algorithm (9.1.3.2.7), as a hash. */
const SIGNATURE_ALGORITHMS: Record<string, { hash: string; pss?: boolean }> = {
  "SHA-1 with RSA Encryption (PKCS#1 v1.5)": { hash: "SHA-1" }, "SHA-224 with RSA Encryption (PKCS#1 v1.5)": { hash: "SHA-224" },
  "SHA-256 with RSA Encryption (PKCS#1 v1.5)": { hash: "SHA-256" }, "SHA-384 with RSA Encryption (PKCS#1 v1.5)": { hash: "SHA-384" },
  "SHA-512 with RSA Encryption (PKCS#1 v1.5)": { hash: "SHA-512" },
  "ECDSA with SHA-1": { hash: "SHA-1" }, "ECDSA with SHA224": { hash: "SHA-224" },
  "ECDSA with SHA256": { hash: "SHA-256" }, "ECDSA with SHA384": { hash: "SHA-384" },
  "ECDSA with SHA512": { hash: "SHA-512" },
};

function signatureOptions(p: CryptoParams, key: KeyObject): { hash: string; options: Record<string, unknown> } {
  const dsa = p.digitalSignatureAlgorithm;
  let hash: string;
  let pss = false;
  if (dsa !== undefined) {
    if (dsa === "RSASSA-PSS (PKCS#1 v2.1)") {
      hash = hashOf(p.hashingAlgorithm);
      pss = true;
    } else {
      const entry = SIGNATURE_ALGORITHMS[dsa];
      if (entry === undefined) throw new KmsError("Feature Not Supported", `${dsa} is not supported`);
      hash = hashOf(entry.hash);
    }
  } else {
    // Cryptographic Parameters (3.6) carry a Digital Signature Algorithm, or a
    // Hashing Algorithm with a Padding Method.
    if (p.hashingAlgorithm === undefined) {
      throw new KmsError("Invalid Field", "a signature needs a Digital Signature Algorithm or a Hashing Algorithm");
    }
    hash = hashOf(p.hashingAlgorithm);
    pss = p.paddingMethod === "PSS";
  }
  const options: Record<string, unknown> = { key };
  if (key.asymmetricKeyType === "rsa" && pss) {
    options.padding = constants.RSA_PKCS1_PSS_PADDING;
    options.saltLength = constants.RSA_PSS_SALTLEN_DIGEST;
  }
  return { hash, options };
}

export function signData(key: KeyObject, p: CryptoParams, data: Buffer): Buffer {
  const { hash, options } = signatureOptions(p, key);
  try {
    return nodeSign(hash, data, options as unknown as KeyObject);
  } catch {
    throw new KmsError("Cryptographic Failure", "the signature could not be made with this key and these parameters");
  }
}

export function verifyData(key: KeyObject, p: CryptoParams, data: Buffer, signature: Buffer): boolean {
  const { hash, options } = signatureOptions(p, key);
  try {
    return nodeVerify(hash, data, options as unknown as KeyObject, signature);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// MAC

const HMACS: Record<string, string> = {
  "HMAC-SHA1": "sha1", "HMAC-SHA224": "sha224", "HMAC-SHA256": "sha256", "HMAC-SHA384": "sha384",
  "HMAC-SHA512": "sha512", "HMAC-MD5": "md5",
};

export function mac(key: Buffer, algorithm: string | undefined, data: Buffer): Buffer {
  const h = HMACS[algorithm ?? ""];
  if (h === undefined) {
    throw new KmsError("Feature Not Supported", `the MAC algorithm ${algorithm ?? "(none)"} is not supported`);
  }
  return createHmac(h, key).update(data).digest();
}

export const macMatches = (a: Buffer, b: Buffer): boolean => a.length === b.length && timingSafeEqual(a, b);

// ---------------------------------------------------------------------------
// Symmetric encryption

export interface CipherResult {
  data: Buffer;
  iv?: Buffer;
  tag?: Buffer;
}

const AES_MODES: Record<string, string> = { CBC: "cbc", ECB: "ecb", GCM: "gcm", CTR: "ctr", CFB: "cfb", OFB: "ofb" };

function aesName(key: Buffer, mode: string): string {
  if (![16, 24, 32].includes(key.length)) throw new KmsError("Cryptographic Failure", "an AES key is 128, 192 or 256 bits");
  return `aes-${key.length * 8}-${AES_MODES[mode]}`;
}

function ivLengthOf(p: CryptoParams, mode: string): number {
  return p.ivLength !== undefined ? p.ivLength / 8 : mode === "GCM" ? 12 : 16;
}

export function aesEncrypt(key: Buffer, p: CryptoParams, data: Buffer, given: { iv?: Buffer; aad?: Buffer }): CipherResult {
  const mode = p.blockCipherMode;
  if (mode === "NISTKeyWrap" || mode === "AESKeyWrapPadding") return { data: wrapAes(key, mode, data) };
  if (mode === undefined || AES_MODES[mode] === undefined) {
    throw new KmsError(mode === undefined ? "Invalid Field" : "Feature Not Supported",
      `the block cipher mode ${mode ?? "(none)"} is not supported`);
  }
  let iv: Buffer | undefined;
  let generated = false;
  if (mode !== "ECB") {
    if (given.iv !== undefined) iv = given.iv;
    else if (p.randomIV) {
      iv = randomBytes(ivLengthOf(p, mode));
      generated = true;
    } else {
      throw new KmsError("Missing Data", `${mode} needs an IV/Counter/Nonce, or Random IV`);
    }
  }
  const padding = p.paddingMethod ?? (mode === "CBC" || mode === "ECB" ? "PKCS5" : "None");
  try {
    const c = createCipheriv(aesName(key, mode), key, iv ?? null,
      mode === "GCM" ? { authTagLength: (p.tagLength ?? 16) } : undefined);
    if (mode === "CBC" || mode === "ECB") c.setAutoPadding(padding === "PKCS5");
    if (given.aad !== undefined) {
      if (mode !== "GCM") throw new KmsError("Invalid Field", "additional data applies to GCM");
      c.setAAD(given.aad);
    }
    const out = Buffer.concat([c.update(data), c.final()]);
    return { data: out, ...(generated ? { iv } : {}), ...(mode === "GCM" ? { tag: c.getAuthTag() } : {}) };
  } catch (e) {
    if (e instanceof KmsError) throw e;
    throw new KmsError("Cryptographic Failure", String((e as Error).message));
  }
}

export function aesDecrypt(key: Buffer, p: CryptoParams, data: Buffer, given: { iv?: Buffer; aad?: Buffer; tag?: Buffer }): Buffer {
  const mode = p.blockCipherMode;
  if (mode === "NISTKeyWrap" || mode === "AESKeyWrapPadding") return unwrapAes(key, mode, data);
  if (mode === undefined || AES_MODES[mode] === undefined) {
    throw new KmsError(mode === undefined ? "Invalid Field" : "Feature Not Supported",
      `the block cipher mode ${mode ?? "(none)"} is not supported`);
  }
  if (mode !== "ECB" && given.iv === undefined) {
    throw new KmsError("Missing Data", `${mode} needs the IV/Counter/Nonce it was encrypted with`);
  }
  const padding = p.paddingMethod ?? (mode === "CBC" || mode === "ECB" ? "PKCS5" : "None");
  try {
    const d = createDecipheriv(aesName(key, mode), key, given.iv ?? null,
      mode === "GCM" ? { authTagLength: given.tag?.length ?? p.tagLength ?? 16 } : undefined);
    if (mode === "CBC" || mode === "ECB") d.setAutoPadding(padding === "PKCS5");
    if (mode === "GCM") {
      if (given.tag === undefined) throw new KmsError("Missing Data", "GCM decryption needs the Authenticated Encryption Tag");
      if (given.aad !== undefined) d.setAAD(given.aad);
      d.setAuthTag(given.tag);
    }
    return Buffer.concat([d.update(data), d.final()]);
  } catch (e) {
    if (e instanceof KmsError) throw e;
    // Includes a tag that does not authenticate.
    throw new KmsError("Cryptographic Failure", "the data does not decrypt with this key and these parameters");
  }
}

/** NISTKeyWrap (RFC 3394) or AESKeyWrapPadding (RFC 5649). */
export function wrapAes(kek: Buffer, mode: string, data: Buffer): Buffer {
  try {
    if (mode === "NISTKeyWrap") return aesKeyWrap(kek, data);
    const c = createCipheriv(`id-aes${kek.length * 8}-wrap-pad`, kek, Buffer.from("A65959A6", "hex"));
    return Buffer.concat([c.update(data), c.final()]);
  } catch (e) {
    throw new KmsError("Cryptographic Failure", `the data cannot be wrapped by ${mode}: ${(e as Error).message}`);
  }
}

export function unwrapAes(kek: Buffer, mode: string, data: Buffer): Buffer {
  try {
    if (mode === "NISTKeyWrap") return aesKeyUnwrap(kek, data);
    const d = createDecipheriv(`id-aes${kek.length * 8}-wrap-pad`, kek, Buffer.from("A65959A6", "hex"));
    return Buffer.concat([d.update(data), d.final()]);
  } catch {
    throw new KmsError("Cryptographic Failure", `the data does not unwrap by ${mode} under this key`);
  }
}

// ---------------------------------------------------------------------------
// RSA encryption

function rsaPadding(p: CryptoParams): Record<string, unknown> {
  if (p.paddingMethod === "OAEP") {
    // OAEP by the Hashing Algorithm given, SHA-1 where none is.
    return { padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: hashOf(p.hashingAlgorithm, "SHA-1") };
  }
  if (p.paddingMethod === "PKCS1 v1.5") return { padding: constants.RSA_PKCS1_PADDING };
  throw new KmsError("Invalid Field", "RSA encryption needs a Padding Method of OAEP or PKCS1 v1.5");
}

export function rsaEncrypt(key: KeyObject, p: CryptoParams, data: Buffer): Buffer {
  try {
    return publicEncrypt({ key, ...rsaPadding(p) } as never, data);
  } catch (e) {
    if (e instanceof KmsError) throw e;
    throw new KmsError("Cryptographic Failure", "the data cannot be encrypted with this key");
  }
}

export function rsaDecrypt(key: KeyObject, p: CryptoParams, data: Buffer): Buffer {
  try {
    return privateDecrypt({ key, ...rsaPadding(p) } as never, data);
  } catch (e) {
    if (e instanceof KmsError) throw e;
    throw new KmsError("Cryptographic Failure", "the data does not decrypt with this key");
  }
}
