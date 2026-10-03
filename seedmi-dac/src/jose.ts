// JSON Object Signing and Encryption, as much of it as this server needs:
// JSON Web Signature (RFC 7515), JSON Web Encryption (RFC 7516), JSON Web Key
// (RFC 7517) and the algorithms of RFC 7518, in the compact and the JSON
// serializations.
//
// It is used by delegated access control (the Delegated access control
// subclause of the CDMI draft), where a request is encrypted to the provider
// and signed by this server, and a response is encrypted to this server and
// signed by the provider. The algorithms every CDMI server implements are
// those of the draft's Cryptographic algorithms subclause:
//
//   JWS signature          ES256 and RS256
//   JWE key management     ECDH-ES+A128KW and RSA-OAEP-256
//   JWE content encryption A256GCM
//
// Others are read where a counterparty uses them, and are listed in ALGORITHMS
// below; none is produced unless it is asked for by name.
//
// Three requirements of that subclause are applied by this module, so that no
// caller can omit them:
//
//   * an "alg" of "none" is neither produced nor accepted, whatever else the
//     structure contains;
//   * the algorithm is determined by the key the caller expects, and not by the
//     "alg" header parameter of the structure received; where that parameter
//     names another algorithm the structure is rejected; and
//   * the structure is verified, or decrypted, before its content is returned.

import {
  createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, constants,
  diffieHellman, generateKeyPairSync, type KeyObject, privateDecrypt, publicEncrypt, randomBytes,
  sign as nodeSign, verify as nodeVerify, X509Certificate,
} from "node:crypto";
import { aesKeyUnwrap, aesKeyWrap } from "./aes-kw.ts";

/** A structure that does not conform, or that this module will not produce. */
export class JoseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JoseError";
  }
}

// ---------------------------------------------------------------------------
// base64url (RFC 7515 Appendix C)

export const b64u = (b: Buffer | string): string =>
  (typeof b === "string" ? Buffer.from(b, "utf8") : b).toString("base64url");

export function unb64u(s: string): Buffer {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new JoseError("a base64url value holds other characters");
  return Buffer.from(s, "base64url");
}

const json = (o: unknown): Buffer => Buffer.from(JSON.stringify(o), "utf8");

function parseJson(b: Buffer, what: string): Record<string, unknown> {
  let v: unknown;
  try {
    v = JSON.parse(b.toString("utf8"));
  } catch {
    throw new JoseError(`${what} is not JSON`);
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new JoseError(`${what} is not a JSON object`);
  return v as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// JSON Web Key (RFC 7517)

export interface Jwk {
  kty: string;
  kid?: string;
  use?: string;
  alg?: string;
  crv?: string;
  /** X.509 certificate chain, each a base64 (not base64url) DER certificate. */
  x5c?: string[];
  [parameter: string]: unknown;
}

const CURVES: Record<string, string> = { "P-256": "prime256v1", "P-384": "secp384r1", "P-521": "secp521r1" };
const CURVE_OF: Record<string, string> = { prime256v1: "P-256", secp384r1: "P-384", secp521r1: "P-521" };
const COORDINATE_OCTETS: Record<string, number> = { "P-256": 32, "P-384": 48, "P-521": 66 };

/** Whether a JWK holds the private parameters of its key type. */
export const isPrivateJwk = (jwk: Jwk): boolean =>
  (jwk.kty === "RSA" || jwk.kty === "EC") && typeof jwk.d === "string";

/**
 * The key a JWK holds, as a Node key object. A JWK with private parameters
 * yields a private key; one without, a public key.
 */
export function importJwk(jwk: Jwk): KeyObject {
  try {
    if (jwk.kty === "oct") {
      throw new JoseError("a symmetric key is not used by this module");
    }
    if (jwk.kty !== "RSA" && jwk.kty !== "EC") throw new JoseError(`a key of type ${jwk.kty} is not supported`);
    if (jwk.kty === "EC" && CURVES[String(jwk.crv)] === undefined) {
      throw new JoseError(`the curve ${String(jwk.crv)} is not supported`);
    }
    // Node reads a JWK directly, and checks the parameters of each type.
    return isPrivateJwk(jwk)
      ? createPrivateKey({ key: jwk as never, format: "jwk" })
      : createPublicKey({ key: jwk as never, format: "jwk" });
  } catch (e) {
    if (e instanceof JoseError) throw e;
    throw new JoseError(`the JSON Web Key does not parse: ${(e as Error).message}`);
  }
}

/** The public JWK of a key, with the members given added to it. */
export function exportJwk(key: KeyObject, members: Partial<Jwk> = {}): Jwk {
  const pub = key.type === "private" ? createPublicKey(key) : key;
  return { ...(pub.export({ format: "jwk" }) as unknown as Jwk), ...members };
}

/**
 * The certificates of the "x5c" parameter of a JWK, first the one holding the
 * key. The chain is not validated here; a caller that relies upon it says what
 * it requires of it.
 */
export function chainOf(jwk: Jwk): X509Certificate[] {
  const x5c = jwk.x5c;
  if (x5c === undefined) return [];
  if (!Array.isArray(x5c) || x5c.some((c) => typeof c !== "string")) {
    throw new JoseError("the x5c parameter is an array of strings");
  }
  try {
    return (x5c as string[]).map((c) => new X509Certificate(Buffer.from(c, "base64")));
  } catch (e) {
    throw new JoseError(`a certificate of the x5c parameter does not parse: ${(e as Error).message}`);
  }
}

/** Whether the public key of a JWK is the public key of the first certificate of its chain. */
export function chainMatchesKey(jwk: Jwk): boolean {
  const chain = chainOf(jwk);
  if (chain.length === 0) return false;
  const inChain = chain[0].publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const inKey = importJwk({ ...jwk, d: undefined } as Jwk).export({ format: "der", type: "spki" }) as Buffer;
  return inChain.equals(inKey);
}

// ---------------------------------------------------------------------------
// Algorithms

interface SignatureAlgorithm {
  kind: "signature";
  keyType: "rsa" | "ec";
  curve?: string;
  hash: string;
  /** A signature of this algorithm is the concatenation of r and s, of this length each. */
  raw?: number;
  produce: boolean;
}

interface KeyManagementAlgorithm {
  kind: "key";
  keyType: "rsa" | "ec";
  oaepHash?: string;
  /** The length in octets of the key the agreement wraps with, where it wraps. */
  wrap?: number;
  produce: boolean;
}

interface ContentAlgorithm {
  kind: "content";
  cipher: string;
  keyOctets: number;
  ivOctets: number;
  tagOctets: number;
  produce: boolean;
}

/**
 * The algorithms this module reads, and whether it produces them. Those the
 * draft requires of every CDMI server are produced; the others are read alone,
 * so that a structure from a counterparty is understood without this server
 * choosing an algorithm the draft does not require.
 */
export const ALGORITHMS: Record<string, SignatureAlgorithm | KeyManagementAlgorithm | ContentAlgorithm> = {
  // JWS (RFC 7518 section 3).
  RS256: { kind: "signature", keyType: "rsa", hash: "sha256", produce: true },
  RS384: { kind: "signature", keyType: "rsa", hash: "sha384", produce: false },
  RS512: { kind: "signature", keyType: "rsa", hash: "sha512", produce: false },
  ES256: { kind: "signature", keyType: "ec", curve: "P-256", hash: "sha256", raw: 32, produce: true },
  ES384: { kind: "signature", keyType: "ec", curve: "P-384", hash: "sha384", raw: 48, produce: false },
  ES512: { kind: "signature", keyType: "ec", curve: "P-521", hash: "sha512", raw: 66, produce: false },
  // JWE key management (RFC 7518 sections 4.3 and 4.6).
  "RSA-OAEP-256": { kind: "key", keyType: "rsa", oaepHash: "sha256", produce: true },
  "RSA-OAEP": { kind: "key", keyType: "rsa", oaepHash: "sha1", produce: false },
  "ECDH-ES+A128KW": { kind: "key", keyType: "ec", wrap: 16, produce: true },
  "ECDH-ES+A192KW": { kind: "key", keyType: "ec", wrap: 24, produce: false },
  "ECDH-ES+A256KW": { kind: "key", keyType: "ec", wrap: 32, produce: false },
  // JWE content encryption (RFC 7518 section 5.3).
  A256GCM: { kind: "content", cipher: "aes-256-gcm", keyOctets: 32, ivOctets: 12, tagOctets: 16, produce: true },
  A192GCM: { kind: "content", cipher: "aes-192-gcm", keyOctets: 24, ivOctets: 12, tagOctets: 16, produce: false },
  A128GCM: { kind: "content", cipher: "aes-128-gcm", keyOctets: 16, ivOctets: 12, tagOctets: 16, produce: false },
};

function algorithm<T extends { kind: string; produce: boolean }>(name: string, kind: T["kind"], producing: boolean): T {
  if (name === "none") {
    // "A CDMI server shall not produce a JSON Web Signature whose alg header
    // parameter is none, and shall reject one it receives, whatever else that
    // structure contains."
    throw new JoseError('"none" is the Unsecured JWS of RFC 7515 and is not a signature');
  }
  const a = ALGORITHMS[name];
  if (a === undefined || a.kind !== kind) throw new JoseError(`${name} is not an algorithm this server uses here`);
  if (producing && !a.produce) throw new JoseError(`${name} is read by this server and not produced`);
  return a as unknown as T;
}

const keyTypeOf = (key: KeyObject): "rsa" | "ec" => {
  const t = key.asymmetricKeyType;
  if (t === "rsa" || t === "rsa-pss") return "rsa";
  if (t === "ec") return "ec";
  throw new JoseError(`a key of type ${String(t)} is not used here`);
};

const curveOf = (key: KeyObject): string => {
  const named = (key.asymmetricKeyDetails?.namedCurve ?? "") as string;
  const crv = CURVE_OF[named];
  if (crv === undefined) throw new JoseError(`the curve ${named} is not supported`);
  return crv;
};

/**
 * The algorithm expected for a key: the one the draft requires this server to
 * implement for that kind of key. A structure that names another algorithm is
 * rejected, whatever its header says.
 */
export function expectedSignatureAlgorithm(key: KeyObject): string {
  return keyTypeOf(key) === "rsa" ? "RS256" : ({ "P-256": "ES256", "P-384": "ES384", "P-521": "ES512" })[curveOf(key)]!;
}

export function expectedKeyAlgorithm(key: KeyObject): string {
  return keyTypeOf(key) === "rsa" ? "RSA-OAEP-256" : "ECDH-ES+A128KW";
}

// ---------------------------------------------------------------------------
// JSON Web Signature (RFC 7515)

export interface JwsHeader {
  alg?: string;
  kid?: string;
  cty?: string;
  typ?: string;
  jwk?: Jwk;
  [parameter: string]: unknown;
}

/**
 * An ECDSA signature from the DER form Node produces to the r || s form JOSE
 * carries, each coordinate padded to its length (RFC 7518 section 3.4).
 * Exported so that the padding is tested on a coordinate shorter than its
 * length, which arises in about one signature in 256 and so is not reached
 * reliably by signing.
 */
export function rawSignature(der: Buffer, octets: number): Buffer {
  // An ECDSA signature in JOSE is r || s, each of the coordinate length; Node
  // produces and takes DER, so the two forms are converted here (RFC 7518 3.4).
  const out = Buffer.alloc(octets * 2);
  let at = 2;
  if (der[1] & 0x80) at += der[1] & 0x7f;
  for (const half of [0, 1]) {
    if (der[at] !== 0x02) throw new JoseError("an ECDSA signature does not parse");
    const len = der[at + 1];
    let value = der.subarray(at + 2, at + 2 + len);
    at += 2 + len;
    if (value.length > octets) value = value.subarray(value.length - octets);
    value.copy(out, half * octets + (octets - value.length));
  }
  return out;
}

/** The converse of rawSignature. */
export function derSignature(raw: Buffer, octets: number): Buffer {
  if (raw.length !== octets * 2) throw new JoseError("an ECDSA signature is of the wrong length");
  const integer = (b: Buffer): Buffer => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    const v = b.subarray(i);
    const body = (v[0] & 0x80) ? Buffer.concat([Buffer.from([0]), v]) : v;
    return Buffer.concat([Buffer.from([0x02, body.length]), body]);
  };
  const body = Buffer.concat([integer(raw.subarray(0, octets)), integer(raw.subarray(octets))]);
  const head = body.length < 0x80
    ? Buffer.from([0x30, body.length])
    : Buffer.concat([Buffer.from([0x30, 0x81]), Buffer.from([body.length])]);
  return Buffer.concat([head, body]);
}

function signInput(protectedHeader: string, payload: string): Buffer {
  return Buffer.from(`${protectedHeader}.${payload}`, "ascii");
}

/** Signs a payload, returning the protected header, payload and signature, each base64url. */
function signParts(payload: Buffer, key: KeyObject, header: JwsHeader): { protected: string; payload: string; signature: string } {
  const alg = header.alg ?? expectedSignatureAlgorithm(key);
  const a = algorithm<SignatureAlgorithm>(alg, "signature", true);
  if (keyTypeOf(key) !== a.keyType) throw new JoseError(`${alg} is not an algorithm of this key`);
  if (a.curve !== undefined && curveOf(key) !== a.curve) throw new JoseError(`${alg} is not an algorithm of this curve`);
  if (key.type !== "private") throw new JoseError("signing needs a private key");
  const protectedHeader = b64u(json({ ...header, alg }));
  const encoded = b64u(payload);
  let signature = nodeSign(a.hash, signInput(protectedHeader, encoded), key);
  if (a.raw !== undefined) signature = rawSignature(signature, a.raw);
  return { protected: protectedHeader, payload: encoded, signature: b64u(signature) };
}

/**
 * A JWS in compact serialization whose private key is held elsewhere and
 * operated in place: the signature over the signing input is made by `sign`,
 * given the JWS algorithm, and returned as the key management server makes it
 * (DER for ECDSA, which is converted here). `publicKey` is the public half, from
 * which the algorithm is determined.
 */
export async function signJwsWith(payload: Buffer, publicKey: KeyObject,
  sign: (alg: string, input: Buffer) => Promise<Buffer>, header: JwsHeader = {}): Promise<string> {
  const alg = header.alg ?? expectedSignatureAlgorithm(publicKey);
  const a = algorithm<SignatureAlgorithm>(alg, "signature", true);
  if (keyTypeOf(publicKey) !== a.keyType) throw new JoseError(`${alg} is not an algorithm of this key`);
  if (a.curve !== undefined && curveOf(publicKey) !== a.curve) throw new JoseError(`${alg} is not an algorithm of this curve`);
  const protectedHeader = b64u(json({ ...header, alg }));
  const encoded = b64u(payload);
  let signature = await sign(alg, signInput(protectedHeader, encoded));
  if (a.raw !== undefined) signature = rawSignature(signature, a.raw);
  return `${protectedHeader}.${encoded}.${b64u(signature)}`;
}

/** A JWS in compact serialization (RFC 7515 section 7.1). */
export function signJws(payload: Buffer, key: KeyObject, header: JwsHeader = {}): string {
  const p = signParts(payload, key, header);
  return `${p.protected}.${p.payload}.${p.signature}`;
}

/** A JWS in flattened JSON serialization (RFC 7515 section 7.2.2). */
export function signJwsJson(payload: Buffer, key: KeyObject, header: JwsHeader = {}): Record<string, string> {
  return signParts(payload, key, header);
}

export interface VerifiedJws {
  payload: Buffer;
  header: JwsHeader;
}

/**
 * Verifies a JWS, in either serialization, with the key expected. The algorithm
 * is the one expected for that key unless `alg` names another this module
 * reads; a structure naming any other is rejected before its payload is read.
 */
export function verifyJws(jws: string | Record<string, unknown>, key: KeyObject, opts: { alg?: string } = {}): VerifiedJws {
  let protectedHeader: string;
  let payload: string;
  let signature: string;
  if (typeof jws === "string") {
    const parts = jws.split(".");
    if (parts.length !== 3) throw new JoseError("a JWS in compact serialization has three parts");
    [protectedHeader, payload, signature] = parts;
  } else {
    const flat = jws.signatures === undefined ? jws : (jws.signatures as Record<string, unknown>[])[0];
    if (flat === undefined) throw new JoseError("a JWS in JSON serialization has a signature");
    for (const name of ["protected", "signature"]) {
      if (typeof flat[name] !== "string") throw new JoseError(`a JWS in JSON serialization has a ${name} member`);
    }
    protectedHeader = flat.protected as string;
    signature = flat.signature as string;
    if (typeof jws.payload !== "string") throw new JoseError("a JWS in JSON serialization has a payload member");
    payload = jws.payload;
  }
  const header = parseJson(unb64u(protectedHeader), "a JWS protected header") as JwsHeader;
  const expected = opts.alg ?? expectedSignatureAlgorithm(key);
  const a = algorithm<SignatureAlgorithm>(expected, "signature", false);
  // The algorithm comes from the key expected; the header parameter is checked
  // against it and never used to choose.
  if (header.alg !== expected) {
    throw new JoseError(`the signature states ${String(header.alg)}, and ${expected} is expected for this key`);
  }
  if (keyTypeOf(key) !== a.keyType) throw new JoseError(`${expected} is not an algorithm of this key`);
  let raw = unb64u(signature);
  if (a.raw !== undefined) raw = derSignature(raw, a.raw);
  const pub = key.type === "private" ? createPublicKey(key) : key;
  if (!nodeVerify(a.hash, signInput(protectedHeader, payload), pub, raw)) {
    throw new JoseError("the signature does not verify");
  }
  return { payload: unb64u(payload), header };
}

// ---------------------------------------------------------------------------
// JSON Web Encryption (RFC 7516)

export interface JweHeader {
  alg?: string;
  enc?: string;
  kid?: string;
  cty?: string;
  apu?: string;
  apv?: string;
  epk?: Jwk;
  [parameter: string]: unknown;
}

/** The Concat KDF of RFC 7518 section 4.6.2, one round, which suffices to 256 bits. */
function concatKdf(secret: Buffer, octets: number, algorithmId: string, apu: Buffer, apv: Buffer): Buffer {
  const lengthPrefixed = (b: Buffer): Buffer => {
    const n = Buffer.alloc(4);
    n.writeUInt32BE(b.length);
    return Buffer.concat([n, b]);
  };
  const supp = Buffer.alloc(4);
  supp.writeUInt32BE(octets * 8);
  const counter = Buffer.from([0, 0, 0, 1]);
  const hash = createHash("sha256")
    .update(counter).update(secret)
    .update(lengthPrefixed(Buffer.from(algorithmId, "ascii")))
    .update(lengthPrefixed(apu)).update(lengthPrefixed(apv))
    .update(supp)
    .digest();
  if (octets > hash.length) throw new JoseError("the key derivation is of one round here");
  return hash.subarray(0, octets);
}

interface JweParts {
  protected: string;
  encrypted_key: string;
  iv: string;
  ciphertext: string;
  tag: string;
}

function encryptParts(plaintext: Buffer, key: KeyObject, header: JweHeader): JweParts {
  const alg = header.alg ?? expectedKeyAlgorithm(key);
  const enc = header.enc ?? "A256GCM";
  const a = algorithm<KeyManagementAlgorithm>(alg, "key", true);
  const c = algorithm<ContentAlgorithm>(enc, "content", true);
  const pub = key.type === "private" ? createPublicKey(key) : key;
  if (keyTypeOf(pub) !== a.keyType) throw new JoseError(`${alg} is not an algorithm of this key`);
  const cek = randomBytes(c.keyOctets);
  let encryptedKey = Buffer.alloc(0);
  const full: JweHeader = { ...header, alg, enc };
  if (a.keyType === "rsa") {
    encryptedKey = publicEncrypt({ key: pub, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: a.oaepHash } as never, cek);
  } else {
    // ECDH-ES with key wrapping (RFC 7518 section 4.6): an ephemeral key of the
    // recipient's curve, the agreed secret through the Concat KDF, and the
    // content encryption key wrapped with the result.
    const ephemeral = generateKeyPairSync("ec", { namedCurve: CURVES[curveOf(pub)] });
    const secret = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: pub });
    const apu = header.apu === undefined ? Buffer.alloc(0) : unb64u(String(header.apu));
    const apv = header.apv === undefined ? Buffer.alloc(0) : unb64u(String(header.apv));
    const wrapping = concatKdf(secret, a.wrap!, alg, apu, apv);
    encryptedKey = aesKeyWrap(wrapping, cek);
    full.epk = exportJwk(ephemeral.publicKey);
  }
  const protectedHeader = b64u(json(full));
  const iv = randomBytes(c.ivOctets);
  const cipher = createCipheriv(c.cipher, cek, iv, { authTagLength: c.tagOctets });
  cipher.setAAD(Buffer.from(protectedHeader, "ascii"));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    protected: protectedHeader, encrypted_key: b64u(encryptedKey), iv: b64u(iv),
    ciphertext: b64u(ciphertext), tag: b64u(cipher.getAuthTag()),
  };
}

/** A JWE in compact serialization (RFC 7516 section 7.1). */
export function encryptJwe(plaintext: Buffer, key: KeyObject, header: JweHeader = {}): string {
  const p = encryptParts(plaintext, key, header);
  return `${p.protected}.${p.encrypted_key}.${p.iv}.${p.ciphertext}.${p.tag}`;
}

/** A JWE in flattened JSON serialization (RFC 7516 section 7.2.2). */
export function encryptJweJson(plaintext: Buffer, key: KeyObject, header: JweHeader = {}): Record<string, string> {
  return { ...encryptParts(plaintext, key, header) };
}

export interface DecryptedJwe {
  plaintext: Buffer;
  header: JweHeader;
}

/**
 * Decrypts a JWE, in either serialization, with the private key expected. As
 * for a signature, the key management algorithm is the one expected for that
 * key unless another this module reads is named, and the structure is
 * authenticated before its plaintext is returned.
 */
/** The five parts of a JWE, in either serialization. */
function jweParts(jwe: string | Record<string, unknown>): JweParts {
  if (typeof jwe === "string") {
    const five = jwe.split(".");
    if (five.length !== 5) throw new JoseError("a JWE in compact serialization has five parts");
    return { protected: five[0], encrypted_key: five[1], iv: five[2], ciphertext: five[3], tag: five[4] };
  }
  const flat = jwe.recipients === undefined ? jwe : { ...jwe, ...(jwe.recipients as Record<string, unknown>[])[0] };
  const take = (name: string, required: boolean): string => {
    const v = flat[name];
    if (v === undefined) {
      if (required) throw new JoseError(`a JWE in JSON serialization has a ${name} member`);
      return "";
    }
    if (typeof v !== "string") throw new JoseError(`the ${name} member of a JWE is a string`);
    return v;
  };
  return {
    protected: take("protected", true), encrypted_key: take("encrypted_key", false), iv: take("iv", true),
    ciphertext: take("ciphertext", true), tag: take("tag", true),
  };
}

/** The header and algorithms of a JWE, checked against those the key expects. */
function jweAlgorithms(parts: JweParts, key: KeyObject, opts: { alg?: string }):
  { header: JweHeader; expected: string; a: KeyManagementAlgorithm; c: ContentAlgorithm } {
  const header = parseJson(unb64u(parts.protected), "a JWE protected header") as JweHeader;
  const expected = opts.alg ?? expectedKeyAlgorithm(key);
  const a = algorithm<KeyManagementAlgorithm>(expected, "key", false);
  if (header.alg !== expected) {
    throw new JoseError(`the encryption states ${String(header.alg)}, and ${expected} is expected for this key`);
  }
  if (keyTypeOf(key) !== a.keyType) throw new JoseError(`${expected} is not an algorithm of this key`);
  const c = algorithm<ContentAlgorithm>(String(header.enc), "content", false);
  return { header, expected, a, c };
}

/** The plaintext of a JWE, given its content encryption key. */
function jweContent(parts: JweParts, header: JweHeader, c: ContentAlgorithm, cek: Buffer): DecryptedJwe {
  if (cek.length !== c.keyOctets) throw new JoseError(`a ${String(header.enc)} key is ${c.keyOctets} octets`);
  try {
    const decipher = createDecipheriv(c.cipher, cek, unb64u(parts.iv), { authTagLength: c.tagOctets });
    decipher.setAAD(Buffer.from(parts.protected, "ascii"));
    decipher.setAuthTag(unb64u(parts.tag));
    const plaintext = Buffer.concat([decipher.update(unb64u(parts.ciphertext)), decipher.final()]);
    return { plaintext, header };
  } catch (e) {
    if (e instanceof JoseError) throw e;
    // Includes an authentication tag that does not authenticate.
    throw new JoseError("the ciphertext does not decrypt");
  }
}

export function decryptJwe(jwe: string | Record<string, unknown>, key: KeyObject, opts: { alg?: string } = {}): DecryptedJwe {
  const parts = jweParts(jwe);
  const { header, expected, a, c } = jweAlgorithms(parts, key, opts);
  if (key.type !== "private") throw new JoseError("decryption needs a private key");
  let cek: Buffer;
  if (a.keyType === "rsa") {
    try {
      cek = privateDecrypt({ key, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: a.oaepHash } as never,
        unb64u(parts.encrypted_key));
    } catch {
      throw new JoseError("the encrypted key does not decrypt with this key");
    }
  } else {
    if (header.epk === undefined) throw new JoseError("an ECDH-ES structure carries an ephemeral public key");
    const epk = importJwk(header.epk);
    if (curveOf(epk) !== curveOf(key)) throw new JoseError("the ephemeral key is of another curve");
    const secret = diffieHellman({ privateKey: key, publicKey: epk });
    const apu = header.apu === undefined ? Buffer.alloc(0) : unb64u(String(header.apu));
    const apv = header.apv === undefined ? Buffer.alloc(0) : unb64u(String(header.apv));
    const wrapping = concatKdf(secret, a.wrap!, expected, apu, apv);
    try {
      cek = aesKeyUnwrap(wrapping, unb64u(parts.encrypted_key));
    } catch {
      throw new JoseError("the encrypted key does not unwrap");
    }
  }
  return jweContent(parts, header, c, cek);
}

/**
 * Decrypts a JWE whose private key is held elsewhere and operated in place:
 * the content encryption key is unwrapped by `unwrap`, given the encrypted key
 * and the OAEP hash the algorithm states, and the content is then decrypted
 * here with that key, which is the key of this one message. `publicKey` is the
 * public half, from which the algorithm expected is determined.
 *
 * RSA-OAEP only: "Where the key is an RSA key and the sender used RSA-OAEP,
 * Decrypt" (the Use of a credential table). ECDH-ES is a key agreement, which
 * the table gives to Derive Key, and no derivation method of KMIP 1.2 to 1.4
 * performs one (ECR-113A); a structure of that kind is refused.
 */
export async function decryptJweWith(jwe: string | Record<string, unknown>, publicKey: KeyObject,
  unwrap: (encryptedKey: Buffer, oaepHash: string) => Promise<Buffer>, opts: { alg?: string } = {}):
  Promise<DecryptedJwe> {
  const parts = jweParts(jwe);
  const { header, a, c } = jweAlgorithms(parts, publicKey, opts);
  if (a.keyType !== "rsa") {
    throw new JoseError("an ECDH-ES structure is unwrapped by a key agreement, which a key operated in place " +
      "at a KMIP server cannot perform");
  }
  const cek = await unwrap(unb64u(parts.encrypted_key), a.oaepHash!);
  return jweContent(parts, header, c, cek);
}

// ---------------------------------------------------------------------------
// Signed and encrypted together

/**
 * A payload signed by `signingKey` and the signature encrypted to
 * `recipientKey`, as the delegated access control subclause requires of a
 * request and of a response. The JWS is the plaintext of the JWE, and the "cty"
 * header parameter of the JWE states that (RFC 7516 section 5.2).
 */
export function signAndEncrypt(payload: Buffer, signingKey: KeyObject, recipientKey: KeyObject,
  opts: { signHeader?: JwsHeader; encryptHeader?: JweHeader } = {}): Record<string, string> {
  // Revision 269: the JWS in the flattened JSON serialization, and cty "jose+json".
  const jws = signJws(payload, signingKey, opts.signHeader ?? {});
  return encryptJweJson(Buffer.from(JSON.stringify(flattenJws(jws)), "utf8"), recipientKey,
    { cty: "jose+json", ...(opts.encryptHeader ?? {}) });
}

/** The converse: decrypted with `decryptionKey`, then verified with `signatureKey`. */
export function decryptAndVerify(structure: string | Record<string, unknown>, decryptionKey: KeyObject,
  signatureKey: KeyObject, opts: { keyAlg?: string; signatureAlg?: string } = {}): VerifiedJws {
  const inner = decryptJwe(structure, decryptionKey, opts.keyAlg === undefined ? {} : { alg: opts.keyAlg });
  return verifyJws(nestedJws(inner), signatureKey,
    opts.signatureAlg === undefined ? {} : { alg: opts.signatureAlg });
}

/**
 * The flattened JSON serialization of a JWS given in the compact one (RFC 7515
 * section 7.2.2): the same three parts, rearranged, nothing signed again.
 */
export function flattenJws(compact: string): Record<string, string> {
  const parts = compact.split(".");
  if (parts.length !== 3) throw new JoseError("not a JWS in the compact serialization");
  return { protected: parts[0], payload: parts[1], signature: parts[2] };
}

/**
 * The JWS a JWE protects, as CDMI revision 269 requires of delegated access
 * control: "The \"cty\" header parameter of the JWE shall contain
 * \"jose+json\", since the plaintext it protects is a JWS in that
 * serialization", the flattened JSON serialization. A media type compares
 * without case, and "application/" may be omitted (RFC 7515 section 4.1.10).
 * Anything else is refused: a compact JWS, the general serialization, or a
 * plaintext that is not a JWS.
 */
export function nestedJws(d: DecryptedJwe): Record<string, string> {
  const cty = String(d.header.cty ?? "").toLowerCase();
  if (cty !== "jose+json" && cty !== "application/jose+json") {
    throw new JoseError(`the JWE's cty is ${JSON.stringify(d.header.cty)}, not "jose+json"`);
  }
  let o: unknown;
  try { o = JSON.parse(d.plaintext.toString("utf8")); } catch { throw new JoseError("the JWE's plaintext is not JSON"); }
  const j = o as Record<string, unknown>;
  if (j === null || typeof j !== "object" || typeof j.protected !== "string" || typeof j.payload !== "string" ||
      typeof j.signature !== "string" || "signatures" in j) {
    throw new JoseError("the JWE's plaintext is not a JWS in the flattened JSON serialization");
  }
  return { protected: j.protected, payload: j.payload, signature: j.signature };
}
