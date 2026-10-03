// CMS EnvelopedData and AuthEnvelopedData.
//
// An enveloped structure carries a content encrypted under a
// content encryption key, and that key encrypted once for each
// recipient. A recipient decrypts the key it can, then the content.
//
// Two structures rather than one: a cipher that authenticates, such
// as AES-GCM, belongs in AuthEnvelopedData, whose mac field carries
// the authentication tag. Putting an authenticated cipher in an
// EnvelopedData leaves the tag with nowhere to go, so this module
// chooses the structure from the algorithm rather than letting a
// caller pair them wrongly.

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import {
  contentsOf, contextTag, decodeInteger, DERError, encodeInteger,
  encodeOctetString, encodeOID, type Element, expect, isContext, readOne,
  sequence, setOf, TAG, tagNumber,
} from "./der.ts";
import {
  type AlgorithmIdentifier, CONTENT_TYPE, contentOf, decodeAlgorithm,
  decodeCBCParameters, decodeGCMParameters, decodeOIDOf, encodeAlgorithm,
  encodeCBCParameters, encodeContentInfo, encodeGCMParameters, ENCRYPTION,
  KEY_ALGORITHM, NODE_CIPHER,
} from "./cms.ts";

/** Whether a content encryption algorithm authenticates its content. */
export function authenticates(oid: string): boolean {
  return oid === ENCRYPTION["aes-128-gcm"] || oid === ENCRYPTION["aes-192-gcm"] ||
    oid === ENCRYPTION["aes-256-gcm"];
}

/** The length of a content encryption key, in octets. */
export function keyLength(oid: string): number {
  const name = NODE_CIPHER[oid];
  if (name === undefined) throw new DERError("an unknown content encryption algorithm");
  if (name.includes("128")) return 16;
  if (name.includes("192")) return 24;
  return 32;
}

// ---------------------------------------------------------------------
// RecipientInfo

/**
 * A recipient identified by a key held elsewhere.
 *
 *   KEKRecipientInfo ::= SEQUENCE {
 *     version                 CMSVersion,  -- always 4
 *     kekid                   KEKIdentifier,
 *     keyEncryptionAlgorithm  KeyEncryptionAlgorithmIdentifier,
 *     encryptedKey            EncryptedKey }
 *
 * This is the form that suits a key named in a key management
 * server: the identifier travels with the structure and the key
 * itself does not.
 */
export interface KEKRecipient {
  kind: "kek";
  /** The identifier of the key encryption key. */
  keyIdentifier: Buffer;
  keyEncryptionAlgorithm: AlgorithmIdentifier;
  encryptedKey: Buffer;
}

/**
 * A recipient identified by a certificate, whose public key
 * encrypts the content encryption key.
 *
 *   KeyTransRecipientInfo ::= SEQUENCE {
 *     version                 CMSVersion,  -- 0 or 2
 *     rid                     RecipientIdentifier,
 *     keyEncryptionAlgorithm  KeyEncryptionAlgorithmIdentifier,
 *     encryptedKey            EncryptedKey }
 */
export interface KeyTransRecipient {
  kind: "ktri";
  /** The subject key identifier, which is version 2 of the structure. */
  subjectKeyIdentifier: Buffer;
  keyEncryptionAlgorithm: AlgorithmIdentifier;
  encryptedKey: Buffer;
}

export type Recipient = KEKRecipient | KeyTransRecipient;

export function encodeRecipient(r: Recipient): Buffer {
  if (r.kind === "kek") {
    // KEKIdentifier ::= SEQUENCE { keyIdentifier OCTET STRING, ... }
    const kekid = sequence(encodeOctetString(r.keyIdentifier));
    return contextTag(2, sequence(
      encodeInteger(4),
      kekid,
      encodeAlgorithm(r.keyEncryptionAlgorithm),
      encodeOctetString(r.encryptedKey),
    ), false);
  }
  // A subject key identifier is context tag 0 of the choice, and
  // requires version 2.
  return sequence(
    encodeInteger(2),
    contextTag(0, encodeOctetString(r.subjectKeyIdentifier), false),
    encodeAlgorithm(r.keyEncryptionAlgorithm),
    encodeOctetString(r.encryptedKey),
  );
}

export function decodeRecipient(e: Element): Recipient {
  // A KeyTransRecipientInfo is the untagged alternative of the
  // choice; every other alternative carries a context tag.
  // The whole identifier octet is compared: TAG.SEQUENCE carries
  // the constructed bit, which tagNumber strips.
  if (e.tag === TAG.SEQUENCE) {
    const parts = contentsOf(e);
    if (parts.length !== 4) {
      throw new DERError("a KeyTransRecipientInfo is four elements");
    }
    const version = Number(decodeInteger(parts[0]));
    if (version !== 2) {
      throw new DERError(
        "this CDMI server reads a KeyTransRecipientInfo of version 2, which " +
        "identifies the recipient by subject key identifier");
    }
    if (!isContext(parts[1], 0)) {
      throw new DERError("a recipient identified by issuer and serial number");
    }
    return {
      kind: "ktri",
      subjectKeyIdentifier: Buffer.from(parts[1].content),
      keyEncryptionAlgorithm: decodeAlgorithm(parts[2]),
      encryptedKey: Buffer.from(expect(parts[3], TAG.OCTET_STRING).content),
    };
  }
  if (isContext(e, 2)) {
    const parts = contentsOf(e);
    if (parts.length !== 4) throw new DERError("a KEKRecipientInfo is four elements");
    const version = Number(decodeInteger(parts[0]));
    if (version !== 4) throw new DERError("a KEKRecipientInfo is version 4");
    const kekid = contentsOf(expect(parts[1], TAG.SEQUENCE));
    return {
      kind: "kek",
      keyIdentifier: Buffer.from(expect(kekid[0], TAG.OCTET_STRING).content),
      keyEncryptionAlgorithm: decodeAlgorithm(parts[2]),
      encryptedKey: Buffer.from(expect(parts[3], TAG.OCTET_STRING).content),
    };
  }
  throw new DERError(
    `a recipient info this CDMI server does not read: tag 0x${e.tag.toString(16)}`);
}

// ---------------------------------------------------------------------
// EncryptedContentInfo

/**
 *   EncryptedContentInfo ::= SEQUENCE {
 *     contentType                 ContentType,
 *     contentEncryptionAlgorithm  ContentEncryptionAlgorithmIdentifier,
 *     encryptedContent            [0] IMPLICIT EncryptedContent OPTIONAL }
 *
 * The encrypted content is implicitly tagged, so its OCTET STRING
 * tag is replaced rather than wrapped.
 */
export interface EncryptedContentInfo {
  contentType: string;
  contentEncryptionAlgorithm: AlgorithmIdentifier;
  encryptedContent?: Buffer;
}

export function encodeEncryptedContentInfo(e: EncryptedContentInfo): Buffer {
  const parts = [encodeOID(e.contentType), encodeAlgorithm(e.contentEncryptionAlgorithm)];
  if (e.encryptedContent !== undefined) {
    parts.push(contextTag(0, encodeOctetString(e.encryptedContent), false));
  }
  return sequence(...parts);
}

export function decodeEncryptedContentInfo(e: Element): EncryptedContentInfo {
  const parts = contentsOf(expect(e, TAG.SEQUENCE));
  if (parts.length < 2 || parts.length > 3) {
    throw new DERError("an EncryptedContentInfo is two or three elements");
  }
  const out: EncryptedContentInfo = {
    contentType: decodeOIDOf(parts[0]),
    contentEncryptionAlgorithm: decodeAlgorithm(parts[1]),
  };
  if (parts.length === 3) {
    if (!isContext(parts[2], 0)) {
      throw new DERError("the encrypted content carries context tag 0");
    }
    out.encryptedContent = Buffer.from(parts[2].content);
  }
  return out;
}

// ---------------------------------------------------------------------
// Enveloping

export interface EnvelopeOptions {
  /** The plaintext. */
  content: Buffer;
  /** The content type of the plaintext, id-data unless stated. */
  contentType?: string;
  /** The content encryption algorithm. */
  algorithm?: keyof typeof ENCRYPTION;
  /** The recipients, and how each receives the content encryption key. */
  recipients: RecipientKey[];
  /** The content encryption key, generated where not supplied. */
  contentKey?: Buffer;
}

/** How one recipient receives the content encryption key. */
export type RecipientKey =
  | {
    kind: "kek";
    /** The identifier of the key encryption key. */
    keyIdentifier: Buffer;
    /** The key encryption key itself, which wraps the content key. */
    key: Buffer;
  }
  | {
    kind: "ktri";
    subjectKeyIdentifier: Buffer;
    /** Encrypts the content key, in the manner of the algorithm. */
    encrypt: (contentKey: Buffer) => Buffer;
    keyEncryptionAlgorithm: AlgorithmIdentifier;
  };

/**
 * Builds an enveloped structure, choosing EnvelopedData or
 * AuthEnvelopedData from the algorithm: an authenticated cipher
 * produces a tag, and only the second structure has a field for it.
 */
export function envelope(o: EnvelopeOptions): Buffer {
  const algorithmName = o.algorithm ?? "aes-256-gcm";
  const oid = ENCRYPTION[algorithmName];
  const cipherName = NODE_CIPHER[oid];
  const contentKey = o.contentKey ?? randomBytes(keyLength(oid));
  if (contentKey.length !== keyLength(oid)) {
    throw new DERError(
      `a content encryption key of ${keyLength(oid)} octets for ${algorithmName}`);
  }
  const contentType = o.contentType ?? CONTENT_TYPE.data;
  const recipients = o.recipients.map((r) => encodeRecipient(wrap(r, contentKey)));

  if (authenticates(oid)) {
    // A nonce of twelve octets, which is the length AES-GCM is
    // defined for and the only one this module produces.
    const nonce = randomBytes(12);
    const cipher = createCipheriv(cipherName, contentKey, nonce, {
      authTagLength: 16,
    });
    const ciphertext = Buffer.concat([cipher.update(o.content), cipher.final()]);
    const tag = cipher.getAuthTag();
    const inner = sequence(
      encodeInteger(0),
      setOf(...recipients),
      encodeEncryptedContentInfo({
        contentType,
        contentEncryptionAlgorithm: {
          algorithm: oid,
          parameters: encodeGCMParameters(nonce, 16),
        },
        encryptedContent: ciphertext,
      }),
      // The authentication tag, which is why this structure and not
      // the other.
      encodeOctetString(tag),
    );
    return encodeContentInfo({
      contentType: CONTENT_TYPE.authEnvelopedData,
      content: inner,
    });
  }

  const iv = randomBytes(16);
  const cipher = createCipheriv(cipherName, contentKey, iv);
  const ciphertext = Buffer.concat([cipher.update(o.content), cipher.final()]);
  const inner = sequence(
    encodeInteger(0),
    setOf(...recipients),
    encodeEncryptedContentInfo({
      contentType,
      contentEncryptionAlgorithm: {
        algorithm: oid,
        parameters: encodeCBCParameters(iv),
      },
      encryptedContent: ciphertext,
    }),
  );
  return encodeContentInfo({
    contentType: CONTENT_TYPE.envelopedData,
    content: inner,
  });
}

/** Encrypts the content key for one recipient. */
function wrap(r: RecipientKey, contentKey: Buffer): Recipient {
  if (r.kind === "ktri") {
    return {
      kind: "ktri",
      subjectKeyIdentifier: r.subjectKeyIdentifier,
      keyEncryptionAlgorithm: r.keyEncryptionAlgorithm,
      encryptedKey: r.encrypt(contentKey),
    };
  }
  return {
    kind: "kek",
    keyIdentifier: r.keyIdentifier,
    keyEncryptionAlgorithm: { algorithm: wrapAlgorithmFor(r.key) },
    encryptedKey: aesKeyWrap(r.key, contentKey),
  };
}

/** The key wrap algorithm of a key encryption key, by its length. */
export function wrapAlgorithmFor(key: Buffer): string {
  if (key.length === 16) return KEY_ALGORITHM["aes-128-wrap"];
  if (key.length === 24) return KEY_ALGORITHM["aes-192-wrap"];
  if (key.length === 32) return KEY_ALGORITHM["aes-256-wrap"];
  throw new DERError("a key encryption key of 16, 24 or 32 octets");
}

// ---------------------------------------------------------------------
// AES key wrap

/**
 * Exclusive-ors the wrap counter into the trailing octets of A. The
 * counter is 64 bits and its upper half is always zero for any key
 * this module wraps, so only the low four octets are written.
 */
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
    throw new DERError("a wrapped key is a whole number of 8-octet blocks, 16 or more");
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
    throw new DERError("a wrapped key is a whole number of 8-octet blocks, 24 or more");
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
    throw new DERError("the wrapped key did not unwrap under this key");
  }
  return Buffer.concat(r);
}

// ---------------------------------------------------------------------
// Opening an envelope

/** What a recipient supplies in order to recover the content key. */
export type RecipientSecret =
  | { kind: "kek"; keyIdentifier: Buffer; key: Buffer }
  | {
    kind: "ktri";
    subjectKeyIdentifier: Buffer;
    decrypt: (encryptedKey: Buffer) => Buffer;
  };

/** The structure of an envelope, read without decrypting it. */
export interface Envelope {
  /** Whether the content is authenticated, and the structure therefore AuthEnvelopedData. */
  authenticated: boolean;
  recipients: Recipient[];
  encryptedContentInfo: EncryptedContentInfo;
  /** The authentication tag, where the structure carries one. */
  mac?: Buffer;
}

/** Reads an envelope, of either structure. */
export function readEnvelope(b: Buffer): Envelope {
  const type = requireEnvelopeType(b);
  const authenticated = type === CONTENT_TYPE.authEnvelopedData;
  const parts = contentsOf(readOne(contentOf(b, type)));
  // version, recipientInfos, encryptedContentInfo, and for the
  // authenticated structure a mac. Neither originatorInfo nor the
  // attribute fields are read by this CDMI server.
  let at = 0;
  const version = Number(decodeInteger(parts[at++]));
  if (version !== 0) {
    throw new DERError(`an enveloped structure of version ${version} is not read`);
  }
  if (isContext(parts[at], 0)) {
    throw new DERError("an originator info is not read by this CDMI server");
  }
  const recipients = contentsOf(expect(parts[at++], TAG.SET)).map(decodeRecipient);
  if (recipients.length === 0) throw new DERError("an envelope with no recipient");
  const encryptedContentInfo = decodeEncryptedContentInfo(parts[at++]);
  let mac: Buffer | undefined;
  if (authenticated) {
    // The authenticated attributes, where present, precede the mac.
    if (at < parts.length && isContext(parts[at], 1)) {
      throw new DERError("authenticated attributes are not read by this CDMI server");
    }
    if (at >= parts.length) throw new DERError("an AuthEnvelopedData with no mac");
    mac = Buffer.from(expect(parts[at++], TAG.OCTET_STRING).content);
  }
  return { authenticated, recipients, encryptedContentInfo, mac };
}

function requireEnvelopeType(b: Buffer): string {
  const info = readOne(b);
  const first = contentsOf(info)[0];
  const type = decodeOIDOf(first);
  if (type !== CONTENT_TYPE.envelopedData &&
    type !== CONTENT_TYPE.authEnvelopedData) {
    throw new DERError("a CMS structure that is not an envelope");
  }
  return type;
}

/**
 * Opens an envelope with the secret of one recipient, returning the
 * plaintext. An authenticated cipher verifies its tag, so a
 * ciphertext that has been altered fails here rather than producing
 * plaintext that is wrong.
 */
export function open(b: Buffer, secret: RecipientSecret): Buffer {
  const env = readEnvelope(b);
  const contentKey = recoverKey(env.recipients, secret);
  const { contentEncryptionAlgorithm: alg, encryptedContent } =
    env.encryptedContentInfo;
  if (encryptedContent === undefined) {
    throw new DERError("an envelope carrying no content");
  }
  const cipherName = NODE_CIPHER[alg.algorithm];
  if (cipherName === undefined) {
    throw new DERError("a content encryption algorithm this CDMI server does not read");
  }
  if (alg.parameters === undefined) {
    throw new DERError("a content encryption algorithm with no parameters");
  }
  if (authenticates(alg.algorithm)) {
    if (env.mac === undefined) throw new DERError("an authenticated envelope with no mac");
    const { nonce } = decodeGCMParameters(alg.parameters);
    const d = createDecipheriv(cipherName, contentKey, nonce, {
      authTagLength: env.mac.length,
    });
    d.setAuthTag(env.mac);
    // final() throws where the tag does not verify, which is the
    // check that makes the content authenticated.
    return Buffer.concat([d.update(encryptedContent), d.final()]);
  }
  const iv = decodeCBCParameters(alg.parameters);
  const d = createDecipheriv(cipherName, contentKey, iv);
  return Buffer.concat([d.update(encryptedContent), d.final()]);
}

/** The content encryption key, from the recipient this secret matches. */
function recoverKey(recipients: Recipient[], secret: RecipientSecret): Buffer {
  for (const r of recipients) {
    if (secret.kind === "kek" && r.kind === "kek" &&
      r.keyIdentifier.equals(secret.keyIdentifier)) {
      return aesKeyUnwrap(secret.key, r.encryptedKey);
    }
    if (secret.kind === "ktri" && r.kind === "ktri" &&
      r.subjectKeyIdentifier.equals(secret.subjectKeyIdentifier)) {
      return secret.decrypt(r.encryptedKey);
    }
  }
  throw new DERError("no recipient of this envelope matches the key supplied");
}
