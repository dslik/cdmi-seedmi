// Cryptographic Message Syntax: the identifiers and the outer
// structures.
//
// Every CMS structure is a ContentInfo carrying a content type and a
// content defined by it, and almost every structure within one
// carries an AlgorithmIdentifier. This module holds those two and
// the object identifiers CMS uses, so that the structures built on
// them read as their definitions do.

import {
  contentsOf, contextTag, decodeOID, DERError, encodeNull, encodeOctetString,
  encodeOID, type Element, encodeInteger, decodeInteger, expect, isContext,
  readOne, sequence, TAG, tagNumber,
} from "./der.ts";

// ---------------------------------------------------------------------
// Object identifiers

/** The content types of CMS. */
export const CONTENT_TYPE = {
  data: "1.2.840.113549.1.7.1",
  signedData: "1.2.840.113549.1.7.2",
  envelopedData: "1.2.840.113549.1.7.3",
  digestedData: "1.2.840.113549.1.7.5",
  encryptedData: "1.2.840.113549.1.7.6",
  authEnvelopedData: "1.2.840.113549.1.9.16.1.23",
} as const;

/** The digest algorithms. */
export const DIGEST = {
  "sha-256": "2.16.840.1.101.3.4.2.1",
  "sha-384": "2.16.840.1.101.3.4.2.2",
  "sha-512": "2.16.840.1.101.3.4.2.3",
} as const;

/** The content encryption algorithms. */
export const ENCRYPTION = {
  "aes-128-gcm": "2.16.840.1.101.3.4.1.6",
  "aes-192-gcm": "2.16.840.1.101.3.4.1.26",
  "aes-256-gcm": "2.16.840.1.101.3.4.1.46",
  "aes-128-cbc": "2.16.840.1.101.3.4.1.2",
  "aes-192-cbc": "2.16.840.1.101.3.4.1.22",
  "aes-256-cbc": "2.16.840.1.101.3.4.1.42",
} as const;

/** The key transport and key agreement algorithms. */
export const KEY_ALGORITHM = {
  rsaEncryption: "1.2.840.113549.1.1.1",
  rsaesOaep: "1.2.840.113549.1.1.7",
  mgf1: "1.2.840.113549.1.1.8",
  pSpecified: "1.2.840.113549.1.1.9",
  ecPublicKey: "1.2.840.10045.2.1",
  "aes-128-wrap": "2.16.840.1.101.3.4.1.5",
  "aes-192-wrap": "2.16.840.1.101.3.4.1.25",
  "aes-256-wrap": "2.16.840.1.101.3.4.1.45",
} as const;

/** The signature algorithms. */
export const SIGNATURE = {
  "sha256WithRSA": "1.2.840.113549.1.1.11",
  "sha384WithRSA": "1.2.840.113549.1.1.12",
  "sha512WithRSA": "1.2.840.113549.1.1.13",
  rsassaPss: "1.2.840.113549.1.1.10",
  "ecdsa-with-SHA256": "1.2.840.10045.4.3.2",
  "ecdsa-with-SHA384": "1.2.840.10045.4.3.3",
} as const;

/** The attribute types of a signed attribute set. */
export const ATTRIBUTE = {
  contentType: "1.2.840.113549.1.9.3",
  messageDigest: "1.2.840.113549.1.9.4",
  signingTime: "1.2.840.113549.1.9.5",
} as const;

/** The name of an object identifier, where this module knows one. */
export function nameOfOID(oid: string): string | undefined {
  for (const table of [CONTENT_TYPE, DIGEST, ENCRYPTION, KEY_ALGORITHM,
    SIGNATURE, ATTRIBUTE] as Record<string, string>[]) {
    for (const [name, value] of Object.entries(table)) {
      if (value === oid) return name;
    }
  }
  return undefined;
}

/** The digest a Node hash name produces, by its object identifier. */
export const NODE_DIGEST: Record<string, string> = {
  [DIGEST["sha-256"]]: "sha256",
  [DIGEST["sha-384"]]: "sha384",
  [DIGEST["sha-512"]]: "sha512",
};

/** The cipher a Node name produces, by its object identifier. */
export const NODE_CIPHER: Record<string, string> = {
  [ENCRYPTION["aes-128-gcm"]]: "aes-128-gcm",
  [ENCRYPTION["aes-192-gcm"]]: "aes-192-gcm",
  [ENCRYPTION["aes-256-gcm"]]: "aes-256-gcm",
  [ENCRYPTION["aes-128-cbc"]]: "aes-128-cbc",
  [ENCRYPTION["aes-192-cbc"]]: "aes-192-cbc",
  [ENCRYPTION["aes-256-cbc"]]: "aes-256-cbc",
};

// ---------------------------------------------------------------------
// AlgorithmIdentifier

/**
 * An algorithm and its parameters.
 *
 *   AlgorithmIdentifier ::= SEQUENCE {
 *     algorithm   OBJECT IDENTIFIER,
 *     parameters  ANY DEFINED BY algorithm OPTIONAL }
 *
 * Whether the parameters are absent, NULL, or a structure is
 * decided by the algorithm, and getting it wrong is the usual way a
 * signature fails to verify against another implementation: the
 * bytes of the identifier are covered by the signature.
 */
export interface AlgorithmIdentifier {
  algorithm: string;
  /** The parameters as encoded, absent where the algorithm has none. */
  parameters?: Buffer;
}

export function encodeAlgorithm(a: AlgorithmIdentifier): Buffer {
  return a.parameters === undefined
    ? sequence(encodeOID(a.algorithm))
    : sequence(encodeOID(a.algorithm), a.parameters);
}

export function decodeAlgorithm(e: Element): AlgorithmIdentifier {
  const parts = contentsOf(expect(e, TAG.SEQUENCE));
  if (parts.length === 0 || parts.length > 2) {
    throw new DERError("an algorithm identifier is one or two elements");
  }
  const algorithm = decodeOID(parts[0]);
  return parts.length === 1
    ? { algorithm }
    : { algorithm, parameters: Buffer.from(parts[1].raw) };
}

/**
 * The identifier of a digest algorithm. RSA digest algorithms carry
 * an explicit NULL rather than absent parameters, which RFC 5754
 * requires for the algorithms of this profile and which a verifier
 * that reproduces the encoding depends on.
 */
export function digestAlgorithm(name: keyof typeof DIGEST): AlgorithmIdentifier {
  return { algorithm: DIGEST[name], parameters: encodeNull() };
}

// ---------------------------------------------------------------------
// GCMParameters

/**
 * The parameters of an AES-GCM content encryption.
 *
 *   GCMParameters ::= SEQUENCE {
 *     aes-nonce    OCTET STRING,
 *     aes-ICVlen   AES-GCM-ICVlen DEFAULT 12 }
 *
 * DER omits a value equal to its default, so an authentication tag
 * of twelve octets leaves the field out. Encoding it anyway
 * produces bytes another implementation will reject as a
 * non-distinguished encoding.
 */
export function encodeGCMParameters(nonce: Buffer, icvLen = 12): Buffer {
  if (nonce.length === 0) throw new DERError("a GCM nonce is not empty");
  return icvLen === 12
    ? sequence(encodeOctetString(nonce))
    : sequence(encodeOctetString(nonce), encodeInteger(icvLen));
}

export function decodeGCMParameters(parameters: Buffer):
  { nonce: Buffer; icvLen: number } {
  const parts = contentsOf(expect(readOne(parameters), TAG.SEQUENCE));
  if (parts.length === 0 || parts.length > 2) {
    throw new DERError("GCM parameters are one or two elements");
  }
  const nonce = Buffer.from(expect(parts[0], TAG.OCTET_STRING).content);
  if (parts.length === 1) return { nonce, icvLen: 12 };
  const icvLen = Number(decodeInteger(parts[1]));
  // A value equal to the default is omitted in a distinguished
  // encoding, so its presence is an error rather than a redundancy.
  if (icvLen === 12) {
    throw new DERError(
      "a GCM authentication tag length of 12 is the default and is omitted");
  }
  return { nonce, icvLen };
}

/** The parameters of an AES-CBC content encryption, which are the IV. */
export const encodeCBCParameters = (iv: Buffer): Buffer => encodeOctetString(iv);

export function decodeCBCParameters(parameters: Buffer): Buffer {
  return Buffer.from(expect(readOne(parameters), TAG.OCTET_STRING).content);
}

// ---------------------------------------------------------------------
// ContentInfo

/**
 * The outermost structure of every CMS message.
 *
 *   ContentInfo ::= SEQUENCE {
 *     contentType  ContentType,
 *     content      [0] EXPLICIT ANY DEFINED BY contentType }
 *
 * The content is explicitly tagged, so the tag wraps the value
 * rather than replacing its tag.
 */
export interface ContentInfo {
  contentType: string;
  /** The content as encoded, absent where there is none. */
  content?: Buffer;
}

export function encodeContentInfo(c: ContentInfo): Buffer {
  return c.content === undefined
    ? sequence(encodeOID(c.contentType))
    : sequence(encodeOID(c.contentType), contextTag(0, c.content, true));
}

export function decodeContentInfo(b: Buffer): ContentInfo {
  const parts = contentsOf(expect(readOne(b), TAG.SEQUENCE));
  if (parts.length === 0 || parts.length > 2) {
    throw new DERError("a ContentInfo is one or two elements");
  }
  const contentType = decodeOID(parts[0]);
  if (parts.length === 1) return { contentType };
  if (!isContext(parts[1], 0)) {
    throw new DERError("the content of a ContentInfo carries context tag 0");
  }
  const inner = contentsOf(parts[1]);
  if (inner.length !== 1) {
    throw new DERError("an explicitly tagged content holds one element");
  }
  return { contentType, content: Buffer.from(inner[0].raw) };
}

/** Whether a buffer begins with a ContentInfo of a known content type. */
export function contentTypeOf(b: Buffer): string | undefined {
  try {
    return decodeContentInfo(b).contentType;
  } catch {
    return undefined;
  }
}

/**
 * The content of a ContentInfo, requiring a content type. A CMS
 * structure whose content type is not the one an operation expects
 * is refused rather than read as though it were.
 */
export function contentOf(b: Buffer, expected: string): Buffer {
  const info = decodeContentInfo(b);
  if (info.contentType !== expected) {
    throw new DERError(
      `a CMS structure of ${nameOfOID(info.contentType) ?? info.contentType} ` +
      `where ${nameOfOID(expected) ?? expected} was required`);
  }
  if (info.content === undefined) {
    throw new DERError("a CMS structure with no content");
  }
  return info.content;
}

/** The object identifier an element holds. */
export function decodeOIDOf(e: Element): string {
  return decodeOID(e);
}

/** The version numbers CMS assigns to its structures. */
export const encodeVersion = (n: number): Buffer => encodeInteger(n);

/** Reads a version, which every CMS structure begins with. */
export function decodeVersion(e: Element): number {
  if (tagNumber(e) !== TAG.INTEGER) {
    throw new DERError("a CMS structure begins with a version");
  }
  return Number(decodeInteger(e));
}
