// The signature over an object as a whole, which the cdmi_enc_signature
// storage system metadata item holds as a JWS compact serialization.
//
// "The payload of that JWS compact serialization shall be the canonical
// form, as specified in RFC 8785, of a JSON object containing the following
// members, each omitted where the object does not contain the corresponding
// field or item": objectID, mimetype, valuedigest, valuedigestalgorithm,
// metadata and datasystemmetadata. "The payload shall contain no storage
// system metadata item. A CDMI server populates those items, and several of
// them change as a consequence of an operation that does not change the
// object, so a payload containing one cannot be verified twice."
import { createHash } from "node:crypto";

/** What the payload of an object signature describes. */
export interface SignedObject {
  objectID?: string;
  mimetype?: string;
  value?: Buffer;
  /** The user metadata items: those the client set, storage system items excluded. */
  metadata?: Record<string, unknown>;
  /** The data system metadata items of the object. */
  dataSystemMetadata?: Record<string, unknown>;
}

/**
 * The digest algorithms this server computes for a signature payload, named
 * as the IANA Named Information Hash Algorithm registry names them, which
 * the cdmi_enc_digest capability reports.
 */
export const DIGEST_ALGORITHMS = ["sha-256", "sha-384", "sha-512"];

/**
 * The canonical form of a JSON value, as RFC 8785 specifies it: the members
 * of an object in ascending order of their names compared as sequences of
 * UTF-16 code units, no insignificant whitespace, and strings serialized as
 * ECMAScript JSON.stringify serializes them. Numbers are not produced here:
 * every value this payload holds is a string, an array, an object or a
 * boolean, and a number would need the ECMAScript number-to-string rules
 * the specification also requires.
 */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("a canonical form holds no infinity or NaN");
    // Integers serialize alike in every implementation; a fractional number
    // would need the full rules, which this payload never requires.
    if (!Number.isInteger(v)) throw new Error("a canonical form of a fractional number is not produced here");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (typeof v === "object") {
    const entries = Object.entries(v as Record<string, unknown>)
      .filter(([, value]) => value !== undefined)
      .sort(([a], [b]) => codeUnitOrder(a, b));
    return `{${entries.map(([k, value]) => `${JSON.stringify(k)}:${canonicalJson(value)}`).join(",")}}`;
  }
  throw new Error(`a canonical form of ${typeof v} is not defined`);
}

/** Ascending order of two strings by their UTF-16 code units, as RFC 8785 requires. */
function codeUnitOrder(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = a.charCodeAt(i) - b.charCodeAt(i);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/**
 * The payload of the object signature: the canonical form of what the
 * subclause lists, each member omitted where the object does not have it.
 */
export function signaturePayload(o: SignedObject, algorithm = "sha-256"): Buffer {
  if (!DIGEST_ALGORITHMS.includes(algorithm)) {
    throw new Error(`${algorithm} is not a digest algorithm this server computes`);
  }
  const payload: Record<string, unknown> = {};
  if (o.objectID !== undefined) payload.objectID = o.objectID;
  if (o.mimetype !== undefined && o.mimetype !== "") payload.mimetype = o.mimetype;
  if (o.value !== undefined) {
    // "the digest of the value of the object as stored, encoded using the
    // Base16 encoding rules of RFC 4648", which are upper case.
    payload.valuedigest = createHash(algorithm.replace("-", ""))
      .update(o.value).digest("hex").toUpperCase();
    payload.valuedigestalgorithm = algorithm;
  }
  if (o.metadata !== undefined && Object.keys(o.metadata).length > 0) {
    payload.metadata = o.metadata;
  }
  if (o.dataSystemMetadata !== undefined && Object.keys(o.dataSystemMetadata).length > 0) {
    payload.datasystemmetadata = o.dataSystemMetadata;
  }
  return Buffer.from(canonicalJson(payload), "utf8");
}

/**
 * Whether the payload of a signature describes the object as it stands: the
 * digest is recomputed from the value held, since the payload carries the
 * digest rather than the value.
 */
export function payloadMatches(payload: Buffer, o: SignedObject): boolean {
  let held: Record<string, unknown>;
  try {
    held = JSON.parse(payload.toString("utf8")) as Record<string, unknown>;
  } catch {
    return false;
  }
  const algorithm = typeof held.valuedigestalgorithm === "string"
    ? held.valuedigestalgorithm
    : "sha-256";
  if (!DIGEST_ALGORITHMS.includes(algorithm)) return false;
  return canonicalJson(held) === signaturePayload(o, algorithm).toString("utf8");
}

/**
 * Signs the payload of an object signature with a key held at a key
 * management server, returning the JWS compact serialization the
 * cdmi_enc_signature item holds.
 *
 * The item is stored as a string: the subclause requires "a JWS compact
 * serialization", which is three base64url segments and not a JSON object,
 * though Annex D types the item as one. That contradiction is ECR-162A.
 */
export async function signObjectPayload(
  sign: (data: Buffer) => Promise<Buffer>, payload: Buffer,
  header: { alg: string; kid?: string }): Promise<string> {
  const protectedHeader = Buffer.from(JSON.stringify(header), "utf8").toString("base64url");
  const body = payload.toString("base64url");
  const signature = await sign(Buffer.from(`${protectedHeader}.${body}`, "ascii"));
  return `${protectedHeader}.${body}.${signature.toString("base64url")}`;
}

/**
 * Whether an object signature verifies against the object as it stands: the
 * signature over the payload, and the payload against the object, since the
 * payload carries the digest of the value rather than the value.
 */
export function objectSignatureMatches(compact: string, o: SignedObject,
  verify: (signed: Buffer, signature: Buffer) => boolean): boolean {
  const parts = compact.split(".");
  if (parts.length !== 3) return false;
  const [protectedHeader, body, signature] = parts;
  if (!verify(Buffer.from(`${protectedHeader}.${body}`, "ascii"),
    Buffer.from(signature, "base64url"))) {
    return false;
  }
  return payloadMatches(Buffer.from(body, "base64url"), o);
}

/**
 * The JWS algorithms this server signs an object signature with, one for
 * each kind of key a key management server may hold for the purpose. The
 * cdmi_jws_alg capability reports them.
 */
export const JWS_ALGORITHMS = ["ES256", "RS256"];

/**
 * The JWS algorithm a key of the named cryptographic algorithm signs with,
 * and the KMIP parameters that perform it. A key of another kind is not
 * used: an algorithm this server cannot name in a protected header would
 * produce a signature no client could verify.
 */
export function signatureAlgorithm(cryptographic: string):
  { alg: string; params: Record<string, string> } {
  if (cryptographic === "ECDSA" || cryptographic === "EC") {
    return {
      alg: "ES256",
      params: { digitalSignatureAlgorithm: "ECDSA with SHA256", hashingAlgorithm: "SHA-256" },
    };
  }
  if (cryptographic === "RSA") {
    return {
      alg: "RS256",
      params: {
        digitalSignatureAlgorithm: "SHA-256 with RSA Encryption (PKCS#1 v1.5)",
        hashingAlgorithm: "SHA-256",
      },
    };
  }
  throw new Error(`a key of the algorithm ${cryptographic} does not sign an object signature here`);
}
