// Encrypted objects: the recognition and validation every CDMI server owes
// them, whether or not it can decrypt one.
//
// "An encrypted object is an object whose value is ciphertext. The media
// type of the plaintext is contained within the ciphertext and is not
// reported in the mimetype field of the object." An object is encrypted
// where its mimetype is "application/cms" or "application/jose+json"; in
// the second case the value is a JWE or a JWS in the JSON serialization,
// and the media type of the plaintext is the "cty" header parameter of the
// protected header. Storing and reading such an object requires no
// capability of the subclause: a server that supports none of them stores
// and returns the object unchanged, which is what this module supports.
import { unb64u } from "./jose.ts";

export const MT_CMS = "application/cms";
export const MT_JOSE_JSON = "application/jose+json";
/** The compact serialization, which is not an encrypted object of the subclause. */
export const MT_JOSE_COMPACT = "application/jose";

/** Whether a media type marks a value as the ciphertext of an encrypted object. */
export function isEncryptedMediaType(mimetype: string): boolean {
  const base = mimetype.split(";")[0].trim().toLowerCase();
  return base === MT_CMS || base === MT_JOSE_JSON;
}

/** What an encrypted object's value was found to be. */
export interface EncryptedValue {
  /** "cms", "jwe" or "jws". A JWS is signed and not encrypted. */
  kind: "cms" | "jwe" | "jws";
  /** The media type of the plaintext, from the protected header. */
  plaintextType?: string;
  /** The key the structure names, where it names one. */
  kid?: string;
  /** The recipients of a JWE, where it has more than one. */
  recipients: number;
}

export class EncryptedValueError extends Error {}

/**
 * Reads the protected header of a JOSE structure in the JSON serialization.
 * "The JWE Protected Header is integrity-protected by the authenticated
 * encryption ... and the other two are not. The same applies to a JWS
 * structure and its protected header": the media type of the plaintext is
 * taken from the protected header alone.
 */
function protectedHeader(s: Record<string, unknown>): Record<string, unknown> {
  const p = s.protected;
  if (typeof p !== "string" || p === "") return {};
  let text: string;
  try {
    text = unb64u(p).toString("utf8");
  } catch {
    throw new EncryptedValueError("the protected header is not base64url");
  }
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new EncryptedValueError("the protected header is not a JSON object");
    }
    return parsed as Record<string, unknown>;
  } catch (e) {
    if (e instanceof EncryptedValueError) throw e;
    throw new EncryptedValueError("the protected header is not JSON");
  }
}

/**
 * Validates the value of an encrypted object and reports what it is. Throws
 * EncryptedValueError where the value is not a structure the media type
 * promises: "its value shall be a valid CMS structure", or "a valid JWE
 * structure or a valid JWS structure, in each case in JSON serialization".
 */
export function readEncryptedValue(mimetype: string, value: Buffer): EncryptedValue {
  const base = mimetype.split(";")[0].trim().toLowerCase();
  if (base === MT_CMS) {
    // A CMS structure is DER: a SEQUENCE, whose content this server does not
    // parse. It carries the media type of the plaintext within it, which a
    // server that cannot decrypt does not read.
    if (value.length < 2 || value[0] !== 0x30) {
      throw new EncryptedValueError("a CMS structure is a DER SEQUENCE");
    }
    return { kind: "cms", recipients: 0 };
  }
  let s: Record<string, unknown>;
  try {
    const parsed = JSON.parse(value.toString("utf8")) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new EncryptedValueError("a JOSE structure in the JSON serialization is a JSON object");
    }
    s = parsed as Record<string, unknown>;
  } catch (e) {
    if (e instanceof EncryptedValueError) throw e;
    // "A value in the JWE compact serialization ... is not an encrypted
    // object of this subclause", so a compact structure is reported as what
    // it is rather than as broken JSON.
    if (/^[\w-]+\.[\w-]*\.[\w-]*/.test(value.toString("utf8").trim())) {
      throw new EncryptedValueError(
        "the value is in the compact serialization, and an encrypted object of " +
        `the media type ${MT_JOSE_JSON} is in the JSON serialization`);
    }
    throw new EncryptedValueError("the value is not a JOSE structure in the JSON serialization");
  }
  const head = protectedHeader(s);
  const cty = typeof head.cty === "string" ? head.cty : undefined;
  const kid = typeof head.kid === "string" ? head.kid : undefined;
  // A JWS carries a payload and signatures; a JWE carries ciphertext and
  // recipients.
  if ("payload" in s) {
    if (!("signature" in s) && !Array.isArray(s.signatures)) {
      throw new EncryptedValueError("a JWS holds a signature or an array of signatures");
    }
    // "A value that is a JWS is signed and is not encrypted."
    return { kind: "jws", plaintextType: cty, kid, recipients: 0 };
  }
  if (typeof s.ciphertext !== "string") {
    throw new EncryptedValueError("a JWE holds a ciphertext member");
  }
  if (cty === undefined) {
    // "A CDMI server shall reject a JWE structure whose cty header parameter
    // is absent from the JWE Protected Header, and shall not take the media
    // type of the plaintext from a JWE Shared Unprotected Header or from a
    // per-recipient JWE Header."
    throw new EncryptedValueError(
      "a JWE holds the media type of the plaintext in the cty header parameter " +
      "of its protected header, which is integrity-protected");
  }
  const recipients = Array.isArray(s.recipients)
    ? s.recipients.length
    : ("encrypted_key" in s || "header" in s ? 1 : 0);
  return { kind: "jwe", plaintextType: cty, kid, recipients };
}

/**
 * The key an encrypted object's value is protected under, as the subclause
 * decides it between the metadata item and the structure.
 *
 * * "where an object contains no cdmi_enc_key_id item and the structure
 *   stored as its value contains no key identifier, the CDMI server shall
 *   use the object ID of the object as the Name of the managed object,
 *   within the scope the domain owning the object determines";
 * * "where an object contains a metadata item identifying a key and the
 *   structure stored as its value contains a kid header parameter, the CDMI
 *   server shall use the key the metadata item identifies, and shall not use
 *   the key the kid header parameter identifies. Where the key the metadata
 *   item identifies and the key the kid header parameter identifies are not
 *   the same key, the CDMI server shall reject the structure and shall
 *   report the conflict condition".
 *
 * The item and the header parameter are compared as the names they are: two
 * references that name one managed object are the same key, and a CDMI
 * server that cannot tell reports the conflict, which is the safe way round.
 */
export interface KeyChoice {
  /** The Name of the managed object to obtain, at the key management server. */
  name: string;
  /** Where the Name is the object ID, no item and no key identifier being present. */
  fromObjectID: boolean;
}

export class KeyConflictError extends Error {}

export function keyForEncryptedValue(
  item: string | undefined, structure: EncryptedValue, objectID: string): KeyChoice {
  if (item === undefined) {
    // No item: the structure's own identifier, or the object ID.
    if (structure.kid !== undefined) return { name: structure.kid, fromObjectID: false };
    return { name: objectID, fromObjectID: true };
  }
  const named = nameOfReference(item);
  if (structure.kid !== undefined && structure.kid !== named && structure.kid !== item) {
    throw new KeyConflictError(
      `the cdmi_enc_key_id item names ${named} and the kid header parameter names ` +
      `${structure.kid}, which are not the same key`);
  }
  return { name: named, fromObjectID: false };
}

/**
 * The Name a credential reference addresses. A reference may be given as a
 * bare Name or as a URI of the form "<label>:<name>", the label naming the
 * key management server of the domain's descriptor.
 */
export function nameOfReference(reference: string): string {
  const at = reference.indexOf(":");
  return at < 0 ? reference : reference.slice(at + 1);
}
