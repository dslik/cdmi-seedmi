// Verifying an S3 request signature.
//
// An S3 request is authenticated by AWS Signature Version 4: the
// client forms a canonical request, hashes it, signs the hash with a
// key derived from its secret access key and the credential scope,
// and presents the result in the Authorization header field. A
// server that holds the same secret derives the same key and reaches
// the same signature.
//
// The CDMI document defers the mechanism to the S3 API reference and
// says that a CDMI server makes access key identifiers and secret
// access keys available by means outside its scope, and that no
// field of an S3 export entry conveys them. They are therefore
// configured here rather than read from an entry.

import { createHash, createHmac, timingSafeEqual } from "node:crypto";

/** The algorithm of a signature this module verifies. */
export const ALGORITHM = "AWS4-HMAC-SHA256";

/** The service name of the credential scope of an S3 request. */
export const SERVICE = "s3";

/** What a CDMI server holds for an access key identifier. */
export interface Credential {
  /** The secret access key, which signs and verifies. */
  secret: string;
  /** The name of the CDMI principal the identifier belongs to. */
  principal: string;
}

/** The parts of an Authorization header field of this algorithm. */
export interface Presented {
  accessKey: string;
  date: string;
  region: string;
  service: string;
  signedHeaders: string[];
  signature: string;
}

/** Why a request was not authenticated, as an S3 error code. */
export type SignatureFault =
  | "AccessDenied"
  | "AuthorizationQueryParametersError"
  | "AuthorizationHeaderMalformed"
  | "InvalidAccessKeyId"
  | "SignatureDoesNotMatch"
  | "RequestTimeTooSkewed";

const sha256 = (data: string | Buffer): string =>
  createHash("sha256").update(data).digest("hex");

const hmac = (key: Buffer | string, data: string): Buffer =>
  createHmac("sha256", key).update(data, "utf8").digest();

/**
 * Reads an Authorization header field. The form is the algorithm,
 * then Credential, SignedHeaders and Signature separated by commas.
 */
export function parseAuthorization(header: string): Presented | undefined {
  if (!header.startsWith(`${ALGORITHM} `)) return undefined;
  const parts = new Map<string, string>();
  for (const piece of header.slice(ALGORITHM.length + 1).split(",")) {
    const at = piece.indexOf("=");
    if (at < 0) return undefined;
    parts.set(piece.slice(0, at).trim(), piece.slice(at + 1).trim());
  }
  const credential = parts.get("Credential");
  const signedHeaders = parts.get("SignedHeaders");
  const signature = parts.get("Signature");
  if (credential === undefined || signedHeaders === undefined ||
    signature === undefined) {
    return undefined;
  }
  // access-key/date/region/service/aws4_request
  const scope = credential.split("/");
  if (scope.length !== 5 || scope[4] !== "aws4_request") return undefined;
  return {
    accessKey: scope[0],
    date: scope[1],
    region: scope[2],
    service: scope[3],
    signedHeaders: signedHeaders.split(";").filter((h) => h !== ""),
    signature,
  };
}

/**
 * The canonical request: the method, the URI, the query, the signed
 * header fields, the names of those fields, and the hash of the
 * payload, each on a line of its own.
 */
export function canonicalRequest(o: {
  method: string;
  path: string;
  query: string;
  headers: Record<string, string | string[] | undefined>;
  signedHeaders: string[];
  payloadHash: string;
}): string {
  const headers = o.signedHeaders.map((name) => {
    const raw = o.headers[name];
    const value = Array.isArray(raw) ? raw.join(",") : (raw ?? "");
    // Sequential spaces within a value are one space, and the value
    // is trimmed.
    return `${name}:${value.trim().replace(/\s+/g, " ")}\n`;
  }).join("");
  return [
    o.method.toUpperCase(),
    canonicalPath(o.path),
    canonicalQuery(o.query),
    headers,
    o.signedHeaders.join(";"),
    o.payloadHash,
  ].join("\n");
}

/**
 * The path of the canonical request. Each segment is encoded once
 * more than the URI already encodes it, save for the solidus that
 * separates segments; the path of an S3 request is not normalised.
 */
export function canonicalPath(path: string): string {
  if (path === "") return "/";
  return path.split("/").map((segment) =>
    encodeRFC3986(decodeURIComponent(segment))).join("/");
}

/** The query of the canonical request, sorted by name and then value. */
export function canonicalQuery(query: string): string {
  if (query === "") return "";
  const pairs: [string, string][] = [];
  for (const piece of query.replace(/^\?/, "").split("&")) {
    if (piece === "") continue;
    const at = piece.indexOf("=");
    const name = at < 0 ? piece : piece.slice(0, at);
    const value = at < 0 ? "" : piece.slice(at + 1);
    pairs.push([
      encodeRFC3986(decodeURIComponent(name)),
      encodeRFC3986(decodeURIComponent(value)),
    ]);
  }
  pairs.sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : 1) : (a[0] < b[0] ? -1 : 1)));
  return pairs.map(([n, v]) => `${n}=${v}`).join("&");
}

/**
 * Percent encoding as the signature requires it: unreserved
 * characters alone are left, and encodeURIComponent leaves four more
 * than that.
 */
export function encodeRFC3986(s: string): string {
  return encodeURIComponent(s).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

/** The string that is signed: the algorithm, the instant, the scope, the hash. */
export function stringToSign(amzDate: string, scope: string,
  canonical: string): string {
  return [ALGORITHM, amzDate, scope, sha256(canonical)].join("\n");
}

/** The signing key, derived from the secret and the credential scope. */
export function signingKey(secret: string, date: string, region: string,
  service = SERVICE): Buffer {
  const k1 = hmac(`AWS4${secret}`, date);
  const k2 = hmac(k1, region);
  const k3 = hmac(k2, service);
  return hmac(k3, "aws4_request");
}

/** The signature of a string to sign, under a signing key. */
export function sign(key: Buffer, toSign: string): string {
  return createHmac("sha256", key).update(toSign, "utf8").digest("hex");
}

export interface VerifyOptions {
  method: string;
  path: string;
  query: string;
  headers: Record<string, string | string[] | undefined>;
  /** The hash of the payload, which the client states in a header field. */
  payloadHash: string;
  /** The region the bucket names, which the scope shall match. */
  region: string;
  /** The credential of an access key identifier, where the server holds one. */
  credential: (accessKey: string) => Credential | undefined;
  /** The instant to measure the skew from, for a test to fix. */
  now?: number;
}

/** What verification reached. */
export type Verified =
  | { ok: true; principal: string; accessKey: string }
  | { ok: false; fault: SignatureFault };

/**
 * Verifies the signature of a request. The signature authenticates
 * the request and does not conceal it: a verified request is one
 * this CDMI server may attribute to the principal of the access key
 * identifier, and nothing more.
 */
export function verify(o: VerifyOptions): Verified {
  const raw = o.headers.authorization;
  const header = Array.isArray(raw) ? raw[0] : raw;
  if (header === undefined || header === "") {
    return { ok: false, fault: "AccessDenied" };
  }
  const presented = parseAuthorization(header);
  if (presented === undefined) {
    return { ok: false, fault: "AuthorizationHeaderMalformed" };
  }
  if (presented.service !== SERVICE || presented.region !== o.region) {
    return { ok: false, fault: "AuthorizationHeaderMalformed" };
  }

  // The instant of the request, which bounds how long a signature
  // may be replayed.
  const amzRaw = o.headers["x-amz-date"];
  const amzDate = Array.isArray(amzRaw) ? amzRaw[0] : amzRaw;
  if (amzDate === undefined || !/^\d{8}T\d{6}Z$/.test(amzDate)) {
    return { ok: false, fault: "AuthorizationHeaderMalformed" };
  }
  if (amzDate.slice(0, 8) !== presented.date) {
    return { ok: false, fault: "AuthorizationHeaderMalformed" };
  }
  const when = Date.UTC(
    Number(amzDate.slice(0, 4)),
    Number(amzDate.slice(4, 6)) - 1,
    Number(amzDate.slice(6, 8)),
    Number(amzDate.slice(9, 11)),
    Number(amzDate.slice(11, 13)),
    Number(amzDate.slice(13, 15)),
  );
  // Fifteen minutes either way, which is what S3 allows.
  if (Math.abs((o.now ?? Date.now()) - when) > 15 * 60 * 1000) {
    return { ok: false, fault: "RequestTimeTooSkewed" };
  }

  const held = o.credential(presented.accessKey);
  if (held === undefined) return { ok: false, fault: "InvalidAccessKeyId" };

  const scope = `${presented.date}/${presented.region}/${presented.service}/aws4_request`;
  const canonical = canonicalRequest({
    method: o.method,
    path: o.path,
    query: o.query,
    headers: o.headers,
    signedHeaders: presented.signedHeaders,
    payloadHash: o.payloadHash,
  });
  const expected = sign(
    signingKey(held.secret, presented.date, presented.region, presented.service),
    stringToSign(amzDate, scope, canonical),
  );
  // Compared without revealing where the two differ.
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(presented.signature, "utf8");
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return { ok: false, fault: "SignatureDoesNotMatch" };
  }
  return { ok: true, principal: held.principal, accessKey: presented.accessKey };
}

/** The hash of an empty payload, which many requests carry. */
export const EMPTY_PAYLOAD_HASH = sha256("");

/** The hash of a payload, for a client of this module or a test. */
export const hashPayload = (body: Buffer | string): string => sha256(body);

// ---------------------------------------------------------------------
// A signature presented in the query component

/** The query parameters of a presigned request. */
export const PRESIGNED_ALGORITHM = "X-Amz-Algorithm";
export const PRESIGNED_SIGNATURE = "X-Amz-Signature";

/** The payload hash of a presigned request, which is not computed. */
export const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";

/** The greatest period a presigned URL may be valid for, in seconds. */
export const MAX_PRESIGNED_EXPIRY = 7 * 24 * 60 * 60;

export interface PresignedOptions {
  method: string;
  path: string;
  /** The query component, from which the signature is removed. */
  query: string;
  headers: Record<string, string | string[] | undefined>;
  region: string;
  credential: (accessKey: string) => Credential | undefined;
  now?: number;
}

/** Whether a query component carries a signature. */
export function isPresigned(query: string): boolean {
  return new URLSearchParams(query).has(PRESIGNED_SIGNATURE);
}

/**
 * Verifies a signature presented as parameters of the query
 * component. The canonical request of a presigned request omits the
 * signature parameter, and its payload hash is the constant
 * UNSIGNED-PAYLOAD: the body is not covered, which is why a
 * presigned URL authorizes every request it describes rather than
 * the one request that carries it.
 */
export function verifyPresigned(o: PresignedOptions): Verified {
  const params = new URLSearchParams(o.query);
  const signature = params.get(PRESIGNED_SIGNATURE) ?? "";
  if (signature === "") return { ok: false, fault: "AccessDenied" };
  if (params.get(PRESIGNED_ALGORITHM) !== ALGORITHM) {
    return { ok: false, fault: "AuthorizationQueryParametersError" };
  }
  const credential = params.get("X-Amz-Credential") ?? "";
  const scopeParts = credential.split("/");
  if (scopeParts.length !== 5 || scopeParts[4] !== "aws4_request") {
    return { ok: false, fault: "AuthorizationQueryParametersError" };
  }
  const [accessKey, date, region, service] = scopeParts;
  if (service !== SERVICE || region !== o.region) {
    return { ok: false, fault: "AuthorizationQueryParametersError" };
  }
  const amzDate = params.get("X-Amz-Date") ?? "";
  if (!/^\d{8}T\d{6}Z$/.test(amzDate) || amzDate.slice(0, 8) !== date) {
    return { ok: false, fault: "AuthorizationQueryParametersError" };
  }
  const expires = Number(params.get("X-Amz-Expires") ?? "");
  if (!Number.isInteger(expires) || expires <= 0) {
    return { ok: false, fault: "AuthorizationQueryParametersError" };
  }
  // A presigned URL whose expiry is more than seven days after the
  // instant the signature was generated is refused.
  if (expires > MAX_PRESIGNED_EXPIRY) {
    return { ok: false, fault: "AuthorizationQueryParametersError" };
  }

  const signedAt = Date.UTC(
    Number(amzDate.slice(0, 4)),
    Number(amzDate.slice(4, 6)) - 1,
    Number(amzDate.slice(6, 8)),
    Number(amzDate.slice(9, 11)),
    Number(amzDate.slice(11, 13)),
    Number(amzDate.slice(13, 15)),
  );
  const now = o.now ?? Date.now();
  // A presigned request received after the expiry the URL carries.
  if (now > signedAt + expires * 1000) {
    return { ok: false, fault: "AccessDenied" };
  }
  // The permitted skew applies to a signature naming an instant in
  // the future as it does to one in the past.
  if (signedAt - now > 15 * 60 * 1000) {
    return { ok: false, fault: "RequestTimeTooSkewed" };
  }

  const held = o.credential(accessKey);
  if (held === undefined) return { ok: false, fault: "InvalidAccessKeyId" };

  const signedHeaders = (params.get("X-Amz-SignedHeaders") ?? "host")
    .split(";").filter((h) => h !== "");
  // The signature parameter is not part of what was signed.
  const covered = new URLSearchParams(o.query);
  covered.delete(PRESIGNED_SIGNATURE);
  const scope = `${date}/${region}/${service}/aws4_request`;
  const canonical = canonicalRequest({
    method: o.method,
    path: o.path,
    query: covered.toString(),
    headers: o.headers,
    signedHeaders,
    payloadHash: UNSIGNED_PAYLOAD,
  });
  const expected = sign(
    signingKey(held.secret, date, region, service),
    stringToSign(amzDate, scope, canonical),
  );
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(signature, "utf8");
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return { ok: false, fault: "SignatureDoesNotMatch" };
  }
  return { ok: true, principal: held.principal, accessKey };
}
