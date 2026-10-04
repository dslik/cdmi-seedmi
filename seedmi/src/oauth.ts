// Access tokens: verifying the one a client presents, and exchanging it for
// one the import source will accept.
//
// Nothing here issues a token. A CDMI server is not an authorization server,
// and until 0.128 this module held one — enabled by [oauth].server, so that
// delegated identity could be demonstrated without an external party. It is
// gone: a deployment states [oauth].token_endpoint and [oauth].verify_key and
// names an authorization server of its own, which is what every deployment
// did in any case, and seedmi no longer carries the one thing in it that
// could mint a credential. The tests use `oauth-stub.ts`, which is not part
// of the release.
//
// `signJWT` therefore has no caller here. It remains exported because
// `verifyJWT` is meaningless to test without it, and because the stub signs
// with it.

import { createHmac, createSign, createVerify, timingSafeEqual } from "node:crypto";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { derSignature, rawSignature } from "./jose.ts";

export class TokenError extends Error {}

export interface Claims {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  /** The party acting for the subject, as RFC 8693 defines it. */
  act?: { sub?: string };
  /** The groups of the subject, where the issuer states them. */
  groups?: string[];
  scope?: string;
  [claim: string]: unknown;
}

/**
 * The scopes a token carries.
 *
 * "The value of the scope parameter is expressed as a list of space-delimited,
 * case-sensitive strings" (RFC 6749). A comma-delimited value is not a list of
 * scopes; it is one scope whose text contains commas, and an authorization
 * server rejects it as an invalid token, which is what a client configured
 * with a comma-separated list produces. This splits on whitespace and on
 * nothing else, so such a value yields one scope that matches none this
 * binding defines and the call is refused by scope rather than admitted by
 * accident.
 *
 * The "scp" claim is read where "scope" is absent, and an array is taken as it
 * stands: neither is RFC 6749, and both are common enough in tokens this
 * server will be given that refusing them would be a refusal of the deployment
 * rather than of the token.
 */
export function scopesOfClaims(claims: Record<string, unknown>): string[] {
  const held = claims.scope ?? claims.scp;
  if (Array.isArray(held)) return held.filter((v): v is string => typeof v === "string");
  if (typeof held !== "string") return [];
  return held.split(/[ \t]+/).filter((v) => v !== "");
}

const b64url = (b: Buffer): string =>
  b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const unb64url = (s: string): Buffer =>
  Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");

/**
 * Signs a set of claims, as a JWT.
 *
 * `typ` and `kid` are the two header parameters a relying party of an access
 * token looks at before it looks at anything else. "at+jwt" is the media type
 * RFC 9068 gives an access token, and a verifier that distinguishes an access
 * token from an ID token rejects a "JWT" — this server's own domain controller
 * does. The "kid" names the key in the JWK Set the issuer publishes, and a
 * verifier that fetches a set cannot choose a key without it.
 */
export function signJWT(claims: Claims, key: string, algorithm = "HS256",
  header: { typ?: string; kid?: string } = {}): string {
  const head = b64url(Buffer.from(JSON.stringify({
    alg: algorithm,
    typ: header.typ ?? "JWT",
    ...(header.kid === undefined ? {} : { kid: header.kid }),
  })));
  const payload = b64url(Buffer.from(JSON.stringify(claims)));
  const signing = `${head}.${payload}`;
  return `${signing}.${b64url(sign(signing, key, algorithm))}`;
}

function sign(data: string, key: string, algorithm: string): Buffer {
  if (algorithm === "HS256") {
    return createHmac("sha256", key).update(data).digest();
  }
  if (algorithm === "RS256") {
    return createSign("RSA-SHA256").update(data).sign(key);
  }
  if (algorithm === "ES256") {
    // A JWS signature is the two integers of the ECDSA signature, fixed width
    // and concatenated, where Node produces the DER sequence of them.
    return rawSignature(createSign("SHA256").update(data).sign(key), 32);
  }
  throw new TokenError(`${algorithm} is not an algorithm this server signs with`);
}

export interface VerifyOptions {
  key: string;
  algorithm: string;
  issuer?: string;
  /**
   * The audience or audiences this server answers to. More than one is the
   * ordinary case and not an unusual one: "The CDMI server shall be the MCP
   * server. The two are one server", and each binding of that one server has a
   * resource identifier of its own — the base URI of the HTTP binding and the
   * endpoint of the MCP binding — so a token issued for either was issued for
   * this server. Only one could be stated until 0.88, so a deployment serving
   * both refused every token obtained for whichever it did not name, and a
   * client that followed the protected resource metadata to obtain a token for
   * the MCP endpoint had it refused by the endpoint that advertised it.
   */
  audience?: string | string[];
  /** The time to check the expiry against, for a test. */
  now?: number;
}

/** Verifies a JWT and returns its claims, or says why it was not accepted. */
export function verifyJWT(token: string, opts: VerifyOptions): Claims {
  const parts = token.split(".");
  if (parts.length !== 3) throw new TokenError("the token is not a JWT");
  const [header, payload, signature] = parts;
  let head: { alg?: string };
  try {
    head = JSON.parse(unb64url(header).toString("utf8"));
  } catch {
    throw new TokenError("the header of the token is not JSON");
  }
  if (head.alg !== opts.algorithm) {
    // The algorithm is taken from the configuration and not from the
    // token, so that a token cannot name one of its own choosing.
    throw new TokenError(
      `the token states the algorithm ${String(head.alg)}, and this server accepts ` +
      `${opts.algorithm}`);
  }
  const signing = `${header}.${payload}`;
  if (opts.algorithm === "HS256") {
    const expected = sign(signing, opts.key, "HS256");
    const given = unb64url(signature);
    if (expected.length !== given.length || !timingSafeEqual(expected, given)) {
      throw new TokenError("the signature of the token is not valid");
    }
  } else if (opts.algorithm === "ES256") {
    const ok = createVerify("SHA256").update(signing)
      .verify(opts.key, derSignature(unb64url(signature), 32));
    if (!ok) throw new TokenError("the signature of the token is not valid");
  } else {
    const ok = createVerify("RSA-SHA256").update(signing)
      .verify(opts.key, unb64url(signature));
    if (!ok) throw new TokenError("the signature of the token is not valid");
  }

  let claims: Claims;
  try {
    claims = JSON.parse(unb64url(payload).toString("utf8"));
  } catch {
    throw new TokenError("the payload of the token is not JSON");
  }
  const now = Math.floor((opts.now ?? Date.now()) / 1000);
  if (typeof claims.exp === "number" && claims.exp < now) {
    throw new TokenError("the token has expired");
  }
  if (opts.issuer !== undefined && claims.iss !== opts.issuer) {
    throw new TokenError(`the token was issued by ${String(claims.iss)}`);
  }
  if (opts.audience !== undefined) {
    const aud = (Array.isArray(claims.aud) ? claims.aud : [claims.aud])
      .filter((a): a is string => typeof a === "string");
    const wanted = (Array.isArray(opts.audience) ? opts.audience : [opts.audience])
      .filter((a) => a !== "");
    // An audience that names this server, or a place within it: a token
    // obtained for a container object of this server is a token for
    // this server.
    if (wanted.length > 0 && !aud.some((a) => wanted.some((w) => a === w || a.startsWith(w)))) {
      throw new TokenError("the token is for another audience");
    }
  }
  return claims;
}

// ---------------------------------------------------------------------------
// Token exchange, RFC 8693

export interface ExchangeOptions {
  tokenEndpoint: string;
  clientId?: string;
  /**
   * The credential with which this server authenticates to the security token
   * service, retrieved at each exchange: one of the server's own credentials,
   * which "Each is a credential reference, configured on the CDMI server, and a
   * CDMI server shall not hold such a secret by any other means" (revision
   * 245). It was a string of seedmi.toml before 0.49.
   */
  clientSecret?: () => Promise<string>;
  timeout?: number;
  /**
   * The authority for the token endpoint's certificate, PEM, where it is not one
   * the system trusts, as a domain controller's commonly is. Before 0.58 there
   * was none, and such an endpoint could not be used.
   */
  ca?: string;
}

export interface ExchangedToken {
  token: string;
  /** When it stops being usable, in milliseconds. */
  expires: number;
}

/**
 * Exchanges the token a principal presented for one whose recipient is
 * the import source. The token presented to this server is never
 * presented onward, whatever its audience: that is the whole point of
 * the exchange, and the draft says so.
 */
export async function exchangeToken(subjectToken: string, resource: string,
  opts: ExchangeOptions): Promise<ExchangedToken> {
  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token: subjectToken,
    subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
    resource,
  }).toString();

  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
    Accept: "application/json",
    "Content-Length": String(Buffer.byteLength(body)),
  };
  if (opts.clientId !== undefined) {
    const secret = opts.clientSecret === undefined ? "" : await opts.clientSecret();
    // "The client identifier is encoded using the application/x-www-form-urlencoded
    // encoding algorithm ... and the encoded value is used as the username; the
    // client password is encoded using the same algorithm and used as the
    // password" (RFC 6749 section 2.3.1). Before 0.58 they were sent as they
    // stood, so a secret holding "+", "%" or ":" reached a server that decodes
    // them otherwise than it was.
    const form = (v: string) => new URLSearchParams({ v }).toString().slice(2);
    const basic = Buffer.from(`${form(opts.clientId)}:${form(secret)}`)
      .toString("base64");
    headers.Authorization = `Basic ${basic}`;
  }

  const url = new URL(opts.tokenEndpoint);
  const { status, text } = await post(url, headers, body, opts.timeout ?? 5000, opts.ca);
  if (status !== 200) {
    throw new TokenError(`the token endpoint answered ${status}: ${text.slice(0, 200)}`);
  }
  let answer: { access_token?: string; expires_in?: number; issued_token_type?: string };
  try {
    answer = JSON.parse(text);
  } catch {
    throw new TokenError("the token endpoint returned a body that is not JSON");
  }
  if (typeof answer.access_token !== "string") {
    throw new TokenError("the token endpoint returned no access token");
  }
  const ttl = typeof answer.expires_in === "number" ? answer.expires_in : 300;
  return { token: answer.access_token, expires: Date.now() + ttl * 1000 };
}

function post(url: URL, headers: Record<string, string>, body: string,
  timeout: number, ca?: string): Promise<{ status: number; text: string }> {
  const secure = url.protocol === "https:";
  return new Promise((resolve, reject) => {
    const req = (secure ? httpsRequest : httpRequest)({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port === "" ? undefined : Number(url.port),
      path: url.pathname + url.search,
      method: "POST",
      headers,
      ...(secure && ca !== undefined ? { ca } : {}),
    } as never, (res: {
      statusCode: number;
      on: (e: string, f: (c?: Buffer) => void) => void;
    }) => {
      const chunks: Buffer[] = [];
      res.on("data", (c?: Buffer) => chunks.push(c as Buffer));
      res.on("end", () => resolve({
        status: res.statusCode,
        text: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    req.setTimeout(timeout, () => {
      req.destroy();
      reject(new TokenError("the token endpoint did not answer within the timeout"));
    });
    req.on("error", (err: Error) =>
      reject(new TokenError(`the token endpoint could not be reached: ${err.message}`)));
    req.write(body);
    req.end();
  });
}

/**
 * The tokens obtained by exchange, by the principal they were obtained
 * for and the recipient they were obtained from. A token obtained for
 * one principal is never presented for another, which is also why the
 * representations fetched with it are held under the same key.
 */
const exchanged = new Map<string, ExchangedToken>();

export async function delegatedToken(subjectToken: string, subject: string,
  resource: string, opts: ExchangeOptions): Promise<string> {
  const key = `${subject}\u0000${resource}`;
  const held = exchanged.get(key);
  // A token is reused until shortly before it expires.
  if (held && held.expires - 5000 > Date.now()) return held.token;
  const fresh = await exchangeToken(subjectToken, resource, opts);
  exchanged.set(key, fresh);
  return fresh.token;
}

export function forgetDelegatedTokens(): void {
  exchanged.clear();
}
