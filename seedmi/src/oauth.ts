// Access tokens: verifying the one a client presents, exchanging it for
// one the import source will accept, and — so that a demonstration
// stands on its own — issuing them.
//
// A CDMI server is not an authorization server, and the one here exists
// only so that delegated identity can be shown and tested without an
// external party. It is enabled deliberately, in the configuration, and
// is not what a deployment would use.

import { createHmac, createPrivateKey, createPublicKey, createSign, createVerify, generateKeyPairSync,
  randomUUID, timingSafeEqual } from "node:crypto";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { answerListenerPreflight, listenerCorsOrVary, originOf } from "./cors.ts";
import { derSignature, exportJwk, type Jwk, jwkThumbprint, rawSignature } from "./jose.ts";
import { createServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";

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

// ---------------------------------------------------------------------------
// An authorization server, for a demonstration that stands on its own

/** Whether a key is PEM, which is how an asymmetric one is given. */
const isPem = (key: string): boolean => key.includes("-----BEGIN");

/**
 * The scopes this authorization server issues where none is configured: those
 * the CDMI over MCP binding defines. They are named here rather than imported
 * so that this module, which is an authorization server and not a CDMI server,
 * does not depend on the binding.
 */
const SCOPES_OF_THE_BINDING = ["cdmi:read", "cdmi:write", "cdmi:admin"];

export interface AuthServerOptions {
  /**
   * The issuer identifier its tokens carry. RFC 8414 section 2 makes this the
   * URL its metadata is served from, so where it is absent the address this
   * server is reached at is used, and a deployment that states one states the
   * same string as the base URI.
   */
  issuer?: string;
  /**
   * The key it signs with: a shared secret for HS256, or a PEM private key for
   * RS256 or ES256. Where none is given, a key pair is generated at startup and
   * the algorithm is RS256 — which is what a relying party fetching a JWK Set
   * requires, and what an HS256 secret can never satisfy, there being no public
   * half to publish.
   */
  signKey?: string;
  algorithm?: string;
  /** The principals it will issue a token for, by password. */
  users: { name: string; password: string; groups?: string[] }[];
  /** How long an issued token lasts, in seconds. */
  ttl?: number;
  /**
   * The clients registered with it, by identifier and secret. A client that
   * presents credentials is authenticated against this list where it is not
   * empty; where it is, this server accepts any client, which is what a
   * demonstration authorization server with no registry can do and what a real
   * one must not.
   */
  clients?: {
    id: string;
    secret: string;
    scopes?: string[];
    /**
     * The principal a token issued to this client names, where the client
     * credentials grant is used. Without it the token names the client itself,
     * which is a name no access control list grants anything to — so a client
     * that authenticated correctly and obtained a valid token was then refused
     * every object, which is not a refusal it can act on. This is what
     * [[s3_key]] does with the principal an access key acts as.
     */
    user?: string;
  }[];
  /** The scopes it will issue. Where absent, those of the CDMI over MCP binding. */
  scopes?: string[];
  /**
   * The address it is reached at, which its metadata reports as the token
   * endpoint and the JWK Set URI. Where absent it is derived from the address
   * it is listening on, which is right for a test and wrong for a deployment
   * reached by any other name.
   */
  baseUri?: string;
  /**
   * The certificate it presents, where it is served over TLS.
   *
   * RFC 8414 section 2 requires the issuer identifier to use the https scheme,
   * and RFC 6749 section 3.2 requires the token endpoint to. This server could
   * only ever listen on plain HTTP until 0.88, so its issuer was an http URI
   * and a client that holds either requirement refused to discover it at all —
   * a client credential travels on that endpoint in a request body.
   */
  certificate?: { cert: string; key: string };
  /**
   * The origins a browser-based client may present.
   *
   * Everything this server serves is fetched cross-origin by a client that runs
   * in a browser: the metadata, the JWK Set and the token endpoint are on a
   * listener of their own, at another port, and a port is part of an origin.
   * Without the cross-origin fields a browser withholds each answer from the
   * page, so such a client could discover nothing and obtain no token. The
   * default is the wildcard: the metadata and the JWK Set are public documents
   * by definition, and the token endpoint is guarded by a client credential
   * rather than by who may read its answer.
   */
  origins?: string[];
}

/**
 * The smallest authorization server that serves this purpose: it issues
 * a token to a principal that presents a password, and exchanges a token
 * for one whose audience is the resource asked for. It is not a
 * conforming OAuth server and is not meant to be one.
 */
export class AuthServer {
  readonly opts: Omit<Required<AuthServerOptions>, "issuer" | "baseUri" | "certificate"> &
    { issuer?: string; baseUri?: string; certificate?: { cert: string; key: string } };
  private server?: Server;

  /** The public half of the signing key, where the key is asymmetric. */
  private readonly publicKey: string | undefined;
  /** The identifier of that key in the JWK Set, its RFC 7638 thumbprint. */
  private readonly kid: string | undefined;
  /** The interface it was told to listen on, which its base URI reports. */
  private listenHost = "127.0.0.1";

  constructor(opts: AuthServerOptions) {
    // Where no key is configured, an RSA pair is generated: a relying party
    // that verifies by fetching a JWK Set needs a public half, which an HS256
    // secret does not have. That is why the default algorithm is RS256 and no
    // longer HS256 — the default could not be used by the one verifier in this
    // deployment that matters, namely the domain controller a CDMI over MCP
    // operation resolves its token at.
    const generated = opts.signKey === undefined
      ? generateKeyPairSync("rsa", {
        modulusLength: 2048,
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
      }) as unknown as { privateKey: string; publicKey: string }
      : undefined;
    const signKey = opts.signKey ?? generated!.privateKey;
    const algorithm = opts.algorithm ?? (generated !== undefined || isPem(signKey) ? "RS256" : "HS256");
    this.opts = {
      ttl: 600,
      clients: [],
      origins: ["*"],
      scopes: SCOPES_OF_THE_BINDING,
      ...opts,
      signKey,
      algorithm,
    } as typeof this.opts;
    if (algorithm !== "HS256") {
      this.publicKey = generated?.publicKey ??
        createPublicKey(createPrivateKey(signKey)).export({ format: "pem", type: "spki" }) as string;
      this.kid = jwkThumbprint(exportJwk(createPublicKey(this.publicKey)));
    }
  }

  /** The public signing key as a JWK, where this server has one to publish. */
  get signingJwk(): Jwk | undefined {
    if (this.publicKey === undefined) return undefined;
    return exportJwk(createPublicKey(this.publicKey), {
      kid: this.kid!,
      alg: this.opts.algorithm,
      use: "sig",
    });
  }

  /** The public key in PEM, for a relying party configured with it directly. */
  get verifyKey(): string {
    return this.publicKey ?? this.opts.signKey;
  }

  listen(port: number, host = "127.0.0.1"): Promise<Server> {
    this.listenHost = host;
    const handler = (req: IncomingMessage, res: ServerResponse) => this.handle(req, res);
    const tls = this.opts.certificate;
    const server = tls === undefined
      ? createServer(handler)
      : createHttpsServer({ cert: tls.cert, key: tls.key }, handler) as unknown as Server;
    this.server = server;
    return new Promise((resolve) => server.listen(port, host, () => resolve(server)));
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.server) return resolve();
      this.server.close(() => resolve());
    });
  }

  address(): { port: number } | undefined {
    const a = this.server?.address();
    return a && typeof a !== "string" ? a as { port: number } : undefined;
  }

  /** The address this server is reached at, which its metadata reports. */
  get baseUri(): string {
    if (this.opts.baseUri !== undefined) return this.opts.baseUri.replace(/\/+$/, "");
    // A wildcard interface is not an address a client can reach, so the
    // loopback one stands for it.
    const h = this.listenHost === "0.0.0.0" || this.listenHost === "::" ? "127.0.0.1" : this.listenHost;
    const scheme = this.opts.certificate === undefined ? "http" : "https";
    return `${scheme}://${h.includes(":") ? `[${h}]` : h}:${this.address()?.port ?? 0}`;
  }

  /**
   * The issuer identifier its tokens carry and its metadata reports.
   *
   * RFC 8414 section 2 requires it to be the URL the metadata is served from,
   * because that is how a relying party given a token finds the metadata: it
   * appends "/.well-known/oauth-authorization-server" to the "iss" claim. An
   * issuer that named anything else left a token no relying party could verify
   * by discovery, however well formed the token was.
   */
  get issuer(): string {
    return this.opts.issuer ?? this.baseUri;
  }

  /** The endpoint at which a token is obtained and exchanged. */
  get tokenEndpoint(): string {
    return `${this.baseUri}/token`;
  }

  /** The endpoint at which the JWK Set of the signing key is published. */
  get jwksUri(): string {
    return `${this.baseUri}/jwks`;
  }

  /**
   * The metadata of RFC 8414, which a client reads to find the token endpoint,
   * and which a relying party reads to find the JWK Set.
   *
   * This server served the token endpoint and nothing else until 0.88 — every
   * other path answered 404 — so a client given the issuer could not discover
   * where to obtain a token, and a relying party that verifies by fetching a
   * JWK Set could not find one. Both are the ordinary way an OAuth client and
   * an OAuth resource server are configured, and neither worked.
   */
  metadata(): Record<string, unknown> {
    return {
      issuer: this.issuer,
      token_endpoint: this.tokenEndpoint,
      ...(this.publicKey === undefined ? {} : { jwks_uri: this.jwksUri }),
      grant_types_supported: [
        "password", "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange",
      ],
      // "A space-delimited list of case-sensitive strings" is how a scope is
      // written on the wire; a metadata document carries them as a JSON array,
      // which a client joins with spaces when it asks for them.
      scopes_supported: this.opts.scopes,
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
      response_types_supported: ["token"],
      ...(this.publicKey === undefined
        ? {}
        : { id_token_signing_alg_values_supported: [this.opts.algorithm] }),
    };
  }

  /** The JWK Set of the signing key, which a relying party fetches to verify. */
  jwks(): { keys: Jwk[] } {
    const jwk = this.signingJwk;
    return { keys: jwk === undefined ? [] : [jwk] };
  }

  /** Issues a token directly, which saves a round trip in a test. */
  issue(subject: string, audience: string, extra: Claims = {}): string {
    const now = Math.floor(Date.now() / 1000);
    const user = this.opts.users.find((u) => u.name === subject);
    return signJWT({
      iss: this.issuer,
      sub: subject,
      aud: audience,
      iat: now,
      exp: now + this.opts.ttl,
      jti: randomUUID(),
      ...(user?.groups ? { groups: user.groups } : {}),
      ...extra,
      // "at+jwt", and the key identified, so that a relying party that
      // distinguishes an access token from an ID token accepts it and one that
      // fetches a JWK Set can choose the key. The header said "JWT" and carried
      // no kid until 0.88, which this deployment's own domain controller
      // rejects on both counts.
    }, this.opts.signKey, this.opts.algorithm,
    { typ: "at+jwt", ...(this.kid === undefined ? {} : { kid: this.kid }) });
  }

  /**
   * The client a request authenticates as, by the Basic scheme or by the form
   * fields, and whether its credentials are accepted.
   *
   * A client presenting credentials had only its identifier read until 0.88 —
   * the secret was never checked at all — so any party knowing a client
   * identifier could act as that client.
   */
  private client(req: IncomingMessage, form: URLSearchParams):
    { id?: string; ok: boolean; scopes?: string[]; user?: string } {
    const auth = req.headers.authorization as string | undefined;
    let id: string | undefined;
    let secret: string | undefined;
    if (auth !== undefined && auth.toLowerCase().startsWith("basic ")) {
      // "The client identifier and password are encoded using the
      // application/x-www-form-urlencoded encoding algorithm" before they are
      // joined and base 64 encoded (RFC 6749 section 2.3.1).
      const decoded = Buffer.from(auth.slice(6), "base64").toString("utf8");
      const cut = decoded.indexOf(":");
      if (cut >= 0) {
        id = decodeURIComponent(decoded.slice(0, cut).replace(/\+/g, " "));
        secret = decodeURIComponent(decoded.slice(cut + 1).replace(/\+/g, " "));
      }
    } else if (form.get("client_id") !== null) {
      id = form.get("client_id")!;
      secret = form.get("client_secret") ?? undefined;
    }
    if (id === undefined) return { ok: true };
    // With no registry, any client is accepted: that is what a demonstration
    // authorization server can do, and it is stated in the options rather than
    // being a silent property of the code.
    if (this.opts.clients.length === 0) return { id, ok: true };
    const held = this.opts.clients.find((c) => c.id === id);
    if (held === undefined || secret === undefined) return { id, ok: false };
    const a = Buffer.from(held.secret, "utf8");
    const b = Buffer.from(secret, "utf8");
    const ok = a.length === b.length && timingSafeEqual(a, b);
    return { id, ok, ...(held.scopes === undefined ? {} : { scopes: held.scopes }),
      ...(held.user === undefined ? {} : { user: held.user }) };
  }

  /**
   * The scopes granted for a request, from the "scope" parameter.
   *
   * "The value of the scope parameter is expressed as a list of space-delimited,
   * case-sensitive strings" (RFC 6749). A request asking for a scope this server
   * does not issue, or one the client is not registered for, is the invalid
   * scope error rather than a token quietly narrower than what was asked for:
   * a client that is given less than it asked for and not told fails later, at
   * the resource, with a refusal it cannot explain.
   */
  private granted(form: URLSearchParams, client: { scopes?: string[] }):
    { scope?: string } | { error: string; description: string } {
    const asked = (form.get("scope") ?? "").split(/[ \t]+/).filter((v) => v !== "");
    if (asked.length === 0) return {};
    const available = client.scopes ?? this.opts.scopes;
    const refused = asked.filter((a) => !available.includes(a));
    if (refused.length > 0) {
      return {
        error: "invalid_scope",
        description: `${refused.join(" ")} is not a scope this authorization server issues ` +
          `for this client; it issues ${available.join(" ")}`,
      };
    }
    return { scope: asked.join(" ") };
  }

  /** The header fields a browser client sends to this server. */
  private static readonly REQUEST_HEADERS = ["Authorization", "Content-Type", "Accept"];

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = (req.url ?? "/").split("?")[0]!;
    // A preflight request, answered before anything else: a browser sends one
    // before a POST carrying an Authorization header field, and never sends
    // credentials on it. This server answered 404 to an OPTIONS until 0.92, so
    // a browser client's token request was never made at all.
    if (req.method === "OPTIONS") {
      answerListenerPreflight(this.opts.origins, req, res, {
        own: this.baseUri,
        methods: ["GET", "POST", "OPTIONS"],
        headers: AuthServer.REQUEST_HEADERS,
      });
      return;
    }
    // Set on the response rather than threaded through every answer: Node
    // merges what setHeader put there with what writeHead is given, so every
    // route below carries them without each one repeating it.
    for (const [k, v] of Object.entries(this.cors(req))) res.setHeader(k, v);
    // The metadata of RFC 8414, at the path that RFC gives it, and the JWK Set
    // it points at. Both paths answered 404 until 0.88.
    if (url === "/.well-known/oauth-authorization-server" ||
        url === "/.well-known/openid-configuration") {
      return this.json(res, 200, this.metadata());
    }
    if (url === "/jwks") {
      return this.json(res, 200, this.jwks());
    }
    if (url !== "/token") {
      return this.json(res, 404, { error: "not_found" });
    }
    const body = await read(req);
    const form = new URLSearchParams(body.toString("utf8"));
    const grant = form.get("grant_type");

    // The client, authenticated where it presents credentials.
    const client = this.client(req, form);
    if (!client.ok) {
      return this.json(res, 401, {
        error: "invalid_client",
        error_description: "the client credentials presented are not those of a registered client",
      });
    }
    const scope = this.granted(form, client);
    if ("error" in scope) {
      return this.json(res, 400, { error: scope.error, error_description: scope.description });
    }
    /** The scope claim of a token issued, where the request asked for scopes. */
    const scoped: Claims = scope.scope === undefined ? {} : { scope: scope.scope };
    /** The scope member of the response, which RFC 6749 requires where it differs. */
    const reported = scope.scope === undefined ? {} : { scope: scope.scope };

    // The client credentials grant: a token for the client itself, which is
    // what a program with no user obtains. It is the grant an MCP client
    // configured with a client identifier and secret uses, and this server
    // answered unsupported_grant_type for it.
    if (grant === "client_credentials") {
      if (client.id === undefined) {
        return this.json(res, 401, {
          error: "invalid_client",
          error_description: "the client credentials grant requires the client to authenticate",
        });
      }
      const audience = form.get("resource") ?? form.get("audience") ?? this.issuer;
      // The principal the client acts as, where it is registered with one, and
      // the client itself otherwise. The groups of that principal come with it,
      // issue() reading them from the users this server knows.
      return this.json(res, 200, {
        access_token: this.issue(client.user ?? client.id, audience, scoped),
        token_type: "Bearer",
        expires_in: this.opts.ttl,
        ...reported,
      });
    }

    if (grant === "password") {
      const name = form.get("username") ?? "";
      const password = form.get("password") ?? "";
      const user = this.opts.users.find((u) => u.name === name);
      if (!user || user.password !== password) {
        return this.json(res, 400, { error: "invalid_grant" });
      }
      const audience = form.get("resource") ?? form.get("audience") ?? this.issuer;
      return this.json(res, 200, {
        access_token: this.issue(name, audience, scoped),
        token_type: "Bearer",
        expires_in: this.opts.ttl,
        ...reported,
      });
    }

    if (grant === "urn:ietf:params:oauth:grant-type:token-exchange") {
      const subjectToken = form.get("subject_token") ?? "";
      const resource = form.get("resource");
      if (resource === null) {
        return this.json(res, 400, { error: "invalid_request" });
      }
      let claims: Claims;
      try {
        claims = verifyJWT(subjectToken, {
          // The public half where the key is asymmetric: a verification uses
          // the key that checks a signature, not the one that makes it.
          key: this.verifyKey,
          algorithm: this.opts.algorithm,
          issuer: this.issuer,
        });
      } catch (err) {
        return this.json(res, 400, {
          error: "invalid_grant",
          error_description: String(err),
        });
      }
      // The token issued names the subject of the token presented, and
      // the party acting for it: the client that asked for the
      // exchange.
      const actor = client.id ?? "unknown";
      const token = this.issue(String(claims.sub ?? ""), resource, {
        act: { sub: actor },
        ...(claims.groups ? { groups: claims.groups } : {}),
        // The scopes of the token exchanged carry over where the request asks
        // for none, a token exchange narrowing the audience and not the scope.
        ...(scope.scope === undefined && typeof claims.scope === "string" ? { scope: claims.scope } : scoped),
      });
      return this.json(res, 200, {
        access_token: token,
        issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
        token_type: "Bearer",
        expires_in: this.opts.ttl,
        ...reported,
      });
    }

    return this.json(res, 400, { error: "unsupported_grant_type" });
  }


  /** The cross-origin fields of a response, where a browser asked for them. */
  private cors(req: IncomingMessage): Record<string, string> {
    return listenerCorsOrVary(this.opts.origins, originOf(req),
      { own: this.baseUri, cookie: req.headers.cookie !== undefined });
  }

  private json(res: ServerResponse, status: number, body: unknown): void {
    const text = Buffer.from(JSON.stringify(body) + "\n");
    res.writeHead(status, {
      "Content-Type": "application/json",
      "Content-Length": String(text.length),
      "Cache-Control": "no-store",
    });
    res.end(text);
  }
}

function read(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
  });
}
