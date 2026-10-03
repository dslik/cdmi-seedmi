// Phase 3 of PLAN.md: tokens.
//
// An OAuth 2.0 authorization server (RFC 6749) for the realm, on the
// controller's HTTPS listener:
//
//   POST /token                                    the token endpoint
//   GET  /jwks                                     the keys that verify its tokens (RFC 7517)
//   GET  /.well-known/oauth-authorization-server   its metadata (RFC 8414)
//
// A client authenticates by HTTP Basic (client_secret_basic, RFC 6749 section
// 2.3.1) and may use the grants its [[client]] table names:
//
//   client_credentials   a token for the client itself
//   password             a token for a user, whose password the directory verifies
//   token exchange       a token for a subject token this controller issued, or one a
//                        realm it trusts issued ([[trust]], phase 5) (RFC 8693), which is
//                        how a CDMI server obtains one for a delegated import
//
// An access token is a JWT in the profile of RFC 9068: typ "at+jwt"; iss, exp,
// aud, sub, client_id, iat, jti; and, for a user, groups (RFC 9068 section
// 2.2.3.1), every group the user belongs to, nesting followed.
//
// Written before the texts of RFC 6749, 8693, 9068 and 8414 were to hand, and
// then checked against them (PLAN.md, "Phase 3 checked against the RFCs").

import { createHash, createPublicKey, type KeyObject, randomBytes } from "node:crypto";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { type Directory, verifySecret } from "./dc-directory.ts";
import { exportJwk, importJwk, type Jwk, signJws, verifyJws } from "./jose.ts";
import { Throttle } from "./throttle.ts";

export const GRANT = {
  clientCredentials: "client_credentials",
  password: "password",
  tokenExchange: "urn:ietf:params:oauth:grant-type:token-exchange",
} as const;
export const GRANTS: string[] = Object.values(GRANT);
/** Token type identifiers (RFC 8693 section 3). */
const TOKEN_TYPE = {
  accessToken: "urn:ietf:params:oauth:token-type:access_token",
  jwt: "urn:ietf:params:oauth:token-type:jwt",
};

/**
 * The scopes this controller defines for its own administrative interface
 * (DESIGN-admin.md §7). A scope is "a space-delimited list of case-sensitive
 * strings ... defined by the authorization server" (RFC 6749 section 3.3), so
 * these are this server's and no standard's.
 */
export const SCOPES = Object.freeze({
  /** Read the directory through the administrative interface. */
  read: "dc.read",
  /** Write it. It does not include read: a client is given both where it needs both. */
  admin: "dc.admin",
});

export interface ClientSpec {
  id: string;
  /** A hash --hash-password writes, or undefined where a plain secret is given. */
  secretHash: string;
  grants: string[];
  /** The audiences it may ask a token for; the first where it asks for none. */
  audiences: string[];
  /**
   * The scopes it may be issued. A client that asks for none is issued none, as
   * RFC 6749 leaves to the server: a token with every scope its client could have
   * is a token wider than the request, and a client that wants a scope asks.
   */
  scopes?: string[];
  /**
   * Where given, the audiences a subject token it presents for exchange must
   * name one of: a client exchanges the tokens issued to it, and not a token
   * issued to another service that came into its hands.
   */
  subjectAudiences?: string[];
}

/** Another realm whose tokens this controller exchanges: a [[trust]] table (phase 5). */
export interface TrustedRealm {
  realm: string;
  /** Its issuer identifier, whose metadata (RFC 8414) names its JWK Set. */
  issuer: string;
  /** The authority for its certificate, PEM. */
  ca: string;
}

/** Fetches a JSON document over HTTPS, trusting the authority given; replaced in a test. */
export type FetchJson = (url: string, ca: string) => Promise<unknown>;

export const httpsJson: FetchJson = (url, ca) => new Promise((resolve, reject) => {
  const u = new URL(url);
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const req = httpsRequest({ hostname: host, port: Number(u.port || 443), path: `${u.pathname}${u.search}`, method: "GET", ca,
    timeout: 5000, ...(isIP(host) ? {} : { servername: host }) } as never, (res: never) => {
    const r = res as { statusCode: number; on: (e: string, f: (d?: Buffer) => void) => void };
    const chunks: Buffer[] = [];
    r.on("data", (d) => chunks.push(d!));
    r.on("end", () => {
      if (r.statusCode !== 200) return reject(new Error(`${url} answered ${r.statusCode}`));
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); } catch { reject(new Error(`${url} is not JSON`)); }
    });
  });
  // A fetch that does not complete in time ends, and is reported by the error handler.
  req.on("timeout", () => req.destroy());
  req.on("error", (e: Error) => reject(e));
  req.end();
});

export interface TokenConfig {
  issuer: string;
  signingKey: KeyObject;
  /** Public keys no longer signing, published until the tokens they signed expire. */
  previousKeys: KeyObject[];
  lifetimeSeconds: number;
  clients: ClientSpec[];
  /** Other realms whose tokens are exchanged. */
  trusted?: TrustedRealm[];
}

/** A key's public half, whether it is given a private or a public key: createPublicKey takes no public key. */
const publicOf = (k: KeyObject): KeyObject => (k.type === "public" ? k : createPublicKey(k));

/**
 * Whether a typ header names the access token media type, application/at+jwt:
 * "JWT access tokens MUST include this media type in the typ header parameter"
 * (RFC 9068 section 2.1), which may omit "application/" (RFC 7515 section
 * 4.1.9) and, as a media type, compares without case (its own example writes
 * "at+JWT").
 */
export function isAccessTokenType(typ: unknown): boolean {
  if (typeof typ !== "string") return false;
  const t = typ.toLowerCase();
  return t === "at+jwt" || t === "application/at+jwt";
}

/** The algorithm a key signs with: RS256 for RSA, ES256 for a P-256 key. */
function algOf(key: KeyObject): string {
  const jwk = exportJwk(publicOf(key));
  if (jwk.kty === "RSA") return "RS256";
  if (jwk.kty === "EC" && jwk.crv === "P-256") return "ES256";
  throw new Error("a token signing key is RSA, or an elliptic curve key on P-256");
}
const b64u = (b: Buffer) => b.toString("base64url");

/**
 * A key's thumbprint (RFC 7638): SHA-256 over its required members, in
 * lexicographic order, without whitespace. It is the key's kid.
 */
export function thumbprint(key: KeyObject): string {
  const j = exportJwk(publicOf(key));
  const required = j.kty === "RSA" ? { e: j.e, kty: j.kty, n: j.n } : { crv: j.crv, kty: j.kty, x: j.x, y: j.y };
  return b64u(createHash("sha256").update(JSON.stringify(required)).digest());
}

export interface TokenReply {
  status: number;
  body: Record<string, unknown>;
  headers: Record<string, string>;
  /** For the log: never a secret or a token. */
  log: Record<string, unknown>;
}

/** An error response (RFC 6749 section 5.2), and what the log is told. */
function oauthError(status: number, error: string, description: string, log: Record<string, unknown>, headers: Record<string, string> = {}): TokenReply {
  return { status, body: { error, error_description: description }, log: { event: "token refused", error, ...log },
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", Pragma: "no-cache", ...headers } };
}

/**
 * The audiences a claim set names. "aud" is "a StringOrURI value or an array of
 * such values" (RFC 7519 §4.1.3), so both shapes are read, and anything else is
 * no audience at all rather than one that happens to compare equal.
 */
function audiencesOf(aud: unknown): string[] {
  if (typeof aud === "string") return [aud];
  if (Array.isArray(aud)) return aud.filter((a): a is string => typeof a === "string");
  return [];
}

/**
 * How long a trusted realm's published keys are held before they are fetched
 * again. Short enough that a withdrawn key stops working in minutes, long enough
 * that a verification is not a network round trip; the thirty-second floor on
 * re-fetching for an unseen key ID still applies within it.
 */
const FOREIGN_KEY_LIFETIME = 300_000;

export class TokenService {
  private readonly config: TokenConfig;
  private readonly directory: () => Directory;
  private readonly throttle: Throttle;
  private readonly alg: string;
  private readonly kid: string;
  private readonly fetchJson: FetchJson;
  /** Each trusted realm's JWK Set, and when it was fetched. */
  private readonly foreignKeys = new Map<string, { keys: Jwk[]; fetched: number }>();

  constructor(config: TokenConfig, directory: () => Directory, throttle: Throttle = new Throttle(), fetchJson: FetchJson = httpsJson) {
    this.config = config;
    this.directory = directory;
    this.throttle = throttle;
    this.fetchJson = fetchJson;
    this.alg = algOf(config.signingKey);
    this.kid = thumbprint(config.signingKey);
  }

  /** The keys that verify this controller's tokens: the signing key and those it replaced. */
  jwks(): { keys: Jwk[] } {
    const entry = (k: KeyObject) => {
      const pub = publicOf(k);
      return { ...exportJwk(pub), kid: thumbprint(pub), use: "sig", alg: algOf(pub) };
    };
    return { keys: [entry(this.config.signingKey), ...this.config.previousKeys.map(entry)] };
  }

  /** The authorization server's metadata (RFC 8414). */
  metadata(): Record<string, unknown> {
    const base = this.config.issuer.replace(/\/$/, "");
    return {
      issuer: this.config.issuer,
      token_endpoint: `${base}/token`,
      jwks_uri: `${base}/jwks`,
      grant_types_supported: GRANTS,
      token_endpoint_auth_methods_supported: ["client_secret_basic"],
      // No authorization endpoint is offered, so no response type.
      response_types_supported: [],
      // "scopes_supported: ... a list of the OAuth 2.0 scope values that this
      // authorization server supports" (RFC 8414 section 2). Every scope any
      // client of this controller may be issued, which is the pair this program
      // defines for its administrative interface plus whatever a deployment named.
      scopes_supported: [...new Set([...Object.values(SCOPES),
        ...this.config.clients.flatMap((c) => c.scopes ?? [])])].sort(),
    };
  }

  /**
   * The audience of this controller's own administrative interface: what a token
   * presented at `/scim/v2/` must name. It is derived from the issuer rather than
   * configured, because the two cannot disagree — the issuer *is* this
   * controller's address as clients reach it, and the interface is a path beneath
   * it. A client that wants to administer this realm lists this value in its
   * `audiences`, and `/.well-known/oauth-authorization-server` names the issuer it
   * is built from, so a client can compute it.
   */
  get scimAudience(): string {
    return `${this.config.issuer.replace(/\/$/, "")}/scim/v2/`;
  }

  /**
   * Verifies a token this controller issued: its signature by the signing key
   * or one it replaced (chosen by kid), typ at+jwt, the issuer, the **audience**
   * where the caller names one, and not expired. The claims, or undefined.
   *
   * `audience` is what the caller is: a resource server passes its own audience
   * and every other token is refused. RFC 8725 §3.9: "If the same issuer can
   * issue JWTs that are intended for use by more than one relying party or
   * application, the JWT MUST contain an 'aud' (audience) claim ... the relying
   * party or application MUST validate the audience value, and if the audience
   * value is not present or not associated with the recipient, it MUST reject the
   * JWT." This issuer does issue for more than one party — every `[[client]]`
   * names its own `audiences` — and while nothing checked `aud`, a token issued to
   * a CDMI storage node for its own audience administered the directory through
   * `/scim/v2/`. That was proven against a running controller, not reasoned about:
   * a `dc.admin` token with `aud` of `https://cdmi.example/storage` created a user.
   *
   * The parameter is optional because one caller legitimately has no audience of
   * its own: the token endpoint verifying a `subject_token` it is about to
   * exchange, which checks the audience against the presenting client instead.
   */
  verify(token: string, now = Date.now(), audience?: string): Record<string, unknown> | undefined {
    const parts = token.split(".");
    if (parts.length !== 3) return undefined;
    let header: Record<string, unknown>;
    try {
      header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    } catch {
      return undefined;
    }
    if (!isAccessTokenType(header.typ)) return undefined;
    const key = this.jwks().keys.find((k) => k.kid === header.kid);
    if (key === undefined) return undefined;
    let claims: Record<string, unknown>;
    try {
      claims = JSON.parse(verifyJws(token, importJwk(key), { alg: key.alg as string }).payload.toString("utf8"));
    } catch {
      return undefined;
    }
    if (claims.iss !== this.config.issuer || typeof claims.exp !== "number" || claims.exp * 1000 <= now) return undefined;
    if (audience !== undefined && !audiencesOf(claims.aud).includes(audience)) return undefined;
    return claims;
  }

  /**
   * Verifies a token a trusted realm issued: its realm found by its (as yet
   * unverified) issuer, that realm's metadata fetched and its issuer required
   * to be identical ("The issuer value returned MUST be identical to the
   * authorization server's issuer identifier value into which the well-known
   * URI string was inserted", RFC 8414 section 3.3), its JWK Set fetched (again,
   * at most every thirty seconds, for a key ID not yet seen), and the token's
   * typ, algorithm, signature, issuer and expiry checked. Its realm and claims,
   * or undefined.
   */
  async verifyForeign(token: string, now = Date.now()): Promise<{ realm: TrustedRealm; claims: Record<string, unknown> } | undefined> {
    const parts = token.split(".");
    if (parts.length !== 3 || (this.config.trusted ?? []).length === 0) return undefined;
    let header: Record<string, unknown>, unverified: Record<string, unknown>;
    try {
      header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
      unverified = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    } catch {
      return undefined;
    }
    if (!isAccessTokenType(header.typ) || (header.alg !== "RS256" && header.alg !== "ES256")) return undefined;
    const realm = (this.config.trusted ?? []).find((t) => t.issuer === unverified.iss);
    if (realm === undefined) return undefined;
    const keysOf = async (refresh: boolean): Promise<Jwk[]> => {
      const held = this.foreignKeys.get(realm.issuer);
      // The cache **expires**. It used to be consulted with `refresh` false first,
      // and with that flag the only condition was the thirty-second floor on
      // *re-fetching for an unknown key ID* — so a key already in the cache was
      // never looked at again for the life of the process. A trusted realm that
      // rotated away from a compromised signing key was still honoured
      // indefinitely, and the exchange grant turned those tokens into local ones.
      // "the application MUST validate that the cryptographic keys used for the
      // cryptographic operations in the JWT belong to the issuer" (RFC 8725 §3.8) —
      // which a key the realm has withdrawn no longer does.
      const fresh = held !== undefined && now - held.fetched < FOREIGN_KEY_LIFETIME;
      if (fresh && !(refresh && now - held!.fetched > 30_000)) return held!.keys;
      const meta = await this.fetchJson(`${realm.issuer.replace(/\/$/, "")}/.well-known/oauth-authorization-server`, realm.ca) as
        Record<string, unknown>;
      if (meta.issuer !== realm.issuer || typeof meta.jwks_uri !== "string") return [];
      const set = await this.fetchJson(meta.jwks_uri, realm.ca) as { keys?: Jwk[] };
      const keys = Array.isArray(set.keys) ? set.keys : [];
      this.foreignKeys.set(realm.issuer, { keys, fetched: now });
      return keys;
    };
    let key: Jwk | undefined;
    try {
      key = (await keysOf(false)).find((k) => k.kid === header.kid) ?? (await keysOf(true)).find((k) => k.kid === header.kid);
    } catch {
      return undefined;
    }
    if (key === undefined) return undefined;
    let claims: Record<string, unknown>;
    try {
      claims = JSON.parse(verifyJws(token, importJwk(key), { alg: header.alg as string }).payload.toString("utf8"));
    } catch {
      return undefined;
    }
    if (claims.iss !== realm.issuer || typeof claims.exp !== "number" || claims.exp * 1000 <= now || typeof claims.sub !== "string") return undefined;
    return { realm, claims };
  }

  private issue(sub: string, clientId: string, aud: string | string[], extra: Record<string, unknown>, now: number): { token: string; jti: string } {
    const iat = Math.floor(now / 1000);
    const jti = b64u(randomBytes(16));
    const claims = { iss: this.config.issuer, sub, aud, client_id: clientId, iat, exp: iat + this.config.lifetimeSeconds, jti, ...extra };
    const token = signJws(Buffer.from(JSON.stringify(claims), "utf8"), this.config.signingKey,
      { alg: this.alg, typ: "at+jwt", kid: this.kid });
    return { token, jti };
  }

  /** A request to the token endpoint: its Authorization header and its form-encoded body. */
  async token(authorization: string | undefined, body: string, now = Date.now()): Promise<TokenReply> {
    // "Request and response parameters MUST NOT be included more than once"
    // (RFC 6749 section 3.2), but for resource and audience, of which "Multiple
    // ... parameters may be used" (RFC 8693 section 2.1). "Parameters sent
    // without a value MUST be treated as if they were omitted."
    const form = new URLSearchParams(body);
    const seen = new Set<string>();
    for (const [k, v] of form.entries()) {
      if (v === "" || k === "resource" || k === "audience") continue;
      if (seen.has(k)) return oauthError(400, "invalid_request", `the parameter ${k} is given more than once`, {});
      seen.add(k);
    }
    const p = (k: string) => { const v = form.get(k); return v === null || v === "" ? undefined : v; };

    // The client, by HTTP Basic, its id and secret form-encoded first (RFC 6749 section 2.3.1).
    const client = this.authenticate(authorization);
    if (client === undefined) {
      return oauthError(401, "invalid_client", "the client is not authenticated", {},
        { "WWW-Authenticate": `Basic realm="${this.config.issuer}"` });
    }
    const grant = p("grant_type");
    if (grant === undefined) return oauthError(400, "invalid_request", "grant_type is given", { client: client.id });
    if (!GRANTS.includes(grant)) return oauthError(400, "unsupported_grant_type", `${grant} is not a grant this server supports`, { client: client.id });
    if (!client.grants.includes(grant)) {
      return oauthError(400, "unauthorized_client", `the client may not use ${grant}`, { client: client.id, grant });
    }
    // The targets asked for: resource (RFC 8707) and audience (RFC 8693), each
    // any number of times, and each one of the client's; the first of them
    // where none is asked for. "If the authorization server is unwilling or
    // unable to issue a token for any target service indicated by the resource
    // or audience parameters, the invalid_target error code SHOULD be used."
    const asked = [...new Set([...form.getAll("resource"), ...form.getAll("audience")].filter((v) => v !== ""))];
    const refusedTarget = asked.find((a) => !client.audiences.includes(a));
    if (refusedTarget !== undefined) {
      return oauthError(400, "invalid_target", `the client may not ask a token for ${refusedTarget}`, { client: client.id, aud: refusedTarget });
    }
    // aud is a string where there is one, an array where there are several (RFC 7519 section 4.1.3).
    const aud: string | string[] = asked.length === 0 ? client.audiences[0] : asked.length === 1 ? asked[0] : asked;

    let sub: string, extra: Record<string, unknown> = {}, exchanged = false;
    if (grant === GRANT.clientCredentials) {
      // No resource owner: the subject is the client (RFC 9068 section 2.2).
      sub = client.id;
    } else if (grant === GRANT.password) {
      const username = p("username"), password = form.get("password") ?? "";
      if (username === undefined || password === "") {
        return oauthError(400, "invalid_request", "username and password are given", { client: client.id });
      }
      // A user locked by failures is refused without the password being checked.
      if (this.throttle.locked("user", username)) {
        return oauthError(400, "invalid_grant", "the resource owner's credentials are not accepted",
          { client: client.id, user: username, reason: "locked" });
      }
      const verdict = this.directory().verify(username, password);
      this.throttle.record("user", username, verdict.ok || (verdict as { reason: string }).reason === "disabled" ||
        (verdict as { reason: string }).reason === "expired");
      if (!verdict.ok) {
        return oauthError(400, "invalid_grant", "the resource owner's credentials are not accepted",
          { client: client.id, user: username, reason: verdict.reason });
      }
      sub = verdict.user.name;
      extra = { groups: this.directory().groupsOf(sub) };
    } else {
      // Token exchange (RFC 8693 section 2.1).
      const subjectToken = p("subject_token"), subjectType = p("subject_token_type");
      if (subjectToken === undefined || subjectType === undefined) {
        return oauthError(400, "invalid_request", "subject_token and subject_token_type are given", { client: client.id });
      }
      if (subjectType !== TOKEN_TYPE.accessToken && subjectType !== TOKEN_TYPE.jwt) {
        return oauthError(400, "invalid_request", `a subject token of the type ${subjectType} is not accepted`, { client: client.id });
      }
      const requested = p("requested_token_type");
      if (requested !== undefined && requested !== TOKEN_TYPE.accessToken) {
        return oauthError(400, "invalid_request", `a token of the type ${requested} is not issued`, { client: client.id });
      }
      // A token this controller issued, or one a realm it trusts issued.
      let subject = this.verify(subjectToken, now);
      let foreignRealm: TrustedRealm | undefined;
      if (subject === undefined) {
        const f = await this.verifyForeign(subjectToken, now);
        if (f !== undefined) { subject = f.claims; foreignRealm = f.realm; }
      }
      if (subject === undefined || typeof subject.sub !== "string") {
        // "If ... either the subject_token or actor_token are invalid for any
        // reason, or are unacceptable based on policy ... The value of the error
        // parameter MUST be the invalid_request error code" (RFC 8693 section 2.2.2).
        return oauthError(400, "invalid_request", "the subject token is not one this server issued, or has expired", { client: client.id });
      }
      // A client exchanges the tokens issued **to it**, and nothing else. The
      // audiences its subject tokens must carry are `subject_audiences` where a
      // deployment names them, and otherwise the client's own `audiences` — which
      // is the whole point of the check, and is the safe default rather than the
      // permissive one.
      //
      // While this ran only `if (client.subjectAudiences !== undefined)`, a
      // deployment that had not set it exchanged *any* token this controller ever
      // issued, for any audience, into a live token impersonating that token's
      // subject with that subject's current groups. Combined with `verify` not
      // checking `aud` at all until now, a client with the exchange grant that
      // came by a token for an unrelated service could mint one for itself.
      const wanted = client.subjectAudiences ?? client.audiences;
      if (!audiencesOf(subject.aud).some((a) => wanted.includes(a))) {
        return oauthError(400, "invalid_request",
          "the subject token was not issued to this client: its audience is not one this client " +
          "presents tokens for", { client: client.id });
      }
      if (foreignRealm !== undefined) {
        // Trust is not transitive: a subject already named with a realm came to
        // the trusted realm by an exchange of its own, from a realm this
        // controller has not chosen to trust.
        if (subject.sub.includes("@")) {
          return oauthError(400, "invalid_request", `a subject ${foreignRealm.realm} obtained from another realm is not exchanged here`,
            { client: client.id, user: subject.sub });
        }
        // Named with its realm, as its groups are: not a user of this directory.
        sub = `${subject.sub}@${foreignRealm.realm}`;
        const groups = Array.isArray(subject.groups) ? subject.groups.filter((g): g is string => typeof g === "string" && !g.includes("@")) : [];
        extra = { groups: groups.map((g) => `${g}@${foreignRealm!.realm}`) };
      } else {
        // A user no longer in the directory, or no longer enabled, has no token
        // exchanged for it; a subject of another realm, named with it, is not one.
        const who = this.directory().user(subject.sub);
        if (!subject.sub.includes("@") && subject.groups !== undefined &&
            (who === undefined || who.disabled || (who.expires !== undefined && who.expires.getTime() <= now))) {
          return oauthError(400, "invalid_request", "the subject is no longer a user who may be given a token", { client: client.id, user: subject.sub });
        }
        sub = subject.sub;
        extra = subject.groups === undefined ? {}
          : { groups: subject.sub.includes("@") ? subject.groups : this.directory().groupsOf(sub) };
      }
      // An actor token names who acts for the subject: the act claim (RFC 8693 section 4.1).
      const actorToken = p("actor_token"), actorType = p("actor_token_type");
      if ((actorToken === undefined) !== (actorType === undefined)) {
        return oauthError(400, "invalid_request", "actor_token and actor_token_type are given together", { client: client.id });
      }
      if (actorToken !== undefined) {
        const actor = this.verify(actorToken, now);
        if (actor === undefined || typeof actor.sub !== "string") {
          return oauthError(400, "invalid_request", "the actor token is not one this server issued, or has expired", { client: client.id });
        }
        extra = { ...extra, act: { sub: actor.sub } };
      }
      exchanged = true;
    }

    // The scopes asked for, of those the client may have. "If the issued access
    // token scope is different from the one requested ... the authorization
    // server MUST include the scope response parameter" (RFC 6749 section 3.3),
    // and a scope the client may not have is refused rather than dropped: a
    // client that asked to write and was quietly given a token that reads would
    // discover it at the first write.
    const asking = (p("scope") ?? "").split(/\s+/).filter((s) => s !== "");
    const allowed = client.scopes ?? [];
    const refusedScope = asking.find((s) => !allowed.includes(s));
    if (refusedScope !== undefined) {
      // "invalid_scope: The requested scope is ... exceeds the scope granted by
      // the resource owner" (RFC 6749 section 5.2).
      return oauthError(400, "invalid_scope", `the client may not be issued the scope ${refusedScope}`,
        { client: client.id, scope: refusedScope });
    }
    const granted = [...new Set(asking)];
    const { token, jti } = this.issue(sub, client.id, aud,
      // RFC 9068 section 2.2.3: "scope ... SHOULD be included", as one string.
      { ...extra, ...(granted.length === 0 ? {} : { scope: granted.join(" ") }) }, now);
    return {
      status: 200,
      body: { access_token: token, token_type: "Bearer", expires_in: this.config.lifetimeSeconds,
        ...(granted.length === 0 ? {} : { scope: granted.join(" ") }),
        ...(exchanged ? { issued_token_type: TOKEN_TYPE.accessToken } : {}) },
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store", Pragma: "no-cache" },
      log: { event: "token issued", client: client.id, grant, sub, aud, jti,
        ...(granted.length === 0 ? {} : { scope: granted.join(" ") }) },
    };
  }

  /** The scopes a verified token carries, for a resource deciding what it may do. */
  static scopesOf(claims: Record<string, unknown>): string[] {
    const scope = claims.scope;
    return typeof scope === "string" ? scope.split(/\s+/).filter((s) => s !== "") : [];
  }

  private authenticate(authorization: string | undefined): ClientSpec | undefined {
    const m = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(authorization ?? "");
    if (!m) return undefined;
    const decoded = Buffer.from(m[1], "base64").toString("utf8");
    const cut = decoded.indexOf(":");
    if (cut < 0) return undefined;
    let id: string, secret: string;
    try {
      id = decodeURIComponent(decoded.slice(0, cut).replace(/\+/g, " "));
      secret = decodeURIComponent(decoded.slice(cut + 1).replace(/\+/g, " "));
    } catch {
      return undefined;
    }
    // A client locked by failures is refused without its secret being checked.
    if (this.throttle.locked("client", id)) return undefined;
    const client = this.config.clients.find((c) => c.id === id);
    // A client that is not there has a secret compared all the same.
    const ok = verifySecret(secret, client?.secretHash);
    this.throttle.record("client", id, client !== undefined && ok);
    return client !== undefined && ok ? client : undefined;
  }
}
