// Delegated access control: the exchange between this CDMI server and a
// delegated access control provider, as the subclause of that name specifies
// (CDMI 3.0 working draft, revision 211).
//
// Where an object carries both the cdmi_dac_uri and the cdmi_dac_certificate
// metadata items, the decision is referred to the provider those items
// identify: this server sends the permission mask its access control list
// evaluation yielded, and applies the mask the provider returns in its place.
// "Where the CDMI server does not receive a valid response, it shall not
// perform the operation and shall report the forbidden condition."
//
// This module builds and reads the messages and performs the exchange. It does
// not decide when delegation applies, nor apply the mask; that belongs to
// access control evaluation.

import { randomUUID, type KeyObject, X509Certificate } from "node:crypto";
import {
  chainOf, decryptJweWith, encryptJweJson, importJwk, type Jwk, JoseError, signJwsWith, verifyJws, flattenJws, nestedJws,
} from "./jose.ts";
import { OriginatedError, OriginatedTooLarge, submitOriginated } from "./originated.ts";

/** The version of the request and of the response this server speaks. */
export const DAC_VERSION = "1";

/** The Application Namespace under which a header field is passed through. */
export const PASSTHROUGH_PREFIX = "CDMI-DAC-";

/**
 * The value of "cdmi_operation": the access for which a decision is asked. The
 * three the subclause defines, and the four ECR-066A proposes for the accesses
 * they do not describe. A provider that does not recognize a value denies,
 * which is the safe direction; until that ECR is resolved, a server may be
 * configured to send the three alone (see `narrowOperation`).
 */
export type DacOperation =
  | "cdmi_read" | "cdmi_modify" | "cdmi_delete"
  | "cdmi_read_metadata" | "cdmi_list" | "cdmi_create" | "cdmi_modify_metadata";

/**
 * The mapping onto the three values of revision 247, for a provider that
 * recognizes those alone. Revision 269's table gives seven, which seedmi sends
 * (binding.ts, accessesOf); "A provider that recognizes only the three values of
 * the previous edition still receives cdmi_read, cdmi_modify and cdmi_delete for
 * the accesses they named" (annex E).
 */
export function narrowOperation(operation: DacOperation): "cdmi_read" | "cdmi_modify" | "cdmi_delete" {
  if (operation === "cdmi_delete") return "cdmi_delete";
  return operation === "cdmi_read" || operation === "cdmi_read_metadata" || operation === "cdmi_list"
    ? "cdmi_read" : "cdmi_modify";
}

/** Where delegation is asked of: the two metadata items of the object. */
export interface DacTarget {
  /** The value of the cdmi_dac_uri metadata item. */
  uri: string;
  /** The value of the cdmi_dac_certificate metadata item: a JWK of the provider. */
  certificate: Jwk;
}

/**
 * What this server is, to a provider. Revision 221: the "server_identity"
 * field carries a JWK Set holding "one key whose use member contains sig,
 * whose public key verifies the signature on the request, and one key whose
 * use member contains enc, whose public key a delegated access control
 * provider uses to encrypt the response. The two shall be different keys ...
 * A CDMI server shall use neither key for the purpose of the other."
 */
export interface DacIdentity {
  /** The public sig key, from which the signature algorithm is determined. */
  signingPublic: KeyObject;
  /** The public enc key, from which the key management algorithm is determined. */
  encryptionPublic: KeyObject;
  /** The public sig key, as a JWK; its "use" member is set by this module. */
  signingJwk: Jwk;
  /** The public enc key, as a JWK. */
  encryptionJwk: Jwk;
  /**
   * Signs a JWS signing input with the private sig key, by the JWS algorithm
   * given. Both private keys are credentials of the CDMI server itself, which
   * "Each is a credential reference, configured on the CDMI server, and a CDMI
   * server shall not hold such a secret by any other means", and each is
   * "Operated in place" (the Use of a credential table): this server holds
   * neither, and a key management server performs both operations (dac-kms.ts).
   * Before 0.50 both were held in seedmi.toml.
   */
  sign(alg: string, input: Buffer): Promise<Buffer>;
  /** Unwraps a response's content encryption key with the private enc key, by RSA-OAEP with the hash given. */
  unwrap(encryptedKey: Buffer, oaepHash: string): Promise<Buffer>;
  /**
   * Reads the public parts again where a key has changed, before a request is
   * made. Where the keys cannot be resolved the request is not made: "a key
   * management server that is unavailable stops the operation rather than
   * falling back" (PLAN-dac.md phase 6).
   */
  refresh?(): Promise<void>;
}

/** The JWK Set a request carries, with each key marked for its one purpose. */
export function identitySet(identity: DacIdentity): { keys: Jwk[] } {
  return {
    keys: [
      { ...identity.signingJwk, use: "sig" },
      { ...identity.encryptionJwk, use: "enc" },
    ],
  };
}

/** The key of a JWK Set for a purpose, where the set holds exactly one. */
export function keyFor(set: unknown, use: "sig" | "enc"): Jwk {
  const keys = (set as { keys?: unknown })?.keys;
  if (!Array.isArray(keys)) throw new DacError("the identity is not a JWK Set");
  const found = keys.filter((k) => (k as Jwk)?.use === use);
  if (found.length !== 1) {
    throw new DacError(`the JWK Set holds ${found.length} keys whose use is ${use}, and one is required`);
  }
  return found[0] as Jwk;
}

/** The context of the operation for which a decision is asked. */
export interface DacContext {
  objectId: string;
  operation: DacOperation;
  /** The mask access control list evaluation yielded, in the form of Annex C. */
  effectiveMask: string;
  principal?: { name: string; groups: string[] };
  /** Header fields of the operation beginning CDMI-DAC-, by their names. */
  clientHeaders?: Record<string, string>;
  /** Where the key of an encrypted object is asked for (phase 7). */
  encryptionKeyId?: string;
  /** Where a response is to be sent out of band (phase 4). */
  responseUri?: string;
}

/** What a provider decided. */
export interface DacDecision {
  /** Whether this decision was retained from an earlier identical operation. */
  cached?: boolean;
  /** The mask to be applied in place of the one sent. */
  appliedMask: string;
  responseHeaders: Record<string, string>;
  objectKey?: Jwk;
  /** Milliseconds since the epoch, where the response states an expiry. */
  responseCacheExpiry?: number;
  keyCacheExpiry?: number;
  redirectObjectId?: string;
  auditUri?: string;
}

/** The exchange did not yield a decision; the caller reports the forbidden condition. */
export class DacError extends Error {
  /** Whether the failure was of the exchange rather than of the decision. */
  readonly unavailable: boolean;
  constructor(message: string, unavailable = false) {
    super(message);
    this.name = "DacError";
    this.unavailable = unavailable;
  }
}

const text = (v: unknown, what: string): string => {
  if (typeof v !== "string") throw new DacError(`the response has no ${what}`);
  return v;
};

/** A date of the form the draft's basic types define, as milliseconds since the epoch. */
function dateOf(v: unknown, what: string): number {
  const ms = Date.parse(String(v));
  if (Number.isNaN(ms)) throw new DacError(`the ${what} of the response is not a time`);
  return ms;
}

export interface DacOptions {
  identity: DacIdentity;
  /**
   * Where a response is to be sent where it is not returned to the request:
   * the "dac_response_uri" field of every request this server submits. A
   * provider answering asynchronously sends the packaged response there, and
   * `acceptAsync` receives it.
   */
  responseUri?: string;
  /**
   * How long a response is accepted for a request, in milliseconds. The
   * subclause leaves this to the server ("a period it determines"); ECR-067A
   * proposes that it be reported and be at least 60 seconds, which is the
   * default here.
   */
  responseWindowMs?: number;
  /** Trust anchors for the TLS connection to a provider, in PEM. */
  ca?: string;
  /** The schemes this server submits a request to (the cdmi_dac_methods capability). */
  methods?: string[];
  now?: () => number;
}

interface Outstanding {
  at: number;
  /** The provider the request went to, so that a response is matched to it. */
  certificate: Jwk;
  /** Where an operation is waiting for this response to arrive out of band. */
  waiting?: {
    resolve: (decision: DacDecision) => void;
    reject: (e: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  };
}

export class DacClient {
  private readonly opts: Required<Pick<DacOptions, "identity" | "responseWindowMs" | "methods">> & DacOptions;

  /**
   * The identity this server presents to a provider, refreshed from the key
   * management server. A provider authenticates a CDMI server by its
   * registered public signing key, and since 0.50 this server holds neither
   * identity key, so an operator has no other way to read it (weedmi, 0.70).
   */
  async identityNow(): Promise<{ signingPublic: KeyObject; signingJwk: Jwk }> {
    await this.opts.identity.refresh?.();
    return {
      signingPublic: this.opts.identity.signingPublic,
      signingJwk: this.opts.identity.signingJwk,
    };
  }
  /** Requests submitted and not yet answered, by their dac_request_id. */
  private readonly outstanding = new Map<string, Outstanding>();
  /**
   * Responses retained to their stated expiry. "A retained response shall be
   * used only for an operation identical to the one for which it was obtained,
   * in respect of the principal, the object ID, the operation, the permission
   * mask determined by access control list evaluation, and any information
   * passed through from the CDMI client", so the key of this map is all of
   * those together with the provider addressed.
   */
  private readonly retained = new Map<string, { expiry: number; objectId: string; decision: DacDecision }>();

  constructor(opts: DacOptions) {
    this.opts = {
      responseWindowMs: 60_000,
      methods: ["https"],
      ...opts,
    };
  }

  private now(): number {
    return (this.opts.now ?? Date.now)();
  }

  /** The URI schemes this server submits a request to (the cdmi_dac_methods capability). */
  /** The response window, in milliseconds (revision 269, cdmi_dac_response_window). */
  get responseWindowMs(): number { return this.opts.responseWindowMs; }

  get methods(): string[] {
    return [...this.opts.methods];
  }

  /** The window within which a response is accepted, in seconds (ECR-067A). */
  get responseWindowSeconds(): number {
    return Math.round(this.opts.responseWindowMs / 1000);
  }

  /** What makes one operation identical to another, for a retained response. */
  private static retentionKey(target: DacTarget, ctx: DacContext): string {
    return JSON.stringify([
      target.uri, target.certificate,
      ctx.objectId, ctx.operation, ctx.effectiveMask,
      ctx.principal?.name ?? null, [...(ctx.principal?.groups ?? [])].sort(),
      Object.entries(ctx.clientHeaders ?? {}).sort(),
      ctx.encryptionKeyId ?? null,
    ]);
  }

  /**
   * Discards every response retained for an object. "A CDMI server shall
   * discard a retained response where the access control list of the object,
   * the cdmi_dac_uri metadata item or the cdmi_dac_certificate metadata item
   * of the object changes, so that a decision obtained under one configuration
   * is not applied under another."
   */
  forget(objectId: string): void {
    for (const [key, held] of this.retained) {
      if (held.objectId === objectId) this.retained.delete(key);
    }
  }

  /** A response retained for this operation, where one is held and has not expired. */
  retainedFor(target: DacTarget, ctx: DacContext): DacDecision | undefined {
    const key = DacClient.retentionKey(target, ctx);
    const held = this.retained.get(key);
    if (held === undefined) return undefined;
    if (held.expiry <= this.now()) {
      this.retained.delete(key);
      return undefined;
    }
    return { ...held.decision, cached: true };
  }

  /**
   * The keys whose retention has ended since this was last called, so that the
   * caller records the audit of purging each ("audit logging messages shall be
   * generated for ... determining when to purge the key").
   */
  purgeExpired(): { objectId: string; auditUri?: string }[] {
    const purged: { objectId: string; auditUri?: string }[] = [];
    const now = this.now();
    for (const [key, held] of this.retained) {
      if (held.expiry > now) continue;
      this.retained.delete(key);
      if (held.decision.objectKey !== undefined || held.decision.keyCacheExpiry !== undefined) {
        purged.push({
          objectId: held.objectId,
          ...(held.decision.auditUri === undefined ? {} : { auditUri: held.decision.auditUri }),
        });
      }
    }
    return purged;
  }

  /**
   * The request of Table 190, in the order of that table. The identifier "shall
   * be unique within the window within which multiple DAC responses can be
   * received".
   */
  buildRequest(ctx: DacContext, id = randomUUID()): Record<string, unknown> {
    const request: Record<string, unknown> = {
      dac_request_version: DAC_VERSION,
      dac_request_id: id,
      server_identity: identitySet(this.opts.identity),
    };
    if (ctx.principal !== undefined) {
      request.client_identity = { acl_name: ctx.principal.name, acl_group: ctx.principal.groups };
    }
    request.acl_effective_mask = ctx.effectiveMask;
    // Mandatory, and an empty object where the operation carried no such header
    // field (the committee's answer, and ECR-066A).
    request.client_headers = { ...(ctx.clientHeaders ?? {}) };
    request.cdmi_objectID = ctx.objectId;
    if (ctx.encryptionKeyId !== undefined) request.cdmi_enc_key_id = ctx.encryptionKeyId;
    request.cdmi_operation = ctx.operation;
    const responseUri = ctx.responseUri ?? this.opts.responseUri;
    if (responseUri !== undefined) request.dac_response_uri = responseUri;
    return request;
  }

  /**
   * The packaged request of Table 194: the request encrypted to the provider
   * and signed by this server, together with what an intermediary needs to
   * route it.
   */
  async packageRequest(request: Record<string, unknown>, target: DacTarget): Promise<Record<string, unknown>> {
    const recipient = importJwk(target.certificate);
    const signed = await signJwsWith(Buffer.from(JSON.stringify(request), "utf8"), this.opts.identity.signingPublic,
      (alg, input) => this.opts.identity.sign(alg, input));
    return {
      // Signed, then encrypted, the JWS in the flattened JSON serialization and
      // cty "jose+json" (revision 269; ECR-073B). Before 0.61 the JWS was compact,
      // with cty "JWT".
      dac_request: encryptJweJson(Buffer.from(JSON.stringify(flattenJws(signed)), "utf8"), recipient, { cty: "jose+json" }),
      dac_request_dest_certificate: target.certificate,
      dac_request_dest_uri: target.uri,
    };
  }

  /**
   * Asks the provider, and returns what it decided. Every failure of the
   * exchange is a DacError: the caller reports the forbidden condition, as the
   * subclause requires of a CDMI server that receives no valid response.
   */
  async decide(target: DacTarget, ctx: DacContext): Promise<DacDecision> {
    try {
      await this.opts.identity.refresh?.();
    } catch (e) {
      throw new DacError(`this server's identity is unavailable: ${(e as Error).message}`);
    }
    const scheme = schemeOf(target.uri);
    if (!this.opts.methods.includes(scheme)) {
      // "Where the scheme of that URI is not one reported by the
      // cdmi_dac_methods capability, the CDMI server shall not perform the
      // operation and shall report the capability not present condition."
      throw new DacError(`this server submits no delegated access control request of the scheme ${scheme}`, true);
    }
    // A response retained from an identical operation is used in place of an
    // exchange; the caller records the audit of performing the operation, as
    // the subclause requires for "every operation permitted on the basis of a
    // retained copy of it".
    const held = this.retainedFor(target, ctx);
    if (held !== undefined) return held;
    const id = randomUUID();
    const request = this.buildRequest(ctx, id);
    const packaged = await this.packageRequest(request, target);
    this.outstanding.set(id, { at: this.now(), certificate: target.certificate });
    this.forgetExpired();
    let answer;
    try {
      answer = await submitOriginated(target.uri, {
        method: "POST",
        body: Buffer.from(JSON.stringify(packaged), "utf8"),
        contentType: "application/json",
        accept: "application/json",
        ...(this.opts.ca === undefined ? {} : { ca: this.opts.ca }),
      });
    } catch (e) {
      this.outstanding.delete(id);
      if (e instanceof OriginatedTooLarge) throw new DacError("the provider returned more than this server reads", true);
      if (e instanceof OriginatedError) throw new DacError("the provider could not be reached", true);
      throw e;
    }
    // "A delegated access control provider that has decided shall respond with
    // an HTTP status code of 200 OK ... A provider that will answer later ...
    // shall respond with 202 Accepted and no content. A CDMI server shall treat
    // any other status code as the absence of a valid response" (revision 269).
    // Before 0.61 any 2xx was taken, an empty body as a later answer.
    const decided = answer.status === 200 && answer.body.length > 0;
    const later = answer.status === 202 && answer.body.length === 0;
    if (!decided && !later) {
      this.outstanding.delete(id);
      throw new DacError(`the provider answered ${answer.status}${answer.body.length === 0 ? " with no content" : ""}, ` +
        "which is neither 200 with a response nor 202 without one", true);
    }
    // A provider that will answer later sends the response to the
    // "dac_response_uri" of the request rather than returning it here.
    if (later) {
      if (this.opts.responseUri === undefined && ctx.responseUri === undefined) {
        this.outstanding.delete(id);
        throw new DacError("the provider returned no response, and none was asked to be sent elsewhere", true);
      }
      return this.awaitResponse(id, target, ctx);
    }
    const decision = await this.accept(answer.body, target);
    // "Where a response specifies a cache expiry, a CDMI server may retain the
    // response, or the key it contains, until that expiry"; where it specifies
    // none, "the response shall not be cached".
    if (decision.responseCacheExpiry !== undefined && decision.responseCacheExpiry > this.now()) {
      this.retained.set(DacClient.retentionKey(target, ctx),
        { expiry: decision.responseCacheExpiry, objectId: ctx.objectId, decision });
    }
    return decision;
  }

  /**
   * Waits for a response to arrive out of band, to the URI the request stated.
   * The wait ends with the response, or when the window within which one is
   * accepted has passed, whichever is first.
   */
  private awaitResponse(id: string, target: DacTarget, ctx: DacContext): Promise<DacDecision> {
    const held = this.outstanding.get(id);
    if (held === undefined) throw new DacError("the request is no longer awaiting a response");
    return new Promise<DacDecision>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.outstanding.delete(id);
        reject(new DacError("no response arrived within the window within which one is accepted", true));
      }, this.opts.responseWindowMs);
      held.waiting = {
        resolve: (decision) => {
          // A response that arrives out of band is retained as one returned to
          // the request is (see decide).
          if (decision.responseCacheExpiry !== undefined && decision.responseCacheExpiry > this.now()) {
            this.retained.set(DacClient.retentionKey(target, ctx),
              { expiry: decision.responseCacheExpiry, objectId: ctx.objectId, decision });
          }
          resolve(decision);
        },
        reject,
        timer,
      };
    });
  }

  /**
   * Receives a packaged response that arrived out of band, at the URI the
   * request stated. The provider it came from is not known in advance, so the
   * response is decrypted with this server's key and then verified against the
   * provider of each request awaiting one; it is acted upon only where one of
   * them verifies it, and never before.
   *
   * Returns the identifier of the request it answered, or undefined where it
   * answers none.
   */
  async acceptAsync(body: Buffer): Promise<string | undefined> {
    // Decrypted once, the content key unwrapped by one operation at the key
    // management server, and then verified against each provider in turn.
    let opened: Record<string, string>;
    try {
      opened = await this.open(body);
    } catch {
      return undefined;
    }
    for (const [id, held] of [...this.outstanding]) {
      let decision: DacDecision;
      try {
        decision = this.acceptOpened(opened, { uri: "", certificate: held.certificate });
      } catch {
        continue;
      }
      const waiting = held.waiting;
      if (waiting !== undefined) {
        clearTimeout(waiting.timer);
        waiting.resolve(decision);
      }
      return id;
    }
    return undefined;
  }

  /**
   * Reads a packaged response: decrypts it, verifies its signature, matches it
   * to a request submitted and not yet answered, and returns the decision.
   * Used for a response returned to the request and, from phase 4, for one that
   * arrives out of band.
   */
  async accept(body: Buffer, target?: DacTarget): Promise<DacDecision> {
    return this.acceptOpened(await this.open(body), target);
  }

  /**
   * Decrypts a packaged response with the key of the server identity the
   * request carried, the content encryption key unwrapped in place, and
   * returns the JWS it holds. Nothing the response says is read here.
   */
  private async open(body: Buffer): Promise<Record<string, string>> {
    let packaged: Record<string, unknown>;
    try {
      packaged = JSON.parse(body.toString("utf8")) as Record<string, unknown>;
    } catch {
      throw new DacError("the response is not JSON");
    }
    const inner = packaged.dac_response;
    if (typeof inner !== "object" || inner === null) throw new DacError("the response holds no dac_response");
    // Decrypt with the key of the server identity the request carried, then
    // verify with the provider's key. Both are done before anything the
    // response says is read.
    let decrypted;
    try {
      decrypted = await decryptJweWith(inner as Record<string, unknown>, this.opts.identity.encryptionPublic,
        (encryptedKey, oaepHash) => this.opts.identity.unwrap(encryptedKey, oaepHash));
    } catch (e) {
      throw new DacError(`the response does not decrypt: ${(e as Error).message}`);
    }
    try {
      return nestedJws(decrypted);
    } catch (e) {
      throw new DacError(`the response does not hold a JWS as revision 269 requires: ${(e as Error).message}`);
    }
  }

  /** Verifies an opened response against the provider expected, and returns the decision it states. */
  private acceptOpened(opened: Record<string, string>, target?: DacTarget): DacDecision {
    const response = this.verified(opened, target);
    const id = text(response.dac_response_id, "dac_response_id");
    const held = this.outstanding.get(id);
    if (held === undefined) {
      // "Where the response matches no such request, the CDMI server shall not
      // perform the operation", and at most one response is accepted for each.
      throw new DacError("the response matches no request awaiting one");
    }
    if (this.now() - held.at > this.opts.responseWindowMs) {
      this.outstanding.delete(id);
      throw new DacError("the response arrived after the window within which one is accepted");
    }
    this.outstanding.delete(id);
    if (text(response.dac_response_version, "dac_response_version") !== DAC_VERSION) {
      throw new DacError("the response is of another version");
    }
    const decision: DacDecision = {
      appliedMask: text(response.dac_applied_mask, "dac_applied_mask"),
      responseHeaders: {},
    };
    const headers = response.dac_response_headers;
    if (typeof headers === "object" && headers !== null) {
      for (const [name, value] of Object.entries(headers as Record<string, unknown>)) {
        // "A series of headers that start with CDMI-DAC- to be returned to the
        // CDMI client": a member outside that prefix is ignored, so that a
        // provider cannot set a header field of the response that the CDMI
        // client would read as this server's own. The name is carried in lower
        // case, as in the other direction (ECR-074A).
        if (name.toUpperCase().startsWith(PASSTHROUGH_PREFIX) && typeof value === "string") {
          decision.responseHeaders[name.toLowerCase()] = value;
        }
      }
    }
    if (response.dac_object_key !== undefined) decision.objectKey = response.dac_object_key as Jwk;
    if (response.dac_response_cache_expiry !== undefined) {
      decision.responseCacheExpiry = dateOf(response.dac_response_cache_expiry, "dac_response_cache_expiry");
    }
    if (response.dac_key_cache_expiry !== undefined) {
      decision.keyCacheExpiry = dateOf(response.dac_key_cache_expiry, "dac_key_cache_expiry");
    }
    if (response.dac_redirect_objectID !== undefined) {
      decision.redirectObjectId = text(response.dac_redirect_objectID, "dac_redirect_objectID");
    }
    if (response.dac_audit_uri !== undefined) decision.auditUri = text(response.dac_audit_uri, "dac_audit_uri");
    return decision;
  }

  /**
   * Verifies the signature of a response. It is signed by the provider's key,
   * or by a key whose certificate chains to the certificate of the
   * cdmi_dac_certificate metadata item. "A verification key that is retrievable
   * from a JOSE header of the response, and that does not so chain, shall not
   * be used."
   */
  private verified(jws: Record<string, string>, target?: DacTarget): Record<string, unknown> {
    const certificate = target?.certificate;
    if (certificate === undefined) throw new DacError("the provider of the response is not known");
    const attempts: KeyObject[] = [importJwk(certificate)];
    const anchor = chainOf(certificate)[0];
    const offered = headerChain(jws);
    if (offered !== undefined && anchor !== undefined && offered.verify(anchor.publicKey)) {
      // A different key, whose certificate chains to the provider's.
      attempts.push(offered.publicKey);
    }
    for (const key of attempts) {
      try {
        const verified = verifyJws(jws, key);
        const payload = JSON.parse(verified.payload.toString("utf8")) as unknown;
        if (typeof payload !== "object" || payload === null) throw new DacError("the response is not a JSON object");
        return payload as Record<string, unknown>;
      } catch (e) {
        if (e instanceof DacError) throw e;
        if (!(e instanceof JoseError)) throw e;
      }
    }
    throw new DacError("the signature of the response is not the provider's");
  }

  private forgetExpired(): void {
    const now = this.now();
    for (const [id, held] of this.outstanding) {
      if (now - held.at > this.opts.responseWindowMs) this.outstanding.delete(id);
    }
  }

  /** Whether a response is still accepted for a request, for a test and for phase 4. */
  awaiting(id: string): boolean {
    const held = this.outstanding.get(id);
    return held !== undefined && this.now() - held.at <= this.opts.responseWindowMs;
  }
}

function schemeOf(uri: string): string {
  try {
    return new URL(uri).protocol.replace(":", "");
  } catch {
    throw new DacError(`${uri} is not an absolute URI`);
  }
}

/** The certificate a JWS offers in its protected header, where it offers one. */
function headerChain(jws: Record<string, string>): X509Certificate | undefined {
  try {
    const header = JSON.parse(Buffer.from(jws.protected, "base64url").toString("utf8")) as { x5c?: string[] };
    if (header.x5c === undefined || header.x5c.length === 0) return undefined;
    return new X509Certificate(Buffer.from(header.x5c[0], "base64"));
  } catch {
    return undefined;
  }
}
