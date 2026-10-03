// The authorization of the CDMI over MCP binding.
//
// "A CDMI server that supports this protocol binding shall act as an OAuth
// 2.1 resource server, and shall: publish protected resource metadata as
// specified in RFC 9728, stating the authorization servers it accepts;
// return, where a request contains no access token or an access token it
// does not accept, the response its transport defines; validate that each
// access token presented to it was issued for it, and reject a token that
// does not identify it; resolve the subject of the access token to a
// principal within the domain that owns the object" (revision 347).
//
// The verification of a token itself is the domain controller's, which
// already fetches a key set, verifies a signature and checks an audience:
// this module is the resource server around it — the metadata, the
// challenge, the scopes, and the rule that a scope grants nothing.
import type { Principal } from "./acl.ts";

/** The scopes this binding defines, in the subclause's words. */
export const SCOPE_READ = "cdmi:read";
export const SCOPE_WRITE = "cdmi:write";
export const SCOPE_ADMIN = "cdmi:admin";
export const SCOPES = [SCOPE_READ, SCOPE_WRITE, SCOPE_ADMIN];

/**
 * The scope a call requires, or undefined where this server requires none.
 *
 * "cdmi:read, which permits an operation that reads an object or lists the
 * children of a container object; cdmi:write, which permits an operation
 * that creates, updates or deletes an object; and cdmi:admin, which permits
 * an operation upon an export entry, an import entry, an access control
 * list ... A CDMI server that requires scopes requires cdmi:admin for a
 * call that supplies such an item, whatever else the call does."
 */
export function scopeFor(tool: string, body: Record<string, unknown> | undefined): string {
  if (body !== undefined && suppliesAdministrativeItem(body)) return SCOPE_ADMIN;
  return tool === "cdmi_read" ? SCOPE_READ : SCOPE_WRITE;
}

/** Whether a representation supplies an export entry, an import entry or an access control list. */
function suppliesAdministrativeItem(body: Record<string, unknown>): boolean {
  if ("exports" in body || "imports" in body) return true;
  const metadata = body.metadata;
  if (typeof metadata === "object" && metadata !== null && "cdmi_acl" in metadata) return true;
  return false;
}

export interface Authorization {
  /** The principal the subject of the token resolves to. */
  principal: Principal;
  /** The scopes the token carries, where it carries any. */
  scopes: string[];
}

/** Raised where a request carries no token, or one this server does not accept. */
export class Unauthenticated extends Error {
  readonly challenge: string;
  constructor(challenge: string, message: string) {
    super(message);
    this.name = "Unauthenticated";
    this.challenge = challenge;
  }
}

/** Raised where a token is accepted but does not carry the scope the call requires. */
export class InsufficientScope extends Error {
  readonly challenge: string;
  readonly required: string;
  constructor(challenge: string, required: string) {
    super(`this operation requires the ${required} scope`);
    this.name = "InsufficientScope";
    this.challenge = challenge;
    this.required = required;
  }
}

export interface ResourceServerOptions {
  /** The address of this endpoint, which is the resource identifier. */
  resource: string;
  /**
   * The authorization servers whose tokens this server accepts, read at each
   * request: a deployment configures one after this endpoint is built.
   */
  authorizationServers: string[] | (() => string[]);
  /** The scopes this server requires, or none where it requires no scope. */
  scopesRequired: boolean;
  /**
   * Verifies a token at the domain named, and resolves its subject to a
   * principal there. "Resolve the subject of the access token to a
   * principal within the domain that owns the object": which domain that
   * is cannot be known in the transport, before the target of the call has
   * been read, so this is called by the operation and not by the endpoint.
   * The audience is checked here, by the domain controller: "validate that
   * each access token presented to it was issued for it".
   */
  verifyIn: (domain: string, token: string)
    => Promise<{ principal: Principal; scopes: string[] } | undefined>;
  /**
   * Whether a token is one an authorization server this CDMI server accepts
   * issued for it. "A CDMI server shall ... validate that each access token
   * presented to it was issued for it, and reject a token that does not
   * identify it as the intended recipient", which applies to every method
   * and not only to a tool call: a method that addresses no object — the
   * tool list, the initialization — names no domain to resolve a subject
   * within, and its token was not checked at all before 0.83.
   */
  accepts: (token: string) => Promise<boolean>;
}

export class ResourceServer {
  private readonly opts: ResourceServerOptions;

  constructor(opts: ResourceServerOptions) {
    this.opts = opts;
  }

  /**
   * The protected resource metadata of RFC 9728, served at
   * /.well-known/oauth-protected-resource, which is how a client discovers
   * where to obtain a token for this endpoint.
   */
  metadata(): Record<string, unknown> {
    return {
      resource: this.opts.resource,
      authorization_servers: typeof this.opts.authorizationServers === "function"
        ? this.opts.authorizationServers()
        : this.opts.authorizationServers,
      bearer_methods_supported: ["header"],
      // The scopes this binding defines, published whether or not this
      // deployment requires one: RFC 9728 has this describe what the resource
      // understands, not what it demands, and a client pre-configuring a
      // space-separated scope list reads it from here. It was published only
      // where scopes were required, so a client of a deployment that does not
      // require them had nothing to fill that field from.
      scopes_supported: SCOPES,
    };
  }

  /**
   * The challenge of a response to a request with no token or one that is
   * not accepted. The resource metadata is named so that a client can find
   * the authorization server without being told out of band.
   */
  private challenge(error?: string, description?: string, scope?: string): string {
    const parts = [
      `Bearer resource_metadata="${metadataUrl(this.opts.resource)}"`,
    ];
    if (error !== undefined) parts.push(`error="${error}"`);
    if (description !== undefined) parts.push(`error_description="${description}"`);
    // "the scope attribute ... SHOULD be included" with an insufficient_scope
    // error, and its value is "a space-delimited list of case-sensitive scope
    // values" (RFC 6750, RFC 6749). A client reading a comma-delimited value
    // sends it back as one scope and is refused again, so the separator is a
    // space here as it is everywhere else scopes are written.
    if (scope !== undefined) parts.push(`scope="${scope}"`);
    return parts.join(", ");
  }

  /**
   * The token a request bears, which the endpoint takes before it reads
   * the message. A request with no token is the unauthenticated condition
   * and is reported by the transport; whether the token is accepted cannot
   * be decided here, since the domain it is resolved at is the domain of
   * the object the call names.
   */
  tokenOf(authorization: string | undefined): string {
    const token = bearer(authorization);
    if (token === undefined) {
      throw new Unauthenticated(this.challenge(),
        "this endpoint requires an access token of an authorization server it accepts");
    }
    return token;
  }

  /**
   * Checks that a token is one this CDMI server accepts, before any message
   * is read. The subject is not resolved here: the domain within which it is
   * resolved is the domain that owns the object a call addresses, which the
   * transport does not know. What is checked is that an authorization server
   * this server accepts issued the token, for this server.
   */
  async accept(token: string): Promise<void> {
    if (await this.opts.accepts(token)) return;
    throw new Unauthenticated(
      this.challenge("invalid_token",
        "the access token was not issued for this CDMI server by an authorization " +
        "server it accepts"),
      "the access token is not accepted");
  }

  /**
   * The principal a token resolves to within a domain, once the operation
   * knows which domain owns the object it addresses. A token this server
   * does not accept is the unauthenticated condition, reported with the
   * challenge that says so.
   */
  async resolveIn(domain: string, token: string): Promise<Authorization> {
    const accepted = await this.opts.verifyIn(domain, token);
    if (accepted === undefined) {
      // "Reject a token that does not identify it": a token issued for
      // another resource is not accepted here, whatever else it carries.
      throw new Unauthenticated(
        this.challenge("invalid_token", "the access token is not accepted by this CDMI server"),
        "the access token is not accepted");
    }
    return { principal: accepted.principal, scopes: accepted.scopes };
  }

  /**
   * The scope a call requires, where this server requires scopes. "A scope
   * permits no operation the access control lists of an object do not
   * permit": this narrows what a token may ask for and grants nothing, and
   * the access control lists are evaluated afterwards regardless.
   */
  demandScope(auth: Authorization, tool: string, body?: Record<string, unknown>): void {
    if (!this.opts.scopesRequired) return;
    const required = scopeFor(tool, body);
    if (auth.scopes.includes(required)) return;
    throw new InsufficientScope(
      this.challenge("insufficient_scope", `the ${required} scope is required`, required), required);
  }
}

/** The token of an Authorization header field, where it bears one. */
export function bearer(authorization: string | undefined): string | undefined {
  if (authorization === undefined) return undefined;
  const m = /^Bearer[ \t]+([^ \t]+)[ \t]*$/i.exec(authorization);
  return m === null ? undefined : m[1];
}

/**
 * Where the protected resource metadata of a resource is published. "The
 * well-known URI path suffix is appended to the path component of the
 * resource identifier, after the host" (RFC 9728), so a resource at
 * https://host/mcp publishes its metadata at
 * https://host/.well-known/oauth-protected-resource/mcp and not at
 * https://host/mcp/.well-known/oauth-protected-resource, which this server
 * named in its challenge until 0.83. A client that followed the challenge,
 * as the subclause tells it to, met a 405 (weedmi BMCP-010).
 */
export function metadataUrl(resource: string): string {
  const u = new URL(resource);
  const at = u.pathname.replace(/\/$/, "");
  return `${u.origin}/.well-known/oauth-protected-resource${at === "/" ? "" : at}`;
}
