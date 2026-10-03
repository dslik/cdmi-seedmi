// Resolving a principal. The draft leaves the means to the server, so
// seedmi takes HTTP Basic credentials against a directory given on the
// command line. A request with no credentials, or with credentials seedmi
// does not accept, is the anonymous principal.

import { timingSafeEqual } from "node:crypto";
import { ANONYMOUS, type Principal } from "./acl.ts";
import { type VerifyOptions, scopesOfClaims, verifyJWT } from "./oauth.ts";
import { unauthenticated } from "./problems.ts";

interface User {
  password: string;
  groups: string[];
  administrator: boolean;
  privileges: string[];
  /**
   * The domain that recognizes this identity, as a namespace path. A
   * sub-domain recognizes the principals its parent domain
   * recognizes, so an identity of a domain is recognized within it and
   * everything beneath it.
   */
  domain: string;
}

/** The domain at the root of the hierarchy, which recognizes by default. */
export const ROOT_DOMAIN = "/cdmi_domains/";

export class Directory {
  private readonly users = new Map<string, User>();
  /**
   * The privileges conferred on a group, by domain and group name.
   * A principal holds a privilege where the CDMI server confers it
   * on that principal or on a group to which it belongs.
   */
  private readonly groupPrivileges = new Map<string, string[]>();

  /**
   * Confers privileges on a group within a domain. Every principal
   * belonging to that group holds them.
   */
  grantToGroup(domain: string, group: string, privileges: string[]): void {
    for (const p of privileges) {
      if (!PRIVILEGES.includes(p)) {
        throw new Error(
          `${p} is not a privilege this document defines: ` +
          `${PRIVILEGES.join(", ")}`);
      }
    }
    const at = domain.endsWith("/") ? domain : `${domain}/`;
    this.groupPrivileges.set(`${at}\u0000${group}`, privileges);
  }
  /**
   * The privileges conferred within a domain on any of the groups given: a
   * principal resolved at a domain controller holds those of its groups there.
   */
  privilegesOf(domain: string, groups: string[]): string[] {
    const at = domain.endsWith("/") ? domain : `${domain}/`;
    return [...new Set(groups.flatMap((g) => this.groupPrivileges.get(`${at}\u0000${g}`) ?? []))];
  }

  /**
   * How an access token is verified, where this server accepts one. A
   * principal resolved from a token can be delegated to an import
   * source; one resolved from a password cannot, since no token can be
   * obtained from a password.
   */
  tokens?: VerifyOptions;

  /**
   * Adds a user from a specification of the form
   * name:password[:group,group][:privilege,privilege][:domain].
   */
  add(spec: string): void {
    // A domain is a namespace path and holds solidi, so it is taken
    // from the end rather than by splitting on every colon.
    const parts = spec.split(":");
    const domain = parts.length > 4 ? parts.slice(4).join(":") : ROOT_DOMAIN;
    const [name, password, groups = "", flags = ""] = parts;
    if (!name || password === undefined) {
      throw new Error(`a user is given as name:password[:groups][:flags], not ${spec}`);
    }
    const given = flags === "" ? [] : flags.split(",");
    const administrator = given.includes("admin");
    // A privilege is conferred by naming it, and a name that is
    // not one this document defines confers nothing: accepting it
    // silently would leave an operation refused for a reason no
    // configuration explains.
    for (const f of given) {
      if (f !== "admin" && !PRIVILEGES.includes(f)) {
        throw new Error(
          `${f} is not a privilege this document defines: ` +
          `${PRIVILEGES.join(", ")}`);
      }
    }
    // An administrator may configure an import in service identity mode
    // with no credential of its own. Any other privilege is conferred
    // by naming it: cross_domain lets a principal give an object a
    // domain other than that of its parent.
    const privileges = given.filter((f) => f !== "admin");
    if (administrator) privileges.push("import_service_credential");
    this.users.set(`${domain}\u0000${name}`, {
      password,
      groups: groups === "" ? [] : groups.split(","),
      administrator,
      privileges,
      domain: domain.endsWith("/") ? domain : `${domain}/`,
    });
  }

  get size(): number {
    return this.users.size;
  }

  /**
   * The identity of that name a domain recognizes: the one the domain
   * itself holds, or the nearest above it. An identity of a
   * sub-domain hides one of the same name above it.
   */
  private within(name: string, domain: string): User | undefined {
    let at = domain.endsWith("/") ? domain : `${domain}/`;
    for (;;) {
      const user = this.users.get(`${at}\u0000${name}`);
      if (user) return user;
      if (at === ROOT_DOMAIN || !at.startsWith(ROOT_DOMAIN)) return undefined;
      const trimmed = at.replace(/\/$/, "");
      const cut = trimmed.lastIndexOf("/");
      at = trimmed.slice(0, cut + 1);
    }
  }

  /**
   * The principal of that name as this server holds it, for a decision made
   * without a request: an export that publishes outward does so under the
   * authority of the principal that created its entry, and there is no
   * credential to resolve when a value is published. The groups and privileges
   * are the ones the identity holds now, so a principal removed from a group
   * loses what the group granted it.
   */
  principalNamed(name: string, domain = ROOT_DOMAIN): Principal {
    const user = this.within(name, domain);
    const groups = user?.groups ?? [];
    return {
      name,
      groups,
      administrator: (user?.privileges ?? []).includes("administrator"),
      privileges: [...new Set([...(user?.privileges ?? []), ...this.privilegesOf(domain, groups)])],
    };
  }

  /** The identities a domain recognizes, for a test and for reporting. */
  namesIn(domain: string): string[] {
    const out: string[] = [];
    for (const key of this.users.keys()) {
      const [where, name] = key.split("\u0000");
      if (this.within(name, domain)?.domain === where) out.push(name);
    }
    return [...new Set(out)].sort();
  }

  /**
   * The means by which this server authenticates a principal. A request
   * that presents none, or one this server does not accept, is the
   * anonymous principal rather than an error.
   */
  methods(): string[] {
    const out: string[] = [];
    if (this.users.size > 0) out.push("basic");
    if (this.tokens !== undefined) out.push("bearer");
    // "Each value is the name of an HTTP authentication scheme registered
    // with IANA, and unauthenticated access is not reported, being provided
    // for by granting access to ANONYMOUS@" (revision 347). This server
    // reported "anonymous" as a method until then (ECR-154B).
    return out;
  }

  /**
   * The principal a token resolves to, or undefined where this server does
   * not accept it. Exposed so that a protocol binding can check a token
   * against the authorization server this deployment accepts without
   * resolving a principal for an operation: the MCP transport validates
   * every token before it reads the message, for a method that addresses no
   * object as for one that does.
   */
  principalOfToken(token: string): Principal | undefined {
    if (this.tokens === undefined) return undefined;
    const p = this.fromToken(token);
    return p.name === ANONYMOUS.name ? undefined : p;
  }

  /**
   * The same, with the scopes the token carries.
   *
   * A deployment configured with an [oauth] issuer and no domain controller
   * accepts a token at the transport and could resolve no principal from it for
   * an operation until 0.86: the MCP binding resolved a principal at the
   * domain controller of the domain owning the object, and where there was
   * none, the call was refused as an unaccepted token — on a token the same
   * server had just accepted on its other binding. This is the route for such a
   * deployment.
   */
  tokenPrincipal(token: string): { principal: Principal; scopes: string[] } | undefined {
    if (this.tokens === undefined) return undefined;
    let claims: Record<string, unknown>;
    try {
      claims = verifyJWT(token, this.tokens) as unknown as Record<string, unknown>;
    } catch {
      return undefined;
    }
    const p = principalOfClaims(claims as { sub?: string; groups?: unknown });
    if (p.name === "") return undefined;
    return { principal: { ...p, token }, scopes: scopesOfClaims(claims) };
  }

  private fromToken(token: string): Principal {
    try {
      const claims = verifyJWT(token, this.tokens!);
      const p = principalOfClaims(claims);
      if (p.name === "") return ANONYMOUS;
      // The token itself is carried, so that a remote import in
      // delegated identity mode has something to exchange.
      return { ...p, token };
    } catch {
      // A token this server does not accept leaves the principal
      // unresolved, as credentials it does not accept do.
      return ANONYMOUS;
    }
  }

  /**
   * The principal a request authenticates as. A request presenting no
   * credentials is the anonymous principal; one presenting credentials this
   * server does not accept (a password that does not verify, a name it cannot
   * resolve, a token it does not accept, a scheme it does not offer, a
   * malformed header) is refused with the unauthenticated condition, as the
   * draft requires, and never performed as the anonymous principal.
   *
   * So is a request using an authentication method the domain does not
   * enable: "a request that presents credentials of an authentication method
   * the domain does not enable, present[s] credentials the CDMI server does
   * not accept" (the domains clause). This server took such a request as
   * presenting no credentials until 0.43.
   */
  authenticate(authorization: string | undefined, domain = ROOT_DOMAIN, methods?: string[]): Principal {
    if (!authorization) return ANONYMOUS;
    const method = (authorization.split(" ")[0] ?? "").toLowerCase();
    if (methods !== undefined && !methods.includes(method)) {
      throw unauthenticated(`this domain does not enable the ${method || "given"} authentication method; ` +
        `it enables ${methods.join(", ") || "none"}`, methods.map((m) => m.charAt(0).toUpperCase() + m.slice(1)));
    }
    const who = this.resolve(authorization, domain, methods);
    if (who === ANONYMOUS) {
      throw unauthenticated("the credentials the request presents are not accepted",
        this.tokens ? ["Basic", "Bearer"] : ["Basic"]);
    }
    return who;
  }

  /** The principal a request resolves to, or the anonymous principal. */
  resolve(authorization: string | undefined, domain = ROOT_DOMAIN,
    methods?: string[]): Principal {
    if (!authorization) return ANONYMOUS;
    const [scheme, encoded] = authorization.split(" ");
    const method = (scheme ?? "").toLowerCase();
    // A domain that enables a set of authentication methods does not
    // have credentials presented by another method resolved: such a
    // request presents no credentials, which is not the same as being
    // refused.
    if (methods !== undefined && !methods.includes(method)) return ANONYMOUS;
    if (method === "bearer" && encoded && this.tokens) {
      return this.fromToken(encoded);
    }
    if (method !== "basic" || !encoded) return ANONYMOUS;
    let decoded: string;
    try {
      decoded = Buffer.from(encoded, "base64").toString("utf8");
    } catch {
      return ANONYMOUS;
    }
    const cut = decoded.indexOf(":");
    if (cut < 0) return ANONYMOUS;
    const name = decoded.slice(0, cut);
    const password = decoded.slice(cut + 1);
    // The identity is resolved within the domain that owns the object,
    // and within the domains above it: a sub-domain recognizes the
    // principals its parent recognizes.
    const user = this.within(name, domain);
    if (!user || !constantTimeEqual(user.password, password)) return ANONYMOUS;
    return {
      name,
      groups: user.groups,
      administrator: user.administrator,
      // A principal holds a privilege where the CDMI server
      // confers it on that principal or on a group to which it
      // belongs.
      privileges: [...new Set([
        ...user.privileges,
        ...user.groups.flatMap((g) => this.groupPrivileges.get(
          `${user.domain}\u0000${g}`) ?? []),
      ])],
    };
  }
}

/**
 * The privileges this document defines. A privilege conferred by
 * configuration is one of these; any other name is a mistake
 * rather than an extension, since a privilege permits an operation
 * no access control entry grants.
 */
export const PRIVILEGES = [
  // The privilege a principal holds to configure the key management servers of
  // a domain, by the cdmi_domain_kms item (Annex D).
  "cross_domain", "import_service_credential", "backup_operator", "domain_kms_admin",
  // To create or update the cdmi_domain_auth item of a domain object (revision 269).
  "domain_auth_admin",
];

/** The principal an access token names, where the token is accepted. */
function principalOfClaims(claims: {
  sub?: string;
  groups?: unknown;
}): Principal {
  const groups = Array.isArray(claims.groups)
    ? claims.groups.filter((g): g is string => typeof g === "string")
    : [];
  return {
    name: String(claims.sub ?? ""),
    groups,
    administrator: false,
    privileges: [],
  };
}

function constantTimeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  if (x.length !== y.length) return false;
  return timingSafeEqual(x, y);
}
