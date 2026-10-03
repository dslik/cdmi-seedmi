// The description of the requesting principal, and homes.
//
// Revision 282 of the draft gives every domain object a reserved child data
// object, "cdmi_domain_userinfo", whose value "describes the requesting
// principal as the domain resolves it": the identifier an access control entry
// names it by, and optionally its groups, its privileges, its home and more
// (ECR-137C, which closes seedmi's ECR-137B). A CDMI client learns from it who
// it is, which it cannot otherwise do, and where its home is.
//
// Since 0.106 this server carries it as a metadata item of the domain object
// rather than as a child of one, which is what ECR-226A asks the draft for: the
// child was an object defined by subtracting every property of the kind of
// object it had been made, and the handler that synthesised its representation
// had four faults, each of them a fault of synthesising one. What remains here
// is the description itself and the homes, which are the same either way.
//
// The home is two members: "home_base", "The base URI beneath which the home of
// the principal is held", and "home_path", "The namespace path of the home
// container object of the principal, relative to the base URI \"home_base\"
// names". The base URI may be that of another CDMI server, which is how a
// deployment keeps homes on a server of their own.
//
// Where the members come from is not stated by revision 282 (seedmi's
// ECR-140A): a directory holds such facts about a principal, and no field maps
// them. Until that is settled, this server takes the home from its own
// configuration, [homes], which names the base URI and the form of the path.

import type { Principal } from "./acl.ts";

/**
 * The members of the description of a principal, which a directory descriptor
 * may map to attributes of a directory entry (revision 298; ECR-140B).
 */
export const USERINFO_MEMBERS = ["identifier", "name", "preferred_username", "realm", "groups", "privileges",
  "home_base", "home_path", "publickey", "email", "locale", "zoneinfo", "auth_method", "expires"];

/** The reserved child of a domain object, and its capability. */
export const USERINFO = "cdmi_domain_userinfo";

/** [homes]: the homes of the principals of a domain, served by this server or another. */
export interface HomesConfig {
  /** The domain whose principals have homes, as a namespace path. */
  domain: string;
  /** The base URI beneath which they are held, ending with "/". */
  base: string;
  /** The form of the path within it, with {identifier} for the principal. */
  path: string;
}

/** [home_server]: how this server holds the homes of a domain's principals. */
export interface HomeServerConfig {
  /** The container within which homes are held, as a namespace path ending with "/". */
  container: string;
  /** The domain owning them, as a namespace path. */
  domain: string;
  /** Whether a principal's home is made on its first authenticated request for it. */
  provision: boolean;
}

/** The path of a principal's home within a base URI: the pattern with the identifier encoded. */
export function homePathOf(homes: HomesConfig, identifier: string): string {
  return homes.path.replace("{identifier}", encodeURIComponent(identifier));
}

/** The name of a principal's home container, the identifier as a single name. */
export const homeNameOf = (identifier: string): string => identifier;

/**
 * The home of a principal as the directory holds it, divided into the two
 * members of the description of that principal (revision 302; ECR-145B):
 *
 * * "where it is a namespace path: the value of that member as home_base, and
 *   the path as home_path";
 * * "where it is an absolute URI beginning with the value of that member:
 *   that value as home_base, and the remainder, with a leading /, as
 *   home_path"; and
 * * "where it is an absolute URI that does not begin with that value, or
 *   where that member is absent: neither member".
 *
 * A path of the Universal Naming Convention is mapped by this server's own
 * SMB export entries, and a value of none of these kinds gives neither member.
 */
export function homeOf(value: string | undefined, homeBase: string | undefined, opts: {
  /** The namespace path an SMB share of this server is placed on, by share and host. */
  shareAt?: (share: string, host: string) => string | undefined;
} = {}): { home_base: string; home_path: string } | undefined {
  if (value === undefined || value === "") return undefined;
  const ending = (p: string) => (p.endsWith("/") ? p : `${p}/`);
  // A path of the Universal Naming Convention: \\<host>\<share>\<path>.
  const unc = /^\\\\([^\\]+)\\([^\\]+)(?:\\(.*))?$/.exec(value);
  if (unc !== null) {
    if (homeBase === undefined) return undefined;
    const at = opts.shareAt?.(unc[2], unc[1]);
    // "Where no export entry of this CDMI server presents that share at that
    // host, the CDMI server reports neither member."
    if (at === undefined) return undefined;
    const within = (unc[3] ?? "").split("\\").filter((p) => p !== "").join("/");
    return { home_base: homeBase, home_path: ending(`${ending(at)}${within}`) };
  }
  if (value.startsWith("/")) {
    // A namespace path, which a file system path of a UNIX deployment is
    // taken as, "appending / where the value does not end with one".
    if (homeBase === undefined) return undefined;
    return { home_base: homeBase, home_path: ending(value) };
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(value)) {
    if (homeBase === undefined || !value.startsWith(homeBase)) return undefined;
    const rest = value.slice(homeBase.length);
    return { home_base: homeBase, home_path: ending(`/${rest}`) };
  }
  // Neither a namespace path, nor an absolute URI, nor a path of that convention.
  return undefined;
}

/**
 * The value of "cdmi_domain_userinfo" for a principal, in the domain whose
 * object is its parent. Only "identifier" is mandatory: "A CDMI server returns
 * each optional member where it knows the value and chooses to disclose it".
 * An unauthenticated request is described as the anonymous principal, and is
 * given no home.
 */
export function userinfoOf(who: Principal, domain: string, opts: {
  homes?: HomesConfig;
  /** The realm of the authority that resolved the principal, where one did. */
  realm?: string;
  /** The method the request authenticated by, a value of cdmi_authentication_methods. */
  authMethod?: string;
  /** The home the directory of the domain gives, where it gives one. */
  home?: { home_base: string; home_path: string };
}): Record<string, unknown> {
  const anonymous = who.name === "ANONYMOUS@";
  const value: Record<string, unknown> = { identifier: who.name };
  if (anonymous) return value;
  if (opts.realm !== undefined) value.realm = opts.realm;
  if (who.groups.length > 0) value.groups = [...who.groups];
  if (who.privileges.length > 0) value.privileges = [...who.privileges];
  if (opts.authMethod !== undefined) value.auth_method = opts.authMethod;
  // The home: the directory of the domain first, which holds it for each
  // principal, and this server's configuration where the directory gives none
  // (revision 302; ECR-145B and ECR-140B).
  const homes = opts.homes;
  if (opts.home !== undefined) {
    value.home_base = opts.home.home_base;
    value.home_path = opts.home.home_path;
  } else if (homes !== undefined && sameDomain(homes.domain, domain)) {
    value.home_base = homes.base;
    value.home_path = homePathOf(homes, who.name);
  }
  return value;
}

/** Whether two namespace paths name the same domain, a trailing "/" aside. */
export function sameDomain(a: string, b: string): boolean {
  const end = (x: string) => (x.endsWith("/") ? x : `${x}/`);
  return end(a) === end(b);
}

/**
 * The principal whose home a namespace path names, where it names one within
 * the container homes are held in: /home/alice@EU.EXAMPLE/notes.txt names the
 * home of alice@EU.EXAMPLE. Undefined where the path is not within it, or names
 * the container itself.
 */
export function homeOwnerOf(server: HomeServerConfig, ns: string): string | undefined {
  const within = server.container.endsWith("/") ? server.container : `${server.container}/`;
  if (!ns.startsWith(within)) return undefined;
  const name = ns.slice(within.length).split("/")[0];
  return name === "" ? undefined : name;
}
