// The realm's directory: users and groups, built from the configuration and
// rebuilt when it is read again (SIGHUP).
//
// A user has a password, held only as a salted scrypt hash (RFC 7914), and may
// be disabled or expire; a user or a group names the groups it belongs to, and
// a group may belong to groups, so they nest. The whole is checked when it is
// built: a name malformed or given twice (in any case, by a user and a group
// alike), a group named that is not given, or a group coming to contain itself,
// directly or through others, refuses it, so that a configuration with a
// mistake starts nothing and replaces nothing on a reload.

import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { prepareSecret } from "./prepare.ts";

export class DirectoryError extends Error {}

/** A user or group name: letters, digits, and . _ -, beginning with a letter or digit, at most 64 characters. */
export const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * The password hash: scrypt with N = 2^15, r = 8, p = 1, a salt of 16 random
 * octets and 32 octets of output, written with its parameters so that they can
 * be raised later without invalidating a hash already written.
 */
const SCRYPT = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(prepareSecret(password), salt, 32, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString("base64")}$${hash.toString("base64")}`;
}
/** Whether a string is a hash this program writes. */
export const HASH = /^scrypt\$\d+\$\d+\$\d+\$[A-Za-z0-9+/]{22}==\$[A-Za-z0-9+/]{43}=$/;
function checkPassword(password: string, stored: string): boolean {
  const [, n, r, p, salt, hash] = stored.split("$");
  const want = Buffer.from(hash, "base64");
  // Prepared on both sides, so that the comparison is of the password and not of a
  // spelling of it (RFC 7644 §5; see `prepareSecret`). Identity on ASCII, so no hash
  // this program has already written changes meaning.
  const got = scryptSync(prepareSecret(password), Buffer.from(salt, "base64"), want.length,
    { N: Number(n), r: Number(r), p: Number(p), maxmem: SCRYPT.maxmem });
  return timingSafeEqual(got, want);
}
/** A hash of no password, compared against where a name is not there, so that timing does not tell which names exist. */
const ABSENT = hashPassword(randomBytes(16).toString("base64"));

/**
 * Whether a secret matches a hash, a client's as a user's password is. Where
 * there is no hash, because there is no such client, one is compared all the
 * same, and the answer is no.
 */
export function verifySecret(secret: string, hash: string | undefined): boolean {
  const matches = checkPassword(secret, hash ?? ABSENT);
  return hash !== undefined && matches;
}

/** A user as the configuration gives it, or as the store holds it. */
export interface UserSpec {
  name: string;
  /**
   * The group whose POSIX number is this user's `gidNumber`, for RFC 2307's
   * `posixAccount`. Where there is none the user bears no `posixAccount`, the class
   * being `MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory )`.
   */
  primaryGroup?: string;
  /** The home of the principal, served as unixHomeDirectory. */
  home?: string;
  /** A hash this program wrote (--hash-password), or undefined where a plain password is given. */
  passwordHash?: string;
  password?: string;
  groups: string[];
  disabled: boolean;
  expires?: Date;
  /**
   * The identifiers a store allocates and keeps (DESIGN-admin.md §3), where the
   * directory comes from one. A principal from the configuration has none, and
   * its relative identifier is derived from its name by `ridOf`: the derivation
   * is this program's own convention, and a store replaces it with a counter so
   * that a rename re-identifies nothing.
   */
  rid?: number;
  /** The POSIX number, served as uidNumber. A configuration gives none. */
  posixId?: number;
  /** The credentials recorded for the principal, as public material alone. */
  certificates?: { fingerprint: string; subject?: string; certificate?: string; created?: Date }[];
  s3Keys?: { accessKeyId: string; created?: Date }[];
  /** The identifier a token's subject and a SCIM client hold, where a store holds one. */
  id?: string;
  /** The display name, served as displayName and cn. */
  displayName?: string;
  /** The path of the unit the principal is in, as `eng/platform`. */
  unit?: string;
  /** When the principal was created, served as the createTimestamp of its entry. */
  created?: Date;
  /** When it last changed, served as modifyTimestamp. */
  modified?: Date;
  /**
   * That the verifier of this user could not be read, so no password matches it:
   * the controller started with its key server away, serves the directory, and
   * refuses what needs a secret (DESIGN-admin.md §4, cold start). Distinct from a
   * user with no password, which the configuration refuses outright.
   */
  verifierUnavailable?: boolean;
  /**
   * The long-term Kerberos keys the store holds for this principal, by enctype:
   * what `kerberosPrincipals` yields instead of a password where a store and a
   * key server supply them.
   */
  keys?: { etype: number; key: Buffer }[];
  /**
   * The principal has Kerberos credentials recorded and their keys could not be
   * read — the key server is away, or the material is gone. A different thing from
   * having none, which is a principal that never could be issued a ticket; the key
   * distribution centre says which rather than reporting both as unknown.
   */
  keysUnavailable?: boolean;
}
/** An organizational unit as a store holds one: its path, and its description. */
export interface UnitSpec {
  /** The path, as `eng/platform`. */
  path: string;
  description?: string;
  /** The store's identifier for the unit, where a store holds it. */
  id?: string;
  /**
   * The UUID of this unit's second LDAP entry, the one beneath `ou=groups`; `id` is
   * the first's. A unit is one stored thing and two entries, and RFC 4530 §2.4
   * requires an immutable UUID of each entry.
   */
  groupsId?: string;
  /** When the unit was created and last changed, where a store holds them. */
  created?: Date;
  modified?: Date;
}

export interface GroupSpec {
  name: string;
  groups: string[];
  /** As a user's: the identifiers a store allocates, where one holds them. */
  rid?: number;
  /** The POSIX number, served as gidNumber. */
  posixId?: number;
  id?: string;
  displayName?: string;
  unit?: string;
  created?: Date;
  modified?: Date;
}

/**
 * The relative identifier of a principal or a group within the domain, for
 * the privilege attribute certificate ([MS-PAC]) and for the objectSid this
 * directory serves. Windows assigns these from a counter held with the
 * account database; this controller derives one from the name, so that the
 * identifiers of a realm are the same wherever its configuration is read,
 * and records the derivation as its own convention rather than a rule.
 *
 * The values begin at 1000, below which Windows reserves identifiers for
 * accounts it defines ([MS-PAC] section 4.1.2.2 lists them).
 */
export function ridOf(name: string): number {
  let h = 0x811c9dc5;
  for (const c of name.toLowerCase()) {
    h ^= c.charCodeAt(0);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return 1000 + (h % 1000000);
}

export interface User {
  name: string;
  disabled: boolean;
  expires?: Date;
}

/**
 * A principal the key distribution centre serves: a password to make a key from,
 * or the keys themselves. The shape krb-kdc.ts takes, named here so that this
 * module does not depend on that one.
 */
export interface KdcPrincipalSpec {
  parts: string[];
  password?: string;
  keys?: { etype: number; key: Buffer }[];
  type: number;
  rid: number;
  groups: number[];
}

/** Why a verification failed, for the log; a client is told only that it failed. */
export type Verdict = { ok: true; user: User } | { ok: false; reason: "unknown" | "password" | "disabled" | "expired" };

interface HeldUser extends User {
  hash: string;
  /** The group whose POSIX number is this user's gidNumber, where it has one. */
  primaryGroup?: string;
  /** Its Kerberos keys are recorded and could not be read; see UserSpec. */
  keysUnavailable?: boolean;
  /** The home of the principal, served as unixHomeDirectory (revision 302). */
  home?: string;
  memberOf: string[];
  /**
   * The password as the configuration gave it, where it gave one rather than a
   * hash: a Kerberos key is made from the password itself (krb-kdc.ts), which a
   * hash cannot give. It is used for nothing else; a bind is verified against
   * the hash as before.
   */
  password?: string;
  created?: Date;
  modified?: Date;
  /**
   * The public material of the credentials a store records: a client
   * certificate's fingerprint and subject, and an S3 access key identifier. No
   * secret and no reference — what a front end reports and a reader may see.
   */
  certificates?: { fingerprint: string; subject?: string; certificate?: string; created?: Date }[];
  s3Keys?: { accessKeyId: string; created?: Date }[];
  /** The keys a store supplies, where the password itself is not known here. */
  keys?: { etype: number; key: Buffer }[];
  rid?: number;
  posixId?: number;
  id?: string;
  displayName?: string;
  unit?: string;
}

/** What a store holds of a group, beside its name and the groups it is in. */
interface HeldGroup {
  rid?: number;
  posixId?: number;
  id?: string;
  displayName?: string;
  unit?: string;
  created?: Date;
  modified?: Date;
}

export class Directory {
  private readonly users = new Map<string, HeldUser>();
  /** The groups each group is directly a member of, by the group's name in lower case. */
  private readonly groupParents = new Map<string, string[]>();
  private readonly groupNames = new Map<string, string>();
  /** What a store holds of each group, by its name in lower case. */
  private readonly groupHeld = new Map<string, HeldGroup>();
  /** The units of the directory, by path; empty where the configuration is the directory. */
  private readonly unitHeld = new Map<string, UnitSpec>();
  private readonly unitPaths: string[] = [];
  /** How many users were given a plain password, which the log warns of. */
  readonly plainPasswords: number;

  constructor(users: UserSpec[], groups: GroupSpec[], units: UnitSpec[] = []) {
    for (const u of units) {
      this.unitHeld.set(u.path, u);
      this.unitPaths.push(u.path);
    }
    const seen = new Map<string, string>();
    const claim = (kind: string, name: string) => {
      if (!NAME.test(name)) {
        throw new DirectoryError(`${JSON.stringify(name)} is not a ${kind} name: letters, digits and . _ -, ` +
          "beginning with a letter or digit, at most 64 characters");
      }
      const clash = seen.get(name.toLowerCase());
      if (clash !== undefined) throw new DirectoryError(`the name ${name} is given twice: ${clash} is given already`);
      seen.set(name.toLowerCase(), `${kind} ${name}`);
    };
    for (const g of groups) {
      claim("group", g.name);
      this.groupNames.set(g.name.toLowerCase(), g.name);
      this.groupHeld.set(g.name.toLowerCase(), {
        ...(g.rid === undefined ? {} : { rid: g.rid }),
        ...(g.posixId === undefined ? {} : { posixId: g.posixId }),
        ...(g.id === undefined ? {} : { id: g.id }),
        ...(g.displayName === undefined ? {} : { displayName: g.displayName }),
        ...(g.unit === undefined ? {} : { unit: g.unit }),
        ...(g.created === undefined ? {} : { created: g.created }),
        ...(g.modified === undefined ? {} : { modified: g.modified }),
      });
    }
    const known = (from: string, g: string): string => {
      const found = this.groupNames.get(g.toLowerCase());
      if (found === undefined) throw new DirectoryError(`${from} names the group ${g}, which is not given`);
      return found;
    };
    for (const g of groups) this.groupParents.set(g.name.toLowerCase(), g.groups.map((p) => known(`the group ${g.name}`, p)));
    // No group may come to contain itself.
    for (const g of groups) {
      if (this.ancestors(g.name).has(g.name)) {
        throw new DirectoryError(`the group ${g.name} comes to contain itself through the groups it belongs to`);
      }
    }
    let plain = 0;
    for (const u of users) {
      claim("user", u.name);
      let hash: string;
      if (u.passwordHash !== undefined) {
        if (u.password !== undefined) throw new DirectoryError(`the user ${u.name} is given a password and a password hash; one is given`);
        if (!HASH.test(u.passwordHash)) throw new DirectoryError(`the password hash of ${u.name} is not one --hash-password writes`);
        hash = u.passwordHash;
      } else if (u.password !== undefined && u.password !== "") {
        hash = hashPassword(u.password);
        plain++;
      } else if (u.verifierUnavailable === true) {
        // A verifier that could not be read: a hash of nothing, which no password
        // matches, so the user is served and binds nowhere until the key server is
        // reachable and the directory is built again.
        hash = ABSENT;
      } else {
        throw new DirectoryError(`the user ${u.name} is given a password_hash, or a password`);
      }
      this.users.set(u.name.toLowerCase(), {
        name: u.name, disabled: u.disabled, ...(u.expires === undefined ? {} : { expires: u.expires }),
        hash, ...(u.password === undefined ? {} : { password: u.password }),
        ...(u.home === undefined ? {} : { home: u.home }),
        ...(u.keys === undefined ? {} : { keys: u.keys }),
        ...(u.rid === undefined ? {} : { rid: u.rid }),
        ...(u.posixId === undefined ? {} : { posixId: u.posixId }),
        ...(u.id === undefined ? {} : { id: u.id }),
        ...(u.displayName === undefined ? {} : { displayName: u.displayName }),
        ...(u.unit === undefined ? {} : { unit: u.unit }),
        ...(u.created === undefined ? {} : { created: u.created }),
        ...(u.modified === undefined ? {} : { modified: u.modified }),
        ...(u.certificates === undefined ? {} : { certificates: u.certificates }),
        ...(u.primaryGroup === undefined ? {} : { primaryGroup: u.primaryGroup }),
        ...(u.keysUnavailable === undefined ? {} : { keysUnavailable: u.keysUnavailable }),
        ...(u.s3Keys === undefined ? {} : { s3Keys: u.s3Keys }),
        memberOf: u.groups.map((g) => known(`the user ${u.name}`, g)),
      });
    }
    this.plainPasswords = plain;
  }

  /** Every group a group is within, through any nesting. */
  private ancestors(group: string): Set<string> {
    const found = new Set<string>();
    const walk = (g: string) => {
      for (const p of this.groupParents.get(g.toLowerCase()) ?? []) if (!found.has(p)) { found.add(p); walk(p); }
    };
    walk(group);
    return found;
  }

  /** A user, by its name in any case. */
  user(name: string): User | undefined {
    const u = this.users.get(name.toLowerCase());
    return u === undefined ? undefined : { name: u.name, disabled: u.disabled, ...(u.expires === undefined ? {} : { expires: u.expires }) };
  }
  userNames(): string[] {
    return [...this.users.values()].map((u) => u.name).sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
  }
  /** A group's name as given, by its name in any case. */
  group(name: string): string | undefined {
    return this.groupNames.get(name.toLowerCase());
  }
  groupList(): string[] {
    return [...this.groupNames.values()].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
  }

  /**
   * The principals a key distribution centre can serve. A configuration gives a
   * password, from which a key is made (krb-kdc.ts); a store gives the keys
   * themselves, read from the key server, because no cleartext is kept once a
   * password has been written through the administrative interface. A user with
   * neither — a configuration that gave only a hash — is not served, since no key
   * can be had from a hash.
   */
  kerberosPrincipals(): KdcPrincipalSpec[] {
    const out: KdcPrincipalSpec[] = [];
    for (const u of this.users.values()) {
      if (u.keys !== undefined && u.keys.length > 0) {
        out.push({ parts: [u.name], keys: u.keys, type: 1, rid: this.ridOf(u.name),
          groups: this.groupRidsOf(u.name) });
      } else if (u.password !== undefined) {
        out.push({ parts: [u.name], password: u.password, type: 1, rid: this.ridOf(u.name),
          groups: this.groupRidsOf(u.name) });
      }
    }
    return out;
  }

  /**
   * The relative identifier of a user or a group: the one a store allocated and
   * keeps, or, for a directory that is a configuration and has no store, the one
   * derived from the name. The derived form is why a store exists: it changes
   * when the name does.
   */
  ridOf(name: string): number {
    const key = name.toLowerCase();
    return this.users.get(key)?.rid ?? this.groupHeld.get(key)?.rid ?? ridOf(name);
  }

  /**
   * The POSIX number of a user or a group, where a store allocated one:
   * uidNumber and gidNumber, which NFS resolves an identity by and which SMB
   * maps. A configuration has none, and the attribute is not served.
   */
  posixOf(name: string): number | undefined {
    const key = name.toLowerCase();
    return this.users.get(key)?.posixId ?? this.groupHeld.get(key)?.posixId;
  }

  /** The identifier a token's subject and a SCIM client hold, where there is one. */
  idOf(name: string): string | undefined {
    const key = name.toLowerCase();
    return this.users.get(key)?.id ?? this.groupHeld.get(key)?.id;
  }

  /** The display name of a user or a group, where one is recorded. */
  displayNameOf(name: string): string | undefined {
    const key = name.toLowerCase();
    return this.users.get(key)?.displayName ?? this.groupHeld.get(key)?.displayName;
  }

  /** The path of the unit a principal is in, as `eng/platform`, where it is in one. */
  unitOf(name: string): string | undefined {
    const key = name.toLowerCase();
    return this.users.get(key)?.unit ?? this.groupHeld.get(key)?.unit;
  }

  /**
   * When a principal was created and last changed, where a store records it:
   * the createTimestamp and modifyTimestamp of its LDAP entry, which are
   * operational attributes and are served as such.
   */
  timesOf(name: string): { created?: Date; modified?: Date } {
    const key = name.toLowerCase();
    const held = this.users.get(key) ?? this.groupHeld.get(key);
    if (held === undefined) return {};
    return {
      ...(held.created === undefined ? {} : { created: held.created }),
      ...(held.modified === undefined ? {} : { modified: held.modified }),
    };
  }

  /**
   * Every organizational unit of this directory, in path order. The store's own,
   * where one holds them — an empty unit is a unit, and inferring the set from the
   * principals in it made an empty one invisible: it could not be read back,
   * listed or deleted, and over LDAP a client could not create the first entry in
   * it, an add requiring its superior to exist. Found by creating one.
   */
  units(): string[] {
    const found = new Set<string>(this.unitPaths);
    // A unit named by a principal counts too, so that a directory read from a
    // store written by an older build still serves the units its principals name.
    for (const u of this.users.values()) if (u.unit !== undefined) found.add(u.unit);
    for (const g of this.groupHeld.values()) if (g.unit !== undefined) found.add(g.unit);
    // A unit's ancestors hold it, so they are units of the directory as well.
    for (const p of [...found]) {
      const parts = p.split("/");
      for (let i = 1; i < parts.length; i++) found.add(parts.slice(0, i).join("/"));
    }
    return [...found].sort();
  }

  /**
   * The `gidNumber` of a user: the POSIX number of its primary group, where it has
   * one and that group has a number. Undefined otherwise, and an entry without one
   * bears no `posixAccount` — RFC 2307 §3 makes `gidNumber` one of that class's
   * five MUSTs, so claiming the class without it would publish an invalid entry.
   */
  primaryGidOf(name: string): number | undefined {
    const of = this.users.get(name.toLowerCase())?.primaryGroup;
    if (of === undefined) return undefined;
    return this.posixOf(of);
  }

  /**
   * Whether a user is a principal of this realm whose Kerberos keys could not be
   * read. The key distribution centre answers such a request with a reason rather
   * than with `C_PRINCIPAL_UNKNOWN`, which says the principal does not exist —
   * DESIGN-admin.md §4 recorded that as "still the wrong one".
   */
  keysUnavailableFor(name: string): boolean {
    return this.users.get(name.toLowerCase())?.keysUnavailable === true;
  }

  /** The name of a user's primary group, where it has one. */
  primaryGroupOf(name: string): string | undefined {
    return this.users.get(name.toLowerCase())?.primaryGroup;
  }

  /** What a unit holds of its own: its description, where one is recorded. */
  unitDescription(path: string): string | undefined {
    return this.unitHeld.get(path)?.description;
  }

  /** The store's identifier for a unit, where a store holds it. */
  unitId(path: string): string | undefined {
    return this.unitHeld.get(path)?.id;
  }

  /**
   * The UUID of a unit's entry beneath one of the two containers. A unit is served as
   * two LDAP entries and RFC 4530 §2.4 requires a UUID of each — "Servers SHALL
   * generate and assign a new UUID to each entry ... An entry's UUID is immutable" —
   * which one identifier cannot be, so the store keeps two. Neither entry carried one
   * at all until phase E, which is that SHALL simply unmet.
   */
  unitUuid(path: string, container: "people" | "groups"): string | undefined {
    const held = this.unitHeld.get(path);
    return container === "people" ? held?.id : held?.groupsId;
  }

  /**
   * When a unit was created and last changed, where a store holds them. A
   * directory kept in the configuration holds neither, so a unit of one has no
   * meta times and no version — the same as a principal of one (§3 of
   * DESIGN-admin.md).
   */
  unitTimes(path: string): { created?: Date; modified?: Date } {
    const held = this.unitHeld.get(path);
    return {
      ...(held?.created === undefined ? {} : { created: held.created }),
      ...(held?.modified === undefined ? {} : { modified: held.modified }),
    };
  }

  /**
   * The relative identifiers of the groups a user belongs to, transitively,
   * for the privilege attribute certificate of a ticket ([MS-PAC]).
   */
  groupRidsOf(name: string): number[] {
    return this.groupsOf(name).map((g) => this.ridOf(g));
  }

  /**
   * The public material of a user's credentials: the certificates that
   * authenticate it and the access key identifiers it holds. No secret is here,
   * and none is reachable from here; the secrets live at the key management
   * server and a front end reports only these.
   */
  credentialsOf(name: string): {
    certificates: { fingerprint: string; subject?: string; certificate?: string; created?: Date }[];
    s3Keys: { accessKeyId: string; created?: Date }[];
  } {
    const held = this.users.get(name.toLowerCase());
    return { certificates: held?.certificates ?? [], s3Keys: held?.s3Keys ?? [] };
  }

  /** When a user's account expires, where it does. */
  expiresOf(name: string): Date | undefined {
    return this.users.get(name.toLowerCase())?.expires;
  }

  /** The home of a user, where its entry holds one. */
  homeOf(name: string): string | undefined {
    return this.users.get(name.toLowerCase())?.home;
  }

  /** The groups a user names directly, as a directory whose memberOf is not transitive reports them. */
  directGroupsOf(name: string): string[] {
    return [...(this.users.get(name.toLowerCase())?.memberOf ?? [])].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
  }

  /** The groups a group names directly, which a client follows to resolve membership transitively. */
  parentsOf(group: string): string[] {
    const g = this.group(group);
    return g === undefined ? [] : [...(this.groupParents.get(g.toLowerCase()) ?? [])];
  }

  /** The groups a user belongs to: those it names, and every group containing one of them. */
  groupsOf(name: string): string[] {
    const u = this.users.get(name.toLowerCase());
    if (u === undefined) return [];
    const all = new Set<string>(u.memberOf);
    for (const g of u.memberOf) for (const a of this.ancestors(g)) all.add(a);
    return [...all].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
  }
  /** The members of a group: the users and groups that name it directly. */
  membersOf(group: string): { users: string[]; groups: string[] } {
    const g = this.group(group);
    if (g === undefined) return { users: [], groups: [] };
    return {
      users: [...this.users.values()].filter((u) => u.memberOf.includes(g)).map((u) => u.name).sort(),
      groups: [...this.groupParents.entries()].filter(([, ps]) => ps.includes(g)).map(([k]) => this.groupNames.get(k)!).sort(),
    };
  }

  /**
   * Verifies a password. A name that is not there has a hash compared all the
   * same, so that the time taken does not tell which names exist; a disabled or
   * expired account is refused after its password is checked, for the same reason.
   */
  verify(name: string, password: string, now = new Date()): Verdict {
    const u = this.users.get(name.toLowerCase());
    const matches = checkPassword(password, u?.hash ?? ABSENT);
    if (u === undefined) return { ok: false, reason: "unknown" };
    if (!matches) return { ok: false, reason: "password" };
    if (u.disabled) return { ok: false, reason: "disabled" };
    if (u.expires !== undefined && u.expires <= now) return { ok: false, reason: "expired" };
    return { ok: true, user: this.user(u.name)! };
  }
}
