// The directory a store holds, read into memory.
//
// DESIGN-admin.md §1: "The whole directory is read into memory at start and
// rebuilt after each write, which is what `Directory` already does with the
// configuration, so nothing downstream changes and a reader never waits on the
// store." This module is that reading: a `Store` and a `KeyStore` in, a
// `Directory` out, with the identifiers the store allocated (§3) in place of the
// ones a configuration derives from a name.
//
// What comes from the key management server, and what does not:
//
//   * the scrypt verifier of each user is read here and held in memory, because
//     every bind and every password grant needs it and a verifier is what a
//     configuration already kept in a file on disk;
//   * a Kerberos long-term key is read here as well, for the key distribution
//     centre, which needs one on every AS exchange.
//
// Cold start (§4): where the key server cannot be reached, the directory is built
// without secret material — every name, every membership, every number is served
// — and each user is marked as having no verifier, so a bind and a token are
// refused while a search succeeds. The reasons are returned rather than thrown,
// for the caller to log: "a controller that will not start because a key server
// is briefly away is worse than one that says what it cannot do."

import { Directory, DirectoryError, type GroupSpec, type UserSpec } from "./dc-directory.ts";
import type { Credential, Ou, Store } from "./dc-store.ts";
import type { KeyStore } from "./dc-write.ts";

/** What a reading of the store produced, and what it could not read. */
export interface View {
  directory: Directory;
  /** Users whose verifier could not be read, which therefore accept no password. */
  withoutVerifier: string[];
  /** Users for whom no Kerberos key could be read, which are issued no ticket. */
  withoutKeys: string[];
  /**
   * Why, once per distinct message, for the log. Empty where everything was
   * read; the key server being away gives one message, not one per principal.
   */
  reasons: string[];
}

/** The paths of the units of a store, by identifier. */
export function pathsOf(units: Ou[]): Map<string, string> {
  const byId = new Map(units.map((u) => [u.id, u]));
  const out = new Map<string, string>();
  const pathOf = (id: string, seen = new Set<string>()): string => {
    const held = out.get(id);
    if (held !== undefined) return held;
    const unit = byId.get(id);
    if (unit === undefined) return "";
    // A parent that is its own ancestor cannot happen through the write path,
    // which refuses it; a store edited by hand could hold one, and a cycle here
    // would not return.
    if (seen.has(id)) return unit.name;
    seen.add(id);
    const path = unit.parent === undefined
      ? unit.name
      : `${pathOf(unit.parent, seen)}/${unit.name}`;
    out.set(id, path);
    return path;
  };
  for (const u of units) pathOf(u.id);
  return out;
}

/**
 * Reads the directory a store holds. The key store is asked for the material of
 * each credential that has a reference; a key store that refuses or cannot be
 * reached leaves the directory whole and the material out of it.
 */
export async function readDirectory(store: Store, keys: KeyStore): Promise<View> {
  const paths = pathsOf(store.units());
  const principals = store.principals();
  const byId = new Map(principals.map((p) => [p.id, p]));
  // The groups each principal is directly a member of, which is what both a user
  // and a group carry in a Directory.
  const within = new Map<string, string[]>();
  for (const m of store.memberships()) {
    const group = byId.get(m.group);
    if (group === undefined) continue;
    const held = within.get(m.member);
    if (held === undefined) within.set(m.member, [group.name]);
    else held.push(group.name);
  }
  const withoutVerifier: string[] = [];
  const withoutKeys: string[] = [];
  const reasons = new Set<string>();
  const read = async (c: Credential): Promise<Buffer | undefined> => {
    if (c.ref === undefined) return undefined;
    try {
      return await keys.get(c.ref);
    } catch (e) {
      reasons.add((e as Error).message);
      return undefined;
    }
  };

  const users: UserSpec[] = [];
  const groups: GroupSpec[] = [];
  for (const p of principals) {
    const common = {
      rid: p.sidRid,
      posixId: p.posixId,
      id: p.id,
      ...(p.displayName === undefined ? {} : { displayName: p.displayName }),
      ...(p.ou === undefined ? {} : { unit: paths.get(p.ou) ?? "" }),
      created: p.created,
      modified: p.modified,
    };
    if (p.kind === "group") {
      groups.push({ name: p.name, groups: within.get(p.id) ?? [], ...common });
      continue;
    }
    const held = store.credentialsOf(p.id);
    const verifier = held.find((c) => c.kind === "password");
    const material = verifier === undefined ? undefined : await read(verifier);
    if (material === undefined) withoutVerifier.push(p.name);
    const keyed: { etype: number; key: Buffer }[] = [];
    for (const c of held.filter((c) => c.kind === "kerberos")) {
      // The enctype is the credential's material, written when the key was
      // registered; a credential without one is a store this build did not write.
      const etype = Number(c.material);
      if (!Number.isInteger(etype)) {
        reasons.add(`a Kerberos credential of ${p.name} names no enctype`);
        continue;
      }
      const key = await read(c);
      if (key !== undefined) keyed.push({ etype, key });
    }
    // A principal whose Kerberos credentials are recorded and whose keys could not
    // be read is a different thing from one that never had any: the first is a
    // principal of this realm that cannot be served *right now*, which is what §4's
    // cold start is about, and the second is a hash-only import that never could be.
    // Told apart so that the key distribution centre can say which (krb-kdc.ts).
    const hasKerberos = held.some((c) => c.kind === "kerberos");
    if (keyed.length === 0) withoutKeys.push(p.name);
    // The public material of the other credentials: what a front end reports.
    const certificates = held.filter((c) => c.kind === "certificate" && c.material !== undefined)
      .map((c) => ({ fingerprint: c.material!, ...(c.detail === undefined ? {} : { subject: c.detail }),
        // The certificate itself, where the store has it (schema 5). A front end
        // serves it as `userCertificate`, which RFC 4523 §2.1 requires be preserved.
        ...(c.value === undefined ? {} : { certificate: c.value }),
        created: c.created }));
    const s3Keys = held.filter((c) => c.kind === "s3" && c.material !== undefined)
      .map((c) => ({ accessKeyId: c.material!, created: c.created }));
    users.push({
      name: p.name,
      groups: within.get(p.id) ?? [],
      // The name of the primary group, where the user has one: RFC 2307's
      // posixAccount MUSTs a gidNumber, and that is where a user's comes from.
      ...(p.primaryGroup === undefined ? {} : (() => {
        const of = store.principal(p.primaryGroup!);
        return of === undefined ? {} : { primaryGroup: of.name };
      })()),
      disabled: p.disabled,
      ...(p.expires === undefined ? {} : { expires: p.expires }),
      ...(p.home === undefined ? {} : { home: p.home }),
      ...(material === undefined
        ? { verifierUnavailable: true }
        : { passwordHash: material.toString("utf8") }),
      ...(keyed.length === 0 ? {} : { keys: keyed }),
      ...(keyed.length === 0 && hasKerberos ? { keysUnavailable: true } : {}),
      ...(certificates.length === 0 ? {} : { certificates }),
      ...(s3Keys.length === 0 ? {} : { s3Keys }),
      ...common,
    });
  }
  // The invariants of dc-directory.ts are checked again here, on material the
  // write path already checked: a store edited by hand, or written by another
  // build, is refused rather than served half-right.
  // The units themselves, so that one holding nothing is still a unit of the
  // directory: an empty unit that could not be read back was a bug found by
  // creating one (dc-directory.ts, units).
  const unitSpecs = store.units().map((u) => ({
    path: paths.get(u.id) ?? u.name,
    ...(u.description === undefined ? {} : { description: u.description }),
    // The unit's own identifier and times, which a SCIM meta requires of every
    // resource (RFC 7643 §3.1) and which LDAP serves as createTimestamp and
    // modifyTimestamp. A unit served over SCIM had none of the three.
    id: u.id,
    // The second entry's UUID (store schema 7). A unit is served as two LDAP
    // entries and RFC 4530 §2.4 requires an immutable UUID of each.
    ...(u.groupsId === undefined ? {} : { groupsId: u.groupsId }),
    created: u.created,
    modified: u.modified,
  }));
  let directory: Directory;
  try {
    directory = new Directory(users, groups, unitSpecs);
  } catch (e) {
    if (e instanceof DirectoryError) {
      throw new DirectoryError(`the store does not read as a directory: ${e.message}`);
    }
    throw e;
  }
  return { directory, withoutVerifier, withoutKeys, reasons: [...reasons] };
}
