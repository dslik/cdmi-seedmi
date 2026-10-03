// dc-import: seeds a store from a bootstrap file, once.
//
//   node src/dc-import.ts --config dc.toml --from bootstrap.toml
//
// A deployment that writes its directory through an administrative interface
// gives [directory].store, and then the configuration holds no user and no group
// (config.ts refuses them). This program is how the first users get in: it reads
// a bootstrap file — the same vocabulary a configuration used for its directory,
// and [[ou]] besides — and writes it into an **empty** store, allocating the
// identifiers of DESIGN-admin.md §3 as it goes. It is a one-time step and not a
// synchronization: a store that already holds a principal is refused, because a
// second run of a changed file would otherwise be a quiet half-import.
//
// The store's location, the ranges numbers are allocated from, the realm and the
// key server all come from the configuration, so the two files cannot disagree
// about them. The bootstrap file holds the directory alone.
//
//   [[ou]]      name, parent (a path, as eng/platform), description
//   [[user]]    name, password or password_hash, groups, ou, display_name,
//               disabled, expires, home, certificate, certificate_subject, s3
//   [[group]]   name, groups, ou, display_name
//
// What is lost is said rather than hidden: a password_hash becomes a verifier and
// no Kerberos key, so such a principal binds and is issued tokens and is never
// issued a ticket — as it never was when the hash was in the configuration.

import { readFileSync } from "node:fs";
import * as path from "node:path";
import { type Config, ConfigError, parseConfig } from "./config.ts";
import { parseTOML, type TOMLValue } from "./toml.ts";
import { Store, StoreError } from "./dc-store.ts";
import { type KeyStore, WriteError, Writer } from "./dc-write.ts";
import { KmipKeyStore } from "./dc-keys.ts";
import { ETYPE } from "./krb-crypto.ts";

export const VERSION = "1.4";

const USAGE = `dc-import: seeds a seedmi-dc store from a bootstrap file.
Usage: node src/dc-import.ts --config <path> --from <path> [flags]
  --config <path>   the controller's configuration, which gives [directory].store,
                    the ranges numbers are allocated from, the realm and [kms]
  --from <path>     the bootstrap file: [[ou]], [[user]] and [[group]]
  --dry-run         read and check the bootstrap file, write nothing
  --help            print this text and exit (also -h)
  --version         print the version and exit (also -v)
The store is seeded once: one that already holds a principal or a unit is
refused. A user is given a password, from which a verifier and a Kerberos key for
each enctype are derived, or a password_hash, from which only a verifier can be —
so a principal imported with a hash is never issued a ticket until a password is
set through the administrative interface.
`;

/** A unit of the bootstrap file: a name, and the path of the unit above it. */
export interface UnitEntry {
  name: string;
  parent?: string;
  description?: string;
}

export interface UserEntry {
  name: string;
  password?: string;
  passwordHash?: string;
  groups: string[];
  ou?: string;
  displayName?: string;
  disabled: boolean;
  expires?: string;
  home?: string;
  /** A client certificate, as sha256: and sixty-four hexadecimal digits. */
  certificate?: string;
  certificateSubject?: string;
  /** Whether an S3 key pair is created, whose secret this program prints once. */
  s3: boolean;
}

export interface GroupEntry {
  name: string;
  groups: string[];
  ou?: string;
  displayName?: string;
}

export interface Bootstrap {
  units: UnitEntry[];
  users: UserEntry[];
  groups: GroupEntry[];
}

export class ImportError extends Error {}

type Table = Record<string, TOMLValue>;

const list = (v: TOMLValue | undefined, where: string): Table[] => {
  if (v === undefined) return [];
  if (!Array.isArray(v)) throw new ImportError(`${where} is an array of tables`);
  return v.map((t, i) => {
    if (t === null || typeof t !== "object" || Array.isArray(t)) {
      throw new ImportError(`${where}[${i}] is a table`);
    }
    return t as Table;
  });
};
const str = (t: Table, k: string, where: string): string | undefined => {
  const v = t[k];
  if (v === undefined) return undefined;
  if (typeof v !== "string") throw new ImportError(`${where}.${k} is a string`);
  return v;
};
const strings = (t: Table, k: string, where: string): string[] => {
  const v = t[k];
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
    throw new ImportError(`${where}.${k} is an array of strings`);
  }
  return v as string[];
};
const flag = (t: Table, k: string, where: string): boolean => {
  const v = t[k];
  if (v === undefined) return false;
  if (typeof v !== "boolean") throw new ImportError(`${where}.${k} is true or false`);
  return v;
};
const only = (t: Table, where: string, allowed: string[]) => {
  for (const k of Object.keys(t)) {
    if (!allowed.includes(k)) {
      throw new ImportError(
        `${where} takes no setting ${JSON.stringify(k)}; it takes ${allowed.join(", ")}`);
    }
  }
};

/**
 * Reads a bootstrap file. A setting this program does not take is refused rather
 * than ignored, as the configuration reader refuses one: an import is run once,
 * and a field quietly dropped would not be noticed until much later.
 */
export function parseBootstrap(text: string): Bootstrap {
  let doc: Table;
  try {
    doc = parseTOML(text) as Table;
  } catch (e) {
    throw new ImportError(`the bootstrap file is not TOML: ${(e as Error).message}`);
  }
  only(doc, "a bootstrap file", ["ou", "user", "group"]);
  const units = list(doc.ou, "[[ou]]").map((t, i) => {
    const where = `[[ou]][${i}]`;
    only(t, where, ["name", "parent", "description"]);
    const name = str(t, "name", where);
    if (name === undefined) throw new ImportError(`${where} gives a name`);
    const parent = str(t, "parent", where);
    const description = str(t, "description", where);
    return {
      name,
      ...(parent === undefined ? {} : { parent }),
      ...(description === undefined ? {} : { description }),
    };
  });
  const users = list(doc.user, "[[user]]").map((t, i) => {
    const where = `[[user]][${i}]`;
    only(t, where, ["name", "password", "password_hash", "groups", "ou", "display_name",
      "disabled", "expires", "home", "certificate", "certificate_subject", "s3"]);
    const name = str(t, "name", where);
    if (name === undefined) throw new ImportError(`${where} gives a name`);
    const password = str(t, "password", where);
    const passwordHash = str(t, "password_hash", where);
    if (password !== undefined && passwordHash !== undefined) {
      throw new ImportError(`${where} gives a password and a password_hash; one is given`);
    }
    const expires = str(t, "expires", where);
    if (expires !== undefined && Number.isNaN(Date.parse(expires))) {
      throw new ImportError(`${where}.expires is a time, as "2027-01-01T00:00:00Z"`);
    }
    const ou = str(t, "ou", where);
    const displayName = str(t, "display_name", where);
    const home = str(t, "home", where);
    const certificate = str(t, "certificate", where);
    const certificateSubject = str(t, "certificate_subject", where);
    if (certificateSubject !== undefined && certificate === undefined) {
      throw new ImportError(`${where} gives a certificate_subject and no certificate`);
    }
    return {
      name,
      ...(password === undefined ? {} : { password }),
      ...(passwordHash === undefined ? {} : { passwordHash }),
      groups: strings(t, "groups", where),
      ...(ou === undefined ? {} : { ou }),
      ...(displayName === undefined ? {} : { displayName }),
      disabled: flag(t, "disabled", where),
      ...(expires === undefined ? {} : { expires }),
      ...(home === undefined ? {} : { home }),
      ...(certificate === undefined ? {} : { certificate }),
      ...(certificateSubject === undefined ? {} : { certificateSubject }),
      s3: flag(t, "s3", where),
    };
  });
  const groups = list(doc.group, "[[group]]").map((t, i) => {
    const where = `[[group]][${i}]`;
    only(t, where, ["name", "groups", "ou", "display_name"]);
    const name = str(t, "name", where);
    if (name === undefined) throw new ImportError(`${where} gives a name`);
    const ou = str(t, "ou", where);
    const displayName = str(t, "display_name", where);
    return {
      name,
      groups: strings(t, "groups", where),
      ...(ou === undefined ? {} : { ou }),
      ...(displayName === undefined ? {} : { displayName }),
    };
  });
  return { units, users, groups };
}

/** What an import did, which the program prints and a test reads. */
export interface Report {
  units: number;
  users: number;
  groups: number;
  memberships: number;
  passwords: number;
  /** Users whose verifier was imported hashed, and who therefore have no key. */
  hashed: string[];
  certificates: number;
  /** The S3 key pairs created, whose secret is printed once and never again. */
  s3: { name: string; accessKeyId: string; secret: string }[];
}

/**
 * Writes a bootstrap into a store through the one write path, so that an
 * imported directory is one the administrative interface could have produced and
 * every invariant of §2 is checked on the way in.
 *
 * The order is the order the rules require: units from the top down, then groups
 * (so a membership has something to name), then users, then the memberships of
 * groups in groups, then credentials.
 */
export async function seed(w: Writer, b: Bootstrap): Promise<Report> {
  const report: Report = {
    units: 0, users: 0, groups: 0, memberships: 0, passwords: 0, hashed: [],
    certificates: 0, s3: [],
  };
  // Units, parents first. A file may list a child before its parent, so the list
  // is walked until nothing more can be created; what is left names a parent that
  // is not in the file at all.
  const pending = [...b.units];
  while (pending.length > 0) {
    const before = pending.length;
    for (let i = pending.length - 1; i >= 0; i--) {
      const u = pending[i];
      const ready = u.parent === undefined || hasUnit(w, u.parent);
      if (!ready) continue;
      w.createUnit(u.name, u.parent, u.description);
      report.units++;
      pending.splice(i, 1);
    }
    if (pending.length === before) {
      const names = pending.map((u) => `${u.name} (under ${u.parent})`).join(", ");
      throw new ImportError(
        `[[ou]] names a parent that is not in the file and not in the store: ${names}`);
    }
  }
  // Groups before users, so that a user's groups name something, and before the
  // memberships of groups in groups for the same reason.
  for (const g of b.groups) {
    w.create("group", g.name, {
      ...(g.ou === undefined ? {} : { ou: g.ou }),
      ...(g.displayName === undefined ? {} : { displayName: g.displayName }),
    });
    report.groups++;
  }
  for (const u of b.users) {
    w.create("user", u.name, {
      ...(u.ou === undefined ? {} : { ou: u.ou }),
      ...(u.displayName === undefined ? {} : { displayName: u.displayName }),
      disabled: u.disabled,
      ...(u.expires === undefined ? {} : { expires: u.expires }),
      ...(u.home === undefined ? {} : { home: u.home }),
    });
    report.users++;
  }
  for (const g of b.groups) {
    for (const of of g.groups) {
      w.addMember(of, g.name);
      report.memberships++;
    }
  }
  for (const u of b.users) {
    for (const of of u.groups) {
      w.addMember(of, u.name);
      report.memberships++;
    }
  }
  // Credentials last: a key store that cannot be reached leaves a directory that
  // is whole and has no secret material, which is a state an administrator can
  // finish by hand, rather than a half-written tree.
  for (const u of b.users) {
    if (u.password !== undefined) {
      await w.setPassword(w.principal(u.name).id, u.password);
      report.passwords++;
    } else if (u.passwordHash !== undefined) {
      await w.setPasswordHash(w.principal(u.name).id, u.passwordHash);
      report.hashed.push(u.name);
    }
    if (u.certificate !== undefined) {
      w.addCertificate(w.principal(u.name).id, u.certificate, u.certificateSubject);
      report.certificates++;
    }
    if (u.s3) {
      const pair = await w.createS3Key(w.principal(u.name).id);
      report.s3.push({ name: u.name, ...pair });
    }
  }
  return report;
}

const hasUnit = (w: Writer, p: string): boolean => {
  try {
    w.unitAt(p);
    return true;
  } catch {
    return false;
  }
};

/** The configuration a seed needs, and the reason where it does not have it. */
export function storeOf(c: Config): { store: string; uid: [number, number]; gid: [number, number] } {
  if (c.store === undefined) {
    throw new ImportError(
      "the configuration gives no [directory].store, so its directory is the configuration " +
      "itself and there is nothing to import into: give a store, and move the users and " +
      "groups of the file into a bootstrap file");
  }
  if (c.uidRange === undefined || c.gidRange === undefined) {
    throw new ImportError("the configuration gives no ranges to allocate POSIX numbers from");
  }
  return { store: c.store, uid: c.uidRange, gid: c.gidRange };
}

/**
 * The first value the relative identifier counter issues. Windows reserves the
 * numbers below this for its own well-known principals ([MS-ADTS] 6.1.6), and a
 * directory whose identifiers are read by a Windows client stays out of them.
 */
export const FIRST_RID = 1000;

/** Opens the store of a configuration, setting the counters where it is new. */
export function openStore(c: Config): Store {
  const { store, uid, gid } = storeOf(c);
  const s = Store.open(store);
  s.transact(() => {
    s.seedCounter("sid_rid", FIRST_RID);
    s.seedCounter("posix_user", uid[0]);
    s.seedCounter("posix_group", gid[0]);
    // The realm a store belongs to, so that a store opened against another
    // realm's configuration is noticed rather than silently written: the
    // identifiers within it only mean anything beside the realm that issued them.
    const held = s.meta("realm");
    if (held === undefined) {
      s.setMeta("realm", c.realm);
      s.setMeta("domain_sid", c.domainSid);
    } else if (held !== c.realm) {
      throw new StoreError(
        `the store at ${store} holds the directory of ${held}, and this configuration ` +
        `serves ${c.realm}`);
    }
  });
  return s;
}

function main(): void {
  const argv = process.argv.slice(2);
  const flags: Record<string, string | true> = {};
  const takes: Record<string, boolean> = {
    "--config": true, "--from": true, "--dry-run": false, "--help": false, "-h": false,
    "--version": false, "-v": false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!(a in takes)) {
      process.stderr.write(`dc-import: ${a} is not a flag of this program; --help lists them\n`);
      process.exit(2);
    }
    if (takes[a]) {
      if (i + 1 >= argv.length) {
        process.stderr.write(`dc-import: ${a} takes a value\n`);
        process.exit(2);
      }
      flags[a] = argv[++i];
    } else {
      flags[a] = true;
    }
  }
  if (flags["--help"] || flags["-h"]) { process.stdout.write(USAGE); return; }
  if (flags["--version"] || flags["-v"]) { process.stdout.write(`dc-import ${VERSION}\n`); return; }
  const configPath = flags["--config"], fromPath = flags["--from"];
  if (typeof configPath !== "string" || typeof fromPath !== "string") {
    process.stderr.write("dc-import: --config and --from are both given; --help says what each is\n");
    process.exit(2);
    return;
  }
  run(configPath, fromPath, flags["--dry-run"] === true).catch((e: unknown) => {
    const known = e instanceof ImportError || e instanceof ConfigError ||
      e instanceof StoreError || e instanceof WriteError;
    process.stderr.write(`dc-import: ${known ? (e as Error).message : String(e)}\n`);
    if (!known) process.stderr.write(`${(e as Error).stack ?? ""}\n`);
    process.exit(1);
  });
}

async function run(configPath: string, fromPath: string, dry: boolean): Promise<void> {
  const config = parseConfig(readFileSync(configPath, "utf8"), path.dirname(configPath));
  const bootstrap = parseBootstrap(readFileSync(fromPath, "utf8"));
  const { store } = storeOf(config);
  if (dry) {
    process.stdout.write(
      `dc-import: the bootstrap file reads: ${bootstrap.units.length} unit(s), ` +
      `${bootstrap.users.length} user(s), ${bootstrap.groups.length} group(s); ` +
      `nothing was written to ${store}\n`);
    return;
  }
  if (config.kms === undefined) {
    throw new ImportError(
      "the configuration gives no [kms]; secret material is kept at a key management " +
      "server and this program does not write it anywhere else");
  }
  const s = openStore(config);
  try {
    if (!s.empty) {
      throw new ImportError(
        `the store at ${store} already holds a directory, and a seed is a one-time step: ` +
        "use the administrative interface to change a directory that exists");
    }
    const keys: KeyStore = KmipKeyStore.over(config.kms);
    const w = new Writer(s, keys, { name: config.realm, etypes: [ETYPE.aes256, ETYPE.aes128] });
    const report = await seed(w, bootstrap);
    process.stdout.write(
      `dc-import: ${report.units} unit(s), ${report.groups} group(s), ${report.users} user(s), ` +
      `${report.memberships} membership(s), ${report.passwords} password(s) and ` +
      `${report.certificates} certificate(s) written to ${store}\n`);
    if (report.hashed.length > 0) {
      process.stdout.write(
        `dc-import: imported with a hashed verifier and no Kerberos key, so no ticket is ` +
        `issued until a password is set: ${report.hashed.join(", ")}\n`);
    }
    for (const pair of report.s3) {
      // Printed once. The secret is not readable again through either front end.
      process.stdout.write(`dc-import: S3 key for ${pair.name}: ${pair.accessKeyId} ${pair.secret}\n`);
    }
  } finally {
    s.close();
  }
}

// Run as a program, not when a test imports the readers above.
if (process.argv[1] !== undefined && /dc-import\.ts$/.test(process.argv[1])) main();
