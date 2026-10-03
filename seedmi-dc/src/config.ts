// The configuration of seedmi-dc: a TOML file, and flags that win over it.
//
//   [realm]    name (EU.EXAMPLE), domain (eu.example)
//   [listen]   host, port (HTTPS), ldap_port (LDAPS), certificate(_file), key(_file)
//   [[user]]   name, password_hash (or password), groups, disabled, expires
//   [[group]]  name, groups
//   [directory] memberof, store, uid_range, gid_range
//   [kms]      host, port, certificate(_file), key(_file), authority(_file),
//              key_cache_seconds, timeout_seconds (dc-keys.ts)
//   [tokens]   issuer, signing_key(_file), previous_keys, lifetime_seconds (tokens.ts)
//   [[client]] id, secret_hash (or secret), grants, audiences, subject_audiences
//   [[trust]]  realm, issuer, ca(_file): another realm whose tokens are exchanged
//   [log]      level, file, format
//
// The directory is the configuration's: users and groups are given here and
// read again on SIGHUP, and checked as a whole (dc-directory.ts). A deployment
// whose directory is written through an administrative interface gives
// [directory].store instead, and then this file holds no user or group: the
// store is the directory and [kms] says where its secret material is kept
// (DESIGN-admin.md). A setting this program does not take is refused rather
// than ignored, and a path is relative to the configuration file.

import { ETYPE } from "./krb-crypto.ts";
import type { KdcConfig, KdcPrincipal } from "./krb-kdc.ts";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { parseTOML, type TOMLValue } from "./toml.ts";
import { Directory, DirectoryError, type GroupSpec, HASH, hashPassword, type UserSpec } from "./dc-directory.ts";
import { type ClientSpec, GRANTS, SCOPES, TokenService, type TrustedRealm } from "./tokens.ts";
import { Throttle } from "./throttle.ts";
import { formatDn, parseDn } from "./dn.ts";
import type { KmsConfig } from "./dc-keys.ts";
import { createPrivateKey, createPublicKey } from "node:crypto";

export class ConfigError extends Error {}

/** A domain identifier derived from the realm's name, where none is given. */
function derivedSid(realm: string): string {
  const parts: number[] = [];
  let h = 0x811c9dc5;
  for (const c of `${realm}\u0000seedmi-dc`) {
    h ^= c.charCodeAt(0);
    h = Math.imul(h, 0x01000193) >>> 0;
    parts.push(h);
  }
  const at = (i: number) => (parts[i % parts.length] ?? 1) >>> 1;
  return `S-1-5-21-${at(3)}-${at(7)}-${at(11)}`;
}

export interface Config {
  /** The realm's name, in the upper-case form Kerberos gives it. */
  realm: string;
  /** Its DNS domain, from which an LDAP base name is formed (dc=eu,dc=example). */
  domain: string;
  /** The security identifier of the domain ([MS-PAC]), given or derived. */
  domainSid: string;
  host: string;
  port: number;
  /** Where LDAP is served over TLS, or undefined where it is not. */
  ldapPort?: number;
  /**
   * A cleartext LDAP listener where a client installs a TLS layer with StartTLS
   * (RFC 4511 §4.14). RFC 4513 §2 makes supporting it a MUST for a server offering
   * more than an anonymous simple bind; before the layer is installed the session
   * serves only the root DSE, so StartTLS can be discovered, and refuses everything
   * else with `confidentialityRequired`.
   */
  ldapStartTlsPort?: number;
  /**
   * Whether memberOf reports direct memberships alone, as Active Directory's
   * does, rather than every group a user belongs to ([directory] memberof).
   */
  directMemberOf: boolean;
  /** The key distribution centre, where [kerberos] configures one (krb-kdc.ts). */
  kdc?: KdcConfig;
  /**
   * The service principals [[service]] gives, kept apart from the users so that a
   * directory read from the store replaces the users and leaves these.
   */
  kdcServices?: KdcPrincipal[];
  /** The port it answers on. */
  kdcPort?: number;
  tlsCert: string;
  tlsKey: string;
  directory: Directory;
  /**
   * Where the directory is kept, for a deployment whose directory is written
   * through an administrative interface rather than given in this file
   * ([directory] store). Where it is unset, the file is the directory.
   */
  store?: string;
  /** The range a POSIX user number is allocated from ([directory] uid_range). */
  uidRange?: [number, number];
  /** The range a POSIX group number is allocated from ([directory] gid_range). */
  gidRange?: [number, number];
  /** The key management server secret material is kept at, where [kms] is given. */
  kms?: KmsConfig;
  /**
   * Who may write the directory: a client certificate the authority issued and
   * naming one of the subjects ([admin], DESIGN-admin.md §6). Where it is unset,
   * the directory is read only through every front end, whether or not a store
   * holds it.
   */
  admin?: { authority: string; subjects: string[] };
  /** The token service, where [tokens] is given. */
  tokens?: TokenService;
  /** How many clients were given a plain secret, which the log warns of. */
  plainSecrets: number;
  log: "off" | "problems" | "requests";
  logFile?: string;
  logFormat: "text" | "json";
}

export const DEFAULTS: Config = {
  realm: "", domain: "", host: "127.0.0.1", port: 8636, tlsCert: "", tlsKey: "", directory: new Directory([], []), plainSecrets: 0,
  directMemberOf: false,
  domainSid: "",
  log: "off", logFormat: "text",
};

type Table = Record<string, TOMLValue>;
const table = (v: TOMLValue | undefined, where: string): Table => {
  if (v === undefined) return {};
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new ConfigError(`${where} is a table`);
  return v as Table;
};
const only = (t: Table, where: string, allowed: string[]) => {
  for (const k of Object.keys(t)) if (!allowed.includes(k)) throw new ConfigError(`${where} takes no setting ${JSON.stringify(k)}`);
};
const str = (t: Table, k: string, where: string): string | undefined => {
  const v = t[k];
  if (v === undefined) return undefined;
  if (typeof v !== "string") throw new ConfigError(`${where}.${k} is a string`);
  return v;
};
const int = (t: Table, k: string, where: string): number | undefined => {
  const v = t[k];
  if (v === undefined) return undefined;
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > 65535) throw new ConfigError(`${where}.${k} is a port number`);
  return v;
};
/** A whole number of seconds, of the sizes this program's windows take. */
const seconds = (t: Table, k: string, where: string): number | undefined => {
  const v = t[k];
  if (v === undefined) return undefined;
  if (typeof v !== "number" || !Number.isInteger(v) || v < 1 || v > 86400) {
    throw new ConfigError(`${where}.${k} is a whole number of seconds, 1 to 86400`);
  }
  return v;
};
/** A range of POSIX numbers, as [first, last]. */
const numberRange = (t: Table, k: string, where: string): [number, number] | undefined => {
  const v = t[k];
  if (v === undefined) return undefined;
  const whole = (x: unknown) => typeof x === "number" && Number.isInteger(x) && x >= 0 && x <= 0xffffffff;
  if (!Array.isArray(v) || v.length !== 2 || !whole(v[0]) || !whole(v[1])) {
    throw new ConfigError(`${where}.${k} is a range of whole numbers, as [first, last]`);
  }
  const [first, last] = v as [number, number];
  if (last < first) throw new ConfigError(`${where}.${k} ends before it begins`);
  // A number is never reissued, so a range that holds a handful is a deployment
  // that will run out; nothing here forbids it, but zero numbers is a mistake.
  if (first === 0) throw new ConfigError(`${where}.${k} begins at 0, which is the superuser's number`);
  return [first, last];
};
/** Whether two ranges share a number. */
const overlaps = (a: [number, number], b: [number, number]): boolean => a[0] <= b[1] && b[0] <= a[1];
/** A path as the configuration gives it: relative to the file it was read from. */
const resolve = (p: string, dir: string): string => (path.isAbsolute(p) ? p : path.join(dir, p));
/** An array of strings, as several settings of this file take. */
const strings = (t: Table, k: string, where: string): string[] => {
  const v = t[k];
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) throw new ConfigError(`${where}.${k} is an array of strings`);
  return v as string[];
};
const material = (t: Table, k: string, where: string, dir: string): string | undefined => {
  const inline = str(t, k, where);
  const file = str(t, `${k}_file`, where);
  if (inline !== undefined && file !== undefined) throw new ConfigError(`${where} gives ${k} and ${k}_file; one is given`);
  if (file === undefined) return inline;
  try {
    return readFileSync(path.isAbsolute(file) ? file : path.join(dir, file), "utf8");
  } catch (e) {
    throw new ConfigError(`${where}.${k}_file cannot be read: ${(e as Error).message}`);
  }
};

/** A realm name: labels of upper-case letters, digits and hyphens, separated by dots. */
export const REALM = /^[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?)*$/;
/** A DNS domain, in lower case. */
export const DOMAIN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/;

/**
 * Reads a configuration. The throttle is the program's, held across reloads so
 * that a reload does not clear the failures it has counted.
 */
export function parseConfig(text: string, dir = ".", throttle: Throttle = new Throttle()): Config {
  let doc: Table;
  try {
    doc = parseTOML(text) as Table;
  } catch (e) {
    throw new ConfigError(`the configuration is not TOML: ${(e as Error).message}`);
  }
  only(doc, "the configuration", ["realm", "listen", "user", "group", "directory", "kms", "admin", "tokens", "client", "trust", "kerberos", "service", "log"]);
  const c: Config = { ...DEFAULTS };

  const realm = table(doc.realm, "[realm]");
  only(realm, "[realm]", ["name", "domain", "sid"]);
  c.realm = str(realm, "name", "[realm]") ?? "";
  c.domain = str(realm, "domain", "[realm]") ?? "";
  // The security identifier of the domain, which the privilege attribute
  // certificate of a ticket carries and which the directory serves as
  // objectSid. Where it is not given, one is derived from the realm's name,
  // so that a realm has the same identifiers wherever its configuration is
  // read; a realm that must match an existing domain gives its own.
  const sid = str(realm, "sid", "[realm]");
  if (sid !== undefined && !/^S-1-5-21(-\d+){3}$/.test(sid)) {
    throw new ConfigError('[realm].sid is a domain security identifier, as "S-1-5-21-<a>-<b>-<c>"');
  }
  c.domainSid = sid ?? derivedSid(c.realm);

  const listen = table(doc.listen, "[listen]");
  only(listen, "[listen]", ["host", "port", "ldap_port", "ldap_starttls_port",
    "certificate", "certificate_file", "key", "key_file"]);
  const ldapPort = int(listen, "ldap_port", "[listen]");
  if (ldapPort !== undefined) c.ldapPort = ldapPort;
  const startTlsPort = int(listen, "ldap_starttls_port", "[listen]");
  if (startTlsPort !== undefined) {
    if (startTlsPort === ldapPort) {
      throw new ConfigError(
        "[listen].ldap_starttls_port and ldap_port are the same port: one is cleartext until a " +
        "client sends StartTLS and the other is TLS from the first octet");
    }
    c.ldapStartTlsPort = startTlsPort;
  }
  c.host = str(listen, "host", "[listen]") ?? c.host;
  c.port = int(listen, "port", "[listen]") ?? c.port;
  c.tlsCert = material(listen, "certificate", "[listen]", dir) ?? "";
  c.tlsKey = material(listen, "key", "[listen]", dir) ?? "";

  // [directory]: how the directory is served over LDAP, and where it is kept.
  {
    const dt = table(doc.directory, "[directory]");
    only(dt, "[directory]", ["memberof", "store", "uid_range", "gid_range"]);
    const memberof = str(dt, "memberof", "[directory]") ?? "transitive";
    if (memberof !== "transitive" && memberof !== "direct") {
      throw new ConfigError('[directory].memberof is "transitive", every group a user belongs to, or "direct", those it names');
    }
    c.directMemberOf = memberof === "direct";
    // The store, where a deployment keeps a directory that an administrative
    // interface writes (DESIGN-admin.md §1). Where it is given, this file is a
    // bootstrap and not a second source of truth: the users and groups within
    // it are refused, and dc-import seeds the store from a file that has them.
    const store = str(dt, "store", "[directory]");
    if (store !== undefined) {
      if (store === "") throw new ConfigError("[directory].store is a path");
      c.store = resolve(store, dir);
      if (doc.user !== undefined || doc.group !== undefined) {
        throw new ConfigError(
          "[directory].store is given, so the directory is the store and not this file: " +
          "remove [[user]] and [[group]], and seed the store from a bootstrap file with " +
          `dc-import --from <file> --store ${store}`);
      }
      // A POSIX number is allocated from these ranges and is never reissued, so
      // this server chooses no default: a default would collide with the numbers
      // of whatever host the deployment already has.
      c.uidRange = numberRange(dt, "uid_range", "[directory]");
      c.gidRange = numberRange(dt, "gid_range", "[directory]");
      if (c.uidRange === undefined || c.gidRange === undefined) {
        throw new ConfigError(
          "[directory].uid_range and gid_range are given where a store is, each as " +
          "[first, last]: a POSIX number is allocated from them and is never reissued, " +
          "so this server chooses no range of its own");
      }
      // Separate spaces are permitted, and a deployment that wants one space gives
      // one range to both; what is refused is a partial overlap, which is neither.
      if (overlaps(c.uidRange, c.gidRange) &&
        (c.uidRange[0] !== c.gidRange[0] || c.uidRange[1] !== c.gidRange[1])) {
        throw new ConfigError(
          "[directory].uid_range and gid_range overlap in part; give them the same range " +
          "for one space of numbers, or ranges that do not meet");
      }
    }
  }
  // [admin]: who may write the directory. A certificate the named authority
  // issued, presented on the LDAP connection and naming a listed subject
  // (DESIGN-admin.md §6). No administrator password exists anywhere, and no
  // principal of the directory is an administrator by being in a group: an
  // administrator is a certificate holder, and the authority is the operator's.
  {
    const at = table(doc.admin, "[admin]");
    only(at, "[admin]", ["authority", "authority_file", "subjects"]);
    const authority = material(at, "authority", "[admin]", dir);
    const subjects = strings(at, "subjects", "[admin]");
    if (authority !== undefined) {
      if (authority.trim() === "") throw new ConfigError("[admin].authority is a certificate in PEM");
      if (subjects.length === 0) {
        throw new ConfigError(
          "[admin].subjects names the certificate subjects that may write, as " +
          '"CN=dcadmin,O=Example": an authority alone would admit every certificate it ever issues');
      }
      // Each subject is a distinguished name, checked here rather than left to
      // fail silently at a bind: a string that is not one can never match a
      // certificate, so a deployment that wrote the OpenSSL "/CN=x/O=y" form would
      // have an administrator nobody can be. Normalized to the RFC 4514 form at the
      // same time, so that what the log and RFC 4532's "Who am I?" report is a
      // distinguished name a client can parse.
      c.admin = { authority, subjects: subjects.map((wanted) => {
        const rdns = parseDn(wanted);
        if (rdns === undefined || rdns.length === 0) {
          throw new ConfigError(
            `[admin].subjects holds ${JSON.stringify(wanted)}, which is not a distinguished ` +
            'name: a subject is written as RFC 4514 writes one, "CN=dcadmin,O=Example", and a ' +
            "value containing a comma, plus, equals, quote, backslash, semicolon or angle " +
            "bracket has it escaped with a backslash");
        }
        return formatDn(rdns);
      }) };
    } else if (subjects.length > 0) {
      throw new ConfigError(
        "[admin].subjects is given and [admin].authority is not: a subject is checked against " +
        "a certificate, and a certificate is accepted under an authority");
    }
  }
  // [kms]: the key management server this controller keeps secret material at
  // (DESIGN-admin.md §4). Given where a store is, since a password written
  // through the administrative interface becomes a verifier and a Kerberos key,
  // and neither belongs in the directory.
  {
    const kt = table(doc.kms, "[kms]");
    only(kt, "[kms]", ["host", "port", "certificate", "certificate_file", "key", "key_file",
      "authority", "authority_file", "key_cache_seconds", "timeout_seconds"]);
    const host = str(kt, "host", "[kms]");
    if (host !== undefined) {
      if (host === "") throw new ConfigError("[kms].host is the name the key server's certificate is checked against");
      const certificate = material(kt, "certificate", "[kms]", dir);
      const key = material(kt, "key", "[kms]", dir);
      if (certificate === undefined || key === undefined) {
        throw new ConfigError(
          "[kms] gives the certificate and key this controller authenticates with, as " +
          "certificate(_file) and key(_file): the KMIP Basic Authentication Suite " +
          "identifies a client by the certificate it presents");
      }
      const authority = material(kt, "authority", "[kms]", dir);
      const timeout = seconds(kt, "timeout_seconds", "[kms]");
      c.kms = {
        host,
        port: int(kt, "port", "[kms]") ?? 5696,
        certificate,
        key,
        ...(authority === undefined ? {} : { authority }),
        // The window in which material destroyed at the key server still works
        // here, because a ticket request needs a key and this server serves no
        // Decrypt. Stated in the log at start.
        lifetime: (seconds(kt, "key_cache_seconds", "[kms]") ?? 300) * 1000,
        ...(timeout === undefined ? {} : { timeout: timeout * 1000 }),
      };
    } else if (c.store !== undefined) {
      throw new ConfigError(
        "[directory].store is given and [kms] is not: a password written through the " +
        "administrative interface becomes a verifier and a Kerberos key, and both are " +
        "kept at a key management server rather than in the directory");
    }
  }

  // The directory: [[user]] and [[group]] tables, each naming the groups it belongs to.
  const list = (v: TOMLValue | undefined, where: string): Table[] => {
    if (v === undefined) return [];
    if (!Array.isArray(v)) throw new ConfigError(`${where} is an array of tables`);
    return v.map((t, i) => table(t as TOMLValue, `${where}[${i}]`));
  };
  const users: UserSpec[] = list(doc.user, "[[user]]").map((t, i) => {
    const where = `[[user]][${i}]`;
    only(t, where, ["name", "password_hash", "password", "groups", "disabled", "expires", "home"]);
    const name = str(t, "name", where);
    if (name === undefined) throw new ConfigError(`${where} gives a name`);
    const disabled = t.disabled;
    if (disabled !== undefined && typeof disabled !== "boolean") throw new ConfigError(`${where}.disabled is true or false`);
    // A time as the draft writes one; this TOML reader takes no date-time, so it is a string.
    const expires = str(t, "expires", where);
    if (expires !== undefined && Number.isNaN(Date.parse(expires))) {
      throw new ConfigError(`${where}.expires is a time, as "2027-01-01T00:00:00Z"`);
    }
    const passwordHash = str(t, "password_hash", where);
    const password = str(t, "password", where);
    return { name, groups: strings(t, "groups", where), disabled: disabled === true,
      ...(passwordHash === undefined ? {} : { passwordHash }), ...(password === undefined ? {} : { password }),
      // The home of the principal, which the directory serves as
      // unixHomeDirectory: a CDMI server reads it from there where the domain's
      // descriptor names no attribute of its own (revision 302).
      ...(str(t, "home", where) === undefined ? {} : { home: str(t, "home", where)! }),
      ...(expires === undefined ? {} : { expires: new Date(expires) }) };
  });
  const groups: GroupSpec[] = list(doc.group, "[[group]]").map((t, i) => {
    const where = `[[group]][${i}]`;
    only(t, where, ["name", "groups"]);
    const name = str(t, "name", where);
    if (name === undefined) throw new ConfigError(`${where} gives a name`);
    return { name, groups: strings(t, "groups", where) };
  });
  try {
    c.directory = new Directory(users, groups);
  } catch (e) {
    if (e instanceof DirectoryError) throw new ConfigError(e.message);
    throw e;
  }

  // Tokens: [tokens] and the [[client]] tables that may ask for them.
  const tok = table(doc.tokens, "[tokens]");
  const clientTables = list(doc.client, "[[client]]");
  if (Object.keys(tok).length === 0 && clientTables.length > 0) throw new ConfigError("[[client]] is given with [tokens]");
  if (Object.keys(tok).length > 0) {
    only(tok, "[tokens]", ["issuer", "signing_key", "signing_key_file", "previous_keys", "lifetime_seconds"]);
    const issuer = str(tok, "issuer", "[tokens]");
    let issuerUrl: URL | undefined;
    try { issuerUrl = issuer === undefined ? undefined : new URL(issuer); } catch { issuerUrl = undefined; }
    // RFC 8414 section 2: an https URL "that has no query or fragment components".
    if (issuerUrl === undefined || issuerUrl.protocol !== "https:" || issuerUrl.search !== "" || issuerUrl.hash !== "") {
      throw new ConfigError("[tokens].issuer is an https URL with no query or fragment: the controller's, as its clients reach it");
    }
    // The metadata of an issuer with a path is found beneath that path (RFC
    // 8414 section 3), and the endpoints this controller serves are at its root.
    if (issuerUrl.pathname !== "/") {
      throw new ConfigError(`[tokens].issuer has the path ${issuerUrl.pathname}; the controller serves its endpoints at the root, so the issuer has none`);
    }
    const keyPem = material(tok, "signing_key", "[tokens]", dir);
    if (keyPem === undefined) throw new ConfigError("[tokens] gives the signing key its tokens are signed with");
    let signingKey;
    try { signingKey = createPrivateKey(keyPem); } catch (e) { throw new ConfigError(`[tokens].signing_key is not a private key: ${(e as Error).message}`); }
    const previousKeys = strings(tok, "previous_keys", "[tokens]").map((f) => {
      try {
        return createPublicKey(readFileSync(path.isAbsolute(f) ? f : path.join(dir, f), "utf8"));
      } catch (e) {
        throw new ConfigError(`[tokens].previous_keys holds ${f}, which is not a public key: ${(e as Error).message}`);
      }
    });
    const lifetime = tok.lifetime_seconds;
    if (lifetime !== undefined && (typeof lifetime !== "number" || !Number.isInteger(lifetime) || lifetime < 1 || lifetime > 86400)) {
      throw new ConfigError("[tokens].lifetime_seconds is a whole number of seconds, 1 to 86400");
    }
    let plain = 0;
    const ids = new Set<string>();
    const clients: ClientSpec[] = clientTables.map((t, i) => {
      const where = `[[client]][${i}]`;
      only(t, where, ["id", "secret_hash", "secret", "grants", "audiences", "subject_audiences", "scopes"]);
      const id = str(t, "id", where);
      if (id === undefined || id === "") throw new ConfigError(`${where} gives an id`);
      if (ids.has(id)) throw new ConfigError(`the client ${id} is given twice`);
      ids.add(id);
      // A token for the client names it as its subject (RFC 9068 section 2.2), so
      // a client named as a user is would be given tokens indistinguishable from
      // that user's; section 5 warns against it.
      const asUser = c.directory.user(id);
      if (asUser !== undefined) {
        throw new ConfigError(`the client ${id} has the name of the user ${asUser.name}, whose tokens its own would be mistaken for`);
      }
      const hash = str(t, "secret_hash", where), secret = str(t, "secret", where);
      if ((hash === undefined) === (secret === undefined || secret === "")) {
        throw new ConfigError(`${where} gives a secret_hash (as --hash-password prints), or a secret; one`);
      }
      if (hash !== undefined && !HASH.test(hash)) throw new ConfigError(`${where}.secret_hash is not one --hash-password writes`);
      if (secret !== undefined) plain++;
      const grants = strings(t, "grants", where);
      if (grants.length === 0) throw new ConfigError(`${where} gives the grants it may use: ${GRANTS.join(", ")}`);
      for (const g of grants) if (!GRANTS.includes(g)) throw new ConfigError(`${where}.grants names ${g}; the grants are ${GRANTS.join(", ")}`);
      const audiences = strings(t, "audiences", where);
      if (audiences.length === 0) throw new ConfigError(`${where} gives the audiences it may ask a token for`);
      const subjectAudiences = t.subject_audiences === undefined ? undefined : strings(t, "subject_audiences", where);
      // The scopes this client may be issued. A scope of the administrative
      // interface is checked here against the pair this program defines, so that
      // a misspelling is refused at start rather than at the first request that
      // needed it: a client configured with "dc.write" would be authenticated,
      // issued a token, and refused by the interface with nothing to point at.
      const scopes = strings(t, "scopes", where);
      for (const s of scopes) {
        if (s.startsWith("dc.") && !(Object.values(SCOPES) as string[]).includes(s)) {
          throw new ConfigError(
            `${where}.scopes names ${s}; the scopes of this controller's administrative ` +
            `interface are ${Object.values(SCOPES).join(" and ")}`);
        }
      }
      return { id, secretHash: hash ?? hashPassword(secret!), grants, audiences,
        ...(subjectAudiences === undefined ? {} : { subjectAudiences }),
        ...(scopes.length === 0 ? {} : { scopes }) };
    });
    c.plainSecrets = plain;
    // [[trust]]: other realms whose tokens this controller exchanges (phase 5).
    const trusted: TrustedRealm[] = list(doc.trust, "[[trust]]").map((t, i) => {
      const where = `[[trust]][${i}]`;
      only(t, where, ["realm", "issuer", "ca", "ca_file"]);
      const trealm = str(t, "realm", where);
      if (trealm === undefined || !REALM.test(trealm)) throw new ConfigError(`${where}.realm is a realm's name in upper case`);
      if (trealm === c.realm) throw new ConfigError(`${where} names this controller's own realm`);
      const tissuer = str(t, "issuer", where);
      let u: URL | undefined;
      try { u = tissuer === undefined ? undefined : new URL(tissuer); } catch { u = undefined; }
      if (u === undefined || u.protocol !== "https:") throw new ConfigError(`${where}.issuer is the trusted realm's https issuer identifier`);
      const ca = material(t, "ca", where, dir);
      if (ca === undefined || ca.trim() === "") throw new ConfigError(`${where} gives the authority for the trusted realm's certificate`);
      return { realm: trealm, issuer: tissuer!, ca };
    });
    c.tokens = new TokenService({ issuer: issuer!, signingKey, previousKeys, lifetimeSeconds: (lifetime as number | undefined) ?? 3600, clients, trusted },
      () => c.directory, throttle);
  }

  const log = table(doc.log, "[log]");
  only(log, "[log]", ["level", "file", "format"]);
  const level = str(log, "level", "[log]");
  if (level !== undefined) c.log = logLevel(level);
  const file = str(log, "file", "[log]");
  if (file !== undefined) c.logFile = path.isAbsolute(file) ? file : path.join(dir, file);
  const format = str(log, "format", "[log]");
  if (format !== undefined) c.logFormat = logFormat(format);
  // [kerberos] and [[service]]: the key distribution centre of this realm
  // (PLAN-auth.md, phase 6), which issues tickets for the services named here.
  // A principal is served where its password is in this configuration, a
  // Kerberos key being made from the password itself and not from its hash.
  {
    const kt = table(doc.kerberos, "[kerberos]");
    only(kt, "[kerberos]", ["port", "lifetime_seconds"]);
    const port = int(kt, "port", "[kerberos]");
    const services = list(doc.service, "[[service]]").map((t, i) => {
      const where = `[[service]][${i}]`;
      only(t, where, ["name", "password"]);
      const name = str(t, "name", where);
      const password = str(t, "password", where);
      if (name === undefined || !/^[A-Za-z0-9][A-Za-z0-9._-]*(\/[A-Za-z0-9][A-Za-z0-9._-]*)*$/.test(name)) {
        throw new ConfigError(`${where}.name is a service principal, as HTTP/cdmi.eu.example`);
      }
      if (password === undefined || password === "") throw new ConfigError(`${where} gives the password its key is made from`);
      return { parts: name.split("/"), password, type: 3 };
    });
    if (port !== undefined) {
      // Zero asks the system for a port, as [listen].port does.
      if (port < 0 || port > 65535) throw new ConfigError("[kerberos].port is a port number, or 0 for one the system gives");
      const users = c.directory.kerberosPrincipals();
      // Where a store holds the directory, the principals come from it and their
      // keys from the key server (dc-view.ts), so this file naming none is
      // ordinary; where the file is the directory, a centre with nothing to serve
      // is a mistake.
      if (users.length === 0 && services.length === 0 && c.store === undefined) {
        throw new ConfigError("[kerberos] is configured, and no principal has a password here to make a key from");
      }
      // Kept apart from the principals, so that a directory read again from the
      // store replaces the principals and leaves the services of this file.
      c.kdcServices = services;
      c.kdcPort = port;
      c.kdc = {
        realm: c.realm,
        principals: [...users, ...services],
        domainSid: c.domainSid,
        netbios: c.realm.split(".")[0],
        lifetime: int(kt, "lifetime_seconds", "[kerberos]") ?? 8 * 3600,
        etype: ETYPE.aes256,
      };
    } else if (services.length > 0) {
      throw new ConfigError("[[service]] names a service of a realm this controller does not serve: [kerberos].port is unset");
    }
  }
  return c;
}

const logLevel = (v: string): Config["log"] => {
  if (v !== "off" && v !== "problems" && v !== "requests") throw new ConfigError("the log level is off, problems or requests");
  return v;
};
const logFormat = (v: string): Config["logFormat"] => {
  if (v !== "text" && v !== "json") throw new ConfigError("the log format is text or json");
  return v;
};

const FLAGS: Record<string, boolean> = {
  "--config": true, "--host": true, "--port": true, "--log": true, "--log-file": true,
  "--log-format": true, "--help": false, "-h": false, "--version": false, "-v": false, "--hash-password": false,
  "--sweep-keys": false,
};

/** The flags of a command line, refusing one this program does not take. */
export function readArgv(argv: string[]): Record<string, string | true> {
  const out: Record<string, string | true> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!(a in FLAGS)) throw new ConfigError(`${a} is not a flag of this program; --help lists them`);
    if (FLAGS[a]) {
      if (i + 1 >= argv.length) throw new ConfigError(`${a} takes a value`);
      out[a] = argv[++i];
    } else {
      out[a] = true;
    }
  }
  return out;
}

export function applyFlags(c: Config, f: Record<string, string | true>): Config {
  const out = { ...c };
  if (typeof f["--host"] === "string") out.host = f["--host"];
  if (typeof f["--port"] === "string") {
    const n = Number(f["--port"]);
    if (!Number.isInteger(n) || n < 0 || n > 65535) throw new ConfigError("--port is a port number");
    out.port = n;
  }
  if (typeof f["--log"] === "string") out.log = logLevel(f["--log"]);
  if (typeof f["--log-file"] === "string") out.logFile = f["--log-file"];
  if (typeof f["--log-format"] === "string") out.logFormat = logFormat(f["--log-format"]);
  return out;
}

/** What the program needs to run. */
export function checkComplete(c: Config): void {
  if (c.realm === "") throw new ConfigError("[realm].name gives the realm this controller serves");
  if (!REALM.test(c.realm)) throw new ConfigError(`[realm].name ${JSON.stringify(c.realm)} is labels of upper-case letters, digits and hyphens, separated by dots`);
  if (c.domain === "") throw new ConfigError("[realm].domain gives the realm's DNS domain");
  if (!DOMAIN.test(c.domain)) throw new ConfigError(`[realm].domain ${JSON.stringify(c.domain)} is a DNS domain in lower case`);
  if (c.tlsCert === "" || c.tlsKey === "") throw new ConfigError("[listen] gives the certificate and key the controller presents");
}
