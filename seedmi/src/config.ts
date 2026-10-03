// The configuration file. Everything a server needs to run is stated
// here or on the command line, and a setting given on the command line
// wins.
//
// Until KMIP is supported, this file also holds the material that a KMIP
// server would hold: certificates and their private keys, the
// credentials a remote import presents, and the keys with which access
// tokens are signed and verified. The draft is firm that no such
// material belongs in the "exports" field of an object, and it is not
// put there: an export entry names a certificate by an identifier, and
// the identifier is resolved here. When KMIP arrives only this lookup
// changes.

import { ETYPE, stringToKey } from "./krb-crypto.ts";
import { LOG_FORMATS, LOG_LEVELS, type LogFormat, type LogLevel } from "./log.ts";
import type { DomainControllerConfig } from "./domain-controller.ts";
import { PIPE_DEFAULTS, type PipePermit, type PipesConfig } from "./pipe.ts";
import type { HomeServerConfig, HomesConfig } from "./userinfo.ts";
import { regionFault } from "./service-level.ts";
import { withinRange } from "./originated.ts";
import { browseDomainFault, resolverFault } from "./doh.ts";
import { isIP } from "node:net";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { type TOMLValue, parseTOML } from "./toml.ts";
import { PRIVILEGES } from "./identity.ts";

export class ConfigError extends Error {}

export interface UserConfig {
  name: string;
  password: string;
  groups: string[];
  administrator: boolean;
  /** The privileges the draft defines that this principal holds. */
  privileges: string[];
}

export interface CertificateConfig {
  /** The identifier an export entry names, standing in for a KMIP one. */
  id: string;
  chain: string;
  key: string;
}


/**
 * An access key an S3 client signs with, and the principal it acts
 * as. The draft makes these available "by means outside the scope of
 * this document", and no field of an S3 export entry conveys them.
 */
/**
 * Delegated access control (dac.ts). The certificate names a [[certificate]]
 * whose key this server signs a request with and a response is encrypted to.
 */
export interface DacConfig {
  /**
   * The Names of the two keys of this server's identity, within the root
   * domain's scope at its default key management server, where each is
   * operated in place (dac-kms.ts). Before 0.50 both were private keys of
   * [[certificate]] entries, held here, which revision 245 forbids.
   */
  signingKeyId: string;
  encryptionKeyId: string;
  /** The certificate chain of each key, PEM, reported in its x5c member where given. */
  signingChain?: string;
  encryptionChain?: string;
  methods: string[];
  ca?: string;
  responseWindowMs?: number;
  /** Where a provider sends a response it does not return to the request. */
  responseUri?: string;
}

/**
 * A URI this server may make a request of its own to, and the addresses that
 * URI's authority may resolve to (originated.ts). Nothing is permitted until a
 * [[permit]] table says so: the draft requires a statement of the URIs
 * permitted and not of the URIs forbidden.
 */
export interface PermitConfig {
  uri: string;
  addresses: string[];
}

/** A key management server (kms.ts), by the label a domain's cdmi_domain_kms names it. */
export type KmsConfig =
  | { label: string; kind: "kmip"; host: string; port: number; servername?: string; ca: string; certificate: string;
    key: string; timeoutMs?: number };

export interface S3KeyConfig {
  accessKey: string;
  secret: string;
  /** The name of a configured principal. */
  user: string;
}

export interface OAuthConfig {
  /** The issuer whose access tokens this server accepts. */
  issuer?: string;
  /** The audience this server answers to in an access token. */
  audience?: string;
  /** Where a token is exchanged, as RFC 8693 defines. */
  tokenEndpoint?: string;
  /** The authority for the token endpoint's certificate, PEM. */
  tokenEndpointCa?: string;
  /** The key with which an incoming token is verified. */
  verifyKey?: string;
  /** The algorithm of that key: HS256, RS256 or ES256. */
  algorithm: string;
  /** The credential this server presents when it exchanges a token. */
  clientId?: string;
  /** The Name of the token service credential at the root domain's default key management server. */
  clientSecretId?: string;
  /** Whether to run an authorization server of this server's own. */
  server: boolean;
  /** Where that authorization server listens. */
  serverPort: number;
  /** The key it signs with, which is also the verify key by default. */
  signKey?: string;
  /**
   * The address that authorization server is reached at, which its RFC 8414
   * metadata reports as the issuer, the token endpoint and the JWK Set URI.
   * Where absent it is derived from the address it listens on, which is right
   * for a test on one host and wrong for anything a client reaches by another
   * name.
   */
  serverBaseUri?: string;
  /** The scopes that authorization server will issue. */
  serverScopes?: string[];
  /** The certificate that authorization server presents, by identifier. */
  serverCertificate?: string;
  /** The origins a browser-based client may present to it (cors.ts). */
  serverOrigins?: string[];
  /**
   * The clients registered with that authorization server, from
   * [[oauth_client]]. A client that presents credentials is authenticated
   * against this list where it is not empty; where it is empty, the
   * demonstration server accepts any client, which no deployment should do.
   */
  clients: { id: string; secret: string; scopes?: string[]; user?: string }[];
}

export interface Config {
  /** The domain controllers principals are resolved at, by domain (domain-controller.ts). */
  domainControllers: DomainControllerConfig[];
  /** Pipes: [pipes] and [[pipe_permit]] (pipe.ts, RELAY-draft-2.md). */
  pipes: PipesConfig;
  /**
   * [service_level]: the facts about this deployment that no measurement
   * reveals, which the provided data system metadata items report
   * (service-level.ts). The copies, the infrastructures and the distance between
   * them follow from the architecture, and the latency and the throughput are
   * measured when the server starts, so neither appears here.
   */
  serviceLevel?: { regions?: string[]; rpo?: string; rto?: string };

  /** [homes]: where the homes of a domain's principals are held (userinfo.ts). */
  homes?: HomesConfig;
  /** [home_server]: the homes this server holds (userinfo.ts). */
  homeServer?: HomeServerConfig;
  /** Privileges conferred on a group within a domain: a controller's groups, or this server's. */
  groupPrivileges: { domain: string; group: string; privileges: string[] }[];
  /**
   * The endpoint of the CDMI over MCP protocol binding, which is served on
   * a listener of its own: [mcp] host, port, uri, tls, scopes_required.
   */
  mcp?: {
    host: string; port: number; uri: string;
    certificate?: string; scopesRequired: boolean;
    /** The origins a browser-based client may present (mcp.ts). */
    origins?: string[];
    /** Whether the request metadata headers of the revision are required. */
    strictHeaders: boolean;
  };
  store: string;
  base: string;
  host: string;
  port: number;
  /** The HTTPS port of the protocol binding, where one is served. */
  tlsPort?: number;
  /** The certificate the protocol binding presents, by identifier. */
  tlsCertificate?: string;
  exportOrigins: string[];
  exportScheme: string;
  rootExport?: string;
  rootExportPath: string;
  /** What is logged: nothing, the problems, or every request. */
  /** Whether an MQTT export connects to the broker its entry names. */
  mqtt: { enabled: boolean };
  logLevel: LogLevel;
  logFormat: LogFormat;
  /** Where the log is written, or stderr where none is named. */
  logFile?: string;
  users: UserConfig[];
  certificates: CertificateConfig[];
  /** The Name of the service credential at the root domain's default key management server. */
  serviceCredential?: string;
  oauth: OAuthConfig;
  /**
   * The NFS server. `mapCredentials` makes an `AUTH_SYS` credential name a principal
   * rather than every request being anonymous; it is resolved at the one configured
   * domain controller where there is one, by `uidNumber` and `gidNumber`, and the
   * synthesised `uid@domain` is what a deployment with no controller gets.
   *
   * There was **no key for this at all** before: `NfsServer` has taken a
   * `mapCredentials` option since it was written and nothing outside the tests ever set
   * it, so a deployment's NFS was anonymous whatever its exports said, and the code
   * behind the option — including an `administrator: sys.uid === 0` that would have made
   * an unauthenticated assertion of uid 0 an administrator — was unreachable. An option
   * no configuration can turn on is a trap waiting for the day someone adds the key.
   */
  nfs: { enabled: boolean; port: number; host: string; mapCredentials: boolean };
  /** The SMB server, which serves the shares of SMB export entries. */
  smb: { enabled: boolean; port: number; host: string };
  s3Keys: S3KeyConfig[];
  kms: KmsConfig[];
  permit: PermitConfig[];
  dac?: DacConfig;
  originated: { maxRedirects: number; maxResponseBytes: number; timeoutMs: number };
  /** The base URIs of this server, for classifying an import URI. */
  selfBases: string[];
  /**
   * Whether to serve the discovery tree at "/.well-known/cdmi/". A
   * server serves it only where it controls the origin, which it
   * cannot determine for itself, so it is stated here.
   */
  wellKnown: boolean;
  /** The origins a browser-based client may present to the discovery tree. */
  wellKnownOrigins?: string[];
  /**
   * Whether the cdmi_representations capability and item are offered
   * (binding.ts). Off by default: this server holds one representation of a
   * value, so the item always had one member and told a CDMI client nothing
   * "mimetype" did not already.
   */
  valueRepresentations: boolean;
  /** The name of the namespace this server offers in that tree. */
  namespaceName: string;
  /**
   * Service discovery: the cdmi_domain_doh domain metadata item, which hands a
   * client the DoH resolver to begin DNS-SD discovery at, and the browsing
   * domains to search (ECR-224A). Off by default — the item is a proposed
   * addition and not one revision 365 defines, so a stock deployment refuses
   * it as it refuses any other cdmi_ name the document does not give.
   *
   * seedmi speaks no DNS itself. The records the item leads a client to are
   * published by seedmi-mdns, which advertises this server on the local link,
   * and by seedmi-zone, which puts what it hears there into a real zone.
   */
  discovery: {
    /** Whether the item and its capability are offered at all. */
    doh: boolean;
    /** Written onto the root domain object at startup where it carries none. */
    resolver?: string;
    /** Likewise, the browsing domains a client is to search. */
    browseDomains?: string[];
  };
}

const DEFAULTS: Config = {
  store: "./data",
  base: "/cdmi/3.0.0/",
  host: "127.0.0.1",
  port: 8080,
  exportOrigins: [],
  exportScheme: "http",
  rootExportPath: "/",
  mqtt: { enabled: false },
  logLevel: "off",
  logFormat: "text",
  users: [],
  certificates: [],
  oauth: { algorithm: "HS256", server: false, serverPort: 0, clients: [] },
  nfs: { enabled: false, port: 2049, host: "127.0.0.1", mapCredentials: false },
  smb: { enabled: false, port: 445, host: "127.0.0.1" },
  s3Keys: [],
  kms: [],
  permit: [],
  originated: { maxRedirects: 0, maxResponseBytes: 16 * 1024 * 1024, timeoutMs: 5000 },
  selfBases: [],
  domainControllers: [],
  pipes: { ...PIPE_DEFAULTS, permits: [] },
  groupPrivileges: [],
  wellKnown: false,
  valueRepresentations: true,
  namespaceName: "default",
  discovery: { doh: false },
};

/** A reader that names the setting in every complaint it makes. */
class Reader {
  private readonly dir: string;
  constructor(dir: string) {
    this.dir = dir;
  }

  table(v: TOMLValue | undefined, where: string): Record<string, TOMLValue> {
    if (v === undefined) return {};
    if (typeof v !== "object" || Array.isArray(v)) {
      throw new ConfigError(`${where} shall be a table`);
    }
    return v as Record<string, TOMLValue>;
  }

  tables(v: TOMLValue | undefined, where: string): Record<string, TOMLValue>[] {
    if (v === undefined) return [];
    if (!Array.isArray(v)) throw new ConfigError(`${where} shall be an array of tables`);
    return v.map((e, i) => this.table(e, `${where}[${i}]`));
  }

  str(t: Record<string, TOMLValue>, key: string, where: string): string | undefined {
    const v = t[key];
    if (v === undefined) return undefined;
    if (typeof v !== "string") throw new ConfigError(`${where}.${key} shall be a string`);
    return v;
  }

  need(t: Record<string, TOMLValue>, key: string, where: string): string {
    const v = this.str(t, key, where);
    if (v === undefined) throw new ConfigError(`${where}.${key} is required`);
    return v;
  }

  int(t: Record<string, TOMLValue>, key: string, where: string): number | undefined {
    const v = t[key];
    if (v === undefined) return undefined;
    if (typeof v !== "number" || !Number.isInteger(v)) {
      throw new ConfigError(`${where}.${key} shall be an integer`);
    }
    return v;
  }

  bool(t: Record<string, TOMLValue>, key: string, where: string): boolean | undefined {
    const v = t[key];
    if (v === undefined) return undefined;
    if (typeof v !== "boolean") throw new ConfigError(`${where}.${key} shall be true or false`);
    return v;
  }

  strings(t: Record<string, TOMLValue>, key: string, where: string): string[] | undefined {
    const v = t[key];
    if (v === undefined) return undefined;
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
      throw new ConfigError(`${where}.${key} shall be an array of strings`);
    }
    return v as string[];
  }

  /**
   * A value given either inline or in a file beside the configuration.
   * A key in a file is the ordinary arrangement; a key inline suits a
   * test and a container that has one file to mount.
   */
  material(t: Record<string, TOMLValue>, key: string, where: string): string | undefined {
    const inline = this.str(t, key, where);
    const file = this.str(t, `${key}_file`, where);
    if (inline !== undefined && file !== undefined) {
      throw new ConfigError(`${where} gives both ${key} and ${key}_file`);
    }
    if (inline !== undefined) return inline;
    if (file === undefined) return undefined;
    const at = path.isAbsolute(file) ? file : path.join(this.dir, file);
    try {
      return readFileSync(at, "utf8");
    } catch (err) {
      throw new ConfigError(`${where}.${key}_file: ${String(err)}`);
    }
  }

  /** Refuses a key the reader does not know, rather than ignoring it. */
  only(t: Record<string, TOMLValue>, where: string, keys: string[]): void {
    for (const k of Object.keys(t)) {
      if (!keys.includes(k)) {
        throw new ConfigError(
          `${where}.${k} is not a setting this server knows; the settings of ${where} are ` +
          keys.join(", "));
      }
    }
  }
}

/** Reads a configuration file. */
export function readConfig(file: string): Config {
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch (err) {
    throw new ConfigError(`the configuration file could not be read: ${String(err)}`);
  }
  return parseConfig(text, path.dirname(path.resolve(file)));
}

export function parseConfig(text: string, dir = "."): Config {
  const doc = parseTOML(text);
  const r = new Reader(dir);
  const c: Config = {
    ...DEFAULTS,
    users: [],
    certificates: [],
    oauth: { ...DEFAULTS.oauth, clients: [] },
    nfs: { ...DEFAULTS.nfs },
    smb: { ...DEFAULTS.smb },
    s3Keys: [],
    kms: [],
    permit: [],
    originated: { ...DEFAULTS.originated },
    exportOrigins: [],
    selfBases: [],
    domainControllers: [],
    discovery: { ...DEFAULTS.discovery },
  pipes: { ...PIPE_DEFAULTS, permits: [] },
    groupPrivileges: [],
  };

  r.only(doc, "the configuration", [
    "store", "base", "http", "https", "export", "user", "certificate",
    "remote_credential", "imports", "oauth", "oauth_client",
    "nfs", "smb", "s3_key", "kms", "permit", "originated", "dac",
    "domain_controller", "group_privileges", "pipes", "pipe_permit", "homes", "home_server",
    "self_base", "well_known", "well_known_origins", "value_representations", "mcp",
    "namespace_name", "discovery", "service_level",
  ]);
  c.store = r.str(doc, "store", "the configuration") ?? c.store;
  c.base = r.str(doc, "base", "the configuration") ?? c.base;
  c.selfBases = r.strings(doc, "self_base", "the configuration") ?? [];
  c.wellKnown = (() => {
    const v = doc.well_known;
    if (v === undefined) return false;
    if (typeof v !== "boolean") {
      throw new ConfigError("well_known shall be true or false");
    }
    return v;
  })();
  // The origins a browser-based client may present to the discovery tree. It is
  // a property of the origin and not of an object, so the three data system
  // metadata items cannot configure it: there is no object to set them on. The
  // default is the wildcard, this tree being what "a CDMI client that knows
  // only an origin" reads and being served without authentication.
  c.wellKnownOrigins = r.strings(doc, "well_known_origins", "the configuration");
  for (const origin of c.wellKnownOrigins ?? []) {
    if (origin === "*") continue;
    try {
      if (new URL(origin).origin !== origin) throw new Error("not an origin");
    } catch {
      throw new ConfigError(`well_known_origins holds ${JSON.stringify(origin)}, which is not an origin: an ` +
        'origin is a scheme, a host and a port, as "https://app.example.com", with no path. "*" answers any.');
    }
  }
  if (c.wellKnownOrigins !== undefined && !c.wellKnown) {
    throw new ConfigError("well_known_origins states who may read the discovery tree, which well_known does not serve");
  }
  // What this deployment provides for the service-level items of Annex D that
  // are neither architectural nor measurable: where it stores objects, and the
  // recovery objectives of whatever backup arrangement stands behind it. Each
  // provided item is reported only where the corresponding value is configured,
  // a CDMI server not reporting a provided item "where it cannot" determine what
  // it achieves.
  {
    const sl = r.table(doc.service_level, "[service_level]");
    r.only(sl, "[service_level]", ["regions", "rpo", "rto"]);
    const level: { regions?: string[]; rpo?: string; rto?: string } = {};
    const regions = r.strings(sl, "regions", "[service_level]");
    if (regions !== undefined) {
      if (regions.length === 0) {
        throw new ConfigError("[service_level].regions is a non-empty list of ISO 3166 codes");
      }
      for (const code of regions) {
        const fault = regionFault(code);
        if (fault !== undefined) throw new ConfigError(`[service_level].regions: ${fault}`);
      }
      level.regions = regions;
    }
    for (const [key, set] of [["rpo", (v: string) => { level.rpo = v; }],
      ["rto", (v: string) => { level.rto = v; }]] as const) {
      const v = r.str(sl, key, "[service_level]");
      if (v === undefined) continue;
      if (!/^[1-9][0-9]*$/.test(v)) {
        throw new ConfigError(`[service_level].${key} is a duration in seconds, as a positive number`);
      }
      set(v);
    }
    if (Object.keys(level).length > 0) c.serviceLevel = level;
  }
  // Service discovery (ECR-224A). The item is refused unless doh is set, so a
  // deployment that says nothing here behaves as one that has never heard of
  // it — which is what a conformance suite reads, the item being a proposed
  // addition and not a name revision 365 defines.
  {
    const d = r.table(doc.discovery, "[discovery]");
    r.only(d, "[discovery]", ["doh", "resolver", "browse_domains"]);
    c.discovery = { doh: r.bool(d, "doh", "[discovery]") ?? false };
    const resolver = r.str(d, "resolver", "[discovery]");
    if (resolver !== undefined) {
      const fault = resolverFault(resolver);
      if (fault !== undefined) throw new ConfigError(`[discovery].resolver: ${fault}`);
      c.discovery.resolver = resolver;
    }
    const browse = r.strings(d, "browse_domains", "[discovery]");
    if (browse !== undefined) {
      if (browse.length === 0) throw new ConfigError("[discovery].browse_domains is a non-empty list of DNS names");
      for (const name of browse) {
        const fault = browseDomainFault(name);
        if (fault !== undefined) throw new ConfigError(`[discovery].browse_domains: ${fault}`);
      }
      c.discovery.browseDomains = browse;
    }
    // The resolver is the one member the item requires, so browsing domains
    // without one would publish an item this server then refuses to store.
    if (browse !== undefined && resolver === undefined) {
      throw new ConfigError("[discovery] gives browse_domains and no resolver, which cdmi_domain_doh requires");
    }
    // A resolver named while the item is refused would be written onto the root
    // domain object and then rejected by the check that stores it, which is a
    // configuration that cannot do what it says.
    if (!c.discovery.doh && (resolver !== undefined || browse !== undefined)) {
      throw new ConfigError("[discovery] gives a resolver or browsing domains, and doh does not accept the " +
        "cdmi_domain_doh item that would carry them");
    }
  }
  // On by default since 0.96: a data object whose value is a JPEG has a PNG
  // representation and the reverse, derived when it is read. A deployment that
  // does not want the transcoding sets this to false.
  c.valueRepresentations = r.bool(doc, "value_representations", "the configuration") ?? true;
  c.namespaceName = r.str(doc, "namespace_name", "the configuration")
    ?? c.namespaceName;

  const http = r.table(doc.http, "[http]");
  r.only(http, "[http]", ["host", "port"]);
  c.host = r.str(http, "host", "[http]") ?? c.host;
  c.port = r.int(http, "port", "[http]") ?? c.port;

  const https = r.table(doc.https, "[https]");
  r.only(https, "[https]", ["port", "certificate"]);
  c.tlsPort = r.int(https, "port", "[https]");
  c.tlsCertificate = r.str(https, "certificate", "[https]");
  if (c.tlsPort !== undefined && c.tlsCertificate === undefined) {
    throw new ConfigError("[https] gives a port and no certificate");
  }

  const ex = r.table(doc.export, "[export]");
  r.only(ex, "[export]", ["origins", "scheme", "root_name", "root_path"]);
  c.exportOrigins = r.strings(ex, "origins", "[export]") ?? [];
  c.exportScheme = r.str(ex, "scheme", "[export]") ?? c.exportScheme;
  c.rootExport = r.str(ex, "root_name", "[export]");
  c.rootExportPath = r.str(ex, "root_path", "[export]") ?? c.rootExportPath;

  for (const [i, u] of r.tables(doc.user, "[[user]]").entries()) {
    const where = `[[user]][${i}]`;
    r.only(u, where, ["name", "password", "groups", "administrator", "privileges"]);
    // The privileges the draft defines, conferred by naming them: without this
    // a configured principal could hold none of them, and an operation that
    // needs one (cdmi_domain_kms needs domain_kms_admin) could be performed by
    // no one the configuration describes.
    const privileges = r.strings(u, "privileges", where) ?? [];
    for (const p of privileges) {
      if (!PRIVILEGES.includes(p)) {
        throw new ConfigError(`${where}.privileges names ${JSON.stringify(p)}, which is not a privilege; ` +
          `the privileges are ${PRIVILEGES.join(", ")}`);
      }
    }
    c.users.push({
      name: r.need(u, "name", where),
      password: r.need(u, "password", where),
      groups: r.strings(u, "groups", where) ?? [],
      administrator: r.bool(u, "administrator", where) ?? false,
      privileges,
    });
  }
  const names = new Set<string>();
  for (const u of c.users) {
    if (names.has(u.name)) throw new ConfigError(`the user ${u.name} is given twice`);
    names.add(u.name);
  }

  for (const [i, t] of r.tables(doc.certificate, "[[certificate]]").entries()) {
    const where = `[[certificate]][${i}]`;
    r.only(t, where, ["id", "chain", "chain_file", "key", "key_file"]);
    const chain = r.material(t, "chain", where);
    const key = r.material(t, "key", where);
    if (chain === undefined) throw new ConfigError(`${where} gives no chain`);
    if (key === undefined) throw new ConfigError(`${where} gives no key`);
    if (!chain.includes("BEGIN CERTIFICATE")) {
      throw new ConfigError(`${where}: the chain is not a PEM certificate`);
    }
    if (!/BEGIN (RSA |EC )?PRIVATE KEY/.test(key)) {
      throw new ConfigError(`${where}: the key is not a PEM private key`);
    }
    c.certificates.push({ id: r.need(t, "id", where), chain, key });
  }
  const ids = new Set<string>();
  for (const cert of c.certificates) {
    if (ids.has(cert.id)) {
      throw new ConfigError(`the certificate ${cert.id} is given twice`);
    }
    ids.add(cert.id);
  }
  if (c.tlsCertificate !== undefined && !ids.has(c.tlsCertificate)) {
    throw new ConfigError(
      `[https] names the certificate ${JSON.stringify(c.tlsCertificate)}, which is not configured`);
  }

  // The service credential of this CDMI server: what a remote import in
  // service identity mode presents where its entry names no credential_id.
  // It is the Name of a credential at the root domain's default key
  // management server, and never the secret: "a CDMI server shall not hold
  // such a secret by any other means" (revision 245). [[remote_credential]],
  // which held the secret itself, was removed in 0.46.
  if (doc.remote_credential !== undefined) {
    throw new ConfigError("[[remote_credential]] is not a setting of this server since 0.46: a credential it " +
      "presents is held at a key management server, named by a credential reference; an import entry names " +
      "one by credential_id, and [imports] service_credential names the server's own");
  }
  const imp = r.table(doc.imports, "[imports]");
  if (imp !== undefined) {
    r.only(imp, "[imports]", ["service_credential"]);
    const name = r.str(imp, "service_credential", "[imports]");
    if (name !== undefined) {
      if (name === "" || name.includes("/")) {
        throw new ConfigError("[imports].service_credential is the name of a credential within the root domain's " +
          "scope, which is not empty and holds no /");
      }
      c.serviceCredential = name;
    }
  }

  const o = r.table(doc.oauth, "[oauth]");
  r.only(o, "[oauth]", [
    "issuer", "audience", "token_endpoint", "algorithm", "verify_key", "verify_key_file",
    "client_id", "client_secret", "client_secret_id", "server", "server_port", "sign_key", "sign_key_file",
    "token_endpoint_ca", "token_endpoint_ca_file", "server_base_uri", "server_scopes",
    "server_certificate", "server_origins",
  ]);
  c.oauth.issuer = r.str(o, "issuer", "[oauth]");
  c.oauth.audience = r.str(o, "audience", "[oauth]");
  c.oauth.tokenEndpoint = r.str(o, "token_endpoint", "[oauth]");
  // The authority for the token endpoint's certificate, where the system does not trust it.
  c.oauth.tokenEndpointCa = r.material(o, "token_endpoint_ca", "[oauth]");
  c.oauth.server = r.bool(o, "server", "[oauth]") ?? false;
  c.oauth.serverPort = r.int(o, "server_port", "[oauth]") ?? 0;
  const stated = r.str(o, "algorithm", "[oauth]");
  if (stated !== undefined && !["HS256", "RS256", "ES256"].includes(stated)) {
    throw new ConfigError("[oauth].algorithm shall be HS256, RS256 or ES256");
  }
  c.oauth.verifyKey = r.material(o, "verify_key", "[oauth]");
  c.oauth.signKey = r.material(o, "sign_key", "[oauth]");
  // Where the algorithm is not stated it follows the key. A PEM key is
  // asymmetric and RS256 is the algorithm of an RSA one; a key given as
  // characters is a shared secret and HS256 is the only thing it can be. An
  // asymmetric key is also the only kind whose public half can be published as
  // a JWK Set, which is how the built-in authorization server's tokens are
  // verified, so [oauth].server with no key at all generates a pair and is
  // RS256 too. An HS256 default there would have been a default no relying
  // party in this deployment could use.
  const pem = (k: string | undefined) => k !== undefined && k.includes("-----BEGIN");
  c.oauth.algorithm = stated ??
    (pem(c.oauth.signKey) || pem(c.oauth.verifyKey) ||
      (c.oauth.server && c.oauth.signKey === undefined) ? "RS256" : "HS256");
  c.oauth.clientId = r.str(o, "client_id", "[oauth]");
  // The credential with which this server authenticates to the security
  // token service is one of its own, named here and held at the root domain's
  // default key management server; the secret itself is never held here.
  if (o.client_secret !== undefined) {
    throw new ConfigError("[oauth].client_secret is not a setting of this server since 0.49: the credential it " +
      "presents to the token service is held at a key management server; [oauth].client_secret_id names it");
  }
  const secretName = r.str(o, "client_secret_id", "[oauth]");
  if (secretName !== undefined && (secretName === "" || secretName.includes("/"))) {
    throw new ConfigError("[oauth].client_secret_id is the name of a credential within the root domain's scope, " +
      "which is not empty and holds no /");
  }
  c.oauth.clientSecretId = secretName;
  // [oauth].server no longer requires a sign_key: where none is given the
  // authorization server generates a key pair at startup and publishes its
  // public half as a JWK Set, which is what a client that verifies by
  // discovery needs and what nothing here could supply while the only key was
  // a shared secret.
  if (c.oauth.server && c.oauth.signKey !== undefined && c.oauth.algorithm === "HS256") {
    throw new ConfigError("[oauth].server with an HS256 sign_key cannot publish a JWK Set, so no client that " +
      "verifies by discovery can accept its tokens; give a PEM private key, or none, and let it generate one");
  }
  c.oauth.serverCertificate = r.str(o, "server_certificate", "[oauth]");
  if (c.oauth.serverCertificate !== undefined) {
    if (!c.certificates.some((x) => x.id === c.oauth.serverCertificate)) {
      throw new ConfigError(
        `[oauth].server_certificate names the certificate ${JSON.stringify(c.oauth.serverCertificate)}, ` +
        "which is not configured");
    }
    if (!c.oauth.server) {
      throw new ConfigError("[oauth].server_certificate is the certificate the authorization server of this " +
        "server's own presents, which [oauth].server does not start");
    }
  }
  c.oauth.serverBaseUri = r.str(o, "server_base_uri", "[oauth]");
  if (c.oauth.serverBaseUri !== undefined) {
    if (!/^https?:\/\//.test(c.oauth.serverBaseUri)) {
      throw new ConfigError("[oauth].server_base_uri shall be an http or https URI");
    }
    c.oauth.serverBaseUri = c.oauth.serverBaseUri.replace(/\/+$/, "");
    // The scheme is what a client reaches the server by, so it shall be the
    // scheme the server serves: a base URI saying https where the server
    // presents no certificate sends every client to a port that will not
    // complete a handshake, and one saying http where it does presents a
    // metadata document no client following RFC 8414 will accept.
    const wanted = c.oauth.serverCertificate === undefined ? "http" : "https";
    if (!c.oauth.serverBaseUri.startsWith(`${wanted}://`)) {
      throw new ConfigError(`[oauth].server_base_uri shall be a ${wanted} URI, because ` +
        (c.oauth.serverCertificate === undefined
          ? "[oauth].server_certificate names no certificate for that server to present"
          : `[oauth].server_certificate names ${JSON.stringify(c.oauth.serverCertificate)}, ` +
            "which it presents"));
    }
  }
  // The origins a browser-based client may present to that server. Everything
  // it serves is fetched cross-origin by such a client, the server being on a
  // listener of its own; the default is the wildcard, its metadata and JWK Set
  // being public documents and its token endpoint being guarded by a client
  // credential rather than by who may read the answer.
  c.oauth.serverOrigins = r.strings(o, "server_origins", "[oauth]");
  for (const origin of c.oauth.serverOrigins ?? []) {
    if (origin === "*") continue;
    try {
      if (new URL(origin).origin !== origin) throw new Error("not an origin");
    } catch {
      throw new ConfigError(`[oauth].server_origins holds ${JSON.stringify(origin)}, which is not an origin: an ` +
        'origin is a scheme, a host and a port, as "https://app.example.com", with no path. "*" answers any.');
    }
  }
  c.oauth.serverScopes = r.strings(o, "server_scopes", "[oauth]");
  if (c.oauth.serverScopes !== undefined) {
    // RFC 6749 section 3.3: a scope is a space-delimited list of tokens, and a
    // token holds no space. One written with a comma is one invalid token, and
    // is refused here rather than at the client that cannot use it.
    for (const s of c.oauth.serverScopes) {
      if (s === "" || /[\s,"\\]/.test(s)) {
        throw new ConfigError(`[oauth].server_scopes holds ${JSON.stringify(s)}, which is not a scope token of ` +
          "RFC 6749 section 3.3: a token is not empty and holds no space, comma, quotation mark or reverse solidus");
      }
    }
  }
  if (c.oauth.verifyKey === undefined && c.oauth.signKey !== undefined) {
    // A server that issues its own tokens verifies them with the same
    // key, where the algorithm is symmetric.
    if (c.oauth.algorithm === "HS256") c.oauth.verifyKey = c.oauth.signKey;
  }

  // [[oauth_client]]: the clients registered with the built-in authorization
  // server. An MCP client is given one of these as its "Resource AS Client ID"
  // and secret, and presents them at the token endpoint.
  for (const t of r.tables(doc.oauth_client, "[[oauth_client]]")) {
    r.only(t, "[[oauth_client]]", ["id", "secret", "scopes", "user"]);
    const id = r.need(t, "id", "[[oauth_client]]");
    if (c.oauth.clients.some((x) => x.id === id)) {
      throw new ConfigError(`[[oauth_client]] gives the identifier ${id} twice`);
    }
    const scopes = r.strings(t, "scopes", "[[oauth_client]]");
    // The principal a token issued to this client names, as [[s3_key]].user
    // names the principal an access key acts as. It shall be a configured one:
    // a token naming a principal this server cannot resolve is one every
    // object refuses, and saying so here is better than at the first call.
    const user = r.str(t, "user", "[[oauth_client]]");
    if (user !== undefined && !c.users.some((u) => u.name.toLowerCase() === user.toLowerCase())) {
      throw new ConfigError(`[[oauth_client]] ${id} acts as ${JSON.stringify(user)}, which is not a [[user]]`);
    }
    c.oauth.clients.push({
      id,
      secret: r.need(t, "secret", "[[oauth_client]]"),
      ...(scopes === undefined ? {} : { scopes }),
      ...(user === undefined ? {} : { user }),
    });
  }
  if (c.oauth.clients.length > 0 && !c.oauth.server) {
    throw new ConfigError("[[oauth_client]] registers a client with the authorization server of this server's own, " +
      "which [oauth].server does not start");
  }

  const nfs = r.table(doc.nfs, "[nfs]");
  r.only(nfs, "[nfs]", ["enabled", "port", "host", "map_credentials"]);
  c.nfs.enabled = r.bool(nfs, "enabled", "[nfs]") ?? false;
  c.nfs.port = r.int(nfs, "port", "[nfs]") ?? c.nfs.port;
  c.nfs.host = r.str(nfs, "host", "[nfs]") ?? c.nfs.host;
  c.nfs.mapCredentials = r.bool(nfs, "map_credentials", "[nfs]") ?? false;

  const smb = r.table(doc.smb, "[smb]");
  r.only(smb, "[smb]", ["enabled", "port", "host"]);
  c.smb.enabled = r.bool(smb, "enabled", "[smb]") ?? false;
  c.smb.port = r.int(smb, "port", "[smb]") ?? c.smb.port;
  c.smb.host = r.str(smb, "host", "[smb]") ?? c.smb.host;

  for (const [i, t] of r.tables(doc.s3_key, "[[s3_key]]").entries()) {
    const where = `[[s3_key]][${i}]`;
    r.only(t, where, ["access_key", "secret", "secret_file", "user"]);
    const accessKey = r.need(t, "access_key", where);
    if (accessKey === "") throw new ConfigError(`${where}.access_key is empty`);
    const secret = r.material(t, "secret", where);
    if (secret === undefined || secret.trim() === "") {
      throw new ConfigError(`${where} gives no secret`);
    }
    c.s3Keys.push({ accessKey, secret: secret.trim(), user: r.need(t, "user", where) });
  }
  for (const [i, t] of r.tables(doc.kms, "[[kms]]").entries()) {
    const where = `[[kms]][${i}]`;
    const label = r.need(t, "label", where);
    if (label === "") throw new ConfigError(`${where}.label is empty`);
    const kind = r.need(t, "kind", where);
    if (kind === "kmip") {
      r.only(t, where, ["label", "kind", "host", "port", "servername", "ca", "ca_file", "certificate",
        "certificate_file", "key", "key_file", "timeout_ms"]);
      const pem = (key: string) => {
        const v = r.material(t, key, where);
        if (v === undefined || v.trim() === "") throw new ConfigError(`${where} gives no ${key}`);
        return v;
      };
      const servername = r.str(t, "servername", where);
      const timeoutMs = r.int(t, "timeout_ms", where);
      c.kms.push({
        label, kind, host: r.need(t, "host", where), port: r.int(t, "port", where) ?? 5696,
        ca: pem("ca"), certificate: pem("certificate"), key: pem("key"),
        ...(servername === undefined ? {} : { servername }), ...(timeoutMs === undefined ? {} : { timeoutMs }),
      });
    } else {
      throw new ConfigError(`${where}.kind is ${JSON.stringify(kind)}; it is "kmip"`);
    }
  }
  // [homes] (revision 282, cdmi_domain_userinfo): where the homes of a domain's
  // principals are held, which this server reports to each of them.
  {
    const t = r.table(doc.homes, "[homes]");
    if (Object.keys(t).length > 0) {
      r.only(t, "[homes]", ["domain", "base", "path"]);
      const domain = r.need(t, "domain", "[homes]");
      if (!domain.startsWith("/cdmi_domains/") || !domain.endsWith("/")) {
        throw new ConfigError("[homes].domain is the namespace path of a domain object, as /cdmi_domains/eu/");
      }
      const base = r.need(t, "base", "[homes]");
      let u: URL | undefined;
      try { u = new URL(base); } catch { u = undefined; }
      if (u === undefined || (u.protocol !== "https:" && u.protocol !== "http:") || !base.endsWith("/")) {
        throw new ConfigError("[homes].base is the base URI of the server holding the homes, ending with /");
      }
      const path = r.str(t, "path", "[homes]") ?? "/home/{identifier}/";
      if (!path.startsWith("/") || !path.endsWith("/") || !path.includes("{identifier}")) {
        throw new ConfigError("[homes].path is a namespace path holding {identifier}, as /home/{identifier}/");
      }
      c.homes = { domain, base, path };
    }
  }
  // [home_server]: the homes this server holds, and makes on first request.
  {
    const t = r.table(doc.home_server, "[home_server]");
    if (Object.keys(t).length > 0) {
      r.only(t, "[home_server]", ["container", "domain", "provision"]);
      const container = r.str(t, "container", "[home_server]") ?? "/home/";
      if (!container.startsWith("/") || !container.endsWith("/")) {
        throw new ConfigError("[home_server].container is a namespace path of a container, as /home/");
      }
      const domain = r.need(t, "domain", "[home_server]");
      if (!domain.startsWith("/cdmi_domains/") || !domain.endsWith("/")) {
        throw new ConfigError("[home_server].domain is the namespace path of a domain object, as /cdmi_domains/eu/");
      }
      c.homeServer = { container, domain, provision: r.bool(t, "provision", "[home_server]") ?? true };
    }
  }
  // [pipes] and [[pipe_permit]] (RELAY-draft-2.md section 4): the destinations
  // a pipe may reach, as an allow-list of names, ports and address ranges.
  {
    const t = r.table(doc.pipes, "[pipes]");
    r.only(t, "[pipes]", ["enabled", "allow_anonymous", "ticket_ttl", "connect_timeout", "idle_timeout", "max_lifetime",
      "max_connections", "max_connections_per_pipe", "max_connections_total", "max_frame"]);
    const n = (k: string, dflt: number, max = Number.MAX_SAFE_INTEGER) => {
      const v = r.int(t, k, "[pipes]");
      if (v === undefined) return dflt;
      if (v < 1 || v > max) throw new ConfigError(`[pipes].${k} is a whole number from 1 to ${max}`);
      return v;
    };
    c.pipes = {
      enabled: r.bool(t, "enabled", "[pipes]") ?? false,
      allowAnonymous: r.bool(t, "allow_anonymous", "[pipes]") ?? false,
      ticketTtl: n("ticket_ttl", PIPE_DEFAULTS.ticketTtl, 300),
      connectTimeout: n("connect_timeout", PIPE_DEFAULTS.connectTimeout),
      idleTimeout: n("idle_timeout", PIPE_DEFAULTS.idleTimeout),
      maxLifetime: n("max_lifetime", PIPE_DEFAULTS.maxLifetime),
      maxConnections: n("max_connections", PIPE_DEFAULTS.maxConnections),
      maxConnectionsPerPipe: n("max_connections_per_pipe", PIPE_DEFAULTS.maxConnectionsPerPipe),
      maxConnectionsTotal: n("max_connections_total", PIPE_DEFAULTS.maxConnectionsTotal),
      maxFrame: n("max_frame", PIPE_DEFAULTS.maxFrame),
      permits: [],
    };
    const strings = (p: Record<string, TOMLValue>, k: string, where: string): string[] | undefined => {
      const v = p[k];
      if (v === undefined) return undefined;
      if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) throw new ConfigError(`${where}.${k} is an array of strings`);
      return v as string[];
    };
    for (const [i, p] of r.tables(doc.pipe_permit, "[[pipe_permit]]").entries()) {
      const where = `[[pipe_permit]][${i}]`;
      r.only(p, where, ["name", "hosts", "ports", "addresses", "principals", "groups", "domains"]);
      const name = r.need(p, "name", where);
      const hosts = strings(p, "hosts", where) ?? [];
      if (hosts.length === 0) throw new ConfigError(`${where} gives the host names it permits`);
      for (const h of hosts) {
        // Names, not addresses; a wildcard is the leftmost label alone.
        if (isIP(h) !== 0) throw new ConfigError(`${where}.hosts holds the address ${h}; a permit names hosts, and gives addresses as ranges`);
        if (!/^(\*\.)?[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$/.test(h)) {
          throw new ConfigError(`${where}.hosts holds ${JSON.stringify(h)}, which is not a DNS name, nor one with a wildcard as its leftmost label`);
        }
      }
      // The ports permitted: an array of port numbers, or "*" for any port,
      // which may be written as the string or as an array holding it alone. A
      // wildcard was refused until 0.86 — "there is no wildcard" — which left a
      // deployment whose destinations answer on ports it cannot enumerate with
      // no usable permit. What confines a destination is the host names and the
      // address ranges, both of which remain required and non-empty.
      const ports = typeof p.ports === "string" ? [p.ports] : p.ports;
      const anyPort = Array.isArray(ports) && ports.length === 1 && ports[0] === "*";
      if (!anyPort && (!Array.isArray(ports) || ports.length === 0 ||
          ports.some((x) => typeof x !== "number" || !Number.isInteger(x) || x < 1 || x > 65535))) {
        throw new ConfigError(`${where}.ports is an array of port numbers, or "*" for any port`);
      }
      const addresses = strings(p, "addresses", where) ?? [];
      if (addresses.length === 0) throw new ConfigError(`${where} gives the address ranges every resolved address must be within`);
      for (const a of addresses) {
        if (!withinRange(a.split("/")[0], a)) throw new ConfigError(`${where}.addresses holds ${JSON.stringify(a)}, which is not an address range`);
      }
      const principals = strings(p, "principals", where), groups = strings(p, "groups", where), domains = strings(p, "domains", where);
      for (const d of domains ?? []) {
        if (!d.startsWith("/cdmi_domains/") || !d.endsWith("/")) throw new ConfigError(`${where}.domains holds ${d}, which is not a domain's path`);
      }
      const permit: PipePermit = { name, hosts, ports: anyPort ? "*" : ports as number[], addresses,
        ...(principals === undefined ? {} : { principals }), ...(groups === undefined ? {} : { groups }),
        ...(domains === undefined ? {} : { domains }) };
      c.pipes.permits.push(permit);
    }
  }
  // [[domain_controller]]: a domain, and those beneath it unless they name their
  // own, whose principals are resolved at a domain controller.
  for (const [i, t] of r.tables(doc.domain_controller, "[[domain_controller]]").entries()) {
    const where = `[[domain_controller]][${i}]`;
    r.only(t, where, ["domain", "realm", "ldap", "base", "ca", "ca_file", "issuer", "audience", "cache_seconds", "timeout_ms",
      "service_principal", "service_password", "search_dn", "search_password",
      // What the directory of a domain would say, for a domain whose
      // principals this server resolves from its own configuration.
      "kdcs", "home_base", "userinfo_attributes"]);
    const domain = r.need(t, "domain", where);
    if (!domain.startsWith("/cdmi_domains/") || !domain.endsWith("/")) {
      throw new ConfigError(`${where}.domain is the namespace path of a domain object, as /cdmi_domains/eu/`);
    }
    if (c.domainControllers.some((d) => d.domain === domain)) throw new ConfigError(`${where}: the domain ${domain} is given a controller twice`);
    const realm = r.need(t, "realm", where);
    if (!/^[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?)*$/.test(realm)) {
      throw new ConfigError(`${where}.realm is a realm's name in upper case, as EU.EXAMPLE`);
    }
    const ldap = r.need(t, "ldap", where);
    let ldapUrl: URL;
    try { ldapUrl = new URL(ldap); } catch { throw new ConfigError(`${where}.ldap is an ldaps:// URL`); }
    if (ldapUrl.protocol !== "ldaps:") throw new ConfigError(`${where}.ldap is an ldaps:// URL: credentials go to the controller over TLS alone`);
    const ca = r.material(t, "ca", where);
    if (ca === undefined || ca.trim() === "") throw new ConfigError(`${where} gives the authority for the controller's certificate (ca or ca_file)`);
    const issuer = r.str(t, "issuer", where), audience = r.str(t, "audience", where);
    if ((issuer === undefined) !== (audience === undefined)) {
      throw new ConfigError(`${where} gives an issuer and this server's audience for its tokens, both or neither`);
    }
    const cacheSeconds = r.int(t, "cache_seconds", where), timeoutMs = r.int(t, "timeout_ms", where);
    const kdcs = r.strings(t, "kdcs", where);
    const homeBase = r.str(t, "home_base", where);
    if (homeBase !== undefined && !(/^https:\/\//.test(homeBase) && homeBase.endsWith("/"))) {
      throw new ConfigError(`${where}.home_base is an absolute URI of the scheme https, ending with a solidus`);
    }
    const userinfo = r.table(t.userinfo_attributes, `${where}.userinfo_attributes`);
    for (const [member, attribute] of Object.entries(userinfo)) {
      if (typeof attribute !== "string" || attribute === "") {
        throw new ConfigError(`${where}.userinfo_attributes.${member} is the name of an attribute`);
      }
    }
    // The service principal of this server in the realm, and the password its
    // key is made from, with which a Kerberos ticket of the Negotiate scheme is
    // verified (PLAN-auth.md, phase 3b). Both, or neither.
    const servicePrincipal = r.str(t, "service_principal", where), servicePassword = r.str(t, "service_password", where);
    if ((servicePrincipal === undefined) !== (servicePassword === undefined)) {
      throw new ConfigError(`${where} gives a service_principal and the service_password its key is made from, both or neither`);
    }
    if (servicePrincipal !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._-]*(\/[A-Za-z0-9][A-Za-z0-9._-]*)*$/.test(servicePrincipal)) {
      throw new ConfigError(`${where}.service_principal is a service principal, as HTTP/cdmi.eu.example`);
    }
    c.domainControllers.push({
      domain, realm, ldap, ca,
      // The realm's labels as the base, as the controller forms it: EU.EXAMPLE is dc=eu,dc=example.
      base: r.str(t, "base", where) ?? realm.toLowerCase().split(".").map((l) => `dc=${l}`).join(","),
      ...(issuer === undefined ? {} : { issuer, audience: audience! }),
      cacheSeconds: cacheSeconds ?? 60, timeoutMs: timeoutMs ?? 5000,
      ...(kdcs === undefined || kdcs.length === 0 ? {} : { kdcs }),
      ...(homeBase === undefined ? {} : { homeBase }),
      ...(Object.keys(userinfo).length === 0 ? {} : { userinfoAttributes: userinfo as Record<string, string> }),
      ...(r.str(t, "search_dn", where) === undefined ? {} : {
        searchDn: r.str(t, "search_dn", where)!,
        searchPassword: r.str(t, "search_password", where) ?? "",
      }),
      ...(servicePrincipal === undefined ? {} : {
        servicePrincipal,
        // The key of the principal, by the string-to-key of RFC 3962 with the
        // salt Kerberos gives: the realm, then the components of the name.
        serviceKey: stringToKey(servicePassword!, realm + servicePrincipal.split("/").join(""), ETYPE.aes256),
        serviceEtype: ETYPE.aes256,
      }),
    });
  }
  const mcp = doc.mcp;
  if (mcp !== undefined) {
    const t = r.table(mcp, "[mcp]");
    r.only(t, "[mcp]", ["host", "port", "uri", "certificate", "scopes_required", "origins", "strict_headers"]);
    const port = r.int(t, "port", "[mcp]") ?? 8100;
    const host = r.str(t, "host", "[mcp]") ?? "127.0.0.1";
    c.mcp = {
      host,
      port,
      // The address this endpoint is reported at in cdmi_mcp_uri, and the
      // resource identifier of the access tokens it accepts. Where a
      // certificate is configured the endpoint is served over TLS, so the
      // address it reports of itself is an https one; it reported an http
      // address whatever the certificate said until 0.86, which is the address
      // a client would then have been given and the resource identifier it
      // would have asked a token for.
      uri: r.str(t, "uri", "[mcp]") ??
        `${r.str(t, "certificate", "[mcp]") === undefined ? "http" : "https"}://${host}:${port}/mcp`,
      certificate: r.str(t, "certificate", "[mcp]"),
      scopesRequired: r.str(t, "scopes_required", "[mcp]") === "true",
      // The origins a browser-based client may present. The transport requires
      // a server to validate the field and refuse one it does not answer;
      // where none is stated here, the endpoint's own origin is the one it
      // answers, and "*" answers any, which is what a deployment whose clients
      // are not browsers may as well say plainly.
      ...(r.strings(t, "origins", "[mcp]") === undefined
        ? {}
        : { origins: r.strings(t, "origins", "[mcp]")! }),
      strictHeaders: r.str(t, "strict_headers", "[mcp]") === "true",
    };
    for (const o of c.mcp.origins ?? []) {
      if (o === "*") continue;
      try {
        if (new URL(o).origin !== o) throw new Error("not an origin");
      } catch {
        throw new ConfigError(`[mcp].origins holds ${JSON.stringify(o)}, which is not an origin: an origin is a ` +
          'scheme, a host and a port, as "https://app.example.com", with no path. "*" answers any.');
      }
    }
    // The certificate must be one of the [[certificate]] entries, as [https]'s
    // must be. An identifier naming none was accepted and the endpoint then
    // served plain HTTP, so a deployment that asked for TLS got none and was
    // not told; nothing read this key at all before 0.86.
    if (c.mcp.certificate !== undefined && !c.certificates.some((x) => x.id === c.mcp!.certificate)) {
      throw new ConfigError(
        `[mcp] names the certificate ${JSON.stringify(c.mcp.certificate)}, which is not configured`);
    }
  }
  for (const [i, t] of r.tables(doc.group_privileges, "[[group_privileges]]").entries()) {
    const where = `[[group_privileges]][${i}]`;
    r.only(t, where, ["domain", "group", "privileges"]);
    const privileges = t.privileges;
    if (!Array.isArray(privileges) || privileges.some((p) => typeof p !== "string")) {
      throw new ConfigError(`${where}.privileges is an array of the privileges the draft defines`);
    }
    c.groupPrivileges.push({ domain: r.need(t, "domain", where), group: r.need(t, "group", where), privileges: privileges as string[] });
  }
  for (const [i, t] of r.tables(doc.permit, "[[permit]]").entries()) {
    const where = `[[permit]][${i}]`;
    r.only(t, where, ["uri", "addresses"]);
    const uri = r.need(t, "uri", where);
    try {
      new URL(uri);
    } catch {
      throw new ConfigError(`${where}.uri is not an absolute URI`);
    }
    c.permit.push({ uri, addresses: r.strings(t, "addresses", where) ?? [] });
  }
  const originated = r.table(doc.originated, "[originated]");
  r.only(originated, "[originated]", ["max_redirects", "max_response_bytes", "timeout_ms"]);
  c.originated = {
    maxRedirects: r.int(originated, "max_redirects", "[originated]") ?? c.originated.maxRedirects,
    maxResponseBytes: r.int(originated, "max_response_bytes", "[originated]") ?? c.originated.maxResponseBytes,
    timeoutMs: r.int(originated, "timeout_ms", "[originated]") ?? c.originated.timeoutMs,
  };

  const dac = r.table(doc.dac, "[dac]");
  if (Object.keys(dac).length > 0) {
    for (const gone of ["certificate", "encryption_certificate"]) {
      if (dac[gone] !== undefined) {
        throw new ConfigError(`[dac].${gone} is not a setting of this server since 0.50: the keys of its identity ` +
          "are held at a key management server and operated there, never here; [dac].signing_key_id and " +
          "[dac].encryption_key_id name them, and [dac].signing_chain and [dac].encryption_chain give their " +
          "certificates where there are any");
      }
    }
    r.only(dac, "[dac]", ["signing_key_id", "encryption_key_id", "signing_chain", "signing_chain_file",
      "encryption_chain", "encryption_chain_file", "methods", "ca", "ca_file", "response_window_ms", "response_uri"]);
    const keyName = (field: string): string => {
      const v = r.need(dac, field, "[dac]");
      if (v === "" || v.includes("/")) {
        throw new ConfigError(`[dac].${field} is the name of a key within the root domain's scope, which is not ` +
          "empty and holds no /");
      }
      return v;
    };
    const signingKeyId = keyName("signing_key_id");
    const encryptionKeyId = keyName("encryption_key_id");
    if (signingKeyId === encryptionKeyId) {
      throw new ConfigError("[dac].signing_key_id and [dac].encryption_key_id name one key; a request is signed " +
        "with one and a response encrypted to another, and neither is used for the purpose of the other");
    }
    const signingChain = r.material(dac, "signing_chain", "[dac]");
    const encryptionChain = r.material(dac, "encryption_chain", "[dac]");
    const methods = r.strings(dac, "methods", "[dac]") ?? ["https"];
    for (const m of methods) {
      if (m !== "https" && m !== "http") {
        throw new ConfigError(`[dac].methods names ${JSON.stringify(m)}; this server submits a request over https or http`);
      }
    }
    const ca = r.material(dac, "ca", "[dac]");
    const window = r.int(dac, "response_window_ms", "[dac]");
    const responseUri = r.str(dac, "response_uri", "[dac]");
    if (responseUri !== undefined) {
      try {
        new URL(responseUri);
      } catch {
        throw new ConfigError("[dac].response_uri is not an absolute URI");
      }
    }
    // "The response window ... is not less than 60 seconds where the request
    // contains a dac_response_uri field" (revision 269), and it is reported in
    // whole seconds.
    if (window !== undefined && (window % 1000 !== 0 || window < 1000)) {
      throw new ConfigError("[dac].response_window_ms is a whole number of seconds, in milliseconds");
    }
    if (window !== undefined && responseUri !== undefined && window < 60_000) {
      throw new ConfigError("[dac].response_window_ms is at least 60000 where a response_uri is given, as revision 269 requires");
    }
    c.dac = {
      signingKeyId, encryptionKeyId,
      ...(signingChain === undefined ? {} : { signingChain }),
      ...(encryptionChain === undefined ? {} : { encryptionChain }),
      methods,
      ...(ca === undefined ? {} : { ca }),
      ...(window === undefined ? {} : { responseWindowMs: window }),
      ...(responseUri === undefined ? {} : { responseUri }),
    };
  }

  // The keys of the identity are held at a key management server, so delegated
  // access control needs one: "A CDMI server that does not publish that
  // capability ... cannot perform delegated access control" (revision 245).
  if (c.dac !== undefined && c.kms.length === 0) {
    throw new ConfigError("[dac] needs a key management server, a [[kms]] table, at which the keys of this " +
      "server's identity are held and operated");
  }
  const labels = new Set<string>();
  for (const s of c.kms) {
    if (labels.has(s.label)) throw new ConfigError(`the key management server ${s.label} is given twice`);
    labels.add(s.label);
  }

  const keys = new Set<string>();
  for (const k of c.s3Keys) {
    if (keys.has(k.accessKey)) {
      throw new ConfigError(`the S3 access key ${k.accessKey} is given twice`);
    }
    keys.add(k.accessKey);
  }

  return c;
}

/**
 * Checks what refers to something the command line may also supply,
 * once both have been applied: an S3 access key names a principal,
 * which a --user flag may define.
 */
export function checkReferences(c: Config): void {
  const names = new Set(c.users.map((u) => u.name));
  for (const k of c.s3Keys) {
    if (!names.has(k.user)) {
      throw new ConfigError(
        `the S3 access key ${k.accessKey} acts as ${k.user}, who is not a configured user`);
    }
  }
}

/**
 * Applies the command line over a configuration, so that a flag wins.
 * Every flag this server accepted before the configuration file existed
 * is accepted still.
 */
/**
 * The flags this server takes: the name, the argument each names, and
 * what it does. One table, so that the usage text and the check for a
 * flag this server does not take cannot disagree with what applyArgv
 * reads.
 */
export const FLAGS: { name: string; argument: string; description: string }[] = [
  { name: "config", argument: "<path>", description: "read settings from a TOML file" },
  {
    name: "dac-identity",
    argument: "[pem|jwk]",
    description: "print the public key of the delegated access control signing identity and exit",
  },
  { name: "store", argument: "<path>", description: "the directory the store lives in" },
  { name: "base", argument: "<path>", description: "the base URI of the protocol binding" },
  { name: "host", argument: "<address>", description: "the address to listen on" },
  { name: "port", argument: "<port>", description: "the port to listen on" },
  { name: "tls-port", argument: "<port>", description: "the port to listen on for TLS" },
  {
    name: "tls-certificate",
    argument: "<id>",
    description: "the identifier of the certificate to serve",
  },
  {
    name: "export-origins",
    argument: "<origin,...>",
    description: "the origins at which an HTTP export may be served",
  },
  {
    name: "root-export",
    argument: "<name>",
    description: "the name of an HTTP export entry to place on the root " +
      "container object",
  },
  {
    name: "root-export-path",
    argument: "<path>",
    description: "the path that export is served at, which defaults to /",
  },
  {
    name: "user",
    argument: "<name:password[:groups][:flags]>",
    description: "a principal; flags are admin and privileges, comma-separated; repeat for more than one",
  },
  {
    name: "log",
    argument: "<off|problems|requests>",
    description: "what to log; nothing is logged unless this is given",
  },
  { name: "log-file", argument: "<path>", description: "write the log there, not to stderr" },
  { name: "log-format", argument: "<text|json>", description: "how each line is written" },
  {
    name: "mqtt",
    argument: "",
    description: "connect to the broker an MQTT export entry names",
  },
  { name: "help", argument: "", description: "print this text and exit (also -h)" },
  { name: "version", argument: "", description: "print the version of seedmi and exit (also -v)" },
];

/** The usage text. */
export function usage(): string {
  const width = FLAGS.reduce(
    (n, f) => Math.max(n, `--${f.name} ${f.argument}`.trimEnd().length), 0);
  const lines = FLAGS.map((f) => {
    const left = `--${f.name} ${f.argument}`.trimEnd();
    return `  ${left.padEnd(width)}  ${f.description}`;
  });
  return [
    "seedmi: a CDMI 3.0 server.",
    "",
    "Usage: node src/main.ts [flags]",
    "",
    "Settings come from a configuration file, the command line, or both,",
    "and a flag wins over the file.",
    "",
    ...lines,
    "",
    "With no --user, every request is the anonymous principal and the",
    "store is open. seedmi.toml in the source directory is a commented",
    "example of a configuration file.",
  ].join("\n");
}

/**
 * Reports a flag this server does not take. The value of a flag is
 * skipped, so that a value beginning with two hyphens is not mistaken
 * for a flag of its own.
 */
export function unknownFlag(argv: string[]): string | undefined {
  const takesValue = new Set(FLAGS.filter((f) => f.argument !== "").map((f) => f.name));
  const known = new Set(FLAGS.map((f) => f.name));
  for (let i = 2; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith("--")) return token;
    const name = token.slice(2);
    if (!known.has(name)) return token;
    if (takesValue.has(name)) i += 1;
  }
  return undefined;
}

export function applyArgv(c: Config, argv: string[]): Config {
  const out: Config = {
    ...c, users: [...c.users], exportOrigins: [...c.exportOrigins], s3Keys: [...c.s3Keys], kms: [...c.kms],
    permit: [...c.permit], originated: { ...c.originated },
  };
  const value = (name: string): string | undefined => {
    const i = argv.lastIndexOf(`--${name}`);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
  };
  const all = (name: string): string[] => {
    const found: string[] = [];
    for (let i = 0; i < argv.length - 1; i++) {
      if (argv[i] === `--${name}`) found.push(argv[i + 1]);
    }
    return found;
  };

  out.store = value("store") ?? out.store;
  out.base = value("base") ?? out.base;
  out.host = value("host") ?? out.host;
  const port = value("port");
  if (port !== undefined) out.port = Number(port);
  const tlsPort = value("tls-port");
  if (tlsPort !== undefined) out.tlsPort = Number(tlsPort);
  out.tlsCertificate = value("tls-certificate") ?? out.tlsCertificate;
  const origins = value("export-origins");
  if (origins !== undefined) {
    out.exportOrigins = origins.split(",").map((o) => o.trim()).filter(Boolean);
  }
  out.rootExport = value("root-export") ?? out.rootExport;
  out.rootExportPath = value("root-export-path") ?? out.rootExportPath;

  if (argv.includes("--mqtt")) out.mqtt = { enabled: true };

  const level = value("log");
  if (level !== undefined) {
    if (!LOG_LEVELS.includes(level as LogLevel)) {
      throw new ConfigError(`--log is one of ${LOG_LEVELS.join(", ")}`);
    }
    out.logLevel = level as LogLevel;
  }
  const format = value("log-format");
  if (format !== undefined) {
    if (!LOG_FORMATS.includes(format as LogFormat)) {
      throw new ConfigError(`--log-format is one of ${LOG_FORMATS.join(", ")}`);
    }
    out.logFormat = format as LogFormat;
  }
  out.logFile = value("log-file") ?? out.logFile;

  for (const spec of all("user")) {
    const [name, password, groups = "", flags = ""] = spec.split(":");
    if (!name || password === undefined) {
      throw new ConfigError("a user is given as name:password[:groups][:flags]");
    }
    out.users = out.users.filter((u) => u.name !== name);
    out.users.push({
      name,
      password,
      groups: groups === "" ? [] : groups.split(","),
      administrator: flags.split(",").includes("admin"),
      // The same flags field names privileges, as --user alice:pw::admin,domain_kms_admin.
      privileges: flags.split(",").filter((f) => f !== "" && f !== "admin"),
    });
  }
  return out;
}

/** The certificate an identifier names, as an export entry names one. */
export function certificateOf(c: Config, id: string): CertificateConfig | undefined {
  return c.certificates.find((x) => x.id === id);
}
