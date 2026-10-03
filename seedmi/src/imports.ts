// The imports field: parsing and validation of the entries a CDMI client
// supplies. What the entries then present is the layering engine's business;
// this file decides only whether an imports field is well formed.
//
// Section references are to clause 9 of the draft, revision 49.

import { boundReference } from "./credential.ts";
import { CDMI_IMPORT_VERSIONS, parseVersions } from "./protocol-versions.ts";
import { checkPermitted } from "./originated.ts";
import {
  Condition, capabilityNotPresent, conflictingFields, forbidden, invalidField,
} from "./problems.ts";
import { sharedSubscriptionProblem,
  MQTT_VERSIONS, type MqttTls, parseImportURI, parseTls,
} from "./mqtt-entry.ts";
import { parseS3Import } from "./s3-import.ts";

/** The fields of an import entry a CDMI client supplies. */
export interface ImportEntry {
  /** The versions of HTTP an HTTP import may negotiate, in preference order. */
  httpProtocol?: string[];
  /**
   * The seconds for which an HTTP import presents the value it holds before
   * obtaining it again. "0" obtains it again for every read; absent obtains
   * it once, when the importing object is first read (revision 327).
   */
  cache_max_age?: string;
  /** The entity tag the origin server last returned, used to revalidate. */
  etag?: string;
  /** The Last-Modified the origin server last returned. */
  last_modified?: string;
  type: string;
  import_uri?: string;
  write_enabled?: string;
  identity_mode?: string;
  /**
   * The credential reference of the secret presented in service identity
   * mode, as bound: a Password for a CDMI or SMB import. It was the name of a
   * credential in seedmi.toml before 0.46.
   */
  credential_id?: { kms: string; name: string; scope?: string };
  /**
   * The trust anchor against which the certificate the origin server presents
   * is verified, as a credential reference addressing a managed object of type
   * Certificate (revision 365, HTTP imports, and the subclause on verifying
   * the certificate of a party a CDMI server connects to). Where absent, the
   * CDMI server verifies against the trust anchors it is configured with.
   */
  trust_anchor?: { kms: string; name: string; scope?: string };
  /** The fields of an NFS import. The versions, in order of preference. */
  protocol?: string[];
  security?: string;
  transport?: string;
  port?: string;
  follow_symlinks?: string;
  anon_uid?: string;
  anon_gid?: string;
  /** The fields of an MQTT import. */
  /** The MQTT versions to negotiate, in order of preference (revision 245
   * renamed this field from protocol_version and made it an array). */
  mqttProtocol?: string[];
  /** The credential reference of the password presented to the broker, as bound. */
  password_secret_id?: { kms: string; name: string; scope?: string };
  qos?: string;
  clean_session?: string;
  keep_alive_interval?: string;
  /** Of an MQTT import: the interval, in seconds, at which its credentials are resolved again (revision 269). */
  refresh_interval?: string;
  value_transfer_encoding?: string;
  mimetype?: string;
  client_id?: string;
  username?: string;
  tls?: MqttTls;
  /** The fields of an SMB import. */
  signing?: string;
  encryption?: string;
  follow_reparse?: string;
  auth_method?: string;
  max_sessions?: string;
  domain?: string;
  domain_servers?: string[];
  disabled?: string;
  required?: string;
  resource?: string;
  preserve_objectid?: string;
  /** Image imports. */
  filesystem?: string;
  partition?: string;
  offset?: string;
}

/** The CDMI server populated fields, added when an entry is reported. */
export interface ImportEntryOut extends ImportEntry {
  active: string;
  last_problems: unknown[];
  state_determined_time: string;
  source_objectid?: string;
}

export const isWriteTarget = (e: ImportEntry) => e.write_enabled === "true";
export const isDisabled = (e: ImportEntry) => e.disabled === "true";
export const isRequired = (e: ImportEntry) => e.required === "true";
export const preservesObjectID = (e: ImportEntry) => e.preserve_objectid !== "false";

/**
 * The base URIs at which clients reach this server. An absolute import URI
 * beginning with one of them addresses a container object of this server,
 * and is a local import (9.4).
 */
export let selfBases: string[] = [];

export function setSelfBases(bases: string[]): void {
  selfBases = bases.map((b) => (b.endsWith("/") ? b : b + "/"));
}

/** The base URIs of this server, for a caller that resolves against them. */
export function ownBases(): string[] {
  return selfBases;
}

/**
 * Maps an import URI to a namespace path of this server. Returns undefined
 * where the URI addresses another server.
 */
/** The parts of an NFS import URI, as RFC 2224 defines the form. */
export function parseNfsURI(uri: string):
  { host: string; port?: number; path: string } | undefined {
  const m = /^nfs:\/\/([^/:]+)(?::(\d+))?(\/.*)$/.exec(uri);
  if (!m) return undefined;
  if (!m[3].endsWith("/")) return undefined;
  return {
    host: m[1],
    port: m[2] === undefined ? undefined : Number(m[2]),
    path: m[3],
  };
}

export function localImportPath(uri: string): string | undefined {
  if (uri.startsWith("/")) return uri;
  for (const base of selfBases) {
    if (uri.toLowerCase().startsWith(base.toLowerCase())) {
      return "/" + uri.slice(base.length);
    }
  }
  return undefined;
}

/** The fields of the common table, which every entry may contain. */
const COMMON = ["type", "write_enabled", "disabled", "required",
  "active", "last_problems", "state_determined_time"];

/** The fields of the addressing table, which a "self" entry shall not contain. */
const ADDRESSING = ["import_uri", "identity_mode", "credential_id"];

const FIELDS: Record<string, string[]> = {
  CDMI: [...COMMON, ...ADDRESSING, "resource", "preserve_objectid", "auth_method", "username", "protocol"],
  self: [...COMMON],
  // "An HTTP import presents the representation an origin server returns
  // for one URI as the value of a data object." It is a value import: the
  // source holds a sequence of bytes and no namespace (revision 327).
  HTTP: [...COMMON, "import_uri", "protocol", "cache_max_age", "auth_method",
    "username", "credential_id", "trust_anchor", "etag", "last_modified"],
  // An image import has no preserve_objectid field: an object it presents
  // has no object ID at all, so there is none to preserve.
  image: [...COMMON, "import_uri", "identity_mode", "filesystem", "partition", "offset",
    "source_objectid"],
  NFS: [...COMMON, ...ADDRESSING, "protocol", "security", "transport", "port",
    "follow_symlinks", "anon_uid", "anon_gid"],
  SMB: [...COMMON, ...ADDRESSING, "protocol", "username", "domain", "domain_servers", "signing",
    "encryption", "follow_reparse", "auth_method", "max_sessions"],
  // An MQTT import is placed on a queue object and enqueues the messages of
  // a topic. "An MQTT import entry contains the fields common to every
  // import entry", write_enabled among them: the MQTT imports subclause
  // refers to it by name, and makes an append to the importing queue object
  // either refused or published to the broker according to its value. This
  // server excluded it, on the reading that an entry presenting no namespace
  // has no write target, so an entry supplying it was refused and an append
  // was always permitted (weedmi IMQT-001). identity_mode remains excluded:
  // an MQTT import performs no operation as a principal.
  MQTT: ["type", "write_enabled", "disabled", "required", "active",
    "last_problems", "state_determined_time",
    "import_uri", "protocol", "qos", "clean_session",
    "keep_alive_interval", "username", "password_secret_id", "refresh_interval", "tls",
    "mimetype", "value_transfer_encoding", "client_id",
    "connected", "messages_enqueued", "messages_dropped"],
  // An S3 import presents the objects of a bucket another server
  // holds. The credentials the CDMI server signs with are conveyed
  // by no field, as they are not for an S3 export.
  S3: [...COMMON, ...ADDRESSING, "region", "addressing_style", "folder_markers",
    "listing_max_age", "object_lock"],
};

/**
 * The versions of SMB an import entry may name. Annex B defines no
 * capability for any of them, and none for the versions of an SMB
 * import as a whole, so a client discovers only that SMB imports are
 * supported. See Q2 in NOTES-on-smb.md.
 */
const SMB_PROTOCOLS = ["SMB2", "SMB2.1", "SMB3", "SMB3.0.2", "SMB3.1.1"];

/**
 * The versions field of an entry: "a JSON array of JSON strings ... in order
 * of preference, the first being the one it attempts first" (revision 245,
 * where earlier revisions carried one version as a JSON string). A field that
 * is absent takes the default given.
 */
export function versionsOf(value: unknown, byDefault: string[]): string[] | undefined {
  if (value === undefined) return byDefault;
  if (!Array.isArray(value) || value.length === 0) return undefined;
  if (value.some((v) => typeof v !== "string")) return undefined;
  return value as string[];
}

/**
 * The versions of a protocol are reported by one capability holding an array
 * of them, which revision 245 put in place of one capability for each
 * version, and the field of an entry carries the versions a CDMI server may
 * negotiate "in order of preference, the first being the one it attempts
 * first".
 */
const SMB_IMPORT_CAPABILITY = "cdmi_import_smb_versions";

/** The versions this server negotiates with an SMB import source. */
const SMB_NEGOTIATED = ["SMB2", "SMB2.1", "SMB3", "SMB3.0.2", "SMB3.1.1"];

/**
 * The host and the share an SMB import URI names, of the form
 * smb://host[:port]/share/path/.
 */
export function parseSmbURI(uri: string):
  { host: string; port?: number; share: string; path: string } | undefined {
  const m = /^smb:\/\/([^/:?#]+)(?::(\d+))?(\/[^?#]*)?$/i.exec(uri);
  if (!m) return undefined;
  const rest = (m[3] ?? "/").replace(/^\//, "");
  if (rest === "") return undefined; // a share is named
  const cut = rest.indexOf("/");
  const share = cut < 0 ? rest : rest.slice(0, cut);
  if (share === "") return undefined;
  const path = cut < 0 ? "/" : rest.slice(cut);
  return {
    host: m[1],
    port: m[2] === undefined ? undefined : Number(m[2]),
    share: decodeURIComponent(share),
    path: path.endsWith("/") ? path : `${path}/`,
  };
}

/** The versions of NFS an import entry may name, and the capability of each. */
const NFS_PROTOCOLS: Record<string, string> = {
  NFSv3: "cdmi_import_nfs_v3",
  NFSv4: "cdmi_import_nfs_v4",
  "NFSv4.1": "cdmi_import_nfs_v4_1",
  "NFSv4.2": "cdmi_import_nfs_v4_2",
};

/** The versions this server negotiates with an import source. */
const NFS_NEGOTIATED = ["NFSv4.1", "NFSv4.2"];

/**
 * The file systems seedmi can interpret, the cdmi_import_filesystems
 * capability. FAT12, FAT16 and FAT32 differ in the width of one table and
 * in where the root directory sits, and are otherwise one format, so they
 * are offered under a single identifier and the driver determines which it
 * has by counting the data clusters, as the specification requires.
 */
export const FILESYSTEMS = ["fat"];

/** The MQTT versions an import negotiates with a broker. */
export const MQTT_IMPORT_VERSIONS = MQTT_VERSIONS;

/**
 * The versions of HTTP this server negotiates with an origin server, as the
 * cdmi_import_http_versions capability reports them (revision 327).
 */
export const HTTP_IMPORT_VERSIONS = ["HTTP/1.1"];

/**
 * Whether this server is able to obtain a token for the requesting
 * principal, which is what delegated identity mode needs. It is
 * configuration of the server, so it is set at startup rather than held
 * in the namespace.
 */
let delegationAvailable = false;

export function setDelegationAvailable(yes: boolean): void {
  delegationAvailable = yes;
}

/** Whether a token endpoint is configured, for the capability. */
export function delegationConfigured(): boolean {
  return delegationAvailable;
}

export interface ParseOptions {
  /**
   * Whether the entries were accepted when they were written, and are parsed
   * again to be presented. The privilege of the principal that configured an
   * entry was determined then: entitlement "is determined when the feature is
   * configured ..., and not when the credential is used". Before 0.46 a stored
   * entry was checked again with no principal, which refused every import in
   * service identity mode that named no credential_id, on every read.
   */
  stored?: boolean;
  /** Whether a key management server is configured, so that a credential reference is accepted. */
  kms?: boolean;
  /** Whether the image import type is implemented yet. */
  images?: boolean;
  /**
   * Whether an S3 import entry is accepted. seedmi has no S3 client
   * and reads no bucket, so the server does not set this and refuses
   * the type, publishing no S3 import capability. The tests of the
   * entry's validation set it, so that the validation is still checked
   * for the day a client exists.
   */
  s3?: boolean;
  /**
   * The privileges the principal making the request holds. An
   * entry in service identity mode with no credential of its own
   * asks the CDMI server to present one of its configuration,
   * which the import_service_credential privilege permits.
   */
  privileges?: string[];
}

/**
 * Validates a complete imports field for the container object at the
 * namespace path ns, returning its entries in order.
 */
export function parseImports(raw: unknown, ns: string, opts: ParseOptions = {}): ImportEntry[] {
  if (!Array.isArray(raw)) {
    throw invalidField("/imports", 'the "imports" field shall be a JSON array of import entries');
  }
  const out: ImportEntry[] = [];
  let selfAt = -1;
  let writeAt = -1;
  const seen = new Map<string, number>();

  raw.forEach((rawEntry, i) => {
    const e = parseEntry(i, rawEntry, ns, opts);

    // At most one entry of type "self" (9.2).
    if (e.type === "self") {
      if (selfAt >= 0) {
        throw invalidField(`/imports/${i}/type`,
          'entries %s and %s are both of type "self"; an imports field shall contain at most one',
          selfAt, i).atImport(i, ns);
      }
      selfAt = i;
    }

    // At most one entry selects the write target (9.2).
    if (isWriteTarget(e)) {
      if (writeAt >= 0) {
        throw conflictingFields(`/imports/${i}/write_enabled`,
          'write_enabled is "true" in entries %s and %s; at most one entry selects the write target',
          writeAt, i).atImport(i, ns);
      }
      writeAt = i;
    }

    // Two entries of one object shall not address the same namespace. Two
    // entries are duplicates where their type and their import_uri are the
    // same; values that differ in form need not be compared (9.2).
    if (e.import_uri !== undefined && /^[a-z][a-z0-9+.-]*:/i.test(e.import_uri)) {
      // A URI this server would make a request to is a server-originated
      // request, and is made only to a URI this server is configured to permit.
      checkPermitted(e.import_uri, `/imports/${i}/import_uri`);
    }
    if (e.import_uri !== undefined) {
      const key = `${e.type} ${e.import_uri}`;
      const first = seen.get(key);
      if (first !== undefined) {
        throw conflictingFields(`/imports/${i}/import_uri`,
          "entries %s and %s address the same namespace %j", first, i, e.import_uri)
          .atImport(i, ns);
      }
      seen.set(key, i);
    }

    out.push(e);
  });
  return out;
}

function parseEntry(i: number, raw: unknown, ns: string, opts: ParseOptions): ImportEntry {
  const base = `/imports/${i}`;
  const fail = (c: Condition): never => {
    throw c.atImport(i, ns);
  };

  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    fail(invalidField(base, "an import entry shall be a JSON object"));
  }
  const obj = raw as Record<string, unknown>;

  const str = (k: string): string | undefined => {
    const v = obj[k];
    if (v === undefined) return undefined;
    if (typeof v !== "string") {
      fail(invalidField(`${base}/${k}`,
        "the %j field of an import entry shall be a JSON string", k));
    }
    return v as string;
  };
  // credential_id is a credential reference, bound by the binding before the
  // entry is parsed, as every credential reference is. A CDMI server run
  // without a key management server resolves none, and "cannot configure an
  // import in service identity mode" by one, so does not accept it. It named a
  // credential in seedmi.toml before 0.46.
  const referenceIn = (field: string): { kms: string; name: string; scope?: string } | undefined => {
    if (!(field in obj)) return undefined;
    if (opts.kms !== true) {
      fail(capabilityNotPresent("cdmi_kms", "/cdmi_capabilities/",
        "the %s field holds a credential reference, and this CDMI server is run without " +
        "a key management server", field));
    }
    const r = obj[field] as Record<string, unknown> | null;
    if (r === null || typeof r !== "object" || typeof r.kms !== "string" || typeof r.name !== "string") {
      fail(invalidField(`${base}/${field}`,
        "%s is a credential reference, a JSON object naming a credential", field));
    }
    return boundReference(r)!;
  };
  const credentialRef = () => referenceIn("credential_id");

  const type = str("type");
  if (type === undefined) {
    fail(invalidField(`${base}/type`, 'the "type" field of an import entry is mandatory'));
  }

  if (type === "image" && !opts.images) {
    fail(capabilityNotPresent("cdmi_import_image", "/cdmi_capabilities/",
      "seedmi does not implement imports of type %j", type));
  }
  // Before 0.2 an S3 import entry was accepted and reported, and no
  // bucket was ever read, while cdmi_import_s3 was published. A
  // capability that cannot be exercised is not published, and the
  // entry is refused as the capability not present condition requires.
  if (type === "S3" && !opts.s3) {
    fail(capabilityNotPresent("cdmi_import_s3", "/cdmi_capabilities/",
      "this CDMI server reads no S3 bucket: it has no S3 client yet"));
  }
  const allowed = FIELDS[type!];
  if (!allowed) {
    // A type the draft defines but seedmi does not implement, or one named
    // by the reverse domain name of another organization (9.1). Either way
    // the capability is not present.
    fail(capabilityNotPresent(`cdmi_import_${type!.toLowerCase()}`, "/cdmi_capabilities/",
      "seedmi does not implement imports of type %j", type));
  }

  for (const k of Object.keys(obj)) {
    if (allowed!.includes(k)) continue;
    if (type === "self" && ADDRESSING.includes(k)) {
      fail(invalidField(`${base}/${k}`,
        'an import entry of type "self" imports no namespace and shall not contain a %j field', k));
    }
    fail(invalidField(`${base}/${k}`,
      "the %j field is not defined for an import entry of type %j", k, type));
  }

  const e: ImportEntry = { type: type! };
  for (const k of ["write_enabled", "disabled", "required", "preserve_objectid"] as const) {
    const v = str(k);
    if (v === undefined) continue;
    if (v !== "true" && v !== "false") {
      fail(invalidField(`${base}/${k}`, 'the %j field shall be "true" or "false"', k));
    }
    e[k] = v;
  }
  if (type === "self") return e;

  // Entries that address a namespace.
  const uri = str("import_uri");
  if (uri === undefined) {
    fail(invalidField(`${base}/import_uri`,
      'the "import_uri" field is mandatory for an import entry of type %j', type));
  }

  const identity = str("identity_mode");
  if (identity !== undefined && identity !== "delegated" && identity !== "service") {
    fail(invalidField(`${base}/identity_mode`,
      'the identity mode shall be "delegated" or "service"'));
  }
  e.identity_mode = identity;

  if (type === "CDMI") {
    checkCDMIImportURI(uri!, ns, `${base}/import_uri`, fail);
    e.import_uri = uri;

    // Delegated identity mode for a remote import requires an access
    // token obtained by exchange, which seedmi does not do. It is always
    // able to delegate for a local import.
    if (localImportPath(uri!) === undefined && !delegationAvailable &&
      (identity === undefined || identity === "delegated")) {
      fail(capabilityNotPresent("cdmi_import_cdmi_delegation", "/cdmi_capabilities/",
        "no token endpoint is configured on this server, so a remote import is in " +
        "service identity mode alone"));
    }

    // 9.4: a local import shall be in delegated identity mode.
    if (localImportPath(uri!) !== undefined && identity === "service") {
      fail(invalidField(`${base}/identity_mode`,
        "a local import shall be in delegated identity mode, since service identity mode would " +
        "present every object at the import source to every principal permitted to access the " +
        "importing object"));
    }

    const credential = credentialRef();
    if (credential !== undefined && identity !== "service") {
      const why = identity === undefined
        ? " (the default for an import of the namespace category)"
        : "";
      fail(conflictingFields(`${base}/credential_id`,
        'credential_id applies only in service identity mode, and the identity mode of this ' +
        'entry is "delegated"%s', why));
    }
    // 9.2 ("Service identity"): an entry in service identity mode with no
    // credential_id asks the CDMI server to present a credential of its own
    // configuration, which requires the import_service_credential privilege.
    if (identity === "service" && credential === undefined && opts.stored !== true &&
      !(opts.privileges ?? []).includes("import_service_credential")) {
      fail(forbidden(
        'an import entry in service identity mode with no "credential_id" field ' +
        "asks this CDMI server to present a credential of its own configuration, " +
        "which the import_service_credential privilege permits"));
    }
    // In service identity mode the entry states how the credential is
    // presented: "Permitted values are bearer and basic. A CDMI server shall
    // report the invalid field condition where the identity mode is service
    // and this field is absent", and basic presents the username field.
    const method = str("auth_method");
    const username = str("username");
    if (identity === "service") {
      if (method !== "bearer" && method !== "basic") {
        fail(invalidField(`${base}/auth_method`, method === undefined
          ? 'an import entry in service identity mode states its auth_method, "bearer" or "basic"'
          : 'the auth_method field is "bearer" or "basic"'));
      }
      if (method === "basic" && username === undefined) {
        fail(invalidField(`${base}/username`, 'the basic method presents the user name the username field gives'));
      }
    }
    e.auth_method = method;
    e.username = username;
    // The CDMI versions the server may negotiate with the source, in order of
    // preference, checked against cdmi_import_cdmi_versions. Refused before 0.46
    // as not defined for the type.
    if ("protocol" in obj) {
      e.protocol = parseVersions(`${base}/protocol`, obj.protocol, "cdmi_import_cdmi_versions", CDMI_IMPORT_VERSIONS);
    }
    e.credential_id = credential;
    e.resource = str("resource");
    return e;
  }

  if (type === "HTTP") {
    const uri = str("import_uri");
    if (uri === undefined) {
      throw invalidField(`${base}/import_uri`, "an HTTP import entry names the URI it presents");
    }
    // "Its scheme shall be https, and a CDMI server shall report the
    // invalid field condition for any other scheme": the exchange carries
    // a credential, and what it returns becomes the value of an object of
    // this server's namespace.
    if (!uri.toLowerCase().startsWith("https://")) {
      throw invalidField(`${base}/import_uri`,
        "the URI of an HTTP import has the https scheme, and %j has not", uri);
    }
    e.import_uri = uri;
    const versions = versionsOf(obj.protocol, HTTP_IMPORT_VERSIONS);
    if (versions === undefined) {
      throw invalidField(`${base}/protocol`, "the protocol field is an array of JSON strings");
    }
    for (const v of versions) {
      if (!HTTP_IMPORT_VERSIONS.includes(v)) {
        throw invalidField(`${base}/protocol`,
          "%j is not a version of HTTP this server negotiates; it negotiates %s",
          v, HTTP_IMPORT_VERSIONS.join(", "));
      }
    }
    e.httpProtocol = versions;
    const age = str("cache_max_age");
    if (age !== undefined && !/^[0-9]+$/.test(age)) {
      throw invalidField(`${base}/cache_max_age`,
        "the cache_max_age field is a number of seconds as a decimal integer");
    }
    e.cache_max_age = age;
    const auth = str("auth_method") ?? "none";
    if (!["none", "basic", "bearer"].includes(auth)) {
      throw invalidField(`${base}/auth_method`,
        "the authentication scheme of an HTTP import is none, basic or bearer");
    }
    e.auth_method = auth;
    // "Conditional: present where auth_method contains basic."
    const username = str("username");
    if (auth === "basic" && username === undefined) {
      throw invalidField(`${base}/username`,
        "an HTTP import that authenticates by the basic scheme names a user");
    }
    e.username = username;
    // "A credential reference ... addressing a managed object of type
    // Certificate, being the trust anchor against which the CDMI server
    // verifies the certificate the origin server presents ... Where absent,
    // the CDMI server verifies against the trust anchors it is configured
    // with" (revision 365).
    e.trust_anchor = referenceIn("trust_anchor");
    // etag and last_modified are CDMI server populated: a value a client
    // supplies for either is ignored.
    return e;
  }

  if (type === "MQTT") {
    // An MQTT import subscribes to a topic filter of a broker and
    // enqueues each message it receives to the queue object the entry
    // is placed on. The layering of a namespace import does not
    // apply: a queue object holds a sequence of values.
    const at = parseImportURI(`${base}/import_uri`, uri ?? "");
    e.import_uri = uri;

    const versions = versionsOf(obj.protocol, ["3.1.1"]);
    if (versions === undefined) {
      fail(invalidField(`${base}/protocol`,
        "the protocol field is a JSON array of the MQTT versions to negotiate, " +
        "in order of preference"));
    }
    for (const version of versions!) {
      if (!MQTT_VERSIONS.includes(version)) {
        fail(invalidField(`${base}/protocol`,
          "%j is not an MQTT version this document defines: the versions are %s",
          version, MQTT_VERSIONS.join(", ")));
      }
    }
    e.mqttProtocol = versions;
    // The filter is valid under every version the entry names (revision 247):
    // under 5.0, one beginning "$share/" has the form of a shared subscription.
    if (versions!.includes("5.0") && at.topic !== undefined) {
      const problem = sharedSubscriptionProblem(at.topic);
      if (problem !== undefined) {
        fail(invalidField(`${base}/import_uri`, "the topic filter %j is not valid under MQTT 5.0, which the protocol " +
          "field names: %s", at.topic, problem));
      }
    }

    const qos = str("qos") ?? "0";
    if (!["0", "1", "2"].includes(qos)) {
      fail(invalidField(`${base}/qos`, 'the qos field shall be "0", "1" or "2"'));
    }
    e.qos = qos;

    for (const [f, dflt] of [["clean_session", "true"]] as [string, string][]) {
      const v = str(f) ?? dflt;
      if (v !== "true" && v !== "false") {
        fail(invalidField(`${base}/${f}`,
          'the %j field shall be "true" or "false"', f));
      }
      (e as unknown as Record<string, unknown>)[f] = v;
    }
    const keep = str("keep_alive_interval") ?? "60";
    if (!/^[0-9]+$/.test(keep) || Number(keep) > 65535) {
      fail(invalidField(`${base}/keep_alive_interval`,
        "the keep_alive_interval field is a whole number of at most 65535"));
    }
    e.keep_alive_interval = keep;
    // "The interval, in seconds, at which the CDMI server resolves the
    // credential references of this entry again ... The default value shall be
    // 0, which disables resolution at an interval" (revision 269; ECR-090B).
    const refresh = str("refresh_interval");
    if (refresh !== undefined) {
      if (!/^[0-9]+$/.test(refresh) || Number(refresh) > 2147483647) {
        fail(invalidField(`${base}/refresh_interval`, "the refresh_interval field is a whole number of seconds"));
      }
      e.refresh_interval = refresh;
    }

    const encoding = str("value_transfer_encoding") ?? "base64";
    if (!["utf-8", "base64", "json"].includes(encoding)) {
      fail(invalidField(`${base}/value_transfer_encoding`,
        'the value_transfer_encoding field shall be "utf-8", "base64" or "json"'));
    }
    e.value_transfer_encoding = encoding;
    e.mimetype = str("mimetype");

    e.client_id = str("client_id") ?? `seedmi-import-${i}`;
    e.username = str("username");
    // An MQTT import defines no password field, in this revision or
    // the last; a CDMI server "shall not accept a secret ... as the
    // value of any field". The password is addressed by a credential
    // reference in password_secret_id, which is resolved against a key
    // management server, and this CDMI server does not publish
    // cdmi_kms. Revision 196 withdrew cdmi_import_mqtt_kmip, the name
    // this refusal gave before.
    if ("password" in obj) {
      fail(invalidField(`${base}/password`,
        "the password field is not defined: a password is held by a key " +
        "management server and addressed by a credential reference in " +
        "password_secret_id"));
    }
    // A credential reference, bound by the binding before the entry is
    // parsed (bindImportCredentials). The draft types this field as a JSON
    // string and describes it as "a credential reference, a JSON object";
    // this server takes the object, as every other credential reference is,
    // and an ECR raises the discrepancy.
    if ("password_secret_id" in obj) {
      if (opts.kms !== true) {
        fail(capabilityNotPresent("cdmi_kms", "/cdmi_capabilities/",
          "the password_secret_id field holds a credential reference, and this CDMI " +
          "server is run without a key management server"));
      }
      const r = obj.password_secret_id as Record<string, unknown> | null;
      if (r === null || typeof r !== "object" || typeof r.kms !== "string" || typeof r.name !== "string") {
        fail(invalidField(`${base}/password_secret_id`,
          "the password_secret_id field holds a credential reference, a JSON object naming a credential"));
      }
      e.password_secret_id = { kms: String(r!.kms), name: String(r!.name),
        ...(typeof r!.scope === "string" ? { scope: r!.scope } : {}) };
    }
    if ("tls" in obj) {
      e.tls = parseTls((f) => `${base}/${f}`, obj.tls, { kms: opts.kms === true });
    }
    if ((at.scheme === "mqtts" || at.scheme === "wss") && e.tls === undefined) {
      e.tls = { rejectUnauthorized: true };
    }
    if (e.tls !== undefined && at.scheme !== "mqtts" && at.scheme !== "wss") {
      fail(invalidField(`${base}/tls`,
        "a tls field applies to an import URI of a TLS scheme, and %j is not one",
        at.scheme));
    }
    return e;
  }

  if (type === "SMB") {
    // An SMB import: the import source is a share held by an SMB
    // server, named by a URI of the form smb://host/share/path/.
    const parsed = parseSmbURI(uri!);
    if (parsed === undefined) {
      fail(invalidField(`${base}/import_uri`,
        "the import URI of an SMB import is of the form smb://host/share/path/, and " +
        "%j is not", uri));
    }
    e.import_uri = uri;

    const protocol = versionsOf(obj.protocol, ["SMB2.1"]);
    if (protocol === undefined) {
      fail(invalidField(`${base}/protocol`,
        "the protocol field is a JSON array of the versions to negotiate, in order of preference"));
    }
    for (const version of protocol!) {
      if (!SMB_PROTOCOLS.includes(version)) {
        fail(invalidField(`${base}/protocol`,
          "%j is not a version of the SMB protocol this document defines", version));
      }
      if (!SMB_NEGOTIATED.includes(version)) {
        fail(capabilityNotPresent(SMB_IMPORT_CAPABILITY, "/cdmi_capabilities/",
          "seedmi negotiates %s with an import source", SMB_NEGOTIATED.join(", ")));
      }
    }
    e.protocol = protocol;

    for (const [k, values] of [
      ["signing", ["disabled", "required"]],
      ["encryption", ["disabled", "required"]],
    ] as [string, string[]][]) {
      const v = str(k);
      if (v !== undefined && !values.includes(v)) {
        fail(invalidField(`${base}/${k}`, "%j shall be one of %s", k, values.join(", ")));
      }
      if (k === "encryption" && v === "required") {
        fail(capabilityNotPresent("cdmi_import_smb_encryption", "/cdmi_capabilities/",
          "seedmi does not encrypt the transport of an SMB import"));
      }
      (e as unknown as Record<string, unknown>)[k] = v;
    }

    const follow = str("follow_reparse");
    if (follow !== undefined && follow !== "true" && follow !== "false") {
      fail(invalidField(`${base}/follow_reparse`,
        'follow_reparse shall be "true" or "false"'));
    }
    e.follow_reparse = follow;

    // The authentication method used with the import source. The
    // default is Kerberos, which this server does not implement, so an
    // entry that does not name ntlmv2 reports the capability that
    // would carry it.
    const method = str("auth_method") ?? "kerberos";
    if (method !== "kerberos" && method !== "ntlmv2") {
      fail(invalidField(`${base}/auth_method`,
        '%j is not an authentication method this document defines', method));
    }
    if (method === "kerberos") {
      fail(capabilityNotPresent("cdmi_import_smb_krb5", "/cdmi_capabilities/",
        "seedmi authenticates with an SMB import source using NTLMv2, which the " +
        '"auth_method" field names as "ntlmv2"'));
    }
    e.auth_method = method;

    const sessions = str("max_sessions");
    if (sessions !== undefined && !/^(0|[1-9][0-9]*)$/.test(sessions)) {
      fail(invalidField(`${base}/max_sessions`,
        "max_sessions shall be a non-negative decimal integer"));
    }
    e.max_sessions = sessions;

    // A credential names the principal the session authenticates as,
    // and applies in service identity mode as it does for a CDMI
    // import. An entry naming none authenticates anonymously.
    const credential = credentialRef();
    if (credential !== undefined && e.identity_mode !== "service") {
      fail(conflictingFields(`${base}/credential_id`,
        "credential_id applies only in service identity mode, and the identity mode " +
        "of this entry is %j", e.identity_mode ?? "delegated"));
    }
    if (e.identity_mode === "service" && credential === undefined) {
      fail(forbidden('an import entry in service identity mode with no ' +
        '"credential_id" field asks the CDMI server to present a credential of its ' +
        "own, which this server does not do for an SMB import"));
    }
    // "A CDMI server shall report the invalid field condition where the
    // identity mode is service and this field is absent" (the SMB import
    // clause): the session authenticates as the username field.
    const smbUser = str("username");
    if (e.identity_mode === "service" && smbUser === undefined) {
      fail(invalidField(`${base}/username`,
        "an SMB import entry in service identity mode gives the username field its session authenticates as"));
    }
    e.username = smbUser;
    e.credential_id = credential;
    e.domain = str("domain");
    const servers = obj.domain_servers;
    if (servers !== undefined && servers !== null &&
      (!Array.isArray(servers) || servers.some((x) => typeof x !== "string"))) {
      fail(invalidField(`${base}/domain_servers`,
        "domain_servers shall be a JSON array of JSON strings"));
    }
    e.domain_servers = servers as string[] | undefined;
    return e;
  }

  if (type === "S3") {
    // An S3 import: the import source is a bucket another server
    // holds, named by a URI in the path addressing style.
    const parsed = parseS3Import(String(i),
      { ...(raw as object), type, import_uri: uri });
    Object.assign(e, parsed);

    // An S3 import is of the namespace category, so the identity
    // mode that applies where the field is absent is delegated.
    // Delegated mode obtains temporary credentials scoped to the
    // requesting principal from a security token service of the
    // import source, which this CDMI server is not configured
    // with, so the capability is absent and such an entry is
    // refused — including one that relies on the default.
    if (identity === undefined || identity === "delegated") {
      fail(capabilityNotPresent("cdmi_import_s3_delegation",
        "/cdmi_capabilities/",
        "no security token service is configured on this CDMI server, so an S3 " +
        "import is in service identity mode alone and the entry states it"));
    }
    // Service identity mode signs every request with one
    // credential, retrieved from a key management server as the
    // credential_id field identifies.
    if (str("credential_id") === undefined) {
      fail(invalidField(`${base}/credential_id`,
        "an S3 import in service identity mode names the credential it signs " +
        "with in the credential_id field"));
    }
    return e;
  }

  if (type === "NFS") {
    // An NFS import: the import source is a namespace held by an NFS
    // server, named by a URI of the form RFC 2224 defines.
    const parsed = parseNfsURI(uri!);
    if (parsed === undefined) {
      fail(invalidField(`${base}/import_uri`,
        "the import URI of an NFS import is of the form nfs://host/path/, and %j is not",
        uri));
    }
    e.import_uri = uri;

    const protocol = versionsOf(obj.protocol, ["NFSv4.1"]);
    if (protocol === undefined) {
      fail(invalidField(`${base}/protocol`,
        "the protocol field is a JSON array of the versions to negotiate, in order of preference"));
    }
    for (const version of protocol!) {
      if (NFS_PROTOCOLS[version] === undefined) {
        fail(invalidField(`${base}/protocol`,
          "%j is not a version of the NFS protocol this document defines", version));
      }
    }
    for (const version of protocol!) {
      if (!NFS_NEGOTIATED.includes(version)) {
        fail(capabilityNotPresent("cdmi_import_nfs_versions", "/cdmi_capabilities/",
          "seedmi negotiates %s with an import source", NFS_NEGOTIATED.join(" and ")));
      }
    }
    e.protocol = protocol;

    // A security flavour of "sys" carries a numeric identifier and no
    // authentication, so it is offered only where its capability is
    // present, and never as delegation.
    const security = str("security") ?? "krb5p";
    if (!["krb5", "krb5i", "krb5p", "sys"].includes(security)) {
      fail(invalidField(`${base}/security`,
        "%j is not a security flavour this document defines", security));
    }
    if (security !== "sys") {
      fail(capabilityNotPresent("cdmi_import_nfs_krb5", "/cdmi_capabilities/",
        "seedmi establishes no Kerberos context, and offers the %j security flavour alone",
        "sys"));
    }
    if (identity === "delegated") {
      fail(invalidField(`${base}/identity_mode`,
        'a security flavour of "sys" is not delegation, and shall not be specified ' +
        'together with an identity mode of "delegated"'));
    }
    e.security = security;
    e.identity_mode = "service";

    const transport = str("transport") ?? "tcp";
    if (transport !== "tcp" && transport !== "rdma") {
      fail(invalidField(`${base}/transport`, 'the transport is "tcp" or "rdma"'));
    }
    if (transport === "rdma") {
      fail(capabilityNotPresent("cdmi_import_nfs_rdma", "/cdmi_capabilities/",
        "seedmi reaches an import source over TCP alone"));
    }
    e.transport = transport;

    const port = str("port") ?? "2049";
    if (!/^(0|[1-9][0-9]*)$/.test(port) || Number(port) > 65535) {
      fail(invalidField(`${base}/port`, "the port is a decimal string naming a port"));
    }
    e.port = port;

    for (const k of ["anon_uid", "anon_gid"] as const) {
      const v = str(k);
      if (v !== undefined && !/^(0|[1-9][0-9]*)$/.test(v)) {
        fail(invalidField(`${base}/${k}`,
          "%j is a non-negative integer expressed as a decimal string", k));
      }
      e[k] = v;
    }

    const follow = str("follow_symlinks") ?? "false";
    if (follow !== "true" && follow !== "false") {
      fail(invalidField(`${base}/follow_symlinks`,
        'the follow_symlinks field is "true" or "false"'));
    }
    e.follow_symlinks = follow;
    // The security flavour this server offers is "sys" alone
    // (cdmi_import_nfs_authsys), which presents no credential: a keytab a
    // credential_id addresses is for a krb5 flavour, not offered. The field was
    // accepted and bound, and then not presented, before 0.49.
    if ("credential_id" in obj) {
      fail(invalidField(`${base}/credential_id`,
        'this CDMI server offers the NFS security flavour "sys" alone, which presents no credential; ' +
        "a keytab is presented only by a krb5 flavour, which it does not offer"));
    }
    return e;
  }

  // An image import (9.x): the import source is a data object of this
  // server whose value holds a file system.
  if (!uri!.startsWith("/") || uri!.endsWith("/")) {
    fail(invalidField(`${base}/import_uri`,
      "the import URI of an image import shall be the namespace path of a data object, which " +
      'does not end with "/"'));
  }
  if (!validNamespacePath(uri!)) {
    fail(invalidField(`${base}/import_uri`, "%j is not a valid namespace path", uri));
  }
  if (uri!.startsWith(ns)) {
    fail(invalidField(`${base}/import_uri`,
      "the import URI addresses %j, a data object within the importing container object %j",
      uri, ns));
  }
  e.import_uri = uri;

  // An image import supports service identity mode alone, and presents no
  // credential, since it is a local import.
  if (identity === "delegated") {
    fail(invalidField(`${base}/identity_mode`,
      'an image import supports service identity mode alone'));
  }
  e.identity_mode = "service";

  const filesystem = str("filesystem");
  if (filesystem === undefined) {
    fail(invalidField(`${base}/filesystem`,
      'the "filesystem" field is mandatory for an import entry of type "image"'));
  }
  // A name is compared without regard to case.
  if (!FILESYSTEMS.includes(filesystem!.toLowerCase())) {
    fail(capabilityNotPresent("cdmi_import_filesystems", "/cdmi_capabilities/",
      "seedmi interprets %s alone, and cannot interpret %j",
      FILESYSTEMS.join(", "), filesystem));
  }
  e.filesystem = filesystem;

  const partition = str("partition");
  const offset = str("offset");
  if (partition !== undefined && offset !== undefined) {
    fail(invalidField(`${base}/offset`,
      'the "partition" and "offset" fields shall not both be specified'));
  }
  // Whether the value holds a partition table, and whether that table
  // holds a partition of this number, are properties of the import
  // source and not of the entry, and are reported in last_problems.
  if (partition !== undefined && !/^[1-9][0-9]*$/.test(partition)) {
    fail(invalidField(`${base}/partition`,
      "the partition shall be a decimal string"));
  }
  if (offset !== undefined && !/^(0|[1-9][0-9]*)$/.test(offset)) {
    fail(invalidField(`${base}/offset`,
      "the offset shall be a non-negative decimal integer"));
  }
  e.partition = partition;
  e.offset = offset;
  return e;
}

/**
 * The syntax of a CDMI import URI (9.4) and the self-reference rule of 9.2:
 * the URI shall not address the importing container object itself, a
 * container object that contains it, or a namespace within it. The rule is
 * evaluated against the path by which the request addresses the importing
 * object; an entry it does not reject but that forms a cycle is caught by
 * cycle detection.
 */
function checkCDMIImportURI(uri: string, ns: string, field: string,
  fail: (c: Condition) => never): void {
  if (!uri.endsWith("/")) {
    fail(invalidField(field, 'the import URI of a CDMI import shall end with "/"'));
  }
  let p = uri;
  if (!uri.startsWith("/")) {
    let parsed: URL;
    try {
      parsed = new URL(uri);
    } catch {
      fail(invalidField(field,
        "the import URI shall be a namespace path or an absolute http or https URI"));
    }
    if ((parsed!.protocol !== "http:" && parsed!.protocol !== "https:") ||
      parsed!.host === "" || parsed!.search !== "" || parsed!.hash !== "") {
      fail(invalidField(field,
        "the import URI shall be a namespace path or an absolute http or https URI"));
    }
    const local = localImportPath(uri);
    if (local === undefined) {
      // A remote import. The self-reference rules below test the
      // position of the source within a namespace, and a source held by
      // another server is in none of this server's namespace, so they
      // do not apply to it.
      if (!uri.endsWith("/")) {
        fail(invalidField(field,
          "the import URI of a CDMI import addresses a container object, and shall end " +
          'with "/"'));
      }
      return;
    }
    p = local!;
  }
  if (!validNamespacePath(p)) {
    fail(invalidField(field, "%j is not a valid namespace path", p));
  }
  if (p === ns) {
    fail(invalidField(field, "the import URI addresses the importing container object itself"));
  }
  if (ns.startsWith(p)) {
    fail(invalidField(field,
      "the import URI addresses %j, a container object that contains the importing container " +
      "object %j", p, ns));
  }
  if (p.startsWith(ns)) {
    fail(invalidField(field,
      "the import URI addresses %j, a namespace within the importing container object %j", p, ns));
  }
}

/** A namespace path: it begins with a solidus and has no empty or dot segment. */
export function validNamespacePath(p: string): boolean {
  if (!p.startsWith("/")) return false;
  if (p === "/") return true;
  const segs = p.replace(/\/$/, "").split("/").slice(1);
  return segs.every((s) => s !== "" && s !== "." && s !== ".." && !s.includes("?") &&
    !s.includes("#"));
}
