// HTTP exports of clause 8. An export entry on a container object serves
// the objects within it as ordinary HTTP resources: the value of a data
// object rather than its CDMI representation.
//
// seedmi serves exports at one scheme and one port, which it is told rather
// than deriving from its listening socket, because a server behind an
// intermediary is reached at an address it cannot see (revision 49).

import { uploadedFile } from "./multipart.ts";
import { randomUUID } from "node:crypto";
import { boundReference } from "./credential.ts";
import { HTTP_EXPORT_VERSIONS, parseVersions } from "./protocol-versions.ts";
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  decideFor, delegatedHeaders, delegatedMask, delegationOf, DelegationRefused, withDelegation,
} from "./dac-context.ts";
import type { DacClient } from "./dac.ts";
import { createHash } from "node:crypto";
import type { Meta, Node, Store } from "./store.ts";
import type { Log } from "./log.ts";
import {
  Resolver, type View, denyChange, ensureWriteTarget, listChildren, presentable, rankCmp,
  referenceIn, resolveFile,
} from "./layers.ts";
import { nodeOf, type ObjRef, readValueOf, viewOf } from "./objects.ts";
import { isEncryptedMediaType, readEncryptedValue } from "./encrypted.ts";
import { restrictedWithin, underRestriction } from "./retention.ts";
import { parseS3Entry, type S3Export } from "./s3.ts";
import { serveBucket } from "./s3-serve.ts";
import { Uploads } from "./s3-multipart.ts";
export { type S3Export };
import {
  checkTopic, MQTT_VERSIONS, type MqttTls, parseBrokerURI, parseImportURI,
  parseTls, RECONNECT_STRATEGIES,
} from "./mqtt-entry.ts";
export {
  checkTopic, MQTT_VERSIONS, type MqttTls, parseBrokerURI, parseImportURI,
  parseTls, RECONNECT_STRATEGIES,
};
import { answerPreflight, applyCors, isPreflight } from "./cors.ts";
import {
  defaultType, derive, heldType, negotiate, orderedFor, REPRESENTABLE_LIMIT,
  type Representation, typesOf, VALUE_REPRESENTATIONS,
} from "./representations.ts";
import { capabilityWithheld, capabilityCondition,
  seedmiProblem,
  capabilityNotPresent, cdmiTime, Condition, conflict, conflictImportLayer,
  conflictingFields, forbidden, invalidField, malformed,
  notAcceptable, notFound, type Problem, problem, exportAddressUnavailable, exportNameInUse,
} from "./problems.ts";
import { ANONYMOUS, M, aclForNewObject, granted, type Principal } from "./acl.ts";
import { ownBases, versionsOf} from "./imports.ts";
import { metadataUrl } from "./mcp-auth.ts";

/** The client-supplied fields of an NFS export entry. */
export interface NfsExport {
  type: string;
  /** The versions the server offers, of which a client negotiates one. */
  protocol: string[];
  path: string;
  usermap?: string[][];
  groupmap?: string[][];
  security_flavors?: string[];
  domain?: string;
  domain_servers?: string[];
  squash?: string;
  anon_uid?: string;
  anon_gid?: string;
  root_hosts?: string[];
  rw_hosts?: string[];
  ro_hosts?: string[];
  recurse?: string;
  write_mode?: string;
  subtree_check?: string;
  rdma_enabled?: string;
  disabled?: string;
}

/** An export entry of either type seedmi accepts. */
export type ExportEntry =
  | HttpExport
  | NfsExport
  | SmbExport
  | MqttExport
  | S3Export;

export const isS3 = (e: ExportEntry): e is S3Export => e.type === "S3";

/**
 * What an SMB export entry needs of an SMB server: the shares it
 * offers, kept in step with the entries. The interface is stated here
 * rather than imported so that the export machinery does not depend
 * on the protocol implementation.
 */
/**
 * What an NFS export entry needs of an NFS server: the exports it
 * offers, kept in step with the entries. Stated here rather than
 * imported, so that the export machinery does not depend on the
 * protocol implementation.
 */
export interface NfsShares {
  offer(shared: {
    /** The name of the export entry. */
    name: string;
    /** The path the entry states, within the namespace of the export. */
    path: string;
    /** The namespace path of the container object presented. */
    ns: string;
    /** Whether every host admitted is admitted read only. */
    readOnly: boolean;
  }): void;
  withdraw(name: string): void;
  /** The names of the entries now offered. */
  offered(): string[];
  /** Whether the server is listening. */
  running(): boolean;
}

/**
 * What an MQTT export entry needs of the publisher: the exports it
 * has established and what each reports. Stated here so that the
 * export machinery does not depend on the MQTT implementation.
 */
export interface MqttPublisher {
  offer(name: string, entry: MqttExport, node: Node): void;
  withdraw(name: string): void;
  offered(): string[];
  state(name: string): {
    connected: boolean;
    published: number;
    pending: number;
    dropped: number;
    lastConnected: string;
    problems: Problem[];
  } | undefined;
  /** Whether this CDMI server connects to a broker at all. */
  readonly connecting: boolean;
}

export interface SmbShares {
  offer(share: {
    name: string;
    dialects: number[];
    signingRequired: boolean;
    anonymous: boolean;
    mount?: {
      store: Store;
      path: string;
      readOnly: boolean;
      usermap?: string[][];
      groupmap?: string[][];
      extendedAttributes?: boolean;
    };
  }): void;
  withdraw(name: string): void;
  /** The names of the shares now offered. */
  offered(): string[];
  /** Whether the server is listening. */
  running(): boolean;
  /** The revision number of each version name. */
  revisions(names: string[]): number[];
}

export const isNfs = (e: ExportEntry): e is NfsExport => e.type === "NFS";

/**
 * Whether an entry is an HTTP export. Asked of the entry rather than
 * by excluding every other type: a list of what a thing is not grows
 * a hole each time a type is defined, and this one grew two, an MQTT
 * entry and then an S3 entry each being taken for an HTTP export
 * until the exclusion was added.
 */
export const isHttp = (e: ExportEntry): e is HttpExport => e.type === "HTTP";
export const isSmb = (e: ExportEntry): e is SmbExport => e.type === "SMB";

/** The client-supplied fields of an HTTP export entry. */
/** An element of the certificates field: an origin and a KMIP identifier. */
export interface ExportCertificate {
  origin: string;
  certificate_id: string;
}

export interface HttpExport {
  /**
   * Origins this entry names that this server cannot serve at present. Such
   * a value is well formed, so the entry stands; the origins are left out of
   * origins_provided and the reason is reported (revision 347).
   */
  unservable?: string[];
  /**
   * A CDMI export's base URI, formed from the first origin and the path.
   * "CDMI server populated, and ignored where a CDMI client supplies it."
   */
  base_uri?: string;
  type: string;
  origins: string[];
  path: string;
  /** The HTTP versions offered, where the entry states them. */
  protocol?: string[];
  certificates?: ExportCertificate[];
  read_only?: string;
  auth_method?: string;
  anonymous_read?: string;
  index_document?: string;
  error_document?: string;
  max_age?: string;
  disabled?: string;
}

const FIELDS = new Set([
  "type", "origins", "path", "certificates", "read_only", "auth_method", "anonymous_read",
  "index_document", "error_document", "max_age", "disabled", "protocol",
  // CDMI server populated: accepted and ignored, so a client may write back
  // what it read.
  "origins_provided", "certificate_expiry", "active", "last_problems", "state_determined_time",
]);

/** Export types the draft defines that seedmi does not implement. */
const OTHER_TYPES = ["SMB", "S3", "iSCSI", "NVMe", "MQTT"];

/**
 * The versions of this document served through a CDMI export, as the
 * cdmi_export_cdmi_versions capability reports them.
 */
export const CDMI_EXPORT_VERSIONS = ["CDMIv3.0"];

/** The fields of a CDMI export entry, and those common to every entry. */
const CDMI_FIELDS = new Set([
  "type", "protocol", "origins", "path", "read_only", "base_uri",
  "disabled", "description", "name", "certificates",
  // CDMI server populated: accepted and ignored, so a CDMI client may write back
  // what it read. The exports model makes "active", "last_problems" and
  // "state_determined_time" Mandatory fields of every export entry and says of
  // each that it "is CDMI server populated and shall be ignored if specified in a
  // create or update", and an inbound export reports its addresses in a populated
  // field of its own, which for this type is "origins_provided" as it is for an
  // HTTP export. This set omitted all four until 0.114, while the report emitted
  // them — so a CDMI client that read a CDMI export entry and wrote it back
  // unchanged was refused with the invalid field condition, for fields the
  // document requires a CDMI server to ignore. Every other export type of this
  // server accepted them; this one type did not.
  "origins_provided", "active", "last_problems", "state_determined_time",
]);

/** An export entry of type SMB. */
export interface SmbExport {
  type: string;
  /** The versions the server offers, of which a client negotiates one. */
  protocol: string[];
  sharename: string;
  comment?: string;
  domain?: string;
  domain_servers?: string[];
  usermap?: string[][];
  groupmap?: string[][];
  rw_hosts?: string[];
  ro_hosts?: string[];
  root_hosts?: string[];
  auth_methods?: string[];
  signing?: string;
  encryption?: string;
  access_based_enumeration?: string;
  oplocks?: string;
  continuous_availability?: string;
  dfs_enabled?: string;
  shadow_copies?: string;
  max_connections?: string;
  disabled?: string;
  active?: string;
  server_addresses?: string[];
  last_problems?: unknown[];
  state_determined_time?: string;
}

const SMB_FIELDS = new Set([
  "type", "protocol", "sharename", "comment", "domain", "domain_servers", "usermap",
  "groupmap", "rw_hosts", "ro_hosts", "root_hosts", "auth_methods", "signing",
  "encryption", "access_based_enumeration", "oplocks", "continuous_availability",
  "dfs_enabled", "shadow_copies", "max_connections", "disabled",
  // CDMI server populated: accepted and ignored.
  "active", "server_addresses", "last_problems", "state_determined_time",
]);

/** The SMB versions, and the capability each requires. */
const SMB_PROTOCOLS: Record<string, string> = {
  SMB2: "cdmi_export_smb_2",
  "SMB2.1": "cdmi_export_smb_2_1",
  SMB3: "cdmi_export_smb_3",
  "SMB3.0.2": "cdmi_export_smb_3_0_2",
  "SMB3.1.1": "cdmi_export_smb_3_1_1",
};

/** The versions for which transport encryption is defined. */
const SMB_ENCRYPTING = ["SMB3", "SMB3.0.2", "SMB3.1.1"];

/** The characters a share name shall not contain. */
const SHARENAME_FORBIDDEN = /[\\/:*?"<>|]/;

const NFS_FIELDS = new Set([
  "type", "protocol", "path", "usermap", "groupmap", "security_flavors", "domain",
  "domain_servers", "squash", "anon_uid", "anon_gid", "root_hosts", "rw_hosts",
  "ro_hosts", "recurse", "write_mode", "subtree_check", "rdma_enabled", "disabled",
  // CDMI server populated: accepted and ignored.
  "active", "server_addresses", "last_problems", "state_determined_time",
]);

/** The NFS versions, and the capability each requires. */
const NFS_PROTOCOLS: Record<string, string> = {
  NFSv3: "cdmi_export_nfs_v3",
  NFSv4: "cdmi_export_nfs_v4",
  "NFSv4.1": "cdmi_export_nfs_v4_1",
  "NFSv4.2": "cdmi_export_nfs_v4_2",
};

/** The security flavors, and the capability each requires, where any. */
const NFS_FLAVORS: Record<string, string | undefined> = {
  sys: undefined,
  krb5: "cdmi_export_nfs_krb5",
  krb5i: "cdmi_export_nfs_krb5",
  krb5p: "cdmi_export_nfs_krb5",
  tls: "cdmi_export_nfs_tls",
};

const SQUASH = ["root_squash", "no_root_squash", "all_squash"];
const MAP_OPERATORS = ["<--", "<-->", "-->"];

const readOnly = (e: HttpExport) => e.read_only !== "false";
const disabled = (e: ExportEntry) => e.disabled === "true";

// ---------------------------------------------------------------------------
// Origins

export interface Origin {
  scheme: string;
  host: string;
  port: string;
}

const defaultPort = (scheme: string) => (scheme === "https" ? "443" : "80");

/**
 * Whether a name is an export or import type "defined by another
 * organization", which 9.1 and 10.1 say should be "the reverse domain name
 * of that organization, followed by an underscore and a name of its
 * choosing, as an extension field is named". The same form an extension
 * field takes, so the same test serves both.
 */
export function isExtensionTypeName(type: string): boolean {
  const cut = type.lastIndexOf("_");
  if (cut <= 0 || cut === type.length - 1) return false;
  const domain = type.slice(0, cut);
  return domain.includes(".") &&
    domain.split(".").every((l) => /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/.test(l));
}

/**
 * Whether the name of a header field carries a user metadata item.
 * The pattern is "x-*-meta-*", matched without regard to case, where
 * each asterisk stands for one or more characters.
 */
export function isMetadataHeader(name: string): boolean {
  return /^x-.+-meta-.+$/i.test(name);
}

/**
 * Whether a metadata item of that pattern can be carried as a header field:
 * its name must be a field name, which RFC 9110 defines as a token. An item
 * whose name is not one is stored as any other user metadata item and is
 * omitted from the header fields, as the draft requires of an item whose
 * *value* is not a valid field value; it says nothing of the name, which is
 * ECR-155A (weedmi META-011).
 */
export function carriedAsHeader(name: string, value: unknown): boolean {
  return isMetadataHeader(name) && typeof value === "string" && isFieldName(name) &&
    isFieldValue(value);
}

/** A field name is a token, as RFC 9110 defines one. */
export const isFieldName = (name: string): boolean =>
  /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name);

/**
 * A field value holds no control character and no line break, as RFC 9110
 * defines one. A value carrying CR LF would let an item write a header field
 * of its own through an HTTP export, which is why the rule exists.
 */
// eslint-disable-next-line no-control-regex
export const isFieldValue = (value: string): boolean => !/[\u0000-\u001f\u007f]/.test(value);

/**
 * "Where such an item is created or updated by any operation, its name shall
 * be a field name and its value shall be a JSON string that is a field
 * value, each as defined in RFC 9110 ... A CDMI server shall report the
 * invalid field condition where they do not."
 *
 * This server stored such an item and omitted it from the header fields of
 * an HTTP export before 0.83, on the reading that the document said nothing
 * of the name. It says it here, of the name and of the value alike, and of
 * "any operation" and not of the export alone (weedmi META-011).
 */
export function checkHeaderMetadataItem(name: string, value: unknown): void {
  if (!isMetadataHeader(name)) return;
  if (!isFieldName(name)) {
    throw invalidField(`metadata/${name}`,
      "a metadata item whose name matches \"x-*-meta-*\" is carried in a header field, " +
      "so its name shall be a field name, which RFC 9110 defines as a token");
  }
  if (typeof value !== "string" || !isFieldValue(value)) {
    throw invalidField(`metadata/${name}`,
      "a metadata item whose name matches \"x-*-meta-*\" is carried in a header field, " +
      "so its value shall be a JSON string that is a field value, which holds no " +
      "control character and no line break");
  }
}

/**
 * The user metadata items a request carries in header fields. A field
 * whose value is empty removes the item, which is why the value may be
 * an empty string.
 */
export function headerMetadata(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if (!isMetadataHeader(name)) continue;
    out[name] = Array.isArray(value) ? value.join(", ") : String(value ?? "");
  }
  return out;
}

/** The limits this server applies to metadata carried in header fields. */
export const HEADER_METADATA_MAXITEMS = 64;
export const HEADER_METADATA_MAXSIZE = 4096;
export const HEADER_METADATA_MAXTOTALSIZE = 16384;

/**
 * Checks the user metadata a request carries in header fields against
 * the limits this server applies, and against the reserved prefix.
 */
export function checkHeaderMetadata(items: Record<string, string>):
  Record<string, string> {
  const names = Object.keys(items);
  if (names.length > HEADER_METADATA_MAXITEMS) {
    throw malformed("a request carries at most %s metadata items in header fields",
      String(HEADER_METADATA_MAXITEMS));
  }
  let total = 0;
  for (const [k, v] of Object.entries(items)) {
    const size = Buffer.byteLength(k, "utf8") + Buffer.byteLength(v, "utf8");
    if (size > HEADER_METADATA_MAXSIZE) {
      throw malformed("the metadata item %j is larger than this server carries in a " +
        "header field", k);
    }
    total += size;
  }
  if (total > HEADER_METADATA_MAXTOTALSIZE) {
    throw malformed("the metadata carried in header fields is larger than this server " +
      "accepts");
  }
  return items;
}

/** Whether a request arrived over TLS. */
export function encrypted(req: IncomingMessage): boolean {
  return (req as unknown as { socket?: { encrypted?: boolean } }).socket?.encrypted === true;
}

/** Serializes an origin: the port appears only where it is not the default. */
export function originOf(o: Origin): string {
  return o.port === defaultPort(o.scheme)
    ? `${o.scheme}://${o.host}`
    : `${o.scheme}://${o.host}:${o.port}`;
}

/** Parses an origin of an origins field, or explains why it is not one. */
export function parseOrigin(s: string): { origin?: Origin; why?: string } {
  const sep = s.indexOf("://");
  if (sep < 0) return { why: 'the scheme shall be "http" or "https", followed by "://"' };
  const scheme = s.slice(0, sep);
  if (scheme !== "http" && scheme !== "https") {
    return { why: 'the scheme shall be "http" or "https"' };
  }
  let rest = s.slice(sep + 3);
  let port = defaultPort(scheme);
  const colon = rest.lastIndexOf(":");
  if (colon >= 0) {
    const p = rest.slice(colon + 1);
    rest = rest.slice(0, colon);
    if (!/^[1-9][0-9]{0,4}$/.test(p) || Number(p) > 65535) {
      return { why: "a port shall be a decimal integer between 1 and 65535 with no leading zero" };
    }
    if (p === defaultPort(scheme)) {
      return { why: "the default port of the scheme is written by omitting it" };
    }
    port = p;
  }
  if (rest === "") return { why: "a host is required" };
  if (/[/?#@[\]\\]/.test(rest)) {
    return { why: "an origin shall contain no userinfo, path, query or fragment" };
  }
  if (rest !== rest.toLowerCase()) {
    return { why: "the host shall be given in lower case, and is not converted" };
  }
  if (rest.endsWith(".")) return { why: "the host shall not end with a full stop" };
  if (/[^\x20-\x7e]/.test(rest)) return { why: "the host shall be given in A-label form" };
  if (/^\d+\.\d+\.\d+\.\d+$/.test(rest)) return { why: "the host shall not be an IP address" };
  const labels = rest.split(".");
  if (labels.length < 2) return { why: "the host shall not consist of a single label" };
  for (const l of labels) {
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l)) {
      return { why: `${JSON.stringify(l)} is not a valid host label` };
    }
  }
  return { origin: { scheme, host: rest, port } };
}

/** Validates a value of the cdmi_export_http_origins capability. */
export function checkOriginCap(c: string): string | undefined {
  const sep = c.indexOf("://");
  if (sep < 0) return `${c}: the scheme shall be "http" or "https"`;
  const scheme = c.slice(0, sep);
  let rest = c.slice(sep + 3);
  let port = "";
  const colon = rest.lastIndexOf(":");
  if (colon >= 0) {
    port = rest.slice(colon);
    rest = rest.slice(0, colon);
  }
  const probe = rest === "*" ? "x.example" : rest.startsWith("*.") ? "x" + rest.slice(1) : rest;
  const { why } = parseOrigin(`${scheme}://${probe}${port}`);
  return why ? `${c}: ${why}` : undefined;
}

/** Whether an origin matches a value of the origins capability. */
export function matchOriginCap(o: Origin, c: string): boolean {
  const sep = c.indexOf("://");
  if (sep < 0 || c.slice(0, sep) !== o.scheme) return false;
  let rest = c.slice(sep + 3);
  let port = defaultPort(o.scheme);
  const colon = rest.lastIndexOf(":");
  if (colon >= 0) {
    port = rest.slice(colon + 1);
    rest = rest.slice(0, colon);
  }
  if (port !== o.port) return false;
  rest = rest.toLowerCase();
  if (rest === "*") return true;
  if (rest.startsWith("*.")) {
    const suffix = rest.slice(1);
    if (!o.host.endsWith(suffix)) return false;
    const label = o.host.slice(0, o.host.length - suffix.length);
    return label !== "" && !label.includes(".");
  }
  return o.host === rest;
}

// ---------------------------------------------------------------------------
// Validation

function validExportPath(p: string): string | undefined {
  if (!p.startsWith("/") || !p.endsWith("/")) return 'the path shall begin and end with "/"';
  if (p.includes("//")) return 'the path shall not contain consecutive "/" characters';
  if (/[?#]/.test(p)) return "the path shall not contain a query or fragment";
  for (const seg of p.split("/")) {
    if (seg === "." || seg === "..") return "the path shall not contain a dot segment";
  }
  return undefined;
}

const overlap = (a: string, b: string) => a.startsWith(b) || b.startsWith(a);

/** Validates a complete exports field. */
export function parseExports(raw: unknown, caps: string[], basePath: string,
  features: string[] = []): Record<string, ExportEntry> {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw invalidField("/exports",
      'the "exports" field shall be a JSON object whose members are export entries');
  }
  const obj = raw as Record<string, unknown>;
  const out: Record<string, ExportEntry> = {};
  for (const name of Object.keys(obj).sort()) {
    if (obj[name] === null) continue; // removed
    if (name === "" || /[/?]/.test(name)) {
      throw invalidField("/exports",
        'an export name shall not be empty and shall not contain "/" or "?"');
    }
    const entry = obj[name];
    const type = entry !== null && typeof entry === "object" && !Array.isArray(entry)
      ? (entry as Record<string, unknown>).type
      : undefined;
    out[name] = type === "NFS"
      ? parseNfsEntry(name, entry, features)
      : type === "SMB"
      ? parseSmbEntry(name, entry, features)
      : type === "MQTT"
      ? parseMqttEntry(name, entry, features)
      : type === "S3"
      ? parseS3Entry(name, entry)
      : httpOffered(caps, basePath, name) ?? parseEntry(name, entry, caps, basePath);
  }
  const names = Object.keys(out);
  for (let i = 0; i < names.length; i++) {
    for (let j = i + 1; j < names.length; j++) {
      const a = out[names[i]];
      const b = out[names[j]];
      // An NFS export occupies a path of the file system the server
      // presents, which is one namespace rather than one per origin, so
      // two of them conflict on the path alone.
      if (isNfs(a) || isNfs(b)) {
        if (isNfs(a) && isNfs(b) && overlap(`${a.path}/`, `${b.path}/`)) {
          throw conflict(
            "the path %j of export %j is equal to, a prefix of, or prefixed by the " +
            "path %j of export %j", b.path, names[j], a.path, names[i])
            .with("cdmi_export", names[j]).with("cdmi_export_conflict", names[i]);
        }
        continue;
      }
      // An SMB export occupies a share name, which is one namespace of
      // the CDMI server: two entries conflict where they name the same
      // share, and an SMB entry conflicts with nothing else.
      if (isSmb(a) || isSmb(b)) {
        if (isSmb(a) && isSmb(b) &&
          a.sharename.toLowerCase() === b.sharename.toLowerCase()) {
          throw conflict(
            "the share name %j of export %j is the share name of export %j; a share " +
            "name is matched without regard to case", b.sharename, names[j], names[i])
            .with("cdmi_export", names[j]).with("cdmi_export_conflict", names[i]);
        }
        continue;
      }
      // An MQTT export occupies a topic of a broker rather than a
      // path or a share name of this CDMI server. Two entries naming
      // one topic of one broker publish the same values twice, which
      // a CDMI client may intend, so neither conflicts with the other
      // nor with an export of another type.
      if (isMqtt(a) || isMqtt(b)) continue;
      // An S3 export occupies a bucket name, which is checked across
      // every object rather than within one entry list.
      if (isS3(a) || isS3(b)) {
        if (isS3(a) && isS3(b) && a.bucket_name === b.bucket_name) {
          throw conflictingFields(`/exports/${names[i]}/bucket_name`,
            "the bucket name %j is in use by the %j export of this object",
            a.bucket_name, names[j])
            .with("cdmi_export", names[i])
            .with("cdmi_export_conflict", names[j]);
        }
        continue;
      }
      // An HTTP entry whose path is a base URI of the protocol binding is
      // exempt: requests there are dispatched by media type, not by path.
      if (a.path === basePath || b.path === basePath) continue;
      // And likewise where the base URI is one a CDMI export of this same
      // container object establishes. Both entries present this object, so one
      // request URI names one object either way, and the pair is the migration
      // arrangement of the document: "the CDMI server shall select that export
      // for a request that names no CDMI media type in its Content-Type or
      // Accept header field, and shall serve every other request as a request
      // of the protocol binding". The HTTP export is what the previous edition
      // called a non-CDMI request, and the two are complementary rather than
      // ambiguous. seedmi refused the pair with the conflict condition until
      // 0.98, recognizing the exemption for the configured base URI alone.
      if (basePairOn(a, b)) continue;
      const shared = a.origins.find((o) => b.origins.includes(o));
      if (shared && overlap(a.path, b.path)) {
        // Two entries are named: cdmi_export the one being validated,
        // and cdmi_export_conflict the one it clashes with.
        throw conflict(
          "the path %j of export %j is equal to, a prefix of, or prefixed by the path %j of " +
          "export %j, both served at %s", b.path, names[j], a.path, names[i], shared)
          .with("cdmi_export", names[j]).with("cdmi_export_conflict", names[i]);
      }
    }
  }
  return out;
}

/**
 * An HTTP export where no origin is offered. The cdmi_export_http_origins
 * capability is then an empty array, which revision 269 reads as withheld: "A
 * capability that is present with a value indicating that the functionality is
 * not offered, being false or an empty string, array or object, indicates that
 * the functionality is supported and withheld", and an operation requiring it is
 * refused with the capability withheld condition. Before 0.61 such an entry was an
 * invalid field, its origin matching no value. Returns nothing where origins are offered.
 */
function httpOffered(caps: string[], basePath: string, name: string): undefined {
  if (caps.length > 0) return undefined;
  // "The namespace path of the capability object that a CDMI client reads in
  // order to confirm the absence reported by the cdmi_capability member"
  // (Annex C): the object that publishes the capability, which is the root of
  // the capability hierarchy now that the capability is a feature of the export
  // type rather than a property of one container object (ECR-223A). It named
  // the container object's in 0.99 and 0.100, and the root before that.
  throw capabilityWithheld("cdmi_export_http_origins",
    `${basePath}cdmi_capabilities/`,
    "the HTTP export %j names an origin, and this server offers no origin at which to serve an HTTP export", name);
}

function parseEntry(name: string, raw: unknown, caps: string[], basePath = "/"): HttpExport {
  const f = `/exports/${name}`;
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw invalidField(f, "an export entry shall be a JSON object");
  }
  const obj = raw as Record<string, unknown>;
  const str = (k: string): string | undefined => {
    const v = obj[k];
    if (v === undefined || v === null) return undefined;
    if (typeof v !== "string") throw invalidField(`${f}/${k}`, "the %j field shall be a JSON string", k);
    return v;
  };
  const bool = (k: string): string | undefined => {
    const v = str(k);
    if (v === undefined) return undefined;
    if (v !== "true" && v !== "false") {
      throw invalidField(`${f}/${k}`, 'the %j field shall be "true" or "false"', k);
    }
    return v;
  };

  const type = str("type");
  if (type === undefined) throw invalidField(`${f}/type`, 'an export entry shall contain a "type" field');
  if (OTHER_TYPES.includes(type)) {
    throw capabilityCondition(
      `seedmi does not implement exports of type ${JSON.stringify(type)}`)
      .with("cdmi_capability", `cdmi_export_${type.toLowerCase()}`);
  }
  // "A CDMI export presents a container object, and the objects it
  // contains, at a base URI of an origin the CDMI server serves. At that
  // base URI the container object is the root container object." Its
  // entry carries the fields of an HTTP export's origins and path, and a
  // protocol field naming the versions served.
  if (type === "CDMI") {
    for (const k of Object.keys(obj)) {
      if (!CDMI_FIELDS.has(k)) {
        throw invalidField(`${f}/${k}`,
          'the field %j is not defined for an export entry of type "CDMI"', k);
      }
    }
    const versions = obj.protocol;
    if (versions !== undefined) {
      if (!Array.isArray(versions) || versions.some((v) => typeof v !== "string")) {
        throw invalidField(`${f}/protocol`, "the protocol field is an array of JSON strings");
      }
      for (const v of versions as string[]) {
        if (!CDMI_EXPORT_VERSIONS.includes(v)) {
          throw invalidField(`${f}/protocol`,
            "%j is not a version this CDMI server serves through an export; it serves %s",
            v, CDMI_EXPORT_VERSIONS.join(", "));
        }
      }
    }
  } else if (type !== "HTTP") {
    // "An export type defined by another organization should be named by the
    // reverse domain name of that organization, followed by an underscore
    // and a name of its choosing, as an extension field is named" (9.1). A
    // type of that form is one this document provides for and this server
    // does not serve, which is the capability not present condition, as it
    // is for an import type of the same form. A name of any other form is
    // an export type neither this document nor another organization
    // defines, which is the invalid field condition.
    //
    // This server reported the invalid field condition for both, saying
    // that the document defines no such type — which is not what the
    // document says of an extension name, and which told a vendor following
    // 9.1 that its own name was malformed. Annex A refuses such a name too,
    // export-type being a closed set, which is ECR-182B.
    if (isExtensionTypeName(type)) {
      throw capabilityNotPresent(`cdmi_export_${type.toLowerCase()}`, "/cdmi_capabilities/",
        "this CDMI server serves no export of type %j", type);
    }
    throw invalidField(`${f}/type`,
      "%j is neither an export type this document defines nor one named as 9.1 names an " +
      "export type of another organization", type);
  }
  if (type === "HTTP") {
    for (const k of Object.keys(obj)) {
      if (!FIELDS.has(k)) {
        throw invalidField(`${f}/${k}`,
          'the field %j is not defined for an export entry of type "HTTP"', k);
      }
    }
  }

  const rawOrigins = obj.origins;
  if (!Array.isArray(rawOrigins) || rawOrigins.length === 0) {
    throw invalidField(`${f}/origins`,
      'the "origins" field shall be a JSON array of at least one origin');
  }
  const origins: string[] = [];
  // Origins the entry names that this server cannot serve: kept, reported
  // in last_problems, and left out of origins_provided.
  const unservable: string[] = [];
  const seen = new Set<string>();
  for (const o of rawOrigins) {
    if (typeof o !== "string") {
      throw invalidField(`${f}/origins`, "each origin shall be a JSON string");
    }
    const { origin, why } = parseOrigin(o);
    if (!origin) throw invalidField(`${f}/origins`, "%j is not a permitted origin: %s", o, why);
    const canonical = originOf(origin);
    if (seen.has(canonical)) {
      throw invalidField(`${f}/origins`, "the origin %j is listed more than once", o);
    }
    seen.add(canonical);
    if (!caps.some((c) => matchOriginCap(origin, c))) {
      // "... and not a value that is well formed but that the CDMI server
      // is not at present able to serve" (revision 347): an origin this
      // server cannot serve is well formed, so the entry is accepted, the
      // origin is left out of origins_provided, and the reason is recorded
      // in last_problems. This server refused such an entry at creation
      // until 0.79 (weedmi EXPT, ECR-162B).
      unservable.push(o);
    }
    origins.push(canonical);
  }

  const path = str("path");
  if (path === undefined) {
    throw invalidField(`${f}/path`, 'an HTTP export entry shall contain a "path" field');
  }
  const why = validExportPath(path);
  if (why) throw invalidField(`${f}/path`, "%s", why);

  const e: HttpExport = { type, origins, path };
  // The HTTP versions offered, checked against cdmi_export_http_versions.
  if ("protocol" in obj) {
    // The versions an entry names are those its own capability offers: an
    // HTTP export serves versions of HTTP, and a CDMI export versions of
    // this document (revision 327).
    e.protocol = type === "CDMI"
      ? parseVersions(`${f}/protocol`, obj.protocol,
        "cdmi_export_cdmi_versions", CDMI_EXPORT_VERSIONS)
      : parseVersions(`${f}/protocol`, obj.protocol,
        "cdmi_export_http_versions", HTTP_EXPORT_VERSIONS);
  }

  // The certificates field associates an https origin with a
  // certificate held elsewhere. No key material appears here: the
  // entry names an identifier, which the server resolves.
  // "certificates": each element names a Certificate and the Private Key that
  // corresponds to it, and "The CDMI server shall ... request the key
  // management server to produce the signature the handshake requires using the
  // managed object that key_id addresses, and shall not retrieve that private
  // key." The TLS implementation this server uses signs a handshake with a key
  // it holds and offers no means of having the signature produced elsewhere, so
  // it cannot present a certificate an entry names. It refuses the field, as it
  // refuses an MQTT entry's client certificate, rather than retrieve the key or
  // ignore the field. The field is optional: "For an origin for which no element
  // is present, or where the field is absent, the CDMI server shall obtain a
  // certificate by its own means", which it does from the certificates it is
  // configured with. Before 0.51 the field was accepted with a certificate_id
  // naming a certificate of seedmi.toml and no key_id, a form no revision defines.
  //
  // Revision 269 names the condition: "Support is indicated by the
  // cdmi_export_http_certificates capability, and a CDMI server shall report the
  // capability not present condition where this field is supplied and that
  // capability is unavailable" (ECR-114B). This server does not publish it.
  // Before 0.61 the field was refused as an invalid field.
  if ("certificates" in obj) {
    throw capabilityNotPresent("cdmi_export_http_certificates", `${basePath}cdmi_capabilities/`,
      "this CDMI server cannot present a certificate an entry names: its private key is to be operated in place " +
      "by the key management server during the TLS handshake, which the TLS implementation this server uses " +
      "cannot do, and the key shall not be retrieved. A certificate this server holds for the origin's host is " +
      "presented without the field");
  }

  e.read_only = bool("read_only");
  e.disabled = bool("disabled");
  e.anonymous_read = bool("anonymous_read");

  // "auth_method: the HTTP authentication scheme by which a request is
  // associated with a principal", one of the values the draft names, and a
  // value other than "anonymous" shall be one this server advertises in
  // cdmi_authentication_methods. What it advertises depends on the domain
  // and its configuration, so the value is checked here against the
  // schemes this server can perform at all, and against the domain's own
  // list when a request arrives.
  const auth = str("auth_method");
  if (auth !== undefined && !EXPORT_AUTH_METHODS.includes(auth)) {
    throw invalidField(`${f}/auth_method`,
      "the authentication scheme of an HTTP export is one of %s",
      EXPORT_AUTH_METHODS.join(", "));
  }
  e.auth_method = auth;

  const index = str("index_document");
  if (index !== undefined && (index.includes("/") || index === "." || index === "..")) {
    throw invalidField(`${f}/index_document`, "the index document shall be a single object name");
  }
  e.index_document = index;

  const error = str("error_document");
  if (error !== undefined) {
    if (error === "" || error.startsWith("/") || error.endsWith("/") ||
      error.split("/").some((s) => s === "" || s === "." || s === "..")) {
      throw invalidField(`${f}/error_document`,
        "the error document shall be the relative path of a data object");
    }
  }
  e.error_document = error;

  const maxAge = str("max_age");
  if (maxAge !== undefined &&
    (!/^(0|[1-9][0-9]*)$/.test(maxAge) || Number(maxAge) > 2147483648)) {
    throw invalidField(`${f}/max_age`,
      "max_age shall be a non-negative decimal integer not greater than 2147483648");
  }
  e.max_age = maxAge;
  // "base_uri: CDMI server populated, and ignored where a CDMI client
  // supplies it. The base URI at which the export is served, formed from
  // the first value of "origins" and the value of "path"" (revision 327).
  if (type === "CDMI") {
    e.base_uri = origins.length > 0
      ? `${origins[0].replace(/\/$/, "")}${e.path ?? "/"}`
      : undefined;
  }

  return e;
}

/**
 * Validates an SMB export entry. What is checked here is that the entry
 * describes a configuration a CDMI client could rely on: the share
 * name, the versions offered, and the combinations of fields the
 * clause requires to agree with one another.
 */
function parseSmbEntry(name: string, raw: unknown, features: string[]): SmbExport {
  const f = `/exports/${name}`;
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw invalidField(f, "an export entry shall be a JSON object");
  }
  const obj = raw as Record<string, unknown>;
  for (const k of Object.keys(obj)) {
    if (!SMB_FIELDS.has(k)) {
      throw invalidField(`${f}/${k}`,
        'the field %j is not defined for an export entry of type "SMB"', k);
    }
  }
  const capability = (cap: string, detail: string, ...a: unknown[]) =>
    capabilityCondition(
      detail.replace(/%j/g, () => JSON.stringify(a.shift())))
      .with("cdmi_capability", cap);

  const str = (k: string): string | undefined => {
    const v = obj[k];
    if (v === undefined || v === null) return undefined;
    if (typeof v !== "string") {
      throw invalidField(`${f}/${k}`, "%j shall be a JSON string", k);
    }
    return v;
  };
  const arr = (k: string): string[] | undefined => {
    const v = obj[k];
    if (v === undefined || v === null) return undefined;
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
      throw invalidField(`${f}/${k}`, "%j shall be a JSON array of JSON strings", k);
    }
    return v as string[];
  };
  const bool = (k: string): string | undefined => {
    const v = str(k);
    if (v !== undefined && v !== "true" && v !== "false") {
      throw invalidField(`${f}/${k}`, '%j shall be "true" or "false"', k);
    }
    return v;
  };
  const pairs = (k: string): string[][] | undefined => {
    const v = obj[k];
    if (v === undefined || v === null) return undefined;
    if (!Array.isArray(v) ||
      v.some((x) => !Array.isArray(x) || x.length !== 3 ||
        x.some((y) => typeof y !== "string"))) {
      throw invalidField(`${f}/${k}`,
        "%j shall be a JSON array of three-element JSON arrays of JSON strings", k);
    }
    return v as string[][];
  };

  const e: SmbExport = { type: "SMB", protocol: [], sharename: "" };

  // The share name is one to 80 characters and excludes the characters
  // the file system of the exported protocol reserves.
  const sharename = str("sharename");
  if (sharename === undefined || sharename === "") {
    throw invalidField(`${f}/sharename`, "sharename is mandatory for an SMB export");
  }
  if ([...sharename].length > 80) {
    throw invalidField(`${f}/sharename`,
      "a share name is one to 80 characters, and %j is longer", sharename);
  }
  if (SHARENAME_FORBIDDEN.test(sharename)) {
    throw invalidField(`${f}/sharename`,
      'a share name shall not contain any of \\ / : * ? " < > |');
  }
  e.sharename = sharename;

  // The versions offered, of which a client negotiates one.
  const protocol = arr("protocol") ?? ["SMB3.1.1"];
  if (protocol.length === 0) {
    throw invalidField(`${f}/protocol`, "the protocol array holds at least one value");
  }
  for (const [i, v] of protocol.entries()) {
    if (SMB_PROTOCOLS[v] === undefined) {
      throw invalidField(`${f}/protocol`,
        "%j is not a version of the SMB protocol this document defines", v);
    }
    if (protocol.indexOf(v) !== i) {
      throw invalidField(`${f}/protocol`, "the version %j appears twice", v);
    }
    // Revision 245: one capability holds the versions offered, in place of
    // one capability for each version, so what a version is checked against
    // is the array that capability carries.
    if (!features.includes(v)) {
      throw capability("cdmi_export_smb_versions", "seedmi does not offer %j", v);
    }
  }
  e.protocol = protocol;

  const auth = arr("auth_methods");
  if (auth !== undefined) {
    for (const m of auth) {
      if (m !== "kerberos" && m !== "ntlmv2" && m !== "anonymous") {
        throw invalidField(`${f}/auth_methods`,
          '%j is not an authentication method this document defines', m);
      }
      if (m === "ntlmv2" && (arr("domain_servers") ?? []).length > 0) {
        // "it passes the NTLMv2 response the client presents through to a
        // domain controller of the directory of the domain that owns the
        // container object the export is placed on, over the secure channel
        // of its machine account": this server holds no machine account and
        // performs no such pass-through, so it does not accept an entry that
        // would require one. NTLMv2 against a password this server holds,
        // which is the workgroup case, is unaffected.
        throw invalidField(`${f}/domain_servers`,
          "this server authenticates an NTLMv2 response against a password it holds, and does not pass one " +
          "through to a domain controller: an entry naming domain_servers authenticates by kerberos");
      }
    }
    // Anonymous access is unauthenticated guest access with read-only
    // permissions, and is permitted only where ro_hosts is configured.
    if (auth.includes("anonymous") && arr("ro_hosts") === undefined) {
      throw invalidField(`${f}/auth_methods`,
        'the "anonymous" method grants read-only guest access, and is permitted only ' +
        "where ro_hosts is also configured");
    }
    e.auth_methods = auth;
  }

  const signing = str("signing");
  if (signing !== undefined && signing !== "disabled" && signing !== "required") {
    throw invalidField(`${f}/signing`, 'signing shall be "disabled" or "required"');
  }
  e.signing = signing;

  const encryption = str("encryption");
  if (encryption !== undefined && encryption !== "disabled" &&
    encryption !== "required") {
    throw invalidField(`${f}/encryption`,
      'encryption shall be "disabled" or "required"');
  }
  if (encryption !== undefined && encryption !== "disabled") {
    // Every version offered is able to encrypt, so that no connection
    // is negotiated at a version that cannot.
    const unable = protocol.filter((v) => !SMB_ENCRYPTING.includes(v));
    if (unable.length > 0) {
      throw invalidField(`${f}/encryption`,
        "transport encryption is defined for %s, and the protocol field offers %j",
        SMB_ENCRYPTING.join(", "), unable[0]);
    }
    throw capability("cdmi_export_smb_encryption",
      "seedmi does not encrypt the transport of an SMB export");
  }
  e.encryption = encryption;

  const max = str("max_connections");
  if (max !== undefined && !/^(0|[1-9][0-9]*)$/.test(max)) {
    throw invalidField(`${f}/max_connections`,
      "max_connections shall be a non-negative decimal integer");
  }
  e.max_connections = max;

  for (const [k, cap] of [
    ["continuous_availability", "cdmi_export_smb_ca"],
    ["dfs_enabled", "cdmi_export_smb_dfs"],
    ["shadow_copies", "cdmi_export_smb_shadow_copies"],
  ] as [string, string][]) {
    const v = bool(k);
    if (v === "true") throw capability(cap, "seedmi does not offer %j", k);
    (e as unknown as Record<string, unknown>)[k] = v;
  }

  e.comment = str("comment");
  e.domain = str("domain");
  e.domain_servers = arr("domain_servers");
  e.usermap = pairs("usermap");
  e.groupmap = pairs("groupmap");
  e.rw_hosts = arr("rw_hosts");
  e.ro_hosts = arr("ro_hosts");
  e.root_hosts = arr("root_hosts");
  e.access_based_enumeration = bool("access_based_enumeration");
  e.oplocks = bool("oplocks");

  e.disabled = bool("disabled");
  return e;
}

/**
 * Validates an NFS export entry. seedmi does not serve one yet, so the
 * entry is accepted, reported, and shown as not active; what is checked
 * here is that it describes a configuration a CDMI client could rely on.
 */
function parseNfsEntry(name: string, raw: unknown, features: string[]): NfsExport {
  const f = `/exports/${name}`;
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw invalidField(f, "an export entry shall be a JSON object");
  }
  const obj = raw as Record<string, unknown>;
  for (const k of Object.keys(obj)) {
    if (!NFS_FIELDS.has(k)) {
      throw invalidField(`${f}/${k}`,
        'the field %j is not defined for an export entry of type "NFS"', k);
    }
  }
  const capability = (cap: string, detail: string, ...a: unknown[]) =>
    capabilityCondition(
      detail.replace(/%j/g, () => JSON.stringify(a.shift())))
      .with("cdmi_capability", cap);

  const str = (k: string): string | undefined => {
    const v = obj[k];
    if (v === undefined || v === null) return undefined;
    if (typeof v !== "string") {
      throw invalidField(`${f}/${k}`, "the %j field shall be a JSON string", k);
    }
    return v;
  };
  const bool = (k: string): string | undefined => {
    const v = str(k);
    if (v === undefined) return undefined;
    if (v !== "true" && v !== "false") {
      throw invalidField(`${f}/${k}`, 'the %j field shall be "true" or "false"', k);
    }
    return v;
  };
  const list = (k: string): string[] | undefined => {
    const v = obj[k];
    if (v === undefined || v === null) return undefined;
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
      throw invalidField(`${f}/${k}`, "the %j field shall be a JSON array of strings", k);
    }
    return v as string[];
  };
  const mapping = (k: string): string[][] | undefined => {
    const v = obj[k];
    if (v === undefined || v === null) return undefined;
    if (!Array.isArray(v)) {
      throw invalidField(`${f}/${k}`, "the %j field shall be a JSON array", k);
    }
    for (const row of v) {
      if (!Array.isArray(row) || row.length !== 3 ||
        row.some((x: unknown) => typeof x !== "string")) {
        throw invalidField(`${f}/${k}`,
          "each entry of %j is three JSON strings: a name, an operator and a name", k);
      }
      if (!MAP_OPERATORS.includes(row[1] as string)) {
        throw invalidField(`${f}/${k}`, "the operator shall be %s, and not %j",
          MAP_OPERATORS.join(", "), row[1]);
      }
    }
    return v as string[][];
  };

  const protocol = list("protocol");
  if (protocol === undefined) {
    throw invalidField(`${f}/protocol`,
      'an NFS export entry shall contain a "protocol" field');
  }
  if (protocol.length === 0) {
    throw invalidField(`${f}/protocol`,
      "the protocol field shall contain at least one version");
  }
  for (const version of protocol) {
    const protocolCap = NFS_PROTOCOLS[version];
    if (protocolCap === undefined) {
      throw invalidField(`${f}/protocol`,
        "%j is not an NFS version this document defines; version 2 is not supported",
        version);
    }
    if (!features.includes(version)) {
      throw capability("cdmi_export_nfs_versions", "seedmi does not serve %j", version);
    }
  }

  const path = str("path");
  if (path === undefined) {
    throw invalidField(`${f}/path`, 'an NFS export entry shall contain a "path" field');
  }
  if (!path.startsWith("/") || path.endsWith("/") || path.includes("//")) {
    throw invalidField(`${f}/path`,
      'the path shall begin with "/", shall not end with one, and shall hold no empty ' +
      "component");
  }
  for (const seg of path.split("/").slice(1)) {
    if (seg === "." || seg === "..") {
      throw invalidField(`${f}/path`, "the path shall contain no dot component");
    }
  }

  const e: NfsExport = { type: "NFS", protocol, path };
  e.usermap = mapping("usermap");
  e.groupmap = mapping("groupmap");

  const flavors = list("security_flavors");
  if (flavors !== undefined) {
    if (flavors.length === 0) {
      throw invalidField(`${f}/security_flavors`,
        "at least one security flavor is required where the field is present");
    }
    for (const flavor of flavors) {
      if (!(flavor in NFS_FLAVORS)) {
        throw invalidField(`${f}/security_flavors`,
          "%j is not a security flavor this document defines", flavor);
      }
      const cap = NFS_FLAVORS[flavor];
      if (cap !== undefined && !features.includes(cap)) {
        throw capability(cap, "seedmi does not offer the %j security flavor", flavor);
      }
    }
  }
  e.security_flavors = flavors;
  e.domain = str("domain");
  e.domain_servers = list("domain_servers");

  const squash = str("squash");
  if (squash !== undefined && !SQUASH.includes(squash)) {
    throw invalidField(`${f}/squash`, "the squash shall be %s", SQUASH.join(", "));
  }
  e.squash = squash;

  for (const k of ["anon_uid", "anon_gid"] as const) {
    const v = str(k);
    if (v !== undefined && !/^(0|[1-9][0-9]*)$/.test(v)) {
      throw invalidField(`${f}/${k}`,
        "%j shall be a non-negative integer expressed as a decimal string", k);
    }
    e[k] = v;
  }

  for (const k of ["root_hosts", "rw_hosts", "ro_hosts"] as const) {
    const hosts = list(k);
    if (hosts !== undefined) {
      for (const h of hosts) {
        if (!validHostPattern(h)) {
          throw invalidField(`${f}/${k}`,
            "%j is not a host, a pattern of one, or a CIDR range", h);
        }
      }
    }
    e[k] = hosts;
  }

  e.recurse = bool("recurse");
  e.subtree_check = bool("subtree_check");
  const rdma = bool("rdma_enabled");
  if (rdma === "true" && !features.includes("cdmi_export_nfs_rdma")) {
    throw capability("cdmi_export_nfs_rdma", "seedmi does not serve NFS over RDMA");
  }
  e.rdma_enabled = rdma;

  const writeMode = str("write_mode");
  if (writeMode !== undefined && writeMode !== "sync" && writeMode !== "async") {
    throw invalidField(`${f}/write_mode`, 'the write mode shall be "sync" or "async"');
  }
  e.write_mode = writeMode;
  e.disabled = bool("disabled");
  return e;
}

/**
 * A host of an access list: a name, a name carrying the wildcards the
 * draft requires, an address, or a CIDR range.
 */
export function validHostPattern(h: string): boolean {
  if (h === "") return false;
  const slash = h.indexOf("/");
  if (slash >= 0) {
    const prefix = h.slice(slash + 1);
    const address = h.slice(0, slash);
    if (!/^(0|[1-9][0-9]*)$/.test(prefix)) return false;
    const bits = Number(prefix);
    if (address.includes(":")) return bits <= 128; // IPv6
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(address)) return false;
    return bits <= 32 && address.split(".").every((o) => Number(o) <= 255);
  }
  if (/[^A-Za-z0-9.:*?_-]/.test(h)) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Serving

const TITLES: Record<string, string> = {
  "origin-not-served": "An origin is not being served.",
  "certificate-unavailable": "No certificate is available for an origin.",
  "path-in-use": "Part of the exported path is in use.",
  "error-document-absent": "The error document is absent.",
};

function exportProblem(cond: string, name: string, origin: string, detail: string): Problem {
  const members: Record<string, unknown> = { cdmi_export: name };
  if (origin !== "") members.cdmi_origin = origin;
  return problem(`exports/http/${cond}`, TITLES[cond] ?? cond, detail, members);
}

/** Resolves dot segments, RFC 3986 section 5.2.4, on the encoded path. */
export function removeDotSegments(input: string): string {
  let out = "";
  let rest = input;
  const drop = () => {
    const i = out.lastIndexOf("/");
    out = i >= 0 ? out.slice(0, i) : "";
  };
  while (rest !== "") {
    if (rest.startsWith("../")) rest = rest.slice(3);
    else if (rest.startsWith("./")) rest = rest.slice(2);
    else if (rest.startsWith("/./")) rest = "/" + rest.slice(3);
    else if (rest === "/.") rest = "/";
    else if (rest.startsWith("/../")) { rest = "/" + rest.slice(4); drop(); }
    else if (rest === "/..") { rest = "/"; drop(); }
    else if (rest === "." || rest === "..") rest = "";
    else {
      const start = rest[0] === "/" ? 1 : 0;
      const next = rest.indexOf("/", start);
      if (next < 0) { out += rest; rest = ""; } else { out += rest.slice(0, next); rest = rest.slice(next); }
    }
  }
  return out === "" ? "/" : out;
}

/** Splits an encoded path and decodes each segment exactly once. */
function splitDecoded(p: string): { segs: string[]; trailing: boolean } | undefined {
  const trailing = p.endsWith("/");
  const t = p.replace(/^\/+/, "").replace(/\/+$/, "");
  if (t === "") return { segs: [], trailing: true };
  const segs: string[] = [];
  for (const raw of t.split("/")) {
    try {
      segs.push(decodeURIComponent(raw));
    } catch {
      return undefined;
    }
  }
  return { segs, trailing };
}

const pathSegs = (p: string) => p.split("/").filter((s) => s !== "");

/**
 * An address as the authority component of a URI: an IPv6 address is enclosed
 * in brackets, as RFC 3986 requires, and everything else stands as given.
 */
const authorityOf = (address: string): string =>
  address.split(":").length > 2 && !address.startsWith("[") ? `[${address}]` : address;

/** The network transports an export object reports, and what each is called. */
const TCP_IP = "TCP/IP";
const RDMA = "RDMA";
const WEBSOCKET = "WebSocket";

/** The security flavors an NFS export offers where its entry names none. */
const DEFAULT_FLAVORS = ["sys"];

/** The authentication methods an SMB export offers where its entry names none. */
const DEFAULT_SMB_AUTH = ["kerberos", "ntlmv2"];

/**
 * The three members of an export object that describe the connection rather
 * than the address of it: the transport, the flags a client of the exported
 * protocol presents, and the location of the access.
 *
 * All three are Optional, and revision 365 defines none of them well enough to
 * produce interoperably: client_protocol_transport says "for details, see
 * clause 8" and clause 8 does not mention it, and client_flags is "absent where
 * the export type defines no such flag" where no export type subclause defines
 * one. Both are raised as **ECR-228A**, and this is the option that request
 * recommends, implemented so that the request describes something that works.
 *
 * The rule a flag passes: it is determined by a field of the entry, and a
 * client that does not present it, or does not match it, does not connect. So
 * the security flavors of an NFS export yield flags and its squash setting does
 * not, the client connecting without knowing how its identities will be mapped.
 * A flag is never invented: every value here is the value of a field, which is
 * why they are not the mount options of the examples of clause 8 (`hard`,
 * `multiuser`, `mfsymlinks` are of one operating system's clients and no field
 * of an entry determines them; `rdma-put` and `rdma-get` name no S3 flag at
 * all, and stand in an example whose transport member reads "TCP/IP").
 *
 * @param determined whether client_protocol names one version, in which case no
 *   version flag is reported: the two members would say the same thing twice,
 *   and the flag exists for the entry that offers several and determines none.
 */
export function connectionOf(e: ExportEntry, determined: boolean): {
  client_protocol_transport?: string;
  client_flags?: string[];
  access_location?: string;
} {
  const flags: string[] = [];
  // The versions a client may negotiate, where this server has determined none.
  const versions = (offered: string[] | undefined) => {
    if (determined) return;
    for (const v of offered ?? []) flags.push(`vers=${v}`);
  };
  const some = (transport: string) => ({
    client_protocol_transport: transport,
    // "An empty array is not returned in place of the field."
    ...(flags.length > 0 ? { client_flags: flags } : {}),
  });

  if (isNfs(e)) {
    // "The security flavors the NFS server shall offer and accept for this
    // export": a client presents one of them. The draft places RFC 9289
    // transport security in the same field, so it is named here as the field
    // names it, and not as a client that spells it differently would.
    for (const f of e.security_flavors ?? DEFAULT_FLAVORS) flags.push(`sec=${f}`);
    versions(e.protocol);
    // rdma_enabled is the "TCP/IP and RDMA" distinction the transport member
    // offers as its own motivating example, which clause 8 never connects to it.
    return some(e.rdma_enabled === "true" ? RDMA : TCP_IP);
  }

  if (isSmb(e)) {
    for (const m of e.auth_methods ?? DEFAULT_SMB_AUTH) flags.push(`sec=${m}`);
    // A share requiring either is reached only by a connection that agreed it,
    // and [MS-SMB2] provides a share flag reporting that a share requires
    // encryption and none reporting that it requires signing — so this is the
    // one place a client learns of the second before it connects.
    if (e.signing === "required") flags.push("sign");
    if (e.encryption === "required") flags.push("seal");
    versions(e.protocol);
    return some(TCP_IP);
  }

  if (isS3(e)) {
    // "The region name that S3 clients shall use when computing request
    // signatures for this bucket": without it no authenticated request can be
    // signed, so it is required in order to connect successfully. It is also
    // the location of the access, which is what the examples of clause 8 report
    // there ("eu-west-3", "us-west-2") and is the only material this server
    // holds for that member.
    flags.push(`region=${e.region}`);
    if (e.tls === "required") flags.push("tls=required");
    return { ...some(TCP_IP), access_location: e.region };
  }

  if (isMqtt(e)) {
    // "or "ws" or "wss" for a connection carried over a WebSocket": a
    // difference of transport, in the sense the member means, and the second
    // this server can determine. A subscriber to the topic connects with what
    // the access URI and its scheme carry and nothing else, so no flag.
    const scheme = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(e.broker_uri)?.[1]?.toLowerCase();
    return some(scheme === "ws" || scheme === "wss" ? WEBSOCKET : TCP_IP);
  }

  // An HTTP export, and a CDMI export, which carries the fields of one: served
  // over TCP/IP, and with no flag, which is the case the draft's own member
  // description names ("absent where the export type defines no such flag, as
  // for an HTTP export").
  return some(TCP_IP);
}

/**
 * Whether two entries of ONE container object are an HTTP export and a CDMI
 * export at the same path — the pair the document provides for, in which the
 * CDMI export establishes a base URI and the HTTP export serves the requests at
 * it that name no CDMI media type.
 *
 * "An entry whose path is the root path of a base URI at which the CDMI server
 * serves the protocol binding is exempt from the constraint above", and "a base
 * URI comes into being when a CDMI export establishes it" — so an HTTP entry
 * whose path is a CDMI entry's path is exempt from the overlapping-path rule,
 * exactly as one whose path is the configured base URI is. The resolution is by
 * media type and not by path, so the two are not ambiguous: "the CDMI server
 * shall select that export for a request that names no CDMI media type in its
 * Content-Type or Accept header field, and shall serve every other request as a
 * request of the protocol binding."
 *
 * This is asked only of two entries of the same container object. The document
 * does not say that much — its exemption is written without reference to what
 * the two entries present, so read literally it exempts the pair across two
 * container objects as well, and then one request URI names an object of the
 * binding and a different object of an export, which is the outcome the
 * selection rule exists to prevent (ECR-221A). This implementation takes the
 * reading the migration annex assumes, "an HTTP export of the root container
 * object of each base URI it serves": the same object, reached two ways.
 */
const basePairOn = (a: ExportEntry, b: ExportEntry): boolean => {
  const kinds = [a.type, b.type];
  if (!kinds.includes("CDMI") || !kinds.includes("HTTP")) return false;
  // The root path of the base URI, and not merely a path that overlaps it.
  return (a as HttpExport).path === (b as HttpExport).path;
};

function encodePath(segs: string[], trailing: boolean): string {
  const body = segs.map((s) => encodeURIComponent(s)).join("/");
  return "/" + body + (trailing || segs.length === 0 ? (body === "" ? "" : "/") : "");
}

interface Selected {
  name: string;
  entry: HttpExport;
  /** The segments of the URI path at which the container is served. */
  epath: string[];
  /** The segments below that, which name an object within it. */
  rel: string[];
  trailing: boolean;
  /** The namespace path of the exported container object. */
  base: string;
  /** The namespace path of the object the request addresses. */
  ns: string;
}

/** An export entry, with the container object it is placed on. */
export interface Placed {
  node: Node;
  /** The namespace path of that container object. */
  ns: string;
  name: string;
  entry: ExportEntry;
}

/** The object at a namespace path, where this server holds one there. */
function nodeAtPath(store: Store, ns: string): Node | undefined {
  let node: Node = store.root();
  for (const seg of ns.split("/")) {
    if (seg === "") continue;
    const next = store.tryLookup(node, seg);
    if (!next) return undefined;
    node = next;
  }
  return node;
}

/**
 * The authentication schemes an HTTP export entry may name here. "digest"
 * and "x509" are not among them: this server performs neither, and an entry
 * that named one would promise what it cannot do.
 */
export const EXPORT_AUTH_METHODS = ["anonymous", "basic", "bearer", "krb5"];

export interface ExportOptions {
  /** The port at which requests of the https scheme are accepted. */
  tlsPort?: string;
  /**
   * Delegated access control, where this server is configured for it: an
   * object served through an export has its decision referred to its provider
   * as one served through the protocol binding does.
   */
  dac?: DacClient;
  /**
   * Decrypts the value of an encrypted object for a request served through
   * an HTTP export, where the cdmi_enc_access capability is available.
   * "The CDMI server shall return the plaintext only where cdmi_enc_access
   * is available, shall obtain the key under the identity of the request,
   * and shall not obtain a key for ANONYMOUS@". Absent where this server
   * cannot decrypt, in which case the ciphertext is returned as stored.
   */
  decryptForExport?: (ref: ObjRef, who: Principal) =>
    Promise<{ plaintext: Buffer; plaintextType: string }>;
  /**
   * The cdmi_representation_default item that applies to an object, which is data
   * system metadata and so is inherited from the container objects above it. The
   * binding resolves the inheritance; this module only needs the value.
   */
  defaultRepresentationOf?: (ref: ObjRef) => unknown;
  /**
   * The principal a request to an HTTP export acts for, resolved by the
   * scheme the entry names, within the domain that owns the object. A
   * refusal is reported as it is for a request of the protocol binding,
   * with the WWW-Authenticate header field the scheme requires.
   */
  /**
   * Where this server publishes protected resource metadata, for the
   * bearer challenge of an export. Absent where no authorization server
   * is configured, and the challenge is then the bare one.
   */
  resourceMetadataBase?: string;

  exportPrincipal?: (req: IncomingMessage, ns: string, method: string) =>
    Promise<{ who: Principal } | { refused: Condition }>;
  /**
   * The object whose cdmi_lock item refuses an operation of that kind upon
   * a namespace path, where one does. A lock refuses an operation however
   * it reaches the object, and each protocol reports it in its own terms
   * (revision 327).
   */
  lockCovering?: (ns: string, operation: "create" | "update" | "delete") => string | undefined;
  /** Retrieves a certificate by the identifier an entry names. */
  certificates?: (id: string) => { chain: string; key: string } | undefined;
  /** A certificate the server holds for a host on its own account. */
  hostCertificate?: (host: string) => { chain: string; key: string } | undefined;
  /**
   * The features of the NFS export type seedmi offers, which are the
   * capabilities a client must see before it configures one.
   */
  /** The NFS versions served, as the protocol field of an entry spells them. */
  nfsFeatures?: string[];
  /** The addresses at which an NFS client would reach this server. */
  nfsAddresses?: string[];
  /**
   * The features of the SMB export type seedmi offers. Where it is
   * absent every version this document defines is offered, which is
   * what the capabilities publish.
   */
  smbFeatures?: string[];
  /**
   * The MQTT features this CDMI server offers, as capability names. A
   * version an entry names is refused where its capability is absent.
   */
  mqttFeatures?: string[];
  /** Whether a key management server is configured, so that a credential reference is accepted. */
  kmsConfigured?: () => boolean;
  /**
   * The credential of an access key identifier, which an S3 client
   * signs with. A CDMI server makes these available by means outside
   * the scope of this document, and no field of an S3 export entry
   * conveys them.
   */
  s3Credentials?: (accessKey: string) =>
    { secret: string; principal: string } | undefined;
  /** The principal, with its groups, that a credential's name resolves to. */
  s3Principal?: (name: string) => Principal | undefined;
  /**
   * The credentials a Kerberos service ticket in X-Amz-Security-Token gives:
   * the session key of the ticket as the secret access key, and the client
   * principal it names (revision 282; PLAN-auth.md, phase 8).
   */
  s3Temporary?: (token: string, bucket: { entry: { bucket_name?: string }; node: Node; ns: string }) =>
    Promise<{ secret: Buffer; principal: Principal } | { refused: string } | undefined>;
  /**
   * The host name or address at which clients reach this server, from
   * which the endpoints of an S3 export are reported. Where absent the
   * loopback address is reported.
   */
  host?: string;
  /**
   * What publishes the values of a queue object to a broker. Where
   * none is given an MQTT entry is validated and reported and no
   * connection is made.
   */
  mqtt?: MqttPublisher;
  /**
   * The NFS server that serves the exports of the NFS export entries.
   * Where one is given, an entry is established on it and reported as
   * active; without one an entry is validated and reported only.
   */
  nfs?: NfsShares;
  /** Where a request served through an export is written. */
  log?: Log;
  /** The addresses through which an SMB export is reached. */
  smbAddresses?: string[];
  /**
   * The SMB server that serves the shares of the SMB export entries.
   * Where one is given, an entry is established on it and reported as
   * active; without one an entry is validated and reported only.
   */
  smb?: SmbShares;
  /** The values of the cdmi_export_http_origins and cdmi_export_cdmi_origins capabilities. */
  originCaps: string[];
  /** The scheme at which clients reach this server. */
  scheme: string;
  /** The port at which clients reach this server. */
  port: string;
  /** The base URI path of the protocol binding, which is reserved. */
  base: string;
}

export class Exports {
  readonly store: Store;
  readonly opts: ExportOptions;

  constructor(store: Store, opts: ExportOptions) {
    this.store = store;
    this.opts = opts;
  }

  /** The exports field of a container object. */
  entries(node: Node): Record<string, ExportEntry> {
    const m = this.store.meta(node);
    return (m.exports ?? {}) as unknown as Record<string, ExportEntry>;
  }

  configured(node: Node): boolean {
    return this.store.meta(node).exports !== undefined;
  }

  /**
   * Every export entry the server holds, with the container object it is
   * placed on and the namespace path of that container. An export is
   * selected by origin and path, so every entry has to be reachable
   * without walking the namespace.
   */
  all(): Placed[] {
    const out: Placed[] = [];
    for (const node of this.store.exportedContainers()) {
      let ns: string;
      try {
        ns = this.store.pathOf(node);
      } catch {
        continue; // the container object has gone
      }
      const entries = this.entries(node);
      for (const name of Object.keys(entries).sort()) {
        out.push({ node, ns, name, entry: entries[name] });
      }
    }
    return out.sort((a, b) => (a.ns + a.name < b.ns + b.name ? -1 : 1));
  }

  /** The HTTP entries alone, which are the ones seedmi serves. */
  /**
   * The container object a CDMI export serves at the base URI a request
   * addresses, and the path of that base URI, where one does.
   *
   * "A CDMI export presents a container object, and the objects it
   * contains, at a base URI of an origin the CDMI server serves. At that
   * base URI the container object is the root container object" (revision
   * 327). The protocol binding serves it, this class only finds it.
   */
  /**
   * The base URIs that CDMI exports establish, for the discovery tree.
   * "A base URI comes into being when a CDMI export establishes it, and no
   * longer exists when that export is removed" (revision 327); an object ID
   * URI is a base URI that no export established, and "is not reported in
   * the discovery namespace".
   */
  cdmiBases(): { name: string; uri: string; ns: string }[] {
    const out: { name: string; uri: string; ns: string }[] = [];
    for (const p of this.all()) {
      const e = p.entry as
        { type?: string; disabled?: string; base_uri?: string; name?: string };
      if (e.type !== "CDMI" || e.disabled === "true" || e.base_uri === undefined) continue;
      out.push({ name: e.name ?? p.name, uri: e.base_uri, ns: p.ns });
    }
    return out;
  }

  cdmiBaseFor(req: IncomingMessage): { ns: string; base: string; readOnly: boolean } | undefined {
    const host = String(req.headers.host ?? "").toLowerCase();
    if (host === "") return undefined;
    const scheme = encrypted(req) ? "https" : this.opts.scheme;
    const path = (req.url ?? "/").split("?")[0];
    for (const p of this.all()) {
      const entry = p.entry as { type?: string; origins?: string[]; path?: string; disabled?: string };
      if (entry.type !== "CDMI" || entry.disabled === "true") continue;
      const root = entry.path ?? "/";
      if (!(path === root || path.startsWith(root))) continue;
      for (const o of entry.origins ?? []) {
        const parsed = parseOrigin(o).origin;
        if (parsed === undefined) continue;
        const port = parsed.port === "80" || parsed.port === "443" ? "" : `:${parsed.port}`;
        if (parsed.scheme === scheme && `${parsed.host}${port}`.toLowerCase() === host) {
          // "Where this field contains "true", the CDMI server shall
          // refuse through this export every operation that creates,
          // updates or deletes an object."
          return { ns: p.ns, base: root, readOnly: (entry as { read_only?: string }).read_only === "true" };
        }
      }
    }
    return undefined;
  }

  httpPlaced(): (Placed & { entry: HttpExport })[] {
    return this.all().filter((p): p is Placed & { entry: HttpExport } =>
      isHttp(p.entry));
  }

  /**
   * Serves a request against a bucket, reporting whether it did. A
   * bucket is addressed by a path segment of an endpoint or by a
   * subdomain of one, as the addressing_style of its entry says.
   */
  private async serveS3(req: IncomingMessage, res: ServerResponse):
    Promise<boolean> {
    const placed = this.all().filter((p): p is Placed & { entry: S3Export } =>
      isS3(p.entry) && p.entry.disabled !== "true");
    if (placed.length === 0) return false;
    return await serveBucket(req, res, {
      buckets: placed.map((p) => ({ entry: p.entry, node: p.node, ns: p.ns })),
      store: this.store,
      credentials: this.opts.s3Credentials,
      principal: this.opts.s3Principal,
      // A Kerberos service ticket as a temporary credential (revision 282).
      ...(this.opts.s3Temporary === undefined ? {} : { temporary: this.opts.s3Temporary }),
      uploads: this.uploads,
      secure: encrypted(req),
      ...(this.opts.dac === undefined ? {} : { dac: this.opts.dac }),
    });
  }

  /** The uploads in progress of the buckets this server serves. */
  private readonly uploads = new Uploads();

  /** The MQTT export entries, each placed on a queue object. */
  mqttPlaced(): (Placed & { entry: MqttExport })[] {
    return this.all().filter((p): p is Placed & { entry: MqttExport } =>
      isMqtt(p.entry));
  }

  /**
   * Replaces the exports field, validating it first. isImageSource, where
   * given, reports whether an active filesystem import interprets the
   * value of the data object at a path: an export that would transfer
   * that value conflicts with the import.
   */
  set(node: Node, value: unknown, by?: string): void {
    const m = this.store.meta(node);
    const onQueue = m.isQueue;
    const parsed = value === null || value === undefined
      ? undefined
      : parseExports(value, this.opts.originCaps, this.opts.base,
        [...(this.opts.nfsFeatures ?? []),
          ...(this.opts.smbFeatures ?? Object.keys(SMB_PROTOCOLS)),
          // Revision 245: one capability holds the versions offered, in
          // place of one capability for each version.
          ...(this.opts.mqttFeatures ?? ["cdmi_export_mqtt_versions"]),
          // A credential reference is accepted where a key management
          // server is configured to resolve it.
          ...(this.opts.kmsConfigured?.() === true ? ["cdmi_kms"] : [])]);
    // A field that carries a shared secret is accepted and never
    // returned, so a CDMI client that reads an entry and writes it
    // back omits it. Where an update omits such a field and this
    // CDMI server holds a value supplied for it earlier, that value
    // is retained: the alternative is that reading an entry and
    // writing it back silently discards the credential.
    const earlierEntries = this.entries(node);
    // The principal under whose authority an export that publishes outward
    // publishes: "such an export publishes under the authority of the principal
    // that created the export entry" (revision 365). It is stamped after the
    // entry is parsed, the parser passing through only the fields the clause
    // defines, and an entry whose fields are unchanged keeps the principal it
    // was created under rather than taking that of whoever last wrote the
    // field.
    if (by !== undefined) {
      for (const [name, entry] of Object.entries(parsed ?? {})) {
        if (!isMqtt(entry)) continue;
        const earlier = earlierEntries[name];
        const same = earlier !== undefined && isMqtt(earlier) &&
          JSON.stringify({ ...earlier, publishedBy: undefined }) ===
          JSON.stringify({ ...entry, publishedBy: undefined });
        entry.publishedBy = same && earlier.publishedBy !== undefined ? earlier.publishedBy : by;
      }
    }
    for (const [name, entry] of Object.entries(parsed ?? {})) {
      const earlier = earlierEntries[name] as unknown as
        Record<string, unknown> | undefined;
      if (earlier === undefined) continue;
      for (const secret of WITHHELD_FIELDS) {
        const now = entry as unknown as Record<string, unknown>;
        if (now[secret] === undefined && earlier[secret] !== undefined) {
          now[secret] = earlier[secret];
        }
      }
    }

    // An MQTT export is placed on a queue object, because it
    // publishes the values that object holds; every other type is
    // placed on a container object, because it presents a namespace.
    for (const [name, entry] of Object.entries(parsed ?? {})) {
      if (isMqtt(entry) && !onQueue) {
        throw invalidField(`/exports/${name}/type`,
          "an MQTT export publishes the values of a queue object, and is placed on " +
          "one rather than on a container object");
      }
      if (isS3(entry) && onQueue) {
        throw invalidField(`/exports/${name}/type`,
          "an S3 export presents the objects a container object contains, and is " +
          "placed on one rather than on a queue object");
      }
      if (!isMqtt(entry) && onQueue) {
        throw invalidField(`/exports/${name}/type`,
          "an export of type %j presents a namespace, and is placed on a container " +
          "object rather than on a queue object", entry.type);
      }
    }
    if (parsed) this.checkBaseUriExports(node, parsed);
    if (parsed) this.checkAcrossContainers(node, parsed);
    // An entry that has been removed withdraws whatever it
    // established. A disabled entry is withdrawn where it is reported,
    // but an entry that is gone is never reported again, so it is
    // withdrawn here.
    const before = this.entries(node);
    const after = new Set(Object.keys(parsed ?? {}));
    for (const [name, entry] of Object.entries(before)) {
      if (after.has(name)) continue;
      // An NFS export is withdrawn by the name of the entry and an SMB
      // export by its share name, each being what the server holds it
      // under.
      if (isNfs(entry)) this.opts.nfs?.withdraw(name);
      if (isSmb(entry)) this.opts.smb?.withdraw(entry.sharename);
      // An MQTT export that is removed sends a clean DISCONNECT and
      // the messages still pending are removed with it.
      if (isMqtt(entry)) this.opts.mqtt?.withdraw(name);
    }
    m.exports = parsed as unknown as Record<string, unknown>;
    this.store.setMeta(node, m);
    this.store.setExported(node, parsed !== undefined && Object.keys(parsed).length > 0);
  }

  /**
   * An HTTP export whose path is the root path of a base URI this server serves
   * the protocol binding at, where the container object it is placed on is not
   * the root container object of that base URI.
   *
   * Such an entry is exempt from the overlapping-path rule, requests at that
   * path being dispatched by media type rather than by path: "the CDMI server
   * shall select that export for a request that names no CDMI media type in its
   * Content-Type or Accept header field, and shall serve every other request as
   * a request of the protocol binding". The exemption is for the arrangement
   * Annex E describes — "an HTTP export **of the root container object** of each
   * base URI it serves ... A CDMI client of the previous edition then reaches
   * **the same objects** at the same request URIs as before" — which is one
   * object reached two ways.
   *
   * Placed on any other container object it is two objects reached at one
   * request URI, chosen by a header field, which is what the selection rule
   * exists to prevent: requests within a base URI are served by the binding "so
   * that one request URI does not name both an object of the binding and an
   * object of an export". The access control lists of the two objects are
   * unrelated, so the choice of route is also a choice of what a principal may
   * read, and a CDMI client that verified an objectID against the
   * representation has verified nothing about the octets it then reads.
   *
   * The document does not say this. Its exemption is written in terms of paths
   * alone and, read literally, permits the entry wherever it is placed; ECR-221A
   * asks for the condition Annex E assumes. Until 0.98 seedmi permitted it for
   * the configured base URI — so a principal able to write an "exports" field on
   * any container object it owns took over every request to the whole base URI
   * that named no CDMI media type, substituting its own objects for the ones the
   * binding serves.
   *
   * Two kinds of base URI are served here, and the rule is the same for both:
   * the one this server is configured with, whose root container object is the
   * root, and one a CDMI export establishes, whose root container object is the
   * object that CDMI export is placed on.
   */
  private checkBaseUriExports(node: Node, parsed: Record<string, ExportEntry>): void {
    const rootId = this.store.root().id;
    // Every CDMI export of this server, with the object each is placed on. The
    // entries being supplied now are taken from the supplied set and not from
    // the store, which still holds what this operation is replacing.
    const established: { path: string; origins: string[]; node: Node; name: string; ns: string }[] = [];
    for (const [name, e] of Object.entries(parsed)) {
      if (e.type !== "CDMI" || disabled(e)) continue;
      const c = e as HttpExport;
      established.push({ path: c.path, origins: c.origins, node, name, ns: this.store.pathOf(node) });
    }
    for (const p of this.all()) {
      if (p.node.id === node.id || p.entry.type !== "CDMI" || disabled(p.entry)) continue;
      const c = p.entry as HttpExport;
      established.push({ path: c.path, origins: c.origins, node: p.node, name: p.name, ns: p.ns });
    }
    for (const [name, e] of Object.entries(parsed)) {
      if (!isHttp(e) || disabled(e)) continue;
      if (e.path === this.opts.base && node.id !== rootId) {
        throw conflict(
          "the path %j of export %j is the base URI at which this CDMI server serves the " +
          "protocol binding, and an export there is served for a request naming no CDMI media " +
          "type: it presents the root container object of that base URI, and this entry is " +
          "placed on %s",
          e.path, name, this.store.pathOf(node))
          .with("cdmi_export", name);
      }
      for (const base of established) {
        if (base.path !== e.path || base.node.id === node.id) continue;
        if (!e.origins.some((o) => base.origins.includes(o))) continue;
        throw conflict(
          "the path %j of export %j is the base URI the CDMI export %j of %s establishes, and " +
          "an export there is served for a request naming no CDMI media type: it presents the " +
          "root container object of that base URI, which is %s, and this entry is placed on %s",
          e.path, name, base.name, base.ns, base.ns, this.store.pathOf(node))
          .with("cdmi_export", name).with("cdmi_export_conflict", base.name);
      }
    }
  }

  /**
   * The name an export entry supplies is unique within a namespace the
   * section defining the type states: the path of an NFS export within
   * one global to the server, and the path of an HTTP export within the
   * origins it is served at. Either way the rule holds across every
   * container object, so entries placed elsewhere are checked too.
   */
  private checkAcrossContainers(node: Node, parsed: Record<string, ExportEntry>): void {
    for (const other of this.all()) {
      if (other.node.id === node.id) continue;
      for (const [name, e] of Object.entries(parsed)) {
        if (disabled(e) || disabled(other.entry)) continue;
        // An MQTT export occupies a topic of a broker rather than a
        // namespace of this CDMI server, so it conflicts with no entry
        // held anywhere on it. Two entries publishing to one topic
        // send the values of both queue objects there, which a CDMI
        // client may intend.
        if (isMqtt(e) || isMqtt(other.entry)) continue;
        // An S3 export occupies a bucket name, shared with every other S3
        // export of the server and with nothing else. It has no origins or
        // path, and was compared as an HTTP entry before 0.46, which failed
        // with a TypeError reported as a 500 wherever an HTTP export existed.
        if (isS3(e) || isS3(other.entry)) {
          if (isS3(e) && isS3(other.entry) && e.bucket_name === other.entry.bucket_name) {
            throw conflict(
              "the bucket name %j is already the bucket name of the export %j of %s",
              e.bucket_name, other.name, other.ns)
              .with("cdmi_export", name).with("cdmi_export_conflict", other.name);
          }
          continue;
        }
        // An SMB export shares its namespace of share names with every
        // other SMB export of the server, and with nothing else.
        if (isSmb(e) || isSmb(other.entry)) {
          if (isSmb(e) && isSmb(other.entry) &&
            e.sharename.toLowerCase() === other.entry.sharename.toLowerCase()) {
            throw conflict(
              "the share name %j is already the share name of the export %j of %s",
              e.sharename, other.name, other.ns)
              .with("cdmi_export", name).with("cdmi_export_conflict", other.name);
          }
          continue;
        }
        if (isNfs(e) !== isNfs(other.entry)) continue;
        if (isNfs(e) && isNfs(other.entry)) {
          if (overlap(`${e.path}/`, `${other.entry.path}/`)) {
            throw conflict(
              "the path %j is already the path of the export %j of %s",
              e.path, other.name, other.ns)
              .with("cdmi_export", name).with("cdmi_export_conflict", other.name);
          }
          continue;
        }
        const a = e as HttpExport;
        const b = other.entry as HttpExport;
        if (a.path === this.opts.base || b.path === this.opts.base) continue;
        const shared = a.origins.find((o) => b.origins.includes(o));
        // "A CDMI server shall serve only one CDMI export at a base URI,
        // so that a base URI names one root container object. When a base
        // URI is already in use, the CDMI server shall report the name in
        // use condition" (revision 327), which is more particular than the
        // conflict two overlapping paths report. It is a rule about two CDMI
        // exports: what puts a base URI in use is a CDMI export establishing
        // it, and an HTTP export establishes none. Until 0.98 this reported the
        // name in use condition for an HTTP entry facing a CDMI entry as well,
        // which named the wrong reason — the base URI is not in use twice, two
        // paths overlap.
        if (shared && a.path === b.path && a.type === "CDMI" && b.type === "CDMI") {
          throw exportNameInUse(
            "the base URI %s is already served by the export %j of %s",
            `${shared.replace(/\/$/, "")}${a.path}`, other.name, other.ns)
            .with("cdmi_export", name).with("cdmi_export_conflict", other.name);
        }
        // An HTTP export and a CDMI export at one path co-exist where they are
        // entries of ONE container object, the pair then presenting one object
        // two ways. Across two container objects they do not: the request URI
        // would name an object of the protocol binding and a different object
        // of an export, chosen by a header field, which is what the selection
        // rule of the document exists to prevent — "so that one request URI
        // does not name both an object of the binding and an object of an
        // export". The document's exemption does not say this, and read
        // literally permits the pair here too; ECR-221A asks for it to.
        if (shared && basePairOn(a, b)) {
          throw conflict(
            "the path %j of export %j is the path of the export %j of %s, and one of the two " +
            "is a CDMI export: an HTTP export and a CDMI export share a path only as two " +
            "entries of one container object, which present one object, and these present %s " +
            "and %s",
            a.path, name, other.name, other.ns, this.store.pathOf(node), other.ns)
            .with("cdmi_export", name).with("cdmi_export_conflict", other.name);
        }
        if (shared && overlap(a.path, b.path)) {
          throw conflict(
            "the path %j of export %j is equal to, a prefix of, or prefixed by the " +
            "path %j of export %j of %s, both served at %s",
            a.path, name, b.path, other.name, other.ns, shared)
            .with("cdmi_export", name).with("cdmi_export_conflict", other.name);
        }
      }
    }
  }

  /**
   * Whether an active HTTP export would transfer the value of the object
   * at ns. An export transfers the values of the objects within the
   * container object it is placed on.
   */
  transfersValueOf(ns: string): boolean {
    for (const p of this.httpPlaced()) {
      if (disabled(p.entry) || !ns.startsWith(p.ns)) continue;
      const { served } = this.servedOrigins(p.name, p.entry);
      if (served.length > 0) return true;
    }
    return false;
  }

  /**
   * The certificate to present at an origin: the one the entry names,
   * where it names one, retrieved by its identifier. A server that
   * holds a certificate for the host on its own account may present
   * that instead, which is what the draft permits where a client
   * nominates no certificate of its own.
   */
  certificateFor(e: HttpExport, origin: string):
    { chain: string; key: string } | undefined {
    void e;
    const parsed = parseOrigin(origin).origin;
    return parsed ? this.opts.hostCertificate?.(parsed.host) : undefined;
  }

  /** Places an entry where the root container object has no exports field. */
  establish(name: string, origins: string[], path: string): boolean {
    const root = this.store.root();
    const held = this.entries(root);
    const wanted = { type: "HTTP", origins, path };
    const before = held[name];
    if (before !== undefined &&
      JSON.stringify({ type: before.type, origins: (before as HttpExport).origins,
        path: (before as HttpExport).path }) === JSON.stringify(wanted)) {
      return false; // already established as asked
    }
    // The entry is replaced where it differs, and every other entry of
    // the root container object is kept: a store outlives the command
    // line that made it, and an entry a CDMI client placed is not the
    // server's to remove. Without this an entry from an earlier run
    // stands, naming an origin the server is no longer reached at, and
    // nothing says so.
    this.set(root, { ...held, [name]: wanted });
    return true;
  }

  /**
   * Whether an operation of an export is permitted on an object. An
   * export admits a principal by its entry where it names no
   * authentication scheme, and the list is then evaluated against the
   * anonymous principal. Where the entry names a scheme, the request is
   * associated with the principal it resolves to and the list is
   * evaluated against that one.
   */
  private permits(node: Node, bit: number, who: Principal = ANONYMOUS): boolean {
    const m = this.store.meta(node);
    // A decision of a delegated access control provider applies to the object
    // however it is reached (dac-context.ts).
    const delegated = delegatedMask(m.objectID);
    if (delegated !== undefined) return (delegated & bit) === bit;
    return granted(m.acl, who, bit, {
      owner: m.owner,
      group: m.group,
      isContainer: node.isContainer,
      isRoot: m.parent === null,
    });
  }

  /** The destination where the request names a reference. */
  private async referenceAt(sel: Selected): Promise<string | undefined> {
    if (sel.ns.endsWith("/")) return undefined;
    const cut = sel.ns.lastIndexOf("/");
    const r = new Resolver(this.store);
    let pv: View;
    try {
      pv = await r.view(sel.ns.slice(0, cut + 1));
    } catch {
      return undefined;
    }
    if (pv.unavail) return undefined;
    return referenceIn(this.store, pv, sel.ns.slice(cut + 1));
  }

  /**
   * The Location of a redirection. Where the destination lies within
   * the exported container object, the URI within the export is given,
   * formed from the origin the request was received at; otherwise the
   * destination is given as it was recorded.
   */
  private locationOf(sel: Selected, destination: string): string {
    const base = this.opts.base;
    // A destination that addresses this server through the protocol
    // binding, within the exported container object.
    for (const self of ownBases()) {
      if (!destination.startsWith(self)) continue;
      const ns = "/" + destination.slice(self.length);
      if (!ns.startsWith(sel.base)) break;
      return this.location(sel, ns);
    }
    void base;
    return destination;
  }

  /** The origins at which an entry is served, and a problem for each that is not. */
  servedOrigins(name: string, e: HttpExport): { served: string[]; problems: Problem[] } {
    const served: string[] = [];
    const problems: Problem[] = [];
    if (disabled(e)) return { served, problems };
    for (const o of e.origins) {
      const { origin } = parseOrigin(o);
      if (!origin) continue;
      const scheme = origin.scheme;
      const listens = scheme === "https"
        ? this.opts.tlsPort !== undefined && origin.port === this.opts.tlsPort
        : scheme === this.opts.scheme && origin.port === this.opts.port;
      if (scheme === "https" && this.opts.tlsPort === undefined) {
        problems.push(exportProblem("origin-not-served", name, o,
          "seedmi serves no origin of the https scheme: no TLS port is configured"));
      } else if (!listens) {
        problems.push(exportProblem("origin-not-served", name, o,
          `seedmi accepts requests at port ${scheme === "https" ? this.opts.tlsPort : this.opts.port}, ` +
          `and this origin has port ${origin.port}`));
      } else if (scheme === "https" && !this.certificateFor(e, o)) {
        // An origin whose certificate cannot be retrieved is not served,
        // is omitted from origins_provided, and the reason is recorded.
        problems.push(exportProblem("certificate-unavailable", name, o,
          e.certificates?.some((c) => c.origin === o)
            ? "the certificate this entry names could not be retrieved"
            : "the entry names no certificate for this origin, and the server holds none " +
              "for its host"));
      } else {
        served.push(o);
      }
    }
    return { served, problems };
  }

  /** The exports field as reported, with the CDMI server populated fields. */
  /**
   * Reports the export entries of a queue object. Every entry there
   * is an MQTT entry, whose report needs nothing this CDMI server has
   * to await, so it is formed without one.
   */
  /**
   * Establishes, withdraws and re-establishes the MQTT exports of a queue
   * object to match the entries it now carries.
   *
   * This ran within reportMqtt alone until 0.83, which establishes an entry
   * as a side effect of reporting it. An update that answers 204 reports
   * nothing, so an entry disabled by a PATCH kept its connection and its
   * place in the running set, and a value enqueued afterwards still reached
   * the broker (weedmi EMQT-001). Applying the entries is now a step of the
   * update, and reporting them reports what is running.
   */
  settleMqtt(node: Node): void {
    const mqtt = this.opts.mqtt;
    if (mqtt === undefined) return;
    const entries = this.entries(node);
    for (const [name, entry] of Object.entries(entries)) {
      if (!isMqtt(entry)) continue;
      if (entry.disabled === "true") {
        if (mqtt.offered().includes(name)) mqtt.withdraw(name);
        continue;
      }
      if (mqtt.connecting) mqtt.offer(name, entry, node);
    }
    // An entry that has gone from the field withdraws the connection it
    // held, which set() does for a whole object and this does for one
    // entry removed from among others.
    for (const name of mqtt.offered()) {
      const held = entries[name];
      if (held === undefined || !isMqtt(held)) mqtt.withdraw(name);
    }
  }

  reportSync(node: Node): Record<string, unknown> {
    const now = cdmiTime(Date.now());
    const out: Record<string, unknown> = {};
    for (const [name, entry] of Object.entries(this.entries(node))) {
      if (isMqtt(entry)) out[name] = this.reportMqtt(name, entry, now, node);
    }
    return out;
  }

  async report(node: Node): Promise<Record<string, unknown>> {
    const out: Record<string, unknown> = {};
    const now = cdmiTime();
    const entries = this.entries(node);
    const ns = this.store.pathOf(node);
    for (const name of Object.keys(entries).sort()) {
      const entry = entries[name];
      if (isNfs(entry)) {
        out[name] = this.reportNfs(name, entry, now, ns);
        continue;
      }
      if (isSmb(entry)) {
        out[name] = this.reportSmb(name, entry, now, ns);
        continue;
      }
      if (isMqtt(entry)) {
        out[name] = this.reportMqtt(name, entry, now, node);
        continue;
      }
      if (isS3(entry)) {
        out[name] = this.reportS3(name, entry, now);
        continue;
      }
      const e = entry;
      const { served, problems } = this.servedOrigins(name, e);
      // The base URI of the protocol binding is reserved at every origin,
      // and an export whose path contains it does not serve the objects
      // beneath it. The export remains active.
      if (this.opts.base.startsWith(e.path) && e.path !== this.opts.base) {
        for (const o of served) {
          problems.push(exportProblem("path-in-use", name, o,
            `seedmi serves the protocol binding at ${this.opts.base}, which lies within the ` +
            "path of this export"));
        }
      }
      if (e.error_document !== undefined) {
        const r = new Resolver(this.store);
        if (!await this.resolveData(r, ns + e.error_document)) {
          problems.push(exportProblem("error-document-absent", name, "",
            `the exported container object holds no data object at ${JSON.stringify(e.error_document)}`));
        }
      }
      // A CDMI export reports the fields its own table defines, and the
      // fields common to every entry: the HTTP export's own fields —
      // auth_method, the documents, max_age — are not among them, and
      // base_uri is server populated (revision 327).
      if (e.type === "CDMI") {
        out[name] = {
          type: e.type,
          origins: e.origins,
          path: e.path,
          ...(e.protocol !== undefined ? { protocol: e.protocol } : {}),
          read_only: e.read_only ?? "false",
          ...(e.base_uri !== undefined ? { base_uri: e.base_uri } : {}),
          disabled: e.disabled ?? "false",
          origins_provided: served,
          active: served.length > 0 ? "true" : "false",
          last_problems: [...problems, ...unservableProblems(e)],
          state_determined_time: now,
        };
        continue;
      }
      out[name] = {
        type: e.type,
        origins: e.origins,
        path: e.path,
        ...(e.protocol !== undefined ? { protocol: e.protocol } : {}),
        read_only: e.read_only ?? "true",
        auth_method: e.auth_method ?? "anonymous",
        anonymous_read: e.anonymous_read ?? "false",
        ...(e.index_document !== undefined ? { index_document: e.index_document } : {}),
        ...(e.error_document !== undefined ? { error_document: e.error_document } : {}),
        max_age: e.max_age ?? "0",
        disabled: e.disabled ?? "false",
        origins_provided: served,
        active: served.length > 0 ? "true" : "false",
        last_problems: [...problems, ...unservableProblems(e)],
        // The time seedmi determined this state, which it does when the
        // entry is read; no state is retained between requests.
        state_determined_time: now,
      };
    }
    return out;
  }

  /**
   * An NFS export entry as reported. seedmi validates and reports the
   * entry but does not serve one yet, so it is never active and says so.
   */
  /**
   * Reports an SMB export entry. seedmi validates one and does not yet
   * serve it, so the entry is reported as supplied, shown as not
   * active, and the reason recorded.
   */
  private reportSmb(
    name: string,
    e: SmbExport,
    now: string,
    ns?: string,
  ): Record<string, unknown> {
    const problems: Problem[] = [];
    const smb = this.opts.smb;
    let active = false;
    if (e.disabled !== "true") {
      if (smb === undefined || !smb.running()) {
        problems.push(problem("exports/not-established",
          "The export could not be established.",
          "this CDMI server is not configured to serve an SMB export",
          { cdmi_export: name }));
      } else {
        // The share is established: the export is active whether or
        // not a host is admitted, since the server is able to serve a
        // request through it.
        active = true;
        smb.offer({
          name: e.sharename,
          dialects: smb.revisions(e.protocol),
          signingRequired: e.signing === "required",
          anonymous: (e.auth_methods ?? []).includes("anonymous"),
          mount: ns === undefined
            ? undefined
            : {
              store: this.store,
              path: ns,
              // The maps translate between a name of this document
              // and a name of the identity domain of the SMB server,
              // in both directions.
              usermap: e.usermap,
              groupmap: e.groupmap,
              // The user metadata of an object is presented as
              // extended attributes, which the cdmi_export_smb_ea
              // capability reports for every container object.
              extendedAttributes: true,
              // A share admitting only read-only hosts presents a
              // read-only file system.
              readOnly: (e.rw_hosts ?? []).length === 0 &&
                (e.ro_hosts ?? []).length > 0,
            },
        });
      }
      // An export that admits no host is established and active, and
      // says why no client reaches it.
      if ((e.rw_hosts ?? []).length === 0 && (e.ro_hosts ?? []).length === 0) {
        problems.push(problem("exports/smb/no-hosts-permitted",
          "No host is permitted.",
          'neither the "rw_hosts" field nor the "ro_hosts" field admits a host, so no ' +
          "client reaches this export", { cdmi_export: name }));
      }
    }
    if (!active && smb !== undefined && smb.offered().includes(e.sharename)) {
      // An entry that has been disabled withdraws its share.
      smb.withdraw(e.sharename);
    }
    const opt = (k: keyof SmbExport) =>
      e[k] !== undefined ? { [k]: e[k] } : {};
    return {
      type: e.type,
      protocol: e.protocol,
      sharename: e.sharename,
      ...opt("comment"), ...opt("domain"), ...opt("domain_servers"),
      ...opt("usermap"), ...opt("groupmap"),
      ...opt("rw_hosts"), ...opt("ro_hosts"), ...opt("root_hosts"),
      ...opt("auth_methods"), ...opt("signing"), ...opt("encryption"),
      ...opt("access_based_enumeration"), ...opt("oplocks"),
      ...opt("continuous_availability"), ...opt("dfs_enabled"),
      ...opt("shadow_copies"),
      ...opt("max_connections"), ...opt("disabled"),
      active: active ? "true" : "false",
      server_addresses: this.opts.smbAddresses ?? [],
      last_problems: problems,
      state_determined_time: now,
    };
  }

  /**
   * Reports an MQTT export entry. The CDMI server connects outbound
   * to the broker, so the entry reports the state of that connection
   * and the counts of what has been published through it.
   */
  /**
   * The endpoints at which a bucket is reached: the listeners of this
   * server that the entry's tls field admits. An S3 client combines one
   * with the bucket name as the addressing_style field says.
   */
  s3Endpoints(e: S3Export): string[] {
    const host = this.opts.host ?? "127.0.0.1";
    const authority = host.includes(":") ? `[${host}]` : host;
    const out: string[] = [];
    if (e.tls !== "required") out.push(`${this.opts.scheme}://${authority}:${this.opts.port}`);
    if (this.opts.tlsPort !== undefined) out.push(`https://${authority}:${this.opts.tlsPort}`);
    return out;
  }

  /**
   * Reports an S3 export entry. Before 0.2 this said every bucket was
   * not served, from the first phase of the S3 work, although requests
   * to it were served; it now reports what serving the entry amounts
   * to on this server.
   */
  private reportS3(name: string, e: S3Export, now: string):
    Record<string, unknown> {
    const problems: Problem[] = [];
    let endpoints: string[] = [];
    let active = false;
    if (e.disabled !== "true") {
      endpoints = this.s3Endpoints(e);
      const host = this.opts.host ?? "127.0.0.1";
      // A subdomain of an address is not a name a client can resolve.
      const isAddress = /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":");
      if (endpoints.length === 0) {
        // No condition specific to S3 describes this, so the common one
        // does, as Annex C directs: not-established is reported "where no
        // other condition of this annex describes the reason".
        problems.push(problem("exports/not-established",
          "The export could not be established.",
          'the tls field is "required", and this CDMI server has no TLS port',
          { cdmi_export: name }));
      } else if (e.addressing_style === "virtual_hosted" && isAddress) {
        problems.push(problem("exports/s3/virtual-hosted-unavailable",
          "The virtual hosted addressing style is unavailable.",
          `this CDMI server is reached at the address ${host}, which has no ` +
          "subdomain in which to address a bucket", { cdmi_export: name }));
        endpoints = [];
      } else {
        active = true;
      }
    }
    return {
      ...e,
      endpoints,
      active: active ? "true" : "false",
      // The aggregate counts of the uploads in progress, which are
      // all a CDMI client observes of them.
      multipart_uploads: String(this.uploads.count(e.bucket_name)),
      multipart_uploads_size: String(this.uploads.size(e.bucket_name)),
      last_problems: problems,
      state_determined_time: now,
    };
  }

  private reportMqtt(name: string, e: MqttExport, now: string, node?: Node):
    Record<string, unknown> {
    const mqtt = this.opts.mqtt;
    let problems: Problem[] = [];
    let state;
    if (e.disabled === "true") {
      // A disabled entry holds no connection, and withdraws one it
      // held.
      if (mqtt !== undefined && mqtt.offered().includes(name)) mqtt.withdraw(name);
    } else if (mqtt === undefined || !mqtt.connecting) {
      // Not broker-unreachable: no connection was attempted.
      problems = [problem("exports/not-established",
        "The export could not be established.",
        "this CDMI server is not configured to connect to an MQTT broker",
        { cdmi_export: name })];
    } else {
      if (node !== undefined) mqtt.offer(name, e, node);
      state = mqtt.state(name);
      problems = state?.problems ?? [];
    }
    return {
      type: e.type,
      broker_uri: e.broker_uri,
      topic: e.topic,
      client_id: e.client_id,
      protocol: e.protocol,
      reconnect_strategy: e.reconnect_strategy,
      qos: e.qos,
      retain: e.retain,
      clean_session: e.clean_session,
      keep_alive_interval: e.keep_alive_interval,
      dequeue_on_publish: e.dequeue_on_publish,
      ...(e.username === undefined ? {} : { username: e.username }),
      // The credential reference, and never the credential. Its scope is not
      // returned: the scope is populated by this server and discloses how
      // credentials are named at the key management server, which a CDMI
      // client that does not register its own credentials has no use for.
      ...(e.password_secret_id === undefined ? {} : {
        password_secret_id: { kms: e.password_secret_id.kms, name: e.password_secret_id.name },
      }),

      ...(e.will === undefined ? {} : { will: e.will }),
      // The TLS settings as supplied. No certificate or key is held
      // in an entry, so none is reported.
      ...(e.tls === undefined ? {} : {
        tls: {
          verify_broker: e.tls.rejectUnauthorized === false ? "false" : "true",
          ...(e.tls.servername === undefined ? {} : { sni: e.tls.servername }),
          ...(e.tls.versions === undefined ? {} : { tls_versions: e.tls.versions }),
          ...(e.tls.ALPNProtocols === undefined
            ? {}
            : { alpn_protocols: e.tls.ALPNProtocols }),
          // The reference, without its scope, and never the certificate.
          ...(e.tls.ca_cert_id === undefined ? {} : {
            ca_cert_id: { kms: e.tls.ca_cert_id.kms, name: e.tls.ca_cert_id.name },
          }),
        },
      }),
      ...(e.refresh_interval === undefined
        ? {}
        : { refresh_interval: e.refresh_interval }),
      ...(e.session_expiry_interval === undefined
        ? {}
        : { session_expiry_interval: e.session_expiry_interval }),
      ...(e.message_expiry_interval === undefined
        ? {}
        : { message_expiry_interval: e.message_expiry_interval }),
      ...(e.content_type === undefined ? {} : { content_type: e.content_type }),
      ...(e.response_topic === undefined ? {} : { response_topic: e.response_topic }),
      ...(e.user_properties === undefined
        ? {}
        : { user_properties: e.user_properties }),
      disabled: e.disabled ?? "false",
      connected: state?.connected === true ? "true" : "false",
      messages_published: String(state?.published ?? 0),
      messages_pending: String(state?.pending ?? 0),
      messages_dropped: String(state?.dropped ?? 0),
      last_connected: state?.lastConnected ?? "",
      // "active" is a field of every export entry, whatever its type. An
      // MQTT export reported "connected" and not this one, so a CDMI client
      // could not ask of it the question it asks of the others (weedmi
      // EMQT-001). An entry that is not disabled and reports no problem is
      // active; whether the broker is reached is what "connected" says.
      active: e.disabled === "true" || problems.length > 0 ? "false" : "true",
      last_problems: problems,
      state_determined_time: now,
    };
  }

  private reportNfs(name: string, e: NfsExport, now: string,
    ns?: string): Record<string, unknown> {
    const problems: Problem[] = [];
    const addresses = this.opts.nfsAddresses ?? [];
    const nfs = this.opts.nfs;
    let active = false;
    if (e.disabled !== "true") {
      if (nfs === undefined || !nfs.running()) {
        problems.push(problem("exports/not-established",
          "The export could not be established.",
          "this CDMI server is not configured to serve an NFS export",
          { cdmi_export: name }));
      } else {
        // The export is established: it is active whether or not a
        // host is admitted, since the server is able to serve a
        // request through it.
        active = true;
        nfs.offer({
          name,
          path: e.path,
          ns: ns ?? "/",
          readOnly: (e.rw_hosts ?? []).length === 0 && (e.ro_hosts ?? []).length > 0,
        });
      }
      // An export that admits no host is established and active, and says
      // why no client reaches it.
      if ((e.rw_hosts ?? []).length === 0 && (e.ro_hosts ?? []).length === 0) {
        problems.push(problem("exports/nfs/no-hosts-permitted",
          "No host is permitted.",
          'neither the "rw_hosts" field nor the "ro_hosts" field admits a host, so no ' +
          "client reaches this export", { cdmi_export: name }));
      }
    }
    // An entry that has been disabled withdraws its export.
    if (!active && nfs !== undefined && nfs.offered().includes(name)) {
      nfs.withdraw(name);
    }
    return {
      type: e.type,
      protocol: e.protocol,
      path: e.path,
      ...(e.usermap !== undefined ? { usermap: e.usermap } : {}),
      ...(e.groupmap !== undefined ? { groupmap: e.groupmap } : {}),
      security_flavors: e.security_flavors ?? ["sys"],
      ...(e.domain !== undefined ? { domain: e.domain } : {}),
      ...(e.domain_servers !== undefined ? { domain_servers: e.domain_servers } : {}),
      squash: e.squash ?? "root_squash",
      anon_uid: e.anon_uid ?? "65534",
      anon_gid: e.anon_gid ?? "65534",
      root_hosts: e.root_hosts ?? [],
      rw_hosts: e.rw_hosts ?? [],
      ro_hosts: e.ro_hosts ?? [],
      recurse: e.recurse ?? "false",
      write_mode: e.write_mode ?? "sync",
      subtree_check: e.subtree_check ?? "false",
      rdma_enabled: e.rdma_enabled ?? "false",
      disabled: e.disabled ?? "false",
      active: active ? "true" : "false",
      server_addresses: addresses,
      last_problems: problems,
      state_determined_time: now,
    };
  }

  /**
   * The exportsProvided field of the object at ns: one entry per export
   * that provides access to it, with one access URI per address it is
   * reachable at.
   *
   * "The exportsProvided field reports **every** protocol export through which
   * an object is accessible, including an export configured on a container
   * object above it", and the "type" member of each export object is "the value
   * of the type field of the export entry ... as shown in [the export types
   * table]" — which is every type, not the two this method walked before 0.98.
   * An NFS, SMB, S3 or CDMI export was accepted, reported in the object's
   * "exports" field, and served, and never appeared here, on the container
   * object it was placed on or on any object beneath it. The reason the field
   * exists is that a CDMI client "that requires the complete set of protocols by
   * which an object is accessible would otherwise read every container object
   * between that object and the root container object"; a set that omits four of
   * the six types this server serves is not that set, and a CDMI client reading
   * it had no way to tell an object reachable over SMB alone from one reachable
   * over nothing.
   *
   * An entry is reported only where the object is reachable through it: the
   * export is not disabled, its server is running, and it has at least one
   * address. "The array shall contain at least one value", so an entry that
   * yields no access URI cannot be reported at all — and an object reachable
   * through no export has the empty array the common fields require.
   */
  providedFor(ns: string): unknown[] {
    const out: unknown[] = [];
    for (const p of this.all()) {
      const e = p.entry as ExportEntry;
      if (disabled(e)) continue;
      // Where the export is placed. An export placed on a container object
      // provides access to the objects within it; an MQTT export is placed on
      // the queue object itself, so it provides access to that object and to
      // nothing beneath it.
      if (isMqtt(e) ? ns !== p.ns : !ns.startsWith(p.ns)) continue;
      const split = splitDecoded("/" + ns.slice(p.ns.length));
      if (!split) continue;
      const reached = this.reachedThrough(p, e, split);
      if (reached === undefined || reached.access_uris.length === 0) continue;
      out.push({
        type: e.type,
        // "The namespace path of the object whose exports field contains the
        // export entry that provides the access."
        export_definition_uri: p.ns,
        export_name: p.name,
        ...reached,
        // The transport, the flags a client presents, and the location, each
        // derived from a field of the entry (ECR-228A). reached supplies
        // client_protocol, which decides whether a version flag is reported,
        // so the two are computed together.
        ...connectionOf(e, reached.client_protocol !== undefined),
      });
    }
    return out;
  }

  /**
   * The access URIs of one export entry for one object, and the client protocol
   * where this server has determined it, or undefined where the object is not
   * reachable through that entry. The remaining three members of an export
   * object are computed by connectionOf, which needs the entry alone.
   *
   * "Each value is formed as the subclause defining that export type specifies,
   * from an address at which the export is reachable and the path of the object
   * relative to the exported object."
   *
   * The client_protocol member is "the data access protocol and the version of
   * it that a client of the exported protocol uses, where the export type
   * permits more than one **and the CDMI server has determined which applies**
   * ... Absent where the export type determines it, as it does for an HTTP
   * export". So it is reported only where the entry offers exactly one version:
   * where it offers several this server has determined nothing, the client
   * choosing at connection time, and naming one of them would be a guess.
   */
  private reachedThrough(p: Placed, e: ExportEntry,
    split: { segs: string[]; trailing: boolean }):
    { access_uris: string[]; client_protocol?: string } | undefined {
    const relative = encodePath(split.segs, split.trailing);
    // The version this server has determined, where the entry fixes one.
    const one = (versions: string[] | undefined) =>
      versions !== undefined && versions.length === 1 ? { client_protocol: versions[0]! } : {};

    if (isHttp(e) || e.type === "CDMI") {
      // A CDMI export carries the fields of an HTTP export and is served over
      // the same listener, so both are formed the same way and both are subject
      // to the base URI rule below.
      const entry = e as HttpExport;
      const { served } = this.servedOrigins(p.name, entry);
      if (served.length === 0) return undefined;
      // "A request within the base URI is a request of the protocol binding,
      // and an export whose path contains it does not serve it. An export whose
      // path is the base URI is the exception": the rule serveInner applies, and
      // it is a rule about the **request URI path** an export serves at. Until
      // 0.98 this compared the object's **namespace path** against the base
      // instead — two different spaces — so an object whose namespace path
      // happened to begin with the base URI's path was reported as reachable
      // through no export while the export served it with 200.
      const uriPath = entry.path.replace(/\/$/, "") + relative;
      if (entry.path !== this.opts.base &&
        hasPrefix(pathSegs(uriPath), pathSegs(this.opts.base))) {
        return undefined;
      }
      return {
        access_uris: served.map((o) => o + uriPath),
        // An HTTP export's protocol is determined by the export type, so no
        // client_protocol is reported for one; a CDMI export names the CDMI
        // versions it serves.
        ...(isHttp(e) ? {} : one(entry.protocol)),
      };
    }

    if (isNfs(e)) {
      // The NFS server must be running for the export to have been
      // established: reportNfs reports the not-established condition where it
      // is not, and an entry that is not established is reached by nobody.
      if (this.opts.nfs === undefined || !this.opts.nfs.running()) return undefined;
      // "nfs://example/docs/mydocument.txt": the address, then the path the
      // entry states within the exported namespace, then the object's path
      // relative to the exported container object (RFC 2224).
      const within = e.path.replace(/\/$/, "") + relative;
      return {
        access_uris: (this.opts.nfsAddresses ?? []).map((a) => `nfs://${authorityOf(a)}${within}`),
        ...one(e.protocol),
      };
    }

    if (isSmb(e)) {
      // Likewise: no SMB server, no share, and an entry naming one is refused
      // at the point it is supplied.
      if (this.opts.smb === undefined) return undefined;
      // "smb://example/shares/docs/mydocument.txt": the address, the share name,
      // then the object's path relative to the exported container object.
      return {
        access_uris: (this.opts.smbAddresses ?? []).map((a) =>
          `smb://${authorityOf(a)}/${encodeURIComponent(e.sharename)}${relative}`),
        ...one(e.protocol),
      };
    }

    if (isS3(e)) {
      // A bucket is addressed by a path segment of an endpoint or by a
      // subdomain of one, as the addressing_style of the entry says, and the
      // object is a key within it. A key has no leading solidus.
      const key = relative.replace(/^\//, "");
      const uris: string[] = [];
      for (const endpoint of this.s3Endpoints(e)) {
        if (e.addressing_style !== "virtual_hosted") {
          uris.push(`${endpoint}/${encodeURIComponent(e.bucket_name)}/${key}`);
        }
        if (e.addressing_style !== "path") {
          // The bucket as a subdomain of the endpoint's host, which reportS3
          // refuses where this server is reached at an address rather than a
          // name — there being no subdomain of an address.
          const at = parseOrigin(endpoint).origin;
          if (at === undefined) continue;
          const address = /^\d+\.\d+\.\d+\.\d+$/.test(at.host) || at.host.includes(":");
          if (address) continue;
          const port = at.port === "80" || at.port === "443" ? "" : `:${at.port}`;
          uris.push(`${at.scheme}://${e.bucket_name}.${at.host}${port}/${key}`);
        }
      }
      return { access_uris: uris, ...one(e.protocol) };
    }

    if (isMqtt(e)) {
      return {
        // The topic of a broker is where the values of the queue
        // object are published, and is what a client subscribes to
        // in order to read them.
        access_uris: [`${e.broker_uri.replace(/\/$/, "")}/${encodeURIComponent(e.topic)}`],
        ...one(e.protocol),
      };
    }
    return undefined;
  }

  /**
   * Refuses a request through an HTTP export that would delete or modify an
   * object under retention or under hold, and says so where it does.
   *
   * A read is not refused: "retention and hold prohibit deletion and
   * modification. They do not prohibit reading". A create within a container
   * object is not refused either, the restriction being on the object it
   * protects and not on the names its container may acquire; the protocol
   * binding draws the line in the same place.
   */
  private refusedByRestriction(res: ServerResponse, at: Node,
    method: string): boolean {
    if (!["PUT", "PATCH", "POST", "DELETE"].includes(method)) return false;
    let held: string | undefined;
    try {
      if (underRestriction(this.store.meta(at).metadata)) {
        held = "this object is under retention or under hold";
      } else if (method === "DELETE" && at.isContainer) {
        // "A container object is not deleted while an object it contains, at any
        // depth, is under retention or under hold ... whether or not that
        // container object is itself under retention or under hold."
        const within = restrictedWithin(at,
          (n) => this.store.children(n)
            .map((c) => ({ name: c.name, node: c.node, isContainer: c.node.isContainer })),
          (n) => this.store.meta(n).metadata);
        if (within !== undefined) {
          held = `this container holds ${within}, which is under retention or under hold`;
        }
      }
    } catch {
      return false;
    }
    if (held === undefined) return false;
    plain(res, 409, `${held}, and is not deleted or modified until that ends`);
    return true;
  }

  /**
   * Whether an HTTP export has the root path of a base URI this server serves
   * the protocol binding at, and so takes the requests there that name no CDMI
   * media type.
   *
   * The base URI is the configured one where none is named. A CDMI export
   * establishes a base URI of its own — "a base URI comes into being when a
   * CDMI export establishes it" — and the same arrangement applies there: the
   * exemption is written of "a base URI at which the CDMI server serves the
   * protocol binding", which is either kind. Until 0.98 this asked about the
   * configured base URI alone, so an HTTP export at a CDMI export's base URI
   * was never selected and a client of the previous edition reaching that base
   * URI was answered with a representation it could not read.
   */
  baseExportServed(base: string = this.opts.base): boolean {
    return this.httpPlaced().some((p) => !disabled(p.entry) && p.entry.path === base);
  }

  // -----------------------------------------------------------------

  /** Serves a request through an export, reporting whether it did. */
  async serve(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
    const began = Date.now();
    this.takeCondition();
    // Each request served by an export has a delegation context of its own,
    // as each request of the protocol binding does.
    const served = await withDelegation(() => this.serveInner(req, res));
    // A line is written where an export served the request. Where none
    // did, the request was not this surface's, and the surface that
    // answers it writes its own.
    const log = this.opts.log;
    const condition = this.takeCondition();
    if (served && log?.enabled === true) {
      log.write({
        surface: "export",
        outcome: String(res.statusCode),
        failed: res.statusCode >= 400,
        operation: req.method ?? "GET",
        instance: exportPathOnly(req.url ?? "/"),
        // An export admits a principal by its entry rather than by
        // authentication, so every request through one is performed as
        // the anonymous principal.
        principal: ANONYMOUS.name,
        ms: Date.now() - began,
        type: condition?.type,
        detail: condition?.detail,
        members: condition?.members,
      });
    }
    return served;
  }

  /** The condition the request in progress reported, for the log. */
  private lastCondition: Condition | undefined = undefined;

  /** The condition recorded since this was last called, and clears it. */
  private takeCondition(): Condition | undefined {
    const c = this.lastCondition;
    this.lastCondition = undefined;
    return c;
  }

  private async serveInner(req: IncomingMessage, res: ServerResponse):
    Promise<boolean> {
    // An S3 export is served first: a bucket is addressed by a path
    // segment of an endpoint or by a subdomain of one, and a request
    // for it is not a request of the HTTP export at the same origin.
    if (await this.serveS3(req, res)) return true;
    const placed = this.httpPlaced();
    if (placed.length === 0) return false;

    // The scheme of a request is the scheme of the connection it
    // arrived on, not a setting: one server answers both, and an origin
    // of the https scheme is reached over TLS alone.
    const scheme = encrypted(req) ? "https" : this.opts.scheme;
    const hostHeader = (req.headers.host as string | undefined) ?? "";
    const colon = hostHeader.lastIndexOf(":");
    const host = (colon >= 0 ? hostHeader.slice(0, colon) : hostHeader)
      .toLowerCase().replace(/\.$/, "");
    const port = colon >= 0 ? hostHeader.slice(colon + 1) : defaultPort(scheme);
    if (host === "") return false;
    const origin = originOf({ scheme, host, port });

    const url = req.url ?? "/";
    const q = url.indexOf("?");
    const rawPath = q < 0 ? url : url.slice(0, q);
    const query = q < 0 ? "" : url.slice(q);
    const split = splitDecoded(removeDotSegments(rawPath === "" ? "/" : rawPath));
    if (!split) {
      plain(res, 400, "the request URI path is not well formed");
      return true;
    }

    let sel: Selected | undefined;
    let hostKnown = false;
    for (const p of placed) {
      const e = p.entry;
      for (const o of e.origins) {
        if (parseOrigin(o).origin?.host === host) hostKnown = true;
      }
      if (disabled(e)) continue;
      const { served } = this.servedOrigins(p.name, e);
      if (!served.includes(origin)) continue;
      const ep = pathSegs(e.path);
      if (!hasPrefix(split.segs, ep)) continue;
      sel = {
        name: p.name, entry: e, epath: ep, rel: split.segs.slice(ep.length),
        trailing: split.trailing, ns: "", base: p.ns,
      };
      break;
    }
    // A request within the base URI is a request of the protocol binding,
    // and an export whose path contains it does not serve it. An export
    // whose path is the base URI is the exception, handled by the caller.
    if (sel && sel.entry.path !== this.opts.base &&
      hasPrefix(split.segs, pathSegs(this.opts.base))) {
      sel = undefined;
    }
    if (!sel) {
      if (hostKnown) {
        plain(res, 404, "no export serves this request");
        return true;
      }
      return false;
    }

    const changes = ["PUT", "PATCH", "POST"].includes(req.method ?? "GET");
    for (const [i, n] of sel.rel.entries()) {
      if (/[/?#]/.test(n) || n === "." || n === "..") {
        plain(res, 400, `the segment ${JSON.stringify(n)} cannot be the name of a CDMI object`);
        return true;
      }
      if (presentable(n)) continue;
      // A request that reads a reserved name addresses nothing; one that
      // would create an object with that name is malformed, since a CDMI
      // client may not create a reserved name.
      // The prefix is tested here and not the reserved names table, because
      // the HTTP export clause writes the prefix into a requirement of its
      // own: a CDMI server "shall exclude the following from the mapping and
      // from listings, and shall respond to a request naming or beneath one
      // with 404 Not Found: an object whose name begins with cdmi_ ... A PUT
      // request that would create such a name shall be rejected with 400 Bad
      // Request" (revision 365). The binding no longer reserves the whole
      // prefix, so an object a client creates there under an unreserved
      // cdmi_ name is reachable through the binding and not through an
      // export of its container. NOTES-on-reserved-names.md records that, and
      // ECR-247A asks for the two to be settled together.
      if (changes && i === sel.rel.length - 1 && n.startsWith("cdmi_")) {
        await this.fail(req, res, sel,
          malformed(`${JSON.stringify(n)} begins with "cdmi_", which is reserved`));
        return true;
      }
      await this.fail(req, res, sel, notFound(n));
      return true;
    }
    // A request names an object within the exported container object, so
    // the namespace path is that container's, with the segments below
    // the export's own path appended.
    sel.ns = sel.rel.length === 0
      ? sel.base
      : sel.base + sel.rel.join("/") + (sel.trailing ? "/" : "");
    if (sel.rel.length === 0 && !sel.trailing) {
      this.redirect(res, sel, query);
      return true;
    }

    const method = req.method ?? "GET";
    // "auth_method: the HTTP authentication scheme by which a request is
    // associated with a principal". Where the entry names one, the request
    // acts for the principal its credentials resolve to, within the domain
    // that owns the object; where it names none, or names "anonymous", the
    // request acts for the anonymous principal and presented credentials
    // are ignored, as the field requires.
    let who: Principal = ANONYMOUS;
    const entryScheme = sel.entry.auth_method ?? "anonymous";
    if (entryScheme !== "anonymous" && this.opts.exportPrincipal !== undefined) {
      const got = await this.opts.exportPrincipal(req, sel.ns, method);
      if ("refused" in got) {
        const c = got.refused;
        plain(res, c.status, c.detail, c.headers);
        return true;
      }
      who = got.who;
    }
    // "Neither this field nor auth_method grants access: ANONYMOUS@ shall
    // obtain only what the access control lists grant it." An export is a
    // route to an object and not a grant upon it, so the list of the object
    // addressed is evaluated for every request, against the principal the
    // entry's scheme resolved. This server served whatever an export
    // reached before 0.70, the entry being the grant.
    // "A preflight request is answered from the metadata of the object
    // addressed, without authentication and without evaluating its access
    // control lists, because a browser presents no credentials on one."
    // The access check below would otherwise refuse every preflight of an
    // export that names an authentication scheme, and a browser would
    // never make the request that follows it (weedmi EHTP-009).
    if (isPreflight(req)) {
      const preflightAllow = readOnly(sel.entry)
        ? "GET, HEAD, OPTIONS"
        : "GET, HEAD, PUT, POST, PATCH, DELETE, OPTIONS";
      answerPreflight(this.store, req, res, sel.ns, preflightAllow.split(", "));
      return true;
    }
    // "Where an object is locked, a CDMI server shall refuse an operation
    // that the value of the item does not permit, whether the operation
    // reaches the object through a protocol binding, through an export or
    // through an import ... an HTTP export reports an HTTP status code of
    // 403 Forbidden" (revision 327, the locking subclause).
    if (method === "PUT" || method === "POST" || method === "PATCH" || method === "DELETE") {
      const locked = this.opts.lockCovering?.(sel.ns,
        method === "DELETE" ? "delete" : "update");
      if (locked !== undefined) {
        plain(res, 403, `this object is locked by the cdmi_lock item of ${locked}`);
        return true;
      }
    }
    const at = nodeAtPath(this.store, sel.ns);
    if (at === undefined && (method === "PUT" || method === "POST")) {
      // The object does not exist, so what governs the request is the
      // container that would hold it: a create through an export is
      // permitted by the list of that container, and by nothing else.
      const holder = nodeAtPath(this.store, sel.ns.replace(/\/[^/]*\/?$/, "/"));
      const bit = sel.ns.endsWith("/") ? M.ADD_SUBCONTAINER : M.ADD_OBJECT;
      if (holder !== undefined && !this.permits(holder, bit, who)) {
        if (who.name === ANONYMOUS.name && entryScheme !== "anonymous") {
          plain(res, 401, "this export serves an authenticated principal",
            { "WWW-Authenticate": wwwAuthenticate(entryScheme, this.opts.resourceMetadataBase) });
          return true;
        }
        plain(res, 403, "the access control list of the container does not permit this operation");
        return true;
      }
    }
    if (at !== undefined) {
      const wanted = method === "DELETE"
        ? M.DELETE
        : method === "GET" || method === "HEAD" || method === "OPTIONS"
          ? (at.isContainer ? M.LIST_CONTAINER : M.READ_OBJECT)
          : method === "POST" ? M.ADD_OBJECT : M.WRITE_OBJECT;
      const operation = method === "DELETE"
        ? "cdmi_delete"
        : method === "GET" || method === "HEAD" || method === "OPTIONS"
          ? (at.isContainer ? "cdmi_list" : "cdmi_read")
          : method === "POST" ? "cdmi_create" : "cdmi_modify";
      // An object that has delegated access control is governed by its
      // provider however it is reached, and the decision applies in place
      // of the list.
      const delegated = this.opts.dac !== undefined &&
        delegationOf(this.store.meta(at)) !== undefined;
      if (delegated) {
        try {
          await decideFor(this.opts.dac!, this.store, at, who, operation);
        } catch (e) {
          if (!(e instanceof DelegationRefused)) throw e;
          plain(res, 403, "the delegated access control provider of this object did not authorize this operation");
          return true;
        }
      }
      if (!this.permits(at, wanted, who)) {
        // Where the entry names a scheme and no principal was presented,
        // the answer is 401 rather than 403: credentials may help.
        if (who.name === ANONYMOUS.name && entryScheme !== "anonymous") {
          plain(res, 401, "this export serves an authenticated principal",
            { "WWW-Authenticate": wwwAuthenticate(entryScheme, this.opts.resourceMetadataBase) });
          return true;
        }
        plain(res, 403, delegated
          ? "the delegated access control provider of this object did not permit this operation"
          : "the access control list of this object does not permit this operation");
        return true;
      }
      if (delegated) {
        for (const [name, value] of Object.entries(delegatedHeaders())) res.setHeader(name, value);
      }
      // "A rule of this document that governs what may be done to an object
      // governs a request that reaches that object through an export as it
      // governs an operation of a protocol binding. The retention and hold
      // rules ... apply, so that a request through an export that would delete
      // or modify an object under retention or under hold is refused, however
      // the exported protocol expresses that request" (exports model, revision
      // 365). The status table of this subclause names the answer: "conflict,
      // including retention, hold, and a block export active on the object" is
      // 409. Until 0.109 an HTTP export answered 204 to a PUT that overwrote an
      // object under retention, and 204 to the DELETE that then removed it,
      // while the protocol binding refused both with 409.
      if (this.refusedByRestriction(res, at, method)) return true;
    }
    const allow = readOnly(sel.entry)
      ? "GET, HEAD, OPTIONS"
      : sel.ns.endsWith("/")
        ? "GET, HEAD, PUT, POST, DELETE, OPTIONS"
        : "GET, HEAD, PUT, PATCH, DELETE, OPTIONS";
    // A reference is presented through an HTTP export as a redirection
    // to its destination, which is what the previous edition did and
    // what the section defining this export type requires. A delete is
    // not redirected: it removes the reference and not its destination.
    if (method !== "DELETE" && method !== "OPTIONS") {
      const destination = await this.referenceAt(sel);
      if (destination !== undefined) {
        // "A request naming a reference shall be answered with 307 Temporary
        // Redirect and a Location header field giving the destination, the
        // status code preserving the request method" (revision 211; before it
        // a method other than POST was answered with 302).
        res.writeHead(307, {
          Location: this.locationOf(sel, destination),
          "Content-Length": "0",
        });
        res.end();
        return true;
      }
    }

    applyCors(this.store, req, res, sel.ns);
    try {
      switch (method) {
        case "OPTIONS":
          res.writeHead(204, { Allow: allow });
          res.end();
          break;
        case "GET":
        case "HEAD":
          await this.read(req, res, sel, query, who);
          break;
        default:
          if (!allow.split(", ").includes(method)) {
            res.writeHead(405, { Allow: allow });
            res.end();
            break;
          }
          if (method === "PUT" || method === "PATCH") {
            await this.write(req, res, sel, method === "PATCH", who);
          } else if (method === "POST") {
            await this.post(req, res, sel, origin);
          } else {
            await this.remove(req, res, sel);
          }
      }
    } catch (err) {
      await this.fail(req, res, sel, err);
    }
    return true;
  }

  /**
   * A POST to a container object of a writable export: "a POST request to a
   * container object shall be answered by a CDMI server by creating a data
   * object with a server-assigned name, with 201 Created and a Location header
   * field giving its absolute request URI within the export; the CDMI server
   * shall not report its namespace path or object ID." A form-based file upload,
   * "a POST request whose Content-Type is multipart/form-data (RFC 7578)", is
   * served "where cdmi_export_http_form_upload is available" (revision 269,
   * which moved it from cdmi_multipart_mime; ECR-115B), which this server
   * publishes: the file's name is taken where it is one this container
   * can hold and holds nothing by, and otherwise the server assigns one, never
   * replacing an object. Before 0.51 an export answered POST with 405.
   */
  private async post(req: IncomingMessage, res: ServerResponse, sel: Selected, origin: string): Promise<void> {
    const body = await readBody(req);
    const ct = req.headers["content-type"] as string | undefined;
    let content = body;
    let wanted: string | undefined;
    let typed = ct;
    if (ct !== undefined && /^\s*multipart\/form-data\b/i.test(ct)) {
      const boundary = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(ct);
      if (boundary === null) throw malformed("a form-based file upload states the boundary of its parts");
      const file = uploadedFile(body, boundary[1] ?? boundary[2]);
      if (file === undefined) throw malformed("a form-based file upload holds no part carrying a file");
      content = file.body;
      typed = file.type === "" ? undefined : file.type;
      // A filename may carry a path, which a browser may send; its last
      // segment is the name asked for.
      wanted = file.filename.split(/[\\/]/).pop();
    }
    const { mimetype, vte } = mimetypeOf(typed, content);

    this.checkNotAnActiveSource(sel.ns, "change");
    const r = new Resolver(this.store);
    const pv = await r.view(sel.ns);
    if (pv.unavail) throw pv.unavail;
    const target = await ensureWriteTarget(this.store, pv);
    const free = async (n: string) => this.store.tryLookup(target, n) === undefined &&
      (await resolveFile(this.store, pv, n)) === undefined;
    // The prefix, not the reserved names table: a CDMI server "may derive the
    // assigned name from that file name, but shall assign a name of its own
    // where the file name contains /, ? or #, is a dot segment, begins with
    // cdmi_, is not valid UTF-8, or is already in use" (revision 365).
    const acceptable = (n: string | undefined): n is string => n !== undefined && n !== "" && n !== "." &&
      n !== ".." && !n.startsWith("cdmi_") && !/[\u0000-\u001f\u007f]/.test(n) && Buffer.byteLength(n) <= 255;
    let name: string;
    if (acceptable(wanted) && await free(wanted)) {
      name = wanted;
    } else {
      // A name of the server's choosing, keeping the extension of the one asked
      // for so that the object is served with the same meaning.
      const dot = wanted === undefined ? -1 : wanted.lastIndexOf(".");
      const ext = dot > 0 && /^\.[A-Za-z0-9]{1,10}$/.test(wanted!.slice(dot)) ? wanted!.slice(dot) : "";
      do name = `${randomUUID()}${ext}`; while (!(await free(name)));
    }
    const node = this.store.createData(target, name, {
      mimetype, vte,
      // A plain POST carries user metadata in header fields as a PUT does; the
      // parts of a form carry none.
      metadata: wanted === undefined ? checkHeaderMetadata(headerMetadata(req)) : {},
      acl: aclForNewObject(undefined, this.store.meta(target).acl, false),
    });
    await this.store.setValue(node, content);
    res.writeHead(201, { Location: origin + this.location(sel, sel.ns + name), "Content-Length": "0" });
    res.end();
  }

  private redirect(res: ServerResponse, sel: Selected, query: string): void {
    const loc = encodePath([...sel.epath, ...sel.rel], true) + query;
    res.writeHead(307, { Location: loc });
    res.end();
  }

  private location(sel: Selected, ns: string): string {
    const within = ns.startsWith(sel.base) ? ns.slice(sel.base.length) : ns;
    const t = within.replace(/^\/+/, "").replace(/\/+$/, "");
    const rel = t === "" ? [] : t.split("/");
    return encodePath([...sel.epath, ...rel], ns.endsWith("/"));
  }

  private async fail(req: IncomingMessage, res: ServerResponse, sel: Selected,
    err: unknown): Promise<void> {
    const c = err instanceof Condition
      ? err
      : new Condition(500, "server-error", "The CDMI server encountered an error.", String(err));
    if ((c.status === 404 || c.status === 403) && sel.entry.error_document !== undefined) {
      const docNS = sel.base + sel.entry.error_document;
      if (docNS !== sel.ns) {
        const found = await this.resolveData(new Resolver(this.store), docNS);
        if (found) {
          const m = this.store.meta(found.node);
          const body = await this.store.readValue(found.node);
          res.writeHead(c.status, {
            "Content-Type": m.mimetype || "application/octet-stream",
            "X-Content-Type-Options": "nosniff",
            "Content-Length": String(body.length),
          });
          res.end(req.method === "HEAD" ? undefined : body);
          return;
        }
      }
    }
    // The occurrence is identified by the request it arose from,
    // which is what a client that received it holds.
    if (req.url !== undefined) c.at(req.url);
    this.lastCondition = c;
    const body = Buffer.from(JSON.stringify(c.toProblem(), null, 2) + "\n");
    res.writeHead(c.status, {
      "Content-Type": "application/problem+json",
      "Content-Length": String(body.length),
    });
    res.end(req.method === "HEAD" ? undefined : body);
  }

  private async resolveData(r: Resolver, ns: string):
    Promise<{ ref: ObjRef; node: Node; view: View } | undefined> {
    if (ns.endsWith("/")) return undefined;
    const cut = ns.lastIndexOf("/");
    let pv: View;
    try {
      pv = await r.view(ns.slice(0, cut + 1));
    } catch {
      return undefined;
    }
    const found = await resolveFile(this.store, pv, ns.slice(cut + 1));
    return found ? { ref: found.ref, node: found.node, view: pv } : undefined;
  }

  /**
   * The Cache-Control of a response transporting a value or a listing:
   * "max-age with the value of max_age where that is greater than 0 and
   * no-cache where it is 0, and private in addition where the request was
   * authorized under an identity other than ANONYMOUS@". The private
   * directive was missing before 0.79, so a shared cache could hold one
   * principal's response and serve it to another (weedmi EHTP).
   */
  private cacheControl(e: HttpExport, who: Principal = ANONYMOUS): string {
    const age = e.max_age === undefined || e.max_age === "0"
      ? "no-cache"
      : `max-age=${e.max_age}`;
    return who.name === ANONYMOUS.name ? age : `${age}, private`;
  }

  /**
   * The Vary of a response an export serves, beside whatever the
   * representation selection adds.
   *
   * Where the entry names an authentication scheme, what the response contains
   * depends on the credentials the request presented, so a cache that stored it
   * under the request URI alone could serve one principal's object to another.
   * The protocol binding pairs "Cache-Control: private" with a Vary on
   * Authorization for exactly this reason; an export marked the response
   * private and named no Vary at all, so "private" told a shared cache not to
   * store it and told a private cache nothing about what the stored copy
   * depended on.
   */
  private varyOn(e: HttpExport, also?: string): string {
    const parts = also === undefined ? [] : [also];
    if ((e.auth_method ?? "anonymous") !== "anonymous") parts.push("Authorization");
    return parts.join(", ");
  }

  private async read(req: IncomingMessage, res: ServerResponse, sel: Selected,
    query: string, who: Principal = ANONYMOUS): Promise<void> {
    const r = new Resolver(this.store);
    let cv: View;
    if (sel.ns === sel.base) {
      cv = await r.view(sel.base);
    } else {
      const cut = sel.ns.replace(/\/$/, "").lastIndexOf("/");
      const parentNS = sel.ns.slice(0, cut + 1);
      const name = sel.ns.replace(/\/$/, "").slice(cut + 1);
      const pv = await r.view(parentNS);
      if (pv.unavail) throw pv.unavail;
      if (!sel.ns.endsWith("/")) {
        const found = await resolveFile(this.store, pv, name);
        // A path that denotes only a queue object is mapped, and no
        // method but OPTIONS is served for it: serving the value of a
        // queue object by GET would either remove values from it or
        // return a part of it.
        const node = found === undefined ? undefined : nodeOf(found.ref);
        if (node !== undefined && this.store.meta(node).isQueue) {
          res.writeHead(405, { Allow: "OPTIONS", "Content-Length": "0" });
          return res.end();
        }
        const servable = found;
        if (!servable) {
          try {
            await r.child(pv, name);
          } catch {
            throw notFound(sel.ns);
          }
          return this.redirect(res, sel, query);
        }
        return this.sendValue(req, res, sel, servable.ref, name, who);
      }
      cv = await r.child(pv, name);
    }
    if (sel.entry.index_document !== undefined) {
      const found = await resolveFile(this.store, cv, sel.entry.index_document);
      if (found) {
        return this.sendValue(req, res, sel, found.ref, sel.entry.index_document, who);
      }
    }
    return this.sendListing(req, res, sel, cv, who);
  }

  /**
   * The value of a data object an active filesystem import interprets is
   * reached through the imported namespace alone. An export that
   * mediates every operation, as an HTTP export does, enforces that on
   * the one object rather than refusing to serve at all: see K9 in
   * NOTES-on-nfs-server.md, where the draft requires the stronger rule.
   */
  private checkNotAnActiveSource(ns: string, what: "read" | "change"): void {
    const sources = this.store.imageSourcesOf(ns).filter((s) => !s.disabled);
    if (sources.length === 0) return;
    if (what === "read" && !sources.some((s) => s.writeEnabled)) return;
    throw conflict(
      "the value of %j is interpreted by an active file system import, and is reached " +
      "through the imported namespace alone", ns);
  }

  private async sendValue(req: IncomingMessage, res: ServerResponse, sel: Selected,
    ref: ObjRef, name: string, who: Principal = ANONYMOUS): Promise<void> {
    this.checkNotAnActiveSource(sel.ns, "read");
    // An object of an imported file system has no row of the store, so
    // its size, times and validator come from the file system itself.
    const v = viewOf(this.store, ref);
    const m: Meta = {
      objectID: v.objectID ?? "",
      parent: null,
      name,
      isContainer: false,
      // An object of an imported file system is not a queue object:
      // an imported namespace presents container objects and data
      // objects, as the imports model requires.
      isQueue: false,
      nextDesignator: 0,
      queueCount: 0,
      hash: null,
      mimetype: v.mimetype ?? "",
      vte: v.vte ?? "",
      rel: undefined,
      extensions: undefined,
      reference: undefined,
      group: "",
      acount: 0,
      mcount: 0,
      valueID: v.objectID ?? "",
      frozen: false,
      pinnedID: null,
      partial: false,
      contiguous: v.size,
      isDomain: false,
      domain: null,
      versionOf: null,
      versionParent: null,
      currentVersion: null,
      metadata: v.userMetadata,
      owner: v.owner ?? "",
      acl: v.acl ?? null,
      imports: undefined,
      exports: undefined,
      version: v.version,
      size: v.size,
      ctime: v.ctime ?? 0,
      mtime: v.mtime ?? 0,
      atime: v.atime ?? 0,
    };
    // "Where cdmi_representations is available for a data object, the CDMI server
    // shall select, for a GET or HEAD request, among the representations reported
    // in the cdmi_representations storage system metadata item ... by proactive
    // content negotiation on Accept."
    //
    // After the encrypted-value handling above, as the encryption subclause
    // requires: "an encrypted value and its plaintext are not representations
    // within the meaning of [this subclause]; the CDMI server shall apply that
    // subclause to the plaintext after applying this one."
    let selected: Representation | undefined;
    let bodySize = m.size;
    let variesByAccept = false;
    let contentType = m.mimetype || "application/octet-stream";
    if (VALUE_REPRESENTATIONS && m.size > 0 && m.size <= REPRESENTABLE_LIMIT) {
      // The signature from the leading octets alone: a value that is not a picture
      // is not read further, so an export of a directory of text serves it at the
      // cost it always did.
      let whole: Buffer | undefined;
      try {
        if (heldType(await readValueOf(this.store, ref, 0, 8)) !== undefined) {
          whole = await readValueOf(this.store, ref);
        }
      } catch {
        whole = undefined;
      }
      const types = whole === undefined ? [] : typesOf(whole);
      if (whole !== undefined && types.length > 1) {
        const def = defaultType(whole, this.opts.defaultRepresentationOf?.(ref)) ?? types[0]!;
        // Every response for such an object varies by Accept, the ciphertext case
        // above included: which representation a shared cache holds depends on it.
        res.setHeader("Vary", this.varyOn(sel.entry, "Accept"));
        variesByAccept = true;
        const want = negotiate(req.headers.accept as string | undefined,
          orderedFor(whole, def), def);
        if (want === undefined) {
          // "Where none is acceptable it shall return 406 Not Acceptable, and
          // shall not disclose the existence of a representation the principal is
          // not permitted to read." Nothing here names what was available.
          throw notAcceptable("no representation of this object is acceptable");
        }
        selected = derive(whole, want);
        if (selected !== undefined) {
          bodySize = selected.size;
          // "The response shall report the media type and storage system metadata
          // of the selected representation."
          contentType = selected.type;
        }
      }
    }
    // The validator names the representation returned. Two representations of one
    // URI sharing a strong validator is how a conditional request goes wrong: a
    // client that cached the PNG and revalidates with Accept: image/jpeg would be
    // answered 304 and would go on using the PNG as a JPEG.
    const tag = selected === undefined
      ? valueETag(m)
      : `"${valueETag(m).replace(/"/g, "")}-${selected.type.replace("/", "-")}"`;
    const lastModified = new Date(m.mtime).toUTCString();
    const headers: Record<string, string> = {
      "Content-Type": contentType,
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": this.cacheControl(sel.entry, who),
      ...(variesByAccept
        ? { Vary: this.varyOn(sel.entry, "Accept") }
        : this.varyOn(sel.entry) === "" ? {} : { Vary: this.varyOn(sel.entry) }),
      ETag: tag,
      "Last-Modified": lastModified,
      "Accept-Ranges": "bytes",
    };
    // A user metadata item whose name matches the pattern is carried
    // in a header field of the response.
    for (const [k, value] of Object.entries(m.metadata)) {
      if (carriedAsHeader(k, value)) headers[k] = value as string;
    }
    const inm = req.headers["if-none-match"] as string | undefined;
    if (inm && (inm === "*" || inm.split(",").some((p) => p.trim() === tag))) {
      res.writeHead(304, headers);
      return res.end();
    }
    const im = req.headers["if-match"] as string | undefined;
    if (im && im !== "*" && !im.split(",").some((p) => p.trim() === tag)) {
      throw new Condition(412, "", "Precondition Failed", "a precondition was not met");
    }

    // "Where such a request prefers a media type other than
    // application/cms and application/jose+json, and the cdmi_enc_access
    // capability is available, the CDMI server shall obtain the key and
    // return the plaintext", under the identity of the request and never
    // for ANONYMOUS@.
    // An encrypted object is served as one of two media types, chosen by
    // the request's Accept, so every response for one varies by it —
    // including the ciphertext, which a cache must not serve to a request
    // that would have received the plaintext.
    if (isEncryptedMediaType(m.mimetype)) res.setHeader("Vary", this.varyOn(sel.entry, "Accept"));
    if (isEncryptedMediaType(m.mimetype) && this.opts.decryptForExport !== undefined &&
        who.name !== ANONYMOUS.name) {
      let named: string | undefined;
      try {
        named = readEncryptedValue(m.mimetype, await readValueOf(this.store, ref)).plaintextType;
      } catch {
        // A value that is not the structure its media type promises is
        // served as it is stored.
      }
      if (named !== undefined &&
          prefersPlaintext(req.headers.accept as string | undefined, m.mimetype, named)) {
        try {
          const got = await this.opts.decryptForExport(ref, who);
          res.writeHead(200, {
            ...headers,
            "Content-Type": got.plaintextType,
            "Content-Length": String(got.plaintext.length),
            // "The response shall include Vary: Accept": which of the two
            // a shared cache holds depends on the request's Accept, and
            // without this one client's plaintext is served to another
            // that asked for the ciphertext (weedmi EHTP-010).
            Vary: this.varyOn(sel.entry, "Accept"),
          });
          return (req.method ?? "GET") === "HEAD" ? res.end() : res.end(got.plaintext);
        } catch {
          // "where decryption fails and the encrypted type is acceptable,
          // it shall return the encrypted value."
        }
      }
    }
    const range = parseRangeHeader(req.headers.range as string | undefined, bodySize);
    if (range === "unsatisfiable") {
      res.writeHead(416, { ...headers, "Content-Range": `bytes */${bodySize}` });
      return res.end();
    }
    const [first, last] = range ?? [0, Math.max(bodySize - 1, 0)];
    const length = bodySize === 0 ? 0 : last - first + 1;
    // "Shall apply a Range to that representation": the range is of the octets
    // returned and not of the octets stored, which differ in length.
    const body = selected === undefined
      ? await readValueOf(this.store, ref, first, length)
      : selected.bytes.subarray(first, first + length);
    if (range) {
      res.writeHead(206, {
        ...headers,
        // The length of the representation returned, not of the one stored: a
        // Content-Range naming the stored length beside the derived octets tells
        // a client the resource is a size it is not, and a client fetching the
        // rest by range would ask for octets that do not exist.
        "Content-Range": `bytes ${first}-${last}/${bodySize}`,
        "Content-Length": String(body.length),
      });
    } else {
      res.writeHead(200, { ...headers, "Content-Length": String(body.length) });
    }
    res.end(req.method === "HEAD" ? undefined : body);
    void name;
  }

  /**
   * A listing of a container object. The draft leaves its form to the
   * server; seedmi serves JSON where the Accept header field asks for it,
   * and HTML otherwise. Vary names Accept either way.
   */
  private async sendListing(req: IncomingMessage, res: ServerResponse, sel: Selected,
    cv: View, who: Principal = ANONYMOUS): Promise<void> {
    // A reference is listed under its own name: the question mark of a
    // CDMI listing has no meaning to a client of an export, which
    // learns what the name is when it follows it and is redirected.
    const all = await listChildren(this.store, cv, "plain");
    // A queue object is omitted from a listing: no method but OPTIONS
    // is served for it, so a name a client could not follow is not
    // offered.
    const at = nodeOf(cv.held);
    const kids = at === undefined
      ? all
      : all.filter((k) => {
        if (k.endsWith("/")) return true;
        const child = this.store.tryLookup(at, k);
        return child === undefined || !this.store.meta(child).isQueue;
      });
    const accept = (req.headers.accept as string | undefined) ?? "";
    const wantsJSON = accept.split(",").some((p) => {
      const t = p.split(";")[0].trim().toLowerCase();
      return t === "application/json" || t === "application/*";
    });
    let body: Buffer;
    let ct: string;
    if (wantsJSON) {
      body = Buffer.from(JSON.stringify({ children: kids }) + "\n");
      ct = "application/json";
    } else {
      const title = escapeHTML(this.location(sel, sel.ns));
      const rows = kids.map((k) => {
        const href = "./" + encodeURIComponent(k.replace(/\/$/, "")) + (k.endsWith("/") ? "/" : "");
        return `<li><a href="${escapeHTML(href)}">${escapeHTML(k)}</a></li>`;
      });
      body = Buffer.from(
        `<!DOCTYPE html>\n<html><head><meta charset="utf-8"><title>Index of ${title}` +
        `</title></head>\n<body><h1>Index of ${title}</h1>\n<ul>\n` +
        (sel.ns === sel.base ? "" : '<li><a href="../">../</a></li>\n') +
        rows.join("\n") + "\n</ul>\n</body></html>\n");
      ct = "text/html; charset=utf-8";
    }
    res.writeHead(200, {
      "Content-Type": ct,
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": this.cacheControl(sel.entry, who),
      Vary: this.varyOn(sel.entry, "Accept"),
      "Content-Length": String(body.length),
    });
    res.end(req.method === "HEAD" ? undefined : body);
  }

  private async write(req: IncomingMessage, res: ServerResponse, sel: Selected,
    patch: boolean, who: Principal = ANONYMOUS): Promise<void> {
    const body = await readBody(req);
    // RFC 9110: a conditional write is evaluated before it is performed,
    // and a condition that does not hold is 412 Precondition Failed. An
    // export honoured these on a read alone before 0.71 (weedmi EHTP-004).
    const held = nodeAtPath(this.store, sel.ns);
    const tag = held === undefined ? undefined : valueETag(this.store.meta(held));
    const ifMatch = req.headers["if-match"] as string | undefined;
    const ifNone = req.headers["if-none-match"] as string | undefined;
    const matches = (header: string) =>
      tag !== undefined && (header.trim() === "*" ||
        header.split(",").some((p) => p.trim() === tag));
    if (ifMatch !== undefined && !matches(ifMatch)) {
      plain(res, 412, "the if-match condition does not hold");
      return;
    }
    if (ifNone !== undefined && (ifNone.trim() === "*" ? held !== undefined : matches(ifNone))) {
      plain(res, 412, "the if-none-match condition does not hold");
      return;
    }
    const r = new Resolver(this.store);

    if (sel.ns.endsWith("/")) {
      if (patch) {
        res.writeHead(405, { Allow: "GET, HEAD, PUT, POST, DELETE, OPTIONS" });
        return res.end();
      }
      if (body.length > 0) {
        throw malformed("a request that creates a container object shall not contain a body");
      }
      return this.putContainer(res, r, sel, who);
    }

    const ctHeader = req.headers["content-type"] as string | undefined;
    const { mimetype, vte } = mimetypeOf(ctHeader, body);
    const contentRange = parseContentRange(req.headers["content-range"] as string | undefined);
    if (req.headers["content-range"] !== undefined &&
      (!contentRange || body.length !== contentRange[1] - contentRange[0] + 1)) {
      throw malformed("the Content-Range header field is not well formed, or does not match the body");
    }

    this.checkNotAnActiveSource(sel.ns, "change");
    const cut = sel.ns.lastIndexOf("/");
    const pv = await r.view(sel.ns.slice(0, cut + 1));
    if (pv.unavail) throw pv.unavail;
    const name = sel.ns.slice(cut + 1);
    const found = await resolveFile(this.store, pv, name);

    if (!found) {
      if (patch) throw notFound(sel.ns);
      // The prefix, not the reserved names table: "A PUT request that would
      // create such a name shall be rejected with 400 Bad Request" is written
      // against the prefix in the HTTP export clause (revision 365).
      if (name.startsWith("cdmi_")) {
        throw malformed(`${JSON.stringify(name)} begins with "cdmi_", which is reserved`);
      }
      const target = await ensureWriteTarget(this.store, pv);
      if (this.store.tryLookup(target, name)) {
        throw conflict("the write target already holds an object named %j", name);
      }
      const supplied = checkHeaderMetadata(headerMetadata(req));
      const node = this.store.createData(target, name, {
        mimetype, vte,
        // Each header field whose name matches the pattern creates a
        // user metadata item.
        metadata: supplied,
        // An object created through an export inherits from the container
        // that holds it, as one created through the binding does, and is
        // owned by the principal that created it, so that the same
        // principal may write it again.
        owner: who.name,
        acl: aclForNewObject(undefined, this.store.meta(target).acl, false),
      });
      if (contentRange) {
        await this.store.writeValue(node, contentRange[0], body);
      } else {
        await this.store.setValue(node, body);
      }
      res.writeHead(201, { Location: this.location(sel, sel.ns) });
      return res.end();
    }

    if (pv.writeRank === undefined) {
      throw pv.writeUnavail ?? forbidden("%s cannot be changed: %s", sel.ns, pv.writeWhy);
    }
    const cmp = rankCmp(found.layer.rank, pv.writeRank);
    let node = found.node;
    if (cmp < 0) throw denyChange(pv, sel.ns, found.layer.rank, "update");
    if (cmp > 0) {
      // An export operation is never a complete replacement, so the object
      // is copied up and keeps its metadata (revision 49).
      node = await this.store.copyUp(found.node, await ensureWriteTarget(this.store, pv), name);
    }
    if (contentRange) {
      await this.store.writeValue(node, contentRange[0], body);
    } else {
      await this.store.setValue(node, body);
    }
    // A range update with no Content-Type leaves the media type as it
    // was. A header field carrying a user metadata item creates it, or
    // updates the value of an existing one, keeping the name that item
    // already has where the two differ only in case; an empty value
    // removes it.
    const supplied = checkHeaderMetadata(headerMetadata(req));
    const changesMetadata = Object.keys(supplied).length > 0;
    // The WRITE_METADATA permission is required in addition to what
    // the method requires. An export serves a principal the export
    // entry admits, and the permission is evaluated against the
    // object as it is for any other request.
    if (changesMetadata && !this.permits(node, M.WRITE_METADATA)) {
      throw forbidden("changing the metadata of %s is not permitted", sel.ns);
    }
    if (!contentRange || ctHeader !== undefined || changesMetadata) {
      const m = this.store.meta(node);
      if (!contentRange || ctHeader !== undefined) {
        m.mimetype = mimetype;
        m.vte = vte;
      }
      for (const [k, value] of Object.entries(supplied)) {
        const already = Object.keys(m.metadata)
          .find((n) => n.toLowerCase() === k.toLowerCase());
        if (value === "") {
          if (already !== undefined) delete m.metadata[already];
          continue;
        }
        m.metadata[already ?? k] = value;
      }
      this.store.setMeta(node, m);
    }
    res.writeHead(204);
    res.end();
  }

  private async putContainer(res: ServerResponse, r: Resolver,
    sel: Selected, who: Principal = ANONYMOUS): Promise<void> {
    if (sel.ns === sel.base) {
      res.writeHead(204); // the exported container object exists
      return res.end();
    }
    const trimmed = sel.ns.replace(/\/$/, "");
    const cut = trimmed.lastIndexOf("/");
    const pv = await r.view(trimmed.slice(0, cut + 1));
    const name = trimmed.slice(cut + 1);
    try {
      await r.child(pv, name);
      res.writeHead(204); // it already exists
      return res.end();
    } catch { /* create it */ }
    if (name.startsWith("cdmi_")) {
      throw malformed(`${JSON.stringify(name)} begins with "cdmi_", which is reserved`);
    }
    const target = await ensureWriteTarget(this.store, pv);
    this.store.createContainer(target, name, {
      owner: who.name,
      acl: aclForNewObject(undefined, this.store.meta(target).acl, true),
    });
    res.writeHead(201, { Location: this.location(sel, sel.ns) });
    res.end();
  }

  private async remove(req: IncomingMessage, res: ServerResponse, sel: Selected): Promise<void> {
    if (sel.ns === sel.base) {
      // A DELETE of the exported container object is always refused; a
      // client deletes it through the protocol binding (revision 49).
      throw forbidden("the exported container object cannot be deleted through the export");
    }
    const r = new Resolver(this.store);
    const isContainer = sel.ns.endsWith("/");
    const trimmed = sel.ns.replace(/\/$/, "");
    const cut = trimmed.lastIndexOf("/");
    const pv = await r.view(trimmed.slice(0, cut + 1));
    if (pv.unavail) throw pv.unavail;
    const name = trimmed.slice(cut + 1);

    if (!isContainer) {
      const found = await resolveFile(this.store, pv, name);
      if (!found) throw notFound(sel.ns);
      if (pv.writeRank === undefined) {
        throw pv.writeUnavail ?? forbidden("%s cannot be deleted: %s", sel.ns, pv.writeWhy);
      }
      if (rankCmp(found.layer.rank, pv.writeRank) !== 0) {
        throw denyChange(pv, sel.ns, found.layer.rank, "delete");
      }
      await this.store.collect(this.store.removeTree(found.node));
    } else {
      const cv = await r.child(pv, name);
      if (pv.writeRank === undefined) {
        throw pv.writeUnavail ?? forbidden("%s cannot be deleted: %s", sel.ns, pv.writeWhy);
      }
      if (cv.upper) {
        throw conflictImportLayer(cv.objLayer.rank[0], pv.ns,
          "%s is present in a layer above the write target, which denies the delete", sel.ns);
      }
      const wt = pv.writeNode ?? pv.writeDelegate?.writeNode;
      const here = wt ? this.store.tryLookup(wt, name) : undefined;
      if (!here || !here.isContainer) {
        throw forbidden("%s is present only in layers other than the write target", sel.ns);
      }
      await this.store.collect(this.store.removeTree(here));
    }
    void req;
    res.writeHead(204);
    res.end();
  }
}

// ---------------------------------------------------------------------------

function hasPrefix(segs: string[], prefix: string[]): boolean {
  return segs.length >= prefix.length && prefix.every((p, i) => segs[i] === p);
}

function valueETag(m: Meta): string {
  const h = createHash("sha256");
  h.update(`${m.version}\u0000${m.size}\u0000${m.mimetype}`);
  return `"${h.digest("hex").slice(0, 24)}"`;
}

function parseRangeHeader(h: string | undefined, size: number):
  [number, number] | "unsatisfiable" | undefined {
  if (!h) return undefined;
  const m = /^bytes=(\d*)-(\d*)$/.exec(h.trim());
  if (!m) return undefined;
  let first: number;
  let last: number;
  if (m[1] === "") {
    if (m[2] === "") return undefined;
    const n = Number(m[2]);
    if (n === 0) return "unsatisfiable";
    first = Math.max(size - n, 0);
    last = size - 1;
  } else {
    first = Number(m[1]);
    last = m[2] === "" ? size - 1 : Math.min(Number(m[2]), size - 1);
  }
  if (size === 0 || first >= size || last < first) return "unsatisfiable";
  return [first, last];
}

function parseContentRange(h: string | undefined): [number, number] | undefined {
  if (!h) return undefined;
  const m = /^bytes (\d+)-(\d+)\/(\d+|\*)$/.exec(h.trim());
  if (!m) return undefined;
  const first = Number(m[1]);
  const last = Number(m[2]);
  if (last < first) return undefined;
  if (m[3] !== "*" && Number(m[3]) <= last) return undefined;
  return [first, last];
}

/**
 * Which of the two the request prefers: the ciphertext, under the encrypted
 * media type, or the plaintext, under the media type the ciphertext names.
 *
 * "the CDMI server shall compare the quality values that Accept gives to the
 * encrypted media type and to the media type of the plaintext (an absent
 * Accept giving each a value of one), and shall return whichever has the
 * greater; where they are equal, it shall return whichever is given by the
 * media range appearing first."
 */
export function prefersPlaintext(accept: string | undefined,
  encryptedType: string, plaintextType: string): boolean {
  if (accept === undefined || accept.trim() === "") return false;
  const ranges = accept.split(",").map((r, i) => {
    const [type, ...params] = r.split(";").map((t) => t.trim());
    const q = params.map((p) => /^q=([\d.]+)$/i.exec(p)).find((mm) => mm !== null);
    return { type: type.toLowerCase(), q: q === null || q === undefined ? 1 : Number(q[1]), at: i };
  });
  const scoreOf = (media: string) => {
    const [type, sub] = media.toLowerCase().split("/");
    let best: { q: number; at: number } | undefined;
    for (const r of ranges) {
      const matches = r.type === media.toLowerCase() || r.type === `${type}/*` || r.type === "*/*";
      if (!matches) continue;
      // The most specific range decides, and among equals the first.
      const specificity = r.type === media.toLowerCase() ? 2 : (r.type === `${type}/*` ? 1 : 0);
      const seen = best === undefined ? -1 : 3;
      void sub; void seen;
      if (best === undefined || specificity > 0 && r.q > best.q) best = { q: r.q, at: r.at };
    }
    return best;
  };
  const cipher = scoreOf(encryptedType);
  const plain = scoreOf(plaintextType);
  if (plain === undefined) return false;
  if (cipher === undefined) return plain.q > 0;
  if (plain.q !== cipher.q) return plain.q > cipher.q;
  return plain.at < cipher.at;
}

/**
 * The mimetype and valuetransferencoding a Content-Type header field
 * implies. The whole field value is kept, with the type, the subtype, the
 * parameter names and a charset value lower-cased.
 */
export function mimetypeOf(header: string | undefined, body: Buffer):
  { mimetype: string; vte: string } {
  // A write through an export states no value transfer encoding:
  // the protocol carries octets and the header field, where there
  // is one, says only what the octets are. So the encoding is left
  // unstated and a CDMI read derives one from the content, rather
  // than recording a choice the writer did not make.
  if (!header) return { mimetype: "application/octet-stream", vte: "" };
  const parts = header.split(";");
  const type = parts[0].trim().toLowerCase();
  const params: string[] = [];
  let charset = "";
  for (const p of parts.slice(1)) {
    const eq = p.indexOf("=");
    if (eq < 0) continue;
    const k = p.slice(0, eq).trim().toLowerCase();
    let v = p.slice(eq + 1).trim();
    if (k === "charset") {
      v = v.toLowerCase();
      charset = v.replace(/^"|"$/g, "");
    }
    params.push(`${k}=${v}`);
  }
  const mimetype = [type, ...params].join("; ");
  const utf8 = charset === "utf-8" && Buffer.from(body.toString("utf8"), "utf8").equals(body);
  // Where the header field states a media type, the encoding
  // follows the octets: a charset parameter of utf-8 is a
  // statement about them, and a body that is not a valid UTF-8
  // string is not carried as one whatever the header says.
  return { mimetype, vte: utf8 ? "utf-8" : "base64" };
}

function escapeHTML(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * The problems an entry reports for origins it names that this server cannot
 * serve. "A value that is well formed but that the CDMI server is not at
 * present able to serve" is not an invalid field, so the entry stands and
 * says why the origin is not among those provided (revision 347).
 */
function unservableProblems(e: { unservable?: string[] }): string[] {
  return (e.unservable ?? []).map((o) =>
    `${o} is not an origin this CDMI server is able to serve at present`);
}

/**
 * The challenge an export offers for the scheme its entry names.
 *
 * Where this CDMI server publishes protected resource metadata, the bearer
 * challenge names where, as RFC 9728 provides and as the MCP endpoint's
 * challenge does: a client meeting a challenge on an export then discovers the
 * authorization servers this CDMI server accepts without being told out of
 * band. The 0.80 release said the challenge did this; the value it needed was
 * carried into this module and read by nothing, so the challenge was the bare
 * realm until 0.86.
 */
function wwwAuthenticate(scheme: string, resource?: string): string {
  if (scheme === "bearer") {
    return resource === undefined
      ? 'Bearer realm="cdmi"'
      : `Bearer realm="cdmi", resource_metadata="${metadataUrl(resource)}"`;
  }
  if (scheme === "krb5") return "Negotiate";
  return 'Basic realm="cdmi", charset="UTF-8"';
}

function plain(res: ServerResponse, status: number, message: string,
  headers: Record<string, string> = {}): void {
  const body = Buffer.from(message + "\n");
  res.writeHead(status, {
    ...headers,
    "Content-Type": "text/plain; charset=utf-8",
    "Content-Length": String(body.length),
  });
  res.end(body);
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  await new Promise<void>((resolve, reject) => {
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve());
    req.on("error", reject);
  });
  return Buffer.concat(chunks);
}

/** The path of a request URI, without the query component. */
function exportPathOnly(url: string): string {
  const q = url.indexOf("?");
  return q < 0 ? url : url.slice(0, q);
}

// ---------------------------------------------------------------------
// MQTT exports
//
// An MQTT export publishes the values of a queue object as messages to
// a topic of a broker. It is the one export type placed on a queue
// object rather than on a container object, and the CDMI server is
// the MQTT client in every case: it connects outbound to the broker
// and exposes no broker endpoint of its own.

export interface MqttExport {
  type: string;
  broker_uri: string;
  topic: string;
  client_id: string;
  protocol: string[];
  reconnect_strategy: string;
  qos: string;
  retain: string;
  clean_session: string;
  keep_alive_interval: string;
  dequeue_on_publish: string;
  username?: string;
  /** The interval at which credential references are resolved again. */
  refresh_interval?: string;
  /** The TLS settings, where the broker URI names a TLS scheme. */
  tls?: MqttTls;
  will?: { topic: string; payload: string; qos: string; retain: string };
  session_expiry_interval?: string;
  message_expiry_interval?: string;
  content_type?: string;
  response_topic?: string;
  user_properties?: string[][];
  disabled: string;
  /** The credential reference of the password sent in CONNECT, as bound. */
  password_secret_id?: { kms: string; name: string; scope?: string };
  /**
   * The principal that created this entry, under whose authority the export
   * publishes (revision 365, access control and protocols). It is set by this
   * CDMI server when the entry is written and is not a field a CDMI client
   * supplies or reads: the exports clause defines no such field, so it is kept
   * with the stored entry and left out of what is reported, as the import side
   * keeps the instant a value was obtained.
   */
  publishedBy?: string;
}

export const isMqtt = (e: ExportEntry): e is MqttExport => e.type === "MQTT";

/**
 * The write-only fields of an export entry. Each would be accepted and
 * never returned, so an update that omits one keeps the value supplied
 * earlier rather than discarding it, as the exports model still
 * requires. Revision 196 deleted the only one this server accepted,
 * the password of an MQTT export, and defines no other: a secret now
 * reaches a CDMI server in the "secret" member of a credential
 * reference, which is not stored at all.
 */
export const WITHHELD_FIELDS: string[] = [];

/**
 * Reads an MQTT export entry. The CDMI server is the MQTT client, so
 * every field of the entry describes the connection it makes to the
 * broker rather than anything it serves.
 */
function parseMqttEntry(name: string, raw: unknown, features: string[]): MqttExport {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw invalidField(`/exports/${name}`, "an export entry shall be a JSON object");
  }
  const e = raw as Record<string, unknown>;
  const at = (f: string) => `/exports/${name}/${f}`;
  const str = (f: string): string | undefined => {
    const v = e[f];
    if (v === undefined) return undefined;
    if (typeof v !== "string") {
      throw invalidField(at(f), "the %j field shall be a JSON string", f);
    }
    return v;
  };
  const need = (f: string): string => {
    const v = str(f);
    if (v === undefined || v === "") {
      throw invalidField(at(f), "an MQTT export entry shall contain a %j field", f);
    }
    return v;
  };
  const bool = (f: string, dflt: string): string => {
    const v = str(f) ?? dflt;
    if (v !== "true" && v !== "false") {
      throw invalidField(at(f), 'the %j field shall be "true" or "false"', f);
    }
    return v;
  };
  const whole = (f: string, dflt: string, max: number): string => {
    const v = str(f) ?? dflt;
    if (!/^[0-9]+$/.test(v) || Number(v) > max) {
      throw invalidField(at(f),
        "the %j field shall be a whole number of at most %d, as a JSON string", f, max);
    }
    return v;
  };

  // The CDMI server populates these and ignores them where a client
  // supplies them, as the common fields of an export entry require.
  for (const f of ["connected", "messages_published", "messages_pending",
    "messages_dropped", "last_connected", "last_problems", "state_determined_time"]) {
    delete e[f];
  }

  const broker = need("broker_uri");
  parseBrokerURI(at("broker_uri"), broker);
  const topic = need("topic");
  checkTopic(at("topic"), topic, false);

  // Revision 245 renamed this field from protocol_version to protocol and
  // made it an array of the versions offered, reported by one capability
  // holding an array in place of one capability for each version.
  const versions = versionsOf(e.protocol, ["3.1.1"]);
  if (versions === undefined) {
    throw invalidField(at("protocol"),
      "the protocol field is a JSON array of the MQTT versions this server offers");
  }
  for (const v of versions) {
    if (!MQTT_VERSIONS.includes(v)) {
      throw invalidField(at("protocol"),
        "%j is not an MQTT version this document defines: the versions are %s",
        v, MQTT_VERSIONS.join(", "));
    }
  }
  const feature = "cdmi_export_mqtt_versions";
  if (!features.includes(feature)) {
    throw capabilityNotPresent(feature, "/cdmi_capabilities/",
      "this CDMI server does not negotiate MQTT %s", versions.join(" or "));
  }

  // A client identifier is at most 65535 octets when encoded, as
  // every MQTT string is; a broker may accept fewer.
  const client_id = need("client_id");
  if (Buffer.byteLength(client_id, "utf8") > 65535) {
    throw invalidField(at("client_id"),
      "a client identifier is at most 65535 octets when encoded");
  }

  const strategy = str("reconnect_strategy") ?? "exponential";
  if (!RECONNECT_STRATEGIES.includes(strategy)) {
    throw invalidField(at("reconnect_strategy"),
      "the reconnect_strategy field shall be one of %s",
      RECONNECT_STRATEGIES.join(", "));
  }
  const qos = str("qos") ?? "0";
  if (!["0", "1", "2"].includes(qos)) {
    throw invalidField(at("qos"), 'the qos field shall be "0", "1" or "2"');
  }

  // A field of MQTT 5.0 supplied for a connection that negotiates
  // 3.1.1 has no packet to travel in. The versions are offered in order of
  // preference, and a field of 5.0 belongs to an entry that offers it.
  const version = versions.includes("5.0") ? "5.0" : versions[0];
  if (version !== "5.0") {
    for (const f of ["session_expiry_interval", "message_expiry_interval",
      "content_type", "response_topic", "user_properties"]) {
      if (f in e) {
        throw invalidField(at(f),
          "the %j field belongs to MQTT 5.0, and this entry negotiates %s", f, version);
      }
    }
  }

  // Revision 196 deletes the password field: a CDMI server "shall not
  // accept a secret ... as the value of any field", and an entry of the
  // previous edition carrying one is not accepted (annex E). Its
  // replacement holds a credential reference, which needs cdmi_kms.
  if ("password" in e) {
    throw invalidField(at("password"),
      "the password field is not defined: a password is held by a key management " +
      "server and addressed by a credential reference in password_secret_id");
  }
  // A credential reference, which the binding binds before the entry is
  // validated (bindExportCredentials): what arrives here is the reference as
  // bound, naming the key management server and the scope that applies. A
  // CDMI server with no key management server resolves no reference, and
  // does not accept one.
  let passwordSecret: { kms: string; name: string; scope?: string } | undefined;
  if ("password_secret_id" in e) {
    if (!features.includes("cdmi_kms")) {
      throw capabilityNotPresent("cdmi_kms", "/cdmi_capabilities/",
        "the password_secret_id field holds a credential reference, and this CDMI " +
        "server is run without a key management server");
    }
    const r = e.password_secret_id as Record<string, unknown> | null;
    if (r === null || typeof r !== "object" || typeof r.kms !== "string" || typeof r.name !== "string") {
      throw invalidField(at("password_secret_id"),
        "the password_secret_id field holds a credential reference, a JSON object naming a credential");
    }
    passwordSecret = boundReference(r)!;
  }
  // The TLS credentials are sub-fields of tls, not fields of the entry. This
  // server accepted ca_cert_id here in 0.41, which was its error.
  for (const f of ["ca_cert_id", "client_cert_id", "client_key_id"]) {
    if (f in e) {
      throw invalidField(at(f), "%j is a sub-field of the tls field, not a field of the entry", f);
    }
  }
  if ("password_refresh_interval" in e) {
    throw invalidField(at("password_refresh_interval"),
      "the password_refresh_interval field is not defined; revision 196 names the " +
      "interval refresh_interval, and it applies to every credential reference of " +
      "the entry");
  }

  const out: MqttExport = {
    type: "MQTT",
    broker_uri: broker,
    topic,
    client_id,
    protocol: versions,
    reconnect_strategy: strategy,
    qos,
    retain: bool("retain", "false"),
    clean_session: bool("clean_session", "true"),
    keep_alive_interval: whole("keep_alive_interval", "60", 65535),
    dequeue_on_publish: bool("dequeue_on_publish", "false"),
    disabled: bool("disabled", "false"),
  };
  const username = str("username");
  if (username !== undefined) out.username = username;
  if (passwordSecret !== undefined) out.password_secret_id = passwordSecret;
  if ("tls" in e) out.tls = parseTls(at, e.tls, { kms: features.includes("cdmi_kms") });
  // A TLS scheme without a tls field uses the trust store of the
  // system, which the clause states as the default.
  const scheme = broker.slice(0, broker.indexOf(":"));
  if ((scheme === "mqtts" || scheme === "wss") && out.tls === undefined) {
    out.tls = { rejectUnauthorized: true };
  }
  if (out.tls !== undefined && scheme !== "mqtts" && scheme !== "wss") {
    throw invalidField(at("tls"),
      "a tls field applies to a broker URI of a TLS scheme, and %j is not one",
      scheme);
  }

  // The last will and testament, which the broker publishes if this
  // CDMI server disconnects unexpectedly.
  if ("will" in e) {
    const w = e.will;
    if (w === null || typeof w !== "object" || Array.isArray(w)) {
      throw invalidField(at("will"), "the will field is a JSON object");
    }
    const will = w as Record<string, unknown>;
    const topic = will.topic;
    const payload = will.payload;
    if (typeof topic !== "string" || topic === "") {
      throw invalidField(at("will/topic"), "a will names the topic it is published on");
    }
    checkTopic(at("will/topic"), topic, false);
    if (typeof payload !== "string") {
      throw invalidField(at("will/payload"),
        "the payload of a will is a UTF-8 encoded string");
    }
    const willQos = typeof will.qos === "string" ? will.qos : "0";
    if (!["0", "1", "2"].includes(willQos)) {
      throw invalidField(at("will/qos"), 'the qos of a will is "0", "1" or "2"');
    }
    const willRetain = typeof will.retain === "string" ? will.retain : "false";
    if (willRetain !== "true" && willRetain !== "false") {
      throw invalidField(at("will/retain"), 'the retain of a will is "true" or "false"');
    }
    out.will = { topic, payload, qos: willQos, retain: willRetain };
  }
  // The interval at which the credential references of the entry are
  // resolved again. It carries no secret, so it is accepted and
  // returned, though an entry this server accepts holds no reference
  // for it to apply to.
  if ("refresh_interval" in e) {
    out.refresh_interval = whole("refresh_interval", "0", 2147483647);
  }
  if (version === "5.0") {
    if ("session_expiry_interval" in e) {
      out.session_expiry_interval = whole("session_expiry_interval", "0", 4294967295);
    }
    if ("message_expiry_interval" in e) {
      out.message_expiry_interval = whole("message_expiry_interval", "0", 4294967295);
    }
    const ct = str("content_type");
    if (ct !== undefined) out.content_type = ct;
    const rt = str("response_topic");
    if (rt !== undefined) {
      checkTopic(at("response_topic"), rt, false);
      out.response_topic = rt;
    }
    if ("user_properties" in e) {
      const v = e.user_properties;
      if (!Array.isArray(v) || v.some((pair) => !Array.isArray(pair) ||
        pair.length !== 2 || pair.some((x) => typeof x !== "string"))) {
        throw invalidField(at("user_properties"),
          "the user_properties field is an array of two-element arrays of strings");
      }
      out.user_properties = v as string[][];
    }
  }
  return out;
}
