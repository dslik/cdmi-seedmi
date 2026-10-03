// S3 imports.
//
// An S3 import presents the objects of a bucket served by another
// S3 server as objects within an importing container object. It is
// the converse of the S3 export: the same mapping between a
// hierarchy of objects and a flat namespace of keys, read from the
// position of a CDMI server acting as an S3 client.
//
// This module holds what an S3 import entry is. Acting as that
// client is elsewhere.

import { reservedName } from "./store.ts";
import { invalidField } from "./problems.ts";
import { ADDRESSING_STYLES, checkBucketName, checkRegion } from "./s3.ts";

/** The fields of an S3 import entry that a CDMI client supplies. */
export interface S3Import {
  type: string;
  import_uri: string;
  region?: string;
  addressing_style: string;
  folder_markers: string;
  listing_max_age: string;
  object_lock: string;
  disabled: string;
}

/** What an import URI resolves to. */
export interface ImportSource {
  /** The authority addressing the S3 endpoint. */
  authority: string;
  bucket: string;
  /** The key prefix, of zero or more segments, ending with a solidus. */
  prefix: string;
}

/**
 * Reads an import URI.
 *
 * The form is https://<authority>/<bucket>/<prefix>, expressed in
 * the path addressing style whether or not the CDMI server issues
 * requests in that style: a value that may be expressed in either
 * style does not say unambiguously which name is the bucket.
 */
export function parseImportURI(at: string, value: string): ImportSource {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw invalidField(at, "the import URI is not a URI");
  }
  if (url.protocol !== "https:") {
    throw invalidField(at,
      "the scheme of an S3 import URI is https, an S3 request signature " +
      "authenticating a request without concealing it");
  }
  if (url.search !== "" || url.hash !== "") {
    throw invalidField(at, "an S3 import URI carries no query and no fragment");
  }
  if (!url.pathname.endsWith("/")) {
    throw invalidField(at, "an S3 import URI ends with a solidus");
  }
  const segments = url.pathname.split("/").filter((s) => s !== "");
  if (segments.length === 0) {
    throw invalidField(at,
      "an S3 import URI names a bucket as the first segment of its path");
  }
  const bucket = decodeURIComponent(segments[0]);
  checkBucketName(at, bucket);
  // The prefix is what follows the bucket, and is empty where the
  // whole bucket is imported.
  const prefix = segments.length === 1
    ? ""
    : `${segments.slice(1).map((s) => decodeURIComponent(s)).join("/")}/`;
  return { authority: url.host, bucket, prefix };
}

/** The duration a listing may be reused for, in milliseconds. */
export function maxAgeMillis(period: string): number {
  const m = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(period);
  if (m === null) throw new Error(`not a duration: ${period}`);
  const [, d, h, mi, s] = m.map((x) => (x === undefined ? 0 : Number(x)));
  return (((Number(d) * 24 + Number(h)) * 60 + Number(mi)) * 60 + Number(s)) * 1000;
}

/** Whether a value is a duration of the form the document defines. */
export function isDuration(value: string): boolean {
  return /^P(?!$)(\d+[YMWD])*(T(?!$)(\d+[HMS])*)?$/.test(value);
}

/**
 * Reads an S3 import entry. The credentials the CDMI server signs
 * with are not conveyed by any field: they are established by
 * means outside the scope of the document, as they are for an S3
 * export.
 */
export function parseS3Import(name: string, raw: unknown): S3Import {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw invalidField(`/imports/${name}`, "an import entry shall be a JSON object");
  }
  const e = raw as Record<string, unknown>;
  const at = (f: string) => `/imports/${name}/${f}`;
  const str = (f: string): string | undefined => {
    const v = e[f];
    if (v === undefined) return undefined;
    if (typeof v !== "string") {
      throw invalidField(at(f), "the %j field shall be a JSON string", f);
    }
    return v;
  };
  const one = (f: string, permitted: string[], dflt: string): string => {
    const v = str(f) ?? dflt;
    if (!permitted.includes(v)) {
      throw invalidField(at(f), "the %j field shall be one of %s",
        f, permitted.join(", "));
    }
    return v;
  };

  // The CDMI server populates these and ignores them where a
  // client supplies them.
  for (const f of ["active", "last_problems", "state_determined_time", "objects",
    "bytes"]) {
    delete e[f];
  }

  const uri = str("import_uri");
  if (uri === undefined || uri === "") {
    throw invalidField(at("import_uri"),
      "an S3 import entry shall contain an import_uri field");
  }
  parseImportURI(at("import_uri"), uri);

  const region = str("region");
  if (region !== undefined) checkRegion(at("region"), region);

  const maxAge = str("listing_max_age") ?? "PT0S";
  if (!isDuration(maxAge)) {
    throw invalidField(at("listing_max_age"),
      "the listing_max_age field is a duration, such as \"PT30S\"");
  }

  return {
    type: "S3",
    import_uri: uri,
    ...(region === undefined ? {} : { region }),
    // A request issued in the virtual hosted style by default,
    // which is the style an S3 endpoint expects unless it is one
    // that requires the path style.
    addressing_style: one("addressing_style", ADDRESSING_STYLES.filter(
      (s) => s !== "both"), "virtual_hosted"),
    // A bucket holds no directory, so a container object created
    // through the import is marked by a zero-length key ending
    // with a solidus unless the entry says otherwise.
    folder_markers: one("folder_markers", ["true", "false"], "true"),
    // A listing is not reused by default: the default requires the
    // CDMI server to list the import source afresh.
    listing_max_age: maxAge,
    object_lock: one("object_lock", ["true", "false"], "false"),
    disabled: one("disabled", ["true", "false"], "false"),
  };
}

// ---------------------------------------------------------------------
// The object mapping

/** Why a key is presented as no object. */
export type Unmappable =
  | "leading-solidus"
  | "empty-segment"
  | "dot-segment"
  | "reserved-name"
  | "segment-too-long";

/** What a key of the import source is presented as. */
export type Mapped =
  | { kind: "data"; segments: string[] }
  | { kind: "container"; segments: string[] }
  | { kind: "none"; why: Unmappable };

/** The greatest length of an object name, in octets of its UTF-8 encoding. */
export const MAX_NAME_OCTETS = 255;

/**
 * Whether a name is reserved by this document and therefore cannot
 * name a child object. A key of the bucket bearing an unreserved name that
 * begins with "cdmi_" is presented, the binding permitting such a name since
 * 0.121; it was recorded as the name not representable condition before.
 */
export function isReservedName(name: string): boolean {
  return reservedName(name);
}

/**
 * What a key is presented as.
 *
 * A key permits almost any sequence of Unicode characters, and many
 * keys that are well formed in S3 denote no object name this
 * document is able to carry. Such a key is presented as no object,
 * and the reason is recorded rather than the key being altered to
 * fit: a CDMI server that renamed it would present an object the
 * import source does not hold.
 *
 * The key is stated relative to the prefix the import URI
 * specifies, and a segment is each name between two solidi.
 */
export function mapKey(key: string, zeroLength = false): Mapped {
  // A leading solidus denotes a segment with an empty name.
  if (key.startsWith("/")) return { kind: "none", why: "leading-solidus" };
  const marker = key.endsWith("/");
  const body = marker ? key.slice(0, -1) : key;
  if (body === "") return { kind: "none", why: "empty-segment" };
  // Each pair of consecutive solidi denotes a segment with an empty
  // name.
  if (body.includes("//")) return { kind: "none", why: "empty-segment" };
  const segments = body.split("/");
  for (const s of segments) {
    // Both names are reserved by this document and cannot denote a
    // child object. A CDMI server does not interpret either as a
    // relative path reference.
    if (s === "." || s === "..") return { kind: "none", why: "dot-segment" };
    if (isReservedName(s)) return { kind: "none", why: "reserved-name" };
    // A key may satisfy the key length limit of the import source
    // while containing a segment this document is unable to name.
    if (Buffer.byteLength(s, "utf8") > MAX_NAME_OCTETS) {
      return { kind: "none", why: "segment-too-long" };
    }
  }
  // A key that ends with a solidus and whose content is of zero
  // length is the marker an S3 client writes to create a folder,
  // and denotes the container object and no data object.
  if (marker) {
    return zeroLength
      ? { kind: "container", segments }
      // A key ending with a solidus whose content is not of zero
      // length denotes a segment with an empty name, there being
      // no name after the final solidus.
      : { kind: "none", why: "empty-segment" };
  }
  return { kind: "data", segments };
}

/**
 * The container objects a set of keys implies. A leading segment of
 * a key denotes a container object whether or not the import source
 * holds a marker for it, so the containers are derived from the
 * keys rather than looked for.
 */
export function containersOf(keys: string[]): Set<string> {
  const out = new Set<string>();
  for (const key of keys) {
    const mapped = mapKey(key, key.endsWith("/"));
    if (mapped.kind === "none") continue;
    const segments = mapped.kind === "container"
      ? mapped.segments
      : mapped.segments.slice(0, -1);
    for (let i = 1; i <= segments.length; i++) {
      out.add(segments.slice(0, i).join("/"));
    }
  }
  return out;
}

/**
 * The key a path relative to the importing container object denotes,
 * with the prefix of the import URI prepended.
 */
export function keyFor(prefix: string, segments: string[],
  container = false): string {
  const key = segments.join("/");
  return `${prefix}${key}${container ? "/" : ""}`;
}

// ---------------------------------------------------------------------
// The operations

/**
 * The capabilities a CDMI server withholds from an object presented
 * through an S3 import, each for a reason the clause gives.
 */
export const WITHHELD_FROM_DATA_OBJECT = [
  // The import source serves no operation that writes a range of a
  // key. A CDMI server that read the key, applied the range and
  // wrote the key would replace the whole of an object it had not
  // been asked to replace, and would lose a concurrent change made
  // at the import source.
  "cdmi_modify_value_range",
  "cdmi_create_value_range",
  // A version of a key is not a version of this document: the
  // identifiers are assigned by the import source, are not object
  // IDs, and are not preserved by the operations of this document.
  "cdmi_versioning",
];

/** The same, for a container object. */
export const WITHHELD_FROM_CONTAINER = ["cdmi_versioning"];

/**
 * Whether an operation that moves or renames an object presented
 * through the import is permitted.
 *
 * Such an operation is performed as a copy of each key affected
 * followed by a delete of each, and is not atomic with respect to
 * an operation of an S3 client of the import source. A CDMI server
 * reports the forbidden condition where the capability is absent.
 */
export function mayRename(capabilities: Set<string>): boolean {
  return capabilities.has("cdmi_import_s3_rename");
}

/**
 * The keys an operation that deletes a container object removes:
 * every key beneath the prefix that container object denotes, and
 * the marker key where one exists.
 */
export function keysToDelete(prefix: string, segments: string[],
  keys: string[]): string[] {
  const under = keyFor(prefix, segments, true);
  return keys.filter((k) => k === under || k.startsWith(under));
}

/**
 * This CDMI server does not reuse a listing of the import source.
 *
 * The `listing_max_age` field states the greatest age of a listing
 * a CDMI server **may** use, so a server that lists afresh for
 * every enumeration conforms whatever the field contains, and
 * `cdmi_import_s3_listing_cache` is correspondingly absent. A
 * listing that is reused reports a bucket as it was rather than as
 * it is, and an S3 client of the import source may have changed it
 * in between; this server does not take that trade.
 */
export const REUSES_LISTINGS = false;

// ---------------------------------------------------------------------
// The metadata mapping

/** What the import source reports for a key. */
export interface KeyMetadata {
  size: number;
  /** The last modified time of the key. */
  mtime: number;
  mimetype?: string;
  /** A checksum, where the import source reports one. */
  checksum?: { algorithm: string; value: string };
  /** The user metadata fields, with the prefix still attached. */
  headers?: Record<string, string>;
  /** The Object Lock configuration, where the import source reports one. */
  objectLock?: { mode: string; retainUntil: string };
  /** Whether a legal hold is in force. */
  legalHold?: boolean;
}

/**
 * The storage system metadata a CDMI server derives for a key.
 *
 * An item for which the import source reports no corresponding
 * value is not reported at all, rather than reported as a default:
 * a bucket reports neither a creation time nor an access time, so
 * `cdmi_ctime` and `cdmi_atime` are absent.
 */
export function storageMetadataFor(m: KeyMetadata, o: {
  /** The algorithm the importing container object specifies. */
  valueHash?: string;
  /** Whether the entry presents the Object Lock configuration. */
  objectLock: boolean;
}): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {
    cdmi_size: String(m.size),
    cdmi_mtime: new Date(m.mtime).toISOString().replace(/\.\d+Z$/, ".000000Z"),
  };
  // The checksum, where the import source reports one computed by
  // the algorithm the importing container object specifies. An
  // entity tag is not used: it is not required to be a digest of
  // the content, and is not one where the key was stored in parts
  // or with server-side encryption under a client-supplied key.
  if (m.checksum !== undefined && o.valueHash !== undefined &&
    m.checksum.algorithm.toUpperCase() === o.valueHash.toUpperCase()) {
    out.cdmi_hash = m.checksum.value;
  }
  if (o.objectLock) {
    // Reported as provided items, which report what the import
    // source enforces. The corresponding data system metadata
    // items are absent: this document does not declare a retention
    // period the import source is required to apply.
    if (m.objectLock !== undefined) {
      out.cdmi_retention_id = m.objectLock.mode;
      out.cdmi_retention_period = m.objectLock.retainUntil;
    }
    if (m.legalHold === true) out.cdmi_hold_id = ["s3-legal-hold"];
  }
  return out;
}

/** The prefix a user metadata field of the import source carries. */
export const USER_METADATA_PREFIX = "x-amz-meta-";

/**
 * The user metadata items a key presents.
 *
 * The name is the field name with the prefix removed. A name that
 * then begins with cdmi_ is not presented, that being reserved by
 * this document.
 */
export function userMetadataFor(headers: Record<string, string> = {}):
  Record<string, string> {
  const out: Record<string, string> = {};
  for (const [field, value] of Object.entries(headers)) {
    const lower = field.toLowerCase();
    if (!lower.startsWith(USER_METADATA_PREFIX)) continue;
    const name = lower.slice(USER_METADATA_PREFIX.length);
    if (name === "" || name.startsWith("cdmi_")) continue;
    // The corresponding decoding of what an S3 response percent
    // encodes, an HTTP field value being restricted to US-ASCII.
    let decoded = value;
    try {
      decoded = decodeURI(value);
    } catch {
      // A value that is not valid percent encoding stands.
    }
    out[name] = decoded;
  }
  return out;
}

/** Whether a metadata item may be stored through the import. */
export function mayStoreMetadata(name: string): boolean {
  // A metadata item the import source does not support is not
  // stored at the CDMI server in place of the import source: a
  // CDMI client that read it back would be told the import source
  // holds something it does not.
  if (name.startsWith("cdmi_")) return false;
  // An S3 metadata name is an HTTP field name, so a name that is
  // not a token cannot be carried.
  return /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name);
}

// ---------------------------------------------------------------------
// Access control

/**
 * The metadata items a CDMI server does not derive from an S3
 * import source.
 *
 * A bucket carries no access control list this document is able to
 * map: authorization at the import source is determined by the
 * policies that server evaluates against the credentials
 * presented, which are expressed in a form this document does not
 * define and are not attached to an object.
 */
export const NOT_DERIVED_FROM_SOURCE = ["cdmi_acl", "cdmi_owner", "cdmi_group"];

/**
 * Whether an operation may be presented as permitted on the basis
 * of the access control lists of the importing container object
 * alone.
 *
 * It may not. Those lists apply to every object presented and are
 * reported for it, and they are necessary rather than sufficient:
 * the import source evaluates its own policies, and where it
 * refuses an operation the CDMI server reports the condition the
 * import source reported rather than the operation the lists
 * permitted.
 */
export function permittedLocally(granted: boolean): boolean {
  return granted;
}

/** Why an import is reported as not active. */
export type ImportFault =
  | "no-response"
  | "no-such-bucket"
  | "region-undetermined"
  | "addressing-style-unusable"
  | "no-object-lock-configuration";

/** The conditions that make an import not active, and their descriptions. */
export const IMPORT_FAULTS: Record<ImportFault, string> = {
  "no-response": "the import source does not respond",
  "no-such-bucket":
    "the bucket the import URI addresses does not exist, or is not reachable " +
    "with the credential presented",
  "region-undetermined": "the region of the import source cannot be determined",
  "addressing-style-unusable":
    "the addressing style the entry specifies cannot be used with this import source",
  "no-object-lock-configuration":
    "the entry presents the Object Lock configuration and the bucket has none",
};

/**
 * Whether a difficulty makes the import not active.
 *
 * Two kinds of difficulty do not. A failure to obtain temporary
 * credentials for one principal is reported to that principal and
 * is not recorded in the last_problems field, since it depends on
 * the principal and not on the import. And a key that is not
 * presented — whether its name is not representable or its kind is
 * not presentable — does not make the import not active either: a
 * bucket holding one key this document cannot name is otherwise
 * perfectly importable.
 */
export function makesImportInactive(what:
  | { kind: "fault"; fault: ImportFault }
  | { kind: "delegation"; principal: string }
  | { kind: "unmappable-key"; key: string }): boolean {
  return what.kind === "fault";
}

/** What a key that is not presented is recorded as. */
export function unmappableKeyRecord(key: string, why: Unmappable):
  { condition: string; cdmi_object: string; detail: string } {
  return {
    // The name not representable condition, with the key in the
    // cdmi_object extension member.
    condition: "name-not-representable",
    cdmi_object: key,
    detail: `the key ${JSON.stringify(key)} denotes no object name this ` +
      `document is able to carry: ${why.replace(/-/g, " ")}`,
  };
}
