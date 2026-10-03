// The store. Metadata lives in one SQLite database; the value of each data
// object lives in its own file under objects/, named by the object ID.
//
//   <root>/seedmi.db             the namespace, metadata, ACLs, imports
//   <root>/objects/<a>/<b>/<uuid> a value, named by a value identifier
//
// A value file is named by a value identifier rather than by an object
// ID, and the value_id column says which file an object reads. The two
// are the same for an object created in the ordinary way, and differ
// once a value is shared: a snapshot, and a copy, give the new object
// the value identifier of the object copied, so no bytes move. A write
// to any object that shares a value gives that object a fresh
// identifier first, copying the bytes where the write does not replace
// all of them, so the other readers keep what they had. A value file is
// therefore read by one object or by several, and is unlinked when the
// last of them goes.
//
// The value files are divided between 256 buckets, two levels of one hex
// digit, taken from the first two digits of the object ID. Object IDs are
// version 4 UUIDs, so those digits are uniformly distributed and a store of
// a million objects holds about four thousand files to a directory rather
// than a million.
//
// Metadata operations are synchronous and take microseconds, so they run on
// the event loop directly. Value operations are asynchronous positional
// reads and writes, so moving data never stalls another client. That split
// is the reason for the two stores: a 64 KiB read through SQLite blocks the
// loop for about 180 microseconds, and the same read through the file API
// takes 26 and blocks nothing.
//
// Three columns exist for protocols above CDMI:
//
//   - object.id is the NFSv4 fileid. AUTOINCREMENT, so it is never reused.
//   - object.version is the NFSv4 change attribute, bumped in the same
//     statement that changes the object. A modification time cannot do this
//     reliably at any granularity a file system offers.
//   - the handle table gives NFS a persistent file handle. A handle names a
//     parent and a name rather than an object, so it survives a copy-up,
//     which changes which object a name resolves to.

import { DatabaseSync, StatementSync } from "node:sqlite";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { open as openFile, mkdir, rm, copyFile, stat, readdir } from "node:fs/promises";
import * as path from "node:path";
import { USERINFO } from "./userinfo.ts";

/** An object of the store. */
export interface Node {
  readonly id: number;
  readonly isContainer: boolean;
}

/**
 * An access control entry. The fields are those of RFC 7530, which the
 * draft adopts unchanged, so one structure is stored, evaluated, served in
 * a CDMI representation and served to NFS.
 */
export interface ACE {
  acetype: string;
  identifier: string;
  aceflags: string;
  acemask: string;
}

/** Everything held about an object other than its value and its children. */
export interface Meta {
  objectID: string;
  name: string;
  parent: number | null;
  isContainer: boolean;
  mimetype: string;
  vte: string;
  metadata: Record<string, unknown>;
  owner: string;
  /** The group GROUP@ designates, where the object is associated with one. */
  group: string;
  acl: ACE[] | null;
  /** Absent (undefined) and present-but-empty are different things. */
  imports: unknown[] | undefined;
  exports: Record<string, unknown> | undefined;
  /** The rel field, which is a field of its own and not metadata. */
  rel: Record<string, unknown> | undefined;
  /**
   * The extension fields stored with the object: "Where a CDMI client
   * supplies an extension field in a create or an update ... a CDMI server
   * shall store the field with the object" (Extension fields). Not stored
   * before 0.52, when such fields were accepted and dropped.
   */
  extensions: Record<string, unknown> | undefined;
  /**
   * Where this name is a reference, the URI it redirects to. A
   * reference is not an object: it has no representation, no object ID
   * and no object type, and a row holds it because a name within a
   * container object is held in this table.
   */
  reference: string | undefined;
  version: number;
  /** The number of reads, writes and lists since the object was made. */
  acount: number;
  /** The number of changes of value or metadata since it was made. */
  mcount: number;
  /** The object whose value file this object reads. */
  valueID: string;
  /** Whether the object is within a snapshot, or is a version. */
  frozen: boolean;
  /** The object ID of the version this row within a snapshot pins. */
  pinnedID: string | null;
  /** Whether the object is not yet complete. */
  partial: boolean;
  /**
   * The length of the value written from the beginning without a gap,
   * which is the range the valuerange field reports.
   */
  contiguous: number;
  /** Whether the row is a domain object. */
  isDomain: boolean;
  /** Whether the object is a queue object. */
  isQueue: boolean;
  /**
   * The hash of the value, in base 16, where the client asked for one
   * through the cdmi_value_hash data system metadata item.
   */
  hash: string | null;
  /** The designator the next value enqueued will take. */
  nextDesignator: number;
  /** The number of values the queue object holds. */
  queueCount: number;
  /** The domain object that owns this object. */
  domain: number | null;
  /** The data object this row is a version of, where it is a version. */
  versionOf: number | null;
  /** The version this one was created from. */
  versionParent: number | null;
  /** The current version, where this is a version-enabled data object. */
  currentVersion: number | null;
  size: number;
  ctime: number;
  mtime: number;
  atime: number;
}

/** What a caller supplies when it creates an object. */
/** One value a queue object holds. */
/** The kind of a representation a name denotes. */
export type Kind = "container" | "data" | "queue";

export interface QueueValue {
  designator: number;
  mimetype: string;
  vte: string;
  /** The metadata of the value, where it carries any. */
  metadata?: Record<string, unknown>;
  body: Buffer;
}

/**
 * The hash algorithms this server computes, named as the algorithm
 * followed by the length in bits, which is the form the
 * cdmi_value_hash data system metadata item takes.
 */
export const VALUE_HASHES: Record<string, string> = {
  SHA160: "sha1",
  SHA224: "sha224",
  SHA256: "sha256",
  SHA384: "sha384",
  SHA512: "sha512",
};

export interface NewMeta {
  objectID?: string;
  /**
   * The moment the object came into being, where a representation is added
   * to an object that already exists: the creation time is of the object
   * and is shared by its representations (5.3.7).
   */
  ctime?: number;
  mimetype?: string;
  vte?: string;
  metadata?: Record<string, unknown>;
  owner?: string;
  acl?: ACE[] | null;
  imports?: unknown[];
  /** The rel field, which a copy-up carries and a create may supply. */
  rel?: Record<string, unknown>;
  /** The extension fields, which a create may supply and a copy carries. */
  extensions?: Record<string, unknown>;
  exports?: Record<string, unknown>;
  /** The destination, where what is created is a reference. */
  reference?: string;
  group?: string;
  /** The object whose value file this one reads, where it is shared. */
  valueID?: string;
  /** Whether the object is within a snapshot, or is a version. */
  frozen?: boolean;
  /** The object ID of the version this row within a snapshot pins. */
  pinnedID?: string;
  /** Whether the object is not yet complete. */
  partial?: boolean;
  /** The length written from the beginning without a gap. */
  contiguous?: number;
  /**
   * The runs of written octets of the value, where the row is created sharing a
   * value that has gaps. Set here rather than by a later update so that the row
   * is created as what it is: setWritten bumps the version and the modification
   * count, which would have a snapshot entry report a modification that never
   * happened.
   */
  written?: [number, number][];
  /** Whether what is created is a domain object. */
  isDomain?: boolean;
  /** Whether the object created is a queue object. */
  isQueue?: boolean;
  /** The domain object that owns what is created. */
  domain?: number;
  /** The data object this row is a version of. */
  versionOf?: number;
  /** The version this one was created from. */
  versionParent?: number;
  /** The size, where the value is shared rather than written. */
  size?: number;
}

/** The reserved container object in which snapshots are addressed. */
export const SNAPSHOTS = "cdmi_snapshots";

/**
 * The metadata of an object without the items a copy and a snapshot do not
 * carry: the retention and hold items, so that "a snapshot and a copy hold
 * a copy of an object under retention that is not itself under retention",
 * and the lock, which revision 327 excludes in the same terms — "a lock is
 * not applied to an object created by copying an object that is under one,
 * and is not preserved in a snapshot". The lock a snapshot needs is applied
 * to the snapshot, which is the ordinary subject of an image export.
 */
export function withoutRestrictions(m: Record<string, unknown>):
  Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(m)) {
    if (k === "cdmi_retention_id" || k === "cdmi_retention_period" ||
      k === "cdmi_retention_autodelete" || k === "cdmi_hold_id" ||
      k === "cdmi_lock" || k === "cdmi_lock_provided") continue;
    out[k] = v;
  }
  return out;
}

/** The reserved child of the root in which domain objects are addressed. */
export const DOMAINS = "cdmi_domains";

/** The prefix of a name this CDMI server assigns to an object created
 * without one. */
export const ASSIGNED = "cdmi_assigned_";

/**
 * A name this CDMI server assigned to an object created without one. Such a
 * name is reserved, so it is presented in no listing and addresses nothing
 * in the namespace; it is resolvable all the same, because a container
 * object created without a name "is the root container object of its own
 * object ID URI, that URI being a base URI" (revision 354), and the objects
 * it holds are addressed by a path beneath that URI. Resolving that path
 * begins at the name this server assigned.
 */
export const isAssigned = (name: string): boolean => name.startsWith(ASSIGNED);

/**
 * The names the reserved names table defines, each of which "is reserved at
 * the position specified in [that table]" (revision 365). This server reserves
 * each of them at every position rather than at the one the table gives, so
 * that a name the table defines never names an object a client created, and so
 * that a name a client reads at one position means there what it means at the
 * root. The table's positions are: cdmi_capabilities, cdmi_domains and
 * cdmi_objectid as children of the root container object, cdmi_domain_userinfo
 * as a child of each domain object, and cdmi_snapshots as a child of any
 * container object.
 */
export const RESERVED_NAMES: readonly string[] = [
  "cdmi_capabilities", DOMAINS, USERINFO, "cdmi_objectid", SNAPSHOTS,
];

/**
 * A name this document reserves, which a CDMI client may not create and may
 * not delete, and which no listing of an object a client created carries.
 *
 * Until 0.121 this was every name beginning with "cdmi_", which is what
 * revision 365 requires: "A CDMI client shall not create an object whose name
 * begins with cdmi_, and a CDMI server shall report the invalid field condition
 * where a CDMI client attempts to do so", and, of the names the table does not
 * list, "A CDMI server shall reject the creation of an object with such a name
 * so that a name added by a subsequent version does not collide with a name a
 * CDMI client has already used". This server now reserves the names the table
 * defines and no others. NOTES-on-reserved-names.md records that as a
 * deliberate departure from those two requirements, and ECR-247A asks the
 * document to narrow them.
 *
 * The prefix of a name this server assigns itself stays reserved whatever the
 * document says of the rest: a client that created such a name would collide
 * with the handle under which an object created without a name is held, and
 * would reach an object that has no name to reach it by.
 *
 * This predicate governs object names alone. A metadata item name beginning
 * with "cdmi_" is reserved by a separate rule that this change does not touch,
 * under which an item the metadata annex defines may be supplied and any other
 * "cdmi_" item is the invalid field condition.
 */
export function reservedName(name: string): boolean {
  return RESERVED_NAMES.includes(name) || isAssigned(name);
}

export interface Child {
  node: Node;
  name: string;
  /** The destination, where the child is a reference. */
  reference?: string;
}

export type StoreErrorCode = "no-object" | "exists" | "not-container";

export class StoreError extends Error {
  code: StoreErrorCode;
  constructor(code: StoreErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

const noObject = (what: string) => new StoreError("no-object", `no object at ${what}`);
const exists = (name: string) => new StoreError("exists", `an object named ${name} is already held`);
const notContainer = () => new StoreError("not-container", "not a container object");

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS object (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,  -- the NFSv4 fileid
  object_id    TEXT NOT NULL,                      -- urn:uuid:..., names the value file
  parent       INTEGER REFERENCES object(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,                      -- '' for the root
  is_container INTEGER NOT NULL,
  mimetype     TEXT NOT NULL DEFAULT '',
  vte          TEXT NOT NULL DEFAULT '',
  metadata     TEXT NOT NULL DEFAULT '{}',
  owner        TEXT NOT NULL DEFAULT '',
  acl          TEXT,
  imports      TEXT,                               -- NULL where the field is absent
  exports      TEXT,
  rel          TEXT,                               -- the graph relationships
  extensions   TEXT,                               -- the extension fields
  reference    TEXT,                               -- the destination of a reference
  group_name   TEXT NOT NULL DEFAULT '',           -- the group of GROUP@
  -- The object ID of the value file this object reads. It differs from
  -- object_id where the value is shared with another object, which is
  -- how a snapshot is taken without copying any bytes: the copy is
  -- made when one of the sharers is written to.
  value_id     TEXT,
  -- Whether the object is within a snapshot, or is a version, and is
  -- therefore not modified. An imports field held within a snapshot is
  -- not processed either.
  frozen       INTEGER NOT NULL DEFAULT 0,
  -- The object ID of the version a row within a snapshot pins. The row
  -- has an identifier of its own, which is a key and not an address;
  -- what it reports, and what addresses it, is the identifier of the
  -- version. The two rows are one object: the version, presented at a
  -- namespace path as well as by its identifier. The reference is by
  -- identifier rather than by row so that the snapshot survives the
  -- deletion of the data object and its versions.
  pinned_id    TEXT,
  -- Whether the row is a queue object, which holds an ordered
  -- sequence of values rather than one value. A queue object is not a
  -- container object and is not a data object; the three are distinct
  -- object types, and a name holds at most one of them.
  is_queue     INTEGER NOT NULL DEFAULT 0,
  -- The hash of the value, where the cdmi_value_hash data system
  -- metadata item asked for one. Held rather than computed on each
  -- read, since a value is hashed when it is written.
  hash         TEXT,
  -- The designator the next value enqueued will take. Designators
  -- begin at zero, increase by one, and are not reused, so this is
  -- one greater than the highest ever assigned rather than a count.
  next_designator INTEGER NOT NULL DEFAULT 0,
  -- Whether the row is a domain object, which represents the
  -- administrative ownership of the objects associated with it.
  is_domain    INTEGER NOT NULL DEFAULT 0,
  -- The domain object that owns this object. Every object other than a
  -- capability object has one.
  domain       INTEGER REFERENCES object(id),
  -- Whether the object is being created or updated by a series of
  -- requests and is not yet complete. Its completionStatus field is
  -- "Processing" until a request completes it, and a version-enabled
  -- data object takes no version until then.
  partial      INTEGER NOT NULL DEFAULT 0,
  -- The length of the value written from the beginning without a gap,
  -- which the valuerange field reports and which is not the size, the
  -- size including every gap. It is derived from the written column
  -- below and is kept here so that a read needs no parsing.
  contiguous   INTEGER NOT NULL DEFAULT 0,
  -- The ranges of the value that have been written, as a JSON array of
  -- [first, last] pairs, ordered and never touching or overlapping. A
  -- value written in ranges that are not contiguous has one entry for
  -- each run, so filling a gap joins two runs and a value written 0-9,
  -- then 50-59, then 10-49 is known to be contiguous. Before this
  -- column only the first run was recorded, and such a value went on
  -- reporting 0-9.
  written      TEXT,
  -- A version of a data object holds the object it is a version of.
  -- A version has no parent: it is outside the namespace and is
  -- addressed by its object ID alone.
  version_of      INTEGER REFERENCES object(id) ON DELETE CASCADE,
  -- The version this one was created from. Two updates that overlap
  -- are both applied to the state that existed when the first began,
  -- so one version may be the parent of two.
  version_parent  INTEGER REFERENCES object(id) ON DELETE SET NULL,
  -- The current version of a version-enabled data object.
  current_version INTEGER REFERENCES object(id) ON DELETE SET NULL,
  acount       INTEGER NOT NULL DEFAULT 0,         -- reads, writes and lists
  mcount       INTEGER NOT NULL DEFAULT 0,         -- changes of value or metadata
  version      INTEGER NOT NULL DEFAULT 1,         -- the NFSv4 change attribute
  size         INTEGER NOT NULL DEFAULT 0,
  ctime        INTEGER NOT NULL,
  mtime        INTEGER NOT NULL,
  atime        INTEGER NOT NULL,
  UNIQUE (parent, name, is_container, is_queue)
);

-- A name may denote more than one representation of one stored object:
-- a data object, a container object and a queue object at once, each
-- addressed independently. "Each representation shall have the same
-- object ID" (5.3.7), so a row holds a representation and the object_id
-- is of the object, shared by its representations: it is indexed and is
-- not unique. The uniqueness is of a name and a kind. The previous
-- edition did not permit a name to denote more than one representation,
-- and this server gave each representation an object ID of its own until
-- 0.68, which weedmi OPER-042 reported.

-- The values a queue object holds, each under the designator the
-- server assigned it. A value is held in a row rather than in a file
-- because a queue value is bounded by cdmi_queue_maxsize, is written
-- once and read whole, and is removed in order from the oldest.
CREATE TABLE IF NOT EXISTS queue_value (
  queue        INTEGER NOT NULL REFERENCES object(id) ON DELETE CASCADE,
  -- The designator, unique within the queue object and never reused.
  designator   INTEGER NOT NULL,
  mimetype     TEXT NOT NULL,
  -- The encoding the value is held under, which is the encoding it was
  -- enqueued with: "utf-8", "base64" or "json".
  vte          TEXT NOT NULL,
  -- The metadata of the value, as JSON. A value of a queue object
  -- carries metadata where an MQTT import records the topic a message
  -- arrived on; the queue object representation defines no field that
  -- presents it. See P2 in NOTES-on-mqtt.md.
  metadata     TEXT,
  -- The octets of the value, whatever the encoding it is reported in.
  body         BLOB NOT NULL,
  PRIMARY KEY (queue, designator)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS handle (
  id     BLOB PRIMARY KEY,
  parent INTEGER NOT NULL REFERENCES object(id) ON DELETE CASCADE,
  name   TEXT NOT NULL,
  UNIQUE (parent, name)
) WITHOUT ROWID;

-- The image imports configured on each container object, by the path of
-- the data object whose value each interprets. While such an import is
-- active the source is subject to the restrictions the draft places on a
-- data object exported as a block device, and those restrictions have to
-- be found from the source rather than from the importer.
CREATE TABLE IF NOT EXISTS image_source (
  importer     INTEGER NOT NULL REFERENCES object(id) ON DELETE CASCADE,
  entry        INTEGER NOT NULL,
  source_path  TEXT NOT NULL,
  write_enabled INTEGER NOT NULL,
  disabled     INTEGER NOT NULL,
  PRIMARY KEY (importer, entry)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS image_source_by_path ON image_source (source_path);

-- The container objects that carry an exports field. An export is
-- selected by origin and path rather than by namespace path, so the
-- server has to be able to find every entry it holds without walking the
-- whole namespace.
CREATE TABLE IF NOT EXISTS exported (
  container INTEGER PRIMARY KEY REFERENCES object(id) ON DELETE CASCADE
) WITHOUT ROWID;

-- A value file left behind by a failed or interrupted operation. The store
-- writes a value file before the row that refers to it, so that a row never
-- points at a file that is not there; a crash in between leaves a file with
-- no row, which this records for collection.
-- The number of parts of an object assembled by an S3 multipart upload,
-- and the version of the object when it was assembled. Its S3 entity tag
-- takes the form that shows the part count while the object is at that
-- version; a later write changes the version and the row no longer applies.
CREATE TABLE IF NOT EXISTS multipart_object (
  object_id TEXT PRIMARY KEY,
  version   INTEGER NOT NULL,
  parts     INTEGER NOT NULL
);

-- Values of this CDMI server's own that belong to key management: the public
-- key it retains for each binding key it claimed (kms-binding.ts).
CREATE TABLE IF NOT EXISTS kms_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orphan (
  object_id TEXT PRIMARY KEY,
  since     INTEGER NOT NULL
);
`;

const HEX = "0123456789abcdef";

/**
 * The access control list placed on the root container object of a new
 * store where the caller supplies none: the default of the draft in the
 * form it takes where the CDMI server authenticates no principal, with
 * ANONYMOUS@ in place of OWNER@ in the first entry.
 */
const OPEN_ROOT_ACL: ACE[] = [
  {
    acetype: "ALLOW",
    // The document's default list for a root container object names
    // OWNER@ with ALL_PERMS. This one names ANONYMOUS@, because a store
    // opened with no principal has no owner an anonymous request can
    // match: ANONYMOUS@ is not an owner, so the document's list would
    // seal such a store rather than open it. The deviation is deliberate
    // and is confined to a store opened with neither an owner nor a list;
    // a deployment supplies both (main.ts), and whether the document
    // intends a principal-less store to be sealed is a question for the
    // working group rather than a thing to decide here.
    identifier: "ANONYMOUS@",
    aceflags: "OBJECT_INHERIT, CONTAINER_INHERIT",
    acemask: "ALL_PERMS",
  },
  {
    acetype: "ALLOW",
    identifier: "AUTHENTICATED@",
    aceflags: "OBJECT_INHERIT, CONTAINER_INHERIT",
    acemask: "READ",
  },
];

/** The object ID of a new object, in the URN form of the draft. */
export function newObjectID(): string {
  return `urn:uuid:${randomUUID()}`;
}

/** The bare UUID of an object ID, which is the name of its value file. */
export function uuidOf(objectID: string): string {
  const u = objectID.startsWith("urn:uuid:") ? objectID.slice("urn:uuid:".length) : objectID;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(u)) {
    throw new Error(`not an object ID in the URN form: ${objectID}`);
  }
  return u;
}

interface Statements {
  queueCount: StatementSync;
  queueBounds: StatementSync;
  queueRange: StatementSync;
  queueSize: StatementSync;
  enqueue: StatementSync;
  dequeue: StatementSync;
  setNextDesignator: StatementSync;
  root: StatementSync;
  lookup: StatementSync;
  lookupKind: StatementSync;
  byObjectID: StatementSync;
  meta: StatementSync;
  parentOf: StatementSync;
  children: StatementSync;
  childrenPage: StatementSync;
  childCount: StatementSync;
  subdirCount: StatementSync;
  insert: StatementSync;
  setMeta: StatementSync;
  touch: StatementSync;
  setValueID: StatementSync;
  setHash: StatementSync;
  setCurrentVersion: StatementSync;
  setPartial: StatementSync;
  setDomain: StatementSync;
  objectsInDomain: StatementSync;
  objectsOwnedBy: StatementSync;
  byPinnedID: StatementSync;
  versionsOf: StatementSync;
  versionChildren: StatementSync;
  oldestVersions: StatementSync;
  versionsIn: StatementSync;
  sharers: StatementSync;
  countAccess: StatementSync;
  startCounts: StatementSync;
  setSize: StatementSync;
  setSizeAndContiguous: StatementSync;
  setWritten: StatementSync;
  written: StatementSync;
  remove: StatementSync;
  rename: StatementSync;
  subtree: StatementSync;
  getHandle: StatementSync;
  putHandle: StatementSync;
  resolveHandle: StatementSync;
  addOrphan: StatementSync;
  dropOrphan: StatementSync;
  orphans: StatementSync;
  orphanOf: StatementSync;
  clearImageSources: StatementSync;
  addImageSource: StatementSync;
  imageSourcesOf: StatementSync;
  imageSourcePaths: StatementSync;
  setExported: StatementSync;
  clearExported: StatementSync;
  exportedContainers: StatementSync;
  setMultipart: StatementSync;
  multipartParts: StatementSync;
  kmsMeta: StatementSync;
  putKmsMeta: StatementSync;
  setKmsMeta: StatementSync;
  bindingKeys: StatementSync;
  forgetKmsMeta: StatementSync;
}

/** An image import that interprets the value of a data object. */
export interface ImageSource {
  importer: number;
  entry: number;
  writeEnabled: boolean;
  disabled: boolean;
}

export class Store {
  readonly dir: string;
  private readonly db: DatabaseSync;
  private readonly q: Statements;

  private constructor(dir: string, db: DatabaseSync, q: Statements) {
    this.dir = dir;
    this.db = db;
    this.q = q;
  }

  /** Opens or creates the store rooted at dir. */
  static async open(dir: string, root: { owner?: string; acl?: ACE[] } = {}): Promise<Store> {
    // The buckets are created once, so no write path has to create one and
    // no two writers can race to do so.
    for (const a of HEX) {
      for (const b of HEX) {
        await mkdir(path.join(dir, "objects", a, b), { recursive: true });
      }
    }
    const db = new DatabaseSync(path.join(dir, "seedmi.db"));
    db.exec(SCHEMA);
    // A store written before the written column existed gains it here, its
    // rows taking the ranges their contiguous length implies: what such a
    // store knew of a value is that its first run is that long.
    const columns = db.prepare("SELECT name FROM pragma_table_info('object')").all() as { name: string }[];
    // A store written while an object ID was unique to a representation
    // carries that constraint in its schema. The representations of a name
    // share an identifier now, so the index is rebuilt without it; the rows
    // themselves keep the identifiers they were given, and a name that
    // already denotes two representations keeps two, which no operation
    // makes and only this server's earlier versions could have left.
    const idIndex = db.prepare(
      `SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'object' AND sql LIKE '%object_id%'`)
      .all() as { name: string }[];
    for (const ix of idIndex) {
      const sql = (db.prepare("SELECT sql FROM sqlite_master WHERE name = ?").get(ix.name) as { sql: string }).sql;
      if (/UNIQUE/i.test(sql)) db.exec(`DROP INDEX IF EXISTS "${ix.name}"`);
    }
    db.exec("CREATE INDEX IF NOT EXISTS object_by_id ON object (object_id)");
    // A store written before extension fields were stored gains the column,
    // empty: what such a store was given of them was not kept.
    if (!columns.some((c) => c.name === "extensions")) db.exec("ALTER TABLE object ADD COLUMN extensions TEXT");
    if (!columns.some((c) => c.name === "written")) {
      db.exec("ALTER TABLE object ADD COLUMN written TEXT");
      db.exec(`UPDATE object SET written = '[[0,' || (contiguous - 1) || ']]' WHERE contiguous > 0`);
    }
    // The sanitization method effective on the object whose value file an
    // orphan row names, where one was. It is recorded with the orphan
    // rather than applied at the moment of deletion, so that a crash
    // between the commit and the unlink leaves a file that is still known
    // to need sanitizing.
    if (!(db.prepare("PRAGMA table_info(orphan)").all() as { name: string }[])
      .some((c) => c.name === "sanitize")) {
      db.exec("ALTER TABLE orphan ADD COLUMN sanitize TEXT");
    }
    const q: Statements = {
      // A version has no parent either, so the root is the row that is
      // neither a child nor a version.
      root: db.prepare(
        `SELECT id FROM object WHERE parent IS NULL AND version_of IS NULL`),
      // The representations a name denotes, container first, then data,
      // then queue. A caller that names no kind is given the container
      // object representation where there is one, which is what a protocol
      // export needs: a file system has one namespace, where a name is a
      // directory or a file and not both, and the children must prevail so
      // that what the object holds is reachable through the export.
      lookup: db.prepare(
        `SELECT id, is_container, is_queue FROM object WHERE parent = ? AND name = ?
         ORDER BY is_container DESC, is_queue ASC`),
      lookupKind: db.prepare(
        `SELECT id, is_container, is_queue FROM object
         WHERE parent = ? AND name = ? AND is_container = ? AND is_queue = ?`),
      // The representations of one object share an identifier (5.3.7), so
      // this returns each of them, the data object first, then the
      // container object, then the queue object: the order a caller that
      // names no representation is given, which ECR-158A asks the group to
      // settle, the document naming no default for an address that has no
      // form to take one from.
      byObjectID: db.prepare(
        `SELECT id, is_container, is_queue FROM object WHERE object_id = ?
         ORDER BY is_queue, is_container`),
      meta: db.prepare(`SELECT * FROM object WHERE id = ?`),
      parentOf: db.prepare(`SELECT name, parent FROM object WHERE id = ?`),
      children: db.prepare(
        `SELECT id, name, is_container, reference FROM object
          WHERE parent = ? ORDER BY name`),
      childrenPage: db.prepare(
        `SELECT id, name, is_container, reference FROM object
          WHERE parent = ? ORDER BY name LIMIT ? OFFSET ?`),
      childCount: db.prepare(`SELECT COUNT(*) AS n FROM object WHERE parent = ?`),
      subdirCount: db.prepare(
        `SELECT COUNT(*) AS n FROM object WHERE parent = ? AND is_container = 1`),
      queueCount: db.prepare(
        "SELECT COUNT(*) AS n FROM queue_value WHERE queue = ?"),
      queueBounds: db.prepare(
        `SELECT MIN(designator) AS lo, MAX(designator) AS hi, COUNT(*) AS n
         FROM queue_value WHERE queue = ?`),
      queueRange: db.prepare(
        `SELECT designator, mimetype, vte, metadata, body FROM queue_value
         WHERE queue = ? AND designator >= ? AND designator <= ?
         ORDER BY designator`),
      queueSize: db.prepare(
        "SELECT COALESCE(SUM(LENGTH(body)), 0) AS n FROM queue_value WHERE queue = ?"),
      enqueue: db.prepare(
        `INSERT INTO queue_value (queue, designator, mimetype, vte, metadata, body)
         VALUES (?, ?, ?, ?, ?, ?)`),
      dequeue: db.prepare(
        "DELETE FROM queue_value WHERE queue = ? AND designator >= ? AND designator <= ?"),
      setNextDesignator: db.prepare(
        "UPDATE object SET next_designator = ? WHERE id = ?"),
      insert: db.prepare(
        `INSERT INTO object (object_id, parent, name, is_container, mimetype, vte,
                             metadata, owner, acl, imports, exports, rel, extensions, reference,
                             group_name, value_id, frozen, pinned_id, partial,
                             is_domain, is_queue, domain, version_of,
                             version_parent, size, contiguous, written, ctime, mtime, atime)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                 ?, ?, ?, ?, ?, ?)`),
      setMeta: db.prepare(
        `UPDATE object SET mimetype = ?, vte = ?, metadata = ?, owner = ?, acl = ?,
                           imports = ?, exports = ?, rel = ?, extensions = ?, group_name = ?,
                           version = version + 1, mcount = mcount + 1, mtime = ?
          WHERE id = ?`),
      setValueID: db.prepare(`UPDATE object SET value_id = ? WHERE id = ?`),
      setHash: db.prepare("UPDATE object SET hash = ? WHERE id = ?"),
      setCurrentVersion: db.prepare(
        `UPDATE object SET current_version = ? WHERE id = ?`),
      setPartial: db.prepare(`UPDATE object SET partial = ? WHERE id = ?`),
      setDomain: db.prepare(`UPDATE object SET domain = ? WHERE id = ?`),
      objectsInDomain: db.prepare(
        `SELECT COUNT(*) AS n FROM object WHERE domain = ? AND is_domain = 0`),
      objectsOwnedBy: db.prepare(
        `SELECT id, is_container FROM object WHERE domain = ? AND is_domain = 0`),
      byPinnedID: db.prepare(
        `SELECT id, is_container FROM object WHERE pinned_id = ? LIMIT 1`),
      versionsOf: db.prepare(
        `SELECT id FROM object WHERE version_of = ? ORDER BY id`),
      versionChildren: db.prepare(
        `SELECT id FROM object WHERE version_parent = ? ORDER BY id`),
      oldestVersions: db.prepare(
        `SELECT id FROM object WHERE version_of = ? AND version_parent IS NULL
          ORDER BY id`),
      versionsIn: db.prepare(
        `SELECT id, object_id, value_id FROM object WHERE version_of IN
           (SELECT value FROM json_each(?))`),
      // The rows that read one value file, which decides whether the
      // file may be unlinked when one of them goes.
      sharers: db.prepare(
        `SELECT COUNT(*) AS n FROM object WHERE COALESCE(value_id, object_id) = ?`),
      // The counters and the times are of the object, not of one
      // representation of it: a name that denotes several has one set,
      // moved together (5.3.7). The rows of one object share an object_id.
      touch: db.prepare(
        `UPDATE object SET version = version + 1, mcount = mcount + 1, mtime = ?
          WHERE object_id = (SELECT object_id FROM object WHERE id = ?)`),
      // An access is counted without moving the version: a read is not
      // a change, and an NFS client watching the change attribute must
      // not see one because somebody read the object.
      countAccess: db.prepare(
        `UPDATE object SET acount = acount + 1, atime = ?
          WHERE object_id = (SELECT object_id FROM object WHERE id = ?)`),
      // The counters of a new object are zero, and its modification time is
      // its creation time: the representation is applied after the row is
      // inserted, so mtime landed a moment after ctime and a client saw an
      // object modified since it was made (weedmi, 0.66).
      startCounts: db.prepare(
        `UPDATE object SET acount = 0, mcount = 0, mtime = ctime
          WHERE object_id = (SELECT object_id FROM object WHERE id = ?)`),
      setSize: db.prepare(
        `UPDATE object SET size = ?, version = version + 1, mcount = mcount + 1,
                           mtime = ? WHERE id = ?`),
      setSizeAndContiguous: db.prepare(
        `UPDATE object SET size = ?, contiguous = ?, version = version + 1,
                           mcount = mcount + 1, mtime = ? WHERE id = ?`),
      setWritten: db.prepare(
        `UPDATE object SET size = ?, contiguous = ?, written = ?, version = version + 1,
                           mcount = mcount + 1, mtime = ? WHERE id = ?`),
      written: db.prepare("SELECT written, size FROM object WHERE id = ?"),
      remove: db.prepare(`DELETE FROM object WHERE id = ?`),
      rename: db.prepare(
        `UPDATE object SET parent = ?, name = ?, version = version + 1 WHERE id = ?`),
      // Every object at or below n, for collecting the value files of a
      // container object that is about to be deleted.
      subtree: db.prepare(
        `WITH RECURSIVE below(id) AS (
           SELECT ? UNION ALL SELECT o.id FROM object o JOIN below b ON o.parent = b.id)
         SELECT o.id, o.object_id, o.is_container, o.value_id
            FROM object o JOIN below ON o.id = below.id`),
      getHandle: db.prepare(`SELECT id FROM handle WHERE parent = ? AND name = ?`),
      putHandle: db.prepare(`INSERT INTO handle (id, parent, name) VALUES (?, ?, ?)`),
      resolveHandle: db.prepare(`SELECT parent, name FROM handle WHERE id = ?`),
      addOrphan: db.prepare(
        `INSERT OR IGNORE INTO orphan (object_id, since, sanitize) VALUES (?, ?, ?)`),
      dropOrphan: db.prepare(`DELETE FROM orphan WHERE object_id = ?`),
      orphans: db.prepare(`SELECT object_id, sanitize FROM orphan`),
      orphanOf: db.prepare(`SELECT sanitize FROM orphan WHERE object_id = ?`),
      clearImageSources: db.prepare(`DELETE FROM image_source WHERE importer = ?`),
      addImageSource: db.prepare(
        `INSERT INTO image_source (importer, entry, source_path, write_enabled, disabled)
         VALUES (?, ?, ?, ?, ?)`),
      imageSourcesOf: db.prepare(
        `SELECT importer, entry, write_enabled, disabled FROM image_source
          WHERE source_path = ?`),
      imageSourcePaths: db.prepare(
        `SELECT source_path, write_enabled FROM image_source WHERE disabled = 0`),
      setExported: db.prepare(`INSERT OR IGNORE INTO exported (container) VALUES (?)`),
      clearExported: db.prepare(`DELETE FROM exported WHERE container = ?`),
      exportedContainers: db.prepare(`SELECT container FROM exported`),
      setMultipart: db.prepare(
        `INSERT OR REPLACE INTO multipart_object (object_id, version, parts) VALUES (?, ?, ?)`),
      multipartParts: db.prepare(
        `SELECT parts FROM multipart_object WHERE object_id = ? AND version = ?`),
      kmsMeta: db.prepare(`SELECT value FROM kms_meta WHERE key = ?`),
      putKmsMeta: db.prepare(`INSERT OR IGNORE INTO kms_meta (key, value) VALUES (?, ?)`),
      setKmsMeta: db.prepare(`UPDATE kms_meta SET value = ? WHERE key = ?`),
      bindingKeys: db.prepare(`SELECT key FROM kms_meta WHERE key LIKE 'binding:%'`),
      forgetKmsMeta: db.prepare(`DELETE FROM kms_meta WHERE key = ?`),
    };
    const s = new Store(dir, db, q);
    // "Where a root container object is created and no access control list
    // is supplied, the CDMI server shall place an access control list
    // containing the following access control entry on that container
    // object" — OWNER@ with ALL_PERMS. Where no owner is supplied either,
    // ANONYMOUS@ owns it, which is the only principal a store with no
    // configured principals has: the list is then the document's and the
    // store is open, where before the list named ANONYMOUS@ directly and
    // so was not the list the document requires.
    s.ensureRoot(root.owner ?? "", root.acl ?? OPEN_ROOT_ACL);
    return s;
  }

  close(): void {
    this.db.close();
  }

  /**
   * Runs fn in a transaction. fn is synchronous by design: a transaction
   * never spans an await, so no other request can interleave within it.
   * Value files are written outside the transaction, before the row that
   * refers to them is committed.
   */
  tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const out = fn();
      this.db.exec("COMMIT");
      return out;
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  // -------------------------------------------------------------------
  // The namespace

  private ensureRoot(owner: string, acl: ACE[] | null): void {
    if (this.q.root.get()) return;
    const now = Date.now();
    this.q.insert.run(newObjectID(), null, "", 1, "", "", "{}", owner,
      // imports, exports, rel, extensions, reference, then the group.
      acl === null ? null : JSON.stringify(acl), null, null, null, null, null, "",
      null, 0, null, 0, 0, 0, null, null, null,
      // size, contiguous, then the written ranges: the root container object
      // has no value, so it records none.
      0, 0, null, now, now, now);
  }

  root(): Node {
    const row = this.q.root.get() as { id: number } | undefined;
    if (!row) throw noObject("the root");
    return { id: row.id, isContainer: true };
  }

  /** The object of the given name within parent, whichever form it takes. */
  lookup(parent: Node, name: string): Node {
    const row = this.q.lookup.get(parent.id, name) as
      { id: number; is_container: number } | undefined;
    if (!row) throw noObject(`${name} within object ${parent.id}`);
    return { id: row.id, isContainer: row.is_container === 1 };
  }

  /**
   * The representation of one kind that a name denotes, where it
   * denotes one. A name may denote a data object, a container object
   * and a queue object at once, each addressed independently.
   */
  /**
   * Every queue object the store holds, so that a registry kept in memory can
   * be rebuilt from what persists. A notification queue's registration lived
   * only in the process that created it until 0.107, so a queue created before
   * a restart was silently deregistered and never enqueued another event.
   */
  queueObjects(): Node[] {
    return (this.db.prepare("SELECT id FROM object WHERE is_queue = 1").all() as { id: number }[])
      .map((r) => ({ id: r.id, isContainer: false }));
  }

  lookupKind(parent: Node, name: string, kind: Kind): Node | undefined {
    const row = this.q.lookupKind.get(parent.id, name,
      kind === "container" ? 1 : 0, kind === "queue" ? 1 : 0) as
      { id: number; is_container: number } | undefined;
    return row === undefined
      ? undefined
      : { id: row.id, isContainer: row.is_container === 1 };
  }

  /** Every representation a name denotes, with the kind of each. */
  representations(parent: Node, name: string): { kind: Kind; node: Node }[] {
    const rows = this.q.lookup.all(parent.id, name) as
      { id: number; is_container: number; is_queue: number }[];
    return rows.map((r) => ({
      kind: r.is_container === 1 ? "container" : r.is_queue === 1 ? "queue" : "data",
      node: { id: r.id, isContainer: r.is_container === 1 },
    }));
  }

  tryLookup(parent: Node, name: string): Node | undefined {
    try {
      return this.lookup(parent, name);
    } catch (err) {
      if (err instanceof StoreError && err.code === "no-object") return undefined;
      throw err;
    }
  }

  byObjectID(objectID: string, kind?: Kind): Node {
    const rows = this.q.byObjectID.all(objectID) as
      { id: number; is_container: number; is_queue: number }[];
    if (rows.length === 0) throw noObject(objectID);
    const of = (r: { is_container: number; is_queue: number }): Kind =>
      r.is_container === 1 ? "container" : r.is_queue === 1 ? "queue" : "data";
    // A caller naming a representation is given that one where the object
    // has it, and nothing where it does not; one naming none is given the
    // first, which is the data object where there is one.
    const row = kind === undefined ? rows[0] : rows.find((r) => of(r) === kind);
    if (row === undefined) throw noObject(`${objectID} as a ${kind} object`);
    return { id: row.id, isContainer: row.is_container === 1 };
  }

  /** The representations an object ID denotes, in the order byObjectID gives them. */
  representationsOf(objectID: string): Kind[] {
    return (this.q.byObjectID.all(objectID) as { is_container: number; is_queue: number }[])
      .map((r) => (r.is_container === 1 ? "container" : r.is_queue === 1 ? "queue" : "data"));
  }

  /** The namespace path of n, with a trailing solidus for a container. */
  pathOf(n: Node): string {
    const parts: string[] = [];
    let id = n.id;
    for (;;) {
      const row = this.q.parentOf.get(id) as
        { name: string; parent: number | null } | undefined;
      if (!row) throw noObject(`object ${id}`);
      if (row.parent === null) break;
      parts.unshift(row.name);
      id = row.parent;
    }
    const p = "/" + parts.join("/");
    return n.isContainer && !p.endsWith("/") ? p + "/" : p;
  }

  /** The object at a namespace path. A trailing solidus is not required. */
  resolve(p: string): Node {
    let n = this.root();
    for (const seg of p.split("/")) {
      if (seg === "") continue;
      if (!n.isContainer) throw noObject(p);
      n = this.lookup(n, seg);
    }
    return n;
  }

  children(parent: Node, offset = 0, limit = 0): Child[] {
    if (!parent.isContainer) throw notContainer();
    const rows = (limit > 0
      ? this.q.childrenPage.all(parent.id, limit, offset)
      : this.q.children.all(parent.id)) as
      { id: number; name: string; is_container: number; reference: string | null }[];
    const from = limit > 0 ? 0 : offset;
    return rows.slice(from).map((r) => ({
      node: { id: r.id, isContainer: r.is_container === 1 },
      name: r.name,
      reference: r.reference === null ? undefined : r.reference,
    }));
  }

  childCount(parent: Node): number {
    return (this.q.childCount.get(parent.id) as { n: number }).n;
  }

  /** The container objects within parent, which NFSv4 numlinks counts. */
  subdirCount(parent: Node): number {
    return (this.q.subdirCount.get(parent.id) as { n: number }).n;
  }

  // -------------------------------------------------------------------
  // Metadata

  meta(n: Node): Meta {
    const r = this.q.meta.get(n.id) as Record<string, any> | undefined;
    if (!r) throw noObject(`object ${n.id}`);
    return {
      objectID: r.object_id,
      name: r.name,
      parent: r.parent,
      isContainer: r.is_container === 1,
      mimetype: r.mimetype,
      vte: r.vte,
      metadata: JSON.parse(r.metadata),
      owner: r.owner,
      group: r.group_name ?? "",
      acl: r.acl === null ? null : JSON.parse(r.acl),
      imports: r.imports === null ? undefined : JSON.parse(r.imports),
      exports: r.exports === null ? undefined : JSON.parse(r.exports),
      rel: r.rel === null || r.rel === undefined ? undefined : JSON.parse(r.rel),
      extensions: r.extensions === null || r.extensions === undefined ? undefined : JSON.parse(r.extensions),
      reference: r.reference === null || r.reference === undefined
        ? undefined
        : r.reference,
      version: r.version,
      // Accesses and modifications, counted since the object was
      // created.
      acount: r.acount ?? 0,
      mcount: r.mcount ?? 0,
      valueID: r.value_id ?? r.object_id,
      frozen: r.frozen === 1,
      pinnedID: r.pinned_id ?? null,
      partial: r.partial === 1,
      contiguous: r.contiguous ?? r.size,
      isDomain: r.is_domain === 1,
      isQueue: r.is_queue === 1,
      hash: (r.hash as string | null) ?? null,
      nextDesignator: r.next_designator ?? 0,
      queueCount: r.is_queue === 1
        ? Number((this.q.queueCount.get(r.id) as { n: number }).n)
        : 0,
      domain: r.domain ?? null,
      versionOf: r.version_of ?? null,
      versionParent: r.version_parent ?? null,
      currentVersion: r.current_version ?? null,
      size: r.size,
      ctime: r.ctime,
      mtime: r.mtime,
      atime: r.atime,
    };
  }

  /** Replaces the mutable metadata of n and moves its version. */
  setMeta(n: Node, m: Meta): void {
    this.q.setMeta.run(
      m.mimetype, m.vte, JSON.stringify(m.metadata ?? {}), m.owner,
      m.acl === null || m.acl === undefined ? null : JSON.stringify(m.acl),
      m.imports === undefined ? null : JSON.stringify(m.imports),
      m.exports === undefined ? null : JSON.stringify(m.exports),
      m.rel === undefined ? null : JSON.stringify(m.rel),
      m.extensions === undefined || Object.keys(m.extensions).length === 0 ? null : JSON.stringify(m.extensions),
      m.group,
      Date.now(), n.id);
  }

  /**
   * Counts an access: a read, a write or a list. The version is not
   * moved, since a read is not a change of the object.
   */
  countAccess(n: Node): void {
    this.q.countAccess.run(Date.now(), n.id);
  }

  /**
   * Sets the counters of a newly created object to zero. Building the
   * object may have taken several statements, each of which counted a
   * modification; none of them is a modification a client made.
   */
  startCounts(n: Node): void {
    this.q.startCounts.run(n.id);
  }

  /** Moves the version of n without changing anything else. */
  touch(n: Node): void {
    this.q.touch.run(Date.now(), n.id);
  }

  // -------------------------------------------------------------------
  // Creation, deletion, renaming

  createContainer(parent: Node, name: string, m: NewMeta = {}): Node {
    m = { ...this.sharedWith(parent, name), ...m };
    return this.create(parent, name, true, m);
  }

  /**
   * Creates a data object with an empty value. The value file is created by
   * writeValue; a data object with no value file reads as empty.
   */
  /**
   * Creates a reference: a name that redirects to a URI. It is not an
   * object, and a row holds it because a name within a container
   * object is held in this table.
   */
  createReference(parent: Node, name: string, destination: string,
    m: NewMeta = {}): Node {
    return this.create(parent, name, false, { ...m, reference: destination });
  }

  /**
   * The ranges of a value, as the written column holds them: ordered, never
   * touching and never overlapping, so that the first entry beginning at zero
   * gives the contiguous length and a gap is the space between two entries.
   */
  static mergeRange(ranges: [number, number][], first: number, last: number): [number, number][] {
    if (last < first) return ranges;
    const out: [number, number][] = [];
    let lo = first;
    let hi = last;
    for (const [a, b] of ranges) {
      // A range that touches or overlaps the new one is absorbed into it;
      // 0-9 and 10-49 are one run of 0-49 and not two.
      if (b + 1 < lo) out.push([a, b]);
      else if (a > hi + 1) out.push([a, b]);
      else {
        lo = Math.min(lo, a);
        hi = Math.max(hi, b);
      }
    }
    out.push([lo, hi]);
    out.sort((x, y) => x[0] - y[0]);
    return out;
  }

  /** The length of the value written from the beginning without a gap. */
  static contiguousOf(ranges: [number, number][]): number {
    const first = ranges[0];
    return first !== undefined && first[0] === 0 ? first[1] + 1 : 0;
  }

  /** The ranges recorded for an object, or the whole of its value where none are. */
  ranges(n: Node): [number, number][] {
    const row = this.q.written.get(n.id) as { written: string | null; size: number } | undefined;
    if (row === undefined) return [];
    if (row.written === null) return row.size > 0 ? [[0, row.size - 1]] : [];
    try {
      return JSON.parse(row.written) as [number, number][];
    } catch {
      return row.size > 0 ? [[0, row.size - 1]] : [];
    }
  }

  createData(parent: Node, name: string, m: NewMeta = {}): Node {
    return this.create(parent, name, false, { ...this.sharedWith(parent, name), ...m });
  }

  /**
   * What a new representation takes from the representations a name already
   * denotes: "A name may denote more than one representation of one object
   * ... each representation shall have the same object ID" (5.3.7). The
   * owner, the list and the domain are of the object and are shared with it;
   * the value and the children are of the representation.
   */
  private sharedWith(parent: Node, name: string): NewMeta {
    for (const kind of ["data", "container", "queue"] as const) {
      const other = this.lookupKind(parent, name, kind);
      if (other === undefined) continue;
      const m = this.meta(other);
      return {
        objectID: m.objectID, owner: m.owner, acl: m.acl,
        domain: m.domain ?? undefined, ctime: m.ctime,
      };
    }
    return {};
  }

  /**
   * Creates a queue object, which holds an ordered sequence of values
   * rather than one value. It is neither a container object nor a data
   * object, and a name holds at most one object of any kind.
   */
  /**
   * Records the hash of the value, or removes it. A hash is computed
   * where the cdmi_value_hash data system metadata item asks for one,
   * so it is written with the value rather than computed on each read.
   */
  setHash(n: Node, hash: string | null): void {
    this.q.setHash.run(hash, n.id);
  }

  /** The total size of the values a queue object holds, in octets. */
  queueSize(n: Node): number {
    return Number((this.q.queueSize.get(n.id) as { n: number }).n);
  }

  /** The values a queue object holds, oldest first. */
  queueValues(n: Node, from?: number, to?: number): QueueValue[] {
    const rows = this.q.queueRange.all(n.id,
      from ?? 0, to ?? Number.MAX_SAFE_INTEGER) as Record<string, unknown>[];
    return rows.map((r) => ({
      designator: Number(r.designator),
      mimetype: String(r.mimetype),
      vte: String(r.vte),
      ...(r.metadata === null || r.metadata === undefined
        ? {}
        : { metadata: JSON.parse(String(r.metadata)) as Record<string, unknown> }),
      body: Buffer.from(r.body as Uint8Array),
    }));
  }

  /** The lowest and highest designators the queue object holds. */
  queueBounds(n: Node): { lowest: number; highest: number; count: number } {
    const r = this.q.queueBounds.get(n.id) as
      { lo: number | null; hi: number | null; n: number };
    return { lowest: r.lo ?? 0, highest: r.hi ?? -1, count: Number(r.n) };
  }

  /**
   * Appends values to a queue object, assigning each the next
   * designator. Designators are not reused, so the counter advances
   * whatever has been removed.
   */
  enqueue(n: Node, values: {
    mimetype: string;
    vte: string;
    body: Buffer;
    metadata?: Record<string, unknown>;
  }[]): number[] {
    const m = this.meta(n);
    let next = m.nextDesignator;
    const assigned: number[] = [];
    for (const v of values) {
      this.q.enqueue.run(n.id, next, v.mimetype, v.vte,
        v.metadata === undefined ? null : JSON.stringify(v.metadata), v.body);
      assigned.push(next);
      next += 1;
    }
    this.q.setNextDesignator.run(next, n.id);
    this.touch(n);
    // An MQTT export publishes each value as it is enqueued, whichever
    // operation enqueued it, so the notice is given here rather than
    // at each of the operations that append.
    for (const listener of this.enqueued) {
      try {
        listener(n, assigned);
      } catch {
        // A listener that fails does not fail the enqueue: the values
        // are held by the queue object either way.
      }
    }
    return assigned;
  }

  /** Called with the designators assigned, whenever values are enqueued. */
  onEnqueue(listener: (node: Node, designators: number[]) => void): void {
    this.enqueued.push(listener);
  }

  /**
   * Called with the identifier of each object removed, whichever
   * operation removed it, so that what runs on an object stops when
   * the object goes.
   */
  onRemove(listener: (id: number) => void): void {
    this.removed.push(listener);
  }

  private readonly removed: ((id: number) => void)[] = [];

  private readonly enqueued: ((node: Node, designators: number[]) => void)[] = [];

  /** Removes the values within a range of designators, inclusive. */
  dequeue(n: Node, from: number, to: number): number {
    const info = this.q.dequeue.run(n.id, from, to);
    if (Number(info.changes) > 0) this.touch(n);
    return Number(info.changes);
  }

  createQueue(parent: Node, name: string, m: NewMeta = {}): Node {
    return this.create(parent, name, false, { ...this.sharedWith(parent, name), ...m, isQueue: true });
  }

  /**
   * Creates a row. A parent of null makes a row outside the namespace,
   * which is what a version is: it has no name and is addressed by its
   * object ID.
   */
  private create(parent: Node | null, name: string, isContainer: boolean,
    m: NewMeta): Node {
    if (parent !== null && !parent.isContainer) throw notContainer();
    const now = Date.now();
    const objectID = m.objectID ?? newObjectID();
    uuidOf(objectID); // reject anything that cannot name a value file
    let info;
    try {
      info = this.q.insert.run(
        objectID, parent === null ? null : parent.id, name, isContainer ? 1 : 0,
        m.mimetype ?? "", m.vte ?? "",
        JSON.stringify(m.metadata ?? {}), m.owner ?? "",
        m.acl ? JSON.stringify(m.acl) : null,
        m.imports === undefined ? null : JSON.stringify(m.imports),
        m.exports === undefined ? null : JSON.stringify(m.exports),
        m.rel === undefined ? null : JSON.stringify(m.rel),
        m.extensions === undefined || Object.keys(m.extensions).length === 0 ? null : JSON.stringify(m.extensions),
        m.reference ?? null, m.group ?? "",
        m.valueID ?? null, m.frozen ? 1 : 0, m.pinnedID ?? null, m.partial ? 1 : 0,
        m.isDomain ? 1 : 0, m.isQueue ? 1 : 0, m.domain ?? null,
        m.versionOf ?? null, m.versionParent ?? null,
        m.size ?? 0, m.contiguous ?? m.size ?? 0,
        m.written === undefined ? null : JSON.stringify(m.written),
        m.ctime ?? now, now, now);
    } catch (err) {
      if (String(err).includes("UNIQUE") || String(err).includes("constraint")) {
        throw exists(name);
      }
      throw err;
    }
    if (parent !== null) this.touch(parent);
    return { id: Number(info.lastInsertRowid), isContainer };
  }

  /**
   * Removes n and everything within it, returning the object IDs whose
   * value files the caller then deletes. They are recorded as orphans
   * first, so that a crash between the commit and the unlink leaves a file
   * that is known to be collectable rather than one that is merely unused.
   */
  removeTree(n: Node): string[] {
    const rows = this.q.subtree.all(n.id) as
      {
        id: number; object_id: string; is_container: number; value_id: string | null;
      }[];
    // "A CDMI server shall delete one representation as a result of the
    // deletion of another" (5.3.7): a name denotes one object, and every
    // representation of it goes with the deletion of any (weedmi OPER-042).
    // A representation is found by the name and parent of the row deleted,
    // and its own subtree follows.
    const siblings: number[] = [];
    const here = this.q.meta.get(n.id) as { parent: number | null; name: string } | undefined;
    if (here !== undefined && here.parent !== null) {
      const seen = new Set(rows.map((r) => r.id));
      for (const kind of ["data", "container", "queue"] as const) {
        const other = this.lookupKind({ id: here.parent, isContainer: true }, here.name, kind);
        if (other === undefined || seen.has(other.id)) continue;
        siblings.push(other.id);
        for (const r of this.q.subtree.all(other.id) as typeof rows) {
          if (!seen.has(r.id)) { seen.add(r.id); rows.push(r); }
        }
      }
    }
    // Deleting a data object deletes every version associated with it.
    // A version is not a child, so the subtree does not reach one.
    const versions = this.q.versionsIn.all(JSON.stringify(rows.map((r) => r.id))) as
      { id: number; object_id: string; value_id: string | null }[];
    for (const v of versions) rows.push({ ...v, is_container: 0 });
    // A value file is unlinked only where nothing else reads it: a
    // snapshot shares the file of the object it copied, and the last
    // reader takes it away.
    const reading = new Map<string, number>();
    for (const r of rows) {
      if (r.is_container === 1) continue;
      const id = r.value_id ?? r.object_id;
      reading.set(id, (reading.get(id) ?? 0) + 1);
    }
    const values: string[] = [];
    for (const [id, going] of reading) {
      const total = (this.q.sharers.get(id) as { n: number }).n;
      if (total <= going) values.push(id);
    }
    const now = Date.now();
    // The sanitization method each value file is to be overwritten with
    // before it is unlinked, where the object that held it asked for one.
    // It is read here, while the object still exists, and recorded with the
    // orphan: after this returns, nothing knows what the object asked for.
    const asked = new Map<string, string>();
    for (const r of rows) {
      if (r.is_container === 1) continue;
      const id = r.value_id ?? r.object_id;
      const method = this.sanitizeMethod?.({ id: r.id, isContainer: false });
      if (method !== undefined && method !== "") asked.set(id, method);
    }
    for (const v of values) this.q.addOrphan.run(v, now, asked.get(v) ?? null);
    const parent = (this.q.parentOf.get(n.id) as { parent: number | null } | undefined)?.parent;
    for (const v of versions) this.q.remove.run(v.id);
    this.q.remove.run(n.id);
    // The other representations of the name go with it: the row of each is
    // removed, its subtree going with it by the same cascade (5.3.7).
    for (const id of siblings) this.q.remove.run(id);
    if (parent !== null && parent !== undefined) {
      this.touch({ id: parent, isContainer: true });
    }
    // Every object of the subtree has gone, so what runs on one is
    // told: a query of a query queue that has been removed has
    // nothing to enqueue to.
    for (const r of rows) {
      for (const listener of this.removed) {
        try {
          listener(r.id);
        } catch {
          // A listener that fails does not fail the removal.
        }
      }
    }
    return values;
  }

  /**
   * Copies a container object and everything within it into a new
   * container, sharing the value file of every data object rather than
   * copying its bytes. A snapshot is therefore a number of rows and no
   * data, and is quick in proportion to the number of objects rather
   * than to their size.
   *
   * Reserved names are not copied, so a snapshot holds no
   * cdmi_snapshots container object of its own and does not contain
   * earlier snapshots.
   */
  snapshotTree(source: Node, parent: Node, name: string): Node {
    const m = this.meta(source);
    const made = this.create(parent, name, true, {
      metadata: withoutRestrictions(m.metadata),
      owner: m.owner,
      group: m.group,
      acl: m.acl,
      rel: m.rel,
      extensions: m.extensions,
      // An imports field is copied and is not processed within a
      // snapshot; an exports field is not copied at all.
      imports: m.imports,
      frozen: true,
    });
    this.fill(made, source);
    return made;
  }

  private fill(into: Node, from: Node): void {
    for (const child of this.children(from)) {
      if (reservedName(child.name)) continue;
      const m = this.meta(child.node);
      // A version-enabled data object is captured by pinning its
      // current version, which already exists, is immutable, and has
      // an object ID of its own. The snapshot holds a row that reads
      // that version rather than a copy with no identity.
      const pinned = !child.node.isContainer && m.currentVersion !== null
        ? this.meta({ id: m.currentVersion, isContainer: false })
        : undefined;
      const copy = this.create(into, child.name, child.node.isContainer, {
        // A queue object of the snapshot is a queue object.
        isQueue: m.isQueue,
        mimetype: m.mimetype,
        vte: m.vte,
        // A snapshot is a copy, and retention and hold are not
        // preserved in a copy.
        metadata: withoutRestrictions(m.metadata),
        owner: m.owner,
        group: m.group,
        acl: m.acl,
        rel: m.rel,
        extensions: m.extensions,
        imports: m.imports,
        reference: m.reference,
        // The domain that owns the object owns the snapshot of it. Snapshot
        // creation left this null, so every object within a snapshot was owned
        // by no domain: its representation could carry no domainURI field,
        // which "applies to every representation other than that of a
        // capability object", and the storage the snapshot occupies was counted
        // against no domain at all.
        ...(m.domain === null ? {} : { domain: m.domain }),
        frozen: true,
        // The object ID of the pinned version, where there is one: the
        // snapshot entry is that version, and is addressable by it.
        pinnedID: pinned?.objectID,
        // The value file of the object is read, not copied.
        valueID: child.node.isContainer ? undefined : (pinned ?? m).valueID,
        size: (pinned ?? m).size,
        // The gaps of the value come with it, as they do in shareValue and in a
        // copy between CDMI servers. Snapshot creation was the one value-sharing
        // path that did not carry them: the entry recorded no written ranges, so
        // it read as a value written from end to end, and a snapshot of an
        // object whose value has a gap reported a range covering the gap and
        // served the unwritten octets as though they had been written. "The
        // snapshot captures the state of the container object at the time the
        // CDMI server accepts the operation", and where the gaps are is part of
        // that state.
        ...(child.node.isContainer || m.isQueue ? {} : {
          contiguous: (pinned ?? m).contiguous,
          written: this.ranges(pinned !== undefined && m.currentVersion !== null
            ? { id: m.currentVersion, isContainer: false }
            : child.node),
        }),
      });
      // A queue object holds a sequence of values rather than a
      // value file, so what it holds is copied into the snapshot:
      // a snapshot presents the state of the objects at a point in
      // time, and for a queue object that state is its values.
      if (m.isQueue) {
        this.enqueue(copy, this.queueValues(child.node).map((v) => ({
          mimetype: v.mimetype,
          vte: v.vte,
          body: v.body,
          ...(v.metadata === undefined ? {} : { metadata: v.metadata }),
        })));
      }
      if (child.node.isContainer) this.fill(copy, child.node);
    }
  }

  /**
   * Makes one object read the value file another reads. The bytes are
   * not copied: a write to either makes the copy, as it does for a
   * snapshot.
   */
  async shareValue(into: Node, from: Node): Promise<void> {
    const m = this.meta(from);
    // What the target held is no longer read by it.
    const was = this.meta(into);
    this.q.setValueID.run(m.valueID, into.id);
    // The gaps of the value come with it.
    this.q.setWritten.run(m.size, m.contiguous, JSON.stringify(this.ranges(from)), Date.now(), into.id);
    await this.rehash(into);
    if ((this.q.sharers.get(was.valueID) as { n: number }).n === 0) {
      await rm(this.valuePath(was.valueID), { force: true });
    }
  }

  // -----------------------------------------------------------------
  // Versions
  //
  // A version is a data object outside the namespace: it has no parent
  // and no name, and is addressed by its object ID alone. It shares
  // the value file of the state it captured, so creating one copies no
  // bytes; a later write to the object gives the object a fresh file
  // and leaves the version reading the old one.

  /**
   * Creates a version holding the current state of a data object. The
   * version becomes the current version, and the version that was
   * current becomes its parent.
   */
  createVersion(n: Node): Node {
    const m = this.meta(n);
    if (m.isContainer) throw notContainer();
    const made = this.create(null, "", false, {
      mimetype: m.mimetype,
      vte: m.vte,
      metadata: { ...m.metadata },
      owner: m.owner,
      group: m.group,
      acl: m.acl,
      rel: m.rel,
      extensions: m.extensions,
      frozen: true,
      versionOf: n.id,
      versionParent: m.currentVersion ?? undefined,
      // The version reads what the object reads.
      valueID: m.valueID,
      size: m.size,
    });
    this.q.setCurrentVersion.run(made.id, n.id);
    return made;
  }

  /** The domain object at the root of the domain hierarchy. */
  domainRoot(create = false): Node | undefined {
    const root = this.root();
    const held = this.tryLookup(root, DOMAINS);
    if (held) return held;
    if (!create) return undefined;
    // The list and the owner of the root container object apply, so
    // that whoever administers the store administers its domains.
    const m = this.meta(root);
    return this.create(root, DOMAINS, true, {
      isDomain: true,
      metadata: { cdmi_domain_enabled: "true" },
      acl: m.acl,
      owner: m.owner,
      group: m.group,
    });
  }

  /** Creates a domain object within another domain object. */
  createDomain(parent: Node, name: string, m: NewMeta = {}): Node {
    return this.create(parent, name, true, { ...m, isDomain: true });
  }

  /**
   * Moves the objects a domain object owns to another domain object,
   * which a move of the domain object itself performs: the objects
   * are unchanged but for the domain they name.
   */
  reassignDomain(from: Node, to: Node): void {
    this.db.exec(
      `UPDATE object SET domain = ${to.id} WHERE domain = ${from.id}`);
  }

  /** How many objects a domain object owns, which a delete checks. */
  objectsInDomain(n: Node): number {
    return (this.q.objectsInDomain.get(n.id) as { n: number }).n;
  }

  /** The objects a domain object owns, its subdomains aside. */
  objectsOwnedBy(n: Node): Node[] {
    return (this.q.objectsOwnedBy.all(n.id) as { id: number; is_container: number }[])
      .map((r) => ({ id: r.id, isContainer: r.is_container === 1 }));
  }

  /** Sets the domain object that owns an object. */
  setDomain(n: Node, domain: Node): void {
    this.q.setDomain.run(domain.id, n.id);
  }

  /**
   * Marks an object as being created or updated by a series of
   * requests, or as complete. The version moves with it: an object
   * that is not complete takes no version.
   */
  setPartial(n: Node, partial: boolean): void {
    this.q.setPartial.run(partial ? 1 : 0, n.id);
  }

  /** The row within a snapshot that pins a version, where one does. */
  byPinnedID(objectID: string): Node | undefined {
    const row = this.q.byPinnedID.get(objectID) as
      { id: number; is_container: number } | undefined;
    return row ? { id: row.id, isContainer: row.is_container === 1 } : undefined;
  }

  /** The versions of a data object, oldest first. */
  versionsOf(n: Node): Node[] {
    return (this.q.versionsOf.all(n.id) as { id: number }[])
      .map((r) => ({ id: r.id, isContainer: false }));
  }

  /** The versions created from a version. */
  versionChildren(n: Node): Node[] {
    return (this.q.versionChildren.all(n.id) as { id: number }[])
      .map((r) => ({ id: r.id, isContainer: false }));
  }

  /** The oldest version or versions: those with no parent. */
  oldestVersions(n: Node): Node[] {
    return (this.q.oldestVersions.all(n.id) as { id: number }[])
      .map((r) => ({ id: r.id, isContainer: false }));
  }

  /** Makes a version the current one, which a rollback does. */
  setCurrentVersion(n: Node, version: Node | null): void {
    this.q.setCurrentVersion.run(version === null ? null : version.id, n.id);
  }

  /** The reserved container object that holds the snapshots of n. */
  snapshotHome(n: Node, create = false): Node | undefined {
    const held = this.tryLookup(n, SNAPSHOTS);
    if (held) return held;
    if (!create) return undefined;
    // It is created when the first snapshot is created, and is not
    // presented before then.
    return this.createContainer(n, SNAPSHOTS, { acl: this.meta(n).acl });
  }

  rename(n: Node, newParent: Node, newName: string): void {
    if (!newParent.isContainer) throw notContainer();
    try {
      this.q.rename.run(newParent.id, newName, n.id);
    } catch (err) {
      if (String(err).includes("UNIQUE") || String(err).includes("constraint")) {
        throw exists(newName);
      }
      throw err;
    }
  }

  // -------------------------------------------------------------------
  // Values

  /**
   * The path of the value file of the object with this object ID:
   * objects/<a>/<b>/<uuid>, where a and b are its first two hex digits.
   */
  valuePath(valueID: string): string {
    const uuid = uuidOf(valueID);
    return path.join(this.dir, "objects", uuid[0], uuid[1], uuid);
  }

  /** Every value file held, for collection and for tests. */
  async valueFiles(): Promise<string[]> {
    const out: string[] = [];
    for (const a of HEX) {
      for (const b of HEX) {
        const bucket = path.join(this.dir, "objects", a, b);
        let names: string[];
        try {
          names = await readdir(bucket);
        } catch (err: any) {
          if (err?.code === "ENOENT") continue;
          throw err;
        }
        for (const n of names) out.push(n);
      }
    }
    return out.sort();
  }

  async readValue(n: Node, offset = 0, length?: number): Promise<Buffer> {
    const m = this.meta(n);
    if (m.isContainer) throw notContainer();
    const want = length === undefined ? m.size - offset : Math.min(length, m.size - offset);
    if (want <= 0) return Buffer.alloc(0);
    let fh;
    try {
      fh = await openFile(this.valuePath(m.valueID), "r");
    } catch (err: any) {
      if (err?.code === "ENOENT") return Buffer.alloc(want); // no file: an empty value
      throw err;
    }
    try {
      const buf = Buffer.alloc(want);
      const { bytesRead } = await fh.read(buf, 0, want, offset);
      return bytesRead === want ? buf : buf.subarray(0, bytesRead);
    } finally {
      await fh.close();
    }
  }

  /**
   * Writes data at offset, extending the value where needed. A gap left by
   * a write beyond the end reads as zero bytes, as a sparse file does.
   */
  /**
   * Gives an object a value file of its own where the one it reads is
   * shared, so that writing to it does not change what another object
   * reads. The object that is written to moves aside: the file stays
   * where the other readers expect it.
   *
   * This is the copy of copy-on-write, and it is the only place bytes
   * are copied on account of a snapshot.
   */
  private async unshare(n: Node, keep: boolean): Promise<void> {
    const m = this.meta(n);
    if ((this.q.sharers.get(m.valueID) as { n: number }).n <= 1) return;
    const fresh = newObjectID();
    if (keep) {
      try {
        await copyFile(this.valuePath(m.valueID), this.valuePath(fresh));
      } catch {
        // What is shared has no value file, so neither has the copy.
      }
    }
    this.q.setValueID.run(fresh, n.id);
  }

  /**
   * The locks that make a read of an object atomic against a write of it:
   * "concurrent readers see the whole state before or after concurrent
   * updates, never a mixture". A value file is written in place and the row
   * that describes it is updated afterwards, so a reader that took the row
   * and the bytes at different moments could see the mimetype of one state
   * with the size of another (weedmi OPER-014). A writer holds the lock from
   * the first byte written to the row committed, and a reader holds it while
   * it takes the row and the bytes it describes.
   */
  private readonly locks = new Map<number, Promise<void>>();

  /**
   * The modification count of an object is the count of the operations
   * that changed it, not of the statements this server ran to perform one:
   * an update that writes metadata and a value runs two, and the count
   * moved by two before 0.71 (weedmi META-006). The lock brackets an
   * operation, so the count is normalized here.
   */
  private countOnce<T>(n: Node, out: T, before: number): T {
    const now = (this.q.meta.get(n.id) as { mcount?: number } | undefined)?.mcount;
    if (now !== undefined && now > before + 1) {
      this.db.exec(`UPDATE object SET mcount = ${before + 1} WHERE id = ${n.id}`);
    }
    return out;
  }

  async locked<T>(n: Node, fn: () => Promise<T>): Promise<T> {
    const held = this.locks.get(n.id);
    let release!: () => void;
    const mine = new Promise<void>((r) => { release = r; });
    this.locks.set(n.id, held === undefined ? mine : held.then(() => mine));
    if (held !== undefined) await held;
    const before = (this.q.meta.get(n.id) as { mcount?: number } | undefined)?.mcount ?? 0;
    try {
      return this.countOnce(n, await fn(), before);
    } finally {
      release();
      // The last waiter clears the entry, so the map does not grow.
      if (this.locks.get(n.id) === mine) this.locks.delete(n.id);
    }
  }

  /**
   * Writes bytes of a value. The caller holds the object's lock across the
   * whole update, metadata and value together, so this does not take it:
   * the lock is not re-entrant, and an update writes both.
   */
  async writeValue(n: Node, offset: number, data: Buffer): Promise<void> {
    // A partial write keeps what it does not overwrite.
    await this.unshare(n, true);
    const m = this.meta(n);
    if (m.isContainer) throw notContainer();
    // "a+" appends whatever offset is given, so positional writes need
    // "r+", with the file created where it does not yet exist.
    const fh = await this.openForWrite(m.valueID);
    try {
      await fh.write(data, 0, data.length, offset);
      if (this.immediateRedundancy?.(n) === true) await fh.sync();
    } finally {
      await fh.close();
    }
    const size = Math.max(m.size, offset + data.length);
    // The ranges of the value, with the one just written merged into them, so
    // that filling a gap joins the runs either side of it.
    const ranges = data.length === 0
      ? this.ranges(n)
      : Store.mergeRange(this.ranges(n), offset, offset + data.length - 1);
    this.q.setWritten.run(size, Store.contiguousOf(ranges), JSON.stringify(ranges), Date.now(), n.id);
    await this.rehash(n);
  }

  /**
   * Recomputes the hash of the value, where the cdmi_value_hash data
   * system metadata item of the object asks for one, and clears it
   * where it does not. Called wherever the value changes, so that the
   * cdmi_hash item reports the value the object holds now rather than
   * the one it held when the item was set.
   */
  async rehash(n: Node): Promise<void> {
    const m = this.meta(n);
    // The item that applies, which is the one the object carries or, where
    // it carries none, the one the nearest container object above it
    // carries: data system metadata is inherited. The binding supplies the
    // reader, the store not interpreting metadata itself. This read the
    // object's own item alone until 0.84, so an item set on a container
    // object hashed nothing it held (weedmi META-012).
    const wanted = m.metadata.cdmi_value_hash
      ?? this.effectiveHashItem?.(n);
    const algorithm = typeof wanted === "string"
      ? VALUE_HASHES[wanted.toUpperCase()]
      : undefined;
    if (algorithm === undefined) {
      if (m.hash !== null) this.setHash(n, null);
      return;
    }
    const value = await this.readValue(n);
    this.setHash(n, createHash(algorithm).update(value).digest("hex").toUpperCase());
  }

  /** Replaces the whole value. */
  async setValue(n: Node, data: Buffer): Promise<void> {
    // A complete replacement reads none of the old bytes, so the
    // object moves aside without copying anything.
    await this.unshare(n, false);
    const m = this.meta(n);
    if (m.isContainer) throw notContainer();
    const fh = await openFile(this.valuePath(m.valueID), "w");
    try {
      if (data.length > 0) await fh.write(data, 0, data.length, 0);
      // Committed before the operation completes, where the object asks for it.
      if (this.immediateRedundancy?.(n) === true) await fh.sync();
    } finally {
      await fh.close();
    }
    // A complete replacement leaves no gap: one run, or none for an empty value.
    const whole: [number, number][] = data.length > 0 ? [[0, data.length - 1]] : [];
    this.q.setWritten.run(data.length, data.length, JSON.stringify(whole), Date.now(), n.id);
    await this.rehash(n);
  }

  async truncateValue(n: Node, size: number): Promise<void> {
    const m = this.meta(n);
    if (m.isContainer) throw notContainer();
    const fh = await this.openForWrite(m.valueID);
    try {
      await fh.truncate(size);
    } finally {
      await fh.close();
    }
    // Truncating cannot leave more written than remains.
    // Truncation clips the ranges: a run beyond the new size is gone, and one
    // spanning it ends at the last byte that remains.
    const clipped: [number, number][] = [];
    for (const [a, b] of this.ranges(n)) {
      if (a > size - 1) continue;
      clipped.push([a, Math.min(b, size - 1)]);
    }
    this.q.setWritten.run(size, Store.contiguousOf(clipped), JSON.stringify(clipped), Date.now(), n.id);
    await this.rehash(n);
  }

  /**
   * The copy-up of the imports model: the value, the metadata and the ACL
   * are copied, and the copy is a new object with a new object ID. The
   * value file is written before the row that refers to it is committed,
   * so the copy is never presented incomplete.
   */
  async copyUp(src: Node, dstParent: Node, name: string): Promise<Node> {
    if (src.isContainer) throw notContainer();
    const m = this.meta(src);
    const ranges = this.ranges(src);
    const objectID = newObjectID();
    try {
      await copyFile(this.valuePath(m.valueID), this.valuePath(objectID));
    } catch (err: any) {
      if (err?.code !== "ENOENT") throw err; // no value file: an empty value
    }
    try {
      return this.tx(() => {
        const dst = this.create(dstParent, name, false, {
          objectID,
          mimetype: m.mimetype,
          vte: m.vte,
          metadata: m.metadata,
          owner: m.owner,
          acl: m.acl,
          // The rel field describes the object, so a copy carries it.
          rel: m.rel,
          extensions: m.extensions,
          // The imports and exports fields are never copied.
        });
        // The gaps of the value come with it, as they do in shareValue.
        // Setting the size alone left the copy reporting a contiguous range
        // of zero for a value that has no gap at all, which made its
        // valuerange field wrong.
        this.q.setWritten.run(m.size, m.contiguous, JSON.stringify(ranges), Date.now(), dst.id);
        return dst;
      });
    } catch (err) {
      await rm(this.valuePath(objectID), { force: true });
      throw err;
    }
  }

  private async openForWrite(objectID: string) {
    try {
      return await openFile(this.valuePath(objectID), "r+");
    } catch (err: any) {
      if (err?.code !== "ENOENT") throw err;
      return await openFile(this.valuePath(objectID), "w+");
    }
  }

  /**
   * Reads the sanitization method effective on an object, where the binding
   * has supplied a reader. The store does not interpret metadata itself; the
   * binding knows what an item inherits from the containers above it.
   */
  sanitizeMethod?: (n: Node) => string | undefined;

  /**
   * Whether an object asks for immediate redundancy, which the binding answers
   * from the cdmi_immediate_redundancy item that applies to it after inheritance.
   * The store does not interpret metadata, so it asks.
   *
   * "At least the number of copies indicated in cdmi_data_redundancy contain the
   * newly written value before the operation completes. This metadata is used to
   * make sure that multiple copies of the data are written to permanent storage so
   * that data are not lost." This store keeps one copy, so the undertaking is that
   * the one copy is on persistent storage before the write returns: the value file
   * is committed with fsync. Without it the write is in the page cache of the
   * operating system when the reply is sent, and a power loss takes it.
   */
  immediateRedundancy?: (n: Node) => boolean;

  /**
   * Reads the cdmi_value_hash item that applies to an object, inherited from
   * the container objects above it where the object carries none.
   */
  effectiveHashItem?: (n: Node) => string | undefined;

  /**
   * Deletes the value files of object IDs returned by removeTree. Where the
   * object that held one asked for a sanitization method, the file is
   * overwritten before it is unlinked, so "the data is unrecoverable after
   * an update or delete operation".
   */
  async collect(objectIDs: string[]): Promise<void> {
    for (const objectID of objectIDs) {
      const row = this.q.orphanOf.get(objectID) as { sanitize: string | null } | undefined;
      if (row?.sanitize) await this.sanitize(objectID, row.sanitize);
      await rm(this.valuePath(objectID), { force: true });
      this.q.dropOrphan.run(objectID);
    }
  }

  /**
   * Overwrites a value file so that what it held is not recoverable from
   * the blocks it occupied, then leaves it to be unlinked. One pass of
   * random octets is what the "overwrite" method names; a filesystem that
   * writes a new block rather than the one it was told (a copy-on-write or
   * log-structured filesystem, or a device that remaps a worn block) may
   * retain the earlier one, which is a property of the filesystem and not
   * of this server. NOTES-on-sanitization.md records that and says what a
   * deployment that requires more is to do.
   */
  private async sanitize(objectID: string, method: string): Promise<void> {
    if (method !== "overwrite") return;
    let fh;
    try {
      fh = await openFile(this.valuePath(objectID), "r+");
    } catch (err: any) {
      if (err?.code === "ENOENT") return;
      throw err;
    }
    try {
      const size = await this.valueFileSize(objectID);
      const chunk = 1 << 20;
      for (let at = 0; at < size; at += chunk) {
        const noise = randomBytes(Math.min(chunk, size - at));
        await fh.write(noise, 0, noise.length, at);
      }
      // The octets reach the device before the file is unlinked: an
      // overwrite left in a page cache that is never written is no
      // overwrite at all.
      await fh.sync();
    } finally {
      await fh.close();
    }
  }

  /** Deletes value files left behind by an interrupted operation. */
  async collectOrphans(): Promise<number> {
    const rows = this.q.orphans.all() as { object_id: string }[];
    await this.collect(rows.map((r) => r.object_id));
    return rows.length;
  }

  /** The size of the value file, for checking the recorded size. */
  async valueFileSize(objectID: string): Promise<number> {
    try {
      return (await stat(this.valuePath(objectID))).size;
    } catch (err: any) {
      if (err?.code === "ENOENT") return 0;
      throw err;
    }
  }

  // -------------------------------------------------------------------
  // Image imports

  /**
   * Records the image imports configured on a container object, replacing
   * whatever was recorded before. The paths are recorded rather than the
   * objects, so that an entry naming a source that does not yet exist
   * still takes effect once it does.
   */
  setImageSources(importer: Node,
    sources: { entry: number; path: string; writeEnabled: boolean; disabled: boolean }[]):
    void {
    this.q.clearImageSources.run(importer.id);
    for (const s of sources) {
      this.q.addImageSource.run(importer.id, s.entry, s.path,
        s.writeEnabled ? 1 : 0, s.disabled ? 1 : 0);
    }
  }

  /** The paths every image import names, whether or not it is disabled. */
  imageSourcePaths(): string[] {
    return (this.q.imageSourcePaths.all() as { source_path: string }[])
      .map((r) => r.source_path);
  }

  /** Records whether a container object carries an exports field. */
  setExported(node: Node, exported: boolean): void {
    if (exported) {
      this.q.setExported.run(node.id);
    } else {
      this.q.clearExported.run(node.id);
    }
  }

  /** Every container object that carries an exports field. */
  /**
   * Every object carrying an exports field. An MQTT export is placed
   * on a queue object, so the kind of each is read rather than
   * assumed: an entry reported as a container object that is a queue
   * object resolves to the wrong path.
   */
  /**
   * The public key of the binding key of a scope, as this server retains it:
   * "A CDMI server shall retain the public key of the binding key of each
   * scope it uses, so that it verifies the binding against a key it held
   * before" (the Scope binding subclause).
   */
  bindingKeyHeld(label: string, scope: string): string | undefined {
    const row = this.q.kmsMeta.get(`binding:${label}:${scope}`) as { value: string } | undefined;
    return row?.value;
  }

  /** Retains that public key, or replaces the one held. */
  retainBindingKey(label: string, scope: string, publicKey: string): void {
    this.q.putKmsMeta.run(`binding:${label}:${scope}`, publicKey);
    this.q.setKmsMeta.run(publicKey, `binding:${label}:${scope}`);
  }

  /** Each scope this server holds a claim on, as the label of its key management server and the scope. */
  bindingKeys(): { label: string; scope: string }[] {
    return (this.q.bindingKeys.all() as { key: string }[]).map(({ key }) => {
      const rest = key.slice("binding:".length);
      const at = rest.indexOf(":");
      return { label: rest.slice(0, at), scope: rest.slice(at + 1) };
    });
  }

  /** Forgets the claim on a scope, once it is released. */
  forgetBindingKey(label: string, scope: string): void {
    this.q.forgetKmsMeta.run(`binding:${label}:${scope}`);
  }

  /** Records that an object at a version was assembled from parts. */
  setMultipart(objectID: string, version: number, parts: number): void {
    this.q.setMultipart.run(objectID, version, parts);
  }

  /** The number of parts an object at a version was assembled from, if it was. */
  multipartParts(objectID: string, version: number): number | undefined {
    const row = this.q.multipartParts.get(objectID, version) as { parts: number } | undefined;
    return row?.parts;
  }

  exportedContainers(): Node[] {
    return (this.q.exportedContainers.all() as { container: number }[])
      .map((r) => {
        const row = this.q.meta.get(r.container) as
          { is_container: number } | undefined;
        return { id: r.container, isContainer: row?.is_container === 1 };
      });
  }

  /** The image imports that interpret the value of the object at a path. */
  imageSourcesOf(path: string): ImageSource[] {
    return (this.q.imageSourcesOf.all(path) as {
      importer: number; entry: number; write_enabled: number; disabled: number;
    }[]).map((r) => ({
      importer: r.importer,
      entry: r.entry,
      writeEnabled: r.write_enabled === 1,
      disabled: r.disabled === 1,
    }));
  }

  // -------------------------------------------------------------------
  // NFS file handles

  /**
   * The persistent handle of a name within a container object, issued on
   * first use. A handle names a position rather than an object, so it stays
   * valid when a copy-up changes which object the name resolves to.
   */
  handle(parent: Node, name: string): Buffer {
    const row = this.q.getHandle.get(parent.id, name) as { id: Buffer } | undefined;
    if (row) return Buffer.from(row.id);
    const id = Buffer.alloc(16);
    id.writeUInt32BE(parent.id >>> 0, 0);
    id.writeUInt32BE((Date.now() / 1000) >>> 0, 4);
    id.set(Buffer.from(randomUUID().replaceAll("-", "").slice(0, 16), "hex"), 8);
    this.q.putHandle.run(id, parent.id, name);
    return id;
  }

  rootHandle(): Buffer {
    return this.handle(this.root(), "");
  }

  resolveHandle(id: Buffer): { parent: Node; name: string } {
    const row = this.q.resolveHandle.get(id) as
      { parent: number; name: string } | undefined;
    if (!row) throw noObject("that file handle");
    return { parent: { id: row.parent, isContainer: true }, name: row.name };
  }
}
