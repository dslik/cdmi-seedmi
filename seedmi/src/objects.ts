// An object presented by seedmi is held either by the store or by a file
// system inside the value of a data object. The layering engine, the
// protocol binding and the exports work in terms of the references defined
// here, so that neither has to know which it has.
//
// The two differ in what the draft says about them. An object presented
// through an image import has no object ID, since a file system image
// holds no identifier stable for the lifetime of an object; its metadata
// is limited to the items the file system actually provides; it carries no
// access control list of its own, the list of the importing container
// object governing every operation on it; and a file that is not a regular
// file or a directory is not presented at all.

import type { ACE, Meta, Node, Store } from "./store.ts";
import { ATTR_DIRECTORY, ATTR_VOLUME_ID, type DirEntry, type FAT } from "./fat.ts";
import { MT_CONTAINER, type RemoteRep, type RemoteSource } from "./remote.ts";
import type { FileSource, NfsEntry } from "./nfs-import.ts";
import { NF4DIR } from "./nfs.ts";

/**
 * A container object: one the store holds, a directory of an imported
 * file system, or a container object of another CDMI server.
 */
export type DirRef =
  | { kind: "store"; node: Node }
  | { kind: "image"; fs: FAT; cluster: number; entry?: DirEntry }
  | { kind: "remote"; src: RemoteSource; path: string; rep?: RemoteRep }
  // An imported file system namespace: NFS or SMB, both of which
  // present names, sizes and times and no object identifier.
  | { kind: "fs"; src: FileSource; path: string; entry?: NfsEntry };

/** Any object, held by any of the three. */
export type ObjRef =
  | { kind: "store"; node: Node }
  | { kind: "image"; fs: FAT; dir: number; entry: DirEntry }
  | { kind: "remote"; src: RemoteSource; path: string; rep: RemoteRep }
  | { kind: "fs"; src: FileSource; path: string; entry: NfsEntry };

export const isImage = (r: DirRef | ObjRef): boolean => r.kind === "image";

/** The object a container reference names, as an object reference. */
export function refOfDir(d: DirRef): ObjRef {
  switch (d.kind) {
    case "store": return { kind: "store", node: d.node };
    case "image": return { kind: "image", fs: d.fs, dir: d.cluster, entry: d.entry! };
    case "remote": return { kind: "remote", src: d.src, path: d.path, rep: d.rep! };
    default: return { kind: "fs", src: d.src, path: d.path, entry: d.entry! };
  }
}

/** The store node of a reference, where it has one. */
export function nodeOf(r: DirRef | ObjRef): Node | undefined {
  return r.kind === "store" ? r.node : undefined;
}

/** Whether the two references name the same object. */
export function sameRef(a: ObjRef, b: ObjRef): boolean {
  if (a.kind === "store" && b.kind === "store") return a.node.id === b.node.id;
  if (a.kind === "image" && b.kind === "image") {
    return a.fs === b.fs && a.dir === b.dir && a.entry.slot === b.entry.slot;
  }
  if (a.kind === "remote" && b.kind === "remote") {
    return a.src === b.src && a.path === b.path;
  }
  if (a.kind === "fs" && b.kind === "fs") {
    return a.src === b.src && a.path === b.path;
  }
  return false;
}

/**
 * What the representation of an object reports, whichever holds it. The
 * fields an image object does not have are undefined rather than empty, so
 * that a caller omits them rather than reporting a value it did not obtain.
 */
export interface ObjectView {
  isContainer: boolean;
  /** The extension fields stored with the object; none for an object an import presents. */
  extensions?: Record<string, unknown>;
  /** Absent for an object presented through an image import. */
  objectID?: string;
  size: number;
  mimetype?: string;
  vte?: string;
  /** The user metadata, which an image object never has. */
  userMetadata: Record<string, unknown>;
  /** The storage system times, in milliseconds, where they are provided. */
  ctime?: number;
  mtime?: number;
  atime?: number;
  /** Absent for an image object: a file system names no principal. */
  owner?: string;
  /** The hash of the value, where the client asked for one. */
  hash?: string;
  /** The group of GROUP@, where the holder associates one. */
  group?: string;
  /**
   * The length of the value written from the beginning without a gap,
   * which is what the valuerange field reports. It is the size where
   * the holder records no gaps.
   */
  contiguous?: number;
  /** The accesses and the changes counted, where the holder counts them. */
  acount?: number;
  mcount?: number;
  /** Absent for an image object: the importing container's list governs. */
  acl?: ACE[] | null;
  /** A validator that changes whenever the object changes. */
  version: number;
}

/** Reads the fields of an object, whichever holds it. */
export function viewOf(store: Store, ref: ObjRef): ObjectView {
  if (ref.kind === "store") {
    const m: Meta = store.meta(ref.node);
    return {
      isContainer: ref.node.isContainer,
      ...(m.extensions === undefined ? {} : { extensions: m.extensions }),
      objectID: m.objectID,
      size: m.size,
      mimetype: m.mimetype,
      vte: m.vte,
      userMetadata: m.metadata,
      ctime: m.ctime,
      mtime: m.mtime,
      atime: m.atime,
      owner: m.owner,
      hash: m.hash ?? undefined,
      contiguous: m.contiguous,
      group: m.group === "" ? undefined : m.group,
      acount: m.acount,
      mcount: m.mcount,
      acl: m.acl,
      version: m.version,
    };
  }
  if (ref.kind === "remote") return viewOfRemote(ref.rep);
  if (ref.kind === "fs") return viewOfNfs(ref.entry);
  const e = ref.entry;
  return {
    isContainer: (e.attr & ATTR_DIRECTORY) !== 0,
    // No object ID: the draft requires the field to be absent.
    size: (e.attr & ATTR_DIRECTORY) !== 0 ? 0 : e.size,
    // The file system records no media type, so none is reported.
    userMetadata: {},
    ctime: e.ctime.getTime(),
    mtime: e.mtime.getTime(),
    atime: e.atime.getTime(),
    // Neither an owner nor a list: the ownership a file system records
    // names identities that are not principals of this CDMI server.
    version: e.mtime.getTime() + e.size,
  };
}

/**
 * The fields of an object another CDMI server presents. Its object ID is
 * its own, and is reported where the import preserves it; its metadata
 * is the metadata that server reports, less the items that belong to the
 * object as that server holds it.
 */
function viewOfRemote(rep: RemoteRep): ObjectView {
  const md = rep.metadata ?? {};
  const time = (v: unknown): number | undefined => {
    if (typeof v !== "string") return undefined;
    const t = Date.parse(v);
    return Number.isNaN(t) ? undefined : t;
  };
  const user: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(md)) {
    if (!k.startsWith("cdmi_")) user[k] = v;
  }
  // The size the source states, or, where it states none, the value's length (remote.ts).
  const size = typeof md.cdmi_size === "string" ? Number(md.cdmi_size) : (rep.derivedSize ?? 0);
  const mtime = time(md.cdmi_mtime);
  return {
    isContainer: rep.objectType === MT_CONTAINER,
    objectID: rep.objectID,
    size: Number.isFinite(size) ? size : 0,
    mimetype: rep.mimetype,
    vte: rep.valuetransferencoding,
    userMetadata: user,
    ctime: time(md.cdmi_ctime),
    mtime,
    atime: time(md.cdmi_atime),
    owner: typeof md.cdmi_owner === "string" ? md.cdmi_owner : undefined,
    group: typeof md.cdmi_group === "string" ? md.cdmi_group : undefined,
    acount: typeof md.cdmi_acount === "string" ? Number(md.cdmi_acount) : undefined,
    mcount: typeof md.cdmi_mcount === "string" ? Number(md.cdmi_mcount) : undefined,
    // The list the source reports. It does not govern a request to this server
    // — in delegated identity mode the source enforces it, and in service
    // identity mode the importing object's list governs — but it is what is
    // *reported* for the object where the import is delegated: "the access
    // control lists reported for the object shall be those the import source
    // reports". Until 0.106 this dropped it, on the ground that it governs
    // nothing here, and reported no list at all for an imported object.
    acl: Array.isArray(md.cdmi_acl) ? md.cdmi_acl as ACE[] : undefined,
    version: (mtime ?? 0) + size,
  };
}

/**
 * The fields of an object of an NFS import. The file handle the source
 * assigns is not required to persist for the life of the file, so no
 * object ID is reported and the object is addressed by path alone.
 */
function viewOfNfs(e: NfsEntry): ObjectView {
  const isContainer = e.type === NF4DIR;
  return {
    isContainer,
    size: isContainer ? 0 : e.size,
    // The NFS protocol carries no media type; the CDMI server assigns
    // one, deriving it from the name where it can.
    userMetadata: e.metadata ?? {},
    ctime: e.ctime,
    mtime: e.mtime,
    atime: e.atime,
    owner: e.owner,
    version: (e.mtime ?? 0) + e.size,
  };
}

/**
 * The size an object is reported as having through a protocol export.
 * Where the object states an assigned size, that is what an export
 * reports; the CDMI server is not required to reserve the space, so
 * the value may be greater than the storage the object consumes.
 */
export function assignedSizeOf(v: ObjectView,
  metadata: Record<string, unknown> | undefined): number {
  const assigned = (metadata ?? v.userMetadata)?.cdmi_assignedsize;
  if (typeof assigned !== "string" || !/^[1-9][0-9]*$/.test(assigned)) return v.size;
  return Number(assigned);
}

/** Reads the value of a data object, whichever holds it. */
export async function readValueOf(store: Store, ref: ObjRef, offset = 0,
  length?: number): Promise<Buffer> {
  if (ref.kind === "store") return store.readValue(ref.node, offset, length);
  if (ref.kind === "remote") {
    const size = viewOfRemote(ref.rep).size;
    const want = Math.max(Math.min(length ?? size - offset, size - offset), 0);
    return ref.src.value(ref.path, offset, want);
  }
  if (ref.kind === "fs") {
    const size = ref.entry.size;
    const want = Math.max(Math.min(length ?? size - offset, size - offset), 0);
    return ref.src.value(ref.path, offset, want);
  }
  return ref.fs.readFile(ref.entry, offset, length);
}

/**
 * Whether a file system entry is presented at all. A directory and a
 * regular file are; the volume label, and any name a CDMI object may not
 * have, are not.
 */
export function presentableEntry(e: DirEntry): boolean {
  if ((e.attr & ATTR_VOLUME_ID) !== 0) return false;
  if (e.name === "." || e.name === "..") return false;
  return true;
}
