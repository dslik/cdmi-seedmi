/**
 * What an SMB export presents: the objects of a container object, seen
 * as the files and directories of a share.
 *
 * This is the seam between the protocol and the CDMI store, and it is
 * the place where the clause "an SMB export is an export that mediates
 * each operation" is carried out: every resolution here authorises
 * against the access control list of the object, using the principal
 * the session authenticated as.
 */

import type { Store, Node, Meta } from "./store.ts";
import { delegatedMask } from "./dac-context.ts";
import { granted, M, type Principal } from "./acl.ts";
import { PrincipalMap } from "./smb-security.ts";
import { EA_MAXNAME, EA_MAXSIZE, type Ea } from "./smb-info.ts";
import type { ACE } from "./store.ts";
import { underRestriction } from "./retention.ts";
import { fileTime, NT } from "./smb-wire.ts";

/** A status this layer answers with, which the server returns unchanged. */
export class SmbStatus extends Error {
  readonly status: number;

  constructor(status: number) {
    super(`0x${(status >>> 0).toString(16)}`);
    this.status = status;
  }
}

/** The file attributes of [MS-FSCC] section 2.6 that this export uses. */
export const FILE_ATTRIBUTE = {
  READONLY: 0x00000001,
  DIRECTORY: 0x00000010,
  ARCHIVE: 0x00000020,
  NORMAL: 0x00000080,
  REPARSE_POINT: 0x00000400,
} as const;

/** An object as an SMB client sees it. */
export interface Entry {
  name: string;
  node?: Node;
  meta?: Meta;
  /** Where the name is a reference, the URI it names. */
  reference?: string;
  isContainer: boolean;
  size: number;
  attributes: number;
  created: bigint;
  accessed: bigint;
  written: bigint;
  changed: bigint;
  /** The identifier a directory listing reports, from the object ID. */
  fileId: bigint;
}

/** The container object a share presents, and how to reach it. */
export interface Mount {
  store: Store;
  /** The namespace path of the exported container object. */
  path: string;
  /** Whether the share admits writes; a read-only share refuses them. */
  readOnly: boolean;
  /**
   * Whether the user metadata of an object is presented as extended
   * attributes, which the cdmi_export_smb_ea capability reports.
   */
  extendedAttributes?: boolean;
  /** The usermap of the export entry, if any. */
  usermap?: string[][];
  /** The groupmap of the export entry, if any. */
  groupmap?: string[][];
}

const TIME = (m: Meta, key: string, fallback: number): bigint => {
  const v = m.metadata[key];
  const ms = typeof v === "string" ? Date.parse(v) : NaN;
  return fileTime(Number.isNaN(ms) ? fallback : ms);
};

/**
 * The size of an object: the length of the value a data object holds,
 * which is the number cdmi_size reports, and zero for a container
 * object, which has no value.
 */
const sizeOf = (m: Meta): number => m.size;

/** Whether a path names something within the exported container object. */
export function within(mount: Mount, path: string): boolean {
  const base = mount.path.endsWith("/") ? mount.path : `${mount.path}/`;
  return path === mount.path || path.startsWith(base);
}

/**
 * The elements of an SMB path. A path is separated by a reverse
 * solidus, an empty path names the root of the share, and "." and ".."
 * are resolved here rather than passed to the store.
 */
export function elements(path: string): string[] | undefined {
  const parts = path.split("\\").filter((p) => p !== "" && p !== ".");
  const out: string[] = [];
  for (const p of parts) {
    if (p === "..") {
      // A path that climbs out of the share is not a path of the share.
      if (out.length === 0) return undefined;
      out.pop();
      continue;
    }
    // A name of a CDMI object holds no solidus, and a name an SMB
    // client sends holds no reverse solidus, having been split on it.
    if (p.includes("/")) return undefined;
    out.push(p);
  }
  return out;
}

export class SmbFs {
  private readonly mount: Mount;
  private readonly principal: Principal;

  constructor(mount: Mount, principal: Principal) {
    this.mount = mount;
    this.principal = principal;
  }

  get readOnly(): boolean {
    return this.mount.readOnly;
  }

  /** The store this share presents, for a decision taken by the server. */
  get store(): Store {
    return this.mount.store;
  }

  /** The principal this share is served to. */
  get who(): Principal {
    return this.principal;
  }

  /** The container object the share presents. */
  root(): Node {
    let node = this.mount.store.root();
    for (const seg of this.mount.path.split("/")) {
      if (seg === "") continue;
      // A container object is held under a name ending in a solidus,
      // and a namespace path may be written with or without it.
      const next = this.mount.store.tryLookup(node, `${seg}/`) ??
        this.mount.store.tryLookup(node, seg);
      if (next === undefined) {
        // The exported container object has been deleted while the
        // share was connected: the share no longer names anything.
        throw new SmbStatus(NT.NETWORK_NAME_DELETED);
      }
      node = next;
    }
    return node;
  }

  /**
   * Resolves a path within the share. The object addressed is
   * authorised where it is used; a container object on the way is not,
   * because the clause states a CDMI server does not enforce
   * traversal checking.
   */
  resolve(path: string): Entry {
    const parts = elements(path);
    if (parts === undefined) throw new SmbStatus(NT.OBJECT_NAME_NOT_FOUND);
    let node = this.root();
    let meta = this.mount.store.meta(node);
    for (const [i, name] of parts.entries()) {
      if (!node.isContainer) throw new SmbStatus(NT.OBJECT_NAME_NOT_FOUND);
      // No traverse check: the clause states that FILE_TRAVERSE is
      // granted where TRAVERSE_CONTAINER is, and that a CDMI server
      // does not enforce it, so a container object on the way is
      // passed through whether or not the bit is held.
      // A container object is held under a name that ends with a
      // solidus, and an SMB path carries no such mark, so both forms
      // are tried. A data object and a container object of the same
      // name cannot both exist, so at most one answers.
      const child = this.mount.store.tryLookup(node, name) ??
        this.mount.store.tryLookup(node, `${name}/`);
      if (child === undefined) {
        // A name the container object does not hold, which may be a
        // reference: a reference is a name and not an object.
        const held = this.referenceAt(node, name);
        if (held !== undefined && i === parts.length - 1) return held;
        throw new SmbStatus(NT.OBJECT_NAME_NOT_FOUND);
      }
      node = child;
      meta = this.mount.store.meta(node);
      if (meta.reference !== undefined && i < parts.length - 1) {
        // A reference is not resolved by the server: a path that
        // continues through one names nothing here.
        throw new SmbStatus(NT.OBJECT_NAME_NOT_FOUND);
      }
    }
    return this.entry(parts[parts.length - 1] ?? "", node, meta);
  }

  /** The children of a container object, in the order the store holds them. */
  list(node: Node): Entry[] {
    const meta = this.mount.store.meta(node);
    this.require(node, meta, M.LIST_CONTAINER);
    const out: Entry[] = [];
    for (const child of this.mount.store.children(node)) {
      const name = child.name.replace(/\/$/, "");
      // A reserved child of a container object is a CDMI construct and
      // is not a file of the share. The prefix is tested here and not the
      // reserved names table, so that the four export types agree with one
      // another and with the HTTP export clause, which writes the prefix into
      // a requirement of its own. NOTES-on-reserved-names.md records that an
      // object the binding now permits under an unreserved cdmi_ name is
      // therefore not presented through an export of its container.
      if (name.startsWith("cdmi_")) continue;
      const n = this.mount.store.tryLookup(node, child.name);
      if (n === undefined) continue;
      const m = this.mount.store.meta(n);
      out.push(this.entry(name, n, m));
    }
    return out;
  }

  /** Reads a range of the value of a data object. */
  async read(node: Node, offset: number, length: number): Promise<Buffer> {
    const meta = this.mount.store.meta(node);
    this.require(node, meta, M.READ_OBJECT);
    if (node.isContainer) throw new SmbStatus(NT.INVALID_DEVICE_REQUEST);
    return this.mount.store.readValue(node, offset, length);
  }

  /**
   * Creates a data object or a container object within the share. The
   * container object that will hold it is authorised for ADD_OBJECT or
   * ADD_SUBCONTAINER, which are the bits of the mask that govern
   * making a name.
   */
  create(path: string, isContainer: boolean): Entry {
    this.writable();
    const parts = elements(path);
    if (parts === undefined || parts.length === 0) {
      throw new SmbStatus(NT.OBJECT_NAME_NOT_FOUND);
    }
    const name = parts[parts.length - 1];
    const parent = this.container(parts.slice(0, -1));
    const parentMeta = this.mount.store.meta(parent);
    this.require(parent, parentMeta,
      isContainer ? M.ADD_SUBCONTAINER : M.ADD_OBJECT);
    if (this.mount.store.tryLookup(parent, name) !== undefined ||
      this.mount.store.tryLookup(parent, `${name}/`) !== undefined) {
      throw new SmbStatus(NT.OBJECT_NAME_COLLISION);
    }
    // The object is owned by the principal that made it, and holds the
    // list of the container object it is made in, which is what the
    // protocol binding does for a create.
    const made = isContainer
      ? this.mount.store.createContainer(parent, `${name}/`,
        { owner: this.principal.name, acl: parentMeta.acl })
      : this.mount.store.createData(parent, name,
        { owner: this.principal.name, acl: parentMeta.acl });
    return this.entry(name, made, this.mount.store.meta(made));
  }

  /**
   * The substitute name that presents a reference, and whether it is
   * relative. Where the destination names an object within the
   * exported container object, the name is the path of that object
   * relative to the container object holding the reference; in every
   * other case the destination is carried unchanged.
   */
  substituteName(entry: Entry): { substitute: string; relative: boolean } {
    const destination = entry.reference ?? "";
    const base = this.mount.path.endsWith("/") ? this.mount.path : `${this.mount.path}/`;
    if (!destination.startsWith(base)) {
      // Another CDMI server, or an object of this one outside the
      // exported container object: unchanged, and not relative.
      return { substitute: destination, relative: false };
    }
    // The path of the destination relative to the container object
    // that holds the reference, which is the parent of the entry.
    const from = entry.meta?.parent === null || entry.meta === undefined
      ? base
      : `${this.mount.store.pathOf({ id: entry.meta.parent!, isContainer: true })}`;
    const target = destination.slice(base.length).replace(/\/$/, "");
    const here = from.startsWith(base) ? from.slice(base.length) : "";
    const up = here.split("/").filter((p) => p !== "").map(() => "..");
    const parts = [...up, ...target.split("/").filter((p) => p !== "")];
    return { substitute: parts.join("\\"), relative: true };
  }

  /**
   * The destination of a reference, from the substitute name of a
   * reparse point, by the inverse of the rules above. Undefined where
   * the name is neither a relative path within the exported container
   * object nor an absolute URI.
   */
  destinationOf(substitute: string, holder: string[]): string | undefined {
    // A drive letter is tested first, because it has the shape of a
    // URI scheme of one character and is not one.
    if (/^[A-Za-z]:/.test(substitute) || substitute.startsWith("\\")) return undefined;
    // A scheme is at least two characters, by RFC 3986 practice.
    if (/^[a-z][a-z0-9+.-]+:/i.test(substitute)) return substitute;
    const parts = [...holder];
    for (const element of substitute.split(/[\\/]/)) {
      if (element === "" || element === ".") continue;
      if (element === "..") {
        // A relative path that would resolve outside the exported
        // container object is refused rather than clamped.
        if (parts.length === 0) return undefined;
        parts.pop();
        continue;
      }
      parts.push(element);
    }
    const base = this.mount.path.endsWith("/") ? this.mount.path : `${this.mount.path}/`;
    return `${base}${parts.join("/")}`;
  }

  /** Creates a reference within the share. */
  createReference(path: string, destination: string): Entry {
    this.writable();
    const parts = elements(path);
    if (parts === undefined || parts.length === 0) {
      throw new SmbStatus(NT.OBJECT_NAME_NOT_FOUND);
    }
    const name = parts[parts.length - 1];
    const parent = this.container(parts.slice(0, -1));
    const parentMeta = this.mount.store.meta(parent);
    this.require(parent, parentMeta, M.ADD_OBJECT);
    const made = this.mount.store.createReference(parent, name, destination,
      { owner: this.principal.name, acl: parentMeta.acl });
    return this.entry(name, made, this.mount.store.meta(made));
  }

  /** The elements of the path of a container object within the share. */
  holderOf(path: string): string[] {
    return (elements(path) ?? []).slice(0, -1);
  }

  /** Writes a range of the value of a data object. */
  async write(node: Node, offset: number, data: Buffer): Promise<void> {
    this.writable();
    const meta = this.mount.store.meta(node);
    if (node.isContainer) throw new SmbStatus(NT.INVALID_DEVICE_REQUEST);
    // A write at the end of the value appends, and a write within it
    // replaces; the two bits govern the two, and a client that holds
    // only one of them does only one of them.
    const appending = offset >= meta.size;
    this.require(node, meta, appending ? M.APPEND_DATA : M.WRITE_OBJECT);
    this.unrestricted(meta);
    await this.mount.store.writeValue(node, offset, data);
  }

  /** Sets the length of the value of a data object. */
  async truncate(node: Node, size: number): Promise<void> {
    this.writable();
    const meta = this.mount.store.meta(node);
    if (node.isContainer) throw new SmbStatus(NT.INVALID_DEVICE_REQUEST);
    this.require(node, meta, M.WRITE_OBJECT);
    this.unrestricted(meta);
    await this.mount.store.truncateValue(node, size);
  }

  /** Removes an object from the share. */
  remove(node: Node, meta: Meta): void {
    this.writable();
    if (meta.parent === null) throw new SmbStatus(NT.ACCESS_DENIED);
    const parent = { id: meta.parent, isContainer: true };
    const parentMeta = this.mount.store.meta(parent);
    // Either the object grants DELETE, or the container object holding
    // it grants the bit that governs removing a name from it.
    const bit = node.isContainer ? M.DELETE_SUBCONTAINER : M.DELETE_OBJECT;
    if (!this.allows(node, meta, M.DELETE) &&
      !this.allows(parent, parentMeta, bit)) {
      throw new SmbStatus(NT.ACCESS_DENIED);
    }
    if (node.isContainer && this.mount.store.childCount(node) > 0) {
      throw new SmbStatus(NT.DIRECTORY_NOT_EMPTY);
    }
    this.unrestricted(meta);
    this.mount.store.removeTree(node);
  }

  /** Moves an object to another name within the share. */
  rename(node: Node, meta: Meta, to: string, replace: boolean): void {
    this.writable();
    const parts = elements(to);
    if (parts === undefined || parts.length === 0) {
      throw new SmbStatus(NT.OBJECT_NAME_NOT_FOUND);
    }
    const name = parts[parts.length - 1];
    const parent = this.container(parts.slice(0, -1));
    const parentMeta = this.mount.store.meta(parent);
    this.require(parent, parentMeta,
      node.isContainer ? M.ADD_SUBCONTAINER : M.ADD_OBJECT);
    if (meta.parent === null) throw new SmbStatus(NT.ACCESS_DENIED);
    const from = { id: meta.parent, isContainer: true };
    this.require(from, this.mount.store.meta(from),
      node.isContainer ? M.DELETE_SUBCONTAINER : M.DELETE_OBJECT);

    // A rename is neither a delete nor a create, and the retention
    // clause treats it as neither; it changes the object, so it is
    // refused for one under retention. See Q14.
    this.unrestricted(meta);
    const held = this.mount.store.tryLookup(parent, name) ??
      this.mount.store.tryLookup(parent, `${name}/`);
    if (held !== undefined) {
      if (!replace) throw new SmbStatus(NT.OBJECT_NAME_COLLISION);
      const heldMeta = this.mount.store.meta(held);
      this.remove(held, heldMeta);
    }
    this.mount.store.rename(node, parent, node.isContainer ? `${name}/` : name);
  }

  /** The container object a sequence of elements names. */
  private container(parts: string[]): Node {
    let node = this.root();
    for (const name of parts) {
      const next = this.mount.store.tryLookup(node, `${name}/`) ??
        this.mount.store.tryLookup(node, name);
      if (next === undefined) throw new SmbStatus(NT.OBJECT_PATH_NOT_FOUND);
      if (!next.isContainer) throw new SmbStatus(NT.NOT_A_DIRECTORY);
      node = next;
    }
    return node;
  }

  /**
   * Refuses a change to an object under retention or under hold. The
   * retention rules are written about the object, so they hold for a
   * request that arrives through an export as for one that arrives
   * through the protocol binding — which the exports model of revision 365
   * now states, closing the gap NOTES-on-smb.md Q14 recorded against
   * earlier revisions, where this reading was the implementer's own.
   */
  private unrestricted(meta: Meta): void {
    if (underRestriction(meta.metadata)) throw new SmbStatus(NT.ACCESS_DENIED);
  }

  /** Refuses where the share admits this client read-only. */
  private writable(): void {
    // Share level access is evaluated before the access control list
    // of the object and does not replace it, so a read-only share
    // refuses whatever the list of the object says.
    if (this.mount.readOnly) throw new SmbStatus(NT.MEDIA_WRITE_PROTECTED);
  }

  /**
   * Something stable that belongs to this export, from which the
   * identifier authority of a security identifier is derived: the
   * object ID of the exported container object, which survives a
   * restart and differs between exports.
   */
  authority(): string {
    try {
      return this.mount.store.meta(this.root()).objectID;
    } catch {
      return this.mount.path;
    }
  }

  /**
   * The mapping between a name of this document and a name of the
   * identity domain of the SMB server, from the export entry.
   */
  principalMap(): PrincipalMap {
    return new PrincipalMap([
      ...(this.mount.usermap ?? []),
      ...(this.mount.groupmap ?? []),
    ]);
  }

  /**
   * Replaces the access control list of an object, and its owner and
   * group where the descriptor named them.
   */
  setAcl(node: Node, meta: Meta, acl: ACE[], owner?: string, group?: string): void {
    this.writable();
    this.require(node, meta, M.WRITE_ACL);
    if (owner !== undefined && owner !== meta.owner) {
      // Changing the owner is the operation WRITE_OWNER governs, and
      // is not granted by WRITE_ACL.
      this.require(node, meta, M.WRITE_OWNER);
    }
    if (group !== undefined && group !== meta.group) {
      this.require(node, meta, M.WRITE_OWNER);
    }
    this.unrestricted(meta);
    this.mount.store.setMeta(node, {
      ...meta,
      acl,
      owner: owner ?? meta.owner,
      group: group ?? meta.group,
    });
  }

  /**
   * The user metadata of an object, as extended attributes.
   *
   * An item whose value is not a JSON string has no encoding as one
   * and is not presented; nor is an item whose name or value exceeds
   * what the exported protocol carries, which is not truncated; nor
   * is one whose name is reserved by this document.
   */
  extendedAttributes(meta: Meta): Ea[] {
    if (this.mount.extendedAttributes !== true) return [];
    const out: Ea[] = [];
    for (const [name, value] of Object.entries(meta.metadata ?? {})) {
      if (name.startsWith("cdmi_")) continue;
      if (typeof value !== "string") continue;
      const encoded = Buffer.from(value, "utf8");
      if (Buffer.byteLength(name, "ascii") > EA_MAXNAME) continue;
      if (encoded.length > EA_MAXSIZE) continue;
      out.push({ name, value: encoded });
    }
    return out;
  }

  /**
   * Applies extended attributes written through the export to the user
   * metadata of an object. An attribute whose value is empty removes
   * the item, and one whose name is reserved by this document changes
   * no item: such a name may be written and is not presented through
   * the interface this document defines.
   */
  setExtendedAttributes(node: Node, meta: Meta, eas: Ea[]): void {
    if (this.mount.extendedAttributes !== true) {
      throw new SmbStatus(NT.EAS_NOT_SUPPORTED);
    }
    this.writable();
    this.require(node, meta, M.WRITE_METADATA);
    this.unrestricted(meta);
    const metadata = { ...(meta.metadata ?? {}) };
    for (const ea of eas) {
      if (ea.name.startsWith("cdmi_")) continue;
      if (ea.value.length === 0) {
        delete metadata[ea.name];
        continue;
      }
      if (Buffer.byteLength(ea.name, "ascii") > EA_MAXNAME ||
        ea.value.length > EA_MAXSIZE) {
        throw new SmbStatus(NT.EA_TOO_LARGE);
      }
      metadata[ea.name] = ea.value.toString("utf8");
    }
    this.mount.store.setMeta(node, { ...meta, metadata });
  }

  /** Whether the principal is granted a mask over an object. */
  allows(node: Node, meta: Meta, wanted: number): boolean {
    const delegated = delegatedMask(meta.objectID);
    if (delegated !== undefined) return (delegated & wanted) === wanted;
    return granted(meta.acl, this.principal, wanted, {
      owner: meta.owner,
      group: meta.group,
      isContainer: node.isContainer,
      isRoot: meta.parent === null,
    });
  }

  /** The mask the principal is granted, for a maximal access request. */
  maximal(node: Node, meta: Meta): number {
    let mask = 0;
    // Every bit of the access mask an SMB client can hold; the
    // retention bits are excluded, since a client of an SMB export
    // neither requests nor is granted them.
    const bits = [
      M.READ_OBJECT, M.WRITE_OBJECT, M.APPEND_DATA, M.READ_METADATA,
      M.WRITE_METADATA, M.EXECUTE, M.DELETE_OBJECT, M.READ_ATTRIBUTES,
      M.WRITE_ATTRIBUTES, M.DELETE, M.READ_ACL, M.WRITE_ACL, M.WRITE_OWNER,
      M.SYNCHRONIZE,
    ];
    for (const bit of bits) if (this.allows(node, meta, bit)) mask |= bit;
    return mask >>> 0;
  }

  private require(node: Node, meta: Meta, wanted: number): void {
    if (!this.allows(node, meta, wanted)) throw new SmbStatus(NT.ACCESS_DENIED);
  }

  /** A reference held under a name of a container object. */
  private referenceAt(parent: Node, name: string): Entry | undefined {
    for (const child of this.mount.store.children(parent)) {
      if (child.name.replace(/\/$/, "") !== name) continue;
      const n = this.mount.store.tryLookup(parent, child.name);
      if (n === undefined) continue;
      const m = this.mount.store.meta(n);
      if (m.reference === undefined) continue;
      // A reference is a name and not an object and carries no list
      // of its own: a request that reaches one through an export is
      // authorised by the list of the container object that holds it.
      this.require(parent, this.mount.store.meta(parent), M.READ_OBJECT);
      return this.entry(name, n, m);
    }
    return undefined;
  }

  /** Forms the entry an SMB client sees for one object. */
  entry(name: string, node: Node, meta: Meta): Entry {
    const now = Date.now();
    const created = TIME(meta, "cdmi_ctime", now);
    const written = TIME(meta, "cdmi_mtime", now);
    const accessed = TIME(meta, "cdmi_atime", now);
    let attributes = node.isContainer
      ? FILE_ATTRIBUTE.DIRECTORY
      : FILE_ATTRIBUTE.ARCHIVE;
    if (meta.reference !== undefined) {
      // A reference is presented as a reparse point of the symbolic
      // link tag; phase 5 carries the tag and the substitute name.
      attributes |= FILE_ATTRIBUTE.REPARSE_POINT;
    }
    if (this.mount.readOnly || meta.frozen) attributes |= FILE_ATTRIBUTE.READONLY;
    return {
      name,
      node,
      meta,
      reference: meta.reference,
      isContainer: node.isContainer,
      size: node.isContainer ? 0 : sizeOf(meta),
      attributes,
      created,
      accessed,
      written,
      changed: written,
      fileId: idOf(meta.objectID),
    };
  }
}

/**
 * The file identifier a directory listing reports. [MS-FSCC] gives it
 * eight octets, and a CDMI object identifier is longer, so the value
 * reported is derived from the identifier rather than being it. It is
 * stable for the life of the object, which is what a client uses it
 * for.
 */
export function idOf(objectID: string): bigint {
  let h = 0xcbf29ce484222325n;
  for (const ch of Buffer.from(objectID, "latin1")) {
    h = BigInt.asUintN(64, (h ^ BigInt(ch)) * 0x100000001b3n);
  }
  return h;
}
