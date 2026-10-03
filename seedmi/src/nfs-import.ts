// The import source of an NFS import: a namespace held by an NFS
// server, presented as objects within an importing container object.
//
// seedmi speaks NFSv4.1 over TCP with AUTH_SYS, which is what its
// client implements. Kerberos is not available here, so the security
// flavour is "sys" alone and the identity mode is service alone: a
// flavour of "sys" carries a numeric identifier and no evidence that
// the party issuing the request is entitled to use it, so the draft
// requires the access control lists of the importing container object
// to govern every object presented, which is what service identity
// mode means.

import { resolveAndCheck } from "./originated.ts";
import { NfsClient, NfsClientError, type Attributes } from "./nfs-client.ts";
import { NF4DIR, NF4LNK, NF4REG, NFS4, FATTR4, XATTR_PREFIX } from "./nfs.ts";

export class NfsSourceError extends Error {}

/**
 * What a layer needs of an imported file system namespace. An NFS
 * import and an SMB import both present one, and everything above this
 * interface is the same for the two: names, sizes, times, an owner,
 * user metadata where the protocol carries it, and no object
 * identifier, since neither protocol has one that persists.
 */
export interface FileSource {
  reachable(): Promise<void>;
  children(path: string): Promise<NfsEntry[]>;
  entry(path: string): Promise<NfsEntry | undefined>;
  value(path: string, offset: number, length: number): Promise<Buffer>;
  close(): void;
}

/** What an object of the imported namespace looks like. */
export interface NfsEntry {
  name: string;
  /**
   * The path within the imported namespace of the object presented,
   * which is the target where a symbolic link was resolved and the
   * path of the entry itself otherwise. It is the path every operation
   * uses, so that a read reaches the file and not the link.
   */
  at: string;
  type: number;
  size: number;
  mtime?: number;
  atime?: number;
  ctime?: number;
  owner?: string;
  /**
   * The user metadata of the object, from the extended attributes of
   * the source. It is fetched when one object is read and not when a
   * directory is listed, since a listing of a hundred names would
   * otherwise cost a hundred round trips for metadata nobody asked
   * for.
   */
  metadata?: Record<string, string>;
}

export interface NfsSourceOptions {
  host: string;
  port: number;
  /** The path within the NFS server, beginning with a solidus. */
  root: string;
  uid: number;
  gid: number;
  /** Whether a symbolic link within the namespace is resolved. */
  followSymlinks: boolean;
  /**
   * Whether the extended attributes of the source are presented as
   * user metadata, which the cdmi_import_nfs_xattr capability governs.
   */
  xattrs: boolean;
}

const ATTRS = [FATTR4.TYPE, FATTR4.SIZE, FATTR4.TIME_MODIFY, FATTR4.OWNER];

/**
 * One import source. A connection and a session are held for as long as
 * the source is used, since establishing one costs two round trips
 * before anything is read.
 */
export class NfsSource {
  readonly opts: NfsSourceOptions;
  private client?: NfsClient;
  private mounting?: Promise<NfsClient>;

  constructor(opts: NfsSourceOptions) {
    this.opts = opts;
  }

  /** The connected client, mounting where this is the first use. */
  private async connected(): Promise<NfsClient> {
    if (this.client) return this.client;
    if (!this.mounting) {
      this.mounting = (async () => {
        const c = new NfsClient();
        // A server-originated request: the address resolved is checked, and is
        // the address connected to (originated.ts).
        const at = await resolveAndCheck(`nfs://${this.opts.host}:${this.opts.port}/`);
        await c.connect(this.opts.port, at.address, {
          uid: this.opts.uid,
          gid: this.opts.gid,
          gids: [this.opts.gid],
        });
        await c.mount();
        this.client = c;
        return c;
      })().catch((err) => {
        this.mounting = undefined;
        throw new NfsSourceError(`${this.where()} could not be reached: ${String(err)}`);
      });
    }
    return this.mounting;
  }

  private where(): string {
    return `nfs://${this.opts.host}:${this.opts.port}${this.opts.root}`;
  }

  /** Closes the connection, which a test does between servers. */
  close(): void {
    this.client?.close();
    this.client = undefined;
    this.mounting = undefined;
  }

  /** The path within the NFS server of a path within the import. */
  private at(path: string): string {
    const root = this.opts.root.replace(/\/$/, "");
    const within = path.replace(/^\//, "").replace(/\/$/, "");
    return within === "" ? root || "/" : `${root}/${within}`;
  }

  /** Whether the source answers at all, which establishes the import. */
  async reachable(): Promise<void> {
    const c = await this.connected();
    const attrs = await c.getattr(this.at(""), ATTRS).catch((err) => {
      throw new NfsSourceError(`${this.where()} could not be read: ${String(err)}`);
    });
    if (attrs.type !== NF4DIR) {
      throw new NfsSourceError(`${this.where()} is not a directory`);
    }
  }

  /**
   * The objects of a directory. A symbolic link is presented where the
   * entry says links are followed and the target lies within the
   * imported namespace; a device, a socket and a named pipe are never
   * presented.
   */
  async children(path: string): Promise<NfsEntry[]> {
    const c = await this.connected();
    let entries;
    try {
      entries = await c.readdir(this.at(path), ATTRS);
    } catch (err) {
      if (err instanceof NfsClientError && err.status === NFS4.NOENT) return [];
      throw new NfsSourceError(`${this.where()} could not be listed: ${String(err)}`);
    }
    const out: NfsEntry[] = [];
    for (const e of entries) {
      const resolved = await this.present(path, e.name, e.attrs);
      if (resolved) out.push(resolved);
    }
    return out;
  }

  /** The object at a path, or nothing where it is not presented. */
  async entry(path: string): Promise<NfsEntry | undefined> {
    const c = await this.connected();
    let attrs: Attributes;
    try {
      attrs = await c.getattr(this.at(path), ATTRS);
    } catch {
      return undefined;
    }
    const cut = path.replace(/\/$/, "").lastIndexOf("/");
    const name = path.replace(/\/$/, "").slice(cut + 1);
    const entry = await this.present(path.slice(0, cut + 1), name, attrs);
    if (entry && this.opts.xattrs) entry.metadata = await this.xattrs(entry.at);
    return entry;
  }

  /**
   * What an entry is presented as. A symbolic link is resolved where
   * the entry says so and the target lies within the imported
   * namespace; one whose target lies outside it is not presented, and
   * neither is a device, a socket or a named pipe.
   */
  private async present(dir: string, name: string,
    attrs: Attributes): Promise<NfsEntry | undefined> {
    let type = attrs.type;
    let size = Number(attrs.size ?? 0n);
    let at = dir + name;
    if (type === NF4LNK) {
      if (!this.opts.followSymlinks) return undefined;
      const target = await this.resolve(dir, name);
      if (!target) return undefined;
      type = target.attrs.type;
      size = Number(target.attrs.size ?? 0n);
      attrs = target.attrs;
      at = target.at;
    }
    if (type !== NF4DIR && type !== NF4REG) return undefined;
    return {
      name,
      at,
      type,
      size,
      mtime: attrs.mtime,
      owner: attrs.owner,
    };
  }

  /**
   * The object a symbolic link resolves to, where the target lies
   * within the imported namespace. A target outside it is not
   * resolved: the namespace presented is the one imported, and nothing
   * beyond it.
   */
  private async resolve(dir: string, name: string):
    Promise<{ at: string; attrs: Attributes } | undefined> {
    const c = await this.connected();
    let text: string;
    try {
      text = await c.readlink(this.at(dir + name));
    } catch {
      return undefined;
    }
    if (text.startsWith("/")) return undefined; // an absolute path leaves the import
    const parts = (dir + text).split("/").filter((p) => p !== "" && p !== ".");
    const walked: string[] = [];
    for (const part of parts) {
      if (part === "..") {
        if (walked.length === 0) return undefined; // above the imported namespace
        walked.pop();
        continue;
      }
      walked.push(part);
    }
    const at = walked.join("/");
    try {
      return { at, attrs: await c.getattr(this.at(at), ATTRS) };
    } catch {
      return undefined;
    }
  }

  /**
   * The extended attributes of an object, as user metadata.
   *
   * The name of an item is the name of the attribute with the "user."
   * prefix removed. RFC 8276 carries a key neither end interprets, so
   * the prefix a POSIX client uses is on the wire; an attribute of
   * another namespace is not presented, and neither is one whose name
   * is reserved by the draft or whose value is not valid UTF-8.
   */
  private async xattrs(path: string): Promise<Record<string, string>> {
    const c = await this.connected();
    let names: string[];
    try {
      names = await c.listxattrs(this.at(path));
    } catch {
      // A source that does not implement the operations has none.
      return {};
    }
    const out: Record<string, string> = {};
    for (const key of names) {
      if (!key.startsWith(XATTR_PREFIX)) continue;
      const name = key.slice(XATTR_PREFIX.length);
      if (name === "" || name.startsWith("cdmi_")) continue;
      try {
        const value = await c.getxattr(this.at(path), key);
        out[name] = new TextDecoder("utf-8", { fatal: true }).decode(value);
      } catch {
        // An attribute that cannot be read, or whose value is not
        // valid UTF-8, is not presented.
      }
    }
    return out;
  }

  /** A range of the value of a file. */
  async value(path: string, offset: number, length: number): Promise<Buffer> {
    if (length <= 0) return Buffer.alloc(0);
    const c = await this.connected();
    const whole = await c.readFile(this.at(path));
    return whole.subarray(offset, offset + length);
  }
}

/** The sources opened, so that a session is shared between requests. */
const sources = new Map<string, NfsSource>();

export function nfsSource(key: string, opts: NfsSourceOptions): NfsSource {
  let src = sources.get(key);
  if (!src) {
    src = new NfsSource(opts);
    sources.set(key, src);
  }
  return src;
}

export function forgetNfsSources(): void {
  for (const src of sources.values()) src.close();
  sources.clear();
}
