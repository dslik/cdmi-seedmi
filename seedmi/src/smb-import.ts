/**
 * An SMB import: a share held by another server, presented as a layer
 * of a CDMI container object.
 *
 * The shape is the one an NFS import has, because what a layer needs
 * of an imported file system namespace is the same for both. What
 * differs is underneath: a session and a tree are held rather than a
 * session and a file handle, a name is opened and closed around every
 * operation rather than a handle being kept, and a reparse point takes
 * the place of a symbolic link.
 */

import { resolveAndCheck } from "./originated.ts";
import { SmbClient, SmbError } from "./smb-client.ts";
import { NT, statusName } from "./smb-wire.ts";
import { NF4DIR, NF4LNK, NF4REG } from "./nfs.ts";
import type { FileSource, NfsEntry } from "./nfs-import.ts";
import { decodeFullEas, DIR_CLASS, FILE_CLASS, INFO_TYPE } from "./smb-info.ts";
import { FSCTL, readSymlinkReparseData } from "./smb-security.ts";
import { fromFileTime } from "./smb-wire.ts";

export class SmbSourceError extends Error {}

export interface SmbSourceOptions {
  host: string;
  port: number;
  /** The share to connect. */
  share: string;
  /** The path within the share, beginning with a solidus. */
  root: string;
  /** The dialect to offer, being the version the entry names. */
  protocol: string;
  /** Whether every message of the session is signed. */
  signing: boolean;
  /** The principal to authenticate as, or none for an anonymous session. */
  user?: string;
  password?: string;
  domain: string;
  /** Whether a reparse point within the namespace is resolved. */
  followReparse: boolean;
  /**
   * Whether the extended attributes of a file are presented as user
   * metadata, which the cdmi_import_smb_ea capability governs.
   */
  extendedAttributes?: boolean;
}

const FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
const FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
const OPEN_REPARSE_POINT = 0x00200000;
const READ_ACCESS = 0x00120089;

/**
 * One import source. A connection, a session and a tree are held for
 * as long as the source is used: establishing one costs a negotiate,
 * two session setups and a tree connect before anything is read.
 */
export class SmbSource implements FileSource {
  readonly opts: SmbSourceOptions;
  private client?: SmbClient;
  private connecting?: Promise<SmbClient>;

  constructor(opts: SmbSourceOptions) {
    this.opts = opts;
  }

  private where(): string {
    return `smb://${this.opts.host}:${this.opts.port}/${this.opts.share}${this.opts.root}`;
  }

  private async connected(): Promise<SmbClient> {
    if (this.client) return this.client;
    if (!this.connecting) {
      this.connecting = (async () => {
        const c = new SmbClient({
          dialects: [this.opts.protocol],
          signingRequired: this.opts.signing,
        });
        const at = await resolveAndCheck(`smb://${this.opts.host}:${this.opts.port}/`);
        await c.connect(this.opts.port, at.address);
        await c.negotiate();
        // No user name authenticates as the anonymous principal,
        // which is what an entry naming no credential asks for.
        await c.sessionSetup(this.opts.user, this.opts.password, this.opts.domain);
        await c.treeConnect(this.opts.host, this.opts.share);
        this.client = c;
        return c;
      })().catch((err) => {
        this.connecting = undefined;
        throw new SmbSourceError(`${this.where()} could not be reached: ${String(err)}`);
      });
    }
    return this.connecting;
  }

  close(): void {
    this.client?.close();
    this.client = undefined;
    this.connecting = undefined;
  }

  /** The path within the share of a path within the import. */
  private at(path: string): string {
    const root = this.opts.root.replace(/^\/|\/$/g, "");
    const rest = path.replace(/^\/|\/$/g, "");
    const parts = [...root.split("/"), ...rest.split("/")].filter((p) => p !== "");
    return parts.join("\\");
  }

  /** Whether the source answers, which decides whether the entry is active. */
  async reachable(): Promise<void> {
    const c = await this.connected();
    const open = await this.openPath(c, this.at(""));
    if (open === undefined) {
      throw new SmbSourceError(`${this.where()} names nothing on that server`);
    }
    await c.closeFile(open.id).catch(() => undefined);
  }

  /** Opens a name, answering undefined where there is nothing of that name. */
  private async openPath(c: SmbClient, path: string, options = OPEN_REPARSE_POINT):
    Promise<{ id: bigint; attributes: number; size: number } | undefined> {
    try {
      const open = await c.create(path, READ_ACCESS, options);
      return { id: open.id, attributes: open.attributes, size: open.size };
    } catch (err) {
      if (err instanceof SmbError &&
        (err.status === NT.OBJECT_NAME_NOT_FOUND ||
          err.status === NT.OBJECT_PATH_NOT_FOUND ||
          err.status === NT.NO_SUCH_FILE)) {
        return undefined;
      }
      throw new SmbSourceError(
        `${this.where()} did not answer for ${path}: ${String(err)}`);
    }
  }

  /** The children of a directory of the imported namespace. */
  async children(path: string): Promise<NfsEntry[]> {
    const c = await this.connected();
    const here = this.at(path);
    const open = await this.openPath(c, here);
    if (open === undefined) return [];
    try {
      if ((open.attributes & FILE_ATTRIBUTE_DIRECTORY) === 0) return [];
      const out: NfsEntry[] = [];
      // A listing is read in parts until the server says there are no
      // more, which is how a directory of any size is enumerated.
      for (let call = 0; ; call++) {
        const listing = await c.queryDirectory(open.id, "*",
          DIR_CLASS.FileIdBothDirectoryInformation, call === 0 ? 0x01 : 0x00);
        if (listing.status !== 0 || listing.names.length === 0) break;
        for (const name of listing.names) {
          // The two names every directory of a file system carries and
          // no namespace of this document does.
          if (name === "." || name === "..") continue;
          const entry = await this.present(path, name);
          if (entry !== undefined) out.push(entry);
        }
      }
      return out;
    } finally {
      await c.closeFile(open.id).catch(() => undefined);
    }
  }

  /** One object of the imported namespace. */
  async entry(path: string): Promise<NfsEntry | undefined> {
    const cut = path.replace(/\/$/, "").lastIndexOf("/");
    const dir = cut < 0 ? "" : path.slice(0, cut);
    const name = cut < 0 ? path : path.slice(cut + 1);
    if (name === "") return undefined;
    return this.present(dir, name);
  }

  /**
   * Forms the entry for one name. A reparse point is resolved where
   * the entry asks for it, so that a read reaches the object and not
   * the link; where it is not resolved, the name is presented as a
   * link, which a CDMI container object presents as a reference.
   */
  private async present(dir: string, name: string): Promise<NfsEntry | undefined> {
    const c = await this.connected();
    const path = dir === "" ? name : `${dir}/${name}`;
    const open = await this.openPath(c, this.at(path));
    if (open === undefined) return undefined;
    try {
      const isReparse = (open.attributes & FILE_ATTRIBUTE_REPARSE_POINT) !== 0;
      if (isReparse && !this.opts.followReparse) {
        // A reparse point the entry does not resolve is not presented.
        // The clause says what happens when one is resolved and not
        // what happens when it is not; this is what the NFS import
        // does with an unresolved symbolic link, and the two are kept
        // alike deliberately. See Q17 in NOTES-on-smb.md.
        return undefined;
      }
      if (isReparse) {
        // Resolved: the object the substitute name reaches, presented
        // under the name of the link.
        const resolved = await this.resolve(c, dir, open.id);
        if (resolved === undefined) return undefined;
        return { ...resolved, name };
      }
      const basic = await c.queryInfo(open.id, INFO_TYPE.FILE,
        FILE_CLASS.FileBasicInformation);
      const standard = await c.queryInfo(open.id, INFO_TYPE.FILE,
        FILE_CLASS.FileStandardInformation);
      // The extended attributes of the file, as user metadata, where
      // the entry asks for them. A file that has none answers
      // NO_EAS_ON_FILE, which is not an error.
      let metadata: Record<string, string> | undefined;
      if (this.opts.extendedAttributes) {
        try {
          const eas = await c.queryInfo(open.id, INFO_TYPE.FILE,
            FILE_CLASS.FileFullEaInformation);
          metadata = {};
          for (const ea of decodeFullEas(eas)) {
            // A name this document reserves is not created on account
            // of an extended attribute.
            if (ea.name.startsWith("cdmi_")) continue;
            metadata[ea.name] = ea.value.toString("utf8");
          }
        } catch {
          metadata = undefined;
        }
      }
      return {
        name,
        at: path,
        type: (open.attributes & FILE_ATTRIBUTE_DIRECTORY) !== 0 ? NF4DIR : NF4REG,
        size: Number(standard.readBigUInt64LE(8)),
        ctime: fromFileTime(basic.readBigUInt64LE(0)),
        atime: fromFileTime(basic.readBigUInt64LE(8)),
        mtime: fromFileTime(basic.readBigUInt64LE(16)),
        ...(metadata === undefined || Object.keys(metadata).length === 0
          ? {}
          : { metadata }),
      };
    } finally {
      await c.closeFile(open.id).catch(() => undefined);
    }
  }

  /** The object a reparse point names, where it is within the share. */
  private async resolve(c: SmbClient, dir: string, id: bigint):
    Promise<NfsEntry | undefined> {
    let substitute: string;
    try {
      const data = readSymlinkReparseData(
        await c.ioctl(id, FSCTL.GET_REPARSE_POINT));
      if (data === undefined) return undefined;
      if (!data.relative) {
        // An absolute substitute name names something outside the
        // share, which this server does not reach and does not
        // present.
        return undefined;
      }
      substitute = data.substitute;
    } catch {
      return undefined;
    }
    // The substitute name is relative to the directory holding the
    // link, and a path that climbs out of the share reaches nothing.
    const parts = dir.split("/").filter((p) => p !== "");
    for (const element of substitute.split(/[\\/]/)) {
      if (element === "" || element === ".") continue;
      if (element === "..") {
        if (parts.length === 0) return undefined;
        parts.pop();
        continue;
      }
      parts.push(element);
    }
    const target = parts.join("/");
    const cut = target.lastIndexOf("/");
    const resolved = await this.present(
      cut < 0 ? "" : target.slice(0, cut),
      cut < 0 ? target : target.slice(cut + 1));
    // A link to a link is not chased: one resolution is performed, and
    // a further reparse point is presented as one.
    return resolved;
  }

  /** A range of the value of an object of the imported namespace. */
  async value(path: string, offset: number, length: number): Promise<Buffer> {
    const c = await this.connected();
    // The reparse point is opened rather than followed: where an
    // entry resolved one, the path it carries is the resolved path,
    // and a read arrives here naming the object rather than the link.
    const open = await this.openPath(c, this.at(path), OPEN_REPARSE_POINT);
    if (open === undefined) return Buffer.alloc(0);
    try {
      if (length <= 0) return Buffer.alloc(0);
      const parts: Buffer[] = [];
      let at = offset;
      let left = length;
      // A read is answered with what the server chose to give, so the
      // range is read until it is complete or the value ends.
      while (left > 0) {
        let chunk: Buffer;
        try {
          chunk = await c.read(open.id, at, Math.min(left, 1048576));
        } catch (err) {
          if (err instanceof SmbError && err.status === NT.END_OF_FILE) break;
          throw new SmbSourceError(
            `${this.where()} did not answer a read of ${path}: ${statusName(
              err instanceof SmbError ? err.status : 0)}`);
        }
        if (chunk.length === 0) break;
        parts.push(chunk);
        at += chunk.length;
        left -= chunk.length;
      }
      return Buffer.concat(parts);
    } finally {
      await c.closeFile(open.id).catch(() => undefined);
    }
  }
}

/**
 * The credentials an SMB import may present, by the credential_id the
 * entry names. They are configured on the server and are not held in
 * the namespace, so that a password is not readable through a
 * representation.
 */
const credentials = new Map<string, { user: string; password: string }>();

export function setSmbCredential(id: string, user: string, password: string): void {
  credentials.set(id, { user, password });
}

export function smbCredential(id: string | undefined):
  { user: string; password: string } | undefined {
  return id === undefined ? undefined : credentials.get(id);
}

export function forgetSmbCredentials(): void {
  credentials.clear();
}

/** The sources in use, one per distinct configuration. */
const sources = new Map<string, SmbSource>();

export function smbSource(key: string, opts: SmbSourceOptions): SmbSource {
  let src = sources.get(key);
  if (!src) {
    src = new SmbSource(opts);
    sources.set(key, src);
  }
  return src;
}

export function forgetSmbSources(): void {
  for (const src of sources.values()) src.close();
  sources.clear();
}
