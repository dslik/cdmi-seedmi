// A user-space NFSv4.1 client: enough of one to mount an export, walk
// it, read and write files, and list directories, without a kernel mount
// and without privilege.
//
// It shares nothing with the server but the XDR codec and the protocol
// constants, so a mistake in either encoder shows up as a round trip that
// fails rather than as two matching mistakes.

import { randomBytes } from "node:crypto";
import { XDRReader, XDRWriter, encode } from "./xdr.ts";
import { NFSPROC4_COMPOUND, NFSPROC4_NULL, NFS_PROGRAM, NFS_VERSION, RpcClient } from "./rpc.ts";
import {
  CLAIM_NULL, FATTR4, FILE_SYNC4, NF4DIR, NF4LNK, NFS4, NFS4_SESSIONID_SIZE,
  OPEN4_CREATE, OPEN4_SHARE_ACCESS_BOTH, OP, SETXATTR4_EITHER, UNCHECKED4,
} from "./nfs.ts";

/** One operation of a compound. */
export interface Op {
  op: number;
  write?: (w: XDRWriter) => void;
}

export interface OpResult {
  op: number;
  status: number;
  /** A reader positioned at the result of this operation. */
  r: XDRReader;
}

export interface CompoundResult {
  status: number;
  results: OpResult[];
}

/** Raised where a compound fails, carrying the status it failed with. */
export class NfsClientError extends Error {
  status: number;
  constructor(status: number, what: string) {
    super(`${what} failed with NFS4ERR ${status}`);
    this.status = status;
  }
}

/** The attributes a client reads back, decoded. */
export interface Attributes {
  type?: number;
  change?: bigint;
  size?: bigint;
  fileid?: bigint;
  mode?: number;
  numlinks?: number;
  owner?: string;
  mtime?: number;
  /** Whether the file system of the object supports extended attributes. */
  xattrSupport?: boolean;
}

export interface DirEntry {
  name: string;
  cookie: bigint;
  attrs: Attributes;
}

const COMMON_ATTRS = [FATTR4.TYPE, FATTR4.CHANGE, FATTR4.SIZE, FATTR4.FILEID,
  FATTR4.MODE, FATTR4.NUMLINKS, FATTR4.OWNER, FATTR4.TIME_MODIFY];

export class NfsClient {
  /** The minor version of NFSv4 this client asks for. */
  minorVersion = 2;

  private readonly rpc = new RpcClient();
  private sessionid = Buffer.alloc(NFS4_SESSIONID_SIZE);
  private sequenceid = 1;
  private readonly slot = 0;
  clientid = 0n;

  /** Connects and presents an AUTH_SYS credential. */
  async connect(port: number, host = "127.0.0.1",
    who: { uid?: number; gid?: number; gids?: number[] } = {}): Promise<void> {
    await this.rpc.connect(port, host);
    this.rpc.authSys({ uid: who.uid ?? 0, gid: who.gid ?? 0, gids: who.gids ?? [] });
  }

  close(): void {
    this.rpc.close();
  }

  /** The NULL procedure, which a client uses to check the server is there. */
  async ping(): Promise<void> {
    const reply = await this.rpc.call(NFS_PROGRAM, NFS_VERSION, NFSPROC4_NULL);
    if (!reply.accepted || reply.status !== 0) {
      throw new NfsClientError(reply.status, "NULL");
    }
  }

  /** Sends a compound exactly as given, without adding a SEQUENCE. */
  async raw(ops: Op[], tag = ""): Promise<CompoundResult> {
    const args = encode((w) => {
      w.string(tag);
      // The second minor version, which is the one that defines the
      // extended attribute operations. Nothing else of it is used.
      w.uint(this.minorVersion);
      w.uint(ops.length);
      for (const o of ops) {
        w.uint(o.op);
        o.write?.(w);
      }
    });
    const reply = await this.rpc.call(NFS_PROGRAM, NFS_VERSION, NFSPROC4_COMPOUND, args);
    if (!reply.accepted) throw new NfsClientError(reply.status, "the RPC");
    const r = reply.results;
    const status = r.uint();
    r.string(); // the tag
    const count = r.uint();
    const results: OpResult[] = [];
    for (let i = 0; i < count; i++) {
      const op = r.uint();
      const opStatus = r.uint();
      // The result follows the status, so a reader is taken there and
      // the body skipped, leaving the stream at the next operation.
      results.push({ op, status: opStatus, r: r.from(r.offset) });
      if (opStatus === NFS4.OK) skipResult(op, r);
    }
    return { status, results };
  }

  /** Sends a compound beginning with SEQUENCE, as a session requires. */
  async compound(ops: Op[], tag = ""): Promise<CompoundResult> {
    const sequence: Op = {
      op: OP.SEQUENCE,
      write: (w) => {
        w.fixed(this.sessionid);
        w.uint(this.sequenceid++);
        w.uint(this.slot);
        w.uint(this.slot);
        w.bool(false);
      },
    };
    return this.raw([sequence, ...ops], tag);
  }

  /** Like compound, but raises where the compound did not succeed. */
  async ok(ops: Op[], what: string): Promise<OpResult[]> {
    const out = await this.compound(ops, what);
    if (out.status !== NFS4.OK) throw new NfsClientError(out.status, what);
    return out.results;
  }

  /** EXCHANGE_ID and CREATE_SESSION: what a mount does first. */
  async mount(): Promise<void> {
    const owner = randomBytes(8);
    const exchange = await this.raw([{
      op: OP.EXCHANGE_ID,
      write: (w) => {
        w.fixed(randomBytes(8)); // the verifier of this client instance
        w.opaque(owner);
        w.uint(0); // flags
        w.uint(0); // SP4_NONE
        w.uint(0); // no implementation id
      },
    }], "EXCHANGE_ID");
    if (exchange.status !== NFS4.OK) {
      throw new NfsClientError(exchange.status, "EXCHANGE_ID");
    }
    const r = exchange.results[0].r;
    this.clientid = r.uhyper();
    const sequence = r.uint();

    const create = await this.raw([{
      op: OP.CREATE_SESSION,
      write: (w) => {
        w.uhyper(this.clientid);
        w.uint(sequence);
        w.uint(0); // flags
        writeChannel(w);
        writeChannel(w);
        w.uint(0); // no callback program
        w.uint(0); // no security parameters
      },
    }], "CREATE_SESSION");
    if (create.status !== NFS4.OK) {
      throw new NfsClientError(create.status, "CREATE_SESSION");
    }
    const cr = create.results[0].r;
    this.sessionid = cr.fixed(NFS4_SESSIONID_SIZE);
    cr.uint(); // csr_sequence, which belongs to the client identity
    // A slot's sequence begins at one, independently of that.
    this.sequenceid = 1;
  }

  // -----------------------------------------------------------------
  // Paths

  /** The operations that walk from the root to a path. */
  private walk(p: string): Op[] {
    const ops: Op[] = [{ op: OP.PUTROOTFH }];
    for (const seg of p.split("/")) {
      if (seg === "") continue;
      ops.push({ op: OP.LOOKUP, write: (w) => w.string(seg) });
    }
    return ops;
  }

  /** The parent of a path, and the last component of it. */
  private split(p: string): { dir: string; name: string } {
    const trimmed = p.replace(/\/+$/, "");
    const cut = trimmed.lastIndexOf("/");
    return { dir: trimmed.slice(0, cut + 1), name: trimmed.slice(cut + 1) };
  }

  /** The attributes of the object at a path. */
  async getattr(p: string, which: number[] = COMMON_ATTRS): Promise<Attributes> {
    const results = await this.ok(
      [...this.walk(p), { op: OP.GETATTR, write: (w) => w.bitmap(which) }],
      `GETATTR ${p}`);
    return readAttributes(results[results.length - 1].r);
  }

  /** The file handle of the object at a path. */
  async lookup(p: string): Promise<Buffer> {
    const results = await this.ok([...this.walk(p), { op: OP.GETFH }], `LOOKUP ${p}`);
    return results[results.length - 1].r.opaque();
  }

  /** Whether an object is there at all. */
  async exists(p: string): Promise<boolean> {
    try {
      await this.lookup(p);
      return true;
    } catch (err) {
      if (err instanceof NfsClientError && err.status === NFS4.NOENT) return false;
      throw err;
    }
  }

  /** The access bits the server grants, of those asked about. */
  async access(p: string, wanted: number): Promise<number> {
    const results = await this.ok(
      [...this.walk(p), { op: OP.ACCESS, write: (w) => w.uint(wanted) }], `ACCESS ${p}`);
    const r = results[results.length - 1].r;
    r.uint(); // the bits answered for
    return r.uint();
  }

  // -----------------------------------------------------------------
  // Reading

  /** Reads a whole file, in as many reads as its size requires. */
  async readFile(p: string, chunk = 1 << 16): Promise<Buffer> {
    const parts: Buffer[] = [];
    let offset = 0;
    for (;;) {
      const results = await this.ok([...this.walk(p), {
        op: OP.READ,
        write: (w) => {
          w.fixed(Buffer.alloc(16)); // the anonymous stateid
          w.uhyper(BigInt(offset));
          w.uint(chunk);
        },
      }], `READ ${p}`);
      const r = results[results.length - 1].r;
      const eof = r.bool();
      const data = r.opaque();
      parts.push(data);
      offset += data.length;
      if (eof || data.length === 0) break;
    }
    return Buffer.concat(parts);
  }

  /** Lists a directory, following the cookie until the end. */
  async readdir(p: string, which: number[] = [FATTR4.TYPE]): Promise<DirEntry[]> {
    const out: DirEntry[] = [];
    let cookie = 0n;
    let verifier = Buffer.alloc(8);
    for (;;) {
      const results = await this.ok([...this.walk(p), {
        op: OP.READDIR,
        write: (w) => {
          w.uhyper(cookie);
          w.fixed(verifier);
          w.uint(8192); // dircount, a hint
          w.uint(8192); // maxcount
          w.bitmap(which);
        },
      }], `READDIR ${p}`);
      const r = results[results.length - 1].r;
      verifier = r.fixed(8);
      let last = cookie;
      while (r.bool()) {
        const entryCookie = r.uhyper();
        const name = r.string();
        out.push({ name, cookie: entryCookie, attrs: readAttributes(r) });
        last = entryCookie;
      }
      const eof = r.bool();
      if (eof) break;
      if (last === cookie) break; // no progress: stop rather than loop
      cookie = last;
    }
    return out;
  }

  // -----------------------------------------------------------------
  // Writing

  /** Opens a file, returning its stateid. */
  async open(p: string, create = false): Promise<Buffer> {
    const { dir, name } = this.split(p);
    const results = await this.ok([...this.walk(dir), {
      op: OP.OPEN,
      write: (w) => {
        w.uint(0); // seqid, which a session makes unnecessary
        w.uint(OPEN4_SHARE_ACCESS_BOTH);
        w.uint(0); // share_deny
        w.uhyper(this.clientid);
        w.opaque(Buffer.from("seedmi-client"));
        w.uint(create ? OPEN4_CREATE : 0);
        if (create) {
          w.uint(UNCHECKED4);
          w.bitmap([]);
          w.opaque(Buffer.alloc(0));
        }
        w.uint(CLAIM_NULL);
        w.string(name);
      },
    }], `OPEN ${p}`);
    const r = results[results.length - 1].r;
    const seqid = r.uint();
    const other = r.fixed(12);
    const stateid = Buffer.alloc(16);
    stateid.writeUInt32BE(seqid, 0);
    other.copy(stateid, 4);
    return stateid;
  }

  async closeFile(p: string, stateid: Buffer): Promise<void> {
    await this.ok([...this.walk(p), {
      op: OP.CLOSE,
      write: (w) => {
        w.uint(0);
        w.fixed(stateid);
      },
    }], `CLOSE ${p}`);
  }

  /** Writes at an offset, in as many writes as the data requires. */
  async write(p: string, stateid: Buffer, offset: number, data: Buffer,
    chunk = 1 << 16): Promise<void> {
    for (let at = 0; at < data.length; at += chunk) {
      const part = data.subarray(at, Math.min(at + chunk, data.length));
      await this.ok([...this.walk(p), {
        op: OP.WRITE,
        write: (w) => {
          w.fixed(stateid);
          w.uhyper(BigInt(offset + at));
          w.uint(FILE_SYNC4);
          w.opaque(part);
        },
      }], `WRITE ${p}`);
    }
  }

  /** Creates a file and writes its whole contents. */
  async writeFile(p: string, data: Buffer): Promise<void> {
    const existed = await this.exists(p);
    const stateid = await this.open(p, !existed);
    await this.write(p, stateid, 0, data);
    if (data.length === 0 || existed) await this.truncate(p, data.length);
    await this.closeFile(p, stateid);
  }

  async truncate(p: string, size: number): Promise<void> {
    await this.ok([...this.walk(p), {
      op: OP.SETATTR,
      write: (w) => {
        w.fixed(Buffer.alloc(16));
        w.bitmap([FATTR4.SIZE]);
        w.opaque(encode((x) => x.uhyper(BigInt(size))));
      },
    }], `SETATTR ${p}`);
  }

  // -----------------------------------------------------------------
  // Extended attributes (RFC 8276)

  /** The names of the extended attributes of an object. */
  async listxattrs(p: string, maxcount = 64 * 1024): Promise<string[]> {
    const out: string[] = [];
    let cookie = 0n;
    for (;;) {
      const results = await this.ok([...this.walk(p), {
        op: OP.LISTXATTRS,
        write: (w) => {
          w.uhyper(cookie);
          w.uint(maxcount);
        },
      }], `LISTXATTRS ${p}`);
      const r = results[results.length - 1].r;
      cookie = r.uhyper();
      const names = r.array(() => r.string());
      out.push(...names);
      if (r.bool()) break;
      if (names.length === 0) break;
    }
    return out;
  }

  /** The value of one extended attribute. */
  async getxattr(p: string, name: string): Promise<Buffer> {
    const results = await this.ok([...this.walk(p), {
      op: OP.GETXATTR,
      write: (w) => w.string(name),
    }], `GETXATTR ${p}`);
    return results[results.length - 1].r.opaque();
  }

  /** Sets an extended attribute. */
  async setxattr(p: string, name: string, value: Buffer | string,
    option = SETXATTR4_EITHER): Promise<void> {
    await this.ok([...this.walk(p), {
      op: OP.SETXATTR,
      write: (w) => {
        w.uint(option);
        w.string(name);
        w.opaque(typeof value === "string" ? Buffer.from(value, "utf8") : value);
      },
    }], `SETXATTR ${p}`);
  }

  /** Removes an extended attribute. */
  async removexattr(p: string, name: string): Promise<void> {
    await this.ok([...this.walk(p), {
      op: OP.REMOVEXATTR,
      write: (w) => w.string(name),
    }], `REMOVEXATTR ${p}`);
  }

  /** The text of the symbolic link at a path. */
  async readlink(p: string): Promise<string> {
    const results = await this.ok([...this.walk(p), { op: OP.READLINK }],
      `READLINK ${p}`);
    return results[results.length - 1].r.string();
  }

  /** Creates a symbolic link whose text is the destination given. */
  async symlink(p: string, text: string): Promise<void> {
    const { dir, name } = this.split(p);
    await this.ok([...this.walk(dir), {
      op: OP.CREATE,
      write: (w) => {
        w.uint(NF4LNK);
        w.string(text);
        w.string(name);
        w.bitmap([]);
        w.opaque(Buffer.alloc(0));
      },
    }], `CREATE ${p}`);
  }

  async mkdir(p: string): Promise<void> {
    const { dir, name } = this.split(p);
    await this.ok([...this.walk(dir), {
      op: OP.CREATE,
      write: (w) => {
        w.uint(NF4DIR);
        w.string(name);
        w.bitmap([]);
        w.opaque(Buffer.alloc(0));
      },
    }], `CREATE ${p}`);
  }

  async remove(p: string): Promise<void> {
    const { dir, name } = this.split(p);
    await this.ok([...this.walk(dir), {
      op: OP.REMOVE, write: (w) => w.string(name),
    }], `REMOVE ${p}`);
  }

  async rename(from: string, to: string): Promise<void> {
    const a = this.split(from);
    const b = this.split(to);
    await this.ok([
      ...this.walk(a.dir),
      { op: OP.SAVEFH },
      ...this.walk(b.dir).slice(1).length > 0
        ? [{ op: OP.PUTROOTFH }, ...this.walk(b.dir).slice(1)]
        : [{ op: OP.PUTROOTFH }],
      { op: OP.RENAME, write: (w) => w.string(a.name).string(b.name) },
    ], `RENAME ${from} ${to}`);
  }
}

// ---------------------------------------------------------------------------

function writeChannel(w: XDRWriter): void {
  w.uint(0); // headerpadsize
  w.uint(1 << 20); // maxrequestsize
  w.uint(1 << 20); // maxresponsesize
  w.uint(0); // maxresponsesize_cached
  w.uint(16); // maxoperations
  w.uint(8); // maxrequests
  w.uint(0); // no RDMA
}

function readChannel(r: XDRReader): void {
  for (let i = 0; i < 6; i++) r.uint();
  r.array(() => undefined);
}

/** Decodes a fattr4 into the attributes this client understands. */
export function readAttributes(r: XDRReader): Attributes {
  const bits = r.bitmap();
  const v = new XDRReader(r.opaque());
  const a: Attributes = {};
  // The values are packed in increasing order of attribute number.
  for (const bit of bits) {
    switch (bit) {
      case FATTR4.SUPPORTED_ATTRS: v.bitmap(); break;
      case FATTR4.TYPE: a.type = v.uint(); break;
      case FATTR4.FH_EXPIRE_TYPE: v.uint(); break;
      case FATTR4.CHANGE: a.change = v.uhyper(); break;
      case FATTR4.SIZE: a.size = v.uhyper(); break;
      case FATTR4.LINK_SUPPORT:
      case FATTR4.SYMLINK_SUPPORT:
      case FATTR4.NAMED_ATTR:
      case FATTR4.UNIQUE_HANDLES: v.bool(); break;
      case FATTR4.FSID: v.uhyper(); v.uhyper(); break;
      case FATTR4.LEASE_TIME: v.uint(); break;
      case FATTR4.RDATTR_ERROR: v.uint(); break;
      case FATTR4.FILEHANDLE: v.opaque(); break;
      case FATTR4.FILEID: a.fileid = v.uhyper(); break;
      case FATTR4.MAXFILESIZE:
      case FATTR4.MAXREAD:
      case FATTR4.MAXWRITE: v.uhyper(); break;
      case FATTR4.MAXNAME: v.uint(); break;
      case FATTR4.MODE: a.mode = v.uint(); break;
      case FATTR4.NUMLINKS: a.numlinks = v.uint(); break;
      case FATTR4.OWNER: a.owner = v.string(); break;
      case FATTR4.XATTR_SUPPORT: a.xattrSupport = v.bool(); break;
      case FATTR4.OWNER_GROUP: v.string(); break;
      case FATTR4.SPACE_USED: v.uhyper(); break;
      case FATTR4.TIME_ACCESS:
      case FATTR4.TIME_METADATA: v.hyper(); v.uint(); break;
      case FATTR4.TIME_MODIFY: {
        const seconds = v.hyper();
        const nanos = v.uint();
        a.mtime = Number(seconds) * 1000 + Math.floor(nanos / 1_000_000);
        break;
      }
      case FATTR4.MOUNTED_ON_FILEID: v.uhyper(); break;
      case FATTR4.SUPPATTR_EXCLCREAT: v.bitmap(); break;
      default:
        // An attribute this client does not decode: it cannot skip past
        // a value whose length it does not know, so it stops here.
        return a;
    }
  }
  return a;
}

/** Moves past the result of one operation, which the caller has read. */
export function skipResult(op: number, r: XDRReader): void {
  switch (op) {
    case OP.SEQUENCE:
      r.fixed(NFS4_SESSIONID_SIZE);
      for (let i = 0; i < 5; i++) r.uint();
      return;
    case OP.EXCHANGE_ID:
      r.uhyper();
      r.uint();
      r.uint();
      r.uint();
      r.uhyper();
      r.opaque();
      r.opaque();
      r.array(() => undefined);
      return;
    case OP.CREATE_SESSION:
      r.fixed(NFS4_SESSIONID_SIZE);
      r.uint();
      r.uint();
      readChannel(r);
      readChannel(r);
      return;
    case OP.GETFH:
      r.opaque();
      return;
    case OP.GETATTR:
      r.bitmap();
      r.opaque();
      return;
    case OP.ACCESS:
      r.uint();
      r.uint();
      return;
    case OP.READ:
      r.bool();
      r.opaque();
      return;
    case OP.READDIR:
      r.fixed(8);
      while (r.bool()) {
        r.uhyper();
        r.string();
        r.bitmap();
        r.opaque();
      }
      r.bool();
      return;
    case OP.OPEN:
      r.uint();
      r.fixed(12);
      r.bool();
      r.uhyper();
      r.uhyper();
      r.uint();
      r.bitmap();
      r.uint();
      return;
    case OP.CLOSE:
      r.uint();
      r.fixed(12);
      return;
    case OP.WRITE:
      r.uint();
      r.uint();
      r.fixed(8);
      return;
    case OP.COMMIT:
      r.fixed(8);
      return;
    case OP.SETATTR:
      r.bitmap();
      return;
    case OP.CREATE:
      r.bool();
      r.uhyper();
      r.uhyper();
      r.bitmap();
      return;
    case OP.REMOVE:
      r.bool();
      r.uhyper();
      r.uhyper();
      return;
    case OP.RENAME:
      for (let i = 0; i < 2; i++) {
        r.bool();
        r.uhyper();
        r.uhyper();
      }
      return;
    case OP.READLINK:
      r.string();
      return;
    case OP.GETXATTR:
      r.opaque();
      return;
    case OP.LISTXATTRS:
      r.uhyper();
      r.array(() => r.string());
      r.bool();
      return;
    case OP.SETXATTR:
    case OP.REMOVEXATTR:
      // A change_info4: atomic, and the change attribute either side.
      r.bool();
      r.uhyper();
      r.uhyper();
      return;
    case OP.SECINFO_NO_NAME:
      r.array(() => r.uint());
      return;
    default:
      // Every other operation carries no result beyond its status.
      return;
  }
}
