// An NFSv4.1 server over the CDMI namespace. The operations it performs
// are those a client needs to mount an export and read it: the session
// operations, the file handle operations, GETATTR, ACCESS, READ and
// READDIR. Writing is not performed yet.
//
// Three things join this to the rest of seedmi:
//
//   - a file handle names a position, not an object, so it survives a
//     copy-up, which changes which object a name resolves to;
//   - the fileid of an object is the primary key of its row, and the
//     change attribute is the version column, both of which the store
//     maintains for this purpose; and
//   - an access control list is evaluated exactly as it is for the HTTP
//     binding, since clause 17 takes the model from RFC 7530 unchanged.

import { decideFor, delegatedMask, DelegationRefused, withDelegation } from "./dac-context.ts";
import type { DacClient, DacOperation } from "./dac.ts";
import { randomBytes } from "node:crypto";
import type { Server } from "node:net";
import { XDRReader, XDRWriter, encode } from "./xdr.ts";
import {
  type Dispatch, type RpcCall, NFSPROC4_COMPOUND, NFSPROC4_NULL, RpcServer,
} from "./rpc.ts";
import {
  ACCESS4, CLAIM_NULL, CREATE_SESSION4_FLAG_PERSIST, EXCLUSIVE4, EXCLUSIVE4_1,
  EXCHGID4_FLAG_CONFIRMED_R, EXCHGID4_FLAG_USE_NON_PNFS, FATTR4, FILE_SYNC4, GUARDED4,
  LEASE_TIME, MAXNAME, MAXREAD, MAXWRITE, NF4DIR, NF4LNK, NF4REG, NFS4,
  MINOR_VERSIONS, NFS4_SESSIONID_SIZE, SETXATTR4_CREATE, SETXATTR4_REPLACE,
  XATTR_PREFIX,
  type NfsAttrs, OPEN4_CREATE, OPEN4_SHARE_ACCESS_WRITE, OPEN_DELEGATE_NONE, OP, OP_NAME,
  SETTABLE_ATTRS, SP4_NONE, SUPPORTED_ATTRS, UNCHECKED4, writeAttrs,
} from "./nfs.ts";
import { type Node, type Store, type Meta } from "./store.ts";
import { aclForNewObject } from "./acl.ts";
import { storableName } from "./fat.ts";
import { M, ANONYMOUS, granted, type Principal } from "./acl.ts";
import {
  Resolver, type View, denyChange, ensureImageWriteTarget, ensureWriteTarget, flushImage,
  listChildren, rankCmp, resolveFile,
} from "./layers.ts";
import { localImportPath } from "./imports.ts";
import {
  type ObjRef, assignedSizeOf, nodeOf, readValueOf, refOfDir, viewOf,
} from "./objects.ts";
import { isCondition } from "./problems.ts";
import { restrictedWithin, underRestriction } from "./retention.ts";
import type { Exports, NfsExport } from "./exports.ts";
import { isNfs } from "./exports.ts";
import { Log, SILENT } from "./log.ts";

/** The state of one client, established by EXCHANGE_ID. */
interface ClientRecord {
  clientid: bigint;
  ownerid: Buffer;
  verifier: Buffer;
  sequenceid: number;
  confirmed: boolean;
}

/** One slot of a session's fore channel, holding its cached reply. */
interface Slot {
  sequenceid: number;
  reply?: Buffer;
  cached: boolean;
}

interface Session {
  id: Buffer;
  clientid: bigint;
  slots: Slot[];
  maxRequestSize: number;
  maxResponseSize: number;
  maxOperations: number;
}

/** An open file, established by OPEN and ended by CLOSE. */
interface OpenState {
  /** The twelve opaque bytes of the stateid. */
  other: Buffer;
  seqid: number;
  /** The handle the open was made against. */
  handle: Buffer;
  shareAccess: number;
  clientid: bigint;
}

/** What a compound is operating on as it runs. */
interface CompoundState {
  current?: Buffer;
  saved?: Buffer;
  principal: Principal;
  /** Set once a SEQUENCE operation has been seen. */
  session?: Session;
  peer: string;
}

/** Raised by an operation to end the compound with a status. */
class NfsError extends Error {
  status: number;
  constructor(status: number) {
    super(`NFS4ERR ${status}`);
    this.status = status;
  }
}

export interface NfsOptions {
  store: Store;
  /** Delegated access control, where this server is configured for it. */
  dac?: DacClient;
  /** The exports of the server, from which the exported paths are taken. */
  exports?: Exports;
  /** Where an operation is written, where one is. */
  log?: Log;
  /** The domain of the owner strings this server returns. */
  domain?: string;
  /**
   * Whether an AUTH_SYS credential names a principal of this CDMI
   * server. Where it does not, every request is evaluated using
   * ANONYMOUS@, as the protocol binding does for a request that presents
   * no credential this server accepts. A server that maps credentials
   * sets this and supplies a usermap through the export entry.
   */
  mapCredentials?: boolean;
  /**
   * Resolves the numbers of an `AUTH_SYS` credential to a principal of the realm,
   * where a domain controller is configured for it: the uid by `uidNumber` and the
   * gids by `gidNumber` (§8 of the controller's `DESIGN-admin.md`). Undefined where no
   * principal has that uid, and then the request is anonymous.
   *
   * Without it, `mapCredentials` synthesises a name from the number — which is what
   * this server did, and which made an NFS identity and a CDMI identity two different
   * things for the same person: an access control entry naming `alice@EU.EXAMPLE`
   * granted nothing to the same alice arriving over NFS as `100000@eu.example`.
   *
   * It throws the authentication-unavailable condition where the directory cannot be
   * reached, which is the draft's rule and the reason this cannot simply fall back to
   * the synthesised name: "It shall not resolve the credentials by any other means,
   * and shall not perform the request as the anonymous principal" (revision 282,
   * ECR-129B).
   */
  resolveSys?: (uid: number, gid: number, gids: number[]) => Promise<Principal | undefined>;
}

export class NfsServer {
  readonly store: Store;
  readonly opts: NfsOptions;
  private readonly rpc: RpcServer;
  private readonly clients = new Map<string, ClientRecord>();
  private readonly byClientid = new Map<string, ClientRecord>();
  private readonly sessions = new Map<string, Session>();
  private readonly opens = new Map<string, OpenState>();
  private nextClientid = 1n;
  private readonly serverStart = Date.now();

  // -----------------------------------------------------------------
  // The pseudo filesystem
  //
  // An export entry states the path at which its export sits in a
  // namespace of the NFS server's own. Those paths form a tree whose
  // interior is not the CDMI namespace: a component of one is a
  // directory that holds only the way down to an export, and holds no
  // object of this document. This server presents that tree, and the
  // container object an entry is placed on is presented at the path
  // its entry states.
  //
  // A handle of such a directory is issued here rather than by the
  // store, since there is no row to name. It is marked, so that a
  // handle is recognised without a lookup, and holds an index into a
  // table of the paths issued.

  /** The first four octets of a handle of a pseudo directory. */
  private static readonly PSEUDO = 0x70736575; // "pseu"

  /** The pseudo paths a handle has been issued for, by index. */
  private readonly pseudoPaths: string[] = [];

  /** The handle of a pseudo directory, issued once per path. */
  private pseudoHandle(path: string): Buffer {
    let i = this.pseudoPaths.indexOf(path);
    if (i < 0) i = this.pseudoPaths.push(path) - 1;
    const fh = Buffer.alloc(16);
    fh.writeUInt32BE(NfsServer.PSEUDO, 0);
    fh.writeUInt32BE(i, 4);
    return fh;
  }

  /** The pseudo path a handle names, where it names one. */
  private pseudoOf(fh: Buffer): string | undefined {
    if (fh.length !== 16 || fh.readUInt32BE(0) !== NfsServer.PSEUDO) return undefined;
    return this.pseudoPaths[fh.readUInt32BE(4)];
  }

  /** The path of an export, as elements, from the path its entry states. */
  private static elements(path: string): string[] {
    return path.split("/").filter((p) => p !== "");
  }

  /**
   * What a pseudo directory holds: the next element of each export
   * path that continues below it, and the export whose path ends
   * there.
   */
  private pseudoChildren(path: string): { name: string; export?: string }[] {
    const here = NfsServer.elements(path);
    const out = new Map<string, { name: string; export?: string }>();
    for (const shared of this.shared.values()) {
      const parts = NfsServer.elements(shared.path);
      if (parts.length <= here.length) continue;
      if (!here.every((seg, i) => parts[i] === seg)) continue;
      const name = parts[here.length];
      const ends = parts.length === here.length + 1;
      const held = out.get(name);
      out.set(name, {
        name,
        export: ends ? shared.name : held?.export,
      });
    }
    return [...out.values()].sort((a, b) => a.name.localeCompare(b.name));
  }

  /** The export whose path is exactly this one, where there is one. */
  private exportAt(path: string): { name: string; ns: string } | undefined {
    const here = NfsServer.elements(path).join("/");
    for (const shared of this.shared.values()) {
      if (NfsServer.elements(shared.path).join("/") === here) return shared;
    }
    return undefined;
  }

  /** The attributes of a pseudo directory, which holds no object. */
  private pseudoAttrs(path: string, fh: Buffer): NfsAttrs {
    // A fileid that is stable for the life of the server and distinct
    // between paths, as the fileid of an object of the store is.
    let id = 0xcbf29ce484222325n;
    for (const ch of Buffer.from(`pseudo:${path}`, "utf8")) {
      id = BigInt.asUintN(64, (id ^ BigInt(ch)) * 0x100000001b3n);
    }
    const now = Date.now();
    return {
      type: NF4DIR,
      change: 1n,
      size: 0n,
      fileid: id,
      fsid: { major: 1n, minor: 1n },
      handle: fh,
      // Readable and traversable by everyone, and writable by nobody:
      // a pseudo directory holds no object and none may be made in it.
      mode: 0o555,
      numlinks: 2,
      owner: `nobody@${this.opts.domain ?? "localdomain"}`,
      ownerGroup: `nobody@${this.opts.domain ?? "localdomain"}`,
      atime: now,
      mtime: now,
      ctime: now,
    };
  }

  /** Where an operation is written, where one is. */
  private readonly log: Log;

  /**
   * The object an operation addressed, for the log: the namespace path
   * of the current handle, which is what identifies it to a person
   * reading the line.
   */
  private loggedPath(state: CompoundState): string {
    if (state.current === undefined) return "";
    const pseudo = this.pseudoOf(state.current);
    if (pseudo !== undefined) return pseudo;
    try {
      const { parent, name } = this.store.resolveHandle(state.current);
      const at = this.store.pathOf(parent);
      return name === "" ? at : `${at}${name}`;
    } catch {
      return "";
    }
  }

  /** The exports established, by the name of the entry. */
  private readonly shared =
    new Map<string, { name: string; path: string; ns: string; readOnly: boolean }>();
  private listening = false;

  private readonly dac: DacClient | undefined;

  constructor(opts: NfsOptions) {
    this.dac = opts.dac;
    this.store = opts.store;
    this.log = opts.log ?? SILENT;
    this.opts = opts;
    const procedures = new Map<number, Dispatch>();
    procedures.set(NFSPROC4_NULL, () => Buffer.alloc(0));
    procedures.set(NFSPROC4_COMPOUND,
      (call: RpcCall, peer: string) => this.compound(call, peer));
    this.rpc = new RpcServer({ procedures });
  }

  listen(port: number, host = "127.0.0.1"): Promise<Server> {
    this.listening = true;
    return this.rpc.listen(port, host);
  }

  close(): Promise<void> {
    return this.rpc.close();
  }

  address(): { port: number; address: string } | undefined {
    return this.rpc.address();
  }

  // -----------------------------------------------------------------
  // The COMPOUND procedure

  private async compound(call: RpcCall, peer: string): Promise<Buffer> {
    return withDelegation(() => this.compoundInner(call, peer));
  }

  private async compoundInner(call: RpcCall, peer: string): Promise<Buffer> {
    const began = Date.now();
    const r = call.args;
    const tag = r.string(1024);
    const minorversion = r.uint();
    const count = r.uint();

    if (!MINOR_VERSIONS.includes(minorversion)) {
      // The extended attribute operations belong to the second minor
      // version, and nothing else of it is implemented: a client that
      // asks for the second and uses an operation of a later one is
      // answered that the operation is not supported, which is the
      // ordinary answer for an operation this server does not have.
      return encode((w) => {
        w.uint(NFS4.MINOR_VERS_MISMATCH);
        w.string(tag);
        w.uint(0);
      });
    }

    const state: CompoundState = {
      principal: await this.principalOf(call),
      peer,
    };
    const results = new XDRWriter();
    let performed = 0;
    let status: number = NFS4.OK;

    for (let i = 0; i < count; i++) {
      const opnum = r.uint();
      const out = new XDRWriter();
      let opStatus: number = NFS4.OK;
      try {
        // SEQUENCE shall be the first operation of a compound, and no
        // other operation may precede it.
        if (opnum !== OP.SEQUENCE && opnum !== OP.EXCHANGE_ID &&
          opnum !== OP.CREATE_SESSION && opnum !== OP.DESTROY_SESSION &&
          opnum !== OP.DESTROY_CLIENTID && opnum !== OP.BIND_CONN_TO_SESSION &&
          state.session === undefined) {
          throw new NfsError(NFS4.OP_NOT_IN_SESSION);
        }
        if (opnum === OP.SEQUENCE && performed > 0) {
          throw new NfsError(NFS4.SEQUENCE_POS);
        }
        await this.operation(opnum, r, out, state);
      } catch (err) {
        opStatus = err instanceof NfsError ? err.status : this.statusOf(err);
        if (opStatus === NFS4.OK) opStatus = NFS4.SERVERFAULT;
      }
      // One line per operation of the compound, since an NFS client
      // sends several in one request and a failure names one of them.
      if (this.log.enabled) {
        this.log.write({
          surface: "nfs",
          outcome: statusName(opStatus),
          failed: opStatus !== NFS4.OK,
          operation: opName(opnum),
          instance: this.loggedPath(state),
          principal: state.principal.name,
          ms: Date.now() - began,
        });
      }
      results.uint(opnum);
      results.uint(opStatus);
      if (opStatus === NFS4.OK) results.raw(out.bytes());
      performed++;
      status = opStatus;
      // Evaluation ends at the first failing operation, and the results
      // of the operations evaluated so far are returned.
      if (opStatus !== NFS4.OK) break;
    }

    const reply = encode((w) => {
      w.uint(status);
      w.string(tag);
      w.uint(performed);
      w.raw(results.bytes());
    });
    return reply;
  }

  /**
   * The principal of a call, from its AUTH_SYS credential.
   *
   * Where a resolver is configured the numbers are resolved at the directory, so that
   * an NFS identity and a CDMI identity are one principal, and a uid the directory
   * does not know is anonymous rather than a name invented here.
   *
   * **`administrator: sys.uid === 0` is gone.** An `AUTH_SYS` credential is asserted
   * by the client and authenticated by nothing — RFC 5531's `AUTH_SYS` carries a uid
   * and a gid list and no proof of either — so on a server that mapped credentials,
   * any client willing to write 0 in a field held administrative status over every
   * object. A resolved principal holds the privileges of the groups the directory
   * gives it and nothing more. Where no resolver is configured the synthesised name
   * remains, for a deployment with no controller, and uid 0 no longer confers
   * anything there either: the number is a name and not a status.
   */
  private async principalOf(call: RpcCall): Promise<Principal> {
    const sys = call.credential.sys;
    if (!sys || this.opts.mapCredentials !== true) return ANONYMOUS;
    if (this.opts.resolveSys !== undefined) {
      // A failure to reach the directory is the authentication-unavailable condition
      // and is left to propagate: the compound is answered with a server fault rather
      // than performed as anonymous, which ECR-129B forbids.
      return (await this.opts.resolveSys(sys.uid, sys.gid, sys.gids)) ?? ANONYMOUS;
    }
    const domain = this.opts.domain ?? "localdomain";
    return {
      name: `${sys.uid}@${domain}`,
      groups: [`${sys.gid}@${domain}`, ...sys.gids.map((g) => `${g}@${domain}`)],
      administrator: false,
      privileges: [],
    };
  }

  /** Maps a CDMI condition to the NFS status that corresponds to it. */
  private statusOf(err: unknown): number {
    if (!isCondition(err)) return NFS4.SERVERFAULT;
    switch (err.status) {
      case 400: return NFS4.INVAL;
      case 403: return NFS4.ACCESS;
      case 404: return NFS4.NOENT;
      case 409: return NFS4.ACCESS; // denied by a layer above the write target
      case 412: return NFS4.ACCESS;
      case 503: return NFS4.IO; // an import source is unavailable
      default: return NFS4.SERVERFAULT;
    }
  }

  private async operation(opnum: number, r: XDRReader, w: XDRWriter,
    state: CompoundState): Promise<void> {
    // An object of this server that has delegated access control is governed
    // by its provider however it is reached (dac-context.ts). The decision is
    // obtained before the operation is performed, and the permission checks
    // below apply the mask the provider returned.
    await this.delegate(opnum, state);
    switch (opnum) {
      case OP.EXCHANGE_ID: return this.exchangeId(r, w);
      case OP.CREATE_SESSION: return this.createSession(r, w);
      case OP.DESTROY_SESSION: return this.destroySession(r, w);
      case OP.DESTROY_CLIENTID: return this.destroyClientid(r, w);
      case OP.SEQUENCE: return this.sequence(r, w, state);
      case OP.RECLAIM_COMPLETE: {
        r.bool(); // rca_one_fs
        return;
      }
      case OP.PUTROOTFH: return this.putRootFh(state);
      case OP.PUTFH: {
        const fh = r.opaque(128);
        this.resolveHandle(fh); // a handle that names nothing is stale
        state.current = fh;
        return;
      }
      case OP.GETFH: {
        w.opaque(this.currentHandle(state));
        return;
      }
      case OP.SAVEFH: {
        state.saved = this.currentHandle(state);
        return;
      }
      case OP.RESTOREFH: {
        if (!state.saved) throw new NfsError(NFS4.NOFILEHANDLE);
        state.current = state.saved;
        return;
      }
      case OP.LOOKUP: return this.lookup(r, state);
      case OP.LOOKUPP: return this.lookupp(state);
      case OP.GETATTR: return this.getattr(r, w, state);
      case OP.ACCESS: return this.access(r, w, state);
      case OP.READ: return this.read(r, w, state);
      case OP.READDIR: return this.readdir(r, w, state);
      case OP.OPEN: return this.open(r, w, state);
      case OP.CLOSE: return this.closeOpen(r, w, state);
      case OP.WRITE: return this.write(r, w, state);
      case OP.COMMIT: return this.commit(r, w, state);
      case OP.SETATTR: return this.setattr(r, w, state);
      case OP.CREATE: return this.create(r, w, state);
      case OP.REMOVE: return this.remove(r, w, state);
      case OP.RENAME: return this.rename(r, w, state);
      case OP.TEST_STATEID: {
        const ids = r.array((x) => x.fixed(16), 64);
        w.array(ids, (x, id) => x.uint(
          this.opens.has(id.subarray(4).toString("hex")) ? NFS4.OK : NFS4.BAD_STATEID));
        return;
      }
      case OP.FREE_STATEID: {
        const id = r.fixed(16);
        this.opens.delete(id.subarray(4).toString("hex"));
        return;
      }
      case OP.READLINK: return this.readlink(w, state);
      case OP.GETXATTR: return this.getxattr(r, w, state);
      case OP.SETXATTR: return this.setxattr(r, w, state);
      case OP.LISTXATTRS: return this.listxattrs(r, w, state);
      case OP.REMOVEXATTR: return this.removexattr(r, w, state);
      case OP.SECINFO_NO_NAME: {
        r.uint(); // the style
        // AUTH_SYS alone, which is what this server accepts.
        w.array([1], (x, flavor) => x.uint(flavor));
        return;
      }
      case OP.ILLEGAL:
        throw new NfsError(NFS4.OP_ILLEGAL);
      default:
        // An operation this server does not perform, including every
        // operation that changes an object.
        throw new NfsError(NFS4.NOTSUPP);
    }
  }

  // -----------------------------------------------------------------
  // Sessions

  private exchangeId(r: XDRReader, w: XDRWriter): void {
    const verifier = r.fixed(8);
    const ownerid = r.opaque(1024);
    r.uint(); // eia_flags
    const how = r.uint(); // state protection
    if (how !== SP4_NONE) throw new NfsError(NFS4.NOTSUPP);
    r.array(() => undefined, 1); // eia_client_impl_id

    const key = ownerid.toString("hex");
    let record = this.clients.get(key);
    if (record && !record.verifier.equals(verifier)) {
      // A new instance of the same client owner: the old state goes.
      this.forgetClient(record);
      record = undefined;
    }
    if (!record) {
      record = {
        clientid: this.nextClientid++,
        ownerid,
        verifier,
        sequenceid: 1,
        confirmed: false,
      };
      this.clients.set(key, record);
      this.byClientid.set(String(record.clientid), record);
    }

    w.uhyper(record.clientid);
    w.uint(record.sequenceid);
    w.uint(EXCHGID4_FLAG_USE_NON_PNFS |
      (record.confirmed ? EXCHGID4_FLAG_CONFIRMED_R : 0));
    w.uint(SP4_NONE);
    // The server owner: one minor id, and a major id that is stable for
    // the lifetime of this server.
    w.uhyper(0n);
    w.opaque(Buffer.from("seedmi", "utf8"));
    w.opaque(Buffer.from("seedmi", "utf8")); // the scope
    w.array([], () => undefined); // no implementation id
  }

  private createSession(r: XDRReader, w: XDRWriter): void {
    const clientid = r.uhyper();
    const sequence = r.uint();
    r.uint(); // csa_flags
    const fore = readChannelAttrs(r);
    readChannelAttrs(r); // the back channel, which this server does not use
    r.uint(); // csa_cb_program
    r.array(() => {
      throw new NfsError(NFS4.NOTSUPP);
    }, 0); // csa_sec_parms

    const record = this.byClientid.get(String(clientid));
    if (!record) throw new NfsError(NFS4.STALE_CLIENTID);
    if (sequence !== record.sequenceid) throw new NfsError(NFS4.SEQ_MISORDERED);
    record.sequenceid = (record.sequenceid + 1) >>> 0;
    record.confirmed = true;

    const slots = Math.max(Math.min(fore.maxRequests, 64), 1);
    const session: Session = {
      id: randomBytes(NFS4_SESSIONID_SIZE),
      clientid,
      slots: Array.from({ length: slots }, () => ({ sequenceid: 0, cached: false })),
      maxRequestSize: Math.min(fore.maxRequestSize, 1 << 20),
      maxResponseSize: Math.min(fore.maxResponseSize, 1 << 20),
      maxOperations: Math.max(Math.min(fore.maxOperations, 64), 2),
    };
    this.sessions.set(session.id.toString("hex"), session);

    w.fixed(session.id);
    w.uint(record.sequenceid);
    w.uint(CREATE_SESSION4_FLAG_PERSIST);
    writeChannelAttrs(w, session);
    writeChannelAttrs(w, session);
  }

  private destroySession(r: XDRReader, w: XDRWriter): void {
    const id = r.fixed(NFS4_SESSIONID_SIZE);
    if (!this.sessions.delete(id.toString("hex"))) {
      throw new NfsError(NFS4.BADSESSION);
    }
    void w;
  }

  private destroyClientid(r: XDRReader, w: XDRWriter): void {
    const clientid = r.uhyper();
    const record = this.byClientid.get(String(clientid));
    if (!record) throw new NfsError(NFS4.STALE_CLIENTID);
    this.forgetClient(record);
    void w;
  }

  private forgetClient(record: ClientRecord): void {
    this.clients.delete(record.ownerid.toString("hex"));
    this.byClientid.delete(String(record.clientid));
    for (const [key, session] of this.sessions) {
      if (session.clientid === record.clientid) this.sessions.delete(key);
    }
  }

  private sequence(r: XDRReader, w: XDRWriter, state: CompoundState): void {
    const id = r.fixed(NFS4_SESSIONID_SIZE);
    const sequenceid = r.uint();
    const slotid = r.uint();
    const highest = r.uint();
    r.bool(); // sa_cachethis

    const session = this.sessions.get(id.toString("hex"));
    if (!session) throw new NfsError(NFS4.BADSESSION);
    if (slotid >= session.slots.length) throw new NfsError(NFS4.BADSLOT);
    const slot = session.slots[slotid];
    // A sequence identifier one greater than the last is a new request;
    // the same one is a retry; anything else is misordered.
    if (sequenceid === slot.sequenceid) {
      throw new NfsError(NFS4.SEQ_MISORDERED); // a retry, which this server
      // does not replay: it caches no reply, so it cannot answer one.
    }
    if (sequenceid !== ((slot.sequenceid + 1) >>> 0)) {
      throw new NfsError(NFS4.SEQ_MISORDERED);
    }
    slot.sequenceid = sequenceid;
    state.session = session;

    w.fixed(session.id);
    w.uint(sequenceid);
    w.uint(slotid);
    w.uint(session.slots.length - 1);
    w.uint(Math.min(highest, session.slots.length - 1));
    w.uint(0); // no status flags
  }

  // -----------------------------------------------------------------
  // File handles and the namespace

  private currentHandle(state: CompoundState): Buffer {
    if (!state.current) throw new NfsError(NFS4.NOFILEHANDLE);
    return state.current;
  }

  /**
   * PUTROOTFH names the root of the namespace this server presents.
   *
   * Where one export is established, its container object is that
   * root: an NFS client that mounts the server reaches the objects the
   * entry presents and nothing above them. Where none is established
   * the store root is served, which is what a server configured with
   * no export entry presents.
   *
   * More than one is never established: placing each at the path its
   * entry states needs a pseudo filesystem this server does not
   * build, so a second entry is reported as not active with the
   * reason, rather than established and presenting something other
   * than what it states. See the note on this in
   * NOTES-on-nfs-exports.md.
   */
  private putRootFh(state: CompoundState): void {
    if (this.shared.size === 0) {
      // No export is established: the store is served from its root,
      // which is what a server configured with no export entry
      // presents.
      state.current = this.store.rootHandle();
      return;
    }
    const atRoot = this.exportAt("/");
    if (atRoot !== undefined) {
      state.current = this.handleOfNs(atRoot.ns);
      return;
    }
    state.current = this.pseudoHandle("/");
  }

  /**
   * The handle of the container object a namespace path names. A
   * handle names a parent and a name within it, so the path is walked
   * to the parent and the last element is the name.
   */
  private handleOfNs(ns: string): Buffer {
    const parts = ns.split("/").filter((p) => p !== "");
    if (parts.length === 0) return this.store.rootHandle();
    let node = this.store.root();
    for (const seg of parts.slice(0, -1)) {
      const next = this.store.tryLookup(node, `${seg}/`) ??
        this.store.tryLookup(node, seg);
      if (next === undefined) throw new NfsError(NFS4.NOENT);
      node = next;
    }
    const last = parts[parts.length - 1];
    const child = this.store.tryLookup(node, `${last}/`) ??
      this.store.tryLookup(node, last);
    if (child === undefined) throw new NfsError(NFS4.NOENT);
    // A handle is keyed by the name without a trailing solidus, as
    // every handle this server issues for a child is.
    return this.store.handle(node, last);
  }

  // -----------------------------------------------------------------
  // The exports this server offers, kept in step with the entries

  /** Establishes an export, replacing one of the same name. */
  offer(shared: { name: string; path: string; ns: string; readOnly: boolean }): void {
    this.shared.set(shared.name, shared);
  }

  /** Withdraws an export. */
  withdraw(name: string): void {
    this.shared.delete(name);
  }

  /** The names of the exports now offered. */
  offered(): string[] {
    return [...this.shared.keys()];
  }

  /** Whether the server is listening. */
  running(): boolean {
    return this.listening;
  }

  /**
   * Whether every host this export admits is admitted read only. A
   * write through an export that admits none is refused whatever the
   * access control list of the object permits, as share level access
   * is evaluated before the list.
   */
  readOnly(): boolean {
    const all = [...this.shared.values()];
    return all.length > 0 && all.every((e) => e.readOnly);
  }

  /**
   * The pseudo directory above the container object a handle names,
   * where that object is the one an export presents. Where the path
   * the entry states is the root there is none, and the object has no
   * parent within the export.
   */
  private pseudoAbove(fh: Buffer): Buffer | undefined {
    for (const shared of this.shared.values()) {
      const parts = NfsServer.elements(shared.path);
      if (parts.length === 0) continue;
      let theirs: Buffer;
      try {
        theirs = this.handleOfNs(shared.ns);
      } catch {
        continue;
      }
      if (theirs.equals(fh)) {
        return this.pseudoHandle(`/${parts.slice(0, -1).join("/")}`);
      }
    }
    return undefined;
  }

  /** The parent and name a handle names, or a stale handle. */
  /** The value of "cdmi_operation" for an NFS operation that touches an object. */
  private static readonly DELEGATED_OPS: Record<number, DacOperation> = {
    [OP.READ]: "cdmi_read",
    [OP.READDIR]: "cdmi_list",
    [OP.WRITE]: "cdmi_modify",
    [OP.SETATTR]: "cdmi_modify_metadata",
    [OP.REMOVE]: "cdmi_delete",
    [OP.OPEN]: "cdmi_read",
    [OP.GETATTR]: "cdmi_read_metadata",
  };

  /**
   * Obtains the decision for the object the current file handle names, where
   * the operation touches one and the object has delegated access control.
   * Where no valid response is received the operation is not performed:
   * NFS4ERR_ACCESS is what this protocol has to report a refusal with.
   */
  private async delegate(opnum: number, state: CompoundState): Promise<void> {
    const operation = NfsServer.DELEGATED_OPS[opnum];
    if (this.dac === undefined || operation === undefined || state.current === undefined) return;
    let node: Node | undefined;
    try {
      const { parent, name } = this.store.resolveHandle(state.current);
      node = name === "" ? parent : this.store.tryLookup(parent, name);
    } catch {
      return;
    }
    if (node === undefined) return;
    try {
      await decideFor(this.dac, this.store, node, state.principal, operation);
    } catch (e) {
      if (!(e instanceof DelegationRefused)) throw e;
      throw new NfsError(NFS4.ACCESS);
    }
  }

  private resolveHandle(fh: Buffer): { parent: Node; name: string } {
    try {
      return this.store.resolveHandle(fh);
    } catch {
      throw new NfsError(NFS4.STALE);
    }
  }

  /**
   * What a handle presents: the view of the container it names, or the
   * data object it names within its parent.
   */
  private async at(fh: Buffer): Promise<{
    ref: ObjRef;
    view?: View;
    parent: View;
    name: string;
  }> {
    const { parent, name } = this.resolveHandle(fh);
    const r = new Resolver(this.store);
    const parentNS = this.store.pathOf(parent);
    let pv: View;
    try {
      pv = await r.view(parentNS);
    } catch {
      throw new NfsError(NFS4.STALE);
    }
    if (name === "") {
      // The root container object: its handle names it directly.
      return { ref: { kind: "store", node: parent }, view: pv, parent: pv, name: "" };
    }
    const found = await resolveFile(this.store, pv, name);
    if (found) return { ref: found.ref, parent: pv, name };
    try {
      const cv = await r.child(pv, name);
      const ref: ObjRef = refOfDir(cv.held);
      return { ref, view: cv, parent: pv, name };
    } catch {
      throw new NfsError(NFS4.STALE);
    }
  }

  private async lookup(r: XDRReader, state: CompoundState): Promise<void> {
    const name = r.string(MAXNAME);
    if (name === "" || name === "." || name === "..") throw new NfsError(NFS4.INVAL);
    const pseudo = this.pseudoOf(this.currentHandle(state));
    if (pseudo !== undefined) {
      // Within the pseudo tree: a name is either a component of the
      // path of an export or the last component of one, at which the
      // container object the entry is placed on begins.
      const below = pseudo === "/" ? `/${name}` : `${pseudo}/${name}`;
      const shared = this.exportAt(below);
      if (shared !== undefined) {
        state.current = this.handleOfNs(shared.ns);
        return;
      }
      if (this.pseudoChildren(below).length === 0) throw new NfsError(NFS4.NOENT);
      state.current = this.pseudoHandle(below);
      return;
    }
    const here = await this.at(this.currentHandle(state));
    if (!here.view) throw new NfsError(NFS4.NOTDIR);
    const resolver = new Resolver(this.store);
    const view = here.view;

    const found = await resolveFile(this.store, view, name);
    if (!found) {
      try {
        await resolver.child(view, name);
      } catch {
        throw new NfsError(NFS4.NOENT);
      }
    }
    // A handle names a position within a container object of the store.
    const holder = nodeOf(view.held);
    if (!holder) {
      // A directory of an imported file system holds no object of the
      // store, so no persistent handle can be issued for a name in it.
      throw new NfsError(NFS4.NOTSUPP);
    }
    state.current = this.store.handle(holder, name);
  }

  private async lookupp(state: CompoundState): Promise<void> {
    const fh = this.currentHandle(state);
    const pseudo = this.pseudoOf(fh);
    if (pseudo !== undefined) {
      if (pseudo === "/") throw new NfsError(NFS4.NOENT); // the root has no parent
      const parts = NfsServer.elements(pseudo).slice(0, -1);
      state.current = this.pseudoHandle(`/${parts.join("/")}`);
      return;
    }
    // The container object an export is placed on: its parent is the
    // pseudo directory holding the last component of the path the
    // entry states, and not the container object that holds it in the
    // CDMI namespace, which the export does not present.
    const above = this.pseudoAbove(fh);
    if (above !== undefined) {
      state.current = above;
      return;
    }
    const { parent, name } = this.resolveHandle(fh);
    if (name === "") throw new NfsError(NFS4.NOENT); // the root has no parent
    const meta = this.store.meta(parent);
    if (meta.parent === null) {
      state.current = this.store.rootHandle();
      return;
    }
    const grand: Node = { id: meta.parent, isContainer: true };
    state.current = this.store.handle(grand, meta.name);
  }

  // -----------------------------------------------------------------
  // Attributes

  /** The metadata of an object of the store, where the object is one. */
  private storedMeta(ref: ObjRef): Record<string, unknown> | undefined {
    const node = nodeOf(ref);
    return node ? this.store.meta(node).metadata : undefined;
  }

  /**
   * The destination a symbolic link created through this export names,
   * or nothing where this CDMI server cannot express one. An absolute
   * URI is the destination; a relative path that resolves within the
   * exported namespace names the object at that path; a path that
   * leaves the exported namespace, and content that is neither, are
   * refused.
   */
  private destinationOf(text: string, from: string): string | undefined {
    if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(text)) return text;
    if (text.startsWith("/")) return undefined; // outside the export
    const parts = (from + text).split("/").filter((p) => p !== "" && p !== ".");
    const walked: string[] = [];
    for (const part of parts) {
      if (part === "..") {
        if (walked.length === 0) return undefined; // above the export
        walked.pop();
        continue;
      }
      walked.push(part);
    }
    return "/" + walked.join("/") + (text.endsWith("/") ? "/" : "");
  }

  /** The destination of a reference, where the object is one. */
  private referenceOf(ref: ObjRef): string | undefined {
    const node = nodeOf(ref);
    return node ? this.store.meta(node).reference : undefined;
  }

  /**
   * The text of the symbolic link that presents a reference. Where the
   * destination lies within the namespace this export presents, the
   * path of that destination relative to the link is given, so that a
   * client resolves it and reaches the object. Otherwise the
   * destination URI is given unchanged, which a client will ordinarily
   * be unable to resolve: no path is invented to make it resolvable.
   */
  private linkText(destination: string, fromNS: string): string {
    const within = localImportPath(destination);
    if (within === undefined) return destination;
    const from = fromNS.replace(/\/[^/]*$/, "/").split("/").filter(Boolean);
    const to = within.split("/").filter(Boolean);
    const isContainer = within.endsWith("/");
    let common = 0;
    while (common < from.length && common < to.length && from[common] === to[common]) {
      common++;
    }
    const up = from.length - common;
    const parts = [...Array.from({ length: up }, () => ".."), ...to.slice(common)];
    if (parts.length === 0) return ".";
    return parts.join("/") + (isContainer ? "/" : "");
  }

  private async attrsOf(ref: ObjRef, handle: Buffer, parent: View,
    name: string): Promise<NfsAttrs> {
    const v = viewOf(this.store, ref);
    const node = nodeOf(ref);
    const domain = this.opts.domain ?? "localdomain";
    // An object of an imported file system has no row of the store, so
    // its fileid comes from the handle it was issued.
    const fileid = node ? BigInt(node.id) : fileidOfHandle(handle);
    let numlinks = 1;
    if (v.isContainer && node) {
      // A directory counts itself, its parent, and each subdirectory.
      numlinks = 2 + this.store.subdirCount(node);
    }
    // A reference is presented as a symbolic link whose text is its
    // destination, so its size is the length of that text.
    const destination = this.referenceOf(ref);
    const text = destination === undefined
      ? undefined
      : this.linkText(destination, parent.ns + name);
    return {
      type: text !== undefined ? NF4LNK : v.isContainer ? NF4DIR : NF4REG,
      change: BigInt(v.version),
      // Where the object states an assigned size, that is the size
      // reported through this export. The server is not required to
      // reserve the space, so it may exceed what the value consumes.
      size: text === undefined
        ? BigInt(assignedSizeOf(v, this.storedMeta(ref)))
        : BigInt(Buffer.byteLength(text, "utf8")),
      fileid,
      // One file system: seedmi presents one namespace, and an imported
      // one is not crossed as a separate file system yet.
      fsid: { major: 1n, minor: 1n },
      handle,
      mode: text !== undefined ? 0o777 : v.isContainer ? 0o755 : 0o644,
      // An object of the store holds user metadata; one of an
      // imported file system holds none.
      xattrSupport: nodeOf(ref) !== undefined,
      numlinks,
      owner: v.owner && v.owner !== "" ? v.owner : `0@${domain}`,
      ownerGroup: `0@${domain}`,
      atime: v.atime ?? Date.now(),
      mtime: v.mtime ?? Date.now(),
      ctime: v.ctime ?? Date.now(),
    };
    void parent;
    void name;
  }

  /**
   * The attributes a principal may read. An NFS attribute is derived
   * either from a CDMI metadata item, which READ_METADATA governs, or
   * from a field of the representation, which READ_ATTRIBUTES governs.
   * An attribute the principal may not read is left out of the bitmap
   * returned, which is how NFS says an attribute was not supplied.
   */
  private permittedAttrs(requested: number[], here: { ref: ObjRef; parent: View },
    state: CompoundState): number[] {
    const mayMetadata = this.mayRead(here, state, M.READ_METADATA);
    const mayAttributes = this.mayRead(here, state, M.READ_ATTRIBUTES);
    return requested.filter((bit) =>
      FROM_METADATA.has(bit) ? mayMetadata : mayAttributes);
  }

  private async getattr(r: XDRReader, w: XDRWriter, state: CompoundState): Promise<void> {
    const requested = r.bitmap();
    const fh = this.currentHandle(state);
    const pseudo = this.pseudoOf(fh);
    if (pseudo !== undefined) {
      writeAttrs(w, requested, this.pseudoAttrs(pseudo, fh));
      return;
    }
    const here = await this.at(fh);
    const permitted = this.permittedAttrs(requested, here, state);
    if (permitted.length === 0 && requested.length > 0) {
      // Nothing the client asked for may be read.
      throw new NfsError(NFS4.ACCESS);
    }
    const attrs = await this.attrsOf(here.ref, fh, here.parent, here.name);
    writeAttrs(w, permitted, attrs);
  }

  /** Whether the principal is granted a bit on what a handle names. */
  private mayRead(here: { ref: ObjRef; parent: View }, state: CompoundState,
    bit: number): boolean {
    const node = nodeOf(here.ref) ?? nodeOf(here.parent.held) ??
      here.parent.importGovernor;
    if (!node) return false;
    const m = this.store.meta(node);
    const delegated = delegatedMask(m.objectID);
    if (delegated !== undefined) return (delegated & bit) === bit;
    return granted(m.acl, state.principal, bit, {
      owner: m.owner,
      group: m.group,
      isContainer: viewOf(this.store, here.ref).isContainer,
      isRoot: m.parent === null,
    });
  }

  private async access(r: XDRReader, w: XDRWriter, state: CompoundState): Promise<void> {
    const wanted = r.uint();
    const pseudo = this.pseudoOf(this.currentHandle(state));
    if (pseudo !== undefined) {
      // A pseudo directory is read and traversed by everyone, and
      // holds no object that may be made, changed or removed.
      w.uint(wanted);
      w.uint(wanted & (ACCESS4.READ | ACCESS4.LOOKUP));
      return;
    }
    const here = await this.at(this.currentHandle(state));
    const isContainer = viewOf(this.store, here.ref).isContainer;
    let allowed = 0;
    const check = (accessBit: number, mask: number) => {
      if ((wanted & accessBit) !== 0 && this.mayRead(here, state, mask)) {
        allowed |= accessBit;
      }
    };
    if (isContainer) {
      check(ACCESS4.READ, M.LIST_CONTAINER);
      check(ACCESS4.LOOKUP, M.LIST_CONTAINER);
      check(ACCESS4.MODIFY, M.ADD_OBJECT);
      check(ACCESS4.EXTEND, M.ADD_SUBCONTAINER);
      check(ACCESS4.DELETE, M.DELETE_SUBCONTAINER);
    } else {
      check(ACCESS4.READ, M.READ_OBJECT);
      check(ACCESS4.MODIFY, M.WRITE_OBJECT);
      check(ACCESS4.EXTEND, M.APPEND_DATA);
      check(ACCESS4.EXECUTE, M.EXECUTE);
    }
    // The bits this server is able to answer for, which is every bit it
    // was asked about.
    w.uint(wanted);
    w.uint(allowed);
  }

  // -----------------------------------------------------------------
  // Reading

  private async read(r: XDRReader, w: XDRWriter, state: CompoundState): Promise<void> {
    r.fixed(4 + 12); // the stateid: a special one, since nothing is open
    const offset = r.uhyper();
    const count = r.uint();
    const here = await this.at(this.currentHandle(state));
    const v = viewOf(this.store, here.ref);
    if (v.isContainer) throw new NfsError(NFS4.ISDIR);
    if (this.referenceOf(here.ref) !== undefined) {
      // A symbolic link is read with READLINK and not with READ.
      throw new NfsError(NFS4.INVAL);
    }
    if (!this.mayRead(here, state, M.READ_OBJECT)) throw new NfsError(NFS4.ACCESS);

    const want = Math.min(count, MAXREAD);
    const start = Number(offset);
    const data = await readValueOf(this.store, here.ref, start, want);
    const eof = start + data.length >= v.size;
    w.bool(eof);
    w.opaque(data);
  }

  // -----------------------------------------------------------------
  // Extended attributes, which present the user metadata of an object
  //
  // The name of an extended attribute is the name of the user metadata
  // item within the "user." namespace, which is the name the CDMI
  // clause gives. RFC 8276 carries a key the client and the server
  // shall not interpret, so the prefix a POSIX client uses reaches
  // this server unchanged.

  /** The object an extended attribute operation addresses. */
  private async xattrTarget(state: CompoundState): Promise<{
    node: Node;
    meta: Meta;
    at: { ref: ObjRef; parent: View };
  }> {
    const at = await this.at(this.currentHandle(state));
    const node = nodeOf(at.ref);
    if (!node) {
      // An object of an imported file system holds no user metadata.
      throw new NfsError(NFS4.NOTSUPP);
    }
    return { node, meta: this.store.meta(node), at };
  }

  /**
   * Whether a name may be presented as an extended attribute. A name
   * beginning with "cdmi_" is reserved by the draft, and an item whose
   * value is not a JSON string has no encoding as one.
   */
  private presentableItem(name: string, value: unknown): boolean {
    return !name.startsWith("cdmi_") && typeof value === "string";
  }

  /**
   * The user metadata item an extended attribute key names, or nothing
   * where the key is not one. A key of another namespace has no item:
   * this document maps the user namespace alone.
   */
  private itemOf(key: string): string | undefined {
    if (!key.startsWith(XATTR_PREFIX)) return undefined;
    return key.slice(XATTR_PREFIX.length);
  }

  private async getxattr(r: XDRReader, w: XDRWriter,
    state: CompoundState): Promise<void> {
    const key = r.string(MAXNAME);
    const { node, meta, at } = await this.xattrTarget(state);
    if (!this.mayRead(at, state, M.READ_METADATA)) throw new NfsError(NFS4.ACCESS);
    void node;
    const name = this.itemOf(key);
    if (name === undefined) throw new NfsError(NFS4.NOXATTR);
    const value = meta.metadata[name];
    if (!this.presentableItem(name, value)) throw new NfsError(NFS4.NOXATTR);
    w.opaque(Buffer.from(String(value), "utf8"));
  }

  private async setxattr(r: XDRReader, w: XDRWriter,
    state: CompoundState): Promise<void> {
    const option = r.uint();
    const key = r.string(MAXNAME);
    const value = r.opaque();
    const { node, meta, at } = await this.xattrTarget(state);
    const name = this.itemOf(key);
    // An extended attribute of another namespace has no user metadata
    // item to hold it, and a name reserved by the draft is not created
    // or changed on account of one.
    if (name === undefined) throw new NfsError(NFS4.NOTSUPP);
    if (name.startsWith("cdmi_")) throw new NfsError(NFS4.ACCESS);
    if (!this.mayRead(at, state, M.WRITE_METADATA)) throw new NfsError(NFS4.ACCESS);
    // The metadata of an object under retention or under hold is part of what
    // is held: "the object shall not be modified ... A CDMI server shall report
    // the conflict condition for an operation that changes the value of such an
    // object, or that changes its metadata".
    this.refuseRestricted(node);
    const exists = typeof meta.metadata[name] === "string";
    if (option === SETXATTR4_CREATE && exists) throw new NfsError(NFS4.EXIST);
    if (option === SETXATTR4_REPLACE && !exists) throw new NfsError(NFS4.NOXATTR);
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(value);
    } catch {
      // A value that is not valid UTF-8 has no user metadata item.
      throw new NfsError(NFS4.INVAL);
    }
    const before = BigInt(meta.version);
    meta.metadata[name] = text;
    this.store.setMeta(node, meta);
    this.writeChangeInfo(w, before, BigInt(this.store.meta(node).version));
  }

  private async listxattrs(r: XDRReader, w: XDRWriter,
    state: CompoundState): Promise<void> {
    const cookie = Number(r.uhyper());
    const maxcount = r.uint();
    const { meta, at } = await this.xattrTarget(state);
    if (!this.mayRead(at, state, M.READ_METADATA)) throw new NfsError(NFS4.ACCESS);
    const all = Object.keys(meta.metadata)
      .filter((n) => this.presentableItem(n, meta.metadata[n]))
      .sort()
      .map((n) => XATTR_PREFIX + n);

    // The maximum count bounds the whole result, the encoding
    // included: the cookie, the count of names, each name, and the end
    // of file flag.
    let size = 8 + 4 + 4;
    const names: string[] = [];
    let eof = true;
    for (let i = cookie; i < all.length; i++) {
      const encoded = 4 + Math.ceil(Buffer.byteLength(all[i], "utf8") / 4) * 4;
      if (size + encoded > maxcount) {
        if (names.length === 0) {
          // Not one name fits within the limit the client gave.
          throw new NfsError(NFS4.TOOSMALL);
        }
        eof = false;
        break;
      }
      size += encoded;
      names.push(all[i]);
    }
    w.uhyper(BigInt(cookie + names.length));
    w.uint(names.length);
    for (const n of names) w.string(n);
    w.bool(eof);
  }

  private async removexattr(r: XDRReader, w: XDRWriter,
    state: CompoundState): Promise<void> {
    const key = r.string(MAXNAME);
    const { node, meta, at } = await this.xattrTarget(state);
    const name = this.itemOf(key);
    if (name === undefined) throw new NfsError(NFS4.NOTSUPP);
    if (name.startsWith("cdmi_")) throw new NfsError(NFS4.ACCESS);
    if (!this.mayRead(at, state, M.WRITE_METADATA)) throw new NfsError(NFS4.ACCESS);
    // As for setting one: the metadata of a held object is part of what is held.
    this.refuseRestricted(node);
    if (!this.presentableItem(name, meta.metadata[name])) {
      throw new NfsError(NFS4.NOXATTR);
    }
    const before = BigInt(meta.version);
    delete meta.metadata[name];
    this.store.setMeta(node, meta);
    this.writeChangeInfo(w, before, BigInt(this.store.meta(node).version));
  }

  private async readlink(w: XDRWriter, state: CompoundState): Promise<void> {
    const here = await this.at(this.currentHandle(state));
    const destination = this.referenceOf(here.ref);
    if (destination === undefined) {
      // The object is not a symbolic link.
      throw new NfsError(viewOf(this.store, here.ref).isContainer
        ? NFS4.ISDIR
        : NFS4.INVAL);
    }
    w.string(this.linkText(destination, here.parent.ns + here.name));
  }

  private async readdir(r: XDRReader, w: XDRWriter, state: CompoundState): Promise<void> {
    const cookie = r.uhyper();
    const cookieverf = r.fixed(8);
    r.uint(); // dircount, a hint
    const maxcount = r.uint();
    const requested = r.bitmap();

    const pseudo = this.pseudoOf(this.currentHandle(state));
    if (pseudo !== undefined) {
      return this.readdirPseudo(w, pseudo, cookie, cookieverf, maxcount, requested);
    }
    const here = await this.at(this.currentHandle(state));
    if (!here.view) throw new NfsError(NFS4.NOTDIR);
    if (!this.mayRead(here, state, M.LIST_CONTAINER)) throw new NfsError(NFS4.ACCESS);

    // The verifier is the time the server started: a cookie from an
    // earlier run of the server is not valid in this one.
    const verifier = Buffer.alloc(8);
    verifier.writeBigUInt64BE(BigInt(this.serverStart));
    if (cookie !== 0n && !cookieverf.equals(verifier)) {
      throw new NfsError(NFS4.BAD_COOKIE);
    }

    // A reference is presented as a symbolic link, under its own name:
    // the question mark of a CDMI listing has no meaning here.
    const kids = await listChildren(this.store, here.view, "plain");
    // A cookie is the position of the entry that follows it. Zero, one
    // and two are reserved, so the first entry has cookie three.
    const first = cookie === 0n ? 0 : Number(cookie) - 2;
    if (first < 0 || first > kids.length) throw new NfsError(NFS4.BAD_COOKIE);

    const holder = nodeOf(here.view.held);
    const entries = new XDRWriter();
    let written = 0;
    let sent = 0;
    let eof = true;
    for (let i = first; i < kids.length; i++) {
      const kid = kids[i];
      const name = kid.endsWith("/") ? kid.slice(0, -1) : kid;
      const entry = new XDRWriter();
      entry.bool(true); // an entry follows
      entry.uhyper(BigInt(i + 3));
      entry.string(name);
      const handle = holder ? this.store.handle(holder, name) : Buffer.alloc(0);
      const child = await this.at(handle).catch(() => undefined);
      if (child) {
        writeAttrs(entry, this.permittedAttrs(requested, child, state),
          await this.attrsOf(child.ref, handle, here.view, name));
      } else {
        // The attributes cannot be obtained: the client is told which
        // entry it was, and why, through rdattr_error.
        writeAttrs(entry, requested.filter((b) => b === FATTR4.RDATTR_ERROR), {
          rdattrError: NFS4.IO,
        } as NfsAttrs);
      }
      const bytes = entry.bytes();
      if (written + bytes.length > maxcount - 64 && sent > 0) {
        eof = false;
        break;
      }
      entries.raw(bytes);
      written += bytes.length;
      sent++;
    }
    w.fixed(verifier);
    w.raw(entries.bytes());
    w.bool(false); // no further entry
    w.bool(eof);
  }

  /**
   * Lists a pseudo directory: the next component of each export path
   * that continues below it. Where a component is the last of a path,
   * the entry is the container object the export presents, and its
   * attributes are that object's.
   */
  private async readdirPseudo(w: XDRWriter, path: string, cookie: bigint,
    cookieverf: Buffer, maxcount: number, requested: number[]): Promise<void> {
    const verifier = Buffer.alloc(8);
    verifier.writeBigUInt64BE(BigInt(this.serverStart));
    if (cookie !== 0n && !cookieverf.equals(verifier)) {
      throw new NfsError(NFS4.BAD_COOKIE);
    }
    const kids = this.pseudoChildren(path);
    const first = cookie === 0n ? 0 : Number(cookie) - 2;
    if (first < 0 || first > kids.length) throw new NfsError(NFS4.BAD_COOKIE);

    const entries = new XDRWriter();
    let written = 0;
    let sent = 0;
    let eof = true;
    for (let i = first; i < kids.length; i++) {
      const kid = kids[i];
      const below = path === "/" ? `/${kid.name}` : `${path}/${kid.name}`;
      const entry = new XDRWriter();
      entry.bool(true);
      entry.uhyper(BigInt(i + 3));
      entry.string(kid.name);
      const shared = kid.export === undefined ? undefined : this.exportAt(below);
      let wrote = false;
      if (shared !== undefined) {
        try {
          const handle = this.handleOfNs(shared.ns);
          const child = await this.at(handle);
          writeAttrs(entry, requested.filter((b) => SUPPORTED_ATTRS.includes(b)),
            await this.attrsOf(child.ref, handle, child.parent, kid.name));
          wrote = true;
        } catch {
          // The exported container object has gone: the name is
          // presented and its attributes are not.
          writeAttrs(entry, requested.filter((b) => b === FATTR4.RDATTR_ERROR),
            { rdattrError: NFS4.IO } as NfsAttrs);
          wrote = true;
        }
      }
      if (!wrote) {
        writeAttrs(entry, requested, this.pseudoAttrs(below,
          this.pseudoHandle(below)));
      }
      const bytes = entry.bytes();
      if (written + bytes.length > maxcount - 64 && sent > 0) {
        eof = false;
        break;
      }
      entries.raw(bytes);
      written += bytes.length;
      sent++;
    }
    w.fixed(verifier);
    w.raw(entries.bytes());
    w.bool(false);
    w.bool(eof);
  }

  // -----------------------------------------------------------------
  // Writing
  //
  // A write through NFS is an ordinary CDMI update: it is directed to
  // the write target of the presented namespace, an object below that
  // target is copied up first, and an object held by a layer above it
  // is not changed at all.

  /** The parent view and name a handle names, for an operation that writes. */
  private async writable(fh: Buffer): Promise<{
    parent: View;
    name: string;
    found?: Awaited<ReturnType<typeof resolveFile>>;
  }> {
    const { parent, name } = this.resolveHandle(fh);
    if (name === "") throw new NfsError(NFS4.ISDIR);
    const r = new Resolver(this.store);
    let pv: View;
    try {
      pv = await r.view(this.store.pathOf(parent));
    } catch {
      throw new NfsError(NFS4.STALE);
    }
    const found = await resolveFile(this.store, pv, name);
    return { parent: pv, name, found };
  }

  /** The view of the container a handle names, for a create or a delete. */
  private async directory(fh: Buffer): Promise<View> {
    const here = await this.at(fh);
    if (!here.view) throw new NfsError(NFS4.NOTDIR);
    return here.view;
  }

  /** The change attribute of a container, for change_info4. */
  private changeOf(v: View): bigint {
    const node = nodeOf(v.held);
    return node ? BigInt(this.store.meta(node).version) : 0n;
  }

  private writeChangeInfo(w: XDRWriter, before: bigint, after: bigint): void {
    // The change is not atomic with the operation: seedmi reads the
    // value before and after rather than within one transaction.
    w.bool(false);
    w.uhyper(before);
    w.uhyper(after);
  }

  private async open(r: XDRReader, w: XDRWriter, state: CompoundState): Promise<void> {
    r.uint(); // seqid, which a session makes unnecessary
    const shareAccess = r.uint();
    r.uint(); // share_deny: this server enforces no share reservation
    const clientid = r.uhyper();
    const owner = r.opaque(1024);
    const openType = r.uint();
    let createMode = UNCHECKED4;
    let createAttrs: number[] = [];
    if (openType === OPEN4_CREATE) {
      createMode = r.uint();
      if (createMode === EXCLUSIVE4) {
        r.fixed(8); // the verifier
      } else if (createMode === EXCLUSIVE4_1) {
        r.fixed(8);
        createAttrs = r.bitmap();
        r.opaque();
      } else {
        createAttrs = r.bitmap();
        r.opaque();
      }
    }
    const claim = r.uint();
    if (claim !== CLAIM_NULL) throw new NfsError(NFS4.NOTSUPP);
    const name = r.string(MAXNAME);
    void createAttrs;

    const dir = await this.directory(this.currentHandle(state));
    const holder = nodeOf(dir.held);
    if (!holder) throw new NfsError(NFS4.NOTSUPP);
    const before = this.changeOf(dir);

    let found = await resolveFile(this.store, dir, name);
    if (found && createMode === GUARDED4 && openType === OPEN4_CREATE) {
      throw new NfsError(NFS4.EXIST);
    }
    if (!found) {
      if (openType !== OPEN4_CREATE) throw new NfsError(NFS4.NOENT);
      await this.createFile(dir, name, state);
      found = await resolveFile(this.store, dir, name);
      if (!found) throw new NfsError(NFS4.SERVERFAULT);
    }

    const handle = this.store.handle(holder, name);
    const other = randomBytes(12);
    const open: OpenState = { other, seqid: 1, handle, shareAccess, clientid };
    this.opens.set(other.toString("hex"), open);

    state.current = handle;
    w.uint(open.seqid);
    w.fixed(other);
    this.writeChangeInfo(w, before, this.changeOf(await this.directory(
      this.store.handle(holder, ""))));
    w.uint(0); // no result flags
    w.bitmap([]); // no attribute was set
    w.uint(OPEN_DELEGATE_NONE);
    void owner;
  }

  /** Creates an empty data object at a name, by the CDMI write rules. */
  private async createFile(dir: View, name: string, state: CompoundState): Promise<void> {
    if (!this.mayCreate(dir, state, M.ADD_OBJECT)) throw new NfsError(NFS4.ACCESS);
    const image = await ensureImageWriteTarget(dir);
    if (image) {
      if (!storableName(name)) throw new NfsError(NFS4.INVAL);
      await image.fs.createFile(image.cluster, name);
      await flushImage(this.store, image.fs);
      return;
    }
    const target = await ensureWriteTarget(this.store, dir);
    if (this.store.tryLookup(target, name)) throw new NfsError(NFS4.EXIST);
    this.store.createData(target, name, {
      acl: aclForNewObject(undefined, this.store.meta(target).acl, false),
    });
  }

  /** Whether the principal may create within a container. */
  private mayCreate(dir: View, state: CompoundState, bit: number): boolean {
    const node = nodeOf(dir.held) ?? dir.importGovernor;
    if (!node) return false;
    const m = this.store.meta(node);
    return granted(m.acl, state.principal, bit, {
      owner: m.owner,
      group: m.group,
      isContainer: true,
      isRoot: m.parent === null,
    });
  }

  private closeOpen(r: XDRReader, w: XDRWriter, state: CompoundState): void {
    r.uint(); // seqid
    const seqid = r.uint();
    const other = r.fixed(12);
    const open = this.opens.get(other.toString("hex"));
    if (!open) throw new NfsError(NFS4.BAD_STATEID);
    this.opens.delete(other.toString("hex"));
    // The stateid returned is the one supplied with its sequence moved
    // on, which marks it as closed.
    w.uint(seqid + 1);
    w.fixed(other);
    void state;
  }

  /** The open a stateid names, where it names one. */
  private openOf(r: XDRReader): OpenState | undefined {
    r.uint(); // the sequence of the stateid
    const other = r.fixed(12);
    if (other.every((b: number) => b === 0)) return undefined; // the anonymous stateid
    return this.opens.get(other.toString("hex"));
  }

  private async write(r: XDRReader, w: XDRWriter, state: CompoundState): Promise<void> {
    const open = this.openOf(r);
    const offset = r.uhyper();
    r.uint(); // stable_how: seedmi commits every write before it replies
    const data = r.opaque(MAXWRITE);
    if (open && (open.shareAccess & OPEN4_SHARE_ACCESS_WRITE) === 0) {
      throw new NfsError(NFS4.OPENMODE);
    }

    const fh = this.currentHandle(state);
    const { parent, name, found } = await this.writable(fh);
    if (!found) throw new NfsError(NFS4.NOENT);
    const node = await this.forWriting(parent, name, found, state);
    await this.applyWrite(node, found, Number(offset), data);

    w.uint(data.length);
    w.uint(FILE_SYNC4);
    w.fixed(this.writeVerifier());
  }

  /**
   * Refuses an operation that would delete or modify an object under retention
   * or under hold.
   *
   * "A rule of this document that governs what may be done to an object governs
   * a request that reaches that object through an export as it governs an
   * operation of a protocol binding. The retention and hold rules ... apply, so
   * that a request through an export that would delete or modify an object
   * under retention or under hold is refused, however the exported protocol
   * expresses that request" (exports model, revision 365). Until 0.109 this
   * server enforced retention through the protocol binding and through an SMB
   * export and not through this one: an NFS client wrote to an object under
   * retention, and then removed it, and both were answered NFS4_OK.
   *
   * NFS defines no error for the refusal, so NFS4ERR_ACCESS reports it, as
   * ACCESS_DENIED does for an SMB export. It is not a permission the client
   * lacks — the same request succeeds once the period has passed — but it is
   * the error an NFS client treats as final, and the alternative of
   * NFS4ERR_PERM names an owner check that is not what happened.
   */
  private refuseRestricted(node: Node): void {
    let metadata: Record<string, unknown>;
    try {
      metadata = this.store.meta(node).metadata;
    } catch {
      return;
    }
    if (underRestriction(metadata)) throw new NfsError(NFS4.ACCESS);
  }

  /**
   * Whether an object within a container object, at any depth, is under
   * retention or under hold. "A container object is not deleted while an object
   * it contains, at any depth, is under retention or under hold ... whatever the
   * access control lists permit and whether or not that container object is
   * itself under retention or under hold."
   */
  private restrictedWithin(node: Node): boolean {
    return restrictedWithin(node,
      (x) => this.store.children(x)
        .map((c) => ({ name: c.name, node: c.node, isContainer: c.node.isContainer })),
      (x) => this.store.meta(x).metadata) !== undefined;
  }

  /**
   * The object a write acts on: the one presented, copied up into the
   * write target first where it is held below it, and refused where a
   * layer above the write target holds it.
   */
  private async forWriting(parent: View, name: string,
    found: NonNullable<Awaited<ReturnType<typeof resolveFile>>>,
    state: CompoundState): Promise<Node | undefined> {
    const ns = parent.ns + name;
    if (!this.mayRead({ ref: found.ref, parent }, state, M.WRITE_OBJECT)) {
      throw new NfsError(NFS4.ACCESS);
    }
    if (parent.writeRank === undefined) throw new NfsError(NFS4.ROFS);
    const cmp = rankCmp(found.layer.rank, parent.writeRank);
    if (cmp < 0) {
      // A layer above the write target holds it, and the denial is not
      // remedied: the object cannot be changed at all.
      void denyChange(parent, ns, found.layer.rank, "write");
      throw new NfsError(NFS4.ACCESS);
    }
    if (found.ref.kind === "image") {
      if (cmp !== 0) throw new NfsError(NFS4.ACCESS);
      return undefined; // written in place, within the file system
    }
    const node = nodeOf(found.ref)!;
    // A write and a truncation both reach here, and neither is performed on an
    // object under retention or under hold. An object below the write target is
    // copied up, and the copy is a new object under neither, so the judgement is
    // made on the object presented and not on the copy.
    this.refuseRestricted(node);
    if (cmp === 0) return node;
    // Below the write target: the object is copied up, and the copy is
    // what the write changes.
    const target = await ensureWriteTarget(this.store, parent);
    return this.store.copyUp(node, target, name);
  }

  private async applyWrite(node: Node | undefined,
    found: NonNullable<Awaited<ReturnType<typeof resolveFile>>>,
    offset: number, data: Buffer): Promise<void> {
    if (node) {
      await this.store.writeValue(node, offset, data);
      return;
    }
    if (found.ref.kind !== "image") throw new NfsError(NFS4.SERVERFAULT);
    await found.ref.fs.writeFile(found.ref.dir, found.ref.entry, offset, data);
    await flushImage(this.store, found.ref.fs);
  }

  /** Every write is committed before the reply, so the verifier is fixed. */
  private writeVerifier(): Buffer {
    const v = Buffer.alloc(8);
    v.writeBigUInt64BE(BigInt(this.serverStart));
    return v;
  }

  private async commit(r: XDRReader, w: XDRWriter, state: CompoundState): Promise<void> {
    r.uhyper(); // offset
    r.uint(); // count
    // Every write is committed before its reply, so a commit has nothing
    // to do and the verifier it returns is the one the writes carried.
    void await this.at(this.currentHandle(state));
    w.fixed(this.writeVerifier());
  }

  private async setattr(r: XDRReader, w: XDRWriter, state: CompoundState): Promise<void> {
    this.openOf(r);
    const requested = r.bitmap();
    const values = new XDRReader(r.opaque());
    const set: number[] = [];
    let size: bigint | undefined;
    for (const bit of requested.slice().sort((a, b) => a - b)) {
      if (!SETTABLE_ATTRS.includes(bit)) {
        // An attribute this server does not set at all.
        throw new NfsError(NFS4.NOTSUPP);
      }
      if (bit === FATTR4.SIZE) {
        size = values.uhyper();
        set.push(bit);
      }
    }
    if (size !== undefined) {
      const fh = this.currentHandle(state);
      const { parent, name, found } = await this.writable(fh);
      if (!found) throw new NfsError(NFS4.NOENT);
      const node = await this.forWriting(parent, name, found, state);
      if (node) {
        await this.store.truncateValue(node, Number(size));
      } else if (found.ref.kind === "image") {
        await found.ref.fs.truncateFile(found.ref.dir, found.ref.entry, Number(size));
        await flushImage(this.store, found.ref.fs);
      }
    }
    w.bitmap(set);
  }

  private async create(r: XDRReader, w: XDRWriter, state: CompoundState): Promise<void> {
    const type = r.uint();
    // A symbolic link creates a reference. Where its content is an
    // absolute URI the destination is that URI; where it is a relative
    // path that resolves within the exported container object, the
    // destination is the object that path names. A path that resolves
    // outside it, and content that is neither, are refused: a CDMI
    // server does not store content whose destination it cannot
    // express.
    let linkdata: string | undefined;
    if (type === NF4LNK) {
      linkdata = r.string(MAXNAME * 4);
    } else if (type !== NF4DIR) {
      throw new NfsError(NFS4.BADTYPE);
    }
    const name = r.string(MAXNAME);
    r.bitmap();
    r.opaque(); // the attributes, which this server does not set on create

    const dir = await this.directory(this.currentHandle(state));
    const before = this.changeOf(dir);
    if (!this.mayCreate(dir, state, M.ADD_SUBCONTAINER)) throw new NfsError(NFS4.ACCESS);
    const holder = nodeOf(dir.held);
    if (!holder) throw new NfsError(NFS4.NOTSUPP);

    if (linkdata !== undefined) {
      const destination = this.destinationOf(linkdata, dir.ns);
      if (destination === undefined) throw new NfsError(NFS4.INVAL);
      linkdata = destination;
      // A reference is an object of the store alone.
      const target = await ensureWriteTarget(this.store, dir);
      if (this.store.tryLookup(target, name)) throw new NfsError(NFS4.EXIST);
      this.store.createReference(target, name, linkdata, {
        acl: aclForNewObject(undefined, this.store.meta(target).acl, false),
      });
      state.current = this.store.handle(holder, name);
      this.writeChangeInfo(w, before,
        this.changeOf(await this.directory(this.store.handle(holder, ""))));
      w.bitmap([]);
      return;
    }
    const image = await ensureImageWriteTarget(dir);
    if (image) {
      if (!storableName(name)) throw new NfsError(NFS4.INVAL);
      if (await image.fs.find(image.cluster, name)) throw new NfsError(NFS4.EXIST);
      await image.fs.createDirectory(image.cluster, name);
      await flushImage(this.store, image.fs);
    } else {
      const target = await ensureWriteTarget(this.store, dir);
      if (this.store.tryLookup(target, name)) throw new NfsError(NFS4.EXIST);
      this.store.createContainer(target, name, {
        acl: aclForNewObject(undefined, this.store.meta(target).acl, true),
      });
    }
    state.current = this.store.handle(holder, name);
    this.writeChangeInfo(w, before,
      this.changeOf(await this.directory(this.store.handle(holder, ""))));
    w.bitmap([]);
  }

  private async remove(r: XDRReader, w: XDRWriter, state: CompoundState): Promise<void> {
    const name = r.string(MAXNAME);
    if (name === "" || name === "." || name === "..") throw new NfsError(NFS4.INVAL);
    const dir = await this.directory(this.currentHandle(state));
    const before = this.changeOf(dir);
    if (dir.writeRank === undefined) throw new NfsError(NFS4.ROFS);

    const found = await resolveFile(this.store, dir, name);
    if (found) {
      if (!this.mayCreate(dir, state, M.DELETE_OBJECT)) throw new NfsError(NFS4.ACCESS);
      if (rankCmp(found.layer.rank, dir.writeRank) !== 0) throw new NfsError(NFS4.ACCESS);
      // An object under retention or under hold is not deleted, whatever the
      // access control lists permit.
      const target = nodeOf(found.ref);
      if (target) this.refuseRestricted(target);
      if (found.ref.kind === "image") {
        await found.ref.fs.remove(found.ref.dir, found.ref.entry);
        await flushImage(this.store, found.ref.fs);
      } else {
        await this.store.collect(this.store.removeTree(nodeOf(found.ref)!));
      }
    } else {
      const resolver = new Resolver(this.store);
      let child: View;
      try {
        child = await resolver.child(dir, name);
      } catch {
        throw new NfsError(NFS4.NOENT);
      }
      if (!this.mayCreate(dir, state, M.DELETE_SUBCONTAINER)) {
        throw new NfsError(NFS4.ACCESS);
      }
      if (child.upper) throw new NfsError(NFS4.ACCESS);
      const wt = dir.writeNode ?? dir.writeDelegate?.writeNode;
      const here = wt ? this.store.tryLookup(wt, name) : undefined;
      if (!here || !here.isContainer) throw new NfsError(NFS4.ACCESS);
      // The container object itself, and anything it holds at any depth: an NFS
      // client removes an empty directory alone, so the second is reached only
      // where the store holds an object the export does not present.
      this.refuseRestricted(here);
      if (this.restrictedWithin(here)) throw new NfsError(NFS4.ACCESS);
      if (this.store.childCount(here) > 0) throw new NfsError(NFS4.NOTEMPTY);
      await this.store.collect(this.store.removeTree(here));
    }
    const holder = nodeOf(dir.held);
    this.writeChangeInfo(w, before, holder
      ? BigInt(this.store.meta(holder).version)
      : before);
  }

  private async rename(r: XDRReader, w: XDRWriter, state: CompoundState): Promise<void> {
    const oldName = r.string(MAXNAME);
    const newName = r.string(MAXNAME);
    if (!state.saved) throw new NfsError(NFS4.NOFILEHANDLE);
    const source = await this.directory(state.saved);
    const target = await this.directory(this.currentHandle(state));
    const sourceBefore = this.changeOf(source);
    const targetBefore = this.changeOf(target);

    const sourceNode = nodeOf(source.held);
    const targetNode = nodeOf(target.held);
    if (!sourceNode || !targetNode) throw new NfsError(NFS4.NOTSUPP);
    if (source.writeRank === undefined || target.writeRank === undefined) {
      throw new NfsError(NFS4.ROFS);
    }
    const found = await resolveFile(this.store, source, oldName);
    if (!found || found.ref.kind === "image") {
      // A rename within an imported file system, or of a container
      // object, is not performed.
      throw new NfsError(found ? NFS4.NOTSUPP : NFS4.NOENT);
    }
    if (rankCmp(found.layer.rank, source.writeRank) !== 0) throw new NfsError(NFS4.ACCESS);
    if (!this.mayCreate(source, state, M.DELETE_OBJECT) ||
      !this.mayCreate(target, state, M.ADD_OBJECT)) {
      throw new NfsError(NFS4.ACCESS);
    }
    // "A rename is neither a delete nor a create, and the retention clause
    // treats it as neither; it changes the object, so it is refused for one
    // under retention" — and the exports model now requires the refusal outright,
    // a CDMI server rejecting a request whose effect the retention subclause
    // does not state rather than permitting through an export what it would not
    // permit through a protocol binding.
    this.refuseRestricted(nodeOf(found.ref)!);
    const into = await ensureWriteTarget(this.store, target);
    if (this.store.tryLookup(into, newName)) throw new NfsError(NFS4.EXIST);
    try {
      this.store.rename(nodeOf(found.ref)!, into, newName);
    } catch {
      throw new NfsError(NFS4.EXIST);
    }
    this.writeChangeInfo(w, sourceBefore, BigInt(this.store.meta(sourceNode).version));
    this.writeChangeInfo(w, targetBefore, BigInt(this.store.meta(targetNode).version));
  }
}

// ---------------------------------------------------------------------------

function readChannelAttrs(r: XDRReader): {
  maxRequestSize: number;
  maxResponseSize: number;
  maxOperations: number;
  maxRequests: number;
} {
  r.uint(); // ca_headerpadsize
  const maxRequestSize = r.uint();
  const maxResponseSize = r.uint();
  r.uint(); // ca_maxresponsesize_cached
  const maxOperations = r.uint();
  const maxRequests = r.uint();
  r.array(() => undefined, 1); // ca_rdma_ird
  return { maxRequestSize, maxResponseSize, maxOperations, maxRequests };
}

function writeChannelAttrs(w: XDRWriter, s: Session): void {
  w.uint(0); // ca_headerpadsize
  w.uint(s.maxRequestSize);
  w.uint(s.maxResponseSize);
  w.uint(0); // nothing is cached, so no reply is held
  w.uint(s.maxOperations);
  w.uint(s.slots.length);
  w.array([], () => undefined); // no RDMA
}

/**
 * The attributes derived from a CDMI metadata item, which READ_METADATA
 * governs. Every other attribute is derived from a field of the
 * representation, which READ_ATTRIBUTES governs.
 */
const FROM_METADATA = new Set<number>([
  FATTR4.SIZE, FATTR4.SPACE_USED, FATTR4.TIME_ACCESS, FATTR4.TIME_MODIFY,
  FATTR4.TIME_METADATA, FATTR4.OWNER, FATTR4.OWNER_GROUP, FATTR4.MODE,
]);

/** The fileid of an object that has no row: taken from its handle. */
function fileidOfHandle(fh: Buffer): bigint {
  // The high bit distinguishes it from the primary key of a row.
  const low = fh.length >= 8 ? fh.readBigUInt64BE(0) : BigInt(fh.length);
  return (low & 0x7fffffffffffffffn) | 0x8000000000000000n;
}

void SUPPORTED_ATTRS;
void MAXWRITE;
void LEASE_TIME;
void OP_NAME;

/** The name of an NFS status, for a log line. */
function statusName(status: number): string {
  const found = Object.keys(NFS4).find(
    (k) => (NFS4 as unknown as Record<string, number>)[k] === status);
  return found === undefined ? String(status) : (status === 0 ? "OK" : `NFS4ERR_${found}`);
}

/** The name of an NFS operation, for a log line. */
function opName(opnum: number): string {
  const found = Object.keys(OP).find(
    (k) => (OP as unknown as Record<string, number>)[k] === opnum);
  return found ?? String(opnum);
}
