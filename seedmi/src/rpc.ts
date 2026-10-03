// ONC RPC version 2 over TCP, as RFC 5531 defines it and NFSv4 uses it.
//
// A TCP connection carries a stream of record fragments. Each fragment is
// preceded by a four-byte marker whose top bit says whether it is the last
// fragment of a record, and whose remaining 31 bits give the length of the
// fragment. A record holds one call or one reply.

import { createServer, type Server, type Socket } from "node:net";
import { XDRError, XDRReader, XDRWriter, encode } from "./xdr.ts";

export const RPC_VERSION = 2;

/** The NFS program, and the version NFSv4 uses. */
export const NFS_PROGRAM = 100003;
export const NFS_VERSION = 4;
export const NFSPROC4_NULL = 0;
export const NFSPROC4_COMPOUND = 1;

export const CALL = 0;
export const REPLY = 1;

export const MSG_ACCEPTED = 0;
export const MSG_DENIED = 1;

export const SUCCESS = 0;
export const PROG_UNAVAIL = 1;
export const PROG_MISMATCH = 2;
export const PROC_UNAVAIL = 3;
export const GARBAGE_ARGS = 4;
export const SYSTEM_ERR = 5;

export const RPC_MISMATCH = 0;
export const AUTH_ERROR = 1;

export const AUTH_NONE = 0;
export const AUTH_SYS = 1;
export const RPCSEC_GSS = 6;

export const AUTH_BADCRED = 1;
export const AUTH_TOOWEAK = 5;

/** The maximum record seedmi will assemble, so a peer cannot exhaust it. */
const MAX_RECORD = 8 << 20;

/** An AUTH_SYS credential, RFC 5531 appendix A. */
export interface AuthSys {
  stamp: number;
  machineName: string;
  uid: number;
  gid: number;
  gids: number[];
}

export interface Credential {
  flavor: number;
  /** The AUTH_SYS body, where the flavor is AUTH_SYS and it parses. */
  sys?: AuthSys;
  body: Buffer;
}

export interface RpcCall {
  xid: number;
  program: number;
  version: number;
  procedure: number;
  credential: Credential;
  verifier: Credential;
  /** A reader positioned at the arguments of the procedure. */
  args: XDRReader;
}

export function encodeAuthSys(a: AuthSys): Buffer {
  return encode((w) => {
    w.uint(a.stamp);
    w.string(a.machineName);
    w.uint(a.uid);
    w.uint(a.gid);
    w.array(a.gids, (x, g) => x.uint(g));
  });
}

export function decodeAuthSys(b: Buffer): AuthSys {
  const r = new XDRReader(b);
  return {
    stamp: r.uint(),
    machineName: r.string(255),
    uid: r.uint(),
    gid: r.uint(),
    gids: r.array((x) => x.uint(), 16),
  };
}

function writeCredential(w: XDRWriter, c: Credential): void {
  w.uint(c.flavor);
  w.opaque(c.body);
}

function readCredential(r: XDRReader): Credential {
  const flavor = r.uint();
  const body = r.opaque(400); // RFC 5531: an opaque_auth body is at most 400 bytes
  const c: Credential = { flavor, body };
  if (flavor === AUTH_SYS) {
    try {
      c.sys = decodeAuthSys(body);
    } catch {
      // A body that does not parse leaves the credential unresolved,
      // which the caller reports as AUTH_BADCRED.
    }
  }
  return c;
}

export const AUTH_NONE_VERIFIER: Credential = { flavor: AUTH_NONE, body: Buffer.alloc(0) };

/** Decodes a call message, returning a reader positioned at its arguments. */
export function decodeCall(record: Buffer): RpcCall {
  const r = new XDRReader(record);
  const xid = r.uint();
  const type = r.uint();
  if (type !== CALL) throw new XDRError(`a message of type ${type} is not a call`);
  const rpcvers = r.uint();
  if (rpcvers !== RPC_VERSION) {
    throw new RpcMismatch(xid, RPC_VERSION, RPC_VERSION);
  }
  const program = r.uint();
  const version = r.uint();
  const procedure = r.uint();
  const credential = readCredential(r);
  const verifier = readCredential(r);
  return { xid, program, version, procedure, credential, verifier, args: r };
}

/** Raised where the peer speaks a version of RPC this server does not. */
export class RpcMismatch extends Error {
  xid: number;
  low: number;
  high: number;
  constructor(xid: number, low: number, high: number) {
    super("the RPC version is not supported");
    this.xid = xid;
    this.low = low;
    this.high = high;
  }
}

/** An accepted reply carrying the results of the procedure. */
export function acceptedReply(xid: number, status: number, results?: Buffer): Buffer {
  return encode((w) => {
    w.uint(xid);
    w.uint(REPLY);
    w.uint(MSG_ACCEPTED);
    writeCredential(w, AUTH_NONE_VERIFIER);
    w.uint(status);
    if (status === PROG_MISMATCH) {
      // The versions this server supports.
      w.uint(NFS_VERSION);
      w.uint(NFS_VERSION);
    }
    if (results) w.raw(results);
  });
}

/** A denied reply: the peer's RPC version or its credential is refused. */
export function deniedReply(xid: number, reason: number, a = 0, b = 0): Buffer {
  return encode((w) => {
    w.uint(xid);
    w.uint(REPLY);
    w.uint(MSG_DENIED);
    w.uint(reason);
    if (reason === RPC_MISMATCH) {
      w.uint(a);
      w.uint(b);
    } else {
      w.uint(a); // the auth_stat
    }
  });
}

// ---------------------------------------------------------------------------
// Record marking

/** Frames a message as one record, in a single fragment. */
export function frame(message: Buffer): Buffer {
  const marker = Buffer.alloc(4);
  // The top bit marks the last fragment of the record. A bitwise or in
  // JavaScript yields a signed 32-bit value, so the result is made
  // unsigned before it is written.
  marker.writeUInt32BE((0x80000000 | message.length) >>> 0, 0);
  return Buffer.concat([marker, message]);
}

/**
 * Assembles records from a stream of fragments. Bytes arrive in whatever
 * sizes TCP gives them, so a fragment may span several chunks and a chunk
 * may hold several fragments.
 */
export class RecordAssembler {
  private pending: Buffer[] = [];
  private pendingLength = 0;
  private fragments: Buffer[] = [];
  private fragmentsLength = 0;

  /** Feeds bytes in, returning the records they complete. */
  push(chunk: Buffer): Buffer[] {
    this.pending.push(chunk);
    this.pendingLength += chunk.length;
    const records: Buffer[] = [];
    for (;;) {
      if (this.pendingLength < 4) break;
      const head = this.peek(4);
      const marker = head.readUInt32BE(0);
      const last = (marker & 0x80000000) !== 0;
      const length = marker & 0x7fffffff;
      if (length > MAX_RECORD || this.fragmentsLength + length > MAX_RECORD) {
        throw new XDRError(`a record of more than ${MAX_RECORD} bytes`);
      }
      if (this.pendingLength < 4 + length) break;
      this.consume(4);
      this.fragments.push(this.consume(length));
      this.fragmentsLength += length;
      if (last) {
        records.push(Buffer.concat(this.fragments, this.fragmentsLength));
        this.fragments = [];
        this.fragmentsLength = 0;
      }
    }
    return records;
  }

  private peek(n: number): Buffer {
    if (this.pending.length > 1) {
      this.pending = [Buffer.concat(this.pending, this.pendingLength)];
    }
    return this.pending[0].subarray(0, n);
  }

  private consume(n: number): Buffer {
    if (this.pending.length > 1) {
      this.pending = [Buffer.concat(this.pending, this.pendingLength)];
    }
    const all = this.pending[0];
    const out = Buffer.from(all.subarray(0, n));
    this.pending = [all.subarray(n)];
    this.pendingLength -= n;
    return out;
  }
}

// ---------------------------------------------------------------------------
// A server

/** What a service does with a call: return the encoded results. */
export type Dispatch = (call: RpcCall, peer: string) => Promise<Buffer> | Buffer;

export interface RpcServerOptions {
  program?: number;
  version?: number;
  /** The procedures the service implements. */
  procedures: Map<number, Dispatch>;
}

/** An ONC RPC server over TCP. */
export class RpcServer {
  readonly opts: Required<RpcServerOptions>;
  private server?: Server;

  constructor(opts: RpcServerOptions) {
    this.opts = {
      program: opts.program ?? NFS_PROGRAM,
      version: opts.version ?? NFS_VERSION,
      procedures: opts.procedures,
    };
  }

  listen(port: number, host = "127.0.0.1"): Promise<Server> {
    const server = createServer((socket: Socket) => this.serve(socket));
    this.server = server;
    return new Promise((resolve) => server.listen(port, host, () => resolve(server)));
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.server) return resolve();
      this.server.close(() => resolve());
    });
  }

  address(): { port: number; address: string } | undefined {
    const a = this.server?.address();
    return a && typeof a !== "string" ? a : undefined;
  }

  private serve(socket: Socket): void {
    socket.setNoDelay(true);
    const assembler = new RecordAssembler();
    const peer = `${socket.remoteAddress ?? "?"}:${socket.remotePort ?? 0}`;
    // Records are answered in the order they arrive, so a slow one does
    // not let a later one overtake it on the same connection.
    let queue: Promise<void> = Promise.resolve();
    socket.on("data", (chunk: Buffer) => {
      let records: Buffer[];
      try {
        records = assembler.push(chunk);
      } catch {
        socket.destroy();
        return;
      }
      for (const record of records) {
        queue = queue.then(async () => {
          const reply = await this.answer(record, peer);
          if (reply) socket.write(frame(reply));
        }).catch(() => socket.destroy());
      }
    });
    socket.on("error", () => socket.destroy());
  }

  /** Answers one record, or returns undefined where none is owed. */
  async answer(record: Buffer, peer: string): Promise<Buffer | undefined> {
    let call: RpcCall;
    try {
      call = decodeCall(record);
    } catch (err) {
      if (err instanceof RpcMismatch) {
        return deniedReply(err.xid, RPC_MISMATCH, err.low, err.high);
      }
      // A record that is not a call at all is dropped: there is no xid to
      // answer with.
      return undefined;
    }
    if (call.program !== this.opts.program) {
      return acceptedReply(call.xid, PROG_UNAVAIL);
    }
    if (call.version !== this.opts.version) {
      return acceptedReply(call.xid, PROG_MISMATCH);
    }
    // NFSv4 admits AUTH_NONE and AUTH_SYS here; RPCSEC_GSS is refused
    // because seedmi offers no Kerberos.
    if (call.credential.flavor === RPCSEC_GSS) {
      return deniedReply(call.xid, AUTH_ERROR, AUTH_TOOWEAK);
    }
    if (call.credential.flavor !== AUTH_NONE && call.credential.flavor !== AUTH_SYS) {
      return deniedReply(call.xid, AUTH_ERROR, AUTH_BADCRED);
    }
    if (call.credential.flavor === AUTH_SYS && !call.credential.sys) {
      return deniedReply(call.xid, AUTH_ERROR, AUTH_BADCRED);
    }
    const procedure = this.opts.procedures.get(call.procedure);
    if (!procedure) return acceptedReply(call.xid, PROC_UNAVAIL);
    try {
      const results = await procedure(call, peer);
      return acceptedReply(call.xid, SUCCESS, results);
    } catch (err) {
      if (err instanceof XDRError) return acceptedReply(call.xid, GARBAGE_ARGS);
      return acceptedReply(call.xid, SYSTEM_ERR);
    }
  }
}

// ---------------------------------------------------------------------------
// A client, which is how the server is tested

export interface RpcReply {
  xid: number;
  accepted: boolean;
  /** The accept_stat where accepted, or the reject_stat where not. */
  status: number;
  /** The auth_stat, where the reply was denied for a credential. */
  authStatus?: number;
  /** A reader positioned at the results. */
  results: XDRReader;
}

/** An ONC RPC client over TCP. */
export class RpcClient {
  private socket?: Socket;
  private readonly assembler = new RecordAssembler();
  private readonly waiting = new Map<number, (r: Buffer) => void>();
  private nextXid = Math.floor(Math.random() * 0x7fffffff);

  credential: Credential = AUTH_NONE_VERIFIER;

  async connect(port: number, host = "127.0.0.1"): Promise<void> {
    const { connect } = await import("node:net");
    await new Promise<void>((resolve, reject) => {
      const socket = connect(port, host, () => resolve());
      socket.on("error", reject);
      socket.on("data", (chunk: Buffer) => {
        for (const record of this.assembler.push(chunk)) {
          const xid = record.readUInt32BE(0);
          const waiter = this.waiting.get(xid);
          if (waiter) {
            this.waiting.delete(xid);
            waiter(record);
          }
        }
      });
      this.socket = socket;
    });
  }

  close(): void {
    this.socket?.end();
    this.socket?.destroy();
  }

  /** Sets an AUTH_SYS credential for the calls that follow. */
  authSys(a: Partial<AuthSys> = {}): void {
    const full: AuthSys = {
      stamp: a.stamp ?? Math.floor(Date.now() / 1000) >>> 0,
      machineName: a.machineName ?? "seedmi-client",
      uid: a.uid ?? 0,
      gid: a.gid ?? 0,
      gids: a.gids ?? [],
    };
    this.credential = { flavor: AUTH_SYS, body: encodeAuthSys(full), sys: full };
  }

  /** Makes one call and waits for its reply. */
  call(program: number, version: number, procedure: number,
    args: Buffer = Buffer.alloc(0)): Promise<RpcReply> {
    const xid = this.nextXid = (this.nextXid + 1) >>> 0;
    const message = encode((w) => {
      w.uint(xid);
      w.uint(CALL);
      w.uint(RPC_VERSION);
      w.uint(program);
      w.uint(version);
      w.uint(procedure);
      writeCredential(w, this.credential);
      writeCredential(w, AUTH_NONE_VERIFIER);
      w.raw(args);
    });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiting.delete(xid);
        reject(new Error(`no reply to call ${xid}`));
      }, 10_000);
      this.waiting.set(xid, (record) => {
        clearTimeout(timer);
        resolve(parseReply(record));
      });
      this.socket?.write(frame(message));
    });
  }
}

export function parseReply(record: Buffer): RpcReply {
  const r = new XDRReader(record);
  const xid = r.uint();
  const type = r.uint();
  if (type !== REPLY) throw new XDRError(`a message of type ${type} is not a reply`);
  const stat = r.uint();
  if (stat === MSG_DENIED) {
    const reason = r.uint();
    const detail = r.uint();
    return {
      xid,
      accepted: false,
      status: reason,
      authStatus: reason === AUTH_ERROR ? detail : undefined,
      results: r,
    };
  }
  readCredential(r); // the verifier of the reply
  const status = r.uint();
  if (status === PROG_MISMATCH) {
    r.uint();
    r.uint();
  }
  return { xid, accepted: true, status, results: r };
}
