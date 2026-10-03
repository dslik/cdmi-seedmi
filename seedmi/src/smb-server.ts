/**
 * The session layer of an SMB export: the transport, NEGOTIATE,
 * SESSION_SETUP with NTLMSSP, and TREE_CONNECT. What a connected tree
 * then serves is the work of a later phase; a command this phase does
 * not implement is answered STATUS_NOT_SUPPORTED, which is what a
 * server answers for a command it does not implement.
 */

import * as net from "node:net";
import { decideFor, DelegationRefused, withDelegation } from "./dac-context.ts";
import type { DacClient } from "./dac.ts";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  align8,
  Body,
  CAP,
  CMD,
  commandName,
  CTX,
  decodeHeader,
  DIALECTS,
  encodeHeader,
  fieldAt,
  FLAG,
  fileTime,
  frame,
  fromUtf16,
  HASH_SHA512,
  header,
  HEADER_SIZE,
  isSmb3,
  NT,
  SHARE_TYPE_DISK,
  SIGNING_ENABLED,
  SIGNING_REQUIRED,
  statusName,
  unframe,
  utf16,
  type Header,
} from "./smb-wire.ts";
import {
  preauthHash,
  PREAUTH_ZERO,
  sign,
  signingKey,
  verifySignature,
} from "./smb-crypto.ts";
import { SmbFs, SmbStatus, type Entry, type Mount } from "./smb-fs.ts";
import type { Log } from "./log.ts";
import {
  allocationOf,
  directoryBuffer,
  directoryEntry,
  encodeFullEas,
  decodeFullEas,
  FILE_CLASS,
  fileInformation,
  filesystemInformation,
  INFO_TYPE,
} from "./smb-info.ts";
import { ANONYMOUS, M, type Principal } from "./acl.ts";
import {
  aclFromDescriptor,
  FSCTL,
  readSymlinkReparseData,
  SmbDescriptorError,
  UnmappedSid,
  securityDescriptor,
  SECURITY_INFORMATION,
  STATUS_STOPPED_ON_SYMLINK,
  symlinkErrorResponse,
  symlinkReparseData,
} from "./smb-security.ts";
import {
  challengeMessage,
  isAnonymous,
  isNtlmssp,
  NEGOTIATE_FLAGS,
  ntlmType,
  readAuthenticate,
  verify,
} from "./ntlm.ts";

/** A share the server offers, being one SMB export entry. */
export interface Share {
  /** The share name, matched without regard to case. */
  name: string;
  /** The dialects the entry offers, as revision numbers. */
  dialects: number[];
  /** Whether every connection to this share signs its messages. */
  signingRequired: boolean;
  /** Whether an unauthenticated client is admitted, read-only. */
  anonymous: boolean;
  /** The container object the share presents, and the store holding it. */
  mount?: Mount;
}

/** The dispositions of a CREATE, of [MS-SMB2] section 2.2.13. */
const DISPOSITION = {
  SUPERSEDE: 0x00000000,
  OPEN: 0x00000001,
  CREATE: 0x00000002,
  OPEN_IF: 0x00000003,
  OVERWRITE: 0x00000004,
  OVERWRITE_IF: 0x00000005,
} as const;

/**
 * The two bits a client requests and is not granted, of [MS-DTYP]
 * section 2.4.3. Neither appears in an answer.
 */
const MAXIMUM_ALLOWED = 0x02000000;
const ACCESS_SYSTEM_SECURITY = 0x01000000;

/** The actions a CREATE response reports. */
const ACTION = { SUPERSEDED: 0, OPENED: 1, CREATED: 2, OVERWRITTEN: 3 } as const;

/** The options of a CREATE that this phase examines. */
const OPTION = {
  DIRECTORY_FILE: 0x00000001,
  NON_DIRECTORY_FILE: 0x00000040,
  DELETE_ON_CLOSE: 0x00001000,
  OPEN_REPARSE_POINT: 0x00200000,
} as const;

/** An open a client holds. */
interface Open {
  /** The identifier, both halves of which this server sets alike. */
  id: bigint;
  entry: Entry;
  /** The path within the share, without a leading separator. */
  path: string;
  fs: SmbFs;
  /** The listing in progress, where the open is being enumerated. */
  listing?: Entry[];
  /** How far through that listing the client has read. */
  at: number;
  /** The pattern the listing was started with. */
  pattern?: string;
  /** Whether the object is removed when the last open of it closes. */
  deleteOnClose: boolean;
}

/** How a principal is authenticated: a password per user name. */
export interface SmbServerOptions {
  /** The passwords, by user name, matched without regard to case. */
  passwords?: Record<string, string>;
  /** Delegated access control, where this server is configured for it. */
  dac?: DacClient;
  /** The NetBIOS name the server reports as the authentication target. */
  target?: string;
  /** Whether the server itself requires signing, whatever a share says. */
  signingRequired?: boolean;
  /** Where a command is written, where one is. */
  log?: Log;
  /**
   * The principal a user name authenticates as. A server that maps
   * credentials supplies this; without it every session is the
   * anonymous principal, which is what the protocol binding does with
   * a credential it does not resolve.
   */
  principal?: (user: string, anonymous: boolean) => Principal;
  /**
   * The principal a Kerberos ticket names, where this server's realm accepts
   * one: "a domain controller authenticates an SMB client, by Kerberos or by
   * the pass-through of an NTLM authentication, and the CDMI server holds no
   * secret of that client" (revision 282; PLAN-auth.md, phase 8). The token
   * is the GSS token of the session setup, a Kerberos AP-REQ alone or within
   * SPNEGO; the answer, where there is one, is returned to the client so that
   * it authenticates this server in turn.
   */
  kerberos?: (token: Buffer) => Promise<{ principal: Principal; answer?: Buffer }> | undefined;
}

/** A session established on a connection. */
interface Session {
  id: bigint;
  /** The name the client authenticated as, or "" where anonymous. */
  user: string;
  anonymous: boolean;
  signingKey?: Buffer;
  /** Whether this session signs, which a share may require. */
  signing: boolean;
  /** The challenge outstanding while the exchange is in progress. */
  challenge?: Buffer;
  /** The preauthentication integrity hash, for the 3.1.1 dialect. */
  preauth: Buffer;
  established: boolean;
  trees: Map<number, Share>;
  /** The opens of this session, by identifier. */
  opens: Map<string, Open>;
  nextOpen: bigint;
  principal: Principal;
}

/** The state of one connection. */
interface Connection {
  socket: net.Socket;
  buffer: Buffer;
  dialect: number;
  negotiated: boolean;
  clientGuid: Buffer;
  sessions: Map<bigint, Session>;
  nextSession: bigint;
  nextTree: number;
  /** The connection-wide preauthentication hash, before a session exists. */
  preauth: Buffer;
  /** Whether the client said it requires signing. */
  clientSigningRequired: boolean;
}

/** What a command handler answers with. */
interface Answer {
  status: number;
  body: Buffer;
  /** The session this answer is signed under, where one applies. */
  session?: Session;
  sessionId?: bigint;
  treeId?: number;
  /**
   * Joins the message, as sent, to a preauthentication integrity hash.
   * The hash covers the bytes on the wire, so it is computed where
   * they are built rather than from a header reconstructed to match.
   */
  hash?: (message: Buffer) => void;
}

export class SmbServer {
  private server?: net.Server;
  private readonly shares = new Map<string, Share>();
  private readonly opts: SmbServerOptions;
  private readonly guid = Buffer.from(randomUUID().replace(/-/g, ""), "hex");
  private readonly started = fileTime(Date.now());
  private readonly connections = new Set<Connection>();

  constructor(opts: SmbServerOptions = {}) {
    this.opts = opts;
  }

  /** Publishes a share, replacing one of the same name. */
  offer(share: Share): void {
    this.shares.set(share.name.toLowerCase(), share);
  }

  /** Withdraws a share; a tree connected to it is not disturbed here. */
  withdraw(name: string): void {
    this.shares.delete(name.toLowerCase());
  }

  /** The names of the shares now offered. */
  offered(): string[] {
    return [...this.shares.values()].map((s) => s.name);
  }

  /** Whether the server is listening. */
  running(): boolean {
    return this.server !== undefined;
  }

  /** The revision number of each version name of an export entry. */
  revisions(names: string[]): number[] {
    return names.map((n) => DIALECTS[n]).filter((n) => n !== undefined);
  }

  listen(port: number, host = "127.0.0.1"): Promise<number> {
    return new Promise((resolve) => {
      this.server = net.createServer((socket) => this.accept(socket));
      this.server.listen(port, host, () => {
        resolve((this.server!.address() as { port: number }).port);
      });
    });
  }

  async close(): Promise<void> {
    for (const c of this.connections) c.socket.destroy();
    this.connections.clear();
    const s = this.server;
    if (!s) return;
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }

  private accept(socket: net.Socket): void {
    const c: Connection = {
      socket,
      buffer: Buffer.alloc(0),
      dialect: 0,
      negotiated: false,
      clientGuid: Buffer.alloc(16),
      sessions: new Map(),
      nextSession: 1n,
      nextTree: 1,
      preauth: PREAUTH_ZERO,
      clientSigningRequired: false,
    };
    this.connections.add(c);
    socket.on("data", (chunk: Buffer) => {
      c.buffer = Buffer.concat([c.buffer, chunk]);
      const split = unframe(c.buffer);
      if (split === undefined) {
        // Not the transport of section 2.1: an SMB 1.0 negotiate
        // begins 0xFF 'S' 'M' 'B' behind the same framing, and
        // anything else is not this protocol at all.
        socket.destroy();
        this.connections.delete(c);
        return;
      }
      c.buffer = split.rest;
      for (const message of split.messages) this.dispatch(c, message);
    });
    socket.on("error", () => {
      socket.destroy();
      this.connections.delete(c);
    });
    socket.on("close", () => this.connections.delete(c));
  }

  /** Handles one message, answering on the same connection. */
  private dispatch(c: Connection, message: Buffer): void {
    const h = decodeHeader(message);
    if (h === undefined) {
      c.socket.destroy();
      return;
    }
    const body = message.subarray(HEADER_SIZE);
    const began = Date.now();
    void (async () => {
      let answer: Answer;
      try {
        answer = await this.handle(c, h, body, message);
      } catch (err) {
        if (err instanceof SmbStatus) {
          answer = { status: err.status, body: errorBody() };
        } else {
          if (process.env.SMB_TRACE) console.error(commandName(h.command), err);
          answer = { status: NT.INVALID_PARAMETER, body: errorBody() };
        }
      }
      const log = this.opts.log;
      if (log?.enabled === true) {
        const session = c.sessions.get(h.sessionId);
        log.write({
          surface: "smb",
          outcome: statusName(answer.status),
          failed: answer.status !== NT.SUCCESS &&
            answer.status !== NT.MORE_PROCESSING_REQUIRED,
          operation: commandName(h.command),
          instance: session?.trees.get(h.treeId)?.name ?? "",
          principal: session?.anonymous === true
            ? "ANONYMOUS@"
            : (session?.user ?? ""),
          ms: Date.now() - began,
        });
      }
      this.reply(c, h, answer);
    })();
  }

  private reply(c: Connection, request: Header, a: Answer): void {
    const out = header({
      command: request.command,
      status: a.status,
      credits: 8192,
      flags: FLAG.SERVER_TO_REDIR,
      messageId: request.messageId,
      sessionId: a.sessionId ?? request.sessionId,
      treeId: a.treeId ?? request.treeId,
      creditCharge: request.creditCharge,
    });
    const session = a.session ?? c.sessions.get(out.sessionId);
    const key = session?.established === true ? session.signingKey : undefined;
    // A message is signed where the session has a key and signs, which
    // is the condition of section 3.3.4.1.1 reduced to what this
    // implementation supports: no encryption, no multichannel.
    const signed = key !== undefined && (session!.signing || a.status === NT.SUCCESS &&
      request.command === CMD.SESSION_SETUP);
    const message = signed && key !== undefined
      ? sign(c.dialect, key, out, a.body)
      : Buffer.concat([encodeHeader(out), a.body]);
    // An interim response joins the hash and is not signed, so the
    // order of the two does not arise.
    a.hash?.(message);
    c.socket.write(frame(message));
  }

  private async handle(
    c: Connection,
    h: Header,
    body: Buffer,
    message: Buffer,
  ): Promise<Answer> {
    // Each request has a delegation context of its own, as each request of
    // the protocol binding and of an export does.
    return withDelegation(() => this.handleInner(c, h, body, message));
  }

  private async handleInner(
    c: Connection,
    h: Header,
    body: Buffer,
    message: Buffer,
  ): Promise<Answer> {
    if (h.command === CMD.NEGOTIATE) return this.negotiate(c, h, body, message);
    if (!c.negotiated) return { status: NT.INVALID_PARAMETER, body: errorBody() };
    if (h.command === CMD.SESSION_SETUP) return await this.sessionSetup(c, h, body, message);

    const session = c.sessions.get(h.sessionId);
    if (session === undefined || !session.established) {
      return { status: NT.USER_SESSION_DELETED, body: errorBody() };
    }
    // A signed session verifies every message after the setup, which
    // is what "required" means for a share and for a server.
    if (session.signing && session.signingKey !== undefined) {
      if ((h.flags & FLAG.SIGNED) === 0 ||
        !verifySignature(c.dialect, session.signingKey, message)) {
        return { status: NT.ACCESS_DENIED, body: errorBody() };
      }
    }

    switch (h.command) {
      case CMD.TREE_CONNECT:
        return this.treeConnect(c, h, body, session);
      case CMD.TREE_DISCONNECT: {
        if (!session.trees.delete(h.treeId)) {
          return { status: NT.SMB_BAD_TID, body: errorBody() };
        }
        return { status: NT.SUCCESS, body: fixed(4) };
      }
      case CMD.LOGOFF: {
        c.sessions.delete(h.sessionId);
        return { status: NT.SUCCESS, body: fixed(4) };
      }
      case CMD.ECHO:
        return { status: NT.SUCCESS, body: fixed(4) };
      case CMD.CREATE:
        return this.create(h, body, message, session);
      case CMD.CLOSE:
        return this.closeFile(h, body, session);
      case CMD.READ:
        return this.read(h, body, session);
      case CMD.QUERY_DIRECTORY:
        return this.queryDirectory(h, body, message, session);
      case CMD.QUERY_INFO:
        return this.queryInfo(h, body, session);
      case CMD.WRITE:
        return this.write(h, body, message, session);
      case CMD.SET_INFO:
        return this.setInfo(h, body, message, session);
      case CMD.IOCTL:
        return this.ioctl(h, body, message, session);
      case CMD.FLUSH: {
        // Nothing is buffered that a flush would write: a value is
        // written to the store before the response is sent.
        this.open(session, body, 8);
        return { status: NT.SUCCESS, body: fixed(4) };
      }
      default: {
        // A command of a later phase, and a command this document
        // defines that an SMB export does not perform.
        if (session.trees.get(h.treeId) === undefined &&
          h.command !== CMD.CANCEL) {
          return { status: NT.SMB_BAD_TID, body: errorBody() };
        }
        return { status: NT.NOT_SUPPORTED, body: errorBody() };
      }
    }
  }

  /** The dialects any share offers, being what the server negotiates. */
  private dialectsOffered(): number[] {
    const all = new Set<number>();
    for (const s of this.shares.values()) for (const d of s.dialects) all.add(d);
    // A dialect is negotiated for a connection and a share is not
    // named until the tree connect, so a server offering no share
    // still negotiates: the client is told at TREE_CONNECT that the
    // share it wants is not there. This is the other half of Q6.
    if (all.size === 0) return Object.values(DIALECTS).sort((a, b) => a - b);
    return [...all].sort((a, b) => a - b);
  }

  private negotiate(c: Connection, h: Header, body: Buffer, message: Buffer): Answer {
    if (c.negotiated || body.length < 36 || body.readUInt16LE(0) !== 36) {
      return { status: NT.INVALID_PARAMETER, body: errorBody() };
    }
    const count = body.readUInt16LE(2);
    const clientMode = body.readUInt16LE(4);
    c.clientSigningRequired = (clientMode & SIGNING_REQUIRED) !== 0;
    c.clientGuid = Buffer.from(body.subarray(12, 28));
    if (36 + count * 2 > body.length) {
      return { status: NT.INVALID_PARAMETER, body: errorBody() };
    }
    const wanted: number[] = [];
    for (let i = 0; i < count; i++) wanted.push(body.readUInt16LE(36 + i * 2));

    // The highest dialect the client offers that a share offers too.
    const mine = this.dialectsOffered();
    const common = wanted.filter((d) => mine.includes(d)).sort((a, b) => b - a);
    if (common.length === 0) {
      return { status: NT.NOT_SUPPORTED, body: errorBody() };
    }
    const dialect = common[0];
    c.dialect = dialect;
    c.negotiated = true;

    // The 3.1.1 dialect carries negotiate contexts, of which the
    // preauthentication integrity one is mandatory, and the hash it
    // names is the only one this document defines.
    let preauthContext = false;
    if (dialect === 0x0311) {
      const contextOffset = body.readUInt32LE(28);
      const contextCount = body.readUInt16LE(32);
      let at = contextOffset;
      for (let i = 0; i < contextCount; i++) {
        if (at + 8 > message.length) break;
        const type = message.readUInt16LE(at);
        const len = message.readUInt16LE(at + 2);
        const data = message.subarray(at + 8, at + 8 + len);
        if (type === CTX.PREAUTH_INTEGRITY_CAPABILITIES && len >= 4) {
          const hashCount = data.readUInt16LE(0);
          for (let k = 0; k < hashCount && 4 + k * 2 + 2 <= data.length; k++) {
            if (data.readUInt16LE(4 + k * 2) === HASH_SHA512) preauthContext = true;
          }
        }
        at = align8(at + 8 + len);
      }
      if (!preauthContext) {
        return { status: NT.INVALID_PARAMETER, body: errorBody() };
      }
      c.preauth = preauthHash(PREAUTH_ZERO, message);
    }

    const security = Buffer.alloc(0); // no SPNEGO hint: the client sends NTLMSSP
    const fixedSize = 64;
    const b = new Body(fixedSize);
    const sec = b.add(security);
    const contexts: Buffer[] = [];
    if (dialect === 0x0311) {
      const salt = randomBytes(32);
      const data = Buffer.alloc(6 + salt.length);
      data.writeUInt16LE(1, 0); // one hash algorithm
      data.writeUInt16LE(salt.length, 2);
      data.writeUInt16LE(HASH_SHA512, 4); // the algorithms, then the salt
      salt.copy(data, 6);
      const ctx = Buffer.alloc(8 + data.length);
      ctx.writeUInt16LE(CTX.PREAUTH_INTEGRITY_CAPABILITIES, 0);
      ctx.writeUInt16LE(data.length, 2);
      data.copy(ctx, 8);
      contexts.push(ctx);
    }
    const contextBuffer = Buffer.concat(contexts);
    const padding = contexts.length > 0
      ? Buffer.alloc(align8(HEADER_SIZE + fixedSize + sec.length) -
        (HEADER_SIZE + fixedSize + sec.length))
      : Buffer.alloc(0);
    const contextOffset = HEADER_SIZE + fixedSize + sec.length + padding.length;

    const out = Buffer.alloc(fixedSize);
    out.writeUInt16LE(65, 0);
    out.writeUInt16LE(
      SIGNING_ENABLED | (this.opts.signingRequired === true ? SIGNING_REQUIRED : 0), 2);
    out.writeUInt16LE(dialect, 4);
    out.writeUInt16LE(contexts.length, 6);
    this.guid.copy(out, 8, 0, 16);
    // No capability is claimed: leasing, multichannel, persistent
    // handles and encryption are features this server does not offer,
    // and the export entry reports each of them absent.
    out.writeUInt32LE(isSmb3(dialect) ? CAP.LARGE_MTU : 0, 24);
    out.writeUInt32LE(1048576, 28); // MaxTransactSize
    out.writeUInt32LE(1048576, 32); // MaxReadSize
    out.writeUInt32LE(1048576, 36); // MaxWriteSize
    out.writeBigUInt64LE(fileTime(Date.now()), 40);
    out.writeBigUInt64LE(this.started, 48);
    out.writeUInt16LE(sec.length === 0 ? 0 : sec.offset, 56);
    out.writeUInt16LE(sec.length, 58);
    out.writeUInt32LE(contexts.length > 0 ? contextOffset : 0, 60);

    const full = Buffer.concat([out, b.buffer(), padding, contextBuffer]);
    return {
      status: NT.SUCCESS,
      body: full,
      hash: dialect === 0x0311
        ? (msg) => {
          c.preauth = preauthHash(c.preauth, msg);
        }
        : undefined,
    };
  }

  private async sessionSetup(c: Connection, h: Header, body: Buffer, message: Buffer): Promise<Answer> {
    if (body.length < 25 || body.readUInt16LE(0) !== 25) {
      return { status: NT.INVALID_PARAMETER, body: errorBody() };
    }
    const clientMode = body.readUInt16LE(2);
    const offset = body.readUInt16LE(12);
    const length = body.readUInt16LE(14);
    const token = fieldAt(message, offset, length);
    if (token === undefined) return { status: NT.NOT_SUPPORTED, body: errorBody() };
    if (!isNtlmssp(token)) {
      // A Kerberos ticket, alone or within SPNEGO, where this server's realm
      // accepts one; a client that sends neither that nor a raw NTLMSSP
      // token is told the mechanism is not supported.
      if (this.opts.kerberos === undefined) return { status: NT.NOT_SUPPORTED, body: errorBody() };
      let accepted: { principal: Principal; answer?: Buffer } | undefined;
      try {
        accepted = await this.opts.kerberos(token);
      } catch {
        accepted = undefined;
      }
      if (accepted === undefined) return { status: NT.LOGON_FAILURE, body: errorBody() };
      const id = c.sessions.get(h.sessionId)?.id ?? c.nextSession++;
      const session: Session = {
        id,
        user: accepted.principal.name,
        anonymous: false,
        signing: false,
        preauth: c.preauth,
        established: true,
        trees: new Map(),
        opens: new Map(),
        nextOpen: 1n,
        principal: accepted.principal,
      };
      c.sessions.set(id, session);
      return {
        status: NT.SUCCESS,
        sessionId: id,
        session,
        body: setupBody(accepted.answer ?? Buffer.alloc(0)),
      };
    }

    const existing = c.sessions.get(h.sessionId);
    const type = ntlmType(token);

    if (type === 1) {
      const id = existing?.id ?? c.nextSession++;
      const challenge = randomBytes(8);
      const session: Session = existing ?? {
        id,
        user: "",
        anonymous: false,
        signing: false,
        preauth: c.preauth,
        established: false,
        trees: new Map(),
        opens: new Map(),
        nextOpen: 1n,
        principal: ANONYMOUS,
      };
      session.challenge = challenge;
      session.established = false;
      if (c.dialect === 0x0311) {
        session.preauth = preauthHash(existing?.preauth ?? c.preauth, message);
      }
      c.sessions.set(id, session);

      const flags = NEGOTIATE_FLAGS.UNICODE | NEGOTIATE_FLAGS.REQUEST_TARGET |
        NEGOTIATE_FLAGS.NTLM | NEGOTIATE_FLAGS.ALWAYS_SIGN |
        NEGOTIATE_FLAGS.TARGET_TYPE_SERVER | NEGOTIATE_FLAGS.EXTENDED_SESSIONSECURITY |
        NEGOTIATE_FLAGS.TARGET_INFO | NEGOTIATE_FLAGS.KEY_EXCH | NEGOTIATE_FLAGS.KEY_128;
      const chal = challengeMessage(
        this.opts.target ?? "SEEDMI", challenge, flags >>> 0, fileTime(Date.now()));
      return {
        status: NT.MORE_PROCESSING_REQUIRED,
        body: setupBody(chal),
        sessionId: id,
        session,
        hash: c.dialect === 0x0311
          ? (msg) => {
            session.preauth = preauthHash(session.preauth, msg);
          }
          : undefined,
      };
    }

    if (type !== 3 || existing === undefined || existing.challenge === undefined) {
      return { status: NT.INVALID_PARAMETER_MIX, body: errorBody() };
    }
    const auth = readAuthenticate(token);
    if (auth === undefined) return { status: NT.INVALID_PARAMETER, body: errorBody() };
    if (c.dialect === 0x0311) {
      existing.preauth = preauthHash(existing.preauth, message);
    }

    let sessionKey: Buffer | undefined;
    let anonymous = false;
    if (isAnonymous(auth)) {
      // An unauthenticated client: whether it reaches anything is
      // decided at TREE_CONNECT, by the share.
      anonymous = true;
      sessionKey = Buffer.alloc(16);
    } else {
      const password = this.password(auth.user);
      if (password === undefined) {
        return { status: NT.LOGON_FAILURE, body: errorBody() };
      }
      sessionKey = verify(auth, password, existing.challenge);
      if (sessionKey === undefined) {
        return { status: NT.LOGON_FAILURE, body: errorBody() };
      }
    }

    existing.user = anonymous ? "" : auth.user;
    existing.anonymous = anonymous;
    existing.principal = this.opts.principal?.(existing.user, anonymous) ?? ANONYMOUS;
    existing.established = true;
    existing.challenge = undefined;
    // An anonymous session has no key material, so it cannot sign, and
    // a server that requires signing therefore admits no anonymous
    // client. That is a consequence of the two rules, not a third one.
    existing.signingKey = anonymous
      ? undefined
      : signingKey(c.dialect, sessionKey, existing.preauth);
    existing.signing = !anonymous &&
      (this.opts.signingRequired === true || c.clientSigningRequired ||
        (clientMode & SIGNING_REQUIRED) !== 0);

    const out = fixed(9);
    out.writeUInt16LE(anonymous ? 0x0002 : 0, 2); // SMB2_SESSION_FLAG_IS_NULL
    return { status: NT.SUCCESS, body: out, sessionId: existing.id, session: existing };
  }

  private password(user: string): string | undefined {
    const table = this.opts.passwords ?? {};
    const key = Object.keys(table).find((k) => k.toLowerCase() === user.toLowerCase());
    return key === undefined ? undefined : table[key];
  }

  private treeConnect(c: Connection, h: Header, body: Buffer, s: Session): Answer {
    if (body.length < 9 || body.readUInt16LE(0) !== 9) {
      return { status: NT.INVALID_PARAMETER, body: errorBody() };
    }
    const offset = body.readUInt16LE(4);
    const length = body.readUInt16LE(6);
    const raw = fieldAt(Buffer.concat([Buffer.alloc(HEADER_SIZE), body]), offset, length);
    if (raw === undefined) return { status: NT.INVALID_PARAMETER, body: errorBody() };
    const path = fromUtf16(raw);
    // The path is \\server\share; only the last element names a share.
    const m = /^\\\\[^\\]+\\([^\\]+)$/.exec(path);
    if (m === null) return { status: NT.BAD_NETWORK_NAME, body: errorBody() };
    const share = this.shares.get(m[1].toLowerCase());
    if (share === undefined) return { status: NT.BAD_NETWORK_NAME, body: errorBody() };

    // The share decides what an unauthenticated client reaches, and
    // whether the connection has to sign.
    if (s.anonymous && !share.anonymous) {
      return { status: NT.ACCESS_DENIED, body: errorBody() };
    }
    if (share.signingRequired && !s.signing) {
      // Signing is agreed for a connection, at NEGOTIATE and
      // SESSION_SETUP, and a share is not named until TREE_CONNECT, so
      // a server cannot ask a client to start signing here. All it can
      // do is refuse, which is what the field of the export entry
      // says: an unsigned connection is rejected. See Q6.
      return { status: NT.ACCESS_DENIED, body: errorBody() };
    }

    const treeId = c.nextTree++;
    s.trees.set(treeId, share);
    const out = fixed(16);
    out.writeUInt8(SHARE_TYPE_DISK, 2);
    out.writeUInt32LE(0, 4); // ShareFlags: no caching, no DFS
    out.writeUInt32LE(0, 8); // Capabilities: none of the 3.x features
    // The maximal access is the mask the principal is granted over
    // the container object the share presents, with the bits that are
    // requested and not granted absent from the answer.
    let maximal = 0;
    if (share.mount !== undefined) {
      try {
        const fs = new SmbFs(share.mount, s.principal);
        const root = fs.root();
        maximal = fs.maximal(root, share.mount.store.meta(root));
      } catch {
        maximal = 0;
      }
    }
    out.writeUInt32LE(maximal, 12);
    return { status: NT.SUCCESS, body: out, treeId };
  }

  // -----------------------------------------------------------------
  // The commands of a connected tree

  /** The file system a session reaches through a tree. */
  private fsOf(session: Session, treeId: number): SmbFs {
    const share = session.trees.get(treeId);
    if (share === undefined) throw new SmbStatus(NT.SMB_BAD_TID);
    if (share.mount === undefined) throw new SmbStatus(NT.NOT_SUPPORTED);
    // A share that admits a client read-only presents a read-only file
    // system, whatever the access control list of an object says: the
    // share level access is evaluated first and does not replace it.
    const mount = share.mount.readOnly || session.anonymous
      ? { ...share.mount, readOnly: true }
      : share.mount;
    return new SmbFs(mount, session.principal);
  }

  /** The open a request names, by the identifier at the given offset. */
  private open(session: Session, body: Buffer, at: number): Open {
    if (body.length < at + 16) throw new SmbStatus(NT.INVALID_PARAMETER);
    const id = body.readBigUInt64LE(at);
    const open = session.opens.get(String(id));
    if (open === undefined) throw new SmbStatus(NT.INVALID_PARAMETER);
    return open;
  }

  private async create(
    h: Header,
    body: Buffer,
    message: Buffer,
    session: Session,
  ): Promise<Answer> {
    if (body.length < 56 || body.readUInt16LE(0) !== 57) {
      throw new SmbStatus(NT.INVALID_PARAMETER);
    }
    const desired = body.readUInt32LE(24);
    const disposition = body.readUInt32LE(36);
    const options = body.readUInt32LE(40);
    const nameOffset = body.readUInt16LE(44);
    const nameLength = body.readUInt16LE(46);
    const raw = fieldAt(message, nameOffset, nameLength);
    if (raw === undefined) throw new SmbStatus(NT.INVALID_PARAMETER);
    const path = fromUtf16(raw);

    const fs = this.fsOf(session, h.treeId);
    // A name holding a colon names a stream of an object, and this
    // export presents none: the capability that would carry one is
    // absent, and the clause states the status for that case.
    if (path.includes(":")) return { status: NT.NOT_SUPPORTED, body: errorBody() };

    const wantsDirectory = (options & OPTION.DIRECTORY_FILE) !== 0;
    let entry: Entry | undefined;
    let action: number = ACTION.OPENED;
    try {
      entry = fs.resolve(path);
    } catch (err) {
      if (!(err instanceof SmbStatus) ||
        err.status !== NT.OBJECT_NAME_NOT_FOUND) {
        throw err;
      }
    }

    // An object of this server that has delegated access control is governed
    // by its provider however it is reached (dac-context.ts). The decision is
    // obtained when the object is opened, and the permission checks of the
    // file system apply the mask the provider returned for the rest of this
    // request. STATUS_ACCESS_DENIED is what this protocol reports a refusal
    // with.
    const opened = entry?.node;
    if (opened !== undefined && this.opts.dac !== undefined) {
      // FILE_WRITE_DATA, FILE_APPEND_DATA and DELETE of the access mask.
      const wanted = (desired & (0x0002 | 0x0004 | 0x00010000)) !== 0;
      try {
        await decideFor(this.opts.dac, fs.store, opened, fs.who,
          wanted ? "cdmi_modify" : opened.isContainer ? "cdmi_list" : "cdmi_read");
      } catch (e) {
        if (!(e instanceof DelegationRefused)) throw e;
        return { status: NT.ACCESS_DENIED, body: errorBody() };
      }
    }

    if (entry === undefined) {
      // Nothing of that name: the disposition decides whether one is
      // made or the client is told there is nothing there.
      if (disposition === DISPOSITION.OPEN ||
        disposition === DISPOSITION.OVERWRITE) {
        return { status: NT.OBJECT_NAME_NOT_FOUND, body: errorBody() };
      }
      entry = fs.create(path, wantsDirectory);
      action = ACTION.CREATED;
    } else {
      if (disposition === DISPOSITION.CREATE) {
        return { status: NT.OBJECT_NAME_COLLISION, body: errorBody() };
      }
      if (entry.reference !== undefined &&
        (options & OPTION.OPEN_REPARSE_POINT) === 0) {
        // The path met a reference and the client did not ask to open
        // one: the client is given the substitute name and resolves it
        // itself, which is what the clause means by the CDMI server
        // resolving neither destination nor substitute name.
        const { substitute, relative } = fs.substituteName(entry);
        return {
          status: STATUS_STOPPED_ON_SYMLINK,
          body: symlinkErrorResponse(substitute, relative, 0),
        };
      }
      if (wantsDirectory && !entry.isContainer) {
        return { status: NT.NOT_A_DIRECTORY, body: errorBody() };
      }
      if ((options & OPTION.NON_DIRECTORY_FILE) !== 0 && entry.isContainer) {
        return { status: NT.FILE_IS_A_DIRECTORY, body: errorBody() };
      }
      if (disposition === DISPOSITION.OVERWRITE ||
        disposition === DISPOSITION.OVERWRITE_IF ||
        disposition === DISPOSITION.SUPERSEDE) {
        if (entry.isContainer) {
          return { status: NT.INVALID_PARAMETER, body: errorBody() };
        }
        // Superseding is defined as deleting what is there and making
        // a new object in its place, and overwriting as emptying the
        // one that is there. The two differ in the object identifier a
        // client sees afterwards, and this export keeps the object for
        // an overwrite and replaces it for a supersede.
        if (disposition === DISPOSITION.SUPERSEDE) {
          fs.remove(entry.node!, entry.meta!);
          entry = fs.create(path, false);
          action = ACTION.SUPERSEDED;
        } else {
          await fs.truncate(entry.node!, 0);
          entry = fs.resolve(path);
          action = ACTION.OVERWRITTEN;
        }
      }
    }

    // The access the client asks for is authorised now, so that a
    // read or a write of the open needs no second decision.
    if (entry.node !== undefined && entry.meta !== undefined &&
      action === ACTION.OPENED) {
      const wanted = desiredToMask(desired, entry.isContainer);
      if (!fs.allows(entry.node, entry.meta, wanted)) {
        return { status: NT.ACCESS_DENIED, body: errorBody() };
      }
      // A request for maximal access is answered with the bits the
      // principal is granted, and is not itself a bit to evaluate.
      if ((desired & MAXIMUM_ALLOWED) !== 0 &&
        fs.maximal(entry.node, entry.meta) === 0) {
        return { status: NT.ACCESS_DENIED, body: errorBody() };
      }
    }

    const id = session.nextOpen++;
    session.opens.set(String(id), {
      id,
      entry,
      path: path.replace(/^\\+/, ""),
      fs,
      at: 0,
      deleteOnClose: (options & OPTION.DELETE_ON_CLOSE) !== 0,
    });

    const out = Buffer.alloc(88);
    out.writeUInt16LE(89, 0);
    out.writeUInt8(0, 2); // OplockLevel: none, this export leases nothing
    out.writeUInt8(0, 3);
    out.writeUInt32LE(action, 4);
    out.writeBigUInt64LE(entry.created, 8);
    out.writeBigUInt64LE(entry.accessed, 16);
    out.writeBigUInt64LE(entry.written, 24);
    out.writeBigUInt64LE(entry.changed, 32);
    out.writeBigUInt64LE(allocationOf(entry.size), 40);
    out.writeBigUInt64LE(BigInt(entry.size), 48);
    out.writeUInt32LE(entry.attributes, 56);
    out.writeUInt32LE(0, 60); // Reserved2
    // Both halves of the identifier are the same value: this server
    // holds no durable handle, so there is nothing for the persistent
    // half to name that the volatile half does not.
    out.writeBigUInt64LE(id, 64);
    out.writeBigUInt64LE(id, 72);
    out.writeUInt32LE(0, 80); // CreateContextsOffset
    out.writeUInt32LE(0, 84); // CreateContextsLength
    return { status: NT.SUCCESS, body: out };
  }

  private closeFile(h: Header, body: Buffer, session: Session): Answer {
    if (body.length < 24 || body.readUInt16LE(0) !== 24) {
      throw new SmbStatus(NT.INVALID_PARAMETER);
    }
    const flags = body.readUInt16LE(2);
    const open = this.open(session, body, 8);
    session.opens.delete(String(open.id));
    if (open.deleteOnClose && open.entry.node !== undefined &&
      open.entry.meta !== undefined) {
      // A close that removes the object: what a client does after
      // asking for the deletion at the open, or through the
      // disposition information level.
      open.fs.remove(open.entry.node, open.entry.meta);
    }

    const out = Buffer.alloc(60);
    out.writeUInt16LE(60, 0);
    if ((flags & 0x0001) !== 0) {
      // SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB: the attributes as they stand
      // at the close, which for this export are the ones the open saw,
      // since nothing of this phase changes them.
      out.writeUInt16LE(0x0001, 2);
      out.writeBigUInt64LE(open.entry.created, 8);
      out.writeBigUInt64LE(open.entry.accessed, 16);
      out.writeBigUInt64LE(open.entry.written, 24);
      out.writeBigUInt64LE(open.entry.changed, 32);
      out.writeBigUInt64LE(allocationOf(open.entry.size), 40);
      out.writeBigUInt64LE(BigInt(open.entry.size), 48);
      out.writeUInt32LE(open.entry.attributes, 56);
    }
    return { status: NT.SUCCESS, body: out };
  }

  private async read(h: Header, body: Buffer, session: Session): Promise<Answer> {
    if (body.length < 49 || body.readUInt16LE(0) !== 49) {
      throw new SmbStatus(NT.INVALID_PARAMETER);
    }
    const length = body.readUInt32LE(4);
    const offset = Number(body.readBigUInt64LE(8));
    const minimum = body.readUInt32LE(32);
    const open = this.open(session, body, 16);
    if (open.entry.node === undefined) throw new SmbStatus(NT.INVALID_DEVICE_REQUEST);

    const data = await open.fs.read(open.entry.node, offset, length);
    if (data.length === 0 && length > 0) {
      // A read at or beyond the end of the value: [MS-SMB2] answers
      // the end of file status rather than an empty read.
      return { status: NT.END_OF_FILE, body: errorBody() };
    }
    if (data.length < minimum) return { status: NT.END_OF_FILE, body: errorBody() };

    const out = Buffer.alloc(16 + data.length);
    out.writeUInt16LE(17, 0);
    out.writeUInt8(HEADER_SIZE + 16, 2); // DataOffset
    out.writeUInt32LE(data.length, 4);
    out.writeUInt32LE(0, 8); // DataRemaining
    data.copy(out, 16);
    return { status: NT.SUCCESS, body: out };
  }

  private queryDirectory(
    h: Header,
    body: Buffer,
    message: Buffer,
    session: Session,
  ): Answer {
    if (body.length < 32 || body.readUInt16LE(0) !== 33) {
      throw new SmbStatus(NT.INVALID_PARAMETER);
    }
    const cls = body.readUInt8(2);
    const flags = body.readUInt8(3);
    const nameOffset = body.readUInt16LE(24);
    const nameLength = body.readUInt16LE(26);
    const outputLength = body.readUInt32LE(28);
    const open = this.open(session, body, 8);
    if (open.entry.node === undefined || !open.entry.isContainer) {
      return { status: NT.INVALID_PARAMETER, body: errorBody() };
    }
    const pattern = nameLength === 0
      ? "*"
      : fromUtf16(fieldAt(message, nameOffset, nameLength) ?? Buffer.alloc(0));

    // A listing is taken once and read through; a restart takes it
    // again, which is what a client asks for when it rewinds.
    const restart = (flags & 0x01) !== 0 || (flags & 0x10) !== 0;
    if (open.listing === undefined || restart || open.pattern !== pattern) {
      open.listing = open.fs.list(open.entry.node).filter((e) => match(pattern, e.name));
      open.at = 0;
      open.pattern = pattern;
    }
    if (open.at >= open.listing.length) {
      // Nothing more to report. The status differs by whether anything
      // ever matched, which is how a client tells an empty directory
      // from the end of a listing.
      return {
        status: open.listing.length === 0 ? NT.NO_SUCH_FILE : NT.NO_MORE_FILES,
        body: errorBody(),
      };
    }

    const single = (flags & 0x02) !== 0;
    const entries: Buffer[] = [];
    let total = 0;
    while (open.at < open.listing.length) {
      const e = directoryEntry(cls, open.listing[open.at], open.at);
      if (e === undefined) {
        return { status: NT.INVALID_PARAMETER, body: errorBody() };
      }
      const padded = (e.length + 7) & ~7;
      if (entries.length > 0 && total + padded > outputLength) break;
      if (entries.length === 0 && e.length > outputLength) {
        // Not even one entry fits, which the client is told rather
        // than being given a truncated one.
        return { status: NT.INFO_LENGTH_MISMATCH, body: errorBody() };
      }
      entries.push(e);
      total += padded;
      open.at++;
      if (single) break;
    }

    const data = directoryBuffer(entries);
    const out = Buffer.alloc(8 + data.length);
    out.writeUInt16LE(9, 0);
    out.writeUInt16LE(HEADER_SIZE + 8, 2);
    out.writeUInt32LE(data.length, 4);
    data.copy(out, 8);
    return { status: NT.SUCCESS, body: out };
  }

  private async write(
    h: Header,
    body: Buffer,
    message: Buffer,
    session: Session,
  ): Promise<Answer> {
    if (body.length < 48 || body.readUInt16LE(0) !== 49) {
      throw new SmbStatus(NT.INVALID_PARAMETER);
    }
    const dataOffset = body.readUInt16LE(2);
    const length = body.readUInt32LE(4);
    const offset = Number(body.readBigUInt64LE(8));
    const open = this.open(session, body, 16);
    const data = fieldAt(message, dataOffset, length);
    if (data === undefined) throw new SmbStatus(NT.INVALID_PARAMETER);
    if (open.entry.node === undefined) throw new SmbStatus(NT.INVALID_DEVICE_REQUEST);

    await open.fs.write(open.entry.node, offset, data);
    // The open holds what the object looked like when it was opened,
    // and a write changes it, so what a later query of this open
    // reports is taken again.
    open.entry = open.fs.resolve(open.path);

    const out = Buffer.alloc(16);
    out.writeUInt16LE(17, 0);
    out.writeUInt32LE(data.length, 4);
    return { status: NT.SUCCESS, body: out };
  }

  private async setInfo(
    h: Header,
    body: Buffer,
    message: Buffer,
    session: Session,
  ): Promise<Answer> {
    if (body.length < 32 || body.readUInt16LE(0) !== 33) {
      throw new SmbStatus(NT.INVALID_PARAMETER);
    }
    const type = body.readUInt8(2);
    const cls = body.readUInt8(3);
    const bufferLength = body.readUInt32LE(4);
    const bufferOffset = body.readUInt16LE(8);
    const open = this.open(session, body, 16);
    const data = fieldAt(message, bufferOffset, bufferLength) ?? Buffer.alloc(0);
    if (type === INFO_TYPE.SECURITY) {
      return this.setSecurity(body, data, open);
    }
    if (type === INFO_TYPE.FILE && cls === FILE_CLASS.FileFullEaInformation) {
      // Extended attributes written through the export change the
      // user metadata of the object.
      if (open.entry.node === undefined || open.entry.meta === undefined) {
        return { status: NT.EAS_NOT_SUPPORTED, body: errorBody() };
      }
      open.fs.setExtendedAttributes(open.entry.node, open.entry.meta,
        decodeFullEas(data));
      open.entry = open.fs.resolve(open.path);
      return { status: NT.SUCCESS, body: fixed(2) };
    }
    if (type !== INFO_TYPE.FILE) {
      // This document defines no object for a quota.
      return { status: NT.NOT_SUPPORTED, body: errorBody() };
    }
    const node = open.entry.node;
    const meta = open.entry.meta;
    if (node === undefined || meta === undefined) {
      throw new SmbStatus(NT.INVALID_DEVICE_REQUEST);
    }

    switch (cls) {
      case FILE_CLASS.FileLinkInformation:
        // A hard link: this document defines no object for a second
        // name of one object, and the clause states the status.
        return { status: NT.NOT_SUPPORTED, body: errorBody() };

      case FILE_CLASS.FileBasicInformation: {
        if (data.length < 36) throw new SmbStatus(NT.INFO_LENGTH_MISMATCH);
        // The times and the attributes of an object are formed from
        // storage system metadata, which a CDMI server generates and a
        // client does not set. A request that would change one is
        // accepted and not applied; see Q13 in NOTES-on-smb.md.
        if (!open.fs.allows(node, meta, M.WRITE_ATTRIBUTES)) {
          return { status: NT.ACCESS_DENIED, body: errorBody() };
        }
        return { status: NT.SUCCESS, body: fixed(2) };
      }

      case FILE_CLASS.FileDispositionInformation: {
        if (data.length < 1) throw new SmbStatus(NT.INFO_LENGTH_MISMATCH);
        // Deletion in SMB is asked for here and performed at the
        // close, which is why the open carries the intent rather than
        // the object being removed now.
        const pending = data.readUInt8(0) !== 0;
        if (pending && open.fs.readOnly) {
          return { status: NT.MEDIA_WRITE_PROTECTED, body: errorBody() };
        }
        open.deleteOnClose = pending;
        return { status: NT.SUCCESS, body: fixed(2) };
      }

      case FILE_CLASS.FileEndOfFileInformation: {
        if (data.length < 8) throw new SmbStatus(NT.INFO_LENGTH_MISMATCH);
        await open.fs.truncate(node, Number(data.readBigUInt64LE(0)));
        open.entry = open.fs.resolve(open.path);
        return { status: NT.SUCCESS, body: fixed(2) };
      }

      case FILE_CLASS.FileAllocationInformation:
        // The allocation of an object is what the store gives it; a
        // client asking for more is told the request succeeded and the
        // object is unchanged, which is true of a sparse file system.
        return { status: NT.SUCCESS, body: fixed(2) };

      case FILE_CLASS.FileRenameInformation: {
        if (data.length < 20) throw new SmbStatus(NT.INFO_LENGTH_MISMATCH);
        const replace = data.readUInt8(0) !== 0;
        const nameLength = data.readUInt32LE(16);
        if (20 + nameLength > data.length) {
          throw new SmbStatus(NT.INFO_LENGTH_MISMATCH);
        }
        const to = fromUtf16(data.subarray(20, 20 + nameLength));
        open.fs.rename(node, meta, to, replace);
        open.path = to.replace(/^\\+/, "");
        open.entry = open.fs.resolve(open.path);
        return { status: NT.SUCCESS, body: fixed(2) };
      }

      default:
        return { status: NT.NOT_SUPPORTED, body: errorBody() };
    }
  }

  /**
   * The control operations an SMB export answers, which are the three
   * that address a reparse point. A reference is the only reparse
   * point this export presents.
   */
  private ioctl(h: Header, body: Buffer, message: Buffer, session: Session): Answer {
    if (body.length < 56 || body.readUInt16LE(0) !== 57) {
      throw new SmbStatus(NT.INVALID_PARAMETER);
    }
    const code = body.readUInt32LE(4);
    const inputOffset = body.readUInt32LE(24);
    const inputCount = body.readUInt32LE(28);
    const maxOutput = body.readUInt32LE(44);
    const open = this.open(session, body, 8);
    const entry = open.entry;

    let output = Buffer.alloc(0);
    switch (code) {
      case FSCTL.GET_REPARSE_POINT: {
        if (entry.reference === undefined) {
          return { status: NT.NOT_A_REPARSE_POINT, body: errorBody() };
        }
        const { substitute, relative } = open.fs.substituteName(entry);
        output = symlinkReparseData(substitute, relative);
        if (output.length > maxOutput) {
          return { status: NT.INFO_LENGTH_MISMATCH, body: errorBody() };
        }
        break;
      }
      case FSCTL.SET_REPARSE_POINT: {
        // A reparse point set on an object that exists would replace
        // it, and this document defines no object that is both; the
        // reference is made by the create instead.
        const input = fieldAt(message, inputOffset, inputCount);
        if (input === undefined) throw new SmbStatus(NT.INVALID_PARAMETER);
        const parsed = readSymlinkReparseData(input);
        if (parsed === undefined) {
          // A tag other than the symbolic link one: no reference
          // corresponds to it.
          return { status: NT.IO_REPARSE_TAG_NOT_HANDLED, body: errorBody() };
        }
        const destination = open.fs.destinationOf(parsed.substitute,
          open.fs.holderOf(open.path));
        if (destination === undefined) {
          // A relative path resolving outside the exported container
          // object, or a name that is neither a relative path nor an
          // absolute URI.
          return { status: NT.INVALID_PARAMETER, body: errorBody() };
        }
        if (entry.reference === undefined && entry.node !== undefined &&
          entry.meta !== undefined && entry.size === 0 && !entry.isContainer) {
          // The object the create made a moment ago is replaced by the
          // reference of the same name, which is how a client makes a
          // symbolic link: create, then set the reparse point on it.
          open.fs.remove(entry.node, entry.meta);
          open.entry = open.fs.createReference(open.path, destination);
          break;
        }
        return { status: NT.NOT_SUPPORTED, body: errorBody() };
      }
      case FSCTL.DELETE_REPARSE_POINT: {
        if (entry.reference === undefined) {
          return { status: NT.NOT_A_REPARSE_POINT, body: errorBody() };
        }
        // Removing the reparse point of a reference removes the
        // reference: there is nothing underneath it to leave behind.
        open.fs.remove(entry.node!, entry.meta!);
        session.opens.delete(String(open.id));
        break;
      }
      default:
        return { status: NT.INVALID_DEVICE_REQUEST, body: errorBody() };
    }

    const out = Buffer.alloc(48 + output.length);
    out.writeUInt16LE(49, 0);
    out.writeUInt32LE(code, 4);
    out.writeBigUInt64LE(open.id, 8);
    out.writeBigUInt64LE(open.id, 16);
    out.writeUInt32LE(0, 24); // InputOffset
    out.writeUInt32LE(0, 28); // InputCount
    out.writeUInt32LE(output.length === 0 ? 0 : HEADER_SIZE + 48, 32);
    out.writeUInt32LE(output.length, 36);
    output.copy(out, 48);
    return { status: NT.SUCCESS, body: out };
  }

  /**
   * Forms the access control list of an object from a security
   * descriptor an SMB client wrote.
   */
  private setSecurity(body: Buffer, data: Buffer, open: Open): Answer {
    const wanted = body.readUInt32LE(12); // AdditionalInformation
    if ((wanted & SECURITY_INFORMATION.SACL) !== 0) {
      // This document defines no system access control list, and a
      // request naming one is refused in either direction.
      return { status: NT.ACCESS_DENIED, body: errorBody() };
    }
    const node = open.entry.node;
    const meta = open.entry.meta;
    if (node === undefined || meta === undefined) {
      throw new SmbStatus(NT.INVALID_DEVICE_REQUEST);
    }
    let formed;
    try {
      formed = aclFromDescriptor(data, open.entry.isContainer, open.fs.authority(),
        open.fs.principalMap(), meta.owner, meta.group);
    } catch (err) {
      if (err instanceof UnmappedSid) {
        // The CDMI server neither stores the security identifier nor
        // discards the entry that carries it, since either would
        // present the CDMI client with a list it did not write.
        return { status: NT.NONE_MAPPED, body: errorBody() };
      }
      if (err instanceof SmbDescriptorError) {
        return { status: NT.INVALID_PARAMETER, body: errorBody() };
      }
      throw err;
    }
    // Only the parts the request named are applied.
    open.fs.setAcl(node, meta, formed.acl,
      (wanted & SECURITY_INFORMATION.OWNER) !== 0 ? formed.owner : undefined,
      (wanted & SECURITY_INFORMATION.GROUP) !== 0 ? formed.group : undefined);
    open.entry = open.fs.resolve(open.path);
    return { status: NT.SUCCESS, body: fixed(2) };
  }

  private queryInfo(h: Header, body: Buffer, session: Session): Answer {
    if (body.length < 40 || body.readUInt16LE(0) !== 41) {
      throw new SmbStatus(NT.INVALID_PARAMETER);
    }
    const type = body.readUInt8(2);
    const cls = body.readUInt8(3);
    const outputLength = body.readUInt32LE(4);
    const open = this.open(session, body, 24);
    const entry = open.entry;

    let data: Buffer | undefined;
    if (type === INFO_TYPE.FILE) {
      if (entry.node !== undefined && entry.meta !== undefined) {
        // Reading the attributes of an object requires
        // READ_ATTRIBUTES, which governs the storage system metadata
        // the size and the times are formed from.
        if (!open.fs.allows(entry.node, entry.meta, M.READ_ATTRIBUTES)) {
          return { status: NT.ACCESS_DENIED, body: errorBody() };
        }
      }
      if (cls === FILE_CLASS.FileFullEaInformation) {
        // The user metadata of the object, as extended attributes.
        if (entry.meta === undefined || entry.node === undefined) {
          return { status: NT.NO_EAS_ON_FILE, body: errorBody() };
        }
        if (!open.fs.allows(entry.node, entry.meta, M.READ_METADATA)) {
          return { status: NT.ACCESS_DENIED, body: errorBody() };
        }
        const eas = open.fs.extendedAttributes(entry.meta);
        if (eas.length === 0) {
          return { status: NT.NO_EAS_ON_FILE, body: errorBody() };
        }
        data = encodeFullEas(eas);
      } else {
        data = fileInformation(cls, entry, open.path);
      }
    } else if (type === INFO_TYPE.FILESYSTEM) {
      data = filesystemInformation(cls, session.trees.get(h.treeId)?.name ?? "");
    } else if (type === INFO_TYPE.SECURITY) {
      if (entry.node === undefined || entry.meta === undefined) {
        return { status: NT.NOT_SUPPORTED, body: errorBody() };
      }
      // Reading the list of an object requires READ_ACL, as it does
      // through the protocol binding.
      if (!open.fs.allows(entry.node, entry.meta, M.READ_ACL)) {
        return { status: NT.ACCESS_DENIED, body: errorBody() };
      }
      const wanted = body.readUInt32LE(16); // AdditionalInformation
      if ((wanted & SECURITY_INFORMATION.SACL) !== 0) {
        // This document defines no system access control list, and
        // asking for one requires a privilege no principal here holds.
        return { status: NT.ACCESS_DENIED, body: errorBody() };
      }
      data = securityDescriptor(entry.meta.acl, entry.meta.owner, entry.meta.group,
        entry.isContainer, wanted, open.fs.authority(), open.fs.principalMap());
    } else {
      // This document defines no object for a quota.
      return { status: NT.NOT_SUPPORTED, body: errorBody() };
    }
    if (data === undefined) return { status: NT.NOT_SUPPORTED, body: errorBody() };
    if (data.length > outputLength) {
      return { status: NT.INFO_LENGTH_MISMATCH, body: errorBody() };
    }

    const out = Buffer.alloc(8 + data.length);
    out.writeUInt16LE(9, 0);
    out.writeUInt16LE(HEADER_SIZE + 8, 2);
    out.writeUInt32LE(data.length, 4);
    data.copy(out, 8);
    return { status: NT.SUCCESS, body: out };
  }
}

/**
 * The mask an operation needs, from the access a CREATE asks for. A
 * generic bit is expanded before it is evaluated, to the bits
 * [MS-SMB2] section 2.2.13.1.1 states for it, and the two bits that
 * are requested and never granted are dropped.
 */
export function desiredToMask(desired: number, isContainer: boolean): number {
  let mask = desired >>> 0;
  const GENERIC_READ = 0x80000000;
  const GENERIC_WRITE = 0x40000000;
  const GENERIC_EXECUTE = 0x20000000;
  const GENERIC_ALL = 0x10000000;
  if ((mask & GENERIC_READ) !== 0) {
    mask |= M.READ_OBJECT | M.READ_ATTRIBUTES | M.READ_METADATA | M.SYNCHRONIZE |
      M.READ_ACL;
  }
  if ((mask & GENERIC_WRITE) !== 0) {
    mask |= M.WRITE_OBJECT | M.APPEND_DATA | M.WRITE_ATTRIBUTES | M.WRITE_METADATA |
      M.SYNCHRONIZE | M.READ_ACL;
  }
  if ((mask & GENERIC_EXECUTE) !== 0) {
    mask |= M.READ_ATTRIBUTES | M.EXECUTE | M.SYNCHRONIZE | M.READ_ACL;
  }
  if ((mask & GENERIC_ALL) !== 0) mask |= M.ALL_PERMS;
  mask &= ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
  // MAXIMUM_ALLOWED and ACCESS_SYSTEM_SECURITY are requested and not
  // granted, and the two retention bits have no counterpart in either
  // access mask of [MS-SMB2] and are never evaluated for an operation
  // of an SMB export.
  mask &= ~(MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY | M.WRITE_RETENTION |
    M.WRITE_RETENTION_HOLD);
  return mask >>> 0;
}

/**
 * Whether a name matches a pattern of a directory listing. The two
 * wildcards of [MS-FSCC] are supported; a CDMI object name is matched
 * with regard to case, which a client of another file system does not
 * expect and which the export cannot help.
 */
export function match(pattern: string, name: string): boolean {
  if (pattern === "*" || pattern === "") return true;
  const rx = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${rx}$`).test(name);
}

/** A fixed part of the given size, with the size in its first field. */
function fixed(size: number): Buffer {
  const b = Buffer.alloc(size);
  b.writeUInt16LE(size, 0);
  return b;
}

/**
 * The body of an error response, of [MS-SMB2] section 2.2.2: a
 * structure size of nine and a single zero byte.
 */
function errorBody(): Buffer {
  const b = Buffer.alloc(9);
  b.writeUInt16LE(9, 0);
  return b;
}

/** A SESSION_SETUP response carrying a security token. */
function setupBody(token: Buffer): Buffer {
  const b = new Body(8);
  const sec = b.add(token);
  const out = Buffer.alloc(8);
  out.writeUInt16LE(9, 0);
  out.writeUInt16LE(0, 2); // SessionFlags
  out.writeUInt16LE(sec.offset, 4);
  out.writeUInt16LE(sec.length, 6);
  return Buffer.concat([out, b.buffer()]);
}

/** The digest a test uses to compare two negotiations. */
export const fingerprint = (b: Buffer): string =>
  createHash("sha256").update(b).digest("hex").slice(0, 16);
