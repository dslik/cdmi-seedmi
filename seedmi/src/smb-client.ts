/**
 * An SMB2 client: the half of the protocol an SMB import needs, and
 * the half a test needs to exercise the server. It negotiates,
 * authenticates with NTLMSSP, connects a tree, and signs where the
 * session signs.
 */

import * as net from "node:net";
import { randomBytes } from "node:crypto";
import {
  align8,
  Body,
  CMD,
  CTX,
  decodeHeader,
  DIALECTS,
  encodeHeader,
  fieldAt,
  FLAG,
  fileTime,
  frame,
  HASH_SHA512,
  header,
  HEADER_SIZE,
  NT,
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
import {
  clientAnonymous,
  clientAuthenticate,
  isNtlmssp,
  negotiateMessage,
  NEGOTIATE_FLAGS,
  readChallenge,
} from "./ntlm.ts";

/** A response, as the caller sees it. */
export interface Response {
  header: Header;
  body: Buffer;
  message: Buffer;
}

/** A status the server returned that the client did not ask for. */
export class SmbError extends Error {
  readonly status: number;

  constructor(command: number, status: number) {
    super(`SMB2 command 0x${command.toString(16)} returned ${statusName(status)}`);
    this.status = status;
  }
}

export interface SmbClientOptions {
  /** The dialects to offer, highest first in the response. */
  dialects?: string[];
  /** Whether this client requires every message of a session to be signed. */
  signingRequired?: boolean;
  /** The name this client reports as its workstation. */
  workstation?: string;
}

export class SmbClient {
  private socket?: net.Socket;
  private buffer = Buffer.alloc(0);
  private readonly waiting = new Map<string, (r: Response) => void>();
  private nextMessageId = 0n;
  private sessionId = 0n;
  private treeId = 0;
  private dialect = 0;
  private preauth = PREAUTH_ZERO;
  private key?: Buffer;
  private signing = false;
  private readonly opts: SmbClientOptions;
  private closed = false;

  constructor(opts: SmbClientOptions = {}) {
    this.opts = opts;
  }

  /** The dialect that was negotiated, as a revision number. */
  get negotiated(): number {
    return this.dialect;
  }

  /** Whether this session signs its messages. */
  get signed(): boolean {
    return this.signing;
  }

  async connect(port: number, host = "127.0.0.1"): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const s = net.connect(port, host, () => resolve());
      s.on("error", (err: Error) => {
        if (!this.closed) reject(err);
      });
      s.on("data", (chunk: Buffer) => this.receive(chunk));
      s.on("close", () => {
        for (const [, resolveOne] of this.waiting) {
          // A connection the server dropped fails what is outstanding
          // rather than hanging the caller.
          resolveOne({
            header: header({ status: NT.USER_SESSION_DELETED }),
            body: Buffer.alloc(0),
            message: Buffer.alloc(0),
          });
        }
        this.waiting.clear();
      });
      this.socket = s;
    });
  }

  close(): void {
    this.closed = true;
    this.socket?.destroy();
  }

  private receive(chunk: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    const split = unframe(this.buffer);
    if (split === undefined) {
      this.socket?.destroy();
      return;
    }
    this.buffer = split.rest;
    for (const message of split.messages) {
      const h = decodeHeader(message);
      if (h === undefined) continue;
      const resolve = this.waiting.get(String(h.messageId));
      if (resolve === undefined) continue;
      this.waiting.delete(String(h.messageId));
      resolve({ header: h, body: message.subarray(HEADER_SIZE), message });
    }
  }

  /** Sends a request and waits for its response. */
  private send(
    command: number,
    body: Buffer,
    over: Partial<Header> = {},
    beforeSend?: (request: Buffer) => void,
  ): Promise<Response> {
    const id = this.nextMessageId++;
    const h = header({
      command,
      messageId: id,
      credits: 1,
      creditCharge: command === CMD.NEGOTIATE ? 0 : 1,
      sessionId: this.sessionId,
      treeId: this.treeId,
      ...over,
    });
    const message = this.signing && this.key !== undefined
      ? sign(this.dialect, this.key, h, body)
      : Buffer.concat([encodeHeader(h), body]);
    // The hash covers the request as sent, signature and all.
    beforeSend?.(message);
    return new Promise((resolve) => {
      this.waiting.set(String(id), resolve);
      this.socket!.write(frame(message));
    });
  }

  /** Negotiates a dialect, answering its name. */
  async negotiate(): Promise<number> {
    const names = this.opts.dialects ?? ["SMB2", "SMB2.1", "SMB3", "SMB3.0.2",
      "SMB3.1.1"];
    const revisions = names.map((n) => DIALECTS[n]);
    const asks311 = revisions.includes(0x0311);

    const fixedSize = 36;
    const dialects = Buffer.alloc(revisions.length * 2);
    revisions.forEach((r, i) => dialects.writeUInt16LE(r, i * 2));

    let contexts = Buffer.alloc(0);
    let padding = Buffer.alloc(0);
    let contextOffset = 0;
    if (asks311) {
      const salt = randomBytes(32);
      const data = Buffer.alloc(6 + salt.length);
      data.writeUInt16LE(1, 0);
      data.writeUInt16LE(salt.length, 2);
      data.writeUInt16LE(HASH_SHA512, 4);
      salt.copy(data, 6);
      const ctx = Buffer.alloc(8 + data.length);
      ctx.writeUInt16LE(CTX.PREAUTH_INTEGRITY_CAPABILITIES, 0);
      ctx.writeUInt16LE(data.length, 2);
      data.copy(ctx, 8);
      contexts = ctx;
      const end = HEADER_SIZE + fixedSize + dialects.length;
      padding = Buffer.alloc(align8(end) - end);
      contextOffset = align8(end);
    }

    const out = Buffer.alloc(fixedSize);
    out.writeUInt16LE(36, 0);
    out.writeUInt16LE(revisions.length, 2);
    out.writeUInt16LE(
      SIGNING_ENABLED | (this.opts.signingRequired === true ? SIGNING_REQUIRED : 0), 4);
    out.writeUInt32LE(0, 8); // Capabilities: none claimed
    randomBytes(16).copy(out, 12); // ClientGuid
    if (asks311) {
      out.writeUInt32LE(contextOffset, 28);
      out.writeUInt16LE(1, 32);
    }
    const body = Buffer.concat([out, dialects, padding, contexts]);

    let request = Buffer.alloc(0);
    const r = await this.send(CMD.NEGOTIATE, body, {}, (sent) => {
      request = sent;
    });
    if (r.header.status !== NT.SUCCESS) {
      throw new SmbError(CMD.NEGOTIATE, r.header.status);
    }
    this.dialect = r.body.readUInt16LE(4);
    if (this.dialect === 0x0311) {
      this.preauth = preauthHash(PREAUTH_ZERO, request);
      this.preauth = preauthHash(this.preauth, r.message);
    }
    // A server that requires signing is signed for, and so is a client
    // that requires it of itself.
    const serverMode = r.body.readUInt16LE(2);
    this.signing = (serverMode & SIGNING_REQUIRED) !== 0 ||
      this.opts.signingRequired === true;
    return this.dialect;
  }

  /** Authenticates, either with a password or as the anonymous principal. */
  async sessionSetup(user?: string, password?: string, domain = ""): Promise<void> {
    const flags = NEGOTIATE_FLAGS.UNICODE | NEGOTIATE_FLAGS.REQUEST_TARGET |
      NEGOTIATE_FLAGS.NTLM | NEGOTIATE_FLAGS.ALWAYS_SIGN |
      NEGOTIATE_FLAGS.EXTENDED_SESSIONSECURITY | NEGOTIATE_FLAGS.KEY_EXCH |
      NEGOTIATE_FLAGS.KEY_128;

    const first = await this.setupRound(negotiateMessage(flags >>> 0), true);
    if (first.header.status !== NT.MORE_PROCESSING_REQUIRED) {
      throw new SmbError(CMD.SESSION_SETUP, first.header.status);
    }
    this.sessionId = first.header.sessionId;
    const offset = first.body.readUInt16LE(4);
    const length = first.body.readUInt16LE(6);
    const token = fieldAt(first.message, offset, length);
    if (token === undefined || !isNtlmssp(token)) {
      throw new SmbError(CMD.SESSION_SETUP, NT.INVALID_PARAMETER);
    }
    const challenge = readChallenge(token);

    let sessionKey = Buffer.alloc(16);
    let authenticate: Buffer;
    if (user === undefined) {
      authenticate = clientAnonymous(this.opts.workstation ?? "SEEDMI", flags >>> 0);
    } else {
      const computed = clientAuthenticate(
        user, domain, password ?? "", this.opts.workstation ?? "SEEDMI",
        challenge.challenge, challenge.targetInfo, fileTime(Date.now()),
        (flags & challenge.flags) >>> 0);
      authenticate = computed.message;
      sessionKey = computed.sessionKey;
    }

    // The key is derived before the last message is sent, because for
    // the 3.1.1 dialect the hash the derivation uses covers that
    // message and not the response to it.
    const second = await this.setupRound(authenticate, false, () => {
      if (user !== undefined) {
        this.key = signingKey(this.dialect, sessionKey, this.preauth);
      }
    });
    if (second.header.status !== NT.SUCCESS) {
      this.key = undefined;
      throw new SmbError(CMD.SESSION_SETUP, second.header.status);
    }
    if (user === undefined) {
      // An anonymous session has no key, so it does not sign.
      this.key = undefined;
      this.signing = false;
      return;
    }
    // The last request of the exchange is not signed: the key is
    // derived from a hash that covers it, so a signature on it could
    // not be computed before the key it needs. The response to it is
    // signed, and is the first message either end verifies.
    this.verify(second);
  }

  /**
   * A session established with a Kerberos ticket: the GSS token is sent as
   * the security buffer of a single SESSION_SETUP, as a client of a realm
   * does (revision 282; PLAN-auth.md, phase 8). The answer, where the server
   * returns one, is given back so that a client may authenticate the server.
   */
  async sessionSetupKerberos(token: Buffer): Promise<Buffer> {
    const r = await this.setupRound(token, true);
    // One exchange settles it: the server either established the session or
    // refused the ticket, and there is no further round to send.
    if (r.header.status !== NT.SUCCESS) throw new SmbError(CMD.SESSION_SETUP, r.header.status);
    this.sessionId = r.header.sessionId;
    const offset = r.body.readUInt16LE(4);
    const length = r.body.readUInt16LE(6);
    return length === 0 ? Buffer.alloc(0) : Buffer.from(r.message.subarray(offset, offset + length));
  }

  private async setupRound(
    token: Buffer,
    first: boolean,
    afterHash?: () => void,
  ): Promise<Response> {
    const b = new Body(24);
    const sec = b.add(token);
    const out = Buffer.alloc(24);
    out.writeUInt16LE(25, 0);
    out.writeUInt8(0, 2); // Flags
    out.writeUInt8(
      SIGNING_ENABLED | (this.opts.signingRequired === true ? SIGNING_REQUIRED : 0), 3);
    out.writeUInt32LE(0, 4); // Capabilities
    out.writeUInt32LE(0, 8); // Channel
    out.writeUInt16LE(sec.offset, 12);
    out.writeUInt16LE(sec.length, 14);
    out.writeBigUInt64LE(0n, 16); // PreviousSessionId
    const body = Buffer.concat([out, b.buffer()]);

    const r = await this.send(CMD.SESSION_SETUP, body, { sessionId: this.sessionId },
      (sent) => {
        if (this.dialect === 0x0311) {
          this.preauth = preauthHash(this.preauth, sent);
        }
        // The key is derived from the hash as it stands with this
        // request joined and before the response arrives.
        afterHash?.();
      });
    if (this.dialect === 0x0311 && first) {
      this.preauth = preauthHash(this.preauth, r.message);
    }
    return r;
  }

  /** Connects a tree, answering the maximal access the server reports. */
  async treeConnect(host: string, share: string): Promise<number> {
    const path = utf16(`\\\\${host}\\${share}`);
    const b = new Body(8);
    const p = b.add(path);
    const out = Buffer.alloc(8);
    out.writeUInt16LE(9, 0);
    out.writeUInt16LE(0, 2); // Flags
    out.writeUInt16LE(p.offset, 4);
    out.writeUInt16LE(p.length, 6);
    const r = await this.send(CMD.TREE_CONNECT, Buffer.concat([out, b.buffer()]));
    if (r.header.status !== NT.SUCCESS) {
      throw new SmbError(CMD.TREE_CONNECT, r.header.status);
    }
    this.treeId = r.header.treeId;
    this.verify(r);
    return r.body.readUInt32LE(12);
  }

  /** Sends an echo, which needs a session and no tree. */
  async echo(): Promise<void> {
    const out = Buffer.alloc(4);
    out.writeUInt16LE(4, 0);
    const r = await this.send(CMD.ECHO, out);
    if (r.header.status !== NT.SUCCESS) throw new SmbError(CMD.ECHO, r.header.status);
    this.verify(r);
  }

  async treeDisconnect(): Promise<void> {
    const out = Buffer.alloc(4);
    out.writeUInt16LE(4, 0);
    const r = await this.send(CMD.TREE_DISCONNECT, out);
    if (r.header.status !== NT.SUCCESS) {
      throw new SmbError(CMD.TREE_DISCONNECT, r.header.status);
    }
    this.treeId = 0;
  }

  async logoff(): Promise<void> {
    const out = Buffer.alloc(4);
    out.writeUInt16LE(4, 0);
    const r = await this.send(CMD.LOGOFF, out);
    if (r.header.status !== NT.SUCCESS) throw new SmbError(CMD.LOGOFF, r.header.status);
    this.sessionId = 0n;
    this.key = undefined;
    this.signing = false;
  }

  /** Opens a path within the connected tree, answering the open. */
  async create(path: string, desired = 0x00120089, options = 0): Promise<{
    id: bigint;
    size: number;
    attributes: number;
    written: bigint;
  }> {
    const name = utf16(path);
    const b = new Body(56);
    const n = b.add(name);
    const out = Buffer.alloc(56);
    out.writeUInt16LE(57, 0);
    out.writeUInt8(0, 2); // SecurityFlags
    out.writeUInt8(0, 3); // RequestedOplockLevel
    out.writeUInt32LE(2, 4); // ImpersonationLevel: impersonation
    out.writeUInt32LE(desired, 24);
    out.writeUInt32LE(0, 28); // FileAttributes
    out.writeUInt32LE(7, 32); // ShareAccess: read, write and delete
    out.writeUInt32LE(1, 36); // CreateDisposition: FILE_OPEN
    out.writeUInt32LE(options, 40);
    out.writeUInt16LE(name.length === 0 ? 0 : n.offset, 44);
    out.writeUInt16LE(name.length, 46);
    // The fixed part is 57 because the buffer counts one octet even
    // where it is empty, which is how a request with no name is sent.
    const buffer = name.length === 0 ? Buffer.alloc(1) : b.buffer();
    const r = await this.send(CMD.CREATE, Buffer.concat([out, buffer]));
    if (r.header.status !== NT.SUCCESS) throw new SmbError(CMD.CREATE, r.header.status);
    this.verify(r);
    return {
      id: r.body.readBigUInt64LE(64),
      size: Number(r.body.readBigUInt64LE(48)),
      attributes: r.body.readUInt32LE(56),
      written: r.body.readBigUInt64LE(24),
    };
  }

  /** Reads a range of an open. */
  async read(id: bigint, offset: number, length: number): Promise<Buffer> {
    const out = Buffer.alloc(49);
    out.writeUInt16LE(49, 0);
    out.writeUInt8(HEADER_SIZE + 48, 2); // Padding
    out.writeUInt32LE(length, 4);
    out.writeBigUInt64LE(BigInt(offset), 8);
    out.writeBigUInt64LE(id, 16);
    out.writeBigUInt64LE(id, 24);
    const r = await this.send(CMD.READ, out);
    if (r.header.status !== NT.SUCCESS) throw new SmbError(CMD.READ, r.header.status);
    this.verify(r);
    const at = r.body.readUInt8(2);
    const len = r.body.readUInt32LE(4);
    return Buffer.from(r.message.subarray(at, at + len));
  }

  /**
   * Lists an open of a container object, answering the names. The
   * class defaults to the one a client of Windows asks for.
   */
  async queryDirectory(
    id: bigint,
    pattern = "*",
    cls = 0x25,
    flags = 0,
    outputLength = 65536,
  ): Promise<{ names: string[]; status: number }> {
    const name = utf16(pattern);
    const b = new Body(32);
    const p = b.add(name);
    const out = Buffer.alloc(32);
    out.writeUInt16LE(33, 0);
    out.writeUInt8(cls, 2);
    out.writeUInt8(flags, 3);
    out.writeUInt32LE(0, 4); // FileIndex
    out.writeBigUInt64LE(id, 8);
    out.writeBigUInt64LE(id, 16);
    out.writeUInt16LE(p.offset, 24);
    out.writeUInt16LE(p.length, 26);
    out.writeUInt32LE(outputLength, 28);
    const buffer = name.length === 0 ? Buffer.alloc(1) : b.buffer();
    const r = await this.send(CMD.QUERY_DIRECTORY, Buffer.concat([out, buffer]));
    if (r.header.status !== NT.SUCCESS) return { names: [], status: r.header.status };
    this.verify(r);
    const at = r.body.readUInt16LE(2);
    const len = r.body.readUInt32LE(4);
    return { names: parseDirectory(cls, r.message.subarray(at, at + len)), status: 0 };
  }

  /** Asks for one information level of an open. */
  async queryInfo(id: bigint, type: number, cls: number, outputLength = 65536):
    Promise<Buffer> {
    // Forty octets of fixed part and one of buffer, which the
    // structure size of 41 counts even where the buffer is empty.
    const out = Buffer.alloc(41);
    out.writeUInt16LE(41, 0);
    out.writeUInt8(type, 2);
    out.writeUInt8(cls, 3);
    out.writeUInt32LE(outputLength, 4);
    out.writeUInt16LE(0, 8); // InputBufferOffset
    out.writeUInt32LE(0, 12); // InputBufferLength
    out.writeUInt32LE(0, 16); // AdditionalInformation
    out.writeUInt32LE(0, 20); // Flags
    out.writeBigUInt64LE(id, 24);
    out.writeBigUInt64LE(id, 32);
    const r = await this.send(CMD.QUERY_INFO, out);
    if (r.header.status !== NT.SUCCESS) {
      throw new SmbError(CMD.QUERY_INFO, r.header.status);
    }
    this.verify(r);
    const at = r.body.readUInt16LE(2);
    const len = r.body.readUInt32LE(4);
    return Buffer.from(r.message.subarray(at, at + len));
  }

  /** Closes an open. */
  async closeFile(id: bigint): Promise<void> {
    const out = Buffer.alloc(24);
    out.writeUInt16LE(24, 0);
    out.writeBigUInt64LE(id, 8);
    out.writeBigUInt64LE(id, 16);
    const r = await this.send(CMD.CLOSE, out);
    if (r.header.status !== NT.SUCCESS) throw new SmbError(CMD.CLOSE, r.header.status);
    this.verify(r);
  }

  /**
   * Opens with a disposition and options of the caller's choosing,
   * answering the action the server reports.
   */
  async createWith(path: string, disposition: number, options = 0, desired = 0x001f01ff):
    Promise<{ id: bigint; action: number; size: number; attributes: number }> {
    const name = utf16(path);
    const b = new Body(56);
    const n = b.add(name);
    const out = Buffer.alloc(56);
    out.writeUInt16LE(57, 0);
    out.writeUInt32LE(2, 4);
    out.writeUInt32LE(desired, 24);
    out.writeUInt32LE(0, 28);
    out.writeUInt32LE(7, 32);
    out.writeUInt32LE(disposition, 36);
    out.writeUInt32LE(options, 40);
    out.writeUInt16LE(name.length === 0 ? 0 : n.offset, 44);
    out.writeUInt16LE(name.length, 46);
    const buffer = name.length === 0 ? Buffer.alloc(1) : b.buffer();
    const r = await this.send(CMD.CREATE, Buffer.concat([out, buffer]));
    if (r.header.status !== NT.SUCCESS) throw new SmbError(CMD.CREATE, r.header.status);
    this.verify(r);
    return {
      id: r.body.readBigUInt64LE(64),
      action: r.body.readUInt32LE(4),
      size: Number(r.body.readBigUInt64LE(48)),
      attributes: r.body.readUInt32LE(56),
    };
  }

  /** Writes to an open, answering the count the server accepted. */
  async write(id: bigint, offset: number, data: Buffer): Promise<number> {
    const b = new Body(48);
    const d = b.add(data);
    const out = Buffer.alloc(48);
    out.writeUInt16LE(49, 0);
    out.writeUInt16LE(d.offset, 2);
    out.writeUInt32LE(data.length, 4);
    out.writeBigUInt64LE(BigInt(offset), 8);
    out.writeBigUInt64LE(id, 16);
    out.writeBigUInt64LE(id, 24);
    const r = await this.send(CMD.WRITE, Buffer.concat([out, b.buffer()]));
    if (r.header.status !== NT.SUCCESS) throw new SmbError(CMD.WRITE, r.header.status);
    this.verify(r);
    return r.body.readUInt32LE(4);
  }

  /** Sets one information level of an open. */
  async setInfo(id: bigint, type: number, cls: number, data: Buffer,
    additional = 0): Promise<void> {
    const b = new Body(32);
    const d = b.add(data);
    const out = Buffer.alloc(32);
    out.writeUInt16LE(33, 0);
    out.writeUInt8(type, 2);
    out.writeUInt8(cls, 3);
    out.writeUInt32LE(data.length, 4);
    out.writeUInt16LE(d.offset, 8);
    // The parts of a security descriptor the request names.
    out.writeUInt32LE(additional, 12);
    out.writeBigUInt64LE(id, 16);
    out.writeBigUInt64LE(id, 24);
    const r = await this.send(CMD.SET_INFO, Buffer.concat([out, b.buffer()]));
    if (r.header.status !== NT.SUCCESS) {
      throw new SmbError(CMD.SET_INFO, r.header.status);
    }
    this.verify(r);
  }

  /** Asks for the object of an open to be removed when it closes. */
  setDeletePending(id: bigint, pending = true): Promise<void> {
    return this.setInfo(id, 1, 0x0d, Buffer.from([pending ? 1 : 0]));
  }

  /** Sets the length of the value of an open. */
  setEndOfFile(id: bigint, size: number): Promise<void> {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(BigInt(size));
    return this.setInfo(id, 1, 0x14, b);
  }

  /** Renames the object of an open. */
  rename(id: bigint, to: string, replace = false): Promise<void> {
    const name = utf16(to);
    const b = Buffer.alloc(20 + name.length);
    b.writeUInt8(replace ? 1 : 0, 0);
    b.writeUInt32LE(name.length, 16);
    name.copy(b, 20);
    return this.setInfo(id, 1, 0x0a, b);
  }

  /** Sends a control operation, answering what it returned. */
  async ioctl(id: bigint, code: number, input = Buffer.alloc(0),
    maxOutput = 65536): Promise<Buffer> {
    const b = new Body(56);
    const i = b.add(input);
    const out = Buffer.alloc(56);
    out.writeUInt16LE(57, 0);
    out.writeUInt32LE(code, 4);
    out.writeBigUInt64LE(id, 8);
    out.writeBigUInt64LE(id, 16);
    out.writeUInt32LE(input.length === 0 ? 0 : i.offset, 24);
    out.writeUInt32LE(input.length, 28);
    out.writeUInt32LE(0, 32); // MaxInputResponse
    out.writeUInt32LE(0, 36); // OutputOffset
    out.writeUInt32LE(0, 40); // OutputCount
    out.writeUInt32LE(maxOutput, 44);
    out.writeUInt32LE(1, 48); // Flags: an operation on the file
    const buffer = input.length === 0 ? Buffer.alloc(1) : b.buffer();
    const r = await this.send(CMD.IOCTL, Buffer.concat([out, buffer]));
    if (r.header.status !== NT.SUCCESS) throw new SmbError(CMD.IOCTL, r.header.status);
    this.verify(r);
    const at = r.body.readUInt32LE(32);
    const len = r.body.readUInt32LE(36);
    return len === 0
      ? Buffer.alloc(0)
      : Buffer.from(r.message.subarray(at, at + len));
  }

  /** Asks for a security descriptor, answering the parts requested. */
  async querySecurity(id: bigint, wanted: number, outputLength = 65536):
    Promise<Buffer> {
    const out = Buffer.alloc(41);
    out.writeUInt16LE(41, 0);
    out.writeUInt8(3, 2); // InfoType: security
    out.writeUInt8(0, 3);
    out.writeUInt32LE(outputLength, 4);
    out.writeUInt32LE(wanted, 16); // AdditionalInformation
    out.writeBigUInt64LE(id, 24);
    out.writeBigUInt64LE(id, 32);
    const r = await this.send(CMD.QUERY_INFO, out);
    if (r.header.status !== NT.SUCCESS) {
      throw new SmbError(CMD.QUERY_INFO, r.header.status);
    }
    this.verify(r);
    const at = r.body.readUInt16LE(2);
    const len = r.body.readUInt32LE(4);
    return Buffer.from(r.message.subarray(at, at + len));
  }

  /**
   * Opens without asking to open a reparse point, answering the
   * substitute name where the path met one.
   */
  async createFollowing(path: string): Promise<
    { id?: bigint; symlink?: { substitute: string; relative: boolean } }> {
    const name = utf16(path);
    const b = new Body(56);
    const n = b.add(name);
    const out = Buffer.alloc(56);
    out.writeUInt16LE(57, 0);
    out.writeUInt32LE(2, 4);
    out.writeUInt32LE(0x00120089, 24);
    out.writeUInt32LE(7, 32);
    out.writeUInt32LE(1, 36); // FILE_OPEN
    out.writeUInt16LE(name.length === 0 ? 0 : n.offset, 44);
    out.writeUInt16LE(name.length, 46);
    const buffer = name.length === 0 ? Buffer.alloc(1) : b.buffer();
    const r = await this.send(CMD.CREATE, Buffer.concat([out, buffer]));
    if (r.header.status === NT.SUCCESS) return { id: r.body.readBigUInt64LE(64) };
    if ((r.header.status >>> 0) !== 0x8000002d) {
      throw new SmbError(CMD.CREATE, r.header.status);
    }
    // The symbolic link error response, whose substitute name the
    // client resolves for itself.
    const data = r.body.subarray(8);
    const subOffset = data.readUInt16LE(16);
    const subLength = data.readUInt16LE(18);
    return {
      symlink: {
        substitute: data.subarray(28 + subOffset, 28 + subOffset + subLength)
          .toString("utf16le"),
        relative: (data.readUInt32LE(24) & 0x01) !== 0,
      },
    };
  }

  /**
   * Damages the signing key, so that a test can observe what a server
   * does with a message whose signature does not verify.
   */
  tamperKey(): void {
    if (this.key !== undefined) this.key[0] ^= 0xff;
  }

  /** Sends a command this phase does not implement, for a test. */
  async raw(command: number, body: Buffer): Promise<Response> {
    return this.send(command, body);
  }

  /** Checks the signature of a response, where the session signs. */
  private verify(r: Response): void {
    if (!this.signing || this.key === undefined) return;
    if ((r.header.flags & FLAG.SIGNED) === 0 ||
      !verifySignature(this.dialect, this.key, r.message)) {
      throw new Error("the response of a signed session is not correctly signed");
    }
  }
}

/** The names a directory listing carries, for each class this client asks for. */
function parseDirectory(cls: number, data: Buffer): string[] {
  const nameAt: Record<number, [number, number]> = {
    0x01: [60, 64],
    0x02: [60, 68],
    0x03: [60, 94],
    0x0c: [8, 12],
    0x25: [60, 104],
    0x26: [60, 80],
  };
  const where = nameAt[cls];
  if (where === undefined) return [];
  const out: string[] = [];
  let at = 0;
  for (;;) {
    if (at + where[1] > data.length) break;
    const next = data.readUInt32LE(at);
    const length = data.readUInt32LE(at + where[0]);
    out.push(data.subarray(at + where[1], at + where[1] + length).toString("utf16le"));
    if (next === 0) break;
    at += next;
  }
  return out;
}
