// Carrying MQTT over a WebSocket, as RFC 6455 defines one.
//
// A broker reached this way has a resource path of its own,
// conventionally "/mqtt", which the CDMI server requests in the
// handshake that establishes the connection, and the subprotocol
// "mqtt" is named in that handshake: MQTT requires it of a
// connection carried over a WebSocket, and a broker that does not
// select it is not one this server will talk to.
//
// A frame boundary has nothing to do with a packet boundary, so the
// payloads of the binary frames are concatenated and the MQTT packet
// reader takes what it needs from the result.

import { connect as tcpConnect, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { createHash, randomBytes } from "node:crypto";

/** The globally unique identifier RFC 6455 appends to the key. */
const ACCEPT_SALT = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/** The opcodes of the frames this transport uses. */
const OP = {
  CONTINUATION: 0x0,
  TEXT: 0x1,
  BINARY: 0x2,
  CLOSE: 0x8,
  PING: 0x9,
  PONG: 0xa,
} as const;

export class WebSocketError extends Error {}

export interface WebSocketOptions {
  host: string;
  port: number;
  /** The resource path of the broker, conventionally "/mqtt". */
  endpoint: string;
  /** Whether the connection is carried over TLS, for a "wss" URI. */
  secure: boolean;
  /** The TLS settings, where the connection is secure. */
  tls?: {
    ca?: string;
    cert?: string;
    key?: string;
    rejectUnauthorized?: boolean;
    servername?: string;
    ALPNProtocols?: string[];
    minVersion?: string;
    maxVersion?: string;
  };
  timeout?: number;
}

/**
 * A duplex of MQTT octets carried over a WebSocket. It presents the
 * part of a socket the MQTT client uses — write, the data and error
 * and close events, and destroy — so that the client speaks to one
 * or the other without knowing which.
 */
export class WebSocketTransport {
  private socket?: Socket;
  private held = Buffer.alloc(0);
  /** The payloads of a message being received across frames. */
  private assembling: Buffer[] = [];
  private readonly listeners = new Map<string, ((...a: unknown[]) => void)[]>();
  private open = false;

  private readonly opts: WebSocketOptions;

  constructor(opts: WebSocketOptions) {
    this.opts = opts;
  }

  /** Connects and performs the opening handshake. */
  async connect(): Promise<void> {
    const timeout = this.opts.timeout ?? 10000;
    const tls = this.opts.tls;
    this.socket = await new Promise<Socket>((resolve, reject) => {
      const s: Socket = this.opts.secure
        ? tlsConnect({
          host: this.opts.host,
          port: this.opts.port,
          servername: tls?.servername ?? this.opts.host,
          ...(tls?.ca === undefined ? {} : { ca: tls.ca }),
          ...(tls?.cert === undefined ? {} : { cert: tls.cert }),
          ...(tls?.key === undefined ? {} : { key: tls.key }),
          ...(tls?.rejectUnauthorized === undefined
            ? {}
            : { rejectUnauthorized: tls.rejectUnauthorized }),
          ...(tls?.minVersion === undefined ? {} : { minVersion: tls.minVersion }),
          ...(tls?.maxVersion === undefined ? {} : { maxVersion: tls.maxVersion }),
        }, () => {
          s.removeListener("error", reject);
          resolve(s);
        })
        : tcpConnect({ host: this.opts.host, port: this.opts.port }, () => {
          s.removeListener("error", reject);
          resolve(s);
        });
      s.setTimeout(timeout, () => {
        s.destroy();
        reject(new WebSocketError(
          `the broker at ${this.opts.host}:${this.opts.port} did not answer`));
      });
      s.once("error", reject);
    });
    this.socket.setTimeout(0);

    const key = randomBytes(16).toString("base64");
    const expected = createHash("sha1").update(key + ACCEPT_SALT).digest("base64");
    const host = this.opts.port === (this.opts.secure ? 443 : 80)
      ? this.opts.host
      : `${this.opts.host}:${this.opts.port}`;
    const request = [
      `GET ${this.opts.endpoint} HTTP/1.1`,
      `Host: ${host}`,
      "Upgrade: websocket",
      "Connection: Upgrade",
      `Sec-WebSocket-Key: ${key}`,
      "Sec-WebSocket-Version: 13",
      // MQTT requires the subprotocol of a connection carried over a
      // WebSocket to be named, and the broker to select it.
      "Sec-WebSocket-Protocol: mqtt",
      "",
      "",
    ].join("\r\n");

    const answered = new Promise<void>((resolve, reject) => {
      const onData = (chunk: Buffer) => {
        this.held = Buffer.concat([this.held, chunk]);
        const end = this.held.indexOf("\r\n\r\n");
        if (end < 0) {
          if (this.held.length > 65536) {
            reject(new WebSocketError("the handshake response is too long"));
          }
          return;
        }
        const head = this.held.subarray(0, end).toString("utf8");
        this.held = Buffer.from(this.held.subarray(end + 4));
        this.socket?.removeListener("data", onData);
        try {
          this.checkHandshake(head, expected);
        } catch (err) {
          reject(err as Error);
          return;
        }
        resolve();
      };
      this.socket?.on("data", onData);
      this.socket?.once("error", reject);
      setTimeout(
        () => reject(new WebSocketError("the broker did not complete the handshake")),
        timeout).unref?.();
    });
    this.socket.write(request);
    await answered;

    this.open = true;
    this.socket.on("data", (chunk: Buffer) => this.received(chunk));
    this.socket.on("error", (err: Error) => this.emit("error", err));
    this.socket.on("close", () => this.emit("close"));
    // Octets that arrived with the handshake response belong to the
    // first frames.
    if (this.held.length > 0) {
      const first = this.held;
      this.held = Buffer.alloc(0);
      this.received(first);
    }
  }

  private checkHandshake(head: string, expected: string): void {
    const lines = head.split("\r\n");
    const status = lines[0] ?? "";
    if (!/^HTTP\/1\.1 101\b/.test(status)) {
      throw new WebSocketError(
        `the broker answered the handshake with ${status.trim() || "nothing"}`);
    }
    const fields = new Map<string, string>();
    for (const line of lines.slice(1)) {
      const at = line.indexOf(":");
      if (at < 0) continue;
      fields.set(line.slice(0, at).trim().toLowerCase(), line.slice(at + 1).trim());
    }
    if ((fields.get("upgrade") ?? "").toLowerCase() !== "websocket") {
      throw new WebSocketError("the broker did not upgrade the connection");
    }
    if (fields.get("sec-websocket-accept") !== expected) {
      throw new WebSocketError("the accept value of the handshake does not match the key");
    }
    // A broker that does not select the subprotocol is not one this
    // server will carry MQTT over.
    if ((fields.get("sec-websocket-protocol") ?? "").toLowerCase() !== "mqtt") {
      throw new WebSocketError(
        'the broker did not select the "mqtt" subprotocol of the handshake');
    }
  }

  // -------------------------------------------------------------------
  // The part a socket presents

  write(data: Buffer): boolean {
    if (this.socket === undefined || !this.open) return false;
    // Every frame a client sends is masked, as RFC 6455 requires.
    return this.socket.write(frame(OP.BINARY, data, true));
  }

  on(event: string, listener: (...a: unknown[]) => void): this {
    const held = this.listeners.get(event) ?? [];
    held.push(listener);
    this.listeners.set(event, held);
    return this;
  }

  destroy(): void {
    if (this.socket !== undefined && this.open) {
      try {
        this.socket.write(frame(OP.CLOSE, Buffer.alloc(0), true));
      } catch {
        // The connection has gone; closing is all that remains.
      }
    }
    this.open = false;
    this.socket?.destroy();
    this.socket = undefined;
  }

  setTimeout(): void {
    // The MQTT client sets a timeout on the socket it connects and
    // clears it once the broker answers. The handshake here does its
    // own waiting, so there is nothing to set.
  }

  removeListener(): this {
    return this;
  }

  private emit(event: string, ...a: unknown[]): void {
    for (const l of this.listeners.get(event) ?? []) l(...a);
  }

  private received(chunk: Buffer): void {
    this.held = Buffer.concat([this.held, chunk]);
    for (;;) {
      const read = readFrame(this.held);
      if (read === undefined) return;
      this.held = Buffer.from(this.held.subarray(read.used));
      const f = read.frame;
      switch (f.opcode) {
        case OP.BINARY:
        case OP.TEXT:
        case OP.CONTINUATION: {
          this.assembling.push(f.payload);
          if (!f.fin) break;
          const message = Buffer.concat(this.assembling);
          this.assembling = [];
          // A frame boundary is not a packet boundary: the MQTT
          // reader takes whole packets from what has arrived.
          this.emit("data", message);
          break;
        }
        case OP.PING:
          this.socket?.write(frame(OP.PONG, f.payload, true));
          break;
        case OP.PONG:
          break;
        case OP.CLOSE:
          this.emit("close");
          this.destroy();
          return;
        default:
          this.emit("error", new WebSocketError(
            `the broker sent a frame of opcode ${f.opcode}`));
          this.destroy();
          return;
      }
    }
  }
}

/** One frame: the header fields this transport reads, and the payload. */
export interface Frame {
  fin: boolean;
  opcode: number;
  payload: Buffer;
}

/**
 * Encodes one frame. A frame a client sends is masked with a key of
 * four octets, which RFC 6455 requires of every frame from a client
 * and forbids of every frame from a server.
 */
export function frame(opcode: number, payload: Buffer, masked: boolean): Buffer {
  const head: number[] = [0x80 | opcode];
  const n = payload.length;
  const flag = masked ? 0x80 : 0;
  if (n < 126) {
    head.push(flag | n);
  } else if (n < 65536) {
    head.push(flag | 126, (n >> 8) & 0xff, n & 0xff);
  } else {
    head.push(flag | 127);
    const big = Buffer.alloc(8);
    big.writeUInt32BE(Math.floor(n / 2 ** 32), 0);
    big.writeUInt32BE(n >>> 0, 4);
    head.push(...big);
  }
  if (!masked) return Buffer.concat([Buffer.from(head), payload]);
  const key = randomBytes(4);
  const body = Buffer.from(payload);
  for (let i = 0; i < body.length; i++) body[i] ^= key[i % 4];
  return Buffer.concat([Buffer.from(head), key, body]);
}

/** The first whole frame in a buffer, and how many octets it took. */
export function readFrame(b: Buffer): { frame: Frame; used: number } | undefined {
  if (b.length < 2) return undefined;
  const first = b.readUInt8(0);
  const second = b.readUInt8(1);
  const masked = (second & 0x80) !== 0;
  let length = second & 0x7f;
  let at = 2;
  if (length === 126) {
    if (b.length < at + 2) return undefined;
    length = b.readUInt16BE(at);
    at += 2;
  } else if (length === 127) {
    if (b.length < at + 8) return undefined;
    const high = b.readUInt32BE(at);
    const low = b.readUInt32BE(at + 4);
    length = high * 2 ** 32 + low;
    at += 8;
  }
  let key: Buffer | undefined;
  if (masked) {
    if (b.length < at + 4) return undefined;
    key = Buffer.from(b.subarray(at, at + 4));
    at += 4;
  }
  if (b.length < at + length) return undefined;
  const payload = Buffer.from(b.subarray(at, at + length));
  if (key !== undefined) {
    for (let i = 0; i < payload.length; i++) payload[i] ^= key[i % 4];
  }
  return {
    frame: { fin: (first & 0x80) !== 0, opcode: first & 0x0f, payload },
    used: at + length,
  };
}

/** The accept value a server answers for a key, for a broker or a test. */
export function acceptFor(key: string): string {
  return createHash("sha1").update(key + ACCEPT_SALT).digest("base64");
}
