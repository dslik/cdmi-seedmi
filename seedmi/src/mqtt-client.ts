// An MQTT client, for the export that publishes the values a queue
// object holds and the import that subscribes to a topic filter.
//
// A CDMI server connects outbound to a broker and exposes no broker
// endpoint of its own, so this is a client alone. It speaks 3.1.1 and
// 5.0, and the transports it makes are TCP and TLS; the WebSocket
// schemes of a broker URI are not yet served.

import { resolveAndCheck } from "./originated.ts";
import { connect as tcpConnect, type Socket } from "node:net";
import { WebSocketTransport } from "./mqtt-ws.ts";
import { connect as tlsConnect } from "node:tls";
import {
  type Connack,
  decodeAck,
  decodeConnack,
  decodePublish,
  encodeAck,
  encodeConnect,
  encodeDisconnect,
  encodePing,
  encodePublish,
  encodeSubscribe,
  MqttError,
  PACKET,
  type Packet,
  packetName,
  type Property,
  type Publish,
  readPacket,
} from "./mqtt-wire.ts";

export interface MqttClientOptions {
  host: string;
  port: number;
  version: string;
  clientID: string;
  keepAlive: number;
  cleanStart: boolean;
  username?: string;
  password?: string;
  will?: { topic: string; payload: Buffer; qos: number; retain: boolean };
  properties?: Property[];
  /** How long to wait for a broker to answer, in milliseconds. */
  timeout?: number;
  /** Called with each message received on a subscription. */
  onMessage?: (m: Publish) => void;
  /**
   * Where given, the connection is carried over a WebSocket to this
   * endpoint of the broker, conventionally "/mqtt".
   */
  websocket?: { endpoint: string; secure: boolean };
  /**
   * Where given, the connection is made over TLS with these
   * settings. The certificate of the broker is verified against the
   * trust store of the system where no authority is given.
   */
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
}

/** What a broker answered a CONNECT with. */
export class MqttRefused extends Error {
  readonly reason: number;

  constructor(reason: number) {
    super(`the broker refused the connection with reason ${reason}`);
    this.reason = reason;
  }
}

export class MqttClient {
  private socket?: Socket;
  private held = Buffer.alloc(0);
  private readonly opts: MqttClientOptions;
  private nextID = 1;
  /** What is waiting for an acknowledgement, by packet identifier. */
  private readonly waiting = new Map<number, {
    resolve: (reason: number) => void;
    reject: (err: Error) => void;
  }>();
  private awaitingConnack?: {
    resolve: (c: Connack) => void;
    reject: (err: Error) => void;
  };
  private ping?: ReturnType<typeof setInterval>;
  private closed = false;

  constructor(opts: MqttClientOptions) {
    this.opts = opts;
  }

  /** Whether the connection is open and the broker accepted it. */
  connected = false;

  /**
   * Connects to the broker and performs the CONNECT exchange. The
   * promise settles when the broker answers, or is rejected where it
   * refuses or does not answer.
   */
  async connect(): Promise<Connack> {
    const timeout = this.opts.timeout ?? 10000;
    const tls = this.opts.tls;
    const ws = this.opts.websocket;
    if (ws !== undefined) {
      // The WebSocket transport presents the part of a socket this
      // client uses, and performs its own handshake.
      const carried = new WebSocketTransport({
        host: this.opts.host,
        port: this.opts.port,
        endpoint: ws.endpoint,
        secure: ws.secure,
        ...(tls === undefined ? {} : { tls }),
        ...(this.opts.timeout === undefined ? {} : { timeout: this.opts.timeout }),
      });
      await carried.connect();
      this.socket = carried as unknown as Socket;
    }
    if (this.socket === undefined) {
      // A broker an entry names is reached by a server-originated request: the
      // address resolved is checked, and is the address connected to.
      const at = await resolveAndCheck(`${tls === undefined ? "mqtt" : "mqtts"}://${this.opts.host}:${this.opts.port}/`);
      this.socket = await new Promise<Socket>((resolve, reject) => {
      const s: Socket = tls === undefined
        ? tcpConnect({ host: at.address, port: this.opts.port }, () => {
          s.removeListener("error", reject);
          resolve(s);
        })
        : tlsConnect({
          host: at.address,
          port: this.opts.port,
          servername: tls.servername ?? this.opts.host,
          ...(tls.ca === undefined ? {} : { ca: tls.ca }),
          ...(tls.cert === undefined ? {} : { cert: tls.cert }),
          ...(tls.key === undefined ? {} : { key: tls.key }),
          ...(tls.rejectUnauthorized === undefined
            ? {}
            : { rejectUnauthorized: tls.rejectUnauthorized }),
          ...(tls.ALPNProtocols === undefined
            ? {}
            : { ALPNProtocols: tls.ALPNProtocols }),
          ...(tls.minVersion === undefined ? {} : { minVersion: tls.minVersion }),
          ...(tls.maxVersion === undefined ? {} : { maxVersion: tls.maxVersion }),
        }, () => {
          s.removeListener("error", reject);
          resolve(s);
        });
      s.setTimeout(timeout, () => {
        s.destroy();
        reject(new MqttError(
          `the broker at ${this.opts.host}:${this.opts.port} did not answer`));
      });
      s.once("error", reject);
      });
    }
    this.socket.setTimeout(0);
    this.socket.on("data", (chunk: Buffer) => this.received(chunk));
    this.socket.on("error", () => this.fail(new MqttError("the connection failed")));
    this.socket.on("close", () => this.fail(new MqttError("the broker closed the connection")));

    const answer = new Promise<Connack>((resolve, reject) => {
      this.awaitingConnack = { resolve, reject };
    });
    this.send(encodeConnect({
      version: this.opts.version,
      clientID: this.opts.clientID,
      keepAlive: this.opts.keepAlive,
      cleanStart: this.opts.cleanStart,
      ...(this.opts.username === undefined ? {} : { username: this.opts.username }),
      ...(this.opts.password === undefined ? {} : { password: this.opts.password }),
      ...(this.opts.will === undefined ? {} : { will: this.opts.will }),
      ...(this.opts.properties === undefined ? {} : { properties: this.opts.properties }),
    }));
    const connack = await this.within(answer, timeout, "CONNACK");
    if (connack.reason !== 0) {
      this.close();
      throw new MqttRefused(connack.reason);
    }
    this.connected = true;
    // The keep alive is the longest a broker waits without hearing
    // from this client, so a PINGREQ is sent at half of it.
    if (this.opts.keepAlive > 0) {
      this.ping = setInterval(() => {
        if (this.socket !== undefined && !this.closed) this.send(encodePing());
      }, (this.opts.keepAlive * 1000) / 2);
      this.ping.unref?.();
    }
    return connack;
  }

  /**
   * Publishes one message. At QoS 0 the promise settles when the
   * packet is written; at QoS 1 and 2 it settles when the broker has
   * acknowledged, so that a caller knows the message was delivered
   * before it removes the value from the queue object.
   */
  async publish(topic: string, payload: Buffer, opts: {
    qos?: number;
    retain?: boolean;
    properties?: Property[];
  } = {}): Promise<void> {
    const qos = opts.qos ?? 0;
    const packetID = qos > 0 ? this.take() : undefined;
    const done = qos > 0 ? this.expect(packetID as number) : undefined;
    this.send(encodePublish({
      version: this.opts.version,
      topic,
      payload,
      qos,
      retain: opts.retain === true,
      ...(packetID === undefined ? {} : { packetID }),
      ...(opts.properties === undefined ? {} : { properties: opts.properties }),
    }));
    if (done === undefined) return;
    const reason = await this.within(done, this.opts.timeout ?? 10000, "an acknowledgement");
    // A reason of 16 is "no matching subscribers", which is delivery
    // as far as this client is concerned.
    if (reason !== 0 && reason !== 16) {
      throw new MqttError(`the broker refused a message with reason ${reason}`);
    }
  }

  /** Subscribes to one or more topic filters, returning the QoS granted. */
  async subscribe(filters: { filter: string; qos: number }[]): Promise<number[]> {
    const packetID = this.take();
    const done = new Promise<number[]>((resolve, reject) => {
      this.granted.set(packetID, { resolve, reject });
    });
    this.send(encodeSubscribe(this.opts.version, packetID, filters));
    return this.within(done, this.opts.timeout ?? 10000, "a SUBACK");
  }

  private readonly granted = new Map<number, {
    resolve: (g: number[]) => void;
    reject: (err: Error) => void;
  }>();

  /** Sends DISCONNECT and closes, as an orderly departure. */
  disconnect(): void {
    if (this.socket !== undefined && !this.closed) {
      try {
        this.send(encodeDisconnect(this.opts.version));
      } catch {
        // The connection has gone; closing is all that remains.
      }
    }
    this.close();
  }

  close(): void {
    this.closed = true;
    this.connected = false;
    if (this.ping !== undefined) clearInterval(this.ping);
    this.socket?.destroy();
    this.socket = undefined;
  }

  // -------------------------------------------------------------------

  private send(b: Buffer): void {
    if (this.socket === undefined) throw new MqttError("the connection is not open");
    this.socket.write(b);
  }

  /** The next packet identifier, which wraps and skips zero. */
  private take(): number {
    const id = this.nextID;
    this.nextID = this.nextID === 65535 ? 1 : this.nextID + 1;
    return id;
  }

  private expect(packetID: number): Promise<number> {
    return new Promise<number>((resolve, reject) => {
      this.waiting.set(packetID, { resolve, reject });
    });
  }

  private async within<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
    let timer: ReturnType<typeof setTimeout>;
    const limit = new Promise<never>((_, reject) => {
      // Not unreferenced: this timer is what turns a broker that
      // never answers into a rejection, and a timer that does not
      // hold the loop open may never fire.
      timer = setTimeout(
        () => reject(new MqttError(`the broker did not send ${what} within ${ms}ms`)),
        ms);
    });
    try {
      return await Promise.race([p, limit]);
    } finally {
      clearTimeout(timer!);
    }
  }

  /** Fails everything waiting, where the connection has gone. */
  private fail(err: Error): void {
    this.connected = false;
    this.awaitingConnack?.reject(err);
    this.awaitingConnack = undefined;
    for (const w of this.waiting.values()) w.reject(err);
    this.waiting.clear();
    for (const g of this.granted.values()) g.reject(err);
    this.granted.clear();
  }

  private received(chunk: Buffer): void {
    this.held = Buffer.concat([this.held, chunk]);
    for (;;) {
      let read;
      try {
        read = readPacket(this.held);
      } catch (err) {
        this.fail(err as Error);
        this.close();
        return;
      }
      if (read === undefined) return;
      this.held = Buffer.from(this.held.subarray(read.used));
      this.handle(read.packet);
    }
  }

  private handle(p: Packet): void {
    switch (p.type) {
      case PACKET.CONNACK: {
        const waiting = this.awaitingConnack;
        this.awaitingConnack = undefined;
        if (waiting === undefined) return;
        try {
          waiting.resolve(decodeConnack(p, this.opts.version));
        } catch (err) {
          waiting.reject(err as Error);
        }
        return;
      }
      case PACKET.PUBACK:
      case PACKET.PUBCOMP: {
        const { packetID, reason } = decodeAck(p);
        this.waiting.get(packetID)?.resolve(reason);
        this.waiting.delete(packetID);
        return;
      }
      case PACKET.PUBREC: {
        // The first half of the QoS 2 exchange: the broker holds the
        // message, and PUBREL releases it. The caller waits for
        // PUBCOMP, so nothing is resolved here.
        const { packetID } = decodeAck(p);
        this.send(encodeAck(PACKET.PUBREL, packetID, this.opts.version));
        return;
      }
      case PACKET.SUBACK: {
        const packetID = p.body.readUInt16BE(0);
        const waiting = this.granted.get(packetID);
        this.granted.delete(packetID);
        if (waiting === undefined) return;
        try {
          const { granted } = decodeSubackOf(p, this.opts.version);
          waiting.resolve(granted);
        } catch (err) {
          waiting.reject(err as Error);
        }
        return;
      }
      case PACKET.PUBLISH: {
        const message = decodePublish(p, this.opts.version);
        // A message of QoS 1 is acknowledged once it is taken; one of
        // QoS 2 is acknowledged in two exchanges, and this client
        // completes the first and waits for PUBREL.
        if (message.qos === 1 && message.packetID !== undefined) {
          this.send(encodeAck(PACKET.PUBACK, message.packetID, this.opts.version));
        }
        if (message.qos === 2 && message.packetID !== undefined) {
          this.send(encodeAck(PACKET.PUBREC, message.packetID, this.opts.version));
        }
        this.opts.onMessage?.(message);
        return;
      }
      case PACKET.PUBREL: {
        const { packetID } = decodeAck(p);
        this.send(encodeAck(PACKET.PUBCOMP, packetID, this.opts.version));
        return;
      }
      case PACKET.PINGRESP:
        return;
      case PACKET.DISCONNECT:
        // MQTT 5.0 permits a broker to disconnect and say why.
        this.fail(new MqttError(
          `the broker disconnected with reason ${p.body.length > 0 ? p.body.readUInt8(0) : 0}`));
        this.close();
        return;
      default:
        this.fail(new MqttError(`a broker does not send ${packetName(p.type)}`));
        this.close();
    }
  }
}

// Imported here rather than at the top so that the name reads as what
// it does at the one place it is used.
import { decodeSuback as decodeSubackOf } from "./mqtt-wire.ts";
