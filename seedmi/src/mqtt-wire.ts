// The MQTT control packets, for the versions this document names:
// 3.1.1, defined by ISO/IEC 20922, and 5.0.
//
// A CDMI server is the MQTT client in both directions — it publishes
// the values a queue object holds to a broker, and subscribes to a
// broker to enqueue what it receives — so this module encodes what a
// client sends and decodes what a broker sends. The broker side is
// decoded too, so that the tests can stand a broker up without one.

/** The control packet types, in the high nibble of the first octet. */
export const PACKET = {
  CONNECT: 1,
  CONNACK: 2,
  PUBLISH: 3,
  PUBACK: 4,
  PUBREC: 5,
  PUBREL: 6,
  PUBCOMP: 7,
  SUBSCRIBE: 8,
  SUBACK: 9,
  UNSUBSCRIBE: 10,
  UNSUBACK: 11,
  PINGREQ: 12,
  PINGRESP: 13,
  DISCONNECT: 14,
  AUTH: 15,
} as const;

/** The protocol level each version presents in a CONNECT packet. */
export const LEVEL: Record<string, number> = { "3.1.1": 4, "5.0": 5 };

/** The name of a packet type, for a log line or a message. */
export function packetName(type: number): string {
  const found = Object.entries(PACKET).find(([, v]) => v === type);
  return found === undefined ? String(type) : found[0];
}

/** A packet that cannot be read, or that this client will not send. */
export class MqttError extends Error {}

/**
 * The properties of an MQTT 5.0 packet. Only those this document
 * requires are named; another is carried as an identifier and octets
 * so that nothing a broker sends is lost.
 */
export const PROPERTY = {
  MESSAGE_EXPIRY_INTERVAL: 0x02,
  CONTENT_TYPE: 0x03,
  RESPONSE_TOPIC: 0x08,
  SESSION_EXPIRY_INTERVAL: 0x11,
  ASSIGNED_CLIENT_IDENTIFIER: 0x12,
  SERVER_KEEP_ALIVE: 0x13,
  REASON_STRING: 0x1f,
  RECEIVE_MAXIMUM: 0x21,
  TOPIC_ALIAS_MAXIMUM: 0x22,
  MAXIMUM_QOS: 0x24,
  RETAIN_AVAILABLE: 0x25,
  USER_PROPERTY: 0x26,
  MAXIMUM_PACKET_SIZE: 0x27,
} as const;

/** One property of an MQTT 5.0 packet. */
export interface Property {
  id: number;
  /** A whole number, a string, or a pair of strings for a user property. */
  value: number | string | [string, string];
}

// ---------------------------------------------------------------------
// The primitives
//
// A string is a two-octet length and that many octets of UTF-8, and
// binary data the same. A variable byte integer carries seven bits per
// octet, the high bit marking that another follows.

export function encodeVarint(n: number): Buffer {
  if (n < 0 || n > 268435455) {
    throw new MqttError(`${n} is outside the range of a variable byte integer`);
  }
  const out: number[] = [];
  do {
    let byte = n % 128;
    n = Math.floor(n / 128);
    if (n > 0) byte |= 0x80;
    out.push(byte);
  } while (n > 0);
  return Buffer.from(out);
}

export function decodeVarint(b: Buffer, at: number): { value: number; next: number } {
  let value = 0;
  let multiplier = 1;
  for (let i = 0; i < 4; i++) {
    if (at + i >= b.length) {
      throw new MqttError("a variable byte integer runs past the end of the packet");
    }
    const byte = b.readUInt8(at + i);
    value += (byte & 0x7f) * multiplier;
    if ((byte & 0x80) === 0) return { value, next: at + i + 1 };
    multiplier *= 128;
  }
  throw new MqttError("a variable byte integer is at most four octets");
}

export function encodeString(s: string): Buffer {
  const body = Buffer.from(s, "utf8");
  if (body.length > 65535) {
    throw new MqttError("a string is at most 65535 octets when encoded");
  }
  const out = Buffer.alloc(2 + body.length);
  out.writeUInt16BE(body.length, 0);
  body.copy(out, 2);
  return out;
}

export function decodeString(b: Buffer, at: number): { value: string; next: number } {
  if (at + 2 > b.length) throw new MqttError("a string runs past the end of the packet");
  const length = b.readUInt16BE(at);
  if (at + 2 + length > b.length) {
    throw new MqttError("a string runs past the end of the packet");
  }
  return { value: b.subarray(at + 2, at + 2 + length).toString("utf8"), next: at + 2 + length };
}

const encodeBinary = encodeString;

// ---------------------------------------------------------------------
// Properties

/** The properties of a packet, as a length-prefixed block. */
export function encodeProperties(props: Property[]): Buffer {
  const parts: Buffer[] = [];
  for (const p of props) {
    parts.push(Buffer.from([p.id]));
    switch (p.id) {
      case PROPERTY.SESSION_EXPIRY_INTERVAL:
      case PROPERTY.MESSAGE_EXPIRY_INTERVAL:
      case PROPERTY.MAXIMUM_PACKET_SIZE: {
        const b = Buffer.alloc(4);
        b.writeUInt32BE(Number(p.value));
        parts.push(b);
        break;
      }
      case PROPERTY.RECEIVE_MAXIMUM:
      case PROPERTY.TOPIC_ALIAS_MAXIMUM:
      case PROPERTY.SERVER_KEEP_ALIVE: {
        const b = Buffer.alloc(2);
        b.writeUInt16BE(Number(p.value));
        parts.push(b);
        break;
      }
      case PROPERTY.MAXIMUM_QOS:
      case PROPERTY.RETAIN_AVAILABLE:
        parts.push(Buffer.from([Number(p.value)]));
        break;
      case PROPERTY.USER_PROPERTY: {
        const [k, v] = p.value as [string, string];
        parts.push(encodeString(k), encodeString(v));
        break;
      }
      default:
        parts.push(encodeString(String(p.value)));
    }
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([encodeVarint(body.length), body]);
}

export function decodeProperties(b: Buffer, at: number):
  { props: Property[]; next: number } {
  const { value: length, next: start } = decodeVarint(b, at);
  const end = start + length;
  const props: Property[] = [];
  let i = start;
  while (i < end) {
    const id = b.readUInt8(i);
    i += 1;
    switch (id) {
      case PROPERTY.SESSION_EXPIRY_INTERVAL:
      case PROPERTY.MESSAGE_EXPIRY_INTERVAL:
      case PROPERTY.MAXIMUM_PACKET_SIZE:
        props.push({ id, value: b.readUInt32BE(i) });
        i += 4;
        break;
      case PROPERTY.RECEIVE_MAXIMUM:
      case PROPERTY.TOPIC_ALIAS_MAXIMUM:
      case PROPERTY.SERVER_KEEP_ALIVE:
        props.push({ id, value: b.readUInt16BE(i) });
        i += 2;
        break;
      case PROPERTY.MAXIMUM_QOS:
      case PROPERTY.RETAIN_AVAILABLE:
        props.push({ id, value: b.readUInt8(i) });
        i += 1;
        break;
      case PROPERTY.USER_PROPERTY: {
        const k = decodeString(b, i);
        const v = decodeString(b, k.next);
        props.push({ id, value: [k.value, v.value] });
        i = v.next;
        break;
      }
      default: {
        // A property this module does not name is carried as a string,
        // which is the form of every remaining property this client
        // meets. One of another form ends the block.
        const s = decodeString(b, i);
        props.push({ id, value: s.value });
        i = s.next;
      }
    }
  }
  return { props, next: end };
}

// ---------------------------------------------------------------------
// The packets a client sends

export interface ConnectOptions {
  version: string;
  clientID: string;
  keepAlive: number;
  cleanStart: boolean;
  username?: string;
  password?: string;
  will?: { topic: string; payload: Buffer; qos: number; retain: boolean };
  properties?: Property[];
}

export function encodeConnect(o: ConnectOptions): Buffer {
  const level = LEVEL[o.version];
  if (level === undefined) {
    throw new MqttError(`${o.version} is not an MQTT version this client speaks`);
  }
  let flags = 0;
  if (o.cleanStart) flags |= 0x02;
  if (o.will) {
    flags |= 0x04 | ((o.will.qos & 0x03) << 3);
    if (o.will.retain) flags |= 0x20;
  }
  if (o.username !== undefined) flags |= 0x80;
  if (o.password !== undefined) flags |= 0x40;

  const head = Buffer.alloc(4);
  head.writeUInt8(level, 0);
  head.writeUInt8(flags, 1);
  head.writeUInt16BE(o.keepAlive, 2);

  const parts: Buffer[] = [encodeString("MQTT"), head];
  if (level === 5) parts.push(encodeProperties(o.properties ?? []));
  parts.push(encodeString(o.clientID));
  if (o.will) {
    // The will properties of MQTT 5.0 precede the will topic; none is
    // sent, so the block is empty.
    if (level === 5) parts.push(encodeProperties([]));
    parts.push(encodeString(o.will.topic), encodeBinary(o.will.payload.toString("binary")));
  }
  if (o.username !== undefined) parts.push(encodeString(o.username));
  if (o.password !== undefined) parts.push(encodeString(o.password));
  return frame(PACKET.CONNECT, 0, Buffer.concat(parts));
}

export interface PublishOptions {
  version: string;
  topic: string;
  payload: Buffer;
  qos: number;
  retain: boolean;
  dup?: boolean;
  packetID?: number;
  properties?: Property[];
}

export function encodePublish(o: PublishOptions): Buffer {
  if (o.qos > 0 && o.packetID === undefined) {
    throw new MqttError("a PUBLISH of QoS 1 or 2 carries a packet identifier");
  }
  const parts: Buffer[] = [encodeString(o.topic)];
  if (o.qos > 0) {
    const id = Buffer.alloc(2);
    id.writeUInt16BE(o.packetID as number);
    parts.push(id);
  }
  if (LEVEL[o.version] === 5) parts.push(encodeProperties(o.properties ?? []));
  parts.push(o.payload);
  const flags = ((o.dup === true ? 1 : 0) << 3) | ((o.qos & 0x03) << 1) |
    (o.retain ? 1 : 0);
  return frame(PACKET.PUBLISH, flags, Buffer.concat(parts));
}

/** An acknowledgement carrying a packet identifier alone, or with a reason. */
export function encodeAck(type: number, packetID: number, version: string,
  reason = 0): Buffer {
  const id = Buffer.alloc(2);
  id.writeUInt16BE(packetID);
  const parts = [id];
  // A reason code and an empty property block are omitted where the
  // reason is success, which MQTT 5.0 permits and 3.1.1 requires.
  if (LEVEL[version] === 5 && reason !== 0) {
    parts.push(Buffer.from([reason]), encodeProperties([]));
  }
  // PUBREL carries the reserved flags 0010.
  const flags = type === PACKET.PUBREL ? 0x02 : 0;
  return frame(type, flags, Buffer.concat(parts));
}

export function encodeSubscribe(version: string, packetID: number,
  filters: { filter: string; qos: number }[]): Buffer {
  const id = Buffer.alloc(2);
  id.writeUInt16BE(packetID);
  const parts: Buffer[] = [id];
  if (LEVEL[version] === 5) parts.push(encodeProperties([]));
  for (const f of filters) {
    parts.push(encodeString(f.filter), Buffer.from([f.qos & 0x03]));
  }
  // SUBSCRIBE carries the reserved flags 0010.
  return frame(PACKET.SUBSCRIBE, 0x02, Buffer.concat(parts));
}

export function encodePing(): Buffer {
  return frame(PACKET.PINGREQ, 0, Buffer.alloc(0));
}

export function encodeDisconnect(version: string, reason = 0): Buffer {
  // MQTT 3.1.1 carries no variable header; 5.0 carries a reason code,
  // which is omitted where it is success.
  const body = LEVEL[version] === 5 && reason !== 0
    ? Buffer.from([reason])
    : Buffer.alloc(0);
  return frame(PACKET.DISCONNECT, 0, body);
}

/** A fixed header and its body. */
export function frame(type: number, flags: number, body: Buffer): Buffer {
  const length = encodeVarint(body.length);
  const out = Buffer.alloc(1 + length.length + body.length);
  out.writeUInt8(((type & 0x0f) << 4) | (flags & 0x0f), 0);
  length.copy(out, 1);
  body.copy(out, 1 + length.length);
  return out;
}

// ---------------------------------------------------------------------
// Reading packets

/** One packet read from a stream. */
export interface Packet {
  type: number;
  flags: number;
  body: Buffer;
}

/**
 * The first whole packet in a buffer, and how many octets it took. A
 * packet that has not arrived in full returns nothing, and the caller
 * reads more.
 */
export function readPacket(b: Buffer): { packet: Packet; used: number } | undefined {
  if (b.length < 2) return undefined;
  let length: { value: number; next: number };
  try {
    length = decodeVarint(b, 1);
  } catch {
    // Not yet arrived in full, unless it is longer than four octets,
    // which the next read settles.
    if (b.length < 5) return undefined;
    throw new MqttError("the remaining length of a packet is malformed");
  }
  const end = length.next + length.value;
  if (b.length < end) return undefined;
  const first = b.readUInt8(0);
  return {
    packet: {
      type: (first >> 4) & 0x0f,
      flags: first & 0x0f,
      body: b.subarray(length.next, end),
    },
    used: end,
  };
}

/** What a CONNACK reports. */
export interface Connack {
  sessionPresent: boolean;
  reason: number;
  properties: Property[];
}

export function decodeConnack(p: Packet, version: string): Connack {
  if (p.body.length < 2) throw new MqttError("a CONNACK is at least two octets");
  const out: Connack = {
    sessionPresent: (p.body.readUInt8(0) & 0x01) === 1,
    reason: p.body.readUInt8(1),
    properties: [],
  };
  if (LEVEL[version] === 5 && p.body.length > 2) {
    out.properties = decodeProperties(p.body, 2).props;
  }
  return out;
}

/** What a PUBLISH carries. */
export interface Publish {
  topic: string;
  payload: Buffer;
  qos: number;
  retain: boolean;
  dup: boolean;
  packetID?: number;
  properties: Property[];
}

export function decodePublish(p: Packet, version: string): Publish {
  const qos = (p.flags >> 1) & 0x03;
  const topic = decodeString(p.body, 0);
  let at = topic.next;
  let packetID: number | undefined;
  if (qos > 0) {
    packetID = p.body.readUInt16BE(at);
    at += 2;
  }
  let properties: Property[] = [];
  if (LEVEL[version] === 5) {
    const read = decodeProperties(p.body, at);
    properties = read.props;
    at = read.next;
  }
  return {
    topic: topic.value,
    payload: Buffer.from(p.body.subarray(at)),
    qos,
    retain: (p.flags & 0x01) === 1,
    dup: ((p.flags >> 3) & 0x01) === 1,
    ...(packetID === undefined ? {} : { packetID }),
    properties,
  };
}

/** The packet identifier of an acknowledgement, and its reason code. */
export function decodeAck(p: Packet): { packetID: number; reason: number } {
  if (p.body.length < 2) throw new MqttError("an acknowledgement carries an identifier");
  return {
    packetID: p.body.readUInt16BE(0),
    reason: p.body.length > 2 ? p.body.readUInt8(2) : 0,
  };
}

/** The granted QoS of each filter of a SUBSCRIBE, in the order sent. */
export function decodeSuback(p: Packet, version: string):
  { packetID: number; granted: number[] } {
  const packetID = p.body.readUInt16BE(0);
  let at = 2;
  if (LEVEL[version] === 5) at = decodeProperties(p.body, at).next;
  return { packetID, granted: [...p.body.subarray(at)] };
}
