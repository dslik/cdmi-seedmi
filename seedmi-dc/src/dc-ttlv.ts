// The TTLV encoding of KMIP 1.4, section 9.1, as a client needs it.
//
// This controller keeps its secret material at a key management server, so it is
// a KMIP client (DESIGN-admin.md §4). It shares no file with seedmi-kms, which is
// the point rather than an inconvenience: an independent client is what actually
// tests a server, and the two were written from the document rather than from
// each other.
//
// An item is a three-octet tag, a one-octet type, a four-octet length and a
// value padded to a multiple of eight. The tags this client uses are declared
// here by name and number, taken from Table 287; nothing is generated, because a
// client needs a few dozen of the several hundred the document defines.
//
// What this module does not do: it knows nothing of operations, messages or
// batches, which are dc-keys.ts, and it knows no enumeration's meaning — an
// Enumeration is a number here and is named at the call site.

/** Raised where an octet string is not a well formed TTLV item. */
export class TtlvError extends Error {}

/** The item types of Table 286. */
export const TYPE = Object.freeze({
  Structure: 0x01,
  Integer: 0x02,
  LongInteger: 0x03,
  BigInteger: 0x04,
  Enumeration: 0x05,
  Boolean: 0x06,
  TextString: 0x07,
  ByteString: 0x08,
  DateTime: 0x09,
  Interval: 0x0a,
} as const);

/**
 * The tags this client sends or reads, by the name the document gives each. A
 * number is written here rather than derived, and the name beside it is what a
 * reader checks against Table 287.
 */
export const TAG = Object.freeze({
  AttributeIndex: 0x420009,          // Attribute Index
  Attribute: 0x420008,               // Attribute
  AttributeName: 0x42000a,           // Attribute Name
  AttributeValue: 0x42000b,          // Attribute Value
  BatchCount: 0x42000d,              // Batch Count
  BatchItem: 0x42000f,               // Batch Item
  CompromiseOccurrenceDate: 0x420021, // Compromise Occurrence Date
  CryptographicAlgorithm: 0x420028,  // Cryptographic Algorithm
  CryptographicLength: 0x42002a,     // Cryptographic Length
  CryptographicUsageMask: 0x42002c,  // Cryptographic Usage Mask
  KeyBlock: 0x420040,                // Key Block
  KeyFormatType: 0x420042,           // Key Format Type
  KeyMaterial: 0x420043,             // Key Material
  KeyValue: 0x420045,                // Key Value
  LocatedItems: 0x4200d5,            // Located Items
  MaximumItems: 0x42004f,            // Maximum Items
  Name: 0x420053,                    // Name
  NameType: 0x420054,                // Name Type
  NameValue: 0x420055,               // Name Value
  ObjectGroup: 0x420056,             // Object Group
  ObjectType: 0x420057,              // Object Type
  OffsetItems: 0x4200d4,             // Offset Items
  Operation: 0x42005c,               // Operation
  ProtocolVersion: 0x420069,         // Protocol Version
  ProtocolVersionMajor: 0x42006a,    // Protocol Version Major
  ProtocolVersionMinor: 0x42006b,    // Protocol Version Minor
  RequestHeader: 0x420077,           // Request Header
  RequestMessage: 0x420078,          // Request Message
  RequestPayload: 0x420079,          // Request Payload
  ResponseHeader: 0x42007a,          // Response Header
  ResponseMessage: 0x42007b,         // Response Message
  ResponsePayload: 0x42007c,         // Response Payload
  ResultMessage: 0x42007d,           // Result Message
  ResultReason: 0x42007e,            // Result Reason
  ResultStatus: 0x42007f,            // Result Status
  RevocationMessage: 0x420080,       // Revocation Message
  RevocationReason: 0x420081,        // Revocation Reason
  RevocationReasonCode: 0x420082,    // Revocation Reason Code
  SecretData: 0x420085,              // Secret Data
  SecretDataType: 0x420086,          // Secret Data Type
  SymmetricKey: 0x42008f,            // Symmetric Key
  TemplateAttribute: 0x420091,       // Template-Attribute
  TimeStamp: 0x420092,               // Time Stamp
  UniqueIdentifier: 0x420094,        // Unique Identifier
} as const);

export type Item =
  | { tag: number; type: typeof TYPE.Structure; value: Item[] }
  | { tag: number; type: typeof TYPE.Integer | typeof TYPE.Enumeration | typeof TYPE.Interval; value: number }
  | { tag: number; type: typeof TYPE.LongInteger | typeof TYPE.DateTime; value: bigint }
  | { tag: number; type: typeof TYPE.Boolean; value: boolean }
  | { tag: number; type: typeof TYPE.TextString; value: string }
  | { tag: number; type: typeof TYPE.ByteString; value: Buffer };

/** The padding an item of this length carries: to a multiple of eight. */
const padding = (length: number): number => (8 - (length % 8)) % 8;

export function encode(item: Item): Buffer {
  const body = bodyOf(item);
  const head = Buffer.alloc(8);
  head.writeUIntBE(item.tag, 0, 3);
  head.writeUInt8(item.type, 3);
  head.writeUInt32BE(body.length, 4);
  const pad = Buffer.alloc(padding(body.length));
  return Buffer.concat([head, body, pad]);
}

function bodyOf(item: Item): Buffer {
  switch (item.type) {
    case TYPE.Structure:
      return Buffer.concat(item.value.map(encode));
    case TYPE.Integer:
    case TYPE.Enumeration:
    case TYPE.Interval: {
      const b = Buffer.alloc(4);
      // An Integer is signed and an Enumeration and an Interval are not; writing
      // the low thirty-two bits serves all three, and a reader of each knows
      // which it has.
      b.writeInt32BE(item.value | 0);
      return b;
    }
    case TYPE.LongInteger:
    case TYPE.DateTime: {
      const b = Buffer.alloc(8);
      b.writeBigInt64BE(item.value);
      return b;
    }
    case TYPE.Boolean: {
      const b = Buffer.alloc(8);
      b.writeBigInt64BE(item.value ? 1n : 0n);
      return b;
    }
    case TYPE.TextString:
      return Buffer.from(item.value, "utf8");
    case TYPE.ByteString:
      return Buffer.from(item.value);
    default:
      throw new TtlvError(`an item of type ${(item as { type: number }).type} is not encoded`);
  }
}

/** Reads one item, and says how many octets it took, padding included. */
export function decodeOne(buf: Buffer, offset = 0): { item: Item; size: number } {
  if (buf.length - offset < 8) {
    throw new TtlvError("an item is at least eight octets: a tag, a type and a length");
  }
  const tag = buf.readUIntBE(offset, 3);
  const type = buf.readUInt8(offset + 3);
  const length = buf.readUInt32BE(offset + 4);
  const start = offset + 8;
  if (buf.length - start < length) {
    throw new TtlvError(
      `an item of tag ${tag.toString(16)} states a length of ${length} and ` +
      `${buf.length - start} octets follow it`);
  }
  const body = buf.subarray(start, start + length);
  const size = 8 + length + padding(length);
  return { item: valueOf(tag, type, body), size };
}

function valueOf(tag: number, type: number, body: Buffer): Item {
  const fixed = (want: number, what: string) => {
    if (body.length !== want) {
      throw new TtlvError(`${what} is ${want} octets and ${body.length} were given`);
    }
  };
  switch (type) {
    case TYPE.Structure: {
      const value: Item[] = [];
      let at = 0;
      while (at < body.length) {
        const { item, size } = decodeOne(body, at);
        value.push(item);
        at += size;
      }
      return { tag, type: TYPE.Structure, value };
    }
    case TYPE.Integer:
      fixed(4, "an Integer");
      return { tag, type: TYPE.Integer, value: body.readInt32BE() };
    case TYPE.Enumeration:
      fixed(4, "an Enumeration");
      // An Enumeration is unsigned: a value with the high bit set is not negative.
      return { tag, type: TYPE.Enumeration, value: body.readUInt32BE() };
    case TYPE.Interval:
      fixed(4, "an Interval");
      return { tag, type: TYPE.Interval, value: body.readUInt32BE() };
    case TYPE.LongInteger:
      fixed(8, "a Long Integer");
      return { tag, type: TYPE.LongInteger, value: body.readBigInt64BE() };
    case TYPE.DateTime:
      fixed(8, "a Date-Time");
      return { tag, type: TYPE.DateTime, value: body.readBigInt64BE() };
    case TYPE.Boolean: {
      fixed(8, "a Boolean");
      const n = body.readBigInt64BE();
      if (n !== 0n && n !== 1n) {
        throw new TtlvError("a Boolean is zero or one");
      }
      return { tag, type: TYPE.Boolean, value: n === 1n };
    }
    case TYPE.TextString: {
      const text = body.toString("utf8");
      // "Text String ... encoded as UTF-8": a string that does not round trip
      // was not UTF-8, and is refused rather than silently replaced.
      if (!Buffer.from(text, "utf8").equals(body)) {
        throw new TtlvError("a Text String is UTF-8");
      }
      return { tag, type: TYPE.TextString, value: text };
    }
    case TYPE.ByteString:
      return { tag, type: TYPE.ByteString, value: Buffer.from(body) };
    default:
      throw new TtlvError(`${type} is not an item type this document defines`);
  }
}

/** Reads the one item an octet string holds, and refuses anything after it. */
export function decode(buf: Buffer): Item {
  const { item, size } = decodeOne(buf, 0);
  if (size !== buf.length) {
    throw new TtlvError(`${buf.length - size} octets follow the item`);
  }
  return item;
}

// ---------------------------------------------------------------------
// Building and reading, as the operations want them

export const struct = (tag: number, value: Item[]): Item =>
  ({ tag, type: TYPE.Structure, value });
export const int = (tag: number, value: number): Item =>
  ({ tag, type: TYPE.Integer, value });
export const enumeration = (tag: number, value: number): Item =>
  ({ tag, type: TYPE.Enumeration, value });
export const text = (tag: number, value: string): Item =>
  ({ tag, type: TYPE.TextString, value });
export const bytes = (tag: number, value: Buffer): Item =>
  ({ tag, type: TYPE.ByteString, value });
export const dateTime = (tag: number, value: Date): Item =>
  ({ tag, type: TYPE.DateTime, value: BigInt(Math.floor(value.getTime() / 1000)) });

/** The children of a structure that carry a tag. */
export function children(item: Item, tag: number): Item[] {
  return item.type === TYPE.Structure ? item.value.filter((i) => i.tag === tag) : [];
}

/** The one child of a structure that carries a tag, where there is one. */
export function child(item: Item, tag: number): Item | undefined {
  return children(item, tag)[0];
}

/** The text of a child, where it is a Text String. */
export function textOf(item: Item, tag: number): string | undefined {
  const c = child(item, tag);
  return c?.type === TYPE.TextString ? c.value : undefined;
}

/** The number of a child, where it is an Integer, an Enumeration or an Interval. */
export function numberOf(item: Item, tag: number): number | undefined {
  const c = child(item, tag);
  return c !== undefined &&
    (c.type === TYPE.Integer || c.type === TYPE.Enumeration || c.type === TYPE.Interval)
    ? c.value
    : undefined;
}

/** The octets of a child, where it is a Byte String. */
export function bytesOf(item: Item, tag: number): Buffer | undefined {
  const c = child(item, tag);
  return c?.type === TYPE.ByteString ? c.value : undefined;
}
