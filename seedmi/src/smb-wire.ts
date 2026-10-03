/**
 * The wire format of SMB2: the transport framing, the packet header,
 * and the constants of [MS-SMB2]. Nothing here knows about CDMI.
 */

/** The dialect revisions of [MS-SMB2] section 2.2.3, and their names. */
export const DIALECTS: Record<string, number> = {
  SMB2: 0x0202,
  "SMB2.1": 0x0210,
  SMB3: 0x0300,
  "SMB3.0.2": 0x0302,
  "SMB3.1.1": 0x0311,
};

/** The name of a dialect revision, for a report and for a condition. */
export const dialectName = (rev: number): string =>
  Object.keys(DIALECTS).find((k) => DIALECTS[k] === rev) ?? `0x${rev.toString(16)}`;

/** Whether a dialect belongs to the SMB 3.x family. */
export const isSmb3 = (rev: number): boolean => rev >= 0x0300;

/** The commands of [MS-SMB2] section 2.2.1.2. */
export const CMD = {
  NEGOTIATE: 0x0000,
  SESSION_SETUP: 0x0001,
  LOGOFF: 0x0002,
  TREE_CONNECT: 0x0003,
  TREE_DISCONNECT: 0x0004,
  CREATE: 0x0005,
  CLOSE: 0x0006,
  FLUSH: 0x0007,
  READ: 0x0008,
  WRITE: 0x0009,
  LOCK: 0x000a,
  IOCTL: 0x000b,
  CANCEL: 0x000c,
  ECHO: 0x000d,
  QUERY_DIRECTORY: 0x000e,
  CHANGE_NOTIFY: 0x000f,
  QUERY_INFO: 0x0010,
  SET_INFO: 0x0011,
  OPLOCK_BREAK: 0x0012,
} as const;

/** The name of a command, for a condition and for a trace. */
export const commandName = (c: number): string =>
  Object.keys(CMD).find((k) => (CMD as Record<string, number>)[k] === c) ??
    `0x${c.toString(16)}`;

/** The NTSTATUS values this implementation returns, from [MS-ERREF]. */
export const NT = {
  SUCCESS: 0x00000000,
  PENDING: 0x00000103,
  MORE_PROCESSING_REQUIRED: 0xc0000016,
  INVALID_PARAMETER: 0xc000000d,
  ACCESS_DENIED: 0xc0000022,
  LOGON_FAILURE: 0xc000006d,
  BAD_NETWORK_NAME: 0xc00000cc,
  NOT_SUPPORTED: 0xc00000bb,
  USER_SESSION_DELETED: 0xc0000203,
  NETWORK_NAME_DELETED: 0xc00000c9,
  INVALID_PARAMETER_MIX: 0xc0000030,
  NOT_IMPLEMENTED: 0xc0000002,
  SMB_BAD_TID: 0x00050002,
  REQUEST_NOT_ACCEPTED: 0xc00000d0,
  NO_SUCH_FILE: 0xc000000f,
  OBJECT_NAME_NOT_FOUND: 0xc0000034,
  INVALID_DEVICE_REQUEST: 0xc0000010,
  END_OF_FILE: 0xc0000011,
  NO_MORE_FILES: 0x80000006,
  INFO_LENGTH_MISMATCH: 0xc0000004,
  NOT_A_DIRECTORY: 0xc0000103,
  FILE_IS_A_DIRECTORY: 0xc00000ba,
  OBJECT_NAME_COLLISION: 0xc0000035,
  OBJECT_PATH_NOT_FOUND: 0xc000003a,
  MEDIA_WRITE_PROTECTED: 0xc00000a2,
  DIRECTORY_NOT_EMPTY: 0xc0000101,
  NOT_A_REPARSE_POINT: 0xc0000275,
  IO_REPARSE_TAG_NOT_HANDLED: 0xc0000279,
  NONE_MAPPED: 0xc0000073,
  EAS_NOT_SUPPORTED: 0xc000004f,
  EA_TOO_LARGE: 0xc0000050,
  NONEXISTENT_EA_ENTRY: 0xc0000051,
  NO_EAS_ON_FILE: 0xc0000052,
} as const;

/** The name of a status, for a condition and for a test. */
export const statusName = (s: number): string =>
  Object.keys(NT).find((k) => (NT as Record<string, number>)[k] === s) ??
    `0x${(s >>> 0).toString(16)}`;

/** The header flags of [MS-SMB2] section 2.2.1.2. */
export const FLAG = {
  SERVER_TO_REDIR: 0x00000001,
  ASYNC_COMMAND: 0x00000002,
  RELATED_OPERATIONS: 0x00000004,
  SIGNED: 0x00000008,
  PRIORITY_MASK: 0x00000070,
  DFS_OPERATIONS: 0x10000000,
  REPLAY_OPERATION: 0x20000000,
} as const;

/** The security modes of a NEGOTIATE and a SESSION_SETUP. */
export const SIGNING_ENABLED = 0x0001;
export const SIGNING_REQUIRED = 0x0002;

/** The global capabilities of [MS-SMB2] section 2.2.3. */
export const CAP = {
  DFS: 0x00000001,
  LEASING: 0x00000002,
  LARGE_MTU: 0x00000004,
  MULTI_CHANNEL: 0x00000008,
  PERSISTENT_HANDLES: 0x00000010,
  DIRECTORY_LEASING: 0x00000020,
  ENCRYPTION: 0x00000040,
} as const;

/** The negotiate context types of [MS-SMB2] section 2.2.3.1. */
export const CTX = {
  PREAUTH_INTEGRITY_CAPABILITIES: 0x0001,
  ENCRYPTION_CAPABILITIES: 0x0002,
  COMPRESSION_CAPABILITIES: 0x0003,
  NETNAME_NEGOTIATE_CONTEXT_ID: 0x0005,
  TRANSPORT_CAPABILITIES: 0x0006,
  RDMA_TRANSFORM_CAPABILITIES: 0x0007,
  SIGNING_CAPABILITIES: 0x0008,
} as const;

/** The hash algorithm of a preauthentication integrity context. */
export const HASH_SHA512 = 0x0001;

/** The share types of a TREE_CONNECT response. */
export const SHARE_TYPE_DISK = 0x01;

/** The size of the packet header. */
export const HEADER_SIZE = 64;

/** The protocol identifier, 0xFE 'S' 'M' 'B'. */
export const PROTOCOL_ID = Buffer.from([0xfe, 0x53, 0x4d, 0x42]);

/** A decoded packet header. */
export interface Header {
  creditCharge: number;
  status: number;
  command: number;
  credits: number;
  flags: number;
  nextCommand: number;
  messageId: bigint;
  treeId: number;
  sessionId: bigint;
  signature: Buffer;
}

/** An empty header, which a caller fills in. */
export const header = (over: Partial<Header> = {}): Header => ({
  creditCharge: 0,
  status: 0,
  command: 0,
  credits: 1,
  flags: 0,
  nextCommand: 0,
  messageId: 0n,
  treeId: 0,
  sessionId: 0n,
  signature: Buffer.alloc(16),
  ...over,
});

/** Encodes a packet header of the synchronous form. */
export function encodeHeader(h: Header): Buffer {
  const b = Buffer.alloc(HEADER_SIZE);
  PROTOCOL_ID.copy(b, 0);
  b.writeUInt16LE(HEADER_SIZE, 4);
  b.writeUInt16LE(h.creditCharge, 6);
  b.writeUInt32LE(h.status >>> 0, 8);
  b.writeUInt16LE(h.command, 12);
  b.writeUInt16LE(h.credits, 14);
  b.writeUInt32LE(h.flags >>> 0, 16);
  b.writeUInt32LE(h.nextCommand, 20);
  b.writeBigUInt64LE(h.messageId, 24);
  // Reserved (4) and TreeId (4) occupy the asynchronous AsyncId.
  b.writeUInt32LE(0, 32);
  b.writeUInt32LE(h.treeId, 36);
  b.writeBigUInt64LE(h.sessionId, 40);
  h.signature.copy(b, 48, 0, 16);
  return b;
}

/** Decodes a packet header, or undefined where it is not one. */
export function decodeHeader(b: Buffer): Header | undefined {
  if (b.length < HEADER_SIZE) return undefined;
  if (!b.subarray(0, 4).equals(PROTOCOL_ID)) return undefined;
  if (b.readUInt16LE(4) !== HEADER_SIZE) return undefined;
  return {
    creditCharge: b.readUInt16LE(6),
    status: b.readUInt32LE(8),
    command: b.readUInt16LE(12),
    credits: b.readUInt16LE(14),
    flags: b.readUInt32LE(16),
    nextCommand: b.readUInt32LE(20),
    messageId: b.readBigUInt64LE(24),
    treeId: b.readUInt32LE(36),
    sessionId: b.readBigUInt64LE(40),
    signature: Buffer.from(b.subarray(48, 64)),
  };
}

/**
 * The transport of [MS-SMB2] section 2.1: over TCP a message carries a
 * four-byte prefix whose first octet is zero and whose remaining three
 * hold the length in network order.
 */
export function frame(message: Buffer): Buffer {
  const b = Buffer.alloc(4 + message.length);
  b.writeUInt32BE(message.length, 0); // the first octet is zero for a length under 2^24
  message.copy(b, 4);
  return b;
}

/**
 * Splits a stream into transport messages, returning the messages and
 * what remains. A length whose first octet is not zero is a message of
 * another transport and is reported by returning undefined.
 */
export function unframe(buf: Buffer): { messages: Buffer[]; rest: Buffer } | undefined {
  const messages: Buffer[] = [];
  let at = 0;
  while (buf.length - at >= 4) {
    if (buf[at] !== 0x00) return undefined;
    const len = buf.readUInt32BE(at) & 0x00ffffff;
    if (buf.length - at - 4 < len) break;
    messages.push(Buffer.from(buf.subarray(at + 4, at + 4 + len)));
    at += 4 + len;
  }
  return { messages, rest: Buffer.from(buf.subarray(at)) };
}

/** A string of the request, as UTF-16LE, which every name of SMB is. */
export const utf16 = (s: string): Buffer => Buffer.from(s, "utf16le");
export const fromUtf16 = (b: Buffer): string => b.toString("utf16le");

/**
 * The time of [MS-DTYP] section 2.3.3: the count of 100-nanosecond
 * intervals since the first of January 1601, held little-endian.
 */
const EPOCH_DIFFERENCE = 11644473600000n;
export const fileTime = (ms: number): bigint =>
  (BigInt(Math.floor(ms)) + EPOCH_DIFFERENCE) * 10000n;
export const fromFileTime = (t: bigint): number =>
  Number(t / 10000n - EPOCH_DIFFERENCE);

/** Writes a buffer of a variable-length field, and its offset and length. */
export class Body {
  private parts: Buffer[] = [];
  private length = 0;
  private readonly fixed: number;

  constructor(fixed: number) {
    this.fixed = fixed;
  }

  /** Appends data, answering its offset from the start of the header. */
  add(data: Buffer): { offset: number; length: number } {
    const offset = HEADER_SIZE + this.fixed + this.length;
    this.parts.push(data);
    this.length += data.length;
    return { offset, length: data.length };
  }

  buffer(): Buffer {
    return Buffer.concat(this.parts);
  }
}

/**
 * The data a variable-length field names, given its offset from the
 * start of the header. An offset of zero with a length of zero is an
 * absent field.
 */
export function fieldAt(
  message: Buffer,
  offset: number,
  length: number,
): Buffer | undefined {
  if (offset === 0 && length === 0) return Buffer.alloc(0);
  if (offset < HEADER_SIZE || length < 0 || offset + length > message.length) {
    return undefined;
  }
  return Buffer.from(message.subarray(offset, offset + length));
}

/** Rounds up to a multiple of eight, as a negotiate context requires. */
export const align8 = (n: number): number => (n + 7) & ~7;
