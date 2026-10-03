// A KMIP 1.4 client: TTLV over TLS as KMIP Profiles 1.4 section 3.1 requires,
// with the operations seedmi's key management uses. Section and table numbers
// are those of KMIP 1.4.
//
// Each operation is a value (an Operation): its name, its request payload with
// fields in the order of its table, and a parser for its response payload.
// `run` performs one and throws KmipOperationError where it fails; `batch`
// performs several in one request, which may use the ID Placeholder.
//
// One request is in flight on a connection at a time; KMIP matches a response to
// its request by the order of the stream. The connection is opened when first
// needed and opened again for the next request after it closes. A request whose
// connection is lost before its response arrives is not sent again, since the
// server may have performed it; it fails with KmipProtocolError.

import { isIP } from "node:net";
import { connect, type TLSSocket } from "node:tls";
import {
  type Attribute, type BatchErrorContinuation, decodeAttribute, decodeQueryResult, decodeResponse, discoverVersionsPayload,
  encodeAttribute, encodeAttributes, encodeRequest, enumName, type ProtocolVersion, queryPayload, type QueryResult,
  readDiscoverVersions, type ResponseBatchItem, V1_4, versionText,
} from "./kmip-message.ts";
import { KMIP_ENUM } from "./kmip-registry.ts";
import { child, children, decode, encode, type Item, k, MessageReader, nameOf, tagOf, TtlvError, TYPE } from "./kmip-ttlv.ts";
import { type CryptoParams, writeParams } from "./kms-crypto.ts";
import { BASIC_SUITE_CIPHERS, BASIC_SUITE_PROTOCOL, KMIP_PORT } from "./kmip-tls.ts";

// ---------------------------------------------------------------------------
// Errors

/**
 * An operation the server performed and refused: the batch item's Result Status
 * was Operation Failed. `reason` is the Result Reason by its 1.4 name
 * (9.1.3.2.29), so a caller tests `e.reason === "Item Not Found"`.
 */
export class KmipOperationError extends Error {
  readonly operation: string | undefined;
  readonly reason: string;
  readonly resultMessage: string | undefined;
  constructor(operation: string | undefined, reason: string, resultMessage: string | undefined) {
    super(`${operation ?? "the request"} failed: ${reason}${resultMessage ? `: ${resultMessage}` : ""}`);
    this.name = "KmipOperationError";
    this.operation = operation;
    this.reason = reason;
    this.resultMessage = resultMessage;
  }
}

/** The exchange itself failed: the connection, the TLS channel, or a response that does not answer the request. */
export class KmipProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KmipProtocolError";
  }
}

// ---------------------------------------------------------------------------
// Operations

/** An operation: its request, and how its response payload is read. */
export interface Operation<T> {
  operation: string;
  payload: Item[];
  parse: (payload: Item[]) => T;
}

const uid = (id: string | undefined, name = "Unique Identifier"): Item[] => id === undefined ? [] : [k.text(name, id)];

function need(payload: Item[], name: string, type: number): Item {
  const item = payload.find((p) => p.tag === tagOf(name));
  if (item === undefined || item.type !== type) {
    throw new KmipProtocolError(`the response payload has no ${name} of the expected type`);
  }
  return item;
}

const text = (payload: Item[], name: string) => need(payload, name, TYPE.TextString).value as string;
const bytes = (payload: Item[], name: string) => need(payload, name, TYPE.ByteString).value as Buffer;

/** A Template-Attribute holding individual attributes, or nothing where there are none. */
const template = (attrs: Attribute[] | undefined, container: Parameters<typeof encodeAttributes>[1] = "Template-Attribute"): Item[] =>
  attrs === undefined || attrs.length === 0 ? [] : [encodeAttributes(attrs, container)];

export interface KeyWrappingSpecification {
  /** A Wrapping Method name: "Encrypt" (9.1.3.2.4). */
  method: string;
  encryptionKey?: { id: string; params?: CryptoParams };
  attributeNames?: string[];
  /** An Encoding Option name: "No Encoding" or "TTLV Encoding" (9.1.3.2.32). */
  encodingOption?: string;
}

/** A Key Wrapping Specification (Table 12), with an Encryption Key Information (Table 10). */
function wrappingSpecification(spec: KeyWrappingSpecification): Item {
  return k.struct("Key Wrapping Specification", [
    k.enum("Wrapping Method", "Wrapping Method", spec.method),
    ...(spec.encryptionKey === undefined ? [] : [k.struct("Encryption Key Information", [
      k.text("Unique Identifier", spec.encryptionKey.id),
      ...(spec.encryptionKey.params === undefined ? [] : [writeParams(spec.encryptionKey.params)]),
    ])]),
    ...(spec.attributeNames ?? []).map((n) => k.text("Attribute Name", n)),
    ...(spec.encodingOption === undefined ? [] : [k.enum("Encoding Option", "Encoding Option", spec.encodingOption)]),
  ]);
}

const cryptoParams = (p: CryptoParams | undefined): Item[] => p === undefined ? [] : [writeParams(p)];
const optBytes = (name: string, b: Buffer | undefined): Item[] => b === undefined ? [] : [k.bytes(name, b)];

/**
 * The operations, each built with its request fields in the order of its table.
 * A Unique Identifier left undefined is omitted, so that the server uses the ID
 * Placeholder (section 4).
 */
export const ops = {
  /** Discover Versions (4.26, Table 224). */
  discoverVersions: (versions: ProtocolVersion[]): Operation<ProtocolVersion[]> => ({
    operation: "Discover Versions", payload: discoverVersionsPayload(versions), parse: readDiscoverVersions,
  }),

  /** Query (4.25, Table 222). */
  query: (functions: string[]): Operation<QueryResult> => ({
    operation: "Query", payload: queryPayload(functions), parse: decodeQueryResult,
  }),

  /** Register (4.3, Table 169): the Unique Identifier of the object registered. */
  register: (objectType: string, attrs: Attribute[], object: Item): Operation<string> => ({
    operation: "Register",
    payload: [k.enum("Object Type", "Object Type", objectType), encodeAttributes(attrs), object],
    parse: (p) => text(p, "Unique Identifier"),
  }),

  /** Create (4.1, Table 163): the Unique Identifier of the key created. */
  create: (objectType: string, attrs: Attribute[]): Operation<string> => ({
    operation: "Create",
    payload: [k.enum("Object Type", "Object Type", objectType), encodeAttributes(attrs)],
    parse: (p) => text(p, "Unique Identifier"),
  }),

  /** Create Key Pair (4.2). */
  createKeyPair: (attrs: { common?: Attribute[]; privateKey?: Attribute[]; publicKey?: Attribute[] }):
    Operation<{ privateKey: string; publicKey: string }> => ({
    operation: "Create Key Pair",
    payload: [
      ...template(attrs.common, "Common Template-Attribute"),
      ...template(attrs.privateKey, "Private Key Template-Attribute"),
      ...template(attrs.publicKey, "Public Key Template-Attribute"),
    ],
    parse: (p) => ({ privateKey: text(p, "Private Key Unique Identifier"), publicKey: text(p, "Public Key Unique Identifier") }),
  }),

  /** Locate (4.9, Table 190): the identifiers found, and Located Items where the server gives it. */
  locate: (attrs: Attribute[], opts: { maximumItems?: number; offsetItems?: number; storageStatusMask?: number } = {}):
    Operation<{ ids: string[]; located?: number }> => ({
    operation: "Locate",
    payload: [
      ...(opts.maximumItems === undefined ? [] : [k.int("Maximum Items", opts.maximumItems)]),
      ...(opts.offsetItems === undefined ? [] : [k.int("Offset Items", opts.offsetItems)]),
      ...(opts.storageStatusMask === undefined ? [] : [k.int("Storage Status Mask", opts.storageStatusMask)]),
      // "Attribute Index values SHOULD NOT be specified in the request" (4.9).
      ...attrs.map((a) => encodeAttribute({ name: a.name, value: a.value })),
    ],
    parse: (p) => {
      const located = p.find((i) => i.tag === tagOf("Located Items"));
      return {
        ids: p.filter((i) => i.tag === tagOf("Unique Identifier")).map((i) => i.value as string),
        ...(located?.type === TYPE.Integer ? { located: located.value } : {}),
      };
    },
  }),

  /** Get (4.11, Table 194): the object, as returned. */
  get: (id: string | undefined, opts: { keyFormatType?: string; keyWrapType?: string; keyCompressionType?: string;
    wrapping?: KeyWrappingSpecification } = {}): Operation<{ objectType: string; id: string; object: Item }> => ({
    operation: "Get",
    payload: [
      ...uid(id),
      ...(opts.keyFormatType === undefined ? [] : [k.enum("Key Format Type", "Key Format Type", opts.keyFormatType)]),
      ...(opts.keyWrapType === undefined ? [] : [k.enum("Key Wrap Type", "Key Wrap Type", opts.keyWrapType)]),
      ...(opts.keyCompressionType === undefined ? [] : [k.enum("Key Compression Type", "Key Compression Type", opts.keyCompressionType)]),
      ...(opts.wrapping === undefined ? [] : [wrappingSpecification(opts.wrapping)]),
    ],
    parse: (p) => {
      const type = need(p, "Object Type", TYPE.Enumeration);
      const objectType = enumName("Object Type", type.value as number);
      const object = p.find((i) => i.tag === tagOf(objectType));
      if (object === undefined) throw new KmipProtocolError(`the Get response holds no ${objectType}`);
      return { objectType, id: text(p, "Unique Identifier"), object };
    },
  }),

  /** Get Attributes (4.12): the attributes named, or all where none is named. */
  getAttributes: (id: string | undefined, names: string[] = []): Operation<Attribute[]> => ({
    operation: "Get Attributes",
    payload: [...uid(id), ...names.map((n) => k.text("Attribute Name", n))],
    parse: (p) => children({ tag: 0, type: TYPE.Structure, value: p } as Item, "Attribute").map(decodeAttribute),
  }),

  /** Get Attribute List (4.13): the names of the object's attributes. */
  getAttributeList: (id: string | undefined): Operation<string[]> => ({
    operation: "Get Attribute List", payload: uid(id),
    parse: (p) => p.filter((i) => i.tag === tagOf("Attribute Name")).map((i) => i.value as string),
  }),

  /** Add Attribute (4.14): "The Attribute Index SHALL NOT be specified in the request". Returns the attribute added. */
  addAttribute: (id: string | undefined, attr: Attribute): Operation<Attribute> => ({
    operation: "Add Attribute",
    payload: [...uid(id), encodeAttribute({ name: attr.name, value: attr.value })],
    parse: (p) => decodeAttribute(need(p, "Attribute", TYPE.Structure)),
  }),

  /** Modify Attribute (4.15): the instance named by its index, 0 where omitted. Returns the attribute modified. */
  modifyAttribute: (id: string | undefined, attr: Attribute): Operation<Attribute> => ({
    operation: "Modify Attribute", payload: [...uid(id), encodeAttribute(attr)],
    parse: (p) => decodeAttribute(need(p, "Attribute", TYPE.Structure)),
  }),

  /** Delete Attribute (4.16, Table 204): returns the attribute deleted. */
  deleteAttribute: (id: string | undefined, name: string, index?: number): Operation<Attribute> => ({
    operation: "Delete Attribute",
    payload: [...uid(id), k.text("Attribute Name", name), ...(index === undefined ? [] : [k.int("Attribute Index", index)])],
    parse: (p) => decodeAttribute(need(p, "Attribute", TYPE.Structure)),
  }),

  /** Activate (4.19). */
  activate: (id: string | undefined): Operation<string> => ({
    operation: "Activate", payload: uid(id), parse: (p) => text(p, "Unique Identifier"),
  }),

  /** Revoke (4.20, Table 209): a Revocation Reason (Table 121), and the Compromise Occurrence Date for a compromise. */
  revoke: (id: string | undefined, code: string, opts: { message?: string; compromiseOccurrence?: number } = {}): Operation<string> => ({
    operation: "Revoke",
    payload: [
      ...uid(id),
      k.struct("Revocation Reason", [
        k.enum("Revocation Reason Code", "Revocation Reason Code", code),
        ...(opts.message === undefined ? [] : [k.text("Revocation Message", opts.message)]),
      ]),
      ...(opts.compromiseOccurrence === undefined ? [] : [k.date("Compromise Occurrence Date", opts.compromiseOccurrence)]),
    ],
    parse: (p) => text(p, "Unique Identifier"),
  }),

  /** Destroy (4.21). */
  destroy: (id: string | undefined): Operation<string> => ({
    operation: "Destroy", payload: uid(id), parse: (p) => text(p, "Unique Identifier"),
  }),

  /** Re-key (4.4): the Unique Identifier of the replacement key. */
  rekey: (id: string | undefined, opts: { offsetSeconds?: number; attrs?: Attribute[] } = {}): Operation<string> => ({
    operation: "Re-key",
    payload: [
      ...uid(id),
      ...(opts.offsetSeconds === undefined ? [] : [k.interval("Offset", opts.offsetSeconds)]),
      ...template(opts.attrs),
    ],
    parse: (p) => text(p, "Unique Identifier"),
  }),

  /** Re-key Key Pair (4.5). */
  rekeyKeyPair: (privateKeyId: string | undefined, opts: { offsetSeconds?: number } = {}):
    Operation<{ privateKey: string; publicKey: string }> => ({
    operation: "Re-key Key Pair",
    payload: [
      ...uid(privateKeyId, "Private Key Unique Identifier"),
      ...(opts.offsetSeconds === undefined ? [] : [k.interval("Offset", opts.offsetSeconds)]),
    ],
    parse: (p) => ({ privateKey: text(p, "Private Key Unique Identifier"), publicKey: text(p, "Public Key Unique Identifier") }),
  }),

  /** Encrypt (4.29, Table 229), single-part. */
  encrypt: (id: string | undefined, req: { params?: CryptoParams; data: Buffer; iv?: Buffer; aad?: Buffer }):
    Operation<{ data: Buffer; iv?: Buffer; tag?: Buffer }> => ({
    operation: "Encrypt",
    payload: [...uid(id), ...cryptoParams(req.params), k.bytes("Data", req.data), ...optBytes("IV/Counter/Nonce", req.iv),
      ...optBytes("Authenticated Encryption Additional Data", req.aad)],
    parse: (p) => {
      const iv = p.find((i) => i.tag === tagOf("IV/Counter/Nonce"));
      const tag = p.find((i) => i.tag === tagOf("Authenticated Encryption Tag"));
      return {
        data: bytes(p, "Data"),
        ...(iv?.type === TYPE.ByteString ? { iv: iv.value } : {}),
        ...(tag?.type === TYPE.ByteString ? { tag: tag.value } : {}),
      };
    },
  }),

  /** Decrypt (4.30), single-part. */
  decrypt: (id: string | undefined, req: { params?: CryptoParams; data: Buffer; iv?: Buffer; aad?: Buffer; tag?: Buffer }):
    Operation<Buffer> => ({
    operation: "Decrypt",
    payload: [...uid(id), ...cryptoParams(req.params), k.bytes("Data", req.data), ...optBytes("IV/Counter/Nonce", req.iv),
      ...optBytes("Authenticated Encryption Additional Data", req.aad), ...optBytes("Authenticated Encryption Tag", req.tag)],
    parse: (p) => bytes(p, "Data"),
  }),

  /** Sign (4.31), single-part. */
  sign: (id: string | undefined, req: { params?: CryptoParams; data: Buffer }): Operation<Buffer> => ({
    operation: "Sign", payload: [...uid(id), ...cryptoParams(req.params), k.bytes("Data", req.data)],
    parse: (p) => bytes(p, "Signature Data"),
  }),

  /** Signature Verify (4.32), single-part: whether the Validity Indicator is Valid. */
  signatureVerify: (id: string | undefined, req: { params?: CryptoParams; data: Buffer; signature: Buffer }): Operation<boolean> => ({
    operation: "Signature Verify",
    payload: [...uid(id), ...cryptoParams(req.params), k.bytes("Data", req.data), k.bytes("Signature Data", req.signature)],
    parse: (p) => enumName("Validity Indicator", need(p, "Validity Indicator", TYPE.Enumeration).value as number) === "Valid",
  }),

  /** MAC (4.33), single-part. */
  mac: (id: string | undefined, req: { params?: CryptoParams; data: Buffer }): Operation<Buffer> => ({
    operation: "MAC", payload: [...uid(id), ...cryptoParams(req.params), k.bytes("Data", req.data)],
    parse: (p) => bytes(p, "MAC Data"),
  }),

  /** MAC Verify (4.34), single-part: whether the Validity Indicator is Valid. */
  macVerify: (id: string | undefined, req: { params?: CryptoParams; data: Buffer; macData: Buffer }): Operation<boolean> => ({
    operation: "MAC Verify",
    payload: [...uid(id), ...cryptoParams(req.params), k.bytes("Data", req.data), k.bytes("MAC Data", req.macData)],
    parse: (p) => enumName("Validity Indicator", need(p, "Validity Indicator", TYPE.Enumeration).value as number) === "Valid",
  }),
};

// ---------------------------------------------------------------------------
// The client

export interface KmipClientOptions {
  host: string;
  /** Defaults to 5696 (Profiles 3.1.4). */
  port?: number;
  /** The name the server's certificate is checked against; defaults to host. */
  servername?: string;
  /** The authority the server's certificate chains to, in PEM. */
  ca: string;
  /** The client's certificate and key, in PEM: its identity to the server (Profiles 3.1.3). */
  cert?: string;
  key?: string;
  /** The protocol version requests declare until `negotiate` chooses one; defaults to 1.4. */
  version?: ProtocolVersion;
  /** A Maximum Response Size for every request (6.3). */
  maximumResponseSize?: number;
  /** Milliseconds a request waits for its response before the connection is closed. Defaults to 30 000. */
  timeoutMs?: number;
  now?: () => number;
}

export interface BatchOptions {
  batchOrderOption?: boolean;
  batchErrorContinuationOption?: BatchErrorContinuation;
  /** Give a single batch item a Unique Batch Item ID too, as some requests do. */
  alwaysIdentifyItems?: boolean;
}

/** The outcome of one operation of a batch. */
export type Outcome<T> = { ok: true; value: T } | { ok: false; error: KmipOperationError };

/** The versions this client speaks, most preferred first. */
export const CLIENT_VERSIONS: ProtocolVersion[] = [4, 3, 2, 1, 0].map((minor) => ({ major: 1, minor }));

interface Pending {
  resolve: (item: Item) => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

export class KmipClient {
  private readonly opts: KmipClientOptions;
  private socket: TLSSocket | undefined;
  private opening: Promise<TLSSocket> | undefined;
  private pending: Pending | undefined;
  private queue: Promise<unknown> = Promise.resolve();
  private closed = false;
  /** The protocol version requests declare. */
  version: ProtocolVersion;

  constructor(opts: KmipClientOptions) {
    this.opts = opts;
    this.version = opts.version ?? V1_4;
  }

  /**
   * The request message a batch would send, as a TTLV item, without sending it.
   * Unique Batch Item IDs are 01, 02, ... in the order of the operations.
   */
  encode(operations: Operation<unknown>[], options: BatchOptions = {}, version = this.version): Item {
    const identify = operations.length > 1 || options.alwaysIdentifyItems === true;
    return encodeRequest({
      header: {
        protocolVersion: version,
        ...(this.opts.maximumResponseSize === undefined ? {} : { maximumResponseSize: this.opts.maximumResponseSize }),
        ...(options.batchErrorContinuationOption === undefined ? {} : { batchErrorContinuationOption: options.batchErrorContinuationOption }),
        ...(options.batchOrderOption === undefined ? {} : { batchOrderOption: options.batchOrderOption }),
      },
      items: operations.map((op, i) => ({
        operation: op.operation,
        payload: op.payload,
        ...(identify ? { uniqueBatchItemId: batchItemId(i) } : {}),
      })),
    });
  }

  /** Performs one operation, throwing KmipOperationError where the server refuses it. */
  async run<T>(op: Operation<T>, options: BatchOptions = {}): Promise<T> {
    const [outcome] = await this.batch([op], options);
    if (!outcome.ok) throw outcome.error;
    return outcome.value;
  }

  /**
   * Performs operations in one request, and returns an outcome for each. Where the
   * batch stopped at a failure (6.13, Stop), the operations after it were not
   * performed, and each reports the error of the failure that stopped it.
   */
  async batch<T extends unknown[]>(operations: { [K in keyof T]: Operation<T[K]> }, options: BatchOptions = {}):
    Promise<{ [K in keyof T]: Outcome<T[K]> }> {
    const ops = operations as Operation<unknown>[];
    const version = this.version;
    const request = this.encode(ops, options, version);
    return readResponse(ops, options, version, await this.exchange(request)) as { [K in keyof T]: Outcome<T[K]> };
  }

  /**
   * Discover Versions, and the version later requests declare: the first of the
   * versions both speak, in the server's order of preference. The request itself
   * declares 1.1, the first version that defines the operation; a server that
   * does not perform it is taken to speak 1.0 alone.
   */
  async negotiate(): Promise<ProtocolVersion> {
    const saved = this.version;
    this.version = { major: 1, minor: 1 };
    try {
      const common = await this.run(ops.discoverVersions(CLIENT_VERSIONS));
      const chosen = common.find((v) => CLIENT_VERSIONS.some((c) => c.major === v.major && c.minor === v.minor));
      if (chosen === undefined) throw new KmipProtocolError("the server speaks no version this client speaks");
      this.version = chosen;
      return chosen;
    } catch (e) {
      if (e instanceof KmipOperationError && e.reason === "Operation Not Supported") {
        this.version = { major: 1, minor: 0 };
        return this.version;
      }
      this.version = saved;
      throw e;
    }
  }

  // Convenience: each operation performed alone.
  query = (functions: string[]) => this.run(ops.query(functions));
  register = (objectType: string, attrs: Attribute[], object: Item) => this.run(ops.register(objectType, attrs, object));
  create = (objectType: string, attrs: Attribute[]) => this.run(ops.create(objectType, attrs));
  createKeyPair = (attrs: Parameters<typeof ops.createKeyPair>[0]) => this.run(ops.createKeyPair(attrs));
  locate = (attrs: Attribute[], opts?: Parameters<typeof ops.locate>[1]) => this.run(ops.locate(attrs, opts));
  get = (id: string, opts?: Parameters<typeof ops.get>[1]) => this.run(ops.get(id, opts));
  getAttributes = (id: string, names?: string[]) => this.run(ops.getAttributes(id, names));
  getAttributeList = (id: string) => this.run(ops.getAttributeList(id));
  addAttribute = (id: string, attr: Attribute) => this.run(ops.addAttribute(id, attr));
  modifyAttribute = (id: string, attr: Attribute) => this.run(ops.modifyAttribute(id, attr));
  deleteAttribute = (id: string, name: string, index?: number) => this.run(ops.deleteAttribute(id, name, index));
  activate = (id: string) => this.run(ops.activate(id));
  revoke = (id: string, code: string, opts?: Parameters<typeof ops.revoke>[2]) => this.run(ops.revoke(id, code, opts));
  destroy = (id: string) => this.run(ops.destroy(id));
  rekey = (id: string, opts?: Parameters<typeof ops.rekey>[1]) => this.run(ops.rekey(id, opts));
  rekeyKeyPair = (id: string, opts?: Parameters<typeof ops.rekeyKeyPair>[1]) => this.run(ops.rekeyKeyPair(id, opts));
  encrypt = (id: string, req: Parameters<typeof ops.encrypt>[1]) => this.run(ops.encrypt(id, req));
  decrypt = (id: string, req: Parameters<typeof ops.decrypt>[1]) => this.run(ops.decrypt(id, req));
  sign = (id: string, req: Parameters<typeof ops.sign>[1]) => this.run(ops.sign(id, req));
  signatureVerify = (id: string, req: Parameters<typeof ops.signatureVerify>[1]) => this.run(ops.signatureVerify(id, req));
  mac = (id: string, req: Parameters<typeof ops.mac>[1]) => this.run(ops.mac(id, req));
  macVerify = (id: string, req: Parameters<typeof ops.macVerify>[1]) => this.run(ops.macVerify(id, req));

  /** Closes the connection; later requests fail. */
  close(): void {
    this.closed = true;
    this.socket?.destroy();
    this.socket = undefined;
  }

  // -------------------------------------------------------------------------
  // Transport

  /** Sends a request and waits for its response, one at a time. */
  private exchange(request: Item): Promise<Item> {
    const turn = this.queue.then(() => this.send(request));
    this.queue = turn.catch(() => undefined);
    return turn;
  }

  private async send(request: Item): Promise<Item> {
    if (this.closed) throw new KmipProtocolError("the client is closed");
    const socket = await this.open();
    return new Promise<Item>((resolve, reject) => {
      const timer = setTimeout(() => {
        // The response's place in the stream is lost with it, so the connection goes too.
        this.fail(new KmipProtocolError(`no response within ${this.opts.timeoutMs ?? 30000} ms`));
      }, this.opts.timeoutMs ?? 30000);
      this.pending = { resolve, reject, timer };
      socket.write(encode(request));
    });
  }

  private fail(e: Error): void {
    const p = this.pending;
    this.pending = undefined;
    this.socket?.destroy();
    this.socket = undefined;
    if (p) {
      clearTimeout(p.timer);
      p.reject(e);
    }
  }

  /** The open connection, opening one where there is none. */
  private open(): Promise<TLSSocket> {
    if (this.socket !== undefined && !this.socket.destroyed) return Promise.resolve(this.socket);
    if (this.opening !== undefined) return this.opening;
    // Each attempt settles its own promise, once, and clears `opening` only
    // while `opening` is still this attempt. A failed socket reports "error"
    // and then "close"; by the time "close" arrives a request after it may have
    // begun an attempt of its own, and clearing that attempt's `opening` left
    // its promise to be settled by nothing, so the request waited for ever.
    let settled = false;
    let mine: Promise<TLSSocket> | undefined;
    const settle = () => {
      settled = true;
      if (this.opening === mine) this.opening = undefined;
    };
    mine = new Promise<TLSSocket>((resolve, reject) => {
      const o = this.opts;
      const s = connect({
        // The server name is sent for a host name and not for an address:
        // RFC 6066 forbids an IP address in server name indication, and the
        // certificate is checked against the address either way.
        host: o.host, port: o.port ?? KMIP_PORT,
        ...(o.servername !== undefined ? { servername: o.servername }
          : isIP(o.host) === 0 ? { servername: o.host } : {}),
        ca: o.ca,
        ...(o.cert === undefined ? {} : { cert: o.cert }), ...(o.key === undefined ? {} : { key: o.key }),
        minVersion: BASIC_SUITE_PROTOCOL, maxVersion: BASIC_SUITE_PROTOCOL, ciphers: BASIC_SUITE_CIPHERS.join(":"),
        rejectUnauthorized: true,
      }, () => {
        settle();
        this.socket = s;
        resolve(s);
      });
      const reader = new MessageReader();
      s.on("data", (chunk: Buffer) => {
        let frames: Buffer[];
        try {
          frames = reader.frames(chunk);
        } catch (e) {
          this.fail(new KmipProtocolError(`the response cannot be separated: ${(e as Error).message}`));
          return;
        }
        for (const f of frames) {
          const p = this.pending;
          if (p === undefined) {
            this.fail(new KmipProtocolError("a response arrived for no request"));
            return;
          }
          this.pending = undefined;
          clearTimeout(p.timer);
          try {
            p.resolve(decode(f));
          } catch (e) {
            p.reject(new KmipProtocolError(`the response cannot be parsed: ${(e as TtlvError).message}`));
          }
        }
      });
      s.on("error", (e: Error) => {
        if (!settled) {
          settle();
          reject(new KmipProtocolError(`the connection could not be made: ${e.message}`));
        } else if (this.socket === s) {
          this.fail(new KmipProtocolError(`the connection failed: ${e.message}`));
        }
      });
      s.on("close", () => {
        if (this.socket === s) this.socket = undefined;
        if (!settled) {
          settle();
          reject(new KmipProtocolError("the connection closed before it was established"));
        }
        // A request waiting on this connection is not sent again (see above).
        if (this.pending !== undefined) this.fail(new KmipProtocolError("the connection closed before the response arrived"));
      });
    });
    this.opening = mine;
    return mine;
  }
}


/**
 * The outcomes of a batch from the response to its request: checked to answer
 * the request (its version, and each batch item's Unique Batch Item ID and
 * Operation), and each payload read by its operation's parser.
 */
export function readResponse(ops: Operation<unknown>[], options: BatchOptions, version: ProtocolVersion, message: Item):
  Outcome<unknown>[] {
    const response = decodeResponseOrThrow(message);
    // "Message cannot be parsed" and "Protocol major version mismatch" are
    // answered with one Batch Item without Operation (11.1), in whatever version
    // the server speaks, so this is recognized before the version is compared.
    if (response.items.length === 1 && response.items[0].operation === undefined && response.items[0].resultStatus !== "Success" &&
      response.items[0].uniqueBatchItemId === undefined) {
      const e = new KmipOperationError(undefined, response.items[0].resultReason ?? "General Failure", response.items[0].resultMessage);
      return ops.map(() => ({ ok: false, error: e }));
    }
    if (response.header.protocolVersion.major !== version.major || response.header.protocolVersion.minor !== version.minor) {
      throw new KmipProtocolError(`the response is of version ${versionText(response.header.protocolVersion)}, ` +
        `and the request of ${versionText(version)}`);
    }
    if (response.items.length > ops.length || response.items.length === 0) {
      throw new KmipProtocolError(`the response holds ${response.items.length} batch items for a request of ${ops.length}`);
    }
    const identify = ops.length > 1 || options.alwaysIdentifyItems === true;
    const outcomes: Outcome<unknown>[] = [];
    let stoppedBy: KmipOperationError | undefined;
    for (let i = 0; i < ops.length; i++) {
      const item = findItem(response.items, i, identify);
      if (item === undefined) {
        // Not answered: the batch stopped at an earlier failure (6.13, Stop).
        outcomes.push({ ok: false, error: stoppedBy ?? new KmipOperationError(ops[i].operation, "General Failure", "not performed") });
        continue;
      }
      if (item.operation !== undefined && item.operation !== ops[i].operation) {
        throw new KmipProtocolError(`batch item ${i + 1} answers ${item.operation}, and asked ${ops[i].operation}`);
      }
      if (item.resultStatus === "Success") {
        outcomes.push({ ok: true, value: ops[i].parse(item.payload ?? []) });
      } else {
        const e = new KmipOperationError(ops[i].operation, item.resultReason ?? "General Failure", item.resultMessage);
        stoppedBy ??= e;
        outcomes.push({ ok: false, error: e });
      }
    }
    return outcomes;
}

function batchItemId(i: number): Buffer {
  const n = i + 1;
  return n < 256 ? Buffer.from([n]) : Buffer.from([n >> 8, n & 0xff]);
}

/** The response batch item answering operation i: by Unique Batch Item ID where items are identified, by position otherwise. */
function findItem(items: ResponseBatchItem[], i: number, identified: boolean): ResponseBatchItem | undefined {
  if (!identified) return items[i];
  const id = batchItemId(i);
  const found = items.filter((it) => it.uniqueBatchItemId !== undefined && Buffer.from(it.uniqueBatchItemId).equals(id));
  if (found.length > 1) throw new KmipProtocolError(`the response answers batch item ${i + 1} more than once`);
  const unidentified = items.filter((it) => it.uniqueBatchItemId === undefined);
  if (unidentified.length > 0) throw new KmipProtocolError("a batch item of the response does not give its Unique Batch Item ID");
  return found[0];
}

function decodeResponseOrThrow(item: Item) {
  try {
    return decodeResponse(item);
  } catch (e) {
    throw new KmipProtocolError(`the response does not conform: ${(e as Error).message}`);
  }
}

// Names used by readers of results.
export { child, KMIP_ENUM, nameOf };
