// The key store: KMIP 1.4 to a key management server, and the cache in front of it.
//
// A password set through the administrative interface becomes a scrypt verifier
// and a Kerberos long-term key per enctype (dc-write.ts); an S3 key pair becomes
// a secret. None of it belongs in the directory, so all of it is registered here
// and the directory keeps the references. The consequence worth having: the store
// can be copied, diffed, backed up and read by an administrator without exposing
// anything (DESIGN-admin.md §3).
//
// Why there is a cache. The key distribution centre needs a principal's long-term
// key on every AS exchange, and this key management server serves no Encrypt or
// Decrypt operation, so the key has to be fetched rather than used in place. A
// fetch per ticket request would make the key server part of the latency of every
// authentication, so material is held for `lifetime` and dropped at once when
// dc-write.ts changes it. That is a window in which a destroyed key still works,
// and it is stated in the log at start rather than discovered.
//
// What this module is not: it holds no rule about the directory. It registers,
// fetches and destroys, and it says plainly when it cannot reach the server, so
// that the controller can serve what needs no secret and refuse what does.

import { connect as tlsConnect, type TLSSocketType } from "node:tls";
import { randomBytes } from "node:crypto";
import {
  bytes, child, children, decode, encode, enumeration, type Item, int, numberOf,
  struct, TAG, text, textOf, TYPE,
} from "./dc-ttlv.ts";
import type { KeyStore } from "./dc-write.ts";

/** Raised where the key management server refused, or could not be reached. */
export class KeyStoreError extends Error {
  /** Whether the server could not be reached, as against refusing what was asked. */
  readonly unreachable: boolean;
  /**
   * The Result Reason the server gave, where it refused. Carried as the number and not
   * only inside the message, so that a caller can act on a particular refusal without
   * reading prose: `Writer.sweep` tells "already destroyed" from a real failure by it.
   */
  readonly reason?: number;
  constructor(message: string, unreachable = false, reason?: number) {
    super(message);
    this.unreachable = unreachable;
    if (reason !== undefined) this.reason = reason;
  }
}

/**
 * The Result Reasons this client distinguishes. From Table 284; the sibling key server
 * carries the whole enumeration, and these are the two a caller here acts on.
 */
export const REASON = Object.freeze({
  /** The object is there and has already been destroyed, so there is nothing to destroy. */
  objectDestroyed: 12,
} as const);

/** The operations of Table 283 this client sends. */
const OP = Object.freeze({
  Register: 0x03,
  Locate: 0x08,
  Get: 0x0a,
  Revoke: 0x13,
  Destroy: 0x14,
  Query: 0x18,
} as const);

/** The object types of Table 288 this client registers. */
const OBJECT = Object.freeze({
  SymmetricKey: 0x02,
  SecretData: 0x07,
} as const);

/** Result Status (Table 287): the only value that is not a failure. */
const SUCCESS = 0x00;

/** Secret Data Type: a password is what a verifier and an S3 secret are. */
const SECRET_PASSWORD = 0x01;

/** Key Format Type: Raw, the octets as they are. */
const FORMAT_RAW = 0x01;

/** Cryptographic Algorithm: AES, which a Kerberos long-term key is for. */
const ALG_AES = 0x03;

/**
 * Cryptographic Usage Mask. Table 171 requires one of every managed
 * cryptographic object, which includes Secret Data, so a verifier carries the
 * mask of what is done with it: nothing but comparison, which Verify names.
 */
const USAGE = Object.freeze({
  verify: 0x02,
  encryptDecrypt: 0x04 | 0x08,
} as const);

/**
 * The object groups the material of this controller is registered in. The group
 * is how the key management server's configuration grants the CDMI server the
 * secret of an S3 key pair **and nothing else**: a grant on
 * `seedmi-dc/s3` does not reach a Kerberos key or a password verifier
 * (DESIGN-admin.md §4a).
 */
export const GROUP = Object.freeze({
  password: "seedmi-dc/password",
  kerberos: "seedmi-dc/kerberos",
  s3: "seedmi-dc/s3",
} as const);

/** The custom attribute naming the principal material belongs to. */
const PRINCIPAL_ATTRIBUTE = "x-seedmi-dc-principal";

/**
 * The prefix of every Name this controller registers. seedmi-kms reads the prefix
 * of a Name as everything up to its last "/" and gives it to the first client
 * that registers beneath it, so one prefix keeps this controller's material
 * apart from any other client's at a shared key server.
 */
export const NAME_PREFIX = "seedmi-dc/";

/** Where the key management server is, and what this controller presents to it. */
export interface KmsConfig {
  host: string;
  port: number;
  /** The certificate and key this controller authenticates with. */
  certificate: string;
  key: string;
  /** The authority the server's certificate is accepted under. */
  authority?: string;
  /** How long fetched material is held, in milliseconds. */
  lifetime: number;
  /** How long to wait for a connection and for a response, in milliseconds. */
  timeout?: number;
}

/** What a transport does: one request, one response, both whole TTLV items. */
export type Transport = (request: Buffer) => Promise<Buffer>;

/**
 * A KMIP client that holds material at a key management server.
 *
 * The transport is a seam so that the operations and the cache are tested
 * without a key server, and so that a deployment reaching one over something
 * other than TLS — a tunnel, a test harness — needs no change here.
 */
export class KmipKeyStore implements KeyStore {
  private readonly send: Transport;
  private readonly lifetime: number;
  private readonly held = new Map<string, { material: Buffer; until: number }>();
  /** Whether the last attempt could not reach the server, for the health check. */
  private reached = true;

  constructor(send: Transport, lifetime: number) {
    this.send = send;
    this.lifetime = lifetime;
  }

  /** A client over TLS, as the Basic Authentication Suite requires of one. */
  static over(config: KmsConfig): KmipKeyStore {
    return new KmipKeyStore(tlsTransport(config), config.lifetime);
  }

  /** Whether the key management server answered the last time it was asked. */
  get available(): boolean {
    return this.reached;
  }

  async register(kind: "password" | "kerberos" | "s3", principal: string,
    material: Buffer, note?: string): Promise<string> {
    const value = kind === "kerberos"
      ? symmetricKey(material)
      : secretData(material);
    const attributes: Item[] = [
      attribute("Cryptographic Usage Mask",
        int(TAG.AttributeValue, kind === "kerberos" ? USAGE.encryptDecrypt : USAGE.verify)),
      attribute("Object Group", text(TAG.AttributeValue, GROUP[kind])),
      attribute(PRINCIPAL_ATTRIBUTE, text(TAG.AttributeValue, principal)),
      // A Name a person reads in the key server's own listing, which is how an
      // operator tells one principal's material from another's. It is beneath a
      // prefix of this controller's own, both so that the names of two clients do
      // not meet and because seedmi-kms lets the holder of a prefix keep it: a
      // key server shared with a CDMI server hands out what is beneath this one
      // only where its configuration says so.
      // A generation tag ends it, because a Name is unique at a key management
      // server and material is replaced by registering the new before destroying
      // the old: KMIP's error tables make "trying to create a new object with the
      // same Name attribute value as an existing object" Invalid Field (11.2),
      // and without the tag a second password for one principal is refused. Found
      // by changing a password twice.
      attribute("Name", struct(TAG.AttributeValue, [
        text(TAG.NameValue, `${NAME_PREFIX}${kind}:${principal}` +
          `${note === undefined ? "" : `:${note}`}:${randomBytes(4).toString("hex")}`),
        enumeration(TAG.NameType, 0x01), // Uninterpreted Text String
      ])),
    ];
    if (kind === "kerberos") {
      attributes.push(
        attribute("Cryptographic Algorithm", enumeration(TAG.AttributeValue, ALG_AES)),
        attribute("Cryptographic Length", int(TAG.AttributeValue, material.length * 8)));
    }
    const payload = struct(TAG.RequestPayload, [
      enumeration(TAG.ObjectType, kind === "kerberos" ? OBJECT.SymmetricKey : OBJECT.SecretData),
      struct(TAG.TemplateAttribute, attributes),
      value,
    ]);
    const response = await this.operation(OP.Register, payload);
    const id = textOf(response, TAG.UniqueIdentifier);
    if (id === undefined) {
      throw new KeyStoreError("a Register response carries the Unique Identifier of what it registered");
    }
    return id;
  }

  async get(ref: string): Promise<Buffer> {
    const held = this.held.get(ref);
    if (held !== undefined && held.until > Date.now()) return held.material;
    const response = await this.operation(OP.Get,
      struct(TAG.RequestPayload, [text(TAG.UniqueIdentifier, ref)]));
    const material = materialOf(response);
    if (material === undefined) {
      throw new KeyStoreError(`the object at ${ref} holds no key material this client reads`);
    }
    this.held.set(ref, { material, until: Date.now() + this.lifetime });
    return material;
  }

  async destroy(ref: string): Promise<void> {
    this.held.delete(ref);
    await this.operation(OP.Destroy,
      struct(TAG.RequestPayload, [text(TAG.UniqueIdentifier, ref)]));
  }

  /**
   * The references of the material of one principal, by the custom attribute
   * every object of this controller carries. Used to find what a principal
   * removed outside this controller left behind.
   */
  async locate(principal: string): Promise<string[]> {
    const response = await this.operation(OP.Locate, struct(TAG.RequestPayload, [
      attribute(PRINCIPAL_ATTRIBUTE, text(TAG.AttributeValue, principal)),
    ]));
    return children(response, TAG.UniqueIdentifier)
      .filter((i) => i.type === TYPE.TextString)
      .map((i) => i.value as string);
  }

  /**
   * Every reference this controller has registered at this key server, found by the
   * `Object Group` each kind is registered in.
   *
   * This is what makes `Writer.sweep` possible against a real key server: the
   * compensating destroy covers a change that fails, and cannot cover a process that
   * stopped between a registration and the commit, so there has to be a way to ask the
   * key server what it holds and compare it with what the store references. Locating by
   * the three groups rather than with an empty filter matters — an empty Locate returns
   * everything the client may see, and this key server is shared with a CDMI server
   * (DESIGN-admin.md §4a), whose objects are none of this controller's business and must
   * not be swept.
   *
   * A principal's own material is found by `locate` instead, which filters on the
   * principal attribute; orphaned material cannot be, its principal not existing, which
   * is the whole reason this exists.
   *
   * **This returns objects that have already been destroyed**, and that is KMIP being
   * obeyed rather than a defect here. §4.9 of the Locate operation: "All attributes are
   * allowed to be used" and "Returned objects SHALL match all of the attributes in the
   * request" — so a Locate that does not mention `State` matches every state, Destroyed
   * included, and nothing in the operation's text hints that a client wanting live
   * objects must say so. The first live run of `Writer.sweep` found thirty such objects
   * and tried to destroy each one again.
   *
   * It is **not** fixed by adding a `State` filter here, because Locate matches on
   * equality and there is no way to say "not Destroyed": an object still holding
   * material may be Pre-Active, Active, Deactivated or Compromised, so excluding the two
   * Destroyed states would take four Locates and a dependence on an enumeration this
   * program would be asserting rather than checking. The sweep tells the two apart by
   * the Result Reason instead, which the server states.
   */
  async references(): Promise<string[]> {
    const all = new Set<string>();
    for (const group of Object.values(GROUP)) {
      const response = await this.operation(OP.Locate, struct(TAG.RequestPayload, [
        attribute("Object Group", text(TAG.AttributeValue, group)),
      ]));
      for (const i of children(response, TAG.UniqueIdentifier)) {
        if (i.type === TYPE.TextString) all.add(i.value as string);
      }
    }
    return [...all];
  }

  /** Drops what is held of one reference, which a change of material requires. */
  forget(ref: string): void {
    this.held.delete(ref);
  }

  /** Drops everything held, which a reload does. */
  forgetAll(): void {
    this.held.clear();
  }

  /** What the controller reports: how much is cached, and for how long. */
  get cached(): number {
    return this.held.size;
  }

  /**
   * Asks the server what it is, which is the one operation that needs no
   * authentication and so the one a health check uses.
   */
  async query(): Promise<string | undefined> {
    const response = await this.operation(OP.Query, struct(TAG.RequestPayload, [
      // Query Function: Query Server Information (Table 287 gives 0x03).
      enumeration(0x420074, 0x03),
    ]));
    return textOf(response, 0x42009d); // Vendor Identification
  }

  /** One operation, one batch item, and the response payload or a refusal. */
  private async operation(operation: number, payload: Item): Promise<Item> {
    const request = encode(struct(TAG.RequestMessage, [
      struct(TAG.RequestHeader, [
        struct(TAG.ProtocolVersion, [
          int(TAG.ProtocolVersionMajor, 1),
          int(TAG.ProtocolVersionMinor, 4),
        ]),
        int(TAG.BatchCount, 1),
      ]),
      struct(TAG.BatchItem, [
        enumeration(TAG.Operation, operation),
        payload,
      ]),
    ]));
    let reply: Buffer;
    try {
      reply = await this.send(request);
      this.reached = true;
    } catch (e) {
      this.reached = false;
      throw new KeyStoreError(
        `the key management server could not be reached: ${(e as Error).message}`, true);
    }
    const message = decode(reply);
    if (message.tag !== TAG.ResponseMessage) {
      throw new KeyStoreError("a response to a Request Message is a Response Message");
    }
    const item = child(message, TAG.BatchItem);
    if (item === undefined) {
      throw new KeyStoreError("a Response Message carries a Batch Item");
    }
    const status = numberOf(item, TAG.ResultStatus);
    if (status !== SUCCESS) {
      // "Result Reason ... REQUIRED if Result Status is Failure", and the
      // message is what an operator wants to read.
      const reason = numberOf(item, TAG.ResultReason);
      const said = textOf(item, TAG.ResultMessage);
      throw new KeyStoreError(
        `the key management server refused the operation` +
        `${reason === undefined ? "" : ` (reason ${reason})`}` +
        `${said === undefined ? "" : `: ${said}`}`, false, reason);
    }
    const response = child(item, TAG.ResponsePayload);
    if (response === undefined) {
      throw new KeyStoreError("a successful Batch Item carries a Response Payload");
    }
    return response;
  }
}

/** An Attribute, which is how everything about an object is given. */
function attribute(name: string, value: Item): Item {
  return struct(TAG.Attribute, [text(TAG.AttributeName, name), value]);
}

/** A Secret Data of the octets given: a verifier, or an S3 secret. */
function secretData(material: Buffer): Item {
  return struct(TAG.SecretData, [
    enumeration(TAG.SecretDataType, SECRET_PASSWORD),
    struct(TAG.KeyBlock, [
      enumeration(TAG.KeyFormatType, FORMAT_RAW),
      struct(TAG.KeyValue, [bytes(TAG.KeyMaterial, material)]),
    ]),
  ]);
}

/**
 * A Symmetric Key of the octets given: a Kerberos long-term key. The algorithm
 * and the length are in the Key Block, which Table 171 permits in place of
 * attributes of their own — "neither given nor held in the Key Block" is the
 * server's complaint where both are missing.
 */
function symmetricKey(material: Buffer): Item {
  return struct(TAG.SymmetricKey, [
    struct(TAG.KeyBlock, [
      enumeration(TAG.KeyFormatType, FORMAT_RAW),
      struct(TAG.KeyValue, [bytes(TAG.KeyMaterial, material)]),
      enumeration(TAG.CryptographicAlgorithm, ALG_AES),
      int(TAG.CryptographicLength, material.length * 8),
    ]),
  ]);
}

/** The octets a Get returned, whichever object type carries them. */
function materialOf(payload: Item): Buffer | undefined {
  for (const tag of [TAG.SymmetricKey, TAG.SecretData]) {
    const object = child(payload, tag);
    if (object === undefined) continue;
    const block = child(object, TAG.KeyBlock);
    if (block === undefined) continue;
    const value = child(block, TAG.KeyValue);
    if (value === undefined) continue;
    const material = child(value, TAG.KeyMaterial);
    if (material?.type === TYPE.ByteString) return material.value;
  }
  return undefined;
}

/**
 * A transport over TLS: one connection per operation.
 *
 * A connection for each is the simple thing and is what a controller setting a
 * password does a handful of times; the cache is what keeps the hot path — a
 * ticket request — off the wire. A pooled connection is a later change and needs
 * no change here.
 */
export function tlsTransport(config: KmsConfig): Transport {
  return (request: Buffer) => new Promise<Buffer>((resolve, reject) => {
    const socket: TLSSocketType = tlsConnect({
      host: config.host,
      port: config.port,
      cert: config.certificate,
      key: config.key,
      ...(config.authority === undefined ? { rejectUnauthorized: false } : { ca: config.authority }),
      minVersion: "TLSv1.2",
    }, () => {
      socket.write(request);
    });
    const timeout = config.timeout ?? 10000;
    socket.setTimeout(timeout);
    const parts: Buffer[] = [];
    let want: number | undefined;
    const finish = (e?: Error) => {
      socket.destroy();
      if (e !== undefined) reject(e);
    };
    socket.on("data", (chunk: Buffer) => {
      parts.push(chunk);
      const held = Buffer.concat(parts);
      // A response is one TTLV item, so its length is known once eight octets
      // have arrived: the four-octet length and the padding to a multiple of
      // eight.
      if (want === undefined && held.length >= 8) {
        const length = held.readUInt32BE(4);
        want = 8 + length + ((8 - (length % 8)) % 8);
      }
      if (want !== undefined && held.length >= want) {
        socket.destroy();
        resolve(held.subarray(0, want));
      }
    });
    socket.on("timeout", () => finish(new Error(`no response within ${timeout} ms`)));
    socket.on("error", (e: Error) => finish(e));
    socket.on("close", () => {
      if (want === undefined || Buffer.concat(parts).length < want) {
        finish(new Error("the connection closed before a whole response arrived"));
      }
    });
  });
}
