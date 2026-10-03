// The managed objects of a key management server, their attributes and
// states, and the operations on them: what KMIP says a server does,
// without the messages that carry it. Section numbers and tables are those
// of the Key Management Interoperability Protocol Specification Version 1.4,
// OASIS Standard. The Result Reason of each refusal is the one the error table
// of section 11 gives for it.
//
// This core is the key management server: kmip-server.ts serves it over TTLV
// and TLS, and kmsd.ts runs that as a program of its own.
//
// Scope, phase 3a: Secret Data, Symmetric Key, Private Key, Public Key,
// Certificate and Opaque Object; Register, Create, Create Key Pair (RSA),
// Locate, Get, Get Attributes, Get Attribute List, Add, Modify and Delete
// Attribute, Activate, Revoke, Destroy, Re-key and Re-key Key Pair. The
// cryptographic operations are phase 4. Objects are held in memory; the
// store behind the internal server is phase 7. Decisions KMIP leaves to
// the server are recorded in NOTES-on-kmip.md.

import { createHash, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { ATTRIBUTE_RULES } from "./kmip-attributes.ts";
import { KMIP_ENUM } from "./kmip-registry.ts";
import { type Attribute, enumName } from "./kmip-message.ts";
import { child, decode, encode, type Item, k, nameOf, tagOf, TYPE } from "./kmip-ttlv.ts";
import {
  aesDecrypt, aesEncrypt, type CipherResult, type CryptoParams, keyMaterial, mac, macMatches, mergeParams,
  paramsMatch, privateKeyOf, publicKeyOf, readParams, rsaDecrypt, rsaEncrypt, signData, unwrapAes, verifyData, wrapAes,
  writeParams,
} from "./kms-crypto.ts";

// ---------------------------------------------------------------------------
// Errors

import { KmsError } from "./kms-core-error.ts";
export { KmsError };

// ---------------------------------------------------------------------------
// Objects

export const OBJECT_TYPES = [
  "Certificate", "Symmetric Key", "Public Key", "Private Key", "Secret Data", "Opaque Object",
] as const;
export type ObjectType = typeof OBJECT_TYPES[number];

export type State =
  "Pre-Active" | "Active" | "Deactivated" | "Compromised" | "Destroyed" | "Destroyed Compromised";

/** One instance of an attribute, with the index 1.x names it by. */
interface Instance {
  name: string;
  index: number;
  value: Item;
}

interface ManagedObject {
  id: string;
  type: ObjectType;
  /** The identity that created or registered the object. */
  owner: string;
  /** The object structure, as registered or generated; absent once destroyed. */
  value: Item | undefined;
  attrs: Instance[];
  /** The next index of each attribute name ("SHALL NOT change", 2.1.1). */
  nextIndex: Map<string, number>;
  /** Order of creation, by which Locate lists the most recent first (this server's choice). */
  seq: number;
}

/**
 * Where the core keeps its objects between runs. Each object is saved as a
 * record (see objectRecord); `save` receives every object an operation changed,
 * and is expected to write them together.
 */
export interface KmsStorage {
  load(): string[];
  save(records: { id: string; record: string }[]): void;
}

export interface CoreOptions {
  /** Milliseconds since the epoch. */
  now?: () => number;
  newId?: () => string;
  /** Objects are held in memory alone where none is given. */
  storage?: KmsStorage;
}

/** An object as a record: JSON, each item carried as its TTLV encoding in base64. */
function objectRecord(o: ManagedObject): string {
  const b64 = (i: Item) => encode(i).toString("base64");
  return JSON.stringify({
    id: o.id, type: o.type, owner: o.owner, seq: o.seq,
    value: o.value === undefined ? null : b64(o.value),
    attrs: o.attrs.map((a) => ({ name: a.name, index: a.index, value: b64(a.value) })),
    nextIndex: [...o.nextIndex.entries()],
  });
}

function objectFromRecord(record: string): ManagedObject {
  const r = JSON.parse(record) as {
    id: string; type: ObjectType; owner: string; seq: number; value: string | null;
    attrs: { name: string; index: number; value: string }[]; nextIndex: [string, number][];
  };
  const item = (b: string) => decode(Buffer.from(b, "base64"));
  return {
    id: r.id, type: r.type, owner: r.owner, seq: r.seq,
    value: r.value === null ? undefined : item(r.value),
    attrs: r.attrs.map((a) => ({ name: a.name, index: a.index, value: item(a.value) })),
    nextIndex: new Map(r.nextIndex),
  };
}

/** The public operations, after each of which the objects it changed are saved. */
const SAVED_AFTER = [
  "register", "create", "createKeyPair", "locate", "get", "getAttributes", "getAttributeList", "addAttribute",
  "modifyAttribute", "deleteAttribute", "activate", "revoke", "destroy", "encrypt", "decrypt", "sign",
  "signatureVerify", "mac", "macVerify", "rekey", "rekeyKeyPair",
] as const;

/** The identity an operation is performed for, as the transport established it. */
export type Who = string;

/**
 * What a server's policy is told about an object when it decides whether an
 * identity may act on it: the first Name it bears, and the Object Groups it is
 * in. KMIP leaves access control to the server, and these two are what a
 * deployment's configuration keys a grant on (see kms-prefixes.ts).
 */
export interface ObjectIdentity {
  name?: string;
  groups: string[];
}

// ---------------------------------------------------------------------------
// Attribute rules, as the tables of section 3 state them

const yes = (text: string | undefined) => /^yes/i.test((text ?? "").trim());
/**
 * A custom attribute (3.39): "All custom attributes created by the client SHALL
 * adhere to a naming scheme, where the name of the attribute SHALL have a prefix
 * of 'x-'", and those the server creates 'y-'. Its rules are those of Table 138.
 * Its value travels under the tag Attribute Value, since "The tag type Custom
 * Attribute is not able to identify the particular attribute".
 */
export const isCustomAttribute = (name: string) => name.startsWith("x-") || name.startsWith("y-");
const rules = (name: string) => isCustomAttribute(name) ? ATTRIBUTE_RULES["Custom Attribute"] : ATTRIBUTE_RULES[name];
const valueTagOf = (name: string) => tagOf(isCustomAttribute(name) ? "Attribute Value" : name);

/** "The server SHALL NOT accept a client-created or modified attribute, where the name of the attribute has a prefix of 'y-'." */
function refuseServerCustom(name: string, reason: string): void {
  if (name.startsWith("y-")) throw new KmsError(reason, `${name} is a custom attribute of the server, not set by a client`);
}

/** "If a structure, then the structure SHALL NOT include sub structures" (Table 137). */
function checkCustomValue(name: string, value: Item): void {
  if (isCustomAttribute(name) && value.type === TYPE.Structure &&
    (value.value as Item[]).some((c) => c.type === TYPE.Structure)) {
    throw new KmsError("Invalid Field", `the custom attribute ${name} holds a structure within a structure`);
  }
}
const multiInstance = (name: string) => yes(rules(name)?.multipleInstances);

/**
 * The attributes a client does not supply when an object is created or
 * registered, because the server sets each from its own act. The rules
 * tables cannot decide this alone: they give Cryptographic Algorithm as
 * "Initially set by: Server" (Table 62), yet Table 171 requires a client to include it
 * in a Register request.
 */
const SERVER_SET = new Set([
  "Unique Identifier", "Object Type", "Initial Date", "State", "Last Change Date",
  "Destroy Date", "Compromise Date", "Compromise Occurrence Date", "Revocation Reason",
  "Digest", "Always Sensitive", "Never Extractable", "Key Value Present", "Key Format Type",
]);

/** The states a qualified rule allows, as "Yes, only while in Pre-Active or Active state". */
function statesAllowed(rule: string): State[] | undefined {
  const m = /only while in (.+?) state/i.exec(rule);
  if (!m) return undefined;
  return m[1].split(/\s+or\s+|,\s*/).map((s) => s.trim()) as State[];
}

// ---------------------------------------------------------------------------
// Values

const dateItem = (name: string, ms: number): Item => k.date(name, ms);
const msOf = (item: Item) => Number(item.value as bigint) * 1000;
const same = (a: Item, b: Item) => encode(a).equals(encode(b));

function enumOfItem(item: Item | undefined, enumeration: string): string | undefined {
  return item?.type === TYPE.Enumeration ? enumName(enumeration, item.value) : undefined;
}

/**
 * Whether an attribute value from a Locate request matches a candidate's.
 * A structure matches where each field the request gives matches ("all of
 * the structure fields are not REQUIRED to be specified").
 */
function matches(want: Item, have: Item): boolean {
  if (want.tag !== have.tag || want.type !== have.type) return false;
  if (want.type !== TYPE.Structure) return same(want, have);
  return (want.value as Item[]).every((w) =>
    (have.value as Item[]).some((h) => matches(w, h)));
}

/** The key material of an object's value, or its certificate or opaque value. */
function materialOf(value: Item | undefined): { bytes: Buffer; format?: string } | undefined {
  if (value === undefined) return undefined;
  const cert = child(value, "Certificate Value") ?? child(value, "Opaque Data Value");
  if (cert?.type === TYPE.ByteString) return { bytes: cert.value };
  const block = child(value, "Key Block");
  if (block === undefined) return undefined;
  const format = enumOfItem(child(block, "Key Format Type"), "Key Format Type");
  const kv = child(block, "Key Value");
  if (kv === undefined) return undefined;
  // A Key Value is a Byte String where wrapped, and a structure otherwise.
  if (kv.type === TYPE.ByteString) return { bytes: kv.value, ...(format ? { format } : {}) };
  const km = child(kv, "Key Material");
  if (km === undefined) return undefined;
  // "If the Key Material is a structure, then the Digest Value SHALL be calculated
  // on the TTLV-encoded (see Section 9.1) Key Material structure" (3.17).
  const bytes = km.type === TYPE.ByteString ? km.value : encode(km);
  return { bytes, ...(format ? { format } : {}) };
}

/** Whether an object's Key Block holds its Key Value wrapped (2.1.3). */
function isWrapped(value: Item | undefined): boolean {
  const block = value === undefined ? undefined : child(value, "Key Block");
  return block !== undefined && child(block, "Key Wrapping Data") !== undefined;
}

/** A Key Block holding raw key material, as Create produces one. */
function keyBlock(format: string, material: Buffer, algorithm?: string, length?: number): Item {
  return k.struct("Key Block", [
    k.enum("Key Format Type", "Key Format Type", format),
    k.struct("Key Value", [k.bytes("Key Material", material)]),
    ...(algorithm === undefined ? [] : [k.enum("Cryptographic Algorithm", "Cryptographic Algorithm", algorithm)]),
    ...(length === undefined ? [] : [k.int("Cryptographic Length", length)]),
  ]);
}

/** The structure an object type's value takes (section 2.2). */
const VALUE_TAG: Record<ObjectType, string> = {
  "Certificate": "Certificate", "Symmetric Key": "Symmetric Key", "Public Key": "Public Key",
  "Private Key": "Private Key", "Secret Data": "Secret Data", "Opaque Object": "Opaque Object",
};

// ---------------------------------------------------------------------------
// The core

/** A Key Wrapping Specification (2.1.6, Table 12), as the core takes it. */
export interface WrappingSpecification {
  method: string;
  encryptionKey?: { id: string; params?: CryptoParams };
  attributeNames?: string[];
  encodingOption?: string;
}

export interface LocateOptions {
  maximumItems?: number;
  offsetItems?: number;
  /** Storage Status Mask bits (9.1.3.3.2); "If omitted, then on-line only is assumed". */
  storageStatusMask?: number;
}

export class KmsCore {
  private readonly objects = new Map<string, ManagedObject>();
  private seq = 0;
  private readonly now: () => number;
  private readonly newId: () => string;
  private readonly storage: KmsStorage | undefined;
  /** The objects the operation in progress has changed. */
  private readonly dirty = new Set<ManagedObject>();

  constructor(opts: CoreOptions = {}) {
    this.now = opts.now ?? Date.now;
    this.newId = opts.newId ?? randomUUID;
    this.storage = opts.storage;
    if (this.storage !== undefined) {
      for (const record of this.storage.load()) {
        const o = objectFromRecord(record);
        this.objects.set(o.id, o);
        this.seq = Math.max(this.seq, o.seq);
      }
      // Each public operation saves what it changed, whether it succeeds or not,
      // so that what is held and what is stored agree. A read can change an
      // object too: a date reached moves its State (3.22).
      for (const name of SAVED_AFTER) {
        const op = (this as unknown as Record<string, (...a: unknown[]) => unknown>)[name].bind(this);
        (this as unknown as Record<string, unknown>)[name] = (...args: unknown[]) => {
          try {
            return op(...args);
          } finally {
            this.flush();
          }
        };
      }
    }
  }

  private flush(): void {
    if (this.dirty.size === 0 || this.storage === undefined) return;
    const records = [...this.dirty].map((o) => ({ id: o.id, record: objectRecord(o) }));
    this.dirty.clear();
    this.storage.save(records);
  }

  private add(o: ManagedObject): void {
    this.objects.set(o.id, o);
    this.dirty.add(o);
  }

  // -------------------------------------------------------------------------
  // Access and state

  /**
   * Whether an identity may perform an operation on an object. The owner may
   * perform every operation; a server that admits other identities to part of
   * the Name space says so by overriding this, and the core keeps no other
   * rule of access.
   */
  protected mayAct(who: Who, owner: Who, _of: ObjectIdentity, _operation: string): boolean {
    return owner === who;
  }

  /** What an object is, as far as admission is concerned: its Name and its groups. */
  private identityOf(o: ManagedObject): ObjectIdentity {
    return { name: this.nameOfObject(o), groups: this.groupsOfObject(o) };
  }

  /** The first Name an object bears, which is the one admission is decided by. */
  private nameOfObject(o: ManagedObject): string | undefined {
    for (const a of o.attrs) {
      if (a.name !== "Name") continue;
      const inner = (a.value.value as Item[] | undefined)?.find((i) => nameOf(i.tag) === "Name Value");
      if (inner !== undefined && typeof inner.value === "string") return inner.value;
    }
    return undefined;
  }

  /**
   * The Object Groups an object bears. Table 171 makes the attribute multiple
   * instances, so an object may be in several, and a grant on any one of them
   * reaches it.
   */
  private groupsOfObject(o: ManagedObject): string[] {
    const out: string[] = [];
    for (const a of o.attrs) {
      if (a.name === "Object Group" && typeof a.value.value === "string") out.push(a.value.value);
    }
    return out;
  }

  /**
   * Whether an identity may know the object exists at all, whatever it may do
   * with it. The core's answer is the owner alone; a server that admits other
   * identities to part of the Name space overrides this beside `mayAct`.
   */
  protected mayKnowOf(who: Who, owner: Who, _of: ObjectIdentity): boolean {
    return owner === who;
  }

  /**
   * The object an identity may act on. KMIP leaves access control to server
   * policy; this core gives each object to the identity that created it, and
   * answers an identity that may not know of it as though no object existed, so
   * that one client does not learn of another's objects.
   *
   * An identity that may know of the object and may not perform *this* operation
   * is told so: "Permission Denied" (11.4). Running the §4a grant of seedmi-dc
   * showed why the distinction is worth drawing — a client admitted to read an
   * object had just retrieved it, and a Destroy answered "no object exists",
   * which is a denial dressed as an absence and which that client can see
   * through. Concealment is for objects an identity knows nothing of.
   */
  private find(who: Who, id: string, operation = ""): ManagedObject {
    const o = this.objects.get(id);
    if (o === undefined || !this.mayKnowOf(who, o.owner, this.identityOf(o))) {
      throw new KmsError("Item Not Found", `no object ${JSON.stringify(id)} exists`);
    }
    if (!this.mayAct(who, o.owner, this.identityOf(o), operation)) {
      throw new KmsError("Permission Denied",
        `${JSON.stringify(id)} is not this identity's, and it is not admitted to ` +
        `${operation === "" ? "that operation" : operation} on it`);
    }
    this.advance(o);
    return o;
  }

  private attr(o: ManagedObject, name: string): Item | undefined {
    return o.attrs.find((a) => a.name === name)?.value;
  }

  state(o: ManagedObject): State {
    return enumOfItem(this.attr(o, "State"), "State") as State;
  }

  private setAttr(o: ManagedObject, value: Item, name = nameOf(value.tag)): void {
    this.dirty.add(o);
    const at = o.attrs.findIndex((a) => a.name === name);
    if (at >= 0 && !multiInstance(name)) o.attrs[at] = { ...o.attrs[at], value };
    else this.pushAttr(o, value, name);
  }

  private pushAttr(o: ManagedObject, value: Item, name = nameOf(value.tag)): void {
    this.dirty.add(o);
    const index = o.nextIndex.get(name) ?? 0;
    o.nextIndex.set(name, index + 1);
    o.attrs.push({ name, index, value });
  }

  private removeAttr(o: ManagedObject, name: string): void {
    this.dirty.add(o);
    o.attrs = o.attrs.filter((a) => a.name !== name);
  }

  private setState(o: ManagedObject, s: State): void {
    this.setAttr(o, k.enum("State", "State", s));
  }

  private touch(o: ManagedObject): void {
    this.setAttr(o, dateItem("Last Change Date", this.now()));
  }

  /**
   * The transitions caused by a date being reached (3.22): Pre-Active to
   * Active when "The Activation Date is reached", Active to Deactivated when
   * "The object's Deactivation Date is reached". They are applied when the
   * object is next looked at.
   */
  private advance(o: ManagedObject): void {
    const now = this.now();
    const act = this.attr(o, "Activation Date");
    if (this.state(o) === "Pre-Active" && act !== undefined && msOf(act) <= now) this.setState(o, "Active");
    const deact = this.attr(o, "Deactivation Date");
    if (this.state(o) === "Active" && deact !== undefined && msOf(deact) <= now) this.setState(o, "Deactivated");
  }

  // -------------------------------------------------------------------------
  // Names

  /**
   * A Name borne by no other object. 1.4 does not say in 3.2 that Names are
   * unique; its error tables do: "Trying to create a new object with the same
   * Name attribute value as an existing object" is Invalid Field (11.2, 11.4),
   * and "Trying to add a Name attribute with the same value that another object
   * already has" is Illegal Operation (11.15, 11.16).
   */
  private checkNamesFree(names: Item[], except: ManagedObject | undefined, reason: string): void {
    for (const n of names) {
      for (const o of this.objects.values()) {
        if (o === except) continue;
        if (o.attrs.some((a) => a.name === "Name" && same(a.value, n))) {
          throw new KmsError(reason,
            `the Name ${JSON.stringify(child(n, "Name Value")?.value)} is borne by another object`);
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Creating objects

  /**
   * Checks and applies the attributes a client supplies for a new object,
   * then those the server sets. Shared by Register, Create and Create Key
   * Pair.
   */
  private build(who: Who, type: ObjectType, supplied: Attribute[], value: Item): ManagedObject {
    const seen = new Map<string, number>();
    for (const a of supplied) {
      const r = rules(a.name);
      if (r === undefined) {
        throw new KmsError("Invalid Field", `${a.name} is not an attribute this server knows`);
      }
      if (SERVER_SET.has(a.name)) {
        throw new KmsError("Invalid Field", `${a.name} is set by the server, not supplied`);
      }
      refuseServerCustom(a.name, "Invalid Field");
      checkCustomValue(a.name, a.value);
      if (a.value.tag !== valueTagOf(a.name)) {
        throw new KmsError("Invalid Field", `the value of ${a.name} has the wrong tag`);
      }
      const n = (seen.get(a.name) ?? 0) + 1;
      if (n > 1 && !multiInstance(a.name)) {
        throw new KmsError("Invalid Field", `${a.name} is given more than once`);
      }
      seen.set(a.name, n);
    }
    this.checkNamesFree(supplied.filter((a) => a.name === "Name").map((a) => a.value), undefined, "Invalid Field");

    const now = this.now();
    const o: ManagedObject = {
      id: this.newId(), type, owner: who, value, attrs: [], nextIndex: new Map(), seq: ++this.seq,
    };
    this.pushAttr(o, k.text("Unique Identifier", o.id));
    this.pushAttr(o, k.enum("Object Type", "Object Type", type));
    for (const a of supplied) this.pushAttr(o, a.value, a.name);
    // "The Initial Date attribute of the object SHALL be set to the current
    // time" (4.3).
    this.pushAttr(o, dateItem("Initial Date", now));
    this.pushAttr(o, dateItem("Last Change Date", now));

    // Sensitive and Extractable "SHALL always have a value"; the companions
    // record their history (3.49, 3.51).
    if (this.attr(o, "Sensitive") === undefined) this.pushAttr(o, k.bool("Sensitive", false));
    if (this.attr(o, "Extractable") === undefined) this.pushAttr(o, k.bool("Extractable", true));
    this.pushAttr(o, k.bool("Always Sensitive", this.attr(o, "Sensitive")!.value as boolean));
    this.pushAttr(o, k.bool("Never Extractable", !(this.attr(o, "Extractable")!.value as boolean)));

    // The digest of a wrapped object would be of its plaintext, which the
    // server does not unwrap at registration; none is computed (3.17: "provided
    // that the server has access to the Key Material").
    const m = isWrapped(value) ? undefined : materialOf(value);
    if (m !== undefined) {
      // "a mandatory attribute instance computed with the SHA-256 hashing
      // algorithm" (3.17).
      this.pushAttr(o, k.struct("Digest", [
        k.enum("Hashing Algorithm", "Hashing Algorithm", "SHA-256"),
        k.bytes("Digest Value", createHash("sha256").update(m.bytes).digest()),
        ...(m.format ? [k.enum("Key Format Type", "Key Format Type", m.format)] : []),
      ]));
    }

    // Transition 1 (3.22): Pre-Active, or Active at once where the Activation
    // Date "has already occurred".
    const act = this.attr(o, "Activation Date");
    this.pushAttr(o, k.enum("State", "State",
      act !== undefined && msOf(act) <= now ? "Active" : "Pre-Active"));
    return o;
  }

  /** The attributes Table 171 requires, taken from the Key Block where it holds them. */
  private requireCryptographic(type: ObjectType, attrs: Attribute[], value: Item): Attribute[] {
    const has = (n: string) => attrs.some((a) => a.name === n);
    const out = [...attrs];
    if (type === "Symmetric Key" || type === "Private Key" || type === "Public Key") {
      const block = child(value, "Key Block");
      for (const [name, build] of [
        ["Cryptographic Algorithm", (i: Item) => i],
        ["Cryptographic Length", (i: Item) => i],
      ] as const) {
        if (has(name)) continue;
        const inBlock = block === undefined ? undefined : child(block, name);
        if (inBlock === undefined) {
          throw new KmsError("Missing Data",
            `${name} is required, and is neither given nor held in the Key Block (Table 171)`);
        }
        out.push({ name, value: build(inBlock) });
      }
    }
    if (type === "Certificate" && !has("Certificate Length")) {
      throw new KmsError("Missing Data", "Certificate Length is required for a Certificate (Table 171)");
    }
    // Cryptographic Usage Mask: "Yes" (Table 171), for "a Managed Cryptographic
    // Object", which an Opaque Object is not.
    if (type !== "Opaque Object" && !has("Cryptographic Usage Mask")) {
      throw new KmsError("Missing Data", "Cryptographic Usage Mask is required (Table 171)");
    }
    return out;
  }

  private checkValue(type: ObjectType, value: Item): void {
    if (value.tag !== tagOf(VALUE_TAG[type]) || value.type !== TYPE.Structure) {
      throw new KmsError("Invalid Field", `a ${type} is registered as a ${VALUE_TAG[type]} structure`);
    }
    const needs: Record<ObjectType, string[]> = {
      "Certificate": ["Certificate Type", "Certificate Value"],
      "Opaque Object": ["Opaque Data Type", "Opaque Data Value"],
      "Secret Data": ["Secret Data Type", "Key Block"],
      "Symmetric Key": ["Key Block"], "Private Key": ["Key Block"], "Public Key": ["Key Block"],
    };
    for (const n of needs[type]) {
      if (child(value, n) === undefined) throw new KmsError("Invalid Field", `a ${type} has a ${n}`);
    }
    const block = child(value, "Key Block");
    if (block !== undefined && child(block, "Key Format Type") === undefined) {
      throw new KmsError("Invalid Field", "a Key Block has a Key Format Type");
    }
  }

  /** Register (4.3). */
  register(who: Who, type: ObjectType, attrs: Attribute[], value: Item): string {
    if (!(OBJECT_TYPES as readonly string[]).includes(type)) {
      throw new KmsError("Invalid Field", `this server does not hold objects of type ${type}`);
    }
    this.checkValue(type, value);
    const o = this.build(who, type, this.requireCryptographic(type, attrs, value), value);
    this.add(o);
    return o.id;
  }

  /**
   * Create (4.1): "This operation requests the server to generate a new
   * symmetric key". Table 165 requires Cryptographic Algorithm and Cryptographic
   * Usage Mask, and not Cryptographic Length; where the length is omitted this
   * server chooses 256 bits for AES and the output length of the hash for HMAC
   * (see NOTES-on-kmip.md).
   */
  create(who: Who, type: ObjectType, attrs: Attribute[]): string {
    if (type !== "Symmetric Key") {
      throw new KmsError("Invalid Field", `Create generates a Symmetric Key, not a ${type}`);
    }
    const get = (n: string) => attrs.find((a) => a.name === n)?.value;
    const algorithm = enumOfItem(get("Cryptographic Algorithm"), "Cryptographic Algorithm");
    if (algorithm === undefined || get("Cryptographic Usage Mask") === undefined) {
      throw new KmsError("Missing Data", "Create needs a Cryptographic Algorithm and a Cryptographic Usage Mask (Table 165)");
    }
    const HMAC_LENGTHS: Record<string, number> = {
      "HMAC-SHA1": 160, "HMAC-SHA224": 224, "HMAC-SHA256": 256, "HMAC-SHA384": 384, "HMAC-SHA512": 512, "HMAC-MD5": 128,
    };
    if (algorithm !== "AES" && HMAC_LENGTHS[algorithm] === undefined) {
      // "Incorrect attribute value(s) specified" (11.2).
      throw new KmsError("Invalid Field", `this server does not create ${algorithm} keys`);
    }
    const given = get("Cryptographic Length")?.value as number | undefined;
    const length = given ?? (algorithm === "AES" ? 256 : HMAC_LENGTHS[algorithm]);
    if (algorithm === "AES" && ![128, 192, 256].includes(length)) {
      throw new KmsError("Invalid Field", `AES has no key of ${length} bits`);
    }
    if (length <= 0 || length % 8 !== 0) {
      throw new KmsError("Invalid Field", "a Cryptographic Length is a whole number of octets");
    }
    const value = k.struct("Symmetric Key", [keyBlock("Raw", randomBytes(length / 8), algorithm, length)]);
    const supplied = given === undefined ? [...attrs, { name: "Cryptographic Length", value: k.int("Cryptographic Length", length) }] : attrs;
    const o = this.build(who, type, supplied, value);
    this.pushAttr(o, dateItem("Original Creation Date", this.now()));
    this.add(o);
    return o.id;
  }

  /**
   * Create Key Pair (4.2), RSA. "Private Key Template-Attribute and Public Key
   * Template-Attribute objects in the request ... take precedence over the
   * Common Template-Attribute object." A required attribute missing is
   * "REQUIRED field(s) missing": Invalid Message (11.3).
   */
  createKeyPair(who: Who, common: Attribute[], priv: Attribute[], pub: Attribute[]):
    { privateKey: string; publicKey: string } {
    const merge = (specific: Attribute[]) => {
      const out = [...specific];
      for (const c of common) {
        if (multiInstance(c.name) || !specific.some((s) => s.name === c.name)) out.push(c);
      }
      return out;
    };
    const pa = merge(priv);
    const ua = merge(pub);
    const one = (list: Attribute[], n: string) => list.find((a) => a.name === n)?.value;
    // One key pair has one algorithm and one length.
    for (const n of ["Cryptographic Algorithm", "Cryptographic Length"]) {
      const p = one(pa, n);
      const u = one(ua, n);
      if (p === undefined || u === undefined) throw new KmsError("Invalid Message", `Create Key Pair needs ${n}`);
      if (!same(p, u)) throw new KmsError("Invalid Field", `${n} differs between the two keys`);
    }
    const algorithm = enumOfItem(one(pa, "Cryptographic Algorithm"), "Cryptographic Algorithm");
    const length = one(pa, "Cryptographic Length")!.value as number;
    if (algorithm !== "RSA") {
      throw new KmsError("Invalid Field", `this server creates RSA key pairs, not ${algorithm}`);
    }
    if (length < 2048) throw new KmsError("Invalid Field", "an RSA key is at least 2048 bits");
    for (const list of [pa, ua]) {
      if (one(list, "Cryptographic Usage Mask") === undefined) {
        throw new KmsError("Invalid Message", "each key of the pair needs a Cryptographic Usage Mask");
      }
    }
    // Names of both are checked together, so that the pair is made or neither.
    const names = [...pa, ...ua].filter((a) => a.name === "Name").map((a) => a.value);
    for (let i = 0; i < names.length; i++) {
      for (let j = i + 1; j < names.length; j++) {
        if (same(names[i], names[j])) {
          throw new KmsError("Invalid Field", "the two keys of a pair cannot share a Name");
        }
      }
    }
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: length,
      privateKeyEncoding: { type: "pkcs1", format: "der" },
      publicKeyEncoding: { type: "pkcs1", format: "der" },
    }) as unknown as { privateKey: Buffer; publicKey: Buffer };
    // 1.4 gives no default Key Format Type; this server generates RSA keys in PKCS#1.
    const po = this.build(who, "Private Key", pa,
      k.struct("Private Key", [keyBlock("PKCS#1", privateKey, "RSA", length)]));
    this.checkNamesFree(ua.filter((a) => a.name === "Name").map((a) => a.value), undefined, "Invalid Field");
    const uo = this.build(who, "Public Key", ua,
      k.struct("Public Key", [keyBlock("PKCS#1", publicKey, "RSA", length)]));
    for (const o of [po, uo]) this.pushAttr(o, dateItem("Original Creation Date", this.now()));
    // "For the Private Key, the server SHALL create a Link attribute of Link
    // Type Public Key pointing to the Public Key", and the converse.
    this.pushAttr(po, link("Public Key Link", uo.id));
    this.pushAttr(uo, link("Private Key Link", po.id));
    this.add(po);
    this.add(uo);
    return { privateKey: po.id, publicKey: uo.id };
  }

  // -------------------------------------------------------------------------
  // Finding and reading

  /** Locate (4.9). */
  locate(who: Who, attrs: Attribute[], opts: LocateOptions = {}): { ids: string[]; located: number } {
    for (const a of attrs) {
      // "Non-existing attributes, attributes that the server does not understand
      // ... are given in the request": Invalid Field (11.10).
      if (rules(a.name) === undefined) throw new KmsError("Invalid Field", `${a.name} is not an attribute`);
    }
    // Storage Status Mask "indicates whether only on-line objects, only archived
    // objects, or both on-line and archived objects are to be searched. If
    // omitted, then on-line only is assumed" (Table 190). This server archives
    // nothing, so every object, a destroyed object's retained metadata included,
    // is on-line; 1.4 defines no mask bit for destroyed objects.
    const wantOnline = ((opts.storageStatusMask ?? 1) & 1) !== 0;
    const groups = new Map<string, Item[]>();
    for (const a of attrs) groups.set(a.name, [...(groups.get(a.name) ?? []), a.value]);

    const found = [...this.objects.values()]
      .filter((o) => this.mayAct(who, o.owner, this.identityOf(o), "locate"))
      .filter((o) => {
        this.advance(o);
        if (!wantOnline) return false;
        for (const [name, wants] of groups) {
          const have = o.attrs.filter((a) => a.name === name).map((a) => a.value);
          if (!this.attributeMatches(name, wants, have)) return false;
        }
        return true;
      })
      // 1.4 gives no order for the objects Locate returns; this server lists the
      // most recently created first.
      .sort((a, b) => b.seq - a.seq)
      .map((o) => o.id);
    const offset = opts.offsetItems ?? 0;
    const end = opts.maximumItems === undefined ? undefined : offset + opts.maximumItems;
    return { ids: found.slice(offset, end), located: found.length };
  }

  private attributeMatches(name: string, wants: Item[], have: Item[]): boolean {
    const isDate = wants[0].type === TYPE.DateTime;
    if (isDate && wants.length === 2) {
      // "If two instances of the same Date attribute are used ... objects for
      // which the Date attribute is inside or at a limit of the range".
      const [lo, hi] = wants.map(msOf).sort((x, y) => x - y);
      return have.some((h) => msOf(h) >= lo && msOf(h) <= hi);
    }
    if (name === "Cryptographic Usage Mask") {
      // "a matching candidate object has all of the bits set in its mask that
      // are set in the requested mask, but MAY have additional bits set."
      return wants.every((w) => have.some((h) =>
        ((h.value as number) & (w.value as number)) === (w.value as number)));
    }
    return wants.every((w) => have.some((h) => matches(w, h)));
  }

  /** Get (4.11), with key wrapping by encryption where a specification is given. */
  get(who: Who, id: string,
    opts: { keyFormatType?: string; keyWrapType?: string; wrapping?: WrappingSpecification } = {}):
    { type: ObjectType; id: string; value: Item } {
    const o = this.find(who, id, "get");
    if (o.value === undefined) throw new KmsError("Key Value Not Present", "the object's key material was destroyed");
    if (this.attr(o, "Extractable")?.value === false) {
      // Wrapped or not: a non-extractable object does not leave the server.
      throw new KmsError("Not Extractable", "the object is not extractable");
    }
    const format = materialOf(o.value)?.format;
    if (opts.keyFormatType !== undefined && format !== undefined && opts.keyFormatType !== format) {
      // "If a client registered a key in a given format, the server SHALL be able to
      // return the key during the Get operation in the same format that was used
      // when the key was registered"; "Any other format conversion MAY be supported
      // by the server" (4.11). This one supports none.
      throw new KmsError("Key Format Type Not Supported",
        `the object is held as ${format}, and this server converts to no other format`);
    }
    if (opts.wrapping !== undefined) {
      return { type: o.type, id: o.id, value: this.wrap(who, o, opts.wrapping) };
    }
    // Key Wrap Type (Table 194): "Determines the Key Wrap Type of the returned
    // key value". Not Wrapped returns the plaintext, unwrapping an object
    // registered wrapped; As Registered, and an omitted Key Wrap Type, return
    // the object as it was registered (see NOTES-on-kmip.md).
    const value = opts.keyWrapType === "Not Wrapped" ? this.plainValue(who, o) : o.value;
    // "If True then the server SHALL prevent the object value being retrieved (via
    // the Get operation) unless it is wrapped by another key" (3.48).
    if (!isWrapped(value) && this.attr(o, "Sensitive")?.value === true) {
      throw new KmsError("Sensitive", "a sensitive object is not returned unwrapped");
    }
    return { type: o.type, id: o.id, value };
  }

  /**
   * The object's value in plaintext. An object registered wrapped ("The object and
   * attributes MAY be wrapped", Table 169) is unwrapped with the key its Key
   * Wrapping Data names. 1.4 does not say which usage the key must permit; this
   * server accepts Unwrap Key or Wrap Key, as KMIP Test Cases 1.4 TC-WRAP-2-14
   * and TC-WRAP-3-14 unwrap with a key whose mask is Wrap Key alone.
   */
  private plainValue(who: Who, o: ManagedObject): Item {
    const value = o.value!;
    if (!isWrapped(value)) return value;
    const block = child(value, "Key Block")!;
    const kwd = child(block, "Key Wrapping Data")!;
    const method = enumOfItem(child(kwd, "Wrapping Method"), "Wrapping Method");
    const eki = child(kwd, "Encryption Key Information");
    if (method !== "Encrypt" || eki === undefined) {
      throw new KmsError("Feature Not Supported", `an object wrapped by ${method} is not unwrapped here`);
    }
    const kekId = child(eki, "Unique Identifier")?.value as string;
    const { o: kek, value: kekValue } = this.usable(who, kekId, [0x20, 0x10], "process",
      ["Symmetric Key", "Private Key"], "Illegal Operation");
    const given = child(eki, "Cryptographic Parameters");
    if (given === undefined && this.paramInstances(kek).length === 0) {
      throw new KmsError("Item Not Found", "the wrapping key has no Cryptographic Parameters");
    }
    const p = { ...(this.paramInstances(kek)[0] ?? {}), ...readParams(given) };
    const noEncoding = enumOfItem(child(kwd, "Encoding Option"), "Encoding Option") === "No Encoding";
    const kv = child(block, "Key Value")!;
    const cipher = noEncoding ? child(kv, "Key Material")?.value as Buffer : kv.value as Buffer;
    if (!Buffer.isBuffer(cipher)) throw new KmsError("Invalid Field", "the wrapped Key Value holds no wrapped bytes");
    const plain = kek.type === "Private Key"
      ? rsaDecrypt(privateKeyOf(keyMaterial(kekValue)), p, cipher)
      : unwrapAes(keyMaterial(kekValue).bytes, p.blockCipherMode ?? "NISTKeyWrap", cipher);
    let plainKv: Item;
    if (noEncoding) {
      plainKv = k.struct("Key Value", [k.bytes("Key Material", plain),
        ...(kv.value as Item[]).filter((c) => c.tag !== tagOf("Key Material"))]);
    } else {
      try {
        plainKv = decode(plain);
      } catch {
        throw new KmsError("Cryptographic Failure", "the unwrapped Key Value is not TTLV");
      }
    }
    const newBlock = k.struct("Key Block", (block.value as Item[])
      .filter((c) => c.tag !== tagOf("Key Wrapping Data"))
      .map((c) => c.tag === tagOf("Key Value") ? plainKv : c));
    return { ...value, value: (value.value as Item[]).map((c) => c.tag === tagOf("Key Block") ? newBlock : c) } as Item;
  }

  /**
   * Get Attributes (4.12). "If a specified attribute has multiple
   * instances, then all instances are returned. If a specified attribute does
   * not exist ... it SHALL NOT be present". With no names, all attributes.
   */
  getAttributes(who: Who, id: string, names?: string[]): Attribute[] {
    const o = this.find(who, id, "getAttributes");
    if (names !== undefined) {
      if (new Set(names).size !== names.length) {
        // "The same Attribute Name is present more than once": Invalid Message (11.13).
        throw new KmsError("Invalid Message", "the same attribute name SHALL NOT be present more than once");
      }
    }
    return o.attrs
      .filter((a) => names === undefined || names.includes(a.name))
      .map((a) => ({ name: a.name, index: a.index, value: a.value }));
  }

  /** Get Attribute List (4.13): the names of the attributes an object has. */
  getAttributeList(who: Who, id: string): string[] {
    return [...new Set(this.find(who, id, "getAttributeList").attrs.map((a) => a.name))];
  }

  // -------------------------------------------------------------------------
  // Changing attributes

  private checkClientChange(o: ManagedObject, name: string, how: "modifiableByClient" | "deletableByClient"): void {
    const r = rules(name);
    if (r === undefined) throw new KmsError("Invalid Field", `${name} is not an attribute`);
    const text = r[how];
    if (!yes(text) || SERVER_SET.has(name)) {
      throw new KmsError("Permission Denied",
        `${name} is not ${how === "deletableByClient" ? "deletable" : "modifiable"} by a client`);
    }
    const states = statesAllowed(text);
    if (states !== undefined && !states.includes(this.state(o))) {
      throw new KmsError("Permission Denied",
        `${name} may be changed only in the ${states.join(" or ")} state, and the object is ${this.state(o)}`);
    }
  }

  /**
   * Add Attribute (4.14). "Existing attribute values SHALL only be changed by the
   * Modify Attribute operation. Read-Only attributes SHALL NOT be added".
   */
  addAttribute(who: Who, id: string, value: Item, name = nameOf(value.tag)): void {
    const o = this.find(who, id, "addAttribute");
    const r = rules(name);
    if (r === undefined) throw new KmsError("Permission Denied", `${name} is not an attribute`);
    refuseServerCustom(name, "Permission Denied");
    checkCustomValue(name, value);
    if (SERVER_SET.has(name) || !yes(r.modifiableByClient)) {
      throw new KmsError("Permission Denied", `${name} is not set by a client`);
    }
    const states = statesAllowed(r.modifiableByClient);
    if (states !== undefined && !states.includes(this.state(o))) {
      throw new KmsError("Permission Denied",
        `${name} may be set only in the ${states.join(" or ")} state, and the object is ${this.state(o)}`);
    }
    if (!multiInstance(name) && this.attr(o, name) !== undefined) {
      throw new KmsError("Illegal Operation", `the object already has ${name}`);
    }
    if (name === "Name") this.checkNamesFree([value], o, "Illegal Operation");
    if (o.attrs.some((a) => a.name === name && same(a.value, value))) {
      // An instance already holding the value is not added again.
      return;
    }
    this.pushAttr(o, value, name);
    this.afterChange(o, name);
  }

  /**
   * Modify Attribute (4.15). Modifies one instance, named by the value it holds where one is
   * given; the dispatcher names it by its Attribute Index (4.15).
   */
  modifyAttribute(who: Who, id: string, value: Item, current?: Item, name = nameOf(value.tag)): void {
    const o = this.find(who, id, "modifyAttribute");
    refuseServerCustom(name, "Permission Denied");
    checkCustomValue(name, value);
    if (current !== undefined && current.tag !== value.tag) {
      throw new KmsError("Invalid Field", "the Current Attribute and New Attribute name different attributes");
    }
    const instances = o.attrs.filter((a) => a.name === name);
    if (instances.length === 0) throw new KmsError("Invalid Field", `the object has no ${name}`);
    this.checkClientChange(o, name, "modifiableByClient");
    let target: Instance | undefined;
    if (current === undefined) {
      if (instances.length > 1) {
        throw new KmsError("Invalid Field",
          `the object has ${instances.length} instances of ${name}; name the one to modify`);
      }
      target = instances[0];
    } else {
      target = instances.find((a) => same(a.value, current));
      if (target === undefined) throw new KmsError("Item Not Found", `no such instance of ${name}`);
    }
    if (name === "Name") this.checkNamesFree([value], o, "Illegal Operation");
    target.value = value;
    this.dirty.add(o);
    this.afterChange(o, name);
  }

  /**
   * Delete Attribute (4.16). "Attributes that are always REQUIRED to have a value
   * SHALL never be deleted by this operation." Deletes the instance holding a value,
   * or every instance of a name; the dispatcher names one instance by its index.
   */
  deleteAttribute(who: Who, id: string, target: { current: Item; name?: string } | { name: string }): void {
    const o = this.find(who, id, "deleteAttribute");
    const name = target.name ?? nameOf((target as { current: Item }).current.tag);
    refuseServerCustom(name, "Permission Denied");
    const r = rules(name);
    if (r === undefined) throw new KmsError("Item Not Found", `${name} is not an attribute`);
    if (yes(r.alwaysHasValue)) throw new KmsError("Permission Denied", `${name} always has a value`);
    const instances = o.attrs.filter((a) => a.name === name);
    if (instances.length === 0) throw new KmsError("Item Not Found", `the object has no ${name}`);
    this.checkClientChange(o, name, "deletableByClient");
    if ("current" in target) {
      const hit = instances.find((a) => same(a.value, target.current));
      if (hit === undefined) throw new KmsError("Item Not Found", `no such instance of ${name}`);
      o.attrs = o.attrs.filter((a) => a !== hit);
      this.dirty.add(o);
    } else {
      this.removeAttr(o, name);
    }
    this.touch(o);
  }

  /** The effects of a client's change beyond the attribute itself. */
  private afterChange(o: ManagedObject, name: string): void {
    // 3.49 and 3.51: the history of Sensitive and Extractable.
    if (name === "Sensitive" && this.attr(o, "Sensitive")?.value === false) {
      this.setAttr(o, k.bool("Always Sensitive", false));
    }
    if (name === "Extractable" && this.attr(o, "Extractable")?.value === true) {
      this.setAttr(o, k.bool("Never Extractable", false));
    }
    // Transitions 4 and 6: a Modify Attribute of the Activation or Deactivation
    // Date to the past or the present.
    this.advance(o);
    this.touch(o);
  }

  // -------------------------------------------------------------------------
  // Lifecycle

  /** Activate (4.19): "SHALL only be performed on an object in the Pre-Active state". */
  activate(who: Who, id: string): void {
    const o = this.find(who, id, "activate");
    if (this.state(o) !== "Pre-Active") {
      throw new KmsError("Permission Denied", `the object is ${this.state(o)}, not Pre-Active`);
    }
    // "The server SHALL set the Activation Date to the time the Activate
    // operation is received."
    this.setAttr(o, dateItem("Activation Date", this.now()));
    this.setState(o, "Active");
    this.touch(o);
  }

  /**
   * Revoke (4.20). A reason of Key Compromise or CA Compromise places the
   * object in Compromised (transitions 3, 5, 8, and 10 from Destroyed);
   * another reason places an Active object in Deactivated (transition 6).
   */
  revoke(who: Who, id: string, code: string, opts: { message?: string; compromiseOccurrence?: number } = {}): void {
    const o = this.find(who, id, "revoke");
    if (KMIP_ENUM["Revocation Reason Code"][code] === undefined) {
      throw new KmsError("Invalid Field", `${code} is not a Revocation Reason Code`);
    }
    const compromise = code === "Key Compromise" || code === "CA Compromise";
    if (!compromise && opts.compromiseOccurrence !== undefined) {
      // "SHALL NOT be specified for other Revocation Reason enumerations."
      throw new KmsError("Invalid Field", "a Compromise Occurrence Date is given only for a compromise");
    }
    const from = this.state(o);
    const now = this.now();
    let to: State;
    if (compromise) {
      const next: Partial<Record<State, State>> = {
        "Pre-Active": "Compromised", "Active": "Compromised", "Deactivated": "Compromised",
        "Destroyed": "Destroyed Compromised",
      };
      const n = next[from];
      if (n === undefined) throw new KmsError("Illegal Operation", `a ${from} object is not revoked again`);
      to = n;
      this.setAttr(o, dateItem("Compromise Date", now));
      // "if a value is not provided ... SHOULD be set to the Initial Date".
      this.setAttr(o, dateItem("Compromise Occurrence Date",
        opts.compromiseOccurrence ?? msOf(this.attr(o, "Initial Date")!)));
    } else {
      if (from !== "Active") {
        // Only transition 6 is caused by a Revoke for another reason, and
        // "Only the transitions described above are permitted."
        throw new KmsError("Illegal Operation",
          `a Revoke for ${code} deactivates an Active object, and this one is ${from}`);
      }
      to = "Deactivated";
      this.setAttr(o, dateItem("Deactivation Date", now));
    }
    this.setAttr(o, k.struct("Revocation Reason", [
      k.enum("Revocation Reason Code", "Revocation Reason Code", code),
      ...(opts.message === undefined ? [] : [k.text("Revocation Message", opts.message)]),
    ]));
    this.setState(o, to);
    this.touch(o);
  }

  /**
   * Destroy (4.21): the key material is destroyed and the metadata kept.
   * 4.21 says "Cryptographic Objects MAY only be destroyed if they are in either
   * Pre-Active or Deactivated state"; transition 9 of 3.22 is a Destroy of a
   * Compromised object, and 11.22 fails a Destroy of an object "not in
   * Pre-Active, Deactivated or Compromised state". This core follows 3.22 and 11.22.
   */
  destroy(who: Who, id: string): void {
    const o = this.find(who, id, "destroy");
    const from = this.state(o);
    const next: Partial<Record<State, State>> = {
      "Pre-Active": "Destroyed", "Deactivated": "Destroyed", "Compromised": "Destroyed Compromised",
    };
    if (from === "Destroyed" || from === "Destroyed Compromised") {
      throw new KmsError("Permission Denied", "the object is already destroyed");
    }
    const to = next[from];
    if (to === undefined) throw new KmsError("Permission Denied", `a ${from} object is not destroyed`);
    o.value = undefined;
    this.dirty.add(o);
    this.setAttr(o, dateItem("Destroy Date", this.now()));
    this.setState(o, to);
    this.touch(o);
  }

  // -------------------------------------------------------------------------
  // Cryptographic operations (phase 4)

  /**
   * The object a cryptographic operation uses, checked: of a type the
   * operation takes, holding key material, its Cryptographic Usage Mask
   * permitting the purpose, and in a state and within dates that permit it.
   *
   * Applying protection (encrypt, sign, MAC, wrap) needs an Active object:
   * a Deactivated or Compromised object "SHALL NOT be used for applying
   * cryptographic protection" (3.22), nor one past its Protect Stop Date.
   * Processing protected data (decrypt, verify) is permitted to an Active or
   * Deactivated object, from its Process Start Date. 3.22 says a Deactivated
   * object "SHOULD only be used to process ... under extraordinary
   * circumstances"; a Compromised one only "in a client that is trusted to use
   * managed objects that have been compromised", which no client of this
   * server is (see NOTES-on-kmip.md).
   */
  private usable(who: Who, id: string, bits: number | number[], purpose: "apply" | "process", types: ObjectType[],
    wrongType = "Permission Denied"): { o: ManagedObject; value: Item } {
    const o = this.find(who, id, "usable");
    if (!types.includes(o.type)) {
      // "Object specified is not able to be used for ..." (11.30 to 11.35);
      // for a wrapping key, "exists, but it is not a key": Illegal Operation (11.12).
      throw new KmsError(wrongType, `a ${o.type} is not used for this operation`);
    }
    if (o.value === undefined) throw new KmsError("Key Value Not Present", "the object's key material was destroyed");
    const mask = this.attr(o, "Cryptographic Usage Mask")?.value as number | undefined;
    // 1.4 defines no Unrestricted bit; the value 0x00200000 is not one of its masks.
    const UNRESTRICTED = 0;
    const permitted = (Array.isArray(bits) ? bits : [bits]).some((bit) => (mask ?? 0) & bit);
    if (mask === undefined || ((mask & UNRESTRICTED) === 0 && !permitted)) {
      throw new KmsError("Permission Denied",
        "the object's Cryptographic Usage Mask does not permit this operation");
    }
    const state = this.state(o);
    const now = this.now();
    if (purpose === "apply") {
      if (state !== "Active") {
        throw new KmsError("Permission Denied", `a ${state} object is not used to apply protection`);
      }
      const stop = this.attr(o, "Protect Stop Date");
      if (stop !== undefined && msOf(stop) < now) {
        throw new KmsError("Permission Denied", "the object's Protect Stop Date has passed");
      }
    } else {
      if (state !== "Active" && state !== "Deactivated") {
        throw new KmsError("Permission Denied", `a ${state} object is not used to process protected data`);
      }
      const start = this.attr(o, "Process Start Date");
      if (start !== undefined && msOf(start) > now) {
        throw new KmsError("Permission Denied", "the object's Process Start Date has not been reached");
      }
    }
    return { o, value: this.plainValue(who, o) };
  }

  /** The instances of an object's Cryptographic Parameters attribute. */
  private paramInstances(o: ManagedObject): CryptoParams[] {
    return o.attrs.filter((a) => a.name === "Cryptographic Parameters").map((a) => readParams(a.value));
  }

  /**
   * The parameters an operation uses: the request's over the object's. "If
   * there are no Cryptographic Parameters associated with the Managed
   * Cryptographic Object and the algorithm requires parameters then the
   * operation SHALL return with a Result Status of Operation Failed."
   */
  private paramsFor(o: ManagedObject, given: CryptoParams | undefined): CryptoParams {
    return mergeParams(this.paramInstances(o)[0] ?? {}, given ?? {});
  }

  private algorithmOf(o: ManagedObject): string | undefined {
    const a = this.attr(o, "Cryptographic Algorithm");
    return a?.type === TYPE.Enumeration ? enumName("Cryptographic Algorithm", a.value) : undefined;
  }

  /** Encrypt (4.29), single-part. */
  encrypt(who: Who, id: string, req: { params?: CryptoParams; data: Buffer; iv?: Buffer; aad?: Buffer }): CipherResult {
    const { o, value } = this.usable(who, id, 0x04, "apply", ["Symmetric Key", "Public Key"]);
    const p = this.paramsFor(o, req.params);
    if (o.type === "Public Key") return { data: rsaEncrypt(publicKeyOf(value, o.type), p, req.data) };
    if (this.algorithmOf(o) !== "AES") {
      throw new KmsError("Feature Not Supported", `encryption with ${this.algorithmOf(o)} keys is not supported`);
    }
    return aesEncrypt(keyMaterial(value).bytes, p, req.data, { iv: req.iv, aad: req.aad });
  }

  /** Decrypt (4.30), single-part. */
  decrypt(who: Who, id: string, req: { params?: CryptoParams; data: Buffer; iv?: Buffer; aad?: Buffer; tag?: Buffer }): Buffer {
    const { o, value } = this.usable(who, id, 0x08, "process", ["Symmetric Key", "Private Key"]);
    const p = this.paramsFor(o, req.params);
    if (o.type === "Private Key") return rsaDecrypt(privateKeyOf(keyMaterial(value)), p, req.data);
    if (this.algorithmOf(o) !== "AES") {
      throw new KmsError("Feature Not Supported", `decryption with ${this.algorithmOf(o)} keys is not supported`);
    }
    return aesDecrypt(keyMaterial(value).bytes, p, req.data, { iv: req.iv, aad: req.aad, tag: req.tag });
  }

  /** Sign (4.31), single-part, over Data. */
  sign(who: Who, id: string, req: { params?: CryptoParams; data: Buffer }): Buffer {
    const { o, value } = this.usable(who, id, 0x01, "apply", ["Private Key"]);
    return signData(privateKeyOf(keyMaterial(value)), this.paramsFor(o, req.params), req.data);
  }

  /** Signature Verify (4.32), single-part: whether the signature is valid. */
  signatureVerify(who: Who, id: string, req: { params?: CryptoParams; data: Buffer; signature: Buffer }): boolean {
    const { o, value } = this.usable(who, id, 0x02, "process", ["Public Key", "Certificate"]);
    return verifyData(publicKeyOf(value, o.type), this.paramsFor(o, req.params), req.data, req.signature);
  }

  /** MAC (4.33), single-part. */
  mac(who: Who, id: string, req: { params?: CryptoParams; data: Buffer }): Buffer {
    const { o, value } = this.usable(who, id, 0x80, "apply", ["Symmetric Key"]);
    const p = this.paramsFor(o, req.params);
    return mac(keyMaterial(value).bytes, p.cryptographicAlgorithm ?? this.algorithmOf(o), req.data);
  }

  /** MAC Verify (4.34), single-part: whether the MAC is valid. */
  macVerify(who: Who, id: string, req: { params?: CryptoParams; data: Buffer; macData: Buffer }): boolean {
    const { o, value } = this.usable(who, id, 0x100, "process", ["Symmetric Key"]);
    const p = this.paramsFor(o, req.params);
    return macMatches(mac(keyMaterial(value).bytes, p.cryptographicAlgorithm ?? this.algorithmOf(o), req.data), req.macData);
  }

  /**
   * The value of an object with its Key Value wrapped, as a Get with a Key
   * Wrapping Specification returns it (2.1.5 and 2.1.6).
   */
  private wrap(who: Who, o: ManagedObject, spec: WrappingSpecification): Item {
    if (spec.method !== "Encrypt") {
      throw new KmsError("Feature Not Supported", `the wrapping method ${spec.method} is not supported`);
    }
    if (spec.encryptionKey === undefined) {
      throw new KmsError("Missing Data", "wrapping by encryption names an Encryption Key Information");
    }
    if ((spec.attributeNames ?? []).length > 0) {
      throw new KmsError("Feature Not Supported", "attributes are not wrapped with the key material");
    }
    const plainObject = this.plainValue(who, o);
    const block = child(plainObject, "Key Block");
    if (block === undefined) throw new KmsError("Illegal Operation", `a ${o.type} holds no Key Block to wrap`);
    const kv = child(block, "Key Value")!;
    const { o: kek, value: kekValue } = this.usable(who, spec.encryptionKey.id, 0x10, "apply",
      ["Symmetric Key", "Public Key"], "Illegal Operation");
    // "If Cryptographic Parameters are specified in the Encryption Key Information
    // ... the server SHALL verify that they match one of the instances of the
    // Cryptographic Parameters attribute of the corresponding key. If
    // Cryptographic Parameters are omitted, then the server SHALL use the
    // Cryptographic Parameters attribute with the lowest Attribute Index of the
    // corresponding key" (2.1.6). Where none exists or none matches: "Cryptographic
    // Parameters associated with the object do not exist or do not match": Item
    // Not Found (11.12).
    const instances = this.paramInstances(kek);
    let p: CryptoParams;
    if (spec.encryptionKey.params !== undefined) {
      const given = spec.encryptionKey.params;
      const hit = instances.find((i) => paramsMatch(given, i));
      if (hit === undefined) {
        throw new KmsError("Item Not Found",
          "the Cryptographic Parameters given match no instance of the wrapping key's attribute");
      }
      p = { ...hit, ...given };
    } else {
      if (instances.length === 0) throw new KmsError("Item Not Found", "the wrapping key has no Cryptographic Parameters");
      p = instances[0];
    }
    // "If No Encoding is specified, then the Key Value structure SHALL NOT
    // contain any attributes"; otherwise "the wrapped Key Value structure SHALL
    // be TTLV encoded" (2.1.5).
    const noEncoding = spec.encodingOption === "No Encoding";
    let plain: Buffer;
    if (noEncoding) {
      const km = child(kv, "Key Material");
      // A Key Value holds its attributes as Attribute structures (2.1.4, Table 8).
      if (km?.type !== TYPE.ByteString || child(kv, "Attribute") !== undefined) {
        throw new KmsError("Encoding Option Error", "No Encoding wraps Key Material that is a Byte String with no attributes");
      }
      plain = km.value;
    } else {
      plain = encode(kv);
    }
    let wrapped: Buffer;
    if (kek.type === "Public Key") {
      wrapped = rsaEncrypt(publicKeyOf(kekValue, kek.type), p, plain);
    } else {
      if (p.blockCipherMode !== "NISTKeyWrap" && p.blockCipherMode !== "AESKeyWrapPadding") {
        throw new KmsError("Invalid Field",
          "a symmetric wrapping key wraps by NISTKeyWrap or AESKeyWrapPadding here");
      }
      wrapped = wrapAes(keyMaterial(kekValue).bytes, p.blockCipherMode, plain);
    }
    const rest = (block.value as Item[]).filter((c) =>
      c.tag !== tagOf("Key Value") && c.tag !== tagOf("Key Wrapping Data"));
    const format = rest.filter((c) => c.tag === tagOf("Key Format Type") || c.tag === tagOf("Key Compression Type"));
    const after = rest.filter((c) => !format.includes(c));
    // 2.1.5: No Encoding is "the wrapped un-encoded value of the Byte String Key
    // Material field in the Key Value structure", so the Key Value stays a
    // structure; TTLV Encoding is "the wrapped TTLV-encoded Key Value structure",
    // so the Key Value becomes that Byte String.
    const newBlock = k.struct("Key Block", [
      ...format,
      noEncoding ? k.struct("Key Value", [k.bytes("Key Material", wrapped)]) : k.bytes("Key Value", wrapped),
      ...after,
      k.struct("Key Wrapping Data", [
        k.enum("Wrapping Method", "Wrapping Method", "Encrypt"),
        k.struct("Encryption Key Information", [
          k.text("Unique Identifier", kek.id),
          ...(spec.encryptionKey.params === undefined ? [] : [writeParams(spec.encryptionKey.params)]),
        ]),
        ...(spec.encodingOption === undefined ? [] : [k.enum("Encoding Option", "Encoding Option", spec.encodingOption)]),
      ]),
    ]);
    return { ...plainObject, value: (plainObject.value as Item[]).map((c) => c.tag === tagOf("Key Block") ? newBlock : c) } as Item;
  }

  // -------------------------------------------------------------------------
  // Replacement

  /** The attributes Tables 304 and 309 say are not copied to a replacement. */
  private static readonly NOT_COPIED = new Set([
    "Unique Identifier", "Initial Date", "Destroy Date", "Compromise Occurrence Date",
    "Compromise Date", "Revocation Reason", "Name", "State", "Digest", "Link",
    "Last Change Date", "Random Number Generator", "Original Creation Date",
    "Always Sensitive", "Never Extractable", "Object Type",
  ]);

  private replacementAttrs(old: ManagedObject, offsetSeconds?: number, supplied: Attribute[] = []): Attribute[] {
    const dates = ["Activation Date", "Process Start Date", "Protect Stop Date", "Deactivation Date"];
    const out = old.attrs
      .filter((a) => !KmsCore.NOT_COPIED.has(a.name) && !dates.includes(a.name))
      .map((a) => ({ name: a.name, value: a.value }));
    const now = this.now();
    const d = (n: string) => this.attr(old, n);
    if (offsetSeconds === undefined) {
      // "If no Offset is specified, the Activation Date, Process Start Date,
      // Protect Stop Date and Deactivation Date values are copied".
      for (const n of dates) if (d(n) !== undefined) out.push({ name: n, value: d(n)! });
    } else {
      // Table 172: AT2 = IT2 + Offset, and each other date moves by AT2 - AT1.
      const at2 = now + offsetSeconds * 1000;
      out.push({ name: "Activation Date", value: dateItem("Activation Date", at2) });
      const at1 = d("Activation Date");
      if (at1 !== undefined) {
        for (const n of ["Process Start Date", "Protect Stop Date", "Deactivation Date"]) {
          if (d(n) !== undefined) out.push({ name: n, value: dateItem(n, msOf(d(n)!) + (at2 - msOf(at1))) });
        }
      }
    }
    // Attributes the request gives ("Specifies desired object attributes")
    // replace those copied under the same name.
    const given = new Set(supplied.map((a) => a.name));
    return [...out.filter((a) => !given.has(a.name)), ...supplied];
  }

  /** Moves the names of an object to its replacement: "all name attributes are removed from the existing key". */
  private moveNames(from: ManagedObject, to: ManagedObject): void {
    for (const n of from.attrs.filter((a) => a.name === "Name")) this.pushAttr(to, n.value);
    this.removeAttr(from, "Name");
  }

  /** Re-key (4.4): a replacement for a symmetric key. */
  rekey(who: Who, id: string, opts: { offsetSeconds?: number; attrs?: Attribute[] } = {}): string {
    const old = this.find(who, id, "rekey");
    this.checkOffset(old, opts.offsetSeconds, opts.attrs ?? []);
    if (old.type !== "Symmetric Key") throw new KmsError("Permission Denied", "Re-key replaces a Symmetric Key");
    if (old.value === undefined) throw new KmsError("Key Value Not Present", "the key's material was destroyed");
    const algorithm = enumOfItem(this.attr(old, "Cryptographic Algorithm"), "Cryptographic Algorithm")!;
    const length = this.attr(old, "Cryptographic Length")!.value as number;
    const value = k.struct("Symmetric Key", [keyBlock("Raw", randomBytes(length / 8), algorithm, length)]);
    const neu = this.build(who, "Symmetric Key", this.replacementAttrs(old, opts.offsetSeconds, opts.attrs), value);
    this.linkReplacement(old, neu);
    this.add(neu);
    return neu.id;
  }

  /**
   * The Offset rules of 11.5 and 11.6: an Offset "is not permitted to be
   * specified at the same time as any of the Activation Date, Process Start Date,
   * Protect Stop Date, or Deactivation Date attributes" (Invalid Message), and
   * "An offset cannot be used to specify new Process Start, Protect Stop and/or
   * Deactivation Date attribute values since no Activation Date has been
   * specified for the existing key" (Illegal Operation).
   */
  private checkOffset(old: ManagedObject, offsetSeconds: number | undefined, supplied: Attribute[]): void {
    if (offsetSeconds === undefined) return;
    const dates = ["Activation Date", "Process Start Date", "Protect Stop Date", "Deactivation Date"];
    if (supplied.some((a) => dates.includes(a.name))) {
      throw new KmsError("Invalid Message", "an Offset is not given with a date attribute");
    }
    if (this.attr(old, "Activation Date") === undefined && dates.slice(1).some((n) => this.attr(old, n) !== undefined)) {
      throw new KmsError("Illegal Operation", "the existing key has no Activation Date from which to offset its dates");
    }
  }

  /** Re-key Key Pair (4.5), RSA. */
  rekeyKeyPair(who: Who, privateKeyId: string, opts: { offsetSeconds?: number } = {}):
    { privateKey: string; publicKey: string } {
    const oldPriv = this.find(who, privateKeyId, "rekeyKeyPair");
    this.checkOffset(oldPriv, opts.offsetSeconds, []);
    if (oldPriv.type !== "Private Key") throw new KmsError("Permission Denied", "Re-key Key Pair names a Private Key");
    const pubLink = oldPriv.attrs.find((a) => a.name === "Link" &&
      enumOfItem(child(a.value, "Link Type"), "Link Type") === "Public Key Link");
    const oldPub = this.find(who, String(child(pubLink?.value ?? k.struct("Link", []), "Linked Object Identifier")?.value), "rekeyKeyPair");
    const length = this.attr(oldPriv, "Cryptographic Length")!.value as number;
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: length,
      privateKeyEncoding: { type: "pkcs1", format: "der" },
      publicKeyEncoding: { type: "pkcs1", format: "der" },
    }) as unknown as { privateKey: Buffer; publicKey: Buffer };
    const np = this.build(who, "Private Key", this.replacementAttrs(oldPriv, opts.offsetSeconds),
      k.struct("Private Key", [keyBlock("PKCS#1", privateKey, "RSA", length)]));
    const nu = this.build(who, "Public Key", this.replacementAttrs(oldPub, opts.offsetSeconds),
      k.struct("Public Key", [keyBlock("PKCS#1", publicKey, "RSA", length)]));
    this.pushAttr(np, link("Public Key Link", nu.id));
    this.pushAttr(nu, link("Private Key Link", np.id));
    this.linkReplacement(oldPriv, np);
    this.linkReplacement(oldPub, nu);
    this.add(np);
    this.add(nu);
    return { privateKey: np.id, publicKey: nu.id };
  }

  private linkReplacement(old: ManagedObject, neu: ManagedObject): void {
    this.moveNames(old, neu);
    // "For the existing key, the server SHALL create a Link attribute of Link
    // Type Replacement Object pointing to the replacement key. For the
    // replacement key ... Link Type Replaced Key pointing to the existing key."
    this.pushAttr(old, link("Replacement Object Link", neu.id));
    this.pushAttr(neu, link("Replaced Object Link", old.id));
    this.touch(old);
  }
}

function link(type: string, id: string): Item {
  return k.struct("Link", [k.enum("Link Type", "Link Type", type), k.text("Linked Object Identifier", id)]);
}
