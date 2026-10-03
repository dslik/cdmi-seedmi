// Prefixes: which identity holds which part of the Name space.
//
// A client claims a prefix by registering a managed object under it where no
// other identity holds it, and holds it thereafter. The key management server
// is not reconfigured when a client begins using a new prefix. This is the
// only rule of access this program adds to KMIP, and it is its own: it knows
// nothing of CDMI, of scopes or of entitlement, which belong to the clients.
//
// The prefix of a Name is everything up to and including its last "/", so
// "tenant-a/backup-key" claims "tenant-a/", and "tenant-a/2026/key" claims
// "tenant-a/2026/". A claim encloses what lies beneath it: an identity
// holding "tenant-a/" holds "tenant-a/2026/" too, and a second identity may
// neither claim within it nor claim a prefix that would enclose it. A Name
// with no "/" claims nothing, being governed by the ownership of its object
// alone.
//
// A shared prefix is one the configuration names as claimed by no one: any
// identity may register beneath it, and each object there belongs to the
// identity that created it. A deployment names one where several clients
// must keep objects of the same form side by side, as CDMI servers keep their
// binding keys under "cdmi_binding/".

import { KmsError } from "./kms-core-error.ts";
import { KmsCore, type CoreOptions, type ObjectIdentity, type Who } from "./kms-core.ts";
import type { Attribute } from "./kmip-message.ts";
import { type Item, nameOf } from "./kmip-ttlv.ts";

/** Where the claims are kept, which is the store's own table of server values. */
export interface ClaimStorage {
  meta(key: string): string | undefined;
  setMeta(key: string, value: string): void;
}

const KEY = "prefixes";

/** The prefix a Name claims, or undefined where it claims none. */
export function prefixOf(name: string): string | undefined {
  const at = name.lastIndexOf("/");
  return at < 0 ? undefined : name.slice(0, at + 1);
}

export class Prefixes {
  private readonly held: Map<string, string>;
  private readonly storage: ClaimStorage;
  private readonly shared: string[];

  constructor(storage: ClaimStorage, shared: string[] = []) {
    this.storage = storage;
    this.shared = shared;
    const recorded = storage.meta(KEY);
    this.held = new Map(recorded === undefined ? [] : Object.entries(JSON.parse(recorded) as Record<string, string>));
  }

  /** Whether a prefix lies within one the configuration shares. */
  isShared(prefix: string): boolean {
    return this.shared.some((s) => prefix.startsWith(s));
  }

  /** The identity holding a prefix, by the claim that encloses it, or undefined. */
  holderOf(prefix: string): string | undefined {
    let best: string | undefined;
    let bestLength = -1;
    for (const [p, who] of this.held) {
      if (prefix.startsWith(p) && p.length > bestLength) {
        best = who;
        bestLength = p.length;
      }
    }
    return best;
  }

  /**
   * Refuses an identity a Name it may not use: one within a prefix another
   * identity holds, or one whose prefix would enclose another's. The refusal
   * is Permission Denied, which is the result reason KMIP gives for an
   * operation the requester is not permitted to perform, and it says whose
   * prefix it is no more than that it is not the requester's.
   */
  check(who: string, name: string): void {
    const prefix = prefixOf(name);
    if (prefix === undefined || this.isShared(prefix)) return;
    const holder = this.holderOf(prefix);
    if (holder !== undefined && holder !== who) {
      throw new KmsError("Permission Denied", `the prefix of ${JSON.stringify(name)} is held by another client`);
    }
    for (const [p, other] of this.held) {
      if (other !== who && p.startsWith(prefix) && p !== prefix) {
        throw new KmsError("Permission Denied",
          `the prefix of ${JSON.stringify(name)} would enclose one another client holds`);
      }
    }
  }

  /** Records the claim a Name makes, where it makes one this identity does not already hold. */
  claim(who: string, name: string): void {
    const prefix = prefixOf(name);
    if (prefix === undefined || this.isShared(prefix)) return;
    if (this.holderOf(prefix) === who) return;
    this.held.set(prefix, who);
    this.storage.setMeta(KEY, JSON.stringify(Object.fromEntries(this.held)));
  }

  /** The prefixes an identity holds, for an operator. */
  heldBy(who: string): string[] {
    return [...this.held].filter(([, w]) => w === who).map(([p]) => p).sort();
  }
}

// ---------------------------------------------------------------------------
// Admission: what an identity may do beneath a prefix it does not hold

/**
 * The degrees of admission, each including the one before. They are the
 * operator's, set in the configuration file, and they add to the ownership
 * rule: the owner of an object may always do everything with it.
 */
export const DEGREES = ["none", "discover", "use", "read", "write"] as const;
export type Degree = typeof DEGREES[number];

/** The degree each operation needs. Destroy needs the owner, at every degree. */
const NEEDS: Record<string, Degree | "owner"> = {
  locate: "discover",
  getAttributes: "discover",
  getAttributeList: "discover",
  // The cryptographic operations performed in place, which a key that never
  // leaves the server needs: Sign, Verify, Encrypt, Decrypt, MAC, Derive Key.
  usable: "use",
  get: "read",
  addAttribute: "write",
  modifyAttribute: "write",
  deleteAttribute: "write",
  activate: "write",
  revoke: "write",
  rekey: "write",
  rekeyKeyPair: "write",
  register: "write",
  // The one operation that cannot be undone stays with the owner.
  destroy: "owner",
};

/**
 * One [[admit]] table of the configuration. It names what it admits an identity
 * to by a prefix of the Name, by an Object Group, or by both; at least one, and
 * where both are given both have to match, which is how a deployment says "the
 * objects of *this* group kept by *that* client".
 */
export interface Admission {
  prefix?: string;
  /**
   * An Object Group the object is in. A grant keyed this way is what lets a
   * deployment hand out one kind of a client's material and not the rest: the
   * kinds may share a Name prefix, as a domain controller's verifiers, Kerberos
   * keys and S3 secrets do, and then the group is the only thing that tells them
   * apart (seedmi-dc's DESIGN-admin.md §4a).
   */
  group?: string;
  /** An identity, or "*" for every authenticated client. */
  identity: string;
  degree: Degree;
}

/**
 * The degree an identity is admitted to for an object, from the configuration.
 * A table with neither a prefix nor a group admits nothing: the configuration
 * reader refuses one, and this answers "none" rather than "everything" in case
 * one reaches here another way.
 */
export function degreeFor(admissions: Admission[], who: string, of: ObjectIdentity): Degree {
  let best: Degree = "none";
  for (const a of admissions) {
    if (a.prefix === undefined && a.group === undefined) continue;
    if (a.prefix !== undefined && !(of.name ?? "\u0000").startsWith(a.prefix)) continue;
    if (a.group !== undefined && !of.groups.includes(a.group)) continue;
    if (a.identity !== "*" && a.identity !== who) continue;
    if (DEGREES.indexOf(a.degree) > DEGREES.indexOf(best)) best = a.degree;
  }
  return best;
}

/** Whether a degree suffices for an operation. */
export function permits(degree: Degree, operation: string): boolean {
  const need = NEEDS[operation];
  // An operation this table does not name is the owner's alone, so an
  // operation added to the core later is closed until it is placed here.
  if (need === undefined || need === "owner") return false;
  return DEGREES.indexOf(degree) >= DEGREES.indexOf(need);
}

// ---------------------------------------------------------------------------
// The core, with the claims enforced


/** The Name values a list of attributes carries. */
function namesIn(attrs: Attribute[]): string[] {
  const out: string[] = [];
  for (const a of attrs) {
    if (a.name !== "Name") continue;
    const value = (a.value.value as Item[] | undefined)?.find((i) => nameTag(i) === "Name Value");
    if (value !== undefined && typeof value.value === "string") out.push(value.value);
  }
  return out;
}

/** The Name Value of a Name attribute's value, where it is one. */
function nameValueOf(value: Item): string | undefined {
  const inner = (value.value as Item[] | undefined)?.find((i) => nameTag(i) === "Name Value");
  return inner !== undefined && typeof inner.value === "string" ? inner.value : undefined;
}

const nameTag = (i: Item): string => nameOf(i.tag);

/**
 * The core of kms-core.ts with the prefix claims enforced. Every operation
 * that can give a managed object a Name checks it first and records the claim
 * after it succeeds: Register, Create, Create Key Pair, and the Add Attribute
 * and Modify Attribute that would rename an object into another's prefix.
 * Every other operation is the core's own, whose rule that an object belongs
 * to the identity that created it already keeps one client from another's
 * objects.
 */
export class PrefixedCore extends KmsCore {
  readonly prefixes: Prefixes;
  readonly admissions: Admission[];

  constructor(prefixes: Prefixes, opts: CoreOptions = {}, admissions: Admission[] = []) {
    super(opts);
    this.prefixes = prefixes;
    this.admissions = admissions;
  }

  /**
   * The owner may do everything; another identity may do what the degree it
   * is admitted to beneath the object's Name permits, and nothing else.
   */
  protected override mayAct(who: Who, owner: Who, of: ObjectIdentity, operation: string): boolean {
    if (owner === who) return true;
    return permits(degreeFor(this.admissions, who, of), operation);
  }

  /**
   * An identity admitted to any degree for an object may know it exists, so a
   * refusal of one operation on it says it was refused rather than pretending the
   * object is not there. An identity admitted to nothing learns nothing.
   */
  protected override mayKnowOf(who: Who, owner: Who, of: ObjectIdentity): boolean {
    return owner === who || degreeFor(this.admissions, who, of) !== "none";
  }

  /**
   * Whether an identity may register beneath another's prefix, by admission.
   * Only the Name is known at this point — the object does not exist yet, and its
   * groups are whatever the request carries — so a grant that names a group alone
   * does not open a prefix. That is the safe way round: a client cannot write into
   * another's prefix by claiming a group it has been granted.
   */
  private admittedToWrite(who: Who, name: string): boolean {
    return permits(degreeFor(this.admissions, who, { name, groups: [] }), "register");
  }

  private guard(who: Who, names: string[]): void {
    for (const n of names) {
      // An identity admitted to write beneath a prefix may register there
      // though another holds it; the holder keeps the claim.
      if (this.admittedToWrite(who, n)) continue;
      this.prefixes.check(who, n);
    }
  }

  private record(who: Who, names: string[]): void {
    for (const n of names) {
      if (this.admittedToWrite(who, n)) continue;
      this.prefixes.claim(who, n);
    }
  }

  override register(who: Who, type: Parameters<KmsCore["register"]>[1], attrs: Attribute[], value: Item): string {
    const names = namesIn(attrs);
    this.guard(who, names);
    const id = super.register(who, type, attrs, value);
    this.record(who, names);
    return id;
  }

  override create(who: Who, type: Parameters<KmsCore["create"]>[1], attrs: Attribute[]): string {
    const names = namesIn(attrs);
    this.guard(who, names);
    const id = super.create(who, type, attrs);
    this.record(who, names);
    return id;
  }

  override createKeyPair(who: Who, common: Attribute[], priv: Attribute[], pub: Attribute[]):
    ReturnType<KmsCore["createKeyPair"]> {
    const names = [...namesIn(common), ...namesIn(priv), ...namesIn(pub)];
    this.guard(who, names);
    const pair = super.createKeyPair(who, common, priv, pub);
    this.record(who, names);
    return pair;
  }

  override addAttribute(who: Who, id: string, value: Item, name = nameOf(value.tag)): void {
    const renamed = name === "Name" ? nameValueOf(value) : undefined;
    if (renamed !== undefined) this.prefixes.check(who, renamed);
    super.addAttribute(who, id, value, name);
    if (renamed !== undefined) this.prefixes.claim(who, renamed);
  }

  override modifyAttribute(who: Who, id: string, value: Item, current?: Item, name = nameOf(value.tag)): void {
    const renamed = name === "Name" ? nameValueOf(value) : undefined;
    if (renamed !== undefined) this.prefixes.check(who, renamed);
    super.modifyAttribute(who, id, value, current, name);
    if (renamed !== undefined) this.prefixes.claim(who, renamed);
  }
}
