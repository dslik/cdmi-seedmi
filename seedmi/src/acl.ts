// Access control lists, which clause 17 takes unchanged from NFSv4
// (RFC 7530 section 6.2.1): the same four ACE fields, the same flags and
// the same 32-bit access mask. One structure is therefore stored,
// evaluated, reported in a CDMI representation, and served to an NFS
// client.

import type { ACE } from "./store.ts";

export const ACE_ALLOW = "ALLOW";
export const ACE_DENY = "DENY";

/**
 * The two entry types. The audit and alarm types of RFC 7530 are not
 * defined by this document, and an entry naming one is an invalid field.
 */
export const TYPE_BITS: Record<string, number> = {
  ALLOW: 0x00000000,
  DENY: 0x00000001,
};

export const FLAG_BITS: Record<string, number> = {
  NO_FLAGS: 0x00000000,
  OBJECT_INHERIT: 0x00000001,
  CONTAINER_INHERIT: 0x00000002,
  NO_PROPAGATE: 0x00000004,
  INHERIT_ONLY: 0x00000008,
  IDENTIFIER_GROUP: 0x00000040,
  INHERITED: 0x00000080,
};

/**
 * The mask bits, in the order the draft tabulates them, greatest first.
 * A bit has one name for a data object and another for a container
 * object, because the same bit means "read the value" and "list the
 * children".
 */
const MASK_TABLE: [number, string, string][] = [
  [0x001f07ff, "ALL_PERMS", "ALL_PERMS"],
  [0x00100000, "SYNCHRONIZE", "SYNCHRONIZE"],
  [0x00080000, "WRITE_OWNER", "WRITE_OWNER"],
  [0x0006006f, "RW_ALL", "RW_ALL"],
  [0x00040000, "WRITE_ACL", "WRITE_ACL"],
  [0x00020000, "READ_ACL", "READ_ACL"],
  [0x00010000, "DELETE", "DELETE"],
  [0x00000400, "WRITE_RETENTION_HOLD", "WRITE_RETENTION_HOLD"],
  [0x00000200, "WRITE_RETENTION", "WRITE_RETENTION"],
  [0x00000100, "WRITE_ATTRIBUTES", "WRITE_ATTRIBUTES"],
  [0x00000080, "READ_ATTRIBUTES", "READ_ATTRIBUTES"],
  [0x00000040, "DELETE_OBJECT", "DELETE_SUBCONTAINER"],
  // One bit with two string forms, as READ_OBJECT/LIST_CONTAINER and
  // WRITE_OBJECT/ADD_OBJECT are: "EXECUTE ... indicates permission to execute
  // an object", "TRAVERSE_CONTAINER ... indicates permission to traverse a
  // container object or domain object", both at 0x00000020, and Annex A admits
  // either name for the one item — aceexecuteitem = "CDMI_ACE_EXECUTE" |
  // "CDMI_ACE_TRAVERSE_CONTAINER" | 0x00000020. The container form was EXECUTE
  // here until 0.101, so an access control entry naming TRAVERSE_CONTAINER was
  // refused as naming no defined value, and a container object's access control
  // list came back spelling the bit as a data object's.
  [0x00000020, "EXECUTE", "TRAVERSE_CONTAINER"],
  [0x0000001f, "RW", "RW"],
  [0x00000010, "WRITE_METADATA", "WRITE_METADATA"],
  [0x00000008, "READ_METADATA", "READ_METADATA"],
  [0x00000004, "APPEND_DATA", "ADD_SUBCONTAINER"],
  [0x00000002, "WRITE_OBJECT", "ADD_OBJECT"],
  [0x00000001, "READ_OBJECT", "LIST_CONTAINER"],
];

/** The individual bits, by the name each form of object gives them. */
export const M = {
  READ_OBJECT: 0x00000001,
  LIST_CONTAINER: 0x00000001,
  WRITE_OBJECT: 0x00000002,
  ADD_OBJECT: 0x00000002,
  APPEND_DATA: 0x00000004,
  ADD_SUBCONTAINER: 0x00000004,
  READ_METADATA: 0x00000008,
  WRITE_METADATA: 0x00000010,
  EXECUTE: 0x00000020,
  DELETE_OBJECT: 0x00000040,
  DELETE_SUBCONTAINER: 0x00000040,
  READ_ATTRIBUTES: 0x00000080,
  WRITE_ATTRIBUTES: 0x00000100,
  WRITE_RETENTION: 0x00000200,
  WRITE_RETENTION_HOLD: 0x00000400,
  DELETE: 0x00010000,
  READ_ACL: 0x00020000,
  WRITE_ACL: 0x00040000,
  WRITE_OWNER: 0x00080000,
  SYNCHRONIZE: 0x00100000,
  ALL_PERMS: 0x001f07ff,
  RW_ALL: 0x0006006f,
  RW: 0x0000001f,
  /** The composite the default ACL of a root container object uses. */
  // READ_OBJECT | READ_METADATA | READ_ATTRIBUTES, so that a principal
  // granted it reads the value, the user metadata, and the storage
  // system and data system metadata by which a client determines the
  // type and the size of an object.
  READ: 0x00000089,
} as const;

const EXTRA_NAMES: Record<string, number> = { READ: M.READ, WRITE: 0x0000001a, NONE: 0 };

/** Parses a value that may be a hex string or a comma-separated list. */
export function parseBits(value: string, table: Record<string, number>): number {
  const s = value.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return Number.parseInt(s, 16) >>> 0;
  let bits = 0;
  for (const part of s.split(",")) {
    const name = part.trim().toUpperCase();
    if (name === "") continue;
    const v = table[name];
    if (v === undefined) throw new Error(`${JSON.stringify(part.trim())} is not a defined value`);
    bits |= v;
  }
  return bits >>> 0;
}

/**
 * Parses an access mask, in either form, for an object of the given type.
 *
 * Both string forms of a bit are accepted whatever the object type. Annex A
 * gives each dual-named bit one rule admitting either name — "acereaditem =
 * "CDMI_ACE_READ_OBJECT" | "CDMI_ACE_LIST_CONTAINER" | 0x00000001" — with no
 * condition on the type of the object the entry is placed on, and the two names
 * are one bit, so a CDMI client that spells it the other way has named a bit
 * this server supports and the entry is not one to reject. The textual form
 * this server *returns* is the one that suits the object type, which is what
 * maskToString does. Only the form matching the type parsed until 0.101.
 */
export function parseMask(value: string, isContainer: boolean): number {
  const table: Record<string, number> = { ...EXTRA_NAMES };
  for (const [bits, objectName, containerName] of MASK_TABLE) {
    table[objectName] = bits;
    table[containerName] = bits;
  }
  void isContainer;
  return parseBits(value, table);
}

export const parseFlags = (value: string): number => parseBits(value, FLAG_BITS);
export const parseType = (value: string): number => parseBits(value, TYPE_BITS);

/**
 * The textual form of a mask: the strings of the table, greatest first,
 * each selected where its bits are present and not already covered.
 */
export function maskToString(mask: number, isContainer: boolean): string {
  let left = mask >>> 0;
  const out: string[] = [];
  for (const [bits, objectName, containerName] of MASK_TABLE) {
    if (bits !== 0 && (left & bits) === bits) {
      out.push(isContainer ? containerName : objectName);
      left &= ~bits;
    }
  }
  if (left !== 0) out.push(`0x${left.toString(16).padStart(8, "0")}`);
  return out.length === 0 ? "NONE" : out.join(", ");
}

export function flagsToString(flags: number): string {
  if (flags === 0) return "NO_FLAGS";
  const out: string[] = [];
  for (const [name, bits] of Object.entries(FLAG_BITS)) {
    if (bits !== 0 && (flags & bits) === bits) out.push(name);
  }
  return out.join(", ");
}

// ---------------------------------------------------------------------------
// Principals

export interface Principal {
  /** The name of the principal, or "ANONYMOUS@" where none was resolved. */
  name: string;
  groups: string[];
  /** Whether the principal holds administrative status. */
  administrator: boolean;
  /** Privileges the principal holds, such as import_service_credential. */
  privileges: string[];
  /**
   * The access token the principal presented, where it presented one.
   * A remote import in delegated identity mode exchanges it; a
   * principal that presented a password has none, and cannot be
   * delegated.
   */
  token?: string;
  /**
   * Values read from the principal's directory entry, by attribute name:
   * what the "userinfo_attributes" member of a directory descriptor maps,
   * and the home attributes a CDMI server reads where it maps none
   * (revision 302). They fill the description of the principal
   * (cdmi_domain_userinfo) and are used for nothing else.
   */
  attributes?: Record<string, string>;
}

export const ANONYMOUS: Principal = {
  name: "ANONYMOUS@",
  groups: [],
  administrator: false,
  privileges: [],
};

export const isAnonymous = (p: Principal) => p.name === "ANONYMOUS@";

/** Whether an ACE refers to the principal. */
export function refersTo(ace: ParsedACE, p: Principal, owner: string, group: string): boolean {
  const who = ace.who;
  // The IDENTIFIER_GROUP flag is ignored on a special identifier, which
  // names what it names whether or not the flag is set.
  switch (who) {
    case "EVERYONE@": return true;
    case "ANONYMOUS@": return isAnonymous(p);
    case "AUTHENTICATED@": return !isAnonymous(p);
    case "OWNER@": return owner !== "" && p.name === owner;
    case "GROUP@": return group !== "" && p.groups.includes(group);
    case "ADMINISTRATOR@": return p.administrator;
    case "ADMINUSERS@": return p.administrator;
    default:
      return (ace.flags & FLAG_BITS.IDENTIFIER_GROUP) !== 0
        ? p.groups.includes(who)
        : p.name === who;
  }
}

// ---------------------------------------------------------------------------
// Evaluation

export interface ParsedACE {
  type: number;
  who: string;
  flags: number;
  mask: number;
}

/** Parses a stored ACE into its bits. An unparsable ACE denies everything. */
export function parseACE(ace: ACE, isContainer: boolean): ParsedACE {
  return {
    type: parseType(ace.acetype ?? "ALLOW"),
    who: ace.identifier ?? "",
    flags: ace.aceflags === undefined || ace.aceflags === "" ? 0 : parseFlags(ace.aceflags),
    mask: parseMask(ace.acemask ?? "NONE", isContainer),
  };
}

export interface EvalContext {
  owner: string;
  group: string;
  isContainer: boolean;
  /** A root container object falls back to the owner and administrators. */
  isRoot: boolean;
}

/**
 * Whether a principal is granted every bit of wanted, by the algorithm of
 * clause 17: walk the list in order, deny on the first DENY that matches
 * any wanted bit, accumulate ALLOW bits, and grant once every wanted bit
 * has been accumulated.
 */
export function granted(acl: ACE[] | null, p: Principal, wanted: number,
  ctx: EvalContext): boolean {
  if (wanted === 0) return true;
  if (acl === null) {
    // No access control list: access is denied to every principal. The
    // draft notes this is not expected, since a default list is placed on
    // the root container object.
    return false;
  }
  // A root container object is reached by its owner and by an
  // administrator whatever its list says, and not only where the list is
  // silent, so that an administrator can always repair it.
  if (ctx.isRoot && ((ctx.owner !== "" && p.name === ctx.owner) || p.administrator)) {
    return true;
  }
  let m = 0;
  for (const raw of acl) {
    let ace: ParsedACE;
    try {
      ace = parseACE(raw, ctx.isContainer);
    } catch {
      continue; // an entry seedmi cannot parse grants nothing
    }
    if ((ace.flags & FLAG_BITS.INHERIT_ONLY) !== 0) continue;
    if (!refersTo(ace, p, ctx.owner, ctx.group)) continue;
    if (ace.type === TYPE_BITS.DENY) {
      // A bit already granted has been granted and takes no part in a
      // later entry, so an entry that denies only such bits denies
      // nothing: a grant to a principal is not undone by a later entry
      // denying the same access to a wider set of principals.
      if ((ace.mask & wanted & ~m) !== 0) return false;
      continue;
    }
    m |= ace.mask;
    if ((m & wanted) === wanted) return true;
  }
  return false;
}

/**
 * Whether the list explicitly denies a bit to the principal, as distinct
 * from being silent on it. EXECUTE grants the reading of a value where
 * READ_OBJECT is not granted, but an entry that explicitly denies
 * READ_OBJECT denies the reading notwithstanding EXECUTE.
 */
/**
 * The mask a principal is granted on an object: the bits `granted` would allow,
 * taken together. A delegated access control request carries it as
 * "acl_effective_mask", "the ACE mask determined by ACL evaluation for the
 * requested operation".
 */
export function grantedMask(acl: ACE[] | null, p: Principal,
  opts: { owner: string; group: string; isContainer: boolean; isRoot?: boolean }): number {
  const context = { ...opts, isRoot: opts.isRoot === true };
  let mask = 0;
  for (const [bits] of MASK_TABLE) {
    if (granted(acl, p, bits, context)) mask |= bits;
  }
  return mask;
}

export function deniedExplicitly(acl: ACE[] | null, p: Principal, bit: number,
  ctx: EvalContext): boolean {
  if (acl === null) return false;
  let m = 0;
  for (const raw of acl) {
    let ace: ParsedACE;
    try {
      ace = parseACE(raw, ctx.isContainer);
    } catch {
      continue;
    }
    if ((ace.flags & FLAG_BITS.INHERIT_ONLY) !== 0) continue;
    if (!refersTo(ace, p, ctx.owner, ctx.group)) continue;
    if (ace.type === TYPE_BITS.DENY) {
      if ((ace.mask & bit & ~m) !== 0) return true;
      continue;
    }
    m |= ace.mask;
    if ((m & bit) === bit) return false;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Inheritance and defaults

const ace = (type: string, who: string, flags: string, mask: string): ACE =>
  ({ acetype: type, identifier: who, aceflags: flags, acemask: mask });

/**
 * The default list of a root container object. Where the CDMI server
 * authenticates no principal, so that every request is evaluated using
 * ANONYMOUS@, that identifier takes the place of OWNER@ in the first
 * entry, since OWNER@ would otherwise match nobody and the store would be
 * unreachable.
 */
export const defaultRootACL = (anonymous = false): ACE[] => [
  ace("ALLOW", anonymous ? "ANONYMOUS@" : "OWNER@",
    "OBJECT_INHERIT, CONTAINER_INHERIT", "ALL_PERMS"),
  ace("ALLOW", "AUTHENTICATED@", "OBJECT_INHERIT, CONTAINER_INHERIT", "READ"),
];

/** The default list of an object that inherits nothing. */
export const defaultObjectACL = (): ACE[] => [
  ace("ALLOW", "OWNER@", "OBJECT_INHERIT, CONTAINER_INHERIT", "ALL_PERMS"),
];

/**
 * The list an object created within a container inherits. Inheritance
 * happens once, when the object is created; the draft defines no
 * evaluation-time walk up the tree.
 */
export function inherited(parentACL: ACE[] | null, childIsContainer: boolean): ACE[] {
  if (parentACL === null) return [];
  const out: ACE[] = [];
  for (const raw of parentACL) {
    let p: ParsedACE;
    try {
      p = parseACE(raw, true);
    } catch {
      continue;
    }
    const objectInherit = (p.flags & FLAG_BITS.OBJECT_INHERIT) !== 0;
    const containerInherit = (p.flags & FLAG_BITS.CONTAINER_INHERIT) !== 0;
    if (childIsContainer ? !(objectInherit || containerInherit) : !objectInherit) continue;

    let flags = p.flags;
    if (!childIsContainer) {
      // A data object contains no object, so no inheritance flag has
      // meaning on it.
      flags &= ~(FLAG_BITS.OBJECT_INHERIT | FLAG_BITS.CONTAINER_INHERIT |
        FLAG_BITS.INHERIT_ONLY);
    } else if ((p.flags & FLAG_BITS.NO_PROPAGATE) !== 0) {
      // NO_PROPAGATE: the entry applies to the new container object and
      // is inherited no further.
      flags &= ~(FLAG_BITS.OBJECT_INHERIT | FLAG_BITS.CONTAINER_INHERIT |
        FLAG_BITS.NO_PROPAGATE | FLAG_BITS.INHERIT_ONLY);
    } else {
      // The inheritable flags are retained as the parent had them, so the
      // entry goes on propagating below the new container object. It is
      // effective there where CONTAINER_INHERIT is set, and INHERIT_ONLY
      // where the entry is inheritable by data objects alone.
      flags &= ~FLAG_BITS.INHERIT_ONLY;
      if (objectInherit && !containerInherit) flags |= FLAG_BITS.INHERIT_ONLY;
    }
    flags |= FLAG_BITS.INHERITED;
    out.push({
      acetype: raw.acetype,
      identifier: raw.identifier,
      aceflags: flagsToString(flags),
      // The mask is stored in the string form of the child's own type, so
      // that a container entry inherited by a data object reads correctly.
      acemask: maskToString(parseMask(raw.acemask ?? "NONE", true), childIsContainer),
    });
  }
  return out;
}

/** The list to place on a new object: supplied, inherited, or the default. */
export function aclForNewObject(supplied: ACE[] | null | undefined,
  parentACL: ACE[] | null, childIsContainer: boolean): ACE[] {
  if (supplied !== null && supplied !== undefined) return supplied;
  const from = inherited(parentACL, childIsContainer);
  return from.length > 0 ? from : defaultObjectACL();
}

// ---------------------------------------------------------------------------
// The mask an operation requires

/** The bits a read of the named fields requires, for field-level exclusion. */
export const READ_BITS = {
  value: M.READ_OBJECT,
  children: M.LIST_CONTAINER,
  childrenrange: M.LIST_CONTAINER,
  metadata: M.READ_METADATA,
  acl: M.READ_ACL,
  attributes: M.READ_ATTRIBUTES,
} as const;

/**
 * The flags and mask bits this server supports: "A CDMI server supports a mask
 * bit or a flag where it stores that bit or flag and enforces it independently of
 * every other bit or flag" (revision 269). They are published as cdmi_acl_flags
 * and cdmi_acl_mask_bits. Each bit of ALL_PERMS is among them: WRITE_ATTRIBUTES,
 * WRITE_RETENTION and WRITE_RETENTION_HOLD each govern the changes of their own
 * items (binding.ts), and SYNCHRONIZE, "permission to access an object locally
 * at the server with synchronous reads and writes", governs no operation this
 * server offers, so that it is stored and has no effect on any other bit
 * (ECR-133A). TRAVERSE_CONTAINER is stored and enforced by no CDMI server, and is
 * published for that reason.
 */
export const SUPPORTED_FLAGS = ["OBJECT_INHERIT", "CONTAINER_INHERIT", "NO_PROPAGATE", "INHERIT_ONLY", "IDENTIFIER_GROUP", "INHERITED"];
/**
 * The names published in cdmi_acl_mask_bits: those the mask bits table of the
 * draft defines, and no other. Before 0.62 this list held TRAVERSE_CONTAINER and
 * WRITE_RETENTION_HOLD, which the table did not then define; the table of
 * revision 365 defines TRAVERSE_CONTAINER, at 0x00000020 with EXECUTE, and this
 * server parses and returns it from 0.101, so it is published again.
 */
export const SUPPORTED_MASK_BITS = ["READ_OBJECT", "LIST_CONTAINER", "WRITE_OBJECT", "ADD_OBJECT", "APPEND_DATA",
  "ADD_SUBCONTAINER", "READ_METADATA", "WRITE_METADATA", "EXECUTE", "TRAVERSE_CONTAINER",
  "DELETE_OBJECT", "READ_ATTRIBUTES",
  "WRITE_ATTRIBUTES", "WRITE_RETENTION", "DELETE", "READ_ACL", "WRITE_ACL", "WRITE_OWNER", "SYNCHRONIZE"];
const supportedFlagBits = SUPPORTED_FLAGS.reduce((a, n) => a | FLAG_BITS[n], 0);
/**
 * The bits supported: every bit of ALL_PERMS, which is what an entry granting
 * that composite names. The bit 0x00000400, which NFSv4 calls
 * ACE4_WRITE_RETENTION_HOLD, is among them and has no name in the draft, so it
 * is stored and is governed with the retention bit.
 */
const supportedMaskBits = M.ALL_PERMS;

/**
 * What an entry names that this server does not support, or undefined: "Where an
 * access control entry names a mask bit or a flag the CDMI server does not
 * support, the CDMI server shall reject the entry and shall not store it"
 * (revision 269). Checked on the parsed bits, so that a hexadecimal form naming
 * an undefined bit is caught as a string form is.
 */
export function unsupportedIn(ace: ParsedACE): string | undefined {
  const mask = ace.mask & ~supportedMaskBits, flags = ace.flags & ~supportedFlagBits;
  if (mask === 0 && flags === 0) return undefined;
  const hex = (n: number) => "0x" + (n >>> 0).toString(16).padStart(8, "0");
  return [mask === 0 ? "" : `the mask bits ${hex(mask)}`, flags === 0 ? "" : `the flags ${hex(flags)}`].filter((x) => x).join(" and ");
}
