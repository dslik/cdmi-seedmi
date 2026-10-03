// Phase 3 of PLAN.md: what the provider decides.
//
// "The CDMI server sends the permission mask obtained from the access control
// list to the delegated access control provider, and the provider returns the
// mask that shall be applied in its place. The provider may therefore grant
// access the access control list denies, and deny access the access control list
// allows" (Position in access control). How it decides is the provider's own:
// here, rules taken in order, the first that matches deciding, and a request no
// rule matches denied.

import { type DacDecision, type DacRequest, DacRefusal } from "./dac-protocol.ts";

/**
 * The mask names of the ACE bit mask/string table (tbl_ace_strings), both
 * forms: a request does not say whether its object is a container, and each
 * row's two names denote the same bits, so both are read.
 */
const NAMES: Record<string, number> = {
  ALL_PERMS: 0x001f07ff, SYNCHRONIZE: 0x00100000, WRITE_OWNER: 0x00080000, RW_ALL: 0x0006006f,
  WRITE_ACL: 0x00040000, READ_ACL: 0x00020000, DELETE: 0x00010000, WRITE_RETENTION_HOLD: 0x00000400,
  WRITE_RETENTION: 0x00000200, WRITE_ATTRIBUTES: 0x00000100, READ: 0x00000089, READ_ATTRIBUTES: 0x00000080,
  DELETE_OBJECT: 0x00000040, DELETE_SUBCONTAINER: 0x00000040, EXECUTE: 0x00000020, TRAVERSE_CONTAINER: 0x00000020,
  RW: 0x0000001f, WRITE_METADATA: 0x00000010, READ_METADATA: 0x00000008, APPEND_DATA: 0x00000004,
  ADD_SUBCONTAINER: 0x00000004, WRITE_OBJECT: 0x00000002, ADD_OBJECT: 0x00000002, READ_OBJECT: 0x00000001,
  LIST_CONTAINER: 0x00000001,
};

/**
 * A mask in "a text or hexadecimal string representation": names and
 * hexadecimal quantities, combined by "|" as the ACE mask expressions show, or
 * separated by commas as CDMI servers write a list of names. undefined where a
 * part is neither.
 */
export function parseMask(text: string): number | undefined {
  let bits = 0;
  for (const raw of text.split(/[|,]/)) {
    const part = raw.trim().replace(/^"(.*)"$/, "$1").toUpperCase();
    if (part === "") continue;
    if (/^0X[0-9A-F]{1,8}$/.test(part)) bits |= parseInt(part.slice(2), 16);
    else if (part in NAMES) bits |= NAMES[part];
    else return undefined;
  }
  return bits >>> 0;
}

/** The canonical hexadecimal form of a mask: "0x", then eight digits. */
export function maskHex(bits: number): string {
  return `0x${(bits >>> 0).toString(16).toUpperCase().padStart(8, "0")}`;
}

export type Decision = "grant" | "narrow" | "pass" | "deny";

/** A [[rule]] table. An absent criterion matches every request. */
export interface Rule {
  servers?: string[];
  objects?: string[];
  operations?: string[];
  principals?: string[];
  groups?: string[];
  /** Header fields of client_headers, by name in lower case, and the value each holds. */
  headers?: Record<string, string>;
  decision: Decision;
  /** For grant and narrow. */
  mask?: number;
  responseHeaders?: Record<string, string>;
  cacheSeconds?: number;
  redirectObjectID?: string;
  auditUri?: string;
  /** Answer later, at the request's dac_response_uri, where the server permits it (dac-deliver.ts). */
  defer?: boolean;
}

const listed = (list: string[] | undefined, v: string | undefined): boolean =>
  list === undefined || list.includes("*") || (v !== undefined && list.includes(v));

/** Whether a rule's every criterion holds of a request from the server named. */
export function matches(rule: Rule, req: DacRequest, server: string): boolean {
  if (!listed(rule.servers, server) || !listed(rule.objects, req.objectId) || !listed(rule.operations, req.operation)) {
    return false;
  }
  if (rule.principals !== undefined && !listed(rule.principals, req.client?.name)) return false;
  if (rule.groups !== undefined && !rule.groups.includes("*") &&
      !(req.client?.groups ?? []).some((g) => rule.groups!.includes(g))) {
    return false;
  }
  if (rule.headers !== undefined) {
    const held = Object.fromEntries(Object.entries(req.clientHeaders).map(([k, v]) => [k.toLowerCase(), v]));
    for (const [k, v] of Object.entries(rule.headers)) if (held[k] !== v) return false;
  }
  return true;
}

/**
 * The decision for a request from the server named: that of the first rule
 * matching it, and a denial where none does.
 *
 * | decision | applied mask                                             |
 * | grant    | the rule's mask, whatever the access control list allowed |
 * | narrow   | the access control list's mask and the rule's, together  |
 * | pass     | the access control list's mask                           |
 * | deny     | no permission                                            |
 */
export function decide(rules: Rule[], req: DacRequest, server: string, now = new Date()):
  DacDecision & { rule?: number; defer?: boolean } {
  const effective = parseMask(req.effectiveMask);
  if (effective === undefined) {
    throw new DacRefusal("malformed", `acl_effective_mask ${JSON.stringify(req.effectiveMask)} is not a mask`);
  }
  const index = rules.findIndex((r) => matches(r, req, server));
  if (index < 0) return { appliedMask: maskHex(0) };
  const r = rules[index];
  const bits = r.decision === "grant" ? r.mask!
    : r.decision === "narrow" ? effective & r.mask!
      : r.decision === "pass" ? effective
        : 0;
  return {
    rule: index,
    appliedMask: maskHex(bits),
    ...(r.responseHeaders === undefined ? {} : { responseHeaders: r.responseHeaders }),
    ...(r.cacheSeconds === undefined ? {} : { responseCacheExpiry: new Date(now.getTime() + r.cacheSeconds * 1000) }),
    ...(r.redirectObjectID === undefined ? {} : { redirectObjectID: r.redirectObjectID }),
    ...(r.auditUri === undefined ? {} : { auditUri: r.auditUri }),
    ...(r.defer === true ? { defer: true } : {}),
  };
}
