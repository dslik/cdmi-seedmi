// The delegated access control decision in force for the request being served,
// shared by every path that serves an object of this server: the protocol
// binding, an HTTP export, an S3 export, the NFS server and the SMB server.
//
// "Where delegated access control applies, the CDMI server shall evaluate it
// after evaluating the access control list of the object and before enforcing
// the result" (Position in access control). That requirement is of the object
// and not of the path by which it is reached, so an object bearing the two
// metadata items is governed by its provider however a client comes to it.
//
// Evaluating an access control list is synchronous and reaching a provider is
// not, so a decision is obtained once, before the operation is performed, and
// held here for the duration of that request. Each path's permission helper
// consults `delegatedMask` before evaluating the list.

import { AsyncLocalStorage } from "node:async_hooks";
import { grantedMask, maskToString, parseMask, type Principal } from "./acl.ts";
import type { Meta, Node, Store } from "./store.ts";
import { type DacClient, type DacContext, DacError, type DacOperation, type DacTarget } from "./dac.ts";

interface Held {
  /** By object ID, the mask the provider returned. */
  masks: Map<string, number>;
  /** Header fields to return to the client, where the path can carry them. */
  headers: Record<string, string>;
  /** Where a decision redirected, the object ID it named. */
  redirect?: string;
}

const current = new AsyncLocalStorage<Held>();

/** Serves one request with a context of its own. */
export const withDelegation = <T>(fn: () => T): T =>
  current.run({ masks: new Map(), headers: {} }, fn);

/** The mask a provider returned for an object during this request, where one was obtained. */
export const delegatedMask = (objectID: string): number | undefined =>
  current.getStore()?.masks.get(objectID);

/** The header fields a provider returned during this request. */
export const delegatedHeaders = (): Record<string, string> => ({ ...(current.getStore()?.headers ?? {}) });

/** The object a decision redirected to, where one did. */
export const delegatedRedirect = (): string | undefined => current.getStore()?.redirect;

/** Whether an object bears both items, and so has its decision delegated. */
export function delegationOf(meta: Meta): DacTarget | undefined {
  const m = meta.metadata as Record<string, unknown>;
  const uri = m.cdmi_dac_uri;
  const certificate = m.cdmi_dac_certificate;
  // "Where only one is present, delegated access control shall not be used."
  if (typeof uri !== "string" || typeof certificate !== "object" || certificate === null) return undefined;
  return { uri, certificate: certificate as DacTarget["certificate"] };
}

/** Why an operation may not proceed: no valid decision was obtained. */
export class DelegationRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DelegationRefused";
  }
}

/**
 * Obtains the decision for an object and holds it for this request. Throws
 * DelegationRefused where no valid response is received, which each path
 * reports in its own terms: "Where the CDMI server does not receive a valid
 * response, it shall not perform the operation and shall report the forbidden
 * condition."
 *
 * Returns the audit URI of the decision where it states one, and whether the
 * decision was retained, so that the caller records what it permits.
 */
export async function decideFor(dac: DacClient, store: Store, node: Node, who: Principal,
  operation: DacOperation, clientHeaders: Record<string, string> = {}):
  Promise<{ auditUri?: string; cached: boolean } | undefined> {
  const meta = store.meta(node);
  const target = delegationOf(meta);
  if (target === undefined) return undefined;
  const context: DacContext = {
    objectId: meta.objectID,
    operation,
    effectiveMask: maskToString(grantedMask(meta.acl, who, {
      owner: meta.owner, group: meta.group, isContainer: node.isContainer, isRoot: meta.parent === null,
    }), node.isContainer),
    principal: { name: who.name, groups: [...who.groups] },
    clientHeaders,
  };
  let decision;
  try {
    decision = await dac.decide(target, context);
  } catch (e) {
    if (e instanceof DacError) throw new DelegationRefused(e.message);
    throw e;
  }
  const held = current.getStore();
  if (held !== undefined) {
    if (decision.redirectObjectId !== undefined) held.redirect = decision.redirectObjectId;
    for (const [name, value] of Object.entries(decision.responseHeaders)) held.headers[name] = value;
    let applied: number;
    try {
      applied = parseMask(decision.appliedMask, node.isContainer);
    } catch {
      throw new DelegationRefused("the provider returned a mask that is not one");
    }
    held.masks.set(meta.objectID, applied);
  }
  return {
    ...(decision.auditUri === undefined ? {} : { auditUri: decision.auditUri }),
    cached: decision.cached === true,
  };
}
