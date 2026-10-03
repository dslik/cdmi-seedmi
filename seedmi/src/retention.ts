// Retention and hold.
//
// Retention prohibits the deletion of an object until a time has
// passed. A hold prohibits its deletion and its modification until the
// hold is released. Both are asked for by data system metadata items,
// and both are enforced whatever the access control lists permit.
//
// The two rules that make this more than a flag are the ones about
// changing what is already in force: a retention period may be
// extended and never shortened, and a hold may be added and never
// removed. A server that let either go the other way would let the
// party subject to the restriction lift it.

import { forbidden, invalidField, malformed, retentionConflict } from "./problems.ts";

export const RETENTION_ID = "cdmi_retention_id";
export const RETENTION_PERIOD = "cdmi_retention_period";
export const RETENTION_AUTODELETE = "cdmi_retention_autodelete";
export const HOLD_ID = "cdmi_hold_id";

/** The items a client sets to ask for retention or hold. */
export const RETENTION_ITEMS = [
  RETENTION_ID, RETENTION_PERIOD, RETENTION_AUTODELETE, HOLD_ID,
];

/** The items reporting what the server applied. */
export const RETENTION_PROVIDED = [
  "cdmi_retention_period_provided",
  "cdmi_retention_autodelete_provided",
  "cdmi_hold_id_provided",
];

const DURATION = /^P(?!$)(\d+Y)?(\d+M)?(\d+D)?(T(?!$)(\d+H)?(\d+M)?(\d+(\.\d+)?S)?)?$/;

/** The milliseconds a duration in the form PnYnMnDTnHnMnS stands for. */
function durationMillis(text: string): number | undefined {
  const m = DURATION.exec(text);
  if (!m) return undefined;
  const n = (v: string | undefined) => (v === undefined ? 0 : Number(v.slice(0, -1)));
  // A year is 365 days and a month 30, which is what a period without
  // a starting instant can mean: the draft gives no calendar rule.
  return (
    n(m[1]) * 365 * 86400000 +
    n(m[2]) * 30 * 86400000 +
    n(m[3]) * 86400000 +
    n(m[5]) * 3600000 +
    n(m[6]) * 60000 +
    Math.round(Number((m[7] ?? "0S").slice(0, -1)) * 1000)
  );
}

function instant(text: string): number | undefined {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(text)) return undefined;
  const t = Date.parse(text);
  return Number.isNaN(t) ? undefined : t;
}

/**
 * The instant a retention period ends. A period is a time interval in
 * one of the four forms of ISO 8601-1, and each form has to yield an
 * end for the period to be compared with another: `from` is when the
 * period was set, which is what a duration is measured from.
 */
export function endOf(period: string, from: number): number | undefined {
  const cut = period.indexOf("/");
  if (cut < 0) {
    const d = durationMillis(period);
    return d === undefined ? undefined : from + d;
  }
  const left = period.slice(0, cut);
  const right = period.slice(cut + 1);
  const start = instant(left);
  if (start !== undefined) {
    // A start and an end, or a start and a duration.
    const end = instant(right);
    if (end !== undefined) return end;
    const d = durationMillis(right);
    return d === undefined ? undefined : start + d;
  }
  // A duration and an end.
  const d = durationMillis(left);
  const end = instant(right);
  return d === undefined || end === undefined ? undefined : end;
}

/** What retention and hold are in force for an object. */
export interface Restriction {
  /** The instant the retention period ends, where one is in force. */
  retainedUntil?: number;
  /** The holds that apply, which are released outside this document. */
  holds: string[];
  autodelete: boolean;
}

/**
 * The instant a retention period ends. Where the value states an end,
 * that is the end. Where it states a duration and no start, the period
 * began when the CDMI server applied the item, so the applied instant
 * is used: the draft states that a server shall not take the start
 * from the time the object was created, since an object may be placed
 * under retention long afterwards and a period so measured may have
 * ended before it was applied.
 */
export function endApplied(metadata: Record<string, unknown>): number | undefined {
  const period = metadata[RETENTION_PERIOD];
  if (typeof period !== "string") return undefined;
  // The applied instant is recorded when the item is written, and is
  // what the cdmi_retention_period_provided item reports.
  const applied = metadata[APPLIED_AT];
  const from = typeof applied === "string" ? Date.parse(applied) : Date.now();
  return endOf(period, Number.isNaN(from) ? Date.now() : from);
}

/**
 * Where the instant the retention period was applied is recorded. It
 * is a storage system detail rather than an item a client supplies,
 * and is held under a name a client cannot write.
 */
export const APPLIED_AT = "cdmi_retention_applied";

export function restrictionOf(metadata: Record<string, unknown>): Restriction {
  const holds = Array.isArray(metadata[HOLD_ID])
    ? (metadata[HOLD_ID] as unknown[]).filter((h): h is string => typeof h === "string")
    : [];
  return {
    retainedUntil: endApplied(metadata),
    holds,
    autodelete: metadata[RETENTION_AUTODELETE] === "true",
  };
}

/** Whether an object is under retention, under hold, or under both. */
export function restricted(r: Restriction, now = Date.now()): boolean {
  return r.holds.length > 0 ||
    (r.retainedUntil !== undefined && r.retainedUntil > now);
}

/**
 * Whether the metadata of an object puts it under retention or under hold, and
 * so refuses a change to it whatever the access control lists permit.
 *
 * Every protocol asks this question, and revision 365 settles that every
 * protocol must: "a rule of this document that governs what may be done to an
 * object governs a request that reaches that object through an export as it
 * governs an operation of a protocol binding. The retention and hold rules ...
 * apply, so that a request through an export that would delete or modify an
 * object under retention or under hold is refused, however the exported
 * protocol expresses that request, and whether it expresses it as one operation
 * or as several." The clause goes further, and closes the gap that earlier
 * revisions left (NOTES-on-smb.md Q14): "where [the retention subclause] does
 * not state the effect of an operation upon an object under retention or under
 * hold, a CDMI server shall reject the request, rather than permit through an
 * export what it would not permit through a protocol binding."
 *
 * Each protocol reports the refusal in its own terms — 409 for an HTTP export,
 * ACCESS_DENIED for SMB, NFS4ERR_ACCESS for NFS, AccessDenied for S3 — and the
 * judgement of whether the object is held is made here, once.
 */
export const underRestriction = (metadata: Record<string, unknown>,
  now = Date.now()): boolean => restricted(restrictionOf(metadata), now);

/**
 * Whether an object should be deleted automatically: the retention
 * period has passed and no hold applies. Both criteria are satisfied,
 * whatever the period specifies.
 */
export function autodeletable(r: Restriction, now = Date.now()): boolean {
  return r.autodelete && r.holds.length === 0 &&
    r.retainedUntil !== undefined && r.retainedUntil <= now;
}

/**
 * The path of an object within a container object, at any depth, that is under
 * retention or under hold, where there is one.
 *
 * "A container object is not deleted while an object it contains, at any depth,
 * is under retention or under hold. A CDMI server shall report the conflict
 * condition for a delete operation on such a container object, whatever the
 * access control lists permit and whether or not that container object is itself
 * under retention or under hold. Deleting a container object deletes the objects
 * it contains ... so a container object that could be deleted would defeat the
 * retention of every object beneath it."
 *
 * The traversal is given the store's two accessors rather than the store, so
 * that the protocol binding and each export walk the namespace the same way
 * without this module depending on the store.
 */
export function restrictedWithin<N>(node: N,
  children: (n: N) => { name: string; node: N; isContainer: boolean }[],
  metadataOf: (n: N) => Record<string, unknown>,
  now = Date.now()): string | undefined {
  for (const child of children(node)) {
    if (underRestriction(metadataOf(child.node), now)) return child.name;
    if (child.isContainer) {
      const deeper = restrictedWithin(child.node, children, metadataOf, now);
      if (deeper !== undefined) return `${child.name}/${deeper}`;
    }
  }
  return undefined;
}

/** Why a change to the retention or hold items is not permitted. */
export interface RetentionFault {
  condition: "invalid" | "malformed" | "forbidden" | "conflict";
  item: string;
  why: string;
}

/**
 * Checks a change to the retention and hold items of an object. The
 * period may be extended and not shortened, a hold may be added and
 * not removed, and one retention period applies at a time.
 */
export function checkChange(before: Record<string, unknown>,
  supplied: Record<string, unknown>): RetentionFault | undefined {
  if (RETENTION_AUTODELETE in supplied) {
    const v = supplied[RETENTION_AUTODELETE];
    if (v !== undefined && v !== null && v !== "true" && v !== "false") {
      return {
        condition: "invalid", item: RETENTION_AUTODELETE,
        why: 'the autodelete item is "true" or "false"',
      };
    }
  }
  if (RETENTION_ID in supplied) {
    const v = supplied[RETENTION_ID];
    if (v !== undefined && v !== null && typeof v !== "string") {
      return {
        condition: "invalid", item: RETENTION_ID,
        why: "the retention identifier is a JSON string",
      };
    }
  }

  const now = Date.now();
  const wasHeld = restrictionOf(before);

  if (RETENTION_PERIOD in supplied) {
    const v = supplied[RETENTION_PERIOD];
    if (v === null) {
      // Removing the period shortens it to nothing.
      if (wasHeld.retainedUntil !== undefined && wasHeld.retainedUntil > now) {
        return {
          condition: "conflict", item: RETENTION_PERIOD,
          why: "a retention period is not shortened",
        };
      }
    } else if (typeof v !== "string") {
      return {
        condition: "invalid", item: RETENTION_PERIOD,
        why: "a retention period is a time interval, as a JSON string",
      };
    } else {
      const end = endOf(v, Date.now());
      if (end === undefined) {
        // "the invalid field condition" is what the subclause names for a
        // value that is not a time interval; this server reported the
        // malformed request condition before 0.74 (weedmi DMGT-011).
        return {
          condition: "invalid", item: RETENTION_PERIOD,
          why: `${JSON.stringify(v)} is not a time interval`,
        };
      }
      // A period that has already ended retains the object for no time at
      // all, which is not a retention: it was accepted before 0.74, so an
      // object could be placed under a retention that was already over
      // (weedmi DMGT-011).
      if (end <= now) {
        return {
          condition: "invalid", item: RETENTION_PERIOD,
          why: "a retention period ends after the time it is set",
        };
      }
      if (wasHeld.retainedUntil !== undefined && wasHeld.retainedUntil > now &&
        end < wasHeld.retainedUntil) {
        return {
          condition: "conflict", item: RETENTION_PERIOD,
          why: "a retention period is extended and not shortened",
        };
      }
    }
  }

  if (HOLD_ID in supplied) {
    const v = supplied[HOLD_ID];
    if (v === null) {
      if (wasHeld.holds.length > 0) {
        return {
          condition: "conflict", item: HOLD_ID,
          why: "a hold is not removed by an operation of this document",
        };
      }
    } else if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
      return {
        condition: "invalid", item: HOLD_ID,
        why: "the hold identifiers are a JSON array of JSON strings",
      };
    } else if (new Set(v as string[]).size !== v.length) {
      // "Each string in the array shall contain a unique user-specified hold
      // identifier." A repeated identifier was accepted until 0.109, and a hold
      // released by the party that placed it would then have been released
      // twice over, or not at all, depending on which occurrence was removed.
      const seen = new Set<string>();
      const repeated = (v as string[]).find((x) => seen.size === seen.add(x).size);
      return {
        condition: "invalid", item: HOLD_ID,
        why: `the hold identifier ${JSON.stringify(repeated)} appears more than once, ` +
          "and each identifier is unique",
      };
    } else {
      const now2 = new Set(v as string[]);
      const gone = wasHeld.holds.filter((h) => !now2.has(h));
      if (gone.length > 0) {
        return {
          condition: "conflict", item: HOLD_ID,
          why: `the hold ${JSON.stringify(gone[0])} is not removed by an operation of ` +
            "this document",
        };
      }
    }
  }
  return undefined;
}

/**
 * Whether a supplied metadata field changes anything other than the two things
 * an object under retention or under hold admits.
 *
 * The clause permits exactly two changes to such an object: "an update that
 * moves the instant at which the retention period ends later, or that adds a
 * value to the cdmi_hold_id item". Everything else is refused, because "the
 * object shall not be modified. A CDMI server shall report the conflict
 * condition for an operation that changes the value of such an object, or that
 * changes its metadata, other than the change the third item of this list
 * permits."
 *
 * So the exemption is granted only where the body leaves every other item as it
 * stands. Two holes this closes, both reproduced against a running server:
 *
 *   - the retention policy identifier and the automatic deletion item were
 *     treated as part of the permitted change, since both are retention items,
 *     so an object under hold accepted `cdmi_retention_autodelete` of "true" —
 *     turning "keep this until 2030" into "delete this in 2030", which is the
 *     change retention exists to prevent; and
 *   - a complete replacement supplying nothing but a retention item removed
 *     every other user metadata item of the object, and was exempt because the
 *     body named nothing else.
 *
 * An item supplied with the value the object already holds changes nothing, so a
 * CDMI client that reads a representation, extends the period and writes the
 * whole of it back is not refused for carrying the rest of it.
 *
 * @param before the user metadata the object holds.
 * @param merging whether the body is a merge, in which an item the body does not
 *   name is left alone; in a complete replacement it is removed, which is a
 *   change like any other.
 */
export function changesMore(supplied: Record<string, unknown>,
  before: Record<string, unknown> = {}, merging = true): boolean {
  const same = (a: unknown, b: unknown) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
  // The two items the change may touch, and the instant this server records
  // beside the period, which is not an item a CDMI client can supply and so is
  // not an item a complete replacement can be said to remove.
  const admitted = (k: string) =>
    k === RETENTION_PERIOD || k === HOLD_ID || k === APPLIED_AT;
  for (const k of Object.keys(supplied)) {
    if (admitted(k)) continue;
    if (!same(supplied[k], before[k])) return true;
  }
  if (merging) return false;
  // A complete replacement removes what it does not carry.
  return Object.keys(before).some((k) => !admitted(k) && !(k in supplied));
}

/**
 * Records the instant a retention period was applied, so that a
 * duration is measured from it. The instant is kept while the item is
 * unchanged, so that extending a period does not move the start of the
 * one already in force.
 */
export function recordApplied(
  metadata: Record<string, unknown>,
  before: Record<string, unknown>,
): void {
  const now = metadata[RETENTION_PERIOD];
  if (typeof now !== "string") {
    delete metadata[APPLIED_AT];
    return;
  }
  const unchanged = before[RETENTION_PERIOD] === now &&
    typeof before[APPLIED_AT] === "string";
  metadata[APPLIED_AT] = unchanged ? before[APPLIED_AT] : stamp(Date.now());
}

/** An instant in the form this document uses. */
const stamp = (ms: number): string =>
  new Date(ms).toISOString().replace(/\.(\d{3})Z$/, ".$1000Z");

/** The items reporting what a CDMI server applied. */
export function providedItems(metadata: Record<string, unknown>):
  Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (typeof metadata[RETENTION_PERIOD] === "string") {
    // The provided item reports the instant the period ends, in the
    // start and end form, so that a client reads the instant rather
    // than computing one from a duration and a clock of its own.
    const end = endApplied(metadata);
    const applied = metadata[APPLIED_AT];
    out.cdmi_retention_period_provided = end === undefined
      ? metadata[RETENTION_PERIOD]
      : `${typeof applied === "string" ? applied : stamp(Date.now())}/${stamp(end)}`;
  }
  if (metadata[RETENTION_AUTODELETE] !== undefined) {
    out.cdmi_retention_autodelete_provided = metadata[RETENTION_AUTODELETE];
  }
  if (Array.isArray(metadata[HOLD_ID])) {
    out.cdmi_hold_id_provided = metadata[HOLD_ID];
  }
  return out;
}

/** The condition a fault raises, as the binding reports it. */
export function faultCondition(f: RetentionFault): Error {
  const at = `metadata/${f.item}`;
  // An update that moves the end of a retention period earlier, or
  // that removes a value from the hold item, is the conflict
  // condition, which this document names for both.
  if (f.condition === "conflict") return retentionConflict("%s: %s", f.item, f.why);
  if (f.condition === "forbidden") return forbidden("%s: %s", f.item, f.why);
  return f.condition === "malformed"
    ? malformed("%s: %s", f.item, f.why)
    : invalidField(at, "%s", f.why);
}
