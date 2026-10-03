// The service-level data system metadata items, and what this server achieves
// for each.
//
// A data system metadata item "specifies what a CDMI client requires of the CDMI
// server for an object: the data services it is to provide, and the constraints
// under which it is to provide them", and the corresponding provided item
// "specifies what the CDMI server can achieve for the object at this time, and
// the two differ where the CDMI server does not achieve what was requested". For
// this family the two differ a great deal: a CDMI client may ask for four copies
// on three infrastructures 500 km apart, and this server keeps one copy of one
// object in one directory of one machine. The request is stored either way —
// "a CDMI server shall preserve an item it does not support" — and the provided
// item says what actually happens.
//
// Where a value comes from:
//
//   - the number of copies, the number of infrastructures and the distance
//     between them follow from the architecture and are not configurable. One
//     copy, one infrastructure, and no distance between a thing and itself;
//   - the latency and the throughput are measured, once, when the server starts,
//     against the directory the store lives in. A configured figure would be a
//     claim; a measured one is what this deployment did when it was asked;
//   - the geographic placement, the recovery point objective and the recovery
//     time objective are facts about the deployment that no measurement reveals,
//     and come from [service_level] in the configuration. Where they are not
//     configured the provided items are absent, which is what the clause
//     provides for: "a CDMI server shall report a provided item where it supports
//     the corresponding data system metadata item and can determine what it
//     achieves, and shall not report one where it cannot."
//
// Only the geographic placement changes what an operation does: a placement that
// permits no location this server has is the forbidden condition, as the item's
// own definition requires.

import { forbidden, invalidField } from "./problems.ts";

export const DATA_REDUNDANCY = "cdmi_data_redundancy";
export const IMMEDIATE_REDUNDANCY = "cdmi_immediate_redundancy";
export const INFRASTRUCTURE_REDUNDANCY = "cdmi_infrastructure_redundancy";
export const DATA_DISPERSION = "cdmi_data_dispersion";
export const GEOGRAPHIC_PLACEMENT = "cdmi_geographic_placement";
export const LATENCY = "cdmi_latency";
export const THROUGHPUT = "cdmi_throughput";
export const RPO = "cdmi_RPO";
export const RTO = "cdmi_RTO";

/** The items of this family, in the order Annex D lists them. */
export const SERVICE_LEVEL_ITEMS = [
  DATA_REDUNDANCY, IMMEDIATE_REDUNDANCY, INFRASTRUCTURE_REDUNDANCY,
  DATA_DISPERSION, GEOGRAPHIC_PLACEMENT, LATENCY, THROUGHPUT, RPO, RTO,
];

/** Their provided items, each named for the item it reports on. */
export const SERVICE_LEVEL_PROVIDED = SERVICE_LEVEL_ITEMS
  .map((k) => `${k}_provided`);

/**
 * The items whose value is "a positive numeric string". Each is validated
 * because a CDMI client that writes "lots" has asked for nothing, and the item's
 * own words are that where it "is not set to a positive numeric string, this data
 * system metadata item shall not be used" — so a value that is not one is
 * refused rather than stored and silently disregarded.
 */
const NUMERIC = [
  DATA_REDUNDANCY, INFRASTRUCTURE_REDUNDANCY, DATA_DISPERSION, LATENCY,
  THROUGHPUT, RPO, RTO,
];

/** What this deployment achieves, as the server starts knows it. */
export interface ServiceLevel {
  /** Measured at startup: the time to the first byte of a value, in ms. */
  latency?: number;
  /** Measured at startup: the rate at which a value is retrieved, in bytes/s. */
  throughput?: number;
  /** [service_level] regions: where this deployment stores objects. */
  regions?: string[];
  /** [service_level] rpo: the recovery point objective, in seconds. */
  rpo?: string;
  /** [service_level] rto: the recovery time objective, in seconds. */
  rto?: string;
}

/**
 * A country code of ISO 3166-1 alpha-2, or a subdivision code of ISO 3166-2.
 * The codes themselves are not enumerated here: this server holds no copy of
 * either register, and a stale copy would refuse a code that had been assigned
 * since. The form is checked, which is what distinguishes "CA-BC" from "Canada".
 */
const COUNTRY = /^[A-Z]{2}$/;
const SUBDIVISION = /^[A-Z]{2}-[A-Z0-9]{1,3}$/;

/** Whether one identifier of a placement list is well formed, "!" aside. */
const wellFormed = (code: string): boolean =>
  code === "*" || COUNTRY.test(code) || SUBDIVISION.test(code);

/**
 * Whether a candidate location is the region an identifier names, or lies within
 * it. "Evaluation of each candidate storage location stopping when the candidate
 * location is a permitted or prohibited region **or is contained within** a
 * permitted or prohibited region": a subdivision is contained within its country,
 * and every region is contained within "*".
 */
function within(candidate: string, region: string): boolean {
  if (region === "*") return true;
  if (candidate === region) return true;
  // "CA-BC" is within "CA"; "CA" is not within "CA-BC".
  return COUNTRY.test(region) && candidate.startsWith(`${region}-`);
}

/**
 * Whether a placement list permits a candidate location.
 *
 * "The list is evaluated, in order, from left to right, with evaluation of each
 * candidate storage location stopping when the candidate location is a permitted
 * or prohibited region or is contained within a permitted or prohibited region.
 * In addition to the ISO 3166 codes, "*" shall indicate all regions. If a
 * candidate location does not match any of the entries in the list, the candidate
 * location shall be considered to be prohibited."
 *
 * So the first entry that matches decides, an entry beginning with "!" prohibits,
 * and falling off the end prohibits.
 */
export function placementPermits(list: string[], candidate: string): boolean {
  for (const entry of list) {
    const excluded = entry.startsWith("!");
    const region = excluded ? entry.slice(1) : entry;
    if (within(candidate, region)) return !excluded;
  }
  return false;
}

/**
 * Checks the service-level items a CDMI client has supplied, and reports the
 * condition each item's own definition names for a value it does not admit.
 *
 * The geographic placement is the one item with an effect beyond the metadata:
 * "when this data system metadata item is present and does not contain valid
 * geopolitical identifiers, the CDMI server shall report the invalid field
 * condition", and "when this data system metadata item is present and valid, but
 * no available storage locations are permitted, the CDMI server shall report the
 * forbidden condition".
 *
 * @param effective the items that apply to the object once inheritance is
 *   resolved, since a placement set on a container object governs what may be
 *   created within it as much as one set on the object itself.
 * @param where the locations this deployment stores objects in, from the
 *   configuration. Where none is configured the placement is validated and not
 *   evaluated: a server that does not know where it is cannot say that a list
 *   permits nowhere.
 */
export function checkServiceLevel(supplied: Record<string, unknown>,
  effective: Record<string, unknown> = supplied, where: string[] = []): void {
  for (const item of NUMERIC) {
    if (!(item in supplied)) continue;
    const v = supplied[item];
    if (v === null || v === undefined) continue;
    if (typeof v !== "string" || !/^[1-9][0-9]*$/.test(v)) {
      throw invalidField(`metadata/${item}`,
        "%s is a positive numeric string", item);
    }
  }

  if (IMMEDIATE_REDUNDANCY in supplied) {
    const v = supplied[IMMEDIATE_REDUNDANCY];
    if (v !== null && v !== undefined && v !== "true" && v !== "false") {
      // The item is used where it is "true" and not used otherwise, so "false"
      // is admitted as the way a CDMI client turns it off, and anything else is
      // a value the item does not define.
      throw invalidField(`metadata/${IMMEDIATE_REDUNDANCY}`,
        '%s is "true" or "false"', IMMEDIATE_REDUNDANCY);
    }
  }

  if (GEOGRAPHIC_PLACEMENT in supplied) {
    const v = supplied[GEOGRAPHIC_PLACEMENT];
    if (v !== null && v !== undefined) {
      if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
        throw invalidField(`metadata/${GEOGRAPHIC_PLACEMENT}`,
          "%s is a JSON array of geopolitical identifiers", GEOGRAPHIC_PLACEMENT);
      }
      for (const raw of v as string[]) {
        const code = raw.startsWith("!") ? raw.slice(1) : raw;
        if (!wellFormed(code)) {
          throw invalidField(`metadata/${GEOGRAPHIC_PLACEMENT}`,
            "%j is not a country code of ISO 3166-1, a subdivision code of " +
            "ISO 3166-2, or %j", raw, "*");
        }
      }
    }
  }

  // The list that applies after inheritance, which is the one the object is
  // stored under. An empty array permits nothing: "if a candidate location does
  // not match any of the entries in the list, the candidate location shall be
  // considered to be prohibited", and no entry matches.
  const applies = effective[GEOGRAPHIC_PLACEMENT];
  if (where.length > 0 && Array.isArray(applies) &&
    (applies as unknown[]).every((x) => typeof x === "string")) {
    const list = applies as string[];
    const permitted = where.filter((loc) => placementPermits(list, loc));
    if (permitted.length === 0) {
      throw forbidden(
        "the geographic placement requested permits no location this CDMI server " +
        "stores objects in, which %s",
        where.length === 1 ? `is ${where[0]}` : `are ${where.join(", ")}`);
    }
  }
}

/**
 * The provided items to report for an object, given the items that apply to it
 * after inheritance and what this deployment achieves.
 *
 * Each is reported only where the corresponding request is set on the object or
 * inherited by it. That is a deliberate divergence from the clause, which has a
 * CDMI server "report a provided item whether or not the corresponding data
 * system metadata item is set, since a CDMI server provides a level of service
 * for an object whether or not a CDMI client has requested one" — followed
 * literally, a deployment that supports this family puts nine items on the
 * metadata of every object it holds, most of them constants. **ECR-234A** asks
 * for the condition to be the request.
 */
export function serviceLevelProvided(effective: Record<string, unknown>,
  level: ServiceLevel = achieved): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const asked = (item: string) => {
    const v = effective[item];
    return v !== undefined && v !== null && v !== "";
  };

  // "Contains the current number of complete copies of the data object at this
  // time." One: the store holds one value file per object, on one file system.
  if (asked(DATA_REDUNDANCY)) out[`${DATA_REDUNDANCY}_provided`] = "1";

  // "If present and set to true, indicates if immediate redundancy is provided
  // for the object." It is provided for the object that asks for it: the value
  // of such an object is committed to persistent storage before the operation
  // completes (store.immediateRedundancy), which for one copy is what the item
  // asks — "at least the number of copies indicated in cdmi_data_redundancy
  // contain the newly written value before the operation completes".
  if (asked(IMMEDIATE_REDUNDANCY)) {
    out[`${IMMEDIATE_REDUNDANCY}_provided`] =
      effective[IMMEDIATE_REDUNDANCY] === "true" ? "true" : "false";
  }

  // "Contains the current number of independent storage infrastructures
  // supporting the data currently operating." One.
  if (asked(INFRASTRUCTURE_REDUNDANCY)) {
    out[`${INFRASTRUCTURE_REDUNDANCY}_provided`] = "1";
  }

  // "Contains the current lowest distance (km) between any two infrastructures
  // hosting the data." There is one infrastructure, so there is no pair of them
  // and no distance between any two; zero is reported, as the distance from the
  // one infrastructure to itself, which is also the truthful answer to what a
  // CDMI client asking for dispersion wants to know. The clause does not say what
  // to report where there is no pair (ECR-234A).
  if (asked(DATA_DISPERSION)) out[`${DATA_DISPERSION}_provided`] = "0";

  // "Contains the geopolitical identifiers ... of the regions in which the object
  // is stored", which is where this deployment is, and is configuration: no
  // measurement tells a server which subdivision it is running in.
  if (asked(GEOGRAPHIC_PLACEMENT) && level.regions !== undefined &&
    level.regions.length > 0) {
    out[`${GEOGRAPHIC_PLACEMENT}_provided`] = level.regions;
  }

  // Measured when the server started, against the directory the store lives in.
  if (asked(LATENCY) && level.latency !== undefined) {
    out[`${LATENCY}_provided`] = String(level.latency);
  }
  if (asked(THROUGHPUT) && level.throughput !== undefined) {
    out[`${THROUGHPUT}_provided`] = String(level.throughput);
  }

  // The recovery objectives, which are properties of a backup arrangement this
  // server does not make and cannot discover. Configured or absent.
  if (asked(RPO) && level.rpo !== undefined) out[`${RPO}_provided`] = level.rpo;
  if (asked(RTO) && level.rto !== undefined) out[`${RTO}_provided`] = level.rto;
  return out;
}

/**
 * What this deployment achieves, set once when the server starts: the configured
 * facts together with the measured ones. Held here rather than threaded through
 * every report of an object's metadata, as the value-representation switch and the
 * set of base URIs of this server are.
 */
let achieved: ServiceLevel = {};

export function setServiceLevel(level: ServiceLevel): void {
  achieved = level;
}

/** What was set, for a startup announcement and for a test to assert. */
export function serviceLevelAchieved(): ServiceLevel {
  return achieved;
}

/** Whether a configured region is well formed, for the configuration reader. */
export function regionFault(code: string): string | undefined {
  return wellFormed(code) && code !== "*"
    ? undefined
    : `${JSON.stringify(code)} is a country code of ISO 3166-1 or a subdivision ` +
      "code of ISO 3166-2, such as CA or CA-BC";
}

/**
 * Measures the latency and the throughput of this deployment, once, when the
 * server starts.
 *
 * The item defines the latency as "a desired maximum time to first byte, in
 * milliseconds ... as measured from the edge of the cloud and factoring out any
 * propagation latency between the CDMI client and the CDMI server", and the
 * throughput as "a desired maximum data rate on retrieve, in bytes per second ...
 * as measured from the edge of the cloud and factoring out any bandwidth
 * capability between the CDMI client and the CDMI server". Both are therefore
 * measured inside the server: the time to open a value and read its first byte,
 * and the rate at which the whole of it is read. The network between the client
 * and this server is what the definitions exclude, and it is what this
 * measurement excludes.
 *
 * The file is written into the directory the store lives in, so the figures are
 * of the storage this deployment actually keeps values on, and is removed
 * afterwards. Where the value is still in the page cache of the operating system
 * the figures are of that cache, which is what a retrieval of a recently written
 * value costs here, and the item asks what a retrieval costs.
 */
export async function measureServiceLevel(dir: string): Promise<{
  latency: number;
  throughput: number;
}> {
  const { open, unlink } = await import("node:fs/promises");
  const path = await import("node:path");
  const file = path.join(dir, `.seedmi-measure-${process.pid}`);
  // Four mebibytes: enough for a rate that is not dominated by the timer's
  // resolution, small enough that starting the server is not delayed.
  const SIZE = 4 * 1024 * 1024;
  const block = Buffer.alloc(SIZE, 0x5a);
  const latencies: number[] = [];
  const rates: number[] = [];
  try {
    const w = await open(file, "w");
    try {
      await w.write(block, 0, SIZE, 0);
      // Committed, so that what is measured is a read of stored bytes and not of
      // a write that has not landed.
      await w.sync();
    } finally {
      await w.close();
    }
    const one = Buffer.alloc(1);
    const whole = Buffer.alloc(SIZE);
    for (let i = 0; i < 3; i += 1) {
      let began = process.hrtime.bigint();
      const fh = await open(file, "r");
      try {
        await fh.read(one, 0, 1, 0);
        // Milliseconds, as the item states, from the moment the value was asked
        // for to the moment its first byte was in hand.
        latencies.push(Number(process.hrtime.bigint() - began) / 1e6);
        began = process.hrtime.bigint();
        await fh.read(whole, 0, SIZE, 0);
        const seconds = Number(process.hrtime.bigint() - began) / 1e9;
        if (seconds > 0) rates.push(SIZE / seconds);
      } finally {
        await fh.close();
      }
    }
  } finally {
    try {
      await unlink(file);
    } catch { /* nothing to remove */ }
  }
  const median = (xs: number[]): number =>
    [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)] ?? 0;
  return {
    // A latency of less than a millisecond is reported as one: the item is in
    // milliseconds and is "a positive numeric string", so zero would say that a
    // retrieval takes no time, which is both untrue and not a positive number.
    latency: Math.max(1, Math.round(median(latencies))),
    throughput: Math.max(1, Math.round(median(rates))),
  };
}
