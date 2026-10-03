// Representations of a value.
//
// "A member of the cdmi_representations item contains the metadata of the
// representation it names ... Where a representation is selected, an item
// contained within the member that names that representation shall replace the
// item of the same name contained in the 'metadata' field of the object, for that
// operation and for that operation alone. An item that the member does not
// contain is taken from the 'metadata' field unchanged."
//
// EXAMPLE 11.1 of the metadata clause is a data object held as a JPEG and as a
// PNG, which is what this module provides: a value that is one of the two raster
// media types raster.ts handles has a representation in the other, derived when
// it is wanted.
//
// What this module decides, and what it leaves to others:
//
//   * which representations a value has — here;
//   * the octets of one of them — here, through raster.ts;
//   * which of them is the default — here, from the item a CDMI client set;
//   * how a CDMI client selects one — not here. The protocol bindings "define no
//     selection of a representation of a value", and the negotiation belongs to
//     the HTTP export (exports.ts).
//
// Derived on each read, by decision: nothing is stored but the value as written.
// The consequence is stated plainly because it is the cost of that decision —
// reporting the item requires the length of every representation, so reading the
// metadata of an object transcodes its value once per representation it does not
// hold. A single operation derives each at most once, through the cache an
// operation carries; across operations nothing is kept.

import { createHash } from "node:crypto";
import { decode, encode, JPEG, PNG, RasterError, sniff } from "./raster.ts";

/**
 * The largest value this server will decode in order to derive a representation
 * of it. A decoded image costs four octets of memory for every octet of picture,
 * and a derivation happens on each read, so this is what keeps one request from
 * taking the server with it.
 */
export const REPRESENTABLE_LIMIT = 16 * 1024 * 1024;

export let VALUE_REPRESENTATIONS = true;
export const setValueRepresentations = (on: boolean): void => { VALUE_REPRESENTATIONS = on; };

/** The media types a value may be held in and derived to. */
export const RASTER_TYPES = [JPEG, PNG];

/** The name of a member of the item: the media type with the solidus encoded. */
export const memberName = (type: string): string => type.replace("/", "%2F");

/** The media type a member name names, or nothing where the name is not one. */
export function typeOfMember(name: string): string | undefined {
  const type = name.replace("%2F", "/").replace("%2f", "/");
  return RASTER_TYPES.includes(type) ? type : undefined;
}

/**
 * What a representation of a value is: its media type, its octets and the
 * storage system metadata that describes it rather than the object.
 */
export interface Representation {
  type: string;
  bytes: Buffer;
  /** The length of these octets, which is the cdmi_size of this representation. */
  size: number;
  /** The hash of these octets, where the object asked for one. */
  hash?: string;
}

/**
 * The work of one operation, so that a value is transcoded once within it
 * however many times the operation asks.
 *
 * Deriving on each read is the deployment's choice; deriving twice in one read is
 * nobody's. Reporting the item needs the length of a representation and serving
 * it needs the octets, and both arise within a single request.
 */
export class Derivations {
  private readonly held = new Map<string, Representation | undefined>();

  /** The representation of a type, derived at most once here. */
  of(value: Buffer, type: string, algorithm?: string): Representation | undefined {
    const key = `${type}\u0000${algorithm ?? ""}`;
    if (this.held.has(key)) return this.held.get(key);
    const made = derive(value, type, algorithm);
    this.held.set(key, made);
    return made;
  }
}

/**
 * The media type a value is held in, by its octets.
 *
 * The signature and not the "mimetype": a value whose mimetype claims image/png
 * and whose octets are a JPEG is a JPEG, and what this server can produce from it
 * follows what it actually holds. A value that is neither has one representation
 * and this returns nothing.
 */
export const heldType = (value: Buffer): string | undefined => sniff(value);

/**
 * The representations a value has: the one it is held in, then the others. The
 * order is the order the members are reported in, which matters — "among
 * representations of equal highest quality it shall prefer the default, then the
 * first listed".
 */
export function typesOf(value: Buffer): string[] {
  const held = heldType(value);
  if (held === undefined) return [];
  return [held, ...RASTER_TYPES.filter((t) => t !== held)];
}

/**
 * One representation of a value, derived where it is not the one held.
 *
 * Nothing here is an error of the object. A value whose octets do not parse as
 * the image they appear to be, or that is a kind raster.ts declines — a
 * progressive JPEG, an interlaced or sixteen-bit PNG — simply has no second
 * representation, and the item reports the one it has.
 */
export function derive(value: Buffer, type: string, algorithm?: string): Representation | undefined {
  const held = heldType(value);
  if (held === undefined || !RASTER_TYPES.includes(type)) return undefined;
  if (type === held) return described(value, type, algorithm);
  let bytes: Buffer;
  try {
    bytes = encode(decode(value, held), type);
  } catch (e) {
    if (e instanceof RasterError) return undefined;
    throw e;
  }
  return described(bytes, type, algorithm);
}

function described(bytes: Buffer, type: string, algorithm?: string): Representation {
  return {
    type,
    bytes,
    size: bytes.length,
    ...(algorithm === undefined
      ? {}
      : { hash: createHash(algorithm).update(bytes).digest("hex").toUpperCase() }),
  };
}

/**
 * The default representation of a value: the one a CDMI client asked for where it
 * is one the server holds, and otherwise the one the value is held in.
 *
 * "A CDMI client specifies the representation it prefers in the
 * cdmi_representation_default data system metadata item ... Where that item is
 * absent, or names a representation the CDMI server does not hold or the CDMI
 * client is not permitted to read, the CDMI server determines the default
 * representation." The one held is what this server determines, so that no
 * transcoding happens unless a CDMI client asks for it.
 */
export function defaultType(value: Buffer, wanted?: unknown): string | undefined {
  const types = typesOf(value);
  if (types.length === 0) return undefined;
  if (typeof wanted === "string") {
    // The item may name the media type, or the member name that encodes it.
    const named = RASTER_TYPES.includes(wanted) ? wanted : typeOfMember(wanted);
    if (named !== undefined && types.includes(named)) return named;
  }
  return types[0];
}

/**
 * The members of the cdmi_representations item, each carrying only the items in
 * which that representation differs from the "metadata" field of the object.
 *
 * The overlay rule makes an omitted item mean the object's, so a member that
 * repeats an item it shares with the object says nothing a member that omits it
 * does not. EXAMPLE 11.1 repeats them; reporting only the differences is the same
 * statement, smaller, and is what makes a member worth reading — what is in it is
 * exactly what is particular to that representation.
 *
 * A member may therefore be empty, and an empty member is still reported: the set
 * of member names is how a CDMI client discovers which representations exist, and
 * "{}" against a name says that this representation exists and differs in
 * nothing. That is only ever true of the default, whose items are the object's.
 */
export function membersOf(value: Buffer, object: Record<string, unknown>,
  algorithm: string | undefined, derivations: Derivations): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const type of typesOf(value)) {
    const r = derivations.of(value, type, algorithm);
    if (r === undefined) continue;
    const member: Record<string, unknown> = {};
    // The items that describe a representation rather than the object. The
    // object's own items are those of the default representation, so comparing
    // against them is what makes the default's member empty. Only these two
    // differ between the representations of one value here: the others —
    // the times, the counts, the owner, the access control list — are of the
    // object, and a member that repeated them would be asserting they differ.
    if (String(object.cdmi_size ?? "") !== String(r.size)) member.cdmi_size = String(r.size);
    if (r.hash !== undefined && object.cdmi_hash !== r.hash) member.cdmi_hash = r.hash;
    out[memberName(type)] = member;
  }
  return out;
}

/**
 * The metadata of an object as one representation states it: the object's items,
 * with the items of that representation's member replacing those of the same name.
 *
 * "Where a representation is selected, an item contained within the member ...
 * shall replace the item of the same name contained in the 'metadata' field of the
 * object, for that operation and for that operation alone ... The stored metadata
 * of the object is not altered by the selection of a representation."
 */
export function overlay(metadata: Record<string, unknown>, type: string): Record<string, unknown> {
  const item = metadata.cdmi_representations;
  if (item === null || typeof item !== "object" || Array.isArray(item)) return metadata;
  const member = (item as Record<string, unknown>)[memberName(type)];
  if (member === null || typeof member !== "object" || Array.isArray(member)) return metadata;
  return { ...metadata, ...(member as Record<string, unknown>) };
}

/**
 * The representation a request prefers, by proactive content negotiation on
 * `Accept`, or nothing where none is acceptable.
 *
 * "By proactive content negotiation on Accept as Section 12.5.1 of RFC 9110
 * specifies. Where Accept is absent it shall select the default representation;
 * among representations of equal highest quality it shall prefer the default,
 * then the first listed; where none is acceptable it shall return 406 Not
 * Acceptable."
 *
 * The caller decides what to do with nothing: the same subclause says "a CDMI
 * server holding one representation is not required to return 406 for a
 * non-matching Accept", so a value with one representation is served as it is.
 */
export function negotiate(accept: string | undefined, types: string[],
  fallback: string): string | undefined {
  if (accept === undefined || accept.trim() === "") return fallback;
  const ranges = accept.split(",").map((part) => {
    const [head, ...params] = part.split(";");
    let q = 1;
    for (const p of params) {
      const m = /^\s*q\s*=\s*([0-9.]+)\s*$/i.exec(p);
      if (m !== null) q = Number(m[1]);
    }
    return { range: (head ?? "").trim().toLowerCase(), q: Number.isFinite(q) ? q : 0 };
  }).filter((r) => r.range !== "");
  if (ranges.length === 0) return fallback;
  /** The quality a media range gives a media type, most specific range winning. */
  const quality = (type: string): number => {
    const [kind] = type.split("/");
    let best: number | undefined;
    let precision = -1;
    for (const r of ranges) {
      // "*/*" is less specific than "type/*", which is less specific than an
      // exact match, and the most specific matching range decides the quality.
      const rank = r.range === type ? 2 : r.range === `${kind}/*` ? 1 : r.range === "*/*" ? 0 : -1;
      if (rank > precision) { precision = rank; best = r.q; }
    }
    return best ?? 0;
  };
  let chosen: string | undefined;
  let top = 0;
  for (const type of types) {
    const q = quality(type);
    // A quality of zero means "not acceptable" and never selects.
    if (q <= 0) continue;
    // Strictly greater, so that the first of an equal-quality set wins — and the
    // default is placed first by typesOf, which orders the held one first, so the
    // caller passes the types in the order it wants them preferred.
    if (q > top) { top = q; chosen = type; }
  }
  return chosen;
}

/**
 * The types of a value, ordered so that the default is preferred first, which is
 * the order negotiate() breaks a tie in.
 */
export function orderedFor(value: Buffer, def: string): string[] {
  const all = typesOf(value);
  return [def, ...all.filter((t) => t !== def)];
}
