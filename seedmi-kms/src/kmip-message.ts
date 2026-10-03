// The messages of the Key Management Interoperability Protocol Version 1.4:
// the request and response envelopes (section 7), the batch items within
// them, and the attributes operations carry (section 2.1.1). Section and table
// numbers are those of KMIP 1.4.
//
// This module builds and reads messages. It does not decide what a server does
// with one: an operation's semantics belong to kms-core.ts.

import { KMIP_ENUM } from "./kmip-registry.ts";
import { child, children, type Item, k, nameOf, tagOf, TYPE } from "./kmip-ttlv.ts";

// ---------------------------------------------------------------------------
// Versions (6.1)

export interface ProtocolVersion {
  major: number;
  minor: number;
}

/** The version this implementation speaks. */
export const V1_4: ProtocolVersion = { major: 1, minor: 4 };

export const versionText = (v: ProtocolVersion): string => `${v.major}.${v.minor}`;
export const compareVersions = (a: ProtocolVersion, b: ProtocolVersion): number =>
  a.major !== b.major ? a.major - b.major : a.minor - b.minor;

function versionItem(v: ProtocolVersion): Item {
  return k.struct("Protocol Version", [
    k.int("Protocol Version Major", v.major),
    k.int("Protocol Version Minor", v.minor),
  ]);
}

function readVersion(item: Item): ProtocolVersion {
  const major = child(item, "Protocol Version Major");
  const minor = child(item, "Protocol Version Minor");
  if (major?.type !== TYPE.Integer || minor?.type !== TYPE.Integer) {
    throw new KmipMessageError("Invalid Message", "a Protocol Version holds an Integer major and minor number");
  }
  return { major: major.value, minor: minor.value };
}

// ---------------------------------------------------------------------------
// Errors

/**
 * A message, or part of one, that does not conform, with the Result Reason
 * section 11.1 (General Errors) gives for it.
 */
export class KmipMessageError extends Error {
  readonly reason: string;
  constructor(reason: string, message: string) {
    super(message);
    this.name = "KmipMessageError";
    if (KMIP_ENUM["Result Reason"][reason] === undefined) {
      throw new Error(`KMIP 1.4 defines no Result Reason named ${JSON.stringify(reason)}`);
    }
    this.reason = reason;
  }
}

// ---------------------------------------------------------------------------
// Enumerations by name

/** The name of an enumeration value, or its hexadecimal form where none is defined. */
export function enumName(enumeration: string, value: number): string {
  const e = KMIP_ENUM[enumeration];
  for (const [n, v] of Object.entries(e ?? {})) if (v === value) return n;
  return `0x${value.toString(16).padStart(8, "0").toUpperCase()}`;
}

/** The value of an enumeration name, accepting the hexadecimal form of an extension value. */
export function enumValue(enumeration: string, name: string): number {
  const v = KMIP_ENUM[enumeration]?.[name];
  if (v !== undefined) return v;
  if (/^0x[0-9A-Fa-f]{8}$/.test(name)) return parseInt(name, 16);
  throw new Error(`the ${enumeration} enumeration has no value named ${JSON.stringify(name)}`);
}

const enumItem = (tag: string, enumeration: string, name: string): Item =>
  ({ tag: tagOf(tag), type: TYPE.Enumeration, value: enumValue(enumeration, name) });

function readEnum(item: Item | undefined, enumeration: string, what: string): string {
  if (item?.type !== TYPE.Enumeration) throw new KmipMessageError("Invalid Message", `${what} is an Enumeration`);
  return enumName(enumeration, item.value);
}

// ---------------------------------------------------------------------------
// Attributes (2.1.1, 2.1.8)

/**
 * An attribute of a managed object: its name, the index of the instance, and
 * its value. The value is held as an item whose tag is the tag of the
 * attribute's name where KMIP defines one; a custom attribute (3.39) keeps
 * the tag Attribute Value.
 */
export interface Attribute {
  name: string;
  /** "Attribute Indices SHALL start with 0" (2.1.1). */
  index?: number;
  value: Item;
}

/** An attribute from a value built under the attribute's own tag, as k.text(name, ...) builds one. */
export function attribute(value: Item, index?: number): Attribute {
  return { name: nameOf(value.tag), value, ...(index === undefined ? {} : { index }) };
}

/** An Attribute structure: Attribute Name, Attribute Index, Attribute Value (Table 2). */
export function encodeAttribute(a: Attribute): Item {
  return k.struct("Attribute", [
    k.text("Attribute Name", a.name),
    ...(a.index === undefined ? [] : [k.int("Attribute Index", a.index)]),
    { ...a.value, tag: tagOf("Attribute Value") } as Item,
  ]);
}

/** Reads an Attribute structure. */
export function decodeAttribute(item: Item): Attribute {
  if (item.tag !== tagOf("Attribute") || item.type !== TYPE.Structure) {
    throw new KmipMessageError("Invalid Message", "an attribute is an Attribute structure");
  }
  const name = child(item, "Attribute Name");
  const index = child(item, "Attribute Index");
  const value = child(item, "Attribute Value");
  if (name?.type !== TYPE.TextString) throw new KmipMessageError("Invalid Message", "an Attribute has an Attribute Name");
  if (index !== undefined && index.type !== TYPE.Integer) {
    throw new KmipMessageError("Invalid Message", "an Attribute Index is an Integer");
  }
  if (value === undefined) throw new KmipMessageError("Invalid Message", `the attribute ${name.value} has no value`);
  let tag: number;
  try {
    tag = tagOf(name.value);
  } catch {
    // A custom attribute: "The tag type Custom Attribute is not able to
    // identify the particular attribute" (3.39).
    tag = tagOf("Attribute Value");
  }
  return {
    name: name.value,
    ...(index === undefined ? {} : { index: index.value as number }),
    value: { ...value, tag } as Item,
  };
}

/** The Template-Attribute structures of 2.1.8. */
export type AttributeContainer =
  "Template-Attribute" | "Common Template-Attribute" | "Private Key Template-Attribute" | "Public Key Template-Attribute";

/** A Template-Attribute structure of individual attributes. */
export const encodeAttributes = (attrs: Attribute[], container: AttributeContainer = "Template-Attribute"): Item =>
  k.struct(container, attrs.map(encodeAttribute));

const CONTAINERS = new Set(["Template-Attribute", "Common Template-Attribute",
  "Private Key Template-Attribute", "Public Key Template-Attribute"]);

/**
 * The individual attributes of a Template-Attribute structure. Names of
 * templates, which the structure may also hold (Table 29), are not attributes
 * of the object and are not returned; see templateNames.
 */
export function decodeAttributes(item: Item): Attribute[] {
  if (item.type !== TYPE.Structure || !CONTAINERS.has(nameOf(item.tag))) {
    throw new KmipMessageError("Invalid Message", `${nameOf(item.tag)} is not a Template-Attribute structure`);
  }
  return children(item, "Attribute").map(decodeAttribute);
}

/** The Names of templates a Template-Attribute structure refers to. */
export const templateNames = (item: Item): Item[] => children(item, "Name");

// ---------------------------------------------------------------------------
// Fields

/**
 * How a structure's fields are checked. Section 11.1: "The same field is
 * contained in a header/batch item/payload more than once": Invalid Message;
 * "Same major version, different minor versions; unknown fields/fields the
 * server does not understand": "Ignore unknown fields, process rest normally";
 * "Same major & minor version, unknown field": Invalid Field. Fields are read
 * in the order of their table, since structures "SHALL have all of their fields
 * encoded in the order in which they appear in their respective structure
 * descriptions" (9.1.1.4); a field out of order cannot be parsed, which is
 * Invalid Message.
 */
function checkFields(s: Item, what: string, allowed: Record<string, "one" | "many">, v: ProtocolVersion): Item {
  const order = Object.keys(allowed);
  const seen = new Map<string, number>();
  const kept: Item[] = [];
  let last = -1;
  for (const c of s.value as Item[]) {
    const name = nameOf(c.tag);
    const rule = allowed[name];
    if (rule === undefined) {
      if (v.minor === V1_4.minor) throw new KmipMessageError("Invalid Field", `${name} is not a field of ${what}`);
      continue;
    }
    const at = order.indexOf(name);
    if (at < last) throw new KmipMessageError("Invalid Message", `${name} is out of order in ${what}`);
    last = at;
    const n = (seen.get(name) ?? 0) + 1;
    if (rule === "one" && n > 1) throw new KmipMessageError("Invalid Message", `${what} holds ${name} more than once`);
    seen.set(name, n);
    kept.push(c);
  }
  return { ...s, value: kept } as Item;
}

function need(s: Item, name: string, type: number, what: string): Item {
  const c = child(s, name);
  if (c === undefined) throw new KmipMessageError("Invalid Message", `${what} has no ${name}`);
  if (c.type !== type) throw new KmipMessageError("Invalid Message", `${name} of ${what} has the wrong type`);
  return c;
}

function optional(s: Item, name: string, type: number, what: string): Item | undefined {
  const c = child(s, name);
  if (c !== undefined && c.type !== type) throw new KmipMessageError("Invalid Message", `${name} of ${what} has the wrong type`);
  return c;
}

// ---------------------------------------------------------------------------
// Requests

export type BatchErrorContinuation = "Continue" | "Stop" | "Undo";

export interface RequestHeader {
  protocolVersion: ProtocolVersion;
  maximumResponseSize?: number;
  clientCorrelationValue?: string;
  serverCorrelationValue?: string;
  /** "True if the client is able to handle asynchronous responses" (6.7). */
  asynchronousIndicator?: boolean;
  batchErrorContinuationOption?: BatchErrorContinuation;
  batchOrderOption?: boolean;
  /** Milliseconds since the epoch; carried to the second. */
  timeStamp?: number;
}

export interface RequestBatchItem {
  /** An Operation enumeration name, such as "Query"; absent where it could not be read. */
  operation?: string;
  uniqueBatchItemId?: Buffer;
  /** The children of the Request Payload structure. */
  payload: Item[];
  /**
   * Why the batch item could not be read. "Error parsing batch item or payload
   * within batch item": "Batch item fails; Result Status is Operation Failed"
   * (11.1), and the rest of the batch is performed.
   */
  error?: KmipMessageError;
}

export interface Request {
  header: RequestHeader;
  items: RequestBatchItem[];
}

/** "If not specified, then False is assumed (i.e., no implied ordering)" (6.12). */
export const batchOrdered = (h: RequestHeader): boolean => h.batchOrderOption ?? false;

const REQUEST_HEADER: Record<string, "one" | "many"> = {
  "Protocol Version": "one", "Maximum Response Size": "one", "Client Correlation Value": "one",
  "Server Correlation Value": "one", "Asynchronous Indicator": "one", "Attestation Capable Indicator": "one",
  "Attestation Type": "many", "Authentication": "one", "Batch Error Continuation Option": "one",
  "Batch Order Option": "one", "Time Stamp": "one", "Batch Count": "one",
};
const REQUEST_BATCH_ITEM: Record<string, "one" | "many"> = {
  "Operation": "one", "Unique Batch Item ID": "one", "Request Payload": "one", "Message Extension": "one",
};

/** The Request Message structure of a request (Tables 280, 282, 283). */
export function encodeRequest(r: Request): Item {
  if (r.items.length === 0) throw new KmipMessageError("Invalid Message", "a request has a batch item");
  if (r.items.length > 1 && r.items.some((i) => i.uniqueBatchItemId === undefined)) {
    // "REQUIRED if Batch Count > 1" (Table 283).
    throw new KmipMessageError("Invalid Message", "each batch item of a batch of more than one has a Unique Batch Item ID");
  }
  const h = r.header;
  const header: Item[] = [versionItem(h.protocolVersion)];
  if (h.maximumResponseSize !== undefined) header.push(k.int("Maximum Response Size", h.maximumResponseSize));
  if (h.clientCorrelationValue !== undefined) header.push(k.text("Client Correlation Value", h.clientCorrelationValue));
  if (h.serverCorrelationValue !== undefined) header.push(k.text("Server Correlation Value", h.serverCorrelationValue));
  if (h.asynchronousIndicator !== undefined) header.push(k.bool("Asynchronous Indicator", h.asynchronousIndicator));
  if (h.batchErrorContinuationOption !== undefined) {
    header.push(enumItem("Batch Error Continuation Option", "Batch Error Continuation Option", h.batchErrorContinuationOption));
  }
  if (h.batchOrderOption !== undefined) header.push(k.bool("Batch Order Option", h.batchOrderOption));
  if (h.timeStamp !== undefined) header.push(k.date("Time Stamp", h.timeStamp));
  header.push(k.int("Batch Count", r.items.length));
  return k.struct("Request Message", [
    k.struct("Request Header", header),
    ...r.items.map((i) => {
      if (i.operation === undefined) throw new KmipMessageError("Invalid Message", "a request batch item has an Operation");
      return k.struct("Batch Item", [
        enumItem("Operation", "Operation", i.operation),
        ...(i.uniqueBatchItemId === undefined ? [] : [k.bytes("Unique Batch Item ID", i.uniqueBatchItemId)]),
        k.struct("Request Payload", i.payload),
      ]);
    }),
  ]);
}

/**
 * Reads a Request Message. A header that cannot be read throws: "Message cannot
 * be parsed" (11.1). A batch item that cannot be read is returned with its
 * error, to fail alone.
 */
export function decodeRequest(item: Item): Request {
  if (item.tag !== tagOf("Request Message") || item.type !== TYPE.Structure) {
    throw new KmipMessageError("Invalid Message", "a request is a Request Message structure");
  }
  const hsRaw = need(item, "Request Header", TYPE.Structure, "a Request Message");
  const v = readVersion(need(hsRaw, "Protocol Version", TYPE.Structure, "a Request Header"));
  const top = checkFields(item, "a Request Message", { "Request Header": "one", "Batch Item": "many" }, v);
  const hs = checkFields(hsRaw, "a Request Header", REQUEST_HEADER, v);
  const header: RequestHeader = { protocolVersion: v };
  const mrs = optional(hs, "Maximum Response Size", TYPE.Integer, "a Request Header");
  if (mrs) header.maximumResponseSize = mrs.value as number;
  const ccv = optional(hs, "Client Correlation Value", TYPE.TextString, "a Request Header");
  if (ccv) header.clientCorrelationValue = ccv.value as string;
  const scv = optional(hs, "Server Correlation Value", TYPE.TextString, "a Request Header");
  if (scv) header.serverCorrelationValue = scv.value as string;
  const ai = optional(hs, "Asynchronous Indicator", TYPE.Boolean, "a Request Header");
  if (ai) header.asynchronousIndicator = ai.value as boolean;
  const beco = child(hs, "Batch Error Continuation Option");
  if (beco) {
    header.batchErrorContinuationOption = readEnum(beco, "Batch Error Continuation Option",
      "Batch Error Continuation Option") as BatchErrorContinuation;
  }
  const boo = optional(hs, "Batch Order Option", TYPE.Boolean, "a Request Header");
  if (boo) header.batchOrderOption = boo.value as boolean;
  const ts = optional(hs, "Time Stamp", TYPE.DateTime, "a Request Header");
  if (ts) header.timeStamp = Number(ts.value as bigint) * 1000;
  const count = need(hs, "Batch Count", TYPE.Integer, "a Request Header").value as number;

  const batch = children(top, "Batch Item");
  if (batch.length !== count) {
    throw new KmipMessageError("Invalid Message", `the Batch Count is ${count} and the request holds ${batch.length} batch items`);
  }
  if (batch.length === 0) throw new KmipMessageError("Invalid Message", "a request has a batch item");
  const items = batch.map((raw): RequestBatchItem => {
    const out: RequestBatchItem = { payload: [] };
    try {
      if (raw.type !== TYPE.Structure) throw new KmipMessageError("Invalid Message", "a Batch Item is a Structure");
      const b = checkFields(raw, "a Batch Item", REQUEST_BATCH_ITEM, v);
      const id = optional(b, "Unique Batch Item ID", TYPE.ByteString, "a Batch Item");
      if (id) out.uniqueBatchItemId = id.value as Buffer;
      out.operation = readEnum(child(b, "Operation"), "Operation", "the Operation of a Batch Item");
      if (count > 1 && id === undefined) {
        throw new KmipMessageError("Invalid Message", "each batch item of a batch of more than one has a Unique Batch Item ID");
      }
      out.payload = need(b, "Request Payload", TYPE.Structure, "a Batch Item").value as Item[];
    } catch (e) {
      if (!(e instanceof KmipMessageError)) throw e;
      out.error = e;
    }
    return out;
  });
  return { header, items };
}

// ---------------------------------------------------------------------------
// Responses

export interface ResponseHeader {
  protocolVersion: ProtocolVersion;
  /** Milliseconds since the epoch; carried to the second. */
  timeStamp: number;
  clientCorrelationValue?: string;
  serverCorrelationValue?: string;
}

export interface ResponseBatchItem {
  operation?: string;
  uniqueBatchItemId?: Buffer;
  /** A Result Status name: "Success", "Operation Failed", "Operation Pending", "Operation Undone". */
  resultStatus: string;
  /** A Result Reason name; "REQUIRED if Result Status is Failure" (Table 285). */
  resultReason?: string;
  resultMessage?: string;
  asynchronousCorrelationValue?: Buffer;
  /** The children of the Response Payload structure, where there is one. */
  payload?: Item[];
}

export interface Response {
  header: ResponseHeader;
  items: ResponseBatchItem[];
}

const RESPONSE_HEADER: Record<string, "one" | "many"> = {
  "Protocol Version": "one", "Time Stamp": "one", "Nonce": "one", "Attestation Type": "many",
  "Client Correlation Value": "one", "Server Correlation Value": "one", "Batch Count": "one",
};
const RESPONSE_BATCH_ITEM: Record<string, "one" | "many"> = {
  "Operation": "one", "Unique Batch Item ID": "one", "Result Status": "one", "Result Reason": "one",
  "Result Message": "one", "Asynchronous Correlation Value": "one", "Response Payload": "one", "Message Extension": "one",
};

/** The Response Message structure of a response (Tables 281, 284, 285). */
export function encodeResponse(r: Response): Item {
  const h = r.header;
  return k.struct("Response Message", [
    k.struct("Response Header", [
      versionItem(h.protocolVersion),
      k.date("Time Stamp", h.timeStamp),
      ...(h.clientCorrelationValue === undefined ? [] : [k.text("Client Correlation Value", h.clientCorrelationValue)]),
      ...(h.serverCorrelationValue === undefined ? [] : [k.text("Server Correlation Value", h.serverCorrelationValue)]),
      k.int("Batch Count", r.items.length),
    ]),
    ...r.items.map((i) => {
      if (i.resultStatus === "Operation Failed" && i.resultReason === undefined) {
        throw new KmipMessageError("Invalid Message", "a Result Reason is required where the Result Status is a failure");
      }
      return k.struct("Batch Item", [
        ...(i.operation === undefined ? [] : [enumItem("Operation", "Operation", i.operation)]),
        ...(i.uniqueBatchItemId === undefined ? [] : [k.bytes("Unique Batch Item ID", i.uniqueBatchItemId)]),
        enumItem("Result Status", "Result Status", i.resultStatus),
        ...(i.resultReason === undefined ? [] : [enumItem("Result Reason", "Result Reason", i.resultReason)]),
        ...(i.resultMessage === undefined ? [] : [k.text("Result Message", i.resultMessage)]),
        ...(i.asynchronousCorrelationValue === undefined
          ? [] : [k.bytes("Asynchronous Correlation Value", i.asynchronousCorrelationValue)]),
        ...(i.payload === undefined ? [] : [k.struct("Response Payload", i.payload)]),
      ]);
    }),
  ]);
}

/** Reads a Response Message. */
export function decodeResponse(item: Item): Response {
  if (item.tag !== tagOf("Response Message") || item.type !== TYPE.Structure) {
    throw new KmipMessageError("Invalid Message", "a response is a Response Message structure");
  }
  const hsRaw = need(item, "Response Header", TYPE.Structure, "a Response Message");
  const v = readVersion(need(hsRaw, "Protocol Version", TYPE.Structure, "a Response Header"));
  const top = checkFields(item, "a Response Message", { "Response Header": "one", "Batch Item": "many" }, v);
  const hs = checkFields(hsRaw, "a Response Header", RESPONSE_HEADER, v);
  const header: ResponseHeader = {
    protocolVersion: v,
    timeStamp: Number(need(hs, "Time Stamp", TYPE.DateTime, "a Response Header").value as bigint) * 1000,
  };
  const ccv = optional(hs, "Client Correlation Value", TYPE.TextString, "a Response Header");
  if (ccv) header.clientCorrelationValue = ccv.value as string;
  const scv = optional(hs, "Server Correlation Value", TYPE.TextString, "a Response Header");
  if (scv) header.serverCorrelationValue = scv.value as string;
  const count = need(hs, "Batch Count", TYPE.Integer, "a Response Header").value as number;
  const batch = children(top, "Batch Item");
  if (batch.length !== count) {
    throw new KmipMessageError("Invalid Message", `the Batch Count is ${count} and the response holds ${batch.length} batch items`);
  }
  const items = batch.map((raw): ResponseBatchItem => {
    const b = checkFields(raw, "a Batch Item", RESPONSE_BATCH_ITEM, v);
    const out: ResponseBatchItem = {
      resultStatus: readEnum(child(b, "Result Status"), "Result Status", "the Result Status of a Batch Item"),
    };
    const op = child(b, "Operation");
    if (op) out.operation = readEnum(op, "Operation", "the Operation of a Batch Item");
    const id = optional(b, "Unique Batch Item ID", TYPE.ByteString, "a Batch Item");
    if (id) out.uniqueBatchItemId = id.value as Buffer;
    const reason = child(b, "Result Reason");
    if (reason) out.resultReason = readEnum(reason, "Result Reason", "the Result Reason of a Batch Item");
    if (out.resultStatus === "Operation Failed" && out.resultReason === undefined) {
      throw new KmipMessageError("Invalid Message", "a Result Reason is required where the Result Status is a failure");
    }
    const msg = optional(b, "Result Message", TYPE.TextString, "a Batch Item");
    if (msg) out.resultMessage = msg.value as string;
    const acv = optional(b, "Asynchronous Correlation Value", TYPE.ByteString, "a Batch Item");
    if (acv) out.asynchronousCorrelationValue = acv.value as Buffer;
    const payload = optional(b, "Response Payload", TYPE.Structure, "a Batch Item");
    if (payload) out.payload = payload.value as Item[];
    return out;
  });
  return { header, items };
}

// ---------------------------------------------------------------------------
// Payloads: Discover Versions (4.26) and Query (4.25)

/** Discover Versions: versions "ranked in decreasing order of preference". */
export const discoverVersionsPayload = (versions: ProtocolVersion[]): Item[] => versions.map(versionItem);

export function readDiscoverVersions(payload: Item[]): ProtocolVersion[] {
  for (const p of payload) {
    if (p.tag !== tagOf("Protocol Version")) {
      throw new KmipMessageError("Invalid Field", `${nameOf(p.tag)} is not a field of a Discover Versions payload`);
    }
  }
  return payload.map(readVersion);
}

/** Query: the functions queried, as Query Function names. */
export const queryPayload = (functions: string[]): Item[] =>
  functions.map((f) => enumItem("Query Function", "Query Function", f));

export interface QueryResult {
  operations: string[];
  objectTypes: string[];
  vendorIdentification?: string;
  serverInformation?: Item;
  applicationNamespaces: string[];
  /** Fields this module does not interpret, kept in order after those it does. */
  other: Item[];
}

/** The fields of a Query response payload, in the order of Table 223. */
const QUERY_ORDER = [
  "Operation", "Object Type", "Vendor Identification", "Server Information", "Application Namespace",
  "Extension Information", "Attestation Type", "RNG Parameters", "Profile Information",
  "Validation Information", "Capability Information", "Client Registration Method",
];

export function encodeQueryResult(q: QueryResult): Item[] {
  return [
    ...q.operations.map((o) => enumItem("Operation", "Operation", o)),
    ...q.objectTypes.map((o) => enumItem("Object Type", "Object Type", o)),
    ...(q.vendorIdentification === undefined ? [] : [k.text("Vendor Identification", q.vendorIdentification)]),
    ...(q.serverInformation === undefined ? [] : [q.serverInformation]),
    ...q.applicationNamespaces.map((n) => k.text("Application Namespace", n)),
    ...q.other,
  ];
}

export function decodeQueryResult(payload: Item[]): QueryResult {
  const q: QueryResult = { operations: [], objectTypes: [], applicationNamespaces: [], other: [] };
  let last = -1;
  for (const p of payload) {
    const name = nameOf(p.tag);
    const at = QUERY_ORDER.indexOf(name);
    if (at < 0) throw new KmipMessageError("Invalid Field", `${name} is not a field of a Query response`);
    if (at < last) throw new KmipMessageError("Invalid Message", `${name} is out of order in a Query response`);
    last = at;
    if (name === "Operation") q.operations.push(readEnum(p, "Operation", "an Operation"));
    else if (name === "Object Type") q.objectTypes.push(readEnum(p, "Object Type", "an Object Type"));
    else if (name === "Vendor Identification" && p.type === TYPE.TextString) q.vendorIdentification = p.value;
    else if (name === "Server Information") q.serverInformation = p;
    else if (name === "Application Namespace" && p.type === TYPE.TextString) q.applicationNamespaces.push(p.value);
    else q.other.push(p);
  }
  return q;
}
