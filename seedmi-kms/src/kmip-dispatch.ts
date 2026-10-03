// The server side of KMIP 1.4 between the transport and the core: a decoded
// Request Message in, a Response Message out. It reads each operation's request
// payload (section 4), performs the batch against kms-core.ts, and writes each
// response payload. What the transport establishes, the identity of the client,
// arrives as `who`. Section and table numbers are those of KMIP 1.4.

import {
  type Attribute, batchOrdered, compareVersions, decodeAttribute, decodeAttributes, decodeRequest,
  discoverVersionsPayload, encodeAttribute, encodeAttributes, encodeQueryResult, encodeResponse, enumName,
  KmipMessageError, type ProtocolVersion, readDiscoverVersions, type RequestBatchItem, type ResponseBatchItem,
  templateNames, V1_4, versionText,
} from "./kmip-message.ts";
import { child, children, encode, type Item, k, nameOf, tagOf, TYPE } from "./kmip-ttlv.ts";
import { KmsCore, KmsError, type ObjectType, OBJECT_TYPES, type WrappingSpecification } from "./kms-core.ts";
import { readParams } from "./kms-crypto.ts";

export interface DispatchOptions {
  core: KmsCore;
  vendorIdentification?: string;
  now?: () => number;
}

/**
 * The versions this server speaks, most preferred first: 1.4 and, since
 * "Servers and clients SHALL support backward compatibility with versions of the
 * protocol with the same major version" (6.1), every earlier 1.x.
 */
export const SERVER_VERSIONS: ProtocolVersion[] = [4, 3, 2, 1, 0].map((minor) => ({ major: 1, minor }));

/** The operations this server performs. */
export const OPERATIONS = [
  "Create", "Create Key Pair", "Register", "Re-key", "Locate", "Get", "Get Attributes", "Get Attribute List",
  "Add Attribute", "Modify Attribute", "Delete Attribute", "Activate", "Revoke", "Destroy", "Query",
  "Re-key Key Pair", "Discover Versions", "Encrypt", "Decrypt", "Sign", "Signature Verify", "MAC", "MAC Verify",
] as const;

/** Operations performed without an authenticated client (KMIP Profiles 1.4, 3.1.3). */
const UNAUTHENTICATED = new Set(["Query", "Discover Versions"]);

/** A batch item's context: the identity and the ID Placeholder. */
interface Context {
  who: string | undefined;
  placeholder: string | undefined;
  /** Whether the ID Placeholder may stand in for an omitted Unique Identifier. */
  placeholderUsable: boolean;
}

// ---------------------------------------------------------------------------
// Reading payloads

const text = (item: Item | undefined): string | undefined =>
  item?.type === TYPE.TextString ? item.value : undefined;

function one(payload: Item[], name: string): Item | undefined {
  const found = payload.filter((p) => p.tag === tagOf(name));
  // "The same field is contained in a header/batch item/payload more than once": Invalid Message (11.1).
  if (found.length > 1) throw new KmsError("Invalid Message", `${name} is given more than once`);
  return found[0];
}

/**
 * The Unique Identifier a request names, or the ID Placeholder where it names
 * none: "If the Batch Error Continuation Option is set to Stop and the Batch
 * Order Option is set to true, then subsequent operations in the batched request
 * MAY make use of the ID Placeholder" (section 4).
 */
function uidOf(payload: Item[], ctx: Context, name = "Unique Identifier"): string {
  const item = one(payload, name);
  if (item !== undefined) {
    if (item.type !== TYPE.TextString) throw new KmsError("Invalid Field", `a ${name} is a Text String`);
    return item.value;
  }
  if (!ctx.placeholderUsable) {
    throw new KmsError("Missing Data", "no Unique Identifier is given, and the ID Placeholder is usable only where " +
      "the Batch Order Option is true and the Batch Error Continuation Option is Stop");
  }
  if (ctx.placeholder === undefined) {
    throw new KmsError("Missing Data", "no Unique Identifier is given, and the ID Placeholder holds none");
  }
  return ctx.placeholder;
}

function objectTypeOf(payload: Item[]): ObjectType {
  const item = one(payload, "Object Type");
  if (item?.type !== TYPE.Enumeration) throw new KmsError("Invalid Message", "an Object Type is required");
  const type = enumName("Object Type", item.value);
  // "Object Type is not recognized": Invalid Field (11.2, 11.4).
  if (!(OBJECT_TYPES as readonly string[]).includes(type)) {
    throw new KmsError("Invalid Field", `this server does not hold objects of type ${type}`);
  }
  return type as ObjectType;
}

/** The individual attributes of a Template-Attribute structure of the request. */
function attrsOf(payload: Item[], container: string, required: boolean): Attribute[] {
  const item = one(payload, container);
  if (item === undefined) {
    if (required) throw new KmsError("Invalid Message", `${container} is required`);
    return [];
  }
  // This server holds no templates, so a template named is one that does not
  // exist: "Templates that do not exist are given in request": Item Not Found
  // (11.2, 11.3, 11.4).
  if (templateNames(item).length > 0) {
    throw new KmsError("Item Not Found", "this server holds no templates; give individual attributes");
  }
  try {
    return decodeAttributes(item);
  } catch (e) {
    throw e instanceof KmipMessageError ? new KmsError(e.reason, e.message) : e;
  }
}

const uidItem = (id: string, name = "Unique Identifier") => k.text(name, id);

/**
 * An attribute in a response, its Attribute Index omitted where it is 0: "the
 * Attribute Index MAY be omitted if the index of the modified attribute instance
 * is 0" (4.15, 4.16). The KMIP Test Cases omit it.
 */
const responseAttribute = (a: Attribute): Item =>
  encodeAttribute(a.index === 0 ? { name: a.name, value: a.value } : a);

function bytesField(p: Item[], name: string, required: boolean): Buffer | undefined {
  const i = one(p, name);
  if (i === undefined) {
    if (required) throw new KmsError("Missing Data", `${name} is required`);
    return undefined;
  }
  if (i.type !== TYPE.ByteString) throw new KmsError("Invalid Field", `${name} is a Byte String`);
  return i.value;
}

function optBytes<K extends string>(p: Item[], name: string, key: K): Partial<Record<K, Buffer>> {
  const b = bytesField(p, name, false);
  return (b === undefined ? {} : { [key]: b }) as Partial<Record<K, Buffer>>;
}

function paramsField(p: Item[]): { params?: ReturnType<typeof readParams> } {
  const i = one(p, "Cryptographic Parameters");
  return i === undefined ? {} : { params: readParams(i) };
}

/** Multi-part operations (Correlation Value, Init Indicator, Final Indicator) are not performed. */
function noStreaming(p: Item[]): void {
  for (const n of ["Correlation Value", "Init Indicator", "Final Indicator"]) {
    if (one(p, n) !== undefined) throw new KmsError("Feature Not Supported", "multi-part cryptographic operations are not supported");
  }
}

/** A Key Wrapping Specification (2.1.6, Table 12). */
function readWrappingSpecification(spec: Item): WrappingSpecification {
  const method = child(spec, "Wrapping Method");
  if (method?.type !== TYPE.Enumeration) throw new KmsError("Invalid Field", "a Key Wrapping Specification has a Wrapping Method");
  if (child(spec, "MAC/Signature Key Information") !== undefined) {
    throw new KmsError("Feature Not Supported", "wrapping with a MAC or signature is not supported");
  }
  const enc = child(spec, "Encryption Key Information");
  const encId = enc === undefined ? undefined : text(child(enc, "Unique Identifier"));
  if (enc !== undefined && encId === undefined) {
    throw new KmsError("Invalid Field", "an Encryption Key Information names a Unique Identifier");
  }
  const names = children(spec, "Attribute Name").map((a) => a.value as string);
  const option = child(spec, "Encoding Option");
  if (names.length > 0 && option !== undefined) {
    // "Encoding Option not permitted when Key Wrapping Specification contains attribute names" (11.12).
    throw new KmsError("Encoding Option Error", "an Encoding Option is not given with Attribute Names");
  }
  const params = enc === undefined ? undefined : child(enc, "Cryptographic Parameters");
  return {
    method: enumName("Wrapping Method", method.value),
    ...(encId === undefined ? {} : { encryptionKey: { id: encId, ...(params === undefined ? {} : { params: readParams(params) }) } }),
    attributeNames: names,
    ...(option === undefined ? {} : { encodingOption: enumName("Encoding Option", option.value as number) }),
  };
}

// ---------------------------------------------------------------------------
// Operations

type Handler = (payload: Item[], ctx: Context, s: DispatchOptions) => Item[];

const HANDLERS: Record<string, Handler> = {
  "Register": (p, ctx, s) => {
    const type = objectTypeOf(p);
    const value = one(p, type);
    // The object being registered is "REQUIRED" (Table 169); an object of another
    // type is "Object Type does not match type of cryptographic object provided":
    // Invalid Field (11.4).
    if (value === undefined) throw new KmsError("Invalid Field", `a Register of a ${type} carries the ${type}`);
    const id = s.core.register(ctx.who!, type, attrsOf(p, "Template-Attribute", true), value);
    // "The server SHALL copy the Unique Identifier returned by this operations into the ID Placeholder variable" (4.3).
    ctx.placeholder = id;
    return [uidItem(id)];
  },

  "Create": (p, ctx, s) => {
    const type = objectTypeOf(p);
    const id = s.core.create(ctx.who!, type, attrsOf(p, "Template-Attribute", true));
    ctx.placeholder = id;
    return [k.enum("Object Type", "Object Type", type), uidItem(id)];
  },

  "Create Key Pair": (p, ctx, s) => {
    const r = s.core.createKeyPair(ctx.who!,
      attrsOf(p, "Common Template-Attribute", false),
      attrsOf(p, "Private Key Template-Attribute", false),
      attrsOf(p, "Public Key Template-Attribute", false));
    // "The ID Placeholder value SHALL be set to the Unique Identifier of the Private Key" (4.2).
    ctx.placeholder = r.privateKey;
    return [uidItem(r.privateKey, "Private Key Unique Identifier"), uidItem(r.publicKey, "Public Key Unique Identifier")];
  },

  "Locate": (p, ctx, s) => {
    const int = (n: string) => {
      const i = one(p, n);
      if (i !== undefined && i.type !== TYPE.Integer) throw new KmsError("Invalid Field", `${n} is an Integer`);
      return i?.value as number | undefined;
    };
    // The Object Group *attribute* is supported, and a Locate carrying one as an
    // Attribute matches on it like any other. Object Group Member is a different
    // thing: "Group Member Fresh" asks for members of a group that have not been
    // given out yet, which needs issuance state per group that this server does
    // not keep. Refused, and said as what it is.
    if (one(p, "Object Group Member") !== undefined) {
      throw new KmsError("Feature Not Supported",
        "Object Group Member asks for fresh or default members of a group, which this " +
        "server does not distinguish; an Attribute of Object Group matches the group itself");
    }
    // "Attribute Index values that are provided SHALL be ignored by the server" (4.9).
    const attrs = children({ tag: 0, type: TYPE.Structure, value: p } as Item, "Attribute")
      .map(decodeAttribute).map((a) => ({ name: a.name, value: a.value }));
    const r = s.core.locate(ctx.who!, attrs, {
      ...(int("Maximum Items") === undefined ? {} : { maximumItems: int("Maximum Items") }),
      ...(int("Offset Items") === undefined ? {} : { offsetItems: int("Offset Items") }),
      ...(int("Storage Status Mask") === undefined ? {} : { storageStatusMask: int("Storage Status Mask") }),
    });
    // "If a single Unique Identifier is returned to the client, then the server SHALL
    // copy the Unique Identifier ... into the ID Placeholder"; where more match and
    // Maximum Items is omitted or larger than one, "the server SHALL empty the ID
    // Placeholder" (4.9).
    ctx.placeholder = r.ids.length === 1 ? r.ids[0] : undefined;
    return [k.int("Located Items", r.located), ...r.ids.map((id) => uidItem(id))];
  },

  "Get": (p, ctx, s) => {
    const id = uidOf(p, ctx);
    if (one(p, "Key Compression Type") !== undefined) {
      throw new KmsError("Key Compression Type Not Supported", "this server compresses no key");
    }
    const spec = one(p, "Key Wrapping Specification");
    const wrapType = one(p, "Key Wrap Type");
    const format = one(p, "Key Format Type");
    const r = s.core.get(ctx.who!, id, {
      ...(wrapType === undefined ? {} : { keyWrapType: enumName("Key Wrap Type", wrapType.value as number) }),
      ...(format === undefined ? {} : { keyFormatType: enumName("Key Format Type", format.value as number) }),
      ...(spec === undefined ? {} : { wrapping: readWrappingSpecification(spec) }),
    });
    return [k.enum("Object Type", "Object Type", r.type), uidItem(r.id), r.value];
  },

  "Get Attributes": (p, ctx, s) => {
    const id = uidOf(p, ctx);
    const names = p.filter((i) => i.tag === tagOf("Attribute Name")).map((i) => i.value as string);
    const attrs = s.core.getAttributes(ctx.who!, id, names.length === 0 ? undefined : names);
    return [uidItem(id), ...attrs.map(responseAttribute)];
  },

  "Get Attribute List": (p, ctx, s) => {
    const id = uidOf(p, ctx);
    return [uidItem(id), ...s.core.getAttributeList(ctx.who!, id).map((n) => k.text("Attribute Name", n))];
  },

  "Add Attribute": (p, ctx, s) => {
    const id = uidOf(p, ctx);
    const a = decodeAttribute(requireItem(p, "Attribute"));
    // "The Attribute Index SHALL NOT be specified in the request" (4.14);
    // "New attribute contains Attribute Index": Invalid Field (11.15).
    if (a.index !== undefined) throw new KmsError("Invalid Field", "an Add Attribute request gives no Attribute Index");
    s.core.addAttribute(ctx.who!, id, a.value, a.name);
    // "The response returns a new Attribute" with its index (4.14).
    const added = s.core.getAttributes(ctx.who!, id, [a.name]).filter((x) => same(x.value, a.value)).at(-1)!;
    return [uidItem(id), responseAttribute(added)];
  },

  "Modify Attribute": (p, ctx, s) => {
    const id = uidOf(p, ctx);
    const a = decodeAttribute(requireItem(p, "Attribute"));
    // "If no Attribute Index is specified in the request, then the Attribute Index SHALL be assumed to be 0" (4.15).
    const index = a.index ?? 0;
    const instances = s.core.getAttributes(ctx.who!, id, [a.name]);
    if (instances.length === 0) {
      // "A specified attribute does not exist (i.e., it needs to first be added)": Invalid Field (11.16).
      throw new KmsError("Invalid Field", `the object has no ${a.name}`);
    }
    const target = instances.find((x) => x.index === index);
    // "No matching attribute instance exists": Item Not Found (11.16).
    if (target === undefined) throw new KmsError("Item Not Found", `the object has no instance ${index} of ${a.name}`);
    s.core.modifyAttribute(ctx.who!, id, a.value, target.value, a.name);
    return [uidItem(id), responseAttribute({ name: a.name, index, value: a.value })];
  },

  "Delete Attribute": (p, ctx, s) => {
    const id = uidOf(p, ctx);
    const name = text(one(p, "Attribute Name"));
    if (name === undefined) throw new KmsError("Invalid Message", "an Attribute Name is required");
    // "If no Attribute Index is specified in the request, then the Attribute Index SHALL be assumed to be 0" (4.16).
    const index = (one(p, "Attribute Index")?.value as number | undefined) ?? 0;
    const target = s.core.getAttributes(ctx.who!, id, [name]).find((x) => x.index === index);
    // "No matching attribute instance exists" and "No attribute with the specified name exists": Item Not Found (11.17).
    if (target === undefined) throw new KmsError("Item Not Found", `the object has no instance ${index} of ${name}`);
    s.core.deleteAttribute(ctx.who!, id, { current: target.value, name });
    // "The response returns the deleted Attribute" (4.16).
    return [uidItem(id), responseAttribute(target)];
  },

  "Activate": (p, ctx, s) => {
    const id = uidOf(p, ctx);
    s.core.activate(ctx.who!, id);
    return [uidItem(id)];
  },

  "Revoke": (p, ctx, s) => {
    const id = uidOf(p, ctx);
    const reason = requireItem(p, "Revocation Reason");
    const code = child(reason, "Revocation Reason Code");
    // "Revocation Reason is not recognized": Invalid Field (11.21).
    if (code?.type !== TYPE.Enumeration) throw new KmsError("Invalid Field", "a Revocation Reason has a code");
    const occurrence = one(p, "Compromise Occurrence Date");
    const message = text(child(reason, "Revocation Message"));
    s.core.revoke(ctx.who!, id, enumName("Revocation Reason Code", code.value), {
      ...(message === undefined ? {} : { message }),
      ...(occurrence === undefined ? {} : { compromiseOccurrence: Number(occurrence.value as bigint) * 1000 }),
    });
    return [uidItem(id)];
  },

  "Destroy": (p, ctx, s) => {
    const id = uidOf(p, ctx);
    s.core.destroy(ctx.who!, id);
    return [uidItem(id)];
  },

  "Re-key": (p, ctx, s) => {
    const id = uidOf(p, ctx);
    const offset = one(p, "Offset");
    const neu = s.core.rekey(ctx.who!, id, {
      ...(offset === undefined ? {} : { offsetSeconds: offset.value as number }),
      attrs: attrsOf(p, "Template-Attribute", false),
    });
    // "The server SHALL copy the Unique Identifier of the replacement key ... into the ID Placeholder variable" (4.4).
    ctx.placeholder = neu;
    return [uidItem(neu)];
  },

  "Re-key Key Pair": (p, ctx, s) => {
    const id = uidOf(p, ctx, "Private Key Unique Identifier");
    const offset = one(p, "Offset");
    for (const c of ["Common Template-Attribute", "Private Key Template-Attribute", "Public Key Template-Attribute"]) {
      if (attrsOf(p, c, false).length > 0) {
        throw new KmsError("Feature Not Supported", "attributes for a replacement key pair are not supported");
      }
    }
    const r = s.core.rekeyKeyPair(ctx.who!, id, offset === undefined ? {} : { offsetSeconds: offset.value as number });
    ctx.placeholder = r.privateKey;
    return [uidItem(r.privateKey, "Private Key Unique Identifier"), uidItem(r.publicKey, "Public Key Unique Identifier")];
  },

  "Encrypt": (p, ctx, s) => {
    noStreaming(p);
    const id = uidOf(p, ctx);
    const r = s.core.encrypt(ctx.who!, id, {
      ...paramsField(p), data: bytesField(p, "Data", true)!,
      ...optBytes(p, "IV/Counter/Nonce", "iv"), ...optBytes(p, "Authenticated Encryption Additional Data", "aad"),
    });
    return [
      uidItem(id), k.bytes("Data", r.data),
      ...(r.iv === undefined ? [] : [k.bytes("IV/Counter/Nonce", r.iv)]),
      ...(r.tag === undefined ? [] : [k.bytes("Authenticated Encryption Tag", r.tag)]),
    ];
  },

  "Decrypt": (p, ctx, s) => {
    noStreaming(p);
    const id = uidOf(p, ctx);
    const data = s.core.decrypt(ctx.who!, id, {
      ...paramsField(p), data: bytesField(p, "Data", true)!,
      ...optBytes(p, "IV/Counter/Nonce", "iv"), ...optBytes(p, "Authenticated Encryption Additional Data", "aad"),
      ...optBytes(p, "Authenticated Encryption Tag", "tag"),
    });
    return [uidItem(id), k.bytes("Data", data)];
  },

  "Sign": (p, ctx, s) => {
    noStreaming(p);
    if (one(p, "Digested Data") !== undefined) throw new KmsError("Feature Not Supported", "signing digested data is not supported");
    const id = uidOf(p, ctx);
    return [uidItem(id), k.bytes("Signature Data", s.core.sign(ctx.who!, id, { ...paramsField(p), data: bytesField(p, "Data", true)! }))];
  },

  "Signature Verify": (p, ctx, s) => {
    noStreaming(p);
    if (one(p, "Digested Data") !== undefined) throw new KmsError("Feature Not Supported", "verifying digested data is not supported");
    const id = uidOf(p, ctx);
    const valid = s.core.signatureVerify(ctx.who!, id, {
      ...paramsField(p), data: bytesField(p, "Data", true)!, signature: bytesField(p, "Signature Data", true)!,
    });
    return [uidItem(id), k.enum("Validity Indicator", "Validity Indicator", valid ? "Valid" : "Invalid")];
  },

  "MAC": (p, ctx, s) => {
    noStreaming(p);
    const id = uidOf(p, ctx);
    return [uidItem(id), k.bytes("MAC Data", s.core.mac(ctx.who!, id, { ...paramsField(p), data: bytesField(p, "Data", true)! }))];
  },

  "MAC Verify": (p, ctx, s) => {
    noStreaming(p);
    const id = uidOf(p, ctx);
    const valid = s.core.macVerify(ctx.who!, id, {
      ...paramsField(p), data: bytesField(p, "Data", true)!, macData: bytesField(p, "MAC Data", true)!,
    });
    return [uidItem(id), k.enum("Validity Indicator", "Validity Indicator", valid ? "Valid" : "Invalid")];
  },

  "Query": (p, _ctx, s) => {
    const functions = p.filter((i) => i.tag === tagOf("Query Function")).map((i) => enumName("Query Function", i.value as number));
    const want = (f: string) => functions.includes(f);
    return encodeQueryResult({
      operations: want("Query Operations") ? [...OPERATIONS] : [],
      objectTypes: want("Query Objects") ? [...OBJECT_TYPES] : [],
      // "SHALL be returned if Query Server Information is requested" (Table 223).
      ...(want("Query Server Information") ? { vendorIdentification: s.vendorIdentification ?? "seedmi" } : {}),
      applicationNamespaces: [],
      other: [],
    });
  },

  "Discover Versions": (p) => {
    const theirs = readDiscoverVersions(p);
    // "If the client provides ... a list of supported protocol versions ... the server
    // SHALL return only the protocol versions that are supported by both"; with none,
    // the server returns all it supports (4.26).
    return discoverVersionsPayload(theirs.length === 0 ? SERVER_VERSIONS
      : SERVER_VERSIONS.filter((m) => theirs.some((t) => compareVersions(t, m) === 0)));
  },
};

function requireItem(p: Item[], name: string): Item {
  const i = one(p, name);
  if (i === undefined) throw new KmsError("Invalid Message", `${name} is required`);
  return i;
}

const same = (a: Item, b: Item) => encode(a).equals(encode(b));

// Kept for readers of the Template-Attribute form of a response.
void encodeAttributes;

// ---------------------------------------------------------------------------
// Messages and batches

/** Whether this server speaks a version: 1.4, or any earlier minor version of major 1 (6.1). */
export const speaks = (v: ProtocolVersion): boolean => v.major === V1_4.major && v.minor <= V1_4.minor;

/**
 * Performs a request, given as its decoded TTLV item, for the identity the
 * transport established (undefined where the client did not authenticate), and
 * returns the Response Message item.
 */
/**
 * The answer to a message that cannot be parsed, or of another major version:
 * "Response message containing a header and a Batch Item without Operation, but
 * with the Result Status field set to Operation Failed", Invalid Message (11.1).
 */
export function unparseable(why: string, now: () => number = Date.now): Item {
  return encodeResponse({
    header: { protocolVersion: V1_4, timeStamp: now() },
    items: [{ resultStatus: "Operation Failed", resultReason: "Invalid Message", resultMessage: why }],
  });
}

export function dispatch(s: DispatchOptions, who: string | undefined, message: Item): Item {
  const now = s.now ?? Date.now;
  const unparsed = (why: string) => unparseable(why, now);
  let request;
  try {
    request = decodeRequest(message);
  } catch (e) {
    if (!(e instanceof KmipMessageError)) throw e;
    // "Message cannot be parsed" (11.1).
    return unparsed(e.message);
  }
  const h = request.header;
  const v = h.protocolVersion;
  // "Protocol major version mismatch" (11.1).
  if (!speaks(v)) return unparsed(`this server speaks version 1.4 and earlier 1.x, not ${versionText(v)}`);

  const failAll = (reason: string, why: string) => encodeResponse({
    header: { protocolVersion: v, timeStamp: now() },
    items: request.items.map((i) => ({
      ...(i.operation ? { operation: i.operation } : {}),
      ...(i.uniqueBatchItemId ? { uniqueBatchItemId: i.uniqueBatchItemId } : {}),
      resultStatus: "Operation Failed", resultReason: reason, resultMessage: why,
    })),
  });
  // "This option SHALL only be present if the Batch Count is greater than 1" (6.13).
  if (request.items.length === 1 && h.batchErrorContinuationOption !== undefined) {
    return failAll("Invalid Message", "a Batch Error Continuation Option is present in a batch of one item");
  }
  if (h.batchErrorContinuationOption === "Undo") {
    // "Server support for this feature is OPTIONAL" (6.13).
    return failAll("Feature Not Supported", "this server cannot undo a batch");
  }

  const continueOnError = h.batchErrorContinuationOption === "Continue";
  const ctx: Context = { who, placeholder: undefined, placeholderUsable: batchOrdered(h) && !continueOnError };
  const out: ResponseBatchItem[] = [];
  for (const item of request.items) {
    const r = performItem(s, ctx, item);
    out.push(r);
    // Stop: "the server SHALL NOT continue processing subsequent operations in the
    // request" (6.13); the items not processed are not answered.
    if (r.resultStatus === "Operation Failed" && !continueOnError) break;
  }

  let response = encodeResponse({ header: { protocolVersion: v, timeStamp: now() }, items: out });
  if (h.maximumResponseSize !== undefined && encode(response).length > h.maximumResponseSize) {
    // "Maximum Response Size has been exceeded": Response Too Large (11.1), in the
    // form KMIP Profiles 1.4 test case MSGENC-HTTPS-M-1-14 shows.
    response = encodeResponse({
      header: { protocolVersion: v, timeStamp: now() },
      items: out.map((i) => ({
        ...(i.operation ? { operation: i.operation } : {}),
        ...(i.uniqueBatchItemId ? { uniqueBatchItemId: i.uniqueBatchItemId } : {}),
        resultStatus: "Operation Failed", resultReason: "Response Too Large", resultMessage: "TOO_LARGE",
      })),
    });
  }
  return response;
}

function performItem(s: DispatchOptions, ctx: Context, item: RequestBatchItem): ResponseBatchItem {
  const base = {
    ...(item.operation ? { operation: item.operation } : {}),
    ...(item.uniqueBatchItemId ? { uniqueBatchItemId: item.uniqueBatchItemId } : {}),
  };
  try {
    // "Error parsing batch item or payload within batch item": the batch item fails (11.1).
    if (item.error !== undefined) throw item.error;
    const handler = HANDLERS[item.operation!];
    // "Server does not support operation": Operation Not Supported (11.1).
    if (handler === undefined) throw new KmsError("Operation Not Supported", `this server does not perform ${item.operation}`);
    if (ctx.who === undefined && !UNAUTHENTICATED.has(item.operation!)) {
      // KMIP Profiles 1.4, 3.1.3: mutual authentication is required "for all operations
      // other than" Query and Discover Versions.
      throw new KmsError("Authentication Not Successful", `${item.operation} requires an authenticated client`);
    }
    return { ...base, resultStatus: "Success", payload: handler(item.payload, ctx, s) };
  } catch (e) {
    if (e instanceof KmsError || e instanceof KmipMessageError) {
      return { ...base, resultStatus: "Operation Failed", resultReason: e.reason, resultMessage: e.message };
    }
    throw e;
  }
}
