// Serving a bucket through an S3 export.
//
// An S3 export presents the objects a container object contains as
// the objects of a bucket. A key is the path of the object relative
// to the exported container, with a solidus between each name; the
// exported container itself has no key, and a child container is not
// presented as a key.
//
// This module holds the surface: the error responses, the mapping
// between a key and an object, and the object operations. The export
// entry is in s3.ts and the signature in s3-sigv4.ts.

import type { IncomingMessage, ServerResponse } from "node:http";
import { decideFor, delegatedMask, DelegationRefused } from "./dac-context.ts";
import type { DacClient } from "./dac.ts";
import { createHash } from "node:crypto";
import { Condition } from "./problems.ts";
import { underRestriction } from "./retention.ts";

/** The S3 error code each CDMI condition is reported as. */
export const CONDITION_CODES: Record<string, string> = {
  "malformed-request": "InvalidRequest",
  "invalid-field": "InvalidArgument",
  "invalid-selection": "InvalidArgument",
  "conflicting-fields": "InvalidRequest",
  unauthenticated: "AccessDenied",
  forbidden: "AccessDenied",
  "not-found": "NoSuchKey",
  "capability-not-present": "NotImplemented",
  "not-permitted-for-object-type": "NotImplemented",
  "range-not-satisfiable": "InvalidRange",
  "limit-exceeded": "MetadataTooLarge",
  // A conflict reported for an object under retention or under hold
  // is reported as AccessDenied, the S3 API Reference giving no code
  // for a refusal of that kind and an S3 client treating that code
  // as final.
  conflict: "AccessDenied",
  "server-error": "InternalError",
  "already-exists": "InvalidRequest",
};

/** The HTTP status each S3 error code is answered with. */
export const CODE_STATUS: Record<string, number> = {
  AccessDenied: 403,
  BadDigest: 400,
  EntityTooLarge: 400,
  EntityTooSmall: 400,
  InternalError: 500,
  InvalidArgument: 400,
  InvalidPart: 400,
  InvalidPartOrder: 400,
  InvalidRange: 416,
  InvalidRequest: 400,
  KeyTooLongError: 400,
  MetadataTooLarge: 400,
  NoSuchBucket: 404,
  NoSuchKey: 404,
  NoSuchUpload: 404,
  NotImplemented: 501,
  PreconditionFailed: 412,
  RequestTimeTooSkewed: 403,
  SignatureDoesNotMatch: 403,
  InvalidAccessKeyId: 403,
  // A temporary credential this server does not accept: a ticket that is not
  // of the realm, is outside its validity period, or cannot be read
  // (revision 282; PLAN-auth.md, phase 8).
  InvalidSecurityToken: 403,
  AuthorizationHeaderMalformed: 400,
  AuthorizationQueryParametersError: 400,
};

/** Escapes the five characters that may not appear in XML character data. */
export function escapeXML(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&apos;",
  })[c] as string);
}

/** The error response the S3 API Reference defines. */
export function errorBody(code: string, message: string, resource: string,
  requestID: string): string {
  return '<?xml version="1.0" encoding="UTF-8"?>\n' +
    "<Error>" +
    `<Code>${escapeXML(code)}</Code>` +
    `<Message>${escapeXML(message)}</Message>` +
    `<Resource>${escapeXML(resource)}</Resource>` +
    `<RequestId>${escapeXML(requestID)}</RequestId>` +
    "</Error>\n";
}

/** Answers a request with an S3 error response. */
export function sendError(res: ServerResponse, code: string, message: string,
  resource: string, requestID: string): void {
  const body = Buffer.from(errorBody(code, message, resource, requestID), "utf8");
  res.writeHead(CODE_STATUS[code] ?? 500, {
    "Content-Type": "application/xml",
    "Content-Length": String(body.length),
    "x-amz-request-id": requestID,
  });
  res.end(body);
}

/**
 * The S3 error code of a CDMI condition. Where a section of the
 * clause specifies a code for a particular request, that code
 * applies in place of this one.
 */
export function codeOf(c: Condition): string {
  // The type of a condition is the URI of the problem, whose last
  // segment names it.
  const name = c.type.split("/").pop() ?? "";
  return CONDITION_CODES[name] ?? "InternalError";
}

/** Answers a request with the S3 error code of a CDMI condition. */
export function sendCondition(res: ServerResponse, c: Condition,
  resource: string, requestID: string, addressedBucket = false): void {
  let code = codeOf(c);
  // Not found is NoSuchKey where a key was addressed and NoSuchBucket
  // where the bucket was.
  if (code === "NoSuchKey" && addressedBucket) code = "NoSuchBucket";
  sendError(res, code, c.detail || c.title, resource, requestID);
}

// ---------------------------------------------------------------------
// Keys

/**
 * The names a key resolves to within the exported container. A key
 * is the path of the object relative to that container, and each
 * name between two solidi is a segment.
 */
export function segmentsOf(key: string): string[] | undefined {
  if (key === "") return undefined;
  const segs = key.split("/");
  // A key with an empty segment resolves to no object: there is no
  // object of an empty name.
  if (segs.some((s) => s === "")) return undefined;
  if (segs.some((s) => s === "." || s === "..")) return undefined;
  // A key is at most 1024 octets when encoded, as S3 requires.
  if (Buffer.byteLength(key, "utf8") > 1024) return undefined;
  return segs;
}

/** The key of an object at a path relative to the exported container. */
export function keyOf(relative: string): string {
  return relative.replace(/^\//, "");
}

/** An identifier for a request, which an error response carries. */
export function requestID(): string {
  // Sixteen hexadecimal digits, which is the shape an S3 client
  // expects and logs.
  let out = "";
  for (let i = 0; i < 16; i++) {
    out += Math.floor(Math.random() * 16).toString(16).toUpperCase();
  }
  return out;
}

/** Whether a request carries no signature of either form. */
export function unsigned(req: IncomingMessage): boolean {
  const auth = req.headers.authorization;
  if (typeof auth === "string" && auth !== "") return false;
  // A request signature is presented in the Authorization header
  // field or as parameters of the query component, and the
  // anonymous_read field governs a request that carries one in
  // neither form.
  const url = req.url ?? "";
  const at = url.indexOf("?");
  return at < 0 || !isPresigned(url.slice(at + 1));
}

// ---------------------------------------------------------------------
// The operations

import type { Node, Store } from "./store.ts";
import type { S3Export } from "./s3.ts";
import {
  EMPTY_PAYLOAD_HASH, isPresigned, verify, verifyPresigned,
} from "./s3-sigv4.ts";
import { ANONYMOUS, granted, M, type Principal } from "./acl.ts";
import {
  completeBody, initiateBody, MAX_PART_SIZE, MAX_PARTS, MIN_PART_SIZE,
  parseCompleteBody, partsBody, type Upload, Uploads, uploadsBody,
} from "./s3-multipart.ts";

/** One bucket this CDMI server serves, and what it presents. */
export interface Bucket {
  entry: S3Export;
  /** The exported container object. */
  node: Node;
  /** Its path, for a log line and a problem. */
  ns: string;
}

export interface BucketOptions {
  buckets: Bucket[];
  store: Store;
  /** Delegated access control, where this server is configured for it. */
  dac?: DacClient;
  /**
   * The uploads in progress of this CDMI server. It belongs to the
   * server rather than to this module: two servers in one process
   * hold their own, and a bucket name is unique within a server and
   * not across them.
   */
  uploads: Uploads;
  credentials?: (accessKey: string) =>
    { secret: string; principal: string } | undefined;
  /**
   * The credentials a Kerberos service ticket gives: "A CDMI server verifies
   * the signature of an S3 request whose X-Amz-Security-Token header field,
   * or the query parameter of that name in a presigned request, contains a
   * Kerberos service ticket for its service principal ... verifies the
   * signature using the session key of the ticket as the secret access key;
   * and evaluates access control for the client principal the ticket names"
   * (revision 282; PLAN-auth.md, phase 8). "An S3 export accepts temporary
   * credentials only", so where this is configured it is the only route.
   * It is given the bucket, so that the ticket is checked against the realm
   * of the domain owning the container the export is placed on.
   */
  temporary?: (token: string, bucket: Bucket) =>
    Promise<{ secret: Buffer; principal: Principal } | { refused: string } | undefined>;
  /**
   * The principal a name a credential maps to resolves to, with its
   * groups and administrative status. Where absent, the principal has
   * the name alone, and an access control entry naming one of its
   * groups does not match it.
   */
  principal?: (name: string) => Principal | undefined;
  /** Whether the request arrived over TLS. */
  secure: boolean;
}

/** The bucket a request addresses, and the key within it. */
export function routeS3(host: string, path: string, buckets: Bucket[]):
  { bucket: Bucket; key: string; addressedBucket: boolean } | undefined {
  const label = host.split(":")[0].split(".")[0].toLowerCase();
  // Virtual hosted addressing: the bucket is a subdomain of an
  // endpoint, and the whole path is the key.
  for (const b of buckets) {
    if (b.entry.addressing_style === "path") continue;
    if (b.entry.bucket_name !== label) continue;
    const key = decodeURIComponent(path.replace(/^\//, ""));
    return { bucket: b, key, addressedBucket: key === "" };
  }
  // Path style addressing: the bucket is the first segment.
  const segs = path.replace(/^\//, "").split("/");
  const first = decodeURIComponent(segs[0] ?? "");
  for (const b of buckets) {
    if (b.entry.addressing_style === "virtual_hosted") continue;
    if (b.entry.bucket_name !== first) continue;
    const key = segs.slice(1).map((s) => decodeURIComponent(s)).join("/");
    return { bucket: b, key, addressedBucket: key === "" };
  }
  return undefined;
}

/**
 * Serves a request against a bucket, reporting whether it did. A
 * request that addresses no bucket this CDMI server serves is not
 * this surface's, and is left for another.
 */
/**
 * The entity tag of an object's value, as an S3 client reads it. The
 * S3 export clause: "The CDMI server shall generate an opaque entity
 * tag, of the same lexical form, that changes whenever the value of the
 * data object changes." Before 0.2 the cdmi_hash of the object was used,
 * which exists only where a client asked for a value hash, so every
 * other object had the empty tag. The tag is 32 base-16 digits, the form
 * S3 gives the tag of an object written in one request, and is derived
 * from the object's identity and the version counter that advances with
 * every change, so it changes whenever the value does.
 */
export function s3ETag(m: { objectID: string; version: number; size: number },
  store?: Store): string {
  const tag = createHash("sha256")
    .update(`${m.objectID}\u0000${m.version}\u0000${m.size}`)
    .digest("hex").slice(0, 32);
  // "A CDMI server shall report every entity tag in the form the Amazon
  // Simple Storage Service API Reference gives for an object created by
  // multipart upload, in which a hyphen and a number follow the leading
  // characters, whatever the means by which the value was written, and shall
  // not report an entity tag in the form that reference gives for an object
  // created by a single request" (revision 211). From the single-request form
  // an S3 client infers that the tag is a digest of the value and compares the
  // two, which an opaque tag fails. An object not assembled from parts reports
  // one part.
  const parts = store?.multipartParts(m.objectID, m.version);
  return `${tag}-${parts ?? 1}`;
}

export async function serveBucket(req: IncomingMessage, res: ServerResponse,
  o: BucketOptions): Promise<boolean> {
  const url = req.url ?? "/";
  const at = url.indexOf("?");
  const path = at < 0 ? url : url.slice(0, at);
  const query = at < 0 ? "" : url.slice(at + 1);
  const host = (req.headers.host as string | undefined) ?? "";
  const routed = routeS3(host, path, o.buckets);
  if (routed === undefined) return false;

  const { bucket, key, addressedBucket } = routed;
  const uploads = o.uploads;
  const id = requestID();
  const resource = path;
  const fail = (code: string, message: string) => {
    sendError(res, code, message, resource, id);
    return true;
  };

  // A bucket whose entry requires TLS is not served over HTTP: an S3
  // request signature authenticates a request without concealing it.
  if (bucket.entry.tls === "required" && !o.secure) {
    return fail("AccessDenied",
      "this bucket is served over TLS alone, as its export entry requires");
  }

  // The identity that signed the request, against which the access
  // control list of the object is evaluated.
  const method = (req.method ?? "GET").toUpperCase();
  const isRead = method === "GET" || method === "HEAD";
  let who: Principal = ANONYMOUS;
  const unsignedRequest = unsigned(req);
  // Every upload of this bucket that has outlived the period of its
  // entry is aborted, the period in effect at the time the expiry is
  // evaluated being the one applied.
  uploads.expire(bucket.entry.bucket_name, bucket.entry.multipart_expiry);
  if (unsignedRequest) {
    // An unsigned request is served where anonymous_read permits it
    // and the operation is a read; the access control list is still
    // evaluated, under the anonymous identity, so enabling the field
    // does not by itself make a bucket publicly readable.
    if (bucket.entry.anonymous_read !== "true" || !isRead) {
      return fail("AccessDenied", "this request carries no signature");
    }
  } else {
    // A temporary credential: the ticket the request carries, whose session
    // key signs it and whose client is the principal (revision 282).
    const tokenRaw = req.headers["x-amz-security-token"];
    const token = (Array.isArray(tokenRaw) ? tokenRaw[0] : tokenRaw) ?? new URLSearchParams(query).get("X-Amz-Security-Token") ?? undefined;
    let temporary: { secret: Buffer; principal: Principal } | undefined;
    if (token !== undefined && o.temporary !== undefined) {
      const got = await o.temporary(token, bucket);
      if (got !== undefined && "refused" in got) {
        return fail("InvalidSecurityToken", got.refused);
      }
      temporary = got;
    }
    if (temporary === undefined && o.credentials === undefined) {
      return fail("InvalidAccessKeyId",
        "this CDMI server holds no credential for any access key identifier");
    }
    // The signature is verified with the session key of the ticket, whatever
    // access key identifier the request names, a temporary credential naming
    // one of its own.
    const credential = temporary === undefined
      ? o.credentials!
      // The session key is octets, and a secret access key is text that a
      // client configures: this server takes the base64 of the key, which the
      // draft does not state (ECR-147A). Before that is settled, a client of
      // this server is given the key in that form.
      : () => ({ secret: temporary!.secret.toString("base64"), principal: temporary!.principal.name });
    // A signature presented in the query component.
    if (isPresigned(query)) {
      const checked = verifyPresigned({
        method,
        path,
        query,
        headers: req.headers as Record<string, string | string[] | undefined>,
        region: bucket.entry.region,
        credential,
      });
      if (!checked.ok) {
        return fail(checked.fault, "the request signature was not accepted");
      }
      // A presigned request is authorized when it is received,
      // against the access control list as it then stands, and not
      // at the time the presigned URL was generated.
      who = temporary?.principal ?? o.principal?.(checked.principal) ?? {
        name: checked.principal, groups: [], administrator: false, privileges: [],
      };
    } else {
      const payloadRaw = req.headers["x-amz-content-sha256"];
      const payloadHash = (Array.isArray(payloadRaw) ? payloadRaw[0] : payloadRaw) ??
        EMPTY_PAYLOAD_HASH;
      const checked = verify({
        method,
        path,
        query,
        headers: req.headers as Record<string, string | string[] | undefined>,
        payloadHash,
        region: bucket.entry.region,
        credential,
      });
      if (!checked.ok) {
        return fail(checked.fault, "the request signature was not accepted");
      }
      who = temporary?.principal ?? o.principal?.(checked.principal) ?? {
        name: checked.principal, groups: [], administrator: false, privileges: [],
      };
    }
  }

  // Where the object this request addresses has delegated access control, the
  // decision is obtained before the operation, and the permission checks below
  // apply the mask the provider returned (dac-context.ts).
  if (o.dac !== undefined && key !== "") {
    const addressed = resolveKey(o.store, bucket, key.split("/"));
    if (addressed !== undefined) {
      try {
        await decideFor(o.dac, o.store, addressed.node, who,
          method === "DELETE" ? "cdmi_delete" : method === "GET" || method === "HEAD" ? "cdmi_read" : "cdmi_modify");
      } catch (e) {
        if (!(e instanceof DelegationRefused)) throw e;
        return fail("AccessDenied", "the delegated access control provider of this object did not authorize this operation");
      }
    }
  }

  if (addressedBucket) {
    const params = new URLSearchParams(query);
    if (method === "HEAD") {
      res.writeHead(200, { "x-amz-request-id": id });
      res.end();
      return true;
    }
    if (method !== "GET") {
      return fail("NotImplemented",
        `this CDMI server does not serve the ${method} method of a bucket`);
    }
    // The region an S3 client uses when computing a signature.
    if (params.has("location")) {
      const body = Buffer.from(locationBody(bucket.entry.region), "utf8");
      res.writeHead(200, {
        "Content-Type": "application/xml",
        "Content-Length": String(body.length),
        "x-amz-request-id": id,
      });
      res.end(body);
      return true;
    }
    // An operation upon a bucket that this CDMI server does not
    // serve, of which the S3 API defines many.
    // The uploads in progress for the bucket.
    if (params.has("uploads")) {
      if (unsignedRequest) {
        return fail("AccessDenied",
          "an unsigned request is not served for a multipart upload operation");
      }
      const mine = uploads.forBucket(bucket.entry.bucket_name)
        .filter((u) => u.initiator === who.name);
      const body = Buffer.from(
        uploadsBody(bucket.entry.bucket_name, mine), "utf8");
      res.writeHead(200, {
        "Content-Type": "application/xml",
        "Content-Length": String(body.length),
        "x-amz-request-id": id,
      });
      res.end(body);
      return true;
    }
    if (params.has("versions")) {
      return listVersions(res, o.store, bucket, who, params, resource, id);
    }
    for (const named of ["acl", "policy", "tagging",
      "lifecycle", "cors", "versioning"]) {
      if (params.has(named)) {
        return fail("NotImplemented",
          `this CDMI server does not serve the ${named} operation of a bucket`);
      }
    }
    return listObjects(res, o.store, bucket, who, params, resource, id);
  }

  const segs = segmentsOf(key);
  if (segs === undefined) {
    return fail("InvalidArgument", "the key names no object of this bucket");
  }

  const params = new URLSearchParams(query);
  try {
    // The multipart operations, which are distinguished by the
    // parameters they carry. None is a read, so an unsigned request
    // for any of them is refused.
    if (params.has("uploads") || params.has("uploadId")) {
      if (unsignedRequest) {
        return fail("AccessDenied",
          "an unsigned request is not served for a multipart upload operation");
      }
      return await multipart(req, res, o.store, bucket, segs, key, who, method,
        params, resource, id, uploads);
    }
    switch (method) {
      case "GET":
      case "HEAD":
        return await getObject(res, o.store, bucket, segs, who, method === "HEAD",
          resource, id, params.get("versionId") ?? "");
      case "PUT":
        return await putObject(req, res, o.store, bucket, segs, who, resource, id);
      case "DELETE":
        return deleteObject(res, o.store, bucket, segs, who, resource, id,
          params.get("versionId") ?? "");
      default:
        return fail("NotImplemented",
          `this CDMI server does not serve the ${method} method of a bucket`);
    }
  } catch (err) {
    if (err instanceof Condition) {
      sendCondition(res, err, resource, id, addressedBucket);
      return true;
    }
    return fail("InternalError", "the CDMI server encountered an error");
  }
}

/** The data object a key resolves to, where one exists. */
function resolveKey(store: Store, bucket: Bucket, segs: string[]):
  { node: Node; parent: Node } | undefined {
  let at = bucket.node;
  for (const seg of segs.slice(0, -1)) {
    const next = store.lookupKind(at, seg, "container");
    if (next === undefined) return undefined;
    at = next;
  }
  const last = segs[segs.length - 1];
  // A key operates on the data object representation of a name, the
  // container object representation being reached by a listing.
  const node = store.lookupKind(at, last, "data");
  return node === undefined ? undefined : { node, parent: at };
}

/** Whether the principal is granted a permission on an object. */
function may(store: Store, node: Node, who: Principal, mask: number): boolean {
  const m = store.meta(node);
  const delegated = delegatedMask(m.objectID);
  if (delegated !== undefined) return (delegated & mask) === mask;
  return granted(m.acl ?? null, who, mask, {
    owner: m.owner,
    group: m.owner,
    isContainer: node.isContainer,
    isRoot: false,
  });
}

async function getObject(res: ServerResponse, store: Store, bucket: Bucket,
  segs: string[], who: Principal, head: boolean, resource: string,
  id: string, versionId = ""): Promise<boolean> {
  const found = resolveKey(store, bucket, segs);
  // A version identifier names a CDMI version of the object, whose
  // object identifier it is.
  if (versionId !== "" && found !== undefined) {
    if (bucket.entry.versioning !== "true") {
      sendError(res, "InvalidArgument",
        "this bucket is not presented as version enabled", resource, id);
      return true;
    }
    const version = store.versionsOf(found.node)
      .find((v) => store.meta(v).objectID === versionId);
    if (version === undefined) {
      sendError(res, "NoSuchKey", "the version identifier names no version of this key",
        resource, id);
      return true;
    }
    if (!may(store, found.node, who, M.READ_OBJECT)) {
      sendError(res, "AccessDenied",
        "the access control list does not permit this read", resource, id);
      return true;
    }
    const vm = store.meta(version);
    const vbody = await store.readValue(version);
    res.writeHead(200, {
      "Content-Type": vm.mimetype || "application/octet-stream",
      "Content-Length": String(vbody.length),
      "Last-Modified": new Date(vm.mtime).toUTCString(),
      ETag: `"${s3ETag(vm, store)}"`,
      "x-amz-version-id": versionId,
      "x-amz-request-id": id,
    });
    res.end(head ? undefined : vbody);
    return true;
  }
  if (found === undefined) {
    sendError(res, "NoSuchKey", "the key names no object of this bucket",
      resource, id);
    return true;
  }
  if (!may(store, found.node, who, M.READ_OBJECT)) {
    sendError(res, "AccessDenied", "the access control list does not permit this read",
      resource, id);
    return true;
  }
  const m = store.meta(found.node);
  const body = await store.readValue(found.node);
  const headers: Record<string, string> = {
    "Content-Type": m.mimetype || "application/octet-stream",
    "Content-Length": String(body.length),
    // The HTTP date format rather than the form CDMI uses.
    "Last-Modified": new Date(m.mtime).toUTCString(),
    ETag: `"${s3ETag(m, store)}"`,
    // Every object is of the one storage class this server reports.
    "x-amz-storage-class": "STANDARD",
    ...metadataFor(m.metadata),
    "x-amz-request-id": id,
  };
  res.writeHead(200, headers);
  if (head) {
    res.end();
    return true;
  }
  res.end(body);
  return true;
}

async function putObject(req: IncomingMessage, res: ServerResponse, store: Store,
  bucket: Bucket, segs: string[], who: Principal, resource: string,
  id: string): Promise<boolean> {
  // A key containing a solidus creates the intervening container
  // objects that do not already exist.
  let at = bucket.node;
  for (const seg of segs.slice(0, -1)) {
    const next = store.lookupKind(at, seg, "container");
    if (next !== undefined) {
      at = next;
      continue;
    }
    if (!may(store, at, who, M.ADD_SUBCONTAINER)) {
      sendError(res, "AccessDenied",
        "the access control list does not permit creating an intervening container",
        resource, id);
      return true;
    }
    at = store.createContainer(at, seg, {
      owner: who.name === ANONYMOUS.name ? "" : who.name,
      acl: store.meta(at).acl,
    });
  }

  const body = await readBody(req);
  const name = segs[segs.length - 1];
  const existing = store.lookupKind(at, name, "data");
  const wanted = existing === undefined ? M.ADD_OBJECT : M.WRITE_OBJECT;
  if (!may(store, existing ?? at, who, wanted)) {
    sendError(res, "AccessDenied", "the access control list does not permit this write",
      resource, id);
    return true;
  }
  if (refusedByRestriction(store, existing, res, resource, id)) return true;
  // Where a PutObject request does not specify a Content-Type, the
  // CDMI server assigns a mimetype of application/octet-stream.
  const typeRaw = req.headers["content-type"];
  const mimetype = (Array.isArray(typeRaw) ? typeRaw[0] : typeRaw) ??
    "application/octet-stream";
  const supplied = metadataFrom(
    req.headers as Record<string, string | string[] | undefined>);
  if ("fault" in supplied) {
    sendError(res, "InvalidArgument", supplied.fault, resource, id);
    return true;
  }
  // A digest the request carries is verified before anything is
  // written.
  const digest = checkDigests(
    req.headers as Record<string, string | string[] | undefined>, body);
  if (digest !== undefined) {
    sendError(res, "BadDigest", digest.fault, resource, id);
    return true;
  }
  // The aggregate size of the metadata this server would present.
  const wouldPresent = metadataFor(supplied.metadata as Record<string, unknown>);
  if (metadataSize(wouldPresent) > S3_METADATA_MAXTOTALSIZE) {
    sendError(res, "MetadataTooLarge",
      `the metadata of an object is at most ${S3_METADATA_MAXTOTALSIZE} octets`,
      resource, id);
    return true;
  }

  const node = existing ?? store.createData(at, name, {
    owner: who.name === ANONYMOUS.name ? "" : who.name,
    acl: store.meta(at).acl,
  });
  // A write that supersedes existing content creates a CDMI
  // version, whose object identifier is the version identifier of
  // the superseded content.
  let superseded: string | undefined;
  if (bucket.entry.versioning === "true" && existing !== undefined) {
    const version = store.createVersion(node);
    superseded = store.meta(version).objectID;
  }
  await store.setValue(node, body);
  const m = store.meta(node);
  m.mimetype = mimetype.split(";")[0].trim();
  m.vte = "base64";
  // The user metadata a request supplies replaces what the object
  // held, save for the items a request does not reach.
  const kept: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(m.metadata)) {
    if (k.startsWith("cdmi_") || !isToken(k)) kept[k] = v;
  }
  m.metadata = { ...kept, ...supplied.metadata };
  store.setMeta(node, m);
  // Awaited: the value hash was recorded after the response was sent.
  await store.rehash(node);

  res.writeHead(200, {
    ETag: `"${s3ETag(store.meta(node), store)}"`,
    "Content-Length": "0",
    // The checksum of each algorithm the request named.
    ...checksumHeaders(
      req.headers as Record<string, string | string[] | undefined>, body),
    ...(superseded === undefined ? {} : { "x-amz-version-id": superseded }),
    "x-amz-request-id": id,
  });
  res.end();
  return true;
}

/** The body of a ListObjectVersions response. */
export function versionsBody(bucket: string, entries: {
  key: string;
  versionId: string;
  latest: boolean;
  size: number;
  mtime: number;
  etag: string;
}[]): string {
  return '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
    `<Name>${escapeXML(bucket)}</Name><IsTruncated>false</IsTruncated>` +
    entries.map((e) =>
      "<Version>" +
      `<Key>${escapeXML(e.key)}</Key>` +
      `<VersionId>${escapeXML(e.versionId)}</VersionId>` +
      `<IsLatest>${e.latest ? "true" : "false"}</IsLatest>` +
      `<LastModified>${new Date(e.mtime).toISOString().replace(/\.\d+Z$/, ".000Z")}` +
      "</LastModified>" +
      `<ETag>&quot;${escapeXML(e.etag)}&quot;</ETag>` +
      `<Size>${e.size}</Size>` +
      "<StorageClass>STANDARD</StorageClass>" +
      "</Version>").join("") +
    "</ListVersionsResult>\n";
}

function deleteObject(res: ServerResponse, store: Store, bucket: Bucket,
  segs: string[], who: Principal, resource: string, id: string,
  versionId = ""): boolean {
  const found = resolveKey(store, bucket, segs);
  const versioned = bucket.entry.versioning === "true";

  // A request naming a version identifier deletes the corresponding
  // CDMI version alone.
  if (versionId !== "") {
    if (!versioned) {
      sendError(res, "InvalidArgument",
        "this bucket is not presented as version enabled", resource, id);
      return true;
    }
    if (found === undefined) {
      res.writeHead(204, { "x-amz-request-id": id });
      res.end();
      return true;
    }
    if (!may(store, found.node, who, M.DELETE)) {
      sendError(res, "AccessDenied",
        "the access control list does not permit this delete", resource, id);
      return true;
    }
    // A version of an object under retention is part of what the retention
    // protects: the object is not modified, and removing one of its versions
    // modifies it.
    if (refusedByRestriction(store, found.node, res, resource, id)) return true;
    const version = store.versionsOf(found.node)
      .find((v) => store.meta(v).objectID === versionId);
    if (version !== undefined) void store.removeTree(version);
    res.writeHead(204, {
      "x-amz-version-id": versionId,
      "x-amz-request-id": id,
    });
    res.end();
    return true;
  }

  // A request naming no version identifier inserts a delete marker.
  // This CDMI server does not: a delete marker has no CDMI
  // representation, and deleting the data object would destroy the
  // versions the clause requires to remain retrievable. See S5.
  if (versioned && found !== undefined) {
    sendError(res, "NotImplemented",
      "this CDMI server does not insert a delete marker; see the findings on " +
      "versioning through an S3 export", resource, id);
    return true;
  }
  // A request for a key that resolves to a container object with no
  // data object representation completes successfully, taking no
  // action; so does one for a key that resolves to no object.
  if (found === undefined) {
    res.writeHead(204, { "x-amz-request-id": id });
    res.end();
    return true;
  }
  if (!may(store, found.node, who, M.DELETE)) {
    sendError(res, "AccessDenied",
      "the access control list does not permit this delete", resource, id);
    return true;
  }
  if (refusedByRestriction(store, found.node, res, resource, id)) return true;
  // The data object alone is deleted, and not a container object of
  // the same name.
  void store.removeTree(found.node);
  res.writeHead(204, { "x-amz-request-id": id });
  res.end();
  return true;
}

/**
 * Refuses an S3 request that would delete or modify an object under retention or
 * under hold, and reports it where it does.
 *
 * "A rule of this document that governs what may be done to an object governs a
 * request that reaches that object through an export as it governs an operation
 * of a protocol binding" (exports model, revision 365), and this subclause names
 * the code: a conflict is reported as ``AccessDenied``, "since the S3 API
 * Reference gives no code for a refusal of that kind and an S3 client treats
 * that code as final" — and "a CDMI server shall not report the Conflict
 * condition arising from retention or hold with a code that an S3 client
 * retries, since the request does not succeed on repetition until the retention
 * period has passed or the hold has been released". AccessDenied is answered
 * with 403, which no S3 client retries.
 *
 * Until 0.109 the S3 export consulted the access control lists and not the
 * retention metadata, so an authorized client replaced the value of an object
 * under retention, and deleted it.
 */
function refusedByRestriction(store: Store, node: Node | undefined,
  res: ServerResponse, resource: string, id: string): boolean {
  if (node === undefined) return false;
  let held: string | undefined;
  try {
    if (underRestriction(store.meta(node).metadata)) {
      held = "the object is under retention or under hold";
    }
  } catch {
    return false;
  }
  if (held === undefined) return false;
  sendError(res, "AccessDenied",
    `${held}, and is not deleted or modified until that ends`, resource, id);
  return true;
}

/** The body of a request, read in full. */
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const parts: Buffer[] = [];
    req.on("data", (c: Buffer) => parts.push(c));
    req.on("end", () => resolve(Buffer.concat(parts)));
    req.on("error", reject);
  });
}

// ---------------------------------------------------------------------
// Listing

/** One key of a bucket, and what a listing reports of it. */
export interface Listed {
  key: string;
  size: number;
  mtime: number;
  etag: string;
}

/**
 * Every key of a bucket, in lexicographic order. A child container
 * is not a key; a data object and a queue object are. The keys are
 * flattened because a listing is computed over the flat namespace of
 * keys and not over the CDMI hierarchy.
 */
export function keysOf(store: Store, at: Node, prefix: string,
  may: (n: Node) => boolean): Listed[] {
  const out: Listed[] = [];
  for (const child of store.children(at)) {
    // A name beginning with cdmi_ is addressed by a path of its own
    // and is not an object of the bucket. The prefix is tested here and not
    // the reserved names table, because the S3 export clause writes it into a
    // requirement of its own: "Containers whose names are reserved by CDMI,
    // including the container in which snapshots of the exported container are
    // discovered, shall not be permitted to be created through S3"
    // (revision 365).
    if (child.name.startsWith("cdmi_")) continue;
    const key = prefix === "" ? child.name : `${prefix}/${child.name}`;
    if (child.node.isContainer) {
      out.push(...keysOf(store, child.node, key, may));
      continue;
    }
    if (!may(child.node)) continue;
    const m = store.meta(child.node);
    out.push({
      key,
      size: m.size,
      mtime: m.mtime,
      etag: s3ETag(m, store),
    });
  }
  return out;
}

/** What a listing answers. */
export interface Listing {
  keys: Listed[];
  commonPrefixes: string[];
  truncated: boolean;
  next?: string;
}

/**
 * Groups the keys of a bucket as a listing reports them. Common
 * prefixes are computed over the flat namespace of keys, so a
 * delimiter other than a solidus groups keys without regard to the
 * container structure that produced them.
 */
export function group(all: Listed[], o: {
  prefix: string;
  delimiter: string;
  maxKeys: number;
  after: string;
}): Listing {
  const sorted = [...all].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const keys: Listed[] = [];
  const prefixes: string[] = [];
  const seen = new Set<string>();
  let truncated = false;
  let last = "";

  for (const entry of sorted) {
    if (!entry.key.startsWith(o.prefix)) continue;
    if (o.after !== "" && entry.key <= o.after) continue;
    let group: string | undefined;
    if (o.delimiter !== "") {
      const rest = entry.key.slice(o.prefix.length);
      const at = rest.indexOf(o.delimiter);
      if (at >= 0) group = o.prefix + rest.slice(0, at + o.delimiter.length);
    }
    const isNew = group === undefined || !seen.has(group);
    if (!isNew) continue;
    if (keys.length + prefixes.length >= o.maxKeys) {
      truncated = true;
      break;
    }
    if (group === undefined) {
      keys.push(entry);
      last = entry.key;
    } else {
      seen.add(group);
      prefixes.push(group);
      last = entry.key;
    }
  }
  return {
    keys,
    commonPrefixes: prefixes,
    truncated,
    ...(truncated ? { next: last } : {}),
  };
}

/** The body of a ListObjectsV2 response. */
export function listingBody(bucket: string, o: {
  prefix: string;
  delimiter: string;
  maxKeys: number;
  continuation: string;
  startAfter: string;
}, listing: Listing): string {
  const parts: string[] = [
    '<?xml version="1.0" encoding="UTF-8"?>\n',
    '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">',
    `<Name>${escapeXML(bucket)}</Name>`,
    `<Prefix>${escapeXML(o.prefix)}</Prefix>`,
    `<MaxKeys>${o.maxKeys}</MaxKeys>`,
    `<KeyCount>${listing.keys.length + listing.commonPrefixes.length}</KeyCount>`,
    `<IsTruncated>${listing.truncated ? "true" : "false"}</IsTruncated>`,
  ];
  if (o.delimiter !== "") {
    parts.push(`<Delimiter>${escapeXML(o.delimiter)}</Delimiter>`);
  }
  if (o.continuation !== "") {
    parts.push(`<ContinuationToken>${escapeXML(o.continuation)}</ContinuationToken>`);
  }
  if (o.startAfter !== "") {
    parts.push(`<StartAfter>${escapeXML(o.startAfter)}</StartAfter>`);
  }
  if (listing.next !== undefined) {
    parts.push("<NextContinuationToken>" +
      escapeXML(Buffer.from(listing.next, "utf8").toString("base64")) +
      "</NextContinuationToken>");
  }
  for (const k of listing.keys) {
    parts.push(
      "<Contents>" +
      `<Key>${escapeXML(k.key)}</Key>` +
      `<LastModified>${new Date(k.mtime).toISOString().replace(/\.\d+Z$/, ".000Z")}` +
      "</LastModified>" +
      `<ETag>&quot;${escapeXML(k.etag)}&quot;</ETag>` +
      `<Size>${k.size}</Size>` +
      "<StorageClass>STANDARD</StorageClass>" +
      "</Contents>",
    );
  }
  for (const p of listing.commonPrefixes) {
    parts.push(`<CommonPrefixes><Prefix>${escapeXML(p)}</Prefix></CommonPrefixes>`);
  }
  parts.push("</ListBucketResult>\n");
  return parts.join("");
}

/** The body of a GetBucketLocation response. */
export function locationBody(region: string): string {
  return '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
    `${escapeXML(region)}</LocationConstraint>\n`;
}

/** Serves a ListObjectsV2 request, or a ListObjects request of the first form. */
function listObjects(res: ServerResponse, store: Store, bucket: Bucket,
  who: Principal, params: URLSearchParams, resource: string, id: string): boolean {
  // The list is of the objects the requesting identity may read: a
  // listing does not disclose the existence of a key the identity is
  // not permitted to know exists.
  if (!may(store, bucket.node, who, M.LIST_CONTAINER)) {
    sendError(res, "AccessDenied",
      "the access control list does not permit listing this bucket", resource, id);
    return true;
  }
  const prefix = params.get("prefix") ?? "";
  const delimiter = params.get("delimiter") ?? "";
  const maxRaw = params.get("max-keys");
  const maxKeys = maxRaw === null ? 1000 : Math.max(0, Math.min(1000, Number(maxRaw)));
  if (Number.isNaN(maxKeys)) {
    sendError(res, "InvalidArgument", "max-keys is a whole number", resource, id);
    return true;
  }
  const continuation = params.get("continuation-token") ?? "";
  const startAfter = params.get("start-after") ?? "";
  // A continuation token carries the key the previous listing
  // stopped at, and takes precedence over start-after.
  const after = continuation === ""
    ? startAfter
    : Buffer.from(continuation, "base64").toString("utf8");

  const all = keysOf(store, bucket.node, "", (n) => may(store, n, who, M.READ_OBJECT));
  const listing = group(all, { prefix, delimiter, maxKeys, after });
  const body = Buffer.from(
    listingBody(bucket.entry.bucket_name,
      { prefix, delimiter, maxKeys, continuation, startAfter }, listing),
    "utf8",
  );
  res.writeHead(200, {
    "Content-Type": "application/xml",
    "Content-Length": String(body.length),
    "x-amz-request-id": id,
  });
  res.end(body);
  return true;
}

/** Serves a multipart upload operation. */
async function multipart(req: IncomingMessage, res: ServerResponse, store: Store,
  bucket: Bucket, segs: string[], key: string, who: Principal, method: string,
  params: URLSearchParams, resource: string, id: string,
  uploads: Uploads): Promise<boolean> {
  const fail = (code: string, message: string) => {
    sendError(res, code, message, resource, id);
    return true;
  };
  const bucketName = bucket.entry.bucket_name;

  // Beginning an upload: the key is evaluated as a PutObject
  // evaluates it, and the identity is the one that may complete it.
  if (method === "POST" && params.has("uploads")) {
    if (key.endsWith("/")) {
      return fail("NotImplemented", "a key of an upload does not end with a solidus");
    }
    const target = resolveKey(store, bucket, segs);
    if (target === undefined && !mayCreateAt(store, bucket, segs, who)) {
      return fail("AccessDenied",
        "the access control list does not permit a write at this key");
    }
    if (target !== undefined && !may(store, target.node, who, M.WRITE_OBJECT)) {
      return fail("AccessDenied",
        "the access control list does not permit a write at this key");
    }
    const typeRaw = req.headers["content-type"];
    const mimetype = (Array.isArray(typeRaw) ? typeRaw[0] : typeRaw) ??
      "application/octet-stream";
    const upload = uploads.begin(bucketName, key, who.name,
      mimetype.split(";")[0].trim());
    const body = Buffer.from(initiateBody(bucketName, key, upload.id), "utf8");
    res.writeHead(200, {
      "Content-Type": "application/xml",
      "Content-Length": String(body.length),
      "x-amz-request-id": id,
    });
    res.end(body);
    return true;
  }

  const uploadId = params.get("uploadId") ?? "";
  const upload = uploads.get(uploadId);
  if (upload === undefined || upload.bucket !== bucketName) {
    return fail("NoSuchUpload", "the upload identifier names no upload in progress");
  }

  // A part is added, and a listing of parts made, under the identity
  // that initiated the upload.
  if (method === "PUT" || (method === "GET" && upload !== undefined)) {
    if (upload.initiator !== who.name) {
      return fail("AccessDenied", "this upload was initiated by another identity");
    }
  }

  if (method === "PUT") {
    const number = Number(params.get("partNumber") ?? "0");
    // A part supplied as the value, or a range of the value, of an
    // existing data object addressed by a key of a bucket this
    // server serves.
    const sourceRaw = req.headers["x-amz-copy-source"];
    const source = Array.isArray(sourceRaw) ? sourceRaw[0] : sourceRaw;
    if (source !== undefined && source !== "") {
      if (!Number.isInteger(number) || number < 1 || number > MAX_PARTS) {
        return fail("InvalidArgument", `a part number is between 1 and ${MAX_PARTS}`);
      }
      return await uploadPartCopy(req, res, store, bucket, upload, number,
        who, source, resource, id, uploads);
    }
    if (!Number.isInteger(number) || number < 1 || number > MAX_PARTS) {
      return fail("InvalidArgument",
        `a part number is between 1 and ${MAX_PARTS}`);
    }
    const body = await readBody(req);
    if (body.length > MAX_PART_SIZE) {
      return fail("EntityTooLarge", "the part is larger than this server accepts");
    }
    const digest = checkDigests(
      req.headers as Record<string, string | string[] | undefined>, body);
    if (digest !== undefined) return fail("BadDigest", digest.fault);
    // A part may arrive more than once for one number, and the most
    // recent replaces the earlier.
    const part = uploads.addPart(upload, number, body);
    res.writeHead(200, {
      ETag: `"${part.etag}"`,
      "Content-Length": "0",
      "x-amz-request-id": id,
    });
    res.end();
    return true;
  }

  if (method === "GET") {
    const body = Buffer.from(partsBody(bucketName, upload), "utf8");
    res.writeHead(200, {
      "Content-Type": "application/xml",
      "Content-Length": String(body.length),
      "x-amz-request-id": id,
    });
    res.end(body);
    return true;
  }

  if (method === "DELETE") {
    // An abort is permitted to the identity that initiated the
    // upload, or one that would be permitted to delete the object.
    const target = resolveKey(store, bucket, segs);
    const mayDelete = target !== undefined && may(store, target.node, who, M.DELETE);
    if (upload.initiator !== who.name && !mayDelete) {
      return fail("AccessDenied", "this identity may neither end this upload nor " +
        "delete the object at its key");
    }
    uploads.end(upload.id);
    res.writeHead(204, { "x-amz-request-id": id });
    res.end();
    return true;
  }

  if (method !== "POST") {
    return fail("NotImplemented",
      `this CDMI server does not serve the ${method} method of an upload`);
  }

  // Completing an upload.
  if (upload.initiator !== who.name) {
    // The permissions a PutObject requires, evaluated at the time of
    // the completion rather than of the initiation.
    const target = resolveKey(store, bucket, segs);
    const permitted = target === undefined
      ? mayCreateAt(store, bucket, segs, who)
      : may(store, target.node, who, M.WRITE_OBJECT);
    if (!permitted) {
      return fail("AccessDenied",
        "the access control list does not permit a write at this key");
    }
  }
  const listed = parseCompleteBody((await readBody(req)).toString("utf8"));
  if (listed === undefined) {
    return fail("InvalidRequest", "the request lists no part to assemble");
  }
  for (let i = 1; i < listed.length; i++) {
    if (listed[i].number <= listed[i - 1].number) {
      return fail("InvalidPartOrder",
        "the parts are listed in ascending order of part number");
    }
  }
  const bodies: Buffer[] = [];
  for (const [i, wanted] of listed.entries()) {
    const held = upload.parts.get(wanted.number);
    if (held === undefined || held.etag !== wanted.etag) {
      return fail("InvalidPart",
        `part ${wanted.number} was not uploaded, or its entity tag does not match`);
    }
    // Every part but the last is at least the smallest this server
    // assembles.
    if (i < listed.length - 1 && held.body.length < MIN_PART_SIZE) {
      return fail("EntityTooSmall",
        `part ${wanted.number} is smaller than this server assembles`);
    }
    bodies.push(held.body);
  }

  // "The CDMI server ... shall reject the request with AccessDenied where it is
  // not permitted or where the data object is subject to retention or to a hold
  // that forbids the replacement. In both cases the upload shall remain in
  // progress, so that the client may abort it or retry after the condition is
  // resolved" — so this returns before uploads.end below, leaving the upload
  // where it was.
  const standing = resolveKey(store, bucket, segs);
  if (standing !== undefined &&
    underRestriction(store.meta(standing.node).metadata)) {
    return fail("AccessDenied",
      "the object at this key is under retention or under hold, and its value " +
      "is not replaced until that ends; this upload remains in progress");
  }
  // The object at the key is created or replaced only now: until a
  // completion succeeds the CDMI server neither creates nor modifies
  // it.
  const at = ensureContainers(store, bucket, segs, who);
  if (at === undefined) {
    return fail("AccessDenied",
      "the access control list does not permit creating an intervening container");
  }
  const name = segs[segs.length - 1];
  const node = store.lookupKind(at, name, "data") ?? store.createData(at, name, {
    owner: who.name === ANONYMOUS.name ? "" : who.name,
    acl: store.meta(at).acl,
  });
  const whole = Buffer.concat(bodies);
  await store.setValue(node, whole);
  const m = store.meta(node);
  m.mimetype = upload.mimetype;
  m.vte = "base64";
  store.setMeta(node, m);
  await store.rehash(node);
  uploads.end(upload.id);
  const assembled = store.meta(node);
  store.setMultipart(assembled.objectID, assembled.version, listed.length);

  const body = Buffer.from(
    completeBody(`/${bucketName}/${key}`, bucketName, key,
      s3ETag(store.meta(node), store)),
    "utf8",
  );
  res.writeHead(200, {
    "Content-Type": "application/xml",
    "Content-Length": String(body.length),
    "x-amz-request-id": id,
  });
  res.end(body);
  return true;
}

/** Whether the principal may create the object a key names. */
function mayCreateAt(store: Store, bucket: Bucket, segs: string[],
  who: Principal): boolean {
  let at = bucket.node;
  for (const seg of segs.slice(0, -1)) {
    const next = store.lookupKind(at, seg, "container");
    if (next === undefined) return may(store, at, who, M.ADD_SUBCONTAINER);
    at = next;
  }
  return may(store, at, who, M.ADD_OBJECT);
}

/** The container a key's object belongs in, creating what is absent. */
function ensureContainers(store: Store, bucket: Bucket, segs: string[],
  who: Principal): Node | undefined {
  let at = bucket.node;
  for (const seg of segs.slice(0, -1)) {
    const next = store.lookupKind(at, seg, "container");
    if (next !== undefined) {
      at = next;
      continue;
    }
    if (!may(store, at, who, M.ADD_SUBCONTAINER)) return undefined;
    at = store.createContainer(at, seg, {
      owner: who.name === ANONYMOUS.name ? "" : who.name,
      acl: store.meta(at).acl,
    });
  }
  return at;
}

// ---------------------------------------------------------------------
// Metadata

/** Whether a name is a token, which is what an HTTP field name may be. */
export function isToken(name: string): boolean {
  return /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name);
}

/**
 * The user metadata items a response presents as x-amz-meta- fields.
 *
 * An item whose name is not a token is omitted, an HTTP field name
 * being restricted to those characters while a CDMI metadata item
 * name is an arbitrary UTF-8 string; it remains reachable through
 * CDMI. An item whose name begins with cdmi_ is not presented. Where
 * two items differ only in case, neither is presented, there being
 * no way to tell which a client meant.
 */
export function metadataFor(metadata: Record<string, unknown>):
  Record<string, string> {
  const byLower = new Map<string, string[]>();
  for (const name of Object.keys(metadata)) {
    if (name.startsWith("cdmi_")) continue;
    if (!isToken(name)) continue;
    const lower = name.toLowerCase();
    byLower.set(lower, [...(byLower.get(lower) ?? []), name]);
  }
  const out: Record<string, string> = {};
  for (const [lower, names] of byLower) {
    // Two items differing only in case: neither is presented.
    if (names.length > 1) continue;
    const value = metadata[names[0]];
    if (typeof value !== "string") continue;
    // A value is percent encoded, an HTTP field value being
    // restricted to US-ASCII while a CDMI value is arbitrary UTF-8,
    // and never carries a carriage return, line feed or null.
    out[`x-amz-meta-${lower}`] = encodeURI(value)
      .replace(/[\r\n\u0000]/g, "");
  }
  return out;
}

/**
 * The user metadata a request supplies, with the prefix removed and
 * the names in lower case.
 */
export function metadataFrom(headers: Record<string, string | string[] | undefined>):
  { metadata: Record<string, string> } | { fault: string } {
  const out: Record<string, string> = {};
  for (const [field, raw] of Object.entries(headers)) {
    const lower = field.toLowerCase();
    if (!lower.startsWith("x-amz-meta-")) continue;
    const name = lower.slice("x-amz-meta-".length);
    if (name === "") continue;
    // A name which, once the prefix is removed, begins with cdmi_ is
    // refused: a request does not create or modify those items.
    if (name.startsWith("cdmi_")) {
      return { fault: "a metadata name may not begin with \"cdmi_\"" };
    }
    const value = Array.isArray(raw) ? raw.join(",") : (raw ?? "");
    if (/[\r\n\u0000]/.test(value)) {
      return { fault: "a metadata value carries no carriage return, line feed or null" };
    }
    // The corresponding decoding of what a response percent encodes.
    let decoded = value;
    try {
      decoded = decodeURI(value);
    } catch {
      // A value that is not valid percent encoding is taken as it
      // stands, which is what a client that did not encode meant.
    }
    out[name] = decoded;
  }
  return { metadata: out };
}

/** Serves a ListObjectVersions request. */
function listVersions(res: ServerResponse, store: Store, bucket: Bucket,
  who: Principal, params: URLSearchParams, resource: string, id: string): boolean {
  if (bucket.entry.versioning !== "true") {
    sendError(res, "InvalidArgument",
      "this bucket is not presented as version enabled", resource, id);
    return true;
  }
  if (!may(store, bucket.node, who, M.LIST_CONTAINER)) {
    sendError(res, "AccessDenied",
      "the access control list does not permit listing this bucket", resource, id);
    return true;
  }
  const prefix = params.get("prefix") ?? "";
  const entries: {
    key: string; versionId: string; latest: boolean;
    size: number; mtime: number; etag: string;
  }[] = [];
  for (const k of keysOf(store, bucket.node, "", (n) => may(store, n, who, M.READ_OBJECT))) {
    if (!k.key.startsWith(prefix)) continue;
    const found = resolveKey(store, bucket, k.key.split("/"));
    if (found === undefined) continue;
    const m = store.meta(found.node);
    // The current content first, then the CDMI versions from most
    // to least recent.
    entries.push({
      key: k.key,
      versionId: m.objectID,
      latest: true,
      size: m.size,
      mtime: m.mtime,
      etag: s3ETag(m, store),
    });
    const versions = store.versionsOf(found.node)
      .map((v) => ({ node: v, m: store.meta(v) }))
      .sort((a, b) => b.m.mtime - a.m.mtime);
    for (const v of versions) {
      entries.push({
        key: k.key,
        versionId: v.m.objectID,
        latest: false,
        size: v.m.size,
        mtime: v.m.mtime,
        etag: s3ETag(v.m, store),
      });
    }
  }
  const body = Buffer.from(versionsBody(bucket.entry.bucket_name, entries), "utf8");
  res.writeHead(200, {
    "Content-Type": "application/xml",
    "Content-Length": String(body.length),
    "x-amz-request-id": id,
  });
  res.end(body);
  return true;
}

// ---------------------------------------------------------------------
// Checksums

/**
 * The checksum algorithms this CDMI server verifies. CRC32 and
 * CRC64NVME are the defaults of the AWS libraries, and a server that
 * lists neither rejects their default configuration.
 */
export const CHECKSUMS = ["CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256"];

/** The table of CRC-32, computed once. */
const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[i] = c >>> 0;
  }
  return table;
})();

/** The table of CRC-32C, which uses the Castagnoli polynomial. */
const CRC32C_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0x82f63b78 ^ (c >>> 1) : c >>> 1;
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32With(table: Uint32Array, body: Buffer): number {
  let c = 0xffffffff;
  for (const byte of body) c = table[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** The table of CRC-64/NVME, which uses the Rocksoft polynomial reflected. */
const CRC64_TABLE = (() => {
  const poly = 0x9a6c9329ac4bc9b5n;
  const table: bigint[] = [];
  for (let i = 0; i < 256; i++) {
    let c = BigInt(i);
    for (let k = 0; k < 8; k++) {
      c = c & 1n ? poly ^ (c >> 1n) : c >> 1n;
    }
    table.push(c & 0xffffffffffffffffn);
  }
  return table;
})();

function crc64nvme(body: Buffer): bigint {
  let c = 0xffffffffffffffffn;
  for (const byte of body) {
    c = CRC64_TABLE[Number((c ^ BigInt(byte)) & 0xffn)] ^ (c >> 8n);
  }
  return (c ^ 0xffffffffffffffffn) & 0xffffffffffffffffn;
}

/** The checksum of a body under one algorithm, base 64 encoded. */
export function checksumOf(algorithm: string, body: Buffer): string | undefined {
  switch (algorithm.toUpperCase()) {
    case "CRC32": {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(crc32With(CRC32_TABLE, body));
      return b.toString("base64");
    }
    case "CRC32C": {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(crc32With(CRC32C_TABLE, body));
      return b.toString("base64");
    }
    case "CRC64NVME": {
      const b = Buffer.alloc(8);
      const v = crc64nvme(body);
      b.writeUInt32BE(Number((v >> 32n) & 0xffffffffn), 0);
      b.writeUInt32BE(Number(v & 0xffffffffn), 4);
      return b.toString("base64");
    }
    case "SHA1":
      return createHash("sha1").update(body).digest("base64");
    case "SHA256":
      return createHash("sha256").update(body).digest("base64");
    default:
      return undefined;
  }
}

/**
 * Verifies the digests a request carries. A Content-MD5 field is
 * verified always; an x-amz-checksum- field is verified where the
 * algorithm it names is one this CDMI server lists.
 */
export function checkDigests(headers: Record<string, string | string[] | undefined>,
  body: Buffer): { fault: string } | undefined {
  const one = (name: string): string | undefined => {
    const raw = headers[name];
    const value = Array.isArray(raw) ? raw[0] : raw;
    return value === undefined || value === "" ? undefined : value;
  };
  const md5 = one("content-md5");
  if (md5 !== undefined) {
    if (createHash("md5").update(body).digest("base64") !== md5) {
      return { fault: "the Content-MD5 of the request does not match its body" };
    }
  }
  for (const algorithm of CHECKSUMS) {
    const supplied = one(`x-amz-checksum-${algorithm.toLowerCase()}`);
    if (supplied === undefined) continue;
    if (checksumOf(algorithm, body) !== supplied) {
      return { fault: `the ${algorithm} checksum of the request does not match its body` };
    }
  }
  // An algorithm this server does not list is not verified, and a
  // request naming one is served: the capability says which are.
  return undefined;
}

/** The checksum fields a response carries for a body. */
export function checksumHeaders(
  headers: Record<string, string | string[] | undefined>,
  body: Buffer): Record<string, string> {
  const out: Record<string, string> = {};
  for (const algorithm of CHECKSUMS) {
    const field = `x-amz-checksum-${algorithm.toLowerCase()}`;
    if (headers[field] === undefined) continue;
    const got = checksumOf(algorithm, body);
    if (got !== undefined) out[field] = got;
  }
  return out;
}

/**
 * The aggregate size of the metadata presented for an object,
 * measured as the sum of the UTF-8 encoded lengths of the names and
 * the values after the encoding is applied.
 */
export function metadataSize(presented: Record<string, string>): number {
  let total = 0;
  for (const [name, value] of Object.entries(presented)) {
    total += Buffer.byteLength(name, "utf8") + Buffer.byteLength(value, "utf8");
  }
  return total;
}

/** The greatest aggregate size of metadata this CDMI server presents. */
export const S3_METADATA_MAXTOTALSIZE = 2048;

/**
 * Supplies a part from the value of an existing data object. The
 * read is authorised under the identity that signed the request,
 * and the bytes are copied at the time of the request, so a later
 * change to the source does not affect the part.
 */
async function uploadPartCopy(req: IncomingMessage, res: ServerResponse,
  store: Store, bucket: Bucket, upload: Upload, number: number, who: Principal,
  source: string, resource: string, id: string,
  uploads: Uploads): Promise<boolean> {
  const fail = (code: string, message: string) => {
    sendError(res, code, message, resource, id);
    return true;
  };
  // The source is /bucket/key, the bucket being one this server
  // serves. A version identifier is not accepted here.
  const at = source.replace(/^\//, "");
  const cut = at.indexOf("/");
  if (cut < 0) return fail("InvalidArgument", "a copy source is of the form /bucket/key");
  const sourceBucket = decodeURIComponent(at.slice(0, cut));
  const sourceKey = at.slice(cut + 1).split("/")
    .map((s) => decodeURIComponent(s)).join("/");
  if (sourceBucket !== bucket.entry.bucket_name) {
    // A bucket of another export is not reached from here: this
    // server holds one bucket per entry and the entry is the one
    // routed to.
    return fail("NoSuchBucket",
      "a copy source names a bucket this request does not address");
  }
  const segs = segmentsOf(sourceKey);
  if (segs === undefined) return fail("NoSuchKey", "the copy source names no object");
  const found = resolveKey(store, bucket, segs);
  if (found === undefined) return fail("NoSuchKey", "the copy source names no object");
  if (!may(store, found.node, who, M.READ_OBJECT)) {
    return fail("AccessDenied",
      "the access control list of the source does not permit this read");
  }

  const whole = await store.readValue(found.node);
  // A range of the value, where the request names one.
  const rangeRaw = req.headers["x-amz-copy-source-range"];
  const range = Array.isArray(rangeRaw) ? rangeRaw[0] : rangeRaw;
  let body = whole;
  if (range !== undefined && range !== "") {
    const m = /^bytes=(\d+)-(\d+)$/.exec(range);
    if (m === null) return fail("InvalidArgument", "a copy source range is bytes=first-last");
    const first = Number(m[1]);
    const last = Number(m[2]);
    if (first > last || last >= whole.length) {
      return fail("InvalidRange", "the copy source range is not satisfiable");
    }
    body = whole.subarray(first, last + 1);
  }
  if (body.length > MAX_PART_SIZE) {
    return fail("EntityTooLarge", "the part is larger than this server accepts");
  }

  // Copied now, so a later change to the source does not affect it.
  const part = uploads.addPart(upload, number, Buffer.from(body));
  const xml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<CopyPartResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
    `<ETag>&quot;${escapeXML(part.etag)}&quot;</ETag>` +
    `<LastModified>${new Date(part.received).toISOString().replace(/\.\d+Z$/, ".000Z")}` +
    "</LastModified></CopyPartResult>\n";
  const out = Buffer.from(xml, "utf8");
  res.writeHead(200, {
    "Content-Type": "application/xml",
    "Content-Length": String(out.length),
    "x-amz-request-id": id,
  });
  res.end(out);
  return true;
}
