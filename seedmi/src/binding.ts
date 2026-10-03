// The HTTP protocol binding of clause 13: representations, selections, the
// three update forms, conditional requests, and the operations of clause 11
// as the layering rules of clause 9 direct them.

import { homeNameOf, homeOf, homeOwnerOf, USERINFO_MEMBERS, type HomeServerConfig, type HomesConfig, sameDomain, USERINFO, userinfoOf } from "./userinfo.ts";
import { PIPE_QUEUE_TYPE, type PipeService, SUBPROTOCOL, TICKET_MEDIA_TYPE } from "./pipe.ts";
import { runRelay } from "./pipe-relay.ts";
import { handshake } from "./ws-server.ts";
import { DomainController, DomainControllers } from "./domain-controller.ts";
import { ETYPE } from "./krb-crypto.ts";
import { extensionFields as bodyExtensions, isDefinedField, mergedExtensions, type ObjectKind } from "./fields.ts";
import { splitMultipart } from "./multipart.ts";
import {
  EncryptedValueError, isEncryptedMediaType, keyForEncryptedValue, MT_CMS, readEncryptedValue,
} from "./encrypted.ts";
import {
  decryptValue, encryptValue, isSignedValue, JWE_ALG, JWE_ENC, verificationKey,
  verifiedPayload,
} from "./encrypt-inplace.ts";
import { DIGEST_ALGORITHMS, signatureAlgorithm, signaturePayload, signObjectPayload, JWS_ALGORITHMS } from "./object-signature.ts";
import { enumName } from "./kmip-message.ts";

import { readReference, boundReference, type CredentialReference, registersItself, resolveReference } from "./credential.ts";
import { CDMI_IMPORT_VERSIONS, HTTP_EXPORT_VERSIONS, S3_EXPORT_VERSIONS } from "./protocol-versions.ts";
import { AsyncLocalStorage } from "node:async_hooks";
import { DacClient, type DacContext, DacError, type DacOperation, type DacTarget } from "./dac.ts";
import { withDelegation } from "./dac-context.ts";
import { checkDescriptors, descriptorsOf, type KmsDescriptor } from "./credential.ts";
import { type KeyManagement, kmsCapabilities } from "./kms.ts";
import { claimScope, releaseScope } from "./kms-binding.ts";
import { bindReference, CERTIFICATE, type CredentialContext, PASSWORD, retrieveCertificate, retrieveSecret,
  scopeStillApplies, SERVICE_KEY, KEY_ENCRYPTION_KEY, resolveKeyInPlace, OBJECT_SIGNING_KEY, SIGNATURE_VERIFY_KEY } from "./credential-use.ts";
import { checkPermitted } from "./originated.ts";
import { dohItemFault } from "./doh.ts";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createHash, randomUUID } from "node:crypto";
import {
  ASSIGNED, DOMAINS, SNAPSHOTS, type ACE, type Meta as StoredMeta, type Node,
  type Kind, type QueueValue, Store, StoreError, VALUE_HASHES,
  isAssigned, reservedName, withoutRestrictions,
} from "./store.ts";
import {
  type DirRef, type ObjRef, type ObjectView, nodeOf, readValueOf, refOfDir,
  viewOf,
} from "./objects.ts";
import {
  FILESYSTEMS, HTTP_IMPORT_VERSIONS, delegationConfigured, parseImports, type ImportEntry,
  localImportPath,
} from "./imports.ts";
import {
  establish as establishImport, type HttpImportEntry, obtain as obtainImport, stillFresh,
} from "./http-import.ts";
import {
  Resolver, type View, denyChange, ensureImageWriteTarget, ensureWriteTarget, flushImage,
  importsProvidedFor, listChildren, presentable, rankCmp, referenceIn, resolveFile,
  type Layer, type Provided,
} from "./layers.ts";
import { type Published, profilesMet } from "./profiles.ts";
import { capabilityCondition,
  conflictingFields,
  problem,
  alreadyExists, alreadyExistsPrecondition, cdmiTime, Condition, conflict, conflictImportLayer, forbidden, notPermittedForObjectType, invalidField,
  invalidSelection, isCondition, malformed, notAcceptable, notFound, serverError, capabilityNotPresent, fieldPointer,
  SEEDMI_PROBLEM_BASE, PROBLEM_BASE, lockConflict, lockForbidden, retentionConflict,
} from "./problems.ts";
import {
  checkHeaderMetadataItem,
  Exports, HEADER_METADATA_MAXITEMS, HEADER_METADATA_MAXSIZE,
  HEADER_METADATA_MAXTOTALSIZE, CDMI_EXPORT_VERSIONS, EXPORT_AUTH_METHODS,
} from "./exports.ts";
import { Discovery } from "./discovery.ts";
import {
  addressOf, collectResponse, composeRequest, mediaTypeOf as mcpMediaTypeOf, rangeAsked,
  relativeToBase, remoteAddresses, representationOf, resultOf,
} from "./mcp-operations.ts";
import type { ResourceServer as McpResourceServer } from "./mcp-auth.ts";
import {
  mcpAccountOf, mcpAccountOfProblem, mcpNotYet,
} from "./mcp-account.ts";
import { Log, SILENT } from "./log.ts";
import { MqttImporter } from "./mqtt-import.ts";
import { failInterruptedQueries, QueryRunner } from "./query-run.ts";
import {
  checkServiceLevel, GEOGRAPHIC_PLACEMENT, IMMEDIATE_REDUNDANCY,
  serviceLevelAchieved, serviceLevelProvided,
} from "./service-level.ts";
import {
  DEFAULT_EXPIRY, MAX_PART_SIZE, MAX_PARTS, MIN_PART_SIZE,
} from "./s3-multipart.ts";
import { CHECKSUMS, S3_METADATA_MAXTOTALSIZE } from "./s3-serve.ts";
import {
  checkNotificationMetadata, EVENTS, isNotificationQueue, Notifier,
} from "./notify.ts";
import {
  checkQueryMetadata, isQueryQueue, QUERY_STATUS, QUEUE_TYPE, refuseQueryChange,
  RESULTS, SCOPE,
} from "./query.ts";
import { EA_MAXNAME, EA_MAXSIZE } from "./smb-info.ts";
import { type RemoteSource, remoteSource } from "./remote.ts";
import {
  CORS_HEADERS, CORS_METHODS, CORS_ORIGINS, answerPreflight, applyCors, checkCorsItems,
  isPreflight,
} from "./cors.ts";
import { checkRel } from "./rel.ts";
import {
  defaultType, Derivations, heldType, membersOf, memberName, REPRESENTABLE_LIMIT,
  type Representation, setValueRepresentations, typesOf, VALUE_REPRESENTATIONS,
} from "./representations.ts";

// Re-exported so that the name a deployment and the tests already use keeps
// working: the switch itself lives with the feature it governs.
export { REPRESENTABLE_LIMIT, setValueRepresentations, VALUE_REPRESENTATIONS };
import { MAXNAME } from "./nfs.ts";
import {
  RETENTION_ITEMS, HOLD_ID, type Restriction, autodeletable, changesMore, checkChange,
  APPLIED_AT, faultCondition, providedItems, recordApplied, restricted, restrictedWithin,
  restrictionOf,
} from "./retention.ts";
import {
  type Canonical, type SerializeContext, SerializeError, deserializableMetadata,
  extensionFields, MT_QUEUE as CANONICAL_QUEUE, nameOf, parseCanonical, serialize,
  valueOf,
} from "./serialize.ts";
import { type FAT, storableName } from "./fat.ts";
import { unsupportedIn, SUPPORTED_FLAGS, SUPPORTED_MASK_BITS,
  ANONYMOUS, M, aclForNewObject, deniedExplicitly, granted, grantedMask, maskToString, parseACE,
  parseMask, type Principal,
} from "./acl.ts";
import { Directory } from "./identity.ts";

export const MT_CONTAINER = "application/cdmi-container";
export const MT_DOMAIN = "application/cdmi-domain";
export const MT_OBJECT = "application/cdmi-object";
export const MT_CAPABILITY = "application/cdmi-capability";
/** A queue object holds an ordered sequence of values. */
/**
 * A conditional request whose validator does not match: revision 211 gives
 * this condition its own type, in place of the bare status this server
 * reported before.
 */
const validatorConflict = () =>
  new Condition(412, "conflict/validator",
    "The request was not performed because a validator did not match.",
    "the entity tag supplied does not match the current representation of the object");

/** The metadata items that request delegated access control (Annex D). */
export const DAC_ITEMS = ["cdmi_dac_uri", "cdmi_dac_certificate"];

export const MT_QUEUE = "application/cdmi-queue";

/**
 * The path, beneath the base URI, at which a delegated access control response
 * sent out of band is received. The draft leaves the URI to the CDMI server;
 * this server serves one path, and the configured "response_uri" is expected
 * to address it.
 */
export const DAC_RESPONSE_PATH = "cdmi_dac_response";

/**
 * The storage system metadata items this server generates for an
 * object, each reported by the capability of the same name.
 */
const STORAGE_SYSTEM_METADATA = [
  "cdmi_acl", "cdmi_size", "cdmi_ctime", "cdmi_atime", "cdmi_mtime",
  "cdmi_acount", "cdmi_mcount", "cdmi_owner", "cdmi_group",
];

/**
 * The items an object presented through an import does not have. This server
 * counts nothing for an object it does not hold, and neither a file system nor
 * another server's representation is obliged to carry the counts — where a
 * remote source does report them they are passed through, so the capability is
 * withheld and the items appear where the source provides them, as every other
 * item of an imported object does.
 */
const UNCOUNTED = ["cdmi_acount", "cdmi_mcount"];

/**
 * The entry flags and the mask bits this server both stores and
 * enforces, each in its string form. TRAVERSE_CONTAINER is stored and
 * enforced by no CDMI server, and is reported for that reason.
 */
const ACL_CAPABILITIES: Record<string, unknown> = {
  // The same lists by which an entry is refused (acl.ts, unsupportedIn).
  cdmi_acl_flags: SUPPORTED_FLAGS,
  cdmi_acl_mask_bits: SUPPORTED_MASK_BITS,
};

/** The reserved child through which objects are addressed by object ID. */
const OBJECTID_TREE = "/cdmi_objectid/";

/**
 * The reserved children of the root container object. They are not
 * objects of the store, and are presented by the protocol binding
 * alone: an export or an NFS client sees the namespace without them.
 */
// The reserved children of the root, in the order of the draft's table: "A CDMI
// server shall report each reserved child that it supports". This server
// supports all three, publishing cdmi_domains and cdmi_object_access_by_ID;
// cdmi_domains/ was omitted before 0.44.
const RESERVED_CHILDREN = ["cdmi_capabilities/", "cdmi_domains/", "cdmi_objectid/"];
const MAX_BODY = 64 << 20;

/** The fields a client may select. Any other name is an invalid selection. */
const SELECTABLE = new Set([
  "objectType", "objectID", "objectName", "parentURI", "parentID", "domainURI",
  "capabilitiesURI", "completionStatus", "percentComplete", "metadata", "imports",
  "exports", "importsProvided", "exportsProvided", "mimetype", "valuetransferencoding",
  "valuerange", "value", "children", "childrenrange", "childfields", "capabilities",
  "rel", "snapshots",
  // Fields the representation clause defines that were missing before 0.3,
  // so selecting them was refused as an invalid selection: the queue
  // object's designator range, and the common field reporting why an
  // operation did not complete.
  "queueValues", "completionError",
]);

/** The fields reported for a child in an extended child listing. */
const CHILD_FIELDS = new Set([
  "objectType", "objectID", "objectName", "parentURI", "parentID", "capabilitiesURI",
  "completionStatus", "metadata", "mimetype", "valuetransferencoding", "importsProvided",
  "rel",
  // A container's children, as a plain list of names, and null for any other
  // child: a field defined for the object type is answered, with null where it
  // does not exist for a child. It was refused before 0.44.
  "children",
  // "The absolute URI to which a child that is a reference redirects ... A
  // reference has no representation, and this field reports its destination
  // rather than a field of a child. It is returned only in an extended child
  // listing that names it, and the value is null for a child that is not a
  // reference" (revision 297).
  "location",
  // The value of a child, and the range of it returned.
  //
  // This is a **deliberate divergence** from revision 365, which says that "an
  // extended child listing may name any field of the representation of a child
  // other than the value field". The exclusion is what stops a listing from
  // reporting what a serialization reports, and is one of the six gaps between
  // the two that ECR-235A records; nothing else in the definition of an extended
  // child listing depends on it.
  //
  // Two mechanisms keep the divergence from being a hazard, and both are the
  // document's own. The value of a child is returned only where the access
  // control lists of that child permit the principal to read it, as every other
  // field of a child already is — a listing that disclosed values a read would
  // refuse would be a disclosure defect rather than a relaxation. And a listing
  // carries at most one representation's worth of value in total, after which the
  // value of each further child is declined: "a CDMI server that declines to
  // return a field an extended child listing names shall return null for that
  // field and shall not report an error", so a container object of ten thousand
  // large children yields a bounded response rather than the sum of its values.
  "value", "valuerange",
]);

interface Selection {
  /** Whether the children of each child container object are listed. */
  recursive?: boolean;
  /** How far a recursive listing descends. */
  childDepth?: number;
  fields: string[];
  any: boolean;
  value: boolean;
  valueRanges: [number, number][];
  childRange?: [number, number];
  metaPrefixes: string[];
  metaSelected: boolean;
  childFields: string[];
  /**
   * What remains of the value a listing of this request may carry, in octets.
   * One per request, spent by each child whose value is returned, so that a
   * listing that names the value field is bounded however many children the
   * container object holds (CHILD_FIELDS above).
   */
  valueBudget?: { left: number };
  /**
   * The queue value selection: a count of values, or a range of
   * designators. Bare "values" is equivalent to a count of one, which
   * is what distinguishes removing a value from deleting the queue
   * object itself.
   */
  queueValues?: { count: number } | { range: [number, number] };
  /**
   * The value layout selection, valuerange=<offset> (revision 269): the
   * valuerange field reports the first range at or after the offset to which
   * bytes have been written.
   */
  layoutOffset?: number;
  /**
   * The selection "*": "A field selection of \"*\" selects every field of the
   * representation, the \"value\" field included, so that a CDMI client
   * receives a field this document defines later and that a CDMI client
   * written before it does not name" (revision 297). A value range or child
   * range selection beside it governs the bytes or the children returned.
   */
  everyField?: boolean;
  /**
   * The fields named with a value, such as a metadata prefix or a value
   * range: those may repeat, and a field named bare may not repeat at all.
   */
  valued: Set<string>;
  /**
   * Whether the value returned is less than the whole because a gap cut it
   * short: its range is then reported beside it, since a client cannot
   * otherwise tell how much it received.
   */
  partialValue?: boolean;
}

const emptySelection = (): Selection => ({
  fields: [], any: false, value: false, valueRanges: [],
  metaPrefixes: [], metaSelected: false, childFields: [], valued: new Set(),
  // The same bound a single representation of a value is held to, so that a
  // listing carrying values is no larger than a read of one object could be.
  valueBudget: { left: REPRESENTABLE_LIMIT },
});

function parseRange(s: string): [number, number] | undefined {
  // A number of the grammar has no leading zero: "01-3" is not a range
  // (weedmi OPER-006).
  const m = /^(0|[1-9]\d*)-(0|[1-9]\d*)$/.exec(s);
  if (!m) return undefined;
  const a = Number(m[1]);
  const b = Number(m[2]);
  return b < a ? undefined : [a, b];
}

/** Parses the query component of a request URI as a selection. */
export function parseSelection(query: string): Selection {
  const sel = emptySelection();
  if (query === "") return sel;
  sel.any = true;
  const seen = new Set<string>();
  for (const token of query.split("&")) {
    const eq = token.indexOf("=");
    const rawName = eq < 0 ? token : token.slice(0, eq);
    const rawValue = eq < 0 ? undefined : token.slice(eq + 1);
    let name: string;
    try {
      name = decodeURIComponent(rawName);
    } catch {
      throw invalidSelection(token, "the selection is malformed");
    }
    if (name === "") throw invalidSelection(token, "the selection is malformed");

    // The metadata selection and the value range selection may each appear
    // more than once; every other selection may appear once.
    const repeatable = name === "metadata" || (name === "value" && rawValue !== undefined);
    if (seen.has(name) && !repeatable) {
      throw invalidSelection(token, "the selection %j appears more than once", name);
    }
    seen.add(name);

    switch (name) {
      case "*": {
        if (rawValue !== undefined) throw invalidSelection(token, "a field selection does not take a value");
        sel.everyField = true;
        continue;
      }
      case "value": {
        if (sel.value && (rawValue === undefined || sel.valueRanges.length === 0)) {
          throw invalidSelection(token,
            "a value selection without a range appears with another value selection");
        }
        sel.value = true;
        if (rawValue !== undefined) {
          const r = parseRange(rawValue);
          if (!r) throw invalidSelection(token, "the range is malformed");
          if (sel.valueRanges.some(([a, b]) => r[0] <= b && a <= r[1])) {
            throw invalidSelection(token, "the selected ranges overlap");
          }
          sel.valueRanges.push(r);
        }
        break;
      }
      case "children": {
        if (rawValue !== undefined) {
          const r = parseRange(rawValue);
          if (!r) throw invalidSelection(token, "the range is malformed");
          sel.childRange = r;
        }
        break;
      }
      case "metadata": {
        sel.metaSelected = true;
        sel.metaPrefixes.push(rawValue === undefined ? "" : decodeURIComponent(rawValue));
        break;
      }
      case "childfields": {
        if (rawValue === undefined || rawValue === "") {
          throw invalidSelection(token,
            "the extended child selection requires one or more field names");
        }
        for (const f of decodeURIComponent(rawValue).split(";")) {
          if (!CHILD_FIELDS.has(f)) {
            throw invalidSelection(token, "%j is not a field seedmi reports for a child", f);
          }
          sel.childFields.push(f);
        }
        break;
      }
      case "childrecursive": {
        if (rawValue !== undefined && rawValue !== "") {
          if (!/^[0-9]+$/.test(rawValue)) {
            throw invalidSelection(token, "the depth of a recursive listing is a number");
          }
          sel.childDepth = Number(rawValue);
        } else {
          sel.childDepth = Infinity;
        }
        sel.recursive = true;
        break;
      }
      case "valuerange": {
        // "Value layout selection - valuerange=<offset> - Selects the valuerange
        // field, which indicates the first range of the value at or after the byte
        // offset given to which bytes have been written ... valuerange without an
        // offset selects the field as a field selection does" (revision 269).
        if (rawValue !== undefined) {
          if (!/^[0-9]+$/.test(rawValue)) throw invalidSelection(token, "the offset of a value layout selection is a number");
          sel.layoutOffset = Number(rawValue);
        }
        break;
      }
      case "values": {
        if (rawValue === undefined || rawValue === "") {
          // Bare "values" selects the oldest value alone.
          sel.queueValues = { count: 1 };
          break;
        }
        if (/^[0-9]+$/.test(rawValue)) {
          sel.queueValues = { count: Number(rawValue) };
          break;
        }
        const r = parseRange(rawValue);
        if (!r) {
          throw invalidSelection(token,
            "a queue value selection is a count or a range of designators");
        }
        sel.queueValues = { range: r };
        break;
      }
      default: {
        if (rawValue !== undefined) {
          throw invalidSelection(token, "a field selection does not take a value");
        }
        // A name the draft does not define may be an extension field stored
        // with the object, which a selection may name; whether it is one is
        // known when the object is read (applySelection).
        if (!SELECTABLE.has(name) && isDefinedField(name)) {
          throw invalidSelection(token,
            "%j is not a field of a representation this server returns", name);
        }
      }
    }
    // A field is named once, except that a metadata prefix and a value
    // range may each be given several times: "?metadata=a&metadata=b" and
    // "?value=0-1&value=5-6" are selections of several parts. Naming a
    // field bare and again with a value, or bare twice, is a selection of
    // the same field twice (weedmi OPER-006).
    // A field is named once. A metadata prefix and a value range may each
    // be given several times, being selections of several parts, but a
    // field named bare and again with a value selects the same field twice
    // (weedmi OPER-006).
    const bare = sel.fields.includes(name) && !sel.valued.has(name);
    if (sel.fields.includes(name) && (rawValue === undefined || bare)) {
      throw invalidSelection(name, "the selection names %j more than once", name);
    }
    if (rawValue !== undefined) sel.valued.add(name);
    if (!sel.fields.includes(name)) sel.fields.push(name);
  }
  // "It shall not be named with another field, which it already selects": a
  // range selection is not a field, and governs what it returns.
  if (sel.everyField === true) {
    const named = sel.fields.filter((f) => f !== "value" && f !== "children");
    if (named.length > 0 || sel.metaSelected || (sel.value && sel.valueRanges.length === 0)) {
      throw invalidSelection("*", "a selection of every field is not named with another field");
    }
  }
  // "This selection shall not be combined with a value range selection, and the
  // CDMI server shall report the invalid selection condition where it is."
  if (sel.layoutOffset !== undefined && sel.valueRanges.length > 0) {
    throw invalidSelection("valuerange", "a value layout selection is not combined with a value range selection");
  }

  // Several ranges of a value are transported as parts of a multipart body
  // (8.2.6), and they describe distinct parts: ranges that overlap would
  // return the same octets twice and are refused.
  const ordered = [...sel.valueRanges].sort((a, b) => a[0] - b[0]);
  for (let i = 1; i < ordered.length; i++) {
    if (ordered[i][0] <= ordered[i - 1][1]) {
      throw invalidSelection("value",
        "the value ranges %d-%d and %d-%d overlap",
        ordered[i - 1][0], ordered[i - 1][1], ordered[i][0], ordered[i][1]);
    }
  }
  // An extended child listing and a recursive child listing are served in one
  // operation, which is a deliberate divergence from Clause 6 of revision 365
  // and is ECR-235B. Clause 6 prohibits the combination — "a CDMI client shall
  // not request extended child listing and recursive child listing in one
  // operation, and a CDMI server shall report the conflicting fields condition
  // ... where a CDMI client does" — on the ground that "the array reporting the
  // fields of a child and the array reporting the children of a descendant
  // container object could not be told apart". Clause 7 defines what the
  // combination returns, in three sentences, and says the two "are distinguished
  // by position". Both are normative and no server can meet both, and this
  // server refused the combination until 0.116 because Clause 6 was the clause
  // implemented first.
  //
  // Clause 7 is followed because Clause 6's objection is true of Clause 6's own
  // placement of the recursion and false of Clause 7's: Clause 6 puts the array
  // of a container object's children "immediately after" that child, a sibling
  // within the children field, where Clause 7 makes it "a further member" of the
  // child's own array. Under the sibling placement a listing that names one
  // array-valued field is genuinely ambiguous — with "children" named, a field
  // array and a recursive array have the same shape at every level — and the
  // children field holds more members than there are children, so childrenrange
  // does not index it. Under the nesting neither holds. See recursiveChildren
  // and nestChildren below.
  return sel;
}

/**
 * Places the children of a child container object in a child listing, and
 * answers whether it placed them: where it did not, the caller returns them
 * after the child, which is the sibling placement of a recursive listing that
 * names no fields.
 *
 * Where fields are named, the child is an array of their values and the
 * children go inside it, "as a further member of that array, so that the two
 * kinds of array are distinguished by position" — the member after the last
 * field named, a position the CDMI client knows from its own request.
 *
 * Where the fields named include "children", they go in that field instead of
 * after it: "where the extended child listing names the children field, the
 * children of a child are returned once, as the value of that field". The
 * children of a child container object are then reported in the field named
 * for them, in the same form, and are not reported twice. Reading that sentence
 * the other way — the field carrying the names and the recursion following it —
 * reports every descendant of a child twice over, once by name in the field of
 * its parent and once as a member of the recursive array, which is what
 * "returned once" appears to be there to prevent. ECR-235B records that the
 * sentence admits both readings.
 */
function nestChildren(row: unknown, under: unknown[], sel: Selection): boolean {
  if (!Array.isArray(row)) return false;
  const at = sel.childFields.indexOf("children");
  if (at >= 0) row[at] = under;
  else row.push(under);
  return true;
}

/** Applies a selection to a complete representation. */
/**
 * The fields of a representation in the order it is sent: "where the
 * childrenrange and children fields are present, they shall be the last two
 * fields of the representation and shall appear in that order", and the same
 * of valuerange and value. Everything else keeps the order it was built in
 * (weedmi REPR-004).
 */
function inFieldOrder(rep: Record<string, unknown>): Record<string, unknown> {
  const sorted = withSortedMetadata(rep);
  const last = ["childrenrange", "children", "valuerange", "value"];
  if (!last.some((f) => f in sorted)) return sorted;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(sorted)) if (!last.includes(k)) out[k] = v;
  for (const f of last) if (f in sorted) out[f] = sorted[f];

  return out;
}

/**
 * The metadata field of a representation, with its items in order of name.
 *
 * The items of a representation are a JSON object, so their order carries no
 * meaning and a CDMI client that needs one sorts them itself — but a CDMI client
 * is usually a person reading a response, and the order the items were built in
 * is the order this server happened to compute them: the storage system items,
 * then what was provided, then the user metadata, which was the only group that
 * was sorted. An object with thirty items was thirty lines a reader had to search
 * rather than scan, and two reads of two objects put their common items in
 * different places where one had an item the other did not.
 *
 * Sorted by code unit, so "cdmi_RPO" precedes "cdmi_acl": the order is the one
 * JSON.stringify would give a sorted key list, which is what another tool
 * comparing two responses will have done to them.
 *
 * The members of the cdmi_representations item hold metadata items of their own,
 * and are sorted for the same reason.
 */
function withSortedMetadata(rep: Record<string, unknown>): Record<string, unknown> {
  const md = rep.metadata;
  if (md === null || typeof md !== "object" || Array.isArray(md)) return rep;
  const sortItems = (o: Record<string, unknown>): Record<string, unknown> => {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(o).sort()) out[k] = o[k];
    return out;
  };
  const items = sortItems(md as Record<string, unknown>);
  const reps = items.cdmi_representations;
  if (reps !== null && typeof reps === "object" && !Array.isArray(reps)) {
    const members: Record<string, unknown> = {};
    for (const [name, member] of Object.entries(reps as Record<string, unknown>)) {
      members[name] = member !== null && typeof member === "object" && !Array.isArray(member)
        ? sortItems(member as Record<string, unknown>)
        : member;
    }
    items.cdmi_representations = members;
  }
  return { ...rep, metadata: items };
}

function applySelection(rep: Record<string, unknown>, sel: Selection): Record<string, unknown> {
  if (!sel.any) return rep;
  // "A field selection of \"*\" selects every field of the representation, the
  // value field included" (revision 297): the representation is complete, and
  // a range selection beside it has already governed what the field holds.
  if (sel.everyField === true) return rep;
  // "a field name in a field selection ... that is not defined for that object
  // type ... and is not an extension field stored with that object" is an
  // invalid selection (Operations overview).
  for (const name of sel.fields) {
    if (name === "childfields" || name === "childrecursive") continue;
    if (!SELECTABLE.has(name) && !isDefinedField(name) && !(name in rep)) {
      throw invalidSelection(name, "%j is neither a field this object type defines nor an extension field stored " +
        "with this object", name);
    }
  }
  const out: Record<string, unknown> = {};
  const pick = (name: string) => {
    if (name in rep) out[name] = rep[name];
  };
  for (const name of sel.fields) {
    if (name === "childfields" || name === "childrecursive") {
      pick("childrenrange");
      pick("children");
      continue;
    }
    // Each field is returned where it is named and not otherwise: a
    // selection of the value alone does not carry its range with it
    // (weedmi OPER-030). A range of the value is different: the range
    // returned is part of the answer, since it may be less than the range
    // asked for.
    // A partial answer carries its range: a range the client asked for, or a
    // value cut short by a gap. A whole value is returned alone
    // (weedmi OPER-030).
    if (name === "value" && (sel.valueRanges.length > 0 || sel.partialValue === true)) {
      pick("valuerange");
    }
    // "Where a CDMI server returns the value field, it shall return the
    // valuetransferencoding field with it ... whether or not the field
    // selection names them. A CDMI client that selects a field this rule adds
    // receives it once. A response is thereby interpretable from itself"
    // (revision 365, closing ECR-159A). Before 0.85 a CDMI client reading
    // ?value=0-3 received base 64 and nothing saying so.
    if (name === "value") pick("valuetransferencoding");
    // The same of the children: a range of them is a partial answer, and
    // the range returned may be shorter than the range asked for where it
    // extends beyond the last child (weedmi OPER-038, OPER-041).
    if (name === "children" && sel.childRange !== undefined) pick("childrenrange");
    pick(name);
  }
  return out;
}

/**
 * The kinds of object whose representation an Accept field admits, or
 * undefined where it admits every type (absent, empty, or a wildcard). A type
 * given a q of 0 is excluded, as RFC 9110 12.5.1 provides.
 */
/**
 * The kinds of object an Accept field admits, best first: "Where the Accept
 * header field names more than one media type, the CDMI server shall evaluate
 * them in order of quality value and, among equal quality values, in the order
 * listed, as RFC 9110 provides, and shall return the first representation the
 * name addressed has" (revision 297). A wildcard admits every kind, and takes
 * the quality value it was given.
 */
function kindsRanked(accept: string | undefined): { kind: "queue" | "data" | "container" | "any"; q: number }[] {
  if (!accept || accept.trim() === "") return [{ kind: "any", q: 1 }];
  const out: { kind: "queue" | "data" | "container" | "any"; q: number; at: number }[] = [];
  for (const [at, part] of accept.split(",").entries()) {
    const [type, ...params] = part.split(";").map((x) => x.trim().toLowerCase());
    const given = params.find((x) => x.startsWith("q="));
    const q = given === undefined ? 1 : Number(given.slice(2));
    if (!(q > 0)) continue;
    const base = type.replace(/\+json$/, "");
    const kind = type === "*/*" || type === "application/*"
      ? "any" as const
      : base === MT_QUEUE ? "queue" as const : base === MT_OBJECT ? "data" as const
        : base === MT_CONTAINER ? "container" as const : undefined;
    if (kind !== undefined) out.push({ kind, q, at });
  }
  // By quality value, and among equal values by the order listed.
  out.sort((a, b) => (b.q - a.q) || (a.at - b.at));
  return out.map(({ kind, q }) => ({ kind, q }));
}

function kindsAccepted(accept: string | undefined): Set<"queue" | "data" | "container"> | undefined {
  if (!accept || accept.trim() === "") return undefined;
  const out = new Set<"queue" | "data" | "container">();
  for (const part of accept.split(",")) {
    const [type, ...params] = part.split(";").map((x) => x.trim().toLowerCase());
    const q = params.find((x) => x.startsWith("q="));
    if (q !== undefined && Number(q.slice(2)) === 0) continue;
    if (type === "*/*" || type === "application/*") return undefined;
    const base = type.replace(/\+json$/, "");
    if (base === MT_QUEUE) out.add("queue");
    else if (base === MT_OBJECT) out.add("data");
    else if (base === MT_CONTAINER) out.add("container");
  }
  return out;
}

function acceptable(accept: string | undefined, mt: string): boolean {
  if (!accept || accept.trim() === "") return true;
  for (const part of accept.split(",")) {
    const t = part.split(";")[0].trim().toLowerCase();
    if (t === "*/*" || t === "application/*" || t === mt || t === `${mt}+json`) return true;
  }
  return false;
}

/**
 * The 406 a request earns where its Accept header field names no media type
 * this server can return for the object addressed.
 *
 * The field received is named in the detail, and the media type that would have
 * been returned. The message said only the latter until 0.118 — "no
 * representation of media type application/cdmi-container is acceptable" —
 * which reads as though the server could not produce that representation, and
 * sent at least one deployment looking at the object rather than at the Accept
 * header field of its own request.
 */
function notAcceptableFor(accept: string | undefined, served: string, ns: string): Condition {
  return notAcceptable(
    "the Accept header field %j names no media type this server can return for %s, " +
    "which is returned as %s",
    accept ?? "", ns, served);
}

function mediaTypeOf(header: string | undefined): string {
  return (header ?? "").split(";")[0].trim().toLowerCase();
}

function guessMimetype(name: string, vte: string): string {
  const ext = name.slice(name.lastIndexOf(".") + 1).toLowerCase();
  const known: Record<string, string> = {
    txt: "text/plain", html: "text/html", htm: "text/html", css: "text/css",
    js: "text/javascript", json: "application/json", pdf: "application/pdf",
    png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif",
    svg: "image/svg+xml", md: "text/markdown", img: "application/octet-stream",
  };
  return known[ext] ?? (vte === "utf-8" ? "text/plain" : "application/octet-stream");
}

function etagOf(m: ObjectView): string {
  const h = createHash("sha256");
  h.update(`${m.version}\u0000${m.size}\u0000${m.mimetype ?? ""}`);
  return `"${h.digest("hex").slice(0, 24)}"`;
}

function matchesETag(list: string, tag: string): boolean {
  return list.split(",").some((p) => p.trim().replace(/^W\//, "") === tag);
}

// ---------------------------------------------------------------------------
// Representations

/** The user metadata items a prefix set selects, with the derived items. */
/**
 * The metadata field of an object. The kind of an item decides which
 * mask bits govern it, and not the field it is carried in: a user
 * metadata item is governed by READ_METADATA and WRITE_METADATA, and a
 * storage system or data system metadata item by READ_ATTRIBUTES and
 * WRITE_ATTRIBUTES. An item the principal may not read is excluded.
 */
/**
 * Whether the "cdmi_representations" capability and item are offered.
 *
 * The item reports the representations a CDMI server holds of the *value* of a
 * data object, one member per media type — which is a different feature from a
 * name denoting more than one representation of an object, the duality of
 * ref_cdmi_duality, and is not affected by this. This server holds one
 * representation of a value, so the item it reported always had exactly one
 * member and told a CDMI client nothing it could not read from "mimetype".
 *
 * It is withheld for now, by decision rather than by omission: the capability is
 * not published, the item is not reported, and an item a CDMI client supplies is
 * ignored as any other storage system metadata item supplied by a client is.
 * The code that produces it is kept and gated, so that turning it back on is one
 * setting rather than a reconstruction.
 */

/** Whether a metadata selection, which selects by prefix, asks for an item. */
const selects = (prefixes: string[], item: string): boolean =>
  prefixes.length === 0 || prefixes.some((p) => item.startsWith(p));

/**
 * The metadata of a domain object as a read reports it, with a metadata prefix
 * selection applied.
 *
 * A domain object built its metadata field itself and never applied the
 * prefixes, which metadataRep applies for every other object type: until 0.106
 * a client asking for "?metadata=cdmi_owner" on a domain object was given every
 * item it held.
 */
function domainMetadataRep(items: Record<string, unknown>, prefixes: string[]): Record<string, unknown> {
  if (prefixes.length === 0) return items;
  return Object.fromEntries(Object.entries(items).filter(([k]) => prefixes.some((p) => k.startsWith(p))));
}

function metadataRep(m: ObjectView, isData: boolean, prefixes: string[],
  mayReadACL = true, mayReadAttributes = true, mayReadUser = true, mayAdministerKms = false,
  lockProvided?: string, sanitizeProvided?: string,
  inherited?: Record<string, unknown>):
  Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const add = (k: string, v: unknown) => {
    // Every item this function adds other than the user metadata is a
    // storage system or data system metadata item.
    if (!mayReadAttributes && k !== "cdmi_acl") return;
    if (prefixes.length === 0 || prefixes.some((p) => k.startsWith(p))) out[k] = v;
  };
  // An item the holder does not provide is absent rather than empty: for
  // an object presented through an image import, that is most of them.
  if (isData) add("cdmi_size", String(m.size));
  // The hash of the value, where the client asked for one. The item is
  // present where cdmi_value_hash names an algorithm, and holds the
  // hash in the base 16 encoding of RFC 4648.
  if (isData && typeof m.hash === "string" && m.hash !== "") {
    add("cdmi_hash", m.hash);
    // "Contains the algorithm and length being used to hash the object value":
    // the provided item that reports what the CDMI server did with the
    // cdmi_value_hash request, in the designator that item uses. It is reported
    // where a hash is in force and not otherwise, since a CDMI server that hashes
    // nothing has no algorithm to name, and a provided item is not reported
    // "where it cannot [determine what it achieves]". The effective item is the
    // object's own or the one inherited from the container objects above it, the
    // hash being computed from whichever applies.
    const asked = m.userMetadata?.cdmi_value_hash ?? inherited?.cdmi_value_hash;
    const named = typeof asked === "string"
      ? Object.keys(VALUE_HASHES).find((k) => k === asked.toUpperCase())
      : undefined;
    if (named !== undefined) add("cdmi_value_hash_provided", named);
  }
  if (m.ctime !== undefined) add("cdmi_ctime", cdmiTime(m.ctime));
  if (m.mtime !== undefined) add("cdmi_mtime", cdmiTime(m.mtime));
  if (m.atime !== undefined) add("cdmi_atime", cdmiTime(m.atime));
  if (m.owner !== undefined && m.owner !== "") add("cdmi_owner", m.owner);
  // What this CDMI server achieves for the service-level items of Annex D, for
  // each item the object asks for or inherits a request for. The request is what
  // a CDMI client wants; these are what it gets (service-level.ts).
  for (const [k, v] of Object.entries(serviceLevelProvided(
    { ...(inherited ?? {}), ...(m.userMetadata ?? {}) }))) {
    add(k, v);
  }
  // What the CDMI server applied for retention and hold.
  for (const [k, v] of Object.entries(providedItems(m.userMetadata ?? {}))) {
    add(k, v);
  }
  if (m.group !== undefined && m.group !== "") add("cdmi_group", m.group);
  // The counters are decimal strings, as every storage system metadata
  // item that holds a number is.
  if (m.acount !== undefined) add("cdmi_acount", String(m.acount));
  // "[a CDMI server] reports the lock it applies in the cdmi_lock_provided
  // data system metadata item of each object the lock covers" (revision
  // 327): the lock of the object itself, or of the nearest container above
  // it that holds one.
  if (lockProvided !== undefined) add("cdmi_lock_provided", lockProvided);
  // "Contains the sanitization method used": the method that applies to this
  // object, which is the item it carries or the one the nearest container
  // object above it carries, data system metadata being inherited.
  if (sanitizeProvided !== undefined) {
    add("cdmi_sanitization_method_provided", sanitizeProvided);
  }

  if (m.mcount !== undefined) add("cdmi_mcount", String(m.mcount));
  if (m.acl !== undefined && m.acl !== null && mayReadACL) add("cdmi_acl", m.acl);
  if (mayReadUser) {
    // "The metadata field of an object contains ... the data system metadata
    // items inherited from the parent container object ... the metadata
    // items stored with the object, which override an inherited item of the
    // same name" (11.1.2). An inherited item is emitted first and the stored
    // items overwrite it, which is that precedence. This server reported the
    // stored items alone, so an item set on a container object applied to
    // nothing it held and was reported by nothing it held (weedmi META-012).
    for (const [k, v] of Object.entries(inherited ?? {})) {
      if (prefixes.length === 0 || prefixes.some((p) => k.startsWith(p))) out[k] = v;
    }
    for (const k of Object.keys(m.userMetadata).sort()) {
      // The instant a retention period was applied is held with the
      // metadata and is not an item this document defines: what a
      // client reads is cdmi_retention_period_provided, formed from it.
      if (k === APPLIED_AT) continue;
      // The two items that request delegated access control are kept with the
      // metadata of the object and are governed as cdmi_acl is, "for reading
      // it as for changing it" (Annex D, revision 221).
      if (DAC_ITEMS.includes(k) && !mayReadACL) continue;
      const v = k === "cdmi_domain_kms" ? reportedKms(m.userMetadata[k], mayAdministerKms) : m.userMetadata[k];
      if (prefixes.length === 0 || prefixes.some((p) => k.startsWith(p))) out[k] = v;
    }
  }
  // The cdmi_representations item is not built here. It reports the length of
  // every representation of the value, and a length is only known by encoding
  // one, so it needs the octets — which this function does not have and, at the
  // call sites that report a child of a listing, should not read: deriving a
  // representation for every child of a container object would transcode the
  // whole container to answer one listing. The item is reported where a single
  // object's metadata is read, by defaultRepresentation, which has the value.
  return out;
}

/** The kind of object a CDMI media type creates or updates, where it is one of the three that carry extension fields. */
function kindOf(ct: string): ObjectKind | undefined {
  if (ct === MT_OBJECT || ct === `${MT_OBJECT}+json`) return "data";
  if (ct === MT_CONTAINER || ct === `${MT_CONTAINER}+json`) return "container";
  if (ct === MT_QUEUE || ct === `${MT_QUEUE}+json`) return "queue";
  return undefined;
}

/**
 * A domain's cdmi_domain_kms item as a read reports it: "Where this field
 * [client_registration] is absent or contains false, a CDMI client places a
 * credential under management by supplying it to the CDMI server, and the
 * endpoint, version and scope fields of this key management server are not
 * reported." A CDMI client is not told where a key management server is that
 * it may not reach. They were reported before 0.48.
 */
function withReportedKms(settings: Record<string, unknown>, mayAdministerKms = false): Record<string, unknown> {
  return "cdmi_domain_kms" in settings
    ? { ...settings, cdmi_domain_kms: reportedKms(settings.cdmi_domain_kms, mayAdministerKms) }
    : settings;
}

/**
 * The cdmi_domain_kms item as a principal reads it: the endpoint, version and
 * scope are withheld where the key management server offers no client
 * registration, except that "The fields are reported to a principal holding
 * the domain_kms_admin privilege" (revision 297; ECR-104B), which is the
 * principal that configured them. Before 0.63 they were withheld from every
 * principal, so an administrator could not read back what it had set.
 */
function reportedKms(item: unknown, mayAdminister = false): unknown {
  if (item === null || typeof item !== "object" || Array.isArray(item)) return item;
  const out: Record<string, unknown> = {};
  for (const [label, d] of Object.entries(item as Record<string, unknown>)) {
    if (d === null || typeof d !== "object" || Array.isArray(d)) {
      out[label] = d;
      continue;
    }
    const descriptor = { ...(d as Record<string, unknown>) };
    if (descriptor.client_registration !== "true" && !mayAdminister) {
      delete descriptor.endpoint;
      delete descriptor.version;
      delete descriptor.scope;
    }
    out[label] = descriptor;
  }
  return out;
}

/** The container object whose list governs an object of a view. */
function governedBy(v: View): Node | undefined {
  return nodeOf(v.held) ?? v.importGovernor;
}

/** The imports field with its CDMI server populated fields (9.2). */
function importsRep(v: View): unknown[] {
  const now = cdmiTime();
  return v.entries.map((st) => {
    const e: Record<string, unknown> = { ...st.entry };
    // The identity mode that applies is reported whether or not a client
    // supplied it; a CDMI import is of the namespace category.
    if (st.entry.type === "CDMI" && e.identity_mode === undefined) {
      e.identity_mode = "delegated";
    }
    if (st.sourceObjectID !== undefined) e.source_objectid = st.sourceObjectID;
    e.active = st.active ? "true" : "false";
    e.last_problems = st.problems;
    e.state_determined_time = now;
    return e;
  });
}

export class Binding {
  readonly store: Store;
  readonly base: string;
  /** The HTTP exports of the root container object, where any are served. */
  exports?: Exports;
  /** The principals this server accepts. Empty means anonymous alone. */
  readonly directory = new Directory();

  /**
   * The resource server of the CDMI over MCP protocol binding, where that
   * binding is served. It resolves an access token at the domain that owns
   * the object a call addresses, and says which scope a call requires.
   */
  mcpAuth: McpResourceServer | undefined;

  /**
   * The principal of a request this server composed for itself, which the
   * CDMI over MCP binding resolved before dispatching the operation. Held
   * per request and never for a request that arrived over a socket.
   */
  private readonly resolvedPrincipal = new WeakMap<IncomingMessage, Principal>();

  /**
   * The field passed through to a delegated access control provider that says
   * where the operation came from, so that the provider's log and this
   * server's log can be read as records of one operation.
   *
   * It is a `CDMI-DAC-` field, which is what the subclause reserves for a
   * field carried to a provider, so it needs no provision of its own and a
   * provider that does not recognize it ignores it as it ignores any other. It
   * holds no credential and no path: the binding, the tool where there is one,
   * the trace identifier where the call carried one, and the program that made
   * the call where it named itself.
   */
  private dacOperationMeta(req: IncomingMessage): Record<string, string> {
    const tool = this.mcpTool.get(req);
    if (tool === undefined) return { "cdmi-dac-operation": "binding=http" };
    const trace = this.mcpTrace.get(req);
    const parts = ["binding=mcp", `tool=${tool}`];
    if (trace !== undefined) parts.push(`traceparent=${trace.traceparent}`);
    if (trace?.client !== undefined) parts.push(`client=${trace.client}`);
    return { "cdmi-dac-operation": parts.join(" ") };
  }

  /** The tool a call of the CDMI over MCP binding named, for the record above. */
  private readonly mcpTool = new WeakMap<IncomingMessage, string>();

  /**
   * The trace identifier of an operation of the CDMI over MCP binding,
   * and the program that called it, recorded with the operation.
   */
  private readonly mcpTrace =
    new WeakMap<IncomingMessage, { traceparent: string; client?: string }>();

  /**
   * The address the CDMI over MCP endpoint is served at, which the
   * cdmi_mcp_uri capability reports. Undefined where that binding is not
   * served, and the capability is then not published.
   */
  mcpUri: string | undefined;

  /**
   * "A CDMI server shall apply a default bound, through this protocol
   * binding, to the number of children a read of a container object
   * returns" — a client of this binding acts on text it has read, and an
   * unbounded listing is the easiest way to fill its context with one
   * call. A client that wants more asks for a range.
   */
  static readonly MCP_CHILDREN_BOUND = 100;

  /** Where a request and a condition are written, where they are. */
  log: Log = SILENT;

  /**
   * Delegated access control, where this server is configured for it. Where it
   * is undefined the cdmi_dac capability is not published and the metadata
   * items of an object are stored and not acted upon, as the subclause
   * provides for a CDMI server that does not support delegation.
   */
  private readonly dac: DacClient | undefined;

  /**
   * The decision obtained for the object of the request in progress, by the
   * identifier of its node. The evaluation of an access control list is
   * synchronous and a decision is an exchange with another party, so the
   * decision is obtained once, before the operation is performed, and the
   * evaluation consults it.
   */
  private readonly perRequest = new AsyncLocalStorage<{ masks: Map<number, number> }>();

  /**
   * The key management servers configured, by the label a domain's
   * cdmi_domain_kms item names. A scope a domain declares is claimed at the
   * server it names (kms-binding.ts).
   */
  keyManagement: KeyManagement[] = [];
  /** [homes]: where the homes of a domain's principals are held (userinfo.ts). */
  homes?: HomesConfig;
  /** [home_server]: the homes this server holds (userinfo.ts). */
  homeServer?: HomeServerConfig;
  /** The pipes, where [pipes] is configured (pipe.ts, RELAY-draft-2.md). */
  pipes?: PipeService;
  /** The domain controllers principals are resolved at, by domain (domain-controller.ts). */
  domainControllers?: DomainControllers;
  /** Those built from the cdmi_domain_auth item of a domain, by domain and descriptor. */
  private readonly directories = new Map<string, DomainController>();

  constructor(store: Store, base = "/cdmi/3.0.0/", log: Log = SILENT, dac?: DacClient) {
    this.store = store;
    this.base = base.endsWith("/") ? base : base + "/";
    this.log = log;
    this.dac = dac;
    // The store overwrites the value file of an object that asked for a
    // sanitization method before it unlinks it, and reads the method that
    // applies through this: the store does not interpret metadata, and the
    // item is inherited from the container objects above the object.
    store.sanitizeMethod = (n) => this.effectiveDataSystemItem(n, "cdmi_sanitization_method");
    // The value hash asked for by the nearest container object above an
    // object, where the object itself asks for none.
    store.effectiveHashItem = (n) => this.effectiveDataSystemItem(n, "cdmi_value_hash");
    // Whether the object asks that its value be on persistent storage before the
    // operation completes, from the item that applies to it after inheritance:
    // a CDMI client sets it on a container object and every object within it is
    // written that way.
    store.immediateRedundancy = (n) =>
      this.effectiveDataSystemItem(n, IMMEDIATE_REDUNDANCY) === "true";
    // A query in progress lives in the memory of the process performing it, and
    // its status is in the store. A process that stopped between the two left a
    // query queue reporting Processing with nothing performing it, and a CDMI
    // client "determines that a query has completed by reading this item, and
    // not by the absence of further results" — so it waited for ever. Each such
    // query is failed here, once, before any query of this process begins.
    failInterruptedQueries(store);
  }

  // -----------------------------------------------------------------
  // Dispatch

  /**
   * The discovery tree at the well-known path prefix, where this server
   * is configured to serve one. It is a property of the origin and not
   * of a base URI, so it is answered before the base URI is considered.
   */
  discovery?: Discovery;

  async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const began = Date.now();
    // What the log records of this request is held per request: the
    // binding serves requests concurrently, and state held on the
    // binding itself was overwritten by whichever request resolved a
    // principal last, so a line could name another request's principal.
    this.requestLog.set(req, { byExport: false });
    try {
      await this.perRequest.run({ masks: new Map() }, () => withDelegation(() => this.route(req, res)));
      this.logRequest(req, res, began);
    } catch (err) {
      if (isCondition(err)) return this.fail(res, err, req, began);
      if (err instanceof StoreError) {
        return this.fail(res, err.code === "no-object"
          ? notFound(req.url ?? "")
          : conflict("%s", err.message), req, began);
      }
      // An error this server did not anticipate is a fault of this server:
      // its text, which may name internal code or state, is written for the
      // operator and not given to the CDMI client. It was given before 0.46.
      process.stderr.write(`seedmi: an unexpected error answering ${req.method} ${req.url}: ` +
        `${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
      this.fail(res, serverError("this CDMI server met an error it did not anticipate; " +
        "the operator's log records it"), req, began);
    }
  }

  /**
   * For each request in progress: the principal it resolved to, for
   * the log, and whether an export served it. An export writes its own
   * line, and a request is one line whichever surface answered it.
   */
  private readonly requestLog =
    new WeakMap<IncomingMessage, { principal?: string; byExport: boolean }>();

  private noted(req: IncomingMessage):
    { principal?: string; byExport: boolean; idBase?: string; exportBase?: string } {
    let n = this.requestLog.get(req);
    if (n === undefined) {
      n = { byExport: false };
      this.requestLog.set(req, n);
    }
    return n;
  }

  /** Writes a request that was served, where the log wants one. */
  private logRequest(req: IncomingMessage, res: ServerResponse, began: number): void {
    if (!this.log.enabled || this.noted(req).byExport) return;
    const status = res.statusCode;
    this.log.write({
      // The surface an operation arrived on: a call of the CDMI over MCP
      // binding is recorded as such, with the trace identifier the call
      // carried and the program that made it, so that this record and an
      // intermediary's are recognizable as being of one operation.
      surface: this.mcpTrace.get(req) === undefined ? "http" : "mcp",
      ...(this.mcpTrace.get(req) === undefined ? {} : {
        traceparent: this.mcpTrace.get(req)!.traceparent,
        ...(this.mcpTrace.get(req)!.client === undefined
          ? {}
          : { client: this.mcpTrace.get(req)!.client }),
      }),
      outcome: String(status),
      failed: status >= 400,
      operation: req.method ?? "GET",
      instance: pathOnly(req.url ?? "/"),
      principal: this.noted(req).principal ?? ANONYMOUS.name,
      ms: Date.now() - began,
    });
  }

  private fail(res: ServerResponse, c: Condition, req?: IncomingMessage,
    began?: number): void {
    if (req?.url !== undefined) c.at(req.url);
    if (this.log.enabled) {
      this.log.write({
        surface: "http",
        outcome: String(c.status),
        failed: true,
        operation: req?.method ?? "",
        instance: pathOnly(req?.url ?? ""),
        principal: (req === undefined ? undefined : this.noted(req).principal) ??
          ANONYMOUS.name,
        ms: began === undefined ? 0 : Date.now() - began,
        type: c.type,
        detail: c.detail,
        members: c.members,
      });
    }
    const body = Buffer.from(JSON.stringify(c.toProblem(), null, 2) + "\n");
    res.writeHead(c.status, {
      ...c.headers,
      "Content-Type": "application/problem+json",
      "Content-Length": String(body.length),
    });
    res.end(body);
  }

  private send(res: ServerResponse, status: number, mt: string,
    rep: unknown, headers: Record<string, string> = {}, head = false): void {
    // The two pairs the draft orders come last, whatever order the
    // representation was built in (weedmi REPR-004).
    const ordered = rep !== null && typeof rep === "object" && !Array.isArray(rep) && !Buffer.isBuffer(rep)
      ? inFieldOrder(rep as Record<string, unknown>)
      : rep;
    // A value stored as the octets a CDMI client sent is returned as those
    // octets: the serializer puts a token where it stands, and the token is
    // replaced by the octets. The indentation around them is the document's
    // and the octets between are the CDMI client's, unchanged.
    const verbatim = ordered !== null && typeof ordered === "object" && !Buffer.isBuffer(ordered)
      ? (ordered as Record<string, unknown>).value
      : undefined;
    let text = JSON.stringify(ordered, null, 2);
    if (verbatim instanceof Verbatim) {
      text = text.replace(JSON.stringify(verbatim.token), verbatim.bytes.toString("utf8"));
    }
    const body = Buffer.from(text + "\n");
    res.writeHead(status, {
      "Content-Type": mt,
      "Content-Length": String(body.length),
      // A representation holds the fields the requesting principal is
      // permitted to read, and an entity tag identifies the state of the
      // object rather than the permissions of the principal, so a shared
      // cache must not store it and every cache must vary on the header
      // field the identity depends on.
      "Cache-Control": "private",
      Vary: varyWith(res, "Authorization"),
      ...headers,
    });
    res.end(head ? undefined : body);
  }

  private async route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = req.url ?? "/";
    const q = url.indexOf("?");
    const rawPath = q < 0 ? url : url.slice(0, q);
    const query = q < 0 ? "" : url.slice(q + 1);

    // A delegated access control response that arrives out of band, at the
    // URI the request stated. It addresses no object and carries no CDMI
    // representation, so it is answered before the namespace is considered.
    if (this.dac !== undefined && rawPath === `${this.base}${DAC_RESPONSE_PATH}`) {
      return this.dacResponse(req, res);
    }

    // The discovery tree is a property of the origin, so it is answered
    // before the base URI is considered, and in place of an export that
    // would otherwise cover the same path.
    if (this.discovery && Discovery.addresses(rawPath)) {
      if (this.discovery.serve(req, res, rawPath, query)) return;
    }

    // A CDMI export is served by this protocol binding at a base URI of
    // its own, so a request that addresses one is a request of the
    // binding and not of the export server (revision 327).
    const cdmiExport = this.exports?.cdmiBaseFor(req);
    if (!rawPath.startsWith(this.base) && cdmiExport === undefined) {
      if (this.exports && await this.exports.serve(req, res)) {
        this.noted(req).byExport = true;
        return;
      }
      // A path outside the base URI is not a path of the CDMI
      // namespace, and no export serves it. Reporting the not found
      // condition of an operation here would answer for an object
      // that was never addressed, and would tell a client that a CDMI
      // server is present at an origin it does not serve. The export
      // clause asks that such a request be indistinguishable from one
      // for an origin this server does not serve at all.
      const body = Buffer.from("no export serves this request\n");
      res.writeHead(404, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Length": String(body.length),
      });
      res.end(req.method === "HEAD" ? undefined : body);
      return;
    }
    // A request within the base URI is a request of the protocol binding.
    // The exception is an export whose path is the base URI, which serves
    // a request there that names no CDMI media type, as the previous
    // edition did. Where one is served, each response of the binding
    // reports the header fields the choice depended on.
    // The base URI the request is within: the one a CDMI export established
    // where it addresses one, and otherwise the configured base URI. Both are
    // "a base URI at which the CDMI server serves the protocol binding", and
    // the exemption is written of either. Only the configured one was asked
    // about before 0.98.
    if (this.exports?.baseExportServed(cdmiExport?.base)) {
      res.setHeader("Vary", "Accept, Content-Type");
      if (namesNoCDMIMediaType(req) && await this.exports.serve(req, res)) {
        this.noted(req).byExport = true;
        return;
      }
    }
    let ns = "/" + rawPath.slice(this.base.length);
    // A percent-encoded octet sequence that is not UTF-8 names nothing, and
    // decoding it throws: the malformed request condition says so, where
    // this server answered 500 before 0.79 (weedmi BHTP-013).
    ns = ns.split("/").map((seg, i) => {
      if (i === 0) return seg;
      try {
        return decodeURIComponent(seg);
      } catch {
        throw malformed(
          "the path of the request holds a percent-encoded sequence that is not UTF-8: %j", seg);
      }
    }).join("/");
    // "A CDMI export presents a container object ... at a base URI of an
    // origin the CDMI server serves. At that base URI the container object
    // is the root container object, and the objects it contains are
    // addressed by namespace paths beneath it" (revision 327). The
    // remainder of the path is resolved beneath the exported container,
    // and what is read there reports names relative to that base URI, as a
    // representation read beneath an object ID URI does.
    const exported = cdmiExport;
    if (exported !== undefined) {
      const beneath = rawPath.slice(exported.base.length);
      const decoded = beneath.split("/").map((seg) => decodeURIComponent(seg)).join("/");
      // A reserved child of the root container object is a property of this
      // CDMI server and not of the container object the export presents, so at
      // the base URI it addresses the one tree this server holds: the
      // capability hierarchy, the domain hierarchy, and the tree through which
      // an object is addressed by its object ID. Resolving it beneath the
      // exported container object instead would address an object of the
      // namespace named "cdmi_capabilities", which a CDMI client may not create
      // and this server does not hold.
      const reserved = RESERVED_CHILDREN.find((r) =>
        decoded === r || decoded === r.slice(0, -1) || decoded.startsWith(r));
      ns = reserved === undefined ? exported.ns + decoded : `/${decoded}`;
      this.noted(req).idBase = exported.ns;
      // And that this base URI is one a CDMI export established, which an
      // object ID URI is not: "every root container object is a container
      // object with a CDMI export, except the root container object of an
      // object ID URI". The reserved children of a root container object are
      // presented at the first and not at the second.
      this.noted(req).exportBase = exported.ns;
      // "Where this field contains "true", the CDMI server shall refuse
      // through this export every operation that creates, updates or
      // deletes an object" (revision 327).
      const asked = req.method ?? "GET";
      if (exported.readOnly && asked !== "GET" && asked !== "HEAD" && asked !== "OPTIONS") {
        throw forbidden("this CDMI export serves read-only access to %s", exported.base);
      }
    }

    const method = req.method ?? "GET";
    // A pipe deleted, or switched off by a change to its cdmi_queue_type,
    // closes the connections open through it (RELAY-draft-2.md section 3.1),
    // once the operation has been answered.
    if (this.pipes !== undefined && (method === "DELETE" || method === "PUT" || method === "PATCH")) {
      const before = this.nodeForDelegation(ns);
      if (before !== undefined && this.isPipe(before)) {
        res.on("finish", () => {
          const after = this.nodeForDelegation(ns);
          if (after === undefined || after.id !== before.id || !this.isPipe(after)) {
            this.pipes?.closePipe(before.id, 4403, "not-permitted");
          }
        });
      }
    }
    // A preflight request is answered from the metadata of the object
    // addressed, without authentication and without evaluating its
    // access control lists, because a browser presents no credentials
    // on one.
    // The methods this object admits: a capability object is read and not
    // written, and the discovery tree is read-only, so neither offers the
    // methods that change an object (weedmi BHTP-005).
    const readOnly = ns === "/cdmi_capabilities/" || ns.startsWith("/cdmi_capabilities/");
    const allowed = readOnly
      ? ["GET", "HEAD", "OPTIONS"]
      : ["GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"];
    if (isPreflight(req)) {
      return answerPreflight(this.store, req, res, ns, allowed);
    }
    if (method === "OPTIONS") {
      res.writeHead(204, { Allow: allowed.join(", ") });
      return res.end();
    }
    // A cross-origin request that is not a preflight request is
    // evaluated as any other, and the response carries in addition the
    // header fields that let a browser make it available.
    applyCors(this.store, req, res, ns);

    // The principal is noted for the log before anything can refuse the
    // request, so that a refusal names who made it. It is resolved as
    // the operation resolves it below, in the domain that owns the
    // object; the operation's own resolution is not moved, since that
    // would change which condition is reported first. Where the domain
    // cannot be determined, the line names the principal of the root.
    try {
      const d = this.domainOfRequest(req, ns);
      // A domain resolved at a domain controller is resolved by the operation
      // below, which notes the principal; the controller is not asked twice.
      if (this.domainControllers?.for(this.store.pathOf(d)) !== undefined) throw new Error("resolved below");
      this.noted(req).principal = this.directory.resolve(
        req.headers.authorization as string | undefined,
        this.store.pathOf(d), this.authenticationMethods(d)).name;
    } catch {
      try {
        this.noted(req).principal =
          this.directory.resolve(req.headers.authorization as string | undefined).name;
      } catch { /* the operation reports what is wrong with the credentials */ }
    }

    const sel = parseSelection(query);
    // The domain that owns the object the operation acts on determines
    // the authentication context: the credentials are resolved to a
    // principal within that domain, and the same credentials may
    // resolve to different principals, or to none, for two objects
    // owned by different domains.
    // An object whose retention period has passed, with no hold and
    // automatic deletion asked for, is deleted no later than the next
    // operation that addresses it.
    await this.autodelete(ns);
    const domain = this.domainOfRequest(req, ns);
    // An operation on an object owned by a domain that is not enabled
    // is refused, whatever the access control list of the object
    // permits. The domain hierarchy itself is exempt: a domain object
    // is owned by itself, so applying the rule to it would make a
    // domain that is disabled impossible to enable again. See the note
    // on this.
    if (!ns.startsWith(`/${DOMAINS}`) && !this.domainEnabled(domain)) {
      throw forbidden("%s is owned by a domain that is not enabled",
        ns === "" ? "/" : ns);
    }
    // Credentials presented and not accepted are refused, not taken as the
    // anonymous principal: a request so performed would act for, and create
    // objects owned by, a principal the client did not present.
    // Where a domain controller serves the domain, the credentials are
    // referred to it (domain-controller.ts), "an external identity service" as
    // the domains clause allows; otherwise they are resolved here. A domain
    // that names its directory in cdmi_domain_auth is resolved there
    // (controllerOfDomain), and this server's own configuration serves the rest.
    const controller = this.domainControllers?.for(this.store.pathOf(domain))
      ?? await this.controllerOfDomain(domain);
    // A request the CDMI over MCP binding composed carries a principal
    // already resolved: "the CDMI server shall be the MCP server. The two
    // are one server", and that endpoint resolved the subject of the
    // access token at the domain that owns the object before dispatching
    // the operation. Authenticating a second time would require the
    // credential to be acceptable to two configurations at once, and
    // would do the same work twice.
    const already = this.resolvedPrincipal.get(req);
    let who: Principal;
    if (already !== undefined) {
      who = already;
    } else if (controller !== undefined) {
      const accepted = await controller.accept(req.headers.authorization as string | undefined, this.authenticationMethods(domain));
      who = accepted.principal;
      // "WWW-Authenticate: Negotiate <base64>" where the client asked for
      // mutual authentication (RFC 4559), so that it knows it reached this server.
      if (accepted.negotiate !== undefined) res.setHeader("WWW-Authenticate", `Negotiate ${accepted.negotiate}`);
    } else {
      who = this.directory.authenticate(req.headers.authorization as string | undefined,
        this.store.pathOf(domain), this.authenticationMethods(domain));
    }
    this.noted(req).principal = who.name;
    // The home of a principal is made on its first authenticated request for
    // it, where this server holds the homes of that principal's domain.
    this.provisionHome(ns, who, controller);
    const r = new Resolver(this.store, { principal: who });

    // Where the object of the request has delegated access control, the
    // decision is obtained here, before the operation is performed, and the
    // evaluation of the access control list applies the mask it returns
    // (the access control flow, step 7).
    if (await this.delegate(req, res, ns, who, method, sel)) return;

    // An object that has an object ID is addressable by appending that
    // ID to the reserved name. The address and the namespace path of the
    // same object address the same object, and an operation has the same
    // effect through either, so the address is translated to the path
    // and everything that follows is unchanged.
    // A name this server assigned to an object created without one is
    // resolvable, so that the objects a nameless container object holds are
    // reached by a path beneath its object ID URI. It addresses nothing in
    // the namespace all the same: the object was created without a name, and
    // a client is not given one by the back door.
    if (isAssigned(ns.slice(1).split("/")[0] ?? "")) throw notFound(ns);

    if (ns === OBJECTID_TREE) {
      // A POST creates an object addressed by its object ID alone, and
      // a PUT that supplies the move field takes the path away from an
      // object that has one. Nothing else changes the tree itself.
      if (method === "GET" || method === "HEAD") {
        return this.sendObjectIdTree(res, sel, method === "HEAD");
      }
      if (method !== "POST" && method !== "PUT" && method !== "PATCH") {
        throw forbidden("%s is a reserved child of the root container object", ns);
      }
    }
    if (ns.startsWith(OBJECTID_TREE) && ns !== OBJECTID_TREE) {
      // A version has no namespace path: it is outside the namespace
      // and is addressed by its object ID alone, so it is served here
      // rather than by translating the address to a path.
      const version = this.versionAt(ns);
      if (version) return this.versionRequest(req, res, version, sel, who, method, ns);
      // A version a snapshot pinned outlives the data object it
      // belonged to: the snapshot holds the state, and the identifier
      // still addresses it.
      const pinnedPath = this.pathOfPinned(ns);
      if (pinnedPath !== undefined) {
        return this.snapshotRequest(req, res, r, pinnedPath, sel, who, method);
      }
      // An object this CDMI server assigned a name to has no path a
      // client may use, and is served here rather than by translating
      // the address to a path.
      const pathless = this.pathlessAt(ns);
      if (pathless) {
        return this.pathlessRequest(req, res, pathless, sel, who, method, ns);
      }
      // "A URI that addresses a container object by object ID shall end with
      // a /". Where it does not, the correction of a path's form applies to it
      // as to a namespace path: a GET, HEAD or DELETE is redirected to the form
      // with the solidus, the query preserved. It was refused with 409 before
      // 0.44, which is neither the redirection nor the object served.
      const corrected = this.objectIDContainerForm(ns);
      if (corrected !== undefined && (method === "GET" || method === "HEAD" || method === "DELETE")) {
        res.writeHead(307, { Location: withQuery(req, this.base.slice(0, -1) + corrected), "Content-Length": "0" });
        return res.end();
      }
      ns = this.pathOfObjectID(ns, (base) => { this.noted(req).idBase = base; });
    }

    // A path within a cdmi_snapshots container object addresses a
    // snapshot, or an object within one. Neither is presented by the
    // layering engine: a snapshot holds objects of this server alone,
    // and an imports field within one is not processed.
    if (ns.includes(`/${SNAPSHOTS}/`) || ns.endsWith(`/${SNAPSHOTS}`)) {
      // A create of the reserved name itself is refused as the name it is,
      // rather than reported as not found by the snapshot route
      // (weedmi REPR-015).
      if ((method === "PUT" || method === "POST") && ns.endsWith(`/${SNAPSHOTS}`)) {
        throw invalidField("objectName",
          "%j is a name this document reserves as a child of any container object",
          SNAPSHOTS);
      }
      return this.snapshotRequest(req, res, r, ns, sel, who, method);
    }

    // The domain hierarchy, at the reserved child of the root. A
    // domain object is not an object of the namespace the layers
    // present: it represents administrative ownership, and holds no
    // data.
    // No client creates or deletes one of the reserved names themselves: "A
    // CDMI server shall not permit a CDMI client to create or delete an object
    // with one of these names" (revision 365). A create beneath
    // /cdmi_domains/ names the domain, not a reserved name, and is
    // unaffected; a create of a reserved name was reported as not found
    // before 0.66 (weedmi REPR-015).
    // The name a client supplies is tested against the reserved names table
    // and not against the "cdmi_" prefix. Until 0.121 the prefix was tested,
    // which is what revision 365 requires of every name the table does not
    // list; NOTES-on-reserved-names.md records why this server no longer does
    // and ECR-247A asks the document to change.
    // An object that bears a reserved name exists and answers for itself: a
    // write to it is not permitted for its object type, which the capability
    // route below reports. This check is for names that would be created.
    // The domain tree is excluded from the check, a create beneath it naming a
    // domain rather than a reserved name, but the name "cdmi_domains" itself is
    // not: a create of it is the invalid field condition, and was reported as
    // not found until 0.121 because the exclusion covered the name as well as
    // the tree. That is the defect weedmi REPR-015 raised, fixed for the other
    // reserved names in 0.66 and left standing for this one.
    const reservedRoute = ns === "/cdmi_capabilities" || ns.startsWith("/cdmi_capabilities/") ||
      ns.startsWith(`/${DOMAINS}/`) || ns === "/cdmi_objectid/";
    if ((method === "PUT" || method === "POST") && !reservedRoute) {
      // The object ID tree is addressed by its own operations, which name no
      // object: a POST creates an object by identifier, and a PUT moves one
      // into the tree. Neither creates a name, so neither is refused here.
      const last = ns.replace(/\/$/, "").split("/").pop() ?? "";
      if (reservedName(last)) {
        throw invalidField("objectName",
          "%j is a name this document reserves", last);
      }
    }

    if (ns === `/${DOMAINS}` || ns.startsWith(`/${DOMAINS}/`)) {
      return this.domainRequest(req, res, ns, sel, who, method);
    }

    if (ns === "/cdmi_capabilities") {
      // A create of that name is a create of a reserved name; a read of it
      // without the solidus is corrected to the container form.
      if (method === "PUT" || method === "POST") {
        throw invalidField("objectName",
          "%j is a name this document reserves as a child of the root container object",
          "cdmi_capabilities");
      }
      return correctForm(req, res, this.base, ns);
    }
    if (ns.startsWith("/cdmi_capabilities/")) {
      if (method !== "GET" && method !== "HEAD") {
        throw notPermittedForObjectType(
          "a capability object is read, and is not created, changed or deleted", "GET, HEAD, OPTIONS");
      }
      return this.sendCapability(req, res, ns, sel);
    }

    // A request that addresses a reference, other than the create that
    // made it and a delete, reports the destination rather than
    // performing the operation. Revision 196 answers 307 rather than
    // 302: "The status code preserves the request method, so a request
    // that updates an object through a reference updates the
    // destination object rather than being reissued as a GET."
    if (method !== "DELETE") {
      const destination = await this.referenceAt(r, ns);
      if (destination !== undefined) {
        res.writeHead(307, { Location: throughReference(destination, req), "Content-Length": "0" });
        return res.end();
      }
    }

    // "Where an object is locked, a CDMI server shall refuse an operation
    // that the value of the item does not permit, whether the operation
    // reaches the object through a protocol binding, through an export or
    // through an import. It shall report the conflict condition to a CDMI
    // client of a protocol binding" (revision 327). Which condition is
    // ECR-166A: the same revision defines lock-conflict and lock-forbidden
    // that no subclause names, and this server reports what the subclause
    // says, in this one place.
    if (method === "PUT" || method === "PATCH" || method === "POST" || method === "DELETE") {
      this.refuseWhereLocked(ns, method === "DELETE" ? "delete" : "update");
    }
    // "An HTTP import is read only. A CDMI server shall refuse an operation
    // that writes the value of the importing object" (revision 327). The
    // value belongs to the origin server; this server presents it. Deleting
    // the object, which removes the import with it, is not such a write.
    if (method === "PUT" || method === "PATCH") {
      const at = this.nodeAt(ns);
      if (at !== undefined && !at.isContainer) {
        const entries = (this.store.meta(at).imports ?? []) as unknown as ImportEntry[];
        if (entries.some((e) => e.type === "HTTP")) {
          throw forbidden(
            "%s presents the value an HTTP import obtains, which this server does not write", ns);
        }
      }
    }
    // The value of the item is checked wherever it is supplied, including
    // on the update that releases a lock, which the refusal above lets
    // through.
    switch (method) {
      case "GET":
      case "HEAD":
        return this.read(req, res, r, ns, sel, who);
      case "PUT":
        return this.write(req, res, r, ns, sel, who, false);
      case "PATCH":
        return this.write(req, res, r, ns, sel, who, true);
      case "DELETE":
        return this.remove(req, res, r, ns, sel, who);
      case "POST":
        // A create with a name this CDMI server assigns.
        return this.post(req, res, r, ns, sel, who);
      default:
        res.writeHead(405, { Allow: "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS" });
        return res.end();
    }
  }

  /**
   * A create with a name this CDMI server assigns: a POST to a
   * container object creates a data object within it, and a POST to
   * the object ID tree creates one that has no name and no parent and
   * is addressed by its object ID alone.
   */
  private async post(req: IncomingMessage, res: ServerResponse, r: Resolver,
    ns: string, sel: Selection, who: Principal): Promise<void> {
    const byID = ns === OBJECTID_TREE;
    if (!byID && !ns.endsWith("/")) {
      // A POST also appends to a queue object, which is addressed by a
      // name that carries no trailing solidus.
      const { parentNS, name } = this.split(ns);
      const pv0 = await r.view(parentNS);
      if (pv0.unavail === undefined) {
        // The media type of the request names the representation it
        // acts upon: a name may denote a data object and a queue
        // object at once, and an append addresses the queue object.
        const found = await resolveFile(this.store, pv0, name);
        const first = found === undefined ? undefined : nodeOf(found.ref);
        const writeAt = nodeOf(pv0.held);
        const node = first !== undefined && this.store.meta(first).isQueue
          ? first
          : (writeAt === undefined
            ? undefined
            : this.store.lookupKind(writeAt, name, "queue"));
        if (node !== undefined) {
          return this.appendQueue(req, res, node, ns, who);
        }
      }
      throw new Condition(405, "", "Method Not Allowed",
        "a POST addresses a container object, a queue object, or the object ID tree");
    }
    const raw = await readBody(req);
    const ct = mediaTypeOf(req.headers["content-type"] as string);
    // A POST to the object ID tree creates an object of the type its
    // media type names, as a PUT to a name does.
    const wantsQueue = ct === MT_QUEUE || ct === `${MT_QUEUE}+json`;
    // "A container object is created without a name in either of two ways.
    // The create supplies a CDMI export, which makes the container object
    // the root container object of a base URI. Or the CDMI server publishes
    // the cdmi_object_access_by_ID capability, in which case the container
    // object is the root container object of its own object ID URI, that
    // URI being a base URI" (revision 354). This server publishes that
    // capability, so the second way is offered; it refused such a create
    // as an unsupported media type before 0.82.
    const wantsContainer = ct === MT_CONTAINER || ct === `${MT_CONTAINER}+json`;
    if (ct !== "" && ct !== MT_OBJECT && ct !== `${MT_OBJECT}+json` &&
      !wantsQueue && !wantsContainer) {
      throw new Condition(415, "",
        "The media type is not supported.",
        `${ct} is not the media type of a data object`);
    }
    let body: Record<string, unknown> = {};
    if (raw.length > 0) {
      body = parseBodyJson(raw);
      if (body === null || typeof body !== "object" || Array.isArray(body)) {
        throw malformed("the message body shall be a JSON object");
      }
    }
    // The name is assigned by this CDMI server. An object created
    // within a container object is addressed by that name as well as
    // by its object ID, so the name is one a client may address; an
    // object created in the object ID tree is not presented in the
    // namespace, and takes a reserved name so that it is not.
    const name = byID ? `${ASSIGNED}${randomUUID()}` : randomUUID();

    if (byID) {
      // An object created here has no parent: it is addressed by its
      // object ID alone. "Where a create operation with a server-assigned
      // name is made at <base>/cdmi_objectid/, the root container object of
      // that base URI is the object the operation acts on. The rules of
      // [the create subclause] that govern a create within a container
      // object apply to that root container object as they apply to a
      // parent container object. Those rules determine four things: the
      // domain within which the credentials are resolved, the permission
      // the requesting principal holds, the domain of the object created
      // where the request names none, and whether the cross_domain
      // privilege is required" (revision 354). So the root container object
      // stands for the parent everywhere below.
      // "the root container object **of that base URI**": the object a CDMI
      // export presents, where the request came through the base URI that
      // export established, and this server's own root otherwise. This read
      // this server's own root whatever base URI the request used until 0.101,
      // so a principal granted ALL_PERMS on a container object it reached
      // through a CDMI export was refused a create at that base URI's
      // cdmi_objectid/ for want of a permission on a container object it had
      // never addressed and could not see.
      //
      // It governs the four things the subclause names and no others — "the
      // domain within which the credentials are resolved, the permission the
      // requesting principal holds, the domain of the object created where the
      // request names none, and whether the cross_domain privilege is
      // required" — so it is not where the object is put. An object created
      // here "has no parent: it is addressed by its object ID alone" and "is
      // not presented in the namespace", so it is held under a reserved name as
      // it was, and the holder below is this server's own root.
      const governing = this.baseRootFor(req);
      const root = this.store.root();
      this.demand(governing, who, M.ADD_OBJECT, true, "creating an object by object ID");
      // The object created is of the type the copy or the
      // deserialization produces, where one is asked for, and of the
      // type the media type names otherwise.
      let queue = wantsQueue;
      let container = wantsContainer;
      let source: { node: Node } | undefined;
      let doc: Canonical | undefined;
      // A serialization creates a data object whose value is the
      // canonical format, whatever the type of the object serialized.
      let serialized: Buffer | undefined;
      let serializedType: string | undefined;
      if ("serialize" in body) {
        const from = body.serialize;
        if (typeof from !== "string" || from === "") {
          throw invalidField("serialize",
            "the serialize field addresses the object to be serialized");
        }
        const of = await this.sourceOf(r, from, who);
        let format;
        try {
          format = await serialize(this.serializeContext(who), of.node);
        } catch (err) {
          if (err instanceof SerializeError) throw forbidden("%s: %s", from, err.message);
          throw err;
        }
        serialized = Buffer.from(JSON.stringify(format, null, 2) + "\n", "utf8");
        serializedType = format.objectType;
        queue = false;
        container = false;
      } else if ("copy" in body) {
        source = await this.sourceOf(r, String(body.copy), who);
        // A copy produces an object of the type of its source, whatever
        // the media type of the request names. A container object source
        // was refused outright before 0.82, there being no way to create
        // a container object here at all.
        container = source.node.isContainer;
        queue = !container && this.store.meta(source.node).isQueue;
      } else if ("deserialize" in body || "deserializevalue" in body) {
        doc = await this.canonicalOf(r, body, who);
        queue = doc.objectType === CANONICAL_QUEUE;
        container = doc.objectType === MT_CONTAINER;
      }
      if (container) {
        // "The requesting principal holds ADD_SUBCONTAINER on c, the object
        // created being a container object" (EXAMPLE 7.11a).
        this.demand(governing, who, M.ADD_SUBCONTAINER, true,
          "creating a container object by object ID");
      }
      // The domain, the owner and the access control list are those a
      // create within the root container object of that base URI would give
      // the object, the cross_domain privilege and the cdmi_owner rule
      // included — three of the four things that object determines.
      const m = this.newObjectIdentity(body, governing, who, container);
      // A container object copied here is copied whole, the objects it
      // holds and the objects those hold, as a copy to a name is.
      if (container && source !== undefined) {
        const copied = await this.copyInto(root, name, source.node, who, undefined);
        return this.createdByID(res, copied, MT_CONTAINER, false);
      }
      const node = container
        ? this.store.createContainer(root, name, m)
        : queue
        ? this.store.createQueue(root, name, m)
        : this.store.createData(root, name, m);
      if (serialized !== undefined) {
        const sm = this.store.meta(node);
        // The media type of the object created reports the type of the
        // object serialized, as it does for a serialization to a name.
        sm.mimetype = serializedType ?? MT_OBJECT;
        sm.vte = "utf-8";
        this.store.setMeta(node, sm);
        await this.store.setValue(node, serialized);
      } else if (source !== undefined) {
        await this.copyValueAndMetadata(node, source.node);
      } else if (doc !== undefined) {
        await this.applyCanonical(doc, root, name, who, undefined, node, body);
      } else if (queue) {
        // A queue object created with no source holds no value: the
        // values are appended by a POST addressing it.
        for (const f of ["queueValues", "valuerange", "value"]) {
          if (f in body) {
            throw invalidField(f,
              "the values of a queue object are appended by a POST addressing it");
          }
        }
      } else if (container) {
        // The fields of a container object create are applied as they
        // are to a create by name: the metadata, and the imports and
        // exports, whose credential references are bound first.
        const bound = await this.withBoundImports(root, body, who, this.domainOf(root));
        this.applyContainerFields(node, ns, bound, "complete", sel, true, who);
      } else {
        await this.applyData(node, body, "complete", sel, name, true, who);
      }
      return this.createdByID(res, node,
        container ? MT_CONTAINER : queue ? MT_QUEUE : MT_OBJECT, !container && !queue);
    }

    const pv = await r.view(ns);
    if (pv.unavail) throw pv.unavail;
    if (pv.writeRank === undefined) {
      throw pv.writeUnavail ?? forbidden("%s cannot be added to: %s", ns, pv.writeWhy);
    }
    const target = await ensureWriteTarget(this.store, pv);
    // "cdmi_post_queue ... the ability of the container to add a new queue
    // object via POST"; "cdmi_post_container ... the ability of the
    // container object to add a new container object with a name the CDMI
    // server assigns" (Annex B). This server published cdmi_post_queue and
    // refused the media type with 415 before 0.82, and published
    // cdmi_post_container not at all.
    const at = this.base.slice(0, -1) + ns + name;
    if (wantsQueue) {
      // A queue object created here is created by the path that creates one
      // at a name the client supplies, so its query metadata, its exports
      // and its imports are checked as they are there.
      return this.createQueueAt(res, pv, target, `${ns}${name}`, name, body, "complete",
        who, { Location: at });
    }
    this.demand(target, who, wantsContainer ? M.ADD_SUBCONTAINER : M.ADD_OBJECT, true,
      `creating an object within ${ns}`);
    const kind = this.newObjectIdentity(body, target, who, wantsContainer);
    const node = wantsContainer
      ? this.store.createContainer(target, name, kind)
      : this.store.createData(target, name, kind);
    if (wantsContainer) {
      const bound = await this.withBoundImports(target, body, who, this.domainOf(target));
      this.applyContainerFields(node, `${ns}${name}/`, bound, "complete", sel, true, who);
    } else {
      await this.applyData(node, body, "complete", sel, name, true, who);
    }
    this.store.startCounts(node);
    // "The requirements of [Fields], [Data sources] and [Result] apply, so that
    // the response carries a representation of the object created as it does
    // for a create addressed by name, and the address in addition" (revision
    // 365, create with a server-assigned name). This answered 201 with an empty
    // body and the address alone, so a CDMI client learned the name assigned
    // and nothing else — not the object ID, and not the fields the CDMI server
    // had set. It had to read the object to find out what it had made.
    //
    // A field selection is not applied to the representation. The Result
    // subclause says one limits it and the Fields subclause of the same clause
    // says it does not (ECR-200A); this server holds the reading it held for a
    // create addressed by name, which is the Result subclause's, and a create
    // with a server-assigned name carries no selection of its own in this
    // binding, so the two agree here whichever way the ECR is settled.
    const location = at + (wantsContainer ? "/" : "");
    if (wantsContainer) {
      const cv = await r.child(pv, name);
      return this.sendContainer(req, res, cv, pv, name, emptySelection(), 201, false, who,
        { Location: location });
    }
    return this.sendData(req, res, pv, { kind: "store", node },
      {
        dir: { kind: "store", node: target }, rank: pv.writeRank!, via: [],
        imported: false, hideIDs: false, readOnly: false,
      },
      name, emptySelection(), 201, false, who, { Location: location });
  }

  /** Copies the value and the metadata of one data object to another. */
  private async copyValueAndMetadata(into: Node, from: Node): Promise<void> {
    if (this.store.meta(from).isQueue) {
      // A queue object holds an ordered sequence of values rather than
      // a value, and the designators of the object created begin at
      // zero, being unique within it.
      const held = this.store.queueBounds(into);
      if (held.count > 0) this.store.dequeue(into, held.lowest, held.highest);
      this.store.enqueue(into, this.store.queueValues(from).map((v) => ({
        mimetype: v.mimetype,
        vte: v.vte,
        body: v.body,
      })));
      const m = this.store.meta(into);
      m.metadata = withoutRestrictions(this.store.meta(from).metadata);
      this.store.setMeta(into, m);
      return;
    }
    const m = this.store.meta(from);
    const target = this.store.meta(into);
    target.mimetype = m.mimetype;
    target.vte = m.vte;
    // Retention and hold are not applied to an object created by
    // copying one that is under either.
    target.metadata = withoutRestrictions(m.metadata);
    this.store.setMeta(into, target);
    await this.store.shareValue(into, from);
  }

  /** Splits a namespace path into its parent, its name, and its form. */
  private split(ns: string): { parentNS: string; name: string; isContainer: boolean } {
    const isContainer = ns.endsWith("/");
    const trimmed = isContainer ? ns.slice(0, -1) : ns;
    const cut = trimmed.lastIndexOf("/");
    return { parentNS: trimmed.slice(0, cut + 1), name: trimmed.slice(cut + 1), isContainer };
  }

  // -----------------------------------------------------------------
  // Read

  /**
   * Whether the principal is granted every bit of wanted on the object,
   * by the access control list stored with it.
   */
  /**
   * Whether the principal is granted every bit of wanted. An object
   * presented through an image import carries no list of its own, so the
   * list of the container object that imports it governs, as clause 9
   * requires; the caller passes that container as governs.
   */
  private may(ref: DirRef | ObjRef | Node, who: Principal, wanted: number,
    isContainer: boolean, governs?: Node): boolean {
    // The object's own list governs where it has one. The container that
    // imports an image governs only the objects of that image, which
    // carry none.
    const node = asNode(ref) ?? governs;
    if (!node) {
      // An image object with nothing governing it: nothing is granted.
      return false;
    }
    // The backup operator privilege permits an operation the access
    // control list of an object does not permit, for the purpose of
    // backing up an object or restoring it. It does not reach the
    // rules that are not access control: an object under retention
    // or under hold is refused as it is for any principal, those
    // being obligations of the CDMI server rather than grants to a
    // principal.
    if (who.privileges.includes("backup_operator")) return true;
    // "The CDMI server sends the permission mask obtained from the access
    // control list to the delegated access control provider, and the provider
    // returns the mask that shall be applied in its place. The provider may
    // therefore grant access the access control list denies, and deny access
    // the access control list allows."
    const delegated = this.perRequest.getStore()?.masks.get(node.id);
    if (delegated !== undefined) return (delegated & wanted) === wanted;
    const m = this.store.meta(node);
    return granted(m.acl, who, wanted, {
      owner: m.owner,
      group: m.group,
      isContainer,
      // A root container object falls back to its owner and to the
      // administrators, so that a list below it can be repaired.
      isRoot: m.parent === null,
    });
  }

  /**
   * Refers the decision for the object a request addresses to its delegated
   * access control provider, where the object carries both of the metadata
   * items that request it. The mask the provider returns is held for the
   * request, and `may` applies it in place of the one the list yielded.
   *
   * Where no valid response is received the operation is not performed and the
   * forbidden condition is reported. A provider that cannot be reached is the
   * same case: "Where the CDMI server does not receive a valid response, it
   * shall not perform the operation and shall report the forbidden condition."
   */
  private async delegate(req: IncomingMessage, res: ServerResponse, ns: string,
    who: Principal, method: string, sel: Selection): Promise<boolean> {
    if (this.dac === undefined) return false;
    // A key whose retention has ended is purged, and the purge recorded.
    for (const purged of this.dac.purgeExpired()) {
      if (purged.auditUri !== undefined) {
        await this.audit(purged.auditUri, who, { event: "key_purged", cdmi_objectID: purged.objectId });
      }
    }
    const accesses = await this.accessesOf(req, ns, method, sel);
    for (const [index, access] of accesses.entries()) {
      if (await this.delegateAccess(req, res, access.ns, access.node, access.operation, who, index === 0,
        access.presented)) return true;
    }
    return false;
  }

  /**
   * One delegated access control request, for one access of an operation, and
   * the mask it returns recorded for that object. A redirection answers the
   * request only where it is for the first access, the object the operation
   * addresses or the container it creates within. True where the request has
   * been answered.
   */
  private async delegateAccess(req: IncomingMessage, res: ServerResponse, ns: string, node: Node, operation: DacOperation,
    who: Principal, first: boolean, presented?: string): Promise<boolean> {
    const dac = this.dac;
    if (dac === undefined) return false;
    const meta = this.store.meta(node).metadata as Record<string, unknown>;
    const uri = meta.cdmi_dac_uri;
    const certificate = meta.cdmi_dac_certificate;
    // "Delegated access control is used where the metadata items cdmi_dac_uri
    // and cdmi_dac_certificate are both present for an object ... Where only
    // one is present, delegated access control shall not be used."
    if (typeof uri !== "string" || typeof certificate !== "object" || certificate === null) {
      // "Where only one is present, delegated access control shall not be used
      // for that object." That is silent by design, and it is also what an
      // object looks like where a CDMI client set one item and expected
      // delegation, so the one item present is recorded. Neither present is
      // the ordinary case and is not recorded.
      if (uri !== undefined || certificate !== undefined) {
        this.log.dac({
          event: "not delegated", instance: ns, principal: who.name, operation,
          detail: typeof uri === "string"
            ? "cdmi_dac_uri is present and cdmi_dac_certificate is not"
            : "cdmi_dac_certificate is present and cdmi_dac_uri is not",
        });
      }
      return false;
    }
    const target: DacTarget = { uri, certificate: certificate as DacTarget["certificate"] };
    const m = this.store.meta(node);
    // An object an import presents is named by its own identity, the provider
    // of the importing object deciding for it (revision 297; ECR-089B).
    const identity = presented === undefined ? this.store.meta(node).objectID : await this.presentedIdentity(presented);
    const context: DacContext = {
      objectId: identity,
      operation,
      // "A text or hexadecimal string representation of the ACE mask": a mask
      // granting nothing has no name in the ACE bit mask table, so it is sent in
      // hexadecimal. It was sent as "NONE" before 0.55, which the draft does not
      // define and a provider could not read.
      effectiveMask: ((granted: number) => granted === 0 ? "0x00000000" : maskToString(granted, node.isContainer))(
        grantedMask(m.acl, who, {
          owner: m.owner, group: m.group, isContainer: node.isContainer, isRoot: m.parent === null,
        })),
      principal: { name: who.name, groups: [...who.groups] },
      clientHeaders: {
        ...passedThroughHeaders(req),
        // A request of the CDMI over MCP binding carries no header fields of a
        // CDMI client's own — the call arrives as a JSON-RPC message, and the
        // header fields of the request that carried it are the transport's — so
        // a provider reading client_headers could not tell an operation of that
        // binding from one of the HTTP binding, and its log said nothing of
        // where the operation came from. This says so, under the prefix the
        // subclause reserves for a field passed through, and carries the trace
        // identifier of the call and the program that made it: "A CDMI server
        // that keeps a record of an operation records that value with it, so
        // that the record an intermediary keeps and the record the CDMI server
        // keeps are recognizable as being of one operation" — the provider's
        // record is a third such record, and this is what joins it to the other
        // two.
        ...this.dacOperationMeta(req),
      },
    };
    // Every delegated access control request this server makes is recorded,
    // whatever the log level, as is what became of it. An operation refused
    // because no valid response arrived is indistinguishable, at the CDMI
    // client, from one the access control list refused, and these two lines
    // are what tells them apart.
    this.log.dac({
      event: "request sent", uri: target.uri, object: context.objectId, operation: context.operation,
      instance: ns, principal: who.name, effective: context.effectiveMask,
    });
    let decision;
    const began = Date.now();
    try {
      decision = await dac.decide(target, context);
    } catch (err) {
      if (err instanceof DacError) {
        this.log.dac({
          event: "no valid response", uri: target.uri, object: context.objectId,
          operation: context.operation, instance: ns, principal: who.name,
          detail: err.message, ms: Date.now() - began,
        });
        throw forbidden("the delegated access control provider of %s did not authorize this operation", ns);
      }
      this.log.dac({
        event: "request failed", uri: target.uri, object: context.objectId, operation: context.operation,
        instance: ns, principal: who.name, detail: err instanceof Error ? err.message : String(err),
        ms: Date.now() - began,
      });
      throw err;
    }
    this.log.dac({
      event: "response applied", uri: target.uri, object: context.objectId, operation: context.operation,
      instance: ns, principal: who.name, applied: decision.appliedMask, retained: decision.cached === true,
      ...(decision.redirectObjectId === undefined ? {} : { redirect: decision.redirectObjectId }),
      ms: Date.now() - began,
    });
    // "Where a response specifies an audit URI, the CDMI server shall generate
    // an audit record for every operation it permits on the basis of that
    // response, including every operation permitted on the basis of a retained
    // copy of it", and a record for receiving the response.
    if (decision.auditUri !== undefined) {
      if (decision.cached !== true) {
        await this.audit(decision.auditUri, who, {
          event: "response_received", cdmi_objectID: context.objectId, cdmi_operation: context.operation,
        });
      }
      await this.audit(decision.auditUri, who, {
        event: "operation_permitted", cdmi_objectID: context.objectId, cdmi_operation: context.operation,
        dac_applied_mask: decision.appliedMask, retained: decision.cached === true,
      });
    }
    // "If present, the CDMI server shall redirect the CDMI client to that
    // object by the means the protocol binding defines. Redirection confers no
    // access", so nothing of this decision is carried to the object addressed:
    // the redirection answers the request, and a request for that object is
    // evaluated on its own when the CDMI client makes one.
    if (decision.redirectObjectId !== undefined && first) {
      res.writeHead(307, {
        Location: `${this.base}cdmi_objectid/${decision.redirectObjectId}`,
        "Content-Length": "0",
      });
      res.end();
      return true;
    }
    // "A series of headers that start with CDMI-DAC- to be returned to the
    // CDMI client."
    for (const [name, value] of Object.entries(decision.responseHeaders)) res.setHeader(name, value);
    let applied;
    try {
      applied = parseMask(decision.appliedMask, node.isContainer);
    } catch {
      throw forbidden("the delegated access control provider of %s returned a mask that is not one", ns);
    }
    this.perRequest.getStore()?.masks.set(node.id, applied);
    return false;
  }

  /**
   * Receives a packaged delegated access control response sent to the URI a
   * request stated. The content is protected end to end, so this endpoint
   * needs no authentication of its own: a response is acted upon only where it
   * decrypts to this server, verifies against the provider of a request
   * awaiting one, and carries that request's identifier.
   */
  private async dacResponse(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== "POST") {
      res.writeHead(405, { Allow: "POST", "Content-Length": "0" });
      return void res.end();
    }
    const limit = 256 * 1024;
    const chunks: Buffer[] = [];
    let read = 0;
    for await (const chunk of req as unknown as AsyncIterable<Buffer>) {
      read += chunk.length;
      if (read > limit) {
        res.writeHead(413, { "Content-Length": "0" });
        return void res.end();
      }
      chunks.push(chunk);
    }
    const answered = await this.dac!.acceptAsync(Buffer.concat(chunks));
    // Recorded whatever the log level, as a request sent is: a response
    // delivered here and not accepted leaves the operation waiting for one,
    // and nothing else shows that it arrived.
    this.log.dac({
      event: answered === undefined ? "response not accepted" : "response accepted",
      instance: `${this.base}${DAC_RESPONSE_PATH}`, bytes: read,
      ...(answered === undefined ? {} : { request: answered }),
    });
    // Nothing of what was decided, and nothing of why a response was not
    // accepted, is told to whoever posted it.
    res.writeHead(answered === undefined ? 400 : 204, { "Content-Length": "0" });
    res.end();
  }

  /**
   * Writes an audit record to the CDMI queue a response names. "Where the CDMI
   * server cannot generate an audit logging message that this field requires,
   * it shall not perform the operation, so that an operation is not performed
   * on the basis of a response whose use cannot be recorded." The content of a
   * record is not defined by the draft; this server writes a JSON object of
   * the event, the time, the object, the operation and the principal.
   */
  private async audit(uri: string, who: Principal, record: Record<string, unknown>): Promise<void> {
    const queue = this.queueForAudit(uri);
    if (queue === undefined) {
      throw forbidden("the audit queue %s of the delegated access control provider cannot be written", uri);
    }
    const body = Buffer.from(JSON.stringify({
      ...record,
      time: cdmiTime(Date.now()),
      principal: who.name,
    }), "utf8");
    try {
      this.store.enqueue(queue, [{ mimetype: "application/json", vte: "utf-8", body }]);
    } catch {
      throw forbidden("the audit queue %s of the delegated access control provider cannot be written", uri);
    }
  }

  /** The queue object an audit URI addresses, where this server holds one there. */
  private queueForAudit(uri: string): Node | undefined {
    // An absolute URI addresses this server only where it begins with a base
    // URI of this server; one naming another server's queue is not written
    // here, and the operation is not performed. Before 0.54 an absolute URI was
    // reduced to its path, whatever its host, and a queue of this server at
    // that path was written in place of the one the provider named.
    let ns: string | undefined;
    if (/^[a-z][a-z0-9+.-]*:/i.test(uri)) {
      ns = localImportPath(uri);
    } else if (uri.startsWith(this.base)) {
      ns = uri.slice(this.base.length - 1);
    }
    if (ns === undefined) return undefined;
    const node = this.nodeForDelegation(ns);
    if (node === undefined || node.isContainer) return undefined;
    // A queue object, and not a data object.
    return this.store.meta(node).isQueue ? node : undefined;
  }

  /**
   * The object a decision is asked about: the one the request addresses, where
   * this server holds it. An object presented by an import, or one that does
   * not exist, has no metadata of this server's to carry the items; phase 5
   * extends delegation to the other paths.
   */
  private nodeForDelegation(ns: string): Node | undefined {
    return this.forDelegation(ns).node;
  }

  /**
   * The object of the store an operation is referred by, and the part of the
   * path beneath it that the store does not hold: an object an import presents
   * has no object of the store, and "Where the importing object carries the
   * cdmi_dac_uri and cdmi_dac_certificate metadata items, the CDMI server
   * shall refer every operation on an object that the import presents to the
   * delegated access control provider those items name, as it does for the
   * importing object itself" (revision 297; ECR-089B). Before 0.63 such an
   * operation was referred to no provider.
   */
  private forDelegation(ns: string): { node?: Node; presented?: string } {
    let node: Node = this.store.root();
    const segments = ns.split("/").filter((s) => s !== "");
    for (const [i, seg] of segments.entries()) {
      const next = this.store.tryLookup(node, seg);
      if (!next) {
        // What remains is presented by an import, where this object imports
        // and carries the delegation items. A name that is simply not there,
        // such as the name of an object about to be created, is not presented.
        const m = this.store.meta(node);
        const held = m.metadata as Record<string, unknown>;
        if (m.imports === undefined || typeof held.cdmi_dac_uri !== "string") return {};
        return { node, presented: `${ns.startsWith("/") ? "" : "/"}${ns}` };
      }
      node = next;
    }
    return { node };
  }

  /**
   * The accesses an operation makes, each an object and the value of
   * "cdmi_operation" that Table "The value of cdmi_operation for each access"
   * of revision 269 gives it (ECR-066B): a delegated access control request is
   * submitted for each whose object carries the delegation items. "A move is a
   * create within the destination container object and a delete from the source
   * container object, and a copy is a read of the source and a create within the
   * destination; a CDMI server submits a request for each, against the object
   * concerned." Where the access is not determined more closely, "cdmi_read" is
   * sent where it changes nothing and "cdmi_modify" where it does, so that it
   * "is not sent as a value that understates it". Before 0.61 four values were
   * sent, by method alone, and nothing for a create.
   */
  private async accessesOf(req: IncomingMessage, ns: string, method: string, sel: Selection):
    Promise<{ node: Node; ns: string; operation: DacOperation; presented?: string }[]> {
    const found = this.forDelegation(ns);
    const target = found.node;
    // An object an import presents is referred to the provider of the
    // importing object, and named by its own identity (revision 297).
    const presented = found.presented === undefined ? undefined : ns;
    const parentNs = ns.replace(/[^/]+\/?$/, "");
    if (method === "DELETE") return target === undefined ? [] : [{ node: target, ns, operation: "cdmi_delete", presented }];
    if (method === "GET" || method === "HEAD") {
      if (target === undefined) return [];
      const m = this.store.meta(target);
      // A value is read by a request naming no CDMI media type, or by selecting it.
      const readsValue = namesNoCDMIMediaType(req) || sel.value || sel.everyField === true || sel.valueRanges.length > 0;
      let operation: DacOperation;
      if (target.isContainer) {
        // A container's representation lists its children unless a selection omits them.
        operation = !sel.any || sel.fields.includes("children") || sel.childRange !== undefined ? "cdmi_list" : "cdmi_read_metadata";
      } else if (m.isQueue === true) {
        operation = readsValue || sel.queueValues !== undefined ? "cdmi_read" : "cdmi_read_metadata";
      } else {
        operation = readsValue ? "cdmi_read" : "cdmi_read_metadata";
      }
      return [{ node: target, ns, operation, presented }];
    }
    if (method === "POST") {
      if (target === undefined) return [];
      // A POST to a container creates within it; to a queue it appends values.
      return [{ node: target, ns, operation: target.isContainer ? "cdmi_create" : "cdmi_modify", presented }];
    }
    if (method !== "PUT" && method !== "PATCH") {
      return target === undefined ? [] : [{ node: target, ns, operation: "cdmi_modify", presented }];
    }
    const out: { node: Node; ns: string; operation: DacOperation; presented?: string }[] = [];
    // What a CDMI body asks: a value, a copy, a move or a deserialization changes a value.
    const ct = mediaTypeOf(String(req.headers["content-type"] ?? ""));
    let body: Record<string, unknown> | undefined;
    let changesValue = true;
    if (ct.startsWith("application/cdmi-")) {
      try {
        const parsed = JSON.parse((await readBody(req)).toString("utf8")) as unknown;
        if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) body = parsed as Record<string, unknown>;
      } catch { /* not understood: a change of the value, which does not understate it */ }
      if (body !== undefined) {
        changesValue = ["value", "copy", "move", "deserialize", "deserializevalue"].some((f) => f in body!);
      }
    }
    if (target === undefined) {
      const parent = this.nodeForDelegation(parentNs);
      if (parent !== undefined) out.push({ node: parent, ns: parentNs, operation: "cdmi_create" });
    } else {
      out.push({ node: target, ns, operation: target.isContainer || !changesValue ? "cdmi_modify_metadata" : "cdmi_modify" });
    }
    // The source of a move is deleted from where it was, and that of a copy read.
    for (const [field, operation] of [["move", "cdmi_delete"], ["copy", "cdmi_read"]] as const) {
      const source = body?.[field];
      if (typeof source !== "string") continue;
      const sourceNs = this.localPathOf(source);
      const node = sourceNs === undefined ? undefined : this.nodeForDelegation(sourceNs);
      if (node !== undefined && sourceNs !== undefined) out.push({ node, ns: sourceNs, operation });
    }
    return out;
  }

  /** The namespace path of a copy or move source of this server, given as a path or as a URI of its base; else undefined. */
  private localPathOf(source: string): string | undefined {
    let path = source;
    try {
      if (/^[a-z][a-z0-9+.-]*:/i.test(source)) path = new URL(source).pathname;
    } catch {
      return undefined;
    }
    if (path.startsWith(this.base)) path = "/" + path.slice(this.base.length);
    if (!path.startsWith("/")) return undefined;
    try {
      return path.split("/").map((x, i) => (i === 0 ? x : decodeURIComponent(x))).join("/");
    } catch {
      return undefined;
    }
  }


  /** Whether the list of an object explicitly denies a bit. */
  private denies(ref: DirRef | ObjRef | Node, who: Principal, bit: number,
    governs?: Node): boolean {
    const node = asNode(ref) ?? governs;
    if (!node) return true;
    const m = this.store.meta(node);
    return deniedExplicitly(m.acl, who, bit, {
      owner: m.owner,
      group: m.group,
      isContainer: false,
      isRoot: m.parent === null,
    });
  }

  /**
   * An object within a snapshot is not created, updated or deleted.
   * The rule is enforced where permission is demanded, so that every
   * door reaches it rather than each operation repeating it.
   */
  /**
   * Deletes the object a request addresses where it asked to be
   * deleted automatically and the criteria are satisfied: the
   * retention period has passed and no hold applies. Both are
   * required, whatever the period specifies.
   *
   * The draft does not say when a CDMI server notices, so this one
   * notices when the object is next addressed; see R3.
   */
  private async autodelete(ns: string): Promise<void> {
    let node: Node = this.store.root();
    for (const seg of ns.split("/")) {
      if (seg === "") continue;
      const next = this.store.tryLookup(node, seg);
      if (!next) return;
      node = next;
    }
    if (node.id === this.store.root().id) return;
    let due: boolean;
    try {
      const m = this.store.meta(node);
      due = autodeletable(restrictionOf(m.metadata));
    } catch {
      return;
    }
    if (!due) return;
    // A container object holding a restricted object is not deleted,
    // and neither is one deleted automatically.
    if (node.isContainer && this.restrictedWithin(node) !== undefined) return;
    await this.store.collect(this.store.removeTree(node));
  }

  /**
   * Whether an object is under retention or under hold, and therefore
   * not deleted and not modified whatever its access control lists
   * permit.
   */
  private restrictionOf(node: Node): Restriction {
    const m = this.store.meta(node);
    return restrictionOf(m.metadata);
  }

  /**
   * The name of an object within a container that is under retention
   * or hold, where there is one. Deleting a container deletes what it
   * holds, so a restricted object within it prohibits that too.
   */
  private restrictedWithin(node: Node): string | undefined {
    return restrictedWithin(node,
      (n) => this.store.children(n)
        .map((c) => ({ name: c.name, node: c.node, isContainer: c.node.isContainer })),
      (n) => this.store.meta(n).metadata);
  }

  /**
   * Refuses a change to an object under retention or hold. The change
   * that adds to either is permitted, and is checked separately: this
   * covers everything else.
   */
  private refuseRestricted(ref: DirRef | ObjRef | Node, wanted: number,
    what: string): void {
    // Every bit that governs a change to the object. WRITE_ATTRIBUTES and the
    // two retention bits were missing until 0.109, and they are the bits that
    // govern a change to a cdmi_ metadata item: so an object under hold accepted
    // a change to cdmi_retention_id, and to cdmi_retention_autodelete — turning
    // "keep this until 2030" into "delete this in 2030", which is the change
    // retention exists to prevent. The clause permits two changes to such an
    // object and no others, "an update that moves the instant at which the
    // retention period ends later, or that adds a value to the cdmi_hold_id
    // item", and those two reach here exempted, changesMore having judged the
    // body first.
    const CHANGING = M.WRITE_OBJECT | M.WRITE_METADATA | M.DELETE |
      M.DELETE_OBJECT | M.DELETE_SUBCONTAINER | M.WRITE_ACL | M.WRITE_OWNER |
      M.APPEND_DATA | M.WRITE_ATTRIBUTES | M.WRITE_RETENTION |
      M.WRITE_RETENTION_HOLD;
    if ((wanted & CHANGING) === 0) return;
    const node = "id" in ref ? ref as Node : nodeOf(ref as ObjRef);
    if (!node) return;
    let r: Restriction;
    try {
      r = this.restrictionOf(node);
    } catch {
      return;
    }
    if (!restricted(r)) return;
    throw retentionConflict(
      "%s: the object is under %s, and is not deleted or modified until %s", what,
      r.holds.length > 0 ? "hold" : "retention",
      r.holds.length > 0
        ? `the hold${r.holds.length > 1 ? "s are" : " is"} released`
        : "the retention period has passed");
  }

  private refuseFrozen(ref: DirRef | ObjRef | Node, wanted: number, what: string,
    copiedUp = false): void {
    // An object of a layer below the write target is copied up before
    // it is changed, so the frozen object is read and not written:
    // this is how a snapshot serves as the lower layer of a sandbox.
    if (copiedUp) return;
    const CHANGING = M.WRITE_OBJECT | M.WRITE_METADATA | M.ADD_OBJECT |
      M.ADD_SUBCONTAINER | M.DELETE | M.DELETE_OBJECT | M.DELETE_SUBCONTAINER |
      M.WRITE_ACL | M.WRITE_OWNER | M.APPEND_DATA;
    if ((wanted & CHANGING) === 0) return;
    const node = "id" in ref ? ref as Node : nodeOf(ref as ObjRef);
    if (!node) return;
    let m;
    try {
      m = this.store.meta(node);
    } catch {
      return;
    }
    if (m.frozen) {
      throw forbidden("an object within a snapshot is not modified: %s", what);
    }
  }

  /**
   * The root container object of the base URI a request used: the object a
   * CDMI export presents, where the request came through the base URI that
   * export established, and this server's own root container object otherwise.
   *
   * "Where a create operation with a server-assigned name is made at
   * <base>/cdmi_objectid/, the root container object of that base URI is the
   * object the operation acts on. The rules of [the create subclause] that
   * govern a create within a container object apply to that root container
   * object as they apply to a parent container object."
   */
  private baseRootFor(req: IncomingMessage): Node {
    const base = this.noted(req).exportBase;
    if (base === undefined) return this.store.root();
    const node = this.nodeAt(base);
    return node ?? this.store.root();
  }

  private demand(ref: DirRef | ObjRef | Node, who: Principal, wanted: number,
    isContainer: boolean, what: string, governs?: Node, copiedUp = false): void {
    this.refuseFrozen(ref, wanted, what, copiedUp);
    if (!copiedUp) this.refuseRestricted(ref, wanted, what);
    if (!this.may(ref, who, wanted, isContainer, governs)) {
      throw forbidden("%s requires %s, which %s is not granted", what,
        maskToString(wanted, isContainer), who.name);
    }
  }

  private async read(req: IncomingMessage, res: ServerResponse, r: Resolver,
    ns: string, sel: Selection, who: Principal): Promise<void> {
    const head = req.method === "HEAD";
    if (ns === "/") {
      return this.sendContainer(req, res, await r.rootView(), undefined, "/", sel, 200, head, who);
    }
    const { parentNS, name, isContainer } = this.split(ns);
    const pv = await r.view(parentNS);
    if (pv.unavail) throw pv.unavail;

    if (!isContainer) {
      const found = await resolveFile(this.store, pv, name);
      if (!found) {
        // A name that denotes a container object alone gets a redirect.
        try {
          await r.child(pv, name);
        } catch {
          throw notFound(ns);
        }
        res.writeHead(307, { Location: withQuery(req, this.base.slice(0, -1) + ns + "/") });
        return res.end();
      }
      // The CDMI client names the representation it requires; where
      // it names none, the one corresponding to the form of the path
      // is acted upon, and a path without a solidus corresponds to a
      // data object and to a queue object alike.
      let ref = found.ref;
      let node = nodeOf(ref);
      let isQueue = node !== undefined && this.store.meta(node).isQueue;
      const heldAt = nodeOf(pv.held);
      const wanted = this.kindWanted(req, isQueue, () =>
        heldAt !== undefined && this.store.lookupKind(heldAt, name, isQueue ? "data" : "queue") !== undefined,
        () => heldAt !== undefined && this.store.lookupKind(heldAt, name, "container") !== undefined);
      if (wanted === "container") {
        return correctForm(req, res, this.base, ns);
      }
      if (wanted !== undefined) {
        const writeAt = heldAt;
        const other = writeAt === undefined
          ? undefined
          : this.store.lookupKind(writeAt, name, wanted);
        if (other === undefined) {
          throw notFound(
            `${ns}: the name denotes no ${wanted === "queue" ? "queue" : "data"} ` +
            "object representation");
        }
        ref = { kind: "store", node: other };
        node = other;
        isQueue = wanted === "queue";
      }
      if (node !== undefined && isQueue) {
        return this.sendQueue(req, res, pv, node, ns, name, sel, head, who);
      }
      return this.sendData(req, res, pv, ref, found.layer, name, sel, 200, head, who);
    }
    const cv = await r.child(pv, name);
    return this.sendContainer(req, res, cv, pv, name, sel, 200, head, who);
  }

  /**
   * Sends the representation of a queue object. Reading a value does
   * not remove it: a value is removed by a delete operation carrying a
   * queue value selection.
   */
  /**
   * The representation a request names in its Accept header field,
   * where it names one this document defines. A namespace path names
   * the object and does not select the representation; a CDMI client
   * that names none is answered with the representation that
   * corresponds to the form of the path.
   */
  /**
   * Which of the data object and the queue object of a name a request is
   * for, where a name may denote both: the kind found, where the Accept field
   * admits it; the other kind, where Accept admits that and not the kind
   * found; and the kind found otherwise, which content negotiation then
   * refuses with 406 where Accept admits nothing it can return.
   *
   * Every type Accept lists is acceptable, not the first alone: "Where the
   * Accept header field matches no media type the CDMI server can return, the
   * CDMI server shall return ... 406". Before 0.44 the first CDMI type found
   * decided, queue first, so an Accept listing both types answered 404 for
   * every data object.
   */
  private kindWanted(req: IncomingMessage, foundIsQueue: boolean,
    hasOther: () => boolean = () => true,
    hasContainer: () => boolean = () => false): "queue" | "data" | "container" | undefined {
    const ranked = kindsRanked(req.headers.accept as string | undefined);
    if (ranked.some((r) => r.kind === "any")) return undefined;
    // A field naming no media type of this document, such as multipart/mixed
    // for the values of a queue, is answered where the operation provides for
    // it, and is not a choice between representations.
    if (ranked.length === 0) return undefined;
    const found = foundIsQueue ? "queue" : "data";
    const other = foundIsQueue ? "data" : "queue";
    // The first representation the name has, in the order the field gives.
    // Before 0.63 the representation found decided wherever it was admitted,
    // whatever quality value the field gave the other.
    for (const { kind } of ranked) {
      if (kind === found) return undefined;
      if (kind === other && hasOther()) return other;
    }
    // "Where the Accept header field matches no media type the CDMI server can
    // return, the CDMI server shall return 406": a name whose only
    // representation is not admitted is not reported as absent, which it was
    // before 0.63.
    // A request that names the container representation of a name addressed
    // without a trailing solidus is asking for the other form, and is
    // directed to it rather than refused, where the name denotes one
    // (5.3.7). The correction applies to the representation the client
    // named and not to the form of the path, so a client that named the
    // data object representation is served it.
    if (hasContainer() && kindsRanked(req.headers.accept as string | undefined)
      .some((r) => r.kind === "container")) {
      return "container";
    }
    throw notAcceptable(
      "the Accept header field %j names no representation this object has; it is returned as %s",
      (req.headers.accept as string | undefined) ?? "", foundIsQueue ? MT_QUEUE : MT_OBJECT);
  }

  private async sendQueue(req: IncomingMessage, res: ServerResponse, pv: View,
    node: Node, ns: string, name: string, sel: Selection, head: boolean,
    who: Principal): Promise<void> {
    const accept = req.headers.accept as string | undefined;
    // A client asks for the values outside the representation by
    // naming multipart/mixed in the Accept header field.
    const multipart = accept !== undefined && /multipart\/mixed/i.test(accept);
    if (!multipart && !acceptable(accept, MT_QUEUE)) {
      throw notAcceptableFor(accept, MT_QUEUE, ns);
    }
    this.demand(node, who, M.READ_METADATA, false, `reading ${ns}`);
    const rep = this.queueRep(node, ns, name, pv, who, sel);
    // A queue value selection is not a field selection: it selects the
    // values returned rather than the fields of the representation, so
    // it does not by itself make the representation partial.
    const fields = sel.fields.filter((f) => f !== "values");
    // The four arrays describe the same values, hold the same number
    // of entries, and the entry at a position of each describes the
    // value at that position. A partial representation carrying one
    // of them alone would not meet that requirement, so selecting the
    // value returns the three that describe it. See Y5.
    if (fields.includes("value")) {
      for (const f of ["queueValues", "mimetype", "valuetransferencoding",
        "valuerange"]) {
        if (!fields.includes(f)) fields.push(f);
      }
    }
    const partial = fields.length === 0
      ? rep
      : Object.fromEntries(Object.entries(rep).filter(([k]) => fields.includes(k)));
    this.store.countAccess(node);
    if (multipart) {
      // The values are transported outside the representation, so the
      // value field is not present in it, and each value is a part.
      const values = (rep.value ?? []) as unknown[];
      const encodings = (rep.valuetransferencoding ?? []) as string[];
      const mimetypes = (rep.mimetype ?? []) as string[];
      delete partial.value;
      const parts = values.map((v, i) => ({
        mimetype: mimetypes[i] ?? "application/octet-stream",
        vte: encodings[i] ?? "utf-8",
        body: encodings[i] === "base64"
          ? Buffer.from(String(v), "base64")
          : Buffer.from(encodings[i] === "json" ? JSON.stringify(v) : String(v), "utf8"),
      }));
      this.readEvent(node, ns, who);
      return this.sendMultipart(res, MT_QUEUE, partial, parts, head);
    }
    this.readEvent(node, ns, who);
    return this.send(res, 200, MT_QUEUE, partial, {}, head);
  }

  /**
   * A read of a data object, taken atomically against a write of it: the
   * representation and the bytes it describes are read while the object's
   * lock is held, so that a reader sees the whole state before a write or
   * the whole state after it, and never a mixture of the two
   * (weedmi OPER-014). An object of another layer has no lock of this
   * store, and is read as before.
   */
  /**
   * The representations of a data object's value: the item that reports them, the
   * default in effect, and the octets of that default where it is not the one
   * held.
   *
   * Reports into `rep.metadata` where a metadata field is being returned, and
   * returns the default representation where deriving one was necessary — so the
   * caller serves the octets of the representation whose cdmi_size it reported.
   *
   * The value is read and transcoded on each read, which is the deployment's
   * decision and has a cost worth naming: reporting the item needs the length of
   * every representation, and a length is only known by encoding. A single
   * operation derives each at most once, through the cache it carries. A value
   * larger than the cap below has one representation, because decoding it would
   * cost four octets of memory for every octet of picture.
   */
  private async defaultRepresentation(ref: ObjRef, m: ObjectView,
    rep: Record<string, unknown>, prefixes: string[] = []): Promise<Representation | undefined> {
    if (!VALUE_REPRESENTATIONS || m.size === 0 || m.size > REPRESENTABLE_LIMIT) return undefined;
    const metadata = rep.metadata as Record<string, unknown> | undefined;
    // The signature first, from the leading octets alone. Reading the whole value
    // in order to discover that it is not a picture would make every read of every
    // data object read its value twice, whatever the value is — which is what the
    // first draft of this did, and what made the test suite crawl.
    let head: Buffer;
    try {
      head = await readValueOf(this.store, ref, 0, 8);
    } catch {
      return undefined;
    }
    // Not a raster value, so this server holds one representation of it and
    // reports neither representation item: a value that is not an image is not an
    // error, and nothing further of it is read. See onlyOneRepresentation below
    // for why the items are withheld.
    if (heldType(head) === undefined) return undefined;
    let value: Buffer;
    try {
      value = await readValueOf(this.store, ref);
    } catch {
      return undefined;
    }
    const types = typesOf(value);
    // A value whose signature is a raster and whose content raster.ts declines — a
    // progressive JPEG, an interlaced or sixteen-bit PNG — has the one
    // representation it is held in.
    if (types.length < 2) return undefined;
    const algorithm = ref.kind === "store"
      ? VALUE_HASHES[String(this.effectiveDataSystemItem(ref.node, "cdmi_value_hash") ?? "").toUpperCase()]
      : undefined;
    const derivations = new Derivations();
    // "A CDMI client specifies the representation it prefers in the
    // cdmi_representation_default data system metadata item", which is data system
    // metadata and so is inherited from the container objects above the object.
    const wanted = ref.kind === "store"
      ? this.effectiveDataSystemItem(ref.node, "cdmi_representation_default")
      : undefined;
    const which = defaultType(value, wanted);
    if (which === undefined) return undefined;
    const selected = derivations.of(value, which, algorithm);
    if (selected === undefined) return undefined;
    if (metadata !== undefined) {
      // The object's own items are those of the default representation:
      // "consequently the value of an item such as cdmi_size reported for an
      // object follows the default representation, and changes where the default
      // representation changes".
      if (metadata.cdmi_size !== undefined) metadata.cdmi_size = String(selected.size);
      if (metadata.cdmi_hash !== undefined && selected.hash !== undefined) {
        metadata.cdmi_hash = selected.hash;
      }
      // A metadata selection selects by prefix, and these two items are selected
      // as any other are: adding them after metadataRep has applied the selection
      // would return an item a CDMI client did not ask for, which is what
      // "a selection returns only the fields named" means.
      if (selects(prefixes, "cdmi_representation_default_provided")) {
        metadata.cdmi_representation_default_provided = which;
      }
      if (selects(prefixes, "cdmi_representations")) {
        metadata.cdmi_representations = membersOf(value, metadata, algorithm, derivations);
      }
    }
    // The media type reported is that of the representation returned.
    if (rep.mimetype !== undefined) rep.mimetype = which;
    return selected.type === heldType(value) ? undefined : selected;
  }

  /**
   * The cdmi_representation_default item that applies to an object, resolved
   * through the inheritance that data system metadata has. Read by the HTTP
   * export, which negotiates among representations and needs the default.
   */
  defaultRepresentationItem(ref: ObjRef): unknown {
    return ref.kind === "store"
      ? this.effectiveDataSystemItem(ref.node, "cdmi_representation_default")
      : undefined;
  }

  /**
   * Why an object with one representation of its value reports neither
   * cdmi_representations nor cdmi_representation_default_provided.
   *
   * Until 0.112 it reported both: a cdmi_representations item with one member,
   * named for the media type of the value and **empty** — every item such a member
   * would carry is the object's own, the member holding "only what is particular
   * to the representation" — and a cdmi_representation_default_provided item
   * naming that same media type, which is the "mimetype" field of the same
   * representation. So every read of every data object carried two items that told
   * a CDMI client what it already had, one of them an object whose only member was
   * empty.
   *
   * They are now reported only where this server holds more than one
   * representation, which is where they say something: which forms are available,
   * and which of them a read returns.
   *
   * This diverges from revision 365, which requires both wherever the
   * cdmi_representations capability is available — and that capability belongs to a
   * capability object, so it cannot be withheld for the objects that have one
   * representation, which in most deployments is all of them. **ECR-232A** asks
   * for the condition to be the useful one.
   */

  private async sendData(req: IncomingMessage, res: ServerResponse, pv: View, ref: ObjRef,
    layer: Layer, name: string, sel: Selection, status: number, head: boolean,
    who: Principal, extra: Record<string, string> = {}): Promise<void> {
    if (ref.kind === "store") {
      const node = ref.node;
      return this.store.locked(node, () =>
        this.sendDataLocked(req, res, pv, ref, layer, name, sel, status, head, who, extra));
    }
    return this.sendDataLocked(req, res, pv, ref, layer, name, sel, status, head, who, extra);
  }

  /**
   * "cdmi_read: An object has been read." A CDMI server "shall enqueue a
   * notification for each event ... that is of a type the queue object
   * specifies", and this is the one type of the eleven that seedmi defined,
   * accepted in a queue's event list, and never raised — so a notification
   * queue asking for reads was created, reported Current, and enqueued nothing
   * for ever. Reported by cvwm against 0.104.
   *
   * Raised where the read answered 200: a create answers 201 with a
   * representation through the same path, and a create is not a read. A HEAD
   * raises it as a GET does, the binding's own table of operations calling HEAD
   * "Read, headers only" and the access control clause requiring the same
   * permission for it.
   *
   * The draft says no more than "an object has been read", so it is raised for
   * a data object, a container object, a queue object and a domain object
   * alike, those being the objects a scope specification can match. A
   * capability object raises none: it is generated by the CDMI server, carries
   * no metadata and matches no scope.
   */
  private readEvent(node: Node | undefined, ns: string, who: Principal, status = 200): void {
    if (status !== 200 || node === undefined) return;
    this.event("cdmi_read", node, ns, who);
  }

  /**
   * Puts the value of a data object into a representation, honouring a selected
   * range, and answers the request itself where several ranges were selected and
   * travel as a multipart body. Returns true where it has answered, so that the
   * caller does not send the representation a second time.
   *
   * Two senders read a data object and must report a value identically: the
   * ordinary one, and the one that serves an object within a snapshot, which
   * walks the store because "no layer of an import applies within a snapshot".
   * Until 0.125 the snapshot sender had the single-range case written out again
   * and refused several ranges, since the multipart body was built here alone.
   * One responder is what keeps the two from differing on gaps, on the encoding
   * of a range that divides a character, and on what a range beyond the value
   * does, none of which is obvious enough to write twice.
   */
  private async sendValueField(a: {
    req: IncomingMessage;
    res: ServerResponse;
    rep: Record<string, unknown>;
    sel: Selection;
    head: boolean;
    mayValue: boolean;
    valueSize: number;
    /** The value transfer encoding the object holds the value in. */
    vte: string | undefined;
    /**
     * The end of the first contiguous run of written octets, where this server
     * records where the gaps in the value are, and undefined where it does not
     * or where the octets come from a derived representation that has none.
     */
    contiguous: number | undefined;
    /**
     * The runs of written octets this server records for the value, empty where
     * it records none. The plain valuerange selection and the value layout
     * selection are both answered from these without reading the value.
     */
    ranges: [number, number][];
    readAt: (first: number, length: number) => Promise<Buffer>;
  }): Promise<boolean> {
    let content: Buffer = Buffer.alloc(0);
    // "?valuerange returns the extent of the value without transferring it":
    // the range is reported from what the object records, with no value read
    // (weedmi OPER-030).
    if (a.mayValue && !a.sel.value && a.sel.everyField !== true && a.sel.any &&
      a.sel.fields.includes("valuerange")) {
      // Where the value has a gap, the range is the one up to the first gap,
      // as a read of the whole value reports.
      a.rep.valuerange = a.valueSize === 0
        ? ""
        : a.ranges.length > 0
          ? `${a.ranges[0]![0]}-${a.ranges[0]![1]}`
          : `0-${a.valueSize - 1}`;
    }
    const withheld = !a.sel.value && a.sel.everyField !== true;
    if (!a.mayValue || withheld) {
      // The value field is excluded, and so is the range that describes it.
    } else if (a.sel.valueRanges.length > 1) {
      // "Several value ranges are returned as multipart/mixed: the
      // representation first, one Content-Range part per range" (8.2.6).
      // A client that does not accept multipart/mixed cannot be answered
      // with several ranges in one representation (weedmi BHTP-016).
      const accept = a.req.headers.accept as string | undefined;
      if (accept === undefined || !/multipart\/mixed/i.test(accept)) {
        throw notAcceptable("several value ranges are transported as parts of a multipart/mixed " +
          "body, which this request does not accept");
      }
      const parts: { mimetype: string; vte: string; body: Buffer; range: string }[] = [];
      for (const [first, last] of a.sel.valueRanges) {
        if (first >= a.valueSize) {
          throw new Condition(416, "range-not-satisfiable", "The range is not satisfiable.",
            `the value is ${a.valueSize} bytes`);
        }
        const bytes = await a.readAt(first, last - first + 1);
        parts.push({
          mimetype: String(a.rep.mimetype ?? "application/octet-stream"),
          vte: "base64",
          body: bytes,
          range: `bytes ${first}-${first + bytes.length - 1}/${a.valueSize}`,
        });
      }
      // The value travels in the parts, so the representation carries
      // neither it nor the range that describes it.
      delete a.rep.value;
      delete a.rep.valuerange;
      await this.sendMultipart(a.res, MT_OBJECT, applySelection(a.rep, a.sel), parts, a.head);
      return true;
    } else if (a.sel.valueRanges.length === 1) {
      const [first, last] = a.sel.valueRanges[0];
      if (first >= a.valueSize) {
        throw new Condition(416, "range-not-satisfiable", "The range is not satisfiable.",
          `the value is ${a.valueSize} bytes`);
      }
      // "A range addresses octets of the value as it is stored, and may divide
      // a character of a utf-8 value or a token of a json value. Where a CDMI
      // server returns a range of the value, this field reports the encoding
      // of the octets it returns, determined by those octets" (revision 365,
      // closing ECR-159A). Before 0.85 a range was always base 64.
      //
      // One octet beyond the range is read with it, because the "utf-8" test
      // asks whether the octet following the range begins a character. It is
      // read here rather than in a second request because the value may be
      // held at another CDMI server, where a second read is a second request
      // over the network. It is not returned: what is returned is the range
      // the CDMI client asked for, a CDMI server being forbidden to adjust a
      // range so that a test succeeds.
      const wanted = last - first + 1;
      const read = await a.readAt(first, wanted + 1);
      // Fewer octets than asked for means the value ended, or a gap cut it
      // short; either way nothing follows what is returned.
      content = read.length > wanted ? read.subarray(0, wanted) : read;
      const after = read.length > wanted ? read.subarray(wanted) : undefined;
      a.rep.valuerange = `${first}-${first + content.length - 1}`;
      const encoding = rangeEncoding(a.vte, content, after);
      a.rep.valuetransferencoding = encoding;
      a.rep.value = encoding === "base64" ? content.toString("base64")
        : encoding === "utf-8" ? content.toString("utf8")
        : new Verbatim(content);
    } else {
      // "Where no range of the value has been requested, the value of the
      // data object contains a gap, and the CDMI server records where the
      // gaps in a value are, this field shall indicate the range up to the
      // first gap in the value, and the value field shall contain those bytes
      // alone. A CDMI client reads the remainder of the value by requesting
      // ranges" (revision 221). This server records where the gaps are, and
      // returned the whole value with a range describing part of it before.
      // cdmi_size reports the size, gaps included.
      // "Where no range of the value has been requested, the value of the
      // data object contains a gap, and the CDMI server records where the
      // gaps in a value are, this field shall indicate the range up to the
      // first gap in the value, and the value field shall contain those
      // bytes alone. A CDMI client reads the remainder of the value by
      // requesting ranges" (revision 221). This server records the ranges
      // written, so it knows where the gaps are and reports them exactly.
      const upto = a.contiguous ?? a.valueSize;
      content = await a.readAt(0, upto);
      const utf8 = isUTF8(content);
      a.rep.valuerange = upto === 0 ? "" : `0-${upto - 1}`;
      // Where a gap cut the value short, the range travels with it.
      if (upto < a.valueSize) a.sel.partialValue = true;
      // A value stored as a JSON object is returned as one, so that a
      // client reads back what it wrote.
      if (a.vte === "json" && utf8) {
        try {
          const parsed = JSON.parse(content.toString("utf8"));
          if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
            a.rep.valuetransferencoding = "json";
            // The octets as they were stored, which are the octets the CDMI
            // client sent: "It returns those octets when the value is read"
            // (revision 365). The parse above is the validation that they are
            // still a JSON object, and its result is not what is returned.
            a.rep.value = new Verbatim(content);
          }
        } catch {
          // No longer a JSON object; it is returned as text.
        }
      }
      if (a.rep.value === undefined) {
        // The encoding the object was given, where it still
        // describes the content: a CDMI client reads back what it
        // wrote, which is the same principle the JSON branch
        // above applies. "base64" describes any content, and
        // "utf-8" only content that is a valid UTF-8 string, so a
        // stored "utf-8" is honoured only while that holds.
        const stored = a.vte === "base64" || (a.vte === "utf-8" && utf8)
          ? a.vte
          : undefined;
        const encoding = stored ?? (utf8 ? "utf-8" : "base64");
        a.rep.valuetransferencoding = encoding;
        a.rep.value = encoding === "utf-8"
          ? content.toString("utf8")
          : content.toString("base64");
      }
    }
    // The value layout selection (revision 269): "Where this field is selected
    // with an offset ... it shall indicate the first range of the value that
    // begins at or after that offset, to which bytes have been written, and that
    // contains no gap. Where no byte at or after the offset has been written, it
    // shall contain an empty string. Where the CDMI server does not record where
    // the gaps in a value are, the range indicated extends from the offset to
    // the end of the value." It describes the layout, and is given in place of
    // the range a value selection would report.
    if (a.sel.layoutOffset !== undefined && a.mayValue) {
      a.rep.valuerange = layoutRange(
        a.ranges.length > 0 || a.valueSize === 0
          ? a.ranges
          : [[0, a.valueSize - 1]],
        a.sel.layoutOffset);
    }
    return false;
  }

  private async sendDataLocked(req: IncomingMessage, res: ServerResponse, pv: View, ref: ObjRef,
    layer: Layer, name: string, sel: Selection, status: number, head: boolean,
    who: Principal, extra: Record<string, string> = {}): Promise<void> {
    this.demandOfImportingObject(pv, ref, who, M.READ_OBJECT, `reading ${pv.ns}${name}`);
    // "A CDMI server obtains the value when the importing object is first
    // read, and thereafter as the cache_max_age field provides" (revision
    // 327, HTTP imports). The value, the mimetype and the times come from
    // what the origin server returns.
    if (ref.kind === "store") await this.refreshHttpImport(ref.node, `${pv.ns}${name}`);
    if (sel.fields.includes("children")) {
      throw invalidSelection("children", "the children selection does not apply to a data object");
    }
    if (sel.recursive) {
      throw invalidSelection("childrecursive",
        "a recursive child listing applies to a container object, and not to a data object");
    }
    if (sel.childFields.length > 0) {
      throw invalidSelection("childfields",
        "the extended child selection does not apply to a data object");
    }
    // A client asking for several ranges names multipart/mixed, in which the
    // representation and the ranges travel as parts (8.2.6), so that Accept
    // is admitted here as it is for a queue object (weedmi BHTP-016).
    const acceptsMultipart = /multipart\/mixed/i.test((req.headers.accept as string) ?? "");
    if (!acceptable(req.headers.accept as string, MT_OBJECT) && !acceptsMultipart) {
      // Where the name also denotes a container object and the request
      // admits one, the client is asking for the other representation and
      // is directed to the form that addresses it: the data object form
      // serves the data object, and the correction applies only where the
      // client named the container representation (5.3.7).
      if (ref.kind === "store" && acceptable(req.headers.accept as string, MT_CONTAINER)) {
        const m0 = this.store.meta(ref.node);
        const parent = m0.parent === null ? undefined : { id: m0.parent, isContainer: true };
        if (parent !== undefined &&
            this.store.lookupKind(parent, m0.name, "container") !== undefined) {
          return correctForm(req, res, this.base, pv.ns + name);
        }
      }
      throw notAcceptableFor(req.headers.accept as string | undefined, MT_OBJECT, pv.ns + name);
    }
    // A read is an access, and is counted. The version is not moved:
    // an access is not a change, and a client watching the change
    // attribute must not see one because somebody read the object.
    const readNode = nodeOf(ref);
    // The representation a create returns is part of the create and not a
    // read of the object, so its access count is zero in what the create
    // answers (weedmi META-006).
    if (readNode && status !== 201) this.store.countAccess(readNode);
    const m = viewOf(this.store, ref);
    // Where a bit is not granted, the field it governs is excluded; where
    // the selection asks for that field alone, the read is forbidden. An
    // object of an image layer is governed by the importing container.
    const governs = governedBy(pv);
    // A value cannot be executed without being read, so EXECUTE grants a
    // read of it where READ_OBJECT is not granted. An entry that
    // explicitly denies READ_OBJECT denies the read notwithstanding.
    const mayValue = this.may(ref, who, M.READ_OBJECT, false, governs) ||
      (this.may(ref, who, M.EXECUTE, false, governs) &&
        !this.denies(ref, who, M.READ_OBJECT, governs));
    // A user metadata item is governed by READ_METADATA; a storage
    // system or data system metadata item by READ_ATTRIBUTES.
    const mayMeta = this.may(ref, who, M.READ_METADATA, false, governs);
    const mayAttrs = this.may(ref, who, M.READ_ATTRIBUTES, false, governs);
    const mayACL = this.may(ref, who, M.READ_ACL, false, governs);
    if (!mayValue && onlySelects(sel, ["value", "valuerange"])) {
      throw forbidden("reading the value of %s requires READ_OBJECT", pv.ns + name);
    }
    if (!mayMeta && onlySelects(sel, ["metadata"])) {
      throw forbidden("reading the metadata of %s requires READ_METADATA", pv.ns + name);
    }
    // The attribute fields (the object ID, the names, the domain, the exports
    // and the rest) are governed by READ_ATTRIBUTES; a principal granted
    // nothing that reads any part of the object is refused.
    if (status === 200 && !mayAttrs && selectsOnlyAttributes(sel)) {
      throw forbidden("reading the attribute fields of %s requires READ_ATTRIBUTES", pv.ns + name);
    }
    // A read by a principal granted nothing is refused. The response to an
    // operation already performed (a create, answered 201) is not: it withholds
    // what the principal may not read, the operation having been done.
    if (status === 200 && !mayValue && !mayMeta && !mayAttrs && !mayACL) {
      throw forbidden("reading %s requires READ_OBJECT, READ_METADATA or READ_ATTRIBUTES", pv.ns + name);
    }
    const rep: Record<string, unknown> = { objectType: MT_OBJECT };
    // An object presented through an image import has no object ID.
    if (!layer.hideIDs && m.objectID !== undefined) rep.objectID = m.objectID;
    rep.objectName = name;
    rep.parentURI = pv.ns;
    const parentID = nodeOf(pv.held) === undefined
      ? undefined
      : viewOf(this.store, { kind: "store", node: nodeOf(pv.held)! }).objectID;
    if (!pv.objLayer.hideIDs && parentID !== undefined) rep.parentID = parentID;
    rep.capabilitiesURI = layer.imported
      ? "/cdmi_capabilities/imported_dataobject/"
      : "/cdmi_capabilities/dataobject/";
    // Every object other than a capability object is owned by a
    // domain, which the domainURI field addresses.
    if (ref.kind === "store") rep.domainURI = this.domainURI(ref.node);
    rep.completionStatus = ref.kind === "store" && this.store.meta(ref.node).partial
      ? "Processing"
      : "Complete";
    if (mayMeta || mayAttrs) {
      rep.metadata = metadataRep({ ...m, acl: this.reportedAcl(m, layer, governs) },
        true, sel.metaPrefixes, mayACL, mayAttrs, mayMeta,
        who.privileges.includes("domain_kms_admin"),
        this.lockCovering(pv.ns + name)?.lock,
        ref.kind === "store"
          ? this.effectiveDataSystemItem(ref.node, "cdmi_sanitization_method")
          : undefined,
        ref.kind === "store" ? this.inheritedDataSystem(ref.node) : undefined);
    }
    if (ref.kind === "store") rep.rel = relRep(this.store.meta(ref.node));
    // The items that thread the chain of versions.
    if (mayMeta && ref.kind === "store") {
      Object.assign(rep.metadata as Record<string, unknown>,
        versionMetadata(this.store, ref.node));
    }
    if (layer.via.length > 0) rep.importsProvided = layer.via;
    // A data object carries an imports field where a value import presents
    // its value: "An HTTP import ... is placed on a data object, as an entry
    // of the imports field of that object" (revision 327). Only a container
    // object's and a queue object's were reported before 0.78, so an entry
    // stored on a data object could not be read back.
    if (ref.kind === "store") {
      const held = (this.store.meta(ref.node).imports ?? []) as unknown as ImportEntry[];
      if (held.length > 0) {
        const at = cdmiTime();
        rep.imports = held.map((e) => {
          const problems = (e as { last_problems?: unknown[] }).last_problems ?? [];
          return {
            ...this.readableEntry(ref.node, e as unknown as Record<string, unknown>),
            active: problems.length === 0 ? "true" : "false",
            last_problems: problems,
            state_determined_time: at,
          };
        });
      }
    }
    const ep = this.exports?.providedFor(pv.ns + name) ?? [];
    // "Where the object is accessible through no export, the value shall be
    // an empty JSON array": this server omitted the field before 0.67
    // (weedmi REPR-001, EXPT-002).
    rep.exportsProvided = ep;
    rep.mimetype = m.mimetype || guessMimetype(name, m.vte || "base64");
    // "This field is a property of the object and not of one operation", so
    // it is reported whether or not the value is returned; a read of the
    // value below replaces it with the encoding that read uses (weedmi
    // REPR-001).
    rep.valuetransferencoding = m.vte || "utf-8";

    // "* ... selects every field of the representation, the value field
    // included" (revision 297), which a data object's read returns only where
    // it is selected.
    if (mayValue && (sel.value || sel.everyField === true || !sel.any)) {
      // A read that would return the value is restricted where an active
      // image import is writing the file system it holds.
      this.checkNotAnActiveSource(pv.ns + name, "read");
    }
    // "The representation does not contain the value field unless the field
    // selection names it, that field being returned only where it is
    // requested, and the valuerange field is therefore not returned unless the
    // value field is" (revision 211, of the response to a create). A read
    // without a selection returns the value as before.
    // "The representation does not contain the value field unless the field
    // selection names it" (revision 211, of the response to a create).
    // Revision 221 extends that to every read: the value field "shall be
    // returned only where it is explicitly selected". That extension is not
    // yet made; NOTES-on-conformance.md records what it needs.
    // "Where no selection is supplied, a CDMI server shall return a complete
    // representation of the target object ... with the following exceptions:
    // the value field of a data object shall be returned only where it is
    // explicitly selected" (revision 221). The valuerange field describes the
    // value field, so it is not returned where the value is not.
    // The default representation of the value, where this object has more than
    // one and the default is not the one held. "A CDMI client that reads an object
    // through a protocol binding receives the default representation", so the
    // value, its length and its media type all come from it: reporting the
    // object's own cdmi_size beside another representation's octets would be an
    // object contradicting itself.
    const derivedDefault = await this.defaultRepresentation(ref, m, rep, sel.metaPrefixes);
    /** The octets of the value as the selected representation holds them. */
    const readAt = async (first: number, length: number): Promise<Buffer> =>
      (derivedDefault === undefined
        ? await readValueOf(this.store, ref, first, length)
        : derivedDefault.bytes.subarray(first, first + length));
    /** The length of the value as the selected representation holds it. */
    const valueSize = derivedDefault === undefined ? m.size : derivedDefault.size;
    if (await this.sendValueField({
      req, res, rep, sel, head, mayValue, valueSize, vte: m.vte,
      contiguous: derivedDefault === undefined ? m.contiguous : undefined,
      ranges: ref.kind === "store" ? this.store.ranges(ref.node) : [],
      readAt,
    })) return;

    const tag = etagOf(m);
    const headers: Record<string, string> = { ETag: sel.any ? `W/${tag}` : tag };
    // A precondition on the absence of the object governs whether the
    // create is performed, and is answered before this. Applying it
    // again to the representation returned would answer a create that
    // succeeded with not modified.
    if (status === 200 && conditionalRead(req, tag)) {
      res.writeHead(304, headers);
      return res.end();
    }
    // "return the field in a complete representation of that object"
    // (Extension fields), and to a field selection naming it. An extension
    // field describes the object as its attributes do, and is governed as they
    // are.
    if (mayAttrs) Object.assign(rep, m.extensions ?? {});
    if (!mayAttrs) withholdAttributes(rep);
    this.relativeToIdBase(req, rep);
    this.readEvent(nodeOf(ref), `${pv.ns}${name}`, who, status);
    this.send(res, status, MT_OBJECT, applySelection(rep, sel), { ...headers, ...extra }, head);
  }

  private async sendContainer(req: IncomingMessage, res: ServerResponse, cv: View,
    pv: View | undefined, name: string, sel: Selection, status: number,
    head: boolean, who: Principal, extra: Record<string, string> = {}): Promise<void> {
    if (sel.value) {
      throw invalidSelection("value", "the value selection does not apply to a container object");
    }
    if (!acceptable(req.headers.accept as string, MT_CONTAINER)) {
      throw notAcceptableFor(req.headers.accept as string | undefined, MT_CONTAINER, cv.ns);
    }
    const listed = nodeOf(cv.held);
    if (listed) this.store.countAccess(listed);
    const heldRef: ObjRef = refOfDir(cv.held);
    const m = viewOf(this.store, heldRef);
    const governs = governedBy(cv);
    const mayList = this.may(heldRef, who, M.LIST_CONTAINER, true, governs);
    const mayMeta = this.may(heldRef, who, M.READ_METADATA, true, governs);
    const mayAttrs = this.may(heldRef, who, M.READ_ATTRIBUTES, true, governs);
    const mayACL = this.may(heldRef, who, M.READ_ACL, true, governs);
    if (!mayList && onlySelects(sel, ["children", "childrenrange"])) {
      throw forbidden("listing the children of %s requires LIST_CONTAINER", cv.ns);
    }
    if (!mayMeta && onlySelects(sel, ["metadata"])) {
      throw forbidden("reading the metadata of %s requires READ_METADATA", cv.ns);
    }
    if (status === 200 && !mayAttrs && selectsOnlyAttributes(sel)) {
      throw forbidden("reading the attribute fields of %s requires READ_ATTRIBUTES", cv.ns);
    }
    // As for a data object: a read granted nothing is refused, and the
    // response to an operation already performed withholds instead.
    if (status === 200 && !mayList && !mayMeta && !mayAttrs && !mayACL) {
      throw forbidden("reading %s requires LIST_CONTAINER, READ_METADATA or READ_ATTRIBUTES", cv.ns);
    }
    const rep: Record<string, unknown> = { objectType: MT_CONTAINER };
    // The snapshots of the container object, where it has any. The
    // reserved container object that holds them is created with the
    // first snapshot and is not presented before then.
    // "Each value shall be the namespace path of a snapshot of the container
    // object" (revision 245). It was relative to the container before 0.46.
    if (listed) {
      const home = this.store.snapshotHome(listed);
      rep.snapshots = home
        ? this.store.children(home).map((c) => `${cv.ns}${SNAPSHOTS}/${c.name}/`)
        : [];
    }
    if (!cv.objLayer.hideIDs && m.objectID !== undefined) rep.objectID = m.objectID;
    if (pv === undefined) {
      rep.objectName = "/";
      rep.parentURI = "";
    } else {
      rep.objectName = `${name}/`;
      rep.parentURI = pv.ns;
      const parent = nodeOf(pv.held);
      if (!pv.objLayer.hideIDs && parent !== undefined) {
        rep.parentID = viewOf(this.store, { kind: "store", node: parent }).objectID;
      }
    }
    rep.capabilitiesURI = cv.objLayer.imported
      ? "/cdmi_capabilities/imported_container/"
      : "/cdmi_capabilities/container/";
    if (listed) rep.domainURI = this.domainURI(listed);
    rep.completionStatus = "Complete";
    if (mayMeta || mayAttrs) {
      rep.metadata = metadataRep({ ...m, acl: this.reportedAcl(m, cv.objLayer, governs) },
        false, sel.metaPrefixes, mayACL, mayAttrs, mayMeta,
        who.privileges.includes("domain_kms_admin"),
        this.lockCovering((pv?.ns ?? "/") + name)?.lock,
        cv.held.kind === "store"
          ? this.effectiveDataSystemItem(cv.held.node, "cdmi_sanitization_method")
          : undefined,
        cv.held.kind === "store" ? this.inheritedDataSystem(cv.held.node) : undefined);
    }
    const heldNode = nodeOf(cv.held);
    if (heldNode !== undefined) rep.rel = relRep(this.store.meta(heldNode));
    if (cv.importing) {
      const holding = nodeOf(cv.held);
      rep.imports = holding === undefined ? importsRep(cv)
        : importsRep(cv).map((e) => this.readableEntry(holding, e as Record<string, unknown>));
    }
    if (this.exports?.configured(cv.held.kind === "store"
      ? cv.held.node
      : this.store.root())) {
      const holder = nodeOf(cv.held);
      if (holder) rep.exports = this.readableExports(holder, await this.exports.report(holder));
    }
    const provided = importsProvidedFor(cv);
    if (provided.length > 0) rep.importsProvided = provided;
    const ep = this.exports?.providedFor(cv.ns) ?? [];
    // "Where the object is accessible through no export, the value shall be
    // an empty JSON array": this server omitted the field before 0.67
    // (weedmi REPR-001, EXPT-002).
    rep.exportsProvided = ep;

    // The extension fields, governed as the attribute fields are.
    if (mayAttrs) Object.assign(rep, m.extensions ?? {});
    // Without READ_ATTRIBUTES, only the children and the metadata remain.
    if (!mayAttrs) withholdAttributes(rep);
    if (!mayList) {
      // The children and childrenrange fields are excluded together.
      delete rep.children;
      delete rep.childrenrange;
      this.relativeToIdBase(req, rep);
      this.readEvent(nodeOf(cv.held), `${pv?.ns ?? "/"}${name}`, who, status);
      this.send(res, status, MT_CONTAINER, applySelection(rep, sel), extra, head);
      return;
    }
    const kids = await listChildren(this.store, cv);
    // The reserved children of the root container object. Both are
    // mandatory where the capability that defines them is offered, and
    // neither is an object of the store.
    //
    // A CDMI export makes the container object it presents the root container
    // object of the base URI it establishes — "at that base URI the container
    // object is the root container object" — so read through that base URI it
    // has them too: "the root container object has the reserved children shown
    // in [the reserved children table]. A CDMI server shall report each
    // reserved child that it supports in the children field of the root
    // container object", and cdmi_capabilities/ is mandatory there.
    //
    // The exports model says the opposite — "an object whose name is reserved
    // by this document shall not be presented through an export ... shall not
    // present the reserved children of the root container object" — and that
    // sentence was written for an export to another protocol, before the CDMI
    // export existed. Following it left a CDMI client at such a base URI unable
    // to perform a step this document requires of it: "to determine whether an
    // operation on an existing object is supported, a CDMI client shall read
    // the capability object addressed by the capabilitiesURI field of that
    // object", and that field holds a namespace path resolved against the base
    // URI it read the object through — a path that addressed nothing. ECR-222A
    // asks for the rule to be narrowed to a non-CDMI export; this server
    // presents them, for that reason, from 0.100.
    //
    // Not for an object ID URI, which is the base URI this document excepts
    // from being established by a CDMI export, and whose client reached it
    // through a base URI that presents them already.
    if (pv === undefined || this.noted(req).exportBase === cv.ns) {
      kids.unshift(...RESERVED_CHILDREN);
    }
    // The container of a container object's snapshots is a reserved child
    // which, "where present, is listed in the children field in the same
    // manner as any other child". It was not listed before 0.46, so a CDMI
    // client that browses by listing could not reach the snapshots.
    if (listed !== undefined && this.store.snapshotHome(listed) !== undefined &&
        !kids.includes(`${SNAPSHOTS}/`)) {
      kids.push(`${SNAPSHOTS}/`);
    }
    let lo = 0;
    let hi = kids.length - 1;
    if (sel.childRange) {
      [lo, hi] = sel.childRange;
      if (hi > kids.length - 1) hi = kids.length - 1;
    }
    if (kids.length === 0 || lo > hi) {
      rep.childrenrange = "";
      rep.children = [];
    } else {
      rep.childrenrange = `${lo}-${hi}`;
      const page = kids.slice(lo, hi + 1);
      const listed: unknown[] = [];
      for (const k of page) {
        const row: unknown = sel.childFields.length > 0
          ? await this.childFieldValues(cv, k, sel, who)
          : k;
        listed.push(row);
        // Where a recursive listing is requested, an array reports the children
        // of each child that is a container object, in the same form: after that
        // child where no fields are named, and within the child's own array
        // where they are (nestChildren).
        // "The depth of a recursive child listing is the number of levels of
        // container object it descends: a depth of one returns the children
        // of the container object addressed and no further level." This
        // server descended one level too far before 0.67, so a depth of one
        // returned a child container's children as well (weedmi OPER-040).
        const below = (sel.childDepth ?? Infinity) - 1;
        if (sel.recursive && k.endsWith("/") && below >= 1) {
          const under = await this.recursiveChildren(cv, k.slice(0, -1), sel, who, below);
          if (!nestChildren(row, under, sel)) listed.push(under);
        }
      }
      rep.children = listed;
    }
    this.relativeToIdBase(req, rep);
    this.readEvent(nodeOf(cv.held), `${pv?.ns ?? "/"}${name}`, who, status);
    this.send(res, status, MT_CONTAINER, applySelection(rep, sel), extra, head);
  }

  /**
   * Creates a data object within a directory of an imported file system.
   * Such an object has no object ID and no access control list of its
   * own, so nothing is stored for it beyond what the file system holds.
   */
  private async createInImage(req: IncomingMessage, res: ServerResponse, pv: View,
    image: { fs: FAT; cluster: number }, ns: string, name: string,
    body: Record<string, unknown>, who: Principal): Promise<void> {
    if (!storableName(name)) {
      throw invalidField("objectName",
        "%j cannot be the name of an object of a FAT file system", name);
    }
    if ("metadata" in body) {
      throw invalidField("metadata",
        "an object of an imported file system holds no metadata of this document");
    }
    const content = decodeSuppliedValue(body);
    const entry = await image.fs.createFile(image.cluster, name);
    if (content.length > 0) await image.fs.setFile(image.cluster, entry, content);
    await flushImage(this.store, image.fs);
    const created = await image.fs.find(image.cluster, name);
    if (!created) throw serverError("the object just created cannot be found");
    const layer: Layer = {
      dir: { kind: "image", fs: image.fs, cluster: image.cluster },
      rank: pv.writeRank ?? [0], via: [], imported: true, hideIDs: true, readOnly: false,
    };
    return this.sendData(req, res, pv,
      { kind: "image", fs: image.fs, dir: image.cluster, entry: created },
      layer, name, emptySelection(), 201, false, who);
  }

  /** Replaces the value of an object held by an imported file system. */
  private async updateInImage(res: ServerResponse, ref: ObjRef & { kind: "image" },
    body: Record<string, unknown>, sel: Selection): Promise<void> {
    if ("metadata" in body || "mimetype" in body) {
      throw invalidField("metadata",
        "an object of an imported file system holds no metadata of this document");
    }
    if ("value" in body) {
      const content = decodeSuppliedValue(body);
      if (sel.valueRanges.length === 1) {
        await ref.fs.writeFile(ref.dir, ref.entry, sel.valueRanges[0][0], content);
      } else {
        await ref.fs.setFile(ref.dir, ref.entry, content);
      }
      await flushImage(this.store, ref.fs);
    }
    res.writeHead(204);
    res.end();
  }

  /**
   * Copies an object that no layer of the store holds into the write
   * target: one presented by an imported file system, or by another
   * CDMI server. The value and the fields that carry across are taken
   * as the layer presents them; what does not carry across, such as the
   * object ID of another server, is left behind.
   */
  private async copyUpForeign(ref: ObjRef, target: Node, name: string, who: Principal,
    body: Record<string, unknown>, form: string): Promise<Node> {
    const v = viewOf(this.store, ref);
    const node = this.store.createData(target, name, {
      mimetype: v.mimetype ?? "",
      vte: v.vte ?? "",
      metadata: form === "complete" ? {} : { ...v.userMetadata },
      owner: who.name === ANONYMOUS.name ? "" : who.name,
      acl: aclForNewObject(suppliedACL(body), this.store.meta(target).acl, false),
    });
    if (form !== "complete" && !("value" in body)) {
      // The value carries across, since the update does not replace it.
      const data = await readValueOf(this.store, ref);
      if (data.length > 0) await this.store.setValue(node, data);
    }
    return node;
  }

  /**
   * The namespace path of the object an address by object ID names.
   * Where the form of the address does not match the object, the other
   * form is reported rather than the object, as it is for a namespace
   * path in the wrong form.
   */
  /**
   * Where a path by object ID names a container object without the trailing
   * solidus, the path it should have been; otherwise undefined.
   */
  private objectIDContainerForm(ns: string): string | undefined {
    if (ns.endsWith("/")) return undefined;
    const id = ns.slice(OBJECTID_TREE.length);
    if (id === "" || id.includes("/")) return undefined;
    try {
      const node = this.store.byObjectID(id);
      return node.isContainer && !this.store.meta(node).frozen ? `${OBJECTID_TREE}${id}/` : undefined;
    } catch {
      return undefined;
    }
  }

  /**
   * The namespace path an object ID address names, and the part of the
   * store's namespace that address is a base URI for.
   *
   * "An object ID URI ... is itself a base URI for the representation
   * returned for it. The object it addresses is the root container object
   * of that base URI where it is a container object, and every namespace
   * path of that representation, and of a representation of an object
   * addressed beneath it, is relative to that object ID URI" (revision
   * 327). So a path may follow the identifier, and what is read beneath it
   * reports names relative to it; this server refused such a path before
   * 0.71.
   */
  /**
   * Makes the namespace paths of a representation relative to the object ID
   * URI the request used, where it used one: "every namespace path of that
   * representation ... is relative to that object ID URI", so a client
   * reading "/cdmi_objectid/<id>/test/doc.txt" receives a parentURI of
   * "/test/" (revision 327).
   */
  private relativeToIdBase(req: IncomingMessage, rep: Record<string, unknown>): void {
    const base = this.noted(req).idBase;
    if (base === undefined) return;
    const parent = rep.parentURI;
    if (typeof parent !== "string") return;
    const within = parent.startsWith(base) ? `/${parent.slice(base.length)}` : parent;
    // "The root container object of any base URI: the parentURI field shall
    // contain an empty string and the parentID field shall not be returned.
    // ... It reports that the root container object has no parent within
    // the base URI through which it was read" (revision 347, which replaced
    // a table of three cases with this one). The object of the base URI
    // itself is that root, whatever it is named in the namespace, and its
    // objectName is "/" there.
    if (`${base}` === `${parent}${String(rep.objectName ?? "")}`) {
      rep.parentURI = "";
      delete rep.parentID;
      rep.objectName = "/";
      return;
    }
    rep.parentURI = within;
  }

  private pathOfObjectID(ns: string, note?: (base: string) => void): string {
    const whole = ns.slice(OBJECTID_TREE.length);
    const cut = whole.indexOf("/");
    const beneath = cut < 0 ? "" : whole.slice(cut + 1);
    const rest = cut < 0 ? whole : whole.slice(0, cut + 1);
    const trailing = rest.endsWith("/");
    const id = trailing ? rest.slice(0, -1) : rest;
    if (id === "") {
      throw notFound(ns);
    }
    if (beneath !== "") {
      // The identifier names the root container object of the base URI,
      // and the remainder is resolved beneath it.
      const root = this.store.byObjectID(id, "container");
      const under = `${this.store.pathOf(root)}${beneath}`;
      note?.(this.store.pathOf(root));
      return under;
    }
    if (id.length > 255) {
      // An object ID is at most 255 octets in either form, so a longer
      // one identifies nothing this server could have assigned.
      throw malformed("an object ID shall not be longer than 255 octets");
    }
    let node;
    try {
      // Where the identifier denotes more than one representation, the form
      // of the address chooses among them as the form of a namespace path
      // does, and a client naming the other representation is directed to
      // the other form by the conflict below. Which representation an
      // identifier reaches where the client names none is ECR-158A; this
      // server answers with the data object representation, as the order of
      // byObjectID gives it.
      node = this.store.byObjectID(id, trailing ? "container" : undefined);
    } catch {
      try {
        node = this.store.byObjectID(id);
      } catch {
        throw notFound(ns);
      }
    }
    // An object within a snapshot is addressed by object ID where the
    // snapshot pinned a version: the entry is that version, which has
    // an identifier of its own. An entry that had to be copied, because
    // versioning was not enabled for the object, has no identifier and
    // is addressed by namespace path alone.
    if (this.store.meta(node).frozen) throw notFound(ns);
    // A data object named with a trailing solidus is not redirected to the
    // form without it: "a CDMI path that ends with a solidus and denotes no
    // container object ... shall not be redirected", and names no object.
    if (!node.isContainer && trailing) throw notFound(ns);
    if (node.isContainer !== trailing) {
      const right = OBJECTID_TREE + id + (node.isContainer ? "/" : "");
      throw conflict(
        "%s names a %s, which is addressed at %s", ns,
        node.isContainer ? "container object" : "data object", right)
        .with("seedmi_other_form", right);
    }
    const path = this.store.pathOf(node);
    // "An object ID URI ... is itself a base URI for the representation
    // returned for it. The object it addresses is the root container object
    // of that base URI where it is a container object" (revision 327). So a
    // container object read through its object ID URI reports itself as the
    // root of that base URI, whatever it is named in the namespace: the
    // parentURI field is empty, the parentID field is absent, and the
    // objectName field is "/". This server reported the namespace name and
    // parent before 0.82, which is the representation of the object read
    // through the other base URI and not through this one.
    if (node.isContainer) note?.(path);
    return path;
  }

  /**
   * The container object through which objects are addressed by object
   * ID. Its children are not enumerated: every object that has an
   * object ID is addressable within it, and a listing of them is a
   * listing of the whole store by another route.
   */
  private sendObjectIdTree(res: ServerResponse, sel: Selection, head: boolean): void {
    const root = this.store.meta(this.store.root());
    const rep: Record<string, unknown> = {
      objectType: MT_CONTAINER,
      objectName: "cdmi_objectid/",
      parentURI: "/",
      parentID: root.objectID,
      capabilitiesURI: "/cdmi_capabilities/container/",
      completionStatus: "Complete",
      metadata: {},
      childrenrange: "",
      children: [],
    };
    this.send(res, 200, MT_CONTAINER, applySelection(rep, sel), {}, head);
  }

  /**
   * The destination where a namespace path addresses a reference. A
   * reference is not a container object, so a path in the form of one
   * names no reference.
   */
  private async referenceAt(r: Resolver, ns: string): Promise<string | undefined> {
    if (ns === "/" || ns.endsWith("/")) return undefined;
    const cut = ns.lastIndexOf("/");
    let pv: View;
    try {
      pv = await r.view(ns.slice(0, cut + 1));
    } catch {
      return undefined;
    }
    if (pv.unavail) return undefined;
    return referenceIn(this.store, pv, ns.slice(cut + 1));
  }

  /**
   * Creates a reference: a name that redirects to a URI. No other
   * field may be supplied, nothing is stored, and the destination is
   * not verified and cannot be changed afterwards.
   */
  private async createReference(res: ServerResponse, r: Resolver, ns: string,
    body: Record<string, unknown>, who: Principal): Promise<void> {
    const destination = body.reference;
    if (typeof destination !== "string" || destination === "") {
      throw invalidField("reference",
        "the reference field contains the URI the reference redirects to");
    }
    // The destination is of a scheme this CDMI server serves, or one
    // it is configured to permit. A server that stored a destination
    // of any scheme would redirect whoever reads the reference to a
    // URI chosen by whichever principal created it, on the authority
    // of this server.
    if (!destination.startsWith("/")) {
      const scheme = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(destination)?.[1];
      if (scheme === undefined) {
        // "a relative-path reference, which begins with neither "/" nor a
        // scheme" (revision 327). It names nothing outside this CDMI
        // server, so no scheme rule applies to it and only its form is
        // checked: a destination that is not a URI reference has no
        // resolution.
        if (!isUriReference(destination)) {
          throw invalidField("reference",
            "the destination of a reference is a URI reference, and %j is not one", destination);
        }
      } else if (!REFERENCE_SCHEMES.includes(scheme.toLowerCase())) {
        throw invalidField("reference",
          "%j is not a scheme this CDMI server serves or is configured to permit as " +
          "the destination of a reference; it serves %s",
          scheme, REFERENCE_SCHEMES.join(", "));
      }
    }
    const others = Object.keys(body).filter((k) => k !== "reference");
    if (others.length > 0) {
      throw invalidField(`/${others[0]}`,
        "no field other than the reference field is supplied where a reference is " +
        "created, and %j was", others[0]);
    }
    if (ns.endsWith("/")) {
      throw invalidField("objectName",
        "a reference is not a container object, and its name has no trailing solidus");
    }
    const cut = ns.lastIndexOf("/");
    const name = ns.slice(cut + 1);
    if (!presentable(name)) {
      throw invalidField("objectName", "%j is a reserved name", name);
    }
    const pv = await r.view(ns.slice(0, cut + 1));
    if (pv.unavail) throw pv.unavail;
    if (pv.writeRank === undefined) {
      throw pv.writeUnavail ?? forbidden("%s cannot be created: %s", ns, pv.writeWhy);
    }
    const target = await ensureWriteTarget(this.store, pv);
    this.demand(target, who, M.ADD_OBJECT, true, `creating ${ns}`);
    if (this.store.tryLookup(target, name)) {
      throw conflict("%s is already in use", ns);
    }
    // A reference is not an object, and an operation upon it is
    // nonetheless authorised: it takes the list an object created here
    // would inherit, so that what governs the name is what governs
    // everything else in the container.
    const made = this.store.createReference(target, name, destination, {
      owner: who.name === ANONYMOUS.name ? "" : who.name,
      acl: aclForNewObject(undefined, this.store.meta(target).acl, false),
    });
    // A reference has been created. It has no representation, so
    // the notification carries the name and the path alone.
    this.event("cdmi_reference", undefined, ns, who);
    void made;
    // A reference has no representation, so nothing is returned but
    // the status and the place it was created.
    res.writeHead(201, { Location: this.base.slice(0, -1) + ns, "Content-Length": "0" });
    res.end();
  }

  /**
   * A copy or a move. The value of the field addresses the source
   * object; a source held by another CDMI server is not implemented,
   * and reports the capability that would be needed.
   */
  /**
   * Copies or moves the representations of the source that the operation
   * itself did not carry. "A name may denote more than one representation of
   * one object": a copy of the object copies each of them, and a move moves
   * each of them, so that what arrives is the object rather than a part of
   * it (weedmi OPER-042).
   */
  private async carryOtherRepresentations(r: Resolver, ns: string,
    body: Record<string, unknown>, who: Principal, move: boolean): Promise<void> {
    const from = String(body[move ? "move" : "copy"] ?? "");
    if (from === "" || from.startsWith(OBJECTID_TREE)) return;
    const bare = from.replace(/\/$/, "");
    const target = ns.replace(/\/$/, "");
    const carried = ns.endsWith("/") ? "container" : "data";
    for (const kind of ["data", "container"] as const) {
      if (kind === carried) continue;
      const source = kind === "container" ? `${bare}/` : bare;
      const into = kind === "container" ? `${target}/` : target;
      // The other representation is copied only where the source has one.
      // Attempting it and catching the failure was not equivalent: the
      // attempt reaches the target before it discovers the source has no
      // such representation, and a restore in place clears the target's
      // children on the way. That is what made a restore lose all but the
      // first child, intermittently, from 0.69 (weedmi snapshot restore).
      const sourceNode = this.nodeAt(source);
      if (sourceNode === undefined ||
        sourceNode.isContainer !== (kind === "container")) {
        continue;
      }
      try {
        // No response is written: the operation already answered for the
        // representation the request named.
        await this.copyOrMove(undefined, r, into,
          { [move ? "move" : "copy"]: source }, who, move,
          kind === "container" ? MT_CONTAINER : MT_OBJECT);
      } catch (e) {
        // The source has no representation of this kind, which is the
        // ordinary case: a name usually denotes one.
        if (e instanceof Condition && (e.status === 404 || e.status === 409)) continue;
        throw e;
      }
    }
  }

  private async copyOrMove(res: ServerResponse | undefined, r: Resolver, ns: string,
    body: Record<string, unknown>, who: Principal, move: boolean,
    requested = ""): Promise<void> {
    const field = move ? "move" : "copy";
    const from = body[field];
    if (typeof from !== "string" || from === "") {
      throw invalidField(field, "the %s field addresses the source object", field);
    }
    // A move from the object ID tree gives an object without a path a
    // path, leaving it accessible by both.
    // A selection may qualify the source; it is not part of the path
    // and is stripped before the source is resolved.
    const sourceQuery = from.includes("?") ? from.slice(from.indexOf("?") + 1) : "";
    const fromPath = from.includes("?") ? from.slice(0, from.indexOf("?")) : from;
    const local = fromPath.startsWith("/") ? fromPath : localImportPath(fromPath);
    if (local === undefined) {
      // The source is held by another CDMI server. The object is read
      // through the protocol binding of that server and created here;
      // a move deletes it there once it is created here, so that a
      // failure at either end leaves the object in one place and not
      // in neither.
      if (res === undefined) throw notFound(ns);
      return this.copyFromRemote(res, r, ns, fromPath, body, who, move);
    }
    // A move to the object ID tree removes the path of the object,
    // leaving it accessible by object ID alone.
    if (move && ns === OBJECTID_TREE) {
      const source = await this.sourceOf(r, local, who);
      this.demand(source.node, who, M.DELETE, source.node.isContainer,
        `moving ${local}`, undefined, true);
      const id = this.store.meta(source.node).objectID;
      this.store.rename(source.node, this.store.root(),
        `${ASSIGNED}${randomUUID()}`);
      if (res === undefined) return;
      res.writeHead(204, {
        Location: `${this.base}cdmi_objectid/${id}`,
        "Content-Length": "0",
      });
      return res.end();
    }

    // The form of the source and of the target agree: an object is
    // copied as an object of its own type. An address by object ID
    // carries the form of the object it names, so the comparison holds
    // for it too.
    const byID = local.startsWith(OBJECTID_TREE);
    if (!byID && local.endsWith("/") !== ns.endsWith("/")) {
      throw conflict(
        "the type of the object created by a %s operation is the type of the source, " +
        "and %j and %j are of different types", field, from, ns);
    }
    if (ns === "/" || local === "/") {
      throw forbidden("the root container object is neither a source nor a target of a %s",
        field);
    }
    if (move && (ns + "/").startsWith(local.endsWith("/") ? local : local + "/")) {
      throw conflict("%j is within %j, and cannot be moved into it", ns, from);
    }

    const source = await this.sourceOf(r, local, who);
    // "A copy or a move shall not place on an object an access control list
    // containing a mask bit or a flag the CDMI server does not support; the CDMI
    // server shall reject the operation, and shall report the invalid field
    // condition" (revision 269). A list stored by this server before 0.61 may name
    // an undefined bit in hexadecimal; the source and everything beneath it is
    // checked, a container being copied or moved whole.
    this.checkPlaceable(source.node, field);
    const sourceIsQueue = this.store.meta(source.node).isQueue;
    // The type of the created object is the type of the source, except
    // that a data object may be created from a queue object: the
    // values it holds are concatenated to form the value.
    const namesData = (v: unknown) =>
      v === MT_OBJECT || v === `${MT_OBJECT}+json`;
    const intoData = sourceIsQueue &&
      (namesData(body.objectType) || namesData(requested));
    if (sourceIsQueue && move && intoData) {
      throw invalidField("objectType",
        "a move preserves the object, and a data object is created from a queue " +
        "object by a copy");
    }
    const cut = ns.replace(/\/$/, "").lastIndexOf("/");
    const name = ns.replace(/\/$/, "").slice(cut + 1);
    const pv = await r.view(ns.slice(0, cut + 1));
    if (pv.unavail) throw pv.unavail;
    if (pv.writeRank === undefined) {
      throw pv.writeUnavail ?? forbidden("%s cannot be created: %s", ns, pv.writeWhy);
    }
    const target = await ensureWriteTarget(this.store, pv);

    // An object already at the target is replaced and not merged with. A
    // name denotes one object, so the representation of the kind being
    // created is the one replaced, and a representation of another kind at
    // that name is a representation of the same object rather than an
    // object in the way (5.3.7).
    const existing = this.store.lookupKind(target, name,
      source.node.isContainer ? "container" : (sourceIsQueue && !intoData ? "queue" : "data")) ??
      (this.store.lookupKind(target, name, "container") === undefined &&
        this.store.lookupKind(target, name, "data") === undefined
        ? this.store.tryLookup(target, name)
        : undefined);
    if (existing) {
      const heldIsQueue = this.store.meta(existing).isQueue;
      const madeIsQueue = sourceIsQueue && !intoData;
      if (existing.isContainer !== source.node.isContainer ||
        heldIsQueue !== madeIsQueue) {
        throw conflict("an object of another type is at %j", ns);
      }
      this.demand(existing, who, M.WRITE_OBJECT, existing.isContainer,
        `replacing ${ns}`);
    } else {
      this.demand(target, who, M.ADD_OBJECT, true, `creating ${ns}`);
    }

    if (move) {
      // The object ID is preserved: the object at the target is the
      // same object, addressed at a different namespace path. A move
      // therefore does not delete an object under retention or hold,
      // and the object remains under it; only a move that would take
      // it off this server would be a conflict, and this server moves
      // within itself alone.
      this.demand(source.node, who, M.DELETE, source.node.isContainer,
        `moving ${local}`, undefined, true);
      // A move is a create at the target, where domainURI names the domain the
      // object takes, subject to cross_domain as for any create. The moved
      // object changes domain as by any other means, so a move needs what such
      // a change needs (domain_kms_admin for an object carrying
      // cdmi_dac_certificate), and is refused before anything is renamed. The
      // field was ignored on a move before 0.47.
      const movedTo = this.domainFor(body, target, who);
      if (movedTo) await this.changeDomain(source.node, movedTo, who);
      if (existing) await this.store.collect(this.store.removeTree(existing));
      this.store.rename(source.node, target, name);
      // The metadata of the source is preserved, except where the
      // client supplies a metadata field.
      if ("metadata" in body && body.metadata !== null &&
        typeof body.metadata === "object") {
        const m = this.store.meta(source.node);
        m.metadata = userMetadata(body.metadata as Record<string, unknown>);
        this.store.setMeta(source.node, m);
      }
      // An object has been renamed by a move. A move within this
      // server renames rather than copies, so the event is raised
      // here and not where a copy creates an object.
      this.event("cdmi_rename", source.node, ns, who);
      if (res === undefined) return;
      res.writeHead(existing ? 204 : 201, {
        Location: this.base.slice(0, -1) + ns,
        "Content-Length": "0",
      });
      return res.end();
    }

    if (sourceIsQueue && intoData) {
      // The values are concatenated in order from oldest to newest.
      // Where a queue value selection qualifies the source, only the
      // selected values are concatenated.
      const made = await this.concatenateQueue(target, name, source.node,
        body.metadata as Record<string, unknown> | undefined, existing,
        sourceQuery);
      void made;
      if (res === undefined) return;
      res.writeHead(existing ? 204 : 201, {
        Location: this.base.slice(0, -1) + ns,
        "Content-Length": "0",
      });
      return res.end();
    }
    const made = await this.copyInto(target, name, source.node, who,
      body.metadata as Record<string, unknown> | undefined, existing);
    // An object created by a copy, or renamed by a move. The
    // notification reports the object created rather than the
    // source it was created from.
    this.event(move ? "cdmi_rename" : "cdmi_copy", made, ns, who);
    if (res === undefined) return;
    res.writeHead(existing ? 204 : 201, {
      Location: this.base.slice(0, -1) + ns,
      "Content-Length": "0",
    });
    res.end();
  }

  /** The source object of a copy or a move, which is read in full. */
  /** Refuses a copy or move whose source, or an object beneath it, carries an entry naming an unsupported bit. */
  private checkPlaceable(node: Node, field: string): void {
    const pending: Node[] = [node];
    while (pending.length > 0) {
      const n = pending.pop()!;
      const m = this.store.meta(n);
      for (const ace of m.acl ?? []) {
        let unsupported: string | undefined;
        try {
          unsupported = unsupportedIn(parseACE(ace, n.isContainer));
        } catch {
          unsupported = "an entry that is not well formed";
        }
        if (unsupported !== undefined) {
          throw invalidField(field, "the access control list of the source names %s, which this server does not support, " +
            "and a %s shall not place such a list on an object", unsupported, field);
        }
      }
      if (n.isContainer) for (const c of this.store.children(n)) if (c.reference === undefined) pending.push(c.node);
    }
  }

  private async sourceOf(r: Resolver, ns: string, who: Principal):
    Promise<{ node: Node }> {
    // A domain object is a source of a serialization, and is
    // addressed by a path of the domain hierarchy rather than of
    // the namespace.
    if (ns.replace(/\/$/, "").startsWith(`/${DOMAINS}`)) {
      const domain = this.domainNamed(ns);
      if (domain === undefined) throw notFound(ns);
      this.demand(domain, who, M.READ_METADATA, true, `reading ${ns}`);
      return { node: domain };
    }
    // A version is a source like any other: a client promotes one by
    // copying it over the version-enabled data object. It has no
    // namespace path, so it is found by its identifier.
    if (ns.startsWith(OBJECTID_TREE)) {
      const id = ns.slice(OBJECTID_TREE.length).replace(/\/$/, "");
      let node: Node | undefined;
      try {
        node = this.store.byObjectID(id);
      } catch {
        node = this.store.byPinnedID(id);
      }
      if (!node) throw notFound(ns);
      const m = this.store.meta(node);
      const governs: Node = m.versionOf !== null
        ? { id: m.versionOf, isContainer: false }
        : node;
      this.demand(governs, who, node.isContainer ? M.LIST_CONTAINER : M.READ_OBJECT,
        node.isContainer, `reading ${ns}`);
      return { node };
    }

    // A snapshot is a source like any other, and is restored by a copy
    // addressing it. It is not presented by the layering engine, so it
    // is walked by store lookup.
    if (ns.includes(`/${SNAPSHOTS}/`)) {
      const cut = ns.indexOf(`/${SNAPSHOTS}/`);
      const ov = await r.view(ns.slice(0, cut + 1));
      if (ov.unavail) throw ov.unavail;
      const holder = nodeOf(ov.held);
      const home = holder ? this.store.snapshotHome(holder) : undefined;
      if (!home) throw notFound(ns);
      let node: Node = home;
      for (const seg of ns.slice(cut + 2 + SNAPSHOTS.length).split("/")
        .filter((x) => x !== "")) {
        const next = this.store.tryLookup(node, seg);
        if (!next) throw notFound(ns);
        node = next;
      }
      this.demand(node, who, node.isContainer ? M.LIST_CONTAINER : M.READ_OBJECT,
        node.isContainer, `reading ${ns}`);
      return { node };
    }
    const view = await r.view(ns.endsWith("/") ? ns : ns.slice(0, ns.lastIndexOf("/") + 1));
    if (view.unavail) throw view.unavail;
    let node: Node | undefined;
    if (ns.endsWith("/")) {
      node = nodeOf(view.held) ?? undefined;
    } else {
      const found = await resolveFile(this.store, view, ns.slice(ns.lastIndexOf("/") + 1));
      node = found ? nodeOf(found.ref) ?? undefined : undefined;
    }
    if (!node) throw notFound(ns);
    // The client is permitted to read the source object.
    this.demand(node, who, node.isContainer ? M.LIST_CONTAINER : M.READ_OBJECT,
      node.isContainer, `reading ${ns}`);
    this.demand(node, who, M.READ_METADATA, node.isContainer, `reading ${ns}`);
    return { node };
  }

  /**
   * Copies one object into a container, recursively where it is a
   * container object. The copy is a new object with a new object ID;
   * the imports and exports fields are not copied.
   */
  /**
   * Creates a data object whose value is the values a queue object
   * holds, concatenated in order from oldest to newest.
   */
  private async concatenateQueue(target: Node, name: string, source: Node,
    metadata: Record<string, unknown> | undefined, replacing: Node | undefined,
    query: string): Promise<Node> {
    // A queue value selection may qualify the source, in which case
    // only the selected values are concatenated.
    let values = this.store.queueValues(source);
    const q = /(?:^|&)values(?:=([^&]*))?/.exec(query);
    if (q !== null) {
      const arg = q[1] ?? "";
      if (arg === "" || /^[0-9]+$/.test(arg)) {
        values = values.slice(0, arg === "" ? 1 : Number(arg));
      } else {
        const r = parseRange(arg);
        if (!r) {
          throw invalidSelection(`values=${arg}`,
            "a queue value selection is a count or a range of designators");
        }
        values = values.filter((v) => v.designator >= r[0] && v.designator <= r[1]);
      }
    }
    const m = this.store.meta(source);
    const node = replacing ?? this.store.createData(target, name, {
      owner: this.store.meta(target).owner,
      acl: aclForNewObject(undefined, this.store.meta(target).acl, false),
      domain: this.domainOf(target).id,
    });
    const into = this.store.meta(node);
    // The value is the octets of the values, one after another.
    //
    // Where every value concatenated has the same media type the
    // created data object takes it, and where they differ it takes
    // the type of a stream of octets, the concatenation of values
    // of differing media types being of no media type this document
    // can determine.
    const types = new Set(values.map((v) => v.mimetype));
    into.mimetype = types.size === 1 ? [...types][0] : "application/octet-stream";
    // The same for the value transfer encoding: where every value
    // has the same one the created object takes it, and where they
    // differ it takes base 64, since concatenating a value encoded
    // as utf-8 with one encoded as base 64 yields octets that are
    // not a character string.
    const encodings = new Set(values.map((v) => v.vte));
    into.vte = encodings.size === 1 ? [...encodings][0] : "base64";
    into.metadata = metadata === undefined
      ? withoutRestrictions(m.metadata)
      : userMetadata(metadata);
    this.store.setMeta(node, into);
    await this.store.setValue(node, Buffer.concat(values.map((v) => v.body)));
    if (replacing === undefined) this.store.startCounts(node);
    return node;
  }

  private async copyInto(target: Node, name: string, source: Node, who: Principal,
    metadata: Record<string, unknown> | undefined, replacing?: Node): Promise<Node> {
    const m = this.store.meta(source);
    if (m.isQueue) {
      // A queue object is copied as a queue object, holding copies of
      // the values the source holds. The designators of the created
      // object begin at zero: they are unique within a queue object,
      // and the created object is another queue object.
      const node = replacing ?? this.store.createQueue(target, name, {
        owner: who.name === ANONYMOUS.name ? "" : who.name,
        acl: aclForNewObject(undefined, this.store.meta(target).acl, false),
        domain: this.domainOf(target).id,
      });
      const into = this.store.meta(node);
      into.metadata = metadata === undefined
        ? withoutRestrictions(m.metadata)
        : userMetadata(metadata);
      // An extension field is a field of the representation the copy sources.
      into.extensions = m.extensions;
      this.store.setMeta(node, into);
      if (replacing !== undefined) {
        const held = this.store.queueBounds(node);
        if (held.count > 0) this.store.dequeue(node, held.lowest, held.highest);
      }
      this.store.enqueue(node, this.store.queueValues(source).map((v) => ({
        mimetype: v.mimetype,
        vte: v.vte,
        body: v.body,
      })));
      if (replacing === undefined) this.store.startCounts(node);
      return node;
    }
    const supplied = metadata === undefined
      ? undefined
      : userMetadata(metadata as Record<string, unknown>);
    if (replacing) {
      // The object at the target keeps its object ID, and what it held
      // is replaced rather than merged with.
      const into = this.store.meta(replacing);
      into.mimetype = m.mimetype;
      into.vte = m.vte;
      // Retention and hold are not applied to an object created by
      // copying one that is under either.
      into.metadata = supplied ?? withoutRestrictions(m.metadata);
      into.rel = m.rel;
      into.extensions = m.extensions;
      this.store.setMeta(replacing, into);
      if (!source.isContainer) {
        await this.store.shareValue(replacing, source);
        return replacing;
      }
      // The objects the source holds are listed before anything is
      // deleted: a restore in place addresses a snapshot held within
      // the container being replaced, and deleting first would take
      // the source away.
      const from = this.store.children(source);
      for (const child of this.store.children(replacing)) {
        // A reserved child is not an object of the container in the
        // sense a copy deals with: the snapshots of the container
        // survive a restore, and a snapshot holds none of its own.
        if (reservedName(child.name)) continue;
        await this.store.collect(this.store.removeTree(child.node));
      }
      for (const child of from) {
        if (reservedName(child.name)) continue;
        await this.copyInto(replacing, child.name, child.node, who, undefined);
      }
      return replacing;
    }
    const made = source.isContainer
      ? this.store.createContainer(target, name, {
        metadata: supplied ?? withoutRestrictions(m.metadata),
        owner: who.name === ANONYMOUS.name ? "" : who.name,
        acl: aclForNewObject(undefined, this.store.meta(target).acl, true),
        rel: m.rel,
        extensions: m.extensions,
      })
      : this.store.createData(target, name, {
        mimetype: m.mimetype,
        vte: m.vte,
        metadata: supplied ?? withoutRestrictions(m.metadata),
        owner: who.name === ANONYMOUS.name ? "" : who.name,
        acl: aclForNewObject(undefined, this.store.meta(target).acl, false),
        rel: m.rel,
        extensions: m.extensions,
      });
    if (!source.isContainer) {
      // The copy reads the value file of the source rather than
      // holding a second one; a write to either makes the copy.
      await this.store.shareValue(made, source);
    } else {
      // The objects the source container object contains are copied,
      // and the objects those contain. A reserved child is not copied,
      // so a copy of a container holds none of its snapshots.
      for (const child of this.store.children(source)) {
        if (reservedName(child.name)) continue;
        await this.copyInto(made, child.name, child.node, who, undefined);
      }
    }
    this.store.startCounts(made);
    return made;
  }

  /**
   * The children of a child container object, for a recursive listing.
   * An access control list may prevent the principal from listing
   * them, in which case the container object is listed and an empty
   * array is returned for its children.
   *
   * Where the listing also names fields, each child at each level is the array
   * of the values of those fields, and the children of a child container object
   * are placed within that array rather than after it (nestChildren).
   */
  private async recursiveChildren(cv: View, name: string, sel: Selection,
    who: Principal, depth: number): Promise<unknown[]> {
    if (depth < 0) return [];
    let child: View;
    try {
      child = await new Resolver(this.store, { principal: who }).child(cv, name);
    } catch {
      return [];
    }
    if (child.unavail) return [];
    const holder = nodeOf(child.held);
    if (holder && !granted(this.store.meta(holder).acl, who, M.LIST_CONTAINER, {
      owner: this.store.meta(holder).owner,
      group: this.store.meta(holder).group,
      isContainer: true,
      isRoot: this.store.meta(holder).parent === null,
    })) {
      return [];
    }
    const out: unknown[] = [];
    for (const k of await listChildren(this.store, child)) {
      const row: unknown = sel.childFields.length > 0
        ? await this.childFieldValues(child, k, sel, who)
        : k;
      out.push(row);
      if (k.endsWith("/") && depth - 1 >= 1) {
        const under = await this.recursiveChildren(child, k.slice(0, -1), sel, who, depth - 1);
        if (!nestChildren(row, under, sel)) out.push(under);
      }
    }
    return out;
  }

  // -----------------------------------------------------------------
  // Serialization

  /** The context a serialization is performed in. */
  private serializeContext(who: Principal): SerializeContext {
    return {
      store: this.store,
      domainURI: (node) => this.domainURI(node),
      mayRead: (node) => this.may(node, who,
        node.isContainer ? M.LIST_CONTAINER : M.READ_OBJECT, node.isContainer) &&
        this.may(node, who, M.READ_METADATA, node.isContainer),
      inherited: (node) => this.inheritedMetadata(node),
    };
  }

  /**
   * The metadata an object inherits from the container objects above
   * it, which the canonical format records at the top level so that
   * what applied where the object was serialized applies where it is
   * deserialized.
   */
  private inheritedMetadata(node: Node): Record<string, unknown> {
    const chain: Record<string, unknown>[] = [];
    let m = this.store.meta(node);
    while (m.parent !== null) {
      const parent: Node = { id: m.parent, isContainer: true };
      m = this.store.meta(parent);
      chain.push(m.metadata);
    }
    const out: Record<string, unknown> = {};
    // The nearest container wins, so the chain is applied outwards in.
    for (const md of chain.reverse()) {
      for (const [k, v] of Object.entries(md)) {
        // The storage system metadata of a container object is its
        // own and is not inherited.
        if (k.startsWith("cdmi_")) continue;
        out[k] = v;
      }
    }
    return out;
  }

  /**
   * Copies an object held by another CDMI server, and moves one by
   * copying it and then deleting it there.
   *
   * The source is read through the protocol binding of that server, as
   * a remote import reads one. A container object is copied with the
   * objects it contains, as a copy within one server is.
   */
  private async copyFromRemote(res: ServerResponse, r: Resolver, ns: string,
    from: string, body: Record<string, unknown>, who: Principal,
    move: boolean): Promise<void> {
    // A source that is neither a namespace path nor a URI this server can
    // parse is a malformed request, not an internal error: this threw and
    // was answered 500 before 0.73 (weedmi REPR-F01).
    let at: URL;
    try {
      at = new URL(from);
    } catch {
      throw malformed(
        "the source %j is neither a path of this CDMI server nor a URI of another", from);
    }
    // The base URI of the other server is the part of the address
    // above the object: everything before the path of the object is
    // the base, and this server addresses the object by that path.
    const cut = from.lastIndexOf("/", from.endsWith("/") ? from.length - 2 : undefined);
    void at;
    if (cut < 0) {
      throw invalidField(move ? "move" : "copy",
        "%j does not address an object of another CDMI server", from);
    }
    // The source is read anonymously: the draft defines no means of
    // presenting a credential for a copy or move, and this server presents
    // none. Before 0.46 a credential_id field of seedmi's own named one of
    // the credentials in seedmi.toml, which any principal able to create an
    // object could have presented, with no privilege or entitlement.
    // A copy, a move or a deserialization whose source is held by another CDMI
    // server is a server-originated request (originated.ts).
    checkPermitted(from, move ? "move" : "copy");
    const src = remoteSource(from.slice(0, cut + 1), {});
    const name = from.slice(cut + 1);

    let rep;
    try {
      rep = await src.rep(name);
    } catch (err) {
      // Not a condition of the document: a remote copy is not an import,
      // which is what source-unavailable concerns. RFC 9457 about:blank.
      throw new Condition(502, "",
        "The object could not be read from the other CDMI server.", String(err))
        .with("seedmi_source", from);
    }
    const isContainer = rep.objectType === MT_CONTAINER;
    if (isContainer !== ns.endsWith("/")) {
      throw conflict(
        "the type of the object created by a %s operation is the type of the source, " +
        "and %j and %j are of different types", move ? "move" : "copy", from, ns);
    }

    const cutTarget = ns.replace(/\/$/, "").lastIndexOf("/");
    const targetName = ns.replace(/\/$/, "").slice(cutTarget + 1);
    const pv = await r.view(ns.slice(0, cutTarget + 1));
    if (pv.unavail) throw pv.unavail;
    if (pv.writeRank === undefined) {
      throw pv.writeUnavail ?? forbidden("%s cannot be created: %s", ns, pv.writeWhy);
    }
    const target = await ensureWriteTarget(this.store, pv);
    const existing = this.store.tryLookup(target, targetName);
    if (existing) {
      this.demand(existing, who, M.WRITE_OBJECT, existing.isContainer,
        `replacing ${ns}`);
    } else {
      this.demand(target, who, M.ADD_OBJECT, true, `creating ${ns}`);
    }

    await this.remoteInto(src, name, target, targetName, who,
      body.metadata as Record<string, unknown> | undefined, existing);

    if (move) {
      // The object is deleted at the other server once it exists here.
      // A move that cannot delete it leaves the object in both places
      // and says so, rather than leaving it in neither.
      try {
        await src.remove(name);
      } catch (err) {
        throw new Condition(502, "",
          "The object was copied and could not be removed from the other CDMI server.",
          `${from} is now held by both CDMI servers: ${String(err)}`)
          .with("seedmi_source", from);
      }
    }
    res.writeHead(existing ? 204 : 201, {
      Location: this.base.slice(0, -1) + ns,
      "Content-Length": "0",
    });
    return res.end();
  }

  /** Creates one object of a remote copy, and the objects it holds. */
  private async remoteInto(src: RemoteSource, path: string, target: Node,
    name: string, who: Principal, metadata: Record<string, unknown> | undefined,
    replacing?: Node): Promise<void> {
    // The complete representation, so that the extension fields of the
    // source are there to carry: a selection cannot name a field whose name
    // it does not know.
    const rep = await src.rep(path, { complete: true });
    const isContainer = rep.objectType === MT_CONTAINER;
    const supplied = metadata === undefined ? undefined : userMetadata(metadata);
    const m = {
      owner: who.name === ANONYMOUS.name ? "" : who.name,
      acl: aclForNewObject(undefined, this.store.meta(target).acl, isContainer),
      // The metadata of the source is applied, less the items a CDMI
      // server generates and the restrictions, which are not copied.
      metadata: supplied ?? withoutRestrictions(userMetadata(rep.metadata ?? {})),
      domain: this.domainOf(target).id,
      mimetype: isContainer ? "" : (rep.mimetype ?? ""),
      // "An extension field of the source object is carried to the object
      // created": a field this document does not define belongs to the
      // object and travels with a copy, as it does within one CDMI server
      // (weedmi OPER-051).
      extensions: extensionsOfRepresentation(rep),
    };
    const node = replacing ?? (isContainer
      ? this.store.createContainer(target, name, m)
      : this.store.createData(target, name, m));
    if (replacing !== undefined) {
      const into = this.store.meta(replacing);
      into.metadata = m.metadata;
      into.mimetype = m.mimetype;
      this.store.setMeta(replacing, into);
    }

    if (isContainer) {
      for (const kid of rep.children ?? []) {
        const child = kid.endsWith("/") ? kid.slice(0, -1) : kid;
        await this.remoteInto(src, path + kid, node, child, who, undefined);
      }
      if (replacing === undefined) this.store.startCounts(node);
      return;
    }
    // The value is read in ranges, as a remote import reads one.
    const parts: Buffer[] = [];
    for (let at = 0; ; at += REMOTE_CHUNK) {
      const chunk = await src.value(path, at, REMOTE_CHUNK);
      if (chunk.length === 0) break;
      parts.push(chunk);
      if (chunk.length < REMOTE_CHUNK) break;
    }
    await this.store.setValue(node, Buffer.concat(parts));
    if (replacing === undefined) this.store.startCounts(node);
  }

  /**
   * Creates a data object whose value is the serialization of an
   * existing object. The object created is a data object whatever the
   * type of the object serialized, and its media type reports that
   * type.
   */
  private async serializeInto(res: ServerResponse, r: Resolver, ns: string,
    body: Record<string, unknown>, who: Principal): Promise<void> {
    const from = body.serialize;
    if (typeof from !== "string" || from === "") {
      throw invalidField("serialize", "the serialize field addresses the object to " +
        "be serialized");
    }
    if (ns.endsWith("/")) {
      throw invalidField("objectName",
        "a serialization creates a data object, whatever the type of the object " +
        "serialized");
    }
    const source = await this.sourceOf(r, from, who);
    let doc;
    try {
      doc = await serialize(this.serializeContext(who), source.node);
    } catch (err) {
      if (err instanceof SerializeError) {
        throw forbidden("%s: %s", from, err.message);
      }
      throw err;
    }
    const text = Buffer.from(JSON.stringify(doc, null, 2) + "\n", "utf8");

    const cut = ns.lastIndexOf("/");
    const name = ns.slice(cut + 1);
    const pv = await r.view(ns.slice(0, cut + 1));
    if (pv.unavail) throw pv.unavail;
    if (pv.writeRank === undefined) {
      throw pv.writeUnavail ?? forbidden("%s cannot be created: %s", ns, pv.writeWhy);
    }
    const target = await ensureWriteTarget(this.store, pv);
    const existing = this.store.tryLookup(target, name);
    if (existing) {
      this.demand(existing, who, M.WRITE_OBJECT, false, `replacing ${ns}`);
    } else {
      this.demand(target, who, M.ADD_OBJECT, true, `creating ${ns}`);
    }
    const node = existing ?? this.store.createData(target, name, {
      owner: who.name === ANONYMOUS.name ? "" : who.name,
      acl: aclForNewObject(undefined, this.store.meta(target).acl, false),
      domain: this.domainOf(target).id,
    });
    const m = this.store.meta(node);
    m.mimetype = source.node.isContainer ? MT_CONTAINER : MT_OBJECT;
    m.vte = "utf-8";
    this.store.setMeta(node, m);
    await this.store.setValue(node, text);
    if (!existing) this.store.startCounts(node);
    res.writeHead(existing ? 204 : 201, {
      Location: this.base.slice(0, -1) + ns,
      "Content-Length": "0",
    });
    res.end();
  }

  /**
   * Creates objects from a canonical format, at the target of the
   * operation. Where the target exists it and the objects it contains
   * are replaced, and its object ID is preserved.
   */
  /**
   * The canonical format a deserialization names: carried in the
   * request, or held as the value of a data object.
   */
  private async canonicalOf(r: Resolver, body: Record<string, unknown>,
    who: Principal): Promise<Canonical> {
    let text: string;
    if ("deserializevalue" in body) {
      const v = body.deserializevalue;
      if (typeof v !== "string") {
        throw invalidField("deserializevalue",
          "the deserializevalue field carries the canonical format as a base 64 " +
          "encoded string");
      }
      text = Buffer.from(v, "base64").toString("utf8");
    } else {
      const from = body.deserialize;
      if (typeof from !== "string" || from === "") {
        throw invalidField("deserialize",
          "the deserialize field addresses a data object whose value is the " +
          "canonical format");
      }
      const source = await this.sourceOf(r, from, who);
      if (source.node.isContainer) {
        throw conflict("%s is a container object, and does not hold a canonical " +
          "format", from);
      }
      text = (await this.store.readValue(source.node)).toString("utf8");
    }
    const canonical = parseCanonical(text);
    // A domain object is created within the domain hierarchy and
    // not within the namespace, so a canonical format of one is not
    // deserialized here.
    if (canonical.objectType === MT_DOMAIN) {
      throw invalidField("deserialize",
        "the canonical format holds a domain object, which is deserialized within " +
        "the domain hierarchy and not within the namespace");
    }
    return canonical;
  }

  private async deserializeInto(res: ServerResponse, r: Resolver, ns: string,
    body: Record<string, unknown>, who: Principal, ct: string): Promise<void> {
    const doc = await this.canonicalOf(r, body, who);

    // The type of the object created is the one the canonical format reports,
    // and the client shall have asked for that type: "the type of the object
    // created or updated shall be the type reported by the objectType field of
    // the object at the top level of the canonical format, and a CDMI server
    // shall report an error where that type differs from the type supplied by
    // the CDMI client".
    //
    // Before 0.118 this was a boolean — container or not — taken from the
    // trailing solidus of the path rather than from the media type supplied, so
    // a queue object and a data object were one type to it: a data object
    // canonical format deserialized onto a queue object answered 204 and
    // established nothing, a queue canonical format onto a data object answered
    // 204 and discarded the canonical format, and a create answered 201 having
    // made an object of a type the CDMI client had not asked for.
    const held: Kind = doc.objectType === MT_CONTAINER
      ? "container"
      : (doc.objectType === CANONICAL_QUEUE ? "queue" : "data");
    if ((held === "container") !== ns.endsWith("/")) {
      throw conflict(
        "the canonical format holds %j, and the target %j is of the other type",
        doc.objectType, ns);
    }
    const asked = kindOf(ct);
    if (asked !== undefined && asked !== held) {
      throw invalidField("objectType",
        "the canonical format holds %j and the request supplies %j, and a deserialization " +
        "creates an object of the type the canonical format holds",
        doc.objectType, ct);
    }

    const cut = ns.replace(/\/$/, "").lastIndexOf("/");
    const name = ns.replace(/\/$/, "").slice(cut + 1);
    const pv = await r.view(ns.slice(0, cut + 1));
    if (pv.unavail) throw pv.unavail;
    if (pv.writeRank === undefined) {
      throw pv.writeUnavail ?? forbidden("%s cannot be created: %s", ns, pv.writeWhy);
    }
    const target = await ensureWriteTarget(this.store, pv);

    // The domain applied to every object created, where the client
    // supplies one or holds the privilege to choose.
    const supplied = this.domainFor(body, target, who);
    const parentDomain = this.domainOf(target);
    const cross = who.privileges.includes("cross_domain");
    this.checkDeserializeDomains(doc, supplied, parentDomain, cross);

    // "A name may denote more than one representation of one object. An object
    // can have a container object representation together with a data object
    // representation, or together with a queue object representation" (5.3.7),
    // so the object replaced is the one of the kind being established, and a
    // representation of another kind at that name is a representation of the
    // same object rather than an object in the way — which is what the copy and
    // move path does for the same reason. Before 0.118 this path took whatever
    // the name held and refused where its container-ness differed, so a
    // deserialization at a name that denoted the other form of one object was
    // answered with the conflict condition although the two coexist, and a
    // restore of a container object over a name that also had a data object
    // representation could not be performed at all.
    const existing = this.store.lookupKind(target, name, held);
    // "A name shall not denote both a data object representation and a queue
    // object representation. A CDMI server shall report the conflict condition
    // where an operation would establish one at a name that denotes the other."
    // That pair is the one the create paths refuse, and the deserialization
    // established it silently until 0.118: the operation answered 204 and
    // either discarded the canonical format or emptied the queue object it
    // found.
    if (existing === undefined && held !== "container") {
      const other = this.store.lookupKind(target, name, held === "queue" ? "data" : "queue");
      if (other !== undefined) {
        throw conflict(
          "%s denotes a %s object representation, and a name does not denote a data object " +
          "representation and a queue object representation at once",
          ns, held === "queue" ? "data" : "queue");
      }
    }
    if (existing) {
      this.demand(existing, who, M.WRITE_OBJECT, existing.isContainer,
        `replacing ${ns}`);
    } else {
      this.demand(target, who, M.ADD_OBJECT, true, `creating ${ns}`);
    }

    const made = await this.applyCanonical(doc, target, name, who, supplied,
      existing, body);
    void made;
    res.writeHead(existing ? 204 : 201, {
      Location: this.base.slice(0, -1) + ns,
      "Content-Length": "0",
    });
    res.end();
  }

  /**
   * Checks the domain recorded for each object of a canonical format
   * against what the principal may apply, before anything is created:
   * where the check fails no object is created.
   */
  private checkDeserializeDomains(doc: Canonical, supplied: Node | undefined,
    parentDomain: Node, cross: boolean): void {
    const parentURI = this.store.pathOf(parentDomain);
    const walk = (c: Canonical): void => {
      const recorded = typeof c.domainURI === "string" ? c.domainURI : undefined;
      if (supplied === undefined && recorded !== undefined) {
        if (cross) {
          // The domain recorded is applied, and shall address a domain
          // object of this CDMI server.
          let node;
          try {
            node = this.store.resolve(recorded);
          } catch {
            throw invalidField("domainURI",
              "the canonical format records the domain %j, which addresses no domain " +
              "object of this CDMI server", recorded);
          }
          if (!this.store.meta(node).isDomain) {
            throw invalidField("domainURI",
              "the canonical format records the domain %j, which addresses no domain " +
              "object of this CDMI server", recorded);
          }
        } else if (recorded !== parentURI) {
          throw forbidden(
            "the canonical format records the domain %j, which is not the domain of " +
            "the parent object, and the cross_domain privilege is not held", recorded);
        }
      }
      for (const child of c.children ?? []) walk(child);
    };
    walk(doc);
  }

  /** Creates one object of a canonical format, and those within it. */
  private async applyCanonical(c: Canonical, parent: Node, name: string,
    who: Principal, domain: Node | undefined, replacing: Node | undefined,
    request: Record<string, unknown>): Promise<Node> {
    // A reference in a serialization carries a destination and no object
    // type: it is created as the reference it is, "with that destination,
    // unchanged" (revision 327).
    const destination = (c as { reference?: unknown }).reference;
    if (c.objectType === undefined && typeof destination === "string") {
      return this.store.createData(parent, name.replace(/\?$/, ""), {
        reference: destination,
        owner: who.name,
        acl: aclForNewObject(undefined, this.store.meta(parent).acl, false),
      });
    }
    const isContainer = c.objectType === MT_CONTAINER;
    const isQueue = c.objectType === MT_QUEUE;
    // The metadata the format records, except where the client
    // supplies a metadata field for the object at the target.
    const supplied = replacing !== undefined || request.metadata === undefined
      ? undefined
      : userMetadata(request.metadata as Record<string, unknown>);
    // The extension fields of the format are fields of the object created, as
    // the Serialization subclause requires; before 0.52 they were made items
    // of its metadata.
    const metadata = {
      ...deserializableMetadata(c.metadata),
      ...(supplied ?? {}),
    };
    const extensions = extensionFields(c);
    const recorded = typeof c.domainURI === "string" ? c.domainURI : undefined;
    let owns = domain;
    if (owns === undefined && recorded !== undefined) {
      try {
        const node = this.store.resolve(recorded);
        if (this.store.meta(node).isDomain) owns = node;
      } catch {
        // Checked already; the domain of the parent applies.
      }
    }

    let node: Node;
    if (replacing) {
      // The object ID of the target is preserved: it is updated and
      // not created.
      const m = this.store.meta(replacing);
      m.metadata = metadata;
      m.mimetype = typeof c.mimetype === "string" ? c.mimetype : "";
      m.rel = c.rel;
      m.imports = c.imports;
      m.extensions = extensions;
      this.store.setMeta(replacing, m);
      // A deserialization that replaces an object and moves it to another
      // domain changes its domain as any other means does.
      if (owns) await this.changeDomain(replacing, owns, who);
      node = replacing;
      if (isContainer) {
        for (const child of this.store.children(node)) {
          if (reservedName(child.name)) continue;
          await this.store.collect(this.store.removeTree(child.node));
        }
      }
    } else {
      const m = {
        metadata,
        owner: who.name === ANONYMOUS.name ? "" : who.name,
        acl: aclForNewObject(undefined, this.store.meta(parent).acl, isContainer),
        rel: c.rel,
        imports: c.imports,
        extensions,
        domain: (owns ?? this.domainOf(parent)).id,
      };
      node = isContainer
        ? this.store.createContainer(parent, name, m)
        : isQueue
        ? this.store.createQueue(parent, name, m)
        : this.store.createData(parent, name, {
          ...m,
          mimetype: typeof c.mimetype === "string" ? c.mimetype : "",
        });
    }

    if (isQueue) {
      // The values the format carries are enqueued in the order they
      // are given, oldest first. The designators of the object created
      // begin at zero: a designator is unique within a queue object,
      // and this is another queue object.
      const held = this.store.queueBounds(node);
      if (held.count > 0) this.store.dequeue(node, held.lowest, held.highest);
      const values = Array.isArray(c.value) ? c.value : [];
      const types = Array.isArray(c.mimetype) ? c.mimetype : [];
      const encodings = Array.isArray(c.valuetransferencoding)
        ? c.valuetransferencoding
        : [];
      this.store.enqueue(node, values.map((v, i) => {
        const vte = String(encodings[i] ?? "utf-8");
        const body = vte === "base64"
          ? Buffer.from(String(v), "base64")
          : Buffer.from(vte === "json" ? JSON.stringify(v) : String(v), "utf8");
        return { mimetype: String(types[i] ?? "text/plain"), vte, body };
      }));
      return node;
    }

    if (isContainer) {
      for (const [i, child] of (c.children ?? []).entries()) {
        await this.applyCanonical(child, node, nameOf(child, `/children/${i}`), who,
          domain, undefined, {});
      }
      // A serialization carries every representation of one object: where
      // it holds a value beside its children, the object deserialized has a
      // data object representation too, which takes the object's identity
      // (5.3.7, ECR-160B).
      if (c.value !== undefined && !Array.isArray(c.value)) {
        const m0 = this.store.meta(node);
        const parent = m0.parent === null ? undefined : { id: m0.parent, isContainer: true };
        if (parent !== undefined && this.store.lookupKind(parent, m0.name, "data") === undefined) {
          const beside = this.store.createData(parent, m0.name, {
            owner: m0.owner, acl: m0.acl, domain: m0.domain ?? undefined,
          });
          await this.store.setValue(beside, valueOf(c));
          const bm = this.store.meta(beside);
          bm.mimetype = typeof c.mimetype === "string" ? c.mimetype : bm.mimetype;
          this.store.setMeta(beside, bm);
          this.store.startCounts(beside);
        }
      }
      this.store.startCounts(node);
      return node;
    }

    // "On deserializing such a serialization, a CDMI server shall create the
    // version-enabled data object and each version the JSON array holds":
    // the versions are the value field of the serialization, which 13.4.7
    // replaces with the array (weedmi DMGT-009). This server read them from
    // a field of its own named "versions" before 0.67, and wrote them there.
    const versions = Array.isArray(c.value)
      ? c.value as Canonical[]
      : Array.isArray(c.versions) ? c.versions as Canonical[] : undefined;
    if (versions === undefined) await this.store.setValue(node, valueOf(c));
    if (versions !== undefined) {
      for (const v of versions) {
        await this.store.setValue(node, valueOf(v));
        const m = this.store.meta(node);
        m.metadata = { ...deserializableMetadata(v.metadata), ...metadata };
        this.store.setMeta(node, m);
        this.store.createVersion(node);
      }
      // The object holds the state of the newest version.
      const newest = versions[versions.length - 1];
      if (newest) await this.store.setValue(node, valueOf(newest));
    }
    // The mirror of the container branch above: a serialization of a data
    // object that carries children carries the container object
    // representation of the same object, which is created beside it and
    // takes the object's identity (5.3.7, ECR-160B).
    if (Array.isArray(c.children)) {
      const m0 = this.store.meta(node);
      const parent = m0.parent === null ? undefined : { id: m0.parent, isContainer: true };
      if (parent !== undefined && this.store.lookupKind(parent, m0.name, "container") === undefined) {
        const beside = this.store.createContainer(parent, m0.name, {
          owner: m0.owner, acl: m0.acl, domain: m0.domain ?? undefined,
        });
        for (const [i, child] of (c.children as Canonical[]).entries()) {
          await this.applyCanonical(child, beside, nameOf(child, `/children/${i}`), who,
            domain, undefined, {});
        }
        this.store.startCounts(beside);
      }
    }
    this.store.startCounts(node);
    return node;
  }

  // -----------------------------------------------------------------
  // Domains

  /**
   * The domain that owns the object a request addresses. The object
   * may not exist — a create addresses a name that is not there yet —
   * so the nearest ancestor that does exist is used, which is the
   * object whose domain a created object would inherit.
   */
  /** The domain object at a namespace path exactly, or undefined where there is none. */
  private domainExactly(ns: string): Node | undefined {
    let node: Node = this.store.root();
    for (const seg of ns.split("/")) {
      if (seg === "") continue;
      const next = this.store.tryLookup(node, seg);
      if (next === undefined) return undefined;
      node = next;
    }
    return node.isContainer && this.store.meta(node).isDomain ? node : undefined;
  }

  /**
   * The domain within which the credentials of a request are resolved.
   *
   * It is the domain that owns the object the operation acts on, which is the
   * domain at the namespace path — except for a create with a server-assigned
   * name at "<base>/cdmi_objectid/", where "the root container object of that
   * base URI is the object the operation acts on" and that object determines
   * four things, of which this is the first: "**the domain within which the
   * credentials are resolved**, the permission the requesting principal holds,
   * the domain of the object created where the request names none, and whether
   * the cross_domain privilege is required."
   *
   * 0.101 moved the last three onto the root container object of the base URI
   * and left this one at the namespace path. For a create by object ID that
   * path is the object ID tree's, so the credentials were resolved in the root
   * domain: a privilege conferred within the domain that owns the exported
   * container object was invisible, and a principal holding cross_domain in the
   * domain the operation is supposed to be resolved in was refused for not
   * holding it (reported by cvwm against 0.101).
   *
   * It applies to the create alone. Every other operation acts on the object
   * the path names, and is resolved in the domain that owns that object,
   * whatever base URI reached it — "an object reached through a CDMI export is
   * owned by the domain that owns it within the namespace of the CDMI server".
   */
  private domainOfRequest(req: IncomingMessage, ns: string): Node {
    const base = this.noted(req).exportBase;
    const method = req.method ?? "GET";
    if (base !== undefined && method === "POST" && ns === OBJECTID_TREE) {
      const node = this.nodeAt(base);
      if (node !== undefined) return this.domainOf(node);
    }
    // An object addressed by its object ID is the object of the namespace,
    // owned by the domain that owns it there: "the credentials are resolved to
    // a principal within that domain, and the same credentials may resolve to
    // different principals, or to none, for two objects owned by different
    // domains." The path is mapped to that object's namespace path further
    // down, after this, so until 0.103 every operation beneath the object ID
    // tree was resolved at the domain of the path as written — which resolves
    // to nothing and falls back to the root domain. A principal of a domain
    // beneath the root was therefore not recognized at all when it addressed
    // its own object by identifier, and a privilege conferred within the
    // owning domain was not held.
    //
    // The address is resolved here for the domain alone, and a failure is
    // swallowed: the operation resolves it again below and reports what is
    // wrong with it, and reporting it here would change which condition is
    // reported first.
    if (ns.startsWith(OBJECTID_TREE)) {
      try {
        return this.domainAt(this.pathOfObjectID(ns));
      } catch { /* the operation reports what is wrong with the address */ }
    }
    return this.domainAt(ns);
  }

  private domainAt(ns: string): Node {
    let node: Node = this.store.root();
    for (const seg of ns.split("/")) {
      if (seg === "") continue;
      const next = this.store.tryLookup(node, seg);
      if (!next) break;
      node = next;
    }
    return this.domainOf(node);
  }

  /**
   * Whether a domain is enabled. The setting is inherited, so a domain
   * that says nothing follows the one above it.
   */
  private domainEnabled(domain: Node): boolean {
    return this.domainSettings(domain).cdmi_domain_enabled !== "false";
  }

  /**
   * The authentication methods a domain enables, where it names any.
   * A method the domain does not enable is not used to resolve
   * credentials.
   */
  private authenticationMethods(domain: Node): string[] | undefined {
    const v = this.domainSettings(domain).cdmi_authentication_methods;
    if (!Array.isArray(v)) return undefined;
    return v.filter((m): m is string => typeof m === "string")
      .map((m) => m.toLowerCase());
  }

  /**
   * The domain object that owns an object. Where the row names none,
   * the domain of the parent object applies, and the domain at the
   * root of the hierarchy where nothing above names one.
   */
  private domainOf(node: Node): Node {
    let at: Node | undefined = node;
    while (at) {
      const m: StoredMeta = this.store.meta(at);
      if (m.domain !== null) return { id: m.domain, isContainer: true };
      at = m.parent === null ? undefined : { id: m.parent, isContainer: true };
    }
    return this.store.domainRoot(true)!;
  }

  /** The namespace path of the domain object that owns an object. */
  private domainURI(node: Node): string {
    try {
      return this.store.pathOf(this.domainOf(node));
    } catch {
      return `/${DOMAINS}/`;
    }
  }

  /**
   * The domain a representation asks for, where it asks for one. A
   * value that is not a namespace path is a malformed request, and one
   * that addresses no domain object is not found; giving an object a
   * domain other than that of its parent requires the cross_domain
   * privilege.
   */
  private domainFor(body: Record<string, unknown>, parent: Node,
    who: Principal): Node | undefined {
    const v = body.domainURI;
    if (v === undefined || v === null) return undefined;
    if (typeof v !== "string" || !v.startsWith("/") || !v.endsWith("/")) {
      throw malformed("the domainURI field contains a namespace path, and %j is not",
        String(v));
    }
    let node: Node;
    try {
      node = this.store.resolve(v);
    } catch {
      throw notFound(v);
    }
    if (!this.store.meta(node).isDomain) throw notFound(v);
    if (node.id !== this.domainOf(parent).id &&
      !who.privileges.includes("cross_domain")) {
      throw forbidden(
        "giving an object a domain other than that of its parent requires the " +
        "cross_domain privilege, which %s does not hold", who.name);
    }
    return node;
  }

  /**
   * The domain, the owner and the access control list of an object being
   * created, which revision 354 ties together.
   *
   * "An access control entry shall not be inherited across a domain
   * boundary. Where the domain of the object created is not the domain of
   * the parent container object, the second rule above does not apply, and
   * a create supplying no cdmi_acl metadata item receives the default
   * access control list, which grants the owner alone."
   *
   * "A create operation shall supply the [cdmi_owner] item where the object
   * created belongs to a domain other than the domain within which the
   * credentials of the request were resolved. A CDMI server shall report
   * the invalid field condition, identifying cdmi_owner, where such a
   * create supplies no item." The reason the revision gives is that an
   * identifier is resolved within the domain that owns the object, so the
   * creating principal's identifier names no principal of the domain the
   * object created belongs to, and an object owned by no principal of its
   * own domain is owned by nobody who can be named.
   */
  /**
   * The reply to a create in the object ID tree. The object created has no
   * name a client may address, so the representation reports its object ID
   * and the object ID URI, and nothing of a namespace path.
   */
  private createdByID(res: ServerResponse, node: Node, type: string,
    isData: boolean): void {
    const id = this.store.meta(node).objectID;
    this.store.startCounts(node);
    return this.send(res, 201, type, {
      objectType: type,
      objectID: id,
      capabilitiesURI: type === MT_CONTAINER
        ? "/cdmi_capabilities/container/"
        : type === MT_QUEUE
        ? "/cdmi_capabilities/queue/"
        : "/cdmi_capabilities/dataobject/",
      completionStatus: "Complete",
      metadata: metadataRep(viewOf(this.store, { kind: "store", node }), isData, [], true),
    }, { Location: `${this.base}cdmi_objectid/${id}` }, false);
  }

  private newObjectIdentity(body: Record<string, unknown>, target: Node, who: Principal,
    isContainer: boolean): { owner: string; acl: ACE[]; domain: number } {
    const asked = this.domainFor(body, target, who);
    const parentDomain = this.domainOf(target);
    const domain = asked ?? parentDomain;
    const crosses = domain.id !== parentDomain.id;
    const supplied = (body.metadata ?? {}) as Record<string, unknown>;
    const owner = typeof supplied.cdmi_owner === "string" ? supplied.cdmi_owner : undefined;
    // The domain within which the credentials were resolved is the domain
    // that owns the object the request was made upon, which for a create
    // is the parent container object.
    if (domain.id !== parentDomain.id && owner === undefined) {
      throw invalidField("metadata/cdmi_owner",
        "an object created in a domain other than the one within which the credentials of " +
        "this request were resolved states its owner, an identifier being resolved within " +
        "the domain that owns the object");
    }
    return {
      owner: owner ?? (who.name === ANONYMOUS.name ? "" : who.name),
      // Across a domain boundary nothing is inherited: the entries of the
      // parent name identifiers of another domain, which name a different
      // principal there, or none.
      acl: aclForNewObject(suppliedACL(body),
        crosses ? null : this.store.meta(target).acl, isContainer),
      domain: domain.id,
    };
  }

  /**
   * A request within the domain hierarchy. A domain object is read,
   * created, updated and deleted by the operations that apply to a
   * container object, and its representation holds the common fields
   * alone.
   */
  private async domainRequest(req: IncomingMessage, res: ServerResponse, ns: string,
    sel: Selection, who: Principal, method: string): Promise<void> {
    if (ns === `/${DOMAINS}`) return correctForm(req, res, this.base, ns);
    if (!ns.endsWith("/")) {
      // Everything within the domain hierarchy is a domain object, and a
      // domain object is addressed with a trailing solidus: one named
      // without it is directed to the form with it, where it exists.
      const root = this.store.domainRoot();
      let at: Node | undefined = root;
      for (const seg of ns.slice(DOMAINS.length + 2).split("/")) {
        at = at === undefined ? undefined : this.store.tryLookup(at, seg);
      }
      if (at !== undefined && this.store.meta(at).isDomain) return correctForm(req, res, this.base, ns);
      throw notFound(ns);
    }
    const segs = ns.split("/").filter((x) => x !== "").slice(1);
    const root = this.store.domainRoot(true)!;
    let node: Node = root;
    for (const [i, seg] of segs.entries()) {
      const next = this.store.tryLookup(node, seg);
      if (!next) {
        // The last segment may name a domain object to create.
        if (i === segs.length - 1 && (method === "PUT" || method === "PATCH")) {
          return this.createDomain(req, res, node, seg, ns, who);
        }
        throw notFound(ns);
      }
      node = next;
    }

    switch (method) {
      case "GET":
      case "HEAD":
        return await this.sendDomain(req, res, node, ns, sel, who, method === "HEAD");
      case "PUT":
      case "PATCH":
        return this.updateDomain(req, res, node, ns, sel, who, method);
      case "DELETE":
        return this.deleteDomain(res, node, root, ns, who);
      default:
        throw new Condition(405, "", "Method Not Allowed",
          "a domain object takes GET, HEAD, PUT, PATCH and DELETE");
    }
  }

  /** The representation of a domain object. */
  private async sendDomain(req: IncomingMessage, res: ServerResponse, node: Node, ns: string,
    sel: Selection, who: Principal, head: boolean): Promise<void> {
    this.demand(node, who, M.LIST_CONTAINER, true, `reading ${ns}`);
    const m = this.store.meta(node);
    const cut = ns.replace(/\/$/, "").lastIndexOf("/");
    const kids = this.store.children(node).map((c) => `${c.name}/`);
    const rep: Record<string, unknown> = {
      objectType: MT_DOMAIN,
      objectID: m.objectID,
      rel: relRep(m),
      objectName: ns.replace(/\/$/, "").slice(cut + 1) + "/",
      parentURI: ns === `/${DOMAINS}/` ? "/" : ns.slice(0, cut + 1),
      parentID: m.parent === null
        ? undefined
        : this.store.meta({ id: m.parent, isContainer: true }).objectID,
      // The domainURI field of a domain object addresses that domain
      // object.
      domainURI: ns,
      capabilitiesURI: "/cdmi_capabilities/domain/",
      completionStatus: "Complete",
      // A domain object inherits from its parent the settings that are
      // not specified for it.
      // A domain's own read reports cdmi_domain_kms as metadataRep does,
      // without what a key management server offering no client registration
      // does not report. It reported it whole before 0.48.
      //
      // The owner, the group and the access control list of the domain object
      // travel with them, as they do in every other representation. They are
      // the object's own and not settings of the domain, so they are taken
      // from the object rather than from the walk that inherits a setting from
      // the domain above. Until 0.105 none of the three was reported at all,
      // and a CDMI client that read a domain object and wrote it back could
      // not carry its list with it — nor see the list that governed every
      // operation it made against that domain.
      // The cdmi_domain_userinfo item describes the requesting principal as
      // this domain resolves it (ECR-226A), which is why every domain object
      // representation is uncacheable: see the response headers below.
      metadata: domainMetadataRep({
        ...withReportedKms(this.domainSettings(node), who.privileges.includes("domain_kms_admin")),
        ...(m.owner === undefined || m.owner === "" ? {} : { cdmi_owner: m.owner }),
        ...(m.group === undefined || m.group === "" ? {} : { cdmi_group: m.group }),
        // "for reading the access control list, READ_ACL": withheld from a
        // principal the list does not permit to read it, as it is elsewhere.
        ...(m.acl === undefined || m.acl === null || !this.may(node, who, M.READ_ACL, true)
          ? {}
          : { cdmi_acl: m.acl }),
        [USERINFO]: await this.userinfoItem(req, who, node),
      }, sel.metaPrefixes),
      childrenrange: kids.length ? `0-${kids.length - 1}` : "",
      children: kids,
      // The extension fields stored with it (Extension fields).
      ...(m.extensions ?? {}),
    };
    // A domain object representation carries the description of the requesting
    // principal, so it is held for no one and varies by the credential that
    // produced it. Until 0.106 the description was a reserved child and these
    // three were on that child alone; the representation that now carries it
    // needs them, or an intermediary serves one principal's description to
    // another.
    this.readEvent(node, ns, who);
    this.send(res, 200, MT_DOMAIN, applySelection(rep, sel), {
      "Cache-Control": "private, no-store",
      Vary: "Authorization",
    }, head);
  }

  /**
   * Writes the discovery bootstrap onto the root domain object, where the
   * configuration gives one and the object carries none (ECR-224A).
   *
   * A deployment turning discovery on in one place gets the whole flow without
   * a separate client step; and an item a client has since set is left exactly
   * as it is, so a restart does not undo a change made through the protocol.
   * Returns whether anything was written, for the line the server prints.
   */
  publishDiscovery(item: Record<string, unknown>): boolean {
    const root = this.store.domainRoot(true)!;
    const m = this.store.meta(root);
    const held = m.metadata as Record<string, unknown>;
    if (held.cdmi_domain_doh !== undefined) return false;
    this.store.setMeta(root, { ...m, metadata: { ...held, cdmi_domain_doh: item } } as never);
    return true;
  }

  /**
   * The access control list reported for an object, which is not always the one
   * that governs it.
   *
   * "The access control lists reported for the object shall be those the import
   * source reports, mapped as the subclause defining the import type specifies,
   * where the import is in delegated identity mode and the import source
   * provides access control information the CDMI server can map. Where it is
   * not, or where the import is in service identity mode, the access control
   * lists of the importing object shall apply."
   *
   * So for a delegated import the source's list is reported, and the source
   * enforces it; for a service import, and for every file system import, the
   * importing object's list is reported and this server enforces it. Until
   * 0.106 an object presented through an import reported no list at all — the
   * view dropped the source's because it governs nothing here, and nothing put
   * the importing object's in its place — so a CDMI client could not see what
   * governed an imported object by any means.
   *
   * For a merged container object the list is that of "the container object
   * held by the uppermost holder of its name", which is the layer the view
   * already resolved: where the write target holds it, that object's list is
   * reported, which is the one a write will be judged against.
   */
  private reportedAcl(m: ObjectView, layer: { imported: boolean; via: Provided[] },
    governs: Node | undefined): ACE[] | null | undefined {
    if (!layer.imported) return m.acl;
    // The innermost import is the one that presents the object.
    const via = layer.via[0];
    if (via?.delegated === true && m.acl !== undefined && m.acl !== null) return m.acl;
    if (governs === undefined) return undefined;
    return this.store.meta(governs).acl;
  }

  /**
   * The settings of a domain object, with those it does not specify
   * taken from its parent domain object.
   */
  private domainSettings(node: Node): Record<string, unknown> {
    const chain: StoredMeta[] = [];
    let at: Node | undefined = node;
    while (at) {
      const m: StoredMeta = this.store.meta(at);
      chain.push(m);
      at = m.parent !== null && m.isDomain
        ? { id: m.parent, isContainer: true }
        : undefined;
      if (at && !this.store.meta(at).isDomain) at = undefined;
    }
    const out: Record<string, unknown> = {};
    // The nearest setting wins, so the chain is applied from the
    // farthest ancestor inwards.
    for (const m of chain.reverse()) Object.assign(out, m.metadata);
    return out;
  }

  /**
   * The value of a data system metadata item that applies to an object,
   * which is the item the object itself carries or, where it carries none,
   * the one the nearest container object above it carries. "Data system
   * metadata is inherited by the objects a container holds, and the nearest
   * setting applies" (weedmi META-012): a CDMI client sets an item once on a
   * container rather than on every object beneath it.
   *
   * The namespace is walked, and not the domain hierarchy, which
   * domainSettings walks for the items of a domain object.
   */
  /**
   * The data system metadata items an object inherits from the container
   * objects above it, nearest first, excluding those it carries itself.
   *
   * "A data system metadata item applies to the object on which it is set
   * and to the objects that object contains, however deeply ... the item set
   * on the object applies. Inheritance is therefore resolved from the object
   * outwards, and the nearest setting takes precedence."
   *
   * Storage system metadata, provided items and user metadata do not
   * participate, and neither does cdmi_assignedsize, which Annex D says is
   * "not inherited by the objects a container object contains".
   */
  inheritedDataSystem(node: Node): Record<string, unknown> {
    const own = (this.store.meta(node).metadata ?? {}) as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    let at: Node | undefined = node.isContainer
      ? (this.store.meta(node).parent === null
        ? undefined
        : { id: this.store.meta(node).parent!, isContainer: true })
      : { id: this.store.meta(node).parent!, isContainer: true };
    for (let depth = 0; at !== undefined && depth < 256; depth += 1) {
      const m: StoredMeta = this.store.meta(at);
      for (const [k, v] of Object.entries((m.metadata ?? {}) as Record<string, unknown>)) {
        if (!INHERITED_METADATA.includes(k)) continue;
        // The nearest setting takes precedence, and the object's own
        // overrides every one of them.
        if (k in own || k in out) continue;
        out[k] = v;
      }
      at = m.parent === null ? undefined : { id: m.parent, isContainer: true };
    }
    return out;
  }

  effectiveDataSystemItem(node: Node, item: string): string | undefined {
    let at: Node | undefined = node;
    // A store is not deep, and this is read on a delete and on a read of the
    // provided item, so the walk is made rather than a value cached: a
    // cached one would go stale when a container above was updated.
    for (let depth = 0; at !== undefined && depth < 256; depth += 1) {
      const m: StoredMeta = this.store.meta(at);
      const v = (m.metadata as Record<string, unknown> | undefined)?.[item];
      if (typeof v === "string" && v !== "") return v;
      at = m.parent === null ? undefined : { id: m.parent, isContainer: true };
    }
    return undefined;
  }

  /**
   * Checks the service-level items of a create or an update: each numeric item is
   * a positive number, the geographic placement holds identifiers of ISO 3166, and
   * the placement that applies after inheritance permits somewhere this CDMI
   * server stores objects.
   *
   * The placement is evaluated after inheritance because a placement set on a
   * container object governs what may be created within it: an object created in a
   * container whose placement excludes every region this server has would be
   * stored where that placement forbids, so the create is refused with the
   * forbidden condition, as the item requires.
   *
   * @param own the metadata the object will carry, merged for a merge update.
   * @param parent the container object above it, from which the rest is inherited.
   */
  private checkServiceLevelOf(supplied: Record<string, unknown>,
    own: Record<string, unknown>, parent: Node | undefined): void {
    let inherited: Record<string, unknown> = {};
    if (parent !== undefined) {
      try {
        const pm = (this.store.meta(parent).metadata ?? {}) as Record<string, unknown>;
        inherited = { ...this.inheritedDataSystem(parent), ...pm };
      } catch {
        inherited = {};
      }
    }
    checkServiceLevel(supplied, { ...inherited, ...own },
      serviceLevelAchieved().regions ?? []);
  }

  private async createDomain(req: IncomingMessage, res: ServerResponse, parent: Node,
    name: string, ns: string, who: Principal): Promise<void> {
    if (!presentable(name)) throw invalidField("objectName", "%j is reserved", name);
    this.demand(parent, who, M.ADD_SUBCONTAINER, true, `creating ${ns}`);
    const body = await this.domainBody(req);
    // Every field classified before anything is created (fields.ts): a domain
    // object takes extension fields as every object other than a capability
    // object does. It ignored them before 0.53.
    const extensions = bodyExtensions(body, "domain");
    // A domain object is created by copying or by moving an
    // existing one, or by deserializing a canonical format, as a
    // container object is.
    for (const [field, move] of [["copy", false], ["move", true]] as
      [string, boolean][]) {
      if (typeof body[field] !== "string") continue;
      return await this.copyDomain(res, parent, name, ns,
        String(body[field]), move, body, who);
    }
    if (typeof body.deserialize === "string") {
      return await this.deserializeDomain(res, parent, name, ns,
        body.deserialize, who, false);
    }
    if (typeof body.deserializevalue === "string") {
      return await this.deserializeDomainValue(res, parent, name, ns,
        body.deserializevalue, who, false);
    }
    const supplied = domainMetadata(body);
    checkReassignPrivilege(supplied, who);
    checkDomainKmsPrivilege(supplied, who);
    checkDomainAuth(supplied, who, this.base, this.keyManagement.length > 0);
    checkKmsOffered(supplied, this.keyManagement);
    // A scope the domain declares is claimed before the item is stored.
    await claimScopesOf(this.keyManagement, this.store, supplied);
    // The graph relationships supplied with the create. The field applies to
    // every representation other than that of a capability object, and a domain
    // object neither stored nor validated it until 0.95.
    const newRel: StoredMeta = { rel: undefined } as StoredMeta;
    applyRel(newRel, body, (f) => f in body, "replace");
    const node = this.store.createDomain(parent, name, {
      metadata: userMetadata(supplied),
      owner: who.name === ANONYMOUS.name ? "" : who.name,
      acl: aclForNewObject(suppliedACL(body), this.store.meta(parent).acl, true),
      extensions: mergedExtensions(undefined, extensions, true),
      ...(newRel.rel === undefined ? {} : { rel: newRel.rel }),
    });
    this.store.setDomain(node, node);
    res.writeHead(201, {
      "Content-Type": MT_DOMAIN,
      Location: this.base.slice(0, -1) + ns,
      "Content-Length": "0",
    });
    res.end();
  }

  private async updateDomain(req: IncomingMessage, res: ServerResponse, node: Node,
    ns: string, sel: Selection, who: Principal, method: string): Promise<void> {
    this.demand(node, who, M.WRITE_METADATA, true, `updating ${ns}`);
    const body = await this.domainBody(req);
    const extensions = bodyExtensions(body, "domain");
    const merging = method === "PATCH";
    // The three forms, and the two refusals that go with them, as every other
    // object type has had them since 0.71. A domain object had none of this:
    // a merge with no body was a silent no-op where elsewhere it is the
    // malformed condition, and a field selection was accepted and ignored.
    if (merging && Object.keys(body).length === 0) {
      throw malformed("a merge update requires a message body");
    }
    if (merging && sel.any) {
      throw invalidSelection("", "a merge update does not take a field selection");
    }
    // "Complete replacement where no selection appears, field-constrained
    // where one does, merge for PATCH."
    const form = merging ? "merge" : sel.any ? "selected" : "complete";
    // "A CDMI server shall report an error where a field selection names a
    // field that is not supplied in the request representation."
    if (form === "selected") {
      for (const f of sel.fields) {
        if (!(f in body)) {
          throw invalidSelection(f,
            "the field selection names %j, which the representation does not supply", f);
        }
      }
    }
    // "Exactly one declarative request field is supplied in one operation."
    // A domain object takes the two that deserialize one; the others create an
    // object and are not an update of the one addressed. Until 0.105 this path
    // looked for those two and passed over the rest, so a request supplying a
    // copy and a deserialization together was neither refused nor understood —
    // it performed the deserialization and said nothing of the copy.
    const declared = ["reference", "copy", "move", "snapshot", "serialize",
      "deserialize", "deserializevalue"].filter((f) => f in body);
    if (declared.length > 1) {
      throw conflictingFields(declared[1]!,
        "exactly one declarative request field is supplied in one operation, and %j " +
        "and %j were both", declared[0]!, declared[1]!);
    }
    if (declared.length === 1 && declared[0] !== "deserialize" && declared[0] !== "deserializevalue") {
      throw invalidField(`/${declared[0]!}`,
        "%j creates an object and is not an update of the domain object addressed", declared[0]!);
    }
    // A domain object that exists is deserialized over, which
    // replaces the metadata of the object and creates the
    // subdomains the canonical format holds.
    if (typeof body.deserialize === "string") {
      const parent = this.parentDomainOf(node);
      return await this.deserializeDomain(res, parent, this.store.meta(node).name,
        ns, body.deserialize, who, true);
    }
    if (typeof body.deserializevalue === "string") {
      const parent = this.parentDomainOf(node);
      return await this.deserializeDomainValue(res, parent,
        this.store.meta(node).name, ns, body.deserializevalue, who, true);
    }
    // "Update, complete replacement: PUT ... the request URI ... contains no
    // field selection. The body is a complete representation"; "Update,
    // merge: PATCH ... the body is a partial representation, applied as
    // specified in RFC 7396". Until 0.104 a domain object took both as a
    // merge, and a merge that was not one: see the comment at the store below.
    const m = this.store.meta(node);
    const changes = domainMetadata(body, m.metadata, who.privileges.includes("domain_kms_admin"), merging);
    // What the update leaves behind, which is what the checks judge. Until
    // 0.104 they judged the partial the client supplied instead,
    // which was harmless only because the store took the partial too: once a
    // merge merges, a request naming one member of a descriptor was checked —
    // and its scopes claimed — as though the members it did not mention had
    // been removed. Each check compares against what is held and passes over an
    // item that has not changed, so judging the result rather than the request
    // asks no privilege that was not already asked.
    // Which fields this operation applies: everything the representation
    // carries, and for a field-constrained replacement only those the
    // selection names as well.
    const has = (f: string) => f in body && (form !== "selected" || sel.fields.includes(f));
    const effective = !has("metadata")
      ? m.metadata
      : merging ? mergePatch(m.metadata, changes) : changes;
    checkReassignPrivilege(effective, who, m.metadata);
    checkDomainKmsPrivilege(effective, who, m.metadata);
    checkDomainAuth(effective, who, this.base, this.keyManagement.length > 0, m.metadata);
    checkKmsOffered(effective, this.keyManagement, m.metadata);
    await claimScopesOf(this.keyManagement, this.store, effective);
    // A merge applies "the processing rules of JSON Merge Patch ... A field or
    // member whose supplied value is null is removed from the stored object",
    // the recursion beginning at the metadata field and applying "at every
    // depth". A complete replacement replaces what is supplied and leaves the
    // metadata alone where the field is absent.
    //
    // Until 0.104 this was a shallow spread of the supplied items over the held
    // ones, for PUT and PATCH alike, which is neither: a partial
    // cdmi_domain_auth or cdmi_domain_kms replaced the whole descriptor rather
    // than merging its members, and a null was stored as the value of the item
    // rather than removing it — a value no metadata item may hold, since "a
    // CDMI client cannot store null as the value of a field or of a metadata
    // item". Every other object type merged correctly; the domain path was
    // written before mergePatch existed and was never brought to it. Found by a
    // test that removed cdmi_domain_doh.
    if (has("metadata")) {
      m.metadata = merging ? mergePatch(m.metadata, userMetadata(changes, true)) : userMetadata(changes);
      // The owner, the group and the access control list of the domain object,
      // which travel in the metadata field as they do for every other object
      // type. Until 0.105 this path never applied them: a client that supplied
      // cdmi_acl on a domain object was answered 204 and nothing was stored or
      // reported, while the list it could not change governed every operation
      // against that domain.
      this.applyOwnerAndACL(node, m, (body.metadata ?? {}) as Record<string, unknown>, who, true, false);
    }
    // Each extension field supplied replaces the one held, and null removes it;
    // a complete replacement assigns them, and a field-constrained update
    // applies those it selects.
    m.extensions = mergedExtensions(m.extensions,
      form === "selected"
        ? Object.fromEntries(Object.entries(extensions).filter(([k]) => sel.fields.includes(k)))
        : extensions,
      form === "complete");
    // The graph relationships, which have the exception the metadata field has:
    // absent from a complete replacement, they are left as they are (ECR-225A).
    applyRel(m, body, has, form);
    this.store.setMeta(node, m);
    // The references of a directory named here are bound, now that the item is stored.
    await this.bindDomainAuth(node, who);
    // A scope the change left no domain declaring is released.
    if ("cdmi_domain_kms" in changes) await this.releaseUndeclared();
    res.writeHead(204);
    res.end();
  }

  /**
   * Creates a domain object by copying an existing one, or by moving
   * it. The subdomains beneath it are copied with it; the objects
   * the domain owns are not, their domain being unchanged by a copy
   * of the domain object itself.
   */
  private async copyDomain(res: ServerResponse, parent: Node, name: string,
    ns: string, from: string, move: boolean, body: Record<string, unknown>,
    who: Principal): Promise<void> {
    const source = this.domainNamed(from);
    if (source === undefined) {
      throw notFound(`${from}: the source names no domain object`);
    }
    if (this.store.tryLookup(parent, name) !== undefined) {
      throw alreadyExists("%s exists", ns);
    }
    this.demand(source, who, M.READ_METADATA, true, `reading ${from}`);
    if (move) this.demand(source, who, M.DELETE, true, `moving ${from}`);

    const made = this.copyDomainTree(source, parent, name, who);
    // A field the request supplies beside the copy is applied to the
    // object created, as it is for a data object.
    const given = domainMetadata(body, this.store.meta(made).metadata, who.privileges.includes("domain_kms_admin"));
    checkDomainKmsPrivilege(given, who, this.store.meta(made).metadata);
    checkDomainAuth(given, who, this.base, this.keyManagement.length > 0, this.store.meta(made).metadata);
    checkKmsOffered(given, this.keyManagement, this.store.meta(made).metadata);
    await claimScopesOf(this.keyManagement, this.store, given);
    const supplied = userMetadata(given);
    if (Object.keys(supplied).length > 0) {
      const m = this.store.meta(made);
      m.metadata = { ...m.metadata, ...supplied };
      this.store.setMeta(made, m);
      await this.bindDomainAuth(made, who);
    }
    if (move) {
      // The objects the domain owned are owned by the domain object
      // created, the move being of the object and not a deletion of
      // it.
      this.store.reassignDomain(source, made);
      await this.store.collect(this.store.removeTree(source));
    }
    res.writeHead(201, {
      "Content-Type": MT_DOMAIN,
      Location: this.base.slice(0, -1) + ns,
      "Content-Length": "0",
    });
    res.end();
  }

  /** Copies a domain object and the subdomains beneath it. */
  private copyDomainTree(source: Node, parent: Node, name: string,
    who: Principal): Node {
    const sm = this.store.meta(source);
    const made = this.store.createDomain(parent, name, {
      metadata: { ...sm.metadata },
      owner: who.name === ANONYMOUS.name ? "" : who.name,
      acl: sm.acl ?? aclForNewObject(undefined, this.store.meta(parent).acl, true),
    });
    this.store.setDomain(made, made);
    for (const child of this.store.children(source)) {
      if (!this.store.meta(child.node).isDomain) continue;
      this.copyDomainTree(child.node, made, child.name, who);
    }
    return made;
  }

  /** The domain object that holds this one. */
  private parentDomainOf(node: Node): Node {
    const m = this.store.meta(node);
    if (m.parent === null) return node;
    return { id: m.parent, isContainer: true };
  }

  /** The domain object a domain path names, where it names one. */
  private domainNamed(ns: string): Node | undefined {
    const trimmed = ns.replace(/\/$/, "");
    if (!trimmed.startsWith(`/${DOMAINS}`)) return undefined;
    const segs = trimmed.slice(DOMAINS.length + 2).split("/").filter((s) => s !== "");
    let at = this.store.domainRoot();
    if (at === undefined) return undefined;
    for (const seg of segs) {
      const next = this.store.tryLookup(at, seg);
      if (next === undefined || !this.store.meta(next).isDomain) return undefined;
      at = next;
    }
    return at;
  }

  /** Creates a domain object from a canonical format held elsewhere. */
  private async deserializeDomain(res: ServerResponse, parent: Node, name: string,
    ns: string, from: string, who: Principal, modify: boolean): Promise<void> {
    const source = await this.sourceOf(
      new Resolver(this.store, { principal: who }), from, who);
    const text = (await this.store.readValue(source.node)).toString("utf8");
    return await this.domainFromCanonical(res, parent, name, ns, text, who, modify);
  }

  /** Creates a domain object from a canonical format supplied inline. */
  private async deserializeDomainValue(res: ServerResponse, parent: Node,
    name: string, ns: string, encoded: string, who: Principal,
    modify: boolean): Promise<void> {
    const text = Buffer.from(encoded, "base64").toString("utf8");
    return await this.domainFromCanonical(res, parent, name, ns, text, who, modify);
  }

  /** Creates a domain object and the subdomains a canonical format holds. */
  private async domainFromCanonical(res: ServerResponse, parent: Node, name: string,
    ns: string, text: string, who: Principal, modify: boolean): Promise<void> {
    let canonical;
    try {
      canonical = parseCanonical(text);
    } catch (err) {
      throw invalidField("deserialize", "%s",
        err instanceof Error ? err.message : String(err));
    }
    if (canonical.objectType !== MT_DOMAIN) {
      throw invalidField("deserialize",
        "the canonical format holds %j, and a domain object is created from the " +
        "canonical format of one", String(canonical.objectType));
    }
    const existing = this.store.tryLookup(parent, name);
    if (existing !== undefined && !modify) throw alreadyExists("%s exists", ns);
    this.demand(parent, who, M.ADD_SUBCONTAINER, true, `creating ${ns}`);

    const made = existing ?? this.store.createDomain(parent, name, {
      owner: who.name === ANONYMOUS.name ? "" : who.name,
      acl: aclForNewObject(undefined, this.store.meta(parent).acl, true),
    });
    const m = this.store.meta(made);
    m.metadata = {
      ...m.metadata,
      ...userMetadata(deserializableMetadata(
        canonical.metadata as Record<string, unknown> | undefined) ?? {}),
    };
    this.store.setMeta(made, m);
    if (existing === undefined) this.store.setDomain(made, made);

    // The subdomains the canonical format holds, each created
    // beneath the domain object created. They answer nothing of
    // their own: the response is of the domain object requested.
    for (const child of (canonical.children ?? []) as Record<string, unknown>[]) {
      const childName = String(child.objectName ?? "").replace(/\/$/, "");
      if (childName === "") continue;
      this.domainSubtree(made, childName, JSON.stringify(child), who);
    }
    res.writeHead(existing === undefined ? 201 : 204, {
      "Content-Type": MT_DOMAIN,
      Location: this.base.slice(0, -1) + ns,
      "Content-Length": "0",
    });
    res.end();
  }

  /** Creates a subdomain and those beneath it from a canonical format. */
  private domainSubtree(parent: Node, name: string, text: string,
    who: Principal): void {
    let canonical;
    try {
      canonical = parseCanonical(text);
    } catch {
      return;
    }
    if (canonical.objectType !== MT_DOMAIN) return;
    const made = this.store.tryLookup(parent, name) ??
      this.store.createDomain(parent, name, {
        owner: who.name === ANONYMOUS.name ? "" : who.name,
        acl: aclForNewObject(undefined, this.store.meta(parent).acl, true),
      });
    const m = this.store.meta(made);
    m.metadata = {
      ...m.metadata,
      ...userMetadata(deserializableMetadata(
        canonical.metadata as Record<string, unknown> | undefined) ?? {}),
    };
    this.store.setMeta(made, m);
    this.store.setDomain(made, made);
    for (const child of (canonical.children ?? []) as Record<string, unknown>[]) {
      const childName = String(child.objectName ?? "").replace(/\/$/, "");
      if (childName === "") continue;
      this.domainSubtree(made, childName, JSON.stringify(child), who);
    }
  }

  private async deleteDomain(res: ServerResponse, node: Node, root: Node, ns: string,
    who: Principal): Promise<void> {
    if (node.id === root.id) {
      throw forbidden("the domain object at the root of the hierarchy is not deleted");
    }
    this.demand(node, who, M.DELETE, true, `deleting ${ns}`);
    // A subdomain deleted with it that owns objects would leave them naming a
    // domain that does not exist. The draft provides for the objects of the
    // domain deleted, not those of its subdomains, so such a delete is refused
    // until each subdomain is deleted itself.
    const within: Node[] = [];
    const collect = (d: Node) => {
      for (const c of this.store.children(d)) {
        if (c.node.isContainer && this.store.meta(c.node).isDomain) {
          within.push(c.node);
          collect(c.node);
        }
      }
    };
    collect(node);
    for (const sub of within) {
      if (this.store.objectsInDomain(sub) > 0) {
        throw conflict("%s owns objects, and is deleted with %s; it is deleted first, its objects reassigned",
          this.store.pathOf(sub), ns);
      }
    }
    // "The objects that the deleted domain object owned shall be reassigned to
    // the domain object addressed by the cdmi_domain_delete_reassign metadata
    // item of the deleted domain object ... Where the deleted domain object owns
    // one or more objects and the cdmi_domain_delete_reassign metadata item is
    // absent, or does not address a domain object other than the domain object
    // being deleted, the CDMI server shall report the invalid field condition and
    // shall not delete the domain object" (the Delete subclause). Before 0.53 a
    // domain owning objects was refused with 409 whatever the item said.
    const owned = this.store.objectsOwnedBy(node);
    if (owned.length > 0) {
      const path = this.store.meta(node).metadata.cdmi_domain_delete_reassign;
      const target = typeof path === "string" ? this.domainExactly(path) : undefined;
      if (target === undefined || target.id === node.id || within.some((d) => d.id === target.id)) {
        throw invalidField("metadata/cdmi_domain_delete_reassign",
          "%s owns objects, and its cdmi_domain_delete_reassign item does not address another domain object " +
          "that remains, to which they would be reassigned", ns);
      }
      // A reassignment is a change of domain as any other means is, and makes
      // no change where it cannot be made for every object: each is checked
      // before any is moved.
      for (const o of owned) {
        if ("cdmi_dac_certificate" in (this.store.meta(o).metadata ?? {}) &&
            !who.privileges.includes("domain_kms_admin")) {
          throw forbidden("%s owns %s, which carries cdmi_dac_certificate; reassigning it requires the " +
            "domain_kms_admin privilege, which %s does not hold", ns, this.store.pathOf(o), who.name);
        }
      }
      for (const o of owned) await this.changeDomain(o, target, who);
    }
    await this.store.collect(this.store.removeTree(node));
    // A scope the deleted domains alone declared is released.
    await this.releaseUndeclared();
    res.writeHead(204);
    res.end();
  }

  private async domainBody(req: IncomingMessage): Promise<Record<string, unknown>> {
    const raw = await readBody(req);
    const ct = mediaTypeOf(req.headers["content-type"] as string);
    if (ct !== "" && ct !== MT_DOMAIN && ct !== `${MT_DOMAIN}+json`) {
      throw new Condition(415, "", "The media type is not supported.",
        `${ct} is not the media type of a domain object`);
    }
    if (raw.length === 0) return {};
    try {
      const body = JSON.parse(raw.toString("utf8")) as Record<string, unknown>;
      if (body === null || typeof body !== "object" || Array.isArray(body)) {
        throw new Error("not an object");
      }
      return body;
    } catch {
      throw malformed("the message body shall be a JSON object");
    }
  }

  // -----------------------------------------------------------------
  // Versions

  /** The namespace path of the snapshot entry that pins an identifier. */
  private pathOfPinned(ns: string): string | undefined {
    const rest = ns.slice(OBJECTID_TREE.length).replace(/\/$/, "");
    if (rest === "" || rest.includes("/")) return undefined;
    const node = this.store.byPinnedID(rest);
    if (!node) return undefined;
    try {
      return this.store.pathOf(node);
    } catch {
      return undefined;
    }
  }

  /**
   * The object with no path that an object ID address names. An object
   * created by a POST to the object ID tree, or moved into it, holds a
   * name this CDMI server assigned, which is reserved: the object is
   * reached by its object ID alone.
   */
  /**
   * A request addressing a queue object that has no path. The values
   * are appended by a POST and removed by a DELETE carrying a queue
   * value selection, as they are for one that has a name.
   */
  /**
   * Applies an exports field supplied for a queue object. An MQTT
   * export publishes the values the object holds, and is the one
   * export type placed on a queue object.
   */
  private async applyQueueExports(node: Node, body: Record<string, unknown>, form: string,
    who: Principal, ns: string): Promise<void> {
    if (!("exports" in body)) {
      if (form === "complete" && this.exports?.configured(node)) {
        this.exports.set(node, null);
      }
      return;
    }
    if (!this.exports) {
      throw capabilityCondition(
        "this server serves no exports")
        .with("cdmi_capability", "cdmi_export_mqtt");
    }
    this.demand(node, who, M.WRITE_METADATA, false, `changing the exports of ${ns}`);
    const v = body.exports;
    if (v === null) {
      this.exports.set(node, null);
      this.exports.settleMqtt(node);
      return;
    }
    // A credential reference an entry carries is bound before the entry is
    // validated and stored: entitlement is determined when a feature is
    // configured, and the reference stored records the scope that applies.
    const bound = await this.bindExportCredentials(node, v, who);
    const merged = form === "merge"
      ? mergePatch((this.store.meta(node).exports ?? {}) as Record<string, unknown>,
        bound as Record<string, unknown>)
      : bound;
    this.exports.set(node, merged, who.name);
    // The entries now stored are established, withdrawn or re-established to
    // match. An update that answers 204 reports nothing, and establishing an
    // entry as a side effect of reporting it left a disabled entry
    // publishing (weedmi EMQT-001).
    this.exports.settleMqtt(node);
  }

  /**
   * Whether the access control list of an object still grants a principal the
   * permission to read it, for an export that publishes outward under that
   * principal's authority. The principal is named, not held, so its groups and
   * privileges are those the directory gives it now.
   */
  mayPublishAs(node: Node, principal: string): boolean {
    const m = this.store.meta(node);
    const who: Principal = this.directory.principalNamed(principal);
    return granted(m.acl, who, M.READ_OBJECT, {
      owner: m.owner, group: m.group, isContainer: node.isContainer, isRoot: m.parent === null,
    });
  }

  /**
   * Binds the password_secret_id of each MQTT import entry, returning the
   * entries with the bound references in place of those supplied; an entry
   * already holding the reference supplied, unchanged, keeps it.
   */
  private async bindImportCredentials(node: Node, value: unknown, who: Principal): Promise<unknown> {
    if (!Array.isArray(value) || this.keyManagement.length === 0) return value;
    const held = (this.store.meta(node).imports ?? []) as Record<string, unknown>[];
    const out: unknown[] = [];
    for (const [i, entry] of value.entries()) {
      if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
        out.push(entry);
        continue;
      }
      const e = entry as Record<string, unknown>;
      out.push(await this.bindMqttCredentials(node, e,
        held.find((h) => h.import_uri === e.import_uri), `/imports/${i}`, who));
    }
    return out;
  }

  /**
   * Binds the credential references of an MQTT entry, export or import:
   * password_secret_id at the top level, and ca_cert_id in the tls object,
   * of which it is a sub-field. A reference the entry already holds, supplied
   * unchanged, is kept. client_cert_id and client_key_id are left for the
   * parser, which refuses them, so that no key management server is reached
   * for a field this server cannot use.
   */
  private async bindMqttCredentials(node: Node, entry: Record<string, unknown>,
    held: Record<string, unknown> | undefined, at: string, who: Principal): Promise<Record<string, unknown>> {
    const configurer = { name: who.name, privileges: who.privileges ?? [] };
    const bind = async (supplied: unknown, already: unknown, field: string,
      requirement: typeof PASSWORD, defaultType: string) => {
      const a = already as Record<string, unknown> | undefined;
      const sup = supplied as Record<string, unknown> | null;
      const unchanged = a !== undefined && sup !== null && typeof sup === "object" &&
        sup.name === a.name && (sup.kms ?? a.kms) === a.kms && !("secret" in sup) &&
        scopeStillApplies(this.credentialContext(), node, boundReference(a)!);
      return unchanged ? a : await bindReference(this.credentialContext(), `${at}/${field}`, supplied, node,
        configurer, requirement, defaultType);
    };
    const e = { ...entry };
    if ("password_secret_id" in e) {
      e.password_secret_id = await bind(e.password_secret_id, held?.password_secret_id,
        "password_secret_id", PASSWORD, "Secret Data");
    }
    const tls = e.tls;
    if (tls !== null && typeof tls === "object" && !Array.isArray(tls) && "ca_cert_id" in tls) {
      const heldTls = (held?.tls ?? {}) as Record<string, unknown>;
      e.tls = { ...(tls as Record<string, unknown>),
        ca_cert_id: await bind((tls as Record<string, unknown>).ca_cert_id, heldTls.ca_cert_id,
          "tls/ca_cert_id", CERTIFICATE, "Certificate") };
    }
    return e;
  }

  /**
   * A request body with the credential_id of each import entry bound: the
   * entitlement of the principal is determined when the entry is written, and
   * the reference stored records the scope that applies. An entry already
   * holding the reference supplied, unchanged, keeps it. A body without
   * imports, or a server without a key management server, is returned as it
   * is, the parser refusing a credential_id where none can be resolved.
   */
  private async withBoundImports(node: Node, body: Record<string, unknown>, who: Principal,
    domain?: Node): Promise<Record<string, unknown>> {
    const v = body.imports;
    if (!Array.isArray(v) || this.keyManagement.length === 0) return body;
    // A container being created holds no entries yet, and is bound against
    // the domain it will have rather than that of the node given.
    const held = domain !== undefined ? []
      : (this.store.meta(node).imports ?? []) as unknown as Record<string, unknown>[];
    const base = this.credentialContext();
    const ctx: CredentialContext = domain === undefined ? base : {
      ...base,
      descriptorsFor: () => descriptorsOf(this.domainSettings(domain)),
      domainObjectIDFor: () => this.store.meta(domain).objectID,
    };
    const out: unknown[] = [];
    for (const [i, entry] of v.entries()) {
      if (entry === null || typeof entry !== "object" || Array.isArray(entry) ||
          !("credential_id" in entry || "trust_anchor" in entry)) {
        out.push(entry);
        continue;
      }
      const e = { ...(entry as Record<string, unknown>) };
      const heldEntry = held.find((h) => h.import_uri === e.import_uri);
      // Each credential reference an import entry carries: the secret it
      // presents to the origin server, and the trust anchor it verifies that
      // server against, which revision 365 adds. Both are bound when the entry
      // is written, so that a use of either needs no principal.
      for (const [field, requirement, defaultType] of
        [["credential_id", PASSWORD, "Secret Data"], ["trust_anchor", CERTIFICATE, "Certificate"]] as const) {
        if (!(field in e)) continue;
        const supplied = e[field] as Record<string, unknown> | null;
        // A string is left for the parser to refuse, as naming no credential
        // reference.
        if (typeof supplied !== "object" || supplied === null) continue;
        const already = heldEntry?.[field] as Record<string, unknown> | undefined;
        const unchanged = already !== undefined &&
          supplied.name === already.name && (supplied.kms ?? already.kms) === already.kms &&
          !("secret" in supplied) && scopeStillApplies(ctx, node, boundReference(already)!);
        e[field] = unchanged ? already : await bindReference(ctx,
          `/imports/${i}/${field}`, supplied, node,
          { name: who.name, privileges: who.privileges ?? [] }, requirement, defaultType);
      }
      out.push(e);
    }
    return { ...body, imports: out };
  }

  /**
   * Changes the domain owning an object, as the change-of-domain subclause
   * requires of every means by which it changes:
   *
   * - the change is refused, without domain_kms_admin, for an object carrying
   *   cdmi_dac_certificate, since the requirement a delegated access control
   *   provider places is a property of the key management server the domain
   *   specifies;
   * - each managed object this server registered for a secret deposited on
   *   the object is revoked while the object is still in the domain that holds
   *   it, "since that managed object is held in the scope of the domain that no
   *   longer owns the object and is reachable by the administrators of that
   *   domain"; and
   * - each other credential reference is left as it is, and is checked at its
   *   next use: resolved where the scope that applies in the new domain is the
   *   scope recorded, and otherwise reported as needing to be bound again
   *   (credential-use.ts, assertScopeApplies).
   */
  private async changeDomain(node: Node, domain: Node, who: Principal,
    body?: Record<string, unknown>): Promise<void> {
    if (this.domainOf(node).id === domain.id) return;
    // "A CDMI server shall report the invalid field condition where an
    // update changes the domain of an object and supplies no cdmi_acl
    // metadata item" (revision 354). The reason is that the access control
    // list the object carries was written for the identifiers of the
    // domain it is leaving, which name a different principal in the domain
    // it is entering, or none.
    //
    // The rule governs an update a CDMI client made: a body is passed where
    // there is one, and this server also changes the domain of an object
    // for reasons of its own — the objects a domain being deleted owned —
    // where no representation was supplied and the rule does not apply.
    const m = this.store.meta(node);
    if ("cdmi_dac_certificate" in (m.metadata ?? {}) && !who.privileges.includes("domain_kms_admin")) {
      throw forbidden("changing the domain of %s, which carries cdmi_dac_certificate, requires the " +
        "domain_kms_admin privilege, which %s does not hold", this.store.pathOf(node), who.name);
    }
    // The field is examined after the permissions are, so that a principal
    // that may not make the change at all is told so rather than being told
    // how to form a request it may not make.
    if (body !== undefined && suppliedACL(body) === undefined) {
      throw invalidField("metadata/cdmi_acl",
        "an update that changes the domain of an object states its access control list, the " +
        "list the object carries having been written for the identifiers of the domain it " +
        "is leaving");
    }
    await this.revokeDeposits(this.store.pathOf(node), this.depositedReferences(node),
      "the domain owning the object carrying it changed");
    this.store.setDomain(node, domain);
  }

  /**
   * Revokes the managed objects this server registered for deposits. A
   * deposit already gone, or a server not reached, does not stop the operation
   * that withdrew it; what was not revoked is written for the operator.
   */
  private async revokeDeposits(where: string, refs: CredentialReference[], why: string): Promise<void> {
    for (const ref of refs) {
      const server = this.keyManagement.find((k) => k.label === ref.kms);
      if (server === undefined) continue;
      try {
        const resolved = await resolveReference(server, ref, ref.scope ?? "",
          // Any type a deposit may be registered as: an empty list would
          // refuse every one, and each revocation would fail unseen.
          { objectTypes: ["Secret Data", "Certificate", "Symmetric Key", "Private Key", "Public Key",
            "Opaque Object"], usage: 0, purpose: "revoking a deposited credential" });
        await server.revoke(resolved.id, "Cessation of Operation", { message: why });
      } catch {
        process.stderr.write(`seedmi: a deposited credential ${JSON.stringify(ref.name)} of ` +
          `${where} was not revoked (${why})\n`);
      }
    }
  }

  /**
   * Revokes the deposits an object held before a write and no longer holds:
   * "A CDMI client withdraws a deposited credential by removing the field
   * carrying the credential reference, and the CDMI server shall revoke the
   * managed objects it registered for it" (the Deposit subclause). Removing the
   * entry, replacing the reference, or replacing the whole field all withdraw
   * it. Before 0.49 a deposit withdrawn was left active at the key management
   * server.
   */
  private async revokeWithdrawn(node: Node, before: CredentialReference[]): Promise<void> {
    const key = (r: CredentialReference) => `${r.kms}\u0000${r.scope ?? ""}\u0000${r.name}`;
    const held = new Set(this.depositedReferences(node).map(key));
    const gone = before.filter((r) => !held.has(key(r)));
    if (gone.length > 0) await this.revokeDeposits(this.store.pathOf(node), gone, "the credential reference was withdrawn");
  }

  /** The deposits held by an object and every object beneath it, which deleting it withdraws. */
  private depositsBeneath(node: Node): CredentialReference[] {
    const out = [...this.depositedReferences(node)];
    if (node.isContainer) for (const c of this.store.children(node)) out.push(...this.depositsBeneath(c.node));
    return out;
  }

  /** The credential references an object's exports and imports hold for secrets deposited on it. */
  private depositedReferences(node: Node): CredentialReference[] {
    const m = this.store.meta(node);
    const out: CredentialReference[] = [];
    const take = (v: unknown) => {
      const r = boundReference(v);
      if (r !== undefined && r.deposited === "true") out.push(r);
    };
    const entries = [
      ...Object.values((m.exports ?? {}) as Record<string, Record<string, unknown>>),
      ...((m.imports ?? []) as unknown as Record<string, unknown>[]),
    ];
    for (const e of entries) {
      if (e === null || typeof e !== "object") continue;
      take(e.password_secret_id);
      take(e.credential_id);
      const tls = e.tls as Record<string, unknown> | undefined;
      if (tls !== undefined && tls !== null && typeof tls === "object") take(tls.ca_cert_id);
    }
    return out;
  }

  /**
   * A credential reference as a read reports it: the key management server
   * and the name, and the scope "where client registration is available for
   * the key management server addressed", omitted "where client registration
   * is not available, a deployment that does not offer client registration
   * disclosing no scope to a CDMI client". What this server records beside
   * them (the principal, whether it is a deposit) is never reported.
   */
  private readableRef(node: Node, raw: unknown): unknown {
    const r = boundReference(raw);
    if (r === undefined) return raw;
    const d = descriptorsOf(this.domainSettings(this.domainOf(node)))[r.kms];
    return { kms: r.kms, name: r.name,
      ...(d !== undefined && registersItself(d) && r.scope !== undefined ? { scope: r.scope } : {}) };
  }

  /**
   * An export or import entry with each credential reference it holds as a
   * read reports it. stored is the entry as held, where the entry given is a
   * report that has already dropped what the references record. Before 0.48 an
   * MQTT import's password_secret_id, and an import's tls.ca_cert_id, were
   * reported whole, scope and all.
   */
  private readableEntry(node: Node, entry: Record<string, unknown>,
    stored: Record<string, unknown> = entry): Record<string, unknown> {
    const e = { ...entry };
    for (const f of ["password_secret_id", "credential_id", "trust_anchor"]) {
      if (stored[f] !== undefined) e[f] = this.readableRef(node, stored[f]);
    }
    const tls = stored.tls as Record<string, unknown> | undefined;
    if (tls !== undefined && tls !== null && typeof tls === "object" && tls.ca_cert_id !== undefined &&
        e.tls !== null && typeof e.tls === "object") {
      e.tls = { ...(e.tls as Record<string, unknown>), ca_cert_id: this.readableRef(node, tls.ca_cert_id) };
    }
    return e;
  }

  /** An exports report with each credential reference as a read reports it. */
  private readableExports(node: Node, report: Record<string, unknown>): Record<string, unknown> {
    const stored = (this.store.meta(node).exports ?? {}) as Record<string, Record<string, unknown>>;
    const out: Record<string, unknown> = {};
    for (const [name, entry] of Object.entries(report)) {
      out[name] = entry !== null && typeof entry === "object" && stored[name] !== undefined
        ? this.readableEntry(node, entry as Record<string, unknown>, stored[name])
        : entry;
    }
    return out;
  }

  /**
   * Releases each claim this server holds on a scope that no domain object
   * declares any longer: "Where no domain object of a CDMI server declares a
   * scope, whether because the cdmi_domain_kms item was changed or because the
   * domain object was deleted, the CDMI server shall remove its own identifier
   * from the Application Specific Information" of the binding key (the Scope
   * binding subclause), which kms-binding.ts's releaseScope does, destroying
   * the binding key where no other CDMI server is recorded in it. Before 0.49 a
   * claim was never released. A server not reached keeps the claim, which is
   * released at the next such change.
   */
  private async releaseUndeclared(): Promise<void> {
    const declared = new Set<string>();
    const visit = (node: Node) => {
      if (this.store.meta(node).isDomain) {
        for (const [label, d] of Object.entries(descriptorsOf(this.domainSettings(node)))) {
          declared.add(`${label}\u0000${d.scope ?? ""}`);
        }
      }
      for (const c of this.store.children(node)) if (c.node.isContainer) visit(c.node);
    };
    const root = this.store.domainRoot();
    if (root !== undefined) visit(root);
    for (const { label, scope } of this.store.bindingKeys()) {
      if (declared.has(`${label}\u0000${scope}`)) continue;
      const server = this.keyManagement.find((k) => k.label === label);
      if (server === undefined) continue;
      try {
        await releaseScope(server, scope, await server.identifier());
        this.store.forgetBindingKey(label, scope);
      } catch {
        process.stderr.write(`seedmi: the claim on scope ${JSON.stringify(scope)} at ${label} was not released\n`);
      }
    }
  }

  /**
   * Stores the extension fields a create or update supplied: "store the field
   * with the object", each replacing the one held and null removing it; a
   * complete replacement assigns them, and a field-constrained update applies
   * those it selects.
   */
  private applyExtensionFields(node: Node, body: Record<string, unknown>, kind: ObjectKind, form: string,
    sel?: Selection): void {
    let supplied = bodyExtensions(body, kind);
    if (form === "selected" && sel !== undefined) {
      supplied = Object.fromEntries(Object.entries(supplied).filter(([k]) => sel.fields.includes(k)));
    }
    const m = this.store.meta(node);
    const next = mergedExtensions(m.extensions, supplied, form === "complete");
    if (JSON.stringify(next) === JSON.stringify(m.extensions ?? {})) return;
    m.extensions = next;
    this.store.setMeta(node, m);
  }

  /** What a credential reference needs to be bound and resolved. */
  credentialContext(): CredentialContext {
    return {
      servers: this.keyManagement,
      store: this.store,
      descriptorsFor: (node) => descriptorsOf(this.domainSettings(this.domainOf(node))),
      domainObjectIDFor: (node) => this.store.meta(this.domainOf(node)).objectID,
    };
  }

  /**
   * Binds each credential reference an exports field carries, returning the
   * field with the bound references in place of those supplied. The
   * references an MQTT export carries are password_secret_id; one an entry
   * already holds, supplied unchanged, is left as it is.
   */
  private async bindExportCredentials(node: Node, value: unknown, who: Principal): Promise<unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return value;
    if (this.keyManagement.length === 0) return value;
    const held = (this.store.meta(node).exports ?? {}) as Record<string, Record<string, unknown>>;
    const out: Record<string, unknown> = {};
    for (const [name, entry] of Object.entries(value as Record<string, unknown>)) {
      if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
        out[name] = entry;
        continue;
      }
      out[name] = await this.bindMqttCredentials(node, entry as Record<string, unknown>,
        held[name], `/exports/${name}`, who);
    }
    return out;
  }

  /**
   * Applies an imports field supplied for a queue object. An MQTT
   * import enqueues to the object the messages of a topic, and is the
   * one import type placed on a queue object: the layering rules do
   * not apply, a queue object holding a sequence of values and not a
   * namespace.
   */
  private async applyQueueImports(node: Node, body: Record<string, unknown>, form: string,
    who: Principal, ns: string): Promise<void> {
    if (!("imports" in body)) {
      if (form === "complete") this.setQueueImports(node, []);
      return;
    }
    this.demand(node, who, M.WRITE_METADATA, false, `changing the imports of ${ns}`);
    const v = body.imports;
    if (v === null) {
      this.setQueueImports(node, []);
      return;
    }
    // A credential reference an entry carries is bound first, as an export's
    // is, and the parser accepts it where a key management server is configured.
    const bound = await this.bindImportCredentials(node, v, who);
    const entries = parseImports(bound, ns, { kms: this.keyManagement.length > 0 });
    for (const e of entries) {
      if (e.type !== "MQTT") {
        throw invalidField("/imports/0/type",
          "an import entry on a queue object is of type MQTT, and enqueues the " +
          "messages of a topic; %j presents a namespace and is placed on a " +
          "container object", e.type);
      }
    }
    this.setQueueImports(node, entries);
  }

  /**
   * Applies the imports field of a data object, which carries a value
   * import: "An HTTP import presents the representation an origin server
   * returns for one URI as the value of a data object ... It is placed on a
   * data object, as an entry of the imports field of that object" (revision
   * 327). A namespace import is placed on a container object instead.
   */
  private async applyDataImports(node: Node, body: Record<string, unknown>, form: string,
    who: Principal, ns: string): Promise<void> {
    if (!("imports" in body)) {
      if (form === "complete") this.setDataImports(node, []);
      return;
    }
    this.demand(node, who, M.WRITE_METADATA, false, `changing the imports of ${ns}`);
    const bound = body.imports;
    const entries = parseImports(bound, ns, { kms: this.keyManagement.length > 0 });
    for (const e of entries) {
      if (e.type !== "HTTP") {
        throw invalidField("/imports/0/type",
          "an import entry on a data object is of type HTTP, and presents what an " +
          "origin server returns as the value; %j presents a namespace and is " +
          "placed on a container object", e.type);
      }
    }
    // "A CDMI server establishes the import by issuing a HEAD request for
    // the URI, which confirms that the origin server serves it and provides
    // the header fields the CDMI server records ... Where the request does
    // not succeed, the CDMI server shall report the import as not active
    // and shall record the condition in the last_problems field."
    for (const e of entries) {
      try {
        const got = await establishImport(e as HttpImportEntry,
          () => this.importSecret(node, e), () => this.importTrustAnchor(node, e));
        if (got.status >= 200 && got.status < 300) {
          e.etag = got.etag;
          e.last_modified = got.lastModified;
          (e as { last_problems?: unknown[] }).last_problems = [];
        } else {
          (e as { last_problems?: unknown[] }).last_problems =
            [`the origin server answered ${got.status}`];
        }
      } catch (err) {
        (e as { last_problems?: unknown[] }).last_problems =
          [`the origin server could not be reached: ${(err as Error).message}`];
      }
    }
    this.setDataImports(node, entries);
  }

  /**
   * The credential an HTTP import presents to an origin server: the password
   * of the Basic scheme or the token of the Bearer scheme, held as a
   * credential reference so that the entry itself holds no secret.
   */
  private async importSecret(node: Node, entry: ImportEntry): Promise<string | undefined> {
    const reference = (entry as { credential_id?: unknown }).credential_id;
    if (reference === undefined) return undefined;
    const got = await retrieveSecret(this.credentialContext(), node,
      reference as never, PASSWORD);
    return got.octets.toString("utf8");
  }

  /**
   * The trust anchor an import entry names, in PEM, against which the
   * certificate the origin server presents is verified. Where the entry names
   * none, the connection is verified against the trust anchors this server is
   * configured with, which is what returning undefined leaves it to do.
   */
  private async importTrustAnchor(node: Node, entry: ImportEntry): Promise<string | undefined> {
    const reference = (entry as { trust_anchor?: unknown }).trust_anchor;
    if (reference === undefined) return undefined;
    const got = await retrieveCertificate(this.credentialContext(), node, reference as never);
    return got.pem;
  }

  /** Records the import entries of a data object. */
  private setDataImports(node: Node, entries: ImportEntry[]): void {
    const m = this.store.meta(node);
    const before = (m.imports ?? []) as unknown as ImportEntry[];
    if (before.length === 0 && entries.length === 0) return;
    m.imports = entries as unknown as Record<string, unknown>[];
    this.store.setMeta(node, m);
  }

  /** Records the import entries of a queue object and establishes them. */
  private setQueueImports(node: Node, entries: ImportEntry[]): void {
    const m = this.store.meta(node);
    const before = (m.imports ?? []) as unknown as ImportEntry[];
    if (before.length === 0 && entries.length === 0) return;
    m.imports = entries as unknown as Record<string, unknown>[];
    this.store.setMeta(node, m);
    this.mqttImports?.withdrawAllOf(node);
    for (const [i, e] of entries.entries()) {
      this.mqttImports?.offer(MqttImporter.keyOf(node, i), e, node);
    }
  }

  /** What enqueues the messages of a topic to a queue object. */
  mqttImports?: MqttImporter;

  private runner?: QueryRunner;

  /** What enqueues a notification of an event. */
  private notifier?: Notifier;

  private notifications(): Notifier {
    if (this.notifier === undefined) this.notifier = new Notifier(this.store);
    return this.notifier;
  }

  /**
   * Reports an event to the notification queues that report it. The
   * representation is the one a notification carries, which is the
   * one a query would report of the same object.
   */
  private event(type: string, node: Node | undefined, ns: string,
    who: Principal, result = "Success"): void {
    const notifier = this.notifications();
    if (!notifier.enabled) return;
    void who;
    notifier.notify({
      type,
      ...(node === undefined ? {} : { node }),
      // Formed once for each notification queue, as the owner of
      // that queue object rather than as the principal that caused
      // the event: a CDMI client reads through a notification queue
      // what it could read directly, and no more.
      representation: (as: string) => {
        const reader: Principal = as === "" || as === ANONYMOUS.name
          ? ANONYMOUS
          : { name: as, groups: [], administrator: false, privileges: [] };
        if (node !== undefined) {
          try {
            const formed = this.representationFor(node, ns, reader);
            if (formed !== undefined) return formed;
          } catch {
            // The object has gone, and the name is all that is left.
          }
        }
        // An object that has been deleted has no representation to
        // form, so the notification carries the path and the name
        // alone. An event of an object the reader may not read has
        // no notification at all, which the undefined above says.
        if (node !== undefined) return undefined;
        const name = ns.replace(/\/$/, "").split("/").pop() ?? "";
        return {
          objectName: ns.endsWith("/") ? `${name}/` : name,
          parentURI: ns.replace(/[^/]*\/?$/, ""),
        };
      },
      result,
      user: who.name,
    });
  }

  /** The principal a query runs as. */
  private asking: Principal = ANONYMOUS;

  /**
   * What runs a query, on behalf of the principal that owns the
   * query queue: a query reports the objects that principal may
   * read and no others.
   */
  private queries(who: Principal): QueryRunner {
    if (this.runner === undefined) {
      this.runner = new QueryRunner(this.store, {
        representationOf: (node, ns, withValue) =>
          this.queryRepresentation(node, ns, this.asking, withValue),
      });
    }
    this.asking = who;
    return this.runner;
  }

  /** Creates the queue object representation of a name. */
  private async createQueueAt(res: ServerResponse, pv: View, target: Node,
    ns: string, name: string, body: Record<string, unknown>, form: string,
    who: Principal, headers: Record<string, string> = {}): Promise<void> {
    this.demand(pv.held, who, M.ADD_OBJECT, true, `creating ${ns}`);
    // A query queue is a queue object carrying the metadata of one.
    const wanted = userMetadata((body.metadata ?? {}) as Record<string, unknown>);
    checkQueryMetadata(wanted);
    checkNotificationMetadata(wanted);
    // The graph relationships supplied with the create, validated before the
    // object exists so that a malformed one refuses the create rather than
    // leaving a queue object behind. This path stored neither the field nor a
    // refusal until 0.95: a CDMI client supplying it was answered 201 and the
    // field was gone, and "@graph" — which the field admits nowhere — was
    // accepted.
    const newRel: StoredMeta = { rel: undefined } as StoredMeta;
    applyRel(newRel, body, (f) => f in body, "replace");
    const node = this.store.createQueue(target, name, {
      ...this.newObjectIdentity(body, target, who, false),
      metadata: userMetadata((body.metadata ?? {}) as Record<string, unknown>),
      ...(newRel.rel === undefined ? {} : { rel: newRel.rel }),
      // The domain, the owner and the access control list come from
      // newObjectIdentity above, which the domainURI field governs as it
      // does for a data object: a queue object ignored the field before
      // 0.71, and so was placed in its parent's domain whatever the
      // request said.
    });
    this.store.startCounts(node);
    // The exports and imports fields are checked as they are applied,
    // which is after the object exists. A refused field refuses the
    // create, and a CDMI server performs no part of a refused
    // operation, so the object is removed again. Before this, a queue
    // object created with an MQTT export entry that was refused (a qos
    // of "3", say) answered 400 and remained in the namespace.
    try {
      await this.applyQueueExports(node, body, form, who, ns);
      await this.applyQueueImports(node, body, form, who, ns);
    } catch (err) {
      if (this.exports?.configured(node)) this.exports.set(node, null);
      await this.store.collect(this.store.removeTree(node));
      throw err;
    }
    // A CDMI server begins the query when the query queue is created.
    this.queries(who).offer(node);
    this.notifications().offer(node);
    this.event("cdmi_create_complete", node, ns, who);
    this.applyExtensionFields(node, body, "queue", "complete");
    return this.send(res, 201, MT_QUEUE, this.queueRep(node, ns, name, pv, who), headers);
  }

  /**
   * The representation of an object as a query reports it. The
   * fields are those of the representation clause; a query matches
   * against them and a results specification selects among them.
   *
   * An object the principal of the query may not read is not
   * reported, which is what an operation performed on its behalf
   * would do.
   */
  representationFor(node: Node, ns: string, who: Principal):
    Record<string, unknown> | undefined {
    if (!this.may(node, who, M.READ_METADATA, node.isContainer)) return undefined;
    const m = this.store.meta(node);
    const v = viewOf(this.store, { kind: "store", node });
    const name = ns.replace(/\/$/, "").split("/").pop() ?? "";
    const isQueue = !node.isContainer && m.isQueue;
    const rep: Record<string, unknown> = {
      objectType: node.isContainer
        ? MT_CONTAINER
        : (isQueue ? MT_QUEUE : MT_OBJECT),
      objectID: v.objectID,
      objectName: node.isContainer ? `${name}/` : name,
      parentURI: ns.replace(/[^/]*\/?$/, ""),
      domainURI: this.domainURI(node),
      capabilitiesURI: node.isContainer
        ? "/cdmi_capabilities/container/"
        : (isQueue ? "/cdmi_capabilities/queue/" : "/cdmi_capabilities/dataobject/"),
      metadata: metadataRep(v, !node.isContainer && !isQueue, []),
    };
    if (node.isContainer) {
      const kids = this.store.children(node)
        .filter((c) => !reservedName(c.name))
        .map((c) => (c.node.isContainer ? `${c.name}/` : c.name));
      rep.children = kids;
      rep.childrenrange = kids.length === 0 ? "" : `0-${kids.length - 1}`;
    } else if (!isQueue) {
      rep.mimetype = m.mimetype;
      rep.completionStatus = m.partial ? "Processing" : "Complete";
      // The encoding a read of the object would return. The value
      // itself is read asynchronously and a query reports the
      // fields it can form without awaiting, so it is not reported
      // here; see the notes.
      rep.valuetransferencoding = m.vte ?? "utf-8";
    }
    return rep;
  }

  /**
   * The representation a query matches and reports, which is the one above and,
   * where the query needs it, the "value" field of a data object (0.119,
   * cdmi_query_value).
   *
   * "The value is matched as a base 64 encoded string, whatever the value
   * transfer encoding of the object, so that a condition may be specified for a
   * value that is not a valid UTF-8 string", and a reported value "shall be
   * transported as a base 64 encoded string" likewise — so one form serves both
   * and the field carries it.
   *
   * The value is absent, rather than empty, in four cases, and a condition on it
   * therefore does not match such an object while "!*" does: the object is a
   * container object or a queue object, neither of which has a value field (the
   * values a queue object holds are its queueValues); the access control lists
   * of the object do not permit the principal that owns the query queue to read
   * the value, though they permit its metadata, so that a query discloses
   * nothing a read would refuse; the value cannot be read; or the value is
   * larger than one representation's worth, REPRESENTABLE_LIMIT, which is the
   * bound this server holds every value-bearing response to. The last is a
   * deliberate divergence: the clause says nothing about how large a value a
   * query reads, and a query that matched on the value of objects without limit
   * would be a way for any CDMI client to exhaust the CDMI server.
   */
  private async queryRepresentation(node: Node, ns: string, who: Principal,
    withValue: boolean): Promise<Record<string, unknown> | undefined> {
    const rep = this.representationFor(node, ns, who);
    if (rep === undefined || !withValue) return rep;
    if (rep.objectType !== MT_OBJECT) return rep;
    const ref: ObjRef = { kind: "store", node };
    if (!this.may(ref, who, M.READ_OBJECT, false)) return rep;
    if (this.store.meta(node).size > REPRESENTABLE_LIMIT) return rep;
    try {
      rep.value = (await readValueOf(this.store, ref)).toString("base64");
    } catch { /* the value is not readable, and the field is absent */ }
    return rep;
  }

  private async pathlessQueue(req: IncomingMessage, res: ServerResponse, node: Node,
    sel: Selection, who: Principal, method: string, ns: string): Promise<void> {
    switch (method) {
      case "GET":
      case "HEAD": {
        this.demand(node, who, M.READ_METADATA, false, `reading ${ns}`);
        const rep = this.queueRep(node, ns, "", undefined, who, sel);
        this.store.countAccess(node);
        return this.send(res, 200, MT_QUEUE, rep, {}, method === "HEAD");
      }
      case "POST":
        return this.appendQueue(req, res, node, ns, who);
      case "DELETE": {
        if (sel.queueValues !== undefined) {
          return this.dequeue(res, node, ns, sel.queueValues, who);
        }
        this.demand(node, who, M.DELETE, false, `deleting ${ns}`);
        await this.store.collect(this.store.removeTree(node));
        res.writeHead(204);
        return res.end();
      }
      default:
        res.writeHead(405, { Allow: "GET, HEAD, POST, DELETE" });
        return res.end();
    }
  }

  private pathlessAt(ns: string): Node | undefined {
    const rest = ns.slice(OBJECTID_TREE.length).replace(/\/$/, "");
    if (rest === "" || rest.includes("/")) return undefined;
    let node;
    try {
      node = this.store.byObjectID(rest);
    } catch {
      return undefined;
    }
    const m = this.store.meta(node);
    // A container object created without a name is served through its
    // namespace path all the same, so that everything a container object
    // takes — a listing, a child, an export, an import — applies to it. The
    // path is the name this server assigned, which no client may address;
    // pathOfObjectID notes the object ID URI as the base URI, and the
    // representation reports the object as the root of it.
    if (node.isContainer) return undefined;
    return isAssigned(m.name) ? node : undefined;
  }

  /** A request addressing an object that has no path. */
  private async pathlessRequest(req: IncomingMessage, res: ServerResponse, node: Node,
    sel: Selection, who: Principal, method: string, ns: string): Promise<void> {
    const m = this.store.meta(node);
    if (m.isQueue) return this.pathlessQueue(req, res, node, sel, who, method, ns);
    switch (method) {
      case "GET":
      case "HEAD": {
        this.demand(node, who, M.READ_OBJECT, false, `reading ${ns}`);
        this.store.countAccess(node);
        const v = viewOf(this.store, { kind: "store", node });
        const data = await this.store.readValue(node);
        const utf8 = isUTF8(data);
        const rep: Record<string, unknown> = {
          objectType: MT_OBJECT,
          objectID: m.objectID,
          // No objectName, parentURI or parentID: the object is
          // accessible by ID alone.
          domainURI: this.domainURI(node),
          capabilitiesURI: "/cdmi_capabilities/dataobject/",
          completionStatus: m.partial ? "Processing" : "Complete",
          mimetype: m.mimetype,
          metadata: metadataRep(v, true, sel.metaPrefixes, true),
          valuerange: data.length === 0 ? "" : `0-${data.length - 1}`,
          valuetransferencoding: utf8 ? "utf-8" : "base64",
          value: utf8 ? data.toString("utf8") : data.toString("base64"),
        };
        return this.send(res, 200, MT_OBJECT, applySelection(rep, sel), {},
          method === "HEAD");
      }
      case "PUT":
      case "PATCH": {
        const raw = await readBody(req);
        let body: Record<string, unknown> = {};
        if (raw.length > 0) {
          body = parseBodyJson(raw);
        }
        this.demand(node, who, M.WRITE_OBJECT, false, `updating ${ns}`);
        await this.applyData(node, body, method === "PUT" ? "complete" : "merge", sel,
          m.name, false, who);
        res.writeHead(204);
        return res.end();
      }
      case "DELETE":
        this.demand(node, who, M.DELETE, false, `deleting ${ns}`);
        await this.store.collect(this.store.removeTree(node));
        res.writeHead(204);
        return res.end();
      default:
        res.writeHead(405, { Allow: "GET, HEAD, PUT, PATCH, DELETE" });
        return res.end();
    }
  }

  /** The version an object ID address names, where it names one. */
  private versionAt(ns: string): Node | undefined {
    const rest = ns.slice(OBJECTID_TREE.length);
    if (rest === "" || rest.includes("/")) return undefined;
    let node;
    try {
      node = this.store.byObjectID(rest);
    } catch {
      return undefined;
    }
    return this.store.meta(node).versionOf !== null ? node : undefined;
  }

  /**
   * A request addressing a version. A version is immutable and is
   * presented as a data object; reading one is permitted where the
   * lists permit the principal to read both the version and the
   * version-enabled data object.
   */
  private async versionRequest(req: IncomingMessage, res: ServerResponse, node: Node,
    sel: Selection, who: Principal, method: string, ns: string): Promise<void> {
    const m = this.store.meta(node);
    const owner: Node = { id: m.versionOf!, isContainer: false };
    if (method === "DELETE") return this.deleteVersion(res, node, owner, who);
    if (method !== "GET" && method !== "HEAD") {
      throw forbidden("a version is immutable");
    }
    // The list, the owner and the domain that apply to a version are
    // those of the version-enabled data object, whatever the version
    // stores.
    this.demand(owner, who, M.READ_OBJECT, false, `reading ${ns}`);
    this.demand(owner, who, M.READ_METADATA, false, `reading ${ns}`);
    // Reading a version counts an access on that version.
    this.store.countAccess(node);

    const v = viewOf(this.store, { kind: "store", node });
    const rep: Record<string, unknown> = {
      objectType: MT_OBJECT,
      objectID: m.objectID,
      // A version is accessible by object ID alone, and the common
      // fields require that the objectName, parentURI and parentID
      // fields of such an object do not exist and are not returned.
      capabilitiesURI: "/cdmi_capabilities/dataobject/",
      completionStatus: "Complete",
      mimetype: m.mimetype,
    };
    rep.metadata = {
      ...metadataRep(v, true, sel.metaPrefixes, true),
      ...versionMetadata(this.store, node),
      // The retention and hold in force, taken from the version-enabled data
      // object: "placing it under retention or hold applies the same restrictions
      // to its versions", so the restriction a version is under is the object's
      // and not whatever the version stores — a version stores the metadata the
      // object had when it was created, which for a version made before the
      // retention was applied carries none of it.
      //
      // The provided items are what report this: they state "what the CDMI server
      // can achieve for the object at this time", and what it achieves for a
      // version is the object's restriction. The requested items are not copied,
      // since a CDMI client did not request retention of this version. Until
      // 0.110 a version reported neither, so a CDMI client could not tell a
      // version it may delete from one it may not, and learned the difference
      // from a 409.
      //
      // The document determines none of this: the subclause on access control,
      // ownership and domain names the access control list, the owner and the
      // domain as what a version takes from the version-enabled data object
      // "whatever a version stores", and retention is not among them, although
      // the operations list says the restriction applies to versions. So this is
      // one implementation's reading and not a rule. ECR-231B asks the document
      // to determine it, and recommends none of the candidate answers.
      ...providedItems(this.store.meta(owner).metadata),
    };
    const data = await this.store.readValue(node);
    const utf8 = data.toString("utf8");
    const printable = Buffer.from(utf8, "utf8").equals(data);
    rep.valuerange = data.length === 0 ? "" : `0-${data.length - 1}`;
    rep.valuetransferencoding = printable ? "utf-8" : "base64";
    rep.value = printable ? utf8 : data.toString("base64");
    void req;
    this.send(res, 200, MT_OBJECT, applySelection(rep, sel), {}, method === "HEAD");
  }

  /**
   * Deletes a version. Deleting the current version reverts the
   * current version to its parent, and is refused where it has none;
   * deleting a historical version requires the principal to be
   * permitted to delete both it and the version-enabled data object.
   */
  private async deleteVersion(res: ServerResponse, node: Node, owner: Node,
    who: Principal): Promise<void> {
    const m = this.store.meta(node);
    const om = this.store.meta(owner);
    // "Placing it under retention or hold applies the same restrictions to its
    // versions" (the operations on a version-enabled data object). A version of
    // an object under retention or under hold is therefore not deleted, and until
    // 0.110 every version of one was: the restriction was enforced on the
    // version-enabled data object and on nothing addressed by a version's own
    // object ID.
    //
    // Deleting the current version was the worse of the two, because it is not
    // only a delete. It "reverts the current version to its parent", and the
    // revert takes the parent's metadata with it — so a client that could not
    // write to an object under retention could change its value by deleting the
    // current version, and the metadata that came back with the parent no longer
    // carried the retention. Three requests, none of them mentioned by the
    // retention subclause: delete the current version, and the object reverts and
    // is no longer retained; then delete the object. The retained object is gone.
    this.refuseRestricted(owner, M.DELETE, "deleting a version of this data object");
    if (!this.may(owner, who, M.DELETE, false)) {
      throw forbidden("deleting a version requires DELETE on the data object it " +
        "belongs to, which %s is not granted", who.name);
    }
    if (om.currentVersion === node.id) {
      // Reverting: the parent becomes the current version, and the
      // object takes its state.
      if (m.versionParent === null) {
        throw forbidden(
          "the current version has no parent, and deleting it would leave the data " +
          "object with no version");
      }
      const parent: Node = { id: m.versionParent, isContainer: false };
      const pm = this.store.meta(parent);
      const into = this.store.meta(owner);
      into.mimetype = pm.mimetype;
      into.vte = pm.vte;
      into.metadata = { ...pm.metadata };
      this.store.setMeta(owner, into);
      await this.store.shareValue(owner, parent);
      this.store.setCurrentVersion(owner, parent);
    }
    await this.store.collect(this.store.removeTree(node));
    res.writeHead(204);
    res.end();
  }

  // -----------------------------------------------------------------
  // Snapshots

  /**
   * A request within a cdmi_snapshots container object. The objects of
   * a snapshot are read as any other object is, and are not modified:
   * the forbidden condition is reported for an operation that would
   * create, update or delete one, other than the deletion of the
   * snapshot itself.
   */
  private async snapshotRequest(req: IncomingMessage, res: ServerResponse, r: Resolver,
    ns: string, sel: Selection, who: Principal, method: string): Promise<void> {
    const cut = ns.indexOf(`/${SNAPSHOTS}`);
    const ownerNS = ns.slice(0, cut + 1);
    let rest = ns.slice(cut + 1 + SNAPSHOTS.length);
    if (rest === "") return correctForm(req, res, this.base, ns);
    rest = rest.replace(/^\//, "");

    const ov = await r.view(ownerNS);
    if (ov.unavail) throw ov.unavail;
    const holder = nodeOf(ov.held);
    if (!holder) throw notFound(ns);
    const home = this.store.snapshotHome(holder);
    if (!home) throw notFound(ns);

    // An operation that would create, update or delete within a
    // snapshot is refused before the path is resolved, so that the
    // answer does not depend on whether the object happens to exist.
    if (method !== "GET" && method !== "HEAD" && method !== "DELETE") {
      throw forbidden("an object within a snapshot is not created or changed");
    }

    // The remainder is walked by store lookup: no layer of an import
    // applies within a snapshot.
    const segs = rest.split("/").filter((x) => x !== "");
    let node: Node = home;
    for (const seg of segs) {
      const next = this.store.tryLookup(node, seg);
      if (!next) throw notFound(ns);
      node = next;
    }
    if (node.isContainer !== ns.endsWith("/")) {
      // A container named without its solidus is directed to the form with
      // it; a data object named with one is not directed to the form without
      // it, and names nothing.
      if (node.isContainer) return correctForm(req, res, this.base, ns);
      throw notFound(ns);
    }

    if (method === "DELETE") {
      if (segs.length !== 1) {
        throw forbidden(
          "an object within a snapshot is not deleted; the snapshot itself is");
      }
      // The snapshot itself is deleted, although it is frozen: this
      // is the one operation the rule admits.
      if (!this.may(node, who, M.DELETE, true)) {
        throw forbidden("deleting %s requires DELETE, which %s is not granted",
          ns, who.name);
      }
      await this.store.collect(this.store.removeTree(node));
      res.writeHead(204);
      return res.end();
    }
    if (segs.length === 0) {
      return this.sendSnapshotHome(res, home, sel, method === "HEAD", ownerNS, holder, who);
    }
    return this.sendSnapshotObject(req, res, node, sel, who, ns, method === "HEAD",
      segs.length === 1);
  }

  /**
   * The names of the children of a node within a snapshot, in the form the
   * children field gives them. A reserved name is not among them: "a snapshot
   * shall not include the cdmi_snapshots container object of the container
   * object it is a snapshot of", so a snapshot holds no snapshots of its own.
   */
  private snapshotChildNames(node: Node): string[] {
    return this.store.children(node)
      .filter((c) => !reservedName(c.name))
      .map((c) => (c.node.isContainer ? `${c.name}/` : c.name));
  }

  /**
   * One array of field values for a child within a snapshot, resolved by store
   * lookup and reported by the same mapping the ordinary listing uses. No layer
   * of an import applies within a snapshot, so the child is not imported, its
   * identifiers are not hidden, and it has no importsProvided field.
   */
  private async snapshotChildRow(parentNS: string, parent: Node, kid: string,
    sel: Selection, who: Principal): Promise<unknown[]> {
    const fields = sel.childFields;
    const isContainer = kid.endsWith("/");
    const name = isContainer ? kid.slice(0, -1) : kid;
    const node = this.store.tryLookup(parent, name);
    if (node === undefined) return fields.map((f) => (f === "objectName" ? kid : null));
    const ref: ObjRef = { kind: "store", node };
    const m = viewOf(this.store, ref);
    // Each child's fields follow the child's own access control list, as a read
    // of that child would, exactly as they do outside a snapshot.
    const mayAttrs = this.may(ref, who, M.READ_ATTRIBUTES, isContainer);
    const mayMeta = this.may(ref, who, M.READ_METADATA, isContainer);
    const mayACL = this.may(ref, who, M.READ_ACL, isContainer);
    const mayList = isContainer && this.may(ref, who, M.LIST_CONTAINER, true);
    const kids = mayList && fields.includes("children")
      ? this.snapshotChildNames(node)
      : undefined;
    let bytes: Buffer | undefined;
    if (fields.includes("value") && !isContainer && !this.store.meta(node).isQueue &&
      this.may(ref, who, M.READ_OBJECT, false)) {
      try {
        const data = await this.store.readValue(node);
        const budget = sel.valueBudget;
        if (budget !== undefined && data.length <= budget.left) {
          budget.left -= data.length;
          bytes = data;
        }
      } catch { /* the value is not readable, and is declined */ }
    }
    return this.childRowFields({
      fields, kid, isContainer, name, parentURI: parentNS, parent, ref, m,
      layer: { imported: false, via: [], hideIDs: false },
      governs: undefined, mayAttrs, mayMeta, mayACL, kids, importsProvided: null,
      bytes, asUTF8: bytes !== undefined && isUTF8(bytes), who,
    });
  }

  /** The children of a node within a snapshot, recursively, as the ordinary
   * listing reports them. */
  private async snapshotRecursive(parentNS: string, node: Node, sel: Selection,
    who: Principal, depth: number): Promise<unknown[]> {
    if (depth < 0) return [];
    if (!this.may({ kind: "store", node }, who, M.LIST_CONTAINER, true)) return [];
    const out: unknown[] = [];
    for (const k of this.snapshotChildNames(node)) {
      const row: unknown = sel.childFields.length > 0
        ? await this.snapshotChildRow(parentNS, node, k, sel, who)
        : k;
      out.push(row);
      if (k.endsWith("/") && depth - 1 >= 1) {
        const under = this.store.tryLookup(node, k.slice(0, -1));
        if (under !== undefined) {
          const below = await this.snapshotRecursive(parentNS + k, under, sel, who, depth - 1);
          if (!nestChildren(row, below, sel)) out.push(below);
        }
      }
    }
    return out;
  }

  /**
   * The childrenrange and children fields of a container object within a
   * snapshot, honouring the range, the extended form and the recursive form.
   *
   * Until 0.124 the two snapshot senders built the children field as plain
   * strings and left the selection to applySelection, which chooses the fields
   * of a representation and cannot apply a range or report a field per child.
   * So a request naming childfields, childrecursive or a range of children was
   * answered 200 with a listing that ignored it -- plain strings where arrays
   * were asked for, one level where a recursive listing was asked for, and every
   * child with a childrenrange that said otherwise. The capability object of a
   * snapshot publishes cdmi_list_children_extended and
   * cdmi_list_children_recursive, so the server advertised what it then ignored.
   * "A snapshot is itself a container object ... A CDMI client reads a snapshot,
   * and the objects within it, by the operations that apply to any container
   * object" (revision 365). Reported by the cvwm implementer.
   */
  private async snapshotChildren(parentNS: string, node: Node, sel: Selection,
    who: Principal, names = this.snapshotChildNames(node)):
    Promise<{ childrenrange: string; children: unknown[] }> {
    let lo = 0;
    let hi = names.length - 1;
    if (sel.childRange) {
      [lo, hi] = sel.childRange;
      if (hi > names.length - 1) hi = names.length - 1;
    }
    if (names.length === 0 || lo > hi) return { childrenrange: "", children: [] };
    const children: unknown[] = [];
    for (const k of names.slice(lo, hi + 1)) {
      const row: unknown = sel.childFields.length > 0
        ? await this.snapshotChildRow(parentNS, node, k, sel, who)
        : k;
      children.push(row);
      const below = (sel.childDepth ?? Infinity) - 1;
      if (sel.recursive && k.endsWith("/") && below >= 1) {
        const under = this.store.tryLookup(node, k.slice(0, -1));
        if (under !== undefined) {
          const deeper = await this.snapshotRecursive(parentNS + k, under, sel, who, below);
          if (!nestChildren(row, deeper, sel)) children.push(deeper);
        }
      }
    }
    return { childrenrange: `${lo}-${hi}`, children };
  }

  /** The reserved container object that holds the snapshots. */
  private async sendSnapshotHome(res: ServerResponse, home: Node, sel: Selection,
    head: boolean, ownerNS: string, holder: Node, who: Principal): Promise<void> {
    // Every child of this container object is a snapshot, so each is listed
    // with a trailing solidus.
    const kids = this.store.children(home).map((c) => `${c.name}/`);
    const listing = await this.snapshotChildren(`${ownerNS}${SNAPSHOTS}/`, home, sel,
      who, kids);
    const rep: Record<string, unknown> = {
      objectType: MT_CONTAINER,
      objectName: `${SNAPSHOTS}/`,
      parentURI: ownerNS,
      parentID: this.store.meta(holder).objectID,
      // A frozen container object: a CDMI client creates and deletes nothing
      // within it, the snapshots it holds being created through the container
      // object they are snapshots of and deleted by addressing them directly.
      capabilitiesURI: "/cdmi_capabilities/snapshot_container/",
      completionStatus: "Complete",
      metadata: {},
      childrenrange: listing.childrenrange,
      children: listing.children,
    };
    this.send(res, 200, MT_CONTAINER, applySelection(rep, sel), {}, head);
  }

  /** A snapshot, or an object within one. */
  private async sendSnapshotObject(req: IncomingMessage, res: ServerResponse, node: Node,
    sel: Selection, who: Principal, ns: string, head: boolean,
    /** Whether the object addressed is a snapshot itself rather than one of the
     *  objects within it: the one object of a snapshot a client may delete. */
    itself: boolean): Promise<void> {
    const m = this.store.meta(node);
    this.demand(node, who, node.isContainer ? M.LIST_CONTAINER : M.READ_OBJECT,
      node.isContainer, `reading ${ns}`);
    const cut = ns.replace(/\/$/, "").lastIndexOf("/");
    // An objectID field where the snapshot pinned a version: an object
    // that has one is addressable by it, and a pinned version is. An
    // entry that was copied has none. See S1.
    // A queue object of a snapshot is a queue object: a snapshot
    // presents the state of the objects at a point in time, and for
    // a queue object that state is the values it held.
    const isQueue = !node.isContainer && m.isQueue;
    const rep: Record<string, unknown> = {
      objectType: node.isContainer ? MT_CONTAINER : (isQueue ? MT_QUEUE : MT_OBJECT),
      // The identifier of the version pinned, where one is: the entry
      // is that version, and is addressed by it. An entry that had to
      // be copied has none.
      ...(m.pinnedID !== null ? { objectID: m.pinnedID } : {}),
      objectName: ns.replace(/\/$/, "").slice(cut + 1) + (node.isContainer ? "/" : ""),
      parentURI: ns.slice(0, cut + 1),
      // The capability objects of a frozen object. A snapshot itself is the one
      // a CDMI client may delete, and it is the object whose path names it
      // directly beneath the reserved container: anything deeper is within a
      // snapshot and is deleted by no operation.
      capabilitiesURI: !node.isContainer
        ? (isQueue
          ? "/cdmi_capabilities/snapshot_queue/"
          : "/cdmi_capabilities/snapshot_dataobject/")
        : (itself
          ? "/cdmi_capabilities/snapshot/"
          : "/cdmi_capabilities/snapshot_container/"),
      completionStatus: "Complete",
    };
    if (!node.isContainer && !isQueue) rep.mimetype = m.mimetype;
    // "The domainURI field applies to every representation other than that of a
    // capability object, as a capability object is generated by the CDMI server
    // and is not owned by a domain" (revision 365). An object within a snapshot
    // is not a capability object, and the domain that owns the object owns the
    // snapshot of it. The field was absent until 0.126, and the entry was owned
    // by no domain for snapshot creation to report (Store.fill).
    rep.domainURI = this.domainURI(node);
    // No parentID, although "for objects in a container, the parentID field
    // shall be returned" and an object within a snapshot is in one. The field
    // is the "object ID of the parent container object, in the form given for
    // the objectID field", and the parent here reports no objectID of its own:
    // a snapshot is addressable by object ID only where versions are supported,
    // which is finding S1 of NOTES-on-snapshots.md. Returning one would hand a
    // client an identifier for an object whose own representation says it has
    // none, and which answers 404. Added in 0.126 and taken out again the same
    // day, the test that asserts its absence having the better argument.
    // "Where the object is accessible through no export, the value shall be an
    // empty JSON array", and nothing within a snapshot is: "the exports field
    // shall not be preserved in a snapshot". The field applies to data object,
    // container object and queue object representations, so it is reported
    // rather than omitted. Absent until 0.126.
    rep.exportsProvided = [];
    rep.rel = relRep(m);
    // The metadata as a read of an ordinary object assembles it, which includes
    // the data system metadata inherited from the container objects above —
    // within a snapshot, the snapshot's own containers, which carry what they
    // carried when it was taken. Until 0.126 this passed three of the arguments
    // and so reported neither the inherited items nor their _provided items, the
    // third time that omission has been found in a second assembly of one field.
    rep.metadata = metadataRep(viewOf(this.store, { kind: "store", node }),
      !node.isContainer, sel.metaPrefixes, true, true, true,
      who.privileges.includes("domain_kms_admin"),
      this.lockCovering(ns)?.lock,
      this.effectiveDataSystemItem(node, "cdmi_sanitization_method"),
      this.inheritedDataSystem(node));
    if (isQueue) {
      const values = this.store.queueValues(node);
      rep.queueValues = values.length === 0
        ? ""
        : `${values[0].designator}-${values[values.length - 1].designator}`;
      rep.mimetype = values.map((v) => v.mimetype);
      rep.valuetransferencoding = values.map((v) => v.vte);
      rep.valuerange = values.map((v) =>
        v.body.length === 0 ? "" : `0-${v.body.length - 1}`);
      rep.value = values.map((v) =>
        v.vte === "json"
          ? JSON.parse(v.body.toString("utf8"))
          : v.vte === "base64"
          ? v.body.toString("base64")
          : v.body.toString("utf8"));
    } else if (node.isContainer) {
      const listing = await this.snapshotChildren(ns, node, sel, who);
      rep.childrenrange = listing.childrenrange;
      rep.children = listing.children;
    } else {
      // The value, through the one responder both senders use, so that a range
      // of an object within a snapshot is the range asked for, several ranges
      // travel as a multipart body as they do elsewhere, and the value is
      // returned "only where it is explicitly selected" (revision 221) rather
      // than on every read. Until 0.125 this branch had the single-range case
      // written out again, refused several ranges, and returned the whole value
      // whether it was selected or not.
      rep.valuetransferencoding = m.vte || "utf-8";
      // An object within a snapshot has no derived representation to serve in
      // place of the one it holds, so the octets and their length are its own,
      // and the gaps in its value are those this server recorded.
      if (await this.sendValueField({
        req, res, rep, sel, head, mayValue: true, valueSize: m.size, vte: m.vte,
        contiguous: m.contiguous, ranges: this.store.ranges(node),
        readAt: (first, length) => this.store.readValue(node, first, length),
      })) return;
    }
    this.send(res, 200, node.isContainer ? MT_CONTAINER : MT_OBJECT,
      applySelection(rep, sel), {}, head);
  }

  /**
   * Creates a snapshot of a container object. The value file of every
   * data object within it is shared rather than copied, so the
   * operation completes in proportion to the number of objects and not
   * to the quantity of data.
   */
  private snapshot(node: Node, ns: string, value: unknown, who: Principal): void {
    if (typeof value !== "string" || value === "") {
      throw invalidField("snapshot", "the snapshot field names the snapshot to create");
    }
    if (!presentable(value) || value.includes("/")) {
      throw invalidField("snapshot", "%j is not a name an object may have", value);
    }
    this.demand(node, who, M.ADD_SUBCONTAINER, true, `creating a snapshot of ${ns}`);
    const home = this.store.snapshotHome(node, true)!;
    if (this.store.tryLookup(home, value)) {
      throw alreadyExists("a snapshot named %j already exists", value);
    }
    this.store.snapshotTree(node, home, value);
    // A snapshot of a container object has been created. The
    // notification reports the container object it was taken of.
    this.event("cdmi_snapshot", node, ns, who);
  }

  /**
   * Creates a version where the update calls for one. The level says
   * which updates count: a change of the value, a change of the value
   * or the user metadata, or any update at all.
   *
   * Enabling versioning for an object that has none creates the
   * current version, and enabling it again for an object whose
   * versioning was disabled creates a new current version.
   */
  private async versionOnUpdate(node: Node, before: StoredMeta,
    changed: { value: boolean; userMetadata: boolean }): Promise<void> {
    const after = this.store.meta(node);
    const level = versioningLevel(after);
    if (level === undefined) return;
    if (versioningLevel(before) === undefined) {
      // Versioning has just been enabled. Where it was enabled before
      // and disabled, the versions that exist are preserved and a new
      // current version is created.
      this.store.createVersion(node);
      await this.applyVersionLimits(node);
      return;
    }
    const counts = level === "all" ||
      (level === "user" && (changed.value || changed.userMetadata)) ||
      (level === "value" && changed.value);
    if (counts) this.store.createVersion(node);
    // The limits are applied whether or not this update created a
    // version: an update that changes a limit takes effect at once.
    await this.applyVersionLimits(node);
  }

  /**
   * Discards historical versions until the limits the object states
   * are satisfied. Versions go from the oldest to the newest, and the
   * current version is never discarded.
   */
  private async applyVersionLimits(node: Node): Promise<void> {
    const m = this.store.meta(node);
    const limit = (item: string): number | undefined => {
      const v = m.metadata[item];
      return typeof v === "string" && /^[0-9]+$/.test(v) ? Number(v) : undefined;
    };
    const count = limit("cdmi_versions_count");
    const age = limit("cdmi_versions_age");
    const size = limit("cdmi_versions_size");
    if (count === undefined && age === undefined && size === undefined) return;

    // The historical versions, oldest first. The current version is
    // not among them: a limit never discards it.
    let historical = this.store.versionsOf(node)
      .filter((v) => v.id !== m.currentVersion);
    const sizeOf = (v: Node) => this.store.meta(v).size;
    const now = Date.now();

    const drop = async (v: Node) => {
      await this.store.collect(this.store.removeTree(v));
      historical = historical.filter((x) => x.id !== v.id);
    };

    // An age limit discards a version once its age in seconds since
    // creation is greater than the value.
    if (age !== undefined) {
      for (const v of [...historical]) {
        if ((now - this.store.meta(v).ctime) / 1000 > age) await drop(v);
      }
    }
    // A count of zero retains the current version alone.
    if (count !== undefined) {
      while (historical.length > count) await drop(historical[0]);
    }
    if (size !== undefined) {
      let total = historical.reduce((n, v) => n + sizeOf(v), 0);
      while (historical.length > 0 && total > size) {
        total -= sizeOf(historical[0]);
        await drop(historical[0]);
      }
    }
  }

  /**
   * One array of field values for a child, in the order named, from inputs its
   * caller has resolved. Two callers resolve a child differently and must then
   * report it identically: the ordinary listing resolves through the layering
   * engine, and a listing within a snapshot walks the store, "a snapshot [being]
   * itself a container object" whose objects "a CDMI client reads ... by the
   * operations that apply to any container object" (revision 365). Keeping the
   * mapping here is what stops the two drifting, which is how a child's metadata
   * came to omit four items that a read of the child reports.
   */
  private childRowFields(a: {
    fields: string[];
    kid: string;
    isContainer: boolean;
    name: string;
    parentURI: string;
    parent: Node | undefined;
    ref: ObjRef;
    m: ObjectView;
    layer: { imported: boolean; via: Provided[]; hideIDs: boolean };
    governs: Node | undefined;
    mayAttrs: boolean;
    mayMeta: boolean;
    mayACL: boolean;
    kids: unknown[] | undefined;
    /** The importsProvided field of the child, which only its caller can resolve. */
    importsProvided: unknown;
    bytes: Buffer | undefined;
    asUTF8: boolean;
    who: Principal;
  }): unknown[] {
    return a.fields.map((f) => {
      if (f === "objectName") return a.kid;
      if (f === "metadata") {
        if (!(a.mayAttrs || a.mayMeta)) return null;
        // The metadata of the child, assembled exactly as a read of the child
        // assembles it. "The contents of that array [are] the values of the
        // requested a.fields" (revision 365), so the value reported for the
        // metadata field is the child's metadata field and not a subset of it: a
        // row that carries the field but drops items from it is not a field
        // declined, which a client is to treat as unknown, but an answer, and a
        // client reading one cannot tell that it is incomplete.
        //
        // Until 0.123 this called metadataRep with three of its arguments and
        // dropped four items that a read reports: cdmi_version_current and
        // cdmi_version_oldest, so a client listing a container could not see
        // which children were version-enabled -- reported by the cvwm
        // implementer, whose Open dialog showed no version badge -- and the
        // inherited data system metadata, cdmi_data_redundancy and its
        // _provided item among them, so a listing could not show which children
        // were replicated either. The lock, the sanitization method and the
        // items a domain_kms_admin sees were omitted by the same token.
        //
        // A metadata prefix selection is deliberately not passed on: it selects
        // items of the object being read, where this field is the whole metadata
        // field of a child.
        const node = nodeOf(a.ref);
        const md = metadataRep({ ...a.m, acl: this.reportedAcl(a.m, a.layer, a.governs) },
          !a.isContainer, [], a.mayACL, a.mayAttrs, a.mayMeta,
          a.who.privileges.includes("domain_kms_admin"),
          this.lockCovering(a.parentURI + a.kid)?.lock,
          node !== undefined
            ? this.effectiveDataSystemItem(node, "cdmi_sanitization_method")
            : undefined,
          node !== undefined ? this.inheritedDataSystem(node) : undefined);
        if (a.mayMeta && node !== undefined) {
          Object.assign(md, versionMetadata(this.store, node));
        }
        return md;
      }
      if (f === "children") return a.kids ?? null;
      // Of a child that is not a reference, the location is null.
      if (f === "location") return null;
      if (!a.mayAttrs) return null;
      switch (f) {
        case "objectType":
          // A queue object is neither a container object nor a data
          // object, and its a.name carries no trailing solidus, so the
          // type reported for it is the only thing that tells a client
          // which media type to ask for.
          return a.isContainer
            ? MT_CONTAINER
            : (nodeOf(a.ref) !== undefined && this.store.meta(nodeOf(a.ref)!).isQueue
              ? MT_QUEUE
              : MT_OBJECT);
        case "objectID": return a.layer.hideIDs ? null : (a.m.objectID ?? null);
        case "objectName": return a.kid;
        case "parentURI": return a.parentURI;
        case "parentID":
          return a.parent === undefined
            ? null
            : viewOf(this.store, { kind: "store", node: a.parent }).objectID ?? null;
        case "capabilitiesURI":
          return a.layer.imported
            ? (a.isContainer ? "/cdmi_capabilities/imported_container/"
              : "/cdmi_capabilities/imported_dataobject/")
            : (a.isContainer ? "/cdmi_capabilities/container/"
              : "/cdmi_capabilities/dataobject/");
        case "completionStatus": return "Complete";
        case "mimetype":
          return a.isContainer ? null : (a.m.mimetype || guessMimetype(a.name, a.m.vte || "base64"));
        case "valuetransferencoding":
          if (a.isContainer) return null;
          // Where the value is carried in this listing, the encoding reported is
          // the encoding it is carried in, as it is in a read of the object.
          return a.bytes === undefined ? (a.m.vte || "base64") : (a.asUTF8 ? "utf-8" : "base64");
        case "value":
          if (a.bytes === undefined) return null;
          return a.asUTF8 ? a.bytes.toString("utf8") : a.bytes.toString("base64");
        case "valuerange":
          // The range of the value the child holds, which is known from its size
          // and needs no read: a read of the object reports it the same way.
          return a.isContainer ? null : (a.m.size === 0 ? "" : `0-${a.m.size - 1}`);
        case "importsProvided":
          // Resolved by the caller: the layered listing reads it from the
          // child's own view, and a listing within a snapshot has none, "an
          // imports field within [a snapshot being] not processed".
          return a.importsProvided;
        case "rel": {
          const node = nodeOf(a.ref);
          return node ? this.store.meta(node).rel ?? null : null;
        }
        default: return null;
      }
    });
  }

  /** One array of field values for each child, in the order named. */
  private async childFieldValues(cv: View, kid: string, sel: Selection,
    who: Principal): Promise<unknown[]> {
    const fields = sel.childFields;
    const isContainer = kid.endsWith("/");
    const name = isContainer ? kid.slice(0, -1) : kid;
    // A reference is listed by its name with a trailing "?", and has no other
    // field: "[ null, "MyReference?", null ]" (the namespace discovery
    // example). Before 0.44 it was looked up as a data object, found as
    // nothing, and every field reported null, its name included.
    if (kid.endsWith("?")) {
      // A reference has no representation: its name, and where the listing
      // names it, the URI it redirects to (revision 297).
      const to = referenceIn(this.store, cv, kid.slice(0, -1));
      return fields.map((f) => f === "objectName" ? kid : f === "location" ? to ?? null : null);
    }
    if (RESERVED_CHILDREN.includes(kid)) {
      // A reserved child of the root container object is not an object
      // of the store, and has the fields the section defining it gives.
      return fields.map((f) => {
        switch (f) {
          case "objectType":
            return kid === "cdmi_capabilities/" ? MT_CAPABILITY
              : kid === "cdmi_domains/" ? MT_DOMAIN : MT_CONTAINER;
          case "objectName": return kid;
          case "parentURI": return "/";
          case "capabilitiesURI":
            return kid === "cdmi_capabilities/" ? "/cdmi_capabilities/capability/"
              : kid === "cdmi_domains/" ? "/cdmi_capabilities/domain/"
              : "/cdmi_capabilities/container/";
          case "completionStatus": return "Complete";
          case "metadata": return {};
          default: return null;
        }
      });
    }
    const r = new Resolver(this.store, { principal: who });
    let ref: ObjRef;
    let layer: Layer;
    let child: View | undefined;
    if (isContainer) {
      try {
        child = await r.child(cv, name);
        ref = refOfDir(child.held);
        layer = child.objLayer;
      } catch {
        // A child that is not an ordinary container (the container of the
        // snapshots, say) is still reported by the name it is listed by.
        return fields.map((f) => f === "objectName" ? kid : null);
      }
    } else {
      const found = await resolveFile(this.store, cv, name);
      if (!found) return fields.map(() => null);
      ref = found.ref;
      layer = found.layer;
    }
    const m = viewOf(this.store, ref);
    const parent = nodeOf(cv.held);
    // Each child's fields follow the child's own access control list, as a
    // read of that child would: the attribute fields by READ_ATTRIBUTES, the
    // metadata by READ_METADATA and READ_ATTRIBUTES, and its children by
    // LIST_CONTAINER. A field withheld is reported null, which in an extended
    // listing reports an absent field. The name is always reported, listing
    // having disclosed it. Before 0.44 nothing here was checked, so a principal
    // that could list a container read every child's metadata, cdmi_acl
    // included.
    const governs = governedBy(cv);
    const mayAttrs = this.may(ref, who, M.READ_ATTRIBUTES, isContainer, governs);
    const mayMeta = this.may(ref, who, M.READ_METADATA, isContainer, governs);
    const mayACL = this.may(ref, who, M.READ_ACL, isContainer, governs);
    const mayList = isContainer && this.may(ref, who, M.LIST_CONTAINER, true, governs);
    const kids = mayList && fields.includes("children") && child !== undefined
      ? await listChildren(this.store, child)
      : undefined;
    // The value of the child, where the listing names it. Read once, before the
    // fields are assembled, because the encoding reported by
    // valuetransferencoding has to be the encoding the value is carried in.
    //
    // Declined, and reported as null, where: the child is a container object or a
    // queue object, neither of which has a value field; the access control lists
    // of the child do not permit this principal to read its value; the value
    // cannot be read; or what remains of this request's budget will not hold it.
    let bytes: Buffer | undefined;
    if (fields.includes("value") && !isContainer) {
      const node = nodeOf(ref);
      const isQueue = node !== undefined && this.store.meta(node).isQueue;
      if (!isQueue && this.may(ref, who, M.READ_OBJECT, false, governs)) {
        try {
          const data = await readValueOf(this.store, ref);
          const budget = sel.valueBudget;
          if (budget !== undefined && data.length <= budget.left) {
            budget.left -= data.length;
            bytes = data;
          }
        } catch { /* the value is not readable, and is declined */ }
      }
    }
    const asUTF8 = bytes !== undefined && isUTF8(bytes);
    return this.childRowFields({
      fields, kid, isContainer, name, parentURI: cv.ns, parent, ref, m, layer, governs,
      mayAttrs, mayMeta, mayACL, kids, bytes, asUTF8, who,
      importsProvided: isContainer
        ? (child!.objLayer.via.length ? importsProvidedFor(child!) : null)
        : (layer.via.length ? layer.via : null),
    });
  }

  // -----------------------------------------------------------------
  // Write

  private async write(req: IncomingMessage, res: ServerResponse, r: Resolver,
    ns: string, sel: Selection, who: Principal, merge: boolean): Promise<void> {
    const raw = await readBody(req);
    const ct = mediaTypeOf(req.headers["content-type"] as string);
    // "The Content-Type header field specifies the type of the object to be
    // created", and "a trailing solidus is required in the name of a
    // container object ... and is not permitted in the name of a data
    // object or a queue object". A request that names a container object
    // at a name without the solidus asks for an object that cannot bear
    // that name, which is the invalid field condition; this server created
    // one before 0.71 (weedmi BHTP-001).
    // The object ID tree is addressed by its own operations, which name no
    // object, so the form of that path says nothing about a type.
    if (ns !== OBJECTID_TREE) {
      if (ct === MT_CONTAINER && !ns.endsWith("/")) {
        throw invalidField("objectName",
          "a container object is named with a trailing solidus, and %j has none", ns);
      }
      if ((ct === MT_OBJECT || ct === MT_QUEUE) && ns.endsWith("/")) {
        throw invalidField("objectName",
          "a %s is named without a trailing solidus, and %j has one",
          ct === MT_QUEUE ? "queue object" : "data object", ns);
      }
    }
    // A request that carries a body carries a Content-Type naming what the
    // body is: without one the request "does not contain a representation
    // and is therefore not a request of this protocol binding", which is
    // 415 rather than a create of whatever the body happened to hold
    // (weedmi BHTP-001).
    if (ct === "" && raw.length > 0) {
      throw new Condition(415, "", "The media type is not supported.",
        "a request with a body carries a Content-Type header field naming a CDMI media type");
    }
    if (ct !== "" && ct !== MT_OBJECT && ct !== MT_CONTAINER && ct !== MT_QUEUE &&
      ct !== `${MT_OBJECT}+json` && ct !== `${MT_CONTAINER}+json` &&
      ct !== `${MT_QUEUE}+json`) {
      throw new Condition(415, "", "The media type is not supported.",
        `${ct} is not a CDMI media type; the value of an object is transported through an export`);
    }
    let body: Record<string, unknown> = {};
    if (raw.length > 0) {
      body = parseBodyJson(raw);
      if (body === null || typeof body !== "object" || Array.isArray(body)) {
        throw malformed("the message body shall be a JSON object");
      }
    } else if (merge) {
      throw malformed("a merge update requires a message body");
    }
    if (merge && sel.any) {
      throw invalidSelection("", "a merge update does not take a field selection");
    }
    // Complete replacement where no selection appears, field-constrained
    // where one does, merge for PATCH.
    const form = merge ? "merge" : sel.any ? "selected" : "complete";
    // "A CDMI server shall report an error where a field selection names a
    // field that is not supplied in the request representation" (7.4.4).
    // The selection says which fields of the request are applied; naming
    // one the request does not carry asks for something that is not there.
    // 7.4.7 governs the response separately: the fields named are returned.
    // This server dropped the check in 0.67 and restores it in 0.71
    // (weedmi OPER-004).
    if (form === "selected") {
      for (const f of sel.fields) {
        if (!(f in body)) {
          throw invalidSelection(f,
            "the field selection names %j, which the representation does not supply", f);
        }
      }
    }

    // The object ID tree takes a move, which removes the path of an
    // object, and nothing else: it is a reserved child of the root
    // container object.
    if (ns === OBJECTID_TREE && !("move" in body)) {
      throw forbidden("%s is a reserved child of the root container object", ns);
    }

    // Exactly one declarative request field is supplied in a single
    // operation.
    // A copy or move presents no credential of this server: the draft defines
    // none for it. The credential_id field this server once accepted here is
    // refused, so that a CDMI client relying on it learns that it no longer
    // has effect rather than having its request made anonymously unawares.
    if (("copy" in body || "move" in body) && "credential_id" in body) {
      throw invalidField("/credential_id",
        "a copy or move presents no credential of this CDMI server, and credential_id is not a " +
        "field of this request; the source is read without one");
    }
    // Every field is classified before anything is created, so that a field
    // refused leaves no object behind (fields.ts): a field of another object
    // type, or a reserved name, is an invalid field, and an extension field
    // holding null within it is malformed.
    const kind = kindOf(ct);
    if (kind !== undefined) bodyExtensions(body, kind);
    const declared = ["reference", "copy", "move", "snapshot", "serialize",
      "deserialize", "deserializevalue"].filter((f) => f in body);
    // "... or a declarative request field is supplied together with a
    // field it excludes": a declarative field says where the object comes
    // from, so a value or a set of children supplied beside it says the
    // same thing twice and differently (weedmi OPER-017).
    // A reference excludes every other field, which the check below it
    // reports in those terms; this one is for the fields that supply
    // content beside a source.
    if (declared.length === 1 && declared[0] !== "reference") {
      for (const excluded of ["value", "valuerange", "children", "childrenrange"]) {
        if (excluded in body) {
          throw conflictingFields(excluded,
            "the %j field takes the content of the object from its source, and %j supplies it too",
            declared[0], excluded);
        }
      }
    }
    if (declared.length > 1) {
      // "More than one declarative request field is supplied, or a
      // declarative request field is supplied together with a field it
      // excludes" is the conflicting fields condition, which this server
      // reported as an invalid field before 0.66 (weedmi OPER-016, OPER-017).
      throw conflictingFields(declared[1],
        "exactly one declarative request field is supplied in one operation, and %j " +
        "and %j were both", declared[0], declared[1]);
    }
    if (!merge && "reference" in body) {
      // A reference is not an object and has no representation.
      return this.createReference(res, r, ns, body, who);
    }
    if ("copy" in body || "move" in body) {
      // A copy or move is a create, and is made conditional as one is: "A
      // CDMI client that requires the operation to fail rather than replace
      // an existing object" says so by If-None-Match. The conditions were not
      // evaluated for a copy or move before 0.46, which replaced the object,
      // and a move then removed its source as well.
      await this.createConditions(req, r, ns);
      // The media type of the request names the representation to
      // be created, as it does for every other operation, so it
      // decides whether a data object is created from a queue
      // object. The objectType field of the body says the same
      // where a CDMI client supplies it.
      // A name denotes one object: a copy of it copies every representation
      // it has, and a move moves them all (5.3.7). The representation the
      // request names is created first, and each other representation of
      // the source is then established at the target.
      await this.copyOrMove(res, r, ns, body, who, "move" in body, ct);
      return this.carryOtherRepresentations(r, ns, body, who, "move" in body);
    }
    if ("serialize" in body) {
      return this.serializeInto(res, r, ns, body, who);
    }
    if ("deserialize" in body || "deserializevalue" in body) {
      return this.deserializeInto(res, r, ns, body, who, ct);
    }
    if ("snapshot" in body) {
      // A snapshot is created by an update operation on a container
      // object that exists.
      if (!ns.endsWith("/")) {
        throw invalidField("snapshot", "a snapshot is taken of a container object");
      }
      const cv = await r.view(ns);
      if (cv.unavail) throw cv.unavail;
      // A snapshot of a container object presented through an import
      // would be held by the import source, and is refused whether or
      // not this server happens to hold the objects.
      const node = nodeOf(cv.held);
      if (!node || cv.objLayer.via.length > 0) {
        // "A CDMI server shall not create a snapshot of a container object
        // presented through an import, and shall report the capability not
        // present condition for an operation that requests one ... This
        // applies to an import of every type, including one whose import
        // source is this CDMI server." The capability is the one that
        // creates a snapshot, which such a container object does not offer.
        // This server reported the forbidden condition until 0.83, which
        // says the principal may not do it where the truth is that no
        // principal may (weedmi IMPT-001, whose citation this is).
        throw capabilityNotPresent("cdmi_create_snapshot",
          `${this.base}cdmi_capabilities/imported_container/`,
          `${ns} is presented through an import, and a snapshot of it would be held ` +
          "by the import source");
      }
      if (this.store.meta(node).frozen) {
        throw forbidden("an object within a snapshot is not changed");
      }
      this.snapshot(node, ns, body.snapshot, who);
      res.writeHead(204);
      return res.end();
    }

    if (ns === "/") {
      // The root container object exists; an operation on it is a change.
      const rv = await r.rootView();
      if (changesUserMetadata(body) || "imports" in body || "exports" in body) {
        this.demand(rv.held, who, M.WRITE_METADATA, true, "changing /");
      }
      const target = await ensureWriteTarget(this.store, rv);
      this.applyContainerFields(target, "/", await this.withBoundImports(target, body, who), form, sel, false, who);
      res.writeHead(204);
      return res.end();
    }
    const { parentNS, name, isContainer } = this.split(ns);
    const pv = await r.view(parentNS);
    if (pv.unavail) throw pv.unavail;
    if (!presentable(name)) {
      throw invalidField("objectName", "%j is a name a CDMI client may not create", name);
    }
    if (ct === MT_QUEUE || ct === `${MT_QUEUE}+json`) {
      // A queue object is created by the media type of the request:
      // the name of a queue object carries no trailing solidus, so
      // the form of the path does not distinguish it from a data
      // object as it does a container object.
      if (isContainer) {
        throw invalidField("objectName",
          "a queue object is not a container object, and its name does not end in a " +
          "solidus");
      }
      return this.putQueue(res, r, pv, ns, name, body, form, who, sel.fields);
    }
    return isContainer
      ? this.putContainer(req, res, r, pv, ns, name, body, form, sel, who)
      : this.putData(req, res, r, pv, ns, name, body, form, sel, who);
  }

  /**
   * Creates or updates a queue object. A queue object holds an
   * ordered sequence of values; the values it holds are not changed by
   * an update, and are appended by the operation of phase two.
   */
  private async putQueue(res: ServerResponse, r: Resolver, pv: View,
    ns: string, name: string, body: Record<string, unknown>, form: string,
    who: Principal, selected: string[] = []): Promise<void> {
    // An MQTT export publishes the values a queue object holds, and
    // an MQTT import enqueues to one what it receives, so a queue
    // object carries both fields. The export machinery refuses an
    // entry of any other type placed here.

    // The fields a client does not supply on a queue object. The
    // values are appended by the append operation and are not set
    // here, and the three arrays that describe them are server
    // populated or accompany an append.
    for (const f of ["queueValues", "valuerange"]) {
      if (f in body) {
        throw invalidField(f,
          "the %j field is CDMI server populated and is ignored in a create or update",
          f);
      }
    }

    const found = await resolveFile(this.store, pv, name);
    const target = await ensureWriteTarget(this.store, pv);

    // The media type names the representation this request acts
    // upon. A create that names a form the name does not yet denote
    // establishes it, which is how a second representation of a name
    // comes about; an update does not establish one.
    const held = found === undefined ? undefined : nodeOf(found.ref);
    const queue = held !== undefined && this.store.meta(held).isQueue
      ? held
      : this.store.lookupKind(target, name, "queue");
    if (queue === undefined) {
      // A merge update establishes no queue object; a create carrying a field
      // selection applies only the selected fields (the Create subclause).
      if (form === "merge") {
        throw notFound(
          `${ns}: the name denotes no queue object representation, and a merge update ` +
          "does not establish one");
      }
      // "A name shall not denote both a data object representation and a queue
      // object representation. A CDMI server shall report the conflict
      // condition where an operation would establish one at a name that
      // denotes the other" (revision 365).
      if (held !== undefined && !held.isContainer && !this.store.meta(held).isQueue) {
        throw conflict("%s denotes a data object representation, and a name does not denote " +
          "a data object representation and a queue object representation at once", ns);
      }
      const applied = form === "selected"
        ? Object.fromEntries(Object.entries(body).filter(([k]) => selected.includes(k)))
        : body;
      return this.createQueueAt(res, pv, target, ns, name, applied, form, who);
    }

    const node = queue;
    const m = this.store.meta(node);
    // The values a queue object holds are not changed by an update.
    // An update that does nothing but extend a retention period or
    // add a hold is permitted on an object under either, so the
    // restriction is not applied to it: checkChange above has
    // already refused a shortening or a release.
    const extendsOnly = typeof body.metadata === "object" &&
      body.metadata !== null &&
      !changesMore((body.metadata ?? {}) as Record<string, unknown>, m.metadata,
        form === "merge");
    this.demand(node, who, M.WRITE_METADATA, false, `updating ${ns}`, undefined,
      extendsOnly);
    const supplied = userMetadata((body.metadata ?? {}) as Record<string, unknown>,
      form === "merge");
    // A queue object that holds a lock admits an update that removes the item
    // or weakens it, and no other, as a container object and a data object do.
    // The gate that refuses an operation on a locked object exempts the
    // holder's own update, because whether the update weakens the lock can only
    // be judged once the body has been read; that judgement was made for a
    // container object and for a data object and not here, so a locked queue
    // object accepted a change to any other metadata item until 0.86.
    this.refuseLockedChange(node, body);
    // A query queue is a queue object carrying the metadata of one,
    // so the items are checked wherever a queue object is written.
    this.checkServiceLevelOf((body.metadata ?? {}) as Record<string, unknown>,
      form === "merge" ? { ...m.metadata, ...supplied } : supplied,
      m.parent === null ? undefined : { id: m.parent, isContainer: true });
    checkQueryMetadata(form === "merge"
      ? { ...m.metadata, ...supplied }
      : supplied);
    checkNotificationMetadata(form === "merge"
      ? { ...m.metadata, ...supplied }
      : supplied);
    // An item of the query and notification metadata is not changed
    // once the queue object has been created, other than the item
    // that states how the CDMI server manages it.
    refuseQueryChange(m.metadata, form === "merge"
      ? { ...m.metadata, ...supplied }
      : supplied);
    // Versioning does not apply to a queue object, so an item that
    // asks for it is refused rather than stored and ignored.
    for (const item of VERSIONING_ITEMS) {
      if (item in supplied) {
        throw invalidField(`metadata/${item}`,
          "versioning does not apply to a queue object");
      }
    }
    // A retention period may be extended and a hold added; neither
    // may be shortened or removed.
    const fault = checkChange(m.metadata, supplied);
    if (fault) {
      throw faultCondition(fault);
    }
    // An object under hold is not modified, and its metadata is part
    // of what is held. An extension of the retention or a further
    // hold is the change the rules permit, and checkChange has
    // allowed it above.
    if (Object.keys(supplied).length > 0 || "metadata" in body) {
      m.metadata = form === "merge" ? mergePatch(m.metadata, supplied) : supplied;
      recordApplied(m.metadata, this.store.meta(node).metadata);
      // The access control list of an object is set through the
      // cdmi_acl item of its metadata, as it is for every other type.
      const acl = suppliedACL(body);
      if (acl !== undefined) {
        this.demand(node, who, M.WRITE_ACL, false, `changing the list of ${ns}`);
        m.acl = acl;
      }
      this.store.setMeta(node, m);
    }
    // As for a container object: a queue object ignored domainURI on an
    // update before 0.47. A queue object being created takes its domain when
    // it is made, so only an existing one is moved.
    const parentOfQueue = nodeOf(pv.held);
    const wantedQueueDomain = parentOfQueue === undefined ? undefined : this.domainFor(body, parentOfQueue, who);
    if (wantedQueueDomain && this.domainOf(node).id !== wantedQueueDomain.id) {
      await this.changeDomain(node, wantedQueueDomain, who);
    }
    // The graph relationships. The field applies to every representation other
    // than that of a capability object, and this path neither stored nor
    // validated it until 0.95: a CDMI client supplying it on a queue object was
    // answered 201 and the field was gone, and a malformed one was accepted
    // where "a CDMI server shall validate this field" once cdmi_graph_rels is
    // available.
    {
      const relMeta = this.store.meta(node);
      const hasField = (f: string) => f in body && (form !== "selected" || selected.includes(f));
      applyRel(relMeta, body, hasField, form);
      if (hasField("rel")) this.store.setMeta(node, relMeta);
    }
    const depositsBefore = this.depositedReferences(node);
    await this.applyQueueExports(node, body, form, who, ns);
    await this.applyQueueImports(node, body, form, who, ns);
    await this.revokeWithdrawn(node, depositsBefore);
    this.applyExtensionFields(node, body, "queue", form);
    // Changing the item that states how the CDMI server manages the
    // queue object stops a query in progress or starts a new one.
    this.queries(who).offer(node);
    this.notifications().offer(node);
    this.event("cdmi_modify_complete", node, ns, who);
    res.writeHead(204);
    return res.end();
  }

  /**
   * Sends a representation with the values outside it, as parts of a
   * multipart/mixed body. The first part is the representation and
   * each part after it is one value.
   */
  private sendMultipart(res: ServerResponse, mt: string,
    rep: Record<string, unknown>,
    parts: { mimetype: string; vte: string; body: Buffer; range?: string }[],
    head: boolean): void {
    const boundary = `cdmi-${randomUUID()}`;
    const pieces: Buffer[] = [];
    const push = (headers: string, body: Buffer) => {
      pieces.push(Buffer.from(`--${boundary}\r\n${headers}\r\n\r\n`, "utf8"), body,
        Buffer.from("\r\n", "utf8"));
    };
    push(`Content-Type: ${mt}`,
      Buffer.from(JSON.stringify(rep, null, 2) + "\n", "utf8"));
    for (const p of parts) {
      // A part carrying a UTF-8 value names the charset, as the
      // binding requires of a value transfer encoding of utf-8.
      const type = p.vte === "utf-8" ? `${p.mimetype}; charset=utf-8` : p.mimetype;
      // A part carrying a range of a value names the range it holds.
      push(p.range === undefined ? `Content-Type: ${type}`
        : `Content-Type: ${type}\r\nContent-Range: ${p.range}`, p.body);
    }
    pieces.push(Buffer.from(`--${boundary}--\r\n`, "utf8"));
    const body = Buffer.concat(pieces);
    res.writeHead(200, {
      "Content-Type": `multipart/mixed; boundary=${boundary}`,
      "Content-Length": String(body.length),
    });
    if (head) return res.end();
    res.end(body);
  }

  /**
   * Appends values to a queue object. The operation does not replace
   * the values the queue object holds, and each value takes the next
   * designator.
   */
  /**
   * Refuses an append to a queue object whose values an import supplies,
   * where no entry of it is write enabled.
   *
   * "An operation that changes the value of the importing object is directed
   * to the import source only where the write_enabled field of the import
   * entry contains true, and is reported with the forbidden condition where
   * that field does not" (the subclause on imports placed on a data object
   * or a queue object), and the MQTT imports subclause says the same of an
   * append in particular: "an operation that appends a value to the
   * importing queue object ... where the write_enabled field of the import
   * entry contains false".
   *
   * This server permitted such an append until 0.83 and enqueued the value
   * locally, which made the queue object hold values from two sources with
   * nothing to tell them apart. weedmi reported it as IMQT-001 and we asked
   * for the citation; it is the sentence above, which was in the revision
   * all along and which we did not find.
   */
  private refuseAppendThroughImport(node: Node, ns: string): void {
    const entries = (this.store.meta(node).imports ?? []) as Record<string, unknown>[];
    if (entries.length === 0) return;
    if (entries.some((e) => e.write_enabled === "true")) return;
    throw forbidden(
      "the values of %s are supplied by an import, and no entry of it is write enabled: " +
      "an operation that changes the value of an importing object is directed to the " +
      "import source only where the write_enabled field of the entry contains \"true\"",
      ns);
  }

  private async appendQueue(req: IncomingMessage, res: ServerResponse, node: Node,
    ns: string, who: Principal): Promise<void> {
    const full = String(req.headers["content-type"] ?? "");
    const ct = mediaTypeOf(full);
    // A pipe holds no values: bytes pass through it, and nothing is enqueued.
    // A POST of its ticket media type asks for a ticket instead (RELAY-draft-2.md
    // sections 3.1 and 5.1).
    if (this.isPipe(node)) {
      if (ct === TICKET_MEDIA_TYPE && this.pipes !== undefined) return this.pipeTicket(req, res, node, ns, who);
      throw forbidden("%s is a pipe, which holds no values", ns);
    }
    if (ct !== "" && ct !== MT_QUEUE && ct !== `${MT_QUEUE}+json` &&
      ct !== "multipart/mixed") {
      throw new Condition(415, "",
        "The media type is not supported.",
        `${ct} is not the media type of a queue object`);
    }
    // Appending a value does not change any existing part of what the
    // queue object holds, so APPEND_DATA is sufficient, as revision
    // 121 states: the bit is permission to append data to the value
    // of a data object and to append a value to a queue object.
    if (!this.may(node, who, M.APPEND_DATA, false) &&
      !this.may(node, who, M.WRITE_OBJECT, false)) {
      throw forbidden("appending to %s requires APPEND_DATA or WRITE_OBJECT", ns);
    }
    // An object under retention or under hold is not modified, and
    // appending a value modifies what the queue object holds. The
    // permission check above replaced a call that carried this, and
    // the restriction went with it.
    this.refuseRestricted(node, M.APPEND_DATA, `appending to ${ns}`);
    this.refuseAppendThroughImport(node, ns);
    const raw = await readBody(req);
    let body: Record<string, unknown> = {};
    if (ct === "multipart/mixed") {
      // The values are outside the representation: the first part is
      // the representation and each part after it is one value.
      const boundary = /boundary="?([^";]+)"?/i.exec(full)?.[1];
      if (boundary === undefined) {
        throw malformed("a multipart body names a boundary in its media type");
      }
      const parts = splitMultipart(raw, boundary);
      if (parts.length < 2) {
        throw malformed("a multipart body has at least two parts: the representation " +
          "and one value");
      }
      try {
        body = JSON.parse(parts[0].body.toString("utf8")) as Record<string, unknown>;
      } catch {
        throw malformed("the first part of a multipart body is the representation");
      }
      if (body === null || typeof body !== "object" || Array.isArray(body)) {
        throw malformed("the first part of a multipart body is a JSON object");
      }
      if ("value" in body) {
        // The value field is not present where the values are
        // transported outside the representation.
        throw invalidField("value",
          "the values are transported outside the representation, and the value field " +
          "is therefore not present in it");
      }
      const values = parts.slice(1);
      // Where the representation states the value transfer
      // encoding of each value, that is what the encoding is.
      // Where it does not, a part carrying an encoding of utf-8
      // names a charset parameter of utf-8, and that parameter is
      // then the only statement of it.
      const stated = Array.isArray(body.valuetransferencoding)
        ? body.valuetransferencoding as unknown[]
        : undefined;
      if (stated !== undefined && stated.length !== values.length) {
        throw invalidField("valuetransferencoding",
          "the valuetransferencoding field holds one entry for each part that " +
          "contains a value, and %d were supplied for %d",
          stated.length, values.length);
      }
      const encodings = values.map((p, i) =>
        stated !== undefined
          ? String(stated[i])
          : (/charset\s*=\s*"?utf-8"?/i.test(p.type) ? "utf-8" : "base64"));
      body.value = values.map((p, i) =>
        encodings[i] === "base64"
          ? p.body.toString("base64")
          : p.body.toString("utf8"));
      body.valuetransferencoding = encodings;
      // The media type of a part is the media type of the value it
      // carries, where the client supplied none in the representation.
      if (!("mimetype" in body)) {
        body.mimetype = values.map((p) => mediaTypeOf(p.type) || "application/octet-stream");
      }
    } else if (raw.length > 0) {
      body = parseBodyJson(raw);
      if (body === null || typeof body !== "object" || Array.isArray(body)) {
        throw malformed("the message body shall be a JSON object");
      }
    }

    const values = body.value;
    if (!Array.isArray(values)) {
      throw invalidField("value",
        "the values appended to a queue object are supplied in a JSON array");
    }
    const arrayOf = (field: string): string[] | undefined => {
      const v = body[field];
      if (v === undefined) return undefined;
      if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
        throw invalidField(field, "the %j field is a JSON array of JSON strings", field);
      }
      if (v.length !== values.length) {
        // Each array describes the same values, so each holds the same
        // number of entries and the entry at a position describes the
        // value at that position.
        throw invalidField(field,
          "the %j field holds %d entries and the value field holds %d; each array " +
          "describes the same values", field, v.length, values.length);
      }
      return v as string[];
    };
    const mimetypes = arrayOf("mimetype");
    const encodings = arrayOf("valuetransferencoding");

    const m = this.store.meta(node);
    const held = this.store.queueBounds(node).count;
    if (held + values.length > QUEUE_MAXVALUES) {
      throw new Condition(413, "limit-exceeded", "A limit would be exceeded.",
        `a queue object of this server holds ${QUEUE_MAXVALUES} values, and this ` +
        `request would make ${held + values.length}`)
        .with("cdmi_limit", "cdmi_queue_maxvalues")
        .with("cdmi_limit_value", String(QUEUE_MAXVALUES));
    }

    const prepared: { mimetype: string; vte: string; body: Buffer }[] = [];
    let added = 0;
    for (const [i, value] of values.entries()) {
      const vte = encodings?.[i] ?? "utf-8";
      let octets: Buffer;
      if (vte === "utf-8") {
        if (typeof value !== "string") {
          throw malformed("the value at position %d is not a JSON string, and its " +
            "value transfer encoding is utf-8", i);
        }
        octets = Buffer.from(value, "utf8");
      } else if (vte === "base64") {
        if (typeof value !== "string" ||
          !/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4 !== 0) {
          throw malformed("the value at position %d is not base 64, and its value " +
            "transfer encoding says it is", i);
        }
        octets = Buffer.from(value, "base64");
      } else if (vte === "json") {
        if (value === null || typeof value !== "object") {
          throw malformed("the value at position %d is not a JSON object, and its " +
            "value transfer encoding says it is", i);
        }
        octets = Buffer.from(JSON.stringify(value), "utf8");
      } else {
        throw invalidField(`valuetransferencoding/${i}`,
          "%j is not a value transfer encoding this document defines", vte);
      }
      if (octets.length > QUEUE_MAXSIZE) {
        throw new Condition(413, "limit-exceeded", "A limit would be exceeded.",
          `a value of ${octets.length} octets exceeds the ${QUEUE_MAXSIZE} this server ` +
          "holds for one value of a queue object")
          .with("cdmi_limit", "cdmi_queue_maxsize")
          .with("cdmi_limit_value", String(QUEUE_MAXSIZE));
      }
      added += octets.length;
      prepared.push({
        mimetype: (mimetypes?.[i] ?? (vte === "json"
          ? "application/json"
          : "text/plain")).toLowerCase(),
        vte,
        body: octets,
      });
    }
    if (this.store.queueSize(node) + added > QUEUE_MAXTOTALSIZE) {
      throw new Condition(413, "limit-exceeded", "A limit would be exceeded.",
        `the values of a queue object of this server total ${QUEUE_MAXTOTALSIZE} octets`)
        .with("cdmi_limit", "cdmi_queue_maxtotalsize")
        .with("cdmi_limit_value", String(QUEUE_MAXTOTALSIZE));
    }

    const assigned = this.store.enqueue(node, prepared);
    const rep: Record<string, unknown> = {
      objectType: MT_QUEUE,
      objectID: viewOf(this.store, { kind: "store", node }).objectID,
      capabilitiesURI: "/cdmi_capabilities/queue/",
      completionStatus: "Complete",
      queueValues: assigned.length === 0
        ? ""
        : `${assigned[0]}-${assigned[assigned.length - 1]}`,
    };
    if (m.parent !== null) rep.objectName = this.split(ns).name;
    return this.send(res, 204, MT_QUEUE, rep, {}, true);
  }

  /** The representation of a queue object. */
  private queueRep(node: Node, ns: string, name: string, pv: View | undefined,
    who: Principal, sel?: Selection): Record<string, unknown> {
    const m = this.store.meta(node);
    const ref: ObjRef = { kind: "store", node };
    const mayMeta = this.may(node, who, M.READ_METADATA, false);
    const mayAttrs = this.may(node, who, M.READ_ATTRIBUTES, false);
    const mayACL = this.may(node, who, M.READ_ACL, false);
    const v = viewOf(this.store, ref);
    const rep: Record<string, unknown> = { objectType: MT_QUEUE };
    rep.objectID = v.objectID;
    // The graph relationships, which this representation dropped until 0.95: a
    // CDMI client could supply the field on a queue object, be answered 201, and
    // find it gone.
    rep.rel = relRep(m);
    // An object created in the object ID tree is addressed by its
    // object ID alone: it has no name a client may use, and its
    // representation omits the three fields, as the common fields
    // table requires of an object with no parent container object.
    if (m.parent !== null && pv !== undefined) {
      rep.objectName = name;
      rep.parentURI = pv.ns;
      const parent = nodeOf(pv.held);
      if (parent !== undefined) {
        rep.parentID = viewOf(this.store, { kind: "store", node: parent }).objectID;
      }
    }
    rep.capabilitiesURI = "/cdmi_capabilities/queue/";
    // An MQTT export publishes the values this object holds, so a
    // queue object reports an exports field as a container object
    // does.
    if (this.exports?.configured(node)) {
      rep.exports = this.readableExports(node, this.exports.reportSync(node));
    }
    // An export is provided for a queue object as well as for a
    // container object and a data object.
    const provided = this.exports?.providedFor(ns) ?? [];
    // "Where the object is accessible through no export, the value shall be
    // an empty JSON array": this server omitted the field before 0.67
    // (weedmi REPR-001, EXPT-002).
    rep.exportsProvided = provided;
    // The import entries of a queue object, with what each has
    // enqueued through the connection it holds.
    const imports = (m.imports ?? []) as unknown as ImportEntry[];
    if (imports.length > 0) {
      const now = cdmiTime();
      rep.imports = imports.map((e, i) => {
        const state = this.mqttImports?.state(MqttImporter.keyOf(node, i));
        const connecting = this.mqttImports?.connecting === true;
        return {
          ...this.readableEntry(node, e as unknown as Record<string, unknown>),
          connected: state?.connected === true ? "true" : "false",
          // "active" is a field of every import entry, whatever its type,
          // and an MQTT import reported "connected" alone (weedmi
          // IMQT-001). An entry that is not disabled and reports no
          // problem is active; whether the broker is reached is what
          // "connected" says.
          active: (e as { disabled?: string }).disabled === "true" || !connecting
            ? "false"
            : ((state?.problems ?? []).length > 0 ? "false" : "true"),
          messages_enqueued: String(state?.enqueued ?? 0),
          messages_dropped: String(state?.dropped ?? 0),
          last_problems: connecting
            ? (state?.problems ?? [])
            : [problem("imports/mqtt/broker-unreachable",
              "The MQTT broker cannot be reached.",
              "this CDMI server is not configured to connect to an MQTT broker")],
          state_determined_time: now,
        };
      });
    }
    rep.domainURI = this.domainURI(node);
    rep.completionStatus = m.partial ? "Processing" : "Complete";
    if (mayMeta || mayAttrs) {
      rep.metadata = metadataRep(v, false, [], mayACL, mayAttrs, mayMeta);
      // The state of the query, which the runner records as it
      // proceeds. A query queue whose query has not begun reports
      // that it has been stopped.
      if (mayMeta && isQueryQueue(m.metadata)) {
        const metadata = rep.metadata as Record<string, unknown>;
        metadata[QUERY_STATUS] = m.metadata[QUERY_STATUS] ?? "Halted";
      }
    }
    // The values a queue object holds, in order from oldest to
    // newest. A read does not remove them.
    const mayValue = this.may(node, who, M.READ_OBJECT, false);
    const bounds = this.store.queueBounds(node);
    let values: QueueValue[] = [];
    if (mayValue && bounds.count > 0) {
      const q = sel?.queueValues;
      if (q === undefined) {
        values = this.store.queueValues(node);
      } else if ("count" in q) {
        // A count returns that number of values beginning with the
        // oldest, and where the queue object holds fewer, what it
        // holds.
        values = this.store.queueValues(node).slice(0, q.count);
      } else {
        // A range of designators returns the values within it. A
        // designator within the range that names no value is omitted
        // and is not an error.
        values = this.store.queueValues(node, q.range[0], q.range[1]);
      }
    }
    rep.queueValues = values.length === 0
      ? ""
      : `${values[0].designator}-${values[values.length - 1].designator}`;
    rep.mimetype = values.map((v) => v.mimetype);

    // A range of an enqueued value. A byte range of a UTF-8 string is
    // often not itself a valid UTF-8 string, and a range of a JSON
    // object is not a JSON object at all, so a range is always
    // transported as base 64 whatever encoding applies to the whole
    // value.
    const wanted = sel?.valueRanges.length === 1 ? sel.valueRanges[0] : undefined;
    const parts = values.map((v) => {
      if (wanted === undefined) {
        return {
          vte: v.vte,
          range: v.body.length === 0 ? "" : `0-${v.body.length - 1}`,
          body: v.body,
          whole: true,
        };
      }
      // Where the range extends beyond the end of the value, the
      // smaller range returned is what is reported.
      const first = Math.min(wanted[0], v.body.length);
      const last = Math.min(wanted[1], v.body.length - 1);
      const slice = first > last ? Buffer.alloc(0) : v.body.subarray(first, last + 1);
      return {
        vte: "base64",
        range: slice.length === 0 ? "" : `${first}-${last}`,
        body: slice,
        whole: false,
      };
    });
    rep.valuetransferencoding = parts.map((p) => p.vte);
    rep.valuerange = parts.map((p) => p.range);
    rep.value = parts.map((p) => {
      if (!p.whole) return p.body.toString("base64");
      if (p.vte === "json") return JSON.parse(p.body.toString("utf8"));
      return p.vte === "base64"
        ? p.body.toString("base64")
        : p.body.toString("utf8");
    });
    // The extension fields, governed as the attribute fields are.
    if (mayAttrs) Object.assign(rep, m.extensions ?? {});
    return rep;
  }

  /**
   * The conditions of a request that creates or replaces the object at ns
   * by copy or move: If-None-Match: * fails with 412 where the object
   * exists, and If-Match where it does not, or where its entity tag does
   * not match, as they do for a create or update carrying a value.
   */
  private async createConditions(req: IncomingMessage, r: Resolver, ns: string): Promise<void> {
    const inm = req.headers["if-none-match"] as string | undefined;
    const im = req.headers["if-match"] as string | undefined;
    if (inm === undefined && im === undefined) return;
    const cut = ns.replace(/\/$/, "").lastIndexOf("/");
    const name = ns.replace(/\/$/, "").slice(cut + 1);
    let tag: string | undefined;
    try {
      const pv = await r.view(ns.slice(0, cut + 1));
      if (ns.endsWith("/")) {
        const cv = await r.child(pv, name);
        const held = nodeOf(cv.held);
        if (held !== undefined) tag = etagOf(viewOf(this.store, { kind: "store", node: held }));
      } else {
        const found = await resolveFile(this.store, pv, name);
        if (found !== undefined) tag = etagOf(viewOf(this.store, found.ref));
      }
    } catch {
      tag = undefined;
    }
    if (inm === "*" && tag !== undefined) {
      throw alreadyExistsPrecondition("%s exists, and the request was made conditional on its absence", ns);
    }
    if (im !== undefined && (tag === undefined || (im !== "*" && !matchesETag(im, tag)))) {
      throw validatorConflict();
    }
  }

  private async putData(req: IncomingMessage, res: ServerResponse, r: Resolver, pv: View,
    ns: string, name: string, body: Record<string, unknown>, form: string,
    sel: Selection, who: Principal): Promise<void> {
    if ("imports" in body) {
      // A namespace import is placed on a container object; a value import
      // is placed on the object whose value it presents. "An HTTP import
      // ... is placed on a data object, as an entry of the imports field of
      // that object" (revision 327), so a data object's imports field
      // carries value imports and nothing else.
      const entries = body.imports;
      const kinds = entries === null || typeof entries !== "object"
        ? []
        : Object.values(entries as Record<string, unknown>)
          .map((v) => (v !== null && typeof v === "object"
            ? (v as { type?: unknown }).type
            : undefined));
      if (kinds.length > 0 && kinds.every((k) => k === "HTTP")) {
        // The entries are applied once the object exists, below: this is
        // reached before it is resolved or created. Only the placement is
        // decided here, and the entries are parsed once, where they are
        // recorded.
      } else {
        throw invalidField("imports",
          "a data object carries an import of a value, which is of type \"HTTP\"; " +
          "an import of a namespace is placed on a container object");
      }
    }
    if ("exports" in body) {
      throw invalidField("exports", "an exports field applies to a container object alone");
    }
    // A name may denote a data object representation and a queue
    // object representation at once, and the media type names the
    // one this request acts upon. Where the layering engine found
    // the queue object, the data object of that name is what is
    // wanted: a create establishes it where the name does not yet
    // denote one, and an update reports that it is not there.
    let found = await resolveFile(this.store, pv, name);
    const heldNode = found === undefined ? undefined : nodeOf(found.ref);
    if (heldNode !== undefined && this.store.meta(heldNode).isQueue) {
      const writeAt = await ensureWriteTarget(this.store, pv);
      const data = this.store.lookupKind(writeAt, name, "data");
      if (data === undefined) {
        if (form === "merge") {
          throw notFound(
            `${ns}: the name denotes no data object representation, and a merge update ` +
            "does not establish one");
        }
        // "A name shall not denote both a data object representation and a
        // queue object representation. A CDMI server shall report the conflict
        // condition where an operation would establish one at a name that
        // denotes the other. The two describe the value they hold by fields of
        // one set of names, a queue object taking an array where a data object
        // takes one value, so an object of both could be neither read nor
        // serialized as one object" (revision 365). Before 0.85 this server
        // established both, which is what revision 354 permitted.
        throw conflict("%s denotes a queue object representation, and a name does not denote " +
          "a data object representation and a queue object representation at once", ns);
      } else {
        found = { ref: { kind: "store", node: data }, node: data, layer: found!.layer };
      }
    }

    // Conditional requests.
    const inm = req.headers["if-none-match"] as string | undefined;
    const im = req.headers["if-match"] as string | undefined;
    if (inm === "*" && found) {
      throw alreadyExistsPrecondition("%s exists, and the request was made conditional on its absence", ns);
    }
    if (found) {
      const tag = etagOf(viewOf(this.store, found.ref));
      if (im && im !== "*" && !matchesETag(im, tag)) {
        throw validatorConflict();
      }
    } else if (im) {
      throw validatorConflict();
    }

    if (!found) {
      // "A field selection may be supplied with a create operation, in which
      // case only the selected fields of the request representation are
      // applied", and so may a value range selection. A merge update (PATCH)
      // changes an object that exists and creates none. Before 0.53 a create
      // carrying a field selection answered 404, only a value range being
      // accepted.
      if (form === "merge") throw notFound(ns);
      // A name held in the other form by any layer: the conflict
      // condition. A queue object of the name is not that: a name
      // denotes a data object representation and a queue object
      // representation at once, and this create establishes the
      // first beside the second.
      for (const l of pv.layers) {
        if (l.dir.kind !== "store") continue;
        const other = this.store.tryLookup(l.dir.node, name);
        if (!other) continue;
        if (!other.isContainer && this.store.meta(other).isQueue) continue;
        // "A name may denote more than one representation of one object"
        // (5.3.7): a container object at this name in the write target is
        // not a conflict, it is the object this create adds a data object
        // representation to, which takes the object's identity
        // (weedmi OPER-042).
        if (other.isContainer && l.dir.node.id === nodeOf(pv.held)?.id) continue;
        if (pv.writeRank !== undefined && rankCmp(l.rank, pv.writeRank) < 0) {
          throw conflictImportLayer(l.rank[0], pv.ns,
            "the name of %s is held, by an object of another type, by a layer above the write " +
            "target of %s", ns, pv.ns);
        }
        throw conflict("an object of another type is presented at the name of %s", ns);
      }
      const image = await ensureImageWriteTarget(pv);
      if (image) {
        // The write target is a directory of an imported file system. The
        // list of the container that imports it governs, and an object
        // created there carries none of its own.
        this.demand(pv.held, who, M.ADD_OBJECT, true, `creating ${ns}`, governedBy(pv));
        return this.createInImage(req, res, pv, image, ns, name, body, who);
      }
      const target = await ensureWriteTarget(this.store, pv);
      this.demandCreate(target, name, ns, who);
      // The domain, the owner and the access control list of the object
      // created, which revision 354 governs: no entry is inherited across a
      // domain boundary, and a create whose object belongs to another domain
      // states cdmi_owner.
      //
      // This is the create a CDMI client performs most often, and it was the
      // one site of the four that 0.82 did not wire to newObjectIdentity, so
      // neither rule applied to a data object created at a name. A test that
      // creates a data object in another domain and expects it to succeed
      // passed throughout, which is what the gap looks like from outside.
      const node = this.store.createData(target, name,
        this.newObjectIdentity(body, target, who, false));
      await this.applyToNew(node, body, form, sel, name, who);
      // The counters of a newly created object are zero, whatever the
      // server did to build it.
      this.store.startCounts(node);
      if (isPartial(req)) this.store.setPartial(node, true);
      // A version-enabled data object always has a current version,
      // which holds the same value and metadata as the object. An
      // object that is not yet complete takes none until it is.
      if (!isPartial(req) && versioningLevel(this.store.meta(node)) !== undefined) {
        this.store.createVersion(node);
        await this.applyVersionLimits(node);
      }
      const created: ObjRef = { kind: "store", node };
      void created;
      // A value import placed on the object presents what an origin server
      // returns as its value (revision 327). It is recorded once the object
      // exists, the imports field having been validated above.
      if ("imports" in body) await this.applyDataImports(node, body, form, who, ns);
      const m = this.store.meta(node);
      // A data object has been created. Where the operation was
      // accepted as a long-running one the object is in the
      // processing state and the event says so.
      this.event(m.partial ? "cdmi_create_processing" : "cdmi_create_complete",
        node, ns, who);
      return this.sendData(req, res, pv, { kind: "store", node },
        {
          dir: { kind: "store", node: target }, rank: pv.writeRank!, via: [],
          imported: false, hideIDs: false, readOnly: false,
        },
        name, sel.any ? sel : emptySelection(), 201, false, who);
    }

    // An update. Where the object is held below the write target it is
    // copied up first, except for a complete replacement, which creates a
    // new object in the write target and carries nothing of the original.
    if (pv.writeRank === undefined) {
      throw pv.writeUnavail ?? forbidden("%s cannot be changed: %s", ns, pv.writeWhy);
    }
    const cmp = rankCmp(found.layer.rank, pv.writeRank);
    // A layer above the write target denies the update before anything
    // else is considered, and an image layer is often such a layer.
    if (cmp < 0) throw denyChange(pv, ns, found.layer.rank, "update");

    // The access control list of the object as presented governs the
    // update, whichever layer holds it. An object of an image layer
    // carries none, and is governed by the container that imports it.
    const governs = governedBy(pv);
    // Where the object is below the write target it is copied up, and
    // what is changed is the copy: a frozen object is read for that.
    const copiedUp = cmp > 0;
    if ("value" in body) {
      this.checkNotAnActiveSource(ns, "change");
      this.demand(found.ref, who, M.WRITE_OBJECT, false, `updating ${ns}`, governs,
        copiedUp);
    }
    // cdmi_acl and cdmi_owner are storage system metadata with bits of
    // their own, so a change to them alone does not require
    // WRITE_METADATA. RW_ALL notably grants WRITE_ACL and not
    // WRITE_METADATA, so the two are genuinely separate.
    // An update that does nothing but extend a retention period or add
    // a hold is permitted on an object that is under either: there are
    // legitimate reasons to extend both.
    const md = (body.metadata ?? {}) as Record<string, unknown>;
    const stored = (() => {
      const n = nodeOf(found.ref);
      try {
        return n === undefined ? {} : this.store.meta(n).metadata;
      } catch {
        return {};
      }
    })();
    const extendsOnly = !("value" in body) && !("mimetype" in body) &&
      typeof body.metadata === "object" && body.metadata !== null &&
      !changesMore(md, stored, form === "merge");
    if (changesUserMetadata(body) || "mimetype" in body) {
      this.demand(found.ref, who, M.WRITE_METADATA, false, `updating ${ns}`, governs,
        copiedUp || extendsOnly);
    }
    if (changesAttributes(body)) {
      this.demand(found.ref, who, M.WRITE_ATTRIBUTES, false, `updating ${ns}`, governs,
        copiedUp || extendsOnly);
    }
    if (suppliedItems(body).some((k) => RETENTION_ONLY.has(k))) {
      this.demand(found.ref, who, M.WRITE_RETENTION, false, `changing the retention of ${ns}`, governs,
        copiedUp || extendsOnly);
    }
    // A hold is a retention attribute, and the draft's mask bits table names
    // WRITE_RETENTION alone; NFSv4's separate hold bit has no name there.
    if (suppliedItems(body).some((k) => HOLD_ITEMS.has(k))) {
      this.demand(found.ref, who, M.WRITE_RETENTION, false, `changing the holds of ${ns}`, governs,
        copiedUp || extendsOnly);
    }
    if (found.ref.kind !== "store") {
      if (cmp === 0) {
        // The object is held by the write target itself, which is a
        // directory of an imported file system.
        if (found.ref.kind !== "image") {
          throw forbidden("%s is presented by a remote CDMI import, and seedmi issues " +
            "no operation that changes an object of another CDMI server", ns);
        }
        return this.updateInImage(res, found.ref, body, sel);
      }
      // Below the write target: the object is copied up into it, as one
      // held by a lower layer of the store is, and the copy is what the
      // update changes.
      const target = await ensureWriteTarget(this.store, pv);
      this.demand(target, who, M.ADD_OBJECT, true, `copying ${ns} up`);
      const node = await this.copyUpForeign(found.ref, target, name, who, body, form);
      await this.applyData(node, body, form, sel, name, false, who);
      res.writeHead(204);
      return res.end();
    }
    let node = storedNode(found.ref, ns);
    if (cmp > 0) {
      const target = await ensureWriteTarget(this.store, pv);
      if (form === "complete") {
        // A complete replacement creates a new object and carries nothing
        // of the one it conceals, so its list is inherited or supplied.
        this.demand(target, who, M.ADD_OBJECT, true, `creating ${ns} in the write target`);
        node = this.store.createData(target, name, {
          owner: who.name === ANONYMOUS.name ? "" : who.name,
          acl: aclForNewObject(suppliedACL(body), this.store.meta(target).acl, false),
        });
      } else {
        node = await this.store.copyUp(node, target, name);
      }
    }
    // The state before the update, so that what changed decides
    // whether a version is created.
    // A domain the update asks for; where it asks for none the
    // existing domain is preserved.
    const parentNode = nodeOf(pv.held);
    const wanted = parentNode === undefined
      ? undefined
      : this.domainFor(body, parentNode, who);
    if (wanted) await this.changeDomain(node, wanted, who, body);
    const before = this.store.meta(node);
    await this.applyData(node, body, form, sel, name, form === "complete", who);
    // A request marked partial leaves the object not complete, and a
    // version-enabled data object takes no version until a request
    // completes it: a value written by a series of operations produces
    // one version and not one for each.
    const partial = isPartial(req);
    if (partial !== before.partial) this.store.setPartial(node, partial);
    if (partial) {
      // The object is in the processing state, and an update that
      // put it there is reported as such.
      if (!before.partial) this.event("cdmi_modify_processing", node, ns, who);
      res.writeHead(204);
      return res.end();
    }
    // An object updated. Where it was in the processing state and
    // has left it, the event is the corresponding complete event,
    // reporting the outcome the operation would have reported had
    // it not been accepted as a long-running operation.
    this.event("cdmi_modify_complete", node, ns, who);
    const after = this.store.meta(node);
    await this.versionOnUpdate(node, before, {
      value: "value" in body,
      userMetadata: JSON.stringify(before.metadata) !== JSON.stringify(after.metadata),
    });
    res.writeHead(204);
    res.end();
  }

  /** Applies a representation to a data object. */
  /**
   * Applies a request representation to an object just created, and removes
   * that object where the representation is refused: "A refused request
   * changes nothing". The body is checked as it is applied, and a check that
   * fails after the object exists would otherwise leave it behind, which a
   * client retrying after the refusal then finds (weedmi REPR-F01).
   */
  /**
   * Encrypts, decrypts or re-encrypts the value of an object in place, as an
   * update that changes the mimetype field asks. Returns the value to store,
   * or undefined where the change is not one of those operations.
   *
   * "Encrypt in place: an update operation that changes the mimetype field
   * of a stored object to application/cms or application/jose+json and
   * supplies a cdmi_enc_key_id item"; "Decrypt in place: an update operation
   * that changes the mimetype field of an encrypted object to the media type
   * the ciphertext specifies for the plaintext"; "Re-encrypt in place: an
   * update operation that supplies a different cdmi_enc_key_id item, or that
   * changes the mimetype field from one encrypted media type to the other."
   */
  private async encryptionInPlace(node: Node, m: StoredMeta, before: string, after: string,
    item: unknown, who: Principal): Promise<Buffer | undefined> {
    const wasEncrypted = isEncryptedMediaType(before);
    const willBeEncrypted = isEncryptedMediaType(after);
    if (before === after && !wasEncrypted) return undefined;
    if (after === MT_CMS || (wasEncrypted && before === MT_CMS)) {
      // No CMS implementation: the capability is not published, and the
      // operation is refused rather than half-performed.
      throw capabilityNotPresent("cdmi_enc_cms", this.store.pathOf(node),
        "this server encrypts an object as a JWE and does not implement CMS");
    }
    if (!this.capabilities()["/cdmi_capabilities/"]?.capabilities.cdmi_enc_inplace) {
      throw capabilityNotPresent("cdmi_enc_inplace", this.store.pathOf(node),
        "this server encrypts and decrypts in place where a key management server is configured");
    }
    const stored = await readValueOf(this.store, { kind: "store", node });
    if (willBeEncrypted) {
      // Encrypting or re-encrypting: the plaintext is what the object holds,
      // or what its ciphertext decrypts to.
      const keyID = item;
      if (keyID === undefined || nameOfCredential(keyID) === undefined) {
        throw invalidField("metadata/cdmi_enc_key_id",
          "encrypting the value of an object in place requires the key encryption key to be named");
      }
      // Re-encrypting: the value is decrypted under the key the object
      // holds, which is the key its stored metadata names, and not the key
      // this request supplies. Reading the updated metadata here made a
      // re-encryption report a conflict with its own new key.
      const held = wasEncrypted
        ? await this.decryptInPlace(node, this.store.meta(node), stored, who)
        : undefined;
      const plain = held?.plaintext ?? stored;
      const type = wasEncrypted
        ? held!.plaintextType
        : (before === "" ? "application/octet-stream" : before);
      const key = await this.keyInPlace(node, keyID, who);
      const plaintextType = type;
      // The kid header parameter names the key as a CDMI client does, not
      // as the key management server identifies it internally: another
      // CDMI server reads this structure.
      return await encryptValue(key.server, key.id, plain, plaintextType,
        nameOfCredential(keyID));
    }
    // Decrypting: the mimetype asked for is the one the ciphertext names.
    const got = await this.decryptInPlace(node, m, stored, who);
    if (got.plaintextType !== after) {
      throw conflictingFields("mimetype",
        "the ciphertext names %j as the media type of its plaintext, and the update names %j",
        got.plaintextType, after);
    }
    return got.plaintext;
  }

  /** Decrypts the stored value of an encrypted object, obtaining its key. */
  private async decryptInPlace(node: Node, m: StoredMeta, stored: Buffer, who: Principal):
    Promise<{ plaintext: Buffer; plaintextType: string }> {
    const structure = readEncryptedValue(m.mimetype, stored);
    const held = m.metadata?.cdmi_enc_key_id;
    const choice = keyForEncryptedValue(nameOfCredential(held), structure, m.objectID);
    // The item the object holds names the key; where it holds none, the
    // Name the structure or the object ID gives is used at the domain's
    // key management server.
    const key = await this.keyInPlace(node, held ?? choice.name, who);
    const got = structure.kind === "jws"
      // "A value that is a JWS is signed and is not encrypted. Its
      // plaintext is the payload of that structure", so it is verified
      // rather than decrypted.
      ? { plaintext: stored, plaintextType: structure.plaintextType ?? "application/octet-stream" }
      : await decryptValue(key.server, key.id, stored);
    return await this.verifySignedValue(node, m, got, who);
  }

  /**
   * Verifies the signature of a value that carries one, and returns what it
   * signs. "Where a CDMI server decrypts a value that contains a signature,
   * it shall verify that signature using the verification key the
   * corresponding metadata item identifies. Where verification does not
   * succeed, the CDMI server shall not return the plaintext and shall
   * report the condition, so that a value that has been altered is not
   * presented as though it were intact."
   */
  private async verifySignedValue(node: Node, m: StoredMeta,
    got: { plaintext: Buffer; plaintextType: string }, who: Principal):
    Promise<{ plaintext: Buffer; plaintextType: string }> {
    if (!isSignedValue(got.plaintext)) return got;
    const item = m.metadata?.cdmi_enc_value_verify_id;
    if (item === undefined) {
      throw conflictingFields("metadata/cdmi_enc_value_verify_id",
        "the value carries a signature and the object names no key to verify it with");
    }
    const key = await this.keyInPlace(node, item, who, SIGNATURE_VERIFY_KEY,
      "metadata/cdmi_enc_value_verify_id", "Public Key");
    let verified;
    try {
      verified = verifiedPayload(got.plaintext, await verificationKey(key.server, key.id));
    } catch (e) {
      // The plaintext is withheld: a value that has been altered is not
      // presented as though it were intact.
      throw forbidden("the signature of the value does not verify: %s", (e as Error).message);
    }
    return {
      plaintext: verified.payload,
      plaintextType: verified.plaintextType ?? got.plaintextType,
    };
  }

  /** The key encryption key a reference names, resolved but not taken. */
  private async keyInPlace(node: Node, reference: unknown, who: Principal,
    requirement = KEY_ENCRYPTION_KEY, field = "metadata/cdmi_enc_key_id",
    defaultType = "Symmetric Key"): Promise<{ server: KeyManagement; id: string }> {
    const bound = await bindReference(this.credentialContext(), field,
      reference, node, { name: who.name, privileges: [...who.privileges] }, requirement, defaultType);
    return await resolveKeyInPlace(this.credentialContext(), node, bound, requirement);
  }

  /**
   * Signs the object as a whole where it names a signing key, storing the
   * JWS compact serialization in the cdmi_enc_signature item. "If present
   * and true, the CDMI server shall generate [the item] for each stored
   * object when a corresponding sign_id data system metadata item is
   * present": the payload is the canonical form the signatures subclause
   * defines, and is produced after the value and the metadata are stored,
   * since it carries the digest of the value as stored.
   *
   * The item holds a string, which is what a JWS compact serialization is,
   * though Annex D types it as a JSON object: ECR-162A.
   */
  private async signObject(node: Node, who: Principal): Promise<void> {
    const m = this.store.meta(node);
    const item = m.metadata?.cdmi_enc_object_sign_id;
    if (item === undefined) return;
    const key = await this.keyInPlace(node, item, who, OBJECT_SIGNING_KEY,
      "metadata/cdmi_enc_object_sign_id", "Private Key");
    const attrs = await key.server.getAttributes(key.id, ["Cryptographic Algorithm"]);
    const named = attrs.find((a) => a.name === "Cryptographic Algorithm")?.value;
    const algorithm = named === undefined
      ? "RSA"
      : enumName("Cryptographic Algorithm", (named as { value: number }).value);
    const { alg, params } = signatureAlgorithm(algorithm);
    const payload = signaturePayload({
      objectID: m.objectID,
      mimetype: m.mimetype,
      value: await readValueOf(this.store, { kind: "store", node }),
      // The user metadata items, storage system items excluded: "the
      // payload shall contain no storage system metadata item".
      metadata: Object.fromEntries(Object.entries(m.metadata ?? {})
        .filter(([k]) => !k.startsWith("cdmi_"))),
      dataSystemMetadata: Object.fromEntries(Object.entries(m.metadata ?? {})
        .filter(([k]) => CLIENT_SET_METADATA.includes(k) && k !== "cdmi_enc_signature")),
    });
    const compact = await signObjectPayload(
      (data) => key.server.sign(key.id, { params: params as never, data }), payload, { alg });
    const held = this.store.meta(node);
    held.metadata = { ...held.metadata, cdmi_enc_signature: compact };
    this.store.setMeta(node, held);
  }

  /**
   * Decrypts the value of an encrypted object for a request served through
   * an HTTP export. "The CDMI server shall return the plaintext only where
   * cdmi_enc_access is available, shall obtain the key under the identity
   * of the request, and shall not obtain a key for ANONYMOUS@": the caller
   * has established the identity, and the key is obtained as it is for a
   * decryption in place.
   */
  async decryptForExport(ref: ObjRef, who: Principal):
    Promise<{ plaintext: Buffer; plaintextType: string }> {
    if (ref.kind !== "store") throw notFound("an object of another layer is not decrypted here");
    if (who.name === ANONYMOUS.name) {
      throw forbidden("a key is not obtained for the anonymous principal");
    }
    const node = ref.node;
    return await this.decryptInPlace(node, this.store.meta(node),
      await readValueOf(this.store, ref), who);
  }

  /**
   * The principal a request to an HTTP export acts for, where the entry
   * names an authentication scheme. The credentials are resolved exactly as
   * they are for a request of the protocol binding: at the domain
   * controller that serves the domain owning the object, or against this
   * server's own configuration, and within the schemes that domain
   * advertises. A refusal is returned rather than thrown, so that the
   * export answers it with the header fields the scheme requires.
   */
  async exportPrincipal(req: IncomingMessage, ns: string):
    Promise<{ who: Principal } | { refused: Condition }> {
    try {
      const domain = this.domainAt(ns);
      const controller = this.domainControllers?.for(this.store.pathOf(domain))
        ?? await this.controllerOfDomain(domain);
      if (controller !== undefined) {
        const accepted = await controller.accept(
          req.headers.authorization as string | undefined, this.authenticationMethods(domain));
        return { who: accepted.principal };
      }
      return {
        who: this.directory.authenticate(req.headers.authorization as string | undefined,
          this.store.pathOf(domain), this.authenticationMethods(domain)),
      };
    } catch (e) {
      if (e instanceof Condition) return { refused: e };
      throw e;
    }
  }

  /**
   * Refuses an operation upon an object a lock covers. "The cdmi_lock data
   * system metadata item locks an object, and every object it contains",
   * so the lock of the nearest ancestor that holds one applies, and an
   * operation that creates within a locked container is refused as a
   * change to what the lock covers.
   */
  /**
   * The object whose lock refuses an operation of that kind upon a path,
   * for a protocol that reports the refusal in its own terms rather than
   * as a condition: an export or an import.
   */
  lockRefusing(ns: string, operation: "create" | "update" | "delete"): string | undefined {
    const covering = this.lockCovering(ns);
    if (covering === undefined) return undefined;
    const kind = this.nodeAt(ns) === undefined ? "create" : operation;
    return lockRefuses(covering.lock, kind) ? covering.at : undefined;
  }

  private refuseWhereLocked(ns: string, operation: "create" | "update" | "delete"): void {
    const covering = this.lockCovering(ns);
    if (covering === undefined) return;
    const { lock, at } = covering;
    // A lock "is released by removing the item or by removing an export
    // that requires it", so an update of the object that holds the item
    // is permitted: a lock that refused the change to its own item could
    // never be released. A delete of that object is refused as any other.
    // Whether the principal may make that change is the lock forbidden
    // condition of the same revision, which no subclause names: ECR-166A.
    // "An update that removes this item, or that changes it to a value
    // refusing fewer operations, is not refused by the lock in force. Every
    // other update of the object is refused by lock_shared and by
    // lock_exclusive, including an update of another metadata item"
    // (revision 347). Which of the two an update is cannot be known here,
    // before the body is read, so an update of the object that holds the
    // item passes this gate and is judged where the item is applied. This
    // server permitted every update of that object before 0.79, which was
    // wider than the rule.
    const here = ns.endsWith("/") ? ns.slice(0, -1) : ns;
    const holder = at.endsWith("/") ? at.slice(0, -1) : at;
    if (operation === "update" && here === holder) return;
    // An operation upon an object that does not exist yet creates it, and a
    // create within what a lock covers is refused as a change to it.
    const kind = this.nodeAt(ns) === undefined ? "create" : operation;
    if (!lockRefuses(lock, kind)) return;
    throw lockConflict(
      "%j is locked by the cdmi_lock item of %j, which does not permit this operation",
      ns, at);
  }

  /** The object at a namespace path of this store, where it holds one. */
  private nodeAt(ns: string): Node | undefined {
    let node: Node = this.store.root();
    for (const seg of ns.split("/")) {
      if (seg === "") continue;
      const next = this.store.tryLookup(node, seg);
      if (next === undefined) return undefined;
      node = next;
    }
    return node;
  }

  /** The lock that covers a namespace path, and the object that holds it. */
  private lockCovering(ns: string): { lock: string; at: string } | undefined {
    let path = ns.endsWith("/") ? ns.slice(0, -1) : ns;
    for (;;) {
      const cut = path.lastIndexOf("/");
      const here = path === "" ? "/" : path;
      const node = this.nodeAt(here);
      if (node !== undefined) {
        const lock = this.store.meta(node).metadata?.cdmi_lock;
        if (typeof lock === "string" && lock !== "lock_none") {
          return { lock, at: here === "" ? "/" : here };
        }
      }
      if (cut < 0 || path === "") return undefined;
      path = path.slice(0, cut);
    }
  }

  /**
   * Evaluates the access control list of the importing object, where an
   * object is reached through a protocol import.
   *
   * "The CDMI server evaluates the access control lists of the importing
   * object before it issues any request to the import source, so that a
   * principal not permitted to access the importing object does not reach
   * an object through it." The list of the object itself is the import
   * source's to enforce, and the source is authoritative for it; the list
   * of the importing object is this server's, and is the gate on the
   * indirect path. This server enforced it on a listing and not on a read
   * of a value before 0.73 (weedmi ACTL-016).
   */
  private demandOfImportingObject(pv: View, ref: ObjRef, who: Principal, bit: number,
    doing: string): void {
    // The question is whether the object was reached *through* an import,
    // not what kind of reference names it: an importing container may
    // present an object this server holds in a lower layer, whose own list
    // grants what the importing object's denies. Returning early for a
    // store reference let exactly that through (weedmi ACTL-016), which is
    // the fifth path of this shape they have found.
    if (!pv.importing && pv.entries.length === 0 && pv.importGovernor === undefined) return;
    // The importing object is the nearest container of this server's own
    // namespace through which the object was reached.
    const holder = nodeOf(pv.held);
    if (holder === undefined) return;
    this.demand(holder, who, bit, true, doing);
  }

  /**
   * Obtains the value of an object an HTTP import presents, where the value
   * this server holds is not to be presented again.
   *
   * "A CDMI server obtains the value when the importing object is first read,
   * and thereafter as the cache_max_age field provides. Where that field
   * states an interval, the CDMI server obtains the value again by a
   * conditional request, using the entity tag or the time the origin server
   * last returned." A request that does not succeed leaves the value this
   * server holds in place and records the condition, the import being
   * reported not active rather than the read failing.
   */
  private async refreshHttpImport(node: Node, ns: string): Promise<void> {
    const m = this.store.meta(node);
    const entries = (m.imports ?? []) as unknown as ImportEntry[];
    const entry = entries.find((e) => e.type === "HTTP");
    if (entry === undefined) return;
    const held = (entry as { obtainedAt?: number }).obtainedAt;
    if (stillFresh(entry as HttpImportEntry, held)) return;
    try {
      const got = await obtainImport(entry as HttpImportEntry,
        () => this.importSecret(node, entry), held !== undefined,
        () => this.importTrustAnchor(node, entry));
      const now = this.store.meta(node);
      const held2 = (now.imports ?? []) as unknown as ImportEntry[];
      const mine = held2.find((e) => e.type === "HTTP") ?? entry;
      (mine as { obtainedAt?: number }).obtainedAt = Date.now();
      (mine as { last_problems?: unknown[] }).last_problems = [];
      if (got.status === 304) {
        // The value this server holds is the value: nothing else changes.
        this.store.setMeta(node, now);
        return;
      }
      if (got.status < 200 || got.status >= 300) {
        (mine as { last_problems?: unknown[] }).last_problems =
          [`the origin server answered ${got.status}`];
        this.store.setMeta(node, now);
        return;
      }
      mine.etag = got.etag;
      mine.last_modified = got.lastModified;
      // "the mimetype field, from the Content-Type header field", and the
      // size from the length of what was returned.
      if (got.mimetype !== undefined) now.mimetype = got.mimetype;
      // "the cdmi_mtime metadata item, from the Last-Modified header field,
      // where the origin server returns one."
      if (got.lastModified !== undefined) {
        const at = Date.parse(got.lastModified);
        if (!Number.isNaN(at)) now.mtime = at;
      }
      this.store.setMeta(node, now);
      if (got.value !== undefined) await this.store.writeValue(node, 0, got.value);
    } catch (err) {
      const now = this.store.meta(node);
      const held2 = (now.imports ?? []) as unknown as ImportEntry[];
      const mine = held2.find((e) => e.type === "HTTP");
      if (mine !== undefined) {
        (mine as { last_problems?: unknown[] }).last_problems =
          [`the origin server could not be reached: ${(err as Error).message}`];
        this.store.setMeta(node, now);
      }
      void ns;
    }
  }

  /**
   * An object that holds a lock admits an update that removes the item or
   * weakens it, and no other: "every other update of the object is refused
   * ... including an update of another metadata item" (revision 347).
   */
  private refuseLockedChange(node: Node, body: Record<string, unknown>): void {
    const held = this.store.meta(node).metadata?.cdmi_lock;
    if (typeof held !== "string" || !lockRefuses(held, "update")) return;
    const supplied = (body.metadata ?? {}) as Record<string, unknown>;
    const after = "cdmi_lock" in supplied ? supplied.cdmi_lock : held;
    const weaker = after === null || after === undefined || after === "lock_none" ||
      LOCK_ORDER.indexOf(String(after)) < LOCK_ORDER.indexOf(held);
    if (!weaker) {
      throw lockConflict(
        "this object is locked by its cdmi_lock item, which admits an update that " +
        "removes the item or weakens it, and no other");
    }
  }

  /**
   * The scope a tool call requires, checked against the token resolved at
   * the domain that owns the object the call addresses. Returns the tool
   * result to answer with where the call is refused, and undefined where
   * it may proceed.
   */
  private async resolveMcpPrincipal(
    c: { tool: string; args: Record<string, unknown>; token: string },
    path: string): Promise<{ who?: Principal; refused?: Record<string, unknown> }> {
    if (this.mcpAuth === undefined) return {};
    const domain = this.domainOfPath(path);
    try {
      const auth = await this.mcpAuth.resolveIn(domain, c.token);
      this.mcpAuth.demandScope(auth, c.tool, c.args.body as Record<string, unknown> | undefined);
      // The operation runs as this principal: it has been resolved at the
      // domain that owns the object, which is what the subclause asks
      // for, and nothing is gained by resolving the same token again.
      return { who: auth.principal };
    } catch (e) {
      // Both the unaccepted token and the insufficient scope are reported
      // in the tool result: the operation has begun, the target has been
      // read, and this is not a fault of the message.
      const of = e as { challenge?: string; message: string; name: string; required?: string };
      const type = of.name === "InsufficientScope" ? "insufficient-scope" : "unauthenticated";
      const problem = {
        type: `${SEEDMI_PROBLEM_BASE}mcp/${type}`,
        title: of.name === "InsufficientScope"
          ? "The access token does not carry the scope this operation requires."
          : "The access token is not accepted within the domain that owns this object.",
        detail: of.message,
        // The challenge, and the scope it names, carried in the problem
        // document rather than in a header field: the call was dispatched and
        // its target read, so the response is a tool result and not a 401, and
        // a WWW-Authenticate on a 200 would be a misuse of HTTP. A client that
        // has to obtain a token with another scope, or from another
        // authorization server, reads what it needs from here — it had no way
        // to learn either before 0.86, the challenge having been built and
        // discarded.
        ...(of.required === undefined ? {} : { scope: of.required }),
        ...(of.challenge === undefined ? {} : { www_authenticate: of.challenge }),
      };
      return {
        refused: {
          // Every tool result of this protocol binding carries a resultType
          // of "complete", one reporting a condition included: the call
          // completed, and the condition is its outcome.
          resultType: "complete",
          isError: true,
          structuredContent: problem,
          content: [{ type: "text", text: `${problem.title} ${problem.detail}` }],
        },
      };
    }
  }

  /**
   * The mode of an update against the selection its uri carries. A mode that
   * does not agree with the selection is reported in the tool result: the call
   * has been dispatched and its target read.
   *
   * The two disagreements carry different conditions, which is not a choice
   * this server makes. Of "replace-fields": "The uri argument shall contain a
   * field selection, and the CDMI server shall report the invalid selection
   * condition where it does not" — a selection that is absent where the mode
   * requires one is a fault of the selection, and the condition names it in the
   * cdmi_selection member. Of "replace": the uri "shall not contain a field
   * selection", which the subclause leaves to the malformed request condition
   * for a request a client cannot have intended. Both were reported as the
   * malformed request condition until 0.96, so a client that distinguishes the
   * two was told the wrong one for the mode the subclause is explicit about.
   */
  private refuseMcpMode(tool: string, args: Record<string, unknown>, query: string):
    Record<string, unknown> | undefined {
    if (tool !== "cdmi_update") return undefined;
    const mode = String(args.mode);
    const hasFields = query !== "" && query !== "?";
    // A mode outside the set is refused before dispatch, against the enum the
    // input schema declares, so it does not reach here through the endpoint.
    // It is still detected, for a caller that reaches the binding directly.
    const wrong = mode === "replace" && hasFields
      ? { detail: "a complete replacement takes no field selection", selection: undefined }
      : mode === "replace-fields" && !hasFields
        ? {
          detail: "a field-constrained replacement takes a field selection in the uri",
          selection: "",
        }
        : !["replace", "replace-fields", "merge"].includes(mode)
          ? {
            detail: `the mode is "replace", "replace-fields" or "merge"; ` +
              `${JSON.stringify(mode)} is none`,
            selection: undefined,
          }
          : undefined;
    if (wrong === undefined) return undefined;
    const problem = wrong.selection === undefined
      ? {
        type: `${PROBLEM_BASE}malformed-request`,
        title: "The request is malformed.",
        detail: wrong.detail,
        cdmi_argument: "mode",
      }
      : {
        type: `${PROBLEM_BASE}invalid-selection`,
        title: "A selection is invalid.",
        detail: wrong.detail,
        cdmi_selection: wrong.selection,
      };
    return {
      // Every tool result of this protocol binding carries a resultType
      // of "complete", one reporting a condition included: the call
      // completed, and the condition is its outcome.
      resultType: "complete",
      isError: true,
      structuredContent: problem,
      content: [{ type: "text", text: `${problem.title} ${problem.detail}` }],
    };
  }

  /**
   * The domain that owns the object a path names, which is the domain the
   * access token is resolved at. Where the object is not there, or the
   * path does not resolve, the root domain answers: a token that resolves
   * nowhere is refused, and the operation reports the object's absence
   * rather than the token's.
   */
  private domainOfPath(path: string): string {
    const within = path.startsWith(this.base) ? path.slice(this.base.length - 1) : path;
    const node = this.nodeAt(within);
    if (node === undefined) {
      // Not there: the root domain resolves the token, and the operation
      // reports the object's absence rather than the token's.
      return "/cdmi_domains/";
    }
    return this.store.pathOf(this.domainOf(node));
  }

  /**
   * The base URIs this server reports under "org.snia.cdmi/baseUris", which
   * a namespace path of an MCP call is resolved against. "A CDMI server
   * serves more than one base URI: a CDMI export establishes one for each
   * container object it publishes" (CDMI over MCP).
   */
  baseUris(): string[] {
    const exported = (this.exports?.cdmiBases() ?? []).map((b) => b.uri);
    return [this.base, ...exported];
  }

  /**
   * Resolves an access token at the domain named, to the principal the
   * subject names there. "Resolve the subject of the access token to a
   * principal within the domain that owns the object": the domain is the
   * object's, which the operation knows and the transport does not, so
   * this is called from the operation.
   */
  async resolveTokenIn(domain: string, token: string):
    Promise<{ principal: Principal; scopes: string[] } | undefined> {
    const controller = this.domainControllers?.for(domain);
    if (controller === undefined) {
      // No directory serves this domain. "Where the domain names no directory,
      // a CDMI server resolves the subject of the token to a principal of that
      // domain by the means it is configured with, as it resolves a principal
      // authenticated by any other means for such a domain. A domain that
      // names no directory is a domain whose principals the CDMI server holds,
      // and this document requires no directory of a domain" (revision 365).
      // The means this server is configured with is the [oauth] issuer.
      return this.directory.tokenPrincipal(token);
    }
    const accepted = await controller.accept(`Bearer ${token}`, ["bearer"]);
    if (accepted.principal.name === "ANONYMOUS@") return undefined;
    // The scopes a token carries, which narrow what it may ask for. A token
    // carrying none is resolved all the same: a server that requires no scope
    // accepts it, and one that does refuses the call by scope.
    //
    // This read the field through a cast until 0.86, and the controller never
    // set it, so the set was always empty and every call was refused by scope
    // wherever scopes were required. The controller now returns them.
    return { principal: accepted.principal, scopes: accepted.scopes ?? [] };
  }

  /**
   * Whether a token is one an authorization server this CDMI server accepts
   * issued for this CDMI server. "A CDMI server shall ... validate that each
   * access token presented to it was issued for it, and reject a token that
   * does not identify it as the intended recipient" (8.3.3).
   *
   * This is a check of the token and not a resolution of a principal: the
   * domain within which the subject is resolved is the domain that owns the
   * object a call addresses, and a method that addresses no object — the
   * tool list, the initialization — has none. Before 0.83 nothing checked
   * such a method's token at all, so a token with a signature that is not
   * one, from an issuer this server does not know, for another audience,
   * received the full tool list; the presence of a token was checked and its
   * validity was not (weedmi BMCP-010).
   *
   * A token is accepted here where any configured domain controller accepts
   * it, each of which verifies the issuer, the signature, the expiry and
   * that this server is the intended recipient. Where this server has no
   * domain controller it accepts no token: the endpoint says in its
   * challenge that it requires "an access token of an authorization server
   * it accepts", and it has none.
   */
  async acceptsToken(token: string): Promise<boolean> {
    // The authorization server this whole deployment accepts, configured in
    // [oauth] and used by the HTTP binding. 0.83 consulted the domain
    // controllers alone, so a deployment with an [oauth] issuer and no
    // controller accepted a token at its CDMI binding and refused the same
    // token at its MCP endpoint, which made the binding unusable and left
    // nine of weedmi's ten MCP tests unable to run (BMCP-010).
    if (this.directory.tokens !== undefined) {
      const p = this.directory.principalOfToken(token);
      if (p !== undefined) return true;
    }
    for (const controller of this.domainControllers?.all() ?? []) {
      try {
        const accepted = await controller.accept(`Bearer ${token}`, ["bearer"]);
        if (accepted.principal.name !== ANONYMOUS.name) return true;
      } catch {
        // A controller that refuses the token, or that cannot be reached,
        // does not decide for the others.
      }
    }
    return false;
  }

  /**
   * The authorization servers from which this CDMI server accepts access
   * tokens, which RFC 9728 metadata states and 8.3.3 requires it to state.
   * The issuer of [oauth], where one is configured, and the issuer of each
   * domain controller. 0.83 published the controllers alone, so a deployment
   * that accepts tokens published an empty array.
   */
  authorizationServers(): string[] {
    const out = new Set<string>();
    const own = this.directory.tokens?.issuer;
    if (own !== undefined && own !== "") out.add(own);
    for (const c of this.domainControllers?.all() ?? []) {
      const issuer = c.config.issuer;
      if (issuer !== undefined && issuer !== "") out.add(issuer);
    }
    return [...out];
  }

  /**
   * Performs a tool call of the CDMI over MCP binding. Phase 3 of PLAN-mcp
   * maps each tool onto the operation it names; until then a call is
   * refused in the channel the subclause requires, rather than answered
   * wrongly.
   */
  async mcpCall(c: { tool: string; args: Record<string, unknown>; token: string;
    authorization?: string; traceparent?: string; client?: Record<string, unknown> }):
    Promise<Record<string, unknown>> {
    if (!["cdmi_read", "cdmi_create", "cdmi_update", "cdmi_delete", "cdmi_post"]
      .includes(c.tool)) {
      return mcpNotYet(c.tool);
    }
    const baseUri = typeof c.args.baseUri === "string" ? c.args.baseUri : this.base;
    const { path, query } = addressOf(baseUri, String(c.args.uri));
    // "Resolve the subject of the access token to a principal within the
    // domain that owns the object": the domain is known now that the
    // target has been read, which is why this happens here and not in the
    // transport. The scope is then checked against what that resolution
    // returned; a scope permits no operation the access control lists do
    // not permit, so the operation evaluates those regardless.
    const resolved = await this.resolveMcpPrincipal(c, path);
    if (resolved.refused !== undefined) return resolved.refused;
    // "A CDMI server reports the limit exceeded condition where a CDMI
    // client requests more than the bound, and a CDMI client obtains the
    // rest by requesting a further range", with the bound reported in the
    // extension members so that the client can choose a range that works.
    const asked = rangeAsked(query);
    if (asked !== undefined && asked > Binding.MCP_CHILDREN_BOUND) {
      const problem = {
        type: `${PROBLEM_BASE}limit-exceeded`,
        title: "A limit of this CDMI server was exceeded.",
        detail: `this protocol binding returns at most ${Binding.MCP_CHILDREN_BOUND} ` +
          `of the children or values of an object in one call; ${asked} were requested, ` +
          "and the rest are obtained by requesting a further range",
        cdmi_limit: "range",
        cdmi_limit_value: String(Binding.MCP_CHILDREN_BOUND),
      };
      return {
        // Every tool result of this protocol binding carries a resultType
        // of "complete", one reporting a condition included: the call
        // completed, and the condition is its outcome.
        resultType: "complete",
        isError: true,
        structuredContent: problem,
        content: [{ type: "text", text: `${problem.title} ${problem.detail}` }],
      };
    }
    // "Specified as the media type ... without the application/ prefix,
    // for example cdmi-object": the operation speaks media types, and
    // the result reports the form the argument takes.
    const accept = mcpMediaTypeOf(c.args.representation);
    // The operation is performed by the path that performs it for the HTTP
    // protocol binding: the access control lists, the selections, the
    // conditions and the representations are that path's, and there is no
    // second place for a rule to be forgotten.
    // A base URI may be an absolute URI, where an export established it,
    // or the path this server serves its own namespace at. Both give a
    // path to request and, for the first, the authority to request it of.
    const absolute = /^https?:\/\//i.test(path);
    const where = absolute ? new URL(path) : undefined;
    // The method each tool performs: a create is a PUT, an update a PUT or
    // a PATCH by its mode, a delete a DELETE, and a create with a
    // server-assigned name a POST.
    const body = c.args.body === undefined ? undefined : JSON.stringify(c.args.body);
    const method = {
      cdmi_read: "GET",
      cdmi_create: "PUT",
      cdmi_update: c.args.mode === "merge" ? "PATCH" : "PUT",
      cdmi_delete: "DELETE",
      cdmi_post: "POST",
    }[c.tool] ?? "GET";
    const refusedMode = this.refuseMcpMode(c.tool, c.args, query);
    if (refusedMode !== undefined) return refusedMode;
    const req = composeRequest(method, `${where?.pathname ?? path}${query}`, {
      ...(where === undefined ? {} : { host: where.host }),
      // The token the call bore, presented to the operation as the
      // credential of the request it performs.
      authorization: c.authorization ?? `Bearer ${c.token}`,
      ...(accept === undefined ? {} : { accept }),
      ...(body === undefined ? {} : {
        "content-type": accept ?? "application/cdmi-object",
        "content-length": String(Buffer.byteLength(body)),
      }),
      // "onlyIfAbsent: where true, the operation shall be performed only
      // where no object exists at the target", which the HTTP binding
      // states as a precondition.
      ...(c.args.onlyIfAbsent === true ? { "if-none-match": "*" } : {}),
      ...(typeof c.args.ifMatch === "string" ? { "if-match": c.args.ifMatch } : {}),
    }, body);
    if (resolved.who !== undefined) this.resolvedPrincipal.set(req, resolved.who);
    // "A CDMI server that keeps a record of an operation records that
    // value with it, so that the record an intermediary keeps and the
    // record the CDMI server keeps are recognizable as being of one
    // operation. It records with them the identity of the program that
    // made the call", which the clientInfo of the call carries.
    if (c.traceparent !== undefined) {
      this.mcpTrace.set(req, {
        traceparent: c.traceparent,
        client: typeof c.client?.name === "string" ? c.client.name : undefined,
      });
    }
    // The tool is recorded whether or not the call carried a trace identifier,
    // and is what marks the operation as one of this binding: a call that
    // carried none is still an MCP call, and a provider reading the field this
    // server passes through is told so.
    this.mcpTool.set(req, c.tool);
    const { res, done } = collectResponse();
    await this.handle(req, res);
    const answer = await done;
    let object: unknown;
    try {
      object = answer.body === "" ? undefined : JSON.parse(answer.body);
    } catch {
      object = undefined;
    }
    if (answer.status >= 400) {
      // "Every other condition" is reported in a tool result, whose
      // structuredContent is the problem details document.
      return {
        // Every tool result of this protocol binding carries a resultType
        // of "complete", one reporting a condition included: the call
        // completed, and the condition is its outcome.
        resultType: "complete",
        isError: true,
        structuredContent: object ?? {
          type: `${SEEDMI_PROBLEM_BASE}unknown`,
          title: "The operation did not succeed.",
        },
        content: [{ type: "text", text: mcpAccountOfProblem(object) }],
      };
    }
    const reported = (object ?? {}) as Record<string, unknown>;
    // "A CDMI server shall apply a default bound ... to the number of
    // children a read of a container object returns and to the number of
    // values a read of a queue object returns. It shall report what it
    // returned in the childrenrange field or the valuerange field."
    //
    // The bound is applied to what is returned rather than by a selection
    // of the request: a selection makes the representation partial, which
    // would drop every other field the client asked for.
    for (const [field, range] of [["children", "childrenrange"],
      ["value", "valuerange"]] as [string, string][]) {
      const got = reported[field];
      if (!query.includes(field) && Array.isArray(got)
        && got.length > Binding.MCP_CHILDREN_BOUND) {
        reported[field] = got.slice(0, Binding.MCP_CHILDREN_BOUND);
        reported[range] = `0-${Binding.MCP_CHILDREN_BOUND - 1}`;
      }
    }
    // "For a cdmi_post call, and for any operation in which the CDMI
    // server assigned the name, this member reports the address at which
    // the object is addressable from then on, and is the only means by
    // which a CDMI client obtains it": the address the operation
    // returned, made relative to the base URI the call was resolved
    // against, and not the address the call named.
    // A redirection is a reference, not an assignment: the protocol
    // binding of the HTTP binding answers a reference with a redirection
    // whose Location is the destination, where it reports a name this
    // server assigned with a 2xx carrying one. Reading both from the same
    // header without regard to the status made a reference report its
    // destination as the address addressed, and carry no reference member
    // at all, so a CDMI client learned neither that the object was a
    // reference nor where it pointed.
    const redirected = answer.status >= 300 && answer.status < 400
      ? (answer.headers.location as string | undefined)
      : undefined;
    const assigned = redirected === undefined ? answer.headers.location : undefined;
    const at = assigned === undefined
      ? String(c.args.uri)
      : relativeToBase(assigned, baseUri, where?.origin);
    // "Present only where the object addressed is a reference": the
    // destination the operation reported, where it reported one. "A CDMI
    // client that follows the destination shall limit the number of
    // destinations it follows", so this server reports it and does not
    // follow it.
    const reference = typeof reported.reference === "string"
      ? reported.reference
      : redirected;
    // "correctedUri: the namespace path in the form that addresses the
    // object, where the form of the uri argument did not address it."
    const addressed = typeof reported.parentURI === "string"
      && typeof reported.objectName === "string"
      ? `${reported.parentURI}${reported.objectName}`
      : undefined;
    const corrected = addressed !== undefined && addressed !== at.split("?")[0]
      ? addressed
      : undefined;
    // "remote: present where an address this result reports is of another
    // CDMI server: a JSON array of the absolute URIs so reported", which a
    // CDMI client reaches through the endpoint of that CDMI server.
    const remote = remoteAddresses(reported, this.baseUris());
    const structured = resultOf({
      uri: at,
      representation: representationOf(
        (answer.headers["content-type"] as string | undefined)?.split(";")[0].trim()),
      object: reported,
      baseUri,
      reference,
      ...(corrected === undefined ? {} : { correctedUri: corrected }),
      ...(remote.length === 0 ? {} : { remote }),
      validator: answer.headers.etag,
    });
    return {
      // "A CDMI server shall return a resultType of complete from every
      // tool defined in this subclause, and shall not return a resultType
      // of input_required": an operation of this document either happened
      // or reported a condition, and never asks the caller for more.
      resultType: "complete",
      // "A CDMI server shall set the isError member to false in a result
      // reporting an operation that was performed, and to true in a result
      // reporting one that was not", and "a CDMI client determines the outcome
      // of an operation from the structuredContent member and from the isError
      // member". A result of an operation that was performed carried no
      // isError member at all until 0.96: the Model Context Protocol takes an
      // absent member to be false, so a client reading it got the right answer
      // by the default rather than from what this server stated, and a client
      // that distinguishes absent from false got no answer.
      isError: false,
      structuredContent: structured,
      content: [{
        type: "text",
        text: mcpAccountOf(c.tool, at, reported, reference,
          c.args.body as Record<string, unknown> | undefined),
      }],
    };
  }

  /**
   * The permission a create demands. Where the name already denotes a
   * representation, this create adds another to an object that exists
   * rather than making a new one, so it is a change to that object and
   * demands WRITE_METADATA upon it; the parent's ADD_OBJECT governs only a
   * name that is not yet held (5.3.7, weedmi OPER-042).
   */
  private demandCreate(target: Node, name: string, ns: string, who: Principal,
    bit: number = M.ADD_OBJECT): void {
    for (const kind of ["data", "container", "queue"] as const) {
      const other = this.store.lookupKind(target, name, kind);
      if (other === undefined) continue;
      this.demand(other, who, M.WRITE_METADATA, true,
        `adding a representation to ${ns}`);
      return;
    }
    this.demand(target, who, bit, true, `creating ${ns}`);
  }

  private async applyToNew(node: Node, body: Record<string, unknown>, form: string,
    sel: Selection, name: string, who: Principal): Promise<void> {
    try {
      await this.applyData(node, body, form, sel, name, true, who);
    } catch (e) {
      try {
        await this.store.collect(this.store.removeTree(node));
      } catch {
        // The object could not be removed: the refusal stands regardless, and
        // the object is left for the operator to find.
      }
      throw e;
    }
  }

  /**
   * Applies a representation to an object, holding its lock: the metadata
   * and the value are written together, so a concurrent read sees the state
   * before this update or the state after it, and not a mixture of the two
   * (weedmi OPER-014).
   */
  private async applyData(node: Node, body: Record<string, unknown>, form: string,
    sel: Selection, name: string, fresh: boolean, who: Principal): Promise<void> {
    return this.store.locked(node, () =>
      this.applyDataLocked(node, body, form, sel, name, fresh, who));
  }

  private async applyDataLocked(node: Node, body: Record<string, unknown>, form: string,
    sel: Selection, name: string, fresh: boolean, who: Principal): Promise<void> {
    const m = this.store.meta(node);
    // "An update that removes this item, or that changes it to a value
    // refusing fewer operations, is not refused by the lock in force. Every
    // other update of the object is refused by lock_shared and by
    // lock_exclusive, including an update of another metadata item"
    // (revision 347). The gate above lets an update of the object holding
    // the item through, because which of the two it is cannot be known
    // before the body is read; it is judged here.
    const lockHeld = m.metadata?.cdmi_lock;
    if (typeof lockHeld === "string" && lockRefuses(lockHeld, "update")) {
      const supplied = (body.metadata ?? {}) as Record<string, unknown>;
      const after = "cdmi_lock" in supplied ? supplied.cdmi_lock : lockHeld;
      const weaker = after === null || after === undefined || after === "lock_none" ||
        LOCK_ORDER.indexOf(String(after)) < LOCK_ORDER.indexOf(lockHeld);
      if (!weaker) {
        throw lockConflict(
          "this object is locked by its cdmi_lock item, which admits an update that " +
          "removes the item or weakens it, and no other");
      }
    }
    // Whether the cdmi_value_hash item was supplied, in which case the
    // value the object holds is hashed even where the value itself did
    // not change.
    let hashWanted = false;
    const has = (f: string) => f in body &&
      (form !== "selected" || sel.fields.includes(f));

    if (form === "complete" && fresh) {
      // "The metadata field is an exception: where it is absent, the stored
      // user metadata and data system metadata are left unchanged" (revision
      // 211). Every other field takes the value a create would assign, which
      // for the media type is its default.
      if ("metadata" in body) m.metadata = {};
      m.mimetype = "";
    }
    // The rel field has the exception the metadata field has: where it is
    // absent from a complete replacement the stored relationships are left
    // unchanged, rather than removed as "the value a create operation would
    // assign ... for any other field is removal" would otherwise give.
    //
    // The document states the exception for the metadata field alone, and
    // ECR-225A asks for it here too. The two fields are the same kind of
    // thing: a store of members a client adds to over time, which a client
    // manages by naming the member it means. A complete replacement of any
    // other field carries what that field is; a complete replacement that
    // silently discarded every relationship an object had, because the
    // representation being written back was read before those relationships
    // existed, is a loss of data a client did not ask for and cannot see it
    // asked for. Until 0.105 a data object removed them here and a container
    // object and a domain object did not, so this server did not even agree
    // with itself.
    applyRel(m, body, has, form);
    // The value transfer encoding describes the value supplied with it:
    // given without a value, the field is not part of this operation, which
    // is the invalid field condition (weedmi OPER-028).
    if (!has("value") && has("valuetransferencoding")) {
      throw invalidField("valuetransferencoding",
        "the valuetransferencoding field describes a value, and no value is supplied");
    }
    if (has("mimetype")) {
      const v = body.mimetype;
      if (v !== null && typeof v !== "string") {
        throw malformed("the mimetype field holds a JSON string");
      }
      m.mimetype = v === null ? "" : v;
    }
    if (has("metadata")) {
      const v = body.metadata;
      if (v === null) {
        m.metadata = {};
      } else if (typeof v !== "object" || Array.isArray(v)) {
        throw malformed("the metadata field holds a JSON object");
      } else {
        const badCors = checkCorsItems(v as Record<string, unknown>);
        if (badCors) {
          throw invalidField(`metadata/${badCors.item}`, "%s", badCors.why);
        }
        const badVersion = checkVersioningItems(v as Record<string, unknown>);
        if (badVersion) {
          throw invalidField(`metadata/${badVersion.item}`, "%s", badVersion.why);
        }
        // A retention period may be extended and a hold added; neither
        // may be shortened or removed.
        const fault = checkChange(m.metadata, v as Record<string, unknown>);
        if (fault) {
          if (fault.condition === "forbidden") {
            throw forbidden("%s: %s", fault.item, fault.why);
          }
          throw faultCondition(fault);
        }
        const supplied = userMetadata(v as Record<string, unknown>, form === "merge");
        m.metadata = form === "merge" ? mergePatch(m.metadata, supplied) : supplied;
        checkValueHash(m.metadata);
        this.checkServiceLevelOf(v as Record<string, unknown>, m.metadata,
          m.parent === null ? undefined : { id: m.parent, isContainer: true });
        recordApplied(m.metadata, this.store.meta(node).metadata);
        // The item asks for the value to be hashed, so a change to it
        // hashes the value the object already holds.
        hashWanted = true;
        const tooMuch = checkMetadataLimits(m.metadata);
        if (tooMuch) {
          throw new Condition(413, "limit-exceeded", "A limit would be exceeded.",
            tooMuch.why).with("cdmi_field", fieldPointer(`metadata/${tooMuch.item}`))
            .with("cdmi_limit", tooMuch.limit)
            .with("cdmi_limit_value", tooMuch.value);
        }
        this.applyOwnerAndACL(node, m, v as Record<string, unknown>, who, false, fresh);
      }
    }

    if (has("mimetype")) {
      const given = body.mimetype;
      if (typeof given !== "string" || mediaType(given) === undefined) {
        // "The value shall be a media type as defined in RFC 2046."
        throw malformed("the mimetype field holds a media type, as RFC 2046 defines one");
      }
      // "The type, the subtype, and the name of each parameter shall be
      // converted to lower case before being stored, as shall the value of a
      // charset parameter. The value of any other parameter shall be stored
      // unchanged" (weedmi REPR-007, REPR-019).
      m.mimetype = mediaType(given)!;
    }
    let content: Buffer | undefined;
    if (has("value")) {
      const vte = typeof body.valuetransferencoding === "string"
        ? body.valuetransferencoding
        : "utf-8";
      if (typeof body.valuetransferencoding !== "string" && body.valuetransferencoding !== undefined) {
        throw malformed("the valuetransferencoding field holds a JSON string");
      }
      if (vte !== "utf-8" && vte !== "base64" && vte !== "json") {
        // A value that does not conform to the form defined for the field is
        // the malformed request condition, not an invalid field, which names
        // a field rather than judges its value (weedmi REPR-011).
        throw malformed('a value is transported as "utf-8", "base64" or "json", and not as %j',
          String(body.valuetransferencoding));
      }
      const v = body.value;
      if (vte === "json") {
        // The value field contains the JSON object itself rather than
        // a string, and the object holds a valid JSON object.
        if (v === null || typeof v !== "object" || Array.isArray(v)) {
          // "Where the value transfer encoding is json and the contents of
          // the value field are set to any value other than a valid JSON
          // object, the CDMI server shall report the malformed request
          // condition", where this server reported an invalid field
          // (weedmi REPR-011).
          throw malformed('where the encoding is "json" the value field contains a JSON object');
        }
        // "The value of a data object whose value transfer encoding is json is
        // the octets of the JSON text the CDMI server received, stored
        // unchanged ... and [the CDMI server] shall neither normalize nor
        // re-serialize them thereafter" (revision 365, closing ECR-153A).
        // Before 0.85 this stored JSON.stringify of the parsed value, so
        // cdmi_size and every range of the value were counted over octets the
        // CDMI client never sent, and a member whose name is a decimal integer
        // came back in another position.
        content = rawValueOf(body) ?? Buffer.from(JSON.stringify(v), "utf8");
      } else {
        if (typeof v !== "string") {
          throw malformed('where the encoding is %j the value field holds a JSON string', vte);
        }
        // "base64" indicates ... transported as a base 64 string: a string
        // that is not one is a malformed request, where this server decoded
        // it loosely and stored whatever fell out (weedmi REPR-011).
        if (vte === "base64" && !isBase64(v)) {
          throw malformed('where the encoding is "base64" the value field contains a base 64 string, ' +
            "as RFC 4648 section 4 defines it");
        }
        content = Buffer.from(v, vte === "base64" ? "base64" : "utf8");
      }
      // "Where a range of the value is requested or supplied, this field
      // shall contain base64": that is the encoding of the transfer, not of
      // the object, so a range update leaves the object's own encoding as it
      // was. This server stored base64 for the object before 0.66, so a
      // complete read of a text object reported base64 afterwards
      // (weedmi OPER-025).
      if (sel.valueRanges.length === 0) m.vte = vte;
    } else if (fresh) {
      content = Buffer.alloc(0);
      m.vte = "utf-8";
    }
    if (m.mimetype === "" && content !== undefined) {
      // "Where the value is not specified when a data object is created, the
      // CDMI server shall assign a value of text/plain where the value
      // transfer encoding is utf-8, a value of application/octet-stream
      // where it is base64, and a value of application/json where it is
      // json." This server guessed from the name's extension before 0.66,
      // which the draft does not provide for (weedmi REPR-006, REPR-010).
      m.mimetype = m.vte === "json"
        ? "application/json"
        : m.vte === "base64" ? "application/octet-stream" : "text/plain";
    }
    if (content !== undefined && sel.valueRanges.length === 1) {
      // The bytes supplied are the bytes the range names: "where the length
      // of the value supplied does not match the range, the CDMI server
      // shall report the malformed request condition" (weedmi OPER-027).
      const [from, to] = sel.valueRanges[0];
      const wanted = to - from + 1;
      if (content.length !== wanted) {
        throw malformed("the value supplied is %d octet(s) and the range %d-%d names %d",
          content.length, from, to, wanted);
      }
    }
    // The three operations of the encrypted objects subclause that act on
    // the ciphertext itself, each an update that changes the mimetype field:
    // encrypt in place, decrypt in place, and re-encrypt in place. The key
    // encryption key is obtained for the operation and is not retained, the
    // key management server performing the wrapping (PLAN-encryption.md).
    if (!fresh && has("mimetype") && content === undefined) {
      // The mimetype field of the request has already been applied to the
      // metadata about to be stored, so what the object holds now is read
      // from the store: the operation is decided by the change between them.
      const before = this.store.meta(node).mimetype;
      const after = typeof body.mimetype === "string" ? mediaType(body.mimetype)! : before;
      const item = suppliedEncKeyID(body);
      const wasEncrypted = isEncryptedMediaType(before);
      const willBeEncrypted = isEncryptedMediaType(after);
      if (wasEncrypted || willBeEncrypted) {
        content = await this.encryptionInPlace(node, m, before, after, item, who);
        if (content !== undefined) m.vte = isUTF8(content) ? "utf-8" : "base64";
      }
    }
    // An encrypted object is one whose mimetype is "application/cms" or
    // "application/jose+json", and its value is the structure that media
    // type promises: a CMS structure, or a JWE or a JWS in the JSON
    // serialization whose protected header carries the media type of the
    // plaintext. Storing one requires no capability, and this server
    // neither decrypts it nor reports the plaintext's media type in the
    // mimetype field (PLAN-encryption.md, phase 1).
    if (content !== undefined && isEncryptedMediaType(m.mimetype) &&
        sel.valueRanges.length === 0) {
      try {
        readEncryptedValue(m.mimetype, content);
      } catch (e) {
        if (e instanceof EncryptedValueError) {
          // Revision 347 names the condition for every fault of an
          // encrypted value met in that subclause: the invalid field
          // condition, identifying the value field. This server reported
          // the malformed request condition, which was equally defensible
          // until the revision said otherwise (ECR-171B).
          throw invalidField("value",
            "the value of an object of the media type %j is not one: %s",
            m.mimetype, e.message);
        }
        throw e;
      }
    }
    this.store.setMeta(node, m);
    // The object signature is produced after the value and the metadata are
    // stored: its payload carries the digest of the value as stored.
    const signAfterwards = m.metadata?.cdmi_enc_object_sign_id !== undefined;
    if (content !== undefined) {
      if (sel.valueRanges.length === 1) {
        await this.store.writeValue(node, sel.valueRanges[0][0], content);
      } else {
        await this.store.setValue(node, content);
      }
    } else if (hashWanted) {
      // The value did not change and the item did, so the value the
      // object already holds is hashed.
      await this.store.rehash(node);
    }
    this.applyExtensionFields(node, body, "data", form, sel);
    // "the CDMI server shall generate [the cdmi_enc_signature item] for
    // each stored object when a corresponding sign_id data system metadata
    // item is present", over the object as it now stands.
    if (signAfterwards) await this.signObject(node, who);
  }

  private async putContainer(req: IncomingMessage, res: ServerResponse, r: Resolver, pv: View,
    ns: string, name: string, body: Record<string, unknown>, form: string,
    sel: Selection, who: Principal): Promise<void> {
    let cv: View | undefined;
    try {
      cv = await r.child(pv, name);
    } catch {
      cv = undefined;
    }
    // A conditional request, evaluated against the container object
    // representation this request names and not against the name: a name may
    // denote a container object representation beside another, and
    // "If-None-Match: *" asks whether the one being created is there.
    //
    // Nothing here evaluated a precondition before 0.85, so a create made
    // conditional on the absence of a container object replaced one that was
    // there and answered 204, and an "If-Match" naming a stale entity tag was
    // applied. Found by rewriting a duality test that revision 365 made
    // unreachable in its old form: the test moved from a data object and a
    // queue object to a container object and a queue object, and the
    // precondition it had always asserted stopped being honoured.
    {
      const inm = req.headers["if-none-match"] as string | undefined;
      const im = req.headers["if-match"] as string | undefined;
      const held = cv === undefined ? undefined : nodeOf(cv.held);
      if (inm === "*" && held !== undefined) {
        throw alreadyExistsPrecondition("%s exists, and the request was made conditional on its absence", ns);
      }
      if (im !== undefined) {
        if (held === undefined) throw validatorConflict();
        const tag = etagOf(viewOf(this.store, { kind: "store", node: held }));
        if (im !== "*" && !matchesETag(im, tag)) throw validatorConflict();
      }
    }
    if (!cv) {
      // A merge update creates nothing; a create carrying a field selection
      // applies only the selected fields, as applyContainerFields does.
      if (form === "merge") throw notFound(ns);
      // A data object or a queue object of this name is not a
      // conflict: a name denotes a container object representation
      // beside them, each addressed independently.
      const target = await ensureWriteTarget(this.store, pv);
      this.demandCreate(target, name, ns, who, M.ADD_SUBCONTAINER);
      // The create and the fields it carries are one change: a field
      // that does not validate leaves no container object behind.
      // The credential references of the imports are bound before the
      // transaction, which cannot wait on a key management server, against
      // the domain the container will have.
      const domain = this.domainFor(body, target, who) ?? this.domainOf(target);
      const bound = await this.withBoundImports(target, body, who, domain);
      this.store.tx(() => {
        const node = this.store.createContainer(target, name,
          this.newObjectIdentity(body, target, who, true));
        this.applyContainerFields(node, ns, bound, form, sel, true, who);
        this.store.startCounts(node);
      });
      const created = await r.child(await r.view(pv.ns), name);
      // "Where a field selection was supplied, the CDMI server shall return a
      // partial representation containing the selected fields" (7.4.7).
      return this.sendContainer(req, res, created, pv, name, sel.any ? sel : emptySelection(), 201, false, who);
    }
    // An operation on a merged container object goes to the write target,
    // unless a layer above it holds a container object of that name.
    if (cv.upper) {
      throw conflictImportLayer(cv.objLayer.rank[0], pv.ns,
        "%s is present in a layer above the write target of %s, which denies the change",
        ns, pv.ns);
    }
    if (cv.importing && pv.writeRank !== undefined &&
      rankCmp(cv.objLayer.rank, pv.writeRank) !== 0) {
      // An importing container object is never copied into the write
      // target, since its imports field is not copied.
      throw denyChange(pv, ns, cv.objLayer.rank, "change");
    }
    if (changesUserMetadata(body) || "imports" in body || "exports" in body) {
      this.demand(cv.held, who, M.WRITE_METADATA, true, `changing ${ns}`);
    }
    // The items governed by a bit of their own, as on a data object: a cdmi_
    // item other than cdmi_acl and cdmi_owner is governed by WRITE_ATTRIBUTES,
    // a retention item by WRITE_RETENTION, and the hold item by
    // WRITE_RETENTION_HOLD. None of the three was demanded of a container object
    // until 0.109 — the bits were enforced for a data object and for a queue
    // object alone — so a principal granted none of them changed the retention
    // of a container object, and, because a body naming nothing but cdmi_ items
    // passed no gate at all, the gate that refuses a change to an object under
    // retention or under hold was never reached either: a container object under
    // hold accepted cdmi_retention_autodelete of "true".
    //
    // The two changes the clause permits on such an object are exempt, as they
    // are for a data object.
    const heldMetadata = (() => {
      const n = nodeOf(cv.held);
      try {
        return n === undefined ? {} : this.store.meta(n).metadata;
      } catch {
        return {};
      }
    })();
    const extendsOnly = !("value" in body) && typeof body.metadata === "object" &&
      body.metadata !== null &&
      !changesMore((body.metadata ?? {}) as Record<string, unknown>, heldMetadata,
        form === "merge");
    if (changesAttributes(body)) {
      this.demand(cv.held, who, M.WRITE_ATTRIBUTES, true, `changing ${ns}`, undefined,
        extendsOnly);
    }
    if (suppliedItems(body).some((k) => RETENTION_ONLY.has(k))) {
      this.demand(cv.held, who, M.WRITE_RETENTION, true,
        `changing the retention of ${ns}`, undefined, extendsOnly);
    }
    if (suppliedItems(body).some((k) => HOLD_ITEMS.has(k))) {
      this.demand(cv.held, who, M.WRITE_RETENTION_HOLD, true,
        `changing the holds of ${ns}`, undefined, extendsOnly);
    }
    // An operation that changes an importing container object, its
    // imports field included, acts on that object and is not directed
    // into the layers it presents (9.2). For a merged container object it
    // is directed to the write target, which may have to be created.
    const target = cv.importing && cv.held.kind === "store"
      ? cv.held.node
      : await ensureWriteTarget(this.store, cv);
    // "The domain that owns the object may be changed, subject to the
    // cross_domain privilege" (the update subclause). A container object
    // ignored domainURI on an update before 0.47.
    const parentOfContainer = nodeOf(pv.held);
    const wantedDomain = parentOfContainer === undefined ? undefined : this.domainFor(body, parentOfContainer, who);
    if (wantedDomain) await this.changeDomain(target, wantedDomain, who, body);
    const depositsBefore = this.depositedReferences(target);
    this.applyContainerFields(target, ns, await this.withBoundImports(target, body, who), form, sel, false, who);
    await this.revokeWithdrawn(target, depositsBefore);
    res.writeHead(204);
    res.end();
  }

  private applyContainerFields(node: Node, ns: string, body: Record<string, unknown>,
    form: string, sel: Selection, fresh: boolean, who: Principal): void {
    // A lock on the container admits an update that removes the item or
    // weakens it, and no other (revision 347).
    this.refuseLockedChange(node, body);
    const m = this.store.meta(node);
    const has = (f: string) => f in body && (form !== "selected" || sel.fields.includes(f));
    if (form === "complete" && fresh) m.metadata = {};
    if (has("metadata")) {
      const v = body.metadata;
      if (v === null) {
        m.metadata = {};
      } else if (typeof v !== "object" || Array.isArray(v)) {
        throw malformed("the metadata field holds a JSON object");
      } else {
        const badCors = checkCorsItems(v as Record<string, unknown>);
        if (badCors) {
          throw invalidField(`metadata/${badCors.item}`, "%s", badCors.why);
        }
        const supplied = userMetadata(v as Record<string, unknown>, form === "merge");
        m.metadata = form === "merge" ? mergePatch(m.metadata, supplied) : supplied;
        this.checkServiceLevelOf(v as Record<string, unknown>, m.metadata,
          m.parent === null ? undefined : { id: m.parent, isContainer: true });
        this.applyOwnerAndACL(node, m, v as Record<string, unknown>, who, true, fresh);
      }
    }
    applyRel(m, body, has, form);
    if (has("exports")) {
      if (!this.exports) {
        throw capabilityCondition(
          "this server serves no exports")
          .with("cdmi_capability", "cdmi_export_http");
      }
      const v = body.exports;
      if (v === null) {
        this.exports.set(node, null);
      } else if (form === "merge") {
        this.exports.set(node, mergePatch(
          (this.store.meta(node).exports ?? {}) as Record<string, unknown>,
          v as Record<string, unknown>));
      } else {
        this.exports.set(node, v);
      }
      // An export has been established on a container object.
      if (v !== null) this.event("cdmi_export", node, ns, who);
    } else if (form === "complete" && this.exports && this.exports.configured(node)) {
      // A complete replacement removes a field the representation does
      // not carry, the exports field included.
      this.exports.set(node, null);
    }
    // exports.set writes the row directly, so take the new value rather
    // than the stale one, without discarding the changes made above.
    m.exports = this.store.meta(node).exports;
    if (has("imports")) {
      const v = body.imports;
      if (v === null) {
        m.imports = undefined;
      } else {
        // Validated before it is stored, so an invalid entry never reaches
        // the layering engine.
        const entries = parseImports(v, ns, {
          images: true,
          privileges: who.privileges,
          kms: this.keyManagement.length > 0,
        });
        this.checkImageSources(node, ns, entries);
        m.imports = entries as unknown as ImportEntry[];
      }
    } else if (form === "complete") {
      // A complete replacement removes a field the representation does not
      // carry, the imports field included.
      m.imports = undefined;
    }
    this.store.setMeta(node, m);
    this.recordImageSources(node, m.imports as ImportEntry[] | undefined);
    this.applyExtensionFields(node, body, "container", form, sel);
  }

  /**
   * Records the image imports of a container object, so that the
   * restrictions on a source can be found from the source.
   */
  private recordImageSources(node: Node, entries: ImportEntry[] | undefined): void {
    const images = (entries ?? [])
      .map((e, i) => ({ e, i }))
      .filter(({ e }) => e.type === "image");
    this.store.setImageSources(node, images.map(({ e, i }) => ({
      entry: i,
      path: e.import_uri!,
      writeEnabled: e.write_enabled === "true",
      disabled: e.disabled === "true",
    })));
  }

  /**
   * The conditions of "the import source while the import is active": a
   * second image import of the same source that is write enabled, and an
   * import of a source that another entry of the same object already
   * interprets, both conflict.
   */
  private checkImageSources(node: Node, ns: string, entries: ImportEntry[]): void {
    for (const [i, e] of entries.entries()) {
      if (e.type !== "image" || e.disabled === "true") continue;
      // The draft refuses an import whose source an export transfers.
      // seedmi locks the source instead, since an HTTP export mediates
      // every operation and can enforce the lock on that one object;
      // see K9. An export that hands over control of the bytes, which
      // seedmi does not implement, would still have to be refused.
      if (e.write_enabled !== "true") continue;
      for (const other of this.store.imageSourcesOf(e.import_uri!)) {
        if (other.importer === node.id) continue;
        if (other.disabled || !other.writeEnabled) continue;
        throw conflict(
          "%s is already the source of an image import that is write enabled, and a " +
          "second one would interpret the same file system", e.import_uri)
          .atImport(i, ns);
      }
    }
  }

  /**
   * The restrictions the draft places on a data object whose value an
   * active image import interprets: its value is reached through the
   * imported namespace alone. An operation that modifies it, or deletes
   * it, is reported with the conflict condition; where an import of it is
   * write enabled, so is an operation that reads it. Its metadata,
   * including its imports and exports fields, is not restricted.
   */
  private checkNotAnActiveSource(ns: string, what: "read" | "change" | "delete"): void {
    const sources = this.store.imageSourcesOf(ns).filter((s) => !s.disabled);
    if (sources.length === 0) return;
    if (what === "read" && !sources.some((s) => s.writeEnabled)) {
      // No party is writing the file system, so a read is permitted.
      return;
    }
    throw conflict(
      "the value of %s is interpreted by an active image import, and is reached through " +
      "the imported namespace alone; an operation that would %s it conflicts with that " +
      "import", ns, what);
  }

  /**
   * Applies the cdmi_owner and cdmi_acl items of a supplied metadata
   * field, which require WRITE_OWNER and WRITE_ACL. They are storage
   * system metadata, so userMetadata drops them from the user items.
   */
  private applyOwnerAndACL(node: Node, m: StoredMeta, supplied: Record<string, unknown>,
    who: Principal, isContainer: boolean, fresh: boolean): void {
    // These are generated by the CDMI server. A CDMI client holding
    // the backup operator privilege sets five of them, so that an
    // object restored from a backup has the times and counts it had
    // when the backup was taken; this server grants that privilege
    // to no principal. cdmi_size is computed from the value and is
    // set by no principal at all.
    //
    // An attempt to set one of them is **ignored** and is not
    // reported as an error, which each of the two clauses requires
    // in its own words: the privileges table for the five, and the
    // definition of cdmi_size for the sixth. A CDMI client that
    // writes a whole metadata object it read earlier therefore has
    // the generated items dropped rather than the request refused.
    // A principal holding the backup operator privilege would set
    // the five that describe when the object was touched and how
    // often. That is not implemented: setMeta persists none of
    // those columns, so it needs a store operation of its own.
    for (const item of SERVER_GENERATED_METADATA) {
      delete supplied[item];
    }
    if ("cdmi_group" in supplied) {
      const v = supplied.cdmi_group;
      if (typeof v !== "string") {
        throw invalidField("metadata/cdmi_group", "cdmi_group shall be a JSON string");
      }
      // The group is changed by a principal the list permits to change
      // the ownership of the object. The permission governs a change,
      // so it is evaluated where there is one: a CDMI client that
      // reads a representation and writes it back unaltered is not
      // asking to change the ownership of anything.
      if (!fresh && v !== m.group) {
        this.demand(node, who, M.WRITE_OWNER, isContainer, "changing cdmi_group");
      }
      m.group = v;
    }
    if ("cdmi_owner" in supplied) {
      const v = supplied.cdmi_owner;
      if (typeof v !== "string") {
        throw invalidField("metadata/cdmi_owner", "cdmi_owner shall be a JSON string");
      }
      if (!fresh && v !== m.owner) {
        this.demand(node, who, M.WRITE_OWNER, isContainer, "changing cdmi_owner");
      }
      m.owner = v;
    }
    // The items that request delegated access control determine the
    // authorization applied to the object, and are "governed as the cdmi_acl
    // item is governed": a CDMI client that adds, changes or removes one needs
    // the permission that item requires, and a CDMI client holding the backup
    // operator privilege may set it. The requirement applies whether or not
    // this server supports delegated access control.
    for (const item of ["cdmi_dac_uri", "cdmi_dac_certificate"]) {
      if (!(item in supplied)) continue;
      // What is stored, not what this update has already merged into m.
      const before = (this.store.meta(node).metadata as Record<string, unknown>)[item];
      const after = supplied[item];
      if (!fresh && JSON.stringify(before ?? null) !== JSON.stringify(after ?? null)) {
        this.demand(node, who, M.WRITE_ACL, isContainer, `changing ${item}`);
        // The decision was obtained under the configuration that is changing.
        this.dac?.forget(this.store.meta(node).objectID);
      }
    }
    if ("cdmi_acl" in supplied) {
      // The list of the object is part of the configuration under which a
      // delegated decision was obtained, so a change to it discards what was
      // retained, as a change to either of the two items does.
      this.dac?.forget(this.store.meta(node).objectID);
      const v = supplied.cdmi_acl;
      if (v === null) {
        if (!fresh && m.acl !== null) {
          this.demand(node, who, M.WRITE_ACL, isContainer, "changing cdmi_acl");
        }
        m.acl = null;
        return;
      }
      if (!Array.isArray(v)) {
        throw invalidField("metadata/cdmi_acl", "cdmi_acl shall be a JSON array of entries");
      }
      // The list supplied is parsed before it is compared, so that a
      // list written back in the form it was read is recognised as the
      // list that is already there.
      const parsed = v.map((raw, i) => {
        if (raw === null || typeof raw !== "object") {
          throw invalidField(`metadata/cdmi_acl/${i}`, "an access control entry is a JSON object");
        }
        const e = raw as Record<string, unknown>;
        const entry = {
          acetype: String(e.acetype ?? "ALLOW"),
          identifier: String(e.identifier ?? ""),
          aceflags: String(e.aceflags ?? "NO_FLAGS"),
          acemask: String(e.acemask ?? "NONE"),
        };
        let bits;
        try {
          bits = parseACE(entry, isContainer);
        } catch (err) {
          throw invalidField(`metadata/cdmi_acl/${i}`, "%s", String(err));
        }
        // "Where an access control entry names a mask bit or a flag the CDMI
        // server does not support, the CDMI server shall reject the entry and
        // shall not store it" (revision 269). Before 0.61 an undefined bit given
        // in hexadecimal was stored.
        const unsupported = unsupportedIn(bits);
        if (unsupported !== undefined) {
          throw invalidField(`metadata/cdmi_acl/${i}`,
            "the entry names %s, which this server does not support (see cdmi_acl_mask_bits and cdmi_acl_flags)", unsupported);
        }
        return entry;
      });
      if (!fresh && JSON.stringify(parsed) !== JSON.stringify(m.acl)) {
        this.demand(node, who, M.WRITE_ACL, isContainer, "changing cdmi_acl");
      }
      m.acl = parsed;
    }
  }

  // -----------------------------------------------------------------
  // Delete

  /**
   * Removes values from a queue object. Values are removed in order
   * from the oldest, and a gap is not created: a range whose first
   * position lies above the lowest designator held would leave one,
   * and is refused.
   */
  private async dequeue(res: ServerResponse, node: Node, ns: string,
    q: { count: number } | { range: [number, number] }, who: Principal): Promise<void> {
    // Removing a value changes what the queue object holds, and is
    // the operation APPEND_DATA alone does not permit.
    this.demand(node, who, M.WRITE_OBJECT, false, `removing values from ${ns}`);
    // A removal names the values by their designators. A count would
    // select the values that are oldest when the removal is
    // performed, which are not the values the client read, and would
    // remove further values each time it was repeated.
    if ("count" in q) {
      throw invalidSelection(`values=${q.count}`,
        "a removal supplies a range of designators, which identify the values to " +
        "be removed, and not a count");
    }
    const bounds = this.store.queueBounds(node);
    const [first, last] = q.range;
    if (bounds.count > 0 && first > bounds.lowest) {
      throw conflict(
        "values are removed in order from the oldest and a gap is not created: the " +
        "range begins at %d and the oldest value this queue object holds is %d",
        first, bounds.lowest);
    }
    // A first position below the lowest begins at the lowest, and a
    // last position above the highest stops at the highest.
    const from = bounds.lowest;
    const to = Math.min(last, bounds.highest);
    if (bounds.count === 0 || last < bounds.lowest) {
      // The queue object holds no value the range names: they have
      // been removed already, which is what a repetition of a removal
      // finds. Nothing is removed and the conflict condition says so.
      throw conflict(
        "this queue object holds no value whose designator lies within %d-%d, so the " +
        "values that range names have been removed already", first, last);
    }
    this.store.dequeue(node, from, to);
    res.writeHead(204);
    return res.end();
  }

  private async remove(req: IncomingMessage, res: ServerResponse, r: Resolver,
    ns: string, sel: Selection, who: Principal): Promise<void> {
    if (ns === "/") throw forbidden("the root container object cannot be deleted");
    // A delete takes the queue value selection of a queue object and no
    // other selection: a selection that is not valid for the operation is
    // the invalid selection condition, and this server deleted the object
    // regardless before 0.67 (weedmi OPER-031).
    if (sel.any && sel.queueValues === undefined) {
      throw invalidSelection(sel.fields[0] ?? "selection",
        "a delete takes no field selection; the object addressed is deleted whole");
    }
    const { parentNS, name, isContainer } = this.split(ns);
    const pv = await r.view(parentNS);
    if (pv.unavail) throw pv.unavail;

    if (!isContainer) {
      let found = await resolveFile(this.store, pv, name);
      if (!found) {
        try {
          await r.child(pv, name);
        } catch {
          throw notFound(ns);
        }
        res.writeHead(307, { Location: withQuery(req, this.base.slice(0, -1) + ns + "/") });
        return res.end();
      }
      // Deleting one representation does not delete another, so the
      // one the CDMI client named is the one removed. A client that
      // names none removes the representation corresponding to the
      // form of the path, which is the one found here.
      const first = nodeOf(found.ref);
      const firstIsQueue = first !== undefined && this.store.meta(first).isQueue;
      const wanted = this.kindWanted(req, firstIsQueue, () => {
        const at = nodeOf(pv.held);
        return at !== undefined && this.store.lookupKind(at, name, firstIsQueue ? "data" : "queue") !== undefined;
      });
      if (wanted !== undefined) {
        {
          const writeAt = nodeOf(pv.held);
          const other = writeAt === undefined
            ? undefined
            : this.store.lookupKind(writeAt, name, wanted);
          if (other === undefined) throw notFound(ns);
          found = {
            ref: { kind: "store", node: other },
            node: other,
            layer: found.layer,
          };
        }
      }
      const qnode = nodeOf(found.ref);
      if (qnode !== undefined && this.store.meta(qnode).isQueue &&
        sel.queueValues !== undefined) {
        // A delete carrying a queue value selection removes values;
        // the queue object itself is not deleted.
        return this.dequeue(res, qnode, ns, sel.queueValues, who);
      }
      const im = req.headers["if-match"] as string | undefined;
      if (im && im !== "*" && !matchesETag(im, etagOf(viewOf(this.store, found.ref)))) {
        throw validatorConflict();
      }
      // An object under retention or hold is not deleted, whatever
      // the lists permit.
      this.refuseRestricted(found.ref, M.DELETE, `deleting ${ns}`);
      // "Where delegated access control applies to the object to be deleted,
      // the mask the delegated access control provider returns governs its
      // deletion, and DELETE_OBJECT or DELETE_SUBCONTAINER on the container
      // object or domain object that holds it does not permit the deletion
      // where that mask does not contain DELETE" (revision 297; ECR-121B).
      // Before 0.63 the holding container's bit permitted it notwithstanding.
      if (!this.may(found.ref, who, M.DELETE, false, governedBy(pv)) &&
        (this.delegatedMaskOf(found.ref, governedBy(pv)) !== undefined ||
          !this.may(pv.held, who, M.DELETE_OBJECT, true, governedBy(pv)))) {
        throw forbidden("deleting %s requires DELETE on it%s", ns,
          this.delegatedMaskOf(found.ref, governedBy(pv)) !== undefined
            ? ", which its delegated access control provider did not return"
            : ` or DELETE_OBJECT on ${pv.ns}`);
      }
      if (pv.writeRank === undefined) {
        throw pv.writeUnavail ?? forbidden("%s cannot be deleted: %s", ns, pv.writeWhy);
      }
      if (rankCmp(found.layer.rank, pv.writeRank) !== 0) {
        throw denyChange(pv, ns, found.layer.rank, "delete");
      }
      if (found.ref.kind === "image") {
        await found.ref.fs.remove(found.ref.dir, found.ref.entry);
        await flushImage(this.store, found.ref.fs);
        res.writeHead(204);
        return res.end();
      }
      this.checkNotAnActiveSource(ns, "delete");
      // The notification is formed before the object goes, the
      // representation being what a query would report of it.
      this.event("cdmi_delete", storedNode(found.ref, ns), ns, who);
      const removing = storedNode(found.ref, ns);
      const withdrawn = this.depositsBeneath(removing);
      await this.store.collect(this.store.removeTree(removing));
      // Deleting the object removes the fields carrying its deposits.
      await this.revokeDeposits(ns, withdrawn, "the object carrying the credential reference was deleted");
      res.writeHead(204);
      return res.end();
    }

    const cv = await r.child(pv, name);
    if (!this.may(cv.held, who, M.DELETE, true) &&
      !this.may(pv.held, who, M.DELETE_SUBCONTAINER, true)) {
      throw forbidden("deleting %s requires DELETE on it or DELETE_SUBCONTAINER on %s",
        ns, pv.ns);
    }
    if (pv.writeRank === undefined) {
      throw pv.writeUnavail ?? forbidden("%s cannot be deleted: %s", ns, pv.writeWhy);
    }
    if (cv.upper) {
      throw conflictImportLayer(cv.objLayer.rank[0], pv.ns,
        "%s is present in a layer above the write target of %s, which denies the delete",
        ns, pv.ns);
    }
    if (cv.importing && rankCmp(cv.objLayer.rank, pv.writeRank) !== 0) {
      throw denyChange(pv, ns, cv.objLayer.rank, "delete");
    }
    // Only the container object of the write target, and the objects it
    // holds, are deleted; another layer of that name remains presented.
    const wt = pv.writeNode ?? pv.writeDelegate?.writeNode;
    const here = wt ? this.store.tryLookup(wt, name) : undefined;
    if (!here || !here.isContainer) {
      throw forbidden("%s is present only in layers other than the write target of %s", ns, pv.ns);
    }
    // A container object under retention or hold is not deleted, and
    // neither is one that holds an object that is.
    this.refuseRestricted(here, M.DELETE, `deleting ${ns}`);
    const held = this.restrictedWithin(here);
    if (held) {
      throw conflict("%s holds %j, which is under retention or hold", ns, held);
    }
    this.event("cdmi_delete", here, ns, who);
    const withdrawn = this.depositsBeneath(here);
    await this.store.collect(this.store.removeTree(here));
    await this.revokeDeposits(ns, withdrawn, "the object carrying the credential reference was deleted");
    res.writeHead(204);
    res.end();
  }

  // -----------------------------------------------------------------
  // Capabilities

  private sendCapability(req: IncomingMessage, res: ServerResponse, ns: string,
    sel: Selection): void {
    const tree = this.capabilities();
    const c = tree[ns];
    if (!c) {
      if (tree[ns + "/"]) {
        res.writeHead(307, { Location: withQuery(req, this.base.slice(0, -1) + ns + "/") });
        return res.end();
      }
      throw notFound(ns);
    }
    if (!acceptable(req.headers.accept as string, MT_CAPABILITY)) {
      throw notAcceptableFor(req.headers.accept as string | undefined, MT_CAPABILITY, ns);
    }
    // An extended child selection "Requires the cdmi_list_children_extended
    // capability", and a recursive one the cdmi_list_children_recursive
    // capability, neither of which a capability object publishes. Both were
    // ignored before 0.44, answering plain names to a CDMI client that asked
    // for arrays.
    if (sel.childFields.length > 0) {
      throw capabilityNotPresent("cdmi_list_children_extended", ns,
        "a capability object does not offer an extended listing of its children");
    }
    if (sel.recursive !== undefined) {
      throw capabilityNotPresent("cdmi_list_children_recursive", ns,
        "a capability object does not offer a recursive listing of its children");
    }
    // The fields of a capability object, which the served representation and
    // the discovery tree's copy build alike (Table 6.14).
    const rep = this.capabilityRepresentation(ns)!;
    this.send(res, 200, MT_CAPABILITY, applySelection(rep, sel), {}, req.method === "HEAD");
  }

  /**
   * The representation of a capability object at a namespace path, for
   * a reader that is not the ordinary request path: the discovery tree
   * serves the same hierarchy at a second address, and the fields must
   * be the ones the object has here.
   */
  capabilityRepresentation(ns: string): Record<string, unknown> | undefined {
    const c = this.capabilities()[ns];
    if (!c) return undefined;
    return {
      objectType: MT_CAPABILITY,
      objectName: c.name,
      parentURI: c.parent,
      // The Association and Metadata field groups apply to every
      // representation, a capability object included; only domainURI is
      // excluded for one (Table 6.14). A capability object's own
      // capabilities are those of the capability object type, which the
      // root capability object publishes, and it holds no metadata
      // (weedmi CAPS-004, REPR-003).
      // A namespace path, which a client resolves against the base URI, as
      // every other object's capabilitiesURI is: including the base URI here
      // made a client request it twice (weedmi CAPS-004, 0.66 regression).
      capabilitiesURI: "/cdmi_capabilities/",
      metadata: {},
      // The Completion group applies to all representations (Table 6.14),
      // and a capability object is always complete (weedmi REPR-003).
      completionStatus: "Complete",
      capabilities: c.capabilities,
      childrenrange: c.children.length ? `0-${c.children.length - 1}` : "",
      children: c.children,
    };
  }

  /**
   * The capability tree, less the capabilities of an export type whose
   * server is not configured. Before 0.2 the NFS and SMB export
   * capabilities were published whatever was configured, and the
   * server started by main.ts starts an SMB server never and an NFS
   * server only where [nfs] enables it: a client told it could place
   * an export found nothing listening. A capability that cannot be
   * exercised is not published.
   */
  private capabilities(): Record<string, {
    name: string; parent: string; capabilities: Record<string, unknown>; children: string[];
  }> {
    const tree = this.capabilityTree();
    const withheld: RegExp[] = [];
    if (this.exports?.opts.nfs === undefined) withheld.push(/^cdmi_export_(container_)?nfs(_|$)/);
    if (this.exports?.opts.smb === undefined) withheld.push(/^cdmi_export_(container_)?smb(_|$)/);
    if (withheld.length > 0) {
      for (const node of Object.values(tree)) {
        for (const name of Object.keys(node.capabilities)) {
          if (withheld.some((r) => r.test(name))) delete node.capabilities[name];
        }
      }
    }
    return this.claimProfiles(tree);
  }

  /**
   * Publishes cdmi_profiles, the conformance profiles of Annex F this
   * deployment meets. "Each value is the identifier of a profile of [Annex F]
   * that the CDMI server claims to implement ... An empty array indicates that
   * the CDMI server claims no profile."
   *
   * The claim is computed from the capability objects this server is about to
   * serve, after everything a deployment withholds has been withheld, and not
   * from a list carried in this source: a deployment with no NFS listener
   * claims no profile that requires one, and a claim cannot outrun what is
   * published. Annex F is informative and a claim binds nothing (ECR-187A),
   * so this is the only reading under which the capability says anything.
   */
  private claimProfiles(tree: Record<string, {
    name: string; parent: string; capabilities: Record<string, unknown>; children: string[];
  }>): typeof tree {
    const p = "/cdmi_capabilities/";
    const published: Published = {};
    for (const [at, node] of Object.entries(tree)) {
      const key = at === p ? "root" : at.slice(p.length).replace(/\/$/, "");
      published[key] = Object.keys(node.capabilities);
    }
    const root = tree[p];
    if (root !== undefined) root.capabilities.cdmi_profiles = profilesMet(published);
    return tree;
  }

  private capabilityTree(): Record<string, {
    name: string; parent: string; capabilities: Record<string, unknown>; children: string[];
  }> {
    // A capability whose type Annex B gives as an array of strings carries
    // that array and not "true": a name list would publish the wrong type,
    // which it did for cdmi_lock and cdmi_cors_methods before 0.79 (weedmi
    // CAPS-002, CAPS-012).
    const VALUED: Record<string, unknown> = {
      cdmi_lock: LOCK_VALUES.filter((v) => v !== "lock_none"),
      cdmi_cors_methods: ["GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"],
    };
    const yes = (...names: string[]) =>
      Object.fromEntries(names.map((n) => [n, VALUED[n] ?? "true"]));
    /**
     * The capabilities of the storage system and data system metadata
     * tables, which "are found in the capability objects for domains, data
     * objects, containers, and queues" (Annex B) and not in the root
     * capability object, where this server published them before 0.66
     * (weedmi CAPS-010).
     */
    // The data system metadata capabilities that carry a value rather than
    // "true". Annex B: "These capabilities are found in the capability
    // objects for domains, data objects, containers, and queues", so none
    // of them belongs to the root capability object, where this server
    // published all of them until 0.83 (weedmi CAPS-010). Each is placed
    // in the capability object of the objects that carry the item it
    // governs: versioning and the assigned size describe a data object,
    // the value hash describes a value, and the cross-origin items
    // describe any object a request may address.
    const versioningCaps = {
      cdmi_versioning: VERSIONING_LEVELS,
      cdmi_assignedsize: "true",
      // The greatest limit a client may ask for. The age is published under
      // the deprecated name of the previous edition as well, with the same
      // value.
      cdmi_versions_count: String(VERSIONS_MAXCOUNT),
      cdmi_versions_age: String(VERSIONS_MAXAGE),
      cdmi_version_age: String(VERSIONS_MAXAGE),
      cdmi_versions_size: String(VERSIONS_MAXSIZE),
    };
    /** The value of an object is hashed where a client asks for it. */
    const hashCaps = { cdmi_value_hash: Object.keys(VALUE_HASHES) };
    // The service-level items of Annex D, and what this server undertakes for
    // each. The three redundancy capabilities carry "a positive numeric string
    // representing the maximum value that the server supports" rather than
    // "true", so each names what one copy on one machine amounts to; the rest are
    // "true", the capability reporting that the item is interpreted and the
    // provided item reporting what came of it.
    //
    // cdmi_immediate_redundancy is published as a number because Annex B requires
    // it — "this capability shall contain a string set to a positive numeric
    // string representing the maximum value that the server supports" — although
    // the item itself is "true" or not used, so there is no number to be the
    // maximum of. It is published as "1", meaning the one copy for which
    // immediate redundancy can be provided (ECR-234A).
    const serviceCaps = {
      cdmi_data_redundancy: "1",
      cdmi_immediate_redundancy: "1",
      cdmi_infrastructure_redundancy: "1",
      cdmi_data_dispersion: "true",
      cdmi_geographic_placement: "true",
      cdmi_latency: "true",
      cdmi_throughput: "true",
      cdmi_RPO: "true",
      cdmi_RTO: "true",
    };
    /**
     * "Supported sanitization method values are provided by the
     * cdmi_sanitization_method capability ... Supported sanitization methods
     * are defined as system-specific strings." This server offers one: the
     * value file is overwritten with random octets, and the write reaches
     * the device, before the file is unlinked.
     */
    const sanitizeCaps = { cdmi_sanitization_method: SANITIZATION_METHODS };
    /**
     * The cross-origin items. cdmi_cors_methods carries the methods and not
     * "true": it was published as an array at the root, where it does not
     * belong, and as "true" in the capability objects where it does, so a
     * CDMI client reading the object it was about to address saw the wrong
     * type (weedmi CAPS-002, CAPS-010).
     */
    const corsCaps = {
      cdmi_cors_origins: "true",
      cdmi_cors_methods: ["GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"],
      cdmi_cors_headers: "true",
    };
    const metadataCaps = [
      "cdmi_hash",
      // Retention and hold, each item as well as the feature that groups
      // them: a client reads the item it means to set.
      "cdmi_data_retention", "cdmi_data_autodelete", "cdmi_data_holds",
      "cdmi_retention_id", "cdmi_retention_period",
      "cdmi_retention_autodelete", "cdmi_hold_id",
      // The items that thread the chain of versions.
      "cdmi_version_object", "cdmi_version_current", "cdmi_version_parent",
      "cdmi_version_children", "cdmi_version_oldest",
      // The items that name a delegated access control provider, which this
      // server stores and acts on. A client reads the capability of the
      // item it means to set, and these were missing though the items work.
      ...(this.dac === undefined ? [] : ["cdmi_dac_uri", "cdmi_dac_certificate"]),
      // The items of an encrypted object that name the keys: the key the
      // value is wrapped under, and the keys that sign and verify. Each is
      // a credential reference this server resolves at a key management
      // server, so they are offered only where one is configured.
      ...(this.keyManagement.length > 0
        ? ["cdmi_enc_key_id", "cdmi_enc_signature",
          "cdmi_enc_object_sign_id", "cdmi_enc_object_verify_id",
          "cdmi_enc_value_sign_id", "cdmi_enc_value_verify_id"]
        : []),
    ];
    const containerCaps = [
      "cdmi_list_children", "cdmi_list_children_range", "cdmi_list_children_extended",
      "cdmi_read_metadata", "cdmi_modify_metadata", "cdmi_create_dataobject",
      "cdmi_create_container", "cdmi_delete_container", "cdmi_import_container_cdmi",
      "cdmi_import_container_image", "cdmi_import_container_nfs",
      "cdmi_import_container_smb", "cdmi_export_container_smb",
      // A child created by a copy or a move, and a recursive listing.
      // cdmi_post_container is "the ability of the container object to add a
      // new container object with a name the CDMI server assigns"; it was
      // published by no revision of this server before 0.82, which is the
      // release that came to accept the media type.
      "cdmi_post_dataobject", "cdmi_post_container", "cdmi_create_value_range",
      // Queue objects created within this container object, and values
      // appended to one.
      // cdmi_delete_queue is a capability of a queue object, which is
      // where Annex B defines it and where this server publishes it; it
      // was published here as well until 0.83.
      "cdmi_create_queue", "cdmi_post_queue",
      // The copy, move and reference of a queue object are capabilities
      // of the container object within which the object is created,
      // beside the same capabilities of a data object.
      "cdmi_copy_queue", "cdmi_move_queue", "cdmi_reference_queue",
      // A data object created from a queue object by concatenating
      // the values it holds.
      "cdmi_copy_dataobject_from_queue",
      // A domain object is serialized into a data object of this container
      // object, which is why cdmi_serialize_domain is a capability of a
      // container object. The copy, the move and the deserialization of a
      // domain object are capabilities of a domain object, which Annex B
      // places in the domain table and this server published here until
      // 0.83; cdmi_serialize_domain_to_ID is system-wide, and is published
      // with the other _to_ID capabilities.
      "cdmi_serialize_domain",
      // A reference to a data object, which revision 121 defines a
      // capability for where earlier revisions did not.
      "cdmi_reference_dataobject",
      // The lock values this server applies. `cdmi_lock` is a data system
      // metadata capability and belongs to the capability objects of the
      // objects that carry the item — which is an object of any type: the gate
      // that refuses an operation on a locked object refuses a PUT, PATCH,
      // POST or DELETE on a container object, a data object and a queue object
      // alike, and a lock on a container object covers everything beneath it,
      // which is the case this server's own tests exercise. It was published
      // on the data object capability object alone until 0.86, so a CDMI client
      // reading the capabilities of the container object it was about to lock
      // found none.
      "cdmi_lock",
      "cdmi_serialize_queue", "cdmi_deserialize_queue",
      "cdmi_serialize_container", "cdmi_serialize_dataobject",
      "cdmi_deserialize_container", "cdmi_deserialize_dataobject",
      "cdmi_modify_deserialize_container",
      "cdmi_copy_container", "cdmi_copy_dataobject", "cdmi_move_container",
      "cdmi_move_dataobject", "cdmi_list_children_recursive",
      // Snapshots of this container object. The deprecated name of
      // the previous edition is published beside the current one, as
      // the draft requires.
      "cdmi_snapshots", "cdmi_create_snapshot", "cdmi_snapshot", "cdmi_import_container_nfs",
      // The cross-origin items are published with their values by corsCaps.
      // The storage system metadata this server generates for an
      // object, and the access control lists it stores and enforces.
      ...STORAGE_SYSTEM_METADATA, ...metadataCaps,
    ];
    const dataCaps = [
      "cdmi_read_value", "cdmi_read_value_range", "cdmi_read_metadata", "cdmi_modify_value",
      "cdmi_modify_value_range", "cdmi_modify_metadata", "cdmi_delete_dataobject",
      "cdmi_modify_deserialize_dataobject",
      // "This server records where the gaps in a value are, so the valuerange
      // field reports the range up to the first gap."
      "cdmi_value_sparse",
      // The lock values this server applies. A data system metadata
      // capability belongs to the capability objects of the objects that
      // carry the item, and not to the root (weedmi CAPS-010).
      "cdmi_lock",
      // The representations this server holds of the value of a data
      // object, which is one: a member named by its media type. The item
      // describes a value, so it is a capability of the objects that have
      // one (revision 327). Withheld while VALUE_REPRESENTATIONS is off, so
      // that a CDMI client does not read a capability for an item this server
      // is not reporting.
      // The representations of the value of a data object, and the item by which a
      // CDMI client states which of them it prefers. Both belong to the capability
      // object of the objects that have a value, and not to the root.
      ...(VALUE_REPRESENTATIONS ? ["cdmi_representations", "cdmi_representation_default"] : []),
      // The data system metadata items that configure cross-origin requests,
      // which an object carries, are published with their values by corsCaps.
      ...STORAGE_SYSTEM_METADATA, ...metadataCaps,
    ];
    const p = "/cdmi_capabilities/";
    const tree: Record<string, {
      name: string; parent: string; capabilities: Record<string, unknown>; children: string[];
    }> = {
      [p]: {
        name: "cdmi_capabilities/", parent: "/",
        capabilities: {
          ...yes("cdmi_dataobjects",
            // Imports.
            "cdmi_imports", "cdmi_imports_provided", "cdmi_imports_copy_up",
            "cdmi_import_cdmi", "cdmi_import_cdmi_local", "cdmi_import_cdmi_remote",
            "cdmi_import_image", "cdmi_import_image_partitions",
            // NFS imports over NFSv4.1, with the AUTH_SYS flavour.
            // cdmi_import_nfs_authsys is not a capability Annex B defines,
            // and a name beginning with cdmi_ that the document does not
            // define is this document's to give (weedmi CAPS-015).
            "cdmi_import_nfs", "cdmi_import_nfs_xattr",
            // cdmi_import_s3 is not offered: the entry of an S3 import is
            // parsed, and no layer presents the objects of a bucket, so a
            // capability saying this server imports from S3 would promise
            // what it cannot do.
            // "A CDMI import ... preserves the object ID of the object it
            // presents where the preserve_objectid field permits", which
            // this server does (imports.ts, preservesObjectID).
            "cdmi_import_cdmi_objectid",
            // SMB: an export entry establishes a share on the SMB
            // server and is reported active; an import presents a
            // remote share as a layer.
            "cdmi_export_smb", "cdmi_import_smb",
            // The authentication methods this server offers, of an export
            // and of an import. An export admits a client that presents a
            // Kerberos ticket of a realm this server belongs to, and one
            // that answers an NTLMv2 challenge with a password this server
            // holds, which is the workgroup and standalone case. It does not
            // pass an NTLM authentication through to a domain controller
            // over the secure channel of a machine account ([MS-NRPC]), so
            // an entry naming domain_servers is refused; an import by
            // Kerberos is not offered, so cdmi_import_smb_krb5 is absent.
            // cdmi_export_smb_anonymous is withdrawn in 0.83: Annex B defines
            // no such capability, and a name beginning with "cdmi_" that this
            // document does not define is the document's to give. An SMB
            // export that authenticates nobody is reported by the value
            // "none" of cdmi_export_smb_auth_methods below, which is where
            // Annex B puts it. cdmi_import_nfs_authsys was withdrawn on the
            // same ground in 0.79.
            "cdmi_export_smb_krb5", "cdmi_export_smb_ntlmv2",
            // The user metadata of an object is presented as extended
            // attributes of the file an SMB export presents.
            "cdmi_export_smb_ea", "cdmi_import_smb_ea",
            // MQTT: the entry of an export is validated and reported,
            // and no connection to a broker is made yet.
            "cdmi_export_mqtt",
            // Query queues, with the matching expressions whose
            // support a capability of its own reports.
            "cdmi_query", "cdmi_query_contains", "cdmi_query_tags",
            "cdmi_query_regex",
            // "That capability governs both the matching of a value by a scope
            // specification and the reporting of a value by a results
            // specification": both from 0.119, the value carried as base 64 in
            // the representation a query forms (queryRepresentation).
            "cdmi_query_value",
            // Notification queues.
            "cdmi_notification",
            // S3 exports: the entry is validated and reported, and
            // no bucket is served yet, so only the placement
            // capability is offered.
            "cdmi_export_s3",
            // A bucket is reached by virtual hosted addressing as
            // well as by path style, and anonymous_read is served.
            "cdmi_export_s3_virtual_hosted", "cdmi_export_s3_anonymous_read",
            // A part supplied from the value of an existing object.
            "cdmi_export_s3_multipart_copy",
            "cdmi_import_mqtt",
            // An HTTP import presents what an origin server returns for one
            // URI as the value of a data object, read only (revision 327).
            "cdmi_import_http",
            // No S3 import: seedmi has no S3 client, so an entry is
            // refused and cdmi_import_s3 is not published.
            // A connection to a broker is made over TLS. A credential
            // held by a key management server is not retrieved, so
            // the KMIP capabilities stay absent.
            "cdmi_export_mqtt_tls", "cdmi_import_mqtt_tls",
            "cdmi_import_smb_ntlmv2",
            // The versions of each protocol are reported by the
            // cdmi_export_<type>_versions and cdmi_import_<type>_versions
            // capabilities below, which revision 245 put in place of one
            // capability for each version. The extended attribute operations
            // belong to the second minor version of NFS, which this server
            // both speaks and serves.
            "cdmi_export_nfs_xattr",
            // Exports. The NFS type is validated and reported, not served.
            "cdmi_exports_provided", "cdmi_export_http", "cdmi_export_http_write",
            // A CDMI export presents a container object at a base URI of
            // its own, served by this protocol binding (revision 327).
            "cdmi_export_cdmi",
            "cdmi_export_http_anonymous_read",
            // The description of the requesting principal within a domain,
            // carried as a metadata item of the domain object since 0.106
            // (ECR-226A; revision 282 made it a reserved child; userinfo.ts).
            "cdmi_domain_userinfo",
            // The directory of a domain, whose references are resolved at a key
            // management server, so it is supported where one is configured.
            ...(this.keyManagement.length > 0 ? ["cdmi_domain_auth"] : []),
            // The discovery bootstrap a domain carries (ECR-224A), published
            // only where a deployment offers the item. System-wide rather than
            // on the domain capability object, following cdmi_domain_auth and
            // cdmi_domain_userinfo: Annex B puts the capability of a domain
            // metadata item in the system-wide table, the item being one the
            // server either interprets or does not.
            ...(DOH_ITEM ? ["cdmi_domain_doh"] : []),
            // A form-based file upload through a writable HTTP export, which
            // revision 269 governs by a capability of its own rather than by
            // cdmi_multipart_mime (ECR-115B).
            "cdmi_export_http_form_upload",
            "cdmi_export_nfs",
            // Access control lists, as clause 17 defines them.
            "cdmi_security_access_control",
            // An object that has an object ID is addressable by it.
            "cdmi_object_access_by_ID",
            // A POST to the object ID tree creates a queue object, a
            // copy of one, or an object from a canonical format, and
            // serializes an object into one.
            // The capabilities of the storage system and data system
            // metadata tables "are found in the capability objects for
            // domains, data objects, containers, and queues" (Annex B), and
            // not in the root capability object, which published cdmi_hash
            // and the retention and version items before 0.66
            // (weedmi CAPS-010).
            // An object of another CDMI server is copied here, and
            // moved here by copying it and deleting it there.
            "cdmi_object_copy_from_remote", "cdmi_object_move_from_remote",
            "cdmi_post_queue_by_ID", "cdmi_copy_queue_by_ID",
            "cdmi_deserialize_dataobject_by_ID", "cdmi_deserialize_queue_by_ID",
            "cdmi_serialize_queue_to_ID", "cdmi_serialize_dataobject_to_ID",
            "cdmi_serialize_container_to_ID",
            // A domain object serialized into a data object of the object ID
            // tree. Annex B places this in the system-wide table with the
            // other _to_ID capabilities; this server published it on the
            // container capability object alone until 0.83, so a CDMI client
            // reading the root capability object saw the other three and not
            // this one.
            "cdmi_serialize_domain_to_ID",
            // "the CDMI server supports the extended child listing ...
            // Whether it is supported for a given container object is
            // reported by the capability of the same name published by the
            // capability object of that container object." Annex B defines
            // each of these twice, once system-wide and once for a container
            // object, and the two say different things; this server
            // published the container one alone until 0.83.
            "cdmi_list_children_extended", "cdmi_list_children_recursive",
            // Copying and moving within this CDMI server.
            "cdmi_object_copy_from_local", "cdmi_object_move_from_local",
            // The object ID tree: creating, copying and moving through it.
            "cdmi_post_dataobject_by_ID", "cdmi_copy_dataobject_by_ID",
            // Annex B defines this in the system-wide table as well
            // as the container object table.
            "cdmi_copy_dataobject_from_queue",
            "cdmi_create_value_range_by_ID", "cdmi_object_move_from_ID",
            "cdmi_object_move_to_ID",
            // Snapshots, which share the value of every object copied.
            "cdmi_snapshots", "cdmi_domains", "cdmi_serialization_json",
            "cdmi_security_immutability",
            // "the CDMI server supports data/media sanitization": the value
            // file of an object that asked for a method is overwritten
            // before it is unlinked (store.sanitize). What that achieves
            // depends on the filesystem beneath, which
            // NOTES-on-sanitization.md sets out.
            "cdmi_security_sanitization",
            // The lock values this server applies, which the cdmi_lock
            // capability holds (revision 327, the locking subclause).

            // Retention, hold and the chain of versions are capabilities of
            // the storage system and data system metadata tables, which
            // "are found in the capability objects for domains, data
            // objects, containers, and queues" and are published there
            // rather than here (weedmi CAPS-010).
            // User metadata carried in header fields of an export.
            "cdmi_header_metadata",
            // Cross-origin requests. The three items that configure them
            // are data system metadata capabilities, which Annex B places
            // in the capability objects of the objects that carry them
            // (weedmi CAPS-010).
            // Cross-origin requests. cdmi_cors is system-wide and stays
            // here; the three items that configure them are data system
            // metadata capabilities, which Annex B places in the capability
            // objects of the objects that carry them (weedmi CAPS-010).
            "cdmi_cors",
            // The rel field is validated and stored.
            "cdmi_graph_rels",
            // References: a name that redirects to a URI.
            "cdmi_references"),
          // The limits on the user metadata of an object.
          cdmi_metadata_maxitems: String(METADATA_MAXITEMS),
          // The limits of a multipart upload this CDMI server
          // assembles, each of which carries a value rather than
          // reporting that the feature is present.
          cdmi_export_s3_multipart_maxparts: String(MAX_PARTS),
          cdmi_export_s3_multipart_maxpartsize: String(MAX_PART_SIZE),
          cdmi_export_s3_multipart_minpartsize: String(MIN_PART_SIZE),
          cdmi_export_s3_multipart_default_expiry: DEFAULT_EXPIRY,
          // The greatest aggregate size of the metadata an S3
          // export presents for an object.
          cdmi_export_s3_metadata_maxtotalsize: String(S3_METADATA_MAXTOTALSIZE),
          // The checksum algorithms this server verifies, which
          // include the two the AWS libraries default to.
          cdmi_export_s3_checksums: CHECKSUMS,
          cdmi_metadata_maxsize: String(METADATA_MAXSIZE),
          cdmi_metadata_maxtotalsize: String(METADATA_MAXTOTALSIZE),
          // What an NFS export is able to carry of those limits: an
          // extended attribute name carries the "user." prefix, so the
          // longest item name the export presents is shorter than the
          // longest this server holds.
          cdmi_export_nfs_xattr_maxname: String(METADATA_MAXNAME),
          cdmi_export_nfs_xattr_maxsize: String(METADATA_MAXSIZE),
          // These limits report what this CDMI server holds, and an
          // exported protocol may carry less; what each export type
          // carries is reported by the capabilities of that type.
          // cdmi_value_sparse is a data object capability (Annex B), and is
          // published in the data object's capability object rather than
          // here, where a client looking for it did not find it
          // (weedmi OPER-026).
          // "the CDMI server resolves a credential reference against a key
          // management server" and "holds credentials at a key management
          // server external to it, reached using KMIP": published where one is
          // configured, now that a field (an MQTT export's password_secret_id)
          // carries a reference this server resolves.
          ...kmsCapabilities(this.keyManagement),
          // The encrypted objects subclause. Storing and reading an
          // encrypted object requires no capability; these report the
          // operations in which this server acts on the ciphertext itself,
          // which need a key management server to hold the key encryption
          // key. CMS is not implemented, so cdmi_enc_cms is absent.
          ...(this.keyManagement.length > 0
            // cdmi_encryption is not among these: it reports the
            // algorithm/mode/length values this server offers for
            // encryption *at rest*, which it does not perform. The
            // encrypted objects subclause is reported by the items below
            // (weedmi CAPS, 0.70).
            ? {
              cdmi_enc_jwe: "true", cdmi_enc_inplace: "true",
              // The plaintext is reachable through an HTTP export whose
              // entry names an authentication scheme, the key being
              // obtained under the identity of the request.
              cdmi_enc_access: "true",
              // A value that carries a signature is verified when it is
              // decrypted, and the digest algorithms of a signature payload
              // are those this server computes. cdmi_enc_signature is not
              // among these: Annex B defines it in the storage system
              // metadata capabilities table, which is found in the
              // capability objects of the objects that carry the item, and
              // metadataCaps publishes it there. It was published here too,
              // and the check that found the other eight did not see it
              // because the harness it runs in configures no key management
              // server and the whole of this block is then absent (weedmi
              // CAPS-010, the last of the nine).
              cdmi_enc_digest: DIGEST_ALGORITHMS,
              // The signature algorithms this server produces and accepts
              // for an object signature.
              cdmi_jws_alg: JWS_ALGORITHMS,
              // "Which JOSE alg key management algorithms are enabled, for
              // every use this document makes of JSON Web Encryption", and
              // the enc content encryption algorithms likewise. This server
              // wraps a content key with AES Key Wrap and encrypts the
              // value with AES-GCM; the two were not published though both
              // are used.
              cdmi_jwe_alg: JWE_ALG,
              cdmi_jwe_enc: JWE_ENC,
            }
            : {}),
          // "The versions of the NFS protocol the NFS server offers for an
          // export, each spelled as the protocol field of an export entry of
          // that type spells it" (revision 245, which put one capability
          // holding an array of versions in place of one capability for each
          // version). An empty array says the type is supported and no
          // version of that protocol is; this server publishes a capability
          // only for a type it offers, so none here is empty.
          cdmi_export_nfs_versions: ["NFSv4.1", "NFSv4.2"],
          cdmi_import_nfs_versions: ["NFSv4.1", "NFSv4.2"],
          // "The authentication methods a CDMI server accepts for the NFS
          // import": this server speaks NFSv4.1 over TCP with AUTH_SYS,
          // which is the one flavour it offers (nfs-import.ts).
          cdmi_import_nfs_auth_methods: ["AUTH_SYS"],
          cdmi_export_smb_versions: ["SMB2", "SMB2.1", "SMB3", "SMB3.0.2", "SMB3.1.1"],
          cdmi_import_smb_versions: ["SMB2", "SMB2.1", "SMB3", "SMB3.0.2", "SMB3.1.1"],
          cdmi_export_mqtt_versions: ["3.1.1", "5.0"],
          cdmi_import_mqtt_versions: ["3.1.1", "5.0"],
          cdmi_import_http_versions: HTTP_IMPORT_VERSIONS,
          // The lists entries are checked against (protocol-versions.ts).
          cdmi_export_http_versions: HTTP_EXPORT_VERSIONS,
          cdmi_export_s3_versions: S3_EXPORT_VERSIONS,
          // "The authentication methods a CDMI server accepts for the S3
          // export": this server verifies a signature of the version 4
          // signing process, and serves an anonymous request where the
          // entry permits one (s3-sigv4.ts).
          cdmi_export_s3_auth_methods: ["AWS4-HMAC-SHA256", "anonymous"],
          // "The authentication methods a CDMI server accepts for the SMB
          // export, each a value the auth_method field of such an entry may
          // take, being none, ntlmv2 and kerberos": this server serves all
          // three, and published none of them under this name until 0.83.
          cdmi_export_smb_auth_methods: ["none", "ntlmv2", "kerberos"],
          // "... for the NFS export ... being sys, krb5, krb5i and krb5p":
          // this server's NFS server speaks AUTH_SYS alone, which is why
          // cdmi_export_nfs_krb5 is absent.
          cdmi_export_nfs_auth_methods: ["sys"],
          // Versioning of the objects of a bucket, which an entry turns on
          // with its versioning field and this server keeps versions for.
          cdmi_export_s3_versioning: "true",
          cdmi_import_cdmi_versions: CDMI_IMPORT_VERSIONS,
          // The limits an SMB export is able to carry: the name length
          // of the structure is one octet and the value length is two.
          cdmi_export_smb_ea_maxname: String(EA_MAXNAME),
          cdmi_export_smb_ea_maxsize: String(EA_MAXSIZE),
          cdmi_security_data_integrity: "true",
          // Queue objects, and the limits this server places on one.
          cdmi_queues: "true",
          // The values a queue object holds may be transported outside
          // the representation, as parts of a multipart/mixed body.
          cdmi_multipart_mime: "true",
          // Delegated access control, where this server is configured with an
          // identity and a provider may be reached. The schemes are those a
          // request is submitted to.
          // cdmi_dac_response_window: "The number of seconds, as a decimal integer,
          // for which the CDMI server accepts a delegated access control response
          // for a request it has submitted ... Present where cdmi_dac is present."
          ...(this.dac === undefined ? {} : { cdmi_dac: "true", cdmi_dac_methods: this.dac.methods,
            cdmi_dac_response_window: String(Math.floor(this.dac.responseWindowMs / 1000)) }),
          // An object is created or updated by a series of requests
          // carrying X-CDMI-Partial. Revision 196 defines this
          // capability, and without it the header field is refused
          // with the capability not present condition, so a server
          // that honours the header field publishes it.
          cdmi_partial_upload: "true",
          cdmi_queue_maxvalues: String(QUEUE_MAXVALUES),
          cdmi_queue_maxsize: String(QUEUE_MAXSIZE),
          cdmi_queue_maxtotalsize: String(QUEUE_MAXTOTALSIZE),
          // A value transported as a JSON object.
          cdmi_valuetransferencoding_json: "true",
          cdmi_import_filesystems: FILESYSTEMS,
          // A remote import may delegate only where this server is able
          // to obtain a token for the requesting principal.
          ...(delegationConfigured() ? yes("cdmi_import_cdmi_delegation") : {}),
          // "The CDMI server supports the protocol binding defined in this
          // subclause, and specifies the address of the endpoint": named
          // only where that endpoint is served.
          ...(this.mcpUri === undefined ? {} : { cdmi_mcp_uri: this.mcpUri }),
          // The origins at which this server is able to serve an HTTP export
          // and a CDMI export. An entry naming an origin these do not contain
          // is one this server cannot at present serve, so it is accepted and
          // reported not active, and a CDMI client that reads these first
          // writes an entry that works.
          //
          // A feature of an export type, at the root and named for the type:
          // "a feature of an export type that a CDMI server may support
          // independently of the type itself is indicated by a capability named
          // cdmi_export_<type>_<feature>, published by the capability object at
          // the root of the capability hierarchy", which every other feature
          // capability of every export type follows. Annex B instead names this
          // one cdmi_export_container_http_origins and the HTTP exports
          // subclause publishes it from the container object — the only
          // capability in the export scheme to do either. ECR-223A asks for the
          // name and the place the rule gives it, and for the CDMI export,
          // whose origins the same listeners serve, to have one of its own.
          // This server published the Annex B name at the root until 0.98, from
          // the container object in 0.99 and 0.100, and these from 0.101.
          cdmi_export_http_origins: this.exports?.opts.originCaps ?? [],
          cdmi_export_cdmi_origins: this.exports?.opts.originCaps ?? [],
          // "The authentication methods a CDMI server accepts for the HTTP
          // export, each a value the auth_method field of such an entry may
          // take": the same set the entry is checked against, so the two
          // cannot disagree.
          cdmi_export_http_auth_methods: EXPORT_AUTH_METHODS,
          // "If present and true, the CDMI server presents the certificates
          // an HTTP export entry references for its https origins", which
          // this server does through the certificates field of an entry.
          cdmi_export_http_certificates: "true",
          // The versions of this document served through a CDMI export.
          // Annex B gives this capability an array of strings, and it was
          // published as "true" by a name list before 0.79 (weedmi CAPS).
          cdmi_export_cdmi_versions: CDMI_EXPORT_VERSIONS,
          // The means by which this server authenticates a principal.
          cdmi_authentication_methods: this.directory.methods(),
          // The limits this server applies to metadata carried in
          // header fields.
          cdmi_header_metadata_maxitems: String(HEADER_METADATA_MAXITEMS),
          cdmi_header_metadata_maxsize: String(HEADER_METADATA_MAXSIZE),
          cdmi_header_metadata_maxtotalsize: String(HEADER_METADATA_MAXTOTALSIZE),
        },
        children: ["capability/", "container/", "dataobject/", "domain/", "queue/",
          "imported_container/", "imported_dataobject/"],
      },
      [`${p}capability/`]: {
        name: "capability/", parent: p,
        capabilities: yes("cdmi_list_children", "cdmi_list_children_range"), children: [],
      },
      [`${p}container/`]: {
        name: "container/", parent: p,
        capabilities: {
          ...yes(...containerCaps, "cdmi_export_container_http",
            "cdmi_export_container_nfs", "cdmi_export_container_smb",
            "cdmi_export_container_s3",
            // "Support for an export type is indicated by two capabilities,
            // both of which shall be present before a CDMI client configures an
            // export of that type": cdmi_export_<type> at the root, and this
            // one, "published by the capability object addressed by the
            // capabilitiesURI field of the object on which the export entry is
            // to be placed". Annex B defines no such capability for the CDMI
            // export type, so a CDMI client obeying that rule could configure no
            // CDMI export at all; ECR-223A asks for it, and this server
            // publishes it from 0.101.
            "cdmi_export_container_cdmi",
            "cdmi_create_reference",
            "cdmi_delete_reference"),
          ...ACL_CAPABILITIES,
          // A container object carries the cross-origin items, and the
          // value hash, which is data system metadata and so is inherited by
          // the objects the container holds: a CDMI client sets it once on a
          // container rather than on every object beneath it. A container
          // object holds no value of its own and is not version enabled.
          ...corsCaps, ...hashCaps, ...sanitizeCaps, ...serviceCaps,
        },
        children: [],
      },
      [`${p}dataobject/`]: {
        name: "dataobject/", parent: p,
        capabilities: {
          ...yes(...dataCaps), ...ACL_CAPABILITIES,
          ...corsCaps, ...hashCaps, ...versioningCaps, ...sanitizeCaps,
          ...serviceCaps,
        },
        children: [],
      },
      [`${p}queue/`]: {
        name: "queue/", parent: p,
        capabilities: {
          ...yes("cdmi_read_value", "cdmi_read_metadata", "cdmi_modify_metadata",
            "cdmi_modify_value", "cdmi_delete_queue",
            "cdmi_modify_deserialize_queue",
            // An MQTT import entry may be placed on this queue object.
            "cdmi_import_queue_mqtt",
            // An MQTT export entry may be placed on this queue object.
            // The name is the one annex B defines for the per-object
            // capability; the clause prose names the system-wide
            // capability in its place. See P1 in NOTES-on-mqtt.md.
            "cdmi_export_queue_mqtt",
            // A queue object carries cdmi_lock as any other object does, and
            // an operation upon a locked queue object is refused by the same
            // gate.
            "cdmi_lock",
            // Retention and hold "apply to a data object, a container object,
            // and a queue object", and this server enforces them on one: an
            // enqueue to a queue object under hold is refused, and so is a
            // removal of the values it holds. The capabilities were published on
            // the data object and container capability objects alone until
            // 0.109, so a CDMI client reading this one was told that retention
            // was unsupported for a queue object while the server enforced it.
            "cdmi_data_retention", "cdmi_data_autodelete", "cdmi_data_holds",
            "cdmi_retention_id", "cdmi_retention_period",
            "cdmi_retention_autodelete", "cdmi_hold_id"),
          ...ACL_CAPABILITIES,
          ...STORAGE_SYSTEM_METADATA.reduce<Record<string, string>>((o, c) => {
            o[c] = "true";
            return o;
          }, {}),
          // A queue object holds values, each of which may be hashed; it is
          // not version enabled.
          ...corsCaps, ...hashCaps, ...sanitizeCaps, ...serviceCaps,
        },
        children: [],
      },
      [`${p}domain/`]: {
        name: "domain/", parent: p,
        capabilities: {
          ...yes("cdmi_create_domain", "cdmi_delete_domain",
          "cdmi_list_children", "cdmi_read_metadata", "cdmi_modify_metadata",
          // A domain object is copied, moved and deserialized, which Annex B
          // makes capabilities of a domain object. This server published
          // them on the container capability object until 0.83, where a
          // CDMI client reading the capability object of the domain it was
          // about to copy found none of them.
          "cdmi_copy_domain", "cdmi_move_domain",
          "cdmi_deserialize_domain", "cdmi_modify_deserialize_domain"),
          // "Contains the authentication methods the CDMI server accepts":
          // Annex B defines it for a domain object as well as system-wide,
          // a domain resolving the credentials of its own principals.
          cdmi_authentication_methods: this.directory.methods(),
          // A domain object carries the cross-origin items as any other
          // object does; it holds no value and is not version enabled.
          ...corsCaps, ...sanitizeCaps,
        },
        children: [],
      },
      // An object presented through an import reports a list: the one the
      // source reports where the import is delegated, and the one of the
      // importing object where it is not, as the imports model requires. Until
      // 0.106 these two withheld cdmi_acl, cdmi_owner, cdmi_group, cdmi_acount
      // and cdmi_mcount on the ground that "an object presented through an
      // import has no access control list and no owner of its own", which was
      // a statement about what governs it rather than about what is reported
      // for it — and was in any case not what this server did, cdmi_owner
      // having been reported all along. The counts stay withheld: neither a
      // file system nor another server's representation is obliged to carry
      // them, and this server counts nothing for an object it does not hold.
      [`${p}imported_container/`]: {
        name: "imported_container/", parent: p,
        capabilities: yes(...containerCaps.filter((c) => !UNCOUNTED.includes(c))),
        children: [],
      },
      [`${p}imported_dataobject/`]: {
        name: "imported_dataobject/", parent: p,
        capabilities: yes(...dataCaps.filter((c) => !UNCOUNTED.includes(c))),
        children: [],
      },
    };

    // The capability objects of an object within a snapshot, which are the
    // capability objects of an ordinary object without the operations a
    // snapshot refuses. A snapshot is frozen: the protocol binding answers
    // anything other than a read of an object within one, or a delete of the
    // snapshot itself, with the forbidden condition.
    //
    // Until 0.126 a snapshot and every object within one reported the
    // capabilitiesURI of an ordinary object, which publishes
    // cdmi_create_dataobject, cdmi_create_container, cdmi_modify_metadata,
    // cdmi_delete_container, cdmi_create_snapshot and the rest. So this server
    // told a CDMI client that it could create, modify, delete and snapshot
    // within a snapshot, and refused every one of them with 403 -- the same
    // fault as advertising cdmi_list_children_extended for a snapshot and then
    // ignoring it, which 0.124 fixed by implementing the listing. Here the
    // advertisement is what is wrong, the refusals being right.
    //
    // It also settles the snapshots field: a snapshot holds no snapshots of its
    // own, "a snapshot shall not include the cdmi_snapshots container object of
    // the container object it is a snapshot of", and that field is reported
    // "where the cdmi_snapshots capability is available for that container
    // object". The capability is not published here, so the field is rightly
    // absent rather than absent while the capability claims it.
    /** Every capability naming an operation a frozen object does not serve. */
    const frozenOut = (name: string): boolean =>
      /^cdmi_(create|modify|delete|post|copy|move|reference|deserialize)/.test(name) ||
      /^cdmi_(import|export)_/.test(name) ||
      /^cdmi_serialize/.test(name) ||
      name === "cdmi_snapshots" || name === "cdmi_snapshot" ||
      name === "cdmi_versioning" || name === "cdmi_dequeue" ||
      // The lock values this server applies: a lock is applied by an update,
      // and an object within a snapshot takes none. "A lock is not applied to
      // an object created by copying an object that is under one, and is not
      // preserved in a snapshot."
      name === "cdmi_lock" || name === "cdmi_lock_provided";
    const frozen = (from: string, also: Record<string, unknown> = {}):
      Record<string, unknown> => ({
      ...Object.fromEntries(Object.entries(tree[from]!.capabilities)
        .filter(([k]) => !frozenOut(k))),
      ...also,
    });
    for (const [name, from, also] of [
      // A snapshot itself, which a CDMI client may delete: "the snapshot itself
      // is deleted, although it is frozen: this is the one operation the rule
      // admits", as the snapshots clause provides.
      ["snapshot/", `${p}container/`, { cdmi_delete_container: "true" }],
      // The reserved container object that holds the snapshots, and any
      // container object within a snapshot: neither is created or deleted by a
      // CDMI client.
      ["snapshot_container/", `${p}container/`, {}],
      ["snapshot_dataobject/", `${p}dataobject/`, {}],
      ["snapshot_queue/", `${p}queue/`, {}],
    ] as [string, string, Record<string, unknown>][]) {
      tree[`${p}${name}`] = {
        name, parent: p, capabilities: frozen(from, also), children: [],
      };
      tree[p]!.children.push(name);
    }
    return tree;
  }

  /**
   * Serves "cdmi_domain_userinfo" (revision 282): a data object whose value
   * describes the requesting principal as this domain resolves it. "It shall
   * not be created, updated or deleted by a CDMI client"; "Access control lists
   * do not govern it: every principal may read the description of itself"; and
   * the response is not cached for another principal.
   */
  /**
   * The value of the cdmi_domain_userinfo metadata item of a domain object:
   * the requesting principal as that domain resolves it (ECR-226A).
   *
   * Until 0.106 this was a reserved child data object of the domain object, as
   * revision 365 defines it. It is an item of the domain object instead, which
   * is what a description of the principal within that domain is: a client
   * reads the domain and learns who it is there, in one request, and the
   * description is governed by the permission that governs the rest of the
   * domain object rather than by a rule of its own. The reserved child was also
   * the only object of this server with no object ID, no parent identifier and
   * no domain of its own, because it was not an object at all.
   */
  private async userinfoItem(req: IncomingMessage, who: Principal, domain: Node): Promise<unknown> {
    const scheme = String(req.headers.authorization ?? "").split(" ")[0].toLowerCase();
    const controller = this.domainControllers?.for(this.store.pathOf(domain))
      ?? await this.controllerOfDomain(domain);
    // The home the directory of the domain holds for this principal, divided
    // against the base URI the descriptor names (revision 302; ECR-145B).
    const dc = controller?.config;
    const held = who.attributes ?? {};
    const attribute = dc?.userinfoAttributes?.home;
    const fromDirectory = attribute !== undefined
      ? held[attribute.toLowerCase()]
      : held.unixhomedirectory ?? held.homedirectory;
    const home = homeOf(fromDirectory, dc?.homeBase, {
      // "It takes an SMB export entry of this CDMI server whose sharename is
      // that share and whose server_addresses contain that host."
      shareAt: (share, host) => this.exports?.all().find((p) => {
        const e = p.entry as { type?: string; sharename?: string; server_addresses?: string[] };
        return e.type === "SMB" && (e.sharename ?? "").toLowerCase() === share.toLowerCase() &&
          (e.server_addresses ?? []).some((a) => a.toLowerCase() === host.toLowerCase());
      })?.ns,
    });
    return userinfoOf(who, this.store.pathOf(domain), {
      ...(home === undefined ? {} : { home }),
      ...(this.homes === undefined ? {} : { homes: this.homes }),
      ...(controller === undefined ? {} : { realm: controller.config.realm }),
      ...(scheme === "" ? {} : { authMethod: scheme }),
    });
  }

  /**
   * Makes the home of a principal where this server holds homes and the request
   * is that principal's first for its own home ([home_server]), as a UNIX host
   * makes a home at first login. A home is owned by its principal, and its list
   * admits that principal alone, inherited by what it holds.
   */
  private provisionHome(ns: string, who: Principal, controller?: DomainController): void {
    const server = this.homeServer;
    if (server === undefined || !server.provision || who.name === "ANONYMOUS@") return;
    // The home of this principal as the directory of its domain names it,
    // where it names one (revision 302), and otherwise the principal's own
    // name beneath the container this server holds homes in.
    const dc = controller?.config;
    const attribute = dc?.userinfoAttributes?.home;
    const fromDirectory = dc === undefined
      ? undefined
      : homeOf(attribute !== undefined
        ? (who.attributes ?? {})[attribute.toLowerCase()]
        : (who.attributes ?? {}).unixhomedirectory ?? (who.attributes ?? {}).homedirectory,
      dc.homeBase);
    const path = fromDirectory?.home_path;
    let parentPath: string, name: string;
    if (path !== undefined) {
      // The request must be for that home, or for something within it.
      if (!(ns === path || ns.startsWith(path) || `${ns}/` === path)) return;
      const trimmed = path.replace(/\/$/, "");
      const cut = trimmed.lastIndexOf("/");
      parentPath = trimmed.slice(0, cut + 1);
      name = decodeURIComponent(trimmed.slice(cut + 1));
      if (name === "") return;
    } else {
      const owner = homeOwnerOf(server, ns);
      if (owner === undefined || decodeURIComponent(owner) !== who.name) return;
      parentPath = server.container;
      name = homeNameOf(who.name);
    }
    // The container the home is made in, where it is there.
    let within: Node | undefined = this.store.root();
    for (const seg of parentPath.split("/")) {
      if (seg === "" || within === undefined) continue;
      within = within.isContainer ? this.store.tryLookup(within, seg) : undefined;
    }
    if (within === undefined || !within.isContainer) return;
    if (this.store.tryLookup(within, name) !== undefined) return;
    // Owned by its principal, in the domain the homes belong to, and admitting
    // that principal alone, inherited by what the home holds.
    let domainNode: Node | undefined = this.store.root();
    for (const seg of server.domain.split("/")) {
      if (seg === "" || domainNode === undefined) continue;
      domainNode = domainNode.isContainer ? this.store.tryLookup(domainNode, seg) : undefined;
    }
    this.store.createContainer(within, name, {
      owner: who.name,
      acl: [{ acetype: "ALLOW", identifier: "OWNER@", aceflags: "OBJECT_INHERIT, CONTAINER_INHERIT", acemask: "ALL_PERMS" }],
      ...(domainNode === undefined ? {} : { domain: domainNode.id }),
    });
  }

  /**
   * Binds the credential references of the cdmi_domain_auth item to the key
   * management server the domain names, as an export's password_secret_id is
   * bound: a reference is resolved and recorded here, so that the value is
   * fetched later without the client's word for where it lives.
   */
  private async bindDomainAuth(node: Node, who: Principal): Promise<void> {
    const m = this.store.meta(node);
    const item = (m.metadata as Record<string, unknown>).cdmi_domain_auth;
    if (item === null || item === undefined || typeof item !== "object" || Array.isArray(item)) return;
    const d = { ...(item as Record<string, unknown>) };
    const configurer = { name: who.name, privileges: who.privileges ?? [] };
    const ctx = this.credentialContext();
    let changed = false;
    for (const [field, requirement, defaultType] of [
      ["service_key_id", SERVICE_KEY, "Secret Data"], ["ca_cert_id", CERTIFICATE, "Certificate"]] as const) {
      const supplied = d[field];
      if (supplied === undefined || boundReference(supplied) !== undefined) continue;
      d[field] = await bindReference(ctx, `metadata/cdmi_domain_auth/${field}`, supplied, node, configurer,
        requirement, defaultType);
      changed = true;
    }
    if (!changed) return;
    this.store.setMeta(node, { ...m, metadata: { ...(m.metadata as Record<string, unknown>), cdmi_domain_auth: d } } as never);
  }

  /**
   * The controller of a domain that names its directory in cdmi_domain_auth
   * (revision 282), where that directory covers the protocol binding: its
   * references are resolved at the key management server, and the controller is
   * kept until the item changes. Undefined where the domain names none, or
   * where its directory does not cover the binding, the domains clause then
   * leaving the credentials to this server's own configuration.
   */
  private async controllerOfDomain(domain: Node): Promise<DomainController | undefined> {
    const item = (this.store.meta(domain).metadata as Record<string, unknown>).cdmi_domain_auth;
    if (item === null || item === undefined || typeof item !== "object" || Array.isArray(item)) return undefined;
    const d = item as Record<string, unknown>;
    // "The values of the type field of the export types for which the directory
    // authenticates, and binding where it also authenticates requests of the
    // protocol bindings."
    const protocols = Array.isArray(d.protocols) ? d.protocols : [];
    if (!protocols.includes("binding")) return undefined;
    const key = `${domain.id}\u0000${JSON.stringify(d)}`;
    const held = this.directories.get(key);
    if (held !== undefined) return held;
    const ctx = this.credentialContext();
    const ca = d.ca_cert_id === undefined ? "" : (await retrieveCertificate(ctx, domain, boundReference(d.ca_cert_id)!)).pem;
    const serviceKey = (await retrieveSecret(ctx, domain, boundReference(d.service_key_id)!, SERVICE_KEY)).octets;
    const uris = (d.uris as string[]).filter((u) => typeof u === "string" && u.startsWith("ldaps:"));
    if (uris.length === 0) return undefined;
    const controller = new DomainController({
      domain: this.store.pathOf(domain),
      realm: String(d.realm),
      ldap: uris[0],
      base: String(d.base_dn),
      ca,
      cacheSeconds: 60,
      timeoutMs: 5000,
      servicePrincipal: String(d.service_principal),
      serviceKey,
      serviceEtype: ETYPE.aes256,
      // How the directory's entries are read, and where the realm's key
      // distribution centres are (revision 298; ECR-139B and ECR-142B).
      ...(typeof d.principal_attribute === "string" ? { principalAttribute: d.principal_attribute } : {}),
      ...(typeof d.group_attribute === "string" ? { groupAttribute: d.group_attribute } : {}),
      ...(Array.isArray(d.kdcs) && d.kdcs.every((k) => typeof k === "string")
        ? { kdcs: d.kdcs as string[] }
        : {}),
      ...(typeof d.home_base === "string" ? { homeBase: d.home_base } : {}),
      // The claims a bearer token is resolved from, which the descriptor names
      // and which nothing read before 0.87.
      fromDescriptor: true,
      ...(typeof d.principal_claim === "string" ? { principalClaim: d.principal_claim } : {}),
      ...(typeof d.groups_claim === "string" ? { groupsClaim: d.groups_claim } : {}),
      ...(d.userinfo_attributes !== null && typeof d.userinfo_attributes === "object" && !Array.isArray(d.userinfo_attributes)
        ? { userinfoAttributes: d.userinfo_attributes as Record<string, string> }
        : {}),
    }, (groups) => this.directory.privilegesOf(this.store.pathOf(domain), groups));
    // One at a time, so that a change of the item is taken at the next request.
    this.directories.clear();
    this.directories.set(key, controller);
    return controller;
  }

  /**
   * The object ID of an object an import presents, for a delegated access
   * control request that names it. Where it cannot be resolved, which a
   * create beneath an import gives, the namespace path is sent in its place,
   * so that the provider is told which object is meant.
   */
  private async presentedIdentity(ns: string): Promise<string> {
    try {
      const r = new Resolver(this.store, { principal: { name: "ANONYMOUS@", groups: [], administrator: false, privileges: [] } });
      const { parentNS, name, isContainer } = this.split(ns);
      // A container an import presents is named by its path: its identity is
      // of the layer that presents it, and is not read here.
      if (isContainer) return ns;
      const parent = await r.view(parentNS);
      const found = await resolveFile(this.store, parent, name);
      const id = found === undefined ? undefined : viewOf(this.store, found.ref).objectID;
      return typeof id === "string" ? id : ns;
    } catch {
      return ns;
    }
  }

  /**
   * The credentials a Kerberos service ticket presented to an S3 export
   * gives: this server decrypts it with the key of its service principal in
   * the realm of the domain owning the container the export is placed on,
   * "verifies that the ticket is within its validity period, and that it was
   * issued in the realm of the directory of the domain that owns the
   * container object the export is placed on", takes the session key as the
   * secret access key, and resolves the client principal the ticket names,
   * with the groups of its privilege attribute certificate where it carries
   * one (revision 282; PLAN-auth.md, phase 8).
   */
  async temporaryS3Credentials(token: string, bucket: { node: Node }):
    Promise<{ secret: Buffer; principal: Principal } | { refused: string } | undefined> {
    const controller = this.domainControllers?.for(this.store.pathOf(this.domainOf(bucket.node)));
    if (controller === undefined) return { refused: "no realm is configured for the domain this bucket belongs to" };
    try {
      return await controller.fromS3Token(token);
    } catch (e) {
      return { refused: (e as Error).message.slice(0, 200) };
    }
  }

  /**
   * The principal a Kerberos ticket presented to this server's SMB service
   * names: "a domain controller authenticates an SMB client, by Kerberos or
   * by the pass-through of an NTLM authentication, and the CDMI server holds
   * no secret of that client" (revision 282; PLAN-auth.md, phase 8). A
   * session is established before a share is named, so the realm is not known
   * from the export; each realm this server belongs to is tried, and only the
   * one whose service key decrypts the ticket accepts it.
   */
  async smbKerberos(token: Buffer): Promise<{ principal: Principal; answer?: Buffer } | undefined> {
    const authorization = `Negotiate ${token.toString("base64")}`;
    for (const controller of this.domainControllers?.all() ?? []) {
      if (controller.config.serviceKey === undefined) continue;
      try {
        const accepted = await controller.accept(authorization, ["kerberos"]);
        if (accepted.principal.name === "ANONYMOUS@") continue;
        return {
          principal: accepted.principal,
          ...(accepted.negotiate === undefined ? {} : { answer: Buffer.from(accepted.negotiate, "base64") }),
        };
      } catch {
        // A ticket of another realm, which this controller's key does not
        // open: the next realm is tried, and none accepting it is a refusal.
      }
    }
    return undefined;
  }

  /** The mask a delegated access control provider returned for an object in this request, where it did. */
  private delegatedMaskOf(ref: DirRef | ObjRef | Node, governs?: Node): number | undefined {
    const node = asNode(ref) ?? governs;
    return node === undefined ? undefined : this.perRequest.getStore()?.masks.get(node.id);
  }

  /** Whether an object is a pipe: a queue object of the type seedmi_pipe. */
  private isPipe(node: Node): boolean {
    const m = this.store.meta(node);
    return m.isQueue === true && (m.metadata as Record<string, unknown>).cdmi_queue_type === PIPE_QUEUE_TYPE;
  }

  /**
   * A ticket for a connection through a pipe (RELAY-draft-2.md section 5.1): for
   * a principal the pipe's list admits to read and write it, to the destination
   * the body names, where a permit admits the principal to it. A refusal says
   * "not permitted" alone; the reason is the log's.
   */
  private async pipeTicket(req: IncomingMessage, res: ServerResponse, node: Node, ns: string, who: Principal): Promise<void> {
    const pipes = this.pipes!;
    const logged = (event: string, detail: Record<string, unknown>) => {
      if (this.log.enabled) {
        this.log.write({ surface: "pipe", outcome: event, failed: event !== "ticket issued", operation: "POST",
          instance: pathOnly(req.url ?? ""), principal: who.name, ms: 0, members: { origin: req.headers.origin, ...detail } });
      }
    };
    const notPermitted = (reason: string) => {
      logged("ticket refused", { reason });
      return forbidden("not permitted");
    };
    if (!pipes.settings.enabled) throw notPermitted("pipes are not enabled");
    if (!this.may(node, who, M.READ_OBJECT, false) || !this.may(node, who, M.WRITE_OBJECT, false)) {
      throw notPermitted("the pipe's list does not admit the principal to read and write it");
    }
    let body: { host?: unknown; port?: unknown };
    try {
      body = JSON.parse((await readBody(req)).toString("utf8"));
    } catch {
      // The malformed request condition, which Annex C defines: reported with
      // its type URI and not as about:blank. These three sites carried the
      // title of that condition and no type until 0.94, so a CDMI client
      // matching on the URI — which is what the document tells it to do, the
      // title and the detail being ones it "shall not rely on" — could not
      // recognize a condition this server was in fact reporting. The 429 below
      // had been given a type of this server's own, so the omission was not a
      // decision about type URIs; it was three calls that did not make one.
      throw malformed("a ticket request is a JSON object naming a host and a port");
    }
    if (body === null || typeof body !== "object") {
      throw malformed("a ticket request is a JSON object naming a host and a port");
    }
    const origin = typeof req.headers.origin === "string" ? req.headers.origin : undefined;
    const domain = this.store.pathOf(this.domainAt(ns));
    const out = await pipes.issue({ principal: who, pipe: node.id, domain, host: body.host, port: body.port, origin });
    if (!out.ok) {
      if (out.status === 400) {
        logged("ticket refused", { reason: out.reason });
        throw malformed("a ticket request names a host by its DNS name, and a port");
      }
      if (out.status === 429) {
        logged("ticket refused", { reason: out.reason });
        const c = new Condition(429, "", "A connection limit is reached.", "a connection limit is reached");
        c.type = SEEDMI_PROBLEM_BASE + "pipe-limit";
        throw c;
      }
      throw notPermitted(out.reason);
    }
    logged("ticket issued", { host: out.ticket.host, port: out.ticket.port, address: out.ticket.address, permit: out.ticket.permit });
    const reply = Buffer.from(JSON.stringify({ ticket: out.ticket.id, expires: cdmiTime(out.ticket.expires) }));
    res.writeHead(201, { "Content-Type": "application/json", "Cache-Control": "no-store", "Content-Length": String(reply.length) });
    res.end(reply);
  }

  /**
   * A WebSocket upgrade (RELAY-draft-2.md section 5.2): on the TLS listener
   * alone, of a pipe's URI, with the subprotocol seedmi-pipe.v1. The first frame
   * presents the ticket (pipe-relay.ts); no credentials are taken here.
   */
  handleUpgrade(req: IncomingMessage, socket: import("node:net").Socket, head: Buffer, secure: boolean): void {
    const refuse = (status: number, text: string) =>
      socket.end(`HTTP/1.1 ${status} ${text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
    if (this.pipes === undefined || !this.pipes.settings.enabled) return refuse(404, "Not Found");
    // The ticket, and the traffic, cross the network inside TLS alone.
    if (!secure) return refuse(403, "Forbidden");
    const url = req.url ?? "/";
    const q = url.indexOf("?");
    const rawPath = q < 0 ? url : url.slice(0, q);
    if (!rawPath.startsWith(this.base)) return refuse(404, "Not Found");
    let ns: string;
    try {
      ns = ("/" + rawPath.slice(this.base.length)).split("/").map((x, i) => (i === 0 ? x : decodeURIComponent(x))).join("/");
    } catch {
      return refuse(400, "Bad Request");
    }
    const node = this.nodeForDelegation(ns);
    if (node === undefined || !this.isPipe(node)) return refuse(404, "Not Found");
    const hs = handshake(req, SUBPROTOCOL);
    if (!hs.ok) return refuse(hs.status, hs.status === 405 ? "Method Not Allowed" : "Bad Request");
    socket.write(hs.response);
    const origin = typeof req.headers.origin === "string" ? req.headers.origin : undefined;
    runRelay(socket, head, {
      service: this.pipes, pipe: node.id, origin,
      stillAdmitted: (t) => {
        const now = this.nodeForDelegation(ns);
        if (now === undefined || now.id !== node.id || !this.isPipe(now)) return false;
        if (!this.domainEnabled(this.domainAt(ns))) return false;
        if (!this.may(now, t.principal, M.READ_OBJECT, false) || !this.may(now, t.principal, M.WRITE_OBJECT, false)) return false;
        return this.pipes!.stillPermitted(t);
      },
      log: (event) => {
        if (this.log.enabled) {
          this.log.write({ surface: "pipe", outcome: String(event.event), failed: false, operation: "WEBSOCKET",
            instance: rawPath, principal: String(event.principal ?? ANONYMOUS.name), ms: Number(event.ms ?? 0), members: event });
        }
      },
    });
  }

  /** An HTTP server serving this binding. An upgrade on it is refused: pipes are served over TLS alone. */
  listen(port: number, host = "127.0.0.1"): Promise<Server> {
    const server = createServer((req, res) => {
      void this.handle(req, res);
    });
    server.on("upgrade", (req: IncomingMessage, socket: import("node:net").Socket, head: Buffer) => this.handleUpgrade(req, socket, head, false));
    return new Promise((resolve) => server.listen(port, host, () => resolve(server)));
  }
}

// ---------------------------------------------------------------------------

/**
 * Whether a representation changes any metadata item other than the
 * storage system items that have access mask bits of their own.
 */
function changesUserMetadata(body: Record<string, unknown>): boolean {
  if (!("metadata" in body)) return false;
  const md = body.metadata;
  if (md === null || typeof md !== "object" || Array.isArray(md)) return true;
  // A user metadata item is governed by WRITE_METADATA; the items
  // below are governed by their own bits or by WRITE_ATTRIBUTES.
  return Object.keys(md as Record<string, unknown>)
    .some((k) => !k.startsWith("cdmi_"));
}

/**
 * Whether an update changes a storage system or data system metadata
 * item, which WRITE_ATTRIBUTES governs. The items with bits of their
 * own are excluded: they are checked where those bits are.
 */
/**
 * The retention items and the hold item, each governed by a mask bit of its own:
 * "WRITE_RETENTION - If true, indicates permission to change retention
 * attributes of an object", and WRITE_RETENTION_HOLD for a hold, as section
 * 6.2.1.3 of RFC 8881 defines the two. Before 0.61 WRITE_ATTRIBUTES governed them.
 */
const RETENTION_ONLY = new Set(RETENTION_ITEMS.filter((k) => k !== HOLD_ID));
const HOLD_ITEMS = new Set([HOLD_ID]);

/** The system metadata items a supplied metadata field names. */
function suppliedItems(body: Record<string, unknown>): string[] {
  const md = body.metadata;
  if (md === null || typeof md !== "object" || Array.isArray(md)) return [];
  return Object.keys(md as Record<string, unknown>);
}

function changesAttributes(body: Record<string, unknown>): boolean {
  if (!("metadata" in body)) return false;
  return suppliedItems(body).some((k) => k.startsWith("cdmi_") && k !== "cdmi_acl" && k !== "cdmi_owner" &&
    !RETENTION_ONLY.has(k) && !HOLD_ITEMS.has(k));
}

/** The cdmi_acl item of a supplied metadata field, where one appears. */
function suppliedACL(body: Record<string, unknown>): ACE[] | undefined {
  const md = body.metadata;
  if (md === null || typeof md !== "object" || Array.isArray(md)) return undefined;
  const v = (md as Record<string, unknown>).cdmi_acl;
  return Array.isArray(v) ? (v as ACE[]) : undefined;
}

/**
 * The store node a reference names. An object presented from an image
 * import has none, and seedmi does not write into an imported file
 * system, so an operation that would reports that.
 */
function decodeSuppliedValue(body: Record<string, unknown>): Buffer {
  if (!("value" in body)) return Buffer.alloc(0);
  const vte = typeof body.valuetransferencoding === "string"
    ? body.valuetransferencoding
    : "utf-8";
  if (vte !== "utf-8" && vte !== "base64") {
    throw invalidField("valuetransferencoding",
      'seedmi transports a value as "utf-8" or "base64"');
  }
  if (typeof body.value !== "string") {
    throw invalidField("value", "the value field shall be a JSON string");
  }
  return Buffer.from(body.value, vte === "base64" ? "base64" : "utf8");
}

function storedNode(ref: ObjRef, ns: string): Node {
  const n = nodeOf(ref);
  if (!n) {
    throw forbidden(
      "%s is held by an imported file system, into which seedmi does not write", ns);
  }
  return n;
}

/** The store node a reference names, where it names one. */
function asNode(r: DirRef | ObjRef | Node): Node | undefined {
  if ("kind" in r) return nodeOf(r);
  return r;
}

/** The Vary header field of a response, with a field name added. */
function varyWith(res: ServerResponse, name: string): string {
  const current = res.getHeader("Vary");
  const names = String(current ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  if (!names.some((n) => n.toLowerCase() === name.toLowerCase())) names.push(name);
  return names.join(", ");
}

/**
 * Applies a supplied rel field. An update that supplies it replaces it
 * entirely, except in a merge update, where a member whose supplied
 * value is null is removed.
 */
/**
 * The "rel" field of a representation, as it is reported.
 *
 * "Where the object has no graph relationships, the value shall be an empty
 * JSON object", and the field "applies to every representation other than that
 * of a capability object". Before 0.95 this server omitted the field entirely
 * where an object had none, so a CDMI client could not tell an object with no
 * graph relationships from a CDMI server that does not report them — and a
 * selection naming the field came back as an empty representation, which says
 * the field does not exist rather than that it is empty.
 *
 * It is a function rather than four expressions because the four builders had
 * drifted: two reported the field and two dropped it.
 */
const relRep = (m: { rel?: Record<string, unknown> | undefined }): Record<string, unknown> =>
  m.rel ?? {};

function applyRel(m: StoredMeta, body: Record<string, unknown>,
  has: (f: string) => boolean, form: string): void {
  if (!has("rel")) return;
  const v = body.rel;
  if (v === null) {
    m.rel = undefined;
    return;
  }
  if (v === undefined || typeof v !== "object" || Array.isArray(v)) {
    throw invalidField("rel", "the rel field shall be a JSON object");
  }
  const supplied = v as Record<string, unknown>;
  // In a merge update a member supplied as null is removed, so what is
  // validated is the field as it will stand and not the patch, which
  // holds nulls that the structure does not permit.
  const merged = form === "merge" && m.rel !== undefined
    ? mergePatch(m.rel, supplied)
    : supplied;
  const bad = checkRel(merged);
  if (bad) throw invalidField(bad.at, "%s", bad.why);
  // A merge that removes every member leaves the field absent rather
  // than present and empty.
  m.rel = form === "merge" && Object.keys(merged).length === 0 ? undefined : merged;
}

/** Whether a selection asks for the named fields and nothing else. */
/**
 * The fields of a representation that are not attribute fields: "The value
 * fields, children fields, and metadata field are considered to be
 * non-attribute fields. All other fields are considered to be attribute
 * fields", which READ_ATTRIBUTES governs (the ACL structure subclause).
 */
const NON_ATTRIBUTE_FIELDS = ["value", "valuerange", "valuetransferencoding", "children", "childrenrange", "metadata"];

/** Removes the attribute fields of a representation, for a principal not granted READ_ATTRIBUTES. */
function withholdAttributes(rep: Record<string, unknown>): void {
  for (const k of Object.keys(rep)) if (!NON_ATTRIBUTE_FIELDS.includes(k)) delete rep[k];
}

/** Whether a selection names attribute fields alone. */
function selectsOnlyAttributes(sel: Selection): boolean {
  return sel.any && sel.fields.length > 0 && sel.fields.every((f) => !NON_ATTRIBUTE_FIELDS.includes(f));
}

/**
 * A redirect's Location with the request's query component carried over:
 * the correction of a path's form gives "the request URI with a trailing
 * solidus added to the CDMI path, preserving the query component unchanged",
 * so that a selection survives it. The query was dropped before 0.44.
 */
function withQuery(req: IncomingMessage, location: string): string {
  const url = req.url ?? "";
  const at = url.indexOf("?");
  return at < 0 ? location : location + url.slice(at);
}

/**
 * The correction of a path's form, for a name that denotes a container
 * object, a capability object or a domain object and was given without its
 * trailing solidus: "Where a GET request, a HEAD request, or a DELETE request
 * addresses a CDMI path that does not end with a solidus, and the name denotes
 * a container object, a capability object, or a domain object ..., the CDMI
 * server shall respond with an HTTP status code of 307 Temporary Redirect and a
 * Location header field giving the request URI with a trailing solidus added
 * to the CDMI path, preserving the query component unchanged. ... In every
 * other case the CDMI server shall serve the object the CDMI path names, or
 * shall report the not found condition." Before 0.46 capability and domain
 * objects answered 404 or 301, which a client may cache and on which it may
 * change the method.
 */
function correctForm(req: IncomingMessage, res: ServerResponse, base: string, ns: string): void {
  const method = req.method ?? "GET";
  if (method !== "GET" && method !== "HEAD" && method !== "DELETE") throw notFound(ns);
  res.writeHead(307, { Location: withQuery(req, base.slice(0, -1) + ns + "/"), "Content-Length": "0" });
  res.end();
}

function onlySelects(sel: Selection, fields: string[]): boolean {
  return sel.any && sel.fields.length > 0 && sel.fields.every((f) => fields.includes(f));
}

/** Whether neither the Content-Type nor the Accept field names a CDMI type. */
/**
 * The first written range at or after an offset, in the form of the valuerange
 * field: a range beginning before the offset and ending at or after it is given
 * from the offset; an empty string where nothing at or after it is written.
 */
export function layoutRange(ranges: [number, number][], offset: number): string {
  const r = ranges.find(([, last]) => last >= offset);
  return r === undefined ? "" : `${Math.max(r[0], offset)}-${r[1]}`;
}

/**
 * The destination of a reference, with the query component of the request:
 * "Where the request carries a query component, the CDMI server shall give the
 * destination URI in the Location header field that query component, in place
 * of any query component the destination URI has of its own. A selection made
 * through a reference therefore reaches the destination, and is the selection
 * the CDMI client made and no other. Where the request carries no query
 * component, the destination URI is given as it was supplied" (revision 297).
 * Before 0.63 the destination was given as supplied, so a selection made
 * through a reference was lost.
 */
function throughReference(destination: string, req: IncomingMessage): string {
  const at = (req.url ?? "").indexOf("?");
  if (at < 0) return destination;
  const query = (req.url ?? "").slice(at + 1);
  const hash = destination.indexOf("#");
  const withoutFragment = hash < 0 ? destination : destination.slice(0, hash);
  const fragment = hash < 0 ? "" : destination.slice(hash);
  const own = withoutFragment.indexOf("?");
  return `${own < 0 ? withoutFragment : withoutFragment.slice(0, own)}?${query}${fragment}`;
}

/**
 * A media type as RFC 2046 defines one, stored as the draft requires: the
 * type, the subtype and each parameter name in lower case, the value of a
 * charset parameter in lower case, and every other parameter value as it
 * came, some being case sensitive. Undefined where the string is not a media
 * type at all.
 */
function mediaType(given: string): string | undefined {
  const [head, ...rest] = given.split(";");
  const m = /^\s*([A-Za-z0-9!#$&^_.+-]+)\/([A-Za-z0-9!#$&^_.+-]+)\s*$/.exec(head ?? "");
  if (m === null) return undefined;
  const parts = [`${m[1].toLowerCase()}/${m[2].toLowerCase()}`];
  for (const p of rest) {
    const at = p.indexOf("=");
    if (at < 0) return undefined;
    const name = p.slice(0, at).trim();
    const value = p.slice(at + 1).trim();
    if (!/^[A-Za-z0-9!#$&^_.+-]+$/.test(name) || value === "") return undefined;
    parts.push(`${name.toLowerCase()}=${name.toLowerCase() === "charset" ? value.toLowerCase() : value}`);
  }
  return parts.join("; ");
}

/**
 * Whether a string is a URI reference, as section 4.1 of RFC 3986 defines
 * one: it resolves against a base. A destination that does not resolve is
 * refused, "so that every destination it stores has a resolution".
 */
function isUriReference(v: string): boolean {
  if (v === "" || /[\s<>"\\^`{|}]/.test(v)) return false;
  try {
    new URL(v, "http://example.invalid/base/");
    return true;
  } catch {
    return false;
  }
}

/**
 * Whether a string is base 64 as RFC 4648 section 4 defines it: the alphabet,
 * padded to a multiple of four, and no other character, whitespace included.
 * Buffer.from(s, "base64") ignores everything it does not recognize, so a
 * value has to be checked before it is decoded.
 */
function isBase64(s: string): boolean {
  if (s.length % 4 !== 0) return false;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return false;
  const padding = /=*$/.exec(s)![0].length;
  return padding === 0 || s.length >= 4;
}

/**
 * The cdmi_enc_key_id item a request supplies, which names the key
 * encryption key of an encrypted object.
 */
function suppliedEncKeyID(body: Record<string, unknown>): unknown {
  const md = body.metadata;
  if (md === null || typeof md !== "object" || Array.isArray(md)) return undefined;
  return (md as Record<string, unknown>).cdmi_enc_key_id;
}

/**
 * The Name a credential reference addresses, for the comparison the
 * subclause makes against a "kid" header parameter. A reference is a JSON
 * object naming a key management server and a managed object.
 */
function nameOfCredential(item: unknown): string | undefined {
  if (typeof item === "string") return item === "" ? undefined : item;
  if (item === null || typeof item !== "object" || Array.isArray(item)) return undefined;
  const name = (item as Record<string, unknown>).name;
  return typeof name === "string" ? name : undefined;
}

/**
 * The extension fields of a representation: those whose names this document
 * does not define, which a CDMI server stores and returns unchanged.
 */
function extensionsOfRepresentation(rep: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (rep === null || typeof rep !== "object") return out;
  for (const [k, v] of Object.entries(rep as Record<string, unknown>)) {
    if (!isDefinedField(k) && !k.startsWith("cdmi_")) out[k] = v;
  }
  return out;
}

/**
 * The values the cdmi_lock data system metadata item takes, and what each
 * refuses (revision 327, the locking subclause):
 *
 * * "lock_none", which requests no lock, and is the value where the item is
 *   absent;
 * * "lock_shared", which refuses every operation that creates, updates or
 *   deletes such an object, and permits another shared lock at the same
 *   time;
 * * "lock_exclusive", the same refusal, and no other lock held at the same
 *   time;
 * * "lock_delete", which refuses every operation that deletes such an
 *   object, and permits an operation that updates one.
 */
/** The cdmi_lock capability: the values of the item this server supports. */

export const LOCK_VALUES = ["lock_none", "lock_shared", "lock_exclusive", "lock_delete"];

/**
 * The values in order of what they refuse, least first: an update that moves
 * the item down this order "changes it to a value refusing fewer operations"
 * and is not refused by the lock in force (revision 347).
 */
export const LOCK_ORDER = ["lock_none", "lock_delete", "lock_shared", "lock_exclusive"];

/** Whether a lock of that value refuses an operation of that kind. */
export function lockRefuses(lock: string, operation: "create" | "update" | "delete"): boolean {
  if (lock === "lock_shared" || lock === "lock_exclusive") return true;
  if (lock === "lock_delete") return operation === "delete";
  return false;
}

function namesNoCDMIMediaType(req: IncomingMessage): boolean {
  for (const h of [req.headers["content-type"], req.headers.accept]) {
    if (typeof h !== "string") continue;
    for (const part of h.split(",")) {
      if (part.split(";")[0].trim().toLowerCase().startsWith("application/cdmi-")) return false;
    }
  }
  return true;
}

function conditionalRead(req: IncomingMessage, tag: string): boolean {
  const inm = req.headers["if-none-match"] as string | undefined;
  return inm !== undefined && (inm === "*" || matchesETag(inm, tag));
}

/** Drops the items a CDMI client may not set. */
/**
 * The metadata items a client supplies that are stored as given. The
 * storage system metadata items are computed by the server and are
 * dropped; the data system metadata items this server offers are
 * supplied by the client and are kept.
 */
/**
 * The user metadata items a supplied cdmi_representations item carries, and
 * the two faults 11.2.4 names within one.
 *
 * "A member of the cdmi_representations item contains the metadata of the
 * representation it names. It may contain a storage system metadata item, a
 * provided data system metadata item, and a user metadata item." This server
 * holds one representation of a value, so the metadata of that representation
 * is the metadata of the object: a user metadata item supplied within the
 * member is a user metadata item of the object and is stored as one. A
 * storage system item is server-generated and is ignored, as one supplied
 * anywhere else is.
 */
function representationItems(v: unknown): Record<string, unknown> {
  if (typeof v !== "object" || Array.isArray(v)) {
    throw malformed("the cdmi_representations item holds a JSON object, one member per " +
      "representation");
  }
  const out: Record<string, unknown> = {};
  for (const [name, member] of Object.entries(v as Record<string, unknown>)) {
    if (member === null) continue;
    if (typeof member !== "object" || Array.isArray(member)) {
      throw invalidField(`metadata/cdmi_representations/${name}`,
        "a member of the cdmi_representations item holds the metadata of the " +
        "representation it names, which is a JSON object");
    }
    for (const [item, value] of Object.entries(member as Record<string, unknown>)) {
      const at = `metadata/cdmi_representations/${name}/${item}`;
      if (item === "cdmi_representations") {
        throw invalidField(at,
          "a member of the cdmi_representations item shall not contain a " +
          "cdmi_representations item of its own");
      }
      if (DATA_SYSTEM_METADATA.includes(item)) {
        throw invalidField(at,
          "a member of the cdmi_representations item shall not contain a data system " +
          "metadata item: such an item is a request for a data service and applies to " +
          "the object rather than to one form of its value");
      }
      // A storage system metadata item is generated by this server and is
      // ignored where a client supplies it, here as anywhere else.
      if (item.startsWith("cdmi_")) continue;
      out[item] = value;
    }
  }
  return out;
}

function userMetadata(m: Record<string, unknown>, merging = false): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(m)) {
    // "A member shall not contain a data system metadata item ... and shall
    // not contain a cdmi_representations item of its own. A CDMI server
    // shall report the invalid field condition ... where a CDMI client
    // supplies either" (11.2.4). The item as a whole is storage system
    // metadata, which a CDMI server generates and which is ignored where a
    // client supplies it; these two faults within it are named errors all
    // the same, and this server dropped the whole item without looking
    // (weedmi META-013).
    if (VALUE_REPRESENTATIONS && k === "cdmi_representations" && v !== null && v !== undefined) {
      Object.assign(out, representationItems(v));
      continue;
    }
    if (k.startsWith("cdmi_") && !clientSets(k)) {
      // An item this server computes is ignored where a client supplies it;
      // a cdmi_ name this document does not define is the invalid field
      // condition, and was silently dropped before 0.66 (weedmi META-010).
      if (!defines(k)) {
        throw invalidField(`metadata/${k}`,
          "%j is not a metadata item this document defines, and the cdmi_ names are its own", k);
      }
      continue;
    }
    // The cdmi_sanitization_method item names a method this CDMI server
    // offers, as the cdmi_value_hash item names an algorithm it computes. The
    // method was stored verbatim before 0.87, whatever it said, and then
    // reported back in cdmi_sanitization_method_provided — an item whose
    // meaning is "the sanitization method used" — while the store, which acts
    // on "overwrite" and on nothing else, overwrote nothing. A CDMI client was
    // told its data had been sanitized by a method this server has never
    // claimed and does not implement.
    if (k === "cdmi_sanitization_method" && v !== null &&
        !(typeof v === "string" && SANITIZATION_METHODS.includes(v))) {
      throw invalidField(`metadata/${k}`,
        "%j is not a sanitization method this CDMI server performs; the " +
        "cdmi_sanitization_method capability names the ones it does: %s",
        v, SANITIZATION_METHODS.join(", "));
    }
    // The cdmi_lock item takes the four values the annex defines and no
    // other: a value this server does not recognize would lock nothing
    // while appearing to (revision 327, the locking subclause).
    //
    // A null is the instruction to remove the item, not a value for it, and the
    // locking subclause admits "an update that removes the item or weakens it".
    // This check ran first and refused the null, so a lock, once placed, could
    // never be removed by any CDMI client on any object: the rule that admits
    // the removal is in the code and was unreachable, and the value check is
    // where it stopped. Found by writing a test that removes a lock, which none
    // of the locking tests did.
    if (k === "cdmi_lock" && v !== null && !(typeof v === "string" && LOCK_VALUES.includes(v))) {
      throw malformed("the cdmi_lock item holds one of %s, or null to remove it",
        LOCK_VALUES.join(", "));
    }
    // "The value of a metadata item may be a JSON string, a JSON array, or a
    // JSON object": a number or a boolean, at any depth, is a value that does
    // not conform to the type defined for it, which is the malformed request
    // condition. A null is the merge instruction to remove a member, at the
    // top level and within a value alike.
    // "The merge rules recurse into the metadata field", so a null member at
    // any depth is a removal and not a stored value: only a number or a
    // boolean is refused. Refusing a nested null was a 0.66 regression
    // (weedmi META-003, META-F01).
    checkMetadataValue(`metadata/${k}`, v);
    // "Where such an item is created or updated by any operation, its name
    // shall be a field name and its value shall be a JSON string that is a
    // field value ... A CDMI server shall report the invalid field condition
    // where they do not." A null is the instruction to remove the item and
    // is not a value being created (weedmi META-011).
    if (v !== null) checkHeaderMetadataItem(k, v);
    // A null within a value is the instruction to remove that member, so it
    // is not stored: "a field or member whose supplied value is null shall
    // be removed from the stored object", applied recursively where both
    // values are objects (RFC 7396). This server checked the null and then
    // stored it, which left a value no metadata value may hold (weedmi
    // SCHM, Annex A admitting a string, an array or an object).
    //
    // Where the operation is a merge, the nulls are left in place for
    // mergePatch to act on and are removed by it: taking them out here left
    // "the merge rules recurse into the metadata field" true of the members
    // and false of the removals, so a member supplied as null at depth
    // survived the patch that asked for it to go (weedmi ECR-188B). A
    // complete replacement has nothing to remove from, so a null at depth
    // is dropped here as it always was.
    out[k] = merging ? v : withoutNulls(v);
  }
  return out;
}

/**
 * A metadata value with the members a null removes taken out of it.
 * "metadata-value = tstr / [* metadata-value] / {* tstr => metadata-value}"
 * (Annex A): no null is a metadata value at any depth, and a null member is
 * the instruction to remove that member rather than a value to store. A
 * null within an array is neither, so the element is dropped with the rest.
 */
function withoutNulls(v: unknown): unknown {
  if (Array.isArray(v)) return v.filter((e) => e !== null).map(withoutNulls);
  if (v === null || typeof v !== "object") return v;
  const out: Record<string, unknown> = {};
  for (const [k, member] of Object.entries(v as Record<string, unknown>)) {
    if (member === null) continue;
    out[k] = withoutNulls(member);
  }
  return out;
}

/** A metadata value: a string, an array or an object, at every depth. */
function checkMetadataValue(at: string, v: unknown, depth = 0): void {
  if (depth > 64) throw malformed("%s is nested more deeply than this server reads", at);
  if (typeof v === "string") return;
  // A null is the merge instruction to remove a member, at the top level and
  // within a value alike.
  if (v === null) return;
  if (Array.isArray(v)) {
    for (const item of v) checkMetadataValue(at, item, depth + 1);
    return;
  }
  if (v !== null && typeof v === "object") {
    for (const item of Object.values(v as Record<string, unknown>)) checkMetadataValue(at, item, depth + 1);
    return;
  }
  throw malformed("%s is a JSON string, a JSON array or a JSON object", at);
}

/**
 * The data system metadata items a client may set, which are kept in
 * the metadata field as supplied. cdmi_acl and cdmi_owner are storage
 * system metadata with bits of their own and are applied separately.
 */
/**
 * The data system metadata items of Annex D, which a CDMI client supplies
 * and a CDMI server stores: "a CDMI server shall preserve a metadata item
 * whose name it does not recognize, and shall return it unchanged", and an
 * item this server does not interpret is still the client's to set. The
 * items ending in _provided are reported by the server and are filtered out
 * where a client supplies them (weedmi META, 0.70).
 */
/**
 * The sanitization methods this server offers, which the
 * cdmi_sanitization_method capability publishes and the item of that name
 * selects from. "Supported sanitization methods are defined as
 * system-specific strings."
 */
export const SANITIZATION_METHODS = ["overwrite"];


const DATA_SYSTEM_METADATA = [
  "cdmi_assignedsize", "cdmi_authentication_methods", "cdmi_cors_headers",
  "cdmi_cors_methods", "cdmi_cors_origins", "cdmi_data_dispersion", "cdmi_data_redundancy",
  "cdmi_enc_key_id", "cdmi_enc_object_sign_id", "cdmi_enc_object_verify_id",
  "cdmi_enc_value_sign_id", "cdmi_enc_value_verify_id", "cdmi_encryption",
  "cdmi_geographic_placement", "cdmi_hold_id", "cdmi_immediate_redundancy",
  "cdmi_infrastructure_redundancy", "cdmi_latency", "cdmi_lock",
  "cdmi_representation_default", "cdmi_retention_autodelete", "cdmi_retention_id",
  "cdmi_retention_period", "cdmi_sanitization_method", "cdmi_throughput",
  "cdmi_value_hash", "cdmi_versioning", "cdmi_versions_age", "cdmi_versions_count",
  "cdmi_versions_size",
  // The recovery objectives, which Annex D defines and which this list omitted
  // until 0.113 — so a CDMI client that supplied cdmi_RPO or cdmi_RTO was refused
  // for a name this document defines, the rule being that "only a name the
  // document does not define at all is refused".
  "cdmi_RPO", "cdmi_RTO",
  // cdmi_hash was in this list and is storage system metadata, not data system
  // metadata: Annex D defines it in the storage system table, it is computed by
  // the CDMI server rather than requested, and a member of the
  // cdmi_representations item "may contain a storage system metadata item" while
  // it "shall not contain a data system metadata item" — so a member carrying
  // cdmi_hash, which is exactly what a member describing a representation would
  // carry, was refused with the invalid field condition until 0.113.
].filter((n) => !n.endsWith("_provided"));
/**
 * The data system metadata items that participate in inheritance, which is
 * every one of them but cdmi_assignedsize: "This item is not inherited by
 * the objects a container object contains" (Annex D). Storage system
 * metadata, provided items and user metadata do not participate, and none of
 * them is in this list.
 */
const INHERITED_METADATA = DATA_SYSTEM_METADATA.filter((n) => n !== "cdmi_assignedsize");

const CLIENT_SET_METADATA = [...DATA_SYSTEM_METADATA, CORS_ORIGINS, CORS_METHODS, CORS_HEADERS,
  // "A CDMI server that does not support signature verification shall
  // return the value and its signature unchanged, and the CDMI client
  // verifies the signature itself": a signature a CDMI client supplies is
  // the client's, and is stored and returned as given. This server
  // generates the item where the object names a signing key, and accepted
  // and silently discarded a supplied one before 0.73 (weedmi DMGT-018).
  "cdmi_enc_signature",
  // The two items that request delegated access control. A CDMI client "may
  // supply this item when the object is created, and may add, change or remove
  // it afterwards", subject to the permission cdmi_acl requires, which
  // applyOwnerAndACL demands.
  "cdmi_dac_uri", "cdmi_dac_certificate",
  // The credential references of an encrypted object: the key encryption
  // key its value is wrapped under, and the keys that sign and verify.
  // "A CDMI client that supplies one of these items demonstrates
  // entitlement to the key it addresses", so a client sets them and a
  // CDMI server stores them (PLAN-encryption.md).
  "cdmi_enc_key_id", "cdmi_enc_value_sign_id", "cdmi_enc_value_verify_id",
  "cdmi_enc_object_sign_id", "cdmi_enc_object_verify_id",
  "cdmi_versioning", "cdmi_versions_count", "cdmi_versions_age",
  "cdmi_versions_size",
  // The settings of a domain object, which a client configures.
  "cdmi_domain_enabled", "cdmi_authentication_methods", "cdmi_domain_kms",
  // The directory of a domain (revision 282), which the domain_auth_admin
  // privilege governs and whose references are resolved at a key management
  // server; before 0.63 it was accepted and then silently discarded here.
  "cdmi_domain_auth",
  // Where the objects of a domain go when it is deleted (Annex D).
  "cdmi_domain_delete_reassign",
  // The size reported for an object through a protocol export.
  "cdmi_assignedsize",
  // The metadata of a query queue, which a CDMI client supplies to
  // create one. The status items are CDMI server populated and are
  // not here.
  QUEUE_TYPE, SCOPE, RESULTS, EVENTS,
  // The algorithm a client asks the value to be hashed with.
  "cdmi_value_hash",
  // Retention and hold, which a client asks for.
  ...RETENTION_ITEMS];

/**
 * Whether the cdmi_domain_doh item is offered ([discovery] doh; ECR-224A).
 *
 * The item is a proposed addition, and a cdmi_ name revision 365 does not
 * define is the document's to give: 0.83 withdrew cdmi_export_smb_anonymous,
 * which this implementation had invented, on that ground. So it is off unless
 * a deployment asks for it, and a server that says nothing about discovery
 * refuses the item exactly as 0.103 did. The flag is a module variable rather
 * than an option of the binding because the two lists below are consulted by a
 * free function that has no binding to ask, which is how VALUE_REPRESENTATIONS
 * is held as well.
 */
export let DOH_ITEM = false;
export const setDohItem = (on: boolean): void => { DOH_ITEM = on; };

/** Whether a client may set this item: the list, and the item behind the switch. */
const clientSets = (k: string): boolean =>
  CLIENT_SET_METADATA.includes(k) || (DOH_ITEM && k === "cdmi_domain_doh");

/** Whether this document defines the name at all. */
const defines = (k: string): boolean =>
  DEFINED_METADATA.includes(k) || (DOH_ITEM && k === "cdmi_domain_doh");

/**
 * The metadata items this document defines: those this server computes, and
 * those a client sets. A cdmi_ name outside this list is refused rather than
 * passed over (weedmi META-010).
 */
const DEFINED_METADATA = [...STORAGE_SYSTEM_METADATA, ...CLIENT_SET_METADATA,
  // The metadata items of Annex C and Annex D, whose names this document
  // defines whether or not this server interprets them: an item it does not
  // interpret is stored as supplied, and only a name the document does not
  // define at all is refused. Refusing cdmi_data_redundancy, which Table D.3
  // defines, was a 0.66 regression (weedmi META-010).
  "cdmi_acl", "cdmi_acount", "cdmi_argument", "cdmi_assignedsize", "cdmi_atime",
  "cdmi_authentication_methods", "cdmi_authentication_methods_provided", "cdmi_capability",
  "cdmi_capability_uri", "cdmi_cors_headers", "cdmi_cors_methods", "cdmi_cors_origins",
  "cdmi_cors_provided", "cdmi_ctime", "cdmi_dac_certificate", "cdmi_dac_methods",
  "cdmi_dac_uri", "cdmi_data_dispersion", "cdmi_data_dispersion_provided",
  "cdmi_data_redundancy", "cdmi_data_redundancy_provided", "cdmi_domain_auth",
  "cdmi_domain_delete_reassign", "cdmi_domain_enabled", "cdmi_domain_kms", "cdmi_domains",
  // The description of the requesting principal within a domain (ECR-226A),
  // which this server computes: an item it computes is ignored where a client
  // supplies it, and only a cdmi_ name the document does not define at all is
  // refused. It is not in CLIENT_SET_METADATA, so a client cannot store one.
  "cdmi_domain_userinfo",
  "cdmi_enc_key_id", "cdmi_enc_object_sign_id", "cdmi_enc_object_verify_id",
  "cdmi_enc_signature", "cdmi_enc_value_sign_id", "cdmi_enc_value_verify_id",
  "cdmi_encryption", "cdmi_encryption_provided", "cdmi_export", "cdmi_field",
  "cdmi_geographic_placement", "cdmi_geographic_placement_provided", "cdmi_group",
  // The recovery objectives and their provided items, which Annex D defines.
  "cdmi_RPO", "cdmi_RPO_provided", "cdmi_RTO", "cdmi_RTO_provided",
  "cdmi_hash", "cdmi_hold_id", "cdmi_hold_id_provided", "cdmi_immediate_redundancy",
  "cdmi_immediate_redundancy_provided", "cdmi_import", "cdmi_infrastructure_redundancy",
  "cdmi_infrastructure_redundancy_provided", "cdmi_latency", "cdmi_latency_provided",
  "cdmi_limit", "cdmi_limit_value", "cdmi_lock", "cdmi_lock_provided", "cdmi_mcount",
  "cdmi_metadata", "cdmi_mtime", "cdmi_notification", "cdmi_notification_events",
  "cdmi_notification_queue", "cdmi_notification_status", "cdmi_object", "cdmi_origin",
  "cdmi_owner", "cdmi_partitions", "cdmi_query", "cdmi_query_queue", "cdmi_query_status",
  "cdmi_queue_type", "cdmi_range", "cdmi_representation_default",
  "cdmi_representation_default_provided", "cdmi_representations",
  "cdmi_results_specification", "cdmi_retention_autodelete",
  "cdmi_retention_autodelete_provided", "cdmi_retention_id", "cdmi_retention_period",
  "cdmi_retention_period_provided", "cdmi_retry_after", "cdmi_s3_uploads_aborted",
  "cdmi_sanitization_method", "cdmi_sanitization_method_provided",
  "cdmi_scope_specification", "cdmi_selection", "cdmi_size", "cdmi_throughput",
  "cdmi_throughput_provided", "cdmi_value_hash", "cdmi_value_hash_provided",
  "cdmi_version_children", "cdmi_version_current", "cdmi_version_object",
  "cdmi_version_oldest", "cdmi_version_parent", "cdmi_versioning",
  "cdmi_versioning_provided", "cdmi_versions_age", "cdmi_versions_age_provided",
  "cdmi_versions_count", "cdmi_versions_count_provided", "cdmi_versions_size",
  "cdmi_versions_size_provided"
];


/**
 * The limits on the user metadata of an object.
 *
 * The user metadata of an object is presented as extended attributes
 * through an NFS export, so the limits are chosen to be ones NFS can
 * carry. A name is at most MAXNAME octets because it travels as a
 * component4 with the "user." prefix; a value is bounded so that one
 * attribute fits in a single READ, and the total so that a listing of
 * every name fits within a reasonable LISTXATTRS count.
 */
export const METADATA_MAXITEMS = 256;
export const METADATA_MAXSIZE = 64 * 1024;
/** How much of a remote value is read in one request. */
const REMOTE_CHUNK = 1 << 20;

/**
 * The schemes a reference may name: those this CDMI server serves. A
 * destination that is a namespace path of this server is permitted
 * as well, and is not a URI.
 */
export const REFERENCE_SCHEMES = ["http", "https", "nfs", "smb"];

export const METADATA_MAXTOTALSIZE = 1024 * 1024;

/**
 * The storage system metadata items this CDMI server generates and
 * a CDMI client does not set. An attempt to set one is ignored.
 */
/**
 * The header fields of an operation that are passed to a delegated access
 * control provider: "a JSON string for each HTTP header in the operation
 * request that starts with CDMI-DAC-".
 */
function passedThroughHeaders(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if (!name.toUpperCase().startsWith("CDMI-DAC-")) continue;
    // A field name is case-insensitive in HTTP and a JSON member name is not,
    // and the subclause does not say which form is carried; this server carries
    // the name in lower case, which is what ECR-074A proposes, and combines a
    // field that appears more than once as RFC 9110 describes.
    out[name.toLowerCase()] = Array.isArray(value) ? value.join(", ") : String(value);
  }
  return out;
}

export const SERVER_GENERATED_METADATA = [
  "cdmi_acount", "cdmi_mcount", "cdmi_size", "cdmi_ctime", "cdmi_mtime",
  "cdmi_atime",
];


/**
 * Checks the algorithm a cdmi_value_hash item names. The draft permits
 * a CDMI server to ignore an item it does not recognise; this one
 * reports the invalid field condition, so that a client is not left
 * believing a value was hashed when it was not.
 */
export function checkValueHash(metadata: Record<string, unknown>): void {
  const wanted = metadata.cdmi_value_hash;
  if (wanted === undefined || wanted === null || wanted === "") return;
  if (typeof wanted !== "string") {
    throw invalidField("metadata/cdmi_value_hash",
      "cdmi_value_hash names an algorithm and a length, as a JSON string");
  }
  if (VALUE_HASHES[wanted.toUpperCase()] === undefined) {
    throw invalidField("metadata/cdmi_value_hash",
      "%j is not an algorithm this CDMI server computes; the cdmi_value_hash " +
      "capability names the ones it does", wanted);
  }
}

/** The greatest number of values a queue object holds. */
export const QUEUE_MAXVALUES = 1024;
/** The largest single value a queue object holds, in octets. */
export const QUEUE_MAXSIZE = 1024 * 1024;
/** The largest total size of the values a queue object holds. */
export const QUEUE_MAXTOTALSIZE = 16 * 1024 * 1024;

/** The greatest length of an item name, in octets. */
const METADATA_MAXNAME = MAXNAME - "user.".length;

/**
 * Checks the user metadata of an object against the limits this
 * server applies. The size of an item is the size of its name and of
 * its value together, since both travel as an extended attribute.
 */
function checkMetadataLimits(metadata: Record<string, unknown>):
  { item: string; why: string; limit?: string; value?: string } | undefined {
  const names = Object.keys(metadata);
  if (names.length > METADATA_MAXITEMS) {
    return {
      item: "metadata",
      why: `this server holds at most ${METADATA_MAXITEMS} user metadata items for an object`,
      limit: "cdmi_metadata_maxitems", value: String(METADATA_MAXITEMS),
    };
  }
  let total = 0;
  for (const [k, v] of Object.entries(metadata)) {
    if (Buffer.byteLength(k, "utf8") > METADATA_MAXNAME) {
      return {
        item: k,
        why: `the name of a user metadata item is at most ${METADATA_MAXNAME} octets, ` +
          "so that it is presented as an extended attribute within the user namespace",
      };
    }
    const size = Buffer.byteLength(k, "utf8") +
      Buffer.byteLength(typeof v === "string" ? v : JSON.stringify(v) ?? "", "utf8");
    if (size > METADATA_MAXSIZE) {
      return {
        item: k,
        why: `a user metadata item is at most ${METADATA_MAXSIZE} octets`,
        limit: "cdmi_metadata_maxsize", value: String(METADATA_MAXSIZE),
      };
    }
    total += size;
  }
  // The limit this server publishes as cdmi_metadata_maxtotalsize.
  // Before 0.3 the S3 export's limit of 2048 octets was applied here, so a
  // CDMI write of more was refused while 1 MiB was advertised. The S3
  // export applies its own limit to what it presents.
  if (total > METADATA_MAXTOTALSIZE) {
    return {
      item: "metadata",
      why: `the user metadata of an object is at most ${METADATA_MAXTOTALSIZE} octets`,
      limit: "cdmi_metadata_maxtotalsize", value: String(METADATA_MAXTOTALSIZE),
    };
  }
  return undefined;
}

/** The levels of versioning, and what each counts as an update. */
/** The metadata items that ask for versioning, which a queue object has none of. */
export const VERSIONING_ITEMS = [
  "cdmi_versioning", "cdmi_versions_count", "cdmi_versions_age",
  "cdmi_versions_size",
];

export const VERSIONING_LEVELS = ["value", "user", "all"];

/**
 * The limits on retained versions a client may ask for. Each is the
 * greatest value this server accepts in the data system metadata item
 * of the same name, and is published as the capability of that name.
 */
export const VERSIONS_MAXCOUNT = 1000;
/** In seconds: ten years, which is longer than a limit is worth. */
export const VERSIONS_MAXAGE = 10 * 365 * 24 * 60 * 60;
/** In bytes. */
export const VERSIONS_MAXSIZE = 1 << 30;

const VERSION_LIMITS: [string, number][] = [
  ["cdmi_versions_count", VERSIONS_MAXCOUNT],
  ["cdmi_versions_age", VERSIONS_MAXAGE],
  ["cdmi_versions_size", VERSIONS_MAXSIZE],
];

/**
 * Checks the versioning items a client supplies. The level is one of
 * the three defined, and each limit is a non-negative integer no
 * greater than the capability of the same name reports.
 */
function checkVersioningItems(metadata: Record<string, unknown>):
  { item: string; why: string } | undefined {
  const level = metadata.cdmi_versioning;
  if (level !== undefined && level !== null && level !== "") {
    if (typeof level !== "string" || !VERSIONING_LEVELS.includes(level)) {
      return {
        item: "cdmi_versioning",
        why: `the level of versioning is ${VERSIONING_LEVELS.join(", ")}`,
      };
    }
  }
  for (const [item, most] of VERSION_LIMITS) {
    const v = metadata[item];
    if (v === undefined || v === null || v === "") continue;
    if (typeof v !== "string" || !/^(0|[1-9][0-9]*)$/.test(v)) {
      return { item, why: "the limit is a non-negative integer as a decimal string" };
    }
    if (Number(v) > most) {
      return {
        item,
        why: `this server accepts a limit of at most ${most}, and ${v} is greater`,
      };
    }
  }
  return undefined;
}

/**
 * The version-related storage system metadata of an object, which
 * threads the chain of versions. Each item holds an object ID, so a
 * client moves between the versions by reading them.
 */
function versionMetadata(store: Store, node: Node): Record<string, unknown> {
  const m = store.meta(node);
  const out: Record<string, unknown> = {};
  const idOf = (n: Node) => store.meta(n).objectID;
  if (m.versionOf !== null) {
    // A version. It holds the object it belongs to, the current
    // version, the version it was created from, the versions created
    // from it, and the oldest.
    const owner: Node = { id: m.versionOf, isContainer: false };
    const om = store.meta(owner);
    out.cdmi_version_object = om.objectID;
    if (om.currentVersion !== null) {
      out.cdmi_version_current = idOf({ id: om.currentVersion, isContainer: false });
    }
    if (m.versionParent !== null) {
      out.cdmi_version_parent = idOf({ id: m.versionParent, isContainer: false });
      out.cdmi_version_oldest = store.oldestVersions(owner).map(idOf);
    } else {
      // The oldest version holds no parent and no oldest of its own.
      out.cdmi_version_children = store.versionChildren(node).map(idOf);
      return out;
    }
    if (m.currentVersion === null && om.currentVersion !== node.id) {
      out.cdmi_version_children = store.versionChildren(node).map(idOf);
    }
    if (om.currentVersion === node.id) delete out.cdmi_version_children;
    return out;
  }
  if (m.currentVersion === null) return out;
  // A version-enabled data object: the current version and the oldest.
  out.cdmi_version_current = idOf({ id: m.currentVersion, isContainer: false });
  const oldest = store.oldestVersions(node);
  if (oldest.length > 0) out.cdmi_version_oldest = oldest.map(idOf);
  return out;
}

/**
 * Whether a request marks the object as being created or updated by a
 * series of requests. The object is then not complete, and its
 * completionStatus field says so until a request completes it.
 */
function isPartial(req: IncomingMessage): boolean {
  return String(req.headers["x-cdmi-partial"] ?? "").toLowerCase() === "true";
}

/**
 * The metadata a domain object representation supplies, checked
 * against the items this document defines for one.
 */
/**
 * The privilege the cdmi_domain_kms item requires: "A CDMI server shall report
 * the forbidden condition where a principal that does not hold the
 * domain_kms_admin privilege creates or updates this item" (Annex D). The item
 * states which key management servers hold the credentials of every object the
 * domain owns, so setting it decides where a secret goes.
 */
/**
 * Claims each scope a domain declares, at the key management server it names.
 * "A CDMI server claims a scope before it resolves a credential reference
 * against it" (the Scope binding subclause), and the public key of the
 * binding key is retained so that a later verification is against a key this
 * server held before.
 *
 * Where a scope is claimed by another CDMI server, the scope claimed
 * condition is reported and the item is not stored: a domain that names a
 * scope it may not use would otherwise resolve nothing.
 */
async function claimScopesOf(servers: KeyManagement[], store: Store,
  supplied: Record<string, unknown>): Promise<void> {
  const descriptors = descriptorsOf(supplied);
  for (const [label, descriptor] of Object.entries(descriptors)) {
    const server = servers.find((s) => s.label === label);
    // A label naming no configured server is a configuration matter and not
    // a fault of the request: the item records where credentials live, and a
    // CDMI server that cannot reach that key management server resolves
    // nothing against it and says so when it tries.
    if (server === undefined) continue;
    const scope = descriptor.scope ?? "";
    const claim = await claimScope(server, scope, await server.identifier());
    store.retainBindingKey(label, scope, claim.publicKey);
  }
}

/**
 * The cdmi_domain_kms item names the key management servers where a domain's
 * credentials are held, and it means something only to a CDMI server that
 * resolves credential references: one that publishes cdmi_kms. A CDMI server
 * run without a key management server publishes no such capability, and so
 * does not accept the item that would configure it; it reports the capability
 * not present condition, naming cdmi_kms, rather than storing an item it can
 * never act on.
 *
 * A value supplied unchanged is accepted, so that a CDMI client reading a
 * domain object and writing it back is not refused for an item stored before
 * the key management server was removed from the configuration.
 */
function checkKmsOffered(supplied: Record<string, unknown>, servers: KeyManagement[],
  held: Record<string, unknown> = {}): void {
  if (servers.length > 0 || !("cdmi_domain_kms" in supplied)) return;
  if (JSON.stringify(supplied.cdmi_domain_kms ?? null) === JSON.stringify(held.cdmi_domain_kms ?? null)) return;
  throw capabilityNotPresent("cdmi_kms", "/cdmi_capabilities/",
    "this CDMI server is run without a key management server, so it resolves no credential " +
    "reference and does not accept the cdmi_domain_kms item that would name one");
}

/**
 * A cdmi_domain_kms item written back as it was read keeps what the read did
 * not report. A read omits the endpoint, version and scope of a key management
 * server offering no client registration, so a CDMI client that reads a domain
 * object and writes it back supplies the item without them; taken literally,
 * that would change the scope the domain claims. Where a descriptor supplied
 * omits a field the read would not have reported, and the one held gives it,
 * the held value is kept. A field the read reports, or one the client supplies,
 * is taken as supplied.
 */
function restoreUnreportedKms(supplied: Record<string, unknown>, held: Record<string, unknown> = {}): void {
  const given = supplied.cdmi_domain_kms as Record<string, Record<string, unknown>> | undefined;
  const kept = held.cdmi_domain_kms as Record<string, Record<string, unknown>> | undefined;
  if (given === undefined || given === null || typeof given !== "object" || kept === undefined) return;
  const out: Record<string, unknown> = {};
  for (const [label, d] of Object.entries(given)) {
    const was = kept[label];
    if (d === null || typeof d !== "object" || was === undefined || was.client_registration === "true" ||
        d.client_registration === "true") {
      out[label] = d;
      continue;
    }
    const merged = { ...d };
    for (const f of ["endpoint", "version", "scope"]) {
      if (!(f in merged) && f in was) merged[f] = was[f];
    }
    out[label] = merged;
  }
  supplied.cdmi_domain_kms = out;
}

/**
 * "Such a reassignment changes the key management server and the scope in which
 * every credential reference those objects carry resolves ... so a CDMI server
 * shall report the forbidden condition where a principal that does not hold the
 * cross_domain privilege creates or updates this item" (Annex D). An item
 * supplied unchanged is not a change of it.
 */
function checkReassignPrivilege(supplied: Record<string, unknown>, who: Principal,
  held: Record<string, unknown> = {}): void {
  if (!("cdmi_domain_delete_reassign" in supplied)) return;
  if (supplied.cdmi_domain_delete_reassign === held.cdmi_domain_delete_reassign) return;
  if (supplied.cdmi_domain_delete_reassign !== null && typeof supplied.cdmi_domain_delete_reassign !== "string") {
    throw invalidField("metadata/cdmi_domain_delete_reassign", "the item is the namespace path of a domain object");
  }
  if (!who.privileges.includes("cross_domain")) {
    throw forbidden("setting cdmi_domain_delete_reassign requires the cross_domain privilege, which %s does not hold",
      who.name);
  }
}

/**
 * The cdmi_domain_auth item (revision 269): "A CDMI server shall report the
 * forbidden condition where a principal that does not hold the domain_auth_admin
 * privilege creates or updates this item", then the descriptor of
 * tbl_cdmi_auth_descriptor, checked field by field.
 *
 * A valid descriptor is then refused: the item names "The directory against
 * which a CDMI server authenticates a principal of this domain", and this server
 * does not yet authenticate against one (a Kerberos ticket, an LDAP bind, an
 * NTLMv2 pass-through), so storing it would claim what is not done. Revision 269
 * defines no capability by which a server says it does not support delegated
 * authentication (ECR-134A); the capability not present condition is reported,
 * naming the capability that ECR proposes, cdmi_domain_auth.
 */
function checkDomainAuth(supplied: Record<string, unknown>, who: Principal, base: string, supported: boolean,
  held: Record<string, unknown> = {}): void {
  if (!("cdmi_domain_auth" in supplied)) return;
  const v = supplied.cdmi_domain_auth;
  if (JSON.stringify(v ?? null) === JSON.stringify(held.cdmi_domain_auth ?? null)) return;
  if (!who.privileges.includes("domain_auth_admin")) {
    throw forbidden("setting cdmi_domain_auth requires the domain_auth_admin privilege, which %s does not hold", who.name);
  }
  if (v === null) return;
  const at = (f: string) => `metadata/cdmi_domain_auth${f === "" ? "" : "/" + f}`;
  if (typeof v !== "object" || Array.isArray(v)) throw invalidField(at(""), "cdmi_domain_auth is a JSON object");
  const d = v as Record<string, unknown>;
  const known = ["realm", "service_principal", "service_key_id", "uris", "base_dn", "ca_cert_id", "machine_account_id",
    "principal_attribute", "group_attribute", "protocols",
    // Revision 298: where the realm's key distribution centres are, and which
    // attribute each member of cdmi_domain_userinfo is taken from. Revision
    // 302: the base URI the domain's homes are held beneath.
    "kdcs", "userinfo_attributes", "home_base",
    // The claims of a bearer token that name the principal and its groups.
    // The domains clause has resolved a bearer token against the directory
    // "from the claim the principal_claim member of the cdmi_domain_auth
    // metadata item names" since revision 298, and this list never admitted
    // either name: a descriptor stating how to resolve a token — the one thing
    // the clause requires the member for — was refused as invalid.
    "principal_claim", "groups_claim"];
  for (const k of Object.keys(d)) if (!known.includes(k)) throw invalidField(at(k), "%j is not a field of a directory descriptor", k);
  for (const k of ["realm", "service_principal", "base_dn"]) {
    if (typeof d[k] !== "string" || d[k] === "") throw invalidField(at(k), "the %j field is a non-empty JSON string, and is mandatory", k);
  }
  for (const k of ["principal_attribute", "group_attribute", "principal_claim", "groups_claim"]) {
    if (k in d && (typeof d[k] !== "string" || d[k] === "")) throw invalidField(at(k), "the %j field is a non-empty JSON string", k);
  }
  readReference(at("service_key_id"), d.service_key_id);
  for (const k of ["ca_cert_id", "machine_account_id"]) if (k in d) readReference(at(k), d[k]);
  // "A URL shall have the scheme ldaps, or the scheme ldap where the CDMI server
  // establishes TLS by the StartTLS operation".
  if (!Array.isArray(d.uris) || d.uris.length === 0) throw invalidField(at("uris"), "the uris field is a non-empty array of LDAP URLs");
  for (const u of d.uris) {
    let url: URL | undefined;
    try { url = typeof u === "string" ? new URL(u) : undefined; } catch { url = undefined; }
    if (url === undefined || (url.protocol !== "ldaps:" && url.protocol !== "ldap:")) {
      throw invalidField(at("uris"), "%j is not an LDAP URL with the scheme ldaps or ldap", u);
    }
  }
  // "The key distribution centres of the realm, each a host name or address
  // with an optional port, which a CDMI server tries in the order given."
  if ("kdcs" in d) {
    const kdcs = d.kdcs;
    if (!Array.isArray(kdcs) || kdcs.length === 0 ||
        kdcs.some((k) => typeof k !== "string" || !/^[A-Za-z0-9.:[\]_-]+$/.test(k))) {
      throw invalidField(at("kdcs"), "the kdcs field is a non-empty array of hosts, each with an optional port");
    }
  }
  // "The base URI beneath which the homes of the principals of this domain
  // are held, an absolute URI with the scheme https ending with /."
  if ("home_base" in d) {
    const base = d.home_base;
    let u: URL | undefined;
    try { u = typeof base === "string" ? new URL(base) : undefined; } catch { u = undefined; }
    if (u === undefined || u.protocol !== "https:" || !String(base).endsWith("/")) {
      throw invalidField(at("home_base"), "home_base is an absolute URI of the scheme https, ending with a solidus");
    }
  }
  // "A map from the names of members of [the cdmi_domain_userinfo table] to
  // the attributes of a directory entry from which the CDMI server takes
  // their values."
  if ("userinfo_attributes" in d) {
    const map = d.userinfo_attributes;
    if (map === null || typeof map !== "object" || Array.isArray(map)) {
      throw invalidField(at("userinfo_attributes"), "the userinfo_attributes field is a JSON object");
    }
    for (const [member, attribute] of Object.entries(map as Record<string, unknown>)) {
      // "A member named \"home\" takes the home of the principal, which the
      // attribute holds as one value" (revision 302): it is not a member of
      // the description of a principal, and the map takes it (ECR-146A).
      // "The names this member takes are the names of the members of [the
      // cdmi_domain_userinfo table] other than home_base and home_path,
      // together with home, which that table does not define and which this
      // member defines. A CDMI server shall report the invalid field condition
      // where this member names home_base or home_path" (revision 365, closing
      // ECR-146A). home_base is set by the member of that name and "is set by
      // no other means", and home_path is divided out of home; a map naming
      // either was a second provision able to set the same member.
      if (member === "home_base" || member === "home_path") {
        throw invalidField(at("userinfo_attributes"),
          "%j is not taken from a directory attribute: home_base is set by the member of that name, " +
          "and home_path is divided out of the value of %j", member, "home");
      }
      if (member !== "home" && !USERINFO_MEMBERS.includes(member)) {
        throw invalidField(at("userinfo_attributes"), "%j is not a member of the description of a principal", member);
      }
      if (typeof attribute !== "string" || attribute === "") {
        throw invalidField(at("userinfo_attributes"), "the attribute of %j is a non-empty JSON string", member);
      }
    }
  }
  if ("protocols" in d && (!Array.isArray(d.protocols) || d.protocols.some((p) => typeof p !== "string"))) {
    throw invalidField(at("protocols"), "the protocols field is an array of the type names of export types");
  }
  // Where this server has no key management server, it cannot resolve the
  // references the descriptor carries, so it does not support the item.
  if (!supported) {
    // Annex B defines cdmi_domain_auth in the system-wide table, so the
    // capability object that publishes it is the one at the root of the
    // hierarchy. This named the domain capability object until 0.104, where a
    // CDMI client following the URI of the refusal to see which capability it
    // had run into found no such name.
    throw capabilityNotPresent("cdmi_domain_auth", `${base}cdmi_capabilities/`,
      "this CDMI server resolves the references of a directory descriptor at a key management server, and none is configured");
  }
}

function checkDomainKmsPrivilege(supplied: Record<string, unknown>, who: Principal,
  held: Record<string, unknown> = {}): void {
  if (!("cdmi_domain_kms" in supplied)) return;
  if (JSON.stringify(supplied.cdmi_domain_kms ?? null) === JSON.stringify(held.cdmi_domain_kms ?? null)) return;
  if (who.privileges.includes("domain_kms_admin")) return;
  throw forbidden("setting cdmi_domain_kms requires the domain_kms_admin privilege, which %s does not hold", who.name);
}

function domainMetadata(body: Record<string, unknown>, held?: Record<string, unknown>,
  mayAdministerKms = false, merging = false): Record<string, unknown> {
  const v = body.metadata;
  if (v === undefined || v === null) return {};
  if (typeof v !== "object" || Array.isArray(v)) {
    throw malformed("the metadata field holds a JSON object");
  }
  const md = v as Record<string, unknown>;
  const enabled = md.cdmi_domain_enabled;
  if (enabled !== undefined && enabled !== "true" && enabled !== "false") {
    throw invalidField("metadata/cdmi_domain_enabled",
      'cdmi_domain_enabled is "true" or "false"');
  }
  // What a read did not report is restored before the item is checked, so
  // that an item written back as read is complete.
  // "Where an update supplies a descriptor omitting a field that is not
  // reported to the principal supplying it, the CDMI server shall retain the
  // value held" (revision 297; ECR-104B). A principal holding
  // domain_kms_admin is shown those fields, so an omission by that principal
  // removes them; before 0.63 they were restored for every principal.
  // "Where an update supplies a descriptor omitting a field that is not
  // reported to the principal supplying it, the CDMI server shall retain the
  // value held" (ECR-104B). The rule is for a replacement, where an omission
  // would otherwise remove; in a merge an omission removes nothing, so there
  // is nothing to restore and restoring would be indistinguishable from the
  // merge itself.
  if (held !== undefined && !mayAdministerKms && !merging) restoreUnreportedKms(md, held);
  if (md.cdmi_domain_kms !== undefined) checkDescriptors("metadata/cdmi_domain_kms", md.cdmi_domain_kms);
  // The discovery bootstrap (ECR-224A). An item a deployment does not offer
  // never reaches here: userMetadata refuses the name itself, so this checks
  // the contents of an item that is admitted. A null is a removal and is not
  // an item to check.
  if (md.cdmi_domain_doh !== undefined && md.cdmi_domain_doh !== null) {
    // Where the update is a merge, what is checked is the item the merge
    // leaves behind and not the partial the client supplied: a request naming
    // one member of an item already stored is a change to that member, and
    // checking the partial alone would refuse it for want of the members it
    // did not mention. The merge is computed and thrown away — md is left as
    // supplied, so that the nulls it carries still remove what they name when
    // the item is stored. A replacement supplies the whole item, so there the
    // partial is the item.
    const supplied = md.cdmi_domain_doh;
    const base = merging ? held?.cdmi_domain_doh : undefined;
    const objects = (v: unknown): v is Record<string, unknown> =>
      typeof v === "object" && v !== null && !Array.isArray(v);
    const effective = objects(base) && objects(supplied) ? mergePatch(base, supplied) : supplied;
    const fault = dohItemFault(effective);
    if (fault !== undefined) {
      const [member, why] = fault;
      throw invalidField(`metadata/cdmi_domain_doh${member === "" ? "" : `/${member}`}`, "%s", why);
    }
  }
  return md;
}

/** The level of versioning enabled for an object, where any is. */
function versioningLevel(m: StoredMeta): string | undefined {
  const v = m.metadata.cdmi_versioning;
  return typeof v === "string" && VERSIONING_LEVELS.includes(v) ? v : undefined;
}

/** RFC 7396 merge patch, which is what null means in a representation. */
export function mergePatch(target: Record<string, unknown>,
  patch: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...target };
  for (const [k, v] of Object.entries(patch)) {
    if (v === null) {
      delete out[k];
    } else if (typeof v === "object" && !Array.isArray(v)) {
      // RFC 7396 recurses whatever the target member is: "if Target is not
      // an Object, Target = {}", and then a null member of the patch removes
      // a name that is not there, which adds nothing. Taking the patch value
      // wholesale where the target holds no object, as this did before 0.84,
      // stores every null it contains — and a null is no metadata value at
      // any depth (Annex A). It also made a removal at depth disappear
      // before the merge could act on it, because the caller stripped the
      // nulls to keep them out of the store (weedmi ECR-188B).
      const into = typeof out[k] === "object" && out[k] !== null && !Array.isArray(out[k])
        ? out[k] as Record<string, unknown>
        : {};
      out[k] = mergePatch(into, v as Record<string, unknown>);
    } else {
      out[k] = v;
    }
  }
  return out;
}

/**
 * A CDMI request body, which is a JSON document. "JSON text shall be encoded
 * using UTF-8" (RFC 8259), so a body that is not valid UTF-8 is not a JSON
 * document and is the malformed request condition. This server decoded the
 * octets with Buffer.toString, which replaces an invalid sequence with
 * U+FFFD and never fails, so a body carrying invalid UTF-8 parsed and the
 * replacement character was stored in place of what was sent (weedmi
 * BHTP-013). The path of a request was already checked; the body was not.
 */
function parseBodyJson(raw: Buffer): Record<string, unknown> {
  if (!isUTF8(raw)) {
    throw malformed("the message body is not valid UTF-8, and a JSON document is " +
      "encoded in UTF-8");
  }
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(raw.toString("utf8")) as Record<string, unknown>;
  } catch {
    throw malformed("the message body is not valid JSON");
  }
  // The octets of the value field, as they arrived. A value whose transfer
  // encoding is "json" is stored as those octets and not as a re-serialization
  // of them, which revision 365 requires and which cdmi_size, valuerange and
  // every range of the value are counted over (ECR-153A). They are carried on
  // the parsed body rather than through the signature of every operation that
  // reads one, and are not a member of it.
  if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
    const span = jsonMemberSpan(raw, "value");
    if (span !== undefined) {
      Object.defineProperty(parsed, RAW_VALUE, {
        value: raw.subarray(span.start, span.end), enumerable: false, configurable: true,
      });
    }
  }
  return parsed;
}

/** Where the octets of the value field, as the CDMI client sent them, are kept. */
const RAW_VALUE = Symbol("the octets of the value field as received");

/** Those octets, where this body carried a value field and they were recorded. */
function rawValueOf(body: Record<string, unknown>): Buffer | undefined {
  const held = (body as Record<symbol, unknown>)[RAW_VALUE];
  return Buffer.isBuffer(held) ? held : undefined;
}

/**
 * The span of the bytes of one member of a top-level JSON object, within the
 * document those bytes came from.
 *
 * The document has already been parsed, so this scan need only follow a text
 * it knows to be valid JSON and need not diagnose one that is not. It works on
 * the bytes: every structural character of JSON is ASCII, and no byte of a
 * multi-byte UTF-8 sequence is ASCII, so a byte scan and a character scan
 * agree on where each value begins and ends, and a byte offset is what the
 * caller needs.
 */
function jsonMemberSpan(raw: Buffer, member: string): { start: number; end: number } | undefined {
  const isWs = (b: number): boolean => b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0d;
  let i = 0;
  const ws = (): void => { while (i < raw.length && isWs(raw[i]!)) i += 1; };
  const skipString = (): void => {
    i += 1;
    while (i < raw.length) {
      const b = raw[i]!;
      if (b === 0x5c) { i += 2; continue; }
      i += 1;
      if (b === 0x22) return;
    }
  };
  const skipValue = (): void => {
    ws();
    const b = raw[i];
    if (b === 0x22) return skipString();
    if (b === 0x7b || b === 0x5b) {
      const close = b === 0x7b ? 0x7d : 0x5d;
      i += 1;
      for (;;) {
        ws();
        if (i >= raw.length) return;
        const c = raw[i]!;
        if (c === close) { i += 1; return; }
        if (c === 0x2c || c === 0x3a) { i += 1; continue; }
        skipValue();
      }
    }
    // A number, or true, false or null: it ends where a structural character
    // or a space begins.
    while (i < raw.length && !isWs(raw[i]!) && raw[i] !== 0x2c && raw[i] !== 0x7d && raw[i] !== 0x5d) i += 1;
  };
  ws();
  if (raw[i] !== 0x7b) return undefined;
  i += 1;
  for (let members = 0; members < 4096; members += 1) {
    ws();
    if (i >= raw.length || raw[i] === 0x7d) return undefined;
    if (raw[i] === 0x2c) { i += 1; continue; }
    if (raw[i] !== 0x22) return undefined;
    const from = i;
    skipString();
    let name: string;
    try {
      name = JSON.parse(raw.subarray(from, i).toString("utf8")) as string;
    } catch {
      return undefined;
    }
    ws();
    if (raw[i] !== 0x3a) return undefined;
    i += 1;
    ws();
    const start = i;
    skipValue();
    if (name === member) return { start, end: i };
  }
  return undefined;
}

/**
 * The value transfer encoding of a range of a value, determined by the octets
 * the CDMI server is about to return (revision 365, data object
 * representation):
 *
 * * "utf-8", where the value transfer encoding of the object is "utf-8" and
 *   the first octet of the range begins a character and the octet following
 *   the range begins a character or the range ends the value;
 * * "json", where the value transfer encoding of the object is "json" and the
 *   octets of the range are a valid JSON value; and
 * * "base64" in every other case.
 *
 * `after` is the octet following the range, or undefined where the range ends
 * the value. A CDMI server "shall not adjust a range so that a test succeeds",
 * so nothing here changes what is returned; it reports what is there.
 *
 * The "json" case is narrowed to a JSON object. The "value" field of a data
 * object representation holds a string or a JSON object and holds no other
 * JSON value, so a range whose octets are a valid JSON array, number, string,
 * boolean or null cannot be carried in that field at all, and this server
 * reports "base64" for one. That is ECR-204A, and this is where it bites.
 */
function rangeEncoding(vte: string | undefined, bytes: Buffer,
  after: Buffer | undefined): "utf-8" | "json" | "base64" {
  // A continuation octet is 10xxxxxx: one at the first position of the range
  // means the range begins inside a character, and one at the position
  // following means the range ends inside one.
  const continues = (b: Buffer | undefined): boolean =>
    b !== undefined && b.length > 0 && (b[0]! & 0xc0) === 0x80;
  if (vte === "utf-8") {
    return !continues(bytes) && !continues(after) && isUTF8(bytes) ? "utf-8" : "base64";
  }
  if (vte === "json" && isUTF8(bytes)) {
    try {
      const parsed: unknown = JSON.parse(bytes.toString("utf8"));
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) return "json";
    } catch {
      // Not a JSON value, so the octets travel as base 64.
    }
  }
  return "base64";
}

/**
 * Bytes to be placed in a JSON document exactly as they are, rather than
 * re-serialized from a parsed form.
 *
 * "The value of a data object whose value transfer encoding is `json` is the
 * octets of the JSON text the CDMI server received, stored unchanged ... and
 * [the CDMI server] shall neither normalize nor re-serialize them thereafter.
 * It returns those octets when the value is read" (revision 365). A value put
 * through JSON.parse and JSON.stringify is re-serialized: the spelling of its
 * numbers, its whitespace, the form of its escapes and the order of any
 * members whose names are decimal integers all change.
 */
class Verbatim {
  readonly bytes: Buffer;
  /** What stands in the serialized document until the bytes replace it. */
  readonly token = `\u0000verbatim:${randomUUID()}\u0000`;

  constructor(bytes: Buffer) {
    this.bytes = bytes;
  }

  toJSON(): string {
    return this.token;
  }
}

function isUTF8(b: Buffer): boolean {
  const s = b.toString("utf8");
  return Buffer.from(s, "utf8").equals(b);
}

/**
 * The body of each request, read once: delegated access control reads a CDMI
 * body to tell a change of a value from a change of metadata, before the
 * operation reads it again.
 */
const bodies = new WeakMap<IncomingMessage, Promise<Buffer>>();
function readBody(req: IncomingMessage): Promise<Buffer> {
  let held = bodies.get(req);
  if (held === undefined) {
    held = readBodyOnce(req);
    bodies.set(req, held);
  }
  return held;
}

async function readBodyOnce(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  await new Promise<void>((resolve, reject) => {
    req.on("data", (c: Buffer) => {
      total += c.length;
      if (total > MAX_BODY) {
        reject(new Condition(413, "limit-exceeded", "A limit would be exceeded.",
          `seedmi accepts a message body of up to ${MAX_BODY} bytes`));
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve());
    req.on("error", reject);
  });
  return Buffer.concat(chunks);
}


/**
 * The path of a request URI, without the query component. A query may
 * carry a selection and could in principle carry something else, so
 * the log holds the path alone.
 */
export function pathOnly(url: string): string {
  const q = url.indexOf("?");
  return q < 0 ? url : url.slice(0, q);
}
