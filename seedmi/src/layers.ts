// The layering engine of clause 9. An importing container object presents a
// stack of layers: the entries of its imports field, uppermost first. This
// file decides what is presented at a name, which layer holds it, where an
// operation that changes an object is directed, and what condition is
// reported where no layer will perform it.
//
// The rules this implements, with the revision that settled each:
//
//   - the uppermost layer holding a name, in any form, alone determines
//     what is presented there; a data object conceals a container object of
//     that name below it, and a lower container object with an imports
//     field of its own is concealed (38);
//   - a merged container object takes its fields, metadata and object ID
//     from that uppermost holder (38);
//   - an operation denied at a layer above the write target reports
//     conflict/import-layer, naming the entry that denied it (39);
//   - a write target that is disabled reports conflict/import-disabled, and
//     one whose source cannot be reached reports source unavailable (39);
//   - while an entry whose required field is "true" is not active, the
//     importing object presents nothing (38);
//   - a cycle is any import whose resolution requires resolving the same
//     entry again (34).

import { parseACE, unsupportedIn } from "./acl.ts";
import { isCondition } from "./problems.ts";
import {
  ASSIGNED, SNAPSHOTS, isAssigned, reservedName, type Node, type Store,
} from "./store.ts";
import {
  type DirRef, type ObjRef, nodeOf, presentableEntry, viewOf,
} from "./objects.ts";
import { ATTR_DIRECTORY, BufferImage, FAT } from "./fat.ts";
import { NF4DIR } from "./nfs.ts";
import { type NfsSource, type NfsSourceOptions, nfsSource } from "./nfs-import.ts";
import {
  smbCredential, type SmbSource, type SmbSourceOptions, smbSource,
} from "./smb-import.ts";
import { parseSmbURI } from "./imports.ts";
import { PartitionImage, partitions } from "./partition.ts";
import { remoteSource } from "./remote.ts";
import { createHash } from "node:crypto";
import { type ExchangeOptions, delegatedToken } from "./oauth.ts";
import type { Principal } from "./acl.ts";

/**
 * Where a token is exchanged for one the import source will accept.
 * This is configuration of the server rather than of an object, so it
 * is held here and not in the namespace.
 */
let delegation: ExchangeOptions | undefined;

export function setDelegation(opts: ExchangeOptions | undefined): void {
  delegation = opts;
  setDelegationAvailable(opts !== undefined);
}
import {
  type ImportEntry, isDisabled, isRequired, isWriteTarget, localImportPath,
  parseImports, parseNfsURI, preservesObjectID, setDelegationAvailable,
} from "./imports.ts";
import {
  type Condition, type Problem, conflict, conflictImportLayer, forbidden, importDisabled,
  notFound, problem, seedmiProblem, sourceUnavailable,
} from "./problems.ts";

/** A CDMI server may limit the depth to which it processes nested imports. */
export const MAX_IMPORT_DEPTH = 8;

/** An entry of the importsProvided field (9.3). */
export interface Provided {
  type: string;
  import_definition_uri: string;
  import_uri?: string;
  /**
   * Whether this import is in delegated identity mode, which decides the
   * access control list reported for an object presented through it: "the
   * access control lists reported for the object shall be those the import
   * source reports ... where the import is in delegated identity mode ...
   * Where it is not, or where the import is in service identity mode, the
   * access control lists of the importing object shall apply."
   */
  delegated?: boolean;
}

/** One layer of a presented namespace. */
export interface Layer {
  /** The container object whose children this layer contributes. */
  dir: DirRef;
  /**
   * The position of this layer in the stack. A nested import contributes
   * several layers, which sort within the entry that imported them, so the
   * rank has one element per level of nesting.
   */
  rank: number[];
  /** The imports through which this layer is reached, uppermost first. */
  via: Provided[];
  /** Whether this layer is reached through any import at all. */
  imported: boolean;
  /** Whether an object of this layer is presented without an object ID. */
  hideIDs: boolean;
  /** Whether this layer can be changed at all. An image import that is
   * not write enabled presents a read-only layer. */
  readOnly: boolean;
}

/** The state of one entry of an imports field, as reported. */
export interface EntryState {
  entry: ImportEntry;
  index: number;
  active: boolean;
  problems: Problem[];
  /** The object ID of the import source, for an image import. */
  sourceObjectID?: string;
}

/** A presented container object. */
export interface View {
  /** Its namespace path, ending with a solidus. */
  ns: string;
  /** The uppermost holder of its name, which supplies its fields. */
  held: DirRef;
  /** Its layers, uppermost first. */
  layers: Layer[];
  /** Whether it has an imports field of its own. */
  importing: boolean;
  /** Its entries, where it is importing. */
  entries: EntryState[];
  /** The layer of the parent's stack through which it was reached. */
  objLayer: Layer;

  /** The write target container object, where it already exists. */
  writeNode?: Node;
  /** Where the write target is a directory of an imported file system. */
  writeImage?: { fs: FAT; cluster: number };
  /** The image directory within which this view's write target is made. */
  writeImageParent?: { fs: FAT; cluster: number };
  /** Where it does not, the view and name under which to create it. */
  writeParent?: View;
  writeName?: string;
  /** An importing container object whose write target lies within it. */
  writeDelegate?: View;
  /** The rank of the write target within this stack. */
  writeRank?: number[];
  /** Why there is no write target, for the detail of a condition. */
  writeWhy: string;
  /** The condition to report instead of "forbidden" where one applies. */
  writeUnavail?: Condition;

  /**
   * Set where a layer above the write target holds a container object of
   * this name. That layer denies a change to the merged container object,
   * and the denial is not remedied.
   */
  upper: boolean;

  /** Set where a required entry is not active: nothing is presented. */
  unavail?: Condition;

  /**
   * The container object whose access control list governs the objects
   * of a layer that carries none of its own: an imported file system, or
   * the namespace of another CDMI server. It is the container object on
   * which the import entry is placed.
   */
  importGovernor?: Node;
}

/** Compares two ranks. Lower sorts uppermost. */
export function rankCmp(a: number[], b: number[]): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

/** A name seedmi presents. Reserved names are not presented. */
export function presentable(name: string): boolean {
  // A segment of a namespace path contains neither a solidus nor a question
  // mark. It may contain a "#": "a character that RFC 3986 reserves appears in
  // it as itself. Where a namespace path is placed in a URI, every such
  // character is percent-encoded ... so that a segment containing a "#"
  // addresses the object it names rather than introducing a fragment"
  // (revision 211, unchanged in 221). This server refused such a name before.
  return name !== "" && !reservedName(name) &&
    !name.includes("/") && !name.includes("?");
}

const importProblem = (type: string, title: string, detail: string,
  members: Record<string, unknown> = {}): Problem =>
  problem(`imports/${type}`, title, detail, members);

/**
 * The file systems of image imports, keyed by the object ID and the
 * version of the source, so that a value is interpreted once rather than
 * on every request, and a change to the source is picked up because the
 * version moves. A few are kept; the least recently used is dropped.
 */
export interface OpenImage {
  fs: FAT;
  /** The buffer the file system is interpreted in. */
  image: BufferImage;
  /** The data object whose value it is. */
  source: Node;
  /** Where the file system begins within that value. */
  base: number;
}

const openImages = new Map<string, OpenImage>();
const MAX_OPEN_IMAGES = 4;

/** The file systems a view's image layers were opened from. */
const imagesOfFS = new Map<FAT, OpenImage>();

/** What a file system was opened from, for writing changes back. */
export function openImageOf(fs: FAT): OpenImage | undefined {
  return imagesOfFS.get(fs);
}

/**
 * Writes back the parts of an image that have changed, and moves the
 * version of the source so that the next request re-reads nothing it
 * need not and sees the change.
 */
export async function flushImage(store: Store, fs: FAT): Promise<void> {
  const open = imagesOfFS.get(fs);
  if (!open || !open.image.hasDirty) return;
  for (const { from, to } of open.image.takeDirty()) {
    await store.writeValue(open.source, from, open.image.buffer.subarray(from, to));
  }
}

function cacheImage(key: string, open: OpenImage): FAT {
  openImages.delete(key);
  openImages.set(key, open);
  imagesOfFS.set(open.fs, open);
  while (openImages.size > MAX_OPEN_IMAGES) {
    const oldest = openImages.keys().next().value as string | undefined;
    if (oldest === undefined) break;
    const dropped = openImages.get(oldest);
    if (dropped) imagesOfFS.delete(dropped.fs);
    openImages.delete(oldest);
  }
  return open.fs;
}

function cachedImage(key: string): FAT | undefined {
  const open = openImages.get(key);
  if (open) cacheImage(key, open); // it becomes the most recently used
  return open?.fs;
}

/** Forgets every open image, which a test does between stores. */
export function forgetImages(): void {
  openImages.clear();
  imagesOfFS.clear();
}

/** The child of a layer's directory by name, of either kind. */
async function lookupIn(store: Store, dir: DirRef, name: string):
  Promise<{ ref: ObjRef; isContainer: boolean } | undefined> {
  if (dir.kind === "store") {
    const n = store.tryLookup(dir.node, name);
    return n ? { ref: { kind: "store", node: n }, isContainer: n.isContainer } : undefined;
  }
  if (dir.kind === "remote") {
    // The children field says which form the name takes there, so one
    // listing settles whether it is a container object without asking
    // for the object itself.
    let kids: string[];
    try {
      kids = await dir.src.children(dir.path);
    } catch {
      return undefined;
    }
    const asContainer = kids.includes(name + "/");
    if (!asContainer && !kids.includes(name)) return undefined;
    const path = dir.path + name + (asContainer ? "/" : "");
    try {
      const rep = await dir.src.rep(path);
      // "An import shall not present an object whose access control list
      // contains such a mask bit or flag, and the CDMI server shall report for
      // that object the condition ... that an access control list is not
      // supported" (revision 269).
      const unsupported = unsupportedAclOf(rep.metadata?.cdmi_acl, asContainer);
      if (unsupported !== undefined) {
        dir.src.declined.set(path, {
          type: "https://www.snia.org/cdmi/problems/imports/acl-not-supported",
          title: "An object is not presented, its access control list not being supported.",
          detail: `${path} is not presented: its access control list names ${unsupported}, which this server does not support`,
        });
        return undefined;
      }
      dir.src.declined.delete(path);
      return {
        ref: { kind: "remote", src: dir.src, path, rep },
        isContainer: asContainer,
      };
    } catch {
      return undefined;
    }
  }
  if (dir.kind === "fs") {
    const entry = await dir.src.entry(dir.path + name).catch(() => undefined);
    if (!entry) return undefined;
    const isContainer = entry.type === NF4DIR;
    return {
      // The path is the one the entry names, which is the target where
      // a symbolic link was resolved.
      ref: {
        kind: "fs",
        src: dir.src,
        path: entry.at + (isContainer ? "/" : ""),
        entry,
      },
      isContainer,
    };
  }
  const e = await dir.fs.find(dir.cluster, name);
  if (!e || !presentableEntry(e)) return undefined;
  return {
    ref: { kind: "image", fs: dir.fs, dir: dir.cluster, entry: e },
    isContainer: (e.attr & ATTR_DIRECTORY) !== 0,
  };
}

/** The names a layer's directory holds, of either kind. */
async function childrenOf(store: Store, dir: DirRef):
  Promise<{ name: string; isContainer: boolean; reference?: string }[]> {
  if (dir.kind === "store") {
    return store.children(dir.node).map((c) => ({
      name: c.name,
      isContainer: c.node.isContainer,
      reference: c.reference,
    }));
  }
  if (dir.kind === "remote") {
    let kids: string[];
    try {
      kids = await dir.src.children(dir.path);
    } catch {
      return [];
    }
    // An object already found not presentable is not listed (lookup, above).
    kids = kids.filter((k) => !dir.src.declined.has(dir.path + k));
    return kids.map((k) => k.endsWith("/")
      ? { name: k.slice(0, -1), isContainer: true }
      : { name: k, isContainer: false });
  }
  if (dir.kind === "fs") {
    const entries = await dir.src.children(dir.path).catch(() => []);
    return entries.map((e) => ({ name: e.name, isContainer: e.type === NF4DIR }));
  }
  return (await dir.fs.list(dir.cluster))
    .filter(presentableEntry)
    .map((e) => ({ name: e.name, isContainer: (e.attr & ATTR_DIRECTORY) !== 0 }));
}

/** The directory a container reference names, for use as a layer. */
function dirOf(ref: ObjRef): DirRef {
  if (ref.kind === "store") return { kind: "store", node: ref.node };
  if (ref.kind === "remote") {
    return { kind: "remote", src: ref.src, path: ref.path, rep: ref.rep };
  }
  if (ref.kind === "fs") {
    return { kind: "fs", src: ref.src, path: ref.path, entry: ref.entry };
  }
  return { kind: "image", fs: ref.fs, cluster: ref.entry.cluster, entry: ref.entry };
}

/** The imports field of a container, which an image object never has. */
function importsOf(store: Store, dir: DirRef): unknown[] | undefined {
  if (dir.kind !== "store") return undefined;
  const m = store.meta(dir.node);
  // An imports field held within a snapshot is not processed: the
  // snapshot presents the objects it holds, and nothing else, for as
  // long as it is presented.
  if (m.frozen) return undefined;
  return m.imports as unknown[] | undefined;
}

/**
 * Resolves namespace paths through the layers. One resolver serves one
 * request: it carries the cycle-detection stack, so an import whose
 * resolution requires resolving the same entry again is detected however
 * deeply it is nested.
 */
export interface ResolverOptions {
  /**
   * The principal whose request is being resolved. A remote import in
   * delegated identity mode obtains a token for it.
   */
  principal?: Principal;
}

/** A credential reference as an import entry holds it, bound. */
export interface ImportCredentialRef { kms: string; name: string; scope?: string }

/**
 * Retrieves the secret an import entry's credential_id addresses, for the
 * importing object, from the key management server its domain names. The
 * program sets it; with none set, an entry naming a credential reports it
 * unavailable. A refusal is a condition of the key management subclause.
 */
export type ImportSecretResolver = (node: Node, reference: ImportCredentialRef) => Promise<Buffer>;
let importSecrets: ImportSecretResolver | undefined;
export function setImportSecretResolver(resolver: ImportSecretResolver | undefined): void {
  importSecrets = resolver;
}

/**
 * The service credential of this CDMI server: what a remote import in service
 * identity mode presents where its entry names no credential_id. It is a
 * credential reference configured on the server and resolved at the root
 * domain's default key management server (credential-use.ts,
 * retrieveOwnCredential). With none set, such an entry reports the credential
 * not found.
 */
let serviceCredential: (() => Promise<Buffer>) | undefined;
export function setServiceCredential(retrieve: (() => Promise<Buffer>) | undefined): void {
  serviceCredential = retrieve;
}

async function ownSecret(): Promise<{ octets?: Buffer; problem?: Problem }> {
  try {
    return { octets: await serviceCredential!() };
  } catch (err) {
    const c = err as { type?: string; title?: string; detail?: string; message?: string };
    return { problem: {
      type: c.type ?? "https://www.snia.org/cdmi/problems/kms/credential-unavailable",
      title: c.title ?? "The credential is unavailable.",
      detail: c.detail ?? c.message ?? String(err),
    } };
  }
}

/** The secret an entry's credential_id addresses, or the problem that prevented it. */
async function importSecret(node: Node, reference: ImportCredentialRef):
  Promise<{ octets?: Buffer; problem?: Problem }> {
  if (importSecrets === undefined) {
    return { problem: { type: "https://www.snia.org/cdmi/problems/kms/credential-unavailable",
      title: "The credential is unavailable.", detail: "no key management server is configured" } };
  }
  try {
    return { octets: await importSecrets(node, reference) };
  } catch (err) {
    const c = err as { type?: string; title?: string; detail?: string; message?: string };
    return { problem: {
      type: c.type ?? "https://www.snia.org/cdmi/problems/kms/credential-unavailable",
      title: c.title ?? "The credential is unavailable.",
      detail: c.detail ?? c.message ?? String(err),
    } };
  }
}

export class Resolver {
  private readonly store: Store;
  private readonly resolving = new Set<string>();
  private depth = 0;
  private readonly who?: Principal;


  constructor(store: Store, opts: ResolverOptions = {}) {
    this.store = store;
    this.who = opts.principal;
  }

  /** The root container object as a presented namespace. */
  async rootView(): Promise<View> {
    const root = this.store.root();
    const m = this.store.meta(root);
    const base: Layer = {
      dir: { kind: "store", node: root },
      rank: [0], via: [], imported: false, hideIDs: false, readOnly: false,
    };
    if (m.imports !== undefined) {
      return this.importingView(root, "/", m.imports as ImportEntry[], base);
    }
    const v = this.plainView("/", { kind: "store", node: root }, [base], base);
    v.writeNode = root;
    v.writeRank = [0];
    return v;
  }

  /** The container object at a namespace path. */
  async view(ns: string): Promise<View> {
    // A path within a cdmi_snapshots container object names a
    // snapshot, or an object within one. A snapshot is a container
    // object like any other and may be the source of an import, so it
    // is resolved here; it is not presented by the layers, since the
    // reserved name is not a child of any of them.
    const at = ns.indexOf(`/${SNAPSHOTS}/`);
    if (at >= 0) return this.snapshotView(ns, at);
    let v = await this.rootView();
    for (const seg of ns.split("/")) {
      if (seg === "") continue;
      v = await this.child(v, seg);
    }
    return v;
  }

  /** A snapshot, or a container object within one, as a view. */
  private async snapshotView(ns: string, at: number): Promise<View> {
    const owner = await this.view(ns.slice(0, at + 1));
    if (owner.unavail) throw owner.unavail;
    const holder = nodeOf(owner.held);
    const home = holder ? this.store.snapshotHome(holder) : undefined;
    if (!home) throw notFound(ns);
    let node: Node = home;
    for (const seg of ns.slice(at + 1 + SNAPSHOTS.length).split("/")) {
      if (seg === "") continue;
      const next = this.store.tryLookup(node, seg);
      if (!next || !next.isContainer) throw notFound(ns);
      node = next;
    }
    const dir: DirRef = { kind: "store", node };
    const layer: Layer = {
      dir,
      rank: [0],
      via: [],
      imported: false,
      hideIDs: false,
      // An object within a snapshot is not modified.
      readOnly: true,
    };
    return {
      ns,
      held: dir,
      layers: [layer],
      importing: false,
      entries: [],
      objLayer: layer,
      upper: false,
      writeWhy: "an object within a snapshot is not modified",
    };
  }

  /**
   * The container object named name within v. Throws not found where the
   * name is not presented, or is presented by a data object.
   */
  async child(v: View, name: string): Promise<View> {
    if (v.unavail) throw v.unavail;
    if (!presentable(name) && !isAssigned(name)) throw notFound(`${v.ns}${name}/`);
    const ns = `${v.ns}${name}/`;

    const candidates: Layer[] = [];
    for (const l of v.layers) {
      const found = await lookupIn(this.store, l.dir, name);
      if (!found) continue;
      if (candidates.length === 0 && !found.isContainer) {
        // The uppermost holder is a data object, which conceals every
        // container object of that name below it.
        throw notFound(ns);
      }
      if (!found.isContainer) continue;
      const layer: Layer = { ...l, dir: dirOf(found.ref) };
      const imports = importsOf(this.store, layer.dir);
      if (candidates.length === 0) {
        if (imports !== undefined) {
          // An importing container object is presented alone.
          const inner = await this.importingView(nodeOf(found.ref)!, ns,
            imports as ImportEntry[], layer, v);
          inner.importGovernor ??= v.importGovernor;
          return inner;
        }
        candidates.push(layer);
        continue;
      }
      // A lower container object with an imports field of its own is
      // concealed, and contributes nothing.
      if (imports === undefined) candidates.push(layer);
    }
    if (candidates.length === 0) throw notFound(ns);

    const merged = this.plainView(ns, candidates[0].dir, candidates, candidates[0]);
    // The container object whose list governs an image layer governs the
    // whole of the imported namespace, however deep.
    merged.importGovernor = v.importGovernor;
    this.inheritWriteTarget(merged, v, name);
    merged.upper = v.writeRank !== undefined &&
      rankCmp(candidates[0].rank, v.writeRank) < 0;
    return merged;
  }

  private plainView(ns: string, held: DirRef, layers: Layer[], objLayer: Layer): View {
    return {
      ns, held, layers, importing: false, entries: [], objLayer,
      writeWhy: "", upper: false,
    };
  }

  /** Carries the write target of a parent view down to a child of it. */
  private inheritWriteTarget(child: View, parent: View, name: string): void {
    if (parent.writeRank === undefined) {
      child.writeWhy = parent.writeWhy;
      child.writeUnavail = parent.writeUnavail;
      return;
    }
    child.writeRank = parent.writeRank;
    child.writeParent = parent;
    child.writeName = name;
    if (parent.writeImage) {
      // The write target of the child is the directory of that name
      // within the write target of the parent. Whether it is there yet is
      // settled by ensureImageWriteTarget, which can create it.
      child.writeImageParent = parent.writeImage;
      return;
    }
    const wt = parent.writeNode ?? parent.writeDelegate?.writeNode;
    if (wt) {
      const n = this.store.tryLookup(wt, name);
      if (n?.isContainer) child.writeNode = n;
    }
    void nodeOf;
  }

  /**
   * Builds the presented namespace of a container object that has an
   * imports field, resolving each entry in order.
   */
  private async importingView(node: Node, ns: string, raw: unknown[], objLayer: Layer,
    parent?: View): Promise<View> {
    // An importing container object is presented alone, so it takes no
    // layers from its parent's stack; it does inherit nothing but its
    // position, which objLayer carries.
    void parent;
    let entries: ImportEntry[];
    let invalid: Problem | undefined;
    try {
      // A credential reference is accepted where there is a key management
      // server to resolve it, which the resolver's presence says; an entry
      // naming one on a server that no longer has one is reported as such.
      entries = parseImports(raw, ns, { images: true, kms: importSecrets !== undefined, stored: true });
    } catch (err) {
      // A stored imports field that no longer validates, because a
      // capability the server offered when the field was supplied has
      // since been withdrawn. The field is not discarded: the entries
      // are reported as the client supplied them, and each is reported
      // as not active with the reason, so that a client can see what
      // became of its configuration.
      entries = (Array.isArray(raw) ? raw : []) as ImportEntry[];
      // "a CDMI server shall report that entry as it was supplied, shall
      // report it as not active, and shall record the condition that its
      // validation would report in the last_problems field" (revision 211).
      // The condition recorded is therefore the one the validation raised,
      // and not a condition of this server's own, which is what it recorded
      // before.
      invalid = isCondition(err)
        ? { type: err.type, title: err.title, detail: err.detail, ...err.members }
        : seedmiProblem("imports/entry-no-longer-valid",
          "The import entry is no longer valid.",
          `the entry was accepted when it was supplied, and this CDMI server no longer ` +
          `offers what it requires: ${String((err as Error).message ?? err)}`);
    }

    const v: View = {
      ns, held: { kind: "store", node }, layers: [], importing: true, entries: [], objLayer,
      writeWhy: 'no entry of the "imports" field has write_enabled set to "true"',
      upper: false,
    };

    for (const [i, entry] of entries.entries()) {
      if (invalid) {
        // Nothing of the entry is resolved, and the reason is reported
        // on each entry of the field.
        v.entries.push({ entry, index: i, active: false, problems: [invalid] });
        continue;
      }
      const st: EntryState = { entry, index: i, active: false, problems: [] };
      v.entries.push(st);
      const write = isWriteTarget(entry);

      if (isDisabled(entry)) {
        if (write) {
          v.writeWhy = 'the entry whose write_enabled field is "true" is disabled';
          v.writeUnavail = importDisabled(i, ns,
            "the write target, import entry %s of %s, is disabled", i, ns);
        }
        if (isRequired(entry) && !v.unavail) {
          v.unavail = importDisabled(i, ns,
            "import entry %s of %s is required and is disabled", i, ns);
        }
        continue;
      }

      if (entry.type === "self") {
        st.active = true;
        const self: Layer = {
          dir: { kind: "store", node },
          rank: [i], via: objLayer.via, imported: objLayer.imported,
          hideIDs: objLayer.hideIDs, readOnly: objLayer.readOnly,
        };
        v.layers.push(self);
        if (write) {
          v.writeNode = node;
          v.writeRank = [i];
          v.writeWhy = "";
        }
        continue;
      }

      if (entry.type === "NFS" || entry.type === "SMB") {
        const opened = entry.type === "SMB"
          ? await this.openSmb(node, entry)
          : await this.openNfs(entry);
        if (opened.problem) {
          st.problems.push(opened.problem);
          if (write) {
            v.writeWhy = `the write target is not active: ${opened.problem.detail}`;
          }
          if (isRequired(entry) && !v.unavail) {
            v.unavail = sourceUnavailable(i, ns,
              "import entry %s of %s is required and is not active: %s", i, ns,
              opened.problem.detail);
          }
          continue;
        }
        st.active = true;
        const dir: DirRef = { kind: "fs", src: opened.src!, path: "" };
        v.layers.push({
          dir,
          rank: [i],
          via: [{
            type: entry.type,
            import_definition_uri: ns,
            import_uri: entry.import_uri,
          }, ...objLayer.via],
          imported: true,
          // The file handle an NFS server assigns is not required to
          // persist for the life of the file, so no object ID is
          // presented and an object is addressed by path alone.
          hideIDs: true,
          readOnly: true,
        });
        // A security flavour of "sys" is service identity mode, so the
        // lists of the importing container object govern.
        v.importGovernor ??= node;
        if (write) {
          v.writeWhy = `seedmi presents ${entry.type === "SMB" ? "an SMB" : "an NFS"} ` +
            "import read only";
        }
        continue;
      }

      if (entry.type === "image") {
        const opened = await this.openImage(node, i, entry);
        if (opened.problem) {
          st.problems.push(opened.problem);
          if (write) {
            v.writeWhy =
              `the entry whose write_enabled field is "true" is not active: ${opened.problem.detail}`;
            v.writeUnavail = sourceUnavailable(i, ns,
              "the write target, import entry %s of %s, is not active: %s", i, ns,
              opened.problem.detail);
          }
          if (isRequired(entry) && !v.unavail) {
            v.unavail = sourceUnavailable(i, ns,
              "import entry %s of %s is required and is not active: %s", i, ns,
              opened.problem.detail);
          }
          continue;
        }
        st.active = true;
        st.sourceObjectID = opened.sourceObjectID;
        const fs = opened.fs!;
        v.layers.push({
          dir: { kind: "image", fs, cluster: fs.rootDirectory },
          rank: [i],
          via: [{
            type: entry.type,
            import_definition_uri: ns,
            import_uri: entry.import_uri,
          }, ...objLayer.via],
          imported: true,
          // An object of a file system image has no object ID at all, so
          // the preserve_objectid field has nothing to preserve.
          hideIDs: true,
          readOnly: !isWriteTarget(entry),
        });
        v.importGovernor = node;
        if (write) {
          // The write target lies inside the imported file system.
          v.writeImage = { fs, cluster: fs.rootDirectory };
          v.writeRank = [i];
          v.writeWhy = "";
        }
        continue;
      }

      // A CDMI import: resolve the source through the presented namespace.
      const { view: target, problem: prob } = await this.resolveCDMI(node, i, entry);
      if (prob) {
        st.problems.push(prob);
        if (write) {
          v.writeWhy = `the entry whose write_enabled field is "true" is not active: ${prob.detail}`;
          v.writeUnavail = sourceUnavailable(i, ns,
            "the write target, import entry %s of %s, is not active: %s", i, ns, prob.detail);
        }
        if (isRequired(entry) && !v.unavail) {
          v.unavail = sourceUnavailable(i, ns,
            "import entry %s of %s is required and is not active: %s", i, ns, prob.detail);
        }
        continue;
      }
      st.active = true;
      // The objects of a remote source not presented, each reported.
      if (target!.held.kind === "remote") {
        for (const p of target!.held.src.declined.values()) st.problems.push({ ...p, cdmi_import: i } as unknown as Problem);
      }

      const provided: Provided = {
        type: entry.type,
        import_definition_uri: ns,
        import_uri: entry.import_uri,
        // The default identity mode of an import that addresses a namespace is
        // delegated, as resolveRemote reads it.
        ...((entry.identity_mode ?? "delegated") === "delegated" ? { delegated: true } : {}),
      };
      const hide = objLayer.hideIDs || !preservesObjectID(entry);
      // An object of another CDMI server carries no list that governs a
      // request to this one, so the importing container object does.
      if (target!.layers.some((l) => l.dir.kind === "remote")) {
        v.importGovernor ??= node;
      }
      for (const l of target!.layers) {
        v.layers.push({
          dir: l.dir,
          rank: [i, ...l.rank],
          via: [provided, ...l.via],
          imported: true,
          hideIDs: hide || l.hideIDs,
          readOnly: l.readOnly,
        });
      }
      if (write) {
        // The write target is within the imported container object, which
        // has its own stack: the operation is delegated to it.
        if (target!.writeRank !== undefined) {
          v.writeDelegate = target!;
          v.writeNode = target!.writeNode;
          v.writeRank = [i, ...target!.writeRank];
          v.writeWhy = "";
        } else {
          v.writeWhy =
            `the container object imported by the write-enabled entry has no write target: ${target!.writeWhy}`;
          if (target!.writeUnavail) {
            // The condition the import source reports, identifying the
            // entry of this object rather than of the source (9.2).
            const c = target!.writeUnavail;
            const here = Object.create(Object.getPrototypeOf(c)) as Condition;
            Object.assign(here, c, { members: { ...c.members } });
            here.atImport(i, ns);
            v.writeUnavail = here;
          }
        }
      }
    }

    if (v.unavail) {
      // A required import is not active: present nothing within.
      v.layers = [];
      v.writeNode = undefined;
      v.writeRank = undefined;
      v.writeDelegate = undefined;
      v.writeWhy = v.unavail.detail;
      v.writeUnavail = v.unavail;
    }
    return v;
  }

  /**
   * Opens the file system in the value of the data object an image import
   * names. The whole value is read: a file system is interpreted in place,
   * and reading it in pieces through the store on every request would cost
   * more than holding it.
   */
  private async openImage(node: Node, index: number, entry: ImportEntry): Promise<{
    fs?: FAT;
    sourceObjectID?: string;
    problem?: Problem;
  }> {
    const problemOf = (type: string, title: string, detail: string) =>
      ({ problem: importProblem(type, title, detail) });
    let source: Node;
    try {
      source = this.store.resolve(entry.import_uri!);
    } catch {
      return problemOf("source-not-found", "The import source was not found.",
        `no object is addressed by ${entry.import_uri}`);
    }
    if (source.isContainer) {
      return problemOf("source-not-found", "The import source was not found.",
        `${entry.import_uri} addresses a container object, not a data object`);
    }
    const m = this.store.meta(source);
    const key = `${m.objectID}#${m.version}#${entry.partition ?? ""}#${entry.offset ?? ""}`;
    const cached = cachedImage(key);
    if (cached) return { fs: cached, sourceObjectID: m.objectID };

    const value = await this.store.readValue(source);
    const image = new BufferImage(value);
    const table = await partitions(image);
    const describe = () => table.partitions.map((pt) => ({
      partition: String(pt.number),
      offset: String(pt.offset),
      bytes: String(pt.bytes),
      type: pt.type,
      ...(pt.name !== undefined ? { name: pt.name } : {}),
    }));

    /** Opens the file system at a place within the value. */
    const openAt = async (view: BufferImage | PartitionImage, base: number) => {
      try {
        return await FAT.open(view, base);
      } catch {
        return undefined;
      }
    };

    // The partition and offset fields state where the file system begins;
    // where neither is given the CDMI server locates it.
    if (entry.partition !== undefined) {
      const want = Number(entry.partition);
      const part = table.partitions.find((pt) => pt.number === want);
      const fs = part
        ? await openAt(new PartitionImage(image, part.offset, part.bytes), 0)
        : undefined;
      if (!part) {
        return {
          problem: importProblem("filesystem/matching-partition-not-found",
            "No matching partition was found.",
            `the value holds no partition numbered ${want}`, { cdmi_partitions: describe() }),
        };
      }
      if (!fs) {
        return {
          problem: importProblem("filesystem/not-recognized",
            "The file system was not recognized.",
            `partition ${want} holds no file system of the FAT family`,
            { cdmi_partitions: describe() }),
        };
      }
      return {
        fs: cacheImage(key, { fs, image, source, base: part.offset }),
        sourceObjectID: m.objectID,
      };
    }

    if (entry.offset !== undefined) {
      const base = Number(entry.offset);
      const fs = await openAt(image, base);
      if (!fs) {
        return {
          problem: importProblem("filesystem/not-recognized",
            "The file system was not recognized.",
            `the value holds no file system of the FAT family at byte ${base}`),
        };
      }
      return { fs: cacheImage(key, { fs, image, source, base }), sourceObjectID: m.objectID };
    }

    // Neither field: locate the file system.
    if (table.partitions.length === 0) {
      const fs = await openAt(image, 0);
      if (!fs) {
        return {
          problem: importProblem("filesystem/not-recognized",
            "The file system was not recognized.",
            "the value holds no partition table and no file system of the FAT family"),
        };
      }
      return { fs: cacheImage(key, { fs, image, source, base: 0 }), sourceObjectID: m.objectID };
    }
    const matching: { part: typeof table.partitions[number]; fs: FAT }[] = [];
    for (const pt of table.partitions) {
      const fs = await openAt(new PartitionImage(image, pt.offset, pt.bytes), 0);
      if (fs) matching.push({ part: pt, fs });
    }
    if (matching.length === 0) {
      return {
        problem: importProblem("filesystem/matching-partition-not-found",
          "No matching partition was found.",
          "the value holds no partition within which a file system of the FAT family is " +
          "recognized", { cdmi_partitions: describe() }),
      };
    }
    if (matching.length > 1) {
      // The CDMI server does not choose between them.
      return {
        problem: importProblem("filesystem/matching-partition-ambiguous",
          "More than one partition matches.",
          `the value holds ${matching.length} partitions within which a file system of ` +
          "the FAT family is recognized, and the import entry specifies neither a " +
          "partition nor an offset", { cdmi_partitions: describe() }),
      };
    }
    return {
      fs: cacheImage(key,
        { fs: matching[0].fs, image, source, base: matching[0].part.offset }),
      sourceObjectID: m.objectID,
    };
  }

  /**
   * Opens an NFS import source. The connection and the session are
   * held between requests, since establishing one costs two round
   * trips before anything is read.
   */
  private async openNfs(entry: ImportEntry): Promise<{
    src?: NfsSource;
    problem?: Problem;
  }> {
    const parsed = parseNfsURI(entry.import_uri!);
    if (parsed === undefined) {
      return {
        problem: importProblem("source-unreachable",
          "The imported namespace could not be reached.",
          `${entry.import_uri} is not an NFS URI`),
      };
    }
    const port = parsed.port ?? Number(entry.port ?? "2049");
    const opts: NfsSourceOptions = {
      host: parsed.host,
      port,
      root: parsed.path,
      uid: Number(entry.anon_uid ?? "65534"),
      gid: Number(entry.anon_gid ?? "65534"),
      followSymlinks: entry.follow_symlinks === "true",
      // The extended attributes of the source are presented as user
      // metadata, which the cdmi_import_nfs_xattr capability governs.
      xattrs: true,
    };
    const key = [parsed.host, port, parsed.path, opts.uid, opts.gid,
      opts.followSymlinks, opts.xattrs].join("\u0000");
    const src = nfsSource(key, opts);
    try {
      await src.reachable();
    } catch (err) {
      return {
        problem: importProblem("source-unreachable",
          "The imported namespace could not be reached.", String(err)),
      };
    }
    return { src };
  }

  /**
   * Opens an SMB import source. A connection, a session and a tree are
   * held between requests, since establishing one costs a negotiate,
   * two session setups and a tree connect before anything is read.
   */
  private async openSmb(node: Node, entry: ImportEntry): Promise<{
    src?: SmbSource;
    problem?: Problem;
  }> {
    const parsed = parseSmbURI(entry.import_uri!);
    if (parsed === undefined) {
      return {
        problem: importProblem("source-unreachable",
          "The imported namespace could not be reached.",
          `${entry.import_uri} is not an SMB URI`),
      };
    }
    // In service identity mode the session authenticates as the username
    // field, with the password the credential_id field addresses (the SMB
    // import clause); an entry naming none authenticates anonymously, which
    // is what a share admitting a guest expects.
    let credential: { user: string; password: string } | undefined;
    if (entry.credential_id !== undefined) {
      const got = await importSecret(node, entry.credential_id);
      if (got.problem !== undefined) return { problem: got.problem };
      credential = { user: entry.username ?? "", password: got.octets!.toString("utf8") };
    } else {
      credential = smbCredential(undefined);
    }
    const opts: SmbSourceOptions = {
      host: parsed.host,
      port: parsed.port ?? 445,
      share: parsed.share,
      root: parsed.path,
      // The field carries the versions in order of preference, "the first
      // being the one it attempts first" (revision 245).
      protocol: entry.protocol?.[0] ?? "SMB2.1",
      signing: entry.signing === "required",
      user: credential?.user,
      password: credential?.password,
      domain: entry.domain ?? "",
      followReparse: entry.follow_reparse === "true",
      // The extended attributes of a file are presented as user
      // metadata, as they are for an NFS import.
      extendedAttributes: true,
    };
    // The password is part of what distinguishes a source, by its digest, so
    // that a password rotated at the key management server opens a session
    // with the new one rather than reusing a source made with the old.
    const secretKey = opts.password === undefined ? ""
      : createHash("sha256").update(opts.password).digest("hex").slice(0, 16);
    const key = [opts.host, opts.port, opts.share, opts.root, opts.protocol,
      opts.signing, opts.user ?? "", secretKey, opts.domain, opts.followReparse].join("\u0000");
    const src = smbSource(key, opts);
    try {
      await src.reachable();
    } catch (err) {
      return {
        problem: importProblem("source-unreachable",
          "The imported namespace could not be reached.", String(err)),
      };
    }
    return { src };
  }

  /**
   * Opens a remote import source. A remote import presents one layer,
   * the container object at the import URI as that server presents it:
   * its own imports are resolved by that server and reach this one
   * already merged, so there is no stack to carry across.
   */
  private async resolveRemote(node: Node, entry: ImportEntry):
    Promise<{ view?: View; problem?: Problem }> {
    const uri = entry.import_uri!;
    // The default identity mode of an import that addresses a namespace
    // is delegated.
    const mode = entry.identity_mode ?? "delegated";
    let authorization: string | undefined;
    if (mode === "service") {
      // The credential the entry names or, where it names none, the service
      // credential of this CDMI server, which the principal configuring it
      // needed import_service_credential to have presented. Either is
      // retrieved each time the source is opened, and presented by the method
      // the entry states: "bearer" as the token, "basic" with the username
      // field (the CDMI import clause).
      let got: { octets?: Buffer; problem?: Problem };
      if (entry.credential_id !== undefined) {
        got = await importSecret(node, entry.credential_id);
      } else if (serviceCredential !== undefined) {
        got = await ownSecret();
      } else {
        // Not authentication-failed, which is the import source refusing a
        // credential: no credential was presented at all. Before 0.46 this
        // was the answer whatever was configured, the lookup of the server's
        // own credential never finding one.
        return { problem: seedmiProblem("imports/credential-not-found", "The credential was not found.",
          "the entry names no credential_id, and no service credential is configured on this CDMI server") };
      }
      if (got.problem !== undefined) return { problem: got.problem };
      const secret = got.octets!.toString("utf8");
      authorization = entry.auth_method === "basic"
        ? `Basic ${Buffer.from(`${entry.username ?? ""}:${secret}`, "utf8").toString("base64")}`
        : `Bearer ${secret}`;
    } else {
      // Delegated identity: a token is obtained for the requesting
      // principal whose recipient is the import source, by exchanging
      // the token that principal presented. The token presented to this
      // server is never presented onward.
      if (delegation === undefined) {
        return {
          problem: importProblem("delegation-unavailable",
            "A credential for the requesting principal could not be obtained.",
            "no token endpoint is configured on this CDMI server"),
        };
      }
      const who = this.who;
      if (!who || who.token === undefined) {
        // The principal authenticated by a means from which no access
        // token can be obtained, or by none at all.
        return {
          problem: importProblem("delegation-unavailable",
            "A credential for the requesting principal could not be obtained.",
            "an access token for the requesting principal could not be obtained: the " +
            "request presented none, and a token is not obtained from another means " +
            "of authentication"),
        };
      }
      // The resource the token is asked for, as RFC 8707 defines it.
      // The draft says the base URI derived from the import URI is used
      // where the entry states none, and a base URI cannot in general
      // be derived from an import URI: the namespace path of the source
      // is not known to this server. The import URI itself is used,
      // which names the same recipient; see the note on this.
      const resource = entry.resource ?? uri;
      try {
        authorization = `Bearer ${await delegatedToken(who.token, who.name, resource,
          delegation)}`;
      } catch (err) {
        return {
          problem: importProblem("delegation-unavailable",
            "A credential for the requesting principal could not be obtained.",
            `the token exchange did not succeed: ${String(err)}`),
        };
      }
    }

    const src = remoteSource(uri, { authorization });
    try {
      await src.reachable();
    } catch (err) {
      return {
        problem: importProblem("source-unreachable",
          "The imported namespace could not be reached.", String(err)),
      };
    }
    const dir: DirRef = { kind: "remote", src, path: "" };
    const layer: Layer = {
      dir,
      rank: [0],
      via: [],
      imported: true,
      hideIDs: false,
      // Nothing is written into a remote import: seedmi issues reads to
      // the import source alone.
      readOnly: true,
    };
    const view: View = {
      ns: uri,
      held: dir,
      layers: [layer],
      importing: false,
      entries: [],
      objLayer: layer,
      upper: false,
      writeWhy: "the import source is held by another CDMI server, and seedmi issues " +
        "no operation that changes it",
    };
    return { view };
  }

  /**
   * Resolves the import source of a CDMI entry, returning either its view
   * or the problem to record in last_problems.
   */
  private async resolveCDMI(node: Node, index: number, entry: ImportEntry):
    Promise<{ view?: View; problem?: Problem }> {
    const target = localImportPath(entry.import_uri!);
    if (target === undefined) {
      // A remote import: the source is a container object held by
      // another CDMI server, and is fetched rather than resolved.
      return this.resolveRemote(node, entry);
    }
    const key = `${node.id}#${index}`;
    if (this.resolving.has(key)) {
      // The cycle closes here, but the entry to report it on is the one
      // whose resolution led back to it, which is further up the chain.
      // The marker is carried up to that entry's own frame.
      throw new CycleDetected(key);
    }
    if (this.depth >= MAX_IMPORT_DEPTH) {
      return {
        problem: importProblem("depth-limit-reached", "The depth limit was reached.",
          `seedmi processes nested imports to a depth of ${MAX_IMPORT_DEPTH}`),
      };
    }
    this.resolving.add(key);
    this.depth++;
    try {
      return { view: await this.view(target) };
    } catch (err) {
      if (isNotFound(err)) {
        return {
          problem: importProblem("source-not-found", "The import source was not found.",
            `no container object is addressed by ${entry.import_uri}`),
        };
      }
      if (err instanceof CycleDetected && err.key === key) {
        // Every entry whose resolution requires resolving itself reports
        // the cycle; which entries those are depends on where resolution
        // started, as the draft allows.
        return {
          problem: importProblem("cycle-detected", "A cycle was detected.",
            `resolving ${entry.import_uri} requires resolving this entry again`),
        };
      }
      throw err;
    } finally {
      this.depth--;
      this.resolving.delete(key);
    }
  }
}

/** Carried up from the point a cycle closes to the entry that reports it. */
class CycleDetected extends Error {
  key: string;
  constructor(key: string) {
    super(`a cycle closing at ${key}`);
    this.key = key;
  }
}

function isNotFound(err: unknown): boolean {
  return typeof err === "object" && err !== null && "type" in err &&
    String((err as { type: string }).type).endsWith("/not-found");
}

/**
 * The data object named name within v, and the layer that holds it. A
 * container object of that name in a layer above conceals it.
 */
/** The destination where a name of a view is a reference, in any layer. */
export function referenceIn(store: Store, v: View, name: string): string | undefined {
  for (const l of v.layers) {
    if (l.dir.kind !== "store") continue;
    const n = store.tryLookup(l.dir.node, name);
    if (!n) continue;
    return store.meta(n).reference;
  }
  return undefined;
}

export async function resolveFile(store: Store, v: View, name: string,
  allowReserved = false): Promise<{ ref: ObjRef; node: Node; layer: Layer } | undefined> {
  // A name the CDMI server assigned to an object that has no path is
  // reserved, and is reached through the object ID tree alone.
  if (!allowReserved && !presentable(name) && !isAssigned(name)) return undefined;
  for (const l of v.layers) {
    let found = await lookupIn(store, l.dir, name);
    if (!found) continue;
    if (found.isContainer) {
      // A name denotes a container object representation and a data
      // object or queue object representation at once, and this
      // resolves the latter. Where the name denotes the container
      // object alone, it names no file.
      if (l.dir.kind !== "store") return undefined;
      const beside = store.lookupKind(l.dir.node, name, "data") ??
        store.lookupKind(l.dir.node, name, "queue");
      if (beside === undefined) return undefined;
      found = { ref: { kind: "store", node: beside }, isContainer: false };
    }
    // node is the store node where there is one; a caller that needs it
    // has already established that the layer is not an image.
    return { ref: found.ref, node: nodeOf(found.ref) as Node, layer: l };
  }
  return undefined;
}

/**
 * The children of v: the union of the names its layers hold, uppermost
 * first, each name once, in the form its uppermost holder presents.
 */
/**
 * How a consumer of a listing presents a reference. The protocol
 * binding marks one with a trailing question mark; an export that
 * presents references lists the name plain and redirects when it is
 * followed; an export that cannot present one omits it, as the export
 * model requires.
 */
export type ReferenceStyle = "mark" | "plain" | "omit";

export async function listChildren(store: Store, v: View,
  references: ReferenceStyle = "mark"): Promise<string[]> {
  // A name may denote more than one representation of one object, and is
  // listed once. Where one of them is a container object the name is listed
  // in the container form: the children overrule, so an object that holds
  // children is found by a client walking the namespace. A layer above
  // covers a name of a layer below, as before.
  const seen = new Set<string>();
  const out: string[] = [];
  const at = new Map<string, number>();
  for (const l of v.layers) {
    const here = new Set<string>();
    for (const c of await childrenOf(store, l.dir)) {
      if (!presentable(c.name)) continue;
      if (seen.has(c.name) && !here.has(c.name)) continue;
      here.add(c.name);
      if (c.reference !== undefined) {
        if (seen.has(c.name)) continue;
        seen.add(c.name);
        // A reference is listed with a trailing question mark, which is
        // what distinguishes it from an object.
        if (references === "omit") continue;
        at.set(c.name, out.length);
        out.push(references === "mark" ? `${c.name}?` : c.name);
        continue;
      }
      const listed = c.isContainer ? `${c.name}/` : c.name;
      const was = at.get(c.name);
      if (was === undefined) {
        seen.add(c.name);
        at.set(c.name, out.length);
        out.push(listed);
      } else if (c.isContainer) {
        // The container form of a name already listed as a data object.
        out[was] = listed;
      }
    }
  }
  return out.sort((a, b) =>
    a.replace(/\/$/, "") < b.replace(/\/$/, "") ? -1 : 1);
}

/**
 * The importsProvided field of v (9.3): for an importing container object,
 * the imports through which it was reached followed by its own active
 * entries; for a merged container object, the imports of every layer in
 * which a container object of that name is present, in layer order, each
 * once.
 */
export function importsProvidedFor(v: View): Provided[] {
  const out: Provided[] = [];
  const add = (p: Provided) => {
    if (!out.some((q) => q.type === p.type &&
      q.import_definition_uri === p.import_definition_uri &&
      q.import_uri === p.import_uri)) {
      out.push(p);
    }
  };
  if (v.importing) {
    for (const p of v.objLayer.via) add(p);
    for (const st of v.entries) {
      if (st.active && st.entry.type !== "self") {
        add({
          type: st.entry.type,
          import_definition_uri: v.ns,
          import_uri: st.entry.import_uri,
        });
      }
    }
    return out;
  }
  for (const l of v.layers) for (const p of l.via) add(p);
  return out;
}

/** The condition for an operation on a name within a view that presents nothing. */
export function checkPresented(v: View): void {
  if (v.unavail) throw v.unavail;
}

/**
 * The container object of the write target at v, created where it does not
 * yet exist, notwithstanding the create operation's prohibition of
 * intermediate container objects (9.2). Each container created takes the
 * user metadata of the container object presented at that position, so the
 * metadata a client reads does not change when the write target comes to
 * hold one.
 */
export async function ensureWriteTarget(store: Store, v: View): Promise<Node> {
  if (v.writeImage || v.writeImageParent) {
    throw forbidden("the write target of %s is a directory of an imported file system, " +
      "which holds no object of the store", v.ns);
  }
  if (v.writeRank === undefined) {
    if (v.writeUnavail) throw v.writeUnavail;
    throw forbidden("no operation that changes an object can be directed within %s: %s",
      v.ns, v.writeWhy);
  }
  if (v.writeNode) return v.writeNode;
  if (v.writeDelegate) return ensureWriteTarget(store, v.writeDelegate);
  if (!v.writeParent || v.writeName === undefined) {
    throw forbidden("the write target of %s does not exist", v.ns);
  }
  const parent = await ensureWriteTarget(store, v.writeParent);
  const existing = store.tryLookup(parent, v.writeName);
  if (existing && !existing.isContainer) {
    throw conflictImportLayer(0, v.ns,
      "the write target holds a data object where the container object %s is required", v.ns);
  }
  // The container created carries the metadata, owner and access control
  // list of the container object presented at that position, so that
  // neither what a client reads nor what it is permitted changes when the
  // write target comes to hold one.
  const presented = v.held.kind === "store"
    ? viewOf(store, { kind: "store", node: v.held.node })
    : undefined;
  const node = existing ?? store.createContainer(parent, v.writeName, {
    metadata: presented?.userMetadata ?? {},
    owner: presented?.owner ?? "",
    acl: presented?.acl ?? null,
  });
  v.writeNode = node;
  return node;
}

/**
 * Where an operation that changes the object at a name within v is denied,
 * the condition to report. rank is the rank of the layer holding it.
 */
export function denyChange(v: View, ns: string, rank: number[], what: string): Condition {
  if (v.writeRank === undefined) {
    return v.writeUnavail ?? forbidden("%s cannot be changed: %s", ns, v.writeWhy);
  }
  if (rankCmp(rank, v.writeRank) < 0) {
    // Denied at a layer above the write target, and not remedied.
    return conflictImportLayer(rank[0], v.ns,
      "%s is held by a layer above the write target of %s, which denies the %s", ns, v.ns, what);
  }
  return forbidden("%s is held by a layer below the write target of %s, and the %s is not remedied",
    ns, v.ns, what);
}

/**
 * The directory of an imported file system into which an operation on v
 * is directed, creating the directories on the path to it. Returns
 * undefined where the write target is not an imported file system.
 */
export async function ensureImageWriteTarget(v: View):
  Promise<{ fs: FAT; cluster: number } | undefined> {
  if (v.writeImage) return v.writeImage;
  if (!v.writeImageParent || v.writeName === undefined) return undefined;
  const parent = v.writeImageParent;
  const existing = await parent.fs.find(parent.cluster, v.writeName);
  if (existing && (existing.attr & ATTR_DIRECTORY) !== 0) {
    v.writeImage = { fs: parent.fs, cluster: existing.cluster };
    return v.writeImage;
  }
  if (existing) {
    throw conflict("a data object is held at %s within the imported file system", v.ns);
  }
  const made = await parent.fs.createDirectory(parent.cluster, v.writeName);
  v.writeImage = { fs: parent.fs, cluster: made.cluster };
  return v.writeImage;
}

/** What a remote object's access control list names that this server does not support, or undefined. */
function unsupportedAclOf(acl: unknown, isContainer: boolean): string | undefined {
  if (!Array.isArray(acl)) return undefined;
  for (const raw of acl) {
    if (raw === null || typeof raw !== "object") continue;
    const e = raw as Record<string, unknown>;
    try {
      const found = unsupportedIn(parseACE({ acetype: String(e.acetype ?? "ALLOW"), identifier: String(e.identifier ?? ""),
        aceflags: String(e.aceflags ?? "NO_FLAGS"), acemask: String(e.acemask ?? "NONE") }, isContainer));
      if (found !== undefined) return found;
    } catch {
      return "an entry that is not well formed";
    }
  }
  return undefined;
}
