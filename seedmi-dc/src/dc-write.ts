// The only thing that writes the directory.
//
// Two front ends will call it — LDAP writes and SCIM 2.0 — and neither holds a
// rule of its own, so that the two cannot differ (DESIGN-admin.md §2). The
// lesson is paid for twice over in this family: 0.2 of this program kept its
// online and offline interfaces honest by giving them one module, and the CDMI
// server spent four releases with a table that one half of a file read and the
// other half did not list.
//
// What a change is here: a named operation with named fields, validated whole,
// applied in one transaction, with the key material a password implies derived
// and registered before the row is written. A front end translates a request into
// one of these and renders what comes back; it does not decide anything.
//
// Secrets never reach the store. A password becomes a scrypt verifier and a
// Kerberos long-term key per enctype, each registered at the key store, and the
// row keeps the references; an S3 key pair keeps its access key identifier and a
// reference; a certificate keeps a fingerprint and a subject, which are public.
// So the store can be copied, diffed, backed up and read by an administrator
// without exposing anything, which is what made a store acceptable again.

import { createHash, randomUUID, randomBytes } from "node:crypto";
import { HASH, hashPassword, NAME } from "./dc-directory.ts";
import {
  type Credential, type Kind, type Ou, type Principal, Store,
} from "./dc-store.ts";
import { stringToKey } from "./krb-crypto.ts";
import { type Etype } from "./krb-crypto.ts";
import { saltOf } from "./krb-client.ts";
import { KeyStoreError, REASON } from "./dc-keys.ts";
import { prepareSecret } from "./prepare.ts";

/**
 * Why a change was refused. The front ends map `code` to what their protocol
 * says: LDAP a result code, SCIM a status and a `scimType`. The message is for a
 * person, and is the text an invalid configuration would have produced.
 */
export class WriteError extends Error {
  readonly code: WriteCode;
  readonly field?: string;
  constructor(code: WriteCode, message: string, field?: string) {
    super(message);
    this.code = code;
    if (field !== undefined) this.field = field;
  }
}

export type WriteCode =
  /** A name, a number or a field is not of the form the realm admits. */
  | "invalid"
  /** A name is taken, by a user, a group or a unit. */
  | "taken"
  /** What the change names is not there. */
  | "absent"
  /** The change would leave the directory invalid: a cycle, a unit in use. */
  | "conflict"
  /** A limit of the realm: two S3 key pairs, and no more. */
  | "limit";

const bad = (message: string, field?: string) => new WriteError("invalid", message, field);

/**
 * Where secret material is kept. The implementation the controller uses speaks
 * KMIP to the key management server (phase B); the one the tests use holds it in
 * memory, so that the rules here are tested without a key server.
 */
/** What a sweep found and did, in both directions. */
export interface Swept {
  /** Unreferenced material this sweep destroyed. */
  destroyed: string[];
  /** Already destroyed at the key server, which a Locate still returns. Nothing to do. */
  gone: string[];
  /** Unreferenced material the key server would not destroy, and why. */
  unreadable: { ref: string; why: string }[];
}

// A sweep deliberately does **not** report the mirror case — a row that references
// material the key server no longer holds. It was written to, by asking whether a
// Locate still listed the reference, and that is the wrong question: KMIP leaves a
// destroyed object in place and a Locate with no `State` still returns it, so the check
// could never fire against a real key server. It fired against `MemoryKeyStore` only
// because that double removed the entry, which the real one does not.
//
// The right answer is that this direction needs no new mechanism. A reference whose
// material cannot be read is already reported by `readDirectory`, at every read, in
// `withoutVerifier` and `withoutKeys` with the key server's own reason beside it, and
// such a principal's binds are refused with a line saying why. Asking twice, once
// wrongly, is worse than asking once. `dcd --sweep-keys` prints what that read found.
//
// The asymmetry is the point: a dangling reference was always visible, orphaned material
// never was, which is why the latter needed the compensating destroy and this did not.

export interface KeyStore {
  /**
   * Registers material and returns the reference the directory keeps. `kind` and
   * `principal` become attributes of the managed object, so that everything of
   * one principal can be found and destroyed with it, and so that the grant that
   * lets the CDMI server read an S3 secret can name the S3 group alone
   * (DESIGN-admin.md §4a).
   */
  register(kind: "password" | "kerberos" | "s3", principal: string, material: Buffer,
    note?: string): Promise<string>;
  get(ref: string): Promise<Buffer>;
  destroy(ref: string): Promise<void>;
  /**
   * Every reference this key store holds for the realm, where it can say. `Writer.sweep`
   * uses it to find material no row references and destroy it — which it can only do
   * because `register` records the kind and principal as attributes of the managed
   * object, so the key server can be asked.
   *
   * Optional, and a store that cannot enumerate leaves it out rather than returning an
   * empty list: the sweep then reports that it destroyed nothing, which is the truth —
   * it has not looked, as against having looked and found nothing.
   */
  references?(): Promise<string[]>;
}

/** A key store in memory, for the tests and for a deployment with no key server. */
export class MemoryKeyStore implements KeyStore {
  private readonly held = new Map<string, Buffer>();
  /** Destroyed, and still listed: what a KMIP key server leaves behind. */
  private readonly destroyed = new Set<string>();
  readonly registered: { ref: string; kind: string; principal: string; note?: string }[] = [];

  register(kind: "password" | "kerberos" | "s3", principal: string, material: Buffer,
    note?: string): Promise<string> {
    const ref = `mem:${randomUUID()}`;
    this.held.set(ref, Buffer.from(material));
    this.registered.push({ ref, kind, principal, ...(note === undefined ? {} : { note }) });
    return Promise.resolve(ref);
  }

  /** Every object, destroyed ones included, as a KMIP Locate with no `State` returns. */
  references(): Promise<string[]> {
    return Promise.resolve([...this.held.keys(), ...this.destroyed]);
  }

  /**
   * The references whose material is still there, which `references` deliberately does
   * not tell apart — a Locate cannot. For a test that wants to say what secret material
   * exists, as against what the key server still lists.
   */
  get live(): string[] {
    return [...this.held.keys()];
  }

  get(ref: string): Promise<Buffer> {
    const held = this.held.get(ref);
    if (held === undefined) return Promise.reject(new Error(`no material at ${ref}`));
    return Promise.resolve(held);
  }

  /**
   * Destroys material, **as a KMIP key server does**: the managed object stays, with its
   * material gone, and a Locate still returns it (KMIP's Locate matches every `State`
   * unless one is named). A second destroy is refused with the Result Reason for an
   * object already destroyed.
   *
   * This used to `delete` the entry, so `references()` stopped returning it and a second
   * destroy succeeded — neither of which is what the real key server does. The sweep's
   * unit tests were green against that behaviour while the first live run found thirty
   * objects it could not destroy and a consistency check that silently never fired. A
   * double that does not model the thing under test gives exactly as much confidence as
   * no test, and reads like more.
   */
  destroy(ref: string): Promise<void> {
    if (this.destroyed.has(ref)) {
      return Promise.reject(new KeyStoreError(
        "the key management server refused the operation (reason 12): the object is " +
        "already destroyed", false, REASON.objectDestroyed));
    }
    this.held.delete(ref);
    this.destroyed.add(ref);
    return Promise.resolve();
  }

  /** What is held, for a test that asserts a change left nothing behind. */
  get count(): number {
    return this.held.size;
  }
}

/** What the writer needs to know of the realm it writes. */
export interface Realm {
  /** The realm's name, which salts a Kerberos key. */
  name: string;
  /** The enctypes a key is derived for; a ticket is issued with the first. */
  etypes: Etype[];
}

/** Two S3 key pairs at once, so a rotation is create-new, migrate, delete-old. */
export const S3_KEYS_PER_PRINCIPAL = 2;

/** The form of an access key identifier: what S3 tooling expects to see. */
const ACCESS_KEY = /^[A-Z0-9]{20}$/;

/** The alphabet an access key identifier is generated from. */
const ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export class Writer {
  private readonly store: Store;
  private readonly keys: KeyStore;
  private readonly realm: Realm;
  /** The changes of `atomic`, one at a time; see there. */
  private queue: Promise<void> = Promise.resolve();
  /**
   * The key-server references the change in flight has registered, where one is being
   * collected. Undefined between changes: `compensated` establishes it, and a nested
   * call joins the outer collection rather than starting its own.
   */
  private registered: string[] | undefined;

  constructor(store: Store, keys: KeyStore, realm: Realm) {
    this.store = store;
    this.keys = keys;
    this.realm = realm;
  }

  /**
   * One change made of several of the writers below: all of it or none. A SCIM
   * PATCH with several operations is required to be atomic in those words (RFC
   * 7644 §3.5.2), and an LDAP modify's list of changes is all-or-none as this
   * server has always told clients; each writer opens a transaction of its own, so
   * without this the first operation committed before the second one failed.
   *
   * Key material is a second system and cannot be inside the store's transaction, so
   * it is **compensated** rather than rolled back: every registration a change makes
   * is recorded, and a change that throws destroys what it registered before the
   * refusal is passed on. See `registering`.
   */
  async atomic<T>(change: () => Promise<T> | T): Promise<T> {
    // One change at a time. The transaction below spans an await — a password set
    // part way through a PATCH reaches the key server — and the store is one
    // connection, so a second change starting while the first is awaiting would
    // find itself inside the first one's transaction and be committed or rolled
    // back with it. The queue is what makes "all of it or none" mean this change's
    // operations and no others.
    const run = this.queue.then(() => this.compensated(() => this.store.transactAsync(change)));
    this.queue = run.then(() => undefined, () => undefined);
    return await run;
  }

  /**
   * Runs a change and, if it throws, destroys the key material it had registered.
   *
   * The store's transaction cannot reach the key server, so a change that registered a
   * password and then failed left that material behind — a scrypt verifier and a
   * Kerberos long-term key per enctype, derived from a real password, belonging to a
   * principal that does not exist. Nothing referenced them, so nothing would ever
   * destroy them: `remove` destroys the credentials *of a principal*, and there was no
   * principal. Every refused create added two more.
   *
   * It was recorded as unfixable — "a two-system problem a single transaction cannot
   * solve" — which is true of a *transaction* and not of the problem. Two systems want
   * a compensating action, and this is it. It became urgent rather than untidy when the
   * creates were made atomic (§13c of NOTES-on-ldap-writes.md): before that a failed
   * create left the principal behind too, so the material was at least referenced.
   *
   * Re-entrant: only the outermost call collects and drains, so a `setPassword` inside
   * an `atomic` is compensated once, by the whole change, and not twice.
   *
   * What remains, and is recorded rather than claimed closed: a compensating destroy can
   * itself fail, and the process can stop between the registration and the commit. Both
   * leave material the sweep below is for.
   */
  private async compensated<T>(change: () => Promise<T>): Promise<T> {
    if (this.registered !== undefined) return await change();
    const mine: string[] = [];
    this.registered = mine;
    try {
      return await change();
    } catch (e) {
      // In reverse, so that the most recent registration goes first, and each failure
      // swallowed: the caller is owed the refusal that caused this, not a failure to
      // tidy up after it. What cannot be destroyed is what `sweep` is for.
      for (const ref of [...mine].reverse()) {
        try {
          await this.keys.destroy(ref);
        } catch { /* left for the sweep */ }
      }
      throw e;
    } finally {
      this.registered = undefined;
    }
  }

  /**
   * Registers material, recording the reference where a change is collecting them so
   * that a refusal can destroy what it had already written. Every registration in this
   * module goes through here; calling `this.keys.register` directly is what left
   * material behind.
   */
  private async keep(kind: "password" | "kerberos" | "s3", principal: string,
    material: Buffer, note?: string): Promise<string> {
    const ref = await this.keys.register(kind, principal, material, note);
    this.registered?.push(ref);
    return ref;
  }

  /**
   * Destroys material at the key server that no row of this store references.
   *
   * The compensating action above covers a change that fails; it cannot cover a process
   * that stops between a registration and the commit, nor a compensating destroy that
   * itself failed, nor anything orphaned by a build that predates it. Those want a
   * sweep, and a sweep is only possible because every registration carries the
   * principal and kind as attributes of the managed object (`KeyStore.register`), so
   * the key server can be asked what it holds for this realm.
   *
   * Returns what it destroyed, so that a caller can say so. A `KeyStore` that cannot
   * enumerate what it holds leaves out `references` and the sweep does nothing,
   * which is honest: it has not found no orphans, it has not looked.
   */
  async sweep(): Promise<Swept> {
    if (this.keys.references === undefined) return { destroyed: [], gone: [], unreadable: [] };
    const referenced = new Set<string>();
    for (const p of this.store.principals()) {
      for (const c of this.store.credentialsOf(p.id)) {
        if (c.ref !== undefined) referenced.add(c.ref);
      }
    }
    const destroyed: string[] = [];
    // Already destroyed, which is not a failure: a KMIP Locate that does not name a
    // `State` matches every state, Destroyed included (see `KmipKeyStore.references`),
    // so a key server keeps returning what it has already destroyed. The sweep's purpose
    // is that no unreferenced material remains, and such an object satisfies it.
    const gone: string[] = [];
    // **With the reason.** This swallowed the error and reported only the reference, and
    // the first live run against a real key server reported thirty objects it could not
    // destroy with no way to tell why — while destroying the same object by hand worked.
    // A sweep that cannot say what stopped it cannot be operated, and the reason turned
    // out to be the line above.
    const unreadable: { ref: string; why: string }[] = [];
    for (const ref of await this.keys.references()) {
      if (referenced.has(ref)) continue;
      try {
        await this.keys.destroy(ref);
        destroyed.push(ref);
      } catch (e) {
        if (e instanceof KeyStoreError && e.reason === REASON.objectDestroyed) gone.push(ref);
        else unreadable.push({ ref, why: e instanceof Error ? e.message : String(e) });
      }
    }
    return { destroyed, gone, unreadable };
  }

  // -------------------------------------------------------------------
  // Organizational units

  createUnit(name: string, parentPath?: string, description?: string): Ou {
    this.checkName(name, "ou");
    const parent = parentPath === undefined ? undefined : this.unitAt(parentPath);
    if (this.store.unitNamed(parent?.id, name) !== undefined) {
      throw new WriteError("taken",
        `${name} is already a unit of ${parentPath === undefined ? "the realm" : parentPath}`, "ou");
    }
    return this.store.transact(() => this.store.addUnit({
      ...(parent === undefined ? {} : { parent: parent.id }),
      name,
      ...(description === undefined ? {} : { description }),
    }));
  }

  /**
   * Moves or renames a unit. What it holds goes with it, which is what the LDAP
   * modify-DN operation means when it carries a new superior.
   */
  moveUnit(path: string, to: { parent?: string | null; name?: string; description?: string | null }): Ou {
    const unit = this.unitAt(path);
    const name = to.name ?? unit.name;
    this.checkName(name, "ou");
    const parent = to.parent === undefined
      ? unit.parent
      : (to.parent === null ? undefined : this.unitAt(to.parent).id);
    // A unit may not come to contain itself, directly or through its own
    // descendants: the directory is a tree and has to stay one.
    if (parent !== undefined && this.descends(parent, unit.id)) {
      throw new WriteError("conflict",
        `${path} cannot be moved within itself`, "ou");
    }
    const clash = this.store.unitNamed(parent, name);
    if (clash !== undefined && clash.id !== unit.id) {
      throw new WriteError("taken", `${name} is already a unit there`, "ou");
    }
    const moved: Ou = {
      ...unit,
      ...(parent === undefined ? { parent: undefined } : { parent }),
      name,
      ...(to.name === undefined ? {} : { name }),
      // A description set to null is cleared, which is how a PUT that omits it
      // says so; undefined leaves what is there, which is how a rename says so.
      ...(to.description === undefined
        ? {}
        : { description: to.description === null ? undefined : to.description }),
    };
    this.store.transact(() => this.store.updateUnit(moved));
    return moved;
  }

  deleteUnit(path: string): void {
    const unit = this.unitAt(path);
    const holds = this.store.unitHolds(unit.id);
    if (holds.principals > 0 || holds.units > 0) {
      throw new WriteError("conflict",
        `${path} holds ${holds.principals} principal(s) and ${holds.units} unit(s), ` +
        "and a unit that holds anything is not deleted", "ou");
    }
    this.store.transact(() => this.store.removeUnit(unit.id));
  }

  // -------------------------------------------------------------------
  // Principals

  /**
   * Creates a user or a group. The identifiers are allocated here and never
   * change: the UUID a token and a SCIM client hold, the relative identifier an
   * access control list holds, and the POSIX number a file system holds.
   */
  create(kind: Kind, name: string, fields: Fields = {}): Principal {
    this.checkName(name, kind === "user" ? "uid" : "cn");
    this.checkFree(name);
    this.checkKind(kind, fields);
    const ou = fields.ou === undefined || fields.ou === null
      ? undefined
      : this.unitAt(fields.ou);
    const expires = this.checkExpires(fields.expires);
    return this.store.transact(() => this.store.addPrincipal({
      id: randomUUID(),
      kind,
      ...(ou === undefined ? {} : { ou: ou.id }),
      name,
      ...(fields.displayName === undefined || fields.displayName === null
        ? {}
        : { displayName: fields.displayName }),
      sidRid: this.store.allocate("sid_rid"),
      posixId: this.store.allocate(kind === "user" ? "posix_user" : "posix_group"),
      disabled: fields.disabled ?? false,
      ...(expires === undefined ? {} : { expires }),
      // A field supplied as null removes one, which at a create means it is
      // simply not set.
      ...(fields.home === undefined || fields.home === null ? {} : { home: fields.home }),
      ...(fields.primaryGroup === undefined || fields.primaryGroup === null
        ? {} : { primaryGroup: this.groupNamed(fields.primaryGroup).id }),
    }));
  }

  /**
   * The fields that belong to a user and not to a group, refused on a group.
   *
   * A group and a user share one table and so one set of columns, and this check is
   * what keeps that an implementation detail. Without it all four were **accepted,
   * written, and then dropped**: `UserSpec` of `dc-directory.ts` carries `disabled`,
   * `expires` and `home` and `GroupSpec` does not, so a group given any of them kept
   * the value in the store where nothing could read it and nothing acted on it. A
   * group could be disabled, expire, have a home directory, and have a *primary
   * group* — which is not a thing a group has at all: RFC 2307's `gidNumber` on a
   * group is the group's own number, not a reference to another.
   *
   * It is refused and not ignored, which is DESIGN-admin.md §6's rule and the same
   * reasoning the LDAP front end applies to `uidNumber`: a client told its change
   * succeeded believes a state the directory is not in, and every later decision it
   * makes from that belief is wrong. Found by the read-side conformance test, which
   * asks whether each front end can recover every field the store holds and so
   * noticed that for a group the store held fields *neither* could.
   */
  private checkKind(kind: Kind, fields: Fields): void {
    if (kind === "user") return;
    const named: [keyof Fields, string][] = [
      ["disabled", "a group does not authenticate, so it is not disabled"],
      ["expires", "a group does not authenticate, so it does not expire"],
      ["home", "a home directory belongs to a user"],
      ["primaryGroup", "a group's own gidNumber is its number; a primary group " +
        "belongs to a user (RFC 2307 section 3)"],
    ];
    for (const [field, why] of named) {
      // Null clears a field, and clearing one a group never had is a change that
      // asks for nothing; only setting one is refused.
      if (fields[field] === undefined || fields[field] === null) continue;
      throw bad(`${field} is not a field of a group: ${why}`, field);
    }
  }

  /**
   * Changes the fields of a principal. A field not supplied is left alone; a
   * field supplied as null is removed, which is how both front ends express a
   * field cleared. Nothing allocated is changed, and a rename changes the name
   * alone.
   */
  update(id: string, fields: Fields): Principal {
    const held = this.principal(id);
    this.checkKind(held.kind, fields);
    if (fields.name !== undefined && fields.name !== null) {
      this.checkName(fields.name, held.kind === "user" ? "uid" : "cn");
      const clash = this.store.named(fields.name);
      if (clash !== undefined && clash.id !== held.id) {
        throw new WriteError("taken", `${fields.name} is already a name in this realm`, "name");
      }
    }
    const ou = fields.ou === undefined
      ? held.ou
      : (fields.ou === null ? undefined : this.unitAt(fields.ou).id);
    const expires = fields.expires === undefined
      ? held.expires
      : (fields.expires === null ? undefined : this.checkExpires(fields.expires));
    const next: Principal = {
      ...held,
      ...(ou === undefined ? { ou: undefined } : { ou }),
      name: fields.name === undefined || fields.name === null ? held.name : fields.name,
      ...(fields.displayName === undefined
        ? {}
        : { displayName: fields.displayName === null ? undefined : fields.displayName }),
      ...(fields.disabled === undefined ? {} : { disabled: fields.disabled }),
      ...(expires === undefined ? { expires: undefined } : { expires }),
      ...(fields.primaryGroup === undefined
        ? {}
        : { primaryGroup: fields.primaryGroup === null
          ? undefined : this.groupNamed(fields.primaryGroup).id }),
      ...(fields.home === undefined
        ? {}
        : { home: fields.home === null ? undefined : fields.home }),
    };
    this.store.transact(() => this.store.updatePrincipal(next));
    return this.principal(id);
  }

  /** Removes a principal, with its memberships, and destroys its key material. */
  async remove(id: string): Promise<void> {
    const held = this.principal(id);
    const refs = this.store.credentialsOf(held.id)
      .map((c) => c.ref).filter((r): r is string => r !== undefined);
    this.store.transact(() => this.store.removePrincipal(held.id));
    // After the row has gone, so that a key server that cannot be reached leaves
    // material behind rather than leaving a principal that cannot authenticate.
    // The material is unreachable either way, and phase B logs what it could not
    // destroy.
    for (const ref of refs) await this.keys.destroy(ref);
  }

  // -------------------------------------------------------------------
  // Membership: the group's side is authoritative, as both front ends present it

  addMember(group: string, member: string): void {
    const g = this.expectGroup(group);
    const m = this.principal(member);
    if (m.id === g.id) {
      throw new WriteError("conflict", `${g.name} cannot be a member of itself`, "member");
    }
    // A group may not come to contain itself through the groups it belongs to:
    // the check the configuration has always made, made here instead.
    if (m.kind === "group" && this.contains(m.id, g.id)) {
      throw new WriteError("conflict",
        `${g.name} comes to contain itself through ${m.name}`, "member");
    }
    this.store.transact(() => this.store.addMembership(m.id, g.id));
  }

  removeMember(group: string, member: string): void {
    const g = this.expectGroup(group);
    const m = this.principal(member);
    this.store.transact(() => this.store.removeMembership(m.id, g.id));
  }

  /** Replaces the whole membership of a group, which is what a PUT of one means. */
  setMembers(group: string, members: string[]): void {
    const g = this.expectGroup(group);
    const wanted = members.map((m) => this.principal(m));
    for (const m of wanted) {
      if (m.id === g.id || (m.kind === "group" && this.contains(m.id, g.id))) {
        throw new WriteError("conflict",
          `${g.name} comes to contain itself through ${m.name}`, "members");
      }
    }
    this.store.transact(() => {
      for (const held of this.store.membersOf(g.id)) this.store.removeMembership(held, g.id);
      for (const m of wanted) this.store.addMembership(m.id, g.id);
    });
  }

  // -------------------------------------------------------------------
  // Credentials

  /**
   * Sets a principal's password. The one moment both derivations are possible is
   * this one, so both are done: the scrypt verifier a bind and a token are
   * checked against, and the Kerberos long-term key for each enctype the realm
   * serves. No cleartext is kept, and a principal administered this way is
   * servable by the key distribution centre — which a principal whose
   * configuration gave only a hash never was.
   */
  async setPassword(id: string, password: string): Promise<void> {
    const held = this.principal(id);
    if (held.kind !== "user") {
      throw bad("a group has no password", "password");
    }
    if (password === "") throw bad("a password is not empty", "password");
    // Prepared **here**, where the password enters, because it feeds two derivations
    // below — a scrypt verifier and a Kerberos long-term key per enctype — and
    // preparing it for one only would make an LDAP bind and a Kerberos exchange
    // disagree about the same password. RFC 7644 §5 makes preparing it a MUST; see
    // `prepareSecret` for what of PRECIS is and is not done.
    //
    // The Kerberos half cannot be made to work for a non-canonical spelling whatever
    // this server does: the client derives its own key from what the user typed
    // (RFC 3961's string-to-key, which mandates no normalization), so a password typed
    // in Form D yields a different key at the client no matter which form the server
    // stored. A realm serving both SCIM and Kerberos therefore cannot make such a
    // password work in both. NOTES-on-scim.md §12 records it.
    password = prepareSecret(password);
    const verifier = hashPassword(password);
    const refs: { kind: "password" | "kerberos"; ref: string; note?: string }[] = [
      { kind: "password", ref: await this.keep("password", held.id, Buffer.from(verifier, "utf8")) },
    ];
    for (const etype of this.realm.etypes) {
      const key = stringToKey(password, saltOf(this.realm.name, [held.name]), etype);
      refs.push({
        kind: "kerberos",
        ref: await this.keep("kerberos", held.id, key, String(etype)),
        note: String(etype),
      });
    }
    const stale = this.store.credentialsOf(held.id)
      .filter((c) => c.kind === "password" || c.kind === "kerberos");
    this.store.transact(() => {
      this.store.clearCredentials(held.id, "password");
      this.store.clearCredentials(held.id, "kerberos");
      for (const r of refs) {
        this.store.addCredential({
          principal: held.id,
          kind: r.kind,
          ref: r.ref,
          ...(r.note === undefined ? {} : { material: r.note }),
        });
      }
      this.store.updatePrincipal(this.store.principal(held.id)!);
    });
    for (const c of stale) if (c.ref !== undefined) await this.keys.destroy(c.ref);
  }

  /**
   * Records a verifier that is already hashed, for an import carrying a
   * `password_hash` and nothing else. What is lost is stated rather than hidden:
   * a Kerberos key is derived from the password and not from its hash, so a
   * principal imported this way binds and is issued tokens but is never issued a
   * ticket — which is exactly what it could do when its hash was in the
   * configuration. Setting a password through either front end repairs it.
   * Neither front end offers this: a client sends a password, not a hash.
   */
  async setPasswordHash(id: string, hash: string): Promise<void> {
    const held = this.principal(id);
    if (held.kind !== "user") throw bad("a group has no password", "password");
    if (!HASH.test(hash)) {
      throw bad("a hashed verifier is one --hash-password prints", "password_hash");
    }
    const ref = await this.keep("password", held.id, Buffer.from(hash, "utf8"));
    const stale = this.store.credentialsOf(held.id)
      .filter((c) => c.kind === "password" || c.kind === "kerberos");
    this.store.transact(() => {
      this.store.clearCredentials(held.id, "password");
      this.store.clearCredentials(held.id, "kerberos");
      this.store.addCredential({ principal: held.id, kind: "password", ref });
      this.store.updatePrincipal(this.store.principal(held.id)!);
    });
    for (const c of stale) if (c.ref !== undefined) await this.keys.destroy(c.ref);
  }

  /**
   * Records a client certificate that authenticates a principal. Public material
   * only: the fingerprint a request is resolved by, and the subject an
   * administrator reads.
   */
  /**
   * Records a certificate a principal may authenticate with.
   *
   * `der` is the certificate itself, where the caller has it. It is kept, which RFC
   * 4523 §2.1 requires — "As values of this syntax contain digitally signed data,
   * values of this syntax and the form of each value MUST be preserved as
   * presented" — and which only the fingerprint used to be: a client that wrote a
   * `userCertificate` and read the entry back found the attribute absent, and
   * `NOTES-on-ldap.md` §5 recorded that as a choice rather than the violation it is.
   *
   * Without `der` only the fingerprint is kept, which is the case of an import that
   * has nothing else (`dc-import`) and of the SCIM extension's `certificates`,
   * whose `value` is this server's own attribute and names a fingerprint. Such a
   * certificate still authenticates a connection — that is what a fingerprint is
   * for — and is still absent from a search, which is now a stated consequence of
   * what the caller had rather than of what this server keeps.
   */
  addCertificate(id: string, fingerprint: string, subject?: string, der?: Buffer): Credential {
    const held = this.principal(id);
    if (!/^sha256:[0-9a-f]{64}$/.test(fingerprint)) {
      throw bad("a certificate is recorded as sha256: and sixty-four hexadecimal digits",
        "certificate");
    }
    if (der !== undefined) {
      // The fingerprint has to be this certificate's, or the row would say two
      // different things.
      const of = `sha256:${createHash("sha256").update(der).digest("hex")}`;
      if (of !== fingerprint) {
        throw bad("the fingerprint given is not that of the certificate given", "certificate");
      }
    }
    const taken = this.store.byMaterial("certificate", fingerprint);
    if (taken !== undefined) {
      throw new WriteError("taken",
        taken.principal === held.id
          ? "that certificate is already recorded for this principal"
          : "that certificate already authenticates another principal", "certificate");
    }
    return this.store.transact(() => this.store.addCredential({
      principal: held.id,
      kind: "certificate",
      material: fingerprint,
      ...(subject === undefined ? {} : { detail: subject }),
      ...(der === undefined ? {} : { value: der.toString("base64") }),
    }));
  }

  /**
   * What a certificate given as a value is: its DER and the fingerprint by which a
   * connection bearing it is resolved. A certificate arrives either as its DER
   * octets or in PEM, and both forms name the same certificate, so both are
   * accepted and what is kept is the DER.
   *
   * This lives here, in the one thing that writes, because it is a rule about what
   * a value of this realm is — and it did not. It lived in the LDAP translation,
   * and the consequence was exactly the one DESIGN-admin.md §2 says a rule in a
   * translation has: the SCIM front end, unable to reach it, invented a narrower
   * rule of its own and would accept **only** a fingerprint, so a certificate
   * could be registered over one front end and not the other, and the certificate
   * itself — which RFC 4523 §2.1 requires be preserved — could only ever be
   * preserved for an LDAP client. The phase E conformance test is what found it.
   */
  static certificateValue(raw: Buffer): { fingerprint: string; der: Buffer } {
    // The octets, as they arrived. This used to take a string, and the LDAP write
    // path had decoded the value as UTF-8 before handing it over — so every octet
    // of a DER certificate that is not valid UTF-8 had already become U+FFFD, and
    // the fingerprint was of something else. A certificate sent in its DER form,
    // which is the form RFC 4523 §2.1 requires, recorded a credential that could
    // never authenticate it; the PEM form, being ASCII, worked, which is why no
    // test saw it. "Values of this syntax and the form of each value MUST be
    // preserved as presented" (RFC 4523 §2.1), so the value is passed as octets
    // and only *read* as text where it turns out to be PEM.
    const asText = raw.toString("latin1");
    const pem = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(asText);
    const der = pem !== null ? Buffer.from(pem[1].replace(/\s+/g, ""), "base64") : raw;
    if (der.length === 0 || der[0] !== 0x30) {
      throw bad("a certificate is an X.509 certificate, in PEM or as its DER encoding " +
        "(RFC 4523 section 2.1)", "certificate");
    }
    return { fingerprint: `sha256:${createHash("sha256").update(der).digest("hex")}`, der };
  }

  /**
   * Creates an S3 key pair. The secret is returned **once**, here, and is never
   * readable again through either front end: what the directory keeps is the
   * access key identifier and the reference to the secret at the key store,
   * which the CDMI server reads under the grant of DESIGN-admin.md §4a.
   */
  async createS3Key(id: string): Promise<{ accessKeyId: string; secret: string }> {
    const held = this.principal(id);
    if (held.kind !== "user") {
      throw bad("a group holds no S3 key pair", "s3");
    }
    const already = this.store.credentialsOf(held.id).filter((c) => c.kind === "s3");
    if (already.length >= S3_KEYS_PER_PRINCIPAL) {
      throw new WriteError("limit",
        `${held.name} holds ${already.length} S3 key pairs, which is the limit; ` +
        "delete one before creating another", "s3");
    }
    const accessKeyId = this.accessKeyId();
    // Forty characters of base 64, which is the length and alphabet every S3
    // client accepts and what the services generate.
    const secret = randomBytes(30).toString("base64");
    const ref = await this.keep("s3", held.id, Buffer.from(secret, "utf8"), accessKeyId);
    this.store.transact(() => this.store.addCredential({
      principal: held.id, kind: "s3", ref, material: accessKeyId,
    }));
    return { accessKeyId, secret };
  }

  /**
   * The credentials recorded for a principal: public material and references, as
   * the store holds them, and no secret. A front end reads these to report what a
   * principal holds and to find the one a client asked to remove.
   */
  credentials(id: string): Credential[] {
    return this.store.credentialsOf(this.principal(id).id);
  }

  async removeCredential(credentialId: string): Promise<void> {
    const held = this.store.allCredentials().find((c) => c.id === credentialId);
    if (held === undefined) {
      throw new WriteError("absent", "no credential of that identifier is recorded");
    }
    this.store.transact(() => this.store.removeCredential(held.id));
    if (held.ref !== undefined) await this.keys.destroy(held.ref);
  }

  // -------------------------------------------------------------------
  // What the rules need to ask of the store

  /** A principal by its identifier, or by its name where a front end gives one. */
  /**
   * The group whose POSIX number is the one given. RFC 2307 §3's `gidNumber` holds
   * a number, so that is what a client writes; the store keeps the group, so the
   * user's `gidNumber` follows the group rather than being a copy of its number.
   */
  groupWithPosix(number: number): Principal {
    const found = this.store.principals()
      .find((p) => p.kind === "group" && p.posixId === number);
    if (found === undefined) {
      // "conflict", not "absent": the entry being written exists and it is the
      // *value* that names nothing, which is a constraint on the value rather than
      // a missing object. noSuchObject would tell a client its entry had gone.
      throw new WriteError("conflict",
        `${number} is not the gidNumber of a group of this realm, so it names no primary group`,
        "primary_group");
    }
    return found;
  }

  /**
   * The group a name denotes, for a primary group. A user is not one: a
   * `gidNumber` is a group's number, and pointing a user's primary group at another
   * user would give it a number from the user space.
   */
  private groupNamed(name: string) {
    const held = this.store.named(name);
    if (held === undefined) throw new WriteError("absent", `${name} is not a group of this realm`, "primary_group");
    if (held.kind !== "group") {
      throw bad(`${name} is a user, and a primary group is a group`, "primary_group");
    }
    return held;
  }

  principal(idOrName: string): Principal {
    const held = this.store.principal(idOrName) ?? this.store.named(idOrName);
    if (held === undefined) {
      throw new WriteError("absent", `no principal of this realm is ${idOrName}`);
    }
    return held;
  }

  private expectGroup(idOrName: string): Principal {
    const held = this.principal(idOrName);
    if (held.kind !== "group") {
      throw new WriteError("conflict", `${held.name} is a user and holds no members`, "member");
    }
    return held;
  }

  /** The unit a path names, as `eng` or `eng/platform`. */
  unitAt(path: string): Ou {
    let parent: string | undefined;
    let found: Ou | undefined;
    for (const part of path.split("/").filter((p) => p !== "")) {
      found = this.store.unitNamed(parent, part);
      if (found === undefined) {
        throw new WriteError("absent", `no unit of this realm is ${path}`, "ou");
      }
      parent = found.id;
    }
    if (found === undefined) {
      throw new WriteError("absent", "a unit is named by a path, and the path is empty", "ou");
    }
    return found;
  }

  /** The path of a unit, which both front ends report. */
  pathOf(id: string | undefined): string | undefined {
    const parts: string[] = [];
    let at = id;
    while (at !== undefined) {
      const unit = this.store.unit(at);
      if (unit === undefined) break;
      parts.unshift(unit.name);
      at = unit.parent;
    }
    return parts.length === 0 ? undefined : parts.join("/");
  }

  /** Whether `unit` is `ancestor` or lies beneath it. */
  private descends(unit: string, ancestor: string): boolean {
    let at: string | undefined = unit;
    while (at !== undefined) {
      if (at === ancestor) return true;
      at = this.store.unit(at)?.parent;
    }
    return false;
  }

  /** Whether `group` contains `wanted`, through however many levels. */
  private contains(group: string, wanted: string): boolean {
    const seen = new Set<string>();
    const walk = (at: string): boolean => {
      if (at === wanted) return true;
      if (seen.has(at)) return false;
      seen.add(at);
      return this.store.membersOf(at).some(walk);
    };
    return walk(group);
  }

  private checkName(name: string, field: string): void {
    if (!NAME.test(name)) {
      throw bad(
        `${JSON.stringify(name)} is not a name this realm admits: a letter or a digit, ` +
        "then up to sixty-three letters, digits, full stops, hyphens or underscores", field);
    }
  }

  private checkFree(name: string): void {
    if (this.store.named(name) !== undefined) {
      throw new WriteError("taken",
        `${name} is already a name in this realm, which holds one name for a user, ` +
        "a group or neither, whatever its case", "name");
    }
  }

  private checkExpires(when: Date | string | null | undefined): Date | undefined {
    if (when === undefined || when === null) return undefined;
    const d = when instanceof Date ? when : new Date(when);
    if (Number.isNaN(d.getTime())) {
      throw bad(`${JSON.stringify(String(when))} is not a time`, "expires");
    }
    return d;
  }

  private accessKeyId(): string {
    for (let tries = 0; tries < 8; tries++) {
      const bytes = randomBytes(20);
      let id = "";
      for (const b of bytes) id += ID_ALPHABET[b % ID_ALPHABET.length];
      if (!ACCESS_KEY.test(id)) continue;
      if (this.store.byMaterial("s3", id) === undefined) return id;
    }
    throw new WriteError("conflict", "no unused access key identifier was found");
  }
}

/** The fields of a principal a change may carry. Null removes one. */
export interface Fields {
  name?: string | null;
  displayName?: string | null;
  /** The path of the unit, or null for the realm's base. */
  ou?: string | null;
  disabled?: boolean;
  expires?: Date | string | null;
  home?: string | null;
  /**
   * The name of the group whose number is this user's `gidNumber`, for RFC 2307's
   * `posixAccount`. Null clears it, after which the user bears no `posixAccount` —
   * the class is `MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory )` and a
   * user without one has no gidNumber to give.
   */
  primaryGroup?: string | null;
}
