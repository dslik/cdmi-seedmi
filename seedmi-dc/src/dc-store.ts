// The directory's store.
//
// Until 0.12 the directory was the configuration file, read again on SIGHUP.
// From 0.13 a deployment that gives [directory] store keeps it here instead, so
// that an administrative interface has something to write to; the configuration
// then seeds the store once (dc-import) and holds no [[user]] or [[group]] of
// its own. A deployment that gives no store behaves exactly as it did, and every
// write is refused.
//
// What this module is, and what it is not. It is the rows: organizational units,
// principals, memberships, credentials, the allocation counters and the schema
// version, with the queries that read and write them and a transaction to wrap a
// change in. It holds no rules: which changes are permitted, what a name may be,
// whether a group may contain itself, what key material a password produces —
// all of that is dc-write.ts, which is the only thing that calls the writers
// here. Keeping the two apart is what lets the LDAP and SCIM front ends share
// one set of rules (DESIGN-admin.md §2).
//
// Three things are the database's business rather than a caller's, because a
// rule enforced by an index cannot be forgotten by a code path:
//
//   * a name is one name whatever its case, and is unique across the realm,
//     users and groups together, whatever organizational unit each is in — a
//     unique index on the folded name;
//   * a membership is a pair, and a pair occurs once — the primary key;
//   * an allocated identifier is never issued twice — a counter row updated in
//     the same transaction as the row that takes the value.

import { DatabaseSync, type StatementSync } from "node:sqlite";
import { randomUUID } from "node:crypto";
import * as path from "node:path";
import { mkdirSync } from "node:fs";
import { prepare } from "./prepare.ts";

/** Raised where the store cannot do what was asked of it. */
export class StoreError extends Error {}

/**
 * The version of the schema this build writes and reads. A store written by an
 * older version is brought forward by `migrate` below; one written by a newer
 * version is not opened at all.
 *
 * 2: credential_material covers only the kinds whose material is a lookup key,
 *    and credential_kerberos takes its place for Kerberos keys. See the DDL.
 * 3: a unit carries created and modified, which SCIM's meta requires of every
 *    resource and which LDAP's timestamps serve. See the `ou` table.
 * 4: `fold` became RFC 4518's string preparation, so every `name_folded` an
 *    earlier version wrote is a different key and is recomputed. See `fold`.
 * 5: a credential carries `value`, the public part of it, which for a certificate
 *    is the certificate itself. RFC 4523 §2.1 requires it be preserved.
 * 7: a unit carries a second UUID, `groups_id`. A unit is one row and **two** LDAP
 *    entries — one beneath ou=people, one beneath ou=groups — and RFC 4530 §2.4 says
 *    "Servers SHALL generate and assign a new UUID to each entry upon its addition to
 *    the directory ... An entry's UUID is immutable", and that each "MUST ... be
 *    unique in space and time". One identifier cannot be the immutable UUID of two
 *    entries, so neither entry carried one at all, which is the SHALL unmet. The
 *    second UUID is this row's second entry's; `id` remains the first's, and the SCIM
 *    resource's, since there a unit is one resource.
 * 6: a user carries `primary_group`, without which no entry could bear RFC 2307's
 *    `posixAccount` — it is `MUST ( cn $ uid $ uidNumber $ gidNumber $
 *    homeDirectory )` and a user had no gidNumber. See `primaryGroup`.
 */
export const SCHEMA = 7;

/** A principal is a user or a group; the two share a name space. */
export type Kind = "user" | "group";

/** What a credential row holds, by kind. */
export type CredentialKind = "password" | "kerberos" | "certificate" | "s3";

/** An organizational unit: a node of the tree the directory presents. */
export interface Ou {
  id: string;
  /** The parent unit, or undefined for a unit directly beneath the realm's base. */
  parent?: string;
  name: string;
  description?: string;
  /** When the unit was created and last changed, which SCIM's meta and LDAP's timestamps serve. */
  created: Date;
  modified: Date;
  /**
   * The UUID of this unit's LDAP entry beneath `ou=groups`; `id` is the one beneath
   * `ou=people`, and the one SCIM serves, a unit being one resource there. A unit is
   * one row and two entries, and RFC 4530 §2.4 requires a UUID of each entry — "An
   * entry's UUID is immutable", each "unique in space and time" — so there are two.
   */
  groupsId?: string;
}

/** A user or a group, as the store holds one. */
export interface Principal {
  id: string;
  kind: Kind;
  /** The unit this principal is in, or undefined for one directly beneath the base. */
  ou?: string;
  name: string;
  displayName?: string;
  /** The relative identifier of the principal's security identifier. */
  sidRid: number;
  /** uidNumber for a user, gidNumber for a group. */
  posixId: number;
  disabled: boolean;
  expires?: Date;
  home?: string;
  /**
   * The group whose `posixId` is this user's `gidNumber`, for RFC 2307's
   * `posixAccount`. Undefined for a group, and for a user that has none.
   */
  primaryGroup?: string;
  created: Date;
  modified: Date;
  /** Changed by every write to this principal; the entity tag a front end reports. */
  version: number;
}

/**
 * A credential of a principal. The secret is never here: `ref` is the unique
 * identifier of the object at the key management server that holds it, and
 * `material` is the part that is not secret — the fingerprint of a certificate,
 * the access key identifier of an S3 key pair, the enctype of a Kerberos key.
 */
export interface Credential {
  id: string;
  principal: string;
  kind: CredentialKind;
  ref?: string;
  material?: string;
  /** A second column of public material: a certificate's subject, an S3 key's group. */
  detail?: string;
  /**
   * The public part of the credential itself, where there is one to keep: for a
   * certificate, base 64 of the certificate's DER. RFC 4523 §2.1 requires that the
   * value "be preserved as presented", which a fingerprint does not do.
   */
  value?: string;
  created: Date;
}

/** The counters an identifier is allocated from. */
export type Counter = "sid_rid" | "posix_user" | "posix_group";

/**
 * The uniqueness of a credential's material, kept apart from the rest of the
 * schema because the migration in `Store.open` runs it again.
 *
 * An access key identifier and a certificate fingerprint are how a request
 * arrives, so each is looked up directly and each is unique across the realm.
 * Those two kinds and no others: material is not a lookup key for every kind, and
 * for a Kerberos credential it is the enctype, which every principal of the realm
 * shares. While one index covered every kind, the *second* principal of a realm
 * to be given a password could not be given one — setting it wrote an aes256 key,
 * and the row ('kerberos', '18') was already taken by the first. Every test wrote
 * a password for exactly one principal, so none of them saw it; what found it was
 * a test of RFC 3062's oldPasswd rule, which needed two principals with passwords
 * for the first time.
 *
 * What uniqueness means for a Kerberos credential is one key per principal per
 * enctype, so that a second key of the same enctype replaces rather than joins,
 * and that is the second index.
 */
const CREDENTIAL_INDEXES = `
CREATE UNIQUE INDEX IF NOT EXISTS credential_material
  ON credential (kind, material)
  WHERE material IS NOT NULL AND kind IN ('certificate', 's3');
CREATE UNIQUE INDEX IF NOT EXISTS credential_kerberos
  ON credential (principal, material) WHERE kind = 'kerberos' AND material IS NOT NULL;
`;

/**
 * The columns later schema versions added, added to a store that predates them —
 * **before any statement is prepared**.
 *
 * `db.exec(DDL)` runs every statement with IF NOT EXISTS, so it creates a missing
 * table and does nothing at all to a table that is there and is missing a column.
 * That is what the numbered migrations are for; but a prepared statement naming a
 * column that does not exist fails at `prepare`, and `new Store` prepares every
 * statement in its constructor. So the column has to exist before the Store object
 * does, which puts these here rather than beside their numbered steps.
 *
 * Each is idempotent and each is safe to run on a store of any version: the check is
 * whether the column is there, not what the schema number says, because the column
 * being absent is the only thing that matters to `prepare`. The numbered migrations
 * then do whatever has to happen to the rows.
 */
function addColumns(db: DatabaseSync): void {
  const column = (table: string, name: string, type: string) => {
    const has = (db.prepare(`SELECT 1 FROM pragma_table_info('${table}') WHERE name = ?`)
      .get(name) as unknown) !== undefined;
    if (!has) db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`);
  };
  // 4 -> 5: a credential gains `value`, the certificate itself. The certificates
  // already recorded keep their fingerprint and have no certificate to serve, which
  // is what a client reads as the attribute being absent — the state they were in.
  column("credential", "value", "TEXT");
  // 5 -> 6: a user gains `primary_group`. Every existing user has none, which is what
  // it had before, so no principal gains or loses a posixAccount by being migrated.
  column("principal", "primary_group", "TEXT REFERENCES principal(id)");
  // 6 -> 7: a unit gains `groups_id`, the UUID of its second LDAP entry. Filled by
  // the numbered step, which runs in the migration transaction.
  column("ou", "groups_id", "TEXT");
}

const DDL = `
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- A unit carries its own times and version, as a principal does. Without them a
-- unit served over SCIM had a meta with neither created nor lastModified nor
-- version, which RFC 7643 section 3.1 forbids ("the attributes 'id' and 'meta'
-- (and its associated sub-attributes) MUST be assigned values by the service
-- provider"), and If-Match on a unit could not be honoured because there was
-- nothing to compare. The columns default so that a store written by schema 2,
-- where they did not exist, is migrated by adding them.
CREATE TABLE IF NOT EXISTS ou (
  id          TEXT PRIMARY KEY,
  parent      TEXT REFERENCES ou(id),
  name        TEXT NOT NULL,
  name_folded TEXT NOT NULL,
  description TEXT,
  created     TEXT NOT NULL DEFAULT '1970-01-01T00:00:00.000Z',
  modified    TEXT NOT NULL DEFAULT '1970-01-01T00:00:00.000Z',
  -- The UUID of this unit's entry beneath ou=groups. The id column is the one
  -- beneath ou=people, and the one SCIM uses. Two entries, two immutable UUIDs
  -- (RFC 4530 section 2.4); see the schema note at the top of this file.
  -- No backtick may appear in this comment: the DDL is a template literal.
  groups_id   TEXT
);
-- A unit's name is unique among its siblings, folded, so that ou=Eng and ou=eng
-- are one unit wherever a client writes either.
CREATE UNIQUE INDEX IF NOT EXISTS ou_sibling
  ON ou (IFNULL(parent, ''), name_folded);

CREATE TABLE IF NOT EXISTS principal (
  id           TEXT PRIMARY KEY,
  kind         TEXT NOT NULL CHECK (kind IN ('user', 'group')),
  ou           TEXT REFERENCES ou(id),
  name         TEXT NOT NULL,
  name_folded  TEXT NOT NULL,
  display_name TEXT,
  sid_rid      INTEGER NOT NULL UNIQUE,
  posix_id     INTEGER NOT NULL,
  disabled     INTEGER NOT NULL DEFAULT 0,
  expires      TEXT,
  home         TEXT,
  -- The group whose gidNumber is this user's primary one, for RFC 2307's
  -- posixAccount. A group, not a number: the number is the group's and moves with
  -- it. Null for a group, and for a user that has none, which then bears no
  -- posixAccount — the class MUSTs a gidNumber.
  primary_group TEXT REFERENCES principal(id),
  created      TEXT NOT NULL,
  modified     TEXT NOT NULL,
  version      INTEGER NOT NULL DEFAULT 1
);
-- The rule the realm rests on: one name, whatever its case, across users and
-- groups and every unit. A Kerberos principal, a security identifier and an
-- access control entry are flat per realm, so the name has to be.
CREATE UNIQUE INDEX IF NOT EXISTS principal_name ON principal (name_folded);
-- A POSIX number is unique within its kind and not across the two: a user and a
-- group may share a number, as they may on any system with separate spaces.
CREATE UNIQUE INDEX IF NOT EXISTS principal_posix ON principal (kind, posix_id);
CREATE INDEX IF NOT EXISTS principal_ou ON principal (ou);

CREATE TABLE IF NOT EXISTS membership (
  member TEXT NOT NULL REFERENCES principal(id) ON DELETE CASCADE,
  "group" TEXT NOT NULL REFERENCES principal(id) ON DELETE CASCADE,
  PRIMARY KEY (member, "group")
);
CREATE INDEX IF NOT EXISTS membership_group ON membership ("group");

CREATE TABLE IF NOT EXISTS credential (
  id        TEXT PRIMARY KEY,
  principal TEXT NOT NULL REFERENCES principal(id) ON DELETE CASCADE,
  kind      TEXT NOT NULL CHECK (kind IN ('password', 'kerberos', 'certificate', 's3')),
  ref       TEXT,
  material  TEXT,
  detail    TEXT,
  -- The public part of the credential, where there is one to keep. For a
  -- certificate it is the certificate, base 64 of its DER: RFC 4523 section 2.1,
  -- "As values of this syntax contain digitally signed data, values of this syntax
  -- and the form of each value MUST be preserved as presented", which a SHA-256
  -- fingerprint does not do. Null for a password, a Kerberos key and an S3 secret,
  -- whose public part is the material column and whose secret is at the key server.
  value     TEXT,
  created   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS credential_principal ON credential (principal, kind);
-- The uniqueness of a credential's material: see CREDENTIAL_INDEXES above.
${CREDENTIAL_INDEXES}

CREATE TABLE IF NOT EXISTS counter (
  name TEXT PRIMARY KEY,
  next INTEGER NOT NULL
);
`;

const ISO = (d: Date): string => d.toISOString();
const at = (s: string): Date => new Date(s);

/**
 * The preparation a name is compared by: the one name per realm, whatever its
 * case, that `principal_name` and `ou_sibling` index.
 *
 * This is RFC 4518, the string preparation behind `caseIgnoreMatch`, in
 * prepare.ts. What was here was `name.normalize("NFC").toLowerCase()` with a
 * comment calling it "the Unicode case fold of a name" — it is not a case fold,
 * and RFC 4518 §2.3 asks for Form **KC**, not Form C. Four divergences, each of
 * which let two names the standard calls one coexist, are listed in prepare.ts;
 * the one that matters most is that nothing performed §2.2's mapping step, so
 * `ali<SOFT HYPHEN>ce` and `alice` were different names — identical on screen.
 *
 * **None of it was reachable**, and saying so is part of the record: `NAME` in
 * dc-directory.ts admits ASCII letters, digits and `. _ -` only, so no name can
 * contain a character any of those steps touches. What made the old comment worth
 * replacing is that it promised the opposite — "a realm that may hold a name
 * outside ASCII" — which invites widening `NAME` on a guarantee the code did not
 * give. It gives it now.
 *
 * The result is prepared for comparison and is not a name: it carries the
 * surrounding spaces of §2.6.1 and is only ever used as an index key.
 */
export const fold = (name: string): string => prepare(name);

interface Rows {
  ou: StatementSync;
  ouAll: StatementSync;
  ouChildren: StatementSync;
  ouByName: StatementSync;
  ouInsert: StatementSync;
  ouUpdate: StatementSync;
  ouDelete: StatementSync;
  ouHolds: StatementSync;
  principal: StatementSync;
  principalAll: StatementSync;
  principalByName: StatementSync;
  principalByPosix: StatementSync;
  principalInsert: StatementSync;
  principalUpdate: StatementSync;
  principalDelete: StatementSync;
  principalInOu: StatementSync;
  memberships: StatementSync;
  membersOf: StatementSync;
  memberAdd: StatementSync;
  memberRemove: StatementSync;
  memberClear: StatementSync;
  credentials: StatementSync;
  credentialsOf: StatementSync;
  credentialByMaterial: StatementSync;
  credentialAdd: StatementSync;
  credentialDelete: StatementSync;
  credentialClear: StatementSync;
  counterGet: StatementSync;
  counterSet: StatementSync;
  metaGet: StatementSync;
  metaSet: StatementSync;
}

/**
 * The store. It is opened once by the controller and once by each tool; the
 * controller holds it open while it runs, as the key management server's store
 * is held, so a tool that writes beside a running controller is a thing a
 * deployment is told not to do rather than a thing this guards against.
 */
export class Store {
  private readonly db: DatabaseSync;
  /** How deep the open transaction is nested; see `transact`. */
  private depth = 0;
  private readonly q: Rows;
  readonly file: string;

  private constructor(db: DatabaseSync, file: string) {
    this.db = db;
    this.file = file;
    const p = (sql: string) => db.prepare(sql);
    this.q = {
      ou: p("SELECT * FROM ou WHERE id = ?"),
      ouAll: p("SELECT * FROM ou"),
      ouChildren: p("SELECT * FROM ou WHERE IFNULL(parent, '') = ?"),
      ouByName: p("SELECT * FROM ou WHERE IFNULL(parent, '') = ? AND name_folded = ?"),
      ouInsert: p("INSERT INTO ou (id, parent, name, name_folded, description, created, " +
        "modified, groups_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
      ouUpdate: p("UPDATE ou SET parent = ?, name = ?, name_folded = ?, description = ?, " +
        "modified = ? WHERE id = ?"),
      ouDelete: p("DELETE FROM ou WHERE id = ?"),
      ouHolds: p(
        "SELECT (SELECT COUNT(*) FROM principal WHERE ou = ?) AS principals, " +
        "(SELECT COUNT(*) FROM ou WHERE parent = ?) AS units"),
      principal: p("SELECT * FROM principal WHERE id = ?"),
      principalAll: p("SELECT * FROM principal"),
      principalByName: p("SELECT * FROM principal WHERE name_folded = ?"),
      principalByPosix: p("SELECT * FROM principal WHERE kind = ? AND posix_id = ?"),
      principalInsert: p(
        "INSERT INTO principal (id, kind, ou, name, name_folded, display_name, sid_rid, " +
        "posix_id, disabled, expires, home, primary_group, created, modified, version) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)"),
      principalUpdate: p(
        "UPDATE principal SET ou = ?, name = ?, name_folded = ?, display_name = ?, " +
        "disabled = ?, expires = ?, home = ?, primary_group = ?, modified = ?, " +
        "version = version + 1 WHERE id = ?"),
      principalDelete: p("DELETE FROM principal WHERE id = ?"),
      principalInOu: p("SELECT * FROM principal WHERE IFNULL(ou, '') = ?"),
      memberships: p("SELECT member, \"group\" FROM membership"),
      membersOf: p("SELECT member FROM membership WHERE \"group\" = ?"),
      memberAdd: p("INSERT OR IGNORE INTO membership (member, \"group\") VALUES (?, ?)"),
      memberRemove: p("DELETE FROM membership WHERE member = ? AND \"group\" = ?"),
      memberClear: p("DELETE FROM membership WHERE member = ?"),
      credentials: p("SELECT * FROM credential"),
      credentialsOf: p("SELECT * FROM credential WHERE principal = ? ORDER BY created"),
      credentialByMaterial: p("SELECT * FROM credential WHERE kind = ? AND material = ?"),
      credentialAdd: p(
        "INSERT INTO credential (id, principal, kind, ref, material, detail, value, created) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
      credentialDelete: p("DELETE FROM credential WHERE id = ?"),
      credentialClear: p("DELETE FROM credential WHERE principal = ? AND kind = ?"),
      counterGet: p("SELECT next FROM counter WHERE name = ?"),
      counterSet: p("INSERT INTO counter (name, next) VALUES (?, ?) " +
        "ON CONFLICT(name) DO UPDATE SET next = excluded.next"),
      metaGet: p("SELECT value FROM meta WHERE key = ?"),
      metaSet: p("INSERT INTO meta (key, value) VALUES (?, ?) " +
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value"),
    };
  }

  /**
   * Opens the store in a directory, creating it where it is not there. The
   * schema version is written on creation and checked on every open: a store
   * written by a later build is not opened, since a build that does not know a
   * column would drop what it does not understand.
   */
  static open(dir: string): Store {
    mkdirSync(dir, { recursive: true });
    const file = path.join(dir, "directory.sqlite");
    const db = new DatabaseSync(file);
    db.exec("PRAGMA journal_mode = WAL");
    db.exec("PRAGMA foreign_keys = ON");
    db.exec(DDL);
    // **Before any statement is prepared.** Every column a prepared statement names
    // has to exist, and `new Store` prepares all of them eagerly — so a migration
    // that adds a column cannot run after the constructor. It did, and the result was
    // that 1.0 could not open any store written by 0.19 at all: the first thing it
    // said was "table ou has no column named groups_id", from `prepare`, before the
    // migration that adds the column had a chance to run. No test saw it, because
    // every test opens a store this build created. It was found by starting 1.0
    // against a store a running 0.19 had left behind, which is the only way it could
    // have been found.
    addColumns(db);
    const s = new Store(db, file);
    const held = s.meta("schema");
    if (held === undefined) {
      s.setMeta("schema", String(SCHEMA));
    } else if (Number(held) > SCHEMA) {
      db.close();
      throw new StoreError(
        `the store at ${file} was written by a later version of this program ` +
        `(its schema is ${held}, this build knows ${SCHEMA})`);
    } else if (Number(held) < SCHEMA) {
      // The DDL above runs with IF NOT EXISTS, so it cannot correct an index that
      // is already there and wrong. Each step below does, and the whole is one
      // transaction: a store half migrated is worse than one not migrated.
      s.transact(() => {
        if (Number(held) < 2) {
          // 1 -> 2: credential_material was unique over every kind, which made a
          // Kerberos enctype unique across the realm and so allowed one principal
          // with a password. Dropping it and running the two index statements of
          // the DDL again is the whole change; no row moves.
          db.exec("DROP INDEX IF EXISTS credential_material");
          db.exec(CREDENTIAL_INDEXES);
        }
        if (Number(held) < 7) {
          // 6 -> 7: every unit gains the second UUID, which `addColumns` has just
          // made room for. **Filled for every existing unit**, because a unit without
          // one serves no entryUUID on its second entry and that is the state this
          // migration exists to leave behind. A fresh UUID per row is correct: these
          // entries have never had one, so none is being changed, and RFC 4530 §2.4's
          // "An entry's UUID is immutable" starts from here.
          const missing = db.prepare("SELECT id FROM ou WHERE groups_id IS NULL").all() as
            { id: string }[];
          const fill = db.prepare("UPDATE ou SET groups_id = ? WHERE id = ?");
          for (const row of missing) fill.run(randomUUID(), row.id);
        }
        if (Number(held) < 4 && Number(held) >= 1) {
          // 3 -> 4: `fold` changed, so every folded name in the store is a key this
          // build would not compute. Recomputed from the spelling beside it, which
          // the rows keep. The unique indexes are what would otherwise go quietly
          // wrong: two names an earlier fold called different may be one name now,
          // and the recompute is where that is discovered — it fails the migration
          // rather than leaving a realm with two principals of one name.
          for (const row of db.prepare("SELECT id, name FROM principal").all() as
            { id: string; name: string }[]) {
            db.prepare("UPDATE principal SET name_folded = ? WHERE id = ?").run(fold(row.name), row.id);
          }
          for (const row of db.prepare("SELECT id, name FROM ou").all() as
            { id: string; name: string }[]) {
            db.prepare("UPDATE ou SET name_folded = ? WHERE id = ?").run(fold(row.name), row.id);
          }
        }
        if (Number(held) < 3) {
          // 2 -> 3: a unit gains created and modified. The DDL above created the
          // table with them, so this runs only where the table was already there
          // without them; the columns carry a default, which is what makes the
          // ALTER legal and gives an existing row a value a client can read.
          const has = (db.prepare("SELECT 1 FROM pragma_table_info('ou') WHERE name = ?")
            .get("created") as unknown) !== undefined;
          if (!has) {
            for (const column of ["created", "modified"]) {
              db.exec(`ALTER TABLE ou ADD COLUMN ${column} TEXT NOT NULL ` +
                "DEFAULT '1970-01-01T00:00:00.000Z'");
            }
          }
        }
        s.setMeta("schema", String(SCHEMA));
      });
    }
    return s;
  }

  close(): void {
    this.db.close();
  }

  /** Applies a change as one transaction: either all of it or none. */
  transact<T>(change: () => T): T {
    // Re-entrant: an inner call joins the transaction already open rather than
    // beginning a second one, which SQLite refuses. Every writer of dc-write.ts
    // opens one of these, so a change made of several writer calls — a SCIM PATCH
    // with several operations, an LDAP modify with several changes — committed
    // each call as it went. RFC 7644 §3.5.2: "A PATCH request, regardless of the
    // number of operations, SHALL be treated as atomic. If a single operation
    // encounters an error condition, the original SCIM resource MUST be restored";
    // RFC 4511 §4.6 says the same of a modify's changes. Without this the second
    // operation's failure left the first one's effect behind, so the client's view
    // and the server's diverged permanently and a retry applied it twice.
    if (this.depth > 0) {
      this.depth++;
      try {
        return change();
      } finally {
        this.depth--;
      }
    }
    this.db.exec("BEGIN IMMEDIATE");
    this.depth = 1;
    try {
      const out = change();
      this.db.exec("COMMIT");
      return out;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    } finally {
      this.depth = 0;
    }
  }

  /**
   * The same, for a change that awaits part way through — a password set within a
   * SCIM PATCH reaches the key server before it writes here. The transaction is
   * held open across the await, which is sound on one connection in one thread so
   * long as no second change begins meanwhile; `Writer.atomic` is what guarantees
   * that, and nothing else should call this.
   */
  async transactAsync<T>(change: () => Promise<T> | T): Promise<T> {
    if (this.depth > 0) {
      this.depth++;
      try {
        return await change();
      } finally {
        this.depth--;
      }
    }
    this.db.exec("BEGIN IMMEDIATE");
    this.depth = 1;
    try {
      const out = await change();
      this.db.exec("COMMIT");
      return out;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    } finally {
      this.depth = 0;
    }
  }

  // -------------------------------------------------------------------
  // Metadata and counters

  meta(key: string): string | undefined {
    const row = this.q.metaGet.get(key) as { value: string } | undefined;
    return row?.value;
  }

  setMeta(key: string, value: string): void {
    this.q.metaSet.run(key, value);
  }

  /** Whether the store holds any principal, which `dc-import` requires it not to. */
  get empty(): boolean {
    return this.principals().length === 0 && this.units().length === 0;
  }

  /**
   * Sets the first value a counter issues. Called when a store is created, from
   * the ranges the configuration gives; a counter already set is left alone, so
   * that changing a range does not re-issue identifiers already in use.
   */
  seedCounter(name: Counter, from: number): void {
    if (this.q.counterGet.get(name) === undefined) this.q.counterSet.run(name, from);
  }

  /**
   * The next value of a counter, and the counter advanced. The caller is within
   * a transaction, so a value is never issued twice even where two tools write
   * at once: the second waits for the first to commit or rolls back.
   */
  allocate(name: Counter): number {
    const row = this.q.counterGet.get(name) as { next: number } | undefined;
    if (row === undefined) {
      throw new StoreError(`the ${name} counter is not set; the store was not initialized`);
    }
    this.q.counterSet.run(name, row.next + 1);
    return row.next;
  }

  /** What a counter would issue next, without advancing it. */
  peek(name: Counter): number | undefined {
    return (this.q.counterGet.get(name) as { next: number } | undefined)?.next;
  }

  // -------------------------------------------------------------------
  // Organizational units

  units(): Ou[] {
    return (this.q.ouAll.all() as OuRow[]).map(ouOf);
  }

  unit(id: string): Ou | undefined {
    const row = this.q.ou.get(id) as OuRow | undefined;
    return row === undefined ? undefined : ouOf(row);
  }

  unitNamed(parent: string | undefined, name: string): Ou | undefined {
    const row = this.q.ouByName.get(parent ?? "", fold(name)) as OuRow | undefined;
    return row === undefined ? undefined : ouOf(row);
  }

  unitsIn(parent: string | undefined): Ou[] {
    return (this.q.ouChildren.all(parent ?? "") as OuRow[]).map(ouOf);
  }

  /**
   * Whether a unit holds anything: a unit that does is not deleted.
   *
   * The counts are copied out of the row rather than returned as it came. A row
   * from node:sqlite has a null prototype, which a caller comparing it against
   * an object literal finds out the hard way; every other reader here maps its
   * rows, and this one does too.
   */
  unitHolds(id: string): { principals: number; units: number } {
    const row = this.q.ouHolds.get(id, id) as { principals: number; units: number };
    return { principals: row.principals, units: row.units };
  }

  addUnit(u: Omit<Ou, "id" | "created" | "modified" | "groupsId"> & { id?: string }): Ou {
    const id = u.id ?? randomUUID();
    // The second UUID, for the second LDAP entry this one row is served as. Allocated
    // here rather than when the entry is built, because RFC 4530 §2.4 says an entry's
    // UUID is assigned "upon its addition to the directory" and is immutable: one
    // computed per answer would be neither.
    const groupsId = randomUUID();
    const now = new Date();
    this.q.ouInsert.run(id, u.parent ?? null, u.name, fold(u.name), u.description ?? null,
      ISO(now), ISO(now), groupsId);
    return { ...u, id, groupsId, created: now, modified: now };
  }

  /** Updates a unit, which moves its modified time on: a client reads it as an ETag. */
  updateUnit(u: Ou): void {
    this.q.ouUpdate.run(u.parent ?? null, u.name, fold(u.name), u.description ?? null,
      ISO(new Date()), u.id);
  }

  removeUnit(id: string): void {
    this.q.ouDelete.run(id);
  }

  // -------------------------------------------------------------------
  // Principals

  principals(): Principal[] {
    return (this.q.principalAll.all() as PrincipalRow[]).map(principalOf);
  }

  principal(id: string): Principal | undefined {
    const row = this.q.principal.get(id) as PrincipalRow | undefined;
    return row === undefined ? undefined : principalOf(row);
  }

  /** The principal of a name, compared as the realm compares one: folded. */
  named(name: string): Principal | undefined {
    const row = this.q.principalByName.get(fold(name)) as PrincipalRow | undefined;
    return row === undefined ? undefined : principalOf(row);
  }

  /** The principal of a POSIX number, by which an NFS request is resolved. */
  byPosix(kind: Kind, posixId: number): Principal | undefined {
    const row = this.q.principalByPosix.get(kind, posixId) as PrincipalRow | undefined;
    return row === undefined ? undefined : principalOf(row);
  }

  principalsIn(ou: string | undefined): Principal[] {
    return (this.q.principalInOu.all(ou ?? "") as PrincipalRow[]).map(principalOf);
  }

  addPrincipal(p: Omit<Principal, "created" | "modified" | "version">): Principal {
    const now = new Date();
    this.q.principalInsert.run(p.id, p.kind, p.ou ?? null, p.name, fold(p.name),
      p.displayName ?? null, p.sidRid, p.posixId, p.disabled ? 1 : 0,
      p.expires === undefined ? null : ISO(p.expires), p.home ?? null, p.primaryGroup ?? null,
      ISO(now), ISO(now));
    return { ...p, created: now, modified: now, version: 1 };
  }

  /** Writes the mutable columns, and advances the version the front ends report. */
  updatePrincipal(p: Principal): void {
    this.q.principalUpdate.run(p.ou ?? null, p.name, fold(p.name), p.displayName ?? null,
      p.disabled ? 1 : 0, p.expires === undefined ? null : ISO(p.expires),
      p.home ?? null, p.primaryGroup ?? null, ISO(new Date()), p.id);
  }

  /** Removes a principal; its memberships and credentials go with it. */
  removePrincipal(id: string): void {
    this.q.principalDelete.run(id);
  }

  // -------------------------------------------------------------------
  // Memberships: the member names the groups, as the directory always has

  /** Every membership, as pairs of principal identifiers. */
  memberships(): { member: string; group: string }[] {
    return this.q.memberships.all() as { member: string; group: string }[];
  }

  membersOf(group: string): string[] {
    return (this.q.membersOf.all(group) as { member: string }[]).map((r) => r.member);
  }

  addMembership(member: string, group: string): void {
    this.q.memberAdd.run(member, group);
  }

  removeMembership(member: string, group: string): void {
    this.q.memberRemove.run(member, group);
  }

  /** Every membership of one principal, for a write that replaces them all. */
  clearMemberships(member: string): void {
    this.q.memberClear.run(member);
  }

  // -------------------------------------------------------------------
  // Credentials

  allCredentials(): Credential[] {
    return (this.q.credentials.all() as CredentialRow[]).map(credentialOf);
  }

  credentialsOf(principal: string): Credential[] {
    return (this.q.credentialsOf.all(principal) as CredentialRow[]).map(credentialOf);
  }

  /**
   * The credential a request arrives with: an S3 access key identifier, or the
   * fingerprint of a client certificate. Those two kinds and no others, because
   * only their material is unique across the realm (see CREDENTIAL_INDEXES). A
   * Kerberos credential's material is its enctype, which every principal shares,
   * so asking this for one would return whichever row the query reached first and
   * read as though it named a principal. It refuses instead.
   */
  byMaterial(kind: CredentialKind, material: string): Credential | undefined {
    if (kind !== "s3" && kind !== "certificate") {
      throw new StoreError(
        `a ${kind} credential is not looked up by its material, which does not name one principal`);
    }
    const row = this.q.credentialByMaterial.get(kind, material) as CredentialRow | undefined;
    return row === undefined ? undefined : credentialOf(row);
  }

  addCredential(c: Omit<Credential, "id" | "created"> & { id?: string }): Credential {
    const id = c.id ?? randomUUID();
    const now = new Date();
    this.q.credentialAdd.run(id, c.principal, c.kind, c.ref ?? null,
      c.material ?? null, c.detail ?? null, c.value ?? null, ISO(now));
    return { ...c, id, created: now };
  }

  removeCredential(id: string): void {
    this.q.credentialDelete.run(id);
  }

  /** Every credential of one kind a principal holds, for a password that is replaced. */
  clearCredentials(principal: string, kind: CredentialKind): void {
    this.q.credentialClear.run(principal, kind);
  }
}

interface OuRow {
  id: string; parent: string | null; name: string; name_folded: string;
  description: string | null; created: string; modified: string;
  groups_id: string | null;
}

interface PrincipalRow {
  id: string; kind: Kind; ou: string | null; name: string; name_folded: string;
  display_name: string | null; sid_rid: number; posix_id: number; disabled: number;
  expires: string | null; home: string | null; primary_group: string | null;
  created: string; modified: string; version: number;
}

interface CredentialRow {
  id: string; principal: string; kind: CredentialKind; ref: string | null;
  material: string | null; detail: string | null; value: string | null; created: string;
}

const ouOf = (r: OuRow): Ou => ({
  id: r.id,
  ...(r.parent === null ? {} : { parent: r.parent }),
  name: r.name,
  ...(r.description === null ? {} : { description: r.description }),
  created: at(r.created),
  modified: at(r.modified),
  // Null only for a row written before schema 7 and not yet migrated, which
  // `Store.open` does not leave behind.
  ...(r.groups_id === null ? {} : { groupsId: r.groups_id }),
});

const principalOf = (r: PrincipalRow): Principal => ({
  id: r.id,
  kind: r.kind,
  ...(r.ou === null ? {} : { ou: r.ou }),
  name: r.name,
  ...(r.display_name === null ? {} : { displayName: r.display_name }),
  sidRid: r.sid_rid,
  posixId: r.posix_id,
  disabled: r.disabled === 1,
  ...(r.expires === null ? {} : { expires: at(r.expires) }),
  ...(r.home === null ? {} : { home: r.home }),
  ...(r.primary_group === null || r.primary_group === undefined
    ? {} : { primaryGroup: r.primary_group }),
  created: at(r.created),
  modified: at(r.modified),
  version: r.version,
});

const credentialOf = (r: CredentialRow): Credential => ({
  id: r.id,
  principal: r.principal,
  kind: r.kind,
  ...(r.ref === null ? {} : { ref: r.ref }),
  ...(r.material === null ? {} : { material: r.material }),
  ...(r.detail === null ? {} : { detail: r.detail }),
  ...(r.value === null || r.value === undefined ? {} : { value: r.value }),
  created: at(r.created),
});
