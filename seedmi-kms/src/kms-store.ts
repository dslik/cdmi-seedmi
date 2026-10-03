// The store of the key management server: a directory holding a SQLite
// database of the managed objects, and nothing of CDMI.
//
// The core (kms-core.ts) keeps its objects in memory and writes each one
// through a KmsStorage of two methods, so what is kept here is the record
// format the core already writes: one JSON document for each managed object,
// each of its TTLV items carried as base 64. This store neither reads nor
// interprets those documents; the core owns their shape.
//
// This program shares no file with a CDMI server. Its store is its own, its
// schema is its own, and a CDMI server has no access to either: a key
// management server holding the credentials of every object a CDMI server
// serves has a different lifetime, a different backup regime and a different
// set of administrators, which is the reason for the separation.

import { DatabaseSync, type StatementSync } from "node:sqlite";
import { mkdir, rename, writeFile } from "node:fs/promises";
import * as path from "node:path";
import type { KmsStorage } from "./kms-core.ts";

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- One managed object, as the core records it: JSON holding the TTLV
-- encoding of each attribute and of the object itself, in base 64. The
-- identifier is the Unique Identifier the core assigned.
CREATE TABLE IF NOT EXISTS managed_object (
  id      TEXT PRIMARY KEY,
  record  TEXT NOT NULL,
  -- When the row was last written, for an operator reading the database
  -- directly; the core records its own times within the record.
  written INTEGER NOT NULL
);

-- Values of the server itself that are not managed objects.
CREATE TABLE IF NOT EXISTS server_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`;

interface Statements {
  load: StatementSync;
  put: StatementSync;
  remove: StatementSync;
  count: StatementSync;
  getMeta: StatementSync;
  putMeta: StatementSync;
  setMeta: StatementSync;
}

/**
 * The managed objects of a key management server, kept in a directory of its
 * own. Every write is one transaction, so an interruption loses at most the
 * operation in flight and never half of one.
 */
export class KmsStore implements KmsStorage {
  private readonly db: DatabaseSync;
  private readonly q: Statements;
  readonly dir: string;

  private constructor(dir: string, db: DatabaseSync, q: Statements) {
    this.dir = dir;
    this.db = db;
    this.q = q;
  }

  /** Opens the store in a directory, creating it where it does not exist. */
  static async open(dir: string): Promise<KmsStore> {
    await mkdir(dir, { recursive: true });
    const db = new DatabaseSync(path.join(dir, "kms.db"));
    db.exec(SCHEMA);
    return new KmsStore(dir, db, {
      load: db.prepare("SELECT record FROM managed_object ORDER BY rowid"),
      put: db.prepare(
        "INSERT INTO managed_object (id, record, written) VALUES (?, ?, ?) " +
        "ON CONFLICT(id) DO UPDATE SET record = excluded.record, written = excluded.written"),
      remove: db.prepare("DELETE FROM managed_object WHERE id = ?"),
      count: db.prepare("SELECT count(*) AS n FROM managed_object"),
      getMeta: db.prepare("SELECT value FROM server_meta WHERE key = ?"),
      putMeta: db.prepare("INSERT OR IGNORE INTO server_meta (key, value) VALUES (?, ?)"),
      setMeta: db.prepare("UPDATE server_meta SET value = ? WHERE key = ?"),
    });
  }

  /** Every record held, as the core reads them at start. */
  load(): string[] {
    return (this.q.load.all() as { record: string }[]).map((r) => r.record);
  }

  /**
   * Writes the records given, in one transaction: the core hands over every
   * object it changed in an operation, so either the operation is recorded
   * whole or none of it is.
   */
  save(records: { id: string; record: string }[]): void {
    if (records.length === 0) return;
    const now = Date.now();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      for (const r of records) this.q.put.run(r.id, r.record, now);
      this.db.exec("COMMIT");
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }

  /**
   * Removes a record. KMIP keeps a destroyed object and records its State, so
   * the core does not ask for this; it is here for an operator clearing a
   * store and for the tests.
   */
  forget(id: string): void {
    this.q.remove.run(id);
  }

  /** How many managed objects are held. */
  get size(): number {
    return Number((this.q.count.get() as { n: number }).n);
  }

  /** A value of the server itself, such as the identity of its own key. */
  meta(key: string): string | undefined {
    return (this.q.getMeta.get(key) as { value: string } | undefined)?.value;
  }

  /** Records a value of the server itself, replacing the one held. */
  setMeta(key: string, value: string): void {
    this.q.putMeta.run(key, value);
    this.q.setMeta.run(value, key);
  }

  /**
   * Writes a copy of the store to a file, for a backup taken while serving.
   * SQLite's own backup is used, so the copy is consistent without stopping.
   */
  async backup(to: string): Promise<void> {
    const target = path.resolve(to);
    await mkdir(path.dirname(target), { recursive: true });
    // A plain copy of a database being written is not a backup; the VACUUM
    // INTO form writes a consistent copy of the whole database.
    this.db.exec(`VACUUM INTO ${quote(`${target}.part`)}`);
    await rename(`${target}.part`, target);
  }

  close(): void {
    this.db.close();
  }
}

/** A string as SQL writes one, for the file name of a backup. */
const quote = (s: string): string => `'${s.replace(/'/g, "''")}'`;

/** Writes a file so that a reader sees all of it or none: for an export. */
export async function writeWhole(to: string, content: string): Promise<void> {
  await writeFile(`${to}.part`, content);
  await rename(`${to}.part`, to);
}
