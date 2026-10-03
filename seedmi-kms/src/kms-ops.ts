// Operating seedmi-kms: a backup taken while it serves, and a health check.
//
//   node src/kms-ops.ts backup --store ./kms-data --to ./backups/kms.db
//   node src/kms-ops.ts health --host 127.0.0.1 --port 5696 --ca server-ca.pem
//
// A backup is taken from a connection of its own to the store's database, so
// it needs nothing of the running server and does not stop it. SQLite writes a
// consistent copy while the server goes on writing, and the copy opens as a
// store of its own: restoring it is copying it into an empty store directory,
// as kms.db, with the server stopped.
//
// The health check connects as a client with no certificate and asks the
// server which protocol versions it speaks. KMIP answers Discover Versions and
// Query without a client certificate (Profiles 3.1.3), so a check needs no
// credential of its own, and learns that the server is up, that its
// certificate is one the authority given issued, and that it speaks KMIP.

import { DatabaseSync } from "node:sqlite";
import { existsSync, mkdirSync, readFileSync, renameSync } from "node:fs";
import * as path from "node:path";
import { CLIENT_VERSIONS, KmipClient, ops } from "./kmip-client.ts";

/** Writes a consistent copy of a store's database, while the server serves. */
export function backupStore(storeDir: string, to: string): void {
  const db = path.join(storeDir, "kms.db");
  if (!existsSync(db)) throw new Error(`${storeDir} is not a seedmi-kms store: it holds no kms.db`);
  const target = path.resolve(to);
  if (existsSync(target)) throw new Error(`${to} exists already; a backup does not overwrite one`);
  mkdirSync(path.dirname(target), { recursive: true });
  const source = new DatabaseSync(db);
  try {
    // VACUUM INTO writes the whole database as it stands at one moment,
    // whatever the server writes meanwhile; a copy of the file would not be
    // consistent while the server has changes in its write-ahead log.
    source.exec(`VACUUM INTO '${`${target}.part`.replace(/'/g, "''")}'`);
  } finally {
    source.close();
  }
  renameSync(`${target}.part`, target);
}

/** What a health check learned. */
export interface Health {
  ok: boolean;
  /** The protocol versions the server offered, most preferred first. */
  versions?: string[];
  /** Why the server could not be reached, where it could not. */
  problem?: string;
}

/** Asks a server which versions it speaks, with no client certificate. */
export async function checkHealth(opts: { host: string; port: number; ca: string; timeoutMs?: number }):
  Promise<Health> {
  const client = new KmipClient({ host: opts.host, port: opts.port, ca: opts.ca, timeoutMs: opts.timeoutMs ?? 5000 });
  try {
    // Discover Versions with every version this client speaks: the server
    // answers with those it shares, most preferred first.
    const versions = await client.run(ops.discoverVersions(CLIENT_VERSIONS));
    return { ok: true, versions: versions.map((v) => `${v.major}.${v.minor}`) };
  } catch (e) {
    return { ok: false, problem: (e as Error).message };
  } finally {
    client.close();
  }
}

const USAGE = `kms-ops: operating seedmi-kms.

Usage:
  node src/kms-ops.ts backup --store <dir> --to <file>
      write a consistent copy of the store while the server serves; the copy
      is restored by placing it, as kms.db, in an empty store directory with
      the server stopped

  node src/kms-ops.ts health --host <address> --port <port> --ca <file>
      ask the server which protocol versions it speaks, with no client
      certificate; exits 0 where it answers and 1 where it does not
`;

const asProgram = process.argv[1] !== undefined && path.basename(process.argv[1]) === "kms-ops.ts";

if (asProgram) {
  const [command, ...rest] = process.argv.slice(2);
  const flag = (name: string): string | undefined => {
    const i = rest.indexOf(name);
    return i < 0 ? undefined : rest[i + 1];
  };
  const need = (name: string): string => {
    const v = flag(name);
    if (v === undefined) {
      process.stderr.write(`kms-ops: ${command} needs ${name}\n`);
      process.exit(2);
    }
    return v;
  };
  if (command === undefined || command === "--help" || command === "-h") {
    process.stdout.write(USAGE);
    process.exit(command === undefined ? 2 : 0);
  }
  if (command === "backup") {
    try {
      backupStore(need("--store"), need("--to"));
      process.stdout.write(`kms-ops: backup written to ${flag("--to")}\n`);
      process.exit(0);
    } catch (e) {
      process.stderr.write(`kms-ops: ${(e as Error).message}\n`);
      process.exit(2);
    }
  } else if (command === "health") {
    const health = await checkHealth({
      host: need("--host"), port: Number(need("--port")), ca: readFileSync(need("--ca"), "utf8"),
    });
    if (health.ok) {
      process.stdout.write(`kms-ops: healthy, speaking KMIP ${health.versions!.join(", ")}\n`);
      process.exit(0);
    }
    process.stdout.write(`kms-ops: not healthy: ${health.problem}\n`);
    process.exit(1);
  } else {
    process.stderr.write(`kms-ops: ${command} is not a command; --help lists them\n`);
    process.exit(2);
  }
}
