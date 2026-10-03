// seedmi-kms: a KMIP 1.4 key management server, run on its own.
//
//   node src/kmsd.ts --config kms.toml
//
// It serves the core of kms-core.ts over TLS, as the KMIP Profiles Basic
// Authentication Suite requires, keeping its managed objects in a store of
// its own. It holds nothing of CDMI and shares no file with a CDMI server:
// a key management server holding the credentials of the objects a CDMI
// server serves has a different lifetime, a different backup regime and a
// different set of administrators.

import { appendFileSync } from "node:fs";
import { PrefixedCore, Prefixes } from "./kms-prefixes.ts";
import { KmipServer } from "./kmip-server.ts";
import { KmsStore } from "./kms-store.ts";
import { applyArgv, checkComplete, type Config, ConfigError, DEFAULTS, parseConfig } from "./config.ts";
import { readFileSync } from "node:fs";
import * as path from "node:path";

export const VERSION = "1.1";

const USAGE = `seedmi-kms: a KMIP 1.4 key management server.

Usage: node src/kmsd.ts [flags]

  --config <path>                  read settings from a TOML file
  --store <path>                   the directory the store lives in
  --host <address>                 the address to listen on
  --port <port>                    the port to listen on
  --log <off|problems|requests>    what to log; nothing is logged unless this is given
  --log-file <path>                write the log there, not to stderr
  --log-format <text|json>         how each line is written
  --help                           print this text and exit (also -h)
  --version                        print the version and exit (also -v)

SIGHUP re-reads the configuration and presents the certificate, key and
authority it names from the next connection, dropping none already made.

A configuration file gives [server] (host, port, cert, key, ca, vendor),
[store] (path) and [log] (level, file, format). A flag wins over the file.
`;

/** Writes a line of the log, where the level asks for it. */
export function logger(c: Config): (level: "problems" | "requests", event: Record<string, unknown>) => void {
  if (c.log === "off") return () => undefined;
  const wanted = c.log === "requests" ? ["problems", "requests"] : ["problems"];
  return (level, event) => {
    if (!wanted.includes(level)) return;
    const at = new Date().toISOString();
    // A log never carries key material, a secret, or the value of a managed
    // object: what is recorded is who asked for what and how it ended.
    const line = c.logFormat === "json"
      ? JSON.stringify({ time: at, ...event })
      : `${at} ${Object.entries(event).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(" ")}`;
    if (c.logFile === undefined) process.stderr.write(`${line}\n`);
    else appendFileSync(c.logFile, `${line}\n`);
  };
}

/** Reads the configuration a command line asks for. */
export function configure(argv: string[]): Config {
  const at = argv.indexOf("--config");
  let c = { ...DEFAULTS };
  const rest = [...argv];
  if (at >= 0) {
    const file = rest[at + 1];
    if (file === undefined) throw new ConfigError("--config needs a path");
    rest.splice(at, 2);
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      throw new ConfigError(`the configuration file ${file} could not be read`);
    }
    c = parseConfig(text, path.dirname(path.resolve(file)));
  }
  return applyArgv(c, rest);
}

/** Starts the server, and returns what stops it and what reloads its certificate. */
export async function start(c: Config): Promise<{
  port: number;
  host: string;
  store: KmsStore;
  /** Presents another certificate, and trusts another authority, from the next connection. */
  reload: (next: Config) => void;
  stop: () => Promise<void>;
}> {
  checkComplete(c);
  const store = await KmsStore.open(c.store);
  const log = logger(c);
  // The core with the prefix claims enforced (kms-prefixes.ts): a client
  // claims a prefix by registering beneath it, and no other client may.
  const prefixes = new Prefixes(store, c.shared);
  // [[admit]] tables let identities other than a prefix's holder act beneath
  // it, to the degree the operator sets.
  const core = new PrefixedCore(prefixes, { storage: store }, c.admit);
  const server = new KmipServer({
    core,
    cert: c.cert,
    key: c.key,
    ca: c.ca,
    vendorIdentification: c.vendor,
    // Each connection and each operation is logged at "requests"; an
    // operation that did not succeed is logged at "problems" too. What is
    // logged is who, what, how it ended and which object, and nothing of a
    // payload: no key material, no secret, no attribute value.
    onConnection: (e) => log("requests", {
      event: "connection", identity: e.identity ?? "(no certificate)", address: e.address ?? "",
    }),
    onOperation: (e) => log(e.status === "Success" ? "requests" : "problems", {
      event: "operation", identity: e.identity ?? "(no certificate)", operation: e.operation,
      status: e.status, ...(e.reason === undefined ? {} : { reason: e.reason }),
      ...(e.uniqueIdentifier === undefined ? {} : { object: e.uniqueIdentifier }),
    }),
  });
  const at = await server.listen(c.port, c.host);
  log("problems", { event: "listening", host: at.host, port: at.port, objects: store.size });
  return {
    ...at,
    store,
    reload: (next: Config) => {
      checkComplete(next);
      server.reload({ cert: next.cert, key: next.key, ca: next.ca });
      log("problems", { event: "reloaded", what: "certificate, key and authority" });
    },
    stop: async () => {
      log("problems", { event: "stopping" });
      await server.close();
      store.close();
    },
  };
}

/** Run as a program rather than imported by a test. */
// Run as a program, not imported by a test: the test file is kmsd.test.ts,
// which starts with the same characters, so the whole name is compared.
const asProgram = process.argv[1] !== undefined &&
  path.basename(process.argv[1]) === "kmsd.ts";

if (asProgram) {
  const argv = process.argv.slice(2);
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write(USAGE);
    process.exit(0);
  }
  if (argv.includes("--version") || argv.includes("-v")) {
    process.stdout.write(`seedmi-kms ${VERSION}\n`);
    process.exit(0);
  }
  let config: Config;
  try {
    config = configure(argv);
  } catch (e) {
    process.stderr.write(`seedmi-kms: ${(e as Error).message}\n`);
    process.exit(2);
  }
  let running;
  try {
    running = await start(config);
  } catch (e) {
    process.stderr.write(`seedmi-kms: ${(e as Error).message}\n`);
    process.exit(2);
  }
  process.stdout.write(`seedmi-kms ${VERSION} listening on ${running.host}:${running.port}, ` +
    `store ${config.store}\n`);
  // SIGHUP re-reads the configuration and presents the certificate, key and
  // authority it now names, from the next connection: the server's own
  // certificate is rotated without dropping a connection already made. Only
  // those are reloaded; a change of address, store or log needs a restart.
  process.on("SIGHUP", () => {
    try {
      running.reload(configure(argv));
    } catch (e) {
      process.stderr.write(`seedmi-kms: the configuration was not reloaded: ${(e as Error).message}\n`);
    }
  });
  let stopping = false;
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
      if (stopping) return;
      stopping = true;
      // The operation in flight finishes: close waits for the connections it
      // is serving before the store is closed.
      void running.stop().then(() => process.exit(0));
    });
  }
}
