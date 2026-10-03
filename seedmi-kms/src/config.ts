// The configuration of the key management server: a TOML file, the command
// line, or both, with a flag winning over the file.
//
// The settings are the server's own: where it listens, the certificate it
// presents, the authority whose certificates identify its clients, where its
// store lives, and what it logs. There is nothing of CDMI here: this program
// serves KMIP, and what its clients do with the objects they register is
// their affair.

import { readFileSync } from "node:fs";
import * as path from "node:path";
import { type TOMLValue, parseTOML } from "./toml.ts";
import { type Admission, DEGREES, type Degree } from "./kms-prefixes.ts";

/** A configuration that cannot be used, named so that it can be corrected. */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export interface Config {
  /** Where the store lives. */
  store: string;
  host: string;
  port: number;
  /** The certificate chain this server presents, in PEM. */
  cert: string;
  /** Its private key, in PEM. */
  key: string;
  /** The authority whose certificates identify clients, in PEM. */
  ca: string;
  /** What is logged: nothing, refusals alone, or every operation. */
  log: "off" | "problems" | "requests";
  logFile?: string;
  logFormat: "text" | "json";
  /** What this server calls itself in a Query response. */
  vendor: string;
  /**
   * Prefixes claimed by no one, where any client may register and each object
   * belongs to the client that created it.
   */
  shared: string[];
  /** What identities other than a prefix's holder may do beneath it. */
  admit: Admission[];
}

export const DEFAULTS: Config = {
  store: "./kms-data",
  host: "127.0.0.1",
  port: 5696,
  cert: "",
  key: "",
  ca: "",
  log: "off",
  logFormat: "text",
  vendor: "seedmi-kms",
  shared: [],
  admit: [],
};

const table = (v: TOMLValue | undefined, where: string): Record<string, TOMLValue> => {
  if (v === undefined) return {};
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new ConfigError(`${where} shall be a table`);
  }
  return v as Record<string, TOMLValue>;
};

const only = (t: Record<string, TOMLValue>, where: string, keys: string[]): void => {
  for (const k of Object.keys(t)) {
    if (!keys.includes(k)) {
      throw new ConfigError(`${where}.${k} is not a setting; the settings are ${keys.join(", ")}`);
    }
  }
};

const str = (t: Record<string, TOMLValue>, k: string, where: string): string | undefined => {
  const v = t[k];
  if (v === undefined) return undefined;
  if (typeof v !== "string") throw new ConfigError(`${where}.${k} shall be a string`);
  return v;
};

const int = (t: Record<string, TOMLValue>, k: string, where: string): number | undefined => {
  const v = t[k];
  if (v === undefined) return undefined;
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new ConfigError(`${where}.${k} shall be a whole number`);
  }
  return v;
};

/**
 * Material given either in the file or in a file beside it: `cert` holds the
 * PEM, `cert_file` names a file holding it, and naming both is an error
 * rather than a silent preference.
 */
function material(t: Record<string, TOMLValue>, k: string, where: string, dir: string): string | undefined {
  const inline = str(t, k, where);
  const named = str(t, `${k}_file`, where);
  if (inline !== undefined && named !== undefined) {
    throw new ConfigError(`${where} gives both ${k} and ${k}_file; give one`);
  }
  if (inline !== undefined) return inline;
  if (named === undefined) return undefined;
  const at = path.isAbsolute(named) ? named : path.join(dir, named);
  try {
    return readFileSync(at, "utf8");
  } catch {
    throw new ConfigError(`${where}.${k}_file names ${named}, which could not be read`);
  }
}

/** Reads a configuration file. */
export function parseConfig(text: string, dir = "."): Config {
  let doc: Record<string, TOMLValue>;
  try {
    doc = parseTOML(text) as Record<string, TOMLValue>;
  } catch (e) {
    throw new ConfigError(`the configuration is not TOML: ${(e as Error).message}`);
  }
  only(doc, "the configuration", ["server", "store", "log", "shared", "admit"]);
  const c: Config = { ...DEFAULTS, shared: [], admit: [] };

  const store = table(doc.store, "[store]");
  only(store, "[store]", ["path"]);
  const at = str(store, "path", "[store]");
  if (at !== undefined) c.store = path.isAbsolute(at) ? at : path.join(dir, at);

  const server = table(doc.server, "[server]");
  only(server, "[server]", ["host", "port", "cert", "cert_file", "key", "key_file",
    "ca", "ca_file", "vendor"]);
  c.host = str(server, "host", "[server]") ?? c.host;
  c.port = int(server, "port", "[server]") ?? c.port;
  c.vendor = str(server, "vendor", "[server]") ?? c.vendor;
  c.cert = material(server, "cert", "[server]", dir) ?? "";
  c.key = material(server, "key", "[server]", dir) ?? "";
  c.ca = material(server, "ca", "[server]", dir) ?? "";

  // [[shared]] tables, each naming a prefix claimed by no one.
  const sharedTables = doc.shared === undefined ? [] : doc.shared;
  if (!Array.isArray(sharedTables)) throw new ConfigError("[[shared]] is an array of tables");
  for (const [i, t] of sharedTables.entries()) {
    const where = `[[shared]][${i}]`;
    const entry = table(t as TOMLValue, where);
    only(entry, where, ["prefix"]);
    const prefix = str(entry, "prefix", where);
    if (prefix === undefined || prefix === "") throw new ConfigError(`${where}.prefix names a prefix`);
    if (!prefix.endsWith("/")) throw new ConfigError(`${where}.prefix ends with "/"`);
    c.shared.push(prefix);
  }

  // [[admit]] tables: an identity, a prefix, and the degree it is admitted to.
  const admitTables = doc.admit === undefined ? [] : doc.admit;
  if (!Array.isArray(admitTables)) throw new ConfigError("[[admit]] is an array of tables");
  for (const [i, t] of admitTables.entries()) {
    const where = `[[admit]][${i}]`;
    const entry = table(t as TOMLValue, where);
    only(entry, where, ["prefix", "group", "identity", "degree"]);
    const prefix = str(entry, "prefix", where);
    const group = str(entry, "group", where);
    const identity = str(entry, "identity", where);
    const degree = str(entry, "degree", where);
    // One of the two keys, or both. A table with neither would admit every
    // object, which is not something an operator writes by accident and is not
    // something this server infers for them.
    if (prefix === undefined && group === undefined) {
      throw new ConfigError(
        `${where} names what it admits: a prefix of the Name, a group the object is in, or both`);
    }
    if (prefix !== undefined && !prefix.endsWith("/")) {
      throw new ConfigError(`${where}.prefix names a prefix ending with "/"`);
    }
    if (group === "") throw new ConfigError(`${where}.group names an Object Group`);
    if (identity === undefined || identity === "") {
      throw new ConfigError(`${where}.identity names a client, or "*" for every authenticated client`);
    }
    if (degree === undefined || !(DEGREES as readonly string[]).includes(degree)) {
      throw new ConfigError(`${where}.degree is one of ${DEGREES.join(", ")}`);
    }
    c.admit.push({
      ...(prefix === undefined ? {} : { prefix }),
      ...(group === undefined ? {} : { group }),
      identity, degree: degree as Degree,
    });
  }

  const log = table(doc.log, "[log]");
  only(log, "[log]", ["level", "file", "format"]);
  const level = str(log, "level", "[log]");
  if (level !== undefined) {
    if (level !== "off" && level !== "problems" && level !== "requests") {
      throw new ConfigError('[log].level is "off", "problems" or "requests"');
    }
    c.log = level;
  }
  const format = str(log, "format", "[log]");
  if (format !== undefined) {
    if (format !== "text" && format !== "json") {
      throw new ConfigError('[log].format is "text" or "json"');
    }
    c.logFormat = format;
  }
  const file = str(log, "file", "[log]");
  if (file !== undefined) c.logFile = path.isAbsolute(file) ? file : path.join(dir, file);
  return c;
}

/**
 * Applies the command line over a configuration. A flag this program does not
 * take is refused rather than ignored, so that a misspelling does not start
 * the server with the setting it was meant to change.
 */
export function applyArgv(c: Config, argv: string[]): Config {
  const out = { ...c };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const value = (): string => {
      const v = argv[++i];
      if (v === undefined) throw new ConfigError(`${flag} needs a value`);
      return v;
    };
    switch (flag) {
      case "--store": out.store = value(); break;
      case "--host": out.host = value(); break;
      case "--port": {
        const v = Number(value());
        if (!Number.isInteger(v) || v < 0 || v > 65535) throw new ConfigError("--port takes a port number");
        out.port = v;
        break;
      }
      case "--log": {
        const v = value();
        if (v !== "off" && v !== "problems" && v !== "requests") {
          throw new ConfigError('--log takes "off", "problems" or "requests"');
        }
        out.log = v;
        break;
      }
      case "--log-file": out.logFile = value(); break;
      case "--log-format": {
        const v = value();
        if (v !== "text" && v !== "json") throw new ConfigError('--log-format takes "text" or "json"');
        out.logFormat = v;
        break;
      }
      default:
        throw new ConfigError(`${flag} is not a flag this program takes; --help lists them`);
    }
  }
  return out;
}

/** What must be present before the server can listen. */
export function checkComplete(c: Config): void {
  for (const [what, value] of [["certificate", c.cert], ["private key", c.key],
    ["authority", c.ca]] as [string, string][]) {
    if (value.trim() === "") {
      throw new ConfigError(
        `no ${what} is configured: [server] needs cert, key and ca, or the _file form of each`);
    }
  }
}
