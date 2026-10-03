// The configuration of seedmi-zone: a TOML file, and flags that win over it.
//
//   [link]      interfaces, ipv6, browse (the domains browsed)
//   [zone]      name, ttl_host, ttl_other, sweep_interval_ms, allow, ca(_file)
//   [update]    host, port, key_name, key_algorithm, key_secret(_file)
//   [unbound]   command, args
//   [log]       level, file
//
// One of [update] and [unbound] is given: they are the two ways of writing the
// zone, not two halves of one way.
//
// A setting this program does not take is refused rather than ignored, so a
// misspelling does not start the program without the setting it was meant to
// change.

import { readFileSync } from "node:fs";
import * as path from "node:path";
import { labels, type Name, presentation } from "./dns.ts";
import { ALGORITHMS, type TsigKey } from "./tsig.ts";
import { parseTOML, type TOMLValue } from "./toml.ts";

export class ConfigError extends Error {}

export type LogLevel = "off" | "problems" | "sweeps";
export const LOG_LEVELS: LogLevel[] = ["off", "problems", "sweeps"];

export interface Config {
  interfaces: string[];
  ipv6: boolean;
  /** The browsing domains this program browses, normally ["local"]. */
  browse: Name[];
  /** The subtree written, which this program owns and writes nothing outside. */
  zone: Name;
  ttlHost: number;
  ttlOther: number;
  sweepIntervalMs: number;
  /** Instance labels admitted, where any are given; all of them where none is. */
  allow: RegExp[];
  /** Anchors for the gate's certificate, where the system does not trust the issuer. */
  ca?: string;
  update?: { host: string; port: number; key: TsigKey };
  unbound?: { command: string; args: string[] };
  log: LogLevel;
  logFile?: string;
}

export const DEFAULTS: Config = {
  interfaces: [], ipv6: true, browse: [["local"]], zone: [], ttlHost: 120, ttlOther: 300,
  sweepIntervalMs: 60_000, allow: [], log: "problems",
};

type Table = Record<string, TOMLValue>;
const table = (v: TOMLValue | undefined, where: string): Table => {
  if (v === undefined) return {};
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new ConfigError(`${where} is a table`);
  return v as Table;
};
const only = (t: Table, where: string, allowed: string[]) => {
  for (const k of Object.keys(t)) {
    if (!allowed.includes(k)) throw new ConfigError(`${where} takes no setting ${JSON.stringify(k)}`);
  }
};
const str = (t: Table, k: string, where: string): string | undefined => {
  const v = t[k];
  if (v === undefined) return undefined;
  if (typeof v !== "string") throw new ConfigError(`${where}.${k} is a string`);
  return v;
};
const bool = (t: Table, k: string, where: string): boolean | undefined => {
  const v = t[k];
  if (v === undefined) return undefined;
  if (typeof v !== "boolean") throw new ConfigError(`${where}.${k} is true or false`);
  return v;
};
const int = (t: Table, k: string, where: string): number | undefined => {
  const v = t[k];
  if (v === undefined) return undefined;
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
    throw new ConfigError(`${where}.${k} is a whole number`);
  }
  return v;
};
const strings = (t: Table, k: string, where: string): string[] | undefined => {
  const v = t[k];
  if (v === undefined) return undefined;
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
    throw new ConfigError(`${where}.${k} is a list of strings`);
  }
  return v as string[];
};
const material = (t: Table, k: string, where: string, dir: string): string | undefined => {
  const inline = str(t, k, where);
  const file = str(t, `${k}_file`, where);
  if (inline !== undefined && file !== undefined) {
    throw new ConfigError(`${where} gives ${k} and ${k}_file; one is given`);
  }
  if (file === undefined) return inline;
  try {
    return readFileSync(path.isAbsolute(file) ? file : path.join(dir, file), "utf8");
  } catch (e) {
    throw new ConfigError(`${where}.${k}_file cannot be read: ${(e as Error).message}`);
  }
};

const name = (s: string, where: string): Name => {
  const n = labels(s);
  if (n.length === 0) throw new ConfigError(`${where} is a DNS name, and this is the root`);
  for (const label of n) {
    if (label === "") throw new ConfigError(`${where}: ${JSON.stringify(s)} holds an empty label`);
    if (new TextEncoder().encode(label).length > 63) {
      throw new ConfigError(`${where}: ${JSON.stringify(s)} holds a label longer than 63 octets`);
    }
  }
  return n;
};

export function parseConfig(text: string, dir = "."): Config {
  const doc = parseTOML(text);
  only(doc, "the configuration", ["link", "zone", "update", "unbound", "log"]);
  const c: Config = { ...DEFAULTS, interfaces: [], browse: [], zone: [], allow: [] };

  const link = table(doc.link, "[link]");
  only(link, "[link]", ["interfaces", "ipv6", "browse"]);
  c.interfaces = strings(link, "interfaces", "[link]") ?? [];
  c.ipv6 = bool(link, "ipv6", "[link]") ?? true;
  c.browse = (strings(link, "browse", "[link]") ?? ["local"]).map((s) => name(s, "[link].browse"));
  if (c.browse.length === 0) throw new ConfigError("[link].browse is a non-empty list of browsing domains");

  const zone = table(doc.zone, "[zone]");
  only(zone, "[zone]", ["name", "ttl_host", "ttl_other", "sweep_interval_ms", "allow", "ca", "ca_file"]);
  const zn = str(zone, "name", "[zone]");
  if (zn === undefined) {
    throw new ConfigError("[zone].name gives the subtree this program writes; there is nowhere to publish without one");
  }
  c.zone = name(zn, "[zone].name");
  c.ttlHost = int(zone, "ttl_host", "[zone]") ?? 120;
  c.ttlOther = int(zone, "ttl_other", "[zone]") ?? 300;
  c.sweepIntervalMs = int(zone, "sweep_interval_ms", "[zone]") ?? 60_000;
  if (c.sweepIntervalMs < 5000) {
    // A sweep asks the link and then makes a TLS connection per instance. More
    // often than this is a load on every CDMI server on the link, to publish
    // records whose lifetimes are longer than the interval anyway.
    throw new ConfigError("[zone].sweep_interval_ms is at least 5000");
  }
  for (const pattern of strings(zone, "allow", "[zone]") ?? []) {
    try {
      c.allow.push(new RegExp(pattern));
    } catch (e) {
      throw new ConfigError(`[zone].allow holds ${JSON.stringify(pattern)}, which is not a pattern: ` +
        (e as Error).message);
    }
  }
  const ca = material(zone, "ca", "[zone]", dir);
  if (ca !== undefined) c.ca = ca;

  const update = table(doc.update, "[update]");
  if (Object.keys(update).length > 0) {
    only(update, "[update]", ["host", "port", "key_name", "key_algorithm", "key_secret", "key_secret_file"]);
    const host = str(update, "host", "[update]");
    if (host === undefined) throw new ConfigError("[update].host names the name server the update is sent to");
    const keyName = str(update, "key_name", "[update]");
    if (keyName === undefined) throw new ConfigError("[update].key_name names the TSIG key");
    const algorithm = (str(update, "key_algorithm", "[update]") ?? "hmac-sha256").toLowerCase();
    if (!(algorithm in ALGORITHMS)) {
      throw new ConfigError(`[update].key_algorithm is one of ${Object.keys(ALGORITHMS).join(", ")}`);
    }
    const secret = material(update, "key_secret", "[update]", dir);
    if (secret === undefined) throw new ConfigError("[update].key_secret gives the shared secret, base64");
    let octets: Uint8Array;
    try {
      octets = new Uint8Array(Buffer.from(secret.trim(), "base64"));
    } catch {
      octets = new Uint8Array(0);
    }
    if (octets.length === 0) throw new ConfigError("[update].key_secret is the shared secret in base64");
    c.update = {
      host,
      port: int(update, "port", "[update]") ?? 53,
      key: { name: name(keyName, "[update].key_name"), algorithm, secret: octets },
    };
  }

  const unbound = table(doc.unbound, "[unbound]");
  if (Object.keys(unbound).length > 0) {
    only(unbound, "[unbound]", ["command", "args"]);
    c.unbound = {
      command: str(unbound, "command", "[unbound]") ?? "unbound-control",
      args: strings(unbound, "args", "[unbound]") ?? [],
    };
  }

  const log = table(doc.log, "[log]");
  only(log, "[log]", ["level", "file"]);
  const level = str(log, "level", "[log]");
  if (level !== undefined) {
    if (!LOG_LEVELS.includes(level as LogLevel)) {
      throw new ConfigError(`[log].level is one of ${LOG_LEVELS.join(", ")}`);
    }
    c.log = level as LogLevel;
  }
  const file = str(log, "file", "[log]");
  if (file !== undefined) c.logFile = path.isAbsolute(file) ? file : path.join(dir, file);
  return c;
}

const FLAGS: Record<string, boolean> = {
  "--config": true, "--log": true, "--log-file": true, "--once": false, "--dry-run": false,
  "--help": false, "-h": false, "--version": false, "-v": false,
};

export function readArgv(argv: string[]): Record<string, string | true> {
  const out: Record<string, string | true> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (!(a in FLAGS)) throw new ConfigError(`${a} is not a flag of this program; --help lists them`);
    if (FLAGS[a]) {
      if (i + 1 >= argv.length) throw new ConfigError(`${a} takes a value`);
      out[a] = argv[++i]!;
    } else {
      out[a] = true;
    }
  }
  return out;
}

export function applyFlags(c: Config, f: Record<string, string | true>): Config {
  const out = { ...c };
  if (typeof f["--log"] === "string") {
    if (!LOG_LEVELS.includes(f["--log"] as LogLevel)) {
      throw new ConfigError(`--log is one of ${LOG_LEVELS.join(", ")}`);
    }
    out.log = f["--log"] as LogLevel;
  }
  if (typeof f["--log-file"] === "string") out.logFile = f["--log-file"];
  return out;
}

export function checkComplete(c: Config): void {
  if (c.update === undefined && c.unbound === undefined) {
    throw new ConfigError("neither [update] nor [unbound] is given: there is nowhere to write what the link offers");
  }
  if (c.update !== undefined && c.unbound !== undefined) {
    throw new ConfigError("[update] and [unbound] are two ways of writing the zone, and one is given: " +
      "two writers on one subtree undo each other's work");
  }
  // Publishing into a browsing domain would have this program write the names
  // it is reading, and read back what it wrote.
  for (const d of c.browse) {
    if (d.length === c.zone.length && d.every((l, i) => l.toLowerCase() === c.zone[i]!.toLowerCase())) {
      throw new ConfigError(`[zone].name is ${presentation(c.zone)}, which [link].browse also browses: ` +
        "the zone written and the domain browsed are different places");
    }
  }
}
