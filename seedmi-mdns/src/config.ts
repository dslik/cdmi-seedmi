// The configuration of seedmi-mdns: a TOML file, and flags that win over it.
//
//   [link]        interfaces, ipv6
//   [[instance]]  each CDMI server advertised on this host: name, domain,
//                 target, port, ver, display, addresses, and the well-known
//                 check that decides whether it is advertised at all
//   [log]         level, file
//
// A setting this program does not take is refused rather than ignored, so a
// misspelling does not start the responder without the setting it was meant to
// change.

import { readFileSync } from "node:fs";
import * as path from "node:path";
import { labels, type Name, presentation } from "./dns.ts";
import { parseTOML, type TOMLValue } from "./toml.ts";

export class ConfigError extends Error {}

export type LogLevel = "off" | "problems" | "records";
export const LOG_LEVELS: LogLevel[] = ["off", "problems", "records"];

export interface InstanceConfig {
  /** The DNS-SD instance label, "any user-friendly text" (RFC 6763). */
  name: string;
  /** The browsing domain, normally "local". */
  domain: Name;
  /** The SRV target: the name a client connects to, and the one its certificate must match. */
  target: Name;
  port: number;
  /** The CDMI versions offered, as the TXT "ver" key. */
  ver: string[];
  /** A friendly name, as the TXT "name" key, where the label is not suitable. */
  display?: string;
  /** Addresses published for the target, where the target is this host's own name. */
  addresses: string[];
  /** The well-known tree polled to decide whether the instance is advertised. */
  check: boolean;
  checkUrl: string;
  checkIntervalMs: number;
  /** The anchors for the check's certificate, where the system does not trust it. */
  checkCa?: string;
}

export interface Config {
  /** The interfaces joined; empty means every non-loopback interface. */
  interfaces: string[];
  ipv6: boolean;
  instances: InstanceConfig[];
  log: LogLevel;
  logFile?: string;
}

export const DEFAULTS: Config = { interfaces: [], ipv6: true, instances: [], log: "problems" };

type Table = Record<string, TOMLValue>;

const table = (v: TOMLValue | undefined, where: string): Table => {
  if (v === undefined) return {};
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new ConfigError(`${where} is a table`);
  return v as Table;
};
const tables = (v: TOMLValue | undefined, where: string): Table[] => {
  if (v === undefined) return [];
  if (!Array.isArray(v)) throw new ConfigError(`${where} is a list of tables`);
  return v.map((x, i) => table(x, `${where}[${i}]`));
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

/**
 * A name given in presentation form. A DNS-SD instance label may hold a dot,
 * so an instance is named by its label alone and the labels of a domain or a
 * target are split here, where "\." is a dot within a label.
 */
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

const address = (s: string, where: string): string => {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(s) && s.split(".").every((p) => Number(p) <= 255)) return s;
  if (/^[0-9a-fA-F:]+$/.test(s) && s.includes(":")) return s;
  throw new ConfigError(`${where}: ${JSON.stringify(s)} is not an address`);
};

export function parseConfig(text: string, dir = "."): Config {
  const doc = parseTOML(text);
  only(doc, "the configuration", ["link", "instance", "log"]);
  const c: Config = { ...DEFAULTS, interfaces: [], instances: [] };

  const link = table(doc.link, "[link]");
  only(link, "[link]", ["interfaces", "ipv6"]);
  c.interfaces = strings(link, "interfaces", "[link]") ?? [];
  c.ipv6 = bool(link, "ipv6", "[link]") ?? true;

  for (const [i, t] of tables(doc.instance, "[[instance]]").entries()) {
    const where = `[[instance]][${i}]`;
    only(t, where, ["name", "domain", "target", "port", "ver", "display", "addresses",
      "check", "check_url", "check_interval_ms", "check_ca", "check_ca_file"]);
    const label = str(t, "name", where);
    if (label === undefined || label === "") throw new ConfigError(`${where} gives the instance name`);
    const port = int(t, "port", where);
    if (port === undefined || port === 0 || port > 65535) {
      throw new ConfigError(`${where} gives the port of the CDMI server's TLS binding`);
    }
    const given = str(t, "target", where);
    if (given === undefined || given === "") {
      throw new ConfigError(`${where} gives the target: the host name a client connects to, which is the ` +
        "name the CDMI server's certificate is issued for and not necessarily a name in the browsing domain");
    }
    const target = name(given, `${where}.target`);
    const domain = name(str(t, "domain", where) ?? "local", `${where}.domain`);
    const addresses = (strings(t, "addresses", where) ?? []).map((a) => address(a, `${where}.addresses`));
    const check = bool(t, "check", where) ?? true;
    // A _cdmi._tcp instance always denotes a binding served over TLS: "a client
    // MUST NOT construct an http base URI from one". So the check is https, and
    // an instance is advertised at the name its certificate is issued for.
    const checkUrl = str(t, "check_url", where) ??
      `https://${presentation(target)}:${port}/.well-known/cdmi/cdmi_namespaces/`;
    if (!checkUrl.startsWith("https://")) {
      throw new ConfigError(`${where}.check_url is an https URL: a _cdmi._tcp instance denotes a TLS binding`);
    }
    const interval = int(t, "check_interval_ms", where) ?? 30_000;
    if (check && interval < 1000) throw new ConfigError(`${where}.check_interval_ms is at least 1000`);
    const ca = material(t, "check_ca", where, dir);
    c.instances.push({
      name: label, domain, target, port,
      ver: strings(t, "ver", where) ?? [],
      ...(str(t, "display", where) === undefined ? {} : { display: str(t, "display", where)! }),
      addresses, check, checkUrl, checkIntervalMs: interval,
      ...(ca === undefined ? {} : { checkCa: ca }),
    });
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
  "--config": true, "--log": true, "--log-file": true,
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

/** What the responder needs to run. */
export function checkComplete(c: Config): void {
  if (c.instances.length === 0) {
    throw new ConfigError("no [[instance]] is given: the responder would advertise nothing at all");
  }
  // Two instances of the same name in one domain are this host advertising a
  // name against itself, which probing cannot settle: the conflict rules
  // resolve a name contested by two hosts, not one held twice by one.
  const seen = new Set<string>();
  for (const i of c.instances) {
    const key = `${i.name}\u0000${presentation(i.domain).toLowerCase()}`;
    if (seen.has(key)) {
      throw new ConfigError(`the instance ${JSON.stringify(i.name)} is given twice in ${presentation(i.domain)}`);
    }
    seen.add(key);
  }
}
