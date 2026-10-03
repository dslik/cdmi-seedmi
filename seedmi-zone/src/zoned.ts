// seedmi-zone: browses the link for CDMI servers and publishes what it finds
// into a real DNS zone.
//
//   node src/zoned.ts --config zone.toml
//   node src/zoned.ts --config zone.toml --once --dry-run
//
// One instance per link, owning one zone subtree. A client then discovers CDMI
// servers by ordinary DNS — including a browser, through any DoH resolver —
// without anything having to bridge multicast at query time, and without the
// CDMI servers holding a credential that can write the zone.
//
// It shares no file with a CDMI server, and reads nothing from one but the
// well-known discovery tree it uses to decide whether an announcement deserves
// a name.

import { appendFileSync, readFileSync } from "node:fs";
import { Browser } from "./browse.ts";
import {
  applyFlags, checkComplete, type Config, ConfigError, parseConfig, readArgv,
} from "./config.ts";
import { type Name, presentation, type ResourceRecord } from "./dns.ts";
import { LinkError, openLink } from "./link.ts";
import { type Publisher, reconcile, UnboundPublisher, UpdatePublisher } from "./publish.ts";
import { sweep } from "./sweep.ts";

export const VERSION = "0.2";

const USAGE = `seedmi-zone: publishes the CDMI servers on a link into a DNS zone.
Usage: node src/zoned.ts [flags]
  --config <path>             read settings from a TOML file
  --once                      browse, sweep once and exit
  --dry-run                   say what would be written and write nothing
  --log <off|problems|sweeps> what to log beyond starting and stopping
  --log-file <path>           write the log there, not to stderr
                              (the log is JSON Lines, one object per line)
  --help                      print this text and exit (also -h)
  --version                   print the version and exit (also -v)
A configuration file gives [link] (interfaces, ipv6, browse), [zone] (name,
ttl_host, ttl_other, sweep_interval_ms, allow, ca), one of [update] (host,
port, key_name, key_algorithm, key_secret) or [unbound] (command, args), and
[log] (level, file). A flag wins over the file.
One instance per link, owning one zone subtree: two writers on one subtree undo
each other's work, so a site with several links gives each its own subtree.
SIGHUP re-reads the configuration and sweeps afresh.
`;

let logFile: string | undefined;
let logLevel: Config["log"] = "problems";

function record(event: Record<string, unknown>, always = false): void {
  if (!always && logLevel === "off") return;
  if (!always && logLevel === "problems" &&
      !["malformed", "socket", "not published", "write failed", "join"].includes(String(event.event))) {
    return;
  }
  const line = JSON.stringify({ time: new Date().toISOString(), ...event }) + "\n";
  if (logFile === undefined) process.stderr.write(line);
  else {
    try {
      appendFileSync(logFile, line);
    } catch {
      process.stderr.write(line);
    }
  }
}

const publisherFor = (c: Config): Publisher =>
  c.update !== undefined
    ? new UpdatePublisher({ host: c.update.host, port: c.update.port, zone: c.zone, key: c.update.key })
    : new UnboundPublisher({ command: c.unbound!.command, args: c.unbound!.args, zone: c.zone });

async function main(): Promise<void> {
  let flags: Record<string, string | true>;
  try {
    flags = readArgv(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`seedmi-zone: ${(e as Error).message}\n`);
    process.exit(2);
  }
  if (flags["--help"] === true || flags["-h"] === true) {
    process.stdout.write(USAGE);
    return;
  }
  if (flags["--version"] === true || flags["-v"] === true) {
    process.stdout.write(`seedmi-zone ${VERSION}\n`);
    return;
  }
  const dryRun = flags["--dry-run"] === true;
  const once = flags["--once"] === true;

  const load = (): Config => {
    const at = flags["--config"];
    if (typeof at !== "string") {
      throw new ConfigError("--config names the configuration file; there is nothing to publish without one");
    }
    const c = applyFlags(parseConfig(readFileSync(at, "utf8"), dirOf(at)), flags);
    checkComplete(c);
    return c;
  };

  let config: Config;
  try {
    config = load();
  } catch (e) {
    process.stderr.write(`seedmi-zone: ${(e as Error).message}\n`);
    process.exit(2);
  }
  logLevel = config.log;
  logFile = config.logFile;

  let link;
  try {
    link = await openLink({
      interfaces: config.interfaces,
      ipv6: config.ipv6,
      receive: (bytes, from) => browser.receive(bytes, from),
      log: record,
    });
  } catch (e) {
    process.stderr.write(`seedmi-zone: ${(e as Error).message}\n`);
    process.exit(e instanceof LinkError ? 3 : 2);
  }
  const browser = new Browser({ link, domains: config.browse, log: record });
  const publisher = publisherFor(config);
  record({
    event: "started", program: "seedmi-zone", version: VERSION,
    zone: presentation(config.zone),
    browsing: config.browse.map(presentation),
    writing: dryRun ? "nothing (--dry-run)" : publisher.describe(),
  }, true);
  browser.start();

  /** What the subtree held after the last sweep, so the next writes the difference. */
  let published: ResourceRecord[] = [];
  let sweeping = false;

  const pass = async (): Promise<void> => {
    // A sweep that overruns its interval is not started twice: the second
    // would work from the same view and write the same records.
    if (sweeping) return;
    sweeping = true;
    try {
      const instances = browser.instances();
      const result = await sweep(instances, {
        zone: config.zone,
        domains: config.browse,
        ttlHost: config.ttlHost,
        ttlOther: config.ttlOther,
        ...(config.ca === undefined ? {} : { ca: config.ca }),
        allow: config.allow,
        log: record,
      });
      const { add, remove } = reconcile(result.records, published);
      record({
        event: "sweep",
        found: instances.length,
        published: result.verdicts.filter((v) => v.published).length,
        adding: add.length,
        removing: remove.map((n: Name) => presentation(n)),
      });
      if (add.length === 0 && remove.length === 0) return;
      if (dryRun) {
        for (const r of add) process.stdout.write(`+ ${describe(r)}\n`);
        for (const n of remove) process.stdout.write(`- ${presentation(n)}\n`);
        published = result.records;
        return;
      }
      try {
        await publisher.apply(add, remove);
        published = result.records;
        record({ event: "wrote", added: add.length, removed: remove.length }, true);
      } catch (e) {
        // What the zone holds is now unknown, so the next sweep is made to
        // write everything again rather than the difference against a view
        // that may be wrong.
        published = [];
        record({ event: "write failed", why: (e as Error).message }, true);
      }
    } finally {
      sweeping = false;
    }
  };

  if (once) {
    // Long enough for the link to answer: multicast DNS has no "no such name",
    // so what a browse finds is what arrived before it was asked.
    await new Promise((r) => setTimeout(r, 2000));
    await pass();
    browser.close();
    link.close();
    return;
  }

  const timer = setInterval(() => void pass(), config.sweepIntervalMs);
  if (typeof timer.unref === "function") timer.unref();
  setTimeout(() => void pass(), 2000);

  const stop = (signal: string) => {
    record({ event: "stopping", signal }, true);
    clearInterval(timer);
    browser.close();
    link.close();
    // The records are left in the zone rather than withdrawn: this program
    // stopping does not mean the CDMI servers have, and a lifetime that runs
    // out says the right thing where it does.
    process.exit(0);
  };
  process.on("SIGINT", () => stop("SIGINT"));
  process.on("SIGTERM", () => stop("SIGTERM"));
  process.on("SIGHUP", () => {
    record({ event: "reloading" }, true);
    try {
      const next = load();
      logLevel = next.log;
      logFile = next.logFile;
      config = next;
      // The view of the zone is dropped, so the next sweep writes everything
      // the new configuration asks for rather than the difference against what
      // the old one wanted.
      published = [];
      record({ event: "reloaded", zone: presentation(config.zone) }, true);
    } catch (e) {
      record({ event: "reload refused", why: (e as Error).message }, true);
    }
  });
}

const describe = (r: ResourceRecord): string => {
  const d = r.data;
  const rest = d.kind === "SRV"
    ? `SRV 0 0 ${d.port} ${presentation(d.target)}`
    : d.kind === "TXT"
      ? `TXT ${d.strings.join(" ")}`
      : d.kind === "PTR"
        ? `PTR ${presentation(d.name)}`
        : d.kind === "A" || d.kind === "AAAA"
          ? `${d.kind} ${d.address}`
          : d.kind;
  return `${presentation(r.name)} ${r.ttl} ${rest}`;
};

const dirOf = (p: string): string => {
  const at = p.lastIndexOf("/");
  return at <= 0 ? "." : p.slice(0, at);
};


await main();
