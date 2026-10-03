// seedmi-mdns: a multicast DNS responder that makes a CDMI server visible on
// the local link.
//
//   node src/mdnsd.ts --config mdns.toml
//
// It advertises each [[instance]] as a DNS-SD service instance of the type
// _cdmi._tcp (ECR-224A), so that a client browsing the link finds the CDMI
// servers on it, and a discovery proxy or seedmi-zone can carry what it hears
// into a real DNS zone. It shares no file with a CDMI server, and reads
// nothing from one but the well-known tree it polls to know whether the server
// is answering.
//
// One responder per host: port 5353 is a singleton, and a host already running
// avahi-daemon has one. It advertises this host's own instances and publishes
// addresses only for its own names; discovering what other hosts advertise is
// seedmi-zone's job, not this one's.

import { appendFileSync, readFileSync } from "node:fs";
import {
  applyFlags, checkComplete, type Config, ConfigError, DEFAULTS, parseConfig, readArgv,
} from "./config.ts";
import { Check } from "./check.ts";
import { presentation } from "./dns.ts";
import { LinkError, openLink } from "./link.ts";
import { type Advertisement, type Link, Responder, SERVICE } from "./mdns.ts";

export const VERSION = "0.2";

const USAGE = `seedmi-mdns: a multicast DNS responder advertising CDMI servers.
Usage: node src/mdnsd.ts [flags]
  --config <path>              read settings from a TOML file
  --log <off|problems|records> what to log beyond starting and stopping
  --log-file <path>            write the log there, not to stderr
                               (the log is JSON Lines, one object per line)
  --help                       print this text and exit (also -h)
  --version                    print the version and exit (also -v)
A configuration file gives [link] (interfaces, ipv6), one [[instance]] per CDMI
server advertised on this host (name, domain, target, port, ver, display,
addresses, check, check_url, check_interval_ms, check_ca) and [log] (level,
file). A flag wins over the file.
One responder runs per host: port 5353 is held by one process, and a host
running avahi-daemon already has one.
SIGHUP re-reads the configuration: the instances advertised are withdrawn with
a goodbye and the new set is probed for afresh.
`;

let logFile: string | undefined;
let logLevel: Config["log"] = "problems";

/** A line of the log; never an address of a host other than this one's peers. */
function record(event: Record<string, unknown>, always = false): void {
  if (!always && logLevel === "off") return;
  if (!always && logLevel === "problems" && event.event !== "malformed" && event.event !== "socket" &&
      event.event !== "renamed" && event.event !== "instance down" && event.event !== "join") {
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

const advertisementOf = (i: Config["instances"][number]): Advertisement => ({
  instance: i.name,
  domain: i.domain,
  target: i.target,
  port: i.port,
  // "txtvers ... required. TXT record format version; 1 for this addition."
  txt: [
    "txtvers=1",
    ...(i.ver.length > 0 ? [`ver=${i.ver.join(",")}`] : []),
    ...(i.display === undefined ? [] : [`name=${i.display}`]),
  ],
  addresses: i.addresses,
});

interface Running {
  responder: Responder;
  link: Link;
  checks: Check[];
}

async function run(config: Config): Promise<Running> {
  const link = await openLink({
    interfaces: config.interfaces,
    ipv6: config.ipv6,
    receive: (bytes, from) => responder.receive(bytes, from),
    log: record,
  });
  const responder = new Responder({
    link,
    advertisements: config.instances.map(advertisementOf),
    log: record,
  });
  const checks: Check[] = [];
  for (const i of config.instances) {
    if (!i.check) continue;
    const check = new Check({
      url: i.checkUrl,
      intervalMs: i.checkIntervalMs,
      ...(i.checkCa === undefined ? {} : { ca: i.checkCa }),
      onChange: (up, why) => {
        record({ event: up ? "instance up" : "instance down", instance: i.name, url: i.checkUrl, why }, true);
        responder.setUp(i.name, up);
      },
    });
    // Nothing is advertised until the first poll answers: an instance
    // advertised and then withdrawn a moment later is worse than one that
    // appears a moment late.
    responder.setUp(i.name, false);
    check.start();
    checks.push(check);
  }
  responder.start();
  for (const i of config.instances) {
    record({
      event: "advertising",
      instance: presentation([i.name, ...SERVICE, ...i.domain]),
      target: presentation(i.target),
      port: i.port,
      checking: i.check ? i.checkUrl : false,
    }, true);
  }
  return { responder, link, checks };
}

async function main(): Promise<void> {
  let flags: Record<string, string | true>;
  try {
    flags = readArgv(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`seedmi-mdns: ${(e as Error).message}\n`);
    process.exit(2);
  }
  if (flags["--help"] === true || flags["-h"] === true) {
    process.stdout.write(USAGE);
    return;
  }
  if (flags["--version"] === true || flags["-v"] === true) {
    process.stdout.write(`seedmi-mdns ${VERSION}\n`);
    return;
  }

  const load = (): Config => {
    const at = flags["--config"];
    if (typeof at !== "string") {
      throw new ConfigError("--config names the configuration file; there is nothing to advertise without one");
    }
    const c = applyFlags(parseConfig(readFileSync(at, "utf8"), dirOf(at)), flags);
    checkComplete(c);
    return c;
  };

  let config: Config;
  try {
    config = load();
  } catch (e) {
    process.stderr.write(`seedmi-mdns: ${(e as Error).message}\n`);
    process.exit(2);
  }
  logLevel = config.log;
  logFile = config.logFile;

  let running: Running;
  try {
    running = await run(config);
  } catch (e) {
    process.stderr.write(`seedmi-mdns: ${(e as Error).message}\n`);
    process.exit(e instanceof LinkError ? 3 : 2);
  }
  record({ event: "started", program: "seedmi-mdns", version: VERSION, instances: config.instances.length }, true);

  const stop = (signal: string) => {
    record({ event: "stopping", signal }, true);
    // The goodbye goes before the socket does, so that the link is told rather
    // than left to time the records out.
    running.responder.close();
    for (const c of running.checks) c.stop();
    setTimeout(() => {
      running.link.close();
      process.exit(0);
    }, 100);
  };
  process.on("SIGINT", () => stop("SIGINT"));
  process.on("SIGTERM", () => stop("SIGTERM"));
  process.on("SIGHUP", () => {
    record({ event: "reloading" }, true);
    let next: Config;
    try {
      next = load();
    } catch (e) {
      // The responder that is running keeps running: a configuration that does
      // not parse is a reason not to change, not a reason to stop advertising.
      record({ event: "reload refused", why: (e as Error).message }, true);
      return;
    }
    running.responder.close();
    for (const c of running.checks) c.stop();
    running.link.close();
    logLevel = next.log;
    logFile = next.logFile;
    void run(next).then((r) => {
      running = r;
      record({ event: "reloaded", instances: next.instances.length }, true);
    }).catch((e: unknown) => {
      record({ event: "reload failed", why: (e as Error).message }, true);
      process.exit(3);
    });
  });
}

const dirOf = (p: string): string => {
  const at = p.lastIndexOf("/");
  return at <= 0 ? "." : p.slice(0, at);
};

await main();
