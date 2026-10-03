// seedmi-dac: a reference delegated access control provider, run on its own.
//
//   node src/dacd.ts --config dac.toml
//
// It answers the delegated access control requests of the CDMI servers its
// [[server]] tables name, over HTTPS, at the path of the cdmi_dac_uri its
// objects give (CDMI 3.0, revision 247, Delegated access control). It shares
// no file with a CDMI server.
//
// A request is read (addressed to this provider, decrypted, its signature
// verified: dac-protocol.ts), its server authenticated and its identifier
// checked against the replay window (dac-trust.ts), and decided by the first
// [[rule]] that matches it, none matching denying (dac-policy.ts).

import { appendFileSync, readFileSync } from "node:fs";
import type { Server } from "node:http";
import { createServer } from "node:https";
import * as path from "node:path";
import { applyFlags, checkComplete, type Config, ConfigError, DEFAULTS, parseConfig, readArgv } from "./config.ts";
import { buildResponse, DacRefusal, readRequest } from "./dac-protocol.ts";
import { authenticate, ReplayWindow } from "./dac-trust.ts";
import { decide } from "./dac-policy.ts";
import { deliver, permitted } from "./dac-deliver.ts";

export const VERSION = "0.11";

const USAGE = `seedmi-dac: a reference delegated access control provider.
Usage: node src/dacd.ts [flags]
  --config <path>                  read settings from a TOML file
  --host <address>                 the address to listen on
  --port <port>                    the port to listen on
  --log <off|problems|requests>    what to log beyond the arrival of a request,
                                   which is always written
  --log-file <path>                write the log there, not to stderr
                                   (the log is JSON Lines, one object per line)
  --certificate-jwk                print the JWK objects give as cdmi_dac_certificate, and exit
  --help                           print this text and exit (also -h)
  --version                        print the version and exit (also -v)
A configuration file gives [listen] (host, port, path, certificate, key),
[provider] (decryption_key, certificate, signing_key, signing_chain,
replay_window_ms), [[server]] (name, and ca with subject, or key) for each CDMI
server answered (with response_uris and response_ca where it is answered
later), [[rule]] (servers, objects, operations, principals, groups,
headers, decision, mask, response_headers, cache_seconds, redirect_objectID,
audit_uri, defer) in order, the first matching deciding and none matching denying, and
[log] (level, file). A flag wins over the file.
SIGHUP re-reads the configuration: the certificate the listener presents, the
provider's keys, the servers answered and the rules apply from the next request.
`;

/**
 * Writes a line of the log where the level asks for it; never a key, a secret
 * or a request's content.
 *
 * The "received" level is written whatever the configured level, including
 * "off". A provider that records nothing when a request arrives cannot answer
 * the first question asked of it — whether the CDMI server reached it at all —
 * and every other level here is written after the request has been decrypted,
 * verified and decided, so a request refused before any of that left no trace.
 * The arrival line holds the method, the path, the peer and the length, and
 * nothing of the content, which is encrypted to this provider in any case.
 */
function logger(c: Config): (level: "received" | "problems" | "requests", event: Record<string, unknown>) => void {
  const wanted = c.log === "off" ? ["received"]
    : c.log === "requests" ? ["received", "problems", "requests"] : ["received", "problems"];
  return (level, event) => {
    if (!wanted.includes(level)) return;
    // JSON Lines: one JSON object per line, newline-delimited. This log is read
    // by a program — it is the provider's half of the record of an operation,
    // the CDMI server keeping the other half — and a line of key=value pairs is
    // not, since a value may hold a space and nothing quotes it. The text
    // format this program offered is withdrawn; [log].format and --log-format
    // are gone with it.
    const line = JSON.stringify({ time: new Date().toISOString(), ...event });
    if (c.logFile === undefined) process.stderr.write(line + "\n");
    else appendFileSync(c.logFile, line + "\n");
  };
}

/** The HTTP status a refusal is answered with; the draft defines none (PLAN.md, questions for the draft). */
const STATUS: Record<DacRefusal["reason"], number> = {
  "malformed": 400, "not-addressed": 400, "undecryptable": 400, "unverified": 403, "untrusted": 403, "replayed": 403,
};
const LIMIT = 1 << 20;

/**
 * The one field of `client_headers` this provider records: what the CDMI server
 * says of the operation the decision is for.
 *
 * Every other field of `client_headers` is a CDMI client's own, passed through
 * by the CDMI server without being read, and may carry anything including a
 * credential; none is logged. This field is one the CDMI server generates, and
 * seedmi documents its contents as the binding, the tool, the trace identifier
 * and the calling program.
 */
function operationOf(headers: Record<string, string>): string | undefined {
  for (const [name, value] of Object.entries(headers)) {
    if (name.toLowerCase() === "cdmi-dac-operation") return value;
  }
  return undefined;
}

function main(): void {
  let flags: Record<string, string | true>;
  let config: Config;
  let configPath: string | undefined;
  const load = (): Config => {
    const base = configPath === undefined ? { ...DEFAULTS, servers: [] }
      : parseConfig(readFileSync(configPath, "utf8"), path.dirname(configPath));
    return applyFlags(base, flags);
  };
  try {
    flags = readArgv(process.argv.slice(2));
    if (flags["--help"] || flags["-h"]) { process.stdout.write(USAGE); return; }
    if (flags["--version"] || flags["-v"]) { process.stdout.write(`seedmi-dac ${VERSION}\n`); return; }
    configPath = typeof flags["--config"] === "string" ? flags["--config"] : undefined;
    config = load();
    if (flags["--certificate-jwk"]) {
      if (config.keys === undefined) throw new ConfigError("[provider] gives no certificate to print");
      process.stdout.write(JSON.stringify(config.keys.certificate, null, 2) + "\n");
      return;
    }
    checkComplete(config);
  } catch (e) {
    if (e instanceof ConfigError) {
      process.stderr.write(`seedmi-dac: ${e.message}\n`);
      process.exit(2);
    }
    throw e;
  }
  let log = logger(config);
  const window = new ReplayWindow(config.replayWindowMs);

  const server: Server = createServer({ cert: config.tlsCert, key: config.tlsKey, minVersion: "TLSv1.2" } as never,
    (req, res) => {
      const url = new URL(req.url ?? "/", "https://provider");
      if (url.pathname === "/health") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "ok", version: VERSION }));
        return;
      }
      // Every request that arrives for a decision is recorded here, before it
      // is read, so that one that is refused before it can be decided is
      // recorded too: a wrong path, a wrong method, a body too large, a body
      // this provider cannot decrypt. Nothing of the content is written.
      const peer = req.socket.remoteAddress ?? "unknown";
      log("received", {
        event: "request received", method: req.method ?? "", path: url.pathname, peer,
        ...(url.pathname === config.path ? {} : { expected: config.path }),
      });
      if (url.pathname !== config.path) {
        res.writeHead(404);
        res.end();
        return;
      }
      // The draft does not state the method of a request (PLAN.md): seedmi
      // sends POST, and the draft's one mention is of PUT. Both are taken.
      if (req.method !== "POST" && req.method !== "PUT") {
        res.writeHead(405, { Allow: "POST, PUT" });
        res.end();
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      req.on("data", (c: Buffer) => {
        size += c.length;
        if (size > LIMIT) {
          log("problems", { event: "request too large", peer, limit: LIMIT });
          req.destroy();
        } else chunks.push(c);
      });
      req.on("end", () => {
        const current = config;
        try {
          const request = readRequest(Buffer.concat(chunks), current.keys!);
          const name = authenticate(request, current.servers);
          window.admit(name, request.id);
          // The first rule matching decides, and none matching denies (dac-policy.ts).
          const decision = decide(current.rules, request, name);
          const body = JSON.stringify(buildResponse(request, decision, current.keys!));
          log("requests", { event: "decided", server: name, request: request.id, operation: request.operation,
            object: request.objectId, rule: decision.rule ?? "none", applied: decision.appliedMask,
            // Where the CDMI server said which of its protocol bindings the
            // operation arrived on, and under what trace identifier, that is
            // recorded with the decision: the CDMI server's record of the
            // operation and this record are then readable as records of one
            // operation. This one field of client_headers is logged and no
            // other — the rest are a CDMI client's own and may carry a
            // credential, which is why nothing of client_headers was logged
            // before.
            ...(operationOf(request.clientHeaders) === undefined
              ? {} : { cdmi_operation: operationOf(request.clientHeaders) }) });
          // A rule may defer the answer: acknowledged now, the response sent
          // to the request's dac_response_uri, where the server permits that
          // URI. Otherwise, and where the request names none, answered now.
          const trusted = current.servers.find((sv) => sv.name === name)!;
          if (decision.defer === true && request.responseUri !== undefined &&
              permitted(request.responseUri, trusted.responseUris ?? [])) {
            res.writeHead(202, { "Content-Length": "0" });
            res.end();
            void deliver(request.responseUri, body, { attempts: 4, backoffMs: 1000,
              ...(trusted.responseCa === undefined ? {} : { ca: trusted.responseCa }) }).then(({ outcome, status }) =>
              log(outcome === "delivered" ? "requests" : "problems",
                { event: `response ${outcome}`, server: name, request: request.id, status }));
            return;
          }
          if (decision.defer === true) {
            log("problems", { event: "answered at once", server: name, request: request.id,
              detail: request.responseUri === undefined ? "the request names no dac_response_uri"
                : `${request.responseUri} is not a response URI ${name} is permitted` });
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(body);
        } catch (e) {
          if (e instanceof DacRefusal) {
            log("problems", { event: "refused", reason: e.reason, detail: e.message });
            res.writeHead(STATUS[e.reason], { "Content-Type": "text/plain" });
            res.end(e.message + "\n");
            return;
          }
          log("problems", { event: "error", detail: e instanceof Error ? e.message : String(e) });
          res.writeHead(500);
          res.end();
        }
      });
    });

  // SIGHUP: the configuration read again. What fails to load leaves the one in
  // use; what loads applies from the next request and the next connection.
  process.on("SIGHUP", () => {
    try {
      const next = load();
      checkComplete(next);
      server.setSecureContext({ cert: next.tlsCert, key: next.tlsKey } as never);
      config = next;
      log = logger(config);
      log("problems", { event: "reloaded", servers: config.servers.map((s) => s.name) });
    } catch (e) {
      log("problems", { event: "reload refused", detail: e instanceof Error ? e.message : String(e) });
    }
  });
  const stop = () => server.close(() => process.exit(0));
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);

  server.listen(config.port, config.host, () => {
    const at = server.address() as { port: number };
    // Recorded before it is announced, so that anything reading the log after
    // seeing the announcement finds this line already in it.
    //
    // It is written at the level written whatever is configured. The
    // announcement below goes to standard output, so a log read on its own —
    // which is how this log is read, being the provider's half of a record the
    // CDMI server keeps the other half of — said nothing about what wrote it.
    // The format of these records changed in 0.9, and a reader who still had an
    // older provider running could not tell that from the records themselves:
    // the version that produced a log is now the first line of it.
    log("received", {
      event: "started", provider: "seedmi-dac", version: VERSION,
      servers: config.servers.map((s) => s.name), level: config.log,
      endpoint: `https://${config.host}:${at.port}${config.path}`,
    });
    process.stdout.write(`seedmi-dac ${VERSION}: answering ${config.servers.length} CDMI server(s) at ` +
      `https://${config.host}:${at.port}${config.path}\n`);
  });
}

main();
