// seedmi-dc: a reference domain controller, run on its own.
//
//   node src/dcd.ts --config dc.toml
//   node src/dcd.ts --hash-password < password.txt
//
// One instance serves one realm: its users and groups, given in its
// configuration and read again on SIGHUP, and the verification of their
// credentials for a CDMI server that refers the resolution of a principal to
// it. Several instances, each with its own configuration and ports, stand for
// several domain controllers. It shares no file with a CDMI server. See PLAN.md.

import { createServer as createNetServer, type Server as NetServer } from "node:net";
import { answer, keyOf } from "./krb-kdc.ts";
import { openStore } from "./dc-import.ts";
import { readDirectory } from "./dc-view.ts";
import { KmipKeyStore } from "./dc-keys.ts";
import { type KeyStore, Writer } from "./dc-write.ts";
import { LdapWriter } from "./dc-ldap-writes.ts";
import { formatDn, subjectOfCertificate } from "./dn.ts";
import { ScimService } from "./dc-scim.ts";
import { ETYPE } from "./krb-crypto.ts";
import type { Store } from "./dc-store.ts";
import { appendFileSync, readFileSync } from "node:fs";
import type { Server } from "node:http";
import { createServer } from "node:https";
import * as path from "node:path";
import { applyFlags, checkComplete, type Config, ConfigError, DEFAULTS, parseConfig, readArgv } from "./config.ts";
import { hashPassword } from "./dc-directory.ts";
import { createServer as createTlsServer, TLSSocket, type TLSServer, type TLSSocketType } from "node:tls";
import type { Socket as NetSocket } from "node:net";
import { baseOf, LdapSession } from "./ldap.ts";
import { Throttle } from "./throttle.ts";

export const VERSION = "1.4";
const LIMIT = 64 * 1024;

const USAGE = `seedmi-dc: a reference domain controller.
Usage: node src/dcd.ts [flags]
  --config <path>                  read settings from a TOML file
  --host <address>                 the address to listen on
  --port <port>                    the port HTTPS is served on
  --log <off|problems|requests>    what to log; nothing is logged unless this is given
  --log-file <path>                write the log there, not to stderr
  --log-format <text|json>         how each line is written
  --hash-password                  read a password on standard input, print its hash, and exit
  --sweep-keys                     destroy key material no row of the store references, and exit
  --help                           print this text and exit (also -h)
  --version                        print the version and exit (also -v)
--sweep-keys needs [directory].store and [kms]: it asks the key server what it
holds for this controller, compares it with what the store references, and destroys
the difference. A change that is refused already destroys what it registered; this
is for material a stopped process left between a registration and the commit.
A configuration file gives [realm] (name, domain), [listen] (host, port,
ldap_port, certificate, key), [[user]] (name, password_hash, groups, disabled, expires),
[[group]] (name, groups), [directory] (memberof, store, uid_range, gid_range),
[kms] (host, port, certificate, key, authority, key_cache_seconds),
[admin] (authority, subjects),
[tokens] (issuer, signing_key, previous_keys,
lifetime_seconds), [[client]] (id, secret_hash, grants, audiences, scopes) and [log]
(level, file, format). A flag wins over the
file. A user's password is given as the hash --hash-password prints; a plain
password is taken, and warned of.
Where [directory].store names a store, the directory is the store's and not this
file's: [[user]] and [[group]] are then refused, dc-import seeds the store from a
bootstrap file, and [kms] says where the secret material of each principal is
kept. A store whose key server cannot be reached is served without its secrets,
and a bind, a token and a ticket are refused with a line saying so.
[admin] says who may write it over LDAP: an administrator binds by SASL EXTERNAL
with a certificate that authority issued and naming a listed subject. SCIM 2.0,
under /scim/v2/, is the other front end, and is authorized instead by a bearer
token this controller issued carrying the dc.read or dc.admin scope. Neither
front end implies the other, and a write through either needs a store.
SIGHUP re-reads the configuration: the users and groups, the certificate and the
log apply from the next request, and a store is read again. A configuration that
does not load leaves the one in use. The realm, its domain and where the
directory is kept are what the instance is, and a reload changing them is refused.
`;

function logger(c: Config): (level: "problems" | "requests", event: Record<string, unknown>) => void {
  if (c.log === "off") return () => undefined;
  const wanted = c.log === "requests" ? ["problems", "requests"] : ["problems"];
  return (level, event) => {
    if (!wanted.includes(level)) return;
    const at = new Date().toISOString();
    const line = c.logFormat === "json"
      ? JSON.stringify({ time: at, realm: c.realm, ...event })
      : `${at} realm=${c.realm} ${Object.entries(event).map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`).join(" ")}`;
    if (c.logFile === undefined) process.stderr.write(line + "\n");
    else appendFileSync(c.logFile, line + "\n");
  };
}

async function main(): Promise<void> {
  let flags: Record<string, string | true>;
  let configPath: string | undefined;
  // --sweep-keys: read with the other flags, acted on once the store and key server are open.
  let sweeping = false;
  // The principals whose material the key server would not hand over, from the last read.
  let unreadableMaterial: string[] = [];
  // Failures counted against names, across reloads, for the token endpoint and LDAP alike.
  const throttle = new Throttle();
  const load = (): Config => {
    const base = configPath === undefined ? { ...DEFAULTS }
      : parseConfig(readFileSync(configPath, "utf8"), path.dirname(configPath), throttle);
    return applyFlags(base, flags);
  };
  let config: Config;
  try {
    flags = readArgv(process.argv.slice(2));
    if (flags["--help"] || flags["-h"]) { process.stdout.write(USAGE); return; }
    if (flags["--version"] || flags["-v"]) { process.stdout.write(`seedmi-dc ${VERSION}\n`); return; }
    sweeping = flags["--sweep-keys"] === true;
    if (flags["--hash-password"]) {
      // The first line of standard input; file descriptor 0 itself, which a pipe from a script gives.
      const line = (readFileSync as unknown as (fd: number, enc: string) => string)(0, "utf8").split(/\r?\n/)[0] ?? "";
      if (line === "") throw new ConfigError("--hash-password reads a password, not empty, on standard input");
      process.stdout.write(hashPassword(line) + "\n");
      return;
    }
    configPath = typeof flags["--config"] === "string" ? flags["--config"] : undefined;
    config = load();
    checkComplete(config);
  } catch (e) {
    if (e instanceof ConfigError) {
      process.stderr.write(`seedmi-dc: ${e.message}\n`);
      process.exit(2);
    }
    throw e;
  }
  let log = logger(config);
  const warnPlain = (c: Config) => {
    if (c.directory.plainPasswords > 0) {
      log("problems", { event: "plain passwords", detail: `${c.directory.plainPasswords} user(s) given a password rather than its hash` });
    }
    if (c.plainSecrets > 0) {
      log("problems", { event: "plain secrets", detail: `${c.plainSecrets} client(s) given a secret rather than its hash` });
    }
  };
  warnPlain(config);

  // Where [directory].store is given, the directory is the store's and not this
  // file's (DESIGN-admin.md §1): it is read into memory here, and read again on
  // SIGHUP and after each write. The secret material of each principal comes from
  // the key management server; where that server is away the directory is served
  // and what needs a secret is refused, with a line saying so, because a
  // controller that will not start because a key server is briefly away is worse
  // than one that says what it cannot do (§4).
  let store: Store | undefined;
  let keys: KeyStore | undefined;
  const fromStore = async (): Promise<void> => {
    if (store === undefined || keys === undefined) return;
    const view = await readDirectory(store, keys);
    // Kept for --sweep-keys, which reports the other direction from this rather than
    // looking for it: a reference whose material the key server will not hand over is
    // what these two lists are.
    unreadableMaterial = [...new Set([...view.withoutVerifier, ...view.withoutKeys])].sort();
    config.directory = view.directory;
    if (config.kdc !== undefined) {
      config.kdc.principals = [...view.directory.kerberosPrincipals(), ...(config.kdcServices ?? [])];
      // So that a principal whose keys could not be read is refused with a reason
      // rather than reported as unknown (§4 of DESIGN-admin.md). The closure reads
      // whatever directory is current, so a key server that comes back is picked up
      // on the next read without the KDC being rebuilt.
      config.kdc.keysUnavailable = (name) => config.directory.keysUnavailableFor(name);
    }
    log("problems", {
      event: "directory read from the store",
      users: view.directory.userNames().length,
      groups: view.directory.groupList().length,
      ...(view.withoutVerifier.length === 0 ? {} : { withoutVerifier: view.withoutVerifier }),
      ...(view.withoutKeys.length === 0 ? {} : { withoutKeys: view.withoutKeys }),
      ...(view.reasons.length === 0 ? {} : { reasons: view.reasons }),
    });
    if (view.reasons.length > 0) {
      process.stderr.write(
        `seedmi-dc: the key management server could not be read, so a bind, a token and a ` +
        `ticket are refused while a search succeeds: ${view.reasons.join("; ")}\n`);
    }
  };
  // The write path, where a store holds the directory. Each front end has its own
  // gate on it and they are independent: LDAP wants a session bound by SASL
  // EXTERNAL with a certificate [admin] names (§6), and SCIM wants a bearer token
  // carrying dc.admin (§7). A deployment that wants no writes configures neither.
  let writer: Writer | undefined;
  let writes: LdapWriter | undefined;
  if (config.store !== undefined) {
    try {
      store = openStore(config);
      keys = KmipKeyStore.over(config.kms!);
      await fromStore();
      writer = new Writer(store, keys,
        { name: config.realm, etypes: [ETYPE.aes256, ETYPE.aes128] });
      // --sweep-keys, which runs here because it is the first point at which both the
      // store and the key server are open, and then exits: it is an operator's command
      // and not a mode the controller serves in.
      if (sweeping) {
        const { destroyed, gone, unreadable } = await writer.sweep();
        // `gone` is said and not counted as work: a key server returns what it has
        // already destroyed, and the sweep's purpose is met for those.
        process.stdout.write(destroyed.length === 0 && unreadable.length === 0
          ? "seedmi-dc: the key server holds no unreferenced material" +
            `${gone.length === 0 ? "" : ` (${gone.length} already destroyed)`}\n`
          : `seedmi-dc: destroyed ${destroyed.length} unreferenced object(s)` +
            `${gone.length === 0 ? "" : `, ${gone.length} already destroyed`}` +
            `${unreadable.length === 0 ? "" : `, and could not destroy ${unreadable.length}`}\n`);
        for (const u of unreadable) process.stdout.write(`  left: ${u.ref}: ${u.why}\n`);
        // The other direction, said and not acted on: a row whose material the key server
        // no longer holds. The sweep does not look for these — a destroyed KMIP object is
        // still listed by a Locate, so comparing the two lists cannot find them — and it
        // does not need to: `readDirectory` above has already reported each such
        // principal, with the key server's own reason, and refuses its binds. Removing
        // the row is a decision for a person: it is the only record that the principal
        // ever had that credential.
        if (unreadableMaterial.length > 0) {
          process.stdout.write("seedmi-dc: and the material of " +
            `${unreadableMaterial.join(", ")} could not be read, which no sweep removes: ` +
            "a row whose key is gone is a decision for a person\n");
        }
        store.close();
        process.exit(unreadable.length === 0 ? 0 : 1);
      }
      // The LDAP writer exists wherever a store does, and **not** only where
      // `[admin]` is configured. The administrator's certificate gates the
      // operations that need one — add, delete, modify, modify-DN are refused with
      // insufficientAccessRights for a session that is not an administrator, in
      // `ldap.ts` — while RFC 3062 Password Modify has rules of its own: a
      // principal may change its own password, authorized by the bind it already
      // made, and needs no administrator at all. While this was built inside the
      // `[admin]` branch, a deployment with a store and no administrator
      // certificate did not offer Password Modify in its root DSE and answered the
      // operation "no extended operation named ... is recognized" — so the
      // commonest write in LDAP, a user changing their own password, was
      // unavailable for want of a block that has nothing to do with it. Found by
      // running a controller configured that way.
      const held = writer;
      writes = new LdapWriter(() => held, config.domain, async () => {
        // Each applied change rebuilds the directory every reader sees, which is
        // what DESIGN-admin.md §1 means by "rebuilt after each write".
        await fromStore();
      });
      // The window in which material destroyed at the key server still works
      // here, which §4 asks be stated at start.
      process.stdout.write(
        `seedmi-dc: the directory is the store at ${config.store}, with keys from ` +
        `${config.kms!.host}:${config.kms!.port} cached for ` +
        `${Math.round(config.kms!.lifetime / 1000)}s\n`);
    } catch (e) {
      // A store that cannot be opened or does not read as a directory is a
      // mistake to fix, not a condition to serve around.
      process.stderr.write(`seedmi-dc: ${e instanceof Error ? e.message : String(e)}\n`);
      process.exit(2);
    }
  }

  // The SCIM front end. It reads whatever directory is in use and writes through
  // the one write path, where there is one; without a store it serves the
  // discovery documents and reads, and answers a write with 501.
  const scim = new ScimService(() => config.directory, config.domain, config.domainSid,
    () => config.tokens, writer === undefined ? undefined : () => writer!, async () => { await fromStore(); });

  const server: Server = createServer({ cert: config.tlsCert, key: config.tlsKey, minVersion: "TLSv1.2" } as never,
    (req, res) => {
      const url = new URL(req.url ?? "/", "https://controller");
      const json = (status: number, body: unknown, headers: Record<string, string> = {}) => {
        res.writeHead(status, { "Content-Type": "application/json", ...headers });
        res.end(JSON.stringify(body));
      };
      // The token service (tokens.ts), where [tokens] is given.
      const tokens = config.tokens;
      if (tokens !== undefined && url.pathname === "/.well-known/oauth-authorization-server" && req.method === "GET") {
        return json(200, tokens.metadata());
      }
      if (tokens !== undefined && url.pathname === "/jwks" && req.method === "GET") return json(200, tokens.jwks());
      if (tokens !== undefined && url.pathname === "/token") {
        if (req.method !== "POST") { res.writeHead(405, { Allow: "POST" }); res.end(); return; }
        const type = String(req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
        if (type !== "application/x-www-form-urlencoded") {
          return json(400, { error: "invalid_request", error_description: "the request is application/x-www-form-urlencoded" },
            { "Cache-Control": "no-store" });
        }
        const chunks: Buffer[] = [];
        let size = 0;
        req.on("data", (c: Buffer) => { size += c.length; if (size > LIMIT) req.destroy(); else chunks.push(c); });
        req.on("end", async () => {
          const out = await tokens.token(req.headers.authorization as string | undefined, Buffer.concat(chunks).toString("utf8"));
          log(out.status === 200 ? "requests" : "problems", out.log);
          res.writeHead(out.status, out.headers);
          res.end(JSON.stringify(out.body));
        });
        return;
      }
      // SCIM 2.0 (dc-scim.ts), the second front end of DESIGN-admin.md §2. Served
      // on this listener because it is HTTP, beside the token endpoint whose
      // tokens authorize it.
      if (url.pathname === "/scim/v2" || url.pathname.startsWith("/scim/v2/")) {
        const chunks: Buffer[] = [];
        let size = 0;
        req.on("data", (c: Buffer) => { size += c.length; if (size > LIMIT) req.destroy(); else chunks.push(c); });
        req.on("end", async () => {
          const out = await scim.handle({
            method: req.method ?? "GET",
            path: url.pathname.replace(/^\/scim\/v2\/?/, ""),
            query: url.searchParams,
            ...(req.headers.authorization === undefined
              ? {} : { authorization: req.headers.authorization as string }),
            ...(req.headers["content-type"] === undefined
              ? {} : { contentType: req.headers["content-type"] as string }),
            ...(req.headers["if-match"] === undefined
              ? {} : { ifMatch: req.headers["if-match"] as string }),
            ...(req.headers["if-none-match"] === undefined
              ? {} : { ifNoneMatch: req.headers["if-none-match"] as string }),
            ...(chunks.length === 0 ? {} : { body: Buffer.concat(chunks).toString("utf8") }),
          });
          if (out.log !== undefined) log(out.status < 400 ? "requests" : "problems", out.log);
          res.writeHead(out.status, out.headers ?? {});
          // A 204 and a 304 carry no body, as HTTP requires.
          res.end(out.body === undefined ? undefined : JSON.stringify(out.body));
        });
        return;
      }
      if (url.pathname === "/health" && (req.method === "GET" || req.method === "HEAD")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "ok", version: VERSION, realm: config.realm, domain: config.domain,
          users: config.directory.userNames().length, groups: config.directory.groupList().length }));
        return;
      }
      res.writeHead(404);
      res.end();
    });

  // SIGHUP: the configuration read again, and the directory rebuilt from it.
  // What fails to load, a mistake in the directory included, leaves the one in
  // use. The realm and its domain are what this instance is.
  process.on("SIGHUP", () => {
    try {
      const next = load();
      checkComplete(next);
      for (const [what, was, now] of [["realm", config.realm, next.realm], ["domain", config.domain, next.domain]] as const) {
        if (was !== now) {
          throw new ConfigError(`the ${what} is what this instance is, ${was}, and is not changed to ${now} by a reload; restart it`);
        }
      }
      server.setSecureContext({ cert: next.tlsCert, key: next.tlsKey } as never);
      ldap?.setSecureContext({ cert: next.tlsCert, key: next.tlsKey });
      if ((next.store ?? "") !== (config.store ?? "")) {
        throw new ConfigError(
          "where the directory is kept is what this instance is, and is not changed by a " +
          "reload; restart it");
      }
      config = next;
      log = logger(config);
      log("problems", { event: "reloaded", users: config.directory.userNames().length, groups: config.directory.groupList().length });
      warnPlain(config);
      // A store-backed directory is read again as well, so that an operator who
      // has run dc-import, or whose key server has come back, picks it up without
      // restarting; the configuration's own users and groups are not the
      // directory in that case, and the line above counted none.
      if (store !== undefined) void fromStore().catch((e: unknown) => {
        log("problems", { event: "reload refused", detail: e instanceof Error ? e.message : String(e) });
      });
    } catch (e) {
      log("problems", { event: "reload refused", detail: e instanceof Error ? e.message : String(e) });
    }
  });
  // LDAP (ldap.ts) on two listeners, where [listen] gives their ports: each
  // connection a session that reads the directory in use at each request, so that a
  // reload applies from the next one.
  //
  //   * `ldap_port` is LDAP over TLS, the layer there from the first octet.
  //   * `ldap_starttls_port` is cleartext, where a client installs the layer with
  //     StartTLS (RFC 4511 §4.14). RFC 4513 §2 makes that a MUST for any server
  //     offering more than an anonymous simple bind, which this one does; until it
  //     existed a client configured for StartTLS — the default for most tooling —
  //     got `protocolError` and could not discover why. Before the layer is there
  //     the session serves the root DSE, so StartTLS can be discovered, and
  //     refuses everything else with `confidentialityRequired`.
  //
  /** The subject of a connection's client certificate, read from its DER. */
  const certificateOfSocket = (socket: Partial<TLSSocketType>) => () => {
    const held = socket.getPeerCertificate?.();
    if (held === undefined || held.raw === undefined) return undefined;
    // The subject is read from the certificate's **DER**, not from Node's
    // `subject` convenience object. That object is a map of attribute names to
    // values: it has lost the order of the relative distinguished names, it cannot
    // say that one RDN held several attributes, and joining it with commas — which
    // is what this did — produces a string in which one attribute whose value
    // contains a comma is indistinguishable from two. A certificate bearing the
    // single legal common name `dcadmin,O=Example` therefore joined to exactly the
    // configured administrator's subject and bound as the administrator. That was
    // run, not reasoned about. See dn.ts.
    //
    // Where the DER cannot be read there is **no** subject, and the bind is
    // refused: falling back on the object would restore the defect.
    const subject = subjectOfCertificate(held.raw);
    if (subject === undefined) return undefined;
    return {
      subject: formatDn(subject),
      authorized: socket.authorized === true,
      // Null where the certificate validated, which is what Node sets.
      ...(socket.authorizationError ? { why: socket.authorizationError.message } : {}),
    };
  };
  /** A session over one connection, and the pump that feeds it. */
  const serveLdap = (socket: NetSocket, opts: { startTls?: boolean } = {}): void => {
    const peer = `${socket.remoteAddress ?? ""}`;
    const session = new LdapSession(() => config.directory, config.domain,
      (level, event) => log(level, event), peer, throttle, config.directMemberOf,
      // The service principal this server answers a GSSAPI bind with, where
      // the realm holds one for LDAP (PLAN-auth.md, phase 7).
      () => {
        const p = config.kdc?.principals.find((x) => x.parts[0].toLowerCase() === "ldap");
        return p === undefined ? undefined : { key: keyOf(config.kdc!, p), etype: config.kdc!.etype, parts: p.parts };
      },
      // The security identifier of the domain, which entries carry as objectSid so
      // that a CDMI server maps the identifiers of a ticket's certificate back to
      // names ([MS-PAC]).
      config.domainSid, VERSION, {
        ...(config.admin === undefined ? {} : { admin: { subjects: config.admin.subjects } }),
        certificate: certificateOfSocket(socket as Partial<TLSSocketType>),
        ...(writes === undefined ? {} : { writes }),
        ...(opts.startTls === true ? { startTls: true } : {}),
      });
    // One connection's requests are served in order. A write reaches the key
    // management server and so is asynchronous, and two requests arriving
    // together must not be applied in the order their key fetches happen to
    // finish: each is chained behind the one before.
    let turn: Promise<void> = Promise.resolve();
    let at: NetSocket = socket;
    const pump = (d: Buffer) => {
      turn = turn.then(async () => {
        const { replies, close, upgrade } = await session.receive(d);
        for (const r of replies) at.write(r);
        if (close) {
          at.end();
          return;
        }
        if (upgrade !== true) return;
        // The reply is written; now the layer. The plain socket stops being read
        // directly — a TLSSocket over it reads the handshake — and the session goes
        // on, with its authorization state reset (RFC 4513 §3.2).
        const pending = session.takePending();
        socket.removeAllListeners("data");
        const secure = new TLSSocket(socket as never, {
          isServer: true, cert: config.tlsCert, key: config.tlsKey, minVersion: "TLSv1.2",
          ...(config.admin === undefined
            ? {}
            : { requestCert: true, rejectUnauthorized: false, ca: config.admin.authority }),
        });
        at = secure as unknown as NetSocket;
        session.tlsInstalled();
        secure.on("secureConnect", () => log("requests",
          { event: "ldap tls installed", peer, by: "StartTLS" }));
        secure.on("data", pump);
        secure.on("error", () => secure.destroy());
        if (pending.length > 0) secure.emit("data", pending);
      }).catch((e: unknown) => {
        log("problems", { event: "ldap failed", peer, detail: e instanceof Error ? e.message : String(e) });
        socket.destroy();
      });
    };
    socket.on("data", pump);
    socket.on("error", () => socket.destroy());
  };
  let ldap: TLSServer | undefined;
  if (config.ldapPort !== undefined) {
    ldap = createTlsServer({
      cert: config.tlsCert, key: config.tlsKey, minVersion: "TLSv1.2",
      // A certificate is asked for where administrators are configured, and a
      // connection without one is still accepted: an ordinary client binds with a
      // password and has no certificate to send, and only a bind by EXTERNAL
      // needs one (DESIGN-admin.md §6).
      ...(config.admin === undefined
        ? {}
        : { requestCert: true, rejectUnauthorized: false, ca: config.admin.authority }),
    }, (socket) => serveLdap(socket as unknown as NetSocket));
  }
  let starttls: NetServer | undefined;
  if (config.ldapStartTlsPort !== undefined) {
    starttls = createNetServer((socket) => serveLdap(socket as unknown as NetSocket, { startTls: true }));
  }
  // The key distribution centre of the realm, where one is configured: Kerberos
  // over TCP, each message prefixed by its length in four octets (RFC 4120
  // section 7.2.2). It answers an AS-REQ with a ticket, or a KRB-ERROR.
  let kdc: NetServer | undefined;
  if (config.kdcPort !== undefined) {
    kdc = createNetServer((socket) => {
      const peer = `${socket.remoteAddress ?? ""}`;
      let held = Buffer.alloc(0);
      socket.on("data", (d: Buffer) => {
        held = Buffer.concat([held, d]);
        for (;;) {
          if (held.length < 4) return;
          const length = held.readUInt32BE(0);
          // "the high-order bit ... reserved, and MUST be set to zero".
          if ((length & 0x80000000) !== 0 || length > 1 << 20) return socket.destroy();
          if (held.length < 4 + length) return;
          const message = held.subarray(4, 4 + length);
          held = held.subarray(4 + length);
          const reply = answer(config.kdc!, message);
          const out = Buffer.alloc(4);
          out.writeUInt32BE(reply.length, 0);
          socket.write(Buffer.concat([out, reply]));
          log("requests", { event: "kerberos request", peer, answered: reply.length });
        }
      });
      socket.on("error", () => socket.destroy());
    });
  }
  const stop = () => { ldap?.close(); starttls?.close(); kdc?.close(); server.close(() => process.exit(0)); };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);

  server.listen(config.port, config.host, () => {
    const at = server.address() as { port: number };
    const announce = (ldapAt?: number) => process.stdout.write(`seedmi-dc ${VERSION}: realm ${config.realm} (${config.domain}) ` +
      `at https://${config.host}:${at.port}/` + (ldapAt === undefined ? "" : ` and ldaps://${config.host}:${ldapAt}/${baseOf(config.domain)}`) + "\n");
    const withKdc = (ldapAt?: number) => {
      const then = () => {
        announce(ldapAt);
        // The cleartext listener is named separately, since what it serves before a
        // client sends StartTLS is the root DSE and nothing else.
        if (starttls !== undefined) {
          process.stdout.write(`seedmi-dc: LDAP with StartTLS at ${config.host}:` +
            `${(starttls.address() as { port: number }).port}, which serves the root DSE until a ` +
            "client installs the TLS layer\n");
        }
      };
      if (kdc === undefined) return then();
      kdc.listen(config.kdcPort!, config.host, () => {
        then();
        process.stdout.write(`seedmi-dc: the key distribution centre of ${config.realm} at ` +
          `${config.host}:${(kdc!.address() as { port: number }).port}, for ${config.kdc!.principals.length} principal(s)\n`);
      });
    };
    const withStartTls = (ldapAt?: number) => {
      if (starttls === undefined) return withKdc(ldapAt);
      starttls.listen(config.ldapStartTlsPort!, config.host, () => withKdc(ldapAt));
    };
    if (ldap === undefined) withStartTls();
    else ldap.listen(config.ldapPort!, config.host, () => withStartTls((ldap!.address() as { port: number }).port));
  });
}

void main();
