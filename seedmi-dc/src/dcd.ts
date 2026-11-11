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
import { redirectBack, SCOPES, type AuthorizationRequest } from "./tokens.ts";
import { createServer as createTlsServer, TLSSocket, type TLSServer, type TLSSocketType } from "node:tls";
import type { Socket as NetSocket } from "node:net";
import { baseOf, LdapSession } from "./ldap.ts";
import { Throttle } from "./throttle.ts";

export const VERSION = "1.12";
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

/**
 * The origin of a validated redirect address, as a CSP source expression, for
 * the sign-in form's `form-action`. A browser checks that directive against
 * the redirects a submission produces, so the address the flow ends at has to
 * be named there or the browser drops it. An address that will not parse
 * yields `'none'`, which forbids rather than permits: this is only ever called
 * with an address `beginAuthorization` has already accepted, and a value that
 * cannot be read is not one to widen a policy with.
 */
function formTarget(redirectUri: string): string {
  try { return new URL(redirectUri).origin; } catch { return "'none'"; }
}

/**
 * The scopes this program defines, in words. A deployment names its own as
 * well (`cdmi:read` and the rest belong to a CDMI server, not to this one), and
 * those have no gloss here: a scope token is shown as it is rather than
 * guessed at, because a wrong description of a permission is worse than none.
 */
const SCOPE_MEANS: Record<string, string> = {
  [SCOPES.read]: "read this directory's users and groups",
  [SCOPES.admin]: "change this directory's users and groups",
};

/**
 * What the token will be able to do, and to what, for the sign-in page. Signing
 * in is the consent, so the page has to say what is being consented to.
 *
 * A request naming no scope is the interesting case and is said plainly: this
 * controller issues what was asked for and nothing more, so no scope means a
 * token that opens nothing, and a person told "no particular permission" can
 * tell that from a client that asked for everything.
 */
function consentBlock(asked: AuthorizationRequest, esc: (v: string) => string): string {
  const scopes = asked.scopes.length === 0
    ? `<p style="margin:.4rem 0 0">No particular permission, so the token will not by itself open anything.</p>`
    : `<ul>${asked.scopes.map((s) => `<li><code>${esc(s)}</code>` +
        (SCOPE_MEANS[s] === undefined ? "" : ` — ${esc(SCOPE_MEANS[s])}`) + `</li>`).join("")}</ul>`;
  const where = asked.resources.length === 0 ? ""
    : `<p class="where">At ${asked.resources.map((r) => esc(r)).join(", ")}</p>`;
  return `<div class="asks">It is asking to be allowed to:${scopes}${where}</div>`;
}

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
    const view = await readDirectory(store, keys, { realm: config.realm, domain: config.domain });
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

      // Cross-origin resource sharing. A browser-based client — the desktop's
      // MCP inspector, or any page that follows RFC 9728 to an authorization
      // server — fetches this controller's metadata, its JWK Set and its token
      // endpoint from another origin, this being a listener of its own. Every
      // release before 1.6 emitted no Access-Control field at all, so the
      // request was made, this controller answered it correctly, and the
      // browser threw the answer away: the page saw a failure to fetch and the
      // client reported it as a certificate it did not trust, which sent a
      // reader to accept a certificate that was already accepted.
      //
      // seedmi met the same thing in its 0.92 and settled it there: validating
      // the Origin field decides whether this server *answers*, and these
      // fields decide whether the browser hands that answer *to the page*.
      // Doing the first without the second refuses nothing and is readable by
      // nobody. The rules below are that release's, which are the standard's.
      const origin = req.headers.origin as string | undefined;
      const permitted = origin !== undefined &&
        (config.origins.includes("*") || config.origins.includes(origin));
      // The specific origin is echoed and never a bare "*", so that a client
      // making its requests in the credentials mode is not refused by the
      // browser: the Fetch standard forbids a wildcard with credentials. Vary
      // is named whether or not the origin is permitted, so that a cache
      // cannot hand one origin's answer, or one origin's refusal, to another.
      const cors: Record<string, string> = origin === undefined ? {}
        : permitted
          ? { "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true",
              "Access-Control-Expose-Headers": "WWW-Authenticate, Content-Type, ETag, Location", Vary: "Origin" }
          : { Vary: "Origin" };

      // The preflight, answered before anything is read or authenticated: a
      // browser sends no credential on one, so requiring a credential here
      // would refuse every cross-origin request before it was made.
      if (req.method === "OPTIONS" && origin !== undefined) {
        if (!permitted) {
          res.writeHead(403, { ...cors, "Content-Type": "application/problem+json" });
          res.end(JSON.stringify({ type: "about:blank", title: "This origin is not permitted.",
            detail: "[listen].origins names the origins a browser may read this controller's answers from" }));
          return;
        }
        res.writeHead(204, { ...cors,
          "Access-Control-Allow-Methods": "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS",
          // Authorization is named rather than left to a wildcard: the Fetch
          // standard excludes it from the wildcard, and every request this
          // controller answers for a client carries one.
          "Access-Control-Allow-Headers": "Authorization, Content-Type, If-Match, If-None-Match",
          "Access-Control-Max-Age": "600" });
        res.end();
        return;
      }

      const json = (status: number, body: unknown, headers: Record<string, string> = {}) => {
        res.writeHead(status, { "Content-Type": "application/json", ...cors, ...headers });
        res.end(JSON.stringify(body));
      };
      // The token service (tokens.ts), where [tokens] is given.
      const tokens = config.tokens;
      if (tokens !== undefined && url.pathname === "/.well-known/oauth-authorization-server" && req.method === "GET") {
        return json(200, tokens.metadata());
      }
      if (tokens !== undefined && url.pathname === "/jwks" && req.method === "GET") return json(200, tokens.jwks());
      // The authorization endpoint (RFC 6749 section 4.1), with the code
      // challenge of RFC 7636. A person signs in here and the client is sent a
      // code; the client proves at the token endpoint that it is the one that
      // asked, by presenting the verifier whose hash it sent. That is what lets
      // a program with no secret — a page in a browser, a desktop application —
      // obtain a token for the person using it without ever holding the
      // person's password or a credential of its own worth stealing.
      //
      // There is no session and no cookie. A GET that carries no credential
      // answers the sign-in form, and the form posts the request's own
      // parameters back as hidden fields together with the password, so the
      // whole exchange is two requests and this controller remembers nothing
      // about a browser between them. A session here would be one more thing to
      // fix to the person, to expire, and to get wrong.
      if (tokens !== undefined && url.pathname === "/authorize") {
        if (req.method !== "GET" && req.method !== "POST") {
          res.writeHead(405, { Allow: "GET, POST", ...cors }); res.end(); return;
        }
        const finish = (q: URLSearchParams, who?: { name: string; password: string }) => {
          const begun = tokens!.beginAuthorization(q);
          if (begun.kind === "refuse") {
            // The client or its redirect address is in doubt, so the answer goes
            // to the person and not to the address in question: RFC 6749 section
            // 4.1.2.1. Redirecting here is how an authorization endpoint becomes
            // a way to send somebody else's code wherever a request asks.
            res.writeHead(400, { "Content-Type": "application/problem+json", ...cors });
            res.end(JSON.stringify({ type: "about:blank", title: begun.title, detail: begun.detail }));
            return;
          }
          if (begun.kind === "error") {
            // iss on an error too: RFC 9207 section 2 has it in every
            // authorization response, and a client that may reject an answer
            // from the wrong server must be able to tell for a refusal as well
            // — otherwise an attacker's error, with its own error_description,
            // is displayed to the person as though it came from here.
            res.writeHead(302, { Location: redirectBack(begun.redirectUri,
              { error: begun.error, error_description: begun.description, state: begun.state,
                iss: tokens!.issuer }), ...cors });
            res.end();
            return;
          }
          // How the person is authenticated here. RFC 6749 section 3.1 leaves
          // this to the server — "username and password login, session
          // cookies ... is beyond the scope" — so the endpoint takes what the
          // caller already holds, and asks only where it holds nothing.
          //
          // A bearer token this controller issued, audienced at THIS
          // CONTROLLER and not at a resource. That restriction is the whole of
          // the safety: were any token of this realm accepted, a token issued
          // for a resource — one the client already holds, narrow and for one
          // endpoint — could be presented here to mint a code for a different
          // client with different scopes, and a narrow token would be a lever
          // for a broad one. A token whose audience is the authorization
          // server is a token for the authorization server, which is this
          // server as its own resource server (RFC 9068 section 2.2), and a
          // client may ask for that audience only where its registration says
          // so. Unlike a session cookie, a browser attaches none of this by
          // itself, so there is nothing here to be made to do cross-site.
          const presented = String(req.headers.authorization ?? "");
          let signedIn: { name: string } | undefined;
          if (/^Bearer /i.test(presented) && tokens !== undefined) {
            const claims = tokens.verify(presented.replace(/^Bearer /i, ""), Date.now(), config.tokens!.issuer);
            const sub = claims === undefined ? undefined : claims.sub;
            if (typeof sub === "string" && !sub.includes("@") && config.directory.user(sub) !== undefined) {
              signedIn = { name: sub };
            } else {
              log("problems", { event: "authorization refused", client: begun.client.id,
                reason: claims === undefined ? "the token is not one this controller issued for itself" : "the token names no user of this directory" });
              res.writeHead(401, { "WWW-Authenticate": `Bearer realm="${config.realm}", error="invalid_token"`,
                "Content-Type": "application/problem+json", ...cors });
              res.end(JSON.stringify({ type: "about:blank", title: "That token does not sign anyone in here.",
                detail: "A token presented at the authorization endpoint is one this controller issued with " +
                  "itself as the audience. A token for a resource is not one." }));
              return;
            }
          } else if (/^Basic /i.test(presented)) {
            // The credential the caller already holds, which is what a desktop
            // that signed a person in has. It saves the form and nothing else:
            // the password reaches this controller either way.
            let decoded = "";
            try { decoded = Buffer.from(presented.replace(/^Basic /i, ""), "base64").toString("utf8"); } catch { decoded = ""; }
            const cut = decoded.indexOf(":");
            if (cut > 0) who = { name: decoded.slice(0, cut), password: decoded.slice(cut + 1) };
          }
          if (signedIn === undefined && who === undefined) { signIn(q, undefined, begun); return; }
          // Guessing. This endpoint verifies the same password the password
          // grant and an LDAP bind verify, and until 1.11 it was the only one of
          // the three outside the throttle: ten wrong passwords here were ten
          // passwords checked, none recorded, and the eleventh attempt with the
          // right one was accepted — while the same ten at the token endpoint
          // locked the name. Throttle's own comment states the intent, that
          // "LDAP binds verify the same passwords, and are throttled by the same
          // record"; this is the third door and now shares it.
          //
          // A locked name is refused exactly as a wrong password is, which is
          // this program's existing convention (see throttle.ts) and means the
          // page says nothing about whether the name exists or is locked.
          const guessing = signedIn === undefined && who !== undefined;
          if (guessing && throttle.locked("user", who!.name)) {
            log("problems", { event: "authorization refused", user: who!.name, client: begun.client.id, reason: "locked" });
            signIn(q, "That is not a name and password of this realm.", begun);
            return;
          }
          const verdict = signedIn !== undefined ? { ok: true as const, user: { name: signedIn.name } }
            : config.directory.verify(who!.name, who!.password);
          if (guessing) {
            // "disabled" and "expired" are not wrong passwords, and a name is
            // not locked for them: the same judgement the password grant makes.
            throttle.record("user", who!.name, verdict.ok ||
              (verdict as { reason: string }).reason === "disabled" ||
              (verdict as { reason: string }).reason === "expired");
          }
          if (!verdict.ok) {
            log("problems", { event: "authorization refused", user: who!.name, client: begun.client.id, reason: (verdict as { reason: string }).reason });
            signIn(q, "That is not a name and password of this realm.", begun);
            return;
          }
          const code = tokens!.issueCode(begun, { name: verdict.user.name, groups: config.directory.groupsOf(verdict.user.name) });
          log("requests", { event: "code issued", user: verdict.user.name, client: begun.client.id, aud: begun.resources.join(" ") });
          res.writeHead(302, { Location: redirectBack(begun.redirectUri,
            { code, state: begun.state, iss: tokens!.issuer }),
            "Cache-Control": "no-store", ...cors });
          res.end();
        };
        // The form. It carries the request's own parameters so that nothing is
        // held here between the two requests, and nothing of the request is
        // taken from anywhere but the address the person arrived at.
        const signIn = (q: URLSearchParams, wrong: string | undefined, asked: AuthorizationRequest) => {
          const redirectUri = asked.redirectUri;
          const esc = (v: string) => v.replace(/[&<>"']/g, (c) =>
            ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
          const hidden = [...q.entries()].filter(([k]) => k !== "username" && k !== "password")
            .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`).join("");
          res.writeHead(wrong === undefined ? 200 : 401,
            { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store",
              // The form posts to this origin and nothing embeds it: a sign-in
              // page in a frame is a sign-in page somebody else is reading.
              //
              // form-action names the client's redirect origin as well as this
              // one, because a browser checks the directive against the
              // REDIRECTS a submission produces and not only against the
              // address the form names. `form-action 'self'` alone therefore
              // forbids the 302 that completes the flow — the one redirect the
              // whole exchange exists to perform — and the page posts, the code
              // is issued, and the browser silently drops the answer. Nothing
              // here caught it: curl followed the redirect, and no test runs a
              // browser, so a header only a browser enforces is a header only a
              // browser can refute. The origin is taken from the redirect
              // address this request already validated, so naming it grants
              // nothing that was not already granted.
              "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; " +
                `form-action 'self' ${formTarget(redirectUri)}; frame-ancestors 'none'`,
              "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", ...cors });
          res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8">` +
            `<meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in</title>` +
            `<style>body{font:16px/1.5 system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f6f7f9;color:#14181f}` +
            `form{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 1px 3px #0002;width:min(22rem,92vw)}` +
            `h1{font-size:1.1rem;margin:0 0 .25rem}p{margin:0 0 1.25rem;color:#5b6472;font-size:.9rem}` +
            `label{display:block;font-size:.85rem;margin:.75rem 0 .25rem}` +
            `input[type=text],input[type=password]{width:100%;padding:.55rem;border:1px solid #c9ced6;border-radius:6px;font:inherit;box-sizing:border-box}` +
            `button{margin-top:1.25rem;width:100%;padding:.6rem;border:0;border-radius:6px;background:#14181f;color:#fff;font:inherit;cursor:pointer}` +
            `.no{color:#a3121f;font-size:.85rem;margin:.75rem 0 0}` +
            `.asks{margin:0 0 1.25rem;padding:.75rem .9rem;background:#f6f7f9;border-radius:8px;font-size:.85rem;color:#14181f}` +
            `.asks ul{margin:.4rem 0 0;padding-left:1.1rem}.asks li{margin:.15rem 0}` +
            `.asks code{font:inherit;font-family:ui-monospace,monospace}` +
            `.asks .where{margin:.5rem 0 0;color:#5b6472;font-size:.8rem}</style></head><body>` +
            `<form method="post" action="/authorize"><h1>Sign in to ${esc(config.realm)}</h1>` +
            `<p>${esc(asked.client.id)} is asking for a token in your name.</p>${hidden}` +
            // What the token will be able to do, and to what. Signing in IS the
            // consent here — there is no second page — and consent to something
            // unnamed is not consent. A public client cannot be authenticated
            // at all (its id is not a secret; only its registered redirect
            // address ties the request to the real program), so what the person
            // is told is the whole of the control. Until 1.11 the page named the
            // client and neither the scopes nor the resource, which meant
            // nobody could decline `cdmi:admin` because nobody was shown it.
            //
            // Taken from the validated request and not from the query, so that
            // what is displayed is what will be issued.
            consentBlock(asked, esc) +
            `<label for="u">Name</label><input id="u" name="username" type="text" autocomplete="username" autofocus required>` +
            `<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>` +
            (wrong === undefined ? "" : `<p class="no">${esc(wrong)}</p>`) +
            `<button type="submit">Sign in</button></form></body></html>`);
        };
        if (req.method === "GET") { finish(url.searchParams); return; }
        const chunks: Buffer[] = [];
        let size = 0;
        req.on("data", (d: Buffer) => {
          size += d.length;
          if (size > 64 * 1024) { res.writeHead(413, cors); res.end(); req.destroy(); return; }
          chunks.push(d);
        });
        req.on("end", () => {
          const posted = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
          const name = posted.get("username") ?? "", password = posted.get("password") ?? "";
          if (name === "" || password === "") { finish(posted); return; }
          finish(posted, { name, password });
        });
        return;
      }
      if (tokens !== undefined && url.pathname === "/token") {
        if (req.method !== "POST") { res.writeHead(405, { Allow: "POST", ...cors }); res.end(); return; }
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
          res.writeHead(out.status, { ...out.headers, ...cors });
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
          res.writeHead(out.status, { ...(out.headers ?? {}), ...cors });
          // A 204 and a 304 carry no body, as HTTP requires.
          res.end(out.body === undefined ? undefined : JSON.stringify(out.body));
        });
        return;
      }
      // A health check stood here until 1.7 and is withdrawn. No standard
      // defines one: not CDMI, which does not mention health at all, and not
      // the nearest thing to a specification for it,
      // draft-inadarei-api-health-check, which expired without becoming an RFC
      // and whose vocabulary this answer did not use in any case. It was this
      // program's own plan that asked for it, nothing outside this tree's
      // tests ever called it, and it told anyone who reached the port the
      // version, the realm, the DNS domain and the size of the directory —
      // an inventory published nowhere else and of use to nobody but someone
      // matching a version against a list of known defects.
      //
      // What it was used for here was observing a reload. The tests observe
      // that through LDAP now, which is the front end this directory is
      // actually served by, and the announcement at startup names the realm
      // and both ports for an operator.
      // A path this controller does not serve, answered as a problem details
      // document (RFC 9457) rather than as an empty body. It was empty until
      // 1.6, and the one occasion a person types the root URL into a browser
      // is the one this setup asks of them — accepting a self-signed
      // certificate, or checking the controller is up — where a blank page
      // confirms neither that they reached this server nor that anything is
      // wrong. It names the paths it serves and not its version: those paths
      // are published already by the metadata document, which RFC 8414 makes
      // public, and a version is of use to nobody but someone matching it
      // against a list of known defects.
      res.writeHead(404, { "Content-Type": "application/problem+json", ...cors });
      res.end(JSON.stringify({
        type: "about:blank",
        title: "This controller serves no such path.",
        detail: "It is a domain controller, not a web site. Over HTTPS it serves " +
          (config.tokens === undefined
            ? "its SCIM front end at /scim/v2/; [tokens] is not configured, so it is no authorization server and serves no token endpoint."
            : "the authorization server metadata of RFC 8414 at /.well-known/oauth-authorization-server, " +
              "its JWK Set at /jwks, its token endpoint at /token, and its SCIM front end at /scim/v2/.") +
          " Its directory is reached over LDAP, on a port of its own.",
        instance: url.pathname,
      }));
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
    const announce = (ldapAt?: number) => {
      process.stdout.write(`seedmi-dc ${VERSION}: realm ${config.realm} (${config.domain}) ` +
        `at https://${config.host}:${at.port}/` + (ldapAt === undefined ? "" : ` and ldaps://${config.host}:${ldapAt}/${baseOf(config.domain)}`) + "\n");
      // An authorization server no browser-based client can use, said at
      // startup rather than left to be discovered. Where [tokens] is given
      // this controller is the authorization server of its realm, and a client
      // that follows RFC 9728 to it from a page fetches its metadata, its JWK
      // Set and its token endpoint across origins — which the browser permits
      // only where this controller names that origin. Naming none is a
      // deployment whose clients are not browsers, which is a reasonable thing
      // to be; it is not a reasonable thing to be by accident, and 1.7 was
      // started with a configuration written before [listen].origins existed
      // and said nothing at all. The TLS warning beside this one set the
      // precedent: a server that knows it cannot serve some client says so.
      if (config.tokens !== undefined && config.origins.length === 0) {
        process.stdout.write("seedmi-dc: [listen].origins names no origin, so no browser-based client can read " +
          "this authorization server's metadata, its JWK Set or its token endpoint: the browser discards an " +
          "answer no Access-Control-Allow-Origin permits it to read. Name the origins a page reaches this " +
          "controller from, or \"*\".\n");
      }
      // The password grant is withdrawn. RFC 9700 section 2.4 — BCP 240, the
      // current best practice — is unconditional: "The resource owner password
      // credentials grant MUST NOT be used", because it "insecurely exposes the
      // credentials of the resource owner to the client", trains people "to
      // enter their credentials in places other than the authorization server",
      // and "is not designed to work with two-factor authentication". OAuth 2.1
      // removes it, and the MCP authorization specification requires an
      // authorization server to implement OAuth 2.1.
      //
      // It is still served, because withdrawing a grant a deployment is using
      // between one version and the next breaks that deployment without
      // warning. This IS the warning. There was nothing to move to before 1.9;
      // now there is, which is what makes the removal a plan rather than a wish.
      const onPassword = config.tokens?.onPasswordGrant ?? [];
      if (onPassword.length > 0) {
        process.stdout.write(`seedmi-dc: ${onPassword.join(", ")} ` +
          `${onPassword.length === 1 ? "is registered" : "are registered"} for the password grant, which RFC 9700 ` +
          "section 2.4 says MUST NOT be used and OAuth 2.1 removes: it gives the client the person's password. " +
          "Use the authorization code flow with PKCE instead — register the client with no secret, " +
          "grants = [\"authorization_code\"] and its redirect_uris. This grant will be removed in a later " +
          "version of seedmi-dc.\n");
      }
    };
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
