// The configuration of seedmi-dac: a TOML file, and flags that win over it.
//
//   [listen]    host, port, path, certificate(_file), key(_file)
//   [provider]  decryption_key(_file), certificate(_file), signing_key(_file),
//               signing_chain(_file), replay_window_ms
//   [[server]]  name, and ca(_file) with subject, or key(_file): each CDMI
//               server this provider answers (dac-trust.ts)
//   [[rule]]    what the provider decides, first match deciding (dac-policy.ts)
//   [log]       level, file
//
// A setting this program does not take is refused rather than ignored, so a
// misspelling does not start the provider without the setting it was meant to
// change. Material is given inline or, by the _file form, in a file beside the
// configuration.

import { createPrivateKey, createPublicKey, type KeyObject, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import type { ProviderKeys } from "./dac-protocol.ts";
import type { TrustedServer } from "./dac-trust.ts";
import { type Decision, parseMask, type Rule } from "./dac-policy.ts";
import { exportJwk } from "./jose.ts";
import { parseTOML, type TOMLValue } from "./toml.ts";

export class ConfigError extends Error {}

export interface Config {
  host: string;
  port: number;
  /** The path requests are accepted at: that of cdmi_dac_uri. */
  path: string;
  tlsCert: string;
  tlsKey: string;
  keys?: ProviderKeys;
  servers: TrustedServer[];
  rules: Rule[];
  replayWindowMs: number;
  log: "off" | "problems" | "requests";
  logFile?: string;

}

export const DEFAULTS: Config = {
  host: "127.0.0.1", port: 9443, path: "/decide", tlsCert: "", tlsKey: "", servers: [], rules: [],
  replayWindowMs: 600_000, log: "off",
};

type Table = Record<string, TOMLValue>;
const table = (v: TOMLValue | undefined, where: string): Table => {
  if (v === undefined) return {};
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new ConfigError(`${where} is a table`);
  return v as Table;
};
const only = (t: Table, where: string, allowed: string[]) => {
  for (const k of Object.keys(t)) if (!allowed.includes(k)) throw new ConfigError(`${where} takes no setting ${JSON.stringify(k)}`);
};
const str = (t: Table, k: string, where: string): string | undefined => {
  const v = t[k];
  if (v === undefined) return undefined;
  if (typeof v !== "string") throw new ConfigError(`${where}.${k} is a string`);
  return v;
};
const int = (t: Table, k: string, where: string): number | undefined => {
  const v = t[k];
  if (v === undefined) return undefined;
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0) throw new ConfigError(`${where}.${k} is a whole number`);
  return v;
};
/** A setting given inline, or by its _file form in a file beside the configuration; not both. */
const material = (t: Table, k: string, where: string, dir: string): string | undefined => {
  const inline = str(t, k, where);
  const file = str(t, `${k}_file`, where);
  if (inline !== undefined && file !== undefined) throw new ConfigError(`${where} gives ${k} and ${k}_file; one is given`);
  if (file === undefined) return inline;
  try {
    return readFileSync(path.isAbsolute(file) ? file : path.join(dir, file), "utf8");
  } catch (e) {
    throw new ConfigError(`${where}.${k}_file cannot be read: ${(e as Error).message}`);
  }
};
/** The certificates of a PEM text, in order. */
const certificates = (pem: string, where: string): X509Certificate[] => {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
  if (blocks.length === 0) throw new ConfigError(`${where} holds no PEM certificate`);
  try {
    return blocks.map((b) => new X509Certificate(b));
  } catch (e) {
    throw new ConfigError(`${where} holds a certificate that does not parse: ${(e as Error).message}`);
  }
};
const derOf = (pem: string): string[] =>
  (pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [])
    .map((b) => b.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
const privateKey = (pem: string, where: string): KeyObject => {
  try {
    return createPrivateKey(pem);
  } catch (e) {
    throw new ConfigError(`${where} is not a private key: ${(e as Error).message}`);
  }
};

export function parseConfig(text: string, dir = "."): Config {
  let doc: Table;
  try {
    doc = parseTOML(text) as Table;
  } catch (e) {
    throw new ConfigError(`the configuration is not TOML: ${(e as Error).message}`);
  }
  only(doc, "the configuration", ["listen", "provider", "server", "rule", "log"]);
  const c: Config = { ...DEFAULTS, servers: [], rules: [] };

  const listen = table(doc.listen, "[listen]");
  only(listen, "[listen]", ["host", "port", "path", "certificate", "certificate_file", "key", "key_file"]);
  c.host = str(listen, "host", "[listen]") ?? c.host;
  c.port = int(listen, "port", "[listen]") ?? c.port;
  c.path = str(listen, "path", "[listen]") ?? c.path;
  if (!c.path.startsWith("/")) throw new ConfigError("[listen].path begins with /");
  c.tlsCert = material(listen, "certificate", "[listen]", dir) ?? "";
  c.tlsKey = material(listen, "key", "[listen]", dir) ?? "";

  const p = table(doc.provider, "[provider]");
  only(p, "[provider]", ["decryption_key", "decryption_key_file", "certificate", "certificate_file",
    "signing_key", "signing_key_file", "signing_chain", "signing_chain_file", "replay_window_ms"]);
  c.replayWindowMs = int(p, "replay_window_ms", "[provider]") ?? c.replayWindowMs;
  const decryption = material(p, "decryption_key", "[provider]", dir);
  const certificate = material(p, "certificate", "[provider]", dir);
  if (decryption !== undefined || certificate !== undefined) {
    if (decryption === undefined || certificate === undefined) {
      throw new ConfigError("[provider] gives a decryption key and the certificate objects name, both");
    }
    const key = privateKey(decryption, "[provider].decryption_key");
    const cert = certificates(certificate, "[provider].certificate")[0];
    const spki = (k: KeyObject) => (k.type === "public" ? k : createPublicKey(k)).export({ format: "der", type: "spki" }) as Buffer;
    if (!spki(cert.publicKey).equals(spki(key))) {
      throw new ConfigError("[provider].certificate is not the certificate of [provider].decryption_key");
    }
    // Requests are encrypted to this key, and responses signed by the signing
    // key where one is given (PLAN.md, "Its keys"); where none is, by this one.
    const signingPem = material(p, "signing_key", "[provider]", dir);
    const chainPem = material(p, "signing_chain", "[provider]", dir);
    if ((signingPem === undefined) !== (chainPem === undefined)) {
      throw new ConfigError("[provider] gives a signing key and its certificate chain, both or neither");
    }
    let signing = key;
    let signingChain: string[] | undefined;
    if (signingPem !== undefined) {
      signing = privateKey(signingPem, "[provider].signing_key");
      const chain = certificates(chainPem!, "[provider].signing_chain");
      if (!spki(chain[0].publicKey).equals(spki(signing))) {
        throw new ConfigError("the first certificate of [provider].signing_chain is not that of [provider].signing_key");
      }
      // "where the certificate for that key chains to the certificate contained
      // in the cdmi_dac_certificate metadata item": checked here, not by a CDMI
      // server refusing every response.
      const last = chain[chain.length - 1];
      if (!last.verify(cert.publicKey) && !chain.some((x) => x.raw.equals(cert.raw))) {
        throw new ConfigError("[provider].signing_chain does not chain to [provider].certificate");
      }
      signingChain = derOf(chainPem!);
    }
    c.keys = {
      decryption: key,
      certificate: exportJwk(key, { kid: "provider", x5c: derOf(certificate) }),
      signing,
      ...(signingChain === undefined ? {} : { signingChain }),
    };
  }

  const servers = doc.server === undefined ? [] : doc.server;
  if (!Array.isArray(servers)) throw new ConfigError("[[server]] is an array of tables");
  const names = new Set<string>();
  for (const [i, raw] of servers.entries()) {
    const where = `[[server]][${i}]`;
    const t = table(raw as TOMLValue, where);
    only(t, where, ["name", "ca", "ca_file", "subject", "key", "key_file", "response_uris", "response_ca", "response_ca_file"]);
    const name = str(t, "name", where);
    if (name === undefined || name === "") throw new ConfigError(`${where} gives a name`);
    if (names.has(name)) throw new ConfigError(`the server ${name} is given twice`);
    names.add(name);
    const ca = material(t, "ca", where, dir);
    const keyPem = material(t, "key", where, dir);
    if (ca === undefined && keyPem === undefined) {
      throw new ConfigError(`${where} gives a trust anchor (ca) or a registered key (key), by which its requests are authenticated`);
    }
    const subject = str(t, "subject", where);
    if (subject !== undefined && ca === undefined) throw new ConfigError(`${where}.subject applies to a chain, and no ca is given`);
    let keys: KeyObject[] = [];
    if (keyPem !== undefined) {
      try {
        keys = [createPublicKey(keyPem)];
      } catch (e) {
        throw new ConfigError(`${where}.key is not a public key: ${(e as Error).message}`);
      }
    }
    // The URIs a response may be sent to later (dac-deliver.ts): https, each
    // a URI exactly or, ending in "/", the URIs beneath it.
    const uris = t.response_uris;
    let responseUris: string[] | undefined;
    if (uris !== undefined) {
      if (!Array.isArray(uris) || uris.some((u) => typeof u !== "string")) throw new ConfigError(`${where}.response_uris is an array of strings`);
      for (const u of uris as string[]) {
        let parsed: URL;
        try {
          parsed = new URL(u);
        } catch {
          throw new ConfigError(`${where}.response_uris holds ${JSON.stringify(u)}, which is not an absolute URI`);
        }
        if (parsed.protocol !== "https:") throw new ConfigError(`${where}.response_uris holds ${u}; a response is sent over https`);
      }
      responseUris = uris as string[];
    }
    const responseCa = material(t, "response_ca", where, dir);
    if (responseCa !== undefined) certificates(responseCa, `${where}.response_ca`);
    c.servers.push({ name, anchors: ca === undefined ? [] : certificates(ca, `${where}.ca`), keys,
      ...(subject === undefined ? {} : { subject }),
      ...(responseUris === undefined ? {} : { responseUris }),
      ...(responseCa === undefined ? {} : { responseCa }) });
  }

  // [[rule]] tables, in order: the first matching a request decides it.
  const rules = doc.rule === undefined ? [] : doc.rule;
  if (!Array.isArray(rules)) throw new ConfigError("[[rule]] is an array of tables");
  for (const [i, raw] of rules.entries()) {
    const where = `[[rule]][${i}]`;
    const t = table(raw as TOMLValue, where);
    only(t, where, ["servers", "objects", "operations", "principals", "groups", "headers", "decision", "mask",
      "response_headers", "cache_seconds", "redirect_objectID", "audit_uri", "defer"]);
    const strings = (k: string): string[] | undefined => {
      const v = t[k];
      if (v === undefined) return undefined;
      if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) throw new ConfigError(`${where}.${k} is an array of strings`);
      return v as string[];
    };
    const pairs = (k: string): Record<string, string> | undefined => {
      const v = t[k];
      if (v === undefined) return undefined;
      if (v === null || typeof v !== "object" || Array.isArray(v) || Object.values(v).some((x) => typeof x !== "string")) {
        throw new ConfigError(`${where}.${k} is a table of strings`);
      }
      return v as Record<string, string>;
    };
    const decision = str(t, "decision", where);
    if (decision !== "grant" && decision !== "narrow" && decision !== "pass" && decision !== "deny") {
      throw new ConfigError(`${where}.decision is grant, narrow, pass or deny`);
    }
    const maskText = str(t, "mask", where);
    let mask: number | undefined;
    if (decision === "grant" || decision === "narrow") {
      if (maskText === undefined) throw new ConfigError(`${where} decides ${decision}, and gives the mask it applies`);
      mask = parseMask(maskText);
      if (mask === undefined) throw new ConfigError(`${where}.mask ${JSON.stringify(maskText)} is not a mask`);
    } else if (maskText !== undefined) {
      throw new ConfigError(`${where} decides ${decision}, which applies no mask of its own`);
    }
    const operations = strings("operations");
    for (const o of operations ?? []) {
      if (!["cdmi_read", "cdmi_modify", "cdmi_delete", "*"].includes(o)) {
        throw new ConfigError(`${where}.operations names ${JSON.stringify(o)}; the draft defines cdmi_read, cdmi_modify and cdmi_delete`);
      }
    }
    const ruleServers = strings("servers");
    for (const n of ruleServers ?? []) {
      if (n !== "*" && !c.servers.some((sv) => sv.name === n)) throw new ConfigError(`${where}.servers names ${n}, which no [[server]] gives`);
    }
    const responseHeaders = pairs("response_headers");
    for (const name of Object.keys(responseHeaders ?? {})) {
      // "A series of headers that start with CDMI-DAC- to be returned to the CDMI client."
      if (!name.toUpperCase().startsWith("CDMI-DAC-")) {
        throw new ConfigError(`${where}.response_headers names ${name}; a response header begins CDMI-DAC-`);
      }
    }
    const headers = pairs("headers");
    const auditUri = str(t, "audit_uri", where);
    if (auditUri !== undefined) {
      try {
        new URL(auditUri);
      } catch {
        throw new ConfigError(`${where}.audit_uri is an absolute URI`);
      }
    }
    const cacheSeconds = int(t, "cache_seconds", where);
    const defer = t.defer;
    if (defer !== undefined && typeof defer !== "boolean") throw new ConfigError(`${where}.defer is true or false`);
    const redirect = str(t, "redirect_objectID", where);
    // "A CDMI client shall treat an object ID as opaque", and none is "longer
    // than 255 octets in either form" (Object IDs).
    if (redirect !== undefined && (redirect === "" || Buffer.byteLength(redirect) > 255 || /[\u0000-\u001f\u007f]/.test(redirect))) {
      throw new ConfigError(`${where}.redirect_objectID is an object ID: not empty, at most 255 octets, no control characters`);
    }
    const rule: Rule = { decision: decision as Decision };
    if (ruleServers !== undefined) rule.servers = ruleServers;
    const objects = strings("objects");
    if (objects !== undefined) rule.objects = objects;
    if (operations !== undefined) rule.operations = operations;
    const principals = strings("principals");
    if (principals !== undefined) rule.principals = principals;
    const groups = strings("groups");
    if (groups !== undefined) rule.groups = groups;
    if (headers !== undefined) rule.headers = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
    if (mask !== undefined) rule.mask = mask;
    if (responseHeaders !== undefined) rule.responseHeaders = responseHeaders;
    if (cacheSeconds !== undefined) rule.cacheSeconds = cacheSeconds;
    if (redirect !== undefined) rule.redirectObjectID = redirect;
    if (auditUri !== undefined) rule.auditUri = auditUri;
    if (defer === true) rule.defer = true;
    c.rules.push(rule);
  }

  const log = table(doc.log, "[log]");
  // The log is JSON Lines and has no other form, so [log].format is gone: a
  // configuration that names it is refused rather than silently ignored, since
  // a deployment that asked for the text format would otherwise get JSON and
  // not be told.
  only(log, "[log]", ["level", "file"]);
  const level = str(log, "level", "[log]");
  if (level !== undefined) c.log = logLevel(level);
  const file = str(log, "file", "[log]");
  if (file !== undefined) c.logFile = path.isAbsolute(file) ? file : path.join(dir, file);
  return c;
}

const logLevel = (v: string): Config["log"] => {
  if (v !== "off" && v !== "problems" && v !== "requests") throw new ConfigError(`the log level is off, problems or requests`);
  return v;
};

/** The flags this program takes, and what each needs. */
const FLAGS: Record<string, boolean> = {
  "--config": true, "--host": true, "--port": true, "--log": true, "--log-file": true,
  "--help": false, "-h": false, "--version": false, "-v": false, "--certificate-jwk": false,
};

/** The flags of a command line, refusing one this program does not take. */
export function readArgv(argv: string[]): Record<string, string | true> {
  const out: Record<string, string | true> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!(a in FLAGS)) throw new ConfigError(`${a} is not a flag of this program; --help lists them`);
    if (FLAGS[a]) {
      if (i + 1 >= argv.length) throw new ConfigError(`${a} takes a value`);
      out[a] = argv[++i];
    } else {
      out[a] = true;
    }
  }
  return out;
}

/** The flags applied over the configuration: a flag wins. */
export function applyFlags(c: Config, f: Record<string, string | true>): Config {
  const out = { ...c };
  if (typeof f["--host"] === "string") out.host = f["--host"];
  if (typeof f["--port"] === "string") {
    const n = Number(f["--port"]);
    if (!Number.isInteger(n) || n < 0 || n > 65535) throw new ConfigError("--port is a port number");
    out.port = n;
  }
  if (typeof f["--log"] === "string") out.log = logLevel(f["--log"]);
  if (typeof f["--log-file"] === "string") out.logFile = f["--log-file"];
  return out;
}

/** What the provider needs to run. */
export function checkComplete(c: Config): void {
  if (c.tlsCert === "" || c.tlsKey === "") throw new ConfigError("[listen] gives the certificate and key the provider presents");
  if (c.keys === undefined) throw new ConfigError("[provider] gives the decryption key and the certificate objects name");
  if (c.servers.length === 0) {
    throw new ConfigError("no [[server]] is given: the provider answers no CDMI server, and would refuse every request");
  }
}
