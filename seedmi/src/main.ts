// The server. Everything it needs is read from a configuration file, a
// command line, or both, with a flag winning over the file.

import { PipeService } from "./pipe.ts";
import { DomainController, DomainControllers } from "./domain-controller.ts";
import { X509Certificate } from "node:crypto";
import { DacClient } from "./dac.ts";
import { kmsIdentity } from "./dac-kms.ts";
import { setOriginatedPolicy } from "./originated.ts";
import { type KeyManagement, KmipKms } from "./kms.ts";
import { retrieveOwnCredential, PASSWORD, retrieveCertificate, retrieveSecret } from "./credential-use.ts";
import { Store } from "./store.ts";
import { Binding, setDohItem, setValueRepresentations } from "./binding.ts";
import { Exports } from "./exports.ts";
import { NfsServer } from "./nfs-server.ts";
import { ownBases, setSelfBases } from "./imports.ts";
import { setServiceCredential, setImportSecretResolver, setDelegation } from "./layers.ts";
import { ANONYMOUS, defaultRootACL, type Principal } from "./acl.ts";
import { SmbServer } from "./smb-server.ts";
import { TLSServer } from "./tls.ts";
import { Discovery } from "./discovery.ts";
import { Mcp, setVersion as setMcpVersion } from "./mcp.ts";
import { ResourceServer } from "./mcp-auth.ts";
import { Log } from "./log.ts";
import { MqttExporter } from "./mqtt-export.ts";
import { MqttImporter } from "./mqtt-import.ts";
import {
  type Config, ConfigError, applyArgv, certificateOf, checkReferences, parseConfig, readConfig,
  unknownFlag, usage,
} from "./config.ts";
import { connect as netConnect } from "node:net";
import { VERSION } from "./version.ts";
import {
  measureServiceLevel, serviceLevelAchieved, setServiceLevel,
} from "./service-level.ts";

const argv = process.argv;

if (argv.includes("--help") || argv.includes("-h")) {
  console.log(usage());
  process.exit(0);
}

// Answered before anything else is read, so that the version of a build
// can be asked without a configuration that would start it.
if (argv.includes("--version") || argv.includes("-v")) {
  console.log(`seedmi ${VERSION}`);
  process.exit(0);
}

// A flag this server does not take is refused rather than ignored: a
// misspelled flag that starts the server with the setting it was meant
// to change is worse than one that does not start it.
const unknown = unknownFlag(argv);
if (unknown !== undefined) {
  console.error(`seedmi: ${JSON.stringify(unknown)} is not a flag seedmi takes`);
  console.error("seedmi: run with --help for the flags it does take");
  process.exit(2);
}
const flag = (name: string): string | undefined => {
  const i = argv.lastIndexOf(`--${name}`);
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
};

let config: Config;
try {
  const file = flag("config");
  config = applyArgv(file === undefined ? parseConfig("") : readConfig(file), argv);
  checkReferences(config);
} catch (err) {
  const name = (err as Error).name;
  if (err instanceof ConfigError || name === "TOMLError") {
    console.error(`seedmi: ${(err as Error).message}`);
    process.exit(2);
  }
  throw err;
}

// The principals, and the list on the root container object of a new
// store. Where none are configured every request is the anonymous
// principal, so the draft's own default would lock the store away.
// "Where a root container object is created and no access control list is
// supplied, the CDMI server shall place an access control list containing
// the following access control entry on that container object", being
// OWNER@ with ALL_PERMS, and an object with no list grants nothing to
// anyone: "this condition is not expected, since a CDMI server places a
// default access control list on a root container object as required by
// this subclause." This server created a store with no list at all where
// no [[user]] was configured, which left it both sealed and unconformant,
// while the startup message said it was open (cvwm deployment notes).
//
// Who owns it depends on who can authenticate:
//
//   * a [[user]] is configured: the first of them, as before;
//   * no [[user]] and no domain controller: every request is ANONYMOUS@,
//     which is then the only principal there is, so it owns the root and
//     the store is open, as the message says;
//   * no [[user]] but a domain controller: principals are real and none of
//     them is known here, so the root is owned by no one and a principal
//     holding the backup_operator privilege sets its list. That is said at
//     startup rather than left to be discovered.
//
// Making ANONYMOUS@ the owner opened the root and left everything created
// within it sealed, which is the same fault one level down. An object created
// by the anonymous principal is owned by no one -- the store records "" for it
// -- and the entry the object inherits names OWNER@, which "matches nobody"
// where the owner is "". So a client could create an object and not read back
// what it had just written: 201 to the PUT and 403 to the GET. defaultRootACL
// takes an argument for exactly this case, naming ANONYMOUS@ in place of
// OWNER@ in the inheritable entry, and it was never passed.
const anonymousOnly = config.users.length === 0 && config.domainControllers.length === 0;
const controllerOnly = config.users.length === 0 && config.domainControllers.length > 0;
const owner = config.users.length > 0
  ? config.users[0].name
  : (controllerOnly ? "" : "ANONYMOUS@");
const store = await Store.open(config.store,
  { owner, acl: defaultRootACL(anonymousOnly) });

const log = new Log(config.logLevel, config.logFormat, config.logFile);
/** The certificates of a PEM chain, as the x5c parameter of a JWK carries them. */
const pemChain = (pem: string): string[] =>
  [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)]
    .map((m) => m[1].replace(/\s+/g, ""));

// Delegated access control, where this server is configured for it: the key
// of a configured certificate signs a request and a response is encrypted to
// it. Until phase 6 of PLAN-dac.md that key is held here rather than operated
// in place at a key management server.
let dacClient: DacClient | undefined;
// The binding, once made: the identity resolves its keys through it, when first used.
let bindingMade: Binding | undefined;
if (config.dac !== undefined) {
  // Both keys of the identity are credentials of this server, held at the key
  // management server the root domain names as default, and operated there:
  // requests are signed by Sign, responses unwrapped by Decrypt. This server
  // holds neither (dac-kms.ts). Before 0.50 they were private keys of
  // [[certificate]] entries.
  const dac = config.dac;
  dacClient = new DacClient({
    identity: kmsIdentity(() => bindingMade!.credentialContext(), () => store.root(), {
      signing: dac.signingKeyId,
      encryption: dac.encryptionKeyId,
      ...(dac.signingChain === undefined ? {} : { signingChain: pemChain(dac.signingChain) }),
      ...(dac.encryptionChain === undefined ? {} : { encryptionChain: pemChain(dac.encryptionChain) }),
    }),
    methods: dac.methods,
    ...(dac.ca === undefined ? {} : { ca: dac.ca }),
    ...(dac.responseWindowMs === undefined ? {} : { responseWindowMs: dac.responseWindowMs }),
    ...(dac.responseUri === undefined ? {} : { responseUri: dac.responseUri }),
  });
  console.log(`seedmi: delegated access control, signing with ${dac.signingKeyId} and unwrapping with ` +
    `${dac.encryptionKeyId} at the root domain's key management server, over ${dac.methods.join(", ")}`);
  // The same thing in the log, so that this half of the record says what wrote
  // it. The line above goes to standard output; a log read on its own said
  // nothing about its producer, and the format of these records changed in
  // 0.86, so a reader looking at records from an older build had no way to tell
  // that from the records themselves. seedmi-dac writes the same record.
  log.dac({
    event: "started", server: "seedmi", version: VERSION, methods: dac.methods,
    ...(dac.responseUri === undefined ? {} : { responseUri: dac.responseUri }),
  });
}

// What this deployment achieves for the service-level items of Annex D. The
// latency and the throughput are measured here, once, against the directory the
// store lives in: the items define both "as measured from the edge of the cloud
// and factoring out any propagation latency between the CDMI client and the CDMI
// server", so what is measured is the storage and not the network. The rest is
// configuration, no measurement revealing which subdivision of which country a
// process is running in or what backup arrangement stands behind it.
{
  const measured = await measureServiceLevel(config.store);
  setServiceLevel({ ...measured, ...(config.serviceLevel ?? {}) });
  const level = serviceLevelAchieved();
  console.log("seedmi: service level, one copy on one infrastructure, " +
    `${level.latency} ms to first byte, ` +
    `${Math.round((level.throughput ?? 0) / (1024 * 1024))} MiB/s on retrieve` +
    (level.regions === undefined ? "" : `, stored in ${level.regions.join(", ")}`) +
    (level.rpo === undefined ? "" : `, RPO ${level.rpo}s`) +
    (level.rto === undefined ? "" : `, RTO ${level.rto}s`));
}
// The cdmi_representations capability and item, off unless the configuration
// asks for them. Set before the binding is built, so that the first capability
// object served already agrees with it.
setValueRepresentations(config.valueRepresentations);
// The cdmi_domain_doh item and its capability, likewise set before the binding
// is built so that the first capability object served agrees with it.
setDohItem(config.discovery.doh);
const binding = new Binding(store, config.base, log, dacClient);
bindingMade = binding;
// The bootstrap a client reads to begin discovery, where the configuration
// gives one. seedmi speaks no DNS: the records it leads to are published by
// seedmi-mdns on the local link and by seedmi-zone into a real zone.
if (config.discovery.resolver !== undefined) {
  const item: Record<string, unknown> = {
    resolver: config.discovery.resolver,
    ...(config.discovery.browseDomains === undefined ? {} : { browse_domains: config.discovery.browseDomains }),
  };
  if (binding.publishDiscovery(item)) {
    console.log("seedmi: service discovery, cdmi_domain_doh published on the root domain object naming " +
      config.discovery.resolver);
  }
} else if (config.discovery.doh) {
  // The capability without the item: a deployment that means a client to set
  // the item asks for exactly this, and one that meant to publish a resolver
  // and left it out sees the capability, reads the domain object, and finds
  // nothing — with nothing said either way until 0.106.
  console.log("seedmi: service discovery, cdmi_domain_doh accepted and reported; " +
    "[discovery] names no resolver, so none is published and a client sets the item");
}
for (const u of config.users) {
  binding.directory.add(
    `${u.name}:${u.password}:${u.groups.join(",")}:${[...(u.administrator ? ["admin"] : []), ...u.privileges].join(",")}`);
}
// The service credential a remote import in service identity mode presents
// where its entry names none: a credential reference, resolved at the root
// domain's default key management server at each use (credential-use.ts).
if (config.serviceCredential !== undefined) {
  const name = config.serviceCredential;
  setServiceCredential(async () =>
    (await retrieveOwnCredential(binding.credentialContext(), store.root(), name)).octets);
}

// The principal a configured user name resolves to, with its groups and
// administrative status, as the protocol binding resolves it. The SMB
// server and the S3 exports authenticate by their own protocols, and
// act as the principal so resolved.
const principalOf = (name: string): Principal | undefined => {
  const u = config.users.find((x) => x.name.toLowerCase() === name.toLowerCase());
  if (u === undefined) return undefined;
  return binding.directory.resolve(
    "Basic " + Buffer.from(`${u.name}:${u.password}`, "utf8").toString("base64"));
};

// An authorization server of this server's own stood here until 0.128, run by
// [oauth].server so that delegated identity could be demonstrated without an
// external party. A CDMI server is not an authorization server, and a program
// that can mint a credential is a different thing to operate from one that can
// only verify, so it is gone. A deployment names its own authorization server
// with [oauth].token_endpoint and [oauth].verify_key, which is what every
// deployment did in any case; the tests use `oauth-stub.ts`, which is not part
// of the release.

const tokenEndpoint = config.oauth.tokenEndpoint;
// The key an incoming token is verified with, from the configuration: the
// public half of the key the deployment's authorization server signs with, or
// the shared secret. Until 0.128 it could also come from the built-in server,
// whose generated public half no configuration could state.
//
// The audiences it answers to are every resource identifier of this one server:
// "The CDMI server shall be the MCP server. The two are one server", so a
// token obtained for the MCP endpoint was obtained for this server. Only
// [oauth].audience was accepted until 0.88, so an MCP client that followed the
// protected resource metadata — which names the endpoint as the resource, as
// RFC 9728 requires — obtained a token for the endpoint and had it refused by
// that endpoint, whatever else it got right.
const audiences = [
  ...(config.oauth.audience === undefined ? [] : [config.oauth.audience]),
  ...(config.mcp === undefined ? [] : [config.mcp.uri]),
];
const verifying = config.oauth.verifyKey === undefined ? undefined : {
  key: config.oauth.verifyKey,
  algorithm: config.oauth.algorithm,
  issuer: config.oauth.issuer,
  audience: audiences,
};
if (verifying !== undefined) binding.directory.tokens = verifying;
setDelegation(tokenEndpoint === undefined ? undefined : {
  tokenEndpoint,
  clientId: config.oauth.clientId,
  ...(config.oauth.tokenEndpointCa === undefined ? {} : { ca: config.oauth.tokenEndpointCa }),
  ...(config.oauth.clientSecretId === undefined ? {} : {
    clientSecret: async () => (await retrieveOwnCredential(binding.credentialContext(), store.root(),
      config.oauth.clientSecretId!)).octets.toString("utf8"),
  }),
});

// The certificates an export entry may name, and the one the protocol
// binding presents. Both are held in the configuration file until a key
// management server is supported.
const certificate = (id: string) => {
  const c = certificateOf(config, id);
  return c ? { chain: c.chain, key: c.key } : undefined;
};

// The NFS server is built before the exports, because an NFS export
// entry establishes an export on it, and is reported active where it
// does. It begins listening once the store is ready.
let nfs: NfsServer | undefined;
if (config.nfs.enabled) {
  nfs = new NfsServer({ store, log, ...(dacClient === undefined ? {} : { dac: dacClient }),
    mapCredentials: config.nfs.mapCredentials,
    // Resolving an `AUTH_SYS` identity at a domain controller (§8 of the controller's
    // DESIGN-admin.md). Late-bound, because the controllers are built further down —
    // an export entry establishes an export on this server, so it is built first.
    //
    // **Which controller** is a question the draft does not answer and this server
    // cannot: an NFS request carries a uid and no domain, and a POSIX uid space is flat
    // where CDMI domains are a tree, so a uid alone does not say which directory should
    // be asked. Where exactly one controller is configured there is no ambiguity and it
    // resolves; where several are, nothing is resolved and the start says so, rather
    // than this server picking one and silently giving a person another domain's
    // identity. Recorded in NOTES-on-domain-controllers.md as an ECR candidate.
    resolveSys: (uid, gid, gids) => {
      const only = nfsController;
      if (only === undefined) return Promise.resolve(undefined);
      return only.fromPosix(uid, [gid, ...gids]);
    } });
}
/** The one controller that resolves NFS sys credentials, where there is exactly one. */
let nfsController: DomainController | undefined;

// The SMB server, likewise, where [smb] enables it. Before 0.2 none was
// started, while the SMB export capabilities were published.
let smb: SmbServer | undefined;
if (config.smb.enabled) {
  smb = new SmbServer({
    ...(dacClient === undefined ? {} : { dac: dacClient }),
    passwords: Object.fromEntries(config.users.map((u) => [u.name, u.password])),
    principal: (user, anonymous) => anonymous
      ? ANONYMOUS
      : principalOf(user) ?? { ...ANONYMOUS, name: user },
    // A Kerberos ticket, where a domain of this server names a realm
    // (revision 282; PLAN-auth.md, phase 8).
    kerberos: async (token) => {
      const got = await binding.smbKerberos(token);
      if (got === undefined) throw new Error("no realm of this server accepts the ticket");
      return got;
    },
    log,
  });
}

// What publishes the values of a queue object to an MQTT broker. It
// connects where the configuration says to; otherwise an entry is
// validated and reported and no connection is made.
const mqtt = new MqttExporter({
  store, connect: config.mqtt.enabled,
  // The password an entry's password_secret_id addresses, retrieved from the
  // key management server the owning domain names, each time it connects.
  resolvePassword: (node, reference) =>
    retrieveSecret(binding.credentialContext(), node, reference, PASSWORD),
  resolveCertificate: (node, reference) => retrieveCertificate(binding.credentialContext(), node, reference),
  // The authority an export that publishes outward publishes under: the
  // principal that created the entry, and whether the list of the object still
  // grants it READ_OBJECT (revision 365).
  mayPublish: (node, principal) => binding.mayPublishAs(node, principal),
});
// The secret an import entry's credential_id addresses, retrieved from the key
// management server the importing object's domain names, each time the import
// source is opened.
setImportSecretResolver(async (node, reference) =>
  (await retrieveSecret(binding.credentialContext(), node, reference, PASSWORD)).octets);

const mqttImports = new MqttImporter({
  store, connect: config.mqtt.enabled,
  resolvePassword: (node, reference) =>
    retrieveSecret(binding.credentialContext(), node, reference, PASSWORD),
  resolveCertificate: (node, reference) => retrieveCertificate(binding.credentialContext(), node, reference),
});
binding.mqttImports = mqttImports;

binding.exports = new Exports(store, {
  // A credential reference is accepted where a key management server is
  // configured; the servers are set on the binding further down.
  kmsConfigured: () => binding.keyManagement.length > 0,
  nfs,
  log,
  mqtt,
  // An object served through an export is governed by its provider as one
  // served through the protocol binding is.
  ...(dacClient === undefined ? {} : { dac: dacClient }),
  originCaps: config.exportOrigins,
  scheme: config.exportScheme,
  port: String(config.port),
  tlsPort: config.tlsPort === undefined ? undefined : String(config.tlsPort),
  base: config.base,
  // A certificate this server holds on its own account for a host, which is
  // how an export at an https origin is served: "For an origin for which no
  // element is present, or where the field is absent, the CDMI server shall
  // obtain a certificate by its own means." The protocol binding's is tried
  // first, then each [[certificate]] in the order configured, and the first
  // that covers the host is presented. Before 0.51 only the binding's was
  // tried, the others being reached through an entry's certificates field,
  // which this server no longer accepts (exports.ts).
  hostCertificate: (host) => {
    const ids = [...(config.tlsCertificate === undefined ? [] : [config.tlsCertificate]),
      ...config.certificates.map((c) => c.id)];
    for (const id of ids) {
      const pair = certificate(id);
      if (pair === undefined) continue;
      try {
        const x = new X509Certificate(pair.chain);
        if (x.checkHost(host) !== undefined || x.checkIP(host) !== undefined) return pair;
      } catch {
        continue;
      }
    }
    return undefined;
  },
  // The versions this server serves, which the cdmi_export_nfs_versions
  // capability reports (revision 245).
  nfsFeatures: config.nfs.enabled ? ["NFSv4.1", "NFSv4.2"] : [],
  nfsAddresses: config.nfs.enabled ? [config.nfs.host] : [],
  smb,
  // No SMB server, no SMB version: an entry is refused as naming a
  // capability that is not present, rather than accepted and not served.
  ...(smb === undefined ? { smbFeatures: [] } : { smbAddresses: [config.smb.host] }),
  host: config.host,
  s3Credentials: (accessKey) => {
    const k = config.s3Keys.find((x) => x.accessKey === accessKey);
    return k === undefined ? undefined : { secret: k.secret, principal: k.user };
  },
  s3Principal: principalOf,
  // An HTTP export whose entry names an authentication scheme associates
  // each request with the principal its credentials resolve to, as a
  // request of the protocol binding is associated.
  exportPrincipal: (req, ns) => binding.exportPrincipal(req, ns),
  // An export naming "bearer" is an OAuth resource: its challenge names
  // where this server publishes protected resource metadata, which is the
  // endpoint of the CDMI over MCP binding where that is served.
  resourceMetadataBase: config.mcp?.uri,
  // A lock refuses an operation however it reaches the object; an HTTP
  // export reports it as 403 Forbidden (revision 327).
  lockCovering: (ns, operation) => binding.lockRefusing(ns, operation),
  // The plaintext of an encrypted object, for a request served under an
  // identity: the key is obtained under that identity and is not retained.
  decryptForExport: (ref, who) => binding.decryptForExport(ref, who),
  // The cdmi_representation_default item that applies to an object, which is data
  // system metadata and so is inherited from the container objects above it. The
  // export negotiates among representations and needs the default to fall back on
  // and to break a tie with; the binding resolves the inheritance.
  defaultRepresentationOf: (ref) => binding.defaultRepresentationItem(ref),
  // A Kerberos service ticket as a temporary credential, where the domain of
  // the bucket names a realm (revision 282; PLAN-auth.md, phase 8).
  s3Temporary: (token, bucket) => binding.temporaryS3Credentials(token, bucket),
});

if (config.rootExport !== undefined) {
  const changed = binding.exports.establish(config.rootExport, config.exportOrigins,
    config.rootExportPath);
  console.log(`seedmi: an HTTP export ${JSON.stringify(config.rootExport)} of / at ` +
    `${config.exportOrigins.join(", ")}${config.rootExportPath}` +
    (changed ? "" : " (unchanged)"));
  // Each origin is said to be served or not, by what the entry reports as
  // provided, and a problem that does not stop it being served (path-in-use,
  // where the binding's own path lies within the export's) is a note. Before
  // 0.46 every problem was reported as the export not being served, though the
  // entry was active and served.
  const reported = (await binding.exports.report(store.root()))[config.rootExport] as
    { origins_provided?: string[]; last_problems?: { type?: string; detail?: string; cdmi_origin?: string }[] } |
    undefined;
  const provided = reported?.origins_provided ?? [];
  for (const origin of config.exportOrigins) {
    const blocking = (reported?.last_problems ?? []).find((p) => p.cdmi_origin === origin &&
      !provided.includes(origin));
    if (blocking !== undefined) {
      console.log(`seedmi: the HTTP export ${JSON.stringify(config.rootExport)} is not served at ${origin}: ` +
        `${blocking.detail ?? ""}`);
    }
  }
  for (const p of reported?.last_problems ?? []) {
    if (p.cdmi_origin !== undefined && !provided.includes(p.cdmi_origin)) continue;
    console.log(`seedmi: the HTTP export ${JSON.stringify(config.rootExport)} is served` +
      `${p.cdmi_origin === undefined ? "" : ` at ${p.cdmi_origin}`}, but: ${p.detail ?? ""}`);
  }
}

const server = await binding.listen(config.port, config.host);
setSelfBases(config.selfBases.length > 0
  ? config.selfBases
  : [
    `http://${config.host}:${config.port}${config.base}`,
    ...(config.tlsPort === undefined
      ? []
      : [`https://${config.host}:${config.tlsPort}${config.base}`]),
  ]);

// One TLS listener answers the binding and the exports, presenting the
// certificate that belongs to the name the client asked for.
let tls: TLSServer | undefined;
if (config.tlsPort !== undefined) {
  const bindingPair = certificate(config.tlsCertificate!);
  tls = new TLSServer({
    binding: bindingPair,
    forHost: (host) => {
      for (const placed of binding.exports?.httpPlaced() ?? []) {
        for (const origin of placed.entry.origins) {
          if (!origin.startsWith("https://")) continue;
          if (origin.slice(8).split(":")[0].toLowerCase() !== host) continue;
          const pair = binding.exports!.certificateFor(placed.entry, origin);
          if (pair) return pair;
        }
      }
      return bindingPair;
    },
  });
  await tls.listen(config.tlsPort, config.host, (req, res) => {
    void binding.handle(req, res);
  });
  // A pipe's WebSocket, on this listener alone (RELAY-draft-2.md section 5.2).
  tls.onUpgrade((req, socket, head) => binding.handleUpgrade(req, socket, head, true));
}

// The discovery tree, by which a client that knows only the origin
// finds a base URI and the capabilities of this server. A server
// serves it only where it controls the origin, so it is configured
// rather than assumed.
if (config.wellKnown) {
  const bases = [
    `http://${config.host}:${config.port}${config.base}`,
    ...(config.tlsPort === undefined
      ? []
      : [`https://${config.host}:${config.tlsPort}${config.base}`]),
  ];
  binding.discovery = new Discovery({
    ...(config.wellKnownOrigins === undefined
      ? {}
      : { origins: () => config.wellKnownOrigins! }),
    namespaces: () => [
      ...bases.map((uri, i) => ({
        name: i === 0 ? config.namespaceName : `${config.namespaceName}-tls`,
        uri,
        store,
      })),
      // "A base URI comes into being when a CDMI export establishes it":
      // such a base URI is offered in the discovery namespace beside the
      // ones this server is configured with (revision 327).
      ...(binding.exports?.cdmiBases() ?? []).map((b) => ({
        name: b.name, uri: b.uri, store, exported: true,
      })),
    ],
    capability: (ns) => binding.capabilityRepresentation(ns),
    // The host this deployment is reached at, as [http] host configures it,
    // and not the Host header field of a request (revision 297).
    host: () => config.host,
    principal: (req) =>
      binding.directory.resolve(req.headers.authorization as string | undefined),
  });
}

if (nfs) await nfs.listen(config.nfs.port, config.nfs.host);
if (smb) await smb.listen(config.smb.port, config.smb.host);

console.log(`seedmi: ${config.store} at http://${config.host}:${config.port}${config.base}`);
if (tls) {
  console.log(`seedmi: and at https://${config.host}:${config.tlsPort}${config.base}`);
}
if (nfs) console.log(`seedmi: NFSv4.1 at ${config.nfs.host}:${config.nfs.port}`);
if (smb) console.log(`seedmi: SMB at ${config.smb.host}:${config.smb.port}`);
if (config.s3Keys.length > 0) {
  console.log(`seedmi: ${config.s3Keys.length} S3 access key(s)`);
}
if (binding.discovery) {
  console.log(`seedmi: a discovery tree at /.well-known/cdmi/`);
}
// The URIs this server may make a request of its own to. Nothing is permitted
// until the configuration says so, as the draft requires.
setOriginatedPolicy({
  permitted: config.permit.map((p) => ({ uri: p.uri, addresses: p.addresses })),
  maxRedirects: config.originated.maxRedirects,
  maxResponseBytes: config.originated.maxResponseBytes,
  timeoutMs: config.originated.timeoutMs,
});
if (config.permit.length > 0) {
  console.log(`seedmi: ${config.permit.length} permitted origin(s) for requests this server makes`);
}

// The key management servers. None is reached until a feature uses it; a KMIP
// server that cannot be reached is reported when it is used.
// Every key management server is reached over KMIP: seedmi holds none within
// itself, the one it is used with being the separate program seedmi-kms.
const keyManagement: KmipKms[] = config.kms.map((k) =>
  new KmipKms({ label: k.label, host: k.host, port: k.port, ca: k.ca, certificate: k.certificate, key: k.key,
    ...(k.servername === undefined ? {} : { servername: k.servername }),
    ...(k.timeoutMs === undefined ? {} : { timeoutMs: k.timeoutMs }) }));
// The key management servers a domain may name, so that a scope it declares
// is claimed at the one that holds it (kms-binding.ts).
binding.keyManagement = keyManagement;

// "A flag that prints the delegated access control signing identity as a
// PEM public key or a JWK, mirroring dacd --certificate-jwk, would unblock
// it": a provider authenticates this server by that key, and since 0.50
// both identity keys are held at the key management server, so nothing on
// this machine holds a copy to hand to an operator (weedmi, 0.70).
if (argv.includes("--dac-identity")) {
  if (dacClient === undefined) {
    console.error("seedmi: no [dac] is configured, so this server has no delegated access control identity");
    process.exit(2);
  }
  const form = flag("dac-identity") ?? "pem";
  if (form !== "pem" && form !== "jwk") {
    console.error(`seedmi: ${JSON.stringify(form)} is not a form of the identity; give pem or jwk`);
    process.exit(2);
  }
  try {
    const identity = await dacClient.identityNow();
    console.log(form === "jwk"
      ? JSON.stringify(identity.signingJwk, null, 2)
      : identity.signingPublic.export({ type: "spki", format: "pem" }).toString().trimEnd());
    process.exit(0);
  } catch (e) {
    console.error(`seedmi: the signing identity cannot be read: ${(e as Error).message}`);
    process.exit(1);
  }
}


// Homes (revision 282, cdmi_domain_userinfo; userinfo.ts).
if (config.homes !== undefined) {
  binding.homes = config.homes;
  console.log(`seedmi: the principals of ${config.homes.domain} have homes beneath ${config.homes.base}`);
}
if (config.homeServer !== undefined) {
  binding.homeServer = config.homeServer;
  console.log(`seedmi: homes of ${config.homeServer.domain} are held in ${config.homeServer.container}` +
    (config.homeServer.provision ? ", each made on its owner's first request" : ", pre-created"));
}

// Pipes (RELAY-draft-2.md): a WebSocket-to-TCP relay through queue objects of
// the type seedmi_pipe, to the destinations [[pipe_permit]] allows.
if (config.pipes.enabled) {
  binding.pipes = new PipeService(config.pipes);
  if (config.pipes.permits.length === 0) {
    console.log("seedmi: pipes are enabled, and no [[pipe_permit]] is given: no connection through a pipe can be made");
  } else {
    console.log(`seedmi: pipes, to the destinations of ${config.pipes.permits.length} permit(s)` +
      (config.tlsPort === undefined ? "; no TLS listener is configured, and a pipe is served over TLS alone" : ""));
  }
}

// Privileges conferred on groups within a domain, and the domain controllers
// principals are resolved at (domain-controller.ts).
for (const g of config.groupPrivileges) binding.directory.grantToGroup(g.domain, g.group, g.privileges);
// A credential under a domain a controller serves is referred to that
// controller, which does not know a local account, so a [[user]] configured
// beneath one can never authenticate. Configuring both is easy and the
// failure is a 401 that says nothing about the cause (cvwm deployment notes,
// item 3), so it is said here, once, at startup.
if (config.users.length > 0 && config.domainControllers.length > 0) {
  const served = config.domainControllers.map((c) =>
    (c.domain.endsWith("/") ? c.domain : `${c.domain}/`));
  // Every local principal belongs to the root domain, so a controller on the
  // root domain covers all of them.
  if (served.includes("/cdmi_domains/")) {
    console.warn(
      `seedmi: ${config.users.length} [[user]] entries are configured, and a domain controller ` +
      "serves /cdmi_domains/: a credential under a domain a controller serves is referred to " +
      "that controller, which does not know a local account, so those users cannot " +
      "authenticate. Remove them, or serve their domain locally.");
  }
}
if (config.domainControllers.length > 0) {
  binding.domainControllers = new DomainControllers(config.domainControllers.map((c) =>
    new DomainController(c, (groups) => binding.directory.privilegesOf(c.domain, groups))));
  // The controller NFS resolves its sys credentials at, where there is one to choose
  // without choosing. See the note at the NFS server above.
  const all = binding.domainControllers.all();
  if (config.nfs.enabled && config.nfs.mapCredentials === true) {
    if (all.length === 1) {
      nfsController = all[0];
      console.log(`seedmi: NFS resolves an AUTH_SYS uid at ${all[0].config.ldap}, by uidNumber, ` +
        "so that an NFS identity and a CDMI identity are one principal");
    } else {
      console.warn("seedmi: NFS maps credentials and " + all.length + " domain controllers are " +
        "configured, so a uid does not say which directory should resolve it: an AUTH_SYS " +
        "request is anonymous. One controller, or no mapping.");
    }
  }
  for (const c of config.domainControllers) {
    console.log(`seedmi: ${c.domain} resolves its principals at the domain controller of ${c.realm}, ${c.ldap}` +
      (c.issuer === undefined ? "" : `, and its tokens from ${c.issuer}`));
    // A controller that cannot be reached makes every request under its
    // domain answer 503, and until one arrives nothing says so: a deployment
    // brought up in the wrong order looks healthy and fails at the first
    // authenticated request. The reachability of the endpoint is therefore
    // reported here, once, without blocking the start.
    void reachable(c.ldap).then((why) => {
      if (why !== undefined) {
        console.warn(`seedmi: the domain controller at ${c.ldap} cannot be reached (${why}). ` +
          "Every request under " + c.domain + " will answer 503 until it can.");
      }
    });
  }
}

for (const k of keyManagement) {
  console.log(`seedmi: key management server ${k.label} at ${k.endpoint}, as ${await k.identifier()}`);
}

// What the root admits, said in the terms of who owns it. "The store is
// open" was printed for every userless store, which was the opposite of
// what happened where a controller resolved the principals, and was true
// only where nothing authenticated at all (cvwm deployment notes, item 2).
console.log(config.users.length > 0
  ? `seedmi: ${config.users.length} principal(s); the root is owned by ${owner}`
  : controllerOnly
    ? "seedmi: no local principals; the root is owned by no one and admits nothing " +
      "until a principal holding the backup_operator privilege sets its access control list"
    : "seedmi: no principals configured, so every request is ANONYMOUS@, which owns the " +
      "root: the store is open to anyone who reaches it");

/**
 * Whether the endpoint of a domain controller accepts a connection, and the
 * reason where it does not. The certificate is not checked here: what is
 * worth saying at startup is whether anything is listening at all, which is
 * the fault an operator meets most often and the one a configuration file
 * cannot show.
 */
async function reachable(endpoint: string): Promise<string | undefined> {
  try {
    const u = new URL(endpoint);
    const port = Number(u.port || (u.protocol === "ldaps:" ? 636 : 389));
    return await new Promise<string | undefined>((resolve) => {
      const socket = netConnect({ host: u.hostname, port } as never);
      socket.setTimeout(4000);
      socket.once("connect", () => { socket.destroy(); resolve(undefined); });
      socket.once("timeout", () => { socket.destroy(); resolve("no answer within four seconds"); });
      socket.once("error", (e: Error) => { socket.destroy(); resolve(e.message); });
    });
  } catch (e) {
    return (e as Error).message;
  }
}

// The CDMI over MCP protocol binding, on a listener of its own. "The CDMI
// server shall be the MCP server. The two are one server": the endpoint
// performs the operation against the same store, through the same paths,
// and evaluates the same access control lists as the HTTP binding.
let mcp: Mcp | undefined;
if (config.mcp !== undefined) {
  setMcpVersion(VERSION);
  const resource = new ResourceServer({
    resource: config.mcp.uri,
    // "The authorization servers from which it accepts access tokens"
    // (8.3.3): the issuer of [oauth], which the HTTP binding accepts, and
    // the issuer of each domain controller. 0.83 named the controllers
    // alone, so a deployment that accepts tokens published an empty array
    // and refused every token a client could obtain (weedmi BMCP-010).
    // It is read at each request rather than captured here, so that a
    // controller configured after this point is reported.
    authorizationServers: () => binding.authorizationServers(),
    scopesRequired: config.mcp.scopesRequired,
    // "Resolve the subject of the access token to a principal within the
    // domain that owns the object": the domain is known once the operation
    // has read the target of the call, so resolution happens there.
    verifyIn: (domain, token) => binding.resolveTokenIn(domain, token),
    // The transport checks that a token is one this server accepts, before
    // any message is read, whether or not the method addresses an object.
    accepts: (token) => binding.acceptsToken(token),
  });
  // The operation resolves the token and checks the scope, at the domain
  // that owns the object it addresses.
  binding.mcpAuth = resource;
  binding.mcpUri = config.mcp.uri;
  // The certificate the endpoint presents, where [mcp] names one. The Mcp
  // listener has honoured this option since the binding was written and
  // nothing ever passed it: [mcp].certificate was parsed, validated against
  // nothing, and read by no code, so the endpoint was unconditionally plain
  // HTTP however a deployment configured it. An access token travels on this
  // endpoint in an Authorization header field, so serving it without TLS puts
  // the token on the wire in the clear.
  const mcpPair = config.mcp.certificate === undefined ? undefined : certificate(config.mcp.certificate);
  if (config.mcp.certificate !== undefined && mcpPair === undefined) {
    console.error(`seedmi: the certificate ${config.mcp.certificate} that [mcp] names cannot be read`);
    process.exit(2);
  }
  mcp = new Mcp({
    uri: config.mcp.uri,
    host: config.mcp.host,
    port: config.mcp.port,
    log,
    auth: resource,
    baseUris: () => binding.baseUris(),
    // The absolute forms, which a resource of the MCP endpoint is addressed
    // beneath: the base of this server's own namespace is a path, which a
    // client has nothing to resolve a resource URI against.
    ownBases: () => ownBases(),
    call: (c) => binding.mcpCall(c),
    ...(mcpPair === undefined ? {} : { tls: { cert: mcpPair.chain, key: mcpPair.key } }),
    ...(config.mcp.origins === undefined ? {} : { origins: config.mcp.origins }),
    strictHeaders: config.mcp.strictHeaders,
  });
  await mcp.listen();
  console.log(`seedmi: CDMI over MCP at ${config.mcp.uri}` +
    (mcpPair === undefined ? " (no certificate configured: the endpoint is plain HTTP, and an access token " +
      "travels on it in the clear)" : "") +
    (config.mcp.scopesRequired ? ", requiring the scopes of the subclause" : ""));
}

const stop = async () => {
  await mcp?.close();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  // Pipes' connections first: the TLS listener's close waits for every
  // connection, and one held by backpressure would never end of itself.
  binding.pipes?.closeAll();
  await tls?.close();
  await nfs?.close();
  await smb?.close();
  for (const k of keyManagement) await k.close();
  store.close();
  process.exit(0);
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
