// seedmi-dac's certificates, made with openssl:
//
//   node src/dac-pki.ts --out pki [--host 127.0.0.1]
//   node src/dac-pki.ts --out pki --signing-only
//
// The first makes, where they are absent, the provider's certificate (the one
// objects give in cdmi_dac_certificate, and the key requests are encrypted to),
// and in any case a signing key with a certificate that one issues, and a
// certificate for the listener at the host given. The second issues a new
// signing key and certificate from the provider's key and nothing else: the
// signing key is replaced without changing an object, since "The provider may
// sign with a different key where the certificate for that key chains to the
// certificate contained in the cdmi_dac_certificate metadata item of the
// object". The old signing files are kept beside the new, dated.
//
// A deployment with a certificate authority of its own issues these from it
// instead; this is for a demonstration, and for the tests.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, renameSync, writeFileSync } from "node:fs";
import * as path from "node:path";

function usage(): never {
  process.stderr.write("usage: node src/dac-pki.ts --out <directory> [--host <address>] [--signing-only]\n");
  process.exit(2);
}

const args = process.argv.slice(2);
let out: string | undefined;
let host = "127.0.0.1";
let signingOnly = false;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--out" && i + 1 < args.length) out = args[++i];
  else if (args[i] === "--host" && i + 1 < args.length) host = args[++i];
  else if (args[i] === "--signing-only") signingOnly = true;
  else usage();
}
if (out === undefined) usage();
mkdirSync(out, { recursive: true });
const run = (a: string[]) => execFileSync("openssl", a, { cwd: out, stdio: ["ignore", "ignore", "pipe"] });
const has = (f: string) => existsSync(path.join(out!, f));
const made: string[] = [];

if (!has("provider.key") || !has("provider.crt")) {
  if (signingOnly) {
    process.stderr.write(`dac-pki: ${out} holds no provider certificate from which to issue a signing certificate\n`);
    process.exit(2);
  }
  run(["req", "-x509", "-newkey", "rsa:3072", "-nodes", "-keyout", "provider.key", "-out", "provider.crt", "-days", "825",
    "-subj", "/CN=seedmi-dac provider", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
    "-addext", "keyUsage=critical,keyCertSign,keyEncipherment"]);
  made.push("provider.key", "provider.crt");
}

// The signing key: the old kept, dated, and a new one issued by the provider's key.
if (has("signing.key")) {
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..*$/, "");
  renameSync(path.join(out, "signing.key"), path.join(out, `signing-${stamp}.key`));
  if (has("signing.crt")) renameSync(path.join(out, "signing.crt"), path.join(out, `signing-${stamp}.crt`));
}
writeFileSync(path.join(out, "signing.ext"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n");
run(["req", "-newkey", "rsa:3072", "-nodes", "-keyout", "signing.key", "-out", "signing.csr", "-subj", "/CN=seedmi-dac signing"]);
run(["x509", "-req", "-in", "signing.csr", "-CA", "provider.crt", "-CAkey", "provider.key", "-CAcreateserial",
  "-out", "signing.crt", "-days", "397", "-extfile", "signing.ext"]);
made.push("signing.key", "signing.crt");

if (!signingOnly) {
  const san = /^[0-9.]+$/.test(host) || host.includes(":") ? `IP:${host}` : `DNS:${host}`;
  run(["req", "-x509", "-newkey", "rsa:3072", "-nodes", "-keyout", "https.key", "-out", "https.crt", "-days", "397",
    "-subj", `/CN=${host}`, "-addext", `subjectAltName=${san}`]);
  made.push("https.key", "https.crt");
}
process.stdout.write(`dac-pki: wrote ${made.join(", ")} in ${out}\n`);
