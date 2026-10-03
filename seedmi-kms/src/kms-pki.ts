// kms-pki: certificates for trying seedmi-kms, and for trying seedmi with it.
//
//   node src/kms-pki.ts --out ./pki --client seedmi
//
// writes, into ./pki:
//
//   ca.pem, ca.key          an authority, which issues everything below and
//                           which both the server and its clients trust
//   server.pem, server.key  the server's certificate, for 127.0.0.1 and localhost
//   seedmi.pem, seedmi.key  a client certificate whose common name, "seedmi",
//                           is the identity the server gives its holder
//
// One --client for each identity wanted. These are for trying the programs on
// one machine: a deployment has certificates from the authority it already
// trusts, for the names the server is reached by. openssl is needed on PATH.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import * as path from "node:path";

/** Writes an authority, a server certificate and client certificates into a directory. */
export function makePki(out: string, clients: string[], opts: { days?: number } = {}): void {
  const days = String(opts.days ?? 365);
  mkdirSync(out, { recursive: true });
  if (existsSync(path.join(out, "ca.pem"))) {
    throw new Error(`${out} already holds an authority; choose an empty directory`);
  }
  const run = (args: string[]) => execFileSync("openssl", args, { cwd: out, stdio: ["ignore", "ignore", "pipe"] });
  run(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
    "-days", days, "-subj", "/CN=seedmi-kms example authority"]);
  const issue = (name: string, cn: string, ext: string) => {
    run(["req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`, "-subj", `/CN=${cn}`]);
    writeFileSync(path.join(out, `${name}.ext`), ext);
    run(["x509", "-req", "-in", `${name}.csr`, "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
      "-out", `${name}.pem`, "-days", days, "-extfile", `${name}.ext`]);
  };
  issue("server", "localhost", "subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n");
  for (const c of clients) {
    if (!/^[A-Za-z0-9._-]+$/.test(c)) throw new Error(`${JSON.stringify(c)} is not a name a client file can take`);
    issue(c, c, "extendedKeyUsage=clientAuth\n");
  }
  // What openssl needed on the way, and a reader does not.
  for (const n of ["server", ...clients]) {
    for (const ext of ["csr", "ext"]) rmSync(path.join(out, `${n}.${ext}`), { force: true });
  }
  rmSync(path.join(out, "ca.srl"), { force: true });
}

const asProgram = process.argv[1] !== undefined && path.basename(process.argv[1]) === "kms-pki.ts";

if (asProgram) {
  const argv = process.argv.slice(2);
  if (argv.includes("--help") || argv.includes("-h") || argv.length === 0) {
    process.stdout.write(`kms-pki: certificates for trying seedmi-kms on one machine.

Usage: node src/kms-pki.ts --out <dir> [--client <name>]... [--days <n>]

Writes ca.pem, server.pem and a <name>.pem for each client, each with its key.
A client certificate's common name is the identity the server gives it.
`);
    process.exit(argv.length === 0 ? 2 : 0);
  }
  let out: string | undefined;
  let days: number | undefined;
  const clients: string[] = [];
  for (let i = 0; i < argv.length; i += 2) {
    const v = argv[i + 1];
    if (v === undefined) {
      process.stderr.write(`kms-pki: ${argv[i]} needs a value\n`);
      process.exit(2);
    }
    if (argv[i] === "--out") out = v;
    else if (argv[i] === "--client") clients.push(v);
    else if (argv[i] === "--days") days = Number(v);
    else {
      process.stderr.write(`kms-pki: ${argv[i]} is not a flag this command takes; --help lists them\n`);
      process.exit(2);
    }
  }
  if (out === undefined) {
    process.stderr.write("kms-pki: --out names the directory to write into\n");
    process.exit(2);
  }
  try {
    makePki(out, clients, days === undefined ? {} : { days });
    process.stdout.write(`kms-pki: wrote an authority, a server certificate` +
      `${clients.length === 0 ? "" : ` and ${clients.join(", ")}`} into ${out}\n`);
  } catch (e) {
    process.stderr.write(`kms-pki: ${(e as Error).message}\n`);
    process.exit(2);
  }
}
