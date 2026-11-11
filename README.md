# seedmi

A CDMI 3.0 server and the programs it is deployed with, written to find defects in the specification by implementing it closely.

Version 0.134. Six programs making up a CDMI reference implementation:

| Directory | Program | Version |
|---|---|---|
| [`seedmi/`](seedmi/) | a CDMI 3.0 server: the reference implementation of the specification | 0.134.0 |
| [`seedmi-kms/`](seedmi-kms/) | a KMIP 1.4 key management server, run and configured on its own | 1.1.0 |
| [`seedmi-dac/`](seedmi-dac/) | a delegated access control provider, which decides an access a CDMI server refers to it | 0.12.0 |
| [`seedmi-dc/`](seedmi-dc/) | a domain controller: LDAP, SCIM, OAuth and a key distribution centre, at which a CDMI server resolves the principals of a domain | 1.12.0 |
| [`seedmi-mdns/`](seedmi-mdns/) | a multicast DNS responder that makes a CDMI server visible on the local link as a `_cdmi._tcp` service instance | 0.2.0 |
| [`seedmi-zone/`](seedmi-zone/) | browses a link for CDMI servers and publishes what it finds into a real DNS zone, so that an ordinary resolver can answer for them | 0.2.0 |

Each program is configured, run and tested on its own. seedmi reaches seedmi-kms as a KMIP client where it keeps credentials at a key server, and any other KMIP 1.4 server serves as well; it refers an access decision to seedmi-dac where an object carries one; and it resolves the principals of a domain at seedmi-dc. None of them requires the others to run.

## Requirements

Node 22 or later, and nothing else. There are **no dependencies** — no `npm install`, no build step — and no package in any of the six has ever had one. Node strips the TypeScript types as it loads each module, so the source is what runs:

```sh
cd seedmi
node src/main.ts --config seedmi.toml
```

`openssl` is only needed on PATH for the certificate generators.

## Commands

| Command | Program | Run as |
|---|---|---|
| [`seedmi`](man/seedmi.md) | `seedmi` | `node src/main.ts` |
| [`kmsd`](man/kmsd.md) | `seedmi-kms` | `node src/kmsd.ts` |
| [`kms-pki`](man/kms-pki.md) | `seedmi-kms` | `node src/kms-pki.ts` |
| [`kms-ops`](man/kms-ops.md) | `seedmi-kms` | `node src/kms-ops.ts` |
| [`dacd`](man/dacd.md) | `seedmi-dac` | `node src/dacd.ts` |
| [`dac-pki`](man/dac-pki.md) | `seedmi-dac` | `node src/dac-pki.ts` |
| [`dcd`](man/dcd.md) | `seedmi-dc` | `node src/dcd.ts` |
| [`dc-import`](man/dc-import.md) | `seedmi-dc` | `node src/dc-import.ts` |
| [`mdnsd`](man/mdnsd.md) | `seedmi-mdns` | `node src/mdnsd.ts` |
| [`zoned`](man/zoned.md) | `seedmi-zone` | `node src/zoned.ts` |

Each has a man page under [`man/`](man/), and answers `--help` and
`--version`.

## Trying it

From the directory of the program:

```sh
cd seedmi
node src/main.ts --store ./data --port 8000
```

The program will output where it is listening and how its root is owned. Then, from another shell:

```sh
curl -H 'Accept: application/cdmi-container' 'http://127.0.0.1:8000/cdmi/3.0.0/?objectName&children'
```

Every command-line option has a default. A flag on a command line overrules what is specified in the config file.

## What is in this release

The runnable source of each program: the modules its commands reach, walked from each entry point, with its `package.json` and the example configuration it documents. The tests and the working notes are not here; they are part of the development tree rather than of a deployment.

## Reporting a defect

These programs exist to find defects in CDMI 3.0 by implementing it closely, so a disagreement between a program and the document is the interesting case and is worth reporting whichever turns out to be wrong. A report that names the subclause, the request and the response is one that can be more easily investigated and resolved.