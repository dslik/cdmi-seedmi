# seedmi

A CDMI 3.0 server and the programs it is deployed with, written to find defects
in the specification by implementing it closely.

Version 0.128. Six programs, side by side, **sharing no file**:

| Directory | Program | Version |
|---|---|---|
| [`seedmi/`](seedmi/) | a CDMI 3.0 server: the reference implementation of the specification | 0.128.0 |
| [`seedmi-kms/`](seedmi-kms/) | a KMIP 1.4 key management server, run and configured on its own | 1.1.0 |
| [`seedmi-dac/`](seedmi-dac/) | a delegated access control provider, which decides an access a CDMI server refers to it | 0.11.0 |
| [`seedmi-dc/`](seedmi-dc/) | a domain controller: LDAP, SCIM, OAuth and a key distribution centre, at which a CDMI server resolves the principals of a domain | 1.4.0 |
| [`seedmi-mdns/`](seedmi-mdns/) | a multicast DNS responder that makes a CDMI server visible on the local link as a `_cdmi._tcp` service instance | 0.2.0 |
| [`seedmi-zone/`](seedmi-zone/) | browses a link for CDMI servers and publishes what it finds into a real DNS zone, so that an ordinary resolver can answer for them | 0.2.0 |

Each program is configured, run and tested on its own. seedmi reaches
seedmi-kms as a KMIP client where it keeps credentials at a key server, and any
other KMIP 1.4 server serves as well; it refers an access decision to
seedmi-dac where an object carries one; and it resolves the principals of a
domain at seedmi-dc. None of them requires the others to run.

## Requirements

Node 22 or later, and nothing else. There are **no dependencies** — no
`npm install`, no build step — and no package in any of the six has ever had
one. Node strips the TypeScript types as it loads each module, so the source
is what runs:

```sh
cd seedmi
node src/main.ts --config seedmi.toml
```

`openssl` is needed on PATH only by the certificate generators.

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

With no principal configured, every request is the anonymous principal and the
store is open, so nothing has to be set up to read and write through it:

```sh
cd seedmi
node src/main.ts --store ./data --port 8080
```

```sh
curl -s http://127.0.0.1:8080/cdmi/3.0.0/
curl -s -X PUT -H 'Content-Type: application/cdmi-object' \
  -d '{"value":"hello"}' http://127.0.0.1:8080/cdmi/3.0.0/greeting.txt
curl -s 'http://127.0.0.1:8080/cdmi/3.0.0/greeting.txt?value'
```

That answers `200`, `201` and `200`.

`seedmi.toml` is a commented example of a configuration file, and it **does**
configure principals — `alice` and an administrator `root` — so a request
through it carries credentials:

```sh
node src/main.ts --config seedmi.toml
curl -s -u alice:secret http://127.0.0.1:8080/cdmi/3.0.0/
```

A request to that configuration without credentials is answered `403`, which
is the configuration working rather than failing.

seedmi-kms, which generates its own certificates first:

```sh
cd seedmi-kms
node src/kms-pki.ts --out pki --client seedmi
node src/kmsd.ts --config kms.toml --log requests
```

## What is in this release

The runnable source of each program: the modules its commands reach, walked
from each entry point, with its `package.json` and the example configuration
it documents. The tests and the working notes are not here; they are part of
the development tree rather than of a deployment.

## Reporting a defect

A defect in one of these programs, and a defect in CDMI 3.0 that implementing
it turned up, are both worth reporting. The second is the point of the
exercise: the specification is the subject, and the implementation is how it
is examined.
