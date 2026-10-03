# seedmi(1)

## NAME

seedmi — a CDMI 3.0 server

## SYNOPSIS

```
node src/main.ts [flags]
```

Run from the `seedmi` directory. There is no build step: Node strips the
TypeScript types as it loads each module.

## DESCRIPTION

seedmi serves the Cloud Data Management Interface, version 3.0, over HTTP and
HTTPS. Objects live in SQLite and their values live in files beneath a store
directory. It implements the protocol binding, the container, data, queue and
domain object representations, access control lists, data system metadata,
snapshots, versioning, query and notification queues, serialization, retention
and holds, and the import and export models — including HTTP, NFS, SMB and S3
exports and CDMI, NFS, SMB, S3, HTTP and filesystem-image imports.

Settings come from a configuration file, the command line, or both, and a flag
wins over the file. `seedmi.toml` beside the source is a commented example.

With no `--user`, every request is the anonymous principal and the store is
open. Give `--user`, or `[[user]]` in the configuration, to require
credentials. Principals may instead be resolved at a domain controller; see
**seedmi-dc** and `dcd`(1).

## OPTIONS

```
  --config <path>                          read settings from a TOML file
  --dac-identity [pem|jwk]                 print the public key of the delegated access control signing identity and exit
  --store <path>                           the directory the store lives in
  --base <path>                            the base URI of the protocol binding
  --host <address>                         the address to listen on
  --port <port>                            the port to listen on
  --tls-port <port>                        the port to listen on for TLS
  --tls-certificate <id>                   the identifier of the certificate to serve
  --export-origins <origin,...>            the origins at which an HTTP export may be served
  --root-export <name>                     the name of an HTTP export entry to place on the root container object
  --root-export-path <path>                the path that export is served at, which defaults to /
  --user <name:password[:groups][:flags]>  a principal; flags are admin and privileges, comma-separated; repeat for more than one
  --log <off|problems|requests>            what to log; nothing is logged unless this is given
  --log-file <path>                        write the log there, not to stderr
  --log-format <text|json>                 how each line is written
  --mqtt                                   connect to the broker an MQTT export entry names
  --help                                   print this text and exit (also -h)
  --version                                print the version of seedmi and exit (also -v)
```

## FILES

`seedmi.toml` — the example configuration, commented throughout.

The store directory named by `--store` or `[store].path` holds `seedmi.db` and
a file per object value. It is created if it does not exist.

## EXAMPLES

Serve the example configuration and read the root container object:

```sh
node src/main.ts --config seedmi.toml
curl -s http://127.0.0.1:8080/cdmi/3.0.0/
```

Serve a store at a chosen port with one administrative principal, logging each
request:

```sh
node src/main.ts --store ./data --port 8080 \
  --user 'alice:secret:staff:admin' --log requests
```

Print the public key a delegated access control provider verifies this
server's requests with:

```sh
node src/main.ts --config seedmi.toml --dac-identity jwk
```

## EXIT STATUS

0 where `--help`, `--version` or `--dac-identity` completed, or the server
stopped on a signal; 2 where the command line or the configuration was
refused.

## SEE ALSO

`kmsd`(1), `dacd`(1), `dcd`(1), `mdnsd`(1), `zoned`(1).

CDMI 3.0, the specification this server implements.
