# kmsd(1)

## NAME

kmsd — a KMIP 1.4 key management server

## SYNOPSIS

```
node src/kmsd.ts [flags]
```

Run from the `seedmi-kms` directory.

## DESCRIPTION

seedmi-kms keeps key material for the CDMI servers that reach it, speaking the
Key Management Interoperability Protocol version 1.4 over TLS with mutual
authentication. A client is identified by the common name of the certificate it
presents, and the objects it may reach are those its identity holds.

It is a program of its own: seedmi holds no key management server, and reaches
this one as a client. Any other KMIP 1.4 server serves as well.

Generate its certificates with `kms-pki`(1) before the first run. `kms-ops`(1)
backs up a running store and asks a server whether it is answering.

`SIGHUP` re-reads the configuration and presents the certificate, key and
authority it names from the next connection, dropping none already made.

## OPTIONS

```
  --config <path>                  read settings from a TOML file
  --store <path>                   the directory the store lives in
  --host <address>                 the address to listen on
  --port <port>                    the port to listen on
  --log <off|problems|requests>    what to log; nothing is logged unless this is given
  --log-file <path>                write the log there, not to stderr
  --log-format <text|json>         how each line is written
  --help                           print this text and exit (also -h)
  --version                        print the version and exit (also -v)
```

## CONFIGURATION

A configuration file gives `[server]` (host, port, cert, key, ca, vendor),
`[store]` (path) and `[log]` (level, file, format). A flag wins over the file.

`kms.toml` beside the source is a commented example.

## FILES

The store directory holds `kms.db`. A backup written by `kms-ops backup` is
restored by placing it, as `kms.db`, in an empty store directory with the
server stopped.

## EXAMPLES

Generate certificates for one client named `seedmi`, then serve:

```sh
node src/kms-pki.ts --out pki --client seedmi
node src/kmsd.ts --config kms.toml --log requests
```

## EXIT STATUS

0 where `--help` or `--version` completed, or the server stopped on a signal;
2 where the command line or the configuration was refused.

## SEE ALSO

`kms-pki`(1), `kms-ops`(1), `seedmi`(1).

KMIP 1.4, the protocol this server speaks.
