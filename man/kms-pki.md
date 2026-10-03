# kms-pki(1)

## NAME

kms-pki — certificates for trying seedmi-kms on one machine

## SYNOPSIS

```
node src/kms-pki.ts --out <dir> [--client <name>]... [--days <n>]
```

Run from the `seedmi-kms` directory.

## DESCRIPTION

Writes a certificate authority, a server certificate and a client certificate
for each name given, each with its key, into the directory named. It exists so
that seedmi-kms can be tried on one machine without a certificate authority to
hand; a deployment uses its own.

**A client certificate's common name is the identity the server gives it.** The
objects a client may reach are the objects that identity holds, so the name
chosen here is the name that appears in the key server's access decisions.

Requires `openssl` on PATH.

## OPTIONS

```
  --out <dir>          the directory to write into
  --client <name>      a client certificate for that name; repeat for more than one
  --days <n>           how long each certificate is valid for
  --help               print this text and exit (also -h)
```

## FILES

In the output directory: `ca.pem`, `server.pem`, and a `<name>.pem` for each
client, each beside its key.

## EXAMPLES

A certificate authority, a server certificate and one client certificate for a
CDMI server that will identify itself as `seedmi`:

```sh
node src/kms-pki.ts --out pki --client seedmi
```

Two clients, valid for a year:

```sh
node src/kms-pki.ts --out pki --client seedmi --client backup --days 365
```

## EXIT STATUS

0 where the certificates were written; 2 where the command line was refused.

## SEE ALSO

`kmsd`(1), `kms-ops`(1).
