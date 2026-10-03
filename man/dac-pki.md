# dac-pki(1)

## NAME

dac-pki — certificates and keys for trying seedmi-dac on one machine

## SYNOPSIS

```
node src/dac-pki.ts --out <directory> [--host <address>] [--signing-only]
```

Run from the `seedmi-dac` directory.

## DESCRIPTION

Writes the certificates and keys seedmi-dac needs into the directory named: the
certificate its listener presents, the key a CDMI server encrypts a request to,
and the key it signs a decision with. It exists so that the provider can be
tried on one machine without a certificate authority to hand; a deployment uses
its own.

`--signing-only` writes the signing identity alone, for a provider whose
listener and decryption keys come from elsewhere.

Requires `openssl` on PATH.

## OPTIONS

```
  --out <directory>    the directory to write into
  --host <address>     the address the listener's certificate names, 127.0.0.1 where not given
  --signing-only       write the signing identity alone
```

Unlike the other nine commands of this release, `dac-pki` prints its usage to
standard error and exits 2 when given `--help`, rather than printing to
standard output and exiting 0. A script that asks each command for its help
should expect that.

## FILES

In the output directory: `https.key` and the certificate the listener presents,
`provider.key`, which a CDMI server encrypts a request to, and `signing.key`
with its chain, which the provider signs a decision with. `dac.toml` names each
of them.

## EXAMPLES

Everything a provider needs, for a listener on the loopback address:

```sh
node src/dac-pki.ts --out pki --host 127.0.0.1
```

The signing identity alone:

```sh
node src/dac-pki.ts --out pki --signing-only
```

## EXIT STATUS

0 where the material was written; 2 where the command line was refused, and
where usage was asked for.

## SEE ALSO

`dacd`(1).
