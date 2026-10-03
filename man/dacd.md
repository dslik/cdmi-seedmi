# dacd(1)

## NAME

dacd — a reference delegated access control provider

## SYNOPSIS

```
node src/dacd.ts [flags]
```

Run from the `seedmi-dac` directory.

## DESCRIPTION

A CDMI server may refer an access decision for an object to another party
rather than deciding it from the object's own access control list. seedmi-dac
is that party: it receives a signed, encrypted request describing the access,
matches it against rules given in its configuration, and answers with a signed
decision.

Rules are tried in order; the first that matches decides, and none matching
denies. A decision may grant in full, grant a reduced mask, deny, redirect to
another object, or be deferred.

Generate its certificates with `dac-pki`(1) before the first run.
`--certificate-jwk` prints the JWK objects a CDMI server gives as the
`cdmi_dac_certificate` metadata item.

`SIGHUP` re-reads the configuration: the certificate the listener presents, the
provider's keys, the servers answered and the rules apply from the next
request.

## OPTIONS

```
  --config <path>                  read settings from a TOML file
  --host <address>                 the address to listen on
  --port <port>                    the port to listen on
  --log <off|problems|requests>    what to log beyond the arrival of a request,
                                   which is always written
  --log-file <path>                write the log there, not to stderr
                                   (the log is JSON Lines, one object per line)
  --certificate-jwk                print the JWK objects give as cdmi_dac_certificate, and exit
  --help                           print this text and exit (also -h)
  --version                        print the version and exit (also -v)
```

## CONFIGURATION

A configuration file gives `[listen]` (host, port, path, certificate, key),
`[provider]` (decryption_key, certificate, signing_key, signing_chain,
replay_window_ms), `[[server]]` (name, and ca with subject, or key) for each
CDMI server answered (with response_uris and response_ca where it is answered
later), `[[rule]]` (servers, objects, operations, principals, groups, headers,
decision, mask, response_headers, cache_seconds, redirect_objectID, audit_uri,
defer) in order, the first matching deciding and none matching denying, and
`[log]` (level, file). A flag wins over the file.

`dac.toml` beside the source is a commented example.

The arrival of every request is logged whatever `--log` says, so that a
decision can always be accounted for.

## EXAMPLES

Generate certificates, then serve:

```sh
node src/dac-pki.ts --out pki
node src/dacd.ts --config dac.toml --log requests
```

Print what a CDMI server records as `cdmi_dac_certificate` for this provider:

```sh
node src/dacd.ts --config dac.toml --certificate-jwk
```

## EXIT STATUS

0 where `--help`, `--version` or `--certificate-jwk` completed, or the provider
stopped on a signal; 2 where the command line or the configuration was refused.

## SEE ALSO

`dac-pki`(1), `seedmi`(1).
