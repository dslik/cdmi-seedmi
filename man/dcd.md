# dcd(1)

## NAME

dcd — a reference domain controller

## SYNOPSIS

```
node src/dcd.ts [flags]
```

Run from the `seedmi-dc` directory.

## DESCRIPTION

seedmi-dc holds the users and groups of a realm and verifies their
credentials, for a CDMI server that refers the principals of a domain to it. It
serves four front ends over one configuration:

- **LDAP**, for reading the directory and for binding as a principal;
- **SCIM 2.0**, under `/scim/v2/`, for administering it over HTTP;
- **OAuth 2.0**, issuing the bearer tokens a CDMI server accepts; and
- a **Kerberos key distribution centre**, issuing tickets.

A controller either holds its users in its configuration file or keeps them in
a store. With a store, `[[user]]` and `[[group]]` in the file are refused,
`dc-import`(1) seeds it from a bootstrap file, and `[kms]` says where the
secret material of each principal is kept — at a key server, not in the store.
A store whose key server cannot be reached is served **without its secrets**,
and a bind, a token and a ticket are refused with a line saying so.

`--hash-password` prints the hash that `[[user]].password_hash` takes.
`--sweep-keys` destroys key material no row of the store references.

`SIGHUP` re-reads the configuration: the users and groups, the certificate and
the log apply from the next request, and a store is read again. A configuration
that does not load leaves the one in use. The realm, its domain and where the
directory is kept are what the instance is, and a reload changing them is
refused.

## OPTIONS

```
  --config <path>                  read settings from a TOML file
  --host <address>                 the address to listen on
  --port <port>                    the port HTTPS is served on
  --log <off|problems|requests>    what to log; nothing is logged unless this is given
  --log-file <path>                write the log there, not to stderr
  --log-format <text|json>         how each line is written
  --hash-password                  read a password on standard input, print its hash, and exit
  --sweep-keys                     destroy key material no row of the store references, and exit
  --help                           print this text and exit (also -h)
  --version                        print the version and exit (also -v)
```

`--sweep-keys` needs `[directory].store` and `[kms]`: it asks the key server
what it holds for this controller, compares it with what the store references,
and destroys the difference. A change that is refused already destroys what it
registered; this is for material a stopped process left between a registration
and the commit.

## CONFIGURATION

A configuration file gives `[realm]` (name, domain), `[listen]` (host, port,
ldap_port, certificate, key), `[[user]]` (name, password_hash, groups,
disabled, expires), `[[group]]` (name, groups), `[directory]` (memberof, store,
uid_range, gid_range), `[kms]` (host, port, certificate, key, authority,
key_cache_seconds), `[admin]` (authority, subjects), `[tokens]` (issuer,
signing_key, previous_keys, lifetime_seconds), `[[client]]` (id, secret_hash,
grants, audiences, scopes) and `[log]` (level, file, format). A flag wins over
the file.

A user's password is given as the hash `--hash-password` prints; a plain
password is taken, and warned of.

`[admin]` says who may write the directory over LDAP: an administrator binds by
SASL EXTERNAL with a certificate that authority issued and naming a listed
subject. SCIM is authorized instead by a bearer token this controller issued
carrying the `dc.read` or `dc.admin` scope. **Neither front end implies the
other**, and a write through either needs a store.

`dc-eu.toml` and `dc-us.toml` beside the source are commented examples of two
controllers that trust each other.

## EXAMPLES

Serve a realm from a configuration file, logging each request:

```sh
node src/dcd.ts --config dc-eu.toml --log requests
```

Hash a password for `[[user]].password_hash`:

```sh
printf 'secret' | node src/dcd.ts --hash-password
```

Destroy key material the store no longer references:

```sh
node src/dcd.ts --config dc-eu.toml --sweep-keys
```

## EXIT STATUS

0 where `--help`, `--version`, `--hash-password` or `--sweep-keys` completed,
or the controller stopped on a signal; 2 where the command line or the
configuration was refused.

## SEE ALSO

`dc-import`(1), `seedmi`(1), `kmsd`(1).

RFC 4511 (LDAP), RFC 4120 (Kerberos), RFC 6749 (OAuth 2.0), RFC 7644 (SCIM
2.0), RFC 2307 (POSIX accounts in LDAP).
