# dc-import(1)

## NAME

dc-import — seeds a seedmi-dc store from a bootstrap file

## SYNOPSIS

```
node src/dc-import.ts --config <path> --from <path> [flags]
```

Run from the `seedmi-dc` directory.

## DESCRIPTION

Creates the organizational units, users and groups a controller starts with, in
a store it has not yet served. **The store is seeded once**: one that already
holds a principal or a unit is refused, so this is not a way to add a user to a
running realm — SCIM or LDAP is.

A user is given a `password`, from which a verifier and a Kerberos key for each
enctype are derived, or a `password_hash`, from which only a verifier can be —
so **a principal imported with a hash is never issued a ticket** until a
password is set through the administrative interface. That is a property of
what a hash can yield, not a limitation of the import.

`--dry-run` reads and checks the bootstrap file and writes nothing, which is
how a file is checked before it is applied to a store that can only be seeded
once.

## OPTIONS

```
  --config <path>   the controller's configuration, which gives [directory].store,
                    the ranges numbers are allocated from, the realm and [kms]
  --from <path>     the bootstrap file: [[ou]], [[user]] and [[group]]
  --dry-run         read and check the bootstrap file, write nothing
  --help            print this text and exit (also -h)
  --version         print the version and exit (also -v)
```

## FILES

`bootstrap.toml` beside the source is a commented example of a bootstrap file.

The store and the key server come from the controller's own configuration, so
an import writes the same store the controller will serve and registers secret
material at the same key server.

## EXAMPLES

Check a bootstrap file without writing:

```sh
node src/dc-import.ts --config dc-eu.toml --from bootstrap.toml --dry-run
```

Seed the store, then serve it:

```sh
node src/dc-import.ts --config dc-eu.toml --from bootstrap.toml
node src/dcd.ts --config dc-eu.toml --log requests
```

## EXIT STATUS

0 where the store was seeded, or where `--dry-run` found the file sound; 2
where the command line, the configuration or the bootstrap file was refused, or
the store already held a principal or a unit.

## SEE ALSO

`dcd`(1).
