# zoned(1)

## NAME

zoned — publishes the CDMI servers on a link into a DNS zone

## SYNOPSIS

```
node src/zoned.ts [flags]
```

Run from the `seedmi-zone` directory.

## DESCRIPTION

Browses a link for CDMI servers advertising themselves over multicast DNS and
writes what it finds into a real DNS zone, so that **an ordinary resolver** can
answer for them — a client that cannot reach the link, or cannot speak
multicast DNS, then finds the same servers through ordinary DNS.

Records are written either by dynamic update with a TSIG key, or by running a
local `unbound-control`-style command. Each sweep reconciles the zone with what
the link currently shows, so a server that has gone is removed.

**One instance per link, owning one zone subtree**: two writers on one subtree
undo each other's work, so a site with several links gives each its own
subtree.

`--once` browses, sweeps once and exits, which is how it is run from a
scheduler rather than as a daemon. `--dry-run` says what would be written and
writes nothing.

`SIGHUP` re-reads the configuration and sweeps afresh.

## OPTIONS

```
  --config <path>             read settings from a TOML file
  --once                      browse, sweep once and exit
  --dry-run                   say what would be written and write nothing
  --log <off|problems|sweeps> what to log beyond starting and stopping
  --log-file <path>           write the log there, not to stderr
                              (the log is JSON Lines, one object per line)
  --help                      print this text and exit (also -h)
  --version                   print the version and exit (also -v)
```

## CONFIGURATION

A configuration file gives `[link]` (interfaces, ipv6, browse), `[zone]` (name,
ttl_host, ttl_other, sweep_interval_ms, allow, ca), one of `[update]` (host,
port, key_name, key_algorithm, key_secret) or `[unbound]` (command, args), and
`[log]` (level, file). A flag wins over the file.

`zone.toml` beside the source is a commented example.

## EXAMPLES

See what a sweep would write, without writing it:

```sh
node src/zoned.ts --config zone.toml --once --dry-run
```

Run as a daemon, logging each sweep:

```sh
node src/zoned.ts --config zone.toml --log sweeps
```

## EXIT STATUS

0 where `--help` or `--version` completed, where `--once` finished its sweep,
or where the daemon stopped on a signal; 2 where the command line or the
configuration was refused.

## SEE ALSO

`mdnsd`(1), `seedmi`(1).

RFC 2136 (dynamic update), RFC 2845 (TSIG), RFC 6763 (DNS-based service
discovery).
