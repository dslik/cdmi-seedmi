# mdnsd(1)

## NAME

mdnsd — a multicast DNS responder advertising CDMI servers

## SYNOPSIS

```
node src/mdnsd.ts [flags]
```

Run from the `seedmi-mdns` directory.

## DESCRIPTION

Makes the CDMI servers on this host visible on the local link as `_cdmi._tcp`
service instances, so that a client browsing the link finds them without being
configured with an address. Each instance carries the port, the version served
and a display name, and may be health checked so that a server that has stopped
answering is withdrawn rather than advertised.

**One responder runs per host**: port 5353 is held by one process, and a host
running `avahi-daemon` already has one. This program is for a host that does
not.

`SIGHUP` re-reads the configuration: the instances advertised are withdrawn
with a goodbye and the new set is probed for afresh.

## OPTIONS

```
  --config <path>              read settings from a TOML file
  --log <off|problems|records> what to log beyond starting and stopping
  --log-file <path>            write the log there, not to stderr
                               (the log is JSON Lines, one object per line)
  --help                       print this text and exit (also -h)
  --version                    print the version and exit (also -v)
```

## CONFIGURATION

A configuration file gives `[link]` (interfaces, ipv6), one `[[instance]]` per
CDMI server advertised on this host (name, domain, target, port, ver, display,
addresses, check, check_url, check_interval_ms, check_ca) and `[log]` (level,
file). A flag wins over the file.

`mdns.toml` beside the source is a commented example.

## EXAMPLES

Advertise the servers named in the example configuration, logging each record
sent:

```sh
node src/mdnsd.ts --config mdns.toml --log records
```

## EXIT STATUS

0 where `--help` or `--version` completed, or the responder stopped on a
signal; 2 where the command line or the configuration was refused.

## SEE ALSO

`zoned`(1), `seedmi`(1).

RFC 6762 (multicast DNS), RFC 6763 (DNS-based service discovery).
