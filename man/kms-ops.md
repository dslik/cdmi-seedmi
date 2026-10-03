# kms-ops(1)

## NAME

kms-ops — operating seedmi-kms

## SYNOPSIS

```
node src/kms-ops.ts backup --store <dir> --to <file>
node src/kms-ops.ts health --host <address> --port <port> --ca <file>
```

Run from the `seedmi-kms` directory.

## DESCRIPTION

Two operations on a key server: taking a backup of its store while it serves,
and asking whether it is answering.

### backup

Writes a consistent copy of the store while the server serves. The copy is
restored by placing it, as `kms.db`, in an empty store directory with the
server stopped.

### health

Asks the server which protocol versions it speaks, with **no client
certificate**, so it needs none of the key material a client would. It exits 0
where the server answers and 1 where it does not, which is what a monitor
reads.

## OPTIONS

```
  backup --store <dir> --to <file>
      --store <dir>    the store directory to copy
      --to <file>      the file to write the copy to

  health --host <address> --port <port> --ca <file>
      --host <address> the address the server listens on
      --port <port>    the port it listens on
      --ca <file>      the authority that issued the server's certificate
```

## EXAMPLES

Back up a running server's store:

```sh
node src/kms-ops.ts backup --store ./kms-data --to /backups/kms-$(date +%F).db
```

Ask whether the server is answering, for a monitor that reads the exit status:

```sh
node src/kms-ops.ts health --host 127.0.0.1 --port 5696 --ca pki/ca.pem
```

## EXIT STATUS

For `health`: 0 where the server answered, 1 where it did not. For `backup`: 0
where the copy was written. 2 where the command line was refused.

## SEE ALSO

`kmsd`(1), `kms-pki`(1).
