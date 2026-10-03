// A KMIP server: TTLV over TLS, as the Basic Authentication Suite of the KMIP
// Profiles Version 1.4 document requires, in front of kmip-dispatch.ts and
// the core. seedmi uses it to test its KMIP client (phase 6) against a server
// whose behaviour it can inspect, and it can stand in for an external key
// management server in a deployment that has none.
//
// Profiles 1.4 section 3.1, the Basic Authentication Suite:
//   3.1.1 Conformant clients and servers "SHALL support" TLS v1.2, and "SHALL
//         NOT support" TLS v1.0 or SSL v3.0, v2.0 or v1.0.
//   3.1.2 They "SHALL support" TLS_RSA_WITH_AES_256_CBC_SHA256 and
//         TLS_RSA_WITH_AES_128_CBC_SHA256, MAY support the others listed, and
//         "SHALL NOT support any cipher suite not listed above".
//   3.1.3 Servers "SHALL require the use of channel (TLS) mutual authentication
//         to provide assurance of client authenticity for all operations other
//         than" Query and Discover Versions.
//   3.1.4 Servers "SHALL use TCP port number 5696".

import { createServer as createTlsServer, type TLSServer, type TLSSocket } from "node:tls";
import { dispatch, type DispatchOptions, unparseable } from "./kmip-dispatch.ts";
import { child, decode, encode, type Item, MessageReader, nameOf, TtlvError } from "./kmip-ttlv.ts";
import { enumName } from "./kmip-message.ts";

import { BASIC_SUITE_CIPHERS, BASIC_SUITE_PROTOCOL, KMIP_PORT } from "./kmip-tls.ts";
export { BASIC_SUITE_CIPHERS, KMIP_PORT };

export interface KmipServerOptions extends DispatchOptions {
  /** The server's certificate chain and private key, in PEM. */
  cert: string;
  key: string;
  /** The authority whose certificates identify clients, in PEM. */
  ca: string;
  /**
   * The identity of a client, from the certificate the channel authenticated.
   * The mechanism is "outside the scope of this specification" (Profiles
   * 3.1.3); by default the certificate subject's common name, or where it has
   * none, the certificate's SHA-256 fingerprint.
   */
  identify?: (subject: Record<string, string> | undefined, fingerprint256: string | undefined) => string;
  /** The largest message read; a larger one closes the connection. */
  maxMessage?: number;
  /** Told of each connection, with the identity its certificate establishes, if any. */
  onConnection?: (event: { identity: string | undefined; address: string | undefined }) => void;
  /**
   * Told of each operation answered: who asked, what, how it ended, and the
   * object it addressed. Nothing of a request's or a response's payload is
   * passed beyond the Unique Identifier, so that a log built from this carries
   * no key material, no secret and no attribute value.
   */
  onOperation?: (event: OperationEvent) => void;
}

/** What is told of an operation. */
export interface OperationEvent {
  identity: string | undefined;
  operation: string;
  status: string;
  reason?: string;
  uniqueIdentifier?: string;
}

/** The operations of a response, read for what may be logged and nothing more. */
function operationsOf(response: Item): Omit<OperationEvent, "identity">[] {
  const out: Omit<OperationEvent, "identity">[] = [];
  for (const b of (response.value as Item[]).filter((i) => nameOf(i.tag) === "Batch Item")) {
    const op = child(b, "Operation");
    const status = child(b, "Result Status");
    const reason = child(b, "Result Reason");
    const uid = child(child(b, "Response Payload") ?? b, "Unique Identifier");
    out.push({
      operation: op === undefined ? "(none)" : enumName("Operation", op.value as number),
      status: status === undefined ? "(none)" : enumName("Result Status", status.value as number),
      ...(reason === undefined ? {} : { reason: enumName("Result Reason", reason.value as number) }),
      ...(uid !== undefined && typeof uid.value === "string" ? { uniqueIdentifier: uid.value } : {}),
    });
  }
  return out;
}

export class KmipServer {
  private readonly opts: KmipServerOptions;
  private readonly server: TLSServer;
  private readonly sockets = new Set<TLSSocket>();

  constructor(opts: KmipServerOptions) {
    this.opts = opts;
    this.server = createTlsServer({
      cert: opts.cert,
      key: opts.key,
      ca: opts.ca,
      // A certificate is asked for and not required at the handshake: Query
      // and Discover Versions are answered without one (Profiles 3.1.3), and
      // each other operation is refused by the dispatcher without an identity.
      requestCert: true,
      rejectUnauthorized: false,
      minVersion: BASIC_SUITE_PROTOCOL,
      maxVersion: BASIC_SUITE_PROTOCOL,
      ciphers: BASIC_SUITE_CIPHERS.join(":"),
      honorCipherOrder: true,
    }, (socket) => this.serve(socket));
  }

  /** Listens; the port defaults to 5696 and the host to the loopback address. */
  listen(port = KMIP_PORT, host = "127.0.0.1"): Promise<{ port: number; host: string }> {
    return new Promise((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(port, host, () => {
        const a = this.server.address() as { port: number; address: string };
        resolve({ port: a.port, host: a.address });
      });
    });
  }

  /**
   * Replaces the certificate and key this server presents, and the authority
   * it trusts, for connections made from now on. A connection already made
   * goes on with the certificate it was made with, so rotating the server's
   * own certificate drops no one.
   */
  reload(material: { cert: string; key: string; ca: string }): void {
    this.server.setSecureContext({ cert: material.cert, key: material.key, ca: material.ca });
  }

  /** Closes every client connection, leaving the server listening. */
  dropConnections(): void {
    for (const s of this.sockets) s.destroy();
  }

  close(): Promise<void> {
    for (const s of this.sockets) s.destroy();
    return new Promise((resolve) => this.server.close(() => resolve()));
  }

  /** The identity a connection's certificate establishes, or undefined. */
  private identityOf(socket: TLSSocket): string | undefined {
    // "authorized" is true only where the client presented a certificate that
    // chains to the configured authority.
    if (!socket.authorized) return undefined;
    const peer = socket.getPeerCertificate();
    const identify = this.opts.identify ??
      ((subject, fp) => subject?.CN ?? fp ?? "");
    const who = identify(peer.subject, peer.fingerprint256);
    return who === "" ? undefined : who;
  }

  private serve(socket: TLSSocket): void {
    this.sockets.add(socket);
    socket.on("close", () => this.sockets.delete(socket));
    socket.on("error", () => socket.destroy());
    const reader = new MessageReader(this.opts.maxMessage);
    const who = this.identityOf(socket);
    this.opts.onConnection?.({ identity: who, address: socket.remoteAddress });
    socket.on("data", (chunk: Buffer) => {
      let frames;
      try {
        frames = reader.frames(chunk);
      } catch (e) {
        // A header that cannot be read, or a length beyond the limit: the
        // messages after it cannot be separated, so the connection is closed.
        // KMIP 1.4 does not say what a server does when framing is lost.
        if (e instanceof TtlvError) {
          socket.destroy();
          return;
        }
        throw e;
      }
      for (const f of frames) {
        let message;
        try {
          message = decode(f);
        } catch (e) {
          if (!(e instanceof TtlvError)) throw e;
          // The message is separated but cannot be parsed: "Message cannot be
          // parsed" is answered with a failed batch item (11.1).
          socket.write(encode(unparseable(e.message)));
          continue;
        }
        const response = dispatch(this.opts, who, message);
        socket.write(encode(response));
        if (this.opts.onOperation !== undefined) {
          for (const op of operationsOf(response)) this.opts.onOperation({ identity: who, ...op });
        }
      }
    });
  }
}
