// TLS. One listener answers both the protocol binding and the HTTP
// exports, as the plain listener does; which certificate it presents is
// decided at the handshake, from the name the client asks for.
//
// A certificate is named by an identifier, never carried in the exports
// field of an object. Today the identifier is resolved in the
// configuration file; when KMIP is supported it will be resolved by
// asking a key management server, and nothing else here changes.

import { type SecureContext, createSecureContext } from "node:tls";
import { createServer } from "node:https";
import type { IncomingMessage, Server, ServerResponse } from "node:http";

export interface KeyPair {
  chain: string;
  key: string;
}

export interface TLSOptions {
  /** The certificate the protocol binding presents, where it has one. */
  binding?: KeyPair;
  /**
   * The certificate to present for a name asked for by SNI. This is
   * consulted at each handshake, so an export entry that changes takes
   * effect without the listener being restarted.
   */
  forHost: (host: string) => KeyPair | undefined;
}

/**
 * An HTTPS listener. Node builds a secure context per certificate;
 * contexts are held by the material they were built from, since
 * building one parses a key.
 */
export class TLSServer {
  private readonly opts: TLSOptions;
  private readonly contexts = new Map<string, SecureContext>();
  private server?: Server;

  constructor(opts: TLSOptions) {
    this.opts = opts;
  }

  private context(pair: KeyPair): SecureContext {
    const key = `${pair.chain}\u0000${pair.key}`;
    let ctx = this.contexts.get(key);
    if (!ctx) {
      ctx = createSecureContext({ cert: pair.chain, key: pair.key });
      this.contexts.set(key, ctx);
    }
    return ctx;
  }

  /** Starts the listener, answering each request with the handler. */
  listen(port: number, host: string,
    handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<Server> {
    const fallback = this.opts.binding;
    const server = createServer({
      // A certificate is required before a connection is accepted, so
      // one is supplied even where no name matches: a client that asks
      // for an unknown name receives a handshake it will reject, which
      // is the right answer and not a dropped connection.
      ...(fallback ? { cert: fallback.chain, key: fallback.key } : {}),
      SNICallback: (name: string,
        cb: (err: Error | null, ctx?: SecureContext) => void) => {
        const pair = this.opts.forHost(name.toLowerCase()) ?? fallback;
        if (!pair) {
          cb(new Error(`no certificate is held for ${name}`));
          return;
        }
        cb(null, this.context(pair));
      },
    }, handler);
    this.server = server;
    return new Promise((resolve) => {
      server.listen(port, host, () => resolve(server));
    });
  }

  /** Hands a WebSocket upgrade to a handler: a pipe's (binding.ts, handleUpgrade). */
  onUpgrade(handler: (req: IncomingMessage, socket: import("node:net").Socket, head: Buffer) => void): void {
    this.server?.on("upgrade", handler);
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.server) return resolve();
      this.server.close(() => resolve());
    });
  }

  address(): { port: number } | undefined {
    const a = this.server?.address();
    return a && typeof a !== "string" ? a as { port: number } : undefined;
  }
}
