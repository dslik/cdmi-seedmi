// One connection through a pipe (PLAN-pipe.md, step 3; RELAY-draft-2.md
// section 5): a WebSocket, whose opening handshake the binding has answered, and
// the TCP connection it carries, once its first frame presents a ticket.
//
//   awaiting the ticket  ->  connecting  ->  open  ->  closed
//
// The bytes are copied as they are, both ways, and never interpreted: seedmi does
// not terminate, decrypt or record what passes. Backpressure holds each direction
// while the other cannot take more, so that neither is buffered without bound:
// reading from TCP stops while the WebSocket's pending output exceeds 1 MiB, and
// reading frames stops while TCP's pending output is not drained.
//
// A connection that cannot be made closes with 4408 "unreachable", whatever the
// cause: "a CDMI server shall not report ... the reason a server-originated
// request failed at the network layer". The cause goes to the log alone.

import { connect as tcpConnect, type Socket } from "node:net";
import type { PipeService, Ticket } from "./pipe.ts";
import { closeFrame, FrameReader, OP, serverFrame } from "./ws-server.ts";

/** The WebSocket's pending output above which reading from TCP stops. */
export const HIGH_WATER = 1 << 20;
/** How long the first frame is waited for. */
export const FIRST_FRAME_MS = 5000;

export interface RelayContext {
  service: PipeService;
  /** The pipe the WebSocket was opened on, and the page's origin. */
  pipe: number;
  origin: string | undefined;
  /**
   * Whether the ticket's principal may still use the pipe: the pipe still exists
   * and is a pipe, its list admits the principal, its domain is enabled, and a
   * permit still admits the principal to the destination (section 5.4).
   */
  stillAdmitted(t: Ticket): boolean;
  /** A line for the log, marked as the pipe's; never payload, tickets or credentials. */
  log(event: Record<string, unknown>): void;
}

/** Runs a connection on a WebSocket whose handshake has been answered; head holds octets read past it. */
export function runRelay(ws: Socket, head: Buffer, ctx: RelayContext): void {
  const settings = ctx.service.settings;
  const reader = new FrameReader(settings.maxFrame);
  let state: "ticket" | "connecting" | "open" | "closed" = "ticket";
  let ticket: Ticket | undefined, handle: object | undefined, tcp: Socket | undefined;
  let bytesIn = 0, bytesOut = 0;
  const began = Date.now();
  const timers: ReturnType<typeof setTimeout>[] = [];
  let idle: ReturnType<typeof setTimeout> | undefined;

  const finish = (how: string, detail?: string) => {
    if (state === "closed") return;
    state = "closed";
    for (const t of timers) clearTimeout(t);
    if (idle !== undefined) clearTimeout(idle);
    tcp?.destroy();
    if (ticket !== undefined && handle !== undefined) ctx.service.closed(ticket, handle);
    ctx.log({ event: "pipe ended", how, ...(detail === undefined ? {} : { detail }), ...(ticket === undefined ? {} : {
      principal: ticket.principal.name, pipe: ticket.pipe, host: ticket.host, port: ticket.port, address: ticket.address,
      permit: ticket.permit }), origin: ctx.origin, in: bytesIn, out: bytesOut, ms: Date.now() - began });
  };
  /** Closes the WebSocket with a code and a short reason; the TCP connection with it. */
  const close = (code: number, reason: string, detail?: string) => {
    if (state === "closed") return;
    if (!ws.destroyed) {
      ws.write(closeFrame(code, reason));
      ws.end();
      // A client that does not answer the close is not waited for long. The timer
      // is not unref'd: at shutdown it must run, or a closing server waits on the
      // connection for ever.
      setTimeout(() => ws.destroy(), 1000);
    }
    finish(`${code} ${reason}`, detail);
  };
  const touch = () => {
    // Bytes in either direction, not pings of either kind (section 5.3).
    if (idle !== undefined) clearTimeout(idle);
    idle = setTimeout(() => close(1000, "idle"), settings.idleTimeout * 1000);
  };
  const sendText = (o: unknown) => ws.write(serverFrame(OP.text, Buffer.from(JSON.stringify(o), "utf8")));

  const first = setTimeout(() => close(4401, "ticket", "no ticket frame within five seconds"), FIRST_FRAME_MS);
  timers.push(first);

  const open = (t: Ticket) => {
    // "Checked again at connect", then counted within the limits.
    if (!ctx.stillAdmitted(t)) return close(4403, "not-permitted", "no longer admitted at connect");
    handle = ctx.service.opened(t, (code, reason) => close(code, reason, "the pipe was deleted or switched off"));
    if (handle === undefined) return close(4429, "limit");
    state = "connecting";
    // The pinned address, not the name: it is not resolved again.
    const socket = tcpConnect({ host: t.address, port: t.port });
    tcp = socket;
    const giveUp = setTimeout(() => { socket.destroy(); close(4408, "unreachable", "the connection timed out"); }, settings.connectTimeout * 1000);
    timers.push(giveUp);
    socket.once("connect", () => {
      clearTimeout(giveUp);
      if (state !== "connecting") return;
      state = "open";
      sendText({ ok: true });
      touch();
      timers.push(setTimeout(() => close(1000, "lifetime"), settings.maxLifetime * 1000));
      ctx.log({ event: "pipe opened", principal: t.principal.name, origin: ctx.origin, pipe: t.pipe, host: t.host, port: t.port,
        address: t.address, permit: t.permit });
    });
    socket.on("error", (e: Error) => {
      if (state === "connecting") close(4408, "unreachable", e.message);
      else close(1000, "remote-closed", e.message);
    });
    socket.on("data", (d: Buffer) => {
      bytesIn += d.length;
      touch();
      ws.write(serverFrame(OP.binary, d));
      if (ws.writableLength > HIGH_WATER) {
        socket.pause();
        ws.once("drain", () => socket.resume());
      }
    });
    // The destination closed: once its bytes are delivered, the WebSocket closes.
    socket.on("end", () => close(1000, "remote-closed"));
  };

  const handleEvents = (events: ReturnType<FrameReader["push"]>) => {
    for (const e of events) {
      if (state === "closed") return;
      if (e.type === "error") {
        return close(e.code, e.code === 1002 ? "protocol" : e.code === 1007 ? "encoding" : "too-large", e.reason);
      }
      if (e.type === "ping") { ws.write(serverFrame(OP.pong, e.data)); continue; }
      if (e.type === "pong") continue;
      if (e.type === "close") return close(1000, "client-closed");
      if (state === "ticket") {
        clearTimeout(first);
        let frame: { v?: unknown; ticket?: unknown };
        try {
          frame = e.type === "text" ? JSON.parse(e.data) : undefined!;
        } catch {
          return close(4400, "malformed", "the first frame is not JSON");
        }
        if (frame === undefined || frame === null || typeof frame !== "object" || frame.v !== 1) {
          return close(4400, "malformed", "the first frame is not a ticket frame");
        }
        const t = ctx.service.consume(frame.ticket, ctx.pipe, ctx.origin);
        if (t === undefined) return close(4401, "ticket", "no such ticket, used, expired, or of another pipe or origin");
        ticket = t;
        open(t);
        continue;
      }
      if (state !== "open") return close(4400, "malformed", "a frame before the connection was made");
      if (e.type === "binary") {
        bytesOut += e.data.length;
        touch();
        if (!tcp!.write(e.data)) {
          ws.pause();
          tcp!.once("drain", () => ws.resume());
        }
        continue;
      }
      // A text frame after the first: the one control message defined.
      let control: { ping?: unknown };
      try { control = JSON.parse(e.data); } catch { return close(4400, "malformed", "a control frame is not JSON"); }
      if (control === null || typeof control !== "object" || typeof control.ping !== "number" || Object.keys(control).length !== 1) {
        return close(4400, "malformed", "an unknown control message");
      }
      sendText({ pong: control.ping });
    }
  };

  ws.on("data", (d: Buffer) => handleEvents(reader.push(d)));
  ws.on("error", (e: Error) => finish("error", e.message));
  ws.on("close", () => finish("closed"));
  if (head.length > 0) handleEvents(reader.push(head));
}
