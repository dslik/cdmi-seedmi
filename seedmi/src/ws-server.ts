// A WebSocket server, as a pipe needs one (PLAN-pipe.md, step 2; RFC 6455).
//
// The opening handshake is checked and answered, and frames are read as octets
// arrive, with the rules a server enforces: every frame a client sends is masked;
// no reserved bit is set, since no extension is negotiated; a control frame is
// not fragmented and carries at most 125 octets; fragments arrive in order, with
// control frames allowed between them; a text message is valid UTF-8, a
// character split between fragments included; and no frame or message larger than
// the limit is read, the limit applied to a frame's declared length before its
// payload is buffered, so that a declared length cannot be a memory attack.
//
// A violation is reported with the close code RFC 6455 gives it: 1002 for a
// protocol error, 1007 for text that is not UTF-8, 1009 for a message too big.

import type { IncomingMessage } from "node:http";
import { acceptFor, frame } from "./mqtt-ws.ts";

export const OP = { continuation: 0x0, text: 0x1, binary: 0x2, close: 0x8, ping: 0x9, pong: 0xa } as const;

/** The opening handshake's answer: the 101 response to write, or the status refusing it. */
export function handshake(req: IncomingMessage, subprotocol: string):
  { ok: true; response: string } | { ok: false; status: number; reason: string } {
  const h = (n: string) => { const v = req.headers[n]; return Array.isArray(v) ? v.join(",") : (v ?? ""); };
  if (req.method !== "GET") return { ok: false, status: 405, reason: "a WebSocket is opened by GET" };
  if (h("upgrade").toLowerCase() !== "websocket" || !h("connection").toLowerCase().split(",").map((x) => x.trim()).includes("upgrade")) {
    return { ok: false, status: 400, reason: "not a WebSocket upgrade" };
  }
  if (h("sec-websocket-version").trim() !== "13") return { ok: false, status: 400, reason: "WebSocket version 13 is spoken" };
  const key = h("sec-websocket-key").trim();
  // "a base64-encoded value that, when decoded, is 16 bytes in length"
  if (!/^[A-Za-z0-9+/]{22}==$/.test(key)) return { ok: false, status: 400, reason: "the Sec-WebSocket-Key is not a 16-octet nonce" };
  const offered = h("sec-websocket-protocol").split(",").map((x) => x.trim());
  if (!offered.includes(subprotocol)) return { ok: false, status: 400, reason: `the subprotocol ${subprotocol} is required` };
  return { ok: true, response: "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
    `Sec-WebSocket-Accept: ${acceptFor(key)}\r\nSec-WebSocket-Protocol: ${subprotocol}\r\n\r\n` };
}

export type Event =
  | { type: "text"; data: string }
  | { type: "binary"; data: Buffer }
  | { type: "ping"; data: Buffer }
  | { type: "pong"; data: Buffer }
  | { type: "close"; code: number; reason: string }
  | { type: "error"; code: 1002 | 1007 | 1009; reason: string };

/** Reads a client's frames as octets arrive. After an error it reads nothing more. */
export class FrameReader {
  private buffer = Buffer.alloc(0);
  private message: { opcode: number; parts: Buffer[]; size: number } | undefined;
  private failed = false;
  private readonly maxFrame: number;

  constructor(maxFrame: number) {
    this.maxFrame = maxFrame;
  }

  push(data: Buffer): Event[] {
    if (this.failed) return [];
    this.buffer = this.buffer.length === 0 ? data : Buffer.concat([this.buffer, data]);
    const out: Event[] = [];
    const fail = (code: 1002 | 1007 | 1009, reason: string) => { this.failed = true; this.buffer = Buffer.alloc(0); out.push({ type: "error", code, reason }); return out; };
    for (;;) {
      const b = this.buffer;
      if (b.length < 2) return out;
      const fin = (b[0] & 0x80) !== 0, rsv = b[0] & 0x70, opcode = b[0] & 0x0f;
      const masked = (b[1] & 0x80) !== 0;
      let length = b[1] & 0x7f, at = 2;
      if (rsv !== 0) return fail(1002, "a reserved bit is set, and no extension was negotiated");
      if (!masked) return fail(1002, "a frame from a client is not masked");
      const control = (opcode & 0x08) !== 0;
      if (![OP.continuation, OP.text, OP.binary, OP.close, OP.ping, OP.pong].includes(opcode as never)) {
        return fail(1002, `the opcode ${opcode} is not defined`);
      }
      if (control && (!fin || length > 125)) return fail(1002, "a control frame is fragmented, or longer than 125 octets");
      if (length === 126) {
        if (b.length < 4) return out;
        length = b.readUInt16BE(2); at = 4;
      } else if (length === 127) {
        if (b.length < 10) return out;
        const high = b.readUInt32BE(2);
        // "the most significant bit MUST be 0"
        if (high & 0x80000000) return fail(1002, "a frame length's most significant bit is set");
        length = high * 2 ** 32 + b.readUInt32BE(6); at = 10;
      }
      // Refused from the header alone, before the payload is buffered.
      if (length > this.maxFrame) return fail(1009, "a frame larger than this server reads");
      if (b.length < at + 4 + length) return out;
      const key = b.subarray(at, at + 4);
      const payload = Buffer.from(b.subarray(at + 4, at + 4 + length));
      for (let i = 0; i < payload.length; i++) payload[i] ^= key[i & 3];
      this.buffer = b.subarray(at + 4 + length);

      if (control) {
        if (opcode === OP.ping) out.push({ type: "ping", data: payload });
        else if (opcode === OP.pong) out.push({ type: "pong", data: payload });
        else {
          if (payload.length === 1) return fail(1002, "a close frame of one octet");
          const code = payload.length >= 2 ? payload.readUInt16BE(0) : 1005;
          const reason = decode(payload.subarray(2));
          if (reason === undefined) return fail(1007, "a close frame's reason is not UTF-8");
          out.push({ type: "close", code, reason });
          this.failed = true; // nothing is read after a close
          return out;
        }
        continue;
      }
      if (opcode === OP.continuation) {
        if (this.message === undefined) return fail(1002, "a continuation frame with no message begun");
      } else {
        if (this.message !== undefined) return fail(1002, "a new message begun before the last was finished");
        this.message = { opcode, parts: [], size: 0 };
      }
      const m = this.message!;
      m.size += payload.length;
      if (m.size > this.maxFrame) return fail(1009, "a message larger than this server reads");
      m.parts.push(payload);
      if (!fin) continue;
      this.message = undefined;
      const whole = Buffer.concat(m.parts);
      if (m.opcode === OP.text) {
        const text = decode(whole);
        if (text === undefined) return fail(1007, "a text message that is not UTF-8");
        out.push({ type: "text", data: text });
      } else {
        out.push({ type: "binary", data: whole });
      }
    }
  }
}

/** UTF-8 decoded strictly, or undefined where it is not UTF-8. */
function decode(b: Buffer): string | undefined {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(b);
  } catch {
    return undefined;
  }
}

/** A frame from the server: unmasked, as RFC 6455 requires of a server. */
export const serverFrame = (opcode: number, payload: Buffer) => frame(opcode, payload, false);

/** A close frame: the code, and a reason of at most 123 octets. */
export function closeFrame(code: number, reason: string): Buffer {
  const r = Buffer.from(reason, "utf8").subarray(0, 123);
  const p = Buffer.alloc(2 + r.length);
  p.writeUInt16BE(code, 0);
  r.copy(p, 2);
  return serverFrame(OP.close, p);
}
