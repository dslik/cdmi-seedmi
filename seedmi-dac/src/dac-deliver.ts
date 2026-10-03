// Phase 4 of PLAN.md: answering later.
//
// "dac_response_uri: An optional URI that specifies where to send the DAC
// response. This URI is required for asynchronous DAC requests." A request a
// rule defers is acknowledged at once with an empty 202, and its packaged
// response is sent afterwards to that URI by POST. The draft does not state the
// method of that delivery (PLAN.md, questions for the draft); seedmi's
// endpoint takes POST, answering 204 where it acts on the response and 400
// where it does not.
//
// A request's dac_response_uri is stated by the CDMI server, from a request its
// client made; sending to any URI so stated would let a client of the server
// direct this provider's requests. So a response is sent only to a URI the
// server's [[server]] table permits, and a rule deferring a request whose URI
// is not permitted, or that names none, is answered at once instead.

import type { IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";

/** Whether a URI is one of those permitted: equal to one, or beneath one ending in "/". */
export function permitted(uri: string, allowed: string[]): boolean {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  if (u.protocol !== "https:" || u.username !== "" || u.password !== "") return false;
  const plain = `${u.origin}${u.pathname}${u.search}`;
  return allowed.some((a) => plain === a || (a.endsWith("/") && plain.startsWith(a)));
}

export type Outcome = "delivered" | "refused" | "failed";

export interface DeliveryOptions {
  /** Attempts in all, the first included. */
  attempts: number;
  /** The wait before the second attempt, doubled before each after it. */
  backoffMs: number;
  /** Trust anchors for the server's endpoint, PEM; the system's where absent. */
  ca?: string;
  timeoutMs?: number;
}

/** One POST of a body, resolving with the status, or 0 where no answer came. */
function post(uri: string, body: string, o: DeliveryOptions): Promise<number> {
  return new Promise((resolve) => {
    const u = new URL(uri);
    const req = httpsRequest({
      hostname: u.hostname.replace(/^\[|\]$/g, ""), port: u.port === "" ? 443 : Number(u.port),
      path: `${u.pathname}${u.search}`, method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": String(Buffer.byteLength(body)) },
      ...(o.ca === undefined ? {} : { ca: o.ca }), timeout: o.timeoutMs ?? 10_000,
    } as never, (res: never) => {
      const r = res as IncomingMessage & { statusCode: number; resume(): void };
      r.resume();
      r.on("end", () => resolve(r.statusCode));
    });
    // A delivery that does not complete in time ends, and counts as no answer.
    req.on("timeout", () => req.destroy());
    req.on("error", () => resolve(0));
    req.end(body);
  });
}

/**
 * Sends a packaged response to the URI a request gave. A 2xx delivers it. A 4xx
 * is the server declining it (a request no longer awaited, a response it does
 * not accept) and is not tried again. No answer, or a 5xx, is tried again after
 * a wait, until the attempts are spent.
 */
export async function deliver(uri: string, body: string, o: DeliveryOptions): Promise<{ outcome: Outcome; status: number }> {
  let wait = o.backoffMs;
  let status = 0;
  for (let attempt = 1; attempt <= o.attempts; attempt++) {
    status = await post(uri, body, o);
    if (status >= 200 && status <= 299) return { outcome: "delivered", status };
    if (status >= 400 && status <= 499) return { outcome: "refused", status };
    if (attempt < o.attempts) {
      await new Promise((r) => setTimeout(r, wait));
      wait *= 2;
    }
  }
  return { outcome: "failed", status };
}
