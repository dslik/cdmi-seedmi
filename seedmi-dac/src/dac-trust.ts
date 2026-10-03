// Phase 2 of PLAN.md: which CDMI servers this provider answers.
//
// A request's signature verifies against the sig key of its server_identity,
// which proves only that its sender holds that key: the draft makes the
// request carry the key that verifies it. So the key is authenticated here, by
// one of two means a [[server]] table gives:
//
// * a certificate chain: the key carries x5c ("A key should include an X.509
//   certificate or certificate chain used to verify the identity of the CDMI
//   server"), whose leaf holds that key, each certificate issued by the next and
//   in date, the last issued by, or being, a trust anchor of the table, and the
//   leaf's subject the one the table names, where it names one; or
// * a registered key: the sig key is one the table holds.
//
// A request no table authenticates is not evaluated. Nor is one whose
// identifier its server used within the window, so that a recorded request
// cannot be replayed for a fresh response.

import { createPublicKey, type KeyObject, X509Certificate } from "node:crypto";
import { type DacRequest, DacRefusal } from "./dac-protocol.ts";
import { chainOf, importJwk } from "./jose.ts";

/** A CDMI server this provider answers: a [[server]] table. */
export interface TrustedServer {
  name: string;
  /** Trust anchors for a chain the sig key carries. */
  anchors: X509Certificate[];
  /** The subject a chain's leaf bears, where one is required; as X509Certificate reports it. */
  subject?: string;
  /** Registered sig keys. */
  keys: KeyObject[];
  /** The dac_response_uri values its requests may give, for a response sent later. */
  responseUris?: string[];
  /** Trust anchors for its endpoint, PEM, where a response is sent later; the system's where absent. */
  responseCa?: string;
}

const spki = (k: KeyObject): Buffer =>
  (k.type === "public" ? k : createPublicKey(k)).export({ format: "der", type: "spki" }) as Buffer;

/** Whether a chain, leaf first, is in date and issued link by link to one of the anchors. */
function chainsTo(chain: X509Certificate[], anchors: X509Certificate[], now: Date): boolean {
  const inDate = (c: X509Certificate) => new Date(c.validFrom) <= now && now <= new Date(c.validTo);
  if (chain.length === 0 || !chain.every(inDate)) return false;
  for (let i = 0; i + 1 < chain.length; i++) {
    if (!chain[i].verify(chain[i + 1].publicKey)) return false;
  }
  const last = chain[chain.length - 1];
  return anchors.some((a) => inDate(a) && (last.raw.equals(a.raw) || last.verify(a.publicKey)));
}

/**
 * The name of the trusted server whose key signed a request, or the untrusted
 * refusal. The signature itself was verified by readRequest.
 */
export function authenticate(req: DacRequest, servers: TrustedServer[], now = new Date()): string {
  const sig = importJwk(req.serverSig);
  const der = spki(sig);
  let chain: X509Certificate[] = [];
  try {
    chain = chainOf(req.serverSig);
  } catch {
    chain = [];
  }
  const leafHolds = chain.length > 0 && spki(chain[0].publicKey).equals(der);
  for (const s of servers) {
    if (s.keys.some((k) => spki(k).equals(der))) return s.name;
    if (leafHolds && s.anchors.length > 0 && chainsTo(chain, s.anchors, now) &&
        (s.subject === undefined || chain[0].subject === s.subject)) {
      return s.name;
    }
  }
  throw new DacRefusal("untrusted", chain.length === 0
    ? "the request's sig key is not one registered for a server this provider answers, and carries no certificate"
    : "the request's sig key does not chain to a trust anchor of a server this provider answers");
}

/**
 * The identifiers each server has used within the window. "This identifier
 * shall be unique within the window within which multiple DAC responses can be
 * received": a second request bearing one is a replay, and is not evaluated.
 */
export class ReplayWindow {
  private readonly seen = new Map<string, number>();
  private readonly windowMs: number;
  private readonly now: () => number;
  constructor(windowMs: number, now: () => number = Date.now) {
    this.windowMs = windowMs;
    this.now = now;
  }

  /** Records a request, or refuses it as a replay. */
  admit(server: string, id: string): void {
    const t = this.now();
    for (const [k, at] of this.seen) if (t - at > this.windowMs) this.seen.delete(k);
    const key = `${server}\u0000${id}`;
    if (this.seen.has(key)) {
      throw new DacRefusal("replayed", `the request identifier ${JSON.stringify(id)} was used by ${server} within the window`);
    }
    this.seen.set(key, t);
  }
}
