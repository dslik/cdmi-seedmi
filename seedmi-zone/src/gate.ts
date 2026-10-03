// The gate: whether an instance heard on the link deserves a name in a real
// DNS zone.
//
// This is the security property of the whole program. Multicast DNS is
// unauthenticated — anything on the link can announce _cdmi._tcp and call
// itself whatever it likes. Promoting that into a zone turns a link-local
// claim into a name that looks administratively blessed, and a DNSSEC-signed
// zone signs the lie. RFC 8766 says as much of a discovery proxy, and it is
// truer here, because a record written into a zone outlives the announcement
// that produced it.
//
// So an instance is published only where its host answers the CDMI well-known
// discovery tree over TLS **with a certificate valid for the name being
// published**. That makes the certificate the browser needs anyway into the
// authenticator for the zone entry: an impostor may announce whatever it likes
// on the link and still cannot get published, because it cannot present a
// certificate for a name in a zone it does not control.
//
// The connection is made to the address the link gave, with the published name
// as the server name, so the certificate is checked against the name a client
// will later use and not against the one the impostor chose.

import { Agent, request } from "node:https";
import { type Name, presentation } from "./dns.ts";

export interface GateRequest {
  /** The address to connect to, from the link; the name where the link gave none. */
  address: string;
  port: number;
  /** The name the certificate must be valid for: the one this program will publish. */
  servername: Name;
  /** The anchors, where the system does not trust the issuer. */
  ca?: string;
  timeoutMs?: number;
}

export interface GateResult {
  ok: boolean;
  why: string;
}

/** One check, made afresh: a certificate may be revoked or replaced between sweeps. */
export function check(r: GateRequest): Promise<GateResult> {
  const name = presentation(r.servername);
  return new Promise((resolve) => {
    let done = false;
    const finish = (ok: boolean, why: string) => {
      if (done) return;
      done = true;
      resolve({ ok, why });
    };
    const host = r.address === "" ? name : r.address;
    let req: ReturnType<typeof request>;
    try {
      req = request({
        protocol: "https:",
        host,
        port: r.port,
        path: "/.well-known/cdmi/cdmi_namespaces/",
        method: "GET",
        // The name the certificate is checked against, which is the published
        // name and not the address dialled. Verification is never turned off:
        // an unverified check would publish exactly the host this gate exists
        // to keep out.
        servername: name,
        headers: { Host: `${name}:${r.port}` },
        agent: new Agent(r.ca === undefined ? {} : { ca: r.ca }),
        timeout: r.timeoutMs ?? 5000,
      });
    } catch (e) {
      finish(false, (e as Error).message);
      return;
    }
    req.on("response", (res) => {
      const status = res.statusCode ?? 0;
      res.resume();
      // Any answer is an answer: a 401 says the server is there and wants a
      // credential, which is a server a client can still use. What matters is
      // that the TLS handshake got this far, which means the certificate
      // verified for the name about to be published.
      finish(status > 0 && status < 500, `HTTP ${status}`);
    });
    req.on("timeout", () => {
      req.destroy();
      finish(false, "timed out");
    });
    req.on("error", (e) => finish(false, (e as Error).message));
    req.end();
  });
}
