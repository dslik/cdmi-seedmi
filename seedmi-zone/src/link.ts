// The multicast socket: one per address family, joined to the mDNS group on
// each interface, bound to port 5353.
//
// A continuous browser binds 5353 and joins the group, rather than asking from
// an ephemeral port. A one-shot query from an ephemeral port is answered, but
// it hears nothing else: not the unsolicited announcements a host makes when it
// arrives, and not the goodbye it sends when it leaves. Both are exactly what a
// program maintaining a zone from the link needs, so the port is bound.
//
// Which means port 5353 is a singleton here too. A host running avahi-daemon
// holds it, so this refuses to start and says who is likely to be holding it.

import { createSocket, type Socket } from "node:dgram";
import { networkInterfaces } from "node:os";
import { type Link, MDNS_PORT, type Peer } from "./browse.ts";

export const MDNS_IPV4 = "224.0.0.251";
export const MDNS_IPV6 = "ff02::fb";

export class LinkError extends Error {}

export interface UdpLinkOptions {
  /** The interfaces joined; empty means every non-loopback interface that has an address. */
  interfaces: string[];
  ipv6: boolean;
  receive: (bytes: Uint8Array, from: Peer) => void;
  log?: (event: Record<string, unknown>) => void;
}

/** The addresses of each interface, by family, for joining and for publishing. */
export function interfaceAddresses(only: string[]): { name: string; v4: string[]; v6: string[] }[] {
  const out: { name: string; v4: string[]; v6: string[] }[] = [];
  for (const [name, addrs] of Object.entries(networkInterfaces())) {
    if (addrs === undefined) continue;
    if (only.length > 0 && !only.includes(name)) continue;
    const usable = addrs.filter((a) => !a.internal);
    if (usable.length === 0) continue;
    out.push({
      name,
      v4: usable.filter((a) => a.family === "IPv4").map((a) => a.address),
      // A link-local address carries its zone, which a socket call needs and a
      // DNS record must not hold.
      v6: usable.filter((a) => a.family === "IPv6").map((a) => a.address.split("%")[0]!),
    });
  }
  return out;
}

export async function openLink(opts: UdpLinkOptions): Promise<Link> {
  const log = opts.log ?? (() => { /* silent */ });
  const nics = interfaceAddresses(opts.interfaces);
  if (nics.length === 0) {
    throw new LinkError(opts.interfaces.length === 0
      ? "no interface has an address to advertise on"
      : `none of ${opts.interfaces.join(", ")} has an address`);
  }
  const sockets: Socket[] = [];
  const bind = async (family: "udp4" | "udp6", group: string, join: (s: Socket) => void): Promise<void> => {
    const s = createSocket({ type: family, reuseAddr: true });
    s.on("message", (buf, rinfo) => opts.receive(new Uint8Array(buf), {
      address: rinfo.address, port: rinfo.port, family: family === "udp4" ? "IPv4" : "IPv6",
    }));
    s.on("error", (e) => log({ event: "socket", family, why: (e as Error).message }));
    await new Promise<void>((resolve, reject) => {
      s.once("error", reject);
      s.bind({ port: MDNS_PORT, exclusive: false }, () => {
        s.removeListener("error", reject);
        resolve();
      });
    }).catch((e: unknown) => {
      const why = (e as NodeJS.ErrnoException).code === "EADDRINUSE"
        ? `port ${MDNS_PORT} is already held on this host, most likely by avahi-daemon, seedmi-mdns or ` +
          "another multicast DNS program. A continuous browser has to hold that port to hear the " +
          "announcements and goodbyes a one-shot query never sees, so run this program on a host that " +
          "is not already running one."
        : (e as Error).message;
      throw new LinkError(why);
    });
    // The group is joined on each interface by name rather than once on the
    // default route, so a host with two links answers on both.
    try {
      join(s);
    } catch (e) {
      log({ event: "join", family, group, why: (e as Error).message });
    }
    s.setMulticastLoopback(true);
    s.setMulticastTTL(255);
    sockets.push(s);
  };

  await bind("udp4", MDNS_IPV4, (s) => {
    for (const nic of nics) for (const a of nic.v4) s.addMembership(MDNS_IPV4, a);
  });
  if (opts.ipv6) {
    try {
      await bind("udp6", MDNS_IPV6, (s) => {
        for (const nic of nics) s.addMembership(MDNS_IPV6, nic.name);
      });
    } catch (e) {
      // A host without IPv6 is not a host that cannot advertise.
      log({ event: "ipv6 unavailable", why: (e as Error).message });
    }
  }

  return {
    send(bytes: Uint8Array, to?: Peer): void {
      const buf = Buffer.from(bytes);
      if (to !== undefined) {
        const s = sockets.find((x) => (x.address().family === "IPv4") === (to.family === "IPv4"));
        s?.send(buf, to.port, to.address);
        return;
      }
      for (const s of sockets) {
        const v4 = s.address().family === "IPv4";
        s.send(buf, MDNS_PORT, v4 ? MDNS_IPV4 : MDNS_IPV6);
      }
    },
    close(): void {
      for (const s of sockets) {
        try {
          s.close();
        } catch { /* already closed */ }
      }
    },
  };
}
