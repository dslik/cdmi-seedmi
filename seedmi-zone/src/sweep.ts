// One pass: what the link is offering, what of it deserves a name, what the
// zone subtree should hold as a result, and the difference against what it held
// last.
//
// The rewriting is the part worth reading carefully. A browsing domain and an
// SRV target are different things — the domain is where the records live, the
// target is the host a client connects to — and ECR-224A's own example seeds
// ["local", "eng.example.com"] as though they were the same kind of thing. For
// a browser client they cannot be: no certificate is issued for a .local name,
// so a target on the link has to become a name in the published zone before
// anything can connect to it. That is what makes the push shape worth building
// rather than a proxy that answers for .local: the names become real, and a
// real name can hold a certificate.

import { type Instance } from "./browse.ts";
import { CLASS, type Name, presentation, type ResourceRecord, TYPE, within } from "./dns.ts";
import { check, type GateRequest, type GateResult } from "./gate.ts";

export const SERVICE = ["_cdmi", "_tcp"];

export interface SweepOptions {
  /** The subtree this program owns, and writes nothing outside. */
  zone: Name;
  /** The browsing domains whose instances are published. */
  domains: Name[];
  /** Lifetimes written into the zone. */
  ttlHost: number;
  ttlOther: number;
  /** Where the gate's certificate is not publicly trusted. */
  ca?: string;
  gateTimeoutMs?: number;
  /** Instances whose label matches none of these are not published, where any are given. */
  allow?: RegExp[];
  /**
   * The gate, which a test replaces. There is no setting for turning it off:
   * a deployment that could publish without it would be a deployment that
   * launders whatever the link says into a zone people trust.
   */
  gate?: (r: GateRequest) => Promise<GateResult>;
  log?: (event: Record<string, unknown>) => void;
}

export interface Published {
  records: ResourceRecord[];
  /** What was considered, and what became of it, for the log and for a test. */
  verdicts: { instance: string; published: boolean; why: string }[];
}

/**
 * The name an instance takes in the published zone: the label it chose, the
 * service type, and this program's zone in place of the browsing domain.
 */
const publishedInstance = (i: Instance, zone: Name): Name => [i.label, ...SERVICE, ...zone];

/**
 * The name the target takes. A target within a browsing domain is on the link
 * and cannot be resolved or trusted by anything off it, so it is republished
 * beneath the zone with the addresses the link gave. A target that is already
 * a real name is left exactly as it is, and no address is published for it: it
 * resolves by ordinary DNS, and the host it names is not this program's to
 * answer for.
 */
function publishedTarget(i: Instance, o: SweepOptions): { name: Name; ours: boolean } {
  if (o.domains.some((d) => within(i.target, d))) {
    return { name: [...i.target.slice(0, i.target.length - 1), ...o.zone], ours: true };
  }
  return { name: i.target, ours: false };
}

export async function sweep(instances: Instance[], o: SweepOptions): Promise<Published> {
  const log = o.log ?? (() => { /* silent */ });
  const records: ResourceRecord[] = [];
  const verdicts: Published["verdicts"] = [];
  const ptrTargets: Name[] = [];

  for (const i of instances) {
    const at = presentation(i.name);
    const refuse = (why: string) => {
      verdicts.push({ instance: at, published: false, why });
      log({ event: "not published", instance: at, why });
    };
    if (!i.complete) {
      refuse("the link has given its name but not yet its SRV and TXT records");
      continue;
    }
    if (i.port === 0 || i.target.length === 0) {
      refuse("its SRV record names no host and port");
      continue;
    }
    if (o.allow !== undefined && o.allow.length > 0 && !o.allow.some((re) => re.test(i.label))) {
      refuse("its name matches no allow pattern");
      continue;
    }
    const target = publishedTarget(i, o);
    if (target.ours && i.addresses.length === 0) {
      refuse(`its target ${presentation(i.target)} is on the link and the link has given no address for it`);
      continue;
    }
    // The gate. Everything above is shape; this is the part that decides
    // whether an announcement anybody could have made becomes a name in a
    // zone that people trust.
    const result = await (o.gate ?? check)({
      address: i.addresses[0] ?? "",
      port: i.port,
      servername: target.name,
      ...(o.ca === undefined ? {} : { ca: o.ca }),
      ...(o.gateTimeoutMs === undefined ? {} : { timeoutMs: o.gateTimeoutMs }),
    });
    if (!result.ok) {
      refuse(`it did not answer the well-known tree with a certificate for ${presentation(target.name)}: ` +
        result.why);
      continue;
    }

    const name = publishedInstance(i, o.zone);
    ptrTargets.push(name);
    records.push(
      { name, type: TYPE.SRV, class: CLASS.IN, ttl: o.ttlHost,
        data: { kind: "SRV", priority: 0, weight: 0, port: i.port, target: target.name } },
      { name, type: TYPE.TXT, class: CLASS.IN, ttl: o.ttlOther,
        data: { kind: "TXT", strings: i.txt } },
    );
    if (target.ours) {
      for (const address of i.addresses) {
        records.push({
          name: target.name,
          type: address.includes(":") ? TYPE.AAAA : TYPE.A,
          class: CLASS.IN, ttl: o.ttlHost,
          data: address.includes(":") ? { kind: "AAAA", address } : { kind: "A", address },
        });
      }
    }
    verdicts.push({ instance: at, published: true, why: result.why });
  }

  if (ptrTargets.length > 0) {
    records.push(...ptrTargets.map((name): ResourceRecord => ({
      name: [...SERVICE, ...o.zone], type: TYPE.PTR, class: CLASS.IN, ttl: o.ttlOther,
      data: { kind: "PTR", name },
    })));
    // So that a client browsing for service types at all finds this one in the
    // published zone, as it would on the link.
    records.push({
      name: ["_services", "_dns-sd", "_udp", ...o.zone], type: TYPE.PTR, class: CLASS.IN, ttl: o.ttlOther,
      data: { kind: "PTR", name: [...SERVICE, ...o.zone] },
    });
  }
  return { records, verdicts };
}
