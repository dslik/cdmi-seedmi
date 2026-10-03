// Resolving a principal at a domain controller (PLAN-dcd.md, phase 4).
//
// "The identities a domain recognizes, the credentials that resolve to each of
// them, the groups to which [they belong] ... This document does not specify
// how they are configured, nor the means by which a CDMI server resolves
// credentials, which may include referring them to an external identity
// service" (the domains clause). A [[domain_controller]] table refers the
// credentials presented for the objects of a domain, and of the domains beneath
// it unless they name their own, to a domain controller:
//
// * Basic credentials by LDAP over TLS (RFC 4511): a simple bind as the user,
//   uid=<name>,ou=people,<base>, and then a search of that entry, on the same
//   connection, for memberOf. This server binds as the user and needs no
//   credential of its own at the controller.
// * Bearer credentials as a JWT access token (RFC 9068) the controller issued:
//   its metadata fetched (RFC 8414), its issuer checked against the one
//   configured, its JWK Set fetched, and the token's typ, algorithm, issuer,
//   audience (this server) and expiry checked.
//
// A principal resolved at a controller is named with the controller's realm,
// alice@EU.EXAMPLE, as are its groups, so that the same name in two realms is
// two principals, and an access control entry naming one is not satisfied by
// the other, where an object moves between their domains. A resolution is kept
// for a short while, keyed by a hash of the credentials, so that a request does
// not always wait on the controller; a failure is not kept.

import { encrypt as encryptKrb } from "./krb-crypto.ts";
import { serviceTicket, ticketParts as ticketPartsOf } from "./krb-client.ts";
import { type PrincipalName, USAGE, writeApReq, writeAuthenticator } from "./krb-ticket.ts";
import { krb5ApReq, unwrapToken, wrapToken } from "./krb-negotiate.ts";
import { createHash } from "node:crypto";
import { request as httpsRequest } from "node:https";
import { connect as tlsConnect } from "node:tls";
import { isIP } from "node:net";
import type { Principal } from "./acl.ts";
import { importJwk, type Jwk, verifyJws } from "./jose.ts";
import type { Etype } from "./krb-crypto.ts";
import { acceptNegotiate } from "./krb-negotiate.ts";
import { KrbError, ReplayCache } from "./krb-ticket.ts";
import { groupsFromPac } from "./krb-pac.ts";
import { decrypt as decryptKrb } from "./krb-crypto.ts";
import { readEncTicketPart } from "./krb-ticket.ts";
import { Condition, SEEDMI_PROBLEM_BASE, unauthenticated } from "./problems.ts";
import { scopesOfClaims } from "./oauth.ts";

export interface DomainControllerConfig {
  /** The namespace path of the domain it serves, and the domains beneath it. */
  domain: string;
  /** Its realm, which names its principals: alice@EU.EXAMPLE. */
  realm: string;
  /** ldaps://host:port */
  ldap: string;
  /** The LDAP base under which users and groups are: dc=eu,dc=example. */
  base: string;
  /** The authority for its certificate, PEM. */
  ca: string;
  /** The issuer of the bearer tokens this domain accepts, or undefined where it accepts none. */
  issuer?: string;
  /** This server, as the audience of those tokens. */
  audience?: string;
  cacheSeconds: number;
  timeoutMs: number;
  /**
   * The service principal of this server in the realm, as a ticket names it,
   * and the key it is known by: with these, the domain resolves a Kerberos
   * ticket presented by the Negotiate scheme of RFC 4559 (PLAN-auth.md, phase 3b).
   */
  servicePrincipal?: string;
  serviceKey?: Buffer;
  serviceEtype?: Etype;
  /**
   * An account this server binds as to read the groups of a principal that
   * authenticated by a ticket, which carries no password to bind with. The
   * draft has the CDMI server bind as its service principal by the SASL
   * mechanism of RFC 4752, which is phase 7 of PLAN-auth.md; until then a
   * directory that refuses an anonymous search needs an account here.
   */
  searchDn?: string;
  searchPassword?: string;
  /**
   * The key distribution centre of the realm, as "host" or "host:port", by
   * which this server obtains a ticket for the directory's own service and
   * binds to it by the SASL mechanism of RFC 4752. Revision 282's directory
   * descriptor names no such address (ECR-142A), so it is configured here.
   */
  kdc?: string;
  /**
   * The attribute of a directory entry that holds the name a principal
   * presents: "Where absent, \"uid\"; a directory that is Active Directory
   * uses \"sAMAccountName\"" (revision 298; ECR-139B).
   */
  principalAttribute?: string;
  /**
   * The attribute that lists the groups of which a principal is a member,
   * "memberOf" where absent. "The attribute may list direct memberships
   * alone; the CDMI server determines transitive membership", which this
   * server does by following each group in turn.
   */
  groupAttribute?: string;
  /**
   * The claim of a bearer token whose value names a principal of this domain,
   * "such as `sub` or `preferred_username`". "Where this member is absent, a
   * CDMI server resolves no principal from a bearer token."
   *
   * The name was read from the descriptor by nothing before 0.87, and a token's
   * subject was taken from the `sub` claim whatever the descriptor said — so a
   * domain whose directory keys its entries on another claim resolved the wrong
   * value, and a domain that named no claim resolved a principal where the
   * clause says it resolves none.
   */
  principalClaim?: string;
  /**
   * The claim whose value names the groups of the principal. "A CDMI server
   * takes the groups of a principal authenticated by a bearer token from that
   * claim where this member is present, and from the directory where it is
   * absent."
   */
  groupsClaim?: string;
  /**
   * Whether this controller was built from the cdmi_domain_auth item of a
   * domain object rather than from this server's own configuration. It decides
   * what an absent principal_claim means: the clause's "resolves no principal
   * from a bearer token" is a statement about a descriptor, and a
   * [[domain_controller]] table of this server's configuration carries no such
   * member and is answered from "sub" as it always was.
   */
  fromDescriptor?: boolean;
  /**
   * The key distribution centres of the realm, tried in the order given
   * (revision 298; ECR-142B). Where none is given, the kdc field above is
   * used, which this server's own configuration sets.
   */
  kdcs?: string[];
  /**
   * The base URI beneath which the homes of this domain's principals are
   * held, against which a home read from the directory is divided
   * (revision 302; ECR-145B).
   */
  homeBase?: string;
  /**
   * The attributes the members of the description of a principal are taken
   * from, by member name, as the "userinfo_attributes" member of the
   * directory descriptor maps them.
   */
  userinfoAttributes?: Record<string, string>;
}

/**
 * The attributes read from a principal's entry: those the descriptor maps,
 * and, where it maps none for the home, "unixHomeDirectory" and then
 * "homeDirectory", so that "A directory holding the homes of a UNIX
 * deployment is thereby used without further statement" (revision 302).
 */
export function attributesWanted(dc: DomainControllerConfig): string[] {
  const mapped = Object.values(dc.userinfoAttributes ?? {});
  const home = dc.userinfoAttributes?.home;
  return [...new Set([...mapped, ...(home === undefined ? ["unixHomeDirectory", "homeDirectory"] : [])])];
}

/**
 * The service that resolves the credentials of a request cannot be reached:
 * "Where the directory or other service that resolves the credentials of a
 * request cannot be reached, the CDMI server shall report the authentication
 * unavailable condition. It shall not resolve the credentials by any other
 * means, and shall not perform the request as the anonymous principal"
 * (revision 282; ECR-129B). Before 0.62 this was a 503 of this server's own,
 * the draft naming no condition.
 *
 * A Retry-After header field is included "where it can estimate the time at
 * which the service becomes reachable again": every case here is a connection
 * that failed or timed out, of which this server can estimate nothing, so none
 * is included.
 */
export function authenticationUnavailable(detail: string): Condition {
  return new Condition(503, "authentication-unavailable",
    "The credentials presented could not be evaluated.", detail);
}

class Unreachable extends Error {}

// --- LDAP, the few messages needed -----------------------------------------

function tlv(tag: number, content: Buffer): Buffer {
  const n = content.length;
  const len = n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]);
  return Buffer.concat([Buffer.from([tag]), len, content]);
}
const octets = (s: string, tag = 0x04) => tlv(tag, Buffer.from(s, "utf8"));
const small = (tag: number, n: number) => tlv(tag, Buffer.from([n]));
/** One TLV at an offset, or undefined where the octets are not all there yet. */
function readTlv(b: Buffer, at: number): { tag: number; content: Buffer; next: number } | undefined {
  if (at + 2 > b.length) return undefined;
  let len = b[at + 1], head = 2;
  if (len & 0x80) {
    const k = len & 0x7f;
    if (k === 0 || k > 4 || at + 2 + k > b.length) return k === 0 || k > 4 ? { tag: -1, content: Buffer.alloc(0), next: -1 } : undefined;
    len = 0;
    for (let i = 0; i < k; i++) len = len * 256 + b[at + 2 + i];
    head += k;
  }
  if (at + head + len > b.length) return undefined;
  return { tag: b[at], content: b.subarray(at + head, at + head + len), next: at + head + len };
}
function children(b: Buffer): { tag: number; content: Buffer }[] {
  const out: { tag: number; content: Buffer }[] = [];
  for (let at = 0; at < b.length;) {
    const t = readTlv(b, at);
    if (t === undefined || t.next < 0) throw new Error("a malformed LDAP message");
    out.push(t);
    at = t.next;
  }
  return out;
}

/** How many groups are followed while resolving membership transitively. */
export const MAX_GROUPS = 256;

/**
 * Binds as a user, reads the groups of that user, and resolves membership
 * transitively: "The groups of a principal include every group of which it is a
 * member directly or through membership of another group, whichever way it
 * authenticated ... Where the groups are determined by an LDAP search, the CDMI
 * server shall determine that transitive membership ... or by resolving the
 * membership of each group found in turn" (revision 282; ECR-131B). Before 0.62
 * the groups of the user's own entry were taken as they stood, which is direct
 * membership alone in a directory whose attribute is not transitive, such as
 * Active Directory.
 *
 * Each group found is searched in turn, on the same connection, for its own
 * groups, a group already seen is not searched again, and at most MAX_GROUPS are
 * followed, so that a directory whose attribute is already transitive costs one
 * search for each group and a cycle cannot be followed for ever.
 *
 * Resolves with the group names (the cn of each group), or undefined where the
 * bind is refused; rejects with Unreachable where the controller cannot be
 * reached or answers nothing sensible.
 */
/**
 * The TLS options for reaching a domain controller whose certificate the
 * configuration names.
 *
 * A certificate that signed itself is what a development deployment has, and
 * OpenSSL will not end a chain at one that is an end-entity certificate: it
 * reports "self-signed certificate" even though the operator named it as the
 * trust anchor. Where the named certificate is self-signed, this server
 * therefore pins to it — the connection is accepted where the certificate
 * presented is byte for byte that certificate, and refused otherwise, which
 * is a stronger check than a chain to a public authority, not a weaker one.
 * A certificate that is a certificate authority is used as one, as before.
 */
export function anchoredBy(ca: string): Record<string, unknown> {
  const anchor = pemDer(ca);
  if (anchor === undefined) return { ca };
  return {
    ca,
    rejectUnauthorized: false,
    checkServerIdentity: () => undefined,
    // The socket is checked against the anchor once the handshake completes.
    seedmiPin: anchor,
  };
}

/**
 * Enforces the pin: the certificate presented shall be the one named. Where
 * it is not, the socket is destroyed with a message that says so, which is
 * the same refusal a failed chain gives and not a silent acceptance.
 */
export function enforcePin(socket: { getPeerCertificate?: (d?: boolean) => { raw?: Buffer };
  destroy: (e?: Error) => void }, ca: string): boolean {
  const anchor = pemDer(ca);
  if (anchor === undefined) return true;
  const shown = socket.getPeerCertificate?.()?.raw;
  if (shown !== undefined && shown.equals(anchor)) return true;
  // The fingerprints say which two certificates are meant, and the usual
  // cause is a controller still running from an earlier start while the
  // certificate beside it has since been written again: an older process
  // holds the older certificate, and an older configuration with it.
  const of = (b: Buffer | undefined) =>
    b === undefined ? "none" : createHash("sha256").update(b).digest("hex").slice(0, 16);
  socket.destroy(new Error(
    "the domain controller presented a certificate other than the one named in ca_file " +
    `(presented ${of(shown)}, named ${of(anchor)}). A controller still running from an ` +
    "earlier start holds the certificate of that start; stop it and start it again."));
  return false;
}

/** The DER of the first certificate of a PEM, where it holds one. */
function pemDer(pem: string): Buffer | undefined {
  const m = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(pem);
  if (m === null) return undefined;
  try {
    return Buffer.from(m[1].replace(/\s+/g, ""), "base64");
  } catch {
    return undefined;
  }
}

function ldapGroups(dc: DomainControllerConfig, userDn: string, password: string, searchDn = userDn,
  gssapi?: { ticket: Buffer; sessionKey: Buffer; service: PrincipalName },
  /** Attributes of the principal's own entry to read beside its groups. */
  extra: string[] = [],
  /** Where the caller wants those values, they are put here. */
  into?: Record<string, string>,
  /**
   * Security identifiers to resolve to names instead of following the groups
   * of an entry: the identifiers a ticket's privilege attribute certificate
   * carries ([MS-PAC]; PLAN-auth.md, phase 5). Each is searched for beneath
   * the base, by the objectSid attribute, and its cn is the group's name.
   */
  sids?: string[]): Promise<string[] | undefined> {
  const u = new URL(dc.ldap);
  const host = u.hostname.replace(/^\[|\]$/g, "");
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = (f: () => void) => { if (!done) { done = true; f(); socket.end(); } };
    /** A bind request: simple, or SASL with the mechanism and its credentials. */
    const bindRequest = (id: number, credentials?: Buffer) => tlv(0x30, Buffer.concat([small(0x02, id),
      tlv(0x60, Buffer.concat([small(0x02, 3), octets(""),
        gssapi === undefined
          ? octets(password, 0x80)
          : tlv(0xa3, Buffer.concat([octets("GSSAPI"), ...(credentials === undefined ? [] : [tlv(0x04, credentials)])])),
      ]))]));
    const simpleBind = (id: number) => tlv(0x30, Buffer.concat([small(0x02, id),
      tlv(0x60, Buffer.concat([small(0x02, 3), octets(userDn), octets(password, 0x80)]))]));
    const socket = tlsConnect({ host, port: Number(u.port || 636), ...anchoredBy(dc.ca),
      ...(isIP(host) ? {} : { servername: host }) } as never, () => {
      if (!enforcePin(socket as never, dc.ca)) return;
      if (gssapi === undefined) {
        // BindRequest: [APPLICATION 0] { version 3, name, simple [0] password }
        socket.write(simpleBind(1));
        return;
      }
      // The SASL mechanism of RFC 4752, which begins with the client's ticket.
      const authenticator = writeAuthenticator({
        crealm: dc.realm, cname: { type: 3, parts: (dc.servicePrincipal ?? "").split("/") },
        cusec: Math.floor(Math.random() * 1000000), ctime: Date.now(),
      });
      const apReq = writeApReq(ticketPartsOf(gssapi.ticket),
        { etype: gssapi.sessionKey.length === 16 ? 17 : 18,
          cipher: encryptKrb(gssapi.sessionKey, USAGE.authenticator, authenticator) },
        // Mutual authentication is not asked for: TLS already tells this client
        // which server it reached, and the exchange is shorter without it.
        Buffer.alloc(4));
      socket.write(bindRequest(1, krb5ApReq(apReq)));
    });
    socket.setTimeout(dc.timeoutMs, () => finish(() => reject(new Unreachable(`the domain controller at ${dc.ldap} did not answer in time`))));
    socket.on("error", (e: Error) => finish(() => reject(new Unreachable(`the domain controller at ${dc.ldap} cannot be reached: ${e.message}`))));
    let buffer = Buffer.alloc(0);
    /** The groups found, by their distinguished names, and those still to search. */
    const found = new Map<string, string>();
    const pending: string[] = [];
    /** The identifiers still to resolve, where that is what this is for. */
    const identifiers = [...(sids ?? [])];
    const named: string[] = [];
    let message = 1;
    // The attribute that lists a principal's groups, which the directory of
    // the domain names (revision 298), and "memberOf" where it names none.
    const groupAttribute = dc.groupAttribute ?? "memberOf";
    /**
     * Searches beneath the base for the entry whose objectSid is the one
     * given, and asks for its cn: a subtree search with an equality filter.
     */
    const searchSid = (sid: string) => {
      message++;
      socket.write(tlv(0x30, Buffer.concat([small(0x02, message), tlv(0x63, Buffer.concat([
        octets(dc.base), small(0x0a, 2), small(0x0a, 0), small(0x02, 0), small(0x02, 0), tlv(0x01, Buffer.from([0])),
        // (objectSid=<sid>), an equality match.
        tlv(0xa3, Buffer.concat([octets("objectSid"), octets(sid)])),
        tlv(0x30, octets("cn")),
      ]))])));
    };
    /** Searches one entry for the groups it is a member of: baseObject, that attribute alone. */
    const searchGroupsOf = (dn: string) => {
      message++;
      // The principal's own entry is asked for the attributes the caller
      // wants beside its groups; a group's entry is asked for its groups alone.
      const wanted = dn === searchDn ? [groupAttribute, ...extra] : [groupAttribute];
      socket.write(tlv(0x30, Buffer.concat([small(0x02, message), tlv(0x63, Buffer.concat([
        octets(dn), small(0x0a, 0), small(0x0a, 0), small(0x02, 0), small(0x02, 0), tlv(0x01, Buffer.from([0])),
        octets("objectClass", 0x87), tlv(0x30, Buffer.concat(wanted.map((w) => octets(w)))),
      ]))])));
    };
    /** The value of the first relative distinguished name, where it is a cn. */
    const nameOf = (dn: string) => {
      const first = dn.split(",")[0] ?? "";
      const eq = first.indexOf("=");
      return eq > 0 && first.slice(0, eq).trim().toLowerCase() === "cn" ? first.slice(eq + 1).trim() : undefined;
    };
    socket.on("data", (d: Buffer) => {
      buffer = Buffer.concat([buffer, d]);
      try {
        for (;;) {
          const m = readTlv(buffer, 0);
          if (m === undefined) return;
          if (m.next < 0) throw new Error("a malformed LDAP message");
          buffer = buffer.subarray(m.next);
          const [, op] = children(m.content);
          const body = children(op.content);
          if (op.tag === 0x61) {
            // BindResponse: success (0), saslBindInProgress (14), or refused.
            const code = body[0].content[0];
            if (code === 14) {
              if (gssapi === undefined) return finish(() => resolve(undefined));
              // serverSaslCreds [7]: the four octets of the security layer
              // offer, under GSS_Wrap (RFC 4752 section 3.2).
              const creds = children(op.content).find((e) => e.tag === 0x87);
              if (creds === undefined) return finish(() => reject(new Unreachable("the directory sent no SASL credentials")));
              const offer = unwrapToken(gssapi.sessionKey, creds.content, { acceptor: true });
              if (offer.length < 4 || (offer[0] & 1) === 0) {
                return finish(() => reject(new Unreachable("the directory offers no security layer this client takes")));
              }
              // No security layer, a maximum of zero, and no authorization identity.
              message++;
              socket.write(bindRequest(message, wrapToken(gssapi.sessionKey, Buffer.from([1, 0, 0, 0]),
                { acceptor: false, sequence: 1 })));
              continue;
            }
            if (code !== 0) return finish(() => resolve(undefined));
            if (sids !== undefined) {
              const first = identifiers.shift();
              if (first === undefined) return finish(() => resolve([]));
              searchSid(first);
              continue;
            }
            searchGroupsOf(searchDn);
          } else if (op.tag === 0x64 && sids !== undefined) {
            // The entry of an identifier: its cn is the name of the group.
            for (const attr of children(body[1].content)) {
              const [type, vals] = children(attr.content);
              if (type.content.toString("utf8").toLowerCase() !== "cn") continue;
              const value = children(vals.content)[0];
              if (value !== undefined) named.push(value.content.toString("utf8"));
            }
          } else if (op.tag === 0x64) {
            // SearchResultEntry: each memberOf value is the distinguished name of a group.
            for (const attr of children(body[1].content)) {
              const [type, vals] = children(attr.content);
              const named = type.content.toString("utf8");
              if (into !== undefined && extra.some((e) => e.toLowerCase() === named.toLowerCase())) {
                const first = children(vals.content)[0];
                if (first !== undefined) into[named.toLowerCase()] = first.content.toString("utf8");
              }
              if (named.toLowerCase() !== groupAttribute.toLowerCase()) continue;
              for (const v of children(vals.content)) {
                const dn = v.content.toString("utf8");
                const key = dn.toLowerCase();
                if (dn === "" || found.has(key) || found.size >= MAX_GROUPS) continue;
                const name = nameOf(dn);
                if (name === undefined) continue;
                found.set(key, name);
                pending.push(dn);
              }
            }
          } else if (op.tag === 0x65 && sids !== undefined) {
            // The next identifier, or the end: an identifier the directory
            // does not hold is passed over, its group being unknown here.
            const next = identifiers.shift();
            if (next !== undefined) { searchSid(next); continue; }
            socket.write(tlv(0x30, Buffer.concat([small(0x02, message + 1), tlv(0x42, Buffer.alloc(0))])));
            return finish(() => resolve(named));
          } else if (op.tag === 0x65) {
            // SearchResultDone: the next group, or the end.
            if (body[0].content[0] !== 0) return finish(() => reject(new Unreachable(`the domain controller refused to read an entry`)));
            const next = pending.shift();
            if (next !== undefined) { searchGroupsOf(next); continue; }
            socket.write(tlv(0x30, Buffer.concat([small(0x02, message + 1), tlv(0x42, Buffer.alloc(0))])));
            return finish(() => resolve([...found.values()]));
          } else {
            return finish(() => reject(new Unreachable(`the domain controller answered with an unexpected operation`)));
          }
        }
      } catch (e) {
        finish(() => reject(new Unreachable((e as Error).message)));
      }
    });
  });
}

/**
 * One entry, found beneath the base by an equality match on one attribute, with the
 * attributes asked for. Returns the first entry's distinguished name and the values
 * found, or undefined where nothing matched.
 *
 * This is for resolving a **protocol identity** to a principal — the uid of an
 * `AUTH_SYS` request by `uidNumber`, a gid by `gidNumber`, an S3 access key by its
 * identifier, a client certificate by its fingerprint — which §8 of the controller's
 * `DESIGN-admin.md` asks of a CDMI server and which the draft is silent about. It is
 * deliberately a separate conversation from `ldapGroups` rather than a third mode of
 * it: that function is a state machine over two modes already, and the thing wanted
 * here is one search. Where the groups of what is found are wanted too, the caller
 * runs `ldapGroups` over the name this returns, which is what it is for.
 */
function ldapFind(dc: DomainControllerConfig, attribute: string, value: string,
  wanted: string[]): Promise<{ dn: string; values: Record<string, string[]> } | undefined> {
  const u = new URL(dc.ldap);
  const host = u.hostname.replace(/^\[|\]$/g, "");
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = (f: () => void) => { if (!done) { done = true; f(); socket.end(); } };
    const socket = tlsConnect({ host, port: Number(u.port || 636), ...anchoredBy(dc.ca),
      ...(isIP(host) ? {} : { servername: host }) } as never, () => {
      if (!enforcePin(socket as never, dc.ca)) return;
      // The search identity of the configuration, as every other search here binds:
      // a directory that admits no anonymous search needs one, and a protocol
      // identity carries no credential of its own to bind with — that is the whole
      // difficulty of resolving one, and §8's point.
      socket.write(tlv(0x30, Buffer.concat([small(0x02, 1),
        tlv(0x60, Buffer.concat([small(0x02, 3), octets(dc.searchDn ?? ""),
          octets(dc.searchPassword ?? "", 0x80)]))])));
    });
    socket.setTimeout(dc.timeoutMs, () => finish(() =>
      reject(new Unreachable(`the domain controller at ${dc.ldap} did not answer in time`))));
    socket.on("error", (e: Error) => finish(() =>
      reject(new Unreachable(`the domain controller at ${dc.ldap} cannot be reached: ${e.message}`))));
    let buffer = Buffer.alloc(0);
    let found: { dn: string; values: Record<string, string[]> } | undefined;
    socket.on("data", (d: Buffer) => {
      buffer = Buffer.concat([buffer, d]);
      try {
        for (;;) {
          const m = readTlv(buffer, 0);
          if (m === undefined) return;
          if (m.next < 0) throw new Error("a malformed LDAP message");
          buffer = buffer.subarray(m.next);
          const [, op] = children(m.content);
          const body = children(op.content);
          if (op.tag === 0x61) {
            // BindResponse. **A refusal is not "not found".** This returned undefined
            // for a refused bind, with a comment saying that a controller which will
            // not say is the same as a number naming nothing — and the caller treats
            // undefined as "stay anonymous", which is the one thing the draft's rule
            // forbids: "Where the directory or other service that resolves the
            // credentials of a request cannot be reached, the CDMI server shall report
            // the authentication unavailable condition. It shall not resolve the
            // credentials by any other means, and shall not perform the request as the
            // anonymous principal" (revision 282; ECR-129B, and
            // `authenticationUnavailable` above). A directory that will not let this
            // server search is a directory that cannot resolve the identity, and
            // falling back to anonymous would be performing the request as anonymous.
            //
            // It was caught by the search being refused with insufficientAccessRights
            // for want of a bound identity, and the resolution reporting "no principal"
            // rather than saying so.
            if (body[0].content[0] !== 0) {
              return finish(() => reject(new Unreachable(
                `the domain controller would not accept this server's search identity ` +
                `(bind result ${body[0].content[0]}), so ${attribute} cannot be resolved`)));
            }
            socket.write(tlv(0x30, Buffer.concat([small(0x02, 2), tlv(0x63, Buffer.concat([
              octets(dc.base), small(0x0a, 2), small(0x0a, 0),
              // One entry: a POSIX number is unique in the realm, and a second would
              // be a directory this server cannot resolve an identity against anyway.
              small(0x02, 1), small(0x02, 0), tlv(0x01, Buffer.from([0])),
              tlv(0xa3, Buffer.concat([octets(attribute), octets(value)])),
              tlv(0x30, Buffer.concat(wanted.map((w) => octets(w)))),
            ]))])));
          } else if (op.tag === 0x64) {
            const values: Record<string, string[]> = {};
            for (const attr of children(body[1].content)) {
              const [type, vals] = children(attr.content);
              values[type.content.toString("utf8").toLowerCase()] =
                children(vals.content).map((v) => v.content.toString("utf8"));
            }
            if (found === undefined) found = { dn: body[0].content.toString("utf8"), values };
          } else if (op.tag === 0x65) {
            // SearchResultDone. A sizeLimitExceeded (4) is success for this search:
            // one entry was asked for and the directory had more to give.
            const code = body[0].content[0];
            if (code !== 0 && code !== 4) {
              // Also not "not found": a refused search is a directory that cannot
              // resolve the identity, which is the authentication-unavailable
              // condition and not an anonymous request.
              return finish(() => reject(new Unreachable(
                `the domain controller refused a search by ${attribute} (result ${code})`)));
            }
            socket.write(tlv(0x30, Buffer.concat([small(0x02, 3), tlv(0x42, Buffer.alloc(0))])));
            return finish(() => resolve(found));
          } else {
            return finish(() => reject(new Unreachable(
              "the domain controller answered with an unexpected operation")));
          }
        }
      } catch (e) {
        finish(() => reject(new Unreachable((e as Error).message)));
      }
    });
  });
}

// --- tokens ------------------------------------------------------------------

/** A JSON document over HTTPS, trusting the controller's authority. */
function getJson(uri: string, dc: DomainControllerConfig): Promise<unknown> {
  const u = new URL(uri);
  const host = u.hostname.replace(/^\[|\]$/g, "");
  return new Promise((resolve, reject) => {
    const req = httpsRequest({ hostname: host, port: Number(u.port || 443), path: `${u.pathname}${u.search}`, method: "GET",
      ...anchoredBy(dc.ca), timeout: dc.timeoutMs,
      ...(isIP(host) ? {} : { servername: host }) } as never, (res: never) => {
      const r = res as { statusCode: number; on: (e: string, f: (d?: Buffer) => void) => void };
      const chunks: Buffer[] = [];
      r.on("data", (d) => chunks.push(d!));
      r.on("end", () => {
        if (r.statusCode !== 200) return reject(new Unreachable(`${uri} answered ${r.statusCode}`));
        try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); } catch { reject(new Unreachable(`${uri} is not JSON`)); }
      });
    });
    req.on("timeout", () => req.destroy());
    req.on("error", (e: Error) => reject(new Unreachable(`${uri} cannot be reached: ${e.message}`)));
    req.end();
  });
}

/** Whether a typ names application/at+jwt, "at+jwt" and case aside (RFC 9068 section 2.1). */
const isAccessTokenType = (t: unknown) => typeof t === "string" && ["at+jwt", "application/at+jwt"].includes(t.toLowerCase());

// --- the controller ------------------------------------------------------------

export class DomainController {
  readonly config: DomainControllerConfig;
  private readonly privileges: (groups: string[]) => string[];
  private readonly cache = new Map<string, { principal: Principal; until: number; scopes?: string[] }>();
  private keys: { jwks: Jwk[]; fetched: number } | undefined;
  /** The authenticators seen, so that one is not accepted twice (RFC 4120 section 5.5.1). */
  private readonly replays = new ReplayCache();
  /** The ticket this server holds for the directory's own service, while it lasts. */
  private serviceTicket: { ticket: Buffer; sessionKey: Buffer; endtime: number } | undefined;
  private readonly now: () => number;

  constructor(config: DomainControllerConfig, privileges: (groups: string[]) => string[], now: () => number = Date.now) {
    this.config = config;
    this.privileges = privileges;
    this.now = now;
  }

  /**
   * A name with the controller's realm. A name already carrying a realm is a
   * principal of another realm the controller trusts, named so by the
   * controller in a token it issued by exchange (PLAN-dcd.md, phase 5), and is
   * kept: the controller's own users have no "@" in their names, so none of
   * them can present one.
   */
  private qualify = (name: string) => (name.includes("@") ? name : `${name}@${this.config.realm}`);

  private principal(name: string, groups: string[], token?: string,
    attributes?: Record<string, string>): Principal {
    const qualified = groups.map(this.qualify);
    return { name: this.qualify(name), groups: qualified, administrator: false, privileges: this.privileges(qualified),
      ...(token === undefined ? {} : { token }),
      // What the directory holds of the principal, which fills the
      // description of it (revision 302).
      ...(attributes === undefined || Object.keys(attributes).length === 0 ? {} : { attributes }) };
  }

  /**
   * The principal an `AUTH_SYS` identity resolves to at this controller: the uid by
   * `uidNumber` and each gid by `gidNumber`, so that an NFS identity and a CDMI
   * identity are one principal (§8 of the controller's `DESIGN-admin.md`).
   *
   * **Where no principal has that number this returns undefined**, and the caller
   * stays anonymous rather than inventing a name. That is the whole of the change it
   * is part of: an NFS server mapping credentials used to synthesise
   * `` `${uid}@${domain}` `` and call uid 0 an administrator, and an `AUTH_SYS`
   * credential is *asserted by the client and authenticated by nothing* — so an
   * unauthenticated claim of uid 0 conferred administrative status. A resolved
   * principal holds the privileges of its groups and nothing more, and a uid the
   * directory does not know resolves to no one.
   *
   * The CDMI draft says nothing about how a CDMI server maps a protocol identity to a
   * principal, which §8 records as an ECR candidate in its own right. What this does
   * is the only mapping the directory makes possible: the numbers RFC 2307 defines
   * for exactly this purpose, served by a controller whose directory is a store. A
   * controller whose directory is its configuration has no such numbers and resolves
   * nothing, which is reported as not found rather than as a failure.
   *
   * Cached, because an NFS compound would otherwise be two directory round trips.
   * The cache is this controller's own and keyed by the whole identity: a client that
   * changes its supplementary groups is a different identity and is resolved again.
   */
  async fromPosix(uid: number, gids: number[]): Promise<Principal | undefined> {
    const key = `posix\u0000${uid}\u0000${[...gids].sort((a, b) => a - b).join(",")}`;
    const kept = this.cache.get(key);
    if (kept !== undefined && kept.until > this.now()) return kept.principal;
    let resolved: Principal | undefined;
    try {
      const entry = await ldapFind(this.config, "uidNumber", String(uid), ["uid", "cn"]);
      if (entry === undefined) return undefined;
      // `uid` is RFC 2307's name for it and what the controller serves; `cn` is the
      // fallback for a directory that names the entry differently.
      const name = entry.values.uid?.[0] ?? entry.values.cn?.[0];
      if (name === undefined) return undefined;
      // The groups the principal belongs to, walked from its own entry as every other
      // resolution here does, and the groups its supplementary gids name. Both,
      // because the two say different things: the directory knows what the principal
      // is a member of, and the client says which of its groups this request is made
      // under. A gid naming no group of the realm contributes nothing, as a uid
      // naming no principal resolves to no one.
      const byMembership = (await ldapGroups(this.config, this.config.searchDn ?? "",
        this.config.searchPassword ?? "", entry.dn)) ?? [];
      const byNumber: string[] = [];
      for (const gid of new Set(gids)) {
        const group = await ldapFind(this.config, "gidNumber", String(gid), ["cn"]);
        const named = group?.values.cn?.[0];
        if (named !== undefined) byNumber.push(named);
      }
      resolved = this.principal(name, [...new Set([...byMembership, ...byNumber])], undefined, {});
    } catch (e) {
      if (e instanceof Unreachable) throw authenticationUnavailable(e.message);
      throw e;
    }
    this.cache.set(key, { principal: resolved, until: this.now() + this.config.cacheSeconds * 1000 });
    return resolved;
  }

  /**
   * The principal a request's credentials resolve to at this controller.
   * Credentials of a method the domain does not enable, and credentials the
   * controller does not accept, are the unauthenticated condition, as the
   * domains clause requires; none presented is the anonymous principal.
   */
  async authenticate(authorization: string | undefined, methods: string[] | undefined): Promise<Principal> {
    return (await this.accept(authorization, methods)).principal;
  }

  /**
   * The same, with the answer a client that asked for mutual authentication is
   * owed, which the binding returns in WWW-Authenticate (RFC 4559).
   */
  async accept(authorization: string | undefined, methods: string[] | undefined):
    Promise<{ principal: Principal; negotiate?: string; scopes?: string[] }> {
    if (!authorization) return { principal: { name: "ANONYMOUS@", groups: [], administrator: false, privileges: [] } };
    const [scheme, credentials] = authorization.split(" ");
    const method = (scheme ?? "").toLowerCase();
    const offered = ["basic",
      ...(this.config.issuer === undefined ? [] : ["bearer"]),
      ...(this.config.serviceKey === undefined ? [] : ["negotiate"])];
    const enabled = methods ?? offered;
    const challenge = offered.filter((m) => enabled.includes(m)).map((m) => m.charAt(0).toUpperCase() + m.slice(1));
    if (!enabled.includes(method) || !offered.includes(method) || !credentials) {
      throw unauthenticated(`this domain resolves ${challenge.join(" and ") || "no"} credentials at its domain controller`, challenge);
    }
    // A ticket is used once, its authenticator being refused a second time, so
    // a Negotiate credential is never kept.
    if (method === "negotiate") return this.fromTicket(credentials, challenge);
    const key = createHash("sha256").update(`${this.config.ldap}\u0000${authorization}`).digest("base64");
    const kept = this.cache.get(key);
    if (kept !== undefined && kept.until > this.now()) {
      return { principal: kept.principal, ...(kept.scopes === undefined ? {} : { scopes: kept.scopes }) };
    }
    let resolved: { principal: Principal; scopes?: string[] } | undefined;
    try {
      resolved = method === "basic"
        ? await this.fromPassword(credentials).then((p) => (p === undefined ? undefined : { principal: p }))
        : await this.fromToken(credentials);
    } catch (e) {
      if (e instanceof Unreachable) throw authenticationUnavailable(e.message);
      throw e;
    }
    if (resolved === undefined) throw unauthenticated("the credentials presented are not accepted by the domain's controller", challenge);
    // The scopes travel with the principal, and are cached with it: a token
    // resolved from the cache carries the scopes it carried when it was first
    // resolved, which are the scopes of that token and of no other.
    this.cache.set(key, { principal: resolved.principal, until: this.now() + this.config.cacheSeconds * 1000,
      ...(resolved.scopes === undefined ? {} : { scopes: resolved.scopes }) });
    return { principal: resolved.principal, ...(resolved.scopes === undefined ? {} : { scopes: resolved.scopes }) };
  }

  /**
   * A Kerberos ticket presented by the Negotiate scheme: verified with this
   * server's service key, and the principal named as the realm names it.
   *
   * The groups are read from the directory by a search of the principal's own
   * entry, made anonymously: a ticket carries no password to bind with, and the
   * bind as the service principal that the draft provides for needs the SASL
   * mechanism of RFC 4752, which is phase 7 of PLAN-auth.md. Where the
   * directory does not answer such a search, the principal has no groups here.
   */
  private async fromTicket(credentials: string, challenge: string[]): Promise<{ principal: Principal; negotiate?: string }> {
    const parts = (this.config.servicePrincipal ?? "").split("/");
    let accepted;
    try {
      accepted = acceptNegotiate(credentials, {
        key: this.config.serviceKey!, etype: this.config.serviceEtype ?? 18,
        ...(parts[0] === "" ? {} : { names: [parts] }),
      }, this.replays, this.now());
    } catch (e) {
      if (e instanceof KrbError) {
        throw unauthenticated(`the ticket presented is not accepted: ${e.code}`, challenge);
      }
      throw e;
    }
    // A ticket of another realm is named by that realm, and reaching a
    // principal of it needs the trust of a realm this server is told about;
    // until then such a ticket is not accepted rather than named as this realm's.
    if (accepted.verified.crealm !== this.config.realm) {
      throw unauthenticated(`the ticket is of the realm ${accepted.verified.crealm}, which this domain does not accept`, challenge);
    }
    const name = accepted.verified.cname.parts.join("/");
    let groups: string[] = [];
    const attributes: Record<string, string> = {};
    // The groups are read by binding as this server's own service principal,
    // by the SASL mechanism of RFC 4752, which is what the draft provides for;
    // by the search account where one is configured instead; and otherwise by
    // an anonymous search, which many directories refuse. Where none answers,
    // the principal is authenticated and has no groups here.
    const searchDn = this.entryOf(name);
    // "The PAC was created to provide this authorization data for Kerberos
    // Protocol Extensions" ([MS-PAC]; PLAN-auth.md, phase 5): where the ticket
    // carries one, verified with this server's own key, the groups come from
    // it and the directory is searched only to name them. The signature is
    // the realm's word for the groups; an unverifiable one is refused rather
    // than ignored, "The signature of a PAC prevents elevation of privilege
    // attacks."
    let pac;
    try {
      pac = groupsFromPac(accepted.verified.ticket.authorizationData, this.config.serviceKey!);
    } catch (e) {
      throw unauthenticated(`the ticket's privilege attribute certificate is not accepted: ${(e as Error).message}`,
        challenge);
    }
    if (pac !== undefined) {
      try {
        groups = (await this.namesOfSids(pac.sids)) ?? [];
      } catch (e) {
        if (e instanceof Unreachable) throw authenticationUnavailable(e.message);
        throw e;
      }
      return {
        principal: this.principal(name, groups, undefined, {}),
        ...(accepted.answer === undefined ? {} : { negotiate: accepted.answer }),
      };
    }
    const byService = this.config.searchDn === undefined && this.config.serviceKey !== undefined &&
      (this.config.kdc !== undefined || (this.config.kdcs?.length ?? 0) > 0);
    try {
      groups = (byService
        ? await this.groupsAsService(searchDn, attributes)
        : await ldapGroups(this.config, this.config.searchDn ?? "", this.config.searchPassword ?? "", searchDn,
          undefined, attributesWanted(this.config), attributes)) ?? [];
    } catch (e) {
      // "Where no server of the directory can be reached when a CDMI server
      // requires an LDAP search ... the CDMI server shall not authenticate the
      // principal by any other means" (revision 298), and the same of a key
      // distribution centre: the failure is reported rather than taken as a
      // principal with no groups, which it was before 0.64.
      if (e instanceof Unreachable) throw authenticationUnavailable(e.message);
      if (e instanceof Condition) throw e;
      groups = [];
    }
    const principal = this.principal(name, groups, undefined, attributes);
    return { principal, ...(accepted.answer === undefined ? {} : { negotiate: accepted.answer }) };
  }

  /**
   * The groups of a principal, read by binding to the directory as this
   * server's own service principal: a ticket for the directory's service is
   * obtained from the realm's key distribution centre, and presented by the
   * GSSAPI mechanism. The ticket is kept until it expires, one being enough
   * for every search this server makes.
   */
  /**
   * The names of the groups a certificate names by security identifier, read
   * from the directory: each is searched for by its objectSid, and one the
   * directory does not hold is passed over, its name being unknown here.
   */
  private async namesOfSids(sids: string[]): Promise<string[] | undefined> {
    if (sids.length === 0) return [];
    if (this.config.searchDn !== undefined) {
      return ldapGroups(this.config, this.config.searchDn, this.config.searchPassword ?? "", this.config.searchDn,
        undefined, [], undefined, sids);
    }
    const gssapi = await this.serviceBind();
    return ldapGroups(this.config, "", "", this.config.base, gssapi, [], undefined, sids);
  }

  /** A ticket for the directory's own service, held while it lasts. */
  private async serviceBind(): Promise<{ ticket: Buffer; sessionKey: Buffer; service: PrincipalName }> {
    const host = new URL(this.config.ldap).hostname.replace(/^\[|\]$/g, "");
    const service: PrincipalName = { type: 3, parts: ["ldap", host] };
    await this.obtainServiceTicket(service);
    return { ticket: this.serviceTicket!.ticket, sessionKey: this.serviceTicket!.sessionKey, service };
  }

  private async groupsAsService(searchDn: string, attributes?: Record<string, string>): Promise<string[] | undefined> {
    const host = new URL(this.config.ldap).hostname.replace(/^\[|\]$/g, "");
    const service: PrincipalName = { type: 3, parts: ["ldap", host] };
    await this.obtainServiceTicket(service);
    return ldapGroups(this.config, "", "", searchDn,
      { ticket: this.serviceTicket!.ticket, sessionKey: this.serviceTicket!.sessionKey, service },
      attributesWanted(this.config), attributes);
  }

  /**
   * The credentials a Kerberos service ticket presented to an S3 export
   * gives. The ticket is decrypted with this server's service key, its
   * validity period and realm are checked, and the session key is the secret
   * access key: "The session key of a ticket is shared by the principal and
   * the service principal the ticket is issued for, as Kerberos provides, and
   * is not a secret of the principal; a CDMI server recovers it from the
   * ticket for each request" (revision 282). No authenticator is presented
   * here, the signature of the request taking its place, so the replay cache
   * does not apply.
   */
  async fromS3Token(token: string): Promise<{ secret: Buffer; principal: Principal }> {
    if (this.config.serviceKey === undefined) {
      throw new Error("this server holds no key for its service principal in the realm");
    }
    const ticket = ticketPartsOf(Buffer.from(token, "base64"));
    if (ticket.realm !== this.config.realm) {
      throw new Error(`the ticket was issued in ${ticket.realm} and not in ${this.config.realm}`);
    }
    const part = readEncTicketPart(decryptKrb(this.config.serviceKey, USAGE.ticket, ticket.cipher));
    void 0;
    const now = this.now();
    if (now < (part.starttime ?? part.authtime) - 300_000 || now > part.endtime) {
      throw new Error("the ticket is not within its validity period");
    }
    if (part.crealm !== this.config.realm) {
      throw new Error(`the client of the ticket is of ${part.crealm} and not of ${this.config.realm}`);
    }
    const name = part.cname.parts.join("/");
    // The groups of the certificate, where the ticket carries one; a ticket
    // without one gives the principal and no groups here, the directory not
    // being searched for a request of this kind.
    const pac = groupsFromPac(part.authorizationData, this.config.serviceKey);
    const groups = pac === undefined ? [] : (await this.namesOfSids(pac.sids)) ?? [];
    return { secret: part.key.value, principal: this.principal(name, groups, undefined, {}) };
  }

  /** Obtains a ticket for a service of the realm, and holds it while it lasts. */
  private async obtainServiceTicket(service: PrincipalName): Promise<void> {
    if (this.serviceTicket === undefined || this.serviceTicket.endtime - this.now() < 60_000) {
      const client: PrincipalName = { type: 3, parts: (this.config.servicePrincipal ?? "").split("/") };
      // "The key distribution centres of the realm ... which a CDMI server
      // tries in the order given" (revision 298; ECR-142B), and the one this
      // server's own configuration names where the directory names none.
      const centres = this.config.kdcs !== undefined && this.config.kdcs.length > 0
        ? this.config.kdcs
        : this.config.kdc === undefined ? [] : [this.config.kdc];
      let last: Error | undefined;
      for (const at of centres) {
        try {
          this.serviceTicket = await serviceTicket(at, this.config.realm, client, service,
            this.config.serviceKey!, this.config.timeoutMs);
          last = undefined;
          break;
        } catch (e) {
          last = e as Error;
        }
      }
      // "A CDMI server shall report the authentication unavailable condition
      // where it cannot reach a key distribution centre of the realm."
      if (this.serviceTicket === undefined) {
        throw authenticationUnavailable(centres.length === 0
          ? `the realm ${this.config.realm} names no key distribution centre, and none is configured here`
          : `no key distribution centre of ${this.config.realm} answered: ${last?.message ?? "none was tried"}`);
      }
    }
  }

  /**
   * The entry of a principal: the attribute the directory names, the name,
   * and the base beneath which the directory is searched. A directory whose
   * entries are not immediately beneath an organizational unit of people is
   * served by naming its attribute and its base accordingly.
   */
  private entryOf(name: string): string {
    const attribute = this.config.principalAttribute ?? "uid";
    return `${attribute}=${name},ou=people,${this.config.base}`;
  }

  private async fromPassword(encoded: string): Promise<Principal | undefined> {
    const decoded = Buffer.from(encoded, "base64").toString("utf8");
    const cut = decoded.indexOf(":");
    if (cut < 0) return undefined;
    const name = decoded.slice(0, cut), password = decoded.slice(cut + 1);
    // A name the controller's directory could hold, and never an empty password,
    // which LDAP would take as an unauthenticated bind (RFC 4513 section 5.1.2).
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(name) || password === "") return undefined;
    const attributes: Record<string, string> = {};
    const groups = await ldapGroups(this.config, this.entryOf(name), password, undefined, undefined,
      attributesWanted(this.config), attributes);
    return groups === undefined ? undefined : this.principal(name, groups, undefined, attributes);
  }

  /** The controller's keys: its metadata's issuer checked, then its JWK Set. */
  private async jwks(refresh: boolean): Promise<Jwk[]> {
    if (this.keys !== undefined && !(refresh && this.now() - this.keys.fetched > 30_000)) return this.keys.jwks;
    const issuer = this.config.issuer!;
    const meta = await getJson(`${issuer.replace(/\/$/, "")}/.well-known/oauth-authorization-server`, this.config) as Record<string, unknown>;
    // "The issuer value returned MUST be identical to the authorization server's
    // issuer identifier value into which the well-known URI string was inserted"
    // (RFC 8414 section 3.3).
    if (meta.issuer !== issuer || typeof meta.jwks_uri !== "string") {
      throw new Unreachable(`the metadata of ${issuer} names another issuer, or no JWK Set`);
    }
    const set = await getJson(meta.jwks_uri, this.config) as { keys?: Jwk[] };
    this.keys = { jwks: Array.isArray(set.keys) ? set.keys : [], fetched: this.now() };
    return this.keys.jwks;
  }

  private async fromToken(token: string): Promise<{ principal: Principal; scopes: string[] } | undefined> {
    const parts = token.split(".");
    if (parts.length !== 3) return undefined;
    let header: Record<string, unknown>;
    try { header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")); } catch { return undefined; }
    if (!isAccessTokenType(header.typ) || (header.alg !== "RS256" && header.alg !== "ES256")) return undefined;
    // The key by its kid; the set fetched again, at most every thirty seconds, for a kid not yet seen.
    let key = (await this.jwks(false)).find((k) => k.kid === header.kid);
    if (key === undefined) key = (await this.jwks(true)).find((k) => k.kid === header.kid);
    if (key === undefined) return undefined;
    let claims: Record<string, unknown>;
    try {
      claims = JSON.parse(verifyJws(token, importJwk(key), { alg: header.alg as string }).payload.toString("utf8"));
    } catch {
      return undefined;
    }
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (claims.iss !== this.config.issuer || !aud.includes(this.config.audience) || typeof claims.sub !== "string" ||
        typeof claims.exp !== "number" || claims.exp * 1000 <= this.now()) {
      return undefined;
    }
    // "A CDMI server ... takes the principal from the claim the principal_claim
    // member of the cdmi_domain_auth metadata item names", and "where this
    // member is absent, a CDMI server resolves no principal from a bearer
    // token". A descriptor configured by this server's own [[domain_controller]]
    // table names no claim and is answered as it always was, from "sub".
    const claim = this.config.principalClaim;
    if (this.config.fromDescriptor === true && claim === undefined) return undefined;
    const named = claim === undefined ? claims.sub : claims[claim];
    if (typeof named !== "string" || named === "") return undefined;
    // "takes the groups of that principal from the claim the groups_claim
    // member names, where the descriptor carries that member, and from the
    // directory where it does not."
    const held = this.config.groupsClaim === undefined ? claims.groups : claims[this.config.groupsClaim];
    const groups = Array.isArray(held) ? held.filter((g): g is string => typeof g === "string") : [];
    // The scopes of the token, space-delimited as RFC 6749 requires. Nothing
    // read them before 0.86: the binding cast the result of this method to a
    // shape carrying scopes, the cast succeeded because the property was
    // merely absent, and every call arrived with an empty set. With
    // [mcp].scopes_required set, that refused every tool call of every token,
    // however the token was scoped.
    return { principal: this.principal(named, groups, token), scopes: scopesOfClaims(claims) };
  }
}

/** The domain controllers of the configuration, the nearest serving a domain found for it. */
export class DomainControllers {
  private readonly list: DomainController[];
  constructor(list: DomainController[]) {
    // The longest path first, so that a sub-domain naming its own controller is served by it.
    this.list = [...list].sort((a, b) => b.config.domain.length - a.config.domain.length);
  }
  /** The controller serving a domain, by its namespace path, or undefined where none does. */
  /** Every controller configured, in the order they are consulted. */
  all(): DomainController[] {
    return [...this.list];
  }

  for(domainPath: string): DomainController | undefined {
    const at = domainPath.endsWith("/") ? domainPath : `${domainPath}/`;
    return this.list.find((dc) => at.startsWith(dc.config.domain));
  }
}
