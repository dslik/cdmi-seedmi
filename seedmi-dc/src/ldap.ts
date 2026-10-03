// LDAP: a subset of RFC 4511, over TLS from the first octet (LDAPS), by which a
// CDMI server verifies a password and reads a user's groups.
//
// The directory as LDAP presents it, from the realm's DNS domain:
//
//   dc=eu,dc=example                      the base
//   ou=people,dc=eu,dc=example
//   uid=alice,ou=people,dc=eu,dc=example  a user: uid, cn, sn, memberOf
//   ou=groups,dc=eu,dc=example
//   cn=staff,ou=groups,dc=eu,dc=example   a group: cn, member
//
// memberOf holds every group the user belongs to, nesting followed, so that a
// server needs one search; member holds a group's direct members.
//
// memberOf is not defined by RFC 4519 or any LDAP RFC: it is the convention of
// several directories for the groups an entry belongs to, given here so that a
// CDMI server finds a user's groups in one search.
//
// Taken: a simple bind (RFC 4513 section 5.1), an anonymous bind, a search
// under the base by a session that has bound, its filter evaluated by RFC 4511's
// three-valued logic (and/or/not, equality, presence; other items, and types not
// recognized, Undefined), unbind, abandon. Refused as RFC 4511 says: a write operation (unwillingToPerform),
// an extended operation it does not know (protocolError), a SASL bind
// (authMethodNotSupported), a critical control (unavailableCriticalExtension),
// and a message it cannot read (a Notice of Disconnection, and the connection closed).

import { ReplayCache } from "./krb-ticket.ts";
import { acceptNegotiate, unwrapToken, wrapToken } from "./krb-negotiate.ts";
import type { Etype } from "./krb-crypto.ts";
import type { Directory } from "./dc-directory.ts";
import { Throttle } from "./throttle.ts";
import { beneath, parseDn, type Rdn, sameDn, sameDnString, subjectOfCertificate } from "./dn.ts";
import { prepare } from "./prepare.ts";
import {
  APPLICATION, BerError, boolean, children, CONSTRUCTED, CONTEXT, type Element, Incomplete, int, integer, octets,
  readElement, seq, T, text,
} from "./ber.ts";

/** The result codes used (RFC 4511 section 4.1.9). */
/**
 * The four octets this server offers under GSS_Wrap in a GSSAPI bind: the
 * layers it supports, and the largest token it will receive, which "MUST be 0
 * if the server does not support any security layer" (RFC 4752 section 3.2).
 */
const NO_SECURITY_LAYER = 1;
const OFFER = Buffer.from([NO_SECURITY_LAYER, 0, 0, 0]);

export const RESULT = {
  success: 0, operationsError: 1, protocolError: 2, sizeLimitExceeded: 4,
  authMethodNotSupported: 7, unavailableCriticalExtension: 12,
  noSuchObject: 32, invalidCredentials: 49, insufficientAccessRights: 50, unwillingToPerform: 53,
  // "confidentialityRequired": what this server answers an operation that would
  // carry a credential or a directory entry over a connection with no TLS layer.
  confidentialityRequired: 13,
  // Compare answers with one of these two rather than with success (RFC 4511 §4.10).
  compareFalse: 5, compareTrue: 6,
  saslBindInProgress: 14,
  // The codes a write is refused with, so that a client can act on the failure
  // rather than retry it (RFC 4511 section A.2; DESIGN-admin.md §6).
  noSuchAttribute: 16, undefinedAttributeType: 17, invalidAttributeSyntax: 21, noSuchObjectClass: 65,
  constraintViolation: 19, entryAlreadyExists: 68, objectClassViolation: 65,
  notAllowedOnNonLeaf: 66, notAllowedOnRDN: 67, invalidDNSyntax: 34,
  inappropriateAuthentication: 48, unavailable: 52, other: 80,
} as const;

/**
 * What the session records itself as when it is bound by a certificate. An
 * administrator is not a principal of the directory, so its name is kept in a
 * space of its own: no search, no bind and no membership can name it, and a
 * principal cannot be given a name that collides with it, "dn:" being a prefix
 * no name of this realm admits.
 */
const ADMIN_PREFIX = "dn:";

/** The protocol operations, by their tags. */
const OP = {
  bindRequest: APPLICATION | CONSTRUCTED | 0, bindResponse: APPLICATION | CONSTRUCTED | 1,
  unbindRequest: APPLICATION | 2, searchRequest: APPLICATION | CONSTRUCTED | 3,
  searchResultEntry: APPLICATION | CONSTRUCTED | 4, searchResultDone: APPLICATION | CONSTRUCTED | 5,
  compareResponse: APPLICATION | CONSTRUCTED | 15,
  abandonRequest: APPLICATION | 16, extendedRequest: APPLICATION | CONSTRUCTED | 23,
  extendedResponse: APPLICATION | CONSTRUCTED | 24,
};
/** A write operation's request tag, and the response it is answered with. */
const WRITES: Record<number, number> = {
  [APPLICATION | CONSTRUCTED | 6]: APPLICATION | CONSTRUCTED | 7,   // modify
  [APPLICATION | CONSTRUCTED | 8]: APPLICATION | CONSTRUCTED | 9,   // add
  [APPLICATION | 10]: APPLICATION | CONSTRUCTED | 11,               // delete
  [APPLICATION | CONSTRUCTED | 12]: APPLICATION | CONSTRUCTED | 13, // modify DN
  [APPLICATION | CONSTRUCTED | 14]: APPLICATION | CONSTRUCTED | 15, // compare
};
/** The request tags of the four write operations, named. */
const ADD = APPLICATION | CONSTRUCTED | 8;
const DELETE = APPLICATION | 10;
const MODIFY = APPLICATION | CONSTRUCTED | 6;
const MODIFY_DN = APPLICATION | CONSTRUCTED | 12;
const COMPARE = APPLICATION | CONSTRUCTED | 14;
/** The Notice of Disconnection's name (RFC 4511 section 4.4.1). */
const NOTICE_OF_DISCONNECTION = "1.3.6.1.4.1.1466.20036";
/** Password Modify (RFC 3062), by which every LDAP client changes a password. */
export const PASSWORD_MODIFY = "1.3.6.1.4.1.4203.1.11.1";
/** "Who am I?" (RFC 4532). */
export const WHO_AM_I = "1.3.6.1.4.1.4203.1.11.3";

/**
 * StartTLS (RFC 4511 §4.14): "The requestName is '1.3.6.1.4.1.1466.20037', and the
 * requestValue field is always absent."
 *
 * This server listens on LDAPS and that was all, which RFC 4513 §2 does not allow:
 * "LDAP implementations that support any authentication mechanism other than the
 * anonymous authentication mechanism of the simple Bind method MUST support the
 * name/password authentication mechanism of the simple Bind method (Section 5.1.3)
 * and MUST be capable of protecting this name/password authentication using TLS as
 * established by the StartTLS operation (Section 3)." A client configured for
 * StartTLS on the cleartext port — the default for most tooling — got
 * `protocolError` and could not discover why. NOTES-on-ldap.md §9d recorded it as
 * an unmet MUST; this is it met.
 */
export const START_TLS = "1.3.6.1.4.1.1466.20037";

/** The largest message read; a larger one is refused and the connection closed. */
export const MAX_MESSAGE = 1 << 20;

// --- names -------------------------------------------------------------------

/**
 * Whether two certificate subjects are the same. Both are distinguished names,
 * and they are compared by RFC 4517 section 4.2.15: the same number of relative
 * distinguished names, corresponding ones **by position**, and the AVAs within one
 * in any order.
 *
 * This used to split on commas and slashes, lower-case, **sort**, and compare as a
 * set, with a comment saying "the order a library prints them in is not the
 * holder's business". That was the wrong reading — a distinguished name is a
 * sequence of RDNs; only the AVAs inside one RDN are unordered — and together with
 * a subject assembled by joining Node's certificate object with commas it let a
 * certificate the configuration does not name bind as the administrator. See
 * dn.ts, which carries the account of it.
 */
export const sameSubject = (a: string, b: string): boolean => sameDnString(a, b);

/**
 * A distinguished name whose every RDN holds exactly one AVA, which is the shape
 * of every entry this directory serves. Undefined where the string is not a
 * distinguished name at all; `"multi"` where it is one but holds a multi-valued
 * RDN, which names nothing here and is a different answer — a client gets
 * `noSuchObject` for that and `invalidDNSyntax` only for a name this server could
 * not read (RFC 4513 section 5.1.3 draws exactly that line).
 */
export function simpleDn(dn: string): [string, string][] | "multi" | undefined {
  const rdns = parseDn(dn);
  if (rdns === undefined) return undefined;
  if (rdns.some((r) => r.length !== 1)) return "multi";
  return rdns.map((r) => [r[0].type.toLowerCase(), r[0].value] as [string, string]);
}

/**
 * Where an entry of a unit lives. The organizational unit a principal is in
 * stands between its name and the container (DESIGN-admin.md §5): a principal of
 * `eng/platform` is named uid=ann,ou=platform,ou=eng,ou=people,<base>. The path is
 * written outermost last, as a distinguished name is. At module scope because
 * both `entries()`, which publishes the name, and `userOf`, which reads one back
 * on a bind, have to agree about it.
 */
const within = (path: string | undefined, container: string) =>
  path === undefined || path === ""
    ? container
    : `${path.split("/").reverse().map((p) => `ou=${p}`).join(",")},${container}`;

/** The base from a DNS domain: eu.example is dc=eu,dc=example. */
export const baseOf = (domain: string) => domain.split(".").map((l) => `dc=${l}`).join(",");

// --- entries -----------------------------------------------------------------

/**
 * One entry. A value is a sequence of octets, and only some attributes hold text:
 * a `userCertificate` carries DER, which is not UTF-8 and is corrupted by being
 * written as it. Such a value travels as a Buffer, and `octets()` sends either.
 */
interface Entry { dn: string; attrs: Record<string, (string | Buffer)[]> }

/** Attribute types whose values are distinguished names, compared as names. */
const DN_VALUED = new Set(["member", "memberof"]);

/**
 * The operational attributes this directory serves. "An attribute type that is
 * operational ... is not returned in a search unless it is requested by name"
 * (RFC 4512 section 3.4), and "+" requests all of them (RFC 4511 section
 * 4.5.1.8). They are the server's own: a client does not write them, and "*"
 * does not ask for them.
 */
const OPERATIONAL = new Set([
  // RFC 4512 section 5.1, of the root DSE.
  "namingcontexts", "supportedldapversion", "supportedsaslmechanisms", "supportedextension",
  "supportedcontrol", "supportedfeatures", "altserver",
  // RFC 4512 section 3.4 and 5.1.
  "subschemasubentry", "objectclasses", "attributetypes", "ldapsyntaxes", "matchingrules",
  // RFC 3672 section 2.3, which gives it USAGE directoryOperation.
  "subtreespecification",
  // RFC 4512 section 3.4: of an entry.
  "createtimestamp", "modifytimestamp", "entryuuid", "entrydn", "hassubordinates",
  // RFC 3045.
  "vendorname", "vendorversion",
]);

/**
 * A time as a Generalized Time of LDAP: "20260101120000Z" (RFC 4517 section
 * 3.3.13, ISO 8601's basic format). No "T" and no separators — ISO 8601's
 * extended format, which Date writes, is not what this syntax takes, and a
 * client reading one would be reading a different instant or none.
 */
const ldapTime = (when: Date): string =>
  when.toISOString().replace(/[-:]/g, "").replace(/T/, "").replace(/\.\d+Z$/, "Z");

/**
 * The supertypes of each attribute description this directory serves, for RFC
 * 4511 §4.5.1.8's "Attributes that are subtypes of listed attributes are
 * implicitly included". Read as: naming any of the values selects the key. The
 * supertypes are RFC 4519 §2's — `cn`, `sn` and `ou` are each `SUP name`, and
 * `member` is `SUP distinguishedName`.
 */
const SUBTYPES_OF: Record<string, string[]> = {
  cn: ["name"], sn: ["name"], ou: ["name"], member: ["distinguishedname"],
};

/** Where the schema of this directory is published (RFC 4512 section 4.2). */
export const SUBSCHEMA_DN = "cn=subschema";

/**
 * The operational attributes of a principal's entry: what this server knows
 * about the entry rather than what the entry says. They are served only where a
 * store records them — a directory kept in the configuration has no identifier
 * and no history — and are returned only when asked for by name or by "+".
 */
function operational(d: Directory, name: string, dn: string): Record<string, string[]> {
  const times = d.timesOf(name);
  const id = d.idOf(name);
  return {
    entryDN: [dn],
    subschemaSubentry: [SUBSCHEMA_DN],
    hasSubordinates: ["FALSE"],
    // The store's own identifier for the principal, which is what entryUUID is
    // for: a name that does not change when the entry is renamed or moved.
    ...(id === undefined ? {} : { entryUUID: [id] }),
    ...(times.created === undefined ? {} : { createTimestamp: [ldapTime(times.created)] }),
    ...(times.modified === undefined ? {} : { modifyTimestamp: [ldapTime(times.modified)] }),
  };
}

/**
 * The entries of the directory. Where direct is true, a user's memberOf holds
 * the groups it names directly, as Active Directory's does, rather than every
 * group it belongs to ([directory] memberof = "direct").
 */
function entries(d: Directory, domain: string, direct = false, domainSid = ""): Entry[] {
  const base = baseOf(domain);
  const people = `ou=people,${base}`, groups = `ou=groups,${base}`;
  const userDn = (u: string) => `uid=${u},${within(d.unitOf(u), people)}`;
  const groupDn = (g: string) => `cn=${g},${within(d.unitOf(g), groups)}`;
  const out: Entry[] = [
    { dn: base, attrs: { objectClass: ["top", "domain"], dc: [domain.split(".")[0]] } },
    { dn: people, attrs: { objectClass: ["top", "organizationalUnit"], ou: ["people"] } },
    { dn: groups, attrs: { objectClass: ["top", "organizationalUnit"], ou: ["groups"] } },
  ];
  // Each unit of the store appears beneath both containers. The store keeps one
  // unit tree and this protocol splits users from groups, so one unit is two
  // entries here; serving it beneath only the container that happens to hold
  // something would mean a client could not create the first group of a unit,
  // since an add requires its superior to exist. See the note in §5.
  for (const path of d.units()) {
    const name = path.split("/").at(-1)!;
    for (const container of [people, groups] as const) {
      const description = d.unitDescription(path);
      const dn = within(path, container);
      const times = d.unitTimes(path);
      // The UUID of **this** entry. A unit is one stored thing served as two entries,
      // and RFC 4530 §2.4 is about entries: "Servers SHALL generate and assign a new
      // UUID to each entry upon its addition to the directory and provide that UUID
      // as the value of the 'entryUUID' operational attribute. An entry's UUID is
      // immutable", each one "unique in space and time". One identifier cannot be the
      // immutable UUID of two entries — which is right, and was the reason given for
      // serving **neither**, leaving that SHALL unmet rather than half met. The store
      // keeps two (schema 7), one per entry, so both are served.
      const uuid = d.unitUuid(path, container === people ? "people" : "groups");
      out.push({
        dn,
        attrs: { objectClass: ["top", "organizationalUnit"], ou: [name],
          ...(description === undefined ? {} : { description: [description] }),
          // The unit's own operational attributes, where a store holds them.
          ...(uuid === undefined ? {} : { entryUUID: [uuid] }),
          entryDN: [dn],
          subschemaSubentry: [SUBSCHEMA_DN],
          hasSubordinates: ["TRUE"],
          ...(times.created === undefined ? {} : { createTimestamp: [ldapTime(times.created)] }),
          ...(times.modified === undefined ? {} : { modifyTimestamp: [ldapTime(times.modified)] }),
        },
      });
    }
  }
  for (const u of d.userNames()) {
    out.push({ dn: userDn(u), attrs: {
      // extensibleObject because this entry holds user attributes that none of
      // its other classes permit: sAMAccountName always, and uidNumber,
      // homeDirectory and unixHomeDirectory where there is one. RFC 4512 section
      // 4.3 is written for exactly this — "allows entries that belong to it to
      // hold any user attribute" — and "the mandatory attributes of the other
      // object classes of this entry are still required to be present", which
      // they are. Without it a client validating against the schema this server
      // publishes would find every user entry invalid.
      // posixAccount where every one of its five MUSTs can be served: it is
      // `MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory )` (RFC 2307 §3),
      // so a user needs a POSIX number, a home, and a primary group with a number
      // of its own. It is AUXILIARY, so it sits beside inetOrgPerson. Claiming it
      // without a gidNumber would publish an entry that fails the schema this
      // server publishes, which is why it was absent altogether and why
      // `(&(objectClass=posixAccount)(uidNumber=%d))` — RFC 2307 §5.2's own
      // getpwuid() filter — matched nothing in a directory that holds the numbers.
      // shadowAccount where the store has an expiry, which is the one class that
      // can carry it. RFC 2307 §4 gives it as `SUP top AUXILIARY ... MUST uid MAY (
      // ... shadowExpire ... )`, so it sits beside inetOrgPerson exactly as
      // posixAccount does and the one MUST is a name every user entry has. This
      // directory held `expires` for four releases with **no LDAP representation at
      // all** — not published, not served, not writable — so a principal given an
      // expiry over SCIM was indistinguishable over LDAP from one without. The
      // phase E conformance test is what made that visible, by being unable to
      // reach the same state through both front ends; see NOTES-on-ldap-writes.md
      // §10. The class was assumed STRUCTURAL, and therefore assumed to collide
      // with inetOrgPerson the way posixGroup collides with groupOfNames (§7 of
      // NOTES-on-ldap.md); reading RFC 2307 §4 showed it is AUXILIARY and there was
      // never a collision.
      objectClass: ["top", "person", "organizationalPerson", "inetOrgPerson",
        ...(posixAccount(d, u) ? ["posixAccount"] : []),
        ...(d.expiresOf(u) === undefined ? [] : ["shadowAccount"]), "extensibleObject"],
      ...(d.expiresOf(u) === undefined ? {} : { shadowExpire: [shadowExpire(d.expiresOf(u)!)] }),
      uid: [u], cn: [u], sn: [u],
      // memberOf holds every group where the directory reports membership
      // transitively, as this one does by default, and the groups the user names
      // directly where it is configured to report as Active Directory does
      // ([directory] memberof = "direct"), so that a client resolving membership
      // transitively can be tested (revision 282; seedmi's ECR-131B).
      // The security identifier of the principal, by which a CDMI server maps
      // the identifiers of a ticket's privilege attribute certificate back to
      // names. Active Directory holds this attribute in its binary form; this
      // directory serves the text form, which is a convention of its own and
      // is what a CDMI server searching this directory looks for.
      ...(domainSid === "" ? {} : { objectSid: [`${domainSid}-${d.ridOf(u)}`] }),
      // The home of the principal, as a directory of a UNIX deployment holds
      // it, from which a CDMI server takes it (revision 302). It is served under
      // both names: homeDirectory, which RFC 2307 section 3 defines and which a
      // UNIX client looks for, and unixHomeDirectory, which is Active Directory's
      // and has no standard definition. Serving only the second, as the first
      // version of this did, meant the standard name was absent from a directory
      // that holds the value.
      ...(d.homeOf(u) === undefined
        ? {}
        : { homeDirectory: [d.homeOf(u)!], unixHomeDirectory: [d.homeOf(u)!] }),
      // The POSIX number, where a store allocated one (DESIGN-admin.md §3): what
      // an NFS server resolves a `sys` identity by, so that a bare uid in a
      // request corresponds to a principal of this realm rather than to nothing.
      // A directory that is a configuration has no number and serves none.
      ...(d.posixOf(u) === undefined ? {} : { uidNumber: [String(d.posixOf(u))] }),
      // A user's gidNumber is its primary group's number (RFC 2307 §3), which is
      // what posixAccount MUSTs and what the store had no notion of until schema 6.
      ...(d.primaryGidOf(u) === undefined ? {} : { gidNumber: [String(d.primaryGidOf(u))] }),
      // sAMAccountName, which a Windows client asks for by that name and which
      // here is the principal's name.
      sAMAccountName: [u],
      ...(d.displayNameOf(u) === undefined ? {} : { displayName: [d.displayNameOf(u)!] }),
      // The certificates this principal may authenticate with, where the store has
      // them. RFC 4523 §2.1: "As values of this syntax contain digitally signed
      // data, values of this syntax and the form of each value MUST be preserved as
      // presented." Only a SHA-256 fingerprint was kept, so a client that wrote a
      // userCertificate and read the entry back found the attribute absent — and
      // NOTES-on-ldap.md §5 recorded that as a choice rather than the violation it
      // is. A certificate recorded as a fingerprint alone (an import, or the SCIM
      // extension's own attribute) still has none to serve, which is now a
      // consequence of what the writer was given.
      ...(certificatesOf(d, u).length === 0 ? {} : { userCertificate: certificatesOf(d, u) }),
      ...((direct ? d.directGroupsOf(u) : d.groupsOf(u)).length === 0
        ? {}
        : { memberOf: (direct ? d.directGroupsOf(u) : d.groupsOf(u)).map(groupDn) }),
      ...operational(d, u, userDn(u)),
    } });
  }
  for (const g of d.groupList()) {
    const m = d.membersOf(g);
    const members = [...m.users.map(userDn), ...m.groups.map(groupDn)];
    // groupOfNames "MUST ( member $ cn )" (RFC 4519 section 3.5): a group with
    // no members is given the zero-length name as its one member, which names
    // no entry, so that it still holds one.
    // A group carries the groups it belongs to, as a user does, so that a client
    // resolves membership transitively by reading each group in turn.
    const parents = d.parentsOf(g);
    // extensibleObject for the same reason as a user's entry: gidNumber,
    // sAMAccountName and displayName are user attributes that groupOfNames does
    // not permit. RFC 2307's posixGroup would permit gidNumber, but it is
    // STRUCTURAL and so is groupOfNames, and "an object or alias entry is
    // characterized by precisely one structural object class" (RFC 4512 section
    // 2.4.2 quoting X.501), so an entry cannot bear both. groupOfNames is kept,
    // since `member` and the transitive memberOf this directory serves rest on
    // it; the cost is that RFC 2307 §5.2's getgrgid() filter,
    // (&(objectClass=posixGroup)(gidNumber=%d)), matches nothing here. See
    // NOTES-on-ldap.md §7.
    out.push({ dn: groupDn(g), attrs: {
      objectClass: ["top", "groupOfNames", "extensibleObject"], cn: [g],
      ...(domainSid === "" ? {} : { objectSid: [`${domainSid}-${d.ridOf(g)}`] }),
      ...(d.posixOf(g) === undefined ? {} : { gidNumber: [String(d.posixOf(g))] }),
      sAMAccountName: [g],
      ...(d.displayNameOf(g) === undefined ? {} : { displayName: [d.displayNameOf(g)!] }),
      ...(parents.length === 0 ? {} : { memberOf: parents.map(groupDn) }),
      member: members.length === 0 ? [""] : members,
      ...operational(d, g, groupDn(g)) } });
  }
  out.push(subschema());
  return out;
}

/**
 * The root DSE: the entry with the empty name, by which a client discovers what
 * it is talking to before it binds (RFC 4512 section 5.1). It is not part of the
 * directory's tree — "the root DSE SHALL NOT be included if the client performs a
 * subtree search" — so it is built here and not with the entries above.
 *
 * Every attribute of it is operational. Section 5.1 says they "are not returned
 * in search requests unless requested by name"; this server also returns them for
 * "+", which RFC 3673 defines as every operational attribute and which every
 * deployed server answers that way. The two documents pull slightly apart, 5.1
 * having been written before "+" existed, and following 3673 is the choice a
 * client can use. `NOTES-on-ldap.md` records it.
 */
export function rootDse(domain: string, mechanisms: string[], version: string,
  extensions: string[] = []): Entry {
  return {
    dn: "",
    attrs: {
      objectClass: ["top"],
      namingContexts: [baseOf(domain)],
      supportedLDAPVersion: ["3"],
      // Empty where none is offered, which is itself the answer a client needs:
      // "if the server does not support any SASL mechanisms, this attribute is
      // absent". It is left absent rather than present and empty.
      ...(mechanisms.length === 0 ? {} : { supportedSASLMechanisms: mechanisms }),
      ...(extensions.length === 0 ? {} : { supportedExtension: extensions }),
      // No control is recognized, so the attribute is absent rather than empty:
      // a client reading it learns the same thing either way, and an absent
      // attribute is what RFC 4512 provides for.
      supportedFeatures: [
        // "All Operational Attributes": that "+" is understood (RFC 3673).
        "1.3.6.1.4.1.4203.1.5.1",
      ],
      subschemaSubentry: [SUBSCHEMA_DN],
      // RFC 3045, which defines these two as operational attributes of the root DSE.
      vendorName: ["seedmi"],
      vendorVersion: [`seedmi-dc ${version}`],
    },
  };
}

/**
 * The subschema subentry: the classes and attribute types this directory holds,
 * so that a client discovers them rather than reading them in a README (RFC 4512
 * sections 4.2 and 4.4). A client reads it with a baseObject search of this name
 * and the filter "(objectClass=subschema)", which section 4.4 makes a MUST.
 *
 * **Every definition of an element a standard defines is that standard's text,
 * verbatim.** The first version of this function wrote them out from memory, and
 * opening the documents showed several were wrong in ways a client would act on:
 * `dc` was published as a Directory String when RFC 4519 gives it an IA5 String
 * and `caseIgnoreIA5Match`; `cn`, `sn`, `ou` and `member` were published with a
 * syntax instead of the supertype each has; `createTimestamp` and
 * `modifyTimestamp` lost their matching rules. A published definition that
 * disagrees with the standard it cites is worse than none, because a client
 * matching by the object identifier believes it.
 *
 * **What cannot be cited is not published.** RFC 4512 section 4.4 provides for
 * exactly this: "Clients SHOULD NOT assume that a published subschema is
 * complete, that the server supports all of the schema elements it publishes, or
 * that the server does not support an unpublished element." So an element whose
 * defining document this program has not been given is served and left out of
 * the schema rather than guessed at. What remains unpublished for that reason is
 * now only `userCertificate` and the Certificate syntax (RFC 4523) and
 * `hasSubordinates` (X.501); `NOTES-on-ldap.md` §1 lists them.
 *
 * NOTE RFC 2307 is older than RFC 4512 and writes a syntax as a quoted string —
 * `SYNTAX 'INTEGER'` — which RFC 4512 section 4.1.2 does not permit, its grammar
 * taking an object identifier there. Its three attribute types are therefore
 * published with the syntax identifier RFC 4517 gives for the syntax RFC 2307
 * names: INTEGER is 1.3.6.1.4.1.1466.115.121.1.27 (RFC 4517 section 3.3.16) and
 * IA5 String is .1.26 (section 3.3.17). The name, identifier, description and
 * matching rules are RFC 2307's own, and `SUBSTRINGS` likewise becomes RFC
 * 4512's `SUBSTR`. This is the one place a definition is not the text of its
 * document, and it is a transcription into the current grammar rather than a
 * choice: published as RFC 2307 writes it, no RFC 4512 client could parse it.
 *
 * NOTE The four attributes this directory serves that no LDAP standard defines —
 * memberOf and sAMAccountName, which are Active Directory's; unixHomeDirectory,
 * of the schema several UNIX directories use; and objectSid, Active Directory's
 * and served here in a text form rather than the binary one — have no object
 * identifier this project may assign, so each is published under the arc of this
 * implementation. A client matching on the identifier rather than the name will
 * not recognize them. That is the cost of serving attributes no standard defines,
 * and is recorded rather than hidden.
 */
function subschema(): Entry {
  // An object identifier arc this project does not hold. See the NOTE.
  const PRIVATE = "1.3.6.1.4.1.99999";
  return {
    dn: SUBSCHEMA_DN,
    attrs: {
      objectClass: ["top", "subentry", "subschema", "extensibleObject"],
      cn: ["subschema"],
      // This entry claims `subentry`, whose definition is "MUST ( cn $
      // subtreeSpecification )" (RFC 3672 section 2.4), so it bears one. The
      // empty value is the whole subtree: "when a value of the Subtree
      // Specification syntax is the empty sequence, {}, the specified subtree
      // implicitly includes all the entries within scope" (section 2.3). An
      // earlier version of this function claimed the class and served no such
      // attribute, which made this entry — the one a client reads to learn what
      // the schema requires — itself fail the schema it publishes.
      subtreeSpecification: ["{}"],
      objectClasses: [
        // RFC 4512 section 2.4.1 and 4.3.
        "( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
        "( 1.3.6.1.4.1.1466.101.120.111 NAME 'extensibleObject' SUP top AUXILIARY )",
        "( 2.5.20.1 NAME 'subschema' AUXILIARY MAY ( dITStructureRules $ nameForms $ " +
          "ditContentRules $ objectClasses $ attributeTypes $ matchingRules $ matchingRuleUse ) )",
        // RFC 3672 section 2.4.
        "( 2.5.17.0 NAME 'subentry' SUP top STRUCTURAL MUST ( cn $ subtreeSpecification ) )",
        // RFC 4524 section 2.4.
        "( 0.9.2342.19200300.100.4.13 NAME 'domain' SUP top STRUCTURAL MUST dc " +
          "MAY ( userPassword $ searchGuide $ seeAlso $ businessCategory $ x121Address $ " +
          "registeredAddress $ destinationIndicator $ preferredDeliveryMethod $ telexNumber $ " +
          "teletexTerminalIdentifier $ telephoneNumber $ internationaliSDNNumber $ " +
          "facsimileTelephoneNumber $ street $ postOfficeBox $ postalCode $ postalAddress $ " +
          "physicalDeliveryOfficeName $ st $ l $ description $ o $ associatedName ) )",
        // RFC 2307 section 4, transcribed as its attribute types are (see the NOTE):
        // AUXILIARY, so a user's entry bears it beside inetOrgPerson where all five
        // of its MUSTs can be served. posixGroup is **not** published, and §7 of
        // NOTES-on-ldap.md says why: it is STRUCTURAL and so is groupOfNames, and
        // "an object or alias entry is characterized by precisely one structural
        // object class" (RFC 4512 §2.4.2), so no entry here can bear it.
        "( 1.3.6.1.1.1.2.0 NAME 'posixAccount' SUP top AUXILIARY " +
          "DESC 'Abstraction of an account with POSIX attributes' " +
          "MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory ) " +
          "MAY ( userPassword $ loginShell $ gecos $ description ) )",
        // nisSchema.2.1. AUXILIARY, like posixAccount, so a user's entry bears it
        // beside inetOrgPerson where the store has an expiry. Its one MUST is `uid`,
        // which every user entry here has, so there is no condition on claiming it
        // beyond having something to put in it. Only shadowExpire of its MAY list is
        // served: the rest are shadow(5) fields this directory does not hold, and
        // RFC 2307 §5.3 forbids the one that looks most useful — "a DUA MAY utilise
        // the attributes in the shadowAccount class to provide shadow password
        // service ... In such cases, the DUA MUST NOT make use of the userPassword
        // attribute for getpwnam() et al" — which this server could not serve anyway,
        // holding no password.
        "( 1.3.6.1.1.1.2.1 NAME 'shadowAccount' SUP top AUXILIARY " +
          "DESC 'Additional attributes for shadow passwords' MUST uid " +
          "MAY ( userPassword $ shadowLastChange $ shadowMin $ shadowMax $ shadowWarning $ " +
          "shadowInactive $ shadowExpire $ shadowFlag $ description ) )",
        // RFC 4519 section 3.
        "( 2.5.6.5 NAME 'organizationalUnit' SUP top STRUCTURAL MUST ou MAY ( businessCategory $ " +
          "description $ destinationIndicator $ facsimileTelephoneNumber $ internationalISDNNumber $ " +
          "l $ physicalDeliveryOfficeName $ postalAddress $ postalCode $ postOfficeBox $ " +
          "preferredDeliveryMethod $ registeredAddress $ searchGuide $ seeAlso $ st $ street $ " +
          "telephoneNumber $ teletexTerminalIdentifier $ telexNumber $ userPassword $ x121Address ) )",
        "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ " +
          "telephoneNumber $ seeAlso $ description ) )",
        "( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL MAY ( title $ x121Address $ " +
          "registeredAddress $ destinationIndicator $ preferredDeliveryMethod $ telexNumber $ " +
          "teletexTerminalIdentifier $ telephoneNumber $ internationalISDNNumber $ " +
          "facsimileTelephoneNumber $ street $ postOfficeBox $ postalCode $ postalAddress $ " +
          "physicalDeliveryOfficeName $ ou $ st $ l ) )",
        "( 2.5.6.9 NAME 'groupOfNames' SUP top STRUCTURAL MUST ( member $ cn ) MAY ( " +
          "businessCategory $ seeAlso $ owner $ ou $ o $ description ) )",
        // RFC 2798 section 2.
        "( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( " +
          "audio $ businessCategory $ carLicense $ departmentNumber $ displayName $ employeeNumber $ " +
          "employeeType $ givenName $ homePhone $ homePostalAddress $ initials $ jpegPhoto $ " +
          "labeledURI $ mail $ manager $ mobile $ o $ pager $ photo $ roomNumber $ secretary $ uid $ " +
          "userCertificate $ x500uniqueIdentifier $ preferredLanguage $ userSMIMECertificate $ " +
          "userPKCS12 ) )",
      ],
      attributeTypes: [
        // RFC 4512 sections 2.4.1, 3.3 and 4.2.
        "( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
        "( 2.5.18.1 NAME 'createTimestamp' EQUALITY generalizedTimeMatch " +
          "ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 " +
          "SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
        "( 2.5.18.2 NAME 'modifyTimestamp' EQUALITY generalizedTimeMatch " +
          "ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 " +
          "SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
        "( 2.5.18.10 NAME 'subschemaSubentry' EQUALITY distinguishedNameMatch " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION " +
          "USAGE directoryOperation )",
        // RFC 4512 section 4.2: the four attributes this very entry is read for.
        // Each is operational, which is why a client must ask for them by name or
        // with "+" — and why a subschema search that asks for neither comes back
        // with cn alone, which is correct and surprises people.
        "( 2.5.21.6 NAME 'objectClasses' EQUALITY objectIdentifierFirstComponentMatch " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.37 USAGE directoryOperation )",
        "( 2.5.21.5 NAME 'attributeTypes' EQUALITY objectIdentifierFirstComponentMatch " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.3 USAGE directoryOperation )",
        "( 2.5.21.4 NAME 'matchingRules' EQUALITY objectIdentifierFirstComponentMatch " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.30 USAGE directoryOperation )",
        "( 1.3.6.1.4.1.1466.101.120.16 NAME 'ldapSyntaxes' " +
          "EQUALITY objectIdentifierFirstComponentMatch " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.54 USAGE directoryOperation )",
        // RFC 4512 section 5.1: the attribute types of the root DSE. A client reads
        // that entry before it binds, to learn the naming context and how to
        // authenticate — so these are the first definitions it may want and were the
        // last to be published. Found by a test that walks every attribute this
        // directory serves and asserts the subschema defines it; five of them did not.
        "( 1.3.6.1.4.1.1466.101.120.5 NAME 'namingContexts' " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 USAGE dSAOperation )",
        "( 1.3.6.1.4.1.1466.101.120.15 NAME 'supportedLDAPVersion' " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 USAGE dSAOperation )",
        "( 1.3.6.1.4.1.1466.101.120.14 NAME 'supportedSASLMechanisms' " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE dSAOperation )",
        "( 1.3.6.1.4.1.1466.101.120.7 NAME 'supportedExtension' " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )",
        "( 1.3.6.1.4.1.4203.1.3.5 NAME 'supportedFeatures' " +
          "EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 " +
          "USAGE dSAOperation )",
        // RFC 3672 section 2.3, which the subentry above MUST bear.
        "( 2.5.18.6 NAME 'subtreeSpecification' SINGLE-VALUE USAGE directoryOperation " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.45 )",
        // RFC 5020 and RFC 4530 section 2.4: the two operational attributes by
        // which a client names an entry and follows it through a rename.
        "( 1.3.6.1.1.20 NAME 'entryDN' DESC 'DN of the entry' " +
          "EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 " +
          "SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
        "( 1.3.6.1.1.16.4 NAME 'entryUUID' DESC 'UUID of the entry' EQUALITY uuidMatch " +
          "ORDERING uuidOrderingMatch SYNTAX 1.3.6.1.1.16.1 SINGLE-VALUE " +
          "NO-USER-MODIFICATION USAGE directoryOperation )",
        // RFC 3045 sections 2.1 and 2.2, of the root DSE. Published as that
        // document writes them, which puts an object identifier in the EQUALITY
        // field — legal under RFC 4512's grammar, and the identifier is
        // caseExactIA5Match, whose syntax is IA5 String where these two are
        // Directory String. The inconsistency is RFC 3045's; see NOTES-on-ldap.md §1.
        "( 1.3.6.1.1.4 NAME 'vendorName' EQUALITY 1.3.6.1.4.1.1466.109.114.1 " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE NO-USER-MODIFICATION " +
          "USAGE dSAOperation )",
        "( 1.3.6.1.1.5 NAME 'vendorVersion' EQUALITY 1.3.6.1.4.1.1466.109.114.1 " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE NO-USER-MODIFICATION " +
          "USAGE dSAOperation )",
        // RFC 4519 section 2. `name` and `distinguishedName` are published because
        // cn, sn, ou and member are defined by their supertype and by nothing
        // else: a client that cannot resolve the supertype learns neither syntax
        // nor matching rule. Leaving them out, as the first version of this
        // function did, made four published definitions unresolvable.
        "( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        "( 2.5.4.49 NAME 'distinguishedName' EQUALITY distinguishedNameMatch " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
        "( 2.5.4.3 NAME 'cn' SUP name )",
        "( 2.5.4.4 NAME 'sn' SUP name )",
        "( 2.5.4.11 NAME 'ou' SUP name )",
        "( 2.5.4.13 NAME 'description' EQUALITY caseIgnoreMatch " +
          "SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        "( 2.5.4.31 NAME 'member' SUP distinguishedName )",
        "( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch " +
          "SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        "( 0.9.2342.19200300.100.1.25 NAME 'dc' EQUALITY caseIgnoreIA5Match " +
          "SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
        // RFC 2798 section 2.
        "( 0.9.2342.19200300.100.1.3 NAME 'mail' EQUALITY caseIgnoreIA5Match " +
          "SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{256} )",
        // RFC 4523 §4.1, which obsoletes RFC 2256's definition — the one published
        // here before, without the DESC and without the equality rule. RFC 4523's
        // own §1 names that change: "update of attribute types to include equality
        // matching rules in accordance with their X.500 specifications". The rule it
        // names is published below and is **not implemented**; see NOTES-on-ldap.md §1.
        "( 2.5.4.36 NAME 'userCertificate' DESC 'X.509 user certificate' " +
          "EQUALITY certificateExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.8 )",
        "( 2.16.840.1.113730.3.1.241 NAME 'displayName' DESC 'preferred name of a person to be " +
          "used when displaying entries' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
        // RFC 2307 section 3, transcribed into RFC 4512's grammar. See the NOTE.
        // These three are what a UNIX client resolves an identity by, and a
        // directory that serves the values and publishes no definition for them
        // leaves a client no way to learn that uidNumber is an integer.
        "( 1.3.6.1.1.1.1.0 NAME 'uidNumber' DESC 'An integer uniquely identifying a user in an " +
          "administrative domain' EQUALITY integerMatch " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "( 1.3.6.1.1.1.1.1 NAME 'gidNumber' DESC 'An integer uniquely identifying a group in an " +
          "administrative domain' EQUALITY integerMatch " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        "( 1.3.6.1.1.1.1.3 NAME 'homeDirectory' DESC 'The absolute path to the home directory' " +
          "EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
        // nisSchema.1.10, by which this directory serves the expiry it has always
        // held and never published. RFC 2307 gives the type and no DESC at all, so
        // the DESC here is this server's, and it states the units RFC 2307 omits
        // and the consequence of their being coarser than the value — see the note
        // on `shadowExpire` and NOTES-on-ldap-writes.md §10. A DESC is a
        // description and may be the implementation's; the OID, name, matching rule
        // and syntax are RFC 2307's.
        "( 1.3.6.1.1.1.1.10 NAME 'shadowExpire' DESC 'Days since 1 January 1970 after which " +
          "the account expires; RFC 2307 states no units for this attribute and this server " +
          "uses the ninth field of /etc/shadow, so a value is a whole day and an expiry read " +
          "back is the start of its UTC day' EQUALITY integerMatch " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
        // The four under this implementation's own arc. See the NOTE.
        // The apostrophe is written \27, which RFC 4512 section 4.1's grammar
        // requires: a qdstring is `dstring = 1*( QS / QQ / QUTF8 )` where QUTF8 is
        // "any UTF-8 encoded Unicode character except %x27 and %x5C", and QQ is
        // the escape "\27". Written bare, as it was, the apostrophe closed the
        // description early and left the rest of the sentence standing where the
        // grammar expects a keyword — a definition no client could parse. Found by
        // reading what a live search returned, not by a test.
        `( ${PRIVATE}.1.1 NAME 'memberOf' DESC 'the groups an entry belongs to; ` +
          `Active Directory\\27s attribute, served here so a client resolves membership in one search' ` +
          "EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 " +
          "NO-USER-MODIFICATION USAGE directoryOperation )",
        `( ${PRIVATE}.1.2 NAME 'objectSid' DESC 'the security identifier of the principal, in ` +
          `the text form S-1-5-21-..., where Active Directory holds it in binary' ` +
          "EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE " +
          "NO-USER-MODIFICATION USAGE directoryOperation )",
        `( ${PRIVATE}.1.3 NAME 'unixHomeDirectory' DESC 'the home of the principal' ` +
          "EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
        `( ${PRIVATE}.1.4 NAME 'sAMAccountName' DESC 'the name of the principal within the ` +
          `domain, which here is its name' EQUALITY caseIgnoreMatch ` +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
      ],
      // Every syntax named by a definition above, so that the schema closes: a
      // client resolving `uidNumber` reaches integerMatch, and from there the
      // INTEGER syntax, without leaving this entry. Certificate (.1.8), which
      // userCertificate names, is RFC 4523's and is absent, so userCertificate is
      // published and its syntax is not — the one definition here that does not
      // close. NOTES-on-ldap.md §1 records it.
      ldapSyntaxes: [
        // RFC 4517 section 3.3.
        "( 1.3.6.1.4.1.1466.115.121.1.3 DESC 'Attribute Type Description' )",
        "( 1.3.6.1.4.1.1466.115.121.1.12 DESC 'DN' )",
        "( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )",
        "( 1.3.6.1.4.1.1466.115.121.1.24 DESC 'Generalized Time' )",
        "( 1.3.6.1.4.1.1466.115.121.1.26 DESC 'IA5 String' )",
        "( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'INTEGER' )",
        "( 1.3.6.1.4.1.1466.115.121.1.30 DESC 'Matching Rule Description' )",
        "( 1.3.6.1.4.1.1466.115.121.1.37 DESC 'Object Class Description' )",
        "( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )",
        "( 1.3.6.1.4.1.1466.115.121.1.54 DESC 'LDAP Syntax Description' )",
        "( 1.3.6.1.4.1.1466.115.121.1.58 DESC 'Substring Assertion' )",
        // RFC 3672 section 2.3.
        "( 1.3.6.1.4.1.1466.115.121.1.45 DESC 'SubtreeSpecification' )",
        // RFC 4530 section 2.1.
        "( 1.3.6.1.1.16.1 DESC 'UUID' )",
        // RFC 4523 sections 2.1, 2.5 and 2.6. The last two are the syntaxes the two
        // certificate matching rules take, and are published so that the schema
        // closes through them as it does through every other rule.
        "( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'X.509 Certificate' )",
        "( 1.3.6.1.1.15.1 DESC 'X.509 Certificate Exact Assertion' )",
        "( 1.3.6.1.1.15.2 DESC 'X.509 Certificate Assertion' )",
      ],
      matchingRules: [
        // RFC 4517 section 4.2.
        "( 1.3.6.1.4.1.1466.109.114.1 NAME 'caseExactIA5Match' " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
        "( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match' " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
        "( 1.3.6.1.4.1.1466.109.114.3 NAME 'caseIgnoreIA5SubstringsMatch' " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
        "( 2.5.13.0 NAME 'objectIdentifierMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
        "( 2.5.13.1 NAME 'distinguishedNameMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
        "( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        "( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
        "( 2.5.13.14 NAME 'integerMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
        "( 2.5.13.27 NAME 'generalizedTimeMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )",
        "( 2.5.13.28 NAME 'generalizedTimeOrderingMatch' " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )",
        "( 2.5.13.30 NAME 'objectIdentifierFirstComponentMatch' " +
          "SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
        // RFC 4530 sections 2.2 and 2.3.
        "( 1.3.6.1.1.16.2 NAME 'uuidMatch' SYNTAX 1.3.6.1.1.16.1 )",
        "( 1.3.6.1.1.16.3 NAME 'uuidOrderingMatch' SYNTAX 1.3.6.1.1.16.1 )",
        // RFC 4523 sections 3.1 and 3.2. Published and **not implemented**: this
        // directory keeps a SHA-256 fingerprint of a certificate and not the
        // certificate, and `certificateExactMatch` compares a GSER assertion naming
        // an issuer and a serial number, which a digest does not contain and cannot
        // yield. RFC 4512 §4.4 provides for publishing an element a server does not
        // support — "Clients SHOULD NOT assume ... that the server supports all of
        // the schema elements it publishes" — and `userCertificate` is kept out of
        // RECOGNIZED, so an assertion on it is Undefined rather than quietly False.
        // NOTES-on-ldap.md §1 records it beside the RFC 3045 and RFC 2307 oddities.
        "( 2.5.13.34 NAME 'certificateExactMatch' DESC 'X.509 Certificate Exact Match' " +
          "SYNTAX 1.3.6.1.1.15.1 )",
        "( 2.5.13.35 NAME 'certificateMatch' DESC 'X.509 Certificate Match' " +
          "SYNTAX 1.3.6.1.1.15.2 )",
      ],
    },
  };
}

/**
 * The `equalityMatch` of one attribute type and one assertion value against an
 * entry: TRUE, FALSE, or Undefined where the type is not one this directory
 * recognizes or the assertion value is not a value of its syntax.
 *
 * Shared by the search filter (RFC 4511 §4.5.1.7.1) and the Compare operation
 * (§4.10), which says compareTrue "indicates that the assertion value in the ava
 * field matches a value of the attribute or subtype according to the attribute's
 * EQUALITY matching rule" — the same rule, so the same code. Two front ends over
 * one directory is this program's whole method; two evaluations of one matching
 * rule would be the same mistake a layer down.
 */
function equalityMatch(e: Entry, type: string, value: string): Tri {
  const t = bareDescription(type);
  if (!RECOGNIZED.has(t)) return undefined;
  const vals = valuesOf(e, t) ?? [];
  // member and memberOf take distinguishedNameMatch (RFC 4519: SUP distinguishedName).
  if (DN_VALUED.has(t)) {
    const want = parseDn(value);
    // "The assertion value is invalid": Undefined, not False (RFC 4511 §4.5.1.7).
    if (want === undefined) return undefined;
    return vals.some((v) => {
      const held = parseDn(v);
      return held !== undefined && sameDn(held, want);
    });
  }
  // uidNumber, gidNumber and shadowExpire take integerMatch (RFC 2307 §3), which
  // compares numbers: " 01 " and "1" are one value, and a non-number is Undefined
  // rather than a string that happens not to match.
  if (INTEGER_VALUED.has(t)) {
    if (!/^\s*-?\d+\s*$/.test(value)) return undefined;
    const want = BigInt(value.trim());
    return vals.some((v) => /^\s*-?\d+\s*$/.test(v) && BigInt(v.trim()) === want);
  }
  // objectClass takes objectIdentifierMatch, whose descriptors compare without
  // case; the rest take caseIgnoreMatch or caseIgnoreIA5Match, which is RFC 4518's
  // preparation. For an IA5 value the two agree, every octet being ASCII.
  if (t === "objectclass") return vals.some((v) => v.toLowerCase() === value.toLowerCase());
  const want = prepare(value);
  return vals.some((v) => prepare(v) === want);
}

/**
 * The attribute options this server recognizes. Exactly one: `binary`, which RFC
 * 4522 defines and which RFC 4523 §2.1 makes the **required** form for a
 * certificate — "values of this syntax MUST only be transferred using the ;binary
 * transfer option".
 *
 * Language tags (`;lang-de`) are deliberately not here. This server
 * holds no language-tagged values, so it does not recognize the option, and §2.5
 * below says what follows from that. Recognizing an option it cannot honour would
 * be worse: a client would believe its tagged write had been stored as tagged.
 */
const OPTIONS = new Set(["binary"]);

/**
 * The attribute type an attribute description denotes, or **undefined** where the
 * description is unrecognized.
 *
 * RFC 4512 §2.5: "An attribute description is composed of an attribute type ... and
 * a set of zero or more attribute options", and then, in the same section:
 *
 *   An attribute description with an unrecognized attribute type is to be treated
 *   as unrecognized.  Servers SHALL treat an attribute description with an
 *   unrecognized attribute option as unrecognized.  Clients MAY treat an
 *   unrecognized attribute option as a tagging option.
 *
 * That is a SHALL, and it was violated in three places — the search selection
 * list, Compare, and the LDAP write path — each of which took the text before the
 * first ";" and used it as the type, so `uid;x-foo` selected, compared and
 * modified `uid`. The option was not merely unhonoured; it was discarded, which is
 * the one thing the sentence forbids. Options are case-insensitive and their order
 * is irrelevant (§2.5), so they are lower-cased and taken as a set.
 *
 * What "unrecognized" then means is per operation, and each is its own sentence:
 * ignored in a selection list (RFC 4511 §4.5.1.8), Undefined in a filter
 * (§4.5.1.7), and `undefinedAttributeType` — "a request field contains an
 * unrecognized attribute description" — for a Compare and for a write.
 */
export function describedType(description: string): string | undefined {
  const parts = description.toLowerCase().split(";");
  if (parts.slice(1).some((o) => o === "" || !OPTIONS.has(o))) return undefined;
  return parts[0];
}

/**
 * The attribute type of a description, with an unrecognized description becoming a
 * type no entry has. Used where the caller has no way to say "unrecognized" and
 * "no such attribute" is the same answer.
 */
const bareDescription = (description: string): string =>
  describedType(description) ?? "\u0000unrecognized";

/**
 * The certificates of a principal as `userCertificate` values: the octets of each
 * certificate, which is what the Certificate syntax holds. A certificate the store
 * has only a fingerprint for contributes nothing, there being no value to serve.
 */
/**
 * Whether a user's entry can bear RFC 2307's `posixAccount`: every one of
 * `MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory )`. `cn` and `uid` are
 * always served; the other three are a POSIX number, a primary group with a number,
 * and a home.
 */
function posixAccount(d: Directory, name: string): boolean {
  return d.posixOf(name) !== undefined && d.primaryGidOf(name) !== undefined
    && d.homeOf(name) !== undefined;
}

/** How many whole days a millisecond count is. */
const DAY = 86_400_000;

/**
 * An expiry as a `shadowExpire` value, and back.
 *
 * **RFC 2307 does not say what the units are.** Its definition is the whole of what
 * it says about the attribute —
 *
 *     ( nisSchema.1.10 NAME 'shadowExpire' EQUALITY integerMatch
 *       SYNTAX 'INTEGER' SINGLE-VALUE )
 *
 * — with no DESC, and §5.3 discusses the class only to say a DUA using it "MUST NOT
 * make use of the userPassword attribute for getpwnam()". So an integer, of
 * unstated units, for a field whose meaning the reader is expected to know from
 * elsewhere: it is the ninth field of `/etc/shadow`, and there it is **days since
 * the epoch**. Every implementation uses that, and a directory that used anything
 * else would expire accounts at a wrong time with no way for a client to tell.
 *
 * The consequence is that the value is coarser than the store's, which holds an
 * instant. A round trip through LDAP therefore moves an expiry to the start of its
 * UTC day — stated here, in the published schema's DESC, and in the refusal text,
 * because a client that wrote 17:00 and read back 00:00 would otherwise have no way
 * to know which of the two the directory will act on. SCIM carries the instant
 * whole, so the two front ends are not equally expressive here and cannot be made
 * so without inventing an attribute.
 */
const shadowExpire = (when: Date): string => String(Math.floor(when.getTime() / DAY));

/** A `shadowExpire` value as the instant the store keeps, or undefined if it is not one. */
export function expiryOfShadow(value: string): Date | undefined {
  // "SYNTAX 'INTEGER'": optionally signed, no leading zeroes beyond a bare "0"
  // (RFC 4517 §3.3.16 gives the production). A negative value is a date before
  // 1970, which is a legal integer and not an expiry this directory will record.
  if (!/^(0|-?[1-9][0-9]*)$/.test(value)) return undefined;
  const days = Number(value);
  if (!Number.isSafeInteger(days) || days < 0) return undefined;
  return new Date(days * DAY);
}

function certificatesOf(d: Directory, name: string): Buffer[] {
  return d.credentialsOf(name).certificates
    .filter((c) => c.certificate !== undefined)
    .map((c) => Buffer.from(c.certificate!, "base64"));
}

/**
 * An attribute's values in an entry, its type compared without case. A value that
 * is octets rather than text is read as latin-1, one code point per octet, so that
 * a comparison is over the octets; no attribute this directory recognizes in a
 * filter holds such a value, and `userCertificate` is deliberately not one of them
 * (its equality rule is `certificateExactMatch`, which this server does not
 * implement — see the subschema).
 */
function valuesOf(e: Entry, type: string): string[] | undefined {
  const t = type.toLowerCase();
  for (const [k, v] of Object.entries(e.attrs)) {
    if (k.toLowerCase() === t) return v.map((x) => typeof x === "string" ? x : x.toString("latin1"));
  }
  return undefined;
}

/**
 * The attribute types this directory recognizes. A filter item on any other
 * evaluates to Undefined: "if a server did not recognize the attribute type
 * shoeSize, the filters (shoeSize=*), (shoeSize=12) ... would each evaluate to
 * Undefined" (RFC 4511 section 4.5.1.7).
 */
const RECOGNIZED = new Set(["objectclass", "dc", "ou", "uid", "cn", "sn", "member", "memberof",
  // The security identifier of an entry, by which a CDMI server maps the
  // identifiers of a ticket's privilege attribute certificate back to names
  // ([MS-PAC]). This directory serves it in its text form.
  "objectsid",
  // The POSIX numbers, by which an NFS server resolves a `sys` identity, and the
  // name and display name a Windows client asks for (DESIGN-admin.md §3). A
  // directory with no store serves no number, and a filter on one is then False
  // rather than Undefined: the type is recognized, and no entry has a value.
  "uidnumber", "gidnumber", "samaccountname", "displayname",
  // The home. Both names, since both are served with the same value: homeDirectory,
  // which RFC 2307 §3 defines, and unixHomeDirectory, which is Active Directory's.
  // Only the second was recognized, so `(homeDirectory=/home/ann)` was Undefined
  // and `(unixHomeDirectory=/home/ann)` was TRUE **for the same value of the same
  // entry** — the standard name being the one that did not work, which is the same
  // defect the write path had and which was fixed there in phase C′.
  "unixhomedirectory", "homedirectory",
  // shadowExpire of RFC 2307's shadowAccount: this directory's `expires`, which had
  // no LDAP representation at all until phase E (NOTES-on-ldap-writes.md §10).
  "shadowexpire",
]);

/**
 * The attribute types whose EQUALITY is integerMatch, so that a filter on one
 * compares numbers rather than strings. All three are RFC 2307's.
 */
const INTEGER_VALUED = new Set(["uidnumber", "gidnumber", "shadowexpire"]);

/** TRUE, FALSE, or Undefined: X.511 (1993) clause 7.8.1, as RFC 4511 section 4.5.1.7 summarizes it. */
type Tri = true | false | undefined;

/**
 * Evaluates a filter against an entry, by "the three-valued logic of [X.511]".
 * "A filter item evaluates to Undefined when the server would not be able to
 * determine whether the assertion value matches an entry", as for a type it does
 * not recognize or "The type of filtering requested is not implemented", and
 * "Servers MUST NOT return errors" for these. Only an entry for which the filter
 * is TRUE is returned.
 */
function evaluate(e: Entry, f: Element): Tri {
  const kind = f.tag & 0x1f;
  const constructed = (f.tag & CONSTRUCTED) !== 0;
  if ((f.tag & 0xc0) !== CONTEXT) throw new BerError("a filter is a context-specific choice");
  switch (kind) {
    case 0: case 1: {
      if (!constructed) break;
      // "At least one filter element MUST be present in an 'and' or 'or'
      // choice": an empty one, which RFC 4526 gives a meaning this server does
      // not claim, is Undefined.
      const parts = children(f.content).map((c) => evaluate(e, c));
      if (parts.length === 0) return undefined;
      // "and": TRUE if all are TRUE, FALSE if at least one is FALSE, Undefined otherwise.
      if (kind === 0) return parts.includes(false) ? false : parts.every((p) => p === true) ? true : undefined;
      // "or": FALSE if all are FALSE, TRUE if at least one is TRUE, Undefined otherwise.
      return parts.includes(true) ? true : parts.every((p) => p === false) ? false : undefined;
    }
    case 2: {
      if (!constructed) break;
      const [inner, ...rest] = children(f.content);
      if (inner === undefined || rest.length > 0) throw new BerError("not holds one filter");
      const v = evaluate(e, inner);
      // "not": TRUE if FALSE, FALSE if TRUE, "and Undefined if it is Undefined".
      return v === undefined ? undefined : !v;
    }
    case 3: {
      if (!constructed) break;
      const [type, value, ...rest] = children(f.content);
      if (type === undefined || value === undefined || rest.length > 0) throw new BerError("an equality match holds a type and a value");
      return equalityMatch(e, text(type), text(value));
    }
    case 7: {
      if (constructed) break;
      const t = text(f).toLowerCase();
      if (!RECOGNIZED.has(t)) return undefined;
      return valuesOf(e, t) !== undefined;
    }
    // substrings, greaterOrEqual, lessOrEqual, approxMatch, extensibleMatch:
    // "The type of filtering requested is not implemented."
    case 4: case 5: case 6: case 8: case 9:
      return undefined;
  }
  throw new BerError("a filter this protocol does not define");
}

// --- messages ----------------------------------------------------------------

const result = (code: number, diagnostic = "", matchedDn = "") =>
  [int(code, T.ENUMERATED), octets(matchedDn), octets(diagnostic)];
const message = (id: number, op: Buffer) => seq([int(id), op]);

export interface LdapLog { (level: "problems" | "requests", event: Record<string, unknown>): void }

/**
 * The write path as this front end uses it. `ldap.ts` holds no rule of its own:
 * it translates a request into one of these calls and a refusal into a result
 * code (DESIGN-admin.md §2). The implementation is dc-ldap-writes.ts, which
 * knows dc-write.ts; this interface is here so that this module does not.
 */
export interface LdapWrites {
  /** Creates an entry from the attributes of an addRequest. */
  add(dn: string, attrs: { type: string; values: string[]; raw: Buffer[] }[]): Promise<void>;
  /** Deletes the entry a name denotes. */
  remove(dn: string): Promise<void>;
  /** Applies the changes of a modifyRequest, in order, all or none. */
  modify(dn: string, changes: LdapChange[]): Promise<void>;
  /** Renames, and moves where a new superior is given. */
  rename(dn: string, newRdn: string, newSuperior: string | undefined, deleteOld: boolean): Promise<void>;
  /**
   * Sets a password (RFC 3062). The identity is a distinguished name, a "dn:"
   * authzId or a "u:" one; the caller has already decided that this session may
   * change that principal's password *and* has verified the request's oldPasswd
   * where one was given, which RFC 3062 section 3 makes a SHALL. The old password
   * is deliberately not a parameter here: while it was one, it was passed down
   * and never checked, and a parameter a writer may ignore is an invitation to
   * ignore it again.
   */
  setPassword(dn: string, newPassword: string): Promise<void>;
  /** The result code and the text a refusal becomes. */
  codeOf(e: unknown): { code: number; why: string };
}

/** One change of a modifyRequest: add, delete or replace the values of a type. */
export interface LdapChange {
  operation: "add" | "delete" | "replace";
  type: string;
  /** The values decoded as UTF-8, for an attribute that holds text. */
  values: string[];
  /**
   * The same values as octets. An attribute value is a sequence of octets and only
   * some attributes hold text: a `userCertificate` carries DER, which is not UTF-8
   * and does not survive being decoded as it. Whoever reads a value has to know
   * which of the two it wants.
   */
  raw: Buffer[];
}

/** What a session is given beyond the directory it serves. */
export interface LdapOptions {
  admin?: { subjects: string[] };
  certificate?: () => { subject: string; authorized: boolean; why?: string } | undefined;
  writes?: LdapWrites;
  /**
   * This connection has no TLS layer yet and StartTLS may install one, which the
   * cleartext listener passes. Absent means the layer is already there — the LDAPS
   * listener — and a StartTLS request is then `operationsError`, "when TLS is
   * currently established on the session" (RFC 4513 §3.1.1).
   */
  startTls?: boolean;
}

/**
 * One LDAP connection: it takes octets as they arrive and returns the octets to
 * send, and whether to close. The directory is fetched afresh for each request,
 * so that a reload applies from the next one.
 */
export class LdapSession {
  private buffer = Buffer.alloc(0);
  /** Whom the session is bound as: a user's name, anonymous, or not yet bound (anonymous too). */
  private bound: string | undefined;
  /** A GSSAPI bind part way through (RFC 4752 section 3.2). */
  private sasl: { mechanism: string; principal: string; key: Buffer; step: number } | undefined;
  /** The authenticators seen, so that a ticket is not presented twice. */
  private readonly replays = new ReplayCache();
  private readonly directory: () => Directory;
  private readonly domain: string;
  private readonly log: LdapLog;
  private readonly peer: string;
  private readonly throttle: Throttle;

  /** Whether memberOf holds direct memberships alone ([directory] memberof). */
  private readonly directMemberOf: boolean;

  /** The security identifier of the domain, served as objectSid ([MS-PAC]). */
  private readonly domainSid: string;

  /** What this program calls itself in the root DSE (RFC 3045 vendorVersion). */
  private readonly version: string;

  /** The key of the service principal this server answers GSSAPI binds with. */
  private readonly serviceKey: (() => { key: Buffer; etype: Etype; parts: string[] } | undefined) | undefined;

  /** Who may write, where the configuration says ([admin]). */
  private readonly admin: { subjects: string[] } | undefined;

  /** The certificate of this connection, for a bind by EXTERNAL. */
  private readonly certificate:
    (() => { subject: string; authorized: boolean; why?: string } | undefined) | undefined;

  /** The write path, where this controller has one (dc-write.ts). */
  private readonly writes: LdapWrites | undefined;

  /**
   * Whether this connection has a TLS layer. True from the start on the LDAPS
   * listener; on the cleartext one it becomes true when StartTLS installs it, and
   * until then the session serves the root DSE and StartTLS and nothing else.
   */
  private tls: boolean;

  /** Whether StartTLS may be offered at all, which the cleartext listener sets. */
  private readonly canStartTls: boolean;

  /** Set by a successful StartTLS; the listener reads it and installs the layer. */
  private upgrading = false;

  constructor(directory: () => Directory, domain: string, log: LdapLog, peer = "", throttle: Throttle = new Throttle(),
    directMemberOf = false, serviceKey?: () => { key: Buffer; etype: Etype; parts: string[] } | undefined,
    domainSid = "", version = "", more: LdapOptions = {}) {
    this.version = version;
    this.directMemberOf = directMemberOf;
    this.serviceKey = serviceKey;
    this.domainSid = domainSid;
    this.throttle = throttle;
    this.directory = directory;
    this.domain = domain;
    this.log = log;
    this.peer = peer;
    this.admin = more.admin;
    this.certificate = more.certificate;
    this.writes = more.writes;
    // The LDAPS listener gives neither, and a session there has TLS from the first
    // octet. The cleartext listener passes `startTls`, and the layer is installed
    // when a client asks for it.
    this.canStartTls = more.startTls === true;
    this.tls = more.startTls !== true;
  }

  /**
   * Called by the listener once it has wrapped the socket, so the session knows the
   * layer is there. "The establishment, change, and/or closure of TLS may cause the
   * authorization state to move to a new state" (RFC 4513 §3.2, and §4 of the same
   * document). It moves to anonymous here, which is the conservative reading: a
   * credential sent in the clear cannot be what authorizes a protected session.
   */
  tlsInstalled(): void {
    this.tls = true;
    this.bound = undefined;
    this.sasl = undefined;
  }

  /**
   * Whatever arrived after the StartTLS request and was not read as an LDAP
   * message. Those octets are the start of the TLS handshake — a client that pipes
   * them is not supposed to, but it costs nothing to hand them on rather than drop
   * a handshake — and the buffer is emptied so the LDAP layer does not see them.
   */
  takePending(): Buffer {
    const held = this.buffer;
    this.buffer = Buffer.alloc(0);
    return held;
  }

  /**
   * Octets received; the replies, and whether the connection is to be closed.
   *
   * Asynchronous because a write reaches the key management server: a password
   * set over LDAP derives a verifier and a Kerberos key and registers both
   * (dc-write.ts). A caller serves one connection's calls in order, since LDAP
   * requests on one connection are answered in the order a server chooses but a
   * write and the search that follows it are not to be interleaved.
   */
  async receive(data: Buffer): Promise<{ replies: Buffer[]; close: boolean; upgrade?: boolean }> {
    this.buffer = Buffer.concat([this.buffer, data]);
    const replies: Buffer[] = [];
    for (;;) {
      let r;
      try {
        r = readElement(this.buffer, 0);
      } catch (e) {
        if (e instanceof Incomplete) {
          if (this.buffer.length > MAX_MESSAGE) return this.disconnect(replies, "a message larger than this server reads");
          return { replies, close: false };
        }
        return this.disconnect(replies, (e as Error).message);
      }
      this.buffer = this.buffer.subarray(r.next);
      try {
        const out = await this.handle(r.el);
        replies.push(...out.replies);
        if (out.close) return { replies, close: true };
        // "The client MUST NOT send any LDAP PDUs at this LDAP message layer
        // following this request until it receives a StartTLS Extended response
        // and, in the case of a successful response, completes TLS negotiations"
        // (RFC 4511 §4.14.1). So the reply is returned here and whatever else
        // arrived in the same read is left in the buffer — it belongs to the TLS
        // handshake, not to this layer, and the listener hands it to the TLS socket.
        if (this.upgrading) {
          this.upgrading = false;
          return { replies, close: false, upgrade: true };
        }
      } catch (e) {
        if (e instanceof BerError) return this.disconnect(replies, e.message);
        throw e;
      }
    }
  }

  /** A Notice of Disconnection (RFC 4511 section 4.4.1), and the connection closed. */
  private disconnect(replies: Buffer[], why: string): { replies: Buffer[]; close: boolean } {
    this.log("problems", { event: "ldap disconnect", peer: this.peer, detail: why });
    replies.push(message(0, seq([...result(RESULT.protocolError, why), octets(NOTICE_OF_DISCONNECTION, CONTEXT | 10)],
      OP.extendedResponse)));
    return { replies, close: true };
  }

  private async handle(el: Element): Promise<{ replies: Buffer[]; close: boolean }> {
    if (el.tag !== T.SEQUENCE) throw new BerError("an LDAPMessage is a SEQUENCE");
    const [idEl, op, controls, ...rest] = children(el.content);
    if (idEl === undefined || idEl.tag !== T.INTEGER || op === undefined || rest.length > 0) {
      throw new BerError("an LDAPMessage holds a message ID, an operation, and controls where there are any");
    }
    const id = integer(idEl);
    if (id < 1) throw new BerError("a message ID of a request is 1 or more");
    // "If the server receives a control ... marked critical ... [it] MUST return
    // unavailableCriticalExtension" where it does not recognize it: it recognizes none.
    let critical = false;
    if (controls !== undefined) {
      if (controls.tag !== (CONTEXT | CONSTRUCTED | 0)) throw new BerError("the third element of an LDAPMessage is its controls");
      for (const c of children(controls.content)) {
        const [, crit] = children(c.content);
        if (crit !== undefined && crit.tag === T.BOOLEAN && boolean(crit)) critical = true;
      }
    }
    if (op.tag === OP.unbindRequest) {
      this.log("requests", { event: "ldap unbind", peer: this.peer, as: this.bound ?? "anonymous" });
      return { replies: [], close: true };
    }
    if (op.tag === OP.abandonRequest) return { replies: [], close: false };
    const refuse = (responseTag: number, code: number, why: string) =>
      ({ replies: [message(id, seq(result(code, why), responseTag))], close: false });
    // Before a TLS layer, this session serves the root DSE — so a client can
    // discover StartTLS at all — and StartTLS and unbind, and nothing else. Anything
    // that would carry a credential or an entry in the clear is
    // confidentialityRequired (13). RFC 4513 §6.3.3 provides for a server with such
    // a policy, and §3.1.1 expects a client to do StartTLS first: "where a client
    // intends to perform both a Bind operation and a StartTLS operation, it SHOULD
    // first perform the StartTLS operation".
    if (!this.tls && op.tag !== OP.extendedRequest) {
      const answerTag = op.tag === OP.searchRequest
        ? OP.searchResultDone
        : (WRITES[op.tag] ?? OP.bindResponse);
      if (op.tag === OP.searchRequest && this.isRootDse(op)) {
        return { replies: this.search(op).map((o) => message(id, o)), close: false };
      }
      return refuse(answerTag, RESULT.confidentialityRequired,
        "this connection has no TLS layer: send StartTLS (1.3.6.1.4.1.1466.20037), which the " +
        "root DSE lists in supportedExtension, before anything else");
    }
    if (op.tag === OP.bindRequest) {
      // "Upon receipt of a Bind request, the server immediately moves the session
      // to an anonymous authorization state. If the Bind request is successful, the
      // session is moved to the requested authentication state ... Otherwise, the
      // session remains in an anonymous state" (RFC 4513 §4, and Appendix B.1.1
      // records that this was clarified for exactly this reason). The reset used to
      // live inside `bind`, which this branch returns before reaching: a session
      // bound as alice that then sent a Bind carrying a critical control was
      // refused — and stayed bound as alice. A client or proxy that re-binds to
      // drop or change identity silently kept the old one.
      this.bound = undefined;
      if (critical) {
        // A BindRequest that is refused here is not a continuation of a SASL
        // negotiation either, so the negotiation goes with it; see `bind` below.
        this.sasl = undefined;
        return refuse(OP.bindResponse, RESULT.unavailableCriticalExtension, "no control is recognized");
      }
      return { replies: [message(id, this.bind(op))], close: false };
    }
    if (op.tag === OP.searchRequest) {
      if (critical) return refuse(OP.searchResultDone, RESULT.unavailableCriticalExtension, "no control is recognized");
      return { replies: this.search(op).map((o) => message(id, o)), close: false };
    }
    if (op.tag in WRITES) {
      if (critical) return refuse(WRITES[op.tag], RESULT.unavailableCriticalExtension, "no control is recognized");
      // Compare is a read, not a write: it is in this branch only because its tag
      // is grouped with them. It is served now; `NOTES-on-ldap.md` §5 used to list
      // it as refused, with "not hard; simply not written" as the reason.
      if (op.tag === COMPARE) return { replies: [message(id, this.compare(op))], close: false };
      if (this.writes === undefined) {
        return refuse(WRITES[op.tag], RESULT.unwillingToPerform,
          "this directory is read only: it is given in the controller's configuration, and " +
          "a directory that is written is kept in a store ([directory].store)");
      }
      if (!this.isAdmin) {
        return refuse(WRITES[op.tag], RESULT.insufficientAccessRights,
          this.bound
            ? "a write is performed by a session bound as an administrator: SASL EXTERNAL with a certificate [admin] names"
            : "a session writes once it has bound");
      }
      return { replies: [message(id, await this.write(op))], close: false };
    }
    if (op.tag === OP.extendedRequest) {
      if (critical) return refuse(OP.extendedResponse, RESULT.unavailableCriticalExtension, "no control is recognized");
      return { replies: [message(id, await this.extended(op))], close: false };
    }
    throw new BerError("an operation this protocol does not define as a request");
  }

  /** The extended operations this server offers, which the root DSE reports. */
  private extensions(): string[] {
    return [
      // Offered only while there is no TLS layer, since a request for one once it is
      // established is operationsError (RFC 4513 §3.1.1): advertising it then would
      // invite an operation that can only fail. RFC 4513 §3.1.5 says the root DSE
      // may read differently either side of the negotiation, and expects it to.
      ...(this.canStartTls && !this.tls ? [START_TLS] : []),
      WHO_AM_I,
      ...(this.writes === undefined ? [] : [PASSWORD_MODIFY]),
    ];
  }

  /**
   * An extended operation. Two are served: "Who am I?" (RFC 4532), which a
   * client uses to learn what its bind actually authenticated it as, and Password
   * Modify (RFC 3062), which is how every LDAP client changes a password.
   */
  private async extended(op: Element): Promise<Buffer> {
    const [nameEl, valueEl] = children(op.content);
    if (nameEl?.tag !== (CONTEXT | 0)) throw new BerError("an extended request holds a request name");
    const name = nameEl.content.toString("utf8");
    const answer = (code: number, why = "", value?: Buffer) =>
      seq([...result(code, why),
        ...(value === undefined ? [] : [octets(value, CONTEXT | 11)])], OP.extendedResponse);
    // Before a TLS layer, StartTLS is the only extended operation served. The
    // confidentiality check in `handle` lets an extendedRequest through so that
    // this one can be reached — which also let "Who am I?" and, worse, Password
    // Modify through, and a Password Modify in the clear sends a password. Caught by
    // writing the test for StartTLS and reading the exemption again.
    if (!this.tls && name !== START_TLS) {
      return answer(RESULT.confidentialityRequired,
        `${JSON.stringify(name)} is not served on a connection with no TLS layer: send ` +
        "StartTLS (1.3.6.1.4.1.1466.20037) first");
    }
    if (name === START_TLS) {
      // "If the server does not support TLS (whether by design or by current
      // configuration), it returns with the resultCode set to protocolError"
      // (RFC 4511 §4.14.1), which is what the LDAPS listener answers: the layer is
      // already there and this operation has no meaning on it.
      if (!this.canStartTls) {
        return answer(RESULT.protocolError,
          "this connection is LDAP over TLS and already has a TLS layer; StartTLS is served on " +
          "the cleartext listener ([listen] ldap_starttls_port)");
      }
      // §3.1.1 of RFC 4513: a client may send it "except - when TLS is currently
      // established on the session, - when a multi-stage SASL negotiation is in
      // progress on the session, or - when there are outstanding responses for
      // operation requests previously issued on the session", and "a (detected)
      // violation of any of these requirements results in a return of the
      // operationsError resultCode". The third this session cannot violate: it
      // answers one request at a time.
      if (this.tls) {
        return answer(RESULT.operationsError, "a TLS layer is already established on this session");
      }
      if (this.sasl !== undefined) {
        return answer(RESULT.operationsError, "a SASL negotiation is in progress on this session");
      }
      this.log("requests", { event: "ldap starttls", peer: this.peer });
      // "The responseName is '1.3.6.1.4.1.1466.20037' when provided ... The
      // responseValue is always absent" (§4.14.2). The listener installs the layer
      // once this reply is written; `upgrade` is how it is told to.
      this.upgrading = true;
      return seq([...result(RESULT.success, ""), octets(START_TLS, CONTEXT | 10)],
        OP.extendedResponse);
    }
    if (name === WHO_AM_I) {
      // "Clients MUST NOT invoke the 'Who am I?' operation while any Bind
      // operation is in progress, including between two Bind requests made as
      // part of a multi-stage Bind operation. Where a whoami Request is received
      // in violation of this absolute prohibition, the server should return a
      // whoami Response with an operationsError resultCode" (RFC 4532 section 3).
      // A GSSAPI bind part way through is exactly that state, and answering it
      // would report the identity of the bind being replaced.
      if (this.sasl !== undefined) {
        this.log("problems", { event: "ldap whoami refused", peer: this.peer,
          reason: "a bind is in progress" });
        return answer(RESULT.operationsError,
          "a bind is in progress; \"Who am I?\" is not invoked between the requests of one");
      }
      // "the authzId representing the current authorization identity ... or an
      // empty value if the current authorization identity is anonymous".
      const who = this.bound === undefined || this.bound === ""
        ? ""
        : (this.isAdmin ? this.bound : `dn:uid=${this.bound},ou=people,${baseOf(this.domain)}`);
      this.log("requests", { event: "ldap whoami", peer: this.peer, as: who === "" ? "anonymous" : who });
      return answer(RESULT.success, "", Buffer.from(who, "utf8"));
    }
    if (name === PASSWORD_MODIFY && this.writes !== undefined) {
      return await this.passwordModify(valueEl, answer);
    }
    // "If the server does not recognize the request name, it MUST return only
    // the response fields from LDAPResult, containing the protocolError result code."
    return answer(RESULT.protocolError, `no extended operation named ${JSON.stringify(name)} is recognized`);
  }

  /**
   * The SASL mechanism of RFC 4752, "GSSAPI", by which a service binds as
   * itself with a Kerberos ticket, rather than as a user with a password: it is
   * how a CDMI server reads the groups of a principal that authenticated by a
   * ticket and so has no password to bind with (revision 282 of the draft;
   * PLAN-auth.md, phase 7).
   *
   * Three steps, as section 3.2 gives them: the client's AP-REQ, answered with
   * the AP-REP where it asked for mutual authentication; then the server's
   * four octets under GSS_Wrap, "the first octet containing a bit-mask
   * specifying the security layers supported by the server and the second
   * through fourth octets containing in network byte order the maximum size
   * output_token the server is able to receive (which MUST be 0 if the server
   * does not support any security layer)"; and then the client's reply, whose
   * first octet is the layer it chose and whose remaining octets are the
   * authorization identity.
   *
   * This server offers no security layer. LDAP is served over TLS here, which
   * protects the connection, and a layer of its own would be a second one.
   */
  private saslBind(auth: Element): Buffer {
    const answer = (code: number, why = "", creds?: Buffer) =>
      seq([...result(code, why), ...(creds === undefined ? [] : [octets(creds, CONTEXT | 7)])], OP.bindResponse);
    const [mechanism, credentials] = children(auth.content);
    if (mechanism?.tag !== T.OCTET_STRING) throw new BerError("SASL credentials hold a mechanism");
    const name = text(mechanism);
    // EXTERNAL: "the client's credentials are established by a lower level"
    // (RFC 4422 appendix A), which here is the client certificate of the TLS
    // connection. It is how an administrator binds, and it is the one credential
    // of this program that needs no key management server, so it is also the one
    // that works while that server is away (DESIGN-admin.md §4).
    if (name === "EXTERNAL") {
      this.sasl = undefined;
      return this.externalBind(credentials);
    }
    if (name !== "GSSAPI") {
      this.sasl = undefined;
      return answer(RESULT.authMethodNotSupported, `the mechanism ${JSON.stringify(name)} is not one this server offers`);
    }
    const service = this.serviceKey?.();
    if (service === undefined) {
      return answer(RESULT.authMethodNotSupported, "this server holds no key for a service principal, and offers no GSSAPI");
    }
    const token = credentials === undefined ? Buffer.alloc(0) : credentials.content;
    // The first of §5.2.1.2's two ways to abort: a BindRequest naming another
    // mechanism. The negotiation in progress is discarded rather than continued.
    if (this.sasl !== undefined && this.sasl.mechanism !== name) this.sasl = undefined;
    const held = this.sasl;
    try {
      if (held === undefined) {
        // The first step: the client's ticket.
        const accepted = acceptNegotiate(token.toString("base64"), {
          key: service.key, etype: service.etype, names: [service.parts],
        }, this.replays);
        this.sasl = { mechanism: name, principal: accepted.verified.principal,
          key: accepted.verified.subkey?.value ?? accepted.verified.sessionKey.value, step: accepted.answer === undefined ? 2 : 1 };
        if (accepted.answer !== undefined) {
          return answer(RESULT.saslBindInProgress, "", Buffer.from(accepted.answer, "base64"));
        }
        return answer(RESULT.saslBindInProgress, "", wrapToken(this.sasl.key, OFFER, { acceptor: true, sequence: 0 }));
      }
      if (held.step === 1) {
        // The reply to the AP-REP carries no data; the offer follows.
        held.step = 2;
        return answer(RESULT.saslBindInProgress, "", wrapToken(held.key, OFFER, { acceptor: true, sequence: 0 }));
      }
      // The client's choice of layer, and the authorization identity.
      const chosen = unwrapToken(held.key, token, { acceptor: false });
      this.sasl = undefined;
      if (chosen.length < 4) return answer(RESULT.protocolError, "the reply holds four octets and an authorization identity");
      if (chosen[0] !== NO_SECURITY_LAYER) {
        return answer(RESULT.unwillingToPerform, "this server offers no security layer, and none may be chosen");
      }
      if (((chosen[1] << 16) | (chosen[2] << 8) | chosen[3]) !== 0) {
        return answer(RESULT.protocolError, "the client's maximum size is zero where no security layer is chosen");
      }
      const authzid = chosen.subarray(4).toString("utf8");
      // "The server must verify that the src_name is authorized to act as the
      // authorization identity": here only its own identity is allowed — and the
      // assertion is read as an authzId, which is the form RFC 4513 §5.2.1.8
      // defines: `authzId = dnAuthzId / uAuthzId`, "dn:" and a distinguished name
      // or "u:" and a userid. This used to compare the field against the bare
      // Kerberos principal name, so the one assertion a conforming client makes —
      // `u:alice@EU.EXAMPLE` — was refused, and only a non-conforming bare name
      // was accepted. Exactly inverted.
      if (authzid !== "" && !this.assertsSelf(authzid, held.principal)) {
        return answer(RESULT.invalidCredentials, "this server does not let a principal act as another");
      }
      this.bound = held.principal;
      this.log("requests", { event: "ldap bind", peer: this.peer, as: held.principal, mechanism: "GSSAPI" });
      return answer(RESULT.success);
    } catch (e) {
      this.sasl = undefined;
      this.log("problems", { event: "ldap bind refused", peer: this.peer, mechanism: "GSSAPI",
        reason: (e as Error).message.slice(0, 200) });
      return answer(RESULT.invalidCredentials);
    }
  }

  /**
   * Whether an authorization identity asserts the identity the session just
   * authenticated as, and nothing else. The forms are RFC 4513 §5.2.1.8's:
   * `dnAuthzId = "dn:" distinguishedName`, compared by distinguishedNameMatch as
   * that section requires, and `uAuthzId = "u:" userid`, whose interpretation "is a
   * local matter" — here the principal's own name, with or without its realm.
   *
   * A bare string that is neither form is **not** an authzId and is refused, which
   * is the opposite of what this did.
   */
  private assertsSelf(authzid: string, principal: string): boolean {
    if (authzid.startsWith("dn:")) {
      // The principal's own entry, where it has one. A Kerberos principal of this
      // realm is a user of the directory, so its distinguished name is its entry's.
      const bare = principal.split("@")[0];
      const name = this.directory().user(bare)?.name;
      if (name === undefined) return false;
      const mine = `uid=${name},${within(this.directory().unitOf(name), `ou=people,${baseOf(this.domain)}`)}`;
      return sameDnString(authzid.slice(3), mine);
    }
    if (authzid.startsWith("u:")) {
      const wanted = authzid.slice(2);
      return wanted === principal || wanted === principal.split("@")[0];
    }
    return false;
  }

  /**
   * A bind by the certificate of the connection (RFC 4513 section 5.2.1.2, RFC
   * 4422 appendix A). The identity is the certificate's subject, which the
   * configuration lists; it is not a principal of the directory, and an
   * administrator is therefore not an account that can be disabled, expire or
   * have a password. A credential of its own, which is the point: it needs no
   * password anywhere, and it keeps working when the key server does not.
   *
   * "The client is not required to send any credentials", and where it sends an
   * authorization identity this server does not let one act as another, as it
   * does not for GSSAPI.
   */
  private externalBind(credentials: Element | undefined): Buffer {
    const answer = (code: number, why = "") => seq(result(code, why), OP.bindResponse);
    const admin = this.admin;
    if (admin === undefined) {
      return answer(RESULT.authMethodNotSupported,
        "this controller has no [admin] authority configured, and offers no EXTERNAL");
    }
    // "Zero-length initial response data is distinguished from no initial response
    // data in the initiating message, a BindRequest PDU, by the presence of the
    // SaslCredentials.credentials OCTET STRING (of length zero) in that PDU" (RFC
    // 4513 §5.2.1.3). So an absent field is the implicit assertion of §5.2.3.1 —
    // "the client is not required to send any credentials" — while a field that is
    // present and empty is an *explicit* assertion of the empty string, which is
    // neither a dnAuthzId nor a uAuthzId and so is refused (§5, and the authzId
    // grammar of §5.2.1.8). The two used to be one value, so the second succeeded
    // and bound as the administrator.
    const asserted = credentials === undefined ? undefined : credentials.content.toString("utf8");
    if (asserted !== undefined && asserted === "") {
      return answer(RESULT.invalidCredentials,
        "the credentials field is present and empty, which asserts no authorization identity: " +
        'omit it to be the certificate\'s own subject, or give "dn:" and the subject');
    }
    const authzid = asserted ?? "";
    const presented = this.certificate?.();
    if (presented === undefined) {
      // "inappropriateAuthentication ... the client has provided no credentials
      // suitable for the requested authentication" — here, no certificate at all.
      this.log("problems", { event: "ldap bind refused", peer: this.peer, mechanism: "EXTERNAL",
        reason: "no client certificate was presented" });
      return answer(RESULT.inappropriateAuthentication,
        "EXTERNAL takes the certificate of the connection, and none was presented");
    }
    if (!presented.authorized) {
      this.log("problems", { event: "ldap bind refused", peer: this.peer, mechanism: "EXTERNAL",
        subject: presented.subject, reason: presented.why ?? "not issued by the configured authority" });
      return answer(RESULT.invalidCredentials);
    }
    // The subject is compared as the configuration writes it, without case, and
    // with the parts in any order: a certificate's subject is a set of attributes
    // and the order a library prints them in is not the holder's business.
    const wanted = admin.subjects.find((s) => sameSubject(s, presented.subject));
    if (wanted === undefined) {
      this.log("problems", { event: "ldap bind refused", peer: this.peer, mechanism: "EXTERNAL",
        subject: presented.subject, reason: "the subject is not one [admin].subjects names" });
      return answer(RESULT.invalidCredentials);
    }
    // "The value of the credentials field ... is the asserted authorization
    // identity and MUST be constructed as documented in Section 5.2.1.8" (RFC 4513
    // §5.2.3.2), so it is a "dn:" or "u:" form and not a bare name — and a "dn:"
    // one is "to be matched in accordance with the distinguishedNameMatch matching
    // rule". A bare distinguished name used to be accepted, which is not an authzId
    // at all, and the comparison behind it was the set-and-sort one; see dn.ts.
    if (authzid !== "" && !(authzid.startsWith("dn:") && sameDnString(authzid.slice(3), presented.subject))) {
      return answer(RESULT.invalidCredentials,
        'an authorization identity is "dn:" and the subject of the certificate presented, ' +
        "which is the only identity this server lets a certificate holder assert");
    }
    this.bound = ADMIN_PREFIX + wanted;
    this.log("requests", { event: "ldap bind", peer: this.peer, as: this.bound, mechanism: "EXTERNAL" });
    return answer(RESULT.success);
  }

  /** Whether the session is bound as an administrator rather than as a principal. */
  private get isAdmin(): boolean {
    return (this.bound ?? "").startsWith(ADMIN_PREFIX);
  }

  private bind(op: Element): Buffer {
    const [version, name, auth] = children(op.content);
    if (version?.tag !== T.INTEGER || name?.tag !== T.OCTET_STRING || auth === undefined) {
      throw new BerError("a bind request holds a version, a name and an authentication choice");
    }
    const answer = (code: number, why = "") => seq(result(code, why), OP.bindResponse);
    // "Upon receipt of a Bind request, the server immediately moves the session
    // to an anonymous authorization state" (RFC 4513 section 4), so a failed
    // bind leaves it anonymous.
    this.bound = undefined;
    if (integer(version) !== 3) {
      this.sasl = undefined;
      return answer(RESULT.protocolError, "this server speaks LDAP version 3");
    }
    // SaslCredentials ::= SEQUENCE { mechanism LDAPString, credentials OCTET STRING OPTIONAL }
    if (auth.tag === (CONTEXT | CONSTRUCTED | 3)) return this.saslBind(auth);
    // "A client may abort a SASL Bind negotiation by sending a BindRequest message
    // with a different value in the mechanism field of SaslCredentials or with an
    // AuthenticationChoice other than sasl" (RFC 4513 §5.2.1.2). This is the second
    // of those, and nothing used to discard the state: a half-finished GSSAPI
    // exchange survived a simple bind, so the *next* GSSAPI bind was taken as a
    // continuation of the abandoned one — answered with a token sealed under a key
    // the new exchange does not have, which no client can recover from — and
    // "Who am I?" answered operationsError on that connection for ever.
    this.sasl = undefined;
    if (auth.tag !== (CONTEXT | 0)) throw new BerError("an authentication choice this protocol does not define");
    const dn = text(name), password = text(auth);
    if (dn === "" && password === "") {
      this.bound = "";
      this.log("requests", { event: "ldap bind", peer: this.peer, as: "anonymous" });
      return answer(RESULT.success);
    }
    // "an unauthenticated bind": a name without a password (RFC 4513 section 5.1.2).
    if (password === "") return answer(RESULT.unwillingToPerform, "a name is bound with its password");
    // "A resultCode of invalidDNSyntax indicates that the DN sent in the name value
    // is syntactically invalid. A resultCode of invalidCredentials indicates that
    // the DN is syntactically correct but not valid for purposes of
    // authentication" (RFC 4513 §5.1.3). The two used to be one answer, so a client
    // whose DN this server could not read was told its credentials were wrong and
    // retried passwords against a name that was never parsed.
    if (parseDn(dn) === undefined) {
      this.log("problems", { event: "ldap bind refused", peer: this.peer, name: dn,
        reason: "not a distinguished name" });
      return answer(RESULT.invalidDNSyntax,
        "the name is not a distinguished name: a value containing a comma, plus, equals, " +
        "quote, backslash, semicolon or angle bracket has it escaped with a backslash (RFC 4514)");
    }
    const user = this.userOf(dn);
    // A user locked by failures, at LDAP or at the token endpoint, is refused
    // without the password being checked (throttle.ts).
    if (user !== undefined && this.throttle.locked("user", user)) {
      this.log("problems", { event: "ldap bind refused", peer: this.peer, name: dn, reason: "locked" });
      return answer(RESULT.invalidCredentials);
    }
    const verdict = this.directory().verify(user ?? "", password);
    if (user !== undefined) {
      const reason = verdict.ok ? "" : (verdict as { reason: string }).reason;
      this.throttle.record("user", user, verdict.ok || reason === "disabled" || reason === "expired");
    }
    if (user === undefined || !verdict.ok) {
      // Which it was is the log's; the client is told only that it failed.
      this.log("problems", { event: "ldap bind refused", peer: this.peer, name: dn,
        reason: user === undefined ? "not a user's name" : (verdict as { reason: string }).reason });
      return answer(RESULT.invalidCredentials);
    }
    this.bound = verdict.user.name;
    this.log("requests", { event: "ldap bind", peer: this.peer, as: verdict.user.name });
    return answer(RESULT.success);
  }

  /** The user a bind name names: uid=<name>,ou=people,<base>, compared without case. */
  private userOf(dn: string): string | undefined {
    const rdns = simpleDn(dn);
    if (rdns === undefined || rdns === "multi" || rdns.length < 2 || rdns[0][0] !== "uid") return undefined;
    // Beneath ou=people of this realm, at **any** depth: a principal in an
    // organizational unit is published at uid=ann,ou=platform,ou=eng,ou=people,
    // <base> (§5 of DESIGN-admin.md), and this used to require exactly
    // uid=<name>,ou=people,<base>. So the standard "search for the entry, then bind
    // as the DN it gave you" flow could not authenticate any user in a unit at all
    // — it was answered invalidCredentials with the right password. Found by
    // reading RFC 4513 §5.1.3 against what `entries()` publishes.
    const under = parseDn(`ou=people,${baseOf(this.domain)}`)!;
    const whole = parseDn(dn);
    if (whole === undefined || !beneath(whole, under)) return undefined;
    const found = this.directory().user(rdns[0][1]);
    if (found === undefined) return undefined;
    // And at the one place the directory puts it: a name is unique in this realm,
    // so a DN naming the right user in the wrong unit is not that user's name.
    const where = this.directory().unitOf(found.name);
    const wanted = parseDn(`uid=${found.name},${within(where, `ou=people,${baseOf(this.domain)}`)}`);
    return wanted !== undefined && sameDn(whole, wanted) ? found.name : undefined;
  }

  private search(op: Element): Buffer[] {
    const [baseEl, scopeEl, , sizeEl, , typesOnlyEl, filter, attrsEl] = children(op.content);
    if (baseEl?.tag !== T.OCTET_STRING || scopeEl?.tag !== T.ENUMERATED || sizeEl?.tag !== T.INTEGER ||
        typesOnlyEl?.tag !== T.BOOLEAN || filter === undefined || attrsEl?.tag !== T.SEQUENCE) {
      throw new BerError("a search request holds a base, a scope, a deref, limits, typesOnly, a filter and attributes");
    }
    const done = (code: number, why = "", matched = "") => seq(result(code, why, matched), OP.searchResultDone);
    const scope = integer(scopeEl);
    if (scope < 0 || scope > 2) throw new BerError("a scope is baseObject, singleLevel or wholeSubtree");
    // The root DSE, read before a bind. "Clients SHOULD NOT assume that the root
    // DSE is readable without authentication" says only that a client may be
    // refused; a client has to read supportedSASLMechanisms to know how to
    // authenticate at all, so refusing it would leave a client no way in. It is
    // served to an unbound session, and it holds nothing of the directory.
    const asked0 = children(attrsEl.content).map((a) => text(a).toLowerCase());
    if (text(baseEl) === "" && scope === 0) {
      const dse = rootDse(this.domain, this.mechanisms(), this.version, this.extensions());
      const found = evaluate(dse, filter) === true ? [dse] : [];
      this.log("requests", { event: "ldap search", peer: this.peer, as: this.bound ?? "anonymous",
        base: "the root DSE", found: found.length });
      return [...this.entriesOut(found, asked0, boolean(typesOnlyEl)), done(RESULT.success)];
    }
    if (!this.bound) return [done(RESULT.insufficientAccessRights, "a session searches once it has bound as a user")];
    const base = parseDn(text(baseEl));
    const all = entries(this.directory(), this.domain, this.directMemberOf, this.domainSid);
    // Each entry's name parsed once: scope is decided structurally, by comparing
    // sequences of RDNs, and not by comparing the tails of two strings. A string
    // comparison has to decide what a comma means, and a value may hold one.
    const named = all.map((e) => ({ entry: e, dn: parseDn(e.dn)! }));
    if (base === undefined || !named.some((e) => sameDn(e.dn, base))) {
      // "the matchedDN field is set ... to the name of the last entry (object or
      // alias) used in finding the target (or base) object. This will be a
      // truncated form of the provided name" (RFC 4511 §4.1.9). The **deepest**
      // ancestor that exists, therefore, and not the realm's base: a client asking
      // for uid=nobody,ou=eng,ou=people,<base> was sent back to <base> and had to
      // walk down again, when ou=eng,ou=people,<base> is where its name ran out.
      let matched = "";
      if (base !== undefined) {
        for (const e of named) {
          if (!beneath(base, e.dn)) continue;
          const better = matched === "";
          if (better || e.dn.length > parseDn(matched)!.length) matched = e.entry.dn;
        }
      }
      return [done(RESULT.noSuchObject, `${text(baseEl)} is not an entry of this directory`, matched)];
    }
    // The base first, for a subtree, then the entries beneath it.
    const inScope = (scope === 2 ? named.filter((e) => sameDn(e.dn, base)) : []).concat(named.filter((e) => {
      if (scope === 0) return sameDn(e.dn, base);
      if (!beneath(e.dn, base)) return false;
      return scope === 2 || e.dn.length === base.length + 1;
    })).map((e) => e.entry);
    // Returned where the filter is TRUE; FALSE and Undefined are ignored alike.
    const found = inScope.filter((e) => evaluate(e, filter) === true);
    const limit = integer(sizeEl);
    const out = this.entriesOut(found.slice(0, limit > 0 ? limit : undefined), asked0, boolean(typesOnlyEl));
    this.log("requests", { event: "ldap search", peer: this.peer, as: this.bound, base: text(baseEl), found: found.length });
    if (limit > 0 && found.length > limit) out.push(done(RESULT.sizeLimitExceeded));
    else out.push(done(RESULT.success));
    return out;
  }

  /**
   * Whether a search request is the one for the root DSE: the empty name, base
   * scope (RFC 4512 §5.1). It is the one read a session with no TLS layer may do,
   * since a client has to read `supportedExtension` to learn that StartTLS is there.
   */
  private isRootDse(op: Element): boolean {
    try {
      const [baseEl, scopeEl] = children(op.content);
      return baseEl?.tag === T.OCTET_STRING && text(baseEl) === ""
        && scopeEl?.tag === T.ENUMERATED && integer(scopeEl) === 0;
    } catch {
      return false;
    }
  }

  /**
   * The Compare operation (RFC 4511 §4.10): "compareTrue indicates that the
   * assertion value in the ava field matches a value of the attribute or subtype
   * according to the attribute's EQUALITY matching rule. compareFalse indicates
   * that the assertion value in the ava field and the values of the attribute or
   * subtype did not match. Other result codes indicate either that the result of
   * the comparison was Undefined (Section 4.5.1.7), or that some error occurred."
   *
   * So three answers and not two, and the Undefined case is the interesting one:
   * a type this directory does not recognize is `undefinedAttributeType`, and an
   * assertion value that is not a value of the type's syntax is
   * `invalidAttributeSyntax`. Answering compareFalse for either would tell a client
   * "that is not the value" where the truth is "that question has no answer here".
   *
   * The matching rule is `equalityMatch`, the same function the search filter uses,
   * so the two cannot drift apart.
   */
  private compare(op: Element): Buffer {
    const answer = (code: number, why = "") => seq(result(code, why), OP.compareResponse);
    // CompareRequest ::= [APPLICATION 14] SEQUENCE { entry LDAPDN, ava AttributeValueAssertion }
    const [dnEl, avaEl] = children(op.content);
    if (dnEl?.tag !== T.OCTET_STRING || avaEl?.tag !== T.SEQUENCE) {
      throw new BerError("a compare request holds an entry name and an attribute value assertion");
    }
    const [typeEl, valueEl, ...rest] = children(avaEl.content);
    if (typeEl?.tag !== T.OCTET_STRING || valueEl?.tag !== T.OCTET_STRING || rest.length > 0) {
      throw new BerError("an attribute value assertion holds a type and a value");
    }
    if (!this.bound) {
      return answer(RESULT.insufficientAccessRights, "a session compares once it has bound as a user");
    }
    const dn = text(dnEl), type = text(typeEl), value = text(valueEl);
    const wanted = parseDn(dn);
    if (wanted === undefined) {
      return answer(RESULT.invalidDNSyntax, `${JSON.stringify(dn)} is not a distinguished name`);
    }
    const all = entries(this.directory(), this.domain, this.directMemberOf, this.domainSid);
    const found = all.find((e) => sameDn(parseDn(e.dn)!, wanted));
    if (found === undefined) {
      // "The server SHALL NOT dereference any aliases in locating the entry to be
      // compared", and a name that is not an entry is noSuchObject with the
      // matchedDN §4.1.9 asks for, as a search's is.
      let matched = "";
      for (const e of all) {
        const at = parseDn(e.dn)!;
        if (beneath(wanted, at) && (matched === "" || at.length > parseDn(matched)!.length)) matched = e.dn;
      }
      return seq(result(RESULT.noSuchObject, `${dn} is not an entry of this directory`, matched),
        OP.compareResponse);
    }
    const t = describedType(type);
    if (t === undefined) {
      // RFC 4512 §2.5: an unrecognized option makes the whole description
      // unrecognized, which for a Compare is the same answer an unrecognized type
      // gets (RFC 4511 Appendix A, undefinedAttributeType: "a request field
      // contains an unrecognized attribute description").
      return answer(RESULT.undefinedAttributeType,
        `${type} carries an attribute option this server does not recognize, so the whole ` +
        `description is unrecognized (RFC 4512 section 2.5); it recognizes ` +
        `${[...OPTIONS].sort().map((o) => `;${o}`).join(", ")}`);
    }
    if (!RECOGNIZED.has(t)) {
      return answer(RESULT.undefinedAttributeType,
        `${type} is not an attribute type this directory recognizes, so the comparison has no ` +
        `answer; those it compares are ${[...RECOGNIZED].sort().join(", ")}`);
    }
    const verdict = equalityMatch(found, type, value);
    if (verdict === undefined) {
      return answer(RESULT.invalidAttributeSyntax,
        `${JSON.stringify(value)} is not a value of ${type}, so the comparison has no answer`);
    }
    this.log("requests", { event: "ldap compare", peer: this.peer, as: this.bound, dn, type,
      answer: verdict });
    return answer(verdict ? RESULT.compareTrue : RESULT.compareFalse);
  }

  /**
   * The entries of a result, with the attributes a client asked for.
   *
   * "A list of the attributes to be returned ... an empty list requests the
   * return of all user attributes", "*" the same, "1.1" none at all, and "+" all
   * operational attributes (RFC 4511 section 4.5.1.8, RFC 3673). A user
   * attribute is not returned for "+" and an operational one is not returned for
   * "*": each is asked for by its own token, or by name.
   */
  private entriesOut(found: Entry[], asked: string[], typesOnly: boolean): Buffer[] {
    const everyUser = asked.length === 0 || asked.includes("*");
    const everyOperational = asked.includes("+");
    // "1.1" is the null OID: "an OID of 1.1 ... indicates that no attributes are
    // to be returned". Listed beside a name it is simply not an attribute type.
    const none = asked.length === 1 && asked[0] === "1.1";
    // The selection list holds attribute *descriptions*, which may carry options:
    // RFC 4511 §4.5.1.8 takes "attributeSelector = attributedescription /
    // selectorspecial", and RFC 4523 §4.1 makes `userCertificate;binary` the
    // required form for a certificate. Matching the whole description meant the one
    // form that specification requires selected nothing, with no way for a client to
    // tell "not supported" from "no value".
    //
    // A description whose option this server does not recognize is unrecognized
    // whole (RFC 4512 §2.5), and §4.5.1.8 says what a selection list does with one:
    // "If an attribute description in the list is not recognized, it is ignored by
    // the server." So it is dropped here rather than contributing its bare type —
    // which is what it used to do, and which is the SHALL of §2.5 broken.
    const bare = asked.map((a) => describedType(a)).filter((t) => t !== undefined);
    const wanted = (type: string): boolean => {
      if (none) return false;
      const t = type.toLowerCase();
      if (bare.includes(t)) return true;
      // "Attributes that are subtypes of listed attributes are implicitly
      // included" (§4.5.1.8). `cn`, `sn` and `ou` are subtypes of `name` (RFC 4519
      // §2, where each is `SUP name`) and `member` of `distinguishedName`, so a
      // client that asks for the supertype is given them. Nothing did this, so
      // `ldapsearch … name` came back empty from entries that hold three of them.
      if ((SUBTYPES_OF[t] ?? []).some((sub) => bare.includes(sub))) return true;
      return OPERATIONAL.has(t) ? everyOperational : everyUser;
    };
    return found.map((e) => {
      const attrs = Object.entries(e.attrs).filter(([k]) => wanted(k));
      return seq([octets(e.dn), seq(attrs.map(([k, vs]) =>
        seq([octets(k), seq(typesOnly ? [] : vs.map((v) => octets(v)), T.SET)])))],
      OP.searchResultEntry);
    });
  }

  /**
   * A write: add, delete, modify or modify-DN, translated into a call on the one
   * write path and its refusal into a result code. No rule of the realm is
   * decided here (DESIGN-admin.md §2).
   */
  private async write(op: Element): Promise<Buffer> {
    const w = this.writes!;
    const answer = (code: number, why = "") => seq(result(code, why), WRITES[op.tag]);
    let act: () => Promise<void>;
    let what: Record<string, unknown>;
    if (op.tag === ADD) {
      // AddRequest ::= [APPLICATION 8] SEQUENCE { entry LDAPDN, attributes AttributeList }
      const [dnEl, attrsEl] = children(op.content);
      if (dnEl?.tag !== T.OCTET_STRING || attrsEl?.tag !== T.SEQUENCE) {
        throw new BerError("an add request holds an entry name and its attributes");
      }
      const attrs = children(attrsEl.content).map((a) => {
        const [typeEl, valsEl] = children(a.content);
        if (typeEl?.tag !== T.OCTET_STRING || valsEl?.tag !== T.SET) {
          throw new BerError("an attribute holds a type and a set of values");
        }
        const vals = children(valsEl.content);
        // `raw` beside `values` because an attribute value is a sequence of octets
        // and only some attributes hold text. A userCertificate carries DER, and
        // decoding DER as UTF-8 replaces every octet that is not valid UTF-8 with
        // U+FFFD — irreversibly. The fingerprint recorded for a certificate sent in
        // its DER form was therefore not that certificate's fingerprint, so the
        // credential could never authenticate it and a later delete of the same
        // value was refused. The PEM form, being ASCII, was unaffected, which is why
        // every test passed. Found by reading RFC 4523 §2.1: "values of this syntax
        // and the form of each value MUST be preserved as presented."
        return { type: text(typeEl), values: vals.map((v) => text(v)), raw: vals.map((v) => v.content) };
      });
      const dn = text(dnEl);
      act = () => w.add(dn, attrs);
      what = { event: "ldap add", dn, types: attrs.map((a) => a.type) };
    } else if (op.tag === DELETE) {
      // DelRequest ::= [APPLICATION 10] LDAPDN — the name is the content itself.
      const dn = op.content.toString("utf8");
      act = () => w.remove(dn);
      what = { event: "ldap delete", dn };
    } else if (op.tag === MODIFY) {
      // ModifyRequest ::= [APPLICATION 6] SEQUENCE { object LDAPDN,
      //   changes SEQUENCE OF change SEQUENCE { operation ENUMERATED, modification PartialAttribute } }
      const [dnEl, changesEl] = children(op.content);
      if (dnEl?.tag !== T.OCTET_STRING || changesEl?.tag !== T.SEQUENCE) {
        throw new BerError("a modify request holds an entry name and its changes");
      }
      const changes: LdapChange[] = children(changesEl.content).map((c) => {
        const [opEl, modEl] = children(c.content);
        if (opEl?.tag !== T.ENUMERATED || modEl?.tag !== T.SEQUENCE) {
          throw new BerError("a change holds an operation and a modification");
        }
        const kind = integer(opEl);
        if (kind < 0 || kind > 2) throw new BerError("a change is add, delete or replace");
        const [typeEl, valsEl] = children(modEl.content);
        if (typeEl?.tag !== T.OCTET_STRING || valsEl?.tag !== T.SET) {
          throw new BerError("a modification holds a type and a set of values");
        }
        const vals = children(valsEl.content);
        return {
          operation: (["add", "delete", "replace"] as const)[kind],
          type: text(typeEl),
          values: vals.map((v) => text(v)),
          // See the note in the add above: text and octets are not the same thing.
          raw: vals.map((v) => v.content),
        };
      });
      const dn = text(dnEl);
      act = () => w.modify(dn, changes);
      what = { event: "ldap modify", dn, changes: changes.map((c) => `${c.operation} ${c.type}`) };
    } else {
      // ModifyDNRequest ::= [APPLICATION 12] SEQUENCE { entry LDAPDN, newrdn RelativeLDAPDN,
      //   deleteoldrdn BOOLEAN, newSuperior [0] LDAPDN OPTIONAL }
      const [dnEl, rdnEl, deleteEl, superiorEl] = children(op.content);
      if (dnEl?.tag !== T.OCTET_STRING || rdnEl?.tag !== T.OCTET_STRING || deleteEl?.tag !== T.BOOLEAN) {
        throw new BerError("a modify DN request holds an entry name, a new RDN and deleteoldrdn");
      }
      if (superiorEl !== undefined && superiorEl.tag !== (CONTEXT | 0)) {
        throw new BerError("the fourth element of a modify DN request is its new superior");
      }
      const dn = text(dnEl), rdn = text(rdnEl);
      const superior = superiorEl === undefined ? undefined : superiorEl.content.toString("utf8");
      const deleteOld = boolean(deleteEl);
      act = () => w.rename(dn, rdn, superior, deleteOld);
      what = { event: "ldap modify DN", dn, newRdn: rdn, ...(superior === undefined ? {} : { newSuperior: superior }) };
    }
    try {
      await act();
      this.log("requests", { ...what, peer: this.peer, as: this.bound });
      return answer(RESULT.success);
    } catch (e) {
      const { code, why } = w.codeOf(e);
      this.log("problems", { ...what, peer: this.peer, as: this.bound, refused: code, detail: why });
      return answer(code, why);
    }
  }

  /**
   * Password Modify (RFC 3062): the operation every LDAP client uses to change a
   * password, so that a user need not know that a password here becomes a scrypt
   * verifier and a Kerberos key for each enctype.
   *
   * A principal may change **its own** password whatever it bound as, and an
   * administrator may change any. "If the userIdentity field is not present, the
   * request is for the password of the user currently bound". A generated password
   * is not offered: this server would have to choose one, and a password it chose
   * would be returned over the connection and then be the only copy in existence.
   */
  private async passwordModify(valueEl: Element | undefined,
    answer: (code: number, why?: string, value?: Buffer) => Buffer): Promise<Buffer> {
    const w = this.writes!;
    if (!this.bound) {
      return answer(RESULT.insufficientAccessRights, "a password is changed by a session that has bound");
    }
    // PasswdModifyRequestValue ::= SEQUENCE { userIdentity [0] OPTIONAL,
    //   oldPasswd [1] OPTIONAL, newPasswd [2] OPTIONAL }
    let identity = "", oldPassword: string | undefined, newPassword: string | undefined;
    if (valueEl !== undefined && valueEl.content.length > 0) {
      let inner;
      try {
        inner = readElement(valueEl.content, 0).el;
      } catch {
        return answer(RESULT.protocolError, "the request value is a PasswdModifyRequestValue");
      }
      if (inner.tag !== T.SEQUENCE) return answer(RESULT.protocolError, "the request value is a SEQUENCE");
      for (const f of children(inner.content)) {
        if (f.tag === (CONTEXT | 0)) identity = f.content.toString("utf8");
        else if (f.tag === (CONTEXT | 1)) oldPassword = f.content.toString("utf8");
        else if (f.tag === (CONTEXT | 2)) newPassword = f.content.toString("utf8");
        else return answer(RESULT.protocolError, "a field this request value does not define");
      }
    }
    if (newPassword === undefined || newPassword === "") {
      // "If the server is unwilling to generate a new password" — it is, and says so.
      return answer(RESULT.unwillingToPerform,
        "this server generates no password; the new password is given in the request");
    }
    // Whose password. An empty identity is the bound identity's own; an
    // administrator binds as no principal, so it has none of its own to change.
    const own = identity === "";
    if (own && this.isAdmin) {
      return answer(RESULT.unwillingToPerform,
        "an administrator is a certificate holder and has no password here; name the principal whose password is to be changed");
    }
    if (!own && !this.isAdmin) {
      // A principal may change its own and no other. The identity is compared as
      // a name of this directory rather than trusted as given.
      const named = this.userOfAuthzid(identity);
      if (named === undefined || named.toLowerCase() !== this.bound.toLowerCase()) {
        this.log("problems", { event: "ldap password modify refused", peer: this.peer, as: this.bound,
          identity, reason: "a principal changes its own password and no other" });
        return answer(RESULT.insufficientAccessRights,
          "a principal bound as itself changes its own password and no other");
      }
    }
    const whose = own ? this.bound : identity;
    // "If oldPasswd is present and the provided value cannot be verified or is
    // incorrect, the server SHALL NOT change the user password" (RFC 3062 section
    // 3). This is a SHALL and it is unconditional: it binds whoever asked, an
    // administrator holding a certificate as much as the principal itself. An
    // earlier version of this read oldPasswd, passed it to the write path and
    // never checked it, which let a client that sent the wrong current password
    // change the password anyway — the one outcome the sentence forbids.
    //
    // The check is made here rather than in the write path because it is a rule
    // of this protocol and not of the realm: dc-ldap-writes.ts translates and
    // holds no rule (DESIGN-admin.md §2). The named principal's own verifier is
    // what the value is compared against, so a disabled or expired account, or
    // one with no password at all, "cannot be verified" and is refused.
    if (oldPassword !== undefined) {
      const named = own ? this.bound : this.userOfAuthzid(identity);
      const verdict = named === undefined
        ? { ok: false as const, reason: "unknown" as const }
        : this.directory().verify(named, oldPassword);
      if (!verdict.ok) {
        this.log("problems", { event: "ldap password modify refused", peer: this.peer,
          as: this.bound, whose, reason: `the old password given ${verdict.reason === "password"
            ? "is incorrect" : `cannot be verified: the account is ${verdict.reason}`}` });
        return answer(RESULT.invalidCredentials,
          "the current password given with the request does not verify; the password is unchanged");
      }
    }
    try {
      // The identity is resolved here, not left to the write path to guess: where
      // the request named none, it is the principal this session bound as.
      await w.setPassword(own ? `u:${this.bound}` : identity, newPassword);
      this.log("requests", { event: "ldap password modify", peer: this.peer, as: this.bound, whose });
      return answer(RESULT.success);
    } catch (e) {
      const { code, why } = w.codeOf(e);
      this.log("problems", { event: "ldap password modify refused", peer: this.peer, as: this.bound,
        whose, refused: code, detail: why });
      return answer(code, why);
    }
  }

  /**
   * The principal an authzId or a distinguished name names, for Password Modify.
   * RFC 3062 leaves the form of userIdentity to the server; a client sends the
   * entry's name, and "dn:" and "u:" are the forms RFC 4513 defines for an
   * authorization identity, so all three are read.
   */
  private userOfAuthzid(identity: string): string | undefined {
    if (identity.startsWith("u:")) return this.directory().user(identity.slice(2))?.name;
    const dn = identity.startsWith("dn:") ? identity.slice(3) : identity;
    return this.userOf(dn);
  }

  /** The SASL mechanisms this server offers, which the root DSE reports. */
  private mechanisms(): string[] {
    return [
      // GSSAPI where the realm holds a key for this service (RFC 4752).
      ...(this.serviceKey?.() === undefined ? [] : ["GSSAPI"]),
      // EXTERNAL where an authority for administrators is configured *and* this
      // connection presented a certificate. RFC 4512 section 5.1: "a server
      // supporting the SASL EXTERNAL mechanism might only list 'EXTERNAL' when
      // the client's identity has been established by a lower level". Offering it
      // to a client with no certificate invites a bind that can only fail.
      ...(this.admin === undefined || !this.tls || this.certificate?.() === undefined
        ? [] : ["EXTERNAL"]),
    ];
  }
}
