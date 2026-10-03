// LDAP's write operations, translated into the one write path.
//
// DESIGN-admin.md §2: `dc-write.ts` is the only thing that writes, and "LDAP and
// SCIM are translations into that vocabulary and hold no rules of their own".
// This module is that translation for LDAP, and it is deliberately the only place
// that knows both an LDAP distinguished name and a `Writer` call.
//
// What the translation has to decide, and what it does:
//
//   * which entry a name denotes — a user under ou=people, a group under
//     ou=groups, a unit beneath either, by the tree ldap.ts serves;
//   * which object class a new entry is, from the classes of the request, since
//     an addRequest says what it is making and the store has three kinds;
//   * which attributes a client may write, since a POSIX number, a security
//     identifier and memberOf are this server's and not a client's;
//   * that `member` on the group is authoritative and `memberOf` is computed —
//     "the rule Active Directory has and every client expects" — so a change to
//     member becomes a change of membership rows and a write to memberOf is
//     refused;
//   * which result code a refusal is, so that a client can act on the failure
//     rather than retry it.

import {
  baseOf, describedType, expiryOfShadow, type LdapChange, type LdapWrites, RESULT, simpleDn,
} from "./ldap.ts";
import type { Fields } from "./dc-write.ts";
import { WriteError, Writer } from "./dc-write.ts";
import type { Kind } from "./dc-store.ts";

/** A refusal of this translation, carrying the result code a client is told. */
export class LdapWriteError extends Error {
  readonly code: number;
  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

/**
 * The attributes this server writes and a client does not. A write to one is
 * refused rather than ignored: a client that set uidNumber and was told success
 * would believe a number it does not have (DESIGN-admin.md §6).
 */
const SERVER_GENERATED = new Set([
  "objectsid", "uidnumber", "memberof", "createtimestamp", "modifytimestamp",
  "entryuuid", "entrydn", "hassubordinates", "subschemasubentry", "samaccountname",
]);

/**
 * `gidNumber` is server-generated on a **group**, whose POSIX number the store
 * allocates, and writable on a **user**, where it names the primary group whose
 * number it is. One name, two meanings, which is RFC 2307's doing rather than this
 * server's: §3 defines one attribute and §4's `posixAccount` and `posixGroup` both
 * MUST it.
 */
const GROUP_GENERATED = new Set(["gidnumber"]);

/**
 * The attributes of a user entry a client may write, by their lower-case names.
 * The home is written under either name, since the entry is served under both:
 * `homeDirectory`, which RFC 2307 section 3 defines and a UNIX client sends, and
 * `unixHomeDirectory`, which is Active Directory's. Accepting only the second,
 * as this did while only the second was served, refused the standard name.
 */
/**
 * `mail` is **not** here, and was. This directory keeps no mail address: there is no
 * column for one, nothing serves the attribute, and nothing resolves by it. It was
 * accepted on an Add, written nowhere, and absent when the client read the entry back
 * — success for a change that did not happen. Removed rather than implemented, because
 * a mail address is a field of this realm or it is not, and adding one quietly as part
 * of a bug fix would be the same mistake in the other direction. It is now
 * `noSuchAttribute`, whose message names what a client may write.
 */
const USER_WRITABLE = new Set(["objectclass", "uid", "cn", "sn", "displayname",
  "homedirectory", "unixhomedirectory", "userpassword", "usercertificate",
  // RFC 2307's shadowExpire, of the shadowAccount class, which is this directory's
  // `expires`. It had no LDAP representation at all until phase E: see
  // NOTES-on-ldap-writes.md §10.
  "shadowexpire",
  // gidNumber on a *user* names its primary group's number, which RFC 2307's
  // posixAccount MUSTs. It is server-generated for a group, whose number the store
  // allocates, so the two kinds differ — see SERVER_GENERATED and §7.
  "gidnumber"]);

/**
 * An attribute description without its transfer and tagging options: the type
 * before the first ";" (RFC 4512 §2.5 "AttributeDescription"). RFC 4523 §2.1 makes
 * `;binary` the *required* form for a certificate — "values of this syntax ... MUST
 * only be transferred using the ;binary transfer option [RFC4522]; that is, by
 * requesting and returning values using attribute descriptions such as
 * 'userCertificate;binary'" — and §4.1 says the same of this attribute by name.
 * While the whole description was lower-cased and looked up, the one form the
 * specification requires was refused as "an attribute of this entry" that does not
 * exist, so every PKI tool's write failed.
 */
const bareType = (description: string): string => {
  const t = describedType(description);
  if (t === undefined) {
    // RFC 4512 §2.5 again, and the other half of it: "Servers SHALL treat an
    // attribute description with an unrecognized attribute option as
    // unrecognized." A write naming one is refused rather than applied to the bare
    // type — `userPassword;x-foo` used to set the password.
    throw new LdapWriteError(RESULT.undefinedAttributeType,
      `${description} carries an attribute option this server does not recognize, so the ` +
      "whole description is unrecognized (RFC 4512 section 2.5)");
  }
  return t;
};

/** The two names the home of a principal is written under. */
const HOME = ["homedirectory", "unixhomedirectory"] as const;

/**
 * The attributes of a group entry a client may write.
 *
 * `description` is **not** here, and was. RFC 4519 §3.5 has `groupOfNames` MAY it, and
 * this directory keeps no description for a principal — only for an organizational
 * unit, which has a column for one. So an Add carrying it succeeded, kept nothing, and
 * served nothing back, while a Modify of the same attribute was refused: one field,
 * two answers, neither of them the truth. Refused in both now. Keeping a group
 * description is a reasonable thing to add and is a store column plus somewhere for
 * SCIM to put it (RFC 7643 §4.2 gives a Group no description either); it is recorded in
 * NOTES-on-ldap-writes.md rather than slipped in here.
 */
const GROUP_WRITABLE = new Set(["objectclass", "cn", "displayname", "member"]);

/** The attributes of an organizational unit a client may write. */
const UNIT_WRITABLE = new Set(["objectclass", "ou", "description"]);

/** An entry a write names: a principal or a unit, as against a container. */
type Entryish =
  | { what: "user"; name: string }
  | { what: "group"; name: string }
  | { what: "unit"; path: string };

/** What a name denotes in the tree this server serves. */
type Place =
  | { what: "user"; name: string }
  | { what: "group"; name: string }
  | { what: "unit"; path: string }
  | { what: "people" }
  | { what: "groups" }
  | { what: "base" };

export class LdapWriter implements LdapWrites {
  private readonly writer: () => Writer;
  private readonly domain: string;
  /** Called after each applied change, so the served directory is rebuilt. */
  private readonly rebuilt: () => Promise<void>;

  constructor(writer: () => Writer, domain: string, rebuilt: () => Promise<void>) {
    this.writer = writer;
    this.domain = domain;
    this.rebuilt = rebuilt;
  }

  // -------------------------------------------------------------------
  // Names

  /**
   * What a distinguished name denotes. The tree is the one ldap.ts serves: users
   * beneath ou=people, groups beneath ou=groups, and an organizational unit as a
   * path beneath either, so that `ou=platform,ou=eng,ou=people,<base>` is the
   * unit `eng/platform`. A name of any other shape denotes nothing, which is
   * `noSuchObject` for an operation on an entry and `invalidDNSyntax` where the
   * name cannot be read at all.
   */
  place(dn: string): Place {
    const rdns = simpleDn(dn);
    if (rdns === undefined) {
      throw new LdapWriteError(RESULT.invalidDNSyntax, `${JSON.stringify(dn)} is not a name this server reads`);
    }
    // A multi-valued RDN is a name this server *can* read and that denotes nothing
    // here, so it is noSuchObject and not invalidDNSyntax. The two used to be one
    // answer, and RFC 4513 §5.1.3 draws the line between them: invalidDNSyntax is
    // "the DN sent in the name value is syntactically invalid", and
    // invalidCredentials or noSuchObject is for a name that reads and denotes nothing.
    if (rdns === "multi") {
      throw new LdapWriteError(RESULT.noSuchObject,
        `${dn} names an entry by a multi-valued relative distinguished name, and this ` +
        "directory names a user by uid alone, a group by cn and a unit by ou");
    }
    const base = simpleDn(baseOf(this.domain)) as [string, string][];
    if (rdns.length < base.length) {
      throw new LdapWriteError(RESULT.noSuchObject, `${dn} is not beneath ${baseOf(this.domain)}`);
    }
    for (let i = 0; i < base.length; i++) {
      const at = rdns[rdns.length - base.length + i];
      if (at[0] !== base[i][0] || at[1].toLowerCase() !== base[i][1].toLowerCase()) {
        throw new LdapWriteError(RESULT.noSuchObject, `${dn} is not beneath ${baseOf(this.domain)}`);
      }
    }
    const above = rdns.slice(0, rdns.length - base.length);
    if (above.length === 0) return { what: "base" };
    // The container is the last RDN above the base: ou=people or ou=groups.
    const container = above[above.length - 1];
    if (container[0] !== "ou" || !["people", "groups"].includes(container[1].toLowerCase())) {
      throw new LdapWriteError(RESULT.noSuchObject,
        `${dn} is not beneath ou=people or ou=groups of ${baseOf(this.domain)}`);
    }
    const within = above.slice(0, above.length - 1);
    const isPeople = container[1].toLowerCase() === "people";
    if (within.length === 0) return isPeople ? { what: "people" } : { what: "groups" };
    const leaf = within[0];
    // Every RDN between the leaf and the container is a unit, outermost last.
    const units = within.slice(1);
    if (units.some((r) => r[0] !== "ou")) {
      throw new LdapWriteError(RESULT.noSuchObject, `${dn} names something between an entry and its container`);
    }
    const path = [...units].reverse().map((r) => r[1]);
    if (leaf[0] === "ou") {
      return { what: "unit", path: [...path, leaf[1]].join("/") };
    }
    if (isPeople && leaf[0] === "uid") return { what: "user", name: leaf[1] };
    if (!isPeople && leaf[0] === "cn") return { what: "group", name: leaf[1] };
    throw new LdapWriteError(RESULT.noSuchObject,
      `${dn} names an entry by ${leaf[0]}, and a user is named by uid and a group by cn`);
  }

  /**
   * The unit a new entry's name puts it in, and the container it sits under. A
   * unit of a name that does not exist is `noSuchObject`: this server creates no
   * parent on the way, as RFC 4511 §4.7 requires — "The immediate superior (parent)
   * of an object or alias entry to be added MUST exist" — and the same section's
   * worked example settles the result code and the `matchedDN` too: "if the client
   * attempted to add <CN=JS,DC=Example,DC=NET>, the <DC=Example,DC=NET> entry did
   * not exist, and the <DC=NET> entry did exist, then the server would return the
   * noSuchObject result code with the matchedDN field containing <DC=NET>".
   *
   * This used to cite "the server SHALL NOT ... create the superior", which is not
   * a sentence RFC 4511 contains. The behaviour was right and the quote invented.
   */
  private unitOf(dn: string): string | undefined {
    const rdns = simpleDn(dn) as [string, string][];
    const base = simpleDn(baseOf(this.domain)) as [string, string][];
    const above = rdns.slice(0, rdns.length - base.length);
    const units = above.slice(1, above.length - 1);
    if (units.length === 0) return undefined;
    return [...units].reverse().map((r) => r[1]).join("/");
  }

  // -------------------------------------------------------------------
  // The operations

  async add(dn: string, attrs: { type: string; values: string[]; raw: Buffer[] }[]): Promise<void> {
    const where = this.place(dn);
    const w = this.writer();
    const by = new Map<string, string[]>();
    // The same values as octets, for an attribute that does not hold text: a
    // userCertificate carries DER. See the note on `fingerprintOf`.
    const octets = new Map<string, Buffer[]>();
    const isGroupEntry = where.what === "group";
    for (const a of attrs) {
      const t = bareType(a.type);
      if (SERVER_GENERATED.has(t) || (isGroupEntry && GROUP_GENERATED.has(t))) {
        throw new LdapWriteError(RESULT.constraintViolation,
          `${a.type} is set by this server and not by a client`);
      }
      // RFC 4512 §2.5: "All attributes of an entry must have distinct attribute
      // descriptions." Note *descriptions*, not types, so `cn` and `cn;binary`
      // alongside each other are two distinct descriptions and a strict reading
      // permits them; this server admits one option and compares the type, which is
      // stricter than the rule and is the safe direction to err in.
      //
      // This used to cite RFC 4511 for "the attribute list ... SHALL NOT contain
      // the same attribute type twice", which RFC 4511 does not say anywhere.
      if (by.has(t)) {
        throw new LdapWriteError(RESULT.invalidAttributeSyntax, `${a.type} is given twice`);
      }
      if (a.values.length === 0) {
        throw new LdapWriteError(RESULT.invalidAttributeSyntax, `${a.type} is given with no value`);
      }
      by.set(t, a.values);
      octets.set(t, a.raw);
    }
    const classes = (by.get("objectclass") ?? []).map((c) => c.toLowerCase());
    if (classes.length === 0) {
      throw new LdapWriteError(RESULT.objectClassViolation, "an entry is added with its objectClass");
    }
    const isUnit = classes.includes("organizationalunit");
    const isGroup = classes.includes("groupofnames");
    const isUser = classes.includes("inetorgperson") || classes.includes("person") ||
      classes.includes("organizationalperson") || classes.includes("posixaccount");
    if ([isUnit, isGroup, isUser].filter((x) => x).length !== 1) {
      throw new LdapWriteError(RESULT.objectClassViolation,
        "an entry is an organizationalUnit, a groupOfNames or an inetOrgPerson, and the " +
        "objectClass given names none of them or more than one");
    }
    if (where.what === "unit" && !isUnit) {
      throw new LdapWriteError(RESULT.objectClassViolation, `${dn} names an organizational unit`);
    }
    if (where.what === "user" && !isUser) {
      throw new LdapWriteError(RESULT.objectClassViolation, `${dn} is beneath ou=people and names a user`);
    }
    if (where.what === "group" && !isGroup) {
      throw new LdapWriteError(RESULT.objectClassViolation, `${dn} is beneath ou=groups and names a group`);
    }
    if (where.what !== "unit" && where.what !== "user" && where.what !== "group") {
      throw new LdapWriteError(RESULT.entryAlreadyExists, `${dn} is an entry this server holds already`);
    }
    const allowed = isUnit ? UNIT_WRITABLE : (isGroup ? GROUP_WRITABLE : USER_WRITABLE);
    for (const t of by.keys()) {
      if (!allowed.has(t)) {
        throw new LdapWriteError(RESULT.noSuchAttribute,
          `${t} is not an attribute of this entry; the ones a client writes are ${[...allowed].sort().join(", ")}`);
      }
    }
    const one = (t: string): string | undefined => {
      const vs = by.get(t);
      if (vs === undefined) return undefined;
      if (vs.length !== 1) {
        throw new LdapWriteError(RESULT.constraintViolation, `${t} holds one value`);
      }
      return vs[0];
    };
    // **All of it or none.** An Add is one operation and creates more than one row: a
    // principal, then its members or its certificates and its password. Without the
    // transaction, an Add whose certificate was already another principal's created the
    // user and then failed — and the client was told it had failed, so the entry it
    // believes does not exist, does. RFC 4511 §3: "Each operation is processed as an
    // atomic action, leaving the directory in a consistent state."
    //
    // This is the defect phase D′ found in Modify (§6 of NOTES-on-ldap-writes.md), in
    // the operation nobody then checked. It hid the same way: every test added an entry
    // whose parts all succeeded, because that is how a test gets written, and the
    // guarantee is about the ones that do not.
    await this.apply(() => w.atomic(async () => {
      if (where.what === "unit") {
        const parts = where.path.split("/");
        const named = one("ou");
        if (named !== undefined && named.toLowerCase() !== parts[parts.length - 1].toLowerCase()) {
          throw new LdapWriteError(RESULT.notAllowedOnRDN,
            `the ou attribute is ${named} and the name says ${parts[parts.length - 1]}`);
        }
        w.createUnit(parts[parts.length - 1], parts.length > 1 ? parts.slice(0, -1).join("/") : undefined,
          one("description"));
        return;
      }
      const kind: Kind = isGroup ? "group" : "user";
      const name = where.what === "user" || where.what === "group" ? where.name : "";
      // The naming attribute has to agree with the name: "the entry's relative
      // distinguished name ... SHALL be the value of the naming attribute".
      const naming = one(kind === "user" ? "uid" : "cn");
      if (naming !== undefined && naming.toLowerCase() !== name.toLowerCase()) {
        throw new LdapWriteError(RESULT.notAllowedOnRDN,
          `the naming attribute is ${naming} and the name says ${name}`);
      }
      // `cn` and `sn` on a user entry are **served from the name** — the entry carries
      // `uid`, `cn` and `sn` all equal to it — so a value that disagrees cannot be
      // kept. It used to be accepted and dropped: an Add with `sn: Example` succeeded
      // and the entry read back `sn: ann`, a different value under the same attribute
      // the client had just written. Refused now, with the same message the naming
      // attribute gets.
      //
      // They cannot simply be left out of the writable set, which is what `mail` and a
      // group's `description` got: `person` is `MUST ( sn $ cn )` (RFC 4519 §3.9) and
      // `inetOrgPerson` derives from it, so an Add that conforms to the schema this
      // server publishes **has** to carry both, and refusing them outright would make
      // a conforming Add impossible. Agreeing with the name is the only value they can
      // take, so that is what is required.
      if (kind === "user") {
        for (const t of ["cn", "sn"]) {
          const given = one(t);
          if (given !== undefined && given.toLowerCase() !== name.toLowerCase()) {
            throw new LdapWriteError(RESULT.constraintViolation,
              `${t} is served from this entry's name, so it is ${name} and not ` +
              `${JSON.stringify(given)}`);
          }
        }
      }
      const unit = this.unitOf(dn);
      const fields: Fields = {
        ...(unit === undefined ? {} : { ou: unit }),
        // gidNumber on a user names its primary group by that group's number, which
        // is how RFC 2307 expresses the relation: §3 has one attribute and
        // posixAccount MUSTs it. The group is resolved from the number here, since
        // the store holds the group and not a copy of its number.
        ...(one("gidnumber") === undefined
          ? {} : { primaryGroup: this.groupWithNumber(one("gidnumber")!) }),
        ...(one("displayname") === undefined ? {} : { displayName: one("displayname")! }),
        ...(HOME.map(one).find((h) => h !== undefined) === undefined
          ? {}
          : { home: HOME.map(one).find((h) => h !== undefined)! }),
        // shadowExpire of RFC 2307's shadowAccount, in whole days since the epoch.
        ...(one("shadowexpire") === undefined
          ? {} : { expires: this.expiry(one("shadowexpire")!) }),
      };
      w.create(kind, name, fields);
      // The members of a new group, and the certificates of a new user, in the
      // same change: an add is one operation and either all of it or none.
      const members = by.get("member")?.filter((m) => m !== "");
      if (members !== undefined && members.length > 0) {
        w.setMembers(name, members.map((m) => this.memberName(m)));
      }
      for (const c of octets.get("usercertificate") ?? []) this.certificate(w, name, c);
      const password = one("userpassword");
      if (password !== undefined) await w.setPassword(w.principal(name).id, password);
    }));
  }

  async remove(dn: string): Promise<void> {
    const where = this.place(dn);
    const w = this.writer();
    await this.apply(async () => {
      if (where.what === "unit") return w.deleteUnit(where.path);
      if (where.what === "user" || where.what === "group") {
        // A group a principal is in loses the membership with it, which the store
        // does by its own cascade; a group that other entries name as a member is
        // deleted and its memberships go with it.
        return await w.remove(w.principal(where.name).id);
      }
      throw new LdapWriteError(RESULT.unwillingToPerform,
        `${dn} is a container this server serves and does not delete`);
    });
  }

  async modify(dn: string, changes: LdapChange[]): Promise<void> {
    const where = this.place(dn);
    const w = this.writer();
    if (where.what !== "user" && where.what !== "group" && where.what !== "unit") {
      throw new LdapWriteError(RESULT.unwillingToPerform,
        `${dn} is a container this server serves and does not modify`);
    }
    for (const c of changes) {
      const t = bareType(c.type);
      if (SERVER_GENERATED.has(t) || (where.what === "group" && GROUP_GENERATED.has(t))) {
        // memberOf is the one a client is most likely to try, so it is named.
        throw new LdapWriteError(RESULT.constraintViolation,
          t === "memberof"
            ? "memberOf is computed from the member attribute of each group; change member on the group"
            : `${c.type} is set by this server and not by a client`);
      }
      if (t === "objectclass") {
        throw new LdapWriteError(RESULT.constraintViolation,
          "the objectClass of an entry is not changed; delete it and add what it is to be");
      }
      // The same writable set an Add is held to. It was applied on an Add and **not
      // on a Modify**, so one request got two answers depending on which operation
      // carried it: `homeDirectory` on a group was `noSuchAttribute` (16) with a
      // message naming what a client may write, and the same attribute in a Modify
      // fell through to a branch that does not look at the kind, reached the write
      // path, and came back as `invalidAttributeSyntax` (21) — a code about a *value*,
      // for a request whose value was fine. Found by checking the group-field refusals
      // over a live socket after the read-side conformance test added them.
      const allowed = where.what === "unit"
        ? UNIT_WRITABLE
        : (where.what === "group" ? GROUP_WRITABLE : USER_WRITABLE);
      if (!allowed.has(t)) {
        throw new LdapWriteError(RESULT.noSuchAttribute,
          `${c.type} is not an attribute of this entry; the ones a client writes are ` +
          `${[...allowed].sort().join(", ")}`);
      }
    }
    // All of the changes or none, which RFC 4511 §4.6 states twice. Of the list:
    // "the resulting entry after the entire list of modifications is performed MUST
    // conform to the requirements of the directory model and controlling schema",
    // and of the response: "Due to the requirement for atomicity in applying the
    // list of modifications in the Modify Request, the client may expect that no
    // modifications of the DIT have been performed if the Modify Response received
    // indicates any sort of error, and that all requested modifications have been
    // performed if the Modify Response indicates successful completion." §3 puts it
    // generally: "Each operation is processed as an atomic action, leaving the
    // directory in a consistent state."
    //
    // Each writer of dc-write.ts opens a transaction of its own, so without the
    // outer one a modify whose third change was refused left the first two applied,
    // and the entry a client read back was neither what it had nor what it asked
    // for — exactly what that sentence says a client may rely on not happening.
    await this.apply(() => w.atomic(async () => {
      for (const c of changes) await this.oneChange(w, where, c);
    }));
  }

  /** One change of a modify, applied in the order the request gives it. */
  private async oneChange(w: Writer, where: Entryish, c: LdapChange): Promise<void> {
    const t = bareType(c.type);
    const single = (): string => {
      if (c.values.length !== 1) {
        throw new LdapWriteError(RESULT.constraintViolation, `${c.type} holds one value`);
      }
      return c.values[0];
    };
    if (where.what === "unit") {
      if (t === "ou") {
        throw new LdapWriteError(RESULT.notAllowedOnRDN,
          "ou names this unit; a modify DN request renames it");
      }
      if (t !== "description") {
        throw new LdapWriteError(RESULT.noSuchAttribute,
          `${c.type} is not an attribute of an organizational unit this server changes; ` +
          "description is");
      }
      // The description the store keeps. A delete, or a replace with no value,
      // removes it: "a replace with no values deletes the entire attribute" (RFC
      // 4511 §4.6). An add where one is already there is a constraintViolation
      // rather than a silent overwrite, description being single-valued here.
      const removing = c.operation === "delete" || (c.operation === "replace" && c.values.length === 0);
      const held = w.unitAt(where.path).description;
      if (c.operation === "delete" && c.values.length > 0 && c.values[0] !== held) {
        throw new LdapWriteError(RESULT.noSuchAttribute,
          "that description is not the one recorded for this organizational unit");
      }
      if (c.operation === "add" && held !== undefined) {
        throw new LdapWriteError(RESULT.constraintViolation,
          "description holds one value here; replace it rather than adding a second");
      }
      w.moveUnit(where.path, { description: removing ? null : single() });
      return;
    }
    const held = w.principal(where.name);
    const set = (fields: Fields) => void w.update(held.id, fields);
    if (t === "member") {
      if (where.what !== "group") {
        throw new LdapWriteError(RESULT.noSuchAttribute, "member is an attribute of a group");
      }
      const named = c.values.filter((v) => v !== "").map((v) => this.memberName(v));
      if (c.operation === "replace") return w.setMembers(where.name, named);
      for (const m of named) {
        if (c.operation === "add") w.addMember(where.name, m);
        else w.removeMember(where.name, m);
      }
      // "delete with no values deletes the entire attribute": every member.
      if (c.operation === "delete" && c.values.length === 0) w.setMembers(where.name, []);
      return;
    }
    if (t === "userpassword") {
      if (c.operation === "delete") {
        throw new LdapWriteError(RESULT.unwillingToPerform,
          "a password is changed and not removed; disable the account instead");
      }
      return await w.setPassword(held.id, single());
    }
    if (t === "usercertificate") {
      if (c.operation === "delete" && c.values.length === 0) {
        for (const cred of w.credentials(held.id).filter((x) => x.kind === "certificate")) {
          await w.removeCredential(cred.id);
        }
        return;
      }
      for (const v of c.raw) {
        if (c.operation === "delete") {
          const held2 = w.credentials(held.id)
            .find((x) => x.kind === "certificate" && x.material === fingerprintOf(v));
          if (held2 === undefined) {
            throw new LdapWriteError(RESULT.noSuchAttribute, "that certificate is not recorded for this entry");
          }
          await w.removeCredential(held2.id);
        } else {
          if (c.operation === "replace") {
            for (const cred of w.credentials(held.id).filter((x) => x.kind === "certificate")) {
              await w.removeCredential(cred.id);
            }
          }
          this.certificate(w, where.name, v);
        }
      }
      return;
    }
    // The single-valued fields of a principal. A delete, or a replace with no
    // value, removes one: "a replace with no values deletes the entire attribute".
    const removing = c.operation === "delete" || (c.operation === "replace" && c.values.length === 0);
    const value = removing ? null : single();
    if (t === "displayname") return set({ displayName: value });
    if ((HOME as readonly string[]).includes(t)) return set({ home: value });
    if (t === "gidnumber") {
      return set({ primaryGroup: value === null ? null : this.groupWithNumber(value) });
    }
    if (t === "shadowexpire") {
      // RFC 2307's shadowExpire, which is this directory's `expires` — days since
      // the epoch, so a value names a day and not an instant. A client writing one
      // and reading it back gets what it wrote; a value SCIM set at 17:00 reads
      // here as the start of that day, which the published DESC states.
      return set({ expires: value === null ? null : this.expiry(value) });
    }
    if (t === "uid" || t === "cn") {
      throw new LdapWriteError(RESULT.notAllowedOnRDN,
        `${c.type} names this entry; a modify DN request renames it`);
    }
    if (t === "sn") {
      // Served from the name, like `cn` and `uid` above it, so changing it is a
      // rename. `mail` and a group's `description` used to be refused here too, with
      // a message that ran the two cases together — "served from the entry's name or
      // is not kept by this directory" — and each is now handled where it belongs:
      // neither is an attribute a client may write at all, so the writable check
      // refuses them first, with `noSuchAttribute` and a message naming what it may.
      throw new LdapWriteError(RESULT.notAllowedOnRDN,
        `${c.type} is served from this entry's name; a modify DN request renames it`);
    }
    throw new LdapWriteError(RESULT.noSuchAttribute, `${c.type} is not an attribute this server changes`);
  }

  async rename(dn: string, newRdn: string, newSuperior: string | undefined, deleteOld: boolean): Promise<void> {
    const where = this.place(dn);
    const w = this.writer();
    const rdn = simpleDn(newRdn);
    if (rdn === undefined) {
      throw new LdapWriteError(RESULT.invalidDNSyntax, `${JSON.stringify(newRdn)} is not a name this server reads`);
    }
    if (rdn === "multi" || rdn.length !== 1) {
      throw new LdapWriteError(RESULT.unwillingToPerform,
        `${JSON.stringify(newRdn)} is one relative name of one attribute, which is how this ` +
        "directory names an entry");
    }
    // "deleteoldrdn ... FALSE ... the old RDN attribute value SHALL be retained
    // as a non-distinguished value of that attribute". This directory holds one
    // name for a principal, so keeping the old one is not something it can do.
    if (!deleteOld) {
      throw new LdapWriteError(RESULT.unwillingToPerform,
        "this directory holds one name for an entry, so the old name is not retained: " +
        "set deleteoldrdn");
    }
    const [type, value] = rdn[0];
    await this.apply(async () => {
      if (where.what === "unit") {
        if (type !== "ou") {
          throw new LdapWriteError(RESULT.notAllowedOnRDN, "an organizational unit is named by ou");
        }
        const to: { parent?: string | null; name?: string } = { name: value };
        if (newSuperior !== undefined) {
          const above = this.place(newSuperior);
          if (above.what === "unit") to.parent = above.path;
          else if (above.what === "people" || above.what === "groups") to.parent = null;
          else {
            throw new LdapWriteError(RESULT.noSuchObject,
              `${newSuperior} does not name a place an organizational unit is moved to`);
          }
        }
        w.moveUnit(where.path, to);
        return;
      }
      if (where.what !== "user" && where.what !== "group") {
        throw new LdapWriteError(RESULT.unwillingToPerform, `${dn} is a container this server does not rename`);
      }
      const wanted = where.what === "user" ? "uid" : "cn";
      if (type !== wanted) {
        throw new LdapWriteError(RESULT.notAllowedOnRDN,
          `a ${where.what} is named by ${wanted}, and the new name is given as ${type}`);
      }
      const held = w.principal(where.name);
      const fields: Fields = { name: value };
      if (newSuperior !== undefined) {
        const above = this.place(newSuperior);
        if (above.what === "unit") fields.ou = above.path;
        else if (above.what === "people" || above.what === "groups") fields.ou = null;
        else {
          throw new LdapWriteError(RESULT.noSuchObject, `${newSuperior} does not name a place an entry is moved to`);
        }
        // A user does not move into ou=groups, nor a group into ou=people: the
        // two containers are how this server tells them apart.
        const intoPeople = above.what === "people" || this.underPeople(newSuperior);
        if (intoPeople !== (where.what === "user")) {
          throw new LdapWriteError(RESULT.unwillingToPerform,
            `a ${where.what} is beneath ou=${where.what === "user" ? "people" : "groups"} and is not moved out of it`);
        }
      }
      w.update(held.id, fields);
    });
  }

  async setPassword(dn: string, newPassword: string): Promise<void> {
    const w = this.writer();
    // RFC 3062's oldPasswd is verified by the session before it calls this, which
    // section 3 makes a SHALL ("the server SHALL NOT change the user password").
    // It is checked there and not here because it is a rule of that protocol,
    // and this class translates names and holds no rule (DESIGN-admin.md §2).
    const name = dn === "" ? undefined : this.nameOf(dn);
    if (name === undefined) {
      throw new LdapWriteError(RESULT.noSuchObject, "the identity named is not a principal of this realm");
    }
    await this.apply(() => w.setPassword(w.principal(name).id, newPassword));
  }

  /** The principal an identity names, for Password Modify. */
  nameOf(identity: string): string | undefined {
    const plain = identity.startsWith("dn:") ? identity.slice(3) : identity;
    if (identity.startsWith("u:")) return identity.slice(2);
    try {
      const where = this.place(plain);
      return where.what === "user" || where.what === "group" ? where.name : undefined;
    } catch {
      return undefined;
    }
  }

  // -------------------------------------------------------------------
  // Helpers

  /** Whether a name is beneath ou=people, for the move check above. */
  private underPeople(dn: string): boolean {
    const rdns = simpleDn(dn);
    if (rdns === undefined || rdns === "multi") return false;
    return rdns.some((r) => r[0] === "ou" && r[1].toLowerCase() === "people");
  }

  /**
   * The group whose POSIX number a `gidNumber` value names. A number and not a
   * name, because that is what RFC 2307's attribute holds; the store keeps the
   * group, so that the user's gidNumber follows the group if the group's number
   * ever changes.
   */
  private groupWithNumber(value: string): string {
    if (!/^\d+$/.test(value)) {
      throw new LdapWriteError(RESULT.invalidAttributeSyntax,
        "gidNumber is an integer (RFC 2307 section 3)");
    }
    return this.writer().groupWithPosix(Number(value)).name;
  }

  /** The principal a member value names. */
  private memberName(value: string): string {
    const where = this.place(value);
    if (where.what !== "user" && where.what !== "group") {
      throw new LdapWriteError(RESULT.constraintViolation,
        `${value} is not the name of a user or a group of this realm`);
    }
    return where.name;
  }

  /** A shadowExpire value as an instant, or a refusal naming the syntax. */
  private expiry(value: string): Date {
    const when = expiryOfShadow(value);
    if (when === undefined) {
      throw new LdapWriteError(RESULT.invalidAttributeSyntax,
        `${JSON.stringify(value)} is not a shadowExpire: a whole number of days since 1 ` +
        "January 1970, not negative (RFC 2307 section 3 gives the type as INTEGER and no units)");
    }
    return when;
  }

  /** Records a certificate given as an attribute value. */
  private certificate(w: Writer, name: string, value: Buffer): void {
    const { fingerprint, der } = certificateOf(value);
    w.addCertificate(w.principal(name).id, fingerprint, undefined, der);
  }

  /**
   * Applies a change and rebuilds the directory. A refusal of the write path
   * becomes this module's, with the result code a client acts on; the directory is
   * rebuilt whether or not the change succeeded, since a change refused part way
   * through has rolled back and a rebuild is then simply the same directory.
   */
  private async apply(change: () => Promise<void> | void): Promise<void> {
    try {
      await change();
    } finally {
      await this.rebuilt();
    }
  }

  /** The result code and text a refusal becomes. */
  codeOf(e: unknown): { code: number; why: string } {
    if (e instanceof LdapWriteError) return { code: e.code, why: e.message };
    if (e instanceof WriteError) {
      const code = {
        invalid: RESULT.invalidAttributeSyntax,
        taken: RESULT.entryAlreadyExists,
        absent: RESULT.noSuchObject,
        conflict: RESULT.constraintViolation,
        limit: RESULT.constraintViolation,
      }[e.code] ?? RESULT.other;
      return { code, why: e.message };
    }
    // Anything else is this server's fault and is said as such rather than
    // reported as a client error the client could act on.
    return { code: RESULT.other, why: `this server could not apply the change: ${(e as Error).message}` };
  }
}

/**
 * The fingerprint a certificate value is recorded by. A client sends the
 * certificate itself in `userCertificate`, binary in LDAP and base 64 in LDIF;
 * the store holds a SHA-256 fingerprint, since that is what a TLS connection is
 * resolved by, alongside the certificate itself.
 */
export function fingerprintOf(raw: Buffer): string {
  return certificateOf(raw).fingerprint;
}

/**
 * A `userCertificate` value as this directory records it: the certificate's octets
 * and their SHA-256 fingerprint.
 *
 * The rule itself is `Writer.certificateValue`, in the module that writes, since
 * what a certificate value is is a rule of the realm and not of this translation
 * (DESIGN-admin.md §2). What remains here is the one thing that *is* LDAP's: the
 * result code a client acts on. A bare fingerprint — `sha256:` and sixty-four
 * hexadecimal digits — is not accepted. RFC 4523 §2.1: "A value of this syntax is
 * an X.509 Certificate", and this server publishes that syntax for the attribute,
 * so a seventy-one character ASCII string is not a value of it. It was accepted,
 * and the refusal text advertised it, which made the published syntax something a
 * client could not rely on.
 */
export function certificateOf(raw: Buffer): { fingerprint: string; der: Buffer } {
  try {
    return Writer.certificateValue(raw);
  } catch (e) {
    if (e instanceof WriteError) {
      throw new LdapWriteError(RESULT.invalidAttributeSyntax,
        "a userCertificate value is an X.509 certificate, in PEM or as its DER encoding " +
        "(RFC 4523 section 2.1)");
    }
    throw e;
  }
}
