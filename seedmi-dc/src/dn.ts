// Distinguished names: the string representation of RFC 4514, and the comparison
// rule of RFC 4517 section 4.2.15.
//
// This module exists because of a privilege escalation. `[admin].subjects` names
// the certificate subjects that may administer the realm, and a bind by SASL
// EXTERNAL compared the presented certificate's subject against them. Two
// mistakes met:
//
//   * the subject was built by joining Node's `getPeerCertificate().subject`
//     object with commas, which is not an encoding of a distinguished name — a
//     certificate holding the *single* attribute `CN=dcadmin,O=Example`, which is
//     a perfectly legal common name, produced the string `CN=dcadmin,O=Example`;
//   * the comparison split that string on commas, lower-cased, **sorted**, and
//     compared as a set, so RDN order did not matter either.
//
// Either one alone admits a certificate the configuration does not name. A
// controller was started with an administrator authority and two certificates
// issued by it — the real `CN=dcadmin/O=Example` and an attacker's single-attribute
// `CN=dcadmin,O=Example` — and the second bound as the administrator and deleted a
// principal. So: parse properly, compare properly, and take the subject from the
// certificate's DER rather than from a convenience object that has already thrown
// the structure away.
//
// RFC 4517 section 4.2.15 is the rule the old code got backwards:
//
//   The rule evaluates to TRUE if and only if the attribute value and the
//   assertion value have the same number of relative distinguished names and
//   corresponding relative distinguished names (by position) are the same. ...
//   The order of the AVAs is not significant.
//
// RDNs are a **sequence**, compared by position. Only the AVAs *within* one RDN
// are a set. A naive join cannot express a multi-valued RDN at all, which is why
// the subject is read from the DER here.

import { contentsOf, decodeOID, read, readAll, TAG } from "./der.ts";
import { prepare } from "./prepare.ts";

/** One attribute value assertion: a type and a value. */
export interface Ava {
  /** The attribute type, as written — a descriptor or a numeric object identifier. */
  type: string;
  /** The value, unescaped. */
  value: string;
  /**
   * True where the value came from the `#hexstring` form, whose octets are a BER
   * encoding rather than a string (RFC 4514 section 3). Such a value is compared
   * by its octets and never against a string form, since this program does not
   * decode arbitrary BER into the syntax the attribute type names.
   */
  binary?: boolean;
}

/** A relative distinguished name: one or more AVAs, joined by "+" in the string form. */
export type Rdn = Ava[];

/** The object identifiers of the attribute types a certificate subject uses (X.520). */
const SHORT: Record<string, string> = {
  "2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "serialNumber", "2.5.4.6": "C",
  "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.9": "STREET", "2.5.4.10": "O",
  "2.5.4.11": "OU", "2.5.4.12": "title", "2.5.4.41": "name", "2.5.4.42": "givenName",
  "2.5.4.43": "initials", "2.5.4.44": "generationQualifier", "2.5.4.46": "dnQualifier",
  "2.5.4.65": "pseudonym", "0.9.2342.19200300.100.1.1": "UID",
  "0.9.2342.19200300.100.1.25": "DC", "1.2.840.113549.1.9.1": "emailAddress",
};

/** Whether a character has to be escaped wherever it appears (RFC 4514 section 2.4). */
const ALWAYS = new Set(['"', "+", ",", ";", "<", ">", "\\", "\0"]);

/** The characters a backslash may escape on its own, rather than as a hex pair. */
const ESCAPABLE = new Set([" ", '"', "#", "+", ",", ";", "<", "=", ">", "\\"]);

/**
 * Parses the string representation of a distinguished name (RFC 4514 section 3).
 * Undefined where the string is not one — which is a different answer from "a
 * well-formed name that denotes nothing", and the two were conflated before: a
 * bind with an unparseable name was answered `invalidCredentials`, whose meaning
 * is "the DN *is* syntactically correct" (RFC 4513 section 5.1.3), so a client
 * retried passwords against a name this server could not read.
 */
export function parseDn(dn: string): Rdn[] | undefined {
  if (dn === "") return [];
  const rdns: Rdn[] = [];
  let rdn: Rdn = [];
  let at = 0;
  while (at < dn.length) {
    const ava = readAva(dn, at);
    if (ava === undefined) return undefined;
    rdn.push(ava.ava);
    at = ava.next;
    if (at === dn.length) break;
    // "+" continues this RDN; "," begins the next. Nothing else may follow a value,
    // since readAva stops only at one of the two or at the end.
    if (dn[at] === "+") {
      at++;
      // A type may appear in at most one AVA of an RDN (RFC 4517 section 4.2.15),
      // so a repeat is not a name at all rather than a name that cannot match.
      if (rdn.some((a) => sameType(a.type, dn.slice(at).split(/[=+,]/)[0].trim()))) return undefined;
      continue;
    }
    if (dn[at] !== ",") return undefined;
    at++;
    while (dn[at] === " ") at++;
    // A trailing comma ends nothing: "dc=example," is not a distinguished name.
    if (at === dn.length) return undefined;
    rdns.push(rdn);
    rdn = [];
  }
  if (rdn.length === 0) return undefined;
  rdns.push(rdn);
  return rdns;
}

/**
 * One `attributeType EQUALS attributeValue`, and where it ended.
 *
 * Whitespace around a separator is **ignored**, which RFC 4514 §3 permits —
 * "Implementations MAY recognize other DN string representations" — and §5.1
 * describes: a long DN is line-wrapped "by inserting whitespace after the RDN
 * separator character", and "the extra whitespace is to be removed before the DN
 * string is used in LDAP". A client that did not remove it is served rather than
 * refused. This cannot blur one AVA into two: a comma, plus or equals that is part
 * of a value has to be escaped (§2.4), so an unescaped one is always a separator,
 * whatever whitespace sits beside it — which is also why an unescaped space next to
 * a separator cannot be part of the value and nothing is lost by dropping it.
 *
 * What is strict is what this program *emits*: `formatDn` escapes, and §3's own
 * advice is that "implementations SHOULD only generate DN strings in accordance
 * with Section 2".
 */
function readAva(dn: string, from: number): { ava: Ava; next: number } | undefined {
  while (dn[from] === " ") from++;
  const eq = dn.indexOf("=", from);
  if (eq <= from) return undefined;
  const type = dn.slice(from, eq).trimEnd();
  // "attributeType = descr / numericoid" (RFC 4514 section 3), and RFC 4512's
  // `descr` is a letter followed by letters, digits and hyphens.
  if (!/^[A-Za-z][A-Za-z0-9-]*$/.test(type) && !/^\d+(\.\d+)*$/.test(type)) return undefined;
  let i = eq + 1;
  // The hexstring form: "#" then hex pairs, whose octets are a BER encoding.
  if (dn[i] === "#") {
    i++;
    const start = i;
    while (i < dn.length && /[0-9A-Fa-f]/.test(dn[i])) i++;
    const hex = dn.slice(start, i);
    if (hex.length === 0 || hex.length % 2 !== 0) return undefined;
    if (i < dn.length && dn[i] !== "," && dn[i] !== "+") return undefined;
    return { ava: { type, value: hex.toLowerCase(), binary: true }, next: i };
  }
  let value = "";
  let escapedLast = false;
  for (; i < dn.length; i++) {
    const c = dn[i];
    if (c === "\\") {
      const next = dn[i + 1];
      if (next === undefined) return undefined;
      if (/[0-9A-Fa-f]/.test(next)) {
        // "pair = ESC ( ESC / special / hexpair )": a hex pair is two digits, and
        // the octets of a multi-byte character are escaped one pair each, so the
        // run is decoded together and then read as UTF-8.
        const bytes: number[] = [];
        while (dn[i] === "\\" && /[0-9A-Fa-f]/.test(dn[i + 1] ?? "") && /[0-9A-Fa-f]/.test(dn[i + 2] ?? "")) {
          bytes.push(parseInt(dn.slice(i + 1, i + 3), 16));
          i += 3;
        }
        if (bytes.length === 0) return undefined;
        i--;
        value += Buffer.from(bytes).toString("utf8");
        escapedLast = true;
        continue;
      }
      if (!ESCAPABLE.has(next)) return undefined;
      value += next;
      i++;
      escapedLast = true;
      continue;
    }
    if (c === "," || c === "+") break;
    // A character that must have been escaped was not, so this is not a name.
    if (ALWAYS.has(c)) return undefined;
    // "leadchar" excludes an unescaped space and "#" at the start of the value.
    if (value === "" && !escapedLast && (c === " " || c === "#")) return undefined;
    value += c;
    escapedLast = false;
  }
  // "trailchar" excludes an unescaped space at the end, so trailing spaces here
  // are the inserted whitespace of §5.1 and are removed, not refused. A space that
  // is part of the value arrives escaped and is kept by the branch above.
  if (!escapedLast) value = value.replace(/ +$/, "");
  if (value === "" && i === eq + 1) return { ava: { type, value }, next: i };
  return { ava: { type, value }, next: i };
}

/** Whether two attribute types are the same: a descriptor compares without case. */
const sameType = (a: string, b: string): boolean => a.toLowerCase() === b.toLowerCase();

/**
 * Whether two AVAs are the same. The value is prepared by RFC 4518 and compared
 * without case, which is `caseIgnoreMatch` — the equality rule of every attribute
 * type a certificate subject or this directory's names use (RFC 4519 section 2,
 * where each is `SUP name`). A type whose rule is not `caseIgnoreMatch` would need
 * its own comparison here; none is used in a name this program compares, and a
 * `#hexstring` value is compared by its octets instead.
 */
function sameAva(a: Ava, b: Ava): boolean {
  if (!sameType(a.type, b.type)) return false;
  if ((a.binary ?? false) !== (b.binary ?? false)) return false;
  if (a.binary === true) return a.value === b.value;
  return prepare(a.value) === prepare(b.value);
}

/**
 * Whether two distinguished names are the same, by RFC 4517 section 4.2.15: the
 * same number of RDNs, corresponding RDNs **by position**, and within an RDN the
 * same AVAs in any order. This is what the old set-and-sort comparison got wrong.
 */
export function sameDn(a: Rdn[], b: Rdn[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    const x = a[i], y = b[i];
    if (x.length !== y.length) return false;
    // "The order of the AVAs is not significant", and "a particular attribute
    // type may appear in at most one AVA in an RDN", so each of x matches one of y.
    if (!x.every((ava) => y.some((other) => sameAva(ava, other)))) return false;
  }
  return true;
}

/** Whether two distinguished names given as strings are the same. Unparseable is never equal. */
export function sameDnString(a: string, b: string): boolean {
  const x = parseDn(a), y = parseDn(b);
  return x !== undefined && y !== undefined && x.length > 0 && sameDn(x, y);
}

/**
 * The string representation of a distinguished name, escaped as RFC 4514 section
 * 2.4 requires. Every DN this program emits goes through this, so that a value
 * carrying a comma — a certificate subject's, which this program does not choose —
 * is written as one value and not as two RDNs.
 */
export function formatDn(rdns: Rdn[]): string {
  return rdns.map((rdn) => rdn.map(formatAva).join("+")).join(",");
}

function formatAva(ava: Ava): string {
  if (ava.binary === true) return `${ava.type}=#${ava.value}`;
  let out = "";
  const chars = [...ava.value];
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i];
    const first = i === 0, last = i === chars.length - 1;
    if (c === "\0") out += "\\00";
    else if (ALWAYS.has(c)) out += `\\${c}`;
    else if (c === " " && (first || last)) out += "\\ ";
    else if (c === "#" && first) out += "\\#";
    else out += c;
  }
  return `${ava.type}=${out}`;
}

/**
 * Whether `inner` lies beneath `outer` in the tree: it has more RDNs, and its
 * outermost ones are `outer`. Done structurally rather than by comparing the tails
 * of two strings, because a string comparison has to decide what a comma means and
 * a value may contain one.
 */
export function beneath(inner: Rdn[], outer: Rdn[]): boolean {
  return inner.length > outer.length && sameDn(inner.slice(inner.length - outer.length), outer);
}

/**
 * The subject of an X.509 certificate, from its DER. Node's
 * `getPeerCertificate().subject` is an object of attribute names to values, which
 * has already lost both the order of the RDNs and the fact that one RDN may hold
 * several AVAs — and a value containing a comma is indistinguishable from two
 * attributes once it is joined. So the subject is read from the certificate
 * itself.
 *
 *   Certificate ::= SEQUENCE { tbsCertificate TBSCertificate, ... }
 *   TBSCertificate ::= SEQUENCE { version [0] EXPLICIT Version DEFAULT v1,
 *     serialNumber, signature, issuer Name, validity, subject Name, ... }
 *   Name ::= RDNSequence
 *   RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *   RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
 *   AttributeTypeAndValue ::= SEQUENCE { type AttributeType, value AttributeValue }
 *
 * Undefined where the certificate cannot be read, which a caller must treat as "no
 * subject" and refuse — never as a reason to fall back on the convenience object.
 */
export function subjectOfCertificate(der: Buffer): Rdn[] | undefined {
  try {
    const certificate = read(der).element;
    const tbs = contentsOf(certificate)[0];
    const fields = contentsOf(tbs);
    // The version is [0] EXPLICIT and optional, so the subject is the fifth field
    // where it is absent and the sixth where it is present.
    const versioned = fields[0] !== undefined && (fields[0].tag & 0xc0) === 0x80;
    const subject = fields[versioned ? 5 : 4];
    if (subject === undefined || subject.tag !== TAG.SEQUENCE) return undefined;
    const out: Rdn[] = [];
    for (const rdnEl of readAll(subject.content)) {
      if (rdnEl.tag !== TAG.SET) return undefined;
      const rdn: Rdn = [];
      for (const avaEl of readAll(rdnEl.content)) {
        const [typeEl, valueEl] = readAll(avaEl.content);
        if (typeEl === undefined || valueEl === undefined) return undefined;
        const oid = decodeOID(typeEl);
        rdn.push({ type: SHORT[oid] ?? oid, ...valueOf(valueEl) });
      }
      if (rdn.length === 0) return undefined;
      out.push(rdn);
    }
    return out;
  } catch {
    return undefined;
  }
}

/**
 * One attribute value of a certificate's subject. A string type becomes a string;
 * anything else keeps its octets, in the `#hexstring` form, which is what RFC 4514
 * section 2.4 provides for a value "of a syntax that does not have an LDAP-specific
 * string encoding" — rather than guessing at a character set.
 */
function valueOf(el: { tag: number; content: Buffer }): { value: string; binary?: boolean } {
  const n = el.tag & 0x1f;
  // UTF8String, PrintableString, IA5String, VisibleString, NumericString,
  // TeletexString and BMPString are the ones a name uses. BMPString is UTF-16BE.
  if (n === 0x0c || n === 0x13 || n === 0x16 || n === 0x1a || n === 0x12 || n === 0x14) {
    return { value: el.content.toString("utf8") };
  }
  if (n === 0x1e) return { value: el.content.toString("utf16le").split("").reverse().join("") };
  // Anything else is kept as its BER encoding, which is what the DN's own
  // hexstring form is for. The tag and length are included, since the form encodes
  // the whole element.
  return { value: derOf(el).toString("hex"), binary: true };
}

/** An element's own DER, tag and length included. */
function derOf(el: { tag: number; content: Buffer }): Buffer {
  const length = el.content.length;
  if (length < 0x80) return Buffer.concat([Buffer.from([el.tag, length]), el.content]);
  const bytes: number[] = [];
  let v = length;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>>= 8;
  }
  return Buffer.concat([Buffer.from([el.tag, 0x80 | bytes.length, ...bytes]), el.content]);
}
