// String preparation for character string matching, RFC 4518.
//
// This is the algorithm behind `caseIgnoreMatch`, and so behind two rules this
// program rests on: the realm's one name per principal, whatever its case
// (`fold` in dc-store.ts, which calls this), and the comparison of a certificate
// subject's attribute values (dn.ts).
//
// What was here before was `name.normalize("NFC").toLowerCase()`, with a comment
// calling it "the Unicode case fold of a name". It is not a case fold, and the
// standard asks for Form **KC**. Reading RFC 4518 against it showed four
// divergences, each of which lets two names the standard calls one coexist:
//
//   * **No mapping step.** Section 2.2 maps SOFT HYPHEN, ZERO WIDTH SPACE,
//     COMBINING GRAPHEME JOINER, the variation selectors and every control
//     character to nothing. Under the old fold, `ali<SOFT HYPHEN>ce` and `alice`
//     were different names — visually identical, and a spoof in any directory.
//   * **NFC instead of NFKC.** Section 2.3: "The input string is to be normalized
//     to Unicode Form KC (compatibility composed)." Under NFC the fullwidth
//     `ａｌｉｃｅ` is a different name from `alice`; under NFKC it is the same one.
//   * **`toLowerCase()` instead of case folding.** Section 2.2: "characters are
//     case folded per B.2 of [RFC3454]". The two differ — case folding maps ß to
//     "ss" — so `straße` and `strasse` were two names where the standard has one.
//   * **The order.** Section 2 maps (and case-folds) *before* normalizing; the old
//     code normalized first.
//
// None of it was reachable: `NAME` in dc-directory.ts admits ASCII letters,
// digits and `. _ -` only, so no name can contain any of these characters. That is
// the honest position, and it is also why the old comment was dangerous — it
// claimed this function handled "a realm that may hold a name outside ASCII",
// which invites widening `NAME` on a promise the code did not keep. It keeps it
// now, as far as it can without Unicode's own tables; see the note at the end.

/**
 * Code points section 2.2 maps **to nothing**: the soft hyphens, the joiner and
 * variation selectors, the object replacement character, zero width space, and
 * every control code point and code point with a control function. The RFC gives
 * the complete list, which is reproduced here rather than derived from a category,
 * because a category differs between Unicode versions and the RFC's repertoire is
 * fixed at Unicode 3.2.
 */
const TO_NOTHING = new RegExp(
  "[" +
  // SOFT HYPHEN, MONGOLIAN TODO SOFT HYPHEN, COMBINING GRAPHEME JOINER,
  // VARIATION SELECTORs, OBJECT REPLACEMENT CHARACTER, ZERO WIDTH SPACE.
  "\\u00AD\\u1806\\u034F\\u180B-\\u180D\\uFE00-\\uFE0F\\uFFFC\\u200B" +
  // "All other control code ... points or code points with a control function",
  // the complete list of section 2.2.
  "\\u0000-\\u0008\\u000E-\\u001F\\u007F-\\u0084\\u0086-\\u009F" +
  "\\u06DD\\u070F\\u180E\\u200C-\\u200F\\u202A-\\u202E\\u2060-\\u2063" +
  "\\u206A-\\u206F\\uFEFF\\uFFF9-\\uFFFB" +
  "]",
  "gu");

/**
 * Code points mapped to SPACE: the ones section 2.2 names by hand, and "all other
 * code points with Separator (space, line, or paragraph) property", for which it
 * also gives the complete list.
 */
const TO_SPACE = new RegExp(
  "[\\u0009\\u000A\\u000B\\u000C\\u000D\\u0085" +
  "\\u0020\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000]",
  "gu");

/** Code points outside the Basic Multilingual Plane that section 2.2 maps to nothing. */
const TO_NOTHING_ASTRAL = /[\u{1D173}-\u{1D17A}\u{E0001}\u{E0020}-\u{E007F}]/gu;

/**
 * The case folding of section 2.2, "per B.2 of [RFC3454]", as far as it differs
 * from `toLowerCase`. JavaScript has no case-folding operation, and B.2 is a table
 * of some 1400 mappings; `toLowerCase` agrees with it for the overwhelming
 * majority and differs where a fold expands one character into several. Those are
 * listed here. A character not listed is folded by `toLowerCase`, which is an
 * approximation and is recorded as one in NOTES-on-ldap.md §9 rather than
 * presented as the algorithm.
 */
const FOLD_EXPANDS: Record<string, string> = {
  "ß": "ss", // LATIN SMALL LETTER SHARP S
  "İ": "i̇", // LATIN CAPITAL LETTER I WITH DOT ABOVE
  "ŉ": "ʼn", // LATIN SMALL LETTER N PRECEDED BY APOSTROPHE
  "ǰ": "ǰ", // LATIN SMALL LETTER J WITH CARON
  "ΐ": "ΐ", "ΰ": "ΰ",
  "և": "եւ", "ẖ": "ẖ", "ẗ": "ẗ",
  "ẘ": "ẘ", "ẙ": "ẙ", "ẚ": "aʾ",
  "ὐ": "ὐ", "ὒ": "ὒ",
  "ὔ": "ὔ", "ὖ": "ὖ",
  "ﬀ": "ff", "ﬁ": "fi", "ﬂ": "fl", "ﬃ": "ffi",
  "ﬄ": "ffl", "ﬅ": "st", "ﬆ": "st",
  "ﬓ": "մն", "ﬔ": "մե", "ﬕ": "մի",
  "ﬖ": "վն", "ﬗ": "մխ",
};

/**
 * Prepares a string for a `caseIgnoreMatch` comparison: the six steps of RFC 4518
 * section 2, in its order — map (including case folding), normalize to Form KC,
 * then insignificant space handling.
 *
 * Two steps are deliberately not performed, and saying so is the point of this
 * comment:
 *
 *   * **Prohibit** (section 2.4) rejects unassigned, private-use, non-character
 *     and surrogate code points, and U+FFFD. "Failure in any step causes the
 *     assertion to evaluate to Undefined" — so a conforming server answers
 *     Undefined for such a value, where this one compares it. The tables are
 *     Unicode-version-specific and this program has no Unicode database; a name
 *     containing one of those code points cannot be created here anyway, `NAME`
 *     being ASCII.
 *   * **Check bidi** (section 2.5) is "Bidirectional characters are ignored",
 *     which is what this does by not treating them specially.
 *
 * Section 2 permits this: "Implementations are free to use alternative processes
 * so long as the matching rule evaluation behavior provided is consistent with the
 * behavior described by this specification." Where this one is *not* consistent,
 * it is recorded rather than claimed — NOTES-on-ldap.md §9.
 */
export function prepare(value: string): string {
  // 2.2 Map. The order within the step follows the section: the code points
  // mapped to nothing, then those mapped to SPACE, then the case fold.
  let out = value.replace(TO_NOTHING, "").replace(TO_NOTHING_ASTRAL, "").replace(TO_SPACE, " ");
  out = [...out].map((c) => FOLD_EXPANDS[c] ?? c.toLowerCase()).join("");
  // 2.3 Normalize, to Form KC and not Form C.
  out = out.normalize("NFKC");
  // The fold can expose a character the normalization then composes, and
  // composition can expose a character that folds differently, so the two are run
  // once more until they settle. Two passes suffice for every mapping in the table
  // above; the loop is bounded so that no input can spin.
  for (let i = 0; i < 2; i++) {
    const again = [...out].map((c) => FOLD_EXPANDS[c] ?? c.toLowerCase()).join("").normalize("NFKC");
    if (again === out) break;
    out = again;
  }
  // 2.6.1 Insignificant Space Handling, for an attribute value or a non-substring
  // assertion value: "the string is modified such that the string starts with
  // exactly one space character, ends with exactly one SPACE character, and any
  // inner (non-empty) sequence of space characters is replaced with exactly two
  // SPACE characters", and a string of no non-space characters becomes exactly two.
  if (out.trim() === "") return "  ";
  return ` ${out.trim().replace(/ +/g, "  ")} `;
}

/**
 * A string prepared for comparison **as SCIM requires**, which is not as LDAP does.
 *
 * RFC 7644 §7.8 is a MUST and is about this: "When comparing Unicode strings such as
 * those in query filters or testing for uniqueness of usernames and passwords, strings
 * MUST be appropriately prepared before comparison. See Section 5." And §5:
 *
 *   Before comparing or evaluating the uniqueness of a "userName" or "password"
 *   attribute, service providers MUST use the preparation, enforcement, and comparison
 *   of internationalized strings (PRECIS) preparation and comparison rules described
 *   in Sections 3 and 4, respectively, of [RFC7613], which is based on the PRECIS
 *   framework specification [RFC7564].
 *
 * Nothing was done at all: the SCIM filter compared `a.toLowerCase() === b.toLowerCase()`,
 * so `displayName eq "café"` written in NFD found nothing where the stored value was
 * NFC, and the same two strings matched over LDAP. Ten inputs compared differently
 * between the two front ends against one directory.
 *
 * **This is not PRECIS.** RFC 7613 and RFC 7564 are not documents this program has, and
 * guessing the FreeformClass tables is the mistake `NOTES-on-ldap.md` §1 exists to
 * prevent. What is done here is the part of PRECIS that is Unicode's rather than
 * PRECIS's own, and which §7.8's "appropriately prepared" cannot mean less than:
 *
 *   * **Case folding**, using the same table RFC 4518's map step needs, because it is
 *     Unicode's case folding and not either specification's invention. `toLowerCase`
 *     is not case folding: it leaves U+00DF alone where folding gives "ss", so
 *     "Straße" and "STRASSE" compared unequal.
 *   * **Normalization to Form C**, which is PRECIS's form. Not Form KC, which is
 *     RFC 4518's: the difference is deliberate and is why the two front ends still
 *     differ on a compatibility equivalence such as the ligature U+FB01.
 *
 * What is **not** done, and is recorded in `NOTES-on-scim.md` §12 rather than guessed:
 * width mapping (so a fullwidth letter still compares unequal), the disallowed code
 * point checks of the FreeformClass and IdentifierClass, and the distinction RFC 7613
 * §3.4 draws between case mapping and case preservation for a `userName`.
 *
 * And what this deliberately does **not** do is RFC 4518 §2.6.1's space handling, which
 * is LDAP's and not PRECIS's. So " ann  example " and "ann example" are one value over
 * LDAP and two over SCIM, which is each specification being obeyed rather than a
 * divergence to fix. The conformance test states it as an asymmetry.
 */
export function prepareScim(value: string): string {
  let out = [...value].map((c) => FOLD_EXPANDS[c] ?? c.toLowerCase()).join("").normalize("NFC");
  // As in `prepare`: folding can expose a character that composition then changes, and
  // composition a character that folds differently, so they are run until they settle
  // under a bound that no input can exceed.
  for (let i = 0; i < 2; i++) {
    const again = [...out].map((c) => FOLD_EXPANDS[c] ?? c.toLowerCase()).join("").normalize("NFC");
    if (again === out) break;
    out = again;
  }
  return out;
}

/**
 * A secret prepared before it is hashed or compared.
 *
 * RFC 7644 §5 makes this a MUST and names the password specifically: "Before comparing
 * or evaluating the uniqueness of a 'userName' or 'password' attribute, service
 * providers MUST use the preparation, enforcement, and comparison of internationalized
 * strings (PRECIS) preparation and comparison rules described in Sections 3 and 4,
 * respectively, of [RFC7613]". Nothing was done, and the consequence was demonstrable:
 * a password set as `le café du matin` with the é as U+00E9 was **refused** when the
 * same password was typed with the é as `e` + U+0301. One password, two spellings, and
 * the user locked out of the second — on platforms that differ in which they produce,
 * which is to say between a Mac and most other things.
 *
 * What is done is **normalization to Form C**, which is the form every PRECIS profile
 * normalizes to and which is identity on ASCII, so no existing ASCII password is
 * affected. There is deliberately **no case folding**: PRECIS's password profile is
 * OpaqueString, which preserves case, and folding a password would make it weaker.
 *
 * What is **not** done, and wants RFC 7613 and RFC 7564, neither of which this program
 * has: width mapping, the mapping of non-ASCII space to ASCII space, and the disallowed
 * code point checks of the FreeformClass. `NOTES-on-scim.md` §12 records it.
 *
 * This is applied where a password **enters** rather than inside the hash, because the
 * one password feeds two derivations — a scrypt verifier and a Kerberos long-term key
 * per enctype — and preparing it for one only would make an LDAP bind and a Kerberos
 * exchange disagree about the same password.
 */
export const prepareSecret = (secret: string): string => secret.normalize("NFC");
