// Query queues.
//
// A query queue reports the objects a CDMI server stores that match a
// scope specification, at the time the query is performed. It is a
// queue object carrying three metadata items, so a CDMI client
// creates one by creating a queue object with those items, reads the
// results by reading the queue object, and removes them by removing
// the values it holds.
//
// This module holds what a query queue is: the metadata items and
// their validation, and the status a query reports. Running the
// query is elsewhere.

import { forbidden, invalidField } from "./problems.ts";

/** The item that states how the CDMI server manages a queue object. */
export const QUEUE_TYPE = "cdmi_queue_type";

/** The value of that item for a query queue. */
export const QUERY_QUEUE = "cdmi_query_queue";

/** The value of that item for a notification queue, which is not served. */
export const NOTIFICATION_QUEUE = "cdmi_notification_queue";

export const SCOPE = "cdmi_scope_specification";
export const RESULTS = "cdmi_results_specification";
export const QUERY_STATUS = "cdmi_query_status";
export const NOTIFICATION_EVENTS = "cdmi_notification_events";
export const NOTIFICATION_STATUS = "cdmi_notification_status";

/**
 * The items of the query and notification metadata table. None may be
 * changed by an update once the queue object has been created, other
 * than cdmi_queue_type.
 */
export const QUEUE_METADATA = [
  QUEUE_TYPE, SCOPE, RESULTS, NOTIFICATION_EVENTS, QUERY_STATUS,
  NOTIFICATION_STATUS,
];

/** The items a CDMI server populates rather than a CDMI client. */
export const QUEUE_STATUS_ITEMS = [QUERY_STATUS, NOTIFICATION_STATUS];

/** The state of a query, reported in the cdmi_query_status item. */
export type QueryStatus = "Processing" | "Current" | "Halted" | "Error";

/** Whether the metadata of a queue object makes it a query queue. */
export function isQueryQueue(metadata: Record<string, unknown>): boolean {
  return metadata[QUEUE_TYPE] === QUERY_QUEUE;
}

/**
 * Checks the metadata of a query queue. The scope and the results
 * specification are mandatory where the queue object is one, and
 * each is of the form its annex states.
 */
export function checkQueryMetadata(metadata: Record<string, unknown>): void {
  const type = metadata[QUEUE_TYPE];
  if (type !== undefined && typeof type !== "string") {
    throw invalidField(`metadata/${QUEUE_TYPE}`,
      "the %s item is a JSON string", QUEUE_TYPE);
  }
  // A CDMI server may define a further value, so a value this
  // document does not define is not refused: the queue object is
  // then managed as any other.
  if (type !== QUERY_QUEUE) {
    // The scope and the results specification are checked wherever
    // they appear, since a queue object that carries them may be
    // made a query queue later by a change to cdmi_queue_type.
    if (SCOPE in metadata) checkScope(metadata[SCOPE]);
    // The form of the results specification is checked wherever it
    // appears, and the capability governing the value of an object
    // is not: that applies to a query queue, and this object is not
    // one.
    if (RESULTS in metadata) checkResults(metadata[RESULTS], false);
    return;
  }
  for (const item of [SCOPE, RESULTS]) {
    if (!(item in metadata)) {
      throw invalidField(`metadata/${item}`,
        "a query queue contains the %s item", item);
    }
  }
  checkScope(metadata[SCOPE]);
  checkResults(metadata[RESULTS]);
}

/**
 * A scope specification is a JSON array of JSON objects. Each object
 * is a conjunction of conditions and the array is their disjunction;
 * an empty array matches every object.
 */
export function checkScope(value: unknown): void {
  if (!Array.isArray(value)) {
    throw invalidField(`metadata/${SCOPE}`,
      "a scope specification is a JSON array of JSON objects");
  }
  for (const [i, clause] of value.entries()) {
    if (clause === null || typeof clause !== "object" || Array.isArray(clause)) {
      throw invalidField(`metadata/${SCOPE}/${i}`,
        "each element of a scope specification is a JSON object");
    }
    checkConditions(`${SCOPE}/${i}`, clause as Record<string, unknown>);
  }
}

/** Every matching expression within one JSON object of a scope. */
function checkConditions(at: string, clause: Record<string, unknown>): void {
  for (const [name, condition] of Object.entries(clause)) {
    checkCondition(`${at}/${name}`, condition);
  }
}

function checkCondition(at: string, condition: unknown): void {
  if (typeof condition === "string") {
    parseExpression(at, condition);
    return;
  }
  if (Array.isArray(condition)) {
    // More than one matching expression for one field, each of which
    // is met, or a condition within an array of JSON objects.
    for (const [i, each] of condition.entries()) checkCondition(`${at}/${i}`, each);
    return;
  }
  if (condition !== null && typeof condition === "object") {
    // Matching within a structure: a JSON object at the corresponding
    // position of the scope.
    checkConditions(at, condition as Record<string, unknown>);
    return;
  }
  throw invalidField(`metadata/${at}`,
    "a matching expression is a JSON string, or a JSON object or array that " +
    "matches within a structure");
}

/** The operators of a matching expression that take no constant. */
const NO_CONSTANT = ["*", "!*"];

/**
 * The operators that take a constant, longest first so that a prefix
 * of another is not mistaken for it: "#==" before "#", "!=" before
 * "!".
 */
const OPERATORS = [
  "#==", "#!=", "#>=", "#<=", "#>", "#<",
  "==", "!=", ">=", "<=", ">", "<",
  "!starts", "starts", "!ends", "ends", "!contains", "contains",
  "!tag", "tag", "=~", "!~",
];

/** One matching expression: an operator and the constant it compares. */
export interface Expression {
  operator: string;
  constant: string;
}

/**
 * Reads a matching expression. A single space separates the operator
 * from the constant and is not part of it, so a constant that begins
 * with a space is written with two.
 */
export function parseExpression(at: string, text: string): Expression {
  const trimmed = text.trim();
  if (NO_CONSTANT.includes(trimmed)) return { operator: trimmed, constant: "" };
  for (const operator of OPERATORS) {
    if (!trimmed.startsWith(operator)) continue;
    const rest = trimmed.slice(operator.length);
    // An operator that is a word is separated from its constant; one
    // that is punctuation need not be.
    if (/^[a-z]/.test(operator) && rest !== "" && !/^\s/.test(rest)) continue;
    // The single space between the two is not part of the constant,
    // and a second space is.
    return { operator, constant: rest.startsWith(" ") ? rest.slice(1) : rest };
  }
  throw invalidField(`metadata/${at}`,
    "%j is not a matching expression this document defines", text);
}

/**
 * A results specification is a JSON object whose member names are the
 * fields reported. The member values are not interpreted, save that a
 * JSON object selects the members of the corresponding field.
 */
export function checkResults(value: unknown, forQuery = true): void {
  void forQuery;
  if (typeof value === "string") {
    // The annex permits a JSON string, which names one field.
    return;
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw invalidField(`metadata/${RESULTS}`,
      "a results specification is a JSON object");
  }
}

/**
 * Whether a query has to read the value of each object it considers: where its
 * scope states a condition on the "value" field, or its results specification
 * reports that field.
 *
 * The value is read for no other query, a value being the most expensive field
 * of an object to form and the only one this server does not hold in the row it
 * reads for every candidate. A results specification of an empty string
 * "reports every field of the object", which includes the value, so such a
 * query reads one — a CDMI client that does not want values names the fields it
 * wants instead.
 */
export function queryNeedsValue(scope: unknown, results: unknown): boolean {
  if (Array.isArray(scope) && scope.some((clause) =>
    clause !== null && typeof clause === "object" && !Array.isArray(clause) &&
    "value" in (clause as Record<string, unknown>))) {
    return true;
  }
  if (results === "" || results === undefined) return true;
  if (typeof results === "string") return results === "value";
  if (results === null || typeof results !== "object" || Array.isArray(results)) {
    return false;
  }
  return "value" in (results as Record<string, unknown>);
}

/**
 * Refuses an update that changes an item of the query and
 * notification metadata table, other than cdmi_queue_type. The
 * results a query queue holds are the results of the query specified
 * when it was created.
 */
export function refuseQueryChange(before: Record<string, unknown>,
  after: Record<string, unknown>): void {
  for (const item of QUEUE_METADATA) {
    if (item === QUEUE_TYPE) continue;
    // A status item is CDMI server populated and is not compared: a
    // client that writes one is ignored rather than refused, as it
    // is for every other server populated item.
    if (QUEUE_STATUS_ITEMS.includes(item)) continue;
    const was = JSON.stringify(before[item]);
    const now = JSON.stringify(after[item]);
    if (was === now) continue;
    throw forbidden(
      "%s: an item of the query and notification metadata is not changed once the " +
      "queue object has been created, other than %s", item, QUEUE_TYPE);
  }
}

// ---------------------------------------------------------------------
// Matching an object against a scope

/**
 * The matching expressions whose support a capability reports. A
 * scope that specifies one whose capability is absent is the
 * capability not present condition.
 */
export const EXPRESSION_CAPABILITIES: Record<string, string> = {
  contains: "cdmi_query_contains",
  "!contains": "cdmi_query_contains",
  tag: "cdmi_query_tags",
  "!tag": "cdmi_query_tags",
  "=~": "cdmi_query_regex",
  "!~": "cdmi_query_regex",
};

/**
 * Whether a representation matches a scope specification. Each JSON
 * object of the scope is a conjunction of conditions and the array is
 * their disjunction; an empty array matches every object.
 */
export function matchesScope(scope: unknown[], rep: Record<string, unknown>): boolean {
  if (scope.length === 0) return true;
  return scope.some((clause) =>
    matchesClause(clause as Record<string, unknown>, rep));
}

/** Every condition of one JSON object of a scope, which all apply. */
function matchesClause(clause: Record<string, unknown>,
  at: Record<string, unknown> | undefined): boolean {
  if (at === undefined) return false;
  return Object.entries(clause).every(([name, condition]) =>
    matchesCondition(condition, at[name], name in at));
}

/** One condition, against the value of the field it names. */
function matchesCondition(condition: unknown, value: unknown,
  present: boolean): boolean {
  if (typeof condition === "string") {
    return meets(parseExpression("scope", condition), value, present);
  }
  if (Array.isArray(condition)) {
    // Where the condition is an array of matching expressions, every
    // one is met. Where it is an array holding a JSON object, the
    // condition is matched within an array of the representation.
    if (condition.every((c) => typeof c === "string")) {
      return condition.every((c) => meets(parseExpression("scope", c as string),
        value, present));
    }
    if (!Array.isArray(value)) return false;
    return condition.every((c) =>
      (value as unknown[]).some((v) =>
        matchesCondition(c, v, true)));
  }
  if (condition !== null && typeof condition === "object") {
    // Matching within a structure.
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return false;
    }
    return matchesClause(condition as Record<string, unknown>,
      value as Record<string, unknown>);
  }
  return false;
}

/**
 * The positive counterpart of each negated operator. A negated expression
 * applied to an array is the complement of its positive form applied to the
 * same array, not the positive form distributed over the elements: "!tag red"
 * against ["red", "blue"] asks whether red is absent, which it is not, where
 * distributing the negation would ask whether some element is not red, which
 * blue satisfies. Getting that backwards makes a scope report the objects it
 * was written to exclude.
 */
const POSITIVE: Record<string, string> = {
  "!=": "==", "!starts": "starts", "!ends": "ends", "!contains": "contains",
  "!tag": "tag", "!~": "=~", "#!=": "#==",
};

/** Whether one matching expression is met by the value of a field. */
export function meets(e: Expression, value: unknown, present: boolean): boolean {
  if (e.operator === "*") return present;
  if (e.operator === "!*") return !present;
  if (!present) return false;
  // An array-valued field is a set of values, and one matching expression is
  // met where any one element meets it. A metadata item "may itself contain
  // JSON objects and JSON arrays" (revision 365), and an array of strings is
  // the natural form for a set of tags or labels.
  //
  // Until 0.123 an array was compared as its JSON text, which no operator could
  // usefully match: "tag red" against ["red", "blue"] split the text
  // ["red","blue"] on its commas and compared ["red" with red, so every tag
  // search over an array returned nothing, and "== red" likewise. The one
  // operator that did match matched the serialization rather than the data, so
  // "contains" was met by the quotes and brackets between the elements.
  // NOTES-on-query.md records this and ECR-248A asks the document to define it,
  // the clause describing how to reach into an array of JSON objects and not
  // into an array of anything else.
  if (Array.isArray(value)) {
    const positive = POSITIVE[e.operator];
    const inner: Expression = positive === undefined
      ? e
      : { ...e, operator: positive as Expression["operator"] };
    const met = value.some((element) => meets(inner, element, true));
    return positive === undefined ? met : !met;
  }
  // A field whose value is not a JSON string is compared as the text
  // of that value, a representation reporting most fields as strings.
  const text = typeof value === "string" ? value : JSON.stringify(value) ?? "";
  const c = e.constant;
  switch (e.operator) {
    case "==": return text === c;
    case "!=": return text !== c;
    case ">": return text > c;
    case ">=": return text >= c;
    case "<": return text < c;
    case "<=": return text <= c;
    case "starts": return text.startsWith(c);
    case "!starts": return !text.startsWith(c);
    case "ends": return text.endsWith(c);
    case "!ends": return !text.endsWith(c);
    case "contains": return text.includes(c);
    case "!contains": return !text.includes(c);
    // A tag is "a substring of the value of a field that begins at the start of
    // that value or after a ','" (revision 365), so only a JSON string has tags:
    // a number has no substrings, and the clause distinguishes a tag comparison
    // from the equals expression, which does compare a value as its text. This
    // follows the rule the clause states for the other kind-specific operator,
    // that "a numeric matching expression shall not match a field whose value is
    // not numeric ... treat such a condition as not met, and shall not report an
    // error". So "tag 3" does not match the 3 in ["red", 3], and "== 3" does.
    case "tag": return typeof value === "string" && hasTag(text, c);
    case "!tag": return !(typeof value === "string" && hasTag(text, c));
    case "=~": return regex(c).test(text);
    case "!~": return !regex(c).test(text);
    default: return numeric(e.operator, text, c);
  }
}

/**
 * A tag is a substring that begins at the start of the value or
 * after a comma and ends at the next comma or at the end. Space
 * around a comma is disregarded and the comparison is not case
 * sensitive, which distinguishes it from the equals expression.
 */
function hasTag(text: string, constant: string): boolean {
  const wanted = constant.trim().toLowerCase();
  return text.split(",").some((tag) => tag.trim().toLowerCase() === wanted);
}

function regex(constant: string): RegExp {
  try {
    return new RegExp(constant);
  } catch {
    // A constant that is not a regular expression matches nothing
    // rather than failing the query.
    return /(?!)/;
  }
}

/**
 * A numeric matching expression does not match a field whose value is
 * not numeric, and a numeric constant is a JSON number.
 */
function numeric(operator: string, text: string, constant: string): boolean {
  const left = Number(text);
  const right = Number(constant);
  if (text.trim() === "" || Number.isNaN(left) || Number.isNaN(right)) return false;
  switch (operator) {
    case "#==": return left === right;
    case "#!=": return left !== right;
    case "#>": return left > right;
    case "#>=": return left >= right;
    case "#<": return left < right;
    case "#<=": return left <= right;
    default: return false;
  }
}

// ---------------------------------------------------------------------
// The result

/**
 * The fields of a representation a results specification selects.
 * Where a member value is a JSON object its members select the
 * members of the corresponding field, so a results specification
 * selects individual metadata items; where it is not, the whole of
 * the field is reported. An empty string reports every field.
 *
 * A field the matching object does not contain is omitted, and that
 * is not an error.
 */
export function project(results: unknown, rep: Record<string, unknown>):
  Record<string, unknown> {
  if (results === "" || results === undefined) return { ...rep };
  if (typeof results === "string") {
    // A JSON string names one field, which the annex permits.
    return results in rep ? { [results]: rep[results] } : {};
  }
  if (results === null || typeof results !== "object" || Array.isArray(results)) {
    return {};
  }
  const out: Record<string, unknown> = {};
  for (const [name, selector] of Object.entries(results as Record<string, unknown>)) {
    if (!(name in rep)) continue;
    const value = rep[name];
    if (selector !== null && typeof selector === "object" &&
      !Array.isArray(selector) && Object.keys(selector).length > 0 &&
      value !== null && typeof value === "object" && !Array.isArray(value)) {
      out[name] = project(selector, value as Record<string, unknown>);
      continue;
    }
    out[name] = value;
  }
  return out;
}

/**
 * The value enqueued for one matching object: a JSON object of the
 * fields the results specification selected, of media type
 * application/json.
 *
 * Where the "value" field is reported "it shall be transported as a base 64
 * encoded string, whatever the value transfer encoding of the matching object",
 * which is the form the representation a query forms carries it in already, for
 * the same reason the scope matches it in that form. The
 * "valuetransferencoding" field, where the results specification reports it,
 * "specifies the encoding that a read of that object would return", and is not
 * the encoding of this field.
 */
export function resultValue(results: unknown, rep: Record<string, unknown>):
  { mimetype: string; vte: string; body: Buffer } {
  const selected = project(results, rep);
  return {
    mimetype: "application/json",
    vte: "utf-8",
    body: Buffer.from(JSON.stringify(selected), "utf8"),
  };
}
