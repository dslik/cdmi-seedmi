// The textual account of the CDMI over MCP binding.
//
// "The content member contains a textual account of the outcome, for a
// CDMI client that does not read the structuredContent member ... The
// textual account is a rendering of the outcome and contains no
// information of its own" (revision 347).
//
// Three rules govern everything here, and each is a rule about what the
// text may not do:
//
//   * every fact it states is also in structuredContent, so a client that
//     discards the text loses nothing;
//   * it is generated deterministically, so two operations with the same
//     outcome produce the same words;
//   * it states neither the value of a data object nor a value a queue
//     object holds, whatever its size, and does not report the absence of
//     a capability, a field or a metadata item as distinct from its not
//     having been reported.
//
// The last is why nothing here reads a "value" field, and why an absent
// field is passed over in silence rather than described as missing.
//
// A note of the subclause is worth keeping in view: "a principal that is
// permitted to name an object, or to write its metadata, thereby places
// text where a language model will read it." Names and metadata values
// appear in this text because the table requires them, and they are
// rendered as data — quoted, never as instructions.

/**
 * A name or value of the store, rendered as data rather than as prose.
 *
 * JSON.stringify does the work that matters: it wraps the value in quotation
 * marks and escapes any quotation mark, newline or control character within it,
 * so a value cannot end its own quoting and cannot begin what looks like a new
 * line of the account. Nothing here examines what it renders — the rendering is
 * uniform, which is why it needs no judgement about which values are dangerous.
 *
 * This deviates from one sentence of the subclause, deliberately, and ECR-218A
 * is raised on it: "A CDMI server shall render such a value into the textual
 * account unchanged, and shall add nothing to it." Quotation marks are something
 * added. Followed literally, that sentence requires a CDMI server to splice text
 * a principal wrote into a string a language model reads with nothing to mark
 * where the data begins or ends, and leaves the whole defence to a "should" on
 * the host. This server quotes instead and says so.
 */
const asData = (v: unknown): string => JSON.stringify(String(v));

/**
 * A name a CDMI client chose, rendered as data.
 *
 * The name of a field is the case the subclause's own list omits. It enumerates
 * "the name of an object, the name or value of a metadata item, the name of a
 * child, or the detail member" as data, and a field name is none of those —
 * while the account of a read is required to state "the fields the result
 * reports", and an extension field is named by the CDMI client that creates it.
 * So the one name a CDMI client chooses most freely was not covered, and this
 * server rendered it as prose until 0.95.
 */
const asName = asData;

/**
 * The prose members of a problem details document, on one line.
 *
 * The title and detail are prose by design and are rendered as the subclause
 * requires, from those two members and nothing else. What is collapsed is the
 * line structure: a detail carries substrings a CDMI client supplied — a field
 * pointer, a namespace path, a media type — and a newline within one would
 * otherwise let the account appear to continue in another voice.
 */
const asProse = (v: string): string => v.replace(/[\r\n\t\u0000-\u001f\u007f]+/g, " ").trim();

/**
 * The account of a read. The table of the subclause requires, for a data
 * object or a queue object, "the address of the object and the fields the
 * result reports"; for a container object, "the address of the container
 * object and the number of children reported, derived from the
 * childrenrange field"; and for a capability object, "the address of the
 * capability object and the capabilities the capabilities field reports as
 * present".
 */
export function mcpAccountOfRead(uri: string, object: Record<string, unknown>): string {
  const type = String(object.objectType ?? "");
  const at = `The object at ${asData(uri)}`;
  if (type.includes("capability")) {
    const caps = Object.keys((object.capabilities ?? {}) as Record<string, unknown>);
    return `${at} is a capability object reporting ${caps.length} ` +
      `${caps.length === 1 ? "capability" : "capabilities"}` +
      (caps.length === 0 ? "." : `: ${caps.sort().map(asName).join(", ")}.`);
  }
  if (type.includes("container")) {
    const range = object.childrenrange;
    const n = countOf(typeof range === "string" ? range : "");
    return `${at} is a container object reporting ${n} ` +
      `${n === 1 ? "child" : "children"}${n === 0 ? "." : `, of the range ${asData(range)}.`}`;
  }
  // An object being created or updated is reported as not complete, with
  // the proportion where the result reports one.
  const status = String(object.completionStatus ?? "Complete");
  const incomplete = status !== "Complete"
    ? ` It is not complete: the operation is ${asData(status)}` +
      (object.percentComplete === undefined
        ? "."
        : `, ${asData(object.percentComplete)} of the way through.`)
    : "";
  const fields = Object.keys(object)
    .filter((f) => f !== "value" && f !== "valuerange" && f !== "valuetransferencoding")
    .sort();
  // "Where the result reports a field selection of one or a few fields,
  // their values." A whole representation is many fields and is named
  // rather than quoted; a selection of a few is quoted, except a value,
  // which this text may never state whatever its size.
  if (fields.length > 0 && fields.length <= 3 && object.objectType === undefined) {
    const said = fields.map((f) => `${asName(f)} is ${asData(JSON.stringify(object[f]))}`);
    return `${at} reports ${said.join(", ")}.`;
  }
  const kind = type.includes("queue") ? "queue object" : "data object";
  return `${at} is a ${kind}. The result reports ${fields.length} ` +
    `${fields.length === 1 ? "field" : "fields"}: ${fields.map(asName).join(", ")}.${incomplete}`;
}

/** The number of children a childrenrange names, which may name none. */
function countOf(range: string): number {
  if (range === "") return 0;
  let total = 0;
  for (const part of range.split(",")) {
    const [a, b] = part.split("-");
    const from = Number(a);
    const to = b === undefined ? from : Number(b);
    if (!Number.isFinite(from) || !Number.isFinite(to)) continue;
    total += to - from + 1;
  }
  return total;
}

/**
 * The account of an outcome that did not succeed, generated from "the
 * title and detail members of the problem details document, where the
 * isError member is true" and nothing else.
 */
export function mcpAccountOfProblem(problem: unknown): string {
  const p = (problem ?? {}) as Record<string, unknown>;
  const title = typeof p.title === "string" ? asProse(p.title) : "The operation did not succeed.";
  const detail = typeof p.detail === "string" ? ` ${asProse(p.detail)}` : "";
  return `${title}${detail}`;
}

/**
 * A tool this server lists and does not yet perform. "A CDMI server shall
 * list every tool defined in this subclause, whether or not it supports
 * every operation", so a listed tool that refuses is correct; it says so
 * rather than failing obscurely.
 */
export function mcpNotYet(tool: string): Record<string, unknown> {
  const detail = `the ${tool} tool is defined by this protocol binding and is not yet ` +
    "performed by this CDMI server";
  return {
    // Every tool result of this protocol binding carries a resultType
    // of "complete", one reporting a condition included: the call
    // completed, and the condition is its outcome.
    resultType: "complete",
    isError: true,
    structuredContent: {
      type: "https://seedmi.example/problems/mcp/not-yet-served",
      title: "This CDMI server does not yet perform this operation.",
      detail,
    },
    content: [{ type: "text", text: `This CDMI server does not yet perform this operation. ${detail}.` }],
  };
}

/**
 * The account of an outcome that returned no representation: an update or
 * a delete that succeeded. The table requires that such an account state
 * what was done and to what, which is all there is to state — the result
 * reports no fields, and the absence of a field is not a fact this text
 * may assert.
 */
export function mcpAccountOfCreate(uri: string, object: Record<string, unknown>): string {
  // "That an object was created, its address, and its type. Where the
  // metadata field of the result reports the cdmi_size storage system
  // metadata item, the size of the value."
  const type = String(object.objectType ?? "an object");
  const size = (object.metadata as Record<string, unknown> | undefined)?.cdmi_size;
  const of = size === undefined ? "" : ` Its value is ${asData(size)} octets.`;
  const status = String(object.completionStatus ?? "Complete");
  if (status !== "Complete") {
    // "That the operation was accepted and has not completed, the address
    // of the target object, and that the progress of the operation is
    // followed by reading it."
    return `The operation on ${asData(uri)} was accepted and has not completed. ` +
      "Its progress is followed by reading that object.";
  }
  return `An object was created at ${asData(uri)}, of the type ${asData(type)}.${of}`;
}

/**
 * The account of an update: "the address of the object and the fields
 * changed, derived from the request representation. Where the update
 * removed a field or a metadata item, that it was removed."
 */
export function mcpAccountOfUpdate(uri: string, body: Record<string, unknown>): string {
  const changed: string[] = [];
  const removed: string[] = [];
  for (const [k, v] of Object.entries(body)) {
    if (v === null) { removed.push(`the ${asName(k)} field`); continue; }
    if (k === "metadata" && typeof v === "object" && v !== null) {
      for (const [item, value] of Object.entries(v as Record<string, unknown>)) {
        (value === null ? removed : changed).push(`the ${asName(item)} metadata item`);
      }
      continue;
    }
    changed.push(`the ${asName(k)} field`);
  }
  const parts = [`The object at ${asData(uri)} was updated.`];
  if (changed.length > 0) parts.push(`Changed: ${changed.sort().join(", ")}.`);
  if (removed.length > 0) parts.push(`Removed: ${removed.sort().join(", ")}.`);
  return parts.join(" ");
}

/**
 * The account of a delete: "that the object was deleted, and its
 * address", or for the values of a queue object, "that values were
 * removed from the queue object, its address, and the designators of the
 * values removed".
 */
export function mcpAccountOfDelete(uri: string, designators?: string): string {
  return designators === undefined
    ? `The object at ${asData(uri)} was deleted.`
    : `Values were removed from the queue object at ${asData(uri)}: ` +
      `the designators ${asData(designators)}.`;
}

/**
 * The account of a create with a server-assigned name: "for an object
 * created, its address and its type. For values appended to a queue
 * object, the address of the queue object, the number of values appended,
 * and the designators assigned."
 */
export function mcpAccountOfPost(uri: string, object: Record<string, unknown>): string {
  const type = object.objectType;
  return type === undefined
    ? `An object was created at ${asData(uri)}, with a name this CDMI server assigned.`
    : `An object was created at ${asData(uri)}, of the type ${asData(type)}, ` +
      "with a name this CDMI server assigned.";
}

/**
 * The account of an operation that addressed a reference: "that the
 * object addressed is a reference, and the destination URI reported in
 * the reference member."
 */
export function mcpAccountOfReference(uri: string, destination: string): string {
  return `The object at ${asData(uri)} is a reference, whose destination is ` +
    `${asData(destination)}.`;
}

export function mcpAccountOfChange(tool: string, uri: string): string {
  const what = {
    cdmi_create: "was created",
    cdmi_update: "was updated",
    cdmi_delete: "was deleted",
    cdmi_post: "was created with a name this CDMI server assigned",
  }[tool] ?? "was acted upon";
  return `The object at ${asData(uri)} ${what}.`;
}

/**
 * The account of an outcome, by the tool that produced it: the table of
 * the subclause gives a row for each, and this chooses among them. An
 * operation that reported a reference is accounted for as such whatever
 * the tool, as the table's own row for that case requires.
 */
export function mcpAccountOf(tool: string, uri: string, object: Record<string, unknown>,
  reference?: string, body?: Record<string, unknown>): string {
  if (reference !== undefined) return mcpAccountOfReference(uri, reference);
  switch (tool) {
    case "cdmi_create":
      return mcpAccountOfCreate(uri, object);
    case "cdmi_update":
      return mcpAccountOfUpdate(uri, body ?? {});
    case "cdmi_delete":
      return mcpAccountOfDelete(uri);
    case "cdmi_post":
      return mcpAccountOfPost(uri, object);
    default:
      return Object.keys(object).length === 0
        ? mcpAccountOfChange(tool, uri)
        : mcpAccountOfRead(uri, object);
  }
}
