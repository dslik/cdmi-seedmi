// Graph relationships: the "rel" field of a representation.
//
// A graph relationship is an RDF triple in the JSON serialization of
// RDF/JSON. A server that supports them validates the field and stores
// it; it does not interpret a relationship, does not resolve a URI a
// triple contains, and does not check that a URI addresses anything
// that exists. That is what distinguishes this field from "imports" and
// "exports", which a server acts on.
//
// The field is not metadata. It is a field of the representation in its
// own right, so it is stored beside the metadata rather than within it.

export interface RelCheck {
  /** The path of the member at fault, for the invalid field condition. */
  at: string;
  why: string;
}

const GRAPH_OBJECT_MEMBERS = ["value", "type", "datatype", "lang"];
const GRAPH_OBJECT_TYPES = ["uri", "literal", "bnode"];

const isObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Validates a rel field. Returns the member at fault where it does not
 * conform, and nothing where it does.
 *
 * The structure is that of the `rel` rule of annex A: at most one
 * context object, and any number of members that are each an RDF triple
 * where the value is an object and a named graph where it is an array.
 */
export function checkRel(value: unknown, at = "rel"): RelCheck | undefined {
  if (!isObject(value)) {
    return { at, why: "the rel field shall be a JSON object" };
  }
  for (const [name, member] of Object.entries(value)) {
    const here = `${at}/${escapePointer(name)}`;
    if (name === "@context") {
      const bad = checkContext(member, here);
      if (bad) return bad;
      continue;
    }
    // "@context" is the only JSON-LD keyword the rel field admits at its
    // top level: a name beginning with "@" is otherwise a keyword this
    // document does not provide for, and is refused rather than taken as
    // the subject of a triple (13.6.3; weedmi DMGT-012). "@id" and "@type"
    // were refused before 0.71 by the checks below, and "@graph" was not,
    // its value being an array and so read as a named graph.
    if (name.startsWith("@")) {
      return {
        at: here,
        why: `the rel field admits no JSON-LD keyword but "@context", and ${JSON.stringify(name)} is one`,
      };
    }
    if (isObject(member)) {
      const bad = checkTriple(member, here);
      if (bad) return bad;
      continue;
    }
    if (Array.isArray(member)) {
      const bad = checkNamedGraph(member, here);
      if (bad) return bad;
      continue;
    }
    // A member is a triple where its value is an object and a named
    // graph where it is an array; anything else is an invalid field.
    return {
      at: here,
      why: "a member of the rel field is a JSON object, which is an RDF triple, or a " +
        "JSON array, which is a named graph",
    };
  }
  return undefined;
}

function checkContext(value: unknown, at: string): RelCheck | undefined {
  if (!isObject(value)) {
    return { at, why: "the context object shall be a JSON object" };
  }
  for (const [short, uri] of Object.entries(value)) {
    if (typeof uri !== "string") {
      return {
        at: `${at}/${escapePointer(short)}`,
        why: "a short name abbreviates a URI, which shall be a JSON string",
      };
    }
  }
  return undefined;
}

function checkTriple(triple: Record<string, unknown>, at: string): RelCheck | undefined {
  // An RDF triple has at least one predicate.
  if (Object.keys(triple).length === 0) {
    return { at, why: "an RDF triple shall contain at least one graph predicate" };
  }
  for (const [predicate, objects] of Object.entries(triple)) {
    const here = `${at}/${escapePointer(predicate)}`;
    if (!Array.isArray(objects) || objects.length === 0) {
      return {
        at: here,
        why: "the value of a graph predicate shall be a JSON array of at least one " +
          "graph object",
      };
    }
    for (const [i, object] of objects.entries()) {
      const bad = checkGraphObject(object, `${here}/${i}`);
      if (bad) return bad;
    }
  }
  return undefined;
}

function checkGraphObject(value: unknown, at: string): RelCheck | undefined {
  if (!isObject(value)) {
    return { at, why: "a graph object shall be a JSON object" };
  }
  for (const name of Object.keys(value)) {
    if (!GRAPH_OBJECT_MEMBERS.includes(name)) {
      return {
        at: `${at}/${escapePointer(name)}`,
        why: `${JSON.stringify(name)} is not a member of a graph object; the members ` +
          `are ${GRAPH_OBJECT_MEMBERS.join(", ")}`,
      };
    }
  }
  if (typeof value.value !== "string") {
    return { at: `${at}/value`, why: "the value member is mandatory and is a JSON string" };
  }
  if (value.type !== undefined) {
    if (typeof value.type !== "string" || !GRAPH_OBJECT_TYPES.includes(value.type)) {
      return {
        at: `${at}/type`,
        why: `the type of a graph object is ${GRAPH_OBJECT_TYPES.join(", ")}`,
      };
    }
  }
  for (const name of ["datatype", "lang"] as const) {
    if (value[name] !== undefined && typeof value[name] !== "string") {
      return { at: `${at}/${name}`, why: `the ${name} member shall be a JSON string` };
    }
    // Both apply to a literal, so a graph object of another kind that
    // carries one is not what its author meant.
    if (value[name] !== undefined && value.type !== undefined && value.type !== "literal") {
      return {
        at: `${at}/${name}`,
        why: `the ${name} member applies to a graph object whose type is "literal"`,
      };
    }
  }
  return undefined;
}

function checkNamedGraph(value: unknown[], at: string): RelCheck | undefined {
  // Each value of the array has the same form as the rel field itself,
  // so a named graph may contain a named graph, to any depth.
  for (const [i, part] of value.entries()) {
    const bad = checkRel(part, `${at}/${i}`);
    if (bad) return bad;
  }
  return undefined;
}

/** A member name within a JSON Pointer, with its two escapes. */
function escapePointer(name: string): string {
  return name.replace(/~/g, "~0").replace(/\//g, "~1");
}

/**
 * The predicate a short name abbreviates, expanded against a context
 * object. A server does not interpret a relationship, so nothing is
 * expanded in what it stores; this is offered for a reader of the
 * stored field.
 */
export function expandPredicate(predicate: string,
  context: Record<string, string>): string {
  const colon = predicate.indexOf(":");
  if (colon <= 0) return predicate;
  const short = predicate.slice(0, colon);
  const uri = context[short];
  return uri === undefined ? predicate : uri + predicate.slice(colon + 1);
}
