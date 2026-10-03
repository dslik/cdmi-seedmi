// CDMI over MCP: the listener.
//
// "This subclause defines the protocol binding that transports the
// operations defined in clause 8 over the Model Context Protocol, revision
// 2026-07-28 ... The CDMI server shall be the MCP server. The two are one
// server: the endpoint that accepts an MCP request is the endpoint that
// performs the operation, evaluates the access control lists that apply to
// it, and returns the result" (revision 347, CDMI over MCP).
//
// This module is the transport and the protocol shell: the endpoint, the
// handshake, the tool list, and the routing of a call into the binding. The
// operations themselves are the binding's, reached through the same paths
// the HTTP binding uses, so that neither binding can be fixed alone.
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse }
  from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { randomBytes } from "node:crypto";
import {
  answer, HEADER_MISMATCH, INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND, parseBody,
  RpcError, UNSUPPORTED_PROTOCOL_VERSION, type Request,
} from "./jsonrpc.ts";
import { answerListenerPreflight, listenerAllows, listenerCorsOrVary, originOf } from "./cors.ts";
import type { Log } from "./log.ts";
import { type ResourceServer, Unauthenticated } from "./mcp-auth.ts";
import { checkPromptArguments, PROMPTS, promptList, promptMessages } from "./mcp-prompts.ts";
import {
  codeOfProblem, contentsOf, pathOfResource, resourceList, resourceTemplates,
} from "./mcp-resources.ts";

/** The revision of the Model Context Protocol this binding speaks. */
export const MCP_PROTOCOL_VERSION = "2026-07-28";

/**
 * What this server offers, which revision 2026-07-28 carries in the result of
 * server/discover: "Servers that support prompts MUST declare the prompts
 * capability in their DiscoverResult", and likewise for resources. That revision
 * removed the initialize handshake, so the discovery result is where a client
 * reads them; this server states them on initialize too, for a client that still
 * calls it.
 *
 * A capability is declared only where the responder is here. The tool list is
 * "the list of [the tools table] for every CDMI client of every CDMI server",
 * published whether or not each operation is implemented — a rule of the
 * subclause, and the opposite of the rule for capabilities. Prompts and
 * resources sit with capabilities, so a client's prompts/list is never answered
 * with a method error after the capability said it would work.
 *
 * Neither listChanged nor subscribe is declared. "Servers may advertise either
 * feature independently, together or neither": the prompt catalogue and the
 * listed resources are fixed, so there is no list change to notify, and this
 * server does not yet answer subscriptions/listen — which is the method revision
 * 2026-07-28 put in place of resources/subscribe, a long-lived stream carrying
 * notifications/resources/updated rather than a subscribe method of its own.
 */
export const CAPABILITIES: Record<string, Record<string, unknown>> = {
  tools: {},
  prompts: {},
  resources: {},
};

/**
 * The revisions this server will accept a request under. One, for now: the
 * revisions before it had a handshake and sessions this binding does not
 * implement, so accepting a request stating one would be claiming something
 * untrue. It is a list because that is how a client negotiates — the
 * "supported" member of an UnsupportedProtocolVersionError is read from here.
 */
export const PROTOCOL_VERSIONS = [MCP_PROTOCOL_VERSION];

/**
 * A traceparent field value, as section 3.2 of Trace Context defines it:
 * the version, a trace identifier, a parent identifier, and the flags.
 */
const TRACEPARENT = /^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/;

const hex = (bytes: number): string =>
  [...randomBytes(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");

/** One this server generates, where the call carried none. */
const newTraceparent = (): string => `00-${hex(16)}-${hex(8)}-01`;

/** Where a condition of this binding, rather than of the document, is named. */
const SEEDMI_MCP_PROBLEM = "https://seedmi.example/problems/mcp/";

/**
 * The reserved keys of the per-request envelope, which revision 2026-07-28 of
 * the Model Context Protocol introduced.
 *
 * That revision removed the "initialize" handshake and protocol-level
 * sessions: a client no longer tells a server its protocol version and
 * capabilities once at the start of a connection, but carries them in the
 * _meta member of every request. A server that read them from a handshake
 * alone learns them from nothing a modern client sends.
 */
const META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion";
const META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo";
const META_SERVER_INFO = "io.modelcontextprotocol/serverInfo";

/**
 * The header fields a browser client sends to this endpoint, which a preflight
 * asks about. Authorization is named rather than covered by a wildcard: the
 * Fetch standard excludes it from the wildcard, so a wildcard would refuse the
 * one field every request here carries.
 */
const MCP_REQUEST_HEADERS = [
  "Authorization", "Content-Type", "Accept", "MCP-Protocol-Version", "Mcp-Method",
  "Mcp-Name", "Mcp-Session-Id", "Last-Event-ID",
];

/**
 * The header fields of a response a browser makes available to the page.
 *
 * WWW-Authenticate is the one that matters. A client that meets a 401 reads the
 * resource_metadata parameter from it to find the protected resource metadata,
 * and from that the authorization servers this endpoint accepts — the whole of
 * the discovery RFC 9728 defines and the subclause requires. Unexposed, a
 * browser client meets a 401 whose challenge it cannot read.
 */
const MCP_EXPOSED_HEADERS = ["WWW-Authenticate", "Content-Type"];

/** What this server calls itself, in a result and in a discovery. */
const SERVER_INFO = () => ({ name: "seedmi", title: "seedmi, a CDMI server", version: VERSION_OF });

/**
 * A header value carried in the Base64 sentinel form, decoded.
 *
 * "When a value cannot be safely represented as a plain ASCII header value
 * ... clients MUST use Base64 encoding of the UTF-8 representation with the
 * following format: =?base64?{Base64EncodedValue}?=", and "servers MUST decode
 * an encoded Mcp-Name or Mcp-Param-{Name} value before comparing it to the
 * corresponding request body value". A CDMI namespace path may hold any
 * character a name may hold, so this is not a rare case here: a container
 * named in a language that is not written in ASCII reaches this server encoded.
 */
function decodeSentinel(value: string): string {
  if (!value.startsWith("=?base64?") || !value.endsWith("?=")) return value;
  const inner = value.slice("=?base64?".length, value.length - "?=".length);
  return Buffer.from(inner, "base64").toString("utf8");
}

/** A header field, taken once however many times it was sent. */
const headerOf = (req: IncomingMessage, name: string): string | undefined => {
  const v = req.headers[name] as string | string[] | undefined;
  const one = Array.isArray(v) ? v[0] : v;
  return one === undefined ? undefined : one.trim();
};

/**
 * Whether the client will read an event stream, from the Accept header field.
 *
 * "The client MUST include an Accept header listing both application/json and
 * text/event-stream", and "the server MUST return either Content-Type:
 * application/json (a single JSON object) or Content-Type: text/event-stream
 * (an SSE response stream)". The choice is the server's, but it is only a free
 * choice for a client that reads both: a client whose transport is in
 * streaming mode parses the response as an event stream, finds no data frame
 * in a JSON body, and reports an empty reply. This server read the header for
 * the first time in 0.90 and answered application/json to everything.
 */
function wantsStream(req: IncomingMessage): boolean {
  const accept = headerOf(req, "accept");
  if (accept === undefined) return false;
  return accept.split(",").some((part) => part.split(";")[0]!.trim().toLowerCase() === "text/event-stream");
}

/**
 * The tools, one for each operation of clause 8, with the annotations the
 * subclause gives them. "A CDMI server shall list every tool defined in
 * this subclause, whether or not it supports every operation", and "a CDMI
 * client shall not infer from the presence of a tool that a CDMI server
 * supports an operation": the list is the shape of the protocol binding,
 * not an inventory of this server, which is the opposite of the rule this
 * implementation follows for capabilities.
 */
export const TOOLS = [
  {
    name: "cdmi_create",
    title: "Create an object",
    description: "Create an object at a namespace path.",
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
    arguments: ["baseUri", "uri", "representation", "body", "onlyIfAbsent"],
  },
  {
    name: "cdmi_read",
    title: "Read an object",
    description:
      "Read an object, list the children of a container object, or read a capability object.",
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    arguments: ["baseUri", "uri", "representation"],
  },
  {
    name: "cdmi_update",
    title: "Update an object",
    description: "Update an object, completely, by field, or by merge.",
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
    arguments: ["baseUri", "uri", "representation", "body", "mode", "ifMatch"],
  },
  {
    name: "cdmi_delete",
    title: "Delete an object",
    description: "Delete an object, or remove the values a queue object holds.",
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
    arguments: ["baseUri", "uri", "representation", "ifMatch"],
  },
  {
    name: "cdmi_post",
    title: "Create an object under a name the server assigns",
    description: "Create an object whose name the CDMI server assigns.",
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
    arguments: ["baseUri", "uri", "representation", "body"],
  },
] as const;

/** The arguments each tool takes, for the schema and for refusing others. */
const ARGUMENT_TYPES: Record<string, "string" | "object" | "boolean"> = {
  baseUri: "string",
  uri: "string",
  representation: "string",
  body: "object",
  mode: "string",
  onlyIfAbsent: "boolean",
  ifMatch: "string",
};

/**
 * The values a closed-set argument may hold, declared in the input schema so
 * that a client offers a choice rather than a text box.
 *
 * Both sets are fixed by the document and not by this server. The
 * representation argument is "the media type of [the representation types
 * table] without the application/ prefix, for example cdmi-object", which is
 * those five and no others; the mode argument "shall contain one of the
 * following", which is those three. A client had no way to know either from
 * the schema until 0.96, so a schema-driven client offered free text where the
 * same client renders onlyIfAbsent as a control, it being typed (cvwm R1).
 *
 * The lists are not narrowed per tool, though not every type can be created or
 * deleted, because a representation that "does not correspond to the type of
 * the object addressed" is the invalid field condition, reported in the tool
 * result — it is decided against the object, at stage 6, and cannot be decided
 * against the tool at stage 1. A narrower enum per tool would report the
 * malformed request condition before the object was read, which is the wrong
 * condition at the wrong stage.
 */
const ENUMS: Record<string, readonly string[]> = {
  representation: [
    "cdmi-object", "cdmi-container", "cdmi-queue", "cdmi-domain", "cdmi-capability",
  ],
  mode: ["replace", "replace-fields", "merge"],
};

/**
 * Whether a value is one the argument admits.
 *
 * The media type with the "application/" prefix is accepted for the
 * representation argument although the enum does not declare it: mediaTypeOf
 * takes a value that already carries the prefix as given rather than refusing
 * it, and tightening that here would refuse a client that has been working.
 * The enum states the spelling the document gives, which is the one a client
 * should offer; this states what is accepted.
 */
function admits(argument: string, value: unknown): boolean {
  const set = ENUMS[argument];
  if (set === undefined || typeof value !== "string") return true;
  if (set.includes(value)) return true;
  return argument === "representation" && set.includes(value.replace(/^application\//, ""));
}

const DESCRIPTIONS: Record<string, string> = {
  baseUri: "One of the base URIs this CDMI server reports, which the uri is resolved against.",
  uri: "The namespace path of the target, with an optional query component selecting fields.",
  representation: "The type of the representation, being the media type of the representations " +
    'table without the "application/" prefix, as "cdmi-object".',
  body: "The request representation, as a JSON object.",
  mode: 'The form of the update: "replace", "replace-fields" or "merge".',
  onlyIfAbsent: "Where true, the operation is performed only where no object exists there.",
  ifMatch: "A validator this CDMI server returned for the object.",
};

/**
 * The problem details document a JSON-RPC error carries. "A JSON-RPC error
 * object. The problem details document defined in [7.11.3] shall be
 * contained in its data member." This server carried a code and a message
 * and no data member before 0.83, so a program that reads the condition the
 * same way through both channels found nothing to read in one of them
 * (weedmi BMCP-004).
 *
 * "An argument that does not conform to the input schema of a tool is
 * rejected before the operation is dispatched, and is reported as a JSON-RPC
 * error ... Both are the malformed request condition", which is the
 * condition every fault of this channel carries.
 */
function rpcProblem(detail: string, argument?: string): Record<string, unknown> {
  return {
    type: "https://www.snia.org/cdmi/problems/malformed-request",
    title: "The request is malformed.",
    detail,
    // "The name of the tool argument to which the condition relates, for a
    // protocol binding that transports an operation as a tool call ... An
    // argument is not a field of a representation, and is identified by this
    // member rather than by cdmi_field" (Annex C). Annex C assigns the member
    // to the malformed request condition, and the subclause's worked example of
    // an argument that does not conform to its input schema shows it. Every
    // fault of this channel relates to an argument, and none named it before
    // 0.96, so a program that reads the member to find which argument to
    // correct found nothing to read.
    ...(argument === undefined ? {} : { cdmi_argument: argument }),
  };
}

/**
 * The period for which a CDMI client may keep the tool list. "A ttlMs field
 * of at least 86400000 ... a CDMI server may state a longer period than the
 * one this subclause requires"; this server states the period the subclause
 * requires, one day, since a longer one buys a client nothing where the list
 * is fixed by the document.
 */
export const TOOL_LIST_TTL_MS = 86400000;

/**
 * The output schema every tool declares. "Exactly one of the two is present
 * in a result": the members of the result members table, or the problem
 * member. One schema describes both, "which is why a problem details
 * document is carried within a member rather than as the value of
 * structuredContent".
 */
export const RESULT_SCHEMA: Record<string, unknown> = {
  type: "object",
  properties: {
    uri: {
      type: "string",
      description: "The namespace path of the object the operation acted on. For a " +
        "cdmi_post call, and for any operation in which the CDMI server assigned the " +
        "name, this member reports the address at which the object is addressable " +
        "from then on.",
    },
    representation: {
      type: "string",
      description: "The type of the representation returned, in the form given for " +
        "the representation argument.",
    },
    object: {
      type: "object",
      description: "The representation of the object, complete or partial as the " +
        "selections of the operation determine. Absent where the operation returns " +
        "no representation.",
    },
    reference: {
      type: "string",
      description: "The destination of a reference, where the object addressed is one.",
    },
    baseUri: {
      type: "string",
      description: "The base URI the addresses of this result are relative to.",
    },
    correctedUri: {
      type: "string",
      description: "The namespace path in the form that addresses the object, where " +
        "the form of the uri argument did not address it.",
    },
    remote: {
      type: "array",
      items: { type: "string" },
      description: "The absolute URIs of another CDMI server that this result reports.",
    },
    validator: {
      type: "string",
      description: "The validator of the object as it stands after the operation, " +
        "which a CDMI client supplies as the ifMatch argument of a later call.",
    },
    problem: {
      type: "object",
      description: "The problem details document of an operation that was not " +
        "performed. A result carrying this member carries none of the members above.",
      properties: {
        type: { type: "string" },
        title: { type: "string" },
        detail: { type: "string" },
      },
      required: ["type", "title"],
    },
  },
  additionalProperties: true,
};

/**
 * A worked call per tool, carried in the _meta member of the tool.
 *
 * "The subclause's worked JSON-RPC exchanges are the cheapest conformance
 * tests; a machine-readable examples array on each tool (input + expected
 * result shape) would let a client offer a 'try it' prefilled call" (cvwm R4).
 * These are drawn from those exchanges, and each is a call that works against
 * this server as it stands.
 *
 * The Model Context Protocol defines no examples field on a tool, so they go in
 * the _meta member under a namespaced key rather than beside the fields the
 * protocol defines — which is what that member is for, and what keeps a client
 * that does not know the key from having to ignore an unexpected field. The key
 * is proposed for the subclause along with the rest of this; until the subclause
 * defines one, a client reading it reads an extension of this server's.
 */
const EXAMPLES: Record<string, { title: string; arguments: Record<string, unknown> }[]> = {
  cdmi_read: [
    {
      title: "Read the capabilities of a container object",
      arguments: { uri: "/cdmi_capabilities/container/?capabilities", representation: "cdmi-capability" },
    },
    {
      title: "List the children of a container object",
      arguments: { uri: "/?children" },
    },
    {
      title: "Read one metadata item of an object",
      arguments: { uri: "/reports/q3.txt?metadata=cdmi_acl" },
    },
  ],
  cdmi_create: [
    {
      title: "Create a data object, only where the name is free",
      arguments: {
        uri: "/reports/q3.txt",
        representation: "cdmi-object",
        body: { mimetype: "text/plain", value: "the third quarter" },
        onlyIfAbsent: true,
      },
    },
    {
      title: "Create a container object",
      arguments: { uri: "/reports/", representation: "cdmi-container", body: {} },
    },
  ],
  cdmi_update: [
    {
      title: "Replace one metadata item, leaving the rest of the object alone",
      arguments: {
        uri: "/reports/q3.txt?metadata=cdmi_acl",
        representation: "cdmi-object",
        mode: "replace-fields",
        body: {
          metadata: {
            cdmi_acl: [
              { acetype: "ALLOW", identifier: "OWNER@", aceflags: "NO_FLAGS", acemask: "ALL_PERMS" },
            ],
          },
        },
      },
    },
    {
      title: "Merge a metadata item into an object, removing one with null",
      arguments: {
        uri: "/reports/q3.txt",
        representation: "cdmi-object",
        mode: "merge",
        body: { metadata: { reviewed: "true", draft: null } },
      },
    },
  ],
  cdmi_delete: [
    {
      title: "Delete a data object, but only if it has not changed",
      arguments: { uri: "/reports/q3.txt", representation: "cdmi-object", ifMatch: '"68e5b53a"' },
    },
    {
      title: "Remove a range of the values a queue object holds",
      arguments: { uri: "/jobs/in?value=0-3", representation: "cdmi-queue" },
    },
  ],
  cdmi_post: [
    {
      title: "Create a data object under a name this CDMI server assigns",
      arguments: {
        uri: "/incoming/",
        representation: "cdmi-object",
        body: { mimetype: "text/plain", value: "whatever arrived" },
      },
    },
  ],
};

/** The input schema of a tool, from the arguments the subclause gives it. */
function schemaOf(tool: typeof TOOLS[number]): Record<string, unknown> {
  const properties: Record<string, unknown> = {};
  for (const a of tool.arguments) {
    properties[a] = {
      type: ARGUMENT_TYPES[a],
      description: DESCRIPTIONS[a],
      ...(ENUMS[a] === undefined ? {} : { enum: [...ENUMS[a]!] }),
    };
  }
  return {
    type: "object",
    properties,
    // "Mandatory in every call" for uri; mode is mandatory in cdmi_update.
    required: tool.name === "cdmi_update" ? ["uri", "mode"] : ["uri"],
    additionalProperties: false,
  };
}

/** What a call becomes once the shell has checked its shape. */
export interface ToolCall {
  tool: string;
  args: Record<string, unknown>;
  /** The request, for what the binding reads of it. */
  req: IncomingMessage;
  /**
   * The access token the request bears, resolved by the operation at the
   * domain that owns the object it addresses.
   */
  token: string;
  /** The Authorization header field as presented. */
  authorization?: string;
  /** The trace identifier of this operation, carried into any record of it. */
  traceparent?: string;
  /** What the calling program says of itself, recorded beside the trace. */
  client?: Record<string, unknown>;
}

export interface McpOptions {
  /** The address this endpoint is reported at, for cdmi_mcp_uri. */
  uri: string;
  host: string;
  port: number;
  tls?: { cert: string; key: string };
  log: Log;
  /** Performs a tool call, returning the tool result. The binding's. */
  call: (c: ToolCall) => Promise<Record<string, unknown>>;
  /**
   * The resource server this endpoint is. Every call is authorized through
   * it before the operation is dispatched: "authentication is performed by
   * the transport, before an operation is dispatched."
   */
  auth: ResourceServer;
  /** The base URIs this server reports under org.snia.cdmi/baseUris. */
  baseUris: () => string[];
  /**
   * The absolute base URIs at which clients reach this server, which a resource
   * of this endpoint is addressed beneath.
   *
   * A resource is addressed by a URI, so a base URI that is a path alone — which
   * the base of this server's own namespace is, until an export establishes an
   * absolute one — gives a client nothing to resolve against. This server knows
   * its absolute forms from its configuration, and they are the ones a resource
   * URI is built from and matched against. Where it is absent, the absolute
   * members of baseUris() serve.
   */
  ownBases?: () => string[];
  /**
   * The origins a browser-based client may present. "Servers MUST validate the
   * Origin header on all incoming connections to prevent DNS rebinding
   * attacks", and "if the Origin header is present and invalid, servers MUST
   * respond with HTTP 403 Forbidden". Nothing validated it before 0.90.
   *
   * A request carrying no Origin is not from a browser and is not refused:
   * the attack this guards against is a page in a browser reaching a server on
   * the loopback address, and a browser always sends the field. Refusing a
   * request that carries none would refuse every client that is not a browser,
   * which is most of them.
   */
  origins?: string[];
  /**
   * Whether to require the request metadata headers of revision 2026-07-28.
   *
   * A header that is present is always checked against the body, that being an
   * unconditional requirement. This governs a header that is absent: the
   * revision lets a server "treat a request that omits the header as protocol
   * version 2025-03-26" where it serves clients of the earlier revisions, and
   * requires it to reject such a request where it does not. Lenient is the
   * default, so that a client of an earlier revision, and a conformance suite
   * that predates this one, are still served.
   */
  strictHeaders?: boolean;
}

/**
 * The endpoint. Streamable HTTP, which is the transport a remote client
 * uses: each message is a POST to the one endpoint, and the reply is a JSON
 * object. The stdio transport is for a client that launches its server as a
 * subprocess, which is not what a CDMI server is.
 */
export class Mcp {
  private server: Server | undefined;

  private readonly opts: McpOptions;

  constructor(opts: McpOptions) {
    this.opts = opts;
  }

  async listen(): Promise<void> {
    const handler = (req: IncomingMessage, res: ServerResponse) => {
      void this.serve(req, res);
    };
    this.server = this.opts.tls === undefined
      ? createHttpServer(handler)
      : createHttpsServer({ cert: this.opts.tls.cert, key: this.opts.tls.key }, handler);
    await new Promise<void>((resolve) => {
      this.server!.listen(this.opts.port, this.opts.host, () => resolve());
    });
  }

  async close(): Promise<void> {
    const s = this.server;
    if (s === undefined) return;
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }

  private async serve(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // "Publish protected resource metadata as specified in RFC 9728": a
    // client that meets a challenge reads this to learn which authorization
    // servers issue a token for this endpoint.
    if (req.method === "GET" && (req.url ?? "").startsWith("/.well-known/oauth-protected-resource")) {
      this.send(req, res, 200, this.opts.auth.metadata());
      return;
    }
    // "Servers MUST validate the Origin header on all incoming connections to
    // prevent DNS rebinding attacks." Checked before anything else, including
    // before the credential: a page that should not be talking to this server
    // is refused whatever it presents.
    const origin = headerOf(req, "origin");
    if (origin !== undefined && !this.permitsOrigin(origin)) {
      // "If the Origin header is present and invalid, servers MUST respond
      // with HTTP 403 Forbidden. The HTTP response body MAY comprise a
      // JSON-RPC error response that has no id."
      this.send(req, res, 403, {
        jsonrpc: "2.0",
        error: {
          code: INVALID_REQUEST,
          message: `the origin ${origin} is not one this endpoint answers`,
        },
      });
      return;
    }
    // A preflight request, answered before anything is authenticated: a browser
    // never sends an Authorization header field on one, so a listener that
    // required a token here would refuse the request that asks whether the real
    // request may be sent. This endpoint answered 405 to an OPTIONS until 0.92,
    // so no browser client ever got as far as sending the real request.
    if (req.method === "OPTIONS") {
      answerListenerPreflight(this.opts.origins ?? [], req, res, {
        own: this.opts.uri,
        methods: ["POST", "OPTIONS"],
        headers: MCP_REQUEST_HEADERS,
        expose: MCP_EXPOSED_HEADERS,
      });
      return;
    }
    if (req.method !== "POST") {
      // "HTTP GET or DELETE to the MCP endpoint: respond with 405 Method Not
      // Allowed." Revision 2026-07-28 removed the standalone GET stream and
      // the sessions a DELETE terminated, so a POST is the whole transport.
      //
      // The body carries a JSON-RPC error, where 0.89 sent none. A client that
      // supports the deprecated HTTP and SSE transport falls back to it on a
      // 405 whose "response body is not a recognized modern JSON-RPC error",
      // and this server does not host that transport, so it would fall back to
      // something that is not there. An error body tells it to stop here.
      this.send(req, res, 405, {
        jsonrpc: "2.0",
        error: {
          code: METHOD_NOT_FOUND,
          message: `this endpoint answers POST; revision ${MCP_PROTOCOL_VERSION} of the Model Context ` +
            "Protocol removed the GET stream and the sessions a DELETE terminated",
        },
      }, { Allow: "POST" });
      return;
    }
    // A request bearing no token is the unauthenticated condition, which
    // the transport reports before any message is read: no tool has been
    // reached, so there is no tool result to carry it. Whether the token
    // is accepted is decided later, at the domain that owns the object the
    // call addresses.
    let token: string;
    try {
      const header = req.headers.authorization;
      token = this.opts.auth.tokenOf(Array.isArray(header) ? header[0] : header);
      // "Validate that each access token presented to it was issued for it,
      // and reject a token that does not identify it as the intended
      // recipient." This is checked before the message is read, so it
      // applies to every method and not to a tool call alone: the tool list
      // was served to any string presented as a bearer token before 0.83.
      await this.opts.auth.accept(token);
    } catch (e) {
      if (e instanceof Unauthenticated) {
        // The challenge, and the fields that let a browser client read it. A
        // cross-origin response carrying no Access-Control-Allow-Origin is
        // withheld from the page entirely — it does not arrive as a 401 that
        // the client can act on, it arrives as a failure to fetch — so before
        // 0.92 a browser client could not begin the authorization flow this
        // challenge exists to start.
        res.writeHead(401, {
          "WWW-Authenticate": e.challenge,
          ...this.cors(req),
        }).end();
        return;
      }
      throw e;
    }
    const body = await readBody(req);
    let message: Request;
    try {
      message = parseBody(body);
    } catch (e) {
      this.send(req, res, 200, {
        jsonrpc: "2.0",
        id: null,
        error: { code: (e as RpcError).code, message: (e as Error).message },
      });
      return;
    }
    // The headers that mirror the body, checked against it before the message
    // is acted on. Nothing checked them before 0.90.
    const mismatch = this.checkHeaders(req, message);
    if (mismatch !== undefined) {
      this.send(req, res, 400, {
        jsonrpc: "2.0",
        id: message.id ?? null,
        error: mismatch,
      });
      return;
    }
    const reply = await answer(message, (m) => this.dispatch(m, req, token),
      (e) => this.opts.log.write({
        at: new Date().toISOString(),
        message: `mcp: ${(e as Error).stack ?? String(e)}`,
        failed: true,
      } as never));
    if (reply === undefined) {
      // "If the server accepts it, the server MUST return HTTP status code
      // 202 Accepted with no body."
      res.writeHead(202).end();
      return;
    }
    // "If the server does not implement the requested RPC method, it MUST
    // respond with 404 Not Found and a JSON-RPC error with code -32601. The
    // JSON-RPC error body distinguishes this case from a 404 returned by a
    // legacy HTTP+SSE server that does not host the modern MCP endpoint."
    // 0.89 answered 200 with the error in the body, which a client performing
    // that discrimination reads as the method having been answered.
    //
    // A tools/call naming a tool this subclause does not define is an error of
    // the same code, and is not this: the method is implemented and its
    // argument names nothing. That one keeps its 200.
    const unknownMethod = reply.error?.code === METHOD_NOT_FOUND && message.method !== "tools/call";
    this.send(req, res, unknownMethod ? 404 : 200, reply);
  }

  /**
   * Whether an origin presented is one this endpoint answers. Where none is
   * configured, the endpoint's own origin is the one it answers: a page served
   * from where this endpoint is served is not the cross-origin case at all.
   */
  private permitsOrigin(origin: string): boolean {
    return listenerAllows(this.opts.origins ?? [], origin, this.opts.uri);
  }

  /**
   * The cross-origin fields of a response, where the request came from a
   * browser at an origin this endpoint answers.
   *
   * Validating the Origin field decides whether this server answers at all;
   * these decide whether the browser hands that answer to the page. Doing the
   * first without the second refuses nothing and is readable by nobody, which
   * is what this endpoint did between 0.90 and 0.92.
   */
  private cors(req: IncomingMessage): Record<string, string> {
    return listenerCorsOrVary(this.opts.origins ?? [], originOf(req),
      { own: this.opts.uri, expose: MCP_EXPOSED_HEADERS, cookie: req.headers.cookie !== undefined });
  }

  /**
   * The request metadata headers against the body they mirror.
   *
   * "Servers that process the request body MUST reject requests where the
   * values specified in the headers do not match the corresponding values in
   * the request body. This prevents potential security vulnerabilities when
   * different components in the network rely on different sources of truth
   * (e.g., a load balancer routing on the header value while the MCP server
   * executes based on the body value)." That is the point of the rule, and it
   * is why a header that is present is checked whether or not this server
   * requires one to be.
   */
  private checkHeaders(req: IncomingMessage, m: Request):
    { code: number; message: string; data?: unknown } | undefined {
    const strict = this.opts.strictHeaders === true;
    const mismatch = (detail: string) => ({ code: HEADER_MISMATCH, message: `Header mismatch: ${detail}` });

    // The protocol version, in the header and in the envelope of the body.
    const stated = headerOf(req, "mcp-protocol-version");
    const meta = (m.params?._meta ?? {}) as Record<string, unknown>;
    const carried = meta[META_PROTOCOL_VERSION];
    if (stated === undefined && carried === undefined) {
      if (strict) {
        return mismatch("the MCP-Protocol-Version header is required and was not sent");
      }
    } else {
      // "The header value MUST match the io.modelcontextprotocol/protocolVersion
      // field carried in the request body's _meta. If the values do not match,
      // the server MUST reject the request with 400 Bad Request and a
      // HeaderMismatch JSON-RPC error."
      if (stated !== undefined && carried !== undefined && stated !== carried) {
        return mismatch(`the MCP-Protocol-Version header value ${JSON.stringify(stated)} does not match ` +
          `the ${META_PROTOCOL_VERSION} field of the body, ${JSON.stringify(String(carried))}`);
      }
      const version = stated ?? String(carried);
      if (!PROTOCOL_VERSIONS.includes(version)) {
        // "If the server does not implement the requested protocol version
        // ... it MUST respond with 400 Bad Request and an
        // UnsupportedProtocolVersionError listing its supported versions."
        return {
          code: UNSUPPORTED_PROTOCOL_VERSION,
          message: `this CDMI server does not implement the protocol version ${version}`,
          data: { supported: PROTOCOL_VERSIONS },
        };
      }
    }

    // "Mcp-Method | method | All requests".
    const method = headerOf(req, "mcp-method");
    if (method === undefined) {
      if (strict) return mismatch("the Mcp-Method header is required and was not sent");
    } else if (method !== m.method) {
      return mismatch(`the Mcp-Method header value ${JSON.stringify(method)} does not match the method of ` +
        `the body, ${JSON.stringify(m.method)}`);
    }

    // "Mcp-Name | params.name or params.uri | tools/call, resources/read,
    // prompts/get requests". Of those three this binding offers tools/call.
    if (m.method === "tools/call") {
      const named = headerOf(req, "mcp-name");
      const inBody = m.params?.name;
      if (named === undefined) {
        if (strict && typeof inBody === "string") {
          return mismatch("the Mcp-Name header is required of a tools/call and was not sent");
        }
      } else if (decodeSentinel(named) !== inBody) {
        return mismatch(`the Mcp-Name header value ${JSON.stringify(decodeSentinel(named))} does not match ` +
          `the params.name of the body, ${JSON.stringify(inBody)}`);
      }
    }
    return undefined;
  }

  /**
   * The reply, framed as the client asked for it.
   *
   * A client that lists text/event-stream is answered with one: it is the
   * framing a client whose transport is in streaming mode can read, and a
   * client of this revision reads both, so nothing is lost by preferring it.
   */
  private send(req: IncomingMessage, res: ServerResponse, status: number, body: unknown,
    extra: Record<string, string> = {}): void {
    const cross = this.cors(req);
    if (status === 200 && wantsStream(req)) {
      // One event carrying the response, and the stream ends: "the final
      // JSON-RPC response SHOULD terminate the stream". This binding sends no
      // notification before it, having no progress to report from an operation
      // that is performed before it answers.
      const frame = Buffer.from(`event: message\ndata: ${JSON.stringify(body)}\n\n`);
      res.writeHead(status, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache, no-store",
        Connection: "keep-alive",
        // "When initiating an SSE stream, servers SHOULD include the
        // X-Accel-Buffering: no header in the HTTP response. This instructs
        // reverse proxies (such as nginx) to disable response buffering."
        "X-Accel-Buffering": "no",
        ...cross,
        ...extra,
      }).end(frame);
      return;
    }
    const text = Buffer.from(`${JSON.stringify(body)}\n`);
    res.writeHead(status, {
      "Content-Type": "application/json",
      "Content-Length": String(text.length),
      ...cross,
      ...extra,
    }).end(text);
  }

  /** The methods of the protocol this binding answers. */
  private async dispatch(m: Request, req: IncomingMessage, token: string): Promise<unknown> {
    switch (m.method) {
      case "initialize":
        return {
          protocolVersion: MCP_PROTOCOL_VERSION,
          capabilities: CAPABILITIES,
          serverInfo: SERVER_INFO(),
          // The base URIs a namespace path is resolved against, which the
          // subclause reports under these names. They are reported here as
          // well as on server/discover, which is where the subclause requires
          // them, so that a CDMI client that reads them from the handshake is
          // not obliged to make a second call.
          _meta: {
            [META_SERVER_INFO]: SERVER_INFO(),
            "org.snia.cdmi/baseUri": this.opts.baseUris()[0],
            "org.snia.cdmi/baseUris": this.opts.baseUris(),
          },
        };
      case "notifications/initialized":
        return {};
      // "A CDMI server that serves this protocol binding shall answer the
      // server/discover method, whether or not the Model Context Protocol
      // requires an MCP server to answer it, a CDMI client of this protocol
      // binding obtaining the base URI in no other way" (revision 365). Before
      // 0.85 this server answered the method-not-found error, and reported the
      // base URIs on initialize alone and under the plural key only, so a CDMI
      // client that called the method the subclause names got nothing.
      case "server/discover": {
        const bases = this.opts.baseUris();
        return {
          // The version of the Model Context Protocol this server speaks, and
          // what it offers, stated here as they are stated on initialize. A
          // client that pins a version negotiates it from the result of this
          // method, and one that finds no version offered here has nothing to
          // negotiate against and no fallback: "Version negotiation failed:
          // the server did not offer pinned protocol version ... via
          // server/discover". 0.85 answered the method without them.
          protocolVersion: MCP_PROTOCOL_VERSION,
          // The versions this server will accept, so that a client pinning one
          // of them sees it offered rather than inferring it from the single
          // version above.
          protocolVersions: PROTOCOL_VERSIONS,
          capabilities: CAPABILITIES,
          serverInfo: SERVER_INFO(),
          _meta: {
            // "Server responses include io.modelcontextprotocol/serverInfo in
            // result _meta": the envelope of revision 2026-07-28, which a
            // client reads where it no longer has a handshake to read it from.
            [META_SERVER_INFO]: SERVER_INFO(),
            // "The CDMI server shall report it in the _meta member of that
            // result, using the key org.snia.cdmi/baseUri, and its value shall
            // be a base URI": the one a call naming none is resolved against,
            // which is the first of them.
            "org.snia.cdmi/baseUri": bases[0],
            // "The base URI reported under org.snia.cdmi/baseUri shall be one
            // of them, and is the one a call that names none is resolved
            // against."
            "org.snia.cdmi/baseUris": bases,
          },
        };
      }
      case "tools/list":
        return {
          // "The resultType member that [the Model Context Protocol] requires
          // on each result": a method result carries it as a tool result does.
          // Only a tool result carried one before 0.96.
          resultType: "complete",
          tools: TOOLS.map((t) => ({
            name: t.name,
            // The human name beside the machine one, which a client shows in
            // the tool list where it has one (cvwm R4). The Model Context
            // Protocol allows it; the subclause fixes the name and says
            // nothing of the title, so declaring one is not a divergence.
            title: t.title,
            description: t.description,
            inputSchema: schemaOf(t),
            // "A CDMI server shall declare them in the input schema of each
            // tool, and shall declare the result of each tool in the output
            // schema of that tool. The output schema describes both outcomes
            // of a call: the members of [the result members table], and the
            // problem member of a result reporting an operation that was not
            // performed." Every tool returns the same shape, so one schema
            // serves them all; a tool declared none before 0.83 (weedmi
            // BMCP-002).
            outputSchema: RESULT_SCHEMA,
            annotations: t.annotations,
            // A worked call a client can prefill, under a namespaced key of the
            // _meta member, the protocol defining no examples field of its own.
            _meta: { "org.snia.cdmi/examples": EXAMPLES[t.name] ?? [] },
          })),
          // "A CDMI server shall return, in the result of a tools/list call,
          // a cacheScope field of public and a ttlMs field of at least
          // 86400000. The list is the list of [the tools table] for every
          // CDMI client of every CDMI server, so it is neither per-principal
          // nor per-server." Neither field was returned before 0.83.
          cacheScope: "public",
          ttlMs: TOOL_LIST_TTL_MS,
        };
      case "tools/call": {
        // "A CDMI client, an intermediary and a CDMI server carry a trace
        // identifier in the _meta member of a call and of a result, under
        // the key org.snia.cdmi/traceparent ... A CDMI server that
        // receives a call carrying none generates one and reports it in
        // the result", so that the record an intermediary keeps and the
        // record this server keeps are recognizable as being of one
        // operation.
        const meta = (m.params?._meta ?? {}) as Record<string, unknown>;
        const carried = meta["org.snia.cdmi/traceparent"];
        const traceparent = typeof carried === "string" && TRACEPARENT.test(carried)
          ? carried
          : newTraceparent();
        const name = m.params?.name;
        if (typeof name !== "string") {
          throw new RpcError(INVALID_PARAMS, 'the "name" member holds the name of a tool',
            rpcProblem('the "name" member of a tools/call holds the name of a tool'));
        }
        if (!TOOLS.some((t) => t.name === name)) {
          // "A call naming a tool this subclause does not define" is a
          // JSON-RPC error and not a tool result: it is detected before any
          // operation is attempted.
          throw new RpcError(METHOD_NOT_FOUND, `this CDMI server defines no tool named ${name}`,
            rpcProblem(`this CDMI server defines no tool named ${name}: the tools are ` +
              TOOLS.map((t) => t.name).join(", ")));
        }
        const args = (m.params?.arguments ?? {}) as Record<string, unknown>;
        checkArguments(name, args);
        // The token is resolved by the operation, at the domain that owns
        // the object, and the scope is checked there against what that
        // resolution returns. The scope narrows what a token may ask for;
        // the access control lists of the object decide what the principal
        // may do, and are evaluated regardless of any scope.
        const answered = await this.opts.call({
          tool: name, args, req, token, traceparent,
          // The program that made the call, which a record keeps beside
          // the trace identifier.
          // What the calling program says of itself. Revision 2026-07-28 moved
          // it under a reserved key of the envelope, there being no handshake
          // left to state it once; the unqualified name is read too, for a
          // client of an earlier revision.
          client: ((meta[META_CLIENT_INFO] ?? meta.clientInfo) ?? {}) as Record<string, unknown>,
          // The credential as presented, so that a deployment accepting a
          // scheme other than Bearer at its CDMI binding is served too.
          authorization: Array.isArray(req.headers.authorization)
            ? req.headers.authorization[0]
            : req.headers.authorization,
        });
        return {
          ...answered,
          _meta: {
            ...((answered._meta ?? {}) as Record<string, unknown>),
            [META_SERVER_INFO]: SERVER_INFO(),
            "org.snia.cdmi/traceparent": traceparent,
          },
        };
      }
      // The prompts of this server. Not a requirement of the subclause, which
      // standardized the tools and left prompts out; each one wraps a job whose
      // rules a bare tool call cannot enforce (cvwm R2).
      case "prompts/list":
        return {
          resultType: "complete",
          prompts: promptList(),
          // The catalogue is fixed by this module, as the tool list is fixed by
          // the subclause, so it is neither per-principal nor per-server and a
          // client may keep it for as long.
          cacheScope: "public",
          ttlMs: TOOL_LIST_TTL_MS,
        };
      case "prompts/get": {
        const name = m.params?.name;
        const prompt = PROMPTS.find((p) => p.name === name);
        if (prompt === undefined) {
          // "Invalid prompt name: -32602 (Invalid params)."
          throw new RpcError(INVALID_PARAMS,
            `this CDMI server defines no prompt named ${JSON.stringify(name)}`,
            rpcProblem(`this CDMI server defines no prompt named ${JSON.stringify(name)}: the ` +
              `prompts are ${PROMPTS.map((p) => p.name).join(", ")}`));
        }
        const supplied = (m.params?.arguments ?? {}) as Record<string, unknown>;
        const wrong = checkPromptArguments(prompt, supplied);
        if (wrong !== undefined) throw new RpcError(INVALID_PARAMS, wrong, rpcProblem(wrong));
        const args = supplied as Record<string, string>;
        return {
          resultType: "complete",
          description: prompt.summary(args),
          // The current state of each object the prompt edits, read as the
          // requesting principal and not as this server: a prompt hands over
          // only what the caller may already read, so the embedded state is not
          // a way around the access control lists.
          messages: await promptMessages(prompt, args,
            async (uri) => await this.readForPrompt(uri, req, token)),
        };
      }
      // The resources of this server: the objects of the namespace, addressed
      // by the http or https URI that addresses them over the HTTP protocol
      // binding. Also an extension of this server's (cvwm R3).
      case "resources/list":
        return {
          resultType: "complete",
          resources: resourceList(this.resourceBases()),
          cacheScope: "public",
          ttlMs: TOOL_LIST_TTL_MS,
        };
      case "resources/templates/list":
        return {
          resultType: "complete",
          resourceTemplates: resourceTemplates(this.resourceBases()),
          cacheScope: "public",
          ttlMs: TOOL_LIST_TTL_MS,
        };
      case "resources/read": {
        const uri = m.params?.uri;
        if (typeof uri !== "string") {
          throw new RpcError(INVALID_PARAMS, 'the "uri" member holds the URI of a resource',
            rpcProblem('the "uri" member of a resources/read holds the URI of a resource'));
        }
        const within = pathOfResource(uri, this.resourceBases());
        if (within === undefined) {
          // Not a resource of this server. The revision permits a client to
          // fetch an https resource itself, so one holding such a URI has a way
          // to read it that is not this method.
          const detail = `${uri} is not beneath a base URI this CDMI server serves; they are ` +
            this.resourceBases().join(", ");
          throw new RpcError(INVALID_PARAMS, detail, rpcProblem(detail));
        }
        // A read that names no field returns the fields the representations
        // clause gives it, and the "value" field is not among them: a client
        // asking for a resource is asking for the content, so where it named no
        // selection of its own the whole representation is selected. "A field
        // selection of * selects every field of the representation, the value
        // field included." A selection the client did name is honoured as it
        // stands, that being what it asked for.
        const selected = within.uri.includes("?") ? within.uri : `${within.uri}?*`;
        const read = await this.readAsPrincipal(selected, req, token);
        if (read.problem !== undefined) {
          // Every condition of this method is a JSON-RPC error: a
          // resources/read result carries no isError member to report one in.
          throw new RpcError(codeOfProblem(read.problem),
            String(read.problem.detail ?? read.problem.title ?? "the resource was not read"),
            read.problem);
        }
        return {
          resultType: "complete",
          contents: contentsOf(uri, read.object!),
          // A representation is what the access control lists grant this
          // principal at this moment, so it is not a public document and a
          // shared cache must not keep it.
          cacheScope: "private",
          ttlMs: 0,
        };
      }
      default:
        throw new RpcError(METHOD_NOT_FOUND, `the method ${m.method} is not offered`);
    }
  }

  /**
   * A read performed for this channel, through the path a tools/call takes.
   *
   * The operation is the binding's cdmi_read, dispatched with the token the
   * request presented, so the token resolution, the scope check, the access
   * control lists, the selections and the conditions are that path's. A
   * resources/read and a prompt's embedded state therefore return exactly what
   * a cdmi_read by the same principal would return, and neither is a second
   * place where a rule could be forgotten.
   */
  /**
   * The absolute base URIs a resource of this endpoint is addressed beneath: the
   * ones this server is configured with, and any an export established. A base
   * URI that is a path alone is not among them, a resource being addressed by a
   * URI and a path giving a client nothing to resolve against.
   */
  private resourceBases(): string[] {
    const absolute = (b: string) => /^https?:\/\//i.test(b);
    const stated = (this.opts.ownBases?.() ?? []).filter(absolute);
    const reported = this.opts.baseUris().filter(absolute);
    return [...new Set([...stated, ...reported])];
  }

  private async readAsPrincipal(uri: string, req: IncomingMessage, token: string):
    Promise<{ object?: Record<string, unknown>; problem?: Record<string, unknown> }> {
    const answered = await this.opts.call({
      tool: "cdmi_read",
      args: { uri },
      req,
      token,
      traceparent: newTraceparent(),
      client: {},
      authorization: Array.isArray(req.headers.authorization)
        ? req.headers.authorization[0]
        : req.headers.authorization,
    });
    const structured = (answered.structuredContent ?? {}) as Record<string, unknown>;
    if (answered.isError === true) return { problem: structured };
    return { object: (structured.object ?? {}) as Record<string, unknown> };
  }

  /**
   * The state a prompt embeds, as a resource block, or nothing where it cannot
   * be read. A prompt runs before its object exists — provisioning a home is
   * the case — so a read that fails omits the block rather than failing the
   * prompt; the instructions do not depend on it.
   */
  private async readForPrompt(uri: string, req: IncomingMessage, token: string):
    Promise<Record<string, unknown> | undefined> {
    const base = this.resourceBases()[0] ?? this.opts.baseUris()[0] ?? "/";
    const read = await this.readAsPrincipal(uri, req, token);
    if (read.problem !== undefined) return undefined;
    const absolute = `${base.replace(/\/+$/, "/")}${uri.replace(/^\//, "")}`;
    return contentsOf(absolute, read.object!)[0];
  }
}

/**
 * The arguments of a call against the input schema of its tool. "A CDMI
 * server shall report the malformed request condition where an argument
 * that does not apply to the tool called is supplied", and a call whose
 * arguments do not conform to the schema is a JSON-RPC error rather than a
 * tool result, being detected before the operation.
 */
export function checkArguments(tool: string, args: Record<string, unknown>): void {
  const defined = TOOLS.find((t) => t.name === tool)!;
  for (const [k, v] of Object.entries(args)) {
    if (!(defined.arguments as readonly string[]).includes(k)) {
      const detail = `the ${tool} tool takes no argument named ${JSON.stringify(k)}`;
      throw new RpcError(INVALID_PARAMS, detail, rpcProblem(detail, k));
    }
    const want = ARGUMENT_TYPES[k];
    const is = want === "object"
      ? typeof v === "object" && v !== null && !Array.isArray(v)
      : typeof v === want;
    if (!is) {
      const detail = `the ${k} argument holds a JSON ${want}`;
      throw new RpcError(INVALID_PARAMS, detail, rpcProblem(detail, k));
    }
    // A value outside the set the schema declares. It is refused here, before
    // the operation is dispatched, because the schema declares the set: "An
    // argument that does not conform to the input schema of a tool is rejected
    // before the operation is dispatched, and is reported as a JSON-RPC error."
    // An out-of-set mode was detected after dispatch until 0.96, once the
    // target had been read, and reported in the tool result.
    if (!admits(k, v)) {
      const detail = `the ${k} argument holds one of ${ENUMS[k]!.join(", ")}; ` +
        `${JSON.stringify(v)} is none`;
      throw new RpcError(INVALID_PARAMS, detail, rpcProblem(detail, k));
    }
  }
  if (typeof args.uri !== "string") {
    throw new RpcError(INVALID_PARAMS, "the uri argument is supplied in every call",
      rpcProblem("the uri argument is supplied in every call", "uri"));
  }
  if (tool === "cdmi_update" && typeof args.mode !== "string") {
    // The detail the subclause's worked example gives for this case, which
    // names the argument and the tool that requires it.
    const detail = `The 'mode' argument is required by the ${tool} tool and was not supplied.`;
    throw new RpcError(INVALID_PARAMS, detail, rpcProblem(detail, "mode"));
  }
}

/** The body of a request, read whole. */
function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const parts: Buffer[] = [];
    req.on("data", (c: Buffer) => parts.push(c));
    req.on("end", () => resolve(Buffer.concat(parts).toString("utf8")));
    req.on("error", reject);
  });
}

/** Filled by the binding, which knows the version of this server. */
export let VERSION_OF = "0";
export const setVersion = (v: string): void => { VERSION_OF = v; };
