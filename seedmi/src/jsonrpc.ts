// JSON-RPC 2.0, as the Model Context Protocol encodes its messages.
//
// Written here rather than taken from a library: the protocol is small, the
// parts this binding needs are smaller still, and the error reporting has to
// meet a rule of the CDMI subclause that a general library would not know
// about — a call naming a tool the subclause does not define, and a call
// whose arguments do not conform to the input schema, are reported as a
// JSON-RPC error carrying a CDMI problem details document, while every other
// condition is reported in the tool result.
//
// This module knows nothing of CDMI. It parses, validates and frames; the
// binding in mcp.ts decides what the messages mean.

/** A request, a notification, or a response: what a peer may send. */
export interface Request {
  jsonrpc: "2.0";
  /** Absent in a notification, which is not answered. */
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

export interface ErrorObject {
  code: number;
  message: string;
  /** The problem details document, where a CDMI condition is being reported. */
  data?: unknown;
}

export interface Response {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: ErrorObject;
}

/**
 * The error codes of JSON-RPC 2.0. The subclause chooses between a JSON-RPC
 * error and a tool result by where the condition is detected, so only the
 * codes for a message this layer itself rejects are needed, plus
 * INVALID_PARAMS, which the binding raises for arguments that do not conform
 * to the input schema of a tool.
 */
export const PARSE_ERROR = -32700;
export const INVALID_REQUEST = -32600;
export const METHOD_NOT_FOUND = -32601;
export const INVALID_PARAMS = -32602;
export const INTERNAL_ERROR = -32603;

/**
 * The codes the Model Context Protocol allocates itself, from the range
 * -32020 to -32099 that revision 2026-07-28 reserves for the specification.
 * They are the transport's, not this document's, and are raised by the
 * Streamable HTTP binding before a message reaches any CDMI operation.
 */
export const HEADER_MISMATCH = -32020;
export const MISSING_CLIENT_CAPABILITY = -32021;
export const UNSUPPORTED_PROTOCOL_VERSION = -32022;

/** An error to answer with, carrying an optional problem details document. */
export class RpcError extends Error {
  readonly code: number;
  readonly data?: unknown;
  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = "RpcError";
    this.code = code;
    this.data = data;
  }
}

/** Whether a value is a JSON object, which the protocol's members must be. */
const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * Reads one message. A message that is not a conformant request is refused
 * here, before anything else sees it: the id is echoed where one can be
 * found, since a peer matches an answer to a call by that alone.
 */
export function parseRequest(raw: unknown): Request {
  if (!isObject(raw)) {
    throw new RpcError(INVALID_REQUEST, "a JSON-RPC message is a JSON object");
  }
  if (raw.jsonrpc !== "2.0") {
    throw new RpcError(INVALID_REQUEST, 'the "jsonrpc" member holds "2.0"');
  }
  if (typeof raw.method !== "string" || raw.method === "") {
    throw new RpcError(INVALID_REQUEST, 'the "method" member holds the name of the method');
  }
  const id = raw.id;
  if (id !== undefined && id !== null && typeof id !== "string" && typeof id !== "number") {
    throw new RpcError(INVALID_REQUEST, 'the "id" member holds a string, a number, or null');
  }
  if (raw.params !== undefined && !isObject(raw.params)) {
    // The protocol permits positional parameters; this binding uses named
    // parameters throughout, so an array is refused rather than guessed at.
    throw new RpcError(INVALID_PARAMS, 'the "params" member holds a JSON object');
  }
  return {
    jsonrpc: "2.0",
    ...(id === undefined ? {} : { id: id as string | number | null }),
    method: raw.method,
    ...(raw.params === undefined ? {} : { params: raw.params }),
  };
}

/** Parses the body of a message, refusing what is not JSON. */
export function parseBody(body: string): Request {
  let raw: unknown;
  try {
    raw = JSON.parse(body);
  } catch (e) {
    throw new RpcError(PARSE_ERROR, `the message is not JSON: ${(e as Error).message}`);
  }
  if (Array.isArray(raw)) {
    // A batch. The Model Context Protocol of this revision does not use one,
    // and answering half a batch is worse than refusing it whole.
    throw new RpcError(INVALID_REQUEST, "a batch of messages is not accepted");
  }
  return parseRequest(raw);
}

/** A notification is a request with no id, and is never answered. */
export const isNotification = (r: Request): boolean => r.id === undefined;

export const result = (id: string | number | null, value: unknown): Response =>
  ({ jsonrpc: "2.0", id, result: value });

export const failure = (id: string | number | null, e: RpcError): Response => ({
  jsonrpc: "2.0",
  id,
  error: { code: e.code, message: e.message, ...(e.data === undefined ? {} : { data: e.data }) },
});

/**
 * The answer to a message, or undefined where none is owed. Anything the
 * handler throws that is not an RpcError is an internal error: the message
 * is not disclosed to the peer, which has no use for it and may not be
 * trusted with it, and the caller logs it instead.
 */
export async function answer(message: Request,
  handle: (r: Request) => Promise<unknown>,
  onInternal?: (e: unknown) => void): Promise<Response | undefined> {
  const id = message.id ?? null;
  try {
    const value = await handle(message);
    return isNotification(message) ? undefined : result(id, value);
  } catch (e) {
    if (e instanceof RpcError) {
      return isNotification(message) ? undefined : failure(id, e);
    }
    onInternal?.(e);
    return isNotification(message)
      ? undefined
      : failure(id, new RpcError(INTERNAL_ERROR, "the request could not be completed"));
  }
}
