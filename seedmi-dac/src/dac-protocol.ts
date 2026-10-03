// The delegated access control protocol from the provider's side: reading a
// packaged request, and building a packaged response (Delegated access
// control, revision 247 of the CDMI 3.0 draft).
//
// The draft specifies the CDMI server's side closely and the provider's
// barely; what a provider must do is mostly implied by the fields a response
// carries. Each rule taken here is quoted where it is applied.

import { createPublicKey, type KeyObject } from "node:crypto";
import {
  decryptJwe, encryptJweJson, flattenJws, importJwk, type Jwk, JoseError, nestedJws, signJws, unb64u, verifyJws,
} from "./jose.ts";

/** A request this provider does not evaluate, and why. */
export class DacRefusal extends Error {
  readonly reason: "malformed" | "not-addressed" | "undecryptable" | "unverified" | "untrusted" | "replayed";
  constructor(reason: DacRefusal["reason"], message: string) {
    super(message);
    this.reason = reason;
  }
}

/** The provider's keys: see PLAN-dacd.md, "Its keys". */
export interface ProviderKeys {
  /** The private key requests are encrypted to: that of the certificate objects name in cdmi_dac_certificate. */
  decryption: KeyObject;
  /** That certificate as objects hold it in cdmi_dac_certificate: a JWK, with x5c. */
  certificate: Jwk;
  /** The private key responses are signed with. */
  signing: KeyObject;
  /**
   * The chain of the signing key's certificate, base64 DER, leaf first, sent as
   * x5c in the JWS header: "The provider may sign with a different key where the
   * certificate for that key chains to the certificate contained in the
   * cdmi_dac_certificate metadata item". Absent where the signing key is the
   * decryption key.
   */
  signingChain?: string[];
}

/** The operations a request may name: "The following operations are defined". */
/**
 * The values of cdmi_operation, one for each access (revision 269, Table "The
 * value of cdmi_operation for each access"; ECR-066B). The first three are those
 * of revision 247, which a server still sends for the accesses they named.
 */
export const OPERATIONS = ["cdmi_read", "cdmi_modify", "cdmi_delete",
  "cdmi_read_metadata", "cdmi_list", "cdmi_create", "cdmi_modify_metadata"] as const;

/** A request, read, decrypted and verified. */
export interface DacRequest {
  id: string;
  /** The server's keys, from server_identity: one to verify its request, one to encrypt the response to. */
  serverSig: Jwk;
  serverEnc: Jwk;
  client?: { name: string; groups: string[] };
  effectiveMask: string;
  clientHeaders: Record<string, string>;
  objectId: string;
  operation: (typeof OPERATIONS)[number];
  encKeyId?: Record<string, unknown>;
  responseUri?: string;
  /** Where the packaged request said it was bound. */
  destUri: string;
}

/** What the provider decides. */
export interface DacDecision {
  appliedMask: string;
  /** Header fields for the CDMI client; only those beginning CDMI-DAC- are sent. */
  responseHeaders?: Record<string, string>;
  responseCacheExpiry?: Date;
  redirectObjectID?: string;
  auditUri?: string;
}

const text = (v: unknown, field: string): string => {
  if (typeof v !== "string") throw new DacRefusal("malformed", `the ${field} field is a JSON string`);
  return v;
};

/** The public key a JWK holds, compared by its SPKI encoding. */
function sameKey(a: Jwk, b: Jwk): boolean {
  try {
    // A JWK imports as a public key, which createPublicKey does not take again.
    const der = (j: Jwk) => {
      const k = importJwk(j);
      return (k.type === "public" ? k : createPublicKey(k)).export({ format: "der", type: "spki" }) as Buffer;
    };
    return der(a).equals(der(b));
  } catch {
    return false;
  }
}

/** The payload of a JWS in the flattened JSON serialization, before it is verified. */
function unverifiedPayload(jws: Record<string, string>): Record<string, unknown> {
  const encoded = jws.payload;
  const payload = JSON.parse(unb64u(encoded).toString("utf8")) as unknown;
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new DacRefusal("malformed", "the request is not a JSON object");
  }
  return payload as Record<string, unknown>;
}

/**
 * Reads a packaged request (the Packaged DAC request table): checks it is
 * addressed to this provider, decrypts it, verifies its signature with the key
 * the request gives for that purpose, and checks each field. Phase 1 verifies
 * the signature but does not authenticate the key; phase 2 does (dac-trust.ts).
 */
export function readRequest(body: Buffer | string, keys: ProviderKeys): DacRequest {
  let packaged: Record<string, unknown>;
  try {
    packaged = JSON.parse(body.toString()) as Record<string, unknown>;
  } catch {
    throw new DacRefusal("malformed", "the packaged request is not JSON");
  }
  if (packaged === null || typeof packaged !== "object" || Array.isArray(packaged)) {
    throw new DacRefusal("malformed", "the packaged request is not a JSON object");
  }
  const inner = packaged.dac_request;
  if (inner === null || typeof inner !== "object" || Array.isArray(inner)) {
    throw new DacRefusal("malformed", "dac_request is a JSON object, the request encrypted in JWE format");
  }
  // "dac_request_dest_certificate: The value of the cdmi_dac_certificate
  // metadata item of the object, which specifies the delegated access control
  // provider for which the request is" intended.
  const dest = packaged.dac_request_dest_certificate;
  if (dest === null || typeof dest !== "object" || !sameKey(dest as Jwk, keys.certificate)) {
    throw new DacRefusal("not-addressed", "the request is addressed to another provider's certificate");
  }
  const destUri = text(packaged.dac_request_dest_uri, "dac_request_dest_uri");

  // Signed, then encrypted: the JWE's plaintext is the JWS in the flattened JSON
  // serialization, and its cty "jose+json" (revision 269; ECR-073B).
  let jws: Record<string, string>;
  try {
    jws = nestedJws(decryptJwe(inner as Record<string, unknown>, keys.decryption));
  } catch (e) {
    if (e instanceof JoseError) throw new DacRefusal("undecryptable", `the request does not decrypt: ${e.message}`);
    throw e;
  }

  // The key that verifies the request is in the request: "one key whose use
  // member contains sig, whose public key verifies the signature on the
  // request". It is found in the payload, and the payload is then verified.
  const claimed = unverifiedPayload(jws);
  const identity = claimed.server_identity as { keys?: unknown } | undefined;
  const set = Array.isArray(identity?.keys) ? (identity!.keys as Jwk[]) : [];
  const sig = set.filter((k) => k?.use === "sig");
  const enc = set.filter((k) => k?.use === "enc");
  if (sig.length !== 1 || enc.length !== 1) {
    throw new DacRefusal("malformed", "server_identity holds one key whose use is sig and one whose use is enc");
  }
  // "The two shall be different keys."
  if (sameKey(sig[0], enc[0])) throw new DacRefusal("malformed", "the sig and enc keys of server_identity are one key");
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(verifyJws(jws, importJwk(sig[0])).payload.toString("utf8")) as Record<string, unknown>;
  } catch (e) {
    if (e instanceof JoseError) throw new DacRefusal("unverified", `the request's signature does not verify: ${e.message}`);
    throw e;
  }

  // The fields of the request (the DAC request table). A member not recognized
  // is ignored.
  if (payload.dac_request_version !== "1") {
    throw new DacRefusal("malformed", 'dac_request_version "shall be set to the value 1"');
  }
  const id = text(payload.dac_request_id, "dac_request_id");
  if (id === "") throw new DacRefusal("malformed", "dac_request_id is empty");
  const operation = text(payload.cdmi_operation, "cdmi_operation");
  if (!(OPERATIONS as readonly string[]).includes(operation)) {
    throw new DacRefusal("malformed", `cdmi_operation ${JSON.stringify(operation)} is not one the draft defines`);
  }
  const headers = payload.client_headers;
  if (headers === null || typeof headers !== "object" || Array.isArray(headers) ||
      Object.values(headers).some((v) => typeof v !== "string")) {
    throw new DacRefusal("malformed", "client_headers is a JSON object holding a JSON string for each header field");
  }
  let client: DacRequest["client"];
  if (payload.client_identity !== undefined) {
    const c = payload.client_identity as Record<string, unknown>;
    if (c === null || typeof c !== "object" || typeof c.acl_name !== "string" ||
        (c.acl_group !== undefined && !(Array.isArray(c.acl_group) && c.acl_group.every((g) => typeof g === "string")))) {
      throw new DacRefusal("malformed", "client_identity holds acl_name, a string, and acl_group, an array of strings");
    }
    client = { name: c.acl_name, groups: (c.acl_group as string[] | undefined) ?? [] };
  }
  let responseUri: string | undefined;
  if (payload.dac_response_uri !== undefined) {
    responseUri = text(payload.dac_response_uri, "dac_response_uri");
    try {
      new URL(responseUri);
    } catch {
      throw new DacRefusal("malformed", "dac_response_uri is not an absolute URI");
    }
  }
  const encKey = payload.cdmi_enc_key_id;
  return {
    id,
    serverSig: sig[0],
    serverEnc: enc[0],
    ...(client === undefined ? {} : { client }),
    effectiveMask: text(payload.acl_effective_mask, "acl_effective_mask"),
    clientHeaders: headers as Record<string, string>,
    objectId: text(payload.cdmi_objectID, "cdmi_objectID"),
    operation: operation as DacRequest["operation"],
    ...(encKey !== null && typeof encKey === "object" ? { encKeyId: encKey as Record<string, unknown> } : {}),
    ...(responseUri === undefined ? {} : { responseUri }),
    destUri,
  };
}

/** A time as the draft writes one: "YYYY-MM-DDThh:mm:ss.ssssssZ", to six digits, in UTC. */
export function cdmiTime(d: Date): string {
  return d.toISOString().replace(/\.(\d{3})Z$/, ".$1000Z");
}

/**
 * Builds the packaged response to a request (the DAC response and Packaged DAC
 * response tables): the response signed with the provider's signing key, and
 * encrypted to the server's enc key.
 */
export function buildResponse(req: DacRequest, decision: DacDecision, keys: ProviderKeys): Record<string, unknown> {
  const response: Record<string, unknown> = {
    dac_response_version: "1",
    // "Contains the system-specified identifier specified in the corresponding dac_request_id."
    dac_response_id: req.id,
    dac_applied_mask: decision.appliedMask,
  };
  // "A series of headers that start with CDMI-DAC- to be returned to the CDMI client."
  const headers = Object.fromEntries(Object.entries(decision.responseHeaders ?? {})
    .filter(([name]) => name.toUpperCase().startsWith("CDMI-DAC-")));
  if (Object.keys(headers).length > 0) response.dac_response_headers = headers;
  if (decision.responseCacheExpiry !== undefined) {
    response.dac_response_cache_expiry = cdmiTime(decision.responseCacheExpiry);
  }
  if (decision.redirectObjectID !== undefined) response.dac_redirect_objectID = decision.redirectObjectID;
  if (decision.auditUri !== undefined) response.dac_audit_uri = decision.auditUri;

  // Signed, then encrypted, the JWS in the flattened JSON serialization and cty
  // "jose+json", as revision 269 requires (ECR-073B). Before 0.8 the JWS was
  // compact, with cty "JWT".
  const jws = signJws(Buffer.from(JSON.stringify(response), "utf8"), keys.signing,
    keys.signingChain === undefined ? {} : { x5c: keys.signingChain });
  const recipient = importJwk(req.serverEnc);
  return {
    dac_response: encryptJweJson(Buffer.from(JSON.stringify(flattenJws(jws)), "utf8"), recipient, { cty: "jose+json" }),
    // "The key of the server_identity field of the request to which this
    // response corresponds whose use member contains enc", and "A delegated
    // access control provider shall not return the key whose use member
    // contains sig in this field."
    dac_response_dest_certificate: req.serverEnc,
    ...(req.responseUri === undefined ? {} : { dac_response_dest_uri: req.responseUri }),
  };
}
