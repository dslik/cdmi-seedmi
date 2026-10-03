// Scope binding: the record, held at the key management server itself, of
// which CDMI servers are authorized to resolve credential references against a
// scope (the Scope binding subclause of the CDMI 3.0 working draft, revision
// 232).
//
// "A scope is a Name prefix, and a Name prefix is a value a CDMI client is able
// to write into the cdmi_domain_kms item of a domain object it administers",
// so without this a CDMI client could declare another domain's scope and reach
// its credentials. The binding key of a scope is the durable record of the
// claim: "A CDMI server that has lost the record of the scopes it uses
// reconstructs it from the binding keys held at the key management server."

import { createHash, createPublicKey, createVerify, randomBytes, type KeyObject } from "node:crypto";
import { attribute, type Attribute, enumName } from "./kmip-message.ts";
import { child, k } from "./kmip-ttlv.ts";
import { type KeyManagement, KeyManagementError, KeyManagementUnavailable } from "./kms.ts";
import { Condition } from "./problems.ts";

/** The prefix reserved for binding keys, which is not a scope. */
export const BINDING_PREFIX = "cdmi_binding/";

/** The Application Namespace under which a CDMI server is recorded. */
export const BINDING_NAMESPACE = "SNIA-CDMI-binding";

const kms = (status: number, condition: string, title: string, detail: string) =>
  new Condition(status, `kms/${condition}`, title, detail);

/** The scope is claimed by another CDMI server. */
export const scopeClaimed = (scope: string) =>
  kms(409, "scope-claimed", "The scope is claimed by another CDMI server.",
    `the scope ${JSON.stringify(scope)} is bound to another CDMI server, which this one is not recorded in`);

/** The binding of the scope could not be verified. */
export const bindingNotVerified = (scope: string, why: string) =>
  kms(502, "binding-not-verified", "The binding of the scope is not verified.",
    `the binding of the scope ${JSON.stringify(scope)} is not verified: ${why}`);

/**
 * The Name of the binding key of a scope: "the reserved prefix `cdmi_binding/`
 * and a digest of the scope".
 *
 * The draft states the digest of a CDMI server's identifier exactly and states
 * nothing of this one, so the form here is this server's choice, made to match
 * the one it does state: SHA-256 of the scope in UTF-8, in base 16 as RFC 4648
 * defines it. ECR-081A proposes stating it, since two CDMI servers sharing a
 * scope must form the same Name or each will claim a binding key of its own and
 * neither will see the other.
 */
export const bindingKeyName = (scope: string): string =>
  `${BINDING_PREFIX}${createHash("sha256").update(Buffer.from(scope, "utf8")).digest("hex").toUpperCase()}`;

/** Whether a Name is that of a binding key, which no credential reference resolves against. */
export const isBindingName = (name: string): boolean => name.startsWith(BINDING_PREFIX);

const nameAttribute = (value: string): Attribute => attribute(k.struct("Name", [
  k.text("Name Value", value),
  k.enum("Name Type", "Name Type", "Uninterpreted Text String"),
]));

const bindingAttribute = (identifier: string): Attribute => attribute(k.struct("Application Specific Information", [
  k.text("Application Namespace", BINDING_NAMESPACE),
  k.text("Application Data", identifier),
]));

/** What a binding key records: its identifiers, and the parts of the key pair. */
export interface BindingKey {
  /** The Unique Identifier of the private key, which signs. */
  privateId: string;
  /** The Unique Identifier of the public key. */
  publicId: string;
  /** The identifiers of the CDMI servers recorded in it. */
  servers: string[];
  /** Those identifiers with the attribute instance holding each. */
  recorded: { identifier: string; index: number }[];
}

/** The public key of a binding key pair, as this server retains it. */
export interface RetainedBinding {
  scope: string;
  publicKey: string;
}

async function locate(kmsServer: KeyManagement, name: string): Promise<string[]> {
  try {
    return await kmsServer.locate([nameAttribute(name)]);
  } catch (e) {
    if (e instanceof KeyManagementUnavailable || e instanceof KeyManagementError) return [];
    throw e;
  }
}

/**
 * The identifiers recorded in the Application Specific Information of an
 * object, each with the index of the attribute instance that holds it. The
 * index is the protocol's and not a position in this list: an instance keeps
 * its index when another is deleted, so removing one identifier by the
 * position of the next would address an instance that no longer exists.
 */
async function recordedServers(kmsServer: KeyManagement, id: string):
  Promise<{ identifier: string; index: number }[]> {
  const attrs = await kmsServer.getAttributes(id, ["Application Specific Information"]);
  const out: { identifier: string; index: number }[] = [];
  for (const a of attrs) {
    const namespace = child(a.value, "Application Namespace")?.value as string | undefined;
    const data = child(a.value, "Application Data")?.value as string | undefined;
    if (namespace === BINDING_NAMESPACE && data !== undefined) {
      out.push({ identifier: data, index: a.index ?? 0 });
    }
  }
  return out;
}

/** The binding key of a scope, where one exists. */
export async function findBindingKey(kmsServer: KeyManagement, scope: string): Promise<BindingKey | undefined> {
  const name = bindingKeyName(scope);
  const ids = await locate(kmsServer, name);
  if (ids.length === 0) return undefined;
  // The Name is borne by the private key, and the public key is reached by
  // the Public Key Link the pair records.
  // A destroyed binding key is no longer a binding key: the protocol keeps
  // the managed object and records its State, and Locate still returns it.
  let privateId: string | undefined;
  for (const id of ids) {
    const state = await kmsServer.getAttributes(id, ["State"]);
    const name = state[0] === undefined ? "" : enumName("State", state[0].value.value as number);
    if (name !== "Destroyed" && name !== "Destroyed Compromised") privateId = id;
  }
  if (privateId === undefined) return undefined;
  const links = await kmsServer.getAttributes(privateId, ["Link"]);
  let publicId: string | undefined;
  for (const link of links) {
    const type = child(link.value, "Link Type")?.value as number | undefined;
    if (type !== undefined && enumName("Link Type", type) === "Public Key Link") {
      publicId = child(link.value, "Linked Object Identifier")?.value as string;
    }
  }
  if (publicId === undefined) return undefined;
  const recorded = await recordedServers(kmsServer, privateId);
  return { privateId, publicId, servers: recorded.map((r) => r.identifier), recorded };
}

export interface ClaimResult {
  /** What the claim did: created the binding key, found this server recorded, or joined a race. */
  outcome: "created" | "already" | "raced";
  key: BindingKey;
  /** The public key retained by this server, in PEM. */
  publicKey: string;
}

/**
 * Claims a scope for this server, as "Claiming a scope" specifies: creates the
 * binding key where none exists and records this server's identifier; accepts
 * the claim where the key already records it; and reports the scope claimed
 * condition where it records another CDMI server and not this one.
 */
export async function claimScope(kmsServer: KeyManagement, scope: string, identifier: string): Promise<ClaimResult> {
  const existing = await findBindingKey(kmsServer, scope);
  if (existing !== undefined) {
    if (!existing.servers.includes(identifier)) throw scopeClaimed(scope);
    return { outcome: "already", key: existing, publicKey: await publicKeyOf(kmsServer, existing.publicId) };
  }
  const name = bindingKeyName(scope);
  try {
    const pair = await kmsServer.createKeyPair({
      common: [
        attribute(k.enum("Cryptographic Algorithm", "Cryptographic Algorithm", "RSA")),
        attribute(k.int("Cryptographic Length", 2048)),
      ],
      // The private key signs the value a verification asks for, and is
      // "registered as sensitive and not extractable, so that the key
      // management server does not release it".
      privateKey: [
        nameAttribute(name), bindingAttribute(identifier),
        attribute(k.int("Cryptographic Usage Mask", 0x01)),
        attribute(k.bool("Sensitive", true)), attribute(k.bool("Extractable", false)),
      ],
      // The Name is borne by the private key alone: the protocol reserves a
      // Name to one managed object, so a key pair cannot share one, and a
      // request naming both halves is refused with Invalid Field. The public
      // key is reached by the link the pair records. ECR-081A raises this,
      // the subclause speaking of the Name of the pair.
      publicKey: [attribute(k.int("Cryptographic Usage Mask", 0x02))],
    });
    await kmsServer.activate(pair.privateKey);
    await kmsServer.activate(pair.publicKey);
    const key: BindingKey = {
      privateId: pair.privateKey, publicId: pair.publicKey, servers: [identifier],
      recorded: [{ identifier, index: 0 }],
    };
    return { outcome: "created", key, publicKey: await publicKeyOf(kmsServer, pair.publicKey) };
  } catch (e) {
    if (!(e instanceof KeyManagementError) && !(e instanceof KeyManagementUnavailable)) throw e;
    // "Two CDMI servers claiming a scope at the same time each attempt to
    // create a binding key of the same Name ... one attempt succeeds and the
    // other is refused." A server "whose attempt is refused shall determine
    // whether a managed object of that Name exists within the scope, and shall
    // use it where it does and report the failure where it does not", the
    // Result Reason not being relied upon, since version 1.4 and those before it
    // report Invalid Field (revision 247, adopting ECR-080B). This server has
    // done so since ECR-080A.
    const raced = await findBindingKey(kmsServer, scope);
    if (raced === undefined) throw bindingNotVerified(scope, "the binding key could not be created");
    if (!raced.servers.includes(identifier)) throw scopeClaimed(scope);
    return { outcome: "raced", key: raced, publicKey: await publicKeyOf(kmsServer, raced.publicId) };
  }
}

/** The public key of a binding key pair, in PEM, as this server retains it. */
async function publicKeyOf(kmsServer: KeyManagement, id: string): Promise<string> {
  const got = await kmsServer.get(id);
  const block = child(got.object, "Key Block");
  const material = child(child(block!, "Key Value")!, "Key Material")!.value as Buffer;
  const key: KeyObject = createPublicKey({ key: material, format: "der", type: "pkcs1" });
  return key.export({ format: "pem", type: "spki" }) as unknown as string;
}

/**
 * Verifies a binding: the key management server signs a value this server has
 * not used before with the private key of the pair, this server verifies the
 * signature with the public key it retains, and this server's identifier is
 * recorded in the binding key.
 */
export async function verifyBinding(kmsServer: KeyManagement, scope: string, identifier: string,
  retained: string): Promise<void> {
  const key = await findBindingKey(kmsServer, scope);
  if (key === undefined) throw bindingNotVerified(scope, "the binding key is not present");
  if (!key.servers.includes(identifier)) {
    throw bindingNotVerified(scope, "this server is no longer recorded in the binding key");
  }
  const challenge = randomBytes(32);
  let signature: Buffer;
  try {
    signature = await kmsServer.sign(key.privateId, {
      params: { digitalSignatureAlgorithm: "SHA-256 with RSA Encryption (PKCS#1 v1.5)" },
      data: challenge,
    });
  } catch {
    throw bindingNotVerified(scope, "the key management server could not sign with the binding key");
  }
  const ok = createVerify("sha256").update(challenge).verify(retained, signature);
  if (!ok) throw bindingNotVerified(scope, "the signature does not verify with the public key held");
}

/**
 * Records another CDMI server in the binding key of a scope this server uses.
 * "A CDMI server shall not record the identifier of another CDMI server on the
 * request of a principal that does not hold that privilege, and shall not
 * record its own identifier in the binding key of a scope it does not already
 * use"; the privilege is the caller's to check.
 */
export async function shareScope(kmsServer: KeyManagement, scope: string, own: string,
  other: string): Promise<void> {
  const key = await findBindingKey(kmsServer, scope);
  if (key === undefined) throw bindingNotVerified(scope, "the binding key is not present");
  if (!key.servers.includes(own)) throw scopeClaimed(scope);
  if (key.servers.includes(other)) return;
  await kmsServer.addAttribute(key.privateId, bindingAttribute(other));
}

/**
 * Releases this server's claim: "the CDMI server shall remove its own
 * identifier from the Application Specific Information attributes of the
 * binding key of that scope, and shall destroy the binding key where it records
 * no other CDMI server."
 */
export async function releaseScope(kmsServer: KeyManagement, scope: string, identifier: string): Promise<void> {
  const key = await findBindingKey(kmsServer, scope);
  if (key === undefined) return;
  const held = key.recorded.find((r) => r.identifier === identifier);
  if (held !== undefined) {
    await kmsServer.deleteAttribute(key.privateId, "Application Specific Information", held.index);
  }
  const left = key.servers.filter((s) => s !== identifier);
  if (left.length === 0) {
    // An object is revoked before it is destroyed: the protocol refuses to
    // destroy one that is still active.
    for (const id of [key.privateId, key.publicId]) {
      await kmsServer.revoke(id, "Cessation of Operation", { message: "the claim on the scope was released" })
        .catch(() => undefined);
      await kmsServer.destroy(id).catch(() => undefined);
    }
  }
}

/**
 * The scopes this server uses at a key management server, read from the binding
 * keys themselves, so that a CDMI server which has lost its own record
 * reconstructs it. The scope is not recoverable from the Name, which holds a
 * digest of it, so each candidate scope is offered by the caller.
 */
export async function claimedScopes(kmsServer: KeyManagement, identifier: string,
  candidates: string[]): Promise<string[]> {
  const out: string[] = [];
  for (const scope of candidates) {
    const key = await findBindingKey(kmsServer, scope);
    if (key !== undefined && key.servers.includes(identifier)) out.push(scope);
  }
  return out;
}
