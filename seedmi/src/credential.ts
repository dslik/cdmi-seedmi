// A credential reference: the identifier of a managed object held at a key
// management server, which is what a field of this document addressing a
// credential contains (the Credential reference subclause of the CDMI 3.0
// working draft, revision 211).
//
// "A credential reference is the identifier of a managed object: it is what a
// CDMI server returns when a CDMI client reads the field, and what a CDMI
// client supplies when it writes the field."
//
// This module reads and writes a reference, chooses the key management server
// it addresses, forms the scope within which it resolves, and resolves it
// against that server. The fields that carry one, and depositing a secret, are
// the phases that follow.

import { createHash, createPrivateKey, randomUUID, X509Certificate } from "node:crypto";
import { type Attribute, attribute } from "./kmip-message.ts";
import { verifyBinding } from "./kms-binding.ts";
import { child, k } from "./kmip-ttlv.ts";
import { enumName } from "./kmip-message.ts";
import { type KeyManagement, KeyManagementError, KeyManagementUnavailable } from "./kms.ts";
import { Condition, invalidField } from "./problems.ts";

/** A credential reference, as stored and as returned in a read (Table 8). */
export interface CredentialReference {
  /** The label of the key management server, always stored and always returned. */
  kms: string;
  /** The name of the managed object, relative to the scope. */
  name: string;
  /** The scope, returned only where client registration is available. */
  scope?: string;
  /**
   * The principal that configured the reference, recorded by this server and
   * never returned: a per-principal scope is formed from it and the owning
   * domain, so that after a change of domain the scope that applies there can
   * be formed and compared, as the change-of-domain subclause requires.
   */
  principal?: string;
  /**
   * "true" where this server registered the managed object for a secret the
   * client deposited, which it revokes where the owning domain changes.
   * Recorded by this server and never returned.
   */
  deposited?: string;
}

/** A credential reference as a CDMI client supplies it. */
export interface SuppliedReference {
  kms?: string;
  name?: string;
  scope?: string;
  secret?: string;
  secret_type?: string;
}

/** One key management server of the cdmi_domain_kms item (Table 7). */
export interface KmsDescriptor {
  endpoint?: string;
  version?: string;
  scope?: string;
  scope_by_principal?: string;
  client_registration?: string;
  default?: string;
}

// ---------------------------------------------------------------------------
// The conditions of Annex C, Key management server problems

const kms = (status: number, condition: string, title: string, detail: string, ...a: unknown[]) =>
  new Condition(status, `kms/${condition}`, title, format(detail, ...a));

const format = (detail: string, ...a: unknown[]) => {
  let at = 0;
  return detail.replace(/%[sj]/g, (m) => {
    const v = a[at++];
    return m === "%j" ? JSON.stringify(v) : String(v);
  });
};

/** No managed object of that Name exists within the scope, or the key management server has none. */
/**
 * "The domain owning the object changed, so the scope recorded in a credential
 * reference no longer applies, and the reference is bound again" (Annex C).
 * The draft gives it no status; 409, the object's state conflicting with its
 * reference, is this server's.
 */
export const rebindRequired = (detail: string, ...a: unknown[]) =>
  kms(409, "rebind-required", "The credential reference was configured in another scope.", detail, ...a);

/**
 * "A CDMI client supplied a credential reference naming a managed object that
 * the CDMI server did not itself store for that field, and client registration
 * is not available for the key management server addressed" (Annex C). The
 * draft gives it no status; 400, the request supplying what this deployment
 * does not accept, is this server's.
 */
export const clientRegistrationNotSupported = (detail: string, ...a: unknown[]) =>
  kms(400, "client-registration-not-supported", "Client registration is not supported.", detail, ...a);

export const credentialUnavailable = (detail: string, ...a: unknown[]) =>
  kms(502, "credential-unavailable", "The credential is unavailable.", detail, ...a);

/** The managed object is not of the type, or does not permit the operation, the purpose requires. */
export const credentialTypeMismatch = (detail: string, ...a: unknown[]) =>
  kms(409, "credential-type-mismatch", "The credential is not of the type required.", detail, ...a);

/** The managed object is no longer usable: its State has passed Active. */
export const credentialExpired = (detail: string, ...a: unknown[]) =>
  kms(409, "credential-expired", "The credential has expired.", detail, ...a);

/** The managed object is compromised. */
export const credentialCompromised = (detail: string, ...a: unknown[]) =>
  kms(409, "credential-compromised", "The credential is compromised.", detail, ...a);

/** The managed object may not be released to the CDMI server. */
export const credentialNotReleasable = (detail: string, ...a: unknown[]) =>
  kms(409, "credential-not-releasable", "The credential is not releasable.", detail, ...a);

// ---------------------------------------------------------------------------
// Reading what a CDMI client supplied

/**
 * Reads a credential reference a CDMI client supplied, for a field of the name
 * given. "Exactly one of the name and secret fields shall be present in a
 * create or an update, and a CDMI server shall report the invalid field
 * condition otherwise."
 */
export function readReference(field: string, value: unknown): SuppliedReference {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw invalidField(field, "a credential reference is a JSON object");
  }
  const v = value as Record<string, unknown>;
  for (const [name, held] of Object.entries(v)) {
    if (!["kms", "name", "scope", "secret", "secret_type"].includes(name)) {
      throw invalidField(field, "%j is not a field of a credential reference", name);
    }
    if (typeof held !== "string") throw invalidField(`${field}/${name}`, "%j is a JSON string", name);
  }
  const hasName = typeof v.name === "string";
  const hasSecret = typeof v.secret === "string";
  // "Exactly one of the name and secret fields shall be present in a create or
  // an update that does not rotate a deposited credential ... A rotation
  // supplies both: the name field names the credential to be replaced and the
  // secret field carries what replaces it" (revision 365). Both present was
  // refused outright until 0.87, so a rotation — which this server has been
  // able to perform since 0.46, and whose machinery sits unreached in
  // depositSecret — could not be asked for at all. Whether the name is one this
  // server holds is settled where the deposit happens, that being the only
  // place that can ask the key management server.
  if (!hasName && !hasSecret) {
    throw invalidField(field,
      "a credential reference carries the name of a credential, or a secret to " +
      "deposit, or both to rotate a deposited credential");
  }
  if (hasName) {
    // "The value of the name field shall not contain a / character and shall
    // not be empty", so that a reference addresses one object within its scope.
    const name = v.name as string;
    if (name === "") throw invalidField(`${field}/name`, "the name of a credential reference is not empty");
    if (name.includes("/")) {
      throw invalidField(`${field}/name`, 'the name of a credential reference does not contain "/"');
    }
  }
  // "This field is CDMI server populated and shall be ignored where a CDMI
  // client supplies it."
  const { scope: _ignored, ...rest } = v as SuppliedReference;
  return rest;
}

// ---------------------------------------------------------------------------
// Which key management server, and which scope

/**
 * The key management server a reference addresses, by the rules of "Which key
 * management server a credential reference addresses": the label the reference
 * names, or the one member, or the member that is the default.
 */
export function selectKms(field: string, supplied: SuppliedReference,
  descriptors: Record<string, KmsDescriptor>): string {
  if (supplied.kms !== undefined) {
    if (descriptors[supplied.kms] === undefined) {
      throw invalidField(`${field}/kms`,
        "the domain owning this object names no key management server %j", supplied.kms);
    }
    return supplied.kms;
  }
  const labels = Object.keys(descriptors);
  if (labels.length === 1) return labels[0];
  const byDefault = labels.filter((l) => descriptors[l].default === "true");
  if (byDefault.length === 1) return byDefault[0];
  // "otherwise, no key management server is determined, and the CDMI server
  // shall report the invalid field condition ... and shall perform no part of
  // the operation."
  throw invalidField(field, labels.length === 0
    ? "the domain owning this object names no key management server"
    : "the domain owning this object names more than one key management server and no default; " +
      "name one in the kms field of the credential reference");
}

/**
 * The scope that applies: "the value of the scope field of the key management
 * server it addresses, followed, where the scope_by_principal field contains
 * true, by a component identifying the principal that supplied the reference
 * and a /".
 *
 * That component "is derived by the CDMI server from the principal and from the
 * domain in which that principal was resolved", since the same credentials
 * resolve to different principals in different domains. This server derives it
 * as the first sixteen hexadecimal digits of the SHA-256 digest of the domain's
 * object ID and the principal name, which is stable for a principal within a
 * domain and discloses neither.
 */
export function scopeOf(descriptor: KmsDescriptor, who: string, domainObjectID: string): string {
  const base = descriptor.scope ?? "";
  if (descriptor.scope_by_principal !== "true") return base;
  const component = createHash("sha256")
    .update(domainObjectID).update("\u0000").update(who)
    .digest("hex").slice(0, 16);
  return `${base}${component}/`;
}

/** Whether a CDMI client may learn where the key management server is (Table 7). */
export const registersItself = (descriptor: KmsDescriptor): boolean =>
  descriptor.client_registration === "true";

/**
 * A stored reference as a read returns it. "A CDMI server shall return it in a
 * read where client registration is available for the key management server
 * addressed, and shall omit it otherwise", so that a deployment offering no
 * client registration discloses neither the endpoint nor the scope.
 */
export function readableReference(stored: CredentialReference, descriptor: KmsDescriptor | undefined):
  CredentialReference {
  const out: CredentialReference = { kms: stored.kms, name: stored.name };
  if (descriptor !== undefined && registersItself(descriptor) && stored.scope !== undefined) {
    out.scope = stored.scope;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Resolution

/** What a resolved credential is: the managed object, and what may be done with it. */
export interface ResolvedCredential {
  /** The Unique Identifier of the managed object. */
  id: string;
  /** Its Object Type, by the KMIP name. */
  objectType: string;
  /** Its Cryptographic Usage Mask. */
  usageMask: number;
  /** The key management server it is held at. */
  kms: KeyManagement;
}

/** What a purpose requires of a managed object (the Use of a credential table). */
export interface CredentialRequirement {
  /** The KMIP Object Types the field permits. */
  objectTypes: string[];
  /** The bits of the Cryptographic Usage Mask the purpose needs. */
  usage: number;
  /** What the field is, for a message. */
  purpose: string;
  /**
   * The Secret Data Types the field accepts, where the object is Secret Data.
   * A password is "Password"; the key of a service principal is "Seed", the
   * octets being a key and not a password.
   */
  secretTypes?: string[];
  /**
   * Whether the field names a secret whose value the consuming protocol
   * transmits, such as the password an MQTT export presents to its broker:
   * "Where the scope that applies to a credential reference addressing such a
   * secret is not followed by a component identifying the principal, the scope
   * route is not satisfied, and the privilege route alone entitles the
   * principal" (revision 297; ECR-091B).
   */
  transmitted?: boolean;
}

/**
 * Resolves a credential reference against the key management server it
 * addresses. "The Name of the managed object at the key management server is
 * formed by concatenating the scope and the value of the name field. A CDMI
 * server shall resolve a credential reference only against a managed object
 * whose Name is so formed, and shall report the credential unavailable
 * condition where none exists."
 */
export async function resolveReference(kmsServer: KeyManagement, stored: CredentialReference,
  scope: string, requirement: CredentialRequirement,
  binding?: { identifier: string; publicKey: string }): Promise<ResolvedCredential> {
  // "A CDMI server shall verify the binding of a scope before it first
  // resolves a credential reference against that scope in the life of the
  // CDMI server", so the verification is done once and remembered, and a
  // scope whose binding does not verify resolves nothing.
  if (binding !== undefined) await ensureBinding(kmsServer, stored.kms, scope, binding);
  const fullName = `${scope}${stored.name}`;
  let ids: string[];
  try {
    ids = await kmsServer.locate([attribute(k.struct("Name", [
      k.text("Name Value", fullName),
      k.enum("Name Type", "Name Type", "Uninterpreted Text String"),
    ]))]);
  } catch (e) {
    if (e instanceof KeyManagementUnavailable) {
      throw credentialUnavailable("the key management server %j could not be reached", stored.kms);
    }
    if (e instanceof KeyManagementError) {
      throw credentialUnavailable("the key management server %j refused the request: %s", stored.kms, e.reason);
    }
    throw e;
  }
  if (ids.length === 0) {
    throw credentialUnavailable("no credential named %j is held within the scope of %j", stored.name, stored.kms);
  }
  if (ids.length > 1) {
    // "The Key Management Interoperability Protocol reserves a Name to one
    // managed object ... A credential reference therefore addresses one
    // managed object" (revision 232), which deleted the credential ambiguous
    // condition this server reported here. More than one is a fault of the
    // key management server, and the credential is not available from it.
    throw credentialUnavailable(
      "the key management server %j holds more than one credential named %j, and a Name addresses one",
      stored.kms, stored.name);
  }
  const id = ids[0];
  const attrs = await kmsServer.getAttributes(id, ["State", "Object Type", "Cryptographic Usage Mask"]);
  const of = (name: string) => attrs.find((a) => a.name === name)?.value;
  const stateItem = of("State");
  const state = stateItem === undefined ? "" : enumName("State", stateItem.value as number);
  // 3.22: an object that is not Active is not used to apply protection, and a
  // compromised one is not used at all.
  if (state === "Compromised" || state === "Destroyed Compromised") {
    throw credentialCompromised("the credential %j is compromised", stored.name);
  }
  if (state !== "Active") {
    throw credentialExpired("the credential %j is %s and not Active", stored.name, state === "" ? "in no state" : state);
  }
  const typeItem = of("Object Type");
  const objectType = typeItem === undefined ? "" : enumName("Object Type", typeItem.value as number);
  if (!requirement.objectTypes.includes(objectType)) {
    throw credentialTypeMismatch("%s requires %s, and the credential %j is %s",
      requirement.purpose, requirement.objectTypes.join(" or "), stored.name, objectType || "of no type");
  }
  const usageMask = (of("Cryptographic Usage Mask")?.value as number | undefined) ?? 0;
  if ((usageMask & requirement.usage) !== requirement.usage) {
    // "A managed object registered without that permission is in every other
    // respect a valid credential, and the mismatch is reported so that the CDMI
    // client corrects the registration."
    throw credentialTypeMismatch(
      "the Cryptographic Usage Mask of the credential %j does not permit what %s requires",
      stored.name, requirement.purpose);
  }
  return { id, objectType, usageMask, kms: kmsServer };
}

/** The scopes verified in the life of this server, by key management server. */
const verified = new Set<string>();

/** Forgets what has been verified, for a test that restarts a server. */
export const forgetVerifiedScopes = (): void => verified.clear();

/**
 * Verifies the binding of a scope, once in the life of this server. A
 * verification that fails is not remembered, so the next resolution tries
 * again rather than treating the scope as unusable for ever.
 */
export async function ensureBinding(kmsServer: KeyManagement, label: string, scope: string,
  binding: { identifier: string; publicKey: string }): Promise<void> {
  const key = `${label}\u0000${scope}`;
  if (verified.has(key)) return;
  await verifyBinding(kmsServer, scope, binding.identifier, binding.publicKey);
  verified.add(key);
}

/** The Name a reference addresses, for a message or a deposit. */
export const nameOfReference = (scope: string, name: string): string => `${scope}${name}`;

/** Reads the cdmi_domain_kms item of a domain object's settings. */
export function descriptorsOf(settings: Record<string, unknown>): Record<string, KmsDescriptor> {
  const item = settings.cdmi_domain_kms;
  if (typeof item !== "object" || item === null || Array.isArray(item)) return {};
  const out: Record<string, KmsDescriptor> = {};
  for (const [label, value] of Object.entries(item as Record<string, unknown>)) {
    if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      out[label] = value as KmsDescriptor;
    }
  }
  return out;
}

/** Whether a value is a conforming cdmi_domain_kms item, for validation on a write. */
export function checkDescriptors(field: string, value: unknown): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw invalidField(field, "cdmi_domain_kms is a JSON object of key management servers");
  }
  const members = Object.entries(value as Record<string, unknown>);
  for (const [label, held] of members) {
    const where = `${field}/${label}`;
    if (typeof held !== "object" || held === null || Array.isArray(held)) {
      throw invalidField(where, "a key management server is described by a JSON object");
    }
    const d = held as Record<string, unknown>;
    for (const [name, v] of Object.entries(d)) {
      if (!["endpoint", "version", "scope", "scope_by_principal", "client_registration", "default"].includes(name)) {
        throw invalidField(where, "%j is not a field describing a key management server", name);
      }
      if (typeof v !== "string") throw invalidField(`${where}/${name}`, "%j is a JSON string", name);
    }
    if (typeof d.endpoint !== "string" || d.endpoint === "") {
      throw invalidField(where, "a key management server states its endpoint");
    }
    for (const flag of ["scope_by_principal", "client_registration", "default"]) {
      const v = d[flag];
      if (v !== undefined && v !== "true" && v !== "false") {
        throw invalidField(`${where}/${flag}`, '%j is "true" or "false"', flag);
      }
    }
    // A scope is a Name prefix, and a reference's name is appended to it.
    if (d.scope !== undefined && (d.scope as string).length > 0 && !(d.scope as string).endsWith("/")) {
      throw invalidField(`${where}/scope`, 'a scope ends with "/", the name of a reference being appended to it');
    }
  }
  const defaults = members.filter(([, d]) => (d as Record<string, unknown>).default === "true");
  if (defaults.length > 1) {
    throw invalidField(field, "more than one key management server is the default");
  }
}

// Used by the binding where a reference is stored.
export { child };

// ---------------------------------------------------------------------------
// Depositing a secret (the Depositing a secret subclause)


/** The managed object a deposited secret becomes, by its KMIP Object Type. */
export interface DepositRequest {
  /** The base 64 encoding of the octets of the secret, as the field carries it. */
  secret: string;
  /** The "secret_type" field, where the subclause defining the field permits more than one. */
  secretType?: string;
  /** The type the subclause states, used where no secret_type is given. */
  defaultType: string;
  /** What the purpose requires: the types permitted and the usage the mask must hold. */
  requirement: CredentialRequirement;
  /** The scope that applies. */
  scope: string;
  /** The label of the key management server addressed. */
  kmsLabel: string;
  /**
   * The name of an existing credential reference, where a CDMI client is
   * rotating: "A CDMI client rotates a deposited credential by supplying a new
   * secret together with the name field of the existing credential reference."
   */
  name?: string;
  /** The name generated for a new deposit; a test supplies one. */
  newName?: () => string;
}

export const nameAttribute = (value: string): Attribute => attribute(k.struct("Name", [
  k.text("Name Value", value),
  k.enum("Name Type", "Name Type", "Uninterpreted Text String"),
]));

/** The value of a managed object of each type this server deposits. */
function managedObject(type: string, octets: Buffer): { value: ReturnType<typeof k.struct>; attrs: Attribute[] } {
  const block = (format: string, algorithm?: string, bits?: number) => k.struct("Key Block", [
    k.enum("Key Format Type", "Key Format Type", format),
    k.struct("Key Value", [k.bytes("Key Material", octets)]),
    ...(algorithm === undefined ? [] : [k.enum("Cryptographic Algorithm", "Cryptographic Algorithm", algorithm)]),
    ...(bits === undefined ? [] : [k.int("Cryptographic Length", bits)]),
  ]);
  switch (type) {
    case "Secret Data":
      return {
        value: k.struct("Secret Data", [
          k.enum("Secret Data Type", "Secret Data Type", "Password"),
          block("Opaque"),
        ]),
        attrs: [],
      };
    case "Opaque Object":
      return {
        value: k.struct("Opaque Object", [
          k.enum("Opaque Data Type", "Opaque Data Type", "0x80000000"),
          k.bytes("Opaque Data Value", octets),
        ]),
        attrs: [],
      };
    case "Symmetric Key":
      return { value: k.struct("Symmetric Key", [block("Raw", "AES", octets.length * 8)]), attrs: [] };
    case "Private Key": {
      let bits: number;
      let algorithm: string;
      try {
        const key = createPrivateKey({ key: octets, format: "der", type: "pkcs8" });
        algorithm = key.asymmetricKeyType === "ec" ? "ECDSA" : "RSA";
        bits = (key.asymmetricKeyDetails?.modulusLength ?? 256) as number;
      } catch {
        throw credentialDepositFailed("the secret is not a private key in PKCS#8 form");
      }
      return {
        value: k.struct("Private Key", [block("PKCS#8", algorithm, bits)]),
        // "where that managed object is of type Private Key, register it as
        // sensitive and not extractable, so that the CDMI server operates it in
        // place thereafter and no party retrieves it".
        attrs: [attribute(k.bool("Sensitive", true)), attribute(k.bool("Extractable", false))],
      };
    }
    case "Certificate": {
      let parsed: X509Certificate;
      try {
        parsed = new X509Certificate(octets);
      } catch {
        throw credentialDepositFailed("the secret is not an X.509 certificate");
      }
      // The Certificate Value is the DER encoding. A CDMI client depositing a
      // trust anchor supplies "the base 64 encoding of the octets of the
      // secret", and the octets of a certificate as an operator holds them are
      // usually PEM — which X509Certificate accepts and which was stored
      // verbatim before 0.87. The value read back was then PEM base 64 again
      // and wrapped in BEGIN CERTIFICATE a second time, so the trust anchor
      // deposited was one no TLS stack could parse. Taking the DER from the
      // parsed certificate accepts either form and stores one.
      const der = parsed.raw;
      return {
        value: k.struct("Certificate", [
          k.enum("Certificate Type", "Certificate Type", "X.509"),
          k.bytes("Certificate Value", der),
        ]),
        // "Certificate Length is required for a Certificate" (KMIP 1.4, Table
        // 171). It was not sent, so every deposit of a trust anchor was
        // refused by the key management server with Missing Data. Every test
        // that registers a certificate supplies it by hand and says why, which
        // is how this path stayed broken while they passed.
        attrs: [attribute(k.int("Certificate Length", der.length))],
      };
    }
    default:
      throw credentialDepositFailed("this server deposits no secret as a %s", type);
  }
}

/** The CDMI server was unable to place the secret under management. */
export const credentialDepositFailed = (detail: string, ...a: unknown[]) =>
  kms(502, "credential-deposit-failed", "The credential could not be deposited.", detail, ...a);

/**
 * Places a secret under management and returns the credential reference to be
 * stored in place of the one supplied. The secret is not returned and is not
 * stored anywhere by this server.
 *
 * Rotation follows KMIP rather than the draft where the two conflict, as
 * ECR-040A records: KMIP requires a Name to be unique, so the Name is removed
 * from the object being replaced, the replacement is registered with it, and
 * the object replaced is then revoked. At no point do two objects share a Name.
 */
export async function depositSecret(kmsServer: KeyManagement, req: DepositRequest):
  Promise<{ reference: CredentialReference; id: string; replaced?: string }> {
  let octets: Buffer;
  try {
    octets = Buffer.from(req.secret, "base64");
    if (octets.length === 0 || octets.toString("base64").replace(/=+$/, "") !== req.secret.replace(/=+$/, "")) {
      throw new Error("not base 64");
    }
  } catch {
    throw invalidField("secret", "the secret field contains the base 64 encoding of the octets of the secret");
  }
  const type = req.secretType ?? req.defaultType;
  if (!req.requirement.objectTypes.includes(type)) {
    throw credentialTypeMismatch("%s requires %s, and the secret is offered as %s",
      req.requirement.purpose, req.requirement.objectTypes.join(" or "), type);
  }
  const { value, attrs } = managedObject(type, octets);
  const name = req.name ?? (req.newName ?? randomUUID)();
  const fullName = nameOfReference(req.scope, name);

  // Rotation: the Name is taken from the object being replaced first.
  let replaced: string | undefined;
  if (req.name !== undefined) {
    const existing = await kmsServer.locate([nameAttribute(fullName)]).catch(() => [] as string[]);
    replaced = existing[0];
    if (replaced !== undefined) {
      try {
        await kmsServer.deleteAttribute(replaced, "Name");
      } catch (e) {
        throw credentialDepositFailed("the credential being replaced could not be renamed: %s",
          (e as Error).message);
      }
    }
  }

  let id: string;
  try {
    id = await kmsServer.register(type, [
      nameAttribute(fullName),
      attribute(k.int("Cryptographic Usage Mask", req.requirement.usage)),
      ...attrs,
    ], value);
    await kmsServer.activate(id);
  } catch (e) {
    if (replaced !== undefined) {
      // The replacement did not take: the Name goes back to the object that
      // holds the credential, so that the reference still resolves.
      await kmsServer.addAttribute(replaced, nameAttribute(fullName)).catch(() => undefined);
    }
    if (e instanceof KeyManagementUnavailable) {
      throw credentialDepositFailed("the key management server %j could not be reached", req.kmsLabel);
    }
    if (e instanceof KeyManagementError) {
      throw credentialDepositFailed("the key management server %j refused the registration: %s",
        req.kmsLabel, e.reason);
    }
    throw e;
  }
  // The object replaced is revoked once the replacement holds the Name.
  if (replaced !== undefined) {
    await kmsServer.revoke(replaced, "Superseded", { message: "replaced by a rotation" }).catch(() => undefined);
  }
  return {
    reference: { kms: req.kmsLabel, name, scope: req.scope },
    id,
    ...(replaced === undefined ? {} : { replaced }),
  };
}

/**
 * Withdraws a deposited credential: "A CDMI client withdraws a deposited
 * credential by removing the field carrying the credential reference, and the
 * CDMI server shall revoke the managed objects it registered for it."
 */
export async function withdrawCredential(kmsServer: KeyManagement, stored: CredentialReference,
  scope: string): Promise<void> {
  const fullName = nameOfReference(scope, stored.name);
  let ids: string[];
  try {
    ids = await kmsServer.locate([nameAttribute(fullName)]);
  } catch {
    // A key management server that cannot be reached is not a reason to keep
    // the field: the object is revoked when it can be.
    return;
  }
  for (const id of ids) {
    await kmsServer.revoke(id, "Superseded", { message: "the credential reference was withdrawn" })
      .catch(() => undefined);
  }
}

/**
 * A credential reference as the binding bound it, taken from an entry for
 * storage: the fields this server records beside those a client supplies are
 * kept, and nothing else. undefined where the value is not a reference.
 */
export function boundReference(raw: unknown): CredentialReference | undefined {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const r = raw as Record<string, unknown>;
  if (typeof r.kms !== "string" || typeof r.name !== "string") return undefined;
  return {
    kms: r.kms, name: r.name,
    ...(typeof r.scope === "string" ? { scope: r.scope } : {}),
    ...(typeof r.principal === "string" ? { principal: r.principal } : {}),
    ...(r.deposited === "true" ? { deposited: "true" } : {}),
  };
}
