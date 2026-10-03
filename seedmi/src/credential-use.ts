// Credential references in use: bound when a feature is configured, and
// resolved when the feature uses the credential.
//
// A feature that carries a credential reference (the first is an MQTT export's
// password_secret_id) gives the reference to bindReference when an entry is
// written, and to retrieveSecret each time it connects. The key management
// server is reached as this CDMI server, never as the principal: what bounds a
// principal is the entitlement it demonstrates when the feature is configured.

import type { Node, Store } from "./store.ts";
import { KeyManagementError, type KeyManagement } from "./kms.ts";
import { child, k, type Item } from "./kmip-ttlv.ts";
import { enumName, attribute } from "./kmip-message.ts";
import { Condition, invalidField } from "./problems.ts";
import {
  type CredentialReference, type CredentialRequirement, credentialUnavailable, depositSecret,
  clientRegistrationNotSupported, credentialNotReleasable, ensureBinding, type KmsDescriptor, readReference, rebindRequired,
  nameAttribute, nameOfReference,
  registersItself, resolveReference, scopeOf, selectKms,
} from "./credential.ts";
import { bindingNotVerified } from "./kms-binding.ts";

/** What a feature needs to reach the credentials of the objects it serves. */
export interface CredentialContext {
  servers: KeyManagement[];
  store: Store;
  /** The key management servers the domain owning an object names. */
  descriptorsFor(node: Node): Record<string, KmsDescriptor>;
  /** The object ID of the domain owning an object, from which a per-principal scope is formed. */
  domainObjectIDFor(node: Node): string;
}

/** The principal configuring a feature: its name and the privileges it holds. */
export interface Configurer {
  name: string;
  privileges: string[];
}

/**
 * Neither route of entitlement is satisfied: "A CDMI server shall report the
 * entitlement not demonstrated condition where neither route is satisfied."
 */
export const entitlementNotDemonstrated = (detail: string) =>
  new Condition(403, "kms/entitlement-not-demonstrated", "Entitlement to the credential is not demonstrated.", detail);

/** A password the consuming protocol transmits: Secret Data, retrieved. */
export const PASSWORD: CredentialRequirement = {
  objectTypes: ["Secret Data"], usage: 0, purpose: "a password the consuming protocol transmits",
  transmitted: true,
};

function serverFor(ctx: CredentialContext, label: string): KeyManagement {
  const server = ctx.servers.find((s) => s.label === label);
  if (server === undefined) {
    throw credentialUnavailable("the key management server %j that the domain names is not one this " +
      "CDMI server is configured to reach", label);
  }
  return server;
}

/**
 * The binding of the scope a domain claimed, verified before the scope is
 * first resolved against: the scope is the one the domain names, of which a
 * per-principal scope is a part.
 */
async function verifyBound(ctx: CredentialContext, server: KeyManagement, label: string,
  descriptor: KmsDescriptor): Promise<void> {
  const scope = descriptor.scope ?? "";
  const publicKey = ctx.store.bindingKeyHeld(label, scope);
  if (publicKey === undefined) {
    throw bindingNotVerified(scope, "this CDMI server holds no binding key for it; the domain claims it " +
      "when its cdmi_domain_kms item is written");
  }
  await ensureBinding(server, label, scope, { identifier: await server.identifier(), publicKey });
}

/**
 * Binds a credential reference a principal supplies when it configures a
 * feature, and returns the reference to store. A reference that names a
 * credential is checked for entitlement; one that supplies a secret deposits
 * it, beneath the principal's own scope. The stored reference records the
 * scope that applies, so that a use of it needs no principal.
 */
export async function bindReference(ctx: CredentialContext, field: string, value: unknown, node: Node,
  who: Configurer, requirement: CredentialRequirement, defaultType: string): Promise<CredentialReference> {
  const supplied = readReference(field, value);
  const descriptors = ctx.descriptorsFor(node);
  const label = selectKms(field, supplied, descriptors);
  const descriptor = descriptors[label];
  const server = serverFor(ctx, label);
  const scope = scopeOf(descriptor, who.name, ctx.domainObjectIDFor(node));
  await verifyBound(ctx, server, label, descriptor);

  if (supplied.secret !== undefined) {
    // A reference carrying both names the credential to be replaced: the
    // deposit registers the replacement under that Name and revokes what held
    // it. "A request that supplies both and names no credential the CDMI
    // server holds is not a rotation, and the invalid field condition is
    // reported for it", so the name is looked for before anything is
    // registered — a rotation of a credential that is not there would
    // otherwise deposit a new one under a name the CDMI client believed was
    // already in use.
    if (supplied.name !== undefined) {
      const held = await server.locate([nameAttribute(nameOfReference(scope, supplied.name))])
        .catch(() => [] as string[]);
      if (held.length === 0) {
        throw invalidField(`${field}/name`,
          "a credential reference carrying both the name and the secret rotates the credential that name " +
          "addresses, and this CDMI server holds no credential named %j for this field", supplied.name);
      }
    }
    // A secret the principal supplies is deposited beneath the scope that
    // applies to it, which is entitlement by scope: the principal placed it.
    const { reference } = await depositSecret(server, {
      secret: supplied.secret, secretType: supplied.secret_type, defaultType, requirement, scope, kmsLabel: label,
      ...(supplied.name === undefined ? {} : { name: supplied.name }),
    });
    // Recorded, never returned: who configured it, for the scope that applies
    // after a change of domain, and that it is a deposit, revoked then.
    return { ...reference, principal: who.name, deposited: "true" };
  }
  // A reference naming a managed object this server did not store for the
  // field is one the client registered itself, which it does only where the
  // key management server offers client registration: "A key management
  // server whose client_registration field does not contain true is usable
  // only by deposit". A reference this server stored for the field and the
  // client supplies unchanged does not reach here (the binding keeps it).
  if (!registersItself(descriptor)) {
    throw clientRegistrationNotSupported(
      "%s names a managed object this server did not store for it, and the key management server %j offers no " +
      "client registration: a secret is supplied by deposit, in the secret field", field, label);
  }
  // A secret the consuming protocol transmits is disclosed to the endpoint the
  // entry names, so a scope shared by every principal of the domain does not
  // entitle a principal to name one: "the privilege route alone entitles the
  // principal" (revision 297; ECR-091B). A secret the principal deposits is
  // its own, and is unaffected.
  if (requirement.transmitted === true && descriptor.scope_by_principal !== "true" &&
      !who.privileges.includes("domain_kms_admin")) {
    throw entitlementNotDemonstrated(
      `${field} names a secret this server transmits to the endpoint the entry names, and the scope of the key ` +
      `management server ${JSON.stringify(label)} is shared by every principal of the domain: a principal holding ` +
      "the domain_kms_admin privilege names such a secret, and another supplies one in the secret field");
  }
  const stored: CredentialReference = { kms: label, name: supplied.name!, scope, principal: who.name };
  // The reference is resolved whoever supplies it: "A CDMI server shall
  // determine, when a credential reference is created and when it is bound
  // again, that the Cryptographic Usage Mask of the managed object permits the
  // operation ... [and] that the managed object is of the type that the
  // subclause defining the field states" (the Credential reference subclause).
  // Before 0.49 a principal holding domain_kms_admin was not resolved, and
  // neither was checked.
  //
  // Entitlement, by privilege or by scope, and by no other means: a principal
  // holding domain_kms_admin is entitled; any other only where the credential
  // resolves within the scope that applies to it. A credential of the wrong
  // type or usage is reported as such to either, and was reported to one
  // without the privilege as a failure of entitlement before 0.49.
  try {
    await resolveReference(server, stored, scope, requirement);
  } catch (e) {
    if (!who.privileges.includes("domain_kms_admin") && e instanceof Condition &&
        /kms\/credential-unavailable$/.test(e.type)) {
      throw entitlementNotDemonstrated(
        `${field} names no credential within the scope that applies to ${who.name}, and ${who.name} ` +
        `does not hold the domain_kms_admin privilege`);
    }
    throw e;
  }
  return stored;
}

/**
 * "A CDMI server shall not resolve a credential reference in a domain other
 * than the one in which it was configured" (the change-of-domain subclause):
 * the scope that applies in the domain now owning the object is formed, as it
 * was when the reference was bound, and compared with the scope recorded. Where
 * they differ the reference is not resolved, and the rebind required condition
 * is reported, until the reference is bound again by writing it anew.
 */
function assertScopeApplies(ctx: CredentialContext, node: Node, stored: CredentialReference): KmsDescriptor {
  const descriptor = ctx.descriptorsFor(node)[stored.kms];
  if (descriptor === undefined) {
    throw rebindRequired("the domain owning this object names no key management server %j, in which the " +
      "reference was configured; it is bound again by writing it anew", stored.kms);
  }
  const perPrincipal = descriptor.scope_by_principal === "true";
  if (perPrincipal && stored.principal === undefined) {
    throw rebindRequired("the scope that applies in the domain owning this object is formed for the principal " +
      "that configured the reference, which is not recorded; it is bound again by writing it anew");
  }
  const applies = perPrincipal
    ? scopeOf(descriptor, stored.principal!, ctx.domainObjectIDFor(node))
    : descriptor.scope ?? "";
  if (applies !== (stored.scope ?? "")) {
    throw rebindRequired("the domain owning this object was changed, and the scope that now applies is not the " +
      "scope in which the reference was configured; it is bound again by writing it anew");
  }
  return descriptor;
}

/** A secret retrieved for use: the managed object it came from, and its octets. */
export interface Retrieved {
  id: string;
  octets: Buffer;
}

/**
 * Resolves a stored reference and retrieves the secret it addresses, for a
 * feature about to use it. The binding of the scope is verified first; the
 * state of the managed object is checked as the key management subclause
 * requires, so a compromised credential is reported and never used.
 */
export async function retrieveSecret(ctx: CredentialContext, node: Node, stored: CredentialReference,
  requirement: CredentialRequirement): Promise<Retrieved> {
  const descriptor = assertScopeApplies(ctx, node, stored);
  const server = serverFor(ctx, stored.kms);
  await verifyBound(ctx, server, stored.kms, descriptor);
  const resolved = await resolveReference(server, stored, stored.scope ?? "", requirement);
  return { id: resolved.id, octets: secretOctets((await released(server, resolved.id)).object, requirement.secretTypes) };
}

/**
 * A managed object retrieved, where the purpose requires it be. "Where the key
 * management server declines to release a managed object because it is
 * sensitive or not extractable, and the purpose for which it is referenced
 * requires that it be retrieved", the credential not releasable condition is
 * reported (the State subclause). A server that answered with a refusal is
 * such a server; one not reached is reported as the credential unavailable.
 * Before 0.49 the condition was defined and never reported.
 */
async function released(server: KeyManagement, id: string): Promise<{ object: Item }> {
  try {
    return await server.get(id);
  } catch (e) {
    if (e instanceof KeyManagementError) {
      throw credentialNotReleasable("the key management server declines to release the managed object (%s)",
        e.message);
    }
    throw e;
  }
}

/** The octets of a Secret Data object, which must be a password. */
function secretOctets(object: Item, accepted: string[] = ["Password"]): Buffer {
  const type = child(object, "Secret Data Type");
  const given = type === undefined ? undefined : enumName("Secret Data Type", type.value as number);
  if (given !== undefined && !accepted.includes(given)) {
    throw credentialUnavailable("the managed object is Secret Data of the type %j, and this field takes %s",
      given, accepted.join(" or "));
  }
  const material = child(child(child(object, "Key Block")!, "Key Value")!, "Key Material");
  if (material === undefined || !Buffer.isBuffer(material.value)) {
    throw credentialUnavailable("the managed object holds no value");
  }
  return material.value;
}

/**
 * The key of a service principal, which a CDMI server uses to decrypt the
 * tickets addressed to it (revision 282, cdmi_domain_auth; PLAN-auth.md).
 * "A shared secret used in a construction that is not a message authentication
 * code" is retrieved, the Kerberos profiles of RFC 3962 being computed here.
 */
/**
 * Resolves a reference to a key the CDMI server uses without taking it: the
 * key management server performs the operation, and the key does not reach
 * this one. "A CDMI server shall not retain a key after the operation that
 * required it has completed", which is kept most simply by never holding it
 * (the encrypted objects subclause; PLAN-encryption.md).
 */
export async function resolveKeyInPlace(ctx: CredentialContext, node: Node,
  stored: CredentialReference, requirement: CredentialRequirement):
  Promise<{ server: KeyManagement; id: string }> {
  const descriptor = assertScopeApplies(ctx, node, stored);
  const server = serverFor(ctx, stored.kms);
  await verifyBound(ctx, server, stored.kms, descriptor);
  const resolved = await resolveReference(server, stored, stored.scope ?? "", requirement);
  return { server, id: resolved.id };
}

/** The key encryption key of an encrypted object, which wraps its content key. */
export const KEY_ENCRYPTION_KEY: CredentialRequirement = {
  objectTypes: ["Public Key", "Private Key", "Symmetric Key"],
  // Encrypt and Decrypt: the content key generated for the object is
  // wrapped and unwrapped by the key management server through those
  // operations, the key encryption key never leaving it.
  usage: 0x04 | 0x08,
  purpose: "the key encryption key of an encrypted object",
  secretTypes: [],
};

/** The key that signs an object signature: Sign usage, and no secret taken. */
export const OBJECT_SIGNING_KEY: CredentialRequirement = {
  objectTypes: ["Private Key", "Symmetric Key"],
  usage: 0x01,
  purpose: "the key that signs the signature of an object",
  secretTypes: [],
};

/** The key that verifies a signature: Verify usage, and public. */
export const SIGNATURE_VERIFY_KEY: CredentialRequirement = {
  objectTypes: ["Public Key", "Symmetric Key", "Certificate"],
  usage: 0x02,
  purpose: "the key that verifies the signature of a value or an object",
  secretTypes: [],
};

export const SERVICE_KEY: CredentialRequirement = {
  objectTypes: ["Secret Data", "Symmetric Key"], usage: 0,
  purpose: "the key of the service principal of this CDMI server",
  secretTypes: ["Seed", "Password"],
};

/** A certificate that verifies a server: a Certificate, retrieved, not being a secret. */

export const CERTIFICATE: CredentialRequirement = {
  objectTypes: ["Certificate"], usage: 0, purpose: "a certificate that verifies the certificate a peer presents",
};

/**
 * Resolves a stored reference to a Certificate and retrieves it, in PEM, for a
 * TLS connection to trust. The binding and the state are checked as for a
 * secret; a certificate is retrieved as the field defining it says.
 */
export async function retrieveCertificate(ctx: CredentialContext, node: Node, stored: CredentialReference):
  Promise<{ id: string; pem: string }> {
  const descriptor = assertScopeApplies(ctx, node, stored);
  const server = serverFor(ctx, stored.kms);
  await verifyBound(ctx, server, stored.kms, descriptor);
  const resolved = await resolveReference(server, stored, stored.scope ?? "", CERTIFICATE);
  const got = await released(server, resolved.id);
  const value = child(got.object, "Certificate Value");
  if (value === undefined || !Buffer.isBuffer(value.value)) {
    throw credentialUnavailable("the managed object holds no certificate value");
  }
  const b64 = value.value.toString("base64").match(/.{1,64}/g)!.join("\n");
  return { id: resolved.id, pem: `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n` };
}

/**
 * A credential of the CDMI server itself (the one a remote import in service
 * identity mode presents where it names none): "a credential reference,
 * configured on the CDMI server, and a CDMI server shall not hold such a
 * secret by any other means. Each is resolved against the key management server
 * that the root domain object specifies as its default, in the scope that
 * applies to that domain object determined as though the scope_by_principal
 * field contained false" (revision 245). It is not a field of any object, and
 * is not returned in any representation.
 *
 * root is any object of the root domain, from which its key management servers
 * are read at each use, so that a change to the root domain's item applies.
 */
export async function retrieveOwnCredential(ctx: CredentialContext, root: Node, name: string): Promise<Retrieved> {
  const descriptors = ctx.descriptorsFor(root);
  // The default: the one the root domain names, or the one it marks default.
  const label = selectKms("the service credential", { name }, descriptors);
  const scope = descriptors[label].scope ?? "";
  return retrieveSecret(ctx, root, { kms: label, name, scope }, PASSWORD);
}

/**
 * Whether a stored reference may be kept as it is where a CDMI client writes
 * the entry again naming the same credential: only while the scope that applies
 * is still the one recorded. After a change of domain, writing it again is how
 * it "has been bound again", and keeping the old one would leave it unresolved.
 */
export function scopeStillApplies(ctx: CredentialContext, node: Node, stored: CredentialReference): boolean {
  try {
    assertScopeApplies(ctx, node, stored);
    return true;
  } catch {
    return false;
  }
}

/** A private key of the CDMI server itself, operated in place for signing. */
export const SIGNING_KEY: CredentialRequirement = {
  objectTypes: ["Private Key"], usage: 0x00000001, purpose: "a private key with which this server signs a request",
};
/** A private key of the CDMI server itself, operated in place to unwrap a response by RSA-OAEP. */
export const UNWRAPPING_KEY: CredentialRequirement = {
  objectTypes: ["Private Key"], usage: 0x00000008,
  purpose: "a private key with which this server unwraps a response addressed to it",
};

/**
 * A credential of the CDMI server itself resolved for use in place, never
 * retrieved: the key management server and the managed object, found as
 * retrieveOwnCredential finds one (at the root domain's default key management
 * server, in its scope, the binding verified, the state and the type and usage
 * checked) at each use.
 */
/**
 * Creates the key pair of an identity this server holds, at the key
 * management server and under the name the configuration gives, returning
 * the private half. The public half is named alongside it, since a provider
 * reads that to verify what this server signs.
 */
async function createOwnKey(server: KeyManagement, stored: CredentialReference,
  requirement: CredentialRequirement): Promise<string> {
  const at = `${stored.scope ?? ""}${stored.name}`;
  const named = (v: string) => attribute(k.struct("Name", [
    k.text("Name Value", v),
    k.enum("Name Type", "Name Type", "Uninterpreted Text String"),
  ]));
  const made = await server.createKeyPair({
    common: [
      attribute(k.enum("Cryptographic Algorithm", "Cryptographic Algorithm", "RSA")),
      attribute(k.int("Cryptographic Length", 2048)),
    ],
    privateKey: [named(at), attribute(k.int("Cryptographic Usage Mask", requirement.usage))],
    // Sign has Verify as its counterpart, and Decrypt has Encrypt.
    publicKey: [named(`${at}-public`),
      attribute(k.int("Cryptographic Usage Mask", requirement.usage === 0x01 ? 0x02 : 0x04))],
  });
  await server.activate(made.privateKey);
  console.log(`seedmi: created the key pair ${JSON.stringify(at)} at the key management server ` +
    `for ${requirement.purpose}, which held none of that name`);
  return made.privateKey;
}

export async function resolveOwnKey(ctx: CredentialContext, root: Node, name: string,
  requirement: CredentialRequirement): Promise<{ server: KeyManagement; id: string }> {
  const descriptors = ctx.descriptorsFor(root);
  const label = selectKms(requirement.purpose, { name }, descriptors);
  const stored: CredentialReference = { kms: label, name, scope: descriptors[label].scope ?? "" };
  const descriptor = assertScopeApplies(ctx, root, stored);
  const server = serverFor(ctx, label);
  await verifyBound(ctx, server, label, descriptor);
  try {
    const resolved = await resolveReference(server, stored, stored.scope ?? "", requirement);
    return { server, id: resolved.id };
  } catch (err) {
    // This server's own identity keys are its own to hold: nothing else can
    // create them, and a deployment naming ids the key management server
    // does not hold had no way to make them but by hand. Where the name is
    // held by nothing, the pair is created here, once, under that name. A
    // name held by something unsuitable is a fault and is not overwritten.
    const why = `${(err as { detail?: unknown }).detail ?? ""} ${(err as Error).message ?? ""}`;
    if (!why.includes("no credential named")) throw err;
    return { server, id: await createOwnKey(server, stored, requirement) };
  }
}
