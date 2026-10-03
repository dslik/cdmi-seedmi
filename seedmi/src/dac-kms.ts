// The identity this server presents to a delegated access control provider,
// with both of its private keys operated in place at a key management server.
//
// "the private key with which the CDMI server signs a delegated access control
// request ... [and] the private key with which the CDMI server unwraps a
// delegated access control response ... Each is a credential reference,
// configured on the CDMI server, and a CDMI server shall not hold such a secret
// by any other means" (Credentials of the CDMI server itself, revision 245).
// Both are "Operated in place" (the Use of a credential table): Sign for the
// signing key; for the unwrapping key, Decrypt where it is an RSA key and the
// sender used RSA-OAEP. Neither is retrieved.
//
// An elliptic curve unwrapping key is refused: the table gives it Derive Key,
// "the unwrapping being a key agreement", and no derivation method KMIP 1.2 to
// 1.4 defines is a key agreement (ECR-113A).

import { createPublicKey, type KeyObject, X509Certificate } from "node:crypto";
import { type CredentialContext, resolveOwnKey, SIGNING_KEY, UNWRAPPING_KEY } from "./credential-use.ts";
import type { DacIdentity } from "./dac.ts";
import { exportJwk, type Jwk } from "./jose.ts";
import type { CryptoParams } from "./kmip-params.ts";
import { child, type Item } from "./kmip-ttlv.ts";
import { enumName } from "./kmip-message.ts";
import type { KeyManagement } from "./kms.ts";
import type { Node } from "./store.ts";

/** What the configuration names: two credentials of this server, and optionally the certificates of each. */
export interface KmsIdentityOptions {
  /** The Name of the signing key within the root domain's scope. */
  signing: string;
  /** The Name of the unwrapping key within the root domain's scope. */
  encryption: string;
  /** The certificate chain of each, as base64 DER, reported in the x5c member where given. */
  signingChain?: string[];
  encryptionChain?: string[];
}

/** The KMIP parameters of Sign for a JWS algorithm, the key management server hashing what it signs. */
export function signParams(alg: string): CryptoParams {
  const bits = alg.slice(2);
  if (alg.startsWith("RS")) return { digitalSignatureAlgorithm: `SHA-${bits} with RSA Encryption (PKCS#1 v1.5)` };
  if (alg.startsWith("PS")) return { digitalSignatureAlgorithm: "RSASSA-PSS (PKCS#1 v2.1)", hashingAlgorithm: `SHA-${bits}` };
  if (alg.startsWith("ES")) return { digitalSignatureAlgorithm: `ECDSA with SHA${bits}` };
  throw new Error(`no KMIP signature parameters are known for ${alg}`);
}

/** The KMIP parameters of Decrypt for RSA-OAEP with a hash, as JOSE names it for Node. */
export function unwrapParams(oaepHash: string): CryptoParams {
  const hash = ({ sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" } as Record<string, string>)[oaepHash];
  if (hash === undefined) throw new Error(`no KMIP hashing algorithm is known for OAEP with ${oaepHash}`);
  return { cryptographicAlgorithm: "RSA", paddingMethod: "OAEP", hashingAlgorithm: hash };
}

/**
 * The public key of a private key held at a key management server: the first
 * certificate of the chain configured where there is one, and otherwise the
 * Public Key its Link attribute names, which is not a secret and is retrieved.
 */
async function publicKeyOf(server: KeyManagement, id: string, chain: string[] | undefined): Promise<KeyObject> {
  if (chain !== undefined && chain.length > 0) {
    return new X509Certificate(Buffer.from(chain[0], "base64")).publicKey;
  }
  const links = await server.getAttributes(id, ["Link"]);
  let publicId: string | undefined;
  for (const l of links) {
    const type = child(l.value as Item, "Link Type");
    const linked = child(l.value as Item, "Linked Object Identifier");
    if (type !== undefined && enumName("Link Type", type.value as number) === "Public Key Link") {
      publicId = String(linked?.value);
    }
  }
  if (publicId === undefined) {
    throw new Error("the key names no Public Key by a Link attribute, and no certificate is configured for it; " +
      "one of the two is needed to publish the public key");
  }
  const got = await server.get(publicId);
  const block = child(got.object, "Key Block");
  const format = enumName("Key Format Type", child(block!, "Key Format Type")!.value as number);
  const material = child(child(block!, "Key Value")!, "Key Material")!.value as Buffer;
  if (format === "PKCS#1") return createPublicKey({ key: material, format: "der", type: "pkcs1" });
  if (format === "X.509") return createPublicKey({ key: material, format: "der", type: "spki" });
  throw new Error(`a public key of format ${format} is not read by this server`);
}

/**
 * The identity, its public parts read at start and read again where a key has
 * been replaced at the key management server (a rotation leaves the Name on a
 * new managed object): each key is resolved at each operation, by Name, so that
 * its State is determined before it is used.
 */
export function kmsIdentity(context: () => CredentialContext, root: () => Node, o: KmsIdentityOptions):
  DacIdentity & { refresh(): Promise<void> } {
  const held = { signingId: "", encryptionId: "" };
  const identity = {
    signingPublic: undefined as unknown as KeyObject,
    encryptionPublic: undefined as unknown as KeyObject,
    signingJwk: undefined as unknown as Jwk,
    encryptionJwk: undefined as unknown as Jwk,
    async refresh(): Promise<void> {
      const s = await resolveOwnKey(context(), root(), o.signing, SIGNING_KEY);
      const e = await resolveOwnKey(context(), root(), o.encryption, UNWRAPPING_KEY);
      if (s.id !== held.signingId) {
        identity.signingPublic = await publicKeyOf(s.server, s.id, o.signingChain);
        identity.signingJwk = exportJwk(identity.signingPublic,
          { kid: o.signing, ...(o.signingChain === undefined ? {} : { x5c: o.signingChain }) });
        held.signingId = s.id;
      }
      if (e.id !== held.encryptionId) {
        const pub = await publicKeyOf(e.server, e.id, o.encryptionChain);
        if (pub.asymmetricKeyType !== "rsa") {
          throw new Error("the key a response is encrypted to is an elliptic curve key, which is unwrapped by a " +
            "key agreement that no KMIP derivation method performs in place (ECR-113A); an RSA key is needed");
        }
        identity.encryptionPublic = pub;
        identity.encryptionJwk = exportJwk(pub,
          { kid: o.encryption, ...(o.encryptionChain === undefined ? {} : { x5c: o.encryptionChain }) });
        held.encryptionId = e.id;
      }
      if (held.signingId === held.encryptionId) {
        // "The two shall be different keys." A CDMI server shall use neither key for the purpose of the other.
        throw new Error("the signing key and the unwrapping key are one managed object; two are needed");
      }
    },
    async sign(alg: string, input: Buffer): Promise<Buffer> {
      const { server, id } = await resolveOwnKey(context(), root(), o.signing, SIGNING_KEY);
      return await server.sign(id, { params: signParams(alg), data: input });
    },
    async unwrap(encryptedKey: Buffer, oaepHash: string): Promise<Buffer> {
      const { server, id } = await resolveOwnKey(context(), root(), o.encryption, UNWRAPPING_KEY);
      return await server.decrypt(id, { params: unwrapParams(oaepHash), data: encryptedKey });
    },
  };
  // Nothing is resolved until the identity is first used: a store newly made
  // names no key management server in its root domain until one is configured.
  return identity;
}
