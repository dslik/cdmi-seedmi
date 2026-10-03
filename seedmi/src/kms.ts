// seedmi's key management: one interface over the key management servers the
// CDMI draft permits (revision 196, the key management subclause of Security).
//
//   "A CDMI server may implement a key management server itself, in which case
//   a secret is held by that key management server and is subject to the
//   requirements of this subclause as one held by an external key management
//   server is." InternalKms is that server: the KMIP core in process, its objects
//   kept in seedmi's store.
//
//   "A CDMI server that holds credentials at a key management server external to
//   it reaches that key management server using the Key Management
//   Interoperability Protocol". KmipKms is that: the KMIP 1.4 client.
//
// Both speak in the terms of KMIP 1.4: managed objects, their attributes, states
// and operations. Consumers (credential references, deposit, scope binding) use
// this interface and not the core or the client.

import { createHash, X509Certificate } from "node:crypto";
import type { Attribute } from "./kmip-message.ts";
import type { Item } from "./kmip-ttlv.ts";
import { KmipClient, KmipOperationError, KmipProtocolError, type KeyWrappingSpecification } from "./kmip-client.ts";
import type { CryptoParams } from "./kmip-params.ts";

/**
 * An operation the key management server refused, with its KMIP 1.4 Result
 * Reason (9.1.3.2.29), from either implementation.
 */
export class KeyManagementError extends Error {
  readonly reason: string;
  constructor(reason: string, message: string) {
    super(message);
    this.name = "KeyManagementError";
    this.reason = reason;
  }
}

/** The key management server could not be reached, or did not answer as KMIP requires. */
export class KeyManagementUnavailable extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeyManagementUnavailable";
  }
}

export interface KeyManagement {
  /** The label configuration gives, by which a domain's cdmi_domain_kms names it. */
  readonly label: string;
  /** How the server is reached. seedmi reaches every one by KMIP. */
  readonly kind: "kmip";
  /**
   * The identifier of this CDMI server at this key management server: "a digest
   * of the public key of the credential with which it authenticates to that key
   * management server" (binding subclause). The same each time it is determined.
   */
  identifier(): Promise<string>;
  /** The KMIP version in use, where the server is reached by KMIP; undefined for the internal one. */
  version(): Promise<string | undefined>;

  locate(attrs: Attribute[], opts?: { maximumItems?: number }): Promise<string[]>;
  get(id: string, opts?: { keyWrapType?: string; wrapping?: KeyWrappingSpecification }): Promise<{ objectType: string; object: Item }>;
  getAttributes(id: string, names?: string[]): Promise<Attribute[]>;
  register(objectType: string, attrs: Attribute[], object: Item): Promise<string>;
  create(objectType: string, attrs: Attribute[]): Promise<string>;
  createKeyPair(attrs: { common?: Attribute[]; privateKey?: Attribute[]; publicKey?: Attribute[] }): Promise<{ privateKey: string; publicKey: string }>;
  addAttribute(id: string, attr: Attribute): Promise<Attribute>;
  deleteAttribute(id: string, name: string, index?: number): Promise<Attribute>;
  activate(id: string): Promise<void>;
  revoke(id: string, code: string, opts?: { message?: string; compromiseOccurrence?: number }): Promise<void>;
  destroy(id: string): Promise<void>;
  sign(id: string, req: { params?: CryptoParams; data: Buffer }): Promise<Buffer>;
  mac(id: string, req: { params?: CryptoParams; data: Buffer }): Promise<Buffer>;
  encrypt(id: string, req: { params?: CryptoParams; data: Buffer; iv?: Buffer; aad?: Buffer }): Promise<{ data: Buffer; iv?: Buffer; tag?: Buffer }>;
  decrypt(id: string, req: { params?: CryptoParams; data: Buffer; iv?: Buffer; aad?: Buffer; tag?: Buffer }): Promise<Buffer>;
  close(): Promise<void>;
}

// ---------------------------------------------------------------------------
// An external key management server, by KMIP

export interface KmipKmsConfig {
  label: string;
  host: string;
  port: number;
  servername?: string;
  /** PEM: the authority the server's certificate chains to. */
  ca: string;
  /** PEM: the certificate and key seedmi authenticates with. */
  certificate: string;
  key: string;
  timeoutMs?: number;
}

/**
 * The identifier of a CDMI server that authenticates with a certificate: SHA-256
 * over the DER encoding of the certificate's SubjectPublicKeyInfo, in base 16.
 *
 * Revision 232 defines the form, which this server chose for itself before:
 * "the public key is encoded as the SubjectPublicKeyInfo structure RFC 5280
 * defines, using the distinguished encoding rules; that encoding is digested
 * with SHA-256; and that digest is encoded in base 16, as RFC 4648 defines".
 * Base 16 of RFC 4648 is upper case, where this server wrote lower case, so
 * two CDMI servers now determine the same identifier for the same key.
 */
export function identifierOfCertificate(pem: string): string {
  const spki = new X509Certificate(pem).publicKey.export({ type: "spki", format: "der" }) as Buffer;
  return createHash("sha256").update(spki).digest("hex").toUpperCase();
}

export class KmipKms implements KeyManagement {
  readonly label: string;
  readonly kind = "kmip" as const;
  readonly endpoint: string;
  private readonly config: KmipKmsConfig;
  private readonly client: KmipClient;
  private negotiated: Promise<void> | undefined;

  constructor(config: KmipKmsConfig) {
    this.config = config;
    this.label = config.label;
    this.endpoint = `kmip://${config.host}:${config.port}`;
    this.client = new KmipClient({
      host: config.host, port: config.port, ca: config.ca, cert: config.certificate, key: config.key,
      ...(config.servername === undefined ? {} : { servername: config.servername }),
      ...(config.timeoutMs === undefined ? {} : { timeoutMs: config.timeoutMs }),
    });
  }

  async identifier(): Promise<string> {
    return identifierOfCertificate(this.config.certificate);
  }

  async version(): Promise<string | undefined> {
    await this.ready();
    return `${this.client.version.major}.${this.client.version.minor}`;
  }

  /** Negotiates the version once, before the first operation; a failure is tried again next time. */
  private ready(): Promise<void> {
    this.negotiated ??= this.client.negotiate().then(() => undefined, (e) => {
      this.negotiated = undefined;
      throw e;
    });
    return this.negotiated;
  }

  private async call<T>(f: () => Promise<T>): Promise<T> {
    try {
      await this.ready();
      return await f();
    } catch (e) {
      if (e instanceof KmipOperationError) throw new KeyManagementError(e.reason, e.message);
      if (e instanceof KmipProtocolError) throw new KeyManagementUnavailable(`${this.endpoint}: ${e.message}`);
      throw e;
    }
  }

  locate = (attrs: Attribute[], opts: { maximumItems?: number } = {}) => this.call(async () => (await this.client.locate(attrs, opts)).ids);
  get = (id: string, opts: { keyWrapType?: string; wrapping?: KeyWrappingSpecification } = {}) =>
    this.call(async () => {
      const r = await this.client.get(id, opts);
      return { objectType: r.objectType, object: r.object };
    });
  getAttributes = (id: string, names?: string[]) => this.call(() => this.client.getAttributes(id, names));
  register = (objectType: string, attrs: Attribute[], object: Item) => this.call(() => this.client.register(objectType, attrs, object));
  create = (objectType: string, attrs: Attribute[]) => this.call(() => this.client.create(objectType, attrs));
  createKeyPair = (attrs: { common?: Attribute[]; privateKey?: Attribute[]; publicKey?: Attribute[] }) =>
    this.call(() => this.client.createKeyPair(attrs));
  addAttribute = (id: string, attr: Attribute) => this.call(() => this.client.addAttribute(id, attr));
  deleteAttribute = (id: string, name: string, index?: number) => this.call(() => this.client.deleteAttribute(id, name, index));
  activate = (id: string) => this.call(async () => { await this.client.activate(id); });
  revoke = (id: string, code: string, opts?: { message?: string; compromiseOccurrence?: number }) =>
    this.call(async () => { await this.client.revoke(id, code, opts); });
  destroy = (id: string) => this.call(async () => { await this.client.destroy(id); });
  sign = (id: string, req: { params?: CryptoParams; data: Buffer }) => this.call(() => this.client.sign(id, req));
  mac = (id: string, req: { params?: CryptoParams; data: Buffer }) => this.call(() => this.client.mac(id, req));
  encrypt = (id: string, req: { params?: CryptoParams; data: Buffer; iv?: Buffer; aad?: Buffer }) => this.call(() => this.client.encrypt(id, req));
  decrypt = (id: string, req: { params?: CryptoParams; data: Buffer; iv?: Buffer; aad?: Buffer; tag?: Buffer }) =>
    this.call(() => this.client.decrypt(id, req));

  async close(): Promise<void> {
    this.client.close();
  }
}

// ---------------------------------------------------------------------------
// Capabilities

/**
 * The capabilities the configured key management servers support (annex B):
 * cdmi_kms where any is configured, and cdmi_kms_kmip where one is external,
 * reached by KMIP. cdmi_kms_client_registration is a property of a domain's
 * descriptors, and is not decided here.
 *
 * Not yet published: cdmi_kms asserts that "the CDMI server resolves a credential
 * reference against a key management server", which seedmi does from phase 8.
 */
export function kmsCapabilities(servers: KeyManagement[]): Record<string, string> {
  if (servers.length === 0) return {};
  return {
    cdmi_kms: "true",
    ...(servers.some((s) => s.kind === "kmip") ? { cdmi_kms_kmip: "true" } : {}),
    // "a CDMI client registers a managed object at a key management server
    // itself and supplies a credential reference addressing it": this server
    // accepts such a reference wherever the domain's key management server
    // offers client registration, which each domain's item says.
    cdmi_kms_client_registration: "true",
  };
}
