// The value an HTTP import presents: "An HTTP import presents the
// representation an origin server returns for one URI as the value of a data
// object. It is a value import ...: the import source holds an ordered
// sequence of bytes, and the CDMI server presents that sequence and no
// namespace" (revision 327, the HTTP imports subclause).
//
// The subclause is small and exact, and the rules it sets are these:
//
//   * the value is "the representation the origin server returns for a GET
//     request for the URI, as the origin server returns it and without
//     decoding a content coding";
//   * the "mimetype" field comes from Content-Type, the cdmi_size item from
//     the length of the representation, and the cdmi_mtime item from
//     Last-Modified where the origin server returns one;
//   * an import is established by a HEAD request, "which confirms that the
//     origin server serves it and provides the header fields the CDMI server
//     records", and by a GET where the origin server does not support HEAD;
//   * a request that does not succeed makes the import not active, and the
//     condition is recorded in the "last_problems" field;
//   * the value is obtained when the importing object is first read, and
//     thereafter as "cache_max_age" provides, by a conditional request
//     carrying the entity tag or the time the origin server last returned.
//
// An HTTP import is read only, which the binding enforces: this module only
// obtains what the origin server holds.
import { submitOriginated } from "./originated.ts";

/** What an origin server returned, as an import records it. */
export interface Obtained {
  /** The bytes of the representation, absent where a conditional request was answered 304. */
  value?: Buffer;
  /** From Content-Type, for the mimetype field. */
  mimetype?: string;
  /** From Last-Modified, for the cdmi_mtime item and for revalidation. */
  lastModified?: string;
  /** From ETag, for revalidation. */
  etag?: string;
  /** The status the origin server returned. */
  status: number;
}

/** The entry's fields this module reads. */
export interface HttpImportEntry {
  import_uri?: string;
  auth_method?: string;
  username?: string;
  cache_max_age?: string;
  etag?: string;
  last_modified?: string;
}

/**
 * The credential this server presents to the origin server: the password of
 * the Basic scheme or the token of the Bearer scheme. It is held as a
 * credential reference and resolved at the key management server, so the
 * entry itself "holds no secret".
 */
export type SecretOf = (entry: HttpImportEntry) => Promise<string | undefined>;

/**
 * The trust anchor an entry names, in PEM, where it names one.
 *
 * "For each such connection, a CDMI server shall verify the certificate the
 * party presents against the trust anchor the entry or the descriptor names,
 * where it names one, and against the trust anchors the CDMI server is
 * configured with where it does not" (revision 365, verifying the certificate
 * of a party a CDMI server connects to).
 */
export type TrustAnchorOf = (entry: HttpImportEntry) => Promise<string | undefined>;

/** The Authorization header field an entry calls for, where it calls for one. */
async function authorization(entry: HttpImportEntry, secret: SecretOf):
  Promise<string | undefined> {
  const method = entry.auth_method ?? "none";
  if (method === "none") return undefined;
  const held = await secret(entry);
  if (held === undefined) return undefined;
  if (method === "bearer") return `Bearer ${held}`;
  return `Basic ${Buffer.from(`${entry.username ?? ""}:${held}`, "utf8").toString("base64")}`;
}

const headerOf = (r: { headers: Record<string, string | string[] | undefined> }, name: string):
  string | undefined => {
  const v = r.headers[name];
  return Array.isArray(v) ? v[0] : v;
};

/**
 * Establishes an import: a HEAD request, "which confirms that the origin
 * server serves it and provides the header fields the CDMI server records",
 * and a GET where the origin server does not support HEAD. The value is not
 * kept here: it is obtained when the importing object is first read.
 */
export async function establish(entry: HttpImportEntry, secret: SecretOf,
  anchor?: TrustAnchorOf): Promise<Obtained> {
  const uri = entry.import_uri ?? "";
  const auth = await authorization(entry, secret);
  const ca = anchor === undefined ? undefined : await anchor(entry);
  const opts = {
    ...(auth === undefined ? {} : { headers: { Authorization: auth } }),
    ...(ca === undefined ? {} : { ca }),
  };
  let answer = await submitOriginated(uri, { method: "HEAD", ...opts });
  // 405 Method Not Allowed and 501 Not Implemented are how an origin server
  // says it does not support the method.
  if (answer.status === 405 || answer.status === 501) {
    answer = await submitOriginated(uri, { method: "GET", ...opts });
  }
  return {
    status: answer.status,
    mimetype: headerOf(answer, "content-type")?.split(";")[0].trim(),
    lastModified: headerOf(answer, "last-modified"),
    etag: headerOf(answer, "etag"),
  };
}

/**
 * Obtains the value. Where the entry records an entity tag or a time, the
 * request is conditional, and an answer of 304 Not Modified leaves the value
 * this server holds in place.
 */
export async function obtain(entry: HttpImportEntry, secret: SecretOf,
  revalidate: boolean, anchor?: TrustAnchorOf): Promise<Obtained> {
  const uri = entry.import_uri ?? "";
  const auth = await authorization(entry, secret);
  const headers: Record<string, string> = {};
  if (auth !== undefined) headers.Authorization = auth;
  if (revalidate && entry.etag !== undefined) headers["If-None-Match"] = entry.etag;
  if (revalidate && entry.etag === undefined && entry.last_modified !== undefined) {
    headers["If-Modified-Since"] = entry.last_modified;
  }
  const ca = anchor === undefined ? undefined : await anchor(entry);
  const answer = await submitOriginated(uri, { method: "GET", headers, ...(ca === undefined ? {} : { ca }) });
  if (answer.status === 304) {
    return { status: 304, etag: entry.etag, lastModified: entry.last_modified };
  }
  return {
    status: answer.status,
    // "as the origin server returns it and without decoding a content
    // coding": the bytes are kept as they arrived.
    value: answer.body,
    mimetype: headerOf(answer, "content-type")?.split(";")[0].trim(),
    lastModified: headerOf(answer, "last-modified"),
    etag: headerOf(answer, "etag"),
  };
}

/**
 * Whether the value this server holds may be presented without obtaining it
 * again. "A value of 0 obtains it again for every read. Where this field is
 * absent, the CDMI server obtains the value once, when the importing object
 * is first read, and does not obtain it again."
 */
export function stillFresh(entry: HttpImportEntry, obtainedAt: number | undefined,
  now = Date.now()): boolean {
  if (obtainedAt === undefined) return false;
  const age = entry.cache_max_age;
  if (age === undefined) return true;
  const seconds = Number(age);
  if (seconds === 0) return false;
  return now - obtainedAt < seconds * 1000;
}
