// S3 exports.
//
// An S3 export presents the objects a container object contains as
// the objects of a bucket, reached by the operations the Amazon
// Simple Storage Service API defines. It is placed on a container
// object, as an entry of the exports field of that object.
//
// This module holds what an S3 export entry is: the fields and their
// validation. Serving the bucket is elsewhere.

import { parseVersions, S3_EXPORT_VERSIONS } from "./protocol-versions.ts";
import { invalidField } from "./problems.ts";

/** The fields of an S3 export entry that a CDMI client supplies. */
export interface S3Export {
  type: string;
  bucket_name: string;
  /** The S3 versions offered, where the entry states them. */
  protocol?: string[];
  region: string;
  addressing_style: string;
  tls: string;
  versioning: string;
  anonymous_read: string;
  multipart_expiry?: string;
  disabled: string;
}

/** The request addressing styles at which a bucket is reachable. */
export const ADDRESSING_STYLES = ["path", "virtual_hosted", "both"];

/** Whether requests to a bucket are protected by TLS. */
export const TLS_SETTINGS = ["disabled", "required"];

/** The region a CDMI server names where an entry names none. */
export const DEFAULT_REGION = "us-east-1";

/**
 * Checks a bucket name against the restrictions the clause states,
 * which permit the bucket to be addressed using the virtual hosted
 * addressing style.
 */
export function checkBucketName(at: string, name: string): void {
  const fail = (why: string): never => {
    throw invalidField(at, "a bucket name %s", why);
  };
  if (name.length < 3 || name.length > 63) {
    fail("is between 3 and 63 characters in length");
  }
  if (!/^[a-z0-9.-]+$/.test(name)) {
    fail("consists only of lowercase letters, decimal digits, hyphens and periods");
  }
  if (!/^[a-z0-9]/.test(name) || !/[a-z0-9]$/.test(name)) {
    fail("begins and ends with a lowercase letter or a decimal digit");
  }
  if (name.includes("..")) fail("does not contain two adjacent periods");
  // A name formatted as an IPv4 address would be ambiguous with the
  // address of an endpoint.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(name)) {
    fail("is not formatted as an IPv4 address");
  }
  for (const prefix of ["xn--", "sthree-"]) {
    if (name.startsWith(prefix)) fail(`does not begin with "${prefix}"`);
  }
  for (const suffix of ["-s3alias", "--ol-s3"]) {
    if (name.endsWith(suffix)) fail(`does not end with "${suffix}"`);
  }
}

/**
 * A region name, which appears as a slash-delimited element of the
 * credential scope within a request signature: a value containing a
 * solidus or white space prevents a signature from being computed.
 */
export function checkRegion(at: string, region: string): void {
  if (region === "" || !/^[a-z0-9-]+$/.test(region)) {
    throw invalidField(at,
      "a region name consists only of lowercase letters, decimal digits and " +
      "hyphens, and is not empty");
  }
}

/**
 * Reads an S3 export entry. The bucket name is checked here; that it
 * is not already in use by another bucket of this CDMI server is
 * checked where the entries of every object are known.
 */
export function parseS3Entry(name: string, raw: unknown): S3Export {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw invalidField(`/exports/${name}`, "an export entry shall be a JSON object");
  }
  const e = raw as Record<string, unknown>;
  const at = (f: string) => `/exports/${name}/${f}`;
  const str = (f: string): string | undefined => {
    const v = e[f];
    if (v === undefined) return undefined;
    if (typeof v !== "string") {
      throw invalidField(at(f), "the %j field shall be a JSON string", f);
    }
    return v;
  };
  const one = (f: string, permitted: string[], dflt: string): string => {
    const v = str(f) ?? dflt;
    if (!permitted.includes(v)) {
      throw invalidField(at(f), "the %j field shall be one of %s",
        f, permitted.join(", "));
    }
    return v;
  };

  // The CDMI server populates these and ignores them where a client
  // supplies them.
  for (const f of ["endpoints", "active", "last_problems", "state_determined_time",
    "multipart_uploads", "multipart_uploads_size"]) {
    delete e[f];
  }

  const bucket = str("bucket_name");
  if (bucket === undefined || bucket === "") {
    throw invalidField(at("bucket_name"),
      "an S3 export entry shall contain a bucket_name field");
  }
  checkBucketName(at("bucket_name"), bucket);

  const region = str("region") ?? DEFAULT_REGION;
  checkRegion(at("region"), region);

  const addressing = one("addressing_style", ADDRESSING_STYLES, "both");
  const tls = one("tls", TLS_SETTINGS, "required");

  // A bucket name containing a period adds a label to the host name
  // of a virtual hosted request, which a wildcard certificate does
  // not match. This CDMI server refuses the entry rather than
  // serving the bucket by path style alone, so that a CDMI client
  // learns of the restriction rather than discovering it in the
  // endpoints reported.
  if (bucket.includes(".") && tls === "required" &&
    (addressing === "virtual_hosted" || addressing === "both")) {
    throw invalidField(at("bucket_name"),
      "a bucket name containing a period is not served by virtual hosted " +
      "addressing over TLS, a wildcard certificate matching no further label");
  }

  const expiry = str("multipart_expiry");
  if (expiry !== undefined && !/^P(?!$)(\d+[YMWD])*(T(?!$)(\d+[HMS])*)?$/.test(expiry)) {
    throw invalidField(at("multipart_expiry"),
      "the multipart_expiry field is a duration, such as \"P7D\"");
  }

  // The S3 versions offered, checked against cdmi_export_s3_versions. It was
  // dropped before 0.46, this parser taking only the fields it knew.
  const protocol = "protocol" in e
    ? parseVersions(at("protocol"), e.protocol, "cdmi_export_s3_versions", S3_EXPORT_VERSIONS)
    : undefined;

  return {
    type: "S3",
    bucket_name: bucket,
    ...(protocol === undefined ? {} : { protocol }),
    region,
    addressing_style: addressing,
    tls,
    versioning: one("versioning", ["true", "false"], "false"),
    anonymous_read: one("anonymous_read", ["true", "false"], "false"),
    ...(expiry === undefined ? {} : { multipart_expiry: expiry }),
    disabled: one("disabled", ["true", "false"], "false"),
  };
}
