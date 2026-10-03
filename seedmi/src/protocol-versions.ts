// The protocol versions this server offers for the export and import types
// whose protocol field revision 245 defines as an array, and the validation of
// that field.
//
// Each list is the value of the capability that publishes it, so that the
// capabilities and what an entry is checked against cannot differ. NFS, SMB
// and MQTT carry theirs with the code that serves them.

import { capabilityNotPresent, invalidField } from "./problems.ts";

/** cdmi_export_http_versions */
export const HTTP_EXPORT_VERSIONS = ["HTTP/1.1"];
/** cdmi_export_s3_versions */
export const S3_EXPORT_VERSIONS = ["2006-03-01"];
/** cdmi_import_cdmi_versions */
export const CDMI_IMPORT_VERSIONS = ["CDMIv3.0"];

/**
 * The protocol field of an entry: "A JSON array of JSON strings ... A CDMI
 * server shall report the capability not present condition where a value
 * names a version that capability does not contain." Before 0.46 the field was
 * refused on an HTTP export and a CDMI import, as not defined for the type.
 */
export function parseVersions(field: string, raw: unknown, capability: string, offered: string[]): string[] {
  if (!Array.isArray(raw) || raw.length === 0 || raw.some((v) => typeof v !== "string")) {
    throw invalidField(field, "the protocol field is a JSON array of one or more JSON strings");
  }
  for (const v of raw as string[]) {
    if (!offered.includes(v)) {
      throw capabilityNotPresent(capability, "/cdmi_capabilities/",
        "%j is not a version the %s capability contains, which are %s", v, capability, offered.join(", "));
    }
  }
  return raw as string[];
}
