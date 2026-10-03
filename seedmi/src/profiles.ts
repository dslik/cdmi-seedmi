// The conformance profiles of Annex F, and which of them a deployment meets.
//
// "A profile is a name for a set of capabilities this document defines. It
// exists so that a buyer can state what minimum is required, an implementer
// can indicate what minimum is provided, and a test suite can report that a
// CDMI server did or did not meet a named bar." Annex F is informative, and a
// claim binds nothing (ECR-187A), so this server does not carry a list of
// profiles it asserts: it evaluates each profile against the capability
// objects it is about to serve, and claims the ones it meets. A claim
// therefore cannot drift from the capabilities, and a deployment that serves
// no NFS listener claims no profile that requires one, without anything being
// configured.
//
// "A profile states what a CDMI server claiming it publishes as a minimum. It
// requires the absence of no capability", so a profile is met where every
// required capability is published, whatever else is.
//
// The Recommended list of a profile is not evaluated: it recommends and does
// not require, and a CDMI server that publishes none of it still claims the
// profile.

/**
 * A requirement names a capability, optionally qualified by the capability
 * object that shall publish it: "container:cdmi_create_container" requires it
 * of the capability object of a container object, and "cdmi_hash" requires it
 * of any capability object Annex B defines it for, which is what the annex
 * means where it names a capability and no object.
 */
export type Requirement = string;

export interface Profile {
  /** The value a CDMI server places in cdmi_profiles. */
  id: string;
  /** The name Annex F gives the profile. */
  title: string;
  /** Every one of these is required. */
  all: Requirement[];
  /** And, of each group, at least `n` of the alternatives shall hold whole. */
  choose?: { n: number; of: Requirement[][] }[];
}

/** The capability objects this server serves, as the keys of a published set. */
export type Published = Record<string, ReadonlyArray<string>>;

export const PROFILES: Profile[] = [
  {
    id: "core",
    title: "Core",
    all: [
      "root:cdmi_dataobjects", "root:cdmi_object_access_by_ID",
      "root:cdmi_security_access_control", "root:cdmi_authentication_methods",
      "root:cdmi_metadata_maxitems", "root:cdmi_metadata_maxsize",
      "root:cdmi_metadata_maxtotalsize",
      "container:cdmi_create_container", "container:cdmi_delete_container",
      "container:cdmi_create_dataobject", "container:cdmi_post_dataobject",
      "container:cdmi_list_children", "container:cdmi_list_children_range",
      "container:cdmi_list_children_extended",
      "container:cdmi_read_metadata", "container:cdmi_modify_metadata",
      "dataobject:cdmi_read_metadata", "dataobject:cdmi_modify_metadata",
      "dataobject:cdmi_read_value", "dataobject:cdmi_read_value_range",
      "dataobject:cdmi_modify_value", "dataobject:cdmi_delete_dataobject",
      "container:cdmi_size", "container:cdmi_ctime", "container:cdmi_mtime",
      "container:cdmi_atime", "container:cdmi_acl", "container:cdmi_owner",
      "container:cdmi_group",
      "dataobject:cdmi_size", "dataobject:cdmi_ctime", "dataobject:cdmi_mtime",
      "dataobject:cdmi_atime", "dataobject:cdmi_acl", "dataobject:cdmi_owner",
      "dataobject:cdmi_group",
    ],
  },
  {
    id: "namespace",
    title: "Multiprotocol namespace",
    all: [
      "root:cdmi_exports_provided",
      "root:cdmi_export_http", "container:cdmi_export_container_http",
      "root:cdmi_imports", "root:cdmi_imports_provided", "root:cdmi_imports_copy_up",
      "container:cdmi_move_dataobject", "container:cdmi_copy_dataobject",
      "container:cdmi_move_container", "container:cdmi_copy_container",
    ],
    choose: [
      // "two of cdmi_export_s3, cdmi_export_smb and cdmi_export_nfs, published
      // by the root capability object, with the matching
      // cdmi_export_container_s3, cdmi_export_container_smb or
      // cdmi_export_container_nfs published by the capability object of a
      // container object".
      {
        n: 2,
        of: [
          ["root:cdmi_export_s3", "container:cdmi_export_container_s3"],
          ["root:cdmi_export_smb", "container:cdmi_export_container_smb"],
          ["root:cdmi_export_nfs", "container:cdmi_export_container_nfs"],
        ],
      },
      // "one of cdmi_import_nfs and cdmi_import_smb, with the matching
      // cdmi_import_container_nfs or cdmi_import_container_smb".
      {
        n: 1,
        of: [
          ["root:cdmi_import_nfs", "container:cdmi_import_container_nfs"],
          ["root:cdmi_import_smb", "container:cdmi_import_container_smb"],
        ],
      },
      // "one of cdmi_import_nfs_delegation and cdmi_import_smb_delegation, so
      // that the identity of a principal reaches the import source for at
      // least one imported type".
      {
        n: 1,
        of: [["root:cdmi_import_nfs_delegation"], ["root:cdmi_import_smb_delegation"]],
      },
    ],
  },
  {
    id: "archive",
    title: "Regulated archive",
    all: [
      "root:cdmi_security_immutability", "root:cdmi_security_data_integrity",
      "container:cdmi_data_retention", "container:cdmi_data_holds",
      "container:cdmi_data_autodelete",
      "dataobject:cdmi_data_retention", "dataobject:cdmi_data_holds",
      "dataobject:cdmi_data_autodelete",
      "container:cdmi_value_hash", "dataobject:cdmi_value_hash", "cdmi_hash",
      "root:cdmi_security_sanitization", "cdmi_sanitization_method",
      "cdmi_versioning", "cdmi_version_current", "cdmi_version_oldest",
      "cdmi_version_object", "cdmi_version_parent",
      "root:cdmi_serialization_json", "container:cdmi_serialize_dataobject",
      "container:cdmi_serialize_container",
    ],
  },
  {
    id: "service",
    title: "Managed service",
    all: [
      "root:cdmi_domains", "domain:cdmi_create_domain", "domain:cdmi_delete_domain",
      "root:cdmi_domain_auth", "root:cdmi_domain_userinfo",
      "container:cdmi_geographic_placement", "container:cdmi_data_redundancy",
      "container:cdmi_immediate_redundancy", "container:cdmi_latency",
      "container:cdmi_throughput", "container:cdmi_RPO", "container:cdmi_RTO",
      "dataobject:cdmi_geographic_placement", "dataobject:cdmi_data_redundancy",
      "dataobject:cdmi_immediate_redundancy", "dataobject:cdmi_latency",
      "dataobject:cdmi_throughput", "dataobject:cdmi_RPO", "dataobject:cdmi_RTO",
      "root:cdmi_cors", "cdmi_cors_origins", "cdmi_cors_methods", "cdmi_cors_headers",
    ],
  },
  {
    id: "agent",
    title: "Agent access",
    all: [
      "root:cdmi_mcp_uri",
      "root:cdmi_queues", "container:cdmi_create_queue", "queue:cdmi_delete_queue",
      "root:cdmi_notification",
      "root:cdmi_query", "root:cdmi_query_contains", "root:cdmi_query_tags",
      "root:cdmi_graph_rels",
      "cdmi_list_children_recursive",
      "root:cdmi_references", "container:cdmi_create_reference",
    ],
  },
];

/** Whether one requirement holds of a published set. */
function holds(req: Requirement, published: Published): boolean {
  const cut = req.indexOf(":");
  if (cut < 0) {
    // Annex F names the capability and no capability object: it is met where
    // any capability object this server serves publishes it.
    return Object.values(published).some((c) => c.includes(req));
  }
  const object = req.slice(0, cut), name = req.slice(cut + 1);
  return (published[object] ?? []).includes(name);
}

/** The requirements of a profile that a published set does not meet. */
export function unmet(profile: Profile, published: Published): string[] {
  const missing = profile.all.filter((r) => !holds(r, published));
  for (const group of profile.choose ?? []) {
    const met = group.of.filter((alt) => alt.every((r) => holds(r, published)));
    if (met.length >= group.n) continue;
    // What is reported is the whole choice, since no one alternative of it is
    // required: a CDMI server meets it by any n of them.
    missing.push(`${group.n} of ${group.of.map((a) => a.join(" + ")).join(", ")}`);
  }
  return missing;
}

/**
 * The identifiers of the profiles a published set meets, in the order Annex F
 * defines them. "An empty array indicates that the CDMI server claims no
 * profile", so the capability is published whatever the outcome.
 */
export function profilesMet(published: Published): string[] {
  return PROFILES.filter((p) => unmet(p, published).length === 0).map((p) => p.id);
}
