// The version of seedmi. Reported by `--version` and `-v`.
//
// The minor version is incremented in every working session that
// revises seedmi, so that a build can be matched to the session that
// produced it; the history is in README.md. package.json carries the
// same version with a patch component of 0, which a test checks.
//
// This is the version of the implementation, not of the CDMI
// specification it implements (3.0.0, sent in X-CDMI-Specification-Version).
export const VERSION = "0.127";
