// The error of the key management core, apart from the core so that the
// cryptographic module the core uses can raise it without importing the core.

import { KMIP_ENUM } from "./kmip-registry.ts";

/** A refused operation, with the Result Reason KMIP names for it. */
export class KmsError extends Error {
  readonly reason: string;
  constructor(reason: string, message: string) {
    super(message);
    this.name = "KmsError";
    if (KMIP_ENUM["Result Reason"][reason] === undefined) {
      throw new Error(`KMIP defines no Result Reason named ${JSON.stringify(reason)}`);
    }
    this.reason = reason;
  }
}
