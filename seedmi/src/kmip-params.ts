// The Cryptographic Parameters structure of KMIP (Table 16): how a request
// names the algorithm, padding, mode and hash an operation is to use.
//
// This is the client's: seedmi encodes these parameters in the requests it
// sends to a key management server, and decodes them where a response carries
// them. The key management server is a separate program (seedmi-kms), and
// nothing of its cryptographic operations is part of seedmi.

import { enumName } from "./kmip-message.ts";
import { child, type Item, k, TYPE } from "./kmip-ttlv.ts";

export interface CryptoParams {
  blockCipherMode?: string;
  paddingMethod?: string;
  hashingAlgorithm?: string;
  digitalSignatureAlgorithm?: string;
  cryptographicAlgorithm?: string;
  randomIV?: boolean;
  ivLength?: number;
  tagLength?: number;
}

const ENUM_FIELDS: [keyof CryptoParams, string][] = [
  ["blockCipherMode", "Block Cipher Mode"], ["paddingMethod", "Padding Method"],
  ["hashingAlgorithm", "Hashing Algorithm"], ["digitalSignatureAlgorithm", "Digital Signature Algorithm"],
  ["cryptographicAlgorithm", "Cryptographic Algorithm"],
];

/** Reads a Cryptographic Parameters structure. */
export function readParams(item: Item | undefined): CryptoParams {
  const p: CryptoParams = {};
  if (item === undefined) return p;
  for (const [key, name] of ENUM_FIELDS) {
    const f = child(item, name);
    if (f?.type === TYPE.Enumeration) (p as Record<string, unknown>)[key] = enumName(name, f.value);
  }
  const random = child(item, "Random IV");
  if (random?.type === TYPE.Boolean) p.randomIV = random.value;
  const iv = child(item, "IV Length");
  if (iv?.type === TYPE.Integer) p.ivLength = iv.value;
  const tag = child(item, "Tag Length");
  if (tag?.type === TYPE.Integer) p.tagLength = tag.value;
  return p;
}

/** A Cryptographic Parameters structure of the fields given, in the order of Table 65. */
export function writeParams(p: CryptoParams): Item {
  return k.struct("Cryptographic Parameters", [
    ...(p.blockCipherMode ? [k.enum("Block Cipher Mode", "Block Cipher Mode", p.blockCipherMode)] : []),
    ...(p.paddingMethod ? [k.enum("Padding Method", "Padding Method", p.paddingMethod)] : []),
    ...(p.hashingAlgorithm ? [k.enum("Hashing Algorithm", "Hashing Algorithm", p.hashingAlgorithm)] : []),
    ...(p.digitalSignatureAlgorithm
      ? [k.enum("Digital Signature Algorithm", "Digital Signature Algorithm", p.digitalSignatureAlgorithm)] : []),
    ...(p.cryptographicAlgorithm
      ? [k.enum("Cryptographic Algorithm", "Cryptographic Algorithm", p.cryptographicAlgorithm)] : []),
    ...(p.randomIV === undefined ? [] : [k.bool("Random IV", p.randomIV)]),
    ...(p.ivLength === undefined ? [] : [k.int("IV Length", p.ivLength)]),
    ...(p.tagLength === undefined ? [] : [k.int("Tag Length", p.tagLength)]),
  ]);
}
