// The transport the Basic Authentication Suite of KMIP Profiles Version 1.4
// (section 3.1) requires of client and server alike: TLS 1.2, the cipher suites
// it lists, and port 5696. Shared by kmip-server.ts and kmip-client.ts.

/** "Conformant KMIP servers SHALL use TCP port number 5696" (Profiles 3.1.4). */
export const KMIP_PORT = 5696;

/**
 * The cipher suites offered, by their OpenSSL names, most preferred first.
 * Each is in the Basic Authentication Suite's list (Profiles 3.1.2): the two
 * it requires, and the forward-secret suites it permits for the RSA and ECDSA
 * certificates a server holds. No TLS 1.3 suite is listed there, so none is
 * offered, and the protocol is TLS 1.2 alone.
 */
export const BASIC_SUITE_CIPHERS = [
  "ECDHE-ECDSA-AES256-GCM-SHA384",   // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (MAY)
  "ECDHE-ECDSA-AES128-GCM-SHA256",   // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (MAY)
  "ECDHE-RSA-AES256-SHA384",         // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (MAY)
  "ECDHE-RSA-AES128-SHA256",         // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (MAY)
  "AES256-SHA256",                   // TLS_RSA_WITH_AES_256_CBC_SHA256 (SHALL)
  "AES128-SHA256",                   // TLS_RSA_WITH_AES_128_CBC_SHA256 (SHALL)
];

/** The TLS protocol the suite requires, and the only one offered. */
export const BASIC_SUITE_PROTOCOL = "TLSv1.2";
