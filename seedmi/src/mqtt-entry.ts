// The parts of an MQTT entry that both an export and an import read.
// Kept apart from exports.ts and imports.ts because each imports the
// other, and a value defined in one and read by the other during
// module evaluation is not yet initialised.

import { capabilityNotPresent, invalidField, malformed, fieldPointer} from "./problems.ts";
import { boundReference } from "./credential.ts";

/**
 * The strategies for reconnecting to a broker: a fixed ten seconds, a
 * delay growing by a second to 256, or one doubling to 256. Each is
 * given jitter of a quarter either way.
 */
export const RECONNECT_STRATEGIES = ["fixed", "linear", "exponential"];

/** The MQTT versions this CDMI server negotiates with a broker. */
export const MQTT_VERSIONS = ["3.1.1", "5.0"];

/** The schemes a broker URI may name, and the default port of each. */
const MQTT_SCHEMES: Record<string, number> = {
  mqtt: 1883,
  mqtts: 8883,
  ws: 80,
  wss: 443,
};

/** Where a broker is reached: a scheme, a host and a port. */
export interface BrokerAt {
  scheme: string;
  host: string;
  port: number;
  /** The topic filter, for an import URI, which carries one. */
  topic?: string;
  /** The path of the endpoint, for a WebSocket scheme. */
  endpoint?: string;
}

/**
 * The broker a URI of an export entry names. The form is
 * scheme://host[:port]: an export entry carries the topic in a field
 * of its own, so the URI has no path. The schemes are those the
 * export clause names, which are the two of TCP.
 */
export function parseBrokerURI(field: string, uri: string): BrokerAt {
  const m = /^([a-z]+):\/\/([^/:?#]+)(?::([0-9]+))?([^?#]*)$/.exec(uri);
  if (m === null) {
    throw invalidField(field,
      "the URI of a broker is of the form scheme://host[:port][path], and %j is not",
      uri);
  }
  const [, scheme, host, port, path] = m;
  if (!(scheme in MQTT_SCHEMES)) {
    throw invalidField(field,
      "%j is not a scheme of an MQTT broker: the schemes are %s",
      scheme, Object.keys(MQTT_SCHEMES).join(", "));
  }
  // The path of a ws or wss URI identifies the endpoint of the
  // broker, conventionally "/mqtt". A URI of the two schemes carried
  // over TCP has no path: the topic is a field of the entry.
  const websocket = scheme === "ws" || scheme === "wss";
  if (!websocket && path !== "" && path !== "/") {
    throw invalidField(field,
      "the topic of an export is a field of the entry, and %j carries a path", uri);
  }
  return {
    scheme,
    host,
    port: port === undefined ? MQTT_SCHEMES[scheme] : Number(port),
    ...(websocket ? { endpoint: path === "" ? "/" : path } : {}),
  };
}

/**
 * The broker and topic filter a URI of an import entry names. The
 * form is scheme://host[:port]/topic-filter, and the four schemes
 * include those of a WebSocket. A multi-level wildcard is percent
 * encoded, a "#" introducing the fragment of a URI, and is decoded
 * before the CDMI server subscribes.
 */
export function parseImportURI(field: string, uri: string): BrokerAt {
  // The path identifies the endpoint of the broker and is not the
  // topic filter: a broker reached over a WebSocket has a resource
  // path of its own, conventionally "/mqtt", which this CDMI server
  // requests in the handshake.
  const m = /^([a-z]+):\/\/([^/:?#]+)(?::([0-9]+))?([^?#]*)\?filter=([^#]+)$/.exec(uri);
  if (m === null) {
    throw invalidField(field,
      "%j is not of the form scheme://host[:port]path?filter=topic-filter", uri);
  }
  const [, scheme, host, port, path, filter] = m;
  if (!(scheme in MQTT_SCHEMES)) {
    throw invalidField(field,
      "%j is not a scheme of an MQTT broker: the schemes are %s",
      scheme, Object.keys(MQTT_SCHEMES).join(", "));
  }
  const topic = decodeURIComponent(filter);
  if (topic === "") {
    throw invalidField(field, "%j names no topic filter", uri);
  }
  checkTopic(field, topic, true);
  return {
    scheme,
    host,
    port: port === undefined ? MQTT_SCHEMES[scheme] : Number(port),
    topic,
    ...(path === "" || path === "/" ? {} : { endpoint: path }),
  };
}

/**
 * Checks a topic name or a topic filter. A name carries no wildcard; a
 * filter may carry "+" as a whole level and "#" as its last level.
 */
export function checkTopic(field: string, topic: string, filter: boolean): void {
  if (topic.includes("\u0000")) {
    throw invalidField(field, "a topic shall not contain a null character");
  }
  if (Buffer.byteLength(topic, "utf8") > 65535) {
    throw invalidField(field, "a topic is at most 65535 octets when encoded");
  }
  const levels = topic.split("/");
  for (const [i, level] of levels.entries()) {
    if (!filter) {
      if (level.includes("+") || level.includes("#")) {
        throw invalidField(field,
          "%j is a topic name and carries the wildcard of a topic filter", topic);
      }
      continue;
    }
    if (level.includes("+") && level !== "+") {
      throw invalidField(field,
        'the single-level wildcard "+" occupies a whole level of a topic filter');
    }
    if (level.includes("#")) {
      if (level !== "#" || i !== levels.length - 1) {
        throw invalidField(field,
          'the multi-level wildcard "#" is the last level of a topic filter and ' +
          "occupies the whole of it");
      }
    }
  }
}


/** The TLS settings of a connection to a broker, as a client uses them. */
export interface MqttTls {
  ca?: string;
  cert?: string;
  key?: string;
  rejectUnauthorized?: boolean;
  servername?: string;
  ALPNProtocols?: string[];
  minVersion?: string;
  maxVersion?: string;
  /** The tls_versions sub-field as supplied, which is what a read reports. */
  versions?: string[];
  /**
   * The ca_cert_id sub-field as bound: a Certificate at a key management
   * server that verifies the broker's. Not a TLS option: the certificate is
   * retrieved and given to the connection as ca.
   */
  ca_cert_id?: { kms: string; name: string; scope?: string };
}

/** The TLS versions an entry may name, and what each is called here. */
/**
 * The values of the tls_versions sub-field, and the protocol version of
 * Node's tls module each names. The MQTT export clause: "Permitted values
 * are "tls12" and "tls13"." Before 0.3 seedmi accepted "1.2", "1.3" and
 * Node's own names, refused the two the draft defines, and reported
 * Node's names back.
 */
const TLS_VERSIONS: Record<string, string> = {
  tls12: "TLSv1.2",
  tls13: "TLSv1.3",
};

/**
 * Reads the tls field of an entry. An identifier of a certificate
 * held by a key management server is refused: this CDMI server
 * retrieves nothing from one, and an entry that names a certificate
 * it never presents looks configured and is not.
 */
export function parseTls(at: (f: string) => string, raw: unknown, opts: { kms?: boolean } = {}): MqttTls {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw invalidField(at("tls"), "the tls field is a JSON object");
  }
  const t = raw as Record<string, unknown>;
  const str = (f: string): string | undefined => {
    const v = t[f];
    if (v === undefined) return undefined;
    if (typeof v !== "string") {
      throw invalidField(at(`tls/${f}`), "the %j sub-field is a JSON string", f);
    }
    return v;
  };
  // Revision 196 deletes the sub-fields that carried a certificate or
  // a private key in the entry, and a CDMI server "shall not accept a
  // secret, a private key, or a certificate together with its private
  // key as the value of any field". An entry of the previous edition
  // carrying one "is not accepted" (annex E), so it is refused here
  // rather than accepted with the sub-field ignored, which would
  // silently drop mutual authentication.
  for (const f of ["ca_cert", "client_cert", "client_key"]) {
    if (f in t) {
      throw invalidField(at(`tls/${f}`),
        "the %j sub-field is not defined: a certificate or key is held by a key " +
        "management server and addressed by a credential reference in %j", f, `${f}_id`);
    }
  }
  // The sub-fields that replace them hold credential references, resolved
  // against a key management server; a CDMI server run without one
  // "shall not accept a field that would carry a secret".
  for (const f of ["ca_cert_id", "client_cert_id", "client_key_id"]) {
    if (f in t && opts.kms !== true) {
      throw capabilityNotPresent("cdmi_kms", "/cdmi_capabilities/",
        "the %j sub-field holds a credential reference, and this CDMI server is run " +
        "without a key management server", f);
    }
  }
  // client_key_id "shall be specified where client_cert_id is specified".
  if ("client_cert_id" in t && !("client_key_id" in t)) {
    throw invalidField(at("tls/client_key_id"),
      "client_key_id is specified where client_cert_id is: it addresses the private key of that certificate");
  }
  // Mutual TLS needs the private key to sign in the handshake, and the key is
  // to be operated in place: "requesting the key management server to produce
  // the signature the handshake requires, and shall not retrieve it". The TLS
  // implementation this server uses signs a handshake with a key it holds, and
  // offers no means of having the signature produced elsewhere, so this server
  // cannot authenticate to a broker by certificate. It refuses the fields
  // rather than retrieve the key, which the draft forbids, or ignore them,
  // which would drop the authentication the entry asks for.
  if ("client_cert_id" in t || "client_key_id" in t) {
    throw invalidField(at("client_cert_id" in t ? "tls/client_cert_id" : "tls/client_key_id"),
      "this CDMI server cannot authenticate to a broker by certificate: it cannot have the key " +
      "management server produce the handshake signature, and the key shall not be retrieved");
  }

  const out: MqttTls = {};
  if ("ca_cert_id" in t) {
    // Bound by the binding before the entry is parsed, as password_secret_id is.
    const r = t.ca_cert_id as Record<string, unknown> | null;
    if (r === null || typeof r !== "object" || typeof r.kms !== "string" || typeof r.name !== "string") {
      throw invalidField(at("tls/ca_cert_id"), "the ca_cert_id sub-field holds a credential reference, a JSON object");
    }
    out.ca_cert_id = boundReference(r)!;
  }

  const verify = str("verify_broker") ?? "true";
  if (verify !== "true" && verify !== "false") {
    throw invalidField(at("tls/verify_broker"),
      'the verify_broker sub-field is "true" or "false"');
  }
  out.rejectUnauthorized = verify === "true";

  const sni = str("sni");
  if (sni !== undefined) out.servername = sni;

  if ("tls_versions" in t) {
    const v = t.tls_versions;
    if (!Array.isArray(v) || v.length === 0 ||
      v.some((x) => typeof x !== "string")) {
      throw invalidField(at("tls/tls_versions"),
        "the tls_versions sub-field is a non-empty array of strings");
    }
    // "If no specified values are supported by the CDMI server, the CDMI
    // server shall report the malformed request condition." A value that is
    // not one the clause permits is supported by no server.
    const supported = (v as string[]).filter((x) => TLS_VERSIONS[x] !== undefined);
    if (supported.length === 0) {
      throw malformed("the tls_versions sub-field names no TLS version this CDMI server " +
        'supports: the permitted values are "tls12" and "tls13"')
        .with("cdmi_field", fieldPointer(at("tls/tls_versions")));
    }
    const unknown = (v as string[]).find((x) => TLS_VERSIONS[x] === undefined);
    if (unknown !== undefined) {
      throw invalidField(at("tls/tls_versions"),
        '%j is not a permitted value: the permitted values are "tls12" and "tls13"', unknown);
    }
    const named = supported.map((x) => TLS_VERSIONS[x]).sort();
    out.minVersion = named[0];
    out.maxVersion = named[named.length - 1];
    out.versions = [...new Set(v as string[])];
  }

  if ("alpn_protocols" in t) {
    const v = t.alpn_protocols;
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
      throw invalidField(at("tls/alpn_protocols"),
        "the alpn_protocols sub-field is an array of strings");
    }
    out.ALPNProtocols = v as string[];
  }
  return out;
}

/**
 * Where a filter names a shared subscription under MQTT 5.0, whether it has
 * that version's form, and otherwise undefined. "The topic filter shall conform
 * to the topic filter syntax of every MQTT version named in the protocol field,
 * so that the filter is valid whichever of them is negotiated" (revision 247).
 * A filter beginning "$share/" is an ordinary filter to version 3.1.1 and a
 * shared subscription to version 5.0, which has the form
 * "$share/{ShareName}/{filter}": a share name of at least one character holding
 * no "/", "+" or "#", followed by a filter of at least one character (MQTT
 * Version 5.0, section 4.8.2).
 */
export function sharedSubscriptionProblem(filter: string): string | undefined {
  if (!filter.startsWith("$share/")) return undefined;
  const rest = filter.slice("$share/".length);
  const cut = rest.indexOf("/");
  const share = cut < 0 ? rest : rest.slice(0, cut);
  if (share === "" || /[+#]/.test(share)) {
    return "a shared subscription names a share of at least one character, holding no \"+\" or \"#\"";
  }
  if (cut < 0 || rest.slice(cut + 1) === "") {
    return "a shared subscription is \"$share/\", a share name, \"/\" and a topic filter";
  }
  return undefined;
}
