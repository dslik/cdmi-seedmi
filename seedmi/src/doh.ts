// The cdmi_domain_doh domain metadata item: what a client needs to begin
// DNS-SD service discovery over DNS-over-HTTPS (ECR-224A).
//
// The item is a proposed addition to the document and not one revision 365
// defines, so this server accepts it only where [discovery] doh is set. A
// cdmi_ name the document does not give is the document's to give, and 0.83
// withdrew a capability this implementation had invented on exactly that
// ground; the item is admitted here because a change request accompanies it
// and a deployment turns it on deliberately.
//
// Nothing in this file speaks DNS. The item names a resolver a client queries
// and the browsing domains it searches; the records it finds there are put in
// place by seedmi-mdns, which advertises this server on the local link, and by
// seedmi-zone, which publishes what it hears into a real zone.
//
// The validators return the complaint as a string and throw nothing, so that
// the protocol binding can raise the invalid field condition naming the member
// and the configuration reader can raise a ConfigError, each in its own terms.

/** The members of the item, and the only ones. */
export const DOH_MEMBERS = ["resolver", "browse_domains"];

/**
 * What is wrong with a resolver URL, or undefined where nothing is.
 *
 * "resolver is a required, absolute https URI (origin and path). A relative or
 * same-origin value is not permitted" — so that a domain may direct a client to
 * a resolver distinct from the CDMI origin, unambiguously and independently of
 * where the client loaded from.
 *
 * A query is refused as well, which the description does not say and which the
 * change request asks for: a client appends its question to the URL as
 * "?dns=<base64url>" (RFC 8484), and a URL that already carries a query
 * produces something no resolver parses. Leaving that to each client to
 * discover is how one client works and the next does not. A fragment is refused
 * for the same reason and is never sent anywhere. Userinfo is refused because
 * credentials in a URL a server hands to every client of a domain are not
 * credentials.
 */
export function resolverFault(v: unknown): string | undefined {
  if (typeof v !== "string" || v === "") return "the resolver member is a non-empty JSON string";
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    return "the resolver member is an absolute URI, and this is not one";
  }
  if (u.protocol !== "https:") return "the resolver member is an absolute URI of the scheme https";
  if (u.hostname === "") return "the resolver member is an absolute URI with a host";
  if (u.username !== "" || u.password !== "") {
    return "the resolver member carries no userinfo: a credential in a URL a domain hands to " +
      "every client of it is not a credential";
  }
  if (u.search !== "") {
    return "the resolver member carries no query: a client appends its question as " +
      "?dns=<base64url>, and a URL that already holds a query yields one no resolver parses";
  }
  if (u.hash !== "") return "the resolver member carries no fragment, which is never sent";
  return undefined;
}

/**
 * What is wrong with a browsing domain, or undefined where nothing is. A DNS
 * name in lower-case A-label form, with no trailing dot: the name is compared
 * and concatenated by clients ("_cdmi._tcp." + the domain), and a value that
 * differs from another only in case or in a trailing dot is the same domain
 * written twice. "local" is a name of one label and is admitted as it stands.
 */
export function browseDomainFault(v: unknown): string | undefined {
  if (typeof v !== "string" || v === "") return "each browsing domain is a non-empty JSON string";
  if (v.endsWith(".")) return `${JSON.stringify(v)} ends with a dot, and a browsing domain is given without one`;
  if (v.length > 253) return `${JSON.stringify(v)} is longer than a DNS name may be`;
  for (const label of v.split(".")) {
    if (label === "") return `${JSON.stringify(v)} holds an empty label`;
    if (label.length > 63) return `${JSON.stringify(v)} holds a label longer than 63 octets`;
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label)) {
      return `${JSON.stringify(v)} is not a DNS name in lower-case A-label form`;
    }
  }
  return undefined;
}

/**
 * What is wrong with the item, as [member, complaint], or undefined where
 * nothing is. The member is "" where the fault is the item as a whole, and
 * names the member at fault otherwise, so that the invalid field condition
 * addresses metadata/cdmi_domain_doh/<member> and a client that misspells one
 * learns which.
 *
 * A member the item does not define is refused rather than stored and passed
 * over: an item whose misspelt member is kept is an item a client believes it
 * has set.
 */
export function dohItemFault(v: unknown): [string, string] | undefined {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    return ["", "cdmi_domain_doh is a JSON object"];
  }
  const d = v as Record<string, unknown>;
  for (const k of Object.keys(d)) {
    if (!DOH_MEMBERS.includes(k)) return [k, `${JSON.stringify(k)} is not a member of cdmi_domain_doh`];
  }
  if (!("resolver" in d)) return ["resolver", "the resolver member is mandatory"];
  const r = resolverFault(d.resolver);
  if (r !== undefined) return ["resolver", r];
  if ("browse_domains" in d) {
    const b = d.browse_domains;
    // An empty array is refused: omitting the member says the same thing, and
    // two ways to say one thing is two things for a client to handle.
    if (!Array.isArray(b) || b.length === 0) {
      return ["browse_domains", "the browse_domains member is a non-empty array of DNS names"];
    }
    for (const name of b) {
      const f = browseDomainFault(name);
      if (f !== undefined) return ["browse_domains", f];
    }
  }
  return undefined;
}
