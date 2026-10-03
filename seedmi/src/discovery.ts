/**
 * The fields of a reference, which are what an extended listing of the
 * discovery namespace may name. "location: the destination of a child that
 * is a reference, as the CDMI client that created it supplied it", and "a
 * CDMI client reads a destination as stored from the location field of an
 * extended child listing of the parent container object of the reference,
 * since that field is the only place a destination is reported as stored."
 * A field a reference does not have is reported as null, as the binding's
 * own extended listing reports one.
 */
const REFERENCE_FIELDS = ["objectName", "location"];

/**
 * The fields an extended child listing may name at all. A child of the
 * discovery namespace is a reference, so only those of REFERENCE_FIELDS
 * carry a value; the rest are answered as null.
 */
const DEFINED_CHILD_FIELDS = [
  "objectType", "objectID", "objectName", "parentURI", "parentID", "domainURI",
  "capabilitiesURI", "completionStatus", "percentComplete", "mimetype", "metadata",
  "location", "reference",
];

/** The fields an extended child selection names, where the query has one. */
function extendedFields(query: string): string[] | undefined {
  for (const part of query.replace(/^\?/, "").split("&")) {
    if (part === "childfields") return [];
    if (part.startsWith("childfields=")) {
      return part.slice("childfields=".length).split(";").filter((f) => f !== "");
    }
  }
  return undefined;
}

// The discovery tree at "/.well-known/cdmi/", by which a CDMI client
// that knows only an origin finds the base URIs a CDMI server offers and
// the capabilities of that server.
//
// It is a property of the origin rather than of a base URI: it appears
// immediately after the authority and is not relative to any base URI,
// and one server serving several base URIs at one origin serves one
// tree for all of them. Nothing beneath it may be changed.
//
// Two things make this awkward enough to be worth its own module. The
// capability hierarchy is reachable here as well as at its namespace
// path, and the fields of a capability object read here must be the
// ones it has at that path, so the prefix is a second door and not a
// relocation. And the namespaces tree depends on the requesting
// principal, since a base URI is listed only where that principal may
// read the root container object it addresses.

import type { IncomingMessage, ServerResponse } from "node:http";
import { answerListenerPreflight, isPreflight, listenerCorsOrVary, originOf } from "./cors.ts";
import type { Store } from "./store.ts";
import { M, granted, type Principal } from "./acl.ts";
import { notFound } from "./problems.ts";

export const WELL_KNOWN = "/.well-known/cdmi/";

export const MT_CONTAINER = "application/cdmi-container";

/** A base URI this server offers, and the store behind it. */
export interface Namespace {
  /**
   * Whether a CDMI export established this base URI, in which case its
   * origin is the entry's rather than the host this server is configured
   * with, and the host filter does not apply to it (revision 327).
   */
  exported?: boolean;
  /** The name of the reference within the namespaces tree. */
  name: string;
  /** The absolute base URI, which ends with a solidus. */
  uri: string;
  /** The store whose root container object that base URI addresses. */
  store: Store;
}

export interface DiscoveryOptions {
  namespaces: () => Namespace[];
  /**
   * The capability object at a namespace path, as the protocol binding
   * serves it. The discovery tree returns what this returns, so that
   * the two doors agree.
   */
  capability: (ns: string) => Record<string, unknown> | undefined;
  /** The principal of a request, resolved as the binding resolves it. */
  principal: (req: IncomingMessage) => Principal;
  /**
   * The host this deployment is reached at, as it is configured: "The
   * destination of a reference within this container object shall be a base
   * URI whose host is the host of the origin that serves the discovery tree,
   * at any scheme and port that host serves. A CDMI server shall not report a
   * base URI at another host ... The host a CDMI server reports in a base URI
   * is configured on the CDMI server, and is not taken from the Host header
   * field of the request, so that a request naming a host the CDMI server does
   * not serve does not cause it to report a base URI at that host" (revision
   * 297). Where it is not configured, every base URI configured is listed, and
   * an operator that configures base URIs at several hosts is told.
   */
  host?: () => string | undefined;
  /**
   * The origins a browser-based client may present.
   *
   * This tree is a property of the origin and not of an object, so the three
   * data system metadata items that configure cross-origin sharing for an
   * object cannot configure it: there is no object to set them on. It carried
   * no cross-origin field and answered no preflight until 0.93, so a browser
   * withheld it from the page — and this tree exists for "a CDMI client that
   * knows only an origin", which is exactly what a page in a browser is.
   *
   * The default is the wildcard. Everything here is a document this tree
   * serves to any client that knows the origin, by design and without
   * authentication; what the base URIs it lists then admit is decided by the
   * access control lists of the objects, as for any other route to them.
   */
  origins?: () => string[];
}

export class Discovery {
  private readonly opts: DiscoveryOptions;

  constructor(opts: DiscoveryOptions) {
    this.opts = opts;
  }

  /** Whether a request addresses the discovery tree. */
  static addresses(path: string): boolean {
    return path === WELL_KNOWN.replace(/\/$/, "") || path.startsWith(WELL_KNOWN);
  }

  /**
   * Answers a request beneath the well-known path prefix. Returns false
   * where the request is not one this tree answers, so that the caller
   * may report it as it reports any other.
   */
  serve(req: IncomingMessage, res: ServerResponse, path: string, query: string): boolean {
    const method = req.method ?? "GET";
    const permitted = this.opts.origins?.() ?? ["*"];
    if (method === "OPTIONS") {
      // A preflight, where the request is one: a browser asks before a GET
      // carrying a header field that is not safelisted, and a bare Allow told
      // it nothing about whether it might read the answer.
      if (isPreflight(req)) {
        answerListenerPreflight(permitted, req, res, {
          methods: ["GET", "HEAD", "OPTIONS"],
          headers: ["Accept", "Authorization", "Content-Type", "X-CDMI-Specification-Version"],
        });
        return true;
      }
      res.writeHead(204, { Allow: "GET, HEAD, OPTIONS" });
      res.end();
      return true;
    }
    // The fields that let a browser make the answer available to the page. Set
    // here, before any of the answers below, so that every one of them carries
    // them — including the 405 and the redirect.
    for (const [k, v] of Object.entries(listenerCorsOrVary(permitted, originOf(req),
      { cookie: req.headers.cookie !== undefined }))) {
      res.setHeader(k, v);
    }
    if (method !== "GET" && method !== "HEAD") {
      // The discovery tree and everything beneath it is read only.
      res.writeHead(405, {
        Allow: "GET, HEAD, OPTIONS",
        "Content-Length": "0",
      });
      res.end();
      return true;
    }
    const head = method === "HEAD";

    if (path === WELL_KNOWN.replace(/\/$/, "")) {
      // The prefix without its trailing solidus.
      res.writeHead(301, { Location: WELL_KNOWN, "Content-Length": "0" });
      res.end();
      return true;
    }
    const rest = path.slice(WELL_KNOWN.length);

    if (rest === "") return this.tree(res, head);
    if (rest === "cdmi_capabilities/" || rest.startsWith("cdmi_capabilities/")) {
      return this.capabilities(res, rest, query, head);
    }
    if (rest === "cdmi_namespaces/") return this.namespaces(req, res, head, query);
    if (rest.startsWith("cdmi_namespaces/")) {
      return this.reference(req, res, rest.slice("cdmi_namespaces/".length));
    }
    // No other child is served.
    this.fail(res, head);
    return true;
  }

  /** The discovery tree itself, which has exactly two children. */
  private tree(res: ServerResponse, head: boolean): boolean {
    this.json(res, 200, MT_CONTAINER, {
      objectType: MT_CONTAINER,
      objectName: "cdmi/",
      parentURI: "",
      // An object of the discovery tree is not held within the
      // namespace of a base URI, so its capabilitiesURI is beneath
      // this prefix: a namespace path could not be resolved by a
      // client that has not yet obtained a base URI.
      capabilitiesURI: `${WELL_KNOWN}cdmi_capabilities/container/`,
      completionStatus: "Complete",
      metadata: {},
      childrenrange: "0-1",
      children: ["cdmi_capabilities/", "cdmi_namespaces/"],
    }, { "Cache-Control": "public, max-age=3600" }, head);
    return true;
  }

  /**
   * The capability hierarchy, reachable here as well as at its
   * namespace path. The fields are the ones the object has at that
   * path: this prefix is an additional means of access and does not
   * relocate the hierarchy.
   */
  private capabilities(res: ServerResponse, rest: string, query: string,
    head: boolean): boolean {
    const ns = "/" + rest;
    const rep = this.opts.capability(ns);
    if (!rep) {
      this.fail(res, head);
      return true;
    }
    const body = query === "capabilities" && rep.capabilities !== undefined
      ? { capabilities: rep.capabilities }
      : rep;
    // A capability object is readable by a client that has not
    // authenticated, so that it may determine the authentication
    // methods this server accepts before it authenticates.
    this.json(res, 200, "application/cdmi-capability", body,
      { "Cache-Control": "public, max-age=3600" }, head);
    return true;
  }

  /**
   * The base URIs this server offers to the requesting principal, as a
   * container object whose children are references. A base URI is
   * listed only where that principal may read the root container object
   * it addresses, so the listing differs between principals.
   */
  private namespaces(req: IncomingMessage, res: ServerResponse, head: boolean,
    query = ""): boolean {
    const who = this.opts.principal(req);
    const offered = this.readable(who);
    // "A GET request for /.well-known/cdmi/cdmi_namespaces/ shall return the
    // representation of a container object whose children are references":
    // a container object's representation, so a child selection applies to
    // it. An extended child selection was ignored before 0.78, and a CDMI
    // client that asked for fields received plain names (cvwm).
    const fields = extendedFields(query);
    if (fields !== undefined) {
      // A field this document defines that a reference does not have is
      // answered as null rather than refused; a name that is no field at
      // all is the invalid selection condition.
      const bad = fields.filter((f) => !DEFINED_CHILD_FIELDS.includes(f));
      if (bad.length > 0) {
        this.json(res, 400, "application/problem+json", {
          type: "https://www.snia.org/cdmi/problems/invalid-selection",
          title: "A selection is invalid.",
          detail: `${bad.join(", ")} is not a field this document defines; the children of ` +
            `the discovery namespace are references, which carry ${REFERENCE_FIELDS.join(" and ")}`,
        }, {}, head);
        return true;
      }
      // An extended listing answers an array for each child, of the fields
      // named and in that order, as the binding's does.
      const children = offered.map((n) => fields.map((f) =>
        f === "objectName" ? `${n.name}?` : f === "location" ? n.uri : null));
      this.json(res, 200, MT_CONTAINER, {
        objectType: MT_CONTAINER,
        objectName: "cdmi_namespaces/",
        parentURI: "",
        capabilitiesURI: `${WELL_KNOWN}cdmi_capabilities/container/`,
        completionStatus: "Complete",
        childrenrange: children.length === 0 ? "" : `0-${children.length - 1}`,
        children,
      }, {}, head);
      return true;
    }
    this.json(res, 200, MT_CONTAINER, {
      objectType: MT_CONTAINER,
      objectName: "cdmi_namespaces/",
      parentURI: "",
      capabilitiesURI: `${WELL_KNOWN}cdmi_capabilities/container/`,
      completionStatus: "Complete",
      metadata: {},
      childrenrange: offered.length === 0 ? "" : `0-${offered.length - 1}`,
      // A reference is listed with a trailing question mark.
      children: offered.map((n) => `${n.name}?`),
    }, this.privately(), head);
    return true;
  }

  /** Following a reference: the base URI it addresses. */
  private reference(req: IncomingMessage, res: ServerResponse, name: string): boolean {
    const who = this.opts.principal(req);
    const wanted = name.replace(/\?$/, "");
    const found = this.readable(who).find((n) => n.name === wanted);
    if (!found) {
      this.fail(res, false);
      return true;
    }
    // The children of the namespaces tree are references, and a
    // reference is answered as the HTTP binding requires, which from
    // revision 196 is 307. The sentence of the discovery subclause
    // still naming "302 Found" defers to that rule ("as required by"),
    // and is recorded as stale in ECR-044A.
    res.writeHead(307, {
      Location: found.uri,
      "Content-Length": "0",
      ...this.privately(),
    });
    res.end();
    return true;
  }

  /**
   * The namespaces whose root container object the principal may read.
   * A client that has not authenticated receives those readable by
   * ANONYMOUS@, which may be none: an empty listing rather than a
   * status code that would report whether the client is known.
   */
  private readable(who: Principal): Namespace[] {
    const host = this.opts.host?.();
    return this.opts.namespaces().filter((n) => {
      // A base URI at another host is not reported, whatever its access
      // control says: this tree describes the deployment reached at this
      // host. A base URI a CDMI export established is exempt: its origin
      // is the one its entry names, which is deliberately not the host
      // this server is configured with (revision 327).
      if (host !== undefined && n.exported !== true) {
        let at: string | undefined;
        try {
          at = new URL(n.uri).hostname.replace(/^\[|\]$/g, "");
        } catch {
          at = undefined;
        }
        if (at === undefined || at.toLowerCase() !== host.toLowerCase()) return false;
      }
      try {
        const root = n.store.root();
        const m = n.store.meta(root);
        // "A CDMI server shall list a base URI in this container object only
        // where the requesting principal is permitted to list the children of
        // the root container object addressed by it" (revision 297): reading
        // its metadata was enough before 0.63, so a principal that could read
        // the root container object but not list it was shown the base URI.
        return granted(m.acl, who, M.LIST_CONTAINER, {
          owner: m.owner,
          group: m.group,
          isContainer: true,
          isRoot: true,
        });
      } catch {
        return false;
      }
    });
  }

  /**
   * The header fields a response that depends on the principal carries.
   *
   * Origin is named beside Authorization because the cross-origin fields differ
   * by it, so a cache must not hand a response prepared for one origin to a
   * request from another. Naming Authorization alone here replaced the Vary set
   * for the cross-origin fields, since this is spread into the header block
   * rather than added to it — which is the kind of thing that is invisible
   * until a cache in front of the server serves one origin's answer to another.
   */
  private privately(): Record<string, string> {
    return { "Cache-Control": "private, no-store", Vary: "Authorization, Origin" };
  }

  private fail(res: ServerResponse, head: boolean): void {
    const problem = notFound("no such child of the discovery tree");
    const body = Buffer.from(JSON.stringify({
      type: problem.type,
      title: problem.title,
      detail: problem.detail,
    }, null, 2) + "\n");
    res.writeHead(404, {
      "Content-Type": "application/problem+json",
      "Content-Length": String(body.length),
    });
    res.end(head ? undefined : body);
  }

  private json(res: ServerResponse, status: number, type: string, body: unknown,
    headers: Record<string, string>, head: boolean): void {
    const text = Buffer.from(JSON.stringify(body, null, 2) + "\n");
    res.writeHead(status, {
      "Content-Type": type,
      "Content-Length": String(text.length),
      ...headers,
    });
    res.end(head ? undefined : text);
  }
}
