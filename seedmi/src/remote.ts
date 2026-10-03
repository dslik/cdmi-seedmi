// The import source of a remote CDMI import: a container object held by
// another CDMI server, reached over HTTP through its protocol binding.
//
// A local import presents the same objects at a second position and
// issues no request; a remote import fetches a representation. What this
// module provides is the same three things the store and the FAT driver
// provide, so that the layering engine can treat all three alike: the
// names a container holds, the fields of an object, and the bytes of a
// value.
//
// Representations are held for a short time. Without that, one listing
// of a container would fetch the representation of every child, and a
// walk down a path would fetch each container twice.

import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { checkRedirection, originatedPolicy, OriginatedError, resolveAndCheck } from "./originated.ts";

export class RemoteError extends Error {
  /** The status the remote server returned, where it returned one. */
  status?: number;
  /** The response exceeded the size this server reads (the limit exceeded condition). */
  limit?: boolean;
  constructor(message: string, status?: number) {
    super(message);
    this.status = status;
  }
}

/** The fields of an object as another CDMI server reports them. */
export interface RemoteRep {
  objectType: string;
  objectID?: string;
  objectName?: string;
  mimetype?: string;
  valuetransferencoding?: string;
  metadata: Record<string, unknown>;
  children?: string[];
  childrenrange?: string;
  /**
   * The size of a data object's value where the source states no cdmi_size:
   * the length of the value, read whole. See rep().
   */
  derivedSize?: number;
}

export const MT_OBJECT = "application/cdmi-object";
export const MT_CONTAINER = "application/cdmi-container";

interface Cached {
  rep: RemoteRep;
  at: number;
}

export interface RemoteOptions {
  /** The value of the Authorization header field, where one is presented. */
  authorization?: string;
  /** How long a representation is held, in milliseconds. */
  ttl?: number;
  timeout?: number;
}

/**
 * One import source. The base is the absolute URI of the container
 * object imported, ending in a solidus, and every path is relative to
 * it.
 */
export class RemoteSource {
  /**
   * The objects of this source not presented, by path, each with the problem
   * recorded for it: an object whose access control list names a mask bit or flag
   * this server does not support (revision 269; layers.ts).
   */
  readonly declined = new Map<string, { type: string; title: string; detail: string }>();
  readonly base: string;
  private readonly opts: Required<RemoteOptions>;
  private readonly cache = new Map<string, Cached>();

  constructor(base: string, opts: RemoteOptions = {}) {
    this.base = base.endsWith("/") ? base : base + "/";
    this.opts = {
      authorization: opts.authorization ?? "",
      ttl: opts.ttl ?? 2000,
      timeout: opts.timeout ?? 5000,
    };
  }

  /** Forgets everything held, which a test does between requests. */
  forget(): void {
    this.cache.clear();
  }

  /**
   * The representation of the object at a path relative to the base. A
   * path ending in a solidus names a container object.
   */
  async rep(path: string, opts: { complete?: boolean } = {}): Promise<RemoteRep> {
    const key = opts.complete === true ? `\u0000complete\u0000${path}` : path;
    const held = this.cache.get(key);
    if (held && Date.now() - held.at < this.opts.ttl) return held.rep;

    const isContainer = path === "" || path.endsWith("/");
    // The value is not asked for: a listing needs the other fields, and
    // a value is fetched in ranges when it is read.
    // The fields of a selection are separated by "&", as the HTTP
    // protocol binding requires.
    //
    // A selection names the fields it wants, and cannot name a field whose
    // name it does not know: the extension fields of the source are
    // therefore not in a selected representation. A copy asks for the
    // complete representation instead, which carries them and which carries
    // no value for a data object. This server copied from a selected
    // representation, so "an extension field of the source object is carried
    // to the object created" was implemented against a representation that
    // never contained one (weedmi OPER-051, open since 0.74 and reported
    // fixed in 0.71).
    const query = opts.complete === true
      ? ""
      : isContainer
      ? "?objectType&objectID&objectName&metadata&children&childrenrange"
      : "?objectType&objectID&objectName&mimetype&valuetransferencoding&metadata";
    const { status, body, type } = await this.get(path + query,
      isContainer ? MT_CONTAINER : MT_OBJECT);
    if (status === 404) throw new RemoteError(`${this.base}${path} is not there`, 404);
    if (status === 401 || status === 403) {
      throw new RemoteError(`the import source refused the credential presented (${status})`,
        status);
    }
    if (status !== 200) {
      throw new RemoteError(`the import source answered ${status}`, status);
    }
    let rep: RemoteRep;
    try {
      rep = JSON.parse(body.toString("utf8")) as RemoteRep;
    } catch {
      throw new RemoteError("the import source returned a representation that is not JSON");
    }
    if (typeof rep !== "object" || rep === null) {
      throw new RemoteError("the import source returned no representation");
    }
    rep.metadata = (rep.metadata ?? {}) as Record<string, unknown>;
    if (rep.objectType === undefined) rep.objectType = type;
    // cdmi_size is storage system metadata, which READ_ATTRIBUTES governs, and
    // a source withholds it from a principal it admits to the value alone. The
    // size is then the value's length, read whole: it tells the principal
    // nothing the value it may read does not. Before 0.58 a missing size was
    // taken as zero, the value never fetched, and the object presented as empty.
    if (!isContainer && typeof rep.metadata.cdmi_size !== "string") {
      const whole = await this.get(`${path}?value&valuetransferencoding`, MT_OBJECT);
      if (whole.status === 200) {
        try {
          const v = JSON.parse(whole.body.toString("utf8")) as { value?: unknown; valuetransferencoding?: string };
          if (typeof v.value === "string") {
            rep.derivedSize = Buffer.from(v.value, v.valuetransferencoding === "base64" ? "base64" : "utf8").length;
          }
        } catch { /* no size is derived */ }
      }
    }
    this.cache.set(key, { rep, at: Date.now() });
    return rep;
  }

  /** The names a container holds, as its children field reports them. */
  /**
   * Deletes an object at the other CDMI server, which is the second
   * half of a move from one. The cached representation of the object
   * is discarded, since it names something that is no longer there.
   */
  async remove(path: string): Promise<void> {
    const { status } = await this.request("DELETE", path,
      path.endsWith("/") ? MT_CONTAINER : MT_OBJECT);
    if (status !== 204 && status !== 200) {
      throw new RemoteError(
        `a delete of ${this.base}${path} answered ${status}`, status);
    }
    this.cache.delete(path);
  }

  async children(path: string): Promise<string[]> {
    const rep = await this.rep(path);
    if (rep.objectType !== MT_CONTAINER) {
      throw new RemoteError(`${this.base}${path} is not a container object`);
    }
    return rep.children ?? [];
  }

  /** A range of the value of a data object. */
  async value(path: string, offset: number, length: number): Promise<Buffer> {
    if (length <= 0) return Buffer.alloc(0);
    const last = offset + length - 1;
    const { status, body } = await this.get(`${path}?value=${offset}-${last}`, MT_OBJECT);
    if (status !== 200) {
      if (status === 416) return Buffer.alloc(0); // past the end of the value
      throw new RemoteError(`a read of ${this.base}${path} answered ${status}`, status);
    }
    let rep: { value?: string; valuetransferencoding?: string };
    try {
      rep = JSON.parse(body.toString("utf8"));
    } catch {
      throw new RemoteError("the import source returned a value that is not JSON");
    }
    if (typeof rep.value !== "string") return Buffer.alloc(0);
    // A range of a value is always transported as base 64, since a range
    // need not be valid UTF-8.
    return Buffer.from(rep.value, rep.valuetransferencoding === "utf-8" ? "utf8" : "base64");
  }

  /** Whether the source answers at all, which establishes the import. */
  async reachable(): Promise<void> {
    await this.rep("");
  }

  private get(rel: string, accept: string): Promise<{
    status: number;
    body: Buffer;
    type: string;
  }> {
    return this.request("GET", rel, accept);
  }

  /**
   * One request to the import source. Every request this method makes is a
   * server-originated request, and originated.ts governs it: the URI is
   * permitted, the address resolved is permitted and is the address connected
   * to, the wait and the response read are limited, and only a permitted
   * redirection is followed. A failure names no address, no network-layer
   * reason and no timing.
   */
  private async request(method: string, rel: string, accept: string): Promise<{
    status: number;
    body: Buffer;
    type: string;
  }> {
    const policy = originatedPolicy();
    let target = new URL(rel, this.base).toString();
    for (let followed = 0; ; followed++) {
      const answer = await this.once(method, target, accept, policy);
      if (answer.location === undefined) return answer;
      // "the CDMI server shall determine that each URI to which it is
      // redirected is permitted" and "shall not follow more redirections than
      // it is configured to follow".
      try {
        target = checkRedirection(target, answer.location, followed, policy);
      } catch (e) {
        throw new RemoteError(e instanceof OriginatedError ? `${this.base} could not be reached` : String(e));
      }
    }
  }

  private async once(method: string, target: string, accept: string,
    policy: ReturnType<typeof originatedPolicy>): Promise<{
      status: number; body: Buffer; type: string; location?: string;
    }> {
    const url = new URL(target);
    const secure = url.protocol === "https:";
    let resolved;
    try {
      resolved = await resolveAndCheck(target, policy);
    } catch {
      throw new RemoteError(`${this.base} could not be reached`);
    }
    const headers: Record<string, string> = {
      Accept: accept,
      "X-CDMI-Specification-Version": "3.0.0",
      // The connection is made to the address checked, so the authority is
      // carried in the Host header field rather than resolved a second time.
      Host: url.host,
    };
    if (this.opts.authorization !== "") headers.Authorization = this.opts.authorization;
    const limit = policy.maxResponseBytes;
    return new Promise((resolve, reject) => {
      const req = (secure ? httpsRequest : httpRequest)({
        protocol: url.protocol,
        hostname: resolved.address,
        ...(secure ? { servername: url.hostname } : {}),
        port: url.port === "" ? undefined : Number(url.port),
        path: url.pathname + url.search,
        method,
        headers,
      }, (res: {
        statusCode: number;
        headers: Record<string, string>;
        on: (e: string, f: (c?: Buffer) => void) => void;
        destroy: () => void;
      }) => {
        const chunks: Buffer[] = [];
        let read = 0;
        let stopped = false;
        res.on("data", (c?: Buffer) => {
          if (stopped) return;
          const chunk = c as Buffer;
          read += chunk.length;
          if (read > limit) {
            stopped = true;
            res.destroy();
            const e = new RemoteError(`${this.base} returned more than this server reads`);
            e.limit = true;
            reject(e);
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          if (stopped) return;
          const status = res.statusCode;
          const location = status >= 300 && status < 400 ? String(res.headers.location ?? "") : undefined;
          resolve({
            status,
            body: Buffer.concat(chunks),
            type: String(res.headers["content-type"] ?? "").split(";")[0],
            ...(location === undefined || location === "" ? {} : { location }),
          });
        });
      });
      req.setTimeout(Math.min(this.opts.timeout, policy.timeoutMs), () => {
        req.destroy();
        // Neither the time taken nor the reason is reported.
        reject(new RemoteError(`${this.base} could not be reached`));
      });
      req.on("error", () => reject(new RemoteError(`${this.base} could not be reached`)));
      req.end();
    });
  }
}

/**
 * The sources opened, by base URI and credential, so that the
 * representations one holds are shared between requests.
 */
const sources = new Map<string, RemoteSource>();

export function remoteSource(base: string, opts: RemoteOptions = {}): RemoteSource {
  const key = `${base}\u0000${opts.authorization ?? ""}`;
  let src = sources.get(key);
  if (!src) {
    src = new RemoteSource(base, opts);
    sources.set(key, src);
  }
  return src;
}

export function forgetRemoteSources(): void {
  sources.clear();
}
