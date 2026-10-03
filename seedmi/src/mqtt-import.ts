// Enqueuing to a queue object the messages of an MQTT topic.
//
// An import subscribes to the topic filter its entry names and
// enqueues each message it receives. The layering of a namespace
// import does not apply: a queue object holds an ordered sequence of
// values and not a namespace, so an import here adds values rather
// than presenting objects.

import { createHash } from "node:crypto";
import { tlsOptions } from "./mqtt-export.ts";
import { MqttClient, MqttRefused } from "./mqtt-client.ts";
import { MqttError, PROPERTY } from "./mqtt-wire.ts";
import type { Node, Store } from "./store.ts";
import { cdmiTime, type Problem, problem, seedmiProblem } from "./problems.ts";
import { parseImportURI } from "./mqtt-entry.ts";
import type { ImportEntry } from "./imports.ts";

/** What an import entry reports of its connection. */
export interface MqttImportState {
  connected: boolean;
  enqueued: number;
  dropped: number;
  problems: Problem[];
}

/** One import: an entry, its connection, and what it has enqueued. */
class Running {
  readonly key: string;
  entry: ImportEntry;
  readonly node: Node;
  client?: MqttClient;
  enqueued = 0;
  dropped = 0;
  problems: Problem[] = [];
  /** Whether the credential was found compromised; no connection is made with it again. */
  compromised = false;
  attempts = 0;
  timer?: ReturnType<typeof setTimeout>;
  closed = false;
  /** The timer resolving the credentials again at the entry's refresh_interval. */
  refresher?: ReturnType<typeof setInterval>;
  refreshing = false;
  /** The credential the connection was made with: its identifier and a digest of its value. */
  credential?: string;
  secretDigest?: string;
  /**
   * The packet identifiers of the messages enqueued, so that a
   * delivery the broker marks as a duplicate of one already enqueued
   * is not enqueued a second time.
   */
  readonly seen = new Set<number>();

  constructor(key: string, entry: ImportEntry, node: Node) {
    this.key = key;
    this.entry = entry;
    this.node = node;
  }
}

export interface MqttImporterOptions {
  store: Store;
  /** Whether to connect at all. */
  connect?: boolean;
  timeout?: number;
  /**
   * Retrieves the password an entry's password_secret_id addresses, each time
   * a connection is made, as an export's is.
   */
  resolvePassword?: (node: Node, reference: { kms: string; name: string; scope?: string }) =>
    Promise<{ id: string; octets: Buffer }>;
  /** Retrieves the certificate an entry's tls.ca_cert_id addresses, in PEM. */
  resolveCertificate?: (node: Node, reference: { kms: string; name: string; scope?: string }) =>
    Promise<{ id: string; pem: string }>;
}

export class MqttImporter {
  private readonly opts: MqttImporterOptions;
  private readonly running = new Map<string, Running>();

  constructor(opts: MqttImporterOptions) {
    this.opts = opts;
  }

  get connecting(): boolean {
    return this.opts.connect === true;
  }

  /**
   * An import entry is named by the object it is placed on and its
   * position, a queue object being permitted more than one.
   */
  static keyOf(node: Node, index: number): string {
    return `${node.id}:${index}`;
  }

  offer(key: string, entry: ImportEntry, node: Node): void {
    const held = this.running.get(key);
    if (held !== undefined) {
      if (JSON.stringify(held.entry) === JSON.stringify(entry)) return;
      this.withdraw(key);
    }
    const now = new Running(key, entry, node);
    this.running.set(key, now);
    if (!this.connecting) return;
    void this.open(now);
  }

  withdraw(key: string): void {
    const held = this.running.get(key);
    if (held === undefined) return;
    held.closed = true;
    if (held.timer !== undefined) clearTimeout(held.timer);
    if (held.refresher !== undefined) clearInterval(held.refresher);
    held.client?.disconnect();
    this.running.delete(key);
  }

  /** Withdraws every import of an object, for an entry list replaced. */
  withdrawAllOf(node: Node): void {
    for (const key of [...this.running.keys()]) {
      if (key.startsWith(`${node.id}:`)) this.withdraw(key);
    }
  }

  offered(): string[] {
    return [...this.running.keys()];
  }

  state(key: string): MqttImportState | undefined {
    const held = this.running.get(key);
    if (held === undefined) return undefined;
    return {
      connected: held.client?.connected === true,
      enqueued: held.enqueued,
      dropped: held.dropped,
      problems: held.problems,
    };
  }

  close(): void {
    for (const key of [...this.running.keys()]) this.withdraw(key);
  }

  // -------------------------------------------------------------------

  private async open(held: Running): Promise<void> {
    if (held.closed || held.client !== undefined || held.compromised) return;
    const e = held.entry;
    let at;
    try {
      at = parseImportURI("import_uri", e.import_uri ?? "");
    } catch (err) {
      held.problems = [problem("imports/mqtt/broker-unreachable",
        "The MQTT broker cannot be reached.", String(err))];
      return;
    }
    // The password is retrieved from the key management server each time a
    // connection is made, and again at the entry's refresh_interval (revision
    // 269; before 0.61 the draft gave an import none).
    let password: string | undefined;
    if (e.password_secret_id !== undefined) {
      try {
        if (this.opts.resolvePassword === undefined) throw new Error("no key management server is reachable");
        const got = await this.opts.resolvePassword(held.node, e.password_secret_id);
        password = got.octets.toString("utf8");
        held.credential = got.id;
        held.secretDigest = createHash("sha256").update(got.octets).digest("hex");
      } catch (err) {
        const c = err as { type?: string; title?: string; detail?: string; message?: string };
        held.problems = [{
          type: c.type ?? "https://www.snia.org/cdmi/problems/kms/credential-unavailable",
          title: c.title ?? "The credential is unavailable.",
          detail: c.detail ?? c.message ?? String(err),
        }];
        if (/credential-compromised$/.test(held.problems[0].type)) held.compromised = true;
        else this.again(held);
        return;
      }
      if (held.closed) return;
    }
    // The import's tls takes the export's form, ca_cert_id included.
    let ca: string | undefined;
    if (e.tls?.ca_cert_id !== undefined) {
      try {
        if (this.opts.resolveCertificate === undefined) throw new Error("no key management server is reachable");
        ca = (await this.opts.resolveCertificate(held.node, e.tls.ca_cert_id)).pem;
      } catch (err) {
        const c = err as { type?: string; title?: string; detail?: string; message?: string };
        held.problems = [{
          type: c.type ?? "https://www.snia.org/cdmi/problems/kms/credential-unavailable",
          title: c.title ?? "The credential is unavailable.",
          detail: c.detail ?? c.message ?? String(err),
        }];
        if (/credential-compromised$/.test(held.problems[0].type)) held.compromised = true;
        else this.again(held);
        return;
      }
      if (held.closed) return;
    }
    const client = new MqttClient({
      host: at.host,
      port: at.port,
      ...(password === undefined ? {} : { password }),
      // The first of the versions offered is the one attempted first.
      version: e.mqttProtocol?.[0] ?? "3.1.1",
      clientID: e.client_id ?? "seedmi-import",
      keepAlive: Number(e.keep_alive_interval ?? "60"),
      cleanStart: (e.clean_session ?? "true") === "true",
      ...(e.username === undefined ? {} : { username: e.username }),
      ...(e.tls === undefined ? {} : { tls: tlsOptions(e.tls, ca) }),
      ...(at.scheme === "ws" || at.scheme === "wss"
        ? {
          websocket: { endpoint: at.endpoint ?? "/", secure: at.scheme === "wss" },
        }
        : {}),
      ...(this.opts.timeout === undefined ? {} : { timeout: this.opts.timeout }),
      onMessage: (m) => this.arrived(held, m),
    });
    held.client = client;
    try {
      await client.connect();
      await client.subscribe([{ filter: at.topic ?? "", qos: Number(e.qos ?? "0") }]);
      held.attempts = 0;
      held.problems = [];
      this.startRefreshing(held);
    } catch (err) {
      held.client = undefined;
      client.close();
      held.problems = [problem("imports/mqtt/broker-unreachable",
        "The MQTT broker cannot be reached.",
        err instanceof MqttRefused
          ? `the broker refused the connection with reason ${err.reason}`
          : String(err instanceof Error ? err.message : err))];
      this.again(held);
    }
  }

  /**
   * Resolves the entry's credential references again at its refresh_interval,
   * in seconds (revision 269; ECR-090B): "where a credential this entry
   * references is replaced, the CDMI server shall apply it by performing a
   * graceful MQTT DISCONNECT and reconnecting, and shall not reconnect where no
   * credential has changed. Where a credential this entry references is found
   * compromised ... the CDMI server shall end the MQTT session". As the export
   * does (mqtt-export.ts).
   */
  private startRefreshing(held: Running): void {
    const seconds = Number(held.entry.refresh_interval ?? "0");
    if (held.entry.password_secret_id === undefined || !(seconds > 0) || held.refresher !== undefined) return;
    held.refresher = setInterval(() => void this.refresh(held), seconds * 1000);
  }

  private async refresh(held: Running): Promise<void> {
    const e = held.entry;
    if (held.closed || held.refreshing || e.password_secret_id === undefined || this.opts.resolvePassword === undefined) return;
    held.refreshing = true;
    try {
      const got = await this.opts.resolvePassword(held.node, e.password_secret_id);
      const digest = createHash("sha256").update(got.octets).digest("hex");
      // The same credential: no reconnection.
      if (got.id === held.credential && digest === held.secretDigest) return;
      // A replaced credential: a graceful DISCONNECT, and a CONNECT that retrieves it again.
      const client = held.client;
      held.client = undefined;
      client?.disconnect();
      held.problems = [];
      await this.open(held);
    } catch (err) {
      const c = err as { type?: string; title?: string; detail?: string; message?: string };
      held.problems = [{
        type: c.type ?? "https://www.snia.org/cdmi/problems/kms/credential-unavailable",
        title: c.title ?? "The credential is unavailable.",
        detail: c.detail ?? c.message ?? String(err),
      }];
      if (/credential-compromised$/.test(held.problems[0].type)) {
        // The session ends, and none is made again with that credential.
        held.compromised = true;
        if (held.refresher !== undefined) clearInterval(held.refresher);
        held.refresher = undefined;
        const client = held.client;
        held.client = undefined;
        client?.disconnect();
      }
      // Otherwise the session goes on with the credential it was made with, and the next interval tries again.
    } finally {
      held.refreshing = false;
    }
  }

  private again(held: Running): void {
    if (held.closed) return;
    held.attempts += 1;
    // The import entry names no strategy, so the delay doubles to a
    // limit, as the export does where its entry names none.
    const seconds = Math.min(2 ** (held.attempts - 1), 256);
    const jitter = seconds * (Math.random() * 0.5 - 0.25);
    held.timer = setTimeout(() => {
      held.timer = undefined;
      void this.open(held);
    }, Math.max(1, (seconds + jitter) * 1000));
    held.timer.unref?.();
  }

  /** Enqueues one message, in the encoding and with the metadata the entry names. */
  private arrived(held: Running, m: {
    topic: string;
    payload: Buffer;
    qos: number;
    dup: boolean;
    packetID?: number;
    properties: { id: number; value: number | string | [string, string] }[];
  }): void {
    if (held.closed) return;
    // A delivery the broker marks as a duplicate of one already
    // enqueued is not enqueued again, where the identifier lets this
    // server tell.
    if (m.dup && m.packetID !== undefined && held.seen.has(m.packetID)) return;
    if (m.packetID !== undefined) {
      held.seen.add(m.packetID);
      // The identifiers a broker uses are reused, so only a recent
      // window is kept.
      if (held.seen.size > 4096) {
        for (const id of held.seen) {
          held.seen.delete(id);
          if (held.seen.size <= 2048) break;
        }
      }
    }

    const wanted = held.entry.value_transfer_encoding ?? "base64";
    let vte = wanted;
    let body = m.payload;
    if (wanted === "utf-8" || wanted === "json") {
      const text = m.payload.toString("utf8");
      const valid = Buffer.from(text, "utf8").equals(m.payload) &&
        (wanted !== "json" || isJSON(text));
      if (!valid) {
        // The payload is not valid as the encoding the entry names,
        // so it is enqueued as base 64 and the condition is recorded.
        vte = "base64";
        held.problems = [problem("imports/mqtt/payload-not-valid-for-encoding",
          "A message payload is not valid as the encoding the entry names.",
          `a message on ${m.topic} is not valid as ${wanted}, and was enqueued as ` +
          "base64")];
      }
    }

    // The media type of the value is the one the entry names, or the
    // content type of the message where the version provides one.
    const contentType = m.properties.find((p) => p.id === PROPERTY.CONTENT_TYPE);
    const mimetype = held.entry.mimetype ??
      (typeof contentType?.value === "string"
        ? contentType.value
        : "application/octet-stream");

    // Revision 121 removed the topic_metadata field and the two
    // metadata items a received message was recorded with, the queue
    // object representation having no field that presents the
    // metadata of a value. Nothing of a message is recorded beside
    // its octets, its media type and its encoding.

    try {
      this.opts.store.enqueue(held.node, [{ mimetype, vte, body }]);
      held.enqueued += 1;
    } catch (err) {
      // A message that cannot be enqueued is counted and not retried,
      // which is what the dropped count reports.
      held.dropped += 1;
      // Not queue-limit-reached: the store refused the value for a reason
      // that is not a limit of the queue object, which Annex C does not
      // define, so the condition is seedmi's own.
      held.problems = [seedmiProblem("imports/mqtt/not-enqueued",
        "A message could not be enqueued.",
        String(err instanceof Error ? err.message : err))];
    }
  }
}

function isJSON(text: string): boolean {
  try {
    JSON.parse(text);
    return true;
  } catch {
    return false;
  }
}

void MqttError;
void cdmiTime;
