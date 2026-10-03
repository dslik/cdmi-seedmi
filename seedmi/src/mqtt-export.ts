// Publishing the values of a queue object to an MQTT broker.
//
// Each value enqueued is published as one message on the topic the
// entry names, at the quality of service it names. A value is removed
// from the queue object after delivery where dequeue_on_publish is
// true, and a value a CDMI client removes itself does not prevent the
// delivery of a message already pending: the message holds the octets
// rather than a reference to the value.

import { createHash } from "node:crypto";
import type { MqttTls } from "./mqtt-entry.ts";
import { MqttClient, MqttRefused } from "./mqtt-client.ts";
import { MqttError, PROPERTY, type Property } from "./mqtt-wire.ts";
import type { Node, Store } from "./store.ts";
import { cdmiTime, type Problem, problem, seedmiProblem } from "./problems.ts";
import type { MqttExport } from "./exports.ts";
import { parseBrokerURI } from "./mqtt-entry.ts";

/** One message waiting to be published. */
interface Pending {
  designator: number;
  payload: Buffer;
  mimetype: string;
}

/** What an export entry reports of its connection. */
export interface MqttState {
  connected: boolean;
  published: number;
  pending: number;
  dropped: number;
  lastConnected: string;
  problems: Problem[];
}

/** One export: an entry, the connection it makes, and what it has sent. */
class Running {
  readonly name: string;
  entry: MqttExport;
  readonly node: Node;
  client?: MqttClient;
  readonly queue: Pending[] = [];
  published = 0;
  dropped = 0;
  lastConnected = "";
  problems: Problem[] = [];
  /** The managed object the password was last retrieved from, where one was. */
  credential: string | undefined;
  /** A digest of the password last presented, to tell a replaced credential from the same one. */
  secretDigest: string | undefined;
  /** The timer resolving the entry's credential references again, where it has one. */
  refresher: ReturnType<typeof setInterval> | undefined;
  /** Whether a resolution at the interval is in progress. */
  refreshing = false;
  /** Whether the credential was found compromised; no connection is made with it again. */
  compromised = false;
  /** How many times connecting has failed since it last succeeded. */
  attempts = 0;
  timer?: ReturnType<typeof setTimeout>;
  /** Whether a publishing pass is running, so that two do not. */
  draining = false;
  closed = false;

  constructor(name: string, entry: MqttExport, node: Node) {
    this.name = name;
    this.entry = entry;
    this.node = node;
  }
}

export interface MqttExporterOptions {
  store: Store;
  /**
   * Whether to connect at all. A server configured without MQTT
   * validates and reports an entry and makes no connection, which is
   * what a server with no broker to reach should do.
   */
  connect?: boolean;
  /** How long to wait for a broker, in milliseconds. */
  timeout?: number;
  /**
   * Retrieves the password an entry's password_secret_id addresses, each time
   * a connection is made. A refusal is a condition of the key management
   * subclause, reported in the entry's last_problems.
   */
  resolvePassword?: (node: Node, reference: { kms: string; name: string; scope?: string }) =>
    Promise<{ id: string; octets: Buffer }>;
  /** Retrieves the certificate an entry's ca_cert_id addresses, in PEM, to verify the broker's. */
  resolveCertificate?: (node: Node, reference: { kms: string; name: string; scope?: string }) =>
    Promise<{ id: string; pem: string }>;
  /**
   * Whether the access control list of the object still grants the principal
   * named the permission to read it.
   *
   * "An export that publishes outward receives no request: the CDMI server
   * sends what the export presents, when the object it presents changes. Such
   * an export publishes under the authority of the principal that created the
   * export entry, and a CDMI server shall publish only what the access control
   * list of the object granted that principal to read when the entry was
   * created. Where that principal loses the permission, the CDMI server shall
   * cease to publish and shall report the fault in the export entry" (revision
   * 365, access control and protocols).
   *
   * Nothing checked any principal's permission before 0.87: whoever could write
   * the queue object's metadata created an entry that thereafter published
   * every value enqueued to it, for as long as the entry existed, whatever
   * became of the list.
   */
  mayPublish?: (node: Node, principal: string) => boolean;
}

export class MqttExporter {
  private readonly opts: MqttExporterOptions;
  private readonly running = new Map<string, Running>();

  constructor(opts: MqttExporterOptions) {
    this.opts = opts;
    // Each value enqueued is published, whichever operation enqueued
    // it: an append, a copy, a deserialization, or an import.
    opts.store.onEnqueue((node, designators) => this.enqueued(node, designators));
  }

  /** Whether this CDMI server connects to a broker at all. */
  get connecting(): boolean {
    return this.opts.connect === true;
  }

  /**
   * Establishes an export, or replaces one whose entry has changed.
   * An entry that is unchanged keeps its connection and its counts.
   */
  offer(name: string, entry: MqttExport, node: Node): void {
    const held = this.running.get(name);
    if (held !== undefined) {
      if (JSON.stringify(held.entry) === JSON.stringify(entry)) return;
      // The entry has changed, so the connection it describes is not
      // the connection that is open.
      this.withdraw(name);
    }
    const now = new Running(name, entry, node);
    this.running.set(name, now);
    if (entry.disabled === "true" || !this.connecting) return;
    void this.open(now);
  }

  /**
   * Withdraws an export: a clean DISCONNECT, and the messages still
   * pending are removed, as the clause requires of an export that is
   * removed.
   */
  withdraw(name: string): void {
    const held = this.running.get(name);
    if (held === undefined) return;
    held.closed = true;
    if (held.timer !== undefined) clearTimeout(held.timer);
    if (held.refresher !== undefined) clearInterval(held.refresher);
    held.client?.disconnect();
    held.queue.length = 0;
    this.running.delete(name);
  }

  /** The names of the exports established. */
  offered(): string[] {
    return [...this.running.keys()];
  }

  /** What an entry reports of its connection and its counts. */
  state(name: string): MqttState | undefined {
    const held = this.running.get(name);
    if (held === undefined) return undefined;
    return {
      connected: held.client?.connected === true,
      published: held.published,
      // The values enqueued and not yet published, and the messages
      // sent and not yet acknowledged, which this client counts
      // together because it holds one until the other completes.
      pending: held.queue.length,
      dropped: held.dropped,
      lastConnected: held.lastConnected,
      problems: held.problems,
    };
  }

  /** Closes every connection, for a server that is shutting down. */
  close(): void {
    for (const name of [...this.running.keys()]) this.withdraw(name);
  }

  // -------------------------------------------------------------------

  private enqueued(node: Node, designators: number[]): void {
    for (const held of this.running.values()) {
      // An entry that has been disabled publishes nothing further: it
      // remains in the running set so that its state can be reported, and a
      // value enqueued after it was disabled still reached the broker
      // before 0.79 (weedmi EMQT-001).
      if (held.entry.disabled === "true") continue;
      if (held.node.id !== node.id) continue;
      // The authority the entry publishes under. Where the principal that
      // created it no longer holds READ_OBJECT on the object, publication
      // ceases and the fault is reported in the entry, as an export that
      // cannot be maintained is reported. It is checked here, where a value
      // becomes publishable, rather than when the list changes: an export is
      // reported from the state it is in, and the list may change by a route
      // that does not reach this module at all.
      const by = held.entry.publishedBy;
      if (by !== undefined && this.opts.mayPublish !== undefined &&
          !this.opts.mayPublish(node, by)) {
        // Annex C defines no condition for this. Revision 365 added the rule —
        // "where that principal loses the permission, the CDMI server shall
        // cease to publish and shall report the fault in the export entry" —
        // without a problem type for the fault it requires to be reported, and
        // none of the nine export conditions fits: the export was established
        // and has ceased, which is not exports/not-established. It is reported
        // under this server's own prefix, as every condition this document does
        // not define is, and raised as ECR-213A.
        const withheld = seedmiProblem("exports/authority-withdrawn",
          "The export can no longer be maintained.",
          `${by}, the principal that created this export entry, is no longer granted READ_OBJECT ` +
          "on the object it publishes, so this CDMI server has ceased to publish it",
          { cdmi_export: held.name });
        if (!held.problems.some((p) => p.type === withheld.type)) held.problems.push(withheld);
        // What is already queued is not sent either: the permission is gone
        // now, and a pending message is a message this server has not sent.
        held.queue.length = 0;
        continue;
      }
      // The octets are taken now rather than when the message is
      // sent: a CDMI client may remove the value at any time, and
      // that shall not prevent the delivery of a pending message.
      for (const designator of designators) {
        const value = this.opts.store
          .queueValues(node, designator, designator)[0];
        if (value === undefined) continue;
        held.queue.push({
          designator,
          payload: value.body,
          mimetype: value.mimetype,
        });
      }
      void this.drain(held);
    }
  }

  private async open(held: Running): Promise<void> {
    if (held.closed || held.client !== undefined || held.compromised) return;
    const e = held.entry;
    let at;
    try {
      at = parseBrokerURI("broker_uri", e.broker_uri);
    } catch (err) {
      held.problems = [problem("exports/mqtt/broker-unreachable",
        "The MQTT broker cannot be reached.", String(err),
        { cdmi_export: held.name })];
      return;
    }
    // The password is retrieved from the key management server each time a
    // connection is made, so a rotated credential is the one presented.
    let password: string | undefined;
    if (e.password_secret_id !== undefined) {
      try {
        if (this.opts.resolvePassword === undefined) {
          throw Object.assign(new Error("no key management server is reachable"),
            { type: "https://www.snia.org/cdmi/problems/kms/credential-unavailable", title: "The credential is unavailable." });
        }
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
          cdmi_export: held.name,
        }];
        // "A CDMI server shall not continue to use a compromised credential":
        // no attempt is made with it again until the entry is written anew.
        if (/credential-compromised$/.test(held.problems[0].type)) held.compromised = true;
        else this.again(held);
        return;
      }
      if (held.closed) return;
    }
    // "a certificate or certificate chain used to verify the certificate the
    // broker presents. The CDMI server retrieves it." Where absent, the trust
    // store configured on this server is used.
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
          cdmi_export: held.name,
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
      // The versions in order of preference; the first is attempted first.
      version: e.protocol[0],
      clientID: e.client_id,
      keepAlive: Number(e.keep_alive_interval),
      cleanStart: e.clean_session === "true",
      ...(e.username === undefined ? {} : { username: e.username }),
      ...(password === undefined ? {} : { password }),
      ...(e.tls === undefined ? {} : { tls: tlsOptions(e.tls, ca) }),
      // A ws or wss URI carries the connection over a WebSocket to
      // the endpoint its path identifies.
      ...(at.scheme === "ws" || at.scheme === "wss"
        ? {
          websocket: { endpoint: at.endpoint ?? "/", secure: at.scheme === "wss" },
        }
        : {}),
      // The last will and testament the broker publishes if this
      // CDMI server disconnects unexpectedly.
      ...(e.will === undefined ? {} : {
        will: {
          topic: e.will.topic,
          payload: Buffer.from(e.will.payload, "utf8"),
          qos: Number(e.will.qos),
          retain: e.will.retain === "true",
        },
      }),
      // The session state a broker retains after this server
      // disconnects, which MQTT 5.0 carries in the CONNECT packet.
      ...(e.protocol[0] === "5.0" && e.session_expiry_interval !== undefined
        ? {
          properties: [{
            id: PROPERTY.SESSION_EXPIRY_INTERVAL,
            value: Number(e.session_expiry_interval),
          }],
        }
        : {}),
      ...(this.opts.timeout === undefined ? {} : { timeout: this.opts.timeout }),
    });
    held.client = client;
    try {
      await client.connect();
      held.attempts = 0;
      held.lastConnected = cdmiTime(Date.now());
      held.problems = [];
      this.startRefreshing(held);
      void this.drain(held);
    } catch (err) {
      held.client = undefined;
      client.close();
      held.problems = [problem("exports/mqtt/broker-unreachable",
        "The MQTT broker cannot be reached.",
        err instanceof MqttRefused
          ? `the broker refused the connection with reason ${err.reason}`
          : String(err instanceof Error ? err.message : err),
        { cdmi_export: held.name })];
      this.again(held);
    }
  }

  /**
   * Resolves the entry's credential references again at its refresh_interval,
   * in seconds, as the rotation subclause provides: "MQTT presents credentials
   * only in the CONNECT packet, so where a credential this entry references is
   * replaced, the CDMI server shall apply it by performing a graceful MQTT
   * DISCONNECT and reconnecting, and shall not reconnect where no credential
   * has changed." The draft states no unit for the interval; this server takes
   * seconds, as the entry's other intervals are.
   */
  private startRefreshing(held: Running): void {
    const e = held.entry;
    const seconds = Number(e.refresh_interval ?? "0");
    if (e.password_secret_id === undefined || !(seconds > 0) || held.refresher !== undefined) return;
    held.refresher = setInterval(() => void this.refresh(held), seconds * 1000);
  }

  private async refresh(held: Running): Promise<void> {
    const e = held.entry;
    if (held.closed || held.refreshing || e.password_secret_id === undefined ||
        this.opts.resolvePassword === undefined) return;
    held.refreshing = true;
    try {
      const got = await this.opts.resolvePassword(held.node, e.password_secret_id);
      const digest = createHash("sha256").update(got.octets).digest("hex");
      // The same credential: no reconnection.
      if (got.id === held.credential && digest === held.secretDigest) return;
      // A replaced credential is applied by a graceful DISCONNECT and a new
      // CONNECT, which retrieves it again.
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
        cdmi_export: held.name,
      }];
      if (/credential-compromised$/.test(held.problems[0].type)) {
        // "the CDMI server shall cease to use the managed object immediately,
        // shall terminate any session established with it": the session ends
        // and none is made again with that credential.
        held.compromised = true;
        if (held.refresher !== undefined) clearInterval(held.refresher);
        held.refresher = undefined;
        const client = held.client;
        held.client = undefined;
        client?.disconnect();
      }
      // Otherwise (a credential found unavailable between the removal of its
      // Name and the registration of its replacement, say) the session goes
      // on with the credential it was made with, and the next interval tries
      // again.
    } finally {
      held.refreshing = false;
    }
  }

  /** Schedules another attempt, by the strategy the entry names. */
  private again(held: Running): void {
    if (held.closed) return;
    held.attempts += 1;
    const n = held.attempts;
    const seconds = held.entry.reconnect_strategy === "fixed"
      ? 10
      : held.entry.reconnect_strategy === "linear"
      ? Math.min(n, 256)
      : Math.min(2 ** (n - 1), 256);
    // Jitter of a quarter either way, so that many exports losing one
    // broker do not return to it together.
    const jitter = seconds * (Math.random() * 0.5 - 0.25);
    held.timer = setTimeout(() => {
      held.timer = undefined;
      void this.open(held);
    }, Math.max(1, (seconds + jitter) * 1000));
    held.timer.unref?.();
  }

  /** Publishes what is pending, one message at a time and in order. */
  private async drain(held: Running): Promise<void> {
    if (held.draining || held.closed) return;
    held.draining = true;
    try {
      while (held.queue.length > 0 && !held.closed) {
        const client = held.client;
        if (client === undefined || !client.connected) return;
        const next = held.queue[0];
        const properties: Property[] = [];
        if (held.entry.protocol[0] === "5.0") {
          // The media type of the value is the content type of the
          // message, where the entry does not name one of its own.
          properties.push({
            id: PROPERTY.CONTENT_TYPE,
            value: held.entry.content_type ?? next.mimetype,
          });
          if (held.entry.response_topic !== undefined) {
            properties.push({
              id: PROPERTY.RESPONSE_TOPIC,
              value: held.entry.response_topic,
            });
          }
          if (held.entry.message_expiry_interval !== undefined) {
            properties.push({
              id: PROPERTY.MESSAGE_EXPIRY_INTERVAL,
              value: Number(held.entry.message_expiry_interval),
            });
          }
          for (const [k, v] of held.entry.user_properties ?? []) {
            properties.push({ id: PROPERTY.USER_PROPERTY, value: [k, v] });
          }
        }
        try {
          await client.publish(held.entry.topic, next.payload, {
            qos: Number(held.entry.qos),
            retain: held.entry.retain === "true",
            ...(properties.length === 0 ? {} : { properties }),
          });
        } catch (err) {
          // The message stays pending and the connection is made
          // again: a message is not dropped because a broker went
          // away mid-flight.
          held.problems = [problem("exports/mqtt/broker-unreachable",
            "The MQTT broker cannot be reached.",
            String(err instanceof Error ? err.message : err),
            { cdmi_export: held.name })];
          held.client = undefined;
          client.close();
          this.again(held);
          return;
        }
        held.queue.shift();
        held.published += 1;
        // The value is removed from the queue object after delivery,
        // where the entry says it should be.
        if (held.entry.dequeue_on_publish === "true") {
          try {
            this.opts.store.dequeue(held.node, next.designator, next.designator);
          } catch {
            // The value has gone already, which a CDMI client may do
            // at any time.
          }
        }
      }
    } finally {
      held.draining = false;
    }
  }
}

/**
 * The options a TLS connection is given: the entry's tls settings, less the
 * credential reference, which is not an option, with the certificate it
 * retrieved in its place.
 */
export function tlsOptions(tls: MqttTls, ca: string | undefined): Omit<MqttTls, "ca_cert_id"> {
  const { ca_cert_id: _reference, ...options } = tls;
  void _reference;
  return { ...options, ...(ca === undefined ? {} : { ca }) };
}
