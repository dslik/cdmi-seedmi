// Notification queues.
//
// A notification queue reports the events that occur to the objects
// that match a scope specification, from the time the queue object
// is created. It is a queue object carrying three metadata items, so
// a CDMI client creates one by creating a queue object with them and
// reads the notifications by reading it.
//
// A notification queue reports changes and not the state that
// existed when it was created: a CDMI client that requires that
// state performs a query.

import { cdmiTime, invalidField } from "./problems.ts";
import {
  checkResults, checkScope, matchesScope, project, QUEUE_TYPE, RESULTS, SCOPE,
} from "./query.ts";
import type { Node, Store } from "./store.ts";

/** The value of the queue type item for a notification queue. */
export const NOTIFICATION_QUEUE = "cdmi_notification_queue";

export const EVENTS = "cdmi_notification_events";

/** The event types this document defines. */
export const EVENT_TYPES = [
  "cdmi_create_processing",
  "cdmi_create_complete",
  "cdmi_read",
  "cdmi_modify_processing",
  "cdmi_modify_complete",
  "cdmi_rename",
  "cdmi_copy",
  "cdmi_reference",
  "cdmi_delete",
  "cdmi_export",
  "cdmi_snapshot",
];

/** The fields a notification carries beside those of the object. */
export const EVENT = "cdmi_event";
export const EVENT_RESULT = "cdmi_event_result";
export const EVENT_TIME = "cdmi_event_time";
export const EVENT_USER = "cdmi_event_user";

/** Whether the metadata of a queue object makes it a notification queue. */
export function isNotificationQueue(metadata: Record<string, unknown>): boolean {
  return metadata[QUEUE_TYPE] === NOTIFICATION_QUEUE;
}

/**
 * Checks the metadata of a notification queue: the three items are
 * mandatory, and the event types are those this document defines.
 */
export function checkNotificationMetadata(metadata: Record<string, unknown>): void {
  if (EVENTS in metadata) checkEvents(metadata[EVENTS]);
  if (!isNotificationQueue(metadata)) return;
  for (const item of [EVENTS, SCOPE, RESULTS]) {
    if (!(item in metadata)) {
      throw invalidField(`metadata/${item}`,
        "a notification queue contains the %s item", item);
    }
  }
  checkEvents(metadata[EVENTS]);
  checkScope(metadata[SCOPE]);
  // The value of an object is in hand when an event occurs, so the
  // capability that governs reporting it in a query does not reach
  // a notification queue.
  checkResults(metadata[RESULTS], false);
}

/** An empty array reports every event type. */
export function checkEvents(value: unknown): void {
  if (!Array.isArray(value) || value.some((e) => typeof e !== "string")) {
    throw invalidField(`metadata/${EVENTS}`,
      "the %s item is a JSON array of JSON strings", EVENTS);
  }
  for (const e of value as string[]) {
    if (!EVENT_TYPES.includes(e)) {
      throw invalidField(`metadata/${EVENTS}`,
        "%j is not an event type this document defines", e);
    }
  }
}

/** One event, as the CDMI server observed it. */
export interface Event {
  /** The event type, which is one of those this document defines. */
  type: string;
  /** The object the event occurred to, where it still exists. */
  node?: Node;
  /**
   * The representation of the object as the named principal would
   * read it, or undefined where that principal may not.
   *
   * A notification is formed once for each queue that reports the
   * event, as the owner of that queue: a CDMI client reads through
   * a notification queue what it could read directly, and no more.
   * Forming it once as the principal that caused the event would
   * report to the owner of a queue the fields of an object it may
   * not read.
   */
  representation: (as: string) => Record<string, unknown> | undefined;
  /** "Success", or the name of the condition the operation reported. */
  result: string;
  /** The principal that caused the event. */
  user: string;
  /** The instant the event occurred. */
  time?: string;
}

/**
 * Delivers an event to the notification queues that report it. A
 * queue reports an event that is of a type it specifies and that
 * occurred to an object matching the scope it specifies.
 */
export class Notifier {
  private readonly store: Store;
  /** The notification queues, by the identifier of the queue object. */
  private readonly queues = new Map<number, Node>();
  /** Whether this CDMI server enqueues notifications at all. */
  readonly enabled: boolean;

  constructor(store: Store, enabled = true) {
    this.store = store;
    this.enabled = enabled;
    store.onRemove((id) => this.queues.delete(id));
    // The registry is rebuilt from the store, because a notification queue
    // persists and its registration did not: until 0.107 the map was populated
    // only by offer(), which runs when a queue object is created or updated, so
    // a queue created in an earlier run of this server was absent from it. The
    // queue object was still there, with its scope and its event types intact,
    // and a CDMI client reading it saw the notifications it had already
    // received and never another — "a notification queue reports the events
    // that occur ... from the time the queue object is created", and this one
    // reported them until the process ended. Reported by cvwm against 0.104.
    for (const node of store.queueObjects()) {
      try {
        this.offer(node);
      } catch {
        // A row without metadata is no notification queue.
      }
    }
  }

  /**
   * Records a queue object as a notification queue, or forgets one
   * that is no longer a notification queue. Removing the queue type
   * item causes the CDMI server to enqueue no further notification
   * and to treat the queue object as any other.
   */
  offer(node: Node): void {
    if (isNotificationQueue(this.store.meta(node).metadata)) {
      this.queues.set(node.id, node);
    } else {
      this.queues.delete(node.id);
    }
  }

  /** Whether a queue object is reporting notifications. */
  reports(node: Node): boolean {
    return this.queues.has(node.id);
  }

  /** Enqueues a notification of this event to every queue that reports it. */
  notify(event: Event): void {
    if (!this.enabled || this.queues.size === 0) return;
    const at = event.time ?? cdmiTime(Date.now());
    for (const [id, node] of [...this.queues]) {
      let m;
      try {
        m = this.store.meta(node);
      } catch {
        // The queue object has gone.
        this.queues.delete(id);
        continue;
      }
      // An event of a queue object's own notifications is not
      // reported to it: enqueuing a notification is a modification
      // of the queue object, and reporting that would not end.
      if (event.node !== undefined && event.node.id === id) continue;

      const types = m.metadata[EVENTS];
      if (!Array.isArray(types)) continue;
      // An empty array reports every event type.
      if (types.length > 0 && !types.includes(event.type)) continue;
      const scope = m.metadata[SCOPE];
      if (!Array.isArray(scope)) continue;

      // Formed as the owner of this queue object, so that the scope
      // is matched against what that principal may read and the
      // notification reports no more than that.
      const rep = event.representation(m.owner);
      if (rep === undefined) continue;
      if (!matchesScope(scope, rep)) continue;

      // The results specification determines the fields reported for
      // each event, together with the notification fields.
      const selected = project(m.metadata[RESULTS], {
        ...rep,
        [EVENT]: event.type,
        [EVENT_RESULT]: event.result,
        [EVENT_TIME]: at,
        [EVENT_USER]: event.user,
      });
      this.store.enqueue(node, [{
        mimetype: "application/json",
        vte: "utf-8",
        body: Buffer.from(JSON.stringify(selected), "utf8"),
      }]);
    }
  }
}

// There is no refuseUnsupportedEvent. One stood here from 0.55 to 0.106 and was
// called from nowhere: it raised the capability not present condition naming
// cdmi_notification for an event type this server did not report, and cdmi_read
// was the one type it did not report. Calling it would have been wrong twice
// over. The capability is present — "support for notification queues is
// indicated by the cdmi_notification capability" — and this document defines no
// per-type capability, so there is no capability whose absence a refusal could
// name; and the type is one this document defines, which a server publishing
// cdmi_notification "shall enqueue a notification for". The answer was to raise
// the event, which 0.107 does, and not to refuse the type. Reported by cvwm as
// dead code, which it was, and as a choice between refusing and implementing,
// which the document does not leave open.
