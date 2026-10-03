// Running a query.
//
// A CDMI server begins the query when the query queue is created and
// enqueues each result as it is found. A query reports the objects
// that match at the time it is performed, and the server does not
// delay one in order to reach a consistent state: an object created,
// changed or deleted while a query is in progress is not necessarily
// reported.

import { SNAPSHOTS, reservedName, type Node, type Store } from "./store.ts";
import {
  isQueryQueue, matchesScope, QUERY_STATUS, queryNeedsValue, resultValue, RESULTS, SCOPE,
} from "./query.ts";

/** What the runner needs of the binding: the representation of an object. */
export interface Representer {
  /**
   * The representation of an object as a query reports it, or
   * undefined where the principal that owns the query queue may not
   * read the object.
   *
   * Where withValue is true the representation carries the "value" field of a
   * data object, as a base 64 encoded string, which is what a scope matches and
   * what a results specification reports. Reading it is why this is
   * asynchronous, and the runner asks for it only for a query that needs it.
   */
  representationOf(node: Node, ns: string, withValue: boolean):
    Promise<Record<string, unknown> | undefined>;
}

/** One query in progress. */
interface Running {
  node: Node;
  stopped: boolean;
}

/**
 * The status of a query this CDMI server was performing when it stopped
 * running. "Text stating the reason may follow the value, and that text is
 * implementation defined", so the reason is given: an operator reading the
 * queue object learns why, and a CDMI client parsing the value finds the
 * "Error" the table defines in front of it.
 */
export const INTERRUPTED =
  "Error: the CDMI server stopped while this query was in progress, so the " +
  "results enqueued are those it had found by then";

/**
 * Fails every query that was in progress when this CDMI server last stopped
 * running.
 *
 * A query queue's status is written to the store before the query begins, and
 * the query itself lives in the memory of the process performing it. A process
 * that stopped between the two left a query queue reporting "Processing", which
 * means "the CDMI server is performing the query, and further results may be
 * enqueued" — and nothing was performing it, and no further result would ever
 * be enqueued. Since "a CDMI client determines that a query has completed by
 * reading this item, and not by the absence of further results", such a client
 * waits for a query that has stopped existing, for as long as it is willing to
 * wait.
 *
 * The status the table provides for this is "Error": "a condition prevented the
 * CDMI server from enqueuing every result". The restart is that condition. The
 * alternative of performing the query again is not open to a CDMI server on its
 * own account — "this document defines no means of pausing a query and resuming
 * it", and the results already enqueued are retained and may already have been
 * read, so a second walk would report them twice. A CDMI client that wants the
 * query performed again changes the cdmi_queue_type item away from
 * "cdmi_query_queue" and back, which "starts a new query", or creates another
 * query queue.
 *
 * This runs once, when the CDMI server starts, and before any query of this
 * process has been offered.
 */
export function failInterruptedQueries(store: Store): void {
  for (const node of store.queueObjects()) {
    try {
      const m = store.meta(node);
      if (!isQueryQueue(m.metadata)) continue;
      if (m.metadata[QUERY_STATUS] !== "Processing") continue;
      m.metadata = { ...m.metadata, [QUERY_STATUS]: INTERRUPTED };
      store.setMeta(node, m);
    } catch {
      // A queue object that has gone between the listing and the read is not
      // one whose status matters.
    }
  }
}

export class QueryRunner {
  private readonly store: Store;
  private readonly rep: Representer;
  private readonly running = new Map<number, Running>();

  constructor(store: Store, rep: Representer) {
    this.store = store;
    this.rep = rep;
    // A query queue that is removed has nothing to enqueue to, and
    // its query stops.
    store.onRemove((id) => {
      const held = this.running.get(id);
      if (held === undefined) return;
      held.stopped = true;
      this.running.delete(id);
    });
  }

  /**
   * Begins the query of a query queue, or stops one that is running
   * where the queue object is no longer a query queue. The metadata
   * decides which: the item that states how the CDMI server manages
   * the queue object controls whether the query runs.
   */
  offer(node: Node): void {
    const m = this.store.meta(node);
    if (!isQueryQueue(m.metadata)) {
      this.stop(node);
      return;
    }
    // A query that is stopped and started again is a new query, and
    // reports the objects that match at the time it is performed.
    this.stop(node);
    const now: Running = { node, stopped: false };
    this.running.set(node.id, now);
    this.setStatus(node, "Processing");
    // The query runs after the operation that created the queue
    // object has answered, so that a CDMI client sees the status
    // rather than waiting for the results.
    setTimeout(() => void this.run(now), 0).unref?.();
  }

  /** Stops a query in progress, retaining the results already enqueued. */
  stop(node: Node): void {
    const held = this.running.get(node.id);
    if (held === undefined) return;
    held.stopped = true;
    this.running.delete(node.id);
  }

  /** Whether a query of this queue object is in progress. */
  runs(node: Node): boolean {
    return this.running.has(node.id);
  }

  /** Whether the queue object is still there to be written to. */
  private present(node: Node): boolean {
    try {
      this.store.meta(node);
      return true;
    } catch {
      return false;
    }
  }

  private setStatus(node: Node, status: string): void {
    // A query queue removed while its query runs is not written to.
    if (!this.present(node)) return;
    const m = this.store.meta(node);
    if (m.metadata[QUERY_STATUS] === status) return;
    m.metadata = { ...m.metadata, [QUERY_STATUS]: status };
    this.store.setMeta(node, m);
  }

  /**
   * Whether the scope of the query in progress names a path within
   * the snapshots of a container object.
   */
  private namesSnapshots = false;

  private async run(now: Running): Promise<void> {
    if (!this.present(now.node)) {
      this.running.delete(now.node.id);
      return;
    }
    const m = this.store.meta(now.node);
    const scope = m.metadata[SCOPE];
    const results = m.metadata[RESULTS];
    if (!Array.isArray(scope)) {
      this.setStatus(now.node, "Error");
      this.running.delete(now.node.id);
      return;
    }
    // A scope reaches a snapshot only where it names one, which a
    // CDMI client does by a constant addressing a path within a
    // cdmi_snapshots container object.
    this.namesSnapshots = JSON.stringify(scope).includes(SNAPSHOTS);
    // The value of each object is read only where this query needs one, which
    // is settled once from the two items rather than per object.
    const withValue = queryNeedsValue(scope, results);
    try {
      for (const { node, ns } of this.walk(this.store.root(), "/")) {
        if (now.stopped) return;
        // The query queue may be removed while its query runs, and
        // a result is not enqueued to an object that has gone.
        if (!this.present(now.node)) {
          this.running.delete(now.node.id);
          return;
        }
        // A query queue does not report itself: the results it holds
        // would otherwise be a term of its own query.
        if (node.id === now.node.id) continue;
        const rep = await this.rep.representationOf(node, ns, withValue);
        // Awaiting gives the queue object time to go, and a result is not
        // enqueued to one that has.
        if (now.stopped || !this.present(now.node)) {
          this.running.delete(now.node.id);
          return;
        }
        // An object the principal may not read is not reported, as
        // the access control clause requires of every operation.
        if (rep === undefined) continue;
        if (!matchesScope(scope, rep)) continue;
        this.store.enqueue(now.node, [resultValue(results, rep)]);
      }
    } catch {
      this.setStatus(now.node, "Error");
      this.running.delete(now.node.id);
      return;
    }
    if (now.stopped) return;
    this.setStatus(now.node, "Current");
    this.running.delete(now.node.id);
  }

  /** Every object of the namespace, depth first. */
  private *walk(at: Node, ns: string):
    Generator<{ node: Node; ns: string }> {
    for (const child of this.store.children(at)) {
      // The object ID tree, the capability objects and the domain
      // objects are addressed by paths of their own and are not
      // objects a query reports.
      //
      // A scope specification reaches the objects a snapshot holds
      // only where it names that snapshot, so the snapshots of a
      // container object are walked only where the scope names a
      // path within them. An empty scope therefore matches the
      // objects of the namespace alone, which would otherwise be
      // reported beside the objects of every snapshot taken of
      // them.
      if (child.name === SNAPSHOTS) {
        if (!this.namesSnapshots) continue;
      } else if (reservedName(child.name)) {
        continue;
      }
      const childNS = child.node.isContainer ? `${ns}${child.name}/` : ns + child.name;
      yield { node: child.node, ns: childNS };
      if (child.node.isContainer) yield* this.walk(child.node, childNS);
    }
  }
}
