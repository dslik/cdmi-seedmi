// Request and problem logging.
//
// Off by default. The objects of a CDMI server are the user's data,
// and a server that begins recording paths and principals because it
// was upgraded is a surprise with consequences, so logging is asked
// for rather than switched off.
//
// What is never written: a request or response body, the value of an
// object, the Authorization header field, a token, a password, any
// NTLM material, the value of a metadata item, and the arguments of a
// query. The name of the principal appears, and nothing that
// authenticated it.

import { appendFileSync } from "node:fs";
import { PROBLEM_BASE } from "./problems.ts";

/** How much is written. */
export type LogLevel = "off" | "problems" | "requests";

/** The levels, for a flag and for the usage text. */
export const LOG_LEVELS: LogLevel[] = ["off", "problems", "requests"];

/** How each line is written. */
export type LogFormat = "text" | "json";

export const LOG_FORMATS: LogFormat[] = ["text", "json"];

/** The surface a request arrived at. */
/** Where a request arrived; "pipe" marks a pipe's tickets and connections, so that they can be filtered. */
export type LogSurface = "http" | "export" | "discovery" | "nfs" | "smb" | "pipe" | "mcp";

/** One request, as it is to be written. */
export interface LogEntry {
  /**
   * The trace identifier of an operation of the CDMI over MCP binding,
   * and the program that called it. "A CDMI server that keeps a record of
   * an operation records that value with it, so that the record an
   * intermediary keeps and the record the CDMI server keeps are
   * recognizable as being of one operation" (revision 347).
   */
  traceparent?: string;
  client?: string;
  surface: LogSurface;
  /**
   * The outcome, as the protocol expresses it: an HTTP status code,
   * an NFS status name, or an SMB status name.
   */
  outcome: string;
  /** Whether the outcome is a failure, which decides the level. */
  failed: boolean;
  /** The operation: an HTTP method, an NFS operation, an SMB command. */
  operation: string;
  /** What was addressed: a request URI path, or a share name. */
  instance: string;
  /** The principal the request was performed as. */
  principal: string;
  /** How long the request took, in milliseconds. */
  ms: number;
  /** The type URI of the condition reported, where one was. */
  type?: string;
  /** The detail of that condition. */
  detail?: string;
  /** The extension members it carried, such as cdmi_export. */
  members?: Record<string, unknown>;
}

/** An instant in the form this document uses for a time. */
const stamp = (ms: number): string =>
  new Date(ms).toISOString().replace(/\.(\d{3})Z$/, ".$1000Z");

/** Pads a column, so that a line stays readable beside its neighbours. */
const pad = (s: string, n: number): string => (s.length >= n ? s : s.padEnd(n));

export class Log {
  readonly level: LogLevel;
  readonly format: LogFormat;
  private readonly file?: string;

  constructor(level: LogLevel, format: LogFormat = "text", file?: string) {
    this.level = level;
    this.format = format;
    this.file = file;
  }

  /** Whether anything at all is written, so a caller may skip the work. */
  get enabled(): boolean {
    return this.level !== "off";
  }

  /** Whether this outcome is written at the level configured. */
  wants(failed: boolean): boolean {
    if (this.level === "off") return false;
    return this.level === "requests" || failed;
  }

  write(e: LogEntry): void {
    if (!this.wants(e.failed)) return;
    const line = this.format === "json" ? this.json(e) : this.text(e);
    if (this.file === undefined) {
      process.stderr.write(`${line}\n`);
      return;
    }
    try {
      appendFileSync(this.file, `${line}\n`);
    } catch {
      // A log that cannot be written does not stop a request being
      // served. It is reported once, so that a misconfigured path is
      // noticed without a line per request.
      if (!this.complained) {
        this.complained = true;
        process.stderr.write(`seedmi: the log file ${this.file} cannot be written\n`);
      }
    }
  }

  private complained = false;

  private text(e: LogEntry): string {
    // Tab separated, so that a column holding a space does not shift
    // the ones after it, and the line stays greppable.
    const parts = [
      stamp(Date.now()),
      pad(e.surface, 9),
      pad(e.outcome, 6),
      pad(e.operation, 8),
      e.instance,
      e.principal,
      `${e.ms}ms`,
    ];
    // The condition is named by the same identifier its problem
    // document carries, with the prefix this document assigns removed.
    if (e.type !== undefined) parts.push(shortType(e.type));
    return parts.join("\t");
  }

  private json(e: LogEntry): string {
    return JSON.stringify({
      time: stamp(Date.now()),
      surface: e.surface,
      outcome: e.outcome,
      operation: e.operation,
      instance: e.instance,
      principal: e.principal,
      ms: e.ms,
      ...(e.type === undefined ? {} : { type: e.type }),
      ...(e.detail === undefined ? {} : { detail: e.detail }),
      ...(e.members ?? {}),
    });
  }

  /**
   * One delegated access control event, written whatever the level, including
   * "off".
   *
   * This is the one exception to the rule above that logging is asked for.
   * Delegation sends a decision to a party outside this server and refuses the
   * operation where no valid response arrives, so an operation can fail for a
   * reason nothing in this server can show: the provider was not reached, or
   * answered something this server would not take. A deployment that records
   * nothing of the exchange cannot tell those apart, or tell either from a
   * denial the access control list itself produced.
   *
   * What is written is the object ID, the operation, the provider URI, the
   * principal and the outcome. What is not written is the content of a request
   * or of a response, either party's keys, and the headers passed through,
   * which may carry a credential.
   */
  dac(event: Record<string, unknown>): void {
    // JSON Lines, whatever the format configured for the request log: one JSON
    // object per line, newline-delimited. These records are read by a program —
    // they are what joins this server's account of an operation to a delegated
    // access control provider's — and a tab-separated line of key=value pairs
    // is not, since a value may hold a tab or a space and nothing quotes it.
    // The request log keeps its two formats; this one has only the one.
    const line = JSON.stringify({ time: stamp(Date.now()), surface: "dac", ...event });
    if (this.file === undefined) {
      process.stderr.write(`${line}\n`);
      return;
    }
    try {
      appendFileSync(this.file, `${line}\n`);
    } catch {
      if (!this.complained) {
        this.complained = true;
        process.stderr.write(`seedmi: the log file ${this.file} cannot be written\n`);
      }
    }
  }
}

/** The condition, without the prefix every type URI of this document has. */
export function shortType(type: string): string {
  return type.startsWith(PROBLEM_BASE) ? type.slice(PROBLEM_BASE.length) : type;
}

/** A log that writes nothing, for a server that was given none. */
export const SILENT = new Log("off");
