// Protection against guessing: "Since this access token request utilizes the
// resource owner's password, the authorization server MUST protect the endpoint
// against brute force attacks" (RFC 6749 section 4.3.2), and likewise for a
// client's password (section 2.3.1). LDAP binds verify the same passwords, and
// are throttled by the same record.
//
// After a number of consecutive failures for one name, attempts for it are
// refused for a while without the password being checked, the wait doubling
// with each further failure up to a limit; a success clears the record. A
// locked name is refused as a wrong password would be, so that the client
// learns nothing more. It is held apart from the configuration, so that a
// reload does not clear it.
//
// Locking a name can be used to keep its owner out for a while, which is the
// usual price of this protection; the limit bounds it.

export interface ThrottleOptions {
  /** Failures before a name is locked. */
  allowed: number;
  /** The first wait, doubled for each further failure. */
  firstWaitMs: number;
  /** The longest wait. */
  maxWaitMs: number;
}

export const DEFAULT_THROTTLE: ThrottleOptions = { allowed: 5, firstWaitMs: 1000, maxWaitMs: 5 * 60 * 1000 };

export class Throttle {
  private readonly records = new Map<string, { failures: number; until: number }>();
  private readonly o: ThrottleOptions;
  private readonly now: () => number;

  constructor(o: ThrottleOptions = DEFAULT_THROTTLE, now: () => number = Date.now) {
    this.o = o;
    this.now = now;
  }

  /** Whether a name is locked now; names compare without case, as the directory's do. */
  locked(kind: string, name: string): boolean {
    const r = this.records.get(`${kind}\u0000${name.toLowerCase()}`);
    return r !== undefined && r.until > this.now();
  }

  /** Records the outcome of a verification that was made. */
  record(kind: string, name: string, ok: boolean): void {
    const key = `${kind}\u0000${name.toLowerCase()}`;
    if (ok) { this.records.delete(key); return; }
    const r = this.records.get(key) ?? { failures: 0, until: 0 };
    r.failures++;
    if (r.failures >= this.o.allowed) {
      const wait = Math.min(this.o.firstWaitMs * 2 ** (r.failures - this.o.allowed), this.o.maxWaitMs);
      r.until = this.now() + wait;
    }
    this.records.set(key, r);
  }
}
