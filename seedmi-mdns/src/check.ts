// Liveness: whether the CDMI server an instance fronts is answering.
//
// The responder runs as its own program and outlives the server it advertises.
// Without this, a server that stops leaves a PTR on the link for as long as its
// lifetime says, and a browser offers a host that fails on the click. The
// in-process case never had to consider it — the advertisement went away with
// the process.
//
// What is polled is the CDMI well-known discovery tree at the instance's own
// origin, which is the thing a client reaches next anyway: a server that
// answers it is a server the client can go on to use. Nothing is read from the
// answer beyond the fact of it, and no credential is presented — the tree is
// what "a CDMI client that knows only an origin" reads.

import { Agent, request } from "node:https";

export interface CheckOptions {
  url: string;
  intervalMs: number;
  /** The anchors for the endpoint's certificate, where the system does not trust it. */
  ca?: string;
  timeoutMs?: number;
  /** Called when the answer changes, and once at the first result. */
  onChange: (up: boolean, why: string) => void;
}

export class Check {
  private readonly opts: CheckOptions;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private up: boolean | undefined;
  private stopped = false;

  constructor(opts: CheckOptions) {
    this.opts = opts;
  }

  start(): void {
    void this.once();
  }

  stop(): void {
    this.stopped = true;
    if (this.timer !== undefined) clearTimeout(this.timer);
  }

  /** One poll, and the next one scheduled. Exposed so a test need not wait. */
  async once(): Promise<boolean> {
    const [ok, why] = await this.probe();
    if (this.up !== ok) {
      this.up = ok;
      this.opts.onChange(ok, why);
    }
    if (!this.stopped) {
      this.timer = setTimeout(() => void this.once(), this.opts.intervalMs);
      if (typeof this.timer.unref === "function") this.timer.unref();
    }
    return ok;
  }

  private probe(): Promise<[boolean, string]> {
    return new Promise((resolve) => {
      let done = false;
      const finish = (ok: boolean, why: string) => {
        if (done) return;
        done = true;
        resolve([ok, why]);
      };
      let req: ReturnType<typeof request>;
      try {
        req = request(this.opts.url, {
          method: "GET",
          // The certificate is verified. An instance denotes a TLS binding and
          // the client that follows it will verify the same certificate, so a
          // check that skipped verification would advertise a host the client
          // then refuses to connect to.
          agent: new Agent(this.opts.ca === undefined ? {} : { ca: this.opts.ca }),
          timeout: this.opts.timeoutMs ?? 5000,
        });
      } catch (e) {
        finish(false, (e as Error).message);
        return;
      }
      req.on("response", (res) => {
        const status = res.statusCode ?? 0;
        res.resume();
        // Any answer from the tree is an answer: a 401 says the server is there
        // and wants a credential, which is a server a client can still use.
        finish(status > 0 && status < 500, `HTTP ${status}`);
      });
      req.on("timeout", () => {
        req.destroy();
        finish(false, "timed out");
      });
      req.on("error", (e) => finish(false, (e as Error).message));
      req.end();
    });
  }
}
