/**
 * The connect relay's audit. One `SandboxConnectSession` row
 * per live connection (written after `hello`, completed at its end) and one
 * structured log line per open and per close.
 *
 * Never on the relay's path, and never a threat to relay authorization reads
 * on the shared Prisma pool. One recorder per process writes through a FIFO
 * queue with a small fixed concurrency (`concurrency`, default 2), and each
 * write is bounded by its statement and transaction timeouts
 * (`connect-sessions.ts`), so a stalled database holds at most that many pool
 * connections. The queue is bounded (`maxPending`): a new open is dropped
 * (and counted) when it is full, but a close for an admitted open is never
 * dropped. A close whose open has not been written yet coalesces with it into
 * one insert; a close waiting on an open in flight follows it once it
 * succeeds; a dropped, refused or failed open drops its close (there is no row
 * to complete). Both instants are the relay's own (`openedAt`/`closedAt` at
 * the hooks), never the write's. Server shutdown drains the queue for a
 * bounded time (`drain`). A failing write is logged rate-capped and
 * swallowed, and nothing here throws into the connection. Ids and counters
 * only: never content, commands, argv, env or paths.
 */
import {
  type ConnectSessionClose,
  type ConnectSessionEnd,
  type ConnectSessionOpen,
  forwardedPortsColumn,
  recordConnectSessionClose,
  recordConnectSessionOpen,
} from "@wssp/api/sandbox/connect-sessions";
import { safeErrorLog } from "@wssp/api/sandbox/sensitive-errors";

export type ConnectAuditOpen = {
  connectionId: string;
  ownerId: string;
  keyId: string;
  sandboxId: string;
  hostId: string;
  /** Epoch ms at which the connection went live (the relay's clock). */
  openedAt: number;
};

export type ConnectAuditClose = ConnectAuditOpen & {
  /** Epoch ms at which the relay ended the connection. */
  closedAt: number;
  intent: string;
  ptyChannels: number;
  execChannels: number;
  /** `tcp` and `unix` relay channels (never counted in `execChannels`). */
  relayChannels: number;
  /**
   * The guest tcp ports relayed. Kept distinct, the first 16 seen; a guest
   * Unix socket path is never passed here.
   */
  forwardedPorts: readonly number[];
  bytesIn: number;
  bytesOut: number;
};

export type ConnectAuditSink = {
  open(row: ConnectSessionOpen): Promise<boolean>;
  close(row: ConnectSessionClose): Promise<boolean>;
};

export type ConnectAuditRecorderOptions = {
  sink?: ConnectAuditSink;
  /** Writes running at once (each holds one pool connection at most). */
  concurrency?: number;
  /** Queued writes before new opens are dropped (closes never are). */
  maxPending?: number;
  /** Log lines per minute, per kind (open/close lines; failure lines). */
  logsPerMinute?: number;
  now?: () => number;
};

const DEFAULT_CONCURRENCY = 2;
const DEFAULT_MAX_PENDING = 4096;
/** The default (server shutdown, lifecycle.ts) bound for `drain`. */
const CONNECT_AUDIT_DRAIN_MS = 3_000;
const DEFAULT_LOGS_PER_MINUTE = 120;
const LOG_WINDOW_MS = 60_000;

class RateCap {
  private start = 0;
  private count = 0;
  /** Lines suppressed so far (reported by the next line that is written). */
  suppressed = 0;
  constructor(
    private readonly perWindow: number,
    private readonly now: () => number,
  ) {}
  take(): boolean {
    const now = this.now();
    if (now - this.start >= LOG_WINDOW_MS) {
      this.start = now;
      this.count = 0;
    }
    if (this.count >= this.perWindow) {
      this.suppressed += 1;
      return false;
    }
    this.count += 1;
    return true;
  }
}

const defaultSink: ConnectAuditSink = {
  open: recordConnectSessionOpen,
  close: recordConnectSessionClose,
};

/** One admitted connection, from its admitted open until its row is complete. */
type Tracked = {
  open: ConnectSessionOpen;
  /**
   * `queued`: the open waits in the queue (a close coalesces into it);
   * `writing`: the open write runs (a close waits in `close`);
   * `written`: the row exists, the connection is live;
   * `closing`: the close is queued or running.
   */
  state: "queued" | "writing" | "written" | "closing";
  end?: ConnectSessionEnd;
};

type Job = { kind: "open" | "close"; id: string };

export class ConnectAuditRecorder {
  private readonly sink: ConnectAuditSink;
  private readonly concurrency: number;
  private readonly maxPending: number;
  private readonly lines: RateCap;
  private readonly failures: RateCap;
  private readonly tracked = new Map<string, Tracked>();
  private readonly queue: Job[] = [];
  private running = 0;
  private idleWaiters: (() => void)[] = [];
  /** Opens dropped because the queue was full (process lifetime). */
  dropped = 0;

  constructor(options: ConnectAuditRecorderOptions = {}) {
    this.sink = options.sink ?? defaultSink;
    this.concurrency = Math.max(1, options.concurrency ?? DEFAULT_CONCURRENCY);
    this.maxPending = Math.max(1, options.maxPending ?? DEFAULT_MAX_PENDING);
    const now = options.now ?? Date.now;
    const perMinute = Math.max(1, options.logsPerMinute ?? DEFAULT_LOGS_PER_MINUTE);
    this.lines = new RateCap(perMinute, now);
    this.failures = new RateCap(Math.min(perMinute, 10), now);
  }

  /** Writes running now (tests). */
  get runningWrites(): number {
    return this.running;
  }

  /** Writes queued or running (tests, shutdown). */
  get pendingWrites(): number {
    return this.queue.length + this.running;
  }

  /** The connection went live (after `hello`). Never throws. */
  opened(open: ConnectAuditOpen): void {
    try {
      this.log("opened", {
        code: "connect_open",
        connectionId: open.connectionId,
        ownerId: open.ownerId,
        keyId: open.keyId,
        sandboxId: open.sandboxId,
        hostId: open.hostId,
      });
      if (this.tracked.has(open.connectionId)) return;
      if (this.queue.length >= this.maxPending) {
        this.dropped += 1;
        if (this.failures.take())
          console.warn("[sandbox-connect] audit open dropped:", {
            code: "connect_audit_dropped",
            dropped: this.dropped,
          });
        return;
      }
      this.tracked.set(open.connectionId, {
        state: "queued",
        open: {
          id: open.connectionId,
          ownerId: open.ownerId,
          sandboxId: open.sandboxId,
          hostId: open.hostId,
          keyId: open.keyId,
          openedAt: new Date(open.openedAt),
        },
      });
      this.enqueue({ kind: "open", id: open.connectionId });
    } catch {
      /* The audit never breaks the relay. */
    }
  }

  /** A connection that went live ended. Never throws. */
  closed(close: ConnectAuditClose): void {
    try {
      this.log("closed", {
        code: "connect_close",
        connectionId: close.connectionId,
        ownerId: close.ownerId,
        keyId: close.keyId,
        sandboxId: close.sandboxId,
        hostId: close.hostId,
        intent: close.intent,
        ptyChannels: close.ptyChannels,
        execChannels: close.execChannels,
        relayChannels: close.relayChannels,
        forwardedPorts: forwardedPortsColumn(close.forwardedPorts).join(","),
        bytesIn: close.bytesIn,
        bytesOut: close.bytesOut,
      });
      const forwardedPorts = forwardedPortsColumn(close.forwardedPorts);
      const entry = this.tracked.get(close.connectionId);
      // Not admitted, or its open was refused/failed: no row to complete.
      if (!entry || entry.end) return;
      entry.end = {
        closedAt: new Date(close.closedAt),
        closeIntent: close.intent,
        ptyChannels: close.ptyChannels,
        execChannels: close.execChannels,
        relayChannels: close.relayChannels,
        forwardedPorts,
        bytesIn: close.bytesIn,
        bytesOut: close.bytesOut,
      };
      // `queued`: the open job writes the complete row; `writing`: the close
      // follows the open's success. Only a written row needs its own job,
      // which is never dropped (its open was admitted).
      if (entry.state === "written") {
        entry.state = "closing";
        this.enqueue({ kind: "close", id: close.connectionId });
      }
    } catch {
      /* The audit never breaks the relay. */
    }
  }

  /**
   * Every queued and running write settled, or `timeoutMs` passed (then the
   * rest is given up and logged; it is lost when the process exits). Never
   * rejects. True when drained.
   */
  async drain(timeoutMs = CONNECT_AUDIT_DRAIN_MS): Promise<boolean> {
    if (this.pendingWrites === 0) return true;
    const idle = new Promise<true>((resolve) => this.idleWaiters.push(() => resolve(true)));
    let timer: ReturnType<typeof setTimeout> | undefined;
    const expired = new Promise<false>((resolve) => {
      timer = setTimeout(() => resolve(false), Math.max(0, timeoutMs));
      timer.unref?.();
    });
    const drained = await Promise.race([idle, expired]);
    clearTimeout(timer);
    if (!drained)
      console.warn("[sandbox-connect] audit drain timed out:", {
        code: "connect_audit_drain_timeout",
        pending: this.pendingWrites,
      });
    return drained;
  }

  private enqueue(job: Job) {
    this.queue.push(job);
    this.pump();
  }

  private pump() {
    while (this.running < this.concurrency) {
      const job = this.queue.shift();
      if (!job) break;
      this.running += 1;
      void this.run(job).finally(() => {
        this.running -= 1;
        this.pump();
        if (this.pendingWrites === 0) {
          const waiters = this.idleWaiters;
          this.idleWaiters = [];
          for (const wake of waiters) wake();
        }
      });
    }
  }

  private async run(job: Job): Promise<void> {
    const entry = this.tracked.get(job.id);
    if (!entry) return;
    if (job.kind === "close") {
      try {
        if (entry.end)
          await this.sink.close({ id: entry.open.id, ownerId: entry.open.ownerId, ...entry.end });
      } catch (error) {
        this.failed("close", error);
      } finally {
        this.tracked.delete(job.id);
      }
      return;
    }
    // One insert when the connection already ended (coalesced).
    const coalesced = entry.end !== undefined;
    entry.state = "writing";
    let ok = false;
    try {
      ok =
        (await this.sink.open(coalesced ? { ...entry.open, end: entry.end } : entry.open)) === true;
    } catch (error) {
      this.failed("open", error);
    }
    if (!ok || coalesced) {
      this.tracked.delete(job.id);
      return;
    }
    if (entry.end) {
      entry.state = "closing";
      this.queue.push({ kind: "close", id: job.id });
    } else entry.state = "written";
  }

  private failed(kind: "open" | "close", error: unknown) {
    if (!this.failures.take()) return;
    console.warn(`[sandbox-connect] audit ${kind} write failed:`, {
      ...safeErrorLog(error, "connect_audit_failed"),
      suppressed: this.failures.suppressed,
    });
  }

  private log(what: "opened" | "closed", fields: Record<string, string | number>) {
    if (!this.lines.take()) return;
    const suppressed = this.lines.suppressed;
    console.info(`[sandbox-connect] connection ${what}:`, {
      ...fields,
      ...(suppressed > 0 ? { suppressed } : {}),
    });
  }
}
