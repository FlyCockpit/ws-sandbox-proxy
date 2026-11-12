import { safeErrorLog } from "@wssp/api/sandbox/sensitive-errors";
/** Recovery scan interval when no dispatch work remains (matches legacy outbox poll). */
export const SANDBOX_DISPATCH_RECOVERY_POLL_MS = 2_000;

type Timer = ReturnType<typeof setTimeout>;

export type SandboxDispatchNotifierDependencies = {
  drainBatch: (shouldStop: () => boolean) => Promise<number>;
  recoveryPollMs?: number;
  setTimer?: (callback: () => void, ms: number) => Timer;
  clearTimer?: (timer: Timer) => void;
};

/**
 * One in-process loop owns outbox claims and lease recovery scans. Wakes are
 * coalesced; each pass drains bounded batches until idle, then schedules recovery.
 */
export class SandboxDispatchNotifier {
  private timer: Timer | null = null;
  private running = false;
  private completion: Promise<void> = Promise.resolve();
  private stopped = false;
  private wakeRequested = false;
  private readonly setTimer: (callback: () => void, ms: number) => Timer;
  private readonly clearTimer: (timer: Timer) => void;

  constructor(private readonly dependencies: SandboxDispatchNotifierDependencies) {
    this.setTimer = dependencies.setTimer ?? ((callback, ms) => setTimeout(callback, ms));
    this.clearTimer = dependencies.clearTimer ?? ((timer) => clearTimeout(timer));
  }

  wake() {
    if (this.stopped) return;
    if (this.running) {
      this.wakeRequested = true;
      return;
    }
    if (this.timer) this.clearTimer(this.timer);
    this.timer = null;
    this.schedule(0);
  }

  stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) this.clearTimer(this.timer);
    this.timer = null;
    return this.completion;
  }

  get isRunning() {
    return this.running;
  }

  private schedule(delayMs: number) {
    if (this.stopped || this.timer || this.running) return;
    this.timer = this.setTimer(() => {
      this.timer = null;
      this.completion = this.run();
    }, delayMs);
  }

  private async run() {
    if (this.stopped || this.running) return;
    this.running = true;
    try {
      let keepDraining = true;
      while (keepDraining && !this.stopped) {
        this.wakeRequested = false;
        const processed = await this.dependencies.drainBatch(() => this.stopped);
        if (this.wakeRequested) {
          keepDraining = true;
          continue;
        }
        keepDraining = processed > 0;
      }
    } catch (error) {
      console.error("[sandbox-relay] dispatch drain failed:", safeErrorLog(error));
    } finally {
      this.running = false;
      if (!this.stopped) {
        if (this.wakeRequested) {
          this.wakeRequested = false;
          this.schedule(0);
        } else {
          this.schedule(this.dependencies.recoveryPollMs ?? SANDBOX_DISPATCH_RECOVERY_POLL_MS);
        }
      }
    }
  }
}
