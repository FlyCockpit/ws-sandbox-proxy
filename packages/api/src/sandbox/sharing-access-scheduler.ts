/** Access sweeps have an independent timer; ordinary dispatch wakes never enter here. */
export class SharingAccessScheduler {
  private stopped = false;
  private pending = false;
  private all = false;
  private pools = new Set<string>();
  private running: Promise<void> | null = null;
  private readonly timer: ReturnType<typeof setInterval>;

  constructor(
    private readonly sweep: (
      shouldStop: () => boolean,
      pools?: ReadonlySet<string>,
    ) => Promise<unknown>,
  ) {
    this.timer = setInterval(() => this.wake(), 15_000);
    this.timer.unref?.();
    this.wake();
  }

  wake(poolId?: string) {
    if (this.stopped) return;
    this.pending = true;
    if (!poolId) this.all = true;
    else if (!this.all) {
      this.pools.add(poolId);
      if (this.pools.size > 250) {
        this.all = true;
        this.pools.clear();
      }
    }
    if (!this.running) this.running = this.drain();
  }

  private async drain() {
    try {
      while (this.pending && !this.stopped) {
        this.pending = false;
        const pools = this.all ? undefined : new Set(this.pools);
        this.all = false;
        this.pools.clear();
        try {
          await this.sweep(() => this.stopped, pools);
        } catch {
          console.error("[sharing-access] sweep failed; periodic retry pending");
        }
      }
    } finally {
      this.running = null;
    }
  }

  async stop() {
    this.stopped = true;
    clearInterval(this.timer);
    this.pools.clear();
    await this.running;
  }
}
