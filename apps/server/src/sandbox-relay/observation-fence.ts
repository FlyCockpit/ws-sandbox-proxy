/**
 * WP2 follow-up (`observationFence`): orders connected evidence against the
 * lifecycle results of one relay session.
 *
 * A targeted observation reads a VM's state and then attaches its lease. A
 * reconnect admitted before that read installs its new lease first, so the
 * entry can say "stopped" under the current arm; if the reconnect's READY
 * result reaches the server before the queued observation, judging that
 * entry would downgrade a running VM and release its capacity. Host trust
 * does not help: a correct daemon produces that frame.
 *
 * The daemon numbers each offered observation (shared by its batches) and
 * starts one only after every batch of the previous one was acknowledged.
 * Frames are applied in arrival order on the session lane, so when a
 * lifecycle result for a sandbox arrives while observation `n` is the last
 * one received, only observations up to `n + 1` (the one possibly in
 * flight) can have begun before that result was built: the next one starts
 * after the server answered `n + 1`, which it does after the result. Those
 * are fenced for that sandbox; later observations are not.
 *
 * Results from before `reconcile.complete` are not recorded: the daemon
 * observes only after it sent that frame. The table is bounded: entries
 * that can no longer fence anything are pruned as observations advance, and
 * an overflow raises a session-wide floor instead (fences more, never less).
 */
const OBSERVATION_FENCE_MAX_SANDBOXES = 4096;

export class ObservationFence {
  /** The last observation received on this session (0: none yet). */
  private last = 0;
  /** Observations at or below this are fenced for every sandbox. */
  private floor = 0;
  /** Per sandbox: the newest observation that may predate a result for it,
   * in insertion order (bounds are non-decreasing in that order). */
  private readonly fenced = new Map<string, number>();

  constructor(private readonly cap = OBSERVATION_FENCE_MAX_SANDBOXES) {}

  /** A lifecycle result (or receipt) for `sandboxId` arrived. */
  noteResult(sandboxId: string) {
    this.fenced.delete(sandboxId);
    this.fenced.set(sandboxId, this.last + 1);
    if (this.fenced.size > this.cap) {
      const [oldest, bound] = this.fenced.entries().next().value as [string, number];
      this.fenced.delete(oldest);
      this.floor = Math.max(this.floor, bound);
    }
  }

  /** An observation-numbered batch arrived. The server never trusts the
   * daemon's numbering beyond its contract: a session's first observation is
   * 1 and each new one is exactly the previous plus one (further batches of
   * the current observation repeat its number). Anything else, a jump past
   * a fenced observation included, is refused (`false`: a protocol
   * violation), since a jump would skip the bound a result just set. */
  accept(observation: number): boolean {
    const repeat = this.last > 0 && observation === this.last;
    if (!repeat && observation !== this.last + 1) return false;
    if (observation > this.last) {
      this.last = observation;
      for (const [id, bound] of this.fenced) if (bound < observation) this.fenced.delete(id);
    }
    return true;
  }

  /** Whether `observation` may have begun before a lifecycle result for
   * `sandboxId` that this session already received. */
  predates(sandboxId: string, observation: number): boolean {
    return observation <= this.floor || observation <= (this.fenced.get(sandboxId) ?? 0);
  }

  /** Entries held (tests). */
  get size() {
    return this.fenced.size;
  }
}
