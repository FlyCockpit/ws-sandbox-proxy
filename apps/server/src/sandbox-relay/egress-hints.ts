/**
 * Relay side of blocked-name hints (template-builds B12, §6.3): an
 * `egress.refused` frame from a session that advertised
 * `egressRefusedHints`. Advisory only: a failure is logged by class and never
 * drops the session. The daemon sends at most one frame per sandbox every 2 s;
 * this throttle holds the server to the same long-run budget per connection,
 * with one frame of burst so transport jitter never drops names.
 */
import { recordBuildEgressHints } from "@wssp/api/template-builds/hints";
import { EGRESS_REFUSED_MIN_INTERVAL_MS } from "@wssp/sandbox-contracts";

const TRACKED_SANDBOXES_MAX = 1024;
/**
 * Frames a sandbox may bank. The long-run budget stays one frame per
 * interval, but a frame the network delivered early (the previous one was
 * handled late) is admitted instead of silently losing its names (E3B-01).
 */
const BURST_FRAMES = 2;

type Bucket = { tokens: number; at: number };

export class EgressHintThrottle {
  private readonly buckets = new Map<string, Bucket>();

  private refill(bucket: Bucket, nowMs: number): number {
    const earned = Math.max(0, nowMs - bucket.at) / EGRESS_REFUSED_MIN_INTERVAL_MS;
    return Math.min(BURST_FRAMES, bucket.tokens + earned);
  }

  /** Whether a frame for `sandboxId` at `nowMs` is within budget (and charge it). */
  admit(sandboxId: string, nowMs: number): boolean {
    const bucket = this.buckets.get(sandboxId);
    if (bucket === undefined && this.buckets.size >= TRACKED_SANDBOXES_MAX) {
      for (const [id, held] of this.buckets)
        if (this.refill(held, nowMs) >= BURST_FRAMES) this.buckets.delete(id);
      if (this.buckets.size >= TRACKED_SANDBOXES_MAX) return false;
    }
    const tokens = bucket === undefined ? BURST_FRAMES : this.refill(bucket, nowMs);
    if (tokens < 1) return false;
    this.buckets.delete(sandboxId);
    this.buckets.set(sandboxId, { tokens: tokens - 1, at: nowMs });
    return true;
  }
}

export async function handleEgressRefused(input: {
  hostId: string;
  sandboxId: string;
  names: readonly string[];
  throttle: EgressHintThrottle;
  nowMs: number;
}): Promise<void> {
  if (!input.throttle.admit(input.sandboxId, input.nowMs)) return;
  await recordBuildEgressHints({
    hostId: input.hostId,
    sandboxId: input.sandboxId,
    names: input.names,
  }).catch((error: unknown) => {
    console.error(
      `[sandbox-relay] egress hint failed (${error instanceof Error ? error.constructor.name : typeof error})`,
    );
  });
}
