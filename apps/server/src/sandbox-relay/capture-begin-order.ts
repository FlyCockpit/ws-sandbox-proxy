import prisma from "@wssp/db";
import type { DaemonImageMessage } from "@wssp/sandbox-contracts";
import type { RelaySender } from "./operation-handlers.js";

type CaptureBegin = Extract<DaemonImageMessage, { type: "image.upload.begin" }>;

/** Capture begins one connection holds at most; another is handled at once. */
export const CAPTURE_BEGINS_HELD_MAX = 16;

/**
 * Capture begin ordering (post-landing #4): a capture whose export is
 * instant can have its `image.upload.begin` reach the server before its own
 * `operation.result`, and the begin needs the capture's architecture from
 * that result. Both frames come over the same connection and are handled in
 * order, so a begin of a capture still waiting for its host result is held
 * here and handled right after that operation's result (or receipt) on this
 * connection. Per connection, bounded; a re-sent begin of the same capture
 * replaces the held one. Dropped with the connection (the daemon sends a
 * begin lost with it again once resumed).
 */
export class CaptureBeginOrder {
  private readonly held = new Map<string, CaptureBegin>();

  /** Hold `m` if it is a capture begin whose result is still pending
   * (`held`); `handle` it now otherwise; `retry` when the lookup failed: the
   * caller refuses it `store_unavailable`, which the daemon retries (handled
   * now it would be refused `unknown_architecture` for good if its result
   * is still queued behind it; held, nothing might ever release it). */
  async hold(sender: RelaySender, m: CaptureBegin): Promise<"held" | "handle" | "retry"> {
    if (m.operationId === undefined || m.attempt === undefined) return "handle";
    const key = `${m.operationId}#${m.attempt}`;
    if (!this.held.has(key) && this.held.size >= CAPTURE_BEGINS_HELD_MAX) return "handle";
    let pending: boolean;
    try {
      pending = await captureResultPending(sender, m.operationId, m.attempt);
    } catch {
      return "retry";
    }
    if (!pending) {
      // Handled now: an older held copy of it goes.
      this.held.delete(key);
      return "handle";
    }
    this.held.set(key, m);
    return "held";
  }

  /** The held begins of `operationId`, removed (any attempt: each is fenced again). */
  release(operationId: string): CaptureBegin[] {
    const released: CaptureBegin[] = [];
    for (const [key, begin] of this.held)
      if (begin.operationId === operationId) {
        released.push(begin);
        this.held.delete(key);
      }
    return released;
  }

  get size(): number {
    return this.held.size;
  }
}

/**
 * The capture of `operationId` / `attempt` runs on this host and connection
 * and its host result is not recorded yet (PENDING, no architecture): a begin
 * for it would be refused `unknown_architecture`. Owner-agnostic read of the
 * sender's own capture; it only decides whether to hold the frame.
 */
export async function captureResultPending(
  sender: RelaySender,
  operationId: string,
  attempt: number,
): Promise<boolean> {
  const pending = await prisma.sandboxTemplateCapture.count({
    where: {
      operationId,
      hostId: sender.hostId,
      state: "PENDING",
      architecture: null,
      capturedAt: null,
      Operation: {
        is: {
          dispatchAttempt: attempt,
          dispatchedConnectionEpoch: sender.connectionEpoch,
          state: { in: ["ACCEPTED", "RUNNING"] },
        },
      },
    },
  });
  return pending > 0;
}
