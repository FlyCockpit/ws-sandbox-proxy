import { useEffect, useRef, useState } from "react";

import {
  CommandOutputBuffer,
  type OutputPage,
  type OutputSnapshot,
} from "@/lib/command-output-buffer";
import { isOutputExpired } from "@/lib/operation-rules";
import { isNotFound } from "@/lib/sandbox-rules";

/**
 * Incremental reader for one command's durable output (C48).
 *
 * One loop per mounted view, one request in flight at a time. While the
 * operation is in flight it polls every `liveMs`; a page that says more is
 * ready is followed at once (at most `pagesPerTick` pages per tick). The
 * operation's status is NOT this hook's business: the page reads it from the
 * operation query, which slows down once the operation settles. Output has
 * its own end — the completion watermark (`complete`) — because a settled
 * operation may still have its last chunks in flight. After the operation
 * settles the hook keeps reading until the watermark commits, for at most
 * `settledPolls` more polls, then reports `unsealed` instead of polling a
 * receipt forever — until the page reports a changed `receipt` (an uncertain
 * outcome reconciled by the host), which resumes reading.
 *
 * A request that does not answer within `requestTimeoutMs` is aborted and
 * reported as `stalled`; a failed one as `offline`. Both retry with backoff
 * and keep the text already shown. `OUTPUT_EXPIRED` (410) and not-found end
 * the loop. Unmounting (navigating away) aborts the request in flight and
 * clears every timer: reading output is read-only, so nothing is rerun and
 * nothing is left polling.
 */

export type OutputTiming = {
  liveMs: number;
  settledMs: number;
  requestTimeoutMs: number;
  maxBackoffMs: number;
  pagesPerTick: number;
  settledPolls: number;
};

export const OUTPUT_TIMING: OutputTiming = {
  liveMs: 1_500,
  settledMs: 2_000,
  requestTimeoutMs: 15_000,
  maxBackoffMs: 30_000,
  pagesPerTick: 20,
  settledPolls: 10,
};

export type OutputStatus =
  | "loading"
  | "live"
  | "complete"
  /** The operation settled but the host never sealed its output (see the hook docs). */
  | "unsealed"
  | "expired"
  | "notFound"
  | "signedOut";

export type OutputConnection = "ok" | "stalled" | "offline";

export type CommandOutputState = {
  snapshot: OutputSnapshot | null;
  status: OutputStatus;
  connection: OutputConnection;
};

export type FetchOutputPage = (
  input: { operationId: string; cursor?: string },
  options: { signal: AbortSignal },
) => Promise<OutputPage>;

export function useCommandOutput({
  operationId,
  enabled,
  settled,
  receipt,
  fetchPage,
  timing = OUTPUT_TIMING,
}: {
  operationId: string;
  /** Only commands have output; false never issues a request. */
  enabled: boolean;
  /** The operation reached a settled state (from the operation query). */
  settled: boolean;
  /**
   * Identity of the operation's receipt. An uncertain outcome can later be
   * reconciled by the host; a change resumes a reader that gave up as
   * `unsealed`, with a fresh settled-poll budget.
   */
  receipt?: string;
  fetchPage: FetchOutputPage;
  timing?: OutputTiming;
}): CommandOutputState {
  const [state, setState] = useState<CommandOutputState>({
    snapshot: null,
    status: "loading",
    connection: "ok",
  });
  // Read by the long-lived loop; synced after every render.
  const settledRef = useRef(settled);
  const fetchRef = useRef(fetchPage);
  const timingRef = useRef(timing);
  const wake = useRef<(() => void) | null>(null);
  const resume = useRef<(() => void) | null>(null);
  useEffect(() => {
    settledRef.current = settled;
    fetchRef.current = fetchPage;
    timingRef.current = timing;
  });
  // A newly settled operation is read again at once (its last chunks and
  // watermark) instead of after the rest of a live-interval wait.
  useEffect(() => {
    if (settled) wake.current?.();
  }, [settled]);
  useEffect(() => {
    if (receipt !== undefined) resume.current?.();
  }, [receipt]);

  useEffect(() => {
    if (!enabled) return;
    const buffer = new CommandOutputBuffer();
    let disposed = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController | undefined;
    let failures = 0;
    let settledPolls = 0;
    let waiting = false;
    let gaveUp = false;

    const schedule = (ms: number) => {
      waiting = true;
      timer = setTimeout(() => {
        waiting = false;
        void tick();
      }, ms);
    };
    wake.current = () => {
      if (!waiting || disposed) return;
      clearTimeout(timer);
      waiting = false;
      void tick();
    };
    resume.current = () => {
      if (disposed) return;
      settledPolls = 0;
      if (!gaveUp) return wake.current?.();
      gaveUp = false;
      void tick();
    };
    const publish = (next: Partial<CommandOutputState>) => {
      if (!disposed) setState((current) => ({ ...current, ...next }));
    };

    async function tick() {
      const t = timingRef.current;
      const settledAtStart = settledRef.current;
      let stalled = false;
      controller = new AbortController();
      const request = controller;
      const deadline = setTimeout(() => {
        stalled = true;
        request.abort();
      }, t.requestTimeoutMs);
      try {
        let page: OutputPage | null = null;
        let pages = 0;
        do {
          const cursor = buffer.snapshot().cursor ?? undefined;
          page = await fetchRef.current(
            cursor === undefined ? { operationId } : { operationId, cursor },
            { signal: request.signal },
          );
          if (disposed) return;
          buffer.apply(page);
          pages += 1;
        } while (page.hasMore && pages < t.pagesPerTick);
        clearTimeout(deadline);
        failures = 0;
        const snapshot = buffer.snapshot();
        if (snapshot.complete && !page.hasMore) {
          publish({ snapshot, status: "complete", connection: "ok" });
          return;
        }
        if (page.hasMore) {
          publish({ snapshot, status: "live", connection: "ok" });
          schedule(0);
          return;
        }
        if (settledAtStart) {
          settledPolls += 1;
          if (settledPolls >= t.settledPolls) {
            gaveUp = true;
            publish({ snapshot, status: "unsealed", connection: "ok" });
            return;
          }
        }
        publish({ snapshot, status: "live", connection: "ok" });
        schedule(settledRef.current ? t.settledMs : t.liveMs);
      } catch (error) {
        clearTimeout(deadline);
        if (disposed) return;
        if (
          error &&
          typeof error === "object" &&
          (("code" in error && error.code === "UNAUTHORIZED") ||
            ("status" in error && error.status === 401))
        ) {
          publish({ snapshot: null, status: "signedOut", connection: "ok" });
          return;
        }
        if (isOutputExpired(error)) {
          publish({ status: "expired", connection: "ok" });
          return;
        }
        if (isNotFound(error)) {
          publish({ status: "notFound", connection: "ok" });
          return;
        }
        failures += 1;
        publish({ connection: stalled ? "stalled" : "offline" });
        schedule(Math.min(t.liveMs * 2 ** failures, t.maxBackoffMs));
      }
    }

    void tick();
    return () => {
      disposed = true;
      wake.current = null;
      resume.current = null;
      clearTimeout(timer);
      controller?.abort();
    };
  }, [enabled, operationId]);

  return state;
}
