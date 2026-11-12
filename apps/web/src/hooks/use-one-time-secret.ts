import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { useOrphanOwnerSync } from "@/hooks/use-orphan-owner-sync";
import { type OrphanScope, useOrphanCredentials } from "@/stores/orphan-credentials";

/**
 * One-time credential reveal (C45). The raw secret lives ONLY in this hook's
 * component state: mints call the oRPC client directly (never a TanStack
 * query or mutation, whose caches outlive the component), nothing is written
 * to storage, the URL or logs, and the secret is dropped when:
 *  - the owner dismisses the reveal explicitly (`clear`),
 *  - the component unmounts (route navigation),
 *  - the page is hidden/unloaded (`pagehide`, so a back-forward-cache restore
 *    cannot show it again). This also fences a mint still in flight: its
 *    answer is discarded, never revealed on the restored page.
 *
 * The owning PAGE holds this hook and shows the secret inline (M7-S4), so a
 * stray Escape on the mint dialog cannot lose it. A mint still in flight when
 * its dialog is cancelled (`discardPending`) or the page goes away is
 * discarded: its result is never revealed and the orphaned credential is
 * revoked by ID, retried a bounded number of times. A revoke that still fails
 * is queued for the owner (nonsecret ID and label only, see
 * `stores/orphan-credentials`) and listed in `orphans`, so the page says so
 * and offers a manual revoke, also after navigating away and back.
 * `discardPending` leaves an already shown secret alone.
 */
export type Revealed<M> = { secret: string; meta: M };
export type OneTimeSecret<M> = ReturnType<typeof useOneTimeSecret<M>>;

/** What a discarded mint leaves behind: nonsecret ID and label only. */
export type Orphan = { id: string; label: string };

/** Waits before the 2nd and 3rd automatic revoke attempts. */
export const ORPHAN_REVOKE_RETRY_MS = [500, 1_500] as const;

/** A revoke answered NOT_FOUND means the credential is already gone. */
function alreadyGone(error: unknown): boolean {
  const shape = (error && typeof error === "object" ? error : {}) as {
    code?: unknown;
    status?: unknown;
  };
  return shape.code === "NOT_FOUND" || shape.status === 404;
}

async function revokeOnce(revoke: (id: string) => Promise<unknown>, id: string) {
  try {
    await revoke(id);
    return true;
  } catch (error) {
    return alreadyGone(error);
  }
}

export function useOneTimeSecret<M>({
  scope,
  revoke,
}: {
  /** Which credential kind this page mints (keys the owner's orphan queue). */
  scope: OrphanScope;
  /** Revoke by ID. Never given a mint result, so nothing it retains is secret. */
  revoke: (id: string) => Promise<unknown>;
}) {
  const [revealed, setRevealed] = useState<Revealed<M> | null>(null);
  const session = useRef(0);
  const ownerId = useOrphanOwnerSync();
  const owner = useRef(ownerId);
  const revokeRef = useRef(revoke);
  useEffect(() => {
    owner.current = ownerId;
    revokeRef.current = revoke;
  });
  const entries = useOrphanCredentials((state) => state.entries);
  const orphans = useMemo<Orphan[]>(
    () =>
      ownerId === null
        ? []
        : entries
            .filter((item) => item.ownerId === ownerId && item.scope === scope)
            .map(({ id, label }) => ({ id, label })),
    [entries, ownerId, scope],
  );

  useEffect(() => {
    const drop = () => {
      session.current += 1;
      setRevealed(null);
    };
    window.addEventListener("pagehide", drop);
    return () => {
      window.removeEventListener("pagehide", drop);
      session.current += 1;
    };
  }, []);

  const clear = useCallback(() => {
    session.current += 1;
    setRevealed(null);
  }, []);

  const discardPending = useCallback(() => {
    session.current += 1;
  }, []);

  /**
   * Bounded automatic revoke of a discarded mint. It may outlive the page, so
   * a failure is queued under the owner who minted it, not in page state.
   */
  const revokeOrphan = useCallback(
    async (
      orphan: Orphan,
      mintedBy: string | null,
      epoch: number,
      revokeById: (id: string) => Promise<unknown>,
    ) => {
      for (let attempt = 0; ; attempt++) {
        if (await revokeOnce(revokeById, orphan.id)) return true;
        const wait = ORPHAN_REVOKE_RETRY_MS[attempt];
        if (wait === undefined) break;
        await new Promise((resolve) => setTimeout(resolve, wait));
      }
      if (mintedBy !== null)
        useOrphanCredentials.getState().add({ ownerId: mintedBy, scope, ...orphan }, epoch);
      return false;
    },
    [scope],
  );

  /** Manual retry from the page; true once the orphan is revoked (or gone). */
  const retryOrphan = useCallback(
    async (id: string) => {
      if (!(await revokeOnce(revokeRef.current, id))) return false;
      useOrphanCredentials.getState().remove(scope, id);
      return true;
    },
    [scope],
  );

  const run = useCallback(
    async <R>(
      mint: () => Promise<R>,
      pick: (result: R) => Revealed<M>,
      onDiscard: (result: R) => Orphan,
    ): Promise<"revealed" | "discarded"> => {
      const mine = session.current;
      const mintedBy = owner.current;
      // A sign-out or owner change after this point voids the cleanup's report.
      const epoch = useOrphanCredentials.getState().epoch;
      const revokeById = revokeRef.current;
      const result = await mint();
      if (session.current !== mine) {
        const { id, label } = onDiscard(result);
        void revokeOrphan({ id: String(id), label: String(label) }, mintedBy, epoch, revokeById);
        return "discarded";
      }
      setRevealed(pick(result));
      return "revealed";
    },
    [revokeOrphan],
  );

  return { revealed, run, clear, discardPending, orphans, retryOrphan };
}
