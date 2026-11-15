import { create } from "zustand";

/**
 * Credentials minted for a dialog that was closed before the answer arrived,
 * whose automatic revoke kept failing. They are still active, so the warning
 * must outlive the page that started the mint: it lives here, in memory only,
 * tagged with the owner it belongs to. Only nonsecret strings are held (never
 * a secret, a mint result or a callback); entries of any other owner are
 * dropped when the owner changes, and everything is dropped on sign-out. Both
 * also bump an epoch so a cleanup still running from before cannot re-add
 * its entry afterwards. `useOrphanOwnerSync` reports the owner from the app
 * shell, so this holds whether or not a credential page is mounted.
 */

export type OrphanScope = "hostToken" | "sdkKey" | "agentToken";
export type OrphanEntry = { ownerId: string; scope: OrphanScope; id: string; label: string };

/** At most this many unrevoked orphans are kept per owner and scope. */
export const ORPHAN_QUEUE_MAX = 10;

type OrphanQueueState = {
  entries: readonly OrphanEntry[];
  /** The signed-in owner last reported (`undefined` until the session is known). */
  ownerId: string | null | undefined;
  /**
   * Bumped on sign-out and on every owner change. A cleanup that outlives the
   * page records the epoch it started in; a stale one may not add anything.
   */
  epoch: number;
  add: (entry: OrphanEntry, epoch: number) => void;
  remove: (scope: OrphanScope, id: string) => void;
  /** Keep only `ownerId`'s entries; `null` (signed out) keeps none. */
  syncOwner: (ownerId: string | null) => void;
  clear: () => void;
};

export const useOrphanCredentials = create<OrphanQueueState>()((set) => ({
  entries: [],
  ownerId: undefined,
  epoch: 0,
  add: (entry, epoch) =>
    set((state) => {
      if (epoch !== state.epoch) return state;
      if (state.ownerId !== undefined && state.ownerId !== entry.ownerId) return state;
      const same = (item: OrphanEntry) =>
        item.ownerId === entry.ownerId && item.scope === entry.scope;
      if (state.entries.some((item) => same(item) && item.id === entry.id)) return state;
      if (state.entries.filter(same).length >= ORPHAN_QUEUE_MAX) return state;
      const copy: OrphanEntry = {
        ownerId: String(entry.ownerId),
        scope: entry.scope,
        id: String(entry.id),
        label: String(entry.label),
      };
      return { entries: [...state.entries, copy] };
    }),
  remove: (scope, id) =>
    set((state) => ({
      entries: state.entries.filter((item) => !(item.scope === scope && item.id === id)),
    })),
  syncOwner: (ownerId) =>
    set((state) => {
      if (state.ownerId === ownerId) return state;
      // The first report only learns who is signed in; it invalidates nothing.
      const changed = state.ownerId !== undefined;
      return {
        ownerId,
        epoch: changed ? state.epoch + 1 : state.epoch,
        entries: state.entries.filter((item) => item.ownerId === ownerId),
      };
    }),
  clear: () => set((state) => ({ entries: [], ownerId: null, epoch: state.epoch + 1 })),
}));
