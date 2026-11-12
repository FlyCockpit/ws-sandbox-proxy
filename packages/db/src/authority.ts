/** Single control-plane process: changes fence reads BEFORE starting database IO.
 * No database lock is held across socket IO. Tickets are checked synchronously
 * immediately before an effect; a ticket sampled during a change never grants.
 * Durable rows remain authoritative after restart and at every active boundary.
 */
/** At least one identity is required: an unscoped ticket or change is unrepresentable. */
export type AuthorityScope =
  | { ownerId: string; hostId?: string; credentialId?: string }
  | { ownerId?: string; hostId: string; credentialId?: string }
  | { ownerId?: string; hostId?: string; credentialId: string };

export type CommittedAuthorityScope = { kind: "global" } | ({ kind: "scoped" } & AuthorityScope);

let globalRevision = 0;
let globalChanging = 0;
const committedListeners = new Set<(scope: CommittedAuthorityScope) => void>();
const versions = new Map<string, { revision: number; changing: number }>();

function version(key: string) {
  let state = versions.get(key);
  if (!state) {
    state = { revision: 0, changing: 0 };
    versions.set(key, state);
  }
  return state;
}

function resourceKey(kind: "host" | "credential", id: string, ownerId?: string): string {
  return JSON.stringify([kind, ownerId ?? null, id]);
}

function scopedVersionKeys(scope: AuthorityScope): string[] {
  const keys: string[] = [];
  if (scope.ownerId !== undefined) keys.push(`owner:${scope.ownerId}`);
  for (const [kind, id] of [
    ["host", scope.hostId],
    ["credential", scope.credentialId],
  ] as const) {
    if (id === undefined) continue;
    keys.push(resourceKey(kind, id));
    if (scope.ownerId !== undefined) keys.push(resourceKey(kind, id, scope.ownerId));
  }
  return keys;
}

function notifyCommitted(scope: CommittedAuthorityScope) {
  queueMicrotask(() => {
    for (const listener of committedListeners) {
      try {
        listener(scope);
      } catch {
        /* Isolate listener failures. */
      }
    }
  });
}

/** Every ticket requires an explicit scope and includes the global policy generation. */
export function authorityTicket(scope: AuthorityScope): () => boolean {
  const keys = scopedVersionKeys(scope);
  if (keys.length === 0)
    throw new Error("Authority ticket requires an owner, host, or credential scope.");
  const globalSampled = globalRevision;
  const globalAvailable = globalChanging === 0;
  // Sampling never allocates: tickets name caller-supplied ids, and an entry per
  // id ever asked about would grow without bound. Only changes create entries,
  // so a key absent at sampling is still current exactly while it stays absent.
  const snapshots = keys.map((key) => {
    const state = versions.get(key);
    return state
      ? { key, state, sampled: state.revision, available: state.changing === 0 }
      : { key, state: undefined, sampled: 0, available: true };
  });
  return () => {
    if (!globalAvailable || globalChanging !== 0 || globalRevision !== globalSampled) return false;
    return snapshots.every(({ key, state, sampled, available }) => {
      if (!state) return !versions.has(key);
      return available && state.changing === 0 && state.revision === sampled;
    });
  };
}

/** Number of tracked authority keys; exposed so tests can prove reads do not allocate. */
export function trackedAuthorityKeyCount(): number {
  return versions.size;
}

export function onAuthorityCommitted(
  listener: (scope: CommittedAuthorityScope) => void,
): () => void {
  committedListeners.add(listener);
  return () => committedListeners.delete(listener);
}

/** Invalidates every in-process authority ticket (global policy such as forced 2FA). */
export async function withGlobalAuthorityChange<T>(change: () => Promise<T>): Promise<T> {
  globalRevision += 1;
  globalChanging += 1;
  try {
    return await change();
  } finally {
    globalChanging -= 1;
    globalRevision += 1;
    notifyCommitted({ kind: "global" });
  }
}

/**
 * A scoped authority change whose in-flight mark is released by settle().
 * Callers wrapping a database transaction settle ONLY after that transaction
 * commits or rolls back: a ticket sampled between the change's statements and
 * the commit must never authorize against pre-commit state (e.g. a host
 * deletion whose allowlist cascade is still uncommitted).
 */
export type AuthorityChangeHold = {
  /** Idempotent: the in-flight mark is released exactly once. */
  settle(committed?: boolean): void;
};

export function holdAuthorityChange(scope: AuthorityScope): AuthorityChangeHold {
  // Bump the most specific key for EVERY id in the scope, so a ticket scoped to any
  // named host or credential observes the change (an owner-only change bumps the owner).
  const keys: string[] = [];
  if (scope.credentialId !== undefined)
    keys.push(resourceKey("credential", scope.credentialId, scope.ownerId));
  if (scope.hostId !== undefined) keys.push(resourceKey("host", scope.hostId, scope.ownerId));
  if (keys.length === 0 && scope.ownerId !== undefined) keys.push(`owner:${scope.ownerId}`);
  if (keys.length === 0) {
    throw new Error("Authority change requires an owner, host, or credential scope.");
  }
  const states = keys.map(version);
  for (const state of states) {
    state.revision += 1;
    state.changing += 1;
  }
  let settled = false;
  return {
    settle(committed = true) {
      if (settled) return;
      settled = true;
      for (const state of states) {
        state.changing -= 1;
        state.revision += 1;
      }
      if (committed) notifyCommitted({ kind: "scoped", ...scope });
    },
  };
}

export async function withAuthorityChange<T>(
  scope: AuthorityScope,
  change: () => Promise<T>,
): Promise<T> {
  const hold = holdAuthorityChange(scope);
  try {
    return await change();
  } finally {
    hold.settle();
  }
}
