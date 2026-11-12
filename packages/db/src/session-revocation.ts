/**
 * In-process notification that durable auth session rows were deleted (C53).
 *
 * Better Auth deletes the `session` row on sign-out, session revocation,
 * password change with "revoke other sessions", and the admin ban/revoke
 * flows. Long-lived browser surfaces (the terminal WebSocket) subscribe so a
 * revoked session's sockets close immediately instead of at their next
 * periodic re-read. The notification carries no authority: listeners must
 * re-read the session row from Postgres and decide from that. A missed
 * notification only delays closure to the next periodic re-read.
 */

/** `userId` when the deleted rows are known to belong to one user; else unknown (all). */
export type SessionRevocation = { userId?: string; sessionId?: string };

const listeners = new Set<(revocation: SessionRevocation) => void>();

export function onAuthSessionsRevoked(listener: (revocation: SessionRevocation) => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Called after the delete returned; listeners run on a later microtask and never throw out. */
export function notifyAuthSessionsRevoked(revocation: SessionRevocation): void {
  queueMicrotask(() => {
    for (const listener of listeners) {
      try {
        listener(revocation);
      } catch {
        /* Isolate listener failures. */
      }
    }
  });
}
