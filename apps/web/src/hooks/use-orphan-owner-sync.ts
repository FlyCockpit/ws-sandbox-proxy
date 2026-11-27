import { useEffect, useSyncExternalStore } from "react";

import { useAuthSession } from "@/hooks/use-auth-session";
import { documentIdentityBaseline, subscribeIdentityVerification } from "@/lib/document-identity";
import { useOrphanCredentials } from "@/stores/orphan-credentials";

/**
 * Report the signed-in owner to the orphaned-credential queue (see
 * `stores/orphan-credentials`). Mounted by the app shell so a sign-out or an
 * owner change invalidates pending cleanups even with no credential page open.
 * Returns the owner ID, or null when not (yet) signed in.
 *
 * Bookkeeping, never painted, so it reads the session unmasked (a masked,
 * unverified render must not drop the owner a mint is recorded under), and
 * the owner is the account this document was admitted as whenever a guard
 * admitted one: the atom may still retain another account read before any
 * guard ran (lib/document-identity.ts `documentIdentityBaseline`). A confirmed
 * sign-out still clears it; a confirmed other account replaces the document.
 */
export function useOrphanOwnerSync(): string | null {
  const auth = useAuthSession({ unmasked: true });
  const admitted = useSyncExternalStore(
    subscribeIdentityVerification,
    documentIdentityBaseline,
    () => undefined,
  );
  const signedOut = auth.state.status === "anonymous";
  const sessionOwner = auth.state.status === "authenticated" ? auth.state.session.user.id : null;
  const ownerId = signedOut ? null : typeof admitted === "string" ? admitted : sessionOwner;
  useEffect(() => {
    if (ownerId !== null || signedOut) useOrphanCredentials.getState().syncOwner(ownerId);
  }, [ownerId, signedOut]);
  return ownerId;
}
