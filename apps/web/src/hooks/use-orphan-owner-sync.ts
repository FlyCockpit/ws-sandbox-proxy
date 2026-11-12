import { useEffect } from "react";

import { useAuthSession } from "@/hooks/use-auth-session";
import { useOrphanCredentials } from "@/stores/orphan-credentials";

/**
 * Report the signed-in owner to the orphaned-credential queue (see
 * `stores/orphan-credentials`). Mounted by the app shell so a sign-out or an
 * owner change invalidates pending cleanups even with no credential page open.
 * Returns the owner ID, or null when not (yet) signed in.
 */
export function useOrphanOwnerSync(): string | null {
  const auth = useAuthSession();
  const ownerId = auth.state.status === "authenticated" ? auth.state.session.user.id : null;
  const signedOut = auth.state.status === "anonymous";
  useEffect(() => {
    if (ownerId !== null || signedOut) useOrphanCredentials.getState().syncOwner(ownerId);
  }, [ownerId, signedOut]);
  return ownerId;
}
