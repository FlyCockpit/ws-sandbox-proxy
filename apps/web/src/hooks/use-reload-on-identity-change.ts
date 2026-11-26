import { useLayoutEffect } from "react";

import { useAuthSession } from "@/hooks/use-auth-session";
import type { AuthSessionState } from "@/lib/auth-session-state";
import {
  announceDocumentIdentity,
  connectIdentityPeers,
  observeDocumentIdentity,
  replaceDocument,
  type SessionIdentity,
} from "@/lib/document-identity";

/**
 * `undefined` (session pending or errored) is never acted on: a flaky session
 * check must not reload a signed-in user's page.
 */
export function sessionIdentity(
  state: AuthSessionState<{ user: { id: string } }>["state"],
): SessionIdentity {
  if (state.status === "authenticated") return state.session.user.id;
  if (state.status === "anonymous") return null;
  return undefined;
}

/**
 * Replaces the document when the signed-in user goes away while a page is
 * open (sign-out in another tab, session expiry or revocation, another account
 * signing in). The identity the document belongs to lives in
 * `lib/document-identity.ts`, not here, so it survives this watcher
 * unmounting; the route guards (`lib/route-session.ts`) check the same
 * baseline before anything renders. Offline, degraded and refetching answers
 * are not proof of a changed identity. Mounted once by the hosted root
 * (`components/identity-boundary.tsx`) from the first account-aware page on.
 *
 * It also connects the other open tabs: an identity this tab confirms (a
 * sign-in included, which Better Auth does not broadcast) makes them check
 * their session, and a request rejected for having no session
 * (`reportSessionRejected`) checks it here.
 */
export function useReloadOnIdentityChange(): void {
  const auth = useAuthSession();
  const identity =
    auth.meta.isOffline || auth.meta.isDegraded || auth.meta.isRefetching
      ? undefined
      : sessionIdentity(auth.state);
  const { refetch } = auth.actions;

  // Connected first (effects run in order), so the first identity below is
  // already announced to the other tabs.
  useLayoutEffect(() => connectIdentityPeers(() => refetch()), [refetch]);

  // Layout effect: replace the document before the browser paints a frame
  // that pairs the new identity's chrome with the old identity's cached data.
  useLayoutEffect(() => {
    if (identity === undefined) return;
    if (observeDocumentIdentity(identity)) {
      replaceDocument();
      return;
    }
    announceDocumentIdentity(identity);
  }, [identity]);
}
