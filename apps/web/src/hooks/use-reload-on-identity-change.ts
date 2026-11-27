import { useLayoutEffect, useRef, useSyncExternalStore } from "react";

import {
  isSessionFetchInFlight,
  readSessionIdentity,
  useAuthSession,
} from "@/hooks/use-auth-session";
import type { AuthSessionState } from "@/lib/auth-session-state";
import {
  announceDocumentIdentity,
  confirmDocumentIdentityFresh,
  connectIdentityPeers,
  documentAdmissions,
  documentIdentityBaseline,
  holdDocumentIdentityUnverified,
  identityVerificationGeneration,
  isDocumentIdentityUnverified,
  observeDocumentIdentity,
  replaceDocument,
  type SessionIdentity,
  subscribeIdentityVerification,
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

type IdentityChecks = {
  leftAccountPage: () => void;
  reconcile: () => void;
  stop: () => void;
};

/**
 * The watcher's session checks while it is mounted: for a peer tab's
 * announcement, a 401, and an unverified identity (another tab announced a
 * change, or a request got a 401, while no watcher was mounted: the chrome
 * shows no account until a check settles it). Only a check started here can
 * settle that state: Better Auth's refetch cancels any fetch already in
 * flight, so the answer it settles with was asked for after `since`, never
 * inherited from before a newer invalidation. A check that gets no settled
 * answer (failed, or still superseded after the follow-ups) leaves the identity
 * unverified, even when it was run for a peer's announcement or a 401 with the
 * identity still trusted: this boundary stays mounted across public pages, so
 * no remount would check it again. One run for a peer or a 401 while no
 * account-aware page is showing (`showsAccount`) holds it unverified from the
 * start, so an app page entered while it runs shows no account either; on an
 * account page the chrome already on screen stays until the answer (no flicker
 * for every tab that confirms its identity); leaving the account pages while
 * one runs (`leftAccountPage`) holds it then. A failed check is retried when the tab
 * regains focus, visibility or the network; one superseded by another fetch
 * still running is followed up (at most 3 times, 250 ms apart). `stop()` drops
 * every pending completion, timer and listener.
 */
function startIdentityChecks(refetch: () => unknown, showsAccount: () => boolean): IdentityChecks {
  let connected = true;
  let followUp: ReturnType<typeof setTimeout> | undefined;
  let running = 0;
  const check = (superseded = 0): Promise<void> => {
    if (!connected) return Promise.resolve();
    const since = identityVerificationGeneration();
    running++;
    return Promise.resolve(refetch())
      .finally(() => {
        running--;
      })
      .then(() => {
        if (!connected) return;
        const checked = readSessionIdentity();
        if (checked === undefined) {
          if (isSessionFetchInFlight() && superseded < 3) {
            clearTimeout(followUp);
            followUp = setTimeout(() => {
              followUp = undefined;
              void check(superseded + 1);
            }, 250);
          } else {
            holdDocumentIdentityUnverified();
          }
          return;
        }
        if (observeDocumentIdentity(checked)) {
          replaceDocument();
          return;
        }
        confirmDocumentIdentityFresh(since);
        announceDocumentIdentity(checked);
      });
  };
  const retry = () => {
    if (isDocumentIdentityUnverified() && document.visibilityState !== "hidden") void check();
  };
  const disconnectPeers = connectIdentityPeers(() => {
    if (!showsAccount()) holdDocumentIdentityUnverified();
    return check();
  });
  if (isDocumentIdentityUnverified()) void check();
  window.addEventListener("focus", retry);
  window.addEventListener("online", retry);
  document.addEventListener("visibilitychange", retry);
  return {
    reconcile: () => {
      holdDocumentIdentityUnverified();
      void check();
    },
    leftAccountPage: () => {
      // A check still running (or about to follow up) was started on an
      // account page, unmasked: the next app page entered before it answers
      // must not show the previous account.
      if (running > 0 || followUp !== undefined) holdDocumentIdentityUnverified();
    },
    stop: () => {
      connected = false;
      clearTimeout(followUp);
      disconnectPeers();
      window.removeEventListener("focus", retry);
      window.removeEventListener("online", retry);
      document.removeEventListener("visibilitychange", retry);
    },
  };
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
 * (`reportSessionRejected`) checks it here. It reads the session unmasked:
 * while the identity is unverified every other reader sees `pending`, and the
 * watcher must still see the answer that settles it.
 */
export function useReloadOnIdentityChange({
  showsAccount,
}: {
  /** An account-aware (`/$lang/_app`) page is showing, not a public one. */
  showsAccount: boolean;
}): void {
  const auth = useAuthSession({ unmasked: true });
  const identity =
    auth.meta.isOffline || auth.meta.isDegraded || auth.meta.isRefetching
      ? undefined
      : sessionIdentity(auth.state);
  const { refetch } = auth.actions;

  // Connected first (effects run in order), so the first identity below is
  // already announced to the other tabs.
  const showsAccountNow = useRef(showsAccount);
  const checks = useRef<IdentityChecks | undefined>(undefined);
  useLayoutEffect(() => {
    const watcher = startIdentityChecks(refetch, () => showsAccountNow.current);
    checks.current = watcher;
    return () => {
      watcher.stop();
      if (checks.current === watcher) checks.current = undefined;
    };
  }, [refetch]);
  useLayoutEffect(() => {
    showsAccountNow.current = showsAccount;
    if (!showsAccount) checks.current?.leftAccountPage();
  }, [showsAccount]);

  // The atom holds another account than the one this document was admitted
  // as, and it is not a fresh answer the identity effect below can act on:
  // retained by failed or running refreshes (`identity` unknown) while a guard
  // admitted someone else, or inherited from before this watcher existed (a
  // public page's language menu) where adopting it over an anonymous
  // admission would be wrong. Held unverified and checked instead (a failed
  // check is retried on focus, visibility and reconnect as usual). A fresh
  // answer while mounted is the identity effect's: another account replaces
  // the document at once, a sign-in over anonymous is adopted. Likewise a
  // session fetch still running when anonymity is admitted (each admission,
  // a repeat included, or at mount over it): it was asked before that admission (a session revoked since), so its
  // answer must not be adopted as a sign-in; the watcher's own check
  // supersedes it (Better Auth keeps only the latest request's answer). The
  // chrome shows no account during such a fetch anyway. Before the identity
  // effect, so it sees the hold.
  const held = auth.state.status === "authenticated" ? auth.state.session.user.id : undefined;
  const admitted = useSyncExternalStore(
    subscribeIdentityVerification,
    documentIdentityBaseline,
    () => undefined,
  );
  const admissions = useSyncExternalStore(
    subscribeIdentityVerification,
    documentAdmissions,
    () => 0,
  );
  const mounting = useRef(true);
  const lastAdmissions = useRef(0);
  useLayoutEffect(() => {
    const inherited = mounting.current && admitted === null;
    const admittedNow = mounting.current || lastAdmissions.current !== admissions;
    mounting.current = false;
    lastAdmissions.current = admissions;
    if (admitted === null && held === undefined && admittedNow && isSessionFetchInFlight()) {
      checks.current?.reconcile();
      return;
    }
    if (held === undefined || admitted === undefined || held === admitted) return;
    if (identity === undefined || inherited) checks.current?.reconcile();
  }, [held, admitted, admissions, identity]);

  // Layout effect: replace the document before the browser paints a frame
  // that pairs the new identity's chrome with the old identity's cached data.
  // While the identity is unverified only the watcher's own checks (which
  // observe their answers themselves) decide: the atom's snapshot may be the
  // inherited or retained one they are checking.
  useLayoutEffect(() => {
    if (identity === undefined || isDocumentIdentityUnverified()) return;
    if (observeDocumentIdentity(identity)) {
      replaceDocument();
      return;
    }
    announceDocumentIdentity(identity);
  }, [identity]);
}
