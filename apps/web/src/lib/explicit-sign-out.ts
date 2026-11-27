import { leaveDocument, markExplicitSignOut } from "@/lib/document-identity";
import { isBrowserOffline, isFetchFailure } from "@/lib/network-failure";

export function signOutFailureKey(
  error: unknown,
): "userMenu.signOutOffline" | "userMenu.signOutFailed" {
  return isBrowserOffline() || isFetchFailure(error)
    ? "userMenu.signOutOffline"
    : "userMenu.signOutFailed";
}

export type ExplicitSignOutResult = { ok: true } | { ok: false; error: unknown };

/**
 * The one explicit sign-out: mark it (so the identity watcher leaves the page
 * load to it), sign out, and only once that succeeded load `href` (the
 * localized sign-in page) as a new, quarantined document (`leaveDocument`:
 * the page is hidden and the query cache and other in-memory private state
 * dropped first). A failure, returned or thrown, undoes the mark (still
 * signed in here; if the identity changed meanwhile anyway, the undo replaces
 * the document) and is returned for the caller's feedback. `disableRedirect`
 * keeps the OAuth provider plugin from redirecting the sign-out itself (the
 * MCP re-authentication keeps its signed transaction in `href`). Every
 * sign-out button goes through this. docs/design/shell-rules.md § Query cache
 * follows identity.
 */
export async function signOutAndLeave(
  href: string,
  options?: { disableRedirect: true },
): Promise<ExplicitSignOutResult> {
  // Dynamic import keeps the sign-out path out of its callers' chunks; the
  // auth client is already warm once a signed-in page offers it.
  const { authClient } = await import("@/lib/auth-client");
  const undo = markExplicitSignOut();
  try {
    const result = await authClient.signOut(options);
    if (result.error) {
      undo();
      return { ok: false, error: result.error };
    }
  } catch (error) {
    undo();
    return { ok: false, error };
  }
  leaveDocument(href);
  return { ok: true };
}
