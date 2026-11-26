import { useState } from "react";

import { useAuthSession } from "./use-auth-session";

/**
 * Whether the browser session has been answered (signed in or signed out) at
 * least once in this mount. Latched: a later revalidation does not unset it.
 *
 * Better Auth refetches the session after every successful `/sign-in/*`,
 * `/sign-up/*` and `/two-factor/*` call, and while it has no session data the
 * refetch reports `isPending` again (and a failing one reports an error). A
 * page that gates on the live status would swap its content for a skeleton on
 * each of those calls and lose the content's local state, such as the 2FA
 * challenge's "email me a code" mode. Gate on this instead.
 */
export function useAuthSessionSettled(): boolean {
  const { status } = useAuthSession().state;
  const [settled, setSettled] = useState(false);
  if (!settled && (status === "authenticated" || status === "anonymous")) setSettled(true);
  return settled || status === "authenticated" || status === "anonymous";
}
