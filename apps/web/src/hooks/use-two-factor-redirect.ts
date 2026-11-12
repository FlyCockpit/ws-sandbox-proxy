import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useCallback, useEffect } from "react";

import { isTwoFactorRequiredError } from "@/lib/credential-rules";
import { orpc } from "@/utils/orpc";

/**
 * Forced-2FA takeover for pages whose procedures are `protectedProcedure`:
 * when the server answers "enroll in 2FA first" (policy turned on, or the
 * grace window ended, while the page was open), send the owner to Security
 * settings instead of showing a generic failure. The navigation re-runs the
 * `_auth` guard, which re-reads the force-2FA settings server-side; the cached
 * `settings.getAll` copy (shell nav mirror, admin nudge) is refreshed too.
 * Returns whether the error was handled.
 */
export function useTwoFactorRedirect(lang: string) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  return useCallback(
    (error: unknown): boolean => {
      if (!isTwoFactorRequiredError(error)) return false;
      void queryClient.invalidateQueries({ queryKey: orpc.settings.getAll.key() });
      void navigate({ to: "/$lang/settings/security", params: { lang } });
      return true;
    },
    [lang, navigate, queryClient],
  );
}

/** Redirect when any of the page's list queries fails with the 2FA refusal. */
export function useTwoFactorRedirectOnError(lang: string, errors: readonly unknown[]) {
  const redirect = useTwoFactorRedirect(lang);
  const refused = errors.find(isTwoFactorRequiredError);
  useEffect(() => {
    if (refused) redirect(refused);
  }, [refused, redirect]);
}
