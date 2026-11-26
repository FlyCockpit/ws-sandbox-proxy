/**
 * The signed-in home: where a signed-in visitor lands when they finish
 * signing in or verifying their email, click the app name in the header, open
 * the app from the public header ("Open app"), or visit the public landing
 * page (`/$lang/`, which forwards them here).
 *
 * The home is the main list, Sandboxes, not a stats page. It carries the
 * getting-started checklist (components/sandboxes/onboarding-checklist.tsx)
 * until its steps are done. Every signed-in page lives under `/dashboard/*`;
 * `/$lang/dashboard` itself is redirect-only and forwards here
 * (`routes/$lang/_app/_auth/dashboard/index.tsx`).
 *
 * This is the one place to change it. The target must be a route under the
 * `_auth` gate (`routes/$lang/_app/_auth/`), so an expired session still falls
 * through to the login page.
 */
export const APP_HOME = "/$lang/dashboard/sandboxes" as const;

/** {@link APP_HOME} as a concrete href for one locale, e.g. `/en-US/dashboard/sandboxes`. */
export function appHomeHref(lang: string): string {
  return APP_HOME.replace("$lang", lang);
}
