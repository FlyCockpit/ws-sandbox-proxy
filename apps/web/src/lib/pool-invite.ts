// Browser memory only: never router context, query state, storage, logs or
// redirect parameters. The one hand-off is `postAuthHref`: a same-origin
// fragment, which no request, access log or Referer ever carries.
let token: string | undefined;
// Bumped on every capture: the accept page keys its preview and form state on
// it, so a newly captured invitation never inherits another's. (Clearing after
// an acceptance keeps the generation, so the accepted state stays on screen.)
let generation = 0;
const INVITE_PATH = /^\/(en-US|es-MX)\/settings\/pools\/invite\/?$/;
export function capturePoolInviteFragment(browser: Pick<Window, "location" | "history"> = window) {
  if (!INVITE_PATH.test(browser.location.pathname)) return;
  const fragment = browser.location.hash.slice(1);
  if (!fragment) {
    if (browser.location.search)
      browser.history.replaceState(browser.history.state, "", browser.location.pathname);
    return;
  }
  token = /^wssp_inv_[A-Za-z0-9_-]{43}$/.test(fragment) ? fragment : undefined;
  generation++;
  browser.history.replaceState(browser.history.state, "", browser.location.pathname);
}
export function poolInviteToken() {
  return token;
}
export function clearPoolInviteToken() {
  token = undefined;
}
/** Non-secret identity of the captured invitation (see `generation`). */
export function poolInviteGeneration() {
  return generation;
}

/** Only the invitation route discards URL details; ordinary intended destinations stay intact. */
export function authRedirectHref(location: { pathname: string; href: string }): string {
  return /\/settings\/pools\/invite\/?$/.test(location.pathname)
    ? location.pathname
    : location.href;
}

/**
 * The full-page post-sign-in navigation reloads the app and would drop the
 * in-memory invitation. When the already-validated target (`safeRedirectTo`:
 * same-origin, under `/$lang/`) is exactly the invitation route, the token
 * rides back as that page's fragment, where `capturePoolInviteFragment`
 * takes it into memory and scrubs it again. A fragment is never sent to the
 * server, so it reaches no access log or Referer. Every other target, and an
 * absolute or cross-locale one, is returned unchanged and token-free.
 */
export function postAuthHref(target: string, lang: string): string {
  if (!token || !target.startsWith(`/${lang}/`) || !INVITE_PATH.test(target)) return target;
  return `${target}#${token}`;
}
