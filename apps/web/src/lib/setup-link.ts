/**
 * True when `setup.claimFirstAdmin` refused the SETUP_KEY link itself: it is
 * expired, replaced or used (`SETUP_LINK_INVALID`), or SETUP_KEY was removed
 * from the server, which kills every unspent link (a NOT_FOUND carrying
 * `data.code` `SETUP_KEY_UNSET`). Either way the page shows the
 * invalid-setup-link card instead of keeping a form that can never succeed. A
 * bare NOT_FOUND (an unknown procedure during a version skew, a proxy 404) is
 * not a dead link and keeps its ordinary error message.
 */
export function isSetupLinkInvalid(error: unknown): boolean {
  if (typeof error !== "object" || error === null || !("code" in error)) return false;
  if (error.code === "SETUP_LINK_INVALID") return true;
  if (error.code !== "NOT_FOUND" || !("data" in error)) return false;
  const data = error.data;
  return (
    typeof data === "object" && data !== null && "code" in data && data.code === "SETUP_KEY_UNSET"
  );
}
