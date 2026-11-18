import { type WaitOptions, waitTimeout } from "./polling";
import type { RouteResponse, WsspTransport } from "./transport";

/** The calling key itself (any active key; no scope needed). */
export type KeyApi = {
  /**
   * This key's name, origin, scopes, pools, expiry, live-sandbox limit and how
   * many live sandboxes it created (the count the limit is enforced on).
   */
  get(options?: WaitOptions): Promise<RouteResponse<"getKey">>;
  /**
   * Revoke this key (`wssp logout`). Only a CLI-login key (`origin:
   * "cliLogin"`) may revoke itself; any other key fails with
   * `key.self_revoke_forbidden`. Every later call with this key is 401.
   */
  revokeSelf(options?: WaitOptions): Promise<RouteResponse<"revokeKey">>;
};

export function createKeyApi(transport: WsspTransport): KeyApi {
  return {
    get: (options) =>
      transport.request("getKey", { signal: options?.signal, timeoutMs: waitTimeout(options) }),
    revokeSelf: (options) =>
      transport.request("revokeKey", {
        signal: options?.signal,
        timeoutMs: waitTimeout(options),
      }),
  };
}
