import { isIP } from "node:net";
import { getConnInfo } from "@hono/node-server/conninfo";
import { env } from "@wssp/env/server";
import type { Context } from "hono";
import { isPrivateIp } from "./private-ip.js";

/**
 * Resolve the client IP for an anonymous request. This is the rate-limit and
 * audit key for traffic that isn't tied to a user id.
 *
 * `X-Forwarded-For` is `<client-supplied>, <appended by hop 1>, <hop 2>, ...`.
 * Everything a client sends is forgeable; each trusted proxy APPENDS the
 * address it received the request from. The chain we read is therefore
 * `[...X-Forwarded-For, socketPeer]`, and only the rightmost entries written
 * by proxies we actually run can be trusted.
 *
 * TRUST_PROXY_HOPS = N (default 0) is the exact number of trusted reverse
 * proxies between the client and the app:
 *
 * - N = 0 (default): key on the TCP socket peer and ignore `X-Forwarded-For`
 *   entirely. Correct for direct exposure and LAN deploys. A deployment that
 *   sits behind a proxy but leaves N = 0 keys every client on the proxy's
 *   address — one shared bucket — which fails safe (over-limits) rather than
 *   letting clients choose their own key.
 * - N >= 1: the client is the entry N positions left of the socket peer. The
 *   generated Dokploy Compose sets 1 (Traefik). The app must be reachable
 *   ONLY through that chain, or a direct caller can forge the entries.
 *
 * There is no private-hop heuristic and no fallback to the leftmost
 * (client-supplied) entry: when the chain is shorter than N + 1, or the
 * selected entry is not an IP literal, the request did not arrive through the
 * configured proxies and is keyed on the socket peer instead.
 *
 * Some proxies (for example Azure Application Gateway) append the client
 * address with its source port by default. After choosing the entry, a port
 * suffix is stripped (`1.2.3.4:5678` → `1.2.3.4`, `[2001:db8::1]:5678` →
 * `2001:db8::1`) before the `isIP` check. A bare IPv6 literal is left alone;
 * anything else that is not an IP literal still falls back to the socket peer.
 */
export function resolveClientIp(c: Context): string {
  const socket = getConnInfo(c).remote.address || "unknown";
  const header = c.req.header("x-forwarded-for");
  const hops = env.TRUST_PROXY_HOPS ?? 0;
  if (hops === 0) {
    if (header) warnUntrustedForwardedOnce(socket);
    return socket;
  }

  const forwarded = (header ?? "")
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
  // `forwarded[forwarded.length - hops]` is N-from-right in [...xff, socket].
  const selected = forwarded[forwarded.length - hops];
  if (selected === undefined) return socket;
  const candidate = stripForwardedPort(selected);
  if (isIP(candidate) === 0) return socket;
  return candidate;
}

/**
 * Remove a port a proxy appended to the selected entry. `[v6]:port` and
 * `v4:port` lose the port; `[v6]` without a port loses its brackets. A bare
 * IPv6 literal (two or more colons, no brackets) is returned unchanged, so its
 * last group is never mistaken for a port. The caller still validates the
 * result with `isIP`.
 */
function stripForwardedPort(entry: string): string {
  const bracketed = /^\[([^\]]+)\](?::(\d{1,5}))?$/.exec(entry);
  if (bracketed) {
    const host = bracketed[1] ?? "";
    return isIP(host) === 6 ? host : entry;
  }
  const v4WithPort = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(entry);
  if (v4WithPort) return v4WithPort[1] ?? entry;
  return entry;
}

let warnedUntrustedForwarded = false;

/**
 * A private socket peer sending X-Forwarded-For while TRUST_PROXY_HOPS is 0 is
 * almost always a reverse proxy the operator has not counted, which collapses
 * every client into the proxy's bucket. Say so once per process; the request
 * is still keyed on the socket peer (a LAN client spoofing the header only
 * triggers this one-time record). The message names no address.
 */
function warnUntrustedForwardedOnce(socket: string): void {
  if (warnedUntrustedForwarded) return;
  const version = isIP(socket);
  if (version === 0 || !isPrivateIp(socket, version)) return;
  warnedUntrustedForwarded = true;
  console.warn(
    "[client-ip] a private peer sent X-Forwarded-For while TRUST_PROXY_HOPS is 0; " +
      "every client behind that proxy shares one rate-limit bucket. Set TRUST_PROXY_HOPS " +
      "to the number of trusted reverse proxies.",
  );
}
