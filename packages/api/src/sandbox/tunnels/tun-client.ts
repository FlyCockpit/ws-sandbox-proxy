import type { TunnelServer } from "./config";

/**
 * The tunnel server's bearer API, as the service credential uses it. HTTPS
 * only; redirects are never followed (a redirect would carry the bearer to
 * another origin); every call is bounded by a timeout. Nothing here logs a
 * token, a link URL or a response body.
 */
const TIMEOUT_MS = 10_000;
/** Tunnels live this long unless deleted first; a `tunnel_gone` recreates. */
const TUNNEL_TTL_SECONDS = 7 * 24 * 3600;

export class TunServerError extends Error {
  constructor(
    readonly status: number,
    readonly code: string | null,
  ) {
    super(`tunnel server answered ${status}${code ? ` (${code})` : ""}`);
    this.name = "TunServerError";
  }
  /** The account/service quota on the tunnel server is exhausted. */
  get quota(): boolean {
    return this.status === 429;
  }
  get notFound(): boolean {
    return this.status === 404 || this.status === 410;
  }
  get unauthorized(): boolean {
    return this.status === 401 || this.status === 403;
  }
}

export type TunFetch = typeof fetch;

async function call<T>(
  server: Pick<TunnelServer, "apiUrl" | "credential">,
  method: "GET" | "POST" | "DELETE",
  path: string,
  body?: unknown,
  doFetch: TunFetch = fetch,
  timeoutMs = TIMEOUT_MS,
): Promise<T> {
  let response: Response;
  try {
    response = await doFetch(`${server.apiUrl}${path}`, {
      method,
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        authorization: `Bearer ${server.credential}`,
        accept: "application/json",
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  } catch {
    throw new TunServerError(0, "unreachable");
  }
  if (response.status === 204) return undefined as T;
  if (response.status < 200 || response.status >= 300) {
    let code: string | null = null;
    try {
      const parsed = (await response.json()) as { error?: { code?: unknown } | string };
      const raw = typeof parsed.error === "object" ? parsed.error?.code : parsed.error;
      if (typeof raw === "string" && /^[a-z_]{1,64}$/.test(raw)) code = raw;
    } catch {
      /* no body */
    }
    throw new TunServerError(response.status, code);
  }
  try {
    return (await response.json()) as T;
  } catch {
    throw new TunServerError(response.status, "invalid_body");
  }
}

const TUNNEL_ID = /^[A-Za-z0-9]{1,64}$/;
const LINK_ID = /^al_[A-Za-z0-9]{1,64}$/;
const TOKEN = /^tntun_[A-Za-z0-9_-]{16,120}$/;

function requireId(id: unknown, pattern = TUNNEL_ID): string {
  if (typeof id !== "string" || !pattern.test(id)) throw new TunServerError(200, "invalid_body");
  return id;
}

/** `{port}-<id>.<zone>`, nothing else. */
function requireTemplate(template: unknown): string {
  if (
    typeof template !== "string" ||
    !/^\{port\}-[A-Za-z0-9]{1,64}\.[a-z0-9.-]{1,200}$/.test(template)
  )
    throw new TunServerError(200, "invalid_body");
  return template;
}

export type CreatedTunnel = { id: string; token: string; hostTemplate: string };

export async function createTunnel(
  server: Pick<TunnelServer, "apiUrl" | "credential">,
  input: { label: string; maxPorts: number },
  doFetch?: TunFetch,
): Promise<CreatedTunnel> {
  const created = await call<{ id?: unknown; tunnel_token?: unknown; host_template?: unknown }>(
    server,
    "POST",
    "/v1/tunnels",
    {
      label: input.label,
      ttl_s: TUNNEL_TTL_SECONDS,
      max_ports: input.maxPorts,
      inject_ice: false,
      access: { mode: "link" },
    },
    doFetch,
  );
  if (typeof created.tunnel_token !== "string" || !TOKEN.test(created.tunnel_token))
    throw new TunServerError(201, "invalid_body");
  return {
    id: requireId(created.id),
    token: created.tunnel_token,
    hostTemplate: requireTemplate(created.host_template),
  };
}

/** A new per-tunnel token; the old one stops working at once. */
export async function rotateTunnelToken(
  server: Pick<TunnelServer, "apiUrl" | "credential">,
  tunnelId: string,
  doFetch?: TunFetch,
): Promise<string> {
  const rotated = await call<{ tunnel_token?: unknown }>(
    server,
    "POST",
    `/v1/tunnels/${encodeURIComponent(requireId(tunnelId))}/token`,
    {},
    doFetch,
  );
  if (typeof rotated.tunnel_token !== "string" || !TOKEN.test(rotated.tunnel_token))
    throw new TunServerError(200, "invalid_body");
  return rotated.tunnel_token;
}

/** Idempotent: a deleted or unknown tunnel counts as deleted. */
export async function deleteTunnel(
  server: Pick<TunnelServer, "apiUrl" | "credential">,
  tunnelId: string,
  doFetch?: TunFetch,
): Promise<void> {
  try {
    await call(
      server,
      "DELETE",
      `/v1/tunnels/${encodeURIComponent(requireId(tunnelId))}`,
      undefined,
      doFetch,
    );
  } catch (error) {
    if (error instanceof TunServerError && error.notFound) return;
    throw error;
  }
}

/** Tunnel ids carrying exactly this label (the service sees only its own).
 * Strict: a malformed page, or a tunnel with another label, is an error —
 * never "nothing there". Follows `next_cursor` (bounded). `beforePage` runs
 * before every request (a caller's deadline check may throw). */
export async function tunnelsByLabel(
  server: Pick<TunnelServer, "apiUrl" | "credential">,
  label: string,
  doFetch?: TunFetch,
  beforePage?: () => void,
): Promise<string[]> {
  const ids: string[] = [];
  let cursor: string | null = null;
  for (let page = 0; page < 20; page++) {
    beforePage?.();
    const query: string = `label=${encodeURIComponent(label)}&limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
    const body: { tunnels?: unknown; next_cursor?: unknown } = await call(
      server,
      "GET",
      `/v1/tunnels?${query}`,
      undefined,
      doFetch,
    );
    if (!Array.isArray(body.tunnels)) throw new TunServerError(200, "invalid_body");
    for (const tunnel of body.tunnels as { id?: unknown; label?: unknown }[]) {
      if (tunnel?.label !== label) throw new TunServerError(200, "invalid_body");
      ids.push(requireId(tunnel.id));
    }
    if (typeof body.next_cursor !== "string" || body.next_cursor === "") return ids;
    cursor = body.next_cursor;
  }
  throw new TunServerError(200, "invalid_body");
}

/**
 * The tunnels this service credential holds whose label starts with
 * `prefix`, in one run of at most 20 × 100 starting at `from` (null: the
 * beginning). `next` is where the following run continues (the caller
 * deletes these first), or null once the listing reached its end.
 */
export async function tunnelsWithLabelPrefix(
  server: Pick<TunnelServer, "apiUrl" | "credential">,
  prefix: string,
  from: string | null = null,
  doFetch?: TunFetch,
): Promise<{ ids: string[]; next: string | null }> {
  const ids: string[] = [];
  let cursor: string | null = from;
  for (let page = 0; page < 20; page++) {
    const query: string = `limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
    const body: { tunnels?: unknown; next_cursor?: unknown } = await call(
      server,
      "GET",
      `/v1/tunnels?${query}`,
      undefined,
      doFetch,
    );
    if (!Array.isArray(body.tunnels)) throw new TunServerError(200, "invalid_body");
    for (const tunnel of body.tunnels as { id?: unknown; label?: unknown }[])
      if (typeof tunnel?.label === "string" && tunnel.label.startsWith(prefix))
        ids.push(requireId(tunnel.id));
    if (typeof body.next_cursor !== "string" || body.next_cursor === "") return { ids, next: null };
    cursor = body.next_cursor;
  }
  return { ids, next: cursor };
}

/** Admin check: the credential is accepted (bounded well inside the admin
 * write transaction's lifetime). */
export async function checkCredential(
  server: Pick<TunnelServer, "apiUrl" | "credential">,
  doFetch?: TunFetch,
): Promise<void> {
  await call(server, "GET", "/v1/tunnels?limit=1", undefined, doFetch, 3_000);
}

export type MintedLink = { id: string; url: string; expiresAt: Date };

export async function mintAccessLink(
  server: Pick<TunnelServer, "apiUrl" | "credential">,
  tunnelId: string,
  input: { port: number; ttlSeconds: number; singleUse: boolean; sessionTtlSeconds: number },
  doFetch?: TunFetch,
): Promise<MintedLink> {
  const link = await call<{ id?: unknown; url?: unknown; expires_at?: unknown }>(
    server,
    "POST",
    `/v1/tunnels/${encodeURIComponent(requireId(tunnelId))}/access-links`,
    {
      ttl_s: input.ttlSeconds,
      single_use: input.singleUse,
      port: input.port,
      session_ttl_s: input.sessionTtlSeconds,
    },
    doFetch,
  );
  let url: URL;
  try {
    url = new URL(String(link.url));
  } catch {
    throw new TunServerError(201, "invalid_body");
  }
  // An https URL (the preview zone may be another domain than the API).
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    typeof link.expires_at !== "number"
  )
    throw new TunServerError(201, "invalid_body");
  return {
    id: requireId(link.id, LINK_ID),
    url: url.toString(),
    expiresAt: new Date(link.expires_at * 1000),
  };
}

/**
 * Revoke an access link (`DELETE /v1/access-links/{id}`): the tunnel server
 * refuses the link and every gate session it granted at once, in-flight
 * responses and WebSockets included. True when this call revoked it; false
 * when the tunnel server no longer has it (revoked already, expired and
 * purged, or its tunnel deleted).
 */
export async function revokeAccessLink(
  server: Pick<TunnelServer, "apiUrl" | "credential">,
  linkId: string,
  doFetch?: TunFetch,
): Promise<boolean> {
  try {
    await call(
      server,
      "DELETE",
      `/v1/access-links/${encodeURIComponent(requireId(linkId, LINK_ID))}`,
      undefined,
      doFetch,
    );
    return true;
  } catch (error) {
    if (error instanceof TunServerError && error.notFound) return false;
    throw error;
  }
}

/** `https://<port>-<id>.<zone>` for each port. */
export function previewUrls(hostTemplate: string | null, ports: readonly number[]) {
  if (!hostTemplate) return [];
  return ports.map((port) => ({
    port,
    url: `https://${hostTemplate.replace("{port}", String(port))}`,
  }));
}
