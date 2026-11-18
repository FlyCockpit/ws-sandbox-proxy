import { z } from "zod";
import { TUNNEL_MAX_PORTS } from "./tunnel-wire";

/**
 * Preview tunnels (docs/guide/tunnels.md). Optional: a deployment without a
 * configured tunnel server refuses every tunnel call with
 * `UNSUPPORTED_CAPABILITY` and `reason: "tunnel_off"`.
 *
 * Ports are DECLARED at create (`network.tunnelPorts`, possibly `[]`: a
 * tunnel sandbox with no ports yet) and changed at runtime only through the
 * audited `POST /v1/sandboxes/{id}/tunnel/ports`: the host's network plan
 * admits only declared ports, and only from the host-side tunnel client.
 * Exposing chooses a subset; links open one.
 */
export const tunnelPortSchema = z.number().int().min(1).max(65535);
export const tunnelPortsSchema = z
  .array(tunnelPortSchema)
  .min(1)
  .max(TUNNEL_MAX_PORTS)
  .refine((ports) => new Set(ports).size === ports.length, "Each port may be named once.");

/** A tunnel sandbox's declared ports: like `tunnelPortsSchema`, but may be empty. */
export const tunnelDeclaredPortsSchema = z
  .array(tunnelPortSchema)
  .max(TUNNEL_MAX_PORTS)
  .refine((ports) => new Set(ports).size === ports.length, "Each port may be named once.");

/** One encoding per set: ascending, as the host compiles it. */
export function normalizeTunnelPorts(ports: readonly number[]): number[] {
  return [...ports].sort((a, b) => a - b);
}

/**
 * Why `UNSUPPORTED_CAPABILITY` refused a tunnel call (`reason`):
 * `tunnel_off` (no tunnel server configured on this deployment),
 * `tunnel_no_host` (no eligible host runs the tunnel client for this caller),
 * `tunnel_host_unsupported` (this sandbox's host does not), `tunnel_not_shared`
 * (another user's host whose owner does not allow tunnels for others),
 * `tunnel_not_enabled` (the sandbox was created without `network.tunnelPorts`:
 * only tunnel sandboxes change their ports).
 */
export const TUNNEL_REFUSAL_REASONS = [
  "tunnel_off",
  "tunnel_no_host",
  "tunnel_host_unsupported",
  "tunnel_not_shared",
  "tunnel_not_enabled",
] as const;
export const tunnelRefusalReasonSchema = z.enum(TUNNEL_REFUSAL_REASONS);
export type TunnelRefusalReason = z.infer<typeof tunnelRefusalReasonSchema>;

export const TUNNEL_STATES = ["pending", "connecting", "connected", "suspended", "error"] as const;
export const TUNNEL_ERRORS = [
  "tunnel_gone",
  "replaced",
  "client_failed",
  "refused",
  "quota",
  "server_unavailable",
  "host_full",
  "not_shared",
] as const;

export const exposeTunnelBodySchema = z
  .object({
    /** A subset of the sandbox's declared `tunnelPorts`; omitted: all of them. */
    ports: tunnelPortsSchema.optional(),
  })
  .strict();
export type ExposeTunnelBody = z.infer<typeof exposeTunnelBodySchema>;

export const updateTunnelPortsBodySchema = z
  .object({
    /** Ports to declare (already declared ones are kept). */
    add: tunnelPortsSchema.optional(),
    /**
     * Ports to stop declaring. An exposed one leaves the tunnel: the tunnel is
     * replaced (every link and browser session of it stops working; the kept
     * ports get a new preview origin) and the host stops forwarding the port.
     */
    remove: tunnelPortsSchema.optional(),
  })
  .strict()
  .refine((body) => (body.add?.length ?? 0) + (body.remove?.length ?? 0) > 0, {
    message: "Name at least one port to add or remove.",
  })
  .refine((body) => !(body.add ?? []).some((port) => (body.remove ?? []).includes(port)), {
    message: "A port cannot be both added and removed.",
  });
export type UpdateTunnelPortsBody = z.infer<typeof updateTunnelPortsBodySchema>;

export const sandboxTunnelPortsSchema = z
  .object({
    sandboxId: z.string(),
    /** The declared ports, ascending. */
    ports: z.array(tunnelPortSchema).max(TUNNEL_MAX_PORTS),
    /** Bumped by every change. */
    revision: z.number().int().min(0),
    /**
     * `applied` once the sandbox's host recorded this revision (an added port
     * can then be exposed), `pending` until then (also while the sandbox is
     * offloaded or between hosts: its next start carries the ports).
     */
    state: z.enum(["applied", "pending"]),
  })
  .strict();
export type SandboxTunnelPortsDto = z.infer<typeof sandboxTunnelPortsSchema>;

export const sandboxTunnelSchema = z
  .object({
    sandboxId: z.string(),
    ports: z.array(tunnelPortSchema).max(TUNNEL_MAX_PORTS),
    /**
     * `pending` (waiting for a running sandbox on a connected host),
     * `connecting`, `connected`, `suspended` (stopped, offloaded or host away:
     * no tunnel exists until it runs again) or `error` (`lastError`).
     */
    state: z.enum(TUNNEL_STATES),
    lastError: z.enum(TUNNEL_ERRORS).nullable(),
    /** Gated preview origins (`https://<port>-<id>.<zone>`) while a tunnel exists. */
    urls: z
      .array(z.object({ port: tunnelPortSchema, url: z.string() }).strict())
      .max(TUNNEL_MAX_PORTS),
    connectedAt: z.iso.datetime().nullable(),
    updatedAt: z.iso.datetime(),
  })
  .strict();
export type SandboxTunnelDto = z.infer<typeof sandboxTunnelSchema>;

export const TUNNEL_LINK_TTL_MIN_SECONDS = 30;
export const TUNNEL_LINK_TTL_MAX_SECONDS = 3600;
export const TUNNEL_SESSION_TTL_MAX_SECONDS = 86400;
export const createTunnelLinkBodySchema = z
  .object({
    /** An exposed port; the link opens it. */
    port: tunnelPortSchema,
    /** How long the link can be redeemed (30–3600 s, default 60). */
    ttlSeconds: z
      .number()
      .int()
      .min(TUNNEL_LINK_TTL_MIN_SECONDS)
      .max(TUNNEL_LINK_TTL_MAX_SECONDS)
      .optional(),
    /** Single use (default true): the first visit consumes it. */
    singleUse: z.boolean().optional(),
    /** How long the browser session it grants lasts (60–86400 s, default 3600). */
    sessionTtlSeconds: z.number().int().min(60).max(TUNNEL_SESSION_TTL_MAX_SECONDS).optional(),
  })
  .strict();
export type CreateTunnelLinkBody = z.infer<typeof createTunnelLinkBodySchema>;

export const tunnelLinkSchema = z
  .object({
    /** The one-time access URL. Treat it as a secret: whoever opens it first gets in. */
    url: z.string(),
    port: tunnelPortSchema,
    expiresAt: z.iso.datetime(),
    singleUse: z.boolean(),
  })
  .strict();
export type TunnelLinkDto = z.infer<typeof tunnelLinkSchema>;
