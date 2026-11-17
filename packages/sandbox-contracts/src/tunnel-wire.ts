import { z } from "zod";

/** Most ports one sandbox may declare (`sandbox_protocol::TUNNEL_MAX_PORTS`). */
export const TUNNEL_MAX_PORTS = 8;

/**
 * Preview-tunnel relay frames. Mirrors `crates/sandbox-protocol/src/tunnel.rs`.
 * `tunnel.apply` carries a per-tunnel token: it is built only in memory, sent
 * only to the host holding the sandbox, and never logged or stored.
 */
const sandboxIdSchema = z.string().regex(/^[A-Za-z0-9_-]{1,128}$/);
const generationSchema = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);
export const tunnelWirePortsSchema = z
  .array(z.number().int().min(1).max(65535))
  .min(1)
  .max(TUNNEL_MAX_PORTS)
  .refine((ports) => ports.every((port, i) => i === 0 || (ports[i - 1] ?? 0) < port));

export const tunnelCapabilityV11Schema = z.strictObject({
  clientSha256: z.string().regex(/^[0-9a-f]{64}$/),
  maxTunnels: z.number().int().min(1).max(256),
  allowForOthers: z.boolean(),
});
export type TunnelCapabilityV11 = z.infer<typeof tunnelCapabilityV11Schema>;

export const tunnelApplyV11Schema = z.strictObject({
  type: z.literal("tunnel.apply"),
  sandboxId: sandboxIdSchema,
  generation: generationSchema,
  server: z
    .string()
    .max(256)
    .regex(/^https:\/\/[A-Za-z0-9][A-Za-z0-9.:-]*$/),
  token: z
    .string()
    .max(128)
    .regex(/^tntun_[A-Za-z0-9_-]{16,}$/),
  ports: tunnelWirePortsSchema,
});
export type TunnelApplyV11 = z.infer<typeof tunnelApplyV11Schema>;

export const tunnelClearV11Schema = z.strictObject({
  type: z.literal("tunnel.clear"),
  sandboxId: sandboxIdSchema,
  generation: generationSchema,
});
export type TunnelClearV11 = z.infer<typeof tunnelClearV11Schema>;

export const tunnelStatusV11Schema = z
  .strictObject({
    type: z.literal("tunnel.status"),
    sandboxId: sandboxIdSchema,
    generation: generationSchema,
    state: z.enum(["connecting", "connected", "stopped", "error"]),
    error: z.enum(["tunnel_gone", "replaced", "client_failed", "refused"]).optional(),
    tunnelId: z
      .string()
      .regex(/^[A-Za-z0-9]{1,64}$/)
      .optional(),
  })
  .refine((status) => (status.state === "error") === (status.error !== undefined));
export type TunnelStatusV11 = z.infer<typeof tunnelStatusV11Schema>;
