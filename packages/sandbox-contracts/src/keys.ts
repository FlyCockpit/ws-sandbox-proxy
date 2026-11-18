import { z } from "zod";
import { isoDateTimeSchema, resourceIdSchema, SDK_SCOPES } from "./dto";

/** Where the calling key came from: the dashboard, or a `wssp login` approval. */
export const KEY_ORIGINS = ["dashboard", "cliLogin"] as const;
export type KeyOrigin = (typeof KEY_ORIGINS)[number];

/**
 * `GET /v1/key`: the calling key itself. It never carries the owner's email or
 * any secret; `pools` lists only a `selected` key's own pools (empty when the
 * key may use every usable pool). `liveSandboxes` is the count the
 * `maxLiveSandboxes` limit is enforced on: live WORKLOAD sandboxes this key
 * created.
 */
export const keyInfoSchema = z
  .object({
    id: resourceIdSchema,
    name: z.string().min(1).max(120),
    origin: z.enum(KEY_ORIGINS),
    scopes: z.array(z.enum(SDK_SCOPES)),
    resourceMode: z.enum(["allOwned", "allowlist"]),
    poolMode: z.enum(["allUsable", "selected"]),
    pools: z
      .array(z.object({ id: resourceIdSchema, slug: z.string(), label: z.string() }).strict())
      .max(200),
    ownSandboxesOnly: z.boolean(),
    expiresAt: isoDateTimeSchema.nullable(),
    maxLiveSandboxes: z.number().int().min(1).max(1000).nullable(),
    liveSandboxes: z.number().int().min(0),
  })
  .strict();
export type KeyInfo = z.infer<typeof keyInfoSchema>;

/** `DELETE /v1/key`: a CLI-login key revoked itself; every later request is 401. */
export const keyRevokedSchema = z
  .object({ id: resourceIdSchema, revoked: z.literal(true) })
  .strict();
export type KeyRevoked = z.infer<typeof keyRevokedSchema>;
