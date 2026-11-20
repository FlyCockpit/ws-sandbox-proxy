import { z } from "zod";

/**
 * `wssp login` (user login) asks for exactly this device authorization scope.
 * The browser approval chooses what the minted `/v1` key may do; nothing the
 * CLI sends besides this scope reaches the approval page or the key.
 */
export const USER_DEVICE_LOGIN_SCOPE = "user-login";

export function isUserDeviceLoginScope(scope: string | null | undefined): boolean {
  return scope === USER_DEVICE_LOGIN_SCOPE;
}

/** Active (unrevoked, unexpired) CLI-login keys one owner may hold. */
export const USER_LOGIN_ACTIVE_KEY_LIMIT = 20;
export const USER_LOGIN_EXPIRY_DAYS = [1, 7, 30, 90] as const;
export const USER_LOGIN_DEFAULT_EXPIRY_DAYS = 30;
export const USER_LOGIN_DEFAULT_NAME = "wssp login";
export const USER_LOGIN_MAX_LIVE_SANDBOXES = 1000;
export const USER_LOGIN_POOL_IDS_MAX = 200;

/** `read`: list and read sandboxes, command output and files; no writes. */
export const USER_LOGIN_READ_SCOPES = [
  "hosts:read",
  "pools:read",
  "templates:read",
  "sandboxes:read",
  "commands:read",
  "files:read",
  "operations:read",
] as const;

/**
 * `write`: read plus sandbox lifecycle, commands, file writes, cancellation,
 * preview tunnels and CLI shells (`sandboxes:connect`). Never host access, template writes/builds, webhooks or
 * CLI-login (`credentials:*`) scopes.
 */
export const USER_LOGIN_WRITE_SCOPES = [
  ...USER_LOGIN_READ_SCOPES,
  "sandboxes:create",
  "sandboxes:manage",
  "sandboxes:destroy",
  "commands:execute",
  "files:write",
  "operations:cancel",
  "sandboxes:tunnel",
  "sandboxes:connect",
] as const;

export type UserLoginAccess = "read" | "write";

export function userLoginScopes(access: UserLoginAccess): readonly string[] {
  return access === "write" ? USER_LOGIN_WRITE_SCOPES : USER_LOGIN_READ_SCOPES;
}

/** The grant an approver chose, stored on `DeviceCode.loginGrant` and re-validated at mint. */
export const userLoginGrantSchema = z
  .object({
    access: z.enum(["read", "write"]),
    poolMode: z.enum(["ALL_USABLE", "SELECTED"]),
    poolIds: z.array(z.string().min(1).max(191)).max(USER_LOGIN_POOL_IDS_MAX),
    ownSandboxesOnly: z.boolean(),
    maxLiveSandboxes: z.number().int().min(1).max(USER_LOGIN_MAX_LIVE_SANDBOXES).nullable(),
    expiresInDays: z.union([z.literal(1), z.literal(7), z.literal(30), z.literal(90)]),
    name: z.string().trim().min(1).max(120),
  })
  .strict()
  .superRefine((grant, ctx) => {
    if (grant.poolMode === "ALL_USABLE" && grant.poolIds.length > 0)
      ctx.addIssue({
        code: "custom",
        path: ["poolIds"],
        message: "All-usable logins cannot select pools.",
      });
    if (grant.poolMode === "SELECTED" && grant.poolIds.length === 0)
      ctx.addIssue({
        code: "custom",
        path: ["poolIds"],
        message: "Select at least one pool.",
      });
    if (new Set(grant.poolIds).size !== grant.poolIds.length)
      ctx.addIssue({ code: "custom", path: ["poolIds"], message: "Pools must be distinct." });
  });

export type UserLoginGrant = z.infer<typeof userLoginGrantSchema>;
