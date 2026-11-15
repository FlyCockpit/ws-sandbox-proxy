import { createProcedureBudget } from "@wssp/api/lib/procedure-budget";

/** Independent, replica-wide, fail-closed buckets; no credential is ever a bucket key. */
export function mcpBudget(name: string, points: number) {
  return createProcedureBudget({
    keyPrefix: `mcp:${name}`,
    points,
    durationSeconds: 60,
    failClosed: true,
    redactErrors: true,
    overBudgetMessage: () => "Request budget exceeded.",
    unavailableMessage: "Service temporarily unavailable.",
    unavailableLog: "[mcp] budget unavailable",
  });
}
export const consumeMcpIpQuota = mcpBudget("ip", 300);
export const consumeMcpCredentialQuota = mcpBudget("credential", 120);
export const consumeMcpCreateQuota = mcpBudget("create", 30);
export const consumeMcpHostCommandQuota = mcpBudget("host-command", 30);
