import {
  type AgentTokenExpiryPolicy,
  agentTokenClientExpiryCapMs,
  agentTokenExpiryPresets,
  endOfLocalDay,
} from "@wssp/config/agent-token-limits";

export {
  agentTokenExpiryPresets,
  latestAgentTokenCustomDate,
} from "@wssp/config/agent-token-limits";

export function localDateInputValue(date: Date): string {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

/** undefined means invalid; null deliberately requests an unlimited lifetime. */
export function agentTokenExpiry(
  choice: string,
  customDate: string,
  nowMs: number,
  policy: AgentTokenExpiryPolicy,
): Date | null | undefined {
  if (choice === "never") return policy.allowNoExpiry ? null : undefined;
  if (choice === "custom") {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(customDate)) return undefined;
    const local = new Date(`${customDate}T00:00:00`);
    if (localDateInputValue(local) !== customDate) return undefined;
    const expiry = endOfLocalDay(local);
    return expiry.getTime() > nowMs &&
      expiry.getTime() <= agentTokenClientExpiryCapMs(nowMs, policy.maxLifetimeDays)
      ? expiry
      : undefined;
  }
  if (!agentTokenExpiryPresets(policy.maxLifetimeDays).some((preset) => preset === choice))
    return undefined;
  // Presets use a rolling duration, with room for client/server clock skew.
  return new Date(agentTokenClientExpiryCapMs(nowMs, Number.parseInt(choice, 10)));
}
