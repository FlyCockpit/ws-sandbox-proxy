/** Browser-safe agent-token expiry policy. The lifetime cap applies to new
 * mints only; turning no-expiry off also blocks existing no-expiry tokens at
 * authentication (see `agentTokenBlockedByPolicy`) until it is turned back on. */
export const AGENT_TOKEN_DAY_MS = 86_400_000;
export const AGENT_TOKEN_EXPIRY_CLIENT_SKEW_MS = 60_000;
export type AgentTokenExpiryPolicy = { allowNoExpiry: boolean; maxLifetimeDays: number };
export const AGENT_TOKEN_EXPIRY_PRESETS = ["7d", "30d", "90d", "365d"] as const;
export type AgentTokenExpiryPreset = (typeof AGENT_TOKEN_EXPIRY_PRESETS)[number];

export function agentTokenExpiryPresets(maxLifetimeDays: number): AgentTokenExpiryPreset[] {
  return AGENT_TOKEN_EXPIRY_PRESETS.filter(
    (preset) => Number.parseInt(preset, 10) <= maxLifetimeDays,
  );
}

export function agentTokenExpiryRejection(
  expiresAt: Date | null,
  nowMs: number,
  policy: AgentTokenExpiryPolicy,
): "no_expiry_disabled" | "past" | "too_far" | null {
  if (expiresAt === null) return policy.allowNoExpiry ? null : "no_expiry_disabled";
  const expiryMs = expiresAt.getTime();
  if (!Number.isFinite(expiryMs) || expiryMs <= nowMs) return "past";
  if (expiryMs > nowMs + policy.maxLifetimeDays * AGENT_TOKEN_DAY_MS) return "too_far";
  return null;
}

/** Error code for an existing no-expiry agent token refused while the
 * deployment disallows no-expiry tokens. The row is kept, not revoked. */
export const AGENT_TOKEN_NO_EXPIRY_BLOCKED_CODE = "agent_token.no_expiry_blocked";

/** True when the credential is an agent token without expiry and the
 * deployment does not allow those. Fails closed: anything but an explicit
 * `allowNoExpiry === true` blocks. Other credential kinds are never blocked. */
export function agentTokenBlockedByPolicy(
  credential: { kind: string; expiresAt: Date | null },
  allowNoExpiry: boolean | undefined,
): boolean {
  return (
    credential.kind === "AGENT_TOKEN" && credential.expiresAt === null && allowNoExpiry !== true
  );
}

export function agentTokenClientExpiryCapMs(nowMs: number, maxLifetimeDays: number): number {
  return nowMs + maxLifetimeDays * AGENT_TOKEN_DAY_MS - AGENT_TOKEN_EXPIRY_CLIENT_SKEW_MS;
}

export function endOfLocalDay(date: Date): Date {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate(), 23, 59, 59, 999);
}

/** Last local date whose entire end-of-day fits inside the mint cap. */
export function latestAgentTokenCustomDate(now: Date, maxLifetimeDays: number): Date {
  const capMs = agentTokenClientExpiryCapMs(now.getTime(), maxLifetimeDays);
  const cap = new Date(capMs);
  return new Date(
    cap.getFullYear(),
    cap.getMonth(),
    cap.getDate() - (endOfLocalDay(cap).getTime() > capMs ? 1 : 0),
  );
}
