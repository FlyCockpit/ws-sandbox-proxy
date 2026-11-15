import {
  AGENT_TOKEN_DAY_MS,
  AGENT_TOKEN_EXPIRY_CLIENT_SKEW_MS,
  agentTokenClientExpiryCapMs,
  agentTokenExpiryRejection,
  endOfLocalDay,
} from "@wssp/config/agent-token-limits";
import { describe, expect, it } from "vitest";
import {
  agentTokenExpiry,
  agentTokenExpiryPresets,
  latestAgentTokenCustomDate,
  localDateInputValue,
} from "./agent-token-expiry";

const now = new Date(2026, 10, 13, 12).getTime();
const policy = { allowNoExpiry: true, maxLifetimeDays: 90 };

describe("agent token expiry", () => {
  it("filters the 7d / 30d / 90d / 1y presets by the deployment cap", () => {
    expect(agentTokenExpiryPresets(1)).toEqual([]);
    expect(agentTokenExpiryPresets(7)).toEqual(["7d"]);
    expect(agentTokenExpiryPresets(30)).toEqual(["7d", "30d"]);
    expect(agentTokenExpiryPresets(90)).toEqual(["7d", "30d", "90d"]);
    expect(agentTokenExpiryPresets(3650)).toEqual(["7d", "30d", "90d", "365d"]);
    expect(agentTokenExpiry("365d", "", now, policy)).toBeUndefined();
    expect(agentTokenExpiry("8d", "", now, policy)).toBeUndefined();
  });
  it("uses a 60-second skew margin for a rolling preset", () => {
    expect(agentTokenExpiry("90d", "", now, policy)?.getTime()).toBe(
      now + 90 * AGENT_TOKEN_DAY_MS - AGENT_TOKEN_EXPIRY_CLIENT_SKEW_MS,
    );
  });
  it("allows never only when enabled", () => {
    expect(agentTokenExpiry("never", "", now, policy)).toBeNull();
    expect(agentTokenExpiry("never", "", now, { ...policy, allowNoExpiry: false })).toBeUndefined();
  });
  it("bounds the entire custom local date and rejects malformed or normalized dates", () => {
    const latest = latestAgentTokenCustomDate(new Date(now), 90);
    const cap = agentTokenClientExpiryCapMs(now, 90);
    expect(endOfLocalDay(latest).getTime()).toBeLessThanOrEqual(cap);
    const tomorrow = new Date(latest.getFullYear(), latest.getMonth(), latest.getDate() + 1);
    expect(endOfLocalDay(tomorrow).getTime()).toBeGreaterThan(cap);
    expect(agentTokenExpiry("custom", localDateInputValue(latest), now, policy)).toEqual(
      endOfLocalDay(latest),
    );
    expect(agentTokenExpiry("custom", localDateInputValue(tomorrow), now, policy)).toBeUndefined();
    for (const value of ["", "2026-02-30", "2026-01-01", "13/11/2026", "2027-13-01"])
      expect(agentTokenExpiry("custom", value, now, policy)).toBeUndefined();
    expect(agentTokenExpiry("custom", "2026-11-14", now, policy)).toEqual(
      endOfLocalDay(new Date(2026, 10, 14)),
    );
  });
  it("accepts the exact server cap and refuses cap+1ms, past, and disabled null", () => {
    const cap = now + 90 * AGENT_TOKEN_DAY_MS;
    expect(agentTokenExpiryRejection(new Date(cap), now, policy)).toBeNull();
    expect(agentTokenExpiryRejection(new Date(cap + 1), now, policy)).toBe("too_far");
    expect(agentTokenExpiryRejection(new Date(now), now, policy)).toBe("past");
    expect(agentTokenExpiryRejection(null, now, { ...policy, allowNoExpiry: false })).toBe(
      "no_expiry_disabled",
    );
  });
});
