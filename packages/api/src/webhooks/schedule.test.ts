import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  nextAttemptAt,
  RETRY_DELAYS_MS,
  retryDelayMs,
  shouldDisableEndpoint,
  WEBHOOK_DELIVERY_WINDOW_MS,
  WEBHOOK_MAX_ATTEMPTS,
} from "./schedule";

const HOUR = 3_600_000;

describe("webhook retry schedule", () => {
  it("has 11 attempts whose un-jittered last start fits inside the 24 h window", () => {
    expect(WEBHOOK_MAX_ATTEMPTS).toBe(11);
    const total = RETRY_DELAYS_MS.reduce((sum, delay) => sum + delay, 0);
    expect(total).toBeLessThan(WEBHOOK_DELIVERY_WINDOW_MS);
    expect(total / HOUR).toBeCloseTo(21.875, 2);
  });

  it("jitters within ±20%", () => {
    expect(retryDelayMs(2, 0)).toBe(24_000);
    expect(retryDelayMs(2, 1)).toBe(36_000);
    expect(retryDelayMs(1, 0.5)).toBe(0);
  });

  it("returns null once attempts are used up or the next time passes expiry", () => {
    const now = new Date(0);
    const expiresAt = new Date(WEBHOOK_DELIVERY_WINDOW_MS);
    expect(nextAttemptAt({ completed: 11, maxAttempts: 11, now, expiresAt })).toBeNull();
    expect(
      nextAttemptAt({
        completed: 10,
        maxAttempts: 11,
        now: new Date(23 * HOUR),
        expiresAt,
        random: 0.5,
      }),
    ).toBeNull();
    expect(nextAttemptAt({ completed: 1, maxAttempts: 11, now, expiresAt, random: 0.5 })).toEqual(
      new Date(30_000),
    );
  });

  it("honors Retry-After, capped at 1 h and never sooner than the schedule", () => {
    const now = new Date(0);
    const expiresAt = new Date(WEBHOOK_DELIVERY_WINDOW_MS);
    const base = { completed: 1, maxAttempts: 11, now, expiresAt, random: 0.5 };
    expect(nextAttemptAt({ ...base, retryAfterSeconds: 600 })?.getTime()).toBe(600_000);
    expect(nextAttemptAt({ ...base, retryAfterSeconds: 86_400 })?.getTime()).toBe(HOUR);
    expect(nextAttemptAt({ ...base, retryAfterSeconds: 5 })?.getTime()).toBe(30_000);
  });

  it("disables only after 72 h of failure AND 20 consecutive failures", () => {
    const now = new Date(100 * HOUR);
    expect(shouldDisableEndpoint({ failingSince: new Date(0), consecutiveFailures: 20, now })).toBe(
      true,
    );
    expect(shouldDisableEndpoint({ failingSince: new Date(0), consecutiveFailures: 19, now })).toBe(
      false,
    );
    expect(
      shouldDisableEndpoint({ failingSince: new Date(29 * HOUR), consecutiveFailures: 500, now }),
    ).toBe(false);
    expect(shouldDisableEndpoint({ failingSince: null, consecutiveFailures: 500, now })).toBe(
      false,
    );
  });
});

describe("webhook retry schedule documentation", () => {
  it("docs/guide/webhooks.md lists the first attempt as immediate and each retry delay", () => {
    const guide = readFileSync(
      new URL("../../../../docs/guide/webhooks.md", import.meta.url),
      "utf8",
    ).replace(/\s+/g, " ");
    const unit = (ms: number) =>
      ms >= HOUR ? `${ms / HOUR} h` : ms >= 60_000 ? `${ms / 60_000} m` : `${ms / 1000} s`;
    const [first, ...retries] = RETRY_DELAYS_MS;
    expect(first).toBe(0);
    const listed = retries.map(unit);
    const sentence = `The first attempt is sent immediately. A failed attempt is retried after about ${listed[0]}, then ${listed.slice(1, -1).join(", ")} and ${listed.at(-1)} (each ±20%): ${WEBHOOK_MAX_ATTEMPTS} attempts in total within 24 hours.`;
    expect(guide).toContain(sentence);
    expect(guide).not.toMatch(/retried immediately/);
  });
});
