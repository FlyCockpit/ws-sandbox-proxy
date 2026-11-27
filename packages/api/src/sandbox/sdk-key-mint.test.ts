import { describe, expect, it, vi } from "vitest";

const findFirst = vi.hoisted(() => vi.fn());
vi.mock("@wssp/db", () => ({ default: { sdkKey: { findFirst } } }));
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));

import { rethrowSdkKeyMintError, revokeOwnedKey } from "./sdk-key-mint";

describe("credential-specific refusals", () => {
  it.each([
    ["API", "Could not mint SDK key."],
    ["AGENT_TOKEN", "Could not mint agent token."],
  ] as const)("uses the %s name for mint conflicts", (kind, message) => {
    expect(() => rethrowSdkKeyMintError({ code: "P2002" }, kind)).toThrow(message);
  });
  it.each([
    ["API", "SDK key not found."],
    ["AGENT_TOKEN", "Agent token not found."],
  ] as const)("uses the %s name when no active credential exists", async (kind, message) => {
    findFirst.mockResolvedValueOnce(null);
    await expect(revokeOwnedKey("owner", { id: "missing", kind })).rejects.toThrow(message);
  });
});
