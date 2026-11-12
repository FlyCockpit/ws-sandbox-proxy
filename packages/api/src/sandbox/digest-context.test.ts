import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));

const { digestContextSnapshot, parseDigestContext } = await import("./digest-context");

describe("digest context snapshot (§8.3a)", () => {
  it("round-trips and fails closed on a malformed stored snapshot", () => {
    const snapshot = digestContextSnapshot(
      { domain: "wssp-request-v2", hostId: "h", hostOwnerId: "o" },
      { generation: 3, configId: "cfg", usagePoolId: null, usageMemberId: null },
    );
    expect(parseDigestContext(snapshot)).toEqual(snapshot);
    expect(() => parseDigestContext(null)).toThrow();
    expect(() => parseDigestContext({ ...snapshot, version: 9 })).toThrow();
    expect(() => parseDigestContext({ ...snapshot, extra: true })).toThrow();
  });
});
