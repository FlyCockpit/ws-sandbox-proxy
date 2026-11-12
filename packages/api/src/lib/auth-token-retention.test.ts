import { beforeEach, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});

import prisma from "@wssp/db";
import { reapExpiredAuthTokens } from "./auth-token-retention";

const db = vi.mocked(prisma, true);
beforeEach(() => vi.resetAllMocks());

it("rechecks expiry at deletion so tokens renewed after selection survive", async () => {
  const cutoff = new Date("2026-11-12T00:00:00Z");
  for (const delegate of [db.session, db.verification, db.deviceCode]) {
    delegate.findMany.mockResolvedValue([{ id: "selected-token" }] as never);
    delegate.deleteMany.mockResolvedValue({ count: 0 });
  }
  expect(await reapExpiredAuthTokens(cutoff)).toEqual({
    deleted: { sessions: 0, verifications: 0, deviceCodes: 0 },
  });
  for (const delegate of [db.session, db.verification, db.deviceCode]) {
    expect(delegate.deleteMany).toHaveBeenCalledExactlyOnceWith({
      where: { id: { in: ["selected-token"] }, expiresAt: { lt: cutoff } },
    });
  }
});
