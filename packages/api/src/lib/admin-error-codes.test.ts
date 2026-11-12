import { describe, expect, it, vi } from "vitest";

import { ACCOUNT_DELETION_BLOCKER_KINDS, ADMIN_ERROR_CODES } from "./admin-error-codes";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});

const { ACCOUNT_DELETION_CLASSIFICATION } = await import("@wssp/db/account-deletion");

describe("admin error codes", () => {
  it("mirrors exactly the account-deletion blocker kinds the database layer can report", () => {
    const dbKinds = ACCOUNT_DELETION_CLASSIFICATION.flatMap((entry) =>
      entry.class === "blocker" ? [entry.kind] : [],
    );
    expect([...ACCOUNT_DELETION_BLOCKER_KINDS].sort()).toEqual([...new Set(dbKinds)].sort());
  });

  it("keeps every code unique and namespaced", () => {
    const codes = Object.values(ADMIN_ERROR_CODES);
    expect(new Set(codes).size).toBe(codes.length);
    for (const code of codes) expect(code).toMatch(/^admin\.[a-z_]+$/);
  });
});
