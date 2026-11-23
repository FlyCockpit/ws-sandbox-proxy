import type { Prisma, default as PrismaClient } from "@wssp/db";
import type { DeepMockProxy } from "vitest-mock-extended";

/** Default authoritative user row so protectedProcedure tests pass unless overridden. */
export const defaultSensitiveSessionGateUser = {
  twoFactorEnabled: true,
  role: "admin" as const,
  emailVerified: true,
  banned: false,
  banExpires: null,
  deletionRequestedAt: null,
  mustChangePassword: false,
  createdAt: new Date("2020-01-01T00:00:00.000Z"),
};

export async function createMockPrisma() {
  const { mockDeep } = await import("vitest-mock-extended");
  const db = mockDeep<typeof PrismaClient>();
  db.sandboxHost.findFirstOrThrow.mockResolvedValue({ rootCount: 0, connectionEpoch: 1 } as never);
  db.sandboxHostStoragePool.findMany.mockResolvedValue([
    {
      id: "storage-1",
      name: "default",
      marker: "a".repeat(32),
      capacityGiB: 8192,
      diskReservedGiB: 0,
      health: "healthy",
      draining: false,
      newRootsAllowed: true,
      connectionEpoch: 1,
      reportedAt: new Date(),
    },
  ] as never);
  db.sandboxHostStoragePool.updateMany.mockResolvedValue({ count: 1 });
  db.appSetting.findMany.mockResolvedValue([]);
  // The SDK key list reads each page's last CLI connect (wssp-ssh §10).
  // (`groupBy`'s generic overloads defeat the deep-mock typing; the runtime mock is plain.)
  (
    db.sandboxConnectSession.groupBy as unknown as { mockResolvedValue(value: unknown): unknown }
  ).mockResolvedValue([]);
  db.sandboxPool.findMany.mockResolvedValue([]);
  db.sandboxPoolMember.findMany.mockResolvedValue([]);
  db.session.findUnique.mockResolvedValue({ id: "test-session-id" } as never);
  db.$queryRaw.mockImplementation((query) => {
    const sql = Array.isArray(query) ? query.join("?") : "";
    const promise = Promise.resolve(
      sql.startsWith("SELECT id FROM sandbox_host") ||
        sql.startsWith("SELECT id FROM sandbox_instance WHERE") ||
        sql.includes("FROM sandbox_template_availability a JOIN")
        ? [{ id: "locked" }]
        : sql.includes("clock_timestamp()")
          ? [{ now: new Date() }]
          : [],
    );
    return Object.defineProperty(promise, Symbol.toStringTag, {
      value: "PrismaPromise",
    }) as Prisma.PrismaPromise<unknown>;
  });
  db.$transaction.mockImplementation(async (work) => {
    if (typeof work === "function") return work(db);
    return Promise.all(work);
  });
  db.user.findUnique.mockResolvedValue({ ...defaultSensitiveSessionGateUser } as never);
  return db;
}

export function wireSensitiveSessionGateUser(
  db: MockPrisma,
  overrides: Partial<typeof defaultSensitiveSessionGateUser> & { role?: unknown },
) {
  db.user.findUnique.mockResolvedValue({
    ...defaultSensitiveSessionGateUser,
    ...overrides,
  } as never);
}

export type MockPrisma = DeepMockProxy<typeof PrismaClient>;
