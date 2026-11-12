vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "image-config-fixture",
  },
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import { accountStoredImageBytes, exactBigint } from "./config";

const db = await pgTestDatabase();
afterAll(() => db.close());

describe("stored-image byte aggregate against real PostgreSQL", () => {
  it("P2-8 (round 2): sum(bigint) comes back as an exact bigint usable in quota arithmetic", async () => {
    const ownerId = randomUUID();
    await db.inspect.user.create({
      data: { id: ownerId, name: "O", email: `${ownerId}@example.test` },
    });
    expect(await accountStoredImageBytes(db.inspect, ownerId)).toBe(0n);
    // Beyond 2^53 so a float conversion would lose the low bits.
    const big = (1n << 60n) + 7n;
    for (const [n, size, state] of [
      [1, big, "STORED"],
      [2, 4096n, "UPLOADING"],
      [3, 1n << 40n, "DELETED"],
    ] as const)
      await db.inspect.sandboxImageArtifact.create({
        data: {
          userId: ownerId,
          fingerprint: `sha256:${String(n).padStart(64, "0")}`,
          architecture: "x86_64",
          sizeBytes: size,
          storeKind: "S3",
          state,
          objectKey: `k/${n}`,
          verifiedAt: state === "STORED" ? new Date() : null,
        },
      });
    const total = await accountStoredImageBytes(db.inspect, ownerId);
    expect(typeof total).toBe("bigint");
    expect(total).toBe(big + 4096n);
    // The upload-begin quota check: total - counted + declared (threw "Cannot mix BigInt").
    expect(total - 4096n + 10n).toBe(big + 10n);
  });

  it("exactBigint refuses lossy aggregate shapes", () => {
    expect(exactBigint(null)).toBe(0n);
    expect(exactBigint(12)).toBe(12n);
    expect(exactBigint({ toString: () => "1152921504606846983" })).toBe(1152921504606846983n);
    expect(() => exactBigint(1.5)).toThrow();
    expect(() => exactBigint({ toString: () => "1.5" })).toThrow();
  });
});
