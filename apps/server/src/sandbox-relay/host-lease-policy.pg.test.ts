/**
 * `host.lease-policy` report handling on real PostgreSQL: the epoch and
 * monotonic-sequence fences, the current-link check, the write-on-change rule
 * under H, and the wake of the pull-in sweep after commit.
 */
vi.mock("@wssp/db", async () => {
  const { pgTestDatabase: database } = await import("@wssp/db/testing/pg");
  return { default: (await database()).prisma };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
const wakes = vi.hoisted(() => ({ notify: vi.fn() }));
vi.mock("@wssp/api/sandbox/sharing-access", async (original) => ({
  ...(await original<typeof import("@wssp/api/sandbox/sharing-access")>()),
  notifySharingAccessChanged: wakes.notify,
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeEach, expect, it, vi } from "vitest";
import { seedLaunchHost } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import { recordHostLeasePolicy } from "./host-lease-policy";

const db = await pgTestDatabase();
afterAll(() => db.close());
beforeEach(() => wakes.notify.mockClear());

async function link() {
  const ownerId = `user-${randomUUID()}`;
  await db.inspect.user.create({
    data: { id: ownerId, name: "Owner", email: `${ownerId}@example.test` },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: ownerId, slug: "lab", label: "Lab", status: "CONNECTED", connectionEpoch: 3 },
  });
  return {
    hostId: host.id,
    session: {
      identity: { hostId: host.id, userId: ownerId },
      connectionEpoch: 3,
      leaseSequence: 0,
    },
  };
}
const report = (sequence: number, maxLeaseMs: number | null, connectionEpoch = 3) => ({
  type: "host.lease-policy" as const,
  connectionEpoch,
  sequence,
  maxLeaseMs,
});
const stored = async (hostId: string) =>
  (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: hostId } })).daemonMaxLeaseMs;

it("writes a changed ceiling under H on the current epoch and wakes the sweep", async () => {
  const { hostId, session } = await link();
  expect(await recordHostLeasePolicy(session, report(1, 21_600_000), () => true)).toBe(true);
  expect(await stored(hostId)).toBe(21_600_000);
  expect(wakes.notify).toHaveBeenCalledTimes(1);
  expect(await recordHostLeasePolicy(session, report(2, null), () => true)).toBe(true);
  expect(await stored(hostId)).toBeNull();
  // Back from unlimited to finite is a change too.
  expect(await recordHostLeasePolicy(session, report(3, 3_600_000), () => true)).toBe(true);
  expect(await stored(hostId)).toBe(3_600_000);
});

it("an unchanged value writes nothing and does not wake", async () => {
  const { hostId, session } = await link();
  const before = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: hostId } });
  expect(await recordHostLeasePolicy(session, report(1, 86_400_000), () => true)).toBe(false);
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: hostId } })).updatedAt,
  ).toEqual(before.updatedAt);
  expect(wakes.notify).not.toHaveBeenCalled();
});

it("refuses a stale sequence, a foreign epoch, a replaced link and a newer DB epoch", async () => {
  const { hostId, session } = await link();
  expect(await recordHostLeasePolicy(session, report(2, 21_600_000), () => true)).toBe(true);
  // Sequence must strictly increase.
  expect(await recordHostLeasePolicy(session, report(2, null), () => true)).toBe(false);
  expect(await recordHostLeasePolicy(session, report(1, null), () => true)).toBe(false);
  // Another epoch's report is ignored.
  expect(await recordHostLeasePolicy(session, report(3, null, 4), () => true)).toBe(false);
  // The link was replaced while the report was in flight.
  expect(await recordHostLeasePolicy(session, report(4, null), () => false)).toBe(false);
  // A newer hello committed: the row's epoch no longer matches the session.
  await db.inspect.sandboxHost.update({ where: { id: hostId }, data: { connectionEpoch: 4 } });
  expect(await recordHostLeasePolicy(session, report(5, null), () => true)).toBe(false);
  expect(await stored(hostId)).toBe(21_600_000);
  expect(wakes.notify).toHaveBeenCalledTimes(1);
});
