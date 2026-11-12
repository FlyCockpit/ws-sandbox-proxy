import { beforeEach, expect, it, vi } from "vitest";

const capEnv = vi.hoisted(() => ({}) as { SANDBOX_MAX_HOSTS_PER_OWNER?: number | null });
vi.mock("@wssp/env/server", () => ({ env: capEnv }));

const { assertOwnerHostCapacity, maxHostsPerOwner, DEFAULT_MAX_HOSTS_PER_OWNER } = await import(
  "./owner-host-cap"
);

function tx(count: number) {
  return {
    $queryRaw: vi.fn(async () => [{ locked: 1 }]),
    sandboxHost: { count: vi.fn(async () => count) },
  };
}
type Tx = Parameters<typeof assertOwnerHostCapacity>[0];

beforeEach(() => {
  delete capEnv.SANDBOX_MAX_HOSTS_PER_OWNER;
});

it("an unset value is the default cap, never unlimited", () => {
  expect(DEFAULT_MAX_HOSTS_PER_OWNER).toBe(20);
  expect(maxHostsPerOwner()).toBe(20);
  capEnv.SANDBOX_MAX_HOSTS_PER_OWNER = null;
  expect(maxHostsPerOwner()).toBeNull();
});

it("locks before counting and refuses at the cap with a typed CONFLICT", async () => {
  capEnv.SANDBOX_MAX_HOSTS_PER_OWNER = 3;
  const full = tx(3);
  await expect(assertOwnerHostCapacity(full as unknown as Tx, "owner-1")).rejects.toMatchObject({
    code: "CONFLICT",
    data: { code: "sandbox.owner_host_limit", limit: 3 },
  });
  expect(full.$queryRaw).toHaveBeenCalledTimes(1);
  expect(full.$queryRaw.mock.invocationCallOrder[0]).toBeLessThan(
    full.sandboxHost.count.mock.invocationCallOrder[0]!,
  );
  expect(full.sandboxHost.count).toHaveBeenCalledWith({ where: { userId: "owner-1" } });
  // Inverse: one below the cap is admitted.
  await expect(assertOwnerHostCapacity(tx(2) as unknown as Tx, "owner-1")).resolves.toBeUndefined();
});

it("unlimited preserves the enrollment lock and skips the count", async () => {
  capEnv.SANDBOX_MAX_HOSTS_PER_OWNER = null;
  const unlimited = tx(1_000_000);
  await expect(
    assertOwnerHostCapacity(unlimited as unknown as Tx, "owner-1"),
  ).resolves.toBeUndefined();
  expect(unlimited.$queryRaw).toHaveBeenCalledTimes(1);
  expect(unlimited.sandboxHost.count).not.toHaveBeenCalled();
});
