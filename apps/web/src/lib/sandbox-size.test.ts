import { expect, it } from "vitest";
import { fakeHost, fakeStoragePool } from "@/test/sandbox-fake";
import { createLifetimeDefault, DEFAULT_SANDBOX_DRAFT } from "./sandbox-rules";
import { gibFromMib, hostChoice, hostSizeCap } from "./sandbox-size";

type Host = Parameters<typeof hostSizeCap>[0] & { draining: boolean };
const host = (overrides: Record<string, unknown> = {}) => fakeHost(overrides) as unknown as Host;
const capacity = (overrides: Record<string, unknown>) => ({
  ...(fakeHost().capacity as Record<string, unknown>),
  ...overrides,
});

it("a host's cap is its per-VM maximum and free capacity, after the VM and root overheads", () => {
  const now = Date.now() + 1_000;
  expect(
    hostSizeCap(
      host({
        capacity: capacity({ maxCpuCount: 16, vcpuAvailable: 6, memoryAvailableMiB: 4000 }),
        storagePools: [
          fakeStoragePool({ capacityGiB: 100, diskReservedGiB: 90 }),
          fakeStoragePool({ id: "s2", capacityGiB: 500, diskReservedGiB: 100 }),
          fakeStoragePool({ id: "s3", capacityGiB: 4000, draining: true }),
        ],
      }),
      now,
    ),
  ).toEqual({ cpuCount: 6, memoryMiB: 3584, diskGiB: 399 });
  // A stale report caps nothing: the server decides.
  expect(hostSizeCap(host({ capacity: capacity({ current: false }) }), now)).toBeNull();
});

it("a host choice is unavailable when draining, without storage or too small; offline stays selectable", () => {
  const now = Date.now() + 1_000;
  expect(hostChoice(host(), {}, now)).toEqual({ kind: "available" });
  expect(hostChoice(host({ draining: true }), {}, now)).toEqual({
    kind: "unavailable",
    reason: "draining",
  });
  expect(hostChoice(host({ storagePools: [] }), {}, now)).toEqual({
    kind: "unavailable",
    reason: "storage",
  });
  expect(hostChoice(host(), { cpuCount: 8 }, now)).toEqual({
    kind: "unavailable",
    reason: "size",
  });
  expect(hostChoice(host({ status: "DISCONNECTED" }), {}, now)).toMatchObject({ kind: "offline" });
});

it("a connected host without a current report is 'unmeasured', never 'offline' or 'stale'", () => {
  const now = Date.now() + 1_000;
  expect(hostChoice(host({ capacity: capacity({ current: false }) }), {}, now)).toEqual({
    kind: "unmeasured",
  });
  expect(hostChoice(host({ capacity: capacity({ memoryBudgetMiB: null }) }), {}, now)).toEqual({
    kind: "unmeasured",
  });
});

it("storage is judged as of the list's read, so an aged browser copy is not 'no storage' or 0 GiB", () => {
  const read = Date.now();
  const later = read + 20_000;
  const fresh = host({
    lastHeartbeatAt: new Date(later - 1_000),
    storagePools: [fakeStoragePool({ reportedAt: new Date(read - 5_000).toISOString() })],
  });
  // Judged at `later` alone, the storage report reads stale.
  expect(hostChoice(fresh, { cpuCount: 1, memoryMiB: 1024, diskGiB: 8 }, later)).toEqual({
    kind: "unavailable",
    reason: "storage",
  });
  expect(hostSizeCap(fresh, later)?.diskGiB).toBe(0);
  // As of the read it was current.
  expect(hostChoice(fresh, { cpuCount: 1, memoryMiB: 1024, diskGiB: 8 }, later, read)).toEqual({
    kind: "available",
  });
  expect(hostSizeCap(fresh, later, read)?.diskGiB).toBe(95);
});

it("a host whose memory is full is unavailable for RAM even when its storage is gone too", () => {
  const now = Date.now() + 1_000;
  expect(
    hostChoice(
      host({ capacity: capacity({ memoryAvailableMiB: 300 }), storagePools: [] }),
      { memoryMiB: 1024 },
      now,
    ),
  ).toEqual({ kind: "unavailable", reason: "ram" });
});

it("Create defaults to one hour then stop, clamped to a shorter placement maximum", () => {
  expect(DEFAULT_SANDBOX_DRAFT).toMatchObject({ lifetimeMinutes: "60", onExpire: "stop" });
  expect(createLifetimeDefault({ maxTimeoutMs: 86_400_000, allowUnlimited: true })).toBe("60");
  expect(createLifetimeDefault({ maxTimeoutMs: 17 * 60_000, allowUnlimited: false })).toBe("15");
  expect(createLifetimeDefault({ maxTimeoutMs: 5 * 60_000, allowUnlimited: false })).toBe("5");
  expect(gibFromMib(3584)).toBe(3.5);
});
