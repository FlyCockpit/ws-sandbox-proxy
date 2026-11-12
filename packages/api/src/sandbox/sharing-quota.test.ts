import type { Prisma } from "@wssp/db";
import { describe, expect, it, vi } from "vitest";
import { disconnectGraceSecondsInput, sharePermissionsInput } from "./pool-input";
import {
  memberQuotaFailure,
  requireShareQuota,
  shareQuotaFailure,
  shareUsageByCreator,
} from "./sharing-quota";

vi.mock("@wssp/db", () => ({ default: {} }));

const used = { memoryMiB: 1024n, vcpu: 2n, diskGiB: 33n };
const none = { memoryMiB: 0n, vcpu: 0n, diskGiB: 0n };
describe("sharing policy and bigint arithmetic", () => {
  it("defaults to BOTH with unlimited caps and preserves zero/30-day grace", () => {
    expect(sharePermissionsInput.parse({})).toEqual({
      canUse: true,
      canContribute: true,
      maxMemoryMiB: null,
      maxVcpu: null,
      maxDiskGiB: null,
    });
    expect(sharePermissionsInput.safeParse({ canUse: false, canContribute: false }).success).toBe(
      false,
    );
    expect(disconnectGraceSecondsInput.parse(0)).toBe(0);
    expect(disconnectGraceSecondsInput.parse(2592000)).toBe(2592000);
  });
  it("checks only increased resources; existing overcommit and retained disk are independent", () => {
    const caps = { maxMemoryMiB: 512, maxVcpu: 1, maxDiskGiB: 33 };
    expect(shareQuotaFailure(caps, used, none)).toBeNull();
    expect(shareQuotaFailure(caps, used, { ...none, diskGiB: 1n })).toBe("disk");
    expect(() => requireShareQuota(caps, used, { ...none, vcpu: 1n })).toThrow();
    expect(
      shareQuotaFailure(
        { maxMemoryMiB: null, maxVcpu: null, maxDiskGiB: null },
        { memoryMiB: 2n ** 60n, vcpu: 2n ** 60n, diskGiB: 2n ** 60n },
        used,
      ),
    ).toBeNull();
  });
  it("classifies share_quota: retryable when usage blocks it, permanent when the request alone exceeds a cap", () => {
    const caps = { maxMemoryMiB: 2048, maxVcpu: 4, maxDiskGiB: 64 };
    const refusal = (current: typeof used, added: typeof used) => {
      try {
        requireShareQuota(caps, current, added);
      } catch (error) {
        return (error as { data: unknown }).data;
      }
      return null;
    };
    expect(refusal(used, { ...none, memoryMiB: 1536n })).toEqual({
      code: "sandbox.share_quota",
      resource: "memory",
      retryable: true,
    });
    expect(refusal(none, { ...none, memoryMiB: 4096n })).toEqual({
      code: "sandbox.share_quota",
      resource: "memory",
      retryable: false,
    });
    // Usage blocks memory, but the request's disk alone can never fit.
    expect(refusal(used, { ...none, memoryMiB: 1536n, diskGiB: 65n })).toEqual({
      code: "sandbox.share_quota",
      resource: "memory",
      retryable: false,
    });
  });
  it("floors member percentages and exempts only owner-local member caps", () => {
    const policy = {
      ownerLocal: false,
      memoryBudgetMiB: 2049,
      vcpuBudget: 5,
      memoryCapPercent: 50,
      vcpuCapPercent: 50,
    };
    expect(memberQuotaFailure(policy, used, { ...none, memoryMiB: 1n })).toBe("memory");
    expect(memberQuotaFailure(policy, used, { ...none, vcpu: 1n })).toBe("vcpu");
    expect(memberQuotaFailure({ ...policy, ownerLocal: true }, used, used)).toBeNull();
  });
});

describe("shareUsageByCreator", () => {
  const client = (rows: unknown[]) => {
    const $queryRaw = vi.fn(async () => rows);
    return { tx: { $queryRaw } as unknown as Prisma.TransactionClient, $queryRaw };
  };
  it("skips the query for an empty page", async () => {
    const { tx, $queryRaw } = client([]);
    expect((await shareUsageByCreator(tx, "pool", [])).size).toBe(0);
    expect($queryRaw).not.toHaveBeenCalled();
  });
  it("defaults creators without rows to zero and maps grouped sums", async () => {
    const { tx, $queryRaw } = client([{ userId: "b", incomplete: 0n, ...used }]);
    const usage = await shareUsageByCreator(tx, "pool", ["a", "b"]);
    expect(usage.get("a")).toEqual(none);
    expect(usage.get("b")).toEqual(used);
    expect($queryRaw).toHaveBeenCalledTimes(1);
  });
  it("refuses the whole read when any creator's evidence is incomplete", async () => {
    const { tx } = client([
      { userId: "a", incomplete: 0n, ...used },
      { userId: "b", incomplete: 1n, ...none },
    ]);
    await expect(shareUsageByCreator(tx, "pool", ["a", "b"])).rejects.toMatchObject({
      code: "CONFLICT",
    });
  });
});
