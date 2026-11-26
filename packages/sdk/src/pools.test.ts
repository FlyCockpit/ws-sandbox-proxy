import { expect, it } from "vitest";
import { createWsspClient } from "./client";
import { WsspError } from "./errors";

const now = "2026-10-27T00:00:00.000Z";
it("discovers pools and members with numeric bounded pagination and strict DTOs", async () => {
  const calls: URL[] = [];
  const pool = {
    id: "pool_1",
    slug: "lab",
    label: "Lab",
    createdAt: now,
    updatedAt: now,
    lease: { maxTimeoutMs: 21_600_000, timeoutZero: false },
    preferOwnHosts: true,
    capacityWait: { maxWaitMs: 3_600_000, perKey: 16, perOwner: 64 },
  };
  const client = createWsspClient({
    baseUrl: "https://api.example.test",
    apiKey: "wssp_sdk_fixture",
    fetch: async (input) => {
      const url = new URL(String(input));
      calls.push(url);
      return Response.json(
        url.pathname.endsWith("/members")
          ? {
              items: [
                {
                  id: "member_1",
                  poolId: pool.id,
                  hostId: "host_1",
                  enabled: true,
                  createdAt: now,
                  updatedAt: now,
                  host: {
                    id: "host_1",
                    slug: "host",
                    label: "Host",
                    draining: true,
                    status: "CONNECTED",
                  },
                },
              ],
              nextCursor: null,
            }
          : url.pathname.endsWith("/pools")
            ? { items: [pool], nextCursor: null }
            : { ...pool, memberCount: 1 },
      );
    },
  });
  expect((await client.pools.list({ limit: 1 })).items[0]).toEqual(pool);
  expect(await client.pools.get(pool.id)).toMatchObject({ memberCount: 1 });
  const member = (await client.pools.members(pool.id, { limit: 2 })).items[0];
  expect(member && "host" in member && member.host.draining).toBe(true);
  expect(calls.map((url) => url.pathname)).toEqual([
    "/v1/pools",
    "/v1/pools/pool_1",
    "/v1/pools/pool_1/members",
  ]);
  expect(calls[0]?.searchParams.get("limit")).toBe("1");
  expect(() => client.pools.list({ limit: 101 })).toThrow(WsspError);
  expect(calls).toHaveLength(3);
});

it("decodes shared pool identity, own quota usage and opaque members; rejects mixed metadata", async () => {
  const pool = {
    id: "shared",
    slug: "lab",
    label: "Shared",
    createdAt: now,
    updatedAt: now,
    lease: { maxTimeoutMs: 86_400_000, timeoutZero: true },
    preferOwnHosts: false,
    capacityWait: { maxWaitMs: null, perKey: null, perOwner: null },
    owner: { id: "owner", name: "Owner" },
    disconnectGraceSeconds: 60,
    share: {
      canUse: true,
      canContribute: false,
      maxMemoryMiB: null,
      maxVcpu: 2,
      maxDiskGiB: null,
      usage: { memoryMiB: "1280", vcpu: "1", diskGiB: "33" },
    },
  };
  let mixed = false;
  const client = createWsspClient({
    baseUrl: "https://api.example.test",
    apiKey: "wssp_sdk_fixture",
    fetch: async (input) =>
      Response.json(
        String(input).endsWith("/members")
          ? {
              items: [{ id: "member", poolId: "shared", ...(mixed ? { hostId: "hidden" } : {}) }],
              nextCursor: null,
            }
          : { items: [pool], nextCursor: null },
      ),
  });
  expect((await client.pools.list()).items).toEqual([pool]);
  expect((await client.pools.members("shared")).items).toEqual([
    { id: "member", poolId: "shared" },
  ]);
  mixed = true;
  await expect(client.pools.members("shared")).rejects.toMatchObject({ kind: "protocol" });
});

it("reads pool capacity with a numeric query, strictly decoded", async () => {
  const calls: URL[] = [];
  const capacity = {
    poolId: "pool_1",
    templateRevisionId: "rev_1",
    size: { cpuCount: 1, memoryMiB: 1024, diskGiB: 32 },
    aggregate: {
      free: { memoryMiB: 4096, vcpu: 8, diskGiB: 100 },
      budget: { memoryMiB: 8192, vcpu: 16, diskGiB: 200 },
    },
    fits: 3,
    largest: { cpuCount: 8, memoryMiB: 3584, diskGiB: 99 },
    lease: { maxTimeoutMs: 86_400_000, timeoutZero: false },
    queue: {
      waiting: 2,
      mine: 1,
      myOldestPosition: 2,
      limits: { maxWaitMs: 3_600_000, perKey: 16, perOwner: 64 },
      preferOwnHosts: true,
    },
    hosts: [],
  };
  const client = createWsspClient({
    baseUrl: "https://api.example.test",
    apiKey: "wssp_sdk_fixture",
    fetch: async (input) => {
      calls.push(new URL(String(input)));
      return Response.json(capacity);
    },
  });
  expect(await client.pools.capacity("pool_1", { template: "base", memoryMiB: 1024 })).toEqual(
    capacity,
  );
  expect(calls[0]?.pathname).toBe("/v1/pools/pool_1/capacity");
  expect(calls[0]?.searchParams.get("memoryMiB")).toBe("1024");
  expect(() => client.pools.capacity("pool_1", { cpuCount: 0 })).toThrow(WsspError);
  await expect(
    createWsspClient({
      baseUrl: "https://api.example.test",
      apiKey: "wssp_sdk_fixture",
      fetch: async () => Response.json({ ...capacity, hosts: [{ id: "foreign" }] }),
    }).pools.capacity("pool_1"),
  ).rejects.toMatchObject({ kind: "protocol" });
});
