import { ORPCError } from "@orpc/server";
import { expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("@wssp/env/server", () => ({ env: {} }));
vi.mock("./host-admission", () => ({ STORAGE_HEALTH_STALE_MS: 15000 }));

vi.mock("./direct-placement", () => ({
  lockOwnerPlacement: vi.fn(),
  resolveDirectPlacement: vi.fn(),
}));
vi.mock("./pool-visibility", () => ({ visiblePool: vi.fn() }));
vi.mock("./relay-fence", () => ({ hostDatabaseNow: vi.fn() }));
vi.mock("./template-resolution", () => ({ resolveTemplateRevision: vi.fn() }));
vi.mock("./idempotency", () => ({ requestDigestMetadata: vi.fn() }));

import {
  hostCapacityConflict,
  hostDrainingConflict,
  hostUnavailable,
  templateImageRejected,
  unsupportedCapability,
  vmSizeUnsupported,
} from "./errors";
import { poolHostRecheck, retryPlacement } from "./pool-placement";

it.each([
  hostCapacityConflict(),
  vmSizeUnsupported(),
  hostDrainingConflict(),
  hostUnavailable(),
  templateImageRejected("changed image"),
  unsupportedCapability("egress"),
])(
  "selected host refusal $data.code retries within the existing bound and never leaks",
  async (error) => {
    const work = vi.fn(async () => {
      throw error;
    });
    await expect(retryPlacement(() => poolHostRecheck("pool", work))).rejects.toMatchObject({
      code: "SERVICE_UNAVAILABLE",
    });
    expect(work).toHaveBeenCalledTimes(3);
    work.mockClear();
    await expect(retryPlacement(() => poolHostRecheck(null, work))).rejects.toBe(error);
    expect(work).toHaveBeenCalledTimes(1);
  },
);
it.each([new ORPCError("FORBIDDEN"), new Error("database fault"), unsupportedCapability("pause")])(
  "pool host rechecks preserve unrelated failures",
  async (error) => {
    const work = vi.fn(async () => {
      throw error;
    });
    await expect(retryPlacement(() => poolHostRecheck("pool", work))).rejects.toBe(error);
    expect(work).toHaveBeenCalledTimes(1);
  },
);

it("orders the build and startup stages right after compatible, in the static set too", async () => {
  const { PLACEMENT_STAGES, STATIC_STAGES } = await import("./pool-placement");
  // The tunnel stage and CLI logins' static owner stage follow them, before templateKnown.
  const head = [
    "enabled",
    "compatible",
    "builder",
    "startup",
    "tunnel",
    "credentialOwner",
    "templateKnown",
  ];
  expect(PLACEMENT_STAGES.slice(0, 7)).toEqual(head);
  expect(STATIC_STAGES.slice(0, 7)).toEqual(head);
});

it("the tunnel stage is inert unless the create declares tunnel ports", async () => {
  const { placementSql } = await import("./pool-placement");
  const { requestDigestMetadata } = await import("./idempotency");
  vi.mocked(requestDigestMetadata).mockReturnValue({ requestDigestKeyId: "kid" } as never);
  const base = {
    viewer: { ownerId: "owner", allowedHostIds: "allOwned" as const },
    poolId: "pool",
    revision: {
      id: "rev",
      incusFingerprint: "f",
      architecture: "x86_64",
      manifestDigest: "d",
    } as never,
    size: { cpuCount: 1, memoryMiB: 1024, diskGiB: 32 },
    now: new Date(),
  };
  const off = placementSql(base).stages.tunnel;
  const on = placementSql({ ...base, tunnel: true }).stages.tunnel;
  expect(off.sql).toBe("TRUE");
  expect(on.sql).toContain('"daemonTunnel" IS NOT NULL');
  expect(on.sql).toContain("allowForOthers");
  expect(on.values).toContain("owner");
});

it("the startup stage is inert unless the revision has a start command", async () => {
  const { placementSql } = await import("./pool-placement");
  const { requestDigestMetadata } = await import("./idempotency");
  vi.mocked(requestDigestMetadata).mockReturnValue({ requestDigestKeyId: "k" } as never);
  const query = {
    viewer: { ownerId: "owner-1", allowedHostIds: "allOwned" as const },
    poolId: "pool-1",
    revision: { id: "r", incusFingerprint: "f", architecture: "x86_64", manifestDigest: "d" },
    size: { cpuCount: 1, memoryMiB: 512, diskGiB: 1 },
    now: new Date(0),
  };
  expect(placementSql(query).stages.startup.sql).toBe("TRUE");
  expect(placementSql({ ...query, startup: true }).stages.startup.sql).toContain(
    "'templateStartup'",
  );
});

it("the builder stage is inert unless the query is a build", async () => {
  const { placementSql } = await import("./pool-placement");
  const { requestDigestMetadata } = await import("./idempotency");
  vi.mocked(requestDigestMetadata).mockReturnValue({ requestDigestKeyId: "k" } as never);
  const query = {
    viewer: { ownerId: "owner-1", allowedHostIds: "allOwned" as const },
    poolId: "pool-1",
    revision: { id: "r", incusFingerprint: "f", architecture: "x86_64", manifestDigest: "d" },
    size: { cpuCount: 1, memoryMiB: 512, diskGiB: 1 },
    now: new Date(0),
  };
  const plain = placementSql(query);
  expect(plain.builder).toBeNull();
  expect(plain.stages.builder.sql).toBe("TRUE");
  const build = placementSql({
    ...query,
    build: { allowForeign: false, targetPlacement: "ANY_NODE", imageMode: "s3" },
  });
  expect(build.builder).not.toBeNull();
  expect(build.stages.builder.sql).toContain("'build'");
});
