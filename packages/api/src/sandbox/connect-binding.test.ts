import { ORPCError } from "@orpc/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/env/server", () => ({ env: { BETTER_AUTH_SECRET: "connect-binding-test" } }));
vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep<typeof import("@wssp/db").default>() };
});
const authorize = vi.hoisted(() => ({
  current: true,
  refusal: null as Error | null,
  calls: [] as unknown[][],
}));
vi.mock("../lib/sdk-key-access", () => ({
  authorizeRetainedServiceAction: async (...args: unknown[]) => {
    authorize.calls.push(args);
    if (authorize.refusal) throw authorize.refusal;
    return { context: {}, current: () => authorize.current, recheck: vi.fn() };
  },
}));

const { default: db } = await import("@wssp/db");
const { checkSandboxConnect } = await import("./connect-binding");

const principal = {
  kind: "sdkKey",
  credentialKind: "API",
  ownSandboxesOnly: false,
  expiresAt: new Date("2027-01-01T00:00:00Z"),
  keyId: "key-1",
  ownerId: "owner-1",
  resourceMode: "ALL_OWNED",
  scopes: new Set(["sandboxes:connect"]),
  allowedHostIds: "allOwned",
  allowedRevisionIds: "allOwned",
  allowedPoolIds: "allUsable",
} as const;
const now = new Date("2026-11-20T00:00:00Z");

function sandbox(overrides: Record<string, unknown> = {}) {
  return {
    state: "READY",
    purpose: "WORKLOAD",
    buildId: null,
    verifyBuildId: null,
    generation: 3,
    sandboxHostId: "host-1",
    hostOwnerId: "owner-1",
    accessGraceUntil: null,
    leaseExpiresAt: new Date("2026-11-20T01:00:00Z"),
    SandboxHost: { userId: "owner-1", connectionEpoch: 7, deletionRequestedAt: null },
    CurrentPlacement: null,
    ...overrides,
  };
}

const check = (expected?: Parameters<typeof checkSandboxConnect>[2]) =>
  checkSandboxConnect(principal as never, "sbx-1", expected, () => now);

beforeEach(() => {
  authorize.current = true;
  authorize.refusal = null;
  authorize.calls.length = 0;
  db.sandbox.findFirst.mockReset();
});

describe("checkSandboxConnect", () => {
  it("binds the connection to the server's own records", async () => {
    db.sandbox.findFirst.mockResolvedValue(sandbox() as never);
    const checked = await check();
    expect(authorize.calls[0]).toEqual([principal, "sandboxes.connect", { sandboxId: "sbx-1" }]);
    // Owner-scoped read: another owner's row is never read.
    expect(db.sandbox.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: "sbx-1", userId: "owner-1" } }),
    );
    expect(checked).toMatchObject({
      ok: true,
      binding: {
        ownerId: "owner-1",
        keyId: "key-1",
        sandboxId: "sbx-1",
        hostId: "host-1",
        hostOwnerId: "owner-1",
        generation: 3,
        epoch: 7,
        keyExpiresAt: principal.expiresAt,
        leaseExpiresAt: new Date("2026-11-20T01:00:00Z"),
      },
    });
  });

  it("propagates the authorization's refusal (403 / 404 / sandbox.managed)", async () => {
    for (const error of [
      new ORPCError("FORBIDDEN"),
      new ORPCError("NOT_FOUND"),
      new ORPCError("CONFLICT", { data: { code: "sandbox.managed" } }),
    ]) {
      authorize.refusal = error;
      await expect(check()).rejects.toBe(error);
    }
    expect(db.sandbox.findFirst).not.toHaveBeenCalled();
  });

  it("decides nothing on a read an authority change overlapped", async () => {
    db.sandbox.findFirst.mockResolvedValue(sandbox() as never);
    authorize.current = false;
    expect(await check()).toEqual({ ok: false, intent: "stale" });
  });

  it.each([
    [{ purpose: "TEMPLATE_BUILD" }, "unsupported"],
    [{ buildId: "build-1" }, "unsupported"],
    [{ verifyBuildId: "build-1" }, "unsupported"],
    [{ accessGraceUntil: now }, "revoked"],
    [{ state: "STOPPING" }, "sandbox_stopped"],
    [{ state: "STOPPED" }, "sandbox_stopped"],
    [{ state: "OFFLOADED" }, "sandbox_stopped"],
    [{ state: "DELETED" }, "sandbox_destroyed"],
    [{ state: "RECLAIMING" }, "sandbox_destroyed"],
    [{ state: "HOST_LOST" }, "sandbox_destroyed"],
    [{ leaseExpiresAt: now }, "expired"],
    [{ state: "CREATING" }, "lifecycle_unconfirmed"],
    [{ sandboxHostId: null }, "lifecycle_unconfirmed"],
    [{ SandboxHost: null }, "revoked"],
    [
      { SandboxHost: { userId: "owner-1", connectionEpoch: 7, deletionRequestedAt: now } },
      "revoked",
    ],
    // On another owner's node only a current placement carries the grant.
    [
      {
        hostOwnerId: "node-owner",
        SandboxHost: { userId: "node-owner", connectionEpoch: 7, deletionRequestedAt: null },
      },
      "revoked",
    ],
    [
      {
        hostOwnerId: "node-owner",
        SandboxHost: { userId: "node-owner", connectionEpoch: 7, deletionRequestedAt: null },
        CurrentPlacement: {
          userId: "owner-1",
          hostOwnerId: "node-owner",
          originHostId: "host-1",
          generation: 2,
        },
      },
      "revoked",
    ],
  ])("refuses %j with %s", async (overrides, intent) => {
    db.sandbox.findFirst.mockResolvedValue(sandbox(overrides) as never);
    expect(await check()).toEqual({ ok: false, intent });
  });

  it("a missing sandbox after authorization is destroyed", async () => {
    db.sandbox.findFirst.mockResolvedValue(null);
    expect(await check()).toEqual({ ok: false, intent: "sandbox_destroyed" });
  });

  it("a shared-pool placement that matches is usable", async () => {
    db.sandbox.findFirst.mockResolvedValue(
      sandbox({
        hostOwnerId: "node-owner",
        SandboxHost: { userId: "node-owner", connectionEpoch: 7, deletionRequestedAt: null },
        CurrentPlacement: {
          userId: "owner-1",
          hostOwnerId: "node-owner",
          originHostId: "host-1",
          generation: 3,
        },
      }) as never,
    );
    expect(await check()).toMatchObject({ ok: true, binding: { hostOwnerId: "node-owner" } });
  });

  it("a live connection's re-read ends on a new generation, host, host owner or host connection", async () => {
    const expected = { hostId: "host-1", hostOwnerId: "owner-1", generation: 3, epoch: 7 };
    db.sandbox.findFirst.mockResolvedValue(sandbox() as never);
    expect(await check(expected)).toMatchObject({ ok: true });
    db.sandbox.findFirst.mockResolvedValue(sandbox({ generation: 4 }) as never);
    expect(await check(expected)).toEqual({ ok: false, intent: "superseded" });
    db.sandbox.findFirst.mockResolvedValue(sandbox({ sandboxHostId: "host-2" }) as never);
    expect(await check(expected)).toEqual({ ok: false, intent: "superseded" });
    db.sandbox.findFirst.mockResolvedValue(
      sandbox({
        hostOwnerId: "other",
        SandboxHost: { userId: "other", connectionEpoch: 7, deletionRequestedAt: null },
        CurrentPlacement: {
          userId: "owner-1",
          hostOwnerId: "other",
          originHostId: "host-1",
          generation: 3,
        },
      }) as never,
    );
    expect(await check(expected)).toEqual({ ok: false, intent: "superseded" });
    db.sandbox.findFirst.mockResolvedValue(
      sandbox({
        SandboxHost: { userId: "owner-1", connectionEpoch: 8, deletionRequestedAt: null },
      }) as never,
    );
    expect(await check(expected)).toEqual({ ok: false, intent: "host_disconnected" });
  });
});
