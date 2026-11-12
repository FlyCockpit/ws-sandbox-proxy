vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { createHash } from "node:crypto";

import { canonicalEgressPolicyJson } from "@wssp/sandbox-contracts";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Principal } from "../contracts";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const { default: db } = await import("@wssp/db");
const { getSandboxView } = await import("./sandbox-views");

const owner: Principal = { kind: "session", ownerId: "user-a" };

function row(overrides: Record<string, unknown>) {
  return {
    id: "sbx-1",
    hostOwnerId: owner.ownerId,
    state: "ERROR",
    lastErrorCode: null,
    metadata: {},
    SandboxHost: null,
    SandboxTemplateRevision: {
      id: "rev-1",
      revision: 1,
      retiredAt: null,
      Template: {
        id: "tpl-1",
        slug: "base",
        label: "Base",
        archivedAt: null,
        imagePlacement: "INHERIT",
      },
    },
    Operations: [],
    // Disk offload facts (disk-view.ts): never offloaded.
    purpose: "WORKLOAD",
    diskOffloadId: null,
    cachedOffloadSeq: null,
    offloadPin: "ANY" as const,
    credentialFilesEver: false,
    DiskOffloads: [],
    User: { ImagePolicy: null },
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("getSandboxView error detail disclosure", () => {
  it("uses catalog text for historical expiry failures without loading raw detail", async () => {
    db.sandbox.findFirst.mockResolvedValueOnce(row({ lastErrorCode: "expiry_failed" }) as never);
    const failed = await getSandboxView(owner, { id: "sbx-1" });
    expect(failed).toMatchObject({
      lastErrorCode: "expiry_failed",
      expiryFailureReason: "Host could not enforce sandbox expiry.",
    });
    expect(failed).not.toHaveProperty("lastErrorDetail");
    expect(db.sandbox.findFirst.mock.calls[0]![0].select).not.toHaveProperty("lastErrorDetail");

    db.sandbox.findFirst.mockResolvedValueOnce(row({ lastErrorCode: "instance_missing" }) as never);
    const missing = await getSandboxView(owner, { id: "sbx-1" });
    expect(missing).toMatchObject({ expiryFailureReason: null });
    expect(missing).not.toHaveProperty("lastErrorDetail");
  });
});

describe("getSandboxView egress projection (C37)", () => {
  it("exposes the normalized recorded policy, never the raw stored JSON", async () => {
    // The golden C34 hash of {"domains":["registry.example.com"],"cidrs":[]}
    // is computed from the canonical JSON, so derive it here the same way.
    const policy = { domains: ["registry.example.com"], cidrs: [] };
    const hash = createHash("sha256")
      .update(canonicalEgressPolicyJson(policy), "utf8")
      .digest("hex");
    db.sandbox.findFirst.mockResolvedValueOnce(
      row({ egressPolicy: policy, egressPolicyHash: hash }) as never,
    );
    const view = await getSandboxView(owner, { id: "sbx-1" });
    // The effective policy with an explicit mode (default-open egress).
    expect(view.egress).toEqual({ mode: "allowlist", ...policy });
    expect(view).not.toHaveProperty("egressPolicy");
    expect(view).not.toHaveProperty("egressPolicyHash");
  });

  it("pre-policy rows read back as deny-all", async () => {
    db.sandbox.findFirst.mockResolvedValueOnce(
      row({ egressPolicy: null, egressPolicyHash: null }) as never,
    );
    const view = await getSandboxView(owner, { id: "sbx-1" });
    expect(view.egress).toEqual({ mode: "allowlist", domains: [], cidrs: [] });
    expect(view.egressRequest).toBeNull();
    expect(view.egressModeReason).toBeNull();
  });

  it("a malformed stored policy fails closed instead of reaching the client", async () => {
    db.sandbox.findFirst.mockResolvedValueOnce(
      row({ egressPolicy: { domains: [42] }, egressPolicyHash: "x" }) as never,
    );
    await expect(getSandboxView(owner, { id: "sbx-1" })).rejects.toMatchObject({
      data: { code: "sandbox.egress_policy_invalid" },
    });
  });
});

it("projects immutable root size and opaque retained storage without host budgets", async () => {
  db.sandbox.findFirst.mockResolvedValueOnce(
    row({ diskGiB: 48, storagePoolId: "storage-1", storagePoolName: "default" }) as never,
  );
  const view = await getSandboxView(owner, { id: "sbx-1" });
  expect(view).toMatchObject({
    diskGiB: 48,
    storagePoolId: "storage-1",
    storagePoolName: "default",
  });
  const select = db.sandbox.findFirst.mock.calls[0]![0].select;
  expect(select).toMatchObject({ diskGiB: true, storagePoolId: true, storagePoolName: true });
  expect(select?.SandboxHost).not.toHaveProperty("select.daemonMemoryBudgetMiB");
  expect(select).not.toHaveProperty("StoragePool");
});

it("redacts foreign storage and host connection metadata before dashboard serialization", async () => {
  db.sandbox.findFirst.mockResolvedValueOnce(
    row({
      hostOwnerId: "foreign-owner",
      sandboxHostId: "foreign-host",
      storagePoolId: "private-storage-id",
      storagePoolName: "private-storage-name",
      SandboxHost: { id: "foreign-host", lastHeartbeatAt: new Date(), label: "private-host-label" },
    }) as never,
  );
  const view = await getSandboxView(owner, { id: "sbx-1" });
  expect(view).toMatchObject({
    host: null,
    sandboxHostId: null,
    storagePoolId: null,
    storagePoolName: null,
  });
  expect(JSON.stringify(view)).not.toMatch(
    /private-storage|private-host-label|lastHeartbeatAt|foreign-owner/,
  );
});

describe("getSandboxView placement pool label", () => {
  it("is null for a direct placement and never asks for a pool", async () => {
    db.sandbox.findFirst.mockResolvedValueOnce(row({ originPoolId: null }) as never);
    const view = await getSandboxView(owner, { id: "sbx-1" });
    expect(view.placementPoolLabel).toBeNull();
    expect(db.sandboxPool.findFirst).not.toHaveBeenCalled();
  });

  it("names the pool only while the viewer owns it or still holds a share", async () => {
    db.sandbox.findFirst.mockResolvedValueOnce(row({ originPoolId: "pool-1" }) as never);
    db.sandboxPool.findFirst.mockResolvedValueOnce({ label: "Team pool" } as never);
    expect((await getSandboxView(owner, { id: "sbx-1" })).placementPoolLabel).toBe("Team pool");
    expect(db.sandboxPool.findFirst.mock.calls[0]![0]).toEqual({
      where: {
        id: "pool-1",
        deletedAt: null,
        OR: [{ userId: owner.ownerId }, { Shares: { some: { granteeUserId: owner.ownerId } } }],
      },
      select: { label: true },
    });

    // A revoked share (or a deleted pool) matches nothing: the label is withheld.
    db.sandbox.findFirst.mockResolvedValueOnce(row({ originPoolId: "pool-1" }) as never);
    db.sandboxPool.findFirst.mockResolvedValueOnce(null as never);
    expect((await getSandboxView(owner, { id: "sbx-1" })).placementPoolLabel).toBeNull();
  });
});
