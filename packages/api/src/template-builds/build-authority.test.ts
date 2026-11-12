/**
 * Build principal action classes: step / cleanup /
 * read in `authorizeAction`, the typed `build.authority_lost` refusal, the
 * guest-access / host-usability checks a step shares with a session, and the
 * dispatch authority of build attribution.
 */
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "build-authority-test-secret",
  },
}));
vi.mock("../sandbox/sharing-access", () => ({
  requireCurrentHostUsability: vi.fn(async () => () => true),
}));

const { default: prisma } = await import("@wssp/db");
const { ORPCError } = await import("@orpc/server");
const access = await import("../lib/sdk-key-access");
const { requireCurrentHostUsability } = await import("../sandbox/sharing-access");
const { loadBuildPrincipal } = await import("./principal");
const { buildActionClass, buildStepAllowed, isBuildAuthorityLost } = await import(
  "./build-authority"
);

const OWNER = "owner-1";
const BUILD = "build-1";
const VM = "vm-1";
const policyUser = {
  banned: false,
  banExpires: null,
  deletionRequestedAt: null,
  twoFactorEnabled: true,
  createdAt: new Date("2020-01-01"),
  role: "user",
};

type Row = { state: string; cancelRequestedAt: Date | null; authorizingKeyId: string | null };
let buildRow: (Row & { id: string; userId: string }) | null;
let ownVm = true;

function keyRow(scopes: string[], revokedAt: Date | null = null) {
  return {
    id: "key-1",
    userId: OWNER,
    resourceMode: "ALL_OWNED",
    poolMode: "ALL_USABLE",
    scopes,
    revokedAt,
    expiresAt: null,
    HostAllowlist: [],
    RevisionAllowlist: [],
    PoolAllowlist: [],
    User: policyUser,
  };
}

async function principal(keyId: string | null = null) {
  buildRow = {
    id: BUILD,
    userId: OWNER,
    state: "RUNNING",
    cancelRequestedAt: null,
    authorizingKeyId: keyId,
  };
  const loaded = await loadBuildPrincipal(prisma, BUILD, OWNER);
  if (!loaded) throw new Error("fixture build missing");
  return loaded;
}

async function refusal(promise: Promise<unknown>) {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error("expected a refusal");
}

beforeEach(() => {
  vi.mocked(requireCurrentHostUsability).mockReset();
  vi.mocked(requireCurrentHostUsability).mockResolvedValue(() => true);
  ownVm = true;
  prisma.user.findUnique.mockResolvedValue(policyUser as never);
  prisma.sdkKey.findUnique.mockResolvedValue(null);
  prisma.sandboxTemplateBuild.findFirst.mockImplementation((async (args: {
    where: { id: string; userId: string };
  }) =>
    buildRow && buildRow.id === args.where.id && buildRow.userId === args.where.userId
      ? buildRow
      : null) as never);
  prisma.sandbox.findFirst.mockImplementation((async (args: {
    where: { buildId?: string; id?: string; OR?: unknown[] };
  }) => {
    // The build's own VMs: `buildId` or (community verify) `verifyBuildId`.
    if (args.where.buildId !== undefined || args.where.OR !== undefined)
      return ownVm ? { id: VM, verifyBuildId: null } : null;
    return { id: VM, sandboxHostId: null, hostOwnerId: null, usagePoolId: null };
  }) as never);
  prisma.sandboxOperation.findFirst.mockResolvedValue({ authorizingKeyId: null } as never);
});

describe("loadBuildPrincipal", () => {
  it("requires the owner: another owner's build id loads nothing", async () => {
    await principal();
    expect(await loadBuildPrincipal(prisma, BUILD, "owner-2")).toBeNull();
    expect(prisma.sandboxTemplateBuild.findFirst).toHaveBeenLastCalledWith(
      expect.objectContaining({ where: { id: BUILD, userId: "owner-2" } }),
    );
    expect(await loadBuildPrincipal(prisma, "", OWNER)).toBeNull();
  });

  it("keeps the real accepting key and its live grant", async () => {
    prisma.sdkKey.findUnique.mockResolvedValue(keyRow(["sandboxes:read"]) as never);
    const build = await principal("key-1");
    expect(build).toMatchObject({ kind: "build", ownerId: OWNER, buildId: BUILD, keyId: "key-1" });
    expect(build.key?.keyId).toBe("key-1");
  });

  it("still loads a keyed build after revocation (cleanup), with no live grant", async () => {
    prisma.sdkKey.findUnique.mockResolvedValue(keyRow(["sandboxes:read"], new Date()) as never);
    const build = await principal("key-1");
    expect(build.keyId).toBe("key-1");
    expect(build.key).toBeNull();
  });
});

describe("build action classes", () => {
  it.each([
    ["sandboxes.create", "step"],
    ["commands.run", "step"],
    ["files.write", "step"],
    ["sandboxes.capture", "step"],
    ["sandboxes.setTimeout", "step"],
    ["sandboxes.stop", "cleanup"],
    ["sandboxes.kill", "cleanup"],
    ["sandboxes.get", "read"],
    ["operations.getCommandOutput", "read"],
    ["operations.cancel", null],
    ["commands.writeStdin", null],
    ["processes.signal", null],
    ["files.read", null],
    ["sandboxes.rename", null],
    ["webhooks.create", null],
  ] as const)("%s is %s", (action, expected) => {
    expect(buildActionClass(action)).toBe(expected);
  });

  it("a receipt replay of a step is a read", () => {
    expect(buildActionClass("commands.run", true)).toBe("read");
  });

  it("no step runs once cancel is requested or the build is CANCELLING/terminal", () => {
    const at = (state: string, cancelRequestedAt: Date | null = null) =>
      buildStepAllowed("commands.run", { state: state as never, cancelRequestedAt });
    expect(at("RUNNING")).toBe(true);
    expect(at("RUNNING", new Date())).toBe(false);
    for (const state of ["CANCELLING", "SUCCEEDED", "FAILED", "CANCELLED", "QUEUED"])
      expect(at(state), state).toBe(false);
    expect(
      buildStepAllowed("sandboxes.create", { state: "PLACING", cancelRequestedAt: null }),
    ).toBe(true);
  });
});

describe("authorizeServiceAction for a build principal", () => {
  it("admits a keyless step on its own VM through the session's guest-access check", async () => {
    const build = await principal();
    const target = { sandboxId: VM };
    await expect(access.authorizeServiceAction(build, "commands.run", target)).resolves.toBe(
      target,
    );
  });

  it.each([
    ["missing build row", () => (buildRow = null)],
    ["CANCELLING", () => (buildRow!.state = "CANCELLING")],
    ["terminal", () => (buildRow!.state = "FAILED")],
    ["cancel requested", () => (buildRow!.cancelRequestedAt = new Date())],
    [
      "owner banned",
      () => prisma.user.findUnique.mockResolvedValue({ ...policyUser, banned: true } as never),
    ],
  ])("refuses a step with build.authority_lost: %s", async (_name, arrange) => {
    const build = await principal();
    arrange();
    const error = await refusal(
      access.authorizeServiceAction(build, "commands.run", { sandboxId: VM }),
    );
    expect(isBuildAuthorityLost(error)).toBe(true);
  });

  it("refuses a step whose host usability is gone (revoked pool share / access grace)", async () => {
    const build = await principal();
    prisma.sandbox.findFirst.mockImplementation((async (args: {
      where: { buildId?: string; OR?: unknown[] };
    }) =>
      args.where.buildId !== undefined || args.where.OR !== undefined
        ? { id: VM, verifyBuildId: null }
        : {
            id: VM,
            sandboxHostId: "foreign-host",
            hostOwnerId: "other-owner",
            usagePoolId: "pool-1",
            accessGraceUntil: new Date(),
          }) as never);
    vi.mocked(requireCurrentHostUsability).mockRejectedValue(
      new ORPCError("FORBIDDEN", { message: "Sandbox access is unavailable." }),
    );
    const error = await refusal(
      access.authorizeServiceAction(build, "commands.run", { sandboxId: VM }),
    );
    expect(isBuildAuthorityLost(error)).toBe(true);
    expect(requireCurrentHostUsability).toHaveBeenCalled();
  });

  it("refuses a keyed step whose key is revoked or lacks templates:build", async () => {
    prisma.sdkKey.findUnique.mockResolvedValue(keyRow(["sandboxes:read"]) as never);
    const build = await principal("key-1");
    let error = await refusal(
      access.authorizeServiceAction(build, "commands.run", { sandboxId: VM }),
    );
    expect(isBuildAuthorityLost(error)).toBe(true);
    prisma.sdkKey.findUnique.mockResolvedValue(keyRow(["sandboxes:read"], new Date()) as never);
    error = await refusal(access.authorizeServiceAction(build, "commands.run", { sandboxId: VM }));
    expect(isBuildAuthorityLost(error)).toBe(true);
    expect(build.key).toBeNull();
  });

  it("admits cleanup and reads after key revocation and in a terminal state", async () => {
    prisma.sdkKey.findUnique.mockResolvedValue(keyRow(["sandboxes:read"]) as never);
    const build = await principal("key-1");
    prisma.sdkKey.findUnique.mockResolvedValue(keyRow([], new Date()) as never);
    buildRow!.state = "CANCELLED";
    buildRow!.cancelRequestedAt = new Date();
    for (const action of ["sandboxes.kill", "sandboxes.stop", "operations.get"] as const)
      await expect(
        access.authorizeServiceAction(build, action, { sandboxId: VM }),
      ).resolves.toBeTruthy();
    await expect(
      access.authorizeServiceAction(build, "commands.run", {
        operationId: "op-1",
        retainedReplay: true,
      }),
    ).resolves.toBeTruthy();
    // Cleanup still needs the build row.
    buildRow = null;
    expect(
      isBuildAuthorityLost(
        await refusal(access.authorizeServiceAction(build, "sandboxes.kill", { sandboxId: VM })),
      ),
    ).toBe(true);
  });

  it("acts only on its own VM and refuses every other action", async () => {
    const build = await principal();
    ownVm = false;
    for (const action of ["sandboxes.kill", "commands.run", "sandboxes.get"] as const) {
      const error = await refusal(access.authorizeServiceAction(build, action, { sandboxId: VM }));
      expect(error).toBeInstanceOf(ORPCError);
      expect((error as InstanceType<typeof ORPCError>).code).toBe("FORBIDDEN");
    }
    ownVm = true;
    for (const action of ["operations.cancel", "webhooks.list", "files.read"] as const) {
      const error = await refusal(access.authorizeServiceAction(build, action, { sandboxId: VM }));
      expect((error as InstanceType<typeof ORPCError>).code).toBe("FORBIDDEN");
      expect(isBuildAuthorityLost(error)).toBe(false);
    }
    // Cleanup and reads need a target; only create may run without one.
    expect(
      (
        (await refusal(access.authorizeServiceAction(build, "sandboxes.kill", {}))) as InstanceType<
          typeof ORPCError
        >
      ).code,
    ).toBe("FORBIDDEN");
  });

  it("is never a browser session", async () => {
    const build = await principal();
    expect(() => access.authorizeSessionManagement(build)).toThrow(/browser session/);
  });

  it("sees what its key sees in resource filters, nothing once the key is invalid", async () => {
    const build = await principal();
    expect(access.serviceResourceFilter(build, "host")).toEqual({ userId: OWNER });
    prisma.sdkKey.findUnique.mockResolvedValue(keyRow(["sandboxes:read"], new Date()) as never);
    const keyed = await principal("key-1");
    expect(access.serviceResourceFilter(keyed, "host")).toEqual({
      userId: OWNER,
      id: { in: [] },
    });
  });
});

describe("checkAcceptedDispatchAuthority for build attribution", () => {
  const context = { sandboxId: VM, sandboxHostId: "host-1", templateRevisionId: "rev-1" };
  const dispatch = (keyId: string | null, cleanup = false) =>
    access.checkAcceptedDispatchAuthority(
      {
        ownerId: OWNER,
        principal: { kind: "build", buildId: BUILD, keyId },
        context: { ...context, originPoolId: null },
        cleanup,
      },
      prisma,
    );

  it("dispatches cleanup key-free after revocation, ban and while CANCELLING", async () => {
    await principal("key-1");
    buildRow!.state = "CANCELLING";
    prisma.user.findUnique.mockResolvedValue({ ...policyUser, banned: true } as never);
    prisma.sdkKey.findUnique.mockResolvedValue(keyRow([], new Date()) as never);
    expect(await dispatch("key-1", true)).toBe("active");
    ownVm = false;
    expect(await dispatch("key-1", true)).toBe("inactive");
    buildRow = null;
    ownVm = true;
    expect(await dispatch("key-1", true)).toBe("inactive");
  });

  it("refuses a step dispatch once the build is no longer active", async () => {
    await principal();
    expect(await dispatch(null)).toBe("active");
    buildRow!.state = "CANCELLING";
    expect(await dispatch(null)).toBe("inactive");
    buildRow!.state = "RUNNING";
    buildRow!.cancelRequestedAt = new Date();
    expect(await dispatch(null)).toBe("inactive");
  });

  it("a keyed step dispatch needs the live key with templates:build", async () => {
    await principal("key-1");
    prisma.sdkKey.findUnique.mockResolvedValue(keyRow(["sandboxes:read"]) as never);
    expect(await dispatch("key-1")).toBe("inactive");
    prisma.sdkKey.findUnique.mockResolvedValue(keyRow(["templates:build"]) as never);
    expect(await dispatch("key-1")).toBe("active");
    prisma.sdkKey.findUnique.mockResolvedValue(keyRow(["templates:build"], new Date()) as never);
    expect(await dispatch("key-1")).toBe("inactive");
    // The recorded key must be the build's accepting key.
    prisma.sdkKey.findUnique.mockResolvedValue(keyRow(["templates:build"]) as never);
    expect(await dispatch(null)).toBe("inactive");
  });
});

describe("community verify role (community-base I4b, T1, review4 U1)", () => {
  async function verifying(finalized: boolean) {
    const build = await principal();
    Object.assign(buildRow!, { state: "CAPTURING", verifyRequired: true, captureAttempt: 0 });
    prisma.sandboxTemplateCapture.findFirst.mockResolvedValue(
      (finalized ? { operationId: "cap-1" } : null) as never,
    );
    prisma.sandbox.findFirst.mockImplementation((async (args: {
      where: { buildId?: string; OR?: unknown[] };
    }) =>
      args.where.OR !== undefined
        ? { id: VM, verifyBuildId: BUILD }
        : { id: VM, sandboxHostId: null, hostOwnerId: null, usagePoolId: null }) as never);
    return build;
  }

  it("the verify table admits only create and the smoke while CAPTURING, finalized, required", async () => {
    const mod = await import("./build-authority");
    const facts = {
      state: "CAPTURING" as const,
      cancelRequestedAt: null,
      verifyRequired: true,
      captureFinalized: true,
    };
    for (const action of ["sandboxes.create", "sandboxes.createIntent", "commands.run"] as const)
      expect(mod.buildStepAllowed(action, facts, "verify")).toBe(true);
    for (const action of ["files.write", "sandboxes.capture", "sandboxes.setTimeout"] as const)
      expect(mod.buildStepAllowed(action, facts, "verify")).toBe(false);
    expect(
      mod.buildStepAllowed("commands.run", { ...facts, captureFinalized: false }, "verify"),
    ).toBe(false);
    expect(
      mod.buildStepAllowed("commands.run", { ...facts, verifyRequired: false }, "verify"),
    ).toBe(false);
    expect(
      mod.buildStepAllowed("commands.run", { ...facts, cancelRequestedAt: new Date() }, "verify"),
    ).toBe(false);
    // The build table is unchanged: commands only while RUNNING, never CAPTURING.
    expect(mod.buildStepAllowed("commands.run", facts, "build")).toBe(false);
    expect(mod.buildStepAllowed("commands.run", { ...facts, state: "RUNNING" }, "build")).toBe(
      true,
    );
    expect(mod.buildStepAllowed("sandboxes.capture", facts, "build")).toBe(true);
    // The managed-policy set: verify steps plus cleanup and reads (U3).
    for (const action of [
      "sandboxes.kill",
      "sandboxes.stop",
      "sandboxes.replayCreate",
      "operations.get",
    ])
      expect(mod.VERIFY_ACTIONS.has(action as never)).toBe(true);
    for (const action of [
      "files.write",
      "files.read",
      "sandboxes.capture",
      "sandboxes.setTimeout",
      "sandboxes.reconnect",
      "processes.signal",
    ])
      expect(mod.VERIFY_ACTIONS.has(action as never)).toBe(false);
    expect(mod.untargetedCreateRole("CAPTURING")).toBe("verify");
    expect(mod.untargetedCreateRole("PLACING")).toBe("build");
  });

  it("(a) a verify VM target derives role verify; (b) an untargeted CAPTURING create is verify", async () => {
    const build = await verifying(true);
    const target = { sandboxId: VM };
    const context = await access.authorizeServiceAction(build, "commands.run", target);
    expect(access.buildRoleOf(context)).toBe("verify");
    // The context is the caller's own object (identity kept, U1).
    expect(context).toBe(target);
    const create = { sandboxHostId: "h", templateRevisionId: "r", originPoolId: null };
    const created = await access.authorizeServiceAction(build, "sandboxes.create", create);
    expect(access.buildRoleOf(created)).toBe("verify");
    expect(created).toBe(create);
  });

  it("refuses the verify smoke before the capture is finalized, and files on the verify VM", async () => {
    let build = await verifying(false);
    expect(
      isBuildAuthorityLost(
        await refusal(access.authorizeServiceAction(build, "commands.run", { sandboxId: VM })),
      ),
    ).toBe(true);
    build = await verifying(true);
    expect(
      isBuildAuthorityLost(
        await refusal(access.authorizeServiceAction(build, "files.write", { sandboxId: VM })),
      ),
    ).toBe(true);
  });

  it("a PLACING build's untargeted create derives role build", async () => {
    const build = await principal();
    buildRow!.state = "PLACING";
    const create = { sandboxHostId: "h", templateRevisionId: "r", originPoolId: null };
    const context = await access.authorizeServiceAction(build, "sandboxes.create", create);
    expect(access.buildRoleOf(context)).toBe("build");
  });
});
