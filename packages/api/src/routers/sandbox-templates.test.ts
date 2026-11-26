vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { createRouterClient } from "@orpc/server";
import type { Session } from "@wssp/auth";
import { beforeEach, expect, it, vi } from "vitest";
import type { Context } from "../context";
import {
  bindHostImageVerifier,
  HostImageMissing,
  HostImageRejected,
} from "../sandbox/host-image-verifier";
import { MALICIOUS_INCUS_IMAGE_REFS } from "../sandbox/incus-image";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "http://localhost:3000",
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const { default: db } = await import("@wssp/db");
const { sandboxTemplatesRouter } = await import("./sandbox-templates");

const now = new Date("2026-09-17T00:00:00Z");
const FP = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

function client(userId = "test-user-id") {
  const context: Context = {
    session: {
      user: {
        id: userId,
        email: "test@example.com",
        name: "Test User",
        emailVerified: true,
        role: "user",
        twoFactorEnabled: false,
        image: null,
        banned: false,
        banReason: null,
        banExpires: null,
        createdAt: now,
        updatedAt: now,
      },
      session: {
        id: "auth-session",
        userId,
        token: "token",
        expiresAt: new Date("2027-01-01"),
        ipAddress: null,
        userAgent: null,
        createdAt: now,
        updatedAt: now,
      },
    } as Session,
  };
  return createRouterClient(sandboxTemplatesRouter, { context });
}

const input = { hostId: "host-1", slug: "base", label: "Base", imageRef: "local:base" };
beforeEach(() => {
  vi.resetAllMocks();
  db.user.findUnique.mockResolvedValue({
    deletionRequestedAt: null,
    twoFactorEnabled: true,
    role: "user",
    createdAt: now,
  } as never);
  db.session.findUnique.mockResolvedValue({ id: "auth-session" } as never);
  db.appSetting.findMany.mockResolvedValue([]);
  db.$transaction.mockImplementation(async (work: (tx: typeof db) => Promise<unknown>) => work(db));
  db.$queryRaw.mockResolvedValue([{ id: "host-1", now }]);
  db.sandboxHost.findFirst.mockResolvedValue({
    id: "host-1",
    userId: "test-user-id",
    connectionEpoch: 1,
    status: "CONNECTED",
  } as never);
  db.sandboxTemplateRevision.create.mockResolvedValue({
    id: "rev-1",
    incusFingerprint: FP,
    architecture: "x86_64",
  } as never);
  bindHostImageVerifier(async () => ({ incusFingerprint: FP, architecture: "x86_64" }));
});
it("requires a browser session", async () => {
  await expect(
    createRouterClient(sandboxTemplatesRouter, { context: { session: null } }).listTemplates({
      limit: 20,
    }),
  ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
});
it("lists each template's launchable live versions, owner-scoped", async () => {
  db.sandboxTemplate.findMany.mockResolvedValue([
    { id: "tpl-a", slug: "a", label: "A", archivedAt: null, createdAt: now },
    { id: "tpl-b", slug: "b", label: "B", archivedAt: null, createdAt: now },
  ] as never);
  db.sandboxTemplateRevision.groupBy.mockResolvedValue([
    { templateId: "tpl-a", _count: { _all: 2 }, _max: { revision: 3 } },
  ] as never);
  const page = await client().listTemplates({ limit: 20 });
  expect(page.items.map((item) => [item.id, item.versions])).toEqual([
    ["tpl-a", { count: 2, latest: 3 }],
    ["tpl-b", { count: 0, latest: null }],
  ]);
  expect(db.sandboxTemplateRevision.groupBy).toHaveBeenCalledWith(
    expect.objectContaining({
      where: {
        userId: "test-user-id",
        templateId: { in: ["tpl-a", "tpl-b"] },
        retiredAt: null,
        sourceKind: { not: "UPSTREAM" },
        pendingVerifyBuildId: null,
      },
    }),
  );
});
it("registers logical identity, immutable revision, defaults and explicit latest", async () => {
  db.sandboxTemplate.create.mockResolvedValue({
    id: "template-1",
    slug: "base",
    label: "Base",
    archivedAt: null,
  } as never);
  expect(await client().createTemplate(input)).toMatchObject({
    id: "template-1",
    firstRevisionId: "rev-1",
  });
  expect(db.sandboxTemplate.create).toHaveBeenCalledWith(
    expect.objectContaining({ data: { userId: "test-user-id", slug: "base", label: "Base" } }),
  );
  expect(db.sandboxTemplateRevision.create).toHaveBeenCalledWith(
    expect.objectContaining({
      data: expect.objectContaining({
        templateId: "template-1",
        incusFingerprint: FP,
        revision: 1,
      }),
    }),
  );
  expect(db.sandboxRevisionConfig.create).toHaveBeenCalledOnce();
  expect(db.sandboxTemplateTag.upsert).toHaveBeenCalledWith(
    expect.objectContaining({
      create: expect.objectContaining({ tag: "latest", revisionId: "rev-1" }),
    }),
  );
});
it.each(["DISCONNECTED", "STALE"])("refuses %s before asking the host", async (status) => {
  const verify = vi.fn();
  bindHostImageVerifier(verify);
  db.sandboxHost.findFirst.mockResolvedValue({ status } as never);
  await expect(client().createTemplate(input)).rejects.toMatchObject({
    data: { code: "sandbox.host_unavailable" },
  });
  expect(verify).not.toHaveBeenCalled();
});
it("refuses draining before asking the host", async () => {
  const verify = vi.fn();
  bindHostImageVerifier(verify);
  db.sandboxHost.findFirst.mockResolvedValue({ status: "CONNECTED", draining: true } as never);
  await expect(client().createTemplate(input)).rejects.toMatchObject({
    data: { code: "sandbox.host_draining" },
  });
  expect(verify).not.toHaveBeenCalled();
});
it("redacts image verifier errors", async () => {
  bindHostImageVerifier(async () => {
    throw new HostImageRejected("synthetic-secret");
  });
  const error = await client()
    .createTemplate(input)
    .catch((error: unknown) => error);
  expect(error).toMatchObject({
    code: "BAD_REQUEST",
    data: { code: "sandbox.template_image_rejected" },
  });
  expect(String(error)).not.toContain("synthetic-secret");
  expect(db.sandboxTemplate.create).not.toHaveBeenCalled();
});
it("archives logical identity while retaining boot references", async () => {
  db.sandboxTemplate.findFirst.mockResolvedValue({ id: "template-1" } as never);
  await expect(client().retireTemplate({ id: "template-1" })).resolves.toEqual({ ok: true });
  expect(db.sandboxTemplate.update).toHaveBeenCalledWith({
    where: { id: "template-1", userId: "test-user-id" },
    data: { archivedAt: expect.any(Date) },
  });
  expect(db.sandboxTemplateRevision.update).not.toHaveBeenCalled();
  expect(db.sandbox.findFirst).not.toHaveBeenCalled();
});
it("hides foreign logical identity", async () => {
  db.sandboxTemplate.findFirst.mockResolvedValue(null);
  await expect(client().getTemplate({ id: "foreign" })).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
});
it("rejects malicious image references before IO", async () => {
  for (const imageRef of MALICIOUS_INCUS_IMAGE_REFS)
    await expect(client().createTemplate({ ...input, imageRef })).rejects.toMatchObject({
      code: "BAD_REQUEST",
    });
  expect(db.sandboxHost.findFirst).not.toHaveBeenCalled();
});
it.each([
  { guestUid: 0 },
  { guestUid: -1 },
  { guestUid: 65535 },
  { guestUid: 1.5 },
  { guestGid: 0 },
  { guestHome: "relative" },
  { guestHome: "/" },
  { guestHome: "/home/../root" },
  { guestHome: "/home/user\0" },
  { guestShell: "bash" },
])("rejects invalid guest identity before registration: %j", async (identity) => {
  vi.clearAllMocks();
  await expect(
    client().createTemplate({
      hostId: "host-1",
      slug: "base",
      label: "Base",
      imageRef: "local:base",
      ...identity,
    }),
  ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  expect(db.sandboxTemplate.create).not.toHaveBeenCalled();
});

it("rejects a verifier architecture mismatch without registering", async () => {
  vi.clearAllMocks();
  db.sandboxHost.findFirst.mockResolvedValue({
    id: "host-1",
    status: "CONNECTED",
    userId: "test-user-id",
    connectionEpoch: 1,
  });
  bindHostImageVerifier(async () => ({ incusFingerprint: FP, architecture: "aarch64" }));
  await expect(
    client().createTemplate({
      hostId: "host-1",
      slug: "base",
      label: "Base",
      imageRef: "local:base",
      architecture: "x86_64",
    }),
  ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  expect(db.sandboxTemplate.create).not.toHaveBeenCalled();
});

it("records MISSING on exact-image association before returning the typed conflict", async () => {
  db.sandboxTemplateRevision.findFirst.mockResolvedValue({
    id: "rev-1",
    templateId: "template-1",
    incusFingerprint: FP,
    architecture: "x86_64",
    manifestDigest: "digest",
  } as never);
  db.sandboxTemplateAvailability.upsert.mockResolvedValue({ id: "availability-1" } as never);
  bindHostImageVerifier(async () => {
    throw new HostImageMissing("synthetic-secret");
  });
  await expect(
    client().associateAvailability({
      templateId: "template-1",
      revisionId: "rev-1",
      hostId: "host-1",
    }),
  ).rejects.toMatchObject({ code: "CONFLICT", data: { code: "sandbox.template_image_missing" } });
  expect(db.sandboxTemplateAvailability.upsert).toHaveBeenCalledWith(
    expect.objectContaining({
      create: expect.objectContaining({
        status: "MISSING",
        localFingerprint: FP,
        verifiedConnectionEpoch: 1,
      }),
      update: expect.objectContaining({ status: "MISSING", verifiedConnectionEpoch: 1 }),
    }),
  );
});
it("missing image during registration is a conflict rather than a rejection", async () => {
  bindHostImageVerifier(async () => {
    throw new HostImageMissing("synthetic-secret");
  });
  await expect(client().createTemplate(input)).rejects.toMatchObject({
    code: "CONFLICT",
    data: { code: "sandbox.template_image_missing" },
  });
  expect(db.sandboxTemplateRevision.create).not.toHaveBeenCalled();
});

it.each(["createTemplate", "appendRevision"] as const)(
  "B5 %s rejects malformed size before verification or persistence",
  async (method) => {
    const verify = vi.fn();
    bindHostImageVerifier(verify);
    const body =
      method === "createTemplate"
        ? input
        : { hostId: input.hostId, imageRef: input.imageRef, templateId: "template-1" };
    let caught: unknown;
    try {
      await client()[method]({
        ...body,
        cpuCount: "private-size-sentinel",
        envs: { PRIVATE: "private-size-sentinel" },
      } as never);
    } catch (error) {
      caught = error;
    }
    expect(caught).toMatchObject({
      code: "BAD_REQUEST",
      data: { code: "sandbox.vm_size_invalid" },
    });
    expect(JSON.stringify(caught)).not.toContain("private-size-sentinel");
    expect(verify).not.toHaveBeenCalled();
    expect(db.sandboxTemplateRevision.create).not.toHaveBeenCalled();
  },
);
