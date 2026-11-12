import { randomUUID } from "node:crypto";
import { createRouterClient } from "@orpc/server";
import type { Session } from "@wssp/auth";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import { seedLaunchHost } from "../testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "sharing-test-credential-secret-long-enough",
    SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64),
  },
  ADMIN_EMAILS: new Set(),
}));
vi.mock("../budgets", () => ({
  consumeSandboxWriteBudget: async () => {},
  consumeCreateConnectBudget: async () => {},
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("../../lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));
vi.mock("@wssp/mailer", () => ({
  renderPoolShare: vi.fn(() => ({ subject: "Invitation", html: "mail" })),
  sendEmail: vi.fn(async () => {}),
}));

import {
  authenticateSdkKeySecret,
  authorizeServiceAction,
  revalidateSdkKey,
  serviceProcedure,
} from "../../lib/sdk-key-access";
import { SERVICE_SCOPES } from "../../lib/service-scopes";
import { sandboxHostsRouter } from "../../routers/sandbox-hosts";
import { sandboxPoolsRouter } from "../../routers/sandbox-pools";
import { lockPoolGraph } from "../pool-locks";
import {
  seedAcceptedOperation,
  seedSandboxInstance,
  seedTemplateRevision,
} from "../testing/resource-fixtures";
import { addPoolMember, deletePool, removePoolMember, updatePool, updatePoolMember } from "./pools";
import { createSdkKey } from "./sdk-keys";
import {
  acceptPoolInvite,
  contributePoolHost,
  getUsablePool,
  grantPoolShare,
  leavePool,
  listPoolContributions,
  listPoolInvites,
  listPoolShares,
  listSharedPools,
  listUsablePoolMembers,
  listUsablePools,
  resendPoolInvite,
  revokePoolInvite,
  revokePoolShare,
  updatePoolShare,
  withdrawPoolHost,
} from "./sharing";

const db = await pgTestDatabase();
afterAll(() => db.close());
const session = (ownerId: string) => ({ kind: "session" as const, ownerId });
async function fixture() {
  const users = [];
  for (let i = 0; i < 3; i++) {
    const id = randomUUID();
    users.push(
      await db.inspect.user.create({
        data: {
          id,
          name: "Member",
          email: `${id}@example.test`,
          emailVerified: true,
          twoFactorEnabled: true,
          createdAt: new Date(0),
        },
      }),
    );
  }
  const [a, b, c] = users as [
    (typeof users)[number],
    (typeof users)[number],
    (typeof users)[number],
  ];
  const pool = await db.inspect.sandboxPool.create({
    data: { userId: a.id, slug: randomUUID(), label: "Shared" },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: b.id, slug: randomUUID(), label: "Owned" },
  });
  return { a, b, c, pool, host };
}
async function invite(
  f: Awaited<ReturnType<typeof fixture>>,
  email = `${randomUUID()}@example.test`,
  signupAllowed = false,
) {
  const result = await grantPoolShare(session(f.a.id), { poolId: f.pool.id, email, signupAllowed });
  expect(result.kind).toBe("invite");
  if (result.kind !== "invite") throw new Error("Expected invitation");
  return result;
}
it("verified direct grants default BOTH; explicit permission lowering, source consent, withdrawal/re-add and ownHostsOnly preserve history", async () => {
  const f = await fixture();
  const grant = await grantPoolShare(session(f.a.id), {
    poolId: f.pool.id,
    email: f.b.email.toUpperCase(),
  });
  expect(grant).toMatchObject({
    kind: "share",
    share: {
      canUse: true,
      canContribute: true,
      maxMemoryMiB: null,
      maxVcpu: null,
      maxDiskGiB: null,
    },
  });
  const member = await contributePoolHost(session(f.b.id), {
    poolId: f.pool.id,
    sandboxHostId: f.host.id,
    memoryCapPercent: 25,
  });
  await expect(
    contributePoolHost(session(f.c.id), { poolId: f.pool.id, sandboxHostId: f.host.id }),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
  await withdrawPoolHost(session(f.b.id), { poolId: f.pool.id, sandboxHostId: f.host.id });
  expect(
    await db.inspect.share.findUnique({
      where: { poolId_granteeUserId: { poolId: f.pool.id, granteeUserId: f.b.id } },
    }),
  ).toMatchObject({ canUse: true });
  expect(
    (await contributePoolHost(session(f.b.id), { poolId: f.pool.id, sandboxHostId: f.host.id })).id,
  ).toBe(member.id);
  await updatePoolShare(session(f.a.id), {
    poolId: f.pool.id,
    granteeUserId: f.b.id,
    canUse: true,
    canContribute: false,
  });
  expect(await db.inspect.sandboxPoolMember.findUnique({ where: { id: member.id } })).toMatchObject(
    { shareId: null, enabled: false, removedAt: expect.any(Date) },
  );
  await updatePoolShare(session(f.a.id), { poolId: f.pool.id, granteeUserId: f.b.id });
  await contributePoolHost(session(f.b.id), { poolId: f.pool.id, sandboxHostId: f.host.id });
  await updatePool(session(f.a.id), {
    id: f.pool.id,
    slug: f.pool.slug,
    label: "Shared",
    ownHostsOnly: true,
    disconnectGraceSeconds: 0,
  });
  expect(await db.inspect.sandboxPoolMember.findUnique({ where: { id: member.id } })).toMatchObject(
    { removedAt: expect.any(Date) },
  );
  await expect(
    contributePoolHost(session(f.b.id), { poolId: f.pool.id, sandboxHostId: f.host.id }),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
});
it("unverified recipient gets only a digest invite; email acceptance needs proof/identity, explicit bearer forwarding works and replay cannot resurrect a revoked grant", async () => {
  const f = await fixture();
  await db.inspect.user.update({ where: { id: f.b.id }, data: { emailVerified: false } });
  const issued = await invite(f, f.b.email);
  const row = await db.inspect.shareInvite.findUniqueOrThrow({ where: { id: issued.invite.id } });
  expect(row.tokenDigest).toMatch(/^[a-f0-9]{64}$/);
  expect(JSON.stringify(row)).not.toContain(issued.token);
  await expect(
    acceptPoolInvite(session(f.b.id), { token: issued.token, mode: "email" }),
  ).rejects.toMatchObject({ code: "CONFLICT" });
  await expect(
    acceptPoolInvite(session(f.c.id), { token: issued.token, mode: "email" }),
  ).rejects.toMatchObject({ code: "CONFLICT" });
  const receipt = await acceptPoolInvite(session(f.c.id), { token: issued.token, mode: "bearer" });
  await revokePoolShare(session(f.a.id), { poolId: f.pool.id, granteeUserId: f.c.id });
  expect(await acceptPoolInvite(session(f.c.id), { token: issued.token, mode: "bearer" })).toEqual(
    receipt,
  );
  expect(await db.inspect.share.count({ where: { id: receipt.shareId } })).toBe(0);
});
it("concurrent bearer acceptors have one winner under G; no silent overwrite of an existing Share", async () => {
  const f = await fixture();
  const issued = await invite(f);
  const pause = db.pauseAt("accept", { after: /sql:SELECT id FROM sandbox_pool WHERE id = ANY/ });
  const first = db.run("accept", () =>
    acceptPoolInvite(session(f.b.id), { token: issued.token, mode: "bearer" }),
  );
  await pause.waitReached();
  const second = db.run("loser", () =>
    acceptPoolInvite(session(f.c.id), { token: issued.token, mode: "bearer" }),
  );
  const refused = expect(second).rejects.toMatchObject({ code: "CONFLICT" });
  try {
    await db.waitUntilBlocked("loser", { by: "accept" });
  } finally {
    pause.release();
  }
  await first;
  await refused;
  const other = await invite(f);
  await expect(
    acceptPoolInvite(session(f.b.id), { token: other.token, mode: "bearer" }),
  ).rejects.toMatchObject({ code: "CONFLICT" });
  expect(await db.inspect.share.count({ where: { poolId: f.pool.id } })).toBe(1);
});
it.each(["rotate", "revoke", "expire", "pool-delete"] as const)(
  "%s defeats stale token activation",
  async (action) => {
    const f = await fixture();
    const issued = await invite(f);
    if (action === "rotate") {
      const next = await resendPoolInvite(session(f.a.id), {
        poolId: f.pool.id,
        inviteId: issued.invite.id,
      });
      expect(next.token).not.toBe(issued.token);
      await expect(
        acceptPoolInvite(session(f.b.id), { token: next.token, mode: "bearer" }),
      ).resolves.toHaveProperty("shareId");
    } else if (action === "revoke")
      await revokePoolInvite(session(f.a.id), { poolId: f.pool.id, inviteId: issued.invite.id });
    else if (action === "expire")
      await db.inspect.shareInvite.update({
        where: { id: issued.invite.id },
        data: { createdAt: new Date(0), expiresAt: new Date(1) },
      });
    else
      await db.inspect.sandboxPool.update({
        where: { id: f.pool.id },
        data: { deletedAt: new Date() },
      });
    await expect(
      acceptPoolInvite(session(f.c.id), { token: issued.token, mode: "bearer" }),
    ).rejects.toMatchObject({ code: action === "pool-delete" ? "NOT_FOUND" : "CONFLICT" });
    if (action === "expire")
      expect(
        await db.inspect.shareInvite.findUnique({ where: { id: issued.invite.id } }),
      ).toMatchObject({ pendingKey: null, expiredAt: expect.any(Date) });
  },
);
it.each(["mint-first", "revoke-first"] as const)(
  "%s: selected key mint and raw use loss serialize through G before H",
  async (order) => {
    const f = await fixture();
    await grantPoolShare(session(f.a.id), { poolId: f.pool.id, email: f.b.email });
    const rev = await seedTemplateRevision(db.inspect, {
      data: {
        userId: f.b.id,
        slug: randomUUID(),
        label: "Exact",
        incusFingerprint: `sha256:${"a".repeat(64)}`,
      },
    });
    const mint = () =>
      createSdkKey(session(f.b.id), {
        name: "selected",
        scopes: SERVICE_SCOPES.filter(
          // An allowlist key can hold neither webhooks:write (all-owned only) nor
          // credentials:use without an allowlisted login.
          (scope) => scope !== "webhooks:write" && scope !== "credentials:use",
        ),
        resourceMode: "ALLOWLIST",
        poolMode: "SELECTED",
        hostIds: [],
        templateRevisionIds: [rev.id],
        poolIds: [f.pool.id],
      });
    const revoke = () =>
      db.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_pool WHERE id = ${f.pool.id} FOR UPDATE`;
        await tx.share.update({
          where: { poolId_granteeUserId: { poolId: f.pool.id, granteeUserId: f.b.id } },
          data: { canUse: false },
        });
      });
    const pause = db.pauseAt("winner", { after: /sql:SELECT id FROM sandbox_pool/ });
    const first = db.run("winner", order === "mint-first" ? mint : revoke);
    await pause.waitReached();
    const next = db.run("follower", order === "mint-first" ? revoke : mint);
    const result =
      order === "revoke-first" ? expect(next).rejects.toMatchObject({ code: "NOT_FOUND" }) : next;
    try {
      await db.waitUntilBlocked("follower", { by: "winner" });
    } finally {
      pause.release();
    }
    await first;
    await result;
    expect(await db.inspect.sdkKeyPoolAllowlist.count({ where: { poolId: f.pool.id } })).toBe(0);
  },
);
it("same creating selected key retains cleanup/read after use loss; other selected keys cannot read or execute; grant reissue never restores selected pools", async () => {
  const f = await fixture();
  await grantPoolShare(session(f.a.id), { poolId: f.pool.id, email: f.b.email });
  const rev = await seedTemplateRevision(db.inspect, {
    data: {
      userId: f.b.id,
      slug: randomUUID(),
      label: "Exact",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const mint = () =>
    createSdkKey(session(f.b.id), {
      name: "selected",
      scopes: SERVICE_SCOPES.filter(
        // An allowlist key can hold neither webhooks:write (all-owned only) nor
        // credentials:use without an allowlisted login.
        (scope) => scope !== "webhooks:write" && scope !== "credentials:use",
      ),
      resourceMode: "ALLOWLIST",
      poolMode: "SELECTED",
      hostIds: [],
      templateRevisionIds: [rev.id],
      poolIds: [f.pool.id],
    });
  const key = await mint(),
    other = await mint();
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: f.b.id,
      hostOwnerId: f.b.id,
      templateId: rev.id,
      sandboxHostId: f.host.id,
      originHostId: f.host.id,
      originPoolId: f.pool.id,
      state: "STOPPED",
    },
  });
  await db.inspect.sandboxOperation.updateMany({
    where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
    data: { authorizingKeyId: key.key.id },
  });
  await leavePool(session(f.b.id), { poolId: f.pool.id });
  const principal = await revalidateSdkKey(key.key.id, f.b.id);
  expect(principal).toBeTruthy();
  const stranger = await revalidateSdkKey(other.key.id, f.b.id);
  expect(stranger).toBeTruthy();
  await expect(
    authorizeServiceAction(principal!, "sandboxes.get", { sandboxId: sandbox.id }),
  ).resolves.toHaveProperty("sandboxId", sandbox.id);
  await expect(
    authorizeServiceAction(principal!, "sandboxes.kill", { sandboxId: sandbox.id }),
  ).resolves.toHaveProperty("sandboxId", sandbox.id);
  await expect(
    authorizeServiceAction(stranger!, "sandboxes.get", { sandboxId: sandbox.id }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  await grantPoolShare(session(f.a.id), { poolId: f.pool.id, email: f.b.email });
  expect((await revalidateSdkKey(key.key.id, f.b.id))?.allowedPoolIds).toEqual(new Set());
});
it.each(["revoked", "impersonated"] as const)(
  "%s session cannot mutate sharing or consent/settings",
  async (mode) => {
    const f = await fixture();
    const authSession = await db.inspect.session.create({
      data: { userId: f.a.id, token: randomUUID(), expiresAt: new Date(Date.now() + 60000) },
    });
    const snapshot = { user: f.a, session: authSession } as Session;
    if (mode === "revoked") await db.inspect.session.delete({ where: { id: authSession.id } });
    else
      await db.inspect.session.update({
        where: { id: authSession.id },
        data: { impersonatedBy: f.c.id },
      });
    const client = createRouterClient(sandboxPoolsRouter, { context: { session: snapshot } });
    const host = await db.inspect.sandboxHost.create({
      data: { userId: f.a.id, slug: randomUUID(), label: "Owned host" },
    });
    const hosts = createRouterClient(sandboxHostsRouter, { context: { session: snapshot } });
    for (const work of [
      () => client.grantShare({ poolId: f.pool.id, email: f.b.email }),
      () =>
        client.update({ id: f.pool.id, slug: f.pool.slug, label: "Changed", ownHostsOnly: true }),
      () => client.delete({ id: f.pool.id }),
      () => client.contributeHost({ poolId: f.pool.id, sandboxHostId: f.host.id }),
      () => hosts.updateHost({ id: host.id, label: "Changed" }),
      () => hosts.deleteHost({ id: host.id }),
    ])
      await expect(work()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    expect(await db.inspect.share.count({ where: { poolId: f.pool.id } })).toBe(0);
  },
);
it.each(["accept-first", "email-change-first"] as const)(
  "%s: current verified email is rechecked under User admission through acceptance",
  async (order) => {
    const f = await fixture();
    await db.inspect.user.update({ where: { id: f.b.id }, data: { emailVerified: false } });
    const issued = await invite(f, f.b.email);
    await db.inspect.user.update({ where: { id: f.b.id }, data: { emailVerified: true } });
    const accept = () => acceptPoolInvite(session(f.b.id), { token: issued.token, mode: "email" });
    const change = () =>
      db.prisma.$transaction(async (tx) => {
        await tx.user.update({
          where: { id: f.b.id },
          data: { email: `${randomUUID()}@example.test`, emailVerified: false },
        });
      });
    const gate = db.pauseAt(
      "first",
      order === "accept-first" ? { before: "share.create" } : { before: "$transaction.commit" },
    );
    const first = db.run("first", order === "accept-first" ? accept : change);
    await gate.waitReached();
    const follower = db.run("second", order === "accept-first" ? change : accept).then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    );
    try {
      await db.waitUntilBlocked("second", { by: "first" });
    } finally {
      gate.release();
    }
    await first;
    const result = await follower;
    if (order === "email-change-first")
      expect(result).toMatchObject({ error: { code: "CONFLICT" } });
    else expect(result).toHaveProperty("value");
    expect(await db.inspect.share.count({ where: { poolId: f.pool.id } })).toBe(
      order === "accept-first" ? 1 : 0,
    );
  },
);
it("SMTP failure preserves digest-only pending invite and copy-once token; resend rotates the same signup allowance-bearing row", async () => {
  const { sendEmail } = await import("@wssp/mailer");
  vi.mocked(sendEmail).mockRejectedValueOnce(new Error("transport unavailable"));
  const f = await fixture();
  const issued = await invite(f, `${randomUUID()}@example.test`, true);
  expect(issued.sent).toBe(false);
  expect(
    await db.inspect.shareInvite.findUnique({ where: { id: issued.invite.id } }),
  ).toMatchObject({ sentAt: null, signupAllowed: true, pendingKey: expect.any(String) });
  const resent = await resendPoolInvite(session(f.a.id), {
    poolId: f.pool.id,
    inviteId: issued.invite.id,
  });
  expect(resent).toMatchObject({
    sent: true,
    invite: { id: issued.invite.id, signupAllowed: true },
  });
  expect(resent.token).not.toBe(issued.token);
  expect(await db.inspect.shareInvite.count({ where: { poolId: f.pool.id } })).toBe(1);
});
it("mails the invitation at /settings/pools/invite with the token only in the fragment", async () => {
  const { renderPoolShare } = await import("@wssp/mailer");
  vi.mocked(renderPoolShare).mockClear();
  const f = await fixture();
  const issued = await invite(f, `${randomUUID()}@example.test`, true);
  expect(issued.sent).toBe(true);
  const sent = vi.mocked(renderPoolShare).mock.calls.at(-1)?.[0];
  const url = new URL(sent?.url ?? "");
  expect(url.pathname).toMatch(/^\/(en-US|es-MX)\/settings\/pools\/invite$/);
  expect(url.search).toBe("");
  expect(url.hash).toBe(`#${issued.token}`);
});
it("an owner-local membership refuses member caps with a clear typed error, never the retryable state-changed conflict", async () => {
  const f = await fixture();
  const host = await db.inspect.sandboxHost.create({
    data: { userId: f.a.id, slug: randomUUID(), label: "Pool owner's host" },
  });
  const input = { poolId: f.pool.id, sandboxHostId: host.id };
  for (const caps of [{ memoryCapPercent: 50 }, { vcpuCapPercent: 50 }])
    await expect(contributePoolHost(session(f.a.id), { ...input, ...caps })).rejects.toMatchObject({
      code: "BAD_REQUEST",
      data: { code: "pool.member_caps_owner_local" },
    });
  expect(await db.inspect.sandboxPoolMember.count({ where: input })).toBe(0);
  // Without caps the owner's own host joins as usual, and caps stay refused.
  const member = await contributePoolHost(session(f.a.id), input);
  expect(member).toMatchObject({ memoryCapPercent: null, vcpuCapPercent: null });
  await expect(
    contributePoolHost(session(f.a.id), { ...input, memoryCapPercent: 50 }),
  ).rejects.toMatchObject({ data: { code: "pool.member_caps_owner_local" } });
});
it("selected-key IO needs the current foreign attribution selected (§5a W1); path loss denies IO but keeps metadata", async () => {
  const f = await fixture();
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: f.a.id, slug: randomUUID(), label: "Pool owner's host" },
  });
  await grantPoolShare(session(f.a.id), { poolId: f.pool.id, email: f.b.email });
  const member = await contributePoolHost(session(f.a.id), {
    poolId: f.pool.id,
    sandboxHostId: host.id,
  });
  await updatePool(session(f.a.id), {
    id: f.pool.id,
    slug: f.pool.slug,
    label: f.pool.label,
    ownHostsOnly: true,
  });
  const rev = await seedTemplateRevision(db.inspect, {
    data: {
      userId: f.b.id,
      slug: randomUUID(),
      label: "Private revision",
      incusFingerprint: `sha256:${"b".repeat(64)}`,
    },
  });
  const key = await createSdkKey(session(f.b.id), {
    name: "P-only",
    scopes: SERVICE_SCOPES.filter(
      // An allowlist key can hold neither webhooks:write (all-owned only) nor
      // credentials:use without an allowlisted login.
      (scope) => scope !== "webhooks:write" && scope !== "credentials:use",
    ),
    resourceMode: "ALLOWLIST",
    poolMode: "SELECTED",
    hostIds: [],
    templateRevisionIds: [rev.id],
    poolIds: [f.pool.id],
  });
  // Authorization fixture only: S3 owns the actual foreign admission/attribution transaction.
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: f.b.id,
      hostOwnerId: f.a.id,
      sandboxHostId: host.id,
      originHostId: host.id,
      originPoolId: f.pool.id,
      usagePoolId: f.pool.id,
      usageMemberId: member.id,
      templateId: rev.id,
      state: "READY",
    },
  });
  await db.inspect.sandboxOperation.updateMany({
    where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
    data: { authorizingKeyId: key.key.id },
  });
  const principal = (await revalidateSdkKey(key.key.id, f.b.id))!;
  await expect(
    authorizeServiceAction(principal, "commands.run", { sandboxId: sandbox.id }),
  ).resolves.toHaveProperty("sandboxId");
  await updatePoolShare(session(f.a.id), {
    poolId: f.pool.id,
    granteeUserId: f.b.id,
    canUse: false,
    canContribute: true,
  });
  await expect(
    authorizeServiceAction(principal, "commands.run", { sandboxId: sandbox.id }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  await expect(
    authorizeServiceAction(principal, "sandboxes.get", { sandboxId: sandbox.id }),
  ).resolves.toHaveProperty("sandboxId");
  const q = await db.inspect.sandboxPool.create({
    data: { userId: f.a.id, slug: randomUUID(), label: "Q" },
  });
  await grantPoolShare(session(f.a.id), { poolId: q.id, email: f.b.email });
  const qMember = await contributePoolHost(session(f.a.id), {
    poolId: q.id,
    sandboxHostId: host.id,
  });
  await db.inspect.sandbox.update({
    where: { id: sandbox.id },
    data: { usagePoolId: q.id, usageMemberId: qMember.id },
  });
  // A SELECTED key's use needs the CURRENT usage pool
  // selected; attribution moved to Q, which this P-only key never selected.
  await expect(
    authorizeServiceAction(principal, "commands.run", { sandboxId: sandbox.id }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  await expect(
    authorizeServiceAction(principal, "sandboxes.get", { sandboxId: sandbox.id }),
  ).resolves.toHaveProperty("sandboxId");
  expect(principal.allowedPoolIds).toEqual(new Set());
  await expect(
    authorizeServiceAction(principal, "sandboxes.create", {
      originPoolId: q.id,
      sandboxHostId: host.id,
      templateRevisionId: rev.id,
    }),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
});
it.each(
  (["resend", "revoke", "expire", "delete-pool"] as const).flatMap((action) =>
    (["accept-first", "mutation-first"] as const).map((order) => [action, order] as const),
  ),
)(
  "%s / %s serializes invite activation through G with one pending-state winner",
  async (action, order) => {
    const f = await fixture();
    const issued = await invite(f);
    const accept = () => acceptPoolInvite(session(f.b.id), { token: issued.token, mode: "bearer" });
    const mutate = async (): Promise<unknown> => {
      if (action === "resend")
        return resendPoolInvite(session(f.a.id), { poolId: f.pool.id, inviteId: issued.invite.id });
      if (action === "revoke")
        return revokePoolInvite(session(f.a.id), { poolId: f.pool.id, inviteId: issued.invite.id });
      if (action === "delete-pool") return deletePool(session(f.a.id), { id: f.pool.id });
      return db.prisma.$transaction(async (tx) => {
        await lockPoolGraph(tx, [f.pool.id]);
        // Inject the expiry boundary without a seven-day wall-clock wait.
        return tx.shareInvite.updateMany({
          where: { id: issued.invite.id, pendingKey: { not: null } },
          data: {
            createdAt: new Date(0),
            expiresAt: new Date(1),
            expiredAt: new Date(),
            pendingKey: null,
          },
        });
      });
    };
    const gate = db.pauseAt("first", { after: /sql:SELECT id FROM sandbox_pool WHERE id = ANY/ });
    const first = db
      .run("first", async () => (order === "accept-first" ? accept() : mutate()))
      .then(
        (value) => ({ value }),
        (error: unknown) => ({ error }),
      );
    await gate.waitReached();
    const next = db
      .run("next", async () => (order === "accept-first" ? mutate() : accept()))
      .then(
        (value) => ({ value }),
        (error: unknown) => ({ error }),
      );
    try {
      expect((await db.waitUntilBlocked("next", { by: "first" })).query).toContain("sandbox_pool");
    } finally {
      gate.release();
    }
    expect(await first).toHaveProperty("value");
    const result = await next;
    if (order === "mutation-first")
      expect(result).toMatchObject({
        error: { code: action === "delete-pool" ? "NOT_FOUND" : "CONFLICT" },
      });
    else if (action === "resend" || action === "revoke")
      expect(result).toMatchObject({ error: { code: "CONFLICT" } });
    else expect(result).toHaveProperty("value");
    const row = await db.inspect.shareInvite.findUniqueOrThrow({ where: { id: issued.invite.id } });
    expect(row.acceptedByUserId).toBe(order === "accept-first" ? f.b.id : null);
    expect(await db.inspect.share.count({ where: { poolId: f.pool.id } })).toBe(
      order === "accept-first" ? 1 : 0,
    );
  },
);

async function readFixture() {
  const f = await fixture();
  await grantPoolShare(session(f.a.id), {
    poolId: f.pool.id,
    email: f.b.email,
    canUse: false,
    canContribute: true,
    maxMemoryMiB: null,
    maxVcpu: null,
    maxDiskGiB: null,
    signupAllowed: false,
  });
  await grantPoolShare(session(f.a.id), {
    poolId: f.pool.id,
    email: f.c.email,
    canUse: true,
    canContribute: false,
    maxMemoryMiB: 4096,
    maxVcpu: 4,
    maxDiskGiB: null,
    signupAllowed: false,
  });
  const member = await contributePoolHost(session(f.b.id), {
    poolId: f.pool.id,
    sandboxHostId: f.host.id,
    enabled: true,
    memoryCapPercent: 50,
    vcpuCapPercent: 50,
  });
  return { ...f, member };
}
it("qualified shared reads disclose only own permissions/usage and opaque use-members; contributions and owner mutations remain separate", async () => {
  const f = await readFixture();
  const page = await listSharedPools(session(f.c.id), { limit: 10 });
  expect(page.items).toHaveLength(1);
  expect(page.items[0]).toMatchObject({
    id: f.pool.id,
    owner: { id: f.a.id, name: f.a.name },
    share: {
      canUse: true,
      canContribute: false,
      maxMemoryMiB: 4096,
      maxVcpu: 4,
      maxDiskGiB: null,
      usage: { memoryMiB: "0", vcpu: "0", diskGiB: "0" },
    },
  });
  const members = await listUsablePoolMembers(session(f.c.id), { poolId: f.pool.id, limit: 10 });
  expect(members.items).toEqual([{ id: f.member.id, poolId: f.pool.id }]);
  expect((await getUsablePool(session(f.c.id), { id: f.pool.id })).memberCount).toBe(1);
  // Disable blocks new placement, not retained use or membership visibility.
  await db.inspect.sandboxPoolMember.update({
    where: { id: f.member.id },
    data: { enabled: false },
  });
  expect(
    (await listUsablePoolMembers(session(f.c.id), { poolId: f.pool.id, limit: 10 })).items,
  ).toEqual([{ id: f.member.id, poolId: f.pool.id }]);
  expect((await getUsablePool(session(f.c.id), { id: f.pool.id })).memberCount).toBe(1);
  const json = JSON.stringify({ page, members });
  for (const hidden of [
    f.b.email,
    f.host.id,
    f.host.label,
    "lastHeartbeatAt",
    "status",
    "tokenDigest",
    "pendingKey",
  ])
    expect(json).not.toContain(hidden);
  const contributionOnly = await listSharedPools(session(f.b.id), { limit: 10 });
  expect(contributionOnly.items[0]?.share).toMatchObject({ canUse: false, canContribute: true });
  expect((await listUsablePools(session(f.b.id), { limit: 10 })).items).toEqual([]);
  await expect(getUsablePool(session(f.b.id), { id: f.pool.id })).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  await expect(
    listUsablePoolMembers(session(f.b.id), { poolId: f.pool.id, limit: 10 }),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
  const own = await listPoolContributions(session(f.b.id), { poolId: f.pool.id, limit: 10 });
  expect(own.items).toHaveLength(1);
  expect(own.items[0]).toMatchObject({
    sandboxHostId: f.host.id,
    memoryCapPercent: 50,
    vcpuCapPercent: 50,
  });
  expect(own.items[0]).not.toHaveProperty("Host");
  expect(
    (await listPoolContributions(session(f.c.id), { poolId: f.pool.id, limit: 10 })).items,
  ).toEqual([]);
  const ownedMembers = await listUsablePoolMembers(session(f.a.id), {
    poolId: f.pool.id,
    limit: 10,
  });
  expect(ownedMembers.items[0]).toMatchObject({
    sandboxHostId: f.host.id,
    hostOwnerId: f.b.id,
    Host: { label: f.host.label },
  });
  for (const read of [listPoolShares, listPoolInvites])
    await expect(read(session(f.c.id), { poolId: f.pool.id, limit: 10 })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
  await expect(
    updatePool(session(f.c.id), { id: f.pool.id, slug: "not-owned", label: "not-owned" }),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
  await expect(deletePool(session(f.c.id), { id: f.pool.id })).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
});
it("shared discovery filters use/owner policy before tied keyset paging, and hides unhinted bans", async () => {
  const f = await readFixture();
  const when = new Date("2026-01-01");
  await db.inspect.sandboxPool.update({ where: { id: f.pool.id }, data: { createdAt: when } });
  for (let i = 0; i < 3; i++) {
    const pool = await db.inspect.sandboxPool.create({
      data: { userId: f.a.id, slug: `shared-${i}`, label: "Shared", createdAt: when },
    });
    await grantPoolShare(session(f.a.id), {
      poolId: pool.id,
      email: f.c.email,
      canUse: true,
      canContribute: false,
      maxMemoryMiB: null,
      maxVcpu: null,
      maxDiskGiB: null,
      signupAllowed: false,
    });
  }
  // A hidden row with a newer sort key must neither fill a page nor leak a count.
  await db.inspect.sandboxPool.create({
    data: { userId: f.a.id, slug: "hidden", label: "Hidden" },
  });
  const { listPoolsInput } = await import("../pool-input");
  const ids: string[] = [];
  let cursor: string | null = null;
  do {
    const page = await listSharedPools(
      session(f.c.id),
      listPoolsInput.parse({ limit: 1, ...(cursor ? { cursor } : {}) }),
    );
    expect(page.items).toHaveLength(1);
    ids.push(page.items[0]!.id);
    cursor = page.nextCursor;
  } while (cursor);
  expect(new Set(ids).size).toBe(4);
  expect(ids).toEqual([...ids].sort().reverse());
  await db.inspect.user.update({ where: { id: f.a.id }, data: { banned: true } });
  expect((await listSharedPools(session(f.c.id), { limit: 10 })).items).toEqual([]);
});
it("native shared reads obey selected pools, preserve the owned-host intersection and strictly decode opaque members", async () => {
  const f = await readFixture();
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: f.c.id,
      slug: "private",
      label: "Private",
      incusFingerprint: `sha256:${"b".repeat(64)}`,
    },
  });
  await updatePoolShare(session(f.a.id), {
    poolId: f.pool.id,
    granteeUserId: f.c.id,
    canUse: true,
    canContribute: true,
    maxMemoryMiB: null,
    maxVcpu: null,
    maxDiskGiB: null,
  });
  const ownHost = await db.inspect.sandboxHost.create({
    data: { userId: f.c.id, slug: "owned", label: "Owned" },
  });
  await contributePoolHost(session(f.c.id), {
    poolId: f.pool.id,
    sandboxHostId: ownHost.id,
    enabled: true,
    memoryCapPercent: null,
    vcpuCapPercent: null,
  });
  const key = await createSdkKey(session(f.c.id), {
    name: "selected",
    resourceMode: "ALLOWLIST",
    poolMode: "SELECTED",
    poolIds: [f.pool.id],
    hostIds: [],
    templateRevisionIds: [revision.id],
    scopes: ["pools:read", "hosts:read"],
  });
  const { authenticateSdkKeySecret } = await import("../../lib/sdk-key-access");
  const principal = await authenticateSdkKeySecret(key.secret);
  if (!principal) throw new Error("Fixture key inactive");
  const { sdkListPools, sdkGetPool, sdkListPoolMembers } = await import("../sdk-reads");
  const { poolPageSchema, poolDetailSchema, poolMemberPageSchema } = await import(
    "@wssp/sandbox-contracts"
  );
  expect(
    poolPageSchema.parse(await sdkListPools(principal, { limit: 10 })).items[0]?.owner?.id,
  ).toBe(f.a.id);
  expect(poolDetailSchema.parse(await sdkGetPool(principal, f.pool.id)).memberCount).toBe(1);
  expect(
    poolMemberPageSchema.parse(await sdkListPoolMembers(principal, f.pool.id, { limit: 10 })).items,
  ).toEqual([{ id: f.member.id, poolId: f.pool.id }]);
  const all = await createSdkKey(session(f.c.id), {
    name: "all",
    resourceMode: "ALL_OWNED",
    hostIds: [],
    templateRevisionIds: [],
    scopes: ["pools:read", "hosts:read"],
  });
  const allPrincipal = await authenticateSdkKeySecret(all.secret);
  if (!allPrincipal) throw new Error("Fixture key inactive");
  expect((await sdkGetPool(allPrincipal, f.pool.id)).memberCount).toBe(2);
  expect((await sdkListPoolMembers(allPrincipal, f.pool.id, { limit: 10 })).items).toHaveLength(2);
  await revokePoolShare(session(f.a.id), { poolId: f.pool.id, granteeUserId: f.c.id });
  expect((await sdkListPools(principal, { limit: 10 })).items).toEqual([]);
  await expect(sdkGetPool(principal, f.pool.id)).rejects.toMatchObject({ code: "NOT_FOUND" });
});
it.each(["share", "host"] as const)(
  "a %s revoke committed after member projection prevents a stale shared response (real PG barrier)",
  async (kind) => {
    const f = await readFixture();
    const pause = db.pauseAt("read", { after: "sandboxPoolMember.findMany" });
    const read = db.run("read", () =>
      listUsablePoolMembers(session(f.c.id), { poolId: f.pool.id, limit: 10 }),
    );
    await pause.waitReached();
    try {
      if (kind === "share") {
        // Raw write deliberately emits no process-local authority hint.
        await db.inspect.share.delete({
          where: { poolId_granteeUserId: { poolId: f.pool.id, granteeUserId: f.c.id } },
        });
      } else {
        await withdrawPoolHost(session(f.b.id), { poolId: f.pool.id, sandboxHostId: f.host.id });
      }
    } finally {
      pause.release();
    }
    await expect(read).rejects.toMatchObject({ code: "NOT_FOUND" });
  },
);
it("an unhinted source-owner ban after pool discovery prevents shared disclosure (real PG barrier)", async () => {
  const f = await readFixture();
  const pause = db.pauseAt("read", { after: "sandboxPool.findMany" });
  const read = db.run("read", () => listSharedPools(session(f.c.id), { limit: 10 }));
  await pause.waitReached();
  try {
    await db.inspect.user.update({ where: { id: f.a.id }, data: { banned: true } });
  } finally {
    pause.release();
  }
  await expect(read).rejects.toMatchObject({ code: "NOT_FOUND" });
});

it("U1 shared-pool revision picker accepts a use grantee with no owned host and refuses contribute-only/withdrawn paths", async () => {
  const { listRevisionChoices } = await import("./templates");
  const f = await readFixture();
  const rev = await seedTemplateRevision(db.inspect, {
    data: {
      userId: f.c.id,
      sandboxHostId: f.host.id,
      slug: randomUUID(),
      label: "Creator revision",
      incusFingerprint: `sha256:${"c".repeat(64)}`,
    },
  });
  const input = { poolId: f.pool.id, hostIds: [], limit: 1, includePending: true };
  const page = await listRevisionChoices(session(f.c.id), input);
  expect(page.items.map((r) => r.id)).toEqual([rev.id]);
  expect(JSON.stringify(page)).not.toContain("envs");
  await expect(listRevisionChoices(session(f.b.id), input)).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  await withdrawPoolHost(session(f.b.id), { poolId: f.pool.id, sandboxHostId: f.host.id });
  expect((await listRevisionChoices(session(f.c.id), input)).items).toEqual([]);
});
it("U1 revision choices recheck contribution after the read before releasing the response (real PG barrier)", async () => {
  const { listRevisionChoices } = await import("./templates");
  const f = await readFixture();
  await seedTemplateRevision(db.inspect, {
    data: {
      userId: f.c.id,
      sandboxHostId: f.host.id,
      slug: randomUUID(),
      label: "Creator revision",
      incusFingerprint: `sha256:${"d".repeat(64)}`,
    },
  });
  const pause = db.pauseAt("picker", { after: "sandboxTemplateRevision.findMany" });
  const result = db.run("picker", () =>
    listRevisionChoices(session(f.c.id), {
      poolId: f.pool.id,
      hostIds: [],
      limit: 10,
      includePending: true,
    }),
  );
  await pause.waitReached();
  try {
    await withdrawPoolHost(session(f.b.id), { poolId: f.pool.id, sandboxHostId: f.host.id });
  } finally {
    pause.release();
  }
  await expect(result).rejects.toMatchObject({ code: "NOT_FOUND" });
});
it("U1 host detail guests are bounded opaque allocation metadata; creator/pool owner/other viewers cannot use custody reads", async () => {
  const { listHostGuests } = await import("./hosts");
  const f = await readFixture();
  const rev = await seedTemplateRevision(db.inspect, {
    data: {
      userId: f.c.id,
      slug: randomUUID(),
      label: "private-creator-label",
      incusFingerprint: `sha256:${"e".repeat(64)}`,
    },
  });
  for (let i = 0; i < 2; i++)
    await seedSandboxInstance(db.inspect, {
      data: {
        userId: f.c.id,
        hostOwnerId: f.b.id,
        sandboxHostId: f.host.id,
        originHostId: f.host.id,
        templateId: rev.id,
        state: "STOPPED",
        metadata: { labels: { private: "private-guest-label" } },
      },
    });
  const first = await listHostGuests(session(f.b.id), { id: f.host.id, limit: 1 });
  expect(first.items).toHaveLength(1);
  expect(first.nextCursor).toBeTruthy();
  expect(Object.keys(first.items[0]!).sort()).toEqual(
    [
      "id",
      "state",
      // B8: the host page labels managed guests (build VMs, login sandboxes).
      "purpose",
      "cpuCount",
      "memoryMiB",
      "diskGiB",
      "leaseExpiresAt",
      "accessGraceUntil",
      "createdAt",
    ].sort(),
  );
  const raw = JSON.stringify(first);
  expect(raw).not.toContain(f.c.id);
  expect(raw).not.toContain("private-");
  expect(raw).not.toContain("storage");
  const next = await listHostGuests(session(f.b.id), {
    id: f.host.id,
    limit: 1,
    cursor: first.nextCursor!,
  });
  expect(next.items).toHaveLength(1);
  expect(next.items[0]!.id).not.toBe(first.items[0]!.id);
  expect(next.nextCursor).toBeNull();
  for (const user of [f.a, f.c])
    await expect(
      listHostGuests(session(user.id), { id: f.host.id, limit: 1 }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
  const roster = await listPoolShares(session(f.a.id), { poolId: f.pool.id, limit: 1 });
  expect(roster.items[0]).toHaveProperty("usage.memoryMiB", "0");
  expect(roster.items[0]).toHaveProperty("Grantee.email");
});

it.each(["banned", "deleting"] as const)(
  "r1 removals succeed against %s counterparties while admission and acting-owner checks remain enforced",
  async (policy) => {
    const block = (id: string) =>
      db.inspect.user.update({
        where: { id },
        data:
          policy === "banned"
            ? { banned: true, banExpires: null }
            : { deletionRequestedAt: new Date() },
      });
    for (const action of [
      "revoke",
      "clear",
      "reduce",
      "leave",
      "withdraw",
      "remove",
      "disable",
      "contributor-cap",
      "contributor-disable",
    ] as const) {
      const f = await fixture();
      await grantPoolShare(session(f.a.id), {
        poolId: f.pool.id,
        email: f.b.email,
        maxMemoryMiB: 512,
        maxVcpu: 2,
        maxDiskGiB: 100,
      });
      await contributePoolHost(session(f.b.id), {
        poolId: f.pool.id,
        sandboxHostId: f.host.id,
        memoryCapPercent: 50,
        vcpuCapPercent: 50,
      });
      const actor =
        action === "leave" || action === "withdraw" || action.startsWith("contributor-")
          ? f.b
          : f.a;
      const counterparty = actor.id === f.a.id ? f.b : f.a;
      await block(counterparty.id);
      const target = { poolId: f.pool.id, sandboxHostId: f.host.id };
      // Adding authority still refuses the blocked counterparty.
      await expect(
        contributePoolHost(session(f.b.id), {
          ...target,
          memoryCapPercent: null,
          vcpuCapPercent: null,
        }),
      ).rejects.toBeDefined();
      if (actor.id === f.a.id)
        await expect(
          updatePoolShare(session(actor.id), {
            poolId: f.pool.id,
            granteeUserId: f.b.id,
            canUse: true,
            canContribute: false,
            maxMemoryMiB: 1024,
            maxVcpu: 2,
            maxDiskGiB: 100,
          }),
        ).rejects.toBeDefined();
      if (action === "revoke")
        await revokePoolShare(session(actor.id), { poolId: f.pool.id, granteeUserId: f.b.id });
      if (action === "clear" || action === "reduce")
        await updatePoolShare(session(actor.id), {
          poolId: f.pool.id,
          granteeUserId: f.b.id,
          canUse: action === "reduce",
          canContribute: false,
          ...(action === "reduce" ? { maxMemoryMiB: 256, maxVcpu: 1, maxDiskGiB: 50 } : {}),
        });
      if (action === "leave") await leavePool(session(actor.id), { poolId: f.pool.id });
      if (action === "withdraw") await withdrawPoolHost(session(actor.id), target);
      if (action === "remove") await removePoolMember(session(actor.id), target);
      if (action === "disable")
        await updatePoolMember(session(actor.id), { ...target, enabled: false });
      if (action.startsWith("contributor-"))
        await contributePoolHost(session(actor.id), {
          ...target,
          enabled: action === "contributor-cap",
          memoryCapPercent: 25,
          vcpuCapPercent: 25,
        });
      if (["revoke", "clear", "leave"].includes(action))
        expect(
          await db.inspect.share.count({
            where: {
              poolId: f.pool.id,
              granteeUserId: f.b.id,
            },
          }),
        ).toBe(0);
      else if (action === "reduce")
        expect(
          await db.inspect.share.findUnique({
            where: {
              poolId_granteeUserId: { poolId: f.pool.id, granteeUserId: f.b.id },
            },
          }),
        ).toMatchObject({ canUse: true, canContribute: false });
      else if (action === "contributor-cap")
        expect(
          await db.inspect.sandboxPoolMember.findUnique({
            where: { poolId_sandboxHostId: target },
          }),
        ).toMatchObject({
          enabled: true,
          removedAt: null,
          memoryCapPercent: 25,
          vcpuCapPercent: 25,
        });
      else
        expect(
          await db.inspect.sandboxPoolMember.findUnique({
            where: {
              poolId_sandboxHostId: target,
            },
          }),
        ).toMatchObject({ enabled: false });
      if (["contributor-disable", "withdraw", "leave"].includes(action))
        await expect(
          contributePoolHost(session(f.b.id), {
            ...target,
            enabled: true,
            memoryCapPercent: 10,
            vcpuCapPercent: 10,
          }),
        ).rejects.toBeDefined();
    }
    const f = await fixture();
    await grantPoolShare(session(f.a.id), { poolId: f.pool.id, email: f.b.email });
    await block(f.a.id);
    await expect(
      revokePoolShare(session(f.a.id), { poolId: f.pool.id, granteeUserId: f.b.id }),
    ).rejects.toBeDefined();
    expect(await db.inspect.share.count({ where: { poolId: f.pool.id } })).toBe(1);
  },
);

it.each(["delete", "remove"] as const)(
  "r1 %s holds graph authority until rollback and emits no committed invalidation",
  async (action) => {
    const f = await fixture();
    await grantPoolShare(session(f.a.id), { poolId: f.pool.id, email: f.b.email });
    await contributePoolHost(session(f.b.id), { poolId: f.pool.id, sandboxHostId: f.host.id });
    const { authorityTicket, onAuthorityCommitted } = await import("@wssp/db/authority");
    const notices: unknown[] = [];
    const off = onAuthorityCommitted((scope) => notices.push(scope));
    const before = authorityTicket({ ownerId: f.a.id });
    const gate = db.pauseAt("rollback-graph", {
      after: action === "delete" ? "sandboxPool.update" : "sandboxPoolMember.updateMany",
    });
    const write = db.run("rollback-graph", () =>
      action === "delete"
        ? deletePool(session(f.a.id), { id: f.pool.id })
        : removePoolMember(session(f.a.id), { poolId: f.pool.id, sandboxHostId: f.host.id }),
    );
    // The service sanitizes injected failures at its public boundary.
    const failed = expect(write).rejects.toMatchObject({ code: "INTERNAL_SERVER_ERROR" });
    try {
      await gate.waitReached();
      expect(before()).toBe(false);
      expect(authorityTicket({ ownerId: f.a.id })()).toBe(false);
    } finally {
      gate.fail(new Error("rollback graph"));
    }
    await failed;
    await Promise.resolve();
    off();
    expect(notices).toEqual([]);
    expect(authorityTicket({ ownerId: f.a.id })()).toBe(true);
    expect(await db.inspect.sandboxPool.findUnique({ where: { id: f.pool.id } })).toMatchObject({
      deletedAt: null,
    });
    expect(
      await db.inspect.sandboxPoolMember.findUnique({
        where: {
          poolId_sandboxHostId: {
            poolId: f.pool.id,
            sandboxHostId: f.host.id,
          },
        },
      }),
    ).toMatchObject({ removedAt: null, enabled: true });
  },
);

it.each(["session", "sdkKey"] as const)(
  "r1 %s read result retains the foreign graph ticket across withdrawal and regrant during body IO",
  async (kind) => {
    const f = await readFixture();
    const revision = await seedTemplateRevision(db.inspect, {
      data: {
        userId: f.c.id,
        slug: randomUUID(),
        label: "Creator private",
        incusFingerprint: `sha256:${"c".repeat(64)}`,
      },
    });
    const sandbox = await seedSandboxInstance(db.inspect, {
      data: {
        userId: f.c.id,
        hostOwnerId: f.b.id,
        templateId: revision.id,
        sandboxHostId: f.host.id,
        originHostId: f.host.id,
        state: "READY",
        usagePoolId: f.pool.id,
        usageMemberId: f.member.id,
        liveResourcesHeld: false,
        diskReservationHeld: false,
      },
    });
    const key = await createSdkKey(session(f.c.id), {
      name: "Read",
      scopes: [...SERVICE_SCOPES],
      resourceMode: "ALL_OWNED",
    });
    const principal =
      kind === "session" ? session(f.c.id) : await authenticateSdkKeySecret(key.secret);
    if (!principal) throw new Error("Missing read principal");
    await seedAcceptedOperation(db.inspect, {
      data: {
        userId: f.c.id,
        sandboxId: sandbox.id,
        kind: "CREATE_SANDBOX",
        generation: 1,
        idempotencyKey: randomUUID(),
        requestBodyHash: "a".repeat(64),
        authorizingKeyId: key.key.id,
        state: "SUCCEEDED",
      },
    });
    // Exercise the real service result boundary; the body stands for a content
    // read that has already fetched its private result before withdrawal.
    const read = serviceProcedure(
      { action: "files.stat", target: (input: { id: string }) => ({ sandboxId: input.id }) },
      async () => {
        await db.prisma.sandbox.count({ where: { id: sandbox.id } });
        return "private result";
      },
    );
    const gate = db.pauseAt("sharing-read", { after: "sandbox.count" });
    const reading = db.run("sharing-read", () => read(principal, { id: sandbox.id }));
    const refused = expect(reading).rejects.toMatchObject({ code: "FORBIDDEN" });
    try {
      await gate.waitReached();
      await removePoolMember(session(f.a.id), { poolId: f.pool.id, sandboxHostId: f.host.id });
      await contributePoolHost(session(f.b.id), { poolId: f.pool.id, sandboxHostId: f.host.id });
      const { currentHostUsability } = await import("../sharing-access");
      expect(await currentHostUsability(db.prisma, f.c.id, sandbox.id)).toBe(true);
    } finally {
      gate.release();
    }
    await refused;
  },
);

it("r1 invalid graph requests cannot invalidate an unrelated pool or host owner's tickets", async () => {
  const f = await fixture();
  await grantPoolShare(session(f.a.id), { poolId: f.pool.id, email: f.b.email });
  await contributePoolHost(session(f.b.id), { poolId: f.pool.id, sandboxHostId: f.host.id });
  const { authorityTicket } = await import("@wssp/db/authority");
  const poolCurrent = authorityTicket({ ownerId: f.a.id });
  const hostCurrent = authorityTicket({ ownerId: f.b.id });
  const target = { poolId: f.pool.id, sandboxHostId: f.host.id };
  await expect(removePoolMember(session(f.c.id), target)).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  await expect(withdrawPoolHost(session(f.c.id), target)).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  await expect(leavePool(session(f.c.id), { poolId: f.pool.id })).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  await expect(contributePoolHost(session(f.c.id), target)).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  expect(poolCurrent()).toBe(true);
  expect(hostCurrent()).toBe(true);
});

it.each(["withdraw", "leave", "contribute"] as const)(
  "r2 rejected historical %s preserves the pool owner's unrelated authority",
  async (action) => {
    const f = await fixture();
    const target = { poolId: f.pool.id, sandboxHostId: f.host.id };
    await grantPoolShare(session(f.a.id), { poolId: f.pool.id, email: f.b.email });
    const member = await contributePoolHost(session(f.b.id), target);
    const unrelatedHost = await db.inspect.sandboxHost.create({
      data: { userId: f.a.id, slug: randomUUID(), label: "Unrelated" },
    });
    await revokePoolShare(session(f.a.id), { poolId: f.pool.id, granteeUserId: f.b.id });
    const retained = await db.inspect.sandboxPoolMember.findUnique({ where: { id: member.id } });
    expect(retained).toMatchObject({
      userId: f.a.id,
      hostOwnerId: f.b.id,
      removedAt: expect.any(Date),
      enabled: false,
      shareId: null,
    });
    const { authorityTicket } = await import("@wssp/db/authority");
    const ownerCurrent = authorityTicket({ ownerId: f.a.id });
    const hostCurrent = authorityTicket({ ownerId: f.a.id, hostId: unrelatedHost.id });
    expect(ownerCurrent()).toBe(true);
    expect(hostCurrent()).toBe(true);
    for (let attempt = 0; attempt < 2; attempt++) {
      await expect(
        action === "withdraw"
          ? withdrawPoolHost(session(f.b.id), target)
          : action === "leave"
            ? leavePool(session(f.b.id), { poolId: f.pool.id })
            : contributePoolHost(session(f.b.id), target),
      ).rejects.toMatchObject({ code: "NOT_FOUND" });
      expect(ownerCurrent()).toBe(true);
      expect(hostCurrent()).toBe(true);
    }
    expect(await db.inspect.sandboxPoolMember.findUnique({ where: { id: member.id } })).toEqual(
      retained,
    );
  },
);

it.each(["banned", "deleting"] as const)(
  "r2 withdrawal still rejects a %s actor with a live membership",
  async (policy) => {
    const f = await fixture();
    const target = { poolId: f.pool.id, sandboxHostId: f.host.id };
    await grantPoolShare(session(f.a.id), { poolId: f.pool.id, email: f.b.email });
    const member = await contributePoolHost(session(f.b.id), target);
    await db.inspect.user.update({
      where: { id: f.b.id },
      data:
        policy === "banned"
          ? { banned: true, banExpires: null }
          : { deletionRequestedAt: new Date() },
    });
    await expect(withdrawPoolHost(session(f.b.id), target)).rejects.toMatchObject({
      code: policy === "banned" ? "NOT_FOUND" : "CONFLICT",
    });
    expect(
      await db.inspect.sandboxPoolMember.findUnique({ where: { id: member.id } }),
    ).toMatchObject({ removedAt: null, enabled: true });
  },
);

it("r2 leaving a deleted pool with a retained share preserves the owner's unrelated authority", async () => {
  const f = await fixture();
  await grantPoolShare(session(f.a.id), { poolId: f.pool.id, email: f.b.email });
  await deletePool(session(f.a.id), { id: f.pool.id });
  const where = { poolId_granteeUserId: { poolId: f.pool.id, granteeUserId: f.b.id } };
  const retained = await db.inspect.share.findUnique({ where });
  expect(retained).toMatchObject({ ownerUserId: f.a.id, granteeUserId: f.b.id });
  const { authorityTicket } = await import("@wssp/db/authority");
  const current = authorityTicket({ ownerId: f.a.id });
  await expect(leavePool(session(f.b.id), { poolId: f.pool.id })).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  expect(current()).toBe(true);
  expect(await db.inspect.share.findUnique({ where })).toEqual(retained);
});

it("r2 leave rechecks pool liveness under G after preflight", async () => {
  const f = await fixture();
  await grantPoolShare(session(f.a.id), { poolId: f.pool.id, email: f.b.email });
  const where = { poolId_granteeUserId: { poolId: f.pool.id, granteeUserId: f.b.id } };
  const retained = await db.inspect.share.findUnique({ where });
  const gate = db.pauseAt("leave-preflight", { after: "share.findUnique" });
  const leaving = db.run("leave-preflight", () =>
    leavePool(session(f.b.id), { poolId: f.pool.id }),
  );
  const refused = expect(leaving).rejects.toMatchObject({ code: "NOT_FOUND" });
  try {
    await gate.waitReached();
    await deletePool(session(f.a.id), { id: f.pool.id });
  } finally {
    gate.release();
  }
  await refused;
  expect(await db.inspect.share.findUnique({ where })).toEqual(retained);
});

it.each(["cap", "disable"] as const)(
  "r1 contribution reduction rechecks %s changes after preflight instead of widening a blocked owner's grant",
  async (change) => {
    const f = await fixture();
    await grantPoolShare(session(f.a.id), { poolId: f.pool.id, email: f.b.email });
    const target = { poolId: f.pool.id, sandboxHostId: f.host.id };
    await contributePoolHost(session(f.b.id), {
      ...target,
      memoryCapPercent: 50,
      vcpuCapPercent: 50,
    });
    await db.inspect.user.update({
      where: { id: f.a.id },
      data: { banned: true, banExpires: null },
    });
    const gate = db.pauseAt("reduce-preflight", { after: "sandboxPoolMember.findFirst" });
    const reduction = db.run("reduce-preflight", () =>
      contributePoolHost(session(f.b.id), {
        ...target,
        enabled: true,
        memoryCapPercent: 25,
        vcpuCapPercent: 25,
      }),
    );
    const refused = expect(reduction).rejects.toMatchObject({ code: "NOT_FOUND" });
    try {
      await gate.waitReached();
      await contributePoolHost(session(f.b.id), {
        ...target,
        enabled: change !== "disable",
        memoryCapPercent: 10,
        vcpuCapPercent: 10,
      });
    } finally {
      gate.release();
    }
    await refused;
    expect(
      await db.inspect.sandboxPoolMember.findUnique({ where: { poolId_sandboxHostId: target } }),
    ).toMatchObject({
      enabled: change !== "disable",
      memoryCapPercent: 10,
      vcpuCapPercent: 10,
      removedAt: null,
    });
  },
);

it("lease limits: only the host owner sets a membership limit; lowering needs no consent, raising re-proves it, omission keeps it, re-activation resets it", async () => {
  const f = await fixture();
  await grantPoolShare(session(f.a.id), { poolId: f.pool.id, email: f.b.email });
  const member = await contributePoolHost(session(f.b.id), {
    poolId: f.pool.id,
    sandboxHostId: f.host.id,
    maxLeaseMs: 21_600_000,
  });
  expect(member).toMatchObject({ maxLeaseMs: 21_600_000 });
  // N2: the pool owner may disable a contributed host, never set its limit.
  await expect(
    updatePoolMember(session(f.a.id), {
      poolId: f.pool.id,
      sandboxHostId: f.host.id,
      maxLeaseMs: 86_400_000,
    }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  await expect(
    updatePoolMember(session(f.a.id), {
      poolId: f.pool.id,
      sandboxHostId: f.host.id,
      maxLeaseMs: null,
    }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  expect(
    await db.inspect.sandboxPoolMember.findUniqueOrThrow({ where: { id: member.id } }),
  ).toMatchObject({ maxLeaseMs: 21_600_000 });
  // Lowering is a reduction (contributionReduction): no counterparty admission.
  await contributePoolHost(session(f.b.id), {
    poolId: f.pool.id,
    sandboxHostId: f.host.id,
    maxLeaseMs: 3_600_000,
  });
  // Minor 5: toggling `enabled` without the field keeps the limit.
  await contributePoolHost(session(f.b.id), {
    poolId: f.pool.id,
    sandboxHostId: f.host.id,
    enabled: false,
  });
  expect(
    await db.inspect.sandboxPoolMember.findUniqueOrThrow({ where: { id: member.id } }),
  ).toMatchObject({ maxLeaseMs: 3_600_000, enabled: false });
  // Raising is not a reduction: it re-proves the contribution consent.
  expect(
    await contributePoolHost(session(f.b.id), {
      poolId: f.pool.id,
      sandboxHostId: f.host.id,
      enabled: false,
      maxLeaseMs: 7_200_000,
    }),
  ).toMatchObject({ maxLeaseMs: 7_200_000 });
  await updatePoolShare(session(f.a.id), {
    poolId: f.pool.id,
    granteeUserId: f.b.id,
    canUse: true,
    canContribute: false,
  });
  await expect(
    contributePoolHost(session(f.b.id), {
      poolId: f.pool.id,
      sandboxHostId: f.host.id,
      maxLeaseMs: null,
    }),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
  // N4: the consent change removed the membership; re-contributing starts fresh.
  await updatePoolShare(session(f.a.id), { poolId: f.pool.id, granteeUserId: f.b.id });
  const again = await contributePoolHost(session(f.b.id), {
    poolId: f.pool.id,
    sandboxHostId: f.host.id,
  });
  expect(again).toMatchObject({ id: member.id, maxLeaseMs: null });
});

it("lease limits: own-host membership limit through add/update; re-adding a removed host resets it (N4)", async () => {
  const f = await fixture();
  const own = await db.inspect.sandboxHost.create({
    data: { userId: f.a.id, slug: randomUUID(), label: "Own", connectionEpoch: 1 },
  });
  const added = await addPoolMember(session(f.a.id), {
    poolId: f.pool.id,
    sandboxHostId: own.id,
    enabled: true,
    maxLeaseMs: 21_600_000,
  });
  expect(added).toMatchObject({ maxLeaseMs: 21_600_000 });
  expect(
    await updatePoolMember(session(f.a.id), {
      poolId: f.pool.id,
      sandboxHostId: own.id,
      enabled: false,
    }),
  ).toMatchObject({ enabled: false, maxLeaseMs: 21_600_000 });
  expect(
    await updatePoolMember(session(f.a.id), {
      poolId: f.pool.id,
      sandboxHostId: own.id,
      maxLeaseMs: 3_600_000,
    }),
  ).toMatchObject({ enabled: false, maxLeaseMs: 3_600_000 });
  await removePoolMember(session(f.a.id), { poolId: f.pool.id, sandboxHostId: own.id });
  expect(
    await addPoolMember(session(f.a.id), {
      poolId: f.pool.id,
      sandboxHostId: own.id,
      enabled: true,
    }),
  ).toMatchObject({ id: added.id, maxLeaseMs: null });
});
