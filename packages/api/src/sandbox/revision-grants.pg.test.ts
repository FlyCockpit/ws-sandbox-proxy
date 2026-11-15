vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "revision-grants-fixture",
  },
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { randomUUID } from "node:crypto";
import { withAuthorityChange } from "@wssp/db/authority";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import { authenticateSdkKeySecret } from "../lib/sdk-key-access";
import { getActionReceipt } from "./action-receipts";
import { bindHostImageVerifier } from "./host-image-verifier";
import { appendRevisionReceipt } from "./sdk-mutations";
import { createSandbox, getSandbox, listSandboxes } from "./services/sandboxes";
import { createSdkKey, listSdkKeys } from "./services/sdk-keys";
import { appendTemplateRevision, listTemplateRevisions, listTemplates } from "./services/templates";
import { resolveTemplateRevision } from "./template-resolution";
import { seedLaunchHost, seedTemplateRevision } from "./testing/resource-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());
async function fixture() {
  const id = randomUUID();
  await db.inspect.user.create({
    data: {
      id,
      name: "Owner",
      email: `${id}@example.test`,
      twoFactorEnabled: true,
      emailVerified: true,
    },
  });
  const owner = { kind: "session" as const, ownerId: id };
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: id,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      egressEnforcement: true,
    },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      incusFingerprint: `sha256:${"b".repeat(64)}`,
    },
  });
  const hidden = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      slug: "hidden",
      label: "Hidden",
      incusFingerprint: `sha256:${"c".repeat(64)}`,
    },
  });
  const key = await createSdkKey(owner, {
    name: "sdk",
    resourceMode: "ALLOWLIST",
    hostIds: [host.id],
    templateRevisionIds: [revision.id],
    scopes: [
      "templates:read",
      "templates:write",
      "hosts:read",
      "sandboxes:read",
      "sandboxes:create",
      "sandboxes:manage",
      "sandboxes:destroy",
      "operations:read",
    ],
  });
  const principal = await authenticateSdkKeySecret(key.secret);
  if (!principal) throw new Error("fixture key inactive");
  return { id, owner, host, revision, hidden, key, principal };
}
function refusal(error: unknown) {
  const value = error as { code: string; data: unknown; message: string };
  return { code: value.code, data: value.data, message: value.message };
}
it("3E pool_revision_absence_equivalence: every selector hides absent, foreign and ungranted revisions with positive controls", async () => {
  const f = await fixture();
  const foreign = await fixture();
  for (const selector of [
    "base",
    `template/${f.revision.templateId}`,
    f.revision.templateId,
    "base:latest",
    `revision/${f.revision.id}`,
  ])
    expect((await resolveTemplateRevision(db.prisma, f.principal, selector)).id).toBe(
      f.revision.id,
    );
  const errors = [];
  for (const selector of [
    "absent",
    "hidden",
    "hidden:latest",
    `template/${f.hidden.templateId}`,
    `template/${foreign.revision.templateId}`,
    "template/absent",
    `revision/${f.hidden.id}`,
    `revision/${foreign.revision.id}`,
    "revision/absent",
  ])
    errors.push(
      await resolveTemplateRevision(db.prisma, f.principal, selector).then(() => null, refusal),
    );
  expect(errors.every((error) => JSON.stringify(error) === JSON.stringify(errors[0]))).toBe(true);
  expect(errors[0]).toMatchObject({
    code: "NOT_FOUND",
    data: { code: "sandbox.template_not_found" },
  });
  expect((await listTemplates(f.principal, { limit: 20 })).items.map((row) => row.id)).toEqual([
    f.revision.templateId,
  ]);
  expect(
    (
      await listTemplateRevisions(f.principal, { templateId: f.revision.templateId, limit: 20 })
    ).items.map((row) => row.id),
  ).toEqual([f.revision.id]);
});
it("3E invisible registration is absence-equivalent before host IO and newly appended revisions never grant themselves", async () => {
  const f = await fixture();
  const other = await fixture();
  const verify = vi.fn(async () => ({
    incusFingerprint: `sha256:${"d".repeat(64)}`,
    architecture: "x86_64",
  }));
  bindHostImageVerifier(verify);
  const input = { hostId: f.host.id, imageRef: "images:next", architecture: "x86_64" };
  const errors = [];
  for (const templateId of ["absent", f.hidden.templateId, other.revision.templateId])
    errors.push(
      await appendTemplateRevision(f.principal, { ...input, templateId }).then(() => null, refusal),
    );
  expect(errors).toEqual([errors[0], errors[0], errors[0]]);
  expect(errors[0]).toMatchObject({ code: "NOT_FOUND" });
  expect(verify).not.toHaveBeenCalled();
  const appended = await appendTemplateRevision(f.principal, {
    ...input,
    templateId: f.revision.templateId,
    envs: { PRIVATE: "template-default-secret" },
  });
  expect(verify).toHaveBeenCalledOnce();
  expect(appended.revision).toBe(2);
  expect(
    await db.inspect.sdkKeyRevisionAllowlist.count({
      where: { sdkKeyId: f.key.key.id, templateRevisionId: appended.id },
    }),
  ).toBe(0);
  expect(
    (
      await listTemplateRevisions(f.principal, { templateId: f.revision.templateId, limit: 20 })
    ).items.map((row) => row.id),
  ).toEqual([f.revision.id]);
  await expect(resolveTemplateRevision(db.prisma, f.principal, "base")).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  await expect(
    resolveTemplateRevision(db.prisma, f.principal, `revision/${appended.id}`),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
  expect(
    (await resolveTemplateRevision(db.prisma, f.principal, `revision/${f.revision.id}`)).id,
  ).toBe(f.revision.id);
});
it("creating selected key retains accepted work after revision grant loss while fresh template work refuses", async () => {
  const f = await fixture();
  const sandbox = await createSandbox(f.principal, {
    template: `revision/${f.revision.id}`,
    sandboxHostId: f.host.id,
    idempotencyKey: randomUUID(),
  });
  await db.inspect.sandbox.update({ where: { id: sandbox.id }, data: { state: "READY" } });
  expect((await listSandboxes(f.principal, { limit: 10 })).items.map((row) => row.id)).toEqual([
    sandbox.id,
  ]);
  await withAuthorityChange({ ownerId: f.id, credentialId: f.principal.keyId }, () =>
    db.inspect.sdkKeyRevisionAllowlist.deleteMany({ where: { sdkKeyId: f.principal.keyId } }),
  );
  const principal = await authenticateSdkKeySecret(f.key.secret);
  expect(principal).not.toBeNull();
  if (!principal) return;
  expect(await db.inspect.sdkKeyHostAllowlist.count({ where: { sdkKeyId: principal.keyId } })).toBe(
    1,
  );
  expect((await listTemplates(principal, { limit: 10 })).items).toEqual([]);
  expect((await listSandboxes(principal, { limit: 10 })).items.map((row) => row.id)).toEqual([
    sandbox.id,
  ]);
  await expect(getSandbox(principal, { id: sandbox.id })).resolves.toHaveProperty("id", sandbox.id);
  await expect(
    createSandbox(principal, {
      template: `revision/${f.revision.id}`,
      sandboxHostId: f.host.id,
      idempotencyKey: randomUUID(),
    }),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
});
it("3E retained legacy host links confer no cross-owner authority", async () => {
  const f = await fixture();
  const foreign = await fixture();
  await db.inspect.sdkKeyHostAllowlist.create({
    data: { sdkKeyId: f.key.key.id, sandboxHostId: foreign.host.id },
  });
  const principal = await authenticateSdkKeySecret(f.key.secret);
  if (!principal) throw new Error("fixture key inactive");
  if (principal.allowedHostIds === "allOwned")
    throw new Error("fixture key unexpectedly unrestricted");
  expect(principal.allowedHostIds.has(foreign.host.id)).toBe(false);
  const keys = await listSdkKeys(
    { kind: "session", ownerId: f.id },
    { limit: 20, includeRevoked: true },
  );
  expect(
    keys.items.flatMap((key) => key.hostAllowlist).some((host) => host.id === foreign.host.id),
  ).toBe(false);
  await expect(
    createSandbox(principal, {
      template: `revision/${f.revision.id}`,
      sandboxHostId: foreign.host.id,
      idempotencyKey: randomUUID(),
    }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
});
it("3E append rechecks grants after verification and rolls back private config after a revocation race", async () => {
  const f = await fixture();
  let reached!: () => void;
  let resume!: () => void;
  const verified = new Promise<void>((resolve) => {
    reached = resolve;
  });
  const continueVerification = new Promise<void>((resolve) => {
    resume = resolve;
  });
  bindHostImageVerifier(async () => {
    reached();
    await continueVerification;
    return { incusFingerprint: `sha256:${"e".repeat(64)}`, architecture: "x86_64" };
  });
  const pending = db
    .run("append", () =>
      appendTemplateRevision(f.principal, {
        templateId: f.revision.templateId,
        hostId: f.host.id,
        imageRef: "images:next",
        architecture: "x86_64",
        envs: { PRIVATE: "grant-race-secret" },
      }),
    )
    .then(() => null, refusal);
  try {
    await verified;
    await withAuthorityChange({ ownerId: f.id, credentialId: f.principal.keyId }, () =>
      db.inspect.sdkKeyRevisionAllowlist.deleteMany({ where: { sdkKeyId: f.principal.keyId } }),
    );
  } finally {
    resume();
  }
  expect(await pending).toMatchObject({ code: "FORBIDDEN" });
  expect(
    await db.inspect.sandboxTemplateRevision.count({
      where: { templateId: f.revision.templateId },
    }),
  ).toBe(1);
  expect(await db.inspect.sandboxRevisionConfig.count({ where: { userId: f.id } })).toBe(2);
});

it("3E append replay retains its logical target without loading or granting the new hidden revision", async () => {
  const f = await fixture();
  bindHostImageVerifier(async () => ({
    incusFingerprint: `sha256:${"e".repeat(64)}`,
    architecture: "x86_64",
  }));
  const input = {
    templateId: f.revision.templateId,
    hostId: f.host.id,
    imageRef: "local:next",
    architecture: "x86_64",
    idempotencyKey: randomUUID(),
  };
  const accepted = await appendRevisionReceipt(f.principal, input);
  expect(accepted.state).toBe("SUCCEEDED");
  const stored = await db.inspect.sandboxActionReceipt.findUniqueOrThrow({
    where: { id: accepted.operationId },
  });
  expect(stored).toMatchObject({ logicalTemplateId: f.revision.templateId });
  expect(stored.templateRevisionId).not.toBe(f.revision.id);
  const hiddenRead = db.pauseAt("replay", { before: "sandboxTemplateRevision.findFirst" });
  const replaying = db.run("replay", () => appendRevisionReceipt(f.principal, input));
  try {
    const outcome = await Promise.race([
      replaying.then((receipt) => ({ kind: "receipt", receipt })),
      hiddenRead.reached.then(() => ({ kind: "hidden-read" })),
    ]);
    expect(outcome).toEqual({ kind: "receipt", receipt: accepted });
  } finally {
    hiddenRead.release();
    await replaying.catch(() => {});
  }
  await expect(getActionReceipt(f.principal, { id: stored.id })).rejects.toMatchObject({
    code: "FORBIDDEN",
  });
  expect(
    await db.inspect.sdkKeyRevisionAllowlist.count({
      where: {
        sdkKeyId: f.key.key.id,
        templateRevisionId: stored.templateRevisionId!,
      },
    }),
  ).toBe(0);
  const foreign = await fixture();
  await expect(
    db.inspect.sandboxActionReceipt.update({
      where: { id: stored.id },
      data: { logicalTemplateId: foreign.revision.templateId },
    }),
  ).rejects.toMatchObject({ code: "P2003" });
  await db.inspect.sdkKeyRevisionAllowlist.create({
    data: {
      userId: f.id,
      sdkKeyId: f.key.key.id,
      templateRevisionId: stored.templateRevisionId!,
    },
  });
  expect(await getActionReceipt(f.principal, { id: stored.id })).toMatchObject({
    id: stored.id,
    resourceId: stored.templateRevisionId,
    state: "SUCCEEDED",
  });
});

it("SDK-key mint refuses archived logical templates exactly like retired revisions without writing grants", async () => {
  const f = await fixture();
  const input = {
    name: "mint lifecycle",
    resourceMode: "ALLOWLIST" as const,
    hostIds: [f.host.id],
    templateRevisionIds: [f.revision.id],
    scopes: ["templates:read"],
  };
  const beforeKeys = await db.inspect.sdkKey.count({ where: { userId: f.id } });
  const beforeGrants = await db.inspect.sdkKeyRevisionAllowlist.count({ where: { userId: f.id } });
  await db.inspect.sandboxTemplateRevision.update({
    where: { id: f.revision.id },
    data: { retiredAt: new Date() },
  });
  const retired = await createSdkKey(f.owner, input).then(() => null, refusal);
  expect(retired).toMatchObject({
    code: "BAD_REQUEST",
    data: {
      code: "sdk_key.template_not_on_selected_host",
    },
  });
  await db.inspect.sandboxTemplateRevision.update({
    where: { id: f.revision.id },
    data: { retiredAt: null },
  });
  await db.inspect.sandboxTemplate.update({
    where: { id: f.revision.templateId },
    data: { archivedAt: new Date() },
  });
  expect(await createSdkKey(f.owner, input).then(() => null, refusal)).toEqual(retired);
  expect(await db.inspect.sdkKey.count({ where: { userId: f.id } })).toBe(beforeKeys);
  expect(await db.inspect.sdkKeyRevisionAllowlist.count({ where: { userId: f.id } })).toBe(
    beforeGrants,
  );
  await db.inspect.sandboxTemplate.update({
    where: { id: f.revision.templateId },
    data: { archivedAt: null },
  });
  expect(await createSdkKey(f.owner, input)).toHaveProperty("secret");
});
