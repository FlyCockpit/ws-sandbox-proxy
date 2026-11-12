import { randomBytes } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));
// Budgets are Redis-backed; their behaviour has its own tests.
vi.mock("../lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));

/**
 * CLI-login control services against real PostgreSQL : definition → login →
 * account → instance → value write → re-pin, and re-pin refused
 * `credential.repin_blocked` by a racing claim, a RECOVERY_REQUIRED lease,
 * uncleared recoverable residue or a pending capture.
 */
const db = await pgTestDatabase();
const { seedOwner, seedSandbox } = await import("../webhooks/testing/fixtures");
const service = await import("./service");
const { claimWorkloadLeases } = await import("./selection");
afterAll(() => db.close());

const savedKey = process.env.DATA_ENCRYPTION_KEY;
beforeAll(() => {
  process.env.DATA_ENCRYPTION_KEY = randomBytes(32).toString("hex");
  process.env.CREDENTIALS_ENABLED = "true";
});
afterAll(() => {
  if (savedKey === undefined) delete process.env.DATA_ENCRYPTION_KEY;
  else process.env.DATA_ENCRYPTION_KEY = savedKey;
});

const definition = (version: string) => ({
  schemaVersion: 1,
  id: "tool",
  displayName: `Tool ${version}`,
  login: { command: "tool login", method: "device-code" },
  credentials: {
    files: { required: [".config/tool"], optional: [], exclude: [] },
    env: [{ name: "TOOL_PROFILE", required: false }],
  },
  "x-version": version,
});

async function setupLogin() {
  const owner = await seedOwner(db.inspect);
  const actor = { kind: "session", ownerId: owner } as const;
  const v1 = await service.createDefinition(actor, { document: definition("1") });
  const v2 = await service.createDefinition(actor, { document: definition("2") });
  expect([v1.version, v2.version]).toEqual([1, 2]);
  const login = await service.createLogin(actor, { name: "tool", definitionId: v1.id });
  expect(login).toMatchObject({
    mode: "EXCLUSIVE",
    delivery: "GUEST",
    copyBack: true,
    checkpointIntervalMin: 30,
  });
  const account = await service.createAccount(actor, { credentialId: login.id, name: "work" });
  const instance = await service.createInstance(actor, {
    credentialId: login.id,
    accountId: account.id,
  });
  expect(instance).toMatchObject({ state: "EMPTY", maxConcurrent: 1, activeLeases: 0 });
  const written = await service.writeValue(actor, {
    credentialId: login.id,
    instanceId: instance.id,
    files: [
      { path: ".config/tool", kind: "dir" },
      { path: ".config/tool/token", contentBase64: Buffer.from("secret-token").toString("base64") },
    ],
    env: { TOOL_PROFILE: "work" },
  });
  expect(written).toMatchObject({ instanceId: instance.id, storageSeq: 1, state: "READY" });
  return { owner, actor, v1, v2, login, account, instance };
}

describe("credential services (pg)", () => {
  it("end to end: create, upload (metadata-only response), list, re-pin re-encrypts under the new policy", async () => {
    const { actor, v2, login, account, instance } = await setupLogin();
    // Responses never carry a value.
    const instances = await service.listInstances(actor, {
      credentialId: login.id,
      accountId: account.id,
    });
    expect(instances.items).toHaveLength(1);
    expect(JSON.stringify(instances)).not.toContain("secret-token");
    // The upload's time (never its value) shows before any capture.
    const upload = await db.inspect.credentialSecretVersion.findUniqueOrThrow({
      where: { instanceId_storageSeq: { instanceId: instance.id, storageSeq: 1 } },
      select: { createdAt: true },
    });
    expect(instances.items[0]).toMatchObject({
      lastCapturedAt: null,
      lastUploadedAt: upload.createdAt.toISOString(),
    });
    // A value missing a required path is refused, naming only the entry.
    await expect(
      service.writeValue(actor, {
        credentialId: login.id,
        instanceId: instance.id,
        env: { TOOL_PROFILE: "x" },
      }),
    ).rejects.toMatchObject({
      // E2-B-02: the class in `entry`, the file in `path` (was `files..config/tool`).
      data: {
        code: "credential.value_invalid",
        entry: "files.missing_required",
        path: ".config/tool",
      },
    });
    // E2-B-02: an undeclared env var is named (env names are not secret).
    await expect(
      service.writeValue(actor, {
        credentialId: login.id,
        instanceId: instance.id,
        env: { TOOL_PROFILE: "x", NOT_DECLARED: "y" },
      }),
    ).rejects.toMatchObject({
      data: { code: "credential.value_invalid", entry: "env.NOT_DECLARED" },
    });
    const repinned = await service.repinLogin(actor, { id: login.id, definitionId: v2.id });
    expect(repinned.definition.version).toBe(2);
    const versions = await db.inspect.credentialSecretVersion.findMany({
      where: { instanceId: instance.id },
      select: { storageSeq: true, kind: true },
    });
    expect(versions).toEqual([{ storageSeq: 2, kind: "REPIN" }]);
    expect(
      await db.inspect.credentialInstance.findUniqueOrThrow({
        where: { id: instance.id },
        select: { currentSeq: true, state: true },
      }),
    ).toEqual({ currentSeq: 2, state: "READY" });
    // Pause is visible on the account and denormalized onto its instances.
    const paused = await service.updateAccount(actor, {
      credentialId: login.id,
      accountId: account.id,
      paused: true,
    });
    expect(paused.paused).toBe(true);
    expect(
      (await db.inspect.credentialInstance.findUniqueOrThrow({ where: { id: instance.id } }))
        .accountPaused,
    ).toBe(true);
  });

  it("22: re-pin vs claim — the claim's FOR SHARE blocks re-pin, which then refuses repin_blocked", async () => {
    const { owner, actor, v2, login } = await setupLogin();
    const sandbox = await seedSandbox(db.inspect, owner, "READY");
    const gate = db.pauseAt("claim", {
      after: /^sql:UPDATE credential_instance SET "activeLeases"/,
    });
    const claim = db.run("claim", () =>
      db.prisma.$transaction((tx) =>
        claimWorkloadLeases(tx, {
          ownerId: owner,
          sandboxId: sandbox.id,
          operationId: "op",
          requests: [{ credentialId: login.id }],
        }),
      ),
    );
    await gate.waitReached();
    const repin = db.run("repin", () =>
      service.repinLogin(actor, { id: login.id, definitionId: v2.id }),
    );
    await db.waitUntilBlocked("repin", { by: "claim" });
    gate.release();
    await claim;
    await expect(repin).rejects.toMatchObject({ data: { code: "credential.repin_blocked" } });
    // Nothing moved.
    expect(
      (await db.inspect.credential.findUniqueOrThrow({ where: { id: login.id } })).definitionDigest,
    ).toBe(
      (
        await db.inspect.credentialDefinition.findFirstOrThrow({
          where: { userId: owner, version: 1 },
        })
      ).digest,
    );
  });

  it("22: RECOVERY_REQUIRED lease, recoverable residue and a pending capture each block re-pin", async () => {
    for (const blocker of ["recovery", "residue", "pending"] as const) {
      const { owner, actor, v2, login, account, instance } = await setupLogin();
      const sandbox = await seedSandbox(db.inspect, owner, "STOPPED");
      const lease = await db.inspect.credentialLease.create({
        data: {
          userId: owner,
          credentialId: login.id,
          accountId: account.id,
          instanceId: instance.id,
          sandboxId: sandbox.id,
          operationId: "op",
          kind: "WORKLOAD",
          exclusive: true,
          state: blocker === "recovery" ? "RECOVERY_REQUIRED" : "RELEASED",
          releasedAt: blocker === "recovery" ? null : new Date(),
        },
      });
      if (blocker === "residue") {
        const binding = await db.inspect.credentialBinding.create({
          data: {
            leaseId: lease.id,
            instanceId: instance.id,
            hostId: "host",
            grantGeneration: 1,
            purpose: "INSTALL",
          },
        });
        await db.inspect.credentialResidue.create({
          data: {
            sandboxId: sandbox.id,
            userId: owner,
            credentialId: login.id,
            instanceId: instance.id,
            leaseId: lease.id,
            bindingId: binding.id,
            grantGeneration: 1,
            paths: [".config/tool"],
            recoverable: true,
          },
        });
      }
      if (blocker === "pending") {
        const host = await db.inspect.sandboxHost.create({
          data: { userId: owner, slug: `h-${randomBytes(4).toString("hex")}`, label: "Host" },
        });
        await db.inspect.credentialPendingCapture.create({
          data: {
            hostId: host.id,
            captureId: "cap",
            leaseId: lease.id,
            bindingId: "b",
            kidR: "0".repeat(16),
            kind: "stop",
          },
        });
      }
      await expect(
        service.repinLogin(actor, { id: login.id, definitionId: v2.id }),
        blocker,
      ).rejects.toMatchObject({
        data: { code: "credential.repin_blocked" },
      });
      // The same blockers refuse delete.
      await expect(service.deleteLogin(actor, { id: login.id })).rejects.toMatchObject({
        data: { code: "credential.busy" },
      });
    }
  });

  it("E1-B-04: a login whose sandboxes were destroyed and settled can be deleted; a live one is busy", async () => {
    const { owner, actor, login, account, instance } = await setupLogin();
    const attach = async (sandboxId: string) =>
      db.inspect.sandboxCredential.create({
        data: { sandboxId, userId: owner, credentialId: login.id, accountId: account.id },
      });
    const settledLease = (sandboxId: string) =>
      db.inspect.credentialLease.create({
        data: {
          userId: owner,
          credentialId: login.id,
          accountId: account.id,
          instanceId: instance.id,
          sandboxId,
          operationId: `op-${sandboxId}`,
          kind: "WORKLOAD",
          exclusive: true,
          state: "RELEASED",
          releasedAt: new Date(),
        },
      });
    // Still holding live resources (teardown not proven): busy.
    const tearingDown = await seedSandbox(db.inspect, owner, "DELETED", {
      liveResourcesHeld: true,
    });
    await attach(tearingDown.id);
    await settledLease(tearingDown.id);
    await expect(service.deleteLogin(actor, { id: login.id })).rejects.toMatchObject({
      data: { code: "credential.busy" },
    });
    await db.inspect.sandbox.update({
      where: { id: tearingDown.id },
      data: { liveResourcesHeld: false },
    });
    // A running sandbox's attachment stays busy.
    const running = await seedSandbox(db.inspect, owner, "STOPPED");
    const live = await attach(running.id);
    await expect(service.deleteLogin(actor, { id: login.id })).rejects.toMatchObject({
      data: { code: "credential.busy" },
    });
    await db.inspect.sandboxCredential.update({
      where: { id: live.id },
      data: { detachedAt: new Date() },
    });
    // Only destroyed, settled sandboxes remain: the delete detaches and succeeds.
    await expect(service.deleteLogin(actor, { id: login.id })).resolves.toEqual({ deleted: true });
    expect(await db.inspect.credential.count({ where: { id: login.id } })).toBe(0);
  });

  it("final-6: a shareable instance capped at one accepts value writes while leased; an exclusive one is busy", async () => {
    const owner = await seedOwner(db.inspect);
    const actor = { kind: "session", ownerId: owner } as const;
    const leasedInstance = async (sharing: "exclusive" | "shareable") => {
      const document = {
        ...definition(sharing),
        credentials: { ...definition(sharing).credentials, sharing },
      };
      const def = await service.createDefinition(actor, { document });
      const login = await service.createLogin(actor, {
        name: `tool-${sharing}`,
        definitionId: def.id,
      });
      expect(login.mode).toBe(sharing === "shareable" ? "SHAREABLE" : "EXCLUSIVE");
      const account = await service.createAccount(actor, { credentialId: login.id, name: "work" });
      const instance = await service.createInstance(actor, {
        credentialId: login.id,
        accountId: account.id,
        ...(sharing === "shareable" ? { maxConcurrent: 1 } : {}),
      });
      expect(instance.maxConcurrent).toBe(1);
      // One running holder (only the counter matters to the upload guard).
      await db.inspect.credentialInstance.update({
        where: { id: instance.id },
        data: { activeLeases: 1 },
      });
      return { login, instance };
    };
    const write = (login: { id: string }, instance: { id: string }) =>
      service.writeValue(actor, {
        credentialId: login.id,
        instanceId: instance.id,
        files: [
          { path: ".config/tool", kind: "dir" },
          { path: ".config/tool/token", contentBase64: Buffer.from("rotated").toString("base64") },
        ],
      });
    const shared = await leasedInstance("shareable");
    await expect(write(shared.login, shared.instance)).resolves.toMatchObject({
      instanceId: shared.instance.id,
      state: "READY",
    });
    const exclusive = await leasedInstance("exclusive");
    await expect(write(exclusive.login, exclusive.instance)).rejects.toMatchObject({
      data: { code: "credential.busy" },
    });
  });

  it("delete removes settled history; an SDK key without an allowlist grant sees nothing", async () => {
    const { owner, actor, login } = await setupLogin();
    await expect(service.deleteLogin(actor, { id: login.id })).resolves.toEqual({ deleted: true });
    expect(await db.inspect.credentialInstance.count({ where: { credentialId: login.id } })).toBe(
      0,
    );
    expect(
      await db.inspect.credentialSecretVersion.count({
        where: { Instance: { credentialId: login.id } },
      }),
    ).toBe(0);
    const other = await service.createLogin(actor, {
      name: "other",
      definitionId: (
        await db.inspect.credentialDefinition.findFirstOrThrow({
          where: { userId: owner, version: 2 },
        })
      ).id,
    });
    const visible = (filter: object) =>
      db.inspect.credential.count({ where: { AND: [filter, { id: other.id }] } });
    const { credentialAccessFilter } = await import("./access");
    const key = {
      kind: "sdkKey",
      ownerId: owner,
      keyId: "key",
      resourceMode: "ALLOWLIST",
    } as never;
    expect(await visible(credentialAccessFilter(key))).toBe(0);
    expect(await visible(credentialAccessFilter(actor))).toBe(1);
  });
});
