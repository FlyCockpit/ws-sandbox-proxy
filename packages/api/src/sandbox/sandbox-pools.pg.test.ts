vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "pool-management-fixture",
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { randomUUID } from "node:crypto";
import { deleteAccountInTransaction } from "@wssp/db/account-deletion";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import {
  authorizeServiceAction,
  checkAcceptedDispatchAuthority,
  SERVICE_ACTION_CUSTODY,
} from "../lib/sdk-key-access";
import { SERVICE_ACTION_REQUIREMENTS, SERVICE_ACTIONS } from "../lib/service-scopes";
import { lockAdmissionHost, tryFinalizeTombstonedHost } from "./host-admission";
import { mutationOperationReceipt } from "./sdk-mutations";
import { listHosts } from "./services/hosts";
import {
  addPoolMember,
  createPool,
  deletePool,
  getPool,
  listPoolMembers,
  listPools,
  removePoolMember,
  updatePool,
  updatePoolMember,
} from "./services/pools";
import { listSandboxViews } from "./services/sandbox-views";
import { createSandbox, getSandbox, listSandboxes } from "./services/sandboxes";
import { createSdkKey } from "./services/sdk-keys";
import { allOwnedPoolKey, mintPoolKey, poolFixture, poolKey } from "./testing/pool-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());

it("pool/member/pool-grant composite FKs reject cross-owner parents", async () => {
  const a = await poolFixture(db);
  const b = await poolFixture(db);
  const key = await poolKey(db, a);
  for (const data of [
    { userId: a.id, hostOwnerId: a.id, poolId: b.pool.id, sandboxHostId: a.host.id },
    { userId: a.id, hostOwnerId: a.id, poolId: a.pool.id, sandboxHostId: b.host.id },
  ])
    await expect(db.inspect.sandboxPoolMember.create({ data })).rejects.toMatchObject({
      code: "P2003",
    });
  await expect(
    db.inspect.sdkKeyPoolAllowlist.create({
      data: {
        poolOwnerId: a.id,
        userId: a.id,
        sdkKeyId: key.key.id,
        poolId: b.pool.id,
      },
    }),
  ).rejects.toMatchObject({ code: "P2003" });
  const otherKey = await poolKey(db, b);
  await expect(
    db.inspect.sdkKeyPoolAllowlist.create({
      data: {
        poolOwnerId: a.id,
        userId: a.id,
        sdkKeyId: otherKey.key.id,
        poolId: a.pool.id,
      },
    }),
  ).rejects.toMatchObject({ code: "P2003" });
});
it("pool_revision_absence_equivalence hides ungranted, foreign, absent and deleted pools before placement", async () => {
  const f = await poolFixture(db);
  const foreign = await poolFixture(db);
  const hidden = await createPool(f.owner, { slug: "hidden", label: "Hidden" });
  const deleted = await createPool(f.owner, { slug: "deleted", label: "Deleted" });
  const key = await poolKey(db, f, [f.pool.id, deleted.id]);
  await deletePool(f.owner, { id: deleted.id });
  for (const id of [hidden.id, foreign.pool.id, "absent", deleted.id]) {
    for (const read of [
      () => getPool(key.principal, { id }),
      () => listPoolMembers(key.principal, { poolId: id, limit: 1 }),
      () => createSandbox(key.principal, { ...f.input, poolId: id, idempotencyKey: randomUUID() }),
    ])
      await expect(read()).rejects.toMatchObject({
        code: "NOT_FOUND",
        message: "Pool not found.",
        data: { code: "sandbox.pool_not_found" },
      });
  }
  expect((await listPools(key.principal, { limit: 1 })).items.map((p) => p.id)).toEqual([
    f.pool.id,
  ]);
  expect((await createSandbox(key.principal, f.input)).originPoolId).toBe(f.pool.id);
});
it("restricted_placement_has_no_hidden_host_oracle in every refusal category", async () => {
  const f = await poolFixture(db);
  const key = await poolKey(db, f, [f.pool.id], [f.host.id]);
  // Hidden member varies across compatible, full, unavailable and incompatible.
  for (const category of ["empty", "disabled", "incompatible", "unavailable", "full"] as const) {
    await db.inspect.sandboxPoolMember.updateMany({
      where: { sandboxHostId: f.host.id },
      data: {
        enabled: category !== "disabled",
        removedAt: category === "empty" ? new Date() : null,
      },
    });
    await db.inspect.sandboxTemplateAvailability.updateMany({
      where: { hostId: f.host.id },
      data: {
        localFingerprint: category === "incompatible" ? "wrong" : f.revision.incusFingerprint,
      },
    });
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: {
        draining: category === "unavailable",
        daemonMemoryBudgetMiB: 65536,
        memoryReservedMiB: category === "full" ? 65536 : 0,
      },
    });
    const errors: unknown[] = [];
    for (const hidden of [
      { status: "CONNECTED" as const, liveCount: 0, draining: false },
      { status: "CONNECTED" as const, liveCount: 4, draining: false },
      { status: "DISCONNECTED" as const, liveCount: 0, draining: true },
    ]) {
      await db.inspect.sandboxHost.update({ where: { id: f.other.id }, data: hidden });
      try {
        await createSandbox(key.principal, { ...f.input, idempotencyKey: randomUUID() });
        throw new Error("Expected refusal");
      } catch (error) {
        const e = error as { code: string; message: string; data?: unknown };
        errors.push({ code: e.code, message: e.message, data: e.data });
      }
    }
    expect(errors[1]).toEqual(errors[0]);
    expect(errors[2]).toEqual(errors[0]);
    expect(errors[0]).toMatchObject(
      category === "empty"
        ? { code: "FORBIDDEN" }
        : {
            data: {
              code:
                // A wrong image identity is "template not on any host" (§3 stage 2b).
                category === "incompatible"
                  ? "sandbox.template_unavailable"
                  : category === "unavailable" || category === "disabled"
                    ? "sandbox.pool_unavailable"
                    : "sandbox.pool_full",
            },
          },
    );
  }
});
it.each(["host", "revision", "pool"] as const)(
  "stored_creation_key_matrix retains history, cleanup and the CREATE dispatch after future %s grant removal; use needs current custody",
  async (removed) => {
    const f = await poolFixture(db);
    const key = await poolKey(db, f);
    const sandbox = await createSandbox(key.principal, f.input);
    const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: sandbox.id },
    });
    if (removed === "pool")
      await db.inspect.sdkKeyPoolAllowlist.deleteMany({ where: { sdkKeyId: key.key.id } });
    else if (removed === "revision")
      await db.inspect.sdkKeyRevisionAllowlist.deleteMany({ where: { sdkKeyId: key.key.id } });
    else await db.inspect.sdkKeyHostAllowlist.deleteMany({ where: { sdkKeyId: key.key.id } });
    // An allowlist key cannot hold credentials:use without an allowlisted
    // login (see poolKey), so the live credential attach/free actions are
    // out of this key's reach regardless of grants.
    const actions = SERVICE_ACTIONS.filter(
      (action) =>
        SERVICE_ACTION_REQUIREMENTS[action].requiresSandbox &&
        !SERVICE_ACTION_REQUIREMENTS[action].scopes.includes("credentials:use"),
    );
    // History reads and cleanup keep the creating
    // key's shortcut; use needs the current host (host leg) and the current
    // pool (pool leg); the revision grant is not custody.
    for (const action of [...actions, "operations.getReceipt", "sandboxes.create"] as const) {
      const check = authorizeServiceAction(key.principal, action, { operationId: operation.id });
      if (removed !== "revision" && SERVICE_ACTION_CUSTODY[action] === "custody")
        await expect(check, action).rejects.toMatchObject({ code: "FORBIDDEN" });
      else await expect(check, action).resolves.toMatchObject({ originPoolId: f.pool.id });
    }
    expect((await getSandbox(key.principal, { id: sandbox.id })).id).toBe(sandbox.id);
    await expect(
      mutationOperationReceipt(key.principal, f.input.idempotencyKey, "sandboxes.create"),
    ).resolves.toHaveProperty("operationId");
    expect(
      (await listSandboxes(key.principal, { status: "all", limit: 1 })).items.map((row) => row.id),
    ).toEqual([sandbox.id]);
    const context = {
      sandboxId: sandbox.id,
      sandboxHostId: sandbox.sandboxHostId,
      templateRevisionId: f.revision.id,
      originPoolId: f.pool.id,
    };
    const dispatch = (operationKind = "CREATE_SANDBOX") =>
      checkAcceptedDispatchAuthority(
        {
          ownerId: f.id,
          principal: { kind: "sdkKey", keyId: key.key.id },
          context,
          operationKind,
        },
        db.prisma,
      );
    expect(await dispatch()).toBe("active");
    // Queued use (an exec) is refused at dispatch revalidation (V1).
    expect(await dispatch("RUN_COMMAND")).toBe(removed === "revision" ? "active" : "inactive");
    if (removed === "pool")
      await db.inspect.sdkKeyPoolAllowlist.create({
        data: {
          poolOwnerId: f.id,
          userId: f.id,
          sdkKeyId: key.key.id,
          poolId: f.pool.id,
        },
      });
    else if (removed === "revision")
      await db.inspect.sdkKeyRevisionAllowlist.create({
        data: { userId: f.id, sdkKeyId: key.key.id, templateRevisionId: f.revision.id },
      });
    else
      for (const host of f.hosts)
        await db.inspect.sdkKeyHostAllowlist.create({
          data: { sdkKeyId: key.key.id, sandboxHostId: host.id },
        });
    for (const action of [...actions, "operations.getReceipt", "sandboxes.create"] as const) {
      await expect(
        authorizeServiceAction(key.principal, action, { operationId: operation.id }),
      ).resolves.toMatchObject({ originPoolId: f.pool.id });
    }
    expect(
      (await listSandboxes(key.principal, { status: "all", limit: 1 })).items.map((s) => s.id),
    ).toEqual([sandbox.id]);
    expect(await dispatch()).toBe("active");
    // Soft deletion/removal retains authority; scheduling state is not revocation.
    await deletePool(f.owner, { id: f.pool.id });
    expect((await getSandbox(key.principal, { id: sandbox.id })).id).toBe(sandbox.id);
    expect(await dispatch()).toBe("active");
    const direct = await createSandbox(key.principal, {
      template: "base",
      sandboxHostId: f.host.id,
      idempotencyKey: randomUUID(),
    });
    await db.inspect.sdkKeyPoolAllowlist.deleteMany({ where: { sdkKeyId: key.key.id } });
    expect((await getSandbox(key.principal, { id: direct.id })).id).toBe(direct.id);
  },
);

it("stored_resource_grant_matrix ALL_OWNED pooled and direct lists equal central gates, including retained history", async () => {
  const f = await poolFixture(db);
  const all = await allOwnedPoolKey(f);
  const allow = await poolKey(db, f);
  const pooled = await createSandbox(all.principal, f.input);
  const direct = await createSandbox(all.principal, {
    template: "base",
    sandboxHostId: f.host.id,
    idempotencyKey: randomUUID(),
  });
  const expected = [pooled.id, direct.id].sort();
  await expect(getSandbox(allow.principal, { id: pooled.id })).rejects.toMatchObject({
    code: "FORBIDDEN",
  });
  expect((await listSandboxes(allow.principal, { status: "all", limit: 10 })).items).toEqual([]);
  const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: pooled.id },
  });
  expect((await listPools(all.principal, { limit: 10 })).items.map((row) => row.id)).toEqual([
    f.pool.id,
  ]);
  expect(
    (await listPoolMembers(all.principal, { poolId: f.pool.id, limit: 10 })).items,
  ).toHaveLength(2);
  expect((await getPool(all.principal, { id: f.pool.id })).memberCount).toBe(2);
  for (const retained of [false, true]) {
    if (retained) await deletePool(f.owner, { id: f.pool.id });
    for (const principal of [f.owner, all.principal]) {
      const gateIds: string[] = [];
      for (const row of [pooled, direct])
        gateIds.push((await getSandbox(principal, { id: row.id })).id);
      const ids: string[] = [];
      let cursor: string | undefined;
      do {
        const page = await listSandboxes(principal, { status: "all", limit: 1, cursor });
        ids.push(...page.items.map((row) => row.id));
        cursor = page.nextCursor ?? undefined;
      } while (cursor);
      expect(ids.sort()).toEqual(gateIds.sort());
      expect(ids.sort()).toEqual(expected);
      for (const action of SERVICE_ACTIONS.filter(
        (action) => SERVICE_ACTION_REQUIREMENTS[action].requiresSandbox,
      )) {
        await expect(
          authorizeServiceAction(principal, action, { operationId: operation.id }),
        ).resolves.toBeDefined();
      }
      if (principal === all.principal)
        await expect(
          mutationOperationReceipt(principal, f.input.idempotencyKey, "sandboxes.create"),
        ).resolves.toBeTruthy();
      expect(
        await checkAcceptedDispatchAuthority(
          {
            ownerId: f.id,
            principal:
              principal.kind === "session"
                ? { kind: "session" }
                : { kind: "sdkKey", keyId: principal.keyId },
            context: {
              sandboxId: pooled.id,
              sandboxHostId: pooled.sandboxHostId,
              templateRevisionId: f.revision.id,
              originPoolId: f.pool.id,
            },
          },
          db.prisma,
        ),
      ).toBe("active");
    }
    expect(
      (await listSandboxViews(f.owner, { status: "all", limit: 10 })).items
        .map((row) => row.id)
        .sort(),
    ).toEqual(expected);
  }
  // All six resource filter branches must preserve ALL_OWNED discovery.
  expect((await listPools(all.principal, { limit: 10 })).items).toEqual([]);
});

it("paged pool/member discovery filters grants before cursor and take; counts match", async () => {
  const f = await poolFixture(db);
  const key = await poolKey(db, f, [f.pool.id], [f.host.id]);
  const page = await listPoolMembers(key.principal, { poolId: f.pool.id, limit: 1 });
  expect(page.items.map((m) => m.sandboxHostId)).toEqual([f.host.id]);
  expect(page.nextCursor).toBeNull();
  expect((await getPool(key.principal, { id: f.pool.id })).memberCount).toBe(1);
  const all = await listPoolMembers(f.owner, { poolId: f.pool.id, limit: 1 });
  expect(all.items).toHaveLength(1);
  expect(all.nextCursor).not.toBeNull();
  const next = await listPoolMembers(f.owner, {
    poolId: f.pool.id,
    limit: 1,
    cursor: all.nextCursor!,
  });
  expect(next.items).toHaveLength(1);
  expect(next.items[0]!.id).not.toBe(all.items[0]!.id);
});
it.each(["add", "reactivate", "update", "remove"] as const)(
  "member %s blocks on exactly one H before acquiring the member",
  async (kind) => {
    const f = await poolFixture(db);
    const input = { poolId: f.pool.id, sandboxHostId: f.host.id };
    if (kind === "add") await db.inspect.sandboxPoolMember.deleteMany({ where: input });
    if (kind === "reactivate") await removePoolMember(f.owner, input);
    const gate = db.pauseAt("holder", { after: /SELECT id FROM sandbox_host .*FOR UPDATE/ });
    const holder = db.run("holder", () =>
      db.prisma.$transaction(
        (tx) => tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.host.id} FOR UPDATE`,
      ),
    );
    await gate.waitReached();
    const writer = db.run("member", () =>
      kind === "remove"
        ? removePoolMember(f.owner, input)
        : kind === "update"
          ? updatePoolMember(f.owner, { ...input, enabled: false })
          : addPoolMember(f.owner, { ...input, enabled: true }),
    );
    const result = writer.then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    );
    const blocked = await db.waitUntilBlocked("member", { by: "holder" });
    expect(blocked.query).toContain("sandbox_host");
    await db.inspect.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_pool_member WHERE "poolId" = ${f.pool.id} AND "sandboxHostId" = ${f.host.id} FOR UPDATE NOWAIT`;
      await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.other.id} FOR UPDATE NOWAIT`;
    });
    gate.release();
    await holder;
    expect(await result).toHaveProperty("value");
  },
);
it("re-add reactivates same member identity; deleted slugs remain reserved", async () => {
  const f = await poolFixture(db);
  const input = { poolId: f.pool.id, sandboxHostId: f.host.id };
  const before = await db.inspect.sandboxPoolMember.findFirstOrThrow({ where: input });
  await removePoolMember(f.owner, input);
  const after = await addPoolMember(f.owner, { ...input, enabled: true });
  expect(after.id).toBe(before.id);
  expect(after.removedAt).toBeNull();
  await deletePool(f.owner, { id: f.pool.id });
  await expect(createPool(f.owner, { slug: f.pool.slug, label: "Reused" })).rejects.toMatchObject({
    code: "CONFLICT",
  });
});
it.each(["delete", "rename"] as const)(
  "pool %s neither takes H nor enumerates or locks members",
  async (kind) => {
    const f = await poolFixture(db);
    const gate = db.pauseAt("holder", { after: /SELECT id FROM sandbox_pool_member/ });
    const holder = db.run("holder", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.host.id} FOR UPDATE`;
        await tx.$queryRaw`SELECT id FROM sandbox_pool_member WHERE "poolId" = ${f.pool.id} FOR UPDATE`;
      }),
    );
    await gate.waitReached();
    try {
      const change =
        kind === "delete"
          ? deletePool(f.owner, { id: f.pool.id })
          : updatePool(f.owner, { id: f.pool.id, slug: "renamed", label: "Renamed" });
      await expect(change).resolves.toMatchObject({ id: f.pool.id });
    } finally {
      gate.release();
      await holder;
    }
  },
);
it.each(
  (["member-first", "finalizer-first"] as const).flatMap((order) =>
    (["add", "reactivate", "update", "remove"] as const).map((kind) => [order, kind] as const),
  ),
)(
  "member/finalizer %s/%s serializes on H without earlier parent acquisition",
  async (order, kind) => {
    const f = await poolFixture(db);
    const input = { poolId: f.pool.id, sandboxHostId: f.host.id };
    if (kind === "add") await db.inspect.sandboxPoolMember.deleteMany({ where: input });
    if (kind === "reactivate") await removePoolMember(f.owner, input);
    const change = () =>
      kind === "remove"
        ? removePoolMember(f.owner, input)
        : kind === "update"
          ? updatePoolMember(f.owner, { ...input, enabled: false })
          : addPoolMember(f.owner, { ...input, enabled: true });
    if (order === "member-first") {
      const gate = db.pauseAt("member", {
        after:
          kind === "remove"
            ? "sandboxPoolMember.updateMany"
            : kind === "update"
              ? "sandboxPoolMember.update"
              : "sandboxPoolMember.upsert",
      });
      const member = db.run("member", change);
      await gate.waitReached();
      const finalizer = db.run("finalizer", () =>
        db.prisma.$transaction(async (tx) => {
          await lockAdmissionHost(tx, f.host.id, f.id);
          await tx.sandboxHost.update({
            where: { id: f.host.id },
            data: { deletionRequestedAt: new Date() },
          });
          return tryFinalizeTombstonedHost(tx, f.host.id, f.id);
        }),
      );
      const result = finalizer.then(
        (value) => ({ value }),
        (error: unknown) => ({ error }),
      );
      expect((await db.waitUntilBlocked("finalizer", { by: "member" })).query).toContain(
        "sandbox_host",
      );
      gate.release();
      await member;
      expect(await result).toEqual({ value: true });
    } else {
      const gate = db.pauseAt("finalizer", { after: /SELECT id FROM sandbox_host .*FOR UPDATE/ });
      const finalizer = db.run("finalizer", () =>
        db.prisma.$transaction(async (tx) => {
          await lockAdmissionHost(tx, f.host.id, f.id);
          await tx.sandboxHost.update({
            where: { id: f.host.id },
            data: { deletionRequestedAt: new Date() },
          });
          return tryFinalizeTombstonedHost(tx, f.host.id, f.id);
        }),
      );
      await gate.waitReached();
      const member = db.run("member", change).then(
        () => null,
        (error: unknown) => error,
      );
      expect((await db.waitUntilBlocked("member", { by: "finalizer" })).query).toContain(
        "sandbox_host",
      );
      gate.release();
      expect(await finalizer).toBe(true);
      expect(await member).toMatchObject({
        code: "NOT_FOUND",
        message: "Host not found.",
        data: { code: "sandbox.host_not_found" },
      });
    }
    expect(await db.inspect.sandboxPoolMember.count({ where: { sandboxHostId: f.host.id } })).toBe(
      0,
    );
    expect(
      (await db.inspect.sandboxPool.findUniqueOrThrow({ where: { id: f.pool.id } })).deletedAt,
    ).toBeNull();
  },
);
it.each(
  (["writer-first", "account-first"] as const).flatMap((order) =>
    (["create-pool", "delete-pool", "add", "reactivate", "remove"] as const).map(
      (kind) => [order, kind] as const,
    ),
  ),
)("pool/member writes and account deletion %s/%s obey owner admission", async (order, kind) => {
  const f = await poolFixture(db);
  const input = { poolId: f.pool.id, sandboxHostId: f.host.id };
  if (kind === "add") await db.inspect.sandboxPoolMember.deleteMany({ where: input });
  if (kind === "reactivate") await removePoolMember(f.owner, input);
  const change = () =>
    kind === "create-pool"
      ? createPool(f.owner, { slug: "new", label: "New" })
      : kind === "delete-pool"
        ? deletePool(f.owner, { id: f.pool.id })
        : kind === "remove"
          ? removePoolMember(f.owner, input)
          : addPoolMember(f.owner, { ...input, enabled: true });
  if (order === "writer-first") {
    const gate = db.pauseAt("writer", {
      after:
        kind === "create-pool"
          ? "sandboxPool.create"
          : kind === "delete-pool"
            ? "sandboxPool.update"
            : kind === "remove"
              ? "sandboxPoolMember.updateMany"
              : "sandboxPoolMember.upsert",
    });
    const writer = db.run("writer", change);
    await gate.waitReached();
    const deletion = db
      .run("account", () => db.prisma.$transaction((tx) => deleteAccountInTransaction(tx, f.id)))
      .then(
        () => null,
        (error: unknown) => error,
      );
    expect((await db.waitUntilBlocked("account", { by: "writer" })).query).toContain("user");
    gate.release();
    await writer;
    expect(await deletion).toBeInstanceOf(Error); // live hosts remain blockers
  } else {
    const gate = db.pauseAt("account", { after: /SELECT .*FROM "user".*FOR UPDATE/ });
    const deletion = db
      .run("account", () => db.prisma.$transaction((tx) => deleteAccountInTransaction(tx, f.id)))
      .then(
        () => null,
        (error: unknown) => error,
      );
    await gate.waitReached();
    const writer = db.run("writer", change);
    const result = writer.then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    );
    expect((await db.waitUntilBlocked("writer", { by: "account" })).query).toContain("user");
    await db.inspect.$transaction(
      (tx) => tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.host.id} FOR UPDATE NOWAIT`,
    );
    gate.release();
    expect(await deletion).toBeInstanceOf(Error);
    expect(await result).toHaveProperty("value");
  }
});

it.each(["pool-first", "finalizer-first"] as const)(
  "pool deletion and actual host finalization %s never require a member scan from the pool writer",
  async (order) => {
    const f = await poolFixture(db);
    const finalize = () =>
      db.prisma.$transaction(async (tx) => {
        await lockAdmissionHost(tx, f.host.id, f.id);
        await tx.sandboxHost.update({
          where: { id: f.host.id },
          data: { deletionRequestedAt: new Date() },
        });
        return tryFinalizeTombstonedHost(tx, f.host.id, f.id);
      });
    if (order === "pool-first") {
      const gate = db.pauseAt("pool", { after: "sandboxPool.update" });
      const deleting = db.run("pool", () => deletePool(f.owner, { id: f.pool.id }));
      await gate.waitReached();
      try {
        expect(await db.run("finalizer", finalize)).toBe(true);
      } finally {
        gate.release();
        await deleting;
      }
    } else {
      const gate = db.pauseAt("finalizer", { after: /SELECT id FROM sandbox_host .*FOR UPDATE/ });
      const finalizing = db.run("finalizer", finalize);
      await gate.waitReached();
      try {
        await deletePool(f.owner, { id: f.pool.id });
      } finally {
        gate.release();
        expect(await finalizing).toBe(true);
      }
    }
    expect(
      (await db.inspect.sandboxPool.findUniqueOrThrow({ where: { id: f.pool.id } })).deletedAt,
    ).not.toBeNull();
    expect(await db.inspect.sandboxPoolMember.count({ where: { sandboxHostId: f.host.id } })).toBe(
      0,
    );
  },
);
it.each(["writer-first", "account-first"] as const)(
  "completed account finalization %s clears pool/grant history and excludes subsequent pool creation",
  async (order) => {
    const f = await poolFixture(db);
    await poolKey(db, f);
    const { deleteHost } = await import("./services/hosts");
    for (const host of f.hosts) await deleteHost(f.owner, { id: host.id });
    if (order === "writer-first") {
      const gate = db.pauseAt("writer", { after: "sandboxPool.create" });
      const writer = db.run("writer", () => createPool(f.owner, { slug: "new", label: "New" }));
      await gate.waitReached();
      const deletion = db.run("account", () =>
        db.prisma.$transaction((tx) => deleteAccountInTransaction(tx, f.id)),
      );
      const result = deletion.then(
        (value) => ({ value }),
        (error: unknown) => ({ error }),
      );
      expect((await db.waitUntilBlocked("account", { by: "writer" })).query).toContain("user");
      gate.release();
      await writer;
      expect(await result).toEqual({ value: true });
    } else {
      const gate = db.pauseAt("account", { after: /SELECT id FROM "user".*FOR UPDATE/ });
      const deletion = db.run("account", () =>
        db.prisma.$transaction((tx) => deleteAccountInTransaction(tx, f.id)),
      );
      await gate.waitReached();
      const writer = db
        .run("writer", () => createPool(f.owner, { slug: "new", label: "New" }))
        .then(
          () => null,
          (error: unknown) => error,
        );
      expect((await db.waitUntilBlocked("writer", { by: "account" })).query).toContain("user");
      gate.release();
      expect(await deletion).toBe(true);
      expect(await writer).toMatchObject({ code: "CONFLICT" });
    }
    expect(await db.inspect.sandboxPool.count({ where: { userId: f.id } })).toBe(0);
    expect(await db.inspect.sandboxPoolMember.count({ where: { userId: f.id } })).toBe(0);
    expect(await db.inspect.sdkKeyPoolAllowlist.count({ where: { userId: f.id } })).toBe(0);
  },
);

it("member foreign and absent hosts are identical 404s while foreign H remains locked", async () => {
  const f = await poolFixture(db);
  const foreign = await poolFixture(db);
  const held = db.pauseAt("foreign", { before: "$transaction.commit" });
  const holder = db.run("foreign", () =>
    db.prisma.$transaction(
      (tx) => tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${foreign.host.id} FOR UPDATE`,
    ),
  );
  await held.waitReached();
  const errors: unknown[] = [];
  try {
    for (const sandboxHostId of [foreign.host.id, "absent"]) {
      const change = db
        .run("member-unowned", () =>
          addPoolMember(f.owner, { poolId: f.pool.id, sandboxHostId, enabled: true }),
        )
        .then(
          () => null,
          (error: unknown) => error,
        );
      const outcome = await Promise.race([
        change,
        db
          .waitUntilBlocked("member-unowned", { by: "foreign" })
          .then((lock) => ({ blockedOn: lock.query })),
      ]);
      expect(outcome).toMatchObject({
        code: "NOT_FOUND",
        status: 404,
        data: { code: "sandbox.host_not_found" },
        message: "Host not found.",
      });
      const e = outcome as { code: string; data: unknown; message: string };
      errors.push({ code: e.code, data: e.data, message: e.message });
    }
    expect(errors[0]).toEqual(errors[1]);
  } finally {
    held.release();
    await holder;
  }
});

it("pool grant mint waits for exclusive G before bounded sorted H and fresh K/grants", async () => {
  const f = await poolFixture(db);
  const parent = db.pauseAt("pool-parent", { after: /SELECT id FROM sandbox_pool / });
  const holder = db.run("pool-parent", () =>
    db.prisma.$transaction(
      (tx) => tx.$queryRaw`SELECT id FROM sandbox_pool WHERE id = ${f.pool.id} FOR UPDATE`,
    ),
  );
  await parent.waitReached();
  const minting = db.run("mint", () => poolKey(db, f));
  const result = minting.then(
    (value) => ({ value }),
    (error: unknown) => ({ error }),
  );
  let hostProbe: Promise<unknown> | undefined;
  try {
    const blocked = await db.waitUntilBlocked("mint", { by: "pool-parent" });
    expect(blocked.query).toMatch(/sandbox_pool.*FOR UPDATE/);
    const hostId = f.hosts.map((h) => h.id).sort()[0]!;
    hostProbe = db.run("host-probe", () =>
      db.prisma.$transaction(
        (tx) => tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${hostId} FOR UPDATE`,
      ),
    );
    // G is blocked, so mint has not acquired H; an independent host writer succeeds.
    await hostProbe;
    const pid = db.backendPid("mint");
    const insertedKey = await db.inspect.$queryRaw<{ acquired: boolean }[]>`SELECT EXISTS (
      SELECT 1 FROM pg_locks WHERE pid = ${pid} AND relation = 'sdk_key'::regclass AND mode = 'RowExclusiveLock'
    ) AS acquired`;
    expect(insertedKey).toEqual([{ acquired: false }]);
  } finally {
    parent.release();
    await holder;
    await hostProbe;
  }
  const minted = await result;
  expect(minted).toHaveProperty("value");
});

it.each(["mint-first", "pool-delete-first"] as const)(
  "pool grant mint versus soft deletion %s serializes through owner placement",
  async (order) => {
    const f = await poolFixture(db);
    if (order === "mint-first") {
      const gate = db.pauseAt("mint", { after: "sdkKey.create" });
      const mint = db.run("mint", () => mintPoolKey(f));
      const minted = mint.then(
        (value) => ({ value }),
        (error: unknown) => ({ error }),
      );
      await gate.waitReached();
      const deletion = db.run("delete", () => deletePool(f.owner, { id: f.pool.id }));
      const deleted = deletion.then(
        (value) => ({ value }),
        (error: unknown) => ({ error }),
      );
      expect((await db.waitUntilBlocked("delete", { by: "mint" })).query).toContain(
        "pg_advisory_xact_lock",
      );
      gate.release();
      expect(await minted).toHaveProperty("value");
      expect(await deleted).toHaveProperty("value");
      expect(await db.inspect.sdkKeyPoolAllowlist.count({ where: { poolId: f.pool.id } })).toBe(0);
    } else {
      const gate = db.pauseAt("delete", { after: "sandboxPool.update" });
      const deletion = db.run("delete", () => deletePool(f.owner, { id: f.pool.id }));
      await gate.waitReached();
      const mint = db.run("mint", () => poolKey(db, f));
      const result = mint.then(
        (value) => ({ value }),
        (error: unknown) => ({ error }),
      );
      expect((await db.waitUntilBlocked("mint", { by: "delete" })).query).toContain(
        "pg_advisory_xact_lock",
      );
      gate.release();
      await deletion;
      expect(await result).toMatchObject({
        error: { code: "NOT_FOUND", data: { code: "sandbox.pool_not_found" } },
      });
      expect(await db.inspect.sdkKey.count({ where: { userId: f.id } })).toBe(0);
    }
  },
);

it.each(["session", "all-owned", "allowlist"] as const)(
  "all disabled visible members return pool_unavailable for %s even without compatible images",
  async (mode) => {
    const f = await poolFixture(db);
    const principal =
      mode === "session"
        ? f.owner
        : mode === "all-owned"
          ? (await allOwnedPoolKey(f)).principal
          : (await poolKey(db, f)).principal;
    await db.inspect.sandboxPoolMember.updateMany({
      where: { userId: f.id },
      data: { enabled: false },
    });
    await db.inspect.sandboxTemplateAvailability.deleteMany({ where: { userId: f.id } });
    // Configuration, not occupancy: no wait can clear it.
    await expect(createSandbox(principal, f.input)).rejects.toMatchObject({
      code: "CONFLICT",
      data: { code: "sandbox.pool_unavailable", retryable: false },
    });
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
  },
);
it("SDK-key mint uses the identical pool_not_found shape for absent, foreign and deleted pools", async () => {
  const f = await poolFixture(db);
  const foreign = await poolFixture(db);
  await deletePool(f.owner, { id: f.pool.id });
  for (const poolId of ["absent", foreign.pool.id, f.pool.id])
    await expect(
      createSdkKey(f.owner, {
        name: "missing-pool",
        resourceMode: "ALLOWLIST",
        hostIds: f.hosts.map((host) => host.id),
        templateRevisionIds: [f.revision.id],
        poolIds: [poolId],
        scopes: ["sandboxes:read"],
      }),
    ).rejects.toMatchObject({
      code: "NOT_FOUND",
      message: "Pool not found.",
      data: { code: "sandbox.pool_not_found" },
    });
});

it.each(["reconnect", "tombstone"] as const)(
  "member disable retains the epoch fence after %s, including pending host deletion",
  async (change) => {
    const f = await poolFixture(db);
    const input = { poolId: f.pool.id, sandboxHostId: f.host.id, enabled: false };
    const gate = db.pauseAt("host-change", { after: /SELECT id FROM sandbox_host .*FOR UPDATE/ });
    const changing = db.run("host-change", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.host.id} FOR UPDATE`;
        // Reproduce hello's H-only epoch bump, without the placement advisory.
        await tx.sandboxHost.update({
          where: { id: f.host.id },
          data: {
            connectionEpoch: { increment: 1 },
            ...(change === "tombstone" ? { deletionRequestedAt: new Date() } : {}),
          },
        });
      }),
    );
    await gate.waitReached();
    const writing = db
      .run("member", () => updatePoolMember(f.owner, input))
      .then(
        (value) => ({ value }),
        (error: unknown) => ({ error }),
      );
    try {
      const blocked = await db.waitUntilBlocked("member", { by: "host-change" });
      expect(blocked.query).toContain('"connectionEpoch"');
    } finally {
      gate.release();
    }
    await changing;
    expect(await writing).toMatchObject({
      error: { code: "CONFLICT", data: { code: "sandbox.state_conflict" } },
    });
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
    ).toMatchObject({
      connectionEpoch: f.host.connectionEpoch + 1,
      ...(change === "reconnect" ? { deletionRequestedAt: null } : {}),
    });
    expect(
      await db.inspect.sandboxPoolMember.findUniqueOrThrow({
        where: {
          poolId_sandboxHostId: { poolId: f.pool.id, sandboxHostId: f.host.id },
        },
      }),
    ).toMatchObject({ enabled: true, removedAt: null });
  },
);

it("pool host picker excludes existing enabled and disabled members before paging and keeps owner visibility", async () => {
  const f = await poolFixture(db);
  const foreign = await poolFixture(db);
  await updatePoolMember(f.owner, { poolId: f.pool.id, sandboxHostId: f.other.id, enabled: false });
  expect((await listHosts(f.owner, { excludePoolId: f.pool.id, limit: 1 })).items).toEqual([]);
  await removePoolMember(f.owner, { poolId: f.pool.id, sandboxHostId: f.other.id });
  const page = await listHosts(f.owner, { excludePoolId: f.pool.id, limit: 1 });
  expect(page.items.map((host) => host.id)).toEqual([f.other.id]);
  expect(page.nextCursor).toBeNull();
  for (const excludePoolId of [foreign.pool.id, "missing-pool"])
    await expect(listHosts(f.owner, { excludePoolId, limit: 1 })).rejects.toMatchObject({
      code: "NOT_FOUND",
      data: { code: "sandbox.pool_not_found" },
    });
});

it.each(["remove", "disable"] as const)(
  "r1 member %s works on a tombstoned host while preserving its epoch fence",
  async (action) => {
    const f = await poolFixture(db);
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { deletionRequestedAt: new Date() },
    });
    const input = { poolId: f.pool.id, sandboxHostId: f.host.id };
    if (action === "remove") await removePoolMember(f.owner, input);
    else await updatePoolMember(f.owner, { ...input, enabled: false });
    expect(
      await db.inspect.sandboxPoolMember.findUnique({ where: { poolId_sandboxHostId: input } }),
    ).toMatchObject({
      enabled: false,
      removedAt: action === "remove" ? expect.any(Date) : null,
    });
    expect(await db.inspect.sandboxHost.findUnique({ where: { id: f.host.id } })).toMatchObject({
      connectionEpoch: f.host.connectionEpoch,
      deletionRequestedAt: expect.any(Date),
    });
  },
);
