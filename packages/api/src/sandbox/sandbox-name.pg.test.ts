vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "sandbox-name-fixture",
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: vi.fn(async () => {}),
  consumeSandboxWriteBudget: vi.fn(async () => {}),
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

/**
 * Sandbox names under real PostgreSQL (UI launch chunk B): every name write
 * of an owner serializes on `lockOwnerPlacement` (lock 31), so concurrent
 * creates and renames never store a duplicate and the loser gets the typed
 * `sandbox.name_taken`; the partial unique index is the backstop; both
 * production insert sites store a generated adjective-noun name; and only
 * the owner, through the shared gate, can rename.
 */
import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { authenticateSdkKeySecret, type ServicePrincipal } from "../lib/sdk-key-access";
import { consumeSandboxWriteBudget } from "./budgets";
import { runCapacityQueuePass } from "./capacity-queue";
import { leaseNow } from "./lease";
import { isSandboxNameViolation, sandboxNameRandom } from "./sandbox-names";
import { createSandbox, renameSandbox } from "./services/sandboxes";
import { createSdkKey, revokeSdkKey } from "./services/sdk-keys";
import { allOwnedPoolKey, mintPoolKey, poolFixture } from "./testing/pool-fixtures";
import { seedSandboxInstance } from "./testing/resource-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());
afterEach(() => vi.restoreAllMocks());

type Fixture = Awaited<ReturnType<typeof poolFixture>>;
const GENERATED = /^[a-z]+-[a-z]+(-[0-9a-z]{4})?$/;
const LOCK_31 = /pg_advisory_xact_lock\(hashtextextended\(\?, 31\)\)/;

async function storedName(id: string) {
  return (await db.inspect.sandbox.findUniqueOrThrow({ where: { id }, select: { name: true } }))
    .name;
}
/** A seeded sandbox row of `f`'s owner (no placement), overridable. */
function seed(f: Fixture, data: Record<string, unknown> = {}) {
  return seedSandboxInstance(db.inspect, {
    data: {
      userId: f.id,
      templateId: f.revision.templateId,
      templateRevisionId: f.revision.id,
      originHostId: f.host.id,
      state: "READY",
      ...data,
    },
  });
}
const settle = <T>(promise: Promise<T>) =>
  promise.then(
    (value) => ({ value, error: undefined }),
    (error: unknown) => ({ value: undefined, error }),
  );
async function key(principal: Promise<{ secret: string }>) {
  const authenticated = await authenticateSdkKeySecret((await principal).secret);
  if (!authenticated) throw new Error("Fixture SDK key inactive");
  return authenticated;
}

describe("concurrent name writes serialize on lock 31", () => {
  it("1: two generated creates (direct + pool, different keys) with the same candidates both succeed with different names", async () => {
    const f = await poolFixture(db);
    const pooled = await allOwnedPoolKey(f);
    // Every candidate of every round is index 0: both picks see one list.
    vi.spyOn(sandboxNameRandom, "int").mockReturnValue(0);
    const gate = db.pauseAt("direct", { after: LOCK_31 });
    const direct = settle(
      db.run("direct", () =>
        createSandbox(f.owner, {
          template: "base",
          sandboxHostId: f.host.id,
          idempotencyKey: randomUUID(),
        }),
      ),
    );
    await gate.waitReached();
    const pool = settle(
      db.run("pool", () => createSandbox(pooled.principal, { ...f.input, idempotencyKey: "p1" })),
    );
    // The pool create waits for the direct create's lock before any name pick.
    await db.waitUntilBlocked("pool", { by: "direct" });
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
    gate.release();
    const [a, b] = [await direct, await pool];
    expect(a.error).toBeUndefined();
    expect(b.error).toBeUndefined();
    const names = [a.value!.name, b.value!.name];
    expect(names[0]).toMatch(GENERATED);
    expect(names[1]).toMatch(GENERATED);
    expect(new Set(names).size).toBe(2);
    // The second pick saw the first's committed name and fell back to a suffix.
    expect(names[1]).toBe(`${names[0]}-0000`);
  });

  it("2: two creates with the same explicit name (different keys): exactly one wins, the other is name_taken", async () => {
    const f = await poolFixture(db);
    const pooled = await allOwnedPoolKey(f);
    const gate = db.pauseAt("first", { after: LOCK_31 });
    const first = settle(
      db.run("first", () =>
        createSandbox(f.owner, {
          template: "base",
          sandboxHostId: f.host.id,
          idempotencyKey: randomUUID(),
          name: "quiet-otter",
        }),
      ),
    );
    await gate.waitReached();
    const second = settle(
      db.run("second", () =>
        createSandbox(pooled.principal, { ...f.input, idempotencyKey: "p2", name: "quiet-otter" }),
      ),
    );
    await db.waitUntilBlocked("second", { by: "first" });
    gate.release();
    const [a, b] = [await first, await second];
    expect(a.value?.name).toBe("quiet-otter");
    expect(b.error).toMatchObject({ code: "CONFLICT", data: { code: "sandbox.name_taken" } });
    expect(await db.inspect.sandbox.count({ where: { userId: f.id, name: "quiet-otter" } })).toBe(
      1,
    );
  });

  it("3: a rename and a create racing for one name: the loser gets name_taken", async () => {
    const f = await poolFixture(db);
    const existing = await seed(f);
    const gate = db.pauseAt("rename", { after: LOCK_31 });
    const rename = settle(
      db.run("rename", () => renameSandbox(f.owner, { id: existing.id, name: "brisk-heron" })),
    );
    await gate.waitReached();
    const create = settle(
      db.run("create", () =>
        createSandbox(f.owner, {
          template: "base",
          sandboxHostId: f.host.id,
          idempotencyKey: randomUUID(),
          name: "brisk-heron",
        }),
      ),
    );
    await db.waitUntilBlocked("create", { by: "rename" });
    gate.release();
    expect((await rename).value?.name).toBe("brisk-heron");
    expect((await create).error).toMatchObject({ data: { code: "sandbox.name_taken" } });
    expect(await storedName(existing.id)).toBe("brisk-heron");
  });
});

describe("index and backstop", () => {
  it("4: a real P2002 on the name index maps; one on buildId or currentPlacementId does not", async () => {
    const f = await poolFixture(db);
    const one = await seed(f, { name: "same-name" });
    const caught = await db.inspect.sandbox
      .update({ where: { id: (await seed(f)).id }, data: { name: "same-name" } })
      .catch((error: unknown) => error);
    expect(caught).toMatchObject({ code: "P2002" });
    // The adapter identifies this partial unique constraint by its index name.
    expect(caught).toMatchObject({
      meta: {
        driverAdapterError: {
          cause: { constraint: { index: "sandbox_instance_owner_live_name" } },
        },
      },
    });
    expect(isSandboxNameViolation(caught)).toBe(true);
    const build = randomUUID();
    await seed(f, { purpose: "TEMPLATE_BUILD", buildId: build });
    const buildDup = await seed(f, { purpose: "TEMPLATE_BUILD", buildId: build }).catch(
      (error: unknown) => error,
    );
    expect(buildDup).toMatchObject({ code: "P2002" });
    expect(isSandboxNameViolation(buildDup)).toBe(false);
    const placed = await seedSandboxInstance(db.inspect, {
      data: {
        userId: f.id,
        templateId: f.revision.templateId,
        templateRevisionId: f.revision.id,
        sandboxHostId: f.host.id,
        hostOwnerId: f.id,
        originHostId: f.host.id,
        state: "READY",
      },
    });
    const placementDup = await db.inspect.sandbox
      .update({
        where: { id: one.id },
        data: { currentPlacementId: placed.currentPlacementId },
      })
      .catch((error: unknown) => error);
    expect(placementDup).toMatchObject({ code: "P2002" });
    expect(isSandboxNameViolation(placementDup)).toBe(false);
  });

  it("5: names are per owner, freed by DELETED, and a managed VM never blocks a workload", async () => {
    const a = await poolFixture(db);
    const b = await poolFixture(db);
    await seed(a, { name: "shared-name" });
    const other = await seed(b);
    await expect(
      renameSandbox(b.owner, { id: other.id, name: "shared-name" }),
    ).resolves.toMatchObject({ name: "shared-name" });
    const gone = await seed(a, { name: "freed-name", state: "DELETED" });
    const reuse = await seed(a);
    await expect(
      renameSandbox(a.owner, { id: reuse.id, name: "freed-name" }),
    ).resolves.toMatchObject({ name: "freed-name" });
    expect(await storedName(gone.id)).toBe("freed-name");
    await seed(a, { name: "login-vm", purpose: "CREDENTIAL_LOGIN" });
    const workload = await createSandbox(a.owner, {
      template: "base",
      sandboxHostId: a.host.id,
      idempotencyKey: randomUUID(),
      name: "login-vm",
    });
    expect(workload.name).toBe("login-vm");
  });
});

describe("insert sites", () => {
  it("6: a fresh create and a capacity-queued create both store an adjective-noun name; the queued one survives materialize", async () => {
    const f = await poolFixture(db);
    const fresh = await createSandbox(f.owner, {
      template: "base",
      sandboxHostId: f.host.id,
      idempotencyKey: randomUUID(),
    });
    expect(await storedName(fresh.id)).toMatch(GENERATED);
    expect(await storedName(fresh.id)).not.toMatch(/^sandbox-[0-9a-f]{12}$/);

    await db.inspect.sandboxHost.updateMany({
      where: { id: { in: [f.host.id, f.other.id] } },
      data: { memoryReservedMiB: 65536 },
    });
    const waiting = await createSandbox(f.owner, {
      ...f.input,
      idempotencyKey: randomUUID(),
      waitForCapacityMs: 3_600_000,
    });
    expect(waiting.state).toBe("WAITING_FOR_CAPACITY");
    const queuedName = await storedName(waiting.id);
    expect(queuedName).toMatch(GENERATED);
    expect(queuedName).not.toBe(await storedName(fresh.id));
    await db.inspect.sandboxHost.updateMany({
      where: { id: f.host.id },
      data: { memoryReservedMiB: 0 },
    });
    await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
    const placed = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: waiting.id } });
    expect(placed.state).toBe("REQUESTED");
    expect(placed.name).toBe(queuedName);
  });

  it("7: a same-key retry with a different explicit name is idempotency_conflict", async () => {
    const f = await poolFixture(db);
    const input = {
      template: "base",
      sandboxHostId: f.host.id,
      idempotencyKey: randomUUID(),
      name: "first-name",
    };
    const created = await createSandbox(f.owner, input);
    expect(created.name).toBe("first-name");
    await expect(createSandbox(f.owner, { ...input, name: "second-name" })).rejects.toMatchObject({
      data: { code: "sandbox.idempotency_conflict" },
    });
    // The same key and body replay the original sandbox.
    expect((await createSandbox(f.owner, input)).id).toBe(created.id);
  });
});

describe("8: only the owner renames, through the shared gate", () => {
  async function setup() {
    const owner = await poolFixture(db);
    const hostOwner = await poolFixture(db);
    const poolOwner = await poolFixture(db);
    const admin = await poolFixture(db);
    await db.inspect.user.update({ where: { id: admin.id }, data: { role: "admin" } });
    // The victim runs on the host owner's host, through the pool owner's pool.
    const victim = await seed(owner, {
      name: "victim-name",
      originHostId: hostOwner.host.id,
      originPoolId: poolOwner.pool.id,
    });
    return { owner, hostOwner, poolOwner, admin, victim };
  }

  it("the owner renames and the ordinary budget is charged once", async () => {
    const { owner, victim } = await setup();
    vi.mocked(consumeSandboxWriteBudget).mockClear();
    const renamed = await renameSandbox(owner.owner, { id: victim.id, name: "renamed" });
    expect(renamed).toMatchObject({ id: victim.id, name: "renamed" });
    expect(await storedName(victim.id)).toBe("renamed");
    expect(vi.mocked(consumeSandboxWriteBudget).mock.calls).toEqual([[owner.id, "ordinary"]]);
  });

  it("the pool host owner, the pool owner and an admin get not_found and change nothing", async () => {
    const { hostOwner, poolOwner, admin, victim } = await setup();
    for (const actor of [hostOwner, poolOwner, admin]) {
      const own = await seed(actor);
      await expect(
        renameSandbox(actor.owner, { id: own.id, name: `own-${actor.id.slice(0, 8)}` }),
      ).resolves.toMatchObject({ id: own.id });
      await expect(
        renameSandbox(actor.owner, { id: victim.id, name: "stolen" }),
      ).rejects.toMatchObject({ code: "NOT_FOUND" });
      expect(await storedName(victim.id)).toBe("victim-name");
    }
  });

  it("a restricted key without the victim's grants gets FORBIDDEN from the shared gate", async () => {
    const { owner, victim } = await setup();
    const restricted = await key(mintPoolKey(owner, [owner.pool.id], [owner.host.id]));
    // The key creates its own sandbox (its CREATE operation records the key).
    const own = await createSandbox(restricted, { ...owner.input, idempotencyKey: randomUUID() });
    await expect(renameSandbox(restricted, { id: own.id, name: "key-own" })).resolves.toMatchObject(
      { name: "key-own" },
    );
    await expect(
      renameSandbox(restricted, { id: victim.id, name: "stolen" }),
    ).rejects.toMatchObject({
      code: "FORBIDDEN",
      message: "Sandbox resource grants are required.",
    });
    expect(await storedName(victim.id)).toBe("victim-name");
  });

  it("a key without sandboxes:write, a build principal, a DELETED and a managed sandbox are refused", async () => {
    const { owner, victim } = await setup();
    const readOnly = await key(
      createSdkKey(owner.owner, {
        name: "read-only",
        resourceMode: "ALL_OWNED",
        hostIds: [],
        templateRevisionIds: [],
        poolIds: [],
        scopes: ["sandboxes:read"],
      }),
    );
    await expect(renameSandbox(readOnly, { id: victim.id, name: "stolen" })).rejects.toMatchObject({
      code: "FORBIDDEN",
    });
    const build = {
      kind: "build",
      ownerId: owner.id,
      buildId: randomUUID(),
      keyId: null,
    } as unknown as ServicePrincipal;
    await expect(renameSandbox(build, { id: victim.id, name: "stolen" })).rejects.toMatchObject({
      code: "FORBIDDEN",
    });
    expect(await storedName(victim.id)).toBe("victim-name");

    const deleted = await seed(owner, { state: "DELETED", name: "deleted-one" });
    await expect(
      renameSandbox(owner.owner, { id: deleted.id, name: "revived" }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(await storedName(deleted.id)).toBe("deleted-one");

    const managed = await seed(owner, { purpose: "CREDENTIAL_LOGIN", name: "login-one" });
    await expect(
      renameSandbox(owner.owner, { id: managed.id, name: "renamed" }),
    ).rejects.toMatchObject({ data: { code: "sandbox.managed" } });
    expect(await storedName(managed.id)).toBe("login-one");
  });

  it("an invalid name is name_invalid and a taken one name_taken", async () => {
    const { owner, victim } = await setup();
    await seed(owner, { name: "taken-name" });
    await expect(
      renameSandbox(owner.owner, { id: victim.id, name: "Bad_Name" }),
    ).rejects.toMatchObject({ data: { code: "sandbox.name_invalid" } });
    await expect(
      renameSandbox(owner.owner, { id: victim.id, name: "taken-name" }),
    ).rejects.toMatchObject({ data: { code: "sandbox.name_taken" } });
    // Renaming to its own current name is allowed (the sandbox itself is excluded).
    await expect(
      renameSandbox(owner.owner, { id: victim.id, name: "victim-name" }),
    ).resolves.toMatchObject({ name: "victim-name" });
  });
});

describe("9: a rename re-checks the SDK key inside its transaction", () => {
  const OWNER_LOCK = /SELECT id FROM "user" WHERE id = \? FOR SHARE/;
  async function keyed() {
    const f = await poolFixture(db);
    const minted = await allOwnedPoolKey(f);
    const victim = await seed(f, { name: "before-revoke" });
    return { f, minted, victim };
  }

  it("a key revoked while the rename waits is FORBIDDEN and the name never commits", async () => {
    const { f, minted, victim } = await keyed();
    // Paused after the owner lock: the key was authorized before the transaction.
    const gate = db.pauseAt("rename", { after: OWNER_LOCK });
    const rename = settle(
      db.run("rename", () =>
        renameSandbox(minted.principal, { id: victim.id, name: "after-revoke" }),
      ),
    );
    await gate.waitReached();
    await revokeSdkKey(f.owner, { id: (minted.principal as { keyId: string }).keyId });
    gate.release();
    expect((await rename).error).toMatchObject({ code: "FORBIDDEN" });
    expect(await storedName(victim.id)).toBe("before-revoke");
  });

  it("the key is held (FOR SHARE) before lock 31: a revocation waits for the rename", async () => {
    const { f, minted, victim } = await keyed();
    const gate = db.pauseAt("rename", { after: LOCK_31 });
    const rename = settle(
      db.run("rename", () => renameSandbox(minted.principal, { id: victim.id, name: "renamed" })),
    );
    await gate.waitReached();
    const revoke = settle(
      db.run("revoke", () =>
        revokeSdkKey(f.owner, { id: (minted.principal as { keyId: string }).keyId }),
      ),
    );
    await db.waitUntilBlocked("revoke", { by: "rename" });
    gate.release();
    // The rename committed while the key was still valid (the revocation
    // serialized after it); the shared response guard then refuses to answer
    // a request whose authority changed in flight.
    expect((await rename).error).toMatchObject({
      code: "FORBIDDEN",
      message: "Authority changed during request.",
    });
    expect((await revoke).error).toBeUndefined();
    expect(await storedName(victim.id)).toBe("renamed");
  });
});
