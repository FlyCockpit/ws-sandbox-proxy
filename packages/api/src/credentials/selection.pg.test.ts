import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
const envState = vi.hoisted(() => ({ CREDENTIAL_MAX_INSTANCES_PER_OWNER: 1000 as number | null }));
vi.mock("@wssp/env/server", () => ({ env: envState, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));

/**
 * CLI-logins selection and claim races. Barriers are real row locks
 * observed through pg_stat_activity, never sleeps.
 */
const db = await pgTestDatabase();
const { seedOwner, seedSandbox } = await import("../webhooks/testing/fixtures");
const { claimLoginLease, claimWorkloadLeases, refuseUnclaimableLogin } = await import(
  "./selection"
);
const { insertInstance, setAccountPaused } = await import("./accounts");
const { lockInstancesInClaimOrder } = await import("./leases");
afterAll(() => db.close());

type Tx = Parameters<Parameters<typeof db.prisma.$transaction>[0]>[0];
const CLAIM_UPDATE = /^sql:UPDATE credential_instance SET "activeLeases" = "activeLeases" \+ 1/;

async function seedLogin(owner: string, mode: "EXCLUSIVE" | "SHAREABLE" = "EXCLUSIVE") {
  const definition = await db.inspect.credentialDefinition.create({
    data: {
      userId: owner,
      slug: `def-${randomUUID().slice(0, 8)}`,
      version: 1,
      document: {},
      digest: "a".repeat(64),
      displayName: "Fixture",
    },
  });
  return db.inspect.credential.create({
    data: {
      userId: owner,
      name: `login-${randomUUID().slice(0, 8)}`,
      definitionId: definition.id,
      definitionDigest: definition.digest,
      mode,
      delivery: "GUEST",
      copyBack: mode === "EXCLUSIVE",
    },
    select: { id: true },
  });
}

async function seedAccount(owner: string, credentialId: string, ordinal: number, paused = false) {
  return db.inspect.credentialAccount.create({
    data: {
      userId: owner,
      credentialId,
      ordinal,
      ...(paused ? { pausedAt: new Date(), pausedBy: owner } : {}),
    },
    select: { id: true, ordinal: true },
  });
}

async function seedInstance(
  owner: string,
  credentialId: string,
  account: { id: string; ordinal: number },
  ordinal: number,
  extra: {
    state?: "READY" | "NEEDS_LOGIN" | "EMPTY";
    capacity?: number | null;
    activeLeases?: number;
    paused?: boolean;
    loginLeaseId?: string;
    id?: string;
  } = {},
) {
  const state = extra.state ?? "READY";
  return db.inspect.credentialInstance.create({
    data: {
      ...(extra.id ? { id: extra.id } : {}),
      userId: owner,
      credentialId,
      accountId: account.id,
      accountOrdinal: account.ordinal,
      ordinal,
      state,
      capacity: extra.capacity === undefined ? 1 : extra.capacity,
      activeLeases: extra.activeLeases ?? 0,
      accountPaused: extra.paused ?? false,
      loginLeaseId: extra.loginLeaseId ?? null,
      currentSeq: state === "READY" ? 1 : null,
      nextStorageSeq: 2,
    },
    select: { id: true },
  });
}

async function seedWorld(mode: "EXCLUSIVE" | "SHAREABLE" = "EXCLUSIVE") {
  const owner = await seedOwner(db.inspect);
  const login = await seedLogin(owner, mode);
  const sandbox = await seedSandbox(db.inspect, owner, "READY");
  return { owner, login, sandbox };
}

function claim(
  actor: string,
  input: Parameters<typeof claimWorkloadLeases>[1],
  between?: (tx: Tx) => Promise<void>,
) {
  return db.run(actor, () =>
    db.prisma.$transaction(async (tx) => {
      const leases = await claimWorkloadLeases(tx, input);
      await between?.(tx);
      return leases;
    }),
  );
}

const codeOf = (result: PromiseSettledResult<unknown>) =>
  result.status === "rejected"
    ? ((result.reason as { data?: { code?: string } }).data?.code ?? String(result.reason))
    : "ok";

async function instanceRow(id: string) {
  return db.inspect.credentialInstance.findUniqueOrThrow({
    where: { id },
    select: { activeLeases: true, loginLeaseId: true },
  });
}

describe("credential selection and claims (pg)", () => {
  it("E1-B-05: the pre-placement check refuses exactly as the claim would, and claims nothing", async () => {
    const { owner, login } = await seedWorld();
    const paused = await seedAccount(owner, login.id, 1, true);
    const live = await seedAccount(owner, login.id, 2);
    const pausedReady = await seedInstance(owner, login.id, paused, 1, { paused: true });
    const held = await seedInstance(owner, login.id, live, 1, { activeLeases: 1 });
    const check = (request: object) =>
      db.prisma.$transaction((tx) =>
        refuseUnclaimableLogin(tx, owner, { credentialId: login.id, ...request }),
      );
    await expect(check({})).rejects.toMatchObject({ data: { code: "credential.in_use" } });
    await expect(check({ instanceId: held.id })).rejects.toMatchObject({
      data: { code: "credential.in_use" },
    });
    await expect(check({ instanceId: pausedReady.id })).rejects.toMatchObject({
      data: { code: "credential.account_paused" },
    });
    await expect(check({ accountId: paused.id })).rejects.toMatchObject({
      data: { code: "credential.account_paused" },
    });
    const free = await seedInstance(owner, login.id, live, 2);
    await expect(check({})).resolves.toBeUndefined();
    await expect(check({ instanceId: free.id })).resolves.toBeUndefined();
    expect(await instanceRow(free.id)).toMatchObject({ activeLeases: 0 });
    // A login the owner does not have keeps the claim's own not_found.
    await expect(
      db.prisma.$transaction((tx) =>
        refuseUnclaimableLogin(tx, owner, { credentialId: "missing-login" }),
      ),
    ).resolves.toBeUndefined();
  });

  it("1: two creates for the last exclusive instance — one RESERVED, one in_use; raw insert hits the partial unique", async () => {
    const { owner, login, sandbox } = await seedWorld();
    const account = await seedAccount(owner, login.id, 1);
    const instance = await seedInstance(owner, login.id, account, 1);
    const other = await seedSandbox(db.inspect, owner, "READY");
    const gate = db.pauseAt("first", { after: CLAIM_UPDATE });
    const first = claim("first", {
      ownerId: owner,
      sandboxId: sandbox.id,
      operationId: "op-1",
      requests: [{ credentialId: login.id }],
    });
    await gate.waitReached();
    const second = claim("second", {
      ownerId: owner,
      sandboxId: other.id,
      operationId: "op-2",
      requests: [{ credentialId: login.id }],
    });
    await db.waitUntilBlocked("second", { by: "first" });
    gate.release();
    const results = await Promise.allSettled([first, second]);
    expect(results.map(codeOf)).toEqual(["ok", "credential.in_use"]);
    expect(await instanceRow(instance.id)).toMatchObject({ activeLeases: 1 });
    const leases = await db.inspect.credentialLease.findMany({
      where: { instanceId: instance.id },
    });
    expect(leases).toHaveLength(1);
    expect(leases[0]).toMatchObject({ state: "RESERVED", exclusive: true, sandboxId: sandbox.id });
    // The PG barrier holds even for a raw writer that skips the claim statement.
    await expect(
      db.inspect.credentialLease.create({
        data: {
          userId: owner,
          credentialId: login.id,
          accountId: account.id,
          instanceId: instance.id,
          sandboxId: other.id,
          operationId: "raw",
          kind: "WORKLOAD",
          exclusive: true,
          state: "ACTIVE",
        },
      }),
    ).rejects.toMatchObject({ code: "P2002" });
  });

  it("2: shareable capacity 2 with three racers — two succeed, activeLeases consistent", async () => {
    const { owner, login } = await seedWorld("SHAREABLE");
    const account = await seedAccount(owner, login.id, 1);
    const instance = await seedInstance(owner, login.id, account, 1, { capacity: 2 });
    const sandboxes = await Promise.all(
      [0, 1, 2].map(() => seedSandbox(db.inspect, owner, "READY")),
    );
    const gate = db.pauseAt("r0", { after: CLAIM_UPDATE });
    const r0 = claim("r0", {
      ownerId: owner,
      sandboxId: sandboxes[0]!.id,
      operationId: "op-0",
      requests: [{ credentialId: login.id }],
    });
    await gate.waitReached();
    const rest = [1, 2].map((i) =>
      claim(`r${i}`, {
        ownerId: owner,
        sandboxId: sandboxes[i]!.id,
        operationId: `op-${i}`,
        requests: [{ credentialId: login.id }],
      }),
    );
    await db.waitUntilBlocked("r1", { by: "r0" });
    await db.waitUntilBlocked("r2");
    gate.release();
    const results = (await Promise.allSettled([r0, ...rest])).map(codeOf);
    expect(results.filter((code) => code === "ok")).toHaveLength(2);
    expect(results.filter((code) => code === "credential.in_use")).toHaveLength(1);
    expect(await instanceRow(instance.id)).toMatchObject({ activeLeases: 2 });
    expect(
      await db.inspect.credentialLease.count({
        where: { instanceId: instance.id, exclusive: false },
      }),
    ).toBe(2);
  });

  it("3: pause vs auto-pick, both orders", async () => {
    // Order A: the pause holds the instance rows; the claim re-evaluates
    // accountPaused after the pause commits and falls through to account 2.
    {
      const { owner, login, sandbox } = await seedWorld();
      const a1 = await seedAccount(owner, login.id, 1);
      const a2 = await seedAccount(owner, login.id, 2);
      const i1 = await seedInstance(owner, login.id, a1, 1);
      const i2 = await seedInstance(owner, login.id, a2, 1);
      const pauseGate = db.pauseAt("pause", {
        after: /^sql:UPDATE credential_instance SET "accountPaused"/,
      });
      const pause = db.run("pause", () =>
        db.prisma.$transaction((tx) =>
          setAccountPaused(tx, owner, {
            credentialId: login.id,
            accountId: a1.id,
            paused: true,
            by: owner,
          }),
        ),
      );
      await pauseGate.waitReached();
      const picked = claim("pick", {
        ownerId: owner,
        sandboxId: sandbox.id,
        operationId: "op",
        requests: [{ credentialId: login.id }],
      });
      await db.waitUntilBlocked("pick", { by: "pause" });
      pauseGate.release();
      await pause;
      const [lease] = await picked;
      expect(lease?.instanceId).toBe(i2.id);
      expect(await instanceRow(i1.id)).toMatchObject({ activeLeases: 0 });
    }
    // Order B: the claim holds instance 1; the pause waits for it and the
    // running lease is kept (pause applies to new claims only).
    {
      const { owner, login, sandbox } = await seedWorld();
      const a1 = await seedAccount(owner, login.id, 1);
      const i1 = await seedInstance(owner, login.id, a1, 1);
      const claimGate = db.pauseAt("pick", { after: CLAIM_UPDATE });
      const picked = claim("pick", {
        ownerId: owner,
        sandboxId: sandbox.id,
        operationId: "op",
        requests: [{ credentialId: login.id }],
      });
      await claimGate.waitReached();
      const pause = db.run("pause", () =>
        db.prisma.$transaction((tx) =>
          setAccountPaused(tx, owner, {
            credentialId: login.id,
            accountId: a1.id,
            paused: true,
            by: owner,
          }),
        ),
      );
      await db.waitUntilBlocked("pause", { by: "pick" });
      claimGate.release();
      const [lease] = await picked;
      await pause;
      expect(lease?.instanceId).toBe(i1.id);
      expect(
        await db.inspect.credentialInstance.findUniqueOrThrow({
          where: { id: i1.id },
          select: { accountPaused: true, activeLeases: true },
        }),
      ).toEqual({ accountPaused: true, activeLeases: 1 });
      // A new claim now refuses with the paused reason.
      const other = await seedSandbox(db.inspect, owner, "READY");
      await expect(
        claim("again", {
          ownerId: owner,
          sandboxId: other.id,
          operationId: "op2",
          requests: [{ credentialId: login.id }],
        }),
      ).rejects.toMatchObject({ data: { code: "credential.account_paused" } });
    }
  });

  it("final-4: pause prelocks the account's instances in the claim order; it never holds a later one while waiting for an earlier one", async () => {
    const { owner, login } = await seedWorld();
    const account = await seedAccount(owner, login.id, 1);
    const tag = randomUUID().slice(0, 8);
    // `later` sorts after `earlier` in the claim order but comes first in
    // every scan the bulk UPDATE could use (inserted first, lower ordinal).
    const later = await seedInstance(owner, login.id, account, 1, { id: `inst-b-${tag}` });
    const earlier = await seedInstance(owner, login.id, account, 2, { id: `inst-a-${tag}` });
    // A settlement holding `earlier`, about to take `later` (claim order).
    const holding = db.pauseAt("settle", {
      after: /^sql:SELECT id FROM credential_instance WHERE id = .* FOR UPDATE$/,
    });
    const settle = db.run("settle", () =>
      db.prisma.$transaction((tx) =>
        lockInstancesInClaimOrder(tx, [
          { credentialId: login.id, instanceId: earlier.id },
          { credentialId: login.id, instanceId: later.id },
        ]),
      ),
    );
    await holding.waitReached();
    const pause = db.run("pause", () =>
      db.prisma.$transaction((tx) =>
        setAccountPaused(tx, owner, {
          credentialId: login.id,
          accountId: account.id,
          paused: true,
          by: owner,
        }),
      ),
    );
    await db.waitUntilBlocked("pause", { by: "settle" });
    // The pause waits on `earlier` holding nothing after it: `later` is free
    // (an UPDATE that held it would let the settlement's next lock close a
    // deadlock).
    const laterFree = await db.inspect
      .$transaction(
        (tx) =>
          tx.$queryRaw`SELECT id FROM credential_instance WHERE id = ${later.id} FOR UPDATE NOWAIT`,
      )
      .then(
        () => true,
        () => false,
      );
    expect(laterFree).toBe(true);
    holding.release();
    await settle;
    await pause;
    for (const instance of [earlier, later])
      expect(
        await db.inspect.credentialInstance.findUniqueOrThrow({
          where: { id: instance.id },
          select: { accountPaused: true },
        }),
      ).toEqual({ accountPaused: true });
  });

  it("4: auto-pick skips paused, NEEDS_LOGIN, full and login-held instances, deterministically; named refusals", async () => {
    const { owner, login, sandbox } = await seedWorld();
    const paused = await seedAccount(owner, login.id, 1, true);
    const live = await seedAccount(owner, login.id, 2);
    const pausedReady = await seedInstance(owner, login.id, paused, 1, { paused: true });
    const needsLogin = await seedInstance(owner, login.id, live, 1, { state: "NEEDS_LOGIN" });
    await seedInstance(owner, login.id, live, 2, { activeLeases: 1 });
    await seedInstance(owner, login.id, live, 3, { loginLeaseId: "held" });
    const pick = await seedInstance(owner, login.id, live, 4);
    const later = await seedInstance(owner, login.id, live, 5);
    const run = (actor: string, sandboxId: string, request: object = {}) =>
      claim(actor, {
        ownerId: owner,
        sandboxId,
        operationId: actor,
        requests: [{ credentialId: login.id, ...request }],
      });
    expect((await run("p1", sandbox.id))[0]?.instanceId).toBe(pick.id);
    const s2 = await seedSandbox(db.inspect, owner, "READY");
    expect((await run("p2", s2.id))[0]?.instanceId).toBe(later.id);
    const s3 = await seedSandbox(db.inspect, owner, "READY");
    // Everything unpaused is full or held now.
    await expect(run("p3", s3.id)).rejects.toMatchObject({ data: { code: "credential.in_use" } });
    // Named forms.
    await expect(run("n1", s3.id, { accountId: paused.id })).rejects.toMatchObject({
      data: { code: "credential.account_paused" },
    });
    await expect(run("n2", s3.id, { instanceId: pausedReady.id })).rejects.toMatchObject({
      data: { code: "credential.account_paused" },
    });
    await expect(run("n3", s3.id, { instanceId: needsLogin.id })).rejects.toMatchObject({
      data: { code: "credential.needs_login" },
    });
    await expect(run("n4", s3.id, { instanceId: pick.id })).rejects.toMatchObject({
      data: { code: "credential.in_use" },
    });
    await expect(run("n5", s3.id, { accountId: live.id })).rejects.toMatchObject({
      data: { code: "credential.in_use" },
    });
    // Only paused READY instances left with room → account_paused; none READY → needs_login.
    const onlyPaused = await seedLogin(owner);
    const pa = await seedAccount(owner, onlyPaused.id, 1, true);
    await seedInstance(owner, onlyPaused.id, pa, 1, { paused: true });
    await expect(
      claim("op", {
        ownerId: owner,
        sandboxId: s3.id,
        operationId: "op",
        requests: [{ credentialId: onlyPaused.id }],
      }),
    ).rejects.toMatchObject({ data: { code: "credential.account_paused" } });
    const empty = await seedLogin(owner);
    const ea = await seedAccount(owner, empty.id, 1);
    await seedInstance(owner, empty.id, ea, 1, { state: "EMPTY" });
    await expect(
      claim("oe", {
        ownerId: owner,
        sandboxId: s3.id,
        operationId: "oe",
        requests: [{ credentialId: empty.id }],
      }),
    ).rejects.toMatchObject({ data: { code: "credential.needs_login" } });
  });

  it("16: login delete vs claim — a lease insert racing the delete fails P2003; leases block delete", async () => {
    const { owner, login, sandbox } = await seedWorld();
    const account = await seedAccount(owner, login.id, 1);
    const instance = await seedInstance(owner, login.id, account, 1);
    const deleteGate = db.pauseAt("delete", { after: /^sql:DELETE FROM credential WHERE/ });
    const deleting = db.run("delete", () =>
      db.prisma.$transaction(
        (tx) =>
          tx.$executeRaw`DELETE FROM credential WHERE id = ${login.id} AND "userId" = ${owner}`,
      ),
    );
    await deleteGate.waitReached();
    const racing = db.run("raw", () =>
      db.prisma.$transaction((tx) =>
        tx.credentialLease.create({
          data: {
            userId: owner,
            credentialId: login.id,
            accountId: account.id,
            instanceId: instance.id,
            sandboxId: sandbox.id,
            operationId: "raw",
            kind: "WORKLOAD",
            exclusive: true,
            state: "RESERVED",
          },
        }),
      ),
    );
    await db.waitUntilBlocked("raw", { by: "delete" });
    deleteGate.release();
    await deleting;
    await expect(racing).rejects.toMatchObject({ code: "P2003" });
    // The service claim after the delete reports the login as gone.
    await expect(
      claim("late", {
        ownerId: owner,
        sandboxId: sandbox.id,
        operationId: "late",
        requests: [{ credentialId: login.id }],
      }),
    ).rejects.toMatchObject({ data: { code: "credential.not_found" } });
    // With a lease (even a terminal one) the delete itself refuses (NO ACTION FK).
    const kept = await seedWorld();
    const ka = await seedAccount(kept.owner, kept.login.id, 1);
    await seedInstance(kept.owner, kept.login.id, ka, 1);
    await claim("kept", {
      ownerId: kept.owner,
      sandboxId: kept.sandbox.id,
      operationId: "kept",
      requests: [{ credentialId: kept.login.id }],
    });
    await expect(
      db.inspect.$executeRaw`DELETE FROM credential WHERE id = ${kept.login.id}`,
    ).rejects.toThrow(/foreign key|23503/i);
  });

  it("19: instance-count limit under concurrent creates (owner lock)", async () => {
    envState.CREDENTIAL_MAX_INSTANCES_PER_OWNER = 2;
    try {
      const { owner, login } = await seedWorld();
      const account = await seedAccount(owner, login.id, 1);
      await seedInstance(owner, login.id, account, 1, { state: "EMPTY" });
      const create = (actor: string, name: string) =>
        db.run(actor, () =>
          db.prisma.$transaction((tx) =>
            insertInstance(tx, owner, { credentialId: login.id, accountId: account.id, name }),
          ),
        );
      const gate = db.pauseAt("c1", { before: "credentialInstance.create" });
      const c1 = create("c1", "one");
      await gate.waitReached();
      const c2 = create("c2", "two");
      await db.waitUntilBlocked("c2", { by: "c1" });
      gate.release();
      const results = (await Promise.allSettled([c1, c2])).map(codeOf);
      expect(results).toEqual(["ok", "credential.limit_reached"]);
      expect(await db.inspect.credentialInstance.count({ where: { userId: owner } })).toBe(2);
      // Ordinals stay dense and unique under the lock.
      const ordinals = await db.inspect.credentialInstance.findMany({
        where: { accountId: account.id },
        orderBy: { ordinal: "asc" },
        select: { ordinal: true },
      });
      expect(ordinals.map((row) => row.ordinal)).toEqual([1, 2]);
    } finally {
      envState.CREDENTIAL_MAX_INSTANCES_PER_OWNER = 1000;
    }
  });

  it("20 (create half): multi-login creates in opposite request orders do not deadlock", async () => {
    const owner = await seedOwner(db.inspect);
    const l1 = await seedLogin(owner, "SHAREABLE");
    const l2 = await seedLogin(owner, "SHAREABLE");
    const a1 = await seedAccount(owner, l1.id, 1);
    const a2 = await seedAccount(owner, l2.id, 1);
    const i1 = await seedInstance(owner, l1.id, a1, 1, { capacity: null });
    const i2 = await seedInstance(owner, l2.id, a2, 1, { capacity: null });
    const s1 = await seedSandbox(db.inspect, owner, "READY");
    const s2 = await seedSandbox(db.inspect, owner, "READY");
    const [first, second] = [l1.id, l2.id].sort();
    // T1 asks [first, second]; T2 asks [second, first]. Both claim in sorted
    // order, so T2 waits on the first login's instance instead of taking the
    // second login's instance and closing a cycle.
    const gate = db.pauseAt("t1", { after: CLAIM_UPDATE });
    const t1 = claim("t1", {
      ownerId: owner,
      sandboxId: s1.id,
      operationId: "t1",
      requests: [{ credentialId: first! }, { credentialId: second! }],
    });
    await gate.waitReached();
    const t2 = claim("t2", {
      ownerId: owner,
      sandboxId: s2.id,
      operationId: "t2",
      requests: [{ credentialId: second! }, { credentialId: first! }],
    });
    await db.waitUntilBlocked("t2", { by: "t1" });
    gate.release();
    const [r1, r2] = await Promise.all([t1, t2]);
    expect(r1.map((lease) => lease.credentialId)).toEqual([first, second]);
    expect(r2.map((lease) => lease.credentialId)).toEqual([first, second]);
    expect(await instanceRow(i1.id)).toMatchObject({ activeLeases: 2 });
    expect(await instanceRow(i2.id)).toMatchObject({ activeLeases: 2 });
    // A request naming one login twice is refused before any claim.
    await expect(
      claim("dup", {
        ownerId: owner,
        sandboxId: s2.id,
        operationId: "dup",
        requests: [{ credentialId: l1.id }, { credentialId: l1.id }],
      }),
    ).rejects.toMatchObject({ data: { code: "credential.limit_reached" } });
  });

  it("21: login claim vs workload claim on one shareable instance", async () => {
    // Workload first: the login claim waits, then finds a holder → busy.
    {
      const { owner, login, sandbox } = await seedWorld("SHAREABLE");
      const account = await seedAccount(owner, login.id, 1);
      const instance = await seedInstance(owner, login.id, account, 1, { capacity: null });
      const gate = db.pauseAt("work", { after: CLAIM_UPDATE });
      const work = claim("work", {
        ownerId: owner,
        sandboxId: sandbox.id,
        operationId: "work",
        requests: [{ credentialId: login.id }],
      });
      await gate.waitReached();
      const loginClaim = db.run("login", () =>
        db.prisma.$transaction((tx) =>
          claimLoginLease(tx, {
            ownerId: owner,
            credentialId: login.id,
            instanceId: instance.id,
            loginSessionId: "session",
            operationId: "login",
          }),
        ),
      );
      await db.waitUntilBlocked("login", { by: "work" });
      gate.release();
      const results = (await Promise.allSettled([work, loginClaim])).map(codeOf);
      expect(results).toEqual(["ok", "credential.busy"]);
      expect(await instanceRow(instance.id)).toEqual({ activeLeases: 1, loginLeaseId: null });
    }
    // Login first: the workload claim waits, then skips the held instance → in_use.
    {
      const { owner, login, sandbox } = await seedWorld("SHAREABLE");
      const account = await seedAccount(owner, login.id, 1);
      const instance = await seedInstance(owner, login.id, account, 1, { capacity: null });
      const gate = db.pauseAt("login", {
        after: /^sql:UPDATE credential_instance SET "activeLeases"/,
      });
      const loginClaim = db.run("login", () =>
        db.prisma.$transaction((tx) =>
          claimLoginLease(tx, {
            ownerId: owner,
            credentialId: login.id,
            instanceId: instance.id,
            loginSessionId: "session",
            operationId: "login",
          }),
        ),
      );
      await gate.waitReached();
      const work = claim("work", {
        ownerId: owner,
        sandboxId: sandbox.id,
        operationId: "work",
        requests: [{ credentialId: login.id, instanceId: instance.id }],
      });
      await db.waitUntilBlocked("work", { by: "login" });
      gate.release();
      const results = (await Promise.allSettled([loginClaim, work])).map(codeOf);
      expect(results).toEqual(["ok", "credential.in_use"]);
      const row = await instanceRow(instance.id);
      expect(row.activeLeases).toBe(1);
      expect(row.loginLeaseId).toBe((await loginClaim).leaseId);
      const lease = await db.inspect.credentialLease.findUniqueOrThrow({
        where: { id: row.loginLeaseId! },
      });
      expect(lease).toMatchObject({ kind: "LOGIN", exclusive: true, loginSessionId: "session" });
    }
  });
});
