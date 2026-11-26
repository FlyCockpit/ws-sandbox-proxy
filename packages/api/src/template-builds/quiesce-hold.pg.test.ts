vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "build-quiesce-fixture",
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

/**
 * WP7 (D9): a template build step held by a quiescing host (its command
 * QUEUED in the outbox, before the claim) does not spend the build deadline:
 * the orchestrator counts the running hold, and the next non-quiescing hello
 * folds it into `deadlineAt` exactly once.
 */
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import { advanceTemplateBuild } from "./orchestrator";
import { markHostQuiescing, settleHostQuiesce } from "./quiesce-hold";
import { acceptTemplateBuild } from "./service";
import { buildOwnerFixture, currentOperation, fakeDaemon } from "./testing/build-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());
const daemon = fakeDaemon(db);

const RECIPE = {
  version: 1,
  from: { template: "base" },
  steps: [{ type: "run", script: "echo hi" }],
};
const MINUTE = 60_000;

/** A build at READY → RUNNING with its first step's command QUEUED. */
async function heldStep() {
  const f = await buildOwnerFixture(db);
  const { build } = await acceptTemplateBuild(f.session, {
    idempotencyKey: `accept-${Math.random()}`,
    template: { slug: "built" },
    recipe: RECIPE,
    sandboxHostId: f.host.id,
    timeoutMinutes: 30,
    noCache: true,
  });
  const advance = () => advanceTemplateBuild({ id: build.id, userId: f.id });
  await advance(); // create
  await daemon.ready(build.id);
  await advance(); // READY → RUNNING, step 0 claimed
  const step = await currentOperation(db, build.id);
  expect(step).toMatchObject({ kind: "RUN_COMMAND", state: "QUEUED", dispatchedAt: null });
  return { f, buildId: build.id, step: step!, advance };
}

const hostOf = async (f: { id: string; host: { id: string } }) => ({
  hostId: f.host.id,
  ownerId: f.id,
  connectionEpoch: (await hostRow(f.host.id)).connectionEpoch,
});
const row = (id: string) => db.inspect.sandboxTemplateBuild.findUniqueOrThrow({ where: { id } });
const hostRow = (id: string) => db.inspect.sandboxHost.findUniqueOrThrow({ where: { id } });

describe("template build deadline vs quiesce hold (WP7)", () => {
  it("a step held while its host quiesces is not timed out; without the hold it is", async () => {
    const { f, buildId, step, advance } = await heldStep();
    const now = Date.now();
    // Held for five minutes so far; the deadline passed one second ago.
    await db.inspect.sandboxOperation.update({
      where: { id: step.id },
      data: { createdAt: new Date(now - 5 * MINUTE) },
    });
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { quiescingSince: new Date(now - 10 * MINUTE) },
    });
    await db.inspect.sandboxTemplateBuild.update({
      where: { id: buildId },
      data: { deadlineAt: new Date(now - 1000) },
    });
    await advance();
    expect(await row(buildId)).toMatchObject({ state: "RUNNING", errorCode: null });
    // The host is no longer quiescing (and the hold was not settled): the
    // ordinary deadline applies.
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { quiescingSince: null },
    });
    await advance();
    expect(await row(buildId)).toMatchObject({ state: "FAILED", errorCode: "build_timeout" });
  });

  it("the next non-quiescing hello folds the hold into deadlineAt exactly once", async () => {
    const { f, buildId, step } = await heldStep();
    const now = new Date();
    const since = new Date(now.getTime() - 4 * MINUTE);
    await db.inspect.sandboxOperation.update({
      where: { id: step.id },
      data: { createdAt: new Date(now.getTime() - 3 * MINUTE) },
    });
    const host = await hostOf(f);
    await markHostQuiescing(host, since);
    // A later quiesce report keeps the earliest start.
    await markHostQuiescing(host, now);
    expect((await hostRow(f.host.id)).quiescingSince).toEqual(since);
    const before = (await row(buildId)).deadlineAt!;
    expect(await settleHostQuiesce(host, now)).toBe(1);
    // Held from the step's creation (after the quiesce began) until now.
    expect((await row(buildId)).deadlineAt!.getTime()).toBe(before.getTime() + 3 * MINUTE);
    expect((await hostRow(f.host.id)).quiescingSince).toBeNull();
    // Settled once: a repeated hello changes nothing.
    expect(await settleHostQuiesce(host, new Date(now.getTime() + MINUTE))).toBe(0);
    expect((await row(buildId)).deadlineAt!.getTime()).toBe(before.getTime() + 3 * MINUTE);
  });

  it("integ review P2b: a held step dispatched before its settlement commits keeps its credit", async () => {
    const { f, buildId, step, advance } = await heldStep();
    const now = Date.now();
    // Held for five minutes; a non-quiescing hello let it dispatch a second
    // ago, while the asynchronous settlement has not run yet (the marker is
    // still set). The original deadline passed one second ago.
    await db.inspect.sandboxOperation.update({
      where: { id: step.id },
      data: {
        createdAt: new Date(now - 5 * MINUTE),
        state: "DISPATCHED",
        dispatchedAt: new Date(now - 1000),
      },
    });
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { quiescingSince: new Date(now - 10 * MINUTE) },
    });
    await db.inspect.sandboxTemplateBuild.update({
      where: { id: buildId },
      data: { deadlineAt: new Date(now - 1000) },
    });
    await advance();
    expect(await row(buildId)).toMatchObject({ state: "RUNNING", errorCode: null });
    // The settlement then folds the same hold (creation → dispatch) into
    // the deadline exactly once; the build keeps running.
    const before = (await row(buildId)).deadlineAt!;
    expect(await settleHostQuiesce(await hostOf(f), new Date())).toBe(1);
    expect((await row(buildId)).deadlineAt!.getTime()).toBe(before.getTime() + 5 * MINUTE - 1000);
    await advance();
    expect(await row(buildId)).toMatchObject({ state: "RUNNING", errorCode: null });
  });

  it("a step dispatched before the quiesce began gets no time back", async () => {
    const { f, buildId, step } = await heldStep();
    const now = new Date();
    await db.inspect.sandboxOperation.update({
      where: { id: step.id },
      data: { state: "DISPATCHED", dispatchedAt: new Date(now.getTime() - 2 * MINUTE) },
    });
    const host = await hostOf(f);
    await markHostQuiescing(host, new Date(now.getTime() - MINUTE));
    const before = (await row(buildId)).deadlineAt!;
    expect(await settleHostQuiesce(host, now)).toBe(0);
    expect((await row(buildId)).deadlineAt).toEqual(before);
    expect((await hostRow(f.host.id)).quiescingSince).toBeNull();
  });

  it("settlement waits for an orchestrator tick holding the build; the tick still sees the hold", async () => {
    const { f, buildId, step } = await heldStep();
    const now = new Date();
    await db.inspect.sandboxOperation.update({
      where: { id: step.id },
      data: { createdAt: new Date(now.getTime() - 3 * MINUTE) },
    });
    const host = await hostOf(f);
    await markHostQuiescing(host, new Date(now.getTime() - 4 * MINUTE));
    const before = (await row(buildId)).deadlineAt!;
    let locked!: () => void;
    const holding = new Promise<void>((resolve) => (locked = resolve));
    let release!: () => void;
    const released = new Promise<void>((resolve) => (release = resolve));
    // A tick: it holds the build row (as the orchestrator does), then reads
    // the deadline and the marker.
    const tick = db.inspect.$transaction(
      async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_template_build WHERE id = ${buildId} FOR UPDATE`;
        locked();
        await released;
        const build = await tx.sandboxTemplateBuild.findUniqueOrThrow({ where: { id: buildId } });
        const marker = await tx.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
        return { deadlineAt: build.deadlineAt, quiescingSince: marker.quiescingSince };
      },
      { timeout: 10_000 },
    );
    await holding;
    let settled = false;
    const settling = settleHostQuiesce(host, now).then((count) => {
      settled = true;
      return count;
    });
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(settled).toBe(false);
    release();
    // Neither cleared marker with the old deadline: the hold stays visible.
    expect(await tick).toEqual({ deadlineAt: before, quiescingSince: expect.any(Date) });
    expect(await settling).toBe(1);
    expect((await row(buildId)).deadlineAt!.getTime()).toBe(before.getTime() + 3 * MINUTE);
    expect((await hostRow(f.host.id)).quiescingSince).toBeNull();
  });

  it("writes from an older connection never land after a newer hello", async () => {
    const { f, buildId, step } = await heldStep();
    const now = new Date();
    await db.inspect.sandboxOperation.update({
      where: { id: step.id },
      data: { createdAt: new Date(now.getTime() - 3 * MINUTE) },
    });
    const old = await hostOf(f);
    // A newer connection registers (its hello bumps the epoch).
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { connectionEpoch: { increment: 1 } },
    });
    const current = await hostOf(f);
    // The old connection's delayed quiesce report: no marker.
    await markHostQuiescing(old, new Date(now.getTime() - 4 * MINUTE));
    expect((await hostRow(f.host.id)).quiescingSince).toBeNull();
    // The current connection quiesces; an old settlement cannot end it.
    await markHostQuiescing(current, new Date(now.getTime() - 4 * MINUTE));
    const before = (await row(buildId)).deadlineAt!;
    expect(await settleHostQuiesce(old, now)).toBe(0);
    expect((await hostRow(f.host.id)).quiescingSince).not.toBeNull();
    expect((await row(buildId)).deadlineAt).toEqual(before);
    expect(await settleHostQuiesce(current, now)).toBe(1);
    expect((await hostRow(f.host.id)).quiescingSince).toBeNull();
  });
});
