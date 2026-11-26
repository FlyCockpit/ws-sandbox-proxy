/**
 * The restore-wait pass's login-refusal bookkeeping (§8.3c), on a mocked
 * client: a transient login refusal (at target selection, or at the bind,
 * undone to a savepoint) is recorded on the locked waiting row and, when
 * the latest evaluation ended that way, becomes the deadline's failure code
 * instead of `restore_no_allowed_host`; a capacity verdict clears it; a
 * permanent refusal still ends the wait at once; an overdue row is never
 * attempted. Real-SQL locking and savepoints are in `restore-wait.pg.test.ts`.
 */
vi.mock("@wssp/env/server", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep<typeof import("@wssp/db").default>() };
});
vi.mock("../outbox", () => ({
  createSandboxOutboxEvent: vi.fn(),
  sandboxOutboxTransaction: vi.fn(),
}));
vi.mock("../relay-fence", () => ({
  hostDatabaseNow: vi.fn(),
  lockCurrentHostEpoch: vi.fn(),
  retireSupersededOperations: vi.fn(),
}));
vi.mock("../sharing-authority", () => ({
  discoverPlacementPrincipals: vi.fn(async () => []),
  lockPlacementPrincipals: vi.fn(async () => undefined),
  requirePlacementPrincipals: vi.fn(),
  requirePoolUse: vi.fn(),
}));
vi.mock("../stored-principal", () => ({
  resolveStoredPrincipal: vi.fn(async ({ userId }: { userId: string }) => ({
    kind: "session",
    ownerId: userId,
  })),
}));
vi.mock("../../lib/sdk-key-access", () => ({
  authorizeRestoreIntent: vi.fn(),
  authorizeServiceAction: vi.fn(async () => undefined),
}));
vi.mock("../direct-placement", () => ({
  lockOwnerPlacement: vi.fn(async () => undefined),
  selectDirectTarget: vi.fn(),
}));
vi.mock("../pool-locks", () => ({ lockPoolGraph: vi.fn(async () => undefined) }));
vi.mock("../../credentials/placement", () => ({
  sandboxCredentialPlacementContext: vi.fn(async () => null),
}));
vi.mock("./eligibility", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./eligibility")>()),
  restoreHostEligibility: vi.fn(async () => ({ ok: true })),
}));
vi.mock("./store", () => ({ supersedeLiveOffload: vi.fn(async () => undefined) }));

import type { Prisma } from "@wssp/db";
import prisma from "@wssp/db";
import { SDK_ERRORS } from "@wssp/sandbox-contracts";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { DeepMockProxy } from "vitest-mock-extended";
import { credentialError } from "../../credentials/errors";
import { selectDirectTarget } from "../direct-placement";
import { sandboxStateConflict } from "../errors";
import { sandboxOutboxTransaction } from "../outbox";
import { hostDatabaseNow } from "../relay-fence";
import { lockPlacementPrincipals } from "../sharing-authority";
import { runRestoreWaitPass } from "./restore-admit";
import {
  PERMANENT_RESTORE_LOGIN_CODES,
  TRANSIENT_RESTORE_LOGIN_CODES,
} from "./restore-login-codes";
import { supersedeLiveOffload } from "./store";

const db = prisma as unknown as DeepMockProxy<Prisma.TransactionClient>;
const clock = { now: () => new Date() } as unknown as Parameters<typeof runRestoreWaitPass>[0];

type Row = {
  operationId: string;
  sandboxId: string;
  userId: string;
  authorizingKeyId: string | null;
  expectedGeneration: number;
  intent: Prisma.JsonValue | null;
  state: string;
  deadlineAt: Date;
  lastAttemptAt: Date | null;
  lastLoginRefusal: string | null;
};

type Code =
  | (typeof TRANSIENT_RESTORE_LOGIN_CODES)[number]
  | (typeof PERMANENT_RESTORE_LOGIN_CODES)[number];

let now: Date;
let row: Row;
let operationUpdates: Record<string, unknown>[];
/** Where this pass is refused: the target host's admission, or the bind. */
let refusal: { at: "select" | "bind"; code: Code } | null;
/** Whether an own host with room is offered to selection. */
let hostOffered: boolean;

function matchesWhere(where: Record<string, unknown> | undefined): boolean {
  if (!where) return true;
  if (where.operationId !== undefined && where.operationId !== row.operationId) return false;
  if (where.state !== undefined && where.state !== row.state) return false;
  const deadline = where.deadlineAt as { lte?: Date } | undefined;
  if (deadline?.lte && !(row.deadlineAt <= deadline.lte)) return false;
  return true;
}

beforeEach(() => {
  vi.clearAllMocks();
  now = new Date("2026-11-07T12:00:00Z");
  row = {
    operationId: "op-1",
    sandboxId: "sbx-1",
    userId: "owner",
    authorizingKeyId: null,
    expectedGeneration: 3,
    intent: { timeoutMs: 60_000, overrideCreatorAllowlist: false },
    state: "WAITING",
    deadlineAt: new Date(now.getTime() + 60_000),
    lastAttemptAt: null,
    lastLoginRefusal: null,
  };
  operationUpdates = [];
  refusal = null;
  hostOffered = false;
  vi.useFakeTimers({ now, toFake: ["Date"] });
  vi.mocked(hostDatabaseNow).mockImplementation(async () => new Date(now));
  vi.mocked(sandboxOutboxTransaction).mockImplementation(async (work) => work(db as never));
  vi.mocked(selectDirectTarget).mockImplementation(async () => {
    if (refusal?.at === "select") throw credentialError(refusal.code);
    return { storagePool: { id: "sp", marker: "m", name: "default" } } as never;
  });
  vi.mocked(supersedeLiveOffload).mockImplementation(async () => {
    // The bind's first step stands in for a refusal at its login claims:
    // it throws inside the placement transaction, which then rolls back.
    if (refusal?.at === "bind") throw credentialError(refusal.code);
  });
  db.sandboxRestoreWait.findMany.mockImplementation((async (args: {
    where?: Record<string, unknown>;
  }) =>
    matchesWhere(args.where)
      ? [{ ...row }]
      : []) as unknown as typeof db.sandboxRestoreWait.findMany);
  db.sandboxRestoreWait.findFirst.mockImplementation((async () =>
    row.state === "WAITING"
      ? { deadlineAt: row.deadlineAt }
      : null) as unknown as typeof db.sandboxRestoreWait.findFirst);
  db.sandboxRestoreWait.updateMany.mockImplementation((async (args: {
    where?: Record<string, unknown>;
    data: Record<string, unknown>;
  }) => {
    if (!matchesWhere(args.where)) return { count: 0 };
    Object.assign(row, args.data);
    return { count: 1 };
  }) as unknown as typeof db.sandboxRestoreWait.updateMany);
  // SAVEPOINT / ROLLBACK TO / RELEASE.
  db.$executeRaw.mockImplementation((async () => 0) as unknown as typeof db.$executeRaw);
  db.$queryRaw.mockImplementation((async (strings: TemplateStringsArray) => {
    const sql = strings.join("?");
    if (sql.includes("FROM sandbox_restore_wait"))
      return row.state === "WAITING" ? [{ ...row }] : [];
    if (sql.includes("FROM sandbox_host h")) return hostOffered ? [{ id: "host-1" }] : [];
    return [];
  }) as unknown as typeof db.$queryRaw);
  db.sandboxOperation.findFirst.mockImplementation((async () => ({
    id: row.operationId,
    idempotencyKey: "key",
    restoreOffloadId: "off-1",
    authorizingKeyId: null,
  })) as unknown as typeof db.sandboxOperation.findFirst);
  db.sandbox.findFirst.mockImplementation((async () => ({
    id: row.sandboxId,
    userId: row.userId,
    state: "OFFLOADED",
    generation: row.expectedGeneration,
    diskOffloadId: "off-1",
    templateRevisionId: "rev-1",
    originPoolId: null,
    cpuCount: 1,
    memoryMiB: 1024,
    diskGiB: 10,
    buildId: null,
    verifyBuildId: null,
    tunnelPorts: [],
  })) as unknown as typeof db.sandbox.findFirst);
  db.sandboxOperation.updateMany.mockImplementation((async (args: {
    data: Record<string, unknown>;
  }) => {
    operationUpdates.push(args.data);
    return { count: 1 };
  }) as unknown as typeof db.sandboxOperation.updateMany);
});

async function passAt(ms: number) {
  now = new Date(now.getTime() + ms);
  vi.setSystemTime(now);
  await runRestoreWaitPass(clock);
}

function refuse(at: "select" | "bind", code: Code) {
  hostOffered = true;
  refusal = { at, code };
}

function capacityOnly() {
  hostOffered = false;
  refusal = null;
}

describe("runRestoreWaitPass login refusals", () => {
  for (const at of ["select", "bind"] as const)
    it(`a transient refusal at ${at}, then the deadline, ends with that login code`, async () => {
      refuse(at, "credential.pending_drain");
      await passAt(0);
      expect(row).toMatchObject({
        state: "WAITING",
        lastLoginRefusal: "credential.pending_drain",
        lastAttemptAt: now,
      });
      expect(operationUpdates).toEqual([]);

      await passAt(61_000);
      expect(row).toMatchObject({ state: "TIMED_OUT", endReason: "credential.pending_drain" });
      expect(operationUpdates).toEqual([
        expect.objectContaining({
          state: "FAILED",
          errorCode: "credential.pending_drain",
          errorDetail: SDK_ERRORS["credential.pending_drain"][1],
        }),
      ]);
    });

  it("a host_forbidden at target selection is a login verdict, not capacity", async () => {
    refuse("select", "credential.host_forbidden");
    await passAt(0);
    expect(row).toMatchObject({ state: "WAITING", lastLoginRefusal: "credential.host_forbidden" });
    await passAt(61_000);
    expect(operationUpdates).toEqual([
      expect.objectContaining({ errorCode: "credential.host_forbidden" }),
    ]);
  });

  it("capacity-only passes end the restore restore_no_allowed_host", async () => {
    capacityOnly();
    await passAt(0);
    expect(row).toMatchObject({ state: "WAITING", lastLoginRefusal: null, lastAttemptAt: now });
    await passAt(61_000);
    expect(row).toMatchObject({ state: "TIMED_OUT", endReason: "restore_no_allowed_host" });
    expect(operationUpdates).toEqual([
      expect.objectContaining({ state: "FAILED", errorCode: "restore_no_allowed_host" }),
    ]);
  });

  it("the newest verdict decides: a capacity pass after a refusal clears it", async () => {
    refuse("bind", "credential.in_use");
    await passAt(0);
    expect(row.lastLoginRefusal).toBe("credential.in_use");
    capacityOnly();
    await passAt(1_000);
    expect(row).toMatchObject({ state: "WAITING", lastLoginRefusal: null });
    await passAt(61_000);
    expect(operationUpdates).toEqual([
      expect.objectContaining({ errorCode: "restore_no_allowed_host" }),
    ]);
  });

  it("a later refusal replaces an earlier one", async () => {
    refuse("bind", "credential.in_use");
    await passAt(0);
    refuse("select", "credential.needs_login");
    await passAt(1_000);
    expect(row.lastLoginRefusal).toBe("credential.needs_login");
    await passAt(61_000);
    expect(operationUpdates).toEqual([
      expect.objectContaining({ errorCode: "credential.needs_login" }),
    ]);
  });

  it("a non-login refusal (a lost race) is no verdict and leaves the recorded one", async () => {
    refuse("bind", "credential.busy");
    await passAt(0);
    vi.mocked(lockPlacementPrincipals).mockRejectedValueOnce(
      sandboxStateConflict("The restore is being placed. Retry the request."),
    );
    await passAt(1_000);
    expect(row).toMatchObject({ state: "WAITING", lastLoginRefusal: "credential.busy" });
  });

  it("a permanent refusal still ends the wait at once", async () => {
    refuse("bind", "credential.not_attached");
    await passAt(0);
    expect(row).toMatchObject({
      state: "FAILED",
      endReason: "credential.not_attached",
      lastLoginRefusal: null,
    });
    expect(operationUpdates).toEqual([
      expect.objectContaining({ state: "FAILED", errorCode: "credential.not_attached" }),
    ]);
  });

  it("every permanent code ends the wait at once with its catalog message", async () => {
    for (const code of PERMANENT_RESTORE_LOGIN_CODES) {
      Object.assign(row, {
        state: "WAITING",
        intent: { timeoutMs: 60_000, overrideCreatorAllowlist: false },
        deadlineAt: new Date(now.getTime() + 60_000),
        lastLoginRefusal: null,
      });
      operationUpdates = [];
      refuse("bind", code);
      await passAt(0);
      expect(row, code).toMatchObject({ state: "FAILED", endReason: code });
      expect(operationUpdates, code).toEqual([
        expect.objectContaining({
          state: "FAILED",
          errorCode: code,
          errorDetail: SDK_ERRORS[code][1],
        }),
      ]);
    }
  });

  for (const code of ["credential.path_conflict", "credential.unavailable"] as const)
    it(`${code} is permanent: never recorded, never waits for the deadline`, () => {
      expect(PERMANENT_RESTORE_LOGIN_CODES).toContain(code);
      expect(TRANSIENT_RESTORE_LOGIN_CODES).not.toContain(code);
    });

  it("every transient code maps to its catalog message at the deadline", async () => {
    for (const code of TRANSIENT_RESTORE_LOGIN_CODES) {
      Object.assign(row, {
        state: "WAITING",
        intent: { timeoutMs: 60_000, overrideCreatorAllowlist: false },
        deadlineAt: new Date(now.getTime() + 60_000),
        lastLoginRefusal: null,
      });
      operationUpdates = [];
      refuse("bind", code);
      await passAt(0);
      await passAt(61_000);
      expect(operationUpdates, code).toEqual([
        expect.objectContaining({ errorCode: code, errorDetail: SDK_ERRORS[code][1] }),
      ]);
    }
  });

  it("an overdue row is never attempted; the deadline ends it", async () => {
    refuse("bind", "credential.in_use");
    await passAt(0);
    // Overdue but not yet expired (the expiry scan missed it this pass).
    row.deadlineAt = new Date(now.getTime() + 500);
    vi.mocked(selectDirectTarget).mockClear();
    refuse("select", "credential.needs_login");
    now = new Date(now.getTime() + 1_000);
    vi.setSystemTime(now);
    db.sandboxRestoreWait.findMany.mockImplementationOnce((async () => []) as never);
    await runRestoreWaitPass(clock);
    expect(selectDirectTarget).not.toHaveBeenCalled();
    expect(row).toMatchObject({ state: "WAITING", lastLoginRefusal: "credential.in_use" });
    await passAt(0);
    expect(row).toMatchObject({ state: "TIMED_OUT", endReason: "credential.in_use" });
  });

  it("a refused bind is undone to its savepoint and the refusal recorded in the same transaction", async () => {
    refuse("bind", "credential.busy");
    await passAt(0);
    const sql = vi
      .mocked(db.$executeRaw)
      .mock.calls.map(([strings]) => (strings as unknown as string[]).join("?"));
    expect(sql).toEqual(["SAVEPOINT restore_bind", "ROLLBACK TO SAVEPOINT restore_bind"]);
    expect(sandboxOutboxTransaction).toHaveBeenCalledTimes(1);
    expect(row.lastLoginRefusal).toBe("credential.busy");
  });
});
