import {
  OPERATION_ERROR_CODES,
  OPERATION_KINDS,
  publicOperationErrorCode,
} from "@wssp/sandbox-contracts";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Principal } from "../contracts";
import { safeOperationError } from "../sensitive-errors";

/**
 * C48 operation projections (mocked Prisma): what the query asks for is the
 * disclosure boundary, so these tests assert the `where` (owner, filters) and
 * the `select` (an allowlist with no payload, result, key or detail in list
 * rows), plus the exit-code read that only ever touches RUN_COMMAND rows.
 * Real-database behavior (cursor paging, foreign owners) is in
 * apps/server/src/sandbox-api/operation-views.pg.test.ts.
 */

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const { default: db } = await import("@wssp/db");
const { listOperationViews, getOperationView } = await import("./operation-views");

const owner: Principal = { kind: "session", ownerId: "user-a" };
const at = new Date("2026-09-26T10:00:00Z");

function row(overrides: Record<string, unknown> = {}) {
  return {
    id: "op-1",
    sandboxId: "sbx-1",
    kind: "RUN_COMMAND",
    state: "SUCCEEDED",
    generation: 1,
    errorCode: null,
    createdAt: at,
    updatedAt: at,
    dispatchedAt: at,
    completedAt: at,
    Sandbox: { state: "READY" },
    ...overrides,
  };
}

type FindManyArgs = { where: unknown; select: Record<string, unknown>; take?: number };
const listCall = () => db.sandboxOperation.findMany.mock.calls[0]![0] as FindManyArgs;
const exitCall = () => db.sandboxOperation.findMany.mock.calls[1]?.[0] as FindManyArgs | undefined;
const findFirstCall = () => db.sandboxOperation.findFirst.mock.calls[0]![0] as FindManyArgs;

beforeEach(() => {
  vi.clearAllMocks();
});

describe("listOperationViews", () => {
  it("selects status metadata only: no request, result, key, hash or free-text error detail", async () => {
    db.sandboxOperation.findMany
      .mockResolvedValueOnce([row()])
      .mockResolvedValueOnce([{ id: "op-1", result: { exitCode: 3, pid: 44, outputBytes: 9 } }]);
    const page = await listOperationViews(owner, { limit: 20 });
    const select = listCall().select;
    expect(Object.keys(select).sort()).toEqual(
      [
        "Sandbox",
        "Capture",
        "progressPhase",
        "progressBytesDone",
        "progressBytesTotal",
        "failure",
        "completedAt",
        "createdAt",
        "dispatchedAt",
        "errorCode",
        "generation",
        "id",
        "kind",
        "sandboxId",
        "state",
        "updatedAt",
      ].sort(),
    );
    expect(select.Sandbox).toEqual({ select: { state: true, name: true } });
    // The capture's storage cause is a CHECK-constrained code (post-landing #6).
    expect(select.Capture).toEqual({ select: { revisionId: true, errorDetail: true } });
    // The row carries the exit code, nothing else from the stored result.
    expect(page.items).toEqual([
      {
        id: "op-1",
        sandboxId: "sbx-1",
        kind: "RUN_COMMAND",
        state: "SUCCEEDED",
        generation: 1,
        errorCode: null,
        createdAt: at,
        updatedAt: at,
        dispatchedAt: at,
        completedAt: at,
        exitCode: 3,
        failure: null,
        sandboxState: "READY",
        progress: null,
        capturedRevisionId: null,
        captureDetail: null,
      },
    ]);
    expect(JSON.stringify(page)).not.toMatch(/pid|outputBytes|result/);
  });

  it("is owner-scoped on the operation and its sandbox, newest first, bounded by limit + 1", async () => {
    db.sandboxOperation.findMany.mockResolvedValueOnce([]);
    await listOperationViews(owner, { limit: 7 });
    const args = listCall() as FindManyArgs & { orderBy: unknown };
    expect(args.where).toEqual({ AND: [{ userId: "user-a", Sandbox: { userId: "user-a" } }] });
    expect(args.orderBy).toEqual([{ createdAt: "desc" }, { id: "desc" }]);
    expect(args.take).toBe(8);
    // An empty page reads no results at all.
    expect(db.sandboxOperation.findMany).toHaveBeenCalledTimes(1);
  });

  it.each([
    [{ sandboxId: "sbx-9" }, { sandboxId: "sbx-9" }],
    [{ kind: "GET_FILE" as const }, { kind: "GET_FILE" }],
    [{ state: "FAILED" as const }, { state: "FAILED" }],
    [
      { state: "active" as const },
      { state: { in: ["QUEUED", "DISPATCHED", "ACCEPTED", "RUNNING", "CANCEL_REQUESTED"] } },
    ],
    [
      { state: "settled" as const },
      { state: { in: ["SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN_OUTCOME"] } },
    ],
  ])("filter %j narrows the owner query to %j", async (filter, expected) => {
    db.sandboxOperation.findMany.mockResolvedValueOnce([]);
    await listOperationViews(owner, { limit: 20, ...filter });
    expect(listCall().where).toEqual({
      AND: [{ userId: "user-a", Sandbox: { userId: "user-a" }, ...expected }],
    });
  });

  it("reads exit codes only for the page's RUN_COMMAND rows, owner-scoped", async () => {
    db.sandboxOperation.findMany
      .mockResolvedValueOnce([
        row({ id: "op-cmd" }),
        row({ id: "op-file", kind: "GET_FILE" }),
        row({ id: "op-dir", kind: "LIST_DIR" }),
      ])
      .mockResolvedValueOnce([{ id: "op-cmd", result: { exitCode: 0 } }]);
    const page = await listOperationViews(owner, { limit: 20 });
    expect(exitCall()).toEqual({
      where: {
        id: { in: ["op-cmd"] },
        kind: "RUN_COMMAND",
        userId: "user-a",
        Sandbox: { userId: "user-a" },
      },
      select: { id: true, result: true },
    });
    expect(page.items.map((item) => [item.id, item.exitCode])).toEqual([
      ["op-cmd", 0],
      ["op-file", null],
      ["op-dir", null],
    ]);
  });

  it("maps stored error codes to the public catalog (unknown ones read as internal)", async () => {
    db.sandboxOperation.findMany.mockResolvedValueOnce([
      row({ id: "a", kind: "MKDIR", state: "FAILED", errorCode: "path_refused" }),
      row({ id: "b", kind: "MKDIR", state: "FAILED", errorCode: "host said: rm -rf /x failed" }),
    ]);
    const page = await listOperationViews(owner, { limit: 20 });
    expect(page.items.map((item) => item.errorCode)).toEqual(["path_refused", "internal"]);
  });
});

describe("getOperationView", () => {
  const detail = (overrides: Record<string, unknown> = {}) => ({
    ...row(),
    Sandbox: {
      id: "sbx-1",
      state: "DELETED",
      generation: 2,
      hostOwnerId: "user-a",
      SandboxHost: null,
    },
    ...overrides,
  });

  it.each(OPERATION_KINDS)(
    "%s error code and message share one catalog entry for all public and legacy codes",
    async (kind) => {
      for (const code of [
        ...OPERATION_ERROR_CODES,
        "private_config_refused",
        "transfer_expired",
        "transfer_quota",
        "expiry_failed",
        "unknown-legacy-code",
        null,
      ]) {
        db.sandboxOperation.findFirst.mockResolvedValueOnce(
          detail({ kind, state: "FAILED", errorCode: code }),
        );
        db.sandboxOperation.findMany.mockResolvedValue([]);
        const view = await getOperationView(owner, { operationId: "op-1" });
        expect(view.errorCode).toBe(publicOperationErrorCode(code) ?? "internal");
        expect({ code: view.errorCode, message: view.errorMessage }).toEqual(
          safeOperationError(view.errorCode),
        );
      }
    },
  );

  it("names a captured revision slug vN through an owner-scoped lookup", async () => {
    db.sandboxOperation.findFirst.mockResolvedValueOnce(
      detail({ kind: "CAPTURE_TEMPLATE", state: "SUCCEEDED", Capture: { revisionId: "rev-9" } }),
    );
    db.sandboxTemplateRevision.findFirst.mockResolvedValueOnce({
      revision: 4,
      Template: { slug: "web" },
    } as never);
    const view = await getOperationView(owner, { operationId: "op-1" });
    expect(view).toMatchObject({
      capturedRevisionId: "rev-9",
      capturedRevision: { slug: "web", revision: 4 },
    });
    expect(db.sandboxTemplateRevision.findFirst).toHaveBeenCalledWith({
      where: { id: "rev-9", Template: { userId: "user-a" } },
      select: { revision: true, Template: { select: { slug: true } } },
    });
  });

  it("shows a failed capture's storage cause, as builds do (post-landing #6)", async () => {
    db.sandboxOperation.findFirst.mockResolvedValueOnce(
      detail({
        kind: "CAPTURE_TEMPLATE",
        state: "FAILED",
        errorCode: "capture_store_failed",
        Capture: { revisionId: null, errorDetail: "upload_timeout" },
      }),
    );
    const view = await getOperationView(owner, { operationId: "op-1" });
    expect(view).toMatchObject({
      errorCode: "capture_store_failed",
      captureDetail: "upload_timeout",
    });
    expect(view).not.toHaveProperty("errorDetail");
    db.sandboxOperation.findFirst.mockResolvedValueOnce(
      detail({
        kind: "CAPTURE_TEMPLATE",
        state: "FAILED",
        errorCode: "capture_failed",
        Capture: { revisionId: null, errorDetail: "upload_timeout" },
      }),
    );
    expect((await getOperationView(owner, { operationId: "op-1" })).captureDetail).toBeNull();
  });

  it("is owner-scoped and a foreign or missing operation is NOT_FOUND", async () => {
    db.sandboxOperation.findFirst.mockResolvedValueOnce(null);
    await expect(getOperationView(owner, { operationId: "op-x" })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    const args = findFirstCall();
    expect(args.where).toEqual({
      AND: [{ id: "op-x", Sandbox: { userId: "user-a" } }, { userId: "user-a" }],
    });
    expect(db.sandboxOperation.findMany).not.toHaveBeenCalled();
  });

  it("carries the sandbox and host summary, exit code and retention, never the result", async () => {
    db.sandboxOperation.findFirst.mockResolvedValueOnce(detail());
    db.sandboxOperation.findMany.mockResolvedValueOnce([
      { id: "op-1", result: { exitCode: 137, pid: 9 } },
    ]);
    const view = await getOperationView(owner, { operationId: "op-1" });
    const select = findFirstCall().select;
    expect(select).not.toHaveProperty("result");
    expect(select).not.toHaveProperty("idempotencyKey");
    expect(select).not.toHaveProperty("requestBodyHash");
    expect(view).toMatchObject({
      exitCode: 137,
      sandboxState: "DELETED",
      sandbox: { id: "sbx-1", state: "DELETED", generation: 2, host: null },
      outputExpiresAt: new Date(at.getTime() + 24 * 60 * 60 * 1000),
    });
    expect(view).not.toHaveProperty("Sandbox");
    expect(JSON.stringify(view)).not.toMatch(/"pid"|"result"/);
  });

  it.each(["user-a", "foreign-owner", null])(
    "redacts the host unless transport owner is the creator (%s)",
    async (hostOwnerId) => {
      const host = { id: "host", slug: "private-host", label: "Private", status: "CONNECTED" };
      db.sandboxOperation.findFirst.mockResolvedValueOnce(
        detail({
          Sandbox: {
            id: "sbx-1",
            state: "READY",
            generation: 2,
            hostOwnerId,
            SandboxHost: host,
          },
        }),
      );
      db.sandboxOperation.findMany.mockResolvedValueOnce([]);
      const view = await getOperationView(owner, { operationId: "op-1" });
      expect(view.sandbox.host).toEqual(hostOwnerId === "user-a" ? host : null);
      expect(view.sandbox).not.toHaveProperty("hostOwnerId");
    },
  );

  it("uses catalog error text and reads no result for other kinds", async () => {
    db.sandboxOperation.findFirst.mockResolvedValueOnce(
      detail({
        kind: "GET_FILE",
        state: "FAILED",
        errorCode: "not_found",
      }),
    );
    const view = await getOperationView(owner, { operationId: "op-1" });
    expect(view.errorCode).toBe("not_found");
    expect(view.errorMessage).toBe("Resource not found.");
    expect(findFirstCall().select).not.toHaveProperty("errorDetail");
    expect(JSON.stringify(view)).not.toContain("PRIVATE-LEGACY");
    expect(view.exitCode).toBeNull();
    expect(view.outputExpiresAt).toBeNull();
    expect(db.sandboxOperation.findMany).not.toHaveBeenCalled();
  });
});
